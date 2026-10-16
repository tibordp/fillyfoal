//! BPF Type Format (BTF): the type information the kernel and BPF loaders
//! use, as a raw file (`/sys/kernel/btf/vmlinux`, `/sys/kernel/btf/<module>`,
//! `pahole --btf_encode_detached` output) or as the `.BTF` section of an ELF
//! object (BPF programs built with `clang -g -target bpf`, kernels), which
//! the ELF dissector hands here.
//!
//! A 24-byte header (magic `0xeB9F` in the writer's byte order, version 1,
//! flags, header length, then the offsets and lengths of the type and string
//! sections, counted from the end of the header) is followed by the type
//! section, a sequence of `struct btf_type` records (name offset, info word
//! with the kind, `vlen` and `kind_flag`, then a size or a type ID) each
//! followed by kind-specific data, and the string section, NUL-terminated
//! names starting with the empty string. Types are numbered from 1 in the
//! order they appear; ID 0 is `void`.
//!
//! Every kind of the kernel's `Documentation/bpf/btf.rst` is decoded: INT,
//! PTR, ARRAY, STRUCT and UNION members (bitfields when `kind_flag` is set),
//! ENUM, ENUM64, FWD, TYPEDEF, VOLATILE, CONST, RESTRICT, FUNC, FUNC_PROTO,
//! VAR, DATASEC, FLOAT, DECL_TAG and TYPE_TAG. Written from that document;
//! checked against `clang -target bpf`/`bpfel` and `bpfeb` output and
//! `bpftool btf dump`.
//!
//! Split BTF (`/sys/kernel/btf/<module>`, the `.BTF` of a `.ko`) continues
//! the type numbering and the string offsets of a base BTF (vmlinux) that is
//! not in the file. It is recognised by its string section, which does not
//! start with the empty string (or is empty). Its own types are numbered
//! `base+1`, `base+2`, ..., since the base's type count is not recorded;
//! type references are shown as the raw IDs they are and never resolved,
//! because without the base nothing tells a reference to the base from one
//! to this file. Names are resolved when the base's string length can be
//! inferred: it is the offset whose subtraction maps every name offset at
//! or above it onto the start of a string of this file (checked against
//! pahole split output and real module BTF); names below it are the
//! base's, shown as offsets. A kernel module built since Linux 6.12 carries
//! its distilled base next to its `.BTF`, in a `.BTF.base` section (a
//! standalone BTF of just the types the module refers to); the ELF
//! dissector hands both over, and then the types are numbered after the
//! base's and every reference and name is resolved, as `bpftool` shows them
//! (checked against `pahole --btf_features=distilled_base` output).
//!
//! The `.BTF.ext` section of BPF objects is decoded too ([`ext`]): the
//! function information (each BPF function's FUNC type), the line
//! information (file, line, column and the source line's text per
//! instruction) and the CO-RE relocations (relocation kind, root type and
//! access string, spelled as the member path it selects), per code section.
//!
//! Type references in summaries are spelled the way C would declare them
//! (`const char *`, `u64[4][2]`, `int (*)(int, const void *)`), following
//! modifier, pointer, array and prototype chains a bounded number of steps.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::{cstrings, get, string_at};
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{int, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "btf",
    title: "BPF Type Format (BTF)",
    extensions: &["btf"],
    mime: "application/x-btf",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// `sizeof(struct btf_header)` in version 1.
const HEADER_LEN: u64 = 24;
/// Longest header accepted (later versions may append fields).
const MAX_HEADER_LEN: u32 = 256;
/// `sizeof(struct btf_type)`.
const TYPE_LEN: u64 = 12;
/// Longest name read.
const MAX_NAME: u64 = 512;
/// Most types one C spelling follows (modifiers, pointers, parameters).
const SPELL_STEPS: u32 = 48;
/// Parameters of a prototype spelled out before `…`.
const SPELL_PARAMS: u64 = 8;
/// Longest C spelling shown.
const SPELL_MAX: usize = 240;
/// Candidate base string lengths tried when inferring a split BTF's.
const STR_BASE_TRIES: usize = 64;

const KIND_INT: u8 = 1;
const KIND_PTR: u8 = 2;
const KIND_ARRAY: u8 = 3;
const KIND_STRUCT: u8 = 4;
const KIND_UNION: u8 = 5;
const KIND_ENUM: u8 = 6;
const KIND_FWD: u8 = 7;
const KIND_TYPEDEF: u8 = 8;
const KIND_VOLATILE: u8 = 9;
const KIND_CONST: u8 = 10;
const KIND_RESTRICT: u8 = 11;
const KIND_FUNC: u8 = 12;
const KIND_FUNC_PROTO: u8 = 13;
const KIND_VAR: u8 = 14;
const KIND_DATASEC: u8 = 15;
const KIND_FLOAT: u8 = 16;
const KIND_DECL_TAG: u8 = 17;
const KIND_TYPE_TAG: u8 = 18;
const KIND_ENUM64: u8 = 19;

const KINDS: EnumTable = &[
    (0, "UNKN"),
    (1, "INT"),
    (2, "PTR"),
    (3, "ARRAY"),
    (4, "STRUCT"),
    (5, "UNION"),
    (6, "ENUM"),
    (7, "FWD"),
    (8, "TYPEDEF"),
    (9, "VOLATILE"),
    (10, "CONST"),
    (11, "RESTRICT"),
    (12, "FUNC"),
    (13, "FUNC_PROTO"),
    (14, "VAR"),
    (15, "DATASEC"),
    (16, "FLOAT"),
    (17, "DECL_TAG"),
    (18, "TYPE_TAG"),
    (19, "ENUM64"),
];

const FUNC_LINKAGE: EnumTable = &[(0, "static"), (1, "global"), (2, "extern")];
const VAR_LINKAGE: EnumTable = &[(0, "static"), (1, "global"), (2, "extern")];

fn kind_name(kind: u8) -> &'static str {
    lookup(KINDS, kind.into()).unwrap_or("unknown kind")
}

fn probe(h: &Head) -> bool {
    let endian = if h.starts_with(&[0x9f, 0xeb]) {
        Endian::Little
    } else if h.starts_with(&[0xeb, 0x9f]) {
        Endian::Big
    } else {
        return false;
    };
    // Version 1, no flags defined.
    if !h.at(2, &[1, 0]) {
        return false;
    }
    let word = |off: usize| get::<u32>(h.data, off, endian);
    let (Some(hdr_len), Some(type_off), Some(type_len), Some(str_off), Some(str_len)) =
        (word(4), word(8), word(12), word(16), word(20))
    else {
        return false;
    };
    if !(24..=MAX_HEADER_LEN).contains(&hdr_len)
        || !hdr_len.is_multiple_of(4)
        || !type_off.is_multiple_of(4)
        || !type_len.is_multiple_of(4)
    {
        return false;
    }
    let end = |off: u32, len: u32| {
        u64::from(hdr_len)
            .saturating_add(u64::from(off))
            .saturating_add(u64::from(len))
    };
    if h.len_known && (end(type_off, type_len) > h.len || end(str_off, str_len) > h.len) {
        return false;
    }
    // A split BTF's strings continue its base's, so they need not start
    // with the empty string (and may be empty): accept that only when the
    // header lays out the file exactly, the way the kernel and pahole
    // write it (types first, strings right after, nothing else).
    let exact = type_off == 0
        && str_off == type_len
        && h.len_known
        && end(str_off, str_len) == h.len
        && type_len > 0;
    if str_len == 0 {
        return exact;
    }
    // A standalone BTF's string section starts with the empty string.
    let strings = u64::from(hdr_len).saturating_add(u64::from(str_off));
    match h.data.get(to_usize(strings)) {
        Some(&b) => b == 0 || exact,
        None => true,
    }
}

record! {
    /// `struct btf_header`
    struct BtfHeader {
        magic: u16 "magic" .hex(),
        version: u8 "version",
        flags: u8 "flags" .hex(),
        hdr_len: u32 "hdr_len" .desc("Length of this header; the offsets below count from its end"),
        type_off: u32 "type_off" .hex(),
        type_len: u32 "type_len",
        str_off: u32 "str_off" .hex(),
        str_len: u32 "str_len",
    }
}

/// What every node of one BTF blob shares.
#[derive(Clone)]
struct Btf {
    endian: Endian,
    types: Span,
    strings: Span,
    /// Split BTF: the numbering and the strings continue a base BTF.
    split: bool,
    /// The base of a split BTF, when the container holds one (the
    /// distilled `.BTF.base` of a kernel module): its types are numbered
    /// first and its strings come first.
    base: Option<Arc<Btf>>,
}

impl Btf {
    /// Whether type references can be resolved: always, except in split BTF
    /// whose base is not at hand.
    fn resolvable(&self) -> bool {
        !self.split || self.base.is_some()
    }
}

/// The offset of each type (ID 1 first) in the type section.
struct Index {
    offsets: Vec<u32>,
    /// Why the walk stopped early, if it did.
    error: Option<Diagnostic>,
    /// Split BTF: the length of the base's string section, the offset at
    /// which this file's strings start (`None` when the base is not at hand
    /// and the names do not settle it).
    str_base: Option<u32>,
    /// Split BTF on a base at hand: the base's index (its type count is the
    /// number this file's types continue from).
    base: Option<Arc<Index>>,
}

impl Index {
    /// How many types are numbered before this file's own.
    fn base_count(&self) -> u32 {
        self.base
            .as_ref()
            .map_or(0, |b| u32::try_from(b.offsets.len()).unwrap_or(u32::MAX))
    }
}

/// The header and the layout of the BTF in `file`.
async fn open(cx: &Cx, file: Span) -> Result<(BtfHeader, Btf)> {
    let magic = cx.read(file.sub(0, 2)).await?;
    let endian = match magic.as_slice() {
        [0xeb, 0x9f] => Endian::Big,
        [0x9f, 0xeb] => Endian::Little,
        _ => return Err(Diagnostic::malformed("no BTF magic (0xeB9F)")),
    };
    let h: BtfHeader = crate::dsl::read_record(cx, file.sub(0, HEADER_LEN), endian).await?;
    let hdr_end = u64::from(h.hdr_len);
    let types = file.sub(
        hdr_end.saturating_add(u64::from(h.type_off)),
        u64::from(h.type_len),
    );
    let strings = file.sub(
        hdr_end.saturating_add(u64::from(h.str_off)),
        u64::from(h.str_len),
    );
    // A standalone BTF's strings start with the empty string; a split
    // BTF's continue its base's.
    let split = if strings.len == 0 {
        types.len > 0
    } else {
        cx.read(strings.sub(0, 1)).await?.first() != Some(&0)
    };
    let btf = Btf {
        endian,
        types,
        strings,
        split,
        base: None,
    };
    Ok((h, btf))
}

/// The BTF in `file`, split on the BTF in `base` when that is a standalone
/// BTF of the same byte order; otherwise why the base is not used.
async fn open_on(
    cx: &Cx,
    file: Span,
    base: Option<Span>,
) -> Result<(BtfHeader, Btf, Option<Diagnostic>)> {
    let (h, mut btf) = open(cx, file).await?;
    let Some(bspan) = base else {
        return Ok((h, btf, None));
    };
    let problem = match open(cx, bspan).await {
        Err(_) => Some("is not BTF"),
        Ok((_, b)) if b.split => Some("is itself split"),
        Ok((_, b)) if b.endian != btf.endian => Some("has the other byte order"),
        Ok(_) if !btf.split => Some("is not needed: this BTF is not split"),
        Ok((_, b)) => {
            btf.base = Some(Arc::new(b));
            None
        }
    };
    let diag = problem
        .map(|p| Diagnostic::warning(format!("the base BTF in .BTF.base {p}; it is not used")));
    Ok((h, btf, diag))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    dissect_on(cx, input, None).await
}

/// The `.BTF` of an ELF object that also has a `.BTF.base` section (a
/// kernel module's split BTF with its distilled base, Linux 6.12+): types
/// and names are resolved through that base, as `bpftool` and libbpf do.
pub async fn dissect_on_base(cx: Cx, (input, base): (Input, Span)) -> Result<()> {
    dissect_on(cx, input, Some(base)).await
}

async fn dissect_on(cx: Cx, input: Input, base: Option<Span>) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, HEADER_LEN);
    let (h, btf, base_problem) = match open_on(&cx, file, base).await {
        Ok(v) => v,
        Err(e) => {
            cx.emit(BtfHeader::node("Header", hspan, Endian::Little));
            return Err(e);
        }
    };
    cx.emit(BtfHeader::node("Header", hspan, btf.endian));
    if let Some(d) = base_problem {
        cx.diag(d);
    }
    let hdr_end = u64::from(h.hdr_len);
    if hdr_end > HEADER_LEN {
        cx.emit(
            Node::new("Header Extension")
                .span(file.sub(HEADER_LEN, hdr_end.saturating_sub(HEADER_LEN)))
                .desc("Header fields this version does not know"),
        );
    }
    let (endian, types, strings, split) = (btf.endian, btf.types, btf.strings, btf.split);
    let mut types_node = Node::new("Types")
        .span(types)
        .summary(size(types.len))
        .lazy(type_list, btf.clone());
    let mut on_base = None;
    if let Some(b) = &btf.base {
        let n = index(&cx, b).await.offsets.len();
        types_node = types_node.diag(Diagnostic::note(format!(
            "split BTF on the base in .BTF.base: its {} are numbered first, so \
             these start at {}, and names below offset {:#x} are the base's",
            plural(n, "type"),
            n.saturating_add(1),
            b.strings.len
        )));
        on_base = Some(n);
    } else if split {
        types_node = types_node.diag(Diagnostic::note(
            "split BTF: the types continue the numbering of a base BTF (vmlinux) \
             that is not in this file, so they are numbered base+N and the type \
             IDs they refer to are shown raw",
        ));
    }
    if types.len < u64::from(h.type_len) {
        types_node = types_node.diag(Diagnostic::truncated(
            file.sub(
                types.offset.saturating_sub(file.offset),
                u64::from(h.type_len),
            ),
            types.len,
        ));
    }
    cx.emit(types_node);
    let mut strings_node = Node::new("Strings")
        .span(strings)
        .summary(size(strings.len))
        .lazy(cstrings, strings);
    if strings.len < u64::from(h.str_len) {
        strings_node = strings_node.diag(Diagnostic::malformed(
            "string section runs past the end of the file",
        ));
    }
    cx.emit(strings_node);
    let end = types.end().max(strings.end()).saturating_sub(file.offset);
    if end < file.len {
        cx.emit(Node::new("Trailing Data").span(file.tail(end)));
    }
    cx.annotate(format!(
        "{}BTF v{}{}, {}-endian, {} of types, {} of strings",
        if split { "split " } else { "" },
        h.version,
        match on_base {
            Some(n) => format!(" on a base of {}", plural(n, "type")),
            None => String::new(),
        },
        match endian {
            Endian::Little => "little",
            Endian::Big => "big",
        },
        size(types.len),
        size(strings.len)
    ));
    Ok(())
}

/// Bytes of kind-specific data after a type's 12-byte head.
fn extra_len(kind: u8, vlen: u16) -> Option<u64> {
    let n = u64::from(vlen);
    Some(match kind {
        KIND_INT | KIND_VAR | KIND_DECL_TAG => 4,
        KIND_ARRAY => 12,
        KIND_STRUCT | KIND_UNION | KIND_DATASEC | KIND_ENUM64 => n.saturating_mul(12),
        KIND_ENUM | KIND_FUNC_PROTO => n.saturating_mul(8),
        KIND_PTR | KIND_FWD | KIND_TYPEDEF | KIND_VOLATILE | KIND_CONST | KIND_RESTRICT
        | KIND_FUNC | KIND_FLOAT | KIND_TYPE_TAG => 0,
        _ => return None,
    })
}

/// A type's head: `name_off`, `info` split up, and `size`/`type`.
#[derive(Clone, Copy)]
struct TypeHead {
    name_off: u32,
    kind: u8,
    vlen: u16,
    kind_flag: bool,
    size_type: u32,
}

impl TypeHead {
    fn decode(b: &[u8], endian: Endian) -> Option<Self> {
        let name_off = get::<u32>(b, 0, endian)?;
        let info = get::<u32>(b, 4, endian)?;
        let size_type = get::<u32>(b, 8, endian)?;
        Some(TypeHead {
            name_off,
            kind: ((info >> 24) & 0x1f) as u8,
            vlen: (info & 0xffff) as u16,
            kind_flag: info >> 31 != 0,
            size_type,
        })
    }

    fn len(&self) -> Option<u64> {
        extra_len(self.kind, self.vlen).map(|n| n.saturating_add(TYPE_LEN))
    }
}

/// Walks the type section once, recording where each type starts (and, for
/// split BTF on a base at hand, the base's index).
async fn index(cx: &Cx, btf: &Btf) -> Arc<Index> {
    let Some(base) = &btf.base else {
        return walk_index(cx, btf, "btf-index").await;
    };
    // The same section indexed without the base differs, so it is cached
    // under its own name.
    if let Some(index) = cx.cached::<Index>(btf.types, "btf-index-on-base") {
        return index;
    }
    let base_index = walk_index(cx, base, "btf-index").await;
    let own = walk_index(
        cx,
        &Btf {
            split: false,
            ..btf.clone()
        },
        "btf-index-own",
    )
    .await;
    let index = Arc::new(Index {
        offsets: own.offsets.clone(),
        error: own.error.clone(),
        str_base: u32::try_from(base.strings.len).ok(),
        base: Some(base_index),
    });
    cx.charge(to_u64(index.offsets.len()) / 256).await;
    cx.cache(btf.types, "btf-index-on-base", index.clone());
    index
}

/// The index of one type section on its own.
async fn walk_index(cx: &Cx, btf: &Btf, kind: &'static str) -> Arc<Index> {
    if let Some(index) = cx.cached::<Index>(btf.types, kind) {
        return index;
    }
    const WINDOW: u64 = 64 * 1024;
    let mut offsets = Vec::new();
    let mut names: Vec<u32> = Vec::new();
    let mut error = None;
    let mut pos = 0u64;
    let mut win_start = 0u64;
    let mut win: Vec<u8> = Vec::new();
    while pos < btf.types.len {
        let rel = pos.saturating_sub(win_start);
        if pos < win_start || rel.saturating_add(TYPE_LEN) > to_u64(win.len()) {
            match cx.read(btf.types.sub(pos, WINDOW)).await {
                Ok(data) => {
                    win = data;
                    win_start = pos;
                }
                Err(e) => {
                    error = Some(e);
                    break;
                }
            }
        }
        let head = win
            .get(to_usize(pos.saturating_sub(win_start))..)
            .and_then(|b| TypeHead::decode(b, btf.endian));
        let Some(head) = head else {
            error = Some(Diagnostic::truncated(
                btf.types.sub(pos, TYPE_LEN),
                btf.types.len.saturating_sub(pos),
            ));
            break;
        };
        let Some(len) = head.len() else {
            error = Some(
                Diagnostic::malformed(format!(
                    "type {} has unknown kind {}; the types after it cannot be found",
                    offsets.len().saturating_add(1),
                    head.kind
                ))
                .at(btf.types.sub(pos, TYPE_LEN)),
            );
            break;
        };
        let Ok(off) = u32::try_from(pos) else {
            break;
        };
        if btf.split {
            let held = pos >= win_start
                && pos.saturating_sub(win_start).saturating_add(len) <= to_u64(win.len());
            if !held && let Ok(data) = cx.read(btf.types.sub(pos, len.max(WINDOW))).await {
                win = data;
                win_start = pos;
            }
            if let Some(b) = win.get(to_usize(pos.saturating_sub(win_start))..) {
                collect_names(b, &head, btf.endian, &mut names);
            }
            cx.charge(u64::from(head.vlen) / 256).await;
        }
        offsets.push(off);
        pos = pos.saturating_add(len);
        if offsets.len().is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    if pos > btf.types.len && error.is_none() {
        error = Some(Diagnostic::malformed(
            "the last type runs past the end of the type section",
        ));
    }
    let str_base = if btf.split {
        infer_str_base(cx, btf, names).await
    } else {
        None
    };
    let index = Arc::new(Index {
        offsets,
        error,
        str_base,
        base: None,
    });
    cx.cache(btf.types, kind, index.clone());
    index
}

/// The non-zero name offsets of one type (`b` starts at its head): its own
/// and its members', values' and parameters'.
fn collect_names(b: &[u8], head: &TypeHead, endian: Endian, names: &mut Vec<u32>) {
    if head.name_off != 0 {
        names.push(head.name_off);
    }
    let width: usize = match head.kind {
        KIND_STRUCT | KIND_UNION | KIND_ENUM64 => 12,
        KIND_ENUM | KIND_FUNC_PROTO => 8,
        _ => return,
    };
    for i in 0..usize::from(head.vlen) {
        let at = i.saturating_mul(width).saturating_add(12);
        match get::<u32>(b, at, endian) {
            Some(0) => {}
            Some(n) => names.push(n),
            None => break,
        }
    }
}

/// The length of a split BTF's base string section: the name offset `s`
/// such that every name offset at or above it, less `s`, is the start of
/// one of this file's strings (`s` itself naming the first). The base's
/// strings are far longer than the file's, so `s` lies within the string
/// section's length below the highest name offset; the lowest candidate
/// there that fits wins.
async fn infer_str_base(cx: &Cx, btf: &Btf, mut names: Vec<u32>) -> Option<u32> {
    let len = u32::try_from(btf.strings.len).ok().filter(|&l| l > 0)?;
    cx.charge(to_u64(names.len()) / 64).await;
    names.sort_unstable();
    names.dedup();
    let max = *names.last()?;
    let data = cx.read(btf.strings).await.ok()?;
    cx.charge(to_u64(data.len()) / 1024).await;
    // Where each of this file's strings starts.
    let mut starts = vec![0u32];
    for (i, &b) in data.iter().enumerate() {
        if b == 0 {
            match u32::try_from(i.saturating_add(1)) {
                Ok(next) if next < len => starts.push(next),
                _ => {}
            }
        }
    }
    let low = max.saturating_sub(len.saturating_sub(1));
    let first = names.partition_point(|&n| n < low);
    let candidates = names.get(first..)?;
    for (i, &base) in candidates.iter().enumerate().take(STR_BASE_TRIES) {
        let rest = candidates.get(i..).unwrap_or_default();
        cx.charge(to_u64(rest.len()) / 64).await;
        if rest
            .iter()
            .all(|&n| starts.binary_search(&n.saturating_sub(base)).is_ok())
        {
            return Some(base);
        }
    }
    None
}

/// The span of type `id`, numbered as references number it (after the
/// base's types, in split BTF on a base at hand), if it exists.
fn type_span(btf: &Btf, index: &Index, id: u32) -> Option<Span> {
    if let (Some(base), Some(base_index)) = (&btf.base, &index.base) {
        let count = index.base_count();
        return if id <= count {
            local_span(base, base_index, id)
        } else {
            local_span(btf, index, id.saturating_sub(count))
        };
    }
    local_span(btf, index, id)
}

/// The span of this section's type `id` (its first is 1).
fn local_span(btf: &Btf, index: &Index, id: u32) -> Option<Span> {
    let i = to_usize(u64::from(id.checked_sub(1)?));
    let start = u64::from(*index.offsets.get(i)?);
    let end = index
        .offsets
        .get(i.saturating_add(1))
        .map_or(btf.types.len, |&e| u64::from(e));
    Some(btf.types.sub(start, end.saturating_sub(start)))
}

async fn read_head(cx: &Cx, btf: &Btf, span: Span) -> Result<TypeHead> {
    let b = cx.read(span.sub(0, TYPE_LEN)).await?;
    TypeHead::decode(&b, btf.endian).ok_or_else(|| Diagnostic::truncated(span, to_u64(b.len())))
}

/// A name from the string section; empty for offset 0, `None` if the offset
/// is outside it (or, in split BTF, in the base's strings or with the base
/// not placed).
async fn name(cx: &Cx, btf: &Btf, index: &Index, off: u32) -> Option<String> {
    if off == 0 {
        return Some(String::new());
    }
    let (strings, local) = if btf.split {
        match off.checked_sub(index.str_base?) {
            Some(local) => (btf.strings, local),
            // Below this file's strings: the base's, if it is at hand.
            None => (btf.base.as_ref()?.strings, off),
        }
    } else {
        (btf.strings, off)
    };
    string_at(cx, strings, u64::from(local))
        .await
        .ok()
        .map(|(s, _)| {
            if to_u64(s.len()) > MAX_NAME {
                crate::formats::util::fmt::clip(&s, to_usize(MAX_NAME))
            } else {
                s
            }
        })
}

async fn name_or_offset(cx: &Cx, btf: &Btf, index: &Index, off: u32) -> String {
    match name(cx, btf, index, off).await {
        Some(s) if s.is_empty() => "(anon)".to_string(),
        Some(s) => s,
        None => match index.str_base {
            Some(base) if btf.split && off < base => format!("(base name at {off:#x})"),
            _ => format!("(name at {off:#x})"),
        },
    }
}

/// How type `id` (from 1, in file order) is numbered: split BTF continues
/// its base's numbering, whose length is recorded only by the base.
fn id_label(btf: &Btf, index: &Index, id: u32) -> String {
    if btf.base.is_some() {
        index.base_count().saturating_add(id).to_string()
    } else if btf.split {
        format!("base+{id}")
    } else {
        id.to_string()
    }
}

/// The span of the type a reference names; none in split BTF without its
/// base, where a reference may name the base's types.
fn ref_span(btf: &Btf, index: &Index, id: u32) -> Option<Span> {
    if btf.resolvable() {
        type_span(btf, index, id)
    } else {
        None
    }
}

/// A short C-ish label for a type: `struct record`, `u32`, `const`.
fn label(head: &TypeHead, name: &str) -> String {
    let anon = name.is_empty();
    let named = |prefix: &str| {
        if anon {
            format!("{prefix} (anon)")
        } else {
            format!("{prefix} {name}")
        }
    };
    match head.kind {
        KIND_STRUCT => named("struct"),
        KIND_UNION => named("union"),
        KIND_ENUM | KIND_ENUM64 => named("enum"),
        KIND_FWD => named(if head.kind_flag { "union" } else { "struct" }),
        KIND_INT | KIND_FLOAT | KIND_TYPEDEF | KIND_FUNC | KIND_VAR | KIND_DATASEC if !anon => {
            name.to_string()
        }
        KIND_PTR => "pointer".to_string(),
        KIND_ARRAY => "array".to_string(),
        KIND_VOLATILE => "volatile".to_string(),
        KIND_CONST => "const".to_string(),
        KIND_RESTRICT => "restrict".to_string(),
        KIND_FUNC_PROTO => "function prototype".to_string(),
        KIND_TYPE_TAG => format!("type tag \"{name}\""),
        KIND_DECL_TAG => format!("decl tag \"{name}\""),
        _ => kind_name(head.kind).to_string(),
    }
}

/// `[id] spelling` for a reference to type `id`: `[4] const char *`. Split
/// BTF shows the raw ID only (it may be the base's).
async fn type_ref(cx: &Cx, btf: &Btf, index: &Index, id: u32) -> String {
    if id == 0 {
        return "[0] void".to_string();
    }
    if !btf.resolvable() {
        return format!("[{id}]");
    }
    if type_span(btf, index, id).is_none() {
        return format!("[{id}] (no such type)");
    }
    format!("[{id}] {}", c_type(cx, btf, index, id).await)
}

/// What a type ID field shows: the type it refers to, and where it is.
async fn ref_value(cx: &Cx, btf: &Btf, index: &Index, id: u32) -> (String, Option<Span>) {
    (type_ref(cx, btf, index, id).await, ref_span(btf, index, id))
}

/// The head of type `id`, if it is in the file (and the file is not split).
async fn ref_head(cx: &Cx, btf: &Btf, index: &Index, id: u32) -> Option<(TypeHead, Span)> {
    let span = ref_span(btf, index, id)?;
    Some((read_head(cx, btf, span).await.ok()?, span))
}

/// Type `id` spelled the way C declares it: `const char *`, `u64[4][2]`,
/// `int (*)(int, const void *)`.
async fn c_type(cx: &Cx, btf: &Btf, index: &Index, id: u32) -> String {
    let mut steps = SPELL_STEPS;
    let s = spell(cx, btf, index, id, String::new(), &mut steps).await;
    crate::formats::util::fmt::clip(&s, SPELL_MAX)
}

/// `base` followed by the declarator `decl` (`*`, `[4]`, `(*)(int)`).
fn declare(base: &str, decl: &str) -> String {
    if decl.is_empty() {
        base.to_string()
    } else if decl.starts_with('[') {
        format!("{base}{decl}")
    } else {
        format!("{base} {decl}")
    }
}

type Spelling<'a> = Pin<Box<dyn Future<Output = String> + Send + 'a>>;

/// Type `id` around the declarator `decl`, following at most `steps` types.
fn spell<'a>(
    cx: &'a Cx,
    btf: &'a Btf,
    index: &'a Index,
    id: u32,
    decl: String,
    steps: &'a mut u32,
) -> Spelling<'a> {
    Box::pin(async move {
        if id == 0 {
            return declare("void", &decl);
        }
        let Some(left) = steps.checked_sub(1) else {
            return declare("…", &decl);
        };
        *steps = left;
        let Some((head, span)) = ref_head(cx, btf, index, id).await else {
            return declare(&format!("[{id}]"), &decl);
        };
        let target = head.size_type;
        match head.kind {
            KIND_PTR => {
                let around = match ref_head(cx, btf, index, target).await {
                    Some((t, _)) if matches!(t.kind, KIND_ARRAY | KIND_FUNC_PROTO) => {
                        format!("(*{decl})")
                    }
                    _ => format!("*{decl}"),
                };
                spell(cx, btf, index, target, around, steps).await
            }
            KIND_CONST | KIND_VOLATILE | KIND_RESTRICT | KIND_TYPE_TAG => {
                let q = match head.kind {
                    KIND_CONST => "const".to_string(),
                    KIND_VOLATILE => "volatile".to_string(),
                    KIND_RESTRICT => "restrict".to_string(),
                    _ => {
                        let n = name(cx, btf, index, head.name_off)
                            .await
                            .unwrap_or_default();
                        format!("btf_type_tag(\"{n}\")")
                    }
                };
                // A qualified pointer is qualified after its `*`; anything
                // else before its type.
                let on_pointer = matches!(
                    ref_head(cx, btf, index, target).await,
                    Some((t, _)) if t.kind == KIND_PTR
                );
                if on_pointer || head.kind == KIND_TYPE_TAG {
                    spell(cx, btf, index, target, declare(&q, &decl), steps).await
                } else {
                    let inner = spell(cx, btf, index, target, decl, steps).await;
                    format!("{q} {inner}")
                }
            }
            KIND_ARRAY => {
                let b = cx.read(span.sub(TYPE_LEN, 12)).await.unwrap_or_default();
                let elem = get::<u32>(&b, 0, btf.endian).unwrap_or(0);
                let n = get::<u32>(&b, 8, btf.endian).unwrap_or(0);
                spell(cx, btf, index, elem, format!("{decl}[{n}]"), steps).await
            }
            KIND_FUNC_PROTO => {
                let count = u64::from(head.vlen);
                let shown = count.min(SPELL_PARAMS);
                let b = cx
                    .read(span.sub(TYPE_LEN, shown.saturating_mul(8)))
                    .await
                    .unwrap_or_default();
                let mut params = Vec::new();
                for i in 0..shown {
                    let ty = get::<u32>(
                        &b,
                        to_usize(i.saturating_mul(8).saturating_add(4)),
                        btf.endian,
                    )
                    .unwrap_or(0);
                    if ty == 0 && i.saturating_add(1) == count {
                        params.push("...".to_string());
                    } else {
                        params.push(spell(cx, btf, index, ty, String::new(), steps).await);
                    }
                }
                if count > shown {
                    params.push("…".to_string());
                }
                let list = if params.is_empty() {
                    "void".to_string()
                } else {
                    params.join(", ")
                };
                spell(cx, btf, index, target, format!("{decl}({list})"), steps).await
            }
            _ => {
                let n = name(cx, btf, index, head.name_off)
                    .await
                    .unwrap_or_default();
                declare(&label(&head, &n), &decl)
            }
        }
    })
}

async fn type_list(cx: Cx, btf: Btf) -> Result<()> {
    let index = index(&cx, &btf).await;
    let count = to_u64(index.offsets.len());
    cx.set_count(Count::Exact(count));
    let mut id = cx.resume::<u32>().unwrap_or(1);
    while u64::from(id) <= count {
        let at = id;
        cx.mark(move || at);
        let Some(span) = local_span(&btf, &index, id) else {
            break;
        };
        let node = if cx.skipping() {
            Node::new(format!("[{}]", id_label(&btf, &index, id))).span(span)
        } else {
            type_node(&cx, &btf, &index, id, span).await
        };
        cx.push(node).await;
        id = id.saturating_add(1);
    }
    if let Some(e) = &index.error {
        cx.diag(e.clone());
    }
    Ok(())
}

/// The line for one type, with a summary of what it is.
async fn type_node(cx: &Cx, btf: &Btf, index: &Index, id: u32, span: Span) -> Node {
    let head = match read_head(cx, btf, span).await {
        Ok(h) => h,
        Err(e) => {
            return Node::new(format!("[{}]", id_label(btf, index, id)))
                .span(span)
                .diag(e);
        }
    };
    let n = name_or_offset(cx, btf, index, head.name_off).await;
    let kind = kind_name(head.kind);
    let title = format!("[{}] {kind} {n}", id_label(btf, index, id));
    let target = |cx: &Cx| {
        let (btf, index) = (btf.clone(), index);
        let cx = cx.clone();
        async move { type_ref(&cx, &btf, index, head.size_type).await }
    };
    let summary = match head.kind {
        KIND_INT => {
            let enc = cx
                .read(span.sub(TYPE_LEN, 4))
                .await
                .ok()
                .and_then(|b| get::<u32>(&b, 0, btf.endian))
                .unwrap_or(0);
            let mut s = format!(
                "{}, {}",
                plural(head.size_type, "byte"),
                plural(enc & 0xff, "bit")
            );
            let e = int_encoding(enc);
            if !e.is_empty() {
                s.push_str(", ");
                s.push_str(&e);
            }
            s
        }
        KIND_STRUCT | KIND_UNION => format!(
            "{}, {}",
            plural(head.size_type, "byte"),
            plural(head.vlen, "member")
        ),
        KIND_ENUM | KIND_ENUM64 => format!(
            "{}, {}{}",
            plural(head.size_type, "byte"),
            plural(head.vlen, "value"),
            if head.kind_flag { ", signed" } else { "" }
        ),
        KIND_FWD => (if head.kind_flag { "union" } else { "struct" }).to_string(),
        KIND_FLOAT => plural(head.size_type, "byte"),
        KIND_DATASEC => format!(
            "{}, {}",
            plural(head.size_type, "byte"),
            plural(head.vlen, "variable")
        ),
        KIND_FUNC_PROTO => format!(
            "returns {}, {}",
            target(cx).await,
            plural(head.vlen, "parameter")
        ),
        KIND_FUNC => format!(
            "{}, {}",
            lookup(FUNC_LINKAGE, head.vlen.into()).unwrap_or("unknown linkage"),
            target(cx).await
        ),
        KIND_ARRAY => {
            let b = cx.read(span.sub(TYPE_LEN, 12)).await.unwrap_or_default();
            let elem = get::<u32>(&b, 0, btf.endian).unwrap_or(0);
            let n = get::<u32>(&b, 8, btf.endian).unwrap_or(0);
            format!("{n} × {}", type_ref(cx, btf, index, elem).await)
        }
        KIND_DECL_TAG => {
            let b = cx.read(span.sub(TYPE_LEN, 4)).await.unwrap_or_default();
            let comp = get::<i32>(&b, 0, btf.endian).unwrap_or(-1);
            let on = target(cx).await;
            if comp < 0 {
                format!("on {on}")
            } else {
                format!("on component {comp} of {on}")
            }
        }
        KIND_PTR | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT | KIND_TYPE_TAG
            if btf.resolvable() =>
        {
            format!(
                "{} → [{}]",
                c_type(cx, btf, index, index.base_count().saturating_add(id)).await,
                head.size_type
            )
        }
        _ => format!("→ {}", target(cx).await),
    };
    Node::new(title)
        .span(span)
        .summary(summary)
        .lazy(type_fields, (btf.clone(), span))
}

fn int_encoding(enc: u32) -> String {
    let e = (enc >> 24) & 0xf;
    let mut parts = Vec::new();
    if e & 1 != 0 {
        parts.push("signed");
    }
    if e & 2 != 0 {
        parts.push("char");
    }
    if e & 4 != 0 {
        parts.push("bool");
    }
    parts.join(" ")
}

/// A field holding a type ID, annotated with what it refers to.
fn type_id_field(f: &mut Fields<'_>, name: &'static str, r: (String, Option<Span>)) -> Result<u32> {
    let (summary, target) = r;
    let mut field = f.u32(name).summary(summary);
    if let Some(t) = target {
        field = field.target(t);
    }
    field.emit()
}

async fn type_fields(cx: Cx, (btf, span): (Btf, Span)) -> Result<()> {
    let index = index(&cx, &btf).await;
    let head = read_head(&cx, &btf, span).await?;
    let n = name_or_offset(&cx, &btf, &index, head.name_off).await;
    let block = cx.block(span.sub(0, TYPE_LEN)).await?;
    let mut f = Fields::emitting(&cx, &block, btf.endian);
    f.u32("name_off").hex().summary(n).emit()?;
    let kind = head.kind;
    f.u32("info")
        .hex()
        .summary(format!(
            "kind {} ({kind}), vlen {}, kind_flag {}",
            kind_name(kind),
            head.vlen,
            u8::from(head.kind_flag)
        ))
        .emit()?;
    match kind {
        KIND_INT | KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_ENUM64 | KIND_DATASEC
        | KIND_FLOAT => {
            f.u32("size")
                .summary(plural(head.size_type, "byte"))
                .emit()?;
        }
        KIND_FWD | KIND_ARRAY => {
            f.u32("size").emit()?;
        }
        _ => {
            let r = ref_value(&cx, &btf, &index, head.size_type).await;
            type_id_field(&mut f, "type", r)?;
        }
    }
    let extra = span.tail(TYPE_LEN);
    match kind {
        KIND_INT => {
            let block = cx.block(extra.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            let enc = f
                .u32("encoding")
                .hex()
                .with(|&v, node| {
                    let e = int_encoding(v);
                    node.summary(format!(
                        "{}offset {}, {} bits",
                        if e.is_empty() {
                            String::new()
                        } else {
                            format!("{e}, ")
                        },
                        (v >> 16) & 0xff,
                        v & 0xff
                    ))
                })
                .emit()?;
            if enc >> 28 != 0 {
                cx.diag(Diagnostic::warning("reserved bits set in the INT encoding"));
            }
        }
        KIND_ARRAY => {
            let b = cx.read(extra.sub(0, 12)).await?;
            let elem = get::<u32>(&b, 0, btf.endian).unwrap_or(0);
            let idx = get::<u32>(&b, 4, btf.endian).unwrap_or(0);
            let r1 = ref_value(&cx, &btf, &index, elem).await;
            let r2 = ref_value(&cx, &btf, &index, idx).await;
            let block = cx.block(extra.sub(0, 12)).await?;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            type_id_field(&mut f, "type", r1)?;
            type_id_field(&mut f, "index_type", r2)?;
            f.u32("nelems").emit()?;
        }
        KIND_VAR => {
            let block = cx.block(extra.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("linkage").enumeration(VAR_LINKAGE).emit()?;
        }
        KIND_DECL_TAG => {
            let block = cx.block(extra.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.int::<i32>("component_idx")
                .with(|&v, node| {
                    node.summary(if v < 0 {
                        "the type itself".to_string()
                    } else {
                        format!("member or parameter {v}")
                    })
                })
                .emit()?;
        }
        KIND_FUNC => {
            cx.emit(
                Node::new("Linkage")
                    .span(span.sub(4, 4))
                    .value(Value::Enum {
                        raw: head.vlen.into(),
                        bits: 16,
                        name: lookup(FUNC_LINKAGE, head.vlen.into()).map(Into::into),
                    })
                    .desc("Kept in vlen"),
            );
        }
        KIND_STRUCT | KIND_UNION | KIND_ENUM | KIND_ENUM64 | KIND_FUNC_PROTO | KIND_DATASEC
            if head.vlen > 0 =>
        {
            let (title, noun) = match kind {
                KIND_STRUCT | KIND_UNION => ("Members", "member"),
                KIND_ENUM | KIND_ENUM64 => ("Values", "value"),
                KIND_FUNC_PROTO => ("Parameters", "parameter"),
                _ => ("Variables", "variable"),
            };
            cx.emit(
                Node::new(title)
                    .span(extra)
                    .summary(plural(head.vlen, noun))
                    .lazy(entries, (btf.clone(), head, extra)),
            );
        }
        _ => {}
    }
    Ok(())
}

/// The members, values, parameters or variables after a type's head.
async fn entries(cx: Cx, (btf, head, extra): (Btf, TypeHead, Span)) -> Result<()> {
    let index = index(&cx, &btf).await;
    let width: u64 = match head.kind {
        KIND_ENUM | KIND_FUNC_PROTO => 8,
        _ => 12,
    };
    let count = u64::from(head.vlen);
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let espan = extra.sub_exact(i.saturating_mul(width), width)?;
        let b = cx.read(espan).await?;
        let w = |off: usize| get::<u32>(&b, off, btf.endian).unwrap_or(0);
        let node = match head.kind {
            KIND_STRUCT | KIND_UNION => {
                let n = name_or_offset(&cx, &btf, &index, w(0)).await;
                let ty = type_ref(&cx, &btf, &index, w(4)).await;
                let off = w(8);
                let place = if head.kind_flag && off >> 24 != 0 {
                    format!("{}-bit field at bit {}", off >> 24, off & 0x00ff_ffff)
                } else {
                    let bits = if head.kind_flag {
                        off & 0x00ff_ffff
                    } else {
                        off
                    };
                    if bits.is_multiple_of(8) {
                        format!("at byte {}", bits / 8)
                    } else {
                        format!("at bit {bits}")
                    }
                };
                Node::new(n).summary(format!("{ty}, {place}"))
            }
            KIND_ENUM => {
                let n = name_or_offset(&cx, &btf, &index, w(0)).await;
                let raw = w(4);
                let value = if head.kind_flag {
                    int(i64::from(raw as i32), 32)
                } else {
                    uint(raw, 32)
                };
                Node::new(n).value(value)
            }
            KIND_ENUM64 => {
                let n = name_or_offset(&cx, &btf, &index, w(0)).await;
                let raw = u64::from(w(4)) | (u64::from(w(8)) << 32);
                let value = if head.kind_flag {
                    int(raw as i64, 64)
                } else {
                    uint(raw, 64)
                };
                Node::new(n).value(value)
            }
            KIND_FUNC_PROTO => {
                let (name_off, ty) = (w(0), w(4));
                if name_off == 0 && ty == 0 && i.saturating_add(1) == count {
                    Node::new("...").summary("variable arguments")
                } else {
                    let n = name_or_offset(&cx, &btf, &index, name_off).await;
                    Node::new(n).summary(type_ref(&cx, &btf, &index, ty).await)
                }
            }
            _ => {
                // DATASEC: btf_var_secinfo.
                let ty = type_ref(&cx, &btf, &index, w(0)).await;
                Node::new(ty).summary(format!("offset {:#x}, {}", w(4), plural(w(8), "byte")))
            }
        };
        let node = node.span(espan).lazy(
            entry_fields,
            (btf.clone(), head.kind, head.kind_flag, espan),
        );
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn entry_fields(cx: Cx, (btf, kind, kind_flag, span): (Btf, u8, bool, Span)) -> Result<()> {
    let index = index(&cx, &btf).await;
    let b = cx.read(span).await?;
    let w = |off: usize| get::<u32>(&b, off, btf.endian).unwrap_or(0);
    let block = cx.block(span).await?;
    match kind {
        KIND_STRUCT | KIND_UNION => {
            let n = name_or_offset(&cx, &btf, &index, w(0)).await;
            let r = ref_value(&cx, &btf, &index, w(4)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("name_off").hex().summary(n).emit()?;
            type_id_field(&mut f, "type", r)?;
            f.u32("offset")
                .with(|&v, node| {
                    if kind_flag {
                        node.summary(format!(
                            "bitfield_size {}, bit offset {}",
                            v >> 24,
                            v & 0x00ff_ffff
                        ))
                    } else {
                        node.summary("bit offset")
                    }
                })
                .emit()?;
        }
        KIND_ENUM => {
            let n = name_or_offset(&cx, &btf, &index, w(0)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("name_off").hex().summary(n).emit()?;
            if kind_flag {
                f.int::<i32>("val").emit()?;
            } else {
                f.u32("val").emit()?;
            }
        }
        KIND_ENUM64 => {
            let n = name_or_offset(&cx, &btf, &index, w(0)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("name_off").hex().summary(n).emit()?;
            f.u32("val_lo32").hex().emit()?;
            f.u32("val_hi32").hex().emit()?;
        }
        KIND_FUNC_PROTO => {
            let n = name_or_offset(&cx, &btf, &index, w(0)).await;
            let r = ref_value(&cx, &btf, &index, w(4)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("name_off").hex().summary(n).emit()?;
            type_id_field(&mut f, "type", r)?;
        }
        _ => {
            let r = ref_value(&cx, &btf, &index, w(0)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            type_id_field(&mut f, "type", r)?;
            f.u32("offset").hex().emit()?;
            f.u32("size").emit()?;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// .BTF.ext

/// `sizeof(struct btf_ext_header)` before CO-RE relocations were added.
const EXT_HEADER_V1: u64 = 24;
/// `sizeof(struct btf_ext_header)` with the CO-RE relocation fields.
const EXT_HEADER_CORE: u64 = 32;
/// Most accessors of a CO-RE access string followed.
const ACCESS_STEPS: usize = 32;
/// BPF instructions are 8 bytes; the `.BTF.ext` of an object counts bytes.
const INSN_LEN: u32 = 8;

const CORE_RELO_KINDS: EnumTable = &[
    (0, "FIELD_BYTE_OFFSET"),
    (1, "FIELD_BYTE_SIZE"),
    (2, "FIELD_EXISTS"),
    (3, "FIELD_SIGNED"),
    (4, "FIELD_LSHIFT_U64"),
    (5, "FIELD_RSHIFT_U64"),
    (6, "TYPE_ID_LOCAL"),
    (7, "TYPE_ID_TARGET"),
    (8, "TYPE_EXISTS"),
    (9, "TYPE_SIZE"),
    (10, "ENUMVAL_EXISTS"),
    (11, "ENUMVAL_VALUE"),
    (12, "TYPE_MATCHES"),
];

/// Where the `.BTF.ext` section of an ELF object is, and what it refers to.
#[derive(Clone)]
pub struct Ext {
    /// The `.BTF.ext` section.
    pub ext: Span,
    /// The `.BTF` section whose types and strings the records name.
    pub btf: Option<Span>,
    /// A `.BTF.base` section, if the `.BTF` is split on it.
    pub base: Option<Span>,
    /// The object's executable sections by name: the records' instruction
    /// offsets count from the start of the section they name.
    pub code: Arc<Vec<(String, Span)>>,
}

/// What the records of one `.BTF.ext` share.
struct ExtCtx {
    endian: Endian,
    btf: Option<Btf>,
    code: Arc<Vec<(String, Span)>>,
}

#[derive(Clone, Copy, PartialEq)]
enum ExtKind {
    Func,
    Line,
    Core,
}

impl ExtKind {
    /// The bytes of a record this decoder reads; records may be longer.
    fn min_len(self) -> u32 {
        match self {
            ExtKind::Func => 8,
            ExtKind::Line | ExtKind::Core => 16,
        }
    }

    fn noun(self) -> &'static str {
        match self {
            ExtKind::Func => "function",
            ExtKind::Line => "line",
            ExtKind::Core => "relocation",
        }
    }
}

#[derive(Default)]
struct ExtHeader {
    blocks: [(u32, u32); 3],
}

/// `struct btf_ext_header`: the CO-RE relocation fields are present when
/// `hdr_len` makes room for them.
fn ext_header(f: &mut Fields<'_>, _: &()) -> Result<ExtHeader> {
    f.u16("magic").hex().emit()?;
    f.u8("version").emit()?;
    f.u8("flags").hex().emit()?;
    let hdr_len = f
        .u32("hdr_len")
        .desc("Length of this header; the offsets below count from its end")
        .emit()?;
    let mut h = ExtHeader::default();
    h.blocks[0] = (
        f.u32("func_info_off").hex().emit()?,
        f.u32("func_info_len").emit()?,
    );
    h.blocks[1] = (
        f.u32("line_info_off").hex().emit()?,
        f.u32("line_info_len").emit()?,
    );
    if u64::from(hdr_len) >= EXT_HEADER_CORE {
        h.blocks[2] = (
            f.u32("core_relo_off").hex().emit()?,
            f.u32("core_relo_len").emit()?,
        );
    }
    Ok(h)
}

/// `.BTF.ext`: the function and line information and the CO-RE
/// relocations of a BPF object, per code section, naming the types and
/// strings of its `.BTF` section. Layout from libbpf's `btf_ext_header`
/// and `btf_ext_info_sec` (`bpf_func_info`, `bpf_line_info`,
/// `bpf_core_relo`), written from memory and checked against clang 19's
/// output, `llvm-objdump -S` (which prints the line information) and the
/// program's source.
pub async fn ext(cx: Cx, ext: Ext) -> Result<()> {
    let span = ext.ext;
    let head = cx.read(span.sub(0, 8)).await?;
    let endian = match head.get(..2) {
        Some([0x9f, 0xeb]) => Endian::Little,
        Some([0xeb, 0x9f]) => Endian::Big,
        _ => return Err(Diagnostic::malformed("no BTF magic (0xeB9F)").at(span.sub(0, 2))),
    };
    let hdr_len = get::<u32>(&head, 4, endian)
        .ok_or_else(|| Diagnostic::truncated(span.sub(0, 8), to_u64(head.len())))?;
    if u64::from(hdr_len) < EXT_HEADER_V1 {
        return Err(Diagnostic::malformed(format!(
            "header length {hdr_len} is too short"
        )));
    }
    let hspan = span.sub(0, u64::from(hdr_len).min(EXT_HEADER_CORE));
    cx.emit(struct_node("Header", hspan, endian, (), ext_header));
    let h = parse(&cx, hspan, endian, &(), ext_header).await?;
    let btf = match ext.btf {
        Some(b) => open_on(&cx, b, ext.base).await.ok().map(|(_, btf, _)| btf),
        None => None,
    };
    if btf.is_none() {
        cx.diag(Diagnostic::note(
            "no usable .BTF section: names are shown as string offsets and types as IDs",
        ));
    }
    let shared = Arc::new(ExtCtx {
        endian,
        btf,
        code: ext.code,
    });
    let blocks = [
        ("Function Information", ExtKind::Func),
        ("Line Information", ExtKind::Line),
        ("CO-RE Relocations", ExtKind::Core),
    ];
    let mut end = u64::from(hdr_len);
    for ((title, kind), (off, len)) in blocks.into_iter().zip(h.blocks) {
        if len == 0 {
            continue;
        }
        let start = u64::from(hdr_len).saturating_add(u64::from(off));
        let block = span.sub(start, u64::from(len));
        end = end.max(block.end().saturating_sub(span.offset));
        let mut node = Node::new(title)
            .span(block)
            .summary(size(block.len))
            .lazy(ext_sections, (shared.clone(), kind, block));
        if block.len < u64::from(len) {
            node = node.diag(Diagnostic::truncated(
                span.sub(start, u64::from(len)),
                block.len,
            ));
        }
        cx.emit(node);
    }
    if end < span.len {
        cx.emit(Node::new("Trailing Data").span(span.tail(end)));
    }
    Ok(())
}

/// One block of `.BTF.ext`: the record size, then per code section its
/// name, its record count and its records (`struct btf_ext_info_sec`).
async fn ext_sections(cx: Cx, (shared, kind, block): (Arc<ExtCtx>, ExtKind, Span)) -> Result<()> {
    let b = cx.read(block.sub(0, 4)).await?;
    let rec_size = get::<u32>(&b, 0, shared.endian)
        .ok_or_else(|| Diagnostic::truncated(block.sub(0, 4), to_u64(b.len())))?;
    let mut size_node = Node::new("Record Size")
        .span(block.sub(0, 4))
        .value(uint(rec_size, 32))
        .summary(plural(rec_size, "byte"));
    let short = rec_size < kind.min_len();
    if short {
        size_node = size_node.diag(Diagnostic::malformed(format!(
            "records are shorter than the {} bytes they hold",
            kind.min_len()
        )));
    }
    cx.emit(size_node);
    if short {
        return Ok(());
    }
    let index = match &shared.btf {
        Some(btf) => Some(index(&cx, btf).await),
        None => None,
    };
    let mut pos = 4u64;
    while pos < block.len {
        let hspan = block.sub(pos, 8);
        let b = cx.read(hspan).await?;
        let (Some(name_off), Some(count)) = (
            get::<u32>(&b, 0, shared.endian),
            get::<u32>(&b, 4, shared.endian),
        ) else {
            cx.diag(Diagnostic::truncated(hspan, to_u64(b.len())));
            break;
        };
        let len = u64::from(count).saturating_mul(u64::from(rec_size));
        let records = block.sub(pos.saturating_add(8), len);
        let name = ext_name(&cx, &shared, index.as_deref(), name_off).await;
        let mut node = Node::new(name.clone())
            .span(block.sub(pos, len.saturating_add(8)))
            .summary(plural(count, kind.noun()));
        if records.len < len {
            node = node.diag(Diagnostic::truncated(
                block.sub(pos.saturating_add(8), len),
                records.len,
            ));
        }
        let code = shared
            .code
            .iter()
            .find(|(n, _)| *n == name)
            .map(|&(_, s)| s);
        let state = ExtBlock {
            shared: shared.clone(),
            kind,
            rec_size,
            records,
            code,
        };
        cx.push(node.lazy(ext_records, state)).await;
        pos = pos.saturating_add(8).saturating_add(len);
    }
    Ok(())
}

/// The records of one code section.
#[derive(Clone)]
struct ExtBlock {
    shared: Arc<ExtCtx>,
    kind: ExtKind,
    rec_size: u32,
    records: Span,
    /// The code section the records point into, if the object has it.
    code: Option<Span>,
}

/// A name from the `.BTF` strings, or its offset.
async fn ext_name(cx: &Cx, shared: &ExtCtx, index: Option<&Index>, off: u32) -> String {
    match (&shared.btf, index) {
        (Some(btf), Some(index)) => name_or_offset(cx, btf, index, off).await,
        _ => format!("(name at {off:#x})"),
    }
}

/// `[id] spelling` and where the type is, or the bare ID without `.BTF`.
async fn ext_type(
    cx: &Cx,
    shared: &ExtCtx,
    index: Option<&Index>,
    id: u32,
) -> (String, Option<Span>) {
    match (&shared.btf, index) {
        (Some(btf), Some(index)) => ref_value(cx, btf, index, id).await,
        _ => (format!("[{id}]"), None),
    }
}

fn insn_label(insn_off: u32) -> String {
    if insn_off.is_multiple_of(INSN_LEN) {
        format!("insn {}", insn_off / INSN_LEN)
    } else {
        format!("byte {insn_off:#x}")
    }
}

async fn ext_records(cx: Cx, blk: ExtBlock) -> Result<()> {
    let shared = &blk.shared;
    let index = match &shared.btf {
        Some(btf) => Some(index(&cx, btf).await),
        None => None,
    };
    let index = index.as_deref();
    let width = u64::from(blk.rec_size);
    let count = blk.records.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let rspan = blk.records.sub_exact(i.saturating_mul(width), width)?;
        let b = cx.read(rspan.sub(0, u64::from(blk.kind.min_len()))).await?;
        let w = |off: usize| get::<u32>(&b, off, shared.endian).unwrap_or(0);
        let insn = w(0);
        let summary = match blk.kind {
            ExtKind::Func => ext_type(&cx, shared, index, w(4)).await.0,
            ExtKind::Line => {
                let file = ext_name(&cx, shared, index, w(4)).await;
                let line = ext_name(&cx, shared, index, w(8)).await;
                let lc = w(12);
                format!("{file}:{}:{}: {}", lc >> 10, lc & 0x3ff, line.trim())
            }
            ExtKind::Core => {
                let kind = w(12);
                let access = ext_name(&cx, shared, index, w(8)).await;
                let what = core_target(&cx, shared, index, w(4), &access, kind).await;
                format!(
                    "{} {what} \"{access}\"",
                    lookup(CORE_RELO_KINDS, kind.into()).unwrap_or("unknown kind")
                )
            }
        };
        let mut node = Node::new(insn_label(insn))
            .span(rspan)
            .summary(crate::formats::util::fmt::clip(&summary, SPELL_MAX))
            .lazy(ext_record_fields, (blk.clone(), rspan));
        if let Some(code) = blk.code {
            node = node.target(code.sub(u64::from(insn), u64::from(INSN_LEN)));
        }
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn ext_record_fields(cx: Cx, (blk, span): (ExtBlock, Span)) -> Result<()> {
    let shared = &blk.shared;
    let index = match &shared.btf {
        Some(btf) => Some(index(&cx, btf).await),
        None => None,
    };
    let index = index.as_deref();
    let known = u64::from(blk.kind.min_len());
    let b = cx.read(span.sub(0, known)).await?;
    let w = |off: usize| get::<u32>(&b, off, shared.endian).unwrap_or(0);
    let block = cx.block(span.sub(0, known)).await?;
    let mut f = Fields::emitting(&cx, &block, shared.endian);
    let mut insn = f.u32("insn_off").hex().summary(insn_label(w(0)));
    if let Some(code) = blk.code {
        insn = insn.target(code.sub(u64::from(w(0)), u64::from(INSN_LEN)));
    }
    insn.emit()?;
    match blk.kind {
        ExtKind::Func => {
            let r = ext_type(&cx, shared, index, w(4)).await;
            type_id_field(&mut f, "type_id", r)?;
        }
        ExtKind::Line => {
            let file = ext_name(&cx, shared, index, w(4)).await;
            let line = ext_name(&cx, shared, index, w(8)).await;
            f.u32("file_name_off").hex().summary(file).emit()?;
            f.u32("line_off").hex().summary(line).emit()?;
            f.u32("line_col")
                .hex()
                .with(|&v, node| node.summary(format!("line {}, column {}", v >> 10, v & 0x3ff)))
                .emit()?;
        }
        ExtKind::Core => {
            let r = ext_type(&cx, shared, index, w(4)).await;
            let access = ext_name(&cx, shared, index, w(8)).await;
            type_id_field(&mut f, "type_id", r)?;
            f.u32("access_str_off").hex().summary(access).emit()?;
            f.u32("kind").enumeration(CORE_RELO_KINDS).emit()?;
        }
    }
    if span.len > known {
        cx.emit(
            Node::new("Rest")
                .span(span.tail(known))
                .desc("Record fields this version does not know"),
        );
    }
    Ok(())
}

/// The type, after typedefs and qualifiers, that type `id` names.
async fn strip_type(cx: &Cx, btf: &Btf, index: &Index, mut id: u32) -> Option<(TypeHead, Span)> {
    for _ in 0..SPELL_STEPS {
        let (head, span) = ref_head(cx, btf, index, id).await?;
        match head.kind {
            KIND_TYPEDEF | KIND_CONST | KIND_VOLATILE | KIND_RESTRICT | KIND_TYPE_TAG => {
                id = head.size_type;
            }
            _ => return Some((head, span)),
        }
    }
    None
}

/// What a CO-RE relocation is about, from its root type and access string:
/// `struct task.sched.flags`, `struct task`, `MODE_B of enum mode`.
async fn core_target(
    cx: &Cx,
    shared: &ExtCtx,
    index: Option<&Index>,
    id: u32,
    access: &str,
    kind: u32,
) -> String {
    let (Some(btf), Some(index)) = (&shared.btf, index) else {
        return format!("[{id}]");
    };
    let root = c_type(cx, btf, index, id).await;
    let accessors: Option<Vec<u32>> = access
        .split(':')
        .take(ACCESS_STEPS)
        .map(|a| a.parse().ok())
        .collect();
    let Some(accessors) = accessors else {
        return root;
    };
    match kind {
        // Type-based: the access string is "0".
        6..=9 | 12 => root,
        // Enumerator-based: the index of the value.
        10 | 11 => {
            let Some(&n) = accessors.first() else {
                return root;
            };
            let value = match strip_type(cx, btf, index, id).await {
                Some((head, span))
                    if matches!(head.kind, KIND_ENUM | KIND_ENUM64) && n < u32::from(head.vlen) =>
                {
                    let width: u64 = if head.kind == KIND_ENUM { 8 } else { 12 };
                    let at = TYPE_LEN.saturating_add(u64::from(n).saturating_mul(width));
                    let b = cx.read(span.sub(at, 4)).await.unwrap_or_default();
                    match get::<u32>(&b, 0, btf.endian) {
                        Some(off) => Some(name_or_offset(cx, btf, index, off).await),
                        None => None,
                    }
                }
                _ => None,
            };
            match value {
                Some(v) => format!("{v} of {root}"),
                None => format!("value {n} of {root}"),
            }
        }
        // Field-based: an index into the root pointer, then members and
        // array elements.
        _ => {
            let mut s = root;
            let mut rest = accessors.iter();
            match rest.next() {
                Some(&0) | None => {}
                Some(&n) => s.push_str(&format!("[{n}]")),
            }
            let mut cur = id;
            for &a in rest {
                let Some((head, span)) = strip_type(cx, btf, index, cur).await else {
                    break;
                };
                match head.kind {
                    KIND_STRUCT | KIND_UNION if a < u32::from(head.vlen) => {
                        let at = TYPE_LEN.saturating_add(u64::from(a).saturating_mul(12));
                        let b = cx.read(span.sub(at, 8)).await.unwrap_or_default();
                        let name_off = get::<u32>(&b, 0, btf.endian).unwrap_or(0);
                        let n = name_or_offset(cx, btf, index, name_off).await;
                        s.push('.');
                        s.push_str(&n);
                        cur = get::<u32>(&b, 4, btf.endian).unwrap_or(0);
                    }
                    KIND_ARRAY => {
                        let b = cx.read(span.sub(TYPE_LEN, 4)).await.unwrap_or_default();
                        s.push_str(&format!("[{a}]"));
                        cur = get::<u32>(&b, 0, btf.endian).unwrap_or(0);
                    }
                    _ => {
                        s.push_str(&format!(" (accessor {a} does not fit)"));
                        break;
                    }
                }
            }
            s
        }
    }
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    fn head(bytes: &[u8]) -> bool {
        probe(&Head {
            data: bytes,
            tail: bytes,
            len: to_u64(bytes.len()),
            len_known: true,
        })
    }

    #[test]
    fn probe_rejects_short_magic() {
        assert!(!head(&[0x9f, 0xeb, 1, 0]));
        let mut h = vec![0x9f, 0xeb, 1, 0, 24, 0, 0, 0];
        h.extend_from_slice(&[0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0]);
        h.push(0);
        assert!(head(&h));
        // A string section that does not start with the empty string.
        h[24] = b'a';
        assert!(!head(&h));
    }

    /// Split BTF: strings that continue a base's (not starting with the
    /// empty string, or none at all) pass only with an exact layout.
    #[test]
    fn probe_accepts_exact_split_btf() {
        // One FUNC type (12 bytes) named at base offset 0x203886, strings
        // "crc16\0": a kernel module's /sys/kernel/btf file in miniature.
        let mut h = vec![0x9f, 0xeb, 1, 0, 24, 0, 0, 0];
        h.extend_from_slice(&[0, 0, 0, 0, 12, 0, 0, 0, 12, 0, 0, 0, 6, 0, 0, 0]);
        h.extend_from_slice(&[0x86, 0x38, 0x20, 0, 0, 0, 0, 0x0c, 0x58, 0xa3, 0, 0]);
        h.extend_from_slice(b"crc16\0");
        assert!(head(&h));
        // Anything after the strings: no longer exact.
        let mut longer = h.clone();
        longer.push(0);
        assert!(!head(&longer));
        // No strings at all: exact, with types.
        let mut bare = h[..36].to_vec();
        bare[20] = 0;
        assert!(head(&bare));
        // Neither types nor strings.
        assert!(!head(&bare[..24]));
    }
}
