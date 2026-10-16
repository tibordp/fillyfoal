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
//! Split BTF (kernel modules) continues the numbering and the string offsets
//! of a base BTF (vmlinux) that is not in the file: its IDs are shown as if
//! it started at 1, and names whose offsets fall past its own strings are
//! shown as offsets.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
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
        || str_len == 0
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
    // The string section starts with the empty string.
    let strings = u64::from(hdr_len).saturating_add(u64::from(str_off));
    match h.data.get(to_usize(strings)) {
        Some(&b) => b == 0,
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
}

/// The offset of each type (ID 1 first) in the type section.
struct Index {
    offsets: Vec<u32>,
    /// Why the walk stopped early, if it did.
    error: Option<Diagnostic>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 2)).await?;
    let endian = if magic == [0xeb, 0x9f] {
        Endian::Big
    } else {
        Endian::Little
    };
    let hspan = file.sub(0, HEADER_LEN);
    cx.emit(BtfHeader::node("Header", hspan, endian));
    let h: BtfHeader = crate::dsl::read_record(&cx, hspan, endian).await?;
    let base = u64::from(h.hdr_len);
    if base > HEADER_LEN {
        cx.emit(
            Node::new("Header Extension")
                .span(file.sub(HEADER_LEN, base.saturating_sub(HEADER_LEN)))
                .desc("Header fields this version does not know"),
        );
    }
    let types = file.sub(
        base.saturating_add(u64::from(h.type_off)),
        u64::from(h.type_len),
    );
    let strings = file.sub(
        base.saturating_add(u64::from(h.str_off)),
        u64::from(h.str_len),
    );
    let btf = Btf {
        endian,
        types,
        strings,
    };
    let mut types_node = Node::new("Types")
        .span(types)
        .summary(size(types.len))
        .lazy(type_list, btf.clone());
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
        "BTF v{}, {}-endian, {} of types, {} of strings",
        h.version,
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

/// Walks the type section once, recording where each type starts.
async fn index(cx: &Cx, btf: &Btf) -> Arc<Index> {
    if let Some(index) = cx.cached::<Index>(btf.types, "btf-index") {
        return index;
    }
    const WINDOW: u64 = 64 * 1024;
    let mut offsets = Vec::new();
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
    let index = Arc::new(Index { offsets, error });
    cx.cache(btf.types, "btf-index", index.clone());
    index
}

/// The span of type `id` (from 1), if it exists.
fn type_span(btf: &Btf, index: &Index, id: u32) -> Option<Span> {
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
/// is outside it (split BTF naming its base's strings).
async fn name(cx: &Cx, btf: &Btf, off: u32) -> Option<String> {
    if off == 0 {
        return Some(String::new());
    }
    string_at(cx, btf.strings.sub(0, btf.strings.len), u64::from(off))
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

async fn name_or_offset(cx: &Cx, btf: &Btf, off: u32) -> String {
    match name(cx, btf, off).await {
        Some(s) if s.is_empty() => "(anon)".to_string(),
        Some(s) => s,
        None => format!("(name at {off:#x})"),
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

/// `[id] label` for a reference to type `id`.
async fn type_ref(cx: &Cx, btf: &Btf, index: &Index, id: u32) -> String {
    if id == 0 {
        return "[0] void".to_string();
    }
    let Some(span) = type_span(btf, index, id) else {
        return format!("[{id}] (no such type)");
    };
    match read_head(cx, btf, span).await {
        Ok(head) => {
            let n = name(cx, btf, head.name_off).await.unwrap_or_default();
            format!("[{id}] {}", label(&head, &n))
        }
        Err(_) => format!("[{id}]"),
    }
}

/// What a type ID field shows: the type it refers to, and where it is.
async fn ref_value(cx: &Cx, btf: &Btf, index: &Index, id: u32) -> (String, Option<Span>) {
    (
        type_ref(cx, btf, index, id).await,
        type_span(btf, index, id),
    )
}

async fn type_list(cx: Cx, btf: Btf) -> Result<()> {
    let index = index(&cx, &btf).await;
    let count = to_u64(index.offsets.len());
    cx.set_count(Count::Exact(count));
    let mut id = cx.resume::<u32>().unwrap_or(1);
    while u64::from(id) <= count {
        let at = id;
        cx.mark(move || at);
        let Some(span) = type_span(&btf, &index, id) else {
            break;
        };
        let node = if cx.skipping() {
            Node::new(format!("[{id}]")).span(span)
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
        Err(e) => return Node::new(format!("[{id}]")).span(span).diag(e),
    };
    let n = name_or_offset(cx, btf, head.name_off).await;
    let kind = kind_name(head.kind);
    let title = format!("[{id}] {kind} {n}");
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
    let n = name_or_offset(&cx, &btf, head.name_off).await;
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
                        name: lookup(FUNC_LINKAGE, head.vlen.into()),
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
                let n = name_or_offset(&cx, &btf, w(0)).await;
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
                let n = name_or_offset(&cx, &btf, w(0)).await;
                let raw = w(4);
                let value = if head.kind_flag {
                    int(i64::from(raw as i32), 32)
                } else {
                    uint(raw, 32)
                };
                Node::new(n).value(value)
            }
            KIND_ENUM64 => {
                let n = name_or_offset(&cx, &btf, w(0)).await;
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
                    let n = name_or_offset(&cx, &btf, name_off).await;
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
            let n = name_or_offset(&cx, &btf, w(0)).await;
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
            let n = name_or_offset(&cx, &btf, w(0)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("name_off").hex().summary(n).emit()?;
            if kind_flag {
                f.int::<i32>("val").emit()?;
            } else {
                f.u32("val").emit()?;
            }
        }
        KIND_ENUM64 => {
            let n = name_or_offset(&cx, &btf, w(0)).await;
            let mut f = Fields::emitting(&cx, &block, btf.endian);
            f.u32("name_off").hex().summary(n).emit()?;
            f.u32("val_lo32").hex().emit()?;
            f.u32("val_hi32").hex().emit()?;
        }
        KIND_FUNC_PROTO => {
            let n = name_or_offset(&cx, &btf, w(0)).await;
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
}
