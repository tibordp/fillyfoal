//! `__LINKEDIT` structures referenced by load commands: function starts,
//! data-in-code entries, chained fixups (with the chains walked), the
//! exports trie, rebase and bind opcode streams and linker optimization
//! hints.

use std::sync::Arc;

use super::tables::*;
use super::{Item, MachInfo, Macho, group};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::binutil::{NodeExt, Reader, cstrings, get_at};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag, lookup};

/// Longest symbol name assembled from trie edges.
const MAX_SYMBOL: usize = 4096;

/// A node for the bytes after the end of an opcode or delta stream.
async fn trailing(cx: &Cx, span: Span) -> Result<Option<Node>> {
    if span.len == 0 {
        return Ok(None);
    }
    let data = cx.read_avail(span.sub(0, 0x1_0000)).await?;
    let zeros = data.iter().all(|&b| b == 0);
    Ok(Some(
        Node::new(if zeros { "Padding" } else { "Trailing Data" })
            .span(span)
            .summary(size(span.len)),
    ))
}

// ---------------------------------------------------------------------------
// Function starts and data in code

pub(super) async fn function_starts(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let base = m.text_vmaddr();
    let mut addr = base;
    let mut index = 0u64;
    loop {
        let start = r.pos();
        let Some(delta) = r.uleb() else { break };
        if delta == 0 {
            r = Reader::at(&data, start);
            break;
        }
        addr = addr.saturating_add(delta);
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.progress_in(span, at.end());
        let mut node = Node::new(format!("[{index}]"))
            .span(at)
            .value(hex(addr, m.bits()))
            .summary(format!("+{delta:#x}"));
        if let Some(t) = m.vm_span(addr, 0) {
            node = node.target(t);
        }
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    if let Some(node) = trailing(&cx, span.tail(to_u64(r.pos()))).await? {
        cx.push(node.desc("The terminating zero and alignment padding"))
            .await;
    }
    cx.annotate(grouped_count(index, "function", "functions"));
    Ok(())
}

record! {
    struct DataInCode {
        offset: u32 "offset" .hex() .desc("File offset of the data, from the mach header"),
        length: u16 "length",
        kind: u16 "kind" .enumeration(DICE_KIND),
    }
}

pub(super) async fn data_in_code(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let n = span.len / DataInCode::SIZE;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(DataInCode::SIZE), DataInCode::SIZE);
        let e = parse(&cx, at, m.endian, &(), DataInCode::layout).await?;
        cx.push(
            DataInCode::node(format!("[{i}]"), at, m.endian)
                .summary(format!(
                    "{} bytes of {} at {:#x}",
                    e.length,
                    name_or(DICE_KIND, e.kind.into(), "kind"),
                    e.offset
                ))
                .target(m.file().sub(e.offset.into(), e.length.into())),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chained fixups: decoding

/// Pointer authentication (arm64e).
#[derive(Clone, Copy, Debug)]
pub(super) struct Auth {
    key: u8,
    diversity: u16,
    addr_div: bool,
}

impl Auth {
    fn describe(&self) -> String {
        format!(
            "auth {}, diversity {:#x}{}",
            lookup(PAC_KEY, self.key.into()).unwrap_or("?"),
            self.diversity,
            if self.addr_div {
                ", address-diversified"
            } else {
                ""
            }
        )
    }
}

#[derive(Clone, Copy, Debug)]
pub(super) enum Fixup {
    Rebase {
        /// The target's virtual address.
        target: u64,
        high8: u8,
        auth: Option<Auth>,
        next: u64,
    },
    Bind {
        ordinal: u32,
        addend: i64,
        auth: Option<Auth>,
        next: u64,
    },
}

impl Fixup {
    fn next(&self) -> u64 {
        match self {
            Fixup::Rebase { next, .. } | Fixup::Bind { next, .. } => *next,
        }
    }
}

fn bits(raw: u64, shift: u32, width: u32) -> u64 {
    raw.checked_shr(shift).unwrap_or(0)
        & 1u64
            .checked_shl(width)
            .map_or(u64::MAX, |v| v.wrapping_sub(1))
}

/// Bytes between chain entries for each pointer format.
fn chain_stride(format: u16) -> u64 {
    match format {
        1 | 9 | 12 | 13 => 8,
        11 => 1,
        _ => 4,
    }
}

/// Size of the pointers of each format.
fn pointer_size(format: u16) -> u64 {
    match format {
        3..=5 => 4,
        _ => 8,
    }
}

/// Decodes a chained pointer; `base` is the image's load address (runtime
/// offsets are relative to it).
pub(super) fn decode_fixup(raw: u64, format: u16, base: u64) -> Option<Fixup> {
    let auth_of = |raw: u64| Auth {
        key: u8::try_from(bits(raw, 49, 2)).unwrap_or(0),
        diversity: u16::try_from(bits(raw, 32, 16)).unwrap_or(0),
        addr_div: bits(raw, 48, 1) != 0,
    };
    Some(match format {
        // ARM64E, ARM64E_KERNEL, ARM64E_USERLAND, ARM64E_FIRMWARE,
        // ARM64E_USERLAND24
        1 | 7 | 9 | 10 | 12 => {
            let next = bits(raw, 51, 11);
            let bind = bits(raw, 62, 1) != 0;
            let auth = bits(raw, 63, 1) != 0;
            let wide_ordinal = format == 12;
            let ordinal_bits = if wide_ordinal { 24 } else { 16 };
            match (auth, bind) {
                (true, false) => Fixup::Rebase {
                    target: base.saturating_add(bits(raw, 0, 32)),
                    high8: 0,
                    auth: Some(auth_of(raw)),
                    next,
                },
                (true, true) => Fixup::Bind {
                    ordinal: u32::try_from(bits(raw, 0, ordinal_bits)).unwrap_or(0),
                    addend: 0,
                    auth: Some(auth_of(raw)),
                    next,
                },
                (false, false) => {
                    let target = bits(raw, 0, 43);
                    Fixup::Rebase {
                        target: if matches!(format, 1 | 10) {
                            target
                        } else {
                            base.saturating_add(target)
                        },
                        high8: u8::try_from(bits(raw, 43, 8)).unwrap_or(0),
                        auth: None,
                        next,
                    }
                }
                (false, true) => Fixup::Bind {
                    ordinal: u32::try_from(bits(raw, 0, ordinal_bits)).unwrap_or(0),
                    addend: crate::formats::util::sound::sign_extend(bits(raw, 32, 19), 19),
                    auth: None,
                    next,
                },
            }
        }
        // 64, 64_OFFSET
        2 | 6 => {
            let next = bits(raw, 51, 12);
            if bits(raw, 63, 1) != 0 {
                Fixup::Bind {
                    ordinal: u32::try_from(bits(raw, 0, 24)).unwrap_or(0),
                    addend: i64::try_from(bits(raw, 24, 8)).unwrap_or(0),
                    auth: None,
                    next,
                }
            } else {
                let target = bits(raw, 0, 36);
                Fixup::Rebase {
                    target: if format == 6 {
                        base.saturating_add(target)
                    } else {
                        target
                    },
                    high8: u8::try_from(bits(raw, 36, 8)).unwrap_or(0),
                    auth: None,
                    next,
                }
            }
        }
        // 32, 32_FIRMWARE
        3 | 5 => {
            let next = bits(raw, 26, if format == 3 { 5 } else { 6 });
            if format == 3 && bits(raw, 31, 1) != 0 {
                Fixup::Bind {
                    ordinal: u32::try_from(bits(raw, 0, 20)).unwrap_or(0),
                    addend: i64::try_from(bits(raw, 20, 6)).unwrap_or(0),
                    auth: None,
                    next,
                }
            } else {
                Fixup::Rebase {
                    target: bits(raw, 0, 26),
                    high8: 0,
                    auth: None,
                    next,
                }
            }
        }
        // 32_CACHE
        4 => Fixup::Rebase {
            target: base.saturating_add(bits(raw, 0, 30)),
            high8: 0,
            auth: None,
            next: bits(raw, 30, 2),
        },
        // 64_KERNEL_CACHE, X86_64_KERNEL_CACHE
        8 | 11 => Fixup::Rebase {
            target: base.saturating_add(bits(raw, 0, 30)),
            high8: 0,
            auth: (bits(raw, 63, 1) != 0).then(|| auth_of(raw)),
            next: bits(raw, 51, 12),
        },
        _ => return None,
    })
}

/// What `LC_DYLD_CHAINED_FIXUPS` says, parsed once per image.
#[derive(Debug)]
pub(super) struct Chains {
    span: Span,
    imports_offset: u32,
    imports_count: u32,
    imports_format: u32,
    symbols_offset: u32,
    /// The pointer format of each segment with fixups.
    formats: Vec<Option<u16>>,
}

impl Chains {
    fn import_width(&self) -> u64 {
        match self.imports_format {
            2 => 8,
            3 => 16,
            _ => 4,
        }
    }
}

async fn chains(cx: &Cx, m: &MachInfo) -> Option<Arc<Chains>> {
    let (off, size) = m.chained_fixups?;
    let span = m.linkedit(off, size);
    if let Some(c) = cx.cached::<Chains>(span, "macho-chains") {
        return Some(c);
    }
    let head = cx.read_avail(span.sub(0, 28)).await.ok()?;
    let w = |at: u64| get_at::<u32>(&head, at, m.endian).unwrap_or(0);
    let mut c = Chains {
        span,
        imports_offset: w(8),
        symbols_offset: w(12),
        imports_count: w(16),
        imports_format: w(20),
        formats: Vec::new(),
    };
    let starts = span.tail(w(4).into());
    let count = cx.read_avail(starts.sub(0, 4)).await.ok()?;
    let count = get_at::<u32>(&count, 0, m.endian).unwrap_or(0);
    let count = to_u64(m.segments.len()).min(count.into()).min(4096);
    let offsets = cx
        .read_avail(starts.sub(4, count.saturating_mul(4)))
        .await
        .ok()?;
    for i in 0..to_u64(offsets.len()) / 4 {
        let offset = get_at::<u32>(&offsets, i.saturating_mul(4), m.endian).unwrap_or(0);
        if offset == 0 {
            c.formats.push(None);
            continue;
        }
        let format = cx
            .read_avail(starts.tail(offset.into()).sub(6, 2))
            .await
            .ok()?;
        c.formats.push(get_at::<u16>(&format, 0, m.endian));
    }
    let c = Arc::new(c);
    cx.cache(span, "macho-chains", c.clone());
    Some(c)
}

/// An import of the chained fixups: its symbol and library.
async fn import_name(cx: &Cx, m: &MachInfo, c: &Chains, ordinal: u32) -> Option<(String, String)> {
    if ordinal >= c.imports_count {
        return None;
    }
    let width = c.import_width();
    let at = c.span.sub(
        u64::from(c.imports_offset).saturating_add(u64::from(ordinal).saturating_mul(width)),
        width,
    );
    let data = cx.read(at).await.ok()?;
    let (library, name) = import_fields(&data, c.imports_format, m.endian);
    let symbols = c.span.tail(c.symbols_offset.into());
    if name >= symbols.len {
        return None;
    }
    let (s, _) = cx.cstr(symbols.tail(name).sub(0, 4096)).await.ok()?;
    Some((s, m.dylib(library)))
}

/// `(library ordinal, name offset)` of an import entry. Special ordinals
/// (main executable, flat and weak lookup) become 0xff, 0xfe and 0xfd.
fn import_fields(data: &[u8], format: u32, endian: Endian) -> (u64, u64) {
    if format == 3 {
        let raw = get_at::<u64>(data, 0, endian).unwrap_or(0);
        let ordinal = raw & 0xffff;
        let ordinal = if ordinal >= 0xfff0 {
            ordinal & 0xff
        } else {
            ordinal
        };
        (ordinal, raw >> 32)
    } else {
        let raw = get_at::<u32>(data, 0, endian).unwrap_or(0);
        (u64::from(raw & 0xff), u64::from(raw >> 9))
    }
}

/// A pointer-sized value in the image, decoded: a chained fixup where the
/// image has them, else a plain address.
pub(super) struct Pointer {
    value: Value,
    pub summary: String,
    /// The address it points at, when it is a rebase or a plain pointer.
    pub address: Option<u64>,
    target: Option<Span>,
}

impl Pointer {
    pub fn apply(&self, node: Node) -> Node {
        let node = node
            .value(self.value.clone())
            .maybe_summary(self.summary.clone());
        match self.target {
            Some(t) => node.target(t),
            None => node,
        }
    }
}

pub(super) async fn pointer(cx: &Cx, m: &MachInfo, addr: u64, raw: u64) -> Pointer {
    if raw != 0
        && let Some(c) = chains(cx, m).await
        && let Some(format) = m
            .vm_index
            .find(addr)
            .and_then(|seg| c.formats.get(seg).copied().flatten())
        && let Some(fixup) = decode_fixup(raw, format, m.text_vmaddr())
    {
        return fixup_pointer(cx, m, &c, fixup).await;
    }
    let target = m.vm_span(raw, 0);
    Pointer {
        value: hex(raw, m.bits()),
        summary: if target.is_some() {
            m.describe(raw)
        } else {
            String::new()
        },
        address: target.map(|_| raw),
        target,
    }
}

async fn fixup_pointer(cx: &Cx, m: &MachInfo, c: &Chains, fixup: Fixup) -> Pointer {
    match fixup {
        Fixup::Rebase {
            target,
            high8,
            auth,
            ..
        } => {
            let mut summary = format!("rebase → {}", m.describe(target));
            if high8 != 0 {
                summary.push_str(&format!(", high byte {high8:#04x}"));
            }
            if let Some(a) = auth {
                summary.push_str(&format!(", {}", a.describe()));
            }
            Pointer {
                value: hex(target, 64),
                summary,
                address: Some(target),
                target: m.vm_span(target, 0),
            }
        }
        Fixup::Bind {
            ordinal,
            addend,
            auth,
            ..
        } => {
            let (value, mut summary) = match import_name(cx, m, c, ordinal).await {
                Some((name, library)) => {
                    (text(name), format!("bind import {ordinal} from {library}"))
                }
                None => (uint(ordinal, 32), format!("bind import {ordinal}")),
            };
            if addend != 0 {
                summary.push_str(&format!(", addend {addend:#x}"));
            }
            if let Some(a) = auth {
                summary.push_str(&format!(", {}", a.describe()));
            }
            Pointer {
                value,
                summary,
                address: None,
                target: None,
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Chained fixups: structure

record! {
    struct FixupsHeader {
        version: u32 "fixups_version",
        starts_offset: u32 "starts_offset" .hex() .desc("Offset of dyld_chained_starts_in_image"),
        imports_offset: u32 "imports_offset" .hex(),
        symbols_offset: u32 "symbols_offset" .hex(),
        imports_count: u32 "imports_count",
        imports_format: u32 "imports_format" .enumeration(CHAINED_IMPORT_FORMAT),
        symbols_format: u32 "symbols_format" .desc("0: uncompressed, 1: zlib"),
    }
}

pub(super) async fn chained_fixups(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let endian = m.endian;
    let header = span.sub(0, FixupsHeader::SIZE);
    let h = parse(&cx, header, endian, &(), FixupsHeader::layout).await?;
    cx.emit(FixupsHeader::node("Header", header, endian).summary(format!("version {}", h.version)));
    cx.annotate(format!(
        "{}, {}",
        grouped_count(h.imports_count, "import", "imports"),
        name_or(CHAINED_IMPORT_FORMAT, h.imports_format.into(), "format")
    ));
    // The parts in file order: starts, imports, symbol names.
    let starts_end = [h.imports_offset, h.symbols_offset]
        .into_iter()
        .filter(|&o| o > h.starts_offset)
        .min()
        .map_or(span.len, u64::from);
    let starts = span.sub(
        h.starts_offset.into(),
        starts_end.saturating_sub(h.starts_offset.into()),
    );
    cx.emit(
        Node::new("Starts in Image")
            .span(starts)
            .desc("Where each segment's chains begin")
            .lazy(starts_in_image, (m.clone(), starts)),
    );
    let width: u64 = match h.imports_format {
        1 => 4,
        2 => 8,
        3 => 16,
        _ => {
            cx.emit(Node::new("Imports").diag(Diagnostic::unsupported(format!(
                "imports format {}",
                h.imports_format
            ))));
            return Ok(());
        }
    };
    let imports = span.sub(
        h.imports_offset.into(),
        u64::from(h.imports_count).saturating_mul(width),
    );
    let symbols = span.tail(h.symbols_offset.into());
    let node = Node::new("Imports").span(imports).summary(grouped_count(
        h.imports_count,
        "import",
        "imports",
    ));
    if h.symbols_format == 0 {
        cx.emit(node.lazy(
            chained_imports,
            (m.clone(), imports, symbols, h.imports_format),
        ));
        cx.emit(
            Node::new("Symbol Names")
                .span(symbols)
                .summary(size(symbols.len))
                .lazy(cstrings, symbols),
        );
    } else {
        cx.emit(node.diag(Diagnostic::unsupported("compressed symbol names")));
        cx.emit(
            Node::new("Symbol Names")
                .span(symbols)
                .diag(Diagnostic::unsupported("zlib-compressed symbol names")),
        );
    }
    Ok(())
}

async fn chained_imports(
    cx: Cx,
    (m, imports, symbols, format): (Macho, Span, Span, u32),
) -> Result<()> {
    let width: u64 = match format {
        1 => 4,
        2 => 8,
        _ => 16,
    };
    let n = imports.len.checked_div(width).unwrap_or(0);
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = imports.sub(i.saturating_mul(width), width);
        let data = cx.read(at).await?;
        let (ordinal, name) = import_fields(&data, format, m.endian);
        let (weak, addend) = if format == 3 {
            (
                get_at::<u64>(&data, 0, m.endian).unwrap_or(0) & 0x1_0000 != 0,
                get_at::<i64>(&data, 8, m.endian).unwrap_or(0),
            )
        } else {
            let raw = get_at::<u32>(&data, 0, m.endian).unwrap_or(0);
            let addend = if format == 2 {
                get_at::<i32>(&data, 4, m.endian).unwrap_or(0).into()
            } else {
                0
            };
            (raw & 0x100 != 0, addend)
        };
        let mut summary = format!("import {i} from {}", m.dylib(ordinal));
        if weak {
            summary.push_str(", weak");
        }
        if addend != 0 {
            summary.push_str(&format!(", addend {addend:#x}"));
        }
        let word = at.sub(0, if format == 3 { 8 } else { 4 });
        let mut fields = vec![
            Node::new("lib_ordinal")
                .span(word)
                .value(uint(ordinal, 16))
                .summary(m.dylib(ordinal)),
            Node::new("weak_import").span(word).value(Value::Bool(weak)),
            Node::new("name_offset")
                .span(word)
                .value(hex(name, 32))
                .target(symbols.sub(name, 0)),
        ];
        if format != 1 {
            fields.push(
                Node::new("addend")
                    .span(at.tail(if format == 3 { 8 } else { 4 }))
                    .value(Value::Int {
                        value: addend,
                        bits: if format == 3 { 64 } else { 32 },
                    }),
            );
        }
        let node = match crate::formats::util::binutil::string_at(&cx, symbols, name).await {
            Ok((s, target)) => group(s, at, fields).target(target),
            Err(e) => group(format!("#{i}"), at, fields).diag(e),
        };
        cx.push(node.summary(summary)).await;
    }
    Ok(())
}

async fn starts_in_image(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let endian = m.endian;
    let head = cx.block(span.sub(0, 4)).await?;
    let n = Fields::emitting(&cx, &head, endian)
        .u32("seg_count")
        .desc("Number of segments (all of them, in load command order)")
        .emit()?;
    let table = span.sub(4, u64::from(n).saturating_mul(4));
    let offsets = cx.read_avail(table).await?;
    for i in 0..to_u64(offsets.len()) / 4 {
        let offset = get_at::<u32>(&offsets, i.saturating_mul(4), endian).unwrap_or(0);
        let entry = table.sub(i.saturating_mul(4), 4);
        let seg_name = m
            .segments
            .get(to_usize(i))
            .map_or_else(|| format!("segment {i}"), |s| s.label());
        let mut field = Node::new(format!("seg_info_offset[{i}]"))
            .span(entry)
            .value(hex(offset, 32))
            .summary(seg_name.clone());
        if offset == 0 {
            cx.emit(field.summary(format!("{seg_name}: no fixups")));
            continue;
        }
        let seg = span.tail(offset.into());
        field = field.target(seg.sub(0, 0));
        cx.emit(field);
        let size = cx.read_avail(seg.sub(0, 4)).await?;
        let size = get_at::<u32>(&size, 0, endian).unwrap_or(0);
        let seg = seg.sub(0, size.into());
        let data = cx.read_avail(seg.sub(0, 22)).await?;
        let format = get_at::<u16>(&data, 6, endian).unwrap_or(0);
        let pages = get_at::<u16>(&data, 20, endian).unwrap_or(0);
        cx.emit(
            Node::new(seg_name)
                .span(seg)
                .summary(format!(
                    "{}, {}",
                    name_or(CHAINED_POINTER_FORMAT, format.into(), "format"),
                    grouped_count(pages, "page", "pages")
                ))
                .lazy(starts_in_segment, (m.clone(), seg, to_usize(i))),
        );
    }
    Ok(())
}

fn starts_in_segment_layout(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16, u16)> {
    f.u32("size").hex().emit()?;
    let page_size = f.u16("page_size").hex().emit()?;
    let format = f
        .u16("pointer_format")
        .enumeration(CHAINED_POINTER_FORMAT)
        .emit()?;
    f.u64("segment_offset")
        .hex()
        .desc("Offset of the segment from the image's load address")
        .emit()?;
    f.u32("max_valid_pointer")
        .hex()
        .desc("For 32-bit formats: larger values are not pointers")
        .emit()?;
    let pages = f.u16("page_count").emit()?;
    Ok((page_size, format, pages))
}

async fn starts_in_segment(cx: Cx, (m, span, segment): (Macho, Span, usize)) -> Result<()> {
    let head = cx.block(span.sub(0, 22)).await?;
    let (page_size, format, pages) =
        starts_in_segment_layout(&mut Fields::emitting(&cx, &head, m.endian), &())?;
    let starts = span.tail(22);
    cx.emit(
        Node::new("page_start")
            .span(starts)
            .summary(grouped_count(pages, "page", "pages"))
            .desc("Offset of the first fixup in each page (0xffff: none)")
            .lazy(page_starts, (m.clone(), starts, pages)),
    );
    cx.emit(
        Node::new("Fixups")
            .span(
                m.segments
                    .get(segment)
                    .map_or(span.sub(0, 0), |s| m.file().sub(s.fileoff, s.filesize)),
            )
            .summary(name_or(CHAINED_POINTER_FORMAT, format.into(), "format"))
            .desc("The chains walked: every pointer the loader rebases or binds")
            .lazy(
                fixups,
                (m.clone(), starts, segment, page_size, format, pages),
            ),
    );
    Ok(())
}

async fn page_starts(cx: Cx, (m, span, pages): (Macho, Span, u16)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let n = to_u64(data.len()) / 2;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let v = get_at::<u16>(&data, i.saturating_mul(2), m.endian).unwrap_or(0);
        let label = if i < u64::from(pages) {
            format!("Page {i}")
        } else {
            format!("Overflow {}", i.saturating_sub(pages.into()))
        };
        let node = Node::new(label).span(span.sub(i.saturating_mul(2), 2));
        cx.push(match v {
            0xffff => node.value(text("none")),
            v if v & 0x8000 != 0 => node
                .value(hex(v, 16))
                .summary("several chains: index into the overflow entries"),
            v => node.value(hex(v, 16)),
        })
        .await;
    }
    Ok(())
}

/// Walks the chains of one segment, pushing a node per fixup.
async fn fixups(
    cx: Cx,
    (m, starts, segment, page_size, format, pages): (Macho, Span, usize, u16, u16, u16),
) -> Result<()> {
    let seg = m
        .segments
        .get(segment)
        .ok_or_else(|| Diagnostic::malformed("fixups for a segment that does not exist"))?;
    let table = cx.read_avail(starts).await?;
    let entry = |i: u64| get_at::<u16>(&table, i.saturating_mul(2), m.endian);
    let stride = chain_stride(format);
    let size = pointer_size(format);
    let page_size = u64::from(page_size);
    let mut total = 0u64;
    for page in 0..u64::from(pages) {
        let Some(start) = entry(page) else { break };
        if start == 0xffff {
            continue;
        }
        let mut chain_starts = Vec::new();
        if start & 0x8000 != 0 && size == 4 {
            // DYLD_CHAINED_PTR_START_MULTI: a list in the overflow area,
            // the last entry flagged DYLD_CHAINED_PTR_START_LAST.
            let mut i = u64::from(start & 0x7fff);
            while let Some(e) = entry(i) {
                chain_starts.push(u64::from(e & 0x3fff));
                if e & 0x8000 != 0 || chain_starts.len() >= 0x4000 {
                    break;
                }
                i = i.saturating_add(1);
            }
        } else {
            chain_starts.push(start.into());
        }
        let page_start = page.saturating_mul(page_size);
        let page_end = page_start.saturating_add(page_size);
        for first in chain_starts {
            let mut offset = page_start.saturating_add(first);
            loop {
                let at = m.file().sub(seg.fileoff.saturating_add(offset), size);
                let data = cx.read(at).await?;
                let raw = if size == 8 {
                    get_at::<u64>(&data, 0, m.endian).unwrap_or(0)
                } else {
                    get_at::<u32>(&data, 0, m.endian).map_or(0, u64::from)
                };
                let addr = seg.vmaddr.saturating_add(offset);
                let Some(fixup) = decode_fixup(raw, format, m.text_vmaddr()) else {
                    return Err(Diagnostic::unsupported(format!(
                        "pointer format {}",
                        name_or(CHAINED_POINTER_FORMAT, format.into(), "")
                    )));
                };
                let p = match chains(&cx, &m).await {
                    Some(c) => fixup_pointer(&cx, &m, &c, fixup).await,
                    None => pointer(&cx, &m, addr, raw).await,
                };
                let next = fixup.next();
                let node = p
                    .apply(Node::new(m.describe(addr)).span(at))
                    .desc(match next {
                        0 => "Last fixup of its chain",
                        _ => "The next fixup follows after `next` strides",
                    });
                cx.push(node).await;
                total = total.saturating_add(1);
                if next == 0 {
                    break;
                }
                offset = offset.saturating_add(next.saturating_mul(stride));
                if offset >= page_end {
                    cx.diag(Diagnostic::malformed(format!(
                        "chain in page {page} runs past the end of the page"
                    )));
                    break;
                }
            }
        }
    }
    cx.annotate(format!(
        "{}, {}",
        grouped_count(total, "fixup", "fixups"),
        name_or(CHAINED_POINTER_FORMAT, format.into(), "format")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Exports trie

const EXPORT_FLAGS: FlagTable = &[
    crate::value::field(0x3, 0x1, "THREAD_LOCAL"),
    crate::value::field(0x3, 0x2, "ABSOLUTE"),
    flag(0x4, "WEAK_DEFINITION"),
    flag(0x8, "REEXPORT"),
    flag(0x10, "STUB_AND_RESOLVER"),
    flag(0x20, "STATIC_RESOLVER"),
];

/// A NUL-terminated string of at most `max` bytes.
fn bounded_cstr<'a>(r: &mut Reader<'a>, max: usize) -> Option<&'a [u8]> {
    let n = r
        .rest()
        .iter()
        .take(max.saturating_add(1))
        .position(|&b| b == 0)?;
    let s = r.bytes(n)?;
    r.u8()?;
    Some(s)
}

/// The exports trie, a node per trie node in depth-first order: terminal
/// nodes are the exported symbols.
pub(super) async fn exports_trie(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let base = m.text_vmaddr();
    let mut visited = vec![false; data.len()];
    let mut stack: Vec<(usize, Vec<u8>)> = vec![(0, Vec::new())];
    let mut exports = 0u64;
    let mut nodes = 0u64;
    let mut end_of_nodes = 0usize;
    while let Some((offset, prefix)) = stack.pop() {
        cx.checkpoint().await;
        let Some(seen) = visited.get_mut(offset) else {
            cx.diag(Diagnostic::malformed(format!(
                "trie node offset {offset:#x} is out of range"
            )));
            continue;
        };
        if *seen {
            cx.diag(Diagnostic::malformed(format!(
                "trie node {offset:#x} is reachable twice"
            )));
            continue;
        }
        *seen = true;
        let at =
            |start: usize, end: usize| span.sub(to_u64(start), to_u64(end.saturating_sub(start)));
        let bad = || Diagnostic::malformed("malformed trie node").at(span.sub(to_u64(offset), 1));
        let mut r = Reader::at(&data, offset);
        let terminal = r.uleb().ok_or_else(bad)?;
        let info_start = r.pos();
        let children = info_start.checked_add(to_usize(terminal)).ok_or_else(bad)?;
        let mut fields = vec![
            Node::new("terminal_size")
                .span(at(offset, info_start))
                .value(uint(terminal, 64))
                .desc("Size of the export information (0: not an export)"),
        ];
        let mut value = None;
        let mut summary: Vec<String> = Vec::new();
        if terminal > 0 {
            let s = r.pos();
            let flags = r.uleb().ok_or_else(bad)?;
            let (set, unknown) = crate::value::decode_flags(EXPORT_FLAGS, flags);
            summary.extend(set.iter().map(|s| (*s).to_owned()));
            fields.push(Node::new("flags").span(at(s, r.pos())).value(Value::Flags {
                raw: flags,
                bits: 64,
                set,
                unknown,
            }));
            if flags & 0x8 != 0 {
                let s = r.pos();
                let ordinal = r.uleb().ok_or_else(bad)?;
                fields.push(
                    Node::new("ordinal")
                        .span(at(s, r.pos()))
                        .value(uint(ordinal, 64))
                        .summary(m.dylib(ordinal)),
                );
                let s = r.pos();
                let imported = bounded_cstr(&mut r, MAX_SYMBOL).unwrap_or_default();
                let imported = String::from_utf8_lossy(imported).into_owned();
                fields.push(
                    Node::new("import_name")
                        .span(at(s, r.pos()))
                        .value(text(imported.clone())),
                );
                let mut s = format!("re-exported from {}", m.dylib(ordinal));
                if !imported.is_empty() {
                    s.push_str(&format!(" as {imported}"));
                }
                summary.push(s);
            } else if flags & 0x10 != 0 {
                let s = r.pos();
                let stub = r.uleb().ok_or_else(bad)?;
                fields.push(
                    Node::new("stub_offset")
                        .span(at(s, r.pos()))
                        .value(hex(base.saturating_add(stub), 64)),
                );
                let s = r.pos();
                let resolver = r.uleb().ok_or_else(bad)?;
                fields.push(
                    Node::new("resolver_offset")
                        .span(at(s, r.pos()))
                        .value(hex(base.saturating_add(resolver), 64)),
                );
                value = Some(base.saturating_add(stub));
                summary.push(format!("resolver {:#x}", base.saturating_add(resolver)));
            } else {
                let s = r.pos();
                let address = r.uleb().ok_or_else(bad)?;
                let absolute = flags & 3 == 2;
                let addr = if absolute {
                    address
                } else {
                    base.saturating_add(address)
                };
                let mut field = Node::new("address")
                    .span(at(s, r.pos()))
                    .value(hex(addr, 64))
                    .desc("Offset from the image's load address (or absolute)");
                if !absolute && let Some(t) = m.vm_span(addr, 0) {
                    field = field.target(t);
                }
                fields.push(field);
                value = Some(addr);
                if !absolute {
                    summary.push(m.describe(addr));
                }
            }
            if r.pos() < children {
                fields.push(Node::new("unused").span(at(r.pos(), children)));
            }
            exports = exports.saturating_add(1);
        }
        let mut r = Reader::at(&data, children);
        let n = r.u8().ok_or_else(bad)?;
        fields.push(
            Node::new("child_count")
                .span(at(children, r.pos()))
                .value(uint(n, 8)),
        );
        let mut next = Vec::new();
        for _ in 0..n {
            let s = r.pos();
            let edge = bounded_cstr(&mut r, MAX_SYMBOL).ok_or_else(bad)?;
            let child = r.uleb().ok_or_else(bad)?;
            let edge_text = String::from_utf8_lossy(edge).into_owned();
            fields.push(
                Node::new("edge")
                    .span(at(s, r.pos()))
                    .value(text(edge_text))
                    .summary(format!("child at {child:#x}"))
                    .target(span.sub(child, 0)),
            );
            if prefix.len().saturating_add(edge.len()) > MAX_SYMBOL {
                cx.diag(Diagnostic::limit("exported symbol name is too long"));
                continue;
            }
            let mut name = prefix.clone();
            name.extend_from_slice(edge);
            next.push((to_usize(child), name));
        }
        end_of_nodes = end_of_nodes.max(r.pos());
        nodes = nodes.saturating_add(1);
        let name = if prefix.is_empty() {
            "(root)".to_owned()
        } else {
            String::from_utf8_lossy(&prefix).into_owned()
        };
        let mut node = group(name, at(offset, r.pos()), fields);
        if let Some(v) = value {
            node = node.value(hex(v, 64));
        }
        if terminal == 0 {
            summary.push(grouped_count(n, "child", "children"));
        }
        cx.push(node.maybe_summary(summary.join(", "))).await;
        // Depth-first, children in order.
        stack.extend(next.into_iter().rev());
    }
    if let Some(node) = trailing(&cx, span.tail(to_u64(end_of_nodes))).await? {
        cx.push(node).await;
    }
    cx.annotate(format!(
        "{} in {}",
        grouped_count(exports, "export", "exports"),
        grouped_count(nodes, "trie node", "trie nodes")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Rebase and bind opcodes (LC_DYLD_INFO)

/// Where a segment index and offset point.
fn place(m: &MachInfo, segment: u8, offset: u64) -> (u64, String) {
    match m.segments.get(usize::from(segment)) {
        Some(s) => {
            let addr = s.vmaddr.wrapping_add(offset);
            (addr, m.describe(addr))
        }
        None => (0, format!("segment {segment} + {offset:#x}")),
    }
}

fn times(n: u64, what: &str, stride: u64) -> String {
    if n == 1 {
        what.to_owned()
    } else {
        format!("{} {what}s, every {stride:#x} bytes", grouped(n))
    }
}

pub(super) async fn rebase_opcodes(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let pointer = m.word();
    let mut kind = 1u8;
    let mut segment = 0u8;
    let mut offset = 0u64;
    let mut total = 0u64;
    let mut r = Reader::new(&data);
    while let Some(op) = r.u8() {
        let start = r.pos().saturating_sub(1);
        let imm = op & 0x0f;
        let bad =
            || Diagnostic::malformed("truncated rebase opcode").at(span.sub(to_u64(start), 1));
        let name = lookup(REBASE_OPCODE, (op & 0xf0).into());
        let mut value = None;
        let mut summary = String::new();
        let mut action: Option<(u64, u64)> = None;
        match op & 0xf0 {
            0x00 => {
                summary = "end of the rebase info".to_owned();
            }
            0x10 => {
                kind = imm;
                value = Some(Value::Enum {
                    raw: imm.into(),
                    bits: 4,
                    name: lookup(REBASE_TYPE, imm.into()),
                });
            }
            0x20 => {
                segment = imm;
                offset = r.uleb().ok_or_else(bad)?;
                value = Some(hex(offset, 64));
                summary = format!("segment {segment}: {}", place(&m, segment, offset).1);
            }
            0x30 => {
                let delta = r.uleb().ok_or_else(bad)?;
                offset = offset.wrapping_add(delta);
                value = Some(hex(delta, 64));
                summary = format!("now {}", place(&m, segment, offset).1);
            }
            0x40 => {
                let delta = u64::from(imm).saturating_mul(pointer);
                offset = offset.wrapping_add(delta);
                value = Some(uint(imm, 4));
                summary = format!("+{delta:#x}, now {}", place(&m, segment, offset).1);
            }
            0x50 => {
                value = Some(uint(imm, 4));
                action = Some((imm.into(), 0));
            }
            0x60 => {
                let n = r.uleb().ok_or_else(bad)?;
                value = Some(uint(n, 64));
                action = Some((n, 0));
            }
            0x70 => {
                let skip = r.uleb().ok_or_else(bad)?;
                value = Some(hex(skip, 64));
                action = Some((1, skip));
            }
            0x80 => {
                let n = r.uleb().ok_or_else(bad)?;
                let skip = r.uleb().ok_or_else(bad)?;
                value = Some(text(format!("{n} times, skipping {skip:#x}")));
                action = Some((n, skip));
            }
            _ => {
                return Err(
                    Diagnostic::malformed(format!("unknown rebase opcode {op:#04x}"))
                        .at(span.sub(to_u64(start), 1)),
                );
            }
        }
        if let Some((n, skip)) = action {
            let (_, at) = place(&m, segment, offset);
            let stride = skip.saturating_add(pointer);
            total = total.saturating_add(n);
            offset = offset.wrapping_add(n.wrapping_mul(stride));
            summary = format!("{} at {at}", times(n, "rebase", stride));
        }
        if kind != 1 && op & 0xf0 >= 0x50 {
            summary.push_str(&format!(", {}", name_or(REBASE_TYPE, kind.into(), "type")));
        }
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.progress_in(span, at.end());
        let mut node = Node::new(name.unwrap_or("REBASE_OPCODE_?"))
            .span(at)
            .maybe_summary(summary);
        if let Some(v) = value {
            node = node.value(v);
        }
        cx.push(node).await;
        if op == 0 {
            break;
        }
    }
    if let Some(node) = trailing(&cx, span.tail(to_u64(r.pos()))).await? {
        cx.push(node).await;
    }
    cx.annotate(grouped_count(total, "rebase", "rebases"));
    Ok(())
}

const BIND_SYMBOL_FLAGS: FlagTable = &[flag(0x1, "WEAK_IMPORT"), flag(0x8, "NON_WEAK_DEFINITION")];

pub(super) async fn bind_opcodes(cx: Cx, (m, span): (Macho, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let lazy = m
        .region(Item::LazyBind)
        .is_some_and(|r| m.region_span(r) == span);
    let pointer = m.word();
    let mut ordinal = 0i64;
    let mut symbol = String::new();
    let mut weak = false;
    let mut kind = 1u8;
    let mut addend = 0i64;
    let mut segment = 0u8;
    let mut offset = 0u64;
    let mut total = 0u64;
    let library = |ordinal: i64| -> String {
        match ordinal {
            0 => "self".to_owned(),
            -1 => "main executable".to_owned(),
            -2 => "flat lookup".to_owned(),
            -3 => "weak lookup".to_owned(),
            o if o > 0 => m.dylib(o.unsigned_abs()),
            o => format!("library {o}"),
        }
    };
    let mut r = Reader::new(&data);
    while let Some(op) = r.u8() {
        let start = r.pos().saturating_sub(1);
        let imm = op & 0x0f;
        let bad = || Diagnostic::malformed("truncated bind opcode").at(span.sub(to_u64(start), 1));
        let mut name = lookup(BIND_OPCODE, (op & 0xf0).into()).unwrap_or("BIND_OPCODE_?");
        let mut value = None;
        let mut summary = String::new();
        let mut action: Option<(u64, u64)> = None;
        match op & 0xf0 {
            0x00 => {
                summary = if lazy {
                    "end of this lazy binding".to_owned()
                } else {
                    "end of the bind info".to_owned()
                };
            }
            0x10 => {
                ordinal = imm.into();
                value = Some(uint(imm, 4));
                summary = library(ordinal);
            }
            0x20 => {
                let v = r.uleb().ok_or_else(bad)?;
                ordinal = i64::try_from(v).unwrap_or(i64::MAX);
                value = Some(uint(v, 64));
                summary = library(ordinal);
            }
            0x30 => {
                ordinal = if imm == 0 {
                    0
                } else {
                    i64::from(i8::from_le_bytes([imm | 0xf0]))
                };
                value = Some(Value::Int {
                    value: ordinal,
                    bits: 4,
                });
                summary = library(ordinal);
            }
            0x40 => {
                weak = imm & 1 != 0;
                symbol = String::from_utf8_lossy(bounded_cstr(&mut r, MAX_SYMBOL).ok_or_else(bad)?)
                    .into_owned();
                value = Some(text(symbol.clone()));
                let (set, _) = crate::value::decode_flags(BIND_SYMBOL_FLAGS, imm.into());
                summary = set.join(", ");
            }
            0x50 => {
                kind = imm;
                value = Some(Value::Enum {
                    raw: imm.into(),
                    bits: 4,
                    name: lookup(BIND_TYPE, imm.into()),
                });
            }
            0x60 => {
                addend = r.sleb().ok_or_else(bad)?;
                value = Some(Value::Int {
                    value: addend,
                    bits: 64,
                });
            }
            0x70 => {
                segment = imm;
                offset = r.uleb().ok_or_else(bad)?;
                value = Some(hex(offset, 64));
                summary = format!("segment {segment}: {}", place(&m, segment, offset).1);
            }
            0x80 => {
                let delta = r.uleb().ok_or_else(bad)?;
                offset = offset.wrapping_add(delta);
                value = Some(hex(delta, 64));
                summary = format!("now {}", place(&m, segment, offset).1);
            }
            0x90 => {
                action = Some((1, 0));
            }
            0xa0 => {
                let skip = r.uleb().ok_or_else(bad)?;
                value = Some(hex(skip, 64));
                action = Some((1, skip));
            }
            0xb0 => {
                value = Some(uint(imm, 4));
                action = Some((1, u64::from(imm).saturating_mul(pointer)));
            }
            0xc0 => {
                let n = r.uleb().ok_or_else(bad)?;
                let skip = r.uleb().ok_or_else(bad)?;
                value = Some(text(format!("{n} times, skipping {skip:#x}")));
                action = Some((n, skip));
            }
            0xd0 => match imm {
                0 => {
                    name = "BIND_SUBOPCODE_THREADED_SET_BIND_ORDINAL_TABLE_SIZE_ULEB";
                    let n = r.uleb().ok_or_else(bad)?;
                    value = Some(uint(n, 64));
                }
                1 => {
                    name = "BIND_SUBOPCODE_THREADED_APPLY";
                    summary = format!(
                        "apply the threaded chain starting at {}",
                        place(&m, segment, offset).1
                    );
                }
                _ => {}
            },
            _ => {
                return Err(
                    Diagnostic::malformed(format!("unknown bind opcode {op:#04x}"))
                        .at(span.sub(to_u64(start), 1)),
                );
            }
        }
        if let Some((n, skip)) = action {
            let (_, at) = place(&m, segment, offset);
            let stride = skip.saturating_add(pointer);
            total = total.saturating_add(n);
            offset = offset.wrapping_add(n.wrapping_mul(stride));
            summary = format!(
                "{} {symbol} from {} at {at}",
                times(n, "bind", stride),
                library(ordinal)
            );
            if kind != 1 {
                summary.push_str(&format!(", {}", name_or(BIND_TYPE, kind.into(), "type")));
            }
            if addend != 0 {
                summary.push_str(&format!(", addend {addend:#x}"));
            }
            if weak {
                summary.push_str(", weak import");
            }
        }
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.progress_in(span, at.end());
        let mut node = Node::new(name).span(at).maybe_summary(summary);
        if let Some(v) = value {
            node = node.value(v);
        }
        cx.push(node).await;
        if op == 0 && (!lazy || r.rest().iter().all(|&b| b == 0)) {
            break;
        }
    }
    if let Some(node) = trailing(&cx, span.tail(to_u64(r.pos()))).await? {
        cx.push(node).await;
    }
    cx.annotate(grouped_count(total, "bind", "binds"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Linker optimization hints

/// `LC_LINKER_OPTIMIZATION_HINT`: ULEB128 records of a kind, an argument
/// count and that many addresses.
pub(super) async fn optimization_hints(cx: Cx, (_m, span): (Macho, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let mut n = 0u64;
    loop {
        let start = r.pos();
        let Some(kind) = r.uleb() else { break };
        if kind == 0 {
            r = Reader::at(&data, start);
            break;
        }
        let bad = || Diagnostic::malformed("truncated hint").at(span.tail(to_u64(start)));
        let args = r.uleb().ok_or_else(bad)?;
        let mut addresses = Vec::new();
        for _ in 0..args.min(16) {
            addresses.push(format!("{:#x}", r.uleb().ok_or_else(bad)?));
        }
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.progress_in(span, at.end());
        cx.push(
            Node::new(name_or(LOH_KIND, kind, "kind"))
                .span(at)
                .value(text(addresses.join(", ")))
                .summary(format!(
                    "{} {}",
                    args,
                    if args == 1 { "address" } else { "addresses" }
                )),
        )
        .await;
        n = n.saturating_add(1);
        if args > 16 {
            cx.diag(Diagnostic::malformed(format!("hint with {args} addresses")));
            break;
        }
    }
    if let Some(node) = trailing(&cx, span.tail(to_u64(r.pos()))).await? {
        cx.push(node).await;
    }
    cx.annotate(grouped_count(n, "hint", "hints"));
    Ok(())
}
