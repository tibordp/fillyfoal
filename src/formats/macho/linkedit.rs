//! `__LINKEDIT` structures referenced by load commands: function starts,
//! data-in-code entries, chained fixups, the exports trie and bind opcodes.

use super::tables::*;
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::binutil::{NodeExt, Reader, get_at, hex, name_or, string_at, text};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

/// Longest symbol name assembled from trie edges.
const MAX_SYMBOL: usize = 4096;

pub(super) async fn function_starts(cx: Cx, (span, base, file): (Span, u64, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let mut addr = base;
    let mut index = 0u64;
    loop {
        let start = r.pos();
        let Some(delta) = r.uleb() else { break };
        if delta == 0 {
            break;
        }
        addr = addr.saturating_add(delta);
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.push(
            Node::new(format!("[{index}]"))
                .span(at)
                .value(hex(addr, 64))
                .target(file.sub(addr.saturating_sub(base), 0)),
        )
        .await;
        index = index.saturating_add(1);
    }
    cx.annotate(format!("{index} functions"));
    Ok(())
}

record! {
    struct DataInCode {
        offset: u32 "offset" .hex() .desc("From the start of the __TEXT segment"),
        length: u16 "length",
        kind: u16 "kind" .enumeration(DICE_KIND),
    }
}

pub(super) async fn data_in_code(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let count = span.len / DataInCode::SIZE;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = span.sub(i.saturating_mul(DataInCode::SIZE), DataInCode::SIZE);
        let e = parse(&cx, at, endian, &(), DataInCode::layout).await?;
        cx.push(
            DataInCode::node(format!("[{i}]"), at, endian).summary(format!(
                "{} bytes of {} at {:#x}",
                e.length,
                name_or(DICE_KIND, e.kind.into(), "kind"),
                e.offset
            )),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Chained fixups

record! {
    struct FixupsHeader {
        version: u32 "fixups_version",
        starts_offset: u32 "starts_offset" .hex(),
        imports_offset: u32 "imports_offset" .hex(),
        symbols_offset: u32 "symbols_offset" .hex(),
        imports_count: u32 "imports_count",
        imports_format: u32 "imports_format" .enumeration(CHAINED_IMPORT_FORMAT),
        symbols_format: u32 "symbols_format" .desc("0: uncompressed, 1: zlib"),
    }
}

pub(super) async fn chained_fixups(
    cx: Cx,
    (span, endian, dylibs): (Span, Endian, Vec<String>),
) -> Result<()> {
    let header = span.sub(0, FixupsHeader::SIZE);
    cx.emit(FixupsHeader::node("Header", header, endian));
    let h = parse(&cx, header, endian, &(), FixupsHeader::layout).await?;
    cx.annotate(format!(
        "{} imports, {}",
        h.imports_count,
        name_or(CHAINED_IMPORT_FORMAT, h.imports_format.into(), "format")
    ));
    let starts = span.tail(h.starts_offset.into());
    cx.emit(
        Node::new("Starts in Image")
            .span(starts)
            .lazy(starts_in_image, (starts, endian)),
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
    let node = Node::new("Imports")
        .span(imports)
        .summary(format!("{} imports", h.imports_count));
    cx.emit(if h.symbols_format == 0 {
        node.lazy(
            chained_imports,
            (imports, symbols, endian, h.imports_format, dylibs),
        )
    } else {
        node.diag(Diagnostic::unsupported("compressed symbol names"))
    });
    Ok(())
}

async fn chained_imports(
    cx: Cx,
    (imports, symbols, endian, format, dylibs): (Span, Span, Endian, u32, Vec<String>),
) -> Result<()> {
    let width: u64 = match format {
        1 => 4,
        2 => 8,
        _ => 16,
    };
    let count = imports.len / width;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = imports.sub(i.saturating_mul(width), width);
        let data = cx.read(at).await?;
        let (ordinal, weak, name, addend) = if format == 3 {
            let raw = get_at::<u64>(&data, 0, endian).unwrap_or(0);
            let ordinal = raw & 0xffff;
            let ordinal = if ordinal >= 0xfff0 { ordinal & 0xff } else { ordinal };
            (
                ordinal,
                raw & 0x1_0000 != 0,
                raw >> 32,
                get_at::<i64>(&data, 8, endian).unwrap_or(0),
            )
        } else {
            let raw = get_at::<u32>(&data, 0, endian).unwrap_or(0);
            let addend = if format == 2 {
                get_at::<i32>(&data, 4, endian).unwrap_or(0).into()
            } else {
                0
            };
            (
                u64::from(raw & 0xff),
                raw & 0x100 != 0,
                u64::from(raw >> 9),
                addend,
            )
        };
        let library = to_usize(ordinal)
            .checked_sub(1)
            .and_then(|i| dylibs.get(i))
            .cloned()
            .unwrap_or_else(|| name_or(BIND_SPECIAL_DYLIB, ordinal, "library"));
        let mut summary = format!("from {library}");
        if weak {
            summary.push_str(", weak");
        }
        if addend != 0 {
            summary.push_str(&format!(", addend {addend:#x}"));
        }
        let node = match string_at(&cx, symbols, name).await {
            Ok((s, target)) => Node::new(s).target(target),
            Err(e) => Node::new(format!("#{i}")).diag(e),
        };
        cx.push(node.span(at).summary(summary)).await;
    }
    Ok(())
}

async fn starts_in_image(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let head = cx.block(span.sub(0, 4)).await?;
    let count = Fields::emitting(&cx, &head, endian)
        .u32("seg_count")
        .emit()?;
    let table = span.sub(4, u64::from(count).saturating_mul(4));
    let offsets = cx.read_avail(table).await?;
    for i in 0..to_u64(offsets.len()) / 4 {
        let offset = get_at::<u32>(&offsets, i.saturating_mul(4), endian).unwrap_or(0);
        let entry = table.sub(i.saturating_mul(4), 4);
        if offset == 0 {
            cx.push(
                Node::new(format!("Segment {i}"))
                    .span(entry)
                    .summary("no fixups"),
            )
            .await;
            continue;
        }
        let seg = span.tail(offset.into());
        let size = cx.read_avail(seg.sub(0, 4)).await?;
        let size = get_at::<u32>(&size, 0, endian).unwrap_or(0);
        let seg = seg.sub(0, size.into());
        let data = cx.read_avail(seg.sub(0, 22)).await?;
        let format = get_at::<u16>(&data, 6, endian).unwrap_or(0);
        let pages = get_at::<u16>(&data, 20, endian).unwrap_or(0);
        cx.push(
            struct_node(format!("Segment {i}"), seg, endian, (), starts_in_segment)
                .summary(format!(
                    "{}, {pages} pages",
                    name_or(CHAINED_POINTER_FORMAT, format.into(), "format")
                ))
                .target(entry),
        )
        .await;
    }
    Ok(())
}

fn starts_in_segment(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("size").hex().emit()?;
    f.u16("page_size").hex().emit()?;
    f.u16("pointer_format")
        .enumeration(CHAINED_POINTER_FORMAT)
        .emit()?;
    f.u64("segment_offset").hex().emit()?;
    f.u32("max_valid_pointer").hex().emit()?;
    let pages = f.u16("page_count").emit()?;
    let span = f.peek_span(u64::from(pages).saturating_mul(2));
    f.node(
        Node::new("page_start")
            .span(span)
            .summary(format!("{pages} entries"))
            .lazy(page_starts, span),
    );
    Ok(())
}

async fn page_starts(cx: Cx, span: Span) -> Result<()> {
    // The endianness of fixups follows the image; Apple only ships
    // little-endian images with chained fixups.
    let data = cx.read_avail(span).await?;
    let count = to_u64(data.len()) / 2;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let v = get_at::<u16>(&data, i.saturating_mul(2), Endian::Little).unwrap_or(0);
        let node = Node::new(format!("Page {i}")).span(span.sub(i.saturating_mul(2), 2));
        cx.push(if v == 0xffff {
            node.value(text("none"))
        } else {
            node.value(hex(v.into(), 16))
        })
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Exports trie

const EXPORT_FLAGS: FlagTable = &[
    flag(0x1, "THREAD_LOCAL"),
    flag(0x2, "ABSOLUTE"),
    flag(0x4, "WEAK_DEFINITION"),
    flag(0x8, "REEXPORT"),
    flag(0x10, "STUB_AND_RESOLVER"),
    flag(0x20, "STATIC_RESOLVER"),
];

pub(super) async fn exports_trie(cx: Cx, (span, base): (Span, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut visited = vec![false; data.len()];
    let mut stack: Vec<(usize, Vec<u8>)> = vec![(0, Vec::new())];
    let mut count = 0u64;
    while let Some((offset, prefix)) = stack.pop() {
        cx.checkpoint().await;
        let Some(seen) = visited.get_mut(offset) else {
            cx.diag(Diagnostic::malformed(format!("trie node offset {offset:#x} is out of range")));
            continue;
        };
        if *seen {
            cx.diag(Diagnostic::malformed(format!("trie node {offset:#x} is reachable twice")));
            continue;
        }
        *seen = true;
        let mut r = Reader::at(&data, offset);
        let bad = || Diagnostic::malformed("malformed trie node").at(span.sub(to_u64(offset), 1));
        let terminal = r.uleb().ok_or_else(bad)?;
        let info_start = r.pos();
        let children = info_start
            .checked_add(to_usize(terminal))
            .ok_or_else(bad)?;
        if terminal > 0 {
            let flags = r.uleb().ok_or_else(bad)?;
            let name = String::from_utf8_lossy(&prefix).into_owned();
            let mut node = Node::new(name).span(span.sub(
                to_u64(info_start),
                to_u64(children.saturating_sub(info_start)),
            ));
            let mut summary: Vec<String> = crate::value::decode_flags(EXPORT_FLAGS, flags & !3)
                .0
                .iter()
                .map(|s| (*s).to_owned())
                .collect();
            match flags & 3 {
                1 => summary.push("THREAD_LOCAL".to_owned()),
                2 => summary.push("ABSOLUTE".to_owned()),
                _ => {}
            }
            if flags & 0x8 != 0 {
                let ordinal = r.uleb().ok_or_else(bad)?;
                let imported = r.cstr().unwrap_or_default();
                let mut s = format!("re-exported from library {ordinal}");
                if !imported.is_empty() {
                    s.push_str(&format!(" as {}", String::from_utf8_lossy(imported)));
                }
                summary.push(s);
            } else if flags & 0x10 != 0 {
                let stub = r.uleb().ok_or_else(bad)?;
                let resolver = r.uleb().ok_or_else(bad)?;
                node = node.value(hex(base.saturating_add(stub), 64));
                summary.push(format!("resolver {:#x}", base.saturating_add(resolver)));
            } else {
                let address = r.uleb().ok_or_else(bad)?;
                node = node.value(hex(base.saturating_add(address), 64));
            }
            count = count.saturating_add(1);
            cx.push(node.maybe_summary(summary.join(", "))).await;
        }
        let mut r = Reader::at(&data, children);
        let n = r.u8().ok_or_else(bad)?;
        let mut next = Vec::new();
        for _ in 0..n {
            let edge = r.cstr().ok_or_else(bad)?;
            let child = r.uleb().ok_or_else(bad)?;
            if prefix.len().saturating_add(edge.len()) > MAX_SYMBOL {
                cx.diag(Diagnostic::limit("exported symbol name is too long"));
                continue;
            }
            let mut name = prefix.clone();
            name.extend_from_slice(edge);
            next.push((to_usize(child), name));
        }
        // Depth-first, children in order.
        stack.extend(next.into_iter().rev());
    }
    cx.annotate(format!("{count} exports"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bind opcodes (LC_DYLD_INFO)

const BIND_TYPE: crate::value::EnumTable =
    &[(1, "pointer"), (2, "text absolute 32"), (3, "text pc-relative 32")];

#[derive(Default)]
struct BindState {
    ordinal: i64,
    symbol: String,
    weak: bool,
    kind: u8,
    addend: i64,
    segment: u8,
    offset: u64,
}

pub(super) async fn bind_opcodes(
    cx: Cx,
    (span, wide, dylibs): (Span, bool, Vec<String>),
) -> Result<()> {
    let data = cx.read(span).await?;
    let pointer: u64 = if wide { 8 } else { 4 };
    // Bounds the work a malicious repeat count can cause.
    let budget = to_u64(data.len()).saturating_mul(16).max(1024);
    let mut emitted = 0u64;
    let mut s = BindState {
        kind: 1,
        ..BindState::default()
    };
    let mut r = Reader::new(&data);
    let library = |ordinal: i64| -> String {
        if ordinal > 0 {
            to_usize(ordinal.unsigned_abs())
                .checked_sub(1)
                .and_then(|i| dylibs.get(i))
                .cloned()
                .unwrap_or_else(|| format!("library {ordinal}"))
        } else {
            match ordinal {
                0 => "self".to_owned(),
                -1 => "main executable".to_owned(),
                -2 => "flat lookup".to_owned(),
                -3 => "weak lookup".to_owned(),
                _ => format!("library {ordinal}"),
            }
        }
    };
    while let Some(op) = r.u8() {
        let start = r.pos().saturating_sub(1);
        let imm = op & 0x0f;
        let bad = || Diagnostic::malformed("truncated bind opcode").at(span.sub(to_u64(start), 1));
        let mut repeat = 0u64;
        let mut advance = 0u64;
        match op & 0xf0 {
            0x00 => {} // BIND_OPCODE_DONE (lazy binds use it as a separator)
            0x10 => s.ordinal = imm.into(),
            0x20 => s.ordinal = i64::try_from(r.uleb().ok_or_else(bad)?).unwrap_or(i64::MAX),
            0x30 => {
                s.ordinal = if imm == 0 {
                    0
                } else {
                    i64::from(i8::from_le_bytes([imm | 0xf0]))
                }
            }
            0x40 => {
                s.weak = imm & 1 != 0;
                s.symbol = String::from_utf8_lossy(r.cstr().ok_or_else(bad)?).into_owned();
            }
            0x50 => s.kind = imm,
            0x60 => s.addend = r.sleb().ok_or_else(bad)?,
            0x70 => {
                s.segment = imm;
                s.offset = r.uleb().ok_or_else(bad)?;
            }
            0x80 => s.offset = s.offset.wrapping_add(r.uleb().ok_or_else(bad)?),
            0x90 => repeat = 1,
            0xa0 => {
                repeat = 1;
                advance = r.uleb().ok_or_else(bad)?;
            }
            0xb0 => {
                repeat = 1;
                advance = u64::from(imm).saturating_mul(pointer);
            }
            0xc0 => {
                repeat = r.uleb().ok_or_else(bad)?;
                advance = r.uleb().ok_or_else(bad)?;
            }
            0xd0 => {
                return Err(Diagnostic::unsupported("threaded binds").at(span.sub(to_u64(start), 1)));
            }
            _ => {
                return Err(Diagnostic::malformed(format!("unknown bind opcode {op:#04x}"))
                    .at(span.sub(to_u64(start), 1)));
            }
        }
        let at = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        for _ in 0..repeat {
            if emitted >= budget {
                cx.diag(Diagnostic::limit("too many binds for the size of the opcode stream"));
                return Ok(());
            }
            emitted = emitted.saturating_add(1);
            let mut summary = format!(
                "from {}, segment {} + {:#x}",
                library(s.ordinal),
                s.segment,
                s.offset
            );
            if s.kind != 1 {
                summary.push_str(&format!(", {}", name_or(BIND_TYPE, s.kind.into(), "type")));
            }
            if s.addend != 0 {
                summary.push_str(&format!(", addend {:#x}", s.addend));
            }
            if s.weak {
                summary.push_str(", weak import");
            }
            cx.push(Node::new(s.symbol.clone()).span(at).summary(summary))
                .await;
            s.offset = s
                .offset
                .wrapping_add(advance)
                .wrapping_add(pointer);
        }
        if repeat == 0 {
            cx.checkpoint().await;
        }
    }
    Ok(())
}
