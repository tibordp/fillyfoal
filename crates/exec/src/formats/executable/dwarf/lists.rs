//! The DWARF tables that are lists of offsets, addresses or entries:
//! `.debug_str_offsets`, `.debug_addr`, `.debug_aranges`, the version 5
//! `.debug_rnglists` and `.debug_loclists`, and the version 2-4
//! `.debug_ranges` and `.debug_loc`.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::binutil::Reader;
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::expr::{self, Sizes};
use super::tables::{LOCATION_ENTRIES, RANGE_ENTRIES};
use super::{Dwarf, Sec, initial_length, uint_of};

/// A version 5 style contribution header: unit length, version, then the
/// rest of the header (`rest` bytes).
#[derive(Clone, Copy, Debug)]
struct Contribution {
    offset: u64,
    /// Offset just past the contribution.
    end: u64,
    /// Offset of the first entry.
    body: u64,
    offset_size: u8,
    version: u16,
    address_size: u8,
    /// `offset_entry_count` of range and location lists.
    count: u64,
}

/// Reads a contribution header; `rest` is how many bytes follow the
/// version (2 for string offsets, 2 for addresses, 6 for lists).
async fn contribution(
    cx: &Cx,
    dw: &Dwarf,
    sec: Sec,
    offset: u64,
    rest: u64,
) -> Result<Option<Contribution>> {
    let section = dw.span_or_empty(sec);
    let head = dw.read(cx, sec, offset, 24).await?;
    let e = dw.endian;
    let Some((length, offset_size, at)) = initial_length(&head, e) else {
        return Ok(None);
    };
    let at_usize = to_usize(at);
    let version = uint_of(head.get(at_usize..).unwrap_or_default(), 2, e).unwrap_or(0);
    let tail = head.get(at_usize.saturating_add(2)..).unwrap_or_default();
    let (address_size, count) = match sec {
        Sec::Addr => (tail.first().copied().unwrap_or(0), 0),
        Sec::Rnglists | Sec::Loclists => (
            tail.first().copied().unwrap_or(0),
            uint_of(tail.get(2..).unwrap_or_default(), 4, e).unwrap_or(0),
        ),
        _ => (dw.address_size, 0),
    };
    Ok(Some(Contribution {
        offset,
        end: offset
            .saturating_add(at)
            .saturating_add(length)
            .min(section.len),
        body: offset
            .saturating_add(at)
            .saturating_add(2)
            .saturating_add(rest),
        offset_size,
        version: u16::try_from(version).unwrap_or(0),
        address_size,
        count,
    }))
}

/// The header fields of a contribution, as nodes.
fn header_nodes(section: Span, c: &Contribution, sec: Sec, dw: &Dwarf, data: &[u8]) -> Vec<Node> {
    let e = dw.endian;
    let at = if c.offset_size == 8 { 12u64 } else { 4 };
    let field = |name: &'static str, a: u64, n: u64, value: Value| {
        Node::new(name)
            .span(section.sub(c.offset.saturating_add(a), n))
            .value(value)
    };
    let mut out = vec![
        field(
            "unit_length",
            0,
            at,
            hex(c.end.saturating_sub(c.offset).saturating_sub(at), 64),
        ),
        field("version", at, 2, uint(c.version, 16)),
    ];
    let p = at.saturating_add(2);
    match sec {
        Sec::StrOffsets => {
            let pad = uint_of(data.get(to_usize(p)..).unwrap_or_default(), 2, e).unwrap_or(0);
            out.push(field("padding", p, 2, uint(pad, 16)));
        }
        _ => {
            out.push(field("address_size", p, 1, uint(c.address_size, 8)));
            let seg = data
                .get(to_usize(p.saturating_add(1)))
                .copied()
                .unwrap_or(0);
            out.push(field(
                "segment_selector_size",
                p.saturating_add(1),
                1,
                uint(seg, 8),
            ));
            if matches!(sec, Sec::Rnglists | Sec::Loclists) {
                out.push(field(
                    "offset_entry_count",
                    p.saturating_add(2),
                    4,
                    uint(c.count, 32),
                ));
            }
        }
    }
    out
}

/// Walks the contributions of a section, pushing one node each.
async fn contributions(cx: &Cx, dw: &Arc<Dwarf>, sec: Sec, rest: u64) -> Result<()> {
    let Some(section) = dw.span(sec) else {
        return Ok(());
    };
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < section.len {
        cx.mark(move || pos);
        let Some(c) = contribution(cx, dw, sec, pos, rest).await? else {
            cx.diag(Diagnostic::malformed("bad unit length").at(section.sub(pos, 4)));
            break;
        };
        let span = section.sub(pos, c.end.saturating_sub(pos));
        let entries = match sec {
            Sec::StrOffsets => c
                .end
                .saturating_sub(c.body)
                .checked_div(u64::from(c.offset_size))
                .unwrap_or(0),
            Sec::Addr => c
                .end
                .saturating_sub(c.body)
                .checked_div(u64::from(c.address_size))
                .unwrap_or(0),
            _ => c.count,
        };
        let what = match sec {
            Sec::StrOffsets => "string offsets",
            Sec::Addr => "addresses",
            _ => "offsets",
        };
        cx.push(
            Node::new(format!("Contribution at {pos:#x}"))
                .span(span)
                .summary(format!("version {}, {entries} {what}", c.version))
                .lazy(contribution_node, (dw.clone(), sec, c)),
        )
        .await;
        if c.end <= pos {
            break;
        }
        pos = c.end;
    }
    Ok(())
}

async fn contribution_node(cx: Cx, (dw, sec, c): (Arc<Dwarf>, Sec, Contribution)) -> Result<()> {
    let section = dw.span_or_empty(sec);
    let resumed = cx.resume::<u64>();
    let mut pos = match resumed {
        Some(p) => p,
        None => {
            let head = dw
                .read(&cx, sec, c.offset, c.body.saturating_sub(c.offset))
                .await?;
            for n in header_nodes(section, &c, sec, &dw, &head) {
                cx.emit(n);
            }
            c.body
        }
    };
    let e = dw.endian;
    match sec {
        Sec::StrOffsets | Sec::Addr => {
            let size = if sec == Sec::StrOffsets {
                c.offset_size
            } else {
                c.address_size
            };
            if !matches!(size, 1 | 2 | 4 | 8) {
                return Err(Diagnostic::malformed(format!("entry size {size}")));
            }
            let step = u64::from(size);
            while pos.saturating_add(step) <= c.end {
                cx.mark(move || pos);
                let index = pos.saturating_sub(c.body).checked_div(step).unwrap_or(0);
                let mut node = Node::new(format!("[{index}]")).span(section.sub(pos, step));
                if !cx.skipping() {
                    let data = dw.read(&cx, sec, pos, step).await?;
                    let v = uint_of(&data, size, e).unwrap_or(0);
                    node = node.value(hex(v, 64));
                    if sec == Sec::StrOffsets {
                        if let Some(s) = dw.string(&cx, Sec::Str, v).await {
                            node = node.value(text(s)).summary(format!("at {v:#x}"));
                        }
                        if let Some(str_span) = dw.span(Sec::Str) {
                            node = node.target(str_span.sub(v, 0));
                        }
                    }
                }
                cx.push(node).await;
                pos = pos.saturating_add(step);
            }
        }
        _ => {
            let step = u64::from(c.offset_size);
            let table_end = c
                .body
                .saturating_add(c.count.saturating_mul(step))
                .min(c.end);
            while pos < table_end {
                let i = pos.saturating_sub(c.body).checked_div(step).unwrap_or(0);
                cx.mark(move || pos);
                let data = dw.read(&cx, sec, pos, step).await?;
                let v = uint_of(&data, c.offset_size, e).unwrap_or(0);
                cx.push(
                    Node::new(format!("offset[{i}]"))
                        .span(section.sub(pos, step))
                        .value(hex(v, 64))
                        .summary(format!("list at {:#x}", c.body.saturating_add(v)))
                        .target(section.sub(c.body.saturating_add(v), 0)),
                )
                .await;
                pos = pos.saturating_add(step);
            }
            let sizes = Sizes {
                address: c.address_size,
                offset: c.offset_size,
                endian: e,
            };
            list_entries(&cx, &dw, sec, pos, c.end, sizes).await?;
        }
    }
    Ok(())
}

/// Range (`DW_RLE_*`) or location (`DW_LLE_*`) list entries from `pos` to
/// `end`, one node each.
async fn list_entries(
    cx: &Cx,
    dw: &Dwarf,
    sec: Sec,
    mut pos: u64,
    end: u64,
    sizes: Sizes,
) -> Result<()> {
    let section = dw.span_or_empty(sec);
    let loc = sec == Sec::Loclists;
    let a = sizes.address;
    while pos < end {
        cx.mark(move || pos);
        let data = dw
            .read(cx, sec, pos, 64.min(end.saturating_sub(pos)))
            .await?;
        let mut r = Reader::new(&data);
        let Some(kind) = r.u8() else {
            break;
        };
        let addr = |r: &mut Reader<'_>| uint_of(r.bytes(usize::from(a))?, a, sizes.endian);
        let operands: Option<String> = (|| {
            Some(match (loc, kind) {
                (_, 0x00) => String::new(),
                (_, 0x01) => format!("index {}", r.uleb()?),
                (_, 0x02) => format!("index {}, index {}", r.uleb()?, r.uleb()?),
                (_, 0x03) => format!("index {}, length {:#x}", r.uleb()?, r.uleb()?),
                (_, 0x04) => format!("{:#x}, {:#x}", r.uleb()?, r.uleb()?),
                (false, 0x05) | (true, 0x06) => format!("{:#x}", addr(&mut r)?),
                (false, 0x06) | (true, 0x07) => {
                    format!("{:#x}, {:#x}", addr(&mut r)?, addr(&mut r)?)
                }
                (false, 0x07) | (true, 0x08) => {
                    format!("{:#x}, length {:#x}", addr(&mut r)?, r.uleb()?)
                }
                (true, 0x05) => String::new(),
                (true, 0x09) => format!("view {}, {}", r.uleb()?, r.uleb()?),
                _ => return None,
            })
        })();
        let table = if loc { LOCATION_ENTRIES } else { RANGE_ENTRIES };
        let name = name_or(table, kind.into(), if loc { "DW_LLE" } else { "DW_RLE" });
        let Some(mut operands) = operands else {
            cx.push(
                Node::new(name)
                    .span(section.sub(pos, 1))
                    .diag(Diagnostic::malformed("unknown or truncated entry")),
            )
            .await;
            break;
        };
        let mut skip = 0u64;
        if loc && !matches!(kind, 0x00 | 0x01 | 0x06 | 0x09) {
            let Some(len) = r.uleb() else {
                break;
            };
            let have = r.rest();
            let bytes = have.get(..to_usize(len)).unwrap_or(have);
            let shown = expr::describe(bytes, sizes);
            operands.push_str(&format!(": {shown}"));
            skip = len.saturating_sub(to_u64(bytes.len()));
            r.bytes(bytes.len());
        }
        let next = pos.saturating_add(to_u64(r.pos())).saturating_add(skip);
        let mut node = Node::new(name).span(section.sub(pos, next.saturating_sub(pos)));
        if !operands.is_empty() {
            node = node.value(text(operands));
        }
        cx.push(node.summary(format!("{pos:#x}"))).await;
        if next <= pos {
            break;
        }
        pos = next;
    }
    Ok(())
}

pub(super) async fn str_offsets(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    contributions(cx, dw, Sec::StrOffsets, 2).await
}

pub(super) async fn addresses(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    contributions(cx, dw, Sec::Addr, 2).await
}

pub(super) async fn lists(cx: &Cx, dw: &Arc<Dwarf>, sec: Sec) -> Result<()> {
    contributions(cx, dw, sec, 6).await
}

/// Expander for `.debug_aranges`: one node per set.
pub(super) async fn aranges(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    let Some(section) = dw.span(Sec::Aranges) else {
        return Ok(());
    };
    let e = dw.endian;
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < section.len {
        cx.mark(move || pos);
        let head = dw.read(cx, Sec::Aranges, pos, 32).await?;
        let Some((length, offset_size, at)) = initial_length(&head, e) else {
            cx.diag(Diagnostic::malformed("bad unit length").at(section.sub(pos, 4)));
            break;
        };
        let end = pos
            .saturating_add(at)
            .saturating_add(length)
            .min(section.len);
        let mut r = Reader::at(&head, to_usize(at));
        let version = r.bytes(2).and_then(|b| uint_of(b, 2, e)).unwrap_or(0);
        let cu = r
            .bytes(offset_size.into())
            .and_then(|b| uint_of(b, offset_size, e))
            .unwrap_or(0);
        let address_size = r.u8().unwrap_or(0);
        let seg = r.u8().unwrap_or(0);
        let span = section.sub(pos, end.saturating_sub(pos));
        let mut fields = vec![
            Node::new("unit_length")
                .span(section.sub(pos, at))
                .value(hex(length, 64)),
            Node::new("version")
                .span(section.sub(pos.saturating_add(at), 2))
                .value(uint(version, 16)),
        ];
        let mut p = pos.saturating_add(at).saturating_add(2);
        let mut cu_node = Node::new("debug_info_offset")
            .span(section.sub(p, offset_size.into()))
            .value(hex(cu, 64));
        if let Some(info) = dw.span(Sec::Info) {
            cu_node = cu_node.target(info.sub(cu, 0));
        }
        fields.push(cu_node);
        p = p.saturating_add(offset_size.into());
        fields.push(
            Node::new("address_size")
                .span(section.sub(p, 1))
                .value(uint(address_size, 8)),
        );
        fields.push(
            Node::new("segment_selector_size")
                .span(section.sub(p.saturating_add(1), 1))
                .value(uint(seg, 8)),
        );
        p = p.saturating_add(2);
        // Tuples are aligned to twice the address size from the set start.
        let tuple = u64::from(address_size)
            .saturating_mul(2)
            .saturating_add(seg.into());
        let rel = p.saturating_sub(pos);
        let aligned = if tuple == 0 {
            rel
        } else {
            rel.next_multiple_of(u64::from(address_size).saturating_mul(2).max(1))
        };
        let body = pos.saturating_add(aligned);
        cx.push(
            Node::new(format!("Set at {pos:#x}"))
                .span(span)
                .summary(format!("CU at {cu:#x}"))
                .lazy(
                    arange_set,
                    (dw.clone(), Arc::new(fields), body, end, address_size, seg),
                ),
        )
        .await;
        if end <= pos {
            break;
        }
        pos = end;
    }
    Ok(())
}

type ArangeState = (Arc<Dwarf>, Arc<Vec<Node>>, u64, u64, u8, u8);

async fn arange_set(cx: Cx, (dw, fields, body, end, address_size, seg): ArangeState) -> Result<()> {
    let section = dw.span_or_empty(Sec::Aranges);
    let mut pos = match cx.resume::<u64>() {
        Some(p) => p,
        None => {
            for f in fields.iter() {
                cx.emit(f.clone());
            }
            body
        }
    };
    if !matches!(address_size, 1 | 2 | 4 | 8) || seg > 8 {
        return Err(Diagnostic::malformed(format!(
            "address size {address_size}"
        )));
    }
    let a = u64::from(address_size);
    let tuple = a.saturating_mul(2).saturating_add(seg.into());
    while pos.saturating_add(tuple) <= end {
        cx.mark(move || pos);
        let data = dw.read(&cx, Sec::Aranges, pos, tuple).await?;
        let rest = data.get(usize::from(seg)..).unwrap_or_default();
        let start = uint_of(rest, address_size, dw.endian).unwrap_or(0);
        let len = uint_of(
            rest.get(usize::from(address_size)..).unwrap_or_default(),
            address_size,
            dw.endian,
        )
        .unwrap_or(0);
        let node = Node::new("Range").span(section.sub(pos, tuple));
        if start == 0 && len == 0 {
            cx.push(node.renamed("Terminator").value(hex(0u8, 64)))
                .await;
            break;
        }
        cx.push(
            node.value(hex(start, 64))
                .summary(format!("{start:#x}..{:#x}", start.saturating_add(len))),
        )
        .await;
        pos = pos.saturating_add(tuple);
    }
    Ok(())
}

/// The largest address of `size` bytes (a base address selection marker).
fn max_address(size: u8) -> u64 {
    if size >= 8 {
        u64::MAX
    } else {
        (1u64 << (u32::from(size).saturating_mul(8))).saturating_sub(1)
    }
}

/// Expander for version 2-4 `.debug_ranges`: address pairs, ended by a
/// zero pair, with base address selections.
pub(super) async fn ranges(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    pairs(cx, dw, Sec::Ranges).await
}

/// Expander for version 2-4 `.debug_loc`: address pairs followed by a
/// 2-byte length and an expression, ended by a zero pair.
pub(super) async fn loc(cx: &Cx, dw: &Arc<Dwarf>) -> Result<()> {
    pairs(cx, dw, Sec::Loc).await
}

async fn pairs(cx: &Cx, dw: &Dwarf, sec: Sec) -> Result<()> {
    let Some(section) = dw.span(sec) else {
        return Ok(());
    };
    let a = dw.address_size;
    if !matches!(a, 2 | 4 | 8) {
        return Ok(());
    }
    let e = dw.endian;
    let pair = u64::from(a).saturating_mul(2);
    let sizes = Sizes {
        address: a,
        offset: 4,
        endian: e,
    };
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos.saturating_add(pair) <= section.len {
        cx.mark(move || pos);
        let data = dw.read(cx, sec, pos, pair.saturating_add(2)).await?;
        let begin = uint_of(&data, a, e).unwrap_or(0);
        let end = uint_of(data.get(usize::from(a)..).unwrap_or_default(), a, e).unwrap_or(0);
        let label = format!("{pos:#x}");
        if begin == 0 && end == 0 {
            cx.push(
                Node::new("End of list")
                    .span(section.sub(pos, pair))
                    .summary(label),
            )
            .await;
            pos = pos.saturating_add(pair);
            continue;
        }
        if begin == max_address(a) {
            cx.push(
                Node::new("Base address")
                    .span(section.sub(pos, pair))
                    .value(hex(end, 64))
                    .summary(label),
            )
            .await;
            pos = pos.saturating_add(pair);
            continue;
        }
        let mut len = pair;
        let mut value = format!("{begin:#x}..{end:#x}");
        if sec == Sec::Loc {
            let n = uint_of(data.get(to_usize(pair)..).unwrap_or_default(), 2, e).unwrap_or(0);
            let expr_at = pos.saturating_add(pair).saturating_add(2);
            let bytes = dw.read(cx, sec, expr_at, n.min(0x400)).await?;
            value.push_str(&format!(": {}", expr::describe(&bytes, sizes)));
            len = pair.saturating_add(2).saturating_add(n);
        }
        cx.push(
            Node::new("Entry")
                .span(section.sub(pos, len))
                .value(text(value))
                .summary(label),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}
