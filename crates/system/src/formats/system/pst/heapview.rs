//! Structural views of the lower layers: the heap-on-node of an LTP node
//! block by block (HNHDR, HNPAGEHDR or HNBITMAPHDR, the page map and every
//! allocation, labelled with what it holds: BTH headers and records,
//! TCINFO, row matrices, property values), the fields of B-tree page
//! trailers and metadata, block trailers and internal blocks (XBLOCK,
//! XXBLOCK, SLBLOCK, SIBLOCK).

use std::collections::BTreeMap;
use std::sync::Arc;

use super::ltp::{self, NodeRef};
use super::ndb::{self, Pst};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::arcutil::emit_nodes;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;

const CLIENT_SIGS: EnumTable = &[
    (0x6c, "bTypeReserved1"),
    (0x7c, "bTypeTC (table context)"),
    (0x8c, "bTypeReserved2"),
    (0x9c, "bTypeReserved3"),
    (0xa5, "bTypeReserved4"),
    (0xac, "bTypeReserved5"),
    (0xb5, "bTypeBTH"),
    (0xbc, "bTypePC (property context)"),
    (0xcc, "bTypeReserved6"),
];

/// What an allocation of the heap holds.
#[derive(Clone, Copy, Debug)]
enum Role {
    BthHeader,
    /// BTH records: key size, record size, level (0 = leaves).
    BthRecords(u8, u8, u8),
    TcInfo,
    RowMatrix,
    Value,
}

/// Follows the heap's user root to label its allocations.
async fn roles(cx: &Cx, pst: &Pst, heap: &ltp::Heap) -> BTreeMap<u32, Role> {
    let mut roles = BTreeMap::new();
    let mut bths = Vec::new();
    match heap.client_sig {
        ltp::SIG_PC | ltp::SIG_BTH => {
            bths.push(heap.user_root);
        }
        ltp::SIG_TC => {
            roles.insert(heap.user_root, Role::TcInfo);
            if let Ok(span) = ltp::item(cx, pst, heap, heap.user_root).await
                && let Ok(b) = cx.read_avail(span.sub(0, 22)).await
            {
                bths.push(u32_le(&b, 10).unwrap_or(0));
                let rows = u32_le(&b, 14).unwrap_or(0);
                if rows != 0 && rows & 0x1f == 0 {
                    roles.insert(rows, Role::RowMatrix);
                }
            }
        }
        _ => {}
    }
    let pc = heap.client_sig == ltp::SIG_PC;
    for root in bths {
        if root == 0 {
            continue;
        }
        roles.insert(root, Role::BthHeader);
        let Ok(span) = ltp::item(cx, pst, heap, root).await else {
            continue;
        };
        let Ok(h) = cx.read_avail(span.sub(0, 8)).await else {
            continue;
        };
        let (key, ent, levels) = (
            h.get(1).copied().unwrap_or(0),
            h.get(2).copied().unwrap_or(0),
            h.get(3).copied().unwrap_or(0),
        );
        let mut pending = vec![(u32_le(&h, 4).unwrap_or(0), levels)];
        let mut steps = 0u32;
        while let Some((hid, level)) = pending.pop() {
            steps = steps.saturating_add(1);
            if hid == 0 || steps > 4096 || roles.contains_key(&hid) {
                continue;
            }
            cx.checkpoint().await;
            let stride = if level == 0 { ent } else { 4 };
            roles.insert(hid, Role::BthRecords(key, stride, level));
            let Ok(span) = ltp::item(cx, pst, heap, hid).await else {
                continue;
            };
            let Ok(data) = cx.read_avail(span).await else {
                continue;
            };
            let size = usize::from(key).saturating_add(usize::from(stride));
            if size == 0 {
                continue;
            }
            for rec in data.chunks_exact(size) {
                let at = usize::from(key);
                if level > 0 {
                    pending.push((u32_le(rec, at).unwrap_or(0), level.saturating_sub(1)));
                } else if pc && stride == 6 {
                    // wPropType, dwValueHnid: values over 4 bytes live in
                    // the heap (or a subnode).
                    let ty = u16_le(rec, at).unwrap_or(0);
                    let hnid = u32_le(rec, at.saturating_add(2)).unwrap_or(0);
                    if ltp::fixed_size(ty).is_none_or(|n| n > 4) && hnid != 0 && hnid & 0x1f == 0 {
                        roles.insert(hnid, Role::Value);
                    }
                }
            }
        }
    }
    roles
}

/// Expander: the heap of an LTP node, block by block.
pub async fn heap_view(cx: Cx, (pst, node): (Pst, NodeRef)) -> Result<()> {
    let heap = ltp::heap(&cx, &pst, node).await?;
    let roles = Arc::new(roles(&cx, &pst, &heap).await);
    for (i, b) in heap.blocks.iter().enumerate() {
        let plain = ndb::plain(&cx, &pst, b).await?;
        cx.push(
            Node::new(format!("Heap block {i}"))
                .span(plain)
                .summary(format!("BID {:#x}, {} bytes", b.bid, plain.len))
                .lazy(heap_block, (pst, node, i, roles.clone())),
        )
        .await;
    }
    Ok(())
}

async fn heap_block(
    cx: Cx,
    (pst, node, index, roles): (Pst, NodeRef, usize, Arc<BTreeMap<u32, Role>>),
) -> Result<()> {
    let heap = ltp::heap(&cx, &pst, node).await?;
    let pm = ltp::page_map(&cx, &pst, &heap, index).await?;
    let block = pm.block;
    let data = cx.read_avail(block).await?;
    let map_at = u64::from(u16_le(&data, 0).unwrap_or(0));
    // The block's header.
    let header_len: u64 = if index == 0 {
        12
    } else if index % 128 == 8 {
        66
    } else {
        2
    };
    let hblock = cx.block(block.sub(0, header_len)).await?;
    let mut f = Fields::new(&hblock, LE);
    let name = match header_len {
        12 => "HNHDR",
        66 => "HNBITMAPHDR",
        _ => "HNPAGEHDR",
    };
    let mut hn = Node::new(name).span(block.sub(0, header_len));
    if index == 0 {
        let ib = f.u16("ibHnpm").hex().get()?;
        let sig = f.u8("bSig").get()?;
        let client = f.u8("bClientSig").get()?;
        let root = f.u32("hidUserRoot").get()?;
        hn = hn
            .value(Value::Enum {
                raw: client.into(),
                bits: 8,
                name: crate::value::lookup(CLIENT_SIGS, client.into()),
            })
            .summary(format!(
                "page map at {ib:#x}, signature {sig:#04x}, user root {root:#x}"
            ))
            .lazy(struct_fields, (block.sub(0, 12), 0u8));
    } else {
        hn = hn
            .value(Value::UInt {
                value: map_at,
                bits: 16,
                radix: crate::value::Radix::Hex,
            })
            .summary("offset of the page map")
            .lazy(
                struct_fields,
                (
                    block.sub(0, header_len),
                    if header_len == 66 { 1u8 } else { 2u8 },
                ),
            );
    }
    cx.emit(hn);
    // Allocations, in page-map order.
    let block_no = u32::try_from(index).unwrap_or(0);
    for (i, w) in pm.bounds.windows(2).enumerate() {
        cx.checkpoint().await;
        let (Some(&s), Some(&e)) = (w.first(), w.get(1)) else {
            break;
        };
        let hid = block_no.wrapping_shl(16).wrapping_add(
            u32::try_from(i.saturating_add(1))
                .unwrap_or(0)
                .wrapping_shl(5),
        );
        let span = block.sub(s.into(), u64::from(e.saturating_sub(s)));
        let mut n = Node::new(format!("HID {hid:#x}")).span(span);
        match roles.get(&hid) {
            Some(Role::BthHeader) => {
                n = n.summary("BTH header").lazy(struct_fields, (span, 3u8));
            }
            Some(Role::TcInfo) => {
                n = n
                    .summary("TCINFO (table header)")
                    .lazy(struct_fields, (span, 4u8));
            }
            Some(&Role::BthRecords(key, ent, level)) => {
                let size = u64::from(key).saturating_add(ent.into());
                n = n
                    .summary(format!(
                        "BTH {} ({} of {size} bytes)",
                        if level == 0 {
                            "leaf records"
                        } else {
                            "index records"
                        },
                        span.len.checked_div(size).unwrap_or(0)
                    ))
                    .lazy(bth_records, (span, key, ent, level));
            }
            Some(Role::RowMatrix) => {
                n = n.summary("row matrix").value(Value::UInt {
                    value: span.len,
                    bits: 32,
                    radix: crate::value::Radix::Dec,
                });
            }
            Some(Role::Value) => {
                n = n.summary("property value").value(Value::UInt {
                    value: span.len,
                    bits: 32,
                    radix: crate::value::Radix::Dec,
                });
            }
            None => {
                n = n.summary(format!("{} bytes", span.len));
            }
        }
        cx.emit(n);
    }
    // The page map at the end.
    let count = pm.bounds.len();
    let map = block.sub(map_at, 4u64.saturating_add(to_u64(count).saturating_mul(2)));
    cx.emit(
        Node::new("HNPAGEMAP")
            .span(map)
            .value(Value::Text(format!(
                "{} allocations",
                count.saturating_sub(1)
            )))
            .lazy(struct_fields, (map, 5u8)),
    );
    Ok(())
}

/// Fields of the small heap structures: 0 HNHDR, 1 HNBITMAPHDR,
/// 2 HNPAGEHDR, 3 BTHHEADER, 4 TCINFO, 5 HNPAGEMAP.
async fn struct_fields(cx: Cx, (span, kind): (Span, u8)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    match kind {
        0 => {
            f.u16("ibHnpm").hex().emit()?;
            f.u8("bSig").emit()?;
            f.u8("bClientSig").enumeration(CLIENT_SIGS).emit()?;
            f.u32("hidUserRoot").hex().emit()?;
            f.u32("rgbFillLevel")
                .hex()
                .desc("Fill level of the first eight blocks, a nibble each")
                .emit()?;
        }
        1 => {
            f.u16("ibHnpm").hex().emit()?;
            f.bytes("rgbFillLevel", 64)
                .desc("Fill level of the next 128 blocks, a nibble each")
                .emit()?;
        }
        2 => {
            f.u16("ibHnpm").hex().emit()?;
        }
        3 => {
            f.u8("bType").hex().emit()?;
            f.u8("cbKey").emit()?;
            f.u8("cbEnt").emit()?;
            f.u8("bIdxLevels").emit()?;
            f.u32("hidRoot").hex().emit()?;
        }
        4 => {
            f.u8("bType").hex().emit()?;
            let cols = f.u8("cCols").emit()?;
            f.u16("TCI_4b")
                .desc("End of the 4- and 8-byte columns")
                .emit()?;
            f.u16("TCI_2b").desc("End of the 2-byte columns").emit()?;
            f.u16("TCI_1b").desc("End of the 1-byte columns").emit()?;
            f.u16("TCI_bm")
                .desc("End of the cell existence bitmap: the row size")
                .emit()?;
            f.u32("hidRowIndex").hex().emit()?;
            f.u32("hnidRows").hex().emit()?;
            f.u32("hidIndex").hex().desc("Deprecated").emit()?;
            for _ in 0..cols {
                if f.remaining() < 8 {
                    break;
                }
                f.u32("TCOLDESC.tag").hex().emit()?;
                f.u16("TCOLDESC.ibData").emit()?;
                f.u8("TCOLDESC.cbData").emit()?;
                f.u8("TCOLDESC.iBit").emit()?;
            }
        }
        _ => {
            let n = f.u16("cAlloc").emit()?;
            f.u16("cFree").emit()?;
            for _ in 0..=n {
                if f.remaining() < 2 {
                    break;
                }
                f.u16("rgibAlloc").hex().emit()?;
            }
        }
    }
    Ok(())
}

/// BTH records: key and data of each.
async fn bth_records(cx: Cx, (span, key, ent, level): (Span, u8, u8, u8)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let size = usize::from(key).saturating_add(usize::from(ent));
    if size == 0 {
        return Ok(());
    }
    for (i, rec) in data.chunks_exact(size).enumerate() {
        cx.checkpoint().await;
        let k = rec.get(..usize::from(key)).unwrap_or_default();
        let v = rec.get(usize::from(key)..).unwrap_or_default();
        let key_value = k
            .iter()
            .rev()
            .fold(0u64, |a, &b| a.wrapping_shl(8) | u64::from(b));
        let summary = if level > 0 {
            format!("child HID {:#x}", u32_le(v, 0).unwrap_or(0))
        } else if key == 4 && ent == 2 {
            format!("row {}", u16_le(v, 0).unwrap_or(0))
        } else if key == 4 && ent == 4 {
            format!("row {}", u32_le(v, 0).unwrap_or(0))
        } else if ent == 6 {
            format!(
                "type {:#06x}, value/HNID {:#x}",
                u16_le(v, 0).unwrap_or(0),
                u32_le(v, 2).unwrap_or(0)
            )
        } else {
            crate::formats::util::datakit::hex_string(v)
        };
        cx.emit(
            Node::new(format!("Record {i}"))
                .span(span.sub(to_u64(i).saturating_mul(to_u64(size)), to_u64(size)))
                .value(Value::UInt {
                    value: key_value,
                    bits: key.saturating_mul(8).min(64),
                    radix: crate::value::Radix::Hex,
                })
                .summary(summary),
        );
    }
    Ok(())
}

/// Expander: the fields of a page trailer (`wide`: Unicode layout).
pub async fn page_trailer(cx: Cx, (span, wide): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("ptype").enumeration(PAGE_TYPES).emit()?;
    f.u8("ptypeRepeat").enumeration(PAGE_TYPES).emit()?;
    f.u16("wSig").hex().emit()?;
    if wide {
        f.u32("dwCRC").hex().emit()?;
        f.u64("bid").hex().emit()?;
    } else {
        f.u32("bid").hex().emit()?;
        f.u32("dwCRC").hex().emit()?;
    }
    Ok(())
}

const PAGE_TYPES: EnumTable = &[
    (0x80, "ptypeBBT"),
    (0x81, "ptypeNBT"),
    (0x82, "ptypeFMap"),
    (0x83, "ptypePMap"),
    (0x84, "ptypeAMap"),
    (0x85, "ptypeFPMap"),
    (0x86, "ptypeDL"),
];

/// Expander: a B-tree page's metadata (entry count, maximum, size, level).
pub async fn page_meta(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("cEnt").emit()?;
    f.u8("cEntMax").emit()?;
    f.u8("cbEnt").emit()?;
    f.u8("cLevel").emit()?;
    if f.remaining() >= 4 {
        f.u32("dwPadding").emit()?;
    }
    Ok(())
}

/// Expander: a block trailer's fields.
pub async fn block_trailer(cx: Cx, (span, wide): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u16("cb").emit()?;
    f.u16("wSig").hex().emit()?;
    if wide {
        f.u32("dwCRC").hex().emit()?;
        f.u64("bid").hex().emit()?;
    } else {
        f.u32("bid").hex().emit()?;
        f.u32("dwCRC").hex().emit()?;
    }
    Ok(())
}

/// Expander: an internal block (XBLOCK, XXBLOCK, SLBLOCK, SIBLOCK).
pub async fn internal_block(cx: Cx, (span, wide): (Span, bool)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let btype = f.u8("btype").emit()?;
    let level = f.u8("cLevel").emit()?;
    let count = f.u16("cEnt").emit()?;
    let id = if wide { 8 } else { 4 };
    let mut nodes = Vec::new();
    if btype == 1 {
        f.u32("lcbTotal").emit()?;
        for i in 0..count {
            if f.remaining() < id {
                break;
            }
            let at = f.peek_span(id);
            let bid = if wide {
                f.u64("rgbid").get()?
            } else {
                u64::from(f.u32("rgbid").get()?)
            };
            nodes.push(
                Node::new(format!("rgbid[{i}]"))
                    .span(at)
                    .value(crate::formats::util::datakit::hex(bid, 64)),
            );
        }
    } else {
        if wide {
            f.u32("dwPadding").emit()?;
        }
        let entry = if level == 0 {
            id.saturating_mul(3)
        } else {
            id.saturating_mul(2)
        };
        for i in 0..count {
            if f.remaining() < entry {
                break;
            }
            let at = f.peek_span(entry);
            let word = |f: &mut Fields<'_>| -> Result<u64> {
                if wide {
                    f.u64("id").get()
                } else {
                    f.u32("id").get().map(u64::from)
                }
            };
            let nid = word(&mut f)?;
            let a = word(&mut f)?;
            let summary = if level == 0 {
                let b = word(&mut f)?;
                format!("data {a:#x}, subnodes {b:#x}")
            } else {
                format!("SLBLOCK {a:#x}")
            };
            nodes.push(
                Node::new(format!(
                    "{} {i}",
                    if level == 0 { "SLENTRY" } else { "SIENTRY" }
                ))
                .span(at)
                .value(crate::formats::util::datakit::hex(nid, 64))
                .summary(summary),
            );
        }
    }
    if !nodes.is_empty() {
        let count = nodes.len();
        cx.emit(
            Node::new("Entries")
                .value(crate::formats::util::datakit::uint(to_u64(count), 32))
                .lazy(emit_nodes, Arc::new(nodes)),
        );
    }
    Ok(())
}
