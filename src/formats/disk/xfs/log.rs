//! The XFS log: a circular sequence of log records. Each record has a
//! 512-byte header (plus extended headers for records over 32 KiB) and a
//! body of operations. When a record is written, the first word of every
//! 512-byte body sector is replaced by the cycle number and saved in the
//! header; the operations are shown from a source with those words
//! restored. Log item formats are written in the host's byte order
//! (the header says which).

use std::collections::BTreeMap;

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::{PieceList, crc32c_update, size, uuid_value};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

use super::{BE, HdrCtx, crc_field, lsn_summary, rest_unused, uint};

const MAGIC: u32 = 0xfeed_babe;
const BB: u64 = 512;
/// Sectors scanned per read while skipping runs of empty records.
const SCAN: u64 = 128;
/// Records listed at most.
const MAX_RECORDS: u64 = 1 << 20;
/// Largest record body followed (XFS writes at most 256 KiB).
const MAX_BODY: u64 = 1 << 20;

const FMT: EnumTable = &[
    (0, "unknown"),
    (1, "Linux, little-endian"),
    (2, "Linux, big-endian"),
    (3, "IRIX, big-endian"),
];

const CLIENTS: EnumTable = &[(0x02, "volume"), (0x69, "transaction"), (0xaa, "log")];

const OP_FLAGS: FlagTable = &[
    flag(0x01, "START_TRANS"),
    flag(0x02, "COMMIT_TRANS"),
    flag(0x04, "CONTINUE_TRANS"),
    flag(0x08, "WAS_CONT_TRANS"),
    flag(0x10, "END_TRANS"),
    flag(0x20, "UNMOUNT_TRANS"),
];

const ITEMS: EnumTable = &[
    (0x1236, "extent free intent"),
    (0x1237, "extent free done"),
    (0x1238, "inode unlink"),
    (0x123b, "inode"),
    (0x123c, "buffer"),
    (0x123d, "quota"),
    (0x123e, "quota off"),
    (0x123f, "inode create"),
    (0x1240, "reverse mapping update intent"),
    (0x1241, "reverse mapping update done"),
    (0x1242, "reference count update intent"),
    (0x1243, "reference count update done"),
    (0x1244, "extent map update intent"),
    (0x1245, "extent map update done"),
    (0x1246, "attribute intent"),
    (0x1247, "attribute done"),
    (0x1248, "mapping exchange intent"),
    (0x1249, "mapping exchange done"),
    (0x124a, "realtime extent free intent"),
    (0x124b, "realtime extent free done"),
    (0x124c, "realtime reverse mapping update intent"),
    (0x124d, "realtime reverse mapping update done"),
    (0x124e, "realtime reference count update intent"),
    (0x124f, "realtime reference count update done"),
];

const INODE_FIELDS: FlagTable = &[
    flag(0x001, "CORE"),
    flag(0x002, "DDATA"),
    flag(0x004, "DEXT"),
    flag(0x008, "DBROOT"),
    flag(0x010, "DEV"),
    flag(0x020, "UUID"),
    flag(0x040, "ADATA"),
    flag(0x080, "AEXT"),
    flag(0x100, "ABROOT"),
    flag(0x200, "DOWNER"),
    flag(0x400, "AOWNER"),
    flag(0x800, "TIMESTAMP"),
];

const BUF_FLAGS: FlagTable = &[
    flag(0x01, "INODE_BUF"),
    flag(0x02, "CANCEL"),
    flag(0x04, "UDQUOT_BUF"),
    flag(0x08, "PDQUOT_BUF"),
    flag(0x10, "GDQUOT_BUF"),
];

/// Buffer types (`enum xfs_blft`), in bits 11-15 of the flags.
const BUF_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "user quota"),
    (2, "project quota"),
    (3, "group quota"),
    (4, "B+tree block"),
    (5, "AGF"),
    (6, "AGFL"),
    (7, "AGI"),
    (8, "inode cluster"),
    (9, "symlink block"),
    (10, "directory block"),
    (11, "directory data block"),
    (12, "directory free block"),
    (13, "directory leaf block"),
    (14, "directory leaf (node form) block"),
    (15, "DA node block"),
    (16, "attribute leaf block"),
    (17, "remote attribute value"),
    (18, "superblock"),
    (19, "realtime bitmap"),
    (20, "realtime summary"),
];

/// Whether a 512-byte sector holds an empty record header (as mkfs
/// stamps the whole log) of cycle `cycle`.
fn empty_header(sector: &[u8], cycle: u32) -> bool {
    u32_be(sector, 0) == Some(MAGIC)
        && u32_be(sector, 4) == Some(cycle)
        && u32_be(sector, 12) == Some(0)
        && u32_be(sector, 40) == Some(0)
}

pub(super) async fn walk(cx: Cx, log: Span) -> Result<()> {
    let total = log.len / BB;
    let (mut blk, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while blk < total && index < MAX_RECORDS {
        cx.progress_in(log, blk.saturating_mul(BB));
        let hspan = log.sub(blk.saturating_mul(BB), BB);
        let h = cx.read_avail(hspan).await?;
        if u32_be(&h, 0) != Some(MAGIC) {
            break;
        }
        let cycle = u32_be(&h, 4).unwrap_or(0);
        let version = u32_be(&h, 8).unwrap_or(0);
        let len = u64::from(u32_be(&h, 12).unwrap_or(0));
        let ops = u32_be(&h, 40).unwrap_or(0);
        let at = (blk, index);
        cx.mark(move || at);
        if len == 0 && ops == 0 {
            // A run of empty headers: scan it in windows.
            let start = blk;
            'scan: while blk < total {
                let window = log.sub(blk.saturating_mul(BB), SCAN.saturating_mul(BB));
                let data = cx.read_avail(window).await?;
                if data.is_empty() {
                    break;
                }
                for sector in data.chunks(to_usize(BB)) {
                    if !empty_header(sector, cycle) {
                        break 'scan;
                    }
                    blk = blk.saturating_add(1);
                }
            }
            let n = blk.saturating_sub(start);
            cx.push(
                uint(
                    "Empty records",
                    log.sub(start.saturating_mul(BB), n.saturating_mul(BB)),
                    n,
                    64,
                )
                .summary(format!(
                    "blocks {start}–{}: headers of cycle {cycle} with no operations, as mkfs writes them",
                    blk.saturating_sub(1)
                )),
            )
            .await;
            index = index.saturating_add(1);
            continue;
        }
        let size_field = u64::from(u32_be(&h, 320).unwrap_or(0));
        let hblks = if version & 2 != 0 && size_field > 32768 {
            size_field.div_ceil(32768)
        } else {
            1
        };
        let body = len.min(MAX_BODY);
        let dblks = body.div_ceil(BB);
        let span = log.sub(
            blk.saturating_mul(BB),
            hblks.saturating_add(dblks).saturating_mul(BB),
        );
        let lsn_blk = u32_be(&h, 20).unwrap_or(0);
        cx.push(
            Node::new(format!("Record {index}"))
                .span(span)
                .summary(format!(
                    "LSN {cycle}:{lsn_blk}, {ops} operation{}, {}",
                    if ops == 1 { "" } else { "s" },
                    size(len)
                ))
                .lazy(record, (span, hblks, body)),
        )
        .await;
        blk = blk.saturating_add(hblks).saturating_add(dblks);
        index = index.saturating_add(1);
    }
    if blk < total {
        let rest = log.tail(blk.saturating_mul(BB));
        cx.emit(
            Node::new("Unused")
                .span(rest)
                .summary(format!("{}, no record headers", size(rest.len))),
        );
    }
    Ok(())
}

fn header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.u32("Magic").hex().emit()?;
    f.u32("Cycle").emit()?;
    f.u32("Version")
        .desc("1, or 2 for logs with stripe units and large records")
        .emit()?;
    f.u32("Body length").emit()?;
    f.u64("LSN").hex().with(lsn_summary).emit()?;
    f.u64("Tail LSN")
        .hex()
        .with(lsn_summary)
        .desc("The oldest record still needed for recovery when this one was written")
        .emit()?;
    let stored = u32_le(&f.block().data, 32).unwrap_or(0);
    if stored == 0 {
        f.u32("CRC-32C")
            .hex()
            .with(|_, n| n.summary("not set (written by mkfs)"))
            .emit()?;
    } else {
        crc_field(f, ctx.crc)?;
    }
    f.u32("Previous record block").emit()?;
    f.u32("Operations").emit()?;
    let body = u64::from(u32_be(&f.block().data, 12).unwrap_or(0));
    let used = body.div_ceil(BB).min(64).saturating_mul(4);
    let words = f.peek_span(used);
    f.node(
        Node::new("Saved cycle words")
            .span(words)
            .summary("the first word of each body sector, replaced on disk by the cycle number")
            .lazy(cycle_words, words),
    );
    f.skip(used);
    if used < 256 {
        f.node(
            Node::new("Unused cycle words")
                .span(f.peek_span(256u64.saturating_sub(used)))
                .summary("for sectors the record does not have"),
        );
        f.skip(256u64.saturating_sub(used));
    }
    f.u32("Format").enumeration(FMT).emit()?;
    f.bytes("Filesystem UUID", 16).with(uuid_value).emit()?;
    f.u32("Record buffer size").emit()?;
    rest_unused(f, "Unused");
    Ok(())
}

async fn cycle_words(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, w) in data.as_chunks::<4>().0.iter().enumerate() {
        cx.push(
            uint(
                format!("Sector {i}"),
                span.sub(to_u64(i).saturating_mul(4), 4),
                u32::from_be_bytes(*w).into(),
                32,
            )
            .summary("saved word"),
        )
        .await;
    }
    Ok(())
}

fn ext_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Cycle").emit()?;
    let words = f.peek_span(256);
    f.node(
        Node::new("Saved cycle words")
            .span(words)
            .lazy(cycle_words, words),
    );
    f.skip(256);
    rest_unused(f, "Unused");
    Ok(())
}

/// The record CRC: the header (as `struct xlog_rec_header`, whose size is
/// 328 bytes on most architectures and 324 on i386), extended headers and
/// body, with the CRC field taken as zero.
fn record_crc(data: &[u8], hblks: u64, body: u64, header_len: usize) -> Option<u32> {
    let header = data.get(..header_len)?;
    let mut c = crc32c_update(!0, header.get(..32)?);
    c = crc32c_update(c, &[0; 4]);
    c = crc32c_update(c, header.get(36..)?);
    for j in 1..hblks {
        let at = to_usize(j.saturating_mul(BB));
        c = crc32c_update(c, data.get(at..at.saturating_add(260))?);
    }
    let start = to_usize(hblks.saturating_mul(BB));
    c = crc32c_update(c, data.get(start..start.saturating_add(to_usize(body)))?);
    Some(!c)
}

async fn record(cx: Cx, (span, hblks, body): (Span, u64, u64)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let stored = u32_le(&data, 32);
    let computed = [328usize, 324]
        .into_iter()
        .filter_map(|n| record_crc(&data, hblks, body, n))
        .find(|&c| Some(c) == stored)
        .or_else(|| record_crc(&data, hblks, body, 328));
    let fmt = u32_be(&data, 300).unwrap_or(0);
    let ops = u32_be(&data, 40).unwrap_or(0);
    cx.emit(
        struct_node(
            "Header",
            span.sub(0, BB),
            BE,
            HdrCtx {
                v5: true,
                crc: computed,
            },
            header_layout,
        )
        .summary(format!(
            "cycle {}, {}",
            u32_be(&data, 4).unwrap_or(0),
            crate::value::lookup(FMT, fmt.into()).unwrap_or("unknown format")
        )),
    );
    for j in 1..hblks {
        cx.emit(struct_node(
            format!("Extended header {j}"),
            span.sub(j.saturating_mul(BB), BB),
            BE,
            (),
            ext_header_layout,
        ));
    }
    let body_span = span.sub(hblks.saturating_mul(BB), body);
    // Restore the first word of each body sector from the saved cycle data.
    let mut list = PieceList::new(body_span);
    let sectors = body.div_ceil(BB);
    for i in 0..sectors {
        let word = if i < 64 {
            span.sub(44u64.saturating_add(i.saturating_mul(4)), 4)
        } else {
            let j = i / 64;
            let k = i % 64;
            span.sub(
                j.saturating_mul(BB)
                    .saturating_add(4)
                    .saturating_add(k.saturating_mul(4)),
                4,
            )
        };
        let sector = body_span.sub(i.saturating_mul(BB), BB);
        list.data(word.sub(0, sector.len.min(4)));
        list.data(sector.tail(4));
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    let restored = list.finish(&cx, "xfs-log-unstamp").await?;
    cx.emit(
        Node::new("Operations")
            .span(restored)
            .summary(format!("{ops} operations"))
            .lazy(operations, (restored, ops, fmt != 1)),
    );
    Ok(())
}

/// What an operation's payload is.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Payload {
    Empty,
    TransHeader,
    Item(u16),
    Region,
    Continued,
    Unmount,
    Unknown,
}

async fn operations(cx: Cx, (src, count, big): (Span, u32, bool)) -> Result<()> {
    let endian = if big { Endian::Big } else { Endian::Little };
    let u16_at = |b: &[u8], at: usize| {
        if big { u16_be(b, at) } else { u16_le(b, at) }
    };
    let mut regions: BTreeMap<u32, u16> = BTreeMap::new();
    let mut pos = 0u64;
    for i in 0..count {
        if pos.saturating_add(12) > src.len {
            break;
        }
        let head = cx.read(src.sub(pos, 12)).await?;
        let tid = u32_be(&head, 0).unwrap_or(0);
        let len = u64::from(u32_be(&head, 4).unwrap_or(0));
        let flags = head.get(9).copied().unwrap_or(0);
        let payload = src.sub(pos.saturating_add(12), len);
        let first = cx.read_avail(payload.sub(0, 4)).await?;
        let kind = if len == 0 {
            Payload::Empty
        } else if flags & 0x20 != 0 {
            Payload::Unmount
        } else if flags & 0x08 != 0 {
            Payload::Continued
        } else if regions.get(&tid).is_some_and(|&n| n > 0) {
            if let Some(n) = regions.get_mut(&tid) {
                *n = n.saturating_sub(1);
            }
            Payload::Region
        } else if first.as_slice() == b"TRAN" || first.as_slice() == b"NART" {
            Payload::TransHeader
        } else if let Some(t) =
            u16_at(&first, 0).filter(|&t| crate::value::lookup(ITEMS, t.into()).is_some())
        {
            let n = u16_at(&first, 2).unwrap_or(1);
            regions.insert(tid, n.saturating_sub(1));
            Payload::Item(t)
        } else {
            Payload::Unknown
        };
        let what = match kind {
            Payload::Empty => {
                if flags & 0x01 != 0 {
                    "transaction start".to_owned()
                } else if flags & 0x02 != 0 {
                    "transaction commit".to_owned()
                } else {
                    "empty".to_owned()
                }
            }
            Payload::TransHeader => "transaction header".to_owned(),
            Payload::Item(t) => format!(
                "{} log item",
                crate::value::lookup(ITEMS, t.into()).unwrap_or("unknown")
            ),
            Payload::Region => "item region".to_owned(),
            Payload::Continued => "continued data".to_owned(),
            Payload::Unmount => "unmount record".to_owned(),
            Payload::Unknown => "data".to_owned(),
        };
        let op = src.sub(pos, len.saturating_add(12));
        cx.push(
            Node::new(format!("Op {i}"))
                .span(op)
                .summary(format!("{what}, transaction {tid:#x}, {len} bytes"))
                .lazy(op_view, (op, kind, endian)),
        )
        .await;
        pos = pos.saturating_add(12).saturating_add(len);
    }
    if pos < src.len {
        cx.emit(
            Node::new("Padding")
                .span(src.tail(pos))
                .summary(size(src.len.saturating_sub(pos))),
        );
    }
    Ok(())
}

fn op_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Transaction ID").hex().emit()?;
    f.u32("Length").emit()?;
    f.u8("Client").hex().enumeration(CLIENTS).emit()?;
    f.u8("Flags").hex().flags(OP_FLAGS).emit()?;
    f.u16("Reserved").emit()?;
    Ok(())
}

fn trans_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Type").emit()?;
    f.u32("Transaction ID").hex().emit()?;
    f.u32("Items").emit()?;
    rest_unused(f, "Unused");
    Ok(())
}

fn unmount_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Magic").hex().emit()?;
    f.u16("Padding").emit()?;
    f.u32("Padding").emit()?;
    rest_unused(f, "Unused");
    Ok(())
}

fn item_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let ty = f.u16("Type").hex().enumeration(ITEMS).emit()?;
    f.u16("Regions")
        .desc("Log regions of this item, this format structure included")
        .emit()?;
    match ty {
        0x123b => {
            f.u32("Logged fields").hex().flags(INODE_FIELDS).emit()?;
            f.u16("Attribute fork bytes").emit()?;
            f.u16("Data fork bytes").emit()?;
            f.u32("Padding").emit()?;
            f.u64("Inode").emit()?;
            f.bytes("Device or UUID", 16).emit()?;
            f.u64("Inode buffer block (512-byte units)").hex().emit()?;
            f.u32("Inode buffer length").emit()?;
            f.u32("Offset in buffer").emit()?;
        }
        0x123c => {
            f.u16("Flags")
                .hex()
                .flags(BUF_FLAGS)
                .with(|&v, n| {
                    n.summary(format!(
                        "{} buffer",
                        crate::value::lookup(BUF_TYPES, ((v >> 11) & 0x1f).into())
                            .unwrap_or("unknown")
                    ))
                })
                .emit()?;
            f.u16("Length (512-byte units)").emit()?;
            f.u64("Block (512-byte units)").hex().emit()?;
            f.u32("Dirty map words").emit()?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("Dirty map", rest)
                    .desc("One bit per 128-byte chunk of the buffer that is logged")
                    .emit()?;
            }
        }
        _ => {}
    }
    rest_unused(f, "Item data");
    Ok(())
}

async fn op_view(cx: Cx, (op, kind, endian): (Span, Payload, Endian)) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        op.sub(0, 12),
        BE,
        (),
        op_header_layout,
    ));
    let payload = op.tail(12);
    if payload.is_empty() {
        return Ok(());
    }
    cx.emit(match kind {
        Payload::TransHeader => struct_node(
            "Transaction header",
            payload,
            endian,
            (),
            trans_header_layout,
        ),
        Payload::Unmount => struct_node("Unmount record", payload, endian, (), unmount_layout),
        Payload::Item(_) => struct_node("Log item format", payload, endian, (), item_layout),
        _ => Node::new("Data").span(payload).summary(size(payload.len)),
    });
    if kind == Payload::Unknown {
        cx.diag(Diagnostic::note("unrecognised operation payload"));
    }
    Ok(())
}
