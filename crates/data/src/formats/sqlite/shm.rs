//! SQLite WAL index (`-shm`): the shared memory a database in WAL mode
//! maps so connections can find frames in the log without reading it.
//!
//! The file is a series of 32 KiB blocks in the writing machine's byte
//! order. The first starts with two copies of the 48-byte `WalIndexHdr`
//! (readers compare them to detect a torn write) and the 40-byte
//! `WalCkptInfo` (frames already copied back into the database, the read
//! marks of up to five readers, lock bytes). After that, and in every later
//! block, comes the page number of each WAL frame the block covers (4062
//! frames in the first block, 4096 in each later one), then a hash table of
//! 8192 two-byte slots mapping page numbers to those frames. Layout as in
//! SQLite's `wal.c`.

use super::wal::wal_checksum;
use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::plural;
use crate::formats::util::{fmt as ufmt, val};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

const VERSION: u32 = 3_007_000;
const HDR: u64 = 48;
const CKPT: u64 = 40;
/// Both header copies and the checkpoint information.
const INDEX_HDR: u64 = 2 * HDR + CKPT;
const BLOCK: u64 = 32 * 1024;
const FRAMES_PER_BLOCK: u64 = 4096;
/// The first block's frame slots: what the headers leave of 4096.
const FRAMES_FIRST: u64 = FRAMES_PER_BLOCK - INDEX_HDR / 4;
const HASH_SLOTS: u64 = 8192;
const READERS: u64 = 5;

pub static SHM: Format = Format {
    name: "sqlite-shm",
    title: "SQLite WAL index",
    extensions: &["db-shm", "sqlite-shm", "shm"],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The byte order in which `iVersion` reads 3007000 in both header copies.
fn order(b: &[u8]) -> Option<Endian> {
    let le = u32_le(b, 0) == Some(VERSION) && u32_le(b, 48) == Some(VERSION);
    let be = u32_be(b, 0) == Some(VERSION) && u32_be(b, 48) == Some(VERSION);
    if le {
        Some(Endian::Little)
    } else if be {
        Some(Endian::Big)
    } else {
        None
    }
}

fn probe(h: &Head<'_>) -> bool {
    // isInit is 0 or 1, and the page size field is a power of two (1
    // standing for 65536).
    order(h.data).is_some()
        && h.len >= INDEX_HDR
        && h.data.get(12).is_some_and(|&b| b <= 1)
        && h.data.get(13).is_some_and(|&b| b <= 1)
        && u16_le(h.data, 14)
            .zip(u16_be(h.data, 14))
            .is_some_and(|(le, be)| le.is_power_of_two() || be.is_power_of_two())
}

fn u32_at(b: &[u8], at: usize, e: Endian) -> u32 {
    match e {
        Endian::Little => u32_le(b, at),
        Endian::Big => u32_be(b, at),
    }
    .unwrap_or(0)
}

fn u16_at(b: &[u8], at: usize, e: Endian) -> u16 {
    match e {
        Endian::Little => u16_le(b, at),
        Endian::Big => u16_be(b, at),
    }
    .unwrap_or(0)
}

fn page_size(raw: u16) -> u32 {
    if raw == 1 { 65536 } else { raw.into() }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let head = cx.read(span.sub(0, INDEX_HDR)).await?;
    let e = order(&head).ok_or_else(|| {
        Diagnostic::malformed("iVersion is not 3007000 in both header copies").at(span.sub(0, 4))
    })?;
    let copy1 = head.get(..48).unwrap_or_default();
    let copy2 = head.get(48..96).unwrap_or_default();
    let max_frame = u32_at(&head, 16, e);
    let backfill = u32_at(&head, 96, e);
    let sums = |copy: &[u8]| {
        let (s1, s2) = wal_checksum(copy.get(..40).unwrap_or_default(), e == Endian::Big, (0, 0));
        (e, s1, s2)
    };
    let mut first = struct_node("Header", span.sub(0, HDR), e, sums(copy1), header_layout)
        .summary(format!("{} valid frames", max_frame));
    if copy1 != copy2 {
        first = first.diag(Diagnostic::warning(
            "the two header copies differ (a write was in progress)",
        ));
    }
    cx.emit(first);
    cx.emit(
        struct_node(
            "Header copy",
            span.sub(HDR, HDR),
            e,
            sums(copy2),
            header_layout,
        )
        .summary(if copy1 == copy2 {
            "identical"
        } else {
            "differs"
        }),
    );
    cx.emit(struct_node(
        "Checkpoint information",
        span.sub(2 * HDR, CKPT),
        e,
        max_frame,
        ckpt_layout,
    ));
    let blocks = span.len.div_ceil(BLOCK);
    cx.emit(
        Node::new("Hash blocks")
            .summary(format!("{blocks}"))
            .lazy(block_list, (span, e, max_frame)),
    );
    cx.annotate(format!(
        "SQLite WAL index, {}, {} valid frames, {} backfilled, {}-endian",
        ufmt::size(page_size(u16_at(&head, 14, e)).into()),
        max_frame,
        backfill,
        if e == Endian::Little { "little" } else { "big" }
    ));
    Ok(())
}

/// `(byte order, computed checksum)` of a header copy.
fn header_layout(f: &mut Fields<'_>, &(_, s1, s2): &(Endian, u32, u32)) -> Result<()> {
    f.u32("Version")
        .check(|&v| {
            (v != VERSION).then(|| Diagnostic::malformed(format!("expected 3007000, not {v}")))
        })
        .desc("iVersion: 3007000 (SQLite 3.7.0)")
        .emit()?;
    f.u32("Unused").emit()?;
    f.u32("Change counter")
        .desc("iChange: incremented by each write transaction")
        .emit()?;
    f.u8("Initialized")
        .desc("isInit: 1 once the header is valid")
        .emit()?;
    f.u8("Big-endian checksums")
        .desc("bigEndCksum: the byte order of the WAL's frame checksums")
        .emit()?;
    f.u16("Page size")
        .with(|&v, n| if v == 1 { n.summary("65536 bytes") } else { n })
        .desc("szPage: the database page size (1 stands for 65536)")
        .emit()?;
    f.u32("Last valid frame")
        .desc("mxFrame: frames after it are not part of the log")
        .emit()?;
    f.u32("Database pages")
        .desc("nPage: the database size in pages")
        .emit()?;
    f.u32("Frame checksum-1").hex().emit()?;
    f.u32("Frame checksum-2")
        .hex()
        .desc("aFrameCksum: the cumulative checksum of the last valid frame")
        .emit()?;
    f.u32("Salt-1").hex().emit()?;
    f.u32("Salt-2")
        .hex()
        .desc("aSalt: copied from the WAL header")
        .emit()?;
    let c1 = f.u32("Checksum-1").hex().emit()?;
    let c2 = f
        .u32("Checksum-2")
        .hex()
        .desc("aCksum: over the 40 bytes before it, in the index's byte order")
        .emit()?;
    let node = Node::new("Checksum check");
    f.node(if (s1, s2) == (c1, c2) {
        node.value(Value::Bool(true)).summary("matches")
    } else {
        node.value(Value::Bool(false))
            .diag(Diagnostic::warning(format!(
                "computed {s1:#010x} {s2:#010x}"
            )))
    });
    Ok(())
}

fn ckpt_layout(f: &mut Fields<'_>, max_frame: &u32) -> Result<()> {
    let max_frame = *max_frame;
    f.u32("Backfilled frames")
        .desc("nBackfill: frames already copied into the database")
        .check(|&v| {
            (v > max_frame)
                .then(|| Diagnostic::malformed(format!("beyond the last valid frame {max_frame}")))
        })
        .emit()?;
    const NAMES: [&str; 5] = [
        "Read mark 0",
        "Read mark 1",
        "Read mark 2",
        "Read mark 3",
        "Read mark 4",
    ];
    for name in NAMES.iter().take(usize::try_from(READERS).unwrap_or(0)) {
        f.u32(name)
            .with(|&v, n| {
                if v == u32::MAX {
                    n.summary("unused")
                } else if v == 0 {
                    n.summary("readers use the database file only")
                } else {
                    n.summary(format!("readers see frames up to {v}"))
                }
            })
            .emit()?;
    }
    f.bytes("Locks", 8)
        .desc("aLock: bytes reserved for the shared-memory locks")
        .emit()?;
    f.u32("Backfill attempted")
        .desc("nBackfillAttempted: frames a checkpoint may have written")
        .emit()?;
    f.u32("Unused").emit()?;
    Ok(())
}

/// The frames block `k` covers: the first frame number and how many.
fn block_frames(k: u64) -> (u64, u64) {
    if k == 0 {
        (1, FRAMES_FIRST)
    } else {
        (
            FRAMES_FIRST
                .saturating_add(k.saturating_sub(1).saturating_mul(FRAMES_PER_BLOCK))
                .saturating_add(1),
            FRAMES_PER_BLOCK,
        )
    }
}

async fn block_list(cx: Cx, (span, e, max_frame): (Span, Endian, u32)) -> Result<()> {
    let blocks = span.len.div_ceil(BLOCK);
    cx.set_count(Count::Exact(blocks));
    for k in 0..blocks {
        let block = span.sub(k.saturating_mul(BLOCK), BLOCK);
        let (first, n) = block_frames(k);
        let pages_at = if k == 0 { INDEX_HDR } else { 0 };
        let last = first.saturating_add(n).saturating_sub(1);
        let used = u64::from(max_frame)
            .saturating_sub(first.saturating_sub(1))
            .min(n);
        let summary = if used == 0 {
            format!("frames {first}-{last}, none in use")
        } else {
            format!("frames {first}-{last}, {used} in use")
        };
        let mut node = Node::new(format!("Block {k}")).span(block).summary(summary);
        if block.len < BLOCK {
            node = node.diag(Diagnostic::truncated(block, block.len));
        }
        cx.push(node.lazy(block_detail, (block, e, pages_at, first, n, used)))
            .await;
    }
    Ok(())
}

async fn block_detail(
    cx: Cx,
    (block, e, pages_at, first, n, used): (Span, Endian, u64, u64, u64, u64),
) -> Result<()> {
    let pages = block.sub(pages_at, n.saturating_mul(4));
    let hash = block.sub(pages_at.saturating_add(n.saturating_mul(4)), HASH_SLOTS * 2);
    cx.emit(
        Node::new("Page numbers")
            .span(pages)
            .summary(format!(
                "{used_frame} in use",
                used_frame = plural(used, "frame")
            ))
            .lazy(page_numbers, (pages, e, first, used)),
    );
    let table = cx.read(hash).await?;
    let filled = (0..HASH_SLOTS)
        .filter(|&i| u16_at(&table, usize::try_from(i.saturating_mul(2)).unwrap_or(0), e) != 0)
        .count();
    cx.emit(
        Node::new("Hash table")
            .span(hash)
            .summary(format!("{filled} of {HASH_SLOTS} slots used"))
            .desc("Slot (page number × 383) mod 8192, probing forward, holds the frame's index in this block plus 1"),
    );
    Ok(())
}

/// The database page each frame holds, for the frames in use.
async fn page_numbers(cx: Cx, (span, e, first, used): (Span, Endian, u64, u64)) -> Result<()> {
    cx.set_count(Count::Exact(used));
    let data = cx.read(span.sub(0, used.saturating_mul(4))).await?;
    for i in 0..used {
        let at = usize::try_from(i.saturating_mul(4)).unwrap_or(usize::MAX);
        let page = u32_at(&data, at, e);
        cx.push(
            Node::new(format!("Frame {}", first.saturating_add(i)))
                .span(span.sub(to_u64(at), 4))
                .value(val::uint(page, 32))
                .desc("The database page this frame holds"),
        )
        .await;
    }
    Ok(())
}
