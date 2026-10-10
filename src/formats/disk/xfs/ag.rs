//! XFS allocation groups: the secondary superblock, the AGF, AGI and AGFL
//! headers, the AG's B+trees and its inode chunks.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::{size, unix_mode, uuid_value};
use crate::node::{Count, Node};
use crate::value::Value;

use super::btree::{Kind, TreeState, tree_block};
use super::{
    BE, FsRef, HdrCtx, NULLAGBLOCK, agbno_field, crc, crc_diag, crc_field, lsn_summary,
    rest_unused, sb_layout,
};

pub(super) async fn groups(cx: Cx, fs: FsRef) -> Result<()> {
    cx.set_count(Count::Exact(fs.ag_count));
    for ag in 0..fs.ag_count {
        let span = fs.agb_span(ag, 0, fs.ag_blocks);
        if span.is_empty() {
            cx.diag(Diagnostic::truncated(fs.vol.tail(fs.agb_offset(ag, 0)), 0));
            break;
        }
        cx.push(
            Node::new(format!("AG {ag}"))
                .span(span)
                .summary(format!(
                    "{}, from block {}",
                    size(span.len),
                    ag.saturating_mul(fs.ag_blocks)
                ))
                .lazy(group, (fs.clone(), ag)),
        )
        .await;
    }
    Ok(())
}

struct Agf {
    roots: [(u32, u32); 4],
    fl_first: u32,
    fl_count: u32,
    free: u32,
    longest: u32,
}

fn agf_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<Agf> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Version").emit()?;
    f.u32("AG number").emit()?;
    f.u32("Length (blocks)").emit()?;
    let bno_root = agbno_field(f, "By-block B+tree root").emit()?;
    let cnt_root = agbno_field(f, "By-size B+tree root").emit()?;
    let rmap_root = agbno_field(f, "Reverse mapping B+tree root").emit()?;
    let bno_level = f.u32("By-block B+tree levels").emit()?;
    let cnt_level = f.u32("By-size B+tree levels").emit()?;
    let rmap_level = f.u32("Reverse mapping B+tree levels").emit()?;
    let fl_first = f.u32("Free list first slot").emit()?;
    f.u32("Free list last slot").emit()?;
    let fl_count = f.u32("Free list count").emit()?;
    let free = f.u32("Free blocks").emit()?;
    let longest = f.u32("Longest free extent (blocks)").emit()?;
    f.u32("B+tree blocks")
        .desc("Blocks used by the free space and reverse mapping B+trees beyond their roots (LAZYSBCOUNT)")
        .emit()?;
    let (mut refc_root, mut refc_level) = (NULLAGBLOCK, 0);
    if ctx.v5 {
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        f.u32("Reverse mapping B+tree blocks").emit()?;
        f.u32("Reference count B+tree blocks").emit()?;
        refc_root = agbno_field(f, "Reference count B+tree root").emit()?;
        refc_level = f.u32("Reference count B+tree levels").emit()?;
        f.bytes("Reserved", 112).emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        crc_field(f, ctx.crc)?;
        f.u32("Padding").emit()?;
    }
    rest_unused(f, "Unused");
    Ok(Agf {
        roots: [
            (bno_root, bno_level),
            (cnt_root, cnt_level),
            (rmap_root, rmap_level),
            (refc_root, refc_level),
        ],
        fl_first,
        fl_count,
        free,
        longest,
    })
}

fn unlinked_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    const NAMES: [&str; 64] = [
        "Bucket 0",
        "Bucket 1",
        "Bucket 2",
        "Bucket 3",
        "Bucket 4",
        "Bucket 5",
        "Bucket 6",
        "Bucket 7",
        "Bucket 8",
        "Bucket 9",
        "Bucket 10",
        "Bucket 11",
        "Bucket 12",
        "Bucket 13",
        "Bucket 14",
        "Bucket 15",
        "Bucket 16",
        "Bucket 17",
        "Bucket 18",
        "Bucket 19",
        "Bucket 20",
        "Bucket 21",
        "Bucket 22",
        "Bucket 23",
        "Bucket 24",
        "Bucket 25",
        "Bucket 26",
        "Bucket 27",
        "Bucket 28",
        "Bucket 29",
        "Bucket 30",
        "Bucket 31",
        "Bucket 32",
        "Bucket 33",
        "Bucket 34",
        "Bucket 35",
        "Bucket 36",
        "Bucket 37",
        "Bucket 38",
        "Bucket 39",
        "Bucket 40",
        "Bucket 41",
        "Bucket 42",
        "Bucket 43",
        "Bucket 44",
        "Bucket 45",
        "Bucket 46",
        "Bucket 47",
        "Bucket 48",
        "Bucket 49",
        "Bucket 50",
        "Bucket 51",
        "Bucket 52",
        "Bucket 53",
        "Bucket 54",
        "Bucket 55",
        "Bucket 56",
        "Bucket 57",
        "Bucket 58",
        "Bucket 59",
        "Bucket 60",
        "Bucket 61",
        "Bucket 62",
        "Bucket 63",
    ];
    for name in NAMES {
        f.u32(name)
            .with(|&v, n| {
                if v == u32::MAX {
                    n.summary("empty")
                } else {
                    n.summary(format!("AG inode {v}"))
                }
            })
            .emit()?;
    }
    Ok(())
}

struct Agi {
    count: u32,
    root: u32,
    level: u32,
    free_count: u32,
    free_root: u32,
    free_level: u32,
}

fn agi_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<Agi> {
    f.ascii("Magic", 4).emit()?;
    f.u32("Version").emit()?;
    f.u32("AG number").emit()?;
    f.u32("Length (blocks)").emit()?;
    let count = f.u32("Allocated inodes").emit()?;
    let root = agbno_field(f, "Inode B+tree root").emit()?;
    let level = f.u32("Inode B+tree levels").emit()?;
    let free_count = f.u32("Free inodes").emit()?;
    f.u32("Newest inode chunk (AG inode)").emit()?;
    f.u32("Unused (directory inode)").emit()?;
    let buckets = f.peek_span(256);
    let raw = f
        .block()
        .data
        .get(to_usize(f.pos())..to_usize(f.pos().saturating_add(256)))
        .unwrap_or_default();
    let in_use = raw
        .as_chunks::<4>()
        .0
        .iter()
        .filter(|b| u32::from_be_bytes(**b) != u32::MAX)
        .count();
    let value = Value::UInt {
        value: to_u64(in_use),
        bits: 32,
        radix: crate::value::Radix::Dec,
    };
    f.node(if in_use == 0 {
        Node::new("Unlinked inode buckets")
            .span(buckets)
            .value(value)
            .summary("all 64 empty")
            .desc("Heads of hashed lists of inodes unlinked while still open")
    } else {
        struct_node("Unlinked inode buckets", buckets, BE, (), unlinked_layout)
            .value(value)
            .summary(format!("{in_use} buckets with unlinked inodes"))
            .desc("Heads of hashed lists of inodes unlinked while still open")
    });
    f.skip(256);
    let (mut free_root, mut free_level) = (NULLAGBLOCK, 0);
    if ctx.v5 {
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        crc_field(f, ctx.crc)?;
        f.u32("Padding").emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        free_root = agbno_field(f, "Free inode B+tree root").emit()?;
        free_level = f.u32("Free inode B+tree levels").emit()?;
        f.u32("Inode B+tree blocks").emit()?;
        f.u32("Free inode B+tree blocks").emit()?;
    }
    rest_unused(f, "Unused");
    Ok(Agi {
        count,
        root,
        level,
        free_count,
        free_root,
        free_level,
    })
}

#[derive(Clone)]
struct AgflCtx {
    fs: FsRef,
    ag: u64,
    crc: Option<u32>,
    first: u32,
    count: u32,
}

fn agfl_layout(f: &mut Fields<'_>, ctx: &AgflCtx) -> Result<()> {
    if ctx.fs.v5 {
        f.ascii("Magic", 4).emit()?;
        f.u32("AG number").emit()?;
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        crc_field(f, ctx.crc)?;
    }
    let base = f.pos();
    let slots = f.remaining() / 4;
    let data: &[u8] = &f.block().data;
    let mut active = vec![false; to_usize(slots)];
    if slots > 0 {
        for i in 0..u64::from(ctx.count).min(slots) {
            let slot = u64::from(ctx.first)
                .saturating_add(i)
                .checked_rem(slots)
                .unwrap_or(0);
            if let Some(a) = active.get_mut(to_usize(slot)) {
                *a = true;
            }
        }
    }
    let mut run_start: Option<u64> = None;
    for slot in 0..=slots {
        let on = active.get(to_usize(slot)).copied().unwrap_or(true);
        if !on {
            run_start.get_or_insert(slot);
            continue;
        }
        if let Some(start) = run_start.take() {
            let n = slot.saturating_sub(start);
            f.seek(base.saturating_add(start.saturating_mul(4)));
            f.node(
                Node::new("Unused slots")
                    .span(f.peek_span(n.saturating_mul(4)))
                    .summary(format!("slots {start}–{}", slot.saturating_sub(1))),
            );
        }
        if slot == slots {
            break;
        }
        let at = base.saturating_add(slot.saturating_mul(4));
        let block = u32_be(data, to_usize(at)).unwrap_or(0);
        f.seek(at);
        let span = f.peek_span(4);
        f.node(
            super::uint(format!("Slot {slot}"), span, block.into(), 32)
                .summary(format!("AG block {block}"))
                .target(ctx.fs.agb_span(ctx.ag, block.into(), 1)),
        );
        if u64::from(block) < ctx.fs.ag_blocks {
            f.node(
                Node::new(format!("Reserved block {block}"))
                    .span(ctx.fs.agb_span(ctx.ag, block.into(), 1))
                    .summary("held on the free list for B+tree splits"),
            );
        }
    }
    f.seek(base.saturating_add(slots.saturating_mul(4)));
    Ok(())
}

pub(super) async fn group(cx: Cx, (fs, ag): (FsRef, u64)) -> Result<()> {
    let base = fs.agb_offset(ag, 0);
    let sect = fs.sect;
    let v5 = fs.v5;
    let sb_span = fs.vol.sub(base, sect);
    if ag != 0 {
        let raw = cx.read_avail(sb_span).await?;
        let computed = if v5 { crc(&raw, 224) } else { None };
        let mut node = struct_node("Superblock (secondary)", sb_span, BE, computed, sb_layout);
        if raw.get(..4) != Some(b"XFSB".as_slice()) {
            node = node.diag(Diagnostic::malformed("bad superblock magic"));
        } else if let Some(d) = v5.then(|| crc_diag(&raw, 224, "superblock")).flatten() {
            node = node.diag(d);
        }
        cx.emit(node);
    } else {
        cx.emit(
            Node::new("Superblock (primary)")
                .span(sb_span)
                .summary("shown at the top level"),
        );
    }

    // AGF
    let agf_span = fs.vol.sub(base.saturating_add(sect), sect);
    let raw = cx.read_avail(agf_span).await?;
    let hctx = HdrCtx {
        v5,
        crc: if v5 { crc(&raw, 216) } else { None },
    };
    let agf = crate::fields::parse(&cx, agf_span, BE, &hctx, agf_layout).await;
    let mut node = struct_node("AGF (free space)", agf_span, BE, hctx, agf_layout);
    if raw.get(..4) != Some(b"XAGF".as_slice()) {
        node = node.diag(Diagnostic::malformed("bad AGF magic"));
    } else if let Some(d) = v5.then(|| crc_diag(&raw, 216, "AGF")).flatten() {
        node = node.diag(d);
    }
    if let Ok(a) = &agf {
        node = node.summary(format!(
            "{} free blocks ({}), longest free extent {} blocks",
            a.free,
            size(u64::from(a.free).saturating_mul(fs.block)),
            a.longest
        ));
    }
    cx.emit(node);

    // AGI
    let agi_span = fs
        .vol
        .sub(base.saturating_add(sect.saturating_mul(2)), sect);
    let raw = cx.read_avail(agi_span).await?;
    let hctx = HdrCtx {
        v5,
        crc: if v5 { crc(&raw, 312) } else { None },
    };
    let agi = crate::fields::parse(&cx, agi_span, BE, &hctx, agi_layout).await;
    let mut node = struct_node("AGI (inodes)", agi_span, BE, hctx, agi_layout);
    if raw.get(..4) != Some(b"XAGI".as_slice()) {
        node = node.diag(Diagnostic::malformed("bad AGI magic"));
    } else if let Some(d) = v5.then(|| crc_diag(&raw, 312, "AGI")).flatten() {
        node = node.diag(d);
    }
    if let Ok(a) = &agi {
        node = node.summary(format!("{} inodes, {} free", a.count, a.free_count));
    }
    cx.emit(node);

    // AGFL
    let agfl_span = fs
        .vol
        .sub(base.saturating_add(sect.saturating_mul(3)), sect);
    let raw = cx.read_avail(agfl_span).await?;
    let (first, count) = agf.as_ref().map_or((0, 0), |a| (a.fl_first, a.fl_count));
    let mut node = struct_node(
        "AGFL (free list)",
        agfl_span,
        BE,
        AgflCtx {
            fs: fs.clone(),
            ag,
            crc: if v5 { crc(&raw, 32) } else { None },
            first,
            count,
        },
        agfl_layout,
    )
    .summary(format!("{count} blocks reserved"));
    if v5 && raw.get(..4) != Some(b"XAFL".as_slice()) {
        node = node.diag(Diagnostic::malformed("bad AGFL magic"));
    } else if let Some(d) = v5.then(|| crc_diag(&raw, 32, "AGFL")).flatten() {
        node = node.diag(d);
    }
    cx.emit(node);
    // The rest of the header block(s), when blocks are larger than four
    // sectors.
    let headers_end = sect.saturating_mul(4);
    let first_block_end = fs.block.max(headers_end);
    if first_block_end > headers_end {
        cx.emit(
            Node::new("Unused")
                .span(fs.vol.sub(
                    base.saturating_add(headers_end),
                    first_block_end.saturating_sub(headers_end),
                ))
                .summary("rest of the AG header block"),
        );
    }

    let mut trees: Vec<(Kind, u32, u32)> = Vec::new();
    if let Ok(a) = &agf {
        let [bno, cnt, rmap, refc] = a.roots;
        trees.push((Kind::Bno, bno.0, bno.1));
        trees.push((Kind::Cnt, cnt.0, cnt.1));
        if fs.rmap {
            trees.push((Kind::Rmap, rmap.0, rmap.1));
        }
        if fs.reflink {
            trees.push((Kind::Refc, refc.0, refc.1));
        }
    }
    if let Ok(a) = &agi {
        trees.push((Kind::Ino, a.root, a.level));
        if fs.finobt {
            trees.push((Kind::Fino, a.free_root, a.free_level));
        }
    }
    for (kind, root, levels) in trees {
        let node = Node::new(kind.title()).summary(format!(
            "root at AG block {root}, {levels} level{}",
            if levels == 1 { "" } else { "s" }
        ));
        if root == NULLAGBLOCK || levels == 0 {
            cx.emit(node.summary("empty"));
            continue;
        }
        cx.emit(node.lazy(
            crate::expander!(tree_block: TreeState),
            TreeState {
                fs: fs.clone(),
                ag,
                kind,
                agbno: root,
                level: Some(levels.saturating_sub(1)),
                path: Path::new(),
            },
        ));
    }
    Ok(())
}

/// An inode chunk: 64 inodes from AG inode `start`, minus sparse holes.
#[derive(Clone)]
pub(super) struct Chunk {
    pub(super) fs: FsRef,
    pub(super) ag: u64,
    pub(super) start: u64,
    pub(super) holes: u16,
    pub(super) free: u64,
}

pub(super) async fn inode_chunk(cx: Cx, c: Chunk) -> Result<()> {
    let fs = &c.fs;
    let first = fs.ino(c.ag, c.start);
    let chunk = fs.ino_span(first)?;
    let all = cx
        .read_avail(chunk.sub(0, fs.inode_size.saturating_mul(64)))
        .await?;
    for i in 0..64u64 {
        if super::bit(c.holes.into(), i / 4) {
            continue;
        }
        let ino = fs.ino(c.ag, c.start.saturating_add(i));
        let span = match fs.ino_span(ino) {
            Ok(s) => s,
            Err(d) => {
                cx.diag(d);
                break;
            }
        };
        let at = to_usize(i.saturating_mul(fs.inode_size));
        let free = super::bit(c.free, i);
        let magic_ok = all.get(at..at.saturating_add(2)) == Some(b"IN".as_slice());
        let summary = if free {
            "free".to_owned()
        } else if magic_ok {
            let mode = u16_be(&all, at.saturating_add(2)).unwrap_or(0);
            let sz = u64_be(&all, at.saturating_add(56)).unwrap_or(0);
            format!("{}, {}", unix_mode(mode.into()), size(sz))
        } else {
            "bad magic".to_owned()
        };
        let node = Node::new(format!("Inode {ino}"))
            .span(span)
            .summary(summary);
        cx.push(if magic_ok {
            node.lazy(super::inode::view, (fs.clone(), ino))
        } else {
            node
        })
        .await;
    }
    Ok(())
}
