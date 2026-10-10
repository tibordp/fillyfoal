//! XFS B+trees: the per-AG short-form trees (free space by block and by
//! size, inodes, free inodes, reverse mappings, reference counts) and the
//! long-form extent map trees rooted in inode forks.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::{size, uuid_value};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

use super::inode::{Ext, decode_ext};
use super::{BE, FsRef, HdrCtx, agbno_field, crc, crc_field, lsn_summary, uint};

/// B+tree depth followed.
const MAX_LEVELS: usize = 12;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Kind {
    Bno,
    Cnt,
    Ino,
    Fino,
    Rmap,
    Refc,
}

impl Kind {
    pub(super) fn title(self) -> &'static str {
        match self {
            Kind::Bno => "Free space B+tree (by block)",
            Kind::Cnt => "Free space B+tree (by size)",
            Kind::Ino => "Inode B+tree",
            Kind::Fino => "Free inode B+tree",
            Kind::Rmap => "Reverse mapping B+tree",
            Kind::Refc => "Reference count B+tree",
        }
    }

    fn magic(self, v5: bool) -> &'static [u8; 4] {
        match (self, v5) {
            (Kind::Bno, true) => b"AB3B",
            (Kind::Bno, false) => b"ABTB",
            (Kind::Cnt, true) => b"AB3C",
            (Kind::Cnt, false) => b"ABTC",
            (Kind::Ino, true) => b"IAB3",
            (Kind::Ino, false) => b"IABT",
            (Kind::Fino, true) => b"FIB3",
            (Kind::Fino, false) => b"FIBT",
            (Kind::Rmap, _) => b"RMB3",
            (Kind::Refc, _) => b"R3FC",
        }
    }

    fn rec_size(self) -> u64 {
        match self {
            Kind::Bno | Kind::Cnt => 8,
            Kind::Ino | Kind::Fino => 16,
            Kind::Rmap => 24,
            Kind::Refc => 12,
        }
    }

    /// Bytes per key slot in a node (the reverse mapping tree keeps a low
    /// and a high key per child, as its records may overlap).
    fn key_size(self) -> u64 {
        match self {
            Kind::Bno | Kind::Cnt => 8,
            Kind::Ino | Kind::Fino | Kind::Refc => 4,
            Kind::Rmap => 40,
        }
    }
}

/// Short-form (AG) B+tree block header.
fn short_header(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u16("Level").desc("0 for a leaf").emit()?;
    f.u16("Records").emit()?;
    agbno_field(f, "Left sibling").emit()?;
    agbno_field(f, "Right sibling").emit()?;
    if ctx.v5 {
        f.u64("Disk address (512-byte units)").hex().emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        f.u32("Owner (AG)").emit()?;
        crc_field(f, ctx.crc)?;
    }
    Ok(())
}

/// Long-form (inode) B+tree block header.
fn long_header(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    f.u16("Level").desc("0 for a leaf").emit()?;
    f.u16("Records").emit()?;
    fsb_field(f, "Left sibling")?;
    fsb_field(f, "Right sibling")?;
    if ctx.v5 {
        f.u64("Disk address (512-byte units)").hex().emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        f.u64("Owner (inode)").emit()?;
        crc_field(f, ctx.crc)?;
        f.u32("Padding").emit()?;
    }
    Ok(())
}

fn fsb_field(f: &mut Fields<'_>, name: &'static str) -> Result<u64> {
    f.u64(name)
        .with(|&v, n| if v == u64::MAX { n.summary("none") } else { n })
        .emit()
}

#[derive(Clone)]
pub(super) struct TreeState {
    pub(super) fs: FsRef,
    pub(super) ag: u64,
    pub(super) kind: Kind,
    pub(super) agbno: u32,
    /// The level this block should have (from its parent or the AG header).
    pub(super) level: Option<u32>,
    pub(super) path: Path,
}

/// The owner of a reverse mapping.
fn owner_text(owner: u64) -> String {
    match owner {
        u64::MAX => "nothing".into(),
        0xffff_ffff_ffff_fffe => "unknown owner".into(),
        0xffff_ffff_ffff_fffd => "static filesystem metadata".into(),
        0xffff_ffff_ffff_fffc => "log".into(),
        0xffff_ffff_ffff_fffb => "AG B+trees and free list".into(),
        0xffff_ffff_ffff_fffa => "inode B+trees".into(),
        0xffff_ffff_ffff_fff9 => "inode chunks".into(),
        0xffff_ffff_ffff_fff8 => "reference count B+tree".into(),
        0xffff_ffff_ffff_fff7 => "copy-on-write staging".into(),
        0xffff_ffff_ffff_fff6 => "bad blocks".into(),
        n => format!("inode {n}"),
    }
}

const RMAP_OFFSET_MASK: u64 = 0x003f_ffff_ffff_ffff;

fn rmap_offset_text(raw: u64) -> String {
    let mut parts = vec![format!("block {}", raw & RMAP_OFFSET_MASK)];
    if raw >> 63 != 0 {
        parts.push("attribute fork".into());
    }
    if (raw >> 62) & 1 != 0 {
        parts.push("extent map B+tree block".into());
    }
    if (raw >> 61) & 1 != 0 {
        parts.push("unwritten".into());
    }
    parts.join(", ")
}

fn blocks_text(start: u64, count: u64) -> String {
    format!(
        "blocks {start}–{}",
        start.saturating_add(count).saturating_sub(1)
    )
}

/// One record of an AG B+tree leaf: a summary for its node.
fn record_summary(st: &TreeState, rec: &[u8]) -> String {
    let fs = &st.fs;
    let a = u64::from(u32_be(rec, 0).unwrap_or(0));
    let b = u64::from(u32_be(rec, 4).unwrap_or(0));
    match st.kind {
        Kind::Bno | Kind::Cnt => format!(
            "{}, {}",
            blocks_text(a, b),
            size(b.saturating_mul(fs.block))
        ),
        Kind::Ino | Kind::Fino => {
            let free = u64_be(rec, 8).unwrap_or(0);
            format!(
                "inodes {}–{}, {} free",
                fs.ino(st.ag, a),
                fs.ino(st.ag, a.saturating_add(63)),
                free.count_ones()
            )
        }
        Kind::Rmap => {
            let owner = u64_be(rec, 8).unwrap_or(0);
            let offset = u64_be(rec, 16).unwrap_or(0);
            if owner > 0xffff_ffff_ffff_ff00 {
                format!("{}: {}", blocks_text(a, b), owner_text(owner))
            } else {
                format!(
                    "{}: {}, {}",
                    blocks_text(a, b),
                    owner_text(owner),
                    rmap_offset_text(offset)
                )
            }
        }
        Kind::Refc => {
            let refs = u32_be(rec, 8).unwrap_or(0);
            let cow = a >> 31 != 0;
            format!(
                "{}: {}",
                blocks_text(a & 0x7fff_ffff, b),
                if cow {
                    "copy-on-write staging".to_owned()
                } else {
                    format!("{refs} references")
                }
            )
        }
    }
}

#[derive(Clone)]
struct RecCtx {
    fs: FsRef,
    ag: u64,
    kind: Kind,
}

fn record_layout(f: &mut Fields<'_>, ctx: &RecCtx) -> Result<()> {
    let fs = &ctx.fs;
    let ag = ctx.ag;
    match ctx.kind {
        Kind::Bno | Kind::Cnt => {
            let start = f.u32("Start block").emit()?;
            let count = f
                .u32("Block count")
                .with(|&v, n| n.summary(size(u64::from(v).saturating_mul(fs.block))))
                .emit()?;
            let span = fs.agb_span(ag, start.into(), count.into());
            if ctx.kind == Kind::Bno {
                f.node(
                    Node::new("Free space")
                        .span(span)
                        .summary(size(span.len))
                        .desc("Unallocated blocks"),
                );
            }
        }
        Kind::Ino | Kind::Fino => {
            let start = f
                .u32("First inode (in AG)")
                .with(|&v, n| n.summary(format!("inode {}", fs.ino(ag, v.into()))))
                .emit()?;
            let mut holes = 0u16;
            if fs.sparse_inodes {
                holes = f
                    .u16("Hole mask")
                    .hex()
                    .desc("Each set bit marks 4 inodes of the chunk that are not allocated (a sparse chunk)")
                    .emit()?;
                f.u8("Inodes in chunk").emit()?;
                f.u8("Free inodes").emit()?;
            } else {
                f.u32("Free inodes").emit()?;
            }
            let free = f
                .u64("Free mask")
                .hex()
                .desc("Bit i set: inode i of the chunk is free")
                .emit()?;
            if ctx.kind == Kind::Ino {
                f.node(
                    Node::new("Inodes")
                        .span(chunk_span(fs, ag, start.into(), holes))
                        .summary(format!(
                            "{} allocated, {} free",
                            64u32.saturating_sub(free.count_ones()),
                            free.count_ones()
                        ))
                        .lazy(
                            super::ag::inode_chunk,
                            super::ag::Chunk {
                                fs: fs.clone(),
                                ag,
                                start: start.into(),
                                holes,
                                free,
                            },
                        ),
                );
            }
        }
        Kind::Rmap => {
            let start = f.u32("Start block").emit()?;
            f.u32("Block count")
                .with(|&v, n| {
                    n.summary(size(u64::from(v).saturating_mul(fs.block)))
                        .target(fs.agb_span(ag, start.into(), v.into()))
                })
                .emit()?;
            f.u64("Owner")
                .with(|&v, n| n.summary(owner_text(v)))
                .emit()?;
            f.u64("Offset and flags")
                .with(|&v, n| {
                    n.value(Value::UInt {
                        value: v & RMAP_OFFSET_MASK,
                        bits: 54,
                        radix: Radix::Dec,
                    })
                    .summary(rmap_offset_text(v))
                })
                .desc("Logical block within the owner; the top bits flag the attribute fork, extent map B+tree blocks and unwritten extents")
                .emit()?;
        }
        Kind::Refc => {
            f.u32("Start block")
                .with(|&v, n| {
                    if v >> 31 != 0 {
                        n.summary(format!(
                            "block {}, copy-on-write staging domain",
                            v & 0x7fff_ffff
                        ))
                    } else {
                        n
                    }
                })
                .emit()?;
            f.u32("Block count").emit()?;
            f.u32("Reference count").emit()?;
        }
    }
    Ok(())
}

/// The blocks of an inode chunk (sparse holes included).
fn chunk_span(fs: &FsRef, ag: u64, start: u64, _holes: u16) -> Span {
    let agbno = start.checked_shr(fs.inopb_log).unwrap_or(0);
    fs.vol
        .sub(fs.agb_offset(ag, agbno), fs.inode_size.saturating_mul(64))
}

fn key_layout(f: &mut Fields<'_>, kind: &Kind) -> Result<()> {
    match kind {
        Kind::Bno | Kind::Cnt => {
            f.u32("Start block").emit()?;
            f.u32("Block count").emit()?;
        }
        Kind::Ino | Kind::Fino => {
            f.u32("First inode (in AG)").emit()?;
        }
        Kind::Refc => {
            f.u32("Start block").emit()?;
        }
        Kind::Rmap => {
            for (block, owner, offset) in [
                ("Low key: start block", "Low key: owner", "Low key: offset"),
                (
                    "High key: start block",
                    "High key: owner",
                    "High key: offset",
                ),
            ] {
                f.u32(block).emit()?;
                f.u64(owner).with(|&v, n| n.summary(owner_text(v))).emit()?;
                f.u64(offset)
                    .with(|&v, n| n.summary(rmap_offset_text(v)))
                    .emit()?;
            }
        }
    }
    Ok(())
}

fn key_summary(kind: Kind, key: &[u8]) -> String {
    let a = u32_be(key, 0).unwrap_or(0);
    match kind {
        Kind::Bno | Kind::Refc => format!("from block {a}"),
        Kind::Cnt => format!("from {} blocks at {a}", u32_be(key, 4).unwrap_or(0)),
        Kind::Ino | Kind::Fino => format!("from AG inode {a}"),
        Kind::Rmap => format!("blocks {a}–{}", u32_be(key, 20).unwrap_or(0)),
    }
}

/// Emits an unused region of a block, if any.
fn unused(cx: &Cx, block: Span, from: u64, to: u64, name: &'static str) {
    if to > from {
        let span = block.sub(from, to.saturating_sub(from));
        cx.emit(Node::new(name).span(span).summary(size(span.len)));
    }
}

/// Expands one block of an AG B+tree.
pub(super) async fn tree_block(cx: Cx, st: TreeState) -> Result<()> {
    let fs = st.fs.clone();
    if u64::from(st.agbno) >= fs.ag_blocks {
        return Err(Diagnostic::malformed(format!(
            "block {} lies outside the AG",
            st.agbno
        )));
    }
    let span = fs.agb_span(st.ag, st.agbno.into(), 1);
    let data = cx.read(span).await?;
    let hdr: u64 = if fs.v5 { 56 } else { 16 };
    let computed = if fs.v5 { crc(&data, 52) } else { None };
    cx.emit(
        struct_node(
            "Header",
            span.sub(0, hdr),
            BE,
            HdrCtx {
                v5: fs.v5,
                crc: computed,
            },
            short_header,
        )
        .summary(format!(
            "level {}, {} records",
            u16_be(&data, 4).unwrap_or(0),
            u16_be(&data, 6).unwrap_or(0)
        )),
    );
    let magic = st.kind.magic(fs.v5);
    if data.get(..4) != Some(magic.as_slice()) {
        return Err(Diagnostic::malformed(format!(
            "expected magic {}",
            String::from_utf8_lossy(magic)
        ))
        .at(span.sub(0, 4)));
    }
    let level = u32::from(u16_be(&data, 4).unwrap_or(0));
    let numrecs = u64::from(u16_be(&data, 6).unwrap_or(0));
    if let Some(want) = st.level
        && want != level
    {
        cx.diag(Diagnostic::malformed(format!(
            "block is at level {level}, expected {want}"
        )));
    }
    let room = fs.block.saturating_sub(hdr);
    if level == 0 {
        let rs = st.kind.rec_size();
        let max = room.checked_div(rs).unwrap_or(0);
        if numrecs > max {
            cx.diag(Diagnostic::malformed(format!(
                "{numrecs} records do not fit in a block (at most {max})"
            )));
        }
        let n = numrecs.min(max);
        let ctx = RecCtx {
            fs: fs.clone(),
            ag: st.ag,
            kind: st.kind,
        };
        for i in 0..n {
            let off = hdr.saturating_add(i.saturating_mul(rs));
            let rec = data
                .get(to_usize(off)..to_usize(off.saturating_add(rs)))
                .unwrap_or_default();
            cx.push(
                struct_node(
                    format!("Record {i}"),
                    span.sub(off, rs),
                    BE,
                    ctx.clone(),
                    record_layout,
                )
                .summary(record_summary(&st, rec)),
            )
            .await;
        }
        unused(
            &cx,
            span,
            hdr.saturating_add(n.saturating_mul(rs)),
            fs.block,
            "Unused",
        );
        return Ok(());
    }
    let ks = st.kind.key_size();
    let max = room.checked_div(ks.saturating_add(4)).unwrap_or(0);
    if numrecs > max {
        cx.diag(Diagnostic::malformed(format!(
            "{numrecs} keys do not fit in a block (at most {max})"
        )));
    }
    let n = numrecs.min(max);
    let ptrs = hdr.saturating_add(max.saturating_mul(ks));
    cx.emit(
        Node::new("Keys")
            .span(span.sub(hdr, n.saturating_mul(ks)))
            .summary(format!("{n} keys"))
            .lazy(keys, (span.sub(hdr, n.saturating_mul(ks)), st.kind)),
    );
    unused(
        &cx,
        span,
        hdr.saturating_add(n.saturating_mul(ks)),
        ptrs,
        "Unused key slots",
    );
    for i in 0..n {
        let at = ptrs.saturating_add(i.saturating_mul(4));
        let child = u32_be(&data, to_usize(at)).unwrap_or(0);
        let key_at = to_usize(hdr.saturating_add(i.saturating_mul(ks)));
        let key = data
            .get(key_at..key_at.saturating_add(to_usize(ks)))
            .unwrap_or_default();
        let node = uint(format!("Child {i}"), span.sub(at, 4), child.into(), 32)
            .summary(format!("AG block {child}, {}", key_summary(st.kind, key)));
        let node = match st.path.enter(child.into(), MAX_LEVELS) {
            Ok(path) => node.lazy(
                crate::expander!(self::tree_block: TreeState),
                TreeState {
                    fs: fs.clone(),
                    ag: st.ag,
                    kind: st.kind,
                    agbno: child,
                    level: Some(level.saturating_sub(1)),
                    path,
                },
            ),
            Err(d) => node.diag(d),
        };
        cx.push(node).await;
    }
    unused(
        &cx,
        span,
        ptrs.saturating_add(n.saturating_mul(4)),
        fs.block,
        "Unused pointer slots",
    );
    Ok(())
}

async fn keys(cx: Cx, (span, kind): (Span, Kind)) -> Result<()> {
    let data = cx.read(span).await?;
    let ks = kind.key_size();
    let n = span.len.checked_div(ks).unwrap_or(0);
    for i in 0..n {
        let at = i.saturating_mul(ks);
        let key = data
            .get(to_usize(at)..to_usize(at.saturating_add(ks)))
            .unwrap_or_default();
        cx.push(
            struct_node(format!("Key {i}"), span.sub(at, ks), BE, kind, key_layout)
                .summary(key_summary(kind, key)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Extent maps

/// A node for one packed extent record (`xfs_bmbt_rec`).
pub(super) fn ext_node(fs: &FsRef, name: String, span: Span, rec: &[u8]) -> Node {
    let Some(e) = decode_ext(rec) else {
        return Node::new(name)
            .span(span)
            .diag(Diagnostic::truncated(span, to_u64(rec.len())));
    };
    let summary = format!(
        "file blocks {}–{} → {}{}",
        e.off,
        e.off.saturating_add(e.count).saturating_sub(1),
        fs.fsb_text(e.fsb),
        if e.unwritten { ", unwritten" } else { "" }
    );
    Node::new(name)
        .span(span)
        .summary(summary)
        .lazy(ext_fields, (span, e, fs.fsb_text(e.fsb), fs.block))
}

async fn ext_fields(cx: Cx, (span, e, at, block): (Span, Ext, String, u64)) -> Result<()> {
    cx.emit(
        Node::new("Unwritten")
            .span(span.sub(0, 1))
            .value(Value::Bool(e.unwritten))
            .desc("Bit 127: preallocated space that reads as zeros"),
    );
    cx.emit(
        uint("File offset (blocks)", span.sub(0, 7), e.off, 54)
            .desc("Bits 126–73: the first logical block of the file this extent maps"),
    );
    cx.emit(
        uint("Start block", span.sub(6, 8), e.fsb, 52)
            .summary(at)
            .desc("Bits 72–21: the absolute filesystem block (AG number in the high bits)"),
    );
    cx.emit(
        uint("Block count", span.sub(13, 3), e.count, 21)
            .summary(size(e.count.saturating_mul(block)))
            .desc("Bits 20–0"),
    );
    Ok(())
}

#[derive(Clone)]
pub(super) struct BmbtState {
    pub(super) fs: FsRef,
    pub(super) fsb: u64,
    pub(super) level: Option<u32>,
    pub(super) path: Path,
}

/// The root of an extent map B+tree in an inode fork (`xfs_bmdr_block`).
pub(super) async fn bmdr_root(cx: Cx, (fs, fork): (FsRef, Span)) -> Result<()> {
    let data = cx.read(fork).await?;
    let level = u16_be(&data, 0).unwrap_or(0);
    let numrecs = u64::from(u16_be(&data, 2).unwrap_or(0));
    cx.emit(uint("Level", fork.sub(0, 2), level.into(), 16));
    cx.emit(uint("Records", fork.sub(2, 2), numrecs, 16));
    let max = fork.len.saturating_sub(4).checked_div(16).unwrap_or(0);
    if level == 0 {
        return Err(Diagnostic::malformed("extent map B+tree root at level 0").at(fork));
    }
    if numrecs > max {
        cx.diag(Diagnostic::malformed(format!(
            "{numrecs} keys do not fit in the fork (at most {max})"
        )));
    }
    let n = numrecs.min(max);
    let ptrs = 4u64.saturating_add(max.saturating_mul(8));
    pointers(
        &cx,
        &fs,
        &data,
        fork,
        4,
        ptrs,
        n,
        level.into(),
        &Path::new(),
    )
    .await;
    unused(
        &cx,
        fork,
        4u64.saturating_add(n.saturating_mul(8)),
        ptrs,
        "Unused key slots",
    );
    unused(
        &cx,
        fork,
        ptrs.saturating_add(n.saturating_mul(8)),
        fork.len,
        "Unused pointer slots",
    );
    Ok(())
}

/// Keys (file offsets) and child pointers of an extent map B+tree node.
#[allow(clippy::too_many_arguments)]
async fn pointers(
    cx: &Cx,
    fs: &FsRef,
    data: &[u8],
    span: Span,
    keys: u64,
    ptrs: u64,
    n: u64,
    level: u32,
    path: &Path,
) {
    for i in 0..n {
        let key_at = keys.saturating_add(i.saturating_mul(8));
        let at = ptrs.saturating_add(i.saturating_mul(8));
        let key = u64_be(data, to_usize(key_at)).unwrap_or(0);
        let child = u64_be(data, to_usize(at)).unwrap_or(0);
        cx.push(
            uint(format!("Key {i}"), span.sub(key_at, 8), key, 64)
                .summary(format!("from file block {key}")),
        )
        .await;
        let node =
            uint(format!("Child {i}"), span.sub(at, 8), child, 64).summary(fs.fsb_text(child));
        let node = if !fs.fsb_valid(child) {
            node.diag(Diagnostic::malformed("block outside the filesystem"))
        } else {
            match path.enter(child, MAX_LEVELS) {
                Ok(path) => node.lazy(
                    crate::expander!(self::bmbt_block: BmbtState),
                    BmbtState {
                        fs: fs.clone(),
                        fsb: child,
                        level: Some(level.saturating_sub(1)),
                        path,
                    },
                ),
                Err(d) => node.diag(d),
            }
        };
        cx.push(node).await;
    }
}

/// One block of an extent map B+tree.
pub(super) async fn bmbt_block(cx: Cx, st: BmbtState) -> Result<()> {
    let fs = st.fs.clone();
    let span = fs.fsb_span(st.fsb, 1);
    let data = cx.read(span).await?;
    let hdr: u64 = if fs.v5 { 72 } else { 24 };
    let computed = if fs.v5 { crc(&data, 64) } else { None };
    cx.emit(
        struct_node(
            "Header",
            span.sub(0, hdr),
            BE,
            HdrCtx {
                v5: fs.v5,
                crc: computed,
            },
            long_header,
        )
        .summary(format!(
            "level {}, {} records",
            u16_be(&data, 4).unwrap_or(0),
            u16_be(&data, 6).unwrap_or(0)
        )),
    );
    let magic: &[u8] = if fs.v5 { b"BMA3" } else { b"BMAP" };
    if data.get(..4) != Some(magic) {
        return Err(Diagnostic::malformed(format!(
            "expected magic {}",
            String::from_utf8_lossy(magic)
        ))
        .at(span.sub(0, 4)));
    }
    let level = u32::from(u16_be(&data, 4).unwrap_or(0));
    let numrecs = u64::from(u16_be(&data, 6).unwrap_or(0));
    if let Some(want) = st.level
        && want != level
    {
        cx.diag(Diagnostic::malformed(format!(
            "block is at level {level}, expected {want}"
        )));
    }
    let max = fs.block.saturating_sub(hdr).checked_div(16).unwrap_or(0);
    if numrecs > max {
        cx.diag(Diagnostic::malformed(format!(
            "{numrecs} entries do not fit in a block (at most {max})"
        )));
    }
    let n = numrecs.min(max);
    if level == 0 {
        for i in 0..n {
            let off = hdr.saturating_add(i.saturating_mul(16));
            let rec = data
                .get(to_usize(off)..to_usize(off.saturating_add(16)))
                .unwrap_or_default();
            cx.push(ext_node(&fs, format!("Extent {i}"), span.sub(off, 16), rec))
                .await;
        }
        unused(
            &cx,
            span,
            hdr.saturating_add(n.saturating_mul(16)),
            fs.block,
            "Unused",
        );
        return Ok(());
    }
    let ptrs = hdr.saturating_add(max.saturating_mul(8));
    pointers(&cx, &fs, &data, span, hdr, ptrs, n, level, &st.path).await;
    unused(
        &cx,
        span,
        hdr.saturating_add(n.saturating_mul(8)),
        ptrs,
        "Unused key slots",
    );
    unused(
        &cx,
        span,
        ptrs.saturating_add(n.saturating_mul(8)),
        fs.block,
        "Unused pointer slots",
    );
    Ok(())
}
