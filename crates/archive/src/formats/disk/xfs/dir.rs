//! XFS directories: short-form (in the inode), block, leaf and node forms.
//!
//! A directory's data fork maps three regions of its logical address
//! space: data blocks (entries) from 0, leaf and DA B+tree node blocks
//! (hash → entry address) from 32 GiB, and free index blocks (the largest
//! free space of each data block) from 64 GiB. A single-block directory
//! keeps its leaf entries at the end of its only data block.

use std::collections::BTreeSet;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::name_field;
use crate::formats::disk::{size, uuid_value};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

use super::inode::{
    Dinode, Ext, FMT_BTREE, FMT_EXTENTS, FMT_LOCAL, S_IFDIR, extents, logical_span,
};
use super::{BE, Fs, FsRef, HdrCtx, MAX_DIR_DEPTH, crc, crc_field, lsn_summary, uint};

/// Directory blocks visited in one directory.
const MAX_DIR_BLOCKS: usize = 1 << 16;
/// Logical byte offsets of the leaf and free index regions.
const LEAF_OFFSET: u64 = 1 << 35;
const FREE_OFFSET: u64 = 1 << 36;

pub(super) const FTYPES: EnumTable = crate::formats::disk::dirent_types!((8, "whiteout"));

/// A file type from a Unix mode.
fn mode_kind(mode: u16) -> &'static str {
    match mode & 0xf000 {
        0x8000 => "regular file",
        0x4000 => "directory",
        0x2000 => "character device",
        0x6000 => "block device",
        0x1000 => "FIFO",
        0xc000 => "socket",
        0xa000 => "symbolic link",
        _ => "unknown",
    }
}

// ---------------------------------------------------------------------------
// Short-form directories

struct SfEnt {
    off: usize,
    len: usize,
    name: Vec<u8>,
    ino: u64,
    ftype: u8,
}

struct Sf {
    wide: bool,
    entries: Vec<SfEnt>,
    problem: Option<Diagnostic>,
}

fn sf_parse(data: &[u8], ftype: bool) -> Sf {
    let count = usize::from(data.first().copied().unwrap_or(0));
    let wide = data.get(1).copied().unwrap_or(0) > 0;
    let isize: usize = if wide { 8 } else { 4 };
    let read_ino = |at: usize| -> Option<u64> {
        if wide {
            u64_be(data, at)
        } else {
            u32_be(data, at).map(u64::from)
        }
    };
    let mut at = 2usize.saturating_add(isize);
    let mut entries = Vec::new();
    let mut problem = None;
    for _ in 0..count {
        let Some(&namelen) = data.get(at) else {
            problem = Some(Diagnostic::malformed(
                "short-form directory entry truncated",
            ));
            break;
        };
        let namelen = usize::from(namelen);
        let name_at = at.saturating_add(3);
        let ft_at = name_at.saturating_add(namelen);
        let ino_at = ft_at.saturating_add(usize::from(ftype));
        let len = ino_at.saturating_add(isize).saturating_sub(at);
        let (Some(name), Some(ino)) = (data.get(name_at..ft_at), read_ino(ino_at)) else {
            problem = Some(Diagnostic::malformed(
                "short-form directory entry truncated",
            ));
            break;
        };
        entries.push(SfEnt {
            off: at,
            len,
            name: name.to_vec(),
            ino,
            ftype: if ftype {
                data.get(ft_at).copied().unwrap_or(0)
            } else {
                0
            },
        });
        at = at.saturating_add(len);
    }
    Sf {
        wide,
        entries,
        problem,
    }
}

#[derive(Clone, Copy)]
struct SfEntCtx {
    ftype: bool,
    wide: bool,
}

fn sf_entry_layout(f: &mut Fields<'_>, ctx: &SfEntCtx) -> Result<()> {
    let namelen = f.u8("Name length").emit()?;
    f.u16("Offset")
        .desc("The offset this entry would have in a block directory (the readdir cookie)")
        .emit()?;
    name_field(f, namelen.into())?;
    if ctx.ftype {
        f.u8("File type").enumeration(FTYPES).emit()?;
    }
    f.uword("Inode", ctx.wide).emit()?;
    Ok(())
}

/// A short-form directory in the data fork.
pub(super) fn sf_layout(f: &mut Fields<'_>, fs: &FsRef) -> Result<()> {
    let data: &[u8] = &f.block().data;
    let start = to_usize(f.pos());
    let sf = sf_parse(data.get(start..).unwrap_or_default(), fs.ftype);
    f.u8("Entries").emit()?;
    f.u8("Entries with 8-byte inode numbers")
        .desc("Nonzero when some inode number needs 64 bits; all entries then use 8 bytes")
        .emit()?;
    f.uword("Parent inode", sf.wide).emit()?;
    for e in &sf.entries {
        f.seek(to_u64(start.saturating_add(e.off)));
        let len = to_u64(e.len);
        let kind = if fs.ftype {
            lookup(FTYPES, e.ftype.into()).unwrap_or("unknown")
        } else {
            "entry"
        };
        f.node(
            struct_node(
                String::from_utf8_lossy(&e.name).into_owned(),
                f.peek_span(len),
                BE,
                SfEntCtx {
                    ftype: fs.ftype,
                    wide: sf.wide,
                },
                sf_entry_layout,
            )
            .summary(format!("{kind}, inode {}", e.ino)),
        );
        f.skip(len);
    }
    if let Some(d) = sf.problem {
        f.node(Node::new("Malformed entry").span(f.peek_span(0)).diag(d));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Data blocks

struct DataEnt {
    off: u64,
    len: u64,
    /// (inode, name, file type) of a used entry; `None` for free space.
    used: Option<(u64, Vec<u8>, u8)>,
}

/// The entries of a data block between `start` and `end`.
fn data_entries(
    data: &[u8],
    start: u64,
    end: u64,
    ftype: bool,
) -> (Vec<DataEnt>, Option<Diagnostic>) {
    let mut out = Vec::new();
    let mut pos = start;
    while pos < end {
        let at = to_usize(pos);
        let entry = if u16_be(data, at) == Some(0xffff) {
            let len = u64::from(u16_be(data, at.saturating_add(2)).unwrap_or(0));
            DataEnt {
                off: pos,
                len,
                used: None,
            }
        } else {
            let ino = u64_be(data, at).unwrap_or(0);
            let namelen = usize::from(data.get(at.saturating_add(8)).copied().unwrap_or(0));
            let name_at = at.saturating_add(9);
            let fixed = 8u64
                .saturating_add(1)
                .saturating_add(to_u64(namelen))
                .saturating_add(u64::from(ftype))
                .saturating_add(2);
            let ft = if ftype {
                data.get(name_at.saturating_add(namelen))
                    .copied()
                    .unwrap_or(0)
            } else {
                0
            };
            DataEnt {
                off: pos,
                len: fixed.next_multiple_of(8),
                used: Some((
                    ino,
                    data.get(name_at..name_at.saturating_add(namelen))
                        .unwrap_or_default()
                        .to_vec(),
                    ft,
                )),
            }
        };
        if entry.len < 8 || entry.len % 8 != 0 || pos.saturating_add(entry.len) > end {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "bad directory entry length {} at block offset {pos}",
                    entry.len
                ))),
            );
        }
        pos = pos.saturating_add(entry.len);
        out.push(entry);
    }
    (out, None)
}

/// What a directory block is, by its magic.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum BlockKind {
    /// A single-block directory: data, leaf entries and a tail.
    Block,
    Data,
    Leaf1,
    LeafN,
    Node,
    Free,
    Unknown,
}

fn block_kind(data: &[u8]) -> BlockKind {
    match (data.get(..4), u16_be(data, 8)) {
        (Some(b"XD2B" | b"XDB3"), _) => BlockKind::Block,
        (Some(b"XD2D" | b"XDD3"), _) => BlockKind::Data,
        (Some(b"XD2F" | b"XDF3"), _) => BlockKind::Free,
        (_, Some(0xd2f1 | 0x3df1)) => BlockKind::Leaf1,
        (_, Some(0xd2ff | 0x3dff)) => BlockKind::LeafN,
        (_, Some(0xfebe | 0x3ebe)) => BlockKind::Node,
        _ => BlockKind::Unknown,
    }
}

fn data_header_len(fs: &Fs) -> u64 {
    if fs.v5 { 64 } else { 16 }
}

/// The byte range of a data (or single) block's entries.
fn data_area(fs: &Fs, kind: BlockKind, data: &[u8]) -> Result<(u64, u64)> {
    let len = to_u64(data.len());
    let start = data_header_len(fs);
    if kind != BlockKind::Block {
        return Ok((start, len));
    }
    let count = u64::from(u32_be(data, to_usize(len.saturating_sub(8))).unwrap_or(0));
    let leaf = len
        .saturating_sub(8)
        .checked_sub(count.saturating_mul(8))
        .filter(|&l| l >= start)
        .ok_or_else(|| Diagnostic::malformed(format!("{count} leaf entries do not fit")))?;
    Ok((start, leaf))
}

/// The logical blocks where directory blocks start, between two logical
/// byte offsets of the directory.
async fn block_starts(cx: &Cx, fs: &Fs, exts: &[Ext], from: u64, to: u64) -> Vec<u64> {
    let per = fs.dir_fsbs.max(1);
    let lo = from.checked_div(fs.block).unwrap_or(0);
    let hi = to.checked_div(fs.block).unwrap_or(0);
    let mut out = BTreeSet::new();
    for e in exts {
        cx.checkpoint().await;
        let first = e.off.max(lo);
        let last = e.off.saturating_add(e.count).min(hi);
        if first >= last {
            continue;
        }
        let mut d = first.checked_div(per).unwrap_or(0).saturating_mul(per);
        while d < last {
            out.insert(d);
            if out.len() >= MAX_DIR_BLOCKS {
                return out.into_iter().collect();
            }
            d = d.saturating_add(per);
            if out.len().is_multiple_of(256) {
                cx.checkpoint().await;
            }
        }
    }
    out.into_iter().collect()
}

#[derive(Clone)]
pub(super) struct DirState {
    pub(super) fs: FsRef,
    pub(super) ino: u64,
    pub(super) path: Path,
}

/// The file type of inode `ino` from its mode, when the directory does not
/// record it.
async fn mode_of(cx: &Cx, fs: &Fs, ino: u64) -> Option<u16> {
    let span = fs.ino_span(ino).ok()?;
    let head = cx.read(span.sub(0, 4)).await.ok()?;
    (head.get(..2) == Some(b"IN".as_slice()))
        .then(|| u16_be(&head, 2))
        .flatten()
}

async fn entry_node(cx: &Cx, st: &DirState, name: &[u8], ino: u64, ftype: u8, span: Span) -> Node {
    let fs = &st.fs;
    let (kind, is_dir) = if fs.ftype {
        (
            lookup(FTYPES, ftype.into()).unwrap_or("unknown"),
            ftype == 2,
        )
    } else {
        match mode_of(cx, fs, ino).await {
            Some(mode) => (mode_kind(mode), mode & 0xf000 == S_IFDIR),
            None => ("unknown", false),
        }
    };
    let node = Node::new(String::from_utf8_lossy(name).into_owned())
        .span(span)
        .value(Value::UInt {
            value: ino,
            bits: 64,
            radix: Radix::Dec,
        })
        .summary(format!("{kind}, inode {ino}"));
    if is_dir {
        match st.path.enter(ino, MAX_DIR_DEPTH) {
            Ok(path) => node.lazy(
                crate::expander!(self::directory: DirState),
                DirState {
                    fs: fs.clone(),
                    ino,
                    path,
                },
            ),
            Err(d) => node.diag(d),
        }
    } else {
        node.lazy(super::inode::view, (fs.clone(), ino))
    }
}

/// Lists a directory: its inode, then its entries (paged).
pub(super) async fn directory(cx: Cx, st: DirState) -> Result<()> {
    let fs = st.fs.clone();
    let di = Dinode::read(&cx, &fs, st.ino).await?;
    if di.kind() != S_IFDIR {
        return Err(
            Diagnostic::malformed(format!("inode {} is not a directory", st.ino)).at(di.span),
        );
    }
    cx.emit(
        Node::new("Inode")
            .span(di.span)
            .summary(format!("inode {}, {}", st.ino, di.summary()))
            .lazy(super::inode::view, (fs.clone(), st.ino)),
    );
    match di.format {
        FMT_LOCAL => {
            let (span, bytes) = di.dfork();
            let sf = sf_parse(bytes.get(..to_usize(di.size)).unwrap_or(bytes), fs.ftype);
            for e in &sf.entries {
                let node = entry_node(
                    &cx,
                    &st,
                    &e.name,
                    e.ino,
                    e.ftype,
                    span.sub(to_u64(e.off), to_u64(e.len)),
                )
                .await;
                cx.push(node).await;
            }
            if let Some(d) = sf.problem {
                cx.diag(d.at(span));
            }
        }
        FMT_EXTENTS | FMT_BTREE => {
            let (exts, problem) = extents(&cx, &fs, &di, false).await?;
            if let Some(d) = problem {
                cx.diag(d);
            }
            let starts = block_starts(&cx, &fs, &exts, 0, LEAF_OFFSET).await;
            for (i, &lblk) in starts.iter().enumerate() {
                cx.progress(to_u64(i), to_u64(starts.len()));
                let Some(span) =
                    logical_span(&cx, &fs, &exts, lblk, fs.dir_fsbs, "xfs-dir-block").await?
                else {
                    continue;
                };
                let data = cx.read_avail(span).await?;
                let kind = block_kind(&data);
                if !matches!(kind, BlockKind::Block | BlockKind::Data) {
                    cx.diag(
                        Diagnostic::malformed(format!(
                            "directory data block at logical block {lblk} has a bad magic"
                        ))
                        .at(span.sub(0, 4)),
                    );
                    continue;
                }
                let (start, end) = match data_area(&fs, kind, &data) {
                    Ok(area) => area,
                    Err(d) => {
                        cx.diag(d.at(span));
                        continue;
                    }
                };
                let (entries, problem) = data_entries(&data, start, end, fs.ftype);
                for e in entries {
                    let Some((ino, name, ftype)) = e.used else {
                        continue;
                    };
                    if name == b"." || name == b".." {
                        continue;
                    }
                    let node =
                        entry_node(&cx, &st, &name, ino, ftype, span.sub(e.off, e.len)).await;
                    cx.push(node).await;
                }
                if let Some(d) = problem {
                    cx.diag(d.at(span));
                }
            }
        }
        _ => {
            return Err(Diagnostic::unsupported(format!(
                "directory data fork format {}",
                di.format
            )));
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Directory block structure

/// Lists a directory's blocks with their structure.
pub(super) async fn blocks(cx: Cx, (fs, ino): (FsRef, u64)) -> Result<()> {
    let di = Dinode::read(&cx, &fs, ino).await?;
    let (exts, problem) = extents(&cx, &fs, &di, false).await?;
    if let Some(d) = problem {
        cx.diag(d);
    }
    let starts = block_starts(&cx, &fs, &exts, 0, u64::MAX).await;
    let dblk = fs.dir_block();
    for lblk in starts {
        let offset = lblk.saturating_mul(fs.block);
        let db = offset.checked_div(dblk).unwrap_or(0);
        let name = if offset < LEAF_OFFSET {
            format!("Data block {db}")
        } else if offset < FREE_OFFSET {
            format!(
                "Leaf block {}",
                db.saturating_sub(LEAF_OFFSET.checked_div(dblk).unwrap_or(0))
            )
        } else {
            format!(
                "Free index block {}",
                db.saturating_sub(FREE_OFFSET.checked_div(dblk).unwrap_or(0))
            )
        };
        let Some(span) = logical_span(&cx, &fs, &exts, lblk, fs.dir_fsbs, "xfs-dir-block").await?
        else {
            cx.push(Node::new(name).diag(Diagnostic::malformed("block not mapped")))
                .await;
            continue;
        };
        let data = cx.read_avail(span).await?;
        let kind = block_kind(&data);
        cx.push(
            Node::new(name)
                .span(span)
                .summary(block_summary(&fs, kind, &data))
                .lazy(dir_block, (fs.clone(), span)),
        )
        .await;
    }
    Ok(())
}

fn block_summary(fs: &Fs, kind: BlockKind, data: &[u8]) -> String {
    let leaf_hdr: usize = if fs.v5 { 56 } else { 12 };
    let count = u16_be(data, leaf_hdr).unwrap_or(0);
    match kind {
        BlockKind::Block | BlockKind::Data => {
            let used = data_area(fs, kind, data)
                .map(|(s, e)| {
                    data_entries(data, s, e, fs.ftype)
                        .0
                        .iter()
                        .filter(|e| e.used.is_some())
                        .count()
                })
                .unwrap_or(0);
            if kind == BlockKind::Block {
                format!("single-block directory, {used} entries")
            } else {
                format!("data, {used} entries")
            }
        }
        BlockKind::Leaf1 => format!("leaf (single), {count} hashes"),
        BlockKind::LeafN => format!("leaf (node form), {count} hashes"),
        BlockKind::Node => format!(
            "DA B+tree node, level {}, {count} entries",
            u16_be(data, leaf_hdr.saturating_add(2)).unwrap_or(0)
        ),
        BlockKind::Free => format!(
            "free index, {} data blocks",
            u32_be(data, if fs.v5 { 52 } else { 8 }).unwrap_or(0)
        ),
        BlockKind::Unknown => "unrecognised".into(),
    }
}

const BESTFREE: [(&str, &str); 3] = [
    ("Best free 0: offset", "Best free 0: length"),
    ("Best free 1: offset", "Best free 1: length"),
    ("Best free 2: offset", "Best free 2: length"),
];

/// The v5 directory block header (`xfs_dir3_blk_hdr`) after the magic.
fn dir3_blk_hdr(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    crc_field(f, ctx.crc)?;
    f.u64("Disk address (512-byte units)").hex().emit()?;
    f.u64("LSN").hex().with(lsn_summary).emit()?;
    f.bytes("UUID", 16).with(uuid_value).emit()?;
    f.u64("Owner (inode)").emit()?;
    Ok(())
}

fn data_header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    if ctx.v5 {
        dir3_blk_hdr(f, ctx)?;
    }
    for (off, len) in BESTFREE {
        f.u16(off).emit()?;
        f.u16(len).emit()?;
    }
    if ctx.v5 {
        f.u32("Padding").emit()?;
    }
    Ok(())
}

fn dirent_layout(f: &mut Fields<'_>, ftype: &bool) -> Result<()> {
    f.u64("Inode").emit()?;
    let namelen = f.u8("Name length").emit()?;
    name_field(f, namelen.into())?;
    if *ftype {
        f.u8("File type").enumeration(FTYPES).emit()?;
    }
    let pad = f.remaining().saturating_sub(2);
    if pad > 0 {
        f.bytes("Padding", pad).emit()?;
    }
    f.u16("Tag")
        .desc("Offset of this entry within its block")
        .emit()?;
    Ok(())
}

fn unused_entry_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Free tag").hex().emit()?;
    f.u16("Length").emit()?;
    let rest = f.remaining().saturating_sub(2);
    if rest > 0 {
        f.node(
            Node::new("Unused")
                .span(f.peek_span(rest))
                .summary(size(rest)),
        );
        f.skip(rest);
    }
    f.u16("Tag")
        .desc("Offset of this entry within its block")
        .emit()?;
    Ok(())
}

/// The DA block info header shared by leaf and node blocks.
fn da_blkinfo(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.u32("Next block").emit()?;
    f.u32("Previous block").emit()?;
    f.u16("Magic").hex().emit()?;
    f.u16("Padding").emit()?;
    if ctx.v5 {
        crc_field(f, ctx.crc)?;
        f.u64("Disk address (512-byte units)").hex().emit()?;
        f.u64("LSN").hex().with(lsn_summary).emit()?;
        f.bytes("UUID", 16).with(uuid_value).emit()?;
        f.u64("Owner (inode)").emit()?;
    }
    Ok(())
}

fn leaf_header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    da_blkinfo(f, ctx)?;
    f.u16("Entries").emit()?;
    f.u16("Stale entries").emit()?;
    if ctx.v5 {
        f.u32("Padding").emit()?;
    }
    Ok(())
}

pub(super) fn node_header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    da_blkinfo(f, ctx)?;
    f.u16("Entries").emit()?;
    f.u16("Level").emit()?;
    if ctx.v5 {
        f.u32("Padding").emit()?;
    }
    Ok(())
}

fn free_header_layout(f: &mut Fields<'_>, ctx: &HdrCtx) -> Result<()> {
    f.ascii("Magic", 4).emit()?;
    if ctx.v5 {
        dir3_blk_hdr(f, ctx)?;
    }
    f.u32("First data block").emit()?;
    f.u32("Valid entries").emit()?;
    f.u32("Used entries").emit()?;
    if ctx.v5 {
        f.u32("Padding").emit()?;
    }
    Ok(())
}

fn tail_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Leaf entries").emit()?;
    f.u32("Stale leaf entries").emit()?;
    Ok(())
}

/// What a list of 8-byte pairs holds.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(super) enum Pairs {
    /// Directory leaf: hash, address (in 8-byte units).
    Leaf,
    /// DA B+tree node: hash, child block.
    Node,
}

fn pair_layout(f: &mut Fields<'_>, kind: &Pairs) -> Result<()> {
    f.u32("Hash").hex().emit()?;
    match kind {
        Pairs::Leaf => {
            f.u32("Address")
                .with(|&v, n| n.summary(format!("byte {} of the directory", u64::from(v) << 3)))
                .desc("Offset of the entry in the directory's data region, in units of 8 bytes; 0 for a stale entry")
                .emit()?;
        }
        Pairs::Node => {
            f.u32("Child block")
                .desc("Logical block of the child, for hashes up to this one")
                .emit()?;
        }
    }
    Ok(())
}

/// A paged list of (hash, address) or (hash, child) pairs.
pub(super) async fn pairs(cx: Cx, (span, kind): (Span, Pairs)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, pair) in data.as_chunks::<8>().0.iter().enumerate() {
        let hash = u32_be(pair, 0).unwrap_or(0);
        let value = u32_be(pair, 4).unwrap_or(0);
        let summary = match kind {
            Pairs::Leaf if value == 0 => format!("hash {hash:#010x}, stale"),
            Pairs::Leaf => format!("hash {hash:#010x} → byte {}", u64::from(value) << 3),
            Pairs::Node => format!("hashes ≤ {hash:#010x} → block {value}"),
        };
        cx.push(
            struct_node(
                format!("Entry {i}"),
                span.sub(to_u64(i).saturating_mul(8), 8),
                BE,
                kind,
                pair_layout,
            )
            .summary(summary),
        )
        .await;
    }
    Ok(())
}

/// A list of 16-bit "best free" lengths, one per data block.
async fn bests(cx: Cx, (span, first): (Span, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, v) in data.as_chunks::<2>().0.iter().enumerate() {
        let v = u16::from_be_bytes(*v);
        let db = first.saturating_add(to_u64(i));
        let node = uint(
            format!("Data block {db}"),
            span.sub(to_u64(i).saturating_mul(2), 2),
            v.into(),
            16,
        );
        cx.push(if v == 0xffff {
            node.summary("no such block")
        } else {
            node.summary(format!("longest free space {v} bytes"))
        })
        .await;
    }
    Ok(())
}

/// Shows one directory block.
async fn dir_block(cx: Cx, (fs, span): (FsRef, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let kind = block_kind(&data);
    let len = to_u64(data.len());
    let v5 = fs.v5;
    match kind {
        BlockKind::Block | BlockKind::Data => {
            let hdr = data_header_len(&fs);
            cx.emit(struct_node(
                "Header",
                span.sub(0, hdr),
                BE,
                HdrCtx {
                    v5,
                    crc: if v5 { crc(&data, 4) } else { None },
                },
                data_header_layout,
            ));
            let (start, end) = data_area(&fs, kind, &data).map_err(|d| d.at(span))?;
            let (entries, problem) = data_entries(&data, start, end, fs.ftype);
            for e in entries {
                let espan = span.sub(e.off, e.len);
                let node = match e.used {
                    Some((ino, name, ftype)) => {
                        let what = if fs.ftype {
                            lookup(FTYPES, ftype.into()).unwrap_or("unknown")
                        } else {
                            "entry"
                        };
                        struct_node(
                            String::from_utf8_lossy(&name).into_owned(),
                            espan,
                            BE,
                            fs.ftype,
                            dirent_layout,
                        )
                        .summary(format!("{what}, inode {ino}"))
                    }
                    None => struct_node("Unused", espan, BE, (), unused_entry_layout)
                        .summary(size(e.len)),
                };
                cx.push(node).await;
            }
            if let Some(d) = problem {
                cx.diag(d.at(span));
            }
            if kind == BlockKind::Block {
                let leaf = span.sub(end, len.saturating_sub(8).saturating_sub(end));
                cx.emit(
                    Node::new("Leaf entries")
                        .span(leaf)
                        .summary(format!("{} hashes", leaf.len / 8))
                        .lazy(pairs, (leaf, Pairs::Leaf)),
                );
                cx.emit(struct_node(
                    "Tail",
                    span.sub(len.saturating_sub(8), 8),
                    BE,
                    (),
                    tail_layout,
                ));
            }
        }
        BlockKind::Leaf1 | BlockKind::LeafN => {
            let hdr: u64 = if v5 { 64 } else { 16 };
            let info: usize = if v5 { 56 } else { 12 };
            let count = u64::from(u16_be(&data, info).unwrap_or(0));
            cx.emit(struct_node(
                "Header",
                span.sub(0, hdr),
                BE,
                HdrCtx {
                    v5,
                    crc: if v5 { crc(&data, 12) } else { None },
                },
                leaf_header_layout,
            ));
            let mut end = len;
            let mut tail_start = len;
            if kind == BlockKind::Leaf1 {
                let bestcount =
                    u64::from(u32_be(&data, to_usize(len.saturating_sub(4))).unwrap_or(0));
                tail_start = len.saturating_sub(4);
                end = tail_start.saturating_sub(bestcount.saturating_mul(2));
            }
            let entries = span.sub(hdr, count.saturating_mul(8));
            if hdr.saturating_add(entries.len) > end {
                cx.diag(Diagnostic::malformed(
                    "leaf entries overlap the best free table",
                ));
            }
            cx.emit(
                Node::new("Entries")
                    .span(entries)
                    .summary(format!("{count} hashes"))
                    .lazy(pairs, (entries, Pairs::Leaf)),
            );
            let used = hdr.saturating_add(entries.len);
            if end > used {
                cx.emit(
                    Node::new("Unused")
                        .span(span.sub(used, end.saturating_sub(used)))
                        .summary(size(end.saturating_sub(used))),
                );
            }
            if kind == BlockKind::Leaf1 {
                let table = span.sub(end, tail_start.saturating_sub(end));
                cx.emit(
                    Node::new("Best free table")
                        .span(table)
                        .summary(format!("{} data blocks", table.len / 2))
                        .lazy(bests, (table, 0)),
                );
                cx.emit(uint(
                    "Best free count",
                    span.sub(tail_start, 4),
                    u64::from(u32_be(&data, to_usize(tail_start)).unwrap_or(0)),
                    32,
                ));
            }
        }
        BlockKind::Node => da_node(&cx, &fs, span, &data),
        BlockKind::Free => {
            let hdr: u64 = if v5 { 64 } else { 16 };
            let first_at: usize = if v5 { 48 } else { 4 };
            let first = u64::from(u32_be(&data, first_at).unwrap_or(0));
            let valid = u64::from(u32_be(&data, first_at.saturating_add(4)).unwrap_or(0));
            cx.emit(struct_node(
                "Header",
                span.sub(0, hdr),
                BE,
                HdrCtx {
                    v5,
                    crc: if v5 { crc(&data, 4) } else { None },
                },
                free_header_layout,
            ));
            let table = span.sub(hdr, valid.saturating_mul(2));
            cx.emit(
                Node::new("Best free table")
                    .span(table)
                    .summary(format!("{} data blocks", table.len / 2))
                    .lazy(bests, (table, first)),
            );
            let used = hdr.saturating_add(table.len);
            if len > used {
                cx.emit(
                    Node::new("Unused")
                        .span(span.sub(used, len.saturating_sub(used)))
                        .summary(size(len.saturating_sub(used))),
                );
            }
        }
        BlockKind::Unknown => {
            return Err(Diagnostic::malformed("unrecognised directory block").at(span.sub(0, 16)));
        }
    }
    Ok(())
}

/// A DA B+tree node block (directories and attributes share it).
pub(super) fn da_node(cx: &Cx, fs: &Fs, span: Span, data: &[u8]) {
    let v5 = fs.v5;
    let hdr: u64 = if v5 { 64 } else { 16 };
    let info: usize = if v5 { 56 } else { 12 };
    let count = u64::from(u16_be(data, info).unwrap_or(0));
    let len = to_u64(data.len());
    cx.emit(struct_node(
        "Header",
        span.sub(0, hdr),
        BE,
        HdrCtx {
            v5,
            crc: if v5 { crc(data, 12) } else { None },
        },
        node_header_layout,
    ));
    let entries = span.sub(hdr, count.saturating_mul(8));
    cx.emit(
        Node::new("Entries")
            .span(entries)
            .summary(format!("{count} children"))
            .lazy(pairs, (entries, Pairs::Node)),
    );
    let used = hdr.saturating_add(entries.len);
    if len > used {
        cx.emit(
            Node::new("Unused")
                .span(span.sub(used, len.saturating_sub(used)))
                .summary(size(len.saturating_sub(used))),
        );
    }
}
