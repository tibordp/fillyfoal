//! A NILFS2 volume's checkpoints and their file trees (`nilfs2_ondisk.h`).
//!
//! The superblock names the latest partial segment written with a super
//! root; the super root (its last block) holds the inodes of the DAT,
//! which maps virtual block numbers to disk blocks, and of the checkpoint
//! file. Each checkpoint holds the inode of its inode file (ifile), whose
//! inodes map file blocks to virtual block numbers through a B-tree (or,
//! for small files, six direct pointers). DAT, ifile entries are found by
//! NILFS's persistent allocator layout (group descriptor, bitmap and entry
//! blocks); directories are ext2-style records.

use std::collections::HashMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::formats::disk::{PieceList, content_node, size, unix_mode};
use crate::formats::util::fmt::plural;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Time, Value};

/// Segment summary magic, and its flag for a partial segment ending in a
/// super root.
const SS_MAGIC: u32 = 0x1eaf_fa11;
const SS_SR: u16 = 4;
/// Pointers in an inode's direct map, and children in a B-tree root.
const DIRECT: usize = 6;
const ROOT_CHILDREN: usize = 3;
/// `NILFS_BMAP_LARGE`: the map is a B-tree.
const BMAP_LARGE: u8 = 1;
/// Limits on what is followed.
const MAX_DEPTH: usize = 64;
const MAX_BTREE_DEPTH: u8 = 8;
const MAX_BLOCKS: usize = 1 << 22;
const ROOT_INO: u64 = 2;
/// Checkpoint flags.
const CP_SNAPSHOT: u32 = 1;
const CP_INVALID: u32 = 2;

/// What the superblock says about the volume's layout.
#[derive(Clone, Copy, Debug)]
pub(super) struct Geometry {
    pub input: Input,
    pub block: u64,
    pub inode_size: u64,
    pub dat_entry: u64,
    pub cp_entry: u64,
    pub last_pseg: u64,
    pub last_cno: u64,
}

/// The volume, with the DAT's block map (physical) and the checkpoint
/// file's (virtual).
pub(super) struct Fs {
    g: Geometry,
    dat: HashMap<u64, u64>,
    cpfile: HashMap<u64, u64>,
}

pub(super) type FsRef = Arc<Fs>;

/// A `nilfs_inode`'s fields used here.
#[derive(Clone, Copy, Debug)]
struct Inode {
    span: Span,
    size: u64,
    mode: u16,
    mtime: u64,
    bmap: [u64; 7],
}

fn inode(raw: &[u8], span: Span) -> Inode {
    let mut bmap = [0u64; 7];
    for (i, w) in bmap.iter_mut().enumerate() {
        *w = u64_le(raw, 56usize.saturating_add(i.saturating_mul(8))).unwrap_or(0);
    }
    Inode {
        span,
        size: u64_le(raw, 8).unwrap_or(0),
        mode: u16_le(raw, 48).unwrap_or(0),
        mtime: u64_le(raw, 24).unwrap_or(0),
        bmap,
    }
}

impl Fs {
    fn blocks(&self, n: u64, count: u64) -> Span {
        self.g.input.span.sub(
            n.saturating_mul(self.g.block),
            count.saturating_mul(self.g.block),
        )
    }

    /// Where entry `nr` of a persistent-allocator file (`alloc.c`) is:
    /// its block in the file and its offset there.
    fn palloc(&self, nr: u64, entry: u64) -> (u64, u64) {
        let bs = self.g.block;
        let per_block = bs.checked_div(entry).unwrap_or(1).max(1);
        let per_group = bs.saturating_mul(8);
        let groups_per_desc = (bs >> 2).max(1);
        let blocks_per_group = per_group.div_ceil(per_block).saturating_add(1);
        let blocks_per_desc = groups_per_desc
            .saturating_mul(blocks_per_group)
            .saturating_add(1);
        let group = nr.checked_div(per_group).unwrap_or(0);
        let within = nr.checked_rem(per_group).unwrap_or(0);
        let desc = group
            .checked_div(groups_per_desc)
            .unwrap_or(0)
            .saturating_mul(blocks_per_desc);
        let bitmap = desc.saturating_add(1).saturating_add(
            group
                .checked_rem(groups_per_desc)
                .unwrap_or(0)
                .saturating_mul(blocks_per_group),
        );
        (
            bitmap
                .saturating_add(1)
                .saturating_add(within.checked_div(per_block).unwrap_or(0)),
            within
                .checked_rem(per_block)
                .unwrap_or(0)
                .saturating_mul(entry),
        )
    }

    /// The disk block virtual block `v` is at, from its DAT entry.
    async fn physical(&self, cx: &Cx, v: u64) -> Result<u64> {
        let (blk, at) = self.palloc(v, self.g.dat_entry);
        let p = self
            .dat
            .get(&blk)
            .ok_or_else(|| Diagnostic::malformed(format!("virtual block {v} has no DAT entry")))?;
        let raw = cx.read_avail(self.blocks(*p, 1).sub(at, 8)).await?;
        u64_le(&raw, 0).ok_or_else(|| Diagnostic::malformed("short DAT block"))
    }

    /// An inode's block map: (file block, pointer), in block order. The
    /// pointers are physical for the DAT (`virtual` false), virtual for
    /// everything else (and so are its B-tree nodes').
    async fn bmap(&self, cx: &Cx, bmap: &[u64; 7], virt: bool) -> Result<Vec<(u64, u64)>> {
        let head = bmap.first().copied().unwrap_or(0).to_le_bytes();
        let [flags, level, n0, n1, ..] = head;
        if flags & BMAP_LARGE == 0 {
            return Ok(bmap
                .iter()
                .skip(1)
                .take(DIRECT)
                .enumerate()
                .filter(|&(_, &p)| p != 0)
                .map(|(i, &p)| (to_u64(i), p))
                .collect());
        }
        let n = usize::from(u16::from_le_bytes([n0, n1])).min(ROOT_CHILDREN);
        let keys = bmap.get(1..=ROOT_CHILDREN).unwrap_or_default();
        let ptrs = bmap
            .get(ROOT_CHILDREN.saturating_add(1)..)
            .unwrap_or_default();
        let mut out = Vec::new();
        // Nodes still to visit, last first: (key, pointer, level).
        let mut stack: Vec<(u64, u64, u8)> = keys
            .iter()
            .zip(ptrs)
            .take(n)
            .rev()
            .map(|(&k, &p)| (k, p, level))
            .collect();
        let ncmax = to_usize(self.g.block.saturating_sub(16) / 16);
        while let Some((key, ptr, level)) = stack.pop() {
            if level <= 1 {
                out.push((key, ptr));
                if out.len() >= MAX_BLOCKS {
                    return Err(Diagnostic::limit("too many blocks in a block map"));
                }
                continue;
            }
            if level > MAX_BTREE_DEPTH {
                return Err(Diagnostic::malformed("block map B-tree too deep"));
            }
            let at = if virt {
                self.physical(cx, ptr).await?
            } else {
                ptr
            };
            let node = cx.read_avail(self.blocks(at, 1)).await?;
            let child_level = node.get(1).copied().unwrap_or(0);
            if child_level.saturating_add(1) != level {
                return Err(Diagnostic::malformed(format!(
                    "B-tree node at block {at} is at level {child_level}, not {}",
                    level.saturating_sub(1)
                )));
            }
            let count = usize::from(u16_le(&node, 2).unwrap_or(0)).min(ncmax);
            let ptrs_at = 16usize.saturating_add(ncmax.saturating_mul(8));
            for i in (0..count).rev() {
                let k = u64_le(&node, 16usize.saturating_add(i.saturating_mul(8))).unwrap_or(0);
                let p = u64_le(&node, ptrs_at.saturating_add(i.saturating_mul(8))).unwrap_or(0);
                stack.push((k, p, child_level));
            }
            cx.checkpoint().await;
        }
        Ok(out)
    }

    /// Opens the volume at its latest super root.
    pub async fn open(cx: &Cx, g: Geometry) -> Result<Fs> {
        let mut fs = Fs {
            g,
            dat: HashMap::new(),
            cpfile: HashMap::new(),
        };
        let seg = fs.blocks(g.last_pseg, 1);
        let ss = cx.read_avail(seg.sub(0, 64)).await?;
        if u32_le(&ss, 8) != Some(SS_MAGIC) {
            return Err(Diagnostic::malformed(
                "no segment summary at the last partial segment",
            ));
        }
        if u16_le(&ss, 14).unwrap_or(0) & SS_SR == 0 {
            return Err(Diagnostic::malformed(
                "the last partial segment has no super root",
            ));
        }
        let nblocks = u64::from(u32_le(&ss, 40).unwrap_or(0));
        let sr = fs.blocks(g.last_pseg.saturating_add(nblocks).saturating_sub(1), 1);
        let raw = cx.read_avail(sr).await?;
        let at = |i: u64| to_usize(16u64.saturating_add(g.inode_size.saturating_mul(i)));
        let dat = inode(raw.get(at(0)..).unwrap_or_default(), sr.sub(16, 128));
        let cp = inode(raw.get(at(1)..).unwrap_or_default(), sr.sub(16, 128));
        fs.dat = fs.bmap(cx, &dat.bmap, false).await?.into_iter().collect();
        fs.cpfile = fs.bmap(cx, &cp.bmap, true).await?.into_iter().collect();
        Ok(fs)
    }

    /// Bytes of a block of a file whose map is `map`, if it is mapped.
    async fn file_block(&self, cx: &Cx, map: &HashMap<u64, u64>, blk: u64) -> Result<Option<Span>> {
        match map.get(&blk) {
            Some(&v) => Ok(Some(self.blocks(self.physical(cx, v).await?, 1))),
            None => Ok(None),
        }
    }
}

/// A checkpoint: its number and the ifile's block map.
pub(super) struct Checkpoint {
    fs: FsRef,
    ifile: HashMap<u64, u64>,
}

type CpRef = Arc<Checkpoint>;

/// A checkpoint entry (`nilfs_checkpoint`): flags, number, time, inode
/// count, and the ifile's inode at 64.
struct CpEntry {
    span: Span,
    flags: u32,
    created: u64,
    inodes: u64,
    ifile: Inode,
}

async fn cp_entry(cx: &Cx, fs: &Fs, cno: u64) -> Result<CpEntry> {
    // The header takes the first entry's place.
    let es = fs.g.cp_entry.max(1);
    let per = fs.g.block.checked_div(es).unwrap_or(1).max(1);
    let blk = cno.checked_div(per).unwrap_or(0);
    let block = fs
        .file_block(cx, &fs.cpfile, blk)
        .await?
        .ok_or_else(|| Diagnostic::malformed(format!("checkpoint {cno} is in a hole")))?;
    let span = block.sub(cno.checked_rem(per).unwrap_or(0).saturating_mul(es), es);
    let raw = cx.read_avail(span).await?;
    Ok(CpEntry {
        span,
        flags: u32_le(&raw, 0).unwrap_or(0),
        created: u64_le(&raw, 32).unwrap_or(0),
        inodes: u64_le(&raw, 48).unwrap_or(0),
        ifile: inode(raw.get(64..).unwrap_or_default(), span.sub(64, 128)),
    })
}

impl Checkpoint {
    async fn inode(&self, cx: &Cx, n: u64) -> Result<Inode> {
        let fs = &self.fs;
        let (blk, at) = fs.palloc(n, fs.g.inode_size);
        let block = fs
            .file_block(cx, &self.ifile, blk)
            .await?
            .ok_or_else(|| Diagnostic::malformed(format!("inode {n} is in a hole")))?;
        let span = block.sub(at, fs.g.inode_size);
        Ok(inode(&cx.read_avail(span).await?, span))
    }

    /// A file's bytes, from its block map (gaps become zeros).
    async fn content(&self, cx: &Cx, ino: &Inode) -> Result<Span> {
        let fs = &self.fs;
        let bs = fs.g.block;
        let mut list = PieceList::new(ino.span);
        for (i, (blk, v)) in fs.bmap(cx, &ino.bmap, true).await?.into_iter().enumerate() {
            if i % 1024 == 1023 {
                cx.checkpoint().await;
            }
            let at = blk.saturating_mul(bs);
            if at >= ino.size || at < list.len() {
                continue;
            }
            list.hole(cx, at.saturating_sub(list.len()))?;
            let p = fs.physical(cx, v).await?;
            list.data(fs.blocks(p, 1).sub(0, bs.min(ino.size.saturating_sub(at))));
        }
        if list.len() < ino.size {
            list.hole(cx, ino.size.saturating_sub(list.len()))?;
        }
        list.finish(cx, "nilfs-blocks").await
    }
}

async fn open_checkpoint(cx: &Cx, fs: &FsRef, cno: u64) -> Result<CpRef> {
    let e = cp_entry(cx, fs, cno).await?;
    let ifile = fs
        .bmap(cx, &e.ifile.bmap, true)
        .await?
        .into_iter()
        .collect();
    Ok(Arc::new(Checkpoint {
        fs: fs.clone(),
        ifile,
    }))
}

/// The root directory of the latest checkpoint.
pub(super) async fn latest(cx: Cx, g: Geometry) -> Result<()> {
    let fs: FsRef = Arc::new(Fs::open(&cx, g).await?);
    let cp = open_checkpoint(&cx, &fs, g.last_cno).await?;
    directory(cx, (cp, ROOT_INO, Path::new())).await
}

/// Every checkpoint in the checkpoint file, each with its file tree.
pub(super) async fn checkpoints(cx: Cx, g: Geometry) -> Result<()> {
    let fs: FsRef = Arc::new(Fs::open(&cx, g).await?);
    cx.set_count(Count::Exact(g.last_cno));
    for cno in 1..=g.last_cno {
        let node = Node::new(format!("Checkpoint {cno}"));
        let node = match cp_entry(&cx, &fs, cno).await {
            Err(e) => node.diag(e),
            Ok(e) if e.flags & CP_INVALID != 0 => node.span(e.span).summary("deleted"),
            Ok(e) => {
                let mut what = vec![if e.flags & CP_SNAPSHOT != 0 {
                    "snapshot".to_owned()
                } else {
                    "checkpoint".to_owned()
                }];
                what.push(format!(
                    "created {}",
                    Time::utc(i64::try_from(e.created).unwrap_or(0))
                ));
                what.push(plural(e.inodes, "inode"));
                node.span(e.span)
                    .summary(what.join(", "))
                    .lazy(checkpoint_root, (fs.clone(), cno))
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn checkpoint_root(cx: Cx, (fs, cno): (FsRef, u64)) -> Result<()> {
    let cp = open_checkpoint(&cx, &fs, cno).await?;
    directory(cx, (cp, ROOT_INO, Path::new())).await
}

fn kind(mode: u16) -> &'static str {
    match mode & 0xf000 {
        0x4000 => "directory",
        0x8000 => "file",
        0xa000 => "symbolic link",
        0x2000 => "character device",
        0x6000 => "block device",
        0x1000 => "FIFO",
        0xc000 => "socket",
        _ => "inode",
    }
}

fn inode_node(n: u64, ino: &Inode) -> Node {
    Node::new(format!("Inode {n}"))
        .span(ino.span)
        .summary(format!(
            "{}, {}, modified {}",
            unix_mode(ino.mode.into()),
            size(ino.size),
            Time::utc(i64::try_from(ino.mtime).unwrap_or(0))
        ))
}

/// A directory: its inode, then its entries (`nilfs_dir_entry`: inode,
/// record length, name length, file type, name), `.` and `..` left out.
async fn directory(cx: Cx, (cp, n, path): (CpRef, u64, Path)) -> Result<()> {
    let dir = cp.inode(&cx, n).await?;
    cx.emit(inode_node(n, &dir));
    let data = cp.content(&cx, &dir).await?;
    let bytes = cx.read_avail(data).await?;
    let bs = to_usize(cp.fs.g.block);
    let mut entries = Vec::new();
    for (b, block) in bytes.chunks(bs.max(1)).enumerate() {
        let mut at = 0usize;
        while at.saturating_add(12) <= block.len() {
            let ino = u64_le(block, at).unwrap_or(0);
            let rec = usize::from(u16_le(block, at.saturating_add(8)).unwrap_or(0));
            let len = usize::from(block.get(at.saturating_add(10)).copied().unwrap_or(0));
            if rec < 12 {
                cx.diag(Diagnostic::malformed(format!(
                    "directory record of {rec} bytes"
                )));
                break;
            }
            let name = block
                .get(at.saturating_add(12)..at.saturating_add(12).saturating_add(len))
                .unwrap_or_default();
            if ino != 0 && name != b"." && name != b".." {
                let span = data.sub(to_u64(b.saturating_mul(bs).saturating_add(at)), to_u64(rec));
                entries.push((String::from_utf8_lossy(name).into_owned(), ino, span));
            }
            at = at.saturating_add(rec);
        }
        cx.checkpoint().await;
    }
    for (name, ino, span) in entries {
        let node = Node::new(name).span(span);
        let node = match cp.inode(&cx, ino).await {
            Err(e) => node.summary(format!("inode {ino}")).diag(e),
            Ok(i) if i.mode & 0xf000 == 0x4000 => match path.enter(ino, MAX_DEPTH) {
                Ok(p) => node.summary(format!("directory, inode {ino}")).lazy(
                    crate::expander!(self::directory: (CpRef, u64, Path)),
                    (cp.clone(), ino, p),
                ),
                Err(d) => node.diag(d),
            },
            Ok(i) => node
                .summary(format!("{}, {}, inode {ino}", kind(i.mode), size(i.size)))
                .lazy(file, (cp.clone(), ino)),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A file's inode and content, or a symbolic link's target.
async fn file(cx: Cx, (cp, n): (CpRef, u64)) -> Result<()> {
    let ino = cp.inode(&cx, n).await?;
    cx.emit(inode_node(n, &ino));
    match ino.mode & 0xf000 {
        0x8000 => {
            let data = cp.content(&cx, &ino).await?;
            cx.emit(content_node(&cp.fs.g.input, data));
        }
        0xa000 => {
            let data = cp.content(&cx, &ino).await?;
            let text = cx.read_avail(data.sub(0, 4096)).await?;
            cx.emit(
                Node::new("Target")
                    .span(data)
                    .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
            );
        }
        _ => {}
    }
    Ok(())
}
