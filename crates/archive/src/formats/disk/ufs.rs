//! UFS / FFS (BSD Unix File System), versions 1 and 2: the superblock,
//! the directory tree from the root inode and file content.
//!
//! The superblock is at 8 KiB for UFS1 (and some UFS2 volumes) or 64 KiB
//! (the standard UFS2 location). Inodes sit in a table in each cylinder
//! group (`ino_to_fsba`: group `ino / ipg`, at the group's start plus
//! `iblkno`; UFS1 groups start staggered by `cgoffset`). A file maps its
//! blocks through 12 direct and 3 indirect pointers, in fragment units,
//! its last block maybe only some fragments; a short symbolic link keeps
//! its target in the pointer area. Directories are `struct direct`
//! records in 512-byte chunks. Layouts as in FreeBSD's `ufs/ffs/fs.h`,
//! `ufs/ufs/dinode.h` and `ufs/ufs/dir.h`.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, content_node, fragments_node, size, unix_mode};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const MAGIC_OFFSET: usize = 1372;
const MAGIC: u64 = 1372;
const UFS1: u32 = 0x0001_1954;
const UFS2: u32 = 0x1954_0119;
const LOCATIONS: [u64; 2] = [8192, 65536];

pub static FORMAT: Format = Format {
    name: "ufs",
    title: "UFS / FFS filesystem",
    extensions: &["img", "ufs", "ffs"],
    mime: "application/x-ufs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The magic (and byte order) of a superblock whose magic field is at `o`.
fn magic_at(data: &[u8], o: usize) -> Option<(u32, Endian)> {
    [
        (u32_le(data, o)?, Endian::Little),
        (u32_be(data, o)?, Endian::Big),
    ]
    .into_iter()
    .find(|(m, _)| *m == UFS1 || *m == UFS2)
}

fn probe(h: &Head<'_>) -> bool {
    LOCATIONS.iter().any(|&l| {
        magic_at(
            h.data,
            crate::bytes::to_usize(l).saturating_add(MAGIC_OFFSET),
        )
        .is_some()
    })
}

record! {
    /// The leading fields of `struct fs`.
    pub struct Superblock {
        _link: u32 "Unused (link)",
        _rlink: u32 "Unused (rlink)",
        sblkno: u32 "Superblock offset in group (fragments)",
        cblkno: u32 "Group block offset (fragments)",
        iblkno: u32 "Inode block offset (fragments)",
        dblkno: u32 "Data block offset (fragments)",
        old_cgoffset: u32 "Group offset (UFS1)",
        old_cgmask: u32 "Group mask (UFS1)",
        old_time: u32 "Written (UFS1)" .timestamp(),
        old_size: u32 "Fragments (UFS1)",
        old_dsize: u32 "Data fragments (UFS1)",
        ncg: u32 "Cylinder groups",
        bsize: u32 "Block size",
        fsize: u32 "Fragment size",
        frag: u32 "Fragments per block",
        minfree: u32 "Minimum free (%)",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let mut found = None;
    for at in LOCATIONS {
        let raw = cx.read_avail(vol.sub(at.saturating_add(MAGIC), 4)).await?;
        if let Some((magic, endian)) = magic_at(&raw, 0) {
            found = Some((at, magic, endian));
            break;
        }
    }
    let Some((at, magic, endian)) = found else {
        return Err(Diagnostic::malformed("no UFS superblock"));
    };
    let span = vol.sub(at, Superblock::SIZE);
    let sb = parse(&cx, span, endian, &(), Superblock::layout).await?;
    cx.emit(Superblock::node("Superblock", vol.sub(at, 1376), endian));
    let ufs2 = magic == UFS2;
    let raw = cx.read_avail(vol.sub(at, 1376)).await?;
    let get_u64 = |o: usize| -> u64 {
        let b: [u8; 8] = raw
            .get(o..o.saturating_add(8))
            .and_then(|s| s.try_into().ok())
            .unwrap_or([0; 8]);
        match endian {
            Endian::Little => u64::from_le_bytes(b),
            Endian::Big => u64::from_be_bytes(b),
        }
    };
    let (fragments, mount, volume) = if ufs2 {
        (
            get_u64(1080),
            crate::text::until_nul(raw.get(212..680).unwrap_or_default()),
            crate::text::until_nul(raw.get(680..712).unwrap_or_default()),
        )
    } else {
        (
            u64::from(sb.old_size),
            crate::text::until_nul(raw.get(212..724).unwrap_or_default()),
            String::new(),
        )
    };
    cx.emit(
        Node::new("Last mount point")
            .span(vol.sub(at.saturating_add(212), 468))
            .value(Value::Text(mount.clone())),
    );
    if ufs2 {
        cx.emit(
            Node::new("Volume name")
                .span(vol.sub(at.saturating_add(680), 32))
                .value(Value::Text(volume.clone())),
        );
    }
    cx.emit(
        Node::new("Magic")
            .span(vol.sub(at.saturating_add(MAGIC), 4))
            .value(Value::UInt {
                value: magic.into(),
                bits: 32,
                radix: crate::value::Radix::Hex,
            }),
    );
    match Fs::new(input, ufs2, endian, &sb, &raw) {
        Ok(fs) => cx.emit(Node::new("Root directory").summary("inode 2").lazy(
            crate::expander!(self::directory: (FsRef, u64, Arc<Vec<u64>>)),
            (Arc::new(fs), ROOT, Arc::new(Vec::new())),
        )),
        Err(e) => cx.diag(e),
    }
    cx.annotate(format!(
        "{} filesystem{}{}, {}, {} cylinder groups, {}-byte blocks",
        if ufs2 { "UFS2" } else { "UFS1" },
        if volume.is_empty() {
            String::new()
        } else {
            format!(" \"{volume}\"")
        },
        if mount.is_empty() {
            String::new()
        } else {
            format!(" (last mounted on {mount})")
        },
        size(fragments.saturating_mul(sb.fsize.into())),
        sb.ncg,
        sb.bsize
    ));
    Ok(())
}

/// The root directory's inode (`UFS_ROOTINO`).
const ROOT: u64 = 2;
const MAX_DEPTH: usize = 64;
const MAX_DIR_BYTES: u64 = 16 << 20;
/// Blocks mapped per file at most.
const MAX_BLOCKS: u64 = 1 << 20;
/// `DIRBLKSIZ`: directory records never cross these chunks.
const DIRBLK: u64 = 512;
/// `FS_44INODEFMT`: directory records with a type byte and an 8-bit name
/// length (older UFS1 volumes have a 16-bit name length).
const INODEFMT_44: u32 = 2;

record! {
    /// `struct ufs1_dinode` (128 bytes).
    pub struct Inode1 {
        mode: u16 "Mode" .hex() .with(|&m, n| n.summary(unix_mode(m.into()))),
        nlink: u16 "Links",
        _old_ids: u32 "Unused (old owner and group)",
        size: u64 "Size" .with(|&v, n| n.summary(size(v))),
        atime: u32 "Accessed" .timestamp(),
        _atime_ns: u32 "Accessed (ns)",
        mtime: u32 "Modified" .timestamp(),
        _mtime_ns: u32 "Modified (ns)",
        ctime: u32 "Changed" .timestamp(),
        _ctime_ns: u32 "Changed (ns)",
        _db: bytes[48] "Direct blocks (fragment addresses)",
        _ib: bytes[12] "Indirect blocks",
        flags: u32 "Flags" .hex(),
        blocks: u32 "Blocks held (512-byte units)",
        generation: u32 "Generation",
        uid: u32 "Owner",
        gid: u32 "Group",
    }
}

fn ts64(v: &i64, node: Node) -> Node {
    node.value(Value::Timestamp { unix_seconds: *v })
}

record! {
    /// `struct ufs2_dinode` (256 bytes), up to the block pointers.
    pub struct Inode2 {
        mode: u16 "Mode" .hex() .with(|&m, n| n.summary(unix_mode(m.into()))),
        nlink: u16 "Links",
        uid: u32 "Owner",
        gid: u32 "Group",
        blksize: u32 "Block size",
        size: u64 "Size" .with(|&v, n| n.summary(size(v))),
        blocks: u64 "Blocks held (512-byte units)",
        atime: i64 "Accessed" .with(ts64),
        mtime: i64 "Modified" .with(ts64),
        ctime: i64 "Changed" .with(ts64),
        birthtime: i64 "Created" .with(ts64),
        _ns: bytes[16] "Nanoseconds (modified, accessed, changed, created)",
        generation: u32 "Generation",
        kernflags: u32 "Kernel flags" .hex(),
        flags: u32 "Flags" .hex(),
        extsize: u32 "Extended attribute size",
        _extb: bytes[16] "Extended attribute blocks",
        _db: bytes[96] "Direct blocks (fragment addresses)",
        _ib: bytes[24] "Indirect blocks",
    }
}

/// What the walker needs from the superblock.
#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    ufs2: bool,
    endian: Endian,
    bsize: u64,
    fsize: u64,
    /// Inodes and fragments per cylinder group.
    ipg: u64,
    fpg: u64,
    /// Inode table offset in a group, in fragments.
    iblkno: u64,
    /// UFS1 group stagger (`cgstart`).
    cgoffset: u64,
    cgmask: u64,
    ncg: u64,
    /// New-style directory records (type byte, 8-bit name length).
    dir44: bool,
}

type FsRef = Arc<Fs>;

impl Fs {
    fn new(input: Input, ufs2: bool, endian: Endian, sb: &Superblock, raw: &[u8]) -> Result<Fs> {
        let u32_at = |o: usize| {
            match endian {
                Endian::Little => u32_le(raw, o),
                Endian::Big => u32_be(raw, o),
            }
            .unwrap_or(0)
        };
        let bsize = u64::from(sb.bsize);
        let fsize = u64::from(sb.fsize);
        let ipg = u64::from(u32_at(184));
        let fpg = u64::from(u32_at(188));
        if !(4096..=65536).contains(&bsize)
            || !bsize.is_power_of_two()
            || !(512..=bsize).contains(&fsize)
            || !fsize.is_power_of_two()
            || ipg == 0
            || fpg == 0
        {
            return Err(Diagnostic::malformed(format!(
                "block size {bsize}, fragment size {fsize}, {ipg} inodes and {fpg} fragments per group"
            )));
        }
        Ok(Fs {
            input,
            vol: input.span,
            ufs2,
            endian,
            bsize,
            fsize,
            ipg,
            fpg,
            iblkno: sb.iblkno.into(),
            cgoffset: sb.old_cgoffset.into(),
            cgmask: sb.old_cgmask.into(),
            ncg: sb.ncg.into(),
            dir44: ufs2 || u32_at(1324) >= INODEFMT_44,
        })
    }

    fn inode_size(&self) -> u64 {
        if self.ufs2 { 256 } else { 128 }
    }

    fn u16(&self, b: &[u8], o: usize) -> u16 {
        match self.endian {
            Endian::Little => crate::bytes::u16_le(b, o),
            Endian::Big => crate::bytes::u16_be(b, o),
        }
        .unwrap_or(0)
    }

    fn u32(&self, b: &[u8], o: usize) -> u32 {
        match self.endian {
            Endian::Little => u32_le(b, o),
            Endian::Big => u32_be(b, o),
        }
        .unwrap_or(0)
    }

    fn u64(&self, b: &[u8], o: usize) -> u64 {
        match self.endian {
            Endian::Little => crate::bytes::u64_le(b, o),
            Endian::Big => crate::bytes::u64_be(b, o),
        }
        .unwrap_or(0)
    }

    /// The inode's bytes in the volume (`ino_to_fsba`, `ino_to_fsbo`).
    fn inode_span(&self, ino: u64) -> Option<Span> {
        let cg = ino.checked_div(self.ipg)?;
        if cg >= self.ncg {
            return None;
        }
        let base = cg.checked_mul(self.fpg)?;
        let start = if self.ufs2 {
            base
        } else {
            base.checked_add(self.cgoffset.checked_mul(cg & !self.cgmask)?)?
        };
        let frag = start.checked_add(self.iblkno)?;
        let at = frag
            .checked_mul(self.fsize)?
            .checked_add(ino.checked_rem(self.ipg)?.checked_mul(self.inode_size())?)?;
        self.vol.sub_exact(at, self.inode_size()).ok()
    }

    fn inode_node(&self, ino: u64, span: Span) -> Node {
        let name = format!("Inode {ino}");
        if self.ufs2 {
            Inode2::node(name, span, self.endian)
        } else {
            Inode1::node(name, span, self.endian)
        }
    }

    fn mode(&self, inode: &[u8]) -> u16 {
        self.u16(inode, 0)
    }

    fn size_of(&self, inode: &[u8]) -> u64 {
        self.u64(inode, if self.ufs2 { 16 } else { 8 })
    }

    fn blocks_held(&self, inode: &[u8]) -> u64 {
        if self.ufs2 {
            self.u64(inode, 24)
        } else {
            u64::from(self.u32(inode, 104))
        }
    }

    /// Where the 15 block pointers start in an inode, and their size.
    fn pointers_at(&self) -> (usize, usize) {
        if self.ufs2 { (112, 8) } else { (40, 4) }
    }

    fn pointer(&self, b: &[u8], i: usize, width: usize) -> u64 {
        let o = i.saturating_mul(width);
        if width == 8 {
            self.u64(b, o)
        } else {
            u64::from(self.u32(b, o))
        }
    }

    /// Block pointers per indirect block.
    fn per_block(&self) -> u64 {
        self.bsize.checked_div(to_u64(self.pointers_at().1)).unwrap_or(0)
    }

    /// The addresses in the indirect block at fragment `addr` (zeros for
    /// a hole).
    async fn indirect(&self, cx: &Cx, addr: u64, seen: &mut HashSet<u64>) -> Result<Vec<u64>> {
        let width = self.pointers_at().1;
        let per = to_usize(self.per_block());
        if addr == 0 {
            return Ok(vec![0; per]);
        }
        if !seen.insert(addr) {
            return Err(Diagnostic::malformed(format!(
                "block {addr} is used twice as an indirect block"
            )));
        }
        let data = cx
            .read(
                self.vol
                    .sub_exact(addr.saturating_mul(self.fsize), self.bsize)?,
            )
            .await?;
        Ok((0..per).map(|i| self.pointer(&data, i, width)).collect())
    }

    /// The content of an inode, as pieces of the volume (holes as zeros).
    async fn content(&self, cx: &Cx, span: Span, inode: &[u8]) -> Result<(Span, Vec<Span>)> {
        let size = self.size_of(inode);
        let needed = size.div_ceil(self.bsize);
        if needed > MAX_BLOCKS {
            return Err(Diagnostic::limit(format!("file of {needed} blocks")).at(span));
        }
        let (at, width) = self.pointers_at();
        let area = inode.get(at..).unwrap_or_default();
        let mut blocks: Vec<u64> = (0..12).map(|i| self.pointer(area, i, width)).collect();
        let mut seen = HashSet::new();
        // Single, double and triple indirect: walk down level by level, as
        // far as the file reaches.
        for level in 0..3usize {
            if to_u64(blocks.len()) >= needed {
                break;
            }
            let mut frontier = vec![self.pointer(area, 12usize.saturating_add(level), width)];
            for depth in 0..level {
                // Pointer blocks below this level each map this many blocks.
                let span_each = self
                    .per_block()
                    .saturating_pow(u32::try_from(level.saturating_sub(depth)).unwrap_or(3));
                let mut next = Vec::new();
                for addr in frontier {
                    let mapped = to_u64(blocks.len())
                        .saturating_add(to_u64(next.len()).saturating_mul(span_each));
                    if mapped >= needed {
                        break;
                    }
                    cx.checkpoint().await;
                    next.extend(self.indirect(cx, addr, &mut seen).await?);
                }
                frontier = next;
            }
            for addr in frontier {
                if to_u64(blocks.len()) >= needed {
                    break;
                }
                blocks.extend(self.indirect(cx, addr, &mut seen).await?);
            }
        }
        let mut list = PieceList::new(span);
        for (i, &addr) in blocks.iter().take(to_usize(needed)).enumerate() {
            if i.is_multiple_of(4096) {
                cx.checkpoint().await;
            }
            let len = self.bsize.min(size.saturating_sub(list.len()));
            if addr == 0 {
                list.hole(cx, len)?;
            } else {
                list.data(self.vol.sub(addr.saturating_mul(self.fsize), len));
            }
        }
        let data = list.finish(cx, "ufs-blocks").await?;
        Ok((data, list.into_pieces()))
    }
}

/// The inode's span and bytes, or a diagnostic for one outside the volume.
async fn read_inode(cx: &Cx, fs: &Fs, ino: u64) -> Result<(Span, Vec<u8>)> {
    let span = fs
        .inode_span(ino)
        .ok_or_else(|| Diagnostic::malformed(format!("inode {ino} is outside the volume")))?;
    Ok((span, cx.read(span).await?))
}

async fn directory(cx: Cx, (fs, ino, ancestors): (FsRef, u64, Arc<Vec<u64>>)) -> Result<()> {
    let (span, raw) = read_inode(&cx, &fs, ino).await?;
    cx.emit(fs.inode_node(ino, span));
    if fs.mode(&raw) & 0o170_000 != 0o040_000 {
        return Err(Diagnostic::malformed(format!("inode {ino} is not a directory")).at(span));
    }
    let (data, _) = fs.content(&cx, span, &raw).await?;
    let data = data.sub(0, MAX_DIR_BYTES);
    let mut ancestors = (*ancestors).clone();
    ancestors.push(ino);
    let ancestors = Arc::new(ancestors);
    let bytes = cx.read_avail(data).await?;
    let total = to_u64(bytes.len());
    let mut pos = 0u64;
    while pos.saturating_add(8) <= total {
        cx.progress(pos, total);
        let e = bytes.get(to_usize(pos)..).unwrap_or_default();
        let child = u64::from(fs.u32(e, 0));
        let reclen = u64::from(fs.u16(e, 4));
        // New records: a type byte, then an 8-bit name length.
        let namlen = if fs.dir44 {
            u64::from(e.get(7).copied().unwrap_or(0))
        } else {
            u64::from(fs.u16(e, 6))
        };
        // A record stays within its 512-byte chunk and holds its name.
        let chunk_end = (pos / DIRBLK).saturating_add(1).saturating_mul(DIRBLK);
        if reclen < 8
            || pos.saturating_add(reclen) > chunk_end
            || 8u64.saturating_add(namlen) > reclen
        {
            cx.diag(
                Diagnostic::malformed(format!("bad directory record (length {reclen})"))
                    .at(data.sub(pos, 8)),
            );
            // Go on with the next chunk.
            pos = chunk_end;
            continue;
        }
        let name_bytes = e
            .get(8..to_usize(8u64.saturating_add(namlen)))
            .unwrap_or_default();
        let name = String::from_utf8_lossy(name_bytes).into_owned();
        let entry = data.sub(pos, reclen);
        pos = pos.saturating_add(reclen);
        if child == 0 || name == "." || name == ".." {
            cx.checkpoint().await;
            continue;
        }
        let node = match read_inode(&cx, &fs, child).await {
            Err(d) => Node::new(name).span(entry).diag(d),
            Ok((_, inode)) => {
                let mode = fs.mode(&inode);
                let summary = format!("{}, inode {child}", unix_mode(mode.into()));
                let node = Node::new(name).span(entry).summary(summary);
                if mode & 0o170_000 == 0o040_000 {
                    if ancestors.contains(&child) || ancestors.len() > MAX_DEPTH {
                        node.diag(Diagnostic::malformed(
                            "directory contains itself; not followed",
                        ))
                    } else {
                        node.lazy(
                            crate::expander!(self::directory: (FsRef, u64, Arc<Vec<u64>>)),
                            (fs.clone(), child, ancestors.clone()),
                        )
                    }
                } else {
                    node.lazy(file, (fs.clone(), child))
                }
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn file(cx: Cx, (fs, ino): (FsRef, u64)) -> Result<()> {
    let (span, raw) = read_inode(&cx, &fs, ino).await?;
    cx.emit(fs.inode_node(ino, span));
    let mode = fs.mode(&raw);
    let size = fs.size_of(&raw);
    let (at, _) = fs.pointers_at();
    // A short symbolic link keeps its target where the block pointers go.
    if mode & 0o170_000 == 0o120_000 && fs.blocks_held(&raw) == 0 {
        let len = size.min(if fs.ufs2 { 120 } else { 60 });
        let bytes = raw
            .get(at..at.saturating_add(to_usize(len)))
            .unwrap_or_default();
        cx.emit(
            Node::new("Target")
                .span(span.sub(to_u64(at), len))
                .value(Value::Text(String::from_utf8_lossy(bytes).into_owned())),
        );
        return Ok(());
    }
    if !matches!(mode & 0o170_000, 0o100_000 | 0o120_000) {
        return Ok(());
    }
    let (data, pieces) = fs.content(&cx, span, &raw).await?;
    cx.emit(fragments_node(&cx, "Blocks", pieces).await);
    cx.emit(content_node(&fs.input, data));
    Ok(())
}
