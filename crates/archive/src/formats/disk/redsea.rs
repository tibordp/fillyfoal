//! RedSea, TempleOS's file system (`Kernel/BlkDev/FileSysRedSea.HC`,
//! `Kernel/KernelA.HH` and `Doc/RedSea.DD` of the public-domain TempleOS
//! V5.03 source).
//!
//! A RedSea volume is 512-byte blocks: a boot sector (`CRedSeaBoot`, told
//! from FAT32 by the byte 0x88 at offset 3), then an allocation bitmap,
//! then contiguous files. Block numbers are absolute, counted from the
//! start of the drive, and the boot sector records where the volume begins
//! (`drv_offset`): the partition's start on a hard disk, block 88 in the
//! distribution ISO (an ISO 9660 shell with an empty primary volume
//! descriptor and El Torito boot, written by `RedSeaISO9660` in
//! `Adam/Opt/Boot/DskISORedSea.HC`; [`super::iso9660`] hands that volume
//! here). The bitmap's bit *i* (LSB first) stands for block
//! `drv_offset + bitmap_sects + i`, the bitmap's own last block, which
//! formatting marks used.
//!
//! A directory is a run of 64-byte `CDirEntry`s (attributes, a 38-byte
//! name, first block, size in bytes, `CDate`), ended by one with an empty
//! name; the first describes the directory itself (its size is the
//! directory's), the second its parent. Every file is contiguous; files
//! whose names end in `.Z` are TempleOS-compressed and are dissected as
//! [`crate::formats::compression::templeos`]. Deleted entries keep their
//! name, with the `DELETED` attribute.
//!
//! On a hard disk TempleOS gives a RedSea partition the FAT32 type (0x0B)
//! "to fool BIOS" (`RedSeaFmt`), and accepts type 0x88 as well; either way
//! the partition is identified by its boot sector.

use std::sync::Arc;

use crate::bytes::{i64_le, to_u64, to_usize, u16_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::disk::{content_node, size, trailing_node};
use crate::formats::util::civil::{self, templeos_cdate_raw};
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const BLK: u64 = 512;
/// `CDIR_SIZE`.
const ENTRY: u64 = 64;
/// `MBR_PT_REDSEA`, the boot sector's `signature`.
const SIGNATURE: u8 = 0x88;
/// Bits per bitmap block.
const BITS_PER_BLK: u64 = BLK * 8;
const MAX_DEPTH: usize = 64;
/// Directory bytes listed at most.
const MAX_DIR_BYTES: u64 = 16 << 20;
/// Directory bytes read per step.
const DIR_CHUNK: u64 = 32 << 10;
/// Bitmap bytes counted eagerly for the volume's summary.
const MAX_SUMMARY_BITMAP: u64 = 1 << 20;
/// Bitmap bytes read per step when listing free runs.
const BITMAP_CHUNK: u64 = 1 << 10;
/// Block numbers beyond this are not plausible (2^40 blocks: 512 TiB).
const MAX_BLOCKS: u64 = 1 << 40;
/// Where `RedSeaISO` puts the volume inside its ISO 9660 shell: 76 blocks
/// for the system area and four descriptors, then the boot catalog and the
/// stage-1 loader (`19<<2+(DVD_BLK_SIZE*2+DVD_BOOT_LOADER_SIZE)/BLK_SIZE`).
pub const ISO_DRV_OFFSET: u64 = 88;

pub static FORMAT: Format = Format {
    name: "redsea",
    title: "RedSea file system (TempleOS)",
    extensions: &["img", "bin"],
    mime: "application/x-redsea",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The parts of `CRedSeaBoot` the dissector needs.
#[derive(Clone, Copy, Debug)]
pub struct Boot {
    pub drv_offset: u64,
    pub sects: u64,
    pub root_clus: u64,
    pub bitmap_sects: u64,
}

impl Boot {
    /// The first block the bitmap describes (`dv->data_area`).
    fn data_area(&self) -> u64 {
        self.drv_offset.saturating_add(self.bitmap_sects)
    }

    /// Blocks the bitmap describes.
    fn data_blocks(&self) -> u64 {
        self.sects.saturating_sub(self.bitmap_sects)
    }
}

/// A RedSea boot sector, if `b` (at least 512 bytes) is one: the
/// signatures, then the sizes `RedSeaFmt` writes (a bitmap block per 4096
/// blocks, the root directory inside the volume, after the bitmap).
pub fn boot(b: &[u8]) -> Option<Boot> {
    if b.get(3) != Some(&SIGNATURE)
        || b.get(4..8) != Some(&[0; 4])
        || b.get(510..512) != Some(&[0x55, 0xaa])
    {
        return None;
    }
    let get = |at| i64_le(b, at).and_then(|v| u64::try_from(v).ok());
    let boot = Boot {
        drv_offset: get(8)?,
        sects: get(16)?,
        root_clus: get(24)?,
        bitmap_sects: get(32)?,
    };
    (boot.drv_offset < MAX_BLOCKS
        && (2..MAX_BLOCKS).contains(&boot.sects)
        && boot.bitmap_sects == boot.sects.div_ceil(BITS_PER_BLK)
        && boot.root_clus > boot.data_area()
        && boot.root_clus < boot.drv_offset.saturating_add(boot.sects))
    .then_some(boot)
}

fn probe(h: &Head<'_>) -> bool {
    boot(h.data).is_some()
}

const ATTRS: FlagTable = &[
    flag(0x01, "READ_ONLY"),
    flag(0x02, "HIDDEN"),
    flag(0x04, "SYSTEM"),
    flag(0x08, "VOL_ID"),
    flag(0x10, "DIR"),
    flag(0x20, "ARCHIVE"),
    flag(0x100, "DELETED"),
    flag(0x200, "RESIDENT"),
    flag(0x400, "COMPRESSED"),
    flag(0x800, "CONTIGUOUS"),
    flag(0x1000, "FIXED"),
];
const ATTR_DIR: u16 = 0x10;
const ATTR_DELETED: u16 = 0x100;
const ATTR_COMPRESSED: u16 = 0x400;

/// Decorator for a `CDate` (`time` in the low 32 bits, `date` above).
fn cdate(v: &u64, node: Node) -> Node {
    if *v == 0 {
        return node.summary("not set");
    }
    node.value(Value::Timestamp {
        unix_seconds: templeos_cdate_raw(*v),
    })
    .desc("CDate: days since year 0 (high half), time of day in 2^-32 days (low half); local time")
}

record! {
    /// `CRedSeaBoot`.
    pub struct BootSector {
        jump: bytes[3] "jump_and_nop",
        signature: u8 "signature" .hex() .desc("MBR_PT_REDSEA (0x88): RedSea, not FAT32"),
        reserved: bytes[4] "reserved",
        drv_offset: i64 "drv_offset"
            .desc("Block where the volume begins; block numbers count from the drive's start"),
        sects: i64 "sects" .with(|&v, n| n.summary(size(u64::try_from(v).unwrap_or(0).saturating_mul(BLK)))),
        root_clus: i64 "root_clus" .desc("First block of the root directory"),
        bitmap_sects: i64 "bitmap_sects" .desc("Blocks of allocation bitmap, after this one"),
        unique_id: u64 "unique_id" .hex(),
        code: bytes[462] "code",
        signature2: u16 "signature2" .hex(),
    }
}

record! {
    /// `CDirEntry` as stored (the part from `start` on).
    pub struct DirEntry {
        attr: u16 "attr" .flags(ATTRS),
        name: bytes[38] "name" .with(|b, n| n.value(Value::Text(crate::text::latin1(until_nul(b))))),
        clus: i64 "clus" .desc("First block (absolute)"),
        size: i64 "size" .with(|&v, n| n.summary(size(u64::try_from(v).unwrap_or(0)))),
        datetime: u64 "datetime" .with(cdate),
    }
}

fn until_nul(b: &[u8]) -> &[u8] {
    let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
    b.get(..end).unwrap_or_default()
}

#[derive(Debug)]
struct Fs {
    input: Input,
    /// The volume, from its boot sector (block `drv_offset`) on.
    vol: Span,
    boot: Boot,
}

type FsRef = Arc<Fs>;

impl Fs {
    /// `len` bytes from absolute block `blk`, if the block is in the
    /// volume.
    fn at(&self, blk: u64, len: u64) -> Option<Span> {
        let rel = blk.checked_sub(self.boot.drv_offset)?;
        (rel < self.boot.sects).then(|| self.vol.sub(rel.saturating_mul(BLK), len))
    }
}

/// One decoded directory entry.
struct Entry {
    attr: u16,
    name: String,
    clus: u64,
    size: u64,
    datetime: u64,
}

fn entry(e: &[u8]) -> Entry {
    let get = |at| {
        i64_le(e, at)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(u64::MAX)
    };
    Entry {
        attr: u16_le(e, 0).unwrap_or(0),
        name: crate::text::latin1(until_nul(e.get(2..40).unwrap_or_default())),
        clus: get(40),
        size: get(48),
        datetime: u64_le(e, 56).unwrap_or(0),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sector = file.sub(0, BLK);
    let raw = cx.read(sector).await?;
    cx.emit(BootSector::node("Boot sector", sector, LE));
    let boot = boot(&raw).ok_or_else(|| Diagnostic::malformed("not a RedSea boot sector"))?;
    let vol_len = boot.sects.saturating_mul(BLK);
    let fs: FsRef = Arc::new(Fs {
        input,
        vol: file.sub(0, vol_len),
        boot,
    });
    let bitmap = file.sub(BLK, boot.bitmap_sects.saturating_mul(BLK));
    let total = boot.data_blocks();
    let mut node = Node::new("Allocation bitmap").span(bitmap);
    let mut used_note = String::new();
    if bitmap.len <= MAX_SUMMARY_BITMAP {
        let bits = cx.read_avail(bitmap).await?;
        cx.charge(to_u64(bits.len()) / 64).await;
        let used = count_used(&bits, total);
        node = node.summary(format!(
            "{} of {} in use",
            plural(used, "block"),
            plural(total, "block")
        ));
        used_note = format!(
            ", {}% used",
            used.saturating_mul(100).checked_div(total).unwrap_or(0)
        );
    } else {
        node = node.summary(format!("{} described", plural(total, "block")));
    }
    cx.emit(node.lazy(free_runs, fs.clone()));
    let root = Node::new("Root directory").summary(format!("block {}", boot.root_clus));
    cx.emit(root.lazy(
        crate::expander!(self::directory: (FsRef, u64, Arc<Vec<u64>>)),
        (fs.clone(), boot.root_clus, Arc::new(Vec::new())),
    ));
    if file.len < vol_len {
        cx.diag(Diagnostic::truncated(fs.vol, file.len));
    } else if let Some(rest) = trailing_node(&fs.input, vol_len) {
        cx.emit(rest);
    }
    let at = if boot.drv_offset == 0 {
        String::new()
    } else {
        format!(", from block {}", boot.drv_offset)
    };
    cx.annotate(format!(
        "RedSea file system (TempleOS), {}{at}{used_note}",
        size(vol_len)
    ));
    Ok(())
}

/// Set bits among the first `n` of a bitmap.
fn count_used(bits: &[u8], n: u64) -> u64 {
    let whole = to_usize(n / 8);
    let full: u64 = bits
        .get(..whole)
        .unwrap_or(bits)
        .iter()
        .map(|b| u64::from(b.count_ones()))
        .sum();
    let rest = u32::try_from(n % 8).unwrap_or(0);
    let mask = 1u8.checked_shl(rest).map_or(0xff, |m| m.wrapping_sub(1));
    full.saturating_add(
        bits.get(whole)
            .map_or(0, |b| u64::from((b & mask).count_ones())),
    )
}

/// Runs of free blocks, from the bitmap.
async fn free_runs(cx: Cx, fs: FsRef) -> Result<()> {
    let boot = fs.boot;
    let total = boot.data_blocks();
    let bitmap = fs.vol.sub(BLK, boot.bitmap_sects.saturating_mul(BLK));
    let run = |f: u64, to: u64| {
        let first = boot.data_area().saturating_add(f);
        let n = to.saturating_sub(f);
        let span = fs
            .at(first, n.saturating_mul(BLK))
            .unwrap_or(Span::zeros(0));
        Node::new(format!(
            "Blocks {first}–{}",
            first.saturating_add(n).saturating_sub(1)
        ))
        .span(span)
        .summary(format!("free, {}", size(n.saturating_mul(BLK))))
    };
    let mut from: Option<u64> = None;
    let mut i = 0u64;
    while i < total {
        let chunk = cx.read_avail(bitmap.sub(i / 8, BITMAP_CHUNK)).await?;
        if chunk.is_empty() {
            break;
        }
        let n = total
            .saturating_sub(i)
            .min(to_u64(chunk.len()).saturating_mul(8));
        for k in 0..n {
            let used = chunk
                .get(to_usize(k / 8))
                .is_some_and(|b| b >> (k % 8) & 1 != 0);
            let blk = i.saturating_add(k);
            match (used, from) {
                (false, None) => from = Some(blk),
                (true, Some(f)) => {
                    from = None;
                    cx.push(run(f, blk)).await;
                }
                _ => {}
            }
        }
        i = i.saturating_add(n);
        cx.charge(to_u64(chunk.len())).await;
    }
    if let Some(f) = from {
        cx.push(run(f, i)).await;
    }
    Ok(())
}

fn flags_summary(e: &Entry) -> String {
    let mut s = String::new();
    for (bit, c) in [
        (0x01u16, 'R'),
        (0x02, 'H'),
        (0x04, 'S'),
        (0x20, 'A'),
        (0x200, 'T'),
        (0x400, 'Z'),
        (0x800, 'C'),
        (0x1000, 'F'),
    ] {
        if e.attr & bit != 0 {
            s.push(c);
        }
    }
    s
}

async fn directory(cx: Cx, (fs, clus, ancestors): (FsRef, u64, Arc<Vec<u64>>)) -> Result<()> {
    let first = fs.at(clus, ENTRY).ok_or_else(|| {
        Diagnostic::malformed(format!("directory at block {clus} is outside the volume"))
    })?;
    let own = entry(&cx.read(first).await?);
    let mut dir_size = own.size;
    if dir_size < ENTRY.saturating_mul(2) || dir_size == u64::MAX {
        cx.diag(Diagnostic::malformed(format!(
            "directory size {dir_size} in its first entry; reading one block"
        )));
        dir_size = BLK;
    }
    if dir_size > MAX_DIR_BYTES {
        cx.diag(Diagnostic::limit(format!(
            "directory of {}; listing the first {}",
            size(dir_size),
            size(MAX_DIR_BYTES)
        )));
        dir_size = MAX_DIR_BYTES;
    }
    let span = fs.at(clus, dir_size).unwrap_or(first);
    if span.len < dir_size {
        cx.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, dir_size),
            span.len,
        ));
    }
    let mut ancestors = (*ancestors).clone();
    ancestors.push(clus);
    let ancestors = Arc::new(ancestors);
    let mut off = 0u64;
    let mut index = 0u64;
    'chunks: while off < span.len {
        let chunk = cx.read_avail(span.sub(off, DIR_CHUNK)).await?;
        if chunk.len() < 64 {
            break;
        }
        for e in chunk.as_chunks::<64>().0 {
            let at = span.sub(off, ENTRY);
            off = off.saturating_add(ENTRY);
            let i = index;
            index = index.saturating_add(1);
            cx.progress(off, span.len);
            let ent = entry(e);
            if ent.name.is_empty() {
                break 'chunks;
            }
            let node = match i {
                0 => DirEntry::node(".", at, LE).summary("this directory"),
                1 => DirEntry::node("..", at, LE).summary("parent directory"),
                _ => entry_node(&fs, &ent, at, &ancestors),
            };
            cx.push(node).await;
        }
    }
    Ok(())
}

fn entry_node(fs: &FsRef, e: &Entry, at: Span, ancestors: &Arc<Vec<u64>>) -> Node {
    let flags = flags_summary(e);
    let flags = if flags.is_empty() {
        String::new()
    } else {
        format!(" [{flags}]")
    };
    let when = if e.datetime == 0 {
        String::new()
    } else {
        format!(", {}", civil::date(templeos_cdate_raw(e.datetime)))
    };
    let node = Node::new(e.name.clone()).span(at);
    if e.attr & ATTR_DELETED != 0 {
        return node
            .summary(format!("deleted, {}{when}", size(e.size)))
            .diag(Diagnostic::note("deleted; its blocks may have been reused"))
            .lazy(file, (fs.clone(), at));
    }
    if e.attr & ATTR_DIR != 0 {
        let node = node.summary(format!("directory, {}{flags}{when}", size(e.size)));
        if ancestors.contains(&e.clus) || ancestors.len() >= MAX_DEPTH {
            return node.diag(Diagnostic::malformed(
                "directory contains itself (or nests too deep); not followed",
            ));
        }
        return node.lazy(
            crate::expander!(self::directory: (FsRef, u64, Arc<Vec<u64>>)),
            (fs.clone(), e.clus, ancestors.clone()),
        );
    }
    node.summary(format!("{}{flags}{when}", size(e.size)))
        .lazy(file, (fs.clone(), at))
}

/// A file: its directory entry and its content (TempleOS-compressed if
/// its name ends in `.Z`).
async fn file(cx: Cx, (fs, at): (FsRef, Span)) -> Result<()> {
    let e = entry(&cx.read(at).await?);
    cx.emit(DirEntry::node("Directory entry", at, LE));
    if e.size == 0 {
        return Ok(());
    }
    if e.size == u64::MAX || e.clus == u64::MAX {
        return Err(Diagnostic::malformed("negative block or size").at(at));
    }
    if e.clus < fs.boot.data_area() {
        return Err(Diagnostic::malformed(format!(
            "file starts at block {}, before the data area",
            e.clus
        ))
        .at(at));
    }
    let Some(span) = fs.at(e.clus, e.size) else {
        return Err(Diagnostic::malformed(format!(
            "file starts at block {}, outside the volume",
            e.clus
        ))
        .at(at));
    };
    let mut node = if e.name.ends_with(".Z") || e.attr & ATTR_COMPRESSED != 0 {
        embedded_as(
            "Content",
            fs.input.nested(span),
            &crate::formats::compression::templeos::FORMAT,
        )
        .summary(size(span.len))
    } else {
        content_node(&fs.input, span)
    };
    if span.len < e.size {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, e.size),
            span.len,
        ));
    }
    cx.emit(node);
    Ok(())
}
