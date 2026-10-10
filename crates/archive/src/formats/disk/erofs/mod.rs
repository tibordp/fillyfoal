//! EROFS (Enhanced Read-Only File System) images.
//!
//! The superblock sits at 1 KiB; compression configurations follow it.
//! Inodes are addressed by "nid", their offset from the metadata area in
//! 32-byte units: a compact (32-byte) or extended (64-byte) core, then the
//! inline extended attribute area, then layout-specific data. File data is
//! flat (whole blocks, optionally with the tail packed inline after the
//! inode), chunk-based (a table of chunk addresses), or compressed: a map
//! header and a logical cluster index describe physical clusters
//! compressed with LZ4, MicroLZMA, DEFLATE or Zstandard, with optional tail
//! packing, fragments (tails stored in a shared "packed" inode) and
//! deduplication. Directories are blocks of 12-byte entries followed by
//! their names.

mod xattr;
mod zmap;

use std::sync::Arc;

use crate::bytes::{align_up, to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::DIRENT_TYPES;
use crate::formats::disk::{
    PieceList, content_node, crc32c_update, size, text, unix_mode, uuid_value,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u32 = 0xe0f5_e1e2;
const NULL_ADDR: u32 = u32::MAX;
const MAX_DIR_DEPTH: usize = 64;
/// Directory bytes read at most.
const MAX_DIR_BYTES: u64 = 64 << 20;
/// Symlink target bytes read at most.
const MAX_TARGET: u64 = 4096;

pub static FORMAT: Format = Format {
    name: "erofs",
    title: "EROFS filesystem",
    extensions: &["img", "erofs"],
    mime: "application/x-erofs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 1024) == Some(MAGIC) && h.data.get(1036).is_some_and(|b| (9..=16).contains(b))
}

const COMPAT: FlagTable = &[
    flag(0x01, "SB_CHKSUM"),
    flag(0x02, "MTIME"),
    flag(0x04, "XATTR_FILTER"),
    flag(0x08, "SHARED_EA_IN_METABOX"),
    flag(0x10, "PLAIN_XATTR_PFX"),
];

/// Some bits have two names: the second applies to compressed images.
const INCOMPAT: FlagTable = &[
    flag(0x001, "ZERO_PADDING"),
    flag(0x002, "COMPR_CFGS/BIG_PCLUSTER"),
    flag(0x004, "CHUNKED_FILE"),
    flag(0x008, "DEVICE_TABLE/COMPR_HEAD2"),
    flag(0x010, "ZTAILPACKING"),
    flag(0x020, "FRAGMENTS/DEDUPE"),
    flag(0x040, "XATTR_PREFIXES"),
    flag(0x080, "48BIT"),
    flag(0x100, "METABOX"),
];

const ALGS: FlagTable = &[
    flag(0x1, "LZ4"),
    flag(0x2, "LZMA"),
    flag(0x4, "DEFLATE"),
    flag(0x8, "ZSTD"),
];

pub(super) const ALG_NAMES: EnumTable = &[
    (0, "LZ4"),
    (1, "MicroLZMA"),
    (2, "DEFLATE"),
    (3, "Zstandard"),
];

const LAYOUTS: EnumTable = &[
    (0, "flat"),
    (1, "compressed (full index)"),
    (2, "flat, tail inline"),
    (3, "compressed (compact index)"),
    (4, "chunk-based"),
];

const LAYOUT_FLAT_PLAIN: u8 = 0;
const LAYOUT_COMPRESSED_FULL: u8 = 1;
const LAYOUT_FLAT_INLINE: u8 = 2;
const LAYOUT_COMPRESSED_COMPACT: u8 = 3;
const LAYOUT_CHUNK_BASED: u8 = 4;

struct Sb {
    compat: u32,
    root_nid: u16,
    inos: u64,
    build_time: u64,
    blocks: u32,
    meta: u32,
    xattr: u32,
    name: Vec<u8>,
    incompat: u32,
    u1: u16,
    extra_devices: u16,
    devt_slotoff: u16,
    dirblkbits: u8,
    prefix_count: u8,
    prefix_start: u32,
    packed_nid: u64,
}

fn sb_layout(f: &mut Fields<'_>, computed: &Option<u32>) -> Result<Sb> {
    f.u32("Magic").hex().emit()?;
    f.u32("Checksum")
        .hex()
        .with(|&v, n| match computed {
            Some(c) if *c == v => n.summary("valid CRC-32C"),
            Some(c) => n.diag(Diagnostic::warning(format!(
                "mismatch: computed {c:#010x}"
            ))),
            None => n.summary("not used"),
        })
        .desc("CRC-32C (no final inversion) of the superblock's block from offset 1024, with this field zeroed")
        .emit()?;
    let compat = f.u32("Compatible features").hex().flags(COMPAT).emit()?;
    let blkbits = f
        .u8("log2(block size)")
        .with(|&v, n| n.summary(size(1u64.checked_shl(v.into()).unwrap_or(0))))
        .emit()?;
    f.u8("Extension slots")
        .with(|&v, n| {
            n.summary(format!(
                "superblock of {} bytes",
                128u32.saturating_add(u32::from(v).saturating_mul(16))
            ))
        })
        .emit()?;
    let root_nid = f.u16("Root directory nid").emit()?;
    let inos = f.u64("Inodes").emit()?;
    let build_time = f.u64("Build time").timestamp().emit()?;
    f.u32("Build time (ns)").emit()?;
    let block = 1u64.checked_shl(blkbits.into()).unwrap_or(0);
    let blocks = f
        .u32("Blocks")
        .with(|&v, n| n.summary(size(u64::from(v).saturating_mul(block))))
        .emit()?;
    let meta = f
        .u32("Metadata area block")
        .desc("Inodes are found at this block plus 32 × nid bytes")
        .emit()?;
    let xattr = f
        .u32("Shared xattr area block")
        .desc("Shared xattrs are found at this block plus 4 × id bytes")
        .emit()?;
    f.bytes("UUID", 16).with(uuid_value).emit()?;
    let name = f
        .bytes("Volume name", 16)
        .with(|b, n| n.value(text(b)))
        .emit()?;
    let incompat = f
        .u32("Incompatible features")
        .hex()
        .flags(INCOMPAT)
        .emit()?;
    let u1 = if incompat & 0x2 != 0 {
        f.u16("Compression algorithms").hex().flags(ALGS).emit()?
    } else {
        f.u16("LZ4 maximum distance").emit()?
    };
    let extra_devices = f.u16("Extra devices").emit()?;
    let devt_slotoff = f
        .u16("Device table slot")
        .with(|&v, n| n.summary(format!("byte {}", u32::from(v).saturating_mul(128))))
        .emit()?;
    let dirblkbits = f.u8("log2(directory block / block)").emit()?;
    let prefix_count = f.u8("Long xattr name prefixes").emit()?;
    let prefix_start = f
        .u32("Long xattr name prefix table")
        .with(|&v, n| n.summary(format!("byte {}", u64::from(v).saturating_mul(4))))
        .desc("In 4-byte units, in the packed inode's data if there is one")
        .emit()?;
    let packed_nid = f
        .u64("Packed inode nid")
        .desc("The inode holding fragments and long xattr name prefixes")
        .emit()?;
    f.u8("Xattr filter (reserved)").emit()?;
    f.bytes("Reserved", 23).emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Extension slots", rest).emit()?;
    }
    Ok(Sb {
        compat,
        root_nid,
        inos,
        build_time,
        blocks,
        meta,
        xattr,
        name,
        incompat,
        u1,
        extra_devices,
        devt_slotoff,
        dirblkbits,
        prefix_count,
        prefix_start,
        packed_nid,
    })
}

/// Filesystem parameters shared by every expansion.
#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    blk: u64,
    blkbits: u32,
    /// Byte offset of the metadata area (nid 0).
    meta: u64,
    /// Byte offset of the shared xattr area (id 0).
    xattr: u64,
    dir_block: u64,
    compat: u32,
    zero_padding: bool,
    packed_nid: Option<u64>,
    lzma_dict: Option<u32>,
    build_time: u64,
    /// Long xattr name prefixes: (base name index, infix).
    prefixes: Vec<(u8, Vec<u8>)>,
}

type FsRef = Arc<Fs>;

/// An inode as read from disk.
struct Ino {
    /// Offset of the inode in the volume.
    off: u64,
    ext: bool,
    layout: u8,
    mode: u16,
    size: u64,
    iu: u32,
    xcount: u16,
    nlink: u32,
}

impl Ino {
    async fn read(cx: &Cx, fs: &Fs, nid: u64) -> Result<Ino> {
        let off = fs.meta.saturating_add(nid.saturating_mul(32));
        let head = cx
            .read(fs.vol.sub(off, 32))
            .await
            .map_err(|d| Diagnostic::malformed(format!("inode nid {nid}: {}", d.message)))?;
        let format = u16_le(&head, 0).unwrap_or(0);
        let ext = format & 1 != 0;
        let raw = if ext {
            cx.read(fs.vol.sub(off, 64)).await?
        } else {
            head
        };
        let layout = u8::try_from((format >> 1) & 7).unwrap_or(0);
        Ok(Ino {
            off,
            ext,
            layout,
            mode: u16_le(&raw, 4).unwrap_or(0),
            size: if ext {
                u64_le(&raw, 8).unwrap_or(0)
            } else {
                u32_le(&raw, 8).unwrap_or(0).into()
            },
            iu: u32_le(&raw, 16).unwrap_or(0),
            xcount: u16_le(&raw, 2).unwrap_or(0),
            nlink: if ext {
                u32_le(&raw, 44).unwrap_or(0)
            } else {
                u16_le(&raw, 6).unwrap_or(0).into()
            },
        })
    }

    fn core_len(&self) -> u64 {
        if self.ext { 64 } else { 32 }
    }

    fn xattr_len(&self) -> u64 {
        if self.xcount == 0 {
            0
        } else {
            12u64.saturating_add(u64::from(self.xcount.saturating_sub(1)).saturating_mul(4))
        }
    }

    /// Offset of the first byte after the core and the inline xattrs.
    fn after(&self) -> u64 {
        self.off
            .saturating_add(self.core_len())
            .saturating_add(self.xattr_len())
    }

    fn kind(&self) -> u16 {
        self.mode & 0xf000
    }

    fn core_span(&self, fs: &Fs) -> Span {
        fs.vol.sub(self.off, self.core_len())
    }

    fn summary(&self) -> String {
        format!(
            "{}, {}, {}",
            unix_mode(self.mode.into()),
            size(self.size),
            lookup(LAYOUTS, self.layout.into()).unwrap_or("unknown layout")
        )
    }
}

/// The superblock checksum: CRC-32C of the rest of the superblock's block,
/// checksum zeroed, without final inversion.
fn sb_checksum(data: &[u8]) -> u32 {
    let before = data.get(..4).unwrap_or_default();
    let after = data.get(8..).unwrap_or_default();
    crc32c_update(crc32c_update(crc32c_update(!0, before), &[0; 4]), after)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let head = cx.read(vol.sub(SUPER, 128)).await?;
    let blkbits = head.get(12).copied().unwrap_or(0);
    if !(9..=16).contains(&blkbits) {
        return Err(
            Diagnostic::malformed(format!("block size 2^{blkbits}")).at(vol.sub(SUPER, 128))
        );
    }
    let blk = 1u64.checked_shl(blkbits.into()).unwrap_or(4096);
    let compat = u32_le(&head, 8).unwrap_or(0);
    let extslots = u64::from(head.get(13).copied().unwrap_or(0));
    let sb_len = 128u64.saturating_add(extslots.saturating_mul(16));
    let computed = if compat & 1 != 0 {
        let raw = cx
            .read_avail(vol.sub(SUPER, blk.saturating_sub(SUPER).max(sb_len)))
            .await?;
        Some(sb_checksum(&raw))
    } else {
        None
    };
    let sb_span = vol.sub(SUPER, sb_len);
    let sb = parse(&cx, sb_span, LE, &computed, sb_layout).await?;
    if blk > SUPER {
        cx.emit(
            Node::new("Boot area")
                .span(vol.sub(0, SUPER))
                .summary("1 KiB left for a boot loader; not used by EROFS"),
        );
    }
    let mut node = struct_node("Superblock", sb_span, LE, computed, sb_layout).summary(format!(
        "{} inodes, {} blocks of {}",
        sb.inos,
        sb.blocks,
        size(blk)
    ));
    if let Some(c) = computed
        && u32_le(&head, 4) != Some(c)
    {
        node = node.diag(Diagnostic::warning("superblock checksum mismatch"));
    }
    cx.emit(node);
    let label = crate::text::until_nul(&sb.name);
    let mut algs = Vec::new();
    if sb.incompat & 0x2 != 0 {
        for (bit, name) in [(1u16, "LZ4"), (2, "LZMA"), (4, "DEFLATE"), (8, "Zstandard")] {
            if sb.u1 & bit != 0 {
                algs.push(name);
            }
        }
    } else if sb.incompat & 0x1 != 0 {
        algs.push("LZ4");
    }
    cx.annotate(format!(
        "EROFS filesystem{}, {}, {} inodes, {}",
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(u64::from(sb.blocks).saturating_mul(blk)),
        sb.inos,
        if algs.is_empty() {
            "uncompressed".to_owned()
        } else {
            format!("{} compression", algs.join(", "))
        }
    ));

    // Compression configurations follow the superblock, one per algorithm.
    let mut lzma_dict = None;
    let mut cfgs = Vec::new();
    if sb.incompat & 0x2 != 0 {
        let mut pos = SUPER.saturating_add(sb_len);
        for alg in 0..16u8 {
            if sb.u1 & 1u16.checked_shl(alg.into()).unwrap_or(0) == 0 {
                continue;
            }
            pos = align_up(pos, 4);
            let rec = cx.read_avail(vol.sub(pos, 16)).await?;
            let len = u64::from(u16_le(&rec, 0).unwrap_or(0));
            if alg == 1 {
                lzma_dict = u32_le(&rec, 2);
            }
            cfgs.push((alg, vol.sub(pos, len.saturating_add(2))));
            pos = pos.saturating_add(2).saturating_add(len);
        }
    }
    let base = Fs {
        input,
        vol,
        blk,
        blkbits: blkbits.into(),
        meta: u64::from(sb.meta).saturating_mul(blk),
        xattr: u64::from(sb.xattr).saturating_mul(blk),
        dir_block: blk.checked_shl(sb.dirblkbits.into()).unwrap_or(blk),
        compat: sb.compat,
        zero_padding: sb.incompat & 0x1 != 0,
        packed_nid: (sb.packed_nid != 0 && sb.incompat & 0x60 != 0).then_some(sb.packed_nid),
        lzma_dict,
        build_time: sb.build_time,
        prefixes: Vec::new(),
    };
    let (prefixes, prefix_spans) = match long_prefixes(&cx, &base, &sb).await {
        Ok(p) => p,
        Err(d) => {
            cx.diag(d);
            (Vec::new(), Vec::new())
        }
    };
    let fs: FsRef = Arc::new(Fs { prefixes, ..base });
    if !cfgs.is_empty() {
        let start = cfgs.first().map_or(0, |c| c.1.offset);
        let end = cfgs.last().map_or(0, |c| c.1.end());
        cx.emit(
            Node::new("Compression configurations")
                .span(Span::new(vol.source, start, end.saturating_sub(start)))
                .summary(format!("{} algorithms", cfgs.len()))
                .lazy(compression_cfgs, Arc::new(cfgs)),
        );
    }
    if sb.extra_devices > 0 {
        let at = u64::from(sb.devt_slotoff).saturating_mul(128);
        let span = vol.sub(at, u64::from(sb.extra_devices).saturating_mul(128));
        cx.emit(
            Node::new("Device table")
                .span(span)
                .summary(format!("{} extra devices", sb.extra_devices))
                .lazy(device_table, span),
        );
    }
    cx.emit(
        Node::new("Root directory")
            .summary(format!("nid {}", sb.root_nid))
            .lazy(
                crate::expander!(self::directory: DirState),
                DirState {
                    fs: fs.clone(),
                    nid: sb.root_nid.into(),
                    path: Path::new(),
                },
            ),
    );
    if let Some(nid) = fs.packed_nid {
        cx.emit(
            Node::new("Packed inode")
                .summary(format!("nid {nid}: fragments and shared metadata"))
                .lazy(view, (fs.clone(), nid)),
        );
    }
    if !prefix_spans.is_empty() {
        cx.emit(
            Node::new("Long xattr name prefixes")
                .summary(format!("{} prefixes", prefix_spans.len()))
                .lazy(xattr::prefix_table, (fs.clone(), Arc::new(prefix_spans))),
        );
    }
    Ok(())
}

/// Reads the long xattr name prefix table: the prefixes, and the span of
/// each record.
async fn long_prefixes(cx: &Cx, fs: &Fs, sb: &Sb) -> Result<(Vec<(u8, Vec<u8>)>, Vec<Span>)> {
    if sb.prefix_count == 0 || sb.incompat & 0x40 == 0 {
        return Ok((Vec::new(), Vec::new()));
    }
    let source = match fs.packed_nid {
        Some(nid) => {
            let ino = Ino::read(cx, fs, nid).await?;
            data(cx, fs, &ino, 1).await?
        }
        None => fs.vol,
    };
    let mut pos = u64::from(sb.prefix_start).saturating_mul(4);
    let mut out = Vec::new();
    let mut spans = Vec::new();
    for _ in 0..sb.prefix_count {
        pos = align_up(pos, 4);
        let len_bytes = cx.read(source.sub(pos, 2)).await?;
        let len = u64::from(u16_le(&len_bytes, 0).unwrap_or(0));
        let rec = source.sub(pos, len.saturating_add(2));
        let body = cx.read(rec.tail(2)).await?;
        let base = body.first().copied().unwrap_or(0);
        out.push((base, body.get(1..).unwrap_or_default().to_vec()));
        spans.push(rec);
        pos = pos.saturating_add(2).saturating_add(len);
    }
    Ok((out, spans))
}

fn lz4_cfg(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.u16("Maximum match distance").emit()?;
    f.u16("Maximum physical cluster blocks").emit()?;
    f.bytes("Reserved", 10).emit()?;
    Ok(())
}

fn lzma_cfg(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.u32("Dictionary size")
        .with(|&v, n| n.summary(size(v.into())))
        .emit()?;
    f.u16("Format").emit()?;
    f.bytes("Reserved", 8).emit()?;
    Ok(())
}

fn deflate_cfg(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.u8("Window bits")
        .with(|&v, n| n.summary(size(1u64.checked_shl(v.into()).unwrap_or(0))))
        .emit()?;
    f.bytes("Reserved", 5).emit()?;
    Ok(())
}

fn zstd_cfg(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.u8("Format").emit()?;
    f.u8("Window log")
        .with(|&v, n| {
            n.summary(format!(
                "window {}",
                size(
                    1u64.checked_shl(u32::from(v).saturating_add(10))
                        .unwrap_or(0)
                )
            ))
        })
        .desc("log2 of the window size, less 10")
        .emit()?;
    f.bytes("Reserved", 4).emit()?;
    Ok(())
}

fn raw_cfg(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Configuration", rest).emit()?;
    }
    Ok(())
}

async fn compression_cfgs(cx: Cx, cfgs: Arc<Vec<(u8, Span)>>) -> Result<()> {
    for &(alg, span) in cfgs.iter() {
        let layout: crate::fields::Layout<(), ()> = match alg {
            0 => lz4_cfg,
            1 => lzma_cfg,
            2 => deflate_cfg,
            3 => zstd_cfg,
            _ => raw_cfg,
        };
        cx.emit(
            struct_node(
                lookup(ALG_NAMES, alg.into()).unwrap_or("Unknown algorithm"),
                span,
                LE,
                (),
                layout,
            )
            .summary(size(span.len)),
        );
    }
    Ok(())
}

fn device_slot(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("Tag", 64).with(|b, n| n.value(text(b))).emit()?;
    f.u32("Blocks").emit()?;
    f.u32("Mapped start block").emit()?;
    f.bytes("Reserved", 56).emit()?;
    Ok(())
}

async fn device_table(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 128;
    for i in 0..n {
        cx.push(struct_node(
            format!("Device {}", i.saturating_add(1)),
            span.sub(i.saturating_mul(128), 128),
            LE,
            (),
            device_slot,
        ))
        .await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct InoCtx {
    ext: bool,
    layout: u8,
    kind: u16,
    /// Base of compact inode modification times, if they have one.
    mtime_base: Option<u64>,
}

fn device_summary(v: u32) -> String {
    // Linux's new_encode_dev.
    let major = (v & 0xf_ff00) >> 8;
    let minor = (v & 0xff) | ((v >> 12) & 0xf_ff00);
    format!("major {major}, minor {minor}")
}

fn inode_layout(f: &mut Fields<'_>, ctx: &InoCtx) -> Result<()> {
    f.u16("Format")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, {}{}",
                if v & 1 != 0 { "extended" } else { "compact" },
                lookup(LAYOUTS, ((v >> 1) & 7).into()).unwrap_or("unknown layout"),
                if v & 0x10 != 0 { ", one link" } else { "" }
            ))
        })
        .desc("Bit 0: extended inode; bits 1–3: data layout")
        .emit()?;
    f.u16("Xattr count")
        .desc("The inline xattr area is 12 bytes plus 4 × (count − 1); 0 for none")
        .emit()?;
    f.u16("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    if ctx.ext {
        f.u16("Reserved").emit()?;
        f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    } else {
        f.u16("Link count").emit()?;
        f.u32("Size")
            .with(|&v, n| n.summary(size(v.into())))
            .emit()?;
        match ctx.mtime_base {
            Some(base) => {
                f.u32("Modification time")
                    .with(|&v, n| {
                        n.value(Value::Timestamp {
                            unix_seconds: i64::try_from(base.saturating_add(v.into()))
                                .unwrap_or(i64::MAX),
                        })
                    })
                    .desc("Seconds after the filesystem's build time")
                    .emit()?;
            }
            None => {
                f.u32("Reserved").emit()?;
            }
        }
    }
    match (ctx.kind, ctx.layout) {
        (0x2000 | 0x6000, _) => {
            f.u32("Device")
                .hex()
                .with(|&v, n| n.summary(device_summary(v)))
                .emit()?;
        }
        (_, LAYOUT_CHUNK_BASED) => {
            f.u16("Chunk format")
                .hex()
                .with(|&v, n| {
                    n.summary(format!(
                        "chunks of 2^{} blocks, {}",
                        v & 0x1f,
                        if v & 0x20 != 0 {
                            "index table"
                        } else {
                            "block map"
                        }
                    ))
                })
                .emit()?;
            f.u16("Reserved").emit()?;
        }
        (_, LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT) => {
            f.u32("Compressed blocks").emit()?;
        }
        _ => {
            f.u32("Start block")
                .with(|&v, n| if v == NULL_ADDR { n.summary("none") } else { n })
                .emit()?;
        }
    }
    f.u32("Inode number")
        .desc("For 32-bit stat(2); nids identify inodes on disk")
        .emit()?;
    if ctx.ext {
        f.u32("Owner UID").emit()?;
        f.u32("Group GID").emit()?;
        f.u64("Modification time").timestamp().emit()?;
        f.u32("Modification time (ns)").emit()?;
        f.u32("Link count").emit()?;
        f.bytes("Reserved", 16).emit()?;
    } else {
        f.u16("Owner UID").emit()?;
        f.u16("Group GID").emit()?;
        f.u32("Reserved").emit()?;
    }
    Ok(())
}

/// [`data`] behind a box, for the recursion through the packed inode.
fn data_boxed<'a>(
    cx: &'a Cx,
    fs: &'a Fs,
    ino: &'a Ino,
    depth: u32,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Span>> + Send + 'a>> {
    Box::pin(data(cx, fs, ino, depth))
}

/// The bytes of an inode's data: flat, chunk-based or decompressed.
/// `depth` guards the recursion through the packed inode.
async fn data(cx: &Cx, fs: &Fs, ino: &Ino, depth: u32) -> Result<Span> {
    match ino.layout {
        LAYOUT_FLAT_PLAIN => {
            if ino.size == 0 {
                return Ok(fs.vol.sub(ino.off, 0));
            }
            let start = u64::from(ino.iu).saturating_mul(fs.blk);
            fs.vol
                .sub_exact(start, ino.size)
                .map_err(|_| Diagnostic::malformed("data runs past the image"))
        }
        LAYOUT_FLAT_INLINE => {
            let (head, tail) = inline_split(fs, ino.size);
            let mut list = PieceList::new(ino.core_span(fs));
            if head > 0 {
                let start = u64::from(ino.iu).saturating_mul(fs.blk);
                list.data(
                    fs.vol
                        .sub_exact(start, head)
                        .map_err(|_| Diagnostic::malformed("data runs past the image"))?,
                );
            }
            list.data(fs.vol.sub(ino.after(), tail));
            list.finish(cx, "erofs-inline").await
        }
        LAYOUT_CHUNK_BASED => {
            let table = chunk_table(cx, fs, ino).await?;
            let mut list = PieceList::new(ino.core_span(fs));
            for (i, c) in table.entries.iter().enumerate() {
                if i.is_multiple_of(1024) {
                    cx.checkpoint().await;
                }
                let at = to_u64(i).saturating_mul(table.chunk);
                let len = table.chunk.min(ino.size.saturating_sub(at));
                match c {
                    Some((0, blk)) => list.data(fs.vol.sub(blk.saturating_mul(fs.blk), len)),
                    _ => list.hole(cx, len)?,
                }
            }
            if list.len() < ino.size {
                list.hole(cx, ino.size.saturating_sub(list.len()))?;
            }
            list.finish(cx, "erofs-chunks").await
        }
        LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT => {
            zmap::content(cx, fs, ino, depth).await
        }
        other => Err(Diagnostic::unsupported(format!("data layout {other}"))),
    }
}

/// Bytes in whole blocks and in the inline tail of a flat inline inode.
fn inline_split(fs: &Fs, size: u64) -> (u64, u64) {
    let nblocks = size.div_ceil(fs.blk);
    let head = nblocks.saturating_sub(1).saturating_mul(fs.blk);
    (head, size.saturating_sub(head))
}

struct ChunkTable {
    span: Span,
    indexes: bool,
    chunk: u64,
    /// (device, block) per chunk; `None` for a hole.
    entries: Vec<Option<(u16, u64)>>,
}

async fn chunk_table(cx: &Cx, fs: &Fs, ino: &Ino) -> Result<ChunkTable> {
    let format = ino.iu & 0xffff;
    let indexes = format & 0x20 != 0;
    let chunk = fs
        .blk
        .checked_shl(format & 0x1f)
        .filter(|&c| c > 0)
        .ok_or_else(|| Diagnostic::malformed("chunk size overflows"))?;
    let count = ino.size.div_ceil(chunk);
    let unit: u64 = if indexes { 8 } else { 4 };
    let start = align_up(ino.after(), unit);
    let span = fs
        .vol
        .sub_exact(start, count.saturating_mul(unit))
        .map_err(|_| Diagnostic::malformed("chunk table runs past the image"))?;
    let raw = cx.read(span).await?;
    let mut entries = Vec::new();
    for (i, e) in raw.chunks(to_usize(unit)).enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        entries.push(if indexes {
            let lo = u32_le(e, 4).unwrap_or(NULL_ADDR);
            let device = u16_le(e, 2).unwrap_or(0);
            (lo != NULL_ADDR).then_some((device, u64::from(lo)))
        } else {
            let b = u32_le(e, 0).unwrap_or(NULL_ADDR);
            (b != NULL_ADDR).then_some((0, u64::from(b)))
        });
    }
    Ok(ChunkTable {
        span,
        indexes,
        chunk,
        entries,
    })
}

fn chunk_index_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Start block (high)")
        .desc("High bits of the start block on 48-bit images (advice bits before)")
        .emit()?;
    f.u16("Device").desc("0 for the primary device").emit()?;
    f.u32("Start block")
        .with(|&v, n| if v == NULL_ADDR { n.summary("hole") } else { n })
        .emit()?;
    Ok(())
}

async fn chunk_view(cx: Cx, (fs, nid): (FsRef, u64)) -> Result<()> {
    let ino = Ino::read(&cx, &fs, nid).await?;
    let table = chunk_table(&cx, &fs, &ino).await?;
    let unit: u64 = if table.indexes { 8 } else { 4 };
    for (i, e) in table.entries.iter().enumerate() {
        let span = table.span.sub(to_u64(i).saturating_mul(unit), unit);
        let at = to_u64(i).saturating_mul(table.chunk);
        let summary = match e {
            Some((dev, b)) => format!(
                "bytes {at}–{} → {}block {b}",
                at.saturating_add(table.chunk.min(ino.size.saturating_sub(at)))
                    .saturating_sub(1),
                if *dev == 0 {
                    String::new()
                } else {
                    format!("device {dev} ")
                }
            ),
            None => "hole".to_owned(),
        };
        let node = if table.indexes {
            struct_node(format!("Chunk {i}"), span, LE, (), chunk_index_layout)
        } else {
            Node::new(format!("Chunk {i}"))
                .span(span)
                .value(Value::UInt {
                    value: e.map_or(u64::from(NULL_ADDR), |(_, b)| b),
                    bits: 32,
                    radix: Radix::Dec,
                })
        };
        cx.push(node.summary(summary)).await;
        if let Some((0, b)) = e {
            cx.push(
                Node::new(format!("Chunk {i} data"))
                    .span(fs.vol.sub(b.saturating_mul(fs.blk), table.chunk))
                    .summary(format!("{} at block {b}", size(table.chunk))),
            )
            .await;
        }
    }
    let end = table.span.end().saturating_sub(fs.vol.offset);
    let aligned = align_up(end, 32);
    if aligned > end {
        cx.push(
            Node::new("Padding")
                .span(fs.vol.sub(end, aligned.saturating_sub(end)))
                .summary("to the next inode slot"),
        )
        .await;
    }
    Ok(())
}

/// Emits the padding from `end` to the next 32-byte inode slot.
fn slot_padding(cx: &Cx, fs: &Fs, end: u64) {
    let aligned = align_up(end, 32);
    if aligned > end {
        cx.emit(
            Node::new("Padding")
                .span(fs.vol.sub(end, aligned.saturating_sub(end)))
                .summary("to the next inode slot"),
        );
    }
}

/// Shows an inode: its core, xattrs, data layout and content.
async fn view(cx: Cx, (fs, nid): (FsRef, u64)) -> Result<()> {
    let ino = Ino::read(&cx, &fs, nid).await?;
    cx.annotate(ino.summary());
    cx.emit(
        struct_node(
            "Core",
            ino.core_span(&fs),
            LE,
            InoCtx {
                ext: ino.ext,
                layout: ino.layout,
                kind: ino.kind(),
                mtime_base: (fs.compat & 0x2 != 0).then_some(fs.build_time),
            },
            inode_layout,
        )
        .summary(format!(
            "nid {nid}, {} inode, {} links",
            if ino.ext { "extended" } else { "compact" },
            ino.nlink
        )),
    );
    if ino.xattr_len() > 0 {
        let span = fs
            .vol
            .sub(ino.off.saturating_add(ino.core_len()), ino.xattr_len());
        cx.emit(
            Node::new("Extended attributes")
                .span(span)
                .summary(size(span.len))
                .lazy(xattr::view, (fs.clone(), nid)),
        );
    }
    let special = matches!(ino.kind(), 0x2000 | 0x6000 | 0x1000 | 0xc000);
    if special || ino.layout == LAYOUT_FLAT_PLAIN {
        slot_padding(&cx, &fs, ino.after());
    }
    if special {
        return Ok(());
    }
    match ino.layout {
        LAYOUT_FLAT_INLINE => {
            let (head, tail) = inline_split(&fs, ino.size);
            if head > 0 {
                cx.emit(
                    Node::new("Data blocks")
                        .span(fs.vol.sub(u64::from(ino.iu).saturating_mul(fs.blk), head))
                        .summary(format!("block {}, {}", ino.iu, size(head))),
                );
            }
            cx.emit(
                Node::new("Inline tail")
                    .span(fs.vol.sub(ino.after(), tail))
                    .summary(format!("{} after the inode", size(tail))),
            );
            slot_padding(&cx, &fs, ino.after().saturating_add(tail));
        }
        LAYOUT_FLAT_PLAIN if ino.size > 0 => {
            cx.emit(
                Node::new("Data blocks")
                    .span(fs.vol.sub(
                        u64::from(ino.iu).saturating_mul(fs.blk),
                        align_up(ino.size, fs.blk),
                    ))
                    .summary(format!("block {}, {}", ino.iu, size(ino.size))),
            );
        }
        LAYOUT_CHUNK_BASED => {
            cx.emit(
                Node::new("Chunk table")
                    .summary(format!(
                        "chunks of {}",
                        size(fs.blk.checked_shl(ino.iu & 0x1f).unwrap_or(0))
                    ))
                    .lazy(chunk_view, (fs.clone(), nid)),
            );
        }
        LAYOUT_COMPRESSED_FULL | LAYOUT_COMPRESSED_COMPACT => {
            cx.emit(
                Node::new("Compression map")
                    .summary(format!("{} compressed blocks", ino.iu))
                    .lazy(zmap::view, (fs.clone(), nid)),
            );
        }
        _ => {}
    }
    let content = data(&cx, &fs, &ino, 0).await?;
    match ino.kind() {
        0x4000 => cx.emit(
            Node::new("Directory blocks")
                .span(content)
                .summary(size(content.len))
                .lazy(dir_blocks, (fs.clone(), nid)),
        ),
        0xa000 => {
            let text = cx.read_avail(content.sub(0, MAX_TARGET)).await?;
            cx.emit(
                Node::new("Target")
                    .span(content)
                    .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
            );
        }
        _ => cx.emit(content_node(&fs.input, content)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Directories

struct Dirent {
    off: u64,
    nid: u64,
    nameoff: u64,
    ftype: u8,
    name: Vec<u8>,
    name_end: u64,
}

/// The entries of one directory block, `valid` bytes of which are in use.
fn dirents(block: &[u8], valid: u64) -> (Vec<Dirent>, Option<Diagnostic>) {
    let first = u64::from(u16_le(block, 8).unwrap_or(0));
    if first < 12 || first % 12 != 0 || first > valid {
        return (
            Vec::new(),
            Some(Diagnostic::malformed(format!(
                "directory block: bad first name offset {first}"
            ))),
        );
    }
    let n = first / 12;
    let mut out = Vec::new();
    for i in 0..n {
        let at = to_usize(i.saturating_mul(12));
        let nameoff = u64::from(u16_le(block, at.saturating_add(8)).unwrap_or(0));
        let end = if i.saturating_add(1) < n {
            u64::from(u16_le(block, at.saturating_add(20)).unwrap_or(0))
        } else {
            valid
        };
        if nameoff < first || end < nameoff || end > valid {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "directory entry {i}: bad name offset {nameoff}"
                ))),
            );
        }
        let raw = block
            .get(to_usize(nameoff)..to_usize(end))
            .unwrap_or_default();
        let len = raw.iter().position(|&b| b == 0).unwrap_or(raw.len());
        out.push(Dirent {
            off: to_u64(at),
            nid: u64_le(block, at).unwrap_or(0),
            nameoff,
            ftype: block.get(at.saturating_add(10)).copied().unwrap_or(0),
            name: raw.get(..len).unwrap_or_default().to_vec(),
            name_end: nameoff.saturating_add(to_u64(len)),
        });
    }
    (out, None)
}

#[derive(Clone)]
struct DirState {
    fs: FsRef,
    nid: u64,
    path: Path,
}

/// Lists a directory: its inode, then its entries.
async fn directory(cx: Cx, st: DirState) -> Result<()> {
    let fs = st.fs.clone();
    let ino = Ino::read(&cx, &fs, st.nid).await?;
    if ino.kind() != 0x4000 {
        return Err(Diagnostic::malformed(format!(
            "nid {} is not a directory",
            st.nid
        )));
    }
    cx.emit(
        Node::new("Inode")
            .span(ino.core_span(&fs))
            .summary(format!("nid {}, {}", st.nid, ino.summary()))
            .lazy(view, (fs.clone(), st.nid)),
    );
    let content = data(&cx, &fs, &ino, 0).await?;
    let len = content.len.min(MAX_DIR_BYTES);
    let blocks = len.div_ceil(fs.dir_block);
    for b in 0..blocks {
        cx.progress(b, blocks);
        let at = b.saturating_mul(fs.dir_block);
        let span = content.sub(at, fs.dir_block);
        let block = cx.read_avail(span).await?;
        let valid = fs.dir_block.min(len.saturating_sub(at));
        let (entries, problem) = dirents(&block, valid);
        for e in entries {
            if e.name == b"." || e.name == b".." {
                continue;
            }
            let kind = lookup(DIRENT_TYPES, e.ftype.into()).unwrap_or("unknown");
            let node = Node::new(String::from_utf8_lossy(&e.name).into_owned())
                .span(span.sub(e.off, 12))
                .value(Value::UInt {
                    value: e.nid,
                    bits: 64,
                    radix: Radix::Dec,
                })
                .summary(format!("{kind}, nid {}", e.nid));
            let node = if e.ftype == 2 {
                match st.path.enter(e.nid, MAX_DIR_DEPTH) {
                    Ok(path) => node.lazy(
                        crate::expander!(self::directory: DirState),
                        DirState {
                            fs: fs.clone(),
                            nid: e.nid,
                            path,
                        },
                    ),
                    Err(d) => node.diag(d),
                }
            } else {
                node.lazy(view, (fs.clone(), e.nid))
            };
            cx.push(node).await;
        }
        if let Some(d) = problem {
            cx.diag(d.at(span));
        }
    }
    Ok(())
}

fn dirent_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("nid").emit()?;
    f.u16("Name offset").emit()?;
    f.u8("File type").enumeration(DIRENT_TYPES).emit()?;
    f.u8("Reserved").emit()?;
    Ok(())
}

/// Lists a directory's blocks with their structure.
async fn dir_blocks(cx: Cx, (fs, nid): (FsRef, u64)) -> Result<()> {
    let ino = Ino::read(&cx, &fs, nid).await?;
    let content = data(&cx, &fs, &ino, 0).await?;
    let len = content.len.min(MAX_DIR_BYTES);
    let blocks = len.div_ceil(fs.dir_block);
    cx.set_count(Count::Exact(blocks));
    for b in 0..blocks {
        let at = b.saturating_mul(fs.dir_block);
        let valid = fs.dir_block.min(len.saturating_sub(at));
        let span = content.sub(at, valid);
        cx.push(
            Node::new(format!("Block {b}"))
                .span(span)
                .summary(size(valid))
                .lazy(dir_block, span),
        )
        .await;
    }
    Ok(())
}

async fn dir_block(cx: Cx, span: Span) -> Result<()> {
    let block = cx.read(span).await?;
    let (entries, problem) = dirents(&block, span.len);
    let names_start = entries.first().map_or(0, |e| e.nameoff);
    for e in &entries {
        cx.emit(
            struct_node(
                String::from_utf8_lossy(&e.name).into_owned(),
                span.sub(e.off, 12),
                LE,
                (),
                dirent_layout,
            )
            .summary(format!(
                "{}, nid {}",
                lookup(DIRENT_TYPES, e.ftype.into()).unwrap_or("unknown"),
                e.nid
            )),
        );
    }
    if !entries.is_empty() {
        let names = span.sub(names_start, span.len.saturating_sub(names_start));
        let list: Vec<(Span, String)> = entries
            .iter()
            .map(|e| {
                (
                    span.sub(e.nameoff, e.name_end.saturating_sub(e.nameoff)),
                    String::from_utf8_lossy(&e.name).into_owned(),
                )
            })
            .collect();
        cx.emit(
            Node::new("Names")
                .span(names)
                .summary(format!("{} names", list.len()))
                .lazy(dir_names, Arc::new(list)),
        );
    }
    if let Some(d) = problem {
        cx.diag(d.at(span));
    }
    Ok(())
}

async fn dir_names(cx: Cx, list: Arc<Vec<(Span, String)>>) -> Result<()> {
    for (i, (span, name)) in list.iter().enumerate() {
        cx.push(
            Node::new(format!("Name {i}"))
                .span(*span)
                .value(Value::Text(name.clone())),
        )
        .await;
    }
    Ok(())
}
