//! F2FS (flash-friendly file system).
//!
//! Two superblock copies (blocks 0 and 1, at offset 1 KiB) describe the
//! areas: two checkpoint packs (the newer valid one is current), the
//! segment information table (SIT), the node address table (NAT, which
//! maps node ids to blocks, with recent changes journalled in the
//! checkpoint's summaries), the segment summary area (SSA) and the main
//! area of node and data blocks. Inodes are node blocks; file data is
//! addressed from the inode and from direct and indirect node blocks.
//! Directories are blocks of 214 hashed entry slots. Checksums (CRC-32,
//! raw) of the superblock, checkpoints and inodes are verified.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::DIRENT_TYPES;
use crate::formats::disk::{PieceList, content_node, crc32_update, size, unix_mode, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Radix, Value, flag, lookup};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u32 = 0xf2f5_2010;
const BLOCK: u64 = 4096;
const NAT_PER_BLOCK: u64 = 455;
const ADDRS_PER_BLOCK: u64 = 1018;
const ADDRS_PER_INODE: u64 = 923;
const NULL_ADDR: u32 = 0;
const NEW_ADDR: u32 = u32::MAX;
const MAX_DEPTH: usize = 64;
/// Blocks of one file mapped at most.
const MAX_FILE_BLOCKS: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "f2fs",
    title: "F2FS filesystem",
    extensions: &["img", "f2fs"],
    mime: "application/x-f2fs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 1024) == Some(MAGIC)
}

const FEATURES: FlagTable = &[
    flag(0x1, "ENCRYPT"),
    flag(0x2, "BLKZONED"),
    flag(0x4, "ATOMIC_WRITE"),
    flag(0x8, "EXTRA_ATTR"),
    flag(0x10, "PRJQUOTA"),
    flag(0x20, "INODE_CHKSUM"),
    flag(0x40, "FLEXIBLE_INLINE_XATTR"),
    flag(0x80, "QUOTA_INO"),
    flag(0x100, "INODE_CRTIME"),
    flag(0x200, "LOST_FOUND"),
    flag(0x400, "VERITY"),
    flag(0x800, "SB_CHKSUM"),
    flag(0x1000, "CASEFOLD"),
    flag(0x2000, "COMPRESSION"),
    flag(0x4000, "RO"),
    flag(0x8000, "DEVICE_ALIAS"),
];

const CP_FLAGS: FlagTable = &[
    flag(0x1, "UMOUNT"),
    flag(0x2, "ORPHAN_PRESENT"),
    flag(0x4, "COMPACT_SUM"),
    flag(0x8, "ERROR"),
    flag(0x10, "FSCK"),
    flag(0x20, "FASTBOOT"),
    flag(0x40, "CRC_RECOVERY"),
    flag(0x80, "NAT_BITS"),
    flag(0x100, "TRIMMED"),
    flag(0x200, "NOCRC_RECOVERY"),
    flag(0x400, "LARGE_NAT_BITMAP"),
    flag(0x800, "QUOTA_NEED_FSCK"),
    flag(0x1000, "DISABLED"),
    flag(0x2000, "DISABLED_QUICK"),
    flag(0x4000, "RESIZEFS"),
];

const INLINE_FLAGS: FlagTable = &[
    flag(0x01, "INLINE_XATTR"),
    flag(0x02, "INLINE_DATA"),
    flag(0x04, "INLINE_DENTRY"),
    flag(0x08, "DATA_EXIST"),
    flag(0x10, "INLINE_DOTS"),
    flag(0x20, "EXTRA_ATTR"),
    flag(0x40, "PIN_FILE"),
    flag(0x80, "COMPRESS_RELEASED"),
];

record! {
    /// `struct f2fs_super_block`.
    pub struct Superblock {
        magic: u32 "Magic" .hex(),
        major: u16 "Major version",
        minor: u16 "Minor version",
        log_sector_size: u32 "Sector size (log2)",
        log_sectors_per_block: u32 "Sectors per block (log2)",
        log_block_size: u32 "Block size (log2)",
        log_blocks_per_segment: u32 "Blocks per segment (log2)",
        segments_per_section: u32 "Segments per section",
        sections_per_zone: u32 "Sections per zone",
        checksum_offset: u32 "Checksum offset",
        block_count: u64 "Blocks",
        section_count: u32 "Sections",
        segment_count: u32 "Segments",
        segment_count_ckpt: u32 "Checkpoint segments",
        segment_count_sit: u32 "SIT segments",
        segment_count_nat: u32 "NAT segments",
        segment_count_ssa: u32 "SSA segments",
        segment_count_main: u32 "Main area segments",
        segment0: u32 "Segment 0 block",
        cp_block: u32 "Checkpoint block",
        sit_block: u32 "SIT block",
        nat_block: u32 "NAT block",
        ssa_block: u32 "SSA block",
        main_block: u32 "Main area block",
        root_ino: u32 "Root inode",
        node_ino: u32 "Node inode",
        meta_ino: u32 "Meta inode",
        uuid: bytes[16] "UUID" .with(uuid_value),
        volume_name: utf16[512] "Volume name",
        extension_count: u32 "Cold file extensions",
        extensions: bytes[512] "Extension list" .with(|b, n| n.value(Value::Text(extension_list(b)))),
        cp_payload: u32 "Checkpoint payload blocks",
        version: ascii[256] "Kernel version",
        init_version: ascii[256] "Initial kernel version",
        features: u32 "Features" .hex() .flags(FEATURES),
        encryption_level: u8 "Encryption level",
        encrypt_salt: bytes[16] "Encryption salt",
        devices: bytes[544] "Devices" .desc("Up to 8 devices of a multi-device filesystem: path and segment count"),
        quota_inodes: bytes[12] "Quota inodes",
        hot_ext_count: u8 "Hot file extensions",
        encoding: u16 "Filename encoding",
        encoding_flags: u16 "Encoding flags" .hex(),
        stop_reason: bytes[32] "Stop reasons",
        errors: bytes[16] "Errors",
        _reserved: bytes[258] "Reserved",
        crc: u32 "Checksum" .hex(),
    }
}

fn extension_list(b: &[u8]) -> String {
    b.chunks(8)
        .map(crate::text::until_nul)
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(", ")
}

/// Filesystem geometry and the current checkpoint.
#[derive(Debug)]
struct Fs {
    input: Input,
    vol: Span,
    log_blocks_per_seg: u32,
    nat_block: u64,
    /// The current checkpoint block.
    cp: Span,
    /// The NAT version bitmap (selects each NAT block's copy).
    nat_bitmap: Vec<u8>,
    /// Recent NAT entries journalled in the checkpoint: (nid, block).
    nat_journal: Vec<(u32, u32)>,
    extra_attr: bool,
    flexible_inline_xattr: bool,
    inode_csum_seed: Option<u32>,
}

type FsRef = Arc<Fs>;

impl Fs {
    fn block(&self, addr: u64) -> Span {
        self.vol.sub(addr.saturating_mul(BLOCK), BLOCK)
    }

    fn blocks_per_seg(&self) -> u64 {
        1u64.checked_shl(self.log_blocks_per_seg).unwrap_or(512)
    }

    /// The block holding node `nid`, from the NAT (journal first).
    async fn node_block(&self, cx: &Cx, nid: u32) -> Result<u64> {
        if let Some(&(_, b)) = self.nat_journal.iter().find(|(n, _)| *n == nid) {
            return Ok(b.into());
        }
        let nid = u64::from(nid);
        let block_off = nid / NAT_PER_BLOCK;
        let seg_off = block_off.checked_shr(self.log_blocks_per_seg).unwrap_or(0);
        let bps = self.blocks_per_seg();
        let mut addr = self
            .nat_block
            .saturating_add(seg_off.saturating_mul(bps).saturating_mul(2))
            .saturating_add(block_off & bps.saturating_sub(1));
        let byte = self
            .nat_bitmap
            .get(to_usize(block_off / 8))
            .copied()
            .unwrap_or(0);
        let bit = u32::try_from(7u64.saturating_sub(block_off % 8)).unwrap_or(0);
        if byte.checked_shr(bit).is_some_and(|b| b & 1 != 0) {
            addr = addr.saturating_add(bps);
        }
        let entry = self
            .block(addr)
            .sub((nid % NAT_PER_BLOCK).saturating_mul(9), 9);
        let raw = cx.read(entry).await?;
        Ok(u32_le(&raw, 5).unwrap_or(0).into())
    }
}

/// F2FS's CRC-32: the raw register, seeded.
fn f2fs_crc(seed: u32, parts: &[&[u8]]) -> u32 {
    parts.iter().fold(seed, |c, p| crc32_update(c, p))
}

fn cp_layout(f: &mut Fields<'_>, computed: &Option<u32>) -> Result<()> {
    f.u64("Checkpoint version").hex().emit()?;
    f.u64("User blocks").emit()?;
    f.u64("Valid blocks").emit()?;
    f.u32("Reserved segments").emit()?;
    f.u32("Overprovisioned segments").emit()?;
    f.u32("Free segments").emit()?;
    for name in ["Hot node segment", "Warm node segment", "Cold node segment"] {
        f.u32(name).emit()?;
    }
    f.bytes("Unused node segments", 20).emit()?;
    for name in ["Hot node offset", "Warm node offset", "Cold node offset"] {
        f.u16(name).emit()?;
    }
    f.bytes("Unused node offsets", 10).emit()?;
    for name in ["Hot data segment", "Warm data segment", "Cold data segment"] {
        f.u32(name).emit()?;
    }
    f.bytes("Unused data segments", 20).emit()?;
    for name in ["Hot data offset", "Warm data offset", "Cold data offset"] {
        f.u16(name).emit()?;
    }
    f.bytes("Unused data offsets", 10).emit()?;
    f.u32("Flags").hex().flags(CP_FLAGS).emit()?;
    f.u32("Pack blocks").emit()?;
    f.u32("Summary start")
        .desc("Block of the pack where the summaries start")
        .emit()?;
    f.u32("Valid nodes").emit()?;
    f.u32("Valid inodes").emit()?;
    f.u32("Next free node id").emit()?;
    let sit = f.u32("SIT bitmap bytes").emit()?;
    let nat = f.u32("NAT bitmap bytes").emit()?;
    let csum_at = f.u32("Checksum offset").emit()?;
    f.u64("Elapsed time (s)").emit()?;
    f.bytes("Allocation types", 16).emit()?;
    let bitmaps = u64::from(sit).saturating_add(nat.into()).min(f.remaining());
    if bitmaps > 0 {
        f.bytes("SIT and NAT version bitmaps", bitmaps).emit()?;
    }
    let csum_at = u64::from(csum_at);
    if csum_at > f.pos() && csum_at.saturating_add(4) <= f.block().span.len {
        let gap = csum_at.saturating_sub(f.pos());
        f.node(
            Node::new("Unused")
                .span(f.peek_span(gap))
                .summary(size(gap)),
        );
        f.skip(gap);
        f.u32("Checksum")
            .hex()
            .with(|&v, n| match computed {
                Some(c) if *c == v => n.summary("valid"),
                Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
                None => n,
            })
            .emit()?;
    }
    let rest = f.remaining();
    if rest > 0 {
        f.node(
            Node::new("Unused")
                .span(f.peek_span(rest))
                .summary(size(rest)),
        );
    }
    Ok(())
}

/// A checkpoint pack's block: (version, checksum ok, flags).
fn cp_info(raw: &[u8]) -> (u64, bool, Option<u32>) {
    let csum_at = to_usize(u32_le(raw, 164).unwrap_or(0).into());
    let computed = raw.get(..csum_at).map(|b| f2fs_crc(MAGIC, &[b]));
    let ok = computed.is_some() && computed == u32_le(raw, csum_at);
    (u64_le(raw, 0).unwrap_or(0), ok, computed)
}

/// The NAT journal: from a compact summary block or the hot data
/// summary's journal.
fn nat_journal(raw: &[u8], compact: bool) -> Vec<(u32, u32)> {
    let base: usize = if compact { 0 } else { 3584 };
    let n = usize::from(u16_le(raw, base).unwrap_or(0)).min(38);
    (0..n)
        .filter_map(|i| {
            let at = base.saturating_add(2).saturating_add(i.saturating_mul(13));
            Some((u32_le(raw, at)?, u32_le(raw, at.saturating_add(9))?))
        })
        .collect()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    cx.emit(
        Node::new("Boot area")
            .span(vol.sub(0, SUPER))
            .summary("1 KiB before the superblock"),
    );
    for (i, at) in [SUPER, BLOCK.saturating_add(SUPER)].into_iter().enumerate() {
        let copy = vol.sub(at, Superblock::SIZE);
        let mut node = Superblock::node(
            if i == 0 {
                "Superblock"
            } else {
                "Superblock (backup)"
            },
            copy,
            LE,
        );
        if sb.features & 0x800 != 0 {
            let csum_at = u64::from(sb.checksum_offset).min(3068);
            let raw = cx
                .read_avail(vol.sub(at, csum_at.saturating_add(4)))
                .await?;
            let computed = f2fs_crc(MAGIC, &[raw.get(..to_usize(csum_at)).unwrap_or_default()]);
            node = if u32_le(&raw, to_usize(csum_at)) == Some(computed) {
                node.summary("checksum valid")
            } else {
                node.diag(Diagnostic::warning(format!(
                    "superblock checksum mismatch: computed {computed:#010x}"
                )))
            };
        }
        cx.emit(node);
        if i == 1 {
            cx.emit(
                Node::new("Unused")
                    .span(vol.sub(BLOCK, SUPER))
                    .summary("1 KiB before the backup superblock"),
            );
        }
    }
    if sb.log_block_size != 12 {
        return Err(
            Diagnostic::unsupported(format!("block size 2^{}", sb.log_block_size)).at(span),
        );
    }
    cx.annotate(format!(
        "F2FS {}.{} filesystem{}, {}, {}",
        sb.major,
        sb.minor,
        if sb.volume_name.is_empty() {
            String::new()
        } else {
            format!(" \"{}\"", sb.volume_name)
        },
        size(sb.block_count.saturating_mul(BLOCK)),
        sb.version.trim_end()
    ));
    let log_bps = sb.log_blocks_per_segment.min(16);
    let bps = 1u64.checked_shl(log_bps).unwrap_or(512);
    // The checkpoint packs: the valid one with the higher version.
    let cp1 = u64::from(sb.cp_block);
    let cp2 = cp1.saturating_add(bps);
    let raw1 = cx
        .read_avail(vol.sub(cp1.saturating_mul(BLOCK), BLOCK))
        .await?;
    let raw2 = cx
        .read_avail(vol.sub(cp2.saturating_mul(BLOCK), BLOCK))
        .await?;
    let (v1, ok1, c1) = cp_info(&raw1);
    let (v2, ok2, c2) = cp_info(&raw2);
    let use2 = ok2 && (!ok1 || v2 > v1);
    let (cp_addr, cp_raw) = if use2 { (cp2, &raw2) } else { (cp1, &raw1) };
    let flags = u32_le(cp_raw, 132).unwrap_or(0);
    let sit_bytes = u64::from(u32_le(cp_raw, 156).unwrap_or(0));
    let nat_bytes = u64::from(u32_le(cp_raw, 160).unwrap_or(0));
    let nat_bitmap = if flags & 0x400 != 0 {
        cp_raw
            .get(196..196usize.saturating_add(to_usize(nat_bytes)))
            .unwrap_or_default()
            .to_vec()
    } else if sb.cp_payload > 0 {
        cp_raw
            .get(192..192usize.saturating_add(to_usize(nat_bytes)))
            .unwrap_or_default()
            .to_vec()
    } else {
        let at = 192usize.saturating_add(to_usize(sit_bytes));
        cp_raw
            .get(at..at.saturating_add(to_usize(nat_bytes)))
            .unwrap_or_default()
            .to_vec()
    };
    let start_sum = u64::from(u32_le(cp_raw, 140).unwrap_or(0));
    let compact = flags & 0x4 != 0;
    let sum_raw = cx
        .read_avail(vol.sub(
            cp_addr.saturating_add(start_sum).saturating_mul(BLOCK),
            BLOCK,
        ))
        .await?;
    let journal = nat_journal(&sum_raw, compact);
    let fs: FsRef = Arc::new(Fs {
        input,
        vol,
        log_blocks_per_seg: log_bps,
        nat_block: sb.nat_block.into(),
        cp: vol.sub(cp_addr.saturating_mul(BLOCK), BLOCK),
        nat_bitmap,
        nat_journal: journal,
        extra_attr: sb.features & 0x8 != 0,
        flexible_inline_xattr: sb.features & 0x40 != 0,
        inode_csum_seed: (sb.features & 0x20 != 0).then(|| f2fs_crc(u32::MAX, &[&sb.uuid])),
    });
    if cp1 > 2 {
        cx.emit(
            Node::new("Unused")
                .span(vol.sub(
                    BLOCK.saturating_mul(2),
                    cp1.saturating_sub(2).saturating_mul(BLOCK),
                ))
                .summary("from the superblocks to the first segment"),
        );
    }
    let mut packs = Node::new("Checkpoint area")
        .span(
            vol.sub(
                cp1.saturating_mul(BLOCK),
                u64::from(sb.segment_count_ckpt)
                    .saturating_mul(bps)
                    .saturating_mul(BLOCK),
            ),
        )
        .summary(format!(
            "pack {} is current (version {:#x})",
            if use2 { 2 } else { 1 },
            if use2 { v2 } else { v1 }
        ));
    if !ok1 && !ok2 {
        packs = packs.diag(Diagnostic::warning(
            "no checkpoint pack has a valid checksum",
        ));
    }
    cx.emit(packs.lazy(checkpoint_area, (fs.clone(), cp1, cp2, c1, c2, bps)));
    for (name, start, segments, what) in [
        (
            "Segment information table",
            sb.sit_block,
            sb.segment_count_sit,
            "valid block counts and bitmaps of each segment, in two copies",
        ),
        (
            "Node address table",
            sb.nat_block,
            sb.segment_count_nat,
            "node id → block, in two copies",
        ),
        (
            "Segment summary area",
            sb.ssa_block,
            sb.segment_count_ssa,
            "the owner of each block of each main area segment",
        ),
        (
            "Main area",
            sb.main_block,
            sb.segment_count_main,
            "node and data blocks",
        ),
    ] {
        let area = vol.sub(
            u64::from(start).saturating_mul(BLOCK),
            u64::from(segments)
                .saturating_mul(bps)
                .saturating_mul(BLOCK),
        );
        cx.emit(
            Node::new(name)
                .span(area)
                .summary(format!("block {start}, {segments} segments: {what}")),
        );
    }
    cx.emit(
        Node::new("NAT journal")
            .summary(format!("{} entries", fs.nat_journal.len()))
            .lazy(journal_view, fs.clone()),
    );
    cx.emit(
        Node::new("Root directory")
            .summary(format!("inode {}", sb.root_ino))
            .lazy(
                crate::expander!(self::directory: DirState),
                DirState {
                    fs: fs.clone(),
                    ino: sb.root_ino,
                    path: Path::new(),
                },
            ),
    );
    Ok(())
}

async fn checkpoint_area(
    cx: Cx,
    (fs, cp1, cp2, c1, c2, bps): (FsRef, u64, u64, Option<u32>, Option<u32>, u64),
) -> Result<()> {
    for (i, (addr, computed)) in [(cp1, c1), (cp2, c2)].into_iter().enumerate() {
        let span = fs.block(addr);
        let raw = cx.read_avail(span).await?;
        let total = u64::from(u32_le(&raw, 136).unwrap_or(0));
        let current = span == fs.cp;
        cx.emit(
            struct_node(
                format!("Pack {} checkpoint", i.saturating_add(1)),
                span,
                LE,
                computed,
                cp_layout,
            )
            .summary(format!(
                "version {:#x}, {total} blocks{}",
                u64_le(&raw, 0).unwrap_or(0),
                if current { ", current" } else { "" }
            )),
        );
        if total > 2 {
            cx.emit(
                Node::new(format!(
                    "Pack {} payload and summaries",
                    i.saturating_add(1)
                ))
                .span(fs.vol.sub(
                    addr.saturating_add(1).saturating_mul(BLOCK),
                    total.saturating_sub(2).saturating_mul(BLOCK),
                ))
                .summary(format!("{} blocks", total.saturating_sub(2))),
            );
        }
        if total >= 2 {
            let last = fs.block(addr.saturating_add(total).saturating_sub(1));
            cx.emit(
                struct_node(
                    format!("Pack {} checkpoint (copy)", i.saturating_add(1)),
                    last,
                    LE,
                    computed,
                    cp_layout,
                )
                .summary("closes the pack"),
            );
        }
        if bps > total {
            cx.emit(
                Node::new(format!("Pack {} unused", i.saturating_add(1)))
                    .span(fs.vol.sub(
                        addr.saturating_add(total).saturating_mul(BLOCK),
                        bps.saturating_sub(total).saturating_mul(BLOCK),
                    ))
                    .summary("rest of the pack's segment"),
            );
        }
    }
    Ok(())
}

async fn journal_view(cx: Cx, fs: FsRef) -> Result<()> {
    for &(nid, block) in &fs.nat_journal {
        cx.push(
            Node::new(format!("Node {nid}"))
                .value(Value::UInt {
                    value: block.into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .summary(format!("block {block}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Inodes

struct Inode {
    ino: u32,
    span: Span,
    raw: Vec<u8>,
}

impl Inode {
    async fn read(cx: &Cx, fs: &Fs, ino: u32) -> Result<Inode> {
        let addr = fs.node_block(cx, ino).await?;
        if addr == 0 {
            return Err(Diagnostic::malformed(format!("node {ino} has no block")));
        }
        let span = fs.block(addr);
        let raw = cx.read(span).await?;
        if u32_le(&raw, 4076) != Some(ino) {
            return Err(Diagnostic::malformed(format!("block {addr} is not inode {ino}")).at(span));
        }
        Ok(Inode { ino, span, raw })
    }

    fn mode(&self) -> u16 {
        u16_le(&self.raw, 0).unwrap_or(0)
    }

    fn size(&self) -> u64 {
        u64_le(&self.raw, 16).unwrap_or(0)
    }

    fn inline(&self) -> u8 {
        self.raw.get(3).copied().unwrap_or(0)
    }

    fn extra_isize(&self, fs: &Fs) -> u64 {
        if fs.extra_attr && self.inline() & 0x20 != 0 {
            u64::from(u16_le(&self.raw, 360).unwrap_or(0))
        } else {
            0
        }
    }

    /// 4-byte words of inline xattrs at the end of the address area.
    fn inline_xattr_words(&self, fs: &Fs) -> u64 {
        if self.inline() & 0x01 == 0 {
            0
        } else if fs.flexible_inline_xattr && self.extra_isize(fs) >= 4 {
            u64::from(u16_le(&self.raw, 362).unwrap_or(0))
        } else {
            50
        }
    }

    /// The data addresses in the inode: (first word index, count).
    fn addrs(&self, fs: &Fs) -> (u64, u64) {
        let first = self.extra_isize(fs) / 4;
        let n = ADDRS_PER_INODE
            .saturating_sub(first)
            .saturating_sub(self.inline_xattr_words(fs));
        (first, n)
    }

    fn checksum(&self, fs: &Fs) -> Option<u32> {
        let seed = fs.inode_csum_seed?;
        if self.extra_isize(fs) < 12 {
            return None;
        }
        let generation = self.raw.get(68..72)?;
        let s = f2fs_crc(seed, &[&self.ino.to_le_bytes(), generation]);
        Some(f2fs_crc(
            s,
            &[self.raw.get(..368)?, &[0; 4], self.raw.get(372..)?],
        ))
    }

    fn summary(&self) -> String {
        format!("{}, {}", unix_mode(self.mode().into()), size(self.size()))
    }
}

#[derive(Clone, Copy, Debug)]
struct InodeCtx {
    extra: u64,
    csum: Option<u32>,
}

fn inode_layout(f: &mut Fields<'_>, ctx: &InodeCtx) -> Result<()> {
    f.u16("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    f.u8("Advice").hex().emit()?;
    f.u8("Inline flags").hex().flags(INLINE_FLAGS).emit()?;
    f.u32("Owner UID").emit()?;
    f.u32("Group GID").emit()?;
    f.u32("Links").emit()?;
    f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Blocks").desc("In 512-byte units").emit()?;
    f.u64("Accessed").timestamp().emit()?;
    f.u64("Changed").timestamp().emit()?;
    f.u64("Modified").timestamp().emit()?;
    f.u32("Accessed (ns)").emit()?;
    f.u32("Changed (ns)").emit()?;
    f.u32("Modified (ns)").emit()?;
    f.u32("Generation").emit()?;
    f.u32("Directory depth").emit()?;
    f.u32("Xattr node").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u32("Parent inode").emit()?;
    let n = f.u32("Name length").emit()?;
    let span = f.peek_span(255);
    let raw = {
        let data: &[u8] = &f.block().data;
        let at = to_usize(f.pos());
        data.get(at..at.saturating_add(to_usize(u64::from(n).min(255))))
            .unwrap_or_default()
            .to_vec()
    };
    f.node(
        Node::new("Name")
            .span(span)
            .value(Value::Text(String::from_utf8_lossy(&raw).into_owned()))
            .desc("The file's name when it was created (for recovery)"),
    );
    f.skip(255);
    f.u8("Directory level").emit()?;
    f.u32("Largest extent: file offset").emit()?;
    f.u32("Largest extent: block").emit()?;
    f.u32("Largest extent: length").emit()?;
    if ctx.extra >= 4 {
        f.u16("Extra size").emit()?;
        f.u16("Inline xattr words").emit()?;
    }
    if ctx.extra >= 8 {
        f.u32("Project ID").emit()?;
    }
    if ctx.extra >= 12 {
        f.u32("Inode checksum")
            .hex()
            .with(|&v, n| match ctx.csum {
                Some(c) if c == v => n.summary("valid"),
                Some(c) => n.diag(Diagnostic::warning(format!("mismatch: computed {c:#010x}"))),
                None => n,
            })
            .emit()?;
    }
    if ctx.extra >= 24 {
        f.u64("Created").timestamp().emit()?;
        f.u32("Created (ns)").emit()?;
    }
    if ctx.extra >= 36 {
        f.u64("Compressed blocks").emit()?;
        f.u8("Compression algorithm").emit()?;
        f.u8("log2(cluster size)").emit()?;
        f.u16("Compression flags").hex().emit()?;
    }
    let addr_start = 360u64.saturating_add(ctx.extra);
    f.seek(addr_start);
    let words = 4052u64.saturating_sub(addr_start) / 4;
    f.node(
        Node::new("Addresses")
            .span(f.peek_span(words.saturating_mul(4)))
            .summary(format!(
                "{words} words: data block addresses, inline data or xattrs"
            ))
            .lazy(addr_list, f.peek_span(words.saturating_mul(4))),
    );
    f.seek(4052);
    for name in [
        "Direct node 1",
        "Direct node 2",
        "Indirect node 1",
        "Indirect node 2",
        "Double indirect node",
    ] {
        f.u32(name)
            .with(|&v, n| if v == 0 { n.summary("none") } else { n })
            .emit()?;
    }
    footer(f)?;
    Ok(())
}

fn footer(f: &mut Fields<'_>) -> Result<()> {
    f.seek(4072);
    f.u32("Footer: node id").emit()?;
    f.u32("Footer: inode").emit()?;
    f.u32("Footer: flags").hex().emit()?;
    f.u64("Footer: checkpoint version").hex().emit()?;
    f.u32("Footer: next block").emit()?;
    Ok(())
}

async fn addr_list(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut zeros: Option<usize> = None;
    for (i, w) in data.as_chunks::<4>().0.iter().enumerate() {
        let v = u32::from_le_bytes(*w);
        if v == NULL_ADDR {
            zeros.get_or_insert(i);
            continue;
        }
        if let Some(from) = zeros.take() {
            cx.push(
                Node::new(format!("Words {from}–{}", i.saturating_sub(1)))
                    .span(span.sub(
                        to_u64(from).saturating_mul(4),
                        to_u64(i.saturating_sub(from)).saturating_mul(4),
                    ))
                    .summary("zero"),
            )
            .await;
        }
        cx.push(
            Node::new(format!("Word {i}"))
                .span(span.sub(to_u64(i).saturating_mul(4), 4))
                .value(Value::UInt {
                    value: v.into(),
                    bits: 32,
                    radix: Radix::Dec,
                })
                .summary(if v == NEW_ADDR {
                    "allocated, not written".to_owned()
                } else {
                    format!("block {v}")
                }),
        )
        .await;
    }
    if let Some(from) = zeros {
        cx.push(
            Node::new(format!(
                "Words {from}–{}",
                (data.len() / 4).saturating_sub(1)
            ))
            .span(
                span.sub(
                    to_u64(from).saturating_mul(4),
                    to_u64(data.len() / 4)
                        .saturating_sub(to_u64(from))
                        .saturating_mul(4),
                ),
            )
            .summary("zero"),
        )
        .await;
    }
    Ok(())
}

fn inode_node(fs: &Fs, inode: &Inode, name: String) -> Node {
    let mut node = struct_node(
        name,
        inode.span,
        LE,
        InodeCtx {
            extra: inode.extra_isize(fs),
            csum: inode.checksum(fs),
        },
        inode_layout,
    )
    .summary(inode.summary());
    if let (Some(c), Some(stored)) = (inode.checksum(fs), u32_le(&inode.raw, 368))
        && c != stored
    {
        node = node.diag(Diagnostic::warning("inode checksum mismatch"));
    }
    node
}

/// The data blocks of an inode in file order (0 for holes).
async fn data_blocks(cx: &Cx, fs: &Fs, inode: &Inode, count: u64) -> Result<Vec<u32>> {
    let (first, n) = inode.addrs(fs);
    let mut out: Vec<u32> = Vec::new();
    let word = |raw: &[u8], i: u64| u32_le(raw, to_usize(i.saturating_mul(4))).unwrap_or(0);
    for i in 0..n.min(count) {
        out.push(word(
            &inode.raw,
            90u64.saturating_add(first).saturating_add(i),
        ));
    }
    // Then direct, indirect and double indirect node blocks.
    let nids: Vec<u32> = (0..5u64)
        .map(|k| word(&inode.raw, 1013u64.saturating_add(k)))
        .collect();
    let mut stack: Vec<(u32, u32)> = Vec::new();
    for (k, nid) in nids.iter().enumerate().rev() {
        let level = match k {
            0 | 1 => 0,
            2 | 3 => 1,
            _ => 2,
        };
        stack.push((*nid, level));
    }
    let mut visited = 0u64;
    while let Some((nid, level)) = stack.pop() {
        if to_u64(out.len()) >= count.min(MAX_FILE_BLOCKS) {
            break;
        }
        cx.checkpoint().await;
        visited = visited.saturating_add(1);
        if visited > 1 << 16 {
            return Err(Diagnostic::limit("too many node blocks"));
        }
        if nid == 0 {
            // A missing node: holes for everything it would map.
            let span = ADDRS_PER_BLOCK.saturating_pow(level.saturating_add(1));
            let n = span.min(count.saturating_sub(to_u64(out.len())));
            out.resize(out.len().saturating_add(to_usize(n)), NULL_ADDR);
            continue;
        }
        let addr = fs.node_block(cx, nid).await?;
        let raw = cx.read(fs.block(addr)).await?;
        if level == 0 {
            for i in 0..ADDRS_PER_BLOCK {
                if to_u64(out.len()) >= count {
                    break;
                }
                out.push(word(&raw, i));
            }
        } else {
            for i in (0..ADDRS_PER_BLOCK).rev() {
                stack.push((word(&raw, i), level.saturating_sub(1)));
            }
        }
    }
    Ok(out)
}

/// An inode's content: inline, or its data blocks (holes as zeros).
async fn content(cx: &Cx, fs: &Fs, inode: &Inode) -> Result<Span> {
    let size = inode.size();
    let (first, n) = inode.addrs(fs);
    if inode.inline() & 0x02 != 0 {
        // Inline data starts after one reserved word.
        let at = 360u64.saturating_add(first.saturating_add(1).saturating_mul(4));
        return Ok(inode
            .span
            .sub(at, size.min(n.saturating_sub(1).saturating_mul(4))));
    }
    let count = size.div_ceil(BLOCK);
    let blocks = data_blocks(cx, fs, inode, count).await?;
    let mut list = PieceList::new(inode.span);
    for (i, addr) in blocks.iter().enumerate() {
        let len = BLOCK.min(size.saturating_sub(to_u64(i).saturating_mul(BLOCK)));
        if *addr == NULL_ADDR || *addr == NEW_ADDR {
            list.hole(cx, len)?;
        } else {
            list.data(fs.block((*addr).into()).sub(0, len));
        }
    }
    if list.len() < size {
        list.hole(cx, size.saturating_sub(list.len()))?;
    }
    list.finish(cx, "f2fs-data").await
}

// ---------------------------------------------------------------------------
// Directories

#[derive(Clone)]
struct DirState {
    fs: FsRef,
    ino: u32,
    path: Path,
}

struct Dentry {
    slot: u64,
    ino: u32,
    file_type: u8,
    name: Vec<u8>,
}

/// The entries of a dentry area: `n` slots, the bitmap at `bitmap`, the
/// entries at `entries` and names at `names` (offsets in `data`).
fn dentries(data: &[u8], n: u64, bitmap: u64, entries: u64, names: u64) -> Vec<Dentry> {
    let mut out = Vec::new();
    let mut i = 0u64;
    while i < n {
        let byte = data
            .get(to_usize(bitmap.saturating_add(i / 8)))
            .copied()
            .unwrap_or(0);
        if byte
            .checked_shr(u32::try_from(i % 8).unwrap_or(0))
            .is_none_or(|b| b & 1 == 0)
        {
            i = i.saturating_add(1);
            continue;
        }
        let at = to_usize(entries.saturating_add(i.saturating_mul(11)));
        let name_len = u64::from(u16_le(data, at.saturating_add(8)).unwrap_or(0));
        let slots = name_len.div_ceil(8).max(1);
        let name_at = to_usize(names.saturating_add(i.saturating_mul(8)));
        out.push(Dentry {
            slot: i,
            ino: u32_le(data, at.saturating_add(4)).unwrap_or(0),
            file_type: data.get(at.saturating_add(10)).copied().unwrap_or(0),
            name: data
                .get(name_at..name_at.saturating_add(to_usize(name_len)))
                .unwrap_or_default()
                .to_vec(),
        });
        i = i.saturating_add(slots);
    }
    out
}

async fn directory(cx: Cx, st: DirState) -> Result<()> {
    let fs = st.fs.clone();
    let inode = Inode::read(&cx, &fs, st.ino).await?;
    if inode.mode() & 0xf000 != 0x4000 {
        return Err(Diagnostic::malformed(format!(
            "inode {} is not a directory",
            st.ino
        )));
    }
    cx.emit(inode_node(&fs, &inode, format!("Inode {}", st.ino)));
    let mut all: Vec<(Dentry, Span)> = Vec::new();
    if inode.inline() & 0x04 != 0 {
        let (first, n) = inode.addrs(&fs);
        let bytes = n.saturating_sub(1).saturating_mul(4);
        let area_at = 360u64.saturating_add(first.saturating_add(1).saturating_mul(4));
        let area = inode.span.sub(area_at, bytes);
        let slots = bytes.saturating_mul(8) / ((11 + 8) * 8 + 1);
        let bitmap_len = slots.div_ceil(8);
        let reserved = bytes.saturating_sub(slots.saturating_mul(19).saturating_add(bitmap_len));
        let data = cx.read_avail(area).await?;
        let entries = bitmap_len.saturating_add(reserved);
        let names = entries.saturating_add(slots.saturating_mul(11));
        for d in dentries(&data, slots, 0, entries, names) {
            let span = area.sub(entries.saturating_add(d.slot.saturating_mul(11)), 11);
            all.push((d, span));
        }
    } else {
        let data = content(&cx, &fs, &inode).await?;
        let blocks = data.len.div_ceil(BLOCK);
        for b in 0..blocks {
            let span = data.sub(b.saturating_mul(BLOCK), BLOCK);
            let raw = cx.read_avail(span).await?;
            for d in dentries(&raw, 214, 0, 30, 30 + 214 * 11) {
                let espan = span.sub(30u64.saturating_add(d.slot.saturating_mul(11)), 11);
                all.push((d, espan));
            }
        }
    }
    for (d, span) in all {
        if d.name == b"." || d.name == b".." {
            continue;
        }
        let what = lookup(DIRENT_TYPES, d.file_type.into()).unwrap_or("unknown");
        let node = Node::new(String::from_utf8_lossy(&d.name).into_owned())
            .span(span)
            .value(Value::UInt {
                value: d.ino.into(),
                bits: 32,
                radix: Radix::Dec,
            })
            .summary(format!("{what}, inode {}", d.ino));
        let node = if d.file_type == 2 {
            match st.path.enter(d.ino.into(), MAX_DEPTH) {
                Ok(path) => node.lazy(
                    crate::expander!(self::directory: DirState),
                    DirState {
                        fs: fs.clone(),
                        ino: d.ino,
                        path,
                    },
                ),
                Err(e) => node.diag(e),
            }
        } else {
            node.lazy(view, (fs.clone(), d.ino))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn view(cx: Cx, (fs, ino): (FsRef, u32)) -> Result<()> {
    let inode = Inode::read(&cx, &fs, ino).await?;
    cx.annotate(inode.summary());
    cx.emit(inode_node(&fs, &inode, format!("Inode {ino}")));
    let kind = inode.mode() & 0xf000;
    if matches!(kind, 0x8000 | 0xa000) {
        let data = content(&cx, &fs, &inode).await?;
        if kind == 0xa000 {
            let text = cx.read_avail(data.sub(0, 4096)).await?;
            cx.emit(
                Node::new("Target")
                    .span(data)
                    .value(Value::Text(String::from_utf8_lossy(&text).into_owned())),
            );
        } else {
            cx.emit(content_node(&fs.input, data));
        }
    }
    Ok(())
}
