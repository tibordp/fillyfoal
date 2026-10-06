//! F2FS (flash-friendly file system) superblock and its area layout.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{crc32_update, size, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u32 = 0xf2f5_2010;

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
];

record! {
    /// `struct f2fs_super_block` up to the feature flags.
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
        extensions: bytes[512] "Extension list",
        cp_payload: u32 "Checkpoint payload blocks",
        version: ascii[256] "Kernel version",
        init_version: ascii[256] "Initial kernel version",
        features: u32 "Features" .hex() .flags(FEATURES),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    let mut node = Superblock::node("Superblock", span, LE);
    if sb.features & 0x800 != 0 {
        let at = u64::from(sb.checksum_offset).min(3072);
        let raw = cx.read_avail(vol.sub(SUPER, at.saturating_add(4))).await?;
        let computed = crc32_update(MAGIC, raw.get(..crate::bytes::to_usize(at)).unwrap_or_default());
        if u32_le(&raw, crate::bytes::to_usize(at)) != Some(computed) {
            node = node.diag(Diagnostic::warning("superblock checksum mismatch"));
        }
    }
    cx.emit(node);
    let block = 1u64.checked_shl(sb.log_block_size).filter(|b| (512..=65536).contains(b)).ok_or_else(|| {
        Diagnostic::malformed(format!("block size 2^{}", sb.log_block_size)).at(span)
    })?;
    cx.annotate(format!(
        "F2FS {}.{} filesystem{}, {}, {}",
        sb.major,
        sb.minor,
        if sb.volume_name.is_empty() { String::new() } else { format!(" \"{}\"", sb.volume_name) },
        size(sb.block_count.saturating_mul(block)),
        sb.version.trim_end()
    ));
    cx.emit(Node::new("Backup superblock").span(vol.sub(block.saturating_add(SUPER), Superblock::SIZE)));
    let seg_blocks = 1u64.checked_shl(sb.log_blocks_per_segment).unwrap_or(0);
    for (name, start, segments) in [
        ("Checkpoint area", sb.cp_block, sb.segment_count_ckpt),
        ("Segment information table", sb.sit_block, sb.segment_count_sit),
        ("Node address table", sb.nat_block, sb.segment_count_nat),
        ("Segment summary area", sb.ssa_block, sb.segment_count_ssa),
        ("Main area", sb.main_block, sb.segment_count_main),
    ] {
        let area = vol.sub(
            u64::from(start).saturating_mul(block),
            u64::from(segments).saturating_mul(seg_blocks).saturating_mul(block),
        );
        cx.emit(
            Node::new(name)
                .span(area)
                .value(Value::UInt { value: start.into(), bits: 32, radix: crate::value::Radix::Dec })
                .summary(format!("{segments} segments")),
        );
    }
    Ok(())
}
