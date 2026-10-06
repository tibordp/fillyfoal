//! NILFS2 (log-structured file system) superblock.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{crc32_update, size, text, unix_time, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u16 = 0x3434;

pub static FORMAT: Format = Format {
    name: "nilfs2",
    title: "NILFS2 filesystem",
    extensions: &["img", "nilfs"],
    mime: "application/x-nilfs2",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    // The magic is only two bytes: check the revision, size and block size.
    u16_le(h.data, 1024 + 6) == Some(MAGIC)
        && u32_le(h.data, 1024).is_some_and(|r| r <= 2)
        && u16_le(h.data, 1024 + 8).is_some_and(|b| (256..=1024).contains(&b))
        && u32_le(h.data, 1024 + 20).is_some_and(|l| l <= 6)
}

const STATES: FlagTable = &[flag(1, "VALID"), flag(2, "ERROR"), flag(4, "RESIZE")];

record! {
    /// `struct nilfs_super_block` (through the volume name).
    pub struct Superblock {
        rev_level: u32 "Revision",
        minor_rev: u16 "Minor revision",
        magic: u16 "Magic" .hex(),
        bytes: u16 "Superblock size",
        flags: u16 "Flags" .hex(),
        crc_seed: u32 "CRC seed" .hex(),
        sum: u32 "Checksum" .hex(),
        log_block_size: u32 "Block size (log2 - 10)",
        segments: u64 "Segments",
        dev_size: u64 "Device size" .with(|&v, n| n.summary(size(v))),
        first_data_block: u64 "First data block",
        blocks_per_segment: u32 "Blocks per segment",
        reserved_percent: u32 "Reserved segments (%)",
        last_cno: u64 "Last checkpoint number",
        last_pseg: u64 "Last partial segment",
        last_seq: u64 "Last sequence number",
        free_blocks: u64 "Free blocks",
        ctime: u64 "Created" .with(unix_time),
        mtime: u64 "Mounted" .with(unix_time),
        wtime: u64 "Written" .with(unix_time),
        mount_count: u16 "Mount count",
        max_mount_count: u16 "Maximum mount count",
        state: u16 "State" .hex() .flags(STATES),
        errors: u16 "On errors",
        last_check: u64 "Last checked" .with(unix_time),
        check_interval: u32 "Check interval",
        creator_os: u32 "Creator OS",
        def_resuid: u16 "Reserved blocks user",
        def_resgid: u16 "Reserved blocks group",
        first_ino: u32 "First inode",
        inode_size: u16 "Inode size",
        dat_entry_size: u16 "DAT entry size",
        checkpoint_size: u16 "Checkpoint size",
        segment_usage_size: u16 "Segment usage size",
        uuid: bytes[16] "UUID" .with(uuid_value),
        volume_name: bytes[80] "Volume name" .with(|b, n| n.value(text(b))),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    let mut node = Superblock::node("Superblock", vol.sub(SUPER, sb.bytes.into()), LE);
    // CRC-32 (seeded) over the superblock with the checksum field zeroed.
    let mut raw = cx.read_avail(vol.sub(SUPER, sb.bytes.into())).await?;
    if let Some(f) = raw.get_mut(16..20) {
        f.fill(0);
    }
    if crc32_update(sb.crc_seed, &raw) != sb.sum {
        node = node.diag(Diagnostic::warning("superblock checksum mismatch"));
    }
    cx.emit(node);
    let block = 1024u64.checked_shl(sb.log_block_size).unwrap_or(0);
    let label = crate::text::until_nul(&sb.volume_name);
    cx.annotate(format!(
        "NILFS2 filesystem{}, {}, {} segments of {} blocks, checkpoint {}",
        if label.is_empty() { String::new() } else { format!(" \"{label}\"") },
        size(sb.dev_size),
        sb.segments,
        sb.blocks_per_segment,
        sb.last_cno
    ));
    let last = vol.sub(sb.last_pseg.saturating_mul(block), block);
    cx.emit(Node::new("Latest partial segment").span(last).summary(format!("block {}", sb.last_pseg)));
    // The secondary superblock sits 4 KiB from the end, 4 KiB aligned.
    let second = (vol.len / 4096).saturating_sub(1).saturating_mul(4096);
    if second > SUPER {
        cx.emit(Node::new("Secondary superblock").span(vol.sub(second, sb.bytes.into())));
    }
    Ok(())
}
