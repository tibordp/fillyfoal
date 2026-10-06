//! JFS (IBM Journaled File System) superblock, at 32 KiB.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::disk::{size, text, uuid_value};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 0x8000;

pub static FORMAT: Format = Format {
    name: "jfs",
    title: "JFS filesystem",
    extensions: &["img", "jfs"],
    mime: "application/x-jfs",
    probe: Probe::Magic(&[(0x8000, b"JFS1")]),
    dissect: crate::expander!(dissect: Input),
};

const STATES: EnumTable = &[(0, "clean"), (1, "mounted"), (2, "dirty"), (4, "log redo"), (8, "extend"), (0x10, "resize")];
const FLAGS: FlagTable = &[
    flag(0x1, "COMMIT"),
    flag(0x2, "GROUPCOMMIT"),
    flag(0x4, "LAZYCOMMIT"),
    flag(0x100, "INLINELOG"),
    flag(0x200, "INLINEMOVE"),
    flag(0x400, "BAD_SAIT"),
    flag(0x800, "SPARSE"),
    flag(0x1000, "DASD_ENABLED"),
    flag(0x2000, "DASD_PRIME"),
    flag(0x4000_0000, "UNICODE"),
    flag(0x8000_0000, "OS2"),
    flag(0x1000_0000, "LINUX"),
];

record! {
    /// `struct jfs_superblock` (through the label).
    pub struct Superblock {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        size: u64 "Size (physical blocks)",
        block_size: u32 "Block size",
        l2_block_size: u16 "Block size (log2)",
        l2_block_factor: u16 "Blocks per physical block (log2)",
        physical_block: u32 "Physical block size",
        l2_physical_block: u16 "Physical block size (log2)",
        _pad: u16 "Padding",
        ag_size: u32 "Allocation group size (blocks)",
        flags: u32 "Flags" .hex() .flags(FLAGS),
        state: u32 "State" .enumeration(STATES),
        compress: u32 "Compression",
        ait2: bytes[8] "Secondary aggregate inode table",
        aim2: bytes[8] "Secondary aggregate inode map",
        log_dev: u32 "Log device",
        log_serial: u32 "Log serial number",
        log_pxd: bytes[8] "Inline log extent",
        fsck_pxd: bytes[8] "fsck work space extent",
        time: u32 "Updated" .timestamp(),
        time_ns: u32 "Updated (ns)",
        fsck_log_len: u32 "fsck log length",
        fsck_log: u8 "fsck log index",
        pack: bytes[11] "Pack name",
        extend_size: u64 "Extend size",
        extend_fsck: bytes[8] "Extend fsck extent",
        extend_log: bytes[8] "Extend log extent",
        uuid: bytes[16] "UUID" .with(uuid_value),
        label: bytes[16] "Label" .with(|b, n| n.value(text(b))),
        log_uuid: bytes[16] "Log UUID" .with(uuid_value),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    cx.emit(Node::new("Reserved").span(vol.sub(0, SUPER)));
    cx.emit(Superblock::node("Superblock", span, LE));
    cx.emit(Node::new("Secondary superblock").span(vol.sub(0xf000, Superblock::SIZE)));
    let label = crate::text::until_nul(&sb.label);
    cx.annotate(format!(
        "JFS v{} filesystem{}, {}, {}-byte blocks",
        sb.version,
        if label.is_empty() { String::new() } else { format!(" \"{label}\"") },
        size(sb.size.saturating_mul(sb.physical_block.into())),
        sb.block_size
    ));
    Ok(())
}
