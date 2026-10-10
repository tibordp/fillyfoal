//! JFS (IBM Journaled File System) aggregates.
//!
//! The primary superblock is at 32 KiB, followed by the aggregate inode
//! map (two pages), the aggregate inode table (32 inodes of 512 bytes:
//! the aggregate itself, its block map, the inline log, bad blocks and the
//! fileset's inode table) and the secondary superblock at 60 KiB. Extents
//! are "pxd" descriptors: a 24-bit length and a 40-bit block address.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{size, text, unix_mode, uuid_value};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 0x8000;
const AIMAP: u64 = 0x9000;
const AITBL: u64 = 0xb000;
const SUPER2: u64 = 0xf000;
const INODE: u64 = 512;

pub static FORMAT: Format = Format {
    name: "jfs",
    title: "JFS filesystem",
    extensions: &["img", "jfs"],
    mime: "application/x-jfs",
    probe: Probe::Magic(&[(0x8000, b"JFS1")]),
    dissect: crate::expander!(dissect: Input),
};

const STATES: EnumTable = &[
    (0, "clean"),
    (1, "mounted"),
    (2, "dirty"),
    (4, "log redo"),
    (8, "extend"),
    (0x10, "resize"),
];
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

/// A `pxd_t`: (length in blocks, block address).
fn pxd(b: &[u8]) -> (u64, u64) {
    let w0 = u32_le(b, 0).unwrap_or(0);
    let w1 = u32_le(b, 4).unwrap_or(0);
    (
        u64::from(w0 & 0x00ff_ffff),
        u64::from(w0 >> 24) << 32 | u64::from(w1),
    )
}

#[allow(clippy::ptr_arg)] // used as a `Field::with` decorator
fn pxd_summary(b: &Vec<u8>, n: Node) -> Node {
    let (len, addr) = pxd(b);
    if len == 0 && addr == 0 {
        n.summary("none")
    } else {
        n.summary(format!("{len} blocks at block {addr}"))
    }
}

record! {
    /// `struct jfs_superblock`.
    pub struct Superblock {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        size: u64 "Size (physical blocks)",
        block_size: u32 "Block size",
        l2_block_size: u16 "Block size (log2)",
        l2_block_factor: u16 "Physical blocks per block (log2)",
        physical_block: u32 "Physical block size",
        l2_physical_block: u16 "Physical block size (log2)",
        _pad: u16 "Padding",
        ag_size: u32 "Allocation group size (blocks)",
        flags: u32 "Flags" .hex() .flags(FLAGS),
        state: u32 "State" .enumeration(STATES),
        compress: u32 "Compression",
        ait2: bytes[8] "Secondary aggregate inode table" .with(pxd_summary),
        aim2: bytes[8] "Secondary aggregate inode map" .with(pxd_summary),
        log_dev: u32 "Log device",
        log_serial: u32 "Log serial number",
        log_pxd: bytes[8] "Inline log" .with(pxd_summary),
        fsck_pxd: bytes[8] "fsck work space" .with(pxd_summary),
        time: u32 "Updated" .timestamp(),
        time_ns: u32 "Updated (ns)",
        fsck_log_len: u32 "fsck log length",
        fsck_log: u8 "fsck log index",
        pack: bytes[11] "Pack name" .with(|b, n| n.value(text(b))),
        extend_size: u64 "Extend size",
        extend_fsck: bytes[8] "Extend fsck work space" .with(pxd_summary),
        extend_log: bytes[8] "Extend log" .with(pxd_summary),
        uuid: bytes[16] "UUID" .with(uuid_value),
        label: bytes[16] "Label" .with(|b, n| n.value(text(b))),
        log_uuid: bytes[16] "Log UUID" .with(uuid_value),
    }
}

/// Names of the aggregate's reserved inodes.
const AGGREGATE_INODES: EnumTable = &[
    (1, "aggregate inode"),
    (2, "block allocation map"),
    (3, "inline log"),
    (4, "bad blocks"),
    (16, "fileset inode table"),
];

fn time_field(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.u32(name).timestamp().emit()?;
    f.u32("Nanoseconds").emit()?;
    Ok(())
}

fn dxd(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.bytes(name, 16)
        .with(|b, n| {
            let flag = b.first().copied().unwrap_or(0);
            let size = u32_le(b, 4).unwrap_or(0);
            if flag == 0 {
                n.summary("none")
            } else {
                n.summary(format!("flags {flag:#x}, {size} bytes"))
            }
        })
        .emit()?;
    Ok(())
}

/// The common part of a `struct dinode`, then its type-specific area.
fn dinode_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Inode stamp").hex().emit()?;
    f.u32("Fileset").emit()?;
    f.u32("Inode number").enumeration(AGGREGATE_INODES).emit()?;
    f.u32("Generation").emit()?;
    f.bytes("Inode extent", 8).with(pxd_summary).emit()?;
    f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Blocks").emit()?;
    f.u32("Links").emit()?;
    f.u32("Owner UID").emit()?;
    f.u32("Group GID").emit()?;
    f.u32("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m & 0xffff)))
        .desc("Unix mode in the low 16 bits; JFS flags above")
        .emit()?;
    time_field(f, "Accessed")?;
    time_field(f, "Changed")?;
    time_field(f, "Modified")?;
    time_field(f, "Created")?;
    dxd(f, "ACL")?;
    dxd(f, "Extended attributes")?;
    f.u32("Next directory index").emit()?;
    f.u32("ACL type").emit()?;
    let rest = f.remaining();
    if rest > 0 {
        f.node(
            Node::new("Type-specific area")
                .span(f.peek_span(rest))
                .summary("directory table and B+tree root, or extent tree root, or inline data"),
        );
        f.skip(rest);
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    cx.emit(
        Node::new("Reserved")
            .span(vol.sub(0, SUPER))
            .summary("32 KiB left for boot loaders and partition data"),
    );
    cx.emit(Superblock::node("Superblock", span, LE).summary(format!("version {}", sb.version)));
    cx.emit(
        Node::new("Unused")
            .span(vol.sub(
                SUPER.saturating_add(Superblock::SIZE),
                0x1000u64.saturating_sub(Superblock::SIZE),
            ))
            .summary("rest of the superblock page"),
    );
    cx.emit(
        Node::new("Aggregate inode map")
            .span(vol.sub(AIMAP, 0x2000))
            .summary("control page and first map page of the aggregate's inodes"),
    );
    cx.emit(
        Node::new("Aggregate inode table")
            .span(vol.sub(AITBL, 0x4000))
            .summary("32 inodes")
            .lazy(
                inode_table,
                (
                    vol,
                    vol.sub(AITBL, 0x4000),
                    u64::from(sb.block_size).max(512),
                ),
            ),
    );
    let s2 = vol.sub(SUPER2, Superblock::SIZE);
    if s2.len == Superblock::SIZE {
        cx.emit(Superblock::node("Secondary superblock", s2, LE));
    }
    let block = u64::from(sb.block_size).max(512);
    for (name, raw) in [
        ("Secondary aggregate inode table", &sb.ait2),
        ("Secondary aggregate inode map", &sb.aim2),
    ] {
        let (len, addr) = pxd(raw);
        if len > 0 {
            cx.emit(
                Node::new(name)
                    .span(vol.sub(addr.saturating_mul(block), len.saturating_mul(block)))
                    .summary(format!("{len} blocks at block {addr}")),
            );
        }
    }
    let (log_len, log_addr) = pxd(&sb.log_pxd);
    if log_len > 0 {
        let block = u64::from(sb.block_size);
        cx.emit(
            Node::new("Inline log")
                .span(vol.sub(
                    log_addr.saturating_mul(block),
                    log_len.saturating_mul(block),
                ))
                .summary(format!("{log_len} blocks at block {log_addr}")),
        );
    }
    let (fsck_len, fsck_addr) = pxd(&sb.fsck_pxd);
    if fsck_len > 0 {
        let block = u64::from(sb.block_size);
        cx.emit(
            Node::new("fsck work space")
                .span(vol.sub(
                    fsck_addr.saturating_mul(block),
                    fsck_len.saturating_mul(block),
                ))
                .summary(format!("{fsck_len} blocks at block {fsck_addr}")),
        );
    }
    let label = crate::text::until_nul(&sb.label);
    cx.annotate(format!(
        "JFS v{} filesystem{}, {}, {}-byte blocks",
        sb.version,
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(sb.size.saturating_mul(sb.physical_block.into())),
        sb.block_size
    ));
    Ok(())
}

async fn inode_table(
    cx: Cx,
    (vol, span, block): (crate::span::Span, crate::span::Span, u64),
) -> Result<()> {
    let data = cx.read_avail(span).await?;
    for i in 0..32u64 {
        let at = crate::bytes::to_usize(i.saturating_mul(INODE));
        let used = data
            .get(at..at.saturating_add(512))
            .is_some_and(|b| b.iter().any(|&x| x != 0));
        let name = crate::value::lookup(AGGREGATE_INODES, i)
            .map_or_else(|| format!("Inode {i}"), |n| format!("Inode {i} ({n})"));
        let ispan = span.sub(i.saturating_mul(INODE), INODE);
        cx.push(if used {
            let size = u64::from(u32_le(&data, at.saturating_add(24)).unwrap_or(0));
            struct_node(name, ispan, LE, (), dinode_layout)
                .summary(crate::formats::disk::size(size))
        } else {
            Node::new(name).span(ispan).summary("unused")
        })
        .await;
        if !used {
            continue;
        }
        // The extents of the inode's in-inode extent tree root (an xtpage
        // whose 32-byte header takes the first two of its 18 slots).
        let root = data
            .get(at.saturating_add(224)..at.saturating_add(512))
            .unwrap_or_default();
        let flag = root.get(16).copied().unwrap_or(0);
        let next = u64::from(crate::bytes::u16_le(root, 18).unwrap_or(0)).min(18);
        if flag & 0x02 == 0 {
            continue;
        }
        for k in 2..next {
            let e = root
                .get(
                    crate::bytes::to_usize(k.saturating_mul(16))
                        ..crate::bytes::to_usize(k.saturating_mul(16).saturating_add(16)),
                )
                .unwrap_or_default();
            let offset = u64::from(e.get(3).copied().unwrap_or(0)) << 32
                | u64::from(u32_le(e, 4).unwrap_or(0));
            let (len, addr) = pxd(e.get(8..16).unwrap_or_default());
            cx.push(
                Node::new(format!("Inode {i} extent {}", k.saturating_sub(2)))
                    .span(vol.sub(addr.saturating_mul(block), len.saturating_mul(block)))
                    .summary(format!("{len} blocks at block {addr}, file block {offset}")),
            )
            .await;
        }
    }
    Ok(())
}
