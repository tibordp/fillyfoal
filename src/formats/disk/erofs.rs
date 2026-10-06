//! EROFS (Enhanced Read-Only File System) superblock.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{crc32c_update, size, text, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 1024;
const MAGIC: u32 = 0xe0f5_e1e2;

pub static FORMAT: Format = Format {
    name: "erofs",
    title: "EROFS filesystem",
    extensions: &["img", "erofs"],
    mime: "application/x-erofs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 1024) == Some(MAGIC)
}

const COMPAT: FlagTable = &[flag(1, "SB_CHKSUM"), flag(2, "MTIME"), flag(4, "XATTR_FILTER")];
const INCOMPAT: FlagTable = &[
    flag(0x1, "ZERO_PADDING / LZ4_0PADDING"),
    flag(0x2, "COMPR_CFGS"),
    flag(0x4, "BIG_PCLUSTER"),
    flag(0x8, "CHUNKED_FILE"),
    flag(0x10, "DEVICE_TABLE"),
    flag(0x20, "ZTAILPACKING"),
    flag(0x40, "FRAGMENTS"),
    flag(0x80, "DEDUPE"),
    flag(0x100, "XATTR_PREFIXES"),
];

record! {
    /// `struct erofs_super_block` (first 128 bytes).
    pub struct Superblock {
        magic: u32 "Magic" .hex(),
        checksum: u32 "Checksum (CRC-32C)" .hex(),
        compat: u32 "Compatible features" .hex() .flags(COMPAT),
        block_bits: u8 "Block size (log2)",
        ext_slots: u8 "Superblock extension slots",
        root_nid: u16 "Root inode number",
        inodes: u64 "Inodes",
        build_time: u64 "Built" .timestamp(),
        build_time_ns: u32 "Built (ns)",
        blocks: u32 "Blocks",
        meta_block: u32 "Metadata area block",
        xattr_block: u32 "Shared xattr area block",
        uuid: bytes[16] "UUID" .with(uuid_value),
        volume_name: bytes[16] "Volume name" .with(|b, n| n.value(text(b))),
        incompat: u32 "Incompatible features" .hex() .flags(INCOMPAT),
        compression: u16 "Available compression algorithms / LZ4 max distance" .hex(),
        extra_devices: u16 "Extra devices",
        devt_slot: u16 "Device table slot",
        dir_block_bits: u8 "Directory block size (log2)",
        xattr_prefix_count: u8 "Xattr prefixes",
        xattr_prefix_start: u32 "Xattr prefix table",
        packed_nid: u64 "Packed inode",
        xattr_filter: u8 "Xattr filter reserved",
        _reserved: bytes[23] "Reserved",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    if !(9..=16).contains(&sb.block_bits) {
        return Err(Diagnostic::malformed(format!("block size 2^{}", sb.block_bits)).at(span));
    }
    let block = 1u64 << sb.block_bits;
    let mut node = Superblock::node("Superblock", span, LE);
    if sb.compat & 1 != 0 {
        // CRC-32C over the rest of the superblock block, checksum zeroed.
        let mut raw = cx.read_avail(vol.sub(SUPER, block.saturating_sub(SUPER).max(128))).await?;
        if let Some(f) = raw.get_mut(4..8) {
            f.fill(0);
        }
        if crc32c_update(!0, &raw) != sb.checksum {
            node = node.diag(Diagnostic::warning("superblock checksum mismatch"));
        }
    }
    cx.emit(node);
    let label = crate::text::until_nul(&sb.volume_name);
    cx.annotate(format!(
        "EROFS filesystem{}, {}, {} inodes",
        if label.is_empty() { String::new() } else { format!(" \"{label}\"") },
        size(u64::from(sb.blocks).saturating_mul(block)),
        sb.inodes
    ));
    let meta = vol.sub(u64::from(sb.meta_block).saturating_mul(block), 0);
    cx.emit(
        Node::new("Root inode")
            .span(vol.sub(meta.offset.saturating_sub(vol.offset).saturating_add(u64::from(sb.root_nid).saturating_mul(32)), 32))
            .summary(format!("nid {}", sb.root_nid)),
    );
    Ok(())
}
