//! Btrfs filesystems: the superblock at 64 KiB (and its mirrors), the
//! bootstrap chunk array and the headers of the trees it points at.
//!
//! The superblock lies beyond what probes see (`HEAD_LEN`), so the probe
//! accepts inputs whose visible start is entirely zero (as Btrfs leaves it)
//! and the dissector checks the magic.

use crate::bytes::{to_u64, u16_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{crc32c, size, text, uuid_value};
use crate::formats::{Format, HEAD_LEN, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 0x10000;
const MAGIC: &[u8] = b"_BHRfS_M";
/// Mirror copies at 64 MiB and 256 GiB.
const MIRRORS: [u64; 2] = [0x400_0000, 0x40_0000_0000];

pub static FORMAT: Format = Format {
    name: "btrfs",
    title: "Btrfs filesystem",
    extensions: &["img", "btrfs"],
    mime: "application/x-btrfs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let magic_at = crate::bytes::to_usize(SUPER.saturating_add(0x40));
    if h.at(magic_at, MAGIC) {
        return true;
    }
    // The magic is beyond the probe window: accept an all-zero window.
    h.len >= SUPER.saturating_add(0x1000)
        && to_u64(h.data.len()) >= HEAD_LEN.min(SUPER)
        && h.data.iter().all(|&b| b == 0)
}

const INCOMPAT: FlagTable = &[
    flag(0x1, "MIXED_BACKREF"),
    flag(0x2, "DEFAULT_SUBVOL"),
    flag(0x4, "MIXED_GROUPS"),
    flag(0x8, "COMPRESS_LZO"),
    flag(0x10, "COMPRESS_ZSTD"),
    flag(0x20, "BIG_METADATA"),
    flag(0x40, "EXTENDED_IREF"),
    flag(0x80, "RAID56"),
    flag(0x100, "SKINNY_METADATA"),
    flag(0x200, "NO_HOLES"),
    flag(0x400, "METADATA_UUID"),
    flag(0x800, "RAID1C34"),
    flag(0x1000, "ZONED"),
    flag(0x2000, "EXTENT_TREE_V2"),
    flag(0x4000, "RAID_STRIPE_TREE"),
    flag(0x10000, "SIMPLE_QUOTA"),
];

const COMPAT_RO: FlagTable = &[
    flag(0x1, "FREE_SPACE_TREE"),
    flag(0x2, "FREE_SPACE_TREE_VALID"),
    flag(0x4, "VERITY"),
    flag(0x8, "BLOCK_GROUP_TREE"),
];

const CSUM: EnumTable = &[(0, "CRC32C"), (1, "xxHash64"), (2, "SHA-256"), (3, "BLAKE2b")];

const CHUNK_TYPE: FlagTable = &[
    flag(0x1, "DATA"),
    flag(0x2, "SYSTEM"),
    flag(0x4, "METADATA"),
    flag(0x8, "RAID0"),
    flag(0x10, "RAID1"),
    flag(0x20, "DUP"),
    flag(0x40, "RAID10"),
    flag(0x80, "RAID5"),
    flag(0x100, "RAID6"),
    flag(0x200, "RAID1C3"),
    flag(0x400, "RAID1C4"),
];

record! {
    /// `struct btrfs_super_block`, up to the bootstrap chunk array.
    pub struct Superblock {
        csum: bytes[32] "Checksum",
        fsid: bytes[16] "Filesystem UUID" .with(uuid_value),
        bytenr: u64 "This copy's offset" .hex(),
        flags: u64 "Flags" .hex(),
        magic: ascii[8] "Magic",
        generation: u64 "Generation",
        root: u64 "Root tree root (logical)" .hex(),
        chunk_root: u64 "Chunk tree root (logical)" .hex(),
        log_root: u64 "Log tree root (logical)" .hex(),
        log_root_transid: u64 "Log root transaction id",
        total_bytes: u64 "Total bytes" .with(|&v, n| n.summary(size(v))),
        bytes_used: u64 "Bytes used" .with(|&v, n| n.summary(size(v))),
        root_dir: u64 "Root directory object id",
        num_devices: u64 "Devices",
        sector_size: u32 "Sector size",
        node_size: u32 "Node size",
        leaf_size: u32 "Leaf size (unused)",
        stripe_size: u32 "Stripe size",
        sys_chunk_array_size: u32 "Bootstrap chunk array size",
        chunk_root_generation: u64 "Chunk root generation",
        compat: u64 "Compatible features" .hex(),
        compat_ro: u64 "Read-only compatible features" .hex() .flags(COMPAT_RO),
        incompat: u64 "Incompatible features" .hex() .flags(INCOMPAT),
        csum_type: u16 "Checksum type" .enumeration(CSUM),
        root_level: u8 "Root tree level",
        chunk_root_level: u8 "Chunk tree level",
        log_root_level: u8 "Log tree level",
        dev_id: u64 "Device id",
        dev_total: u64 "Device size" .with(|&v, n| n.summary(size(v))),
        dev_used: u64 "Device bytes used" .with(|&v, n| n.summary(size(v))),
        dev_io_align: u32 "Device I/O alignment",
        dev_io_width: u32 "Device I/O width",
        dev_sector: u32 "Device sector size",
        dev_type: u64 "Device type",
        dev_generation: u64 "Device generation",
        dev_start: u64 "Device start offset",
        dev_group: u32 "Device group",
        dev_seek: u8 "Device seek speed",
        dev_bandwidth: u8 "Device bandwidth",
        dev_uuid: bytes[16] "Device UUID" .with(uuid_value),
        dev_fsid: bytes[16] "Device filesystem UUID" .with(uuid_value),
        label: bytes[256] "Label" .with(|b, n| n.value(text(b))),
        cache_generation: u64 "Free space cache generation",
        uuid_tree_generation: u64 "UUID tree generation",
        metadata_uuid: bytes[16] "Metadata UUID" .with(uuid_value),
    }
}

record! {
    /// `struct btrfs_header`, at the start of every tree node.
    pub struct NodeHeader {
        csum: bytes[32] "Checksum",
        fsid: bytes[16] "Filesystem UUID" .with(uuid_value),
        bytenr: u64 "Logical address" .hex(),
        flags: u64 "Flags" .hex(),
        chunk_tree_uuid: bytes[16] "Chunk tree UUID" .with(uuid_value),
        generation: u64 "Generation",
        owner: u64 "Owner tree" .enumeration(TREES),
        items: u32 "Items",
        level: u8 "Level",
    }
}

const TREES: EnumTable = &[
    (1, "root tree"),
    (2, "extent tree"),
    (3, "chunk tree"),
    (4, "device tree"),
    (5, "filesystem tree"),
    (6, "root directory tree"),
    (7, "checksum tree"),
    (8, "quota tree"),
    (9, "UUID tree"),
    (10, "free space tree"),
    (11, "block group tree"),
    (12, "raid stripe tree"),
];

/// A chunk from the bootstrap array: logical range → first stripe.
#[derive(Clone, Copy, Debug)]
struct Chunk {
    logical: u64,
    length: u64,
    physical: u64,
}

fn parse_chunks(array: &[u8]) -> Vec<(u64, usize, Chunk, u64)> {
    // (key offset, item position, chunk, type)
    let mut out = Vec::new();
    let mut at = 0usize;
    while at.saturating_add(17 + 48) <= array.len() {
        let logical = u64_le(array, at.saturating_add(9)).unwrap_or(0);
        let item = at.saturating_add(17);
        let length = u64_le(array, item).unwrap_or(0);
        let kind = u64_le(array, item.saturating_add(24)).unwrap_or(0);
        let stripes = usize::from(u16_le(array, item.saturating_add(44)).unwrap_or(0));
        let physical = u64_le(array, item.saturating_add(48 + 8)).unwrap_or(0);
        out.push((logical, at, Chunk { logical, length, physical }, kind));
        at = item.saturating_add(48).saturating_add(stripes.saturating_mul(32));
        if stripes == 0 {
            break;
        }
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let magic = cx.read_avail(vol.sub(SUPER.saturating_add(0x40), 8)).await?;
    if magic != MAGIC {
        let reiser = cx.read_avail(vol.sub(SUPER.saturating_add(0x34), 10)).await?;
        if reiser.starts_with(b"ReIsEr") {
            cx.annotate("ReiserFS filesystem");
            return Err(Diagnostic::unsupported("ReiserFS").at(vol.sub(SUPER, 0x100)));
        }
        return Err(Diagnostic::unsupported(
            "no Btrfs superblock at 64 KiB (the first 36 KiB are empty)",
        )
        .at(vol.sub(0, SUPER)));
    }
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    let full = vol.sub(SUPER, 0x1000);
    let mut node = Superblock::node("Superblock", full, LE).summary(format!("generation {}", sb.generation));
    if sb.csum_type == 0 {
        let data = cx.read_avail(full).await?;
        let computed = crc32c(data.get(32..).unwrap_or_default());
        if sb.csum.get(..4) != Some(&computed.to_le_bytes()[..]) {
            node = node.diag(Diagnostic::warning(format!("checksum mismatch: computed {computed:#010x}")));
        }
    }
    cx.emit(node);
    let label = crate::text::until_nul(&sb.label);
    cx.annotate(format!(
        "Btrfs filesystem{}, {} ({} used), {} device{}",
        if label.is_empty() { String::new() } else { format!(" \"{label}\"") },
        size(sb.total_bytes),
        size(sb.bytes_used),
        sb.num_devices,
        if sb.num_devices == 1 { "" } else { "s" }
    ));

    let array_span = vol.sub(SUPER.saturating_add(0x32b), u64::from(sb.sys_chunk_array_size).min(2048));
    let array = cx.read_avail(array_span).await?;
    let chunks = parse_chunks(&array);
    cx.emit(
        Node::new("Bootstrap chunk array")
            .span(array_span)
            .summary(format!("{} system chunks", chunks.len()))
            .lazy(chunk_array, array_span),
    );
    let map = |logical: u64| {
        chunks.iter().find_map(|(_, _, c, _)| {
            let rel = logical.checked_sub(c.logical)?;
            (rel < c.length).then(|| c.physical.saturating_add(rel))
        })
    };
    let node_size = u64::from(sb.node_size);
    for (name, logical) in [("Chunk tree root", sb.chunk_root), ("Root tree root", sb.root)] {
        let node = Node::new(name).summary(format!("logical {logical:#x}"));
        cx.emit(match map(logical) {
            Some(physical) => {
                let span = vol.sub(physical, node_size);
                node.span(span).lazy(tree_node, span)
            }
            None => node.diag(Diagnostic::note("not in a system chunk; needs the full chunk tree")),
        });
    }
    cx.emit(Node::new("Superblock backups").span(vol.sub(SUPER.saturating_add(0xb2b), 4 * 168)).summary("4 root backups"));
    for (i, at) in MIRRORS.iter().enumerate() {
        let mirror = vol.sub(*at, 0x1000);
        if mirror.len == 0x1000 {
            cx.emit(Superblock::node(format!("Mirror superblock {}", i.saturating_add(1)), mirror, LE));
        }
    }
    Ok(())
}

record! {
    pub struct ChunkItem {
        length: u64 "Length" .with(|&v, n| n.summary(size(v))),
        owner: u64 "Owner",
        stripe_len: u64 "Stripe length",
        kind: u64 "Type" .hex() .flags(CHUNK_TYPE),
        io_align: u32 "I/O alignment",
        io_width: u32 "I/O width",
        sector_size: u32 "Sector size",
        stripes: u16 "Stripes",
        sub_stripes: u16 "Sub-stripes",
    }
}

async fn chunk_array(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let chunks = parse_chunks(&data);
    cx.set_count(Count::Exact(to_u64(chunks.len())));
    for (logical, at, chunk, _) in chunks {
        let item = span.sub(to_u64(at).saturating_add(17), ChunkItem::SIZE);
        cx.push(
            ChunkItem::node(format!("Chunk at logical {logical:#x}"), item, LE).summary(format!(
                "{} → physical {:#x}",
                size(chunk.length),
                chunk.physical
            )),
        )
        .await;
    }
    Ok(())
}

async fn tree_node(cx: Cx, span: Span) -> Result<()> {
    let header = span.sub(0, NodeHeader::SIZE);
    let h = parse(&cx, header, LE, &(), NodeHeader::layout).await?;
    cx.annotate(format!(
        "{}, level {}, {} items",
        crate::value::lookup(TREES, h.owner).unwrap_or("tree"),
        h.level,
        h.items
    ));
    cx.emit(NodeHeader::node("Header", header, LE));
    let leaf = h.level == 0;
    let stride: u64 = if leaf { 25 } else { 33 };
    let count = u64::from(h.items).min(span.len.saturating_sub(NodeHeader::SIZE).checked_div(stride).unwrap_or(0));
    cx.set_count(Count::Exact(count.saturating_add(1)));
    for i in 0..count {
        let at = NodeHeader::SIZE.saturating_add(i.saturating_mul(stride));
        let entry = span.sub(at, stride);
        let raw = cx.read(entry).await?;
        let objectid = u64_le(&raw, 0).unwrap_or(0);
        let kind = raw.get(8).copied().unwrap_or(0);
        let offset = u64_le(&raw, 9).unwrap_or(0);
        let kind_name = crate::value::lookup(ITEM_TYPES, kind.into())
            .map_or_else(|| format!("type {kind}"), str::to_owned);
        let mut node = Node::new(format!("({objectid} {kind_name} {offset})")).span(entry);
        if leaf {
            let data_off = u64::from(crate::bytes::u32_le(&raw, 17).unwrap_or(0));
            let data_len = u64::from(crate::bytes::u32_le(&raw, 21).unwrap_or(0));
            node = node
                .summary(format!("{data_len} bytes of item data"))
                .target(span.sub(NodeHeader::SIZE.saturating_add(data_off), data_len));
        } else {
            node = node.summary(format!("child at logical {:#x}", u64_le(&raw, 17).unwrap_or(0)));
        }
        cx.push(node).await;
    }
    Ok(())
}

const ITEM_TYPES: EnumTable = &[
    (1, "INODE_ITEM"),
    (12, "INODE_REF"),
    (13, "INODE_EXTREF"),
    (24, "XATTR_ITEM"),
    (48, "ORPHAN_ITEM"),
    (60, "DIR_LOG_ITEM"),
    (72, "DIR_LOG_INDEX"),
    (84, "DIR_ITEM"),
    (96, "DIR_INDEX"),
    (108, "EXTENT_DATA"),
    (128, "EXTENT_CSUM"),
    (132, "ROOT_ITEM"),
    (144, "ROOT_BACKREF"),
    (156, "ROOT_REF"),
    (168, "EXTENT_ITEM"),
    (169, "METADATA_ITEM"),
    (176, "TREE_BLOCK_REF"),
    (178, "EXTENT_DATA_REF"),
    (182, "SHARED_BLOCK_REF"),
    (184, "SHARED_DATA_REF"),
    (192, "BLOCK_GROUP_ITEM"),
    (198, "FREE_SPACE_INFO"),
    (199, "FREE_SPACE_EXTENT"),
    (200, "FREE_SPACE_BITMAP"),
    (204, "DEV_EXTENT"),
    (216, "DEV_ITEM"),
    (228, "CHUNK_ITEM"),
    (240, "QGROUP_STATUS"),
    (242, "QGROUP_INFO"),
    (244, "QGROUP_LIMIT"),
    (246, "QGROUP_RELATION"),
    (248, "TEMPORARY_ITEM"),
    (249, "PERSISTENT_ITEM"),
    (250, "DEV_REPLACE"),
    (251, "UUID_SUBVOL"),
    (252, "UUID_RECEIVED_SUBVOL"),
    (253, "STRING_ITEM"),
];
