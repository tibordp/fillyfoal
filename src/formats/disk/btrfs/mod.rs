//! Btrfs filesystems.
//!
//! The superblock at 64 KiB (mirrored at 64 MiB and 256 GiB) holds the
//! bootstrap chunk array: enough of the logical-to-physical mapping to
//! read the chunk tree, which maps the rest. Everything else is a B-tree
//! of nodes addressed logically: the root tree lists the other trees
//! (extent, device, filesystem, checksum, UUID, free space...), and each
//! filesystem tree holds inodes, directory entries and file extents keyed
//! by (object id, type, offset). Tree nodes carry a checksum (CRC-32C
//! here), which is verified.

mod fs;
mod tree;

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::disk::{crc32c, size, text, uuid_value};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
const SUPER: u64 = 0x10000;
const MAGIC: &[u8] = b"_BHRfS_M";
/// Mirror copies at 64 MiB and 256 GiB.
const MIRRORS: [u64; 2] = [0x400_0000, 0x40_0000_0000];
/// Chunks mapped at most.
const MAX_CHUNKS: usize = 1 << 16;

pub static FORMAT: Format = Format {
    name: "btrfs",
    title: "Btrfs filesystem",
    extensions: &["img", "btrfs"],
    mime: "application/x-btrfs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.at(crate::bytes::to_usize(SUPER.saturating_add(0x40)), MAGIC)
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

const SB_FLAGS: FlagTable = &[
    flag(0x1, "WRITTEN"),
    flag(0x2, "RELOC"),
    flag(0x1_0000_0000, "SEEDING"),
    flag(0x2_0000_0000, "CHANGING_FSID"),
    flag(0x4_0000_0000, "CHANGING_FSID_V2"),
    flag(0x10_0000_0000, "CHANGING_BG_TREE"),
    flag(0x20_0000_0000, "CHANGING_DATA_CSUM"),
    flag(0x40_0000_0000, "CHANGING_META_CSUM"),
];

const CSUM: EnumTable = &[
    (0, "CRC32C"),
    (1, "xxHash64"),
    (2, "SHA-256"),
    (3, "BLAKE2b"),
];

pub(super) const CHUNK_TYPE: FlagTable = &[
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
        flags: u64 "Flags" .hex() .flags(SB_FLAGS),
        magic: ascii[8] "Magic",
        generation: u64 "Generation",
        root: u64 "Root tree root (logical)" .hex(),
        chunk_root: u64 "Chunk tree root (logical)" .hex(),
        log_root: u64 "Log tree root (logical)" .hex(),
        log_root_transid: u64 "Log root transaction id (unused)",
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
        nr_global_roots: u64 "Global roots (extent tree v2)",
        _reserved: bytes[216] "Reserved",
    }
}

const BACKUP_FIELDS: [&str; 15] = [
    "Root tree",
    "Root tree generation",
    "Chunk tree",
    "Chunk tree generation",
    "Extent tree",
    "Extent tree generation",
    "Filesystem tree",
    "Filesystem tree generation",
    "Device tree",
    "Device tree generation",
    "Checksum tree",
    "Checksum tree generation",
    "Total bytes",
    "Bytes used",
    "Devices",
];

fn backup_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    for (i, name) in BACKUP_FIELDS.iter().enumerate() {
        let field = f.u64(name);
        if i % 2 == 0 && i < 12 {
            field.hex().emit()?;
        } else {
            field.emit()?;
        }
    }
    f.bytes("Unused", 32).emit()?;
    for name in [
        "Root tree level",
        "Chunk tree level",
        "Extent tree level",
        "Filesystem tree level",
        "Device tree level",
        "Checksum tree level",
    ] {
        f.u8(name).emit()?;
    }
    f.bytes("Unused", 10).emit()?;
    Ok(())
}

/// One mapping of the logical address space to the device.
#[derive(Clone, Copy, Debug)]
pub(super) struct Chunk {
    logical: u64,
    length: u64,
    physical: u64,
    /// The second stripe's offset (DUP, RAID1), if any.
    mirror: Option<u64>,
    kind: u64,
}

/// Filesystem parameters and the chunk map, shared by every expansion.
#[derive(Debug)]
pub(super) struct Fs {
    pub(super) input: Input,
    pub(super) vol: Span,
    pub(super) node_size: u64,
    pub(super) csum_type: u16,
    /// Sorted by logical address.
    chunks: Vec<Chunk>,
}

pub(super) type FsRef = Arc<Fs>;

impl Fs {
    /// `len` bytes at a logical address, if they lie in one chunk.
    pub(super) fn logical_span(&self, logical: u64, len: u64) -> Option<Span> {
        let i = self.chunks.partition_point(|c| c.logical <= logical);
        let c = self.chunks.get(i.checked_sub(1)?)?;
        let rel = logical.checked_sub(c.logical)?;
        if rel.saturating_add(len) > c.length {
            return None;
        }
        Some(self.vol.sub(c.physical.saturating_add(rel), len))
    }

    /// The span of a tree node.
    pub(super) fn node_span(&self, logical: u64) -> Option<Span> {
        self.logical_span(logical, self.node_size)
    }
}

/// Parses the chunks of a bootstrap array or chunk tree leaf items:
/// `(key offset (logical), item position, chunk)`.
fn parse_chunks(array: &[u8]) -> Vec<(u64, usize, Chunk)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at.saturating_add(17 + 48) <= array.len() {
        let logical = u64_le(array, at.saturating_add(9)).unwrap_or(0);
        let item = at.saturating_add(17);
        let stripes = usize::from(u16_le(array, item.saturating_add(44)).unwrap_or(0));
        out.push((logical, at, chunk_at(array, item, logical)));
        at = item
            .saturating_add(48)
            .saturating_add(stripes.saturating_mul(32));
        if stripes == 0 {
            break;
        }
    }
    out
}

/// A chunk item at `item` for logical address `logical`.
fn chunk_at(data: &[u8], item: usize, logical: u64) -> Chunk {
    Chunk {
        logical,
        length: u64_le(data, item).unwrap_or(0),
        kind: u64_le(data, item.saturating_add(24)).unwrap_or(0),
        physical: u64_le(data, item.saturating_add(48 + 8)).unwrap_or(0),
        mirror: (u16_le(data, item.saturating_add(44)).unwrap_or(0) > 1)
            .then(|| u64_le(data, item.saturating_add(48 + 32 + 8)))
            .flatten(),
    }
}

/// Completes the chunk map from the chunk tree (whose nodes the bootstrap
/// chunks map).
async fn load_chunk_tree(cx: &Cx, fs: &mut Fs, root: u64) -> Result<Option<Diagnostic>> {
    let mut stack = vec![root];
    let mut seen = std::collections::HashSet::new();
    let mut found = Vec::new();
    while let Some(logical) = stack.pop() {
        cx.checkpoint().await;
        if !seen.insert(logical) || seen.len() > 4096 {
            return Ok(Some(Diagnostic::malformed("chunk tree revisits a node")));
        }
        let Some(span) = fs.node_span(logical) else {
            return Ok(Some(Diagnostic::malformed(format!(
                "chunk tree node {logical:#x} is not mapped"
            ))));
        };
        let node = cx.read(span).await?;
        let level = node.get(0x64).copied().unwrap_or(0);
        let items = u64::from(crate::bytes::u32_le(&node, 0x60).unwrap_or(0));
        for i in 0..items.min(fs.node_size / 25) {
            let at =
                crate::bytes::to_usize(101u64.saturating_add(i.saturating_mul(if level == 0 {
                    25
                } else {
                    33
                })));
            if level == 0 {
                let ty = node.get(at.saturating_add(8)).copied().unwrap_or(0);
                if ty != 228 {
                    continue;
                }
                let logical = u64_le(&node, at.saturating_add(9)).unwrap_or(0);
                let off =
                    u64::from(crate::bytes::u32_le(&node, at.saturating_add(17)).unwrap_or(0));
                let item = crate::bytes::to_usize(101u64.saturating_add(off));
                found.push(chunk_at(&node, item, logical));
                if found.len() >= MAX_CHUNKS {
                    return Ok(Some(Diagnostic::limit("too many chunks")));
                }
            } else if let Some(child) = u64_le(&node, at.saturating_add(17)) {
                stack.push(child);
            }
        }
    }
    for c in found {
        if !fs.chunks.iter().any(|k| k.logical == c.logical) {
            fs.chunks.push(c);
        }
    }
    fs.chunks.sort_by_key(|c| c.logical);
    Ok(None)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(SUPER, Superblock::SIZE);
    let magic = cx
        .read_avail(vol.sub(SUPER.saturating_add(0x40), 8))
        .await?;
    if magic != MAGIC {
        let reiser = cx
            .read_avail(vol.sub(SUPER.saturating_add(0x34), 10))
            .await?;
        if reiser.starts_with(b"ReIsEr") {
            cx.annotate("ReiserFS filesystem");
            return Err(Diagnostic::unsupported("ReiserFS").at(vol.sub(SUPER, 0x100)));
        }
        return Err(Diagnostic::unsupported("no Btrfs superblock at 64 KiB").at(vol.sub(0, SUPER)));
    }
    let sb = parse(&cx, span, LE, &(), Superblock::layout).await?;
    let full = vol.sub(SUPER, 0x1000);
    cx.emit(
        Node::new("Boot area")
            .span(vol.sub(0, SUPER))
            .summary("64 KiB before the superblock, left for boot loaders"),
    );
    let mut node =
        Superblock::node("Superblock", span, LE).summary(format!("generation {}", sb.generation));
    if sb.csum_type == 0 {
        let data = cx.read_avail(full).await?;
        let computed = crc32c(data.get(32..).unwrap_or_default());
        node = if sb.csum.get(..4) == Some(&computed.to_le_bytes()[..]) {
            node.summary(format!("generation {}, checksum valid", sb.generation))
        } else {
            node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {computed:#010x}"
            )))
        };
    }
    cx.emit(node);
    let label = crate::text::until_nul(&sb.label);
    cx.annotate(format!(
        "Btrfs filesystem{}, {} ({} used), {} device{}",
        if label.is_empty() {
            String::new()
        } else {
            format!(" \"{label}\"")
        },
        size(sb.total_bytes),
        size(sb.bytes_used),
        sb.num_devices,
        if sb.num_devices == 1 { "" } else { "s" }
    ));
    let array_len = u64::from(sb.sys_chunk_array_size).min(2048);
    let array_span = vol.sub(SUPER.saturating_add(0x32b), array_len);
    let array = cx.read_avail(array_span).await?;
    let chunks = parse_chunks(&array);
    cx.emit(
        Node::new("Bootstrap chunk array")
            .span(array_span)
            .summary(format!("{} system chunks", chunks.len()))
            .lazy(chunk_array, array_span),
    );
    if array_len < 2048 {
        cx.emit(
            Node::new("Unused chunk array space")
                .span(vol.sub(
                    SUPER.saturating_add(0x32b).saturating_add(array_len),
                    2048u64.saturating_sub(array_len),
                ))
                .summary(size(2048u64.saturating_sub(array_len))),
        );
    }
    let backups = vol.sub(SUPER.saturating_add(0xb2b), 4 * 168);
    cx.emit(
        Node::new("Root backups")
            .span(backups)
            .summary("the 4 most recent sets of tree roots")
            .lazy(root_backups, backups),
    );
    cx.emit(
        Node::new("Padding")
            .span(vol.sub(
                SUPER.saturating_add(0xb2b + 4 * 168),
                0x1000 - (0xb2b + 4 * 168),
            ))
            .summary("rest of the superblock"),
    );
    let mut fs = Fs {
        input,
        vol,
        node_size: u64::from(sb.node_size).clamp(4096, 65536),
        csum_type: sb.csum_type,
        chunks: chunks.iter().map(|&(_, _, c)| c).collect(),
    };
    fs.chunks.sort_by_key(|c| c.logical);
    if let Some(d) = load_chunk_tree(&cx, &mut fs, sb.chunk_root).await? {
        cx.diag(d);
    }
    let fs: FsRef = Arc::new(fs);
    cx.emit(
        Node::new("Chunk map")
            .summary(format!("{} chunks", fs.chunks.len()))
            .lazy(chunk_map, fs.clone()),
    );
    for (name, logical) in [("Chunk tree", sb.chunk_root), ("Root tree", sb.root)] {
        cx.emit(tree::tree_node_entry(&fs, name, logical, Path::new()));
    }
    if sb.log_root != 0 {
        cx.emit(tree::tree_node_entry(
            &fs,
            "Log tree",
            sb.log_root,
            Path::new(),
        ));
    }
    cx.emit(
        Node::new("Root directory")
            .summary("filesystem tree, inode 256")
            .lazy(fs::root_directory, (fs.clone(), sb.root)),
    );
    for (i, at) in MIRRORS.iter().enumerate() {
        let mirror = vol.sub(*at, 0x1000);
        if mirror.len == 0x1000 {
            cx.emit(Superblock::node(
                format!("Mirror superblock {}", i.saturating_add(1)),
                mirror.sub(0, Superblock::SIZE),
                LE,
            ));
        }
    }
    Ok(())
}

async fn root_backups(cx: Cx, span: Span) -> Result<()> {
    for i in 0..4u64 {
        cx.emit(struct_node(
            format!("Backup {i}"),
            span.sub(i.saturating_mul(168), 168),
            LE,
            (),
            backup_layout,
        ));
    }
    Ok(())
}

async fn chunk_map(cx: Cx, fs: FsRef) -> Result<()> {
    let mut used: Vec<(u64, u64)> = Vec::new();
    for c in &fs.chunks {
        let (set, _) = crate::value::decode_flags(CHUNK_TYPE, c.kind);
        cx.push(
            Node::new(format!("Logical {:#x}", c.logical))
                .span(fs.vol.sub(c.physical, c.length))
                .summary(format!(
                    "{} {} → physical {:#x}",
                    size(c.length),
                    set.join("|"),
                    c.physical
                )),
        )
        .await;
        used.push((c.physical, c.length));
        if let Some(m) = c.mirror {
            cx.push(
                Node::new(format!("Logical {:#x} (second copy)", c.logical))
                    .span(fs.vol.sub(m, c.length))
                    .summary(format!("{} → physical {m:#x}", size(c.length))),
            )
            .await;
            used.push((m, c.length));
        }
    }
    // The device space no chunk claims (the first MiB holds only the
    // superblock and is never allocated).
    used.sort_unstable();
    let mut at = 0u64;
    for (start, len) in used.into_iter().chain([(fs.vol.len, 0)]) {
        if start > at {
            cx.push(
                Node::new(format!("Unallocated {at:#x}"))
                    .span(fs.vol.sub(at, start.saturating_sub(at)))
                    .summary(format!(
                        "{} not in any chunk",
                        size(start.saturating_sub(at))
                    )),
            )
            .await;
        }
        at = at.max(start.saturating_add(len));
    }
    Ok(())
}

async fn chunk_array(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let chunks = parse_chunks(&data);
    cx.set_count(Count::Exact(to_u64(chunks.len()).saturating_mul(2)));
    for (logical, at, chunk) in chunks {
        let key = span.sub(to_u64(at), 17);
        cx.push(tree::key_node(
            "Key",
            key,
            data.get(at..at.saturating_add(17)).unwrap_or_default(),
        ))
        .await;
        let stripes = u64::from(u16_le(&data, at.saturating_add(17 + 44)).unwrap_or(0));
        let item = span.sub(
            to_u64(at).saturating_add(17),
            48u64.saturating_add(stripes.saturating_mul(32)),
        );
        cx.push(
            struct_node(
                format!("Chunk at logical {logical:#x}"),
                item,
                LE,
                (),
                tree::chunk_layout,
            )
            .summary(format!(
                "{} → physical {:#x}",
                size(chunk.length),
                chunk.physical
            )),
        )
        .await;
    }
    Ok(())
}
