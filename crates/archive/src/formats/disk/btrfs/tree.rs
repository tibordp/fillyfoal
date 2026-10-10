//! Btrfs B-tree nodes, the items in their leaves, and key searches.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Fields, struct_node};
use crate::formats::disk::name_field;
use crate::formats::disk::{crc32c, size, unix_mode, uuid_value};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

use super::{CHUNK_TYPE, Fs, FsRef, LE};

/// Bytes of a node header.
pub(super) const HEADER: u64 = 101;
/// Tree depth followed.
const MAX_LEVELS: usize = 10;
/// Items collected by one search at most.
const MAX_ITEMS: usize = 1 << 16;

pub(super) const INODE_ITEM: u8 = 1;
pub(super) const INODE_REF: u8 = 12;
pub(super) const XATTR_ITEM: u8 = 24;
pub(super) const DIR_INDEX: u8 = 96;
pub(super) const EXTENT_DATA: u8 = 108;
pub(super) const ROOT_ITEM: u8 = 132;

record! {
    /// `struct btrfs_header`, at the start of every tree node.
    pub struct NodeHeader {
        csum: bytes[32] "Checksum",
        fsid: bytes[16] "Filesystem UUID" .with(uuid_value),
        bytenr: u64 "Logical address" .hex(),
        flags: u64 "Flags" .hex() .flags(NODE_FLAGS),
        chunk_tree_uuid: bytes[16] "Chunk tree UUID" .with(uuid_value),
        generation: u64 "Generation",
        owner: u64 "Owner tree" .enumeration(OBJECTIDS),
        items: u32 "Items",
        level: u8 "Level",
    }
}

const NODE_FLAGS: FlagTable = &[
    flag(0x1, "WRITTEN"),
    flag(0x2, "RELOC"),
    flag(0x0100_0000_0000_0000, "BACKREF_REV1"),
];

/// Well-known object ids (tree ids and special objects). 256, the first
/// free id, is left as a number: it is also a subvolume's root directory
/// inode and, in chunk items, the chunk tree's id (see `key_text`).
const OBJECTIDS: EnumTable = &[
    (1, "ROOT_TREE"),
    (2, "EXTENT_TREE"),
    (3, "CHUNK_TREE"),
    (4, "DEV_TREE"),
    (5, "FS_TREE"),
    (6, "ROOT_TREE_DIR"),
    (7, "CSUM_TREE"),
    (8, "QUOTA_TREE"),
    (9, "UUID_TREE"),
    (10, "FREE_SPACE_TREE"),
    (11, "BLOCK_GROUP_TREE"),
    (12, "RAID_STRIPE_TREE"),
    (0xffff_ffff_ffff_fffc, "BALANCE"),
    (0xffff_ffff_ffff_fffb, "ORPHAN"),
    (0xffff_ffff_ffff_fffa, "TREE_LOG"),
    (0xffff_ffff_ffff_fff9, "TREE_LOG_FIXUP"),
    (0xffff_ffff_ffff_fff8, "TREE_RELOC"),
    (0xffff_ffff_ffff_fff7, "DATA_RELOC_TREE"),
    (0xffff_ffff_ffff_fff6, "EXTENT_CSUM"),
    (0xffff_ffff_ffff_fff5, "FREE_SPACE"),
    (0xffff_ffff_ffff_fff4, "FREE_INO"),
    (0xffff_ffff_ffff_ff01, "MULTIPLE"),
];

pub(super) const ITEM_TYPES: EnumTable = &[
    (1, "INODE_ITEM"),
    (12, "INODE_REF"),
    (13, "INODE_EXTREF"),
    (24, "XATTR_ITEM"),
    (36, "VERITY_DESC_ITEM"),
    (37, "VERITY_MERKLE_ITEM"),
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
    (172, "EXTENT_OWNER_REF"),
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
    (230, "RAID_STRIPE"),
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

pub(super) const DIR_TYPES: EnumTable = crate::formats::disk::dirent_types!((8, "xattr"));

const COMPRESSION: EnumTable = &[(0, "none"), (1, "zlib"), (2, "LZO"), (3, "zstd")];
const EXTENT_TYPES: EnumTable = &[(0, "inline"), (1, "regular"), (2, "preallocated")];

const INODE_FLAGS: FlagTable = &[
    flag(0x1, "NODATASUM"),
    flag(0x2, "NODATACOW"),
    flag(0x4, "READONLY"),
    flag(0x8, "NOCOMPRESS"),
    flag(0x10, "PREALLOC"),
    flag(0x20, "SYNC"),
    flag(0x40, "IMMUTABLE"),
    flag(0x80, "APPEND"),
    flag(0x100, "NODUMP"),
    flag(0x200, "NOATIME"),
    flag(0x400, "DIRSYNC"),
    flag(0x800, "COMPRESS"),
    flag(0x8000_0000, "ROOT_ITEM_INIT"),
];

const EXTENT_FLAGS: FlagTable = &[
    flag(0x1, "DATA"),
    flag(0x2, "TREE_BLOCK"),
    flag(0x100, "FULL_BACKREF"),
];

/// A key as text: `(object type offset)`.
pub(super) fn key_text(oid: u64, ty: u8, offset: u64) -> String {
    // Object ids whose name depends on the item type, as btrfs-progs
    // prints them.
    let o = lookup(objectid_names(ty), oid).map_or_else(|| oid.to_string(), str::to_owned);
    let t = lookup(ITEM_TYPES, ty.into()).map_or_else(|| format!("type {ty}"), str::to_owned);
    let off = if offset == u64::MAX {
        "-1".to_owned()
    } else {
        offset.to_string()
    };
    format!("({o} {t} {off})")
}

/// The names of a key's object id, which depend on its item type.
fn objectid_names(ty: u8) -> EnumTable {
    match ty {
        216 => &[(1, "DEV_ITEMS")],
        228 => &[(256, "FIRST_CHUNK_TREE")],
        _ => OBJECTIDS,
    }
}

fn key_layout(f: &mut Fields<'_>, ty: &u8) -> Result<()> {
    f.u64("Object id").enumeration(objectid_names(*ty)).emit()?;
    f.u8("Type").enumeration(ITEM_TYPES).emit()?;
    f.u64("Offset").emit()?;
    Ok(())
}

/// A node for a 17-byte key at `span` (whose bytes are `raw`).
pub(super) fn key_node(name: &'static str, span: Span, raw: &[u8]) -> Node {
    let oid = u64_le(raw, 0).unwrap_or(0);
    let ty = raw.get(8).copied().unwrap_or(0);
    let off = u64_le(raw, 9).unwrap_or(0);
    struct_node(name, span, LE, ty, key_layout).summary(key_text(oid, ty, off))
}

fn key_field(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let span = f.peek_span(17);
    let raw = {
        let data: &[u8] = &f.block().data;
        let at = to_usize(f.pos());
        data.get(at..at.saturating_add(17))
            .unwrap_or_default()
            .to_vec()
    };
    f.node(key_node(name, span, &raw));
    f.skip(17);
    Ok(())
}

fn timespec(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.u64(name).timestamp().emit()?;
    f.u32("Nanoseconds").emit()?;
    Ok(())
}

fn inode_item(f: &mut Fields<'_>) -> Result<()> {
    f.u64("Generation").emit()?;
    f.u64("Transaction id").emit()?;
    f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Bytes allocated")
        .with(|&v, n| n.summary(size(v)))
        .emit()?;
    f.u64("Block group (hint)").emit()?;
    f.u32("Links").emit()?;
    f.u32("Owner UID").emit()?;
    f.u32("Group GID").emit()?;
    f.u32("Mode")
        .hex()
        .with(|&m, n| n.summary(unix_mode(m.into())))
        .emit()?;
    f.u64("Device").emit()?;
    f.u64("Flags").hex().flags(INODE_FLAGS).emit()?;
    f.u64("Sequence").emit()?;
    f.bytes("Reserved", 32).emit()?;
    timespec(f, "Accessed")?;
    timespec(f, "Changed")?;
    timespec(f, "Modified")?;
    timespec(f, "Created")?;
    Ok(())
}

fn dev_item(f: &mut Fields<'_>) -> Result<()> {
    f.u64("Device id").emit()?;
    f.u64("Size").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Bytes used")
        .with(|&v, n| n.summary(size(v)))
        .emit()?;
    f.u32("I/O alignment").emit()?;
    f.u32("I/O width").emit()?;
    f.u32("Sector size").emit()?;
    f.u64("Type").emit()?;
    f.u64("Generation").emit()?;
    f.u64("Start offset").emit()?;
    f.u32("Group").emit()?;
    f.u8("Seek speed").emit()?;
    f.u8("Bandwidth").emit()?;
    f.bytes("Device UUID", 16).with(uuid_value).emit()?;
    f.bytes("Filesystem UUID", 16).with(uuid_value).emit()?;
    Ok(())
}

/// `struct btrfs_chunk` and its stripes.
pub(super) fn chunk_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Length").with(|&v, n| n.summary(size(v))).emit()?;
    f.u64("Owner").emit()?;
    f.u64("Stripe length").emit()?;
    f.u64("Type").hex().flags(CHUNK_TYPE).emit()?;
    f.u32("I/O alignment").emit()?;
    f.u32("I/O width").emit()?;
    f.u32("Sector size").emit()?;
    let n = f.u16("Stripes").emit()?;
    f.u16("Sub-stripes").emit()?;
    for _ in 0..n {
        if f.remaining() < 32 {
            break;
        }
        f.node(struct_node(
            "Stripe",
            f.peek_span(32),
            LE,
            (),
            stripe_layout,
        ));
        f.skip(32);
    }
    Ok(())
}

fn stripe_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Device id").emit()?;
    f.u64("Physical offset").hex().emit()?;
    f.bytes("Device UUID", 16).with(uuid_value).emit()?;
    Ok(())
}

/// The data of a leaf item, decoded by its type.
pub(super) fn item_layout(f: &mut Fields<'_>, ty: &u8) -> Result<()> {
    match *ty {
        1 => inode_item(f)?,
        12 => {
            while f.remaining() >= 10 {
                f.u64("Index").emit()?;
                let n = f.u16("Name length").emit()?;
                name_field(f, n.into())?;
            }
        }
        13 => {
            while f.remaining() >= 18 {
                f.u64("Parent directory").emit()?;
                f.u64("Index").emit()?;
                let n = f.u16("Name length").emit()?;
                name_field(f, n.into())?;
            }
        }
        24 | 84 | 96 => {
            while f.remaining() >= 30 {
                key_field(f, "Location")?;
                f.u64("Transaction id").emit()?;
                let data = f.u16("Data length").emit()?;
                let name = f.u16("Name length").emit()?;
                f.u8("Type").enumeration(DIR_TYPES).emit()?;
                name_field(f, name.into())?;
                if data > 0 {
                    f.bytes("Data", data.into())
                        .with(|b, n| {
                            if crate::text::looks_like_text(b) {
                                n.value(Value::Text(String::from_utf8_lossy(b).into_owned()))
                            } else {
                                n
                            }
                        })
                        .emit()?;
                }
            }
        }
        108 => {
            f.u64("Generation").emit()?;
            f.u64("Decoded size")
                .with(|&v, n| n.summary(size(v)))
                .emit()?;
            f.u8("Compression").enumeration(COMPRESSION).emit()?;
            f.u8("Encryption").emit()?;
            f.u16("Other encoding").emit()?;
            let kind = f.u8("Type").enumeration(EXTENT_TYPES).emit()?;
            if kind == 0 {
                let rest = f.remaining();
                f.node(
                    Node::new("Inline data")
                        .span(f.peek_span(rest))
                        .summary(size(rest)),
                );
                f.skip(rest);
            } else {
                f.u64("Disk address (logical)").hex().emit()?;
                f.u64("Disk length")
                    .with(|&v, n| n.summary(size(v)))
                    .emit()?;
                f.u64("Offset in extent").emit()?;
                f.u64("Length").with(|&v, n| n.summary(size(v))).emit()?;
            }
        }
        128 => {
            let n = f.remaining() / 4;
            f.node(
                Node::new("Checksums")
                    .span(f.peek_span(n.saturating_mul(4)))
                    .value(Value::UInt {
                        value: n,
                        bits: 32,
                        radix: Radix::Dec,
                    })
                    .summary("one CRC-32C per data sector"),
            );
            f.skip(n.saturating_mul(4));
        }
        132 => {
            inode_item(f)?;
            f.u64("Generation").emit()?;
            f.u64("Root directory").emit()?;
            f.u64("Root node (logical)").hex().emit()?;
            f.u64("Byte limit").emit()?;
            f.u64("Bytes used").emit()?;
            f.u64("Last snapshot").emit()?;
            f.u64("Flags").hex().emit()?;
            f.u32("References").emit()?;
            key_field(f, "Drop progress")?;
            f.u8("Drop level").emit()?;
            f.u8("Root level").emit()?;
            if f.remaining() >= 200 {
                f.u64("Generation (v2)").emit()?;
                f.bytes("UUID", 16).with(uuid_value).emit()?;
                f.bytes("Parent UUID", 16).with(uuid_value).emit()?;
                f.bytes("Received UUID", 16).with(uuid_value).emit()?;
                f.u64("Changed transaction").emit()?;
                f.u64("Created transaction").emit()?;
                f.u64("Sent transaction").emit()?;
                f.u64("Received transaction").emit()?;
                timespec(f, "Changed")?;
                timespec(f, "Created")?;
                timespec(f, "Sent")?;
                timespec(f, "Received")?;
                let rest = f.remaining();
                f.bytes("Reserved", rest).emit()?;
            }
        }
        144 | 156 => {
            f.u64("Directory").emit()?;
            f.u64("Sequence").emit()?;
            let n = f.u16("Name length").emit()?;
            name_field(f, n.into())?;
        }
        168 | 169 => {
            f.u64("References").emit()?;
            f.u64("Generation").emit()?;
            let flags = f.u64("Flags").hex().flags(EXTENT_FLAGS).emit()?;
            if *ty == 168 && flags & 2 != 0 && f.remaining() >= 18 {
                key_field(f, "First key")?;
                f.u8("Level").emit()?;
            }
            while f.remaining() >= 9 {
                let kind = f.u8("Reference type").enumeration(ITEM_TYPES).emit()?;
                match kind {
                    178 => {
                        f.u64("Root").emit()?;
                        f.u64("Object id").emit()?;
                        f.u64("Offset").emit()?;
                        f.u32("Count").emit()?;
                    }
                    184 => {
                        f.u64("Parent").hex().emit()?;
                        f.u32("Count").emit()?;
                    }
                    182 => {
                        f.u64("Parent").hex().emit()?;
                    }
                    _ => {
                        f.u64("Root").enumeration(OBJECTIDS).emit()?;
                    }
                }
            }
        }
        178 => {
            f.u64("Root").enumeration(OBJECTIDS).emit()?;
            f.u64("Object id").emit()?;
            f.u64("Offset").emit()?;
            f.u32("Count").emit()?;
        }
        184 => {
            f.u32("Count").emit()?;
        }
        192 => {
            f.u64("Bytes used")
                .with(|&v, n| n.summary(size(v)))
                .emit()?;
            f.u64("Chunk object id").emit()?;
            f.u64("Flags").hex().flags(CHUNK_TYPE).emit()?;
        }
        198 => {
            f.u32("Extents").emit()?;
            f.u32("Flags").hex().emit()?;
        }
        204 => {
            f.u64("Chunk tree").emit()?;
            f.u64("Chunk object id").emit()?;
            f.u64("Chunk offset (logical)").hex().emit()?;
            f.u64("Length").with(|&v, n| n.summary(size(v))).emit()?;
            f.bytes("Chunk tree UUID", 16).with(uuid_value).emit()?;
        }
        216 => dev_item(f)?,
        228 => chunk_layout(f, &())?,
        248 | 249 | 251 | 252 => {
            while f.remaining() >= 8 {
                f.u64("Value").emit()?;
            }
        }
        _ => {}
    }
    let rest = f.remaining();
    if rest > 0 {
        f.bytes("Data", rest).emit()?;
    }
    Ok(())
}

/// A short description of a leaf item.
fn item_summary(ty: u8, data: &[u8], len: u64) -> String {
    match ty {
        1 => format!(
            "{}, {}",
            unix_mode(u32_le(data, 52).unwrap_or(0).into()),
            size(u64_le(data, 16).unwrap_or(0))
        ),
        12 => {
            let n = usize::from(u16_le(data, 8).unwrap_or(0));
            format!(
                "\"{}\"",
                String::from_utf8_lossy(
                    data.get(10..10usize.saturating_add(n)).unwrap_or_default()
                )
            )
        }
        24 | 84 | 96 => {
            let n = usize::from(u16_le(data, 27).unwrap_or(0));
            format!(
                "\"{}\" → {}",
                String::from_utf8_lossy(
                    data.get(30..30usize.saturating_add(n)).unwrap_or_default()
                ),
                key_text(
                    u64_le(data, 0).unwrap_or(0),
                    data.get(8).copied().unwrap_or(0),
                    u64_le(data, 9).unwrap_or(0)
                )
            )
        }
        108 => match data.get(20).copied() {
            Some(0) => format!("inline, {}", size(len.saturating_sub(21))),
            Some(t) => format!(
                "{}, {} at logical {:#x}",
                lookup(EXTENT_TYPES, t.into()).unwrap_or("?"),
                size(u64_le(data, 45).unwrap_or(0)),
                u64_le(data, 21).unwrap_or(0)
            ),
            None => "truncated".into(),
        },
        132 => format!(
            "root node at {:#x}, level {}",
            u64_le(data, 176).unwrap_or(0),
            data.get(238).copied().unwrap_or(0)
        ),
        168 | 169 => format!("{} references", u64_le(data, 0).unwrap_or(0)),
        192 => format!("{} used", size(u64_le(data, 0).unwrap_or(0))),
        204 => format!(
            "{} of chunk {:#x}",
            size(u64_le(data, 24).unwrap_or(0)),
            u64_le(data, 16).unwrap_or(0)
        ),
        228 => format!(
            "{} → physical {:#x}",
            size(u64_le(data, 0).unwrap_or(0)),
            u64_le(data, 56).unwrap_or(0)
        ),
        _ => size(len),
    }
}

#[derive(Clone)]
struct NodeState {
    fs: FsRef,
    logical: u64,
    path: Path,
}

/// A lazy node for the tree node at `logical`.
pub(super) fn tree_node_entry(
    fs: &FsRef,
    name: impl Into<std::borrow::Cow<'static, str>>,
    logical: u64,
    path: Path,
) -> Node {
    let node = Node::new(name).summary(format!("node at logical {logical:#x}"));
    match fs.node_span(logical) {
        Some(span) => node.span(span).lazy(
            crate::expander!(self::tree_node: NodeState),
            NodeState {
                fs: fs.clone(),
                logical,
                path,
            },
        ),
        None => node.diag(Diagnostic::malformed(
            "logical address not mapped by any chunk",
        )),
    }
}

async fn tree_node(cx: Cx, st: NodeState) -> Result<()> {
    let fs = st.fs.clone();
    let span = fs
        .node_span(st.logical)
        .ok_or_else(|| Diagnostic::malformed("logical address not mapped"))?;
    let data = cx.read(span).await?;
    let header = span.sub(0, HEADER);
    let mut hnode = NodeHeader::node("Header", header, LE);
    if fs.csum_type == 0 {
        let computed = crc32c(data.get(32..).unwrap_or_default());
        hnode = if data.get(..4) == Some(&computed.to_le_bytes()[..]) {
            hnode.summary("checksum valid")
        } else {
            hnode.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {computed:#010x}"
            )))
        };
    }
    if u64_le(&data, 0x30) != Some(st.logical) {
        hnode = hnode.diag(Diagnostic::malformed("node address does not match"));
    }
    cx.emit(hnode);
    let owner = u64_le(&data, 0x58).unwrap_or(0);
    let items = u64::from(u32_le(&data, 0x60).unwrap_or(0));
    let level = data.get(0x64).copied().unwrap_or(0);
    cx.annotate(format!(
        "{}, level {level}, {items} items",
        lookup(OBJECTIDS, owner).unwrap_or("tree")
    ));
    let len = to_u64(data.len());
    if level == 0 {
        let n = items.min(len.saturating_sub(HEADER) / 25);
        let mut lowest = len;
        for i in 0..n {
            let at = HEADER.saturating_add(i.saturating_mul(25));
            let raw = data
                .get(to_usize(at)..to_usize(at).saturating_add(25))
                .unwrap_or_default();
            let oid = u64_le(raw, 0).unwrap_or(0);
            let ty = raw.get(8).copied().unwrap_or(0);
            let off = u64_le(raw, 9).unwrap_or(0);
            let doff = u64::from(u32_le(raw, 17).unwrap_or(0));
            let dlen = u64::from(u32_le(raw, 21).unwrap_or(0));
            let dat = HEADER.saturating_add(doff);
            lowest = lowest.min(dat);
            let item_data = data
                .get(to_usize(dat)..to_usize(dat.saturating_add(dlen)))
                .unwrap_or_default();
            let dspan = span.sub(dat, dlen);
            cx.push(
                Node::new(key_text(oid, ty, off))
                    .span(span.sub(at, 25))
                    .summary(item_summary(ty, item_data, dlen))
                    .lazy(item_view, (span.sub(at, 25), dspan, ty)),
            )
            .await;
        }
        let headers_end = HEADER.saturating_add(n.saturating_mul(25));
        if lowest > headers_end {
            cx.emit(
                Node::new("Free space")
                    .span(span.sub(headers_end, lowest.saturating_sub(headers_end)))
                    .summary(size(lowest.saturating_sub(headers_end))),
            );
        }
        return Ok(());
    }
    let n = items.min(len.saturating_sub(HEADER) / 33);
    for i in 0..n {
        let at = HEADER.saturating_add(i.saturating_mul(33));
        let raw = data
            .get(to_usize(at)..to_usize(at).saturating_add(33))
            .unwrap_or_default();
        let oid = u64_le(raw, 0).unwrap_or(0);
        let ty = raw.get(8).copied().unwrap_or(0);
        let off = u64_le(raw, 9).unwrap_or(0);
        let child = u64_le(raw, 17).unwrap_or(0);
        let name = format!("{} → {child:#x}", key_text(oid, ty, off));
        let node = match st.path.enter(child, MAX_LEVELS) {
            Ok(path) => tree_node_entry(&fs, name, child, path),
            Err(d) => Node::new(name).diag(d),
        };
        cx.push(node.span(span.sub(at, 33))).await;
    }
    let end = HEADER.saturating_add(n.saturating_mul(33));
    if len > end {
        cx.emit(
            Node::new("Unused")
                .span(span.tail(end))
                .summary(size(len.saturating_sub(end))),
        );
    }
    Ok(())
}

fn item_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    key_field(f, "Key")?;
    f.u32("Data offset")
        .desc("From the end of the node header")
        .emit()?;
    f.u32("Data size").emit()?;
    Ok(())
}

async fn item_view(cx: Cx, (head, data, ty): (Span, Span, u8)) -> Result<()> {
    cx.emit(struct_node("Item header", head, LE, (), item_header_layout));
    cx.emit(
        struct_node("Data", data, LE, ty, item_layout)
            .summary(lookup(ITEM_TYPES, ty.into()).unwrap_or("item")),
    );
    Ok(())
}

/// Compares keys `(object id, type, offset)`.
fn key_of(raw: &[u8]) -> (u64, u8, u64) {
    (
        u64_le(raw, 0).unwrap_or(0),
        raw.get(8).copied().unwrap_or(0),
        u64_le(raw, 9).unwrap_or(0),
    )
}

/// Every item with object id `oid` and type `ty` in the tree rooted at
/// `root`: (key offset, item data span).
pub(super) async fn items(
    cx: &Cx,
    fs: &Fs,
    root: u64,
    oid: u64,
    ty: u8,
) -> Result<Vec<(u64, Span)>> {
    let lo = (oid, ty, 0u64);
    let hi = (oid, ty, u64::MAX);
    let mut out = Vec::new();
    let mut stack = vec![(root, 0usize)];
    let mut visited = 0usize;
    while let Some((logical, depth)) = stack.pop() {
        cx.checkpoint().await;
        visited = visited.saturating_add(1);
        if depth > MAX_LEVELS || visited > 65536 {
            return Err(Diagnostic::limit("tree too deep or too large to search"));
        }
        let span = fs
            .node_span(logical)
            .ok_or_else(|| Diagnostic::malformed(format!("node {logical:#x} is not mapped")))?;
        let data = cx.read(span).await?;
        let items = u64::from(u32_le(&data, 0x60).unwrap_or(0));
        let level = data.get(0x64).copied().unwrap_or(0);
        if level == 0 {
            for i in 0..items.min(fs.node_size / 25) {
                let at = to_usize(HEADER.saturating_add(i.saturating_mul(25)));
                let raw = data.get(at..at.saturating_add(25)).unwrap_or_default();
                let k = key_of(raw);
                if k >= lo && k <= hi {
                    let doff = u64::from(u32_le(raw, 17).unwrap_or(0));
                    let dlen = u64::from(u32_le(raw, 21).unwrap_or(0));
                    out.push((k.2, span.sub(HEADER.saturating_add(doff), dlen)));
                    if out.len() >= MAX_ITEMS {
                        return Ok(out);
                    }
                }
            }
            continue;
        }
        let n = items.min(fs.node_size / 33);
        let mut children = Vec::new();
        for i in 0..n {
            let at = to_usize(HEADER.saturating_add(i.saturating_mul(33)));
            let raw = data.get(at..at.saturating_add(33)).unwrap_or_default();
            let k = key_of(raw);
            let next = data
                .get(at.saturating_add(33)..at.saturating_add(50))
                .filter(|_| i.saturating_add(1) < n)
                .map(key_of);
            if k <= hi && next.is_none_or(|nk| nk > lo) {
                children.push((u64_le(raw, 17).unwrap_or(0), depth.saturating_add(1)));
            }
        }
        children.reverse();
        stack.extend(children);
    }
    Ok(out)
}

/// The root node and level of tree `id`, from the root tree.
pub(super) async fn tree_root(
    cx: &Cx,
    fs: &Fs,
    root_tree: u64,
    id: u64,
) -> Result<Option<(u64, u8)>> {
    let found = items(cx, fs, root_tree, id, ROOT_ITEM).await?;
    let Some((_, span)) = found.last() else {
        return Ok(None);
    };
    let raw = cx.read(span.sub(0, 239)).await?;
    Ok(Some((
        u64_le(&raw, 176).unwrap_or(0),
        raw.get(238).copied().unwrap_or(0),
    )))
}
