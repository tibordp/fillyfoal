//! APFS containers.
//!
//! Block 0 holds a copy of the container superblock (`NXSB`); the latest
//! one is in the checkpoint descriptor area. Its object map (a B-tree keyed
//! by object id and transaction id) translates virtual object ids, such as
//! the volume superblocks (`APSB`) and their file-system tree roots, to
//! physical blocks. Every object starts with a Fletcher-64 checksum, which
//! is verified.

use std::cmp::Ordering;
use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{fletcher64, size, uuid_value};
use crate::formats::util::fmt::plural;
use crate::formats::{Codec, Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
/// B-tree depth followed and volumes listed at most.
const MAX_DEPTH: u32 = 12;
const MAX_VOLUMES: usize = 100;
const ROOT: u16 = 1;
const LEAF: u16 = 2;
const FIXED: u16 = 4;

pub static FORMAT: Format = Format {
    name: "apfs",
    title: "APFS container",
    extensions: &["apfs", "img", "dmg"],
    mime: "application/x-apfs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.at(32, b"NXSB") && u32_le(h.data, 24).is_some_and(|t| t & 0xffff == 1)
}

const OBJECT_TYPES: EnumTable = &[
    (0x01, "container superblock"),
    (0x02, "B-tree root"),
    (0x03, "B-tree node"),
    (0x05, "space manager"),
    (0x06, "space manager CAB"),
    (0x07, "space manager CIB"),
    (0x08, "space manager bitmap"),
    (0x09, "space manager free queue"),
    (0x0a, "extent list tree"),
    (0x0b, "object map"),
    (0x0c, "checkpoint map"),
    (0x0d, "volume superblock"),
    (0x0e, "file-system tree"),
    (0x0f, "block reference tree"),
    (0x10, "snapshot metadata tree"),
    (0x11, "reaper"),
    (0x12, "reaper list"),
    (0x13, "object map snapshot"),
    (0x14, "EFI jumpstart"),
    (0x15, "fusion middle tree"),
    (0x16, "fusion write-back cache"),
    (0x17, "fusion write-back cache list"),
    (0x18, "encryption rolling state"),
    (0x19, "general bitmap"),
    (0x1a, "general bitmap tree"),
    (0x1b, "general bitmap block"),
    (0x1c, "encryption rolling recovery block"),
    (0x1d, "snapshot metadata extension"),
    (0x1e, "integrity metadata"),
    (0x1f, "file extent tree"),
];

const OBJECT_FLAGS: FlagTable = &[
    flag(0x8000_0000, "EPHEMERAL"),
    flag(0x4000_0000, "PHYSICAL"),
    flag(0x2000_0000, "NOHEADER"),
    flag(0x1000_0000, "ENCRYPTED"),
    flag(0x0800_0000, "NONPERSISTENT"),
];

fn object_type(v: &u32, n: Node) -> Node {
    let kind = lookup(OBJECT_TYPES, (v & 0xffff).into()).unwrap_or("unknown type");
    let (flags, _) = crate::value::decode_flags(OBJECT_FLAGS, (*v).into());
    if flags.is_empty() {
        n.summary(kind)
    } else {
        n.summary(format!("{kind} ({})", flags.join(", ")))
    }
}

const INCOMPAT: FlagTable = &[
    flag(1, "VERSION1"),
    flag(2, "VERSION2"),
    flag(0x100, "FUSION"),
];

record! {
    /// `nx_superblock_t` up to the volume list.
    pub struct ContainerSuperblock {
        checksum: u64 "Checksum" .hex(),
        oid: u64 "Object id",
        xid: u64 "Transaction id",
        kind: u32 "Object type" .hex() .with(object_type),
        subtype: u32 "Object subtype" .hex(),
        magic: ascii[4] "Magic",
        block_size: u32 "Block size",
        block_count: u64 "Block count",
        features: u64 "Features" .hex(),
        ro_compat: u64 "Read-only compatible features" .hex(),
        incompat: u64 "Incompatible features" .hex() .flags(INCOMPAT),
        uuid: bytes[16] "UUID" .with(uuid_value),
        next_oid: u64 "Next object id",
        next_xid: u64 "Next transaction id",
        desc_blocks: u32 "Checkpoint descriptor blocks",
        data_blocks: u32 "Checkpoint data blocks",
        desc_base: u64 "Checkpoint descriptor base" .hex(),
        data_base: u64 "Checkpoint data base" .hex(),
        desc_next: u32 "Checkpoint descriptor next",
        data_next: u32 "Checkpoint data next",
        desc_index: u32 "Checkpoint descriptor index",
        desc_len: u32 "Checkpoint descriptor length",
        data_index: u32 "Checkpoint data index",
        data_len: u32 "Checkpoint data length",
        spaceman_oid: u64 "Space manager object id",
        omap_oid: u64 "Object map (physical)" .hex(),
        reaper_oid: u64 "Reaper object id",
        test_type: u32 "Test type",
        max_volumes: u32 "Maximum volumes",
    }
}

const ROLES: EnumTable = &[
    (0x0000, "none"),
    (0x0001, "system"),
    (0x0002, "user"),
    (0x0004, "recovery"),
    (0x0008, "virtual memory"),
    (0x0010, "preboot"),
    (0x0020, "installer"),
    (0x0040, "data"),
    (0x0080, "baseband"),
    (0x00c0, "update"),
    (0x0100, "xART"),
    (0x0140, "hardware"),
    (0x0180, "backup"),
    (0x01c0, "sideloaded code"),
    (0x0200, "enterprise"),
    (0x0280, "prelogin"),
];

const VOLUME_INCOMPAT: FlagTable = &[
    flag(1, "CASE_INSENSITIVE"),
    flag(2, "DATALESS_SNAPS"),
    flag(4, "ENC_ROLLED"),
    flag(8, "NORMALIZATION_INSENSITIVE"),
    flag(0x10, "INCOMPLETE_RESTORE"),
    flag(0x20, "SEALED_VOLUME"),
];

fn ns_time(v: &u64, n: Node) -> Node {
    if *v == 0 {
        return n.summary("not set");
    }
    n.value(Value::Timestamp {
        unix_seconds: i64::try_from(*v / 1_000_000_000).unwrap_or(i64::MAX),
    })
}

record! {
    /// `apfs_superblock_t` up to the volume name and role.
    pub struct VolumeSuperblock {
        checksum: u64 "Checksum" .hex(),
        oid: u64 "Object id",
        xid: u64 "Transaction id",
        kind: u32 "Object type" .hex() .with(object_type),
        subtype: u32 "Object subtype" .hex(),
        magic: ascii[4] "Magic",
        index: u32 "Volume index",
        features: u64 "Features" .hex(),
        ro_compat: u64 "Read-only compatible features" .hex(),
        incompat: u64 "Incompatible features" .hex() .flags(VOLUME_INCOMPAT),
        unmounted: u64 "Last unmounted" .with(ns_time),
        reserve_blocks: u64 "Reserved blocks",
        quota_blocks: u64 "Quota blocks",
        allocated: u64 "Allocated blocks",
        crypto: bytes[20] "Metadata crypto state",
        root_tree_type: u32 "Root tree type" .hex() .with(object_type),
        extentref_tree_type: u32 "Extent reference tree type" .hex() .with(object_type),
        snap_meta_tree_type: u32 "Snapshot metadata tree type" .hex() .with(object_type),
        omap_oid: u64 "Object map (physical)" .hex(),
        root_tree_oid: u64 "Root tree (virtual)" .hex(),
        extentref_tree_oid: u64 "Extent reference tree" .hex(),
        snap_meta_tree_oid: u64 "Snapshot metadata tree" .hex(),
        revert_xid: u64 "Revert to transaction",
        revert_sblock: u64 "Revert to superblock",
        next_obj_id: u64 "Next object id",
        files: u64 "Files",
        directories: u64 "Directories",
        symlinks: u64 "Symbolic links",
        other: u64 "Other objects",
        snapshots: u64 "Snapshots",
        blocks_allocated: u64 "Blocks allocated (total)",
        blocks_freed: u64 "Blocks freed (total)",
        uuid: bytes[16] "Volume UUID" .with(uuid_value),
        modified: u64 "Last modified" .with(ns_time),
        fs_flags: u64 "Flags" .hex(),
        formatted_by: ascii[32] "Formatted by",
        formatted_at: u64 "Formatted" .with(ns_time),
        formatted_xid: u64 "Formatted at transaction",
        _modified_by: bytes[384] "Modification history",
        name: ascii[256] "Volume name",
        next_doc_id: u32 "Next document id",
        role: u16 "Role" .enumeration(ROLES),
    }
}

#[derive(Debug)]
struct Container {
    input: Input,
    vol: Span,
    block: u64,
}

impl Container {
    fn block_span(&self, n: u64) -> Span {
        self.vol.sub(n.saturating_mul(self.block), self.block)
    }

    /// Reads block `n` and checks its object checksum.
    async fn object(&self, cx: &Cx, n: u64) -> Result<(Vec<u8>, bool)> {
        let span = self
            .vol
            .sub_exact(n.saturating_mul(self.block), self.block)
            .map_err(|_| Diagnostic::malformed(format!("block {n} is outside the container")))?;
        let data = cx.read(span).await?;
        let ok = u64_le(&data, 0) == Some(fletcher64(&data));
        Ok((data, ok))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(0, ContainerSuperblock::SIZE);
    let sb0 = parse(&cx, span, LE, &(), ContainerSuperblock::layout).await?;
    let block = u64::from(sb0.block_size);
    if !(4096..=65536).contains(&block) || !block.is_power_of_two() {
        return Err(Diagnostic::malformed(format!("block size {block}")).at(span));
    }
    let c = Arc::new(Container { input, vol, block });
    let (_, ok) = c.object(&cx, 0).await?;
    let mut node = ContainerSuperblock::node("Container superblock (block 0)", c.block_span(0), LE)
        .summary(format!("transaction {}", sb0.xid));
    if !ok {
        node = node.diag(Diagnostic::warning("object checksum mismatch"));
    }
    cx.emit(node);

    // The newest valid superblock in the checkpoint descriptor area.
    let mut latest = (sb0.xid, 0u64);
    let desc = (sb0.desc_base, u64::from(sb0.desc_blocks));
    if sb0.desc_blocks & 0x8000_0000 == 0 {
        for i in 0..desc.1.min(65536) {
            let n = desc.0.saturating_add(i);
            let Ok((data, ok)) = c.object(&cx, n).await else {
                break;
            };
            if ok
                && u32_le(&data, 24).is_some_and(|t| t & 0xffff == 1)
                && data.get(32..36) == Some(b"NXSB")
            {
                let xid = u64_le(&data, 16).unwrap_or(0);
                if xid > latest.0 {
                    latest = (xid, n);
                }
            }
        }
        cx.emit(
            Node::new("Checkpoint descriptor area")
                .span(vol.sub(desc.0.saturating_mul(block), desc.1.saturating_mul(block)))
                .summary(plural(desc.1, "block"))
                .lazy(checkpoint_area, (c.clone(), desc.0, desc.1)),
        );
    } else {
        cx.diag(Diagnostic::unsupported(
            "checkpoint descriptor area stored as a B-tree",
        ));
    }
    if sb0.data_blocks & 0x8000_0000 == 0 {
        cx.emit(Node::new("Checkpoint data area").span(vol.sub(
            sb0.data_base.saturating_mul(block),
            u64::from(sb0.data_blocks).saturating_mul(block),
        )));
    }
    let sb_block = latest.1;
    let sb = parse(
        &cx,
        c.block_span(sb_block).sub(0, ContainerSuperblock::SIZE),
        LE,
        &(),
        ContainerSuperblock::layout,
    )
    .await?;
    if sb_block != 0 {
        cx.emit(
            ContainerSuperblock::node("Latest container superblock", c.block_span(sb_block), LE)
                .summary(format!("block {sb_block}, transaction {}", sb.xid)),
        );
    }

    // Volumes: virtual object ids, resolved through the container's object map.
    let oids_span = c.block_span(sb_block).sub(184, 800);
    let raw = cx.read_avail(oids_span).await?;
    let oids: Vec<u64> = raw
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| u64::from_le_bytes(*b))
        .filter(|&o| o != 0)
        .take(MAX_VOLUMES)
        .collect();
    let omap_tree = omap_tree(&cx, &c, sb.omap_oid).await;
    let mut names = Vec::new();
    let mut volumes = Vec::new();
    for oid in &oids {
        let resolved = match &omap_tree {
            Ok(tree) => omap_lookup(&cx, &c, *tree, *oid, sb.xid).await,
            Err(e) => Err(e.clone()),
        };
        match resolved {
            Ok(Some(paddr)) => {
                let v = parse(
                    &cx,
                    c.block_span(paddr).sub(0, VolumeSuperblock::SIZE),
                    LE,
                    &(),
                    VolumeSuperblock::layout,
                )
                .await;
                if let Ok(v) = &v {
                    names.push(v.name.clone());
                }
                volumes.push((*oid, Ok(paddr)));
            }
            Ok(None) => volumes.push((
                *oid,
                Err(Diagnostic::malformed(format!(
                    "object {oid} is not in the object map"
                ))),
            )),
            Err(e) => volumes.push((*oid, Err(e))),
        }
    }
    cx.annotate(format!(
        "APFS container, {}, {}{}",
        size(sb.block_count.saturating_mul(block)),
        plural(crate::bytes::to_u64(oids.len()), "volume"),
        if names.is_empty() {
            String::new()
        } else {
            format!(
                " ({})",
                names
                    .iter()
                    .map(|n| format!("\"{n}\""))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        }
    ));
    cx.emit(
        Node::new("Object map")
            .span(c.block_span(sb.omap_oid))
            .summary(format!("block {}", sb.omap_oid))
            .lazy(object_map, (c.clone(), sb.omap_oid)),
    );
    for (oid, resolved) in volumes {
        let node = Node::new(format!("Volume (object {oid})"));
        cx.emit(match resolved {
            Ok(paddr) => node
                .span(c.block_span(paddr))
                .summary(format!("block {paddr}"))
                .lazy(volume, (c.clone(), paddr)),
            Err(e) => node.diag(e),
        });
    }
    Ok(())
}

async fn checkpoint_area(cx: Cx, (c, base, count): (Arc<Container>, u64, u64)) -> Result<()> {
    for i in 0..count {
        cx.progress(i, count);
        let n = base.saturating_add(i);
        let (data, ok) = c.object(&cx, n).await?;
        let kind = u32_le(&data, 24).unwrap_or(0);
        let xid = u64_le(&data, 16).unwrap_or(0);
        let name = lookup(OBJECT_TYPES, (kind & 0xffff).into()).unwrap_or("unknown object");
        let mut node = Node::new(format!("Block {n}")).span(c.block_span(n));
        node = if kind & 0xffff == 0x0c {
            let maps = u32_le(&data, 36).unwrap_or(0);
            node.summary(format!("{name}, transaction {xid}, {maps} mappings"))
        } else if kind & 0xffff == 1 {
            node.summary(format!("{name}, transaction {xid}"))
                .lazy(superblock_node, c.block_span(n))
        } else {
            node.summary(name)
        };
        if !ok && data.iter().any(|&b| b != 0) {
            node = node.diag(Diagnostic::warning("object checksum mismatch"));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn superblock_node(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, ContainerSuperblock::SIZE)).await?;
    ContainerSuperblock::read(&mut crate::fields::Fields::emitting(&cx, &block, LE))?;
    Ok(())
}

/// The physical root of an object map's B-tree.
async fn omap_tree(cx: &Cx, c: &Container, omap: u64) -> Result<u64> {
    let (data, _) = c.object(cx, omap).await?;
    if u32_le(&data, 24).is_none_or(|t| t & 0xffff != 0x0b) {
        return Err(
            Diagnostic::malformed(format!("block {omap} is not an object map"))
                .at(c.block_span(omap)),
        );
    }
    Ok(u64_le(&data, 48).unwrap_or(0))
}

/// Table-of-contents entries of a B-tree node: (key offset, key length,
/// value offset, value length), all relative to the node.
fn toc(node: &[u8], block: u64, fixed: (usize, usize)) -> Vec<(usize, usize, usize, usize)> {
    let flags = u16_le(node, 32).unwrap_or(0);
    let count = to_usize(u32_le(node, 36).unwrap_or(0).into());
    let table = 56usize.saturating_add(usize::from(u16_le(node, 40).unwrap_or(0)));
    let keys = table.saturating_add(usize::from(u16_le(node, 42).unwrap_or(0)));
    let values_end = to_usize(block).saturating_sub(if flags & ROOT != 0 { 40 } else { 0 });
    let leaf = flags & LEAF != 0;
    let mut out = Vec::new();
    for i in 0..count.min(to_usize(block) / 4) {
        let entry = if flags & FIXED != 0 {
            let at = table.saturating_add(i.saturating_mul(4));
            let (Some(k), Some(v)) = (u16_le(node, at), u16_le(node, at.saturating_add(2))) else {
                break;
            };
            let vlen = if leaf { fixed.1 } else { 8 };
            (
                keys.saturating_add(k.into()),
                fixed.0,
                values_end.saturating_sub(v.into()),
                vlen,
            )
        } else {
            let at = table.saturating_add(i.saturating_mul(8));
            let field = |o: usize| usize::from(u16_le(node, at.saturating_add(o)).unwrap_or(0));
            (
                keys.saturating_add(field(0)),
                field(2),
                values_end.saturating_sub(field(4)),
                field(6),
            )
        };
        out.push(entry);
    }
    out
}

/// Looks up the newest mapping of `oid` not newer than `xid`.
async fn omap_lookup(cx: &Cx, c: &Container, root: u64, oid: u64, xid: u64) -> Result<Option<u64>> {
    let mut n = root;
    let mut seen = HashSet::new();
    for _ in 0..MAX_DEPTH {
        if !seen.insert(n) {
            return Err(Diagnostic::malformed(format!(
                "object map loops at block {n}"
            )));
        }
        let (node, _) = c.object(cx, n).await?;
        let leaf = u16_le(&node, 32).unwrap_or(0) & LEAF != 0;
        let entries = toc(&node, c.block, (16, 16));
        let pick = entries.iter().rev().find(|&&(k, _, _, _)| {
            let ko = u64_le(&node, k).unwrap_or(u64::MAX);
            let kx = u64_le(&node, k.saturating_add(8)).unwrap_or(u64::MAX);
            (ko, kx) <= (oid, xid)
        });
        let Some(&(k, _, v, _)) = pick else {
            return Ok(None);
        };
        if leaf {
            return Ok((u64_le(&node, k) == Some(oid))
                .then(|| u64_le(&node, v.saturating_add(8)).unwrap_or(0)));
        }
        n = u64_le(&node, v).unwrap_or(0);
    }
    Err(Diagnostic::limit("object map deeper than expected"))
}

async fn object_map(cx: Cx, (c, omap): (Arc<Container>, u64)) -> Result<()> {
    let span = c.block_span(omap);
    let data = cx.read(span.sub(0, 88)).await?;
    cx.emit(Node::new("Header").span(span.sub(0, 88)).summary(format!(
        "{} snapshots, tree at block {}",
        u32_le(&data, 36).unwrap_or(0),
        u64_le(&data, 48).unwrap_or(0)
    )));
    let root = u64_le(&data, 48).unwrap_or(0);
    cx.emit(Node::new("Mappings").span(c.block_span(root)).lazy(
        crate::expander!(self::omap_node: (Arc<Container>, u64, u32)),
        (c.clone(), root, MAX_DEPTH),
    ));
    Ok(())
}

async fn omap_node(cx: Cx, (c, n, depth): (Arc<Container>, u64, u32)) -> Result<()> {
    let (node, ok) = c.object(&cx, n).await?;
    if !ok {
        cx.diag(Diagnostic::warning("object checksum mismatch"));
    }
    let span = c.block_span(n);
    let level = u32::from(u16_le(&node, 34).unwrap_or(0));
    if level > depth {
        return Err(
            Diagnostic::malformed(format!("node level {level} does not decrease")).at(span),
        );
    }
    let leaf = level == 0;
    let entries = toc(&node, c.block, (16, 16));
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (k, _, v, vlen) in entries {
        let oid = u64_le(&node, k).unwrap_or(0);
        let xid = u64_le(&node, k.saturating_add(8)).unwrap_or(0);
        let value = span.sub(to_u64(v), to_u64(vlen));
        let item =
            Node::new(format!("Object {oid} @ transaction {xid}")).span(span.sub(to_u64(k), 16));
        cx.push(if leaf {
            let paddr = u64_le(&node, v.saturating_add(8)).unwrap_or(0);
            item.summary(format!("block {paddr}"))
                .target(c.block_span(paddr))
        } else {
            let child = u64_le(&node, v).unwrap_or(0);
            let item = item.summary(format!("child node {child}")).target(value);
            item.lazy(
                crate::expander!(self::omap_node: (Arc<Container>, u64, u32)),
                (c.clone(), child, level.saturating_sub(1)),
            )
        })
        .await;
    }
    Ok(())
}

async fn volume(cx: Cx, (c, paddr): (Arc<Container>, u64)) -> Result<()> {
    let span = c.block_span(paddr);
    let v = parse(
        &cx,
        span.sub(0, VolumeSuperblock::SIZE),
        LE,
        &(),
        VolumeSuperblock::layout,
    )
    .await?;
    let (_, ok) = c.object(&cx, paddr).await?;
    cx.annotate(format!(
        "\"{}\" ({}), {}, {}",
        v.name,
        lookup(ROLES, v.role.into()).unwrap_or("unknown role"),
        plural(v.files, "file"),
        plural(v.directories, "directory")
    ));
    let mut node = VolumeSuperblock::node("Volume superblock", span, LE);
    if !ok {
        node = node.diag(Diagnostic::warning("object checksum mismatch"));
    }
    if v.magic != "APSB" {
        node = node.diag(Diagnostic::malformed("bad volume superblock magic"));
    }
    cx.emit(node);
    let tree = omap_tree(&cx, &c, v.omap_oid).await?;
    cx.emit(
        Node::new("Object map")
            .span(c.block_span(v.omap_oid))
            .lazy(object_map, (c.clone(), v.omap_oid)),
    );
    let fs = Arc::new(FsTree {
        c: c.clone(),
        omap: tree,
        xid: v.xid,
        root: v.root_tree_oid,
        encrypted: v.fs_flags & FS_UNENCRYPTED == 0,
    });
    cx.emit(Node::new("Root directory").summary(v.name.clone()).lazy(
        crate::expander!(self::directory: Dir),
        Dir {
            fs: fs.clone(),
            id: ROOT_DIR,
            ancestors: Arc::new(Vec::new()),
        },
    ));
    cx.emit(
        Node::new("File-system tree")
            .summary(format!("root object {}", v.root_tree_oid))
            .lazy(
                crate::expander!(self::fs_node: (Arc<FsTree>, u64, u32)),
                (fs, v.root_tree_oid, MAX_DEPTH),
            ),
    );
    Ok(())
}

/// `APFS_FS_UNENCRYPTED` in the volume flags.
const FS_UNENCRYPTED: u64 = 1;

#[derive(Debug)]
struct FsTree {
    c: Arc<Container>,
    omap: u64,
    xid: u64,
    /// The tree's root (a virtual object id).
    root: u64,
    /// File extents are encrypted unless the volume says otherwise.
    encrypted: bool,
}

const RECORD_TYPES: EnumTable = &[
    (1, "snapshot metadata"),
    (2, "physical extent"),
    (3, "inode"),
    (4, "extended attribute"),
    (5, "sibling link"),
    (6, "data stream"),
    (7, "crypto state"),
    (8, "file extent"),
    (9, "directory entry"),
    (10, "directory stats"),
    (11, "snapshot name"),
    (12, "sibling map"),
    (13, "file info"),
];

/// A file-system tree node (virtual object id `oid`): its records.
async fn fs_node(cx: Cx, (fs, oid, depth): (Arc<FsTree>, u64, u32)) -> Result<()> {
    let c = &fs.c;
    let paddr = omap_lookup(&cx, c, fs.omap, oid, fs.xid)
        .await?
        .ok_or_else(|| {
            Diagnostic::malformed(format!("object {oid} is not in the volume's object map"))
        })?;
    let (node, ok) = c.object(&cx, paddr).await?;
    if !ok {
        cx.diag(Diagnostic::warning("object checksum mismatch"));
    }
    let span = c.block_span(paddr);
    let level = u32::from(u16_le(&node, 34).unwrap_or(0));
    if level > depth {
        return Err(
            Diagnostic::malformed(format!("node level {level} does not decrease")).at(span),
        );
    }
    let leaf = level == 0;
    let entries = toc(&node, c.block, (0, 0));
    cx.annotate(format!(
        "block {paddr}, level {}, {}",
        u16_le(&node, 34).unwrap_or(0),
        plural(entries.len(), "record")
    ));
    for (k, klen, v, vlen) in entries {
        let header = u64_le(&node, k).unwrap_or(0);
        let id = header & 0x0fff_ffff_ffff_ffff;
        let kind = header >> 60;
        let kind_name = lookup(RECORD_TYPES, kind).unwrap_or("unknown record");
        let value = span.sub(to_u64(v), to_u64(vlen));
        let mut item =
            Node::new(format!("{id}: {kind_name}")).span(span.sub(to_u64(k), to_u64(klen)));
        if !leaf {
            let child = u64_le(&node, v).unwrap_or(0);
            item = item.summary(format!("child object {child}")).lazy(
                crate::expander!(self::fs_node: (Arc<FsTree>, u64, u32)),
                (fs.clone(), child, level.saturating_sub(1)),
            );
        } else {
            item = item.target(value);
            match kind {
                9 => {
                    // Hashed directory entry key: length (10 bits) and hash, name.
                    let len =
                        to_usize((u32_le(&node, k.saturating_add(8)).unwrap_or(0) & 0x3ff).into());
                    let name = crate::text::until_nul(
                        node.get(k.saturating_add(12)..k.saturating_add(12).saturating_add(len))
                            .unwrap_or_default(),
                    );
                    let file = u64_le(&node, v).unwrap_or(0);
                    item = item
                        .value(Value::Text(name))
                        .summary(format!("→ inode {file}"));
                }
                3 => {
                    let parent = u64_le(&node, v).unwrap_or(0);
                    let mode = u16_le(&node, v.saturating_add(80)).unwrap_or(0);
                    item = item.summary(format!(
                        "{}, parent {parent}",
                        crate::formats::disk::unix_mode(mode.into())
                    ));
                }
                8 => {
                    let logical = u64_le(&node, k.saturating_add(8)).unwrap_or(0);
                    let len = u64_le(&node, v).unwrap_or(0) & 0x00ff_ffff_ffff_ffff;
                    let block = u64_le(&node, v.saturating_add(8)).unwrap_or(0);
                    let crypto = u64_le(&node, v.saturating_add(16)).unwrap_or(0);
                    if block == 0 {
                        item = item.summary(format!("offset {logical:#x}: {} hole", size(len)));
                    } else if fs.encrypted && crypto != 0 {
                        item = item
                            .summary(format!(
                                "offset {logical:#x}: {} at block {block}, encrypted",
                                size(len)
                            ))
                            .diag(Diagnostic::unsupported("encrypted file extent"));
                    } else {
                        let data = c.vol.sub(block.saturating_mul(c.block), len);
                        // The extent's bytes, dissected on expansion.
                        item = crate::formats::content(
                            format!("{id}: {kind_name}"),
                            c.input,
                            data,
                            Codec::Stored,
                            None,
                        )
                        .summary(format!(
                            "offset {logical:#x}: {} at block {block}",
                            size(len)
                        ));
                    }
                }
                _ => {}
            }
        }
        cx.push(item).await;
    }
    Ok(())
}

// The directory view: directory entries (`j_drec_hashed_key_t`) of a
// directory's inode id, each file's inode (`j_inode_val_t`) and its data
// stream assembled from the file extents keyed by the stream's private id,
// with holes where no extent (or block 0) maps it. Extended attributes
// (`j_xattr_val_t`) are embedded or kept in a data stream of their own;
// `com.apple.decmpfs` and `com.apple.ResourceFork` give compressed files
// their content (see `decmpfs`). Layouts from Apple's "APFS Reference".

/// Inode number of the root directory.
const ROOT_DIR: u64 = 2;
/// Record types of the file-system tree.
const INODE: u8 = 3;
const XATTR: u8 = 4;
const FILE_EXTENT: u8 = 8;
const DIR_REC: u8 = 9;
/// Tree nodes visited for one lookup at most, folder depth.
const MAX_NODES: usize = 1 << 20;
const MAX_DIR_DEPTH: usize = 64;

/// A leaf record of the file-system tree.
#[derive(Clone, Debug)]
struct FsRec {
    paddr: u64,
    node: Arc<Vec<u8>>,
    k: usize,
    klen: usize,
    v: usize,
    vlen: usize,
}

impl FsRec {
    fn value_span(&self, c: &Container) -> Span {
        c.block_span(self.paddr)
            .sub(to_u64(self.v), to_u64(self.vlen))
    }

    fn key_span(&self, c: &Container) -> Span {
        c.block_span(self.paddr)
            .sub(to_u64(self.k), to_u64(self.klen))
    }

    fn u64_at(&self, at: usize) -> u64 {
        u64_le(&self.node, self.v.saturating_add(at)).unwrap_or(0)
    }
}

/// The (object id, record type) of the key at `k`.
fn key_of(node: &[u8], k: usize) -> (u64, u8) {
    let header = u64_le(node, k).unwrap_or(0);
    (
        header & 0x0fff_ffff_ffff_ffff,
        u8::try_from(header >> 60).unwrap_or(0),
    )
}

/// The records of object `oid` of type `kind`, in key order: an in-order
/// walk of the subtrees whose key range can hold them (APFS nodes have no
/// sibling links).
async fn fs_records(cx: &Cx, fs: &FsTree, oid: u64, kind: u8) -> Result<Vec<FsRec>> {
    let want = (oid, kind);
    let mut out = Vec::new();
    let mut stack = vec![(fs.root, MAX_DEPTH)];
    let mut seen = HashSet::new();
    while let Some((vid, depth)) = stack.pop() {
        let paddr = omap_lookup(cx, &fs.c, fs.omap, vid, fs.xid)
            .await?
            .ok_or_else(|| {
                Diagnostic::malformed(format!("object {vid} is not in the volume's object map"))
            })?;
        if !seen.insert(paddr) || seen.len() > MAX_NODES {
            return Err(Diagnostic::malformed(format!(
                "file-system tree loops at block {paddr}"
            )));
        }
        let (node, _) = fs.c.object(cx, paddr).await?;
        let node = Arc::new(node);
        let level = u32::from(u16_le(&node, 34).unwrap_or(0));
        if level > depth {
            return Err(
                Diagnostic::malformed(format!("node level {level} does not decrease"))
                    .at(fs.c.block_span(paddr)),
            );
        }
        let entries = toc(&node, fs.c.block, (0, 0));
        if level == 0 {
            for &(k, klen, v, vlen) in &entries {
                match key_of(&node, k).cmp(&want) {
                    Ordering::Less => {}
                    Ordering::Equal => out.push(FsRec {
                        paddr,
                        node: node.clone(),
                        k,
                        klen,
                        v,
                        vlen,
                    }),
                    Ordering::Greater => break,
                }
            }
            continue;
        }
        // Child i holds keys from its own up to the next child's: it can
        // hold `want` if its key is not above it and the next one not below.
        let mut children = Vec::new();
        for (i, &(k, _, v, _)) in entries.iter().enumerate() {
            if key_of(&node, k) > want {
                break;
            }
            let next_below = entries
                .get(i.saturating_add(1))
                .is_some_and(|&(nk, _, _, _)| key_of(&node, nk) < want);
            if !next_below {
                children.push(u64_le(&node, v).unwrap_or(0));
            }
        }
        // Depth first, in key order.
        for child in children.into_iter().rev() {
            stack.push((child, level.saturating_sub(1)));
        }
        cx.checkpoint().await;
    }
    Ok(out)
}

#[derive(Clone)]
struct Dir {
    fs: Arc<FsTree>,
    id: u64,
    ancestors: Arc<Vec<u64>>,
}

/// `DT_*` file types in directory entry flags.
const DT_DIR: u16 = 4;
const DT_REG: u16 = 8;
const DT_LNK: u16 = 10;

async fn directory(cx: Cx, d: Dir) -> Result<()> {
    let fs = d.fs.clone();
    let c = &fs.c;
    match inode(&cx, &fs, d.id).await {
        Ok(Some((_, rec))) => cx.emit(InodeVal::node("Inode", rec.value_span(c), LE)),
        Ok(None) => {}
        Err(e) => cx.diag(e),
    }
    match xattrs(&cx, &fs, d.id).await {
        Ok(attrs) if !attrs.is_empty() => cx.emit(xattrs_node(&fs, attrs)),
        Ok(_) => {}
        Err(e) => cx.diag(e),
    }
    let mut ancestors = (*d.ancestors).clone();
    ancestors.push(d.id);
    let ancestors = Arc::new(ancestors);
    let entries = fs_records(&cx, &fs, d.id, DIR_REC).await?;
    for e in entries {
        let len = to_usize((u32_le(&e.node, e.k.saturating_add(8)).unwrap_or(0) & 0x3ff).into());
        let name = crate::text::until_nul(
            e.node
                .get(e.k.saturating_add(12)..e.k.saturating_add(12).saturating_add(len))
                .unwrap_or_default(),
        );
        let file = e.u64_at(0);
        let dtype = u16_le(&e.node, e.v.saturating_add(16)).unwrap_or(0) & 0xf;
        let node = Node::new(name).span(e.key_span(c));
        let node = match dtype {
            DT_DIR if ancestors.contains(&file) || ancestors.len() > MAX_DIR_DEPTH => node
                .summary("directory")
                .diag(Diagnostic::malformed(format!(
                    "directory {file} contains itself; not followed"
                ))),
            DT_DIR => node.summary("directory").lazy(
                crate::expander!(self::directory: Dir),
                Dir {
                    fs: fs.clone(),
                    id: file,
                    ancestors: ancestors.clone(),
                },
            ),
            _ => node
                .summary(match dtype {
                    DT_REG => "file",
                    DT_LNK => "symbolic link",
                    1 => "FIFO",
                    2 => "character device",
                    6 => "block device",
                    12 => "socket",
                    _ => "other",
                })
                .lazy(file_node, (fs.clone(), file)),
        };
        cx.push(node).await;
    }
    Ok(())
}

record! {
    /// `j_inode_val_t` up to its extended fields.
    pub struct InodeVal {
        parent: u64 "Parent id",
        private_id: u64 "Data stream id",
        created: u64 "Created" .with(ns_time),
        modified: u64 "Content modified" .with(ns_time),
        changed: u64 "Attributes modified" .with(ns_time),
        accessed: u64 "Accessed" .with(ns_time),
        internal_flags: u64 "Internal flags" .hex(),
        links: u32 "Children / links",
        protection_class: u32 "Protection class",
        generation: u32 "Write generation",
        bsd_flags: u32 "BSD flags" .hex(),
        owner: u32 "Owner id",
        group: u32 "Group id",
        mode: u16 "Mode" .with(|&m, n| n.summary(crate::formats::disk::unix_mode(m.into()))),
        _pad: u16 "Padding",
        uncompressed_size: u64 "Uncompressed size",
    }
}

/// An inode's fields that decide how to show it.
#[derive(Clone, Debug, Default)]
struct InodeInfo {
    private_id: u64,
    bsd_flags: u32,
    mode: u16,
    /// The data stream's logical size (`INO_EXT_TYPE_DSTREAM`).
    size: Option<u64>,
}

/// `INO_EXT_TYPE_DSTREAM` in the inode's extended fields.
const INO_EXT_DSTREAM: u8 = 8;

/// The offset of the extended field of `kind` in the `xf_blob_t` at `at`.
fn xfield(b: &[u8], at: usize, kind: u8) -> Option<usize> {
    let count = usize::from(u16_le(b, at)?);
    let mut data = at.saturating_add(4).saturating_add(count.saturating_mul(4));
    for i in 0..count.min(64) {
        let h = at.saturating_add(4).saturating_add(i.saturating_mul(4));
        let t = *b.get(h)?;
        let len = usize::from(u16_le(b, h.saturating_add(2))?);
        if t == kind {
            return Some(data);
        }
        data = data.saturating_add(len.div_ceil(8).saturating_mul(8));
    }
    None
}

async fn inode(cx: &Cx, fs: &FsTree, id: u64) -> Result<Option<(InodeInfo, FsRec)>> {
    let Some(rec) = fs_records(cx, fs, id, INODE).await?.into_iter().next() else {
        return Ok(None);
    };
    let b = rec
        .node
        .get(rec.v..rec.v.saturating_add(rec.vlen))
        .unwrap_or_default();
    let info = InodeInfo {
        private_id: u64_le(b, 8).unwrap_or(0),
        bsd_flags: u32_le(b, 68).unwrap_or(0),
        mode: u16_le(b, 80).unwrap_or(0),
        size: xfield(b, 92, INO_EXT_DSTREAM).and_then(|at| u64_le(b, at)),
    };
    Ok(Some((info, rec)))
}

/// A data stream (`private_id`, `size` bytes) assembled from its extents.
async fn stream(cx: &Cx, fs: &FsTree, anchor: Span, private_id: u64, size: u64) -> Result<Span> {
    let c = &fs.c;
    let mut list = crate::formats::disk::PieceList::new(anchor);
    let mut encrypted = false;
    for (i, e) in fs_records(cx, fs, private_id, FILE_EXTENT)
        .await?
        .into_iter()
        .enumerate()
    {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        let logical = u64_le(&e.node, e.k.saturating_add(8)).unwrap_or(0);
        let len = e.u64_at(0) & 0x00ff_ffff_ffff_ffff;
        let phys = e.u64_at(8);
        let crypto = e.u64_at(16);
        if logical < list.len() || logical >= size {
            continue;
        }
        list.hole(cx, logical.saturating_sub(list.len()))?;
        let len = len.min(size.saturating_sub(logical));
        if phys == 0 {
            list.hole(cx, len)?;
        } else if fs.encrypted && crypto != 0 {
            encrypted = true;
            list.hole(cx, len)?;
        } else {
            list.data(c.vol.sub(phys.saturating_mul(c.block), len));
        }
    }
    list.hole(cx, size.saturating_sub(list.len()))?;
    if encrypted {
        cx.diag(Diagnostic::unsupported(
            "encrypted file extents (read as zeros)",
        ));
    }
    list.finish(cx, "apfs-extents").await
}

/// An extended attribute.
#[derive(Clone, Debug)]
struct Xattr {
    name: String,
    record: Span,
    value: XattrValue,
}

#[derive(Clone, Debug)]
enum XattrValue {
    /// `XATTR_DATA_EMBEDDED`: the value in the record.
    Embedded(Span),
    /// `XATTR_DATA_STREAM`: a data stream of its own (id, size).
    Stream(u64, u64),
}

impl Xattr {
    fn size(&self) -> u64 {
        match self.value {
            XattrValue::Embedded(s) => s.len,
            XattrValue::Stream(_, n) => n,
        }
    }

    async fn data(&self, cx: &Cx, fs: &FsTree) -> Result<Span> {
        match self.value {
            XattrValue::Embedded(s) => Ok(s),
            XattrValue::Stream(id, size) => stream(cx, fs, self.record, id, size).await,
        }
    }
}

async fn xattrs(cx: &Cx, fs: &FsTree, id: u64) -> Result<Vec<Xattr>> {
    let mut out = Vec::new();
    for r in fs_records(cx, fs, id, XATTR).await? {
        let len = usize::from(u16_le(&r.node, r.k.saturating_add(8)).unwrap_or(0));
        let name = crate::text::until_nul(
            r.node
                .get(r.k.saturating_add(10)..r.k.saturating_add(10).saturating_add(len))
                .unwrap_or_default(),
        );
        let flags = u16_le(&r.node, r.v).unwrap_or(0);
        let xlen = u16_le(&r.node, r.v.saturating_add(2)).unwrap_or(0);
        let value = if flags & 1 != 0 {
            // `j_xattr_dstream_t`: the stream's id, then its `j_dstream_t`.
            XattrValue::Stream(r.u64_at(4), r.u64_at(12))
        } else {
            XattrValue::Embedded(r.value_span(&fs.c).sub(4, xlen.into()))
        };
        out.push(Xattr {
            name,
            record: r.key_span(&fs.c),
            value,
        });
    }
    Ok(out)
}

fn xattrs_node(fs: &Arc<FsTree>, attrs: Vec<Xattr>) -> Node {
    Node::new("Extended attributes")
        .summary(plural(to_u64(attrs.len()), "attribute"))
        .lazy(xattrs_list, (fs.clone(), Arc::new(attrs)))
}

async fn xattrs_list(cx: Cx, (fs, attrs): (Arc<FsTree>, Arc<Vec<Xattr>>)) -> Result<()> {
    for a in attrs.iter() {
        let node = match a.data(&cx, &fs).await {
            Ok(data) => {
                crate::formats::content(a.name.clone(), fs.c.input, data, Codec::Stored, None)
            }
            Err(e) => Node::new(a.name.clone()).span(a.record).diag(e),
        };
        cx.push(node.summary(size(a.size()))).await;
    }
    Ok(())
}

/// A file: its inode, content (decompressed if need be), attributes.
async fn file_node(cx: Cx, (fs, id): (Arc<FsTree>, u64)) -> Result<()> {
    use crate::formats::disk::{content_node, decmpfs};
    let c = &fs.c;
    let (info, rec) = inode(&cx, &fs, id)
        .await?
        .ok_or_else(|| Diagnostic::malformed(format!("no inode {id}")))?;
    let value = rec.value_span(c);
    cx.emit(InodeVal::node("Inode", value, LE).summary(format!("inode {id}")));
    let attrs = match xattrs(&cx, &fs, id).await {
        Ok(a) => a,
        Err(e) => {
            cx.diag(e);
            Vec::new()
        }
    };
    let find = |name: &str| attrs.iter().find(|a| a.name == name);
    if info.mode & 0o170_000 == 0o120_000
        && let Some(a) = find("com.apple.fs.symlink")
    {
        let target = cx.read(a.data(&cx, &fs).await?).await?;
        cx.emit(
            Node::new("Target")
                .span(a.data(&cx, &fs).await?)
                .value(Value::Text(crate::text::until_nul(&target))),
        );
    }
    if let Some(size) = info.size {
        let span = stream(&cx, &fs, value, info.private_id, size).await?;
        cx.emit(content_node(&c.input, span));
    }
    if info.bsd_flags & decmpfs::UF_COMPRESSED != 0 {
        match find(decmpfs::XATTR) {
            Some(a) => {
                let attr = a.data(&cx, &fs).await?;
                let rsrc = match find("com.apple.ResourceFork") {
                    Some(r) => Some(r.data(&cx, &fs).await?),
                    None => None,
                };
                match decmpfs::content(&cx, attr, rsrc).await {
                    Ok((h, span)) => {
                        cx.emit(decmpfs::header_node(attr, &h));
                        cx.emit(content_node(&c.input, span).summary(format!(
                            "{}, decompressed ({})",
                            size(span.len),
                            h.kind_name()
                        )));
                    }
                    Err(e) => cx.diag(e),
                }
            }
            None => cx.diag(Diagnostic::malformed(
                "compressed, but there is no com.apple.decmpfs attribute",
            )),
        }
    }
    if !attrs.is_empty() {
        cx.emit(xattrs_node(&fs, attrs));
    }
    Ok(())
}
