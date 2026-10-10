//! APFS containers.
//!
//! Block 0 holds a copy of the container superblock (`NXSB`); the latest
//! one is in the checkpoint descriptor area. Its object map (a B-tree keyed
//! by object id and transaction id) translates virtual object ids, such as
//! the volume superblocks (`APSB`) and their file-system tree roots, to
//! physical blocks. Every object starts with a Fletcher-64 checksum, which
//! is verified.

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
                .summary(format!("{} blocks", desc.1))
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
        "\"{}\" ({}), {} files, {} directories",
        v.name,
        lookup(ROLES, v.role.into()).unwrap_or("unknown role"),
        v.files,
        v.directories
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
    let fs = FsTree {
        c: c.clone(),
        omap: tree,
        xid: v.xid,
    };
    cx.emit(
        Node::new("File-system tree")
            .summary(format!("root object {}", v.root_tree_oid))
            .lazy(
                crate::expander!(self::fs_node: (Arc<FsTree>, u64, u32)),
                (Arc::new(fs), v.root_tree_oid, MAX_DEPTH),
            ),
    );
    Ok(())
}

#[derive(Debug)]
struct FsTree {
    c: Arc<Container>,
    omap: u64,
    xid: u64,
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
        "block {paddr}, level {}, {} records",
        u16_le(&node, 34).unwrap_or(0),
        entries.len()
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
                _ => {}
            }
        }
        cx.push(item).await;
    }
    Ok(())
}
