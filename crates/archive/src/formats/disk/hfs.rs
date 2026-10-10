//! HFS+ and HFSX volumes (and the classic HFS wrapper around them).
//!
//! The volume header at 1 KiB describes the special files as forks of up
//! to eight extents. The catalog file is a B-tree keyed by (parent id,
//! name); a folder's children are found by descending to the folder's
//! thread record and walking the leaf chain. Folders are lazy, paged
//! trees; file content is assembled from the data fork's extents.

use std::collections::HashSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{assemble, coalesce, content_node, fragments_node, size, unix_mode};
use crate::formats::util::finder::FINDER_FLAGS;
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const BE: Endian = Endian::Big;
const HEADER: u64 = 1024;
const ROOT_FOLDER: u32 = 2;
/// B-tree depth and leaf chain length followed before assuming corruption.
const MAX_DEPTH: u32 = 16;
const MAX_LEAVES: usize = 1 << 16;
const MAX_FOLDER_DEPTH: usize = 64;

pub static FORMAT: Format = Format {
    name: "hfsplus",
    title: "HFS+ / HFSX volume",
    extensions: &["hfs", "hfsx", "img", "dmg"],
    mime: "application/x-hfsplus",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let sig = h.data.get(1024..1026);
    let version = u16_be(h.data, 1026).unwrap_or(0);
    match sig {
        Some(b"H+") => version == 4,
        Some(b"HX") => version == 5,
        // Classic HFS: plausible allocation block size.
        Some(b"BD") => u32_be(h.data, 1024 + 20).is_some_and(|s| s >= 512 && s % 512 == 0),
        _ => false,
    }
}

const ATTRIBUTES: FlagTable = &[
    flag(1 << 7, "UNMOUNTED"),
    flag(1 << 8, "SPARED_BLOCKS"),
    flag(1 << 9, "NO_CACHE_REQUIRED"),
    flag(1 << 10, "BOOT_VOLUME_INCONSISTENT"),
    flag(1 << 11, "CATALOG_NODE_IDS_REUSED"),
    flag(1 << 13, "JOURNALED"),
    flag(1 << 15, "SOFTWARE_LOCK"),
];

fn hfs_time(v: &u32, node: Node) -> Node {
    if *v == 0 {
        return node.summary("not set");
    }
    node.value(Value::Timestamp {
        unix_seconds: crate::text::mac_to_unix((*v).into()),
    })
}

record! {
    /// `HFSPlusVolumeHeader`, without the five special file forks.
    pub struct VolumeHeader {
        signature: ascii[2] "Signature",
        version: u16 "Version",
        attributes: u32 "Attributes" .hex() .flags(ATTRIBUTES),
        last_mounted: ascii[4] "Last mounted version",
        journal_info: u32 "Journal info block",
        created: u32 "Created (local time)" .with(hfs_time),
        modified: u32 "Modified" .with(hfs_time),
        backup: u32 "Backed up" .with(hfs_time),
        checked: u32 "Checked" .with(hfs_time),
        files: u32 "Files",
        folders: u32 "Folders",
        block_size: u32 "Allocation block size",
        total_blocks: u32 "Total blocks",
        free_blocks: u32 "Free blocks",
        next_allocation: u32 "Next allocation",
        rsrc_clump: u32 "Resource fork clump size",
        data_clump: u32 "Data fork clump size",
        next_catalog_id: u32 "Next catalog id",
        write_count: u32 "Write count",
        encodings: u64 "Encodings bitmap" .hex(),
        finder_info: bytes[32] "Finder info",
    }
}

record! {
    /// `HFSPlusForkData`: size and the first eight extents.
    pub struct ForkData {
        logical_size: u64 "Logical size" .with(|&v, n| n.summary(size(v))),
        clump_size: u32 "Clump size",
        total_blocks: u32 "Total blocks",
        extents: bytes[64] "Extents" .with(|b, n| n.summary(extents_text(b))),
    }
}

fn extents_text(b: &[u8]) -> String {
    let list: Vec<String> = b
        .as_chunks::<8>()
        .0
        .iter()
        .map(|e| (u32_be(e, 0).unwrap_or(0), u32_be(e, 4).unwrap_or(0)))
        .filter(|&(_, n)| n != 0)
        .map(|(s, n)| format!("{n} at {s}"))
        .collect();
    if list.is_empty() {
        "none".to_owned()
    } else {
        list.join(", ")
    }
}

const SPECIAL_FILES: [&str; 5] = [
    "Allocation file",
    "Extents overflow file",
    "Catalog file",
    "Attributes file",
    "Startup file",
];

/// A fork: logical size and extents (start block, block count).
#[derive(Clone, Debug)]
struct Fork {
    size: u64,
    blocks: u32,
    extents: Vec<(u32, u32)>,
}

impl Fork {
    fn parse(b: &[u8]) -> Fork {
        Fork {
            size: u64_be(b, 0).unwrap_or(0),
            blocks: u32_be(b, 12).unwrap_or(0),
            extents: b
                .get(16..80)
                .unwrap_or_default()
                .as_chunks::<8>()
                .0
                .iter()
                .map(|e| (u32_be(e, 0).unwrap_or(0), u32_be(e, 4).unwrap_or(0)))
                .take_while(|&(_, n)| n != 0)
                .collect(),
        }
    }

    /// The fork's bytes as pieces of the volume, clipped to its size.
    fn pieces(&self, vol: &Volume) -> Vec<Span> {
        let pieces = self.extents.iter().map(|&(start, count)| {
            vol.span.sub(
                u64::from(start).saturating_mul(vol.block),
                u64::from(count).saturating_mul(vol.block),
            )
        });
        coalesce(pieces, self.size)
    }

    fn overflowed(&self) -> bool {
        self.extents.iter().map(|&(_, n)| u64::from(n)).sum::<u64>() < u64::from(self.blocks)
    }
}

#[derive(Debug)]
struct Volume {
    input: Input,
    span: Span,
    block: u64,
    catalog: Vec<Span>,
    node_size: u64,
    root: u32,
}

type Vol = Arc<Volume>;

impl Volume {
    /// Reads B-tree node `n` of the catalog (which may straddle extents).
    async fn node(&self, cx: &Cx, n: u32) -> Result<Vec<u8>> {
        let mut want = u64::from(n).saturating_mul(self.node_size);
        let mut left = self.node_size;
        let mut out = Vec::new();
        for piece in &self.catalog {
            if left == 0 {
                break;
            }
            if want >= piece.len {
                want = want.saturating_sub(piece.len);
                continue;
            }
            let part = piece.sub(want, left);
            out.extend(cx.read(part).await?);
            left = left.saturating_sub(part.len);
            want = 0;
        }
        if left > 0 {
            return Err(Diagnostic::malformed(format!(
                "catalog node {n} lies outside the catalog file"
            )));
        }
        Ok(out)
    }

    /// The volume span of byte `offset` of catalog node `n` (for provenance).
    fn node_span(&self, n: u32, offset: u64, len: u64) -> Span {
        let mut want = u64::from(n)
            .saturating_mul(self.node_size)
            .saturating_add(offset);
        for piece in &self.catalog {
            if want < piece.len {
                return piece.sub(want, len);
            }
            want = want.saturating_sub(piece.len);
        }
        self.span.sub(0, 0)
    }
}

record! {
    /// `BTNodeDescriptor`.
    pub struct NodeDescriptor {
        next: u32 "Next node",
        prev: u32 "Previous node",
        kind: u8 "Kind" .enumeration(NODE_KINDS),
        height: u8 "Height",
        records: u16 "Records",
        _reserved: u16 "Reserved",
    }
}

const NODE_KINDS: EnumTable = &[(0xff, "leaf"), (0, "index"), (1, "header"), (2, "map")];

record! {
    /// `BTHeaderRec`.
    pub struct BTreeHeader {
        depth: u16 "Tree depth",
        root: u32 "Root node",
        leaf_records: u32 "Leaf records",
        first_leaf: u32 "First leaf node",
        last_leaf: u32 "Last leaf node",
        node_size: u16 "Node size",
        max_key: u16 "Maximum key length",
        total_nodes: u32 "Total nodes",
        free_nodes: u32 "Free nodes",
        _reserved: u16 "Reserved",
        clump_size: u32 "Clump size",
        btree_type: u8 "B-tree type",
        compare: u8 "Key compare type" .hex() .enumeration(COMPARE),
        attributes: u32 "Attributes" .hex() .flags(BTREE_ATTRS),
    }
}

const COMPARE: EnumTable = &[(0xcf, "case folding"), (0xbc, "binary")];
const BTREE_ATTRS: FlagTable = &[
    flag(1, "BAD_CLOSE"),
    flag(2, "BIG_KEYS"),
    flag(4, "VARIABLE_INDEX_KEYS"),
];

record! {
    /// `HFSPlusCatalogFolder`.
    pub struct FolderRecord {
        kind: u16 "Record type",
        flags: u16 "Flags" .hex(),
        valence: u32 "Items",
        id: u32 "Folder id",
        created: u32 "Created" .with(hfs_time),
        modified: u32 "Content modified" .with(hfs_time),
        attr_modified: u32 "Attributes modified" .with(hfs_time),
        accessed: u32 "Accessed" .with(hfs_time),
        backup: u32 "Backed up" .with(hfs_time),
        owner: u32 "Owner id",
        group: u32 "Group id",
        admin_flags: u8 "Admin flags" .hex(),
        owner_flags: u8 "Owner flags" .hex(),
        mode: u16 "Mode" .with(|&m, n| n.summary(unix_mode(m.into()))),
        special: u32 "Special",
        user_info: bytes[16] "Finder user info",
        finder_info: bytes[16] "Finder info",
        encoding: u32 "Text encoding",
    }
}

record! {
    /// `HFSPlusCatalogFile` up to its forks.
    pub struct FileRecord {
        kind: u16 "Record type",
        flags: u16 "Flags" .hex(),
        _reserved: u32 "Reserved",
        id: u32 "File id",
        created: u32 "Created" .with(hfs_time),
        modified: u32 "Content modified" .with(hfs_time),
        attr_modified: u32 "Attributes modified" .with(hfs_time),
        accessed: u32 "Accessed" .with(hfs_time),
        backup: u32 "Backed up" .with(hfs_time),
        owner: u32 "Owner id",
        group: u32 "Group id",
        admin_flags: u8 "Admin flags" .hex(),
        owner_flags: u8 "Owner flags" .hex(),
        mode: u16 "Mode" .with(|&m, n| n.summary(unix_mode(m.into()))),
        special: u32 "Special (link count / device)",
        file_type: ascii[4] "File type",
        creator: ascii[4] "Creator",
        finder_flags: u16 "Finder flags" .hex() .flags(FINDER_FLAGS),
        _location: bytes[6] "Finder location",
        finder_info: bytes[16] "Extended Finder info",
        encoding: u32 "Text encoding",
        _reserved2: u32 "Reserved",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let sig = cx.read(vol.sub(HEADER, 2)).await?;
    if sig == b"BD" {
        return hfs_wrapper(&cx, input).await;
    }
    let span = vol.sub(HEADER, VolumeHeader::SIZE);
    let h = parse(&cx, span, BE, &(), VolumeHeader::layout).await?;
    cx.emit(Node::new("Boot blocks").span(vol.sub(0, HEADER)));
    cx.emit(VolumeHeader::node(
        "Volume header",
        vol.sub(HEADER, 512),
        BE,
    ));
    let forks = cx
        .read_avail(vol.sub(
            HEADER.saturating_add(VolumeHeader::SIZE),
            5 * ForkData::SIZE,
        ))
        .await?;
    for (i, name) in SPECIAL_FILES.iter().enumerate() {
        let at = HEADER
            .saturating_add(VolumeHeader::SIZE)
            .saturating_add(to_u64(i).saturating_mul(ForkData::SIZE));
        cx.emit(ForkData::node(*name, vol.sub(at, ForkData::SIZE), BE));
    }
    let block = u64::from(h.block_size);
    let kind = if h.signature == "HX" { "HFSX" } else { "HFS+" };
    let journaled = if h.attributes & (1 << 13) != 0 {
        "journaled "
    } else {
        ""
    };
    if !block.is_power_of_two() || block < 512 {
        return Err(Diagnostic::malformed(format!("allocation block size {block}")).at(span));
    }
    let catalog_fork = Fork::parse(forks.get(160..240).unwrap_or_default());
    let mut volume = Volume {
        input,
        span: vol,
        block,
        catalog: Vec::new(),
        node_size: 0,
        root: ROOT_FOLDER,
    };
    volume.catalog = catalog_fork.pieces(&volume);
    if catalog_fork.overflowed() {
        cx.diag(Diagnostic::unsupported(
            "catalog extents in the overflow file are not followed",
        ));
    }
    // The header node is node 0; its size is in the header record.
    let first = volume.catalog.first().copied().unwrap_or(vol.sub(0, 0));
    let header_rec = first.sub(14, BTreeHeader::SIZE);
    let bt = parse(&cx, header_rec, BE, &(), BTreeHeader::layout).await?;
    volume.node_size = u64::from(bt.node_size);
    let volume_name = folder_name(&cx, &volume, bt.root, bt.depth)
        .await
        .unwrap_or_default();
    cx.annotate(format!(
        "{journaled}{kind} volume{}, {} ({} files, {} folders)",
        if volume_name.is_empty() {
            String::new()
        } else {
            format!(" \"{volume_name}\"")
        },
        size(u64::from(h.total_blocks).saturating_mul(block)),
        h.files,
        h.folders
    ));
    if !(512..=32768).contains(&volume.node_size) || !volume.node_size.is_power_of_two() {
        return Err(
            Diagnostic::malformed(format!("catalog node size {}", volume.node_size)).at(header_rec),
        );
    }
    let fs: Vol = Arc::new(volume);
    cx.emit(
        Node::new("Catalog B-tree header")
            .span(first.sub(0, fs.node_size))
            .lazy(btree_header, first),
    );
    cx.emit(Node::new("Root folder").summary(volume_name).lazy(
        crate::expander!(self::folder: Folder),
        Folder {
            vol: fs.clone(),
            id: fs.root,
            tree: (bt.root, bt.depth.into()),
            record: None,
            ancestors: Arc::new(Vec::new()),
        },
    ));
    if h.journal_info != 0 {
        cx.emit(
            Node::new("Journal info block")
                .span(vol.sub(u64::from(h.journal_info).saturating_mul(block), block)),
        );
    }
    Ok(())
}

async fn btree_header(cx: Cx, node: Span) -> Result<()> {
    cx.emit(NodeDescriptor::node(
        "Node descriptor",
        node.sub(0, NodeDescriptor::SIZE),
        BE,
    ));
    cx.emit(BTreeHeader::node(
        "Header record",
        node.sub(14, BTreeHeader::SIZE),
        BE,
    ));
    Ok(())
}

/// A record in a catalog node: key (parent id, name) and the record body.
#[derive(Clone, Debug)]
struct Rec {
    parent: u32,
    name: Vec<u16>,
    /// Offset of the record (key included) and of its body within the node.
    start: u64,
    body: u64,
    len: u64,
}

/// Parses the records of a node.
fn records(node: &[u8], node_size: u64) -> Vec<Rec> {
    let count = usize::from(u16_be(node, 10).unwrap_or(0));
    let size = to_usize(node_size);
    let offset = |i: usize| -> Option<usize> {
        let at = size.checked_sub(i.checked_add(1)?.checked_mul(2)?)?;
        Some(usize::from(u16_be(node, at)?))
    };
    let mut out = Vec::new();
    for i in 0..count.min(size / 2) {
        let (Some(start), Some(end)) = (offset(i), offset(i.saturating_add(1))) else {
            break;
        };
        let key_len = usize::from(u16_be(node, start).unwrap_or(0));
        let parent = u32_be(node, start.saturating_add(2)).unwrap_or(0);
        let name_len = usize::from(u16_be(node, start.saturating_add(6)).unwrap_or(0)).min(255);
        let name = node
            .get(
                start.saturating_add(8)
                    ..start
                        .saturating_add(8)
                        .saturating_add(name_len.saturating_mul(2)),
            )
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_be_bytes(*c))
            .collect();
        let body = start.saturating_add(2).saturating_add(key_len);
        out.push(Rec {
            parent,
            name,
            start: to_u64(start),
            body: to_u64(body),
            len: to_u64(end.saturating_sub(start)),
        });
    }
    out
}

/// Finds the leaf node holding the first record with parent id `parent`.
async fn find_leaf(cx: &Cx, vol: &Volume, (root, depth): (u32, u32), parent: u32) -> Result<u32> {
    let mut n = root;
    let mut seen = HashSet::new();
    for _ in 0..depth.min(MAX_DEPTH) {
        if !seen.insert(n) {
            return Err(Diagnostic::malformed(format!(
                "catalog B-tree loops at node {n}"
            )));
        }
        let node = vol.node(cx, n).await?;
        if node.get(8) == Some(&0xff) {
            return Ok(n);
        }
        let recs = records(&node, vol.node_size);
        // The last index record whose key is <= (parent, "").
        let pick = recs
            .iter()
            .rev()
            .find(|r| r.parent < parent || (r.parent == parent && r.name.is_empty()))
            .or(recs.first())
            .ok_or_else(|| Diagnostic::malformed(format!("empty index node {n}")))?;
        n = u32_be(&node, to_usize(pick.body)).unwrap_or(0);
    }
    Err(Diagnostic::malformed(
        "catalog B-tree deeper than its header says",
    ))
}

/// The name of folder `ROOT_FOLDER`, from its thread record.
async fn folder_name(cx: &Cx, vol: &Volume, root: u32, depth: u16) -> Result<String> {
    let leaf = find_leaf(cx, vol, (root, depth.into()), ROOT_FOLDER).await?;
    let node = vol.node(cx, leaf).await?;
    for r in records(&node, vol.node_size) {
        if r.parent == ROOT_FOLDER && r.name.is_empty() {
            // Thread: type (2), reserved (2), parent id (4), name.
            let at = to_usize(r.body);
            let len = usize::from(u16_be(&node, at.saturating_add(8)).unwrap_or(0)).min(255);
            let units: Vec<u16> = node
                .get(
                    at.saturating_add(10)
                        ..at.saturating_add(10).saturating_add(len.saturating_mul(2)),
                )
                .unwrap_or_default()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|c| u16::from_be_bytes(*c))
                .collect();
            return Ok(String::from_utf16_lossy(&units));
        }
    }
    Ok(String::new())
}

#[derive(Clone)]
struct Folder {
    vol: Vol,
    id: u32,
    tree: (u32, u32),
    /// The folder's own catalog record (none for the root).
    record: Option<Span>,
    ancestors: Arc<Vec<u32>>,
}

async fn folder(cx: Cx, f: Folder) -> Result<()> {
    let vol = f.vol.clone();
    if let Some(record) = f.record {
        cx.emit(FolderRecord::node("Catalog record", record, BE));
    }
    let mut ancestors = (*f.ancestors).clone();
    ancestors.push(f.id);
    let ancestors = Arc::new(ancestors);
    let mut n = find_leaf(&cx, &vol, f.tree, f.id).await?;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(n) || seen.len() > MAX_LEAVES {
            cx.diag(Diagnostic::malformed(format!(
                "leaf chain loops at node {n}"
            )));
            break;
        }
        let node = vol.node(&cx, n).await?;
        for r in records(&node, vol.node_size) {
            if r.parent < f.id {
                continue;
            }
            if r.parent > f.id {
                return Ok(());
            }
            let kind = u16_be(&node, to_usize(r.body)).unwrap_or(0);
            let span = vol.node_span(
                n,
                r.body,
                r.len.saturating_sub(r.body.saturating_sub(r.start)),
            );
            let name = String::from_utf16_lossy(&r.name).replace('\0', "␀");
            let at = to_usize(r.body);
            let node_out = match kind {
                1 => {
                    let id = u32_be(&node, at.saturating_add(8)).unwrap_or(0);
                    let items = u32_be(&node, at.saturating_add(4)).unwrap_or(0);
                    let out = Node::new(name)
                        .span(span)
                        .summary(format!("folder, {items} items"));
                    if ancestors.contains(&id) || ancestors.len() > MAX_FOLDER_DEPTH {
                        out.diag(Diagnostic::malformed(format!(
                            "folder {id} contains itself; not followed"
                        )))
                    } else {
                        out.lazy(
                            crate::expander!(self::folder: Folder),
                            Folder {
                                vol: vol.clone(),
                                id,
                                tree: f.tree,
                                record: Some(span),
                                ancestors: ancestors.clone(),
                            },
                        )
                    }
                }
                2 => {
                    let data = Fork::parse(
                        node.get(at.saturating_add(88)..at.saturating_add(168))
                            .unwrap_or_default(),
                    );
                    let rsrc = Fork::parse(
                        node.get(at.saturating_add(168)..at.saturating_add(248))
                            .unwrap_or_default(),
                    );
                    let mut summary = size(data.size);
                    if rsrc.size > 0 {
                        summary = format!("{summary} + {} resource fork", size(rsrc.size));
                    }
                    Node::new(name)
                        .span(span)
                        .summary(summary)
                        .lazy(file, (vol.clone(), span, Arc::new((data, rsrc))))
                }
                // Thread records point back at the folder itself.
                _ => {
                    cx.checkpoint().await;
                    continue;
                }
            };
            cx.push(node_out).await;
        }
        let next = u32_be(&node, 0).unwrap_or(0);
        if next == 0 {
            break;
        }
        n = next;
    }
    Ok(())
}

async fn file(cx: Cx, (vol, record, forks): (Vol, Span, Arc<(Fork, Fork)>)) -> Result<()> {
    cx.emit(FileRecord::node(
        "Catalog record",
        record.sub(0, FileRecord::SIZE),
        BE,
    ));
    let (data, rsrc) = &*forks;
    for (name, fork, anchor_at, transform) in [
        ("Data fork", data, 88u64, "hfs-data-fork"),
        ("Resource fork", rsrc, 168, "hfs-resource-fork"),
    ] {
        if fork.size == 0 {
            continue;
        }
        let fork_span = record.sub(anchor_at, ForkData::SIZE);
        cx.emit(ForkData::node(format!("{name} descriptor"), fork_span, BE));
        if fork.overflowed() {
            cx.diag(Diagnostic::unsupported(format!(
                "{name}: extents in the overflow file are not followed"
            )));
        }
        let pieces = fork.pieces(&vol);
        let span = assemble(&cx, fork_span, transform, &pieces).await?;
        cx.emit(fragments_node(&cx, "Extents", pieces).await);
        let node = content_node(&vol.input, span);
        cx.emit(if name == "Data fork" {
            node
        } else {
            node.summary(format!("resource fork, {}", size(span.len)))
        });
    }
    Ok(())
}

record! {
    /// Classic HFS master directory block (the fields that matter here).
    pub struct Mdb {
        signature: ascii[2] "Signature",
        created: u32 "Created" .with(hfs_time),
        modified: u32 "Modified" .with(hfs_time),
        attributes: u16 "Attributes" .hex(),
        root_files: u16 "Files in root",
        bitmap_start: u16 "Volume bitmap start",
        alloc_ptr: u16 "Next allocation",
        blocks: u16 "Allocation blocks",
        block_size: u32 "Allocation block size",
        clump_size: u32 "Clump size",
        first_block: u16 "First allocation block (sectors)",
        next_id: u32 "Next catalog id",
        free_blocks: u16 "Free blocks",
        name: bytes[28] "Volume name" .with(|b, n| n.value(Value::Text(pascal(b)))),
    }
}

/// A Str27 volume name: length byte, then Mac OS Roman text.
fn pascal(b: &[u8]) -> String {
    let len = usize::from(b.first().copied().unwrap_or(0)).min(27);
    crate::codec::charset::Charset::MacRoman
        .decode(b.get(1..len.saturating_add(1)).unwrap_or_default())
}

/// Classic HFS: show the MDB; an embedded HFS+ volume is dissected.
async fn hfs_wrapper(cx: &Cx, input: Input) -> Result<()> {
    let vol = input.span;
    let span = vol.sub(HEADER, Mdb::SIZE);
    let mdb = parse(cx, span, BE, &(), Mdb::layout).await?;
    cx.emit(Mdb::node(
        "Master directory block",
        vol.sub(HEADER, 512),
        BE,
    ));
    let embed = cx
        .read_avail(vol.sub(HEADER.saturating_add(124), 6))
        .await?;
    let name = pascal(&mdb.name);
    if embed.get(..2) == Some(b"H+") {
        let start = u64::from(u16_be(&embed, 2).unwrap_or(0));
        let count = u64::from(u16_be(&embed, 4).unwrap_or(0));
        let block = u64::from(mdb.block_size);
        let at = u64::from(mdb.first_block)
            .saturating_mul(512)
            .saturating_add(start.saturating_mul(block));
        let inner = vol.sub(at, count.saturating_mul(block));
        cx.annotate(format!("HFS wrapper \"{name}\" around an HFS+ volume"));
        cx.emit(embedded("Embedded HFS+ volume", input.nested(inner)));
    } else {
        cx.annotate(format!("Classic HFS volume \"{name}\""));
        cx.diag(Diagnostic::unsupported("classic HFS catalog"));
    }
    Ok(())
}
