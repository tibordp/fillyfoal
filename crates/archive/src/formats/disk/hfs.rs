//! HFS+ and HFSX volumes (and the classic HFS wrapper around them).
//!
//! The volume header at 1 KiB describes the special files as forks of up
//! to eight extents. The catalog file is a B-tree keyed by (parent id,
//! name); a folder's children are found by descending to the folder's
//! thread record and walking the leaf chain. Folders are lazy, paged
//! trees; file content is assembled from the fork's extents, the first
//! eight in the catalog record and the rest in the extents overflow
//! B-tree (keyed by file id, fork type and first block). The attributes
//! B-tree (keyed by file id and name) holds extended attributes, among
//! them `com.apple.decmpfs` for compressed files (see [`decmpfs`]). Hard
//! links are files of type `hlnk`/`hfs+` (directory links `fdrp`/`MACS`)
//! whose `special` field numbers the indirect node `iNode<n>` (`dir_<n>`)
//! in a private folder in the root (TN1150, xnu `hfs_format.h`).

use std::cmp::Ordering;
use std::collections::{BTreeMap, HashSet};
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{
    assemble, coalesce, content_node, decmpfs, fragments_node, size, unix_mode,
};
use crate::formats::util::finder::FINDER_FLAGS;
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Time, Value, flag};

const BE: Endian = Endian::Big;
const HEADER: u64 = 1024;
const ROOT_FOLDER: u32 = 2;
/// B-tree depth and leaf chain length followed before assuming corruption.
const MAX_DEPTH: u32 = 16;
const MAX_LEAVES: usize = 1 << 16;
const MAX_FOLDER_DEPTH: usize = 64;

/// `d` with what it concerns in front.
fn ctx(d: Diagnostic, what: &str) -> Diagnostic {
    Diagnostic {
        message: format!("{what}: {}", d.message),
        ..d
    }
}

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

/// Volume attributes (`kHFSVolume…Bit` in xnu's `hfs_format.h`, TN1150).
const ATTRIBUTES: FlagTable = &[
    flag(1 << 7, "HARDWARE_LOCK"),
    flag(1 << 8, "UNMOUNTED"),
    flag(1 << 9, "SPARED_BLOCKS"),
    flag(1 << 10, "NO_CACHE_REQUIRED"),
    flag(1 << 11, "BOOT_VOLUME_INCONSISTENT"),
    flag(1 << 12, "CATALOG_NODE_IDS_REUSED"),
    flag(1 << 13, "JOURNALED"),
    flag(1 << 14, "INCONSISTENT"),
    flag(1 << 15, "SOFTWARE_LOCK"),
    flag(1 << 30, "CONTENT_PROTECTION"),
    flag(1 << 31, "UNUSED_NODE_FIX"),
];

fn hfs_time(v: &u32, node: Node) -> Node {
    if *v == 0 {
        return node.not_set();
    }
    node.value(Value::utc(crate::text::mac_to_unix((*v).into())))
}

/// A local time in seconds since 1904: the HFS+ volume creation date and
/// every classic HFS date (TN1150).
fn hfs_local(v: &u32, node: Node) -> Node {
    if *v == 0 {
        return node.not_set();
    }
    node.value(Value::Timestamp(Time::local(crate::text::mac_to_unix(
        (*v).into(),
    ))))
}

record! {
    /// `HFSPlusVolumeHeader`, without the five special file forks.
    pub struct VolumeHeader {
        signature: ascii[2] "Signature",
        version: u16 "Version",
        attributes: u32 "Attributes" .hex() .flags(ATTRIBUTES),
        last_mounted: ascii[4] "Last mounted version",
        journal_info: u32 "Journal info block",
        created: u32 "Created" .with(hfs_local),
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

/// Catalog node ids of the special files whose extents can overflow.
const CATALOG_FILE: u32 = 4;
const ATTRIBUTES_FILE: u32 = 8;
/// Fork types in extents overflow keys.
const DATA_FORK: u8 = 0;
const RESOURCE_FORK: u8 = 0xff;

/// A fork: logical size and extents (start block, block count).
#[derive(Clone, Debug, Default)]
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
            extents: extent_list(b.get(16..80).unwrap_or_default()),
        }
    }

    /// The fork's bytes as pieces of the volume, clipped to its size.
    fn pieces(&self, span: Span, block: u64) -> Vec<Span> {
        let pieces = self.extents.iter().map(|&(start, count)| {
            span.sub(
                u64::from(start).saturating_mul(block),
                u64::from(count).saturating_mul(block),
            )
        });
        coalesce(pieces, self.size)
    }

    fn mapped(&self) -> u64 {
        self.extents.iter().map(|&(_, n)| u64::from(n)).sum::<u64>()
    }

    fn overflowed(&self) -> bool {
        self.mapped() < u64::from(self.blocks)
    }

    /// Appends the fork's extents from the extents overflow file: the
    /// records keyed (file id, fork type, first block), in block order.
    /// Returns a diagnostic if the fork is still incomplete.
    async fn complete(
        &mut self,
        cx: &Cx,
        extents: Option<&Tree>,
        id: u32,
        kind: u8,
    ) -> Option<Diagnostic> {
        if !self.overflowed() {
            return None;
        }
        let Some(tree) = extents else {
            return Some(Diagnostic::malformed(
                "fork extents continue in the extents overflow file, which is unreadable",
            ));
        };
        match overflow_extents(cx, tree, self, id, kind).await {
            Err(e) => Some(e),
            Ok(()) if self.overflowed() => Some(Diagnostic::malformed(format!(
                "extents found for {} of the fork's {}",
                self.mapped(),
                plural(self.blocks, "block")
            ))),
            Ok(()) => None,
        }
    }
}

/// Up to eight `HFSPlusExtentDescriptor`s, until the first empty one.
fn extent_list(b: &[u8]) -> Vec<(u32, u32)> {
    b.as_chunks::<8>()
        .0
        .iter()
        .map(|e| (u32_be(e, 0).unwrap_or(0), u32_be(e, 4).unwrap_or(0)))
        .take_while(|&(_, n)| n != 0)
        .collect()
}

/// A B-tree file (catalog, extents overflow, attributes): its bytes as
/// pieces of the volume, and its geometry from the header node.
#[derive(Clone, Debug, Default)]
struct Tree {
    pieces: Vec<Span>,
    node_size: u64,
    root: u32,
    depth: u32,
}

impl Tree {
    /// Reads the header record (node 0) of the B-tree in `pieces`.
    async fn open(cx: &Cx, pieces: Vec<Span>, what: &str) -> Result<(Tree, BTreeHeader, Span)> {
        let first = pieces
            .first()
            .copied()
            .ok_or_else(|| Diagnostic::malformed(format!("the {what} is empty")))?;
        let header_rec = first.sub(14, BTreeHeader::SIZE);
        let bt = parse(cx, header_rec, BE, &(), BTreeHeader::layout).await?;
        let node_size = u64::from(bt.node_size);
        if !(512..=32768).contains(&node_size) || !node_size.is_power_of_two() {
            return Err(
                Diagnostic::malformed(format!("{what} node size {node_size}")).at(header_rec),
            );
        }
        let tree = Tree {
            pieces,
            node_size,
            root: bt.root,
            depth: bt.depth.into(),
        };
        Ok((tree, bt, first.sub(0, node_size)))
    }

    /// Reads node `n` (which may straddle extents).
    async fn node(&self, cx: &Cx, n: u32) -> Result<Vec<u8>> {
        let mut want = u64::from(n).saturating_mul(self.node_size);
        let mut left = self.node_size;
        let mut out = Vec::new();
        for piece in &self.pieces {
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
                "B-tree node {n} lies outside its file"
            )));
        }
        Ok(out)
    }

    /// The volume span of `len` bytes at `offset` in node `n`.
    fn node_span(&self, n: u32, offset: u64, len: u64) -> Span {
        let mut want = u64::from(n)
            .saturating_mul(self.node_size)
            .saturating_add(offset);
        for piece in &self.pieces {
            if want < piece.len {
                return piece.sub(want, len);
            }
            want = want.saturating_sub(piece.len);
        }
        self.pieces.first().map_or(Span::zeros(0), |p| p.sub(0, 0))
    }
}

#[derive(Debug)]
struct Volume {
    input: Input,
    span: Span,
    block: u64,
    catalog: Tree,
    extents: Option<Tree>,
    attributes: Option<Tree>,
    root: u32,
}

type Vol = Arc<Volume>;

impl Volume {
    fn pieces(&self, fork: &Fork) -> Vec<Span> {
        fork.pieces(self.span, self.block)
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
        mode: u16 "Mode" .oct().with(|&m, n| n.summary(unix_mode(m.into()))),
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
        mode: u16 "Mode" .oct().with(|&m, n| n.summary(unix_mode(m.into()))),
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
    let special = |i: usize| {
        Fork::parse(
            forks
                .get(i.saturating_mul(80)..i.saturating_add(1).saturating_mul(80))
                .unwrap_or_default(),
        )
    };
    // The extents overflow file maps its own blocks inline; the catalog
    // and attributes files may continue in it.
    let extents =
        match Tree::open(&cx, special(1).pieces(vol, block), "extents overflow file").await {
            Ok((tree, _, _)) => Some(tree),
            Err(_) => None,
        };
    let mut catalog_fork = special(2);
    if let Some(d) = catalog_fork
        .complete(&cx, extents.as_ref(), CATALOG_FILE, DATA_FORK)
        .await
    {
        cx.diag(ctx(d, "catalog file"));
    }
    let mut attributes_fork = special(3);
    let attributes = if attributes_fork.size == 0 {
        None
    } else {
        if let Some(d) = attributes_fork
            .complete(&cx, extents.as_ref(), ATTRIBUTES_FILE, DATA_FORK)
            .await
        {
            cx.diag(ctx(d, "attributes file"));
        }
        match Tree::open(&cx, attributes_fork.pieces(vol, block), "attributes file").await {
            Ok((tree, _, _)) => Some(tree),
            Err(e) => {
                cx.diag(ctx(e, "attributes file"));
                None
            }
        }
    };
    let (catalog, _, header_node) =
        Tree::open(&cx, catalog_fork.pieces(vol, block), "catalog file").await?;
    let volume = Volume {
        input,
        span: vol,
        block,
        catalog,
        extents,
        attributes,
        root: ROOT_FOLDER,
    };
    let volume_name = folder_name(&cx, &volume).await.unwrap_or_default();
    cx.annotate(format!(
        "{journaled}{kind} volume{}, {} ({}, {} folders)",
        if volume_name.is_empty() {
            String::new()
        } else {
            format!(" \"{volume_name}\"")
        },
        size(u64::from(h.total_blocks).saturating_mul(block)),
        plural(h.files, "file"),
        h.folders
    ));
    let fs: Vol = Arc::new(volume);
    cx.emit(
        Node::new("Catalog B-tree header")
            .span(header_node)
            .lazy(btree_header, header_node),
    );
    cx.emit(Node::new("Root folder").summary(volume_name).lazy(
        crate::expander!(self::folder: Folder),
        Folder {
            vol: fs.clone(),
            id: fs.root,
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

/// A record in a B-tree node: where it, and its body after the key, start
/// and where it ends (offsets within the node).
#[derive(Clone, Copy, Debug)]
struct Rec {
    start: usize,
    body: usize,
    end: usize,
}

impl Rec {
    fn len(&self) -> u64 {
        to_u64(self.end.saturating_sub(self.start))
    }

    fn body_len(&self) -> u64 {
        to_u64(self.end.saturating_sub(self.body))
    }
}

/// The records of a node, from the offset table at its end. Every key
/// starts with its length (`kHFSBigKeysMask` is always set on HFS+).
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
        out.push(Rec {
            start,
            body: start.saturating_add(2).saturating_add(key_len),
            end: end.max(start),
        });
    }
    out
}

/// A UTF-16 name of `len` units at `at`.
fn utf16_at(node: &[u8], at: usize, len: usize) -> Vec<u16> {
    node.get(at..at.saturating_add(len.saturating_mul(2)))
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_be_bytes(*c))
        .collect()
}

/// Catalog key: parent id and name.
fn catalog_key(node: &[u8], r: &Rec) -> (u32, Vec<u16>) {
    let parent = u32_be(node, r.start.saturating_add(2)).unwrap_or(0);
    let len = usize::from(u16_be(node, r.start.saturating_add(6)).unwrap_or(0)).min(255);
    (parent, utf16_at(node, r.start.saturating_add(8), len))
}

fn catalog_parent(node: &[u8], r: &Rec) -> u32 {
    u32_be(node, r.start.saturating_add(2)).unwrap_or(0)
}

/// Whether a catalog key is at most (`parent`, empty name): the thread
/// record, which sorts first among a folder's records.
fn catalog_le(parent: u32) -> impl Fn(&[u8], &Rec) -> bool {
    move |node, r| {
        let p = catalog_parent(node, r);
        p < parent || (p == parent && u16_be(node, r.start.saturating_add(6)) == Some(0))
    }
}

/// Extents overflow key: file id, fork type, first block.
fn extent_key(node: &[u8], r: &Rec) -> (u32, u8, u32) {
    (
        u32_be(node, r.start.saturating_add(4)).unwrap_or(0),
        node.get(r.start.saturating_add(2)).copied().unwrap_or(0),
        u32_be(node, r.start.saturating_add(8)).unwrap_or(0),
    )
}

/// Attributes key: file id (the first block and the name follow).
fn attr_file(node: &[u8], r: &Rec) -> u32 {
    u32_be(node, r.start.saturating_add(4)).unwrap_or(0)
}

/// Descends from the root to the leaf holding the first record whose key
/// is not below the target; `le` says whether a key is at most the target.
async fn find_leaf(cx: &Cx, tree: &Tree, le: &impl Fn(&[u8], &Rec) -> bool) -> Result<u32> {
    let mut n = tree.root;
    let mut seen = HashSet::new();
    for _ in 0..tree.depth.min(MAX_DEPTH) {
        if !seen.insert(n) {
            return Err(Diagnostic::malformed(format!("B-tree loops at node {n}")));
        }
        let node = tree.node(cx, n).await?;
        if node.get(8) == Some(&0xff) {
            return Ok(n);
        }
        let recs = records(&node, tree.node_size);
        // The last index record whose key is <= the target.
        let pick = recs
            .iter()
            .rev()
            .find(|r| le(&node, r))
            .or(recs.first())
            .ok_or_else(|| Diagnostic::malformed(format!("empty index node {n}")))?;
        n = u32_be(&node, pick.body).unwrap_or(0);
    }
    Err(Diagnostic::malformed("B-tree deeper than its header says"))
}

/// A leaf record found by [`range`]: its node's number and bytes.
#[derive(Clone, Debug)]
struct Item {
    n: u32,
    node: Arc<Vec<u8>>,
    rec: Rec,
}

/// The leaf records of one key range, in key order: from the leaf `le`
/// finds, `pick` skips records before the range (`Less`), keeps those in
/// it (`Equal`) and stops at the first one after it.
async fn range(
    cx: &Cx,
    tree: &Tree,
    le: impl Fn(&[u8], &Rec) -> bool,
    pick: impl Fn(&[u8], &Rec) -> Ordering,
) -> Result<Vec<Item>> {
    // An empty tree (a fresh attributes file) has no root.
    if tree.depth == 0 || tree.root == 0 {
        return Ok(Vec::new());
    }
    let mut n = find_leaf(cx, tree, &le).await?;
    let mut seen = HashSet::new();
    let mut out = Vec::new();
    loop {
        if !seen.insert(n) || seen.len() > MAX_LEAVES {
            return Err(Diagnostic::malformed(format!(
                "leaf chain loops at node {n}"
            )));
        }
        let node = Arc::new(tree.node(cx, n).await?);
        for rec in records(&node, tree.node_size) {
            match pick(&node, &rec) {
                Ordering::Less => {}
                Ordering::Equal => out.push(Item {
                    n,
                    node: node.clone(),
                    rec,
                }),
                Ordering::Greater => return Ok(out),
            }
        }
        cx.checkpoint().await;
        match u32_be(&node, 0) {
            Some(0) | None => return Ok(out),
            Some(next) => n = next,
        }
    }
}

/// Appends a fork's overflow extents, in block order, until the fork's
/// block count is reached.
async fn overflow_extents(cx: &Cx, tree: &Tree, fork: &mut Fork, id: u32, kind: u8) -> Result<()> {
    let first = u32::try_from(fork.mapped()).unwrap_or(u32::MAX);
    let items = range(
        cx,
        tree,
        |node, r| extent_key(node, r) <= (id, kind, first),
        |node, r| {
            let (f, k, _) = extent_key(node, r);
            (f, k).cmp(&(id, kind))
        },
    )
    .await?;
    for item in items {
        let (_, _, start) = extent_key(&item.node, &item.rec);
        let have = fork.mapped();
        if u64::from(start) < have {
            continue;
        }
        if u64::from(start) > have {
            return Err(Diagnostic::malformed(format!(
                "overflow extents skip from block {have} to {start}"
            )));
        }
        let list = extent_list(
            item.node
                .get(item.rec.body..item.rec.body.saturating_add(64))
                .unwrap_or_default(),
        );
        if list.is_empty() {
            break;
        }
        fork.extents.extend(list);
        if !fork.overflowed() {
            break;
        }
    }
    Ok(())
}

/// The name of the root folder, from its thread record.
async fn folder_name(cx: &Cx, vol: &Volume) -> Result<String> {
    let tree = &vol.catalog;
    let leaf = find_leaf(cx, tree, &catalog_le(ROOT_FOLDER)).await?;
    let node = tree.node(cx, leaf).await?;
    for r in records(&node, tree.node_size) {
        let (parent, name) = catalog_key(&node, &r);
        if parent == ROOT_FOLDER && name.is_empty() {
            // Thread: type (2), reserved (2), parent id (4), name.
            let len = usize::from(u16_be(&node, r.body.saturating_add(8)).unwrap_or(0)).min(255);
            return Ok(String::from_utf16_lossy(&utf16_at(
                &node,
                r.body.saturating_add(10),
                len,
            )));
        }
    }
    Ok(String::new())
}

/// An extended attribute from the attributes B-tree.
#[derive(Clone, Debug)]
struct Attr {
    name: String,
    /// The record (key and body).
    record: Span,
    value: AttrValue,
}

#[derive(Clone, Debug)]
enum AttrValue {
    /// `kHFSPlusAttrInlineData`: the value inside the record.
    Inline(Span),
    /// `kHFSPlusAttrForkData` (and any `kHFSPlusAttrExtents` records that
    /// continue it): the value in its own fork.
    Fork(Fork),
    Other(u32),
}

impl Attr {
    fn size(&self) -> u64 {
        match &self.value {
            AttrValue::Inline(s) => s.len,
            AttrValue::Fork(f) => f.size,
            AttrValue::Other(_) => 0,
        }
    }

    /// The value's bytes.
    async fn data(&self, cx: &Cx, vol: &Volume) -> Result<Span> {
        match &self.value {
            AttrValue::Inline(s) => Ok(*s),
            AttrValue::Fork(f) => {
                assemble(cx, self.record, "hfs-attribute-fork", &vol.pieces(f)).await
            }
            AttrValue::Other(t) => Err(Diagnostic::malformed(format!(
                "attribute record type {t:#x}"
            ))),
        }
    }
}

/// The extended attributes of catalog node `id`.
async fn attributes(cx: &Cx, vol: &Volume, id: u32) -> Result<Vec<Attr>> {
    let Some(tree) = &vol.attributes else {
        return Ok(Vec::new());
    };
    let items = range(
        cx,
        tree,
        |node, r| {
            let f = attr_file(node, r);
            f < id || (f == id && u16_be(node, r.start.saturating_add(12)) == Some(0))
        },
        |node, r| attr_file(node, r).cmp(&id),
    )
    .await?;
    let mut out: Vec<Attr> = Vec::new();
    for Item { n, node, rec } in items {
        let len = usize::from(u16_be(&node, rec.start.saturating_add(12)).unwrap_or(0)).min(127);
        let name = String::from_utf16_lossy(&utf16_at(&node, rec.start.saturating_add(14), len));
        let record = tree.node_span(n, to_u64(rec.start), rec.len());
        let kind = u32_be(&node, rec.body).unwrap_or(0);
        let value = match kind {
            0x10 => {
                let size = u32_be(&node, rec.body.saturating_add(12)).unwrap_or(0);
                let size = u64::from(size).min(rec.body_len().saturating_sub(16));
                AttrValue::Inline(tree.node_span(n, to_u64(rec.body.saturating_add(16)), size))
            }
            0x20 => AttrValue::Fork(Fork::parse(
                node.get(rec.body.saturating_add(8)..rec.body.saturating_add(88))
                    .unwrap_or_default(),
            )),
            0x30 => {
                // More extents of the previous fork attribute.
                if let Some(Attr {
                    name: prev,
                    value: AttrValue::Fork(f),
                    ..
                }) = out.last_mut()
                    && *prev == name
                {
                    f.extents.extend(extent_list(
                        node.get(rec.body.saturating_add(8)..rec.body.saturating_add(72))
                            .unwrap_or_default(),
                    ));
                }
                continue;
            }
            other => AttrValue::Other(other),
        };
        out.push(Attr {
            name,
            record,
            value,
        });
    }
    Ok(out)
}

async fn attributes_node(cx: Cx, (vol, attrs): (Vol, Arc<Vec<Attr>>)) -> Result<()> {
    for a in attrs.iter() {
        let node = match a.data(&cx, &vol).await {
            Ok(data) => crate::formats::content(
                a.name.clone(),
                vol.input,
                data,
                crate::formats::Codec::Stored,
                None,
            ),
            Err(e) => Node::new(a.name.clone()).span(a.record).diag(e),
        };
        cx.push(node.summary(size(a.size()))).await;
    }
    Ok(())
}

/// A catalog file record's fields that decide how to show it.
#[derive(Clone, Debug)]
struct FileInfo {
    id: u32,
    /// `bsdInfo.ownerFlags` (the low byte of the BSD flags).
    owner_flags: u8,
    /// `bsdInfo.special`: link count, device, or a link's indirect node.
    special: u32,
    file_type: [u8; 4],
    creator: [u8; 4],
    data: Fork,
    rsrc: Fork,
}

impl FileInfo {
    /// The file record whose body starts at `at` in `node`.
    fn parse(node: &[u8], at: usize) -> FileInfo {
        let four = |o: usize| -> [u8; 4] {
            node.get(at.saturating_add(o)..at.saturating_add(o).saturating_add(4))
                .and_then(|b| b.try_into().ok())
                .unwrap_or_default()
        };
        FileInfo {
            id: u32_be(node, at.saturating_add(8)).unwrap_or(0),
            owner_flags: node.get(at.saturating_add(41)).copied().unwrap_or(0),
            special: u32_be(node, at.saturating_add(44)).unwrap_or(0),
            file_type: four(48),
            creator: four(52),
            data: Fork::parse(
                node.get(at.saturating_add(88)..at.saturating_add(168))
                    .unwrap_or_default(),
            ),
            rsrc: Fork::parse(
                node.get(at.saturating_add(168)..at.saturating_add(248))
                    .unwrap_or_default(),
            ),
        }
    }

    /// A file hard link: its content is the indirect node `iNode<special>`.
    fn is_hard_link(&self) -> bool {
        &self.file_type == b"hlnk" && &self.creator == b"hfs+"
    }

    /// A directory hard link: the folder is `dir_<special>`.
    fn is_dir_link(&self) -> bool {
        &self.file_type == b"fdrp" && &self.creator == b"MACS"
    }

    fn compressed(&self) -> bool {
        u32::from(self.owner_flags) & decmpfs::UF_COMPRESSED != 0
    }

    fn summary(&self) -> String {
        if self.is_hard_link() {
            return format!("hard link to iNode{}", self.special);
        }
        let mut s = if self.compressed() {
            "compressed".to_owned()
        } else {
            size(self.data.size)
        };
        if self.rsrc.size > 0 {
            s = format!("{s} + {} resource fork", size(self.rsrc.size));
        }
        s
    }
}

/// The indirect nodes hard links refer to, by number, from the private
/// metadata folders in the root.
#[derive(Debug, Default)]
struct Links {
    /// `iNode<n>` in "\0\0\0\0HFS+ Private Data": record span and fields.
    files: BTreeMap<u32, (Span, FileInfo)>,
    /// `dir_<n>` in ".HFS+ Private Directory Data\r": folder record span
    /// and folder id.
    dirs: BTreeMap<u32, (Span, u32)>,
}

const FILE_LINKS_DIR: &str = "\0\0\0\0HFS+ Private Data";
const DIR_LINKS_DIR: &str = ".HFS+ Private Directory Data\r";

/// The records of folder `id`'s children (thread records left out).
async fn children(cx: &Cx, vol: &Volume, id: u32) -> Result<Vec<Item>> {
    let items = range(cx, &vol.catalog, catalog_le(id), |node, r| {
        catalog_parent(node, r).cmp(&id)
    })
    .await?;
    Ok(items
        .into_iter()
        .filter(|i| matches!(u16_be(&i.node, i.rec.body), Some(1 | 2)))
        .collect())
}

/// Builds (once per volume) the index of indirect nodes.
async fn links(cx: &Cx, vol: &Volume) -> Result<Arc<Links>> {
    if let Some(l) = cx.cached::<Links>(vol.span, "hfs-links") {
        return Ok(l);
    }
    let mut links = Links::default();
    for root in children(cx, vol, ROOT_FOLDER).await? {
        let (_, name) = catalog_key(&root.node, &root.rec);
        let name = String::from_utf16_lossy(&name);
        let files = name == FILE_LINKS_DIR;
        if !files && name != DIR_LINKS_DIR {
            continue;
        }
        let dir = u32_be(&root.node, root.rec.body.saturating_add(8)).unwrap_or(0);
        for item in children(cx, vol, dir).await? {
            let (_, name) = catalog_key(&item.node, &item.rec);
            let name = String::from_utf16_lossy(&name);
            let span = vol
                .catalog
                .node_span(item.n, to_u64(item.rec.body), item.rec.body_len());
            let kind = u16_be(&item.node, item.rec.body);
            if files && kind == Some(2) {
                if let Some(num) = name.strip_prefix("iNode").and_then(|n| n.parse().ok()) {
                    links
                        .files
                        .insert(num, (span, FileInfo::parse(&item.node, item.rec.body)));
                }
            } else if !files
                && kind == Some(1)
                && let Some(num) = name.strip_prefix("dir_").and_then(|n| n.parse().ok())
            {
                let id = u32_be(&item.node, item.rec.body.saturating_add(8)).unwrap_or(0);
                links.dirs.insert(num, (span, id));
            }
        }
    }
    let links = Arc::new(links);
    cx.cache(vol.span, "hfs-links", links.clone());
    Ok(links)
}

#[derive(Clone)]
struct Folder {
    vol: Vol,
    id: u32,
    /// The folder's own catalog record (none for the root).
    record: Option<Span>,
    ancestors: Arc<Vec<u32>>,
}

async fn folder(cx: Cx, f: Folder) -> Result<()> {
    let vol = f.vol.clone();
    if let Some(record) = f.record {
        cx.emit(FolderRecord::node("Catalog record", record, BE));
    }
    match attributes(&cx, &vol, f.id).await {
        Ok(attrs) if !attrs.is_empty() => cx.emit(
            Node::new("Extended attributes")
                .summary(plural(to_u64(attrs.len()), "attribute"))
                .lazy(attributes_node, (vol.clone(), Arc::new(attrs))),
        ),
        Ok(_) => {}
        Err(e) => cx.diag(ctx(e, "extended attributes")),
    }
    let mut ancestors = (*f.ancestors).clone();
    ancestors.push(f.id);
    let ancestors = Arc::new(ancestors);
    let tree = &vol.catalog;
    let mut n = find_leaf(&cx, tree, &catalog_le(f.id)).await?;
    let mut seen = HashSet::new();
    loop {
        if !seen.insert(n) || seen.len() > MAX_LEAVES {
            cx.diag(Diagnostic::malformed(format!(
                "leaf chain loops at node {n}"
            )));
            break;
        }
        let node = tree.node(&cx, n).await?;
        for r in records(&node, tree.node_size) {
            let (parent, name) = catalog_key(&node, &r);
            if parent < f.id {
                continue;
            }
            if parent > f.id {
                return Ok(());
            }
            let kind = u16_be(&node, r.body).unwrap_or(0);
            let span = tree.node_span(n, to_u64(r.body), r.body_len());
            let name = String::from_utf16_lossy(&name).replace('\0', "␀");
            let node_out = match kind {
                1 => {
                    let id = u32_be(&node, r.body.saturating_add(8)).unwrap_or(0);
                    let items = u32_be(&node, r.body.saturating_add(4)).unwrap_or(0);
                    let out = Node::new(name).span(span).summary(format!(
                        "folder, {items_item}",
                        items_item = plural(items, "item")
                    ));
                    subfolder(out, &vol, id, Some(span), &ancestors)
                }
                2 => {
                    let info = FileInfo::parse(&node, r.body);
                    let out = Node::new(name).span(span).summary(info.summary());
                    if info.is_dir_link() {
                        out.summary(format!("directory hard link to dir_{}", info.special))
                            .lazy(
                                crate::expander!(self::dir_link: DirLink),
                                DirLink {
                                    vol: vol.clone(),
                                    record: span,
                                    num: info.special,
                                    ancestors: ancestors.clone(),
                                },
                            )
                    } else {
                        out.lazy(file, (vol.clone(), span, Arc::new(info)))
                    }
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

/// A folder's node: lazy, unless it would contain itself.
fn subfolder(
    out: Node,
    vol: &Vol,
    id: u32,
    record: Option<Span>,
    ancestors: &Arc<Vec<u32>>,
) -> Node {
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
                record,
                ancestors: ancestors.clone(),
            },
        )
    }
}

#[derive(Clone)]
struct DirLink {
    vol: Vol,
    record: Span,
    num: u32,
    ancestors: Arc<Vec<u32>>,
}

/// A directory hard link: its record, then the folder `dir_<num>`.
async fn dir_link(cx: Cx, l: DirLink) -> Result<()> {
    cx.emit(FileRecord::node(
        "Catalog record",
        l.record.sub(0, FileRecord::SIZE),
        BE,
    ));
    let links = links(&cx, &l.vol).await?;
    let &(span, id) = links.dirs.get(&l.num).ok_or_else(|| {
        Diagnostic::malformed(format!(
            "no dir_{} in the private directory data folder",
            l.num
        ))
    })?;
    cx.emit(subfolder(
        Node::new(format!("dir_{}", l.num))
            .span(span)
            .summary("the linked folder"),
        &l.vol,
        id,
        Some(span),
        &l.ancestors,
    ));
    Ok(())
}

async fn file(cx: Cx, (vol, record, info): (Vol, Span, Arc<FileInfo>)) -> Result<()> {
    cx.emit(FileRecord::node(
        "Catalog record",
        record.sub(0, FileRecord::SIZE),
        BE,
    ));
    if !info.is_hard_link() {
        return contents(&cx, &vol, record, &info).await;
    }
    let links = links(&cx, &vol).await?;
    let (span, target) = links.files.get(&info.special).ok_or_else(|| {
        Diagnostic::malformed(format!(
            "no iNode{} in the private data folder",
            info.special
        ))
    })?;
    cx.emit(
        FileRecord::node("Indirect node record", span.sub(0, FileRecord::SIZE), BE)
            .summary(format!("iNode{}, file id {}", info.special, target.id)),
    );
    contents(&cx, &vol, *span, target).await
}

/// A file's forks (or decompressed content) and extended attributes.
async fn contents(cx: &Cx, vol: &Vol, record: Span, info: &FileInfo) -> Result<()> {
    let attrs = match attributes(cx, vol, info.id).await {
        Ok(a) => a,
        Err(e) => {
            cx.diag(ctx(e, "extended attributes"));
            Vec::new()
        }
    };
    let mut rsrc_span = None;
    for (name, fork, kind, anchor_at, transform) in [
        ("Data fork", &info.data, DATA_FORK, 88u64, "hfs-data-fork"),
        (
            "Resource fork",
            &info.rsrc,
            RESOURCE_FORK,
            168,
            "hfs-resource-fork",
        ),
    ] {
        if fork.size == 0 {
            continue;
        }
        let fork_span = record.sub(anchor_at, ForkData::SIZE);
        cx.emit(ForkData::node(format!("{name} descriptor"), fork_span, BE));
        let mut fork = fork.clone();
        if let Some(d) = fork.complete(cx, vol.extents.as_ref(), info.id, kind).await {
            cx.diag(ctx(d, name));
        }
        let pieces = vol.pieces(&fork);
        let span = assemble(cx, fork_span, transform, &pieces).await?;
        cx.emit(fragments_node(cx, "Extents", pieces).await);
        let node = content_node(&vol.input, span);
        if kind == DATA_FORK {
            cx.emit(node);
        } else if info.compressed() {
            rsrc_span = Some(span);
            cx.emit(
                node.renamed("Compressed data")
                    .summary(format!("resource fork, {}", size(span.len))),
            );
        } else {
            cx.emit(node.summary(format!("resource fork, {}", size(span.len))));
        }
    }
    if info.compressed() {
        match attrs.iter().find(|a| a.name == decmpfs::XATTR) {
            Some(a) => {
                let attr = a.data(cx, vol).await?;
                match decmpfs::content(cx, attr, rsrc_span).await {
                    Ok((h, span)) => {
                        cx.emit(decmpfs::header_node(attr, &h));
                        cx.emit(content_node(&vol.input, span).summary(format!(
                            "{}, decompressed ({})",
                            size(span.len),
                            h.kind_name()
                        )));
                    }
                    Err(e) => cx.diag(ctx(e, "decmpfs")),
                }
            }
            None => cx.diag(Diagnostic::malformed(
                "compressed, but there is no com.apple.decmpfs attribute",
            )),
        }
    }
    if !attrs.is_empty() {
        cx.emit(
            Node::new("Extended attributes")
                .summary(plural(to_u64(attrs.len()), "attribute"))
                .lazy(attributes_node, (vol.clone(), Arc::new(attrs))),
        );
    }
    Ok(())
}

record! {
    /// Classic HFS master directory block (the fields that matter here).
    pub struct Mdb {
        signature: ascii[2] "Signature",
        created: u32 "Created" .with(hfs_local),
        modified: u32 "Modified" .with(hfs_local),
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
