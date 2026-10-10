//! The indexes: version 1 B-trees (group members, chunks), symbol table
//! nodes, version 2 B-trees (dense links and attributes, chunks, huge heap
//! objects, shared messages), and the fixed and extensible arrays that
//! index chunks.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

use super::heap::LocalHeap;
use super::util::{File, FileRef, Rd, checksum_node, group, limit_enc_size, log2, uint};

/// B-tree levels followed.
const MAX_DEPTH: u32 = 64;
/// Nodes visited per walk.
const MAX_NODES: usize = 1 << 20;
/// Bytes of a node read at once.
const MAX_NODE: u64 = 4 << 20;

fn emit(cx: &Cx, out: Vec<Node>) {
    for n in out {
        cx.emit(n);
    }
}

// ---------------------------------------------------------------------------
// Version 1 B-trees

/// One entry of a level-0 node: the key before the child, and the child.
#[derive(Clone, Debug)]
pub struct V1Entry {
    pub key: Vec<u8>,
    pub child: u64,
}

/// Walks the level-0 entries of a version 1 B-tree, left to right.
pub struct V1Iter {
    file: FileRef,
    key_len: usize,
    stack: Vec<(u64, u32)>,
    leaf: Option<(Arc<Vec<u8>>, usize, usize)>,
    seen: BTreeSet<u64>,
    pub problems: Vec<Diagnostic>,
}

impl V1Iter {
    pub fn new(file: &FileRef, addr: u64, key_len: usize) -> V1Iter {
        V1Iter {
            file: file.clone(),
            key_len,
            stack: if file.undef(addr) {
                Vec::new()
            } else {
                vec![(addr, 0)]
            },
            leaf: None,
            seen: BTreeSet::new(),
            problems: Vec::new(),
        }
    }

    pub async fn next(&mut self, cx: &Cx) -> Result<Option<V1Entry>> {
        let (o, k) = (self.file.o, self.key_len);
        loop {
            if let Some((data, next, n)) = &mut self.leaf {
                if *next < *n {
                    let at = 8usize
                        .saturating_add(o.saturating_mul(2))
                        .saturating_add(next.saturating_mul(k.saturating_add(o)));
                    *next = next.saturating_add(1);
                    let key = data
                        .get(at..at.saturating_add(k))
                        .unwrap_or_default()
                        .to_vec();
                    let child = uint(data, at.saturating_add(k), o).unwrap_or(u64::MAX);
                    return Ok(Some(V1Entry { key, child }));
                }
                self.leaf = None;
            }
            let Some((addr, depth)) = self.stack.pop() else {
                return Ok(None);
            };
            cx.checkpoint().await;
            if !self.seen.insert(addr) || self.seen.len() > MAX_NODES || depth > MAX_DEPTH {
                self.problems.push(Diagnostic::malformed(format!(
                    "B-tree node {addr:#x} revisited or too deep"
                )));
                continue;
            }
            let head = cx.read(self.file.exact(addr, 8)?).await?;
            if !head.starts_with(b"TREE") {
                self.problems.push(
                    Diagnostic::malformed(format!("no B-tree node at {addr:#x}"))
                        .at(self.file.at(addr, 4)),
                );
                continue;
            }
            let level = head.get(5).copied().unwrap_or(0);
            let n = usize::from(u16_le(&head, 6).unwrap_or(0));
            let len = 8usize
                .saturating_add(o.saturating_mul(2))
                .saturating_add(n.saturating_mul(k.saturating_add(o)))
                .saturating_add(k);
            let span = self.file.exact(addr, to_u64(len).min(MAX_NODE))?;
            let data = Arc::new(cx.read(span).await?);
            if level == 0 {
                self.leaf = Some((data, 0, n));
            } else {
                for i in (0..n).rev() {
                    let at = 8usize
                        .saturating_add(o.saturating_mul(2))
                        .saturating_add(i.saturating_mul(k.saturating_add(o)))
                        .saturating_add(k);
                    if let Some(child) = uint(&data, at, o) {
                        self.stack.push((child, depth.saturating_add(1)));
                    }
                }
            }
        }
    }
}

/// What a version 1 B-tree indexes: group members (keys are heap offsets
/// of names) or chunks (keys are sizes, filter masks and offsets).
#[derive(Clone, Copy, Debug)]
pub enum V1Kind {
    Group(Option<LocalHeap>),
    /// Dimensions in the key (the dataset's rank plus one).
    Chunk(usize),
}

impl V1Kind {
    pub fn key_len(self, file: &File) -> usize {
        match self {
            V1Kind::Group(_) => file.l,
            V1Kind::Chunk(n) => 8usize.saturating_add(n.saturating_mul(8)),
        }
    }
}

pub fn v1_node(file: &FileRef, addr: u64, kind: V1Kind) -> Node {
    if file.undef(addr) {
        return Node::new("B-tree").summary("undefined address");
    }
    Node::new(format!("B-tree node at {addr:#x}"))
        .target(file.at(addr, 4))
        .lazy(
            crate::expander!(self::v1_expand: (FileRef, u64, V1Kind, u32)),
            (file.clone(), addr, kind, 0u32),
        )
}

fn v1_fields(rd: &mut Rd<'_>) -> Option<(u64, u64)> {
    rd.sig(4)?;
    rd.en(
        "Node type",
        1,
        &[(0, "group nodes"), (1, "raw data chunks")],
    )?;
    let level = rd.num("Node level", 1)?;
    let n = rd.num("Entries used", 2)?;
    rd.addr("Left sibling")?;
    rd.addr("Right sibling")?;
    Some((level, n))
}

fn key_fields(rd: &mut Rd<'_>, kind: V1Kind, heap_names: &[(u64, String)]) -> Option<()> {
    match kind {
        V1Kind::Group(_) => {
            let l = rd.l;
            let off = rd.num("Name offset in local heap", l)?;
            if let Some((_, name)) = heap_names.iter().find(|(o, _)| *o == off) {
                rd.note(format!("{name:?}"));
            }
        }
        V1Kind::Chunk(n) => {
            rd.num("Chunk size", 4)?;
            rd.hexn("Filter mask", 4)?;
            for i in 0..n {
                let (v, span) = rd.take(8)?;
                rd.push(
                    Node::new(format!("Offset {i}"))
                        .span(span)
                        .value(super::util::dec(v)),
                );
            }
        }
    }
    Some(())
}

async fn v1_expand(cx: Cx, (file, addr, kind, depth): (FileRef, u64, V1Kind, u32)) -> Result<()> {
    let head = cx.read(file.exact(addr, 8)?).await?;
    if !head.starts_with(b"TREE") {
        return Err(Diagnostic::malformed("B-tree signature missing").at(file.at(addr, 4)));
    }
    let n = usize::from(u16_le(&head, 6).unwrap_or(0));
    let (o, k) = (file.o, kind.key_len(&file));
    let len = 8usize
        .saturating_add(o.saturating_mul(2))
        .saturating_add(n.saturating_mul(k.saturating_add(o)))
        .saturating_add(k);
    let span = file.exact(addr, to_u64(len).min(MAX_NODE))?;
    let data = cx.read(span).await?;
    // Names for group keys, if the heap is known.
    let mut names = Vec::new();
    if let V1Kind::Group(Some(heap)) = kind {
        for i in 0..=n {
            let at = 8usize
                .saturating_add(o.saturating_mul(2))
                .saturating_add(i.saturating_mul(k.saturating_add(o)));
            if let Some(off) = uint(&data, at, file.l)
                && let Ok((name, _)) = super::heap::local_name(&cx, &file, &heap, off).await
            {
                names.push((off, name));
            }
        }
    }
    let mut rd = Rd::new(&file, &data, span);
    let fields = v1_fields(&mut rd);
    rd.finish(fields.map(|_| ()));
    let level = fields.map_or(0, |(l, _)| l);
    let mut children = Vec::new();
    for i in 0..=n {
        let start = rd.pos;
        let mut sub = rd.fork();
        let ok = key_fields(&mut sub, kind, &names);
        rd.join(format!("Key {i}"), start, sub);
        if ok.is_none() || i == n {
            break;
        }
        let Some(child) = rd.addr("Child address") else {
            break;
        };
        rd.note(if level > 0 {
            "B-tree node"
        } else if matches!(kind, V1Kind::Group(_)) {
            "symbol table node"
        } else {
            "chunk"
        });
        if file.undef(child) {
            continue;
        }
        if level > 0 && depth < MAX_DEPTH {
            children.push(
                Node::new(format!("B-tree node at {child:#x}"))
                    .target(file.at(child, 4))
                    .lazy(
                        crate::expander!(self::v1_expand: (FileRef, u64, V1Kind, u32)),
                        (file.clone(), child, kind, depth.saturating_add(1)),
                    ),
            );
        } else if let V1Kind::Group(heap) = kind {
            children.push(snod_node(&file, child, heap));
        }
    }
    // Nodes are allocated for 2K entries.
    let big_k = match kind {
        V1Kind::Group(_) => file.k[1],
        V1Kind::Chunk(_) => file.k[2],
    };
    let room = big_k.saturating_mul(2);
    let allocated = 8u64
        .saturating_add(to_u64(o.saturating_mul(2)))
        .saturating_add(room.saturating_add(1).saturating_mul(to_u64(k)))
        .saturating_add(room.saturating_mul(to_u64(o)));
    let used = to_u64(len);
    if allocated > used && to_u64(n) <= room {
        let span = file.at(addr.saturating_add(used), allocated.saturating_sub(used));
        if unused(&cx, span).await {
            rd.out
                .push(Node::new("Unused entries").span(span).summary(format!(
                    "room for {} more of 2K = {room}",
                    room.saturating_sub(to_u64(n))
                )));
        }
    }
    emit(&cx, rd.out);
    for c in children {
        cx.push(c).await;
    }
    Ok(())
}

/// A symbol table node ("SNOD"): the entries of an old-style group.
pub fn snod_node(file: &FileRef, addr: u64, heap: Option<LocalHeap>) -> Node {
    Node::new(format!("Symbol table node at {addr:#x}"))
        .target(file.at(addr, 4))
        .lazy(snod_expand, (file.clone(), addr, heap))
}

/// One symbol table entry; returns the object header address.
pub fn entry_fields(rd: &mut Rd<'_>, name: Option<&str>) -> Option<u64> {
    let l = rd.l;
    rd.num("Link name offset", l)?;
    if let Some(n) = name {
        rd.note(format!("{n:?}"));
    }
    let addr = rd.addr("Object header address")?;
    let cache = rd.en(
        "Cache type",
        4,
        &[
            (0, "nothing cached"),
            (1, "group: B-tree and heap cached"),
            (2, "symbolic link"),
        ],
    )?;
    rd.reserved(4)?;
    let start = rd.pos;
    let mut sub = rd.fork();
    match cache {
        1 => {
            sub.addr("B-tree address")?;
            sub.addr("Name heap address")?;
        }
        2 => {
            sub.num("Link value offset", 4)?;
        }
        _ => {}
    }
    let end = start.saturating_add(16);
    if sub.pos < end {
        sub.bytes("Unused", end.saturating_sub(sub.pos))?;
    }
    rd.join("Scratch pad", start, sub);
    Some(addr)
}

async fn snod_expand(cx: Cx, (file, addr, heap): (FileRef, u64, Option<LocalHeap>)) -> Result<()> {
    let head = cx.read(file.exact(addr, 8)?).await?;
    if !head.starts_with(b"SNOD") {
        return Err(
            Diagnostic::malformed("symbol table node signature missing").at(file.at(addr, 4))
        );
    }
    let n = usize::from(u16_le(&head, 6).unwrap_or(0));
    let entry = entry_len(&file);
    let span = file.exact(addr, to_u64(8usize.saturating_add(n.saturating_mul(entry))))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    rd.sig(4);
    rd.num("Version", 1);
    rd.reserved(1);
    rd.num("Number of symbols", 2);
    emit(&cx, rd.out);
    for i in 0..n {
        let at = 8usize.saturating_add(i.saturating_mul(entry));
        let name = match (heap, uint(&data, at, file.l)) {
            (Some(h), Some(off)) => super::heap::local_name(&cx, &file, &h, off)
                .await
                .ok()
                .map(|(s, _)| s),
            _ => None,
        };
        let mut rd = Rd::new(&file, &data, span);
        rd.pos = at;
        let ok = entry_fields(&mut rd, name.as_deref());
        rd.finish(ok.map(|_| ()));
        cx.push(
            group(name.unwrap_or_else(|| format!("Entry {i}")), rd.out)
                .span(span.sub(to_u64(at), to_u64(entry))),
        )
        .await;
    }
    // Symbol table nodes are allocated for 2K entries (group leaf K).
    let room = file.k[0].saturating_mul(2);
    if to_u64(n) < room {
        let used = to_u64(8usize.saturating_add(n.saturating_mul(entry)));
        let span = file.at(
            addr.saturating_add(used),
            room.saturating_sub(to_u64(n)).saturating_mul(to_u64(entry)),
        );
        if unused(&cx, span).await {
            cx.push(Node::new("Unused entries").span(span).summary(format!(
                "room for {} more of 2K = {room}",
                room.saturating_sub(to_u64(n))
            )))
            .await;
        }
    }
    Ok(())
}

/// Whether the space a node was allocated beyond its entries is unused:
/// the library zeroes it. (Writers that pack nodes tightly put other
/// structures there.)
async fn unused(cx: &Cx, span: Span) -> bool {
    if span.len == 0 || span.len > MAX_NODE {
        return false;
    }
    cx.read(span).await.is_ok_and(|d| d.iter().all(|&b| b == 0))
}

/// The size of a symbol table entry.
pub fn entry_len(file: &File) -> usize {
    file.o.saturating_mul(2).saturating_add(24)
}

// ---------------------------------------------------------------------------
// Version 2 B-trees

pub const V2_TYPES: EnumTable = &[
    (0, "test"),
    (1, "huge objects, indirect, unfiltered"),
    (2, "huge objects, indirect, filtered"),
    (3, "huge objects, direct, unfiltered"),
    (4, "huge objects, direct, filtered"),
    (5, "group links by name"),
    (6, "group links by creation order"),
    (7, "shared object header messages"),
    (8, "attributes by name"),
    (9, "attributes by creation order"),
    (10, "chunks, unfiltered"),
    (11, "chunks, filtered"),
];

#[derive(Clone, Debug)]
pub struct V2Hdr {
    pub kind: u8,
    pub node_size: u64,
    pub rec_size: usize,
    pub depth: u16,
    pub root: u64,
    pub root_nrec: u64,
    /// Records in the whole tree.
    pub total: u64,
    /// Bytes of the record count in a child pointer.
    pub nrec_size: usize,
    /// Bytes of the total record count, per level (0 for leaves).
    pub cum_size: Vec<usize>,
}

pub async fn v2_header(cx: &Cx, file: &File, addr: u64) -> Result<V2Hdr> {
    let (o, l) = (file.o, file.l);
    let len = 16usize
        .saturating_add(o)
        .saturating_add(2)
        .saturating_add(l)
        .saturating_add(4);
    let d = cx.read(file.exact(addr, to_u64(len))?).await?;
    if !d.starts_with(b"BTHD") {
        return Err(
            Diagnostic::malformed("v2 B-tree header signature missing").at(file.at(addr, 4))
        );
    }
    let u = |at: usize, n: usize| uint(&d, at, n).unwrap_or(0);
    let kind = u8::try_from(u(5, 1)).unwrap_or(0);
    let node_size = u(6, 4);
    let rec_size = to_usize(u(10, 2));
    let depth = u16::try_from(u(12, 2)).unwrap_or(0);
    let root = u(16, o);
    let root_nrec = u(16usize.saturating_add(o), 2);
    let total = u(18usize.saturating_add(o), l);
    // Records per node (H5B2__hdr_init): leaves hold the most.
    let leaf_max = node_size
        .saturating_sub(10)
        .checked_div(to_u64(rec_size))
        .unwrap_or(0);
    let nrec_size = limit_enc_size(leaf_max);
    let mut cum_size = vec![0usize];
    let mut cum_max = leaf_max;
    for _ in 1..=depth.min(64) {
        let prev = cum_size.last().copied().unwrap_or(0);
        let ptr = to_u64(o.saturating_add(nrec_size).saturating_add(prev));
        let max = node_size
            .saturating_sub(10)
            .saturating_sub(ptr)
            .checked_div(to_u64(rec_size).saturating_add(ptr))
            .unwrap_or(0);
        cum_max = max
            .saturating_add(1)
            .saturating_mul(cum_max)
            .saturating_add(max);
        cum_size.push(limit_enc_size(cum_max));
    }
    Ok(V2Hdr {
        kind,
        node_size,
        rec_size,
        depth,
        root,
        root_nrec,
        total,
        nrec_size,
        cum_size,
    })
}

impl V2Hdr {
    /// The size of a child pointer in a node at `depth` (> 0).
    fn ptr_len(&self, o: usize, depth: u16) -> usize {
        let below = self
            .cum_size
            .get(usize::from(depth.saturating_sub(1)))
            .copied()
            .unwrap_or(0);
        o.saturating_add(self.nrec_size).saturating_add(below)
    }

    /// The bytes a node with `nrec` records occupies (up to its checksum).
    fn node_len(&self, o: usize, depth: u16, nrec: u64) -> usize {
        let n = to_usize(nrec);
        let mut len = 6usize.saturating_add(n.saturating_mul(self.rec_size));
        if depth > 0 {
            len = len.saturating_add(n.saturating_add(1).saturating_mul(self.ptr_len(o, depth)));
        }
        len.saturating_add(4)
    }
}

/// A record of a version 2 B-tree, with where it is.
#[derive(Clone, Debug)]
pub struct V2Rec {
    pub data: Vec<u8>,
    pub span: Span,
}

struct Frame {
    data: Arc<Vec<u8>>,
    span: Span,
    depth: u16,
    nrec: usize,
    step: usize,
}

/// Walks the records of a version 2 B-tree in order.
pub struct V2Iter {
    file: FileRef,
    pub hdr: V2Hdr,
    stack: Vec<Frame>,
    pending: Option<(u64, u64, u16)>,
    visited: usize,
}

impl V2Iter {
    pub async fn new(cx: &Cx, file: &FileRef, addr: u64) -> Result<V2Iter> {
        let hdr = v2_header(cx, file, addr).await?;
        let pending = (!file.undef(hdr.root) && hdr.root_nrec > 0).then_some((
            hdr.root,
            hdr.root_nrec,
            hdr.depth,
        ));
        Ok(V2Iter {
            file: file.clone(),
            hdr,
            stack: Vec::new(),
            pending,
            visited: 0,
        })
    }

    pub async fn next(&mut self, cx: &Cx) -> Result<Option<V2Rec>> {
        let o = self.file.o;
        loop {
            if let Some((addr, nrec, depth)) = self.pending.take() {
                cx.checkpoint().await;
                self.visited = self.visited.saturating_add(1);
                if self.visited > MAX_NODES || self.stack.len() > to_usize(MAX_DEPTH.into()) {
                    return Err(Diagnostic::limit("v2 B-tree too large or cyclic"));
                }
                let len = self.hdr.node_len(o, depth, nrec);
                let span = self.file.exact(addr, to_u64(len).min(MAX_NODE))?;
                let data = Arc::new(cx.read(span).await?);
                let sig: &[u8] = if depth > 0 { b"BTIN" } else { b"BTLF" };
                if !data.starts_with(sig) {
                    return Err(Diagnostic::malformed("v2 B-tree node signature missing")
                        .at(span.sub(0, 4)));
                }
                self.stack.push(Frame {
                    data,
                    span,
                    depth,
                    nrec: to_usize(nrec),
                    step: 0,
                });
            }
            let Some(top) = self.stack.last_mut() else {
                return Ok(None);
            };
            let rec_at = |i: usize| 6usize.saturating_add(i.saturating_mul(self.hdr.rec_size));
            if top.depth == 0 {
                if top.step < top.nrec {
                    let at = rec_at(top.step);
                    top.step = top.step.saturating_add(1);
                    let rec = top
                        .data
                        .get(at..at.saturating_add(self.hdr.rec_size))
                        .unwrap_or_default()
                        .to_vec();
                    return Ok(Some(V2Rec {
                        data: rec,
                        span: top.span.sub(to_u64(at), to_u64(self.hdr.rec_size)),
                    }));
                }
                self.stack.pop();
                continue;
            }
            // Internal: child 0, record 0, child 1, ..., child n.
            if top.step > top.nrec.saturating_mul(2) {
                self.stack.pop();
                continue;
            }
            let step = top.step;
            top.step = top.step.saturating_add(1);
            if step % 2 == 1 {
                let at = rec_at(step / 2);
                let rec = top
                    .data
                    .get(at..at.saturating_add(self.hdr.rec_size))
                    .unwrap_or_default()
                    .to_vec();
                return Ok(Some(V2Rec {
                    data: rec,
                    span: top.span.sub(to_u64(at), to_u64(self.hdr.rec_size)),
                }));
            }
            let ptr = self.hdr.ptr_len(o, top.depth);
            let at = rec_at(top.nrec).saturating_add((step / 2).saturating_mul(ptr));
            let child = uint(&top.data, at, o).unwrap_or(u64::MAX);
            let nrec = uint(&top.data, at.saturating_add(o), self.hdr.nrec_size).unwrap_or(0);
            if !self.file.undef(child) && nrec > 0 {
                self.pending = Some((child, nrec, top.depth.saturating_sub(1)));
            }
        }
    }
}

pub fn v2_node(file: &FileRef, addr: u64, label: &'static str, rank: Option<usize>) -> Node {
    if file.undef(addr) {
        return Node::new(label).summary("undefined address");
    }
    Node::new(label)
        .target(file.at(addr, 4))
        .lazy(v2_expand, (file.clone(), addr, rank))
}

fn v2_fields(rd: &mut Rd<'_>) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.en("Type", 1, V2_TYPES)?;
    rd.num("Node size", 4)?;
    rd.num("Record size", 2)?;
    rd.num("Depth", 2)?;
    rd.num("Split percent", 1)?;
    rd.num("Merge percent", 1)?;
    rd.addr("Root node address")?;
    rd.num("Records in root node", 2)?;
    rd.length("Total records")?;
    Some(())
}

async fn v2_expand(cx: Cx, (file, addr, rank): (FileRef, u64, Option<usize>)) -> Result<()> {
    let hdr = v2_header(&cx, &file, addr).await?;
    let len = 16usize
        .saturating_add(file.o)
        .saturating_add(2)
        .saturating_add(file.l)
        .saturating_add(4);
    let span = file.exact(addr, to_u64(len))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = v2_fields(&mut rd);
    rd.finish(ok);
    let at = rd.pos;
    emit(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    if !file.undef(hdr.root) && hdr.root_nrec > 0 {
        cx.emit(v2_tree_node(
            &file,
            Arc::new(hdr.clone()),
            hdr.root,
            hdr.root_nrec,
            hdr.depth,
            rank,
        ));
    }
    Ok(())
}

fn v2_tree_node(
    file: &FileRef,
    hdr: Arc<V2Hdr>,
    addr: u64,
    nrec: u64,
    depth: u16,
    rank: Option<usize>,
) -> Node {
    let len = hdr.node_len(file.o, depth, nrec);
    Node::new(format!(
        "{} node at {addr:#x}",
        if depth > 0 { "Internal" } else { "Leaf" }
    ))
    .span(file.at(addr, to_u64(len)))
    .summary(format!("{nrec} records"))
    .lazy(
        crate::expander!(self::v2_tree_expand: (FileRef, Arc<V2Hdr>, u64, u64, u16, Option<usize>)),
        (file.clone(), hdr, addr, nrec, depth, rank),
    )
}

async fn v2_tree_expand(
    cx: Cx,
    (file, hdr, addr, nrec, depth, rank): (FileRef, Arc<V2Hdr>, u64, u64, u16, Option<usize>),
) -> Result<()> {
    let o = file.o;
    let len = hdr.node_len(o, depth, nrec);
    let span = file.exact(addr, to_u64(len).min(MAX_NODE))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    rd.sig(4);
    rd.num("Version", 1);
    rd.en("Type", 1, V2_TYPES);
    emit(&cx, std::mem::take(&mut rd.out));
    let n = to_usize(nrec);
    for i in 0..n {
        let start = rd.pos;
        let mut sub = rd.fork();
        let end = start.saturating_add(hdr.rec_size);
        sub.data = sub.data.get(..end).unwrap_or(sub.data);
        let summary = record_fields(&mut sub, hdr.kind, rank);
        sub.pos = end;
        rd.join(format!("Record {i}"), start, sub);
        if let Some(s) = summary
            && let Some(last) = rd.last()
        {
            last.summary = Some(s);
        }
        cx.push(rd.out.pop().unwrap_or_else(|| Node::new("Record")))
            .await;
    }
    if depth > 0 {
        let ptr_len = hdr.ptr_len(o, depth);
        let total_len = hdr
            .cum_size
            .get(usize::from(depth.saturating_sub(1)))
            .copied()
            .unwrap_or(0);
        for i in 0..=n {
            let start = rd.pos;
            let mut sub = rd.fork();
            let child = sub.addr("Child address");
            let count = sub.num("Records in child", hdr.nrec_size);
            if total_len > 0 {
                sub.num("Total records in child subtree", total_len);
            }
            sub.pos = start.saturating_add(ptr_len);
            rd.join(format!("Child pointer {i}"), start, sub);
            if let Some(node) = rd.out.pop() {
                cx.push(node).await;
            }
            if let (Some(child), Some(count)) = (child, count)
                && !file.undef(child)
                && count > 0
            {
                cx.push(v2_tree_node(
                    &file,
                    hdr.clone(),
                    child,
                    count,
                    depth.saturating_sub(1),
                    rank,
                ))
                .await;
            }
        }
    }
    let at = rd.pos;
    if let Some(node) = checksum_node(&cx, &data, span, at).await {
        cx.push(node).await;
    }
    let used = to_u64(at).saturating_add(4);
    if hdr.node_size > used {
        cx.push(
            Node::new("Unused")
                .span(file.at(
                    addr.saturating_add(used),
                    hdr.node_size.saturating_sub(used),
                ))
                .summary("free space in the node"),
        )
        .await;
    }
    Ok(())
}

/// The fields of one record; returns a summary.
fn record_fields(rd: &mut Rd<'_>, kind: u8, rank: Option<usize>) -> Option<String> {
    match kind {
        1..=4 => {
            let addr = rd.addr("Address")?;
            let len = rd.length("Length")?;
            if kind == 2 || kind == 4 {
                rd.hexn("Filter mask", 4)?;
                rd.length("Memory size")?;
            }
            if kind <= 2 {
                rd.length("Object ID")?;
            }
            Some(format!("{len} bytes at {addr:#x}"))
        }
        5 => {
            let h = rd.hexn("Name hash", 4)?;
            let n = rd.left();
            rd.bytes("Heap ID", n)?;
            Some(format!("hash {h:#010x}"))
        }
        6 => {
            let c = rd.num("Creation order", 8)?;
            let n = rd.left();
            rd.bytes("Heap ID", n)?;
            Some(format!("creation order {c}"))
        }
        7 => {
            let loc = rd.en(
                "Location",
                1,
                &[(0, "shared message heap"), (1, "object header")],
            )?;
            let h = rd.hexn("Hash", 4)?;
            if loc == 0 {
                rd.num("Reference count", 4)?;
                rd.bytes("Heap ID", 8)?;
            } else {
                rd.reserved(1)?;
                rd.en("Message type", 1, super::message::MESSAGES)?;
                rd.num("Object header index", 2)?;
                rd.addr("Object header address")?;
            }
            Some(format!("hash {h:#010x}"))
        }
        8 | 9 => {
            rd.bytes("Heap ID", 8)?;
            rd.hexn("Message flags", 1)?;
            let c = rd.num("Creation order", 4)?;
            if kind == 8 {
                let h = rd.hexn("Name hash", 4)?;
                return Some(format!("hash {h:#010x}, creation order {c}"));
            }
            Some(format!("creation order {c}"))
        }
        10 | 11 => {
            let addr = rd.addr("Chunk address")?;
            let dims = match (kind, rank) {
                (10, _) => rd.left() / 8,
                (_, Some(r)) => r,
                _ => rd.left().saturating_sub(4) / 8,
            };
            let mut size = None;
            if kind == 11 {
                let width = rd
                    .left()
                    .saturating_sub(4)
                    .saturating_sub(dims.saturating_mul(8));
                size = Some(rd.num("Chunk size", width)?);
                rd.hexn("Filter mask", 4)?;
            }
            let mut offs = Vec::new();
            for i in 0..dims {
                let (v, span) = rd.take(8)?;
                rd.push(
                    Node::new(format!("Scaled offset {i}"))
                        .span(span)
                        .value(super::util::dec(v)),
                );
                offs.push(v);
            }
            Some(format!(
                "chunk [{}] at {addr:#x}{}",
                super::util::join(&offs, ", "),
                size.map_or_else(String::new, |s| format!(", {s} bytes"))
            ))
        }
        _ => {
            let n = rd.left();
            rd.bytes("Record", n)?;
            None
        }
    }
}

// ---------------------------------------------------------------------------
// Fixed arrays and extensible arrays (chunk indexes)

/// A fixed array header.
#[derive(Clone, Copy, Debug)]
pub struct FaHdr {
    pub client: u8,
    pub esize: usize,
    pub page_bits: u8,
    pub count: u64,
    pub dblock: u64,
}

pub async fn fa_header(cx: &Cx, file: &File, addr: u64) -> Result<FaHdr> {
    let len = 8usize
        .saturating_add(file.l)
        .saturating_add(file.o)
        .saturating_add(4);
    let d = cx.read(file.exact(addr, to_u64(len))?).await?;
    if !d.starts_with(b"FAHD") {
        return Err(
            Diagnostic::malformed("fixed array header signature missing").at(file.at(addr, 4)),
        );
    }
    Ok(FaHdr {
        client: d.get(5).copied().unwrap_or(0),
        esize: usize::from(d.get(6).copied().unwrap_or(0)),
        page_bits: d.get(7).copied().unwrap_or(0),
        count: uint(&d, 8, file.l).unwrap_or(0),
        dblock: uint(&d, 8usize.saturating_add(file.l), file.o).unwrap_or(u64::MAX),
    })
}

impl FaHdr {
    fn page_len(&self) -> u64 {
        1u64.checked_shl(self.page_bits.into()).unwrap_or(u64::MAX)
    }

    fn paged(&self) -> bool {
        self.count > self.page_len()
    }

    fn pages(&self) -> u64 {
        self.count.div_ceil(self.page_len().max(1))
    }

    /// Where element `i` is in the data block.
    pub fn element_at(&self, o: usize, i: u64) -> u64 {
        let prefix = to_u64(6usize.saturating_add(o));
        let esize = to_u64(self.esize);
        if !self.paged() {
            return prefix.saturating_add(i.saturating_mul(esize));
        }
        let bitmap = self.pages().div_ceil(8);
        let page = i.checked_div(self.page_len()).unwrap_or(0);
        let within = i.checked_rem(self.page_len()).unwrap_or(0);
        prefix
            .saturating_add(bitmap)
            .saturating_add(4)
            .saturating_add(
                page.saturating_mul(self.page_len().saturating_mul(esize).saturating_add(4)),
            )
            .saturating_add(within.saturating_mul(esize))
    }
}

pub fn fa_node(file: &FileRef, addr: u64) -> Node {
    Node::new("Fixed array")
        .target(file.at(addr, 4))
        .lazy(fa_expand, (file.clone(), addr))
}

fn fa_fields(rd: &mut Rd<'_>) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.en(
        "Client",
        1,
        &[(0, "unfiltered chunks"), (1, "filtered chunks")],
    )?;
    rd.num("Entry size", 1)?;
    rd.num("Page bits", 1)?;
    rd.length("Number of entries")?;
    rd.addr("Data block address")?;
    Some(())
}

async fn fa_expand(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let hdr = fa_header(&cx, &file, addr).await?;
    let len = 8usize.saturating_add(file.l).saturating_add(file.o);
    let span = file.exact(addr, to_u64(len).saturating_add(4))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = fa_fields(&mut rd);
    rd.finish(ok);
    let at = rd.pos;
    emit(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    if !file.undef(hdr.dblock) {
        cx.emit(
            Node::new("Data block")
                .target(file.at(hdr.dblock, 4))
                .summary(format!("{} entries", hdr.count))
                .lazy(fa_dblock, (file.clone(), hdr)),
        );
    }
    Ok(())
}

/// Shows the fields of one chunk index element.
fn element_fields(rd: &mut Rd<'_>, filtered: bool, esize: usize) -> Option<()> {
    let start = rd.pos;
    rd.addr("Chunk address")?;
    if filtered {
        let width = esize.saturating_sub(rd.o).saturating_sub(4);
        rd.num("Chunk size", width)?;
        rd.hexn("Filter mask", 4)?;
    }
    rd.pos = start.saturating_add(esize);
    Some(())
}

async fn fa_dblock(cx: Cx, (file, hdr): (FileRef, FaHdr)) -> Result<()> {
    let o = file.o;
    let prefix = 6usize.saturating_add(o);
    let head_span = file.exact(hdr.dblock, to_u64(prefix))?;
    let head = cx.read(head_span).await?;
    if !head.starts_with(b"FADB") {
        return Err(
            Diagnostic::malformed("fixed array data block signature missing")
                .at(head_span.sub(0, 4)),
        );
    }
    let mut rd = Rd::new(&file, &head, head_span);
    rd.sig(4);
    rd.num("Version", 1);
    rd.en(
        "Client",
        1,
        &[(0, "unfiltered chunks"), (1, "filtered chunks")],
    );
    rd.addr("Header address");
    emit(&cx, rd.out);
    if hdr.paged() {
        let bitmap = file.at(
            hdr.dblock.saturating_add(to_u64(prefix)),
            hdr.pages().div_ceil(8),
        );
        cx.emit(Node::new("Page initialization bitmap").span(bitmap));
    } else {
        // The checksum follows the elements.
        let len = to_u64(prefix).saturating_add(hdr.count.saturating_mul(to_u64(hdr.esize)));
        if len <= MAX_NODE {
            let span = file.exact(hdr.dblock, len.saturating_add(4))?;
            let data = cx.read(span).await?;
            if let Some(n) = checksum_node(&cx, &data, span, to_usize(len)).await {
                cx.emit(n);
            }
        }
    }
    let mut i = 0u64;
    while i < hdr.count {
        let mut window = hdr.count.saturating_sub(i).min(1024);
        // Elements of a page are contiguous; stop the window at a page end.
        if hdr.paged() {
            let page = hdr.page_len();
            window = window.min(page.saturating_sub(i.checked_rem(page).unwrap_or(0)));
        }
        let at = hdr.element_at(o, i);
        let span = file.exact(
            hdr.dblock.saturating_add(at),
            window.saturating_mul(to_u64(hdr.esize)),
        )?;
        let data = cx.read(span).await?;
        for j in 0..to_usize(window) {
            let mut rd = Rd::new(&file, &data, span);
            rd.pos = j.saturating_mul(hdr.esize);
            let start = rd.pos;
            let ok = element_fields(&mut rd, hdr.client == 1, hdr.esize);
            rd.finish(ok);
            let index = i.saturating_add(to_u64(j));
            let span = rd.since(start);
            cx.push(group(format!("Entry {index}"), rd.out).span(span))
                .await;
        }
        i = i.saturating_add(window.max(1));
    }
    Ok(())
}

/// One element of a fixed array: a chunk address (and for filtered
/// chunks, the stored size and the filter mask).
#[derive(Clone, Copy, Debug)]
pub struct Element {
    pub index: u64,
    pub addr: u64,
    pub size: Option<u64>,
    pub mask: u32,
}

fn element(
    data: &[u8],
    at: usize,
    o: usize,
    esize: usize,
    filtered: bool,
) -> (u64, Option<u64>, u32) {
    let addr = uint(data, at, o).unwrap_or(u64::MAX);
    if !filtered {
        return (addr, None, 0);
    }
    let width = esize.saturating_sub(o).saturating_sub(4);
    let size = uint(data, at.saturating_add(o), width);
    let mask = uint(data, at.saturating_add(o).saturating_add(width), 4).unwrap_or(0);
    (addr, size, u32::try_from(mask).unwrap_or(0))
}

/// Walks a fixed array's elements.
pub struct FaIter {
    file: FileRef,
    pub hdr: FaHdr,
    next: u64,
    buf: Vec<u8>,
    buf_start: u64,
}

impl FaIter {
    pub async fn new(cx: &Cx, file: &FileRef, addr: u64) -> Result<FaIter> {
        let hdr = fa_header(cx, file, addr).await?;
        Ok(FaIter {
            file: file.clone(),
            hdr,
            next: 0,
            buf: Vec::new(),
            buf_start: 0,
        })
    }

    pub async fn next(&mut self, cx: &Cx) -> Result<Option<Element>> {
        if self.next >= self.hdr.count || self.file.undef(self.hdr.dblock) {
            return Ok(None);
        }
        let esize = to_u64(self.hdr.esize);
        let i = self.next;
        let buffered = to_u64(self.buf.len())
            .checked_div(esize.max(1))
            .unwrap_or(0);
        if i < self.buf_start || i >= self.buf_start.saturating_add(buffered) {
            let mut window = self.hdr.count.saturating_sub(i).min(1024);
            if self.hdr.paged() {
                let page = self.hdr.page_len();
                window = window.min(page.saturating_sub(i.checked_rem(page).unwrap_or(0)));
            }
            let at = self.hdr.element_at(self.file.o, i);
            let span = self.file.exact(
                self.hdr.dblock.saturating_add(at),
                window.saturating_mul(esize),
            )?;
            self.buf = cx.read(span).await?;
            self.buf_start = i;
        }
        let at = to_usize(i.saturating_sub(self.buf_start).saturating_mul(esize));
        let (addr, size, mask) = element(
            &self.buf,
            at,
            self.file.o,
            self.hdr.esize,
            self.hdr.client == 1,
        );
        self.next = i.saturating_add(1);
        Ok(Some(Element {
            index: i,
            addr,
            size,
            mask,
        }))
    }
}

/// An extensible array header.
#[derive(Clone, Debug)]
pub struct EaHdr {
    pub client: u8,
    pub esize: usize,
    pub max_bits: u8,
    pub iblock_elems: u64,
    pub dblock_min: u64,
    pub sblock_min_ptrs: u64,
    pub page_bits: u8,
    pub max_index: u64,
    pub iblock: u64,
}

impl EaHdr {
    /// Super blocks: (data blocks, elements per data block).
    fn sblocks(&self) -> Vec<(u64, u64)> {
        let n = u32::from(self.max_bits)
            .saturating_sub(log2(self.dblock_min))
            .saturating_add(1)
            .min(64);
        (0..n)
            .map(|u| {
                let dblocks = 1u64.checked_shl(u / 2).unwrap_or(0);
                let elems = self
                    .dblock_min
                    .saturating_mul(1u64.checked_shl(u.saturating_add(1) / 2).unwrap_or(0));
                (dblocks, elems)
            })
            .collect()
    }

    /// Super blocks whose data block addresses are in the index block.
    fn iblock_sblocks(&self) -> usize {
        to_usize(u64::from(log2(self.sblock_min_ptrs)).saturating_mul(2))
    }

    fn iblock_dblocks(&self) -> usize {
        to_usize(self.sblock_min_ptrs.saturating_sub(1).saturating_mul(2))
    }

    fn arr_off_size(&self) -> usize {
        usize::from(self.max_bits).saturating_add(7) / 8
    }

    fn filtered(&self) -> bool {
        self.client == 1
    }
}

pub async fn ea_header(cx: &Cx, file: &File, addr: u64) -> Result<EaHdr> {
    let len = 12usize
        .saturating_add(file.l.saturating_mul(6))
        .saturating_add(file.o)
        .saturating_add(4);
    let d = cx.read(file.exact(addr, to_u64(len))?).await?;
    if !d.starts_with(b"EAHD") {
        return Err(
            Diagnostic::malformed("extensible array header signature missing").at(file.at(addr, 4)),
        );
    }
    let b = |i: usize| d.get(i).copied().unwrap_or(0);
    let l = file.l;
    Ok(EaHdr {
        client: b(5),
        esize: usize::from(b(6)),
        max_bits: b(7),
        iblock_elems: b(8).into(),
        dblock_min: b(9).into(),
        sblock_min_ptrs: b(10).into(),
        page_bits: b(11),
        max_index: uint(&d, 12usize.saturating_add(l.saturating_mul(4)), l).unwrap_or(0),
        iblock: uint(&d, 12usize.saturating_add(l.saturating_mul(6)), file.o).unwrap_or(u64::MAX),
    })
}

fn ea_fields(rd: &mut Rd<'_>) -> Option<()> {
    rd.sig(4)?;
    rd.num("Version", 1)?;
    rd.en(
        "Client",
        1,
        &[(0, "unfiltered chunks"), (1, "filtered chunks")],
    )?;
    rd.num("Element size", 1)?;
    rd.num("Maximum number of elements bits", 1)?;
    rd.num("Index block elements", 1)?;
    rd.num("Data block minimum elements", 1)?;
    rd.num("Secondary block minimum data block pointers", 1)?;
    rd.num("Maximum data block page elements bits", 1)?;
    rd.length("Secondary blocks")?;
    rd.length("Secondary blocks size")?;
    rd.length("Data blocks")?;
    rd.length("Data blocks size")?;
    rd.length("Maximum index set")?;
    rd.length("Elements realized")?;
    rd.addr("Index block address")?;
    Some(())
}

pub fn ea_node(file: &FileRef, addr: u64) -> Node {
    Node::new("Extensible array")
        .target(file.at(addr, 4))
        .lazy(ea_expand, (file.clone(), addr))
}

async fn ea_expand(cx: Cx, (file, addr): (FileRef, u64)) -> Result<()> {
    let hdr = ea_header(&cx, &file, addr).await?;
    let len = 12usize
        .saturating_add(file.l.saturating_mul(6))
        .saturating_add(file.o);
    let span = file.exact(addr, to_u64(len).saturating_add(4))?;
    let data = cx.read(span).await?;
    let mut rd = Rd::new(&file, &data, span);
    let ok = ea_fields(&mut rd);
    rd.finish(ok);
    let at = rd.pos;
    emit(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    if !file.undef(hdr.iblock) {
        cx.emit(
            Node::new("Index block")
                .target(file.at(hdr.iblock, 4))
                .lazy(ea_iblock, (file.clone(), Arc::new(hdr))),
        );
    }
    Ok(())
}

fn ea_iblock_len(file: &File, hdr: &EaHdr) -> usize {
    let nsblocks = hdr.sblocks().len().saturating_sub(hdr.iblock_sblocks());
    (6usize.saturating_add(file.o))
        .saturating_add(to_usize(hdr.iblock_elems).saturating_mul(hdr.esize))
        .saturating_add(hdr.iblock_dblocks().saturating_mul(file.o))
        .saturating_add(nsblocks.saturating_mul(file.o))
}

async fn ea_iblock(cx: Cx, (file, hdr): (FileRef, Arc<EaHdr>)) -> Result<()> {
    let len = ea_iblock_len(&file, &hdr);
    let span = file.exact(hdr.iblock, to_u64(len).saturating_add(4))?;
    let data = cx.read(span).await?;
    if !data.starts_with(b"EAIB") {
        return Err(
            Diagnostic::malformed("extensible array index block signature missing")
                .at(span.sub(0, 4)),
        );
    }
    let mut rd = Rd::new(&file, &data, span);
    rd.sig(4);
    rd.num("Version", 1);
    rd.en(
        "Client",
        1,
        &[(0, "unfiltered chunks"), (1, "filtered chunks")],
    );
    rd.addr("Header address");
    for i in 0..hdr.iblock_elems {
        let start = rd.pos;
        let mut sub = rd.fork();
        let ok = element_fields(&mut sub, hdr.filtered(), hdr.esize);
        rd.join(format!("Element {i}"), start, sub);
        if ok.is_none() {
            break;
        }
    }
    let sblocks = hdr.sblocks();
    let mut children = Vec::new();
    for &(n, elems) in sblocks.iter().take(hdr.iblock_sblocks()) {
        for _ in 0..n {
            let Some(a) = rd.addr("Data block address") else {
                break;
            };
            if !file.undef(a) {
                children.push(ea_dblock_node(&file, &hdr, a, elems));
            }
        }
    }
    for (u, &(n, elems)) in sblocks.iter().enumerate().skip(hdr.iblock_sblocks()) {
        let Some(a) = rd.addr("Secondary block address") else {
            break;
        };
        if !file.undef(a) {
            children.push(
                Node::new(format!("Secondary block {u}"))
                    .target(file.at(a, 4))
                    .lazy(ea_sblock, (file.clone(), hdr.clone(), a, n, elems)),
            );
        }
    }
    let at = rd.pos;
    emit(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    for c in children {
        cx.push(c).await;
    }
    Ok(())
}

fn ea_dblock_node(file: &FileRef, hdr: &Arc<EaHdr>, addr: u64, elems: u64) -> Node {
    Node::new(format!("Data block at {addr:#x}"))
        .target(file.at(addr, 4))
        .summary(format!("{elems} elements"))
        .lazy(ea_dblock, (file.clone(), hdr.clone(), addr, elems))
}

fn ea_paged(hdr: &EaHdr, elems: u64) -> bool {
    elems > 1u64.checked_shl(hdr.page_bits.into()).unwrap_or(u64::MAX)
}

async fn ea_dblock(
    cx: Cx,
    (file, hdr, addr, elems): (FileRef, Arc<EaHdr>, u64, u64),
) -> Result<()> {
    let prefix = 6usize
        .saturating_add(file.o)
        .saturating_add(hdr.arr_off_size());
    let paged = ea_paged(&hdr, elems);
    let body = if paged {
        0
    } else {
        to_u64(hdr.esize).saturating_mul(elems)
    };
    let len = to_u64(prefix).saturating_add(body).min(MAX_NODE);
    let span = file.exact(addr, len.saturating_add(4))?;
    let data = cx.read(span).await?;
    if !data.starts_with(b"EADB") {
        return Err(
            Diagnostic::malformed("extensible array data block signature missing")
                .at(span.sub(0, 4)),
        );
    }
    let mut rd = Rd::new(&file, &data, span);
    rd.sig(4);
    rd.num("Version", 1);
    rd.en(
        "Client",
        1,
        &[(0, "unfiltered chunks"), (1, "filtered chunks")],
    );
    rd.addr("Header address");
    let n = hdr.arr_off_size();
    rd.num("Block offset", n);
    if paged {
        rd.push(Node::new("Elements").summary("in pages (not shown)"));
    } else {
        for i in 0..elems {
            if i % 256 == 255 {
                cx.checkpoint().await;
            }
            let start = rd.pos;
            let mut sub = rd.fork();
            let ok = element_fields(&mut sub, hdr.filtered(), hdr.esize);
            rd.join(format!("Element {i}"), start, sub);
            if ok.is_none() {
                break;
            }
        }
    }
    let at = rd.pos;
    emit(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    Ok(())
}

async fn ea_sblock(
    cx: Cx,
    (file, hdr, addr, dblocks, elems): (FileRef, Arc<EaHdr>, u64, u64, u64),
) -> Result<()> {
    let paged = ea_paged(&hdr, elems);
    let pages = if paged {
        elems
            .checked_shr(hdr.page_bits.into())
            .unwrap_or(0)
            .saturating_mul(dblocks)
            .div_ceil(8)
    } else {
        0
    };
    let prefix = 6usize
        .saturating_add(file.o)
        .saturating_add(hdr.arr_off_size());
    let len = to_u64(prefix)
        .saturating_add(pages)
        .saturating_add(dblocks.saturating_mul(to_u64(file.o)))
        .min(MAX_NODE);
    let span = file.exact(addr, len.saturating_add(4))?;
    let data = cx.read(span).await?;
    if !data.starts_with(b"EASB") {
        return Err(
            Diagnostic::malformed("extensible array secondary block signature missing")
                .at(span.sub(0, 4)),
        );
    }
    let mut rd = Rd::new(&file, &data, span);
    rd.sig(4);
    rd.num("Version", 1);
    rd.en(
        "Client",
        1,
        &[(0, "unfiltered chunks"), (1, "filtered chunks")],
    );
    rd.addr("Header address");
    let n = hdr.arr_off_size();
    rd.num("Block offset", n);
    if pages > 0 {
        rd.bytes("Page initialization bitmap", to_usize(pages));
    }
    let mut children = Vec::new();
    for _ in 0..dblocks {
        let Some(a) = rd.addr("Data block address") else {
            break;
        };
        if !file.undef(a) {
            children.push(ea_dblock_node(&file, &hdr, a, elems));
        }
    }
    let at = rd.pos;
    emit(&cx, rd.out);
    if let Some(n) = checksum_node(&cx, &data, span, at).await {
        cx.emit(n);
    }
    for c in children {
        cx.push(c).await;
    }
    Ok(())
}

/// Walks an extensible array's elements (index block, then data blocks).
pub struct EaIter {
    file: FileRef,
    pub hdr: Arc<EaHdr>,
    /// Data block addresses in order, with their element counts; filled
    /// as secondary blocks are read.
    blocks: Vec<(u64, u64)>,
    sblocks: Vec<(u64, u64, u64)>,
    next: u64,
    buf: Vec<u8>,
    buf_start: u64,
    block: usize,
    block_start: u64,
}

impl EaIter {
    pub async fn new(cx: &Cx, file: &FileRef, addr: u64) -> Result<EaIter> {
        let hdr = Arc::new(ea_header(cx, file, addr).await?);
        let o = file.o;
        let mut iter = EaIter {
            file: file.clone(),
            hdr: hdr.clone(),
            blocks: Vec::new(),
            sblocks: Vec::new(),
            next: 0,
            buf: Vec::new(),
            buf_start: 0,
            block: 0,
            block_start: hdr.iblock_elems,
        };
        if file.undef(hdr.iblock) {
            return Ok(iter);
        }
        let len = ea_iblock_len(file, &hdr);
        let span = file.exact(hdr.iblock, to_u64(len))?;
        let data = cx.read(span).await?;
        let mut at = 6usize.saturating_add(o);
        iter.buf = data
            .get(at..at.saturating_add(to_usize(hdr.iblock_elems).saturating_mul(hdr.esize)))
            .unwrap_or_default()
            .to_vec();
        at = at.saturating_add(to_usize(hdr.iblock_elems).saturating_mul(hdr.esize));
        let sblocks = hdr.sblocks();
        for &(n, elems) in sblocks.iter().take(hdr.iblock_sblocks()) {
            for _ in 0..n {
                iter.blocks
                    .push((uint(&data, at, o).unwrap_or(u64::MAX), elems));
                at = at.saturating_add(o);
            }
        }
        for &(n, elems) in sblocks.iter().skip(hdr.iblock_sblocks()) {
            iter.sblocks
                .push((uint(&data, at, o).unwrap_or(u64::MAX), n, elems));
            at = at.saturating_add(o);
        }
        iter.sblocks.reverse();
        Ok(iter)
    }

    pub async fn next(&mut self, cx: &Cx) -> Result<Option<Element>> {
        let hdr = self.hdr.clone();
        let o = self.file.o;
        loop {
            if self.next >= hdr.max_index {
                return Ok(None);
            }
            let i = self.next;
            let buffered = to_u64(self.buf.len())
                .checked_div(to_u64(hdr.esize).max(1))
                .unwrap_or(0);
            if i >= self.buf_start && i < self.buf_start.saturating_add(buffered) {
                let at = to_usize(i.saturating_sub(self.buf_start)).saturating_mul(hdr.esize);
                let (addr, size, mask) = element(&self.buf, at, o, hdr.esize, hdr.filtered());
                self.next = i.saturating_add(1);
                return Ok(Some(Element {
                    index: i,
                    addr,
                    size,
                    mask,
                }));
            }
            // Load the data block holding element `i`.
            while self.block >= self.blocks.len() {
                cx.checkpoint().await;
                let Some((sb, n, elems)) = self.sblocks.pop() else {
                    return Ok(None);
                };
                if self.file.undef(sb) {
                    for _ in 0..n.min(1 << 20) {
                        self.blocks.push((u64::MAX, elems));
                    }
                    continue;
                }
                let prefix = 6usize.saturating_add(o).saturating_add(hdr.arr_off_size());
                let paged = ea_paged(&hdr, elems);
                let bitmap = if paged {
                    elems
                        .checked_shr(hdr.page_bits.into())
                        .unwrap_or(0)
                        .saturating_mul(n)
                        .div_ceil(8)
                } else {
                    0
                };
                let start = to_u64(prefix).saturating_add(bitmap);
                let span = self.file.exact(
                    sb.saturating_add(start),
                    n.saturating_mul(to_u64(o)).min(MAX_NODE),
                )?;
                let data = cx.read(span).await?;
                for k in 0..to_usize(n) {
                    self.blocks.push((
                        uint(&data, k.saturating_mul(o), o).unwrap_or(u64::MAX),
                        elems,
                    ));
                }
            }
            let Some(&(addr, elems)) = self.blocks.get(self.block) else {
                return Ok(None);
            };
            let start = self.block_start;
            self.block = self.block.saturating_add(1);
            self.block_start = start.saturating_add(elems);
            if self.file.undef(addr) {
                self.next = self.block_start;
                continue;
            }
            if ea_paged(&hdr, elems) {
                return Err(
                    Diagnostic::unsupported("paged extensible array data blocks")
                        .at(self.file.at(addr, 4)),
                );
            }
            let prefix = 6usize.saturating_add(o).saturating_add(hdr.arr_off_size());
            let span = self.file.exact(
                addr.saturating_add(to_u64(prefix)),
                elems.saturating_mul(to_u64(hdr.esize)).min(MAX_NODE),
            )?;
            self.buf = cx.read(span).await?;
            self.buf_start = start;
        }
    }
}
