//! Apple BOM stores (bill-of-materials files, also `Assets.car`): the
//! store's header, block index and named variables, and the B+ trees many
//! variables hold. The asset catalog dissector (`mobile::apple`) builds on
//! these.

use std::collections::{BTreeSet, VecDeque};
use std::sync::Arc;

use crate::bytes::{to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::size;
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Apple BOM (Bill of Materials; also Assets.car)

declare_format!(pub BOMSTORE = "bom", "Apple bill of materials (BOMStore)", ["bom", "car"], "application/x-bom",
    Probe::Magic(&[(0, b"BOMStore")]), bomstore);

record! {
    pub struct BomHeader {
        magic: ascii[8] "Magic",
        version: u32 "Version",
        blocks: u32 "Non-null blocks",
        index_offset: u32 "Block index offset" .hex(),
        index_length: u32 "Block index length",
        vars_offset: u32 "Variables offset" .hex(),
        vars_length: u32 "Variables length",
    }
}

/// Most variables read.
const MAX_VARS: u32 = 1024;
/// Most tree pages followed.
const MAX_PAGES: usize = 100_000;
/// Bytes of a tree entry's key or value shown.
const PREVIEW: u64 = 64;

/// A BOM store: its block index and named variables.
pub struct Bom {
    pub input: Input,
    pub file: Span,
    /// The block index: a count, then (offset, length) pairs.
    pub index: Vec<u8>,
    /// Variables: name, block and the span of the entry naming them.
    pub vars: Vec<(String, u32, Span)>,
}

impl Bom {
    /// The number of blocks in the index.
    pub fn block_count(&self) -> u32 {
        u32_be(&self.index, 0).unwrap_or(0)
    }

    /// The span of block `id`.
    pub fn block(&self, id: u32) -> Option<Span> {
        let at = to_usize(u64::from(id).saturating_mul(8)).saturating_add(4);
        let offset = u32_be(&self.index, at)?;
        let len = u32_be(&self.index, at.saturating_add(4))?;
        Some(self.file.sub(offset.into(), len.into()))
    }

    /// The span of the block variable `name` refers to.
    pub fn var(&self, name: &str) -> Option<Span> {
        self.vars
            .iter()
            .find(|v| v.0 == name)
            .and_then(|v| self.block(v.1))
    }
}

/// Reads the header, block index and variables of the store in `input`.
pub async fn read_bom(cx: &Cx, input: Input) -> Result<Bom> {
    let file = input.span;
    let h: BomHeader = read_record(cx, file.sub(0, BomHeader::SIZE), BE).await?;
    let index = cx
        .read(file.sub_exact(h.index_offset.into(), h.index_length.into())?)
        .await?;
    let mut cur = Cursor::new(cx, file.sub(h.vars_offset.into(), h.vars_length.into()), BE);
    let count = cur.u32().await?;
    let mut vars = Vec::new();
    for _ in 0..count.min(MAX_VARS) {
        let start = cur.pos();
        let block = cur.u32().await?;
        let len = cur.u8().await?;
        let name = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
        vars.push((name, block, cur.since(start)));
    }
    Ok(Bom {
        input,
        file,
        index,
        vars,
    })
}

/// A walk over the leaf entries of a BOM tree (a `tree` block): descends to
/// the leftmost leaf, then follows the leaves' forward links.
pub struct TreeWalk {
    /// The tree header block.
    pub span: Span,
    /// The root page's block.
    pub root: u32,
    /// The number of paths the header records.
    pub paths: u32,
    page: u32,
    done: bool,
    visited: BTreeSet<u32>,
    pending: VecDeque<(u32, u32)>,
}

impl TreeWalk {
    /// Reads the header of the tree in block `block`.
    pub async fn new(cx: &Cx, bom: &Bom, block: u32) -> Result<TreeWalk> {
        let span = bom
            .block(block)
            .ok_or_else(|| Diagnostic::malformed("missing tree block"))?;
        let head = cx.read(span.sub(0, 21)).await?;
        if head.get(..4) != Some(b"tree") {
            return Err(Diagnostic::malformed("not a BOM tree").at(span.sub(0, 4)));
        }
        let root = u32_be(&head, 8).unwrap_or(0);
        Ok(TreeWalk {
            span,
            root,
            paths: u32_be(&head, 16).unwrap_or(0),
            page: root,
            done: false,
            visited: BTreeSet::new(),
            pending: VecDeque::new(),
        })
    }

    /// The next leaf entry: its value and key blocks.
    pub async fn next(&mut self, cx: &Cx, bom: &Bom) -> Result<Option<(u32, u32)>> {
        while self.pending.is_empty() && !self.done {
            let page = self.page;
            if !self.visited.insert(page) || self.visited.len() > MAX_PAGES {
                return Err(Diagnostic::malformed(format!("tree page {page} revisited")));
            }
            let span = bom
                .block(page)
                .ok_or_else(|| Diagnostic::malformed(format!("missing page {page}")))?;
            let h = cx.read(span.sub(0, 12)).await?;
            let leaf = u16_be(&h, 0).unwrap_or(0) != 0;
            let count = u16_be(&h, 2).unwrap_or(0);
            let forward = u32_be(&h, 4).unwrap_or(0);
            let entries = cx
                .read(span.sub_exact(12, u64::from(count).saturating_mul(8))?)
                .await?;
            if !leaf {
                self.page = u32_be(&entries, 0)
                    .ok_or_else(|| Diagnostic::malformed("empty index page").at(span))?;
                continue;
            }
            for i in 0..usize::from(count) {
                let value = u32_be(&entries, i.saturating_mul(8)).unwrap_or(0);
                let key = u32_be(&entries, i.saturating_mul(8).saturating_add(4)).unwrap_or(0);
                self.pending.push_back((value, key));
            }
            self.page = forward;
            self.done = forward == 0;
        }
        Ok(self.pending.pop_front())
    }
}

async fn bomstore(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(BomHeader::node("Header", file.sub(0, BomHeader::SIZE), BE));
    let bom = Arc::new(read_bom(&cx, input).await?);
    for (name, block, var) in &bom.vars {
        let span = bom.block(*block).unwrap_or(file.sub(0, 0));
        let node = if cx.read_avail(span.sub(0, 4)).await? == b"tree" {
            Node::new(name.clone())
                .span(span)
                .summary(format!("block {block}, B+ tree"))
                .lazy(tree_entries, (bom.clone(), *block))
        } else {
            embedded(name.clone(), input.nested(span))
                .summary(format!("block {block}, {} bytes", span.len))
        };
        cx.push(node.target(*var)).await;
    }
    let names: Vec<&str> = bom.vars.iter().map(|v| v.0.as_str()).collect();
    cx.annotate(format!(
        "BOMStore, {} blocks, variables: {}",
        bom.block_count(),
        names.join(", ")
    ));
    Ok(())
}

/// The leaf entries of a tree, in key order.
async fn tree_entries(cx: Cx, (bom, block): (Arc<Bom>, u32)) -> Result<()> {
    let mut walk = TreeWalk::new(&cx, &bom, block).await?;
    cx.emit(
        Node::new("Tree header")
            .span(walk.span)
            .summary(format!("root page {}, {} paths", walk.root, walk.paths)),
    );
    let mut i = 0u64;
    while let Some((value, key)) = walk.next(&cx, &bom).await? {
        let key_span = bom.block(key).unwrap_or(bom.file.sub(0, 0));
        let value_span = bom.block(value).unwrap_or(bom.file.sub(0, 0));
        cx.push(
            Node::new(format!("Entry {i}"))
                .summary(format!(
                    "key block {key} ({}), value block {value} ({})",
                    size(key_span.len),
                    size(value_span.len)
                ))
                .lazy(tree_entry, (key_span, value_span)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn tree_entry(cx: Cx, (key, value): (Span, Span)) -> Result<()> {
    for (name, span) in [("Key", key), ("Value", value)] {
        let data = cx.read_avail(span.sub(0, PREVIEW)).await?;
        cx.emit(Node::new(name).span(span).value(Value::Bytes(data)));
    }
    Ok(())
}
