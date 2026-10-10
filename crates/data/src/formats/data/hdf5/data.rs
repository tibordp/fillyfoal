//! Raw data: element values (of datasets and attributes), and the chunks
//! of chunked datasets with their filters undone where we have the codec.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{Radix, Value};

use super::btree::{EaIter, FaIter, V1Iter, V2Iter};
use super::datatype::{self, Ty};
use super::message::{ChunkIndex, Filter, Layout, Space};
use super::util::{FileRef, join, size_text, uint};

/// Elements read at once.
const WINDOW: u64 = 64 * 1024;
/// Largest decoded chunk unshuffled or checksummed in memory.
const MAX_CHUNK: u64 = 16 << 20;
/// Bytes of a variable-length value shown.
const MAX_VLEN: u64 = 4096;

/// A dataset: what its chunks and elements need.
pub struct Dset {
    pub file: FileRef,
    pub ty: Option<Arc<Ty>>,
    pub space: Space,
    pub layout: Layout,
    pub filters: Vec<Filter>,
    /// The objects above it (for references in its values).
    pub path: Arc<Vec<u64>>,
}

/// A block of elements stored contiguously, in row-major order.
#[derive(Clone)]
pub struct Block {
    pub file: FileRef,
    pub ty: Arc<Ty>,
    pub span: Span,
    pub shape: Arc<Vec<u64>>,
    /// Coordinates of the block's first element in the dataset.
    pub origin: Arc<Vec<u64>>,
    /// The dataset's extent (elements beyond it are chunk padding).
    pub extent: Arc<Vec<u64>>,
    pub path: Arc<Vec<u64>>,
}

fn product(dims: &[u64]) -> u64 {
    dims.iter().fold(1u64, |a, &d| a.saturating_mul(d))
}

/// Row-major coordinates of element `i` in `shape`.
fn coords(mut i: u64, shape: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; shape.len()];
    for (slot, &d) in out.iter_mut().zip(shape).rev() {
        let d = d.max(1);
        *slot = i.checked_rem(d).unwrap_or(0);
        i = i.checked_div(d).unwrap_or(0);
    }
    out
}

/// A node listing the elements of `block`.
pub fn values_node(name: &'static str, block: Block) -> Node {
    let size = u64::from(block.ty.size()).max(1);
    let n = product(&block.shape).min(block.span.len.checked_div(size).unwrap_or(0));
    Node::new(name)
        .span(block.span)
        .summary(format!(
            "{n} element{}, {}",
            if n == 1 { "" } else { "s" },
            size_text(block.span.len)
        ))
        .lazy(values, block)
}

/// The elements of a block, one node each.
pub async fn values(cx: Cx, b: Block) -> Result<()> {
    let size = u64::from(b.ty.size());
    if size == 0 {
        return Ok(());
    }
    let n = product(&b.shape).min(b.span.len.checked_div(size).unwrap_or(0));
    // Values in the global heap bring their collections along, once each:
    // such walks restart from the beginning rather than from a mark.
    let vlen = b.ty.has_vlen();
    let mut i = if vlen {
        0
    } else {
        cx.resume::<u64>().unwrap_or(0)
    };
    if !vlen && b.extent.is_empty() {
        cx.set_count(Count::Exact(n));
    }
    let per = WINDOW.checked_div(size).unwrap_or(1).clamp(1, 4096);
    let mut heaps = BTreeSet::new();
    // Elements of an edge chunk beyond the dataset's extent are padding:
    // counted, not listed.
    let mut padding = 0u64;
    while i < n {
        let w = per.min(n.saturating_sub(i));
        let span = b.span.sub(i.saturating_mul(size), w.saturating_mul(size));
        let data = cx.read(span).await?;
        for j in 0..w {
            let index = i.saturating_add(j);
            if element_name(&b, index).1 {
                padding = padding.saturating_add(1);
                if j % 1024 == 1023 {
                    cx.checkpoint().await;
                }
                continue;
            }
            let at = to_usize(j.saturating_mul(size));
            let bytes = data
                .get(at..at.saturating_add(to_usize(size)))
                .unwrap_or_default();
            let espan = span.sub(j.saturating_mul(size), size);
            let node = element(&cx, &b, index, bytes, espan, &mut heaps).await;
            if !vlen {
                cx.mark(move || index);
            }
            cx.push(node).await;
        }
        i = i.saturating_add(w);
    }
    if padding > 0 {
        cx.push(Node::new("Chunk padding").summary(format!(
            "{padding} element{} beyond the dataset's extent",
            if padding == 1 { "" } else { "s" }
        )))
        .await;
    }
    Ok(())
}

fn element_name(b: &Block, index: u64) -> (String, bool) {
    if b.shape.is_empty() {
        return ("Value".to_owned(), false);
    }
    let local = coords(index, &b.shape);
    let global: Vec<u64> = local
        .iter()
        .zip(b.origin.iter().chain(std::iter::repeat(&0)))
        .map(|(&l, &o)| l.saturating_add(o))
        .collect();
    let outside = !b.extent.is_empty() && global.iter().zip(b.extent.iter()).any(|(&g, &e)| g >= e);
    (format!("[{}]", join(&global, ", ")), outside)
}

/// One element: its value, and what it refers to.
async fn element(
    cx: &Cx,
    b: &Block,
    index: u64,
    bytes: &[u8],
    span: Span,
    heaps: &mut BTreeSet<u64>,
) -> Node {
    let (name, _) = element_name(b, index);
    let mut node = Node::new(name).span(span);
    let file = &b.file;
    match &*b.ty {
        Ty::Vlen { string, base, .. } => {
            let o = file.o;
            let len = uint(bytes, 0, 4).unwrap_or(0);
            let addr = uint(bytes, 4, o).unwrap_or(0);
            let idx = uint(bytes, 4usize.saturating_add(o), 4).unwrap_or(0);
            if len == 0 || addr == 0 || file.undef(addr) {
                return node.value(Value::Text(String::new())).summary("empty");
            }
            if heaps.insert(addr) {
                cx.push(super::heap::gcol_node(file, addr)).await;
            }
            let object =
                match super::heap::gheap_object(cx, file, addr, u32::try_from(idx).unwrap_or(0))
                    .await
                {
                    Ok(s) => s,
                    Err(e) => return node.diag(e),
                };
            let data = match cx.read_avail(object.sub(0, MAX_VLEN)).await {
                Ok(d) => d,
                Err(e) => return node.diag(e),
            };
            node = node.target(object);
            if *string {
                let text = String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_owned();
                node.value(Value::Text(text))
            } else {
                let width = to_usize(base.size().into()).max(1);
                let mut parts: Vec<String> = data
                    .chunks_exact(width)
                    .take(64)
                    .map(|c| datatype::format(base, c))
                    .collect();
                if to_u64(data.len().checked_div(width).unwrap_or(0)) < len || len > 64 {
                    parts.push("…".to_owned());
                }
                node.value(Value::Text(format!("[{}]", parts.join(", "))))
                    .summary(format!("{len} elements"))
            }
        }
        Ty::Ref { kind: 0, .. } => {
            let addr = uint(bytes, 0, bytes.len().min(8)).unwrap_or(u64::MAX);
            node = node.value(Value::UInt {
                value: addr,
                bits: 64,
                radix: Radix::Hex,
            });
            if addr == 0 || file.undef(addr) {
                return node.summary("null reference");
            }
            let target = super::object_node(file, "Object".to_owned(), addr, &b.path);
            node.summary("object reference")
                .target(file.at(addr, 4))
                .lazy(super::util::emit_all, Arc::new(vec![target]))
        }
        Ty::Ref { kind: 1, .. } => {
            let o = file.o;
            let addr = uint(bytes, 0, o).unwrap_or(u64::MAX);
            let idx = uint(bytes, o, 4).unwrap_or(0);
            node = node.value(Value::Text(format!("heap {addr:#x}, object {idx}")));
            if addr == 0 || file.undef(addr) {
                return node.summary("null region reference");
            }
            match super::heap::gheap_object(cx, file, addr, u32::try_from(idx).unwrap_or(0)).await {
                Ok(s) => node.target(s).summary("dataset region reference"),
                Err(e) => node.diag(e),
            }
        }
        Ty::Compound { members, .. } => {
            let mut children = Vec::new();
            for m in members {
                let at = to_usize(m.offset.into());
                let len = to_usize(m.ty.size().into());
                let Some(field) = at.checked_add(len).and_then(|end| bytes.get(at..end)) else {
                    continue;
                };
                children.push(
                    Node::new(m.name.clone())
                        .span(span.sub(to_u64(at), to_u64(len)))
                        .value(datatype::value(&m.ty, field)),
                );
            }
            node.value(Value::Text(datatype::format(&b.ty, bytes)))
                .lazy(super::util::emit_all, Arc::new(children))
        }
        ty => node.value(datatype::value(ty, bytes)),
    }
}

/// A one-line rendering of a whole (small) block, for summaries: the value
/// itself for one element, a list for a few.
pub async fn preview(cx: &Cx, b: &Block) -> Option<Value> {
    let size = u64::from(b.ty.size());
    let n = product(&b.shape).min(b.span.len.checked_div(size.max(1)).unwrap_or(0));
    if n == 0 || size == 0 {
        return None;
    }
    let shown = n.min(8);
    let data = cx
        .read(b.span.sub(0, shown.saturating_mul(size)))
        .await
        .ok()?;
    let mut parts = Vec::new();
    for j in 0..shown {
        let at = to_usize(j.saturating_mul(size));
        let bytes = data.get(at..at.saturating_add(to_usize(size)))?;
        let (value, text) = match &*b.ty {
            Ty::Vlen { string, base, .. } => {
                let o = b.file.o;
                let addr = uint(bytes, 4, o).unwrap_or(0);
                let idx = uint(bytes, 4usize.saturating_add(o), 4).unwrap_or(0);
                let span =
                    super::heap::gheap_object(cx, &b.file, addr, u32::try_from(idx).unwrap_or(0))
                        .await
                        .ok()?;
                let d = cx.read_avail(span.sub(0, 256)).await.ok()?;
                if *string {
                    let s = String::from_utf8_lossy(&d)
                        .trim_end_matches('\0')
                        .to_owned();
                    (Value::Text(s.clone()), format!("{s:?}"))
                } else {
                    let width = to_usize(base.size().into()).max(1);
                    let items: Vec<String> = d
                        .chunks_exact(width)
                        .take(16)
                        .map(|c| datatype::format(base, c))
                        .collect();
                    let s = format!("[{}]", items.join(", "));
                    (Value::Text(s.clone()), s)
                }
            }
            Ty::Ref { kind: 1, .. } => return None,
            ty => (datatype::value(ty, bytes), datatype::format(ty, bytes)),
        };
        if n == 1 {
            return Some(value);
        }
        parts.push(text);
    }
    if n > shown {
        parts.push("…".to_owned());
    }
    Some(Value::Text(format!("[{}]", parts.join(", "))))
}

// ---------------------------------------------------------------------------
// Datasets

/// The node for a dataset's raw data, by layout.
pub fn data_node(d: &Arc<Dset>) -> Option<Node> {
    let file = &d.file;
    let elem = d.ty.as_ref().map_or(0, |t| u64::from(t.size()));
    let block = |span: Span| {
        d.ty.as_ref().map(|ty| Block {
            file: file.clone(),
            ty: ty.clone(),
            span,
            shape: Arc::new(d.space.dims.clone()),
            origin: Arc::new(Vec::new()),
            extent: Arc::new(Vec::new()),
            path: d.path.clone(),
        })
    };
    Some(match &d.layout {
        Layout::Compact { data } => match block(*data) {
            Some(b) => values_node("Data", b),
            None => Node::new("Data").span(*data),
        },
        Layout::Contiguous { addr, size } => {
            let size = size.unwrap_or_else(|| d.space.count().saturating_mul(elem));
            if file.undef(*addr) {
                return Some(Node::new("Data").summary("not allocated: reads as the fill value"));
            }
            let span = file.at(*addr, size);
            let mut node = match block(span) {
                Some(b) => values_node("Data", b),
                None => Node::new("Data").span(span),
            };
            if span.len < size {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset, size),
                    span.len,
                ));
            }
            node
        }
        Layout::Chunked { dims, elem, .. } => {
            let bytes = product(dims).saturating_mul(*elem);
            Node::new("Chunks")
                .summary(format!(
                    "chunks of {} ({})",
                    super::util::shape(dims),
                    size_text(bytes)
                ))
                .lazy(chunks, d.clone())
        }
        Layout::Virtual { heap, index } => {
            let heap = *heap;
            let index = *index;
            Node::new("Virtual dataset mapping")
                .summary(format!("global heap {heap:#x}, object {index}"))
                .target(file.at(heap, 4))
                .lazy(
                    super::util::emit_all,
                    Arc::new(vec![super::heap::gcol_node(file, heap)]),
                )
        }
        Layout::Other => return None,
    })
}

#[derive(Clone, Debug)]
struct Chunk {
    addr: u64,
    stored: u64,
    mask: u32,
    /// Element coordinates of the chunk's first element.
    offset: Vec<u64>,
}

/// Chunks per dimension over `extent`.
fn per_dim(extent: &[u64], chunk: &[u64]) -> Vec<u64> {
    extent
        .iter()
        .zip(chunk)
        .map(|(&e, &c)| e.div_ceil(c.max(1)))
        .collect()
}

/// The extent used to number chunks: the maximum dimensions where fixed.
fn numbering_extent(space: &Space) -> Vec<u64> {
    match &space.max {
        Some(max) => max
            .iter()
            .zip(&space.dims)
            .map(|(&m, &d)| if m == u64::MAX { d } else { m })
            .collect(),
        None => space.dims.clone(),
    }
}

/// Element coordinates of chunk number `i` of a fixed array or implicit
/// index (row-major over the chunks of the maximum extent).
fn chunk_offset(i: u64, space: &Space, dims: &[u64]) -> Vec<u64> {
    let scaled = coords(i, &per_dim(&numbering_extent(space), dims));
    scaled
        .iter()
        .zip(dims)
        .map(|(&s, &c)| s.saturating_mul(c))
        .collect()
}

/// Element coordinates of chunk number `i` of an extensible array, which
/// numbers chunks with the unlimited dimension first.
fn ea_offset(i: u64, space: &Space, dims: &[u64]) -> Vec<u64> {
    let rank = dims.len();
    let unlim = space
        .max
        .as_ref()
        .and_then(|m| m.iter().position(|&v| v == u64::MAX))
        .unwrap_or(0);
    let order: Vec<usize> = std::iter::once(unlim)
        .chain((0..rank).filter(|&k| k != unlim))
        .collect();
    let extent = numbering_extent(space);
    let counts = per_dim(&extent, dims);
    let swizzled: Vec<u64> = order
        .iter()
        .map(|&k| counts.get(k).copied().unwrap_or(1))
        .collect();
    // The first (unlimited) dimension has no bound: let it absorb the rest.
    let mut rest = i;
    let mut out = vec![0u64; rank];
    for (j, &k) in order.iter().enumerate() {
        let down = swizzled
            .iter()
            .skip(j.saturating_add(1))
            .fold(1u64, |a, &d| a.saturating_mul(d.max(1)));
        let c = rest.checked_div(down).unwrap_or(0);
        rest = rest.checked_rem(down).unwrap_or(0);
        if let (Some(slot), Some(&size)) = (out.get_mut(k), dims.get(k)) {
            *slot = c.saturating_mul(size);
        }
    }
    out
}

async fn chunks(cx: Cx, d: Arc<Dset>) -> Result<()> {
    let Layout::Chunked {
        dims,
        elem,
        index,
        addr,
        ..
    } = &d.layout
    else {
        return Ok(());
    };
    let file = &d.file;
    let full = product(dims).saturating_mul(*elem);
    let rank = dims.len();
    if file.undef(*addr) {
        cx.emit(Node::new("No chunks").summary("not allocated: reads as the fill value"));
        return Ok(());
    }
    match index {
        ChunkIndex::BtreeV1 => {
            let key = 8usize.saturating_add(rank.saturating_add(1).saturating_mul(8));
            let mut it = V1Iter::new(file, *addr, key);
            while let Some(e) = it.next(&cx).await? {
                let offset = (0..rank)
                    .map(|k| {
                        uint(&e.key, 8usize.saturating_add(k.saturating_mul(8)), 8).unwrap_or(0)
                    })
                    .collect();
                let c = Chunk {
                    addr: e.child,
                    stored: uint(&e.key, 0, 4).unwrap_or(0),
                    mask: u32::try_from(uint(&e.key, 4, 4).unwrap_or(0)).unwrap_or(0),
                    offset,
                };
                cx.push(chunk_node(&d, c)).await;
            }
            for p in it.problems {
                cx.diag(p);
            }
        }
        ChunkIndex::Single { filtered } => {
            let (stored, mask) = filtered.unwrap_or((full, 0));
            let c = Chunk {
                addr: *addr,
                stored,
                mask,
                offset: vec![0; rank],
            };
            cx.push(chunk_node(&d, c)).await;
        }
        ChunkIndex::Implicit => {
            let n = product(&per_dim(&numbering_extent(&d.space), dims));
            for i in 0..n {
                let c = Chunk {
                    addr: addr.saturating_add(i.saturating_mul(full)),
                    stored: full,
                    mask: 0,
                    offset: chunk_offset(i, &d.space, dims),
                };
                cx.push(chunk_node(&d, c)).await;
            }
        }
        ChunkIndex::Fixed => {
            let mut it = FaIter::new(&cx, file, *addr).await?;
            while let Some(e) = it.next(&cx).await? {
                if file.undef(e.addr) {
                    continue;
                }
                let c = Chunk {
                    addr: e.addr,
                    stored: e.size.unwrap_or(full),
                    mask: e.mask,
                    offset: chunk_offset(e.index, &d.space, dims),
                };
                cx.push(chunk_node(&d, c)).await;
            }
        }
        ChunkIndex::Extensible => {
            let mut it = EaIter::new(&cx, file, *addr).await?;
            while let Some(e) = it.next(&cx).await? {
                if file.undef(e.addr) {
                    continue;
                }
                let c = Chunk {
                    addr: e.addr,
                    stored: e.size.unwrap_or(full),
                    mask: e.mask,
                    offset: ea_offset(e.index, &d.space, dims),
                };
                cx.push(chunk_node(&d, c)).await;
            }
        }
        ChunkIndex::BtreeV2 => {
            let mut it = V2Iter::new(&cx, file, *addr).await?;
            cx.set_count(Count::Exact(it.hdr.total));
            let filtered = it.hdr.kind == 11;
            let o = file.o;
            while let Some(r) = it.next(&cx).await? {
                let chunk_addr = uint(&r.data, 0, o).unwrap_or(u64::MAX);
                let scaled_at = r.data.len().saturating_sub(rank.saturating_mul(8));
                let (stored, mask) = if filtered {
                    let width = scaled_at.saturating_sub(o).saturating_sub(4);
                    (
                        uint(&r.data, o, width).unwrap_or(0),
                        u32::try_from(uint(&r.data, o.saturating_add(width), 4).unwrap_or(0))
                            .unwrap_or(0),
                    )
                } else {
                    (full, 0)
                };
                let offset = (0..rank)
                    .map(|k| {
                        uint(&r.data, scaled_at.saturating_add(k.saturating_mul(8)), 8)
                            .unwrap_or(0)
                            .saturating_mul(dims.get(k).copied().unwrap_or(1))
                    })
                    .collect();
                let c = Chunk {
                    addr: chunk_addr,
                    stored,
                    mask,
                    offset,
                };
                cx.push(chunk_node(&d, c)).await;
            }
        }
    }
    Ok(())
}

/// The filters applied to a chunk (those its mask does not skip), in
/// pipeline order.
fn active(filters: &[Filter], mask: u32) -> Vec<Filter> {
    filters
        .iter()
        .enumerate()
        .filter(|(i, _)| {
            u32::try_from(*i)
                .ok()
                .and_then(|i| 1u32.checked_shl(i))
                .is_none_or(|bit| mask & bit == 0)
        })
        .map(|(_, f)| f.clone())
        .collect()
}

fn chunk_node(d: &Arc<Dset>, c: Chunk) -> Node {
    let filters = active(&d.filters, c.mask);
    let names: Vec<String> = filters.iter().map(Filter::label).collect();
    let mut summary = size_text(c.stored);
    if !names.is_empty() {
        summary = format!("{summary}, {}", names.join(" → "));
    }
    if c.mask != 0 {
        summary = format!("{summary} (filter mask {:#x})", c.mask);
    }
    Node::new(format!("Chunk [{}]", join(&c.offset, ", ")))
        .span(d.file.at(c.addr, c.stored))
        .value(Value::UInt {
            value: c.addr,
            bits: 64,
            radix: Radix::Hex,
        })
        .summary(summary)
        .lazy(chunk_expand, (d.clone(), c))
}

fn codec_for(f: &Filter) -> Option<Codec> {
    Some(match f.id {
        1 => Codec::Zlib,
        307 => Codec::Bzip2,
        32000 => Codec::Lzf,
        32015 => Codec::Zstd,
        _ => return None,
    })
}

fn block_for(d: &Dset, c: &Chunk, span: Span) -> Option<Block> {
    let Layout::Chunked { dims, .. } = &d.layout else {
        return None;
    };
    Some(Block {
        file: d.file.clone(),
        ty: d.ty.clone()?,
        span,
        shape: Arc::new(dims.clone()),
        origin: Arc::new(c.offset.clone()),
        extent: Arc::new(d.space.dims.clone()),
        path: d.path.clone(),
    })
}

async fn chunk_expand(cx: Cx, (d, c): (Arc<Dset>, Chunk)) -> Result<()> {
    let Layout::Chunked { dims, elem, .. } = &d.layout else {
        return Ok(());
    };
    let full = product(dims).saturating_mul(*elem);
    let mut span = d.file.at(c.addr, c.stored);
    let mut filters = active(&d.filters, c.mask);
    if filters.is_empty() {
        if let Some(b) = block_for(&d, &c, span) {
            return values(cx, b).await;
        }
        return Ok(());
    }
    // Fletcher-32 is applied last: its checksum ends the chunk.
    if filters.last().is_some_and(|f| f.id == 3) {
        filters.pop();
        let body = span.sub(0, span.len.saturating_sub(4));
        let sum = span.sub(body.len, 4);
        let raw = cx.read(sum).await?;
        let stored = crate::bytes::u32_le(&raw, 0).unwrap_or(0);
        let mut node = Node::new("Fletcher-32 checksum")
            .span(sum)
            .value(Value::UInt {
                value: stored.into(),
                bits: 32,
                radix: Radix::Hex,
            });
        if body.len <= MAX_CHUNK {
            let data = cx.read(body).await?;
            let computed = super::util::fletcher32(&cx, &data).await;
            let b = computed.to_le_bytes();
            let reversed = u32::from_le_bytes([b[1], b[0], b[3], b[2]]);
            node = if stored == computed || stored == reversed {
                node.summary("valid")
            } else {
                node.diag(Diagnostic::warning(format!(
                    "checksum mismatch: computed {computed:#010x}"
                )))
            };
        }
        cx.emit(node);
        span = body;
    }
    let shuffle = filters
        .first()
        .filter(|f| f.id == 2)
        .map(|f| f.values.first().copied().map_or(*elem, u64::from));
    if shuffle.is_some() {
        filters.remove(0);
    }
    let mut codecs = Vec::new();
    for f in filters.iter().rev() {
        match codec_for(f) {
            Some(codec) => codecs.push(codec),
            None => {
                cx.emit(
                    Node::new("Filtered data")
                        .span(span)
                        .summary(size_text(span.len))
                        .diag(Diagnostic::unsupported(format!("the {} filter", f.label()))),
                );
                return Ok(());
            }
        }
    }
    let name = match filters.first() {
        Some(f) if filters.len() == 1 => format!("{} stream", f.label()),
        Some(_) => "Filtered data".to_owned(),
        None => "Shuffled data".to_owned(),
    };
    let codec = match codecs.len() {
        0 => None,
        1 => codecs.pop(),
        _ => Some(Codec::chain("hdf5-filters", "hdf5-filters (lazy)", codecs)),
    };
    cx.emit(
        Node::new(name)
            .span(span)
            .summary(format!("{} → {}", size_text(span.len), size_text(full)))
            .lazy(decoded, (d.clone(), c, span, codec, shuffle, full)),
    );
    Ok(())
}

async fn decoded(
    cx: Cx,
    (d, c, span, codec, shuffle, full): (Arc<Dset>, Chunk, Span, Option<Codec>, Option<u64>, u64),
) -> Result<()> {
    let mut out = span;
    if let Some(codec) = &codec {
        out = if full > MAX_CHUNK {
            cx.decode_lazy(span, codec, full)?
        } else {
            let decoded = crate::codec::decode_span(&cx, span, codec, Some(full)).await?;
            if let Some(e) = decoded.error {
                cx.diag(e);
            }
            decoded.span
        };
    }
    if let Some(width) = shuffle {
        out = unshuffle(&cx, out, width).await?;
    }
    if let Some(b) = block_for(&d, &c, out) {
        values(cx, b).await?;
    }
    Ok(())
}

/// Undoes HDF5's byte shuffle (byte `j` of every element stored together),
/// into a derived source.
async fn unshuffle(cx: &Cx, span: Span, width: u64) -> Result<Span> {
    let origin = Origin {
        parent: span,
        transform: "hdf5-unshuffle",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    if width <= 1 || span.len > MAX_CHUNK {
        if width > 1 {
            cx.diag(Diagnostic::limit(
                "chunk too large to unshuffle; values are shown shuffled",
            ));
        }
        return Ok(span);
    }
    let data = cx.read(span).await?;
    let w = to_usize(width);
    let n = data.len().checked_div(w).unwrap_or(0);
    // Byte `j` of element `i` was stored at `j * n + i`; bytes after the
    // last whole element are stored as they are.
    let mut out = data.clone();
    for (k, slot) in out.iter_mut().enumerate().take(n.saturating_mul(w)) {
        if k % 65536 == 65535 {
            cx.checkpoint().await;
        }
        let (i, j) = (k.checked_div(w).unwrap_or(0), k.checked_rem(w).unwrap_or(0));
        if let Some(&b) = data.get(j.saturating_mul(n).saturating_add(i)) {
            *slot = b;
        }
    }
    let len = to_u64(data.len());
    Ok(cx.add_derived(origin, out, len, None)?.span)
}
