//! The lists, tables and properties (LTP) layer: heap-on-node, BTH,
//! property contexts and table contexts ([MS-PST] 2.3).

use std::sync::Arc;

use super::ndb::{self, Block, Pst, SubEntry};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::Span;

pub const SIG_HN: u8 = 0xec;
pub const SIG_BTH: u8 = 0xb5;
pub const SIG_PC: u8 = 0xbc;
pub const SIG_TC: u8 = 0x7c;

/// A node holding LTP data: its data tree and its subnodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NodeRef {
    pub nid: u32,
    pub data: u64,
    pub sub: u64,
}

impl NodeRef {
    pub fn from_sub(e: &SubEntry) -> Self {
        NodeRef {
            nid: e.nid,
            data: e.data,
            sub: e.sub,
        }
    }
}

// ---------------------------------------------------------------------------
// Heap-on-node

#[derive(Debug)]
pub struct Heap {
    pub node: NodeRef,
    pub blocks: Vec<Block>,
    pub client_sig: u8,
    pub user_root: u32,
    /// The HNHDR (in the first block).
    pub header: Span,
}

pub async fn heap(cx: &Cx, pst: &Pst, node: NodeRef) -> Result<Arc<Heap>> {
    let root = ndb::block(cx, pst, node.data).await?;
    if let Some(found) = cx.cached::<Heap>(root.alloc, "pst-heap") {
        return Ok(found);
    }
    let blocks = ndb::data_tree(cx, pst, node.data).await?;
    let first = blocks
        .first()
        .ok_or_else(|| Diagnostic::malformed("node has no data blocks"))?;
    let plain = ndb::plain(cx, pst, first).await?;
    let header = plain.sub(0, 12);
    let data = cx.read(header).await?;
    let sig = data.get(2).copied().unwrap_or(0);
    if sig != SIG_HN {
        return Err(Diagnostic::malformed(format!(
            "not a heap-on-node (signature {sig:#04x}, expected 0xec)"
        ))
        .at(header));
    }
    let heap = Arc::new(Heap {
        node,
        client_sig: data.get(3).copied().unwrap_or(0),
        user_root: u32_le(&data, 4).unwrap_or(0),
        blocks,
        header,
    });
    cx.cache(root.alloc, "pst-heap", heap.clone());
    Ok(heap)
}

/// The page map of one heap block: allocation boundaries.
#[derive(Debug)]
pub struct PageMap {
    pub block: Span,
    pub bounds: Vec<u16>,
}

pub async fn page_map(cx: &Cx, pst: &Pst, heap: &Heap, index: usize) -> Result<Arc<PageMap>> {
    let block = heap
        .blocks
        .get(index)
        .ok_or_else(|| Diagnostic::malformed(format!("heap block {index} does not exist")))?;
    let plain = ndb::plain(cx, pst, block).await?;
    if let Some(found) = cx.cached::<PageMap>(plain, "pst-hnmap") {
        return Ok(found);
    }
    let data = cx.read(plain).await?;
    let at = usize::from(u16_le(&data, 0).unwrap_or(0));
    let count = u16_le(&data, at).unwrap_or(0);
    let mut bounds = Vec::new();
    for i in 0..=usize::from(count) {
        match u16_le(
            &data,
            at.saturating_add(4).saturating_add(i.saturating_mul(2)),
        ) {
            Some(b) => bounds.push(b),
            None => {
                return Err(Diagnostic::malformed("heap page map runs past its block").at(plain));
            }
        }
    }
    let pm = Arc::new(PageMap {
        block: plain,
        bounds,
    });
    cx.cache(plain, "pst-hnmap", pm.clone());
    Ok(pm)
}

/// The span of a heap allocation (an HID).
pub async fn item(cx: &Cx, pst: &Pst, heap: &Heap, hid: u32) -> Result<Span> {
    if hid == 0 {
        // An empty value.
        return Ok(heap.header.sub(0, 0));
    }
    if hid & 0x1f != 0 {
        return Err(Diagnostic::malformed(format!("{hid:#x} is not a heap ID")));
    }
    let index = ((hid >> 5) & 0x7ff) as usize;
    let block = (hid >> 16) as usize;
    let pm = page_map(cx, pst, heap, block).await?;
    let start = index.checked_sub(1).and_then(|i| pm.bounds.get(i)).copied();
    let end = pm.bounds.get(index).copied();
    match (start, end) {
        (Some(s), Some(e)) if s <= e => pm
            .block
            .sub_exact(u64::from(s), u64::from(e.saturating_sub(s))),
        _ => Err(Diagnostic::malformed(format!(
            "heap ID {hid:#x}: no allocation {index} in block {block}"
        ))),
    }
}

/// Resolves an HNID: a heap allocation, or a subnode's data.
pub async fn hnid(cx: &Cx, pst: &Pst, heap: &Heap, id: u32) -> Result<Span> {
    if id & 0x1f == 0 {
        return item(cx, pst, heap, id).await;
    }
    let sub = find_sub(cx, pst, heap.node.sub, id).await?;
    ndb::stream(cx, pst, sub.data).await
}

pub async fn find_sub(cx: &Cx, pst: &Pst, sub_bid: u64, nid: u32) -> Result<SubEntry> {
    let subs = ndb::subnodes(cx, pst, sub_bid).await?;
    subs.iter()
        .find(|e| e.nid == nid)
        .copied()
        .ok_or_else(|| Diagnostic::malformed(format!("subnode {nid:#x} not found")))
}

// ---------------------------------------------------------------------------
// BTH

#[derive(Clone, Copy, Debug)]
pub struct BthHeader {
    pub span: Span,
    pub key: u8,
    pub ent: u8,
    pub levels: u8,
    pub root: u32,
}

pub async fn bth_header(cx: &Cx, pst: &Pst, heap: &Heap, hid: u32) -> Result<BthHeader> {
    let span = item(cx, pst, heap, hid).await?;
    let data = cx.read(span).await?;
    let sig = data.first().copied().unwrap_or(0);
    if sig != SIG_BTH || data.len() < 8 {
        return Err(Diagnostic::malformed(format!("not a BTH header (type {sig:#04x})")).at(span));
    }
    Ok(BthHeader {
        span,
        key: data.get(1).copied().unwrap_or(0),
        ent: data.get(2).copied().unwrap_or(0),
        levels: data.get(3).copied().unwrap_or(0),
        root: u32_le(&data, 4).unwrap_or(0),
    })
}

/// All leaf records of a BTH, in key order: `(bytes, span)`.
pub async fn bth_records(
    cx: &Cx,
    pst: &Pst,
    heap: &Heap,
    h: &BthHeader,
) -> Result<Vec<(Vec<u8>, Span)>> {
    let mut out = Vec::new();
    if h.root == 0 {
        return Ok(out);
    }
    if h.levels > 8 {
        return Err(Diagnostic::malformed(format!(
            "BTH with {} index levels",
            h.levels
        )));
    }
    let key = u64::from(h.key);
    let leaf = key.saturating_add(u64::from(h.ent));
    let branch = key.saturating_add(4);
    if key == 0 || leaf == key {
        return Err(Diagnostic::malformed("BTH with empty keys or records").at(h.span));
    }
    let mut pending = vec![(h.root, h.levels)];
    while let Some((hid, level)) = pending.pop() {
        cx.checkpoint().await;
        let span = item(cx, pst, heap, hid).await?;
        let data = cx.read(span).await?;
        let size = if level == 0 { leaf } else { branch };
        let mut children = Vec::new();
        let mut at = 0u64;
        while at.saturating_add(size) <= to_u64(data.len()) {
            let rec = data
                .get(to_usize(at)..to_usize(at.saturating_add(size)))
                .unwrap_or_default();
            if level == 0 {
                out.push((rec.to_vec(), span.sub(at, size)));
            } else {
                let child = u32_le(rec, to_usize(key)).unwrap_or(0);
                children.push((child, level.saturating_sub(1)));
            }
            at = at.saturating_add(size);
        }
        pending.extend(children.into_iter().rev());
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Property context

/// A property of a property context, as stored in its BTH record.
#[derive(Clone, Copy, Debug)]
pub struct Prop {
    pub id: u16,
    pub ty: u16,
    pub raw: u32,
    pub record: Span,
}

pub struct Pc {
    pub heap: Arc<Heap>,
    pub props: Vec<Prop>,
}

pub async fn pc(cx: &Cx, pst: &Pst, node: NodeRef) -> Result<Pc> {
    let heap = heap(cx, pst, node).await?;
    if heap.client_sig != SIG_PC {
        return Err(Diagnostic::malformed(format!(
            "not a property context (heap client {:#04x})",
            heap.client_sig
        ))
        .at(heap.header));
    }
    let bth = bth_header(cx, pst, &heap, heap.user_root).await?;
    if bth.key != 2 || bth.ent != 6 {
        return Err(Diagnostic::malformed(format!(
            "property context BTH with {}-byte keys and {}-byte records",
            bth.key, bth.ent
        ))
        .at(bth.span));
    }
    let records = bth_records(cx, pst, &heap, &bth).await?;
    let props = records
        .iter()
        .map(|(r, span)| Prop {
            id: u16_le(r, 0).unwrap_or(0),
            ty: u16_le(r, 2).unwrap_or(0),
            raw: u32_le(r, 4).unwrap_or(0),
            record: *span,
        })
        .collect();
    Ok(Pc { heap, props })
}

/// Fixed size of a property type, if it is fixed.
pub fn fixed_size(ty: u16) -> Option<u64> {
    Some(match ty {
        0x0002 => 2,
        0x0003 | 0x0004 | 0x000a => 4,
        0x000b => 1,
        0x0005 | 0x0006 | 0x0007 | 0x0014 | 0x0040 => 8,
        0x0048 => 16,
        _ => return None,
    })
}

/// Where a property's value lives.
#[derive(Clone, Copy, Debug)]
pub enum Raw {
    /// Stored in the record itself (types of up to 4 bytes).
    Inline(u32, Span),
    /// In the heap or a subnode.
    Data(Span),
}

pub async fn prop_value(cx: &Cx, pst: &Pst, heap: &Heap, p: &Prop) -> Result<Raw> {
    if fixed_size(p.ty).is_some_and(|s| s <= 4) {
        let size = fixed_size(p.ty).unwrap_or(4);
        return Ok(Raw::Inline(p.raw, p.record.sub(4, size)));
    }
    Ok(Raw::Data(hnid(cx, pst, heap, p.raw).await?))
}

// ---------------------------------------------------------------------------
// Table context

#[derive(Clone, Copy, Debug)]
pub struct Column {
    pub tag: u32,
    pub offset: u16,
    pub size: u8,
    pub bit: u8,
    pub span: Span,
}

impl Column {
    pub fn id(&self) -> u16 {
        (self.tag >> 16) as u16
    }
    pub fn ty(&self) -> u16 {
        (self.tag & 0xffff) as u16
    }
}

/// Where the rows of a table live.
#[derive(Clone, Debug)]
pub enum Rows {
    None,
    /// A heap allocation.
    Heap(Span),
    /// A subnode's data blocks; rows never straddle blocks.
    Blocks(Vec<Block>),
}

pub struct Tc {
    pub heap: Arc<Heap>,
    pub info: Span,
    pub columns: Vec<Column>,
    /// End offsets of the 4-, 2- and 1-byte groups, and the row size.
    pub groups: [u16; 4],
    pub rows: Rows,
    /// For [`Rows::Blocks`]: the row index just past each block's rows.
    row_ends: Vec<u64>,
}

impl Tc {
    pub fn row_size(&self) -> u64 {
        u64::from(self.groups[3])
    }

    pub fn column(&self, id: u16) -> Option<&Column> {
        self.columns.iter().find(|c| c.id() == id)
    }

    fn per_block(&self, pst: &Pst) -> u64 {
        pst.max_block_data()
            .checked_div(self.row_size())
            .unwrap_or(0)
    }

    pub fn count(&self, pst: &Pst) -> u64 {
        let size = self.row_size();
        if size == 0 {
            return 0;
        }
        let per = self.per_block(pst);
        match &self.rows {
            Rows::None => 0,
            Rows::Heap(span) => span.len.checked_div(size).unwrap_or(0),
            Rows::Blocks(blocks) => blocks
                .iter()
                .map(|b| b.raw.len.checked_div(size).unwrap_or(0).min(per))
                .fold(0u64, u64::saturating_add),
        }
    }

    /// The span of row `index` (in matrix order).
    pub async fn row(&self, cx: &Cx, pst: &Pst, index: u64) -> Result<Span> {
        let size = self.row_size();
        match &self.rows {
            Rows::None => Err(Diagnostic::malformed("table has no rows")),
            Rows::Heap(span) => span.sub_exact(index.saturating_mul(size), size),
            Rows::Blocks(blocks) => {
                // The first block whose rows end past `index`.
                let i = self.row_ends.partition_point(|&end| end <= index);
                let (Some(b), Some(&end)) = (blocks.get(i), self.row_ends.get(i)) else {
                    return Err(Diagnostic::malformed(format!(
                        "row {index} past the end of the table"
                    )));
                };
                let per = self.per_block(pst).max(1);
                let here = b.raw.len.checked_div(size).unwrap_or(0).min(per);
                let remaining = index.saturating_sub(end.saturating_sub(here));
                let plain = ndb::plain(cx, pst, b).await?;
                plain.sub_exact(remaining.saturating_mul(size), size)
            }
        }
    }
}

pub async fn tc(cx: &Cx, pst: &Pst, node: NodeRef) -> Result<Tc> {
    let heap = heap(cx, pst, node).await?;
    if heap.client_sig != SIG_TC {
        return Err(Diagnostic::malformed(format!(
            "not a table context (heap client {:#04x})",
            heap.client_sig
        ))
        .at(heap.header));
    }
    let info = item(cx, pst, &heap, heap.user_root).await?;
    let data = cx.read(info).await?;
    let sig = data.first().copied().unwrap_or(0);
    if sig != SIG_TC {
        return Err(Diagnostic::malformed(format!("TCINFO type {sig:#04x}")).at(info));
    }
    let count = data.get(1).copied().unwrap_or(0);
    let g = |i: usize| u16_le(&data, 2usize.saturating_add(i.saturating_mul(2))).unwrap_or(0);
    let groups = [g(0), g(1), g(2), g(3)];
    let rows_hnid = u32_le(&data, 14).unwrap_or(0);
    let mut columns = Vec::new();
    for i in 0..usize::from(count) {
        let at = 22usize.saturating_add(i.saturating_mul(8));
        let Some(tag) = u32_le(&data, at) else {
            break;
        };
        columns.push(Column {
            tag,
            offset: u16_le(&data, at.saturating_add(4)).unwrap_or(0),
            size: data.get(at.saturating_add(6)).copied().unwrap_or(0),
            bit: data.get(at.saturating_add(7)).copied().unwrap_or(0),
            span: info.sub(to_u64(at), 8),
        });
    }
    if !(groups[0] <= groups[1] && groups[1] <= groups[2] && groups[2] <= groups[3]) {
        return Err(Diagnostic::malformed("table column groups out of order").at(info));
    }
    let rows = if rows_hnid == 0 {
        Rows::None
    } else if rows_hnid & 0x1f == 0 {
        Rows::Heap(item(cx, pst, &heap, rows_hnid).await?)
    } else {
        let sub = find_sub(cx, pst, node.sub, rows_hnid).await?;
        Rows::Blocks(ndb::data_tree(cx, pst, sub.data).await?)
    };
    let mut tc = Tc {
        heap,
        info,
        columns,
        groups,
        rows,
        row_ends: Vec::new(),
    };
    if let Rows::Blocks(blocks) = &tc.rows {
        let size = tc.row_size();
        let per = tc.per_block(pst).max(1);
        let mut end = 0u64;
        tc.row_ends = blocks
            .iter()
            .map(|b| {
                end = end.saturating_add(b.raw.len.checked_div(size).unwrap_or(0).min(per));
                end
            })
            .collect();
    }
    Ok(tc)
}

/// A cell of a row: absent, fixed bytes in the row, or an HNID's data.
pub enum Cell {
    Fixed(Vec<u8>, Span),
    Data(Span),
}

pub async fn cell(
    cx: &Cx,
    pst: &Pst,
    tc: &Tc,
    row: &[u8],
    row_span: Span,
    col: &Column,
) -> Result<Option<Cell>> {
    let ceb = usize::from(tc.groups[2]).saturating_add(usize::from(col.bit / 8));
    let present = row
        .get(ceb)
        .is_some_and(|b| b & (0x80u8 >> (col.bit % 8)) != 0);
    if !present {
        return Ok(None);
    }
    let at = usize::from(col.offset);
    let size = usize::from(col.size);
    let bytes = row
        .get(at..at.saturating_add(size))
        .ok_or_else(|| Diagnostic::malformed("column outside the row").at(row_span))?
        .to_vec();
    let span = row_span.sub(to_u64(at), to_u64(size));
    let inline = fixed_size(col.ty()).is_some_and(|s| s <= 8);
    if inline {
        return Ok(Some(Cell::Fixed(bytes, span)));
    }
    let id = u32_le(&bytes, 0).unwrap_or(0);
    let data = hnid(cx, pst, &tc.heap, id).await?;
    Ok(Some(Cell::Data(data)))
}
