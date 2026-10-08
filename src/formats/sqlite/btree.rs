//! B-tree pages, cells, payloads and traversal.
//!
//! Pages are read whole (they are at most 64 KiB) and decoded in memory.
//! Traversal keeps an explicit stack plus a set of visited pages, so a
//! corrupt file whose pages point at each other (or share children) is
//! reported instead of looping; depth and the number of pages are capped.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::record::{self, Column, Encoding, Val};
use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value};

/// Deepest B-tree followed (real trees are rarely deeper than 10).
pub const MAX_DEPTH: usize = 40;
/// Pages one traversal may visit before giving up.
const MAX_VISITED: usize = 1 << 20;
/// Bytes of a text or blob value read for its node.
const VALUE_PREVIEW: u64 = 4096;

/// What the dissector knows about the database, shared by all expansions.
pub struct Db {
    pub input: Input,
    pub page_size: u64,
    pub usable: u64,
    pub page_count: u64,
    pub encoding: Encoding,
    /// Whether page numbers refer to pages of `input` (false for page images
    /// inside WAL and journal files).
    pub linked: bool,
}

pub type DbRef = Arc<Db>;

impl Db {
    /// The span of page `no` (1-based).
    pub fn page(&self, no: u32) -> Result<Span> {
        if no == 0 || u64::from(no) > self.page_count {
            return Err(Diagnostic::malformed(format!(
                "page {no} is outside the database (1..={})",
                self.page_count
            )));
        }
        let offset = u64::from(no)
            .saturating_sub(1)
            .saturating_mul(self.page_size);
        self.input.span.sub_exact(offset, self.page_size)
    }
}

pub const PAGE_TYPES: EnumTable = &[
    (2, "interior index"),
    (5, "interior table"),
    (10, "leaf index"),
    (13, "leaf table"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    IndexInterior,
    TableInterior,
    IndexLeaf,
    TableLeaf,
}

impl Kind {
    pub fn from_byte(b: u8) -> Option<Kind> {
        Some(match b {
            2 => Kind::IndexInterior,
            5 => Kind::TableInterior,
            10 => Kind::IndexLeaf,
            13 => Kind::TableLeaf,
            _ => return None,
        })
    }

    pub fn is_leaf(self) -> bool {
        matches!(self, Kind::IndexLeaf | Kind::TableLeaf)
    }

    pub fn is_table(self) -> bool {
        matches!(self, Kind::TableInterior | Kind::TableLeaf)
    }

    pub fn name(self) -> &'static str {
        match self {
            Kind::IndexInterior => "interior index",
            Kind::TableInterior => "interior table",
            Kind::IndexLeaf => "leaf index",
            Kind::TableLeaf => "leaf table",
        }
    }

    fn header_len(self) -> usize {
        if self.is_leaf() { 8 } else { 12 }
    }
}

/// A B-tree page read into memory.
pub struct Page {
    pub no: u32,
    pub span: Span,
    pub data: Vec<u8>,
    /// Where the B-tree header starts (100 on page 1).
    pub base: usize,
    pub kind: Kind,
    pub cells: u16,
    pub right: Option<u32>,
}

impl Page {
    /// Decodes the B-tree page at `span` (page `no` of the database).
    pub async fn load(cx: &Cx, no: u32, span: Span) -> Result<Page> {
        let data = cx.read(span).await?;
        let base = if no == 1 { 100 } else { 0 };
        let byte = data.get(base).copied().unwrap_or(0);
        let kind = Kind::from_byte(byte).ok_or_else(|| {
            Diagnostic::malformed(format!("page {no} is not a B-tree page (type byte {byte})"))
                .at(span.sub(to_u64(base), 1))
        })?;
        let cells = u16_be(&data, base.saturating_add(3)).unwrap_or(0);
        let right = if kind.is_leaf() {
            None
        } else {
            u32_be(&data, base.saturating_add(8))
        };
        Ok(Page {
            no,
            span,
            data,
            base,
            kind,
            cells,
            right,
        })
    }

    pub fn header_span(&self) -> Span {
        self.span
            .sub(to_u64(self.base), to_u64(self.kind.header_len()))
    }

    pub fn pointers_span(&self) -> Span {
        self.span.sub(
            to_u64(self.base.saturating_add(self.kind.header_len())),
            u64::from(self.cells).saturating_mul(2),
        )
    }

    /// Offset (within the page) of cell `i`, from the cell pointer array.
    pub fn pointer(&self, i: u16) -> Option<u16> {
        let at = self
            .base
            .saturating_add(self.kind.header_len())
            .saturating_add(usize::from(i).saturating_mul(2));
        u16_be(&self.data, at)
    }

    pub fn cell(&self, i: u16, usable: u64) -> Result<Cell> {
        let offset = self.pointer(i).ok_or_else(|| {
            Diagnostic::malformed(format!("cell pointer {i} lies outside page {}", self.no))
                .at(self.pointers_span())
        })?;
        Cell::parse(self, usable, offset.into()).ok_or_else(|| {
            Diagnostic::malformed(format!(
                "cell {i} at {offset:#x} does not fit in page {}",
                self.no
            ))
            .at(self.span.sub(offset.into(), 4))
        })
    }
}

/// Where a cell's payload is.
#[derive(Clone, Copy, Debug)]
pub struct Payload {
    pub total: u64,
    /// Offset within the page of the part stored locally, and its length.
    pub local_at: u64,
    pub local_len: u64,
    pub overflow: Option<u32>,
}

/// A decoded cell. Offsets are relative to the page.
#[derive(Clone, Copy, Debug)]
pub struct Cell {
    pub page: u32,
    pub page_span: Span,
    pub kind: Kind,
    pub offset: u64,
    pub len: u64,
    pub left: Option<u32>,
    pub rowid: Option<i64>,
    pub rowid_at: (u64, u64),
    pub payload_len_at: (u64, u64),
    pub payload: Option<Payload>,
}

/// How much of a payload of `total` bytes is stored on the page.
fn local_len(kind: Kind, total: u64, usable: u64) -> u64 {
    let u = usable;
    let max = if kind == Kind::TableLeaf {
        u.saturating_sub(35)
    } else {
        (u.saturating_sub(12).saturating_mul(64) / 255).saturating_sub(23)
    };
    if total <= max {
        return total;
    }
    let min = (u.saturating_sub(12).saturating_mul(32) / 255).saturating_sub(23);
    let k = total
        .saturating_sub(min)
        .checked_rem(u.saturating_sub(4))
        .unwrap_or(0)
        .saturating_add(min);
    if k <= max { k } else { min }
}

impl Cell {
    fn parse(page: &Page, usable: u64, offset: u64) -> Option<Cell> {
        let data = &page.data;
        let start = to_usize(offset);
        let mut at = start;
        let mut cell = Cell {
            page: page.no,
            page_span: page.span,
            kind: page.kind,
            offset,
            len: 0,
            left: None,
            rowid: None,
            rowid_at: (0, 0),
            payload_len_at: (0, 0),
            payload: None,
        };
        if !page.kind.is_leaf() {
            cell.left = Some(u32_be(data, at)?);
            at = at.checked_add(4)?;
        }
        if page.kind != Kind::TableInterior {
            let (total, n) = record::varint(data, at)?;
            cell.payload_len_at = (to_u64(at), to_u64(n));
            at = at.checked_add(n)?;
            if page.kind == Kind::TableLeaf {
                let (rowid, n) = record::varint(data, at)?;
                cell.rowid = Some(rowid.cast_signed());
                cell.rowid_at = (to_u64(at), to_u64(n));
                at = at.checked_add(n)?;
            }
            let local = local_len(page.kind, total, usable);
            let local_at = to_u64(at);
            at = at.checked_add(to_usize(local))?;
            let overflow = if local < total {
                let next = u32_be(data, at)?;
                at = at.checked_add(4)?;
                Some(next)
            } else {
                None
            };
            data.get(..at)?;
            cell.payload = Some(Payload {
                total,
                local_at,
                local_len: local,
                overflow,
            });
        } else {
            let (rowid, n) = record::varint(data, at)?;
            cell.rowid = Some(rowid.cast_signed());
            cell.rowid_at = (to_u64(at), to_u64(n));
            at = at.checked_add(n)?;
        }
        cell.len = to_u64(at.saturating_sub(start));
        Some(cell)
    }

    pub fn span(&self) -> Span {
        self.page_span.sub(self.offset, self.len)
    }

    pub fn local_span(&self) -> Option<Span> {
        self.payload
            .map(|p| self.page_span.sub(p.local_at, p.local_len))
    }
}

/// The overflow pages of a payload, in order: `(page number, content
/// span)`. Stops at a cycle, a bad page number, or once the payload is
/// complete; the diagnostic says why it stopped early.
pub async fn overflow_chain(
    cx: &Cx,
    db: &Db,
    payload: &Payload,
) -> (Vec<(u32, Span)>, Option<Diagnostic>) {
    let mut out = Vec::new();
    let mut remaining = payload.total.saturating_sub(payload.local_len);
    let mut next = payload.overflow;
    let mut seen = BTreeSet::new();
    let per_page = db.usable.saturating_sub(4);
    while remaining > 0 {
        cx.checkpoint().await;
        let Some(no) = next.filter(|&n| n != 0) else {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "overflow chain ends with {remaining:#x} payload bytes missing"
                ))),
            );
        };
        if !seen.insert(no) {
            return (
                out,
                Some(Diagnostic::malformed(format!(
                    "overflow chain revisits page {no}"
                ))),
            );
        }
        let span = match db.page(no) {
            Ok(span) => span,
            Err(e) => return (out, Some(e)),
        };
        let head = match cx.read(span.sub(0, 4)).await {
            Ok(head) => head,
            Err(e) => return (out, Some(e)),
        };
        let take = remaining.min(per_page);
        out.push((no, span.sub(4, take)));
        remaining = remaining.saturating_sub(take);
        next = u32_be(&head, 0);
    }
    (out, None)
}

/// The whole payload of a cell as one span: the local part directly, or a
/// piecewise source joining it with its overflow pages.
pub async fn payload_span(cx: &Cx, db: &Db, cell: &Cell) -> Result<(Span, Option<Diagnostic>)> {
    let (Some(payload), Some(local)) = (cell.payload, cell.local_span()) else {
        return Err(Diagnostic::internal("cell has no payload"));
    };
    if payload.overflow.is_none() {
        return Ok((local, None));
    }
    let (chain, diag) = overflow_chain(cx, db, &payload).await;
    let mut pieces = vec![local];
    pieces.extend(chain.into_iter().map(|(_, span)| span));
    let span = cx.add_pieces(
        Origin {
            parent: cell.span(),
            transform: "sqlite-overflow",
        },
        pieces,
    )?;
    Ok((span, diag))
}

// ---------------------------------------------------------------------------
// Traversal

struct Frame {
    page: Page,
    /// Interior pages: step `2i` descends into cell `i`'s left child, step
    /// `2i + 1` yields cell `i` (index trees only), step `2n` descends right.
    /// Leaf pages: step `i` yields cell `i`.
    step: u32,
}

/// Walks a B-tree in key order, yielding cells that carry rows (table
/// leaves) or entries (index cells).
pub struct Walker {
    db: DbRef,
    stack: Vec<Frame>,
    visited: BTreeSet<u32>,
}

enum Action {
    Yield(Cell),
    Descend(u32),
    Pop,
    Skip,
}

impl Walker {
    pub async fn new(cx: &Cx, db: DbRef, root: u32) -> Result<Walker> {
        let page = Page::load(cx, root, db.page(root)?).await?;
        Ok(Walker {
            db,
            stack: vec![Frame { page, step: 0 }],
            visited: BTreeSet::from([root]),
        })
    }

    /// The next cell, or `None` at the end. Problems with individual pages
    /// are attached to the expanding node and skipped.
    pub async fn next(&mut self, cx: &Cx) -> Result<Option<Cell>> {
        loop {
            cx.checkpoint().await;
            let action = match self.stack.last_mut() {
                None => return Ok(None),
                Some(frame) => step(frame, self.db.usable),
            };
            match action {
                Action::Pop => {
                    self.stack.pop();
                }
                Action::Skip => {}
                Action::Yield(cell) => return Ok(Some(cell)),
                Action::Descend(child) => {
                    if let Err(e) = self.descend(cx, child).await {
                        cx.diag(e);
                    }
                }
            }
        }
    }

    /// How far the walk has got, in millionths of the tree, estimated from
    /// the position within each page on the stack (for progress reports).
    pub fn progress(&self) -> u64 {
        let mut done = 0.0f64;
        let mut width = 1.0f64;
        for frame in &self.stack {
            let n = f64::from(frame.page.cells);
            let slots = if frame.page.kind.is_leaf() {
                n
            } else {
                2.0 * n + 1.0
            };
            if slots <= 0.0 {
                break;
            }
            let at = f64::from(frame.step.saturating_sub(1)).min(slots);
            done += width * at / slots;
            width /= slots;
        }
        (done.clamp(0.0, 1.0) * 1e6) as u64
    }

    /// The locally stored payload of a cell just yielded (for summaries).
    pub fn local(&self, cell: &Cell) -> &[u8] {
        self.stack
            .last()
            .filter(|f| f.page.no == cell.page)
            .map_or(&[][..], |f| local_bytes(&f.page, cell))
    }

    async fn descend(&mut self, cx: &Cx, child: u32) -> Result<()> {
        if self.stack.len() >= MAX_DEPTH {
            return Err(Diagnostic::limit(format!(
                "B-tree deeper than {MAX_DEPTH} levels"
            )));
        }
        if self.visited.len() >= MAX_VISITED {
            return Err(Diagnostic::limit(format!(
                "more than {MAX_VISITED} pages in one B-tree"
            )));
        }
        if !self.visited.insert(child) {
            return Err(Diagnostic::malformed(format!(
                "page {child} is referenced more than once in the B-tree"
            )));
        }
        let span = self.db.page(child)?;
        let page = Page::load(cx, child, span).await?;
        let parent_table = self.stack.last().is_some_and(|f| f.page.kind.is_table());
        if page.kind.is_table() != parent_table {
            return Err(Diagnostic::malformed(format!(
                "page {child} ({}) does not belong in this B-tree",
                page.kind.name()
            ))
            .at(span));
        }
        self.stack.push(Frame { page, step: 0 });
        Ok(())
    }
}

fn step(frame: &mut Frame, usable: u64) -> Action {
    let n = u32::from(frame.page.cells);
    let s = frame.step;
    frame.step = frame.step.saturating_add(1);
    let cell = |i: u32| u16::try_from(i).ok().map(|i| frame.page.cell(i, usable));
    if frame.page.kind.is_leaf() {
        return match cell(s) {
            Some(Ok(c)) if s < n => Action::Yield(c),
            Some(Err(_)) if s < n => Action::Skip,
            _ => Action::Pop,
        };
    }
    let last = n.saturating_mul(2);
    if s > last {
        return Action::Pop;
    }
    if s == last {
        return frame.page.right.map_or(Action::Pop, Action::Descend);
    }
    match cell(s / 2) {
        Some(Ok(c)) if s.is_multiple_of(2) => c.left.map_or(Action::Skip, Action::Descend),
        Some(Ok(c)) if frame.page.kind == Kind::IndexInterior => Action::Yield(c),
        _ => Action::Skip,
    }
}

// ---------------------------------------------------------------------------
// Rows and records

/// How a B-tree's records are labelled.
#[derive(Clone)]
pub struct Columns(pub Arc<Vec<Column>>);

/// Values of a record decoded from the bytes at hand (the local part of a
/// payload), for summaries.
pub fn record_summary(
    data: &[u8],
    columns: &[Column],
    rowid: Option<i64>,
    encoding: Encoding,
) -> String {
    const MAX_COLUMNS: usize = 8;
    let Some((_, fields)) = record::header(data) else {
        return "(unreadable record)".to_owned();
    };
    let mut parts = Vec::new();
    for (i, field) in fields.iter().enumerate().take(MAX_COLUMNS) {
        let start = to_usize(field.offset);
        let end = to_usize(field.offset.saturating_add(field.len)).min(data.len());
        let bytes = data.get(start..end).unwrap_or_default();
        let complete = to_u64(bytes.len()) == field.len;
        let text = match record::decode(field.serial, bytes, encoding) {
            Some(Val::Null) if columns.get(i).is_some_and(|c| c.rowid_alias) => {
                rowid.map_or_else(|| "NULL".to_owned(), |r| r.to_string())
            }
            Some(v) => record::short(&v, complete),
            None => "…".to_owned(),
        };
        parts.push(text);
    }
    if fields.len() > MAX_COLUMNS {
        parts.push("…".to_owned());
    }
    format!("({})", parts.join(", "))
}

/// Everything needed to show one cell (a row, an index entry, or an
/// interior cell).
#[derive(Clone)]
pub struct CellState {
    pub db: DbRef,
    pub cell: Cell,
    pub columns: Columns,
    /// Pages on the way here, for links to child pages.
    pub path: Arc<Vec<u32>>,
}

/// The node for a row or entry, labelled by rowid (tables) or position.
pub fn row_node(state: CellState, label: String, local: &[u8]) -> Node {
    let summary = record_summary(local, &state.columns.0, state.cell.rowid, state.db.encoding);
    Node::new(label)
        .span(state.cell.span())
        .summary(summary)
        .lazy(expand_cell, state)
}

/// The local payload bytes of a cell, for summaries (no extra reads).
pub fn local_bytes<'a>(page: &'a Page, cell: &Cell) -> &'a [u8] {
    cell.payload
        .and_then(|p| {
            page.data
                .get(to_usize(p.local_at)..to_usize(p.local_at.saturating_add(p.local_len)))
        })
        .unwrap_or_default()
}

fn uint(name: &'static str, value: u64, span: Span) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    })
}

/// Expands a cell: its values, then its raw structure.
pub async fn expand_cell(cx: Cx, state: CellState) -> Result<()> {
    let db = &state.db;
    let cell = &state.cell;
    if cell.payload.is_some() {
        let (payload, diag) = payload_span(&cx, db, cell).await?;
        if let Some(d) = diag {
            cx.diag(d);
        }
        record_nodes(&cx, &state, payload).await?;
    }
    cx.emit(
        Node::new("Cell")
            .span(cell.span())
            .summary(format!(
                "{:#x} bytes at page offset {:#x}",
                cell.len, cell.offset
            ))
            .lazy(cell_fields, state.clone()),
    );
    if let Some(left) = cell.left {
        cx.emit(super::page_link(
            "Left child page",
            db,
            left,
            &state.path,
            super::Role::BTree,
        ));
    }
    Ok(())
}

async fn cell_fields(cx: Cx, state: CellState) -> Result<()> {
    let cell = &state.cell;
    let at = |offset: u64, len: u64| cell.page_span.sub(offset, len);
    if let Some(left) = cell.left {
        cx.emit(uint("Left child page", left.into(), at(cell.offset, 4)));
    }
    if let Some(p) = cell.payload {
        let (o, n) = cell.payload_len_at;
        cx.emit(
            uint("Payload size", p.total, at(o, n))
                .desc("Varint: bytes of payload, including overflow"),
        );
    }
    if let Some(rowid) = cell.rowid {
        let (o, n) = cell.rowid_at;
        cx.emit(
            Node::new(if cell.kind == Kind::TableInterior {
                "Key (rowid)"
            } else {
                "Rowid"
            })
            .span(at(o, n))
            .value(Value::Int {
                value: rowid,
                bits: 64,
            }),
        );
    }
    if let Some(p) = cell.payload {
        cx.emit(
            Node::new("Local payload")
                .span(at(p.local_at, p.local_len))
                .summary(format!("{} of {} bytes", p.local_len, p.total)),
        );
        if let Some(first) = p.overflow {
            let end = p.local_at.saturating_add(p.local_len);
            let mut node = uint("First overflow page", first.into(), at(end, 4));
            if let Ok(target) = state.db.page(first) {
                node = node.target(target);
            }
            cx.emit(node);
            cx.emit(
                Node::new("Overflow chain")
                    .summary(format!(
                        "{:#x} bytes on overflow pages",
                        p.total.saturating_sub(p.local_len)
                    ))
                    .lazy(overflow_pages, state.clone()),
            );
        }
    }
    Ok(())
}

async fn overflow_pages(cx: Cx, state: CellState) -> Result<()> {
    let Some(payload) = state.cell.payload else {
        return Ok(());
    };
    let (chain, diag) = overflow_chain(&cx, &state.db, &payload).await;
    for (no, content) in chain {
        cx.push(
            super::page_link(
                "Overflow page",
                &state.db,
                no,
                &state.path,
                super::Role::Overflow,
            )
            .summary(format!("page {no}, {:#x} payload bytes", content.len)),
        )
        .await;
    }
    if let Some(d) = diag {
        cx.diag(d);
    }
    Ok(())
}

/// The values of the record in `payload`, one node per column, plus the
/// record header.
async fn record_nodes(cx: &Cx, state: &CellState, payload: Span) -> Result<()> {
    let head = cx.read_avail(payload.sub(0, 9)).await?;
    let (size, _) = record::varint(&head, 0)
        .ok_or_else(|| Diagnostic::malformed("invalid record header size").at(payload.sub(0, 9)))?;
    let header_span = payload.sub_exact(0, size)?;
    let header = cx.read(header_span.sub(0, 0x10000)).await?;
    let (_, fields) = record::header(&header)
        .ok_or_else(|| Diagnostic::malformed("invalid record header").at(header_span))?;
    let columns = &state.columns.0;
    for (i, field) in fields.iter().enumerate() {
        cx.checkpoint().await;
        let name = columns
            .get(i)
            .map_or_else(|| format!("Column {i}"), |c| c.name.clone());
        let span = payload.sub(field.offset, field.len);
        let mut node = Node::new(name).span(span);
        if span.len < field.len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, field.len),
                span.len,
            ));
        }
        let data = cx.read_avail(span.sub(0, VALUE_PREVIEW)).await?;
        let complete = to_u64(data.len()) == field.len;
        node = match record::decode(field.serial, &data, state.db.encoding) {
            Some(Val::Null) if columns.get(i).is_some_and(|c| c.rowid_alias) => {
                match state.cell.rowid {
                    Some(rowid) => node
                        .value(Value::Int {
                            value: rowid,
                            bits: 64,
                        })
                        .summary("INTEGER PRIMARY KEY (stored as NULL; the rowid)"),
                    None => node.summary("NULL"),
                }
            }
            Some(Val::Null) => node.summary("NULL"),
            Some(Val::Int(v)) => node.value(Value::Int { value: v, bits: 64 }),
            Some(Val::Float(v)) => node.value(Value::Float(v)),
            Some(Val::Text(s)) => {
                let node = node.value(Value::Text(s));
                if complete {
                    node
                } else {
                    node.summary(format!("{} bytes", field.len))
                }
            }
            Some(Val::Blob(b)) => {
                let node = node
                    .value(Value::Bytes(b.into_iter().take(32).collect()))
                    .summary(format!("{} bytes", field.len));
                if field.len >= 16 {
                    node.lazy(crate::formats::dissect_or_data, state.db.input.nested(span))
                } else {
                    node
                }
            }
            None => node,
        };
        cx.emit(node);
    }
    cx.emit(
        Node::new("Record header")
            .span(header_span)
            .summary(format!("{} columns", fields.len()))
            .lazy(record_header, (header_span, Arc::new(fields))),
    );
    Ok(())
}

async fn record_header(cx: Cx, (span, fields): (Span, Arc<Vec<record::Field>>)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 9)).await?;
    if let Some((size, n)) = record::varint(&head, 0) {
        cx.emit(uint("Header size", size, span.sub(0, to_u64(n))));
    }
    for (i, field) in fields.iter().enumerate() {
        cx.push(
            Node::new(format!("Serial type {i}"))
                .span(span.sub(field.type_at, field.type_len))
                .value(Value::UInt {
                    value: field.serial,
                    bits: 64,
                    radix: Radix::Dec,
                })
                .summary(record::serial_name(field.serial)),
        )
        .await;
    }
    Ok(())
}
