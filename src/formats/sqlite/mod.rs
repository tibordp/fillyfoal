//! SQLite 3 databases, plus their write-ahead logs and rollback journals.
//!
//! Expanding the file reads the 100-byte header and page 1 (to summarise
//! the schema). Everything else is lazy:
//!
//! - **Schema**: the rows of `sqlite_master`, each with its definition, its
//!   rows (or index entries) in key order, and its root page;
//! - **Freelist** and **Pointer map** (auto-vacuum) pages;
//! - **Pages**: every page by number, with its type.
//!
//! B-tree traversal is iterative with a visited set (see `btree.rs`); page
//! links carry the path of pages above them, so cycles are reported rather
//! than followed. Payloads that spill onto overflow pages become piecewise
//! sources, so a large blob is dissected in place without copying.

mod btree;
mod record;
mod wal;

use std::collections::BTreeSet;
use std::sync::Arc;

use btree::{CellState, Columns, Db, DbRef, Kind, Page, Walker};
use record::{Column, Encoding, Val};

pub use wal::{JOURNAL, WAL};

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const BE: Endian = Endian::Big;
const MAGIC: &[u8] = b"SQLite format 3\0";
/// Schema entries looked at to summarise the database.
const MAX_SUMMARY_ENTRIES: usize = 10_000;
/// Freelist pages remembered to classify pages in the page list.
const MAX_FREELIST: usize = 1 << 16;

pub static FORMAT: Format = Format {
    name: "sqlite",
    title: "SQLite 3 database",
    extensions: &["sqlite", "sqlite3", "db", "db3", "s3db", "sl3"],
    mime: "application/vnd.sqlite3",
    probe: Probe::Custom(|h| {
        h.starts_with(MAGIC) && !matches!(app_id(h), Some(GPKG | GP10 | GP11 | MBTILES_ID))
    }),
    dissect: crate::expander!(dissect: Input),
};

pub static GEOPACKAGE: Format = Format {
    name: "gpkg",
    title: "OGC GeoPackage (SQLite)",
    extensions: &["gpkg"],
    mime: "application/geopackage+sqlite3",
    probe: Probe::Custom(|h| h.starts_with(MAGIC) && matches!(app_id(h), Some(GPKG | GP10 | GP11))),
    dissect: crate::expander!(dissect: Input),
};

pub static MBTILES: Format = Format {
    name: "mbtiles",
    title: "MBTiles tile set (SQLite)",
    extensions: &["mbtiles"],
    mime: "application/vnd.mapbox-vector-tile",
    probe: Probe::Custom(|h| h.starts_with(MAGIC) && app_id(h) == Some(MBTILES_ID)),
    dissect: crate::expander!(dissect: Input),
};

const GPKG: u32 = 0x4750_4b47;
const GP10: u32 = 0x4750_3130;
const GP11: u32 = 0x4750_3131;
const MBTILES_ID: u32 = 0x4d50_4258;

fn app_id(h: &Head<'_>) -> Option<u32> {
    u32_be(h.data, 68)
}

const APPLICATION_IDS: EnumTable = &[
    (0x0f05_5112, "Fossil repository"),
    (0x0f05_5113, "Fossil checkout"),
    (0x0f05_5111, "Fossil global configuration"),
    (0x4750_4b47, "GeoPackage"),
    (0x4750_3130, "GeoPackage 1.0"),
    (0x4750_3131, "GeoPackage 1.1"),
    (0x4d50_4258, "MBTiles"),
];

const FORMAT_VERSIONS: EnumTable = &[(1, "legacy (rollback journal)"), (2, "WAL")];
const ENCODINGS: EnumTable = &[(1, "UTF-8"), (2, "UTF-16le"), (3, "UTF-16be")];

fn sqlite_version(v: u32) -> String {
    format!("{}.{}.{}", v / 1_000_000, v / 1000 % 1000, v % 1000)
}

record! {
    /// The database header (first 100 bytes of page 1).
    pub struct Header {
        magic: ascii[16] "Header string",
        page_size: u16 "Page size" .desc("Bytes per page; 1 means 65536"),
        write_version: u8 "File format write version" .enumeration(FORMAT_VERSIONS),
        read_version: u8 "File format read version" .enumeration(FORMAT_VERSIONS),
        reserved: u8 "Reserved space per page" .desc("Bytes at the end of each page used by extensions (e.g. encryption)"),
        max_fraction: u8 "Maximum embedded payload fraction" .desc("Must be 64"),
        min_fraction: u8 "Minimum embedded payload fraction" .desc("Must be 32"),
        leaf_fraction: u8 "Leaf payload fraction" .desc("Must be 32"),
        change_counter: u32 "File change counter",
        page_count: u32 "Database size in pages" .desc("Valid only if the version-valid-for number matches the change counter"),
        freelist_trunk: u32 "First freelist trunk page",
        freelist_count: u32 "Number of freelist pages",
        schema_cookie: u32 "Schema cookie",
        schema_format: u32 "Schema format number",
        cache_size: i32 "Default page cache size",
        largest_root: u32 "Largest root B-tree page" .desc("Non-zero for auto-vacuum and incremental-vacuum databases"),
        encoding: u32 "Text encoding" .enumeration(ENCODINGS),
        user_version: u32 "User version",
        incremental_vacuum: u32 "Incremental vacuum mode",
        application_id: u32 "Application ID" .enumeration(APPLICATION_IDS),
        _reserved: bytes[20] "Reserved for expansion",
        version_valid_for: u32 "Version-valid-for number",
        sqlite_version: u32 "SQLite version number" .with(|&v, n| n.summary(sqlite_version(v))),
    }
}

/// Real page size from the header field.
fn page_size(raw: u16) -> Option<u64> {
    let size = if raw == 1 { 65536 } else { u64::from(raw) };
    (size.is_power_of_two() && (512..=65536).contains(&size)).then_some(size)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    cx.emit(Header::node("Database Header", header_span, BE));
    let header = crate::fields::parse(&cx, header_span, BE, &(), Header::layout).await?;

    let page_size = page_size(header.page_size).ok_or_else(|| {
        Diagnostic::malformed(format!("invalid page size {}", header.page_size))
            .at(header_span.sub(16, 2))
    })?;
    let usable = page_size.saturating_sub(header.reserved.into());
    if usable < 480 {
        return Err(Diagnostic::malformed(format!(
            "usable page size {usable} is below the minimum of 480"
        ))
        .at(header_span.sub(20, 1)));
    }
    let from_file = file.len.checked_div(page_size).unwrap_or(0);
    let page_count = if header.page_count != 0 && header.version_valid_for == header.change_counter
    {
        u64::from(header.page_count)
    } else {
        from_file
    };
    if page_count > from_file {
        cx.diag(Diagnostic::truncated(
            file.sub(0, page_count.saturating_mul(page_size)),
            file.len,
        ));
    }
    let db: DbRef = Arc::new(Db {
        input,
        page_size,
        usable,
        page_count: page_count.min(from_file),
        encoding: Encoding::from_header(header.encoding),
        linked: true,
    });

    let counts = schema_counts(&cx, &db).await;
    cx.annotate(annotation(&header, &db, counts.as_ref().ok()));
    let mut schema = Node::new("Schema")
        .span(db.page(1).unwrap_or(file))
        .desc("The sqlite_master table: tables, indexes, views and triggers")
        .lazy(schema_entries, db.clone());
    match counts {
        Ok(c) => schema = schema.summary(c.describe()),
        Err(e) => schema = schema.diag(e),
    }
    cx.emit(schema);

    if header.freelist_trunk != 0 {
        cx.emit(
            Node::new("Freelist")
                .summary(format!("{} pages", header.freelist_count))
                .lazy(freelist, (db.clone(), header.freelist_trunk)),
        );
    }
    if header.largest_root != 0 {
        cx.emit(
            Node::new("Pointer map")
                .summary("auto-vacuum back-pointers")
                .lazy(pointer_maps, db.clone()),
        );
    }
    cx.emit(
        Node::new("Pages")
            .summary(format!("{} pages of {} bytes", db.page_count, page_size))
            .lazy(
                pages,
                (db.clone(), header.freelist_trunk, header.largest_root),
            ),
    );
    let end = db.page_count.saturating_mul(page_size);
    if end < file.len {
        cx.emit(
            Node::new("Trailing data")
                .span(file.tail(end))
                .summary(format!(
                    "{:#x} bytes after the last page",
                    file.len.saturating_sub(end)
                )),
        );
    }
    Ok(())
}

fn annotation(header: &Header, db: &Db, counts: Option<&Counts>) -> String {
    let mut out = format!(
        "SQLite {} database, {} pages of {} bytes",
        sqlite_version(header.sqlite_version),
        db.page_count,
        db.page_size
    );
    if let Some(name) = crate::value::lookup(APPLICATION_IDS, header.application_id.into()) {
        out = format!("{out}, {name}");
    }
    if header.write_version == 2 {
        out.push_str(", WAL mode");
    }
    if db.encoding != Encoding::Utf8 {
        out = format!("{out}, {:?}", db.encoding);
    }
    if let Some(c) = counts {
        out = format!("{out}; {}", c.describe());
    }
    out
}

#[derive(Default)]
struct Counts {
    tables: usize,
    indexes: usize,
    views: usize,
    triggers: usize,
    more: bool,
}

impl Counts {
    fn describe(&self) -> String {
        let part =
            |n: usize, one: &str, many: &str| format!("{n} {}", if n == 1 { one } else { many });
        let mut out = format!(
            "{}, {}, {}, {}",
            part(self.tables, "table", "tables"),
            part(self.indexes, "index", "indexes"),
            part(self.views, "view", "views"),
            part(self.triggers, "trigger", "triggers")
        );
        if self.more {
            out.push_str(" (at least)");
        }
        out
    }
}

/// Counts schema objects from the local part of each sqlite_master row
/// (its first column, the type, is always stored locally).
async fn schema_counts(cx: &Cx, db: &DbRef) -> Result<Counts> {
    let mut walker = Walker::new(cx, db.clone(), 1).await?;
    let mut counts = Counts::default();
    let mut seen = 0usize;
    while let Some(cell) = walker.next(cx).await? {
        seen = seen.saturating_add(1);
        if seen > MAX_SUMMARY_ENTRIES {
            counts.more = true;
            break;
        }
        let local = walker.local(&cell);
        let kind = first_text(local, db.encoding);
        match kind.as_deref() {
            Some("table") => counts.tables = counts.tables.saturating_add(1),
            Some("index") => counts.indexes = counts.indexes.saturating_add(1),
            Some("view") => counts.views = counts.views.saturating_add(1),
            Some("trigger") => counts.triggers = counts.triggers.saturating_add(1),
            _ => {}
        }
    }
    Ok(counts)
}

fn first_text(local: &[u8], encoding: Encoding) -> Option<String> {
    let (_, fields) = record::header(local)?;
    let field = fields.first()?;
    let start = crate::bytes::to_usize(field.offset);
    let bytes = local.get(start..start.saturating_add(crate::bytes::to_usize(field.len)))?;
    match record::decode(field.serial, bytes, encoding)? {
        Val::Text(s) => Some(s),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Schema

const MASTER_COLUMNS: [&str; 5] = ["type", "name", "tbl_name", "rootpage", "sql"];

fn master_columns() -> Columns {
    Columns(Arc::new(
        MASTER_COLUMNS
            .iter()
            .map(|n| Column {
                name: (*n).to_owned(),
                rowid_alias: false,
            })
            .collect(),
    ))
}

/// Reads a whole record (with overflow) and decodes its values; text and
/// blobs are cut at 64 KiB.
async fn read_record(cx: &Cx, db: &Db, cell: &btree::Cell) -> Result<Vec<Val>> {
    let (payload, _) = btree::payload_span(cx, db, cell).await?;
    let head = cx.read_avail(payload.sub(0, 9)).await?;
    let (size, _) = record::varint(&head, 0)
        .ok_or_else(|| Diagnostic::malformed("invalid record header").at(payload.sub(0, 9)))?;
    let header = cx.read(payload.sub_exact(0, size.min(0x10000))?).await?;
    let (_, fields) =
        record::header(&header).ok_or_else(|| Diagnostic::malformed("invalid record header"))?;
    let mut values = Vec::new();
    for field in fields {
        let data = cx
            .read_avail(payload.sub(field.offset, field.len.min(0x10000)))
            .await?;
        values.push(record::decode(field.serial, &data, db.encoding).unwrap_or(Val::Null));
    }
    Ok(values)
}

#[derive(Clone)]
struct SchemaEntry {
    db: DbRef,
    cell: btree::Cell,
    root: u32,
    columns: Columns,
    is_index: bool,
}

async fn schema_entries(cx: Cx, db: DbRef) -> Result<()> {
    let mut walker = Walker::new(&cx, db.clone(), 1).await?;
    while let Some(cell) = walker.next(&cx).await? {
        let values = match read_record(&cx, &db, &cell).await {
            Ok(v) => v,
            Err(e) => {
                cx.push(Node::new("Unreadable schema row").span(cell.span()).diag(e))
                    .await;
                continue;
            }
        };
        let text = |i: usize| match values.get(i) {
            Some(Val::Text(s)) => s.clone(),
            _ => String::new(),
        };
        let (kind, name, sql) = (text(0), text(1), text(4));
        let root = match values.get(3) {
            Some(Val::Int(n)) => u32::try_from(*n).unwrap_or(0),
            _ => 0,
        };
        let is_index = kind == "index";
        let mut columns = if sql.to_ascii_uppercase().contains("WITHOUT ROWID") {
            Vec::new()
        } else {
            record::columns(&sql)
        };
        if is_index && !columns.is_empty() {
            columns.push(Column {
                name: "rowid".to_owned(),
                rowid_alias: false,
            });
        }
        let summary = if sql.is_empty() {
            "(no SQL: internal object)".to_owned()
        } else {
            squash(&sql)
        };
        cx.push(
            Node::new(format!("{kind} {name}"))
                .span(cell.span())
                .summary(summary)
                .lazy(
                    schema_entry,
                    SchemaEntry {
                        db: db.clone(),
                        cell,
                        root,
                        columns: Columns(Arc::new(columns)),
                        is_index,
                    },
                ),
        )
        .await;
    }
    Ok(())
}

/// SQL on one line, shortened.
fn squash(sql: &str) -> String {
    const MAX: usize = 120;
    let flat = sql.split_whitespace().collect::<Vec<_>>().join(" ");
    let cut: String = flat.chars().take(MAX).collect();
    if cut.len() < flat.len() {
        format!("{cut}…")
    } else {
        cut
    }
}

async fn schema_entry(cx: Cx, entry: SchemaEntry) -> Result<()> {
    let path = Arc::new(Vec::new());
    let definition = CellState {
        db: entry.db.clone(),
        cell: entry.cell,
        columns: master_columns(),
        path: path.clone(),
    };
    cx.emit(
        Node::new("Definition")
            .span(entry.cell.span())
            .desc("This object's row in sqlite_master")
            .lazy(btree::expand_cell, definition),
    );
    if entry.root != 0 {
        cx.emit(
            Node::new(if entry.is_index { "Entries" } else { "Rows" })
                .desc("Records in key order, read page by page as they are requested")
                .lazy(rows, (entry.db.clone(), entry.root, entry.columns.clone())),
        );
        cx.emit(page_link(
            "Root page",
            &entry.db,
            entry.root,
            &path,
            Role::BTree,
        ));
    }
    Ok(())
}

async fn rows(cx: Cx, (db, root, columns): (DbRef, u32, Columns)) -> Result<()> {
    let mut walker = Walker::new(&cx, db.clone(), root).await?;
    let path = Arc::new(Vec::new());
    let mut index = 0u64;
    while let Some(cell) = walker.next(&cx).await? {
        let label = match (cell.kind, cell.rowid) {
            (Kind::TableLeaf, Some(rowid)) => format!("Row {rowid}"),
            _ => format!("Entry {index}"),
        };
        let local = walker.local(&cell).to_vec();
        let state = CellState {
            db: db.clone(),
            cell,
            columns: columns.clone(),
            path: path.clone(),
        };
        cx.push(btree::row_node(state, label, &local)).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Pages

/// What a page is known (or assumed) to be.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Role {
    /// Decided by looking at it: a B-tree page or anything else.
    Unknown,
    BTree,
    Overflow,
    FreelistTrunk,
    FreelistLeaf,
    PointerMap,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Unknown => "page",
            Role::BTree => "B-tree page",
            Role::Overflow => "overflow page",
            Role::FreelistTrunk => "freelist trunk page",
            Role::FreelistLeaf => "freelist leaf page",
            Role::PointerMap => "pointer map page",
        }
    }
}

#[derive(Clone)]
pub struct PageState {
    db: DbRef,
    no: u32,
    span: Span,
    role: Role,
    path: Arc<Vec<u32>>,
}

/// A node for page `no` that expands into it, unless that would revisit a
/// page on the current path (a cycle) or go too deep.
pub fn page_link(name: &'static str, db: &DbRef, no: u32, path: &[u32], role: Role) -> Node {
    let node = Node::new(name).value(Value::UInt {
        value: no.into(),
        bits: 32,
        radix: Radix::Dec,
    });
    if !db.linked {
        return node;
    }
    let span = match db.page(no) {
        Ok(span) => span,
        Err(e) => return node.diag(e),
    };
    let node = node.target(span);
    if path.contains(&no) {
        return node.diag(Diagnostic::malformed(format!(
            "page {no} refers back to itself through its children"
        )));
    }
    if path.len() >= btree::MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "pages linked deeper than {}",
            btree::MAX_DEPTH
        )));
    }
    let mut path = path.to_vec();
    path.push(no);
    node.lazy(
        crate::expander!(self::expand_page: PageState),
        PageState {
            db: db.clone(),
            no,
            span,
            role,
            path: Arc::new(path),
        },
    )
}

pub(crate) fn page_node(db: &DbRef, name: String, no: u32, span: Span, role: Role) -> Node {
    Node::new(name).span(span).lazy(
        crate::expander!(self::expand_page: PageState),
        PageState {
            db: db.clone(),
            no,
            span,
            role,
            path: Arc::new(vec![no]),
        },
    )
}

async fn expand_page(cx: Cx, page: PageState) -> Result<()> {
    match page.role {
        Role::Unknown | Role::BTree => btree_page(&cx, &page).await,
        Role::Overflow => {
            let head = cx.read(page.span.sub(0, 4)).await?;
            let next = u32_be(&head, 0).unwrap_or(0);
            let link = if next == 0 {
                Node::new("Next overflow page").value(Value::UInt {
                    value: 0,
                    bits: 32,
                    radix: Radix::Dec,
                })
            } else {
                page_link(
                    "Next overflow page",
                    &page.db,
                    next,
                    &page.path,
                    Role::Overflow,
                )
            };
            let link = link.span(page.span.sub(0, 4));
            cx.emit(if next == 0 {
                link.summary("end of chain")
            } else {
                link
            });
            cx.emit(Node::new("Content").span(page.span.sub(4, page.db.usable.saturating_sub(4))));
            Ok(())
        }
        Role::FreelistTrunk => freelist_trunk(&cx, &page).await,
        Role::FreelistLeaf => {
            cx.emit(Node::new("Unused").span(page.span));
            Ok(())
        }
        Role::PointerMap => pointer_map(&cx, &page).await,
    }
}

fn btree_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let kind = f.u8("Page type").enumeration(btree::PAGE_TYPES).emit()?;
    f.u16("First freeblock").hex().emit()?;
    f.u16("Number of cells").emit()?;
    f.u16("Cell content area")
        .hex()
        .desc("0 means 65536")
        .emit()?;
    f.u8("Fragmented free bytes").emit()?;
    if Kind::from_byte(kind).is_some_and(|k| !k.is_leaf()) {
        f.u32("Right-most pointer").emit()?;
    }
    Ok(())
}

async fn btree_page(cx: &Cx, state: &PageState) -> Result<()> {
    let db = &state.db;
    let page = match Page::load(cx, state.no, state.span).await {
        Ok(page) => page,
        Err(_) if state.role == Role::Unknown => {
            cx.emit(
                Node::new("Page data")
                    .span(state.span)
                    .summary("not a B-tree page: overflow, freelist or unused"),
            );
            return Ok(());
        }
        Err(e) => return Err(e),
    };
    if state.no == 1 {
        cx.emit(Header::node(
            "Database Header",
            state.span.sub(0, Header::SIZE),
            BE,
        ));
    }
    cx.emit(struct_node(
        "B-tree page header",
        page.header_span(),
        BE,
        (),
        btree_header,
    ));
    cx.emit(
        Node::new("Cell pointer array")
            .span(page.pointers_span())
            .summary(format!("{} cells", page.cells))
            .lazy(cell_pointers, (page.pointers_span(), page.span)),
    );
    cx.set_count(Count::AtLeast(u64::from(page.cells).saturating_add(2)));
    let columns = Columns(Arc::new(Vec::new()));
    for i in 0..page.cells {
        let cell = match page.cell(i, db.usable) {
            Ok(cell) => cell,
            Err(e) => {
                cx.push(Node::new(format!("Cell {i}")).diag(e)).await;
                continue;
            }
        };
        let local = btree::local_bytes(&page, &cell);
        let summary = match (cell.kind, cell.left, cell.rowid) {
            (Kind::TableInterior, Some(left), Some(key)) => {
                format!("child page {left}, rowids ≤ {key}")
            }
            (Kind::TableLeaf, _, Some(rowid)) => format!(
                "rowid {rowid}: {}",
                btree::record_summary(local, &[], Some(rowid), db.encoding)
            ),
            (_, Some(left), _) => format!(
                "child page {left}, {}",
                btree::record_summary(local, &[], None, db.encoding)
            ),
            _ => btree::record_summary(local, &[], None, db.encoding),
        };
        let state = CellState {
            db: db.clone(),
            cell,
            columns: columns.clone(),
            path: state.path.clone(),
        };
        cx.push(
            Node::new(format!("Cell {i}"))
                .span(cell.span())
                .summary(summary)
                .lazy(btree::expand_cell, state),
        )
        .await;
    }
    if let Some(right) = page.right {
        cx.push(page_link(
            "Right-most child page",
            db,
            right,
            &state.path,
            Role::BTree,
        ))
        .await;
    }
    Ok(())
}

async fn cell_pointers(cx: Cx, (span, page): (Span, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let mut i = 0u32;
    while cur.remaining() >= 2 {
        let at = cur.pos();
        let offset = cur.u16().await?;
        cx.push(
            Node::new(format!("Cell {i}"))
                .span(cur.since(at))
                .value(Value::UInt {
                    value: offset.into(),
                    bits: 16,
                    radix: Radix::Hex,
                })
                .target(page.sub(offset.into(), 1)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Freelist and pointer map

async fn freelist(cx: Cx, (db, first): (DbRef, u32)) -> Result<()> {
    let mut seen = BTreeSet::new();
    let mut next = first;
    while next != 0 {
        if !seen.insert(next) {
            cx.diag(Diagnostic::malformed(format!(
                "freelist trunk chain revisits page {next}"
            )));
            break;
        }
        let span = db.page(next)?;
        let head = cx.read(span.sub(0, 8)).await?;
        let leaves = u32_be(&head, 4).unwrap_or(0);
        cx.push(
            page_node(
                &db,
                format!("Trunk page {next}"),
                next,
                span,
                Role::FreelistTrunk,
            )
            .summary(format!("{leaves} leaf pages")),
        )
        .await;
        next = u32_be(&head, 0).unwrap_or(0);
    }
    Ok(())
}

async fn freelist_trunk(cx: &Cx, page: &PageState) -> Result<()> {
    let head = cx.read(page.span.sub(0, 8)).await?;
    let next = u32_be(&head, 0).unwrap_or(0);
    let count = u32_be(&head, 4).unwrap_or(0);
    let mut next_node = if next == 0 {
        Node::new("Next trunk page").value(Value::UInt {
            value: 0,
            bits: 32,
            radix: Radix::Dec,
        })
    } else {
        page_link(
            "Next trunk page",
            &page.db,
            next,
            &page.path,
            Role::FreelistTrunk,
        )
    };
    next_node = next_node.span(page.span.sub(0, 4));
    cx.emit(next_node);
    let max = page.db.usable.saturating_div(4).saturating_sub(2);
    let mut count_node = Node::new("Leaf page count")
        .span(page.span.sub(4, 4))
        .value(Value::UInt {
            value: count.into(),
            bits: 32,
            radix: Radix::Dec,
        });
    if u64::from(count) > max {
        count_node = count_node.diag(Diagnostic::malformed(format!(
            "a trunk page holds at most {max} leaves"
        )));
    }
    cx.emit(count_node);
    let list = page
        .span
        .sub(8, u64::from(count).min(max).saturating_mul(4));
    let data = cx.read(list).await?;
    for (i, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
        let no = u32::from_be_bytes(*chunk);
        let at = to_u64(i).saturating_mul(4);
        cx.push(
            page_link("Leaf page", &page.db, no, &page.path, Role::FreelistLeaf)
                .span(list.sub(at, 4)),
        )
        .await;
    }
    Ok(())
}

/// Pages that hold pointer maps: page 2, then every `usable / 5 + 1` pages.
fn pointer_map_pages(db: &Db) -> impl Iterator<Item = u32> + use<> {
    let stride = (db.usable / 5).saturating_add(1);
    let count = db.page_count;
    (0u64..)
        .map(move |i| i.saturating_mul(stride).saturating_add(2))
        .take_while(move |&p| p <= count)
        .filter_map(|p| u32::try_from(p).ok())
}

async fn pointer_maps(cx: Cx, db: DbRef) -> Result<()> {
    for no in pointer_map_pages(&db) {
        let span = db.page(no)?;
        cx.push(page_node(
            &db,
            format!("Pointer map page {no}"),
            no,
            span,
            Role::PointerMap,
        ))
        .await;
    }
    Ok(())
}

const PTRMAP_TYPES: EnumTable = &[
    (1, "root page"),
    (2, "free page"),
    (3, "first overflow page"),
    (4, "later overflow page"),
    (5, "non-root B-tree page"),
];

async fn pointer_map(cx: &Cx, page: &PageState) -> Result<()> {
    let entries = page.db.usable / 5;
    let data = cx.read(page.span.sub(0, entries.saturating_mul(5))).await?;
    for (i, entry) in data.as_chunks::<5>().0.iter().enumerate() {
        let described = u64::from(page.no)
            .saturating_add(1)
            .saturating_add(to_u64(i));
        if described > page.db.page_count {
            break;
        }
        let [kind, a, b, c, d] = *entry;
        let parent = u32::from_be_bytes([a, b, c, d]);
        let mut node = Node::new(format!("Page {described}"))
            .span(page.span.sub(to_u64(i).saturating_mul(5), 5))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 8,
                name: crate::value::lookup(PTRMAP_TYPES, kind.into()),
            });
        if parent != 0 {
            node = node.summary(format!("parent page {parent}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Every page by number, with its type. Freelist and pointer-map pages are
/// known from their lists; others are told apart by their first byte.
async fn pages(cx: Cx, (db, trunk, largest_root): (DbRef, u32, u32)) -> Result<()> {
    cx.set_count(Count::Exact(db.page_count));
    let mut trunks = BTreeSet::new();
    let mut leaves = BTreeSet::new();
    let mut next = trunk;
    while next != 0 && trunks.len().saturating_add(leaves.len()) < MAX_FREELIST {
        cx.checkpoint().await;
        if !trunks.insert(next) {
            break;
        }
        let Ok(span) = db.page(next) else {
            break;
        };
        let head = cx.read(span.sub(0, 8)).await?;
        let count = u64::from(u32_be(&head, 4).unwrap_or(0))
            .min(db.usable.saturating_div(4).saturating_sub(2));
        let list = cx.read(span.sub(8, count.saturating_mul(4))).await?;
        leaves.extend(
            list.as_chunks::<4>()
                .0
                .iter()
                .map(|c| u32::from_be_bytes(*c)),
        );
        next = u32_be(&head, 0).unwrap_or(0);
    }
    let ptrmaps: BTreeSet<u32> = if largest_root != 0 {
        pointer_map_pages(&db).take(MAX_FREELIST).collect()
    } else {
        BTreeSet::new()
    };
    for no in (1..=db.page_count).filter_map(|n| u32::try_from(n).ok()) {
        let span = db.page(no)?;
        let role = if trunks.contains(&no) {
            Role::FreelistTrunk
        } else if leaves.contains(&no) {
            Role::FreelistLeaf
        } else if ptrmaps.contains(&no) {
            Role::PointerMap
        } else {
            Role::Unknown
        };
        let summary = if role == Role::Unknown {
            let at = if no == 1 { 100 } else { 0 };
            let byte = cx.read_avail(span.sub(at, 1)).await?;
            match byte.first().copied().and_then(Kind::from_byte) {
                Some(kind) => format!("{} B-tree page", kind.name()),
                None => "overflow or unused page".to_owned(),
            }
        } else {
            role.name().to_owned()
        };
        cx.push(page_node(&db, format!("Page {no}"), no, span, role).summary(summary))
            .await;
    }
    Ok(())
}
