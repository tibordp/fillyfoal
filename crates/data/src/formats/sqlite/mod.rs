//! SQLite 3 databases, plus their write-ahead logs and rollback journals.
//!
//! Expanding the file reads the 100-byte header and the schema (the
//! `sqlite_schema` table, rooted on page 1). For databases up to
//! `ROOT_MAP_BYTES` it also walks every B-tree, overflow chain and the
//! freelist once to learn what each page is for and how many rows each
//! table holds (the page map, cached). Everything else is lazy:
//!
//! - **Schema**: tables, indexes, views and triggers, each with its
//!   definition, its columns (declared type and affinity, record order for
//!   WITHOUT ROWID tables and indexes), its rows or index entries in key
//!   order, and its root page;
//! - **Freelist**, **Pointer map** (auto-vacuum) and the lock-byte page;
//! - **Pages**: every page by number and use. A B-tree page shows its
//!   header, cell pointers, cells, freeblocks, fragments, unallocated and
//!   reserved space, so every byte of it is accounted for.
//!
//! B-tree traversal is iterative with a visited set (see `btree.rs`); page
//! links carry the path of pages above them, so cycles are reported rather
//! than followed. Payloads that spill onto overflow pages become piecewise
//! sources, so a large blob is dissected in place without copying.

mod btree;
mod record;
mod wal;

use std::collections::BTreeMap;
use std::sync::Arc;

use btree::{CellState, Columns, Db, DbRef, Kind, Page, Walker};
use record::{Column, Encoding, Table, Val};

pub use wal::{JOURNAL, WAL};

use crate::bytes::{to_u64, u32_be};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::{grouped_count, size};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const BE: Endian = Endian::Big;
const MAGIC: &[u8] = b"SQLite format 3\0";
/// Schema entries read.
const MAX_SCHEMA: usize = 10_000;
/// Databases up to this size are mapped when the file is expanded (for row
/// counts and page uses in the first summaries).
const ROOT_MAP_BYTES: u64 = 16 << 20;
/// Bytes of pages the page map reads at most.
const MAX_MAP_BYTES: u64 = 64 << 20;
/// Pages waiting on the page map's traversal stack.
const MAX_MAP_STACK: usize = 1 << 20;
/// Problems the page map reports.
const MAX_MAP_PROBLEMS: usize = 16;
/// The byte range SQLite locks (the lock-byte page holds it).
const PENDING_BYTE: u64 = 0x4000_0000;

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

/// Registered application IDs (SQLite's `magic.txt`).
const APPLICATION_IDS: EnumTable = &[
    (0, "none"),
    (0x0f05_5111, "Fossil repository"),
    (0x0f05_5112, "Fossil checkout"),
    (0x0f05_5113, "Fossil global configuration"),
    (0x4265_4462, "Bentley Systems BeSQLite database"),
    (0x4265_4c6e, "Bentley Systems localization file"),
    (0x4573_7269, "Esri spatially-enabled database"),
    (0x4750_3130, "GeoPackage 1.0"),
    (0x4750_3131, "GeoPackage 1.1"),
    (0x4750_4b47, "GeoPackage"),
    (0x4d50_4258, "MBTiles"),
];

const FORMAT_VERSIONS: EnumTable = &[(1, "legacy (rollback journal)"), (2, "WAL")];
const ENCODINGS: EnumTable = &[(1, "UTF-8"), (2, "UTF-16le"), (3, "UTF-16be")];
const SCHEMA_FORMATS: EnumTable = &[
    (1, "original"),
    (2, "rows may have fewer columns than the table (ADD COLUMN)"),
    (3, "added columns may have non-NULL defaults"),
    (4, "descending indexes, serial types 8 and 9"),
];

fn sqlite_version(v: u32) -> String {
    format!("{}.{}.{}", v / 1_000_000, v / 1000 % 1000, v % 1000)
}

fn vacuum_mode(largest_root: u32, incremental: u32) -> &'static str {
    match (largest_root, incremental) {
        (0, _) => "no auto-vacuum",
        (_, 0) => "full auto-vacuum",
        _ => "incremental vacuum",
    }
}

fn must_be(expected: u8) -> impl FnOnce(&u8) -> Option<Diagnostic> {
    move |&v: &u8| {
        (v != expected).then(|| Diagnostic::malformed(format!("must be {expected}, not {v}")))
    }
}

record! {
    /// The database header (first 100 bytes of page 1).
    pub struct Header {
        magic: ascii[16] "Header string",
        page_size: u16 "Page size"
            .with(|&v, n| if v == 1 { n.summary("65536 bytes") } else { n })
            .desc("Bytes per page: a power of two from 512 to 32768, or 1 for 65536"),
        write_version: u8 "File format write version" .enumeration(FORMAT_VERSIONS)
            .desc("1 for rollback-journal databases, 2 for WAL; a version the library does not know makes the database read-only"),
        read_version: u8 "File format read version" .enumeration(FORMAT_VERSIONS)
            .desc("A version the library does not know makes the database unreadable"),
        reserved: u8 "Reserved space per page"
            .desc("Bytes at the end of every page kept for extensions (encryption, checksums); the rest is the usable size"),
        max_fraction: u8 "Maximum embedded payload fraction" .check(must_be(64)) .desc("Must be 64"),
        min_fraction: u8 "Minimum embedded payload fraction" .check(must_be(32)) .desc("Must be 32"),
        leaf_fraction: u8 "Leaf payload fraction" .check(must_be(32)) .desc("Must be 32"),
        change_counter: u32 "File change counter"
            .desc("Incremented by every transaction that changes the file in rollback-journal mode"),
        page_count: u32 "Database size in pages"
            .desc("Trusted only when the version-valid-for number equals the change counter; otherwise the size comes from the file length"),
        freelist_trunk: u32 "First freelist trunk page" .desc("0 if no page is free"),
        freelist_count: u32 "Number of freelist pages" .desc("Trunk and leaf pages together"),
        schema_cookie: u32 "Schema cookie" .desc("Incremented whenever the schema changes, so connections reload it"),
        schema_format: u32 "Schema format number" .enumeration(SCHEMA_FORMATS)
            .desc("Highest record-format feature the schema may use"),
        cache_size: i32 "Default page cache size"
            .desc("Suggested cache size (PRAGMA default_cache_size); 0 for the library default"),
        largest_root: u32 "Largest root B-tree page"
            .with(|&v, n| if v == 0 { n.summary("no auto-vacuum") } else { n })
            .desc("Non-zero in auto-vacuum and incremental-vacuum databases, which keep pointer-map pages"),
        encoding: u32 "Text encoding" .enumeration(ENCODINGS),
        user_version: u32 "User version" .desc("Free for the application (PRAGMA user_version)"),
        incremental_vacuum: u32 "Incremental vacuum mode"
            .with(|&v, n| n.summary(vacuum_mode(largest_root, v)))
            .desc("Non-zero for incremental vacuum (free pages are released on request), zero for full auto-vacuum at each commit; meaningful only with auto-vacuum"),
        application_id: u32 "Application ID" .enumeration(APPLICATION_IDS)
            .desc("Identifies the application file format (PRAGMA application_id)"),
        _reserved: bytes[20] "Reserved for expansion" .desc("Must be zero"),
        version_valid_for: u32 "Version-valid-for number"
            .with(|&v, n| n.summary(if v == change_counter {
                "equals the change counter: the page count is current"
            } else {
                "differs from the change counter: the page count is stale"
            }))
            .desc("The change counter when the page count was last written"),
        sqlite_version: u32 "SQLite version number" .with(|&v, n| n.summary(sqlite_version(v)))
            .desc("The library that last wrote the file"),
    }
}

/// Real page size from the header field.
fn page_size(raw: u16) -> Option<u64> {
    let size = if raw == 1 { 65536 } else { u64::from(raw) };
    (size.is_power_of_two() && (512..=65536).contains(&size)).then_some(size)
}

/// The lock-byte page: the page holding the byte at 1 GiB, if the
/// database is that large. It is never used for data.
fn lock_byte_page(db: &Db) -> Option<u32> {
    let no = PENDING_BYTE.checked_div(db.page_size)?.saturating_add(1);
    (no <= db.page_count).then(|| u32::try_from(no).ok())?
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
        freelist_trunk: header.freelist_trunk,
        largest_root: header.largest_root,
    });

    let schema = schema(&cx, &db).await;
    let map = small_map(&cx, &db, &schema, ROOT_MAP_BYTES).await;
    cx.annotate(annotation(&header, &db, &schema, map.as_deref()));
    let mut node = Node::new("Schema")
        .span(db.page(1).unwrap_or(file))
        .summary(schema.describe())
        .desc("The sqlite_schema table (also called sqlite_master): tables, indexes, views and triggers, with their SQL")
        .lazy(schema_entries, db.clone());
    if let Some(e) = &schema.error {
        node = node.diag(e.clone());
    }
    cx.emit(node);

    if header.freelist_trunk != 0 {
        cx.emit(
            Node::new("Freelist")
                .summary(grouped_count(header.freelist_count, "page", "pages"))
                .desc("Pages no longer in use, kept for reuse: trunk pages list leaf pages")
                .lazy(freelist, (db.clone(), header.freelist_trunk)),
        );
    }
    if header.largest_root != 0 {
        let count = pointer_map_pages(&db).count();
        cx.emit(
            Node::new("Pointer map")
                .summary(format!(
                    "{}, {}",
                    grouped_count(to_u64(count), "page", "pages"),
                    vacuum_mode(header.largest_root, header.incremental_vacuum)
                ))
                .desc("Auto-vacuum back-pointers: the type and parent of every page, so pages can be moved")
                .lazy(pointer_maps, db.clone()),
        );
    }
    if let Some(no) = lock_byte_page(&db) {
        cx.emit(
            page_node(
                &db,
                format!("Lock-byte page {no}"),
                no,
                db.page(no)?,
                Role::LockByte,
            )
            .summary("never used: it holds the bytes SQLite locks at 1 GiB"),
        );
    }
    let mut pages_node = Node::new("Pages")
        .summary(format!(
            "{} of {}",
            grouped_count(db.page_count, "page", "pages"),
            size(page_size)
        ))
        .desc("Every page by number and what it is used for")
        .lazy(pages, db.clone());
    if let Some(map) = &map
        && !map.problems.is_empty()
    {
        pages_node = pages_node.diag(Diagnostic::warning(format!(
            "{} pages are used inconsistently",
            map.problems.len()
        )));
    }
    cx.emit(pages_node);
    let end = db.page_count.saturating_mul(page_size);
    if end < file.len {
        cx.emit(
            Node::new("Trailing data")
                .span(file.tail(end))
                .summary(format!(
                    "{} bytes after the last page",
                    file.len.saturating_sub(end)
                )),
        );
    }
    Ok(())
}

fn annotation(header: &Header, db: &Db, schema: &Schema, map: Option<&PageMap>) -> String {
    let mut parts = vec![
        format!("SQLite {}", sqlite_version(header.sqlite_version)),
        format!(
            "{} of {}",
            grouped_count(db.page_count, "page", "pages"),
            size(db.page_size)
        ),
    ];
    if header.application_id != 0
        && let Some(name) = crate::value::lookup(APPLICATION_IDS, header.application_id.into())
    {
        parts.push(name.to_owned());
    }
    parts.push(
        match db.encoding {
            Encoding::Utf8 => "UTF-8",
            Encoding::Utf16Le => "UTF-16le",
            Encoding::Utf16Be => "UTF-16be",
        }
        .to_owned(),
    );
    if header.write_version == 2 {
        parts.push("WAL mode".to_owned());
    }
    if header.largest_root != 0 {
        parts.push(vacuum_mode(header.largest_root, header.incremental_vacuum).to_owned());
    }
    parts.push(schema.describe());
    if let Some(rows) = map.and_then(|m| m.total_rows(schema)) {
        parts.push(grouped_count(rows, "row", "rows"));
    }
    parts.join(", ")
}

// ---------------------------------------------------------------------------
// Schema

const SCHEMA_SQL: &str =
    "CREATE TABLE sqlite_schema (type text, name text, tbl_name text, rootpage integer, sql text)";

fn schema_columns() -> Columns {
    Columns(Arc::new(record::table(SCHEMA_SQL).columns))
}

/// One row of `sqlite_schema`.
struct Entry {
    kind: String,
    name: String,
    tbl_name: String,
    root: u32,
    sql: String,
    cell: btree::Cell,
    /// How its records are labelled (tables and indexes).
    columns: Columns,
    /// Declared columns, for the column list (tables).
    declared: Vec<Column>,
    without_rowid: bool,
    /// What an object without SQL is (automatic indexes).
    note: Option<String>,
    error: Option<Diagnostic>,
}

#[derive(Default)]
struct Schema {
    entries: Vec<Entry>,
    more: bool,
    error: Option<Diagnostic>,
}

impl Schema {
    fn count(&self, kind: &str) -> u64 {
        to_u64(self.entries.iter().filter(|e| e.kind == kind).count())
    }

    fn describe(&self) -> String {
        let mut parts = vec![grouped_count(self.count("table"), "table", "tables")];
        for (kind, one, many) in [
            ("index", "index", "indexes"),
            ("view", "view", "views"),
            ("trigger", "trigger", "triggers"),
        ] {
            let n = self.count(kind);
            if n != 0 {
                parts.push(grouped_count(n, one, many));
            }
        }
        let mut out = parts.join(", ");
        if self.more {
            out.push_str(" (at least)");
        }
        out
    }

    /// The name of the B-tree `owner` (see [`PageUse::owner`]).
    fn owner_name(&self, owner: u32) -> &str {
        match owner.checked_sub(1) {
            None => "sqlite_schema",
            Some(i) => self
                .entries
                .get(crate::bytes::to_usize(i.into()))
                .map_or("?", |e| e.name.as_str()),
        }
    }

    fn owner_columns(&self, owner: u32) -> Columns {
        match owner.checked_sub(1) {
            None => schema_columns(),
            Some(i) => self
                .entries
                .get(crate::bytes::to_usize(i.into()))
                .map(|e| e.columns.clone())
                .unwrap_or_default(),
        }
    }
}

/// The schema, read once and shared by every expansion.
async fn schema(cx: &Cx, db: &DbRef) -> Arc<Schema> {
    let key = db.input.span;
    if let Some(s) = cx.cached::<Schema>(key, "sqlite-schema") {
        return s;
    }
    let s = Arc::new(load_schema(cx, db).await);
    cx.cache(key, "sqlite-schema", s.clone());
    s
}

async fn load_schema(cx: &Cx, db: &DbRef) -> Schema {
    let mut out = Schema::default();
    let mut walker = match Walker::new(cx, db.clone(), 1).await {
        Ok(w) => w,
        Err(e) => {
            out.error = Some(e);
            return out;
        }
    };
    loop {
        let cell = match walker.next(cx).await {
            Ok(Some(cell)) => cell,
            Ok(None) => break,
            Err(e) => {
                out.error = Some(e);
                break;
            }
        };
        if out.entries.len() >= MAX_SCHEMA {
            out.more = true;
            break;
        }
        let mut entry = Entry {
            kind: String::new(),
            name: String::new(),
            tbl_name: String::new(),
            root: 0,
            sql: String::new(),
            cell,
            columns: Columns::default(),
            declared: Vec::new(),
            without_rowid: false,
            note: None,
            error: None,
        };
        match read_record(cx, db, &cell).await {
            Ok(values) => {
                let text = |i: usize| match values.get(i) {
                    Some(Val::Text(s)) => s.clone(),
                    _ => String::new(),
                };
                entry.kind = text(0);
                entry.name = text(1);
                entry.tbl_name = text(2);
                entry.sql = text(4);
                entry.root = match values.get(3) {
                    Some(Val::Int(n)) => u32::try_from(*n).unwrap_or(0),
                    _ => 0,
                };
            }
            Err(e) => entry.error = Some(e),
        }
        out.entries.push(entry);
    }

    // Columns of each table and index, from the tables' definitions.
    let mut tables: BTreeMap<String, Table> = BTreeMap::new();
    for e in &out.entries {
        cx.checkpoint().await;
        if e.kind == "table" {
            tables.insert(e.name.to_ascii_lowercase(), record::table(&e.sql));
        }
    }
    let empty = Table::default();
    for e in &mut out.entries {
        cx.checkpoint().await;
        let table = tables
            .get(&e.tbl_name.to_ascii_lowercase())
            .unwrap_or(&empty);
        let columns = match e.kind.as_str() {
            "table" => {
                e.declared = table.columns.clone();
                e.without_rowid = table.without_rowid;
                let mut columns = table.record_columns();
                if e.name.eq_ignore_ascii_case("sqlite_stat4") {
                    for c in columns.iter_mut().filter(|c| c.name == "sample") {
                        c.record = true;
                    }
                }
                columns
            }
            "index" if !e.sql.is_empty() => table.index_columns(&record::indexed(&e.sql)),
            "index" => {
                let prefix = format!("sqlite_autoindex_{}_", e.tbl_name);
                let n = e
                    .name
                    .strip_prefix(&prefix)
                    .and_then(|n| n.parse::<usize>().ok());
                match n.and_then(|n| table.auto_indexes.get(n.checked_sub(1)?)) {
                    Some((kind, columns)) => {
                        e.note = Some(format!(
                            "automatic index for {kind} ({})",
                            columns.join(", ")
                        ));
                        table.index_columns(columns)
                    }
                    None => {
                        e.note = Some("automatic index".to_owned());
                        Vec::new()
                    }
                }
            }
            _ => Vec::new(),
        };
        e.columns = Columns(Arc::new(columns));
    }
    out
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

/// What SQLite's own tables hold.
fn internal_desc(name: &str) -> Option<&'static str> {
    Some(match name {
        "sqlite_sequence" => {
            "AUTOINCREMENT bookkeeping: the largest rowid ever used by each AUTOINCREMENT table"
        }
        "sqlite_stat1" => {
            "ANALYZE statistics: per index, the row count and the average rows per distinct key prefix"
        }
        "sqlite_stat2" => "ANALYZE samples of SQLite 3.6.18 to 3.7.8 (obsolete)",
        "sqlite_stat3" => "ANALYZE samples of the first index column (SQLITE_ENABLE_STAT3)",
        "sqlite_stat4" => {
            "ANALYZE samples (SQLITE_ENABLE_STAT4): sampled index entries, each a record, with key-prefix counts"
        }
        _ => return None,
    })
}

#[derive(Clone)]
struct EntryState {
    db: DbRef,
    schema: Arc<Schema>,
    index: usize,
}

async fn schema_entries(cx: Cx, db: DbRef) -> Result<()> {
    let schema = schema(&cx, &db).await;
    let map = small_map(&cx, &db, &schema, MAX_MAP_BYTES).await;
    if let Some(e) = &schema.error {
        cx.diag(e.clone());
    }
    cx.set_count(Count::Exact(to_u64(schema.entries.len())));
    for (index, e) in schema.entries.iter().enumerate() {
        if let Some(err) = &e.error {
            cx.push(
                Node::new("Unreadable schema row")
                    .span(e.cell.span())
                    .diag(err.clone()),
            )
            .await;
            continue;
        }
        let mut summary = if e.sql.is_empty() {
            e.note
                .clone()
                .unwrap_or_else(|| "(no SQL: internal object)".to_owned())
        } else {
            squash(&e.sql)
        };
        let owner = u32::try_from(index.saturating_add(1)).unwrap_or(u32::MAX);
        if let Some(n) = map.as_ref().and_then(|m| m.records(owner)) {
            let count = if e.kind == "index" {
                grouped_count(n, "entry", "entries")
            } else {
                grouped_count(n, "row", "rows")
            };
            summary = format!("{count}; {summary}");
        }
        let mut node = Node::new(format!("{} {}", e.kind, e.name))
            .span(e.cell.span())
            .summary(summary)
            .lazy(
                schema_entry,
                EntryState {
                    db: db.clone(),
                    schema: schema.clone(),
                    index,
                },
            );
        if let Some(desc) = internal_desc(&e.name) {
            node = node.desc(desc);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn schema_entry(cx: Cx, state: EntryState) -> Result<()> {
    let Some(e) = state.schema.entries.get(state.index) else {
        return Ok(());
    };
    let db = &state.db;
    let path = Arc::new(Vec::new());
    cx.emit(
        Node::new("Definition")
            .span(e.cell.span())
            .desc("This object's row in sqlite_schema")
            .lazy(
                btree::expand_cell,
                CellState {
                    db: db.clone(),
                    cell: e.cell,
                    columns: schema_columns(),
                    path: path.clone(),
                },
            ),
    );
    if !e.columns.0.is_empty() {
        let list = if e.kind == "table" && !e.without_rowid {
            e.declared.clone()
        } else {
            e.columns.0.to_vec()
        };
        let names: Vec<&str> = list.iter().map(|c| c.name.as_str()).collect();
        cx.emit(
            Node::new("Columns")
                .summary(squash(&names.join(", ")))
                .desc(match e.kind.as_str() {
                    "index" => "Each entry holds the indexed columns, then the rowid (or the rest of the primary key of a WITHOUT ROWID table)",
                    _ if e.without_rowid => "A WITHOUT ROWID table stores the primary key first, then the other columns",
                    _ => "Each row stores its columns in declaration order; an INTEGER PRIMARY KEY is stored as NULL (it is the rowid)",
                })
                .lazy(columns_list, Arc::new(list)),
        );
    }
    if e.root != 0 {
        let map = small_map(&cx, db, &state.schema, MAX_MAP_BYTES).await;
        let owner = u32::try_from(state.index.saturating_add(1)).unwrap_or(u32::MAX);
        let count = map.as_ref().and_then(|m| m.records(owner));
        let is_index = e.kind == "index";
        let mut rows_node = Node::new(if is_index { "Entries" } else { "Rows" })
            .desc("Records in key order, read page by page as they are requested")
            .lazy(
                rows,
                RowsState {
                    db: db.clone(),
                    root: e.root,
                    columns: e.columns.clone(),
                    count,
                    without_rowid: e.without_rowid,
                },
            );
        if let Some(n) = count {
            rows_node = rows_node.summary(if is_index {
                grouped_count(n, "entry", "entries")
            } else {
                grouped_count(n, "row", "rows")
            });
        }
        cx.emit(rows_node);
        if let Some(map) = &map {
            let (pages, overflow) = map.pages_of(owner);
            let mut summary = grouped_count(pages, "B-tree page", "B-tree pages");
            if overflow != 0 {
                summary = format!(
                    "{summary}, {}",
                    grouped_count(overflow, "overflow page", "overflow pages")
                );
            }
            let mut root = page_link("Root page", db, e.root, &path, Role::BTree, &e.columns);
            root = root.summary(summary);
            cx.emit(root);
        } else {
            cx.emit(page_link(
                "Root page",
                db,
                e.root,
                &path,
                Role::BTree,
                &e.columns,
            ));
        }
    }
    Ok(())
}

async fn columns_list(cx: Cx, columns: Arc<Vec<Column>>) -> Result<()> {
    for c in columns.iter() {
        let mut summary = match c.affinity {
            record::Affinity::Integer => "INTEGER affinity",
            record::Affinity::Text => "TEXT affinity",
            record::Affinity::Blob => "BLOB affinity (none)",
            record::Affinity::Real => "REAL affinity",
            record::Affinity::Numeric => "NUMERIC affinity",
        }
        .to_owned();
        if c.rowid_alias {
            summary.push_str(", alias for the rowid");
        }
        if c.record {
            summary.push_str(", holds a record");
        }
        cx.push(
            Node::new(c.name.clone())
                .value(Value::Text(c.decl.clone()))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

#[derive(Clone)]
struct RowsState {
    db: DbRef,
    root: u32,
    columns: Columns,
    count: Option<u64>,
    without_rowid: bool,
}

async fn rows(cx: Cx, state: RowsState) -> Result<()> {
    let db = state.db;
    let mut walker = Walker::new(&cx, db.clone(), state.root).await?;
    let path = Arc::new(Vec::new());
    let mut index = 0u64;
    while let Some(cell) = walker.next(&cx).await? {
        let label = match (cell.kind, cell.rowid) {
            (Kind::TableLeaf, Some(rowid)) => format!("Row {rowid}"),
            _ if state.without_rowid => format!("Row #{}", index.saturating_add(1)),
            _ => format!("Entry {index}"),
        };
        let local = walker.local(&cell).to_vec();
        let cell_state = CellState {
            db: db.clone(),
            cell,
            columns: state.columns.clone(),
            path: path.clone(),
        };
        match state.count {
            Some(n) => cx.progress(index, n),
            None => cx.progress(walker.progress(), 1_000_000),
        }
        cx.push(btree::row_node(cell_state, label, &local)).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The page map

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
    LockByte,
}

impl Role {
    fn name(self) -> &'static str {
        match self {
            Role::Unknown => "page",
            Role::BTree => "B-tree page",
            Role::Overflow => "overflow page",
            Role::FreelistTrunk => "freelist trunk page",
            Role::FreelistLeaf => "freelist leaf page",
            Role::PointerMap => "pointer-map page",
            Role::LockByte => "lock-byte page",
        }
    }
}

/// What one page is used for.
#[derive(Clone, Copy, Debug)]
struct PageUse {
    role: Role,
    kind: Option<Kind>,
    /// The B-tree it belongs to: 0 for sqlite_schema, `i + 1` for schema
    /// entry `i`.
    owner: u32,
    /// Overflow pages: position in the chain (from 1), and the page of the
    /// cell that owns it.
    seq: u32,
    from: u32,
}

impl PageUse {
    fn new(role: Role) -> PageUse {
        PageUse {
            role,
            kind: None,
            owner: u32::MAX,
            seq: 0,
            from: 0,
        }
    }

    fn describe(&self, schema: &Schema) -> String {
        match (self.role, self.kind) {
            (Role::BTree, Some(kind)) => format!(
                "{} B-tree page of {}",
                kind.name(),
                schema.owner_name(self.owner)
            ),
            (Role::BTree, None) => format!("a B-tree page of {}", schema.owner_name(self.owner)),
            (Role::Overflow, _) => format!(
                "overflow page {} of a cell on page {} ({})",
                self.seq,
                self.from,
                schema.owner_name(self.owner)
            ),
            (Role::FreelistLeaf, _) => "freelist leaf page (free)".to_owned(),
            (role, _) => role.name().to_owned(),
        }
    }
}

/// The use of every page reachable from the schema, the freelist and the
/// pointer maps, found by one walk over them all.
struct PageMap {
    uses: BTreeMap<u32, PageUse>,
    /// Records per B-tree (rows of a table, entries of an index), by owner;
    /// `None` where the walk did not get through the tree.
    records: Vec<Option<u64>>,
    /// Whether every structure was walked (the walk reads at most
    /// `MAX_MAP_BYTES`).
    complete: bool,
    problems: Vec<Diagnostic>,
}

impl PageMap {
    fn records(&self, owner: u32) -> Option<u64> {
        self.records
            .get(crate::bytes::to_usize(owner.into()))
            .copied()
            .flatten()
    }

    fn total_rows(&self, schema: &Schema) -> Option<u64> {
        let mut total = 0u64;
        for (i, e) in schema.entries.iter().enumerate() {
            if e.kind == "table" && e.root != 0 {
                let owner = u32::try_from(i.saturating_add(1)).ok()?;
                total = total.saturating_add(self.records(owner)?);
            }
        }
        Some(total)
    }

    /// B-tree pages and overflow pages of one tree.
    fn pages_of(&self, owner: u32) -> (u64, u64) {
        let mut out = (0u64, 0u64);
        for u in self.uses.values().filter(|u| u.owner == owner) {
            match u.role {
                Role::BTree => out.0 = out.0.saturating_add(1),
                Role::Overflow => out.1 = out.1.saturating_add(1),
                _ => {}
            }
        }
        out
    }

    /// Records the use of page `no`, unless another use has it already.
    fn claim(&mut self, schema: &Schema, no: u32, page_use: PageUse) -> bool {
        if let Some(old) = self.uses.get(&no) {
            if self.problems.len() < MAX_MAP_PROBLEMS {
                self.problems.push(Diagnostic::malformed(format!(
                    "page {no} is used twice: as {} and as {}",
                    old.describe(schema),
                    page_use.describe(schema)
                )));
            }
            return false;
        }
        self.uses.insert(no, page_use);
        true
    }
}

/// The page map if it is cached or the database is at most `limit` bytes.
async fn small_map(cx: &Cx, db: &DbRef, schema: &Schema, limit: u64) -> Option<Arc<PageMap>> {
    if let Some(m) = cx.cached::<PageMap>(db.input.span, "sqlite-page-map") {
        return Some(m);
    }
    if db.page_count.saturating_mul(db.page_size) > limit {
        return None;
    }
    Some(page_map(cx, db, schema).await)
}

async fn page_map(cx: &Cx, db: &DbRef, schema: &Schema) -> Arc<PageMap> {
    let key = db.input.span;
    if let Some(m) = cx.cached::<PageMap>(key, "sqlite-page-map") {
        return m;
    }
    let m = Arc::new(build_map(cx, db, schema).await);
    cx.cache(key, "sqlite-page-map", m.clone());
    m
}

async fn build_map(cx: &Cx, db: &DbRef, schema: &Schema) -> PageMap {
    let budget = MAX_MAP_BYTES.checked_div(db.page_size).unwrap_or(0).max(64);
    let mut visits = 0u64;
    let mut map = PageMap {
        uses: BTreeMap::new(),
        records: vec![None; schema.entries.len().saturating_add(1)],
        complete: true,
        problems: Vec::new(),
    };

    for (i, no) in pointer_map_pages(db).enumerate() {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        map.claim(schema, no, PageUse::new(Role::PointerMap));
    }
    if let Some(no) = lock_byte_page(db) {
        map.claim(schema, no, PageUse::new(Role::LockByte));
    }

    let mut next = db.freelist_trunk;
    let max_leaves = db.usable.saturating_div(4).saturating_sub(2);
    while next != 0 {
        cx.checkpoint().await;
        if visits >= budget {
            map.complete = false;
            break;
        }
        visits = visits.saturating_add(1);
        let Ok(span) = db.page(next) else {
            break;
        };
        let Ok(head) = cx.read(span.sub(0, 8)).await else {
            break;
        };
        if !map.claim(schema, next, PageUse::new(Role::FreelistTrunk)) {
            break;
        }
        let count = u64::from(u32_be(&head, 4).unwrap_or(0)).min(max_leaves);
        let Ok(list) = cx.read(span.sub(8, count.saturating_mul(4))).await else {
            break;
        };
        for leaf in list.as_chunks::<4>().0 {
            map.claim(
                schema,
                u32::from_be_bytes(*leaf),
                PageUse::new(Role::FreelistLeaf),
            );
        }
        next = u32_be(&head, 0).unwrap_or(0);
    }

    let per_page = db.usable.saturating_sub(4).max(1);
    let roots = schema
        .entries
        .iter()
        .enumerate()
        .filter(|(_, e)| e.root != 0)
        .filter_map(|(i, e)| Some((u32::try_from(i.saturating_add(1)).ok()?, e.root)));
    'trees: for (owner, root) in std::iter::once((0u32, 1u32)).chain(roots) {
        let mut records = 0u64;
        let mut finished = true;
        let mut stack = vec![root];
        while let Some(no) = stack.pop() {
            cx.checkpoint().await;
            if map.uses.contains_key(&no) {
                // Reported, not read again: a cycle or a page shared with
                // another structure.
                let shared = PageUse {
                    role: Role::BTree,
                    kind: None,
                    owner,
                    seq: 0,
                    from: 0,
                };
                map.claim(schema, no, shared);
                finished = false;
                continue;
            }
            if visits >= budget {
                map.complete = false;
                break 'trees;
            }
            visits = visits.saturating_add(1);
            let page = match db.page(no) {
                Ok(span) => Page::load(cx, no, span).await,
                Err(e) => Err(e),
            };
            let Ok(page) = page else {
                finished = false;
                continue;
            };
            let page_use = PageUse {
                role: Role::BTree,
                kind: Some(page.kind),
                owner,
                seq: 0,
                from: 0,
            };
            if !map.claim(schema, no, page_use) {
                finished = false;
                continue;
            }
            if page.kind != Kind::TableInterior {
                records = records.saturating_add(page.cells.into());
            }
            for i in 0..page.cells {
                let Ok(cell) = page.cell(i, db.usable) else {
                    continue;
                };
                if let Some(left) = cell.left {
                    if stack.len() >= MAX_MAP_STACK {
                        finished = false;
                    } else {
                        stack.push(left);
                    }
                }
                let Some((payload, first)) = cell.payload.and_then(|p| Some((p, p.overflow?)))
                else {
                    continue;
                };
                let mut remaining = payload.total.saturating_sub(payload.local_len);
                let mut next = first;
                let mut seq = 1u32;
                while remaining > 0 && next != 0 {
                    cx.checkpoint().await;
                    if visits >= budget {
                        map.complete = false;
                        break 'trees;
                    }
                    visits = visits.saturating_add(1);
                    let Ok(span) = db.page(next) else {
                        break;
                    };
                    let Ok(head) = cx.read(span.sub(0, 4)).await else {
                        break;
                    };
                    let overflow = PageUse {
                        role: Role::Overflow,
                        kind: None,
                        owner,
                        seq,
                        from: no,
                    };
                    if !map.claim(schema, next, overflow) {
                        break;
                    }
                    remaining = remaining.saturating_sub(per_page);
                    next = u32_be(&head, 0).unwrap_or(0);
                    seq = seq.saturating_add(1);
                }
            }
            if let Some(right) = page.right {
                if stack.len() >= MAX_MAP_STACK {
                    finished = false;
                } else {
                    stack.push(right);
                }
            }
        }
        if finished && let Some(slot) = map.records.get_mut(crate::bytes::to_usize(owner.into())) {
            *slot = Some(records);
        }
    }
    map
}

// ---------------------------------------------------------------------------
// Pages

#[derive(Clone)]
pub struct PageState {
    db: DbRef,
    no: u32,
    span: Span,
    role: Role,
    path: Arc<Vec<u32>>,
    /// How the records on this page are labelled, when its tree is known.
    columns: Columns,
}

/// A node for page `no` that expands into it, unless that would revisit a
/// page on the current path (a cycle) or go too deep.
pub fn page_link(
    name: &'static str,
    db: &DbRef,
    no: u32,
    path: &[u32],
    role: Role,
    columns: &Columns,
) -> Node {
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
            columns: columns.clone(),
        },
    )
}

pub(crate) fn page_node(db: &DbRef, name: String, no: u32, span: Span, role: Role) -> Node {
    page_node_with(db, name, no, span, role, Columns::default())
}

fn page_node_with(
    db: &DbRef,
    name: String,
    no: u32,
    span: Span,
    role: Role,
    columns: Columns,
) -> Node {
    Node::new(name).span(span).lazy(
        crate::expander!(self::expand_page: PageState),
        PageState {
            db: db.clone(),
            no,
            span,
            role,
            path: Arc::new(vec![no]),
            columns,
        },
    )
}

fn page_number(name: &'static str, no: u32, span: Span) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value: no.into(),
        bits: 32,
        radix: Radix::Dec,
    })
}

async fn expand_page(cx: Cx, page: PageState) -> Result<()> {
    match page.role {
        Role::Unknown | Role::BTree => btree_page(&cx, &page).await,
        Role::Overflow => overflow_page(&cx, &page).await,
        Role::FreelistTrunk => freelist_trunk(&cx, &page).await,
        Role::FreelistLeaf => freelist_leaf(&cx, &page).await,
        Role::PointerMap => pointer_map(&cx, &page).await,
        Role::LockByte => {
            cx.emit(
                Node::new("Unused")
                    .span(page.span)
                    .summary("the lock-byte page is never written"),
            );
            Ok(())
        }
    }
}

async fn overflow_page(cx: &Cx, page: &PageState) -> Result<()> {
    let head = cx.read(page.span.sub(0, 4)).await?;
    let next = u32_be(&head, 0).unwrap_or(0);
    let link = if next == 0 {
        page_number("Next overflow page", 0, page.span.sub(0, 4)).summary("end of chain")
    } else {
        page_link(
            "Next overflow page",
            &page.db,
            next,
            &page.path,
            Role::Overflow,
            &Columns::default(),
        )
        .span(page.span.sub(0, 4))
    };
    cx.emit(link.desc("Page number of the next page of the payload; 0 on the last page"));
    cx.emit(
        Node::new("Content")
            .span(page.span.sub(4, page.db.usable.saturating_sub(4)))
            .summary("payload bytes; the last page of a chain uses only what remains")
            .desc(
                "A continuation of a cell's payload: expand the row it belongs to for its values",
            ),
    );
    reserved_node(cx, page);
    Ok(())
}

/// The bytes reserved at the end of every page, if any.
fn reserved_node(cx: &Cx, page: &PageState) {
    let reserved = page.db.page_size.saturating_sub(page.db.usable);
    if reserved != 0 {
        cx.emit(
            Node::new("Reserved space")
                .span(page.span.sub(page.db.usable, reserved))
                .summary(format!("{reserved} bytes"))
                .desc("Reserved by the database header at the end of every page, for extensions such as encryption or checksums"),
        );
    }
}

fn btree_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let kind = f
        .u8("Page type")
        .enumeration(btree::PAGE_TYPES)
        .desc("Interior or leaf, of a table B-tree (keyed by rowid) or an index B-tree (keyed by record)")
        .emit()?;
    f.u16("First freeblock")
        .hex()
        .desc("Offset of the first block of free space in the content area; 0 if none")
        .emit()?;
    f.u16("Number of cells").emit()?;
    f.u16("Cell content area")
        .hex()
        .desc("Offset of the first byte of cell content; 0 means 65536")
        .emit()?;
    f.u8("Fragmented free bytes")
        .desc("Total of the free gaps of 1 to 3 bytes in the content area, too small to be freeblocks")
        .emit()?;
    if Kind::from_byte(kind).is_some_and(|k| !k.is_leaf()) {
        f.u32("Right-most pointer")
            .desc("Child page for keys greater than every cell's key")
            .emit()?;
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
            .summary(grouped_count(page.cells, "cell", "cells"))
            .desc("Offsets of the cells, in key order")
            .lazy(cell_pointers, (page.pointers_span(), page.span)),
    );
    cx.set_count(Count::AtLeast(u64::from(page.cells).saturating_add(2)));
    let columns = &state.columns;
    let mut spans = Vec::with_capacity(usize::from(page.cells));
    for i in 0..page.cells {
        let cell = match page.cell(i, db.usable) {
            Ok(cell) => cell,
            Err(e) => {
                cx.push(Node::new(format!("Cell {i}")).diag(e)).await;
                continue;
            }
        };
        spans.push((cell.offset, cell.len));
        let local = btree::local_bytes(&page, &cell);
        let summary = match (cell.kind, cell.left, cell.rowid) {
            (Kind::TableInterior, Some(left), Some(key)) => {
                format!("child page {left}, rowids ≤ {key}")
            }
            (Kind::TableLeaf, _, Some(rowid)) => format!(
                "rowid {rowid}: {}",
                btree::record_summary(local, &columns.0, Some(rowid), db.encoding)
            ),
            (_, Some(left), _) => format!(
                "child page {left}, {}",
                btree::record_summary(local, &columns.0, None, db.encoding)
            ),
            _ => btree::record_summary(local, &columns.0, None, db.encoding),
        };
        let cell_state = CellState {
            db: db.clone(),
            cell,
            columns: columns.clone(),
            path: state.path.clone(),
        };
        cx.push(
            Node::new(format!("Cell {i}"))
                .span(cell.span())
                .summary(summary)
                .lazy(btree::expand_cell, cell_state),
        )
        .await;
    }
    let free = page.free_space(db.usable, &spans);
    let at = |o: u64, n: u64| state.span.sub(o, n);
    if let Some((o, n)) = free.unallocated {
        cx.push(
            Node::new("Unallocated space")
                .span(at(o, n))
                .summary(format!("{n} bytes"))
                .desc("Between the cell pointer array and the cell content area; new cells grow into it from the end"),
        )
        .await;
    }
    for &(o, next, size) in &free.freeblocks {
        cx.push(
            Node::new("Freeblock")
                .span(at(o, size.into()))
                .summary(format!("{size} bytes at {o:#x}"))
                .desc("Free space in the content area left by deleted cells, linked from the page header")
                .lazy(freeblock, (at(o, size.into()), next, size)),
        )
        .await;
    }
    for &(o, n) in &free.gaps {
        let node = Node::new(if n < 4 {
            "Fragment"
        } else {
            "Unaccounted space"
        })
        .span(at(o, n))
        .summary(format!("{n} bytes"));
        cx.push(if n < 4 {
            node.desc("A gap of 1 to 3 bytes between cells, too small to be a freeblock (counted in the header)")
        } else {
            node.diag(Diagnostic::malformed(
                "free space of 4 bytes or more that is not on the freeblock list",
            ))
        })
        .await;
    }
    for problem in free.problems {
        cx.diag(problem);
    }
    let reserved = db.page_size.saturating_sub(db.usable);
    if reserved != 0 {
        cx.push(
            Node::new("Reserved space")
                .span(at(db.usable, reserved))
                .summary(format!("{reserved} bytes"))
                .desc("Reserved by the database header at the end of every page, for extensions such as encryption or checksums"),
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
            columns,
        ))
        .await;
    }
    Ok(())
}

async fn freeblock(cx: Cx, (span, next, size): (Span, u16, u16)) -> Result<()> {
    cx.emit(
        Node::new("Next freeblock")
            .span(span.sub(0, 2))
            .value(Value::UInt {
                value: next.into(),
                bits: 16,
                radix: Radix::Hex,
            })
            .summary(if next == 0 {
                "last"
            } else {
                "offset in the page"
            }),
    );
    cx.emit(
        Node::new("Size")
            .span(span.sub(2, 2))
            .value(Value::UInt {
                value: size.into(),
                bits: 16,
                radix: Radix::Dec,
            })
            .desc("Bytes in this freeblock, including this header"),
    );
    if size > 4 {
        cx.emit(
            Node::new("Free bytes")
                .span(span.tail(4))
                .summary("left over from deleted cells"),
        );
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
    let mut seen = std::collections::BTreeSet::new();
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
            .summary(grouped_count(leaves, "leaf page", "leaf pages")),
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
    let next_node = if next == 0 {
        page_number("Next trunk page", 0, page.span.sub(0, 4)).summary("last trunk page")
    } else {
        page_link(
            "Next trunk page",
            &page.db,
            next,
            &page.path,
            Role::FreelistTrunk,
            &Columns::default(),
        )
        .span(page.span.sub(0, 4))
    };
    cx.emit(next_node);
    let max = page.db.usable.saturating_div(4).saturating_sub(2);
    let mut count_node = page_number("Leaf page count", count, page.span.sub(4, 4))
        .desc("Free pages listed on this trunk page");
    if u64::from(count) > max {
        count_node = count_node.diag(Diagnostic::malformed(format!(
            "a trunk page holds at most {max} leaves"
        )));
    }
    cx.emit(count_node);
    let listed = u64::from(count).min(max).saturating_mul(4);
    let list = page.span.sub(8, listed);
    let data = cx.read(list).await?;
    for (i, chunk) in data.as_chunks::<4>().0.iter().enumerate() {
        let no = u32::from_be_bytes(*chunk);
        let at = to_u64(i).saturating_mul(4);
        cx.push(
            page_link(
                "Leaf page",
                &page.db,
                no,
                &page.path,
                Role::FreelistLeaf,
                &Columns::default(),
            )
            .span(list.sub(at, 4)),
        )
        .await;
    }
    let used = listed.saturating_add(8);
    if used < page.db.usable {
        cx.push(
            Node::new("Unused")
                .span(page.span.sub(used, page.db.usable.saturating_sub(used)))
                .summary("not part of the list; may hold stale data"),
        )
        .await;
    }
    reserved_node(cx, page);
    Ok(())
}

async fn freelist_leaf(cx: &Cx, page: &PageState) -> Result<()> {
    let head = cx.read_avail(page.span.sub(0, 1)).await?;
    let kind = head.first().copied().and_then(Kind::from_byte);
    let node = Node::new("Unused")
        .span(page.span)
        .desc("A free page: its content is whatever it held before it was freed");
    match kind {
        Some(kind) => {
            // Stale content: shown as the B-tree page it was, without
            // following its links (the pages they name have moved on).
            let stale: DbRef = Arc::new(Db {
                linked: false,
                ..*page.db
            });
            cx.emit(
                node.summary(format!("former {} B-tree page", kind.name()))
                    .lazy(
                        crate::expander!(self::expand_page: PageState),
                        PageState {
                            db: stale,
                            no: page.no,
                            span: page.span,
                            role: Role::Unknown,
                            path: page.path.clone(),
                            columns: Columns::default(),
                        },
                    ),
            );
        }
        None => cx.emit(node),
    }
    Ok(())
}

/// Pages that hold pointer maps: page 2, then every `usable / 5 + 1` pages.
fn pointer_map_pages(db: &Db) -> impl Iterator<Item = u32> + use<> {
    let stride = (db.usable / 5).saturating_add(1);
    let count = if db.largest_root == 0 {
        0
    } else {
        db.page_count
    };
    (0u64..)
        .map(move |i| i.saturating_mul(stride).saturating_add(2))
        .take_while(move |&p| p <= count)
        .filter_map(|p| u32::try_from(p).ok())
}

async fn pointer_maps(cx: Cx, db: DbRef) -> Result<()> {
    for no in pointer_map_pages(&db) {
        let span = db.page(no)?;
        let first = no.saturating_add(1);
        let last = u64::from(no)
            .saturating_add(db.usable / 5)
            .min(db.page_count);
        cx.push(
            page_node(
                &db,
                format!("Pointer map page {no}"),
                no,
                span,
                Role::PointerMap,
            )
            .summary(format!("pages {first} to {last}")),
        )
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
    let mut used = 0u64;
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
        node = match kind {
            1 | 2 if parent == 0 => node,
            3 | 5 => node.summary(format!("parent page {parent}")),
            4 => node.summary(format!("follows overflow page {parent}")),
            _ => node.summary(format!("parent page {parent}")),
        };
        if let Ok(target) = page.db.page(parent) {
            node = node.target(target);
        }
        cx.push(node).await;
        used = to_u64(i).saturating_add(1).saturating_mul(5);
    }
    if used < page.db.usable {
        cx.push(
            Node::new("Unused")
                .span(page.span.sub(used, page.db.usable.saturating_sub(used)))
                .summary("past the last page of the database"),
        )
        .await;
    }
    reserved_node(cx, page);
    Ok(())
}

/// Every page by number, with its use. With the page map, pages are known
/// by what refers to them; without it (a database too large to map, or
/// past where the walk stopped), by their first byte.
async fn pages(cx: Cx, db: DbRef) -> Result<()> {
    cx.set_count(Count::Exact(db.page_count));
    let schema = schema(&cx, &db).await;
    let map = page_map(&cx, &db, &schema).await;
    for problem in &map.problems {
        cx.diag(problem.clone());
    }
    if !map.complete {
        cx.diag(Diagnostic::limit(format!(
            "page uses are known for the first {} of the database; others are guessed from their first byte",
            size(MAX_MAP_BYTES)
        )));
    }
    let start = cx.resume::<u64>().unwrap_or(1);
    for n in start..=db.page_count {
        let Ok(no) = u32::try_from(n) else {
            break;
        };
        cx.mark(move || n);
        let span = db.page(no)?;
        let (role, summary, columns) = match map.uses.get(&no) {
            Some(u) => (
                u.role,
                u.describe(&schema),
                if u.role == Role::BTree {
                    schema.owner_columns(u.owner)
                } else {
                    Columns::default()
                },
            ),
            None if map.complete => (
                Role::Unknown,
                "unused: not reachable from the schema, the freelist or a pointer map".to_owned(),
                Columns::default(),
            ),
            None => {
                let at = if no == 1 { 100 } else { 0 };
                let byte = cx.read_avail(span.sub(at, 1)).await?;
                let summary = match byte.first().copied().and_then(Kind::from_byte) {
                    Some(kind) => format!("{} B-tree page", kind.name()),
                    None => "overflow or unused page".to_owned(),
                };
                (Role::Unknown, summary, Columns::default())
            }
        };
        cx.push(
            page_node_with(&db, format!("Page {no}"), no, span, role, columns).summary(summary),
        )
        .await;
    }
    Ok(())
}
