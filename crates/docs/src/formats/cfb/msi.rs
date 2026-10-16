//! Windows Installer databases: the string pool (`_StringPool` and
//! `_StringData`), the table catalog (`_Tables`, `_Columns`), and table
//! streams decoded row by row. Tables are stored column by column: all
//! values of the first column, then the second, and so on; strings are
//! references into the pool (2 bytes, or 3 when the pool says so) and
//! integers are stored with their sign bit flipped. A transform (.mst, or
//! a transform storage in a package or patch) stores its tables row by
//! row instead, each row a change with a mask of the columns it gives.
//! A standalone transform carries no schema for the tables it changes, so
//! the standard tables' schemas are assumed. Checked against a transform
//! `MsiTran.exe` generated and a patch WiX 6 built: every change decodes to
//! the difference between the two packages.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::rec::quoted;
use super::{CfbRef, TreeWalk, entry_name};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::plural;
use crate::formats::util::val::{hex, uint};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

/// Rows of a table decoded.
const MAX_ROWS: u64 = 1 << 20;

const COLUMN_TYPES: FlagTable = &[
    flag(0x0100, "MSITYPE_VALID"),
    flag(0x0200, "MSITYPE_LOCALIZABLE"),
    flag(0x0800, "MSITYPE_STRING"),
    flag(0x1000, "MSITYPE_NULLABLE"),
    flag(0x2000, "MSITYPE_KEY"),
    flag(0x4000, "MSITYPE_TEMPORARY"),
];

#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub kind: u16,
}

impl Column {
    /// A binary column (`MSITYPE_STRING | MSITYPE_VALID`, possibly
    /// nullable, nothing else): its data lives in a stream named after the
    /// table and the row's key, and the cell is a 2-byte value whatever the
    /// string reference width (Wine's `MSITYPE_IS_BINARY`).
    fn is_binary(&self) -> bool {
        self.kind & !0x1000 == 0x0900
    }

    fn is_string(&self) -> bool {
        self.kind & 0x0800 != 0 && !self.is_binary()
    }

    fn width(&self, long_refs: bool) -> u64 {
        if self.is_binary() {
            2
        } else if self.is_string() {
            if long_refs { 3 } else { 2 }
        } else if self.kind & 0x00ff == 4 {
            4
        } else {
            2
        }
    }

    fn describe(&self) -> String {
        let base = if self.is_binary() {
            "binary stream".to_owned()
        } else if self.is_string() {
            format!("string({})", self.kind & 0xff)
        } else if self.kind & 0xff == 4 {
            "int32".to_owned()
        } else {
            "int16".to_owned()
        };
        format!(
            "{base}{}{}",
            if self.kind & 0x2000 != 0 { ", key" } else { "" },
            if self.kind & 0x1000 != 0 {
                ", nullable"
            } else {
                ""
            }
        )
    }
}

/// The database model: the string pool and the column definitions.
#[derive(Default)]
pub struct Db {
    pub codepage: u32,
    pub long_refs: bool,
    pub strings: Vec<String>,
    pub tables: BTreeMap<String, Vec<Column>>,
}

impl Db {
    fn string(&self, i: u32) -> Option<&str> {
        self.strings.get(to_usize(i.into())).map(String::as_str)
    }
}

/// The MSI streams of `storage` (0: the root) by decoded name.
async fn msi_stream(cx: &Cx, cfb: &CfbRef, storage: u32, name: &str) -> Option<Span> {
    let root = super::read_entry(cx, cfb, storage).await.ok()?;
    let mut walk = TreeWalk::new(root.child);
    while let Some((id, entry)) = walk.next(cx, cfb).await {
        let raw = entry_name(&entry);
        if super::apps::msi_name(&raw)
            .as_deref()
            .and_then(|n| n.strip_prefix('!'))
            == Some(name)
        {
            return super::stream(cx, cfb, id, &entry)
                .await
                .ok()
                .map(|(s, _)| s);
        }
    }
    None
}

/// The root package's database.
pub async fn db(cx: &Cx, cfb: &CfbRef) -> Arc<Db> {
    package_db(cx, cfb, 0).await
}

/// The cache key of `storage`'s database: its string pool, which every
/// database has.
async fn db_key(cx: &Cx, cfb: &CfbRef, storage: u32) -> Span {
    msi_stream(cx, cfb, storage, "_StringPool")
        .await
        .unwrap_or_else(|| cfb.input.span.sub(0, 0))
}

/// A package's database in `storage` (0: the root).
async fn package_db(cx: &Cx, cfb: &CfbRef, storage: u32) -> Arc<Db> {
    let key = db_key(cx, cfb, storage).await;
    if let Some(found) = cx.cached::<Db>(key, "msi-db") {
        return found;
    }
    let db = Arc::new(load(cx, cfb, storage, None).await.unwrap_or_default());
    cx.cache(key, "msi-db", db.clone());
    db
}

/// The database of `storage` (0: the root), a package's, or with
/// `transform` a transform's: its own string pool, and a schema made of
/// the package's (for a transform stored in a package), the standard
/// Property table, and the tables and columns the transform adds.
pub async fn db_at(cx: &Cx, cfb: &CfbRef, storage: u32, transform: bool) -> Arc<Db> {
    if !transform {
        return package_db(cx, cfb, storage).await;
    }
    let key = db_key(cx, cfb, storage).await;
    if let Some(found) = cx.cached::<Db>(key, "msi-transform-db") {
        return found;
    }
    let mut base = BTreeMap::new();
    if storage != 0
        && let Ok(root) = super::read_entry(cx, cfb, 0).await
        && root.clsid.data1() == 0x000c_1084
    {
        base = package_db(cx, cfb, 0).await.tables.clone();
    }
    let db = Arc::new(load(cx, cfb, storage, Some(base)).await.unwrap_or_default());
    cx.cache(key, "msi-transform-db", db.clone());
    db
}

/// `transform`: the tables of the package a transform is stored in (empty
/// for a standalone one); `None` for a package.
async fn load(
    cx: &Cx,
    cfb: &CfbRef,
    storage: u32,
    transform: Option<BTreeMap<String, Vec<Column>>>,
) -> Option<Db> {
    let pool = msi_stream(cx, cfb, storage, "_StringPool").await?;
    let data = msi_stream(cx, cfb, storage, "_StringData").await?;
    let pool = cx.read(pool).await.ok()?;
    let data = cx.read(data).await.ok()?;
    let mut db = Db::default();
    let header = u32_le(&pool, 0)?;
    db.codepage = header & 0x7fff_ffff;
    db.long_refs = header & 0x8000_0000 != 0;
    let codepage = u16::try_from(db.codepage).unwrap_or(1252);
    db.strings.push(String::new());
    let mut offset = 0usize;
    for (len, _, _) in pool_entries(&pool) {
        if db.strings.len().is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let end = offset.saturating_add(len);
        let raw = data.get(offset..end).unwrap_or_default();
        db.strings.push(super::rec::codepage_text(codepage, raw));
        offset = end;
    }
    if let Some(base) = transform {
        db.tables = base;
        transform_schema(cx, cfb, storage, &mut db).await;
        return Some(db);
    }
    // _Columns: Table, Number, Name, Type, column by column.
    if let Some(cols) = msi_stream(cx, cfb, storage, "_Columns").await {
        let cols = cx.read(cols).await.ok()?;
        let r = if db.long_refs { 3usize } else { 2 };
        let row = r.saturating_mul(2).saturating_add(4);
        let n = cols.len().checked_div(row).unwrap_or(0);
        let mut defs: Vec<(String, u16, String, u16)> = Vec::new();
        for i in 0..n {
            if i.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            let table = string_ref(&cols, i.saturating_mul(r), r);
            let number = u16_le(
                &cols,
                n.saturating_mul(r).saturating_add(i.saturating_mul(2)),
            )? ^ 0x8000;
            let name = string_ref(
                &cols,
                n.saturating_mul(r.saturating_add(2))
                    .saturating_add(i.saturating_mul(r)),
                r,
            );
            let kind = u16_le(
                &cols,
                n.saturating_mul(r.saturating_mul(2).saturating_add(2))
                    .saturating_add(i.saturating_mul(2)),
            )? ^ 0x8000;
            defs.push((
                db.string(table).unwrap_or_default().to_owned(),
                number,
                db.string(name).unwrap_or_default().to_owned(),
                kind,
            ));
        }
        defs.sort_by(|a, b| a.0.cmp(&b.0).then(a.1.cmp(&b.1)));
        for (table, _, name, kind) in defs {
            db.tables
                .entry(table)
                .or_default()
                .push(Column { name, kind });
        }
    }
    catalog(&mut db);
    Some(db)
}

fn col(name: &str, kind: u16) -> Column {
    Column {
        name: name.to_owned(),
        kind,
    }
}

/// Standard tables' schemas, for transforms that change a table without
/// defining it (a standalone `.mst` carries no base schema). Taken from a
/// package WiX 6 built (`tests/fixtures/external/msi/fillyfoal-test-1.0.0.msi`),
/// whose `_Columns` follow the Windows Installer SDK schema.
const STANDARD_TABLES: &[(&str, &[(&str, u16)])] = &[
    (
        "AdminExecuteSequence",
        &[
            ("Action", 0x2d48),
            ("Condition", 0x1dff),
            ("Sequence", 0x1502),
        ],
    ),
    (
        "AdminUISequence",
        &[
            ("Action", 0x2d48),
            ("Condition", 0x1dff),
            ("Sequence", 0x1502),
        ],
    ),
    (
        "AdvtExecuteSequence",
        &[
            ("Action", 0x2d48),
            ("Condition", 0x1dff),
            ("Sequence", 0x1502),
        ],
    ),
    (
        "Component",
        &[
            ("Component", 0x2d48),
            ("ComponentId", 0x1d26),
            ("Directory_", 0x0d48),
            ("Attributes", 0x0502),
            ("Condition", 0x1dff),
            ("KeyPath", 0x1d48),
        ],
    ),
    (
        "Directory",
        &[
            ("Directory", 0x2d48),
            ("Directory_Parent", 0x1d48),
            ("DefaultDir", 0x0fff),
        ],
    ),
    (
        "Feature",
        &[
            ("Feature", 0x2d26),
            ("Feature_Parent", 0x1d26),
            ("Title", 0x1f40),
            ("Description", 0x1fff),
            ("Display", 0x1502),
            ("Level", 0x0502),
            ("Directory_", 0x1d48),
            ("Attributes", 0x0502),
        ],
    ),
    (
        "FeatureComponents",
        &[("Feature_", 0x2d26), ("Component_", 0x2d48)],
    ),
    (
        "File",
        &[
            ("File", 0x2d48),
            ("Component_", 0x0d48),
            ("FileName", 0x0fff),
            ("FileSize", 0x0104),
            ("Version", 0x1d48),
            ("Language", 0x1d14),
            ("Attributes", 0x1502),
            ("Sequence", 0x0104),
        ],
    ),
    (
        "InstallExecuteSequence",
        &[
            ("Action", 0x2d48),
            ("Condition", 0x1dff),
            ("Sequence", 0x1502),
        ],
    ),
    (
        "InstallUISequence",
        &[
            ("Action", 0x2d48),
            ("Condition", 0x1dff),
            ("Sequence", 0x1502),
        ],
    ),
    (
        "LaunchCondition",
        &[("Condition", 0x2dff), ("Description", 0x0fff)],
    ),
    (
        "Media",
        &[
            ("DiskId", 0x2502),
            ("LastSequence", 0x0104),
            ("DiskPrompt", 0x1f40),
            ("Cabinet", 0x1dff),
            ("VolumeLabel", 0x1d20),
            ("Source", 0x1d48),
        ],
    ),
    (
        "MsiFileHash",
        &[
            ("File_", 0x2d48),
            ("Options", 0x0502),
            ("HashPart1", 0x0104),
            ("HashPart2", 0x0104),
            ("HashPart3", 0x0104),
            ("HashPart4", 0x0104),
        ],
    ),
    ("Property", &[("Property", 0x2d48), ("Value", 0x0f00)]),
    (
        "Registry",
        &[
            ("Registry", 0x2d48),
            ("Root", 0x0502),
            ("Key", 0x0fff),
            ("Name", 0x1fff),
            ("Value", 0x1f00),
            ("Component_", 0x0d48),
        ],
    ),
    (
        "Upgrade",
        &[
            ("UpgradeCode", 0x2d26),
            ("VersionMin", 0x3d14),
            ("VersionMax", 0x3d14),
            ("Language", 0x3dff),
            ("Attributes", 0x2104),
            ("Remove", 0x1dff),
            ("ActionProperty", 0x0d48),
        ],
    ),
];

/// The catalog tables' own schemas.
fn catalog(db: &mut Db) {
    db.tables.insert(
        "_Columns".to_owned(),
        vec![
            col("Table", 0x2d40),
            col("Number", 0x2502),
            col("Name", 0x2d40),
            col("Type", 0x0502),
        ],
    );
    db.tables
        .insert("_Tables".to_owned(), vec![col("Name", 0x2d40)]);
}

/// A transform's schema, added to the package's tables (when it is stored
/// in a package): the standard tables, the catalog, and the columns the
/// transform's own `_Columns` inserts (in order; Wine's
/// `msi_table_load_transform` numbers columns whose Number is null after
/// the table's last one).
async fn transform_schema(cx: &Cx, cfb: &CfbRef, storage: u32, db: &mut Db) {
    for (name, columns) in STANDARD_TABLES {
        db.tables
            .entry((*name).to_owned())
            .or_insert_with(|| columns.iter().map(|&(c, kind)| col(c, kind)).collect());
    }
    catalog(db);
    let Some(span) = msi_stream(cx, cfb, storage, "_Columns").await else {
        return;
    };
    let Ok(data) = cx.read(span).await else {
        return;
    };
    let schema = db.tables.get("_Columns").cloned().unwrap_or_default();
    let mut at = 0usize;
    let mut rows = 0u32;
    while let Some(row) = transform_row(&data, at, &schema, db.long_refs) {
        rows = rows.saturating_add(1);
        if rows.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        at = at.saturating_add(row.size);
        if row.mask == 0 {
            continue;
        }
        let value = |i: usize| row.cells.iter().find(|c| c.0 == i).map(|c| (c.1, c.2));
        let text = |i: usize| {
            value(i)
                .map(|(off, w)| string_ref(&data, off, w))
                .and_then(|r| db.string(r))
                .map(str::to_owned)
        };
        let (Some(table), Some(name)) = (text(0), text(2)) else {
            continue;
        };
        let Some(kind) = value(3).and_then(|(off, _)| u16_le(&data, off)) else {
            continue;
        };
        let columns = db.tables.entry(table).or_default();
        if !columns.iter().any(|c| c.name == name) {
            columns.push(Column {
                name,
                kind: kind ^ 0x8000,
            });
        }
    }
}

/// One row of a transform's table stream, as Wine's
/// `msi_table_load_transform` reads it.
struct TransformRow {
    /// The column mask: 0 deletes the row with these keys; with bit 0 set,
    /// the high byte counts the leading columns given (a whole row,
    /// inserted or replaced); otherwise bit `i` marks column `i` as given
    /// (keys always are), changing an existing row or inserting one.
    mask: u16,
    /// Bytes of the row, mask included.
    size: usize,
    /// The given columns: index, offset of the value, width.
    cells: Vec<(usize, usize, usize)>,
}

/// The transform row at `at` in `data`, if a whole one is there and its
/// mask fits the schema.
fn transform_row(
    data: &[u8],
    at: usize,
    columns: &[Column],
    long_refs: bool,
) -> Option<TransformRow> {
    let mask = u16_le(data, at)?;
    let given = if mask & 1 != 0 {
        let n = usize::from(mask >> 8);
        if n > columns.len() {
            return None;
        }
        n
    } else {
        columns.len()
    };
    let mut cells = Vec::new();
    let mut off = at.checked_add(2)?;
    for (i, c) in columns.iter().enumerate().take(given) {
        let bit = u32::try_from(i)
            .ok()
            .and_then(|i| 1u16.checked_shl(i))
            .unwrap_or(0);
        if mask & 1 == 0 && c.kind & 0x2000 == 0 && mask & bit == 0 {
            continue;
        }
        let w = to_usize(c.width(long_refs));
        cells.push((i, off, w));
        off = off.checked_add(w)?;
    }
    if off > data.len() {
        return None;
    }
    Some(TransformRow {
        mask,
        size: off.saturating_sub(at),
        cells,
    })
}

/// (length, reference count, size of the entry in bytes) for each string.
fn pool_entries(pool: &[u8]) -> Vec<(usize, u16, usize)> {
    let mut out = Vec::new();
    let mut at = 4usize;
    while at.saturating_add(4) <= pool.len() {
        let len = u16_le(pool, at).unwrap_or(0);
        let refs = u16_le(pool, at.saturating_add(2)).unwrap_or(0);
        if len == 0 && refs != 0 {
            // A long string: its length is in the next entry.
            let lo = usize::from(u16_le(pool, at.saturating_add(4)).unwrap_or(0));
            let hi = usize::from(u16_le(pool, at.saturating_add(6)).unwrap_or(0));
            out.push((hi.saturating_mul(0x10000).saturating_add(lo), refs, 8));
            at = at.saturating_add(8);
        } else {
            out.push((usize::from(len), refs, 4));
            at = at.saturating_add(4);
        }
    }
    out
}

fn string_ref(data: &[u8], at: usize, width: usize) -> u32 {
    let lo = u32::from(u16_le(data, at).unwrap_or(0));
    if width == 3 {
        lo | (u32::from(data.get(at.saturating_add(2)).copied().unwrap_or(0)) << 16)
    } else {
        lo
    }
}

/// `_StringPool`: the header and the length and reference count of each
/// string, with the string itself.
pub async fn string_pool(
    cx: &Cx,
    cfb: &CfbRef,
    (storage, transform): (u32, bool),
    span: Span,
) -> Result<()> {
    let db = db_at(cx, cfb, storage, transform).await;
    let pool = cx.read(span).await?;
    let header = u32_le(&pool, 0).unwrap_or(0);
    cx.emit(
        Node::new("Header")
            .span(span.sub(0, 4))
            .value(hex(header, 32))
            .summary(format!(
                "code page {}{}",
                header & 0x7fff_ffff,
                if header & 0x8000_0000 != 0 {
                    ", 3-byte string references"
                } else {
                    ""
                }
            )),
    );
    let mut at = 4u64;
    let entries = pool_entries(&pool);
    cx.set_count(Count::Exact(to_u64(entries.len()).saturating_add(1)));
    for (i, (len, refs, size)) in entries.into_iter().enumerate() {
        let id = i.saturating_add(1);
        let text = db.strings.get(id).cloned().unwrap_or_default();
        cx.push(
            Node::new(format!("String {id}"))
                .span(span.sub(at, to_u64(size)))
                .value(Value::Text(text))
                .summary(format!(
                    "{len} bytes, {refs_reference}",
                    refs_reference = plural(refs, "reference")
                )),
        )
        .await;
        at = at.saturating_add(to_u64(size));
    }
    Ok(())
}

/// `_StringData`: the strings back to back, each pointing at its bytes.
pub async fn string_data(
    cx: &Cx,
    cfb: &CfbRef,
    (storage, transform): (u32, bool),
    span: Span,
) -> Result<()> {
    let db = db_at(cx, cfb, storage, transform).await;
    let Some(pool) = msi_stream(cx, cfb, storage, "_StringPool").await else {
        return Ok(());
    };
    let pool = cx.read(pool).await?;
    let mut at = 0u64;
    for (i, (len, _, _)) in pool_entries(&pool).into_iter().enumerate() {
        if len == 0 {
            continue;
        }
        let id = i.saturating_add(1);
        cx.push(
            Node::new(format!("String {id}"))
                .span(span.sub(at, to_u64(len)))
                .value(Value::Text(db.strings.get(id).cloned().unwrap_or_default())),
        )
        .await;
        at = at.saturating_add(to_u64(len));
    }
    Ok(())
}

/// A table stream (`!Name`), row by row.
pub async fn table(cx: &Cx, cfb: &CfbRef, name: &str, span: Span) -> Result<()> {
    let db = db(cx, cfb).await;
    let Some(columns) = db.tables.get(name) else {
        cx.emit(
            Node::new("Data")
                .span(span)
                .diag(Diagnostic::malformed(format!(
                    "no columns are defined for table {name}"
                ))),
        );
        return Ok(());
    };
    let widths: Vec<u64> = columns.iter().map(|c| c.width(db.long_refs)).collect();
    let row: u64 = widths.iter().sum();
    let rows = span.len.checked_div(row).unwrap_or(0).min(MAX_ROWS);
    cx.emit(
        Node::new("Columns")
            .summary(
                columns
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .lazy(column_list, (Arc::new(columns.clone()), db.long_refs)),
    );
    let data = cx.read(span.sub(0, rows.saturating_mul(row))).await?;
    let mut starts = Vec::new();
    let mut at = 0u64;
    for w in &widths {
        starts.push(at);
        at = at.saturating_add(w.saturating_mul(rows));
    }
    cx.set_count(Count::Exact(rows.saturating_add(1)));
    for r in 0..rows {
        if r.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let mut cells = Vec::new();
        let mut shown = Vec::new();
        for ((c, w), start) in columns.iter().zip(&widths).zip(&starts) {
            let at = start.saturating_add(r.saturating_mul(*w));
            let cell = span.sub(at, *w);
            let value = cell_value(&db, c, &data, to_usize(at), to_usize(*w));
            if shown.len() < 4 {
                shown.push(show(&value));
            }
            cells.push((c.name.clone(), cell, value));
        }
        cx.push(
            Node::new(format!("Row {r}"))
                .summary(shown.join(", "))
                .lazy(row_cells, Arc::new(cells)),
        )
        .await;
    }
    let used = rows.saturating_mul(row);
    if used < span.len {
        cx.emit(
            Node::new("Trailing data")
                .span(span.tail(used))
                .diag(Diagnostic::malformed(
                    "the stream is not a whole number of rows",
                )),
        );
    }
    Ok(())
}

/// A transform's table stream (`!Name` in a transform storage `storage`):
/// row changes, each a column mask and the values it gives, against the
/// transform's own string pool.
pub async fn transform_table(
    cx: &Cx,
    cfb: &CfbRef,
    storage: u32,
    name: &str,
    span: Span,
) -> Result<()> {
    let db = db_at(cx, cfb, storage, true).await;
    let Some(columns) = db.tables.get(name) else {
        cx.emit(
            Node::new("Data")
                .span(span)
                .summary(format!("{} bytes of row changes", span.len))
                .desc("The table's columns are defined by the package the transform applies to, which is not here"),
        );
        return Ok(());
    };
    cx.emit(
        Node::new("Columns")
            .summary(
                columns
                    .iter()
                    .map(|c| c.name.as_str())
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .lazy(column_list, (Arc::new(columns.clone()), db.long_refs)),
    );
    let data = cx.read(span).await?;
    let mut at = 0usize;
    let mut n = 0u64;
    while at < data.len() && n < MAX_ROWS {
        if n.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let Some(row) = transform_row(&data, at, columns, db.long_refs) else {
            break;
        };
        let mut cells = Vec::new();
        let mut shown = Vec::new();
        for &(i, off, w) in &row.cells {
            let Some(c) = columns.get(i) else { continue };
            let value = cell_value(&db, c, &data, off, w);
            if shown.len() < 4 {
                shown.push(show(&value));
            }
            cells.push((c.name.clone(), span.sub(to_u64(off), to_u64(w)), value));
        }
        let change = match row.mask {
            0 => "delete".to_owned(),
            m if m & 1 != 0 => format!("whole row ({})", plural(m >> 8, "column")),
            m => {
                let set: Vec<&str> = columns
                    .iter()
                    .enumerate()
                    .filter(|(i, c)| {
                        c.kind & 0x2000 == 0
                            && u32::try_from(*i)
                                .ok()
                                .and_then(|i| 1u16.checked_shl(i))
                                .is_some_and(|b| m & b != 0)
                    })
                    .map(|(_, c)| c.name.as_str())
                    .collect();
                format!("set {}", set.join(", "))
            }
        };
        let rspan = span.sub(to_u64(at), to_u64(row.size));
        let mask_span = rspan.sub(0, 2);
        cx.push(
            Node::new(format!("Change {n}"))
                .span(rspan)
                .summary(format!("{change}: {}", shown.join(", ")))
                .lazy(transform_cells, (mask_span, row.mask, Arc::new(cells))),
        )
        .await;
        at = at.saturating_add(row.size);
        n = n.saturating_add(1);
    }
    if at < data.len() {
        cx.emit(Node::new("Trailing data").span(span.tail(to_u64(at))).diag(
            Diagnostic::malformed("a row change does not fit the stream or the table's columns"),
        ));
    }
    Ok(())
}

/// A cell's value: a string from the pool or an integer (stored with its
/// sign bit flipped); `None` for null.
fn cell_value(db: &Db, c: &Column, data: &[u8], at: usize, width: usize) -> Option<Value> {
    if c.is_string() {
        let i = string_ref(data, at, width);
        (i != 0).then(|| Value::Text(db.string(i).unwrap_or("?").to_owned()))
    } else if width == 4 {
        let v = u32_le(data, at).unwrap_or(0);
        (v != 0).then(|| Value::Int {
            value: i64::from((v ^ 0x8000_0000).cast_signed()),
            bits: 32,
        })
    } else {
        let v = u16_le(data, at).unwrap_or(0);
        (v != 0).then(|| Value::Int {
            value: i64::from((v ^ 0x8000).cast_signed()),
            bits: 16,
        })
    }
}

fn show(value: &Option<Value>) -> String {
    match value {
        Some(Value::Text(t)) => quoted(t, 30),
        Some(Value::Int { value, .. }) => value.to_string(),
        _ => "null".to_owned(),
    }
}

async fn transform_cells(cx: Cx, (mask_span, mask, cells): (Span, u16, Cells)) -> Result<()> {
    cx.emit(Node::new("Mask").span(mask_span).value(hex(mask, 16)));
    row_cells(cx, cells).await
}

/// A row's cells: column name, span and value (`None`: null).
type Cells = Arc<Vec<(String, Span, Option<Value>)>>;

async fn row_cells(cx: Cx, cells: Cells) -> Result<()> {
    for (name, span, value) in cells.iter() {
        let mut node = Node::new(name.clone()).span(*span);
        node = match value {
            Some(v) => node.value(v.clone()),
            None => node.value(uint(0u8, 8)).summary("null"),
        };
        cx.emit(node);
    }
    Ok(())
}

async fn column_list(cx: Cx, (columns, long_refs): (Arc<Vec<Column>>, bool)) -> Result<()> {
    for (i, c) in columns.iter().enumerate() {
        cx.emit(
            Node::new(c.name.clone())
                .value(super::rec::flagsv(c.kind, 16, COLUMN_TYPES))
                .summary(format!(
                    "column {}: {}, {} bytes per value",
                    i.saturating_add(1),
                    c.describe(),
                    c.width(long_refs)
                )),
        );
    }
    Ok(())
}

/// Annotation for the file: the product from the Property table.
pub async fn product(cx: &Cx, cfb: &CfbRef) -> Option<String> {
    let db = db(cx, cfb).await;
    let columns = db.tables.get("Property")?;
    if columns.len() != 2 {
        return None;
    }
    let span = msi_stream(cx, cfb, 0, "Property").await?;
    let r = if db.long_refs { 3usize } else { 2 };
    let data = cx.read_avail(span.sub(0, 0x10000)).await.ok()?;
    let rows = data.len().checked_div(r.saturating_mul(2)).unwrap_or(0);
    let mut name = None;
    let mut version = None;
    for i in 0..rows {
        let k = db.string(string_ref(&data, i.saturating_mul(r), r))?;
        let v = db.string(string_ref(
            &data,
            rows.saturating_mul(r).saturating_add(i.saturating_mul(r)),
            r,
        ))?;
        match k {
            "ProductName" => name = Some(v.to_owned()),
            "ProductVersion" => version = Some(v.to_owned()),
            _ => {}
        }
    }
    Some(match (name, version) {
        (Some(n), Some(v)) => format!("{n} {v}"),
        (Some(n), None) => n,
        _ => return None,
    })
}

#[cfg(test)]
mod tests {
    use super::Column;

    fn column(kind: u16) -> Column {
        Column {
            name: String::new(),
            kind,
        }
    }

    #[test]
    fn binary_columns_are_two_bytes_with_long_string_refs() {
        // Binary.Data ("v0") and a nullable binary column.
        assert_eq!(column(0x0900).width(true), 2);
        assert_eq!(column(0x1900).width(true), 2);
        assert!(!column(0x0900).is_string());
        // Strings follow the pool's reference width; a key string is not
        // binary.
        assert_eq!(column(0x0d48).width(true), 3);
        assert_eq!(column(0x2900).width(true), 3);
        assert_eq!(column(0x0d48).width(false), 2);
        assert_eq!(column(0x0104).width(true), 4);
    }
}
