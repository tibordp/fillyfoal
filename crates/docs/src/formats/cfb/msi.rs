//! Windows Installer databases: the string pool (`_StringPool` and
//! `_StringData`), the table catalog (`_Tables`, `_Columns`), and table
//! streams decoded row by row. Tables are stored column by column: all
//! values of the first column, then the second, and so on; strings are
//! references into the pool (2 bytes, or 3 when the pool says so) and
//! integers are stored with their sign bit flipped.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::rec::{hex, quoted, uint};
use super::{CfbRef, TreeWalk, entry_name};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
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
    fn is_string(&self) -> bool {
        self.kind & 0x0800 != 0
    }

    fn width(&self, long_refs: bool) -> u64 {
        if self.is_string() {
            if long_refs { 3 } else { 2 }
        } else if self.kind & 0x00ff == 4 {
            4
        } else {
            2
        }
    }

    fn describe(&self) -> String {
        let base = if self.is_string() {
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

/// The root's MSI streams by decoded name.
async fn msi_stream(cx: &Cx, cfb: &CfbRef, name: &str) -> Option<Span> {
    let root = super::read_entry(cx, cfb, 0).await.ok()?;
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

pub async fn db(cx: &Cx, cfb: &CfbRef) -> Arc<Db> {
    let key = cfb.input.span.sub(0, 0);
    if let Some(found) = cx.cached::<Db>(key, "msi-db") {
        return found;
    }
    let db = Arc::new(load(cx, cfb).await.unwrap_or_default());
    cx.cache(key, "msi-db", db.clone());
    db
}

async fn load(cx: &Cx, cfb: &CfbRef) -> Option<Db> {
    let pool = msi_stream(cx, cfb, "_StringPool").await?;
    let data = msi_stream(cx, cfb, "_StringData").await?;
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
    // _Columns: Table, Number, Name, Type, column by column.
    if let Some(cols) = msi_stream(cx, cfb, "_Columns").await {
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
    // The catalog tables' own schemas.
    let s = |name: &str, kind| Column {
        name: name.to_owned(),
        kind,
    };
    db.tables.insert(
        "_Columns".to_owned(),
        vec![
            s("Table", 0x2d40),
            s("Number", 0x2502),
            s("Name", 0x2d40),
            s("Type", 0x0502),
        ],
    );
    db.tables
        .insert("_Tables".to_owned(), vec![s("Name", 0x2d40)]);
    Some(db)
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
pub async fn string_pool(cx: &Cx, cfb: &CfbRef, span: Span) -> Result<()> {
    let db = db(cx, cfb).await;
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
                .summary(format!("{len} bytes, {refs} references")),
        )
        .await;
        at = at.saturating_add(to_u64(size));
    }
    Ok(())
}

/// `_StringData`: the strings back to back, each pointing at its bytes.
pub async fn string_data(cx: &Cx, cfb: &CfbRef, span: Span) -> Result<()> {
    let db = db(cx, cfb).await;
    let Some(pool) = msi_stream(cx, cfb, "_StringPool").await else {
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
            let a = to_usize(at);
            let value = if c.is_string() {
                let i = string_ref(&data, a, to_usize(*w));
                if i == 0 {
                    None
                } else {
                    Some(Value::Text(db.string(i).unwrap_or("?").to_owned()))
                }
            } else if *w == 4 {
                let v = u32_le(&data, a).unwrap_or(0);
                (v != 0).then(|| Value::Int {
                    value: i64::from((v ^ 0x8000_0000).cast_signed()),
                    bits: 32,
                })
            } else {
                let v = u16_le(&data, a).unwrap_or(0);
                (v != 0).then(|| Value::Int {
                    value: i64::from((v ^ 0x8000).cast_signed()),
                    bits: 16,
                })
            };
            if shown.len() < 4 {
                shown.push(match &value {
                    Some(Value::Text(t)) => quoted(t, 30),
                    Some(Value::Int { value, .. }) => value.to_string(),
                    _ => "null".to_owned(),
                });
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

async fn row_cells(cx: Cx, cells: Arc<Vec<(String, Span, Option<Value>)>>) -> Result<()> {
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
    let span = msi_stream(cx, cfb, "Property").await?;
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
