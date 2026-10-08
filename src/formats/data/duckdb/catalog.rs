//! The catalog written at a checkpoint (schemas, tables, views, sequences,
//! types, macros, indexes) and the table data it points to (statistics,
//! row groups, column segments).
//!
//! Layouts from memory of DuckDB's `CheckpointWriter`, `TableDataWriter`
//! and generated serializers, checked against DuckDB 1.5.6 output. Objects
//! whose grammar is not known here (a view's parsed query, subqueries and
//! window functions in defaults, table macros) stop the entry; the walk
//! then resumes at the next entry, found by its fixed opening bytes.

use std::sync::Arc;

use super::serial::{
    Bs, END, Info, Phys, Stream, Ty, close, enumv, expression, group, leaf, logical_type, pair,
    phys, scalar, summarize, text, uint, value,
};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::text::plural;
use crate::formats::util::binutil::Tree;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub const CATALOG_TYPES: EnumTable = &[
    (1, "table"),
    (2, "schema"),
    (3, "view"),
    (4, "index"),
    (6, "sequence"),
    (7, "collation"),
    (8, "type"),
    (30, "macro"),
    (31, "table macro"),
];

const COMPRESSION: EnumTable = &[
    (0, "auto"),
    (1, "uncompressed"),
    (2, "constant"),
    (3, "RLE"),
    (4, "dictionary"),
    (5, "PFOR delta"),
    (6, "bitpacking"),
    (7, "FSST"),
    (8, "Chimp"),
    (9, "Patas"),
    (10, "ALP"),
    (11, "ALPRD"),
    (12, "ZSTD"),
    (13, "roaring"),
    (14, "empty"),
    (15, "dictionary + FSST"),
];

const CONSTRAINTS: EnumTable = &[
    (1, "NOT NULL"),
    (2, "CHECK"),
    (3, "UNIQUE"),
    (4, "FOREIGN KEY"),
];

const ON_CONFLICT: EnumTable = &[(0, "error"), (1, "ignore"), (2, "replace"), (3, "alter")];

/// A `MetaBlockPointer`'s pieces: the encoded block/sub-block word and the
/// byte offset within that sub-block.
#[derive(Clone, Copy, Debug, Default)]
pub struct MetaPtr {
    pub word: u64,
    pub offset: u64,
}

impl MetaPtr {
    pub fn describe(&self) -> String {
        format!(
            "block {}, sub-block {}, offset {}",
            self.word & super::BLOCK_MASK,
            self.word >> 56,
            self.offset
        )
    }
}

/// Makes the lazy node for table data or for one column's data.
pub trait Links: Sync {
    fn table_data(&self, ptr: MetaPtr, columns: Arc<Vec<(String, Ty)>>) -> Node;
    fn column_data(&self, ptr: MetaPtr, name: String, ty: Ty) -> Node;
    /// The bytes a data block's `offset` points at.
    fn block_target(&self, block: i64, offset: u64) -> Option<Span>;
}

fn meta_ptr(bs: &mut Bs<'_>) -> Result<MetaPtr> {
    let mut p = MetaPtr::default();
    bs.object("a metadata pointer", |bs, id, _| {
        match id {
            100 => p.word = bs.uvar()?,
            101 => p.offset = bs.uvar()?,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(p)
}

fn block_ptr(bs: &mut Bs<'_>) -> Result<(i64, u64)> {
    let (mut block, mut offset) = (0i64, 0u64);
    bs.object("a block pointer", |bs, id, _| {
        match id {
            100 => block = bs.svar()?,
            101 => offset = bs.uvar()?,
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok((block, offset))
}

/// The start of the next catalog entry after `from`: the end marker of the
/// previous entry, field 99 (catalog type `t`), field 100 present, and the
/// create info's own type field repeating `t`.
fn resync(data: &[u8], from: usize) -> Option<usize> {
    let mut i = from;
    while let Some(w) = data.get(i..i.checked_add(11)?) {
        if let [0xff, 0xff, 99, 0, t, 100, 0, 1, 100, 0, u] = *w
            && t == u
            && lookup(CATALOG_TYPES, t.into()).is_some()
        {
            return i.checked_add(2);
        }
        i = i.checked_add(1)?;
    }
    None
}

#[derive(Clone, Copy, Default)]
pub struct Counts {
    pub tables: u64,
    pub views: u64,
    pub other: u64,
}

/// Parses the whole catalog stream into `t`, adding the entry nodes to
/// `roots`, an entry per step.
pub async fn catalog(
    cx: &Cx,
    s: &mut Stream,
    t: &mut Tree,
    links: &dyn Links,
    roots: &mut Vec<usize>,
    counts: &mut Counts,
) -> Result<()> {
    let n = s
        .piece(cx, t, |bs, _| {
            let at = bs.pos();
            let id = bs.id()?;
            if id != 100 {
                return Err(bs.unknown(id, at, "the catalog"));
            }
            bs.count()
        })
        .await?;
    for i in 0..n {
        let (r0, c0) = (roots.len(), *counts);
        let last = s
            .piece(cx, t, |bs, t| {
                roots.truncate(r0);
                *counts = c0;
                catalog_entry(bs, t, links, roots, counts, i, n)
            })
            .await?;
        if last {
            return Ok(());
        }
    }
    s.piece(cx, t, |bs, _| {
        let at = bs.pos();
        let id = bs.id()?;
        if id != END {
            return Err(bs.unknown(id, at, "the catalog"));
        }
        Ok(())
    })
    .await
}

/// Entry `i` of `n`: whether it ended the catalog (the next entry could
/// not be located after a failure).
fn catalog_entry(
    bs: &mut Bs<'_>,
    t: &mut Tree,
    links: &dyn Links,
    roots: &mut Vec<usize>,
    counts: &mut Counts,
    i: u64,
    n: u64,
) -> Result<bool> {
    let start = bs.pos();
    let node = group(t, None, "Entry");
    roots.push(node);
    let (kind, r) = entry(bs, t, node, links);
    match kind {
        1 => counts.tables = counts.tables.saturating_add(1),
        3 => counts.views = counts.views.saturating_add(1),
        _ => counts.other = counts.other.saturating_add(1),
    }
    let Err(e) = r else {
        close(t, node, bs, start);
        return Ok(false);
    };
    if bs.short {
        return Err(e);
    }
    t.update(node, |n| n.diag(e));
    if let Some(next) = resync(bs.data(), start.saturating_add(1)) {
        bs.seek(next);
        close(t, node, bs, start);
        return Ok(false);
    }
    if bs.can_grow {
        // The next entry may be beyond the bytes read so far.
        bs.short = true;
        return Err(Diagnostic::truncated(bs.span(start), 0));
    }
    // Not found: this was the last entry (or the rest is lost). The
    // catalog ends with the entry's and the catalog's end markers.
    let data = bs.data();
    let end = (start..data.len().saturating_sub(1))
        .rev()
        .find(|&k| data.get(k..k.saturating_add(2)) == Some(&[0xff, 0xff][..]))
        .unwrap_or(data.len());
    bs.seek(end.max(start));
    close(t, node, bs, start);
    if i.saturating_add(1) < n {
        t.update(node, |n| {
            n.diag(Diagnostic::unsupported(
                "the rest of the catalog could not be located",
            ))
        });
    }
    Ok(true)
}

/// One entry: its catalog type, and how the parse went.
fn entry(bs: &mut Bs<'_>, t: &mut Tree, node: usize, links: &dyn Links) -> (u64, Result<()>) {
    let mut kind = 0u64;
    let mut info = Created::default();
    let mut table_ptr = None;
    let mut rows = None;
    let result = bs.object("a catalog entry", |bs, id, at| {
        match id {
            99 => {
                kind = bs.uvar()?;
                leaf(t, node, bs, at, "Catalog type", enumv(CATALOG_TYPES, kind));
                let label = lookup(CATALOG_TYPES, kind).unwrap_or("entry");
                let mut cap = label.to_owned();
                if let Some(first) = cap.get_mut(..1) {
                    first.make_ascii_uppercase();
                }
                t.update(node, |n| Node {
                    name: cap.into(),
                    ..n
                });
            }
            100 => {
                if bs.present()? {
                    let g = group(t, Some(node), "Definition");
                    let r = create_info(bs, t, g, &mut info);
                    close(t, g, bs, at);
                    r?;
                }
            }
            101 if kind == 1 => {
                let p = meta_ptr(bs)?;
                let i = leaf(t, node, bs, at, "Table data pointer", text(p.describe()));
                t.update(i, |n| {
                    n.desc("Where the table's statistics and row groups start (metadata)")
                });
                table_ptr = Some(p);
            }
            101 if kind == 4 => {
                let (b, o) = block_ptr(bs)?;
                leaf(
                    t,
                    node,
                    bs,
                    at,
                    "Root block pointer",
                    text(format!("block {b}, offset {o}")),
                );
            }
            102 if kind == 1 => {
                let r = bs.uvar()?;
                leaf(t, node, bs, at, "Total rows", uint(r));
                rows = Some(r);
            }
            103 if kind == 1 => {
                let g = group(t, Some(node), "Index pointers");
                let n = bs.list(|bs, _| {
                    let at = bs.pos();
                    let (b, o) = block_ptr(bs)?;
                    leaf(
                        t,
                        g,
                        bs,
                        at,
                        "Index",
                        text(format!("block {b}, offset {o}")),
                    );
                    Ok(())
                })?;
                close(t, g, bs, at);
                summarize(t, g, plural(n, "pointer", "pointers"));
            }
            104 if kind == 1 => {
                let g = group(t, Some(node), "Index storage");
                let n = bs.list(|bs, _| index_storage(bs, t, g))?;
                close(t, g, bs, at);
                summarize(t, g, plural(n, "index", "indexes"));
            }
            _ => return Ok(false),
        }
        Ok(true)
    });
    // Name and summarise even when the entry stopped part-way.
    let qualified = match (info.schema.as_str(), kind) {
        (s, 2) => s.to_owned(),
        ("", _) => info.name.clone(),
        (s, _) => format!("{s}.{}", info.name),
    };
    let label = lookup(CATALOG_TYPES, kind).unwrap_or("entry");
    let mut name = label.to_owned();
    if let Some(first) = name.get_mut(..1) {
        first.make_ascii_uppercase();
    }
    let name = format!("{name} {qualified}");
    let mut summary = info.summary.clone();
    if let Some(r) = rows {
        if !summary.is_empty() {
            summary.push_str(", ");
        }
        summary.push_str(&plural(r, "row", "rows"));
    }
    t.update(node, |n| Node {
        name: name.into(),
        ..n
    });
    summarize(t, node, summary);
    if result.is_ok()
        && let Some(p) = table_ptr
    {
        t.add(
            Some(node),
            links.table_data(p, Arc::new(info.columns.clone())),
        );
    }
    (kind, result)
}

#[derive(Default)]
struct Created {
    kind: u64,
    schema: String,
    name: String,
    summary: String,
    columns: Vec<(String, Ty)>,
}

/// The `CreateInfo` behind an entry: common fields, then the kind's own.
fn create_info(bs: &mut Bs<'_>, t: &mut Tree, g: usize, c: &mut Created) -> Result<()> {
    let mut types = 0u64;
    let mut seq = (1i64, 1i64);
    let mut macro_params = Vec::new();
    let mut macro_body = String::new();
    let mut index_cols: Vec<String> = Vec::new();
    let r = bs.object("a catalog definition", |bs, id, at| {
        match (id, c.kind) {
            (100, _) => {
                c.kind = bs.uvar()?;
                leaf(t, g, bs, at, "Type", enumv(CATALOG_TYPES, c.kind));
            }
            (101, _) => drop(leaf_str(bs, t, g, at, "Catalog")?),
            (102, _) => c.schema = leaf_str(bs, t, g, at, "Schema")?,
            (103, _) => {
                let v = bs.bool()?;
                leaf(t, g, bs, at, "Temporary", Value::Bool(v));
            }
            (104, _) => {
                let v = bs.bool()?;
                leaf(t, g, bs, at, "Internal", Value::Bool(v));
            }
            (105, _) => {
                let v = bs.uvar()?;
                leaf(t, g, bs, at, "On conflict", enumv(ON_CONFLICT, v));
            }
            (106, _) => {
                let sql = leaf_str(bs, t, g, at, "SQL")?;
                if c.kind == 3 || c.kind == 4 {
                    c.summary = sql;
                }
            }
            (107, _) => {
                let v = value(bs, 0)?;
                leaf(t, g, bs, at, "Comment", text(v));
            }
            (108, _) => {
                let m = group(t, Some(g), "Tags");
                bs.list(|bs, _| {
                    let at = bs.pos();
                    let (mut k, mut v) = (String::new(), String::new());
                    pair(
                        bs,
                        |bs| {
                            k = bs.string()?;
                            Ok(())
                        },
                        |bs| {
                            v = bs.string()?;
                            Ok(())
                        },
                    )?;
                    let i = leaf(t, m, bs, at, "Tag", text(v));
                    t.update(i, |n| Node {
                        name: k.into(),
                        ..n
                    });
                    Ok(())
                })?;
                close(t, m, bs, at);
            }
            (109, _) => {
                let m = group(t, Some(g), "Dependencies");
                bs.object("a dependency list", |bs, id, _| {
                    if id != 100 {
                        return Ok(false);
                    }
                    bs.list(|bs, _| dependency(bs, t, m))?;
                    Ok(true)
                })?;
                close(t, m, bs, at);
            }
            // table
            (200, 1) => c.name = leaf_str(bs, t, g, at, "Name")?,
            (201, 1) => {
                let m = group(t, Some(g), "Columns");
                let mut all = 0u64;
                bs.object("a column list", |bs, id, _| {
                    if id != 100 {
                        return Ok(false);
                    }
                    bs.list(|bs, i| {
                        let (name, ty, stored) = column(bs, t, m, i)?;
                        all = all.saturating_add(1);
                        // Table data has the stored columns only.
                        if stored {
                            c.columns.push((name, ty));
                        }
                        Ok(())
                    })?;
                    Ok(true)
                })?;
                close(t, m, bs, at);
                let n = all;
                summarize(t, m, plural(n, "column", "columns"));
                c.summary = plural(n, "column", "columns");
            }
            (202, 1) => {
                let m = group(t, Some(g), "Constraints");
                let n = bs.list(|bs, _| {
                    if bs.present()? {
                        constraint(bs, t, m, &c.columns)?;
                    }
                    Ok(())
                })?;
                close(t, m, bs, at);
                summarize(t, m, plural(n, "constraint", "constraints"));
            }
            // view
            (200, 3) => c.name = leaf_str(bs, t, g, at, "Name")?,
            (201, 3) | (205, 3) => {
                let m = group(t, Some(g), if id == 201 { "Aliases" } else { "Names" });
                bs.list(|bs, _| {
                    let at = bs.pos();
                    leaf_str(bs, t, m, at, "Name").map(drop)
                })?;
                close(t, m, bs, at);
            }
            (202, 3) => {
                let m = group(t, Some(g), "Column types");
                types = bs.list(|bs, _| {
                    let at = bs.pos();
                    let ty = logical_type(bs, 0)?;
                    leaf(t, m, bs, at, "Type", text(ty.sql()));
                    Ok(())
                })?;
                close(t, m, bs, at);
            }
            (203, 3) => {
                return Err(Diagnostic::note(
                    "the view's parsed query is not decoded (its SQL text is shown)",
                )
                .at(bs.span(at)));
            }
            // sequence
            (200, 6) => c.name = leaf_str(bs, t, g, at, "Name")?,
            (201, 6) => {
                let v = bs.uvar()?;
                leaf(t, g, bs, at, "Usage count", uint(v));
            }
            (202..=205, 6) => {
                let v = bs.svar()?;
                let name = match id {
                    202 => "Increment",
                    203 => "Minimum",
                    204 => "Maximum",
                    _ => "Start (next value)",
                };
                leaf(t, g, bs, at, name, Value::Int { value: v, bits: 64 });
                match id {
                    202 => seq.0 = v,
                    205 => seq.1 = v,
                    _ => {}
                }
            }
            (206, 6) => {
                let v = bs.bool()?;
                leaf(t, g, bs, at, "Cycle", Value::Bool(v));
            }
            // type
            (200, 8) => c.name = leaf_str(bs, t, g, at, "Name")?,
            (201, 8) => {
                let ty = logical_type(bs, 0)?;
                let mut shown = ty.clone();
                shown.alias = None;
                c.summary = shown.sql();
                leaf(t, g, bs, at, "Definition", text(shown.sql()));
            }
            // macros
            (200, 30 | 31) => c.name = leaf_str(bs, t, g, at, "Name")?,
            (201 | 202, 30 | 31) => {
                let mut one = |bs: &mut Bs<'_>| -> Result<()> {
                    if bs.present()? {
                        let (p, b) = macro_function(bs)?;
                        macro_params = p;
                        macro_body = b;
                    }
                    Ok(())
                };
                if id == 201 {
                    one(bs)?;
                } else {
                    bs.list(|bs, _| one(bs))?;
                }
                leaf(
                    t,
                    g,
                    bs,
                    at,
                    "Function",
                    text(format!("({}) AS {macro_body}", macro_params.join(", "))),
                );
                c.summary = format!("{}({}) AS {macro_body}", c.name, macro_params.join(", "));
            }
            // index
            (200, 4) => c.name = leaf_str(bs, t, g, at, "Name")?,
            (201, 4) => drop(leaf_str(bs, t, g, at, "Table")?),
            (202, 4) => {
                let v = bs.uvar()?;
                leaf(t, g, bs, at, "Index type", uint(v));
            }
            (203, 4) => {
                let v = bs.uvar()?;
                leaf(
                    t,
                    g,
                    bs,
                    at,
                    "Constraint type",
                    enumv(
                        &[
                            (0, "none"),
                            (1, "unique"),
                            (2, "primary key"),
                            (3, "foreign key"),
                        ],
                        v,
                    ),
                );
            }
            (204, 4) => {
                let m = group(t, Some(g), "Expressions");
                bs.list(|bs, _| {
                    let at = bs.pos();
                    if bs.present()? {
                        let e = expression(bs, 0)?;
                        leaf(t, m, bs, at, "Expression", text(e.clone()));
                        index_cols.push(e);
                    }
                    Ok(())
                })?;
                close(t, m, bs, at);
            }
            (205, 4) => {
                let m = group(t, Some(g), "Scan types");
                bs.list(|bs, _| {
                    let at = bs.pos();
                    let ty = logical_type(bs, 0)?;
                    leaf(t, m, bs, at, "Type", text(ty.sql()));
                    Ok(())
                })?;
                close(t, m, bs, at);
            }
            (206, 4) => {
                let m = group(t, Some(g), "Column names");
                bs.list(|bs, _| {
                    let at = bs.pos();
                    leaf_str(bs, t, m, at, "Name").map(drop)
                })?;
                close(t, m, bs, at);
            }
            (207, 4) => {
                let m = group(t, Some(g), "Column ids");
                bs.list(|bs, _| {
                    let at = bs.pos();
                    let v = bs.uvar()?;
                    leaf(t, m, bs, at, "Column", uint(v));
                    Ok(())
                })?;
                close(t, m, bs, at);
            }
            (208, 4) => {
                let m = group(t, Some(g), "Options");
                options(bs, t, m)?;
                close(t, m, bs, at);
            }
            (209, 4) => drop(leaf_str(bs, t, g, at, "Index type name")?),
            _ => return Ok(false),
        }
        Ok(true)
    });
    if c.kind == 4 && c.summary.is_empty() && !index_cols.is_empty() {
        c.summary = format!("on ({})", index_cols.join(", "));
    }
    if c.kind == 6 {
        c.summary = format!("next {}, increment {}", seq.1, seq.0);
    }
    if c.kind == 3 && types > 0 && c.summary.is_empty() {
        c.summary = plural(types, "column", "columns");
    }
    r
}

fn leaf_str(
    bs: &mut Bs<'_>,
    t: &mut Tree,
    p: usize,
    at: usize,
    name: &'static str,
) -> Result<String> {
    let s = bs.string()?;
    leaf(t, p, bs, at, name, text(s.clone()));
    Ok(s)
}

fn dependency(bs: &mut Bs<'_>, t: &mut Tree, p: usize) -> Result<()> {
    let at = bs.pos();
    let (mut kind, mut schema, mut name) = (0, String::new(), String::new());
    bs.object("a dependency", |bs, id, _| {
        match id {
            100 => bs.object("a dependency's entry", |bs, id, _| {
                match id {
                    100 => kind = bs.uvar()?,
                    101 => schema = bs.string()?,
                    102 => name = bs.string()?,
                    _ => return Ok(false),
                }
                Ok(true)
            })?,
            101 => drop(bs.string()?),
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    let i = leaf(t, p, bs, at, "Dependency", text(format!("{schema}.{name}")));
    t.update(i, |n| {
        n.summary(lookup(CATALOG_TYPES, kind).unwrap_or("entry"))
    });
    Ok(())
}

fn options(bs: &mut Bs<'_>, t: &mut Tree, m: usize) -> Result<()> {
    bs.list(|bs, _| {
        let at = bs.pos();
        let (mut k, mut v) = (String::new(), String::new());
        pair(
            bs,
            |bs| {
                k = bs.string()?;
                Ok(())
            },
            |bs| {
                v = value(bs, 0)?;
                Ok(())
            },
        )?;
        let i = leaf(t, m, bs, at, "Option", text(v));
        t.update(i, |n| Node {
            name: k.into(),
            ..n
        });
        Ok(())
    })
    .map(drop)
}

/// A column definition; returns its name, type and whether it is stored
/// (generated columns are not).
fn column(bs: &mut Bs<'_>, t: &mut Tree, m: usize, i: u64) -> Result<(String, Ty, bool)> {
    let start = bs.pos();
    let node = group(t, Some(m), format!("Column {i}"));
    let mut name = String::new();
    let mut ty = Ty::default();
    let mut default = None;
    let mut generated = false;
    bs.object("a column definition", |bs, id, at| {
        match id {
            100 => name = leaf_str(bs, t, node, at, "Name")?,
            101 => {
                ty = logical_type(bs, 0)?;
                leaf(t, node, bs, at, "Type", text(ty.sql()));
            }
            102 => {
                if bs.present()? {
                    let e = expression(bs, 0)?;
                    leaf(t, node, bs, at, "Expression", text(e.clone()));
                    default = Some(e);
                }
            }
            103 => {
                let v = bs.uvar()?;
                leaf(
                    t,
                    node,
                    bs,
                    at,
                    "Category",
                    enumv(&[(0, "standard"), (1, "generated")], v),
                );
                generated = v == 1;
            }
            104 => {
                let v = bs.uvar()?;
                leaf(t, node, bs, at, "Compression", enumv(COMPRESSION, v));
            }
            105 => {
                let v = value(bs, 0)?;
                leaf(t, node, bs, at, "Comment", text(v));
            }
            106 => {
                bs.list(|bs, _| pair(bs, |bs| bs.string().map(drop), |bs| bs.string().map(drop)))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    close(t, node, bs, start);
    let notes = match (default, generated) {
        (Some(e), true) => vec![format!("GENERATED ALWAYS AS ({e})")],
        (None, true) => vec!["generated".to_owned()],
        (Some(e), false) => vec![format!("DEFAULT {e}")],
        (None, false) => Vec::new(),
    };
    let sql = ty.sql();
    t.update(node, |n| Node {
        name: name.clone().into(),
        value: Some(text(sql)),
        ..n
    });
    summarize(t, node, notes.join(", "));
    Ok((name, ty, !generated))
}

fn column_name(columns: &[(String, Ty)], i: u64) -> String {
    usize::try_from(i)
        .ok()
        .and_then(|i| columns.get(i))
        .map_or_else(|| format!("column {i}"), |(n, _)| n.clone())
}

fn constraint(bs: &mut Bs<'_>, t: &mut Tree, m: usize, columns: &[(String, Ty)]) -> Result<()> {
    let start = bs.pos();
    let node = group(t, Some(m), "Constraint");
    let mut kind = 0;
    let mut pk = false;
    let mut index = None;
    let mut cols: Vec<String> = Vec::new();
    let mut other: Vec<String> = Vec::new();
    let mut check = String::new();
    let mut target = String::new();
    let mut side = 1;
    bs.object("a constraint", |bs, id, at| {
        match (id, kind) {
            (100, _) => {
                kind = bs.uvar()?;
                leaf(t, node, bs, at, "Type", enumv(CONSTRAINTS, kind));
            }
            (200, 1) | (201, 3) => {
                let v = bs.uvar()?;
                leaf(t, node, bs, at, "Column index", uint(v));
                index = Some(v);
            }
            (200, 2) => {
                if bs.present()? {
                    check = expression(bs, 0)?;
                    leaf(t, node, bs, at, "Expression", text(check.clone()));
                }
            }
            (200, 3) => {
                pk = bs.bool()?;
                leaf(t, node, bs, at, "Primary key", Value::Bool(pk));
            }
            (202, 3) | (200, 4) | (201, 4) => {
                let mut names = Vec::new();
                bs.list(|bs, _| {
                    names.push(bs.string()?);
                    Ok(())
                })?;
                let label = match (id, kind) {
                    (200, 4) => "Referenced columns",
                    _ => "Columns",
                };
                leaf(t, node, bs, at, label, text(names.join(", ")));
                if (id, kind) == (200, 4) {
                    other = names;
                } else {
                    cols = names;
                }
            }
            (202, 4) => {
                let v = bs.uvar()?;
                side = v;
                leaf(
                    t,
                    node,
                    bs,
                    at,
                    "Side",
                    enumv(
                        &[
                            (0, "primary key table"),
                            (1, "foreign key table"),
                            (2, "self reference"),
                        ],
                        v,
                    ),
                );
            }
            (203, 4) => {
                let s = bs.string()?;
                leaf(t, node, bs, at, "Schema", text(s.clone()));
                target = format!("{s}.");
            }
            (204, 4) => {
                let s = bs.string()?;
                leaf(t, node, bs, at, "Table", text(s.clone()));
                target.push_str(&s);
            }
            (205 | 206, 4) => {
                bs.list(|bs, _| bs.uvar().map(drop))?;
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    close(t, node, bs, start);
    let col = || index.map(|i| column_name(columns, i)).unwrap_or_default();
    let shown = match kind {
        1 => format!("NOT NULL ({})", col()),
        2 => format!("CHECK ({check})"),
        3 => {
            let what = if pk { "PRIMARY KEY" } else { "UNIQUE" };
            if cols.is_empty() {
                format!("{what} ({})", col())
            } else {
                format!("{what} ({})", cols.join(", "))
            }
        }
        // The referenced table keeps a copy naming its referrer.
        4 if side == 0 => format!(
            "({}) REFERENCED BY {target} ({})",
            other.join(", "),
            cols.join(", ")
        ),
        4 => format!(
            "FOREIGN KEY ({}) REFERENCES {target} ({})",
            cols.join(", "),
            other.join(", ")
        ),
        _ => String::new(),
    };
    t.update(node, |n| n.value(text(shown)));
    Ok(())
}

/// A scalar macro's parameters and body. Table macros (a query node) are
/// not decoded.
fn macro_function(bs: &mut Bs<'_>) -> Result<(Vec<String>, String)> {
    let mut kind = 0;
    let mut params = Vec::new();
    let mut body = String::new();
    bs.object("a macro function", |bs, id, at| {
        match (id, kind) {
            (100, _) => kind = bs.uvar()?,
            (101, _) => {
                bs.list(|bs, _| {
                    if bs.present()? {
                        params.push(expression(bs, 0)?);
                    }
                    Ok(())
                })?;
            }
            (102, _) => {
                bs.list(|bs, _| {
                    pair(
                        bs,
                        |bs| bs.string().map(drop),
                        |bs| {
                            if bs.present()? {
                                expression(bs, 0)?;
                            }
                            Ok(())
                        },
                    )
                })?;
            }
            (103, _) => {
                bs.list(|bs, _| logical_type(bs, 0).map(drop))?;
            }
            (200, 2) | (200, 0) => {
                if bs.present()? {
                    body = expression(bs, 0)?;
                }
            }
            (200, _) => {
                return Err(Diagnostic::unsupported("table macro query").at(bs.span(at)));
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok((params, body))
}

fn index_storage(bs: &mut Bs<'_>, t: &mut Tree, p: usize) -> Result<()> {
    let start = bs.pos();
    let node = group(t, Some(p), "Index");
    let mut allocators = 0;
    bs.object("index storage info", |bs, id, at| {
        match id {
            100 => {
                let s = leaf_str(bs, t, node, at, "Name")?;
                t.update(node, |n| Node {
                    name: s.into(),
                    ..n
                });
            }
            101 => {
                let v = bs.uvar()?;
                let i = leaf(
                    t,
                    node,
                    bs,
                    at,
                    "Root",
                    text(format!(
                        "block {}, sub-block {}",
                        v & super::BLOCK_MASK,
                        v >> 56
                    )),
                );
                t.update(i, |n| n.desc("The ART root node pointer"));
            }
            102 => {
                let m = group(t, Some(node), "Allocators");
                allocators = bs.list(|bs, _| allocator(bs, t, m))?;
                close(t, m, bs, at);
            }
            103 => {
                let m = group(t, Some(node), "Options");
                options(bs, t, m)?;
                close(t, m, bs, at);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    close(t, node, bs, start);
    summarize(t, node, plural(allocators, "allocator", "allocators"));
    Ok(())
}

fn allocator(bs: &mut Bs<'_>, t: &mut Tree, p: usize) -> Result<()> {
    let start = bs.pos();
    let node = group(t, Some(p), "Allocator");
    let mut size = 0;
    let mut buffers = 0;
    bs.object("a fixed-size allocator", |bs, id, at| {
        match id {
            100 => {
                size = bs.uvar()?;
                leaf(t, node, bs, at, "Segment size", uint(size));
            }
            102 => {
                let m = group(t, Some(node), "Buffers");
                buffers = bs.list(|bs, _| {
                    let at = bs.pos();
                    let (b, o) = block_ptr(bs)?;
                    leaf(
                        t,
                        m,
                        bs,
                        at,
                        "Buffer",
                        text(format!("block {b}, offset {o}")),
                    );
                    Ok(())
                })?;
                close(t, m, bs, at);
            }
            101 | 103 | 104 | 105 => {
                let name = match id {
                    101 => "Buffer ids",
                    103 => "Segment counts",
                    104 => "Allocation sizes",
                    _ => "Buffers with free space",
                };
                let mut vals = Vec::new();
                bs.list(|bs, _| {
                    let v = bs.uvar()?;
                    if vals.len() < 32 {
                        vals.push(v.to_string());
                    }
                    Ok(())
                })?;
                leaf(t, node, bs, at, name, text(vals.join(", ")));
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    close(t, node, bs, start);
    summarize(
        t,
        node,
        format!(
            "{size}-byte segments, {}",
            plural(buffers, "buffer", "buffers")
        ),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Table data

/// The table data stream: statistics, then a raw `u64` row group count and
/// the row groups (a column's statistics or a row group per step). Returns
/// the top-level nodes.
pub async fn table_data(
    cx: &Cx,
    s: &mut Stream,
    t: &mut Tree,
    columns: &[(String, Ty)],
    links: &dyn Links,
    roots: &mut Vec<usize>,
) -> Result<()> {
    let start = s.pos();
    let stats = group(t, None, "Statistics");
    roots.push(stats);
    // The statistics object, a field at a time.
    loop {
        let (at, id) = s
            .piece(cx, t, |bs, _| {
                let at = bs.pos();
                Ok((at, bs.id()?))
            })
            .await?;
        if id == END {
            break;
        }
        match id {
            100 => {
                let n = s.piece(cx, t, |bs, _| bs.count()).await?;
                for i in 0..n {
                    s.piece(cx, t, |bs, t| {
                        let at = bs.pos();
                        let (name, ty) = usize::try_from(i)
                            .ok()
                            .and_then(|i| columns.get(i))
                            .cloned()
                            .unwrap_or_else(|| (format!("column {i}"), Ty::default()));
                        let node = group(t, Some(stats), name);
                        if bs.present()? {
                            column_statistics(bs, t, node, &ty)?;
                        }
                        close(t, node, bs, at);
                        Ok(())
                    })
                    .await?;
                }
            }
            101 => {
                let r0 = roots.len();
                s.piece(cx, t, |bs, t| {
                    roots.truncate(r0);
                    if bs.present()? {
                        let g = group(t, None, "Sample");
                        roots.push(g);
                        let r = sample(bs, t, g);
                        close(t, g, bs, at);
                        r?;
                    }
                    Ok(())
                })
                .await?;
            }
            _ => {
                return s
                    .piece(cx, t, |bs, _| {
                        bs.seek(at);
                        Err(bs.unknown(id, at, "table statistics"))
                    })
                    .await;
            }
        }
    }
    let r0 = roots.len();
    let count = s
        .piece(cx, t, |bs, t| {
            roots.truncate(r0);
            close(t, stats, bs, start);
            let at = bs.pos();
            let count = bs.raw_u64()?;
            let n = t.add(
                None,
                Node::new("Row group count")
                    .span(bs.span(at))
                    .value(uint(count)),
            );
            roots.push(n);
            if count > crate::bytes::to_u64(bs.data().len()) && bs.short {
                return Err(Diagnostic::malformed("implausible row group count"));
            }
            Ok(count)
        })
        .await?;
    for k in 0..count {
        let r0 = roots.len();
        let stop = s
            .piece(cx, t, |bs, t| {
                roots.truncate(r0);
                let at = bs.pos();
                let node = group(t, None, format!("Row group {k}"));
                roots.push(node);
                let r = row_group(bs, t, node, columns, links);
                close(t, node, bs, at);
                if let Err(e) = r {
                    if bs.short {
                        return Err(e);
                    }
                    t.update(node, |n| n.diag(e));
                    return Ok(true);
                }
                Ok(false)
            })
            .await?;
        if stop {
            break;
        }
    }
    Ok(())
}

fn column_statistics(bs: &mut Bs<'_>, t: &mut Tree, node: usize, ty: &Ty) -> Result<()> {
    bs.object("column statistics", |bs, id, at| {
        match id {
            100 => {
                let s = base_stats(bs, t, node, ty, 0)?;
                summarize(t, node, s);
            }
            101 => {
                if bs.present()? {
                    let g = group(t, Some(node), "Distinct");
                    bs.object("distinct statistics", |bs, id, at| {
                        match id {
                            100 => {
                                let v = bs.uvar()?;
                                leaf(t, g, bs, at, "Sample count", uint(v));
                            }
                            101 => {
                                let v = bs.uvar()?;
                                leaf(t, g, bs, at, "Total count", uint(v));
                            }
                            102 => {
                                if bs.present()? {
                                    let h = group(t, Some(g), "HyperLogLog");
                                    bs.object("a HyperLogLog", |bs, id, at| {
                                        match id {
                                            100 => {
                                                let v = bs.uvar()?;
                                                leaf(t, h, bs, at, "Storage type", uint(v));
                                            }
                                            101 => {
                                                let b = bs.blob()?;
                                                let n = crate::bytes::to_u64(b.len());
                                                let i = leaf(
                                                    t,
                                                    h,
                                                    bs,
                                                    at,
                                                    "Data",
                                                    Value::Bytes(b.get(..16).unwrap_or(b).to_vec()),
                                                );
                                                t.update(i, |x| {
                                                    x.summary(plural(n, "byte", "bytes"))
                                                });
                                            }
                                            _ => return Ok(false),
                                        }
                                        Ok(true)
                                    })?;
                                    close(t, h, bs, at);
                                }
                            }
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    close(t, g, bs, at);
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// `BaseStatistics` typed by `ty`; returns a one-line summary.
fn base_stats(bs: &mut Bs<'_>, t: &mut Tree, p: usize, ty: &Ty, depth: usize) -> Result<String> {
    if depth > 32 {
        return Err(Diagnostic::limit("statistics nested too deeply"));
    }
    let mut parts = Vec::new();
    let mut has_null = false;
    let mut has_values = true;
    bs.object("statistics", |bs, id, at| {
        match id {
            100 => {
                has_null = bs.bool()?;
                leaf(t, p, bs, at, "Has NULL", Value::Bool(has_null));
            }
            101 => {
                has_values = bs.bool()?;
                leaf(t, p, bs, at, "Has non-NULL", Value::Bool(has_values));
            }
            102 => {
                let v = bs.uvar()?;
                leaf(t, p, bs, at, "Distinct count", uint(v));
            }
            103 => {
                let s = type_stats(bs, t, p, ty, depth)?;
                if !s.is_empty() {
                    parts.push(s);
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    if has_null {
        parts.push(if has_values {
            "some NULL".to_owned()
        } else {
            "all NULL".to_owned()
        });
    }
    Ok(parts.join(", "))
}

fn type_stats(bs: &mut Bs<'_>, t: &mut Tree, p: usize, ty: &Ty, depth: usize) -> Result<String> {
    let kind = phys(ty);
    let mut shown = Vec::new();
    bs.object("type statistics", |bs, id, at| {
        match (id, kind) {
            (
                200 | 201,
                Phys::Bool | Phys::Signed | Phys::Unsigned | Phys::Huge | Phys::F32 | Phys::F64,
            ) => {
                let mut v = None;
                bs.object("a statistics bound", |bs, id, _| {
                    match id {
                        100 => drop(bs.bool()?),
                        101 => v = Some(scalar(bs, ty, kind)?),
                        _ => return Ok(false),
                    }
                    Ok(true)
                })?;
                let name = if id == 200 { "Min" } else { "Max" };
                if let Some((s, value)) = v {
                    let i = t.add(Some(p), Node::new(name).span(bs.span(at)));
                    let decimal = matches!(ty.info, Info::Decimal(..));
                    t.update(i, |n| match value {
                        Some(value) if !decimal => n.value(value),
                        Some(value) => n.value(value).summary(s.clone()),
                        None => n.summary(s.clone()),
                    });
                    shown.push(format!("{} {s}", name.to_ascii_lowercase()));
                }
            }
            (200 | 201, Phys::Str) => {
                let b = bs.blob()?;
                let s = String::from_utf8_lossy(crate::text::until_nul(b).as_bytes()).into_owned();
                let name = if id == 200 {
                    "Min (prefix)"
                } else {
                    "Max (prefix)"
                };
                let i = leaf(t, p, bs, at, name, Value::Bytes(b.to_vec()));
                t.update(i, |n| n.summary(format!("'{s}'")));
            }
            (202, Phys::Str) => {
                let v = bs.bool()?;
                leaf(t, p, bs, at, "Has Unicode", Value::Bool(v));
            }
            (203, Phys::Str) => {
                let v = bs.bool()?;
                leaf(t, p, bs, at, "Has max length", Value::Bool(v));
            }
            (204, Phys::Str) => {
                let v = bs.uvar()?;
                leaf(t, p, bs, at, "Max length", uint(v));
                shown.push(format!("max length {v}"));
            }
            (200, Phys::List | Phys::Array) => {
                let child = match &ty.info {
                    Info::Child(c) | Info::Array(c, _) => (**c).clone(),
                    _ => Ty::default(),
                };
                let g = group(t, Some(p), "Child");
                let s = base_stats(bs, t, g, &child, depth.saturating_add(1))?;
                close(t, g, bs, at);
                summarize(t, g, s);
            }
            (200, Phys::Struct) => {
                let members = match &ty.info {
                    Info::Members(m) => m.clone(),
                    _ => Vec::new(),
                };
                let g = group(t, Some(p), "Members");
                bs.list(|bs, i| {
                    let at = bs.pos();
                    let (name, child) = usize::try_from(i)
                        .ok()
                        .and_then(|i| members.get(i))
                        .cloned()
                        .unwrap_or_else(|| (format!("member {i}"), Ty::default()));
                    let m = group(t, Some(g), name);
                    let s = base_stats(bs, t, m, &child, depth.saturating_add(1))?;
                    close(t, m, bs, at);
                    summarize(t, m, s);
                    Ok(())
                })?;
                close(t, g, bs, at);
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    Ok(shown.join(", "))
}

fn row_group(
    bs: &mut Bs<'_>,
    t: &mut Tree,
    node: usize,
    columns: &[(String, Ty)],
    links: &dyn Links,
) -> Result<()> {
    let (mut start, mut count) = (0u64, 0u64);
    bs.object("a row group", |bs, id, at| {
        match id {
            100 => {
                start = bs.uvar()?;
                leaf(t, node, bs, at, "Row start", uint(start));
            }
            101 => {
                count = bs.uvar()?;
                leaf(t, node, bs, at, "Tuple count", uint(count));
            }
            102 => {
                let g = group(t, Some(node), "Columns");
                let n = bs.list(|bs, i| {
                    let at = bs.pos();
                    let p = meta_ptr(bs)?;
                    let (name, ty) = usize::try_from(i)
                        .ok()
                        .and_then(|i| columns.get(i))
                        .cloned()
                        .unwrap_or_else(|| (format!("column {i}"), Ty::default()));
                    let n = links
                        .column_data(p, name.clone(), ty.clone())
                        .span(bs.span(at))
                        .value(text(ty.sql()));
                    t.add(Some(g), n);
                    Ok(())
                })?;
                close(t, g, bs, at);
                summarize(t, g, plural(n, "column", "columns"));
            }
            104 => {
                let v = bs.bool()?;
                leaf(t, node, bs, at, "Has metadata blocks", Value::Bool(v));
            }
            105 => {
                let mut words = Vec::new();
                bs.list(|bs, _| {
                    let w = bs.uvar()?;
                    if words.len() < 16 {
                        words.push(format!("{}/{}", w & super::BLOCK_MASK, w >> 56));
                    }
                    Ok(())
                })?;
                let i = leaf(
                    t,
                    node,
                    bs,
                    at,
                    "Extra metadata blocks",
                    text(words.join(", ")),
                );
                t.update(i, |n| {
                    n.desc("Metadata sub-blocks (block/sub-block) the row group also uses")
                });
            }
            103 => {
                let g = group(t, Some(node), "Delete pointers");
                let n = bs.list(|bs, _| {
                    let at = bs.pos();
                    let p = meta_ptr(bs)?;
                    leaf(t, g, bs, at, "Deletes", text(p.describe()));
                    Ok(())
                })?;
                close(t, g, bs, at);
                summarize(t, g, plural(n, "pointer", "pointers"));
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    summarize(
        t,
        node,
        format!(
            "rows {start}–{}",
            start.saturating_add(count).saturating_sub(1)
        ),
    );
    Ok(())
}

/// One column's persistent data in a row group: segments (data
/// pointers), then the validity column and child columns, recursively.
pub fn column_data(
    bs: &mut Bs<'_>,
    t: &mut Tree,
    p: Option<usize>,
    ty: &Ty,
    links: &dyn Links,
    depth: usize,
    out: &mut Vec<usize>,
) -> Result<()> {
    if depth > 32 {
        return Err(Diagnostic::limit("columns nested too deeply"));
    }
    let validity = Ty {
        id: 53,
        ..Ty::default()
    };
    bs.object("column data", |bs, id, at| {
        match id {
            100 => {
                let g = group(t, p, "Segments");
                out.push(g);
                let n = bs.list(|bs, i| data_pointer(bs, t, g, ty, i, links))?;
                close(t, g, bs, at);
                summarize(t, g, plural(n, "segment", "segments"));
            }
            101 => {
                let g = group(t, p, "Validity");
                out.push(g);
                column_data(
                    bs,
                    t,
                    Some(g),
                    &validity,
                    links,
                    depth.saturating_add(1),
                    &mut Vec::new(),
                )?;
                close(t, g, bs, at);
            }
            102 => match (phys(ty), &ty.info) {
                (Phys::List | Phys::Array, Info::Child(c) | Info::Array(c, _)) => {
                    let g = group(t, p, "Child");
                    out.push(g);
                    t.update(g, |n| n.value(text(c.sql())));
                    column_data(
                        bs,
                        t,
                        Some(g),
                        c,
                        links,
                        depth.saturating_add(1),
                        &mut Vec::new(),
                    )?;
                    close(t, g, bs, at);
                }
                (Phys::Struct, Info::Members(m)) => {
                    let g = group(t, p, "Members");
                    out.push(g);
                    bs.list(|bs, i| {
                        let at = bs.pos();
                        let (name, child) = usize::try_from(i)
                            .ok()
                            .and_then(|i| m.get(i))
                            .cloned()
                            .unwrap_or_else(|| (format!("member {i}"), Ty::default()));
                        let c = group(t, Some(g), name);
                        t.update(c, |n| n.value(text(child.sql())));
                        column_data(
                            bs,
                            t,
                            Some(c),
                            &child,
                            links,
                            depth.saturating_add(1),
                            &mut Vec::new(),
                        )?;
                        close(t, c, bs, at);
                        Ok(())
                    })?;
                    close(t, g, bs, at);
                }
                _ => return Ok(false),
            },
            _ => return Ok(false),
        }
        Ok(true)
    })
}

fn data_pointer(
    bs: &mut Bs<'_>,
    t: &mut Tree,
    p: usize,
    ty: &Ty,
    i: u64,
    links: &dyn Links,
) -> Result<()> {
    let start = bs.pos();
    let node = group(t, Some(p), format!("Segment {i}"));
    let (mut row, mut count, mut comp) = (0u64, 0u64, 0u64);
    let mut block = None;
    let mut stats = String::new();
    bs.object("a data pointer", |bs, id, at| {
        match id {
            100 => {
                row = bs.uvar()?;
                leaf(t, node, bs, at, "Row start", uint(row));
            }
            101 => {
                count = bs.uvar()?;
                leaf(t, node, bs, at, "Tuple count", uint(count));
            }
            102 => {
                let (b, o) = block_ptr(bs)?;
                let mut n = Node::new("Block pointer").span(bs.span(at));
                if b < 0 {
                    n = n.value(text("none"));
                } else {
                    n = n.value(text(format!("block {b}, offset {o}")));
                    if let Some(target) = links.block_target(b, o) {
                        n = n.target(target);
                    }
                    block = Some((b, o));
                }
                t.add(Some(node), n);
            }
            103 => {
                comp = bs.uvar()?;
                leaf(t, node, bs, at, "Compression", enumv(COMPRESSION, comp));
            }
            104 => {
                let g = group(t, Some(node), "Statistics");
                stats = base_stats(bs, t, g, ty, 0)?;
                close(t, g, bs, at);
                summarize(t, g, stats.clone());
            }
            105 => {
                if bs.present()? {
                    let g = group(t, Some(node), "Segment state");
                    segment_state(bs, t, g)?;
                    close(t, g, bs, at);
                }
            }
            _ => return Ok(false),
        }
        Ok(true)
    })?;
    close(t, node, bs, start);
    let mut summary = format!(
        "rows {row}–{}, {}",
        row.saturating_add(count).saturating_sub(1),
        lookup(COMPRESSION, comp).unwrap_or("compression ?")
    );
    if let Some((b, o)) = block {
        summary.push_str(&format!(", block {b} + {o:#x}"));
    }
    if !stats.is_empty() {
        summary.push_str(&format!("; {stats}"));
    }
    summarize(t, node, summary);
    Ok(())
}

/// Compression-specific segment state. Only the overflow block list
/// (uncompressed strings) is known.
fn segment_state(bs: &mut Bs<'_>, t: &mut Tree, g: usize) -> Result<()> {
    bs.object("segment state", |bs, id, at| {
        match id {
            100 => {
                let mut ids = Vec::new();
                bs.list(|bs, _| {
                    let v = bs.svar()?;
                    if ids.len() < 32 {
                        ids.push(v.to_string());
                    }
                    Ok(())
                })?;
                leaf(t, g, bs, at, "Overflow blocks", text(ids.join(", ")));
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}

/// The table's reservoir sample (its weights and counters; a sampled data
/// chunk, which small tables do not have, is not decoded).
fn sample(bs: &mut Bs<'_>, t: &mut Tree, g: usize) -> Result<()> {
    bs.object("a table sample", |bs, id, at| {
        match id {
            100 => {
                if bs.present()? {
                    let b = group(t, Some(g), "Reservoir");
                    bs.object("reservoir sampling state", |bs, id, at| {
                        match id {
                            100 | 102 | 103 | 104 => {
                                let v = bs.uvar()?;
                                let name = match id {
                                    100 => "Next index to sample",
                                    102 => "Min weighted entry index",
                                    103 => "Entries to skip",
                                    _ => "Entries seen",
                                };
                                leaf(t, b, bs, at, name, uint(v));
                            }
                            101 => {
                                let v = bs.f64()?;
                                leaf(t, b, bs, at, "Min weight threshold", Value::Float(v));
                            }
                            105 => {
                                let n = bs.list(|bs, _| {
                                    pair(bs, |bs| bs.f64().map(drop), |bs| bs.uvar().map(drop))
                                })?;
                                leaf(t, b, bs, at, "Weights", uint(n));
                            }
                            _ => return Ok(false),
                        }
                        Ok(true)
                    })?;
                    close(t, b, bs, at);
                }
            }
            101 => {
                let v = bs.uvar()?;
                leaf(t, g, bs, at, "Sample type", uint(v));
            }
            102 => {
                let v = bs.bool()?;
                leaf(t, g, bs, at, "Destroyed", Value::Bool(v));
            }
            200 => {
                let v = bs.uvar()?;
                leaf(t, g, bs, at, "Sample count", uint(v));
                summarize(t, g, format!("{v} rows sampled"));
            }
            201 => {
                return Err(
                    Diagnostic::unsupported("the sampled rows are not decoded").at(bs.span(at))
                );
            }
            _ => return Ok(false),
        }
        Ok(true)
    })
}
