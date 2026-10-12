//! Table definitions (page type 0x02): the table header, column
//! descriptors, column names, physical ("real") and logical indexes, and in
//! Jet 4 the long-value maps of memo and OLE columns. A definition longer
//! than a page continues on the pages chained from offset 4; the
//! continuation pages' bytes from offset 8 on are appended, so the whole
//! definition is one pieced source.

use std::sync::Arc;

use super::{Fmt, pointer_text};
use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::{lines, val};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, flag, lookup};

/// Where the table header fields and the entries sit in each version.
struct Layout {
    num_rows: usize,
    autonumber: usize,
    table_type: usize,
    max_cols: usize,
    num_var_cols: usize,
    num_cols: usize,
    num_idx: usize,
    num_real_idx: usize,
    used_pages: usize,
    free_pages: usize,
    cols_start: usize,
    real_idx_entry: usize,
    col_entry: usize,
    col_number: usize,
    col_var_index: usize,
    col_misc: usize,
    col_flags: usize,
    col_fixed_offset: usize,
    col_size: usize,
    real_idx_block: usize,
    real_idx_skip: usize,
    real_idx_flags_skip: usize,
    logical_idx_block: usize,
    logical_idx_skip: usize,
}

const JET3: Layout = Layout {
    num_rows: 12,
    autonumber: 16,
    table_type: 20,
    max_cols: 21,
    num_var_cols: 23,
    num_cols: 25,
    num_idx: 27,
    num_real_idx: 31,
    used_pages: 35,
    free_pages: 39,
    cols_start: 43,
    real_idx_entry: 8,
    col_entry: 18,
    col_number: 1,
    col_var_index: 3,
    col_misc: 9,
    col_flags: 13,
    col_fixed_offset: 14,
    col_size: 16,
    real_idx_block: 39,
    real_idx_skip: 0,
    real_idx_flags_skip: 0,
    logical_idx_block: 20,
    logical_idx_skip: 0,
};

const JET4: Layout = Layout {
    num_rows: 16,
    autonumber: 20,
    table_type: 40,
    max_cols: 41,
    num_var_cols: 43,
    num_cols: 45,
    num_idx: 47,
    num_real_idx: 51,
    used_pages: 55,
    free_pages: 59,
    cols_start: 63,
    real_idx_entry: 12,
    col_entry: 25,
    col_number: 5,
    col_var_index: 7,
    col_misc: 11,
    col_flags: 15,
    col_fixed_offset: 21,
    col_size: 23,
    real_idx_block: 52,
    real_idx_skip: 4,
    real_idx_flags_skip: 4,
    logical_idx_block: 28,
    logical_idx_skip: 4,
};

fn layout(fmt: Fmt) -> &'static Layout {
    if fmt.jet3 { &JET3 } else { &JET4 }
}

/// A definition chained over more pages than this is treated as broken
/// (255 columns with long names fit in a few pages).
const MAX_PAGES: usize = 64;

pub const COLUMN_TYPES: EnumTable = &[
    (0x01, "Boolean"),
    (0x02, "Byte"),
    (0x03, "Integer"),
    (0x04, "Long Integer"),
    (0x05, "Currency"),
    (0x06, "Single"),
    (0x07, "Double"),
    (0x08, "Date/Time"),
    (0x09, "Binary"),
    (0x0a, "Text"),
    (0x0b, "OLE Object"),
    (0x0c, "Memo"),
    (0x0f, "Replication ID"),
    (0x10, "Decimal"),
    (0x12, "Complex"),
    (0x13, "Large Number"),
    (0x14, "Date/Time Extended"),
];

const COLUMN_FLAGS: FlagTable = &[
    flag(0x01, "FIXED_LENGTH"),
    flag(0x02, "UPDATABLE"),
    flag(0x04, "AUTO_NUMBER"),
    flag(0x40, "AUTO_NUMBER_GUID"),
    flag(0x80, "HYPERLINK"),
];

const COLUMN_EXT_FLAGS: FlagTable = &[flag(0x01, "COMPRESSED_UNICODE")];

const TABLE_TYPES: EnumTable = &[(0x4e, "user table"), (0x53, "system table")];

const INDEX_TYPES: EnumTable = &[(0, "normal"), (1, "primary key"), (2, "foreign key")];

const INDEX_FLAGS: FlagTable = &[
    flag(0x01, "UNIQUE"),
    flag(0x02, "IGNORE_NULLS"),
    flag(0x08, "REQUIRED"),
];

#[derive(Clone, Debug)]
pub struct Column {
    pub name: String,
    pub kind: u8,
    /// Position in the row's null mask (counts deleted columns).
    pub number: u16,
    /// Position in the row's variable-length offset table.
    pub var_index: u16,
    pub fixed_offset: u16,
    pub size: u16,
    pub flags: u8,
    pub misc: [u8; 2],
    /// Offset of the descriptor and of the name (its length prefix) in the
    /// definition.
    pub at: usize,
    pub name_at: usize,
    pub name_len: usize,
}

impl Column {
    pub fn fixed(&self) -> bool {
        self.flags & 1 != 0
    }

    /// The type with its size: "Text, 80 bytes", "Decimal (18, 4)".
    pub fn describe(&self) -> String {
        let kind = lookup(COLUMN_TYPES, self.kind.into())
            .map_or_else(|| format!("type {:#04x}", self.kind), str::to_owned);
        let [a, b] = self.misc;
        match self.kind {
            0x09 | 0x0a => format!("{kind}, {} bytes", self.size),
            0x10 => format!("{kind} ({a}, {b})"),
            _ => kind,
        }
    }
}

#[derive(Clone, Debug)]
pub struct RealIndex {
    pub at: usize,
    pub columns: Vec<(u16, bool)>,
    pub used_pages: u32,
    pub first_page: u32,
    pub flags: u8,
}

#[derive(Clone, Debug)]
pub struct LogicalIndex {
    pub at: usize,
    pub name: String,
    pub name_at: usize,
    pub name_len: usize,
    pub number: u32,
    pub real: u32,
    pub kind: u8,
    pub related_table: u32,
}

#[derive(Clone, Debug)]
pub struct LongValueMap {
    pub at: usize,
    pub column: u16,
    pub used_pages: u32,
    pub free_pages: u32,
}

#[derive(Clone, Debug)]
pub struct TableDef {
    /// The whole definition (a pieced source when it spans pages).
    pub span: Span,
    pub page: u32,
    pub pages: Vec<u32>,
    pub num_rows: u32,
    pub table_type: u8,
    pub num_var_cols: u16,
    pub used_pages: u32,
    pub columns: Vec<Column>,
    pub real_indexes: Vec<RealIndex>,
    pub indexes: Vec<LogicalIndex>,
    pub long_value_maps: Vec<LongValueMap>,
    pub problem: Option<Diagnostic>,
}

impl TableDef {
    pub fn column_name(&self, number: u16) -> String {
        self.columns
            .iter()
            .find(|c| c.number == number)
            .map_or_else(|| format!("column {number}"), |c| c.name.clone())
    }
}

/// The definition whose first page is `page`, parsed once per session.
pub async fn load(cx: &Cx, file: Span, fmt: Fmt, page: u32) -> Result<Arc<TableDef>> {
    let first = fmt.page_span(file, page);
    if let Some(def) = cx.cached::<TableDef>(first, "jet-tdef") {
        return Ok(def);
    }
    let head = cx.read(first.sub(0, 8)).await?;
    if head.first() != Some(&2) {
        return Err(
            Diagnostic::malformed(format!("page {page} is not a table definition")).at(first),
        );
    }
    let mut pieces = vec![first];
    let mut pages = vec![page];
    let mut problem = None;
    let mut next = u32_le(&head, 4).unwrap_or(0);
    while next != 0 {
        if pages.len() >= MAX_PAGES || pages.contains(&next) {
            problem = Some(Diagnostic::malformed(format!(
                "table definition chain loops or exceeds {MAX_PAGES} pages"
            )));
            break;
        }
        let span = fmt.page_span(file, next);
        let h = cx.read_avail(span.sub(0, 8)).await?;
        if h.first() != Some(&2) {
            problem = Some(Diagnostic::malformed(format!(
                "table definition continues on page {next}, which is not a definition page"
            )));
            break;
        }
        pieces.push(span.tail(8));
        pages.push(next);
        next = u32_le(&h, 4).unwrap_or(0);
    }
    let span = if pieces.len() == 1 {
        first
    } else {
        cx.add_pieces(
            Origin {
                parent: first,
                transform: "jet-tdef",
            },
            pieces,
        )?
    };
    let data = cx.read(span).await?;
    let mut def = parse(&data, span, fmt, page)?;
    def.pages = pages;
    if def.problem.is_none() {
        def.problem = problem;
    }
    let def = Arc::new(def);
    cx.cache(first, "jet-tdef", def.clone());
    Ok(def)
}

fn name_at(data: &[u8], at: usize, fmt: Fmt) -> Option<(String, usize)> {
    if fmt.jet3 {
        let n = usize::from(*data.get(at)?);
        let raw = data.get(at.checked_add(1)?..at.checked_add(1)?.checked_add(n)?)?;
        Some((fmt.decode_bytes(raw), n.saturating_add(1)))
    } else {
        let n = usize::from(u16_le(data, at)?);
        let raw = data.get(at.checked_add(2)?..at.checked_add(2)?.checked_add(n)?)?;
        Some((
            crate::text::utf16(raw, crate::fields::Endian::Little),
            n.saturating_add(2),
        ))
    }
}

/// Parses a definition. Every loop is bounded by the bytes read.
pub fn parse(data: &[u8], span: Span, fmt: Fmt, page: u32) -> Result<TableDef> {
    let l = layout(fmt);
    let u16_at = |o: usize| u16_le(data, o).unwrap_or(0);
    let u32_at = |o: usize| u32_le(data, o).unwrap_or(0);
    if data.len() < l.cols_start {
        return Err(Diagnostic::truncated(
            span.sub(0, to_u64(l.cols_start)),
            to_u64(data.len()),
        ));
    }
    let num_cols = usize::from(u16_at(l.num_cols));
    let num_idx = usize::try_from(u32_at(l.num_idx)).unwrap_or(usize::MAX);
    let num_real_idx = usize::try_from(u32_at(l.num_real_idx)).unwrap_or(usize::MAX);
    let mut def = TableDef {
        span,
        page,
        pages: vec![page],
        num_rows: u32_at(l.num_rows),
        table_type: data.get(l.table_type).copied().unwrap_or(0),
        num_var_cols: u16_at(l.num_var_cols),
        used_pages: u32_at(l.used_pages),
        columns: Vec::new(),
        real_indexes: Vec::new(),
        indexes: Vec::new(),
        long_value_maps: Vec::new(),
        problem: None,
    };
    let truncated = |what: &str| {
        Some(Diagnostic::malformed(format!(
            "table definition ends inside the {what}"
        )))
    };
    let mut o = l
        .cols_start
        .saturating_add(num_real_idx.saturating_mul(l.real_idx_entry));
    for _ in 0..num_cols {
        let Some(e) = o.checked_add(l.col_entry).and_then(|end| data.get(o..end)) else {
            def.problem = truncated("column descriptors");
            return Ok(def);
        };
        let at = |i: usize| e.get(i).copied().unwrap_or(0);
        let u16e = |i: usize| u16_le(e, i).unwrap_or(0);
        def.columns.push(Column {
            name: String::new(),
            kind: at(0),
            number: u16e(l.col_number),
            var_index: u16e(l.col_var_index),
            fixed_offset: u16e(l.col_fixed_offset),
            size: u16e(l.col_size),
            flags: at(l.col_flags),
            misc: [at(l.col_misc), at(l.col_misc.saturating_add(1))],
            at: o,
            name_at: 0,
            name_len: 0,
        });
        o = o.saturating_add(l.col_entry);
    }
    for col in &mut def.columns {
        let Some((name, len)) = name_at(data, o, fmt) else {
            def.problem = truncated("column names");
            return Ok(def);
        };
        col.name = name;
        col.name_at = o;
        col.name_len = len;
        o = o.saturating_add(len);
    }
    for _ in 0..num_real_idx {
        let Some(b) = o
            .checked_add(l.real_idx_block)
            .and_then(|end| data.get(o..end))
        else {
            def.problem = truncated("index descriptors");
            return Ok(def);
        };
        let mut columns = Vec::new();
        for k in 0..10usize {
            let p = l.real_idx_skip.saturating_add(k.saturating_mul(3));
            let col = u16_le(b, p).unwrap_or(0xffff);
            if col != 0xffff {
                let order = b.get(p.saturating_add(2)).copied().unwrap_or(1);
                columns.push((col, order != 2));
            }
        }
        let after = l.real_idx_skip.saturating_add(30);
        def.real_indexes.push(RealIndex {
            at: o,
            columns,
            used_pages: u32_le(b, after).unwrap_or(0),
            first_page: u32_le(b, after.saturating_add(4)).unwrap_or(0),
            flags: b
                .get(
                    after
                        .saturating_add(8)
                        .saturating_add(l.real_idx_flags_skip),
                )
                .copied()
                .unwrap_or(0),
        });
        o = o.saturating_add(l.real_idx_block);
    }
    for _ in 0..num_idx {
        let Some(b) = o
            .checked_add(l.logical_idx_block)
            .and_then(|end| data.get(o..end))
        else {
            def.problem = truncated("logical index descriptors");
            return Ok(def);
        };
        let s = l.logical_idx_skip;
        def.indexes.push(LogicalIndex {
            at: o,
            name: String::new(),
            name_at: 0,
            name_len: 0,
            number: u32_le(b, s).unwrap_or(0),
            real: u32_le(b, s.saturating_add(4)).unwrap_or(0),
            related_table: u32_le(b, s.saturating_add(13)).unwrap_or(0),
            kind: b.get(s.saturating_add(19)).copied().unwrap_or(0),
        });
        o = o.saturating_add(l.logical_idx_block);
    }
    for idx in &mut def.indexes {
        let Some((name, len)) = name_at(data, o, fmt) else {
            def.problem = truncated("index names");
            return Ok(def);
        };
        idx.name = name;
        idx.name_at = o;
        idx.name_len = len;
        o = o.saturating_add(len);
    }
    if !fmt.jet3 {
        // Jet 4: the usage maps of each long-value column, ended by 0xffff.
        while let Some(column) = u16_le(data, o).filter(|&c| c != 0xffff) {
            if def.long_value_maps.len() >= num_cols.max(1) {
                break;
            }
            def.long_value_maps.push(LongValueMap {
                at: o,
                column,
                used_pages: u32_le(data, o.saturating_add(2)).unwrap_or(0),
                free_pages: u32_le(data, o.saturating_add(6)).unwrap_or(0),
            });
            o = o.saturating_add(10);
        }
    }
    Ok(def)
}

/// Renders the definition whose first page is `page`.
pub async fn definition(cx: Cx, (file, fmt, page): (Span, Fmt, u32)) -> Result<()> {
    let def = load(&cx, file, fmt, page).await?;
    let data = cx.read(def.span).await?;
    let l = layout(fmt);
    let s = def.span;
    let u16_at = |o: usize| u16_le(&data, o).unwrap_or(0);
    let u32_at = |o: usize| u32_le(&data, o).unwrap_or(0);
    let at = |o: usize, n: u64| s.sub(to_u64(o), n);
    if def.pages.len() > 1 {
        let list: Vec<String> = def.pages.iter().map(u32::to_string).collect();
        cx.emit(Node::new("Pages").summary(list.join(", ")));
    }
    cx.emit(
        Node::new("Next page")
            .span(at(4, 4))
            .value(val::uint(u32_at(4), 32)),
    );
    cx.emit(
        Node::new("Definition length")
            .span(at(8, 4))
            .value(val::uint(u32_at(8), 32)),
    );
    cx.emit(
        Node::new("Row count")
            .span(at(l.num_rows, 4))
            .value(val::uint(def.num_rows, 32)),
    );
    cx.emit(
        Node::new("Next autonumber")
            .span(at(l.autonumber, 4))
            .value(val::uint(u32_at(l.autonumber), 32)),
    );
    cx.emit(
        Node::new("Table type")
            .span(at(l.table_type, 1))
            .value(val::enumv(def.table_type, 8, TABLE_TYPES)),
    );
    for (name, o) in [
        ("Maximum columns", l.max_cols),
        ("Variable columns", l.num_var_cols),
        ("Column count", l.num_cols),
    ] {
        cx.emit(
            Node::new(name)
                .span(at(o, 2))
                .value(val::uint(u16_at(o), 16)),
        );
    }
    for (name, o) in [
        ("Logical index count", l.num_idx),
        ("Index count", l.num_real_idx),
    ] {
        cx.emit(
            Node::new(name)
                .span(at(o, 4))
                .value(val::uint(u32_at(o), 32)),
        );
    }
    for (name, o) in [
        ("Used pages map", l.used_pages),
        ("Free pages map", l.free_pages),
    ] {
        let v = u32_at(o);
        cx.emit(
            Node::new(name)
                .span(at(o, 4))
                .value(val::hex(v, 32))
                .summary(pointer_text(v)),
        );
    }
    let mut cols = Node::new("Columns").summary(format!("{}", def.columns.len()));
    if !def.columns.is_empty() {
        cols = cols.lazy(columns, (file, fmt, page));
    }
    cx.emit(cols);
    if !def.real_indexes.is_empty() || !def.indexes.is_empty() {
        cx.emit(
            Node::new("Indexes")
                .summary(format!("{}", def.indexes.len()))
                .lazy(indexes, (file, fmt, page)),
        );
    }
    if !def.long_value_maps.is_empty() {
        cx.emit(
            Node::new("Long value maps")
                .summary(format!("{}", def.long_value_maps.len()))
                .lazy(long_value_maps, (file, fmt, page)),
        );
    }
    if let Some(p) = &def.problem {
        cx.diag(p.clone().at(s));
    }
    Ok(())
}

async fn columns(cx: Cx, (file, fmt, page): (Span, Fmt, u32)) -> Result<()> {
    let def = load(&cx, file, fmt, page).await?;
    let l = layout(fmt);
    let s = def.span;
    for col in &def.columns {
        let entry = s.sub(to_u64(col.at), to_u64(l.col_entry));
        let kind = if col.fixed() {
            format!("fixed at {}", col.fixed_offset)
        } else {
            format!("variable #{}", col.var_index)
        };
        cx.push(
            Node::new(col.name.clone())
                .span(entry)
                .summary(format!("{}, {kind}", col.describe()))
                .lazy(column_fields, (s, fmt, col.clone())),
        )
        .await;
    }
    Ok(())
}

async fn column_fields(cx: Cx, (s, fmt, col): (Span, Fmt, Column)) -> Result<()> {
    let l = layout(fmt);
    let at = |o: usize, n: u64| s.sub(to_u64(col.at.saturating_add(o)), n);
    cx.emit(
        Node::new("Type")
            .span(at(0, 1))
            .value(val::enumv(col.kind, 8, COLUMN_TYPES)),
    );
    cx.emit(
        Node::new("Number")
            .span(at(l.col_number, 2))
            .value(val::uint(col.number, 16))
            .desc("Bit in the row's null mask (counts deleted columns)"),
    );
    cx.emit(
        Node::new("Variable index")
            .span(at(l.col_var_index, 2))
            .value(val::uint(col.var_index, 16)),
    );
    let [a, b] = col.misc;
    match col.kind {
        0x10 => {
            cx.emit(
                Node::new("Precision")
                    .span(at(l.col_misc, 1))
                    .value(val::uint(a, 8)),
            );
            cx.emit(
                Node::new("Scale")
                    .span(at(l.col_misc.saturating_add(1), 1))
                    .value(val::uint(b, 8)),
            );
        }
        0x0a | 0x0c => {
            let v = u16::from_le_bytes(col.misc);
            let name = if fmt.jet3 { "Code page" } else { "Sort order" };
            cx.emit(Node::new(name).span(at(l.col_misc, 2)).value(if fmt.jet3 {
                val::uint(v, 16)
            } else {
                val::hex(v, 16)
            }));
        }
        _ => {}
    }
    cx.emit(
        Node::new("Flags")
            .span(at(l.col_flags, 1))
            .value(lines::flags(COLUMN_FLAGS, col.flags.into(), 8)),
    );
    if !fmt.jet3 {
        let ext = s.sub(to_u64(col.at.saturating_add(16)), 1);
        cx.emit(Node::new("Extra flags").span(ext).lazy(ext_flags, ext));
    }
    cx.emit(
        Node::new("Fixed offset")
            .span(at(l.col_fixed_offset, 2))
            .value(val::uint(col.fixed_offset, 16)),
    );
    cx.emit(
        Node::new("Length")
            .span(at(l.col_size, 2))
            .value(val::uint(col.size, 16)),
    );
    cx.emit(
        Node::new("Name")
            .span(s.sub(to_u64(col.name_at), to_u64(col.name_len)))
            .value(val::text(col.name.clone())),
    );
    Ok(())
}

async fn ext_flags(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    cx.emit(Node::new("Flags").span(span).value(lines::flags(
        COLUMN_EXT_FLAGS,
        b.first().copied().unwrap_or(0).into(),
        8,
    )));
    Ok(())
}

async fn indexes(cx: Cx, (file, fmt, page): (Span, Fmt, u32)) -> Result<()> {
    let def = load(&cx, file, fmt, page).await?;
    let l = layout(fmt);
    let s = def.span;
    for idx in &def.indexes {
        let real = usize::try_from(idx.real)
            .ok()
            .and_then(|i| def.real_indexes.get(i));
        let mut summary = lookup(INDEX_TYPES, idx.kind.into())
            .unwrap_or("index")
            .to_owned();
        if let Some(r) = real {
            let cols: Vec<String> = r
                .columns
                .iter()
                .map(|&(c, asc)| {
                    let name = def.column_name(c);
                    if asc { name } else { format!("{name} DESC") }
                })
                .collect();
            summary = format!("{summary} on {}", cols.join(", "));
            if r.flags & 1 != 0 {
                summary.push_str(", unique");
            }
        }
        let mut node = Node::new(idx.name.clone())
            .span(s.sub(to_u64(idx.at), to_u64(l.logical_idx_block)))
            .summary(summary);
        let mut kids = vec![
            Node::new("Number")
                .span(s.sub(to_u64(idx.at.saturating_add(l.logical_idx_skip)), 4))
                .value(val::uint(idx.number, 32)),
            Node::new("Index")
                .span(s.sub(
                    to_u64(idx.at.saturating_add(l.logical_idx_skip).saturating_add(4)),
                    4,
                ))
                .value(val::uint(idx.real, 32)),
            Node::new("Kind")
                .span(s.sub(
                    to_u64(idx.at.saturating_add(l.logical_idx_skip).saturating_add(19)),
                    1,
                ))
                .value(val::enumv(idx.kind, 8, INDEX_TYPES)),
        ];
        if idx.kind == 2 {
            kids.push(
                Node::new("Related table page")
                    .span(s.sub(
                        to_u64(idx.at.saturating_add(l.logical_idx_skip).saturating_add(13)),
                        4,
                    ))
                    .value(val::uint(idx.related_table, 32)),
            );
        }
        kids.push(
            Node::new("Name")
                .span(s.sub(to_u64(idx.name_at), to_u64(idx.name_len)))
                .value(val::text(idx.name.clone())),
        );
        if let Some(r) = real {
            let b = s.sub(to_u64(r.at), to_u64(l.real_idx_block));
            let after = to_u64(l.real_idx_skip.saturating_add(30));
            let cols: Vec<String> = r.columns.iter().map(|&(c, _)| def.column_name(c)).collect();
            kids.push(
                Node::new("Columns")
                    .span(b.sub(to_u64(l.real_idx_skip), 30))
                    .summary(cols.join(", ")),
            );
            kids.push(
                Node::new("Used pages map")
                    .span(b.sub(after, 4))
                    .value(val::hex(r.used_pages, 32))
                    .summary(pointer_text(r.used_pages)),
            );
            kids.push(
                Node::new("First index page")
                    .span(b.sub(after.saturating_add(4), 4))
                    .value(val::uint(r.first_page, 32)),
            );
            kids.push(
                Node::new("Flags")
                    .span(
                        b.sub(
                            after
                                .saturating_add(8)
                                .saturating_add(to_u64(l.real_idx_flags_skip)),
                            1,
                        ),
                    )
                    .value(lines::flags(INDEX_FLAGS, r.flags.into(), 8)),
            );
        }
        node = node.lazy(emit_all, kids);
        cx.push(node).await;
    }
    Ok(())
}

async fn emit_all(cx: Cx, nodes: Vec<Node>) -> Result<()> {
    for n in nodes {
        cx.emit(n);
    }
    Ok(())
}

async fn long_value_maps(cx: Cx, (file, fmt, page): (Span, Fmt, u32)) -> Result<()> {
    let def = load(&cx, file, fmt, page).await?;
    for m in &def.long_value_maps {
        let span = def.span.sub(to_u64(m.at), 10);
        cx.push(
            Node::new(def.column_name(m.column))
                .span(span)
                .summary(format!(
                    "used pages {}, free pages {}",
                    pointer_text(m.used_pages),
                    pointer_text(m.free_pages)
                )),
        )
        .await;
    }
    Ok(())
}
