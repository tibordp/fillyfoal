//! Microsoft Access databases: Jet 3 (`.mdb`, Access 97, 2 KiB pages),
//! Jet 4 (`.mdb`, Access 2000-2003) and ACE (`.accdb`, Access 2007 on; both
//! 4 KiB pages). Page 0 holds the file header, part of which is obfuscated
//! with RC4 (key `0x6b39dac7`); it is decrypted into a derived source.
//!
//! The catalog is the system table MSysObjects, whose definition is always
//! on page 2: each local table's row there names it and gives its
//! definition page (the low 24 bits of its Id). A table is shown as its
//! definition (columns, indexes) and its rows, found through the table's
//! usage map and decoded column by column; memo and OLE values stored on
//! long-value pages are reassembled into one source. All pages are also
//! listed by number with their type; data pages show their row offsets.
//!
//! Layouts follow mdbtools' HACKING notes and Jackcess, and were checked
//! against Jackcess-written Jet 4 and ACE files read back with mdb-export.

mod row;
mod tdef;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::{fmt as ufmt, val};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value, lookup};

/// What every walker needs to know about the file.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Fmt {
    pub jet3: bool,
    pub page: u64,
    /// The database code page, for Jet 3 text.
    pub codepage: u16,
}

impl Fmt {
    /// Offset of a data page's row count (the offsets follow it).
    pub fn rows_at(self) -> usize {
        if self.jet3 { 8 } else { 12 }
    }

    pub fn page_span(self, file: Span, no: u32) -> Span {
        file.sub(u64::from(no).saturating_mul(self.page), self.page)
    }

    pub fn pages(self, file: Span) -> u64 {
        file.len.checked_div(self.page).unwrap_or(0)
    }

    /// Bytes in the database code page (Windows-1252 if unknown).
    pub fn decode_bytes(self, b: &[u8]) -> String {
        crate::codec::charset::decode_label(&format!("windows-{}", self.codepage), b)
            .unwrap_or_else(|| crate::codec::charset::Charset::Windows1252.decode(b))
    }
}

/// A row pointer: the page number above the low byte, the row in it.
pub fn pointer(v: u32) -> (u32, u8) {
    (v.wrapping_shr(8), u8::try_from(v & 0xff).unwrap_or(0))
}

pub fn pointer_text(v: u32) -> String {
    let (page, row) = pointer(v);
    format!("page {page} row {row}")
}

pub static MDB: Format = Format {
    name: "mdb",
    title: "Microsoft Access database (Jet)",
    extensions: &["mdb", "mde", "mdw"],
    mime: "application/x-msaccess",
    probe: Probe::Custom(|h| h.starts_with(&[0, 1, 0, 0]) && h.at(4, b"Standard Jet DB\0")),
    dissect: crate::expander!(dissect: Input),
};

pub static ACCDB: Format = Format {
    name: "accdb",
    title: "Microsoft Access database (ACE)",
    extensions: &["accdb", "accde", "laccdb"],
    mime: "application/x-msaccess",
    probe: Probe::Custom(|h: &Head<'_>| {
        h.starts_with(&[0, 1, 0, 0]) && h.at(4, b"Standard ACE DB\0")
    }),
    dissect: crate::expander!(dissect: Input),
};

const VERSIONS: EnumTable = &[
    (0, "Jet 3 (Access 97)"),
    (1, "Jet 4 (Access 2000-2003)"),
    (2, "ACE 12 (Access 2007)"),
    (3, "ACE 14 (Access 2010)"),
    (4, "ACE 15 (Access 2013)"),
    (5, "ACE 16 (Access 2016)"),
    (6, "ACE 17 (Access 2019)"),
];

const PAGE_TYPES: EnumTable = &[
    (0x00, "database definition"),
    (0x01, "data"),
    (0x02, "table definition"),
    (0x03, "intermediate index"),
    (0x04, "leaf index"),
    (0x05, "page usage bitmap"),
];

const KEY: [u8; 4] = [0xc7, 0xda, 0x39, 0x6b];

fn rc4(key: &[u8], data: &[u8]) -> Vec<u8> {
    crate::codec::crypto::rc4(key, data)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x18)).await?;
    let version = u32_le(&head, 0x14).unwrap_or(0);
    let jet3 = version == 0;
    let page_size: u64 = if jet3 { 2048 } else { 4096 };
    cx.emit(
        Node::new("Page type")
            .span(file.sub(0, 4))
            .value(Value::Bytes(head.get(..4).unwrap_or_default().to_vec())),
    );
    cx.emit(
        Node::new("Format ID")
            .span(file.sub(4, 16))
            .value(Value::Text(crate::text::until_nul(
                head.get(4..20).unwrap_or_default(),
            ))),
    );
    cx.emit(
        Node::new("Version")
            .span(file.sub(0x14, 4))
            .value(Value::Enum {
                raw: version.into(),
                bits: 32,
                name: lookup(VERSIONS, version.into()),
            }),
    );
    let enc_len: u64 = if jet3 { 126 } else { 128 };
    let enc = file.sub(0x18, enc_len);
    let raw = cx.read(enc).await?;
    let decoded = cx.add_derived(
        Origin {
            parent: enc,
            transform: "jet-rc4",
        },
        rc4(&KEY, &raw),
        enc_len,
        None,
    )?;
    let plain = cx.read(decoded.span).await?;
    let mut header = Node::new("Database header")
        .span(enc)
        .summary("RC4-obfuscated")
        .lazy(header_fields, (decoded.span, jet3));
    if raw.len() < crate::bytes::to_usize(enc_len) {
        header = header.diag(Diagnostic::truncated(enc, to_u64(raw.len())));
    }
    cx.emit(header);
    let pages = file.len.checked_div(page_size).unwrap_or(0);
    let codepage = if jet3 {
        u16_le(&plain, 0x3a - 0x18)
    } else {
        u16_le(&plain, 0x3c - 0x18)
    };
    let mut summary = format!(
        "Access database, {}, {pages} pages of {page_size} bytes",
        lookup(VERSIONS, version.into()).unwrap_or("unknown version")
    );
    if let Some(cp) = codepage.filter(|&c| c != 0) {
        summary = format!("{summary}, code page {cp}");
    }
    cx.annotate(summary);
    let fmt = Fmt {
        jet3,
        page: page_size,
        codepage: codepage.filter(|&c| c != 0).unwrap_or(1252),
    };
    if pages > 2 {
        cx.emit(
            Node::new("Catalog")
                .desc(
                    "The objects listed in MSysObjects; tables expand to their definition and rows",
                )
                .lazy(catalog, (input, fmt)),
        );
    }
    cx.emit(
        Node::new("Pages")
            .summary(format!("{pages}"))
            .lazy(page_list, (input, fmt)),
    );
    Ok(())
}

async fn header_fields(cx: Cx, (span, jet3): (Span, bool)) -> Result<()> {
    let data = cx.read(span).await?;
    // Offsets below are relative to the start of page 0.
    let at = |o: u64| span.sub(o.saturating_sub(0x18), 2);
    let u16_at = |o: u64| u16_le(&data, to_usize(o.saturating_sub(0x18))).unwrap_or(0);
    let (cp, collation) = if jet3 { (0x3a, 0x56) } else { (0x3c, 0x6e) };
    cx.emit(Node::new("Code page").span(at(cp)).value(Value::UInt {
        value: u16_at(cp).into(),
        bits: 16,
        radix: Radix::Dec,
    }));
    cx.emit(
        Node::new("Collation")
            .span(at(collation))
            .value(Value::UInt {
                value: u16_at(collation).into(),
                bits: 16,
                radix: Radix::Hex,
            }),
    );
    cx.emit(
        Node::new("Decrypted bytes")
            .span(span)
            .value(Value::Bytes(data.iter().take(32).copied().collect())),
    );
    Ok(())
}

/// MSysObjects' definition page.
const CATALOG_PAGE: u32 = 2;

const OBJECT_TYPES: EnumTable = &[
    (1, "table"),
    (2, "database"),
    (3, "container"),
    (4, "linked ODBC table"),
    (5, "query"),
    (6, "linked table"),
    (8, "relationship"),
    (0x8000, "form"),
    (0x8002, "report"),
    (0x8004, "macro"),
    (0x8007, "module"),
    (0x8008, "data access page"),
    (0x800b, "database document"),
];

/// Catalog flags that mark system and hidden objects.
const SYSTEM_FLAGS: i64 = 0x8000_0002;

/// A catalog row: the values that matter for the listing.
struct Object {
    id: i64,
    parent: i64,
    name: String,
    kind: i64,
    flags: i64,
    row: row::RowRef,
}

fn is_data_page_of(data: &[u8], tdef: u32) -> bool {
    data.first() == Some(&1) && u32_le(data, 4) == Some(tdef)
}

/// A row's bytes, following an overflow pointer (the row moved to another
/// page; the pointer is a row number and a page number).
async fn resolve_slot(
    cx: &Cx,
    file: Span,
    fmt: Fmt,
    page: Span,
    data: &[u8],
    slot: row::Slot,
) -> Result<(Span, Vec<u8>)> {
    let bytes = data.get(slot.start..slot.end).unwrap_or_default();
    if slot.raw & row::OVERFLOW != 0 {
        let target = u32_le(bytes, 0).unwrap_or(0);
        let (page, row) = pointer(target);
        let (span, bytes, _) = row::locate(cx, file, fmt, page, row).await?;
        return Ok((span, bytes));
    }
    let span = page.sub(
        to_u64(slot.start),
        to_u64(slot.end.saturating_sub(slot.start)),
    );
    Ok((span, bytes.to_vec()))
}

/// The pages to visit for a table's rows.
enum Pages {
    /// The pages its usage map lists.
    Listed(Vec<u32>),
    /// Every page after the header (the map could not be read).
    All(u32),
}

impl Pages {
    fn get(&self, i: usize) -> Option<u32> {
        match self {
            Pages::Listed(v) => v.get(i).copied(),
            Pages::All(n) => u32::try_from(i)
                .ok()
                .and_then(|i| i.checked_add(1))
                .filter(|p| p < n),
        }
    }

    fn len(&self) -> usize {
        match self {
            Pages::Listed(v) => v.len(),
            Pages::All(n) => usize::try_from(n.saturating_sub(1)).unwrap_or(usize::MAX),
        }
    }
}

/// The pages a table owns according to its usage map, or (if the map
/// cannot be read) every page, with the reason.
async fn table_pages(
    cx: &Cx,
    file: Span,
    fmt: Fmt,
    def: &tdef::TableDef,
) -> (Pages, Option<Diagnostic>) {
    match row::usage_map(cx, file, fmt, def.used_pages).await {
        Ok(pages) => (Pages::Listed(pages), None),
        Err(e) => {
            let total = u32::try_from(fmt.pages(file)).unwrap_or(u32::MAX);
            (
                Pages::All(total),
                Some(Diagnostic::warning(format!(
                    "usage map unreadable ({}); scanning every page",
                    e.message
                ))),
            )
        }
    }
}

/// The catalog: every MSysObjects row, tables expanding to their contents.
async fn catalog(cx: Cx, (input, fmt): (Input, Fmt)) -> Result<()> {
    let file = input.span;
    let def = tdef::load(&cx, file, fmt, CATALOG_PAGE).await?;
    let find = |name: &str| def.columns.iter().position(|c| c.name == name);
    let (Some(id), Some(parent), Some(name), Some(kind)) =
        (find("Id"), find("ParentId"), find("Name"), find("Type"))
    else {
        return Err(Diagnostic::malformed(
            "MSysObjects lacks the Id, ParentId, Name or Type column",
        )
        .at(def.span));
    };
    let flags = find("Flags");
    let (pages, problem) = table_pages(&cx, file, fmt, &def).await;
    if let Some(p) = problem {
        cx.diag(p);
    }
    let mut objects = Vec::new();
    let mut pi = 0usize;
    while let Some(page_no) = pages.get(pi) {
        pi = pi.saturating_add(1);
        let span = fmt.page_span(file, page_no);
        let data = cx.read(span).await?;
        if !is_data_page_of(&data, def.page) {
            continue;
        }
        for slot in row::slots(&data, fmt) {
            if slot.raw & row::DELETED != 0 {
                continue;
            }
            let Ok((rspan, bytes)) = resolve_slot(&cx, file, fmt, span, &data, slot).await else {
                continue;
            };
            let Ok(locs) = row::crack(&bytes, fmt, &def) else {
                continue;
            };
            let field = |i: usize| match (locs.get(i), def.columns.get(i)) {
                (Some(&row::Loc::Bytes(s, e)), Some(col)) => {
                    Some((col, bytes.get(s..e).unwrap_or_default()))
                }
                _ => None,
            };
            let int = |i: usize| -> i64 {
                match field(i).and_then(|(col, b)| row::value(col, b, fmt).value) {
                    Some(Value::Int { value, .. }) => value,
                    _ => 0,
                }
            };
            objects.push(Object {
                id: int(id),
                parent: int(parent),
                name: field(name).map_or_else(String::new, |(_, b)| row::text(b, fmt)),
                kind: int(kind),
                flags: flags.map_or(0, int),
                row: row::RowRef {
                    input,
                    fmt,
                    tdef: def.page,
                    span: rspan,
                },
            });
        }
    }
    let parents: std::collections::BTreeMap<i64, String> =
        objects.iter().map(|o| (o.id, o.name.clone())).collect();
    for o in &objects {
        // Type is a 16-bit signed column; the form/report codes are its
        // unsigned values.
        let kind = u64::from(o.kind.to_le_bytes().first().copied().unwrap_or(0))
            | u64::from(o.kind.to_le_bytes().get(1).copied().unwrap_or(0)).wrapping_shl(8);
        let kind_name = val::name_or(OBJECT_TYPES, kind, "type");
        let system = o.flags & SYSTEM_FLAGS != 0;
        let mut summary = kind_name.clone();
        if let Some(p) = parents.get(&o.parent) {
            summary = format!("{summary} in {p}");
        }
        let label = if o.name.is_empty() {
            format!("Object {}", o.id)
        } else {
            o.name.clone()
        };
        let mut node = Node::new(label).span(o.row.span);
        if o.kind == 1 {
            let page = u32::try_from(o.id & 0x00ff_ffff).unwrap_or(0);
            match tdef::load(&cx, file, fmt, page).await {
                Ok(t) => {
                    node = node
                        .summary(format!(
                            "{kind_name}, {}, {}{}",
                            ufmt::count(t.num_rows, "row", "rows"),
                            ufmt::count(to_u64(t.columns.len()), "column", "columns"),
                            if system { ", system" } else { "" }
                        ))
                        .lazy(table, (input, fmt, page));
                }
                Err(e) => node = node.summary(summary).diag(e),
            }
        } else {
            node = node.summary(summary).lazy(catalog_row, o.row);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// A catalog entry other than a table: its MSysObjects row.
async fn catalog_row(cx: Cx, r: row::RowRef) -> Result<()> {
    let def = tdef::load(&cx, r.input.span, r.fmt, r.tdef).await?;
    let bytes = cx.read(r.span).await?;
    cx.emit(row::row_node("Catalog row".to_owned(), &bytes, &def, r));
    Ok(())
}

async fn table(cx: Cx, (input, fmt, page): (Input, Fmt, u32)) -> Result<()> {
    let def = tdef::load(&cx, input.span, fmt, page).await?;
    cx.emit(
        Node::new("Definition")
            .span(def.span)
            .summary(format!("page {page}"))
            .lazy(tdef::definition, (input.span, fmt, page)),
    );
    cx.emit(
        Node::new("Rows")
            .summary(format!("{}", def.num_rows))
            .lazy(rows, (input, fmt, page)),
    );
    Ok(())
}

/// The rows of a table, page by page through its usage map.
async fn rows(cx: Cx, (input, fmt, page): (Input, Fmt, u32)) -> Result<()> {
    let file = input.span;
    let def: Arc<tdef::TableDef> = tdef::load(&cx, file, fmt, page).await?;
    let (pages, problem) = table_pages(&cx, file, fmt, &def).await;
    if let Some(p) = problem {
        cx.diag(p);
    }
    let (mut pi, mut ri, mut n) = cx.resume::<(usize, usize, u64)>().unwrap_or((0, 0, 0));
    while let Some(page_no) = pages.get(pi) {
        let span = fmt.page_span(file, page_no);
        let data = cx.read(span).await?;
        if is_data_page_of(&data, page) {
            let slots = row::slots(&data, fmt);
            while let Some(&slot) = slots.get(ri) {
                if slot.raw & row::DELETED != 0 {
                    ri = ri.saturating_add(1);
                    continue;
                }
                let at = (pi, ri, n);
                cx.mark(move || at);
                let node = match resolve_slot(&cx, file, fmt, span, &data, slot).await {
                    Ok((rspan, bytes)) => row::row_node(
                        format!("Row {n}"),
                        &bytes,
                        &def,
                        row::RowRef {
                            input,
                            fmt,
                            tdef: page,
                            span: rspan,
                        },
                    ),
                    Err(e) => Node::new(format!("Row {n}")).diag(e),
                };
                cx.push(node).await;
                n = n.saturating_add(1);
                ri = ri.saturating_add(1);
            }
        }
        pi = pi.saturating_add(1);
        ri = 0;
        cx.progress(to_u64(pi), to_u64(pages.len()));
    }
    Ok(())
}

/// The owner of long-value pages.
const LVAL: u32 = u32::from_le_bytes(*b"LVAL");

async fn page_list(cx: Cx, (input, fmt): (Input, Fmt)) -> Result<()> {
    let file = input.span;
    let pages = fmt.pages(file);
    cx.set_count(Count::Exact(pages));
    for no in 0..pages {
        let span = file.sub(no.saturating_mul(fmt.page), fmt.page);
        let head = cx.read_avail(span.sub(0, 16)).await?;
        let kind = head.first().copied().unwrap_or(0);
        let mut summary = lookup(PAGE_TYPES, kind.into())
            .unwrap_or("unknown")
            .to_owned();
        let owner = u32_le(&head, 4).unwrap_or(0);
        if kind == 1 {
            let rows = u16_le(&head, fmt.rows_at()).unwrap_or(0);
            let whose = match owner {
                LVAL => "long values".to_owned(),
                0 => "usage maps".to_owned(),
                t => format!("table definition at page {t}"),
            };
            summary = format!("{summary}, {}, {whose}", ufmt::count(rows, "row", "rows"));
        } else if kind == 2 && owner != 0 {
            summary = format!("{summary}, continues on page {owner}");
        }
        let mut node = Node::new(format!("Page {no}")).span(span).summary(summary);
        if kind == 1 && no > 0 {
            node = node.lazy(data_page, (span, fmt));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn data_page(cx: Cx, (span, fmt): (Span, Fmt)) -> Result<()> {
    let data = cx.read(span).await?;
    let rows_at = fmt.rows_at();
    cx.emit(
        Node::new("Free space")
            .span(span.sub(2, 2))
            .value(val::uint(u16_le(&data, 2).unwrap_or(0), 16)),
    );
    let owner = u32_le(&data, 4).unwrap_or(0);
    let mut node = Node::new("Owner")
        .span(span.sub(4, 4))
        .value(val::uint(owner, 32));
    node = match owner {
        LVAL => node.summary("long-value page"),
        0 => node.summary("usage maps"),
        t => node.summary(format!("table definition at page {t}")),
    };
    cx.emit(node);
    let slots = row::slots(&data, fmt);
    cx.emit(
        Node::new("Row count")
            .span(span.sub(to_u64(rows_at), 2))
            .value(val::uint(to_u64(slots.len()), 16)),
    );
    for (i, slot) in slots.iter().enumerate() {
        let row = span.sub(
            to_u64(slot.start),
            to_u64(slot.end.saturating_sub(slot.start)),
        );
        let entry = span.sub(
            to_u64(
                rows_at
                    .saturating_add(2)
                    .saturating_add(i.saturating_mul(2)),
            ),
            2,
        );
        let node = Node::new(format!("Row {i}"))
            .span(row)
            .target(entry)
            .value(Value::UInt {
                value: slot.raw.into(),
                bits: 16,
                radix: Radix::Hex,
            });
        let node = if slot.raw & row::OVERFLOW != 0 {
            node.summary("overflow pointer")
        } else if slot.raw & row::DELETED != 0 {
            node.summary("deleted")
        } else {
            node.summary(format!("{} bytes", row.len))
        };
        cx.push(node).await;
    }
    Ok(())
}
