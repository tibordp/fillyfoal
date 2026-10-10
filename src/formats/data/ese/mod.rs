//! Extensible Storage Engine (ESE, "JET Blue") databases: Windows Search,
//! SRUM, Exchange, Active Directory (`ntds.dit`), WebCache, catroot, ...
//!
//! Page 0 is the database header and page 1 its shadow copy; every other
//! page belongs to a B-tree of some object (table, index, long-value tree
//! or space tree), named by its object ID. The catalog (`MSysObjects`,
//! rooted at page 4) lists the tables with their columns, indexes and
//! long-value trees; records are decoded with those column definitions
//! (fixed, variable and tagged columns, multi-values and separated long
//! values). The page view shows every page's header, checksum and nodes.

mod page;
mod record;

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::datakit::{clip, hex, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag, lookup};

use page::{LeafWalk, Page, load};
use record::{COLUMN_FLAGS, COLUMN_TYPES, ColDef, TAGGED_FLAGS};

const LE: Endian = Endian::Little;
/// Root page of the catalog (`MSysObjects`).
const CATALOG_ROOT: u32 = 4;

fn ese_probe(h: &Head<'_>) -> bool {
    h.at(4, b"\xef\xcd\xab\x89")
}

declare_format!(pub ESE = "ese", "Extensible Storage Engine database", ["edb", "dat", "sdb", "dit"], "application/x-ese",
    Probe::Custom(ese_probe), ese);

const ESE_STATES: EnumTable = &[
    (1, "just created"),
    (2, "dirty shutdown"),
    (3, "clean shutdown"),
    (4, "being converted"),
    (5, "force detach"),
    (6, "incremental reseed in progress"),
    (7, "dirty and patched shutdown"),
    (8, "revert in progress"),
];

const FILE_TYPES: EnumTable = &[(0, "database"), (1, "streaming file")];

/// `JET_filetype*`, as in the newer file type field.
const JET_FILE_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "database"),
    (2, "streaming file"),
    (3, "log"),
    (4, "checkpoint"),
    (5, "temporary database"),
    (7, "flush map"),
];

const BACKUP_TYPES: EnumTable = &[
    (0, "normal"),
    (1, "OS snapshot"),
    (2, "snapshot"),
    (3, "surrogate"),
];

const TABLE_FLAGS: FlagTable = &[
    flag(0x1000_0000, "Derived"),
    flag(0x2000_0000, "Template"),
    flag(0x4000_0000, "FixedDDL"),
    flag(0x8000_0000, "System"),
    flag(0x0800_0000, "SystemDynamic"),
];

/// Index flags: `IDBFLAG` in the low half, `IDXFLAG` in the high half.
const INDEX_FLAGS: FlagTable = &[
    flag(0x0001, "Unique"),
    flag(0x0002, "AllowAllNulls"),
    flag(0x0004, "AllowFirstNull"),
    flag(0x0008, "AllowSomeNulls"),
    flag(0x0010, "NoNullSeg"),
    flag(0x0020, "Primary"),
    flag(0x0040, "LocaleSet"),
    flag(0x0080, "Multivalued"),
    flag(0x0100, "TemplateIndex"),
    flag(0x0200, "DerivedIndex"),
    flag(0x0400, "LocalizedText"),
    flag(0x0800, "SortNullsHigh"),
    flag(0x1000, "UnicodeFixupOn"),
    flag(0x2000, "CrossProduct"),
    flag(0x4000, "DisallowTruncation"),
    flag(0x8000, "NestedTable"),
    flag(0x1_0000, "ExtendedColumns"),
    flag(0x2_0000, "DotNetGuid"),
];

/// What we know about a database file.
pub struct Db {
    file: Span,
    page_size: u64,
    small: bool,
    /// Pages after the two header pages.
    pages: u32,
}

impl Db {
    /// Page `pgno` (1-based; pages 0 and -1 are the headers).
    fn page_span(&self, pgno: u32) -> Result<Span> {
        let at = u64::from(pgno)
            .checked_add(1)
            .and_then(|n| n.checked_mul(self.page_size))
            .ok_or_else(|| Diagnostic::malformed("page number out of range"))?;
        if pgno == 0 || pgno > self.pages {
            return Err(Diagnostic::malformed(format!(
                "page {pgno} is outside the file"
            )));
        }
        self.file.sub_exact(at, self.page_size)
    }
}

type D = Arc<Db>;

async fn ese(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x2ec)).await?;
    let page_size = match u32_le(&head, 0xec).unwrap_or(0) {
        0 => 4096,
        n => u64::from(n),
    };
    let valid = matches!(page_size, 2048 | 4096 | 8192 | 16384 | 32768);
    let page_size = if valid { page_size } else { 4096 };
    let pages = file
        .len
        .checked_div(page_size)
        .unwrap_or(0)
        .saturating_sub(2);
    let db: D = Arc::new(Db {
        file,
        page_size,
        small: page_size <= 8192,
        pages: u32::try_from(pages).unwrap_or(u32::MAX),
    });

    // The header and its shadow copy.
    let header_check = header_checksum(&cx, file).await;
    let mut header = Node::new("Database header")
        .span(file.sub(0, page_size))
        .lazy(header_fields, (file.sub(0, page_size), page_size));
    match header_check {
        Some((stored, computed)) if stored == computed => {
            header = header.summary("checksum valid");
        }
        Some((stored, computed)) => {
            header = header.diag(Diagnostic::warning(format!(
                "checksum {stored:#010x}, computed {computed:#010x}"
            )));
        }
        None => {}
    }
    if !valid {
        header = header.diag(Diagnostic::malformed(format!(
            "page size {:#x} is not one ESE uses; assuming 4 KiB",
            u32_le(&head, 0xec).unwrap_or(0)
        )));
    }
    cx.emit(header);
    let shadow_span = file.sub(page_size, page_size);
    if shadow_span.len > 0 {
        let a = cx.read_avail(file.sub(0, page_size)).await?;
        let b = cx.read_avail(shadow_span).await?;
        let mut shadow = Node::new("Shadow header")
            .span(shadow_span)
            .lazy(header_fields, (shadow_span, page_size));
        shadow = if a == b {
            shadow.summary("identical to the header")
        } else {
            shadow.summary("differs from the header")
        };
        cx.emit(shadow);
    }

    let state =
        lookup(ESE_STATES, u32_le(&head, 0x34).unwrap_or(0).into()).unwrap_or("unknown state");
    let mut summary = format!(
        "ESE database {:#x} update {}, {} KiB pages, {} pages, {state}",
        u32_le(&head, 8).unwrap_or(0),
        u32_le(&head, 0xe8).unwrap_or(0),
        page_size / 1024,
        db.pages
    );
    if pages > 0 {
        match catalog(&cx, &db).await {
            Ok(cat) => {
                let user: Vec<&str> = cat
                    .tables
                    .iter()
                    .filter(|t| !t.name.starts_with("MSys"))
                    .map(|t| t.name.as_str())
                    .collect();
                if !user.is_empty() {
                    summary.push_str(&format!(", tables {}", clip(&user.join(", "), 200)));
                }
                cx.emit(
                    Node::new("Catalog")
                        .summary(format!("{} tables", cat.tables.len()))
                        .desc("MSysObjects: the tables with their columns, indexes and long values")
                        .lazy(catalog_view, (db.clone(), cat.clone())),
                );
            }
            Err(e) => cx.emit(Node::new("Catalog").diag(e)),
        }
        cx.emit(
            Node::new("Pages")
                .span(file.tail(page_size.saturating_mul(2)))
                .summary(format!("{} pages", db.pages))
                .lazy(pages_view, db.clone()),
        );
    }
    cx.annotate(summary);
    Ok(())
}

/// (stored, computed) checksum of the header page: XOR of the dwords of
/// the first 4 KiB after the checksum, seeded.
async fn header_checksum(cx: &Cx, file: Span) -> Option<(u32, u32)> {
    if file.len < 4096 {
        return None;
    }
    let data = cx.read(file.sub(0, 4096)).await.ok()?;
    let stored = u32_le(&data, 0)?;
    Some((stored, page::xor32(data.get(4..)?, page::XOR_SEED)))
}

#[derive(Clone, Copy)]
enum H {
    U32(&'static str),
    I32(&'static str),
    U64(&'static str),
    Hex32(&'static str),
    Hex64(&'static str),
    Enum(&'static str, EnumTable),
    Time(&'static str),
    Lgpos(&'static str),
    Sign(&'static str),
    Backup(&'static str),
    Bytes(&'static str, u64),
}

/// `DBFILEHDR`, field by field.
const HEADER: &[H] = &[
    H::Hex32("Checksum"),
    H::Hex32("Signature"),
    H::Hex32("Format version"),
    H::Enum("File type (legacy attribute)", FILE_TYPES),
    H::U64("Database time"),
    H::Sign("Database signature"),
    H::Enum("Database state", ESE_STATES),
    H::Lgpos("Consistent position"),
    H::Time("Consistent time"),
    H::Time("Attach time"),
    H::Lgpos("Attach position"),
    H::Time("Detach time"),
    H::Lgpos("Detach position"),
    H::U32("Database ID"),
    H::Sign("Log signature"),
    H::Backup("Previous full backup"),
    H::Backup("Previous incremental backup"),
    H::Backup("Current full backup"),
    H::Hex32("Database flags"),
    H::U32("Last object ID"),
    H::U32("OS major version"),
    H::U32("OS minor version"),
    H::U32("OS build number"),
    H::U32("OS service pack"),
    H::U32("Format update (major)"),
    H::U32("Page size"),
    H::U32("Repair count"),
    H::Time("Repair time"),
    H::Bytes("SLV signature (obsolete)", 28),
    H::U64("Last scrub database time"),
    H::Time("Scrub time"),
    H::I32("Minimum required log generation"),
    H::I32("Maximum required log generation"),
    H::I32("Upgrade: Exchange 5.5 format pages"),
    H::I32("Upgrade: free pages"),
    H::I32("Upgrade: space map pages"),
    H::Backup("Current snapshot backup"),
    H::Hex32("Creation format version"),
    H::U32("Creation format update"),
    H::Time("Maximum log generation creation time"),
    H::Enum("Previous full backup type", BACKUP_TYPES),
    H::Enum("Previous incremental backup type", BACKUP_TYPES),
    H::U32("Repair count (old)"),
    H::U32("ECC fixes"),
    H::Time("Last ECC fix"),
    H::U32("ECC fixes (old)"),
    H::U32("ECC fix failures"),
    H::Time("Last ECC fix failure"),
    H::U32("ECC fix failures (old)"),
    H::U32("Bad checksums"),
    H::Time("Last bad checksum"),
    H::U32("Bad checksums (old)"),
    H::I32("Maximum committed log generation"),
    H::Backup("Previous copy backup"),
    H::Backup("Previous differential backup"),
    H::Enum("Previous copy backup type", BACKUP_TYPES),
    H::Enum("Previous differential backup type", BACKUP_TYPES),
    H::U32("Incremental reseeds"),
    H::Time("Last incremental reseed"),
    H::U32("Incremental reseeds (old)"),
    H::U32("Pages patched"),
    H::Time("Last page patch"),
    H::U32("Pages patched (old)"),
    H::Hex64("Sort version"),
    H::Time("Previous database scan"),
    H::Time("Database scan start"),
    H::U32("Database scan: highest continuous page"),
    H::I32("Recovering log generation"),
    H::U32("Extend count"),
    H::Time("Last extend"),
    H::U32("Shrink count"),
    H::Time("Last shrink"),
    H::Time("Last reattach"),
    H::Lgpos("Last reattach position"),
    H::U32("Trim count"),
    H::Sign("Header flush signature"),
    H::Sign("Flush map flush signature"),
    H::I32("Minimum consistent log generation"),
    H::U32("Format update (minor)"),
    H::Hex32("Highest engine format version attached"),
    H::U32("Database scan: highest page"),
    H::Lgpos("Last resize position"),
    H::Bytes("Reserved", 3),
    H::Enum("File type", JET_FILE_TYPES),
    H::Bytes("Reserved", 1),
    H::Time("Maximum required log generation time"),
    H::I32("Pre-redo minimum consistent log generation"),
    H::I32("Pre-redo minimum required log generation"),
    H::Sign("Revert snapshot flush signature"),
    H::U32("Revert count"),
    H::Time("Reverted from"),
    H::Time("Reverted to"),
    H::U32("Reverted pages"),
    H::Lgpos("Last commit before revert"),
];

/// A `LOGTIME`: seconds, minutes, hours, day, month, year - 1900, then
/// UTC flag and milliseconds.
fn logtime(b: &[u8]) -> Option<(Value, String)> {
    let g = |i: usize| b.get(i).copied().unwrap_or(0);
    if b.iter().all(|&x| x == 0) {
        return Some((Value::Text("not set".into()), String::new()));
    }
    let (sec, min, hour, day, month, year) = (g(0), g(1), g(2), g(3), g(4), g(5));
    let utc = g(6) & 1 != 0;
    let ms = u16::from(g(6) >> 1) | (u16::from(g(7) >> 1 & 7) << 7);
    if month == 0 || month > 12 || day == 0 || day > 31 {
        return None;
    }
    let unix = crate::formats::disk::civil_to_unix(
        1900i64.saturating_add(year.into()),
        month.into(),
        day.into(),
        hour.into(),
        min.into(),
        sec.into(),
    );
    Some((
        Value::Timestamp { unix_seconds: unix },
        format!("{ms} ms{}", if utc { "" } else { ", local time" }),
    ))
}

fn lgpos(b: &[u8]) -> String {
    format!(
        "generation {}, sector {}, byte {}",
        u32_le(b, 4).unwrap_or(0),
        u16_le(b, 2).unwrap_or(0),
        u16_le(b, 0).unwrap_or(0)
    )
}

fn time_node(name: impl Into<std::borrow::Cow<'static, str>>, span: Span, b: &[u8]) -> Node {
    let node = Node::new(name).span(span);
    match logtime(b) {
        Some((v, s)) if s.is_empty() => node.value(v),
        Some((v, s)) => node.value(v).summary(s),
        None => node
            .value(Value::Bytes(b.to_vec()))
            .diag(Diagnostic::malformed("invalid LOGTIME")),
    }
}

async fn header_fields(cx: Cx, (span, page_size): (Span, u64)) -> Result<()> {
    let block = cx.block(span.sub(0, 0x2ec)).await?;
    let b = &block.data;
    let mut f = Fields::emitting(&cx, &block, LE);
    for h in HEADER {
        let at = usize::try_from(f.pos()).unwrap_or(usize::MAX);
        let field = |n: usize| b.get(at..at.saturating_add(n));
        match *h {
            H::U32(n) => {
                f.u32(n).emit()?;
            }
            H::I32(n) => {
                f.i32(n).emit()?;
            }
            H::U64(n) => {
                f.u64(n).emit()?;
            }
            H::Hex32(n) => {
                f.u32(n).hex().emit()?;
            }
            H::Hex64(n) => {
                f.u64(n).hex().emit()?;
            }
            H::Enum(n, t) => {
                f.u32(n).enumeration(t).emit()?;
            }
            H::Bytes(n, len) => {
                f.bytes(n, len).emit()?;
            }
            H::Time(n) => {
                let Some(raw) = field(8) else { break };
                cx.emit(time_node(n, f.peek_span(8), raw));
                f.skip(8);
            }
            H::Lgpos(n) => {
                let Some(raw) = field(8) else { break };
                cx.emit(
                    Node::new(n)
                        .span(f.peek_span(8))
                        .value(Value::Text(lgpos(raw))),
                );
                f.skip(8);
            }
            H::Sign(n) => {
                let Some(raw) = field(28) else { break };
                let created = logtime(raw.get(4..12).unwrap_or_default());
                let name = crate::text::latin1(raw.get(12..28).unwrap_or_default());
                let name = name.trim_end_matches('\0');
                let mut node = Node::new(n)
                    .span(f.peek_span(28))
                    .value(hex(u32_le(raw, 0).unwrap_or(0), 32))
                    .desc("Random number, creation time and computer name");
                let mut parts = Vec::new();
                if let Some((v @ Value::Timestamp { .. }, _)) = &created {
                    parts.push(format!("created {}", crate::render::value(v)));
                }
                if !name.is_empty() {
                    parts.push(format!("on {name:?}"));
                }
                if !parts.is_empty() {
                    node = node.summary(parts.join(" "));
                }
                cx.emit(node);
                f.skip(28);
            }
            H::Backup(n) => {
                let Some(raw) = field(24) else { break };
                let node = Node::new(n).span(f.peek_span(24));
                cx.emit(if raw.iter().all(|&x| x == 0) {
                    node.value(Value::Text("none".into()))
                } else {
                    node.value(Value::Text(format!(
                        "generations {}–{}",
                        u32_le(raw, 16).unwrap_or(0),
                        u32_le(raw, 20).unwrap_or(0)
                    )))
                    .summary(lgpos(raw.get(..8).unwrap_or_default()))
                });
                f.skip(24);
            }
        }
    }
    if span.len > 0x2ec {
        cx.emit(
            Node::new("Unused")
                .span(span.sub(0x2ec, page_size.saturating_sub(0x2ec)))
                .desc("Rest of the header page"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The catalog

/// Where a catalog entry is: (page, tag).
type At = (u32, usize);

#[derive(Clone)]
struct Column {
    def: ColDef,
    at: At,
}

#[derive(Clone)]
struct Index {
    name: String,
    objid: u32,
    fdp: u32,
    flags: u32,
    /// (column ID, descending)
    key: Vec<(u32, bool)>,
    at: At,
}

#[derive(Clone)]
struct Table {
    name: String,
    objid: u32,
    fdp: u32,
    flags: u32,
    pages: u32,
    columns: Vec<Column>,
    indexes: Vec<Index>,
    /// Long-value tree: (object ID, FDP, catalog entry).
    lv: Option<(u32, u32, At)>,
    at: At,
}

impl Table {
    fn column(&self, id: u32) -> Option<&ColDef> {
        self.columns.iter().find(|c| c.def.id == id).map(|c| &c.def)
    }
}

struct Catalog {
    tables: Vec<Table>,
    defs: Vec<ColDef>,
}

impl Catalog {
    fn object_name(&self, objid: u32) -> Option<String> {
        for t in &self.tables {
            if t.objid == objid {
                return Some(t.name.clone());
            }
            if let Some(i) = t
                .indexes
                .iter()
                .find(|i| i.objid == objid && i.objid != t.objid)
            {
                return Some(format!("{} index {}", t.name, i.name));
            }
            if t.lv.is_some_and(|(o, _, _)| o == objid) {
                return Some(format!("{} long values", t.name));
            }
        }
        None
    }
}

type C = Arc<Catalog>;

/// Reads the catalog (once per database).
async fn catalog(cx: &Cx, db: &Db) -> Result<C> {
    if let Some(c) = cx.cached::<Catalog>(db.file, "ese-catalog") {
        return Ok(c);
    }
    let defs = record::catalog_columns();
    let mut tables: Vec<Table> = Vec::new();
    let mut walk = LeafWalk::start(cx, db, CATALOG_ROOT).await?;
    while let Some(page) = walk.next(cx, db).await? {
        for i in 1..page.tags.len() {
            cx.checkpoint().await;
            let Some(n) = page.node(i) else { continue };
            if n.flags & 2 != 0 {
                continue;
            }
            let rec = page.node_data(&n);
            let d = record::decode(rec, db.small, |id| defs.iter().find(|c| c.id == id));
            let get = |id: u32| -> Option<&[u8]> {
                let v = d.values.iter().find(|v| v.id == id && !v.null)?;
                rec.get(v.at..v.at.saturating_add(v.len))
            };
            let int = |id: u32| get(id).and_then(|b| u32_le(b, 0)).unwrap_or(0);
            let kind = get(2).and_then(|b| u16_le(b, 0)).unwrap_or(0);
            let name = get(128).map(|b| record::text(1252, b)).unwrap_or_default();
            let at = (page.pgno, i);
            match kind {
                1 => tables.push(Table {
                    name,
                    objid: int(1),
                    fdp: int(4),
                    flags: int(6),
                    pages: int(7),
                    columns: Vec::new(),
                    indexes: Vec::new(),
                    lv: None,
                    at,
                }),
                2 => {
                    if let Some(t) = tables.last_mut().filter(|t| t.objid == int(1)) {
                        t.columns.push(Column {
                            def: ColDef {
                                id: int(3),
                                name,
                                coltyp: int(4),
                                cbmax: int(5),
                                codepage: int(7),
                                flags: int(6),
                            },
                            at,
                        });
                    }
                }
                3 => {
                    let flags = int(6);
                    let fields = get(132).unwrap_or_default();
                    let key = if flags & 0x1_0000 != 0 {
                        fields
                            .as_chunks::<4>()
                            .0
                            .iter()
                            .map(|c| {
                                let v = u32::from_le_bytes(*c);
                                (v >> 16, v & 0x40 != 0)
                            })
                            .collect()
                    } else {
                        fields
                            .as_chunks::<2>()
                            .0
                            .iter()
                            .map(|c| {
                                let v = i16::from_le_bytes(*c);
                                (u32::from(v.unsigned_abs()), v < 0)
                            })
                            .collect()
                    };
                    if let Some(t) = tables.last_mut().filter(|t| t.objid == int(1)) {
                        t.indexes.push(Index {
                            name,
                            objid: int(3),
                            fdp: int(4),
                            flags,
                            key,
                            at,
                        });
                    }
                }
                4 => {
                    if let Some(t) = tables.last_mut().filter(|t| t.objid == int(1)) {
                        t.lv = Some((int(3), int(4), at));
                    }
                }
                _ => {}
            }
        }
    }
    let cat = Arc::new(Catalog { tables, defs });
    cx.cache(db.file, "ese-catalog", cat.clone());
    Ok(cat)
}

fn key_text(t: &Table, key: &[(u32, bool)]) -> String {
    key.iter()
        .map(|&(id, desc)| {
            let name = t
                .column(id)
                .map_or_else(|| format!("column {id}"), |c| c.name.clone());
            format!("{}{name}", if desc { "-" } else { "+" })
        })
        .collect::<Vec<_>>()
        .join(" ")
}

fn column_kind(id: u32) -> &'static str {
    match id {
        0..=127 => "fixed",
        128..=255 => "variable",
        _ => "tagged",
    }
}

fn column_summary(def: &ColDef) -> String {
    let mut s = format!(
        "id {}, {}, {}",
        def.id,
        column_kind(def.id),
        lookup(COLUMN_TYPES, def.coltyp.into()).unwrap_or("unknown type")
    );
    if matches!(def.coltyp, 10 | 12) {
        s.push_str(match def.codepage {
            1200 => " (UTF-16)",
            1252 => " (Windows-1252)",
            20127 => " (ASCII)",
            _ => "",
        });
    }
    if matches!(def.coltyp, 9 | 10) && def.cbmax > 0 {
        s.push_str(&format!(", max {} bytes", def.cbmax));
    }
    let (set, _) = decode_flags(COLUMN_FLAGS, def.flags.into());
    if !set.is_empty() {
        s.push_str(&format!(", {}", set.join(" | ")));
    }
    s
}

async fn catalog_view(cx: Cx, (db, cat): (D, C)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(cat.tables.len())));
    for (i, t) in cat.tables.iter().enumerate() {
        let mut summary = format!(
            "object {}, root page {}, {} columns, {} indexes",
            t.objid,
            t.fdp,
            t.columns.len(),
            t.indexes.len()
        );
        if let Some((_, fdp, _)) = t.lv {
            summary.push_str(&format!(", long values at page {fdp}"));
        }
        cx.push(
            Node::new(t.name.clone())
                .value(Value::Flags {
                    raw: t.flags.into(),
                    bits: 32,
                    set: decode_flags(TABLE_FLAGS, t.flags.into()).0,
                    unknown: decode_flags(TABLE_FLAGS, t.flags.into()).1,
                })
                .summary(summary)
                .lazy(table_view, (db.clone(), cat.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn table_view(cx: Cx, (db, cat, ti): (D, C, usize)) -> Result<()> {
    let Some(t) = cat.tables.get(ti) else {
        return Ok(());
    };
    cx.emit(entry_node(&cx, &db, &cat, "Catalog entry", t.at).await);
    cx.emit(
        Node::new("Columns")
            .value(uint(to_u64(t.columns.len()), 32))
            .lazy(columns_view, (db.clone(), cat.clone(), ti)),
    );
    if !t.indexes.is_empty() {
        cx.emit(
            Node::new("Indexes")
                .value(uint(to_u64(t.indexes.len()), 32))
                .lazy(indexes_view, (db.clone(), cat.clone(), ti)),
        );
    }
    if let Some((objid, fdp, at)) = t.lv {
        cx.emit(
            Node::new("Long values")
                .summary(format!("object {objid}, root page {fdp}"))
                .lazy(lv_view, (db.clone(), cat.clone(), ti, at)),
        );
    }
    cx.emit(
        Node::new("Records")
            .summary(format!("B-tree rooted at page {}", t.fdp))
            .lazy(records_view, (db.clone(), cat.clone(), ti)),
    );
    cx.emit(
        Node::new("Space")
            .summary(format!("{} pages requested at creation", t.pages))
            .lazy(space_view, (db.clone(), t.fdp)),
    );
    Ok(())
}

/// A catalog record, decoded, as a lazy node.
async fn entry_node(cx: &Cx, db: &D, cat: &C, name: &'static str, at: At) -> Node {
    let node = Node::new(name);
    match load(cx, db, at.0).await {
        Ok(page) => {
            let Some(n) = page.node(at.1) else {
                return node.diag(Diagnostic::malformed("catalog entry missing"));
            };
            let span = page::span_in(db, &page, n.data_at, n.data_len);
            node.span(span)
                .lazy(record_fields, (db.clone(), cat.clone(), None, at))
        }
        Err(e) => node.diag(e),
    }
}

async fn columns_view(cx: Cx, (db, cat, ti): (D, C, usize)) -> Result<()> {
    let Some(t) = cat.tables.get(ti) else {
        return Ok(());
    };
    for c in &t.columns {
        cx.checkpoint().await;
        let mut node = entry_node(&cx, &db, &cat, "", c.at).await;
        node.name = c.def.name.clone().into();
        cx.emit(
            node.value(Value::Enum {
                raw: c.def.coltyp.into(),
                bits: 32,
                name: lookup(COLUMN_TYPES, c.def.coltyp.into()),
            })
            .summary(column_summary(&c.def)),
        );
    }
    Ok(())
}

async fn indexes_view(cx: Cx, (db, cat, ti): (D, C, usize)) -> Result<()> {
    let Some(t) = cat.tables.get(ti) else {
        return Ok(());
    };
    for (i, ix) in t.indexes.iter().enumerate() {
        cx.checkpoint().await;
        let (set, _) = decode_flags(INDEX_FLAGS, ix.flags.into());
        let mut node = entry_node(&cx, &db, &cat, "", ix.at).await;
        node.name = ix.name.clone().into();
        let primary = ix.fdp == t.fdp;
        cx.emit(
            node.value(Value::Text(key_text(t, &ix.key)))
                .summary(format!(
                    "{}object {}, root page {}, {}",
                    if primary { "primary (clustered), " } else { "" },
                    ix.objid,
                    ix.fdp,
                    set.join(" | ")
                )),
        );
        if !primary {
            cx.emit(
                Node::new(format!("{} entries", ix.name))
                    .summary(format!("index B-tree at page {}", ix.fdp))
                    .lazy(index_entries, (db.clone(), cat.clone(), ti, i)),
            );
        }
    }
    Ok(())
}

/// The entries of a secondary index: normalized key, then the primary key.
async fn index_entries(cx: Cx, (db, cat, ti, ii): (D, C, usize, usize)) -> Result<()> {
    let Some(ix) = cat.tables.get(ti).and_then(|t| t.indexes.get(ii)) else {
        return Ok(());
    };
    let mut walk = LeafWalk::start(&cx, &db, ix.fdp).await?;
    let mut n = 0u64;
    while let Some(page) = walk.next(&cx, &db).await? {
        for i in 1..page.tags.len() {
            let Some(node) = page.node(i) else { continue };
            let data = page.node_data(&node);
            let span = page::span_in(
                &db,
                &page,
                page.tags.get(i).map_or(0, |t| t.at),
                page.tags.get(i).map_or(0, |t| t.size),
            );
            cx.push(
                Node::new(format!("Entry {n}"))
                    .span(span)
                    .value(Value::Bytes(node.key.clone()))
                    .summary(format!(
                        "primary key {}{}",
                        crate::formats::util::datakit::hex_string(data),
                        if node.flags & 2 != 0 { ", deleted" } else { "" }
                    )),
            )
            .await;
            n = n.saturating_add(1);
        }
    }
    Ok(())
}

/// The long values of a table: a header node (reference count, size) per
/// long-value ID, followed by its chunks.
async fn lv_view(cx: Cx, (db, cat, ti, at): (D, C, usize, At)) -> Result<()> {
    let Some(t) = cat.tables.get(ti) else {
        return Ok(());
    };
    let Some((_, fdp, _)) = t.lv else {
        return Ok(());
    };
    cx.emit(entry_node(&cx, &db, &cat, "Catalog entry", at).await);
    let mut walk = LeafWalk::start(&cx, &db, fdp).await?;
    let mut current: Option<(Vec<u8>, Node, Vec<Node>)> = None;
    while let Some(page) = walk.next(&cx, &db).await? {
        for i in 1..page.tags.len() {
            cx.checkpoint().await;
            let Some(node) = page.node(i) else { continue };
            let data = page.node_data(&node);
            let span = page::span_in(&db, &page, node.data_at, node.data_len);
            let key = node.key.clone();
            if matches!(key.len(), 4 | 8) {
                if let Some((_, head, chunks)) = current.take() {
                    cx.push(head.lazy(crate::formats::util::arcutil::emit_nodes, Arc::new(chunks)))
                        .await;
                }
                let lid = crate::formats::util::datakit::be_uint(&key);
                let refs = u32_le(data, 0).unwrap_or(0);
                let size = u32_le(data, 4).unwrap_or(0);
                let head = Node::new(format!("LID {lid:#x}"))
                    .span(span)
                    .value(uint(size, 32))
                    .summary(format!("{size} bytes, {refs} references"));
                current = Some((key, head, Vec::new()));
            } else if let Some((lid, _, chunks)) = current.as_mut()
                && key.starts_with(lid.as_slice())
            {
                let offset = crate::formats::util::datakit::be_uint(
                    key.get(lid.len()..).unwrap_or_default(),
                );
                chunks.push(
                    Node::new(format!("Chunk at {offset:#x}"))
                        .span(span)
                        .summary(format!("{} bytes, page {}", data.len(), page.pgno)),
                );
            }
        }
    }
    if let Some((_, head, chunks)) = current.take() {
        cx.push(head.lazy(crate::formats::util::arcutil::emit_nodes, Arc::new(chunks)))
            .await;
    }
    Ok(())
}

/// Records of a table, in primary key order, paged; marks record the leaf
/// page and node to resume from.
async fn records_view(cx: Cx, (db, cat, ti): (D, C, usize)) -> Result<()> {
    let Some(t) = cat.tables.get(ti) else {
        return Ok(());
    };
    let mut walk = LeafWalk::start(&cx, &db, t.fdp).await?;
    let (resume_page, mut first_tag, mut n) = cx
        .resume::<(u32, usize, u64)>()
        .map_or((None, 1, 0), |(p, i, n)| (Some(p), i, n));
    if let Some(p) = resume_page {
        walk.next = Some(p);
    }
    while let Some(page) = walk.next(&cx, &db).await? {
        for i in first_tag..page.tags.len() {
            let pgno = page.pgno;
            cx.mark(move || (pgno, i, n));
            let Some(node) = page.node(i) else { continue };
            let rec = page.node_data(&node);
            let span = page::span_in(&db, &page, node.data_at, node.data_len);
            let summary = if cx.skipping() {
                String::new()
            } else {
                record_summary(&db, t, rec)
            };
            let mut item = Node::new(format!("Record {n}"))
                .span(span)
                .summary(summary)
                .lazy(
                    record_fields,
                    (db.clone(), cat.clone(), Some(ti), (pgno, i)),
                );
            if node.flags & 2 != 0 {
                item = item.desc("Deleted (flagged for cleanup)");
            }
            cx.push(item).await;
            n = n.saturating_add(1);
        }
        first_tag = 1;
    }
    Ok(())
}

/// The first few column values of a record.
fn record_summary(db: &Db, t: &Table, rec: &[u8]) -> String {
    let d = record::decode(rec, db.small, |id| t.column(id));
    let mut parts = Vec::new();
    for v in &d.values {
        if parts.len() >= 4 {
            parts.push("…".to_owned());
            break;
        }
        let Some(def) = t.column(v.id) else { continue };
        if v.null || v.header.is_some_and(|h| h & 0x0d != 0) {
            continue;
        }
        let b = rec
            .get(v.at..v.at.saturating_add(v.len))
            .unwrap_or_default();
        let shown = crate::render::value(&record::value(def, b));
        parts.push(format!("{}={}", def.name, clip(&shown, 40)));
    }
    parts.join(", ")
}

/// The fields of a record (a catalog entry when `table` is `None`).
async fn record_fields(cx: Cx, (db, cat, table, at): (D, C, Option<usize>, At)) -> Result<()> {
    let page = load(&cx, &db, at.0).await?;
    let node = page
        .node(at.1)
        .ok_or_else(|| Diagnostic::malformed("node out of range"))?;
    let rec = page.node_data(&node);
    let t = table.and_then(|i| cat.tables.get(i));
    let def = |id: u32| match t {
        Some(t) => t.column(id),
        None => cat.defs.iter().find(|c| c.id == id),
    };
    let span = |o: usize, l: usize| page::span_in(&db, &page, node.data_at.saturating_add(o), l);
    let d = record::decode(rec, db.small, def);
    cx.emit(
        Node::new("Record header")
            .span(span(0, 4))
            .value(Value::Text(format!(
                "fixed 1–{}, variable 128–{}",
                d.last_fixed, d.last_var
            )))
            .summary(format!("fixed data ends at {:#x}", d.end_fixed)),
    );
    if let Some((o, l)) = d.nullmap {
        cx.emit(
            Node::new("Null bitmap")
                .span(span(o, l))
                .value(Value::Bytes(
                    rec.get(o..o.saturating_add(l)).unwrap_or_default().to_vec(),
                ))
                .desc("One bit per fixed column, set when it is null"),
        );
    }
    if let Some((o, l)) = d.var_offsets {
        let offsets: Vec<String> = rec
            .get(o..o.saturating_add(l))
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| {
                let v = u16::from_le_bytes(*c);
                if v & 0x8000 != 0 {
                    format!("{:#x} (null)", v & 0x7fff)
                } else {
                    format!("{v:#x}")
                }
            })
            .collect();
        cx.emit(
            Node::new("Variable offsets")
                .span(span(o, l))
                .value(Value::Text(offsets.join(" ")))
                .desc("End offset of each variable column; bit 15 marks it null"),
        );
    }
    if let Some((o, l)) = d.tag_array {
        let entries: Vec<String> = rec
            .get(o..o.saturating_add(l))
            .unwrap_or_default()
            .as_chunks::<4>()
            .0
            .iter()
            .map(|c| {
                format!(
                    "{}@{:#x}",
                    u16_le(c, 0).unwrap_or(0),
                    u16_le(c, 2).unwrap_or(0)
                )
            })
            .collect();
        cx.emit(
            Node::new("Tagged field array")
                .span(span(o, l))
                .value(Value::Text(entries.join(" ")))
                .desc("Column ID and offset (with flag bits) of each tagged column"),
        );
    }
    for v in &d.values {
        cx.checkpoint().await;
        let b = rec
            .get(v.at..v.at.saturating_add(v.len))
            .unwrap_or_default();
        let name = def(v.id).map_or_else(|| format!("Column {}", v.id), |c| c.name.clone());
        let vspan = span(v.at, v.len);
        let full = match v.header {
            Some(_) => span(v.at.saturating_sub(1), v.len.saturating_add(1)),
            None => vspan,
        };
        let mut n = Node::new(name).span(full);
        if v.null {
            let kind = match v.kind {
                record::Kind::Fixed => "fixed",
                record::Kind::Variable => "variable",
                record::Kind::Tagged => "tagged",
            };
            cx.emit(n.value(Value::Text("null".into())).summary(kind));
            continue;
        }
        if v.derived {
            n = n.desc("Derived from a template table's column");
        }
        let Some(c) = def(v.id) else {
            cx.emit(
                n.value(Value::Bytes(b.to_vec()))
                    .diag(Diagnostic::warning("column not in the catalog")),
            );
            continue;
        };
        let header = v.header.unwrap_or(0);
        let tname = lookup(COLUMN_TYPES, c.coltyp.into()).unwrap_or("?");
        if header & 0x08 != 0 {
            // Multi-valued.
            let parts = record::multi_values(b, header);
            let mut children = vec![header_node(span(v.at.saturating_sub(1), 1), header)];
            let mut shown = Vec::new();
            for (k, (o, l, separated)) in parts.iter().enumerate() {
                let piece = b.get(*o..o.saturating_add(*l)).unwrap_or_default();
                let val = record::value(c, piece);
                shown.push(match &val {
                    Value::Text(t) => clip(t, 40),
                    other => clip(&crate::render::value(other), 40),
                });
                let mut child = Node::new(format!("Value {k}"))
                    .span(span(v.at.saturating_add(*o), *l))
                    .value(val);
                if *separated {
                    child = child.summary("separated (long value ID)");
                }
                children.push(child);
            }
            n = n
                .value(Value::Text(shown.join(" | ")))
                .summary(format!("{tname}, {} values", parts.len()))
                .lazy(
                    crate::formats::util::arcutil::emit_nodes,
                    Arc::new(children),
                );
        } else if header & 0x04 != 0 {
            // Separated: the value lives in the long-value tree.
            n = long_value(
                &cx,
                &db,
                t,
                c,
                b,
                header,
                span(v.at.saturating_sub(1), 1),
                vspan,
            )
            .await
            .span(full);
        } else if header & 0x02 != 0 {
            n = n
                .value(Value::Bytes(b.get(..32).unwrap_or(b).to_vec()))
                .summary(format!("{tname}, compressed, {} bytes", b.len()))
                .diag(Diagnostic::unsupported(
                    "compressed column value (7-bit or Xpress)",
                ));
        } else {
            let mut s = format!("{tname}, {} bytes", b.len());
            if v.header.is_some() && header != 0 {
                let (set, _) = decode_flags(TAGGED_FLAGS, header.into());
                s.push_str(&format!(" [{}]", set.join(" | ")));
            }
            n = n.value(record::value(c, b)).summary(s);
        }
        cx.emit(n);
    }
    if let Some(p) = d.problem {
        cx.diag(Diagnostic::malformed(p));
    }
    Ok(())
}

fn header_node(span: Span, header: u8) -> Node {
    let (set, unknown) = decode_flags(TAGGED_FLAGS, header.into());
    Node::new("Tagged value header")
        .span(span)
        .value(Value::Flags {
            raw: header.into(),
            bits: 8,
            set,
            unknown,
        })
}

/// A separated long value: looked up by its ID in the table's long-value
/// tree, its chunks gathered into one source.
#[allow(clippy::too_many_arguments)]
async fn long_value(
    cx: &Cx,
    db: &D,
    t: Option<&Table>,
    c: &ColDef,
    b: &[u8],
    header: u8,
    header_span: Span,
    vspan: Span,
) -> Node {
    let tname = lookup(COLUMN_TYPES, c.coltyp.into()).unwrap_or("?");
    let node = Node::new(c.name.clone());
    let Some((lid, key)) = record::lid(b) else {
        return node.diag(Diagnostic::malformed("bad long value ID"));
    };
    let mut children = vec![
        header_node(header_span, header),
        Node::new("Long value ID").span(vspan).value(hex(lid, 64)),
    ];
    let Some(fdp) = t.and_then(|t| t.lv).map(|(_, fdp, _)| fdp) else {
        return node
            .value(hex(lid, 64))
            .summary(format!("{tname}, separated"))
            .diag(Diagnostic::malformed("table has no long-value tree"));
    };
    match gather(cx, db, fdp, &key).await {
        Ok((size, pieces, chunks)) => {
            let total: u64 = pieces.iter().map(|p| p.len).sum();
            let mut node = node.summary(format!(
                "{tname}, long value {lid:#x}, {size} bytes in {chunks} chunks"
            ));
            if total != u64::from(size) {
                children.push(
                    Node::new("Data").diag(Diagnostic::unsupported("compressed long value chunks")),
                );
                return node.value(hex(lid, 64)).lazy(
                    crate::formats::util::arcutil::emit_nodes,
                    Arc::new(children),
                );
            }
            match cx.add_pieces(
                Origin {
                    parent: vspan,
                    transform: "ese-long-value",
                },
                pieces,
            ) {
                Ok(data) => {
                    let preview = cx.read_avail(data.sub(0, 0x1000)).await.unwrap_or_default();
                    let value = record::value(c, &preview);
                    let value = match value {
                        Value::Text(s) => Value::Text(clip(&s, 200)),
                        other => other,
                    };
                    node = node.value(value.clone());
                    children.push(Node::new("Data").span(data).value(value));
                }
                Err(e) => children.push(Node::new("Data").diag(e)),
            }
            node.lazy(
                crate::formats::util::arcutil::emit_nodes,
                Arc::new(children),
            )
        }
        Err(e) => node
            .value(hex(lid, 64))
            .summary(format!("{tname}, separated long value {lid:#x}"))
            .diag(e),
    }
}

/// Size, chunk spans and chunk count of the long value with key `key`.
async fn gather(cx: &Cx, db: &Db, root: u32, key: &[u8]) -> Result<(u32, Vec<Span>, u64)> {
    let Some((mut page, mut i)) = page::seek(cx, db, root, key).await? else {
        return Err(Diagnostic::malformed("long value not found"));
    };
    let head = page
        .node(i)
        .filter(|n| n.key == key)
        .ok_or_else(|| Diagnostic::malformed("long value not found"))?;
    let size = u32_le(page.node_data(&head), 4).unwrap_or(0);
    let mut pieces = Vec::new();
    let mut chunks = 0u64;
    let mut steps = 0u32;
    i = i.saturating_add(1);
    loop {
        steps = steps.saturating_add(1);
        if steps > db.pages.saturating_add(1) {
            break;
        }
        cx.checkpoint().await;
        if i >= page.tags.len() {
            if page.next == 0 {
                break;
            }
            page = load(cx, db, page.next).await?;
            i = 1;
            continue;
        }
        let Some(n) = page.node(i) else { break };
        if !n.key.starts_with(key) || n.key.len() <= key.len() {
            break;
        }
        pieces.push(page::span_in(db, &page, n.data_at, n.data_len));
        chunks = chunks.saturating_add(1);
        i = i.saturating_add(1);
    }
    Ok((size, pieces, chunks))
}

/// The owned and available extents of the object rooted at `fdp`.
async fn space_view(cx: Cx, (db, fdp): (D, u32)) -> Result<()> {
    let root = load(&cx, &db, fdp).await?;
    let head = root.tag_bytes(0);
    let fields = if head.len() == 25 {
        head.get(1..)
    } else {
        Some(head)
    };
    let flags = fields.and_then(|f| u32_le(f, 8)).unwrap_or(0);
    let oe = fields.and_then(|f| u32_le(f, 12)).unwrap_or(0);
    if flags & 1 == 0 {
        cx.emit(
            Node::new("Single extent")
                .value(hex(oe, 32))
                .summary("bitmap of available pages in the primary extent"),
        );
        return Ok(());
    }
    for (name, pgno) in [
        ("Owned extents", oe),
        ("Available extents", oe.saturating_add(1)),
    ] {
        let mut list = Vec::new();
        let mut total = 0u64;
        match LeafWalk::start(&cx, &db, pgno).await {
            Ok(mut walk) => {
                while let Some(page) = walk.next(&cx, &db).await? {
                    for i in 1..page.tags.len() {
                        cx.checkpoint().await;
                        let Some(n) = page.node(i) else { continue };
                        let last = crate::formats::util::datakit::be_uint(&n.key);
                        let count = u64::from(u32_le(page.node_data(&n), 0).unwrap_or(0));
                        total = total.saturating_add(count);
                        let first = last.saturating_add(1).saturating_sub(count);
                        let tag = page.tags.get(i).copied();
                        list.push(
                            Node::new(format!("Pages {first}–{last}"))
                                .span(page::span_in(
                                    &db,
                                    &page,
                                    tag.map_or(0, |t| t.at),
                                    tag.map_or(0, |t| t.size),
                                ))
                                .value(uint(count, 32)),
                        );
                    }
                }
                cx.emit(
                    Node::new(name)
                        .summary(format!(
                            "{total} pages in {} extents, tree at page {pgno}",
                            list.len()
                        ))
                        .lazy(crate::formats::util::arcutil::emit_nodes, Arc::new(list)),
                );
            }
            Err(e) => cx.emit(Node::new(name).diag(e)),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The page view

record! {
    pub struct PageHeader {
        checksum: u64 "Checksum" .hex(),
        dbtime: u64 "Database time" .desc("When the page was last modified"),
        prev: u32 "Previous page",
        next: u32 "Next page",
        objid: u32 "Object ID" .desc("The B-tree (table, index, long values, space tree) the page belongs to"),
        cb_free: u16 "Free bytes",
        cb_uncommitted: u16 "Uncommitted free bytes",
        mic_free: u16 "First free byte" .hex() .desc("Offset of the first unused byte after the header"),
        itag: u16 "Tags" .desc("Number of tags (low 12 bits)"),
        flags: u32 "Flags" .flags(page::PAGE_FLAGS),
    }
}

async fn pages_view(cx: Cx, db: D) -> Result<()> {
    let cat = catalog(&cx, &db).await.ok();
    cx.set_count(Count::Exact(db.pages.into()));
    let start = cx.resume::<u32>().unwrap_or(1);
    for pgno in start..=db.pages {
        cx.mark(move || pgno);
        let span = db.page_span(pgno)?;
        let page = load(&cx, &db, pgno).await?;
        let mut node = Node::new(format!("Page {pgno}")).span(span);
        if page.data.iter().all(|&b| b == 0) {
            cx.push(node.summary("unused (zero)")).await;
            continue;
        }
        let owner = cat
            .as_ref()
            .and_then(|c| c.object_name(page.objid))
            .unwrap_or_else(|| format!("object {}", page.objid));
        let kind = if page.flags & page::SPACE_TREE != 0 {
            "space tree"
        } else if page.flags & page::LONG_VALUE != 0 {
            "long values"
        } else if page.flags & page::INDEX != 0 {
            "index"
        } else {
            "data"
        };
        let level = match (page.is_root(), page.is_leaf()) {
            (true, true) => "root leaf",
            (true, false) => "root",
            (false, true) => "leaf",
            (false, false) => "branch",
        };
        node = node.summary(format!("{owner}, {kind} {level}, {} nodes", page.nodes()));
        let c = page::check(&page);
        charge_check(&cx, &page).await;
        if let Some(computed) = c.computed
            && computed != c.stored
        {
            node = node.diag(Diagnostic::warning(format!(
                "{} checksum {:#x}, computed {computed:#x}",
                c.scheme, c.stored
            )));
        }
        cx.push(node.lazy(page_view, (db.clone(), pgno))).await;
    }
    Ok(())
}

/// Charges the work of verifying a page's checksum (a few operations per
/// bit for the ECC).
async fn charge_check(cx: &Cx, page: &Page) {
    crate::formats::util::pace::Pace::new(cx, crate::formats::util::pace::STEPS_PER_UNIT)
        .add(to_u64(page.data.len()).saturating_mul(8))
        .await;
}

async fn page_view(cx: Cx, (db, pgno): (D, u32)) -> Result<()> {
    let span = db.page_span(pgno)?;
    let page = load(&cx, &db, pgno).await?;
    let mut header = PageHeader::node("Header", span.sub(0, PageHeader::SIZE), LE);
    let c = page::check(&page);
    charge_check(&cx, &page).await;
    header = match c.computed {
        Some(x) if x == c.stored => header.summary(format!("{} checksum valid", c.scheme)),
        Some(x) => header.diag(Diagnostic::warning(format!(
            "{} checksum {:#x}, computed {x:#x}",
            c.scheme, c.stored
        ))),
        None => header.summary(c.scheme),
    };
    cx.emit(header);
    if !page.small {
        let block = cx.block(span.sub(40, 40)).await?;
        let mut f = Fields::emitting(&cx, &block, LE);
        f.u64("Checksum (block 2)").hex().emit()?;
        f.u64("Checksum (block 3)").hex().emit()?;
        f.u64("Checksum (block 4)").hex().emit()?;
        f.u32("Page number").emit()?;
        f.bytes("Reserved", 12).emit()?;
    }
    let t0 = page.tags.first().copied();
    if let Some(t0) = t0 {
        let tspan = span.sub(to_u64(t0.at), to_u64(t0.size));
        let b = page.tag_bytes(0);
        cx.emit(external_header(&page, tspan, b));
    }
    for i in 1..page.tags.len() {
        cx.checkpoint().await;
        let Some(tag) = page.tags.get(i).copied() else {
            break;
        };
        let tspan = span.sub(to_u64(tag.at), to_u64(tag.size));
        let Some(n) = page.node(i) else {
            cx.emit(
                Node::new(format!("Node {i}"))
                    .span(tspan)
                    .diag(Diagnostic::malformed("bad node")),
            );
            continue;
        };
        let data = page.node_data(&n);
        let mut summary = if page.is_leaf() {
            if page.flags & page::SPACE_TREE != 0 {
                let last = crate::formats::util::datakit::be_uint(&n.key);
                let count = u64::from(u32_le(data, 0).unwrap_or(0));
                format!(
                    "pages {}–{last}",
                    last.saturating_add(1).saturating_sub(count)
                )
            } else {
                format!("{} bytes of data", data.len())
            }
        } else {
            format!("child page {}", u32_le(data, 0).unwrap_or(0))
        };
        if n.prefix_len > 0 {
            summary.push_str(&format!(
                ", key shares {} bytes with the prefix",
                n.prefix_len
            ));
        }
        let (set, _) = decode_flags(page::NODE_FLAGS, n.flags.into());
        let set: Vec<&str> = set.into_iter().filter(|s| *s != "CompressedKey").collect();
        if !set.is_empty() {
            summary.push_str(&format!(" [{}]", set.join(" | ")));
        }
        let mut node = Node::new(format!("Node {i}"))
            .span(tspan)
            .value(if n.key.is_empty() {
                Value::Text(String::new())
            } else {
                Value::Bytes(n.key.clone())
            })
            .summary(summary);
        if !page.is_leaf()
            && let Some(child) = u32_le(data, 0)
            && let Ok(cs) = db.page_span(child)
        {
            node = node.target(cs);
        }
        cx.emit(node);
    }
    let count = page.tags.len();
    let array = span.tail(span.len.saturating_sub(to_u64(count).saturating_mul(4)));
    cx.emit(
        Node::new("Tag array")
            .span(array)
            .value(Value::Text(format!("{count} tags")))
            .desc("Size and offset (and flags) of each node, from the end of the page backwards"),
    );
    let free_at = to_u64(page.header_len).saturating_add(page.mic_free.into());
    if free_at < array.offset.saturating_sub(span.offset) {
        cx.emit(
            Node::new("Free space")
                .span(
                    span.sub(
                        free_at,
                        array
                            .offset
                            .saturating_sub(span.offset)
                            .saturating_sub(free_at),
                    ),
                )
                .summary(format!("{} bytes free in all", page.cb_free)),
        );
    }
    Ok(())
}

/// Tag 0: the root page's space header, or the key prefix shared by the
/// page's nodes.
fn external_header(page: &Page, span: Span, b: &[u8]) -> Node {
    if page.is_root() && page.flags & page::SPACE_TREE == 0 && matches!(b.len(), 16 | 25) {
        let f = if b.len() == 25 {
            b.get(1..).unwrap_or_default()
        } else {
            b
        };
        let pages = u32_le(f, 0).unwrap_or(0);
        let parent = u32_le(f, 4).unwrap_or(0);
        let flags = u32_le(f, 8).unwrap_or(0);
        let oe = u32_le(f, 12).unwrap_or(0);
        let summary = if flags & 1 != 0 {
            format!(
                "{pages} primary pages, parent page {parent}, space trees at pages {oe} and {}",
                oe.saturating_add(1)
            )
        } else {
            format!(
                "{pages} primary pages, parent page {parent}, single extent (available pages {oe:#x})"
            )
        };
        let mut children = Vec::new();
        let mut at = 0u64;
        if b.len() == 25 {
            children.push(
                Node::new("Header version")
                    .span(span.sub(0, 1))
                    .value(uint(b.first().copied().unwrap_or(0), 8)),
            );
            at = 1;
        }
        let extent = if flags & 1 != 0 {
            "multiple extents"
        } else {
            "single extent"
        };
        for (name, v, h, s) in [
            ("Primary pages", pages, false, ""),
            ("Parent page", parent, false, ""),
            ("Flags", flags, true, extent),
            (
                if flags & 1 != 0 {
                    "Owned extent tree page"
                } else {
                    "Available pages bitmap"
                },
                oe,
                flags & 1 == 0,
                "",
            ),
        ] {
            let mut n = Node::new(name).span(span.sub(at, 4)).value(if h {
                hex(v, 32)
            } else {
                uint(v, 32)
            });
            if !s.is_empty() {
                n = n.summary(s);
            }
            children.push(n);
            at = at.saturating_add(4);
        }
        if b.len() == 25 {
            children.push(
                Node::new("Extension")
                    .span(span.sub(at, 8))
                    .value(Value::Bytes(b.get(17..25).unwrap_or_default().to_vec())),
            );
        }
        return Node::new("Space header").span(span).summary(summary).lazy(
            crate::formats::util::arcutil::emit_nodes,
            Arc::new(children),
        );
    }
    let name = if page.is_root() {
        "External header"
    } else {
        "Key prefix"
    };
    Node::new(name).span(span).value(Value::Bytes(b.to_vec()))
}
