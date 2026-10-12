//! MySQL 8's serialized dictionary information (SDI): the definitions of
//! a tablespace's tables, kept as zlib-compressed JSON in a B-tree of the
//! tablespace (`ibd2sdi` prints them). The definitions give each index's
//! fields in record order, which is what splits records into columns.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use super::index::{self, Slot};
use super::page::{self, BLOB, LOB_FIRST, SDI_BLOB};
use super::{FIL_NULL, SpaceRef};
use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::clip;
use crate::formats::util::json::{self, Json};
use crate::formats::util::val::{text, uint};
use crate::formats::{Input, content};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{Radix, Value};

/// SDI records read for the dictionary.
const MAX_OBJECTS: usize = 4096;
/// Pages of the SDI B-tree visited.
const MAX_SDI_PAGES: usize = 4096;
/// Decompressed JSON bytes parsed, over all objects.
const MAX_JSON_BYTES: u64 = 32 << 20;
/// Pages of one off-page value followed.
pub const MAX_CHAIN: usize = 1 << 16;

/// A column type as the dictionary gives it, reduced to what decoding a
/// stored value needs.
#[derive(Clone, Debug)]
pub enum Ty {
    Int {
        unsigned: bool,
    },
    Float,
    Double,
    Decimal {
        precision: u32,
        scale: u32,
    },
    Date,
    Time {
        fsp: u32,
    },
    DateTime {
        fsp: u32,
    },
    Timestamp {
        fsp: u32,
    },
    Year,
    Text,
    Binary,
    Enum(Arc<Vec<String>>),
    Set(Arc<Vec<String>>),
    Bit,
    Json,
    TrxId,
    RollPtr,
    RowId,
    /// Bytes of unknown type (a compressed page's own field description):
    /// text if they read as text.
    Raw,
}

#[derive(Clone, Debug)]
pub struct Field {
    pub name: String,
    pub ty: Ty,
    pub nullable: bool,
    /// Stored length if fixed; `None` for variable-length fields.
    pub fixed: Option<u64>,
    /// A variable-length field whose length may take two bytes (longer
    /// than 255 bytes, or a BLOB type).
    pub big: bool,
    /// Added by the storage engine: row ID, transaction ID, roll pointer.
    pub hidden: bool,
    /// Part of the index's key as declared (not a column the index merely
    /// carries, like a clustered index's other columns or a secondary
    /// index's primary key).
    pub key: bool,
}

#[derive(Debug)]
pub struct IndexDef {
    pub id: u64,
    pub name: String,
    pub table: String,
    pub root: u32,
    pub fields: Vec<Field>,
    /// Fields that identify a record in node pointers.
    pub n_uniq: usize,
    /// The table was altered with instant ADD COLUMN before MySQL 8.0.29
    /// (records may carry a field count), so the field list cannot be
    /// relied on.
    pub instant: bool,
    /// MySQL 8.0.29+ row versions (instant ADD or DROP COLUMN): for each
    /// field, the version that added it and the one that dropped it (0:
    /// never), with `fields` in physical order and including dropped
    /// columns. Empty for an index without versions.
    pub versions: Vec<(u32, u32)>,
}

#[derive(Default)]
pub struct Dict {
    pub objects: u64,
    pub space_name: Option<String>,
    /// Object names by (type, ID).
    pub names: BTreeMap<(u32, u64), String>,
    pub indexes: BTreeMap<u64, Arc<IndexDef>>,
    pub problems: Vec<Diagnostic>,
}

impl Dict {
    pub fn index(&self, id: u64) -> Option<&Arc<IndexDef>> {
        self.indexes.get(&id)
    }
}

fn int(name: &str, bytes: u64) -> Field {
    Field {
        name: name.to_owned(),
        ty: Ty::Int { unsigned: true },
        nullable: false,
        fixed: Some(bytes),
        big: false,
        hidden: false,
        key: false,
    }
}

/// The SDI index's own layout: (type, id) key, transaction ID, roll
/// pointer, both lengths and the compressed JSON.
pub fn sdi_def() -> Arc<IndexDef> {
    let mut trx = int("DB_TRX_ID", 6);
    trx.ty = Ty::TrxId;
    trx.hidden = true;
    let mut roll = int("DB_ROLL_PTR", 7);
    roll.ty = Ty::RollPtr;
    roll.hidden = true;
    Arc::new(IndexDef {
        id: 0,
        name: "SDI".to_owned(),
        table: "SDI".to_owned(),
        root: 0,
        fields: vec![
            int("Type", 4),
            int("ID", 8),
            trx,
            roll,
            int("Uncompressed length", 4),
            int("Compressed length", 4),
            Field {
                name: "Data".to_owned(),
                ty: Ty::Binary,
                nullable: false,
                fixed: None,
                big: true,
                hidden: false,
                key: false,
            },
        ],
        n_uniq: 2,
        instant: false,
        versions: Vec::new(),
    })
}

const SDI_TYPES: &[(u64, &str)] = &[(1, "table"), (2, "tablespace")];

/// One SDI record: its key and where its compressed JSON is.
#[derive(Clone)]
pub struct SdiObject {
    pub kind: u32,
    pub id: u64,
    pub ulen: u32,
    pub clen: u32,
    /// The record's page and origin, and the bytes the origin is in (the
    /// page, or a compressed page rebuilt).
    pub page: u32,
    pub origin: u64,
    pub page_span: Span,
    pub data: Span,
}

/// The dictionary of a tablespace, decoded once.
pub async fn load(cx: &Cx, space: &SpaceRef) -> Arc<Dict> {
    let key = space.input.span;
    if let Some(d) = cx.cached::<Dict>(key, "innodb-dict") {
        return d;
    }
    let d = Arc::new(build(cx, space).await);
    cx.cache(key, "innodb-dict", d.clone());
    d
}

/// The SDI records, in key order, walking the leaf level from the
/// leftmost leaf.
pub async fn objects(cx: &Cx, space: &SpaceRef) -> (Vec<SdiObject>, Vec<Diagnostic>) {
    let mut out = Vec::new();
    let mut problems = Vec::new();
    let Some(root) = space.sdi_root else {
        return (out, problems);
    };
    let def = sdi_def();
    let mut visited = BTreeSet::new();
    let mut no = root;
    // Down the leftmost path.
    loop {
        if !visited.insert(no) || visited.len() > MAX_SDI_PAGES {
            problems.push(Diagnostic::malformed("SDI B-tree loops"));
            return (out, problems);
        }
        let p = match index::record_page(cx, space, no).await {
            Ok((_, p)) => p,
            Err(e) => {
                problems.push(e);
                return (out, problems);
            }
        };
        let level = u16_be(&p, 64).unwrap_or(0);
        if level == 0 {
            break;
        }
        let first = index::user_records(&p).into_iter().next();
        let child = first.and_then(|o| index::parse(&p, o, Some(&def), false).child);
        match child {
            Some((_, c)) => no = c,
            None => {
                problems.push(Diagnostic::malformed("SDI node page without records"));
                return (out, problems);
            }
        }
    }
    visited.clear();
    while no != FIL_NULL {
        if !visited.insert(no) || visited.len() > MAX_SDI_PAGES || out.len() >= MAX_OBJECTS {
            break;
        }
        let Ok((span, p)) = index::record_page(cx, space, no).await else {
            break;
        };
        cx.charge(to_u64(p.len()) / 1024).await;
        for origin in index::user_records(&p) {
            let rec = index::parse(&p, origin, Some(&def), true);
            let get = |i: usize| -> Option<&Slot> { rec.fields.get(i) };
            let num = |i: usize| {
                get(i).and_then(|s| {
                    let b = p.get(to_usize(s.off)..to_usize(s.off.saturating_add(s.len)))?;
                    b.iter()
                        .try_fold(0u64, |a, &x| a.checked_mul(256)?.checked_add(x.into()))
                })
            };
            let Some(data) = get(6) else {
                continue;
            };
            let data_span = if data.external {
                match external_span(cx, space, span, data).await {
                    Ok(s) => s,
                    Err(e) => {
                        problems.push(e);
                        continue;
                    }
                }
            } else {
                span.sub(data.off, data.len)
            };
            out.push(SdiObject {
                kind: u32::try_from(num(0).unwrap_or(0)).unwrap_or(0),
                id: num(1).unwrap_or(0),
                ulen: u32::try_from(num(4).unwrap_or(0)).unwrap_or(0),
                clen: u32::try_from(num(5).unwrap_or(0)).unwrap_or(0),
                page: no,
                origin,
                page_span: span,
                data: data_span,
            });
        }
        no = u32_be(&p, 12).unwrap_or(FIL_NULL);
    }
    (out, problems)
}

/// The whole value of an externally stored field: its local prefix and the
/// pages the 20-byte reference at its end leads to, as one piecewise span.
pub async fn external_span(cx: &Cx, space: &SpaceRef, page: Span, slot: &Slot) -> Result<Span> {
    let local = slot.len.saturating_sub(20);
    let refb = cx
        .read(page.sub(slot.off.saturating_add(local), 20))
        .await?;
    let first = u32_be(&refb, 4).unwrap_or(FIL_NULL);
    let total = u64_be(&refb, 12).unwrap_or(0) & 0x3fff_ffff_ffff_ffff;
    let mut pieces = Vec::new();
    if local != 0 {
        pieces.push(page.sub(slot.off, local));
    }
    let mut got = 0u64;
    let mut visited = BTreeSet::new();
    let head = match space.page(first) {
        Some(s) => cx.read(s.sub(0, 100)).await?,
        None => {
            return Err(Diagnostic::malformed(format!(
                "off-page value at page {first}, past the end"
            )));
        }
    };
    let head_kind = u16_be(&head, 24).unwrap_or(0);
    if head_kind == ZBLOB || head_kind == ZSDI_BLOB {
        let at = (first, u32_be(&refb, 8).unwrap_or(0), head_kind);
        return zblob(cx, space, page.sub(slot.off, slot.len), at, total).await;
    }
    if matches!(head_kind, 25..=29) {
        return Err(Diagnostic::unsupported(
            "compressed LOB pages (MySQL 8 compressed tables)",
        ));
    }
    if head_kind == LOB_FIRST {
        lob_pieces(cx, space, first, total, &mut pieces).await?;
    } else {
        let mut no = first;
        while no != FIL_NULL && got < total {
            if !visited.insert(no) || visited.len() > MAX_CHAIN {
                return Err(Diagnostic::malformed("off-page value chain loops"));
            }
            let Some(s) = space.page(no) else {
                return Err(Diagnostic::malformed(format!(
                    "off-page value at page {no}, past the end"
                )));
            };
            let h = cx.read(s.sub(0, 46)).await?;
            let kind = u16_be(&h, 24).unwrap_or(0);
            if kind != BLOB && kind != SDI_BLOB {
                return Err(Diagnostic::malformed(format!(
                    "page {no} is not a BLOB page"
                )));
            }
            let part = u64::from(u32_be(&h, 38).unwrap_or(0))
                .min(s.len.saturating_sub(46).saturating_sub(space.geo.trailer()));
            pieces.push(s.sub(46, part));
            got = got.saturating_add(part);
            no = u32_be(&h, 42).unwrap_or(FIL_NULL);
        }
    }
    if pieces.is_empty() {
        return Ok(Span::zeros(0));
    }
    cx.add_pieces(
        Origin {
            parent: page.sub(slot.off, slot.len),
            transform: "innodb-off-page",
        },
        pieces,
    )
}

/// Compressed BLOB page types: the first page and the later ones, and
/// MySQL 8's for the SDI (all pages).
const ZBLOB: u16 = 11;
const ZBLOB2: u16 = 12;
const ZSDI_BLOB: u16 = 19;

/// An off-page value of a compressed table (`btr_copy_zblob_prefix`): one
/// zlib stream over a chain of pages, each holding the next page's number
/// in its FIL header and stream bytes from the end of the FIL header (the
/// first page from the reference's offset). MySQL 8 writes the SDI's
/// long values the same way with a page type of their own. `start` is
/// the first page, the reference's offset and the first page's type.
async fn zblob(
    cx: &Cx,
    space: &SpaceRef,
    field: Span,
    start: (u32, u32, u16),
    total: u64,
) -> Result<Span> {
    let mut pieces = Vec::new();
    let mut visited = BTreeSet::new();
    let (mut no, mut at, mut kind) = (start.0, u64::from(start.1), start.2);
    while no != FIL_NULL {
        if !visited.insert(no) || visited.len() > MAX_CHAIN {
            return Err(Diagnostic::malformed("off-page value chain loops"));
        }
        let Some(s) = space.page(no) else {
            return Err(Diagnostic::malformed(format!(
                "off-page value at page {no}, past the end"
            )));
        };
        let h = cx.read(s.sub(0, 46)).await?;
        if u16_be(&h, 24) != Some(kind) {
            return Err(Diagnostic::malformed(format!(
                "page {no} is not a compressed BLOB page"
            )));
        }
        let next = u32_be(&h, to_usize(at)).unwrap_or(FIL_NULL);
        let start = if at == 12 { 38 } else { at.saturating_add(4) };
        pieces.push(s.sub(start, s.len.saturating_sub(start)));
        if kind == ZBLOB {
            kind = ZBLOB2;
        }
        (no, at) = (next, 12);
    }
    let stream = cx.add_pieces(
        Origin {
            parent: field,
            transform: "innodb-off-page",
        },
        pieces,
    )?;
    let decoded = crate::codec::decode_span(cx, stream, &Codec::Zlib, Some(total)).await?;
    Ok(decoded.span)
}

/// MySQL 8 LOBs: the first page's index entries, each naming a page and
/// how much of the value it holds.
async fn lob_pieces(
    cx: &Cx,
    space: &SpaceRef,
    first: u32,
    total: u64,
    pieces: &mut Vec<Span>,
) -> Result<()> {
    let Some(fspan) = space.page(first) else {
        return Ok(());
    };
    let fp = cx.read(fspan).await?;
    // The index list's first entry.
    let mut at = (
        u32_be(&fp, 68).unwrap_or(FIL_NULL),
        u16_be(&fp, 72).unwrap_or(0),
    );
    let mut got = 0u64;
    let mut visited = BTreeSet::new();
    while at.0 != FIL_NULL && got < total {
        if !visited.insert(at) || visited.len() > MAX_CHAIN {
            return Err(Diagnostic::malformed("LOB index list loops"));
        }
        let Some(espan) = space.page(at.0) else {
            break;
        };
        let e = cx.read(espan.sub(at.1.into(), 60)).await?;
        let no = u32_be(&e, 48).unwrap_or(FIL_NULL);
        let len = u64::from(u16_be(&e, 52).unwrap_or(0));
        let Some(dspan) = space.page(no) else {
            break;
        };
        let data_at = if no == first { 696 } else { 49 };
        let room = dspan
            .len
            .saturating_sub(data_at)
            .saturating_sub(space.geo.trailer());
        let take = len.min(room);
        pieces.push(dspan.sub(data_at, take));
        got = got.saturating_add(take);
        at = (
            u32_be(&e, 6).unwrap_or(FIL_NULL),
            u16_be(&e, 10).unwrap_or(0),
        );
    }
    Ok(())
}

async fn build(cx: &Cx, space: &SpaceRef) -> Dict {
    let (objects, mut problems) = objects(cx, space).await;
    let mut dict = Dict {
        objects: to_u64(objects.len()),
        ..Dict::default()
    };
    let mut budget = MAX_JSON_BYTES;
    for o in &objects {
        if u64::from(o.ulen) > budget {
            problems.push(Diagnostic::limit(
                "dictionary larger than the decoding limit",
            ));
            break;
        }
        budget = budget.saturating_sub(o.ulen.into());
        let Some(json) = decode(cx, o).await else {
            problems.push(Diagnostic::malformed(format!(
                "SDI object {} does not decode",
                o.id
            )));
            continue;
        };
        let Some(dd) = json.get("dd_object") else {
            continue;
        };
        if let Some(name) = dd.get("name").and_then(Json::as_str) {
            let name = match dd.get("schema_ref").and_then(Json::as_str) {
                Some(s) => format!("{s}.{name}"),
                None => name.to_owned(),
            };
            dict.names.insert((o.kind, o.id), name);
        }
        match o.kind {
            2 => {
                if let Some(name) = dd.get("name").and_then(Json::as_str) {
                    dict.space_name = Some(name.to_owned());
                }
            }
            1 => {
                for def in table_indexes(dd) {
                    dict.indexes.insert(def.id, Arc::new(def));
                }
            }
            _ => {}
        }
    }
    dict.problems = problems;
    dict
}

/// The JSON of one SDI object.
async fn decode(cx: &Cx, o: &SdiObject) -> Option<Json> {
    let decoded = crate::codec::decode_span(cx, o.data, &Codec::Zlib, Some(o.ulen.into()))
        .await
        .ok()?;
    if decoded.error.is_some() {
        return None;
    }
    let bytes = cx.read(decoded.span).await.ok()?;
    json::parse(cx, &bytes).await.ok()
}

/// `key=value;` pairs of `se_private_data`.
fn private(s: &str, key: &str) -> Option<u64> {
    s.split(';')
        .filter_map(|kv| kv.split_once('='))
        .find(|(k, _)| *k == key)
        .and_then(|(_, v)| v.parse().ok())
}

fn num(j: &Json, key: &str) -> u64 {
    j.get(key).and_then(Json::as_u64).unwrap_or(0)
}

fn flag(j: &Json, key: &str) -> bool {
    matches!(j.get(key), Some(Json::Bool(true)))
}

/// Bytes per maximum character of a collation (single-byte, UCS-2 and
/// UTF-32 ones give fixed-length CHAR columns).
fn mbmaxlen(collation: u64) -> Option<(u64, u64)> {
    Some(match collation {
        63 => (1, 1),
        1..=11
        | 14..=18
        | 20..=23
        | 25..=27
        | 29
        | 31
        | 32
        | 34
        | 36..=44
        | 47..=53
        | 57..=59
        | 64..=75
        | 77
        | 79..=82
        | 89
        | 92..=94
        | 99 => (1, 1),
        35 | 90 | 128..=151 => (2, 2),
        60 | 61 | 160..=183 => (4, 4),
        33 | 76 | 83 | 192..=215 | 223 => (1, 3),
        45 | 46 | 224..=247 | 255..=323 => (1, 4),
        _ => return None,
    })
}

/// Bytes of a packed decimal.
fn decimal_bytes(precision: u32, scale: u32) -> u64 {
    const DIG2BYTES: [u64; 10] = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4];
    let intg = precision.saturating_sub(scale);
    let part = |digits: u32| {
        u64::from(digits / 9).saturating_mul(4).saturating_add(
            DIG2BYTES
                .get(to_usize((digits % 9).into()))
                .copied()
                .unwrap_or(0),
        )
    };
    part(intg).saturating_add(part(scale))
}

/// The field a column gives, or `None` for a type this decoder does not
/// know the storage of.
fn column_field(
    c: &Json,
    prefix: Option<u64>,
    hidden_element: bool,
    dropped: bool,
) -> Option<Field> {
    let name = c
        .get("name")
        .and_then(Json::as_str)
        .unwrap_or("?")
        .to_owned();
    let ty = num(c, "type");
    let unsigned = flag(c, "is_unsigned");
    let char_len = num(c, "char_length");
    let fsp = u32::try_from(num(c, "datetime_precision")).unwrap_or(0);
    let frac = u64::from(fsp.saturating_add(1) / 2);
    // Dropped columns are hidden from the server but keep their types.
    let hidden_se = num(c, "hidden") == 2 && !dropped;
    let elements = || {
        Arc::new(
            c.get("elements")
                .and_then(Json::as_array)
                .unwrap_or_default()
                .iter()
                .map(|e| {
                    e.get("name")
                        .and_then(Json::as_str)
                        .map(|s| {
                            let d = crate::formats::text::decode::base64(s.as_bytes());
                            String::from_utf8(d.bytes).unwrap_or_else(|_| s.to_owned())
                        })
                        .unwrap_or_default()
                })
                .collect::<Vec<_>>(),
        )
    };
    let fixed = |ty: Ty, n: u64| (ty, Some(n), false);
    let var = |ty: Ty, big: bool| (ty, None, big);
    let (ty, fixed, big) = if hidden_se {
        let t = match name.as_str() {
            "DB_TRX_ID" => Ty::TrxId,
            "DB_ROLL_PTR" => Ty::RollPtr,
            "DB_ROW_ID" => Ty::RowId,
            _ => Ty::Binary,
        };
        fixed(t, char_len)
    } else {
        match ty {
            2 => fixed(Ty::Int { unsigned }, 1),
            3 => fixed(Ty::Int { unsigned }, 2),
            10 => fixed(Ty::Int { unsigned }, 3),
            4 => fixed(Ty::Int { unsigned }, 4),
            9 => fixed(Ty::Int { unsigned }, 8),
            5 => fixed(Ty::Float, 4),
            6 => fixed(Ty::Double, 8),
            14 => fixed(Ty::Year, 1),
            11 | 15 => fixed(Ty::Date, 3),
            18 => fixed(Ty::Timestamp { fsp }, 4u64.saturating_add(frac)),
            19 => fixed(Ty::DateTime { fsp }, 5u64.saturating_add(frac)),
            20 => fixed(Ty::Time { fsp }, 3u64.saturating_add(frac)),
            21 => {
                let p = u32::try_from(num(c, "numeric_precision")).unwrap_or(0);
                let s = u32::try_from(num(c, "numeric_scale")).unwrap_or(0);
                fixed(
                    Ty::Decimal {
                        precision: p,
                        scale: s,
                    },
                    decimal_bytes(p, s),
                )
            }
            17 => fixed(Ty::Bit, num(c, "numeric_precision").saturating_add(7) / 8),
            22 => {
                let e = elements();
                let n = if e.len() > 255 { 2 } else { 1 };
                fixed(Ty::Enum(e), n)
            }
            23 => {
                let e = elements();
                let n = match to_u64(e.len()).saturating_add(7) / 8 {
                    0 | 1 => 1,
                    2 => 2,
                    3 => 3,
                    4 => 4,
                    _ => 8,
                };
                fixed(Ty::Set(e), n)
            }
            16 | 28 => {
                let binary = num(c, "collation_id") == 63;
                let len = prefix.unwrap_or(char_len);
                var(if binary { Ty::Binary } else { Ty::Text }, len > 255)
            }
            29 => {
                let collation = num(c, "collation_id");
                let t = if collation == 63 {
                    Ty::Binary
                } else {
                    Ty::Text
                };
                match mbmaxlen(collation) {
                    Some((min, max)) if min == max => fixed(t, prefix.unwrap_or(char_len)),
                    Some(_) => var(t, prefix.unwrap_or(char_len) > 255),
                    None => return None,
                }
            }
            24..=27 => var(
                if num(c, "collation_id") == 63 {
                    Ty::Binary
                } else {
                    Ty::Text
                },
                true,
            ),
            30 | 32 => var(Ty::Binary, true),
            31 => var(Ty::Json, true),
            _ => return None,
        }
    };
    Some(Field {
        name,
        ty,
        nullable: flag(c, "is_nullable"),
        fixed,
        big,
        hidden: hidden_se,
        key: !hidden_element,
    })
}

/// The index definitions of one table object.
fn table_indexes(dd: &Json) -> Vec<IndexDef> {
    let mut out = Vec::new();
    let table = dd.get("name").and_then(Json::as_str).unwrap_or("?");
    let schema = dd.get("schema_ref").and_then(Json::as_str);
    let table = match schema {
        Some(s) => format!("{s}.{table}"),
        None => table.to_owned(),
    };
    let columns = dd
        .get("columns")
        .and_then(Json::as_array)
        .unwrap_or_default();
    let table_private = dd
        .get("se_private_data")
        .and_then(Json::as_str)
        .unwrap_or("");
    let instant = private(table_private, "instant_col").is_some();
    let col_private = |c: &Json| {
        c.get("se_private_data")
            .and_then(Json::as_str)
            .unwrap_or("")
            .to_owned()
    };
    let versioned = columns.iter().any(|c| {
        let p = col_private(c);
        private(&p, "version_added").is_some() || private(&p, "version_dropped").is_some()
    });
    for ix in dd
        .get("indexes")
        .and_then(Json::as_array)
        .unwrap_or_default()
    {
        let p = ix
            .get("se_private_data")
            .and_then(Json::as_str)
            .unwrap_or("");
        let (Some(id), Some(root)) = (private(p, "id"), private(p, "root")) else {
            continue;
        };
        let mut fields = Vec::new();
        // Physical position, version added and dropped of each field.
        let mut phys = Vec::new();
        let mut used = BTreeSet::new();
        let mut known = true;
        for e in ix
            .get("elements")
            .and_then(Json::as_array)
            .unwrap_or_default()
        {
            let opx = to_usize(num(e, "column_opx"));
            let Some(c) = columns.get(opx) else {
                known = false;
                continue;
            };
            if flag(c, "is_virtual") {
                continue;
            }
            used.insert(opx);
            let length = num(e, "length");
            let prefix = (length != u64::from(u32::MAX)).then_some(length);
            match column_field(c, prefix, flag(e, "hidden"), false) {
                Some(f) => {
                    phys.push(column_versions(&col_private(c)));
                    fields.push(f);
                }
                None => known = false,
            }
        }
        let clustered = fields.iter().any(|f| matches!(f.ty, Ty::TrxId));
        let mut versions = Vec::new();
        if clustered && versioned && known {
            // Dropped columns stay in older records: add them, and put
            // every field in its physical place.
            for (opx, c) in columns.iter().enumerate() {
                let p = col_private(c);
                if used.contains(&opx) || private(&p, "version_dropped").is_none() {
                    continue;
                }
                match column_field(c, None, false, true) {
                    Some(mut f) => {
                        f.name = format!("{} (dropped)", dropped_name(&f.name));
                        f.key = false;
                        phys.push(column_versions(&p));
                        fields.push(f);
                    }
                    None => known = false,
                }
            }
            if phys.iter().any(|v| v.0.is_none()) {
                known = false;
            }
            let mut order: Vec<usize> = (0..fields.len()).collect();
            order.sort_by_key(|&i| phys.get(i).and_then(|v| v.0));
            let mut sorted = Vec::with_capacity(fields.len());
            for &i in &order {
                if let (Some(f), Some(v)) = (fields.get(i), phys.get(i)) {
                    sorted.push(f.clone());
                    versions.push((v.1, v.2));
                }
            }
            fields = sorted;
        }
        let n_uniq = if clustered {
            fields
                .iter()
                .position(|f| matches!(f.ty, Ty::TrxId))
                .unwrap_or(fields.len())
        } else {
            fields.len()
        };
        if !known {
            fields.clear();
            versions.clear();
        }
        out.push(IndexDef {
            id,
            name: ix
                .get("name")
                .and_then(Json::as_str)
                .unwrap_or("?")
                .to_owned(),
            table: table.clone(),
            root: u32::try_from(root).unwrap_or(FIL_NULL),
            fields,
            n_uniq,
            instant,
            versions,
        });
    }
    out
}

/// A column's physical position and the row versions that added and
/// dropped it, from its `se_private_data`.
fn column_versions(p: &str) -> (Option<u64>, u32, u32) {
    let v = |k: &str| u32::try_from(private(p, k).unwrap_or(0)).unwrap_or(u32::MAX);
    (
        private(p, "physical_pos"),
        v("version_added"),
        v("version_dropped"),
    )
}

/// A dropped column's original name: `!hidden!_dropped_v2_p4_b` is `b`.
fn dropped_name(name: &str) -> &str {
    name.strip_prefix("!hidden!_dropped_")
        .and_then(|rest| rest.splitn(3, '_').nth(2))
        .unwrap_or(name)
}

// ---------------------------------------------------------------------------
// Values

/// A packed decimal as text.
fn decimal(b: &[u8], precision: u32, scale: u32) -> Option<String> {
    const DIG2BYTES: [usize; 10] = [0, 1, 1, 2, 2, 3, 3, 4, 4, 4];
    let mut v = b.to_vec();
    let first = v.first_mut()?;
    let negative = *first & 0x80 == 0;
    *first ^= 0x80;
    if negative {
        for x in &mut v {
            *x = !*x;
        }
    }
    let intg = precision.saturating_sub(scale);
    let mut pos = 0usize;
    let mut take = |n: usize| -> Option<u64> {
        let s = v.get(pos..pos.checked_add(n)?)?;
        pos = pos.checked_add(n)?;
        Some(
            s.iter()
                .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x)),
        )
    };
    let mut int_part = String::new();
    let lead = to_usize((intg % 9).into());
    if lead != 0 {
        int_part.push_str(&take(*DIG2BYTES.get(lead)?)?.to_string());
    }
    for _ in 0..intg / 9 {
        let g = take(4)?;
        if int_part.is_empty() {
            int_part.push_str(&g.to_string());
        } else {
            int_part.push_str(&format!("{g:09}"));
        }
    }
    let int_part = int_part.trim_start_matches('0');
    let mut out = String::new();
    if negative {
        out.push('-');
    }
    out.push_str(if int_part.is_empty() { "0" } else { int_part });
    if scale > 0 {
        out.push('.');
        for _ in 0..scale / 9 {
            out.push_str(&format!("{:09}", take(4)?));
        }
        let tail = to_usize((scale % 9).into());
        if tail != 0 {
            let g = take(*DIG2BYTES.get(tail)?)?;
            out.push_str(&format!("{g:0width$}", width = tail));
        }
    }
    Some(out)
}

fn be(b: &[u8]) -> u64 {
    b.iter()
        .fold(0u64, |a, &x| a.wrapping_shl(8) | u64::from(x))
}

fn frac(b: &[u8], fsp: u32) -> String {
    if fsp == 0 || b.is_empty() {
        return String::new();
    }
    let v = be(b);
    // One byte holds two digits, two bytes four, three bytes six.
    let digits = to_usize(to_u64(b.len()).saturating_mul(2));
    let s = format!("{v:0digits$}");
    format!(".{}", s.get(..to_usize(fsp.into())).unwrap_or(&s))
}

/// A stored value's node value and its short form for summaries.
pub fn value(f: &Field, b: &[u8]) -> (Value, String) {
    let shown = |v: Value, s: String| (v, s);
    match &f.ty {
        Ty::Int { unsigned } => {
            let raw = be(b);
            let bits = to_u64(b.len()).saturating_mul(8);
            let bits8 = u8::try_from(bits).unwrap_or(64);
            if *unsigned || b.is_empty() || bits == 0 || bits > 64 {
                return shown(uint(raw, bits8), raw.to_string());
            }
            let sign = 1u64.wrapping_shl(u32::try_from(bits).unwrap_or(64).saturating_sub(1));
            let flipped = raw ^ sign;
            // Sign-extend from `bits`.
            let shift = 64u32.saturating_sub(u32::try_from(bits).unwrap_or(64));
            let v = (flipped.wrapping_shl(shift) as i64).wrapping_shr(shift);
            shown(
                Value::Int {
                    value: v,
                    bits: bits8,
                },
                v.to_string(),
            )
        }
        Ty::Float => {
            let v = crate::bytes::f32_le(b, 0).unwrap_or(0.0);
            shown(Value::Float(v.into()), v.to_string())
        }
        Ty::Double => {
            let v = crate::bytes::f64_le(b, 0).unwrap_or(0.0);
            shown(Value::Float(v), v.to_string())
        }
        Ty::Decimal { precision, scale } => {
            let s = decimal(b, *precision, *scale).unwrap_or_else(|| "?".to_owned());
            shown(text(s.clone()), s)
        }
        Ty::Date => {
            let mut v = be(b);
            if v & 0x80_0000 != 0 {
                v ^= 0x80_0000;
            }
            let s = format!("{:04}-{:02}-{:02}", v >> 9, (v >> 5) & 15, v & 31);
            shown(text(s.clone()), s)
        }
        Ty::DateTime { fsp } => {
            let v = be(b.get(..5).unwrap_or_default()).wrapping_sub(0x80_0000_0000);
            let ym = v >> 22;
            let s = format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}{}",
                ym / 13,
                ym % 13,
                (v >> 17) & 31,
                (v >> 12) & 31,
                (v >> 6) & 63,
                v & 63,
                frac(b.get(5..).unwrap_or_default(), *fsp)
            );
            shown(text(s.clone()), s)
        }
        Ty::Timestamp { fsp } => {
            let secs = be(b.get(..4).unwrap_or_default());
            let s = format!("{secs}{}", frac(b.get(4..).unwrap_or_default(), *fsp));
            (
                Value::Timestamp {
                    unix_seconds: i64::try_from(secs).unwrap_or(0),
                },
                s,
            )
        }
        Ty::Time { fsp } => {
            let raw = be(b.get(..3).unwrap_or_default());
            let negative = raw & 0x80_0000 == 0;
            let v = if negative {
                0x80_0000u64.wrapping_sub(raw)
            } else {
                raw ^ 0x80_0000
            };
            let s = format!(
                "{}{:02}:{:02}:{:02}{}",
                if negative { "-" } else { "" },
                (v >> 12) & 0x3ff,
                (v >> 6) & 63,
                v & 63,
                frac(b.get(3..).unwrap_or_default(), *fsp)
            );
            shown(text(s.clone()), s)
        }
        Ty::Year => {
            let v = be(b);
            let y = if v == 0 { 0 } else { v.saturating_add(1900) };
            shown(uint(y, 16), y.to_string())
        }
        Ty::Text => {
            let s = String::from_utf8_lossy(b).trim_end_matches(' ').to_owned();
            let short = format!("'{}'", clip(&s, 40));
            shown(text(s), short)
        }
        Ty::Raw
            if std::str::from_utf8(b)
                .is_ok_and(|s| !s.is_empty() && s.chars().all(|c| !c.is_control())) =>
        {
            let s = String::from_utf8_lossy(b).into_owned();
            let short = format!("'{}'", clip(&s, 40));
            shown(text(s), short)
        }
        Ty::Binary | Ty::Json | Ty::Bit | Ty::Raw => {
            let short = format!(
                "0x{}",
                clip(
                    &b.iter().map(|x| format!("{x:02x}")).collect::<String>(),
                    32
                )
            );
            shown(Value::Bytes(b.to_vec()), short)
        }
        Ty::Enum(names) => {
            let v = be(b);
            let s = match to_usize(v).checked_sub(1).and_then(|i| names.get(i)) {
                Some(n) => format!("'{n}'"),
                None if v == 0 => "''".to_owned(),
                None => v.to_string(),
            };
            shown(uint(v, 16), s)
        }
        Ty::Set(names) => {
            let v = be(b);
            let set: Vec<&str> = names
                .iter()
                .enumerate()
                .filter(|&(i, _)| {
                    u32::try_from(i).is_ok_and(|i| i < 64 && v & 1u64.wrapping_shl(i) != 0)
                })
                .map(|(_, n)| n.as_str())
                .collect();
            shown(
                Value::UInt {
                    value: v,
                    bits: 64,
                    radix: Radix::Hex,
                },
                format!("'{}'", set.join(",")),
            )
        }
        Ty::TrxId | Ty::RowId => {
            let v = be(b);
            shown(uint(v, 48), v.to_string())
        }
        Ty::RollPtr => {
            let v = be(b);
            let insert = v >> 55 & 1 != 0;
            let rseg = (v >> 48) & 0x7f;
            let page = (v >> 16) & 0xffff_ffff;
            let offset = v & 0xffff;
            (
                Value::UInt {
                    value: v,
                    bits: 56,
                    radix: Radix::Hex,
                },
                format!(
                    "{}rollback segment {rseg}, page {page}:{offset:#x}",
                    if insert { "insert, " } else { "" }
                ),
            )
        }
    }
}

// ---------------------------------------------------------------------------
// Nodes

/// The SDI objects, with their JSON.
pub async fn sdi_objects(cx: Cx, space: SpaceRef) -> Result<()> {
    let (list, problems) = objects(&cx, &space).await;
    for p in problems {
        cx.diag(p);
    }
    cx.set_count(Count::Exact(to_u64(list.len())));
    // Names come from the dictionary, decoded once (and within its limits).
    let dict = load(&cx, &space).await;
    for o in list {
        let kind = crate::value::lookup(SDI_TYPES, o.kind.into()).unwrap_or("object");
        let name = match dict.names.get(&(o.kind, o.id)) {
            Some(n) => format!("{} {n}", crate::formats::util::fmt::capitalize(kind)),
            None => format!("{} {}", crate::formats::util::fmt::capitalize(kind), o.id),
        };
        let page_span = o.page_span;
        cx.push(
            Node::new(name)
                .summary(format!(
                    "ID {}, {} of JSON in {}",
                    o.id,
                    crate::formats::util::fmt::size(o.ulen.into()),
                    crate::formats::util::fmt::size(o.clen.into())
                ))
                .span(o.data)
                .lazy(sdi_object, (space.input, o.clone(), page_span)),
        )
        .await;
    }
    Ok(())
}

async fn sdi_object(cx: Cx, (input, o, page_span): (Input, SdiObject, Span)) -> Result<()> {
    let kind = crate::value::lookup(SDI_TYPES, o.kind.into());
    cx.emit(Node::new("Type").value(Value::Enum {
        raw: o.kind.into(),
        bits: 32,
        name: kind,
    }));
    cx.emit(Node::new("ID").value(uint(o.id, 64)));
    cx.emit(
        Node::new("Record")
            .span(page_span.sub(o.origin, 1))
            .summary(format!("page {}, offset {:#x}", o.page, o.origin)),
    );
    cx.emit(content(
        "JSON",
        input.nested(o.data),
        o.data,
        Codec::Zlib,
        Some(o.ulen.into()),
    ));
    Ok(())
}

/// The indexes the dictionary names, each with its root page.
pub async fn index_list(cx: Cx, space: SpaceRef) -> Result<()> {
    let dict = load(&cx, &space).await;
    for p in &dict.problems {
        cx.diag(p.clone());
    }
    cx.set_count(Count::Exact(to_u64(dict.indexes.len())));
    for def in dict.indexes.values() {
        let mut n = page::node(
            &space,
            format!("{}.{}", def.table, def.name),
            def.root,
            Arc::new(Vec::new()),
        );
        let cols: Vec<&str> = def
            .fields
            .iter()
            .filter(|f| f.key)
            .map(|f| f.name.as_str())
            .collect();
        n = n.summary(format!(
            "index {}, root page {}, {}",
            def.id,
            def.root,
            if def.fields.is_empty() {
                "columns of unknown storage".to_owned()
            } else {
                format!("({})", cols.join(", "))
            }
        ));
        cx.push(n).await;
    }
    Ok(())
}
