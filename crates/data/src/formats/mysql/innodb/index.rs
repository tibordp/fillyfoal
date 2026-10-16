//! InnoDB index pages: the index header, the infimum and supremum system
//! records, user records in key order (walked along their next-record
//! links), the free record list, free space and the page directory.
//!
//! Records come in two formats, told apart by the page header. Redundant
//! records list every field's end offset before the record, so they split
//! into fields without the table definition. Compact records (compact,
//! dynamic and compressed row formats) store only a null bitmap and the
//! lengths of variable-length fields; splitting them needs the index's
//! field list, which MySQL 8's dictionary supplies (`dict`).

use std::collections::BTreeSet;
use std::sync::Arc;

use super::dict::{self, Field, IndexDef};
use super::page::{self, PageState, SDI};
use super::{BE, FIL_HEADER, SpaceRef, Sum, fseg_header, zip};
use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::formats::content;
use crate::formats::util::fmt::{clip, grouped_count, plural, size};
use crate::formats::util::val::{hex, uint};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

/// The index header's end (where the system records start).
const PAGE_DATA: u64 = 94;
const COMPACT_INFIMUM: u64 = 99;
const COMPACT_SUPREMUM: u64 = 112;
const COMPACT_END: u64 = 120;
const REDUNDANT_INFIMUM: u64 = 101;
const REDUNDANT_SUPREMUM: u64 = 116;
const REDUNDANT_END: u64 = 125;

const DIRECTIONS: EnumTable = &[
    (1, "left"),
    (2, "right"),
    (3, "same record"),
    (4, "same page"),
    (5, "none"),
];

fn heap_records(v: u16) -> String {
    format!(
        "{} in the heap, {} format",
        plural(v & 0x7fff, "record"),
        if v & 0x8000 != 0 {
            "compact"
        } else {
            "redundant"
        }
    )
}

record! {
    /// The index page header, after the FIL header.
    pub struct IndexHeader {
        n_dir_slots: u16 "Directory slots",
        heap_top: u16 "Heap top" .hex() .desc("End of the record heap"),
        n_heap: u16 "Heap records" .hex() .with(|&v, n| n.summary(heap_records(v)))
            .desc("Records in the heap including the infimum, supremum and deleted ones; the top bit marks the compact format"),
        free: u16 "Free list" .hex() .desc("Offset of the first deleted record available for reuse (0: none)"),
        garbage: u16 "Garbage" .desc("Bytes in deleted records"),
        last_insert: u16 "Last insert" .hex(),
        direction: u16 "Direction" .enumeration(DIRECTIONS) .desc("Where the last inserts went, for the split heuristic"),
        n_direction: u16 "Inserts in that direction",
        n_recs: u16 "Records" .desc("User records on the page, not counting deleted ones"),
        max_trx_id: u64 "Maximum transaction ID" .desc("Secondary index leaves: the latest transaction that changed the page"),
        level: u16 "Level" .desc("0 for leaves, counting up to the root"),
        index_id: u64 "Index ID",
        seg_leaf: bytes[10] "Leaf segment" .with(|v, n| n.summary(fseg_header(v)))
            .desc("Root page only: the segment the index's leaf pages come from"),
        seg_top: bytes[10] "Non-leaf segment" .with(|v, n| n.summary(fseg_header(v)))
            .desc("Root page only: the segment of the pages above the leaves"),
    }
}

fn compact(page: &[u8]) -> bool {
    u16_be(page, 42).unwrap_or(0) & 0x8000 != 0
}

fn level(page: &[u8]) -> u16 {
    u16_be(page, 64).unwrap_or(0)
}

/// The record after the one at `origin`, by its next-record link.
fn next_of(page: &[u8], origin: u64, compact: bool) -> Option<u64> {
    let at = to_usize(origin).checked_sub(2)?;
    let raw = u16_be(page, at)?;
    if raw == 0 {
        return None;
    }
    if compact {
        let len = to_u64(page.len());
        let sum = u64::from(u16::try_from(origin & 0xffff).ok()?.wrapping_add(raw));
        Some(if len.is_power_of_two() {
            sum & len.saturating_sub(1)
        } else {
            sum
        })
    } else {
        Some(raw.into())
    }
}

/// The user records in key order, from the infimum's link to the supremum.
pub fn user_records(page: &[u8]) -> Vec<u64> {
    let compact = compact(page);
    let (inf, sup) = if compact {
        (COMPACT_INFIMUM, COMPACT_SUPREMUM)
    } else {
        (REDUNDANT_INFIMUM, REDUNDANT_SUPREMUM)
    };
    let limit = usize::from(u16_be(page, 42).unwrap_or(0) & 0x7fff);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let mut at = inf;
    while let Some(next) = next_of(page, at, compact) {
        if next == sup || out.len() >= limit || !seen.insert(next) {
            break;
        }
        out.push(next);
        at = next;
    }
    out
}

/// One field of a record: where its bytes are in the page.
#[derive(Clone, Copy, Debug)]
pub struct Slot {
    /// The index field (or the redundant record's field number).
    pub field: usize,
    pub off: u64,
    pub len: u64,
    pub null: bool,
    /// Stored off-page: the last 20 bytes reference the rest.
    pub external: bool,
}

/// A record as far as it could be decoded.
#[derive(Debug, Default)]
pub struct Parsed {
    /// First byte of the record's extra bytes (lengths, null flags,
    /// header).
    pub start: u64,
    /// One past the last data byte, if known.
    pub end: Option<u64>,
    pub flags: u8,
    pub n_owned: u8,
    pub heap_no: u16,
    /// 0 ordinary, 1 node pointer, 2 infimum, 3 supremum.
    pub status: u8,
    pub next: Option<u64>,
    pub compact: bool,
    pub fields: Vec<Slot>,
    pub child: Option<(u64, u32)>,
    /// Compact: the null bitmap and the field lengths.
    pub nulls: Option<(u64, u64)>,
    pub lens: Option<(u64, u64)>,
    /// Redundant: the field end offsets, and whether they take one byte.
    pub offsets: Option<(u64, u64, bool)>,
    /// MySQL 8.0.29+: the row version byte's offset and value.
    pub version: Option<(u64, u8)>,
    pub problem: Option<String>,
}

impl Parsed {
    pub fn header_len(&self) -> u64 {
        if self.compact { 5 } else { 6 }
    }
}

/// Decodes the record at `origin`. `def` gives the field list of compact
/// records; `leaf` says whether the page is a leaf (for redundant records,
/// which do not record it).
pub fn parse(page: &[u8], origin: u64, def: Option<&IndexDef>, leaf: bool) -> Parsed {
    if compact(page) {
        parse_compact(page, origin, def)
    } else {
        parse_redundant(page, origin, def, leaf)
    }
}

fn byte(page: &[u8], at: u64) -> Option<u8> {
    page.get(to_usize(at)).copied()
}

fn parse_compact(page: &[u8], origin: u64, def: Option<&IndexDef>) -> Parsed {
    let mut p = Parsed {
        start: origin.saturating_sub(5),
        compact: true,
        ..Parsed::default()
    };
    let (Some(b0), Some(hs)) = (
        byte(page, origin.saturating_sub(5)),
        u16_be(page, to_usize(origin.saturating_sub(4))),
    ) else {
        p.problem = Some("record header outside the page".to_owned());
        return p;
    };
    p.flags = b0 & 0xf0;
    p.n_owned = b0 & 0x0f;
    p.heap_no = hs >> 3;
    p.status = u8::try_from(hs & 7).unwrap_or(0);
    p.next = next_of(page, origin, true);
    if p.status >= 2 {
        p.end = Some(origin.saturating_add(8));
        return p;
    }
    let Some(def) = def.filter(|d| !d.fields.is_empty()) else {
        return p;
    };
    if def.instant {
        p.problem = Some("the table was altered with instant ADD COLUMN before MySQL 8.0.29; its records are not split into columns".to_owned());
        return p;
    }
    if p.flags & 0x80 != 0 || p.status > 3 {
        p.problem = Some(
            "the record carries a field count (instant ADD COLUMN before MySQL 8.0.29), which is not decoded"
                .to_owned(),
        );
        return p;
    }
    let node_ptr = p.status == 1;
    // MySQL 8.0.29+ row versions: a versioned record has its version in
    // the byte before the header and holds the fields of that version;
    // other records those of version 0.
    let mut nulls_end = origin.saturating_sub(5);
    let mut version = 0u32;
    if p.flags & 0x40 != 0 && !node_ptr {
        if def.versions.is_empty() {
            p.problem =
                Some("the record carries a row version, but the definition has none".to_owned());
            return p;
        }
        let at = origin.saturating_sub(6);
        let Some(v) = byte(page, at) else {
            p.problem = Some("row version outside the page".to_owned());
            return p;
        };
        p.version = Some((at, v));
        version = v.into();
        nulls_end = at;
    }
    let present = |i: usize| {
        node_ptr
            || def.versions.get(i).is_none_or(|&(added, dropped)| {
                added <= version && (dropped == 0 || dropped > version)
            })
    };
    let n = if node_ptr {
        def.n_uniq.min(def.fields.len())
    } else {
        def.fields.len()
    };
    let n_nullable = def
        .fields
        .iter()
        .enumerate()
        .filter(|&(i, f)| f.nullable && present(i))
        .count();
    let null_bytes = to_u64(n_nullable.div_ceil(8));
    let Some(mut lens) = nulls_end.checked_sub(null_bytes) else {
        p.problem = Some("null flags outside the page".to_owned());
        return p;
    };
    p.nulls = Some((lens, null_bytes));
    let lens_end = lens;
    let mut null_i = 0u64;
    let mut off = origin;
    for (i, f) in def.fields.iter().take(n).enumerate() {
        if !present(i) {
            continue;
        }
        if f.nullable {
            let at = nulls_end.saturating_sub(1).saturating_sub(null_i / 8);
            let bit = 1u8 << (null_i % 8);
            null_i = null_i.saturating_add(1);
            if byte(page, at).is_some_and(|b| b & bit != 0) {
                p.fields.push(Slot {
                    field: i,
                    off,
                    len: 0,
                    null: true,
                    external: false,
                });
                continue;
            }
        }
        let (len, external) = match f.fixed {
            Some(n) => (n, false),
            None => {
                lens = lens.saturating_sub(1);
                let Some(b1) = byte(page, lens) else {
                    p.problem = Some("field lengths outside the page".to_owned());
                    return p;
                };
                if f.big && b1 & 0x80 != 0 {
                    lens = lens.saturating_sub(1);
                    let b2 = byte(page, lens).unwrap_or(0);
                    ((u64::from(b1 & 0x3f) << 8) | u64::from(b2), b1 & 0x40 != 0)
                } else {
                    (u64::from(b1), false)
                }
            }
        };
        p.fields.push(Slot {
            field: i,
            off,
            len,
            null: false,
            external,
        });
        off = off.saturating_add(len);
    }
    p.lens = Some((lens, lens_end.saturating_sub(lens)));
    if node_ptr {
        p.child = u32_be(page, to_usize(off)).map(|c| (off, c));
        off = off.saturating_add(4);
    }
    p.start = lens;
    p.end = Some(off);
    check_bounds(page, &mut p);
    p
}

fn parse_redundant(page: &[u8], origin: u64, def: Option<&IndexDef>, leaf: bool) -> Parsed {
    let mut p = Parsed {
        start: origin.saturating_sub(6),
        compact: false,
        ..Parsed::default()
    };
    let o = to_usize(origin);
    let (Some(b0), Some(heap), Some(nf)) = (
        byte(page, origin.saturating_sub(6)),
        u16_be(page, o.saturating_sub(5)),
        u16_be(page, o.saturating_sub(4)),
    ) else {
        p.problem = Some("record header outside the page".to_owned());
        return p;
    };
    p.flags = b0 & 0xf0;
    p.n_owned = b0 & 0x0f;
    p.heap_no = heap >> 3;
    let n_fields = u64::from((nf >> 1) & 0x3ff);
    let short = nf & 1 != 0;
    p.next = next_of(page, origin, false);
    p.status = match p.heap_no {
        0 => 2,
        1 => 3,
        _ if leaf => 0,
        _ => 1,
    };
    let k = if short { 1u64 } else { 2 };
    let Some(start) = origin.checked_sub(6u64.saturating_add(n_fields.saturating_mul(k))) else {
        p.problem = Some("field offsets outside the page".to_owned());
        return p;
    };
    p.start = start;
    p.offsets = Some((start, n_fields.saturating_mul(k), short));
    let mut prev = 0u64;
    let fields_known = def.filter(|d| !d.fields.is_empty());
    for i in 0..n_fields {
        let (end, null, external) = if short {
            let b = byte(page, origin.saturating_sub(7).saturating_sub(i)).unwrap_or(0);
            (u64::from(b & 0x7f), b & 0x80 != 0, false)
        } else {
            let at = origin
                .saturating_sub(6)
                .saturating_sub(i.saturating_add(1).saturating_mul(2));
            let v = u16_be(page, to_usize(at)).unwrap_or(0);
            (u64::from(v & 0x3fff), v & 0x8000 != 0, v & 0x4000 != 0)
        };
        if end < prev {
            p.problem = Some(format!("field {i} ends before the previous one"));
            return p;
        }
        let slot = Slot {
            field: to_usize(i),
            off: origin.saturating_add(prev),
            len: end.saturating_sub(prev),
            null,
            external,
        };
        prev = end;
        let last = i.saturating_add(1) == n_fields;
        if p.status == 1 && last {
            p.child = u32_be(page, to_usize(slot.off)).map(|c| (slot.off, c));
        } else if p.status < 2 {
            p.fields.push(slot);
        }
    }
    p.end = Some(origin.saturating_add(prev));
    if let Some(d) = fields_known {
        let expected = if p.status == 1 {
            d.n_uniq
        } else {
            d.fields.len()
        };
        if p.status < 2 && p.fields.len() != expected {
            p.problem = Some(format!(
                "{}, the definition has {expected}",
                plural(p.fields.len(), "field")
            ));
        }
    }
    check_bounds(page, &mut p);
    p
}

fn check_bounds(page: &[u8], p: &mut Parsed) {
    let len = to_u64(page.len());
    if p.start < PAGE_DATA || p.end.is_some_and(|e| e > len) {
        p.problem = Some("record runs outside the page".to_owned());
        p.end = p.end.map(|e| e.min(len));
        p.fields.retain(|s| s.off.saturating_add(s.len) <= len);
    }
}

/// The definition of the index a page belongs to, if known.
async fn definition(cx: &Cx, space: &SpaceRef, page: &[u8]) -> Option<Arc<IndexDef>> {
    let kind = u16_be(page, 24).unwrap_or(0);
    if kind == SDI {
        return Some(dict::sdi_def());
    }
    space.sdi_root?;
    let id = crate::bytes::u64_be(page, 66)?;
    dict::load(cx, space).await.index(id).cloned()
}

/// Index page `no` as its records are read: the page itself, or for a
/// compressed tablespace the page rebuilt from it.
pub async fn record_page(cx: &Cx, space: &SpaceRef, no: u32) -> Result<(Span, Vec<u8>)> {
    let span = space
        .page(no)
        .ok_or_else(|| Diagnostic::malformed(format!("page {no} is past the end")))?;
    if space.geo.sum == Sum::Zip {
        let v = zip::view(cx, span, space.geo.logical).await?;
        return Ok((v.span, cx.read(v.span).await?));
    }
    Ok((span, cx.read(span).await?))
}

/// The body of an index page.
pub async fn body(cx: &Cx, state: &PageState, span: Span, page: &[u8]) -> Result<()> {
    let space = &state.space;
    cx.emit(IndexHeader::node(
        "Index header",
        span.sub(FIL_HEADER, IndexHeader::SIZE),
        BE,
    ));
    if space.geo.sum == Sum::Zip {
        return zip_body(cx, state, span).await;
    }
    let def = definition(cx, space, page).await;
    records_body(cx, state, span, page, def);
    Ok(())
}

/// The system records, the user and deleted records, free space and the
/// page directory of an uncompressed (or rebuilt) index page.
fn records_body(cx: &Cx, state: &PageState, span: Span, page: &[u8], def: Option<Arc<IndexDef>>) {
    let compact = compact(page);
    let (inf, sup, end) = if compact {
        (COMPACT_INFIMUM, COMPACT_SUPREMUM, COMPACT_END)
    } else {
        (REDUNDANT_INFIMUM, REDUNDANT_SUPREMUM, REDUNDANT_END)
    };
    for (name, origin, stop) in [
        (
            "Infimum",
            inf,
            sup.saturating_sub(if compact { 5 } else { 7 }),
        ),
        ("Supremum", sup, end),
    ] {
        let rec = parse(page, origin, None, true);
        let next = rec.next.map_or("none".to_owned(), |n| format!("{n:#x}"));
        let start = if name == "Infimum" {
            PAGE_DATA
        } else {
            rec.start.min(origin)
        };
        cx.emit(
            Node::new(name)
                .span(span.sub(start, stop.saturating_sub(start)))
                .summary(format!("system record, next record at {next}"))
                .lazy(
                    record_fields,
                    RecordState {
                        page: state.clone(),
                        origin,
                        def: None,
                    },
                ),
        );
    }
    let records = user_records(page);
    let level = level(page);
    let mut summary = grouped_count(to_u64(records.len()), "record", "records");
    if let Some(d) = &def {
        if d.table.is_empty() {
            summary.push_str(&format!(" of {}", d.name));
        } else {
            summary.push_str(&format!(" of {}.{}", d.table, d.name));
        }
    }
    let heap_top = u64::from(u16_be(page, 40).unwrap_or(0));
    cx.emit(
        Node::new("Records")
            .span(span.sub(end, heap_top.saturating_sub(end)))
            .summary(summary)
            .desc(if level == 0 {
                "Leaf records in key order"
            } else {
                "Node pointers in key order: the smallest key of each child page"
            })
            .lazy(records_list, (state.clone(), def.clone(), false)),
    );
    if u16_be(page, 44).unwrap_or(0) != 0 {
        cx.emit(
            Node::new("Deleted records")
                .summary(format!(
                    "{} bytes of garbage",
                    u16_be(page, 46).unwrap_or(0)
                ))
                .desc("Purged records on the free list, reused by later inserts")
                .lazy(records_list, (state.clone(), def, true)),
        );
    }
    let slots = u64::from(u16_be(page, 38).unwrap_or(0));
    let dir_len = slots.saturating_mul(2);
    let dir_start = span
        .len
        .saturating_sub(state.trailer())
        .saturating_sub(dir_len);
    if dir_start > heap_top {
        cx.emit(
            Node::new("Free space")
                .span(span.sub(heap_top, dir_start.saturating_sub(heap_top)))
                .summary(size(dir_start.saturating_sub(heap_top))),
        );
    }
    cx.emit(
        Node::new("Page directory")
            .span(span.sub(dir_start, dir_len))
            .summary(grouped_count(slots, "slot", "slots"))
            .desc("Every few records in key order, from the end of the page backwards, for binary search")
            .lazy(directory, (state.clone(), dir_start, slots)),
    );
}

/// A compressed index page: the zlib stream, the modification log, the
/// columns kept uncompressed, the dense directory, and the page they
/// rebuild.
async fn zip_body(cx: &Cx, state: &PageState, span: Span) -> Result<()> {
    let space = &state.space;
    let stream_span = span.sub(PAGE_DATA, span.len.saturating_sub(PAGE_DATA));
    let v = match zip::view(cx, span, space.geo.logical).await {
        Ok(v) => v,
        Err(e) => {
            cx.emit(
                content(
                    "Compressed records",
                    space.input.nested(stream_span),
                    stream_span,
                    Codec::Zlib,
                    None,
                )
                .summary("zlib stream, then the modification log and the dense page directory")
                .diag(e),
            );
            return Ok(());
        }
    };
    let z = &v.zip;
    let phys = span.len;
    let stream = span.sub(PAGE_DATA, z.stream);
    let mut node = Node::new("Compressed stream")
        .span(stream)
        .summary(format!(
            "zlib: {} describing the fields, {} of records ({} of the heap)",
            size(z.fields_len),
            size(z.inflated.saturating_sub(z.fields_len)),
            plural(z.from_stream, "record")
        ))
        .lazy(zip_stream, (state.clone(), span));
    if !z.adler_ok {
        node = node.diag(Diagnostic::malformed(
            "the stream's Adler-32 does not match",
        ));
    }
    cx.emit(node);
    let log_start = PAGE_DATA.saturating_add(z.stream);
    cx.emit(
        Node::new("Modification log")
            .span(span.sub(
                log_start,
                z.log_end.saturating_add(1).saturating_sub(log_start),
            ))
            .summary(grouped_count(to_u64(z.entries.len()), "entry", "entries"))
            .desc("Records written since the page was last compressed: heap number, extra bytes backwards, data")
            .lazy(zip_log, (state.clone(), span)),
    );
    let trailer = z.trailer_start(phys);
    let log_after = z.log_end.saturating_add(1);
    if trailer > log_after {
        cx.emit(
            Node::new("Free space")
                .span(span.sub(log_after, trailer.saturating_sub(log_after)))
                .summary(size(trailer.saturating_sub(log_after))),
        );
    }
    let dir_start = z.dir_start(phys);
    if dir_start > trailer {
        let mut what = match z.kind {
            zip::Kind::Clustered => format!(
                "DB_TRX_ID and DB_ROLL_PTR of {}",
                plural(z.n_dense, "record")
            ),
            zip::Kind::NodePtr => {
                format!("child page numbers of {}", plural(z.n_dense, "record"))
            }
            zip::Kind::Secondary => String::new(),
        };
        if z.n_blobs != 0 {
            what.push_str(&format!(
                ", {}",
                plural(z.n_blobs, "off-page column reference")
            ));
        }
        cx.emit(
            Node::new("Uncompressed columns")
                .span(span.sub(trailer, dir_start.saturating_sub(trailer)))
                .summary(what)
                .desc("Kept outside the stream so they can be updated in place, in heap order from the directory backwards"),
        );
    }
    cx.emit(
        Node::new("Dense directory")
            .span(span.sub(dir_start, phys.saturating_sub(dir_start)))
            .summary(grouped_count(z.n_dense, "entry", "entries"))
            .desc("Every record in the heap from the end of the page backwards: user records in key order, then the free list")
            .lazy(zip_directory, (state.clone(), span)),
    );
    let mut view = Node::new("Uncompressed page")
        .span(v.span)
        .summary(format!("{}, as InnoDB rebuilds it", size(v.span.len)))
        .lazy(
            zip_page,
            PageState {
                view: Some(v.span),
                ..state.clone()
            },
        );
    if let Some(p) = &z.problem {
        view = view.diag(Diagnostic::malformed(p.clone()));
    }
    cx.emit(view);
    Ok(())
}

/// The rebuilt page of a compressed index page, with the dictionary's
/// definition of the index or else the page's own field description.
async fn zip_page(cx: Cx, state: PageState) -> Result<()> {
    let Some(file) = state.space.page(state.no) else {
        return Ok(());
    };
    let v = zip::view(&cx, file, state.space.geo.logical).await?;
    let page = cx.read(v.span).await?;
    let def = match definition(&cx, &state.space, &page).await {
        Some(d) if !d.fields.is_empty() => d,
        _ => v.zip.def.clone(),
    };
    records_body(&cx, &state, v.span, &page, Some(def));
    Ok(())
}

/// The zlib stream: its header, the field description, the data and the
/// checksum.
async fn zip_stream(cx: Cx, (state, span): (PageState, Span)) -> Result<()> {
    let v = zip::view(&cx, span, state.space.geo.logical).await?;
    let z = &v.zip;
    let stream = span.sub(PAGE_DATA, z.stream);
    cx.emit(Node::new("zlib header").span(stream.sub(0, 2)).value(hex(
        u16_be(&cx.read(stream.sub(0, 2)).await?, 0).unwrap_or(0),
        16,
    )));
    let fields: Vec<String> = z
        .def
        .fields
        .iter()
        .map(|f| {
            let len = f.fixed.map_or_else(
                || {
                    if f.big {
                        "long variable".to_owned()
                    } else {
                        "variable".to_owned()
                    }
                },
                |n| format!("{n} bytes"),
            );
            format!("{}{}", len, if f.nullable { " or NULL" } else { "" })
        })
        .collect();
    cx.emit(
        Node::new("Field description")
            .summary(clip(&fields.join(", "), 160))
            .desc("The first deflate block: each field's length (consecutive fixed-length columns that cannot be NULL as one), then where the transaction ID is (leaves) or how many fields can be NULL (node pointers)"),
    );
    cx.emit(content(
        "Decompressed",
        state.space.input.nested(stream),
        stream,
        Codec::Zlib,
        Some(z.inflated),
    ));
    let mut adler = Node::new("Adler-32").span(stream.sub(z.stream.saturating_sub(4), 4));
    adler = if z.adler_ok {
        adler.summary("valid")
    } else {
        adler.diag(Diagnostic::malformed(
            "the stream's Adler-32 does not match",
        ))
    };
    cx.emit(adler);
    Ok(())
}

async fn zip_log(cx: Cx, (state, span): (PageState, Span)) -> Result<()> {
    let v = zip::view(&cx, span, state.space.geo.logical).await?;
    cx.set_count(Count::Exact(to_u64(v.zip.entries.len())));
    for (i, e) in v.zip.entries.iter().enumerate() {
        let what = if e.cleared {
            format!("heap no {}: data cleared", e.heap_no)
        } else {
            format!("heap no {}: {} bytes", e.heap_no, e.len)
        };
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(span.sub(e.at, e.len))
                .summary(what),
        )
        .await;
    }
    Ok(())
}

async fn zip_directory(cx: Cx, (state, span): (PageState, Span)) -> Result<()> {
    let v = zip::view(&cx, span, state.space.geo.logical).await?;
    let n = v.zip.n_dense;
    let head = cx.read(span.sub(54, 2)).await?;
    let n_recs = u64::from(u16_be(&head, 0).unwrap_or(0));
    let start = v.zip.dir_start(span.len);
    let b = cx.read(span.sub(start, n.saturating_mul(2))).await?;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = n.saturating_sub(1).saturating_sub(i).saturating_mul(2);
        let raw = u16_be(&b, to_usize(at)).unwrap_or(0);
        let off = raw & 0x3fff;
        let mut flags = Vec::new();
        if i >= n_recs {
            flags.push("free");
        }
        if raw & 0x4000 != 0 {
            flags.push("owns a directory slot");
        }
        if raw & 0x8000 != 0 {
            flags.push("deleted");
        }
        let summary = if flags.is_empty() {
            format!("record at {off:#x}")
        } else {
            format!("record at {off:#x}, {}", flags.join(", "))
        };
        let mut node = Node::new(format!("Entry {i}"))
            .span(span.sub(start.saturating_add(at), 2))
            .value(hex(raw, 16))
            .summary(summary);
        if u64::from(off) < v.span.len {
            node = node.target(v.span.sub(off.into(), 1));
        }
        cx.push(node).await;
    }
    Ok(())
}

#[derive(Clone)]
pub struct RecordState {
    pub page: PageState,
    pub origin: u64,
    pub def: Option<Arc<IndexDef>>,
}

/// The free (deleted) record chain.
fn free_records(page: &[u8]) -> Vec<u64> {
    let compact = compact(page);
    let mut out = Vec::new();
    let mut seen = BTreeSet::new();
    let limit = usize::from(u16_be(page, 42).unwrap_or(0) & 0x7fff);
    let mut at = u64::from(u16_be(page, 44).unwrap_or(0));
    while at != 0 && out.len() < limit && seen.insert(at) {
        out.push(at);
        match next_of(page, at, compact) {
            Some(n) => at = n,
            None => break,
        }
    }
    out
}

/// The span a record without a known end takes: up to the next record in
/// the heap (whose own extra bytes are then included).
fn guessed_end(page: &[u8], origin: u64, heap: &[u64]) -> u64 {
    let heap_top = u64::from(u16_be(page, 40).unwrap_or(0));
    let i = heap.partition_point(|&o| o <= origin);
    heap.get(i)
        .map_or(heap_top, |&next| {
            next.saturating_sub(if compact(page) { 5 } else { 6 })
        })
        .max(origin)
}

/// Summary of a record's fields.
fn describe(page: &[u8], rec: &Parsed, def: Option<&IndexDef>) -> String {
    let mut parts = Vec::new();
    for s in &rec.fields {
        let f = def.and_then(|d| d.fields.get(s.field));
        if f.is_some_and(|f| f.hidden) && def.is_some_and(|d| d.id != 0) {
            continue;
        }
        let shown = if s.null {
            "NULL".to_owned()
        } else if s.external {
            "(off-page)".to_owned()
        } else {
            let b = page
                .get(to_usize(s.off)..to_usize(s.off.saturating_add(s.len)))
                .unwrap_or_default();
            match f {
                Some(f) => dict::value(f, b).1,
                None => format!("{} bytes", b.len()),
            }
        };
        match f {
            Some(f) => parts.push(format!("{}={shown}", f.name)),
            None => parts.push(shown),
        }
        if parts.len() >= 12 {
            parts.push("…".to_owned());
            break;
        }
    }
    clip(&parts.join(", "), 160)
}

async fn records_list(
    cx: Cx,
    (state, def, free): (PageState, Option<Arc<IndexDef>>, bool),
) -> Result<()> {
    let Some(span) = state.span() else {
        return Ok(());
    };
    let page = cx.read(span).await?;
    let list = if free {
        free_records(&page)
    } else {
        user_records(&page)
    };
    let leaf = level(&page) == 0;
    cx.set_count(Count::Exact(to_u64(list.len())));
    // Every record origin in address order, to bound records whose end is
    // unknown.
    let mut heap: Vec<u64> = user_records(&page);
    heap.extend(free_records(&page));
    heap.sort_unstable();
    for (i, &origin) in list.iter().enumerate() {
        if i % 64 == 0 {
            cx.checkpoint().await;
        }
        let rec = parse(&page, origin, def.as_deref(), leaf);
        let end = rec.end.unwrap_or_else(|| guessed_end(&page, origin, &heap));
        let mut summary = if let Some((_, child)) = rec.child {
            let key = describe(&page, &rec, def.as_deref());
            if key.is_empty() {
                format!("child page {child}")
            } else {
                format!("child page {child}: {key}")
            }
        } else if rec.fields.is_empty() {
            format!(
                "heap no {}, {} bytes from the header",
                rec.heap_no,
                end.saturating_sub(rec.start)
            )
        } else {
            describe(&page, &rec, def.as_deref())
        };
        if rec.flags & 0x20 != 0 {
            summary = format!("deleted: {summary}");
        }
        let mut node = Node::new(format!("Record {i}"))
            .span(span.sub(rec.start, end.saturating_sub(rec.start)))
            .summary(summary)
            .lazy(
                record_fields,
                RecordState {
                    page: state.clone(),
                    origin,
                    def: def.clone(),
                },
            );
        if let Some(p) = &rec.problem {
            node = node.diag(Diagnostic::malformed(p.clone()));
        }
        cx.push(node).await;
    }
    Ok(())
}

const RECORD_STATUS: EnumTable = &[
    (0, "ordinary"),
    (1, "node pointer"),
    (2, "infimum"),
    (3, "supremum"),
];

async fn record_fields(cx: Cx, rs: RecordState) -> Result<()> {
    let state = &rs.page;
    let Some(span) = state.span() else {
        return Ok(());
    };
    let page = cx.read(span).await?;
    let leaf = level(&page) == 0;
    let def = rs.def.as_deref();
    let rec = parse(&page, rs.origin, def, leaf);
    let at = |o: u64, n: u64| span.sub(o, n);
    if let Some((off, len, short)) = rec.offsets {
        cx.emit(
            Node::new("Field end offsets")
                .span(at(off, len))
                .summary(format!(
                    "{} bytes each, last field first",
                    if short { 1 } else { 2 }
                )),
        );
    }
    if let Some((off, len)) = rec.lens.filter(|l| l.1 != 0) {
        cx.emit(
            Node::new("Field lengths")
                .span(at(off, len))
                .summary("variable-length fields, last field first"),
        );
    }
    if let Some((off, len)) = rec.nulls.filter(|l| l.1 != 0) {
        cx.emit(
            Node::new("Null flags")
                .span(at(off, len))
                .value(Value::Bytes(
                    page.get(to_usize(off)..to_usize(off.saturating_add(len)))
                        .unwrap_or_default()
                        .to_vec(),
                )),
        );
    }
    let hl = rec.header_len();
    let hstart = rs.origin.saturating_sub(hl);
    let mut flags = Vec::new();
    if rec.flags & 0x10 != 0 {
        flags.push("minimum record");
    }
    if rec.flags & 0x20 != 0 {
        flags.push("deleted");
    }
    if rec.flags & 0x40 != 0 {
        flags.push("versioned");
    }
    if rec.flags & 0x80 != 0 {
        flags.push("instant");
    }
    cx.emit(
        Node::new("Info flags")
            .span(at(hstart, 1))
            .value(hex(rec.flags >> 4, 4))
            .summary(if flags.is_empty() {
                "none".to_owned()
            } else {
                flags.join(", ")
            }),
    );
    cx.emit(
        Node::new("Records owned")
            .span(at(hstart, 1))
            .value(uint(rec.n_owned, 8))
            .desc("Non-zero on the last record of a directory slot's group"),
    );
    cx.emit(
        Node::new("Heap number")
            .span(at(hstart.saturating_add(1), 2))
            .value(uint(rec.heap_no, 16)),
    );
    if let Some((off, v)) = rec.version {
        cx.emit(
            Node::new("Row version")
                .span(at(off, 1))
                .value(uint(v, 8))
                .desc("Instant ADD/DROP COLUMN: the record holds the columns of this version of the table"),
        );
    }
    if rec.compact {
        cx.emit(
            Node::new("Status")
                .span(at(hstart.saturating_add(2), 1))
                .value(Value::Enum {
                    raw: rec.status.into(),
                    bits: 3,
                    name: crate::value::lookup(RECORD_STATUS, rec.status.into()).map(Into::into),
                }),
        );
    } else if let Some((_, len, short)) = rec.offsets {
        let n = if short { len } else { len / 2 };
        cx.emit(
            Node::new("Fields")
                .span(at(hstart.saturating_add(2), 2))
                .value(uint(n, 16))
                .summary(if short {
                    "1-byte offsets"
                } else {
                    "2-byte offsets"
                }),
        );
    }
    let raw = u16_be(&page, to_usize(rs.origin.saturating_sub(2))).unwrap_or(0);
    let mut next = Node::new("Next record").span(at(rs.origin.saturating_sub(2), 2));
    next = if rec.compact {
        next.value(Value::Int {
            value: i64::from(i16::from_be_bytes(raw.to_be_bytes())),
            bits: 16,
        })
    } else {
        next.value(hex(raw, 16))
    };
    next = match rec.next {
        Some(n) => next.summary(format!("record at {n:#x}")).target(at(n, 1)),
        None => next.summary("none"),
    };
    cx.emit(next);
    if rec.status >= 2 {
        // "infimum\0" and "supremum" (compact) or "supremum\0" (redundant).
        let end = rec
            .end
            .unwrap_or(rs.origin)
            .min(rs.origin.saturating_add(9));
        cx.emit(
            Node::new("Data")
                .span(at(rs.origin, end.saturating_sub(rs.origin)))
                .value(crate::formats::util::val::text(crate::text::until_nul(
                    page.get(to_usize(rs.origin)..to_usize(end))
                        .unwrap_or_default(),
                ))),
        );
        return Ok(());
    }
    if rec.fields.is_empty() && rec.child.is_none() {
        let mut heap = user_records(&page);
        heap.extend(free_records(&page));
        heap.sort_unstable();
        let end = guessed_end(&page, rs.origin, &heap);
        let mut n = Node::new("Data")
            .span(at(rs.origin, end.saturating_sub(rs.origin)))
            .desc("Without the table definition the column boundaries are unknown; this runs to the next record's header and so includes its null flags and field lengths");
        if let Some(p) = &rec.problem {
            n = n.diag(Diagnostic::note(p.clone()));
        }
        cx.emit(n);
        return Ok(());
    }
    for s in &rec.fields {
        let f: Option<&Field> = def.and_then(|d| d.fields.get(s.field));
        let name = f.map_or_else(|| format!("Field {}", s.field), |f| f.name.clone());
        let fspan = at(s.off, s.len);
        let mut n = Node::new(name).span(fspan);
        if s.null {
            n = n.summary("NULL");
        } else if s.external {
            let local = s.len.saturating_sub(20);
            let b = page
                .get(to_usize(s.off.saturating_add(local))..to_usize(s.off.saturating_add(s.len)))
                .unwrap_or_default();
            let total = crate::bytes::u64_be(b, 12).unwrap_or(0) & 0x3fff_ffff_ffff_ffff;
            n = n
                .summary(format!(
                    "{} stored off-page from page {}, {} locally",
                    size(total),
                    u32_be(b, 4).unwrap_or(0),
                    size(local)
                ))
                .lazy(external_value, (rs.clone(), *s));
        } else {
            let b = page
                .get(to_usize(s.off)..to_usize(s.off.saturating_add(s.len)))
                .unwrap_or_default();
            match f {
                Some(f) => {
                    let (v, short) = dict::value(f, b);
                    n = n.value(v);
                    if matches!(
                        f.ty,
                        dict::Ty::RollPtr | dict::Ty::Enum(_) | dict::Ty::Set(_)
                    ) {
                        n = n.summary(short);
                    }
                    if matches!(f.ty, dict::Ty::Binary) && def.is_some_and(|d| d.id == 0) {
                        n = n.summary("zlib-compressed JSON");
                    }
                }
                None => n = n.value(Value::Bytes(b.to_vec())),
            }
        }
        cx.emit(n);
    }
    if let Some((off, child)) = rec.child {
        cx.emit(page::link("Child page", state, child, at(off, 4)));
    }
    if let Some(p) = &rec.problem {
        cx.diag(Diagnostic::malformed(p.clone()));
    }
    Ok(())
}

/// An off-page field: its reference, and the whole value as one piecewise
/// source.
async fn external_value(cx: Cx, (rs, slot): (RecordState, Slot)) -> Result<()> {
    let space = &rs.page.space;
    let Some(span) = rs.page.span() else {
        return Ok(());
    };
    let local = slot.len.saturating_sub(20);
    if local != 0 {
        cx.emit(
            Node::new("Local prefix")
                .span(span.sub(slot.off, local))
                .summary(size(local)),
        );
    }
    let rspan = span.sub(slot.off.saturating_add(local), 20);
    let b = cx.read(rspan).await?;
    cx.emit(
        Node::new("Space ID")
            .span(rspan.sub(0, 4))
            .value(uint(u32_be(&b, 0).unwrap_or(0), 32)),
    );
    cx.emit(page::link(
        "First page",
        &rs.page,
        u32_be(&b, 4).unwrap_or(0),
        rspan.sub(4, 4),
    ));
    cx.emit(
        Node::new("Offset or version")
            .span(rspan.sub(8, 4))
            .value(uint(u32_be(&b, 8).unwrap_or(0), 32)),
    );
    let len = crate::bytes::u64_be(&b, 12).unwrap_or(0);
    let mut flags = Vec::new();
    if len & (1 << 63) != 0 {
        flags.push("not owner");
    }
    if len & (1 << 62) != 0 {
        flags.push("inherited");
    }
    cx.emit(
        Node::new("Length")
            .span(rspan.sub(12, 8))
            .value(uint(len & 0x3fff_ffff_ffff_ffff, 64))
            .summary(if flags.is_empty() {
                "owned".to_owned()
            } else {
                flags.join(", ")
            }),
    );
    match dict::external_span(&cx, space, span, &slot).await {
        Ok(whole) => cx.emit(
            Node::new("Value")
                .span(whole)
                .summary(size(whole.len))
                .lazy(crate::formats::dissect_or_data, space.input.nested(whole)),
        ),
        Err(e) => cx.diag(e),
    }
    Ok(())
}

async fn directory(cx: Cx, (state, start, slots): (PageState, u64, u64)) -> Result<()> {
    let Some(span) = state.span() else {
        return Ok(());
    };
    let b = cx.read(span.sub(start, slots.saturating_mul(2))).await?;
    cx.set_count(Count::Exact(slots));
    for i in 0..slots {
        // Slot 0 is the last two bytes before the trailer.
        let at = slots.saturating_sub(1).saturating_sub(i).saturating_mul(2);
        let off = u16_be(&b, to_usize(at)).unwrap_or(0);
        let mut n = Node::new(format!("Slot {i}"))
            .span(span.sub(start.saturating_add(at), 2))
            .value(hex(off, 16));
        if u64::from(off) < span.len {
            n = n.target(span.sub(off.into(), 1));
        }
        cx.push(n).await;
    }
    Ok(())
}
