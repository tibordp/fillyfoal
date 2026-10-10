//! The hint tables of a linearized file (ISO 32000-1, annex F): the page
//! offset hint table at the start of the primary hint stream, the shared
//! object hint table at `/S`, and where the other tables start. Entries are
//! bit-packed: each item is written for every page (or group) in turn,
//! and each such run starts on a byte boundary (as qpdf reads them).

use super::DocRef;
use super::objects::{self, Located};
use super::syntax::Item;
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::Bits;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

/// Hint stream bytes read.
const MAX_HINTS: u64 = 1 << 20;
/// Pages (and shared object groups) decoded.
const MAX_ENTRIES: u64 = 1 << 18;
/// Values read for the per-page lists of shared objects.
const MAX_SHARED: u64 = 1 << 20;

/// Table F.3: (width in bits, name, description).
const PAGE_HEADER: &[(u64, &str, &str)] = &[
    (
        32,
        "Least objects in a page",
        "The fewest objects any page has",
    ),
    (
        32,
        "First page object offset",
        "Where the first page's page object is",
    ),
    (
        16,
        "Bits per object count",
        "Bits per page for its objects beyond the least",
    ),
    (32, "Least page length", "The shortest page, in bytes"),
    (
        16,
        "Bits per page length",
        "Bits per page for its length beyond the least",
    ),
    (
        32,
        "Least content offset",
        "The least offset of a content stream within its page",
    ),
    (
        16,
        "Bits per content offset",
        "Bits per page for its content stream offset beyond the least",
    ),
    (
        32,
        "Least content length",
        "The shortest content stream, in bytes",
    ),
    (
        16,
        "Bits per content length",
        "Bits per page for its content stream length beyond the least",
    ),
    (
        16,
        "Bits per shared reference count",
        "Bits per page for its number of shared objects",
    ),
    (
        16,
        "Bits per shared object identifier",
        "Bits per shared object reference",
    ),
    (
        16,
        "Bits per fraction numerator",
        "Bits per numerator of a shared object's position",
    ),
    (
        16,
        "Fraction denominator",
        "The denominator of shared object positions",
    ),
];

/// Table F.5.
const SHARED_HEADER: &[(u64, &str, &str)] = &[
    (
        32,
        "First shared object",
        "The number of the first object in the shared objects section",
    ),
    (
        32,
        "First shared object offset",
        "Where the shared objects section starts",
    ),
    (
        32,
        "First-page groups",
        "Shared object groups that belong to the first page",
    ),
    (32, "Groups", "All shared object groups"),
    (
        16,
        "Bits per object count",
        "Bits per group for its objects, less one",
    ),
    (32, "Least group length", "The shortest group, in bytes"),
    (
        16,
        "Bits per group length",
        "Bits per group for its length beyond the least",
    ),
];

/// The other tables, by key in the hint stream dictionary.
const OTHER_TABLES: &[(&str, &str)] = &[
    ("T", "Thumbnail hint table"),
    ("O", "Outline hint table"),
    ("A", "Thread information hint table"),
    ("E", "Named destination hint table"),
    ("V", "Interactive form hint table"),
    ("I", "Information dictionary hint table"),
    ("C", "Logical structure hint table"),
    ("L", "Page label hint table"),
    ("R", "Renditions name tree hint table"),
    ("B", "Embedded file stream hint table"),
];

/// `width` (at most 64) bits.
fn read(bits: &mut Bits<'_>, width: u64) -> Option<u64> {
    bits.bits(u32::try_from(width).ok()?)
}

/// Moves to the next byte boundary.
fn align(bits: &mut Bits<'_>) {
    let pad = crate::bytes::padding(to_u64(bits.pos()), 8);
    let _ = bits.skip(to_usize(pad));
}

/// Reads `n` values of `width` bits, then moves to the next byte. Stops
/// early (false) at the end of the data.
async fn read_run(cx: &Cx, bits: &mut Bits<'_>, n: u64, width: u64) -> (Vec<u64>, bool) {
    let mut out = Vec::new();
    for i in 0..n {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        match read(bits, width) {
            Some(v) => out.push(v),
            None => return (out, false),
        }
    }
    align(bits);
    (out, true)
}

/// Reads a table header; `None` if the data ends first.
fn header(bits: &mut Bits<'_>, layout: &[(u64, &str, &str)]) -> Option<Vec<u64>> {
    layout
        .iter()
        .map(|&(width, _, _)| read(bits, width))
        .collect()
}

/// The primary hint stream's data: its tables.
pub async fn hint_tables(cx: Cx, (doc, located): (DocRef, Located)) -> Result<()> {
    let decoded = objects::decode(&cx, &located, doc.security.as_ref()).await?;
    cx.annotate(format!("{:#x} bytes decoded", decoded.len));
    let pages = doc
        .linearized
        .as_ref()
        .and_then(|l| l.item.get("N"))
        .and_then(Item::int)
        .and_then(|n| u64::try_from(n).ok())
        .unwrap_or(0);
    let offset = |k: &str| {
        located
            .item
            .get(k)
            .and_then(Item::int)
            .and_then(|n| u64::try_from(n).ok())
    };
    // Where each table starts; each ends where the next begins.
    let mut tables: Vec<(u64, &str, &str)> = vec![(0, "P", "Page offset hint table")];
    if let Some(at) = offset("S") {
        tables.push((at, "S", "Shared object hint table"));
    }
    for &(key, name) in OTHER_TABLES {
        if let Some(at) = offset(key) {
            tables.push((at, key, name));
        }
    }
    tables.sort_unstable();
    let ends: Vec<u64> = tables
        .iter()
        .skip(1)
        .map(|t| t.0)
        .chain(std::iter::once(decoded.len))
        .collect();
    for (&(at, key, name), &end) in tables.iter().zip(&ends) {
        let span = decoded.sub(at, end.saturating_sub(at));
        let node = Node::new(name).span(span);
        let node = match key {
            "P" => node.summary(plural(pages, "page")).lazy(
                crate::expander!(self::page_table: (Span, u64)),
                (span, pages),
            ),
            "S" => node.lazy(crate::expander!(self::shared_table: Span), span),
            _ => node.summary(format!("at {at:#x}")),
        };
        cx.emit(node);
    }
    Ok(())
}

/// Emits the header fields of a table read from `span`.
fn emit_header(cx: &Cx, span: Span, layout: &[(u64, &'static str, &'static str)], values: &[u64]) {
    let mut at = 0u64;
    for (&(width, name, desc), &value) in layout.iter().zip(values) {
        let bytes = width / 8;
        cx.emit(
            Node::new(name)
                .span(span.sub(at, bytes))
                .value(Value::UInt {
                    value,
                    bits: u8::try_from(width).unwrap_or(64),
                    radix: Radix::Dec,
                })
                .desc(desc),
        );
        at = at.saturating_add(bytes);
    }
}

async fn page_table(cx: Cx, (span, pages): (Span, u64)) -> Result<()> {
    let data = cx.read(span.sub(0, MAX_HINTS)).await?;
    let mut bits = Bits::new(&data);
    let Some(h) = header(&mut bits, PAGE_HEADER) else {
        return Err(Diagnostic::malformed("page offset hint table header is truncated").at(span));
    };
    emit_header(&cx, span, PAGE_HEADER, &h);
    let at = |i: usize| h.get(i).copied().unwrap_or(0);
    let entries_at = to_u64(bits.pos() / 8);
    cx.emit(
        Node::new("Pages")
            .span(span.tail(entries_at))
            .summary(plural(pages, "page"))
            .desc("Per page: objects, length, shared objects, content stream position")
            .lazy(
                crate::expander!(self::page_entries: (Span, u64, Vec<u64>)),
                (span, pages, h.clone()),
            ),
    );
    if at(12) == 0 && at(11) > 0 {
        cx.diag(Diagnostic::warning("fraction denominator is 0"));
    }
    Ok(())
}

async fn page_entries(cx: Cx, (span, pages, h): (Span, u64, Vec<u64>)) -> Result<()> {
    if pages > MAX_ENTRIES {
        return Err(Diagnostic::limit(format!(
            "hint tables for more than {MAX_ENTRIES} pages"
        )));
    }
    let data = cx.read(span.sub(0, MAX_HINTS)).await?;
    let mut bits = Bits::new(&data);
    header(&mut bits, PAGE_HEADER);
    let at = |i: usize| h.get(i).copied().unwrap_or(0);
    let mut complete = true;
    let (objects, ok) = read_run(&cx, &mut bits, pages, at(2)).await;
    complete &= ok;
    let (lengths, ok) = read_run(&cx, &mut bits, pages, at(4)).await;
    complete &= ok;
    let (shared, ok) = read_run(&cx, &mut bits, pages, at(9)).await;
    complete &= ok;
    // Per page, its shared object identifiers, then (all pages again) the
    // numerators of their positions.
    let total: u64 = shared.iter().fold(0u64, |a, &n| a.saturating_add(n));
    if total > MAX_SHARED {
        return Err(Diagnostic::limit(format!(
            "more than {MAX_SHARED} shared object references"
        )));
    }
    let (ids, ok) = read_run(&cx, &mut bits, total, at(10)).await;
    complete &= ok;
    let (_numerators, ok) = read_run(&cx, &mut bits, total, at(11)).await;
    complete &= ok;
    let (content_offsets, ok) = read_run(&cx, &mut bits, pages, at(6)).await;
    complete &= ok;
    let (content_lengths, ok) = read_run(&cx, &mut bits, pages, at(8)).await;
    complete &= ok;
    if !complete {
        cx.diag(Diagnostic::malformed("page offset hint table is truncated"));
    }
    cx.set_count(Count::Exact(to_u64(objects.len())));
    let mut next_id = 0usize;
    for (i, &delta) in objects.iter().enumerate() {
        let get = |v: &[u64]| v.get(i).copied();
        let mut parts = vec![format!("{} objects", at(0).saturating_add(delta))];
        if let Some(len) = get(&lengths) {
            parts.push(format!("{} bytes", at(3).saturating_add(len)));
        }
        if let Some(n) = get(&shared) {
            let n = to_usize(n);
            let list: Vec<String> = ids
                .get(next_id..next_id.saturating_add(n).min(ids.len()))
                .unwrap_or_default()
                .iter()
                .take(8)
                .map(u64::to_string)
                .collect();
            next_id = next_id.saturating_add(n);
            if n > 0 {
                let more = if n > 8 { ", …" } else { "" };
                parts.push(format!(
                    "{} ({}{more})",
                    plural(to_u64(n), "shared object group"),
                    list.join(", ")
                ));
            }
        }
        if let (Some(off), Some(len)) = (get(&content_offsets), get(&content_lengths)) {
            parts.push(format!(
                "content at +{}, {} bytes",
                at(5).saturating_add(off),
                at(7).saturating_add(len)
            ));
        }
        cx.push(Node::new(format!("Page {}", i.saturating_add(1))).summary(parts.join(", ")))
            .await;
    }
    Ok(())
}

async fn shared_table(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span.sub(0, MAX_HINTS)).await?;
    let mut bits = Bits::new(&data);
    let Some(h) = header(&mut bits, SHARED_HEADER) else {
        return Err(Diagnostic::malformed("shared object hint table header is truncated").at(span));
    };
    emit_header(&cx, span, SHARED_HEADER, &h);
    let at = |i: usize| h.get(i).copied().unwrap_or(0);
    let groups = at(3);
    cx.annotate(plural(groups, "group"));
    let entries_at = to_u64(bits.pos() / 8);
    cx.emit(
        Node::new("Groups")
            .span(span.tail(entries_at))
            .summary(plural(groups, "group"))
            .desc("Per group: length, objects, MD5 signature")
            .lazy(
                crate::expander!(self::shared_entries: (Span, Vec<u64>)),
                (span, h.clone()),
            ),
    );
    Ok(())
}

async fn shared_entries(cx: Cx, (span, h): (Span, Vec<u64>)) -> Result<()> {
    let at = |i: usize| h.get(i).copied().unwrap_or(0);
    let groups = at(3);
    if groups > MAX_ENTRIES {
        return Err(Diagnostic::limit(format!(
            "more than {MAX_ENTRIES} shared object groups"
        )));
    }
    let data = cx.read(span.sub(0, MAX_HINTS)).await?;
    let mut bits = Bits::new(&data);
    header(&mut bits, SHARED_HEADER);
    let mut complete = true;
    let (lengths, ok) = read_run(&cx, &mut bits, groups, at(6)).await;
    complete &= ok;
    let (signed, ok) = read_run(&cx, &mut bits, groups, 1).await;
    complete &= ok;
    for (i, &flag) in signed.iter().enumerate() {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if flag != 0 && (bits.bits(64).is_none() || bits.bits(64).is_none()) {
            complete = false;
        }
    }
    align(&mut bits);
    let (objects, ok) = read_run(&cx, &mut bits, groups, at(4)).await;
    complete &= ok;
    if !complete {
        cx.diag(Diagnostic::malformed(
            "shared object hint table is truncated",
        ));
    }
    cx.set_count(Count::Exact(to_u64(lengths.len())));
    for (i, &len) in lengths.iter().enumerate() {
        let mut summary = format!("{} bytes", at(5).saturating_add(len));
        if let Some(n) = objects.get(i) {
            let n = n.saturating_add(1);
            summary = format!("{summary}, {}", plural(n, "object"));
        }
        if signed.get(i).is_some_and(|&s| s != 0) {
            summary.push_str(", MD5 signature");
        }
        if to_u64(i) < at(2) {
            summary.push_str(" (first page)");
        }
        cx.push(Node::new(format!("Group {i}")).summary(summary))
            .await;
    }
    Ok(())
}
