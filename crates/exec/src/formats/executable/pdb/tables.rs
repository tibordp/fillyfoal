//! PDB hash and string tables: the `/names` string table, the global and
//! public symbol hash streams (GSI) and the TPI/IPI hash streams.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::val::{hex, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;

use super::codeview::{TypeHeader, symbol_at, type_name};

const LE: Endian = Endian::Little;

/// `/names` (and the DBI EC substream): a header, the strings, then a
/// hash table of offsets and the name count.
pub(super) async fn names(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Signature")
        .hex()
        .check(|&v| (v != 0xeffe_effe).then(|| Diagnostic::malformed(format!("signature {v:#x}"))))
        .emit()?;
    f.u32("Hash version").emit()?;
    let size = f.u32("String bytes").emit()?;
    let strings = span.sub(12, size.into());
    cx.emit(
        Node::new("Strings")
            .span(strings)
            .lazy(crate::formats::util::binutil::cstrings, strings),
    );
    let at = 12u64.saturating_add(size.into());
    if at.saturating_add(4) > span.len {
        return Ok(());
    }
    let n = cx.read(span.sub_exact(at, 4)?).await?;
    let buckets = u32_le(&n, 0).unwrap_or(0);
    let table = span.sub(at, u64::from(buckets).saturating_mul(4).saturating_add(4));
    cx.emit(
        Node::new("Hash buckets")
            .span(table)
            .summary(format!("{buckets} buckets"))
            .lazy(words, (table.tail(4), "Bucket")),
    );
    let end = table.end().saturating_sub(span.offset);
    if end.saturating_add(4) <= span.len {
        let c = cx.read(span.sub_exact(end, 4)?).await?;
        cx.emit(
            Node::new("Name count")
                .span(span.sub(end, 4))
                .value(uint(u32_le(&c, 0).unwrap_or(0), 32)),
        );
    }
    Ok(())
}

/// An array of 32-bit words.
async fn words(cx: Cx, (span, label): (Span, &'static str)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        cx.push(
            Node::new(format!("{label} {i}"))
                .span(at)
                .value(hex(u32_le(&data, 0).unwrap_or(0), 32)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Global symbol hash (GSI)

/// Bits in the bucket bitmap: 4096 buckets plus one.
const GSI_BUCKETS: u64 = 4097;

fn gsi_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    f.u32("Version signature").hex().emit()?;
    f.u32("Version").hex().desc("0xf12f091a: V70").emit()?;
    let records = f.u32("Hash record bytes").emit()?;
    let buckets = f.u32("Bucket bytes").emit()?;
    Ok((records, buckets))
}

/// A GSI hash table at the start of `span`, with names resolved through the
/// symbol record stream; returns its size.
async fn gsi(cx: &Cx, span: Span, symbols: Option<Span>) -> Result<u64> {
    let header = span.sub(0, 16);
    cx.emit(struct_node("Hash header", header, LE, (), gsi_header));
    let block = cx.block(header).await?;
    let (records, buckets) = gsi_header(&mut Fields::new(&block, LE), &())?;
    let hr = span.sub(16, records.into());
    cx.emit(
        Node::new("Hash records")
            .span(hr)
            .summary(crate::formats::util::arcutil::count(
                hr.len / 8,
                "record",
                "records",
            ))
            .lazy(hash_records, (hr, symbols)),
    );
    let at = 16u64.saturating_add(records.into());
    if buckets > 0 {
        let bitmap_len = GSI_BUCKETS.div_ceil(32).saturating_mul(4);
        let bitmap = span.sub(at, bitmap_len.min(buckets.into()));
        cx.emit(
            Node::new("Bucket bitmap")
                .span(bitmap)
                .desc("One bit per hash bucket that has records"),
        );
        let offsets = span.sub(
            at.saturating_add(bitmap.len),
            u64::from(buckets).saturating_sub(bitmap.len),
        );
        cx.emit(
            Node::new("Bucket offsets")
                .span(offsets)
                .summary(format!("{} buckets", offsets.len / 4))
                .desc("Offsets into the hash records of the non-empty buckets")
                .lazy(words, (offsets, "Bucket")),
        );
    }
    Ok(at.saturating_add(buckets.into()))
}

async fn hash_records(cx: Cx, (span, symbols): (Span, Option<Span>)) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let off = u32_le(&data, 0).unwrap_or(0);
        let refs = u32_le(&data, 4).unwrap_or(0);
        let mut node = Node::new(format!("Record {i}"))
            .span(at)
            .value(hex(off, 32))
            .desc("Offset + 1 of the symbol in the symbol record stream, and a reference count");
        if let Some(s) = symbols
            && off > 0
            && !cx.skipping()
            && let Ok((kind, name)) = symbol_at(&cx, s, u64::from(off).saturating_sub(1)).await
        {
            node = node.summary(format!("{kind} {name}, {refs} refs"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The global symbol stream: a GSI hash table.
pub(super) async fn globals(cx: Cx, (span, symbols): (Span, Option<Span>)) -> Result<()> {
    let end = gsi(&cx, span, symbols).await?;
    if end < span.len {
        cx.emit(Node::new("Trailing data").span(span.tail(end)));
    }
    Ok(())
}

fn publics_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u32, u32)> {
    let hash = f.u32("Symbol hash bytes").emit()?;
    let map = f.u32("Address map bytes").emit()?;
    let thunks = f.u32("Thunks").emit()?;
    f.u32("Thunk size").emit()?;
    f.u16("Thunk table section").emit()?;
    f.u16("Padding").emit()?;
    f.u32("Thunk table offset").hex().emit()?;
    let sections = f.u32("Sections").emit()?;
    Ok((hash, map, thunks, sections))
}

/// The public symbol stream: a header, a GSI hash table, the address map
/// (symbol offsets sorted by address), the thunk map and the section map.
pub(super) async fn publics(cx: Cx, (span, symbols): (Span, Option<Span>)) -> Result<()> {
    let header = span.sub(0, 28);
    cx.emit(struct_node("Header", header, LE, (), publics_header));
    let block = cx.block(header).await?;
    let (hash, map, thunks, sections) = publics_header(&mut Fields::new(&block, LE), &())?;
    let table = span.sub(28, hash.into());
    cx.emit(
        Node::new("Symbol hash")
            .span(table)
            .lazy(publics_hash, (table, symbols)),
    );
    let mut at = 28u64.saturating_add(hash.into());
    let map_span = span.sub(at, map.into());
    cx.emit(
        Node::new("Address map")
            .span(map_span)
            .summary(crate::formats::util::arcutil::count(
                map_span.len / 4,
                "public",
                "publics",
            ))
            .desc("Offsets of the public symbols in the symbol record stream, by address")
            .lazy(address_map, (map_span, symbols)),
    );
    at = at.saturating_add(map.into());
    let thunk_span = span.sub(at, u64::from(thunks).saturating_mul(4));
    if thunk_span.len > 0 {
        cx.emit(
            Node::new("Thunk map")
                .span(thunk_span)
                .lazy(words, (thunk_span, "Thunk")),
        );
    }
    at = at.saturating_add(thunk_span.len);
    let section_span = span.sub(at, u64::from(sections).saturating_mul(8));
    if section_span.len > 0 {
        cx.emit(
            Node::new("Section map")
                .span(section_span)
                .lazy(thunk_sections, section_span),
        );
    }
    at = at.saturating_add(section_span.len);
    if at < span.len {
        cx.emit(Node::new("Trailing data").span(span.tail(at)));
    }
    Ok(())
}

async fn publics_hash(cx: Cx, (span, symbols): (Span, Option<Span>)) -> Result<()> {
    gsi(&cx, span, symbols).await.map(|_| ())
}

async fn address_map(cx: Cx, (span, symbols): (Span, Option<Span>)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let off = u32_le(&data, 0).unwrap_or(0);
        let mut node = Node::new(format!("Entry {i}")).span(at).value(hex(off, 32));
        if let Some(s) = symbols
            && !cx.skipping()
            && let Ok((kind, name)) = symbol_at(&cx, s, off.into()).await
        {
            node = node.summary(format!("{kind} {name}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn thunk_sections(cx: Cx, span: Span) -> Result<()> {
    for i in 0..span.len / 8 {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let off = u32_le(&data, 0).unwrap_or(0);
        let section = u16_le(&data, 4).unwrap_or(0);
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(at)
                .summary(format!("section {section}, offset {off:#x}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// TPI/IPI hash streams

/// A type hash stream: the hash value of each record, offsets of every
/// few records (for seeking by type index) and hash adjusters, located by
/// the TPI/IPI header.
pub(super) async fn type_hash(cx: Cx, (span, h): (Span, TypeHeader)) -> Result<()> {
    let (off, len) = h.hash_values;
    if len > 0 {
        let s = span.sub(off.into(), len.into());
        cx.emit(
            Node::new("Hash values")
                .span(s)
                .summary(format!(
                    "{} values",
                    s.len.checked_div(u64::from(h.hash_key_size)).unwrap_or(0)
                ))
                .lazy(hash_values, (s, h.first, h.hash_key_size)),
        );
    }
    let (off, len) = h.index_offsets;
    if len > 0 {
        let s = span.sub(off.into(), len.into());
        cx.emit(
            Node::new("Type index offsets")
                .span(s)
                .summary(format!("{} entries", s.len / 8))
                .lazy(index_offsets, s),
        );
    }
    let (off, len) = h.hash_adjusters;
    if len > 0 {
        let s = span.sub(off.into(), len.into());
        cx.emit(
            Node::new("Hash adjusters")
                .span(s)
                .summary(format!("{} entries", s.len / 8))
                .lazy(adjusters, s),
        );
    }
    Ok(())
}

async fn hash_values(cx: Cx, (span, first, size): (Span, u32, u32)) -> Result<()> {
    if size != 4 {
        cx.diag(Diagnostic::unsupported(format!("{size}-byte hash keys")));
        return Ok(());
    }
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(4), 4);
        let data = cx.read(at).await?;
        let ti = first.saturating_add(u32::try_from(i).unwrap_or(u32::MAX));
        cx.push(
            Node::new(type_name(ti))
                .span(at)
                .value(hex(u32_le(&data, 0).unwrap_or(0), 32)),
        )
        .await;
    }
    Ok(())
}

/// Pairs of a type index and a 32-bit value (an offset in the type
/// records, or a name offset for hash adjusters).
async fn index_offsets(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let a = u32_le(&data, 0).unwrap_or(0);
        let b = u32_le(&data, 4).unwrap_or(0);
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(at)
                .value(text(format!("{} → {b:#x}", type_name(a)))),
        )
        .await;
    }
    Ok(())
}

/// Hash adjusters: pairs of a name offset in `/names` and the type index
/// the name's hash bucket should prefer.
async fn adjusters(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = span.sub(i.saturating_mul(8), 8);
        let data = cx.read(at).await?;
        let name = u32_le(&data, 0).unwrap_or(0);
        let ti = u32_le(&data, 4).unwrap_or(0);
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(at)
                .value(text(format!("name {name:#x} → {}", type_name(ti)))),
        )
        .await;
    }
    Ok(())
}
