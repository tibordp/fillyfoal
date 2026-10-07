//! .NET serialization: `.resources` files (`ResourceWriter` output, also
//! embedded as manifest resources in assemblies) and BinaryFormatter
//! streams (MS-NRBF).
//!
//! Both layouts are written from memory of the .NET reference source
//! (`ResourceReader`, `ResourceWriter`, `FastResourceComparer`) and of the
//! MS-NRBF specification; the fixtures are synthetic, built by
//! `tests/data/dotnet-resources/make.py` from the same understanding (no .NET
//! SDK was available to produce real files). The name hashes are checked
//! against the reader's hash function, which is a useful self-consistency
//! check but not proof.
//!
//! A `.resources` file starts with the resource manager header (magic
//! `0xBEEFCACE`, the reader and resource set type names), then the resource
//! set header (version, count, type table, padding to 8 bytes, the sorted
//! name hashes and the name positions, the data section offset), the name
//! section (UTF-16 names, each with the offset of its value) and the data
//! section. Version 2 values start with a type code (primitives, strings,
//! `DateTime`, `TimeSpan`, byte arrays and streams, or an index into the
//! type table for serialized objects); version 1 values start with an index
//! into the type table.
//!
//! A BinaryFormatter stream is a sequence of records (header, libraries,
//! class records with member metadata and values, strings, arrays, member
//! references, nulls) ended by `MessageEnd`. Nested values are written
//! inline, so the stream is decoded up front into a tree and displayed
//! lazily. Byte arrays are offered as embedded content (a `Bitmap` holds a
//! PNG), member references point at the object they refer to.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{NodeExt, Reader, Tree, dec, ellipsize, hex, text};
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
/// Largest name section or BinaryFormatter stream decoded in memory.
const MAX_DECODE: u64 = 16 << 20;
/// How deeply BinaryFormatter values may nest.
const MAX_DEPTH: u32 = 64;
/// Primitive array elements shown one by one; the rest is one raw node.
const MAX_ELEMENTS: u64 = 256;
/// Bytes of a value read to summarise it in the resource list.
const SUMMARY_READ: u64 = 4096;

// ---------------------------------------------------------------------------
// Shared: 7-bit encoded integers and length-prefixed strings

/// .NET's `Read7BitEncodedInt`: up to five bytes, low groups first.
fn read7(r: &mut Reader<'_>) -> Option<u32> {
    let mut value = 0u32;
    for i in 0..5u32 {
        let b = r.u8()?;
        value |= u32::from(b & 0x7f)
            .checked_shl(i.saturating_mul(7))
            .unwrap_or(0);
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

async fn cursor7(cur: &mut Cursor<'_>) -> Result<u32> {
    let start = cur.pos();
    let mut value = 0u32;
    for i in 0..5u32 {
        let b = cur.u8().await?;
        value |= u32::from(b & 0x7f)
            .checked_shl(i.saturating_mul(7))
            .unwrap_or(0);
        if b & 0x80 == 0 {
            return Ok(value);
        }
    }
    Err(Diagnostic::malformed("bad 7-bit encoded length").at(cur.since(start)))
}

/// A `BinaryWriter` string: 7-bit byte count, then UTF-8.
async fn cursor_string(cur: &mut Cursor<'_>) -> Result<(String, Span)> {
    let start = cur.pos();
    let len = cursor7(cur).await?;
    let raw = cur.bytes(len.into()).await?;
    Ok((String::from_utf8_lossy(&raw).into_owned(), cur.since(start)))
}

fn reader_string(r: &mut Reader<'_>) -> Option<String> {
    let len = read7(r)?;
    let raw = r.bytes(to_usize(len.into()))?;
    Some(String::from_utf8_lossy(raw).into_owned())
}

/// The type name without its assembly qualification.
fn short_type(name: &str) -> &str {
    name.split(',').next().unwrap_or_default().trim()
}

/// `FastResourceComparer.HashFunction`: djb2 with XOR over UTF-16 units.
fn name_hash(name: &str) -> u32 {
    name.encode_utf16().fold(5381u32, |h, c| {
        (h.wrapping_shl(5).wrapping_add(h)) ^ u32::from(c)
    })
}

/// A `System.Decimal` from its four 32-bit parts (`decimal.GetBits`).
fn decimal(lo: u32, mid: u32, hi: u32, flags: u32) -> String {
    let mantissa = u128::from(lo) | (u128::from(mid) << 32) | (u128::from(hi) << 64);
    let scale = to_usize(u64::from((flags >> 16) & 0xff)).min(28);
    let mut digits = mantissa.to_string();
    if scale > 0 {
        while digits.len() <= scale {
            digits.insert(0, '0');
        }
        digits.insert(digits.len().saturating_sub(scale), '.');
    }
    if flags & 0x8000_0000 != 0 {
        digits.insert(0, '-');
    }
    digits
}

/// `TimeSpan.ToString()`: `[-][d.]hh:mm:ss[.fffffff]`.
fn timespan(ticks: i64) -> String {
    let neg = ticks < 0;
    let t = ticks.unsigned_abs();
    let fraction = t % 10_000_000;
    let seconds = t / 10_000_000;
    let (days, h, m, s) = (
        seconds / 86_400,
        (seconds / 3600) % 24,
        (seconds / 60) % 60,
        seconds % 60,
    );
    let mut out = String::new();
    if neg {
        out.push('-');
    }
    if days > 0 {
        out.push_str(&format!("{days}."));
    }
    out.push_str(&format!("{h:02}:{m:02}:{s:02}"));
    if fraction > 0 {
        out.push_str(&format!(".{fraction:07}"));
    }
    out
}

/// A `DateTime.ToBinary()` value: ticks since 0001-01-01 and the kind in
/// the top two bits.
fn datetime(raw: i64) -> (Value, String) {
    let bits = raw as u64;
    let kind = match bits >> 62 {
        0 => "unspecified",
        1 => "UTC",
        _ => "local",
    };
    let ticks = bits & 0x3fff_ffff_ffff_ffff;
    let unix = i64::try_from(ticks / 10_000_000)
        .unwrap_or(0)
        .saturating_sub(62_135_596_800);
    (
        Value::Timestamp { unix_seconds: unix },
        format!("{kind}, {ticks} ticks"),
    )
}

// ---------------------------------------------------------------------------
// .NET resources

declare_format!(pub DOTNET_RESOURCES = "dotnet-resources", ".NET resources", ["resources"], "application/x-dotnet-resources",
    Probe::Magic(&[(0, b"\xce\xca\xef\xbe")]), dotnet_resources);

const TYPE_CODES: EnumTable = &[
    (0x00, "Null"),
    (0x01, "String"),
    (0x02, "Boolean"),
    (0x03, "Char"),
    (0x04, "Byte"),
    (0x05, "SByte"),
    (0x06, "Int16"),
    (0x07, "UInt16"),
    (0x08, "Int32"),
    (0x09, "UInt32"),
    (0x0a, "Int64"),
    (0x0b, "UInt64"),
    (0x0c, "Single"),
    (0x0d, "Double"),
    (0x0e, "Decimal"),
    (0x0f, "DateTime"),
    (0x10, "TimeSpan"),
    (0x20, "ByteArray"),
    (0x21, "Stream"),
];

const SERIALIZATION_FORMATS: EnumTable = &[
    (1, "BinaryFormatter"),
    (2, "TypeConverter (byte array)"),
    (3, "TypeConverter (string)"),
    (4, "Activator (stream)"),
];

/// Everything the headers say, with where they say it.
struct Headers {
    manager: Span,
    magic: Span,
    manager_version: (u32, Span),
    skip: (u32, Span),
    reader_type: Option<(String, Span)>,
    set_type: Option<(String, Span)>,
    set: Span,
    version: (u32, Span),
    count: (u32, Span),
    type_count: (u32, Span),
    types: Vec<(String, Span)>,
    padding: Span,
    hashes: Span,
    positions: Span,
    data_offset: (u32, Span),
    names: Span,
    data: Span,
    /// `System.Resources.Extensions` files carry a serialization format
    /// and length before each user-type value.
    extensions: bool,
}

#[derive(Clone)]
struct Entry {
    /// Index in hash order (into the hash and position tables).
    index: u32,
    name: String,
    /// The name and its data offset.
    record: Span,
    name_span: Span,
    offset_span: Span,
    data_offset: u32,
    hash: Option<u32>,
    /// The value's bytes: from its offset to the next value (or the end).
    data: Span,
}

async fn headers(cx: &Cx, file: Span) -> Result<Headers> {
    let mut cur = Cursor::new(cx, file, LE);
    let magic = cur.span(4);
    cur.skip(4);
    let at = cur.pos();
    let manager_version = (cur.u32().await?, cur.since(at));
    let at = cur.pos();
    let skip = (cur.u32().await?, cur.since(at));
    let body = cur.pos();
    let (reader_type, set_type) = if manager_version.0 == 1 {
        (
            Some(cursor_string(&mut cur).await?),
            Some(cursor_string(&mut cur).await?),
        )
    } else {
        (None, None)
    };
    cur.seek(body.saturating_add(skip.0.into()));
    let manager = cur.since(0);
    let set_start = cur.pos();
    let at = cur.pos();
    let version = (cur.u32().await?, cur.since(at));
    let at = cur.pos();
    let count = (cur.u32().await?, cur.since(at));
    let at = cur.pos();
    let type_count = (cur.u32().await?, cur.since(at));
    let mut types = Vec::new();
    for _ in 0..type_count.0 {
        types.push(cursor_string(&mut cur).await?);
    }
    // Padded with "PAD" to a multiple of 8 from the start of the stream.
    let pad = (8u64.saturating_sub(cur.pos() & 7)) & 7;
    let padding = cur.span(pad);
    cur.skip(pad);
    let table = u64::from(count.0).saturating_mul(4);
    let hashes = file.sub_exact(cur.pos(), table)?;
    cur.skip(table);
    let positions = file.sub_exact(cur.pos(), table)?;
    cur.skip(table);
    let at = cur.pos();
    let data_offset = (cur.u32().await?, cur.since(at));
    let names_start = cur.pos();
    let data_start = u64::from(data_offset.0);
    if data_start < names_start || data_start > file.len {
        return Err(Diagnostic::malformed(format!(
            "data section offset {data_start:#x} is outside the file"
        ))
        .at(data_offset.1));
    }
    let set = file.sub(set_start, names_start.saturating_sub(set_start));
    let extensions = reader_type
        .as_ref()
        .is_some_and(|(t, _)| t.contains("DeserializingResourceReader"));
    Ok(Headers {
        manager,
        magic,
        manager_version,
        skip,
        reader_type,
        set_type,
        set,
        version,
        count,
        type_count,
        types,
        padding,
        hashes,
        positions,
        data_offset,
        names: file.sub(names_start, data_start.saturating_sub(names_start)),
        data: file.tail(data_start),
        extensions,
    })
}

async fn dotnet_resources(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = Arc::new(headers(&cx, file).await?);
    let reader = h
        .reader_type
        .as_ref()
        .map(|(t, _)| {
            short_type(t)
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .unwrap_or_default();
    let set = h
        .set_type
        .as_ref()
        .map(|(t, _)| {
            short_type(t)
                .rsplit('.')
                .next()
                .unwrap_or_default()
                .to_owned()
        })
        .unwrap_or_default();
    cx.emit(
        Node::new("Resource manager header")
            .span(h.manager)
            .summary(format!("version {}, {reader}, {set}", h.manager_version.0))
            .lazy(manager_fields, h.clone()),
    );
    cx.emit(
        Node::new("Resource set header")
            .span(h.set)
            .summary(format!(
                "version {}, {} resources, {} types",
                h.version.0, h.count.0, h.type_count.0
            ))
            .lazy(set_fields, h.clone()),
    );
    let entries = entries(&cx, file, &h).await;
    match &entries {
        Ok(entries) => {
            let mut kinds: BTreeMap<String, u64> = BTreeMap::new();
            for e in entries.iter().take(64) {
                let kind = value_kind(&cx, &h, e).await;
                let n = kinds.entry(kind).or_insert(0);
                *n = n.saturating_add(1);
            }
            cx.emit(
                Node::new("Resources")
                    .span(h.names)
                    .summary(format!("{} resources", entries.len()))
                    .lazy(resource_list, (h.clone(), input)),
            );
            let mix = kinds
                .iter()
                .map(|(k, n)| format!("{n} {k}"))
                .collect::<Vec<_>>()
                .join(", ");
            let more = if entries.len() > 64 { ", …" } else { "" };
            cx.annotate(format!(
                ".NET resources v{}, {} resources ({mix}{more})",
                h.version.0,
                entries.len()
            ));
        }
        Err(e) => {
            cx.emit(Node::new("Names").span(h.names).diag(e.clone()));
            cx.annotate(format!(
                ".NET resources v{}, {} resources",
                h.version.0, h.count.0
            ));
        }
    }
    cx.emit(Node::new("Data section").span(h.data));
    Ok(())
}

async fn manager_fields(cx: Cx, h: Arc<Headers>) -> Result<()> {
    cx.emit(Node::new("Magic").span(h.magic).value(hex(0xbeef_cace, 32)));
    cx.emit(
        Node::new("Header version")
            .span(h.manager_version.1)
            .value(dec(h.manager_version.0.into(), 32)),
    );
    cx.emit(
        Node::new("Header length")
            .span(h.skip.1)
            .value(dec(h.skip.0.into(), 32))
            .desc("Bytes of type names that follow (readers skip unknown header versions)"),
    );
    if let Some((t, span)) = &h.reader_type {
        cx.emit(Node::new("Reader type").span(*span).value(text(t.clone())));
    }
    if let Some((t, span)) = &h.set_type {
        cx.emit(
            Node::new("Resource set type")
                .span(*span)
                .value(text(t.clone())),
        );
    }
    Ok(())
}

async fn set_fields(cx: Cx, h: Arc<Headers>) -> Result<()> {
    cx.emit(
        Node::new("Version")
            .span(h.version.1)
            .value(dec(h.version.0.into(), 32)),
    );
    cx.emit(
        Node::new("Resource count")
            .span(h.count.1)
            .value(dec(h.count.0.into(), 32)),
    );
    cx.emit(
        Node::new("Type count")
            .span(h.type_count.1)
            .value(dec(h.type_count.0.into(), 32)),
    );
    if !h.types.is_empty() {
        let first = h.types.first().map(|(_, s)| *s);
        let last = h.types.last().map(|(_, s)| *s);
        let span = match (first, last) {
            (Some(a), Some(b)) => Span::new(a.source, a.offset, b.end().saturating_sub(a.offset)),
            _ => h.set,
        };
        cx.emit(
            Node::new("Types")
                .span(span)
                .summary(format!("{} types", h.types.len()))
                .lazy(type_list, h.clone()),
        );
    }
    if h.padding.len > 0 {
        cx.emit(
            Node::new("Padding")
                .span(h.padding)
                .desc("\"PAD\" repeated to an 8-byte boundary"),
        );
    }
    cx.emit(
        Node::new("Name hashes")
            .span(h.hashes)
            .summary(format!("{} hashes, sorted as signed integers", h.count.0))
            .lazy(int_table, (h.hashes, true)),
    );
    cx.emit(
        Node::new("Name positions")
            .span(h.positions)
            .summary("offsets into the name section, in hash order")
            .lazy(int_table, (h.positions, false)),
    );
    cx.emit(
        Node::new("Data section offset")
            .span(h.data_offset.1)
            .value(hex(h.data_offset.0.into(), 32))
            .target(h.data),
    );
    Ok(())
}

async fn type_list(cx: Cx, h: Arc<Headers>) -> Result<()> {
    for (i, (t, span)) in h.types.iter().enumerate() {
        cx.push(
            Node::new(format!("[{i}]"))
                .span(*span)
                .value(text(t.clone())),
        )
        .await;
    }
    Ok(())
}

async fn int_table(cx: Cx, (span, as_hex): (Span, bool)) -> Result<()> {
    let count = span.len / 4;
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let field = span.sub(i.saturating_mul(4), 4);
        let raw = cx.read(field).await?;
        let v = u32_le(&raw, 0).unwrap_or(0);
        let value = if as_hex {
            hex(v.into(), 32)
        } else {
            dec(v.into(), 32)
        };
        cx.push(Node::new(format!("[{i}]")).span(field).value(value))
            .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// The name section, in file order (the writer sorts it by name).
async fn entries(cx: &Cx, file: Span, h: &Headers) -> Result<Arc<Vec<Entry>>> {
    if let Some(e) = cx.cached::<Vec<Entry>>(file, "dotnet-resources") {
        return Ok(e);
    }
    if h.names.len > MAX_DECODE {
        return Err(Diagnostic::limit("name section over 16 MiB").at(h.names));
    }
    let names = cx.read(h.names).await?;
    let positions = cx.read(h.positions).await?;
    let hashes = cx.read(h.hashes).await?;
    let mut order: Vec<(u32, u32)> = (0..h.count.0)
        .filter_map(|i| {
            let p = u32_le(&positions, to_usize(u64::from(i).saturating_mul(4)))?;
            Some((p, i))
        })
        .collect();
    order.sort_unstable();
    let mut out = Vec::with_capacity(order.len());
    for (pos, index) in order {
        let mut r = Reader::at(&names, to_usize(pos.into()));
        let Some(len) = read7(&mut r) else {
            break;
        };
        let name_at = r.pos();
        let Some(raw) = r.bytes(to_usize(len.into())) else {
            break;
        };
        let name = crate::text::utf16(raw, LE);
        let off_at = r.pos();
        let Some(data_offset) = r.int::<u32>(LE) else {
            break;
        };
        let start = u64::from(pos);
        out.push(Entry {
            index,
            name,
            record: h.names.sub(start, to_u64(r.pos()).saturating_sub(start)),
            name_span: h.names.sub(to_u64(name_at), len.into()),
            offset_span: h.names.sub(to_u64(off_at), 4),
            data_offset,
            hash: u32_le(&hashes, to_usize(u64::from(index).saturating_mul(4))),
            data: h.data,
        });
    }
    // Each value runs to the next one in the data section.
    let mut offsets: Vec<u32> = out.iter().map(|e| e.data_offset).collect();
    offsets.sort_unstable();
    offsets.dedup();
    for e in &mut out {
        let start = u64::from(e.data_offset);
        let end = offsets
            .iter()
            .find(|&&o| o > e.data_offset)
            .map_or(h.data.len, |&o| u64::from(o));
        e.data = h.data.sub(start, end.saturating_sub(start));
    }
    let out = Arc::new(out);
    cx.cache(file, "dotnet-resources", out.clone());
    Ok(out)
}

async fn resource_list(cx: Cx, (h, input): (Arc<Headers>, Input)) -> Result<()> {
    let entries = entries(&cx, input.span, &h).await?;
    cx.set_count(Count::Exact(to_u64(entries.len())));
    let mut i = cx.resume::<usize>().unwrap_or(0);
    while let Some(e) = entries.get(i) {
        let at = i;
        cx.mark(move || at);
        let mut node = Node::new(e.name.clone()).span(e.data);
        if !cx.skipping() {
            let v = decode_value(&cx, &h, e, &input, false).await;
            node = match v {
                Ok(v) => {
                    let node = match v.value {
                        Some(value) => node.value(value),
                        None => node,
                    };
                    node.summary(v.summary)
                }
                Err(d) => node.diag(d),
            };
        }
        cx.push(node.lazy(resource, (h.clone(), e.clone(), input)))
            .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn value_kind(cx: &Cx, h: &Headers, e: &Entry) -> String {
    let raw = cx.read_avail(e.data.sub(0, 5)).await.unwrap_or_default();
    let mut r = Reader::new(&raw);
    let Some(code) = read7(&mut r) else {
        return "unreadable".into();
    };
    if h.version.0 == 1 {
        return h
            .types
            .get(to_usize(code.into()))
            .map_or("null".into(), |(t, _)| short_type(t).to_owned());
    }
    match code {
        0x00..=0x21 => lookup(TYPE_CODES, code.into())
            .unwrap_or("unknown")
            .to_owned(),
        _ => h
            .types
            .get(to_usize(u64::from(code).saturating_sub(0x40)))
            .map_or("unknown".into(), |(t, _)| short_type(t).to_owned()),
    }
}

struct Decoded {
    value: Option<Value>,
    summary: String,
    children: Vec<Node>,
}

/// Decodes a value. With `full`, also builds the child nodes (and reads as
/// much as the value needs); otherwise reads only enough to summarise it.
async fn decode_value(
    cx: &Cx,
    h: &Headers,
    e: &Entry,
    input: &Input,
    full: bool,
) -> Result<Decoded> {
    let want = if full {
        e.data.len.min(MAX_DECODE)
    } else {
        e.data.len.min(SUMMARY_READ)
    };
    let raw = cx.read_avail(e.data.sub(0, want)).await?;
    let mut r = Reader::new(&raw);
    let at = |from: usize, to: usize| e.data.sub(to_u64(from), to_u64(to.saturating_sub(from)));
    let short = || Diagnostic::truncated(e.data, to_u64(raw.len()));
    let code = read7(&mut r).ok_or_else(short)?;
    let code_span = at(0, r.pos());
    let mut children = Vec::new();
    // Version 1: an index into the type table (-1 for null), mapped onto
    // the version 2 codes for the primitive types.
    let (code, type_name) = if h.version.0 == 1 {
        let name = h.types.get(to_usize(code.into())).map(|(t, _)| t.clone());
        children.push(
            Node::new("Type index")
                .span(code_span)
                .value(Value::Int {
                    value: i64::from(code as i32),
                    bits: 32,
                })
                .summary(name.as_deref().map_or("null", short_type).to_owned()),
        );
        let mapped = match name.as_deref().map(short_type) {
            None => 0x00,
            Some("System.String") => 0x01,
            Some("System.Boolean") => 0x02,
            Some("System.Char") => 0x03,
            Some("System.Byte") => 0x04,
            Some("System.SByte") => 0x05,
            Some("System.Int16") => 0x06,
            Some("System.UInt16") => 0x07,
            Some("System.Int32") => 0x08,
            Some("System.UInt32") => 0x09,
            Some("System.Int64") => 0x0a,
            Some("System.UInt64") => 0x0b,
            Some("System.Single") => 0x0c,
            Some("System.Double") => 0x0d,
            Some("System.Decimal") => 0x0e,
            Some("System.DateTime") => 0x0f,
            Some("System.TimeSpan") => 0x10,
            Some(_) => 0x40,
        };
        (mapped, name)
    } else {
        let name = code
            .checked_sub(0x40)
            .and_then(|i| h.types.get(to_usize(i.into())))
            .map(|(t, _)| t.clone());
        children.push(
            Node::new("Type code")
                .span(code_span)
                .value(Value::Enum {
                    raw: code.into(),
                    bits: 32,
                    name: lookup(TYPE_CODES, code.into()),
                })
                .maybe_summary(name.as_deref().map(short_type).unwrap_or_default()),
        );
        (code, name)
    };
    let start = r.pos();
    let mut value_start = start;
    let (value, summary) = match code {
        0x00 => (None, "null".to_owned()),
        0x01 => {
            let len = read7(&mut r).ok_or_else(short)?;
            let body = r.pos();
            value_start = body;
            let s = match r.bytes(to_usize(len.into())) {
                Some(b) => String::from_utf8_lossy(b).into_owned(),
                // Long strings are read in full only when expanded.
                None if !full => {
                    let rest = r.rest();
                    let mut s = String::from_utf8_lossy(rest).into_owned();
                    s.push('…');
                    s
                }
                None => return Err(short()),
            };
            if full {
                children.push(
                    Node::new("Length")
                        .span(at(start, body))
                        .value(dec(len.into(), 32)),
                );
            }
            let summary = format!("String, {} characters", s.chars().count());
            (Some(text(s)), summary)
        }
        0x02 => (
            Some(Value::Bool(r.u8().ok_or_else(short)? != 0)),
            "Boolean".into(),
        ),
        0x03 => {
            let c = r.int::<u16>(LE).ok_or_else(short)?;
            let s = String::from_utf16_lossy(&[c]);
            (Some(text(s)), format!("Char U+{c:04X}"))
        }
        0x04 => (
            Some(dec(r.u8().ok_or_else(short)?.into(), 8)),
            "Byte".into(),
        ),
        0x05 => (
            Some(Value::Int {
                value: i64::from(r.u8().ok_or_else(short)? as i8),
                bits: 8,
            }),
            "SByte".into(),
        ),
        0x06 => (
            Some(Value::Int {
                value: r.int::<i16>(LE).ok_or_else(short)?.into(),
                bits: 16,
            }),
            "Int16".into(),
        ),
        0x07 => (
            Some(dec(r.int::<u16>(LE).ok_or_else(short)?.into(), 16)),
            "UInt16".into(),
        ),
        0x08 => (
            Some(Value::Int {
                value: r.int::<i32>(LE).ok_or_else(short)?.into(),
                bits: 32,
            }),
            "Int32".into(),
        ),
        0x09 => (
            Some(dec(r.int::<u32>(LE).ok_or_else(short)?.into(), 32)),
            "UInt32".into(),
        ),
        0x0a => (
            Some(Value::Int {
                value: r.int::<i64>(LE).ok_or_else(short)?,
                bits: 64,
            }),
            "Int64".into(),
        ),
        0x0b => (
            Some(dec(r.int::<u64>(LE).ok_or_else(short)?, 64)),
            "UInt64".into(),
        ),
        0x0c => (
            Some(Value::Float(r.int::<f32>(LE).ok_or_else(short)?.into())),
            "Single".into(),
        ),
        0x0d => (
            Some(Value::Float(r.int::<f64>(LE).ok_or_else(short)?)),
            "Double".into(),
        ),
        0x0e => {
            let parts: Option<Vec<u32>> = (0..4).map(|_| r.int::<u32>(LE)).collect();
            let p = parts.ok_or_else(short)?;
            let get = |i: usize| p.get(i).copied().unwrap_or(0);
            (
                Some(text(decimal(get(0), get(1), get(2), get(3)))),
                "Decimal".into(),
            )
        }
        0x0f => {
            let (v, s) = datetime(r.int::<i64>(LE).ok_or_else(short)?);
            (Some(v), format!("DateTime ({s})"))
        }
        0x10 => {
            let ticks = r.int::<i64>(LE).ok_or_else(short)?;
            (Some(text(timespan(ticks))), "TimeSpan".into())
        }
        0x20 | 0x21 => {
            let len = r.int::<u32>(LE).ok_or_else(short)?;
            let body = r.pos();
            let payload = e.data.sub(to_u64(body), len.into());
            let kind = if code == 0x20 { "Byte array" } else { "Stream" };
            if full {
                children.push(
                    Node::new("Length")
                        .span(at(start, body))
                        .value(dec(len.into(), 32)),
                );
                let node = embedded("Data", input.nested(payload));
                children.push(if payload.len < u64::from(len) {
                    node.diag(Diagnostic::truncated(
                        Span::new(payload.source, payload.offset, len.into()),
                        payload.len,
                    ))
                } else {
                    node
                });
            }
            (None, format!("{kind}, {len} bytes"))
        }
        0x11..=0x1f | 0x22..=0x3f => {
            return Err(
                Diagnostic::malformed(format!("unknown type code {code:#x}")).at(code_span),
            );
        }
        _ => {
            let ty = type_name
                .as_deref()
                .map(short_type)
                .unwrap_or("unknown type")
                .to_owned();
            let mut payload = e.data.tail(to_u64(start));
            let mut format = 1;
            if h.extensions {
                let f_at = r.pos();
                format = read7(&mut r).ok_or_else(short)?;
                let l_at = r.pos();
                let len = read7(&mut r).ok_or_else(short)?;
                let body = r.pos();
                payload = e.data.sub(to_u64(body), len.into());
                if full {
                    children.push(
                        Node::new("Serialization format")
                            .span(at(f_at, l_at))
                            .value(Value::Enum {
                                raw: format.into(),
                                bits: 32,
                                name: lookup(SERIALIZATION_FORMATS, format.into()),
                            }),
                    );
                    children.push(
                        Node::new("Length")
                            .span(at(l_at, body))
                            .value(dec(len.into(), 32)),
                    );
                }
            }
            if full {
                children.push(if format == 1 {
                    embedded_as("Serialized object", input.nested(payload), &NRBF)
                } else {
                    embedded("Serialized data", input.nested(payload))
                });
            }
            let how = if format == 1 {
                "BinaryFormatter"
            } else {
                lookup(SERIALIZATION_FORMATS, format.into()).unwrap_or("serialized")
            };
            (None, format!("{ty} ({how}, {} bytes)", payload.len))
        }
    };
    if full && !matches!(code, 0x00 | 0x20 | 0x21) && code < 0x40 {
        let node = Node::new("Value").span(at(value_start, r.pos()));
        children.push(match &value {
            Some(v) => node.value(v.clone()),
            None => node,
        });
    }
    Ok(Decoded {
        value,
        summary,
        children,
    })
}

async fn resource(cx: Cx, (h, e, input): (Arc<Headers>, Entry, Input)) -> Result<()> {
    let computed = name_hash(&e.name);
    let mut hash = Node::new("Name hash")
        .span(h.hashes.sub(u64::from(e.index).saturating_mul(4), 4))
        .value(hex(e.hash.unwrap_or(0).into(), 32));
    if e.hash != Some(computed) {
        hash = hash.diag(Diagnostic::warning(format!(
            "the name hashes to {computed:#010x}"
        )));
    }
    cx.emit(
        Node::new("Name entry")
            .span(e.record)
            .summary(format!("index {} in hash order", e.index))
            .lazy(name_entry, e.clone()),
    );
    cx.emit(hash);
    let v = decode_value(&cx, &h, &e, &input, true).await?;
    for child in v.children {
        cx.emit(child);
    }
    Ok(())
}

async fn name_entry(cx: Cx, e: Entry) -> Result<()> {
    cx.emit(
        Node::new("Length")
            .span(Span::new(
                e.record.source,
                e.record.offset,
                e.name_span.offset.saturating_sub(e.record.offset),
            ))
            .value(dec(e.name_span.len, 32))
            .desc("Bytes of UTF-16 name"),
    );
    cx.emit(
        Node::new("Name")
            .span(e.name_span)
            .value(text(e.name.clone())),
    );
    cx.emit(
        Node::new("Data offset")
            .span(e.offset_span)
            .value(hex(e.data_offset.into(), 32))
            .desc("Relative to the data section")
            .target(e.data),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// BinaryFormatter (MS-NRBF)

fn nrbf_probe(h: &Head<'_>) -> bool {
    // SerializationHeaderRecord: type 0, root id, header id -1, version 1.0,
    // then a record type.
    h.data.first() == Some(&0)
        && h.at(5, b"\xff\xff\xff\xff\x01\0\0\0\0\0\0\0")
        && u32_le(h.data, 1).is_some_and(|root| root > 0 && root < 0x8000_0000)
        && h.data
            .get(17)
            .is_some_and(|&t| matches!(t, 1..=17 | 21 | 22))
}

declare_format!(pub NRBF = "nrbf", ".NET BinaryFormatter stream (MS-NRBF)", ["nrbf"], "application/x-ms-nrbf",
    Probe::Custom(nrbf_probe), nrbf);

const RECORD_TYPES: EnumTable = &[
    (0, "SerializedStreamHeader"),
    (1, "ClassWithId"),
    (2, "SystemClassWithMembers"),
    (3, "ClassWithMembers"),
    (4, "SystemClassWithMembersAndTypes"),
    (5, "ClassWithMembersAndTypes"),
    (6, "BinaryObjectString"),
    (7, "BinaryArray"),
    (8, "MemberPrimitiveTyped"),
    (9, "MemberReference"),
    (10, "ObjectNull"),
    (11, "MessageEnd"),
    (12, "BinaryLibrary"),
    (13, "ObjectNullMultiple256"),
    (14, "ObjectNullMultiple"),
    (15, "ArraySinglePrimitive"),
    (16, "ArraySingleObject"),
    (17, "ArraySingleString"),
    (21, "MethodCall"),
    (22, "MethodReturn"),
];

const BINARY_TYPES: EnumTable = &[
    (0, "Primitive"),
    (1, "String"),
    (2, "Object"),
    (3, "SystemClass"),
    (4, "Class"),
    (5, "ObjectArray"),
    (6, "StringArray"),
    (7, "PrimitiveArray"),
];

const PRIMITIVE_TYPES: EnumTable = &[
    (1, "Boolean"),
    (2, "Byte"),
    (3, "Char"),
    (5, "Decimal"),
    (6, "Double"),
    (7, "Int16"),
    (8, "Int32"),
    (9, "Int64"),
    (10, "SByte"),
    (11, "Single"),
    (12, "TimeSpan"),
    (13, "DateTime"),
    (14, "UInt16"),
    (15, "UInt32"),
    (16, "UInt64"),
    (17, "Null"),
    (18, "String"),
];

const ARRAY_TYPES: EnumTable = &[
    (0, "Single"),
    (1, "Jagged"),
    (2, "Rectangular"),
    (3, "SingleOffset"),
    (4, "JaggedOffset"),
    (5, "RectangularOffset"),
];

/// A member's (or array element's) declared type.
#[derive(Clone, Debug)]
enum BType {
    Primitive(u8),
    String,
    Object,
    SystemClass(String),
    Class(String, i32),
    ObjectArray,
    StringArray,
    PrimitiveArray(u8),
}

impl BType {
    fn describe(&self) -> String {
        match self {
            BType::Primitive(p) => prim_name(*p).to_owned(),
            BType::String => "String".into(),
            BType::Object => "Object".into(),
            BType::SystemClass(n) => n.clone(),
            BType::Class(n, lib) => format!("{n} (library #{lib})"),
            BType::ObjectArray => "Object[]".into(),
            BType::StringArray => "String[]".into(),
            BType::PrimitiveArray(p) => format!("{}[]", prim_name(*p)),
        }
    }
}

fn prim_name(p: u8) -> &'static str {
    lookup(PRIMITIVE_TYPES, p.into()).unwrap_or("?")
}

struct ClassMeta {
    name: String,
    members: Vec<String>,
    /// `None` for the "WithMembers" records, whose values are all records.
    types: Option<Vec<BType>>,
    library: Option<i32>,
}

/// Parsed stream, shared between expansions.
struct Parsed {
    tree: Arc<Tree>,
    roots: Vec<usize>,
    summary: String,
    problem: Option<Diagnostic>,
}

/// What a record turned out to be, for the caller's bookkeeping.
enum Got {
    Node,
    Nulls(u64),
    Library,
    End,
}

struct Nrbf<'a> {
    r: Reader<'a>,
    base: Span,
    input: Input,
    tree: Tree,
    classes: BTreeMap<i32, Arc<ClassMeta>>,
    objects: BTreeMap<i32, Span>,
    refs: Vec<(usize, i32)>,
    libraries: BTreeMap<i32, String>,
    records: u64,
    root_id: i32,
    root_class: Option<String>,
}

type Pr<T> = std::result::Result<T, Diagnostic>;

impl<'a> Nrbf<'a> {
    fn span(&self, from: usize) -> Span {
        self.base
            .sub(to_u64(from), to_u64(self.r.pos().saturating_sub(from)))
    }

    fn short(&self) -> Diagnostic {
        Diagnostic::malformed("stream ends inside a record")
            .at(self.base.tail(to_u64(self.r.pos())))
    }

    fn i32(&mut self) -> Pr<i32> {
        self.r.int::<i32>(LE).ok_or_else(|| self.short())
    }

    fn u8(&mut self) -> Pr<u8> {
        self.r.u8().ok_or_else(|| self.short())
    }

    fn string(&mut self) -> Pr<String> {
        reader_string(&mut self.r).ok_or_else(|| self.short())
    }

    /// A field leaf under `parent`, spanning from `from` to here.
    fn field(&mut self, parent: usize, name: &'static str, from: usize, value: Value) {
        let span = self.span(from);
        self.tree
            .add(Some(parent), Node::new(name).span(span).value(value));
    }

    fn int_field(&mut self, parent: usize, name: &'static str) -> Pr<i32> {
        let at = self.r.pos();
        let v = self.i32()?;
        self.field(
            parent,
            name,
            at,
            Value::Int {
                value: v.into(),
                bits: 32,
            },
        );
        Ok(v)
    }

    fn string_field(&mut self, parent: usize, name: &'static str) -> Pr<String> {
        let at = self.r.pos();
        let v = self.string()?;
        self.field(parent, name, at, text(v.clone()));
        Ok(v)
    }

    fn enum_field(&mut self, parent: usize, name: &'static str, table: EnumTable) -> Pr<u8> {
        let at = self.r.pos();
        let v = self.u8()?;
        self.field(
            parent,
            name,
            at,
            Value::Enum {
                raw: v.into(),
                bits: 8,
                name: lookup(table, v.into()),
            },
        );
        Ok(v)
    }

    /// A primitive value of type `p` (no record header).
    fn primitive(&mut self, p: u8) -> Pr<(Value, &'static str)> {
        let r = &mut self.r;
        let v = match p {
            1 => r.u8().map(|b| Value::Bool(b != 0)),
            2 => r.u8().map(|b| dec(b.into(), 8)),
            3 => {
                // One UTF-8 encoded character.
                let lead = r.peek().unwrap_or(0);
                let n = match lead {
                    0xf0..=0xff => 4,
                    0xe0..=0xef => 3,
                    0xc0..=0xdf => 2,
                    _ => 1,
                };
                r.bytes(n)
                    .map(|b| text(String::from_utf8_lossy(b).into_owned()))
            }
            5 => reader_string(r).map(text),
            6 => r.int::<f64>(LE).map(Value::Float),
            7 => r.int::<i16>(LE).map(|v| Value::Int {
                value: v.into(),
                bits: 16,
            }),
            8 => r.int::<i32>(LE).map(|v| Value::Int {
                value: v.into(),
                bits: 32,
            }),
            9 => r.int::<i64>(LE).map(|v| Value::Int { value: v, bits: 64 }),
            10 => r.u8().map(|v| Value::Int {
                value: i64::from(v as i8),
                bits: 8,
            }),
            11 => r.int::<f32>(LE).map(|v| Value::Float(v.into())),
            12 => r.int::<i64>(LE).map(|v| text(timespan(v))),
            13 => r.int::<i64>(LE).map(|v| datetime(v).0),
            14 => r.int::<u16>(LE).map(|v| dec(v.into(), 16)),
            15 => r.int::<u32>(LE).map(|v| dec(v.into(), 32)),
            16 => r.int::<u64>(LE).map(|v| dec(v, 64)),
            18 => reader_string(r).map(text),
            _ => {
                return Err(Diagnostic::malformed(format!("bad primitive type {p}"))
                    .at(self.base.sub(to_u64(self.r.pos()), 1)));
            }
        };
        let v = v.ok_or_else(|| self.short())?;
        Ok((v, prim_name(p)))
    }

    fn primitive_type(&mut self, parent: usize, name: &'static str) -> Pr<u8> {
        let at = self.r.pos();
        let p = self.enum_field(parent, name, PRIMITIVE_TYPES)?;
        // Null and the unused codes carry no bytes: refuse them as declared
        // types so every value consumes input.
        if matches!(p, 0 | 4 | 17) || p > 18 {
            return Err(Diagnostic::malformed(format!("bad primitive type {p}"))
                .at(self.base.sub(to_u64(at), 1)));
        }
        Ok(p)
    }

    /// The additional type information following a binary type.
    fn additional(&mut self, parent: usize, t: u8) -> Pr<BType> {
        Ok(match t {
            0 => BType::Primitive(self.primitive_type(parent, "Primitive type")?),
            1 => BType::String,
            2 => BType::Object,
            3 => BType::SystemClass(self.string_field(parent, "Class name")?),
            4 => {
                let name = self.string_field(parent, "Class name")?;
                let lib = self.int_field(parent, "Library ID")?;
                BType::Class(name, lib)
            }
            5 => BType::ObjectArray,
            6 => BType::StringArray,
            7 => BType::PrimitiveArray(self.primitive_type(parent, "Primitive type")?),
            _ => {
                return Err(Diagnostic::malformed(format!("bad binary type {t}"))
                    .at(self.base.sub(to_u64(self.r.pos()), 1)));
            }
        })
    }

    fn register(&mut self, id: i32, span: Span) {
        self.objects.insert(id, span);
    }

    /// One record, added under `parent` and labelled `label` (a member
    /// name or an index) when given.
    fn record(&mut self, parent: Option<usize>, label: Option<String>, depth: u32) -> Pr<Got> {
        if depth > MAX_DEPTH {
            return Err(
                Diagnostic::limit(format!("values nested deeper than {MAX_DEPTH}"))
                    .at(self.base.tail(to_u64(self.r.pos()))),
            );
        }
        let start = self.r.pos();
        let kind = self.u8()?;
        self.records = self.records.saturating_add(1);
        let kind_name = lookup(RECORD_TYPES, kind.into()).unwrap_or("?");
        let named = |default: String| label.clone().unwrap_or(default);
        let node = self
            .tree
            .add(parent, Node::new(named(kind_name.to_owned())));
        let info = |me: &mut Self, from: usize| {
            me.field(
                node,
                "Record type",
                from,
                Value::Enum {
                    raw: kind.into(),
                    bits: 8,
                    name: Some(kind_name),
                },
            );
        };
        let got = match kind {
            0 => {
                info(self, start);
                let root = self.int_field(node, "Root ID")?;
                self.int_field(node, "Header ID")?;
                let major = self.int_field(node, "Major version")?;
                let minor = self.int_field(node, "Minor version")?;
                self.root_id = root;
                self.tree.update(node, |n| {
                    n.summary(format!("root object #{root}, version {major}.{minor}"))
                });
                Got::Node
            }
            1..=5 => {
                let group = self.tree.add(Some(node), Node::new("Class info"));
                self.field(
                    group,
                    "Record type",
                    start,
                    Value::Enum {
                        raw: kind.into(),
                        bits: 8,
                        name: Some(kind_name),
                    },
                );
                let (id, meta) = if kind == 1 {
                    let id = self.int_field(group, "Object ID")?;
                    let at = self.r.pos();
                    let meta_id = self.i32()?;
                    let meta = self.classes.get(&meta_id).cloned();
                    let target = self.objects.get(&meta_id).copied();
                    let span = self.span(at);
                    let mut n = Node::new("Metadata ID").span(span).value(Value::Int {
                        value: meta_id.into(),
                        bits: 32,
                    });
                    if let Some(t) = target {
                        n = n.target(t);
                    }
                    self.tree.add(Some(group), n);
                    let meta = meta.ok_or_else(|| {
                        Diagnostic::malformed(format!("no class metadata for object #{meta_id}"))
                            .at(span)
                    })?;
                    (id, meta)
                } else {
                    let id = self.int_field(group, "Object ID")?;
                    let name = self.string_field(group, "Class name")?;
                    let at = self.r.pos();
                    let count = self.i32()?;
                    self.field(
                        group,
                        "Member count",
                        at,
                        Value::Int {
                            value: count.into(),
                            bits: 32,
                        },
                    );
                    let names_at = self.r.pos();
                    let names_node = self.tree.add(Some(group), Node::new("Member names"));
                    let mut members = Vec::new();
                    for _ in 0..count.max(0) {
                        let at = self.r.pos();
                        let m = self.string()?;
                        let span = self.span(at);
                        self.tree.add(
                            Some(names_node),
                            Node::new(format!("[{}]", members.len()))
                                .span(span)
                                .value(text(m.clone())),
                        );
                        members.push(m);
                    }
                    let span = self.span(names_at);
                    self.tree.update(names_node, |n| n.span(span));
                    let types = if kind == 4 || kind == 5 {
                        let types_at = self.r.pos();
                        let tnode = self.tree.add(Some(group), Node::new("Member types"));
                        let mut kinds = Vec::new();
                        for m in &members {
                            let at = self.r.pos();
                            let t = self.u8()?;
                            let span = self.span(at);
                            self.tree.add(
                                Some(tnode),
                                Node::new(m.clone()).span(span).value(Value::Enum {
                                    raw: t.into(),
                                    bits: 8,
                                    name: lookup(BINARY_TYPES, t.into()),
                                }),
                            );
                            kinds.push(t);
                        }
                        let mut types = Vec::new();
                        for t in kinds {
                            types.push(self.additional(tnode, t)?);
                        }
                        let span = self.span(types_at);
                        self.tree.update(tnode, |n| n.span(span));
                        Some(types)
                    } else {
                        None
                    };
                    let library = if kind == 3 || kind == 5 {
                        let lib = self.i32()?;
                        let at = self.r.pos().saturating_sub(4);
                        let span = self.span(at);
                        let lib_name = self.libraries.get(&lib).cloned();
                        let mut n = Node::new("Library ID").span(span).value(Value::Int {
                            value: lib.into(),
                            bits: 32,
                        });
                        if let Some(l) = lib_name {
                            n = n.summary(l);
                        }
                        self.tree.add(Some(group), n);
                        Some(lib)
                    } else {
                        None
                    };
                    let meta = Arc::new(ClassMeta {
                        name,
                        members,
                        types,
                        library,
                    });
                    self.classes.insert(id, meta.clone());
                    (id, meta)
                };
                let span = self.span(start);
                self.tree.update(group, |n| n.span(span).summary(kind_name));
                if id == self.root_id && self.root_class.is_none() {
                    self.root_class = Some(meta.name.clone());
                }
                // Member values.
                for (i, member) in meta.members.iter().enumerate() {
                    let ty = meta.types.as_ref().and_then(|t| t.get(i)).cloned();
                    match ty {
                        Some(BType::Primitive(p)) => {
                            let at = self.r.pos();
                            let (v, _) = self.primitive(p)?;
                            let span = self.span(at);
                            self.tree
                                .add(Some(node), Node::new(member.clone()).span(span).value(v));
                        }
                        _ => {
                            self.value(node, member.clone(), depth)?;
                        }
                    }
                }
                let span = self.span(start);
                self.register(id, span);
                let lib = meta
                    .library
                    .and_then(|l| self.libraries.get(&l))
                    .map(|l| format!(", {}", l.split(',').next().unwrap_or_default()))
                    .unwrap_or_default();
                let class = meta.name.clone();
                let n = meta.members.len();
                self.tree.update(node, |nd| {
                    let nd = if label.is_none() {
                        Node {
                            name: format!("Object #{id}").into(),
                            ..nd
                        }
                    } else {
                        nd
                    };
                    nd.summary(format!("{class} #{id}, {n} members{lib}"))
                });
                Got::Node
            }
            6 => {
                info(self, start);
                let id = self.int_field(node, "Object ID")?;
                let s = self.string_field(node, "Value")?;
                let span = self.span(start);
                self.register(id, span);
                self.tree.update(node, |n| {
                    let n = if label.is_none() {
                        Node {
                            name: format!("String #{id}").into(),
                            ..n
                        }
                    } else {
                        n
                    };
                    n.value(text(s)).summary(format!("string #{id}"))
                });
                Got::Node
            }
            7 | 15..=17 => {
                info(self, start);
                self.array(node, kind, start, label.is_none(), depth)?;
                Got::Node
            }
            8 => {
                info(self, start);
                let p = self.primitive_type(node, "Primitive type")?;
                let at = self.r.pos();
                let (v, ty) = self.primitive(p)?;
                self.field(node, "Value", at, v.clone());
                self.tree.update(node, |n| n.value(v).summary(ty));
                Got::Node
            }
            9 => {
                info(self, start);
                let id = self.int_field(node, "ID reference")?;
                self.refs.push((node, id));
                self.tree
                    .update(node, |n| n.summary(format!("→ object #{id}")));
                Got::Node
            }
            10 => {
                self.tree.update(node, |n| n.value(text("null")));
                Got::Nulls(1)
            }
            11 => Got::End,
            12 => {
                info(self, start);
                let id = self.int_field(node, "Library ID")?;
                let name = self.string_field(node, "Library name")?;
                self.libraries.insert(id, name.clone());
                self.tree.update(node, |n| {
                    Node {
                        name: format!("Library #{id}").into(),
                        ..n
                    }
                    .value(text(name))
                });
                Got::Library
            }
            13 | 14 => {
                info(self, start);
                let at = self.r.pos();
                let count = if kind == 13 {
                    u32::from(self.u8()?)
                } else {
                    self.i32()?.max(0) as u32
                };
                self.field(node, "Null count", at, dec(count.into(), 32));
                self.tree
                    .update(node, |n| n.summary(format!("{count} nulls")));
                Got::Nulls(count.into())
            }
            21 | 22 => {
                let span = self.span(start);
                self.tree.update(node, |n| {
                    n.span(span)
                        .diag(Diagnostic::unsupported("remoting method records"))
                });
                return Err(
                    Diagnostic::unsupported("remoting method records are not decoded").at(span),
                );
            }
            _ => {
                let span = self.span(start);
                return Err(Diagnostic::malformed(format!("unknown record type {kind}")).at(span));
            }
        };
        let span = self.span(start);
        self.tree.update(node, |n| n.span(span));
        Ok(got)
    }

    /// A member value written as a record (skipping library records, which
    /// may precede any record).
    fn value(&mut self, parent: usize, label: String, depth: u32) -> Pr<u64> {
        loop {
            match self.record(Some(parent), Some(label.clone()), depth.saturating_add(1))? {
                Got::Library => continue,
                Got::Node => return Ok(1),
                Got::Nulls(n) => return Ok(n),
                Got::End => {
                    return Err(Diagnostic::malformed("MessageEnd inside a value")
                        .at(self.base.sub(to_u64(self.r.pos().saturating_sub(1)), 1)));
                }
            }
        }
    }

    fn array(&mut self, node: usize, kind: u8, start: usize, rename: bool, depth: u32) -> Pr<()> {
        let id = self.int_field(node, "Object ID")?;
        let (count, elem, desc) = if kind == 7 {
            let atype = self.enum_field(node, "Array type", ARRAY_TYPES)?;
            let rank = self.int_field(node, "Rank")?;
            if !(1..=32).contains(&rank) {
                return Err(
                    Diagnostic::malformed(format!("bad array rank {rank}")).at(self.span(start))
                );
            }
            let mut lengths = Vec::new();
            let mut count = 1u64;
            for _ in 0..rank {
                let l = self.int_field(node, "Length")?;
                let l = u64::try_from(l).unwrap_or(0);
                count = count.saturating_mul(l);
                lengths.push(l);
            }
            if matches!(atype, 3..=5) {
                for _ in 0..rank {
                    self.int_field(node, "Lower bound")?;
                }
            }
            let t = self.enum_field(node, "Element type", BINARY_TYPES)?;
            let elem = self.additional(node, t)?;
            let dims = lengths
                .iter()
                .map(u64::to_string)
                .collect::<Vec<_>>()
                .join(",");
            let jag = if atype == 1 || atype == 4 { "[]" } else { "" };
            (
                count,
                elem.clone(),
                format!("{}[{dims}]{jag}", elem.describe()),
            )
        } else {
            let at = self.r.pos();
            let len = self.i32()?;
            self.field(
                node,
                "Length",
                at,
                Value::Int {
                    value: len.into(),
                    bits: 32,
                },
            );
            let len = u64::try_from(len).unwrap_or(0);
            let elem = match kind {
                15 => BType::Primitive(self.primitive_type(node, "Primitive type")?),
                16 => BType::Object,
                _ => BType::String,
            };
            (len, elem.clone(), format!("{}[{len}]", elem.describe()))
        };
        let values = self.tree.add(Some(node), Node::new("Elements"));
        let values_at = self.r.pos();
        match elem {
            BType::Primitive(p) => {
                // Fixed-size elements: check they exist before walking.
                let size: u64 = match p {
                    1 | 2 | 10 => 1,
                    7 | 14 => 2,
                    8 | 11 | 15 => 4,
                    6 | 9 | 12 | 13 | 16 => 8,
                    _ => 0,
                };
                if size > 0 {
                    let need = count.saturating_mul(size);
                    if need > to_u64(self.r.rest().len()) {
                        return Err(Diagnostic::malformed(format!(
                            "array of {count} elements runs past the end of the stream"
                        ))
                        .at(self.span(start)));
                    }
                }
                if p == 2 {
                    let at = self.r.pos();
                    self.r.bytes(to_usize(count)).ok_or_else(|| self.short())?;
                    let span = self.span(at);
                    let data = embedded("Data", self.input.nested(span));
                    self.tree
                        .add(Some(values), data.summary(format!("{count} bytes")));
                } else {
                    let mut i = 0u64;
                    while i < count {
                        if i == MAX_ELEMENTS && size > 0 {
                            let at = self.r.pos();
                            let rest = count.saturating_sub(i);
                            self.r
                                .bytes(to_usize(rest.saturating_mul(size)))
                                .ok_or_else(|| self.short())?;
                            let span = self.span(at);
                            self.tree.add(
                                Some(values),
                                Node::new(format!("[{i}…{}]", count.saturating_sub(1)))
                                    .span(span)
                                    .summary(format!("{rest} more elements")),
                            );
                            break;
                        }
                        let at = self.r.pos();
                        let (v, _) = self.primitive(p)?;
                        let span = self.span(at);
                        self.tree.add(
                            Some(values),
                            Node::new(format!("[{i}]")).span(span).value(v),
                        );
                        i = i.saturating_add(1);
                    }
                }
            }
            _ => {
                let mut i = 0u64;
                while i < count {
                    let n = self.value(values, format!("[{i}]"), depth)?;
                    i = i.saturating_add(n.max(1));
                }
            }
        }
        let span = self.span(values_at);
        self.tree.update(values, |n| {
            n.span(span).summary(format!("{count} elements"))
        });
        let span = self.span(start);
        self.register(id, span);
        self.tree.update(node, |n| {
            let n = if rename {
                Node {
                    name: format!("Array #{id}").into(),
                    ..n
                }
            } else {
                n
            };
            n.summary(format!("{desc} #{id}"))
        });
        Ok(())
    }
}

fn parse_nrbf(data: &[u8], input: Input) -> Parsed {
    let mut p = Nrbf {
        r: Reader::new(data),
        base: input.span,
        input,
        tree: Tree::default(),
        classes: BTreeMap::new(),
        objects: BTreeMap::new(),
        refs: Vec::new(),
        libraries: BTreeMap::new(),
        records: 0,
        root_id: 0,
        root_class: None,
    };
    let mut roots = Vec::new();
    let mut problem = None;
    let mut ended = false;
    let mut first = true;
    while !p.r.at_end() {
        let before = p.tree.next_index();
        if first && p.r.peek() != Some(0) {
            problem = Some(
                Diagnostic::malformed("stream does not start with a header record")
                    .at(input.span.sub(0, 1)),
            );
            break;
        }
        first = false;
        let res = p.record(None, None, 0);
        if p.tree.next_index() > before {
            roots.push(before);
        }
        match res {
            Ok(Got::End) => {
                ended = true;
                break;
            }
            Ok(_) => {}
            Err(d) => {
                problem = Some(d);
                break;
            }
        }
    }
    if problem.is_none() && !ended {
        problem = Some(
            Diagnostic::malformed("no MessageEnd record").at(input.span.tail(to_u64(p.r.pos()))),
        );
    }
    let end = p.r.pos();
    if ended && end < data.len() {
        let span = input.span.tail(to_u64(end));
        let idx = p.tree.add(None, Node::new("Trailing data").span(span));
        roots.push(idx);
    }
    // Point references at what they refer to.
    for (node, id) in std::mem::take(&mut p.refs) {
        match p.objects.get(&id).copied() {
            Some(span) => p.tree.update(node, |n| n.target(span)),
            None => p.tree.update(node, |n| {
                n.diag(Diagnostic::warning(format!(
                    "object #{id} is not in the stream"
                )))
            }),
        }
    }
    let root = p.root_class.clone().unwrap_or_else(|| "?".into());
    let summary = format!(
        "BinaryFormatter stream, root {}, {} records",
        ellipsize(&root, 80),
        p.records
    );
    Parsed {
        tree: Arc::new(p.tree),
        roots,
        summary,
        problem,
    }
}

async fn nrbf(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let parsed = match cx.cached::<Parsed>(span, "nrbf") {
        Some(p) => p,
        None => {
            if span.len > MAX_DECODE {
                return Err(Diagnostic::limit("BinaryFormatter stream over 16 MiB").at(span));
            }
            let data = cx.read_avail(span).await?;
            let parsed = Arc::new(parse_nrbf(&data, input));
            cx.cache(span, "nrbf", parsed.clone());
            parsed
        }
    };
    cx.annotate(parsed.summary.clone());
    if let Some(d) = &parsed.problem {
        cx.diag(d.clone());
    }
    cx.set_count(Count::Exact(to_u64(parsed.roots.len())));
    for &root in &parsed.roots {
        cx.push(Tree::node(&parsed.tree, root)).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helpers() {
        assert_eq!(decimal(12345, 0, 0, 2 << 16), "123.45");
        assert_eq!(decimal(5, 0, 0, (3 << 16) | 0x8000_0000), "-0.005");
        assert_eq!(timespan(0), "00:00:00");
        assert_eq!(
            timespan(864_000_000_000 + 36_610_000_000 + 5_000_000),
            "1.01:01:01.5000000"
        );
        // FastResourceComparer.HashFunction of "" is the seed.
        assert_eq!(name_hash(""), 5381);
        assert_eq!(name_hash("a"), (5381u32 * 33) ^ 0x61);
        let mut r = Reader::new(&[0x80, 0x01]);
        assert_eq!(read7(&mut r), Some(128));
    }
}
