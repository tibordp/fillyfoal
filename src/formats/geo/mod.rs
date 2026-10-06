//! Geospatial data, GNSS streams, telemetry, vehicle bus logs, drone and
//! robotics logs, and sports and fitness files.
//!
//! Shared here: value constructors, checksums used by several receivers'
//! protocols, a protobuf wire-format reader, and helpers for text formats
//! whose records are lines of delimited or fixed-column fields.

#![allow(dead_code)] // TEMP
use std::borrow::Cow;

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Head;
use crate::formats::text::piece::Piece;
use crate::formats::text::probe;
use crate::formats::text::scan::LineBuf;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

pub mod fit;
pub mod gis;
pub mod gistext;
pub mod gnss;
pub mod markup;
pub mod rinex;
pub mod robotics;
pub mod tiles;
pub mod vehicle;

// ---------------------------------------------------------------------------
// Values

pub(crate) fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

pub(crate) fn uint(value: u64, bits: u8) -> Value {
    Value::UInt { value, bits, radix: Radix::Dec }
}

pub(crate) fn hex(value: u64, bits: u8) -> Value {
    Value::UInt { value, bits, radix: Radix::Hex }
}

pub(crate) fn int(value: i64, bits: u8) -> Value {
    Value::Int { value, bits }
}

pub(crate) fn enumv(table: EnumTable, raw: u64, bits: u8) -> Value {
    Value::Enum { raw, bits, name: lookup(table, raw) }
}

pub(crate) fn time(unix_seconds: i64) -> Value {
    Value::Timestamp { unix_seconds }
}

/// Emits prepared nodes: the expander for small structures that were
/// parsed anyway to build their parent's summary.
pub(crate) async fn emit_nodes(cx: Cx, nodes: Vec<Node>) -> Result<()> {
    for n in nodes {
        cx.emit(n);
    }
    Ok(())
}

/// `x` rounded to six decimal places, for display.
pub(crate) fn round(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// A plain leaf with a value.
pub(crate) fn leaf(name: impl Into<Cow<'static, str>>, span: Span, value: Value) -> Node {
    Node::new(name).span(span).value(value)
}

/// Text from fixed-width, NUL- or space-padded bytes.
pub(crate) fn fixed(b: &[u8]) -> String {
    crate::text::until_nul(b).trim_end().to_owned()
}

// ---------------------------------------------------------------------------
// Checksums

/// CRC-16/XMODEM (CCITT polynomial 0x1021, initial value 0).
pub(crate) fn crc16_xmodem(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 { (crc << 1) ^ 0x1021 } else { crc << 1 };
        }
    }
    crc
}

/// CRC-24Q (RTCM 3, SBAS): polynomial 0x864CFB, initial value 0.
pub(crate) fn crc24q(data: &[u8]) -> u32 {
    let mut crc = 0u32;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

// ---------------------------------------------------------------------------
// Protobuf wire format

/// A protobuf varint at `*at`, advancing past it.
pub(crate) fn varint(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for i in 0..10u32 {
        let b = *data.get(*at)?;
        *at = at.saturating_add(1);
        value |= u64::from(b & 0x7f).checked_shl(i.saturating_mul(7))?;
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

/// One protobuf field: number, wire type, and either the scalar or the
/// byte range of a length-delimited payload.
#[derive(Clone, Copy, Debug)]
pub(crate) struct PbField {
    pub number: u64,
    pub wire: u8,
    pub value: u64,
    /// Start and end of the field (key included).
    pub start: usize,
    pub end: usize,
    /// Start of a length-delimited payload.
    pub body: usize,
}

impl PbField {
    pub fn payload<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.body..self.end).unwrap_or_default()
    }
}

/// The next field of a message at `*at`; `None` at the end or on malformed
/// input (unknown wire types, overruns).
pub(crate) fn pb_field(data: &[u8], at: &mut usize) -> Option<PbField> {
    let start = *at;
    let key = varint(data, at)?;
    let number = key >> 3;
    let wire = u8::try_from(key & 7).ok()?;
    if number == 0 {
        return None;
    }
    let (value, body) = match wire {
        0 => (varint(data, at)?, *at),
        1 => {
            let v = crate::bytes::u64_le(data, *at)?;
            *at = at.checked_add(8)?;
            (v, at.saturating_sub(8))
        }
        5 => {
            let v = crate::bytes::u32_le(data, *at)?;
            *at = at.checked_add(4)?;
            (u64::from(v), at.saturating_sub(4))
        }
        2 => {
            let len = usize::try_from(varint(data, at)?).ok()?;
            let body = *at;
            let end = body.checked_add(len)?;
            if end > data.len() {
                return None;
            }
            *at = end;
            (u64::try_from(len).ok()?, body)
        }
        _ => return None,
    };
    Some(PbField { number, wire, value, start, end: *at, body })
}

/// All fields of a message, or `None` if it does not parse exactly.
pub(crate) fn pb_fields(data: &[u8]) -> Option<Vec<PbField>> {
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < data.len() {
        out.push(pb_field(data, &mut at)?);
    }
    Some(out)
}

// ---------------------------------------------------------------------------
// Text helpers

/// The probe head as ASCII-compatible text.
pub(crate) fn head_text<'a>(h: &'a Head<'_>) -> Cow<'a, [u8]> {
    probe::head(h)
}

/// The first `n` lines of the head (without terminators).
pub(crate) fn head_lines(h: &Head<'_>, n: usize) -> Vec<Vec<u8>> {
    let data = probe::head(h);
    probe::lines(&data).take(n).map(<[u8]>::to_vec).collect()
}

/// A field label table for delimited or fixed-column records.
pub(crate) type Labels = &'static [&'static str];

/// A node for one line of delimited fields; expanding it shows the fields
/// labelled from `labels` (extra fields are numbered).
pub(crate) fn delimited_node(name: impl Into<Cow<'static, str>>, line: &LineBuf, sep: u8, labels: Labels) -> Node {
    delimited_span(name, line.span, sep, labels)
}

/// Like [`delimited_node`], for part of a line.
pub(crate) fn delimited_span(name: impl Into<Cow<'static, str>>, span: Span, sep: u8, labels: Labels) -> Node {
    Node::new(name).span(span).lazy(delimited, (span, sep, labels))
}

async fn delimited(cx: Cx, (span, sep, labels): (Span, u8, Labels)) -> Result<()> {
    let bytes = cx.read_avail(span.sub(0, crate::formats::text::scan::LINE_CAP as u64)).await?;
    let piece = Piece::new(&bytes, span);
    for (i, field) in piece.split(sep).enumerate() {
        let name: Cow<'static, str> = match labels.get(i) {
            Some(l) => Cow::Borrowed(*l),
            None => Cow::Owned(format!("Field {}", i.saturating_add(1))),
        };
        cx.emit(field_node(name, field));
    }
    Ok(())
}

/// Whitespace-separated words of a line, labelled.
pub(crate) fn words_node(name: impl Into<Cow<'static, str>>, line: &LineBuf, labels: Labels) -> Node {
    Node::new(name).span(line.span).lazy(words, (line.span, labels))
}

async fn words(cx: Cx, (span, labels): (Span, Labels)) -> Result<()> {
    let bytes = cx.read_avail(span.sub(0, crate::formats::text::scan::LINE_CAP as u64)).await?;
    let piece = Piece::new(&bytes, span);
    for (i, word) in piece.words().enumerate() {
        let name: Cow<'static, str> = match labels.get(i) {
            Some(l) => Cow::Borrowed(*l),
            None => Cow::Owned(format!("Field {}", i.saturating_add(1))),
        };
        cx.emit(field_node(name, word));
    }
    Ok(())
}

/// A fixed-column layout: `(start column, width, label)`, 0-based.
pub(crate) type Columns = &'static [(usize, usize, &'static str)];

/// A node for a fixed-column record; expanding it shows the columns.
pub(crate) fn columns_node(name: impl Into<Cow<'static, str>>, span: Span, cols: Columns) -> Node {
    Node::new(name).span(span).lazy(columns, (span, cols))
}

async fn columns(cx: Cx, (span, cols): (Span, Columns)) -> Result<()> {
    let bytes = cx.read_avail(span.sub(0, crate::formats::text::scan::LINE_CAP as u64)).await?;
    let piece = Piece::new(&bytes, span);
    for &(start, width, label) in cols {
        if start >= piece.len() {
            break;
        }
        let field = piece.slice(start, start.saturating_add(width).min(piece.len()));
        cx.emit(field_node(label, field));
    }
    Ok(())
}

/// A text field as a leaf: numbers become numeric values.
pub(crate) fn field_node(name: impl Into<Cow<'static, str>>, field: Piece<'_>) -> Node {
    let t = field.trim();
    let s = t.text();
    // Zero-padded codes (dates, IDs) stay text.
    let padded = s.len() > 1 && !s.contains('.') && s.starts_with('0') && s.as_bytes().get(1).is_some_and(u8::is_ascii_digit);
    let value = if padded { None } else { crate::formats::text::number(&s) }.unwrap_or(Value::Text(s));
    Node::new(name).span(t.span()).value(value)
}

/// `key<sep>value` header lines as leaves (key trimmed, value trimmed).
pub(crate) fn key_value(line: &LineBuf, sep: u8) -> Option<Node> {
    let piece = line.piece();
    let (k, v) = piece.split_once(sep)?;
    let key = k.trim().text();
    if key.is_empty() {
        return None;
    }
    Some(field_node(key, v).span(line.span))
}

// ---------------------------------------------------------------------------
// FlatBuffers

/// A FlatBuffers table in an in-memory buffer: its position and vtable.
#[derive(Clone, Copy, Debug)]
pub(crate) struct FbTable {
    pub pos: usize,
    vtable: usize,
    vlen: usize,
}

/// The root table of a buffer.
pub(crate) fn fb_root(data: &[u8]) -> Option<FbTable> {
    fb_table(data, fb_deref(data, 0)?)
}

pub(crate) fn fb_table(data: &[u8], pos: usize) -> Option<FbTable> {
    let soffset = i64::from(crate::bytes::i32_le(data, pos)?);
    let vtable = usize::try_from(i64::try_from(pos).ok()?.checked_sub(soffset)?).ok()?;
    let vlen = usize::from(crate::bytes::u16_le(data, vtable)?);
    (vlen >= 4 && vlen % 2 == 0).then_some(FbTable { pos, vtable, vlen })
}

/// The position an unsigned offset at `at` points to.
fn fb_deref(data: &[u8], at: usize) -> Option<usize> {
    at.checked_add(usize::try_from(crate::bytes::u32_le(data, at)?).ok()?)
}

impl FbTable {
    /// Absolute position of field `i`, if present.
    pub fn field(&self, data: &[u8], i: usize) -> Option<usize> {
        let entry = 4usize.checked_add(i.checked_mul(2)?)?;
        if entry.checked_add(2)? > self.vlen {
            return None;
        }
        let off = crate::bytes::u16_le(data, self.vtable.checked_add(entry)?)?;
        (off != 0).then(|| self.pos.saturating_add(usize::from(off)))
    }

    pub fn u8(&self, data: &[u8], i: usize) -> Option<u8> {
        data.get(self.field(data, i)?).copied()
    }

    pub fn u16(&self, data: &[u8], i: usize) -> Option<u16> {
        crate::bytes::u16_le(data, self.field(data, i)?)
    }

    pub fn i32(&self, data: &[u8], i: usize) -> Option<i32> {
        crate::bytes::i32_le(data, self.field(data, i)?)
    }

    pub fn u64(&self, data: &[u8], i: usize) -> Option<u64> {
        crate::bytes::u64_le(data, self.field(data, i)?)
    }

    pub fn table(&self, data: &[u8], i: usize) -> Option<FbTable> {
        fb_table(data, fb_deref(data, self.field(data, i)?)?)
    }

    /// A string: its text and byte range.
    pub fn string(&self, data: &[u8], i: usize) -> Option<(String, usize, usize)> {
        let at = fb_deref(data, self.field(data, i)?)?;
        let len = usize::try_from(crate::bytes::u32_le(data, at)?).ok()?;
        let start = at.checked_add(4)?;
        let end = start.checked_add(len)?;
        Some((String::from_utf8_lossy(data.get(start..end)?).into_owned(), start, end))
    }

    /// A vector: element count and the position of the first element. The
    /// count is checked against the buffer for elements of `width` bytes.
    pub fn vector(&self, data: &[u8], i: usize, width: usize) -> Option<(usize, usize)> {
        let at = fb_deref(data, self.field(data, i)?)?;
        let n = usize::try_from(crate::bytes::u32_le(data, at)?).ok()?;
        let start = at.checked_add(4)?;
        let end = start.checked_add(n.checked_mul(width)?)?;
        (end <= data.len()).then_some((n, start))
    }

    /// The `j`th table of a vector of tables starting at `start`.
    pub fn vector_table(data: &[u8], start: usize, j: usize) -> Option<FbTable> {
        fb_table(data, fb_deref(data, start.checked_add(j.checked_mul(4)?)?)?)
    }
}

// ---------------------------------------------------------------------------
// Bit fields

/// Big-endian (MSB-first) bit reader over a byte slice, as used by RTCM.
pub(crate) struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Bits { data, pos: 0 }
    }

    /// The next `n` (at most 64) bits as an unsigned number; `None` past
    /// the end.
    pub fn u(&mut self, n: u32) -> Option<u64> {
        let mut v = 0u64;
        for _ in 0..n.min(64) {
            let byte = *self.data.get(self.pos / 8)?;
            let bit = byte.checked_shr(7u32.saturating_sub(u32::try_from(self.pos % 8).ok()?))? & 1;
            v = (v << 1) | u64::from(bit);
            self.pos = self.pos.saturating_add(1);
        }
        Some(v)
    }

    /// The next `n` bits as a two's-complement signed number.
    pub fn i(&mut self, n: u32) -> Option<i64> {
        let v = self.u(n)?;
        let shift = 64u32.saturating_sub(n.min(64));
        v.cast_signed().checked_shl(shift).and_then(|x| x.checked_shr(shift))
    }
}
