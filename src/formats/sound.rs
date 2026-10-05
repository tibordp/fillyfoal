//! Helpers shared by the audio dissectors: value constructors, durations,
//! 80-bit floats, 24-bit fields, MSB-first bit fields and paged record
//! tables.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// An unsigned decimal value.
pub fn uint(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Dec,
    }
}

/// An unsigned hexadecimal value.
pub fn hex(value: impl Into<u64>, bits: u8) -> Value {
    Value::UInt {
        value: value.into(),
        bits,
        radix: Radix::Hex,
    }
}

/// An enumerated value.
pub fn enumerated(raw: impl Into<u64>, bits: u8, table: EnumTable) -> Value {
    let raw = raw.into();
    Value::Enum {
        raw,
        bits,
        name: lookup(table, raw),
    }
}

/// Text value.
pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// A leaf node with a value.
pub fn leaf(name: impl Into<Cow<'static, str>>, span: Span, value: Value) -> Node {
    Node::new(name).span(span).value(value)
}

/// A four-character code as text, trailing spaces and NULs removed,
/// non-printable bytes escaped.
pub fn fourcc(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(char::from(b));
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    let trimmed = out.trim_end_matches([' ', '\0']);
    if trimmed.is_empty() {
        out
    } else {
        trimmed.to_owned()
    }
}

/// A playing time: `250 ms`, `0:05`, `3:25`, `1:02:03`.
pub fn duration(seconds: f64) -> String {
    if !seconds.is_finite() || seconds < 0.0 {
        return "?".to_owned();
    }
    if seconds < 1.0 {
        return format!("{:.0} ms", seconds * 1000.0);
    }
    let total = seconds as u64;
    let (h, m, s) = (total / 3600, total / 60 % 60, total % 60);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}")
    } else {
        format!("{m}:{s:02}")
    }
}

/// `count / rate` seconds, formatted; `None` if the rate is zero.
pub fn duration_of(count: u64, rate: u64) -> Option<String> {
    (rate > 0).then(|| duration(count as f64 / rate as f64))
}

/// A channel count for summaries: "2 ch".
pub fn channels(n: impl Into<u64>) -> String {
    format!("{} ch", n.into())
}

/// An IEEE 754 80-bit extended float (as in AIFF sample rates), big-endian.
pub fn f80_be(b: &[u8]) -> Option<f64> {
    let b: [u8; 10] = crate::bytes::array(b, 0)?;
    let [e0, e1, m @ ..] = b;
    let sign = if e0 & 0x80 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from(u16::from_be_bytes([e0 & 0x7f, e1]));
    let mantissa = u64::from_be_bytes(m);
    if exponent == 0 && mantissa == 0 {
        return Some(0.0);
    }
    if exponent == 0x7fff {
        return Some(f64::NAN);
    }
    // value = mantissa * 2^(exponent - 16383 - 63)
    let shift = exponent.saturating_sub(16383 + 63);
    Some(sign * mantissa as f64 * 2f64.powi(shift))
}

/// Formats a sample rate without a needless fraction.
pub fn hz(rate: f64) -> String {
    if rate.fract() == 0.0 && rate.abs() < 1e12 {
        format!("{} Hz", rate as i64)
    } else {
        format!("{rate:.3} Hz")
    }
}

/// A 24-bit unsigned field.
pub fn u24<'a>(f: &mut Fields<'a>, name: &'static str, endian: Endian) -> Field<'a, u32> {
    f.bytes(name, 3)
        .map(move |b| {
            let get = |i: usize| b.get(i).copied().unwrap_or(0);
            match endian {
                Endian::Little => u32::from_le_bytes([get(0), get(1), get(2), 0]),
                Endian::Big => u32::from_be_bytes([0, get(0), get(1), get(2)]),
            }
        })
        .with(|&v, n| n.value(uint(v, 24)))
}

/// A length-prefixed or fixed text field interpreted as Latin-1.
pub fn latin1_field<'a>(f: &mut Fields<'a>, name: &'static str, len: u64) -> Field<'a, String> {
    f.bytes(name, len)
        .map(|b| crate::text::latin1(trim_nul(&b)))
        .with(|s, n| n.value(text(s.clone())))
}

/// `data` without trailing NUL and space padding.
pub fn trim_nul(data: &[u8]) -> &[u8] {
    let end = data
        .iter()
        .rposition(|&b| b != 0 && b != b' ')
        .map_or(0, |p| p.saturating_add(1));
    data.get(..end).unwrap_or_default()
}

/// Text up to the first NUL, Latin-1.
pub fn latin1_z(data: &[u8]) -> String {
    let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
    crate::text::latin1(data.get(..end).unwrap_or_default())
}

/// Shortens text for a summary line.
pub fn clip(s: &str, max: usize) -> String {
    let s = s.trim();
    if s.chars().count() <= max {
        return s.replace(['\r', '\n'], " ");
    }
    let mut out: String = s.chars().take(max).collect();
    out = out.replace(['\r', '\n'], " ");
    out.push('…');
    out
}

/// Reads up to `max` bytes of `span` as text (for summaries).
pub async fn peek_text(cx: &Cx, span: Span, max: u64) -> Result<String> {
    let data = cx.read_avail(span.sub(0, max)).await?;
    Ok(decode_text(trim_nul(&data)))
}

/// UTF-8 if valid, else Latin-1.
pub fn decode_text(data: &[u8]) -> String {
    match std::str::from_utf8(data) {
        Ok(s) => s.to_owned(),
        Err(_) => crate::text::latin1(data),
    }
}

// ---------------------------------------------------------------------------
// Bit fields

/// An MSB-first (or LSB-first) bit reader over a block that decodes fields
/// and, optionally, emits them, like [`Fields`] for packed headers. Each
/// field's span covers the bytes its bits occupy.
pub struct Bits<'a> {
    cx: Option<&'a Cx>,
    data: &'a [u8],
    span: Span,
    pos: u64,
    lsb_first: bool,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8], span: Span) -> Self {
        Bits {
            cx: None,
            data,
            span,
            pos: 0,
            lsb_first: false,
        }
    }

    pub fn emitting(cx: &'a Cx, data: &'a [u8], span: Span) -> Self {
        Bits {
            cx: Some(cx),
            ..Bits::new(data, span)
        }
    }

    /// Bits are numbered from the least significant end of each byte (as in
    /// VP8L and Vorbis).
    pub fn lsb_first(mut self) -> Self {
        self.lsb_first = true;
        self
    }

    pub fn pos(&self) -> u64 {
        self.pos
    }

    pub fn skip(&mut self, bits: u64) {
        self.pos = self.pos.saturating_add(bits);
    }

    fn bit(&self, at: u64) -> Option<u64> {
        let byte = self.data.get(to_usize(at / 8))?;
        let shift = if self.lsb_first { at % 8 } else { 7u64.saturating_sub(at % 8) };
        Some(u64::from(byte >> shift) & 1)
    }

    /// Reads `n` (at most 64) bits without emitting.
    pub fn read(&mut self, n: u32) -> Option<u64> {
        let mut value = 0u64;
        for i in 0..u64::from(n.min(64)) {
            let bit = self.bit(self.pos.saturating_add(i))?;
            if self.lsb_first {
                value |= bit << i;
            } else {
                value = (value << 1) | bit;
            }
        }
        self.pos = self.pos.saturating_add(n.into());
        Some(value)
    }

    /// Decodes an `n`-bit field.
    pub fn field(&mut self, name: &'static str, n: u32) -> BitField<'a> {
        let start = self.pos;
        let value = self.read(n);
        let first = start / 8;
        let last = self.pos.saturating_add(7) / 8;
        let span = self.span.sub(first, last.saturating_sub(first));
        let node = Node::new(name).span(span);
        let bits = u8::try_from(n).unwrap_or(64);
        let value = value.ok_or_else(|| {
            Diagnostic::truncated(span, to_u64(self.data.len()).saturating_sub(first))
        });
        let mut field = BitField {
            cx: self.cx,
            node,
            value,
            bits,
        };
        if let Ok(v) = field.value {
            field.node.value = Some(uint(v, bits));
        }
        field
    }

    /// Emits an arbitrary node if this reader is emitting.
    pub fn node(&self, node: Node) {
        if let Some(cx) = self.cx {
            cx.emit(node);
        }
    }
}

/// A decoded bit field, not yet emitted.
#[must_use = "a field does nothing until `emit` or `get` is called"]
pub struct BitField<'a> {
    cx: Option<&'a Cx>,
    node: Node,
    value: Result<u64>,
    bits: u8,
}

impl BitField<'_> {
    pub fn enumeration(mut self, table: EnumTable) -> Self {
        if let Ok(v) = self.value {
            self.node.value = Some(enumerated(v, self.bits, table));
        }
        self
    }

    pub fn flag(mut self) -> Self {
        if let Ok(v) = self.value {
            self.node.value = Some(Value::Bool(v != 0));
        }
        self
    }

    pub fn hex(mut self) -> Self {
        if let Ok(v) = self.value {
            self.node.value = Some(hex(v, self.bits));
        }
        self
    }

    pub fn desc(mut self, d: &'static str) -> Self {
        self.node.description = Some(d.into());
        self
    }

    pub fn with(mut self, f: impl FnOnce(u64, Node) -> Node) -> Self {
        if let Ok(v) = self.value {
            self.node = f(v, self.node);
        }
        self
    }

    pub fn get(self) -> Result<u64> {
        self.value
    }

    pub fn emit(self) -> Result<u64> {
        if let (Some(cx), Ok(_)) = (self.cx, &self.value) {
            cx.emit(self.node);
        }
        self.value
    }
}

/// A bit-field layout function, the [`Bits`] analogue of a [`Fields`]
/// layout.
pub type BitLayout<R> = fn(&mut Bits<'_>) -> Result<R>;

/// A lazy node showing `layout` applied to `span`.
pub fn bits_node<R: 'static>(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    layout: BitLayout<R>,
    lsb_first: bool,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(expand_bits::<R>, (span, layout, lsb_first))
}

async fn expand_bits<R>(cx: Cx, (span, layout, lsb): (Span, BitLayout<R>, bool)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut bits = Bits::emitting(&cx, &data, span);
    if lsb {
        bits = bits.lsb_first();
    }
    layout(&mut bits)?;
    Ok(())
}

/// Reads `span` and decodes it with a bit layout, silently.
pub async fn parse_bits<R>(cx: &Cx, span: Span, layout: BitLayout<R>, lsb: bool) -> Result<R> {
    let data = cx.read_avail(span).await?;
    let mut bits = Bits::new(&data, span);
    if lsb {
        bits = bits.lsb_first();
    }
    layout(&mut bits)
}

// ---------------------------------------------------------------------------
// Tables of fixed-size records

/// Describes one record of a table for its collapsed line.
pub type Describe<R> = fn(&R) -> String;

/// A lazy node listing the records of type `R` that fill `span`, paged,
/// each named `"{item} {index}"` and summarised by `describe`.
pub fn table<R: Record>(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    endian: Endian,
    item: &'static str,
    describe: Option<Describe<R>>,
) -> Node {
    let count = span.len.checked_div(R::SIZE).unwrap_or(0);
    Node::new(name)
        .span(span)
        .summary(format!("{count} entries"))
        .lazy(expand_table::<R>, (span, endian, item, describe))
}

type TableState<R> = (Span, Endian, &'static str, Option<Describe<R>>);

async fn expand_table<R: Record>(
    cx: Cx,
    (span, endian, item, describe): TableState<R>,
) -> Result<()> {
    let size = R::SIZE.max(1);
    cx.set_count(Count::Exact(span.len.checked_div(size).unwrap_or(0)));
    let mut cur = Cursor::new(&cx, span, endian);
    let mut index = 0u64;
    while cur.remaining() >= size {
        let (record, at) = cur.record::<R>().await?;
        let mut node = R::node(format!("{item} {index}"), at, endian);
        if let Some(describe) = describe {
            node = node.summary(describe(&record));
        }
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}
