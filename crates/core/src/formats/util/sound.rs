//! Helpers shared by the audio dissectors: value constructors, durations,
//! 80-bit floats, 24-bit fields, MSB-first bit fields, paged record tables,
//! a walker for elementary streams of self-delimiting frames (with
//! resynchronisation after junk) and cover-art dimensions.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_be};
use crate::codec::crc::Crc;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Field, Fields};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, lookup};

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

    /// The span the reader's bits come from.
    pub fn span(&self) -> Span {
        self.span
    }

    /// A reader over the same bits at the same position that emits
    /// nothing: for decoding a structure ahead before rendering it.
    pub fn silent(&self) -> Bits<'a> {
        Bits {
            cx: None,
            data: self.data,
            span: self.span,
            pos: self.pos,
            lsb_first: self.lsb_first,
        }
    }

    pub fn skip(&mut self, bits: u64) {
        self.pos = self.pos.saturating_add(bits);
    }

    pub fn seek(&mut self, bit: u64) {
        self.pos = bit;
    }

    fn bit(&self, at: u64) -> Option<u64> {
        let byte = self.data.get(to_usize(at / 8))?;
        let shift = if self.lsb_first {
            at % 8
        } else {
            7u64.saturating_sub(at % 8)
        };
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

    /// The span of the bytes holding bits `start..end`.
    pub fn span_of(&self, start: u64, end: u64) -> Span {
        let first = start / 8;
        let last = end.saturating_add(7) / 8;
        self.span.sub(first, last.saturating_sub(first))
    }

    /// `n` whole bytes (the reader must be byte-aligned) as a bytes field.
    pub fn bytes(&mut self, name: &'static str, n: u64) -> BitField<'a> {
        let start = self.pos;
        let bytes = self
            .data
            .get(to_usize(start / 8)..)
            .and_then(|d| d.get(..to_usize(n)))
            .map(<[u8]>::to_vec);
        self.pos = self.pos.saturating_add(n.saturating_mul(8));
        let span = self.span_of(start, self.pos);
        let mut node = Node::new(name).span(span);
        let value = match bytes {
            Some(b) => {
                node.value = Some(Value::Bytes(b));
                Ok(0)
            }
            None => Err(Diagnostic::truncated(span, 0)),
        };
        BitField {
            cx: self.cx,
            node,
            value,
            bits: 0,
        }
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

    pub fn flags(mut self, table: FlagTable) -> Self {
        if let Ok(v) = self.value {
            let (set, unknown) = crate::value::decode_flags(table, v);
            self.node.value = Some(Value::Flags {
                raw: v,
                bits: self.bits,
                set,
                unknown,
            });
        }
        self
    }

    /// A signed value in two's complement.
    pub fn signed(mut self) -> Self {
        if let Ok(v) = self.value {
            self.node.value = Some(Value::Int {
                value: sign_extend(v, self.bits),
                bits: self.bits,
            });
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

/// `v`, an `bits`-bit two's complement number, as a signed integer.
pub fn sign_extend(v: u64, bits: u8) -> i64 {
    let bits = u32::from(bits.clamp(1, 64));
    let shift = 64u32.saturating_sub(bits);
    i64::from_ne_bytes(v.wrapping_shl(shift).to_ne_bytes()).wrapping_shr(shift)
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

// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Elementary streams of self-delimiting frames (MPEG audio, ADTS, AC-3, DTS)

/// CRC-16 of MPEG audio and ADTS frames (polynomial 0x8005, initial value
/// 0xffff, not reflected).
pub const CRC16_MPEG: Crc = Crc::new(16, 0x8005, 0xffff, false, 0);
/// CRC-16 of FLAC frames and AC-3 sync frames (polynomial 0x8005, initial
/// value 0, not reflected).
pub const CRC16_BUYPASS: Crc = Crc::new(16, 0x8005, 0, false, 0);

/// How to recognise and render the frames of an elementary stream.
pub struct FrameSyntax {
    /// Bytes `parse` needs to see.
    pub peek: u64,
    /// The bytes a frame can start with: candidates for resynchronising
    /// after junk are only tried at these.
    pub sync: &'static [u8],
    /// Frame length and a one-line description, if `data` starts with a
    /// valid frame header.
    pub parse: fn(&[u8]) -> Option<(u64, String)>,
    /// Header bytes rendered by `layout` (given the first `peek` bytes).
    pub header: fn(&[u8]) -> u64,
    pub layout: BitLayout<()>,
    /// Renders a frame's children; `None` shows the header with `layout`
    /// and the rest as the payload.
    pub expand: Option<fn(Cx, FrameRef) -> crate::node::Expansion>,
}

/// One frame of an elementary stream, located.
#[derive(Clone, Copy)]
pub struct FrameRef {
    /// The whole frame.
    pub span: Span,
    /// The bytes `layout` renders.
    pub header: Span,
    pub syntax: &'static FrameSyntax,
}

/// Counts the frames at the start of `data` and the bytes they cover.
pub fn count_frames(data: &[u8], syntax: &FrameSyntax) -> (u64, u64) {
    let mut at = 0u64;
    let mut count = 0u64;
    while let Some((len, _)) = data.get(to_usize(at)..).and_then(syntax.parse) {
        if len == 0 || at.saturating_add(len) > to_u64(data.len()) {
            break;
        }
        at = at.saturating_add(len);
        count = count.saturating_add(1);
    }
    (count, at)
}

/// Estimates the number of frames in a `total`-byte stream from the frames
/// found at the start of `window` (its first bytes): exact if the window
/// holds the whole stream.
pub fn estimate_frames(window: &[u8], total: u64, syntax: &FrameSyntax) -> f64 {
    let (count, covered) = count_frames(window, syntax);
    if covered == 0 || to_u64(window.len()) >= total {
        count as f64
    } else {
        count as f64 * total as f64 / covered as f64
    }
}

/// A lazy node listing the frames of `region`, paged.
pub fn frames_node(region: Span, syntax: &'static FrameSyntax) -> Node {
    Node::new("Frames")
        .span(region)
        .summary(crate::formats::util::arcutil::human_size(region.len))
        .lazy(list_frames, (region, syntax))
}

/// How far one step of [`resync`] reads ahead.
const RESYNC_WINDOW: u64 = 0x10000;

/// The offset (relative to `region`) of the first frame at or after `from`
/// that is followed by another frame (or by the end of `region`): where the
/// stream picks up again after junk. `None` if there is none.
pub async fn resync(cx: &Cx, region: Span, from: u64, syntax: &FrameSyntax) -> Result<Option<u64>> {
    let mut pos = from;
    while pos < region.len {
        let window = cx
            .read_avail(region.sub(pos, RESYNC_WINDOW.saturating_add(syntax.peek)))
            .await?;
        let scan = window.len().min(to_usize(RESYNC_WINDOW));
        for i in 0..scan {
            if i % 4096 == 0 {
                cx.checkpoint().await;
            }
            if !window.get(i).is_some_and(|b| syntax.sync.contains(b)) {
                continue;
            }
            let Some((len, _)) = window
                .get(i..)
                .and_then(syntax.parse)
                .filter(|(l, _)| *l > 0)
            else {
                continue;
            };
            let at = pos.saturating_add(to_u64(i));
            let next = at.saturating_add(len);
            if next >= region.len {
                return Ok(Some(at));
            }
            let following = match window.get(i.saturating_add(to_usize(len))..) {
                Some(rest) if to_u64(rest.len()) >= syntax.peek => rest.to_vec(),
                _ => cx.read_avail(region.sub(next, syntax.peek)).await?,
            };
            if (syntax.parse)(&following).is_some() {
                return Ok(Some(at));
            }
        }
        if to_u64(window.len()) <= syntax.peek {
            break;
        }
        pos = pos.saturating_add(to_u64(scan).max(1));
    }
    Ok(None)
}

/// A node for the bytes after the last frame of a stream: padding if they
/// are zeros, otherwise data that is not a frame.
pub async fn tail_node(cx: &Cx, span: Span) -> Result<Node> {
    let head = cx.read_avail(span.sub(0, 4096)).await?;
    let size = crate::formats::util::arcutil::human_size(span.len);
    Ok(if head.iter().all(|&b| b == 0) {
        Node::new("Padding").span(span).summary(size)
    } else {
        Node::new("Unparsed data")
            .span(span)
            .summary(size)
            .diag(Diagnostic::malformed(
                "no frame header found in the rest of the stream",
            ))
    })
}

/// A node for junk between two frames.
pub fn junk_node(span: Span) -> Node {
    Node::new("Junk")
        .span(span)
        .summary(format!(
            "{}, frame sync lost",
            crate::formats::util::arcutil::human_size(span.len)
        ))
        .diag(Diagnostic::warning(format!(
            "{} bytes between frames that are not a frame",
            span.len
        )))
}

async fn list_frames(cx: Cx, (region, syntax): (Span, &'static FrameSyntax)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < region.len {
        let mark = (pos, index);
        let head = cx.read_avail(region.sub(pos, syntax.peek)).await?;
        let Some((len, summary)) = (syntax.parse)(&head).filter(|(l, _)| *l > 0) else {
            match resync(&cx, region, pos.saturating_add(1), syntax).await? {
                Some(next) => {
                    cx.mark(move || mark);
                    cx.push(junk_node(region.sub(pos, next.saturating_sub(pos))))
                        .await;
                    pos = next;
                    continue;
                }
                None => {
                    let node = tail_node(&cx, region.tail(pos)).await?;
                    cx.mark(move || mark);
                    cx.push(node).await;
                    return Ok(());
                }
            }
        };
        let span = region.sub(pos, len);
        let mut node = Node::new(format!("Frame {index}"))
            .span(span)
            .summary(format!("{summary}, {len} bytes"));
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        let header = span.sub(0, (syntax.header)(&head));
        let frame_ref = FrameRef {
            span,
            header,
            syntax,
        };
        node = match syntax.expand {
            Some(expand) => node.lazy(expand, frame_ref),
            None => node.lazy(frame, frame_ref),
        };
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.mark(move || mark);
        cx.push(node).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn frame(cx: Cx, f: FrameRef) -> Result<()> {
    cx.emit(bits_node("Header", f.header, f.syntax.layout, false));
    let payload = f.span.tail(f.header.len);
    if !payload.is_empty() {
        cx.emit(Node::new("Payload").span(payload));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Embedded pictures

/// Dimensions and type of the image whose first bytes are `d` (cover art in
/// tags): `"600×600 JPEG"`, or just `"JPEG"` when the dimensions are not in
/// the bytes given.
pub fn image_info(d: &[u8]) -> Option<String> {
    let (kind, dims) = if d.starts_with(b"\x89PNG\r\n\x1a\n") {
        let dims = match (u32_be(d, 16), u32_be(d, 20)) {
            (Some(w), Some(h)) if d.get(12..16) == Some(b"IHDR") => Some((w, h)),
            _ => None,
        };
        ("PNG", dims)
    } else if d.starts_with(&[0xff, 0xd8, 0xff]) {
        ("JPEG", jpeg_dims(d))
    } else if d.starts_with(b"GIF87a") || d.starts_with(b"GIF89a") {
        let dims = u16_le(d, 6).zip(u16_le(d, 8));
        ("GIF", dims.map(|(w, h)| (u32::from(w), u32::from(h))))
    } else if d.starts_with(b"BM") && d.len() >= 26 {
        let w = crate::bytes::i32_le(d, 18).map(i32::unsigned_abs);
        let h = crate::bytes::i32_le(d, 22).map(i32::unsigned_abs);
        ("BMP", w.zip(h))
    } else if d.starts_with(b"RIFF") && d.get(8..12) == Some(b"WEBP") {
        let dims = match d.get(12..16) {
            Some(b"VP8X") => crate::bytes::u24_le(d, 24)
                .zip(crate::bytes::u24_le(d, 27))
                .map(|(w, h)| (w.saturating_add(1), h.saturating_add(1))),
            Some(b"VP8 ") => u16_le(d, 26)
                .zip(u16_le(d, 28))
                .map(|(w, h)| (u32::from(w & 0x3fff), u32::from(h & 0x3fff))),
            Some(b"VP8L") => crate::bytes::u32_le(d, 21).map(|v| {
                (
                    (v & 0x3fff).saturating_add(1),
                    ((v >> 14) & 0x3fff).saturating_add(1),
                )
            }),
            _ => None,
        };
        ("WebP", dims)
    } else {
        return None;
    };
    Some(match dims {
        Some((w, h)) => format!("{w}×{h} {kind}"),
        None => kind.to_owned(),
    })
}

/// The frame size from the first SOF marker of a JPEG, if `d` reaches it.
fn jpeg_dims(d: &[u8]) -> Option<(u32, u32)> {
    let mut at = 2usize;
    loop {
        if *d.get(at)? != 0xff {
            return None;
        }
        let marker = *d.get(at.saturating_add(1))?;
        match marker {
            0xff => at = at.saturating_add(1),
            0x01 | 0xd0..=0xd8 => at = at.saturating_add(2),
            0xc0..=0xcf if !matches!(marker, 0xc4 | 0xc8 | 0xcc) => {
                let h = u16_be(d, at.saturating_add(5))?;
                let w = u16_be(d, at.saturating_add(7))?;
                return Some((w.into(), h.into()));
            }
            0xd9 | 0xda => return None,
            _ => {
                let len = u16_be(d, at.saturating_add(2))?;
                at = at.saturating_add(2).saturating_add(len.into());
            }
        }
    }
}
