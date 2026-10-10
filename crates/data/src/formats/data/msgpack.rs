//! MessagePack (`.msgpack`, `.mpk`): every value starts with a type byte
//! that also holds small integers, short lengths and counts; longer
//! arguments follow in big-endian. Maps and arrays record their member
//! count but not their size, so finding the end of a value means scanning
//! it. Extension types carry a signed type code; type -1 (timestamp) is
//! decoded in its 32-, 64- and 96-bit forms.
//!
//! MessagePack has no magic number. The probe only accepts a file the
//! probe window holds entirely and that parses, to its last byte, as one
//! map with at least two entries whose keys are all UTF-8 text without
//! control characters, every string in it being valid UTF-8: the common
//! shape of a MessagePack document (a record). A first byte of `0x81..=0x8f`
//! or `0xde`/`0xdf` is not text and not a known magic, and parsing every
//! length to exactly the end of the file rules out almost all other
//! binary data. Anything else (arrays, sequences of values, large files)
//! is reached through the extension ("inspect as").

use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, be_uint, hex};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::valuetree as vt;

pub static FORMAT: Format = Format {
    name: "msgpack",
    title: "MessagePack data",
    extensions: &["msgpack", "mpk", "msgp"],
    mime: "application/vnd.msgpack",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    UInt,
    NegFix,
    Int,
    Nil,
    Bool(bool),
    Float32,
    Float64,
    Str,
    Bin,
    Array,
    Map,
    /// Extension with its type code.
    Ext(i8),
    Unused,
}

/// A value's type byte and argument: the integer, the payload length, or
/// the member count.
#[derive(Clone, Copy, Debug)]
struct Item {
    kind: Kind,
    /// Header bytes (type byte, length, ext type, fixed-size number).
    head: u64,
    arg: u64,
    /// Integer width in bits (for `UInt`/`Int`).
    bits: u8,
}

impl Item {
    /// Payload bytes after the header.
    fn payload(&self) -> u64 {
        match self.kind {
            Kind::Str | Kind::Bin | Kind::Ext(_) => self.arg,
            _ => 0,
        }
    }
    /// Nested values (map entries count twice).
    fn nested(&self) -> u64 {
        match self.kind {
            Kind::Array => self.arg,
            Kind::Map => self.arg.saturating_mul(2),
            _ => 0,
        }
    }
}

/// Decodes the header at the start of `b` (`None` if `b` is too short).
fn decode(b: &[u8]) -> Option<Item> {
    let t = *b.first()?;
    let arg = |n: usize| -> Option<u64> { b.get(1..n.checked_add(1)?).map(be_uint) };
    let item = |kind, head, arg, bits| {
        Some(Item {
            kind,
            head,
            arg,
            bits,
        })
    };
    // Widths of the 1/2/4/8-byte variants, by distance from the first.
    let width = |base: u8| -> Option<usize> {
        [1usize, 2, 4, 8]
            .get(usize::from(t.wrapping_sub(base)))
            .copied()
    };
    let plus = |n: usize, k: u64| (n as u64).saturating_add(k);
    let bits = |n: usize| u8::try_from(n.saturating_mul(8)).unwrap_or(64);
    match t {
        0x00..=0x7f => item(Kind::UInt, 1, u64::from(t), 8),
        0x80..=0x8f => item(Kind::Map, 1, u64::from(t & 0x0f), 0),
        0x90..=0x9f => item(Kind::Array, 1, u64::from(t & 0x0f), 0),
        0xa0..=0xbf => item(Kind::Str, 1, u64::from(t & 0x1f), 0),
        0xc0 => item(Kind::Nil, 1, 0, 0),
        0xc1 => item(Kind::Unused, 1, 0, 0),
        0xc2 | 0xc3 => item(Kind::Bool(t == 0xc3), 1, 0, 0),
        0xc4..=0xc6 => {
            let n = width(0xc4)?;
            item(Kind::Bin, plus(n, 1), arg(n)?, 0)
        }
        0xc7..=0xc9 => {
            let n = width(0xc7)?;
            let ty = i8::from_le_bytes([*b.get(n.checked_add(1)?)?]);
            item(Kind::Ext(ty), plus(n, 2), arg(n)?, 0)
        }
        0xca => item(Kind::Float32, 5, arg(4)?, 32),
        0xcb => item(Kind::Float64, 9, arg(8)?, 64),
        0xcc..=0xcf => {
            let n = width(0xcc)?;
            item(Kind::UInt, plus(n, 1), arg(n)?, bits(n))
        }
        0xd0..=0xd3 => {
            let n = width(0xd0)?;
            item(Kind::Int, plus(n, 1), arg(n)?, bits(n))
        }
        0xd4..=0xd8 => {
            let ty = i8::from_le_bytes([*b.get(1)?]);
            item(
                Kind::Ext(ty),
                2,
                [1u64, 2, 4, 8, 16]
                    .get(usize::from(t.wrapping_sub(0xd4)))
                    .copied()?,
                0,
            )
        }
        0xd9..=0xdb => {
            let n = width(0xd9)?;
            item(Kind::Str, plus(n, 1), arg(n)?, 0)
        }
        0xdc | 0xdd => {
            let n = if t == 0xdc { 2 } else { 4 };
            item(Kind::Array, plus(n, 1), arg(n)?, 0)
        }
        0xde | 0xdf => {
            let n = if t == 0xde { 2 } else { 4 };
            item(Kind::Map, plus(n, 1), arg(n)?, 0)
        }
        0xe0..=0xff => item(Kind::NegFix, 1, u64::from(t), 8),
    }
}

/// The header at `at` (at most 10 bytes: ext32 with its type).
async fn head(r: &mut ByteReader<'_>, at: u64) -> Result<Item> {
    let avail = r.region().len.saturating_sub(at).min(10);
    let b = r.bytes(at, avail).await?;
    match decode(&b) {
        Some(item) if item.kind == Kind::Unused => {
            Err(Diagnostic::malformed("type byte 0xc1 is never used").at(r.span(at, 1)))
        }
        Some(item) => Ok(item),
        None => Err(Diagnostic::truncated(r.span(at, 10), avail)),
    }
}

/// The end of the value starting at `at` (scanning nested values).
async fn end_of(r: &mut ByteReader<'_>, at: u64) -> Result<u64> {
    let mut stack: Vec<u64> = vec![1];
    let mut pos = at;
    let len = r.region().len;
    loop {
        while stack.last() == Some(&0) {
            stack.pop();
        }
        let Some(top) = stack.last_mut() else {
            return Ok(pos);
        };
        *top = top.saturating_sub(1);
        r.cx().checkpoint().await;
        let h = head(r, pos).await?;
        let body = pos.saturating_add(h.head);
        pos = body.saturating_add(h.payload());
        if pos > len {
            return Err(Diagnostic::truncated(
                r.span(body, h.payload()),
                len.saturating_sub(body),
            ));
        }
        let nested = h.nested();
        if nested > 0 {
            // Every value takes at least one byte.
            if nested > len.saturating_sub(pos) {
                return Err(Diagnostic::malformed(format!(
                    "{} members do not fit in the remaining {} bytes",
                    nested,
                    len.saturating_sub(pos)
                ))
                .at(r.span(pos, 1)));
            }
            if stack.len() >= vt::MAX_DEPTH {
                return Err(Diagnostic::limit(format!(
                    "values nested deeper than {}",
                    vt::MAX_DEPTH
                ))
                .at(r.span(pos, 1)));
            }
            stack.push(nested);
        }
    }
}

/// Synchronous validation for the probe: the end of the value at `pos`,
/// requiring UTF-8 strings (and, for `keys_text`, text keys).
fn skip(b: &[u8], pos: usize, depth: usize, keys_text: bool) -> Option<usize> {
    if depth > 32 {
        return None;
    }
    let h = decode(b.get(pos..)?)?;
    let body = pos.checked_add(usize::try_from(h.head).ok()?)?;
    let end = body.checked_add(usize::try_from(h.payload()).ok()?)?;
    match h.kind {
        Kind::Unused => None,
        Kind::Str => {
            std::str::from_utf8(b.get(body..end)?).ok()?;
            Some(end)
        }
        Kind::Array | Kind::Map => {
            let mut p = end;
            for i in 0..h.nested() {
                if keys_text && h.kind == Kind::Map && i % 2 == 0 {
                    let k = decode(b.get(p..)?)?;
                    let kb = p.checked_add(usize::try_from(k.head).ok()?)?;
                    let ke = kb.checked_add(usize::try_from(k.arg).ok()?)?;
                    let key = std::str::from_utf8(b.get(kb..ke)?).ok()?;
                    if k.kind != Kind::Str || key.is_empty() || key.chars().any(char::is_control) {
                        return None;
                    }
                }
                p = skip(b, p, depth.checked_add(1)?, false)?;
            }
            Some(p)
        }
        _ => (end <= b.len()).then_some(end),
    }
}

fn probe(h: &Head<'_>) -> bool {
    let whole = u64::try_from(h.data.len()).is_ok_and(|n| n == h.len);
    let Some(first) = h.data.first().and_then(|_| decode(h.data)) else {
        return false;
    };
    whole
        && h.len >= 8
        && first.kind == Kind::Map
        && first.arg >= 2
        && skip(h.data, 0, 0, true) == Some(h.data.len())
}

fn describe(h: &Item) -> String {
    match h.kind {
        Kind::Map => vt::map_summary("map", Some(h.arg), "entry", "entries"),
        Kind::Array => vt::array_summary("array", Some(h.arg)),
        Kind::Str => "string".to_owned(),
        Kind::Bin => "binary".to_owned(),
        Kind::Ext(t) => format!("extension type {t}"),
        Kind::Nil => "nil".to_owned(),
        Kind::Bool(_) => "boolean".to_owned(),
        Kind::Float32 | Kind::Float64 => "float".to_owned(),
        _ => "integer".to_owned(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let first = head(&mut r, 0).await?;
    // One container filling the file: show its members at the top.
    if matches!(first.kind, Kind::Map | Kind::Array)
        && end_of(&mut r, 0).await.ok() == Some(input.span.len)
    {
        cx.annotate(format!("MessagePack {}", describe(&first)));
        return members(cx, (input.span, 0, Path::new())).await;
    }
    cx.annotate(format!("MessagePack, first value: {}", describe(&first)));
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < input.span.len {
        let at = (pos, index);
        cx.mark(move || at);
        let end = match end_of(&mut r, pos).await {
            Ok(end) => end,
            Err(d) => {
                cx.push(
                    Node::new(format!("[{index}]"))
                        .span(r.span(pos, input.span.len.saturating_sub(pos)))
                        .diag(d),
                )
                .await;
                break;
            }
        };
        let node = item_node(&mut r, pos, end, format!("[{index}]"), &Path::new()).await?;
        cx.progress(end, input.span.len);
        cx.push(node).await;
        pos = end;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The value of a timestamp extension (type -1): seconds and nanoseconds.
fn timestamp(data: &[u8]) -> Option<(i64, u32)> {
    match data.len() {
        4 => Some((i64::try_from(be_uint(data)).ok()?, 0)),
        8 => {
            let v = be_uint(data);
            Some((
                i64::try_from(v & 0x3_ffff_ffff).ok()?,
                u32::try_from(v >> 34).ok()?,
            ))
        }
        12 => {
            let nanos = u32::try_from(be_uint(data.get(..4)?)).ok()?;
            let secs = i64::from_be_bytes(data.get(4..12)?.try_into().ok()?);
            Some((secs, nanos))
        }
        _ => None,
    }
}

/// A node for the value at `start..end`.
async fn item_node(
    r: &mut ByteReader<'_>,
    start: u64,
    end: u64,
    name: String,
    path: &Path,
) -> Result<Node> {
    let h = head(r, start).await?;
    let node = Node::new(name).span(r.span(start, end.saturating_sub(start)));
    let body = start.saturating_add(h.head);
    Ok(match h.kind {
        Kind::UInt => node.value(vt::uint(h.arg, h.bits.max(8))),
        Kind::NegFix => node.value(vt::int(i64::from(i8::from_le_bytes([h.arg as u8])), 8)),
        Kind::Int => {
            let shift = 64u32.saturating_sub(u32::from(h.bits));
            let v = (h.arg.checked_shl(shift).unwrap_or(0) as i64)
                .checked_shr(shift)
                .unwrap_or(0);
            node.value(vt::int(v, h.bits))
        }
        Kind::Nil => node.summary("nil"),
        Kind::Bool(b) => node.value(Value::Bool(b)),
        Kind::Float32 => node.value(Value::Float(f64::from(f32::from_bits(
            u32::try_from(h.arg).unwrap_or(0),
        )))),
        Kind::Float64 => node.value(Value::Float(f64::from_bits(h.arg))),
        Kind::Str => {
            let data = r.bytes(body, h.arg.min(vt::MAX_TEXT)).await?;
            vt::text(node, &data, h.arg)
        }
        Kind::Bin => {
            let data = r.bytes(body, h.arg.min(vt::MAX_BYTES)).await?;
            vt::bytes(node, "binary", data, h.arg)
        }
        Kind::Ext(-1) => {
            let data = r.bytes(body, h.arg.min(12)).await?;
            match timestamp(&data) {
                Some((secs, nanos)) if nanos < 1_000_000_000 => node
                    .value(Value::Timestamp { unix_seconds: secs })
                    .summary(if nanos == 0 {
                        format!("timestamp extension, {} bytes", h.arg)
                    } else {
                        format!(
                            "timestamp extension, {} bytes: {}",
                            h.arg,
                            vt::datetime(secs, nanos)
                        )
                    }),
                _ => vt::bytes(node, "timestamp extension", data, h.arg)
                    .diag(Diagnostic::malformed("invalid timestamp extension")),
            }
        }
        Kind::Ext(t) => {
            let data = r.bytes(body, h.arg.min(vt::MAX_BYTES)).await?;
            vt::bytes(node, &format!("extension type {t}"), data, h.arg)
        }
        Kind::Array | Kind::Map => {
            let node = node.summary(describe(&h));
            if h.arg == 0 {
                node
            } else {
                match vt::enter(path, start) {
                    Ok(p) => node.lazy(
                        crate::expander!(self::members: (Span, u64, Path)),
                        (r.region(), start, p),
                    ),
                    Err(d) => node.diag(d),
                }
            }
        }
        Kind::Unused => node.value(hex(0xc1u8, 8)),
    })
}

/// Short text for a map key: strings as they are, numbers in decimal.
async fn key_name(r: &mut ByteReader<'_>, at: u64, index: u64) -> Result<String> {
    let h = head(r, at).await?;
    Ok(match h.kind {
        Kind::Str => {
            let data = r.bytes(at.saturating_add(h.head), h.arg.min(0x200)).await?;
            vt::key_name(&String::from_utf8_lossy(&data), index)
        }
        Kind::UInt => h.arg.to_string(),
        Kind::NegFix => i8::from_le_bytes([h.arg as u8]).to_string(),
        Kind::Int => {
            let shift = 64u32.saturating_sub(u32::from(h.bits));
            ((h.arg.checked_shl(shift).unwrap_or(0) as i64)
                .checked_shr(shift)
                .unwrap_or(0))
            .to_string()
        }
        Kind::Nil => "nil".to_owned(),
        Kind::Bool(b) => b.to_string(),
        _ => format!("key #{index}"),
    })
}

async fn members(cx: Cx, (region, start, path): (Span, u64, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let h = head(&mut r, start).await?;
    cx.set_count(Count::Exact(h.arg));
    let pairs = h.kind == Kind::Map;
    let (mut pos, mut index) = cx
        .resume::<(u64, u64)>()
        .unwrap_or((start.saturating_add(h.head), 0));
    while index < h.arg {
        let at = (pos, index);
        cx.mark(move || at);
        let node = if pairs {
            let key_end = end_of(&mut r, pos).await?;
            let value_end = end_of(&mut r, key_end).await?;
            let name = key_name(&mut r, pos, index).await?;
            let node = item_node(&mut r, key_end, value_end, name, &path).await?;
            pos = value_end;
            node
        } else {
            let end = end_of(&mut r, pos).await?;
            let node = item_node(&mut r, pos, end, format!("[{index}]"), &path).await?;
            pos = end;
            node
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}
