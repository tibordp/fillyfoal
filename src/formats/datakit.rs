//! Small helpers shared by the data, system-artifact and font dissectors.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Seconds between 1970-01-01 and 2001-01-01 (Core Foundation epoch).
pub const CF_EPOCH: i64 = 978_307_200;

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
pub fn enumv(raw: impl Into<u64>, bits: u8, table: EnumTable) -> Value {
    let raw = raw.into();
    Value::Enum {
        raw,
        bits,
        name: lookup(table, raw),
    }
}

pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// The name for `raw` in `table`, or `fallback` formatted with the number.
pub fn name_or(table: EnumTable, raw: u64, prefix: &str) -> String {
    lookup(table, raw).map_or_else(|| format!("{prefix} {raw:#x}"), str::to_owned)
}

/// Lowercase hexadecimal of `bytes` (hashes, IDs).
pub fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// A four-character code, with non-printable bytes escaped.
pub fn fourcc(bytes: &[u8]) -> String {
    bytes
        .iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b).to_string()
            } else {
                format!("\\x{b:02x}")
            }
        })
        .collect()
}

/// Mac OS Roman, the classic Macintosh character set.
pub fn mac_roman(bytes: &[u8]) -> String {
    const HIGH: &str = "ÄÅÇÉÑÖÜáàâäãåçéèêëíìîïñóòôöõúùûü†°¢£§•¶ß®©™´¨≠ÆØ∞±≤≥¥µ∂∑∏π∫ªºΩæø¿¡¬√ƒ≈∆«»…\u{a0}ÀÃÕŒœ–—“”‘’÷◊ÿŸ⁄€‹›ﬁﬂ‡·‚„‰ÂÊÁËÈÍÎÏÌÓÔ\u{f8ff}ÒÚÛÙıˆ˜¯˘˙˚¸˝˛ˇ";
    bytes
        .iter()
        .map(|&b| {
            if b < 0x80 {
                char::from(b)
            } else {
                HIGH.chars().nth(usize::from(b & 0x7f)).unwrap_or('?')
            }
        })
        .collect()
}

/// Text shortened to `max` characters for summaries.
pub fn clip(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Reads up to `max` bytes of `span` as lossy UTF-8 text (for previews).
pub async fn text_preview(cx: &Cx, span: Span, max: u64) -> Result<String> {
    let data = cx.read_avail(span.sub(0, max)).await?;
    Ok(String::from_utf8_lossy(&data).into_owned())
}

/// A leaf for a text field stored at `span`, read in full (bounded by `max`).
pub async fn text_node(
    cx: &Cx,
    name: &'static str,
    span: Span,
    max: u64,
) -> Result<Node> {
    let text = text_preview(cx, span, max).await?;
    let mut node = Node::new(name).span(span).value(Value::Text(text));
    if span.len > max {
        node = node.summary(format!("first {max:#x} of {:#x} bytes", span.len));
    }
    Ok(node)
}

/// A human-readable byte count.
pub fn size(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} bytes");
    }
    let mut value = n as f64 / 1024.0;
    let mut unit = 0usize;
    while value >= 1024.0 && unit < 4 {
        value /= 1024.0;
        unit = unit.saturating_add(1);
    }
    format!("{value:.1} {}", UNITS.get(unit).copied().unwrap_or("?"))
}

/// Seconds since 2001-01-01 as a Unix timestamp value.
pub fn cf_time(seconds: f64) -> Value {
    let whole = if seconds.is_finite() {
        seconds.floor().clamp(i64::MIN as f64, i64::MAX as f64) as i64
    } else {
        0
    };
    Value::Timestamp {
        unix_seconds: whole.saturating_add(CF_EPOCH),
    }
}

/// Length helper: `usize` to `u64`.
pub fn len64(n: usize) -> u64 {
    to_u64(n)
}
