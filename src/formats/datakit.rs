//! Small helpers shared by the data, system-artifact and font dissectors.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
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
pub async fn text_node(cx: &Cx, name: &'static str, span: Span, max: u64) -> Result<Node> {
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

/// Buffered random access to small pieces of a region, for formats that are
/// decoded a byte at a time (CBOR, pickle, ...). Offsets are relative to the
/// region.
pub struct ByteReader<'a> {
    cx: &'a Cx,
    region: Span,
    buf: Vec<u8>,
    buf_start: u64,
}

impl<'a> ByteReader<'a> {
    const WINDOW: u64 = 0x1000;

    pub fn new(cx: &'a Cx, region: Span) -> Self {
        ByteReader {
            cx,
            region,
            buf: Vec::new(),
            buf_start: 0,
        }
    }

    pub fn region(&self) -> Span {
        self.region
    }

    pub fn cx(&self) -> &'a Cx {
        self.cx
    }

    /// `len` bytes at `at`, which must all exist.
    pub async fn bytes(&mut self, at: u64, len: u64) -> Result<Vec<u8>> {
        let end = at.saturating_add(len);
        let buf_end = self.buf_start.saturating_add(to_u64(self.buf.len()));
        if at < self.buf_start || end > buf_end {
            if len > Self::WINDOW {
                return self.cx.read(self.region.sub_exact(at, len)?).await;
            }
            self.buf = self
                .cx
                .read_avail(self.region.sub(at, Self::WINDOW))
                .await?;
            self.buf_start = at;
        }
        let rel = crate::bytes::to_usize(at.saturating_sub(self.buf_start));
        let rel_end = rel.saturating_add(crate::bytes::to_usize(len));
        match self.buf.get(rel..rel_end) {
            Some(b) => Ok(b.to_vec()),
            None => Err(Diagnostic::truncated(
                Span::new(
                    self.region.source,
                    self.region.offset.saturating_add(at),
                    len,
                ),
                self.region.len.saturating_sub(at).min(len),
            )),
        }
    }

    pub async fn byte(&mut self, at: u64) -> Result<u8> {
        let b = self.bytes(at, 1).await?;
        Ok(b.first().copied().unwrap_or(0))
    }

    /// A big-endian unsigned integer of `len` (at most 8) bytes.
    pub async fn be(&mut self, at: u64, len: u64) -> Result<u64> {
        let b = self.bytes(at, len.min(8)).await?;
        Ok(be_uint(&b))
    }

    /// A little-endian unsigned integer of `len` (at most 8) bytes.
    pub async fn le(&mut self, at: u64, len: u64) -> Result<u64> {
        let b = self.bytes(at, len.min(8)).await?;
        Ok(le_uint(&b))
    }

    /// The span of `len` bytes at `at` (clamped to the region).
    pub fn span(&self, at: u64, len: u64) -> Span {
        self.region.sub(at, len)
    }
}

/// SHA-1 (for verifying Git checksums and computing torrent info hashes;
/// not for security).
pub fn sha1(data: &[u8]) -> [u8; 20] {
    let mut h: [u32; 5] = [
        0x6745_2301,
        0xefcd_ab89,
        0x98ba_dcfe,
        0x1032_5476,
        0xc3d2_e1f0,
    ];
    let bit_len = to_u64(data.len()).wrapping_mul(8);
    let mut padded = data.to_vec();
    padded.push(0x80);
    while padded.len() % 64 != 56 {
        padded.push(0);
    }
    padded.extend_from_slice(&bit_len.to_be_bytes());
    for block in padded.as_chunks::<64>().0 {
        let mut w = [0u32; 80];
        for (i, word) in block.as_chunks::<4>().0.iter().enumerate() {
            if let Some(slot) = w.get_mut(i) {
                *slot = u32::from_be_bytes(*word);
            }
        }
        for i in 16..80usize {
            let x = |k: usize| w.get(i.wrapping_sub(k)).copied().unwrap_or(0);
            let v = (x(3) ^ x(8) ^ x(14) ^ x(16)).rotate_left(1);
            if let Some(slot) = w.get_mut(i) {
                *slot = v;
            }
        }
        let [mut a, mut b, mut c, mut d, mut e] = h;
        for (i, &wi) in w.iter().enumerate() {
            let (f, k) = match i {
                0..=19 => ((b & c) | (!b & d), 0x5a82_7999),
                20..=39 => (b ^ c ^ d, 0x6ed9_eba1),
                40..=59 => ((b & c) | (b & d) | (c & d), 0x8f1b_bcdc),
                _ => (b ^ c ^ d, 0xca62_c1d6u32),
            };
            let t = a
                .rotate_left(5)
                .wrapping_add(f)
                .wrapping_add(e)
                .wrapping_add(k)
                .wrapping_add(wi);
            e = d;
            d = c;
            c = b.rotate_left(30);
            b = a;
            a = t;
        }
        for (slot, v) in h.iter_mut().zip([a, b, c, d, e]) {
            *slot = slot.wrapping_add(v);
        }
    }
    let mut out = [0u8; 20];
    for (chunk, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(h) {
        *chunk = v.to_be_bytes();
    }
    out
}

/// Big-endian unsigned integer from up to 8 bytes.
pub fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &x| {
        acc.checked_shl(8).unwrap_or(0) | u64::from(x)
    })
}

/// Little-endian unsigned integer from up to 8 bytes.
pub fn le_uint(bytes: &[u8]) -> u64 {
    bytes.iter().rev().fold(0u64, |acc, &x| {
        acc.checked_shl(8).unwrap_or(0) | u64::from(x)
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha1_vectors() {
        assert_eq!(
            hex_string(&sha1(b"")),
            "da39a3ee5e6b4b0d3255bfef95601890afd80709"
        );
        assert_eq!(
            hex_string(&sha1(b"abc")),
            "a9993e364706816aba3e25717850c26c9cd0d89d"
        );
        let long = vec![b'a'; 1000];
        assert_eq!(
            hex_string(&sha1(&long)),
            "291e9a6c66994949b57ba5e650361e98fc36b1ba"
        );
    }
}
