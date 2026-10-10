//! Small helpers shared by the data, system-artifact and font dissectors.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

pub use super::civil::CF_EPOCH;
pub use super::fmt::{clip, fourcc, size};
pub use super::val::{enumv, hex, name_or, text, uint};
/// Lowercase hexadecimal of `bytes` (hashes, IDs).
pub use crate::text::hex_lower as hex_string;

/// Mac OS Roman, the classic Macintosh character set.
pub fn mac_roman(bytes: &[u8]) -> String {
    crate::codec::charset::Charset::MacRoman.decode(bytes)
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
///
/// Reads served from the buffered window cost nothing by themselves, so
/// every [`ByteReader::CALLS`] calls charge a checkpoint: a parser driven by
/// this reader pays for its byte-at-a-time work, not just for the windows.
pub struct ByteReader<'a> {
    cx: &'a Cx,
    region: Span,
    buf: Vec<u8>,
    buf_start: u64,
    calls: u32,
}

impl<'a> ByteReader<'a> {
    const WINDOW: u64 = 0x1000;
    /// Calls between checkpoints.
    pub const CALLS: u32 = 256;

    pub fn new(cx: &'a Cx, region: Span) -> Self {
        ByteReader {
            cx,
            region,
            buf: Vec::new(),
            buf_start: 0,
            calls: 0,
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
        self.calls = self.calls.wrapping_add(1);
        if self.calls.is_multiple_of(Self::CALLS) {
            self.cx.checkpoint().await;
        }
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
/// not for security). Of a small buffer; hash input-sized data with
/// [`sha1_paced`].
pub fn sha1(data: &[u8]) -> [u8; 20] {
    use crate::codec::crypto::{Hash, Sha1};
    Sha1::digest(data).try_into().unwrap_or([0; 20])
}

/// Bytes hashed (or checksummed) per unit of work by the paced helpers: on
/// the order of a microsecond of hashing.
pub const HASH_UNIT: usize = 1024;

/// Feeds `data` to `feed` [`HASH_UNIT`] bytes at a time with a checkpoint
/// after each piece, so hashing an input-sized buffer is charged in
/// proportion and yields between pieces.
pub async fn feed_paced(cx: &Cx, data: &[u8], mut feed: impl FnMut(&[u8])) {
    for piece in data.chunks(HASH_UNIT) {
        feed(piece);
        cx.checkpoint().await;
    }
}

/// The digest of `data` with hash `H`, computed in paced pieces.
pub async fn digest_paced<H: crate::codec::crypto::Hash>(cx: &Cx, data: &[u8]) -> Vec<u8> {
    let mut h = H::new();
    feed_paced(cx, data, |piece| h.update(piece)).await;
    h.finish()
}

/// [`sha1`] of an input-sized buffer, in paced pieces.
pub async fn sha1_paced(cx: &Cx, data: &[u8]) -> [u8; 20] {
    digest_paced::<crate::codec::crypto::Sha1>(cx, data)
        .await
        .try_into()
        .unwrap_or([0; 20])
}

/// `crc.checksum(data)` of an input-sized buffer, in paced pieces.
pub async fn crc_paced(cx: &Cx, crc: &crate::codec::crc::Crc, data: &[u8]) -> u64 {
    let mut reg = crc.init();
    feed_paced(cx, data, |piece| reg = crc.update(reg, piece)).await;
    crc.finish(reg)
}

/// [`crate::codec::crc::crc32`] of an input-sized buffer, in paced pieces.
pub async fn crc32_paced(cx: &Cx, data: &[u8]) -> u32 {
    low32(crc_paced(cx, &crate::codec::crc::CRC32, data).await)
}

/// [`crate::codec::crc::crc32c`] of an input-sized buffer, in paced pieces.
pub async fn crc32c_paced(cx: &Cx, data: &[u8]) -> u32 {
    low32(crc_paced(cx, &crate::codec::crc::CRC32C, data).await)
}

/// [`crate::codec::crc::crc24`] of an input-sized buffer, in paced pieces.
pub async fn crc24_paced(cx: &Cx, data: &[u8]) -> u32 {
    low32(crc_paced(cx, &crate::codec::crc::CRC24_OPENPGP, data).await)
}

fn low32(v: u64) -> u32 {
    u32::try_from(v & 0xffff_ffff).unwrap_or(0)
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

/// A GUID in Microsoft mixed-endian layout from raw bytes (zero-padded).
pub fn guid_le(b: &[u8]) -> crate::value::Guid {
    let get = |i: usize| b.get(i).copied().unwrap_or(0);
    let mut data4 = [0u8; 8];
    for (i, d) in data4.iter_mut().enumerate() {
        *d = get(i.saturating_add(8));
    }
    crate::value::Guid {
        data1: u32::from_le_bytes([get(0), get(1), get(2), get(3)]),
        data2: u16::from_le_bytes([get(4), get(5)]),
        data3: u16::from_le_bytes([get(6), get(7)]),
        data4,
    }
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
