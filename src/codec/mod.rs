//! Codecs: decoders that turn a span into a derived source.
//!
//! Decoders here are written in-house (see the codec policy in `DESIGN.md`).
//! Today they decode whole members into memory, bounded by
//! [`crate::Limits::max_derived`], in budgeted steps; streaming with
//! checkpoints is future work.

pub mod inflate;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::{Origin, SourceId, Span};

/// The result of decoding a span.
#[derive(Clone, Debug)]
pub struct Decoded {
    pub source: SourceId,
    /// The whole derived source.
    pub span: Span,
    /// Compressed bytes consumed (the stream may end before its span does).
    pub consumed: u64,
    /// Set if decoding stopped early; `span` then holds the partial output.
    pub error: Option<Diagnostic>,
}

/// Bytes decoded per step between budget checkpoints.
const STEP: usize = 64 * 1024;

/// Reads `span` fully into memory, in pieces no larger than the read limit.
pub async fn read_all(cx: &Cx, span: Span) -> Result<Vec<u8>> {
    let limits = cx.limits();
    if span.len > limits.max_derived {
        return Err(Diagnostic::limit(format!(
            "{:#x} compressed bytes exceed the {:#x}-byte limit",
            span.len, limits.max_derived
        ))
        .at(span));
    }
    let piece = limits.max_read.clamp(1, 1 << 20);
    let mut out = Vec::with_capacity(to_usize(span.len));
    let mut pos = 0u64;
    while pos < span.len {
        let data = cx.read(span.sub(pos, piece)).await?;
        if data.is_empty() {
            break;
        }
        pos = pos.saturating_add(to_u64(data.len()));
        out.extend_from_slice(&data);
    }
    Ok(out)
}

/// Raw DEFLATE (`"deflate"`) or zlib-wrapped (`"zlib"`) data in `span`,
/// decoded into a derived source. `expected` is the decoded size, if the
/// container records it.
pub async fn inflate_span(
    cx: &Cx,
    span: Span,
    zlib: bool,
    expected: Option<u64>,
) -> Result<Decoded> {
    let origin = Origin {
        parent: span,
        transform: if zlib { "zlib" } else { "deflate" },
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found);
    }
    let input = read_all(cx, span).await?;
    let mut start = 0usize;
    if zlib {
        let (Some(&cmf), Some(&flg)) = (input.first(), input.get(1)) else {
            return Err(Diagnostic::truncated(span.sub(0, 2), to_u64(input.len())));
        };
        if cmf & 0x0f != 8 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
            return Err(Diagnostic::malformed("not a zlib stream").at(span.sub(0, 2)));
        }
        if flg & 0x20 != 0 {
            return Err(Diagnostic::unsupported("zlib preset dictionary").at(span.sub(0, 2)));
        }
        start = 2;
    }
    let body = input.get(start..).unwrap_or_default();
    let limit = to_usize(cx.limits().max_derived);
    let mut out = Vec::with_capacity(to_usize(expected.unwrap_or(0).min(1 << 24)));
    let mut inflater = inflate::Inflate::new();
    let mut error = None;
    loop {
        match inflater.step(body, &mut out, STEP, limit) {
            Ok(inflate::Step::Done) => break,
            Ok(inflate::Step::More) => cx.checkpoint().await,
            Err(e) => {
                error = Some(e.at(span));
                break;
            }
        }
    }
    let mut consumed = to_u64(start.saturating_add(inflater.consumed()));
    if zlib && error.is_none() {
        let at = to_usize(consumed);
        match crate::bytes::u32_be(&input, at) {
            Some(stored) if stored != adler32(&out) => {
                error = Some(Diagnostic::warning("zlib Adler-32 checksum mismatch").at(span));
            }
            Some(_) => {}
            None => error = Some(Diagnostic::truncated(span.sub(consumed, 4), 0)),
        }
        consumed = consumed.saturating_add(4);
    }
    if let (Some(expected), None) = (expected, &error)
        && expected != to_u64(out.len())
    {
        error = Some(Diagnostic::warning(format!(
            "decoded {:#x} bytes, expected {expected:#x}",
            out.len()
        )));
    }
    if out.is_empty()
        && let Some(e) = error
    {
        return Err(e);
    }
    cx.add_derived(origin, out, consumed, error)
}

pub fn adler32(data: &[u8]) -> u32 {
    let (mut a, mut b) = (1u32, 0u32);
    for chunk in data.chunks(5552) {
        for &byte in chunk {
            a = a.wrapping_add(u32::from(byte));
            b = b.wrapping_add(a);
        }
        a %= 65521;
        b %= 65521;
    }
    b << 16 | a
}

pub fn crc32(data: &[u8]) -> u32 {
    let mut crc = !0u32;
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 { crc >> 1 ^ 0xedb8_8320 } else { crc >> 1 };
        }
    }
    !crc
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn checksums() {
        assert_eq!(crc32(b"123456789"), 0xcbf4_3926);
        assert_eq!(adler32(b"Wikipedia"), 0x11e6_0398);
    }

    #[test]
    fn inflate_stored_fixed_dynamic() {
        // "hello" as a stored block.
        let stored = [0x01, 0x05, 0x00, 0xfa, 0xff, b'h', b'e', b'l', b'l', b'o'];
        assert_eq!(inflate::inflate(&stored, 100).unwrap(), b"hello");
        // zlib.compress(b"hello hello hello hello")[2:-4] (fixed Huffman).
        let fixed = [203, 72, 205, 201, 201, 87, 200, 64, 39, 1];
        assert_eq!(
            inflate::inflate(&fixed, 100).unwrap(),
            b"hello hello hello hello"
        );
        // Dynamic Huffman blocks (generated by zlib at level 9).
        let dynamic = include_bytes!("testdata/words.deflate");
        let expected = include_bytes!("testdata/words.txt");
        assert_eq!(inflate::inflate(dynamic, 1 << 20).unwrap(), expected);
        // Output limit.
        assert!(inflate::inflate(dynamic, 1000).is_err());
        // Truncation is an error, not a panic.
        assert!(inflate::inflate(&dynamic[..dynamic.len() / 2], 1 << 20).is_err());
    }
}
