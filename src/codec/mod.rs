//! Codecs: decoders (decompressors, filters, ciphers) that turn a span into
//! a derived source.
//!
//! Decoders are written in-house (see the codec policy in `DESIGN.md`)
//! against [`pipeline::Decode`], and chained with [`Codec::Chain`]. A
//! [`Codec`] decodes eagerly ([`decode_span`]) or lazily, as far as reads
//! reach ([`Cx::decode_lazy`](crate::Cx::decode_lazy)); either way decoded
//! bytes count against [`crate::Limits::max_derived`].

pub mod inflate;
pub mod crypto;
pub mod pipeline;

use std::sync::Arc;

use pipeline::{Decode, Decoder, Status, Step, Streaming};

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

/// How content is encoded: a decompressor, a filter, or a chain of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Codec {
    Stored,
    /// Raw DEFLATE (RFC 1951).
    Deflate,
    /// zlib-wrapped DEFLATE (RFC 1950), with its Adler-32 checked.
    Zlib,
    /// Stages applied in order. `name` and `lazy_name` identify the chain
    /// for memoization (see [`Origin`]); they must be distinct.
    Chain {
        name: &'static str,
        lazy_name: &'static str,
        stages: Arc<[Codec]>,
    },
}

impl Codec {
    pub fn chain(name: &'static str, lazy_name: &'static str, stages: impl Into<Arc<[Codec]>>) -> Self {
        Codec::Chain {
            name,
            lazy_name,
            stages: stages.into(),
        }
    }

    /// The transform name of eagerly decoded sources.
    pub fn name(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate => "deflate",
            Codec::Zlib => "zlib",
            Codec::Chain { name, .. } => name,
        }
    }

    /// The transform name of lazily decoded sources.
    pub fn lazy_name(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate => "deflate (lazy)",
            Codec::Zlib => "zlib (lazy)",
            Codec::Chain { lazy_name, .. } => lazy_name,
        }
    }

    /// How the result is described ("decompressed", "decoded", "decrypted").
    pub fn verb(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate | Codec::Zlib => "decompressed",
            Codec::Chain { .. } => "decoded",
        }
    }

    /// The largest plausible ratio of decoded to encoded size; larger claims
    /// from a container are treated as bogus.
    pub fn max_ratio(&self) -> u64 {
        match self {
            Codec::Stored => 1,
            Codec::Deflate | Codec::Zlib => 1032,
            Codec::Chain { stages, .. } => stages
                .iter()
                .map(Codec::max_ratio)
                .fold(1u64, u64::saturating_mul),
        }
    }

    /// A fresh decoder (`None` for [`Codec::Stored`]).
    pub fn decoder(&self) -> Option<Box<dyn Decoder>> {
        Some(match self {
            Codec::Stored => return None,
            Codec::Deflate => Box::new(Streaming(inflate::Inflate::new())),
            Codec::Zlib => Box::new(Streaming(Zlib::default())),
            Codec::Chain { stages, .. } => Box::new(pipeline::Chain::new(
                stages.iter().filter_map(Codec::decoder).collect(),
            )),
        })
    }
}

impl Decode for inflate::Inflate {
    fn step(&mut self, input: &[u8], _eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        inflate::Inflate::step(self, input, out, step, limit)
    }

    fn consumed(&self) -> usize {
        inflate::Inflate::consumed(self)
    }
}

/// zlib: a 2-byte header, DEFLATE, and a big-endian Adler-32 trailer.
#[derive(Clone, Default)]
struct Zlib {
    inflate: inflate::Inflate,
    trailer: Option<u32>,
}

impl Decode for Zlib {
    fn step(&mut self, input: &[u8], _eof: bool, out: &mut Vec<u8>, step: usize, limit: usize) -> Result<Step> {
        let (Some(&cmf), Some(&flg)) = (input.first(), input.get(1)) else {
            return Err(Diagnostic::malformed("truncated zlib header"));
        };
        if cmf & 0x0f != 8 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
            return Err(Diagnostic::malformed("not a zlib stream"));
        }
        if flg & 0x20 != 0 {
            return Err(Diagnostic::unsupported("zlib preset dictionary"));
        }
        let body = input.get(2..).unwrap_or_default();
        match self.inflate.step(body, out, step, limit)? {
            Step::More => Ok(Step::More),
            Step::Done => {
                let at = 2usize.saturating_add(self.inflate.consumed());
                self.trailer = Some(
                    crate::bytes::u32_be(input, at)
                        .ok_or_else(|| Diagnostic::malformed("truncated zlib checksum"))?,
                );
                Ok(Step::Done)
            }
        }
    }

    fn consumed(&self) -> usize {
        let base = 2usize.saturating_add(self.inflate.consumed());
        if self.trailer.is_some() { base.saturating_add(4) } else { base }
    }

    fn warning(&self, out: &[u8]) -> Option<Diagnostic> {
        self.trailer
            .filter(|&t| t != adler32(out))
            .map(|_| Diagnostic::warning("zlib Adler-32 checksum mismatch"))
    }
}

/// Decodes `span` with `codec` into a derived source (memoized). `expected`
/// is the decoded size, if the container records it.
pub async fn decode_span(cx: &Cx, span: Span, codec: &Codec, expected: Option<u64>) -> Result<Decoded> {
    let origin = Origin {
        parent: span,
        transform: codec.name(),
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found);
    }
    let input = read_all(cx, span).await?;
    let Some(mut decoder) = codec.decoder() else {
        let len = to_u64(input.len());
        return cx.add_derived(origin, input, len, None);
    };
    let limit = to_usize(cx.limits().max_derived);
    let mut out = Vec::with_capacity(to_usize(expected.unwrap_or(0).min(1 << 24)));
    let mut error = None;
    loop {
        match decoder.decode(&input, true, &mut out, STEP, limit) {
            Ok(Status::Done) => break,
            Ok(Status::More) => cx.checkpoint().await,
            Ok(Status::NeedInput) => {
                error = Some(Diagnostic::malformed(format!("{} stream ended early", codec.name())).at(span));
                break;
            }
            Err(e) => {
                error = Some(if e.span.is_some() { e } else { e.at(span) });
                break;
            }
        }
    }
    if error.is_none() {
        error = decoder.warning(&out).map(|w| w.at(span));
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
    let consumed = to_u64(decoder.consumed());
    cx.add_derived(origin, out, consumed, error)
}

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

/// [`decode_span`] for raw DEFLATE or zlib-wrapped data.
pub async fn inflate_span(cx: &Cx, span: Span, zlib: bool, expected: Option<u64>) -> Result<Decoded> {
    let codec = if zlib { Codec::Zlib } else { Codec::Deflate };
    decode_span(cx, span, &codec, expected).await
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
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xedb8_8320
            } else {
                crc >> 1
            };
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
