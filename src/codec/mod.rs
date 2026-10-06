//! Codecs: decoders (decompressors, filters, ciphers) that turn a span into
//! a derived source.
//!
//! Decoders are written in-house (see the codec policy in `DESIGN.md`)
//! against [`pipeline::Decode`], and chained with [`Codec::Chain`]. A
//! [`Codec`] decodes eagerly ([`decode_span`]) or lazily, as far as reads
//! reach ([`Cx::decode_lazy`](crate::Cx::decode_lazy)); either way decoded
//! bytes count against [`crate::Limits::max_derived`].

pub mod inflate;
pub mod bzip2;
pub mod crypto;
pub mod filters;
pub mod lz;
pub mod lzfse;
pub mod pbz;
pub mod lzma;
pub mod xz;
pub mod zstd;
pub mod pipeline;
pub mod unixz;

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
    /// Hex digit pairs (PDF `ASCIIHexDecode`).
    AsciiHex,
    /// Base-85 (PDF/PostScript `ASCII85Decode`).
    Ascii85,
    /// PDF `RunLengthDecode`.
    RunLength,
    /// PackBits (TIFF, Mac).
    PackBits,
    /// LZW with MSB-first codes (PDF `LZWDecode`, TIFF).
    Lzw { early_change: bool },
    /// PNG row predictors; `bpp` bytes per pixel, `row` bytes per row.
    PngPredictor { bpp: usize, row: usize },
    /// TIFF horizontal differencing (8-bit components).
    TiffPredictor { bpp: usize, row: usize },
    /// Apple LZFSE (with LZVN blocks).
    Lzfse,
    /// Apple's chunked wrapper (`pbzx`/`pbze`/`pbz4`/`pbzz`).
    Pbz,
    /// Unix `compress` (`.Z`, LSB-first LZW with a header).
    UnixCompress,
    /// Zstandard frames.
    Zstd,
    /// The `.xz` container (LZMA2 with BCJ/Delta filters, checks).
    Xz,
    /// `.lzma` ("LZMA alone").
    LzmaAlone,
    /// Raw LZMA2 chunks.
    Lzma2,
    /// Raw LZMA with known properties and (if known) decoded size.
    LzmaRaw { props: lzma::Props, size: Option<usize> },
    /// bzip2 streams.
    Bzip2,
    /// LZ4 frames (also legacy and skippable frames).
    Lz4Frame,
    /// One raw LZ4 block.
    Lz4Block,
    /// Raw Snappy.
    Snappy,
    /// The Snappy framing format.
    SnappyFramed,
    /// Adobe Type 1 `eexec` decryption (binary, or hex text).
    Eexec { hex: bool },
    /// Traditional PKWARE encryption with this password (the 12-byte
    /// encryption header is consumed, not output).
    ZipCrypto(crypto::Key),
    /// AES-CTR with a little-endian counter from 1 (WinZip AE-x), with this
    /// AES key.
    AesCtrLe(crypto::Key),
    /// RC4 with this key.
    Rc4(crypto::Key),
    /// AES-CBC with this key; the IV is the first 16 bytes and the data is
    /// PKCS#7-padded (PDF AESV2/AESV3).
    AesCbc(crypto::Key),
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
            Codec::ZipCrypto(_) => "zipcrypto",
            Codec::AesCtrLe(_) => "aes-ctr",
            Codec::Rc4(_) => "rc4",
            Codec::AesCbc(_) => "aes-cbc",
            Codec::AsciiHex => "asciihex",
            Codec::Ascii85 => "ascii85",
            Codec::RunLength => "runlength",
            Codec::PackBits => "packbits",
            Codec::Lzw { .. } => "lzw",
            Codec::PngPredictor { .. } => "png-predictor",
            Codec::TiffPredictor { .. } => "tiff-predictor",
            Codec::Eexec { .. } => "eexec",
            Codec::Bzip2 => "bzip2",
            Codec::Zstd => "zstd",
            Codec::UnixCompress => "unix-compress",
            Codec::Lzfse => "lzfse",
            Codec::Pbz => "pbz",
            Codec::Xz => "xz",
            Codec::LzmaAlone => "lzma",
            Codec::Lzma2 => "lzma2",
            Codec::LzmaRaw { .. } => "lzma-raw",
            Codec::Lz4Frame => "lz4",
            Codec::Lz4Block => "lz4-block",
            Codec::Snappy => "snappy",
            Codec::SnappyFramed => "snappy-framed",
            Codec::Chain { name, .. } => name,
        }
    }

    /// The transform name of lazily decoded sources.
    pub fn lazy_name(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate => "deflate (lazy)",
            Codec::Zlib => "zlib (lazy)",
            Codec::ZipCrypto(_) => "zipcrypto (lazy)",
            Codec::AesCtrLe(_) => "aes-ctr (lazy)",
            Codec::Rc4(_) => "rc4 (lazy)",
            Codec::AesCbc(_) => "aes-cbc (lazy)",
            Codec::AsciiHex => "asciihex (lazy)",
            Codec::Ascii85 => "ascii85 (lazy)",
            Codec::RunLength => "runlength (lazy)",
            Codec::PackBits => "packbits (lazy)",
            Codec::Lzw { .. } => "lzw (lazy)",
            Codec::PngPredictor { .. } => "png-predictor (lazy)",
            Codec::TiffPredictor { .. } => "tiff-predictor (lazy)",
            Codec::Eexec { .. } => "eexec (lazy)",
            Codec::Bzip2 => "bzip2 (lazy)",
            Codec::Zstd => "zstd (lazy)",
            Codec::UnixCompress => "unix-compress (lazy)",
            Codec::Lzfse => "lzfse (lazy)",
            Codec::Pbz => "pbz (lazy)",
            Codec::Xz => "xz (lazy)",
            Codec::LzmaAlone => "lzma (lazy)",
            Codec::Lzma2 => "lzma2 (lazy)",
            Codec::LzmaRaw { .. } => "lzma-raw (lazy)",
            Codec::Lz4Frame => "lz4 (lazy)",
            Codec::Lz4Block => "lz4-block (lazy)",
            Codec::Snappy => "snappy (lazy)",
            Codec::SnappyFramed => "snappy-framed (lazy)",
            Codec::Chain { lazy_name, .. } => lazy_name,
        }
    }

    /// How the result is described ("decompressed", "decoded", "decrypted").
    pub fn verb(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate | Codec::Zlib => "decompressed",
            Codec::ZipCrypto(_) | Codec::AesCtrLe(_) | Codec::Rc4(_) | Codec::AesCbc(_) | Codec::Eexec { .. } => {
                "decrypted"
            }
            Codec::Lzw { .. }
            | Codec::RunLength
            | Codec::PackBits
            | Codec::Lz4Frame
            | Codec::Lz4Block
            | Codec::Snappy
            | Codec::SnappyFramed
            | Codec::Bzip2
            | Codec::Xz
            | Codec::Zstd
            | Codec::UnixCompress
            | Codec::Lzfse
            | Codec::Pbz
            | Codec::LzmaAlone
            | Codec::Lzma2
            | Codec::LzmaRaw { .. } => "decompressed",
            Codec::AsciiHex | Codec::Ascii85 | Codec::PngPredictor { .. } | Codec::TiffPredictor { .. } => {
                "decoded"
            }
            Codec::Chain { .. } => "decoded",
        }
    }

    /// The largest plausible ratio of decoded to encoded size; larger claims
    /// from a container are treated as bogus.
    pub fn max_ratio(&self) -> u64 {
        match self {
            Codec::Stored
            | Codec::ZipCrypto(_)
            | Codec::AesCtrLe(_)
            | Codec::Rc4(_)
            | Codec::AesCbc(_)
            | Codec::Eexec { .. }
            | Codec::AsciiHex
            | Codec::Ascii85
            | Codec::PngPredictor { .. }
            | Codec::TiffPredictor { .. } => 1,
            Codec::RunLength | Codec::PackBits => 128,
            Codec::Lz4Frame | Codec::Lz4Block | Codec::Snappy | Codec::SnappyFramed => 256,
            // A block of up to 900 kB can encode runs of 255-byte repeats.
            Codec::Bzip2 => 50_000,
            // LZMA's longest match (273 bytes) costs a handful of bits.
            Codec::Xz | Codec::LzmaAlone | Codec::Lzma2 | Codec::LzmaRaw { .. } => 7_000,
            // RLE blocks can encode 128 KiB in four bytes.
            Codec::Zstd => 32_768,
            Codec::UnixCompress => 8_000,
            Codec::Lzfse => 4_096,
            Codec::Pbz => 7_000,
            Codec::Lzw { .. } => 4096,
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
            Codec::AsciiHex => Box::new(Streaming(filters::Whole::new(filters::AsciiHex))),
            Codec::Ascii85 => Box::new(Streaming(filters::Whole::new(filters::Ascii85))),
            Codec::RunLength => Box::new(Streaming(filters::Whole::new(filters::RunLength))),
            Codec::PackBits => Box::new(Streaming(filters::Whole::new(filters::PackBits))),
            Codec::Lzw { early_change } => Box::new(Streaming(filters::Whole::new(filters::Lzw { early_change: *early_change }))),
            Codec::PngPredictor { bpp, row } => {
                Box::new(Streaming(filters::Whole::new(filters::PngPredictor { bpp: *bpp, row: *row })))
            }
            Codec::TiffPredictor { bpp, row } => {
                Box::new(Streaming(filters::Whole::new(filters::TiffPredictor { bpp: *bpp, row: *row })))
            }
            Codec::Lzfse => Box::new(Streaming(filters::Whole::new(lzfse::Lzfse))),
            Codec::Pbz => Box::new(Streaming(filters::Whole::new(pbz::Pbz))),
            Codec::UnixCompress => Box::new(Streaming(filters::Whole::new(unixz::UnixCompress))),
            Codec::Zstd => Box::new(Streaming(filters::Whole::new(zstd::Zstd))),
            Codec::Xz => Box::new(Streaming(filters::Whole::new(xz::Xz))),
            Codec::LzmaAlone => Box::new(Streaming(filters::Whole::new(lzma::LzmaAlone))),
            Codec::Lzma2 => Box::new(Streaming(filters::Whole::new(lzma::Lzma2))),
            Codec::LzmaRaw { props, size } => Box::new(Streaming(filters::Whole::new(lzma::LzmaRaw { props: *props, end: *size }))),
            Codec::Bzip2 => Box::new(Streaming(filters::Whole::new(bzip2::Bzip2))),
            Codec::Lz4Frame => Box::new(Streaming(filters::Whole::new(lz::Lz4Frame))),
            Codec::Lz4Block => Box::new(Streaming(filters::Whole::new(lz::Lz4Block))),
            Codec::Snappy => Box::new(Streaming(filters::Whole::new(lz::Snappy))),
            Codec::SnappyFramed => Box::new(Streaming(filters::Whole::new(lz::SnappyFramed))),
            Codec::Eexec { hex } => Box::new(Streaming(filters::Whole::new(filters::Eexec { hex: *hex }))),
            Codec::Rc4(key) => Box::new(Streaming(crypto::stream::Rc4::new(key))),
            Codec::AesCbc(key) => Box::new(Streaming(filters::Whole::new(crypto::stream::AesCbcIvPrefixed(key.clone())))),
            Codec::ZipCrypto(key) => Box::new(Streaming(crypto::stream::ZipCrypto::new(key))),
            Codec::AesCtrLe(key) => match crypto::stream::AesCtrLe::new(key) {
                Some(d) => Box::new(Streaming(d)),
                None => Box::new(Streaming(pipeline::Failing("invalid AES key length"))),
            },
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
