//! Codecs: decoders (decompressors, filters, ciphers) that turn a span into
//! a derived source.
//!
//! Decoders are written in-house (see the codec policy in `DESIGN.md`)
//! against [`pipeline::Decode`], and chained with [`Codec::Chain`]. A
//! [`Codec`] decodes eagerly ([`decode_span`]) or lazily, as far as reads
//! reach ([`Cx::decode_lazy`](crate::Cx::decode_lazy)); either way decoded
//! bytes count against [`crate::Limits::max_derived`].

pub mod inflate;
pub mod brotli;
pub mod bzip2;
pub mod charset;
pub mod crc;
pub mod crypto;
pub mod filters;
pub mod lz;
pub mod lzfse;
pub mod pbz;
pub mod wim;
pub mod lznt1;
pub mod lzma;
pub mod xz;
pub mod zstd;
pub mod pipeline;
pub mod unixz;
pub mod xpress;
pub mod lzo;
pub mod legacy;
pub mod implode;
pub mod cab;
pub mod lzx;
pub mod quantum;

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
    /// Brotli streams (RFC 7932).
    Brotli,
    /// Apple LZFSE (with LZVN blocks).
    Lzfse,
    /// Apple's chunked wrapper (`pbzx`/`pbze`/`pbz4`/`pbzz`).
    Pbz,
    /// A compressed WIM resource (chunk table, XPRESS or LZX chunks).
    WimResource(wim::Resource),
    /// Unix `compress` (`.Z`, LSB-first LZW with a header).
    UnixCompress,
    /// LZNT1 ([MS-XCA] 2.5); with a `size` (an NTFS compression unit) the
    /// output is cut or zero-filled to it.
    Lznt1 { size: Option<u64> },
    /// Xpress Plain LZ77 ([MS-XCA] 2.4), up to `size` bytes if known.
    Xpress { size: Option<u64> },
    /// Xpress LZ77+Huffman ([MS-XCA] 2.2), `size` bytes (the stream does not
    /// record it).
    XpressHuffman { size: u64 },
    /// A raw LZX stream (CHM content, WIM chunks); see [`lzx::Params`] for
    /// the window size, reset interval and E8 translation variant.
    Lzx(lzx::Params),
    /// A cabinet folder's data blocks (headers included) through the
    /// folder's codec: stored, MSZIP, Quantum or LZX (see [`cab`]).
    CabFolder(cab::Folder),
    /// Zstandard frames.
    Zstd,
    /// One raw LZO1X stream (with its end marker).
    Lzo1x,
    /// The lzop (`.lzo`) container.
    Lzop,
    /// Raw LZF (liblzf).
    Lzf,
    /// LZF in the `lzf` tool's `ZV` blocks.
    LzfFramed,
    /// Apple Data Compression (DMG chunk type `0x80000004`).
    Adc,
    /// PKWARE implode (ZIP method 6).
    Implode(implode::Implode),
    /// PKWARE Data Compression Library implode (ZIP method 10, "blast").
    DclImplode,
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
            Codec::Lznt1 { .. } => "lznt1",
            Codec::Xpress { .. } => "xpress",
            Codec::XpressHuffman { .. } => "xpress-huffman",
            Codec::Lzo1x => "lzo1x",
            Codec::Lzop => "lzop",
            Codec::Lzf => "lzf",
            Codec::LzfFramed => "lzf-framed",
            Codec::Adc => "adc",
            Codec::Implode(_) => "implode",
            Codec::DclImplode => "dcl-implode",
            Codec::Lzx(_) => "lzx",
            Codec::CabFolder(_) => "cab-folder",
            Codec::Lzfse => "lzfse",
            Codec::Pbz => "pbz",
            Codec::WimResource(_) => "wim-resource",
            Codec::Brotli => "brotli",
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
            Codec::Lznt1 { .. } => "lznt1 (lazy)",
            Codec::Xpress { .. } => "xpress (lazy)",
            Codec::XpressHuffman { .. } => "xpress-huffman (lazy)",
            Codec::Lzo1x => "lzo1x (lazy)",
            Codec::Lzop => "lzop (lazy)",
            Codec::Lzf => "lzf (lazy)",
            Codec::LzfFramed => "lzf-framed (lazy)",
            Codec::Adc => "adc (lazy)",
            Codec::Implode(_) => "implode (lazy)",
            Codec::DclImplode => "dcl-implode (lazy)",
            Codec::Lzx(_) => "lzx (lazy)",
            Codec::CabFolder(_) => "cab-folder (lazy)",
            Codec::Lzfse => "lzfse (lazy)",
            Codec::Pbz => "pbz (lazy)",
            Codec::WimResource(_) => "wim-resource (lazy)",
            Codec::Brotli => "brotli (lazy)",
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
            | Codec::Lznt1 { .. }
            | Codec::Xpress { .. }
            | Codec::XpressHuffman { .. }
            | Codec::Lzo1x
            | Codec::Lzop
            | Codec::Lzf
            | Codec::LzfFramed
            | Codec::Adc
            | Codec::Implode(_)
            | Codec::DclImplode
            | Codec::Lzx(_)
            | Codec::CabFolder(_)
            | Codec::Lzfse
            | Codec::Pbz
            | Codec::WimResource(_)
            | Codec::Brotli
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
            // A 3-byte chunk stands for 4 KiB of zeros when another follows.
            Codec::Lznt1 { .. } => 1_400,
            // Each 64 KiB block costs at least its 256-byte table.
            Codec::XpressHuffman { .. } => 512,
            Codec::Xpress { .. } => 32_768,
            // Each zero length byte adds 255 bytes.
            Codec::Lzo1x | Codec::Lzop => 512,
            // At most 264 bytes per 3-byte back reference.
            Codec::Lzf | Codec::LzfFramed => 128,
            // At most 67 bytes per 3-byte match.
            Codec::Adc => 32,
            // Matches of up to 320 or 518 bytes in about 17 or 24 bits.
            Codec::Implode(_) | Codec::DclImplode => 256,
            // A 32 KiB frame (block) takes a few bytes at least.
            Codec::Lzx(_) => 32_768,
            Codec::CabFolder(f) if f.method() == 0 => 1,
            Codec::CabFolder(_) => 32_768,
            Codec::Lzfse => 4_096,
            Codec::Pbz => 7_000,
            Codec::WimResource(_) => 32_768,
            // A copy of 16 MiB costs a few bits.
            Codec::Brotli => 1 << 20,
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
            Codec::WimResource(r) => Box::new(Streaming(filters::Whole::new(*r))),
            Codec::Brotli => Box::new(Streaming(brotli::Stream::default())),
            Codec::UnixCompress => Box::new(Streaming(filters::Whole::new(unixz::UnixCompress))),
            Codec::Lznt1 { size } => Box::new(Streaming(filters::Whole::new(lznt1::Lznt1 { size: *size }))),
            Codec::Xpress { size } => Box::new(Streaming(filters::Whole::new(xpress::Xpress { size: *size }))),
            Codec::XpressHuffman { size } => {
                Box::new(Streaming(filters::Whole::new(xpress::XpressHuffman { size: *size })))
            }
            Codec::Lzo1x => Box::new(Streaming(filters::Whole::new(lzo::Lzo1x))),
            Codec::Lzop => Box::new(Streaming(filters::Whole::new(lzo::Lzop))),
            Codec::Lzf => Box::new(Streaming(filters::Whole::new(legacy::Lzf))),
            Codec::LzfFramed => Box::new(Streaming(filters::Whole::new(legacy::LzfFramed))),
            Codec::Adc => Box::new(Streaming(filters::Whole::new(legacy::Adc))),
            Codec::Implode(params) => Box::new(Streaming(filters::Whole::new(*params))),
            Codec::DclImplode => Box::new(Streaming(filters::Whole::new(implode::DclImplode))),
            Codec::Lzx(params) => Box::new(lzx::LzxStream::new(*params)),
            Codec::CabFolder(folder) => Box::new(cab::FolderDecoder::new(*folder)),
            Codec::Zstd => Box::new(Streaming(filters::Whole::new(zstd::Zstd))),
            Codec::Xz => Box::new(xz::XzStream::default()),
            Codec::LzmaAlone => Box::new(lzma::LzmaStream::alone()),
            Codec::Lzma2 => Box::new(lzma::Lzma2Stream::default()),
            Codec::LzmaRaw { props, size } => Box::new(lzma::LzmaStream::raw(*props, *size)),
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
    crc::crc32(data)
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
