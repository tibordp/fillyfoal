//! Codecs: decoders (decompressors, filters, ciphers) that turn a span into
//! a derived source.
//!
//! Decoders are written in-house (see the codec policy in `DESIGN.md`)
//! against [`pipeline::Decode`], and chained with [`Codec::Chain`]. A
//! [`Codec`] decodes eagerly ([`decode_span`]) or lazily, as far as reads
//! reach ([`Cx::decode_lazy`](crate::Cx::decode_lazy)); either way decoded
//! bytes count against [`crate::Limits::max_derived`].

pub mod ace;
pub mod bcfz;
pub mod brotli;
pub mod bzip2;
pub mod cab;
pub mod capnp;
pub mod charset;
pub mod crc;
pub mod crypto;
pub mod filters;
pub mod heatshrink;
pub mod implode;
pub mod inflate;
pub mod legacy;
pub mod lz;
pub mod lzfse;
pub mod lzma;
pub mod lznt1;
pub mod lzo;
pub mod lzx;
pub mod meatpack;
pub mod pbz;
pub mod pipeline;
pub mod quantum;
pub mod stuffit;
pub mod unixz;
pub mod wim;
pub mod xpress;
pub mod xz;
pub mod zstd;

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
    Lzw {
        early_change: bool,
    },
    /// PNG row predictors; `bpp` bytes per pixel, `row` bytes per row.
    PngPredictor {
        bpp: usize,
        row: usize,
    },
    /// TIFF horizontal differencing (8-bit components).
    TiffPredictor {
        bpp: usize,
        row: usize,
    },
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
    Lznt1 {
        size: Option<u64>,
    },
    /// Xpress Plain LZ77 ([MS-XCA] 2.4), up to `size` bytes if known.
    Xpress {
        size: Option<u64>,
    },
    /// Xpress LZ77+Huffman ([MS-XCA] 2.2), `size` bytes (the stream does not
    /// record it).
    XpressHuffman {
        size: u64,
    },
    /// A raw LZX stream (CHM content, WIM chunks); see [`lzx::Params`] for
    /// the window size, reset interval and E8 translation variant.
    Lzx(lzx::Params),
    /// A cabinet folder's data blocks (headers included) through the
    /// folder's codec: stored, MSZIP, Quantum or LZX (see [`cab`]).
    CabFolder(cab::Folder),
    /// Zstandard frames.
    Zstd,
    /// The bit-level LZ77 of Guitar Pro 6 `BCFZ` files (after their 8-byte
    /// header), decoding to `size` bytes (see [`bcfz`]).
    Bcfz {
        size: u64,
    },
    /// Heatshrink LZSS with `window` and `lookahead` bits (Prusa binary
    /// G-code).
    Heatshrink {
        window: u8,
        lookahead: u8,
    },
    /// MeatPack-packed G-code text (Prusa binary G-code).
    MeatPack,
    /// Exactly one Zstandard frame (after any skippable frames); what
    /// follows it is left unconsumed.
    ZstdFrame,
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
    /// Raw LZMA2 chunks; `dict` is the dictionary size if known (it lets a
    /// long stream release output before its dictionary).
    Lzma2 {
        dict: Option<u32>,
    },
    /// Raw LZMA with known properties and (if known) decoded and
    /// dictionary sizes.
    LzmaRaw {
        props: lzma::Props,
        size: Option<usize>,
        dict: Option<u32>,
    },
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
    /// Cap'n Proto's packed encoding (see [`capnp`]).
    CapnpPacked,
    /// Adobe Type 1 `eexec` decryption (binary, or hex text).
    Eexec {
        hex: bool,
    },
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
    /// ACE LZ77/blocked data (see [`ace`]); solid archives list the files
    /// before the wanted one.
    Ace(ace::Params),
    /// A StuffIt fork (see [`stuffit`]).
    StuffIt(stuffit::Params),
    /// Stages applied in order. `name` and `lazy_name` identify the chain
    /// for memoization (see [`Origin`]); they must be distinct.
    Chain {
        name: &'static str,
        lazy_name: &'static str,
        stages: Arc<[Codec]>,
    },
}

impl Codec {
    pub fn chain(
        name: &'static str,
        lazy_name: &'static str,
        stages: impl Into<Arc<[Codec]>>,
    ) -> Self {
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
            Codec::ZstdFrame => "zstd-frame",
            Codec::UnixCompress => "unix-compress",
            Codec::Lznt1 { .. } => "lznt1",
            Codec::Xpress { .. } => "xpress",
            Codec::XpressHuffman { .. } => "xpress-huffman",
            Codec::Lzo1x => "lzo1x",
            Codec::Bcfz { .. } => "bcfz",
            Codec::Heatshrink { .. } => "heatshrink",
            Codec::MeatPack => "meatpack",
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
            Codec::Lzma2 { .. } => "lzma2",
            Codec::LzmaRaw { .. } => "lzma-raw",
            Codec::Lz4Frame => "lz4",
            Codec::Lz4Block => "lz4-block",
            Codec::Snappy => "snappy",
            Codec::SnappyFramed => "snappy-framed",
            Codec::CapnpPacked => "capnp-packed",
            Codec::Ace(_) => "ace",
            Codec::StuffIt(_) => "stuffit",
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
            Codec::ZstdFrame => "zstd-frame (lazy)",
            Codec::UnixCompress => "unix-compress (lazy)",
            Codec::Lznt1 { .. } => "lznt1 (lazy)",
            Codec::Xpress { .. } => "xpress (lazy)",
            Codec::XpressHuffman { .. } => "xpress-huffman (lazy)",
            Codec::Lzo1x => "lzo1x (lazy)",
            Codec::Bcfz { .. } => "bcfz (lazy)",
            Codec::Heatshrink { .. } => "heatshrink (lazy)",
            Codec::MeatPack => "meatpack (lazy)",
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
            Codec::Lzma2 { .. } => "lzma2 (lazy)",
            Codec::LzmaRaw { .. } => "lzma-raw (lazy)",
            Codec::Lz4Frame => "lz4 (lazy)",
            Codec::Lz4Block => "lz4-block (lazy)",
            Codec::Snappy => "snappy (lazy)",
            Codec::SnappyFramed => "snappy-framed (lazy)",
            Codec::CapnpPacked => "capnp-packed (lazy)",
            Codec::Ace(_) => "ace (lazy)",
            Codec::StuffIt(_) => "stuffit (lazy)",
            Codec::Chain { lazy_name, .. } => lazy_name,
        }
    }

    /// How the result is described ("decompressed", "decoded", "decrypted").
    pub fn verb(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate | Codec::Zlib => "decompressed",
            Codec::ZipCrypto(_)
            | Codec::AesCtrLe(_)
            | Codec::Rc4(_)
            | Codec::AesCbc(_)
            | Codec::Eexec { .. } => "decrypted",
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
            | Codec::ZstdFrame
            | Codec::UnixCompress
            | Codec::Lznt1 { .. }
            | Codec::Xpress { .. }
            | Codec::XpressHuffman { .. }
            | Codec::Lzo1x
            | Codec::Bcfz { .. }
            | Codec::Heatshrink { .. }
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
            | Codec::Lzma2 { .. }
            | Codec::LzmaRaw { .. }
            | Codec::Ace(_)
            | Codec::StuffIt(_) => "decompressed",
            Codec::AsciiHex
            | Codec::Ascii85
            | Codec::PngPredictor { .. }
            | Codec::TiffPredictor { .. }
            | Codec::MeatPack => "decoded",
            Codec::CapnpPacked => "unpacked",
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
            // A zero tag and a count stand for 256 zero words.
            Codec::CapnpPacked => 1024,
            // A block of up to 900 kB can encode runs of 255-byte repeats.
            Codec::Bzip2 => 50_000,
            // LZMA's longest match (273 bytes) costs a handful of bits.
            Codec::Xz | Codec::LzmaAlone | Codec::Lzma2 { .. } | Codec::LzmaRaw { .. } => 7_000,
            // RLE blocks can encode 128 KiB in four bytes.
            Codec::Zstd | Codec::ZstdFrame => 32_768,
            Codec::UnixCompress => 8_000,
            // A 32 KiB copy costs 35 bits.
            Codec::Bcfz { .. } => 8_000,
            // At most 2^lookahead bytes per back-reference of 1 + window +
            // lookahead bits.
            Codec::Heatshrink { .. } => 16,
            // Two characters per byte, each possibly with a space.
            Codec::MeatPack => 4,
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
            // A 259-byte match costs a handful of bits; a solid member's
            // output is unrelated to the bytes before it, so no bound.
            Codec::Ace(p) if p.members.len() > 1 => u64::MAX,
            Codec::Ace(_) => 1024,
            // Arsenic and RLE90 runs: a few bits for up to 255 bytes, in
            // blocks of up to 16 MiB.
            Codec::StuffIt(_) => 32_768,
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
            Codec::Lzw { early_change } => Box::new(Streaming(filters::Whole::new(filters::Lzw {
                early_change: *early_change,
            }))),
            Codec::PngPredictor { bpp, row } => {
                Box::new(Streaming(filters::Whole::new(filters::PngPredictor {
                    bpp: *bpp,
                    row: *row,
                })))
            }
            Codec::TiffPredictor { bpp, row } => {
                Box::new(Streaming(filters::Whole::new(filters::TiffPredictor {
                    bpp: *bpp,
                    row: *row,
                })))
            }
            Codec::Lzfse => Box::new(Streaming(lzfse::Lzfse::default())),
            Codec::Pbz => Box::new(Streaming(pbz::Pbz::default())),
            Codec::WimResource(r) => Box::new(Streaming(wim::Decoder::new(*r))),
            Codec::Brotli => Box::new(Streaming(brotli::Stream::default())),
            Codec::UnixCompress => Box::new(unixz::UnixCompress::default()),
            Codec::Lznt1 { size } => {
                Box::new(Streaming(filters::Whole::new(lznt1::Lznt1 { size: *size })))
            }
            Codec::Xpress { size } => Box::new(Streaming(filters::Whole::new(xpress::Xpress {
                size: *size,
            }))),
            Codec::XpressHuffman { size } => {
                Box::new(Streaming(filters::Whole::new(xpress::XpressHuffman {
                    size: *size,
                })))
            }
            Codec::Lzo1x => Box::new(Streaming(filters::Whole::new(lzo::Lzo1x))),
            Codec::Bcfz { size } => Box::new(Streaming(bcfz::Bcfz::new(*size))),
            Codec::Heatshrink { window, lookahead } => {
                Box::new(Streaming(heatshrink::Heatshrink::new(*window, *lookahead)))
            }
            Codec::MeatPack => Box::new(Streaming(meatpack::MeatPack::default())),
            Codec::Lzop => Box::new(Streaming(lzo::Lzop::default())),
            Codec::Lzf => Box::new(Streaming(filters::Whole::new(legacy::Lzf))),
            Codec::LzfFramed => Box::new(Streaming(filters::Whole::new(legacy::LzfFramed))),
            Codec::Adc => Box::new(Streaming(filters::Whole::new(legacy::Adc))),
            Codec::Implode(params) => Box::new(Streaming(filters::Whole::new(*params))),
            Codec::DclImplode => Box::new(Streaming(filters::Whole::new(implode::DclImplode))),
            Codec::Lzx(params) => Box::new(lzx::LzxStream::new(*params)),
            Codec::CabFolder(folder) => Box::new(cab::FolderDecoder::new(*folder)),
            Codec::Zstd => Box::new(Streaming(zstd::Zstd::new())),
            Codec::ZstdFrame => Box::new(Streaming(zstd::Zstd::single_frame())),
            Codec::Bzip2 => Box::new(Streaming(bzip2::Bzip2::default())),
            Codec::Lz4Frame => Box::new(Streaming(lz::Lz4Frame::default())),
            Codec::Xz => Box::new(xz::XzStream::default()),
            Codec::LzmaAlone => Box::new(lzma::LzmaStream::alone()),
            Codec::Lzma2 { dict } => Box::new(lzma::Lzma2Stream::new(*dict)),
            Codec::LzmaRaw { props, size, dict } => {
                Box::new(lzma::LzmaStream::raw(*props, *size, *dict))
            }
            Codec::Lz4Block => Box::new(Streaming(filters::Whole::new(lz::Lz4Block))),
            Codec::Snappy => Box::new(Streaming(filters::Whole::new(lz::Snappy))),
            Codec::SnappyFramed => Box::new(Streaming(lz::SnappyFramed::default())),
            Codec::CapnpPacked => Box::new(Streaming(capnp::Packed::default())),
            Codec::Ace(params) => Box::new(Streaming(ace::Decoder::new(params.clone()))),
            Codec::StuffIt(params) => Box::new(Streaming(stuffit::Decoder::new(*params))),
            Codec::Eexec { hex } => {
                Box::new(Streaming(filters::Whole::new(filters::Eexec { hex: *hex })))
            }
            Codec::Rc4(key) => Box::new(Streaming(crypto::stream::Rc4::new(key))),
            Codec::AesCbc(key) => Box::new(Streaming(filters::Whole::new(
                crypto::stream::AesCbcIvPrefixed(key.clone()),
            ))),
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
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        inflate::Inflate::step(self, input, out, step, limit)
    }

    fn consumed(&self) -> usize {
        inflate::Inflate::consumed(self)
    }

    fn releasable_input(&self) -> usize {
        inflate::Inflate::releasable_input(self)
    }

    fn release_input(&mut self, n: usize) {
        inflate::Inflate::release_input(self, n);
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        // Back-references reach at most 32 KiB.
        out_len.saturating_sub(inflate::WINDOW)
    }
}

/// zlib: a 2-byte header, DEFLATE, and a big-endian Adler-32 trailer.
#[derive(Clone)]
struct Zlib {
    inflate: inflate::Inflate,
    /// Header bytes still at the front of the input (2, until released).
    header: usize,
    checked: bool,
    /// Adler-32 of the output so far.
    adler: Adler32,
    trailer: Option<u32>,
}

impl Default for Zlib {
    fn default() -> Self {
        Zlib {
            inflate: inflate::Inflate::new(),
            header: 2,
            checked: false,
            adler: Adler32::new(),
            trailer: None,
        }
    }
}

impl Decode for Zlib {
    fn step(
        &mut self,
        input: &[u8],
        _eof: bool,
        out: &mut Vec<u8>,
        step: usize,
        limit: usize,
    ) -> Result<Step> {
        if !self.checked {
            let (Some(&cmf), Some(&flg)) = (input.first(), input.get(1)) else {
                return Err(Diagnostic::malformed("truncated zlib header"));
            };
            if cmf & 0x0f != 8 || (u16::from(cmf) << 8 | u16::from(flg)) % 31 != 0 {
                return Err(Diagnostic::malformed("not a zlib stream"));
            }
            if flg & 0x20 != 0 {
                return Err(Diagnostic::unsupported("zlib preset dictionary"));
            }
            self.checked = true;
        }
        let body = input.get(self.header..).unwrap_or_default();
        let mark = out.len();
        let result = self.inflate.step(body, out, step, limit)?;
        self.adler.update(out.get(mark..).unwrap_or_default());
        if result == Step::Done {
            let at = self.header.saturating_add(self.inflate.consumed());
            self.trailer = Some(
                crate::bytes::u32_be(input, at)
                    .ok_or_else(|| Diagnostic::malformed("truncated zlib checksum"))?,
            );
        }
        Ok(result)
    }

    fn consumed(&self) -> usize {
        let base = self.header.saturating_add(self.inflate.consumed());
        if self.trailer.is_some() {
            base.saturating_add(4)
        } else {
            base
        }
    }

    fn warning(&self, _out: &[u8]) -> Option<Diagnostic> {
        self.trailer
            .filter(|&t| t != self.adler.value())
            .map(|_| Diagnostic::warning("zlib Adler-32 checksum mismatch"))
    }

    fn releasable_input(&self) -> usize {
        match self.inflate.releasable_input() {
            0 => 0,
            n => self.header.saturating_add(n),
        }
    }

    fn release_input(&mut self, n: usize) {
        if n >= self.header {
            self.inflate.release_input(n.saturating_sub(self.header));
            self.header = 0;
        }
    }

    fn releasable_output(&self, out_len: usize) -> usize {
        out_len.saturating_sub(inflate::WINDOW)
    }
}

/// Decodes `span` with `codec` into a derived source (memoized). `expected`
/// is the decoded size, if the container records it.
pub async fn decode_span(
    cx: &Cx,
    span: Span,
    codec: &Codec,
    expected: Option<u64>,
) -> Result<Decoded> {
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
                error = Some(
                    Diagnostic::malformed(format!("{} stream ended early", codec.name())).at(span),
                );
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
    cx.add_decoded(origin, out, consumed, error, codec)
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
pub async fn inflate_span(
    cx: &Cx,
    span: Span,
    zlib: bool,
    expected: Option<u64>,
) -> Result<Decoded> {
    let codec = if zlib { Codec::Zlib } else { Codec::Deflate };
    decode_span(cx, span, &codec, expected).await
}

pub fn adler32(data: &[u8]) -> u32 {
    let mut a = Adler32::new();
    a.update(data);
    a.value()
}

/// A running Adler-32.
#[derive(Clone, Copy, Debug)]
pub struct Adler32 {
    a: u32,
    b: u32,
}

impl Default for Adler32 {
    fn default() -> Self {
        Self::new()
    }
}

impl Adler32 {
    pub fn new() -> Self {
        Adler32 { a: 1, b: 0 }
    }

    pub fn update(&mut self, data: &[u8]) {
        for chunk in data.chunks(5552) {
            for &byte in chunk {
                self.a = self.a.wrapping_add(u32::from(byte));
                self.b = self.b.wrapping_add(self.a);
            }
            self.a %= 65521;
            self.b %= 65521;
        }
    }

    pub fn value(&self) -> u32 {
        self.b << 16 | self.a
    }
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
