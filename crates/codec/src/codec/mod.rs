//! Codecs: decoders (decompressors, filters, ciphers) that turn a span into
//! a derived source.
//!
//! Decoders are written in-house (see the codec policy in `DESIGN.md`)
//! against [`pipeline::Decode`], and chained with [`Codec::Chain`]. A
//! [`Codec`] decodes eagerly (`decode_span`) or lazily, as far as reads
//! reach (`Cx::decode_lazy`); either way decoded
//! bytes count against `crate::Limits::max_derived`.

pub mod ace;
pub mod bcfz;
pub mod bcj2;
pub mod binhex;
pub mod brotli;
pub mod bzip2;
pub mod bzz;
pub mod cab;
pub mod capnp;
pub mod charset;
pub mod crc;
pub mod crypto;
pub mod dwg;
pub mod filters;
pub mod gzip;
pub mod heatshrink;
pub mod implode;
pub mod inflate;
pub mod legacy;
pub mod lz;
pub mod lzfse;
pub mod lzfu;
pub mod lzh;
pub mod lzma;
pub mod lzms;
pub mod lznt1;
pub mod lzo;
pub mod lzx;
pub mod meatpack;
pub mod palmdoc;
pub mod pbz;
pub mod pipeline;
pub mod psarc;
pub mod quantum;
pub mod rar;
pub mod statdata;
pub mod stuffit;
pub mod unixz;
pub mod wim;
pub mod xpress;
pub mod xz;
pub mod yaz0;
pub mod zstd;

use std::sync::Arc;

use pipeline::{Decode, Decoder, Step, Streaming};

use crate::error::{Diagnostic, Result};
use crate::span::{SourceId, Span};

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

/// How content is encoded: a decompressor, a filter, or a chain of them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Codec {
    Stored,
    /// Raw DEFLATE (RFC 1951).
    Deflate,
    /// Raw Deflate64 (ZIP method 9; see [`inflate`]).
    Deflate64,
    /// zlib-wrapped DEFLATE (RFC 1950), with its Adler-32 checked.
    Zlib,
    /// gzip members (RFC 1952) from the first member's DEFLATE data on (its
    /// header already read), then any further members; each member's CRC-32
    /// and size are checked (see [`gzip`]).
    Gzip,
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
    /// A bare LZVN stream ending in its end-of-stream opcode (decmpfs).
    Lzvn,
    /// Apple's chunked wrapper (`pbzx`/`pbze`/`pbz4`/`pbzz`).
    Pbz,
    /// A compressed WIM resource (chunk table, then XPRESS, LZX or LZMS
    /// chunks; solid or not; see [`wim`]).
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
    /// The text records of a PalmDOC or Mobipocket book (see [`palmdoc`]).
    PalmDoc(palmdoc::Book),
    /// Zstandard frames that may use this dictionary (see
    /// [`zstd::Dictionary`]).
    ZstdDict(zstd::Dict),
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
    /// DjVu's BZZ (Burrows-Wheeler and ZP coder; see [`bzz`]).
    Bzz,
    /// Exactly one Zstandard frame (after any skippable frames); what
    /// follows it is left unconsumed.
    ZstdFrame,
    /// One raw LZO1X stream (with its end marker).
    Lzo1x,
    /// The lzop (`.lzo`) container.
    Lzop,
    /// btrfs's LZO extents: a total length, then LZO1X segments of up to
    /// one sector each (see [`lzo::BtrfsLzo`]).
    BtrfsLzo,
    /// Raw LZF (liblzf).
    Lzf,
    /// LZF in the `lzf` tool's `ZV` blocks.
    LzfFramed,
    /// Compressed RTF (`LZFu`/`MELA`, [MS-OXRTFCP]), header included.
    Lzfu,
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
    /// NSIS's headerless, CRC-less bzip2 variant (see [`bzip2::Bzip2::nsis`]).
    NsisBzip2,
    /// LZ4 frames (also legacy and skippable frames).
    Lz4Frame,
    /// One raw LZ4 block.
    Lz4Block,
    /// The HDF5 LZ4 filter's blocks (see [`lz::Hdf5Lz4`]).
    Hdf5Lz4,
    /// Raw Snappy.
    Snappy,
    /// The Snappy framing format.
    SnappyFramed,
    /// Cap'n Proto's packed encoding (see [`capnp`]).
    CapnpPacked,
    /// SPSS bytecode compression with this bias (an `f64`'s bits) and byte
    /// order (see [`statdata`]).
    SpssBytecode {
        bias: u64,
        big_endian: bool,
    },
    /// SAS7BDAT `SASYZCRL` row compression (run-length).
    SasRle,
    /// SAS7BDAT `SASYZCR2` row compression (Ross Data Compression).
    SasRdc,
    /// One page of an AutoCAD R2004+ DWG file, decompressing to at most
    /// `size` bytes (see [`dwg`]).
    DwgLz77 {
        size: u64,
    },
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
    /// An Excel BIFF8 workbook stream encrypted with RC4 or RC4 CryptoAPI
    /// (see [`crypto::office`]): records after FILEPASS are decrypted.
    XlsRc4(crypto::office::Rc4Key),
    /// An Excel BIFF5 or BIFF8 workbook stream with XOR obfuscation, with
    /// this 16-byte XOR array (see [`crypto::office::xor_array`]).
    XlsXor(crypto::Key),
    /// AES-CBC with this key; the IV is the first 16 bytes and the data is
    /// PKCS#7-padded (PDF AESV2/AESV3).
    AesCbc(crypto::Key),
    /// ACE LZ77/blocked data (see [`ace`]); solid archives list the files
    /// before the wanted one.
    Ace(ace::Params),
    /// A StuffIt fork (see [`stuffit`]).
    StuffIt(stuffit::Params),
    /// The LZSS/LZH family of LHA, ARJ, ZOO and `COMPRESS.EXE` (see
    /// [`lzh`]).
    Lzh(lzh::Params),
    /// A PSARC entry's zlib or LZMA blocks (see [`psarc`]).
    Psarc(psarc::Entry),
    /// 7z PPMd (variant H with 7-Zip's range coder): model `order`, `mem`
    /// bytes of model memory, `size` bytes of output (see [`rar::Ppmd7`]).
    Ppmd7 {
        order: u8,
        mem: u32,
        size: u64,
    },
    /// A RAR 2.9/5.0 group of files (one, or a solid run) decoded as one
    /// stream (see [`rar`]).
    Rar(rar::Params),
    /// A 7z BCJ2 folder: four packed streams, each through its own codec,
    /// combined by 7-Zip's BCJ2 x86 converter (see [`bcj2`]).
    Bcj2(Arc<bcj2::Params>),
    /// A BCJ (x86, ARM, ARM64, PowerPC, IA-64, ARM Thumb, SPARC, RISC-V) or Delta filter, decoding direction, on its
    /// own (7-Zip folders chain it after their decompressor).
    PostFilter(lzma::Post),
    /// A [`Codec::PostFilter`] branch converter whose stream starts at
    /// address `start` (7-Zip's ARM64 and RISC-V coder property).
    PostFilterAt {
        post: lzma::Post,
        start: u32,
    },
    /// Nintendo Yaz0 LZ77 (the body after the 16-byte header), decoding to
    /// `size` bytes.
    Yaz0 {
        size: u64,
    },
    /// BinHex 4.0's 6-bit text and 0x90 run-length encoding (the text
    /// between the colons).
    BinHex,
    /// Base64, standard or URL-safe, whitespace ignored, up to the padding
    /// (see [`filters::Base64`]).
    Base64,
    /// Quoted-printable (RFC 2045).
    QuotedPrintable,
    /// The lines of a uuencoded file's body (see [`filters::UuLines`]).
    Uu,
    /// The lines of an xxencoded file's body.
    Xx,
    /// yEnc-encoded lines (the body between `=ybegin`/`=ypart` and `=yend`).
    YEnc,
    /// Byte planes of `width`-byte elements interleaved back into elements
    /// (HDF5 shuffle, Parquet `BYTE_STREAM_SPLIT`; see
    /// [`filters::Unshuffle`]).
    Unshuffle {
        width: usize,
    },
    /// XOR with a repeating key.
    Xor {
        key: Vec<u8>,
    },
    /// The bytes of each `width`-byte group reversed (N64 `.v64`: 2, `.n64`:
    /// 4).
    ByteSwap {
        width: usize,
    },
    /// Stages applied in order. `name` and `lazy_name` identify the chain
    /// for memoization (see `Origin`); they must be distinct.
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
            Codec::Deflate64 => "deflate64",
            Codec::Zlib => "zlib",
            Codec::Gzip => "gzip",
            Codec::ZipCrypto(_) => "zipcrypto",
            Codec::AesCtrLe(_) => "aes-ctr",
            Codec::Rc4(_) => "rc4",
            Codec::XlsRc4(_) => "xls-rc4",
            Codec::XlsXor(_) => "xls-xor",
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
            Codec::NsisBzip2 => "nsis-bzip2",
            Codec::Zstd => "zstd",
            Codec::ZstdFrame => "zstd-frame",
            Codec::ZstdDict(_) => "zstd-dict",
            Codec::PalmDoc(_) => "palmdoc",
            Codec::BtrfsLzo => "btrfs-lzo",
            Codec::UnixCompress => "unix-compress",
            Codec::Lznt1 { .. } => "lznt1",
            Codec::Xpress { .. } => "xpress",
            Codec::XpressHuffman { .. } => "xpress-huffman",
            Codec::Lzo1x => "lzo1x",
            Codec::Bcfz { .. } => "bcfz",
            Codec::Heatshrink { .. } => "heatshrink",
            Codec::MeatPack => "meatpack",
            Codec::Bzz => "bzz",
            Codec::Lzop => "lzop",
            Codec::Lzf => "lzf",
            Codec::LzfFramed => "lzf-framed",
            Codec::Lzfu => "lzfu",
            Codec::Adc => "adc",
            Codec::Implode(_) => "implode",
            Codec::DclImplode => "dcl-implode",
            Codec::Lzx(_) => "lzx",
            Codec::CabFolder(_) => "cab-folder",
            Codec::Lzfse => "lzfse",
            Codec::Lzvn => "lzvn",
            Codec::Pbz => "pbz",
            Codec::WimResource(_) => "wim-resource",
            Codec::Brotli => "brotli",
            Codec::Xz => "xz",
            Codec::LzmaAlone => "lzma",
            Codec::Lzma2 { .. } => "lzma2",
            Codec::LzmaRaw { .. } => "lzma-raw",
            Codec::Lz4Frame => "lz4",
            Codec::Lz4Block => "lz4-block",
            Codec::Hdf5Lz4 => "hdf5-lz4",
            Codec::Snappy => "snappy",
            Codec::SnappyFramed => "snappy-framed",
            Codec::CapnpPacked => "capnp-packed",
            Codec::Ace(_) => "ace",
            Codec::StuffIt(_) => "stuffit",
            Codec::SpssBytecode { .. } => "spss-bytecode",
            Codec::SasRle => "sas-rle",
            Codec::SasRdc => "sas-rdc",
            Codec::DwgLz77 { .. } => "dwg-lz77",
            Codec::Lzh(_) => "lzh",
            Codec::Psarc(_) => "psarc",
            Codec::Rar(_) => "rar",
            Codec::Ppmd7 { .. } => "ppmd7",
            Codec::Bcj2(_) => "bcj2",
            Codec::PostFilter(lzma::Post::X86) => "bcj-x86",
            Codec::PostFilter(lzma::Post::Arm) => "bcj-arm",
            Codec::PostFilter(lzma::Post::Arm64) => "bcj-arm64",
            Codec::PostFilter(lzma::Post::PowerPc) => "bcj-powerpc",
            Codec::PostFilter(lzma::Post::Ia64) => "bcj-ia64",
            Codec::PostFilter(lzma::Post::ArmThumb) => "bcj-armthumb",
            Codec::PostFilter(lzma::Post::Sparc) => "bcj-sparc",
            Codec::PostFilter(lzma::Post::RiscV) => "bcj-riscv",
            Codec::PostFilter(lzma::Post::Delta(_)) => "delta",
            Codec::PostFilterAt { .. } => "bcj-start",
            Codec::Yaz0 { .. } => "yaz0",
            Codec::BinHex => "binhex",
            Codec::Base64 => "base64",
            Codec::QuotedPrintable => "quoted-printable",
            Codec::Uu => "uudecode",
            Codec::Xx => "xxdecode",
            Codec::YEnc => "ydecode",
            Codec::Unshuffle { .. } => "unshuffle",
            Codec::Xor { .. } => "xor",
            Codec::ByteSwap { .. } => "byteswap",
            Codec::Chain { name, .. } => name,
        }
    }

    /// The transform name of lazily decoded sources.
    pub fn lazy_name(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate => "deflate (lazy)",
            Codec::Deflate64 => "deflate64 (lazy)",
            Codec::Zlib => "zlib (lazy)",
            Codec::Gzip => "gzip (lazy)",
            Codec::ZipCrypto(_) => "zipcrypto (lazy)",
            Codec::AesCtrLe(_) => "aes-ctr (lazy)",
            Codec::Rc4(_) => "rc4 (lazy)",
            Codec::XlsRc4(_) => "xls-rc4 (lazy)",
            Codec::XlsXor(_) => "xls-xor (lazy)",
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
            Codec::NsisBzip2 => "nsis-bzip2 (lazy)",
            Codec::Zstd => "zstd (lazy)",
            Codec::ZstdFrame => "zstd-frame (lazy)",
            Codec::ZstdDict(_) => "zstd-dict (lazy)",
            Codec::PalmDoc(_) => "palmdoc (lazy)",
            Codec::BtrfsLzo => "btrfs-lzo (lazy)",
            Codec::UnixCompress => "unix-compress (lazy)",
            Codec::Lznt1 { .. } => "lznt1 (lazy)",
            Codec::Xpress { .. } => "xpress (lazy)",
            Codec::XpressHuffman { .. } => "xpress-huffman (lazy)",
            Codec::Lzo1x => "lzo1x (lazy)",
            Codec::Bcfz { .. } => "bcfz (lazy)",
            Codec::Heatshrink { .. } => "heatshrink (lazy)",
            Codec::MeatPack => "meatpack (lazy)",
            Codec::Bzz => "bzz (lazy)",
            Codec::Lzop => "lzop (lazy)",
            Codec::Lzf => "lzf (lazy)",
            Codec::LzfFramed => "lzf-framed (lazy)",
            Codec::Lzfu => "lzfu (lazy)",
            Codec::Adc => "adc (lazy)",
            Codec::Implode(_) => "implode (lazy)",
            Codec::DclImplode => "dcl-implode (lazy)",
            Codec::Lzx(_) => "lzx (lazy)",
            Codec::CabFolder(_) => "cab-folder (lazy)",
            Codec::Lzfse => "lzfse (lazy)",
            Codec::Lzvn => "lzvn (lazy)",
            Codec::Pbz => "pbz (lazy)",
            Codec::WimResource(_) => "wim-resource (lazy)",
            Codec::Brotli => "brotli (lazy)",
            Codec::Xz => "xz (lazy)",
            Codec::LzmaAlone => "lzma (lazy)",
            Codec::Lzma2 { .. } => "lzma2 (lazy)",
            Codec::LzmaRaw { .. } => "lzma-raw (lazy)",
            Codec::Lz4Frame => "lz4 (lazy)",
            Codec::Lz4Block => "lz4-block (lazy)",
            Codec::Hdf5Lz4 => "hdf5-lz4 (lazy)",
            Codec::Snappy => "snappy (lazy)",
            Codec::SnappyFramed => "snappy-framed (lazy)",
            Codec::CapnpPacked => "capnp-packed (lazy)",
            Codec::Ace(_) => "ace (lazy)",
            Codec::StuffIt(_) => "stuffit (lazy)",
            Codec::SpssBytecode { .. } => "spss-bytecode (lazy)",
            Codec::SasRle => "sas-rle (lazy)",
            Codec::SasRdc => "sas-rdc (lazy)",
            Codec::DwgLz77 { .. } => "dwg-lz77 (lazy)",
            Codec::Lzh(_) => "lzh (lazy)",
            Codec::Psarc(_) => "psarc (lazy)",
            Codec::Rar(_) => "rar (lazy)",
            Codec::Ppmd7 { .. } => "ppmd7 (lazy)",
            Codec::Bcj2(_) => "bcj2 (lazy)",
            Codec::PostFilter(lzma::Post::X86) => "bcj-x86 (lazy)",
            Codec::PostFilter(lzma::Post::Arm) => "bcj-arm (lazy)",
            Codec::PostFilter(lzma::Post::Arm64) => "bcj-arm64 (lazy)",
            Codec::PostFilter(lzma::Post::PowerPc) => "bcj-powerpc (lazy)",
            Codec::PostFilter(lzma::Post::Ia64) => "bcj-ia64 (lazy)",
            Codec::PostFilter(lzma::Post::ArmThumb) => "bcj-armthumb (lazy)",
            Codec::PostFilter(lzma::Post::Sparc) => "bcj-sparc (lazy)",
            Codec::PostFilter(lzma::Post::RiscV) => "bcj-riscv (lazy)",
            Codec::PostFilter(lzma::Post::Delta(_)) => "delta (lazy)",
            Codec::PostFilterAt { .. } => "bcj-start (lazy)",
            Codec::Yaz0 { .. } => "yaz0 (lazy)",
            Codec::BinHex => "binhex (lazy)",
            Codec::Base64 => "base64 (lazy)",
            Codec::QuotedPrintable => "quoted-printable (lazy)",
            Codec::Uu => "uudecode (lazy)",
            Codec::Xx => "xxdecode (lazy)",
            Codec::YEnc => "ydecode (lazy)",
            Codec::Unshuffle { .. } => "unshuffle (lazy)",
            Codec::Xor { .. } => "xor (lazy)",
            Codec::ByteSwap { .. } => "byteswap (lazy)",
            Codec::Chain { lazy_name, .. } => lazy_name,
        }
    }

    /// How the result is described ("decompressed", "decoded", "decrypted").
    pub fn verb(&self) -> &'static str {
        match self {
            Codec::Stored => "stored",
            Codec::Deflate | Codec::Deflate64 | Codec::Zlib | Codec::Gzip => "decompressed",
            Codec::ZipCrypto(_)
            | Codec::AesCtrLe(_)
            | Codec::Rc4(_)
            | Codec::XlsRc4(_)
            | Codec::XlsXor(_)
            | Codec::AesCbc(_)
            | Codec::Eexec { .. } => "decrypted",
            Codec::Lzw { .. }
            | Codec::RunLength
            | Codec::PackBits
            | Codec::Lz4Frame
            | Codec::Lz4Block
            | Codec::Hdf5Lz4
            | Codec::Snappy
            | Codec::SnappyFramed
            | Codec::Bzip2
            | Codec::NsisBzip2
            | Codec::Xz
            | Codec::Zstd
            | Codec::ZstdFrame
            | Codec::ZstdDict(_)
            | Codec::PalmDoc(_)
            | Codec::BtrfsLzo
            | Codec::UnixCompress
            | Codec::Lznt1 { .. }
            | Codec::Xpress { .. }
            | Codec::XpressHuffman { .. }
            | Codec::Lzo1x
            | Codec::Bcfz { .. }
            | Codec::Heatshrink { .. }
            | Codec::Bzz
            | Codec::Lzop
            | Codec::Lzf
            | Codec::LzfFramed
            | Codec::Lzfu
            | Codec::Adc
            | Codec::Implode(_)
            | Codec::DclImplode
            | Codec::Lzx(_)
            | Codec::CabFolder(_)
            | Codec::Lzfse
            | Codec::Lzvn
            | Codec::Pbz
            | Codec::WimResource(_)
            | Codec::Brotli
            | Codec::LzmaAlone
            | Codec::Lzma2 { .. }
            | Codec::LzmaRaw { .. }
            | Codec::Ace(_)
            | Codec::StuffIt(_) => "decompressed",
            Codec::SpssBytecode { .. } | Codec::SasRle | Codec::SasRdc => "decompressed",
            Codec::DwgLz77 { .. } => "decompressed",
            Codec::Lzh(_) | Codec::Psarc(_) => "decompressed",
            Codec::Rar(_) | Codec::Ppmd7 { .. } | Codec::Bcj2(_) | Codec::Yaz0 { .. } => {
                "decompressed"
            }
            Codec::PostFilter(_) | Codec::PostFilterAt { .. } | Codec::BinHex => "decoded",
            Codec::AsciiHex
            | Codec::Ascii85
            | Codec::PngPredictor { .. }
            | Codec::TiffPredictor { .. }
            | Codec::MeatPack
            | Codec::Base64
            | Codec::QuotedPrintable
            | Codec::Uu
            | Codec::Xx
            | Codec::YEnc
            | Codec::Unshuffle { .. }
            | Codec::Xor { .. }
            | Codec::ByteSwap { .. } => "decoded",
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
            | Codec::XlsRc4(_)
            | Codec::XlsXor(_)
            | Codec::AesCbc(_)
            | Codec::Eexec { .. }
            | Codec::AsciiHex
            | Codec::Ascii85
            | Codec::PngPredictor { .. }
            | Codec::TiffPredictor { .. }
            | Codec::Base64
            | Codec::QuotedPrintable
            | Codec::Uu
            | Codec::Xx
            | Codec::YEnc
            | Codec::Unshuffle { .. }
            | Codec::Xor { .. }
            | Codec::ByteSwap { .. } => 1,
            Codec::RunLength | Codec::PackBits => 128,
            Codec::Lz4Frame
            | Codec::Lz4Block
            | Codec::Hdf5Lz4
            | Codec::Snappy
            | Codec::SnappyFramed => 256,
            // A zero tag and a count stand for 256 zero words.
            Codec::CapnpPacked => 1024,
            // One command byte per 8-byte value.
            Codec::SpssBytecode { .. } => 8,
            // Two bytes insert up to 4112 blanks or zeros.
            Codec::SasRle => 2_100,
            // Three bytes (and two control bits) repeat up to 4114 bytes.
            Codec::SasRdc => 1_400,
            // Each zero byte of a long length adds 255 bytes.
            Codec::DwgLz77 { .. } => 256,
            // A two-byte back-reference copies up to 10 bytes.
            Codec::PalmDoc(_) => 8,
            // A block of up to 900 kB can encode runs of 255-byte repeats.
            Codec::Bzip2 | Codec::NsisBzip2 => 50_000,
            // LZMA's longest match (273 bytes) costs a handful of bits.
            Codec::Xz | Codec::LzmaAlone | Codec::Lzma2 { .. } | Codec::LzmaRaw { .. } => 7_000,
            // RLE blocks can encode 128 KiB in four bytes.
            Codec::Zstd | Codec::ZstdFrame | Codec::ZstdDict(_) => 32_768,
            Codec::UnixCompress => 8_000,
            // A 32 KiB copy costs 35 bits.
            Codec::Bcfz { .. } => 8_000,
            // At most 2^lookahead bytes per back-reference of 1 + window +
            // lookahead bits.
            Codec::Heatshrink { .. } => 16,
            // Two characters per byte, each possibly with a space.
            Codec::MeatPack => 4,
            // A highly probable symbol costs a small fraction of a bit.
            Codec::Bzz => 50_000,
            // A 3-byte chunk stands for 4 KiB of zeros when another follows.
            Codec::Lznt1 { .. } => 1_400,
            // Each 64 KiB block costs at least its 256-byte table.
            Codec::XpressHuffman { .. } => 512,
            Codec::Xpress { .. } => 32_768,
            // Each zero length byte adds 255 bytes.
            Codec::Lzo1x | Codec::Lzop | Codec::BtrfsLzo => 512,
            // At most 264 bytes per 3-byte back reference.
            Codec::Lzf | Codec::LzfFramed => 128,
            // At most 17 bytes per 2-byte reference (plus control bits).
            Codec::Lzfu => 16,
            // At most 67 bytes per 3-byte match.
            Codec::Adc => 32,
            // Matches of up to 320 or 518 bytes in about 17 or 24 bits.
            Codec::Implode(_) | Codec::DclImplode => 256,
            // A 32 KiB frame (block) takes a few bytes at least.
            Codec::Lzx(_) => 32_768,
            // A 4 KiB RAR 5 match costs a few bits; PPMd runs cost less.
            Codec::Rar(_) => 1 << 16,
            // A highly probable symbol costs a small fraction of a bit.
            Codec::Ppmd7 { .. } => 1 << 16,
            // As its main stream's codec (the other streams are smaller).
            Codec::Bcj2(p) => p.streams.first().map_or(1, |s| s.codec.max_ratio()),
            Codec::CabFolder(f) if f.method() == 0 => 1,
            Codec::CabFolder(_) => 32_768,
            Codec::Lzfse => 4_096,
            // A 1-byte opcode copies at most 15 bytes, a 2-byte one 271.
            Codec::Lzvn => 256,
            Codec::Pbz => 7_000,
            // A 1 GiB LZMS match costs a few dozen bits, and a solid
            // chunk can be that large.
            Codec::WimResource(r) if r.solid || r.kind == wim::Kind::Lzms => u64::MAX,
            Codec::WimResource(_) => 32_768,
            // A copy of 16 MiB costs a few bits.
            Codec::Brotli => 1 << 20,
            Codec::Lzw { .. } => 4096,
            Codec::Deflate | Codec::Zlib | Codec::Gzip => 1032,
            // A 64 KiB match costs about 30 bits.
            Codec::Deflate64 => 16_384,
            // A 259-byte match costs a handful of bits; a solid member's
            // output is unrelated to the bytes before it, so no bound.
            Codec::Ace(p) if p.members.len() > 1 => u64::MAX,
            Codec::Ace(_) => 1024,
            // Arsenic and RLE90 runs: a few bits for up to 255 bytes, in
            // blocks of up to 16 MiB.
            Codec::StuffIt(_) => 32_768,
            Codec::Lzh(p) => p.max_ratio(),
            // zlib or LZMA blocks, or stored ones.
            Codec::Psarc(_) => 7_000,
            Codec::PostFilter(_) | Codec::PostFilterAt { .. } => 1,
            // A 3-byte back-reference (and a ninth of a group byte) copies
            // up to 273 bytes.
            Codec::Yaz0 { .. } => 128,
            // Two 6-bit characters per byte; a 0x90 run of up to 255 bytes
            // costs two bytes, 2.7 characters.
            Codec::BinHex => 128,
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
            Codec::Deflate64 => Box::new(Streaming(inflate::Inflate::deflate64())),
            Codec::Zlib => Box::new(Streaming(Zlib::default())),
            Codec::Gzip => Box::new(Streaming(gzip::Gzip::default())),
            Codec::AsciiHex => {
                Box::new(Streaming(filters::Bytes::new(filters::AsciiHex::default())))
            }
            Codec::Ascii85 => Box::new(Streaming(filters::Bytes::new(filters::Ascii85::default()))),
            Codec::RunLength => Box::new(Streaming(filters::Bytes::new(
                filters::RunLength::default(),
            ))),
            Codec::PackBits => {
                Box::new(Streaming(filters::Bytes::new(filters::PackBits::default())))
            }
            Codec::Lzw { early_change } => Box::new(Streaming(filters::Bytes::new(
                filters::Lzw::new(*early_change),
            ))),
            Codec::PngPredictor { bpp, row } => Box::new(Streaming(filters::Bytes::new(
                filters::PngPredictor::new(*bpp, *row),
            ))),
            Codec::TiffPredictor { bpp, row } => Box::new(Streaming(filters::Bytes::new(
                filters::TiffPredictor::new(*bpp, *row),
            ))),
            Codec::Lzfse => Box::new(Streaming(lzfse::Lzfse::default())),
            Codec::Lzvn => Box::new(Streaming(lzfse::Lzvn::default())),
            Codec::Pbz => Box::new(pbz::Pbz::default()),
            Codec::WimResource(r) => Box::new(wim::WimDecoder::new(*r)),
            Codec::Brotli => Box::new(Streaming(brotli::Stream::default())),
            Codec::UnixCompress => Box::new(unixz::UnixCompress::default()),
            Codec::Lznt1 { size } => Box::new(Streaming(lznt1::Lznt1::new(*size))),
            Codec::Xpress { size } => Box::new(Streaming(xpress::Xpress::new(*size))),
            Codec::XpressHuffman { size } => Box::new(Streaming(xpress::XpressHuffman::new(*size))),
            Codec::Lzo1x => Box::new(Streaming(lzo::Lzo1x::default())),
            Codec::Bcfz { size } => Box::new(Streaming(bcfz::Bcfz::new(*size))),
            Codec::Heatshrink { window, lookahead } => {
                Box::new(Streaming(heatshrink::Heatshrink::new(*window, *lookahead)))
            }
            Codec::MeatPack => Box::new(Streaming(meatpack::MeatPack::default())),
            Codec::Bzz => Box::new(Streaming(bzz::Bzz::default())),
            Codec::Lzop => Box::new(Streaming(lzo::Lzop::default())),
            Codec::Lzf => Box::new(Streaming(legacy::Lzf::default())),
            Codec::LzfFramed => Box::new(Streaming(legacy::LzfFramed::default())),
            Codec::Lzfu => Box::new(Streaming(lzfu::Lzfu::default())),
            Codec::Adc => Box::new(Streaming(legacy::Adc::default())),
            Codec::Implode(params) => Box::new(Streaming(implode::Explode::new(*params))),
            Codec::DclImplode => Box::new(Streaming(implode::DclExplode::default())),
            Codec::Lzx(params) => Box::new(lzx::LzxStream::new(*params)),
            Codec::CabFolder(folder) => Box::new(cab::FolderDecoder::new(*folder)),
            Codec::Rar(params) => Box::new(rar::Stream::new(params.clone())),
            Codec::Bcj2(params) => Box::new(bcj2::Bcj2::new(params)),
            Codec::Ppmd7 { order, mem, size } => {
                Box::new(Streaming(rar::Ppmd7::new(u32::from(*order), *mem, *size)))
            }
            Codec::Zstd => Box::new(Streaming(zstd::Zstd::new())),
            Codec::ZstdFrame => Box::new(Streaming(zstd::Zstd::single_frame())),
            Codec::ZstdDict(d) => Box::new(Streaming(zstd::Zstd::with_dictionary(d.clone()))),
            Codec::PalmDoc(book) => Box::new(Streaming(palmdoc::Records::new(book.clone()))),
            Codec::BtrfsLzo => Box::new(Streaming(lzo::BtrfsLzo::default())),
            Codec::Bzip2 => Box::new(Streaming(bzip2::Bzip2::default())),
            Codec::NsisBzip2 => Box::new(Streaming(bzip2::Bzip2::nsis())),
            Codec::Lz4Frame => Box::new(Streaming(lz::Lz4Frame::default())),
            Codec::Xz => Box::new(xz::XzStream::default()),
            Codec::LzmaAlone => Box::new(lzma::LzmaStream::alone()),
            Codec::Lzma2 { dict } => Box::new(lzma::Lzma2Stream::new(*dict)),
            Codec::LzmaRaw { props, size, dict } => {
                Box::new(lzma::LzmaStream::raw(*props, *size, *dict))
            }
            Codec::Lz4Block => Box::new(Streaming(lz::Lz4Block::new())),
            Codec::Hdf5Lz4 => Box::new(Streaming(lz::Hdf5Lz4::default())),
            Codec::Snappy => Box::new(Streaming(lz::Snappy::default())),
            Codec::SnappyFramed => Box::new(Streaming(lz::SnappyFramed::default())),
            Codec::CapnpPacked => Box::new(Streaming(capnp::Packed::default())),
            Codec::Ace(params) => Box::new(ace::Decoder::new(params.clone())),
            Codec::StuffIt(params) => Box::new(stuffit::Decoder::new(*params)),
            Codec::SpssBytecode { bias, big_endian } => {
                Box::new(Streaming(statdata::SpssBytecode::new(*bias, *big_endian)))
            }
            Codec::SasRle => Box::new(Streaming(statdata::SasRle::default())),
            Codec::SasRdc => Box::new(Streaming(statdata::SasRdc::default())),
            Codec::DwgLz77 { size } => Box::new(Streaming(dwg::Lz77::new(*size))),
            Codec::Eexec { hex } => {
                Box::new(Streaming(filters::Bytes::new(filters::Eexec::new(*hex))))
            }
            Codec::Rc4(key) => Box::new(Streaming(crypto::stream::Rc4::new(key))),
            Codec::XlsRc4(key) => Box::new(Streaming(filters::Bytes::new(
                crypto::office::XlsRc4::new(key),
            ))),
            Codec::XlsXor(array) => Box::new(Streaming(filters::Bytes::new(
                crypto::office::XlsRc4::xor(array),
            ))),
            Codec::AesCbc(key) => Box::new(Streaming(filters::Bytes::new(
                crypto::stream::AesCbcIvPrefixed::new(key),
            ))),
            Codec::ZipCrypto(key) => Box::new(Streaming(crypto::stream::ZipCrypto::new(key))),
            Codec::AesCtrLe(key) => match crypto::stream::AesCtrLe::new(key) {
                Some(d) => Box::new(Streaming(d)),
                None => Box::new(Streaming(pipeline::Failing("invalid AES key length"))),
            },
            Codec::Lzh(params) => Box::new(Streaming(lzh::Lzh::new(*params))),
            Codec::Psarc(entry) => Box::new(psarc::Decoder::new(entry.clone())),
            Codec::PostFilter(post) => Box::new(lzma::PostFilter::new(*post)),
            Codec::PostFilterAt { post, start } => {
                Box::new(lzma::PostFilter::with_start(*post, *start))
            }
            Codec::Yaz0 { size } => Box::new(Streaming(yaz0::Yaz0::new(*size))),
            Codec::BinHex => Box::new(Streaming(binhex::BinHex::default())),
            Codec::Base64 => Box::new(Streaming(filters::Bytes::new(filters::Base64::default()))),
            Codec::QuotedPrintable => Box::new(Streaming(filters::Bytes::new(
                filters::QuotedPrintable::default(),
            ))),
            Codec::Uu => Box::new(Streaming(filters::Bytes::new(filters::UuLines::uu()))),
            Codec::Xx => Box::new(Streaming(filters::Bytes::new(filters::UuLines::xx()))),
            Codec::YEnc => Box::new(Streaming(filters::Bytes::new(filters::YEnc::default()))),
            Codec::Unshuffle { width } => Box::new(Streaming(filters::Unshuffle::new(*width))),
            Codec::Xor { key } => Box::new(Streaming(filters::Bytes::new(filters::Xor::new(key)))),
            Codec::ByteSwap { width } => Box::new(Streaming(filters::Bytes::new(
                filters::ByteSwap::new(*width),
            ))),
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
        // Back-references reach at most 32 KiB (64 KiB for Deflate64).
        out_len.saturating_sub(self.window())
    }

    fn heap_size(&self) -> Option<usize> {
        Some(inflate::Inflate::heap_size(self))
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

    fn heap_size(&self) -> Option<usize> {
        Some(self.inflate.heap_size())
    }
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

    /// Deflate64 from 7-Zip 26.03 (`7zz a -tzip -mm=Deflate64 -mx=9`, the
    /// raw stream of the entry; input from `tests/data/7z/make_codecs.sh`):
    /// 40 000 bytes repeated (distances past 32 KiB) and a 70 000-byte run.
    #[test]
    fn deflate64_from_7zip() {
        let data = include_bytes!("testdata/salad.deflate64");
        let out = inflate::inflate(data, usize::MAX).err();
        assert!(out.is_some(), "plain DEFLATE must not accept it");
        let mut d = Codec::Deflate64.decoder().unwrap();
        let out = pipeline::decode_all(d.as_mut(), data, 1 << 20).unwrap();
        assert_eq!(out.len(), 155_000);
        assert_eq!(crc32(&out), 0x5555_a130);
        assert_eq!(&out[40_000..80_000], &out[..40_000]);
        let (checked, _) =
            pipeline::verify_checkpoints(|| Codec::Deflate64.decoder().unwrap(), data, 4096, 3)
                .unwrap();
        assert!(checked > 5, "{checked}");
    }

    /// 7z PPMd from 7-Zip 26.03 (`7zz a -t7z -m0=PPMd:o=6:mem=1m`, the
    /// packed stream; the first 20 000 bytes of the Deflate64 test's input).
    #[test]
    fn ppmd7_from_7zip() {
        let data = include_bytes!("testdata/salad.ppmd7");
        let codec = Codec::Ppmd7 {
            order: 6,
            mem: 1 << 20,
            size: 20_000,
        };
        let out = pipeline::decode_all(codec.decoder().unwrap().as_mut(), data, 1 << 20).unwrap();
        assert_eq!(out.len(), 20_000);
        assert_eq!(crc32(&out), 0xd2f8_5e64);
        let (checked, _) =
            pipeline::verify_checkpoints(|| codec.decoder().unwrap(), data, 2048, 2).unwrap();
        assert!(checked > 3, "{checked}");
        // Truncated: an error, after the bytes that could be decoded.
        assert!(
            pipeline::decode_all(codec.decoder().unwrap().as_mut(), &data[..1000], 1 << 20)
                .is_err()
        );
        // Out of 7-Zip's range: unsupported.
        let bad = Codec::Ppmd7 {
            order: 1,
            mem: 1 << 20,
            size: 1,
        };
        let err = pipeline::decode_all(bad.decoder().unwrap().as_mut(), data, 1 << 20).unwrap_err();
        assert_eq!(err.kind, crate::error::DiagKind::Unsupported);
    }

    #[test]
    fn deflate_and_zlib_checkpoints_resume_exactly() {
        let dynamic = include_bytes!("testdata/words.deflate");
        let (checked, largest) =
            pipeline::verify_checkpoints(|| Codec::Deflate.decoder().unwrap(), dynamic, 512, 3)
                .unwrap();
        assert!(checked > 5, "{checked}");
        assert!(largest < 4096, "{largest}");
        let mut zlib = vec![0x78, 0x9c];
        zlib.extend_from_slice(dynamic);
        zlib.extend_from_slice(&adler32(include_bytes!("testdata/words.txt")).to_be_bytes());
        let (checked, _) =
            pipeline::verify_checkpoints(|| Codec::Zlib.decoder().unwrap(), &zlib, 512, 3).unwrap();
        assert!(checked > 5, "{checked}");
    }
}
