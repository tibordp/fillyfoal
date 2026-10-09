//! Matroska and WebM (EBML).
//!
//! An EBML document is a tree of elements `ID (vint), size (vint), data`.
//! A table gives every element of the Matroska schema its name, type,
//! nesting level and meaning; unknown elements are shown as binary. Master
//! elements expand lazily and list their children in pages (clusters,
//! cues, blocks), so a large file is never walked as a whole. Elements of
//! unknown size (live streams) end where an element of the same or a higher
//! level begins; an unknown-size Segment runs to the end of the file.
//!
//! Codec private data is decoded per codec (AVC/HEVC/AV1/VP9 configuration
//! records, Xiph-laced Vorbis/Theora headers, OpusHead, FLAC metadata,
//! AAC AudioSpecificConfig, VfW/ACM structures, ALAC), blocks show their
//! header, lacing (Xiph, EBML, fixed-size) and frames, and CRC-32 elements
//! are checked against the data they cover.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_be, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::audio::{flac, vorbis};
use crate::formats::iff::wav;
use crate::formats::util::sound;
use crate::formats::util::vidutil::{self, detached, nal, seconds_f64, uint};
use crate::formats::{Format, Head, Input, Probe, content, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, field, flag};

pub static MKV: Format = Format {
    name: "mkv",
    title: "Matroska",
    extensions: &["mkv", "mka", "mks", "mk3d"],
    mime: "video/x-matroska",
    probe: Probe::Custom(|h| doc_type(h).is_some_and(|t| t != b"webm")),
    dissect: crate::expander!(dissect: Input),
};

pub static WEBM: Format = Format {
    name: "webm",
    title: "WebM",
    extensions: &["webm", "weba"],
    mime: "video/webm",
    probe: Probe::Custom(|h| doc_type(h).is_some_and(|t| t == b"webm")),
    dissect: crate::expander!(dissect: Input),
};

const EBML_MAGIC: &[u8] = b"\x1a\x45\xdf\xa3";

/// The DocType from the EBML header in the probe window.
fn doc_type<'a>(h: &Head<'a>) -> Option<&'a [u8]> {
    if !h.starts_with(EBML_MAGIC) {
        return None;
    }
    let (size, size_len) = vint(h.data.get(4..)?)?;
    let start = 4usize.checked_add(size_len)?;
    let end = start.checked_add(usize::try_from(size?).ok()?)?;
    let header = h.data.get(start..end.min(h.data.len()))?;
    let found = mem_children(header).find(|(id, _)| *id == DOC_TYPE)?;
    let t = found.1;
    let t = t.get(..t.iter().position(|&b| b == 0).unwrap_or(t.len()))?;
    (t == b"matroska" || t == b"webm").then_some(t)
}

// ---------------------------------------------------------------------------
// Element IDs used by the code (the schema below names them all)

const EBML: u32 = 0x1a45dfa3;
const DOC_TYPE: u32 = 0x4282;
const DOC_TYPE_VERSION: u32 = 0x4287;
const DOC_TYPE_READ_VERSION: u32 = 0x4285;
const VOID: u32 = 0xec;
const CRC32: u32 = 0xbf;
const SEGMENT: u32 = 0x18538067;
const SEEK_HEAD: u32 = 0x114d9b74;
const SEEK: u32 = 0x4dbb;
const SEEK_ID: u32 = 0x53ab;
const SEEK_POSITION: u32 = 0x53ac;
const INFO: u32 = 0x1549a966;
const TIMESTAMP_SCALE: u32 = 0x2ad7b1;
const DURATION: u32 = 0x4489;
const TITLE: u32 = 0x7ba9;
const MUXING_APP: u32 = 0x4d80;
const WRITING_APP: u32 = 0x5741;
const CLUSTER: u32 = 0x1f43b675;
const TIMESTAMP: u32 = 0xe7;
const SIMPLE_BLOCK: u32 = 0xa3;
const BLOCK_GROUP: u32 = 0xa0;
const BLOCK: u32 = 0xa1;
const BLOCK_DURATION: u32 = 0x9b;
const REFERENCE_BLOCK: u32 = 0xfb;
const TRACKS: u32 = 0x1654ae6b;
const TRACK_ENTRY: u32 = 0xae;
const TRACK_NUMBER: u32 = 0xd7;
const TRACK_TYPE: u32 = 0x83;
const FLAG_DEFAULT: u32 = 0x88;
const FLAG_FORCED: u32 = 0x55aa;
const FLAG_ENABLED: u32 = 0xb9;
const DEFAULT_DURATION: u32 = 0x23e383;
const DEFAULT_FIELD_DURATION: u32 = 0x234e7a;
const NAME: u32 = 0x536e;
const LANGUAGE: u32 = 0x22b59c;
const LANGUAGE_BCP47: u32 = 0x22b59d;
const CODEC_ID: u32 = 0x86;
const CODEC_PRIVATE: u32 = 0x63a2;
const CODEC_DELAY: u32 = 0x56aa;
const SEEK_PRE_ROLL: u32 = 0x56bb;
const BLOCK_ADD_ID_TYPE: u32 = 0x41e7;
const VIDEO: u32 = 0xe0;
const FLAG_INTERLACED: u32 = 0x9a;
const STEREO_MODE: u32 = 0x53b8;
const PIXEL_WIDTH: u32 = 0xb0;
const PIXEL_HEIGHT: u32 = 0xba;
const DISPLAY_WIDTH: u32 = 0x54b0;
const DISPLAY_HEIGHT: u32 = 0x54ba;
const DISPLAY_UNIT: u32 = 0x54b2;
const FRAME_RATE: u32 = 0x2383e3;
const COLOUR: u32 = 0x55b0;
const MATRIX: u32 = 0x55b1;
const BITS_PER_CHANNEL: u32 = 0x55b2;
const RANGE_ID: u32 = 0x55b9;
const TRANSFER: u32 = 0x55ba;
const PRIMARIES: u32 = 0x55bb;
const MAX_CLL: u32 = 0x55bc;
const MAX_FALL: u32 = 0x55bd;
const MASTERING: u32 = 0x55d0;
const LUMINANCE_MAX: u32 = 0x55d9;
const LUMINANCE_MIN: u32 = 0x55da;
const PROJECTION: u32 = 0x7670;
const PROJECTION_TYPE: u32 = 0x7671;
const POSE_YAW: u32 = 0x7673;
const POSE_PITCH: u32 = 0x7674;
const POSE_ROLL: u32 = 0x7675;
const AUDIO: u32 = 0xe1;
const SAMPLING_FREQUENCY: u32 = 0xb5;
const OUTPUT_SAMPLING_FREQUENCY: u32 = 0x78b5;
const CHANNELS: u32 = 0x9f;
const BIT_DEPTH: u32 = 0x6264;
const CONTENT_ENCODINGS: u32 = 0x6d80;
const CONTENT_ENCODING: u32 = 0x6240;
const CONTENT_ENCODING_SCOPE: u32 = 0x5032;
const CONTENT_ENCODING_TYPE: u32 = 0x5033;
const CONTENT_COMPRESSION: u32 = 0x5034;
const CONTENT_COMP_ALGO: u32 = 0x4254;
const CONTENT_COMP_SETTINGS: u32 = 0x4255;
const CONTENT_ENCRYPTION: u32 = 0x5035;
const CONTENT_ENC_ALGO: u32 = 0x47e1;
const CUES: u32 = 0x1c53bb6b;
const CUE_POINT: u32 = 0xbb;
const CUE_TIME: u32 = 0xb3;
const CUE_TRACK_POSITIONS: u32 = 0xb7;
const CUE_TRACK: u32 = 0xf7;
const CUE_CLUSTER_POSITION: u32 = 0xf1;
const CUE_RELATIVE_POSITION: u32 = 0xf0;
const CUE_BLOCK_NUMBER: u32 = 0x5378;
const ATTACHMENTS: u32 = 0x1941a469;
const ATTACHED_FILE: u32 = 0x61a7;
const FILE_DESCRIPTION: u32 = 0x467e;
const FILE_NAME: u32 = 0x466e;
const FILE_MEDIA_TYPE: u32 = 0x4660;
const FILE_DATA: u32 = 0x465c;
const CHAPTERS: u32 = 0x1043a770;
const EDITION_ENTRY: u32 = 0x45b9;
const EDITION_FLAG_DEFAULT: u32 = 0x45db;
const EDITION_FLAG_ORDERED: u32 = 0x45dd;
const EDITION_FLAG_HIDDEN: u32 = 0x45bd;
const EDITION_DISPLAY: u32 = 0x4520;
const EDITION_STRING: u32 = 0x4521;
const CHAPTER_ATOM: u32 = 0xb6;
const CHAPTER_TIME_START: u32 = 0x91;
const CHAPTER_TIME_END: u32 = 0x92;
const CHAPTER_FLAG_HIDDEN: u32 = 0x98;
const CHAPTER_DISPLAY: u32 = 0x80;
const CHAP_STRING: u32 = 0x85;
const CHAP_LANGUAGE: u32 = 0x437c;
const CHAP_LANGUAGE_BCP47: u32 = 0x437d;
const TAGS: u32 = 0x1254c367;
const TAG: u32 = 0x7373;
const TARGETS: u32 = 0x63c0;
const TARGET_TYPE_VALUE: u32 = 0x68ca;
const TARGET_TYPE: u32 = 0x63ca;
const TAG_TRACK_UID: u32 = 0x63c5;
const TAG_EDITION_UID: u32 = 0x63c9;
const TAG_CHAPTER_UID: u32 = 0x63c4;
const TAG_ATTACHMENT_UID: u32 = 0x63c6;
const SIMPLE_TAG: u32 = 0x67c8;
const TAG_NAME: u32 = 0x45a3;
const TAG_STRING: u32 = 0x4487;
const TAG_BINARY: u32 = 0x4485;
const BLOCK_ADDITION_MAPPING: u32 = 0x41e4;
const BLOCK_ADD_ID_VALUE: u32 = 0x41f0;

// ---------------------------------------------------------------------------
// Variable-length integers

/// An element ID (marker bits kept): value and length.
fn element_id(d: &[u8]) -> Option<(u32, usize)> {
    let first = *d.first()?;
    let len = usize::try_from(first.leading_zeros())
        .ok()?
        .checked_add(1)?;
    if len > 4 {
        return None;
    }
    let bytes = d.get(..len)?;
    let id = bytes.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
    Some((id, len))
}

/// A variable-length integer with its marker bit removed, whether it is
/// all ones, and its length.
fn vint_raw(d: &[u8]) -> Option<(u64, bool, usize)> {
    let first = *d.first()?;
    let len = usize::try_from(first.leading_zeros())
        .ok()?
        .checked_add(1)?;
    if len > 8 {
        return None;
    }
    let bytes = d.get(..len)?;
    let mask = 0xffu8.checked_shr(u32::try_from(len).ok()?).unwrap_or(0);
    let mut value = u64::from(first & mask);
    let mut all_ones = first & mask == mask;
    for &b in bytes.get(1..).unwrap_or_default() {
        value = (value << 8) | u64::from(b);
        all_ones &= b == 0xff;
    }
    Some((value, all_ones, len))
}

/// A data size: `None` for the reserved "unknown" value; and its length.
fn vint(d: &[u8]) -> Option<(Option<u64>, usize)> {
    let (value, all_ones, len) = vint_raw(d)?;
    Some((if all_ones { None } else { Some(value) }, len))
}

/// Children of an in-memory master element with known sizes. The last
/// child may be cut short by the end of `d`.
fn mem_children(d: &[u8]) -> impl Iterator<Item = (u32, &[u8])> {
    let mut at = 0usize;
    std::iter::from_fn(move || {
        let rest = d.get(at..)?;
        let (id, id_len) = element_id(rest)?;
        let (size, size_len) = vint(rest.get(id_len..)?)?;
        let start = id_len.checked_add(size_len)?;
        let size = usize::try_from(size?).ok()?;
        let end = start.checked_add(size)?;
        let data = rest.get(start..end.min(rest.len()))?;
        at = at.checked_add(end)?;
        Some((id, data))
    })
}

fn child(d: &[u8], id: u32) -> Option<&[u8]> {
    mem_children(d).find(|(i, _)| *i == id).map(|(_, v)| v)
}

fn child_uint(d: &[u8], id: u32) -> Option<u64> {
    child(d, id).map(be_uint)
}

fn child_text(d: &[u8], id: u32) -> Option<String> {
    child(d, id).map(text)
}

fn be_uint(d: &[u8]) -> u64 {
    d.iter()
        .take(8)
        .fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
}

fn be_int(d: &[u8]) -> i64 {
    let n = d.len().min(8);
    let raw = be_uint(d);
    if n == 0 {
        return 0;
    }
    let shift = u32::try_from(64usize.saturating_sub(n.saturating_mul(8))).unwrap_or(0);
    i64::from_ne_bytes(raw.wrapping_shl(shift).to_ne_bytes()).wrapping_shr(shift)
}

fn be_float(d: &[u8]) -> Option<f64> {
    match d.len() {
        0 => Some(0.0),
        4 => Some(f64::from(f32::from_be_bytes(d.try_into().ok()?))),
        8 => Some(f64::from_be_bytes(d.try_into().ok()?)),
        _ => None,
    }
}

fn text(d: &[u8]) -> String {
    crate::text::until_nul(d)
}

// ---------------------------------------------------------------------------
// Schema

#[derive(Clone, Copy)]
enum Kind {
    Master,
    UInt,
    Bool,
    Enum(EnumTable),
    Flags(FlagTable),
    Int,
    Float,
    Str,
    Utf8,
    Date,
    Binary,
    Block,
    /// Unsigned nanoseconds.
    Ns,
    /// Signed nanoseconds.
    SNs,
    /// Unsigned ticks of the segment's TimestampScale.
    Ticks,
    /// Signed ticks of the segment's TimestampScale.
    STicks,
    /// An offset from the start of the segment's data.
    Position,
}

struct Def {
    id: u32,
    name: &'static str,
    kind: Kind,
    /// Nesting level (0 = top); 255 = global (may appear anywhere).
    level: u8,
    desc: &'static str,
}

const fn d(id: u32, name: &'static str, kind: Kind, level: u8, desc: &'static str) -> Def {
    Def {
        id,
        name,
        kind,
        level,
        desc,
    }
}

const TRACK_TYPES: EnumTable = &[
    (1, "video"),
    (2, "audio"),
    (3, "complex"),
    (0x10, "logo"),
    (0x11, "subtitle"),
    (0x12, "buttons"),
    (0x20, "control"),
    (0x21, "metadata"),
];

const COMP_ALGO: EnumTable = &[
    (0, "zlib"),
    (1, "bzlib"),
    (2, "lzo1x"),
    (3, "header stripping"),
];
const ENC_TYPE: EnumTable = &[(0, "compression"), (1, "encryption")];
const ENC_SCOPE: FlagTable = &[flag(1, "BLOCK"), flag(2, "PRIVATE"), flag(4, "NEXT")];
const ENC_ALGO: EnumTable = &[
    (0, "not encrypted"),
    (1, "DES"),
    (2, "3DES"),
    (3, "Twofish"),
    (4, "Blowfish"),
    (5, "AES"),
];
const AES_MODE: EnumTable = &[(1, "AES-CTR"), (2, "AES-CBC")];
const SIG_ALGO: EnumTable = &[(0, "not signed"), (1, "RSA")];
const SIG_HASH: EnumTable = &[(0, "not signed"), (1, "SHA1-160"), (2, "MD5")];
const INTERLACED: EnumTable = &[(0, "undetermined"), (1, "interlaced"), (2, "progressive")];
const FIELD_ORDER: EnumTable = &[
    (0, "progressive"),
    (1, "top field first"),
    (2, "undetermined"),
    (6, "bottom field first"),
    (9, "top field first, interleaved"),
    (14, "bottom field first, interleaved"),
];
const STEREO: EnumTable = &[
    (0, "mono"),
    (1, "side by side (left eye first)"),
    (2, "top-bottom (right eye first)"),
    (3, "top-bottom (left eye first)"),
    (4, "checkboard (right eye first)"),
    (5, "checkboard (left eye first)"),
    (6, "row interleaved (right eye first)"),
    (7, "row interleaved (left eye first)"),
    (8, "column interleaved (right eye first)"),
    (9, "column interleaved (left eye first)"),
    (10, "anaglyph (cyan/red)"),
    (11, "side by side (right eye first)"),
    (12, "anaglyph (green/magenta)"),
    (13, "both eyes laced in one block (left eye first)"),
    (14, "both eyes laced in one block (right eye first)"),
];
const OLD_STEREO: EnumTable = &[
    (0, "mono"),
    (1, "right eye"),
    (2, "left eye"),
    (3, "both eyes"),
];
const ALPHA_MODE: EnumTable = &[(0, "none"), (1, "present in BlockAdditional")];
const DISPLAY_UNITS: EnumTable = &[
    (0, "pixels"),
    (1, "centimeters"),
    (2, "inches"),
    (3, "display aspect ratio"),
    (4, "unknown"),
];
const ASPECT_TYPES: EnumTable = &[(0, "free resizing"), (1, "keep aspect ratio"), (2, "fixed")];
const RANGE: EnumTable = &[
    (0, "unspecified"),
    (1, "broadcast"),
    (2, "full"),
    (3, "defined by matrix/transfer"),
];
const SITING_HORZ: EnumTable = &[(0, "unspecified"), (1, "left collocated"), (2, "half")];
const SITING_VERT: EnumTable = &[(0, "unspecified"), (1, "top collocated"), (2, "half")];
const PROJECTIONS: EnumTable = &[
    (0, "rectangular"),
    (1, "equirectangular"),
    (2, "cubemap"),
    (3, "mesh"),
];
const EMPHASIS: EnumTable = &[
    (0, "none"),
    (1, "CD audio"),
    (2, "reserved"),
    (3, "CCITT J.17"),
    (4, "FM 50"),
    (5, "FM 75"),
    (10, "phono RIAA"),
    (11, "phono IEC N78"),
    (12, "phono TELDEC"),
    (13, "phono EMI"),
    (14, "phono Columbia LP"),
    (15, "phono LONDON"),
    (16, "phono NARTB"),
];
const PLANE_TYPES: EnumTable = &[(0, "left eye"), (1, "right eye"), (2, "background")];
const TRANSLATE_CODECS: EnumTable = &[(0, "Matroska Script"), (1, "DVD-menu")];
const PROCESS_TIMES: EnumTable = &[
    (0, "during the whole chapter"),
    (1, "before starting playback"),
    (2, "after playback of the chapter"),
];
const SKIP_TYPES: EnumTable = &[
    (0, "no skipping"),
    (1, "opening credits"),
    (2, "end credits"),
    (3, "recap"),
    (4, "next preview"),
    (5, "preview"),
    (6, "advertisement"),
    (7, "intermission"),
];
const TARGET_TYPES: EnumTable = &[
    (70, "COLLECTION"),
    (60, "EDITION / ISSUE / VOLUME / OPUS / SEASON / SEQUEL"),
    (50, "ALBUM / OPERA / CONCERT / MOVIE / EPISODE"),
    (40, "PART / SESSION"),
    (30, "TRACK / SONG / CHAPTER"),
    (20, "SUBTRACK / MOVEMENT / SCENE"),
    (10, "SHOT"),
];

use Kind::{
    Binary, Block, Bool, Date, Float, Int, Master, Ns, Position, SNs, STicks, Str, Ticks, UInt,
    Utf8,
};

#[rustfmt::skip]
const SCHEMA: &[Def] = &[
    // EBML header (RFC 8794)
    d(EBML, "EBML", Master, 0, "EBML header: the version of EBML and the document type"),
    d(0x4286, "EBMLVersion", UInt, 1, "EBML version used to create the file"),
    d(0x42f7, "EBMLReadVersion", UInt, 1, "Minimum EBML version a parser needs"),
    d(0x42f2, "EBMLMaxIDLength", UInt, 1, "Longest element ID in the file, in bytes"),
    d(0x42f3, "EBMLMaxSizeLength", UInt, 1, "Longest element size in the file, in bytes"),
    d(DOC_TYPE, "DocType", Str, 1, "Contents of the file: \"matroska\" or \"webm\""),
    d(DOC_TYPE_VERSION, "DocTypeVersion", UInt, 1, "Version of the DocType writer"),
    d(DOC_TYPE_READ_VERSION, "DocTypeReadVersion", UInt, 1, "Minimum DocType version a parser needs"),
    d(0x4281, "DocTypeExtension", Master, 1, "An extension of the DocType used in the file"),
    d(0x4283, "DocTypeExtensionName", Str, 2, ""),
    d(0x4284, "DocTypeExtensionVersion", UInt, 2, ""),
    d(VOID, "Void", Binary, 255, "Padding, ignored; reserves space for later edits"),
    d(CRC32, "CRC-32", Binary, 255, "CRC-32 (IEEE, little-endian) of the rest of the parent element's data"),
    // Segment
    d(SEGMENT, "Segment", Master, 0, "The root element holding all other top-level elements"),
    d(SEEK_HEAD, "SeekHead", Master, 1, "Index of the positions of other top-level elements"),
    d(SEEK, "Seek", Master, 2, "One top-level element and its position"),
    d(SEEK_ID, "SeekID", Binary, 3, "ID of the indexed element"),
    d(SEEK_POSITION, "SeekPosition", Position, 3, "Position of the element, relative to the segment's data"),
    d(INFO, "Info", Master, 1, "General information about the segment"),
    d(0x73a4, "SegmentUUID", Binary, 2, "Unique 128-bit identifier of the segment"),
    d(0x7384, "SegmentFilename", Utf8, 2, ""),
    d(0x3cb923, "PrevUUID", Binary, 2, "UUID of the previous segment of a linked set"),
    d(0x3c83ab, "PrevFilename", Utf8, 2, ""),
    d(0x3eb923, "NextUUID", Binary, 2, "UUID of the next segment of a linked set"),
    d(0x3e83bb, "NextFilename", Utf8, 2, ""),
    d(0x4444, "SegmentFamily", Binary, 2, "UID shared by all segments of a family"),
    d(0x6924, "ChapterTranslate", Master, 2, "Mapping between this segment and a chapter codec's segment IDs"),
    d(0x69a5, "ChapterTranslateID", Binary, 3, ""),
    d(0x69bf, "ChapterTranslateCodec", Kind::Enum(TRANSLATE_CODECS), 3, ""),
    d(0x69fc, "ChapterTranslateEditionUID", UInt, 3, ""),
    d(TIMESTAMP_SCALE, "TimestampScale", UInt, 2, "Nanoseconds per timestamp tick (1000000 = milliseconds)"),
    d(DURATION, "Duration", Float, 2, "Duration of the segment, in ticks"),
    d(0x4461, "DateUTC", Date, 2, "Creation date (nanoseconds since 2001-01-01)"),
    d(TITLE, "Title", Utf8, 2, "General name of the segment"),
    d(MUXING_APP, "MuxingApp", Utf8, 2, "Muxing library"),
    d(WRITING_APP, "WritingApp", Utf8, 2, "Writing application"),
    // Clusters
    d(CLUSTER, "Cluster", Master, 1, "A group of blocks sharing a base timestamp"),
    d(TIMESTAMP, "Timestamp", Ticks, 2, "Base timestamp of the cluster's blocks"),
    d(0x5854, "SilentTracks", Master, 2, "Tracks not used in this cluster"),
    d(0x58d7, "SilentTrackNumber", UInt, 3, ""),
    d(0xa7, "Position", UInt, 2, "Position of the cluster in the segment"),
    d(0xab, "PrevSize", UInt, 2, "Size of the previous cluster, in bytes"),
    d(SIMPLE_BLOCK, "SimpleBlock", Block, 2, "A block with keyframe and discardable flags and no extras"),
    d(BLOCK_GROUP, "BlockGroup", Master, 2, "A block with its references, duration and additions"),
    d(BLOCK, "Block", Block, 3, "Track number, relative timestamp, flags and frame data"),
    d(0xa2, "BlockVirtual", Binary, 3, "Deprecated"),
    d(0x75a1, "BlockAdditions", Master, 3, "Extra data for the block (alpha channel, metadata)"),
    d(0xa6, "BlockMore", Master, 4, ""),
    d(0xa5, "BlockAdditional", Binary, 5, "The additional data"),
    d(0xee, "BlockAddID", UInt, 5, "What the additional data is (see BlockAdditionMapping)"),
    d(BLOCK_DURATION, "BlockDuration", Ticks, 3, "Duration of the block, in ticks"),
    d(0xfa, "ReferencePriority", UInt, 3, "Importance of this block for decoding (0 = not referenced)"),
    d(REFERENCE_BLOCK, "ReferenceBlock", STicks, 3, "Timestamp of a block this one depends on, relative to it; none means keyframe"),
    d(0xfd, "ReferenceVirtual", Int, 3, "Deprecated"),
    d(0xa4, "CodecState", Binary, 3, "New codec state from this block on"),
    d(0x75a2, "DiscardPadding", SNs, 3, "Duration of audio padding to discard"),
    d(0x8e, "Slices", Master, 3, "Deprecated"),
    d(0xe8, "TimeSlice", Master, 4, "Deprecated"),
    d(0xcc, "LaceNumber", UInt, 5, ""),
    d(0xcd, "FrameNumber", UInt, 5, ""),
    d(0xcb, "BlockAdditionID", UInt, 5, ""),
    d(0xce, "Delay", UInt, 5, ""),
    d(0xcf, "SliceDuration", UInt, 5, ""),
    d(0xc8, "ReferenceFrame", Master, 3, "DivX trick track"),
    d(0xc9, "ReferenceOffset", UInt, 4, ""),
    d(0xca, "ReferenceTimestamp", UInt, 4, ""),
    d(0xaf, "EncryptedBlock", Binary, 2, "Deprecated"),
    // Tracks
    d(TRACKS, "Tracks", Master, 1, "The tracks of the segment"),
    d(TRACK_ENTRY, "TrackEntry", Master, 2, "One track: codec, properties and settings"),
    d(TRACK_NUMBER, "TrackNumber", UInt, 3, "Number used in blocks to refer to the track"),
    d(0x73c5, "TrackUID", UInt, 3, "Unique ID used by tags and chapters"),
    d(TRACK_TYPE, "TrackType", Kind::Enum(TRACK_TYPES), 3, ""),
    d(FLAG_ENABLED, "FlagEnabled", Bool, 3, "Whether the track is usable"),
    d(FLAG_DEFAULT, "FlagDefault", Bool, 3, "Whether the track is eligible for automatic selection"),
    d(FLAG_FORCED, "FlagForced", Bool, 3, "Whether the track must be played (forced subtitles)"),
    d(0x55ab, "FlagHearingImpaired", Bool, 3, ""),
    d(0x55ac, "FlagVisualImpaired", Bool, 3, ""),
    d(0x55ad, "FlagTextDescriptions", Bool, 3, "Text descriptions of video content"),
    d(0x55ae, "FlagOriginal", Bool, 3, "Original language of the content"),
    d(0x55af, "FlagCommentary", Bool, 3, ""),
    d(0x9c, "FlagLacing", Bool, 3, "Whether the track may use lacing"),
    d(0x6de7, "MinCache", UInt, 3, "Frames a player should be able to cache"),
    d(0x6df8, "MaxCache", UInt, 3, ""),
    d(DEFAULT_DURATION, "DefaultDuration", Ns, 3, "Duration of a frame, in nanoseconds"),
    d(DEFAULT_FIELD_DURATION, "DefaultDecodedFieldDuration", Ns, 3, "Duration of a decoded field, in nanoseconds"),
    d(0x23314f, "TrackTimestampScale", Float, 3, "Deprecated: scale applied to the track's timestamps"),
    d(0x537f, "TrackOffset", Int, 3, "Deprecated"),
    d(0x55ee, "MaxBlockAdditionID", UInt, 3, "Highest BlockAddID used by the track"),
    d(BLOCK_ADDITION_MAPPING, "BlockAdditionMapping", Master, 3, "What a BlockAddID value means for this track"),
    d(BLOCK_ADD_ID_VALUE, "BlockAddIDValue", UInt, 4, ""),
    d(0x41a4, "BlockAddIDName", Str, 4, ""),
    d(BLOCK_ADD_ID_TYPE, "BlockAddIDType", UInt, 4, "Type of the additional data (often a FourCC)"),
    d(0x41ed, "BlockAddIDExtraData", Binary, 4, "Configuration for the additional data"),
    d(NAME, "Name", Utf8, 3, "Human-readable track name"),
    d(LANGUAGE, "Language", Str, 3, "ISO 639-2 language code"),
    d(LANGUAGE_BCP47, "LanguageBCP47", Str, 3, "BCP 47 language tag (overrides Language)"),
    d(CODEC_ID, "CodecID", Str, 3, "Codec identifier"),
    d(CODEC_PRIVATE, "CodecPrivate", Binary, 3, "Codec initialisation data"),
    d(0x258688, "CodecName", Utf8, 3, ""),
    d(0x7446, "AttachmentLink", UInt, 3, "Deprecated: UID of an attachment the codec uses"),
    d(0x3a9697, "CodecSettings", Utf8, 3, ""),
    d(0x3b4040, "CodecInfoURL", Str, 3, ""),
    d(0x26b240, "CodecDownloadURL", Str, 3, ""),
    d(0xaa, "CodecDecodeAll", Bool, 3, "Whether the codec can decode damaged data"),
    d(0x6fab, "TrackOverlay", UInt, 3, "A track to use when this one has gaps"),
    d(CODEC_DELAY, "CodecDelay", Ns, 3, "Built-in delay of the codec, in nanoseconds"),
    d(SEEK_PRE_ROLL, "SeekPreRoll", Ns, 3, "Decoding to discard after a seek, in nanoseconds"),
    d(0x6624, "TrackTranslate", Master, 3, ""),
    d(0x66a5, "TrackTranslateTrackID", Binary, 4, ""),
    d(0x66bf, "TrackTranslateCodec", Kind::Enum(TRANSLATE_CODECS), 4, ""),
    d(0x66fc, "TrackTranslateEditionUID", UInt, 4, ""),
    d(VIDEO, "Video", Master, 3, "Video settings"),
    d(FLAG_INTERLACED, "FlagInterlaced", Kind::Enum(INTERLACED), 4, ""),
    d(0x9d, "FieldOrder", Kind::Enum(FIELD_ORDER), 4, ""),
    d(STEREO_MODE, "StereoMode", Kind::Enum(STEREO), 4, "Stereo-3D layout"),
    d(0x53c0, "AlphaMode", Kind::Enum(ALPHA_MODE), 4, ""),
    d(0x53b9, "OldStereoMode", Kind::Enum(OLD_STEREO), 4, "Deprecated"),
    d(PIXEL_WIDTH, "PixelWidth", UInt, 4, "Width of the encoded frames"),
    d(PIXEL_HEIGHT, "PixelHeight", UInt, 4, "Height of the encoded frames"),
    d(0x54aa, "PixelCropBottom", UInt, 4, ""),
    d(0x54bb, "PixelCropTop", UInt, 4, ""),
    d(0x54cc, "PixelCropLeft", UInt, 4, ""),
    d(0x54dd, "PixelCropRight", UInt, 4, ""),
    d(DISPLAY_WIDTH, "DisplayWidth", UInt, 4, "Width to display at, in DisplayUnit"),
    d(DISPLAY_HEIGHT, "DisplayHeight", UInt, 4, "Height to display at, in DisplayUnit"),
    d(DISPLAY_UNIT, "DisplayUnit", Kind::Enum(DISPLAY_UNITS), 4, ""),
    d(0x54b3, "AspectRatioType", Kind::Enum(ASPECT_TYPES), 4, "Deprecated"),
    d(0x2eb524, "UncompressedFourCC", Binary, 4, "Pixel format of uncompressed video"),
    d(0x2fb523, "GammaValue", Float, 4, "Deprecated"),
    d(FRAME_RATE, "FrameRate", Float, 4, "Deprecated: frames per second"),
    d(COLOUR, "Colour", Master, 4, "Colour description (ITU-T H.273 code points)"),
    d(MATRIX, "MatrixCoefficients", Kind::Enum(vidutil::MATRIX_COEFFICIENTS), 5, ""),
    d(BITS_PER_CHANNEL, "BitsPerChannel", UInt, 5, ""),
    d(0x55b3, "ChromaSubsamplingHorz", UInt, 5, "log2 of the horizontal chroma subsampling (1 for 4:2:0)"),
    d(0x55b4, "ChromaSubsamplingVert", UInt, 5, "log2 of the vertical chroma subsampling (1 for 4:2:0)"),
    d(0x55b5, "CbSubsamplingHorz", UInt, 5, ""),
    d(0x55b6, "CbSubsamplingVert", UInt, 5, ""),
    d(0x55b7, "ChromaSitingHorz", Kind::Enum(SITING_HORZ), 5, ""),
    d(0x55b8, "ChromaSitingVert", Kind::Enum(SITING_VERT), 5, ""),
    d(RANGE_ID, "Range", Kind::Enum(RANGE), 5, "Colour range"),
    d(TRANSFER, "TransferCharacteristics", Kind::Enum(vidutil::TRANSFER_CHARACTERISTICS), 5, ""),
    d(PRIMARIES, "Primaries", Kind::Enum(vidutil::COLOUR_PRIMARIES), 5, ""),
    d(MAX_CLL, "MaxCLL", UInt, 5, "Maximum content light level, cd/m²"),
    d(MAX_FALL, "MaxFALL", UInt, 5, "Maximum frame-average light level, cd/m²"),
    d(MASTERING, "MasteringMetadata", Master, 5, "SMPTE 2086 mastering display colour volume"),
    d(0x55d1, "PrimaryRChromaticityX", Float, 6, "CIE 1931 x of the red primary"),
    d(0x55d2, "PrimaryRChromaticityY", Float, 6, ""),
    d(0x55d3, "PrimaryGChromaticityX", Float, 6, ""),
    d(0x55d4, "PrimaryGChromaticityY", Float, 6, ""),
    d(0x55d5, "PrimaryBChromaticityX", Float, 6, ""),
    d(0x55d6, "PrimaryBChromaticityY", Float, 6, ""),
    d(0x55d7, "WhitePointChromaticityX", Float, 6, ""),
    d(0x55d8, "WhitePointChromaticityY", Float, 6, ""),
    d(LUMINANCE_MAX, "LuminanceMax", Float, 6, "Maximum luminance, cd/m²"),
    d(LUMINANCE_MIN, "LuminanceMin", Float, 6, "Minimum luminance, cd/m²"),
    d(PROJECTION, "Projection", Master, 4, "Video projection (360° video)"),
    d(PROJECTION_TYPE, "ProjectionType", Kind::Enum(PROJECTIONS), 5, ""),
    d(0x7672, "ProjectionPrivate", Binary, 5, "Projection parameters (from the ISOBMFF equi/cbmp/mshp box)"),
    d(POSE_YAW, "ProjectionPoseYaw", Float, 5, "Degrees"),
    d(POSE_PITCH, "ProjectionPosePitch", Float, 5, "Degrees"),
    d(POSE_ROLL, "ProjectionPoseRoll", Float, 5, "Degrees"),
    d(AUDIO, "Audio", Master, 3, "Audio settings"),
    d(SAMPLING_FREQUENCY, "SamplingFrequency", Float, 4, "Hz"),
    d(OUTPUT_SAMPLING_FREQUENCY, "OutputSamplingFrequency", Float, 4, "Hz, when it differs (SBR)"),
    d(CHANNELS, "Channels", UInt, 4, ""),
    d(0x7d7b, "ChannelPositions", Binary, 4, "Deprecated"),
    d(BIT_DEPTH, "BitDepth", UInt, 4, "Bits per sample"),
    d(0x52f1, "Emphasis", Kind::Enum(EMPHASIS), 4, ""),
    d(0xe2, "TrackOperation", Master, 3, "A virtual track built from other tracks"),
    d(0xe3, "TrackCombinePlanes", Master, 4, "Video planes combined into one (stereo-3D)"),
    d(0xe4, "TrackPlane", Master, 5, ""),
    d(0xe5, "TrackPlaneUID", UInt, 6, ""),
    d(0xe6, "TrackPlaneType", Kind::Enum(PLANE_TYPES), 6, ""),
    d(0xe9, "TrackJoinBlocks", Master, 4, "Tracks whose blocks are joined"),
    d(0xed, "TrackJoinUID", UInt, 5, ""),
    d(0xc0, "TrickTrackUID", UInt, 3, "DivX trick track"),
    d(0xc1, "TrickTrackSegmentUID", Binary, 3, ""),
    d(0xc6, "TrickTrackFlag", UInt, 3, ""),
    d(0xc7, "TrickMasterTrackUID", UInt, 3, ""),
    d(0xc4, "TrickMasterTrackSegmentUID", Binary, 3, ""),
    d(CONTENT_ENCODINGS, "ContentEncodings", Master, 3, "Compression or encryption applied to the track"),
    d(CONTENT_ENCODING, "ContentEncoding", Master, 4, ""),
    d(0x5031, "ContentEncodingOrder", UInt, 5, "Order in which the encodings were applied"),
    d(CONTENT_ENCODING_SCOPE, "ContentEncodingScope", Kind::Flags(ENC_SCOPE), 5, "What the encoding applies to"),
    d(CONTENT_ENCODING_TYPE, "ContentEncodingType", Kind::Enum(ENC_TYPE), 5, ""),
    d(CONTENT_COMPRESSION, "ContentCompression", Master, 5, ""),
    d(CONTENT_COMP_ALGO, "ContentCompAlgo", Kind::Enum(COMP_ALGO), 6, ""),
    d(CONTENT_COMP_SETTINGS, "ContentCompSettings", Binary, 6, "For header stripping: the bytes removed from the start of every frame"),
    d(CONTENT_ENCRYPTION, "ContentEncryption", Master, 5, ""),
    d(CONTENT_ENC_ALGO, "ContentEncAlgo", Kind::Enum(ENC_ALGO), 6, ""),
    d(0x47e2, "ContentEncKeyID", Binary, 6, ""),
    d(0x47e7, "ContentEncAESSettings", Master, 6, ""),
    d(0x47e8, "AESSettingsCipherMode", Kind::Enum(AES_MODE), 7, ""),
    d(0x47e3, "ContentSignature", Binary, 6, "Deprecated"),
    d(0x47e4, "ContentSigKeyID", Binary, 6, "Deprecated"),
    d(0x47e5, "ContentSigAlgo", Kind::Enum(SIG_ALGO), 6, "Deprecated"),
    d(0x47e6, "ContentSigHashAlgo", Kind::Enum(SIG_HASH), 6, "Deprecated"),
    // Cues
    d(CUES, "Cues", Master, 1, "Seek index: timestamps and the clusters holding them"),
    d(CUE_POINT, "CuePoint", Master, 2, ""),
    d(CUE_TIME, "CueTime", Ticks, 3, ""),
    d(CUE_TRACK_POSITIONS, "CueTrackPositions", Master, 3, ""),
    d(CUE_TRACK, "CueTrack", UInt, 4, ""),
    d(CUE_CLUSTER_POSITION, "CueClusterPosition", Position, 4, "Position of the cluster, relative to the segment's data"),
    d(CUE_RELATIVE_POSITION, "CueRelativePosition", UInt, 4, "Position of the block, relative to the cluster's data"),
    d(0xb2, "CueDuration", Ticks, 4, ""),
    d(CUE_BLOCK_NUMBER, "CueBlockNumber", UInt, 4, "Number of the block within the cluster (from 1)"),
    d(0xea, "CueCodecState", UInt, 4, ""),
    d(0xdb, "CueReference", Master, 4, "A block the cued one depends on"),
    d(0x96, "CueRefTime", Ticks, 5, ""),
    d(0x97, "CueRefCluster", UInt, 5, "Deprecated"),
    d(0x535f, "CueRefNumber", UInt, 5, "Deprecated"),
    d(0xeb, "CueRefCodecState", UInt, 5, "Deprecated"),
    // Attachments
    d(ATTACHMENTS, "Attachments", Master, 1, "Files attached to the segment (fonts, cover art)"),
    d(ATTACHED_FILE, "AttachedFile", Master, 2, ""),
    d(FILE_DESCRIPTION, "FileDescription", Utf8, 3, ""),
    d(FILE_NAME, "FileName", Utf8, 3, ""),
    d(FILE_MEDIA_TYPE, "FileMediaType", Str, 3, ""),
    d(FILE_DATA, "FileData", Binary, 3, "The attached file"),
    d(0x46ae, "FileUID", UInt, 3, ""),
    d(0x4675, "FileReferral", Binary, 3, "Deprecated"),
    d(0x4661, "FileUsedStartTime", Ns, 3, "Deprecated (DivX)"),
    d(0x4662, "FileUsedEndTime", Ns, 3, "Deprecated (DivX)"),
    // Chapters
    d(CHAPTERS, "Chapters", Master, 1, "Chapter editions"),
    d(EDITION_ENTRY, "EditionEntry", Master, 2, "A set of chapters"),
    d(0x45bc, "EditionUID", UInt, 3, ""),
    d(EDITION_FLAG_HIDDEN, "EditionFlagHidden", Bool, 3, ""),
    d(EDITION_FLAG_DEFAULT, "EditionFlagDefault", Bool, 3, ""),
    d(EDITION_FLAG_ORDERED, "EditionFlagOrdered", Bool, 3, "Chapters define the playback order (ordered chapters)"),
    d(EDITION_DISPLAY, "EditionDisplay", Master, 3, ""),
    d(EDITION_STRING, "EditionString", Utf8, 4, ""),
    d(0x45e4, "EditionLanguageIETF", Str, 4, ""),
    d(CHAPTER_ATOM, "ChapterAtom", Master, 3, "A chapter (may contain sub-chapters)"),
    d(0x73c4, "ChapterUID", UInt, 4, ""),
    d(0x5654, "ChapterStringUID", Utf8, 4, "WebVTT cue identifier"),
    d(CHAPTER_TIME_START, "ChapterTimeStart", Ns, 4, "Start, in nanoseconds (not ticks)"),
    d(CHAPTER_TIME_END, "ChapterTimeEnd", Ns, 4, "End, in nanoseconds (not ticks)"),
    d(CHAPTER_FLAG_HIDDEN, "ChapterFlagHidden", Bool, 4, ""),
    d(0x4598, "ChapterFlagEnabled", Bool, 4, ""),
    d(0x6e67, "ChapterSegmentUUID", Binary, 4, "Segment to play for this chapter (ordered chapters)"),
    d(0x4588, "ChapterSkipType", Kind::Enum(SKIP_TYPES), 4, ""),
    d(0x6ebc, "ChapterSegmentEditionUID", UInt, 4, ""),
    d(0x63c3, "ChapterPhysicalEquiv", UInt, 4, "Physical equivalent (60 = disc side, 20 = track, ...)"),
    d(0x8f, "ChapterTrack", Master, 4, "Tracks the chapter applies to"),
    d(0x89, "ChapterTrackUID", UInt, 5, ""),
    d(CHAPTER_DISPLAY, "ChapterDisplay", Master, 4, "A title of the chapter in one language"),
    d(CHAP_STRING, "ChapString", Utf8, 5, ""),
    d(CHAP_LANGUAGE, "ChapLanguage", Str, 5, "ISO 639-2 language code"),
    d(CHAP_LANGUAGE_BCP47, "ChapLanguageBCP47", Str, 5, ""),
    d(0x437e, "ChapCountry", Str, 5, ""),
    d(0x6944, "ChapProcess", Master, 4, "Commands for a chapter codec (menus)"),
    d(0x6955, "ChapProcessCodecID", Kind::Enum(TRANSLATE_CODECS), 5, ""),
    d(0x450d, "ChapProcessPrivate", Binary, 5, ""),
    d(0x6911, "ChapProcessCommand", Master, 5, ""),
    d(0x6922, "ChapProcessTime", Kind::Enum(PROCESS_TIMES), 6, ""),
    d(0x6933, "ChapProcessData", Binary, 6, ""),
    // Tags
    d(TAGS, "Tags", Master, 1, "Metadata"),
    d(TAG, "Tag", Master, 2, "Tags for one target"),
    d(TARGETS, "Targets", Master, 3, "What the tags apply to (empty: the whole segment)"),
    d(TARGET_TYPE_VALUE, "TargetTypeValue", Kind::Enum(TARGET_TYPES), 4, "Logical level of the target"),
    d(TARGET_TYPE, "TargetType", Str, 4, ""),
    d(TAG_TRACK_UID, "TagTrackUID", UInt, 4, ""),
    d(TAG_EDITION_UID, "TagEditionUID", UInt, 4, ""),
    d(TAG_CHAPTER_UID, "TagChapterUID", UInt, 4, ""),
    d(TAG_ATTACHMENT_UID, "TagAttachmentUID", UInt, 4, ""),
    d(SIMPLE_TAG, "SimpleTag", Master, 3, "A name and value (may contain nested tags)"),
    d(TAG_NAME, "TagName", Utf8, 4, ""),
    d(0x447a, "TagLanguage", Str, 4, ""),
    d(0x447b, "TagLanguageBCP47", Str, 4, ""),
    d(0x4484, "TagDefault", Bool, 4, "Whether this is the default language for the tag"),
    d(0x44b4, "TagDefaultBogus", Bool, 4, "TagDefault with a wrong ID, written by old muxers"),
    d(TAG_STRING, "TagString", Utf8, 4, ""),
    d(TAG_BINARY, "TagBinary", Binary, 4, ""),
];

fn lookup(id: u32) -> Option<&'static Def> {
    SCHEMA.iter().find(|d| d.id == id)
}

fn name_of(id: u32) -> String {
    lookup(id).map_or_else(|| format!("Unknown {id:#x}"), |d| d.name.to_owned())
}

/// Human-readable codec name for a Matroska CodecID.
pub fn codec_name(id: &str) -> &str {
    match id {
        "V_MPEG4/ISO/AVC" => "H.264",
        "V_MPEGH/ISO/HEVC" => "HEVC",
        "V_MPEGI/ISO/VVC" => "VVC",
        "V_AV1" => "AV1",
        "V_VP8" => "VP8",
        "V_VP9" => "VP9",
        "V_THEORA" => "Theora",
        "V_DIRAC" => "Dirac",
        "V_MPEG1" => "MPEG-1 video",
        "V_MPEG2" => "MPEG-2 video",
        "V_MPEG4/ISO/ASP" | "V_MPEG4/ISO/SP" | "V_MPEG4/ISO/AP" => "MPEG-4 Visual",
        "V_MPEG4/MS/V3" => "MS MPEG-4 v3",
        "V_MS/VFW/FOURCC" => "VfW",
        "V_QUICKTIME" => "QuickTime video",
        "V_PRORES" => "ProRes",
        "V_FFV1" => "FFV1",
        "V_MJPEG" => "Motion JPEG",
        "V_UNCOMPRESSED" => "uncompressed video",
        "V_REAL/RV10" | "V_REAL/RV20" | "V_REAL/RV30" | "V_REAL/RV40" => "RealVideo",
        "A_OPUS" => "Opus",
        "A_VORBIS" => "Vorbis",
        "A_AAC" | "A_AAC/MPEG4/LC" | "A_AAC/MPEG2/LC" | "A_AAC/MPEG4/MAIN" | "A_AAC/MPEG2/MAIN"
        | "A_AAC/MPEG4/LC/SBR" | "A_AAC/MPEG2/LC/SBR" | "A_AAC/MPEG4/SSR" | "A_AAC/MPEG4/LTP" => {
            "AAC"
        }
        "A_FLAC" => "FLAC",
        "A_MPEG/L3" => "MP3",
        "A_MPEG/L2" => "MP2",
        "A_MPEG/L1" => "MP1",
        "A_AC3" | "A_AC3/BSID9" | "A_AC3/BSID10" => "AC-3",
        "A_EAC3" => "E-AC-3",
        "A_AC4" => "AC-4",
        "A_DTS" | "A_DTS/EXPRESS" | "A_DTS/LOSSLESS" => "DTS",
        "A_TRUEHD" | "A_MLP" => "TrueHD",
        "A_ALAC" => "ALAC",
        "A_TTA1" => "TTA",
        "A_WAVPACK4" => "WavPack",
        "A_MS/ACM" => "ACM",
        "A_QUICKTIME" | "A_QUICKTIME/QDMC" | "A_QUICKTIME/QDM2" => "QuickTime audio",
        "A_PCM/INT/LIT" | "A_PCM/INT/BIG" | "A_PCM/FLOAT/IEEE" => "PCM",
        "A_REAL/14_4" | "A_REAL/28_8" | "A_REAL/COOK" | "A_REAL/SIPR" | "A_REAL/RALF"
        | "A_REAL/ATRC" => "RealAudio",
        "S_TEXT/UTF8" | "S_TEXT/ASCII" => "SRT",
        "S_TEXT/ASS" | "S_TEXT/SSA" | "S_ASS" | "S_SSA" => "ASS",
        "S_TEXT/WEBVTT" => "WebVTT",
        "S_TEXT/USF" => "USF",
        "S_HDMV/PGS" => "PGS",
        "S_HDMV/TEXTST" => "HDMV text",
        "S_VOBSUB" => "VobSub",
        "S_DVBSUB" => "DVB subtitles",
        "S_KATE" => "Kate",
        "S_IMAGE/BMP" => "BMP subtitles",
        "S_ARIBSUB" => "ARIB subtitles",
        "B_VOBBTN" => "VobBtn",
        other => other,
    }
}

/// The codecs whose private data or frames we decode.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Codec {
    #[default]
    Other,
    Avc,
    Hevc,
    Av1,
    Vp9,
    /// Xiph-laced setup headers: Vorbis, Theora, Kate.
    Xiph,
    Opus,
    Flac,
    Aac,
    Vfw,
    Acm,
    Alac,
    Mjpeg,
    /// Text subtitles: text private data and text frames.
    Text,
    /// Binary subtitles with a text private header (VobSub).
    TextHeader,
}

fn codec_of(id: &str) -> Codec {
    match id {
        "V_MPEG4/ISO/AVC" => Codec::Avc,
        "V_MPEGH/ISO/HEVC" => Codec::Hevc,
        "V_AV1" => Codec::Av1,
        "V_VP9" => Codec::Vp9,
        "A_VORBIS" | "V_THEORA" | "S_KATE" => Codec::Xiph,
        "A_OPUS" => Codec::Opus,
        "A_FLAC" => Codec::Flac,
        "V_MS/VFW/FOURCC" => Codec::Vfw,
        "A_MS/ACM" => Codec::Acm,
        "A_ALAC" => Codec::Alac,
        "V_MJPEG" => Codec::Mjpeg,
        "S_VOBSUB" => Codec::TextHeader,
        _ if id.starts_with("A_AAC") => Codec::Aac,
        _ if id.starts_with("S_TEXT/") || id == "S_SSA" || id == "S_ASS" => Codec::Text,
        _ => Codec::Other,
    }
}

// ---------------------------------------------------------------------------
// Walking

/// What an element inherits from its ancestors.
#[derive(Clone, Copy, Debug)]
struct Ctx {
    /// TimestampScale of the segment (ns per tick).
    scale: u64,
    /// The segment's data, which positions are relative to.
    segment: Option<Span>,
    /// The enclosing cluster's timestamp, in ticks.
    cluster: Option<u64>,
    /// The enclosing track's codec.
    codec: Codec,
}

const ROOT: Ctx = Ctx {
    scale: DEFAULT_SCALE,
    segment: None,
    cluster: None,
    codec: Codec::Other,
};

#[derive(Clone, Copy, Debug)]
struct Element {
    input: Input,
    span: Span,
    id: u32,
    header_len: u64,
    depth: u32,
    ctx: Ctx,
}

impl Element {
    fn data(&self) -> Span {
        self.span.tail(self.header_len)
    }
    fn def(&self) -> Option<&'static Def> {
        lookup(self.id)
    }
}

const MAX_DEPTH: u32 = 32;
const DEFAULT_SCALE: u64 = 1_000_000;
/// Parents up to this size have their CRC-32 checked when listed.
const CRC_LIMIT: u64 = 0x40000;

struct RawHeader {
    id: u32,
    header_len: u64,
    size: Option<u64>,
}

async fn read_header(cx: &Cx, region: Span, pos: u64) -> Result<RawHeader> {
    let d = cx.read_avail(region.sub(pos, 12)).await?;
    let bad = || Diagnostic::malformed("invalid EBML element header").at(region.sub(pos, 12));
    let (id, id_len) = element_id(&d).ok_or_else(bad)?;
    let (size, size_len) = vint(d.get(id_len..).unwrap_or_default()).ok_or_else(bad)?;
    Ok(RawHeader {
        id,
        header_len: to_u64(id_len.saturating_add(size_len)),
        size,
    })
}

/// Where an element of unknown size ends: at the first element of the same
/// or a higher level, or at the end of the region.
async fn unknown_end(cx: &Cx, region: Span, data_start: u64, level: u8) -> Result<u64> {
    let mut pos = data_start;
    while pos < region.len {
        let Ok(h) = read_header(cx, region, pos).await else {
            return Ok(region.len);
        };
        if let Some(def) = lookup(h.id)
            && def.level <= level
        {
            return Ok(pos);
        }
        let Some(size) = h.size else {
            return Ok(region.len);
        };
        pos = pos.saturating_add(h.header_len).saturating_add(size);
        cx.checkpoint().await;
    }
    Ok(region.len)
}

/// Lists the elements in `region`.
async fn elements(
    cx: &Cx,
    input: Input,
    region: Span,
    depth: u32,
    ctx: Ctx,
    tracks: Option<&[TrackBrief]>,
) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(
            Diagnostic::limit(format!("elements nested deeper than {MAX_DEPTH}")).at(region),
        );
    }
    let mut pos = 0u64;
    while pos < region.len {
        let h = match read_header(cx, region, pos).await {
            Ok(h) => h,
            Err(e) => {
                cx.emit(Node::new("Invalid data").span(region.tail(pos)).diag(e));
                break;
            }
        };
        let data_start = pos.saturating_add(h.header_len);
        let level = lookup(h.id).map_or(255, |d| d.level);
        let data_len = match h.size {
            Some(n) => n,
            // Only another EBML document (a chained stream) may follow a
            // segment; running to the end saves walking the whole file.
            None if h.id == SEGMENT => region.len.saturating_sub(data_start),
            None => unknown_end(cx, region, data_start, level)
                .await?
                .saturating_sub(data_start),
        };
        let total = h.header_len.saturating_add(data_len);
        let el = Element {
            input,
            span: region.sub(pos, total),
            id: h.id,
            header_len: h.header_len,
            depth,
            ctx,
        };
        let mut node = element_node(cx, &el, tracks).await?;
        if h.id == CRC32 {
            node = check_crc(cx, node, &el, region, pos).await;
        }
        if el.span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(el.span.source, el.span.offset, total),
                el.span.len,
            ));
        }
        if h.size.is_none() {
            let note = "Unknown size: ends where an element of the same or a higher level begins";
            node = match el.def().map(|d| d.desc).filter(|d| !d.is_empty()) {
                Some(desc) => node.desc(format!("{desc}. {note}")),
                None => node.desc(note),
            };
        }
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(total.max(1));
    }
    Ok(())
}

/// Checks a CRC-32 element against the rest of its parent's data.
async fn check_crc(cx: &Cx, node: Node, el: &Element, region: Span, pos: u64) -> Node {
    let data = el.data();
    let raw = match cx.read_avail(data.sub(0, 4)).await {
        Ok(r) => r,
        Err(e) => return node.diag(e),
    };
    let Some(stored) = u32_le(&raw, 0).filter(|_| data.len == 4) else {
        return node.diag(Diagnostic::malformed("a CRC-32 element holds 4 bytes").at(data));
    };
    let node = node.value(Value::UInt {
        value: stored.into(),
        bits: 32,
        radix: Radix::Hex,
    });
    let before = region.sub(0, pos);
    let after = region.tail(pos.saturating_add(el.span.len));
    let covered = before.len.saturating_add(after.len);
    if covered > CRC_LIMIT {
        return node.summary(format!("not checked: covers {covered} bytes"));
    }
    let mut crc = 0xffff_ffffu32;
    for part in [before, after] {
        let Ok(bytes) = cx.read_avail(part).await else {
            return node;
        };
        crate::formats::util::datakit::feed_paced(cx, &bytes, |piece| {
            crc = crate::codec::crc::crc32_update(crc, piece);
        })
        .await;
    }
    let crc = crc ^ 0xffff_ffff;
    if crc == stored {
        node.summary("matches")
    } else {
        node.summary("mismatch").diag(
            Diagnostic::warning(format!(
                "CRC-32 mismatch: stored {stored:#010x}, computed {crc:#010x}"
            ))
            .at(data),
        )
    }
}

/// The node for one element: a value for leaves, a lazy expander for
/// masters and blocks.
async fn element_node(cx: &Cx, el: &Element, tracks: Option<&[TrackBrief]>) -> Result<Node> {
    let data = el.data();
    let Some(def) = el.def() else {
        let node = Node::new(name_of(el.id))
            .span(el.span)
            .summary(format!("{} bytes", data.len))
            .value(Value::UInt {
                value: el.id.into(),
                bits: 32,
                radix: Radix::Hex,
            });
        return Ok(node);
    };
    let mut node = Node::new(def.name).span(el.span);
    if !def.desc.is_empty() {
        node = node.desc(def.desc);
    }
    Ok(match def.kind {
        Master => {
            let summary = master_summary(cx, el, tracks).await;
            let node = node.lazy(crate::expander!(self::master: Element), *el);
            match summary {
                Some(s) => node.summary(s),
                None => node,
            }
        }
        Block => {
            let head = cx.read_avail(data.sub(0, 16)).await?;
            let node = node.lazy(block, *el);
            match block_head(&head) {
                Some(h) => node.summary(block_summary(&h, el, data.len, tracks)),
                None => node,
            }
        }
        Binary => binary_node(cx, el, node).await?,
        Position => {
            let d = cx.read_avail(data.sub(0, 8)).await?;
            let v = be_uint(&d);
            let node = node.value(Value::UInt {
                value: v,
                bits: 64,
                radix: Radix::Hex,
            });
            match el.ctx.segment {
                Some(seg) => match read_header(cx, seg, v).await {
                    Ok(h) if v < seg.len => {
                        let len = h.size.map_or(seg.len.saturating_sub(v), |s| {
                            h.header_len.saturating_add(s)
                        });
                        node.target(seg.sub(v, len)).summary(format!(
                            "{} at {:#x}",
                            name_of(h.id),
                            seg.offset.saturating_add(v)
                        ))
                    }
                    _ => node.diag(Diagnostic::warning("position outside the segment")),
                },
                None => node,
            }
        }
        kind => {
            let d = cx.read_avail(data.sub(0, 0x1000)).await?;
            let node = leaf(node, kind, &d, el);
            if matches!(kind, UInt | Int | Bool | Ns | SNs | Ticks | STicks) && data.len > 8 {
                node.diag(Diagnostic::malformed("integer longer than 8 bytes").at(data))
            } else {
                node
            }
        }
    })
}

/// Binary elements: attachments, codec private data, IDs, padding.
async fn binary_node(cx: &Cx, el: &Element, node: Node) -> Result<Node> {
    let data = el.data();
    Ok(match el.id {
        FILE_DATA => {
            let mut n =
                embedded("FileData", el.input.nested(data)).summary(format!("{} bytes", data.len));
            if let Some(desc) = node.description {
                n = n.desc(desc);
            }
            n
        }
        VOID => node.summary(format!("{} bytes", data.len)),
        CODEC_PRIVATE => {
            let head = vidutil::read_small(cx, data, 0x1000).await?;
            let summary = private_summary(el.ctx.codec, &head)
                .unwrap_or_else(|| format!("{} bytes", data.len));
            let node = node.summary(summary);
            if el.ctx.codec != Codec::Other {
                node.lazy(codec_private, *el)
            } else if data.len <= 32 {
                node.value(Value::Bytes(head))
            } else {
                node.lazy(private_bytes, *el)
            }
        }
        _ if data.len <= 32 => {
            let d = cx.read_avail(data).await?;
            let summary = match el.id {
                SEEK_ID => Some(name_of(u32::try_from(be_uint(&d)).unwrap_or(0))),
                0x73a4 | 0x3cb923 | 0x3eb923 | 0x4444 | 0x6e67 if d.len() == 16 => {
                    Some(vidutil::uuid(&d))
                }
                0x2eb524 if d.len() == 4 => Some(vidutil::fourcc(&d)),
                _ => None,
            };
            let node = node.value(Value::Bytes(d));
            match summary {
                Some(s) => node.summary(s),
                None => node,
            }
        }
        _ => node.summary(format!("{} bytes", data.len)),
    })
}

fn signed_seconds(s: f64) -> String {
    if s < 0.0 {
        format!("-{}", seconds_f64(-s))
    } else {
        seconds_f64(s)
    }
}

fn leaf(node: Node, kind: Kind, d: &[u8], el: &Element) -> Node {
    let uint_value = |v: u64| Value::UInt {
        value: v,
        bits: 64,
        radix: Radix::Dec,
    };
    match kind {
        Kind::UInt => {
            let v = be_uint(d);
            let node = node.value(uint_value(v));
            match el.id {
                TIMESTAMP_SCALE => node.summary(if v.is_multiple_of(1_000_000) {
                    format!("{} ms per tick", v / 1_000_000)
                } else {
                    format!("{v} ns per tick")
                }),
                BLOCK_ADD_ID_TYPE if v > 0xffff => node.summary(vidutil::fourcc(
                    &u32::try_from(v).unwrap_or(0).to_be_bytes(),
                )),
                _ => node,
            }
        }
        Kind::Bool => node.value(Value::Bool(be_uint(d) != 0)),
        Kind::Enum(table) => {
            let v = be_uint(d);
            node.value(Value::Enum {
                raw: v,
                bits: 64,
                name: crate::value::lookup(table, v),
            })
        }
        Kind::Flags(table) => {
            let v = be_uint(d);
            let (set, unknown) = crate::value::decode_flags(table, v);
            node.value(Value::Flags {
                raw: v,
                bits: 8,
                set,
                unknown,
            })
        }
        Kind::Int => node.value(Value::Int {
            value: be_int(d),
            bits: 64,
        }),
        Kind::Float => match be_float(d) {
            Some(f) => {
                let node = node.value(Value::Float(f));
                match el.id {
                    DURATION => node.summary(seconds_f64(f * el.ctx.scale as f64 / 1e9)),
                    SAMPLING_FREQUENCY | OUTPUT_SAMPLING_FREQUENCY => node.summary(sound::hz(f)),
                    LUMINANCE_MAX | LUMINANCE_MIN => {
                        node.summary(format!("{} cd/m²", vidutil::num(f)))
                    }
                    FRAME_RATE => node.summary(format!("{} fps", vidutil::num(f))),
                    POSE_YAW | POSE_PITCH | POSE_ROLL => {
                        node.summary(format!("{}°", vidutil::num(f)))
                    }
                    _ => node,
                }
            }
            None => node.diag(Diagnostic::malformed("float of invalid size")),
        },
        Kind::Str | Kind::Utf8 => node.value(Value::Text(text(d))),
        Kind::Date => {
            let ns = be_int(d);
            node.value(Value::Timestamp {
                unix_seconds: ns
                    .checked_div_euclid(1_000_000_000)
                    .unwrap_or(0)
                    .saturating_add(978_307_200),
            })
        }
        Kind::Ns => {
            let v = be_uint(d);
            let node = node.value(uint_value(v));
            match el.id {
                DEFAULT_DURATION | DEFAULT_FIELD_DURATION if v > 0 => node.summary(format!(
                    "{} ms, {} fps",
                    vidutil::num(v as f64 / 1e6),
                    vidutil::num(1e9 / v as f64)
                )),
                CODEC_DELAY | SEEK_PRE_ROLL => {
                    node.summary(format!("{} ms", vidutil::num(v as f64 / 1e6)))
                }
                _ => node.summary(seconds_f64(v as f64 / 1e9)),
            }
        }
        Kind::SNs => {
            let v = be_int(d);
            node.value(Value::Int { value: v, bits: 64 })
                .summary(format!("{} ms", vidutil::num(v as f64 / 1e6)))
        }
        Kind::Ticks => {
            let v = be_uint(d);
            node.value(uint_value(v))
                .summary(seconds_f64(ticks(v, el.ctx.scale)))
        }
        Kind::STicks => {
            let v = be_int(d);
            node.value(Value::Int { value: v, bits: 64 })
                .summary(signed_seconds(v as f64 * el.ctx.scale as f64 / 1e9))
        }
        _ => node,
    }
}

/// Seconds for `v` ticks of `scale` nanoseconds.
fn ticks(v: u64, scale: u64) -> f64 {
    v as f64 * scale as f64 / 1e9
}

async fn master(cx: Cx, el: Element) -> Result<()> {
    let mut ctx = el.ctx;
    let data = el.data();
    let mut tracks = None;
    match el.id {
        SEGMENT => {
            ctx.scale = segment_scale(&cx, data).await.unwrap_or(DEFAULT_SCALE);
            ctx.segment = Some(data);
            ctx.cluster = None;
        }
        TRACK_ENTRY => {
            let d = vidutil::read_small(&cx, data, 0x10000).await?;
            ctx.codec = child_text(&d, CODEC_ID).map_or(Codec::Other, |id| codec_of(&id));
        }
        CLUSTER => {
            let d = vidutil::read_small(&cx, data, 0x100).await?;
            ctx.cluster = child_uint(&d, TIMESTAMP);
            if let Some(seg) = ctx.segment {
                tracks = Some(track_table(&cx, seg).await);
            }
        }
        BLOCK_GROUP => {
            if let Some(seg) = ctx.segment {
                tracks = Some(track_table(&cx, seg).await);
            }
        }
        _ => {}
    }
    elements(
        &cx,
        el.input,
        data,
        el.depth.saturating_add(1),
        ctx,
        tracks.as_deref().map(Vec::as_slice),
    )
    .await
}

/// The TimestampScale from the segment's Info element.
async fn segment_scale(cx: &Cx, segment: Span) -> Option<u64> {
    let top = top_level(cx, segment).await.ok()?;
    let info = top.iter().find(|(id, _)| *id == INFO)?;
    let d = vidutil::read_small(cx, info.1, 0x10000).await.ok()?;
    child_uint(&d, TIMESTAMP_SCALE).filter(|&s| s > 0)
}

/// The top-level elements of `segment` (id, data span) that precede the
/// first cluster, plus those the SeekHead points to further on.
async fn top_level(cx: &Cx, segment: Span) -> Result<Vec<(u32, Span)>> {
    let mut out: Vec<(u32, Span)> = Vec::new();
    let mut pos = 0u64;
    while pos < segment.len && out.len() < 64 {
        let h = read_header(cx, segment, pos).await?;
        let Some(size) = h.size else {
            break;
        };
        if h.id == CLUSTER {
            break;
        }
        out.push((h.id, segment.sub(pos.saturating_add(h.header_len), size)));
        pos = pos.saturating_add(h.header_len).saturating_add(size);
    }
    let heads: Vec<Span> = out
        .iter()
        .filter(|(id, _)| *id == SEEK_HEAD)
        .map(|(_, s)| *s)
        .take(2)
        .collect();
    for head in heads {
        let d = vidutil::read_small(cx, head, 0x10000).await?;
        for (id, seek) in mem_children(&d).take(64) {
            if id != SEEK {
                continue;
            }
            let (Some(target), Some(at)) = (
                child(seek, SEEK_ID).map(|v| u32::try_from(be_uint(v)).unwrap_or(0)),
                child_uint(seek, SEEK_POSITION),
            ) else {
                continue;
            };
            if target == CLUSTER || at >= segment.len || out.iter().any(|(i, _)| *i == target) {
                continue;
            }
            let Ok(h) = read_header(cx, segment, at).await else {
                continue;
            };
            if let (true, Some(size)) = (h.id == target, h.size) {
                out.push((target, segment.sub(at.saturating_add(h.header_len), size)));
            }
        }
    }
    Ok(out)
}

/// The number of children of `region` with the given ID (walking at most
/// 4096 headers).
async fn count_children(cx: &Cx, region: Span, id: u32) -> usize {
    let mut pos = 0u64;
    let mut n = 0usize;
    for _ in 0..4096 {
        if pos >= region.len {
            break;
        }
        let Ok(h) = read_header(cx, region, pos).await else {
            break;
        };
        let Some(size) = h.size else {
            break;
        };
        if h.id == id {
            n = n.saturating_add(1);
        }
        pos = pos.saturating_add(h.header_len).saturating_add(size);
    }
    n
}

// ---------------------------------------------------------------------------
// Tracks

/// What blocks need to know about their track.
#[derive(Clone, Debug, Default)]
struct TrackBrief {
    number: u64,
    codec_id: String,
    codec: Codec,
    /// Header-stripping bytes removed from every frame.
    stripped: Option<Vec<u8>>,
    /// Frames are zlib-compressed.
    zlib: bool,
}

const MAX_TRACKS: usize = 128;

/// The segment's tracks, parsed once and cached.
async fn track_table(cx: &Cx, segment: Span) -> Arc<Vec<TrackBrief>> {
    if let Some(t) = cx.cached::<Vec<TrackBrief>>(segment, "mkv-tracks") {
        return t;
    }
    let mut out = Vec::new();
    if let Ok(top) = top_level(cx, segment).await
        && let Some((_, span)) = top.iter().find(|(id, _)| *id == TRACKS)
        && let Ok(d) = vidutil::read_small(cx, *span, 0x100000).await
    {
        for (_, entry) in mem_children(&d)
            .filter(|(id, _)| *id == TRACK_ENTRY)
            .take(MAX_TRACKS)
        {
            out.push(track_brief(entry));
        }
    }
    let t = Arc::new(out);
    cx.cache(segment, "mkv-tracks", t.clone());
    t
}

fn track_brief(d: &[u8]) -> TrackBrief {
    let mut t = TrackBrief::default();
    for (id, v) in mem_children(d) {
        match id {
            TRACK_NUMBER => t.number = be_uint(v),
            CODEC_ID => {
                t.codec_id = text(v);
                t.codec = codec_of(&t.codec_id);
            }
            CONTENT_ENCODINGS => {
                for (_, enc) in mem_children(v).filter(|(i, _)| *i == CONTENT_ENCODING) {
                    let scope = child_uint(enc, CONTENT_ENCODING_SCOPE).unwrap_or(1);
                    let kind = child_uint(enc, CONTENT_ENCODING_TYPE).unwrap_or(0);
                    let Some(comp) = child(enc, CONTENT_COMPRESSION) else {
                        continue;
                    };
                    if scope & 1 == 0 || kind != 0 {
                        continue;
                    }
                    match child_uint(comp, CONTENT_COMP_ALGO).unwrap_or(0) {
                        0 => t.zlib = true,
                        3 => {
                            t.stripped = child(comp, CONTENT_COMP_SETTINGS)
                                .map(|s| s.iter().take(256).copied().collect());
                        }
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    t
}

impl TrackBrief {
    fn label(&self) -> String {
        format!("{} ({})", self.number, codec_name(&self.codec_id))
    }
}

fn find_track(tracks: Option<&[TrackBrief]>, number: u64) -> Option<&TrackBrief> {
    tracks?.iter().find(|t| t.number == number)
}

/// Everything a TrackEntry summary shows.
#[derive(Debug, Default)]
struct TrackSummary {
    number: u64,
    kind: u64,
    codec: String,
    name: Option<String>,
    language: Option<String>,
    width: u64,
    height: u64,
    display: Option<(u64, u64, u64)>,
    stereo: u64,
    fps: Option<f64>,
    channels: u64,
    rate: f64,
    bits: u64,
    forced: bool,
    private: Vec<u8>,
}

fn track_summary(d: &[u8]) -> TrackSummary {
    let mut t = TrackSummary::default();
    for (id, v) in mem_children(d) {
        match id {
            TRACK_NUMBER => t.number = be_uint(v),
            TRACK_TYPE => t.kind = be_uint(v),
            CODEC_ID => t.codec = text(v),
            NAME => t.name = Some(text(v)),
            LANGUAGE if t.language.is_none() => t.language = Some(text(v)),
            LANGUAGE_BCP47 => t.language = Some(text(v)),
            FLAG_FORCED => t.forced = be_uint(v) != 0,
            DEFAULT_DURATION => {
                let ns = be_uint(v);
                if ns > 0 {
                    t.fps = Some(1e9 / ns as f64);
                }
            }
            CODEC_PRIVATE => t.private = v.get(..v.len().min(512)).unwrap_or_default().to_vec(),
            VIDEO => {
                let mut dw = None;
                let mut dh = None;
                let mut unit = 0;
                for (i, w) in mem_children(v) {
                    match i {
                        PIXEL_WIDTH => t.width = be_uint(w),
                        PIXEL_HEIGHT => t.height = be_uint(w),
                        DISPLAY_WIDTH => dw = Some(be_uint(w)),
                        DISPLAY_HEIGHT => dh = Some(be_uint(w)),
                        DISPLAY_UNIT => unit = be_uint(w),
                        STEREO_MODE => t.stereo = be_uint(w),
                        _ => {}
                    }
                }
                if dw.is_some() || dh.is_some() {
                    t.display = Some((dw.unwrap_or(t.width), dh.unwrap_or(t.height), unit));
                }
            }
            AUDIO => {
                t.rate = 8000.0;
                t.channels = 1;
                for (i, w) in mem_children(v) {
                    match i {
                        SAMPLING_FREQUENCY => t.rate = be_float(w).unwrap_or(0.0),
                        CHANNELS => t.channels = be_uint(w),
                        BIT_DEPTH => t.bits = be_uint(w),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    t
}

/// "mono", "stereo", "5.1", "3 ch".
fn channel_word(n: u64) -> String {
    match n {
        1 => "mono".to_owned(),
        2 => "stereo".to_owned(),
        6 => "5.1".to_owned(),
        8 => "7.1".to_owned(),
        n => format!("{n} ch"),
    }
}

/// "48 kHz", "44.1 kHz".
fn khz(rate: f64) -> String {
    format!("{} kHz", rate / 1000.0)
}

impl TrackSummary {
    fn codec_detail(&self) -> String {
        let name = codec_name(&self.codec);
        // Only where the private data says more than the track's own
        // elements (profile, level, the real codec of VfW/ACM).
        let codec = codec_of(&self.codec);
        let p = &self.private;
        let detail = match codec {
            // Profile, level and format: the track gives size and rate.
            Codec::Avc => {
                let (h, s, _) = nal::avcc_config(p, detached(p.len()), false);
                s.map(|s| format!("{}, {}", s.profile_level(), s.format()))
                    .or_else(|| h.map(|h| h.describe()))
            }
            Codec::Hevc => {
                let (h, s, _) = nal::hvcc_config(p, detached(p.len()), false);
                s.map(|s| format!("{}, {}", s.profile_level(), s.format()))
                    .or_else(|| h.map(|h| h.describe()))
            }
            Codec::Av1 | Codec::Vp9 | Codec::Aac | Codec::Vfw | Codec::Acm => {
                private_summary(codec, p)
            }
            _ => None,
        };
        match detail {
            Some(d) => format!("{name} ({d})"),
            None => name.to_owned(),
        }
    }

    /// The frame rate an H.264/HEVC SPS declares in its VUI timing, for
    /// tracks without a DefaultDuration.
    fn bitstream_rate(&self) -> Option<(u64, u64)> {
        let p = &self.private;
        let sps = match codec_of(&self.codec) {
            Codec::Avc => nal::avcc(p, detached(p.len()), false).0,
            Codec::Hevc => nal::hvcc(p, detached(p.len()), false).0,
            _ => None,
        };
        sps?.frame_rate
    }

    fn display_note(&self) -> Option<String> {
        let (w, h, unit) = self.display?;
        if (w, h) == (self.width, self.height) && unit == 0 {
            return None;
        }
        Some(match unit {
            0 => format!("display {w}×{h}"),
            3 => format!("display aspect {w}:{h}"),
            _ => format!(
                "display {w}×{h} {}",
                crate::value::lookup(DISPLAY_UNITS, unit).unwrap_or("units")
            ),
        })
    }

    /// "#1 video: H.264 (High@L4.0, 1920×1080), 1920×1080, 25 fps, eng".
    fn describe(&self) -> String {
        let kind = crate::value::lookup(TRACK_TYPES, self.kind).unwrap_or("track");
        let mut s = format!("#{} {kind}: {}", self.number, self.codec_detail());
        if self.width > 0 {
            s.push_str(&format!(", {}×{}", self.width, self.height));
            if let Some(d) = self.display_note() {
                s.push_str(&format!(" ({d})"));
            }
        }
        if self.kind == 1 {
            if let Some(fps) = self.fps {
                s.push_str(&format!(", {} fps", vidutil::num(fps)));
            } else if let Some((n, d)) = self.bitstream_rate() {
                s.push_str(&format!(
                    ", {} fps (from the SPS)",
                    vidutil::tables::rate(n, d)
                ));
            }
        }
        if self.stereo != 0 {
            s.push_str(&format!(", {}", vidutil::lookup_or(STEREO, self.stereo)));
        }
        if self.kind == 2 {
            s.push_str(&format!(
                ", {}, {}",
                channel_word(self.channels),
                sound::hz(self.rate)
            ));
            if self.bits > 0 {
                s.push_str(&format!(", {}-bit", self.bits));
            }
        }
        if let Some(l) = &self.language {
            s.push_str(&format!(", {l}"));
        }
        if let Some(n) = self.name.as_ref().filter(|n| !n.is_empty()) {
            s.push_str(&format!(", \"{n}\""));
        }
        if self.forced {
            s.push_str(", forced");
        }
        s
    }

    /// "VP9 1280×720", "Opus stereo 48 kHz", "SRT subtitles".
    fn short(&self) -> String {
        let real = match codec_of(&self.codec) {
            Codec::Vfw => self
                .private
                .get(16..20)
                .map(crate::formats::video::asf::compression_name),
            Codec::Acm => {
                acm_tag(&self.private).map(|t| vidutil::lookup_or(wav::FORMAT_TAG, t.into()))
            }
            _ => None,
        };
        let name = real.as_deref().unwrap_or(codec_name(&self.codec));
        match self.kind {
            1 if self.width > 0 => format!("{name} {}×{}", self.width, self.height),
            2 => format!("{name} {} {}", channel_word(self.channels), khz(self.rate)),
            0x11 => format!("{name} subtitles"),
            _ => name.to_owned(),
        }
    }
}

// ---------------------------------------------------------------------------
// Master summaries

async fn master_summary(cx: &Cx, el: &Element, tracks: Option<&[TrackBrief]>) -> Option<String> {
    let data = el.data();
    let window = match el.id {
        BLOCK_GROUP => return group_summary(cx, el, tracks).await,
        TRACK_ENTRY | TRACKS | INFO | CHAPTERS | EDITION_ENTRY | TAGS | TAG | SEEK_HEAD
        | ATTACHMENTS => 0x10000,
        CLUSTER => 0x100,
        SEGMENT | CUES => return None,
        _ => 0x1000,
    };
    let d = vidutil::read_small(cx, data, window).await.ok()?;
    let count = |id: u32| mem_children(&d).filter(|(i, _)| *i == id).count();
    match el.id {
        EBML => {
            let doc = child_text(&d, DOC_TYPE)?;
            let version = child_uint(&d, DOC_TYPE_VERSION).unwrap_or(1);
            let read = child_uint(&d, DOC_TYPE_READ_VERSION).unwrap_or(1);
            Some(format!("{doc} v{version} (readable as v{read})"))
        }
        SEEK_HEAD => Some(match count(SEEK) {
            1 => "1 entry".to_owned(),
            n => format!("{n} entries"),
        }),
        SEEK => {
            let id = child(&d, SEEK_ID).map(|v| u32::try_from(be_uint(v)).unwrap_or(0))?;
            let pos = child_uint(&d, SEEK_POSITION)?;
            Some(match el.ctx.segment {
                Some(seg) => format!("{} at {:#x}", name_of(id), seg.offset.saturating_add(pos)),
                None => format!("{} at segment offset {pos:#x}", name_of(id)),
            })
        }
        INFO => {
            let scale = child_uint(&d, TIMESTAMP_SCALE).unwrap_or(DEFAULT_SCALE);
            let mut parts = Vec::new();
            if let Some(f) = child(&d, DURATION).and_then(be_float) {
                parts.push(seconds_f64(f * scale as f64 / 1e9));
            }
            if let Some(t) = child_text(&d, TITLE) {
                parts.push(format!("\"{t}\""));
            }
            if let Some(app) = child_text(&d, WRITING_APP).or_else(|| child_text(&d, MUXING_APP)) {
                parts.push(app);
            }
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        CLUSTER => {
            child_uint(&d, TIMESTAMP).map(|v| format!("at {}", seconds_f64(ticks(v, el.ctx.scale))))
        }
        TRACKS => {
            let list: Vec<String> = mem_children(&d)
                .filter(|(i, _)| *i == TRACK_ENTRY)
                .map(|(_, v)| track_summary(v).short())
                .collect();
            Some(format!(
                "{}: {}",
                vidutil::plural(to_u64(list.len()), "track"),
                list.join(", ")
            ))
        }
        TRACK_ENTRY => Some(track_summary(&d).describe()),
        VIDEO => {
            let w = child_uint(&d, PIXEL_WIDTH)?;
            let h = child_uint(&d, PIXEL_HEIGHT)?;
            let t = TrackSummary {
                width: w,
                height: h,
                display: match (
                    child_uint(&d, DISPLAY_WIDTH),
                    child_uint(&d, DISPLAY_HEIGHT),
                ) {
                    (None, None) => None,
                    (dw, dh) => Some((
                        dw.unwrap_or(w),
                        dh.unwrap_or(h),
                        child_uint(&d, DISPLAY_UNIT).unwrap_or(0),
                    )),
                },
                ..TrackSummary::default()
            };
            let mut parts = vec![format!("{w}×{h}")];
            parts.extend(t.display_note());
            if let Some(i) = child_uint(&d, FLAG_INTERLACED).filter(|&i| i != 0) {
                parts.push(vidutil::lookup_or(INTERLACED, i));
            }
            if let Some(s) = child_uint(&d, STEREO_MODE).filter(|&s| s != 0) {
                parts.push(vidutil::lookup_or(STEREO, s));
            }
            Some(parts.join(", "))
        }
        AUDIO => {
            let rate = child(&d, SAMPLING_FREQUENCY)
                .and_then(be_float)
                .unwrap_or(8000.0);
            let mut s = format!(
                "{}, {}",
                sound::hz(rate),
                channel_word(child_uint(&d, CHANNELS).unwrap_or(1))
            );
            if let Some(b) = child_uint(&d, BIT_DEPTH) {
                s.push_str(&format!(", {b}-bit"));
            }
            if let Some(out) = child(&d, OUTPUT_SAMPLING_FREQUENCY).and_then(be_float) {
                s.push_str(&format!(", output {}", sound::hz(out)));
            }
            Some(s)
        }
        COLOUR => {
            let mut parts = Vec::new();
            for (id, table, what) in [
                (MATRIX, vidutil::MATRIX_COEFFICIENTS, "matrix"),
                (PRIMARIES, vidutil::COLOUR_PRIMARIES, "primaries"),
                (TRANSFER, vidutil::TRANSFER_CHARACTERISTICS, "transfer"),
            ] {
                if let Some(v) = child_uint(&d, id).filter(|&v| v != 2) {
                    parts.push(format!("{what} {}", vidutil::lookup_or(table, v)));
                }
            }
            if let Some(r) = child_uint(&d, RANGE_ID).filter(|&r| r != 0) {
                parts.push(format!("{} range", vidutil::lookup_or(RANGE, r)));
            }
            if let Some(b) = child_uint(&d, BITS_PER_CHANNEL).filter(|&b| b != 0) {
                parts.push(format!("{b}-bit"));
            }
            if let Some(cll) = child_uint(&d, MAX_CLL) {
                parts.push(format!("MaxCLL {cll}"));
            }
            if let Some(fall) = child_uint(&d, MAX_FALL) {
                parts.push(format!("MaxFALL {fall}"));
            }
            if child(&d, MASTERING).is_some() {
                parts.push("mastering metadata".to_owned());
            }
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        MASTERING => {
            let max = child(&d, LUMINANCE_MAX).and_then(be_float)?;
            let min = child(&d, LUMINANCE_MIN).and_then(be_float).unwrap_or(0.0);
            Some(format!(
                "luminance {}–{} cd/m²",
                vidutil::num(min),
                vidutil::num(max)
            ))
        }
        PROJECTION => {
            let kind = child_uint(&d, PROJECTION_TYPE).unwrap_or(0);
            let mut s = vidutil::lookup_or(PROJECTIONS, kind);
            let pose: Vec<String> = [
                (POSE_YAW, "yaw"),
                (POSE_PITCH, "pitch"),
                (POSE_ROLL, "roll"),
            ]
            .iter()
            .filter_map(|&(id, what)| {
                let v = child(&d, id).and_then(be_float)?;
                (v != 0.0).then(|| format!("{what} {}°", vidutil::num(v)))
            })
            .collect();
            if !pose.is_empty() {
                s.push_str(&format!(", {}", pose.join(", ")));
            }
            Some(s)
        }
        CONTENT_ENCODINGS => Some(vidutil::plural(to_u64(count(CONTENT_ENCODING)), "encoding")),
        CONTENT_ENCODING => {
            let scope = child_uint(&d, CONTENT_ENCODING_SCOPE).unwrap_or(1);
            let mut what = Vec::new();
            if scope & 1 != 0 {
                what.push("frames");
            }
            if scope & 2 != 0 {
                what.push("codec private data");
            }
            let how = if let Some(c) = child(&d, CONTENT_COMPRESSION) {
                format!(
                    "{} compression",
                    vidutil::lookup_or(COMP_ALGO, child_uint(c, CONTENT_COMP_ALGO).unwrap_or(0))
                )
            } else if let Some(e) = child(&d, CONTENT_ENCRYPTION) {
                format!(
                    "{} encryption",
                    vidutil::lookup_or(ENC_ALGO, child_uint(e, CONTENT_ENC_ALGO).unwrap_or(0))
                )
            } else {
                vidutil::lookup_or(ENC_TYPE, child_uint(&d, CONTENT_ENCODING_TYPE).unwrap_or(0))
            };
            Some(format!("{how} of {}", what.join(" and ")))
        }
        CONTENT_COMPRESSION => Some(vidutil::lookup_or(
            COMP_ALGO,
            child_uint(&d, CONTENT_COMP_ALGO).unwrap_or(0),
        )),
        CUE_POINT => {
            let time = child_uint(&d, CUE_TIME)?;
            let tracks: Vec<String> = mem_children(&d)
                .filter(|(i, _)| *i == CUE_TRACK_POSITIONS)
                .filter_map(|(_, v)| child_uint(v, CUE_TRACK))
                .map(|t| t.to_string())
                .collect();
            let cluster =
                child(&d, CUE_TRACK_POSITIONS).and_then(|v| child_uint(v, CUE_CLUSTER_POSITION));
            let mut s = format!(
                "{}: track {}",
                seconds_f64(ticks(time, el.ctx.scale)),
                tracks.join(", ")
            );
            if let Some(pos) = cluster {
                s.push_str(&match el.ctx.segment {
                    Some(seg) => format!(" in cluster at {:#x}", seg.offset.saturating_add(pos)),
                    None => format!(" in cluster at segment offset {pos:#x}"),
                });
            }
            Some(s)
        }
        CUE_TRACK_POSITIONS => {
            let track = child_uint(&d, CUE_TRACK)?;
            let mut s = format!("track {track}");
            if let Some(pos) = child_uint(&d, CUE_CLUSTER_POSITION) {
                s.push_str(&match el.ctx.segment {
                    Some(seg) => format!(", cluster at {:#x}", seg.offset.saturating_add(pos)),
                    None => format!(", cluster at segment offset {pos:#x}"),
                });
            }
            if let Some(rel) = child_uint(&d, CUE_RELATIVE_POSITION) {
                s.push_str(&format!(", block at +{rel:#x}"));
            } else if let Some(n) = child_uint(&d, CUE_BLOCK_NUMBER) {
                s.push_str(&format!(", block {n}"));
            }
            Some(s)
        }
        ATTACHMENTS => Some(vidutil::plural(
            to_u64(count_children(cx, data, ATTACHED_FILE).await),
            "file",
        )),
        ATTACHED_FILE => {
            let name = child_text(&d, FILE_NAME).unwrap_or_default();
            let mut extra = Vec::new();
            if let Some(m) = child_text(&d, FILE_MEDIA_TYPE) {
                extra.push(m);
            }
            if let Some(desc) = child_text(&d, FILE_DESCRIPTION) {
                extra.push(format!("\"{desc}\""));
            }
            Some(if extra.is_empty() {
                name
            } else {
                format!("{name} ({})", extra.join(", "))
            })
        }
        CHAPTERS => Some(vidutil::plural(to_u64(count(EDITION_ENTRY)), "edition")),
        EDITION_ENTRY => {
            let mut s = vidutil::plural(to_u64(count(CHAPTER_ATOM)), "chapter");
            if let Some(name) =
                child(&d, EDITION_DISPLAY).and_then(|v| child_text(v, EDITION_STRING))
            {
                s = format!("\"{name}\", {s}");
            }
            for (id, what) in [
                (EDITION_FLAG_DEFAULT, "default"),
                (EDITION_FLAG_ORDERED, "ordered"),
                (EDITION_FLAG_HIDDEN, "hidden"),
            ] {
                if child_uint(&d, id).is_some_and(|v| v != 0) {
                    s.push_str(&format!(", {what}"));
                }
            }
            Some(s)
        }
        CHAPTER_ATOM => {
            let start = child_uint(&d, CHAPTER_TIME_START)?;
            let mut s = seconds_f64(start as f64 / 1e9);
            if let Some(end) = child_uint(&d, CHAPTER_TIME_END) {
                s.push_str(&format!("–{}", seconds_f64(end as f64 / 1e9)));
            }
            if let Some(title) = child(&d, CHAPTER_DISPLAY).and_then(|v| child_text(v, CHAP_STRING))
            {
                s.push_str(&format!(" \"{title}\""));
            }
            let nested = count(CHAPTER_ATOM);
            if nested > 0 {
                s.push_str(&format!(
                    ", {}",
                    vidutil::plural(to_u64(nested), "sub-chapter")
                ));
            }
            if child_uint(&d, CHAPTER_FLAG_HIDDEN).is_some_and(|v| v != 0) {
                s.push_str(", hidden");
            }
            Some(s)
        }
        CHAPTER_DISPLAY => {
            let title = child_text(&d, CHAP_STRING)?;
            let lang =
                child_text(&d, CHAP_LANGUAGE_BCP47).or_else(|| child_text(&d, CHAP_LANGUAGE));
            Some(match lang {
                Some(l) => format!("\"{title}\" ({l})"),
                None => format!("\"{title}\""),
            })
        }
        EDITION_DISPLAY => child_text(&d, EDITION_STRING).map(|t| format!("\"{t}\"")),
        TAGS => Some(vidutil::plural(to_u64(count(TAG)), "tag")),
        TAG => {
            let target = child(&d, TARGETS).map_or_else(|| "segment".to_owned(), targets_summary);
            let names: Vec<String> = mem_children(&d)
                .filter(|(i, _)| *i == SIMPLE_TAG)
                .filter_map(|(_, v)| child_text(v, TAG_NAME))
                .collect();
            Some(format!("{target}: {}", names.join(", ")))
        }
        TARGETS => Some(targets_summary(&d)),
        SIMPLE_TAG => {
            let name = child_text(&d, TAG_NAME)?;
            if let Some(v) = child_text(&d, TAG_STRING) {
                Some(format!("{name} = {v}"))
            } else if let Some(b) = child(&d, TAG_BINARY) {
                Some(format!("{name} ({} bytes of binary data)", b.len()))
            } else {
                Some(name)
            }
        }
        BLOCK_ADDITION_MAPPING => {
            let value = child_uint(&d, BLOCK_ADD_ID_VALUE);
            let kind = child_uint(&d, BLOCK_ADD_ID_TYPE).unwrap_or(0);
            let kind = if kind > 0xffff {
                vidutil::fourcc(&u32::try_from(kind).unwrap_or(0).to_be_bytes())
            } else {
                format!("type {kind}")
            };
            Some(match value {
                Some(v) => format!("BlockAddID {v}: {kind}"),
                None => kind,
            })
        }
        _ => None,
    }
}

/// "TRACK / SONG / CHAPTER, track UID 1".
fn targets_summary(d: &[u8]) -> String {
    let mut parts = Vec::new();
    if let Some(t) = child_text(d, TARGET_TYPE) {
        parts.push(t);
    } else if let Some(v) = child_uint(d, TARGET_TYPE_VALUE) {
        parts.push(vidutil::lookup_or(TARGET_TYPES, v));
    }
    for (id, what) in [
        (TAG_TRACK_UID, "track"),
        (TAG_EDITION_UID, "edition"),
        (TAG_CHAPTER_UID, "chapter"),
        (TAG_ATTACHMENT_UID, "attachment"),
    ] {
        for (_, v) in mem_children(d).filter(|(i, _)| *i == id).take(8) {
            parts.push(format!("{what} UID {}", be_uint(v)));
        }
    }
    if parts.is_empty() {
        "segment".to_owned()
    } else {
        parts.join(", ")
    }
}

/// A BlockGroup: its block's header, duration and references.
async fn group_summary(cx: &Cx, el: &Element, tracks: Option<&[TrackBrief]>) -> Option<String> {
    let data = el.data();
    let mut pos = 0u64;
    let mut block = None;
    let mut refs = 0u32;
    let mut duration = None;
    for _ in 0..16 {
        if pos >= data.len {
            break;
        }
        let h = read_header(cx, data, pos).await.ok()?;
        let size = h.size?;
        let start = pos.saturating_add(h.header_len);
        match h.id {
            BLOCK => block = Some((start, size)),
            REFERENCE_BLOCK => refs = refs.saturating_add(1),
            BLOCK_DURATION => {
                let v = cx.read_avail(data.sub(start, size.min(8))).await.ok()?;
                duration = Some(be_uint(&v));
            }
            _ => {}
        }
        pos = start.saturating_add(size);
    }
    let (start, size) = block?;
    let head = cx.read_avail(data.sub(start, 16)).await.ok()?;
    let h = block_head(&head)?;
    let mut s = block_summary(&h, el, size, tracks);
    if let Some(d) = duration {
        s.push_str(&format!(", lasts {}", seconds_f64(ticks(d, el.ctx.scale))));
    }
    if refs == 0 {
        s.push_str(", keyframe");
    } else {
        s.push_str(&format!(", {}", vidutil::plural(refs, "reference")));
    }
    Some(s)
}

// ---------------------------------------------------------------------------
// Blocks

const LACING: EnumTable = &[(0, "none"), (1, "Xiph"), (2, "fixed-size"), (3, "EBML")];

const SIMPLE_FLAGS: FlagTable = &[
    flag(0x80, "KEYFRAME"),
    flag(0x08, "INVISIBLE"),
    field(0x06, 0x02, "XIPH_LACING"),
    field(0x06, 0x04, "FIXED_LACING"),
    field(0x06, 0x06, "EBML_LACING"),
    flag(0x01, "DISCARDABLE"),
];

const BLOCK_FLAGS: FlagTable = &[
    flag(0x08, "INVISIBLE"),
    field(0x06, 0x02, "XIPH_LACING"),
    field(0x06, 0x04, "FIXED_LACING"),
    field(0x06, 0x06, "EBML_LACING"),
];

/// The fixed part of a block header.
struct BlockHead {
    track: u64,
    /// Length of the track number vint.
    track_len: usize,
    timestamp: i16,
    flags: u8,
    /// The number of laced frames.
    frames: Option<u16>,
}

impl BlockHead {
    fn lacing(&self) -> u8 {
        (self.flags >> 1) & 3
    }
    /// Bytes before the lace count (or the frame).
    fn header_len(&self) -> u64 {
        to_u64(self.track_len).saturating_add(3)
    }
}

fn block_head(d: &[u8]) -> Option<BlockHead> {
    let (track, track_len) = vint(d)?;
    let tc = i16::from_be_bytes(crate::bytes::array(d, track_len)?);
    let flags = *d.get(track_len.checked_add(2)?)?;
    let frames = if (flags >> 1) & 3 != 0 {
        Some(u16::from(*d.get(track_len.checked_add(3)?)?).saturating_add(1))
    } else {
        None
    };
    Some(BlockHead {
        track: track?,
        track_len,
        timestamp: tc,
        flags,
        frames,
    })
}

/// "track 1 (VP9), 00:00:01.200, keyframe, 1234 bytes".
fn block_summary(
    h: &BlockHead,
    el: &Element,
    data_len: u64,
    tracks: Option<&[TrackBrief]>,
) -> String {
    let track = find_track(tracks, h.track).map_or_else(|| h.track.to_string(), TrackBrief::label);
    let time = match el.ctx.cluster {
        Some(base) => {
            let t = i128::from(base).saturating_add(i128::from(h.timestamp));
            signed_seconds(t as f64 * el.ctx.scale as f64 / 1e9)
        }
        None => format!("{:+} ticks", h.timestamp),
    };
    let mut s = format!("track {track}, {time}");
    if el.id == SIMPLE_BLOCK && h.flags & 0x80 != 0 {
        s.push_str(", keyframe");
    }
    if h.flags & 0x08 != 0 {
        s.push_str(", invisible");
    }
    if el.id == SIMPLE_BLOCK && h.flags & 0x01 != 0 {
        s.push_str(", discardable");
    }
    let payload = data_len.saturating_sub(h.header_len());
    match h.frames {
        Some(n) => s.push_str(&format!(
            ", {} ({} lacing), {payload} bytes",
            vidutil::plural(n, "frame"),
            vidutil::lookup_or(LACING, h.lacing().into())
        )),
        None => s.push_str(&format!(", {payload} bytes")),
    }
    s
}

/// One frame of a laced block.
struct Lace {
    size: u64,
    /// Where its size is coded, relative to the lace count byte.
    field: (usize, usize),
    /// For EBML lacing: the coded difference from the previous size.
    delta: Option<i64>,
}

/// Frame sizes of a laced block. `d` starts at the lace count byte;
/// `payload` is the length of the block from there on. Returns the length
/// of the lacing header (count byte included) and the frames.
fn laces(
    d: &[u8],
    lacing: u8,
    payload: u64,
) -> std::result::Result<(u64, Vec<Lace>), &'static str> {
    const SHORT: &str = "lacing header cut short";
    let n = usize::from(*d.first().ok_or(SHORT)?).saturating_add(1);
    let mut at = 1usize;
    let mut out: Vec<Lace> = Vec::with_capacity(n);
    match lacing {
        1 => {
            for _ in 1..n {
                let start = at;
                let mut size = 0u64;
                loop {
                    let b = *d.get(at).ok_or(SHORT)?;
                    at = at.saturating_add(1);
                    size = size.saturating_add(u64::from(b));
                    if b != 255 {
                        break;
                    }
                }
                out.push(Lace {
                    size,
                    field: (start, at.saturating_sub(start)),
                    delta: None,
                });
            }
        }
        3 => {
            let mut prev = 0i64;
            for i in 1..n {
                let start = at;
                let (raw, _, len) = vint_raw(d.get(at..).ok_or(SHORT)?).ok_or(SHORT)?;
                at = at.saturating_add(len);
                let (size, delta) = if i == 1 {
                    (i64::try_from(raw).map_err(|_| "lace size too large")?, None)
                } else {
                    let bits = u32::try_from(len.saturating_mul(7).saturating_sub(1)).unwrap_or(0);
                    let bias = 1i64
                        .checked_shl(bits)
                        .and_then(|b| b.checked_sub(1))
                        .ok_or("lace size too large")?;
                    let delta = i64::try_from(raw)
                        .ok()
                        .and_then(|r| r.checked_sub(bias))
                        .ok_or("lace size too large")?;
                    let size = prev.checked_add(delta).ok_or("lace size too large")?;
                    (size, Some(delta))
                };
                let size = u64::try_from(size).map_err(|_| "negative lace size")?;
                out.push(Lace {
                    size,
                    field: (start, at.saturating_sub(start)),
                    delta,
                });
                prev = i64::try_from(size).unwrap_or(i64::MAX);
            }
        }
        2 => {
            let rest = payload.saturating_sub(1);
            let count = to_u64(n);
            if rest.checked_rem(count) != Some(0) {
                return Err("fixed-size lacing does not divide the data evenly");
            }
            let each = rest.checked_div(count).unwrap_or(0);
            for _ in 0..n {
                out.push(Lace {
                    size: each,
                    field: (0, 0),
                    delta: None,
                });
            }
            return Ok((1, out));
        }
        _ => return Err("not laced"),
    }
    let header = to_u64(at);
    let used = out.iter().fold(0u64, |a, l| a.saturating_add(l.size));
    let last = payload
        .checked_sub(header)
        .and_then(|r| r.checked_sub(used))
        .ok_or("lace sizes exceed the block")?;
    out.push(Lace {
        size: last,
        field: (at, 0),
        delta: None,
    });
    Ok((header, out))
}

/// The most lacing header we read (255 frames of up to ~64 KiB in Xiph
/// lacing).
const LACE_WINDOW: u64 = 0x10000;

async fn block(cx: Cx, el: Element) -> Result<()> {
    let data = el.data();
    let d = cx.read_avail(data.sub(0, LACE_WINDOW)).await?;
    let Some(h) = block_head(&d) else {
        return Err(Diagnostic::malformed("invalid block header").at(data.sub(0, 4)));
    };
    let tracks = match el.ctx.segment {
        Some(seg) => Some(track_table(&cx, seg).await),
        None => None,
    };
    let brief = find_track(tracks.as_deref().map(Vec::as_slice), h.track);
    let at = to_u64(h.track_len);
    let mut track = uint("Track number", data.sub(0, at), h.track, 64);
    if let Some(b) = brief {
        track = track.summary(codec_name(&b.codec_id).to_owned());
    }
    cx.emit(track);
    let mut ts = Node::new("Timestamp")
        .span(data.sub(at, 2))
        .value(Value::Int {
            value: h.timestamp.into(),
            bits: 16,
        })
        .desc("Relative to the cluster's timestamp, in ticks");
    ts = match el.ctx.cluster {
        Some(base) => {
            let t = i128::from(base).saturating_add(i128::from(h.timestamp));
            ts.summary(signed_seconds(t as f64 * el.ctx.scale as f64 / 1e9))
        }
        None => ts.summary(signed_seconds(
            f64::from(h.timestamp) * el.ctx.scale as f64 / 1e9,
        )),
    };
    cx.emit(ts);
    let fspan = data.sub(at.saturating_add(2), 1);
    let table = if el.id == SIMPLE_BLOCK {
        SIMPLE_FLAGS
    } else {
        BLOCK_FLAGS
    };
    let (set, unknown) = crate::value::decode_flags(table, h.flags.into());
    cx.emit(Node::new("Flags").span(fspan).value(Value::Flags {
        raw: h.flags.into(),
        bits: 8,
        set,
        unknown,
    }));
    let head_len = h.header_len();
    let payload = data.tail(head_len);
    let input = el.input;
    if h.lacing() == 0 {
        cx.emit(frame_node(&cx, input, "Frame", payload, brief).await);
        return Ok(());
    }
    let lace_data = d.get(vidutil::us(head_len)..).unwrap_or_default();
    let (lace_len, frames) = match laces(lace_data, h.lacing(), payload.len) {
        Ok(v) => v,
        Err(e) => {
            cx.emit(
                Node::new("Laced frames")
                    .span(payload)
                    .diag(Diagnostic::malformed(e).at(payload)),
            );
            return Ok(());
        }
    };
    cx.emit(
        Node::new("Lacing")
            .span(payload.sub(0, lace_len))
            .summary(format!(
                "{} lacing, {}",
                vidutil::lookup_or(LACING, h.lacing().into()),
                vidutil::plural(to_u64(frames.len()), "frame")
            ))
            .lazy(
                lacing_header,
                (payload.sub(0, lace_len), h.lacing(), payload.len),
            ),
    );
    let mut pos = lace_len;
    for (i, lace) in frames.iter().enumerate() {
        let span = payload.sub(pos, lace.size);
        let name = format!("Frame {}", i.saturating_add(1));
        let mut node = frame_node(&cx, input, "Frame", span, brief).await;
        node.name = name.into();
        if span.len < lace.size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, lace.size),
                span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(lace.size);
    }
    Ok(())
}

/// The lace count and sizes.
async fn lacing_header(cx: Cx, (span, lacing, payload): (Span, u8, u64)) -> Result<()> {
    let d = cx.read_avail(span).await?;
    let count = d.first().copied().unwrap_or(0);
    cx.emit(
        Node::new("Frame count minus one")
            .span(span.sub(0, 1))
            .value(Value::UInt {
                value: count.into(),
                bits: 8,
                radix: Radix::Dec,
            })
            .summary(vidutil::plural(u16::from(count).saturating_add(1), "frame")),
    );
    let Ok((_, frames)) = laces(&d, lacing, payload) else {
        return Ok(());
    };
    if lacing == 2 {
        if let Some(l) = frames.first() {
            cx.emit(
                Node::new("Frame size")
                    .value(Value::UInt {
                        value: l.size,
                        bits: 64,
                        radix: Radix::Dec,
                    })
                    .desc("Fixed-size lacing: the data divided evenly"),
            );
        }
        return Ok(());
    }
    let last = frames.len().saturating_sub(1);
    for (i, lace) in frames.iter().enumerate().take(last) {
        let fspan = span.sub(to_u64(lace.field.0), to_u64(lace.field.1));
        let mut node = Node::new(format!("Size of frame {}", i.saturating_add(1)))
            .span(fspan)
            .value(Value::UInt {
                value: lace.size,
                bits: 64,
                radix: Radix::Dec,
            });
        if let Some(delta) = lace.delta {
            node = node.summary(format!("{delta:+} from the previous frame"));
        }
        cx.emit(node);
    }
    if let Some(l) = frames.get(last) {
        cx.emit(
            Node::new(format!("Size of frame {}", last.saturating_add(1)))
                .value(Value::UInt {
                    value: l.size,
                    bits: 64,
                    radix: Radix::Dec,
                })
                .desc("Not stored: the rest of the block"),
        );
    }
    Ok(())
}

/// A frame: text for text subtitles, an embedded image for Motion JPEG,
/// a decoded view for zlib-compressed tracks.
async fn frame_node(
    cx: &Cx,
    input: Input,
    name: &'static str,
    span: Span,
    brief: Option<&TrackBrief>,
) -> Node {
    let size = format!("{} bytes", span.len);
    let Some(b) = brief else {
        return Node::new(name).span(span).summary(size);
    };
    if b.zlib {
        return content(name, input, span, crate::codec::Codec::Zlib, None)
            .summary(format!("{size}, zlib-compressed"));
    }
    let mut node = Node::new(name).span(span).summary(size.clone());
    if let Some(strip) = &b.stripped {
        node = node.desc(format!(
            "Header stripping: {} bytes ({}) were removed from the start of this frame",
            strip.len(),
            strip
                .iter()
                .take(8)
                .map(|x| format!("{x:02x}"))
                .collect::<Vec<_>>()
                .join(" ")
        ));
    }
    match b.codec {
        Codec::Text => {
            if let Ok(t) = cx.read_avail(span.sub(0, 0x1000)).await {
                node = node.value(Value::Text(String::from_utf8_lossy(&t).into_owned()));
            }
        }
        Codec::Mjpeg | Codec::Vfw if b.stripped.is_none() => {
            let jpeg = cx
                .read_avail(span.sub(0, 3))
                .await
                .is_ok_and(|h| h == [0xff, 0xd8, 0xff]);
            return if jpeg {
                embedded(name, input.nested(span)).summary(size)
            } else {
                node
            };
        }
        _ => {}
    }
    node
}

// ---------------------------------------------------------------------------
// Codec private data

/// Lists the bytes of codec private data we do not decode.
async fn private_bytes(cx: Cx, el: Element) -> Result<()> {
    let data = el.data();
    let d = cx.read_avail(data.sub(0, 0x1000)).await?;
    if crate::text::looks_like_text(&d) {
        cx.emit(
            Node::new("Text")
                .span(data)
                .value(Value::Text(String::from_utf8_lossy(&d).into_owned())),
        );
    } else {
        cx.emit(
            Node::new("Data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        );
    }
    Ok(())
}

/// A one-line description of codec private data.
fn private_summary(codec: Codec, d: &[u8]) -> Option<String> {
    match codec {
        Codec::Avc => vidutil::avcc_summary(d),
        Codec::Hevc => vidutil::hvcc_summary(d),
        Codec::Av1 => nal::av1c(d, detached(d.len()), false).0,
        Codec::Vp9 => {
            let mut parts = Vec::new();
            for (id, v) in vp9_features(d) {
                parts.push(match id {
                    1 => format!("profile {v}"),
                    2 => format!("level {}.{}", v / 10, v % 10),
                    3 => format!("{v}-bit"),
                    4 => vidutil::lookup_or(VP9_CHROMA, v),
                    _ => continue,
                });
            }
            (!parts.is_empty()).then(|| parts.join(", "))
        }
        Codec::Xiph => {
            let (_, packets) = xiph_packets(d, to_u64(d.len()))?;
            let first = packets
                .first()
                .and_then(|&(at, len)| d.get(at..at.saturating_add(len)))?;
            let what = xiph_id_summary(first).unwrap_or_else(|| "headers".to_owned());
            Some(format!(
                "{what}; {}",
                vidutil::plural(to_u64(packets.len()), "header")
            ))
        }
        Codec::Opus => {
            if !d.starts_with(b"OpusHead") {
                return None;
            }
            nal::opus(d, detached(d.len()), false, false)
                .0
                .map(|o| o.describe())
        }
        Codec::Flac => {
            if !d.starts_with(b"fLaC") {
                return None;
            }
            flac_streaminfo(d.get(8..)?)
        }
        Codec::Aac => vidutil::asc_summary(d),
        Codec::Vfw => {
            let w = i32::from_le_bytes(crate::bytes::array(d, 4)?);
            let h = i32::from_le_bytes(crate::bytes::array(d, 8)?);
            let bits = u16::from_le_bytes(crate::bytes::array(d, 14)?);
            let c: [u8; 4] = crate::bytes::array(d, 16)?;
            let codec = match u32::from_le_bytes(c) {
                0 => "RGB".to_owned(),
                1 => "RLE8".to_owned(),
                2 => "RLE4".to_owned(),
                3 => "bitfields".to_owned(),
                _ => vidutil::codec_name(&c).map_or_else(|| vidutil::fourcc(&c), str::to_owned),
            };
            Some(format!("{codec} {w}×{}, {bits}-bit", h.unsigned_abs()))
        }
        Codec::Acm => {
            let tag = acm_tag(d)?;
            let channels = u16::from_le_bytes(crate::bytes::array(d, 2)?);
            let rate = u32::from_le_bytes(crate::bytes::array(d, 4)?);
            Some(format!(
                "{}, {rate} Hz, {}",
                vidutil::lookup_or(wav::FORMAT_TAG, tag.into()),
                channel_word(channels.into())
            ))
        }
        Codec::Alac => {
            let c = alac_config(d)?;
            Some(format!(
                "{} Hz, {}, {}-bit",
                u32_be(c, 20)?,
                channel_word((*c.get(9)?).into()),
                c.get(5)?
            ))
        }
        Codec::Text | Codec::TextHeader => {
            let t = String::from_utf8_lossy(d);
            let line = t.lines().map(str::trim).find(|l| !l.is_empty())?;
            Some(sound::clip(line, 60))
        }
        Codec::Mjpeg | Codec::Other => None,
    }
}

/// The format tag of a WAVEFORMATEX (the subformat's, for EXTENSIBLE).
fn acm_tag(d: &[u8]) -> Option<u16> {
    let tag = u16::from_le_bytes(crate::bytes::array(d, 0)?);
    if tag == 0xfffe {
        return u16::from_le_bytes(crate::bytes::array(d, 24)?).into();
    }
    Some(tag)
}

/// The 24-byte ALACSpecificConfig, with or without its `alac` atom header.
fn alac_config(d: &[u8]) -> Option<&[u8]> {
    if d.get(4..8) == Some(b"alac") {
        d.get(12..36)
    } else {
        d.get(..24)
    }
}

/// FLAC STREAMINFO: "44100 Hz, 2 ch, 16-bit, 441000 samples".
fn flac_streaminfo(d: &[u8]) -> Option<String> {
    let mut b = vidutil::Bits::new(d.get(10..18)?);
    let rate = b.bits(20)?;
    let channels = b.bits(3)?.saturating_add(1);
    let bits = b.bits(5)?.saturating_add(1);
    let samples = b.bits(36)?;
    Some(format!(
        "{rate} Hz, {}, {bits}-bit, {samples} samples",
        channel_word(channels)
    ))
}

const VP9_FEATURES: EnumTable = &[
    (1, "profile"),
    (2, "level"),
    (3, "bit depth"),
    (4, "chroma subsampling"),
];

const VP9_CHROMA: EnumTable = &[
    (0, "4:2:0 vertical"),
    (1, "4:2:0 colocated"),
    (2, "4:2:2"),
    (3, "4:4:4"),
];

/// VP9 CodecPrivate: (feature ID, value) pairs.
fn vp9_features(d: &[u8]) -> Vec<(u8, u64)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let (Some(&id), Some(&len)) = (d.get(at), d.get(at.saturating_add(1))) {
        let start = at.saturating_add(2);
        let end = start.saturating_add(usize::from(len));
        let Some(v) = d.get(start..end) else {
            break;
        };
        out.push((id, be_uint(v)));
        at = end;
    }
    out
}

/// Xiph-laced packets: the header length and (offset, length) of each.
fn xiph_packets(d: &[u8], total: u64) -> Option<(usize, Vec<(usize, usize)>)> {
    let count = usize::from(*d.first()?).checked_add(1)?;
    let mut at = 1usize;
    let mut sizes = Vec::new();
    for _ in 1..count {
        let mut size = 0usize;
        loop {
            let b = *d.get(at)?;
            at = at.checked_add(1)?;
            size = size.checked_add(usize::from(b))?;
            if b != 255 {
                break;
            }
        }
        sizes.push(size);
    }
    let header = at;
    let mut packets = Vec::new();
    for s in sizes {
        packets.push((at, s));
        at = at.checked_add(s)?;
    }
    let last = usize::try_from(total).ok()?.checked_sub(at)?;
    packets.push((at, last));
    Some((header, packets))
}

/// What the identification header of a Xiph codec says.
fn xiph_id_summary(p: &[u8]) -> Option<String> {
    match p {
        [1, b'v', b'o', b'r', b'b', b'i', b's', ..] => {
            let channels = *p.get(11)?;
            let rate = u32::from_le_bytes(crate::bytes::array(p, 12)?);
            let nominal = i32::from_le_bytes(crate::bytes::array(p, 20)?);
            let mut s = format!("Vorbis, {}, {rate} Hz", channel_word(channels.into()));
            if nominal > 0 {
                s.push_str(&format!(", nominal {} kb/s", nominal / 1000));
            }
            Some(s)
        }
        [0x80, b't', b'h', b'e', b'o', b'r', b'a', ..] => {
            let w = crate::bytes::u24_be(p, 14)?;
            let h = crate::bytes::u24_be(p, 17)?;
            Some(format!("Theora, {w}×{h}"))
        }
        [0x80, b'k', b'a', b't', b'e', ..] => Some("Kate".to_owned()),
        _ => None,
    }
}

fn emit_all(cx: &Cx, nodes: Vec<Node>) {
    for node in nodes {
        cx.emit(node);
    }
}

async fn codec_private(cx: Cx, el: Element) -> Result<()> {
    let data = el.data();
    let d = vidutil::read_small(&cx, data, 0x10000).await?;
    let span = data.sub(0, to_u64(d.len()));
    match el.ctx.codec {
        Codec::Avc => emit_all(&cx, nal::avcc(&d, span, true).1),
        Codec::Hevc => emit_all(&cx, nal::hvcc(&d, span, true).1),
        Codec::Av1 => emit_all(&cx, nal::av1c(&d, span, true).1),
        Codec::Aac => emit_all(&cx, nal::asc(&d, span, true).1),
        Codec::Vp9 => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Big);
            while f.remaining() >= 2 {
                let id = f.u8("Feature ID").enumeration(VP9_FEATURES).emit()?;
                let len = f.u8("Feature length").emit()?;
                let at = f.pos();
                let v = f.bytes("Feature value", len.into()).get()?;
                let v = be_uint(&v);
                let summary = match id {
                    2 => Some(format!("{}.{}", v / 10, v % 10)),
                    3 => Some(format!("{v}-bit")),
                    4 => Some(vidutil::lookup_or(VP9_CHROMA, v)),
                    _ => None,
                };
                let name = match id {
                    1 => "Profile",
                    2 => "Level",
                    3 => "Bit depth",
                    4 => "Chroma subsampling",
                    _ => "Feature value",
                };
                let node = Node::new(name)
                    .span(span.sub(at, len.into()))
                    .value(Value::UInt {
                        value: v,
                        bits: 64,
                        radix: Radix::Dec,
                    });
                f.node(match summary {
                    Some(s) => node.summary(s),
                    None => node,
                });
            }
        }
        Codec::Opus => emit_all(&cx, nal::opus(&d, span, true, false).1),
        Codec::Flac => flac_private(&cx, el.input, data).await?,
        Codec::Xiph => xiph_private(&cx, el.input, data).await?,
        Codec::Vfw => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Little);
            crate::formats::video::asf::bitmapinfoheader(&mut f)?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("Extra data", rest).emit()?;
            }
        }
        Codec::Acm => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Little);
            crate::formats::video::asf::waveformatex(&mut f)?;
            let rest = f.remaining();
            if rest > 0 {
                f.bytes("Extra data", rest).emit()?;
            }
        }
        Codec::Alac => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Big);
            if d.get(4..8) == Some(b"alac") {
                f.u32("Atom size").emit()?;
                f.ascii("Atom type", 4).emit()?;
                f.u32("Version and flags").hex().emit()?;
            }
            f.u32("Frame length").desc("Samples per frame").emit()?;
            f.u8("Compatible version").emit()?;
            f.u8("Bit depth").emit()?;
            f.u8("Rice history mult").emit()?;
            f.u8("Rice initial history").emit()?;
            f.u8("Rice parameter limit").emit()?;
            f.u8("Channels").emit()?;
            f.u16("Max run").emit()?;
            f.u32("Max frame bytes").emit()?;
            f.u32("Average bit rate").emit()?;
            f.u32("Sample rate").emit()?;
        }
        Codec::Text | Codec::TextHeader => {
            cx.emit(
                Node::new("Text")
                    .span(span)
                    .value(Value::Text(String::from_utf8_lossy(&d).into_owned())),
            );
        }
        Codec::Mjpeg | Codec::Other => {
            cx.emit(Node::new("Data").span(data));
        }
    }
    Ok(())
}

/// `fLaC` followed by metadata blocks.
async fn flac_private(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let magic = cx.read_avail(data.sub(0, 4)).await?;
    if magic != b"fLaC" {
        cx.emit(Node::new("Data").span(data).diag(Diagnostic::malformed(
            "FLAC codec data without the fLaC signature",
        )));
        return Ok(());
    }
    cx.emit(
        Node::new("Signature")
            .span(data.sub(0, 4))
            .value(Value::Text("fLaC".to_owned())),
    );
    let mut pos = 4u64;
    while pos.saturating_add(4) <= data.len {
        let h = cx.read_avail(data.sub(pos, 4)).await?;
        let Some(len) = crate::bytes::u24_be(&h, 1) else {
            break;
        };
        let last = h.first().is_some_and(|b| b & 0x80 != 0);
        let span = data.sub(pos, 4u64.saturating_add(len.into()));
        cx.emit(flac::block_node(cx, input, span).await?);
        pos = pos.saturating_add(span.len.max(1));
        if last {
            break;
        }
    }
    if pos < data.len {
        cx.emit(Node::new("Trailing data").span(data.tail(pos)));
    }
    Ok(())
}

/// Xiph-laced headers (Vorbis, Theora, Kate).
async fn xiph_private(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let d = vidutil::read_small(cx, data, 0x10000).await?;
    let Some((header, packets)) = xiph_packets(&d, data.len) else {
        cx.emit(
            Node::new("Data")
                .span(data)
                .diag(Diagnostic::malformed("invalid Xiph lacing")),
        );
        return Ok(());
    };
    cx.emit(
        Node::new("Lacing")
            .span(data.sub(0, to_u64(header)))
            .summary(format!(
                "{}: {}",
                vidutil::plural(to_u64(packets.len()), "packet"),
                packets
                    .iter()
                    .map(|(_, l)| format!("{l} bytes"))
                    .collect::<Vec<_>>()
                    .join(", ")
            ))
            .desc("Packet count minus one, then the Xiph-coded sizes of all packets but the last"),
    );
    for (at, len) in packets {
        let span = data.sub(to_u64(at), to_u64(len));
        let head = d.get(at..at.saturating_add(len.min(8))).unwrap_or_default();
        let kind = xiph_kind(head);
        let name = match kind {
            1 => "Vorbis identification header",
            3 => "Vorbis comment header",
            5 => "Vorbis setup header",
            0x80 => "Theora identification header",
            0x81 => "Theora comment header",
            0x82 => "Theora setup header",
            _ => "Header packet",
        };
        let mut node = Node::new(name).span(span);
        let p = d.get(at..at.saturating_add(len)).unwrap_or_default();
        node = match kind {
            1 | 0x80 => match xiph_id_summary(p) {
                Some(s) => node.summary(s),
                None => node,
            },
            3 | 0x81 => match vorbis::title(cx, span.tail(7)).await {
                Some(s) => node.summary(s),
                None => node,
            },
            _ => node.summary(format!("{len} bytes")),
        };
        if matches!(kind, 1 | 3 | 0x80 | 0x81) {
            node = node.lazy(xiph_packet, (input, span, kind));
        }
        cx.emit(node);
    }
    Ok(())
}

fn xiph_kind(head: &[u8]) -> u8 {
    match head {
        [k @ (1 | 3 | 5), b'v', b'o', b'r', b'b', b'i', b's', ..] => *k,
        [k @ 0x80..=0x82, b't', b'h', b'e', b'o', b'r', b'a', ..] => *k,
        _ => 0,
    }
}

async fn xiph_packet(cx: Cx, (input, span, kind): (Input, Span, u8)) -> Result<()> {
    match kind {
        1 => {
            let block = cx.block(span.sub(0, 30)).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Little);
            f.u8("Packet type").emit()?;
            f.ascii("Signature", 6).emit()?;
            f.u32("Vorbis version").emit()?;
            f.u8("Channels").emit()?;
            f.u32("Sample rate").emit()?;
            f.i32("Maximum bitrate").emit()?;
            f.i32("Nominal bitrate").emit()?;
            f.i32("Minimum bitrate").emit()?;
            f.u8("Block sizes")
                .with(|&v, n| {
                    n.summary(format!(
                        "{} / {} samples",
                        1u32 << (v & 0xf).min(31),
                        1u32 << (v >> 4).min(31)
                    ))
                })
                .emit()?;
            f.u8("Framing flag").emit()?;
        }
        0x80 => {
            let block = cx.block(span.sub(0, 42)).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Big);
            f.u8("Packet type").emit()?;
            f.ascii("Signature", 6).emit()?;
            f.u8("Major version").emit()?;
            f.u8("Minor version").emit()?;
            f.u8("Revision").emit()?;
            f.u16("Frame width (macroblocks)").emit()?;
            f.u16("Frame height (macroblocks)").emit()?;
            sound::u24(&mut f, "Picture width", Endian::Big).emit()?;
            sound::u24(&mut f, "Picture height", Endian::Big).emit()?;
            f.u8("Picture X offset").emit()?;
            f.u8("Picture Y offset").emit()?;
            let num = f.u32("Frame rate numerator").emit()?;
            f.u32("Frame rate denominator")
                .with(|&den, n| {
                    if den > 0 {
                        n.summary(format!("{:.3} fps", f64::from(num) / f64::from(den)))
                    } else {
                        n
                    }
                })
                .emit()?;
            sound::u24(&mut f, "Aspect ratio numerator", Endian::Big).emit()?;
            sound::u24(&mut f, "Aspect ratio denominator", Endian::Big).emit()?;
            f.u8("Colour space")
                .enumeration(&[(0, "undefined"), (1, "Rec. 470M"), (2, "Rec. 470BG")])
                .emit()?;
            sound::u24(&mut f, "Nominal bitrate", Endian::Big).emit()?;
            f.u16("Quality, keyframe shift, pixel format")
                .hex()
                .emit()?;
        }
        _ => {
            cx.emit(
                Node::new("Packet type and signature")
                    .span(span.sub(0, 7))
                    .value(Value::Text(
                        if kind == 3 {
                            "\\x03vorbis"
                        } else {
                            "\\x81theora"
                        }
                        .to_owned(),
                    )),
            );
            let used = vorbis::emit(&cx, input, span.tail(7)).await?;
            let rest = span.tail(7u64.saturating_add(used));
            if !rest.is_empty() {
                cx.emit(Node::new("Framing bit").span(rest));
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    if let Some(s) = file_summary(&cx, input.span).await {
        cx.annotate(s);
    }
    elements(&cx, input, input.span, 0, ROOT, None).await
}

/// `WebM, 00:01:23.000, VP9 1280×720 + Opus stereo 48 kHz, 2 chapters, "title"`.
async fn file_summary(cx: &Cx, file: Span) -> Option<String> {
    let mut pos = 0u64;
    let mut label = "Matroska";
    let mut segment = None;
    let mut live = false;
    for _ in 0..4 {
        let h = read_header(cx, file, pos).await.ok()?;
        let data_start = pos.saturating_add(h.header_len);
        match h.id {
            EBML => {
                let d = vidutil::read_small(cx, file.sub(data_start, h.size?), 0x1000)
                    .await
                    .ok()?;
                if child_text(&d, DOC_TYPE).as_deref() == Some("webm") {
                    label = "WebM";
                }
            }
            SEGMENT => {
                let len = h.size.unwrap_or(file.len.saturating_sub(data_start));
                segment = Some(file.sub(data_start, len));
                live = h.size.is_none();
                break;
            }
            _ => {}
        }
        pos = data_start.saturating_add(h.size?);
    }
    let Some(segment) = segment else {
        return Some(label.to_owned());
    };
    let top = top_level(cx, segment).await.ok()?;
    let mut parts = vec![label.to_owned()];
    let mut duration = None;
    let mut title = None;
    let mut tracks = None;
    let mut chapters = 0usize;
    let mut attachments = 0usize;
    for (id, span) in top {
        match id {
            INFO => {
                let d = vidutil::read_small(cx, span, 0x10000).await.ok()?;
                let scale = child_uint(&d, TIMESTAMP_SCALE).unwrap_or(DEFAULT_SCALE);
                duration = child(&d, DURATION)
                    .and_then(be_float)
                    .map(|f| seconds_f64(f * scale as f64 / 1e9));
                title = child_text(&d, TITLE).filter(|t| !t.is_empty());
            }
            TRACKS => {
                let d = vidutil::read_small(cx, span, 0x100000).await.ok()?;
                let list: Vec<String> = mem_children(&d)
                    .filter(|(i, _)| *i == TRACK_ENTRY)
                    .take(MAX_TRACKS)
                    .map(|(_, v)| track_summary(v).short())
                    .collect();
                if !list.is_empty() {
                    tracks = Some(list.join(" + "));
                }
            }
            CHAPTERS => {
                let d = vidutil::read_small(cx, span, 0x10000).await.ok()?;
                if let Some((_, edition)) = mem_children(&d).find(|(i, _)| *i == EDITION_ENTRY) {
                    chapters = mem_children(edition)
                        .filter(|(i, _)| *i == CHAPTER_ATOM)
                        .count();
                }
            }
            ATTACHMENTS => attachments = count_children(cx, span, ATTACHED_FILE).await,
            _ => {}
        }
    }
    parts.extend(duration);
    parts.extend(tracks);
    if chapters > 0 {
        parts.push(vidutil::plural(to_u64(chapters), "chapter"));
    }
    if attachments > 0 {
        parts.push(vidutil::plural(to_u64(attachments), "attachment"));
    }
    if live {
        parts.push("live (unknown sizes)".to_owned());
    }
    if let Some(t) = title {
        parts.push(format!("\"{t}\""));
    }
    Some(parts.join(", "))
}
