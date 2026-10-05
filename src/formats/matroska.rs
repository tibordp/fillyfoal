//! Matroska and WebM (EBML).
//!
//! An EBML document is a tree of elements `ID (vint), size (vint), data`.
//! A table gives names, types and nesting levels for the Matroska schema
//! essentials; unknown elements are shown as binary. Master elements expand
//! lazily and list their children in pages (clusters, cues, blocks), so a
//! large file is never walked as a whole. Elements of unknown size (live
//! streams) end where an element of the same or a higher level begins.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::vidutil::{self, seconds_f64, uint};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

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
    let found = mem_children(header).find(|(id, _)| *id == 0x4282)?;
    let t = found.1;
    let t = t.get(..t.iter().position(|&b| b == 0).unwrap_or(t.len()))?;
    (t == b"matroska" || t == b"webm").then_some(t)
}

// ---------------------------------------------------------------------------
// Variable-length integers

/// An element ID (marker bits kept): value and length.
fn element_id(d: &[u8]) -> Option<(u32, usize)> {
    let first = *d.first()?;
    let len = usize::try_from(first.leading_zeros()).ok()?.checked_add(1)?;
    if len > 4 {
        return None;
    }
    let bytes = d.get(..len)?;
    let id = bytes.iter().fold(0u32, |acc, &b| (acc << 8) | u32::from(b));
    Some((id, len))
}

/// A data size: `None` for the reserved "unknown" value; and its length.
fn vint(d: &[u8]) -> Option<(Option<u64>, usize)> {
    let first = *d.first()?;
    let len = usize::try_from(first.leading_zeros()).ok()?.checked_add(1)?;
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
    Some((if all_ones { None } else { Some(value) }, len))
}

/// Children of an in-memory master element with known sizes.
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

fn be_uint(d: &[u8]) -> u64 {
    d.iter().take(8).fold(0u64, |acc, &b| (acc << 8) | u64::from(b))
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

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Master,
    UInt,
    Enum(EnumTable),
    Int,
    Float,
    Str,
    Utf8,
    Date,
    Binary,
    Block,
}

/// (id, name, kind, level); level 255 = global (may appear anywhere).
type Def = (u32, &'static str, Kind, u8);

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

const COMP_ALGO: EnumTable = &[(0, "zlib"), (1, "bzlib"), (2, "lzo1x"), (3, "header stripping")];
const ENC_TYPE: EnumTable = &[(0, "compression"), (1, "encryption")];
const INTERLACED: EnumTable = &[(0, "undetermined"), (1, "interlaced"), (2, "progressive")];
const STEREO: EnumTable = &[
    (0, "mono"),
    (1, "side by side (left first)"),
    (2, "top-bottom (right first)"),
    (3, "top-bottom (left first)"),
    (11, "side by side (right first)"),
];
const RANGE: EnumTable = &[(0, "unspecified"), (1, "broadcast"), (2, "full"), (3, "defined by matrix/transfer")];

use Kind::{Binary, Block, Date, Float, Int, Master, Str, UInt, Utf8};

const SCHEMA: &[Def] = &[
    (0x1a45dfa3, "EBML", Master, 0),
    (0x4286, "EBMLVersion", UInt, 1),
    (0x42f7, "EBMLReadVersion", UInt, 1),
    (0x42f2, "EBMLMaxIDLength", UInt, 1),
    (0x42f3, "EBMLMaxSizeLength", UInt, 1),
    (0x4282, "DocType", Str, 1),
    (0x4287, "DocTypeVersion", UInt, 1),
    (0x4285, "DocTypeReadVersion", UInt, 1),
    (0xec, "Void", Binary, 255),
    (0xbf, "CRC-32", Binary, 255),
    (0x18538067, "Segment", Master, 0),
    // Meta seek
    (0x114d9b74, "SeekHead", Master, 1),
    (0x4dbb, "Seek", Master, 2),
    (0x53ab, "SeekID", Binary, 3),
    (0x53ac, "SeekPosition", UInt, 3),
    // Segment information
    (0x1549a966, "Info", Master, 1),
    (0x73a4, "SegmentUUID", Binary, 2),
    (0x7384, "SegmentFilename", Utf8, 2),
    (0x3cb923, "PrevUUID", Binary, 2),
    (0x3c83ab, "PrevFilename", Utf8, 2),
    (0x3eb923, "NextUUID", Binary, 2),
    (0x3e83bb, "NextFilename", Utf8, 2),
    (0x4444, "SegmentFamily", Binary, 2),
    (0x2ad7b1, "TimestampScale", UInt, 2),
    (0x4489, "Duration", Float, 2),
    (0x4461, "DateUTC", Date, 2),
    (0x7ba9, "Title", Utf8, 2),
    (0x4d80, "MuxingApp", Utf8, 2),
    (0x5741, "WritingApp", Utf8, 2),
    (0x6924, "ChapterTranslate", Master, 2),
    // Clusters
    (0x1f43b675, "Cluster", Master, 1),
    (0xe7, "Timestamp", UInt, 2),
    (0x5854, "SilentTracks", Master, 2),
    (0x58d7, "SilentTrackNumber", UInt, 3),
    (0xa7, "Position", UInt, 2),
    (0xab, "PrevSize", UInt, 2),
    (0xa3, "SimpleBlock", Block, 2),
    (0xa0, "BlockGroup", Master, 2),
    (0xa1, "Block", Block, 3),
    (0x75a1, "BlockAdditions", Master, 3),
    (0xa6, "BlockMore", Master, 4),
    (0xee, "BlockAddID", UInt, 5),
    (0xa5, "BlockAdditional", Binary, 5),
    (0x9b, "BlockDuration", UInt, 3),
    (0xfa, "ReferencePriority", UInt, 3),
    (0xfb, "ReferenceBlock", Int, 3),
    (0xa4, "CodecState", Binary, 3),
    (0x75a2, "DiscardPadding", Int, 3),
    // Tracks
    (0x1654ae6b, "Tracks", Master, 1),
    (0xae, "TrackEntry", Master, 2),
    (0xd7, "TrackNumber", UInt, 3),
    (0x73c5, "TrackUID", UInt, 3),
    (0x83, "TrackType", Kind::Enum(TRACK_TYPES), 3),
    (0xb9, "FlagEnabled", UInt, 3),
    (0x88, "FlagDefault", UInt, 3),
    (0x55aa, "FlagForced", UInt, 3),
    (0x55ab, "FlagHearingImpaired", UInt, 3),
    (0x55ac, "FlagVisualImpaired", UInt, 3),
    (0x55ad, "FlagTextDescriptions", UInt, 3),
    (0x55ae, "FlagOriginal", UInt, 3),
    (0x55af, "FlagCommentary", UInt, 3),
    (0x9c, "FlagLacing", UInt, 3),
    (0x6de7, "MinCache", UInt, 3),
    (0x6df8, "MaxCache", UInt, 3),
    (0x23e383, "DefaultDuration", UInt, 3),
    (0x234e7a, "DefaultDecodedFieldDuration", UInt, 3),
    (0x23314f, "TrackTimestampScale", Float, 3),
    (0x55ee, "MaxBlockAdditionID", UInt, 3),
    (0x41e4, "BlockAdditionMapping", Master, 3),
    (0x536e, "Name", Utf8, 3),
    (0x22b59c, "Language", Str, 3),
    (0x22b59d, "LanguageBCP47", Str, 3),
    (0x86, "CodecID", Str, 3),
    (0x63a2, "CodecPrivate", Binary, 3),
    (0x258688, "CodecName", Utf8, 3),
    (0x7446, "AttachmentLink", UInt, 3),
    (0xaa, "CodecDecodeAll", UInt, 3),
    (0x6fab, "TrackOverlay", UInt, 3),
    (0x56aa, "CodecDelay", UInt, 3),
    (0x56bb, "SeekPreRoll", UInt, 3),
    (0x6624, "TrackTranslate", Master, 3),
    (0xe0, "Video", Master, 3),
    (0x9a, "FlagInterlaced", Kind::Enum(INTERLACED), 4),
    (0x9d, "FieldOrder", UInt, 4),
    (0x53b8, "StereoMode", Kind::Enum(STEREO), 4),
    (0x53c0, "AlphaMode", UInt, 4),
    (0xb0, "PixelWidth", UInt, 4),
    (0xba, "PixelHeight", UInt, 4),
    (0x54aa, "PixelCropBottom", UInt, 4),
    (0x54bb, "PixelCropTop", UInt, 4),
    (0x54cc, "PixelCropLeft", UInt, 4),
    (0x54dd, "PixelCropRight", UInt, 4),
    (0x54b0, "DisplayWidth", UInt, 4),
    (0x54ba, "DisplayHeight", UInt, 4),
    (0x54b2, "DisplayUnit", UInt, 4),
    (0x54b3, "AspectRatioType", UInt, 4),
    (0x2eb524, "UncompressedFourCC", Binary, 4),
    (0x55b0, "Colour", Master, 4),
    (0x55b1, "MatrixCoefficients", Kind::Enum(vidutil::MATRIX_COEFFICIENTS), 5),
    (0x55b2, "BitsPerChannel", UInt, 5),
    (0x55b3, "ChromaSubsamplingHorz", UInt, 5),
    (0x55b4, "ChromaSubsamplingVert", UInt, 5),
    (0x55b5, "CbSubsamplingHorz", UInt, 5),
    (0x55b6, "CbSubsamplingVert", UInt, 5),
    (0x55b7, "ChromaSitingHorz", UInt, 5),
    (0x55b8, "ChromaSitingVert", UInt, 5),
    (0x55b9, "Range", Kind::Enum(RANGE), 5),
    (0x55ba, "TransferCharacteristics", Kind::Enum(vidutil::TRANSFER_CHARACTERISTICS), 5),
    (0x55bb, "Primaries", Kind::Enum(vidutil::COLOUR_PRIMARIES), 5),
    (0x55bc, "MaxCLL", UInt, 5),
    (0x55bd, "MaxFALL", UInt, 5),
    (0x55d0, "MasteringMetadata", Master, 5),
    (0x7670, "Projection", Master, 4),
    (0xe1, "Audio", Master, 3),
    (0xb5, "SamplingFrequency", Float, 4),
    (0x78b5, "OutputSamplingFrequency", Float, 4),
    (0x9f, "Channels", UInt, 4),
    (0x6264, "BitDepth", UInt, 4),
    (0x52f1, "Emphasis", UInt, 4),
    (0x6d80, "ContentEncodings", Master, 3),
    (0x6240, "ContentEncoding", Master, 4),
    (0x5031, "ContentEncodingOrder", UInt, 5),
    (0x5032, "ContentEncodingScope", UInt, 5),
    (0x5033, "ContentEncodingType", Kind::Enum(ENC_TYPE), 5),
    (0x5034, "ContentCompression", Master, 5),
    (0x4254, "ContentCompAlgo", Kind::Enum(COMP_ALGO), 6),
    (0x4255, "ContentCompSettings", Binary, 6),
    (0x5035, "ContentEncryption", Master, 5),
    (0x47e1, "ContentEncAlgo", UInt, 6),
    (0x47e2, "ContentEncKeyID", Binary, 6),
    (0x47e7, "ContentEncAESSettings", Master, 6),
    (0x47e8, "AESSettingsCipherMode", UInt, 7),
    // Cues
    (0x1c53bb6b, "Cues", Master, 1),
    (0xbb, "CuePoint", Master, 2),
    (0xb3, "CueTime", UInt, 3),
    (0xb7, "CueTrackPositions", Master, 3),
    (0xf7, "CueTrack", UInt, 4),
    (0xf1, "CueClusterPosition", UInt, 4),
    (0xf0, "CueRelativePosition", UInt, 4),
    (0xb2, "CueDuration", UInt, 4),
    (0x5378, "CueBlockNumber", UInt, 4),
    (0xea, "CueCodecState", UInt, 4),
    (0xdb, "CueReference", Master, 4),
    (0x96, "CueRefTime", UInt, 5),
    // Attachments
    (0x1941a469, "Attachments", Master, 1),
    (0x61a7, "AttachedFile", Master, 2),
    (0x467e, "FileDescription", Utf8, 3),
    (0x466e, "FileName", Utf8, 3),
    (0x4660, "FileMediaType", Str, 3),
    (0x465c, "FileData", Binary, 3),
    (0x46ae, "FileUID", UInt, 3),
    // Chapters
    (0x1043a770, "Chapters", Master, 1),
    (0x45b9, "EditionEntry", Master, 2),
    (0x45bc, "EditionUID", UInt, 3),
    (0x45bd, "EditionFlagHidden", UInt, 3),
    (0x45db, "EditionFlagDefault", UInt, 3),
    (0x45dd, "EditionFlagOrdered", UInt, 3),
    (0xb6, "ChapterAtom", Master, 3),
    (0x73c4, "ChapterUID", UInt, 4),
    (0x5654, "ChapterStringUID", Utf8, 4),
    (0x91, "ChapterTimeStart", UInt, 4),
    (0x92, "ChapterTimeEnd", UInt, 4),
    (0x98, "ChapterFlagHidden", UInt, 4),
    (0x4598, "ChapterFlagEnabled", UInt, 4),
    (0x6e67, "ChapterSegmentUUID", Binary, 4),
    (0x80, "ChapterDisplay", Master, 4),
    (0x85, "ChapString", Utf8, 5),
    (0x437c, "ChapLanguage", Str, 5),
    (0x437d, "ChapLanguageBCP47", Str, 5),
    (0x437e, "ChapCountry", Str, 5),
    // Tags
    (0x1254c367, "Tags", Master, 1),
    (0x7373, "Tag", Master, 2),
    (0x63c0, "Targets", Master, 3),
    (0x68ca, "TargetTypeValue", UInt, 4),
    (0x63ca, "TargetType", Str, 4),
    (0x63c5, "TagTrackUID", UInt, 4),
    (0x63c9, "TagEditionUID", UInt, 4),
    (0x63c4, "TagChapterUID", UInt, 4),
    (0x63c6, "TagAttachmentUID", UInt, 4),
    (0x67c8, "SimpleTag", Master, 3),
    (0x45a3, "TagName", Utf8, 4),
    (0x447a, "TagLanguage", Str, 4),
    (0x447b, "TagLanguageBCP47", Str, 4),
    (0x4484, "TagDefault", UInt, 4),
    (0x4487, "TagString", Utf8, 4),
    (0x4485, "TagBinary", Binary, 4),
];

fn lookup(id: u32) -> Option<&'static Def> {
    SCHEMA.iter().find(|d| d.0 == id)
}

fn name_of(id: u32) -> String {
    lookup(id).map_or_else(|| format!("Unknown {id:#x}"), |d| d.1.to_owned())
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
        "V_MPEG1" => "MPEG-1 video",
        "V_MPEG2" => "MPEG-2 video",
        "V_MPEG4/ISO/ASP" | "V_MPEG4/ISO/SP" | "V_MPEG4/ISO/AP" => "MPEG-4 Visual",
        "V_MS/VFW/FOURCC" => "VfW",
        "V_PRORES" => "ProRes",
        "V_FFV1" => "FFV1",
        "V_MJPEG" => "Motion JPEG",
        "V_UNCOMPRESSED" => "uncompressed video",
        "A_OPUS" => "Opus",
        "A_VORBIS" => "Vorbis",
        "A_AAC" | "A_AAC/MPEG4/LC" | "A_AAC/MPEG2/LC" => "AAC",
        "A_FLAC" => "FLAC",
        "A_MPEG/L3" => "MP3",
        "A_MPEG/L2" => "MP2",
        "A_AC3" => "AC-3",
        "A_EAC3" => "E-AC-3",
        "A_DTS" => "DTS",
        "A_TRUEHD" => "TrueHD",
        "A_ALAC" => "ALAC",
        "A_PCM/INT/LIT" | "A_PCM/INT/BIG" | "A_PCM/FLOAT/IEEE" => "PCM",
        "S_TEXT/UTF8" => "SRT",
        "S_TEXT/ASS" | "S_TEXT/SSA" => "ASS",
        "S_TEXT/WEBVTT" => "WebVTT",
        "S_HDMV/PGS" => "PGS",
        "S_VOBSUB" => "VobSub",
        other => other,
    }
}

// ---------------------------------------------------------------------------
// Walking

#[derive(Clone, Copy, Debug)]
struct Element {
    input: Input,
    span: Span,
    id: u32,
    header_len: u64,
    depth: u32,
    /// TimestampScale of the segment (ns per tick).
    scale: u64,
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
            && def.3 <= level
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
async fn elements(cx: &Cx, input: Input, region: Span, depth: u32, scale: u64) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit(format!("elements nested deeper than {MAX_DEPTH}")).at(region));
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
        let level = lookup(h.id).map_or(255, |d| d.3);
        let data_len = match h.size {
            Some(n) => n,
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
            scale,
        };
        let mut node = element_node(cx, &el).await?;
        if el.span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(el.span.source, el.span.offset, total),
                el.span.len,
            ));
        }
        if h.size.is_none() {
            node = node.desc("Unknown size: ends at the next element of the same level");
        }
        cx.push(node).await;
        pos = pos.saturating_add(total.max(1));
    }
    Ok(())
}

/// The node for one element: a value for leaves, a lazy expander for
/// masters and blocks.
async fn element_node(cx: &Cx, el: &Element) -> Result<Node> {
    let name = name_of(el.id);
    let node = Node::new(name).span(el.span);
    let data = el.data();
    let Some(def) = el.def() else {
        return Ok(node.summary(format!("{} bytes", data.len)).value(Value::UInt {
            value: el.id.into(),
            bits: 32,
            radix: Radix::Hex,
        }));
    };
    Ok(match def.2 {
        Master => {
            let summary = master_summary(cx, el).await;
            let node = node.lazy(crate::expander!(self::master: Element), *el);
            match summary {
                Some(s) => node.summary(s),
                None => node,
            }
        }
        Block => {
            let head = cx.read_avail(data.sub(0, 12)).await?;
            let node = node.lazy(block, *el);
            match block_summary(&head, el.id == 0xa3) {
                Some(s) => node.summary(s),
                None => node,
            }
        }
        Binary => {
            if el.id == 0x465c {
                embedded(def.1, el.input.nested(data)).summary(format!("{} bytes", data.len))
            } else if data.len <= 32 {
                let d = cx.read_avail(data).await?;
                let summary = if el.id == 0x53ab {
                    Some(name_of(u32::try_from(be_uint(&d)).unwrap_or(0)))
                } else {
                    None
                };
                let node = node.value(Value::Bytes(d));
                match summary {
                    Some(s) => node.summary(s),
                    None => node,
                }
            } else {
                node.summary(format!("{} bytes", data.len))
            }
        }
        kind => {
            let d = cx.read_avail(data.sub(0, 0x1000)).await?;
            leaf(node, kind, &d, el)
        }
    })
}

fn leaf(node: Node, kind: Kind, d: &[u8], el: &Element) -> Node {
    match kind {
        Kind::UInt => {
            let v = be_uint(d);
            let node = node.value(Value::UInt {
                value: v,
                bits: 64,
                radix: Radix::Dec,
            });
            match el.id {
                0x23e383 if v > 0 => node.summary(format!(
                    "{} ms, {} fps",
                    vidutil::num(v as f64 / 1e6),
                    vidutil::num(1e9 / v as f64)
                )),
                0x2ad7b1 => node.summary("ns per tick"),
                0xe7 | 0xb3 | 0x91 | 0x92 => node.summary(seconds_f64(ticks(v, el.scale))),
                _ => node,
            }
        }
        Kind::Enum(table) => {
            let v = be_uint(d);
            node.value(Value::Enum {
                raw: v,
                bits: 64,
                name: crate::value::lookup(table, v),
            })
        }
        Kind::Int => node.value(Value::Int {
            value: be_int(d),
            bits: 64,
        }),
        Kind::Float => match be_float(d) {
            Some(f) => {
                let node = node.value(Value::Float(f));
                if el.id == 0x4489 {
                    node.summary(seconds_f64(f * el.scale as f64 / 1e9))
                } else {
                    node
                }
            }
            None => node.diag(Diagnostic::malformed("float of invalid size")),
        },
        Kind::Str | Kind::Utf8 => node.value(Value::Text(text(d))),
        Kind::Date => {
            let ns = be_int(d);
            node.value(Value::Timestamp {
                unix_seconds: (ns / 1_000_000_000).saturating_add(978_307_200),
            })
        }
        _ => node,
    }
}

/// Seconds for `v` ticks of `scale` nanoseconds.
fn ticks(v: u64, scale: u64) -> f64 {
    v as f64 * scale as f64 / 1e9
}

async fn master(cx: Cx, el: Element) -> Result<()> {
    let mut scale = el.scale;
    if el.id == 0x18538067 {
        scale = segment_scale(&cx, el.data()).await.unwrap_or(DEFAULT_SCALE);
    }
    elements(&cx, el.input, el.data(), el.depth.saturating_add(1), scale).await
}

/// The TimestampScale from the segment's Info element.
async fn segment_scale(cx: &Cx, segment: Span) -> Option<u64> {
    let info = find_top(cx, segment, &[0x1549a966]).await.ok()?.into_iter().next()?;
    let d = vidutil::read_small(cx, info.1, 0x10000).await.ok()?;
    mem_children(&d)
        .find(|(id, _)| *id == 0x2ad7b1)
        .map(|(_, v)| be_uint(v))
        .filter(|&s| s > 0)
}

/// Finds top-level children of `segment` with the given IDs, stopping at
/// the first Cluster. Returns (id, data span).
async fn find_top(cx: &Cx, segment: Span, ids: &[u32]) -> Result<Vec<(u32, Span)>> {
    let mut out = Vec::new();
    let mut pos = 0u64;
    let mut guard = 0u32;
    while pos < segment.len && guard < 64 {
        let h = read_header(cx, segment, pos).await?;
        let Some(size) = h.size else {
            break;
        };
        if h.id == 0x1f43b675 {
            break;
        }
        if ids.contains(&h.id) {
            out.push((h.id, segment.sub(pos.saturating_add(h.header_len), size)));
        }
        pos = pos.saturating_add(h.header_len).saturating_add(size);
        guard = guard.saturating_add(1);
    }
    Ok(out)
}

async fn master_summary(cx: &Cx, el: &Element) -> Option<String> {
    let data = el.data();
    match el.id {
        0x1f43b675 | 0xae | 0xbb | 0x4dbb | 0x61a7 | 0x67c8 | 0xb6 | 0x1a45dfa3 => {}
        _ => return None,
    }
    let d = vidutil::read_small(cx, data, 0x1000).await.ok()?;
    let mut fields = mem_children(&d);
    match el.id {
        0x1f43b675 => fields
            .find(|(id, _)| *id == 0xe7)
            .map(|(_, v)| format!("at {}", seconds_f64(ticks(be_uint(v), el.scale)))),
        0xae => Some(track_summary(&d).describe()),
        0xbb => {
            let mut time = None;
            let mut pos = None;
            for (id, v) in fields {
                match id {
                    0xb3 => time = Some(be_uint(v)),
                    0xb7 => {
                        pos = mem_children(v)
                            .find(|(i, _)| *i == 0xf1)
                            .map(|(_, p)| be_uint(p));
                    }
                    _ => {}
                }
            }
            Some(format!(
                "{} → cluster at segment offset {:#x}",
                seconds_f64(ticks(time?, el.scale)),
                pos?
            ))
        }
        0x4dbb => {
            let mut id = None;
            let mut pos = None;
            for (i, v) in fields {
                match i {
                    0x53ab => id = Some(u32::try_from(be_uint(v)).unwrap_or(0)),
                    0x53ac => pos = Some(be_uint(v)),
                    _ => {}
                }
            }
            Some(format!("{} at segment offset {:#x}", name_of(id?), pos?))
        }
        0x61a7 => fields
            .find(|(id, _)| *id == 0x466e)
            .map(|(_, v)| text(v)),
        0x67c8 => {
            let mut name = None;
            let mut value = None;
            for (i, v) in fields {
                match i {
                    0x45a3 => name = Some(text(v)),
                    0x4487 => value = Some(text(v)),
                    _ => {}
                }
            }
            Some(format!("{} = {}", name?, value.unwrap_or_default()))
        }
        0xb6 => fields.find(|(id, _)| *id == 0x80).and_then(|(_, v)| {
            mem_children(v)
                .find(|(i, _)| *i == 0x85)
                .map(|(_, s)| text(s))
        }),
        0x1a45dfa3 => {
            let mut doc = None;
            let mut version = None;
            for (i, v) in fields {
                match i {
                    0x4282 => doc = Some(text(v)),
                    0x4287 => version = Some(be_uint(v)),
                    _ => {}
                }
            }
            Some(format!("{} v{}", doc?, version.unwrap_or(1)))
        }
        _ => None,
    }
}

#[derive(Debug, Default)]
struct TrackSummary {
    number: u64,
    kind: u64,
    codec: String,
    width: u64,
    height: u64,
    channels: u64,
    rate: f64,
    language: Option<String>,
    private: Vec<u8>,
}

impl TrackSummary {
    fn codec_detail(&self) -> String {
        let name = codec_name(&self.codec);
        let detail = match self.codec.as_str() {
            "V_MPEG4/ISO/AVC" => vidutil::avcc_summary(&self.private),
            "V_MPEGH/ISO/HEVC" => vidutil::hvcc_summary(&self.private),
            "A_AAC" => vidutil::asc_summary(&self.private),
            _ => None,
        };
        match detail {
            Some(d) => format!("{name} ({d})"),
            None => name.to_owned(),
        }
    }

    fn describe(&self) -> String {
        let kind = crate::value::lookup(TRACK_TYPES, self.kind).unwrap_or("track");
        let mut s = format!("#{} {kind}: {}", self.number, self.codec_detail());
        if self.width > 0 {
            s = format!("{s}, {}×{}", self.width, self.height);
        }
        if self.channels > 0 {
            s = format!("{s}, {} ch, {} Hz", self.channels, vidutil::num(self.rate));
        }
        if let Some(l) = &self.language {
            s = format!("{s}, {l}");
        }
        s
    }

    fn short(&self) -> String {
        let name = codec_name(&self.codec);
        if self.width > 0 {
            format!("{}×{} {name}", self.width, self.height)
        } else {
            name.to_owned()
        }
    }
}

fn track_summary(d: &[u8]) -> TrackSummary {
    let mut t = TrackSummary::default();
    for (id, v) in mem_children(d) {
        match id {
            0xd7 => t.number = be_uint(v),
            0x83 => t.kind = be_uint(v),
            0x86 => t.codec = text(v),
            0x22b59c => t.language = Some(text(v)),
            0x63a2 => t.private = v.get(..v.len().min(512)).unwrap_or_default().to_vec(),
            0xe0 => {
                for (i, w) in mem_children(v) {
                    match i {
                        0xb0 => t.width = be_uint(w),
                        0xba => t.height = be_uint(w),
                        _ => {}
                    }
                }
            }
            0xe1 => {
                t.rate = 8000.0;
                t.channels = 1;
                for (i, w) in mem_children(v) {
                    match i {
                        0xb5 => t.rate = be_float(w).unwrap_or(0.0),
                        0x9f => t.channels = be_uint(w),
                        _ => {}
                    }
                }
            }
            _ => {}
        }
    }
    t
}

// ---------------------------------------------------------------------------
// Blocks

const LACING: EnumTable = &[(0, "none"), (1, "Xiph"), (2, "fixed-size"), (3, "EBML")];

fn block_summary(d: &[u8], simple: bool) -> Option<String> {
    let (track, len) = vint(d)?;
    let at = len;
    let tc = i16::from_be_bytes([*d.get(at)?, *d.get(at.checked_add(1)?)?]);
    let flags = *d.get(at.checked_add(2)?)?;
    let mut s = format!("track {}, {tc:+}", track?);
    if simple && flags & 0x80 != 0 {
        s.push_str(", keyframe");
    }
    if flags & 0x06 != 0 {
        s.push_str(", laced");
    }
    Some(s)
}

async fn block(cx: Cx, el: Element) -> Result<()> {
    let data = el.data();
    let d = cx.read_avail(data.sub(0, 16)).await?;
    let Some((track, len)) = vint(&d) else {
        return Err(Diagnostic::malformed("invalid track number").at(data));
    };
    let at = to_u64(len);
    cx.emit(uint("Track number", data.sub(0, at), track.unwrap_or(0), 64));
    let tc = d
        .get(len..len.saturating_add(2))
        .map(|b| b.iter().fold(0u16, |acc, &x| (acc << 8) | u16::from(x)));
    let Some(tc) = tc else {
        return Err(Diagnostic::truncated(data.sub(at, 3), 0));
    };
    cx.emit(
        Node::new("Relative timestamp")
            .span(data.sub(at, 2))
            .value(Value::Int {
                value: i16::from_ne_bytes(tc.to_ne_bytes()).into(),
                bits: 16,
            })
            .summary(format!(
                "{} s",
                vidutil::num(f64::from(i16::from_ne_bytes(tc.to_ne_bytes())) * el.scale as f64 / 1e9)
            )),
    );
    let fspan = data.sub(at.saturating_add(2), 1);
    let flags = d.get(len.saturating_add(2)).copied().unwrap_or(0);
    let simple = el.id == 0xa3;
    let mut set = Vec::new();
    if simple && flags & 0x80 != 0 {
        set.push("KEYFRAME");
    }
    if flags & 0x08 != 0 {
        set.push("INVISIBLE");
    }
    if simple && flags & 0x01 != 0 {
        set.push("DISCARDABLE");
    }
    cx.emit(Node::new("Flags").span(fspan).value(Value::Flags {
        raw: flags.into(),
        bits: 8,
        set,
        unknown: 0,
    }));
    cx.emit(vidutil::enumerated(
        "Lacing",
        fspan,
        u64::from((flags >> 1) & 3),
        2,
        LACING,
    ));
    let payload = data.tail(at.saturating_add(3));
    cx.emit(
        Node::new("Frame data")
            .span(payload)
            .summary(format!("{} bytes", payload.len)),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    if let Some(s) = file_summary(&cx, input.span).await {
        cx.annotate(s);
    }
    elements(&cx, input, input.span, 0, DEFAULT_SCALE).await
}

/// "WebM (v4), 16×16 VP9 + Opus, 00:00:00.200, "title"".
async fn file_summary(cx: &Cx, file: Span) -> Option<String> {
    let mut pos = 0u64;
    let mut label = String::from("Matroska");
    let mut segment = None;
    for _ in 0..4 {
        let h = read_header(cx, file, pos).await.ok()?;
        let data_start = pos.saturating_add(h.header_len);
        match h.id {
            0x1a45dfa3 => {
                let d = vidutil::read_small(cx, file.sub(data_start, h.size?), 0x1000).await.ok()?;
                let mut doc = String::new();
                let mut version = 0;
                for (id, v) in mem_children(&d) {
                    match id {
                        0x4282 => doc = text(v),
                        0x4287 => version = be_uint(v),
                        _ => {}
                    }
                }
                label = format!(
                    "{} (v{version})",
                    if doc == "webm" { "WebM" } else { "Matroska" }
                );
            }
            0x18538067 => {
                let len = h.size.unwrap_or(file.len.saturating_sub(data_start));
                segment = Some(file.sub(data_start, len));
                break;
            }
            _ => {}
        }
        pos = data_start.saturating_add(h.size?);
    }
    let Some(segment) = segment else {
        return Some(label);
    };
    let found = find_top(cx, segment, &[0x1549a966, 0x1654ae6b]).await.ok()?;
    let mut parts = vec![label];
    let mut duration = None;
    let mut title = None;
    for (id, span) in found {
        let d = vidutil::read_small(cx, span, 0x100000).await.ok()?;
        if id == 0x1549a966 {
            let mut scale = DEFAULT_SCALE;
            let mut dur = None;
            for (i, v) in mem_children(&d) {
                match i {
                    0x2ad7b1 => scale = be_uint(v),
                    0x4489 => dur = be_float(v),
                    0x7ba9 => title = Some(text(v)),
                    _ => {}
                }
            }
            duration = dur.map(|f| seconds_f64(f * scale as f64 / 1e9));
        } else {
            let tracks: Vec<String> = mem_children(&d)
                .filter(|(i, _)| *i == 0xae)
                .map(|(_, v)| track_summary(v).short())
                .collect();
            if !tracks.is_empty() {
                parts.push(tracks.join(" + "));
            }
        }
    }
    if let Some(d) = duration {
        parts.push(d);
    }
    if let Some(t) = title {
        parts.push(format!("\"{t}\""));
    }
    Some(parts.join(", "))
}
