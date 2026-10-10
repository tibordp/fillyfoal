//! ID3 tags: ID3v2.2/2.3/2.4 (prepended to MP3, AAC and FLAC files,
//! appended to MP3 files and embedded in WAV/AIFF chunks), ID3v1/1.1 and
//! the Enhanced TAG+ (the last bytes of a file), and Lyrics3 (before
//! ID3v1).
//!
//! A v2 tag lists its frames lazily. Every common frame is decoded: text
//! (all four encodings, several values per frame), comments and lyrics
//! (also synchronised), pictures and encapsulated objects (dissected as
//! embedded content), URLs, private data, unique file identifiers,
//! popularimeter and play counter, relative volume and equalisation,
//! event timing codes, chapters and tables of contents (with their own
//! sub-frames). Unsynchronised tags and frames are decoded into derived
//! sources, compressed frames are inflated.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{
    clip, enumerated, hex, image_info, latin1_field, latin1_z, leaf, text, uint,
};
use crate::formats::{Format, Input, Probe, audio::apetag, embedded};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const BE: Endian = Endian::Big;

/// A file that is only an ID3v2 tag (as written by some taggers), or an
/// ID3 tag followed by data we do not recognise.
pub static FORMAT: Format = Format {
    name: "id3",
    title: "ID3v2 tag",
    extensions: &["id3", "tag"],
    mime: "application/x-id3",
    probe: Probe::Custom(|h| v2_len(h.data).is_some()),
    dissect: crate::expander!(dissect: Input),
};

/// Total length (header, frames, padding, footer) of the ID3v2 tag at the
/// start of `data`, if there is a plausible one.
pub fn v2_len(data: &[u8]) -> Option<u64> {
    if !data.starts_with(b"ID3") {
        return None;
    }
    let major = *data.get(3)?;
    let flags = *data.get(5)?;
    if !(2..=4).contains(&major) || *data.get(4)? == 0xff {
        return None;
    }
    let size = syncsafe(data.get(6..10)?)?;
    let footer = if major == 4 && flags & 0x10 != 0 {
        10
    } else {
        0
    };
    Some(u64::from(size).saturating_add(10).saturating_add(footer))
}

/// A 28-bit integer stored 7 bits per byte.
fn syncsafe(b: &[u8]) -> Option<u32> {
    if b.len() != 4 || b.iter().any(|&x| x & 0x80 != 0) {
        return None;
    }
    Some(
        b.iter()
            .fold(0u32, |acc, &x| (acc << 7) | u32::from(x & 0x7f)),
    )
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 10)).await?;
    let len = v2_len(&head).ok_or_else(|| Diagnostic::malformed("not an ID3v2 tag"))?;
    let span = input.span.sub(0, len);
    let summary = summary(&cx, span).await;
    cx.annotate(summary.clone().unwrap_or_else(|_| "ID3v2 tag".to_owned()));
    tag(&cx, input, span).await?;
    let rest = input.span.tail(len);
    if !rest.is_empty() {
        cx.emit(embedded("Trailing data", input.nested(rest)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ID3v2 tables

const TAG_FLAGS_22: FlagTable = &[flag(0x80, "UNSYNCHRONISATION"), flag(0x40, "COMPRESSION")];

const TAG_FLAGS_23: FlagTable = &[
    flag(0x80, "UNSYNCHRONISATION"),
    flag(0x40, "EXTENDED_HEADER"),
    flag(0x20, "EXPERIMENTAL"),
];

const TAG_FLAGS_24: FlagTable = &[
    flag(0x80, "UNSYNCHRONISATION"),
    flag(0x40, "EXTENDED_HEADER"),
    flag(0x20, "EXPERIMENTAL"),
    flag(0x10, "FOOTER"),
];

const EXT_FLAGS_23: FlagTable = &[flag(0x8000, "CRC")];

const EXT_FLAGS_24: FlagTable = &[
    flag(0x40, "TAG_IS_UPDATE"),
    flag(0x20, "CRC"),
    flag(0x10, "RESTRICTIONS"),
];

const RESTRICTIONS: FlagTable = &[
    field(0xc0, 0x40, "TAG_64_FRAMES_128KB"),
    field(0xc0, 0x80, "TAG_32_FRAMES_40KB"),
    field(0xc0, 0xc0, "TAG_32_FRAMES_4KB"),
    flag(0x20, "TEXT_LATIN1_OR_UTF8"),
    field(0x18, 0x08, "TEXT_1024_CHARS"),
    field(0x18, 0x10, "TEXT_128_CHARS"),
    field(0x18, 0x18, "TEXT_30_CHARS"),
    flag(0x04, "IMAGE_PNG_OR_JPEG"),
    field(0x03, 0x01, "IMAGE_256PX"),
    field(0x03, 0x02, "IMAGE_64PX"),
    field(0x03, 0x03, "IMAGE_64PX_EXACT"),
];

const FRAME_FLAGS_23: FlagTable = &[
    flag(0x8000, "TAG_ALTER_PRESERVATION"),
    flag(0x4000, "FILE_ALTER_PRESERVATION"),
    flag(0x2000, "READ_ONLY"),
    flag(0x0080, "COMPRESSION"),
    flag(0x0040, "ENCRYPTION"),
    flag(0x0020, "GROUPING"),
];

const FRAME_FLAGS_24: FlagTable = &[
    flag(0x4000, "TAG_ALTER_PRESERVATION"),
    flag(0x2000, "FILE_ALTER_PRESERVATION"),
    flag(0x1000, "READ_ONLY"),
    flag(0x0040, "GROUPING"),
    flag(0x0008, "COMPRESSION"),
    flag(0x0004, "ENCRYPTION"),
    flag(0x0002, "UNSYNCHRONISATION"),
    flag(0x0001, "DATA_LENGTH_INDICATOR"),
];

const CTOC_FLAGS: FlagTable = &[flag(0x1, "ORDERED"), flag(0x2, "TOP_LEVEL")];

const ENCODING: EnumTable = &[
    (0, "ISO-8859-1"),
    (1, "UTF-16 with BOM"),
    (2, "UTF-16BE"),
    (3, "UTF-8"),
];

pub const PICTURE_TYPE: EnumTable = &[
    (0, "Other"),
    (1, "File icon (32×32 PNG)"),
    (2, "Other file icon"),
    (3, "Cover (front)"),
    (4, "Cover (back)"),
    (5, "Leaflet page"),
    (6, "Media"),
    (7, "Lead artist"),
    (8, "Artist"),
    (9, "Conductor"),
    (10, "Band"),
    (11, "Composer"),
    (12, "Lyricist"),
    (13, "Recording location"),
    (14, "During recording"),
    (15, "During performance"),
    (16, "Screen capture"),
    (17, "A bright coloured fish"),
    (18, "Illustration"),
    (19, "Band logotype"),
    (20, "Publisher logotype"),
];

const TIMESTAMP_FORMAT: EnumTable = &[(1, "MPEG frames"), (2, "milliseconds")];

const SYLT_CONTENT: EnumTable = &[
    (0, "other"),
    (1, "lyrics"),
    (2, "text transcription"),
    (3, "movement/part name"),
    (4, "events"),
    (5, "chord"),
    (6, "trivia/pop-up"),
    (7, "URLs of webpages"),
    (8, "URLs of images"),
];

const CHANNEL_TYPE: EnumTable = &[
    (0, "other"),
    (1, "master volume"),
    (2, "front right"),
    (3, "front left"),
    (4, "back right"),
    (5, "back left"),
    (6, "front centre"),
    (7, "back centre"),
    (8, "subwoofer"),
];

const EVENT: EnumTable = &[
    (0x00, "padding"),
    (0x01, "end of initial silence"),
    (0x02, "intro start"),
    (0x03, "main part start"),
    (0x04, "outro start"),
    (0x05, "outro end"),
    (0x06, "verse start"),
    (0x07, "refrain start"),
    (0x08, "interlude start"),
    (0x09, "theme start"),
    (0x0a, "variation start"),
    (0x0b, "key change"),
    (0x0c, "time change"),
    (0x0d, "momentary unwanted noise"),
    (0x0e, "sustained noise"),
    (0x0f, "sustained noise end"),
    (0x10, "intro end"),
    (0x11, "main part end"),
    (0x12, "verse end"),
    (0x13, "refrain end"),
    (0x14, "theme end"),
    (0x15, "profanity"),
    (0x16, "profanity end"),
    (0xfd, "audio end (start of silence)"),
    (0xfe, "audio file ends"),
];

const FRAMES: &[(&str, &str)] = &[
    ("AENC", "Audio encryption"),
    ("APIC", "Attached picture"),
    ("ASPI", "Audio seek point index"),
    ("CHAP", "Chapter"),
    ("COMM", "Comment"),
    ("COMR", "Commercial frame"),
    ("CTOC", "Table of contents"),
    ("ENCR", "Encryption method registration"),
    ("EQU2", "Equalisation"),
    ("EQUA", "Equalisation"),
    ("ETCO", "Event timing codes"),
    ("GEOB", "General encapsulated object"),
    ("GRID", "Group identification registration"),
    ("GRP1", "Grouping (iTunes)"),
    ("IPLS", "Involved people list"),
    ("LINK", "Linked information"),
    ("MCDI", "Music CD identifier"),
    ("MLLT", "MPEG location lookup table"),
    ("MVIN", "Movement number (iTunes)"),
    ("MVNM", "Movement name (iTunes)"),
    ("OWNE", "Ownership frame"),
    ("PCNT", "Play counter"),
    ("PCST", "Podcast flag (iTunes)"),
    ("POPM", "Popularimeter"),
    ("POSS", "Position synchronisation"),
    ("PRIV", "Private frame"),
    ("RBUF", "Recommended buffer size"),
    ("RVA2", "Relative volume adjustment"),
    ("RVAD", "Relative volume adjustment"),
    ("RVRB", "Reverb"),
    ("SEEK", "Seek frame"),
    ("SIGN", "Signature frame"),
    ("SYLT", "Synchronised lyrics"),
    ("SYTC", "Synchronised tempo codes"),
    ("TALB", "Album"),
    ("TBPM", "BPM"),
    ("TCAT", "Podcast category (iTunes)"),
    ("TCMP", "Compilation (iTunes)"),
    ("TCOM", "Composer"),
    ("TCON", "Genre"),
    ("TCOP", "Copyright"),
    ("TDAT", "Date (DDMM)"),
    ("TDEN", "Encoding time"),
    ("TDES", "Podcast description (iTunes)"),
    ("TDLY", "Playlist delay"),
    ("TDOR", "Original release time"),
    ("TDRC", "Recording time"),
    ("TDRL", "Release time"),
    ("TDTG", "Tagging time"),
    ("TENC", "Encoded by"),
    ("TEXT", "Lyricist"),
    ("TFLT", "File type"),
    ("TGID", "Podcast ID (iTunes)"),
    ("TIME", "Time (HHMM)"),
    ("TIPL", "Involved people list"),
    ("TIT1", "Content group"),
    ("TIT2", "Title"),
    ("TIT3", "Subtitle"),
    ("TKEY", "Initial key"),
    ("TKWD", "Podcast keywords (iTunes)"),
    ("TLAN", "Language"),
    ("TLEN", "Length"),
    ("TMCL", "Musician credits"),
    ("TMED", "Media type"),
    ("TMOO", "Mood"),
    ("TOAL", "Original album"),
    ("TOFN", "Original filename"),
    ("TOLY", "Original lyricist"),
    ("TOPE", "Original artist"),
    ("TORY", "Original release year"),
    ("TOWN", "File owner"),
    ("TPE1", "Artist"),
    ("TPE2", "Album artist"),
    ("TPE3", "Conductor"),
    ("TPE4", "Remixed by"),
    ("TPOS", "Disc"),
    ("TPRO", "Produced notice"),
    ("TPUB", "Publisher"),
    ("TRCK", "Track"),
    ("TRDA", "Recording dates"),
    ("TRSN", "Internet radio station"),
    ("TRSO", "Internet radio station owner"),
    ("TSIZ", "Size"),
    ("TSO2", "Album artist sort order (iTunes)"),
    ("TSOA", "Album sort order"),
    ("TSOC", "Composer sort order (iTunes)"),
    ("TSOP", "Performer sort order"),
    ("TSOT", "Title sort order"),
    ("TSRC", "ISRC"),
    ("TSSE", "Encoder settings"),
    ("TSST", "Set subtitle"),
    ("TXXX", "User-defined text"),
    ("TYER", "Year"),
    ("UFID", "Unique file identifier"),
    ("USER", "Terms of use"),
    ("USLT", "Lyrics"),
    ("WCOM", "Commercial information"),
    ("WCOP", "Copyright information"),
    ("WFED", "Podcast feed (iTunes)"),
    ("WOAF", "Official audio file webpage"),
    ("WOAR", "Official artist webpage"),
    ("WOAS", "Official source webpage"),
    ("WORS", "Official internet radio station homepage"),
    ("WPAY", "Payment"),
    ("WPUB", "Publisher webpage"),
    ("WXXX", "User-defined URL"),
    ("PIC", "Attached picture"),
    ("CRM", "Encrypted meta frame"),
];

/// ID3v2.2 frame IDs and their ID3v2.3 equivalents.
const V22: &[(&str, &str)] = &[
    ("BUF", "RBUF"),
    ("CNT", "PCNT"),
    ("COM", "COMM"),
    ("CRA", "AENC"),
    ("EQU", "EQUA"),
    ("ETC", "ETCO"),
    ("GEO", "GEOB"),
    ("IPL", "IPLS"),
    ("LNK", "LINK"),
    ("MCI", "MCDI"),
    ("MLL", "MLLT"),
    ("POP", "POPM"),
    ("REV", "RVRB"),
    ("RVA", "RVAD"),
    ("SLT", "SYLT"),
    ("STC", "SYTC"),
    ("TAL", "TALB"),
    ("TBP", "TBPM"),
    ("TCM", "TCOM"),
    ("TCO", "TCON"),
    ("TCP", "TCMP"),
    ("TCR", "TCOP"),
    ("TDA", "TDAT"),
    ("TDY", "TDLY"),
    ("TEN", "TENC"),
    ("TFT", "TFLT"),
    ("TIM", "TIME"),
    ("TKE", "TKEY"),
    ("TLA", "TLAN"),
    ("TLE", "TLEN"),
    ("TMT", "TMED"),
    ("TOA", "TOPE"),
    ("TOF", "TOFN"),
    ("TOL", "TOLY"),
    ("TOR", "TORY"),
    ("TOT", "TOAL"),
    ("TP1", "TPE1"),
    ("TP2", "TPE2"),
    ("TP3", "TPE3"),
    ("TP4", "TPE4"),
    ("TPA", "TPOS"),
    ("TPB", "TPUB"),
    ("TRC", "TSRC"),
    ("TRD", "TRDA"),
    ("TRK", "TRCK"),
    ("TS2", "TSO2"),
    ("TSA", "TSOA"),
    ("TSC", "TSOC"),
    ("TSI", "TSIZ"),
    ("TSP", "TSOP"),
    ("TSS", "TSSE"),
    ("TST", "TSOT"),
    ("TT1", "TIT1"),
    ("TT2", "TIT2"),
    ("TT3", "TIT3"),
    ("TXT", "TEXT"),
    ("TXX", "TXXX"),
    ("TYE", "TYER"),
    ("UFI", "UFID"),
    ("ULT", "USLT"),
    ("WAF", "WOAF"),
    ("WAR", "WOAR"),
    ("WAS", "WOAS"),
    ("WCM", "WCOM"),
    ("WCP", "WCOP"),
    ("WPB", "WPUB"),
    ("WXX", "WXXX"),
];

/// The ID3v2.3/2.4 ID a frame is decoded as.
fn normalize(id: &str) -> &str {
    V22.iter()
        .find(|(old, _)| *old == id)
        .map_or(id, |(_, new)| *new)
}

fn frame_name(id: &str) -> Option<&'static str> {
    let id = normalize(id);
    FRAMES.iter().find(|(k, _)| *k == id).map(|(_, v)| *v)
}

/// Text frames that do not start with `T`.
fn is_text(id: &str) -> bool {
    (id.starts_with('T') && id != "TXXX") || matches!(id, "GRP1" | "MVNM" | "MVIN")
}

// ---------------------------------------------------------------------------
// ID3v2 structure

/// Everything a frame expansion needs.
#[derive(Clone, Debug)]
struct Tag {
    input: Input,
    major: u8,
    /// ID3v2.4: every frame is unsynchronised.
    unsync: bool,
    /// ID3v2.4 frame sizes written as plain integers (iTunes did).
    plain_sizes: bool,
}

#[derive(Clone, Debug)]
struct Frame {
    tag: Tag,
    id: String,
    /// Header and data.
    span: Span,
    header_len: u64,
    flags: u16,
}

/// A lazy node for the ID3v2 tag at `span`, with a summary.
pub async fn tag_node(cx: &Cx, input: Input, span: Span) -> Node {
    let node = Node::new("ID3v2 tag")
        .span(span)
        .lazy(expand_tag, (input, span));
    match summary(cx, span).await {
        Ok(s) => node.summary(s),
        Err(e) => node.diag(e),
    }
}

async fn expand_tag(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    tag(&cx, input, span).await
}

fn tag_flags(major: u8) -> FlagTable {
    match major {
        2 => TAG_FLAGS_22,
        3 => TAG_FLAGS_23,
        _ => TAG_FLAGS_24,
    }
}

/// The tag header (and the ID3v2.4 footer, which repeats it as `3DI`).
fn header_layout(f: &mut Fields<'_>, _: &()) -> Result<(u8, u8, u32)> {
    f.ascii("Identifier", 3).emit()?;
    let major = f
        .u8("Major version")
        .with(|&v, n| n.summary(format!("ID3v2.{v}")))
        .emit()?;
    f.u8("Revision").emit()?;
    let flags = f.u8("Flags").flags(tag_flags(major)).emit()?;
    let size = f
        .bytes("Size", 4)
        .map(|b| syncsafe(&b).unwrap_or(0))
        .with(|&s, n| n.value(uint(s, 28)).summary(human_size(s.into())))
        .desc("Syncsafe (7 bits per byte); excludes the header and footer")
        .emit()?;
    Ok((major, flags, size))
}

/// The extended header (`major` 3 or 4).
fn ext_layout(f: &mut Fields<'_>, &major: &u8) -> Result<()> {
    if major == 3 {
        f.u32("Size").desc("Excluding this field").emit()?;
        let flags = f.u16("Flags").flags(EXT_FLAGS_23).emit()?;
        f.u32("Padding size").emit()?;
        if flags & 0x8000 != 0 {
            f.u32("CRC-32")
                .hex()
                .desc("Of the frames, before unsynchronisation")
                .emit()?;
        }
        return Ok(());
    }
    f.bytes("Size", 4)
        .map(|b| syncsafe(&b).unwrap_or(0))
        .with(|&s, n| n.value(uint(s, 28)))
        .desc("Syncsafe; including this field")
        .emit()?;
    let count = f.u8("Flag bytes").emit()?;
    let flags = f.u8("Flags").flags(EXT_FLAGS_24).emit()?;
    f.skip(u64::from(count).saturating_sub(1));
    if flags & 0x40 != 0 {
        f.u8("Update data length").emit()?;
    }
    if flags & 0x20 != 0 {
        f.u8("CRC data length").emit()?;
        f.bytes("CRC-32", 5)
            .map(|b| b.iter().fold(0u64, |a, &x| (a << 7) | u64::from(x & 0x7f)))
            .with(|&v, n| n.value(hex(v, 32)))
            .desc("Of the frames and padding; syncsafe (35 bits)")
            .emit()?;
    }
    if flags & 0x10 != 0 {
        f.u8("Restrictions data length").emit()?;
        f.u8("Restrictions").flags(RESTRICTIONS).emit()?;
    }
    Ok(())
}

/// The length of the extended header at the start of `body`.
async fn ext_len(cx: &Cx, body: Span, major: u8) -> Result<u64> {
    let raw = cx.read(body.sub(0, 4)).await?;
    let len = if major == 4 {
        syncsafe(&raw).unwrap_or(0).into()
    } else {
        u64::from(u32_be(&raw, 0).unwrap_or(0)).saturating_add(4)
    };
    Ok(len.min(body.len))
}

/// Header fields and frames of the tag at `span`.
async fn tag(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let header_span = span.sub(0, 10);
    let (major, flags, size) = parse(cx, header_span, BE, &(), header_layout).await?;
    cx.emit(struct_node("Header", header_span, BE, (), header_layout));
    let mut body = span.sub(10, size.into());
    if major == 2 && flags & 0x40 != 0 {
        cx.emit(Node::new("Frames").span(body).diag(Diagnostic::unsupported(
            "ID3v2.2 tag compression (never specified)",
        )));
        return Ok(());
    }
    // ID3v2.2 and 2.3 unsynchronise the whole tag (ID3v2.4 each frame).
    if flags & 0x80 != 0 && major < 4 {
        body = resync(cx, body).await?;
        cx.diag(Diagnostic::note(
            "unsynchronised tag: frames are shown with the unsynchronisation undone",
        ));
    }
    let mut pos = 0u64;
    if flags & 0x40 != 0 && major >= 3 {
        pos = ext_len(cx, body, major).await?;
        cx.emit(struct_node(
            "Extended header",
            body.sub(0, pos),
            BE,
            major,
            ext_layout,
        ));
    }
    let region = body.tail(pos);
    let tag = Tag {
        input,
        major,
        unsync: major == 4 && flags & 0x80 != 0,
        plain_sizes: major == 4 && plain_sizes(cx, region).await?,
    };
    if tag.plain_sizes {
        cx.diag(Diagnostic::warning(
            "frame sizes are plain integers, not syncsafe as ID3v2.4 requires",
        ));
    }
    frames(cx, &tag, region).await?;
    if major == 4 && flags & 0x10 != 0 {
        let footer = span.sub(10u64.saturating_add(size.into()), 10);
        cx.emit(struct_node("Footer", footer, BE, (), header_layout));
    }
    Ok(())
}

/// Undoes unsynchronisation (`ff 00` → `ff`) into a derived source.
async fn resync(cx: &Cx, span: Span) -> Result<Span> {
    let origin = Origin {
        parent: span,
        transform: "id3-unsync",
    };
    if let Some(d) = cx.derived(origin) {
        return Ok(d.span);
    }
    let data = cx.read(span).await?;
    let mut out = Vec::with_capacity(data.len());
    let mut prev = 0u8;
    for chunk in data.chunks(0x10000) {
        for &b in chunk {
            if !(prev == 0xff && b == 0) {
                out.push(b);
            }
            prev = b;
        }
        cx.checkpoint().await;
    }
    Ok(cx.add_derived(origin, out, span.len, None)?.span)
}

/// `ff 00` → `ff` on a small buffer.
fn unsync_bytes(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut prev = 0u8;
    for &b in data {
        if !(prev == 0xff && b == 0) {
            out.push(b);
        }
        prev = b;
    }
    out
}

/// A frame header: ID, size and flags.
fn frame_header(head: &[u8], major: u8, plain: bool) -> Option<(String, u32, u16)> {
    let (id, size, flags) = if major == 2 {
        (head.get(..3)?, crate::bytes::u24_be(head, 3)?, 0)
    } else {
        let raw = head.get(4..8)?;
        let size = if major == 4 && !plain {
            syncsafe(raw).unwrap_or_else(|| u32_be(raw, 0).unwrap_or(0))
        } else {
            u32_be(raw, 0)?
        };
        (head.get(..4)?, size, u16_be(head, 8)?)
    };
    if !id
        .iter()
        .all(|c| c.is_ascii_uppercase() || c.is_ascii_digit())
    {
        return None;
    }
    Some((String::from_utf8_lossy(id).into_owned(), size, flags))
}

/// Walks up to 64 frame headers of an ID3v2.4 tag: how many were valid and
/// whether the walk ended where the frames should (padding or the end).
async fn walk_sizes(cx: &Cx, region: Span, plain: bool) -> Result<(u32, bool)> {
    let mut pos = 0u64;
    let mut count = 0u32;
    while count < 64 && region.len.saturating_sub(pos) >= 10 {
        let head = cx.read(region.sub(pos, 10)).await?;
        if head.first().is_none_or(|&b| b == 0) {
            return Ok((count, true));
        }
        let Some((_, size, _)) = frame_header(&head, 4, plain) else {
            return Ok((count, false));
        };
        count = count.saturating_add(1);
        pos = pos.saturating_add(10).saturating_add(size.into());
    }
    Ok((count, pos <= region.len))
}

/// Whether an ID3v2.4 tag's frame sizes are plain integers: only if the
/// syncsafe reading goes wrong and the plain one does not.
async fn plain_sizes(cx: &Cx, region: Span) -> Result<bool> {
    let (safe, safe_ok) = walk_sizes(cx, region, false).await?;
    if safe_ok {
        return Ok(false);
    }
    let (plain, plain_ok) = walk_sizes(cx, region, true).await?;
    Ok(plain_ok && plain >= safe)
}

/// Pushes one node per frame in `region`; stops at padding.
async fn frames(cx: &Cx, tag: &Tag, region: Span) -> Result<()> {
    let header_len: u64 = if tag.major == 2 { 6 } else { 10 };
    let mut pos = 0u64;
    while region.len.saturating_sub(pos) >= header_len {
        let head = cx.read(region.sub(pos, header_len)).await?;
        if head.first().is_none_or(|&b| b == 0) {
            cx.push(padding_node(cx, region.tail(pos)).await?).await;
            return Ok(());
        }
        let Some((id, size, flags)) = frame_header(&head, tag.major, tag.plain_sizes) else {
            cx.push(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed("invalid frame ID")),
            )
            .await;
            return Ok(());
        };
        let total = header_len.saturating_add(size.into());
        let frame = Frame {
            tag: tag.clone(),
            id,
            span: region.sub(pos, total),
            header_len,
            flags,
        };
        let node = frame_node(cx, frame, total).await;
        cx.push(node).await;
        pos = pos.saturating_add(total);
    }
    if pos < region.len {
        cx.push(padding_node(cx, region.tail(pos)).await?).await;
    }
    Ok(())
}

async fn padding_node(cx: &Cx, span: Span) -> Result<Node> {
    let head = cx.read_avail(span.sub(0, 4096)).await?;
    let mut node = Node::new("Padding")
        .span(span)
        .summary(human_size(span.len));
    if head.iter().any(|&b| b != 0) {
        node = node.diag(Diagnostic::warning("padding is not all zeros"));
    }
    Ok(node)
}

async fn frame_node(cx: &Cx, frame: Frame, total: u64) -> Node {
    let span = frame.span;
    let mut node = Node::new(frame.id.clone()).span(span);
    if let Some(name) = frame_name(&frame.id) {
        node = node.desc(name);
    }
    node = match frame_summary(cx, &frame).await {
        Ok(Some(s)) => node.summary(s),
        Ok(None) => node.summary(human_size(total.saturating_sub(frame.header_len))),
        Err(e) => node.diag(e),
    };
    if span.len < total {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, total),
            span.len,
        ));
    }
    node.lazy(crate::expander!(self::frame: Frame), frame)
}

// ---------------------------------------------------------------------------
// Frame flags and data

/// What the frame flags add between the header and the data.
#[derive(Clone, Copy, Debug)]
struct Extras {
    compressed: bool,
    encrypted: bool,
    unsync: bool,
    group: Option<(Span, u8)>,
    method: Option<(Span, u8)>,
    /// Decompressed size (ID3v2.3) or data length indicator (ID3v2.4).
    size: Option<(Span, u32)>,
    /// The (still encoded) data after them.
    data: Span,
}

async fn extras(cx: &Cx, frame: &Frame) -> Result<Extras> {
    let raw = frame.span.tail(frame.header_len);
    let f = frame.flags;
    let major = frame.tag.major;
    let mut e = Extras {
        compressed: false,
        encrypted: false,
        unsync: false,
        group: None,
        method: None,
        size: None,
        data: raw,
    };
    let (grouped, length) = match major {
        3 => {
            e.compressed = f & 0x0080 != 0;
            e.encrypted = f & 0x0040 != 0;
            (f & 0x0020 != 0, e.compressed)
        }
        4 => {
            e.compressed = f & 0x0008 != 0;
            e.encrypted = f & 0x0004 != 0;
            e.unsync = f & 0x0002 != 0 || frame.tag.unsync;
            (f & 0x0040 != 0, f & 0x0001 != 0)
        }
        _ => return Ok(e),
    };
    let head = cx.read_avail(raw.sub(0, 6)).await?;
    let mut at = 0usize;
    let byte = |at: &mut usize| {
        let span = raw.sub(to_u64(*at), 1);
        let v = head.get(*at).copied().unwrap_or(0);
        *at = at.saturating_add(1);
        Some((span, v))
    };
    let size = |at: &mut usize| {
        let bytes = head.get(*at..at.saturating_add(4)).unwrap_or_default();
        let v = if major == 4 {
            syncsafe(bytes).unwrap_or_else(|| u32_be(bytes, 0).unwrap_or(0))
        } else {
            u32_be(bytes, 0).unwrap_or(0)
        };
        let span = raw.sub(to_u64(*at), 4);
        *at = at.saturating_add(4);
        Some((span, v))
    };
    if major == 3 {
        // Decompressed size, encryption method, group, in this order.
        if length {
            e.size = size(&mut at);
        }
        if e.encrypted {
            e.method = byte(&mut at);
        }
        if grouped {
            e.group = byte(&mut at);
        }
    } else {
        // Group, encryption method, data length indicator.
        if grouped {
            e.group = byte(&mut at);
        }
        if e.encrypted {
            e.method = byte(&mut at);
        }
        if length {
            e.size = size(&mut at);
        }
    }
    e.data = raw.tail(to_u64(at));
    Ok(e)
}

/// The frame's data with unsynchronisation undone and compression
/// inflated; an error for encrypted frames.
async fn frame_data(cx: &Cx, e: &Extras) -> Result<(Span, Option<Diagnostic>)> {
    if e.encrypted {
        return Err(Diagnostic::unsupported("encrypted frame"));
    }
    let mut data = e.data;
    if e.unsync {
        data = resync(cx, data).await?;
    }
    if e.compressed {
        let expected = e.size.map(|(_, s)| u64::from(s));
        let decoded = crate::codec::decode_span(cx, data, &Codec::Zlib, expected).await?;
        return Ok((decoded.span, decoded.error));
    }
    Ok((data, None))
}

/// Up to `max` bytes of the frame's decoded data, for summaries.
async fn frame_prefix(cx: &Cx, frame: &Frame, max: u64) -> Result<Option<(Vec<u8>, u64)>> {
    let e = extras(cx, frame).await?;
    if e.encrypted {
        return Ok(None);
    }
    if e.compressed {
        // Inflate small frames only.
        if e.data.len > 0x4000 {
            return Ok(None);
        }
        let (data, _) = frame_data(cx, &e).await?;
        let bytes = cx.read_avail(data.sub(0, max)).await?;
        return Ok(Some((bytes, data.len)));
    }
    if e.unsync {
        let raw = cx.read_avail(e.data.sub(0, max.saturating_mul(2))).await?;
        let mut bytes = unsync_bytes(&raw);
        bytes.truncate(to_usize(max));
        return Ok(Some((bytes, e.data.len)));
    }
    let bytes = cx.read_avail(e.data.sub(0, max)).await?;
    Ok(Some((bytes, e.data.len)))
}

// ---------------------------------------------------------------------------
// Text

/// Decodes a string in an ID3 text encoding, up to its terminator; returns
/// the text and the bytes consumed (including the terminator).
fn decode(data: &[u8], encoding: u8) -> (String, usize) {
    match encoding {
        1 | 2 => {
            let mut end = 0usize;
            while let Some(pair) = data.get(end..end.saturating_add(2)) {
                if pair == [0, 0] {
                    break;
                }
                end = end.saturating_add(2);
            }
            let body = data.get(..end.min(data.len())).unwrap_or_default();
            let consumed = end.saturating_add(2).min(data.len());
            let text = match (encoding, body) {
                (1, [0xff, 0xfe, rest @ ..]) => crate::text::utf16(rest, Endian::Little),
                (1, [0xfe, 0xff, rest @ ..]) => crate::text::utf16(rest, Endian::Big),
                (1, rest) => crate::text::utf16(rest, Endian::Little),
                (_, rest) => crate::text::utf16(rest, Endian::Big),
            };
            (text, consumed)
        }
        _ => {
            let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
            let body = data.get(..end).unwrap_or_default();
            let text = if encoding == 3 {
                String::from_utf8_lossy(body).into_owned()
            } else {
                crate::text::latin1(body)
            };
            (text, end.saturating_add(1).min(data.len()))
        }
    }
}

/// The NUL-separated values of a text frame body: `(offset, length,
/// text)`, empty values skipped.
fn values(data: &[u8], encoding: u8) -> Vec<(usize, usize, String)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(rest) = data.get(at..).filter(|r| !r.is_empty()) {
        let (text, used) = decode(rest, encoding);
        if used == 0 {
            break;
        }
        if !text.is_empty() {
            out.push((at, used, text));
        }
        at = at.saturating_add(used);
    }
    out
}

/// All values of a text frame body, joined with " / ".
fn decode_all(data: &[u8], encoding: u8) -> String {
    values(data, encoding)
        .into_iter()
        .map(|(_, _, t)| t)
        .collect::<Vec<_>>()
        .join(" / ")
}

/// What a text frame value means, where that is not plain: genre numbers,
/// "track of total", lengths.
fn interpret(id: &str, value: &str) -> Option<String> {
    match id {
        "TCON" => {
            let names = genres(value);
            (names != value).then_some(names)
        }
        "TRCK" | "TPOS" => {
            let (n, total) = value.split_once('/')?;
            Some(format!("{} of {}", n.trim(), total.trim()))
        }
        "TLEN" | "TDLY" => {
            let ms: u64 = value.trim().parse().ok()?;
            Some(ms_time(ms))
        }
        "TCMP" | "PCST" => Some(if value.trim() == "1" { "yes" } else { "no" }.to_owned()),
        _ => None,
    }
}

/// Resolves genre references: ID3v2.3 `(17)`, `(17)(18)Text`, `(RX)`,
/// `(CR)`, `((` for a literal parenthesis; ID3v2.4 plain numbers.
fn genres(value: &str) -> String {
    let named = |code: &str| -> Option<String> {
        match code {
            "RX" => Some("Remix".to_owned()),
            "CR" => Some("Cover".to_owned()),
            _ => code.parse::<u64>().ok().and_then(genre).map(str::to_owned),
        }
    };
    if let Some(name) = named(value.trim()) {
        return name;
    }
    let mut out: Vec<String> = Vec::new();
    let mut rest = value;
    while let Some(inner) = rest.strip_prefix('(') {
        if inner.starts_with('(') {
            break;
        }
        let Some((code, after)) = inner.split_once(')') else {
            break;
        };
        match named(code) {
            Some(name) => out.push(name),
            None => break,
        }
        rest = after;
    }
    let rest = rest
        .strip_prefix('(')
        .filter(|r| r.starts_with('('))
        .unwrap_or(rest);
    if !rest.is_empty() && !out.iter().any(|g| g == rest) {
        out.push(rest.to_owned());
    }
    if out.is_empty() {
        value.to_owned()
    } else {
        out.join(", ")
    }
}

/// Milliseconds as `m:ss.mmm` (or `h:mm:ss.mmm`).
fn ms_time(ms: u64) -> String {
    let (h, m, s, frac) = (ms / 3_600_000, ms / 60_000 % 60, ms / 1000 % 60, ms % 1000);
    if h > 0 {
        format!("{h}:{m:02}:{s:02}.{frac:03}")
    } else {
        format!("{m}:{s:02}.{frac:03}")
    }
}

fn timestamp(format: u8, v: u64) -> String {
    match format {
        1 => format!("frame {v}"),
        _ => ms_time(v),
    }
}

/// A popularimeter rating as stars, by the Windows Media Player mapping.
fn stars(rating: u8) -> &'static str {
    match rating {
        0 => "unrated",
        1..=31 => "★",
        32..=95 => "★★",
        96..=159 => "★★★",
        160..=223 => "★★★★",
        _ => "★★★★★",
    }
}

fn be_uint(b: &[u8]) -> u64 {
    b.iter()
        .take(8)
        .fold(0u64, |acc, &x| (acc << 8) | u64::from(x))
}

// ---------------------------------------------------------------------------
// Frame summaries

const SUMMARY_READ: u64 = 512;

async fn frame_summary(cx: &Cx, frame: &Frame) -> Result<Option<String>> {
    let id = normalize(&frame.id);
    let max = match id {
        "APIC" | "PIC" => 0x10000,
        "CHAP" | "CTOC" => 2048,
        _ => SUMMARY_READ,
    };
    let Some((bytes, len)) = frame_prefix(cx, frame, max).await? else {
        let e = extras(cx, frame).await?;
        let what = if e.encrypted {
            "encrypted"
        } else {
            "compressed"
        };
        return Ok(Some(format!("{what}, {}", human_size(e.data.len))));
    };
    Ok(summarize(id, &bytes, len, frame.tag.major))
}

/// A summary of a frame from the first bytes of its data (`len` bytes in
/// all).
fn summarize(id: &str, d: &[u8], len: u64, major: u8) -> Option<String> {
    let enc = d.first().copied().unwrap_or(0);
    let body = d.get(1..).unwrap_or_default();
    let label = |s: &str| -> String {
        match frame_name(id) {
            Some(name) => format!("{name}: {}", clip(s, 60)),
            None => clip(s, 60),
        }
    };
    Some(match id {
        "TXXX" => {
            let (desc, used) = decode(body, enc);
            let value = decode_all(body.get(used..).unwrap_or_default(), enc);
            format!("{desc}: {}", clip(&value, 60))
        }
        "TIPL" | "TMCL" | "IPLS" => {
            let v: Vec<String> = values(body, enc).into_iter().map(|(_, _, t)| t).collect();
            let pairs: Vec<String> = v.chunks(2).map(|p| p.join(": ")).collect();
            label(&pairs.join(", "))
        }
        "TCON" => {
            let names: Vec<String> = values(body, enc)
                .into_iter()
                .map(|(_, _, v)| genres(&v))
                .collect();
            label(&names.join(", "))
        }
        _ if is_text(id) => {
            let value = decode_all(body, enc);
            match interpret(id, &value) {
                Some(meaning) => label(&format!("{value} ({meaning})")),
                None => label(&value),
            }
        }
        "WXXX" => {
            let (desc, used) = decode(body, enc);
            let url = latin1_z(body.get(used..).unwrap_or_default());
            if desc.is_empty() {
                url
            } else {
                format!("{desc}: {url}")
            }
        }
        _ if id.starts_with('W') => label(&latin1_z(d)),
        "COMM" | "USLT" | "USER" => {
            let lang = crate::text::latin1(body.get(..3).unwrap_or_default());
            let rest = body.get(3..).unwrap_or_default();
            let (desc, text) = if id == "USER" {
                (String::new(), decode_all(rest, enc))
            } else {
                let (desc, used) = decode(rest, enc);
                (desc, decode_all(rest.get(used..).unwrap_or_default(), enc))
            };
            let name = frame_name(id).unwrap_or(id);
            let mut head = format!("{name} [{}", lang.trim_end_matches('\0'));
            if !desc.is_empty() {
                head.push_str(&format!(", {}", clip(&desc, 30)));
            }
            format!("{head}]: {}", clip(&text, 60))
        }
        "SYLT" => {
            let lang = crate::text::latin1(body.get(..3).unwrap_or_default());
            let content = body.get(4).copied().unwrap_or(0);
            let (desc, _) = decode(body.get(5..).unwrap_or_default(), enc);
            let kind = lookup(SYLT_CONTENT, content.into()).unwrap_or("content");
            let mut s = format!("Synchronised {kind} [{}]", lang.trim_end_matches('\0'));
            if !desc.is_empty() {
                s.push_str(&format!(": {}", clip(&desc, 40)));
            }
            s
        }
        "APIC" | "PIC" => {
            let (mime, used) = if id == "PIC" {
                (crate::text::latin1(body.get(..3).unwrap_or_default()), 3)
            } else {
                decode(body, 0)
            };
            let kind = body.get(used).copied().unwrap_or(0);
            let kind = lookup(PICTURE_TYPE, kind.into()).unwrap_or("Picture");
            let rest = body.get(used.saturating_add(1)..).unwrap_or_default();
            let (_, desc_len) = decode(rest, enc);
            let image = rest.get(desc_len..).unwrap_or_default();
            let size = len.saturating_sub(to_u64(used.saturating_add(2).saturating_add(desc_len)));
            match image_info(image) {
                Some(info) => format!("{kind}, {info}, {}", human_size(size)),
                None => format!("{kind}, {mime}, {}", human_size(size)),
            }
        }
        "GEOB" => {
            let (mime, used) = decode(body, 0);
            let rest = body.get(used..).unwrap_or_default();
            let (name, used2) = decode(rest, enc);
            let (desc, _) = decode(rest.get(used2..).unwrap_or_default(), enc);
            let mut parts = vec![mime];
            for s in [name, desc] {
                if !s.is_empty() {
                    parts.push(clip(&s, 40));
                }
            }
            parts.join(", ")
        }
        "PRIV" => {
            let (owner, used) = decode(d, 0);
            format!(
                "{}, {}",
                clip(&owner, 60),
                human_size(len.saturating_sub(to_u64(used)))
            )
        }
        "UFID" => {
            let (owner, used) = decode(d, 0);
            let ident = d.get(used..).unwrap_or_default();
            if ident.iter().all(|b| b.is_ascii_graphic()) {
                format!("{owner}: {}", crate::text::latin1(ident))
            } else {
                owner
            }
        }
        "PCNT" => format!("played {} times", be_uint(d)),
        "ENCR" | "GRID" => {
            let (owner, used) = decode(d, 0);
            format!("{owner}, symbol {:#04x}", d.get(used)?)
        }
        "POPM" => {
            let (email, used) = decode(d, 0);
            let rating = d.get(used).copied().unwrap_or(0);
            let mut s = format!("{} ({rating}/255)", stars(rating));
            if let Some(count) = d.get(used.saturating_add(1)..).filter(|c| !c.is_empty()) {
                s.push_str(&format!(", played {} times", be_uint(count)));
            }
            if !email.is_empty() {
                s.push_str(&format!(", by {email}"));
            }
            s
        }
        "RVA2" => {
            let (ident, used) = decode(d, 0);
            let adjust = d
                .get(used.saturating_add(1)..)
                .and_then(|b| crate::bytes::array::<2>(b, 0))
                .map(|b| f64::from(i16::from_be_bytes(b)) / 512.0);
            match adjust {
                Some(db) => format!("{ident}: {db:+.2} dB"),
                None => ident,
            }
        }
        "CHAP" => chap_summary(d, major)?,
        "CTOC" => ctoc_summary(d)?,
        "ETCO" => format!("{} events", len.saturating_sub(1) / 5),
        "SEEK" => format!("next tag {} bytes on", u32_be(d, 0)?),
        _ => return None,
    })
}

/// "ch1, 0:05.000–0:10.000: Title".
fn chap_summary(d: &[u8], major: u8) -> Option<String> {
    let (element, used) = decode(d, 0);
    let start = u32_be(d, used)?;
    let end = u32_be(d, used.saturating_add(4))?;
    let mut s = format!(
        "{element}, {}–{}",
        ms_time(start.into()),
        ms_time(end.into())
    );
    if let Some(title) = sub_title(d.get(used.saturating_add(16)..)?, major) {
        s.push_str(&format!(": {}", clip(&title, 50)));
    }
    Some(s)
}

/// "toc, top-level, ordered: ch0, ch1, ch2".
fn ctoc_summary(d: &[u8]) -> Option<String> {
    let (element, used) = decode(d, 0);
    let flags = *d.get(used)?;
    let count = *d.get(used.saturating_add(1))?;
    let mut s = element;
    if flags & 2 != 0 {
        s.push_str(", top-level");
    }
    if flags & 1 != 0 {
        s.push_str(", ordered");
    }
    let mut at = used.saturating_add(2);
    let mut children = Vec::new();
    for _ in 0..count.min(8) {
        let (child, n) = decode(d.get(at..)?, 0);
        children.push(child);
        at = at.saturating_add(n);
    }
    if count > 8 {
        children.push("…".to_owned());
    }
    s.push_str(&format!(": {}", children.join(", ")));
    Some(s)
}

/// The title (TIT2) among the sub-frames at the start of `d`.
fn sub_title(d: &[u8], major: u8) -> Option<String> {
    let mut at = 0usize;
    for _ in 0..8 {
        let head = d.get(at..at.saturating_add(10))?;
        let (id, size, _) = frame_header(head, major, false)?;
        let data = d.get(at.saturating_add(10)..)?;
        if id == "TIT2" {
            let data = data.get(..to_usize(size.into()).min(data.len()))?;
            let enc = data.first().copied().unwrap_or(0);
            return Some(decode_all(data.get(1..).unwrap_or_default(), enc));
        }
        at = at.saturating_add(10).saturating_add(to_usize(size.into()));
    }
    None
}

// ---------------------------------------------------------------------------
// Frame contents

async fn frame(cx: Cx, frame: Frame) -> Result<()> {
    let major = frame.tag.major;
    let header = cx.block(frame.span.sub(0, frame.header_len)).await?;
    let mut f = Fields::emitting(&cx, &header, BE);
    if major == 2 {
        f.ascii("Frame ID", 3).emit()?;
        crate::formats::util::sound::u24(&mut f, "Size", BE).emit()?;
    } else {
        f.ascii("Frame ID", 4).emit()?;
        if major == 4 && !frame.tag.plain_sizes {
            f.bytes("Size", 4)
                .map(|b| syncsafe(&b).unwrap_or_else(|| u32_be(&b, 0).unwrap_or(0)))
                .with(|&s, n| n.value(uint(s, 28)))
                .desc("Syncsafe integer")
                .emit()?;
        } else {
            f.u32("Size").emit()?;
        }
        let table = if major == 4 {
            FRAME_FLAGS_24
        } else {
            FRAME_FLAGS_23
        };
        f.u16("Flags").flags(table).emit()?;
    }
    let e = extras(&cx, &frame).await?;
    if let Some((span, v)) = e.size {
        let name = if major == 3 {
            "Decompressed size"
        } else {
            "Data length indicator"
        };
        cx.emit(leaf(name, span, uint(v, 32)).desc("Size of the data once decoded"));
    }
    if let Some((span, v)) = e.group {
        cx.emit(
            leaf("Group ID", span, uint(v, 8)).desc("Groups frames registered in a GRID frame"),
        );
    }
    if let Some((span, v)) = e.method {
        cx.emit(leaf("Encryption method", span, uint(v, 8)).desc("Registered in an ENCR frame"));
    }
    let (data, error) = match frame_data(&cx, &e).await {
        Ok(d) => d,
        Err(d) => {
            cx.emit(Node::new("Data").span(e.data).diag(d));
            return Ok(());
        }
    };
    if let Some(error) = error {
        cx.diag(error);
    }
    match (e.unsync, e.compressed) {
        (true, true) => cx.diag(Diagnostic::note(
            "unsynchronised and compressed: shown decoded",
        )),
        (true, false) => cx.diag(Diagnostic::note("unsynchronised frame: shown decoded")),
        (false, true) => cx.diag(Diagnostic::note("compressed frame: shown inflated")),
        _ => {}
    }
    let id = normalize(&frame.id);
    let limit: u64 = match id {
        "APIC" | "PIC" | "GEOB" | "PRIV" | "UFID" | "MCDI" | "AENC" | "ENCR" | "GRID" | "SIGN"
        | "CRM" | "COMR" | "OWNE" => 1 << 16,
        _ => 1 << 20,
    };
    let block = cx.block(data.sub(0, data.len.min(limit))).await?;
    let mut b = Body {
        cx: &cx,
        span: data,
        data: &block.data,
        at: 0,
    };
    render(&mut b, &frame, id)
}

/// A cursor over a frame's decoded data that emits what it reads.
struct Body<'a> {
    cx: &'a Cx,
    /// The whole data.
    span: Span,
    /// Its first bytes (all of them for text frames).
    data: &'a [u8],
    at: usize,
}

impl Body<'_> {
    fn rest(&self) -> &[u8] {
        self.data.get(self.at..).unwrap_or_default()
    }

    fn rest_span(&self) -> Span {
        self.span.tail(to_u64(self.at))
    }

    fn take(&mut self, n: usize) -> Span {
        let span = self.span.sub(to_u64(self.at), to_u64(n));
        self.at = self.at.saturating_add(n);
        span
    }

    fn emit(&self, node: Node) {
        self.cx.emit(node);
    }

    fn encoding(&mut self) -> u8 {
        let enc = self.rest().first().copied().unwrap_or(0);
        let span = self.take(1);
        let mut node = leaf("Encoding", span, enumerated(enc, 8, ENCODING));
        if enc > 3 {
            node = node.diag(Diagnostic::malformed("unknown text encoding"));
        }
        self.emit(node);
        enc
    }

    /// The next string, up to its terminator.
    fn string(&mut self, name: &'static str, enc: u8) -> String {
        let (s, used) = decode(self.rest(), enc);
        let span = self.take(used);
        self.emit(leaf(name, span, text(s.clone())));
        s
    }

    /// A fixed number of Latin-1 bytes.
    fn fixed(&mut self, name: &'static str, n: usize) -> String {
        let s = crate::text::latin1(self.rest().get(..n).unwrap_or_default());
        let span = self.take(n);
        self.emit(leaf(name, span, text(s.clone())));
        s
    }

    fn byte(&mut self) -> Option<(Span, u8)> {
        let v = self.rest().first().copied()?;
        Some((self.take(1), v))
    }

    fn uint(&mut self, n: usize) -> Option<(Span, u64)> {
        let b = self.rest().get(..n)?;
        let v = be_uint(b);
        Some((self.take(n), v))
    }

    /// The rest as text values, one node each; `meaning` explains a value.
    fn values(&mut self, name: &'static str, enc: u8, id: &str) -> Vec<String> {
        let found = values(self.rest(), enc);
        let base = self.at;
        let many = found.len() > 1;
        if found.is_empty() {
            let span = self.rest_span();
            self.emit(leaf(name, span, text("")));
        }
        let mut out = Vec::new();
        for (i, (at, used, value)) in found.into_iter().enumerate() {
            let span = self.span.sub(to_u64(base.saturating_add(at)), to_u64(used));
            let label: Cow<'static, str> = if many {
                format!("{name} {}", i.saturating_add(1)).into()
            } else {
                name.into()
            };
            let mut node = leaf(label, span, text(value.clone()));
            if let Some(meaning) = interpret(id, &value) {
                node = node.summary(meaning);
            }
            self.emit(node);
            out.push(value);
        }
        self.at = self.data.len();
        out
    }

    /// The rest as an opaque data node.
    fn data(&mut self, name: &'static str) {
        let span = self.rest_span();
        if !span.is_empty() {
            self.emit(Node::new(name).span(span).summary(human_size(span.len)));
        }
        self.at = self.data.len();
    }
}

fn render(b: &mut Body<'_>, frame: &Frame, id: &str) -> Result<()> {
    let input = frame.tag.input;
    match id {
        "TXXX" => {
            let enc = b.encoding();
            b.string("Description", enc);
            b.values("Value", enc, id);
        }
        "TIPL" | "TMCL" | "IPLS" => {
            let enc = b.encoding();
            let found = values(b.rest(), enc);
            let base = b.at;
            for pair in found.chunks(2) {
                let (Some((at, _, role)), last) = (pair.first(), pair.last()) else {
                    continue;
                };
                let end = last.map_or(*at, |(a, u, _)| a.saturating_add(*u));
                let span = b.span.sub(
                    to_u64(base.saturating_add(*at)),
                    to_u64(end.saturating_sub(*at)),
                );
                let person = pair.get(1).map_or("", |(_, _, p)| p.as_str());
                b.emit(leaf(role.clone(), span, text(person)));
            }
            b.at = b.data.len();
        }
        _ if is_text(id) => {
            let enc = b.encoding();
            b.values("Text", enc, id);
        }
        "WXXX" => {
            let enc = b.encoding();
            b.string("Description", enc);
            b.string("URL", 0);
        }
        _ if id.starts_with('W') => {
            b.string("URL", 0);
        }
        "COMM" | "USLT" | "USER" => {
            let enc = b.encoding();
            b.fixed("Language", 3);
            if id != "USER" {
                b.string("Description", enc);
            }
            b.values("Text", enc, id);
        }
        "APIC" | "PIC" => {
            let enc = b.encoding();
            if id == "PIC" {
                b.fixed("Image format", 3);
            } else {
                b.string("MIME type", 0);
            }
            if let Some((span, kind)) = b.byte() {
                b.emit(leaf(
                    "Picture type",
                    span,
                    enumerated(kind, 8, PICTURE_TYPE),
                ));
            }
            b.string("Description", enc);
            let picture = b.rest_span();
            let info = image_info(b.rest());
            let summary = match info {
                Some(i) => format!("{i}, {}", human_size(picture.len)),
                None => human_size(picture.len),
            };
            b.emit(embedded("Picture", input.nested(picture)).summary(summary));
            b.at = b.data.len();
        }
        "GEOB" => {
            let enc = b.encoding();
            b.string("MIME type", 0);
            b.string("File name", enc);
            b.string("Description", enc);
            let object = b.rest_span();
            b.emit(embedded("Object", input.nested(object)).summary(human_size(object.len)));
            b.at = b.data.len();
        }
        "PRIV" => {
            let owner = b.string("Owner", 0);
            private(b, &owner);
        }
        "UFID" => {
            b.string("Owner", 0);
            let ident = b.rest().to_vec();
            let span = b.rest_span();
            let value = if !ident.is_empty() && ident.iter().all(|c| c.is_ascii_graphic()) {
                text(crate::text::latin1(&ident))
            } else {
                Value::Bytes(ident)
            };
            b.emit(leaf("Identifier", span, value));
            b.at = b.data.len();
        }
        "PCNT" => {
            let n = b.rest().len();
            if let Some((span, v)) = b.uint(n) {
                b.emit(leaf("Counter", span, uint(v, 64)));
            }
        }
        "POPM" => {
            b.string("Email", 0);
            if let Some((span, rating)) = b.byte() {
                b.emit(leaf("Rating", span, uint(rating, 8)).summary(stars(rating)));
            }
            let n = b.rest().len();
            if let Some((span, v)) = b.uint(n).filter(|_| n > 0) {
                b.emit(leaf("Counter", span, uint(v, 64)));
            }
        }
        "RVA2" => {
            b.string("Identification", 0);
            let mut index = 0u32;
            while !b.rest().is_empty() && index < 256 {
                let start = b.at;
                let channel = b.rest().first().copied().unwrap_or(0);
                let adjust = b
                    .rest()
                    .get(1..3)
                    .and_then(|a| crate::bytes::array::<2>(a, 0))
                    .map_or(0, i16::from_be_bytes);
                let bits = b.rest().get(3).copied().unwrap_or(0);
                let peak_len = usize::from(bits).div_ceil(8);
                let len = 4usize.saturating_add(peak_len).min(b.rest().len());
                let span = b.take(len);
                let name = lookup(CHANNEL_TYPE, channel.into()).unwrap_or("channel");
                let mut node = Node::new(format!("Adjustment {index}"))
                    .span(span)
                    .summary(format!("{name}: {:+.2} dB", f64::from(adjust) / 512.0))
                    .lazy(expand_rva2, span);
                if b.at.saturating_sub(start) < 4 {
                    node = node.diag(Diagnostic::malformed("truncated adjustment"));
                }
                b.emit(node);
                index = index.saturating_add(1);
            }
        }
        "EQU2" => {
            if let Some((span, v)) = b.byte() {
                b.emit(leaf(
                    "Interpolation",
                    span,
                    enumerated(v, 8, &[(0, "band"), (1, "linear")]),
                ));
            }
            b.string("Identification", 0);
            let points = b.rest_span();
            b.emit(
                Node::new("Adjustment points")
                    .span(points)
                    .summary(format!("{} points", points.len / 4))
                    .lazy(expand_equ2, points),
            );
            b.at = b.data.len();
        }
        "CHAP" => {
            b.string("Element ID", 0);
            for name in ["Start time", "End time"] {
                if let Some((span, v)) = b.uint(4) {
                    b.emit(leaf(name, span, uint(v, 32)).summary(ms_time(v)));
                }
            }
            for name in ["Start offset", "End offset"] {
                if let Some((span, v)) = b.uint(4) {
                    let node = leaf(name, span, hex(v, 32));
                    b.emit(if v == 0xffff_ffff {
                        node.summary("unused: use the times")
                    } else {
                        node.desc("Byte offset from the start of the file")
                    });
                }
            }
            sub_frames(b.cx, frame, b.rest_span());
            b.at = b.data.len();
        }
        "CTOC" => {
            b.string("Element ID", 0);
            if let Some((span, v)) = b.byte() {
                b.emit(leaf("Flags", span, flags_value(v.into(), 8, CTOC_FLAGS)));
            }
            let count = b.byte();
            if let Some((span, v)) = count {
                b.emit(leaf("Entries", span, uint(v, 8)));
            }
            for _ in 0..count.map_or(0, |(_, c)| c) {
                if b.rest().is_empty() {
                    break;
                }
                b.string("Child element ID", 0);
            }
            sub_frames(b.cx, frame, b.rest_span());
            b.at = b.data.len();
        }
        "SYLT" => {
            let enc = b.encoding();
            b.fixed("Language", 3);
            let format = b.byte();
            if let Some((span, v)) = format {
                b.emit(leaf(
                    "Timestamp format",
                    span,
                    enumerated(v, 8, TIMESTAMP_FORMAT),
                ));
            }
            if let Some((span, v)) = b.byte() {
                b.emit(leaf("Content type", span, enumerated(v, 8, SYLT_CONTENT)));
            }
            b.string("Description", enc);
            let span = b.rest_span();
            b.emit(
                Node::new("Lines")
                    .span(span)
                    .summary(human_size(span.len))
                    .lazy(expand_sylt, (span, enc, format.map_or(2, |(_, f)| f))),
            );
            b.at = b.data.len();
        }
        "ETCO" => {
            let format = b.byte();
            if let Some((span, v)) = format {
                b.emit(leaf(
                    "Timestamp format",
                    span,
                    enumerated(v, 8, TIMESTAMP_FORMAT),
                ));
            }
            let span = b.rest_span();
            b.emit(
                Node::new("Events")
                    .span(span)
                    .summary(format!("{} events", span.len / 5))
                    .lazy(expand_etco, (span, format.map_or(2, |(_, f)| f))),
            );
            b.at = b.data.len();
        }
        "SEEK" => {
            if let Some((span, v)) = b.uint(4) {
                b.emit(
                    leaf("Offset to next tag", span, uint(v, 32)).desc("From the end of this tag"),
                );
            }
        }
        "LINK" => {
            let n = if frame.tag.major == 2 { 3 } else { 4 };
            b.fixed("Frame ID", n);
            b.string("URL", 0);
            b.values("ID data", 0, id);
        }
        "AENC" => {
            b.string("Owner", 0);
            for name in ["Preview start", "Preview length"] {
                if let Some((span, v)) = b.uint(2) {
                    b.emit(leaf(name, span, uint(v, 16)).desc("In frames"));
                }
            }
            b.data("Encryption info");
        }
        "ENCR" | "GRID" => {
            b.string("Owner", 0);
            if let Some((span, v)) = b.byte() {
                let name = if id == "ENCR" {
                    "Method symbol"
                } else {
                    "Group symbol"
                };
                b.emit(leaf(name, span, hex(v, 8)));
            }
            b.data("Data");
        }
        "SIGN" => {
            if let Some((span, v)) = b.byte() {
                b.emit(leaf("Group symbol", span, hex(v, 8)));
            }
            b.data("Signature");
        }
        "PCST" => {
            if let Some((span, v)) = b.uint(4) {
                b.emit(leaf("Podcast", span, uint(v, 32)));
            }
        }
        "CRM" => {
            b.string("Owner", 0);
            b.string("Description", 0);
            b.data("Encrypted data");
        }
        _ => b.data("Data"),
    }
    if b.at < b.data.len() {
        b.data("Trailing data");
    }
    Ok(())
}

fn flags_value(raw: u64, bits: u8, table: FlagTable) -> Value {
    let (set, unknown) = crate::value::decode_flags(table, raw);
    Value::Flags {
        raw,
        bits,
        set,
        unknown,
    }
}

/// PRIV payloads whose owners say what they are.
fn private(b: &mut Body<'_>, owner: &str) {
    let span = b.rest_span();
    let data = b.rest().to_vec();
    b.at = b.data.len();
    let node = match owner {
        "com.apple.streaming.transportStreamTimestamp" if data.len() == 8 => {
            let pts = be_uint(&data) & 0x1_ffff_ffff;
            leaf("Timestamp", span, uint(pts, 33))
                .summary(format!("{:.3} s", pts as f64 / 90_000.0))
                .desc("MPEG-TS presentation timestamp (90 kHz) of the first sample (HLS)")
        }
        _ if owner.starts_with("WM/") && data.len() == 16 => {
            let mut d4 = [0u8; 8];
            d4.copy_from_slice(data.get(8..16).unwrap_or(&[0; 8]));
            leaf(
                "GUID",
                span,
                Value::Guid(crate::value::Guid {
                    data1: crate::bytes::u32_le(&data, 0).unwrap_or(0),
                    data2: crate::bytes::u16_le(&data, 4).unwrap_or(0),
                    data3: crate::bytes::u16_le(&data, 6).unwrap_or(0),
                    data4: d4,
                }),
            )
        }
        _ if owner.starts_with("WM/") && data.len().is_multiple_of(2) => {
            let (s, _, _) = crate::text::utf16z(&data, Endian::Little);
            leaf("Value", span, text(s))
        }
        "XMP" => leaf(
            "XMP",
            span,
            text(String::from_utf8_lossy(&data).into_owned()),
        ),
        _ => {
            if span.is_empty() {
                return;
            }
            leaf("Data", span, Value::Bytes(data)).summary(human_size(span.len))
        }
    };
    b.emit(node);
}

async fn expand_rva2(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span).await?;
    let channel = d.first().copied().unwrap_or(0);
    cx.emit(leaf(
        "Channel",
        span.sub(0, 1),
        enumerated(channel, 8, CHANNEL_TYPE),
    ));
    if let Some(a) = crate::bytes::array::<2>(&d, 1) {
        let v = i16::from_be_bytes(a);
        cx.emit(
            leaf(
                "Volume adjustment",
                span.sub(1, 2),
                Value::Int {
                    value: v.into(),
                    bits: 16,
                },
            )
            .summary(format!("{:+.2} dB", f64::from(v) / 512.0))
            .desc("In 1/512 dB"),
        );
    }
    if let Some(&bits) = d.get(3) {
        cx.emit(leaf("Peak bits", span.sub(3, 1), uint(bits, 8)));
        let peak = d.get(4..).unwrap_or_default();
        if !peak.is_empty() {
            let mut node = leaf("Peak volume", span.tail(4), Value::Bytes(peak.to_vec()));
            if (1..=64).contains(&bits) {
                let full = 2f64.powi(i32::from(bits).saturating_sub(1));
                node = node
                    .summary(format!("{:.4} of full scale", be_uint(peak) as f64 / full))
                    .desc("Unsigned, with the peak-bits field giving its width");
            }
            cx.emit(node);
        }
    }
    Ok(())
}

async fn expand_equ2(cx: Cx, span: Span) -> Result<()> {
    cx.set_count(Count::Exact(span.len / 4));
    let mut at = 0u64;
    while at.saturating_add(4) <= span.len {
        let point = span.sub(at, 4);
        let d = cx.read(point).await?;
        let freq = u16_be(&d, 0).unwrap_or(0);
        let adjust = crate::bytes::array::<2>(&d, 2).map_or(0, i16::from_be_bytes);
        cx.push(
            Node::new(format!("{:.1} Hz", f64::from(freq) / 2.0))
                .span(point)
                .value(Value::Int {
                    value: adjust.into(),
                    bits: 16,
                })
                .summary(format!("{:+.2} dB", f64::from(adjust) / 512.0)),
        )
        .await;
        at = at.saturating_add(4);
    }
    Ok(())
}

async fn expand_sylt(cx: Cx, (span, enc, format): (Span, u8, u8)) -> Result<()> {
    let data = cx.read(span.sub(0, span.len.min(1 << 20))).await?;
    let mut at = 0usize;
    while at < data.len() {
        let rest = data.get(at..).unwrap_or_default();
        let (line, used) = decode(rest, enc);
        let stamp = rest.get(used..used.saturating_add(4)).map(be_uint);
        let len = used.saturating_add(4).min(rest.len());
        let entry = span.sub(to_u64(at), to_u64(len));
        let name = stamp.map_or_else(|| "?".to_owned(), |t| timestamp(format, t));
        let mut node = leaf(name, entry, text(line));
        if stamp.is_none() {
            node = node.diag(Diagnostic::malformed("missing timestamp"));
        }
        cx.push(node).await;
        at = at.saturating_add(len.max(1));
    }
    Ok(())
}

async fn expand_etco(cx: Cx, (span, format): (Span, u8)) -> Result<()> {
    cx.set_count(Count::Exact(span.len / 5));
    let mut at = 0u64;
    while at.saturating_add(5) <= span.len {
        let event = span.sub(at, 5);
        let d = cx.read(event).await?;
        let kind = d.first().copied().unwrap_or(0);
        let stamp = be_uint(d.get(1..5).unwrap_or_default());
        cx.push(leaf(
            timestamp(format, stamp),
            event,
            enumerated(kind, 8, EVENT),
        ))
        .await;
        at = at.saturating_add(5);
    }
    Ok(())
}

/// CHAP and CTOC hold frames of their own.
fn sub_frames(cx: &Cx, frame: &Frame, region: Span) {
    if !region.is_empty() {
        cx.emit(Node::new("Sub-frames").span(region).lazy(
            crate::expander!(self::expand_frames: (Tag, Span)),
            (frame.tag.clone(), region),
        ));
    }
}

async fn expand_frames(cx: Cx, (tag, region): (Tag, Span)) -> Result<()> {
    frames(&cx, &tag, region).await
}

// ---------------------------------------------------------------------------
// Tag summary

/// What the summary of a tag shows.
#[derive(Default)]
struct Scan {
    major: u8,
    size: u64,
    frames: u32,
    title: Option<String>,
    artist: Option<String>,
    album: Option<String>,
    year: Option<String>,
    track: Option<String>,
    /// Picture type and description of the chosen cover.
    cover: Option<(u8, String)>,
    chapters: u32,
}

async fn scan(cx: &Cx, span: Span) -> Result<Scan> {
    let head = cx.read(span.sub(0, 10)).await?;
    let major = head.get(3).copied().unwrap_or(0);
    let flags = head.get(5).copied().unwrap_or(0);
    let size = syncsafe(head.get(6..10).unwrap_or_default()).unwrap_or(0);
    let mut s = Scan {
        major,
        size: span.len,
        ..Scan::default()
    };
    if major == 2 && flags & 0x40 != 0 {
        return Ok(s);
    }
    let mut body = span.sub(10, size.into());
    if flags & 0x80 != 0 && major < 4 {
        body = resync(cx, body).await?;
    }
    if flags & 0x40 != 0 && major >= 3 {
        body = body.tail(ext_len(cx, body, major).await?);
    }
    let tag = Tag {
        input: Input::root(span),
        major,
        unsync: major == 4 && flags & 0x80 != 0,
        plain_sizes: major == 4 && plain_sizes(cx, body).await?,
    };
    let header_len: u64 = if major == 2 { 6 } else { 10 };
    let mut pos = 0u64;
    while body.len.saturating_sub(pos) >= header_len && s.frames < 1024 {
        let h = cx.read(body.sub(pos, header_len)).await?;
        if h.first().is_none_or(|&b| b == 0) {
            break;
        }
        let Some((id, size, flags)) = frame_header(&h, major, tag.plain_sizes) else {
            break;
        };
        let total = header_len.saturating_add(size.into());
        let frame = Frame {
            tag: tag.clone(),
            id,
            span: body.sub(pos, total),
            header_len,
            flags,
        };
        s.frames = s.frames.saturating_add(1);
        pos = pos.saturating_add(total);
        let id = normalize(&frame.id);
        let slot = match id {
            "TIT2" => &mut s.title,
            "TPE1" => &mut s.artist,
            "TALB" => &mut s.album,
            "TDRC" | "TYER" => &mut s.year,
            "TRCK" => &mut s.track,
            "CHAP" => {
                s.chapters = s.chapters.saturating_add(1);
                continue;
            }
            "APIC" | "PIC" => {
                if s.cover.as_ref().is_some_and(|(kind, _)| *kind == 3) {
                    continue;
                }
                if let Some((d, _)) = frame_prefix(cx, &frame, 0x10000).await?
                    && let Some((kind, mime, image)) = picture(id, &d)
                    && (s.cover.is_none() || kind == 3)
                {
                    s.cover = Some((kind, image_info(image).unwrap_or(mime)));
                }
                continue;
            }
            _ => continue,
        };
        if slot.is_none()
            && let Some((d, _)) = frame_prefix(cx, &frame, 256).await?
        {
            let enc = d.first().copied().unwrap_or(0);
            let value = decode_all(d.get(1..).unwrap_or_default(), enc);
            if !value.is_empty() {
                *slot = Some(value);
            }
        }
    }
    Ok(s)
}

/// The picture type, MIME type (or ID3v2.2 image format) and image bytes
/// of an APIC/PIC frame's data.
fn picture<'a>(id: &str, d: &'a [u8]) -> Option<(u8, String, &'a [u8])> {
    let enc = *d.first()?;
    let body = d.get(1..)?;
    let (mime, used) = if id == "PIC" {
        (crate::text::latin1(body.get(..3)?), 3)
    } else {
        decode(body, 0)
    };
    let kind = *body.get(used)?;
    let rest = body.get(used.saturating_add(1)..)?;
    let (_, desc) = decode(rest, enc);
    Some((kind, mime, rest.get(desc..)?))
}

impl Scan {
    /// "Artist – Title".
    fn title(&self) -> Option<String> {
        match (&self.artist, &self.title) {
            (Some(a), Some(t)) => Some(format!("{a} – {t}")),
            (a, t) => a.clone().or_else(|| t.clone()),
        }
    }

    /// "ID3v2.4, 12 frames, 48.0 KiB: Artist – Title (Album, 2019), track
    /// 3/12, cover 600×600 JPEG".
    fn summary(&self) -> String {
        let mut line = format!(
            "ID3v2.{}, {}, {}",
            self.major,
            crate::formats::util::arcutil::count(self.frames.into(), "frame", "frames"),
            human_size(self.size)
        );
        let mut parts = Vec::new();
        if let Some(t) = self.title() {
            let extra: Vec<String> = [
                self.album.clone(),
                self.year.as_ref().map(|y| y.chars().take(4).collect()),
            ]
            .into_iter()
            .flatten()
            .collect();
            if extra.is_empty() {
                parts.push(t);
            } else {
                parts.push(format!("{t} ({})", extra.join(", ")));
            }
        } else if let Some(a) = &self.album {
            parts.push(a.clone());
        }
        if let Some(t) = &self.track {
            parts.push(format!("track {t}"));
        }
        if let Some((kind, c)) = &self.cover {
            let what = if matches!(kind, 3 | 4) {
                "cover"
            } else {
                "picture"
            };
            parts.push(format!("{what} {c}"));
        }
        if self.chapters > 0 {
            parts.push(format!("{} chapters", self.chapters));
        }
        if !parts.is_empty() {
            line.push_str(&format!(": {}", parts.join(", ")));
        }
        line
    }
}

/// "ID3v2.4, 12 frames, 48.0 KiB: Artist – Title (Album, 2019), track 3/12,
/// cover 600×600 JPEG".
pub async fn summary(cx: &Cx, span: Span) -> Result<String> {
    Ok(scan(cx, span).await?.summary())
}

/// "Artist – Title" from the tag, for the summary of the file that holds it.
pub async fn title(cx: &Cx, span: Span) -> Option<String> {
    scan(cx, span).await.ok()?.title()
}

// ---------------------------------------------------------------------------
// ID3v1 and Enhanced TAG+

const SPEED: EnumTable = &[
    (0, "unset"),
    (1, "slow"),
    (2, "medium"),
    (3, "fast"),
    (4, "hardcore"),
];

/// What an ID3v1 tag says.
struct V1 {
    title: String,
    artist: String,
    album: String,
    year: String,
    track: Option<u8>,
    genre: u8,
}

fn v1_layout(f: &mut Fields<'_>, _: &()) -> Result<V1> {
    f.ascii("Identifier", 3).emit()?;
    let title = latin1_field(f, "Title", 30).emit()?;
    let artist = latin1_field(f, "Artist", 30).emit()?;
    let album = latin1_field(f, "Album", 30).emit()?;
    let year = latin1_field(f, "Year", 4).emit()?;
    let at = to_usize(f.pos());
    let raw = f
        .block()
        .data
        .get(at..at.saturating_add(30))
        .unwrap_or_default();
    // ID3v1.1: a zero byte and the track number end the comment.
    let v11 = matches!(raw, [.., 0, t] if *t != 0) && raw.len() == 30;
    let mut track = None;
    if v11 {
        latin1_field(f, "Comment", 28).emit()?;
        f.u8("Zero byte").desc("Marks ID3v1.1").emit()?;
        track = Some(f.u8("Track").emit()?);
    } else {
        latin1_field(f, "Comment", 30).emit()?;
    }
    let genre = f
        .u8("Genre")
        .with(|&g, n| {
            n.summary(match genre(g.into()) {
                Some(name) => name,
                None if g == 255 => "none",
                None => "unknown",
            })
        })
        .emit()?;
    Ok(V1 {
        title,
        artist,
        album,
        year,
        track,
        genre,
    })
}

impl V1 {
    fn title(&self) -> Option<String> {
        let parts: Vec<&str> = [self.artist.trim(), self.title.trim()]
            .into_iter()
            .filter(|s| !s.is_empty())
            .collect();
        (!parts.is_empty()).then(|| parts.join(" – "))
    }

    /// "ID3v1.1: Artist – Title (Album, 1999), track 3, Rock".
    fn summary(&self) -> String {
        let mut line = if self.track.is_some() {
            "ID3v1.1".to_owned()
        } else {
            "ID3v1".to_owned()
        };
        let mut parts = Vec::new();
        if let Some(t) = self.title() {
            let extra: Vec<&str> = [self.album.trim(), self.year.trim()]
                .into_iter()
                .filter(|s| !s.is_empty())
                .collect();
            if extra.is_empty() {
                parts.push(t);
            } else {
                parts.push(format!("{t} ({})", extra.join(", ")));
            }
        }
        if let Some(n) = self.track {
            parts.push(format!("track {n}"));
        }
        if let Some(g) = genre(self.genre.into()) {
            parts.push(g.to_owned());
        }
        if !parts.is_empty() {
            line.push_str(&format!(": {}", parts.join(", ")));
        }
        line
    }
}

/// An ID3v1 tag node for the 128 bytes at `span` (which must start with
/// `TAG`).
pub async fn v1_node(cx: &Cx, span: Span) -> Result<Node> {
    let tag = parse(cx, span, BE, &(), v1_layout).await?;
    Ok(struct_node("ID3v1 tag", span, BE, (), v1_layout).summary(tag.summary()))
}

/// "Artist – Title" from an ID3v1 tag.
pub async fn v1_title(cx: &Cx, span: Span) -> Option<String> {
    parse(cx, span, BE, &(), v1_layout).await.ok()?.title()
}

fn plus_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Identifier", 4).emit()?;
    latin1_field(f, "Title", 60)
        .desc("Continues the ID3v1 title")
        .emit()?;
    latin1_field(f, "Artist", 60)
        .desc("Continues the ID3v1 artist")
        .emit()?;
    latin1_field(f, "Album", 60)
        .desc("Continues the ID3v1 album")
        .emit()?;
    f.u8("Speed").enumeration(SPEED).emit()?;
    latin1_field(f, "Genre", 30).emit()?;
    latin1_field(f, "Start time", 6).desc("mmm:ss").emit()?;
    latin1_field(f, "End time", 6).desc("mmm:ss").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Lyrics3

const LYRICS3_FIELDS: &[(&str, &str)] = &[
    ("IND", "Indications"),
    ("LYR", "Lyrics"),
    ("INF", "Additional information"),
    ("AUT", "Lyrics author"),
    ("EAL", "Extended album name"),
    ("EAR", "Extended artist name"),
    ("ETT", "Extended track title"),
    ("IMG", "Image links"),
];

/// A Lyrics3 tag ending at `end` (relative to `file`), not before
/// `start`: its span and whether it is version 2.
async fn find_lyrics3(cx: &Cx, file: Span, end: u64, start: u64) -> Result<Option<(Span, bool)>> {
    let Some(at) = end.checked_sub(15).filter(|&a| a >= start) else {
        return Ok(None);
    };
    let tail = cx.read_avail(file.sub(at, 15)).await?;
    if tail.get(6..) == Some(b"LYRICS200") {
        let size = std::str::from_utf8(tail.get(..6).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse::<u64>().ok());
        let Some(begin) = size.and_then(|s| at.checked_sub(s)).filter(|&b| b >= start) else {
            return Ok(None);
        };
        let magic = cx.read_avail(file.sub(begin, 11)).await?;
        return Ok(
            (magic == b"LYRICSBEGIN").then(|| (file.sub(begin, end.saturating_sub(begin)), true))
        );
    }
    if tail.get(6..) == Some(b"LYRICSEND") {
        let from = end.saturating_sub(5120).max(start);
        let block = cx
            .read_avail(file.sub(from, end.saturating_sub(from)))
            .await?;
        let found = block
            .windows(11)
            .rposition(|w| w == b"LYRICSBEGIN")
            .map(|p| from.saturating_add(to_u64(p)));
        return Ok(found.map(|b| (file.sub(b, end.saturating_sub(b)), false)));
    }
    Ok(None)
}

fn lyrics3_node(span: Span, v2: bool) -> Node {
    Node::new(if v2 { "Lyrics3v2 tag" } else { "Lyrics3 tag" })
        .span(span)
        .summary(human_size(span.len))
        .lazy(expand_lyrics3, (span, v2))
}

async fn expand_lyrics3(cx: Cx, (span, v2): (Span, bool)) -> Result<()> {
    cx.emit(leaf("Begin marker", span.sub(0, 11), text("LYRICSBEGIN")));
    let trailer = if v2 { 15 } else { 9 };
    let body = span.sub(11, span.len.saturating_sub(11).saturating_sub(trailer));
    if !v2 {
        let data = cx.read(body.sub(0, body.len.min(1 << 16))).await?;
        cx.emit(leaf("Lyrics", body, text(crate::text::latin1(&data))));
        cx.emit(leaf(
            "End marker",
            span.tail(span.len.saturating_sub(9)),
            text("LYRICSEND"),
        ));
        return Ok(());
    }
    let mut at = 0u64;
    while body.len.saturating_sub(at) >= 8 {
        let head = cx.read(body.sub(at, 8)).await?;
        let id = crate::text::latin1(head.get(..3).unwrap_or_default());
        let Some(size) = std::str::from_utf8(head.get(3..8).unwrap_or_default())
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
        else {
            cx.emit(
                Node::new("Unparsed data")
                    .span(body.tail(at))
                    .diag(Diagnostic::malformed("invalid Lyrics3 field size")),
            );
            break;
        };
        let field_span = body.sub(at, size.saturating_add(8));
        let value = cx.read_avail(field_span.sub(8, size.min(1 << 16))).await?;
        let mut node = leaf(id.clone(), field_span, text(crate::text::latin1(&value)));
        if let Some((_, name)) = LYRICS3_FIELDS.iter().find(|(k, _)| *k == id) {
            node = node.desc(*name);
        }
        cx.emit(node.summary(clip(&crate::text::latin1(&value), 60)));
        at = at.saturating_add(size).saturating_add(8);
    }
    let tail = span.tail(span.len.saturating_sub(15));
    let size = cx.read_avail(tail.sub(0, 6)).await?;
    cx.emit(
        leaf("Size", tail.sub(0, 6), text(crate::text::latin1(&size)))
            .desc("Of the tag, excluding this field and the end marker"),
    );
    cx.emit(leaf("End marker", tail.sub(6, 9), text("LYRICS200")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Tags at the end of a file

/// The tags at the end of a file, in file order.
pub struct Trailing {
    pub nodes: Vec<Node>,
    /// Where the tags start (relative to the file): the end of the audio.
    pub end: u64,
    /// "Artist – Title" from tags that have it.
    pub titles: Vec<String>,
}

/// Finds the tags at the end of `file` (not before `start`), in whatever
/// order writers stacked them: ID3v1 (with an Enhanced TAG+ before it),
/// APE, Lyrics3 and an appended ID3v2 tag (with a footer).
pub async fn trailing_tags(cx: &Cx, input: Input, file: Span, start: u64) -> Result<Trailing> {
    let mut end = file.len;
    let mut nodes = Vec::new();
    let mut titles = Vec::new();
    let mut v1_seen = false;
    for _ in 0..6 {
        if let Some(ape) = apetag::find(cx, file, end).await?
            && ape.offset >= file.offset.saturating_add(start)
        {
            nodes.push(apetag::node(cx, input, ape).await);
            end = ape.offset.saturating_sub(file.offset);
            continue;
        }
        if let Some((span, v2)) = find_lyrics3(cx, file, end, start).await? {
            nodes.push(lyrics3_node(span, v2));
            end = span.offset.saturating_sub(file.offset);
            continue;
        }
        if let Some(at) = end.checked_sub(10).filter(|&a| a >= start) {
            let footer = cx.read_avail(file.sub(at, 10)).await?;
            if footer.starts_with(b"3DI")
                && let Some(size) = syncsafe(footer.get(6..10).unwrap_or_default())
                && let Some(begin) = at.checked_sub(u64::from(size).saturating_add(10))
                && begin >= start
            {
                let span = file.sub(begin, end.saturating_sub(begin));
                let head = cx.read_avail(span.sub(0, 10)).await?;
                if v2_len(&head) == Some(span.len) {
                    if let Some(t) = title(cx, span).await {
                        titles.push(t);
                    }
                    nodes.push(tag_node(cx, input, span).await.desc("Appended to the file"));
                    end = begin;
                    continue;
                }
            }
        }
        if !v1_seen && let Some(at) = end.checked_sub(128).filter(|&a| a >= start) {
            let v1 = file.sub(at, 128);
            if cx.read_avail(v1.sub(0, 3)).await? == b"TAG" {
                v1_seen = true;
                if let Some(t) = v1_title(cx, v1).await {
                    titles.push(t);
                }
                nodes.push(v1_node(cx, v1).await?);
                end = at;
                if let Some(plus) = enhanced(cx, file, end, start).await? {
                    nodes.push(plus);
                    end = end.saturating_sub(227);
                }
                continue;
            }
        }
        break;
    }
    nodes.reverse();
    Ok(Trailing { nodes, end, titles })
}

/// An Enhanced TAG+ ending at `end` (just before an ID3v1 tag).
async fn enhanced(cx: &Cx, file: Span, end: u64, start: u64) -> Result<Option<Node>> {
    let Some(at) = end.checked_sub(227).filter(|&a| a >= start) else {
        return Ok(None);
    };
    let span = file.sub(at, 227);
    let raw = cx.read_avail(span).await?;
    if !raw.starts_with(b"TAG+") {
        return Ok(None);
    }
    let mut node = struct_node("Enhanced tag (TAG+)", span, BE, (), plus_layout);
    let field = |from: usize| {
        crate::text::latin1(crate::formats::util::sound::trim_nul(
            raw.get(from..from.saturating_add(60)).unwrap_or_default(),
        ))
    };
    let (title, artist) = (field(4), field(64));
    if !title.is_empty() || !artist.is_empty() {
        node = node.summary(format!("{artist} – {title}"));
    }
    Ok(Some(node))
}

// ---------------------------------------------------------------------------
// Genres

pub fn genre(n: u64) -> Option<&'static str> {
    GENRES.get(to_usize(n)).copied()
}

/// The ID3v1 genres with the Winamp extensions (up to Winamp 5.6).
const GENRES: &[&str] = &[
    "Blues",
    "Classic Rock",
    "Country",
    "Dance",
    "Disco",
    "Funk",
    "Grunge",
    "Hip-Hop",
    "Jazz",
    "Metal",
    "New Age",
    "Oldies",
    "Other",
    "Pop",
    "R&B",
    "Rap",
    "Reggae",
    "Rock",
    "Techno",
    "Industrial",
    "Alternative",
    "Ska",
    "Death Metal",
    "Pranks",
    "Soundtrack",
    "Euro-Techno",
    "Ambient",
    "Trip-Hop",
    "Vocal",
    "Jazz+Funk",
    "Fusion",
    "Trance",
    "Classical",
    "Instrumental",
    "Acid",
    "House",
    "Game",
    "Sound Clip",
    "Gospel",
    "Noise",
    "Alt. Rock",
    "Bass",
    "Soul",
    "Punk",
    "Space",
    "Meditative",
    "Instrumental Pop",
    "Instrumental Rock",
    "Ethnic",
    "Gothic",
    "Darkwave",
    "Techno-Industrial",
    "Electronic",
    "Pop-Folk",
    "Eurodance",
    "Dream",
    "Southern Rock",
    "Comedy",
    "Cult",
    "Gangsta Rap",
    "Top 40",
    "Christian Rap",
    "Pop/Funk",
    "Jungle",
    "Native American",
    "Cabaret",
    "New Wave",
    "Psychedelic",
    "Rave",
    "Showtunes",
    "Trailer",
    "Lo-Fi",
    "Tribal",
    "Acid Punk",
    "Acid Jazz",
    "Polka",
    "Retro",
    "Musical",
    "Rock & Roll",
    "Hard Rock",
    "Folk",
    "Folk-Rock",
    "National Folk",
    "Swing",
    "Fast-Fusion",
    "Bebop",
    "Latin",
    "Revival",
    "Celtic",
    "Bluegrass",
    "Avantgarde",
    "Gothic Rock",
    "Progressive Rock",
    "Psychedelic Rock",
    "Symphonic Rock",
    "Slow Rock",
    "Big Band",
    "Chorus",
    "Easy Listening",
    "Acoustic",
    "Humour",
    "Speech",
    "Chanson",
    "Opera",
    "Chamber Music",
    "Sonata",
    "Symphony",
    "Booty Bass",
    "Primus",
    "Porn Groove",
    "Satire",
    "Slow Jam",
    "Club",
    "Tango",
    "Samba",
    "Folklore",
    "Ballad",
    "Power Ballad",
    "Rhythmic Soul",
    "Freestyle",
    "Duet",
    "Punk Rock",
    "Drum Solo",
    "A Cappella",
    "Euro-House",
    "Dance Hall",
    "Goa",
    "Drum & Bass",
    "Club-House",
    "Hardcore",
    "Terror",
    "Indie",
    "BritPop",
    "Afro-Punk",
    "Polsk Punk",
    "Beat",
    "Christian Gangsta Rap",
    "Heavy Metal",
    "Black Metal",
    "Crossover",
    "Contemporary Christian",
    "Christian Rock",
    "Merengue",
    "Salsa",
    "Thrash Metal",
    "Anime",
    "JPop",
    "Synthpop",
    "Abstract",
    "Art Rock",
    "Baroque",
    "Bhangra",
    "Big Beat",
    "Breakbeat",
    "Chillout",
    "Downtempo",
    "Dub",
    "EBM",
    "Eclectic",
    "Electro",
    "Electroclash",
    "Emo",
    "Experimental",
    "Garage",
    "Global",
    "IDM",
    "Illbient",
    "Industro-Goth",
    "Jam Band",
    "Krautrock",
    "Leftfield",
    "Lounge",
    "Math Rock",
    "New Romantic",
    "Nu-Breakz",
    "Post-Punk",
    "Post-Rock",
    "Psytrance",
    "Shoegaze",
    "Space Rock",
    "Trop Rock",
    "World Music",
    "Neoclassical",
    "Audiobook",
    "Audio Theatre",
    "Neue Deutsche Welle",
    "Podcast",
    "Indie Rock",
    "G-Funk",
    "Dubstep",
    "Garage Rock",
    "Psybient",
];
