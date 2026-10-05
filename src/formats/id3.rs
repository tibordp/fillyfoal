//! ID3 tags: ID3v2.2/2.3/2.4 (prepended to MP3, AAC and FLAC files and
//! embedded in WAV/AIFF chunks) and ID3v1 (the last 128 bytes of a file).
//!
//! A v2 tag lists its frames lazily; text, comment, URL and picture frames
//! are decoded, pictures and encapsulated objects are dissected as embedded
//! content. Unsynchronised tags and frames are decoded into derived sources.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::sound::{clip, enumerated, latin1_z, leaf, text, uint};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, flag};

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
    let footer = if major == 4 && flags & 0x10 != 0 { 10 } else { 0 };
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
// ID3v2

const TAG_FLAGS: FlagTable = &[
    flag(0x80, "UNSYNCHRONISATION"),
    flag(0x40, "EXTENDED_HEADER"),
    flag(0x20, "EXPERIMENTAL"),
    flag(0x10, "FOOTER"),
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

const FRAMES: &[(&str, &str)] = &[
    ("AENC", "Audio encryption"),
    ("APIC", "Attached picture"),
    ("CHAP", "Chapter"),
    ("COMM", "Comment"),
    ("CTOC", "Table of contents"),
    ("GEOB", "Encapsulated object"),
    ("GRID", "Group registration"),
    ("MCDI", "Music CD identifier"),
    ("PCNT", "Play counter"),
    ("POPM", "Popularimeter"),
    ("PRIV", "Private"),
    ("SYLT", "Synchronised lyrics"),
    ("TALB", "Album"),
    ("TBPM", "BPM"),
    ("TCMP", "Compilation"),
    ("TCOM", "Composer"),
    ("TCON", "Genre"),
    ("TCOP", "Copyright"),
    ("TDAT", "Date"),
    ("TDEN", "Encoding time"),
    ("TDOR", "Original release time"),
    ("TDRC", "Recording time"),
    ("TDRL", "Release time"),
    ("TENC", "Encoded by"),
    ("TEXT", "Lyricist"),
    ("TIT1", "Content group"),
    ("TIT2", "Title"),
    ("TIT3", "Subtitle"),
    ("TKEY", "Initial key"),
    ("TLAN", "Language"),
    ("TLEN", "Length (ms)"),
    ("TMED", "Media type"),
    ("TOPE", "Original artist"),
    ("TPE1", "Artist"),
    ("TPE2", "Album artist"),
    ("TPE3", "Conductor"),
    ("TPE4", "Remixed by"),
    ("TPOS", "Disc"),
    ("TPUB", "Publisher"),
    ("TRCK", "Track"),
    ("TSOA", "Album sort order"),
    ("TSOP", "Performer sort order"),
    ("TSOT", "Title sort order"),
    ("TSRC", "ISRC"),
    ("TSSE", "Encoder settings"),
    ("TXXX", "User-defined text"),
    ("TYER", "Year"),
    ("UFID", "Unique file identifier"),
    ("USER", "Terms of use"),
    ("USLT", "Lyrics"),
    ("WCOM", "Commercial information"),
    ("WCOP", "Copyright information"),
    ("WOAF", "Official audio file webpage"),
    ("WOAR", "Official artist webpage"),
    ("WOAS", "Official source webpage"),
    ("WPUB", "Publisher webpage"),
    ("WXXX", "User-defined URL"),
    // ID3v2.2 three-character IDs.
    ("COM", "Comment"),
    ("PIC", "Attached picture"),
    ("TAL", "Album"),
    ("TCO", "Genre"),
    ("TCM", "Composer"),
    ("TEN", "Encoded by"),
    ("TP1", "Artist"),
    ("TP2", "Album artist"),
    ("TRK", "Track"),
    ("TSS", "Encoder settings"),
    ("TT2", "Title"),
    ("TYE", "Year"),
    ("TXX", "User-defined text"),
    ("ULT", "Lyrics"),
];

fn frame_name(id: &str) -> Option<&'static str> {
    FRAMES.iter().find(|(k, _)| *k == id).map(|(_, v)| *v)
}

/// Everything a frame expansion needs.
#[derive(Clone, Debug)]
struct Tag {
    input: Input,
    major: u8,
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

record! {
    pub struct Header {
        magic: ascii[3] "Identifier",
        major: u8 "Major version",
        revision: u8 "Revision",
        flags: u8 "Flags" .flags(TAG_FLAGS),
        size: bytes[4] "Size" .with(|b, n| n.value(uint(syncsafe(b).unwrap_or(0), 28)).desc("Syncsafe: 7 bits per byte; excludes the header")),
    }
}

/// Header fields and frames of the tag at `span`.
async fn tag(cx: &Cx, input: Input, span: Span) -> Result<()> {
    let (header, header_span) = crate::dsl::Cursor::new(cx, span, BE)
        .record::<Header>()
        .await?;
    cx.emit(Header::node("Header", header_span, BE));
    let size = syncsafe(&header.size).unwrap_or(0);
    let mut body = span.sub(10, size.into());
    if header.flags & 0x10 != 0 {
        cx.emit(Node::new("Footer").span(span.sub(body.end().saturating_sub(span.offset), 10)));
    }
    // ID3v2.3 unsynchronises the whole tag (ID3v2.4 does it per frame).
    if header.flags & 0x80 != 0 && header.major < 4 {
        body = resync(cx, body).await?;
        cx.diag(Diagnostic::note("unsynchronised tag; frames shown decoded"));
    }
    let mut pos = 0u64;
    if header.flags & 0x40 != 0 {
        let raw = cx.read(body.sub(0, 4)).await?;
        let len = if header.major == 4 {
            syncsafe(&raw).unwrap_or(0).into()
        } else {
            u64::from(u32_be(&raw, 0).unwrap_or(0)).saturating_add(4)
        };
        cx.emit(Node::new("Extended header").span(body.sub(0, len)));
        pos = len;
    }
    let tag = Tag {
        input,
        major: header.major,
    };
    frames(cx, &tag, body.tail(pos)).await
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
    for &b in &data {
        if !(prev == 0xff && b == 0) {
            out.push(b);
        }
        prev = b;
    }
    Ok(cx.add_derived(origin, out, span.len, None)?.span)
}

/// Pushes one node per frame in `region`; stops at padding.
async fn frames(cx: &Cx, tag: &Tag, region: Span) -> Result<()> {
    let header_len: u64 = if tag.major == 2 { 6 } else { 10 };
    let mut pos = 0u64;
    while region.len.saturating_sub(pos) >= header_len {
        let head = cx.read(region.sub(pos, header_len)).await?;
        if head.first().is_none_or(|&b| b == 0) {
            cx.emit(
                Node::new("Padding")
                    .span(region.tail(pos))
                    .summary(format!("{} bytes", region.len.saturating_sub(pos))),
            );
            return Ok(());
        }
        let (id, size, flags) = if tag.major == 2 {
            let size = crate::bytes::u24_be(&head, 3).unwrap_or(0);
            (head.get(..3).unwrap_or_default(), size, 0)
        } else {
            let raw = head.get(4..8).unwrap_or_default();
            let size = if tag.major == 4 {
                // Some writers use plain integers in v2.4; trust syncsafe
                // only when it is valid.
                syncsafe(raw).unwrap_or_else(|| u32_be(raw, 0).unwrap_or(0))
            } else {
                u32_be(&head, 4).unwrap_or(0)
            };
            (
                head.get(..4).unwrap_or_default(),
                size,
                u16_be(&head, 8).unwrap_or(0),
            )
        };
        if !id.iter().all(|c| c.is_ascii_uppercase() || c.is_ascii_digit()) {
            cx.emit(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed("invalid frame ID")),
            );
            return Ok(());
        }
        let id = String::from_utf8_lossy(id).into_owned();
        let total = header_len.saturating_add(size.into());
        let span = region.sub(pos, total);
        let frame = Frame {
            tag: tag.clone(),
            id: id.clone(),
            span,
            header_len,
            flags,
        };
        let mut node = Node::new(id.clone()).span(span);
        if let Some(name) = frame_name(&id) {
            node = node.desc(name);
        }
        node = match frame_summary(cx, &frame).await {
            Ok(Some(s)) => node.summary(s),
            Ok(None) => node.summary(format!("{size} bytes")),
            Err(e) => node.diag(e),
        };
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        cx.push(node.lazy(crate::expander!(self::frame: Frame), frame))
            .await;
        pos = pos.saturating_add(total);
    }
    if pos < region.len {
        cx.emit(Node::new("Padding").span(region.tail(pos)));
    }
    Ok(())
}

/// The frame's data, with v2.4 per-frame unsynchronisation undone and the
/// data length indicator skipped.
async fn frame_data(cx: &Cx, frame: &Frame) -> Result<Span> {
    let mut data = frame.span.tail(frame.header_len);
    if frame.tag.major == 4 {
        if frame.flags & 0x0001 != 0 {
            data = data.tail(4);
        }
        if frame.flags & 0x0002 != 0 {
            data = resync(cx, data).await?;
        }
    }
    Ok(data)
}

fn unsupported_flags(frame: &Frame) -> Option<&'static str> {
    let (compressed, encrypted) = match frame.tag.major {
        3 => (0x0080, 0x0040),
        4 => (0x0008, 0x0004),
        _ => (0, 0),
    };
    if frame.flags & encrypted != 0 {
        Some("encrypted frame")
    } else if frame.flags & compressed != 0 {
        Some("compressed frame")
    } else {
        None
    }
}

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

/// All NUL-separated values of a text frame body, joined with " / ".
fn decode_all(data: &[u8], encoding: u8) -> String {
    let mut out = Vec::new();
    let mut rest = data;
    while !rest.is_empty() {
        let (text, used) = decode(rest, encoding);
        if !text.is_empty() {
            out.push(text);
        }
        if used == 0 {
            break;
        }
        rest = rest.get(used..).unwrap_or_default();
    }
    out.join(" / ")
}

const SUMMARY_READ: u64 = 512;

async fn frame_summary(cx: &Cx, frame: &Frame) -> Result<Option<String>> {
    if unsupported_flags(frame).is_some() {
        return Ok(None);
    }
    let data = frame_data(cx, frame).await?;
    let id = frame.id.as_str();
    let label = |s: String| -> String {
        match frame_name(id) {
            Some(name) => format!("{name}: {}", clip(&s, 60)),
            None => clip(&s, 60),
        }
    };
    let bytes = cx.read_avail(data.sub(0, SUMMARY_READ)).await?;
    let enc = bytes.first().copied().unwrap_or(0);
    let body = bytes.get(1..).unwrap_or_default();
    Ok(match id {
        "TXXX" | "TXX" | "WXXX" => {
            let (desc, used) = decode(body, enc);
            let value = if id == "WXXX" {
                latin1_z(body.get(used..).unwrap_or_default())
            } else {
                decode_all(body.get(used..).unwrap_or_default(), enc)
            };
            Some(format!("{desc}: {}", clip(&value, 60)))
        }
        _ if id.starts_with('T') => Some(label(genre_text(id, decode_all(body, enc)))),
        _ if id.starts_with('W') => Some(label(latin1_z(&bytes))),
        "COMM" | "COM" | "USLT" | "ULT" => {
            let rest = body.get(3..).unwrap_or_default();
            let (_, used) = decode(rest, enc);
            Some(label(decode_all(rest.get(used..).unwrap_or_default(), enc)))
        }
        "APIC" | "PIC" => {
            let (mime, used) = if id == "PIC" {
                (latin1_z(body.get(..3).unwrap_or_default()), 3)
            } else {
                decode(body, 0)
            };
            let kind = body.get(used).copied().unwrap_or(0);
            let kind = crate::value::lookup(PICTURE_TYPE, kind.into()).unwrap_or("picture");
            Some(format!("{kind}, {mime}, {} bytes", data.len))
        }
        "PRIV" | "UFID" => Some(latin1_z(&bytes)),
        _ => None,
    })
}

/// Expands `(NN)` genre references in TCON.
fn genre_text(id: &str, value: String) -> String {
    if id != "TCON" && id != "TCO" {
        return value;
    }
    let inner = value
        .strip_prefix('(')
        .and_then(|v| v.split(')').next())
        .or(Some(value.as_str()))
        .and_then(|v| v.parse::<u8>().ok());
    match inner.and_then(|n| genre(n.into())) {
        Some(name) => format!("{value} ({name})"),
        None => value,
    }
}

async fn frame(cx: Cx, frame: Frame) -> Result<()> {
    let header = cx.block(frame.span.sub(0, frame.header_len)).await?;
    let mut f = Fields::emitting(&cx, &header, BE);
    if frame.tag.major == 2 {
        f.ascii("Frame ID", 3).emit()?;
        crate::formats::sound::u24(&mut f, "Size", BE).emit()?;
    } else {
        f.ascii("Frame ID", 4).emit()?;
        if frame.tag.major == 4 {
            f.bytes("Size", 4)
                .with(|b, n| {
                    n.value(uint(syncsafe(b).unwrap_or(0), 28))
                        .desc("Syncsafe integer")
                })
                .emit()?;
            f.u16("Flags").flags(FRAME_FLAGS_24).emit()?;
        } else {
            f.u32("Size").emit()?;
            f.u16("Flags").flags(FRAME_FLAGS_23).emit()?;
        }
    }
    if let Some(what) = unsupported_flags(&frame) {
        cx.emit(
            Node::new("Data")
                .span(frame.span.tail(frame.header_len))
                .diag(Diagnostic::unsupported(what)),
        );
        return Ok(());
    }
    let data = frame_data(&cx, &frame).await?;
    let id = frame.id.as_str();
    let block = cx.block(data).await?;
    let bytes = &block.data;
    let mut at = 0usize;
    // Emits the next encoded string as a field.
    let string = |name: &'static str, enc: u8, at: &mut usize, all: bool| {
        let rest = bytes.get(*at..).unwrap_or_default();
        let (value, used) = if all {
            (decode_all(rest, enc), rest.len())
        } else {
            decode(rest, enc)
        };
        let span = data.sub(to_u64(*at), to_u64(used));
        *at = at.saturating_add(used);
        cx.emit(leaf(name, span, text(value)));
    };
    let encoding = |cx: &Cx| -> u8 {
        let enc = bytes.first().copied().unwrap_or(0);
        cx.emit(leaf("Encoding", data.sub(0, 1), enumerated(enc, 8, ENCODING)));
        enc
    };
    match id {
        "TXXX" | "TXX" => {
            let enc = encoding(&cx);
            at = 1;
            string("Description", enc, &mut at, false);
            string("Value", enc, &mut at, true);
        }
        "WXXX" | "WXX" => {
            let enc = encoding(&cx);
            at = 1;
            string("Description", enc, &mut at, false);
            string("URL", 0, &mut at, true);
        }
        _ if id.starts_with('T') => {
            let enc = encoding(&cx);
            at = 1;
            string("Text", enc, &mut at, true);
        }
        _ if id.starts_with('W') => string("URL", 0, &mut at, true),
        "COMM" | "COM" | "USLT" | "ULT" | "USER" => {
            let enc = encoding(&cx);
            cx.emit(leaf(
                "Language",
                data.sub(1, 3),
                text(latin1_z(bytes.get(1..4).unwrap_or_default())),
            ));
            at = 4;
            if id != "USER" {
                string("Description", enc, &mut at, false);
            }
            string("Text", enc, &mut at, true);
        }
        "APIC" | "PIC" => {
            let enc = encoding(&cx);
            at = 1;
            if id == "PIC" {
                cx.emit(leaf(
                    "Image format",
                    data.sub(1, 3),
                    text(latin1_z(bytes.get(1..4).unwrap_or_default())),
                ));
                at = 4;
            } else {
                string("MIME type", 0, &mut at, false);
            }
            let kind = bytes.get(at).copied().unwrap_or(0);
            cx.emit(leaf(
                "Picture type",
                data.sub(to_u64(at), 1),
                enumerated(kind, 8, PICTURE_TYPE),
            ));
            at = at.saturating_add(1);
            string("Description", enc, &mut at, false);
            let picture = data.tail(to_u64(at));
            cx.emit(
                embedded("Picture", frame.tag.input.nested(picture))
                    .summary(format!("{} bytes", picture.len)),
            );
        }
        "GEOB" | "GEO" => {
            let enc = encoding(&cx);
            at = 1;
            string("MIME type", 0, &mut at, false);
            string("File name", enc, &mut at, false);
            string("Description", enc, &mut at, false);
            cx.emit(embedded("Object", frame.tag.input.nested(data.tail(to_u64(at)))));
        }
        "PRIV" | "UFID" | "UFI" => {
            string("Owner", 0, &mut at, false);
            let rest = data.tail(to_u64(at));
            let value = bytes.get(at..).unwrap_or_default().to_vec();
            cx.emit(leaf("Data", rest, crate::value::Value::Bytes(value)));
        }
        "PCNT" | "CNT" => {
            let n = bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
            cx.emit(leaf("Counter", data, uint(n, 64)));
        }
        "POPM" | "POP" => {
            string("Email", 0, &mut at, false);
            let rating = bytes.get(at).copied().unwrap_or(0);
            cx.emit(leaf("Rating", data.sub(to_u64(at), 1), uint(rating, 8)));
            let rest = bytes.get(at.saturating_add(1)..).unwrap_or_default();
            if !rest.is_empty() {
                let n = rest.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
                cx.emit(leaf("Counter", data.tail(to_u64(at).saturating_add(1)), uint(n, 64)));
            }
        }
        "CHAP" => {
            string("Element ID", 0, &mut at, false);
            let mut f = Fields::emitting(&cx, &block, BE);
            f.seek(to_u64(at));
            f.u32("Start time (ms)").emit()?;
            f.u32("End time (ms)").emit()?;
            f.u32("Start offset").hex().emit()?;
            f.u32("End offset").hex().emit()?;
            sub_frames(&cx, &frame, data.tail(f.pos()));
        }
        "CTOC" => {
            string("Element ID", 0, &mut at, false);
            let mut f = Fields::emitting(&cx, &block, BE);
            f.seek(to_u64(at));
            f.u8("Flags")
                .flags(CTOC_FLAGS)
                .emit()?;
            let count = f.u8("Entries").emit()?;
            let mut pos = to_usize(f.pos());
            for _ in 0..count {
                string("Child element ID", 0, &mut pos, false);
            }
            sub_frames(&cx, &frame, data.tail(to_u64(pos)));
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

/// CHAP and CTOC hold frames of their own.
fn sub_frames(cx: &Cx, frame: &Frame, region: Span) {
    if !region.is_empty() {
        cx.emit(
            Node::new("Sub-frames")
                .span(region)
                .lazy(crate::expander!(self::expand_frames: (Tag, Span)), (frame.tag.clone(), region)),
        );
    }
}

async fn expand_frames(cx: Cx, (tag, region): (Tag, Span)) -> Result<()> {
    frames(&cx, &tag, region).await
}

/// "ID3v2.4, 6 frames: Artist – Title".
pub async fn summary(cx: &Cx, span: Span) -> Result<String> {
    let head = cx.read(span.sub(0, 10)).await?;
    let major = head.get(3).copied().unwrap_or(0);
    let mut line = format!("ID3v2.{major}");
    let size = syncsafe(head.get(6..10).unwrap_or_default()).unwrap_or(0);
    let flags = head.get(5).copied().unwrap_or(0);
    if flags & 0xc0 != 0 {
        return Ok(line);
    }
    // Scan the frame headers for title and artist.
    let body = span.sub(10, size.into());
    let header_len: u64 = if major == 2 { 6 } else { 10 };
    let mut pos = 0u64;
    let mut count = 0u32;
    let (mut title, mut artist) = (None, None);
    while body.len.saturating_sub(pos) >= header_len && count < 256 {
        let h = cx.read(body.sub(pos, header_len)).await?;
        if h.first().is_none_or(|&b| b == 0) {
            break;
        }
        let (id, size) = if major == 2 {
            (h.get(..3).unwrap_or_default(), crate::bytes::u24_be(&h, 3).unwrap_or(0))
        } else if major == 4 {
            let raw = h.get(4..8).unwrap_or_default();
            (
                h.get(..4).unwrap_or_default(),
                syncsafe(raw).unwrap_or_else(|| u32_be(raw, 0).unwrap_or(0)),
            )
        } else {
            (h.get(..4).unwrap_or_default(), u32_be(&h, 4).unwrap_or(0))
        };
        let data = body.sub(pos.saturating_add(header_len), size.into());
        let slot = match id {
            b"TIT2" | b"TT2" => Some(&mut title),
            b"TPE1" | b"TP1" => Some(&mut artist),
            _ => None,
        };
        if let Some(slot) = slot {
            let bytes = cx.read_avail(data.sub(0, 256)).await?;
            let enc = bytes.first().copied().unwrap_or(0);
            *slot = Some(decode_all(bytes.get(1..).unwrap_or_default(), enc));
        }
        count = count.saturating_add(1);
        pos = pos.saturating_add(header_len).saturating_add(size.into());
    }
    line.push_str(&format!(", {count} frames"));
    match (artist, title) {
        (Some(a), Some(t)) => line.push_str(&format!(": {a} – {t}")),
        (None, Some(t)) => line.push_str(&format!(": {t}")),
        (Some(a), None) => line.push_str(&format!(": {a}")),
        (None, None) => {}
    }
    Ok(line)
}

/// "Artist – Title" from the tag, for the summary of the file that holds it.
pub async fn title(cx: &Cx, span: Span) -> Option<String> {
    let s = summary(cx, span).await.ok()?;
    s.split_once(": ").map(|(_, t)| t.to_owned())
}

// ---------------------------------------------------------------------------
// ID3v1

record! {
    pub struct V1 {
        magic: ascii[3] "Identifier",
        title: ascii[30] "Title",
        artist: ascii[30] "Artist",
        album: ascii[30] "Album",
        year: ascii[4] "Year",
        comment: bytes[30] "Comment" .with(|b, n| n.value(text(v1_comment(b)))),
        genre: u8 "Genre" .with(|&g, n| n.summary(genre(g.into()).unwrap_or("unknown"))),
    }
}

/// The comment, without the ID3v1.1 track number.
fn v1_comment(b: &[u8]) -> String {
    let b = match b {
        [rest @ .., 0, _] => rest,
        _ => b,
    };
    latin1_z(b)
}

/// The ID3v1.1 track number, if any.
fn v1_track(comment: &[u8]) -> Option<u8> {
    match comment {
        [.., 0, t] if *t != 0 => Some(*t),
        _ => None,
    }
}

/// An ID3v1 tag node for the 128 bytes at `span` (which must start with
/// `TAG`).
pub async fn v1_node(cx: &Cx, span: Span) -> Result<Node> {
    let tag = crate::fields::parse(cx, span, BE, &(), V1::layout).await?;
    let mut node = struct_with_track(span);
    let parts: Vec<&str> = [tag.artist.trim(), tag.title.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    let mut summary = if tag.comment.get(28) == Some(&0) && v1_track(&tag.comment).is_some() {
        "ID3v1.1".to_owned()
    } else {
        "ID3v1".to_owned()
    };
    if !parts.is_empty() {
        summary.push_str(&format!(": {}", parts.join(" – ")));
    }
    node = node.summary(summary);
    Ok(node)
}

fn struct_with_track(span: Span) -> Node {
    crate::fields::struct_node("ID3v1 tag", span, BE, (), |f: &mut Fields<'_>, _: &()| {
        let tag = V1::read(f)?;
        if let Some(track) = v1_track(&tag.comment) {
            f.node(leaf(
                "Track",
                Span::new(f.peek_span(0).source, f.peek_span(0).offset.saturating_sub(2), 1),
                uint(track, 8),
            ));
        }
        Ok(())
    })
}

/// "Artist – Title" from an ID3v1 tag.
pub async fn v1_title(cx: &Cx, span: Span) -> Option<String> {
    let tag = crate::fields::parse(cx, span, BE, &(), V1::layout).await.ok()?;
    let parts: Vec<&str> = [tag.artist.trim(), tag.title.trim()]
        .into_iter()
        .filter(|s| !s.is_empty())
        .collect();
    (!parts.is_empty()).then(|| parts.join(" – "))
}

/// Looks for an ID3v1 tag in the last 128 bytes of `span`.
pub async fn find_v1(cx: &Cx, span: Span) -> Result<Option<Span>> {
    if span.len < 128 {
        return Ok(None);
    }
    let at = span.tail(span.len.saturating_sub(128));
    let magic = cx.read(at.sub(0, 3)).await?;
    Ok((magic == b"TAG").then_some(at))
}

pub fn genre(n: u64) -> Option<&'static str> {
    GENRES.get(to_usize(n)).copied()
}

const GENRES: &[&str] = &[
    "Blues", "Classic Rock", "Country", "Dance", "Disco", "Funk", "Grunge", "Hip-Hop", "Jazz",
    "Metal", "New Age", "Oldies", "Other", "Pop", "R&B", "Rap", "Reggae", "Rock", "Techno",
    "Industrial", "Alternative", "Ska", "Death Metal", "Pranks", "Soundtrack", "Euro-Techno",
    "Ambient", "Trip-Hop", "Vocal", "Jazz+Funk", "Fusion", "Trance", "Classical", "Instrumental",
    "Acid", "House", "Game", "Sound Clip", "Gospel", "Noise", "AlternRock", "Bass", "Soul",
    "Punk", "Space", "Meditative", "Instrumental Pop", "Instrumental Rock", "Ethnic", "Gothic",
    "Darkwave", "Techno-Industrial", "Electronic", "Pop-Folk", "Eurodance", "Dream",
    "Southern Rock", "Comedy", "Cult", "Gangsta", "Top 40", "Christian Rap", "Pop/Funk", "Jungle",
    "Native American", "Cabaret", "New Wave", "Psychedelic", "Rave", "Showtunes", "Trailer",
    "Lo-Fi", "Tribal", "Acid Punk", "Acid Jazz", "Polka", "Retro", "Musical", "Rock & Roll",
    "Hard Rock",
];
