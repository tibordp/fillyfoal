//! Blu-ray (BDMV) navigation and clip files: `index.bdmv`,
//! `MovieObject.bdmv`, playlists (`.mpls`) and clip information (`.clpi`),
//! and their AVCHD names (`.bdm`, `.mpl`, `.cpi`).
//!
//! Each starts with a four-character type and a version (`0100`, `0200`,
//! `0300`) and names its sections by absolute offset: the index's
//! application info and title table, the movie objects and their HDMV
//! navigation commands, a playlist's play items (with their stream number
//! tables), sub-paths and marks, and a clip's sequence and program info and
//! EP map. Layouts follow libbluray's `index_parse.c`, `mobj_parse.c`,
//! `mpls_parse.c` and `clpi_parse.c`; command mnemonics follow its
//! `mobj_print.c`.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::{self, fourcc, plural};
use crate::formats::util::sound::{Bits, bits_node};
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const BE: Endian = Endian::Big;

/// `magic` followed by a known version, and section offsets (at `offsets`,
/// u32 each) that lie inside the file.
fn probe_with(h: &Head<'_>, magic: &[u8; 4], offsets: &[usize]) -> bool {
    let version = h.data.get(4..8).unwrap_or_default();
    h.starts_with(magic)
        && matches!(version, b"0100" | b"0200" | b"0240" | b"0300")
        && offsets.iter().all(|&at| {
            let o = u64::from(u32_be(h.data, at).unwrap_or(u32::MAX));
            o == 0 || (o >= 0x28 && o < h.len)
        })
}

fn index_probe(h: &Head<'_>) -> bool {
    probe_with(h, b"INDX", &[8, 12])
}

fn mobj_probe(h: &Head<'_>) -> bool {
    probe_with(h, b"MOBJ", &[8])
}

fn mpls_probe(h: &Head<'_>) -> bool {
    probe_with(h, b"MPLS", &[8, 12, 16])
}

fn clpi_probe(h: &Head<'_>) -> bool {
    probe_with(h, b"HDMV", &[8, 12, 16, 20, 24])
}

declare_format!(pub INDEX = "bdmv-index", "Blu-ray index (index.bdmv)", ["bdmv", "bdm"],
    "application/x-bdmv-index", Probe::Custom(index_probe), index);
declare_format!(pub MOVIE_OBJECT = "bdmv-movieobject", "Blu-ray movie objects (MovieObject.bdmv)",
    ["bdmv", "bdm"], "application/x-bdmv-movieobject", Probe::Custom(mobj_probe), movie_object);
declare_format!(pub PLAYLIST = "bdmv-playlist", "Blu-ray movie playlist", ["mpls", "mpl"],
    "application/x-bdmv-playlist", Probe::Custom(mpls_probe), playlist);
declare_format!(pub CLIP_INFO = "bdmv-clipinfo", "Blu-ray clip information", ["clpi", "cpi"],
    "application/x-bdmv-clipinfo", Probe::Custom(clpi_probe), clip_info);

// ---------------------------------------------------------------------------
// Shared pieces

/// The type and version, then the section offsets named in `offsets`.
fn file_header(f: &mut Fields<'_>, offsets: &&'static [&'static str]) -> Result<()> {
    f.ascii("Type", 4).emit()?;
    f.ascii("Version", 4).emit()?;
    for &name in offsets.iter() {
        f.u32(name).hex().emit()?;
    }
    Ok(())
}

/// A section at absolute offset `start` whose first u32 is its length
/// (excluding itself); `None` if the offset is zero.
async fn section(cx: &Cx, file: Span, start: u64) -> Result<Option<Span>> {
    if start == 0 {
        return Ok(None);
    }
    let head = cx.read_avail(file.sub(start, 4)).await?;
    let Some(len) = u32_be(&head, 0) else {
        return Err(Diagnostic::truncated(
            file.sub(start, 4),
            to_u64(head.len()),
        ));
    };
    Ok(Some(file.sub(start, u64::from(len).saturating_add(4))))
}

/// Emits `node` for the section at `start`, or a diagnostic.
async fn emit_section(
    cx: &Cx,
    file: Span,
    start: u64,
    build: impl FnOnce(Span) -> Node,
) -> Option<Span> {
    match section(cx, file, start).await {
        Ok(Some(span)) => {
            let wanted = u64::from(
                u32_be(&cx.read_avail(span.sub(0, 4)).await.unwrap_or_default(), 0).unwrap_or(0),
            )
            .saturating_add(4);
            let mut node = build(span);
            if span.len < wanted {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset, wanted),
                    span.len,
                ));
            }
            cx.emit(node);
            Some(span)
        }
        Ok(None) => None,
        Err(e) => {
            cx.diag(e);
            None
        }
    }
}

/// 45 kHz ticks, for summaries.
fn ticks(t: u32) -> String {
    crate::formats::util::fmt::duration_of(t.into(), 45_000)
}

const VIDEO_FORMAT: EnumTable = &[
    (1, "480i"),
    (2, "576i"),
    (3, "480p"),
    (4, "1080i"),
    (5, "720p"),
    (6, "1080p"),
    (7, "576p"),
    (8, "2160p"),
];
const FRAME_RATE: EnumTable = &[
    (1, "23.976"),
    (2, "24"),
    (3, "25"),
    (4, "29.97"),
    (6, "50"),
    (7, "59.94"),
];
const AUDIO_FORMAT: EnumTable = &[
    (1, "mono"),
    (3, "stereo"),
    (6, "multi-channel"),
    (12, "stereo and multi-channel"),
];
const AUDIO_RATE: EnumTable = &[
    (1, "48 kHz"),
    (4, "96 kHz"),
    (5, "192 kHz"),
    (12, "192 kHz with a 48 kHz core"),
    (14, "96 kHz with a 48 kHz core"),
];
const ASPECT: EnumTable = &[(2, "4:3"), (3, "16:9")];
const CHAR_CODE: EnumTable = &[
    (1, "UTF-8"),
    (2, "UTF-16BE"),
    (3, "Shift-JIS"),
    (4, "EUC-KR"),
    (5, "GB18030-2000"),
    (6, "GB2312"),
    (7, "Big5"),
];
const CODING_TYPE: EnumTable = &[
    (0x01, "MPEG-1 video"),
    (0x02, "MPEG-2 video"),
    (0x03, "MPEG-1 audio"),
    (0x04, "MPEG-2 audio"),
    (0x1b, "H.264"),
    (0x20, "H.264 MVC"),
    (0x24, "H.265"),
    (0xea, "VC-1"),
    (0x80, "LPCM"),
    (0x81, "AC-3"),
    (0x82, "DTS"),
    (0x83, "Dolby TrueHD"),
    (0x84, "E-AC-3"),
    (0x85, "DTS-HD High Resolution"),
    (0x86, "DTS-HD Master Audio"),
    (0xa1, "E-AC-3 (secondary)"),
    (0xa2, "DTS-HD (secondary)"),
    (0x90, "Presentation graphics"),
    (0x91, "Interactive graphics"),
    (0x92, "Text subtitles"),
];

#[derive(Clone, Copy, PartialEq)]
enum Coding {
    Video,
    Hevc,
    Audio,
    Graphics,
    Text,
    Other,
}

fn coding(t: u64) -> Coding {
    match t {
        0x01 | 0x02 | 0x1b | 0x20 | 0xea => Coding::Video,
        0x24 => Coding::Hevc,
        0x03 | 0x04 | 0x80..=0x86 | 0xa1 | 0xa2 => Coding::Audio,
        0x90 | 0x91 => Coding::Graphics,
        0x92 => Coding::Text,
        _ => Coding::Other,
    }
}

/// A three-letter ISO 639-2 language code.
fn lang(b: &mut Bits<'_>) -> Result<u64> {
    b.bytes("Language", 3)
        .with(|_, n| {
            let code = match &n.value {
                Some(crate::value::Value::Bytes(v)) => fourcc(v),
                _ => String::new(),
            };
            n.value(text(code))
        })
        .emit()
}

/// One line for a stream's coding attributes (from the bytes after the
/// length byte).
fn coding_summary(body: &[u8]) -> String {
    let t = body.first().copied().unwrap_or(0);
    let b1 = body.get(1).copied().unwrap_or(0);
    let name = lookup(CODING_TYPE, t.into()).unwrap_or("unknown coding");
    let format = u64::from(b1 >> 4);
    let rate = u64::from(b1 & 0xf);
    let lang_at = |at: usize| fourcc(body.get(at..at.saturating_add(3)).unwrap_or_default());
    match coding(t.into()) {
        Coding::Video | Coding::Hevc => format!(
            "{name} {} @ {}",
            lookup(VIDEO_FORMAT, format).unwrap_or("?"),
            lookup(FRAME_RATE, rate).unwrap_or("?")
        ),
        Coding::Audio => format!(
            "{name} {}, {}, {}",
            lookup(AUDIO_FORMAT, format).unwrap_or("?"),
            lookup(AUDIO_RATE, rate).unwrap_or("?"),
            lang_at(2)
        ),
        Coding::Graphics => format!("{name}, {}", lang_at(1)),
        Coding::Text => format!("{name}, {}", lang_at(2)),
        Coding::Other => name.into(),
    }
}

/// A playlist stream's attributes (STN table): length, coding type, then
/// the fields of that coding.
fn stream_attributes(b: &mut Bits<'_>) -> Result<()> {
    b.field("Length", 8).emit()?;
    let t = b.field("Coding type", 8).enumeration(CODING_TYPE).emit()?;
    match coding(t) {
        Coding::Video => {
            b.field("Video format", 4)
                .enumeration(VIDEO_FORMAT)
                .emit()?;
            b.field("Frame rate", 4).enumeration(FRAME_RATE).emit()?;
        }
        Coding::Hevc => {
            b.field("Video format", 4)
                .enumeration(VIDEO_FORMAT)
                .emit()?;
            b.field("Frame rate", 4).enumeration(FRAME_RATE).emit()?;
            b.field("Dynamic range type", 4).emit()?;
            b.field("Colour space", 4).emit()?;
            b.field("Copy restriction", 1).flag().emit()?;
            b.field("HDR10+", 1).flag().emit()?;
        }
        Coding::Audio => {
            b.field("Audio format", 4)
                .enumeration(AUDIO_FORMAT)
                .emit()?;
            b.field("Sample rate", 4).enumeration(AUDIO_RATE).emit()?;
            lang(b)?;
        }
        Coding::Graphics => {
            lang(b)?;
        }
        Coding::Text => {
            b.field("Character code", 8).enumeration(CHAR_CODE).emit()?;
            lang(b)?;
        }
        Coding::Other => {}
    }
    Ok(())
}

/// A clip's stream coding info (ProgramInfo): like the playlist's, with
/// the aspect ratio for video, and an ISRC after the coding fields.
fn clip_coding_info(b: &mut Bits<'_>) -> Result<()> {
    let len = b.field("Length", 8).emit()?;
    let t = b.field("Coding type", 8).enumeration(CODING_TYPE).emit()?;
    match coding(t) {
        Coding::Video | Coding::Hevc => {
            b.field("Video format", 4)
                .enumeration(VIDEO_FORMAT)
                .emit()?;
            b.field("Frame rate", 4).enumeration(FRAME_RATE).emit()?;
            b.field("Aspect ratio", 4).enumeration(ASPECT).emit()?;
            b.skip(2);
            b.field("Original content", 1).flag().emit()?;
            if coding(t) == Coding::Hevc {
                b.field("Copy restriction", 1).flag().emit()?;
                b.field("Dynamic range type", 4).emit()?;
                b.field("Colour space", 4).emit()?;
                b.field("HDR10+", 1).flag().emit()?;
            }
        }
        Coding::Audio => {
            b.field("Audio format", 4)
                .enumeration(AUDIO_FORMAT)
                .emit()?;
            b.field("Sample rate", 4).enumeration(AUDIO_RATE).emit()?;
            lang(b)?;
        }
        Coding::Graphics => {
            lang(b)?;
        }
        Coding::Text => {
            b.field("Character code", 8).enumeration(CHAR_CODE).emit()?;
            lang(b)?;
        }
        Coding::Other => {}
    }
    // The coding fields fill the first 5 bytes after the length; the ISRC
    // follows when the entry is long enough.
    if len >= 17 {
        b.seek(6 * 8);
        b.bytes("ISRC", 12)
            .with(|_, n| {
                let code = match &n.value {
                    Some(crate::value::Value::Bytes(v)) => fourcc(v),
                    _ => String::new(),
                };
                n.value(text(code))
            })
            .emit()?;
    }
    Ok(())
}

/// ExtensionData: a header and a directory of (ID1, ID2) blocks, each at
/// an offset from the start of the section.
async fn extension_data(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 12)).await?;
    cx.emit(struct_node("Header", span.sub(0, 12), BE, (), ext_header));
    let count = u64::from(data.get(11).copied().unwrap_or(0));
    let dir = cx
        .read_avail(span.sub(12, count.saturating_mul(12)))
        .await?;
    for i in 0..count {
        let at = i.saturating_mul(12);
        let e = dir.get(to_usize(at)..).unwrap_or_default();
        let (id1, id2) = (u16_be(e, 0).unwrap_or(0), u16_be(e, 2).unwrap_or(0));
        let start = u64::from(u32_be(e, 4).unwrap_or(0));
        let len = u64::from(u32_be(e, 8).unwrap_or(0));
        let name = match (id1, id2) {
            (1, 1) => "picture-in-picture metadata",
            (2, 1) => "stereoscopic STN table",
            (2, 2) => "sub-path entries extension",
            (2, 5) => "extent start points",
            (2, 6) => "stereoscopic program info",
            (2, 7) => "stereoscopic CPI",
            (3, 1) => "UHD disc information",
            (3, 5) => "static metadata",
            _ => "",
        };
        let block = span.sub(start, len);
        let mut node = if (id1, id2) == (3, 1) {
            bits_node(format!("Extension {id1}.{id2}"), block, uhd_info, false)
        } else {
            Node::new(format!("Extension {id1}.{id2}")).span(block)
        };
        if !name.is_empty() {
            node = node.summary(name);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// index.bdmv's UHD extension, as libbluray reads it (the bits it skips
/// are not documented publicly).
fn uhd_info(b: &mut Bits<'_>) -> Result<()> {
    b.field("Length", 32).emit()?;
    b.field("Disc type", 4).emit()?;
    b.skip(3);
    b.field("4K content", 1).flag().emit()?;
    b.skip(8 + 3);
    b.field("HDR10+", 1).flag().emit()?;
    b.skip(1);
    b.field("Dolby Vision", 1).flag().emit()?;
    b.field("HDR flags", 2).hex().emit()?;
    Ok(())
}

fn ext_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Length").emit()?;
    f.u32("Data block start").hex().emit()?;
    f.skip(3);
    f.u8("Entries").emit()?;
    Ok(())
}

async fn emit_extension(cx: &Cx, file: Span, start: u64) {
    emit_section(cx, file, start, |span| {
        let node = Node::new("Extension data").span(span);
        // Some writers point at an empty section (a zero length).
        if span.len <= 4 {
            node.summary("empty")
        } else {
            node.lazy(extension_data, span)
        }
    })
    .await;
}

// ---------------------------------------------------------------------------
// index.bdmv

async fn index(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x28)).await?;
    cx.emit(struct_node(
        "Header",
        file.sub(0, 0x28),
        BE,
        &["Indexes offset", "Extension data offset"][..],
        file_header,
    ));
    let version = fourcc(head.get(4..8).unwrap_or_default());
    emit_section(&cx, file, 0x28, |span| {
        bits_node("AppInfoBDMV", span, app_info, false)
    })
    .await;
    let indexes = u64::from(u32_be(&head, 8).unwrap_or(0));
    let mut titles = 0u16;
    if let Some(span) = emit_section(&cx, file, indexes, |span| {
        Node::new("Indexes").span(span).lazy(expand_indexes, span)
    })
    .await
    {
        let t = cx.read_avail(span.sub(28, 2)).await?;
        titles = u16_be(&t, 0).unwrap_or(0);
    }
    emit_extension(&cx, file, u64::from(u32_be(&head, 12).unwrap_or(0))).await;
    cx.annotate(format!(
        "Blu-ray index {version}, {}",
        plural(titles, "title")
    ));
    Ok(())
}

fn app_info(b: &mut Bits<'_>) -> Result<()> {
    b.field("Length", 32).emit()?;
    b.skip(1);
    b.field("Initial output mode", 1)
        .enumeration(&[(0, "2D"), (1, "3D")])
        .emit()?;
    b.field("Stereoscopic content", 1).flag().emit()?;
    b.skip(1);
    b.field("Initial dynamic range type", 4).emit()?;
    b.field("Video format", 4)
        .enumeration(VIDEO_FORMAT)
        .emit()?;
    b.field("Frame rate", 4).enumeration(FRAME_RATE).emit()?;
    b.bytes("User data", 32).emit()?;
    Ok(())
}

const OBJECT_TYPE: EnumTable = &[(1, "HDMV"), (2, "BD-J")];
const PLAYBACK_TYPE: EnumTable = &[
    (0, "movie"),
    (1, "interactive"),
    (2, "movie"),
    (3, "interactive"),
];
const ACCESS_TYPE: FlagTable = &[flag(1, "title search prohibited"), flag(2, "hidden")];

/// An object reference's summary from its 12 bytes (title entries have the
/// access type in bits 29..28 of the first word).
fn object_summary(e: &[u8]) -> String {
    let kind = e.first().copied().unwrap_or(0) >> 6;
    let play = e.get(4).copied().unwrap_or(0) >> 6;
    let play = lookup(PLAYBACK_TYPE, play.into()).unwrap_or("?");
    match kind {
        1 => format!("HDMV {play}, movie object {}", u16_be(e, 6).unwrap_or(0)),
        2 => format!(
            "BD-J {play}, object {}",
            fourcc(e.get(6..11).unwrap_or_default())
        ),
        k => format!("object type {k}"),
    }
}

fn object_ref(b: &mut Bits<'_>, title: bool) -> Result<()> {
    let kind = b.field("Object type", 2).enumeration(OBJECT_TYPE).emit()?;
    if title {
        b.field("Access type", 2).flags(ACCESS_TYPE).emit()?;
        b.skip(28);
    } else {
        b.skip(30);
    }
    b.field("Playback type", 2)
        .enumeration(PLAYBACK_TYPE)
        .emit()?;
    b.skip(14);
    if kind == 2 {
        b.bytes("BD-J object", 5)
            .with(|_, n| {
                let name = match &n.value {
                    Some(crate::value::Value::Bytes(v)) => fourcc(v),
                    _ => String::new(),
                };
                n.value(text(name))
            })
            .emit()?;
    } else {
        b.field("Movie object", 16).emit()?;
    }
    Ok(())
}

fn playback_object(b: &mut Bits<'_>) -> Result<()> {
    object_ref(b, false)
}

fn title_object(b: &mut Bits<'_>) -> Result<()> {
    object_ref(b, true)
}

async fn expand_indexes(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 30)).await?;
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, 4))
            .value(uint(u32_be(&data, 0).unwrap_or(0), 32)),
    );
    for (name, at) in [("First playback", 4u64), ("Top menu", 16)] {
        let e = data.get(to_usize(at)..).unwrap_or_default();
        cx.emit(
            bits_node(name, span.sub(at, 12), playback_object, false).summary(object_summary(e)),
        );
    }
    let count = u64::from(u16_be(&data, 28).unwrap_or(0));
    cx.emit(
        Node::new("Titles")
            .span(span.sub(28, 2))
            .value(uint(count, 16)),
    );
    let room = span.len.saturating_sub(30) / 12;
    if count > room {
        cx.diag(Diagnostic::malformed(format!("{count} titles do not fit the table")).at(span));
    }
    let list = span.sub(30, count.min(room).saturating_mul(12));
    let entries = cx.read_avail(list).await?;
    for i in 0..count.min(room) {
        let at = i.saturating_mul(12);
        let e = entries.get(to_usize(at)..).unwrap_or_default();
        cx.push(
            bits_node(
                format!("Title {}", i.saturating_add(1)),
                list.sub(at, 12),
                title_object,
                false,
            )
            .summary(object_summary(e)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MovieObject.bdmv

async fn movie_object(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x28)).await?;
    cx.emit(struct_node(
        "Header",
        file.sub(0, 0x28),
        BE,
        &["Extension data offset"][..],
        file_header,
    ));
    let version = fourcc(head.get(4..8).unwrap_or_default());
    let mut objects = 0u16;
    if let Some(span) = emit_section(&cx, file, 0x28, |span| {
        Node::new("Movie objects")
            .span(span)
            .lazy(expand_objects, span)
    })
    .await
    {
        let t = cx.read_avail(span.sub(8, 2)).await?;
        objects = u16_be(&t, 0).unwrap_or(0);
    }
    emit_extension(&cx, file, u64::from(u32_be(&head, 8).unwrap_or(0))).await;
    cx.annotate(format!(
        "Blu-ray movie objects {version}, {}",
        plural(objects, "object")
    ));
    Ok(())
}

async fn expand_objects(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 10)).await?;
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, 4))
            .value(uint(u32_be(&data, 0).unwrap_or(0), 32)),
    );
    let count = u64::from(u16_be(&data, 8).unwrap_or(0));
    cx.emit(
        Node::new("Objects")
            .span(span.sub(8, 2))
            .value(uint(count, 16)),
    );
    let mut at = 10u64;
    for i in 0..count {
        let h = cx.read_avail(span.sub(at, 4)).await?;
        if h.len() < 4 {
            cx.diag(Diagnostic::truncated(span.sub(at, 4), to_u64(h.len())));
            break;
        }
        let flags = h.first().copied().unwrap_or(0);
        let cmds = u64::from(u16_be(&h, 2).unwrap_or(0));
        let obj = span.sub(at, cmds.saturating_mul(12).saturating_add(4));
        let mut summary = plural(cmds, "command");
        if flags & 0x80 != 0 {
            summary.push_str(", resumable");
        }
        cx.push(
            Node::new(format!("Object {i}"))
                .span(obj)
                .summary(summary)
                .lazy(expand_object, obj),
        )
        .await;
        at = at.saturating_add(obj.len.max(4));
        if at >= span.len {
            break;
        }
    }
    Ok(())
}

const OBJECT_FLAGS: FlagTable = &[
    flag(0x8000, "resume intention"),
    flag(0x4000, "menu call masked"),
    flag(0x2000, "title search masked"),
];

async fn expand_object(cx: Cx, obj: Span) -> Result<()> {
    let data = cx.read_avail(obj).await?;
    cx.emit(struct_node("Flags", obj.sub(0, 4), BE, (), object_header));
    let count = to_u64(data.len()).saturating_sub(4) / 12;
    cx.set_count(Count::Exact(count.saturating_add(1)));
    for i in 0..count {
        let at = i.saturating_mul(12).saturating_add(4);
        let insn = u32_be(&data, to_usize(at)).unwrap_or(0);
        let dst = u32_be(&data, to_usize(at.saturating_add(4))).unwrap_or(0);
        let src = u32_be(&data, to_usize(at.saturating_add(8))).unwrap_or(0);
        cx.push(
            bits_node(format!("Command {i}"), obj.sub(at, 12), hdmv_insn, false)
                .summary(hdmv_command(insn, dst, src)),
        )
        .await;
    }
    Ok(())
}

fn object_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Flags").flags(OBJECT_FLAGS).emit()?;
    f.u16("Commands").emit()?;
    Ok(())
}

// HDMV navigation commands (libbluray's hdmv_insn_t and mobj_print.c).

const GROUP: EnumTable = &[(0, "branch"), (1, "compare"), (2, "set")];
const GOTO_OPS: [&str; 3] = ["nop", "goto", "break"];
const JUMP_OPS: [&str; 5] = [
    "JUMP_OBJECT",
    "JUMP_TITLE",
    "CALL_OBJECT",
    "CALL_TITLE",
    "RESUME",
];
const PLAY_OPS: [&str; 6] = [
    "PLAY_PL",
    "PLAY_PL_PI",
    "PLAY_PL_MK",
    "TERMINATE_PL",
    "LINK_PI",
    "LINK_MK",
];
const CMP_OPS: [&str; 8] = ["", "bc", "eq", "ne", "ge", "gt", "le", "lt"];
const SET_OPS: [&str; 16] = [
    "", "move", "swap", "add", "sub", "mul", "div", "mod", "rnd", "and", "or", "xor", "bitset",
    "bitclr", "shl", "shr",
];
const SETSYSTEM_OPS: [&str; 12] = [
    "",
    "SET_STREAM",
    "SET_NV_TIMER",
    "SET_BUTTON_PAGE",
    "ENABLE_BUTTON",
    "DISABLE_BUTTON",
    "SET_SEC_STREAM",
    "POPUP_OFF",
    "STILL_ON",
    "STILL_OFF",
    "SET_OUTPUT_MODE",
    "SET_STREAM_SS",
];

fn hdmv_insn(b: &mut Bits<'_>) -> Result<()> {
    b.field("Operand count", 3).emit()?;
    b.field("Group", 2).enumeration(GROUP).emit()?;
    b.field("Sub-group", 3).emit()?;
    b.field("Immediate operand 1", 1).flag().emit()?;
    b.field("Immediate operand 2", 1).flag().emit()?;
    b.skip(2);
    b.field("Branch option", 4).emit()?;
    b.skip(4);
    b.field("Compare option", 4).emit()?;
    b.skip(3);
    b.field("Set option", 5).emit()?;
    b.field("Destination", 32).hex().emit()?;
    b.field("Source", 32).hex().emit()?;
    Ok(())
}

fn operand(immediate: bool, v: u32) -> String {
    if immediate {
        v.to_string()
    } else if v & 0x8000_0000 != 0 {
        format!("PSR{}", v & 0x7f)
    } else {
        format!("r{}", v & 0xfff)
    }
}

/// A command in libbluray's mnemonics, with its operands.
fn hdmv_command(insn: u32, dst: u32, src: u32) -> String {
    let [b0, b1, b2, b3] = insn.to_be_bytes();
    let op_cnt = b0 >> 5;
    let grp = (b0 >> 3) & 3;
    let sub = b0 & 7;
    let imm1 = b1 & 0x80 != 0;
    let imm2 = b1 & 0x40 != 0;
    let branch = usize::from(b1 & 0xf);
    let cmp = usize::from(b2 & 0xf);
    let set = usize::from(b3 & 0x1f);
    let name = match (grp, sub) {
        (0, 0) => GOTO_OPS.get(branch).copied(),
        (0, 1) => JUMP_OPS.get(branch).copied(),
        (0, 2) => PLAY_OPS.get(branch).copied(),
        (1, _) => CMP_OPS.get(cmp).copied().filter(|n| !n.is_empty()),
        (2, 0) => SET_OPS.get(set).copied().filter(|n| !n.is_empty()),
        (2, 1) if set == 0x10 => Some("SETSYSTEM_0x10"),
        (2, 1) => SETSYSTEM_OPS.get(set).copied().filter(|n| !n.is_empty()),
        _ => None,
    };
    let Some(name) = name else {
        return format!("unknown instruction {insn:#010x}");
    };
    match op_cnt {
        0 => name.to_owned(),
        1 => format!("{name} {}", operand(imm1, dst)),
        _ => format!("{name} {}, {}", operand(imm1, dst), operand(imm2, src)),
    }
}

// ---------------------------------------------------------------------------
// Playlists (.mpls)

async fn playlist(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x28)).await?;
    cx.emit(struct_node(
        "Header",
        file.sub(0, 0x28),
        BE,
        &[
            "PlayList offset",
            "PlayListMark offset",
            "Extension data offset",
        ][..],
        file_header,
    ));
    let version = fourcc(head.get(4..8).unwrap_or_default());
    emit_section(&cx, file, 0x28, |span| {
        struct_node("AppInfoPlayList", span, BE, (), playlist_app_info)
    })
    .await;
    let mut summary = format!("Blu-ray playlist {version}");
    let list = u64::from(u32_be(&head, 8).unwrap_or(0));
    if let Some(span) = emit_section(&cx, file, list, |span| {
        Node::new("PlayList").span(span).lazy(expand_playlist, span)
    })
    .await
    {
        let t = cx.read_avail(span.sub(6, 4)).await?;
        let items = u16_be(&t, 0).unwrap_or(0);
        let subs = u16_be(&t, 2).unwrap_or(0);
        summary.push_str(&format!(
            ", {}, {}",
            plural(items, "play item"),
            plural(subs, "sub-path")
        ));
    }
    let marks = u64::from(u32_be(&head, 12).unwrap_or(0));
    if let Some(span) = emit_section(&cx, file, marks, |span| {
        Node::new("PlayListMark")
            .span(span)
            .lazy(expand_marks, span)
    })
    .await
    {
        let t = cx.read_avail(span.sub(4, 2)).await?;
        summary.push_str(&format!(", {}", plural(u16_be(&t, 0).unwrap_or(0), "mark")));
    }
    emit_extension(&cx, file, u64::from(u32_be(&head, 16).unwrap_or(0))).await;
    cx.annotate(summary);
    Ok(())
}

const PLAYLIST_TYPE: EnumTable = &[(1, "sequential"), (2, "random"), (3, "shuffle")];

/// User operations a playlist or play item masks (bit 63 first).
const UO_MASK: FlagTable = &[
    flag(1 << 63, "menu call"),
    flag(1 << 62, "title search"),
    flag(1 << 61, "chapter search"),
    flag(1 << 60, "time search"),
    flag(1 << 59, "skip to next point"),
    flag(1 << 58, "skip to previous point"),
    flag(1 << 57, "play first play"),
    flag(1 << 56, "stop"),
    flag(1 << 55, "pause on"),
    flag(1 << 54, "pause off"),
    flag(1 << 53, "still off"),
    flag(1 << 52, "forward play"),
    flag(1 << 51, "backward play"),
    flag(1 << 50, "resume"),
    flag(1 << 49, "move up"),
    flag(1 << 48, "move down"),
    flag(1 << 47, "move left"),
    flag(1 << 46, "move right"),
    flag(1 << 45, "select"),
    flag(1 << 44, "activate"),
    flag(1 << 43, "select and activate"),
    flag(1 << 42, "primary audio change"),
    flag(1 << 40, "angle change"),
    flag(1 << 39, "popup on"),
    flag(1 << 38, "popup off"),
    flag(1 << 37, "PG enable/disable"),
    flag(1 << 36, "PG change"),
    flag(1 << 35, "secondary video enable/disable"),
    flag(1 << 34, "secondary video change"),
    flag(1 << 33, "secondary audio enable/disable"),
    flag(1 << 32, "secondary audio change"),
    flag(1 << 30, "PiP PG change"),
];

const APP_FLAGS: FlagTable = &[
    flag(0x8000, "random access prohibited"),
    flag(0x4000, "audio mix"),
    flag(0x2000, "lossless bypass"),
    flag(0x1000, "MVC base view is right eye"),
    flag(0x0800, "SDR conversion notification"),
];

fn playlist_app_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Length").emit()?;
    f.skip(1);
    let kind = f.u8("Playback type").enumeration(PLAYLIST_TYPE).emit()?;
    if kind == 2 || kind == 3 {
        f.u16("Playback count").emit()?;
    } else {
        f.skip(2);
    }
    f.u64("User operation mask").flags(UO_MASK).emit()?;
    f.u16("Flags").flags(APP_FLAGS).emit()?;
    Ok(())
}

async fn expand_playlist(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 10)).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 10),
        BE,
        (),
        playlist_header,
    ));
    let items = u64::from(u16_be(&data, 6).unwrap_or(0));
    let subs = u64::from(u16_be(&data, 8).unwrap_or(0));
    let mut at = 10u64;
    for i in 0..items {
        let h = cx.read_avail(span.sub(at, 22)).await?;
        if h.len() < 2 {
            cx.diag(Diagnostic::truncated(span.sub(at, 2), to_u64(h.len())));
            return Ok(());
        }
        let len = u64::from(u16_be(&h, 0).unwrap_or(0)).saturating_add(2);
        let item = span.sub(at, len);
        let clip = fourcc(h.get(2..7).unwrap_or_default());
        let codec = fourcc(h.get(7..11).unwrap_or_default());
        let t_in = u32_be(&h, 14).unwrap_or(0);
        let t_out = u32_be(&h, 18).unwrap_or(0);
        cx.push(
            Node::new(format!("Play item {i}"))
                .span(item)
                .summary(format!(
                    "{clip}.{codec}, {} – {}",
                    ticks(t_in),
                    ticks(t_out)
                ))
                .lazy(expand_play_item, item),
        )
        .await;
        at = at.saturating_add(len);
    }
    for i in 0..subs {
        let h = cx.read_avail(span.sub(at, 10)).await?;
        if h.len() < 4 {
            cx.diag(Diagnostic::truncated(span.sub(at, 4), to_u64(h.len())));
            return Ok(());
        }
        let len = u64::from(u32_be(&h, 0).unwrap_or(0)).saturating_add(4);
        let sub = span.sub(at, len);
        let kind = h.get(5).copied().unwrap_or(0);
        let items = h.get(9).copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Sub-path {i}"))
                .span(sub)
                .summary(format!(
                    "{}, {}",
                    lookup(SUBPATH_TYPE, kind.into()).unwrap_or("unknown type"),
                    plural(items, "sub-play item")
                ))
                .lazy(expand_sub_path, sub),
        )
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}

fn playlist_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Length").emit()?;
    f.skip(2);
    f.u16("Play items").emit()?;
    f.u16("Sub-paths").emit()?;
    Ok(())
}

const CONNECTION: EnumTable = &[
    (1, "not seamless"),
    (5, "seamless with a clean break"),
    (6, "seamless"),
];
const STILL_MODE: EnumTable = &[(0, "none"), (1, "finite"), (2, "infinite")];

async fn expand_play_item(cx: Cx, item: Span) -> Result<()> {
    let data = cx.read_avail(item).await?;
    let block = crate::cx::Block {
        span: item,
        data: data.clone(),
    };
    let mut f = Fields::emitting(&cx, &block, BE);
    let multi = play_item_fields(&mut f)?;
    let mut at = f.pos();
    if multi {
        let angles = u64::from(data.get(to_usize(at)).copied().unwrap_or(0));
        cx.emit(
            Node::new("Angles")
                .span(item.sub(at, 1))
                .value(uint(angles, 8)),
        );
        cx.emit(
            Node::new("Angle flags")
                .span(item.sub(at.saturating_add(1), 1))
                .value(hex(
                    data.get(to_usize(at.saturating_add(1)))
                        .copied()
                        .unwrap_or(0),
                    8,
                ))
                .summary("bit 1: different audio; bit 0: seamless angle change"),
        );
        at = at.saturating_add(2);
        for a in 1..angles {
            let e = data.get(to_usize(at)..).unwrap_or_default();
            cx.emit(
                Node::new(format!("Angle {a}"))
                    .span(item.sub(at, 10))
                    .summary(format!(
                        "{}.{}, STC {}",
                        fourcc(e.get(..5).unwrap_or_default()),
                        fourcc(e.get(5..9).unwrap_or_default()),
                        e.get(9).copied().unwrap_or(0)
                    )),
            );
            at = at.saturating_add(10);
        }
    }
    let len = u64::from(u16_be(&data, to_usize(at)).unwrap_or(0)).saturating_add(2);
    let stn = item.sub(at, len);
    cx.emit(
        Node::new("STN table")
            .span(stn)
            .summary(stn_summary(data.get(to_usize(at)..).unwrap_or_default()))
            .lazy(expand_stn, stn),
    );
    Ok(())
}

/// The fixed part of a play item; returns whether it is multi-angle.
fn play_item_fields(f: &mut Fields<'_>) -> Result<bool> {
    f.u16("Length").emit()?;
    f.ascii("Clip", 5).emit()?;
    f.ascii("Codec", 4).emit()?;
    let flags = f
        .u16("Flags")
        .hex()
        .with(|&v, n| {
            let cc = lookup(CONNECTION, u64::from(v & 0xf)).unwrap_or("unknown connection");
            if v & 0x10 != 0 {
                n.summary(format!("multi-angle, {cc}"))
            } else {
                n.summary(cc)
            }
        })
        .emit()?;
    f.u8("STC ID").emit()?;
    f.u32("In time").duration(45_000).emit()?;
    f.u32("Out time").duration(45_000).emit()?;
    f.u64("User operation mask").flags(UO_MASK).emit()?;
    f.u8("Random access prohibited")
        .with(|&v, n| n.value(crate::value::Value::Bool(v & 0x80 != 0)))
        .emit()?;
    let still = f.u8("Still mode").enumeration(STILL_MODE).emit()?;
    if still == 1 {
        f.u16("Still time").duration(1).emit()?;
    } else {
        f.skip(2);
    }
    Ok(flags & 0x10 != 0)
}

const STN_GROUPS: [&str; 8] = [
    "Video",
    "Audio",
    "PG",
    "IG",
    "Secondary audio",
    "Secondary video",
    "PiP PG",
    "Dolby Vision",
];

fn stn_summary(stn: &[u8]) -> String {
    let counts: Vec<String> = STN_GROUPS
        .iter()
        .enumerate()
        .filter_map(|(i, name)| {
            let n = stn.get(i.saturating_add(4)).copied().unwrap_or(0);
            (n != 0).then(|| format!("{n} {}", name.to_lowercase()))
        })
        .collect();
    if counts.is_empty() {
        "no streams".into()
    } else {
        counts.join(", ")
    }
}

fn stn_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.skip(2);
    for name in [
        "Video streams",
        "Audio streams",
        "PG streams",
        "IG streams",
        "Secondary audio streams",
        "Secondary video streams",
        "PiP PG streams",
        "Dolby Vision streams",
    ] {
        f.u8(name).emit()?;
    }
    f.skip(4);
    Ok(())
}

async fn expand_stn(cx: Cx, stn: Span) -> Result<()> {
    let data = cx.read_avail(stn).await?;
    cx.emit(struct_node("Header", stn.sub(0, 16), BE, (), stn_header));
    let count = |i: usize| u64::from(data.get(i.saturating_add(4)).copied().unwrap_or(0));
    // libbluray's order: PG and PiP PG share one run of entries.
    let groups: [(&str, u64, usize); 7] = [
        ("Video", count(0), 0),
        ("Audio", count(1), 0),
        ("PG", count(2).saturating_add(count(6)), 0),
        ("IG", count(3), 0),
        ("Secondary audio", count(4), 1),
        ("Secondary video", count(5), 2),
        ("Dolby Vision", count(7), 0),
    ];
    let mut at = 16usize;
    for (name, n, refs) in groups {
        for i in 0..n {
            let start = at;
            // Stream entry, then attributes, each led by its length.
            let entry_len = usize::from(data.get(at).copied().unwrap_or(0));
            let attr_at = at.saturating_add(1).saturating_add(entry_len);
            let attr_len = usize::from(data.get(attr_at).copied().unwrap_or(0));
            let mut end = attr_at.saturating_add(1).saturating_add(attr_len);
            // Secondary streams list the primary streams they go with.
            for _ in 0..refs {
                let k = usize::from(data.get(end).copied().unwrap_or(0));
                end = end
                    .saturating_add(2)
                    .saturating_add(k)
                    .saturating_add(k & 1);
            }
            if end > data.len() {
                cx.diag(
                    Diagnostic::malformed("stream entry runs past the STN table")
                        .at(stn.sub(to_u64(start), to_u64(end.saturating_sub(start)))),
                );
                return Ok(());
            }
            let entry = data.get(start..).unwrap_or_default();
            let pid = match entry.get(1).copied().unwrap_or(0) {
                1 => u16_be(entry, 2),
                2 => u16_be(entry, 4),
                _ => u16_be(entry, 3),
            }
            .unwrap_or(0);
            let attrs = data.get(attr_at.saturating_add(1)..).unwrap_or_default();
            let span = stn.sub(to_u64(start), to_u64(end.saturating_sub(start)));
            cx.push(
                Node::new(format!("{name} stream {i}"))
                    .span(span)
                    .summary(format!("{}, PID {pid:#06x}", coding_summary(attrs)))
                    .lazy(
                        expand_stream,
                        (
                            stn.sub(to_u64(start), to_u64(entry_len.saturating_add(1))),
                            stn.sub(to_u64(attr_at), to_u64(attr_len.saturating_add(1))),
                            stn.sub(
                                to_u64(attr_at.saturating_add(1).saturating_add(attr_len)),
                                to_u64(end.saturating_sub(
                                    attr_at.saturating_add(1).saturating_add(attr_len),
                                )),
                            ),
                        ),
                    ),
            )
            .await;
            at = end;
        }
    }
    Ok(())
}

async fn expand_stream(cx: Cx, (entry, attrs, refs): (Span, Span, Span)) -> Result<()> {
    cx.emit(bits_node("Entry", entry, stream_entry, false));
    cx.emit(bits_node("Attributes", attrs, stream_attributes, false));
    if refs.len != 0 {
        cx.emit(Node::new("Stream references").span(refs));
    }
    Ok(())
}

const ENTRY_TYPE: EnumTable = &[
    (1, "play item's clip"),
    (2, "sub-path clip"),
    (3, "sub-path in the main clip"),
    (4, "sub-path in the main clip (Dolby Vision)"),
];

fn stream_entry(b: &mut Bits<'_>) -> Result<()> {
    b.field("Length", 8).emit()?;
    let kind = b.field("Stream type", 8).enumeration(ENTRY_TYPE).emit()?;
    match kind {
        1 => {
            b.field("PID", 16).hex().emit()?;
        }
        2 => {
            b.field("Sub-path", 8).emit()?;
            b.field("Sub-clip", 8).emit()?;
            b.field("PID", 16).hex().emit()?;
        }
        3 | 4 => {
            b.field("Sub-path", 8).emit()?;
            b.field("PID", 16).hex().emit()?;
        }
        _ => {}
    }
    Ok(())
}

const SUBPATH_TYPE: EnumTable = &[
    (2, "browsable slideshow audio"),
    (3, "interactive graphics menu"),
    (4, "text subtitles"),
    (5, "out-of-mux synchronous"),
    (6, "out-of-mux asynchronous picture-in-picture"),
    (7, "in-mux synchronous picture-in-picture"),
    (8, "stereoscopic video"),
    (9, "stereoscopic interactive graphics"),
    (10, "Dolby Vision enhancement layer"),
];

async fn expand_sub_path(cx: Cx, sub: Span) -> Result<()> {
    let data = cx.read_avail(sub.sub(0, 10)).await?;
    cx.emit(struct_node(
        "Header",
        sub.sub(0, 10),
        BE,
        (),
        sub_path_header,
    ));
    let items = data.get(9).copied().unwrap_or(0);
    let mut at = 10u64;
    for i in 0..items {
        let h = cx.read_avail(sub.sub(at, 2)).await?;
        if h.len() < 2 {
            cx.diag(Diagnostic::truncated(sub.sub(at, 2), to_u64(h.len())));
            break;
        }
        let len = u64::from(u16_be(&h, 0).unwrap_or(0)).saturating_add(2);
        let span = sub.sub(at, len);
        cx.push(struct_node(
            format!("Sub-play item {i}"),
            span,
            BE,
            (),
            sub_play_item,
        ))
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}

fn sub_path_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Length").emit()?;
    f.skip(1);
    f.u8("Sub-path type").enumeration(SUBPATH_TYPE).emit()?;
    f.u16("Repeat")
        .with(|&v, n| n.value(crate::value::Value::Bool(v & 1 != 0)))
        .emit()?;
    f.skip(1);
    f.u8("Sub-play items").emit()?;
    Ok(())
}

fn sub_play_item(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Length").emit()?;
    f.ascii("Clip", 5).emit()?;
    f.ascii("Codec", 4).emit()?;
    let flags = f
        .u32("Flags")
        .hex()
        .with(|&v, n| {
            let cc = lookup(CONNECTION, u64::from((v >> 1) & 0xf)).unwrap_or("unknown connection");
            if v & 1 != 0 {
                n.summary(format!("multi-clip, {cc}"))
            } else {
                n.summary(cc)
            }
        })
        .emit()?;
    f.u8("STC ID").emit()?;
    f.u32("In time").duration(45_000).emit()?;
    f.u32("Out time").duration(45_000).emit()?;
    f.u16("Sync play item").emit()?;
    f.u32("Sync start time").duration(45_000).emit()?;
    if flags & 1 != 0 {
        let clips = f.u8("Clips").emit()?;
        f.skip(1);
        for _ in 1..clips {
            f.ascii("Clip", 5).emit()?;
            f.ascii("Codec", 4).emit()?;
            f.u8("STC ID").emit()?;
        }
    }
    Ok(())
}

const MARK_TYPE: EnumTable = &[(1, "entry mark"), (2, "link point")];

async fn expand_marks(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 6)).await?;
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, 4))
            .value(uint(u32_be(&data, 0).unwrap_or(0), 32)),
    );
    let count = u64::from(u16_be(&data, 4).unwrap_or(0));
    cx.emit(
        Node::new("Marks")
            .span(span.sub(4, 2))
            .value(uint(count, 16)),
    );
    let room = span.len.saturating_sub(6) / 14;
    let list = span.sub(6, count.min(room).saturating_mul(14));
    let marks = cx.read_avail(list).await?;
    for i in 0..count.min(room) {
        let at = i.saturating_mul(14);
        let e = marks.get(to_usize(at)..).unwrap_or_default();
        let kind = e.get(1).copied().unwrap_or(0);
        cx.push(
            struct_node(format!("Mark {i}"), list.sub(at, 14), BE, (), mark).summary(format!(
                "{}, play item {} at {}",
                lookup(MARK_TYPE, kind.into()).unwrap_or("unknown"),
                u16_be(e, 2).unwrap_or(0),
                ticks(u32_be(e, 4).unwrap_or(0))
            )),
        )
        .await;
    }
    Ok(())
}

fn mark(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.skip(1);
    f.u8("Mark type").enumeration(MARK_TYPE).emit()?;
    f.u16("Play item").emit()?;
    f.u32("Time").duration(45_000).emit()?;
    f.u16("Entry ES PID").hex().emit()?;
    f.u32("Duration").duration(45_000).emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Clip information (.clpi)

async fn clip_info(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x28)).await?;
    cx.emit(struct_node(
        "Header",
        file.sub(0, 0x28),
        BE,
        &[
            "SequenceInfo offset",
            "ProgramInfo offset",
            "CPI offset",
            "ClipMark offset",
            "Extension data offset",
        ][..],
        file_header,
    ));
    let version = fourcc(head.get(4..8).unwrap_or_default());
    let mut summary = format!("Blu-ray clip information {version}");
    if let Some(span) = emit_section(&cx, file, 0x28, |span| {
        Node::new("ClipInfo")
            .span(span)
            .lazy(expand_clip_info, span)
    })
    .await
    {
        let h = cx.read_avail(span.sub(0, 20)).await?;
        let app = h.get(7).copied().unwrap_or(0);
        let packets = u32_be(&h, 16).unwrap_or(0);
        summary.push_str(&format!(
            ", {}, {}",
            lookup(APPLICATION_TYPE, app.into()).unwrap_or("unknown application"),
            plural(packets, "source packet")
        ));
    }
    let off = |at: usize| u64::from(u32_be(&head, at).unwrap_or(0));
    emit_section(&cx, file, off(8), |span| {
        Node::new("SequenceInfo")
            .span(span)
            .lazy(expand_sequence_info, span)
    })
    .await;
    if let Some(span) = emit_section(&cx, file, off(12), |span| {
        Node::new("ProgramInfo")
            .span(span)
            .lazy(expand_program_info, span)
    })
    .await
    {
        // The first program's stream count, for the summary.
        let h = cx.read_avail(span.sub(0, 14)).await?;
        if h.get(5).copied().unwrap_or(0) != 0 {
            summary.push_str(&format!(
                ", {}",
                plural(h.get(12).copied().unwrap_or(0), "stream")
            ));
        }
    }
    emit_section(&cx, file, off(16), |span| {
        Node::new("CPI").span(span).lazy(expand_cpi, span)
    })
    .await;
    emit_section(&cx, file, off(20), |span| {
        Node::new("ClipMark")
            .span(span)
            .summary(if span.len <= 4 { "empty" } else { "marks" })
    })
    .await;
    emit_extension(&cx, file, off(24)).await;
    cx.annotate(summary);
    Ok(())
}

const APPLICATION_TYPE: EnumTable = &[
    (1, "main TS of a movie"),
    (2, "main TS of a time-based slideshow"),
    (3, "main TS of a browsable slideshow"),
    (4, "sub TS of a browsable slideshow"),
    (5, "sub TS of an interactive menu"),
    (6, "sub TS of text subtitles"),
    (7, "sub TS of sub-path elementary streams"),
    (8, "sub TS of an enhancement layer"),
];

async fn expand_clip_info(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let block = crate::cx::Block {
        span,
        data: data.clone(),
    };
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Length").emit()?;
    f.skip(2);
    f.u8("Clip stream type").emit()?;
    let app = f
        .u8("Application type")
        .enumeration(APPLICATION_TYPE)
        .emit()?;
    let atc_delta = f
        .u32("ATC delta")
        .with(|&v, n| n.value(crate::value::Value::Bool(v & 1 != 0)))
        .emit()?
        & 1
        != 0;
    f.u32("TS recording rate (bytes/s)").emit()?;
    f.u32("Source packets").emit()?;
    f.skip(128);
    let ts_len = u64::from(f.u16("TS type info length").emit()?);
    if ts_len >= 5 {
        f.u8("Validity flags").hex().emit()?;
        f.ascii("Format ID", 4).emit()?;
        let rest = ts_len.saturating_sub(5);
        if rest != 0 {
            f.node(Node::new("TS type info").span(f.peek_span(rest)));
            f.skip(rest);
        }
    } else {
        f.skip(ts_len);
    }
    if atc_delta {
        f.skip(1);
        let n = f.u8("ATC deltas").emit()?;
        for _ in 0..n {
            f.u32("ATC delta").emit()?;
            f.ascii("File", 5).emit()?;
            f.ascii("Codec", 4).emit()?;
            f.skip(1);
        }
    }
    if app == 6 {
        f.skip(1);
        let n = f.u8("Fonts").emit()?;
        for _ in 0..n {
            f.ascii("Font file", 5).emit()?;
            f.skip(1);
        }
    }
    Ok(())
}

async fn expand_sequence_info(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let block = crate::cx::Block {
        span,
        data: data.clone(),
    };
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Length").emit()?;
    f.skip(1);
    let atcs = f.u8("ATC sequences").emit()?;
    for a in 0..atcs {
        let start = f.pos();
        let stcs = u64::from(
            data.get(to_usize(start.saturating_add(4)))
                .copied()
                .unwrap_or(0),
        );
        let len = stcs.saturating_mul(14).saturating_add(6);
        f.node(
            struct_node(
                format!("ATC sequence {a}"),
                span.sub(start, len),
                BE,
                (),
                atc_sequence,
            )
            .summary(plural(stcs, "STC sequence")),
        );
        f.skip(len);
        if f.pos() > span.len {
            break;
        }
    }
    Ok(())
}

fn atc_sequence(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("SPN ATC start").emit()?;
    let n = f.u8("STC sequences").emit()?;
    f.u8("Offset STC ID").emit()?;
    for i in 0..n {
        f.node(struct_node(
            match i {
                0 => "STC sequence 0",
                1 => "STC sequence 1",
                _ => "STC sequence",
            },
            f.peek_span(14),
            BE,
            (),
            stc_sequence,
        ));
        f.skip(14);
    }
    Ok(())
}

fn stc_sequence(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("PCR PID").hex().emit()?;
    f.u32("SPN STC start").emit()?;
    f.u32("Presentation start").duration(45_000).emit()?;
    f.u32("Presentation end").duration(45_000).emit()?;
    Ok(())
}

async fn expand_program_info(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, 4))
            .value(uint(u32_be(&data, 0).unwrap_or(0), 32)),
    );
    let programs = data.get(5).copied().unwrap_or(0);
    cx.emit(
        Node::new("Programs")
            .span(span.sub(5, 1))
            .value(uint(programs, 8)),
    );
    let mut at = 6usize;
    for p in 0..programs {
        let start = at;
        let streams = usize::from(data.get(at.saturating_add(6)).copied().unwrap_or(0));
        at = at.saturating_add(8);
        let mut list = Vec::new();
        for _ in 0..streams {
            let len = usize::from(data.get(at.saturating_add(2)).copied().unwrap_or(0));
            let end = at.saturating_add(3).saturating_add(len);
            if end > data.len() {
                break;
            }
            list.push((at, end));
            at = end;
        }
        let span_p = span.sub(to_u64(start), to_u64(at.saturating_sub(start)));
        let streams_spans: Vec<(Span, Span)> = list
            .iter()
            .map(|&(s, e)| {
                (
                    span.sub(to_u64(s), to_u64(e.saturating_sub(s))),
                    span.sub(
                        to_u64(s.saturating_add(2)),
                        to_u64(e.saturating_sub(s).saturating_sub(2)),
                    ),
                )
            })
            .collect();
        let summaries: Vec<String> = list
            .iter()
            .map(|&(s, _)| {
                let pid = u16_be(&data, s).unwrap_or(0);
                let body = data.get(s.saturating_add(3)..).unwrap_or_default();
                format!("{}, PID {pid:#06x}", coding_summary(body))
            })
            .collect();
        cx.push(
            Node::new(format!("Program {p}"))
                .span(span_p)
                .summary(plural(to_u64(list.len()), "stream"))
                .lazy(
                    expand_program,
                    (
                        span.sub(to_u64(start), 8),
                        std::sync::Arc::new((streams_spans, summaries)),
                    ),
                ),
        )
        .await;
        if list.len() < streams {
            cx.diag(Diagnostic::malformed("program streams run past ProgramInfo").at(span_p));
            break;
        }
    }
    Ok(())
}

type ProgramStreams = std::sync::Arc<(Vec<(Span, Span)>, Vec<String>)>;

async fn expand_program(cx: Cx, (head, streams): (Span, ProgramStreams)) -> Result<()> {
    cx.emit(struct_node("Header", head, BE, (), program_header));
    for (i, ((whole, info), summary)) in streams.0.iter().zip(streams.1.iter()).enumerate() {
        cx.push(
            Node::new(format!("Stream {i}"))
                .span(*whole)
                .summary(summary.clone())
                .lazy(expand_clip_stream, (*whole, *info)),
        )
        .await;
    }
    Ok(())
}

fn program_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("SPN program sequence start").emit()?;
    f.u16("Program map PID").hex().emit()?;
    f.u8("Streams").emit()?;
    f.u8("Groups").emit()?;
    Ok(())
}

async fn expand_clip_stream(cx: Cx, (whole, info): (Span, Span)) -> Result<()> {
    let data = cx.read_avail(whole.sub(0, 2)).await?;
    cx.emit(
        Node::new("PID")
            .span(whole.sub(0, 2))
            .value(hex(u16_be(&data, 0).unwrap_or(0), 16)),
    );
    cx.emit(bits_node("Coding info", info, clip_coding_info, false));
    Ok(())
}

async fn expand_cpi(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 8)).await?;
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, 4))
            .value(uint(u32_be(&data, 0).unwrap_or(0), 32)),
    );
    if span.len <= 4 {
        return Ok(());
    }
    let kind = u16_be(&data, 4).unwrap_or(0) & 0xf;
    cx.emit(
        Node::new("CPI type")
            .span(span.sub(4, 2))
            .value(crate::formats::util::val::enumv(kind, 4, &[(1, "EP map")])),
    );
    if kind != 1 {
        return Ok(());
    }
    let map = span.tail(6);
    let head = cx.read_avail(map.sub(0, 2)).await?;
    let streams = u64::from(head.get(1).copied().unwrap_or(0));
    cx.emit(
        Node::new("EP map streams")
            .span(map.sub(1, 1))
            .value(uint(streams, 8)),
    );
    let dir = cx
        .read_avail(map.sub(2, streams.saturating_mul(12)))
        .await?;
    for i in 0..streams {
        let at = i.saturating_mul(12);
        let e = dir.get(to_usize(at)..).unwrap_or_default();
        let pid = u16_be(e, 0).unwrap_or(0);
        let word =
            u64::from(u32_be(e, 2).unwrap_or(0)) << 16 | u64::from(u16_be(e, 6).unwrap_or(0));
        // 10 reserved bits, type 4, coarse count 16, fine count 18.
        let kind = (word >> 34) & 0xf;
        let coarse = (word >> 18) & 0xffff;
        let fine = word & 0x3_ffff;
        let start = u64::from(u32_be(e, 8).unwrap_or(0));
        let entry = map.sub(2u64.saturating_add(at), 12);
        cx.push(
            Node::new(format!("Stream {i}"))
                .span(entry)
                .summary(format!(
                    "PID {pid:#06x}, type {kind}, {} coarse and {} fine entries",
                    coarse, fine
                ))
                .lazy(expand_ep_stream, (entry, map.tail(start), coarse, fine)),
        )
        .await;
    }
    Ok(())
}

async fn expand_ep_stream(
    cx: Cx,
    (entry, table, coarse, fine): (Span, Span, u64, u64),
) -> Result<()> {
    cx.emit(bits_node("Entry", entry, ep_stream_entry, false));
    let head = cx.read_avail(table.sub(0, 4)).await?;
    let fine_start = u64::from(u32_be(&head, 0).unwrap_or(0));
    cx.emit(
        Node::new("Fine table offset")
            .span(table.sub(0, 4))
            .value(hex(fine_start, 32)),
    );
    let coarse_span = table.sub(4, coarse.saturating_mul(8));
    cx.emit(
        Node::new("Coarse entries")
            .span(coarse_span)
            .summary(fmt::count(coarse, "entry", "entries"))
            .lazy(expand_ep_list, (coarse_span, true)),
    );
    let fine_span = table.sub(fine_start, fine.saturating_mul(4));
    cx.emit(
        Node::new("Fine entries")
            .span(fine_span)
            .summary(fmt::count(fine, "entry", "entries"))
            .lazy(expand_ep_list, (fine_span, false)),
    );
    Ok(())
}

fn ep_stream_entry(b: &mut Bits<'_>) -> Result<()> {
    b.field("PID", 16).hex().emit()?;
    b.skip(10);
    b.field("EP stream type", 4).emit()?;
    b.field("Coarse entries", 16).emit()?;
    b.field("Fine entries", 18).emit()?;
    b.field("Table offset", 32).hex().emit()?;
    Ok(())
}

fn ep_coarse(b: &mut Bits<'_>) -> Result<()> {
    b.field("Fine entry", 18).emit()?;
    b.field("PTS (bits 32..19)", 14).emit()?;
    b.field("SPN", 32).emit()?;
    Ok(())
}

fn ep_fine(b: &mut Bits<'_>) -> Result<()> {
    b.field("Angle change point", 1).flag().emit()?;
    b.field("I-picture end offset", 3).emit()?;
    b.field("PTS (bits 19..9)", 11).emit()?;
    b.field("SPN (low 17 bits)", 17).emit()?;
    Ok(())
}

async fn expand_ep_list(cx: Cx, (list, coarse): (Span, bool)) -> Result<()> {
    let size = if coarse { 8u64 } else { 4 };
    let count = list.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    let mut i = 0u64;
    while i < count {
        let page = count.saturating_sub(i).min(1024);
        let data = cx
            .read_avail(list.sub(i.saturating_mul(size), page.saturating_mul(size)))
            .await?;
        for j in 0..page {
            let at = to_usize(j.saturating_mul(size));
            let index = i.saturating_add(j);
            let span = list.sub(index.saturating_mul(size), size);
            let w = u32_be(&data, at).unwrap_or(0);
            let node = if coarse {
                let spn = u32_be(&data, at.saturating_add(4)).unwrap_or(0);
                let pts = u64::from(w & 0x3fff) << 19;
                bits_node(format!("Coarse {index}"), span, ep_coarse, false).summary(format!(
                    "fine {}, PTS {}, SPN {spn}",
                    w >> 14,
                    ticks(u32::try_from(pts / 2).unwrap_or(u32::MAX))
                ))
            } else {
                bits_node(format!("Fine {index}"), span, ep_fine, false).summary(format!(
                    "PTS bits {}, SPN bits {}",
                    (w >> 17) & 0x7ff,
                    w & 0x1_ffff
                ))
            };
            cx.push(node).await;
        }
        i = i.saturating_add(page.max(1));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        // Written by tsMuxer; libbluray's mobj_dump prints them as noted.
        let cases = [
            ((0x5000_0001, 10, 0), "move r10, r0"),
            ((0x5040_0001, 3, 0xffff), "move r3, 65535"),
            ((0x4282_0000, 0, 10), "PLAY_PL_MK 0, r10"),
            ((0x0002_0000, 0, 0), "break"),
            ((0x4840_0300, 10, 0xffff), "ne r10, 65535"),
            ((0x2200_0000, 10, 0), "PLAY_PL r10"),
            ((0x2101_0000, 10, 0), "JUMP_TITLE r10"),
            ((0x2181_0000, 1, 0), "JUMP_TITLE 1"),
        ];
        for ((insn, dst, src), text) in cases {
            assert_eq!(hdmv_command(insn, dst, src), text, "{insn:#010x}");
        }
        assert_eq!(ticks(27_045_000), "10 min 1 s");
    }
}
