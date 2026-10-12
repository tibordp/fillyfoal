//! DVD-Video information files: the video manager (`VIDEO_TS.IFO`) and the
//! video title sets (`VTS_nn_0.IFO`), and their `.BUP` backups.
//!
//! An IFO starts with a management table (VMGI_MAT or VTSI_MAT) that names
//! the other tables by sector (2048 bytes) within the file: title search
//! pointers, chapter (part-of-title) maps, program chains (PGCs) with their
//! navigation commands, programs and cells, menu language units, parental
//! management masks, title set attributes, cell address tables, VOBU address
//! maps and time maps. Layouts follow libdvdread's `ifo_types.h` and
//! `ifo_read.c`; command mnemonics follow libdvdnav's `vmcmd.c`.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::{self, fourcc, plural};
use crate::formats::util::sound::{Bits, bits_node};
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, flag, lookup};

const BE: Endian = Endian::Big;
/// Tables are addressed in DVD sectors.
const SECTOR: u64 = 2048;
/// VMGI_MAT up to the end of the menu sub-picture attributes.
const VMGI_MAT_LEN: u64 = 0x1fe;
/// VTSI_MAT up to the end of the multichannel extension.
const VTSI_MAT_LEN: u64 = 0x3d8;
/// A PGC's fixed part, up to the subtable offsets.
const PGC_LEN: u64 = 0xec;
const CELL_PLAYBACK_LEN: u64 = 24;

declare_format!(pub IFO = "dvd-ifo", "DVD-Video information file", ["ifo", "bup"],
    "application/x-dvd-ifo",
    Probe::Magic(&[(0, b"DVDVIDEO-VMG"), (0, b"DVDVIDEO-VTS")]), ifo);

/// The tables an IFO header points at.
#[derive(Clone, Copy, Debug, PartialEq)]
enum Table {
    /// Title search pointers (VMG).
    TtSrpt,
    /// Part-of-title (chapter) search pointers (VTS).
    PttSrpt,
    /// Program chain information table; `true` for a menu PGCIT.
    Pgcit(bool),
    /// Menu PGCI unit table: one PGCIT per language.
    PgciUt,
    /// Parental management information (VMG).
    PtlMait,
    /// Title set attributes (VMG).
    VtsAtrt,
    /// Text data manager (VMG).
    Txtdt,
    /// Cell address table.
    CAdt,
    /// VOBU address map.
    VobuAdmap,
    /// Time map table (VTS).
    Tmapt,
}

/// Header offset, name and kind of each sector pointer.
const VMG_TABLES: &[(usize, &str, Table)] = &[
    (0xc4, "Title search pointers (TT_SRPT)", Table::TtSrpt),
    (0xc8, "Menu PGCI units (VMGM_PGCI_UT)", Table::PgciUt),
    (0xcc, "Parental management (PTL_MAIT)", Table::PtlMait),
    (0xd0, "Title set attributes (VTS_ATRT)", Table::VtsAtrt),
    (0xd4, "Text data (TXTDT_MGI)", Table::Txtdt),
    (0xd8, "Menu cell addresses (VMGM_C_ADT)", Table::CAdt),
    (0xdc, "Menu VOBU map (VMGM_VOBU_ADMAP)", Table::VobuAdmap),
];

const VTS_TABLES: &[(usize, &str, Table)] = &[
    (
        0xc8,
        "Chapter search pointers (VTS_PTT_SRPT)",
        Table::PttSrpt,
    ),
    (0xcc, "Title PGCs (VTS_PGCIT)", Table::Pgcit(false)),
    (0xd0, "Menu PGCI units (VTSM_PGCI_UT)", Table::PgciUt),
    (0xd4, "Time maps (VTS_TMAPT)", Table::Tmapt),
    (0xd8, "Menu cell addresses (VTSM_C_ADT)", Table::CAdt),
    (0xdc, "Menu VOBU map (VTSM_VOBU_ADMAP)", Table::VobuAdmap),
    (0xe0, "Title cell addresses (VTS_C_ADT)", Table::CAdt),
    (0xe4, "Title VOBU map (VTS_VOBU_ADMAP)", Table::VobuAdmap),
];

async fn ifo(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, VTSI_MAT_LEN)).await?;
    let vts = head.get(..12) == Some(b"DVDVIDEO-VTS".as_slice());
    if vts {
        cx.emit(
            struct_node("VTSI_MAT", file.sub(0, VTSI_MAT_LEN), BE, (), vtsi_mat)
                .summary("Video title set information management table"),
        );
    } else {
        cx.emit(
            struct_node("VMGI_MAT", file.sub(0, VMGI_MAT_LEN), BE, (), vmgi_mat)
                .summary("Video manager information management table"),
        );
        // The first-play PGC is addressed in bytes, not sectors.
        let fp = u32_be(&head, 0x84).unwrap_or(0);
        if fp != 0 {
            match pgc_node(&cx, file, "First play PGC", u64::from(fp)).await {
                Ok(node) => cx.emit(node),
                Err(e) => cx.diag(e),
            }
        }
    }
    let tables = if vts { VTS_TABLES } else { VMG_TABLES };
    let mut titles = None;
    for &(at, name, kind) in tables {
        let sector = u32_be(&head, at).unwrap_or(0);
        if sector == 0 {
            continue;
        }
        let offset = u64::from(sector).saturating_mul(SECTOR);
        if offset >= file.len {
            cx.diag(
                Diagnostic::malformed(format!("{name} at sector {sector} is past the end"))
                    .at(file.sub(to_u64(at), 4)),
            );
            continue;
        }
        match table_node(&cx, file, offset, name, kind).await {
            Ok((node, count)) => {
                if kind == Table::TtSrpt || kind == Table::Pgcit(false) {
                    titles = Some(count);
                }
                cx.emit(node);
            }
            Err(e) => cx.diag(e),
        }
    }
    let version = head.get(0x21).copied().unwrap_or(0);
    let mut summary = format!(
        "DVD-Video {} {}.{}",
        if vts { "title set" } else { "manager" },
        version >> 4,
        version & 0xf
    );
    if vts {
        if let Some(n) = titles {
            summary.push_str(&format!(", {}", plural(n, "title PGC")));
        }
        let audio = head.get(0x203).copied().unwrap_or(0);
        let subp = head.get(0x255).copied().unwrap_or(0);
        if let Some(v) = u16_be(&head, 0x200) {
            summary.push_str(&format!(", {}", video_summary(v)));
        }
        summary.push_str(&format!(
            ", {}, {}",
            plural(audio, "audio stream"),
            plural(subp, "subpicture stream")
        ));
    } else {
        let sets = u16_be(&head, 0x3e).unwrap_or(0);
        summary.push_str(&format!(", {}", plural(sets, "title set")));
        if let Some(n) = titles {
            summary.push_str(&format!(", {}", plural(n, "title")));
        }
    }
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Management tables

fn vmgi_mat(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Identifier", 12).emit()?;
    f.u32("Last sector of VMG").emit()?;
    f.skip(12);
    f.u32("Last sector of VMGI").emit()?;
    f.skip(1);
    f.u8("Specification version")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}", v >> 4, v & 0xf)))
        .emit()?;
    f.u32("Category")
        .hex()
        .with(|&v, n| n.summary(regions(v)))
        .emit()?;
    f.u16("Volumes").emit()?;
    f.u16("Volume number").emit()?;
    f.u8("Disc side").emit()?;
    f.skip(19);
    f.u16("Title sets").emit()?;
    f.ascii("Provider ID", 32).emit()?;
    f.u64("POS code").hex().emit()?;
    f.skip(24);
    f.u32("Last byte of VMGI_MAT").hex().emit()?;
    f.u32("First play PGC offset").hex().emit()?;
    f.skip(56);
    f.u32("Menu VOBs start sector").emit()?;
    for name in [
        "TT_SRPT sector",
        "VMGM_PGCI_UT sector",
        "PTL_MAIT sector",
        "VTS_ATRT sector",
        "TXTDT_MGI sector",
        "VMGM_C_ADT sector",
        "VMGM_VOBU_ADMAP sector",
    ] {
        f.u32(name).emit()?;
    }
    f.seek(0x100);
    attributes(f, "Menu", 1, 1)
}

fn vtsi_mat(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Identifier", 12).emit()?;
    f.u32("Last sector of VTS").emit()?;
    f.skip(12);
    f.u32("Last sector of VTSI").emit()?;
    f.skip(1);
    f.u8("Specification version")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}", v >> 4, v & 0xf)))
        .emit()?;
    f.u32("Category")
        .hex()
        .with(|&v, n| {
            n.summary(match v {
                0 => "unspecified",
                1 => "karaoke",
                _ => "unknown",
            })
        })
        .emit()?;
    f.seek(0x80);
    f.u32("Last byte of VTSI_MAT").hex().emit()?;
    f.seek(0xc0);
    for name in [
        "Menu VOBs start sector",
        "Title VOBs start sector",
        "VTS_PTT_SRPT sector",
        "VTS_PGCIT sector",
        "VTSM_PGCI_UT sector",
        "VTS_TMAPT sector",
        "VTSM_C_ADT sector",
        "VTSM_VOBU_ADMAP sector",
        "VTS_C_ADT sector",
        "VTS_VOBU_ADMAP sector",
    ] {
        f.u32(name).emit()?;
    }
    f.seek(0x100);
    attributes(f, "Menu", 1, 1)?;
    f.seek(0x200);
    attributes(f, "Title", 8, 32)?;
    f.seek(0x318);
    f.node(
        Node::new("Multichannel extension").span(f.peek_span(VTSI_MAT_LEN.saturating_sub(0x318))),
    );
    Ok(())
}

/// One block of stream attributes: video, then `audio` audio and `subp`
/// sub-picture slots of which only the used ones are shown. Menu blocks
/// have one slot of each kind in use (and padding for 8 and 28); title
/// blocks have 8 and 32.
fn attributes(f: &mut Fields<'_>, what: &'static str, audio: u64, subp: u64) -> Result<()> {
    let start = f.pos();
    let video = f.peek_span(2);
    let v = u16_be(&f.block().data, to_usize(start)).unwrap_or(0);
    f.node(
        bits_node(
            if what == "Menu" {
                "Menu video"
            } else {
                "Title video"
            },
            video,
            video_attr,
            false,
        )
        .summary(video_summary(v)),
    );
    f.skip(3);
    let audio_count = f
        .u8(if what == "Menu" {
            "Menu audio streams"
        } else {
            "Title audio streams"
        })
        .emit()?;
    for i in 0..u64::from(audio_count).min(audio) {
        let at = f.pos().saturating_add(i.saturating_mul(8));
        let span = f.block().span.sub(at, 8);
        let raw = f.block().data.get(to_usize(at)..).unwrap_or_default();
        f.node(
            bits_node(format!("Audio stream {i}"), span, audio_attr, false)
                .summary(audio_summary(raw)),
        );
    }
    // Eight audio slots, then 17 reserved bytes and the sub-picture count.
    f.seek(start.saturating_add(4 + 64 + 16 + 1));
    let subp_count = f
        .u8(if what == "Menu" {
            "Menu subpicture streams"
        } else {
            "Title subpicture streams"
        })
        .emit()?;
    for i in 0..u64::from(subp_count).min(subp) {
        let at = f.pos().saturating_add(i.saturating_mul(6));
        let span = f.block().span.sub(at, 6);
        let raw = f.block().data.get(to_usize(at)..).unwrap_or_default();
        f.node(
            bits_node(format!("Subpicture stream {i}"), span, subp_attr, false)
                .summary(subp_summary(raw)),
        );
    }
    Ok(())
}

/// The region mask in a VMG category: a set bit forbids that region.
fn regions(category: u32) -> String {
    let mask = (category >> 16) & 0xff;
    let allowed: Vec<String> = (0..8u32)
        .filter(|r| mask & (1 << r) == 0)
        .map(|r| r.saturating_add(1).to_string())
        .collect();
    if allowed.is_empty() {
        "no region".into()
    } else {
        format!("regions {}", allowed.join(","))
    }
}

// ---------------------------------------------------------------------------
// Stream attributes

const MPEG_VERSION: EnumTable = &[(0, "MPEG-1"), (1, "MPEG-2")];
const VIDEO_FORMAT: EnumTable = &[(0, "NTSC"), (1, "PAL")];
const ASPECT: EnumTable = &[(0, "4:3"), (3, "16:9")];
const PERMITTED_DF: EnumTable = &[
    (0, "pan & scan and letterbox"),
    (1, "pan & scan"),
    (2, "letterbox"),
    (3, "unspecified"),
];
const PICTURE_SIZE: EnumTable = &[
    (0, "720 wide"),
    (1, "704 wide"),
    (2, "352 wide"),
    (3, "352 wide, half height"),
];
const AUDIO_FORMAT: EnumTable = &[
    (0, "AC-3"),
    (2, "MPEG-1 audio"),
    (3, "MPEG-2 extended audio"),
    (4, "LPCM"),
    (6, "DTS"),
];
const LANG_TYPE: EnumTable = &[(0, "unspecified"), (1, "language code")];
const AUDIO_APP_MODE: EnumTable = &[(0, "unspecified"), (1, "karaoke"), (2, "surround")];
const QUANTIZATION: EnumTable = &[(0, "16-bit"), (1, "20-bit"), (2, "24-bit"), (3, "DRC")];
const SAMPLE_RATE: EnumTable = &[(0, "48 kHz"), (1, "96 kHz")];
const AUDIO_CODE_EXT: EnumTable = &[
    (0, "unspecified"),
    (1, "normal"),
    (2, "for the visually impaired"),
    (3, "director's comments"),
    (4, "alternate director's comments"),
];
const SUBP_CODE_EXT: EnumTable = &[
    (0, "unspecified"),
    (1, "normal"),
    (2, "large"),
    (3, "children"),
    (5, "normal captions"),
    (6, "large captions"),
    (7, "children's captions"),
    (9, "forced"),
    (13, "director's comments"),
    (14, "large director's comments"),
    (15, "director's comments for children"),
];

fn video_attr(b: &mut Bits<'_>) -> Result<()> {
    b.field("MPEG version", 2)
        .enumeration(MPEG_VERSION)
        .emit()?;
    b.field("Video standard", 2)
        .enumeration(VIDEO_FORMAT)
        .emit()?;
    b.field("Display aspect ratio", 2)
        .enumeration(ASPECT)
        .emit()?;
    b.field("Permitted display format", 2)
        .enumeration(PERMITTED_DF)
        .emit()?;
    b.field("Line 21 captions in field 1", 1).flag().emit()?;
    b.field("Line 21 captions in field 2", 1).flag().emit()?;
    b.skip(1);
    b.field("Constant bit rate", 1).flag().emit()?;
    b.field("Picture size", 2)
        .enumeration(PICTURE_SIZE)
        .emit()?;
    b.field("Letterboxed", 1).flag().emit()?;
    b.field("Film mode", 1).flag().emit()?;
    Ok(())
}

fn video_summary(v: u16) -> String {
    let [a, b] = v.to_be_bytes();
    let standard = (a >> 4) & 3;
    let height = if standard == 1 { 576u32 } else { 480 };
    let (width, height) = match (b >> 2) & 3 {
        0 => (720, height),
        1 => (704, height),
        2 => (352, height),
        _ => (352, height / 2),
    };
    format!(
        "{} {}, {width}×{height}, {}",
        lookup(MPEG_VERSION, u64::from(a >> 6)).unwrap_or("MPEG-?"),
        lookup(VIDEO_FORMAT, u64::from(standard)).unwrap_or("?"),
        lookup(ASPECT, u64::from((a >> 2) & 3)).unwrap_or("aspect ?"),
    )
}

fn audio_attr(b: &mut Bits<'_>) -> Result<()> {
    b.field("Coding mode", 3).enumeration(AUDIO_FORMAT).emit()?;
    b.field("Multichannel extension", 1).flag().emit()?;
    b.field("Language type", 2).enumeration(LANG_TYPE).emit()?;
    b.field("Application mode", 2)
        .enumeration(AUDIO_APP_MODE)
        .emit()?;
    b.field("Quantization", 2)
        .enumeration(QUANTIZATION)
        .emit()?;
    b.field("Sample rate", 2).enumeration(SAMPLE_RATE).emit()?;
    b.skip(1);
    b.field("Channels", 3)
        .with(|v, n| n.value(uint(v.saturating_add(1), 8)))
        .emit()?;
    lang_field(b)?;
    b.field("Language extension", 8).emit()?;
    b.field("Code extension", 8)
        .enumeration(AUDIO_CODE_EXT)
        .emit()?;
    b.skip(8);
    b.field("Application information", 8).hex().emit()?;
    Ok(())
}

fn audio_summary(raw: &[u8]) -> String {
    let a = raw.first().copied().unwrap_or(0);
    let b = raw.get(1).copied().unwrap_or(0);
    let mut s = format!(
        "{}, {} ch, {}",
        lookup(AUDIO_FORMAT, u64::from(a >> 5)).unwrap_or("unknown coding"),
        (b & 7).saturating_add(1),
        lookup(SAMPLE_RATE, u64::from((b >> 4) & 3)).unwrap_or("? kHz"),
    );
    if (a >> 2) & 3 == 1 {
        s.push_str(&format!(", {}", fourcc(raw.get(2..4).unwrap_or_default())));
    }
    s
}

fn subp_attr(b: &mut Bits<'_>) -> Result<()> {
    b.field("Coding mode", 3)
        .enumeration(&[(0, "2-bit RLE")])
        .emit()?;
    b.skip(3);
    b.field("Language type", 2).enumeration(LANG_TYPE).emit()?;
    b.skip(8);
    lang_field(b)?;
    b.field("Language extension", 8).emit()?;
    b.field("Code extension", 8)
        .enumeration(SUBP_CODE_EXT)
        .emit()?;
    Ok(())
}

fn subp_summary(raw: &[u8]) -> String {
    let a = raw.first().copied().unwrap_or(0);
    if a & 3 == 1 {
        fourcc(raw.get(2..4).unwrap_or_default())
    } else {
        "no language".into()
    }
}

/// A two-letter ISO 639 language code.
fn lang_field(b: &mut Bits<'_>) -> Result<u64> {
    b.field("Language", 16)
        .with(|v, n| {
            if v == 0 {
                return n.value(hex(0u8, 16)).summary("none");
            }
            let bytes = u16::try_from(v).unwrap_or(0).to_be_bytes();
            n.value(text(fourcc(&bytes)))
        })
        .emit()
}

// ---------------------------------------------------------------------------
// Tables

/// The header of a table at `offset` in `file`: its span (from its last
/// byte field) and the count of entries it declares.
async fn table_node(
    cx: &Cx,
    file: Span,
    offset: u64,
    name: &'static str,
    kind: Table,
) -> Result<(Node, u64)> {
    let head = cx.read_avail(file.sub(offset, 20)).await?;
    let (last, count, noun) = match kind {
        Table::VobuAdmap => {
            let last = u32_be(&head, 0).unwrap_or(0);
            (last, u64::from(last.saturating_sub(3) / 4), "VOBU")
        }
        Table::Txtdt => (u32_be(&head, 16).unwrap_or(0), 0, ""),
        Table::CAdt => {
            let last = u32_be(&head, 4).unwrap_or(0);
            (last, u64::from(last.saturating_sub(7) / 12), "cell")
        }
        _ => {
            let n = u16_be(&head, 0).unwrap_or(0);
            let noun = match kind {
                Table::TtSrpt => "title",
                Table::PttSrpt => "title",
                Table::Pgcit(_) => "PGC",
                Table::PgciUt => "language unit",
                Table::PtlMait => "country",
                Table::VtsAtrt => "title set",
                _ => "time map",
            };
            (u32_be(&head, 4).unwrap_or(0), u64::from(n), noun)
        }
    };
    let want = u64::from(last).saturating_add(1);
    let span = file.sub(offset, want);
    let mut node = Node::new(name).span(span);
    if span.len < want {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, want),
            span.len,
        ));
    }
    if !noun.is_empty() {
        node = node.summary(plural(count, noun));
    }
    Ok((
        node.lazy(
            crate::expander!(self::expand_table: (Span, Span, Table)),
            (file, span, kind),
        ),
        count,
    ))
}

async fn expand_table(cx: Cx, (file, span, kind): (Span, Span, Table)) -> Result<()> {
    match kind {
        Table::TtSrpt => tt_srpt(&cx, span).await,
        Table::PttSrpt => ptt_srpt(&cx, span).await,
        Table::Pgcit(menu) => pgcit(&cx, file, span, menu).await,
        Table::PgciUt => pgci_ut(&cx, file, span).await,
        Table::PtlMait => ptl_mait(&cx, span).await,
        Table::VtsAtrt => vts_atrt(&cx, span).await,
        Table::Txtdt => {
            cx.emit(struct_node("Header", span.sub(0, 20), BE, (), txtdt_header));
            Ok(())
        }
        Table::CAdt => c_adt(&cx, span).await,
        Table::VobuAdmap => vobu_admap(&cx, span).await,
        Table::Tmapt => tmapt(&cx, span).await,
    }
}

/// The common 8-byte header: a count, two reserved bytes, the last byte.
fn table_header(f: &mut Fields<'_>, noun: &&'static str) -> Result<()> {
    f.u16(noun).emit()?;
    f.skip(2);
    f.u32("Last byte").hex().emit()?;
    Ok(())
}

fn txtdt_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Disc name", 12).emit()?;
    f.skip(2);
    f.u16("Language units").emit()?;
    f.u32("Last byte").hex().emit()?;
    Ok(())
}

async fn tt_srpt(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "Titles",
        table_header,
    ));
    let count = u64::from(u16_be(&data, 0).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 12;
    if count > room {
        cx.diag(Diagnostic::malformed(format!("{count} titles do not fit the table")).at(span));
    }
    for i in 0..count.min(room) {
        let at = 8u64.saturating_add(i.saturating_mul(12));
        let e = data.get(to_usize(at)..).unwrap_or_default();
        let angles = e.get(1).copied().unwrap_or(0);
        let chapters = u16_be(e, 2).unwrap_or(0);
        let set = e.get(6).copied().unwrap_or(0);
        let ttn = e.get(7).copied().unwrap_or(0);
        let node = struct_node(
            format!("Title {}", i.saturating_add(1)),
            span.sub(at, 12),
            BE,
            (),
            title_info,
        )
        .summary(format!(
            "title set {set} title {ttn}, {}, {}",
            plural(chapters, "chapter"),
            plural(angles, "angle")
        ));
        cx.push(node).await;
    }
    Ok(())
}

const PLAYBACK_TYPE: FlagTable = &[
    flag(0x40, "multi-PGC or random title"),
    flag(0x20, "jump/link/call in cell commands"),
    flag(0x10, "jump/link/call in pre/post commands"),
    flag(0x08, "jump/link/call in button commands"),
    flag(0x04, "jump/link/call in title domain"),
    flag(0x02, "chapter search or play prohibited"),
    flag(0x01, "title or time play prohibited"),
];

fn title_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Playback type").flags(PLAYBACK_TYPE).emit()?;
    f.u8("Angles").emit()?;
    f.u16("Chapters").emit()?;
    f.u16("Parental mask").hex().emit()?;
    f.u8("Title set").emit()?;
    f.u8("Title in title set").emit()?;
    f.u32("Title set start sector").emit()?;
    Ok(())
}

async fn ptt_srpt(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "Titles",
        table_header,
    ));
    let count = u64::from(u16_be(&data, 0).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 4;
    let count = count.min(room);
    let end = span.len;
    for i in 0..count {
        let at = 8u64.saturating_add(i.saturating_mul(4));
        let start = u64::from(u32_be(&data, to_usize(at)).unwrap_or(0));
        // A title's chapters run to the next title's, or the table's end.
        let next = if i.saturating_add(1) < count {
            u64::from(u32_be(&data, to_usize(at.saturating_add(4))).unwrap_or(0))
        } else {
            end
        };
        let unit = span.sub(start, next.saturating_sub(start));
        let chapters = unit.len / 4;
        let mut node = Node::new(format!("Title {}", i.saturating_add(1)))
            .span(unit)
            .summary(plural(chapters, "chapter"));
        if start < 8 || start > end || next < start {
            node = node.diag(Diagnostic::malformed("chapter list offset out of order"));
        } else {
            node = node.lazy(expand_ptts, unit);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn expand_ptts(cx: Cx, unit: Span) -> Result<()> {
    let data = cx.read_avail(unit).await?;
    let count = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = i.saturating_mul(4);
        let pgc = u16_be(&data, to_usize(at)).unwrap_or(0);
        let pg = u16_be(&data, to_usize(at.saturating_add(2))).unwrap_or(0);
        cx.push(
            struct_node(
                format!("Chapter {}", i.saturating_add(1)),
                unit.sub(at, 4),
                BE,
                (),
                ptt_info,
            )
            .summary(format!("PGC {pgc}, program {pg}")),
        )
        .await;
    }
    Ok(())
}

fn ptt_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("PGC").emit()?;
    f.u16("Program").emit()?;
    Ok(())
}

const MENU_TYPE: EnumTable = &[
    (2, "title menu"),
    (3, "root menu"),
    (4, "subpicture menu"),
    (5, "audio menu"),
    (6, "angle menu"),
    (7, "chapter menu"),
];

async fn pgcit(cx: &Cx, file: Span, span: Span, menu: bool) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 8)).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "PGCs",
        table_header,
    ));
    let count = u64::from(u16_be(&data, 0).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 8;
    if count > room {
        cx.diag(Diagnostic::malformed(format!("{count} PGCs do not fit the table")).at(span));
    }
    let count = count.min(room);
    let srps = cx.read_avail(span.sub(8, count.saturating_mul(8))).await?;
    for i in 0..count {
        let at = i.saturating_mul(8);
        let e = srps.get(to_usize(at)..).unwrap_or_default();
        let entry = e.first().copied().unwrap_or(0);
        let start = u64::from(u32_be(e, 4).unwrap_or(0));
        let srp = span.sub(8u64.saturating_add(at), 8);
        let role = if entry & 0x80 == 0 {
            String::new()
        } else if menu {
            format!(
                "entry: {}, ",
                lookup(MENU_TYPE, u64::from(entry & 0x0f)).unwrap_or("unknown menu")
            )
        } else {
            format!("entry: title {}, ", entry & 0x7f)
        };
        let name = format!("PGC {}", i.saturating_add(1));
        let offset = span
            .offset
            .saturating_sub(file.offset)
            .saturating_add(start);
        let node = match pgc_node(cx, file, name.clone(), offset).await {
            Ok(node) => {
                let summary = format!("{role}{}", node.summary.clone().unwrap_or_default());
                node.summary(summary)
                    .lazy(expand_pgc_entry, (file, srp, offset, menu))
            }
            Err(e) => Node::new(name).span(srp).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn expand_pgc_entry(
    cx: Cx,
    (file, srp, offset, menu): (Span, Span, u64, bool),
) -> Result<()> {
    cx.emit(struct_node("Search pointer", srp, BE, menu, pgci_srp));
    expand_pgc(cx, (file, offset)).await
}

fn pgci_srp(f: &mut Fields<'_>, menu: &bool) -> Result<()> {
    let menu = *menu;
    f.u8("Entry")
        .hex()
        .with(move |&v, n| {
            if v & 0x80 == 0 {
                n.summary("not an entry PGC")
            } else if menu {
                n.summary(lookup(MENU_TYPE, u64::from(v & 0x0f)).unwrap_or("unknown menu"))
            } else {
                n.summary(format!("entry of title {}", v & 0x7f))
            }
        })
        .emit()?;
    f.u8("Block").hex().emit()?;
    f.u16("Parental mask").hex().emit()?;
    f.u32("PGC offset").hex().emit()?;
    Ok(())
}

async fn pgci_ut(cx: &Cx, file: Span, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 8)).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "Language units",
        table_header,
    ));
    let count = u64::from(u16_be(&data, 0).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 8;
    let count = count.min(room);
    let lus = cx.read_avail(span.sub(8, count.saturating_mul(8))).await?;
    for i in 0..count {
        let at = i.saturating_mul(8);
        let e = lus.get(to_usize(at)..).unwrap_or_default();
        let lang = fourcc(e.get(..2).unwrap_or_default());
        let start = u64::from(u32_be(e, 4).unwrap_or(0));
        let unit = span
            .offset
            .saturating_sub(file.offset)
            .saturating_add(start);
        let lu = span.sub(8u64.saturating_add(at), 8);
        let node = match table_node(cx, file, unit, "PGCIT", Table::Pgcit(true)).await {
            Ok((table, _)) => Node::new(format!("Language unit {}", i.saturating_add(1)))
                .span(table.span.unwrap_or(lu))
                .summary(format!(
                    "{lang}, {}",
                    table.summary.clone().unwrap_or_default()
                ))
                .lazy(expand_lu, (file, lu, unit)),
            Err(e) => Node::new(format!("Language unit {}", i.saturating_add(1)))
                .span(lu)
                .diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

const MENU_EXISTS: FlagTable = &[
    flag(0x80, "root or title menu"),
    flag(0x40, "subpicture menu"),
    flag(0x20, "audio menu"),
    flag(0x10, "angle menu"),
    flag(0x08, "chapter menu"),
];

async fn expand_lu(cx: Cx, (file, lu, unit): (Span, Span, u64)) -> Result<()> {
    cx.emit(struct_node("Search pointer", lu, BE, (), pgci_lu));
    let (table, _) = table_node(&cx, file, unit, "PGCIT", Table::Pgcit(true)).await?;
    cx.emit(table);
    Ok(())
}

fn pgci_lu(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Language", 2).emit()?;
    f.u8("Language extension").emit()?;
    f.u8("Menus").flags(MENU_EXISTS).emit()?;
    f.u32("PGCIT offset").hex().emit()?;
    Ok(())
}

async fn ptl_mait(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 8)).await?;
    cx.emit(struct_node("Header", span.sub(0, 8), BE, (), ptl_header));
    let countries = u64::from(u16_be(&data, 0).unwrap_or(0));
    let sets = u64::from(u16_be(&data, 2).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 8;
    let countries = countries.min(room);
    let list = cx
        .read_avail(span.sub(8, countries.saturating_mul(8)))
        .await?;
    // Eight levels, each a mask for the manager and every title set.
    let matrix = sets.saturating_add(1).saturating_mul(2).saturating_mul(8);
    for i in 0..countries {
        let at = i.saturating_mul(8);
        let e = list.get(to_usize(at)..).unwrap_or_default();
        let country = fourcc(e.get(..2).unwrap_or_default());
        let start = u64::from(u16_be(e, 4).unwrap_or(0));
        cx.push(
            Node::new(format!("Country {}", i.saturating_add(1)))
                .span(span.sub(8u64.saturating_add(at), 8))
                .summary(country)
                .lazy(
                    expand_country,
                    (
                        span.sub(8u64.saturating_add(at), 8),
                        span.sub(start, matrix),
                        sets,
                    ),
                ),
        )
        .await;
    }
    Ok(())
}

fn ptl_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Countries").emit()?;
    f.u16("Title sets").emit()?;
    f.u32("Last byte").hex().emit()?;
    Ok(())
}

async fn expand_country(cx: Cx, (entry, matrix, sets): (Span, Span, u64)) -> Result<()> {
    cx.emit(struct_node("Search pointer", entry, BE, (), ptl_country));
    let row = sets.saturating_add(1).saturating_mul(2);
    for level in 0..8u64 {
        cx.emit(
            Node::new(format!("Level {}", 8u64.saturating_sub(level)))
                .span(matrix.sub(level.saturating_mul(row), row))
                .summary("masks for the manager, then each title set"),
        );
    }
    Ok(())
}

fn ptl_country(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Country", 2).emit()?;
    f.skip(2);
    f.u16("Masks offset").hex().emit()?;
    Ok(())
}

async fn vts_atrt(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 8)).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "Title sets",
        table_header,
    ));
    let count = u64::from(u16_be(&data, 0).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 4;
    let count = count.min(room);
    let offsets = cx.read_avail(span.sub(8, count.saturating_mul(4))).await?;
    for i in 0..count {
        let start = u64::from(u32_be(&offsets, to_usize(i.saturating_mul(4))).unwrap_or(0));
        let head = cx.read_avail(span.sub(start, 4)).await?;
        let len = u64::from(u32_be(&head, 0).unwrap_or(0)).saturating_add(1);
        let at = span.sub(start, len);
        let mut node = struct_node(
            format!("Title set {}", i.saturating_add(1)),
            at,
            BE,
            (),
            vts_attributes,
        );
        if at.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(at.source, at.offset, len),
                at.len,
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// A title set's attributes as copied into the manager: the same blocks
/// as in its VTSI_MAT (at 0x100 and 0x200 there).
fn vts_attributes(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Last byte").hex().emit()?;
    f.u32("Category").hex().emit()?;
    attributes(f, "Menu", 1, 1)?;
    f.seek(0x108);
    attributes(f, "Title", 8, 32)
}

async fn c_adt(cx: &Cx, span: Span) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "VOBs",
        table_header,
    ));
    let count = span.len.saturating_sub(8) / 12;
    cx.emit(
        Node::new("Cells")
            .span(span.tail(8))
            .summary(plural(count, "cell"))
            .lazy(expand_cells, span.sub(8, count.saturating_mul(12))),
    );
    Ok(())
}

async fn expand_cells(cx: Cx, list: Span) -> Result<()> {
    let count = list.len / 12;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let at = list.sub(i.saturating_mul(12), 12);
        let e = cx.read_avail(at).await?;
        let vob = u16_be(&e, 0).unwrap_or(0);
        let cell = e.get(2).copied().unwrap_or(0);
        let first = u32_be(&e, 4).unwrap_or(0);
        let last = u32_be(&e, 8).unwrap_or(0);
        cx.push(
            struct_node(
                format!("Cell {}", i.saturating_add(1)),
                at,
                BE,
                (),
                cell_adr,
            )
            .summary(format!("VOB {vob} cell {cell}, sectors {first}–{last}")),
        )
        .await;
    }
    Ok(())
}

fn cell_adr(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("VOB ID").emit()?;
    f.u8("Cell ID").emit()?;
    f.skip(1);
    f.u32("Start sector").emit()?;
    f.u32("Last sector").emit()?;
    Ok(())
}

async fn vobu_admap(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 4)).await?;
    cx.emit(
        Node::new("Last byte")
            .span(span.sub(0, 4))
            .value(hex(u32_be(&head, 0).unwrap_or(0), 32)),
    );
    let count = span.len.saturating_sub(4) / 4;
    cx.emit(
        Node::new("VOBUs")
            .span(span.tail(4))
            .summary(plural(count, "VOBU"))
            .lazy(expand_vobus, span.sub(4, count.saturating_mul(4))),
    );
    Ok(())
}

async fn expand_vobus(cx: Cx, list: Span) -> Result<()> {
    let count = list.len / 4;
    cx.set_count(Count::Exact(count));
    // Read in pages so a long map is not read whole for its first entries.
    let mut i = 0u64;
    while i < count {
        let page = (count.saturating_sub(i)).min(1024);
        let data = cx
            .read_avail(list.sub(i.saturating_mul(4), page.saturating_mul(4)))
            .await?;
        for j in 0..page {
            let at = j.saturating_mul(4);
            let sector = u32_be(&data, to_usize(at)).unwrap_or(0);
            let index = i.saturating_add(j);
            cx.push(
                Node::new(format!("VOBU {}", index.saturating_add(1)))
                    .span(list.sub(index.saturating_mul(4), 4))
                    .value(uint(sector, 32))
                    .desc("Start sector"),
            )
            .await;
        }
        i = i.saturating_add(page.max(1));
    }
    Ok(())
}

async fn tmapt(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 8)).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        "Time maps",
        table_header,
    ));
    let count = u64::from(u16_be(&data, 0).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 4;
    let count = count.min(room);
    let offsets = cx.read_avail(span.sub(8, count.saturating_mul(4))).await?;
    for i in 0..count {
        let start = u64::from(u32_be(&offsets, to_usize(i.saturating_mul(4))).unwrap_or(0));
        let head = cx.read_avail(span.sub(start, 4)).await?;
        let unit = head.first().copied().unwrap_or(0);
        let entries = u64::from(u16_be(&head, 2).unwrap_or(0));
        let map = span.sub(start, entries.saturating_mul(4).saturating_add(4));
        cx.push(
            Node::new(format!("Time map {}", i.saturating_add(1)))
                .span(map)
                .summary(format!(
                    "{}, every {unit} s",
                    fmt::count(entries, "entry", "entries")
                ))
                .lazy(expand_tmap, map),
        )
        .await;
    }
    Ok(())
}

async fn expand_tmap(cx: Cx, map: Span) -> Result<()> {
    cx.emit(struct_node("Header", map.sub(0, 4), BE, (), tmap_header));
    let list = map.tail(4);
    let count = list.len / 4;
    let data = cx.read_avail(list).await?;
    for i in 0..count {
        let at = i.saturating_mul(4);
        let raw = u32_be(&data, to_usize(at)).unwrap_or(0);
        let mut node = Node::new(format!("Entry {}", i.saturating_add(1)))
            .span(list.sub(at, 4))
            .value(uint(raw & 0x7fff_ffff, 32))
            .desc("VOBU start sector");
        if raw & 0x8000_0000 != 0 {
            node = node.summary("discontinuity flag");
        }
        cx.push(node).await;
    }
    Ok(())
}

fn tmap_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Time unit (s)").emit()?;
    f.skip(1);
    f.u16("Entries").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Program chains

/// A PGC at byte `offset` in `file`, summarised, with its span covering the
/// fixed part and every subtable it points at.
async fn pgc_node(
    cx: &Cx,
    file: Span,
    name: impl Into<std::borrow::Cow<'static, str>>,
    offset: u64,
) -> Result<Node> {
    let head = cx.read_avail(file.sub(offset, PGC_LEN)).await?;
    let programs = head.get(2).copied().unwrap_or(0);
    let cells = head.get(3).copied().unwrap_or(0);
    let time = u32_be(&head, 4).unwrap_or(0);
    let len = pgc_len(cx, file, offset, &head).await;
    let mut summary = format!(
        "{}, {}, {}",
        plural(programs, "program"),
        plural(cells, "cell"),
        dvd_time(time)
    );
    if programs == 0 && cells == 0 {
        summary = "no cells".into();
    }
    let span = file.sub(offset, len);
    let mut node = Node::new(name).span(span).summary(summary);
    if span.len < PGC_LEN {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, PGC_LEN),
            span.len,
        ));
    }
    Ok(node.lazy(expand_pgc, (file, offset)))
}

/// Offsets of the command table, program map, cell playback and cell
/// position tables (relative to the PGC; zero when absent).
fn pgc_offsets(head: &[u8]) -> [u64; 4] {
    [0xe4usize, 0xe6, 0xe8, 0xea].map(|at| u64::from(u16_be(head, at).unwrap_or(0)))
}

async fn pgc_len(cx: &Cx, file: Span, offset: u64, head: &[u8]) -> u64 {
    let programs = u64::from(head.get(2).copied().unwrap_or(0));
    let cells = u64::from(head.get(3).copied().unwrap_or(0));
    let [cmd, map, playback, position] = pgc_offsets(head);
    let mut end = PGC_LEN;
    if cmd != 0 {
        let t = cx
            .read_avail(file.sub(offset.saturating_add(cmd), 8))
            .await
            .unwrap_or_default();
        let last = u64::from(u16_be(&t, 6).unwrap_or(7));
        end = end.max(cmd.saturating_add(last).saturating_add(1));
    }
    if map != 0 {
        end = end.max(map.saturating_add(programs));
    }
    if playback != 0 {
        end = end.max(playback.saturating_add(cells.saturating_mul(CELL_PLAYBACK_LEN)));
    }
    if position != 0 {
        end = end.max(position.saturating_add(cells.saturating_mul(4)));
    }
    end
}

async fn expand_pgc(cx: Cx, (file, offset): (Span, u64)) -> Result<()> {
    let block = cx.block(file.sub(offset, PGC_LEN)).await?;
    pgc_header(&mut Fields::emitting(&cx, &block, BE), &())?;
    let head = &block.data;
    let programs = u64::from(head.get(2).copied().unwrap_or(0));
    let cells = u64::from(head.get(3).copied().unwrap_or(0));
    let [cmd, map, playback, position] = pgc_offsets(head);
    let at = |o: u64| offset.saturating_add(o);
    if cmd != 0 {
        let t = cx.read_avail(file.sub(at(cmd), 8)).await?;
        let pre = u16_be(&t, 0).unwrap_or(0);
        let post = u16_be(&t, 2).unwrap_or(0);
        let cell = u16_be(&t, 4).unwrap_or(0);
        let last = u64::from(u16_be(&t, 6).unwrap_or(7));
        let span = file.sub(at(cmd), last.saturating_add(1));
        cx.emit(
            Node::new("Command table")
                .span(span)
                .summary(format!("{pre} pre, {post} post, {cell} cell"))
                .lazy(expand_commands, span),
        );
    }
    if map != 0 && programs != 0 {
        let span = file.sub(at(map), programs);
        cx.emit(
            Node::new("Program map")
                .span(span)
                .summary(plural(programs, "program"))
                .lazy(expand_program_map, span),
        );
    }
    if playback != 0 && cells != 0 {
        let span = file.sub(at(playback), cells.saturating_mul(CELL_PLAYBACK_LEN));
        cx.emit(
            Node::new("Cell playback")
                .span(span)
                .summary(plural(cells, "cell"))
                .lazy(expand_cell_playback, span),
        );
    }
    if position != 0 && cells != 0 {
        let span = file.sub(at(position), cells.saturating_mul(4));
        cx.emit(
            Node::new("Cell positions")
                .span(span)
                .summary(plural(cells, "cell"))
                .lazy(expand_cell_positions, span),
        );
    }
    Ok(())
}

/// User operations a PGC or cell may prohibit (UOP0 is bit 0).
const USER_OPS: FlagTable = &[
    flag(1 << 0, "title or time play"),
    flag(1 << 1, "chapter search or play"),
    flag(1 << 2, "title play"),
    flag(1 << 3, "stop"),
    flag(1 << 4, "go up"),
    flag(1 << 5, "time or chapter search"),
    flag(1 << 6, "previous or top program search"),
    flag(1 << 7, "next program search"),
    flag(1 << 8, "forward scan"),
    flag(1 << 9, "backward scan"),
    flag(1 << 10, "title menu call"),
    flag(1 << 11, "root menu call"),
    flag(1 << 12, "subpicture menu call"),
    flag(1 << 13, "audio menu call"),
    flag(1 << 14, "angle menu call"),
    flag(1 << 15, "chapter menu call"),
    flag(1 << 16, "resume"),
    flag(1 << 17, "button select or activate"),
    flag(1 << 18, "still off"),
    flag(1 << 19, "pause on"),
    flag(1 << 20, "audio stream change"),
    flag(1 << 21, "subpicture stream change"),
    flag(1 << 22, "angle change"),
    flag(1 << 23, "karaoke mode change"),
    flag(1 << 24, "video presentation mode change"),
];

fn pgc_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.skip(2);
    f.u8("Programs").emit()?;
    f.u8("Cells").emit()?;
    f.u32("Playback time")
        .hex()
        .with(|&v, n| n.summary(dvd_time(v)))
        .emit()?;
    f.u32("Prohibited user operations").flags(USER_OPS).emit()?;
    f.node(struct_node(
        "Audio stream control",
        f.peek_span(16),
        BE,
        (),
        audio_control,
    ));
    f.skip(16);
    f.node(struct_node(
        "Subpicture stream control",
        f.peek_span(128),
        BE,
        (),
        subp_control,
    ));
    f.skip(128);
    f.u16("Next PGC").emit()?;
    f.u16("Previous PGC").emit()?;
    f.u16("Go-up PGC").emit()?;
    f.u8("Playback mode")
        .hex()
        .with(|&v, n| {
            n.summary(match v {
                0 => "sequential".to_owned(),
                v if v & 0x80 != 0 => format!("shuffle, {} programs", v & 0x7f),
                v => format!("random, {} programs", v & 0x7f),
            })
        })
        .emit()?;
    f.u8("Still time")
        .with(|&v, n| if v == 255 { n.summary("infinite") } else { n })
        .emit()?;
    f.node(struct_node("Palette", f.peek_span(64), BE, (), palette));
    f.skip(64);
    f.u16("Command table offset").hex().emit()?;
    f.u16("Program map offset").hex().emit()?;
    f.u16("Cell playback offset").hex().emit()?;
    f.u16("Cell position offset").hex().emit()?;
    Ok(())
}

fn audio_control(f: &mut Fields<'_>, _: &()) -> Result<()> {
    const NAMES: [&str; 8] = [
        "Stream 0", "Stream 1", "Stream 2", "Stream 3", "Stream 4", "Stream 5", "Stream 6",
        "Stream 7",
    ];
    for name in NAMES {
        f.u16(name)
            .hex()
            .with(|&v, n| {
                if v & 0x8000 == 0 {
                    n.summary("not available")
                } else {
                    n.summary(format!("decoding stream {}", (v >> 8) & 7))
                }
            })
            .emit()?;
    }
    Ok(())
}

fn subp_control(f: &mut Fields<'_>, _: &()) -> Result<()> {
    const NAMES: [&str; 32] = [
        "Stream 0",
        "Stream 1",
        "Stream 2",
        "Stream 3",
        "Stream 4",
        "Stream 5",
        "Stream 6",
        "Stream 7",
        "Stream 8",
        "Stream 9",
        "Stream 10",
        "Stream 11",
        "Stream 12",
        "Stream 13",
        "Stream 14",
        "Stream 15",
        "Stream 16",
        "Stream 17",
        "Stream 18",
        "Stream 19",
        "Stream 20",
        "Stream 21",
        "Stream 22",
        "Stream 23",
        "Stream 24",
        "Stream 25",
        "Stream 26",
        "Stream 27",
        "Stream 28",
        "Stream 29",
        "Stream 30",
        "Stream 31",
    ];
    for name in NAMES {
        f.u32(name)
            .hex()
            .with(|&v, n| {
                if v & 0x8000_0000 == 0 {
                    n.summary("not available")
                } else {
                    n.summary(format!(
                        "4:3 {}, wide {}, letterbox {}, pan & scan {}",
                        (v >> 24) & 0x1f,
                        (v >> 16) & 0x1f,
                        (v >> 8) & 0x1f,
                        v & 0x1f
                    ))
                }
            })
            .emit()?;
    }
    Ok(())
}

fn palette(f: &mut Fields<'_>, _: &()) -> Result<()> {
    const NAMES: [&str; 16] = [
        "Colour 0",
        "Colour 1",
        "Colour 2",
        "Colour 3",
        "Colour 4",
        "Colour 5",
        "Colour 6",
        "Colour 7",
        "Colour 8",
        "Colour 9",
        "Colour 10",
        "Colour 11",
        "Colour 12",
        "Colour 13",
        "Colour 14",
        "Colour 15",
    ];
    for name in NAMES {
        f.u32(name)
            .hex()
            .with(|&v, n| {
                n.summary(format!(
                    "Y {}, Cr {}, Cb {}",
                    (v >> 16) & 0xff,
                    (v >> 8) & 0xff,
                    v & 0xff
                ))
            })
            .emit()?;
    }
    Ok(())
}

async fn expand_commands(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    cx.emit(struct_node(
        "Header",
        span.sub(0, 8),
        BE,
        (),
        command_header,
    ));
    let pre = u64::from(u16_be(&data, 0).unwrap_or(0));
    let post = u64::from(u16_be(&data, 2).unwrap_or(0));
    let cell = u64::from(u16_be(&data, 4).unwrap_or(0));
    let room = span.len.saturating_sub(8) / 8;
    if pre.saturating_add(post).saturating_add(cell) > room {
        cx.diag(Diagnostic::malformed("more commands than the table holds").at(span));
    }
    let mut at = 8u64;
    for (name, count) in [("Pre", pre), ("Post", post), ("Cell", cell)] {
        for i in 0..count {
            if at.saturating_add(8) > span.len {
                return Ok(());
            }
            let raw = u64_be(&data, to_usize(at)).unwrap_or(0);
            cx.push(
                Node::new(format!("{name} {}", i.saturating_add(1)))
                    .span(span.sub(at, 8))
                    .value(hex(raw, 64))
                    .summary(vm_command(raw)),
            )
            .await;
            at = at.saturating_add(8);
        }
    }
    Ok(())
}

fn command_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Pre commands").emit()?;
    f.u16("Post commands").emit()?;
    f.u16("Cell commands").emit()?;
    f.u16("Last byte").hex().emit()?;
    Ok(())
}

async fn expand_program_map(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    for (i, &cell) in data.iter().enumerate() {
        let i = to_u64(i);
        cx.push(
            Node::new(format!("Program {}", i.saturating_add(1)))
                .span(span.sub(i, 1))
                .value(uint(cell, 8))
                .desc("Entry cell"),
        )
        .await;
    }
    Ok(())
}

async fn expand_cell_playback(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / CELL_PLAYBACK_LEN;
    for i in 0..count {
        let at = span.sub(i.saturating_mul(CELL_PLAYBACK_LEN), CELL_PLAYBACK_LEN);
        let e = cx.read_avail(at).await?;
        let time = u32_be(&e, 4).unwrap_or(0);
        let first = u32_be(&e, 8).unwrap_or(0);
        let last = u32_be(&e, 20).unwrap_or(0);
        cx.push(
            struct_node(
                format!("Cell {}", i.saturating_add(1)),
                at,
                BE,
                (),
                cell_playback,
            )
            .summary(format!("{}, sectors {first}–{last}", dvd_time(time))),
        )
        .await;
    }
    Ok(())
}

const CELL_FLAGS: FlagTable = &[
    field(0xc0, 0x40, "first cell of block"),
    field(0xc0, 0x80, "inside block"),
    field(0xc0, 0xc0, "last cell of block"),
    field(0x30, 0x10, "angle block"),
    flag(0x08, "seamless playback"),
    flag(0x04, "interleaved"),
    flag(0x02, "STC discontinuity"),
    flag(0x01, "seamless angle change"),
];

const CELL_FLAGS2: FlagTable = &[flag(0x40, "VOBU still"), flag(0x20, "restricted")];

fn cell_playback(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Block and seamless flags").flags(CELL_FLAGS).emit()?;
    f.u8("Playback flags")
        .flags(CELL_FLAGS2)
        .with(|&v, n| {
            if v & 0x1f == 0 {
                n
            } else {
                n.summary(format!("cell type {}", v & 0x1f))
            }
        })
        .emit()?;
    f.u8("Still time")
        .with(|&v, n| if v == 255 { n.summary("infinite") } else { n })
        .emit()?;
    f.u8("Cell command").emit()?;
    f.u32("Playback time")
        .hex()
        .with(|&v, n| n.summary(dvd_time(v)))
        .emit()?;
    f.u32("First VOBU start sector").emit()?;
    f.u32("First ILVU end sector").emit()?;
    f.u32("Last VOBU start sector").emit()?;
    f.u32("Last VOBU end sector").emit()?;
    Ok(())
}

async fn expand_cell_positions(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let count = span.len / 4;
    for i in 0..count {
        let at = i.saturating_mul(4);
        let vob = u16_be(&data, to_usize(at)).unwrap_or(0);
        let cell = data
            .get(to_usize(at.saturating_add(3)))
            .copied()
            .unwrap_or(0);
        cx.push(
            struct_node(
                format!("Cell {}", i.saturating_add(1)),
                span.sub(at, 4),
                BE,
                (),
                cell_position,
            )
            .summary(format!("VOB {vob} cell {cell}")),
        )
        .await;
    }
    Ok(())
}

fn cell_position(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("VOB ID").emit()?;
    f.skip(1);
    f.u8("Cell ID").emit()?;
    Ok(())
}

fn bcd(b: u8) -> u32 {
    u32::from(b >> 4)
        .saturating_mul(10)
        .saturating_add(u32::from(b & 0xf))
}

/// A `dvd_time_t`: BCD hours, minutes, seconds and frames, with the frame
/// rate in the top two bits of the last byte.
fn dvd_time(v: u32) -> String {
    let [h, m, s, f] = v.to_be_bytes();
    let rate = match f >> 6 {
        1 => " @ 25 fps",
        3 => " @ 29.97 fps",
        _ => "",
    };
    format!(
        "{:02}:{:02}:{:02}.{:02}{rate}",
        bcd(h),
        bcd(m),
        bcd(s),
        bcd(f & 0x3f)
    )
}

// ---------------------------------------------------------------------------
// Navigation commands (libdvdnav's vmcmd.c)

/// `count` bits of `c` whose most significant is bit `start` (63 = first).
fn bits(c: u64, start: u32, count: u32) -> u64 {
    let shift = start.saturating_add(1).saturating_sub(count);
    let mask = 1u64
        .checked_shl(count)
        .map_or(u64::MAX, |m| m.wrapping_sub(1));
    c.checked_shr(shift).unwrap_or(0) & mask
}

const SYSTEM_REGS: [&str; 24] = [
    "Menu_Description_Language_Code",
    "Audio_Stream_#",
    "Sub-picture_stream_#",
    "Angle_#",
    "Title_Track_#",
    "VTS_Title_Track_#",
    "VTS_PGC_#",
    "PTT_#_for_One_Sequential_PGC_Title",
    "Highlighted_Button_#",
    "Navigation_Timer",
    "Title_PGC_#_for_Navigation_Timer",
    "Audio_Mixing_Mode_for_Karaoke",
    "Country_Code_for_Parental_Management",
    "Parental_Level",
    "Player_Configurations_for_Video",
    "Player_Configurations_for_Audio",
    "Initial_Language_Code_for_Audio",
    "Initial_Language_Code_Extension_for_Audio",
    "Initial_Language_Code_for_Sub-picture",
    "Initial_Language_Code_Extension_for_Sub-picture",
    "Player_Regional_Code",
    "Reserved_21",
    "Reserved_22",
    "Reserved_23",
];

const CMP_OPS: [&str; 8] = ["", "&", "==", "!=", ">=", ">", "<=", "<"];
const SET_OPS: [&str; 12] = [
    "", "=", "<->", "+=", "-=", "*=", "/=", "%=", "rnd", "&=", "|=", "^=",
];
const LINKSUB: [&str; 17] = [
    "LinkNoLink",
    "LinkTopC",
    "LinkNextC",
    "LinkPrevC",
    "",
    "LinkTopPG",
    "LinkNextPG",
    "LinkPrevPG",
    "",
    "LinkTopPGC",
    "LinkNextPGC",
    "LinkPrevPGC",
    "LinkGoUpPGC",
    "LinkTailPGC",
    "",
    "",
    "RSM",
];

fn g_reg(r: u64) -> String {
    if r < 16 {
        format!("g[{r}]")
    } else {
        format!("invalid register {r}")
    }
}

fn system_reg(r: u64) -> String {
    SYSTEM_REGS
        .get(to_usize(r))
        .map_or_else(|| format!("s[{r}]"), |n| (*n).to_owned())
}

fn reg(r: u64) -> String {
    if r & 0x80 != 0 {
        system_reg(r & 0x7f)
    } else {
        g_reg(r)
    }
}

fn reg_or_data(c: u64, immediate: bool, start: u32) -> String {
    if immediate {
        format!("{:#x}", bits(c, start, 16))
    } else {
        reg(bits(c, start.saturating_sub(8), 8))
    }
}

fn reg_or_data_2(c: u64, immediate: bool, start: u32) -> String {
    if immediate {
        format!("{:#x}", bits(c, start.saturating_sub(1), 7))
    } else {
        format!("g[{}]", bits(c, start.saturating_sub(4), 4))
    }
}

fn cmp(op: u64) -> &'static str {
    CMP_OPS.get(to_usize(op)).copied().unwrap_or("?")
}

fn if_v1(c: u64) -> String {
    let op = bits(c, 54, 3);
    if op == 0 {
        return String::new();
    }
    format!(
        "if ({} {} {}) ",
        g_reg(bits(c, 39, 8)),
        cmp(op),
        reg_or_data(c, bits(c, 55, 1) != 0, 31)
    )
}

fn if_v2(c: u64) -> String {
    let op = bits(c, 54, 3);
    if op == 0 {
        return String::new();
    }
    format!(
        "if ({} {} {}) ",
        reg(bits(c, 15, 8)),
        cmp(op),
        reg(bits(c, 7, 8))
    )
}

fn if_v3(c: u64) -> String {
    let op = bits(c, 54, 3);
    if op == 0 {
        return String::new();
    }
    format!(
        "if ({} {} {}) ",
        g_reg(bits(c, 43, 4)),
        cmp(op),
        reg_or_data(c, bits(c, 55, 1) != 0, 15)
    )
}

fn special(c: u64) -> String {
    match bits(c, 51, 4) {
        0 => "Nop".into(),
        1 => format!("Goto {}", bits(c, 7, 8)),
        2 => "Break".into(),
        3 => format!("SetTmpPML {}, Goto {}", bits(c, 11, 4), bits(c, 7, 8)),
        op => format!("unknown special instruction {op}"),
    }
}

fn linksub(c: u64) -> String {
    let op = bits(c, 7, 8);
    let button = bits(c, 15, 6);
    match LINKSUB.get(to_usize(op)).filter(|n| !n.is_empty()) {
        Some(name) if button != 0 => format!("{name} (button {button})"),
        Some(name) => (*name).to_owned(),
        None => format!("unknown link {op}"),
    }
}

fn with_button(text: String, button: u64) -> String {
    if button == 0 {
        text
    } else {
        format!("{text} (button {button})")
    }
}

/// The link of a type 1 to 3 command; `optional` when a set comes first.
fn link(c: u64, optional: bool) -> String {
    let op = bits(c, 51, 4);
    let text = match op {
        0 if optional => return String::new(),
        0 => "Nop".into(),
        1 => linksub(c),
        4 => format!("LinkPGCN {}", bits(c, 14, 15)),
        5 => with_button(format!("LinkPTT {}", bits(c, 9, 10)), bits(c, 15, 6)),
        6 => with_button(format!("LinkPGN {}", bits(c, 6, 7)), bits(c, 15, 6)),
        7 => with_button(format!("LinkCN {}", bits(c, 7, 8)), bits(c, 15, 6)),
        op => format!("unknown link instruction {op}"),
    };
    if optional { format!(", {text}") } else { text }
}

fn jump(c: u64) -> String {
    match bits(c, 51, 4) {
        1 => "Exit".into(),
        2 => format!("JumpTT {}", bits(c, 22, 7)),
        3 => format!("JumpVTS_TT {}", bits(c, 22, 7)),
        5 => format!("JumpVTS_PTT {}:{}", bits(c, 22, 7), bits(c, 41, 10)),
        6 => match bits(c, 23, 2) {
            0 => "JumpSS FP".into(),
            1 => format!("JumpSS VMGM (menu {})", bits(c, 19, 4)),
            2 => format!(
                "JumpSS VTSM (vts {}, title {}, menu {})",
                bits(c, 30, 7),
                bits(c, 38, 7),
                bits(c, 19, 4)
            ),
            _ => format!("JumpSS VMGM (pgc {})", bits(c, 46, 15)),
        },
        8 => {
            let rsm = bits(c, 31, 8);
            match bits(c, 23, 2) {
                0 => format!("CallSS FP (rsm_cell {rsm})"),
                1 => format!("CallSS VMGM (menu {}, rsm_cell {rsm})", bits(c, 19, 4)),
                2 => format!("CallSS VTSM (menu {}, rsm_cell {rsm})", bits(c, 19, 4)),
                _ => format!("CallSS VMGM (pgc {}, rsm_cell {rsm})", bits(c, 46, 15)),
            }
        }
        op => format!("unknown jump instruction {op}"),
    }
}

fn system_set(c: u64) -> String {
    let imm = bits(c, 60, 1) != 0;
    match bits(c, 59, 4) {
        1 => {
            let mut out = Vec::new();
            for i in 1..=3u32 {
                let start = 47u32.saturating_sub(i.saturating_mul(8));
                if bits(c, start, 1) != 0 {
                    out.push(format!(
                        "{} = {}",
                        system_reg(u64::from(i)),
                        reg_or_data_2(c, imm, start)
                    ));
                }
            }
            out.join(" ")
        }
        2 => format!(
            "{} = {} {} = {}",
            system_reg(9),
            reg_or_data(c, imm, 47),
            system_reg(10),
            bits(c, 30, 15)
        ),
        3 => format!(
            "SetMode {}{} = {}",
            if bits(c, 23, 1) != 0 {
                "Counter "
            } else {
                "Register "
            },
            g_reg(bits(c, 19, 4)),
            reg_or_data(c, imm, 47)
        ),
        6 => {
            if imm {
                format!(
                    "{} = {:#x} (button no {})",
                    system_reg(8),
                    bits(c, 31, 16),
                    bits(c, 31, 6)
                )
            } else {
                format!("{} = g[{}]", system_reg(8), bits(c, 19, 4))
            }
        }
        op => format!("unknown system set instruction {op}"),
    }
}

fn set_v1(c: u64) -> String {
    let op = bits(c, 59, 4);
    match SET_OPS.get(to_usize(op)) {
        Some(&"") => "Nop".into(),
        Some(name) => format!(
            "{} {name} {}",
            g_reg(bits(c, 35, 4)),
            reg_or_data(c, bits(c, 60, 1) != 0, 31)
        ),
        None => format!("unknown set operation {op}"),
    }
}

/// A navigation command in the mnemonics of libdvdnav's `vmcmd.c` (types
/// 4 to 6, compare-and-set forms seen rarely, are named only).
fn vm_command(c: u64) -> String {
    match bits(c, 63, 3) {
        0 => format!("{}{}", if_v1(c), special(c)),
        1 if bits(c, 60, 1) != 0 => format!("{}{}", if_v2(c), jump(c)),
        1 => format!("{}{}", if_v1(c), link(c, false)),
        2 => format!("{}{}{}", if_v2(c), system_set(c), link(c, true)),
        3 => format!("{}{}{}", if_v3(c), set_v1(c), link(c, true)),
        4 => "set, compare, then link (type 4)".into(),
        5 => "compare, then set and link (type 5)".into(),
        6 => "compare, set, then link (type 6)".into(),
        t => format!("unknown command type {t}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn commands() {
        // Written by dvdauthor 0.7.2; dvdunauthor reads them back as noted.
        let cases = [
            (0x3002_0000_0001_0000, "JumpTT 1"),   // jump title 1
            (0x3001_0000_0000_0000, "Exit"),       // exit
            (0x7100_0000_0001_0000, "g[0] = 0x1"), // g0 = 1
            (0x00b1_0000_0001_0003, "if (g[0] != 0x1) Goto 3"), // if (g0 != 1) goto l3
            (0x3008_0001_01c0_0000, "CallSS VMGM (pgc 1, rsm_cell 1)"), // call vmgm menu 1 resume 1
            (0x3003_0000_0002_0000, "JumpVTS_TT 2"), // jump title 2
            (0x3008_0000_0187_0000, "CallSS VTSM (menu 7, rsm_cell 1)"), // call menu entry ptt resume 1
            (0x3005_0002_0001_0000, "JumpVTS_PTT 1:2"),                  // jump title 1 chapter 2
            (0x2004_0000_0000_0001, "LinkPGCN 1"),                       // jump pgc 1
            (0, "Nop"),
        ];
        for (raw, text) in cases {
            assert_eq!(vm_command(raw), text, "{raw:#018x}");
        }
        assert_eq!(dvd_time(0x0000_0145), "00:00:01.05 @ 25 fps");
    }
}
