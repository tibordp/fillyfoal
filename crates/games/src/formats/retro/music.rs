//! Chiptune and game-music rip formats.

use crate::bytes::{to_u64, u16_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::val::text;
use crate::formats::{Codec, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// NSF / NSFe (NES)

declare_format!(pub NSF = "nsf", "NES Sound Format", ["nsf"], "audio/x-nsf",
    Probe::Magic(&[(0, b"NESM\x1a")]), nsf);

const NSF_REGION: FlagTable = &[flag(1, "PAL"), flag(2, "DUAL_PAL_NTSC")];
const NSF_CHIPS: FlagTable = &[
    flag(0x01, "VRC6"),
    flag(0x02, "VRC7"),
    flag(0x04, "FDS"),
    flag(0x08, "MMC5"),
    flag(0x10, "NAMCO_163"),
    flag(0x20, "SUNSOFT_5B"),
    flag(0x40, "VT02+"),
];

record! {
    pub struct NsfHeader {
        magic: bytes[5] "Magic",
        version: u8 "Version",
        songs: u8 "Total songs",
        start: u8 "Starting song",
        load: u16 "Load address" .hex(),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        name: ascii[32] "Song name",
        artist: ascii[32] "Artist",
        copyright: ascii[32] "Copyright",
        ntsc_speed: u16 "NTSC play speed (µs)",
        banks: bytes[8] "Bankswitch init values",
        pal_speed: u16 "PAL play speed (µs)",
        region: u8 "PAL/NTSC" .flags(NSF_REGION),
        chips: u8 "Extra sound chips" .flags(NSF_CHIPS),
        nsf2: u8 "NSF2 flags" .hex(),
        data_len: bytes[3] "Program data length (NSF2)",
    }
}

async fn nsf(cx: Cx, input: Input) -> Result<()> {
    let h: NsfHeader = emit_record(&cx, input.span.sub(0, NsfHeader::SIZE), LE).await?;
    cx.emit(Node::new("Program data").span(input.span.tail(NsfHeader::SIZE)));
    cx.annotate(format!(
        "{:?} by {}, {} songs",
        h.name.trim_end(),
        h.artist.trim_end(),
        h.songs
    ));
    Ok(())
}

declare_format!(pub NSFE = "nsfe", "Extended NES Sound Format", ["nsfe"], "audio/x-nsfe",
    Probe::Magic(&[(0, b"NSFE")]), nsfe);

async fn nsfe(cx: Cx, input: Input) -> Result<()> {
    cx.emit(Node::new("Magic").span(input.span.sub(0, 4)));
    let mut cur = Cursor::new(&cx, input.span, LE);
    cur.skip(4);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let data = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new(id.clone())
            .span(cur.since(start))
            .summary(format!("{len} bytes"));
        if id == "auth" || id == "tlbl" {
            let bytes = cx.read_avail(data).await?;
            let strings: Vec<String> = bytes
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect();
            node = node.summary(strings.join(" / "));
        }
        cx.push(node).await;
        if id == "NEND" {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GBS (Game Boy)

declare_format!(pub GBS = "gbs", "Game Boy Sound System rip", ["gbs"], "audio/x-gbs",
    Probe::Magic(&[(0, b"GBS\x01")]), gbs);

record! {
    pub struct GbsHeader {
        magic: ascii[3] "Magic",
        version: u8 "Version",
        songs: u8 "Number of songs",
        first: u8 "First song",
        load: u16 "Load address" .hex(),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        stack: u16 "Stack pointer" .hex(),
        timer_modulo: u8 "Timer modulo" .hex(),
        timer_control: u8 "Timer control" .hex(),
        title: ascii[32] "Title",
        author: ascii[32] "Author",
        copyright: ascii[32] "Copyright",
    }
}

async fn gbs(cx: Cx, input: Input) -> Result<()> {
    let h: GbsHeader = emit_record(&cx, input.span.sub(0, GbsHeader::SIZE), LE).await?;
    cx.emit(Node::new("Code").span(input.span.tail(GbsHeader::SIZE)));
    cx.annotate(format!(
        "{:?} by {}, {} songs",
        h.title.trim_end(),
        h.author.trim_end(),
        h.songs
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SPC (SNES)

declare_format!(pub SPC = "spc", "SNES SPC700 sound file", ["spc"], "audio/x-spc",
    Probe::Magic(&[(0, b"SNES-SPC700 Sound File Data")]), spc);

record! {
    pub struct SpcHeader {
        magic: ascii[33] "Magic",
        separator: bytes[2] "Separator",
        has_tag: u8 "ID666 present" .enumeration(&[(26, "yes"), (27, "no")]),
        minor: u8 "Version (minor)",
        pc: u16 "PC" .hex(),
        a: u8 "A" .hex(),
        x: u8 "X" .hex(),
        y: u8 "Y" .hex(),
        psw: u8 "PSW" .hex(),
        sp: u8 "SP" .hex(),
        _reserved: bytes[2] "Reserved",
    }
}

record! {
    /// ID666 tag, text variant.
    pub struct Id666 {
        song: ascii[32] "Song title",
        game: ascii[32] "Game title",
        dumper: ascii[16] "Dumper",
        comments: ascii[32] "Comments",
        date: ascii[11] "Dump date",
        seconds: ascii[3] "Length (seconds)",
        fade: ascii[5] "Fade (ms)",
        artist: ascii[32] "Artist",
        channels: u8 "Default channel disables" .hex(),
        emulator: u8 "Dumping emulator" .enumeration(&[(0x30, "unknown"), (0x31, "ZSNES"), (0x32, "Snes9x")]),
    }
}

async fn spc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: SpcHeader = read_record(&cx, file.sub(0, SpcHeader::SIZE), LE).await?;
    cx.emit(SpcHeader::node("Header", file.sub(0, SpcHeader::SIZE), LE));
    let mut summary = String::from("SPC700 snapshot");
    if h.has_tag == 26 {
        let span = file.sub(0x2e, Id666::SIZE);
        let tag: Id666 = read_record(&cx, span, LE).await?;
        cx.emit(Id666::node("ID666 tag", span, LE));
        summary = format!("{:?} from {:?}", tag.song.trim_end(), tag.game.trim_end());
    }
    cx.emit(Node::new("SPC700 RAM").span(file.sub(0x100, 0x10000)));
    cx.emit(Node::new("DSP registers").span(file.sub(0x10100, 128)));
    cx.emit(Node::new("Extra RAM").span(file.sub(0x101c0, 64)));
    if file.len > 0x10200 {
        cx.emit(Node::new("Extended ID666 (xid6)").span(file.tail(0x10200)));
    }
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// VGM (Video Game Music, many chips) and its GD3 tag

declare_format!(pub VGM = "vgm", "Video Game Music log", ["vgm", "vgz"], "audio/x-vgm",
    Probe::Magic(&[(0, b"Vgm ")]), vgm);

record! {
    pub struct VgmHeader {
        magic: ascii[4] "Magic",
        eof: u32 "EOF offset (relative)" .hex(),
        version: u32 "Version (BCD)" .hex(),
        sn76489: u32 "SN76489 clock",
        ym2413: u32 "YM2413 clock",
        gd3: u32 "GD3 offset (relative)" .hex(),
        samples: u32 "Total samples (44.1 kHz)",
        loop_offset: u32 "Loop offset (relative)" .hex(),
        loop_samples: u32 "Loop samples",
        rate: u32 "Rate (Hz)",
        sn_feedback: u16 "SN76489 feedback" .hex(),
        sn_shift: u8 "SN76489 shift register width",
        sn_flags: u8 "SN76489 flags" .hex(),
        ym2612: u32 "YM2612 clock",
        ym2151: u32 "YM2151 clock",
        data_offset: u32 "VGM data offset (relative)" .hex(),
        sega_pcm: u32 "Sega PCM clock",
        sega_pcm_if: u32 "Sega PCM interface register" .hex(),
    }
}

const GD3_FIELDS: [&str; 11] = [
    "Track name",
    "Track name (Japanese)",
    "Game name",
    "Game name (Japanese)",
    "System",
    "System (Japanese)",
    "Author",
    "Author (Japanese)",
    "Release date",
    "Converted by",
    "Notes",
];

async fn vgm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: VgmHeader = read_record(&cx, file.sub(0, VgmHeader::SIZE), LE).await?;
    cx.emit(VgmHeader::node("Header", file.sub(0, VgmHeader::SIZE), LE));
    let data_start = if h.version >= 0x150 && h.data_offset != 0 {
        0x34u64.saturating_add(h.data_offset.into())
    } else {
        0x40
    };
    let gd3 = if h.gd3 != 0 {
        0x14u64.saturating_add(h.gd3.into())
    } else {
        file.len
    };
    cx.emit(Node::new("Command stream").span(file.sub(data_start, gd3.saturating_sub(data_start))));
    let seconds = h.samples / 44100;
    let mut summary = format!(
        "VGM {}.{:02x}, {}:{:02}",
        h.version >> 8,
        h.version & 0xff,
        seconds / 60,
        seconds % 60
    );
    if gd3 < file.len {
        let tag = file.tail(gd3);
        let head = cx.read(tag.sub(0, 12)).await?;
        if head.starts_with(b"Gd3 ") {
            let len = u32_le(&head, 8).unwrap_or(0);
            let strings = cx.read(tag.sub(12, len.into())).await?;
            let mut at = 0usize;
            let mut values = Vec::new();
            for name in GD3_FIELDS {
                let rest = strings.get(at..).unwrap_or_default();
                let (value, used, _) = crate::text::utf16z(rest, LE);
                values.push((
                    name,
                    value,
                    tag.sub(12u64.saturating_add(to_u64(at)), to_u64(used)),
                ));
                at = at.saturating_add(used);
            }
            if let (Some((_, track, _)), Some((_, game, _))) = (values.first(), values.get(2)) {
                summary = format!("{track:?} from {game:?}, {summary}");
            }
            cx.emit(
                Node::new("GD3 tag")
                    .span(tag)
                    .lazy(gd3_tag, values_state(values)),
            );
        }
    }
    cx.annotate(summary);
    Ok(())
}

type Gd3 = Vec<(&'static str, String, Span)>;

fn values_state(values: Gd3) -> std::sync::Arc<Gd3> {
    std::sync::Arc::new(values)
}

async fn gd3_tag(cx: Cx, values: std::sync::Arc<Gd3>) -> Result<()> {
    for (name, value, span) in values.iter() {
        cx.emit(Node::new(*name).span(*span).value(text(value.clone())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PSF family (PlayStation, Saturn, GBA, ...)

fn psf_probe(h: &crate::formats::Head<'_>) -> bool {
    h.starts_with(b"PSF")
        && h.data
            .get(3)
            .is_some_and(|v| lookup(PSF_SYSTEMS, (*v).into()).is_some())
}

declare_format!(pub PSF = "psf", "Portable Sound Format", ["psf", "minipsf", "psf2", "ssf", "dsf", "usf", "gsf", "2sf", "snsf", "qsf"],
    "audio/x-psf", Probe::Custom(psf_probe), psf);

const PSF_SYSTEMS: EnumTable = &[
    (0x01, "PlayStation"),
    (0x02, "PlayStation 2"),
    (0x11, "Sega Saturn"),
    (0x12, "Sega Dreamcast"),
    (0x13, "Sega Mega Drive"),
    (0x21, "Nintendo 64"),
    (0x22, "Game Boy Advance"),
    (0x23, "Super NES"),
    (0x24, "Nintendo DS"),
    (0x41, "Capcom QSound"),
];

record! {
    pub struct PsfHeader {
        magic: ascii[3] "Magic",
        system: u8 "Platform" .enumeration(PSF_SYSTEMS),
        reserved: u32 "Reserved area size",
        program: u32 "Compressed program size",
        crc: u32 "Program CRC-32" .hex(),
    }
}

async fn psf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: PsfHeader = emit_record(&cx, file.sub(0, PsfHeader::SIZE), LE).await?;
    let mut at = PsfHeader::SIZE;
    if h.reserved > 0 {
        cx.emit(Node::new("Reserved area").span(file.sub(at, h.reserved.into())));
        at = at.saturating_add(h.reserved.into());
    }
    if h.program > 0 {
        let span = file.sub(at, h.program.into());
        cx.emit(content("Program", input, span, Codec::Zlib, None));
        at = at.saturating_add(h.program.into());
    }
    let tag = file.tail(at);
    let system = lookup(PSF_SYSTEMS, h.system.into()).unwrap_or("unknown platform");
    let mut summary = format!("{system} rip");
    if cx.read_avail(tag.sub(0, 5)).await? == b"[TAG]" {
        let bytes = cx.read_avail(tag.sub(5, 50_000)).await?;
        let text_tag = String::from_utf8_lossy(&bytes).into_owned();
        let mut pairs = Vec::new();
        for line in text_tag.lines() {
            if let Some((k, v)) = line.split_once('=') {
                pairs.push((k.trim().to_owned(), v.trim().to_owned()));
            }
        }
        if let Some((_, title)) = pairs.iter().find(|(k, _)| k == "title") {
            summary = format!("{title:?}, {summary}");
        }
        cx.emit(Node::new("Tag").span(tag).lazy(psf_tag, (tag, pairs)));
    }
    cx.annotate(summary);
    Ok(())
}

async fn psf_tag(cx: Cx, (span, pairs): (Span, Vec<(String, String)>)) -> Result<()> {
    cx.emit(Node::new("Marker").span(span.sub(0, 5)));
    for (k, v) in pairs {
        cx.push(Node::new(k).value(text(v))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SID (Commodore 64)

declare_format!(pub SID = "sid", "Commodore 64 SID tune", ["sid", "psid"], "audio/prs.sid",
    Probe::Magic(&[(0, b"PSID"), (0, b"RSID")]), sid);

record! {
    pub struct SidHeader {
        magic: ascii[4] "Magic",
        version: u16 "Version",
        data_offset: u16 "Data offset" .hex(),
        load: u16 "Load address" .hex() .desc("0: taken from the first two data bytes"),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        songs: u16 "Songs",
        start: u16 "Start song",
        speed: u32 "Speed flags" .hex(),
        name: ascii[32] "Name",
        author: ascii[32] "Author",
        released: ascii[32] "Released",
    }
}

async fn sid(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: SidHeader = emit_record(&cx, file.sub(0, SidHeader::SIZE), BE).await?;
    if h.version >= 2 {
        let extra = cx.block(file.sub(SidHeader::SIZE, 6)).await?;
        let mut f = Fields::emitting(&cx, &extra, BE);
        f.u16("Flags").hex().emit()?;
        f.u8("Relocation start page").hex().emit()?;
        f.u8("Relocation page length").emit()?;
        f.u8("Second SID address").hex().emit()?;
        f.u8("Third SID address").hex().emit()?;
    }
    cx.emit(Node::new("C64 data").span(file.tail(h.data_offset.into())));
    cx.annotate(format!(
        "{:?} by {}, {} songs ({})",
        h.name.trim_end(),
        h.author.trim_end(),
        h.songs,
        h.magic
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// HES (PC Engine), KSS (MSX / Sega 8-bit)

declare_format!(pub HES = "hes", "PC Engine sound file", ["hes"], "audio/x-hes",
    Probe::Magic(&[(0, b"HESM")]), hes);

record! {
    pub struct HesHeader {
        magic: ascii[4] "Magic",
        version: u8 "Version",
        start: u8 "Starting song",
        request: u16 "Request address" .hex(),
        mpr: bytes[8] "Initial MPR values",
        data_magic: ascii[4] "Data magic",
        size: u32 "Data size" .hex(),
        load: u32 "Load address" .hex(),
        _reserved: u32 "Reserved",
    }
}

async fn hes(cx: Cx, input: Input) -> Result<()> {
    let h: HesHeader = emit_record(&cx, input.span.sub(0, HesHeader::SIZE), LE).await?;
    cx.emit(Node::new("Data").span(input.span.sub(HesHeader::SIZE, h.size.into())));
    cx.annotate(format!("HES v{}, load {:#x}", h.version, h.load));
    Ok(())
}

declare_format!(pub KSS = "kss", "MSX/SMS sound file", ["kss"], "audio/x-kss",
    Probe::Magic(&[(0, b"KSCC"), (0, b"KSSX")]), kss);

const KSS_CHIPS: FlagTable = &[
    flag(0x01, "FM_PAC_or_FM_UNIT"),
    flag(0x02, "SN76489"),
    flag(0x04, "RAM_MODE_or_GG_STEREO"),
    flag(0x08, "MSX_AUDIO"),
];

record! {
    pub struct KssHeader {
        magic: ascii[4] "Magic",
        load: u16 "Load address" .hex(),
        length: u16 "Initial data length" .hex(),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        bank: u8 "Start bank",
        banks: u8 "Extra banks",
        _reserved: u8 "Reserved",
        chips: u8 "Extra chips" .flags(KSS_CHIPS),
    }
}

async fn kss(cx: Cx, input: Input) -> Result<()> {
    let h: KssHeader = emit_record(&cx, input.span.sub(0, KssHeader::SIZE), LE).await?;
    cx.emit(Node::new("Data").span(input.span.tail(KssHeader::SIZE)));
    cx.annotate(format!("{} rip, load {:#x}", h.magic, h.load));
    Ok(())
}

// ---------------------------------------------------------------------------
// AY (ZX Spectrum / Amstrad, ZXAYEMUL)

declare_format!(pub AY = "ay", "ZX Spectrum AY music (ZXAYEMUL)", ["ay"], "audio/x-ay",
    Probe::Magic(&[(0, b"ZXAYEMUL")]), ay);

/// AY files use big-endian, self-relative 16-bit pointers.
async fn relative_string(cx: &Cx, file: Span, at: u64) -> Result<(String, Span)> {
    let raw = cx.read(file.sub(at, 2)).await?;
    let delta = i64::from(u16_be(&raw, 0).unwrap_or(0) as i16);
    let target = i64::try_from(at).unwrap_or(0).saturating_add(delta);
    let target =
        u64::try_from(target).map_err(|_| Diagnostic::malformed("pointer before start of file"))?;
    cx.cstr(file.sub(target, 256)).await
}

async fn ay(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &header, BE);
    f.ascii("Magic", 8).emit()?;
    f.u16("File version").emit()?;
    f.u16("Player version").emit()?;
    f.u16("Special player pointer").hex().emit()?;
    f.u16("Author pointer").hex().emit()?;
    f.u16("Misc pointer").hex().emit()?;
    let songs = f.u8("Last song index").emit()?;
    f.u8("First song index").emit()?;
    let (author, author_span) = relative_string(&cx, file, 0x0e).await?;
    cx.emit(
        Node::new("Author")
            .span(author_span)
            .value(text(author.clone())),
    );
    let (misc, misc_span) = relative_string(&cx, file, 0x10).await?;
    cx.emit(Node::new("Misc").span(misc_span).value(text(misc)));
    cx.annotate(format!(
        "by {author:?}, {} songs",
        u16::from(songs).saturating_add(1)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SAP (Atari 8-bit): text header, then binary

declare_format!(pub SAP = "sap", "Atari SAP music", ["sap"], "audio/x-sap",
    Probe::Magic(&[(0, b"SAP\r\n")]), sap);

async fn sap(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    let end = head
        .windows(2)
        .position(|w| w == b"\xff\xff")
        .unwrap_or(head.len());
    let text_part = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut pos = 0u64;
    let mut name = None;
    for line in text_part.split("\r\n") {
        let len = to_u64(line.len()).saturating_add(2);
        if !line.is_empty() {
            let (key, value) = line.split_once(' ').unwrap_or((line, ""));
            if key == "NAME" {
                name = Some(value.trim_matches('"').to_owned());
            }
            cx.emit(
                Node::new(key.to_owned())
                    .span(file.sub(pos, len))
                    .value(text(value.trim_matches('"').to_owned())),
            );
        }
        pos = pos.saturating_add(len);
    }
    cx.emit(Node::new("Binary (Atari DOS segments)").span(file.tail(to_u64(end))));
    cx.annotate(name.map_or_else(|| "SAP".to_owned(), |n| format!("{n:?}")));
    Ok(())
}

// ---------------------------------------------------------------------------
// YM (Atari ST register dumps)

declare_format!(pub YM = "ym", "Atari ST YM register dump", ["ym"], "audio/x-ym",
    Probe::Magic(&[(0, b"YM5!LeOnArD!"), (0, b"YM6!LeOnArD!")]), ym);

record! {
    pub struct YmHeader {
        magic: ascii[4] "Magic",
        check: ascii[8] "Check string",
        frames: u32 "Frames",
        attributes: u32 "Attributes" .hex(),
        digidrums: u16 "Digidrums",
        clock: u32 "Master clock (Hz)",
        rate: u16 "Frame rate (Hz)",
        loop_frame: u32 "Loop frame",
        extra: u16 "Extra data size",
    }
}

async fn ym(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: YmHeader = emit_record(&cx, file.sub(0, YmHeader::SIZE), BE).await?;
    if h.digidrums > 0 {
        cx.diag(Diagnostic::note(format!(
            "{} digidrum samples precede the strings",
            h.digidrums
        )));
        cx.annotate(format!("{} frames at {} Hz", h.frames, h.rate));
        return Ok(());
    }
    let mut at = YmHeader::SIZE.saturating_add(h.extra.into());
    let mut strings = Vec::new();
    for name in ["Song name", "Author", "Comment"] {
        let (value, span) = cx.cstr(file.sub(at, 1024)).await?;
        at = at.saturating_add(span.len);
        cx.emit(Node::new(name).span(span).value(text(value.clone())));
        strings.push(value);
    }
    cx.emit(Node::new("Register frames").span(file.tail(at)));
    let seconds = h.frames.checked_div(u32::from(h.rate)).unwrap_or(0);
    cx.annotate(format!(
        "{:?} by {}, {}:{:02}",
        strings.first().cloned().unwrap_or_default(),
        strings.get(1).cloned().unwrap_or_default(),
        seconds / 60,
        seconds % 60
    ));
    Ok(())
}
