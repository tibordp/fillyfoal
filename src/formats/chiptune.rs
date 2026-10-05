//! Video game music rips: SNES SPC (with ID666), Commodore 64 PSID/RSID,
//! NES NSF and NSFe, Game Boy GBS, Atari SAP and VGM (with its GD3 tag).
//! These hold a player program or register log for an emulated sound chip;
//! the headers name the song and the hardware.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::sound::{clip, duration, leaf, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn join(parts: &[&str]) -> String {
    parts
        .iter()
        .map(|s| s.trim())
        .filter(|s| !s.is_empty())
        .collect::<Vec<_>>()
        .join(" – ")
}

// ---------------------------------------------------------------------------
// SPC

pub static SPC: Format = Format {
    name: "spc",
    title: "SNES SPC700 sound file",
    extensions: &["spc"],
    mime: "audio/x-spc",
    probe: Probe::Magic(&[(0, b"SNES-SPC700 Sound File Data")]),
    dissect: crate::expander!(spc: Input),
};

record! {
    pub struct SpcHeader {
        magic: ascii[33] "Signature",
        _separator: bytes[2] "Separator",
        has_tag: u8 "ID666 tag" .with(|&v, n| n.summary(if v == 26 { "present" } else { "absent" })),
        version: u8 "Version (minor)",
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
    /// The text form of the ID666 tag.
    pub struct Id666 {
        title: ascii[32] "Song title",
        game: ascii[32] "Game title",
        dumper: ascii[16] "Dumper",
        comments: ascii[32] "Comments",
        date: ascii[11] "Dump date",
        seconds: ascii[3] "Play time (s)",
        fade: ascii[5] "Fade (ms)",
        artist: ascii[32] "Artist",
        channels: u8 "Disabled channels" .hex(),
        emulator: u8 "Emulator",
        _reserved: bytes[45] "Reserved",
    }
}

pub async fn spc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = parse(
        &cx,
        file.sub(0, SpcHeader::SIZE),
        LE,
        &(),
        SpcHeader::layout,
    )
    .await?;
    cx.emit(SpcHeader::node("Header", file.sub(0, SpcHeader::SIZE), LE));
    let mut line = "SPC".to_owned();
    if h.has_tag == 26 {
        let span = file.sub(0x2e, Id666::SIZE);
        let tag = parse(&cx, span, LE, &(), Id666::layout).await?;
        cx.emit(Id666::node("ID666 tag", span, LE).summary(join(&[&tag.title, &tag.game])));
        line = format!("SPC — {}", join(&[&tag.artist, &tag.title, &tag.game]));
        if let Ok(s) = tag.seconds.trim().parse::<u32>() {
            line.push_str(&format!(", {}", duration(f64::from(s))));
        }
    }
    cx.annotate(line);
    for (name, at, len) in [
        ("SPC700 RAM", 0x100, 0x10000),
        ("DSP registers", 0x10100, 128),
        ("Unused", 0x10180, 64),
        ("Extra RAM", 0x101c0, 64),
    ] {
        let span = file.sub(at, len);
        if span.is_empty() {
            break;
        }
        let mut node = Node::new(name).span(span);
        if span.len < len {
            node = node.diag(crate::error::Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.emit(node);
    }
    let extended = file.tail(0x10200);
    if !extended.is_empty() {
        cx.emit(
            Node::new("Extended ID666")
                .span(extended)
                .desc("xid6 chunk: tagged binary fields"),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PSID / RSID

pub static SID: Format = Format {
    name: "sid",
    title: "Commodore 64 SID tune",
    extensions: &["sid", "psid"],
    mime: "audio/prs.sid",
    probe: Probe::Custom(|h| {
        (h.starts_with(b"PSID") || h.starts_with(b"RSID"))
            && crate::bytes::u16_be(h.data, 4).is_some_and(|v| (1..=4).contains(&v))
    }),
    dissect: crate::expander!(sid: Input),
};

const SID_FLAGS: FlagTable = &[
    flag(0x1, "MUS_PLAYER"),
    flag(0x2, "PLAYSID_SPECIFIC"),
    crate::value::field(0xc, 0x4, "PAL"),
    crate::value::field(0xc, 0x8, "NTSC"),
    crate::value::field(0xc, 0xc, "PAL_AND_NTSC"),
    crate::value::field(0x30, 0x10, "MOS6581"),
    crate::value::field(0x30, 0x20, "MOS8580"),
    crate::value::field(0x30, 0x30, "MOS6581_AND_8580"),
];

record! {
    pub struct SidHeader {
        magic: ascii[4] "Magic",
        version: u16 "Version",
        data_offset: u16 "Data offset" .hex(),
        load: u16 "Load address" .hex() .desc("0 = taken from the first two data bytes"),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        songs: u16 "Songs",
        start: u16 "Start song",
        speed: u32 "Speed" .hex() .desc("Bit per song: 0 = vertical blank, 1 = CIA timer"),
        name: ascii[32] "Name",
        author: ascii[32] "Author",
        released: ascii[32] "Released",
    }
}

pub async fn sid(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = parse(
        &cx,
        file.sub(0, SidHeader::SIZE),
        BE,
        &(),
        SidHeader::layout,
    )
    .await?;
    let header_len = u64::from(h.data_offset).max(SidHeader::SIZE);
    let span = file.sub(0, header_len);
    cx.emit(crate::fields::struct_node(
        "Header",
        span,
        BE,
        (),
        |f: &mut Fields<'_>, _: &()| {
            let h = SidHeader::read(f)?;
            if h.version >= 2 && f.remaining() >= 6 {
                f.u16("Flags").flags(SID_FLAGS).emit()?;
                f.u8("Start page").hex().emit()?;
                f.u8("Page length").emit()?;
                f.u8("Second SID address").hex().emit()?;
                f.u8("Third SID address").hex().emit()?;
            }
            Ok(())
        },
    ));
    cx.emit(Node::new("C64 program").span(file.tail(header_len)));
    cx.annotate(format!(
        "{} v{}, {} songs — {}",
        h.magic,
        h.version,
        h.songs,
        join(&[&h.author, &h.name, &h.released])
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// NSF

pub static NSF: Format = Format {
    name: "nsf",
    title: "NES Sound Format",
    extensions: &["nsf"],
    mime: "audio/x-nsf",
    probe: Probe::Magic(&[(0, b"NESM\x1a")]),
    dissect: crate::expander!(nsf: Input),
};

const NSF_CHIPS: FlagTable = &[
    flag(0x1, "VRC6"),
    flag(0x2, "VRC7"),
    flag(0x4, "FDS"),
    flag(0x8, "MMC5"),
    flag(0x10, "NAMCO_163"),
    flag(0x20, "SUNSOFT_5B"),
    flag(0x40, "VT02"),
];

record! {
    pub struct NsfHeader {
        magic: bytes[5] "Magic",
        version: u8 "Version",
        songs: u8 "Songs",
        start: u8 "Start song",
        load: u16 "Load address" .hex(),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        name: ascii[32] "Name",
        artist: ascii[32] "Artist",
        copyright: ascii[32] "Copyright",
        ntsc_speed: u16 "NTSC speed" .desc("Microseconds per tick"),
        banks: bytes[8] "Bankswitch init",
        pal_speed: u16 "PAL speed",
        region: u8 "Region" .with(|&r, n| n.summary(match r & 3 { 0 => "NTSC", 1 => "PAL", _ => "dual" })),
        chips: u8 "Expansion chips" .flags(NSF_CHIPS),
        nsf2: u8 "NSF2 flags" .hex(),
        data_length: bytes[3] "Program data length",
    }
}

pub async fn nsf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, NsfHeader::SIZE);
    let h = parse(&cx, span, LE, &(), NsfHeader::layout).await?;
    cx.emit(NsfHeader::node("Header", span, LE));
    cx.emit(Node::new("Program data").span(file.tail(NsfHeader::SIZE)));
    let (chips, _) = crate::value::decode_flags(NSF_CHIPS, h.chips.into());
    let mut line = format!("NSF v{}, {} songs", h.version, h.songs);
    if !chips.is_empty() {
        line.push_str(&format!(", {}", chips.join(", ")));
    }
    line.push_str(&format!(" — {}", join(&[&h.artist, &h.name])));
    cx.annotate(line);
    Ok(())
}

// ---------------------------------------------------------------------------
// NSFe

pub static NSFE: Format = Format {
    name: "nsfe",
    title: "NES Sound Format, extended",
    extensions: &["nsfe"],
    mime: "audio/x-nsfe",
    probe: Probe::Magic(&[(0, b"NSFE")]),
    dissect: crate::expander!(nsfe: Input),
};

pub async fn nsfe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(leaf("Magic", file.sub(0, 4), text("NSFE")));
    let mut pos = 4u64;
    let mut title = None;
    while file.len.saturating_sub(pos) >= 8 {
        let h = cx.read(file.sub(pos, 8)).await?;
        let size = u64::from(u32_le(&h, 0).unwrap_or(0));
        let id = h.get(4..8).unwrap_or_default().to_vec();
        let span = file.sub(pos, size.saturating_add(8));
        let data = span.tail(8);
        let name = crate::formats::sound::fourcc(&id);
        let mut node = Node::new(name).span(span).summary(format!("{size} bytes"));
        match id.as_slice() {
            b"auth" => {
                let t = cx.read_avail(data.sub(0, 512)).await?;
                let fields: Vec<String> = t
                    .split(|&b| b == 0)
                    .take(4)
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                let refs: Vec<&str> = fields.iter().map(String::as_str).collect();
                title = Some(join(&[
                    refs.get(1).copied().unwrap_or(""),
                    refs.first().copied().unwrap_or(""),
                ]));
                node = node
                    .value(text(fields.join(" / ")))
                    .desc("Game, artist, copyright, ripper");
            }
            b"INFO" => node = node.desc("Load/init/play addresses, region, chips, songs"),
            b"DATA" => node = node.desc("Program data"),
            b"tlbl" => node = node.desc("Track labels"),
            b"time" => node = node.desc("Track times (ms)"),
            b"fade" => node = node.desc("Track fades (ms)"),
            b"plst" => node = node.desc("Playlist"),
            b"NEND" => node = node.desc("End of file"),
            _ => {}
        }
        cx.push(node).await;
        pos = pos.saturating_add(size).saturating_add(8);
        if id == b"NEND" {
            break;
        }
    }
    cx.annotate(match title {
        Some(t) => format!("NSFe — {t}"),
        None => "NSFe".to_owned(),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// GBS

pub static GBS: Format = Format {
    name: "gbs",
    title: "Game Boy Sound System",
    extensions: &["gbs"],
    mime: "audio/x-gbs",
    probe: Probe::Custom(|h| h.starts_with(b"GBS\x01")),
    dissect: crate::expander!(gbs: Input),
};

record! {
    pub struct GbsHeader {
        magic: ascii[3] "Magic",
        version: u8 "Version",
        songs: u8 "Songs",
        first: u8 "First song",
        load: u16 "Load address" .hex(),
        init: u16 "Init address" .hex(),
        play: u16 "Play address" .hex(),
        stack: u16 "Stack pointer" .hex(),
        timer_modulo: u8 "Timer modulo",
        timer_control: u8 "Timer control" .hex(),
        title: ascii[32] "Title",
        author: ascii[32] "Author",
        copyright: ascii[32] "Copyright",
    }
}

pub async fn gbs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, GbsHeader::SIZE);
    let h = parse(&cx, span, LE, &(), GbsHeader::layout).await?;
    cx.emit(GbsHeader::node("Header", span, LE));
    cx.emit(Node::new("Program data").span(file.tail(GbsHeader::SIZE)));
    cx.annotate(format!(
        "GBS, {} songs — {}",
        h.songs,
        join(&[&h.author, &h.title])
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SAP

pub static SAP: Format = Format {
    name: "sap",
    title: "Atari Slight Atari Player",
    extensions: &["sap"],
    mime: "audio/x-sap",
    probe: Probe::Magic(&[(0, b"SAP\r\n")]),
    dissect: crate::expander!(sap: Input),
};

pub async fn sap(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    // Text lines up to the binary part, which starts with ff ff.
    let end = head
        .windows(2)
        .position(|w| w == [0xff, 0xff])
        .unwrap_or(head.len());
    let mut at = 0usize;
    let (mut name, mut author) = (String::new(), String::new());
    for line in head.get(..end).unwrap_or_default().split(|&b| b == b'\n') {
        let len = line.len().saturating_add(1);
        let text_line = String::from_utf8_lossy(line)
            .trim_end_matches('\r')
            .to_owned();
        if !text_line.is_empty() && text_line != "SAP" {
            let (key, value) = text_line.split_once(' ').unwrap_or((&text_line, ""));
            let value = value.trim().trim_matches('"').to_owned();
            match key {
                "NAME" => name = value.clone(),
                "AUTHOR" => author = value.clone(),
                _ => {}
            }
            cx.emit(leaf(
                key.to_owned(),
                file.sub(to_u64(at), to_u64(len)),
                text(value),
            ));
        }
        at = at.saturating_add(len);
    }
    cx.emit(Node::new("6502 program").span(file.tail(to_u64(end))));
    cx.annotate(format!("SAP — {}", join(&[&author, &name])));
    Ok(())
}

// ---------------------------------------------------------------------------
// VGM

pub static VGM: Format = Format {
    name: "vgm",
    title: "Video Game Music log",
    extensions: &["vgm"],
    mime: "audio/x-vgm",
    probe: Probe::Magic(&[(0, b"Vgm ")]),
    dissect: crate::expander!(vgm: Input),
};

/// Chip clock fields of the VGM header that the summary names.
const CHIPS: &[(usize, &str)] = &[
    (0x0c, "SN76489"),
    (0x10, "YM2413"),
    (0x2c, "YM2612"),
    (0x30, "YM2151"),
    (0x38, "Sega PCM"),
    (0x40, "RF5C68"),
    (0x44, "YM2203"),
    (0x48, "YM2608"),
    (0x4c, "YM2610"),
    (0x50, "YM3812"),
    (0x54, "YM3526"),
    (0x58, "Y8950"),
    (0x5c, "YMF262"),
    (0x60, "YMF278B"),
    (0x64, "YMF271"),
    (0x68, "YMZ280B"),
    (0x6c, "RF5C164"),
    (0x70, "PWM"),
    (0x74, "AY8910"),
    (0x80, "Game Boy DMG"),
    (0x84, "NES APU"),
    (0x88, "MultiPCM"),
    (0x8c, "uPD7759"),
    (0x90, "OKIM6258"),
    (0x98, "OKIM6295"),
    (0x9c, "K051649"),
    (0xa0, "K054539"),
    (0xa4, "HuC6280"),
    (0xa8, "C140"),
    (0xac, "K053260"),
    (0xb0, "Pokey"),
    (0xb4, "QSound"),
];

fn vgm_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u32)> {
    f.ascii("Magic", 4).emit()?;
    f.u32("EOF offset").hex().desc("Relative to 0x04").emit()?;
    let version = f
        .u32("Version")
        .hex()
        .with(|&v, n| n.summary(format!("{:x}.{:02x}", v >> 8, v & 0xff)))
        .emit()?;
    f.u32("SN76489 clock").emit()?;
    f.u32("YM2413 clock").emit()?;
    let gd3 = f.u32("GD3 offset").hex().desc("Relative to 0x14").emit()?;
    let samples = f
        .u32("Total samples")
        .with(|&s, n| n.summary(duration(f64::from(s) / 44100.0)))
        .emit()?;
    f.u32("Loop offset").hex().desc("Relative to 0x1c").emit()?;
    f.u32("Loop samples").emit()?;
    if f.remaining() >= 4 {
        f.u32("Rate").desc("Hz, for speed scaling").emit()?;
    }
    if version >= 0x110 && f.remaining() >= 8 {
        f.u16("SN76489 feedback").hex().emit()?;
        f.u8("SN76489 shift register width").emit()?;
        f.u8("SN76489 flags").hex().emit()?;
        f.u32("YM2612 clock").emit()?;
    }
    if version >= 0x110 && f.remaining() >= 4 {
        f.u32("YM2151 clock").emit()?;
    }
    if version >= 0x150 && f.remaining() >= 4 {
        f.u32("VGM data offset")
            .hex()
            .desc("Relative to 0x34")
            .emit()?;
    }
    Ok((version, gd3, samples))
}

pub async fn vgm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x100)).await?;
    let version = u32_le(&head, 8).unwrap_or(0);
    let data_offset = if version >= 0x150 {
        match u32_le(&head, 0x34).unwrap_or(0) {
            0 => 0x40,
            n => u64::from(n).saturating_add(0x34),
        }
    } else {
        0x40
    };
    let header = file.sub(0, data_offset.min(0x100));
    let (version, gd3, samples) = parse(&cx, header, LE, &(), vgm_header).await?;
    cx.emit(crate::fields::struct_node(
        "Header",
        header,
        LE,
        (),
        vgm_header,
    ));
    let gd3_at = if gd3 == 0 {
        None
    } else {
        Some(u64::from(gd3).saturating_add(0x14))
    };
    let data_end = gd3_at.unwrap_or(file.len);
    cx.emit(
        Node::new("Command stream")
            .span(file.sub(data_offset, data_end.saturating_sub(data_offset)))
            .desc("Chip register writes and waits"),
    );
    let chips: Vec<&str> = CHIPS
        .iter()
        .filter(|(at, _)| {
            to_usize(header.len) > *at && u32_le(&head, *at).is_some_and(|c| c & 0x3fff_ffff != 0)
        })
        .map(|(_, n)| *n)
        .collect();
    let mut line = format!(
        "VGM {:x}.{:02x}, {}",
        version >> 8,
        version & 0xff,
        duration(f64::from(samples) / 44100.0)
    );
    if !chips.is_empty() {
        line.push_str(&format!(", {}", chips.join(", ")));
    }
    if let Some(at) = gd3_at {
        let span = file.tail(at);
        let strings = gd3_strings(&cx, span).await.unwrap_or_default();
        let get = |i: usize| strings.get(i).map_or("", String::as_str);
        let t = join(&[get(6), get(0), get(2)]);
        if !t.is_empty() {
            line.push_str(&format!(" — {t}"));
        }
        cx.emit(
            Node::new("GD3 tag")
                .span(span)
                .summary(clip(&t, 60))
                .lazy(gd3_tag, span),
        );
    }
    cx.annotate(line);
    Ok(())
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

async fn gd3_strings(cx: &Cx, span: Span) -> Result<Vec<String>> {
    let head = cx.read(span.sub(0, 12)).await?;
    let len = u64::from(u32_le(&head, 8).unwrap_or(0));
    let body = cx.read_avail(span.sub(12, len.min(1 << 16))).await?;
    let mut out = Vec::new();
    let mut rest: &[u8] = &body;
    while out.len() < GD3_FIELDS.len() && !rest.is_empty() {
        let (s, used, _) = crate::text::utf16z(rest, LE);
        out.push(s);
        rest = rest.get(used..).unwrap_or_default();
    }
    Ok(out)
}

async fn gd3_tag(cx: Cx, span: Span) -> Result<()> {
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Version").hex().emit()?;
    let len = f.u32("Length").emit()?;
    let body = span.sub(12, len.into());
    let data = cx.read_avail(body.sub(0, 1 << 16)).await?;
    let mut at = 0usize;
    for name in GD3_FIELDS {
        let rest = data.get(at..).unwrap_or_default();
        if rest.is_empty() {
            break;
        }
        let (s, used, _) = crate::text::utf16z(rest, LE);
        cx.emit(leaf(name, body.sub(to_u64(at), to_u64(used)), text(s)));
        at = at.saturating_add(used);
    }
    Ok(())
}
