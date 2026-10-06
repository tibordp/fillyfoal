//! Chiptune trackers and register dumps: FamiTracker, DefleMask, Furnace,
//! S98, GYM, Organya, GoatTracker, SNDH, Pro Tracker 3, PSG and AHX.

use super::util::{clean, dec, size, text};
use crate::bytes::{to_u64, u16_be, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// The first bytes of a zlib stream, decompressed (for probes).
fn zlib_peek(h: &Head<'_>) -> Option<Vec<u8>> {
    let cmf = *h.data.first()?;
    let flg = *h.data.get(1)?;
    if cmf != 0x78 || !(u16::from(cmf) << 8 | u16::from(flg)).is_multiple_of(31) {
        return None;
    }
    let mut out = Vec::new();
    let mut inflater = crate::codec::inflate::Inflate::new();
    let _ = inflater.step(h.data.get(2..)?, &mut out, 32, 1 << 16);
    Some(out)
}

/// The module body: the input itself, or its zlib-decompressed contents.
async fn unpack(cx: &Cx, file: Span, magic: &[u8]) -> Result<(Span, bool)> {
    let head = cx.read_avail(file.sub(0, to_u64(magic.len()))).await?;
    if head == magic {
        return Ok((file, false));
    }
    let decoded = crate::codec::inflate_span(cx, file, true, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    cx.emit(Node::new("zlib stream").span(file).summary(format!("{} → {}", size(file.len), size(decoded.span.len))));
    Ok((decoded.span, true))
}

/// A string prefixed with its length in one byte.
async fn pstring(cx: &Cx, cur: &mut Cursor<'_>, name: &'static str) -> Result<String> {
    let start = cur.pos();
    let len = cur.u8().await?;
    let s = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
    cx.emit(Node::new(name).span(cur.since(start)).value(text(s.clone())));
    Ok(s)
}

// ---------------------------------------------------------------------------
// FamiTracker

declare_format!(pub FAMITRACKER = "famitracker", "FamiTracker module", ["ftm", "0cc", "dnm"],
    "audio/x-famitracker", Probe::Magic(&[(0, b"FamiTracker Module")]), famitracker);

const FTM_EXPANSIONS: &[(u8, &str)] = &[(1, "VRC6"), (2, "VRC7"), (4, "FDS"), (8, "MMC5"), (16, "N163"), (32, "5B")];

async fn famitracker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 22)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 18).emit()?;
    let version = f.u32("Version").hex().emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(22);
    let (mut title, mut author, mut chips) = (String::new(), String::new(), String::new());
    let mut blocks = 0u32;
    while cur.remaining() >= 3 {
        let start = cur.pos();
        if cur.peek(3).await? == b"END" {
            cx.push(Node::new("END").span(cur.span(3))).await;
            break;
        }
        let id = crate::text::until_nul(&cur.bytes(16).await?);
        let block_version = cur.u32().await?;
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        blocks = blocks.saturating_add(1);
        let mut node = Node::new(id.clone()).span(cur.since(start)).value(dec(block_version.into(), 32)).summary(format!("version {block_version}, {len} bytes")).target(data);
        if id == "INFO" {
            let raw = cx.read_avail(data.sub(0, 96)).await?;
            title = crate::text::until_nul(raw.get(..32).unwrap_or_default());
            author = crate::text::until_nul(raw.get(32..64).unwrap_or_default());
            node = node.summary(format!("{title:?} by {author}")).lazy(ftm_info, data);
        } else if id == "PARAMS" {
            let raw = cx.read_avail(data.sub(0, 1)).await?;
            let mask = raw.first().copied().unwrap_or(0);
            let names: Vec<&str> = FTM_EXPANSIONS.iter().filter(|e| mask & e.0 != 0).map(|e| e.1).collect();
            chips = if names.is_empty() { "2A03".to_owned() } else { format!("2A03 + {}", names.join(" + ")) };
            node = node.summary(format!("expansion chips: {chips}"));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "FamiTracker module v{:x}.{:02x}, {title:?} by {author}, {chips}, {blocks} blocks",
        version >> 8,
        version & 0xff
    ));
    Ok(())
}

async fn ftm_info(cx: Cx, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, 96)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Title", 32).emit()?;
    f.ascii("Author", 32).emit()?;
    f.ascii("Copyright", 32).emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// DefleMask module (zlib-compressed)

fn dmf_probe(h: &Head<'_>) -> bool {
    h.starts_with(b".DelekDefleMask.") || zlib_peek(h).is_some_and(|d| d.starts_with(b".DelekDefleMask."))
}

declare_format!(pub DEFLEMASK = "deflemask", "DefleMask module", ["dmf"],
    "audio/x-deflemask", Probe::Custom(dmf_probe), deflemask);

const DMF_SYSTEMS: EnumTable = &[
    (0x02, "Sega Genesis (YM2612 + SN76489)"),
    (0x12, "Sega Genesis, extended channel 3"),
    (0x03, "Sega Master System"),
    (0x04, "Game Boy"),
    (0x05, "PC Engine"),
    (0x06, "NES"),
    (0x07, "Commodore 64 (SID 8580)"),
    (0x17, "Commodore 64 (SID 6581)"),
    (0x08, "Arcade (YM2151 + SegaPCM)"),
];

async fn deflemask(cx: Cx, input: Input) -> Result<()> {
    let (body, packed) = unpack(&cx, input.span, b".DelekDefleMask.").await?;
    let mut cur = Cursor::new(&cx, body, LE);
    cx.emit(Node::new("Magic").span(cur.span(16)).value(text(".DelekDefleMask.")));
    cur.skip(16);
    let at = cur.pos();
    let version = cur.u8().await?;
    cx.emit(Node::new("Version").span(cur.since(at)).value(dec(version.into(), 8)));
    let at = cur.pos();
    let system = cur.u8().await?;
    cx.emit(Node::new("System").span(cur.since(at)).value(Value::Enum { raw: system.into(), bits: 8, name: lookup(DMF_SYSTEMS, system.into()) }));
    let name = pstring(&cx, &mut cur, "Song name").await?;
    let author = pstring(&cx, &mut cur, "Author").await?;
    let rest = cur.span(14);
    let block = cx.block(rest).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Highlight A").emit()?;
    f.u8("Highlight B").emit()?;
    f.u8("Time base").emit()?;
    f.u8("Tick time 1").emit()?;
    f.u8("Tick time 2").emit()?;
    let ntsc = f.u8("Frames mode").enumeration(&[(0, "PAL (50 Hz)"), (1, "NTSC (60 Hz)")]).emit()?;
    f.u8("Custom rate").emit()?;
    f.ascii("Custom rate value", 3).emit()?;
    let rows = if version >= 24 { f.u32("Rows per pattern").emit()? } else { f.u8("Rows per pattern").emit()?.into() };
    cur.seek(cur.pos().saturating_add(f.pos()));
    let at = cur.pos();
    let matrix = cur.u8().await?;
    cx.emit(Node::new("Pattern matrix rows").span(cur.since(at)).value(dec(matrix.into(), 8)));
    cx.emit(Node::new("Pattern matrix, instruments, wavetables, patterns, samples").span(body.tail(cur.pos())));
    cx.annotate(format!(
        "DefleMask module v{version}{}, {:?} by {author}, {}, {} Hz, {matrix} orders of {rows} rows",
        if packed { " (zlib)" } else { "" },
        name,
        lookup(DMF_SYSTEMS, system.into()).unwrap_or("unknown system"),
        if ntsc == 1 { 60 } else { 50 }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Furnace module (zlib-compressed)

fn furnace_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"-Furnace module-") || zlib_peek(h).is_some_and(|d| d.starts_with(b"-Furnace module-"))
}

declare_format!(pub FURNACE = "furnace", "Furnace tracker module", ["fur"],
    "audio/x-furnace", Probe::Custom(furnace_probe), furnace);

const FURNACE_CHIPS: EnumTable = &[
    (0x01, "YMU759"),
    (0x02, "Genesis"),
    (0x03, "SMS (SN76489)"),
    (0x04, "Game Boy"),
    (0x05, "PC Engine"),
    (0x06, "NES"),
    (0x07, "C64 (8580)"),
    (0x08, "Arcade (YM2151 + SegaPCM)"),
    (0x09, "Neo Geo CD"),
    (0x42, "Genesis extended"),
    (0x43, "SMS + OPLL"),
    (0x46, "NES + VRC7"),
    (0x47, "C64 (6581)"),
    (0x80, "AY-3-8910"),
    (0x81, "Amiga"),
    (0x82, "YM2151"),
    (0x83, "YM2612"),
    (0x84, "TIA"),
    (0x85, "VIC-20"),
    (0x86, "PET"),
    (0x87, "SNES"),
    (0x88, "VRC6"),
    (0x89, "OPLL"),
    (0x8a, "FDS"),
    (0x8b, "MMC5"),
    (0x8c, "Namco 163"),
];

const FURNACE_BLOCKS: &[(&str, &str)] = &[
    ("INFO", "song information (old)"),
    ("INF2", "song information"),
    ("SONG", "subsong (old)"),
    ("SNG2", "subsong"),
    ("ADIR", "asset directories"),
    ("INST", "instrument (old)"),
    ("INS2", "instrument"),
    ("WAVE", "wavetable"),
    ("SMPL", "sample (old)"),
    ("SMP2", "sample"),
    ("PATR", "pattern (old)"),
    ("PATN", "pattern"),
    ("CFLG", "chip flags"),
    ("FEAT", "features"),
    ("COMP", "compatibility flags"),
    ("PATCH", "patch"),
];

async fn furnace(cx: Cx, input: Input) -> Result<()> {
    let (body, packed) = unpack(&cx, input.span, b"-Furnace module-").await?;
    let head = cx.block(body.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 16).emit()?;
    let version = f.u16("Format version").emit()?;
    f.u16("Reserved").emit()?;
    let info = f.u32("Song info pointer").hex().emit()?;
    f.bytes("Reserved", 8).emit()?;
    let mut cur = Cursor::new(&cx, body, LE);
    cur.seek(info.into());
    let (mut name, mut author, mut chips) = (String::new(), String::new(), Vec::new());
    let mut counts = std::collections::BTreeMap::new();
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        let meaning = FURNACE_BLOCKS.iter().find(|b| b.0 == id).map_or("unknown block", |b| b.1);
        let mut node = Node::new(id.clone()).span(cur.since(start)).desc(meaning).summary(format!("{len} bytes")).target(data);
        let n = counts.entry(id.clone()).or_insert(0u32);
        *n = n.saturating_add(1);
        if id == "INFO" {
            let raw = cx.read_avail(data.sub(0, 512)).await?;
            for &c in raw.get(24..56).unwrap_or_default() {
                if c != 0 {
                    chips.push(lookup(FURNACE_CHIPS, c.into()).map_or_else(|| format!("chip {c:#04x}"), str::to_owned));
                }
            }
            // Name and author are NUL-terminated after the 32+32+32+128 chip tables.
            let strings = raw.get(24usize + 32 + 32 + 32 + 128..).unwrap_or_default();
            let mut it = strings.split(|&b| b == 0);
            name = String::from_utf8_lossy(it.next().unwrap_or_default()).into_owned();
            author = String::from_utf8_lossy(it.next().unwrap_or_default()).into_owned();
            node = node.summary(format!("{name:?} by {author}")).lazy(furnace_info, data);
        }
        cx.push(node).await;
    }
    let tally: Vec<String> = counts.iter().map(|(k, v)| format!("{v} {k}")).collect();
    cx.annotate(format!(
        "Furnace module (format {version}){}, {name:?} by {author}, {}, blocks: {}",
        if packed { ", zlib" } else { "" },
        if chips.is_empty() { "no chips".to_owned() } else { chips.join(" + ") },
        tally.join(", ")
    ));
    Ok(())
}

record! {
    pub struct FurnaceInfo {
        time_base: u8 "Time base",
        speed1: u8 "Speed 1",
        speed2: u8 "Speed 2",
        arp: u8 "Initial arpeggio time",
        hz: f32 "Ticks per second",
        pattern_len: u16 "Pattern length",
        orders: u16 "Orders length",
        highlight_a: u8 "Highlight A",
        highlight_b: u8 "Highlight B",
        instruments: u16 "Instruments",
        wavetables: u16 "Wavetables",
        samples: u16 "Samples",
        patterns: u32 "Patterns",
        chips: bytes[32] "Sound chips",
        volumes: bytes[32] "Chip volumes",
        panning: bytes[32] "Chip panning",
        flags: bytes[128] "Chip flags",
    }
}

async fn furnace_info(cx: Cx, data: Span) -> Result<()> {
    let span = data.sub(0, FurnaceInfo::SIZE);
    let _: FurnaceInfo = emit_record(&cx, span, LE).await?;
    let raw = cx.read_avail(data.sub(24, 32)).await?;
    for (i, &c) in raw.iter().enumerate().filter(|(_, c)| **c != 0) {
        cx.emit(Node::new(format!("Chip {i}")).span(data.sub(24u64.saturating_add(to_u64(i)), 1)).value(Value::Enum { raw: c.into(), bits: 8, name: lookup(FURNACE_CHIPS, c.into()) }));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// S98 (PC-98 FM register log)

fn s98_probe(h: &Head<'_>) -> bool {
    h.at(0, b"S98") && matches!(h.data.get(3), Some(b'0'..=b'3'))
}

declare_format!(pub S98 = "s98", "S98 FM sound log", ["s98"],
    "audio/x-s98", Probe::Custom(s98_probe), s98);

const S98_DEVICES: EnumTable = &[
    (0, "none"),
    (1, "YM2149 (SSG)"),
    (2, "YM2203 (OPN)"),
    (3, "YM2612 (OPN2)"),
    (4, "YM2608 (OPNA)"),
    (5, "YM2151 (OPM)"),
    (6, "YM2413 (OPLL)"),
    (7, "YM3526 (OPL)"),
    (8, "YM3812 (OPL2)"),
    (9, "YMF262 (OPL3)"),
    (15, "AY-3-8910"),
    (16, "SN76489"),
];

record! {
    pub struct S98Header {
        magic: ascii[3] "Magic",
        version: ascii[1] "Version",
        timer: u32 "Timer numerator (default 10)",
        timer2: u32 "Timer denominator (default 1000)",
        compression: u32 "Compression",
        tag: u32 "Tag offset" .hex(),
        dump: u32 "Dump data offset" .hex(),
        loop_point: u32 "Loop offset" .hex(),
        devices: u32 "Device count",
    }
}

async fn s98(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, S98Header::SIZE);
    let h: S98Header = read_record(&cx, span, LE).await?;
    cx.emit(S98Header::node("Header", span, LE));
    let devices = if h.version == "3" { h.devices.min(64) } else { 0 };
    let mut names = Vec::new();
    for i in 0..u64::from(devices) {
        let d = file.sub(32u64.saturating_add(i.saturating_mul(16)), 16);
        let raw = cx.read(d).await?;
        let kind = u32_le(&raw, 0).unwrap_or(0);
        let clock = u32_le(&raw, 4).unwrap_or(0);
        let name = lookup(S98_DEVICES, kind.into()).unwrap_or("unknown");
        names.push(name);
        cx.emit(Node::new(format!("Device {i}")).span(d).value(Value::Enum { raw: kind.into(), bits: 32, name: lookup(S98_DEVICES, kind.into()) }).summary(format!("{clock} Hz, pan {:#x}", u32_le(&raw, 8).unwrap_or(0))));
    }
    if names.is_empty() {
        names.push("YM2608 (OPNA)");
    }
    let dump_end = if h.tag > h.dump { u64::from(h.tag) } else { file.len };
    cx.emit(Node::new("Register dump").span(file.sub(h.dump.into(), dump_end.saturating_sub(h.dump.into()))));
    let mut title = None;
    if h.tag != 0 {
        let tag = file.tail(h.tag.into());
        let raw = cx.read_avail(tag.sub(0, 4096)).await?;
        let body = raw.strip_prefix(b"[S98]").unwrap_or(&raw);
        let body = body.strip_prefix(b"\xef\xbb\xbf").unwrap_or(body);
        let s = crate::text::until_nul(body);
        title = s.lines().find_map(|l| l.strip_prefix("title=")).map(str::to_owned);
        cx.emit(Node::new("Tags").span(tag).value(text(s.replace('\n', "; "))));
    }
    let ms = f64::from(h.timer.max(1)) / f64::from(h.timer2.max(1)) * 1000.0;
    cx.annotate(format!(
        "S98 v{}{}, {}, tick {ms:.1} ms{}",
        h.version,
        title.map_or_else(String::new, |t| format!(" {t:?}")),
        names.join(" + "),
        if h.loop_point != 0 { ", loops" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GYM (Genesis YM2612 log)

declare_format!(pub GYM = "gym", "Genesis YM2612 register log (GYM)", ["gym"],
    "audio/x-gym", Probe::Magic(&[(0, b"GYMX")]), gym);

record! {
    pub struct GymHeader {
        magic: ascii[4] "Magic",
        song: ascii[32] "Song",
        game: ascii[32] "Game",
        publisher: ascii[32] "Publisher",
        emulator: ascii[32] "Emulator",
        dumper: ascii[32] "Dumper",
        comment: ascii[256] "Comment",
        loop_start: u32 "Loop start (frame)",
        packed: u32 "Uncompressed size (0 if not compressed)",
    }
}

async fn gym(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: GymHeader = emit_record(&cx, file.sub(0, GymHeader::SIZE), LE).await?;
    let data = file.tail(GymHeader::SIZE);
    let mut summary = format!("{} of commands", size(data.len));
    let mut frames = None;
    if h.packed == 0 && data.len <= cx.limits().max_read {
        let raw = cx.read(data).await?;
        let (mut i, mut n, mut writes) = (0usize, 0u64, 0u64);
        while let Some(&cmd) = raw.get(i) {
            i = i.saturating_add(match cmd {
                0 => {
                    n = n.saturating_add(1);
                    1
                }
                1 | 2 => {
                    writes = writes.saturating_add(1);
                    3
                }
                3 => {
                    writes = writes.saturating_add(1);
                    2
                }
                _ => 1,
            });
        }
        summary = format!("{n} frames, {writes} register writes");
        frames = Some(n);
    }
    let node = Node::new("Commands").span(data).summary(summary);
    cx.emit(if h.packed != 0 { node.diag(Diagnostic::note("zlib-compressed")) } else { node });
    cx.annotate(format!(
        "GYM log {:?} from {:?}{}",
        clean(&h.song),
        clean(&h.game),
        frames.map_or_else(String::new, |n| format!(", {n} frames ({}:{:02} at 60 Hz)", n / 3600, n / 60 % 60))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Organya (Cave Story)

declare_format!(pub ORGANYA = "organya", "Organya music (Cave Story)", ["org"],
    "audio/x-organya", Probe::Magic(&[(0, b"Org-02"), (0, b"Org-03")]), organya);

record! {
    pub struct OrgHeader {
        magic: ascii[6] "Magic",
        wait: u16 "Tempo (ms per step)",
        beats: u8 "Beats per bar",
        steps: u8 "Steps per beat",
        loop_start: i32 "Loop start (step)",
        loop_end: i32 "Loop end (step)",
    }
}

async fn organya(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: OrgHeader = emit_record(&cx, file.sub(0, OrgHeader::SIZE), LE).await?;
    let table = file.sub_exact(OrgHeader::SIZE, 16 * 6)?;
    let raw = cx.read(table).await?;
    let mut at = OrgHeader::SIZE.saturating_add(96);
    let (mut used, mut total) = (0u32, 0u64);
    for i in 0..16usize {
        let base = i.saturating_mul(6);
        let freq = u16_le(&raw, base).unwrap_or(0);
        let inst = raw.get(base.saturating_add(2)).copied().unwrap_or(0);
        let notes = u64::from(u16_le(&raw, base.saturating_add(4)).unwrap_or(0));
        let entry = table.sub(to_u64(base), 6);
        let notes_span = file.sub(at, notes.saturating_mul(8));
        at = at.saturating_add(notes.saturating_mul(8));
        if notes > 0 {
            used = used.saturating_add(1);
        }
        total = total.saturating_add(notes);
        let kind = if i < 8 { "melody" } else { "drum" };
        cx.emit(
            Node::new(format!("Track {i} ({kind})"))
                .span(entry)
                .value(dec(notes, 16))
                .summary(format!("{notes} notes, instrument {inst}, frequency {freq}"))
                .target(notes_span),
        );
    }
    cx.annotate(format!(
        "Organya {}, {} ms/step, {}/{}, loop {}..{}, {used} tracks, {total} notes",
        h.magic,
        h.wait,
        h.beats,
        h.steps,
        h.loop_start,
        h.loop_end
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GoatTracker (C64)

fn gts_probe(h: &Head<'_>) -> bool {
    h.at(0, b"GTS") && matches!(h.data.get(3), Some(b'2'..=b'5' | b'!'))
}

declare_format!(pub GOATTRACKER = "goattracker", "GoatTracker song (C64)", ["sng"],
    "audio/x-goattracker", Probe::Custom(gts_probe), goattracker);

record! {
    pub struct GtsHeader {
        magic: ascii[4] "Magic",
        name: ascii[32] "Song name",
        author: ascii[32] "Author",
        copyright: ascii[32] "Copyright",
        subtunes: u8 "Subtunes",
    }
}

async fn goattracker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: GtsHeader = emit_record(&cx, file.sub(0, GtsHeader::SIZE), LE).await?;
    cx.emit(Node::new("Order lists, instruments, tables and patterns").span(file.tail(GtsHeader::SIZE)));
    cx.annotate(format!("GoatTracker {} song {:?} by {}, {} subtune(s)", h.magic, clean(&h.name), clean(&h.author), h.subtunes));
    Ok(())
}

// ---------------------------------------------------------------------------
// SNDH (Atari ST)

fn sndh_probe(h: &Head<'_>) -> bool {
    h.at(12, b"SNDH")
}

declare_format!(pub SNDH = "sndh", "SNDH Atari ST music", ["sndh", "snd"],
    "audio/x-sndh", Probe::Custom(sndh_probe), sndh);

const SNDH_STRINGS: &[(&str, &str)] = &[("TITL", "Title"), ("COMM", "Composer"), ("RIPP", "Ripper"), ("CONV", "Converter"), ("YEAR", "Year")];

async fn sndh(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Init / exit / play branches").span(file.sub(0, 12)));
    let tags_span = file.sub(12, 4096);
    let raw = cx.read_avail(tags_span).await?;
    let mut pos = 4usize;
    cx.emit(Node::new("Magic").span(file.sub(12, 4)).value(text("SNDH")));
    let (mut title, mut composer, mut tunes, mut timer) = (String::new(), String::new(), 1u64, String::new());
    loop {
        while raw.get(pos) == Some(&0) {
            pos = pos.saturating_add(1);
        }
        let Some(tag) = raw.get(pos..pos.saturating_add(4)) else { break };
        let tag = String::from_utf8_lossy(tag).into_owned();
        let at = to_u64(pos).saturating_add(12);
        if tag == "HDNS" {
            cx.emit(Node::new("End of header (HDNS)").span(file.sub(at, 4)));
            pos = pos.saturating_add(4);
            break;
        }
        if let Some(&(_, label)) = SNDH_STRINGS.iter().find(|s| s.0 == tag) {
            let s = crate::text::until_nul(raw.get(pos.saturating_add(4)..).unwrap_or_default());
            let len = s.len().saturating_add(5);
            match tag.as_str() {
                "TITL" => title = s.clone(),
                "COMM" => composer = s.clone(),
                _ => {}
            }
            cx.emit(Node::new(label).span(file.sub(at, to_u64(len))).value(text(s)));
            pos = pos.saturating_add(len);
        } else if tag.starts_with("##") {
            tunes = tag.get(2..).and_then(|n| n.parse().ok()).unwrap_or(1);
            cx.emit(Node::new("Subtunes").span(file.sub(at, 4)).value(dec(tunes, 8)));
            pos = pos.saturating_add(4);
        } else if ["TA", "TB", "TC", "TD", "!V"].iter().any(|p| tag.starts_with(p)) {
            let s = crate::text::until_nul(raw.get(pos..).unwrap_or_default());
            let len = s.len().saturating_add(1);
            timer = s.clone();
            cx.emit(Node::new("Timer").span(file.sub(at, to_u64(len))).value(text(s)));
            pos = pos.saturating_add(len);
        } else if tag == "TIME" {
            let len = 4usize.saturating_add(usize::try_from(tunes).unwrap_or(0).saturating_mul(2));
            let times: Vec<String> = (0..usize::try_from(tunes).unwrap_or(0))
                .map(|i| u16_be(&raw, pos.saturating_add(4).saturating_add(i.saturating_mul(2))).unwrap_or(0))
                .map(|s| format!("{}:{:02}", s / 60, s % 60))
                .collect();
            cx.emit(Node::new("Durations").span(file.sub(at, to_u64(len))).value(text(times.join(", "))));
            pos = pos.saturating_add(len);
        } else {
            cx.emit(Node::new(format!("Tag {tag}")).span(file.sub(at, 4)).diag(Diagnostic::unsupported("unknown SNDH tag; stopping")));
            break;
        }
    }
    cx.emit(Node::new("68000 replay code and data").span(file.tail(to_u64(pos).saturating_add(12))));
    cx.annotate(format!(
        "SNDH {title:?} by {composer}, {tunes} tune(s){}",
        if timer.is_empty() { String::new() } else { format!(", timer {timer}") }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Pro Tracker 3 / Vortex Tracker II (ZX Spectrum AY)

declare_format!(pub PT3 = "pt3", "Pro Tracker 3 module (ZX Spectrum)", ["pt3"],
    "audio/x-pt3", Probe::Magic(&[(0, b"ProTracker 3."), (0, b"Vortex Tracker II")]), pt3);

const PT3_TABLES: EnumTable = &[(0, "Pro Tracker"), (1, "Sound Tracker"), (2, "ASC Sound Master"), (3, "Real sound")];

async fn pt3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0xc9)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let banner = f.ascii("Banner", 0x1e).emit()?;
    let title = f.ascii("Title", 32).emit()?;
    f.ascii("Separator", 4).emit()?;
    let author = f.ascii("Author", 32).emit()?;
    f.ascii("Padding", 1).emit()?;
    f.u8("Frequency table").enumeration(PT3_TABLES).emit()?;
    let delay = f.u8("Speed").emit()?;
    let positions = f.u8("Positions").emit()?;
    f.u8("Loop position").emit()?;
    f.u16("Patterns offset").hex().emit()?;
    f.node(Node::new("Sample offsets").span(file.sub(0x69, 64)));
    f.node(Node::new("Ornament offsets").span(file.sub(0xa9, 32)));
    let list = file.sub(0xc9, u64::from(positions).saturating_add(1));
    let raw = cx.read_avail(list).await?;
    let patterns: Vec<String> = raw.iter().take(usize::from(positions)).map(|&p| (p / 3).to_string()).collect();
    cx.emit(Node::new("Position list").span(list).value(text(patterns.join(" "))));
    cx.emit(Node::new("Patterns, samples and ornaments").span(file.tail(list.end().saturating_sub(file.offset))));
    cx.annotate(format!(
        "{} module {:?} by {}, {positions} positions, speed {delay}",
        banner.trim_end().trim_end_matches(" compilation of").trim(),
        clean(&title),
        clean(&author)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// PSG (AY-3-8910 register dump)

declare_format!(pub PSG = "psg", "AY-3-8910 register dump (PSG)", ["psg"],
    "audio/x-psg", Probe::Magic(&[(0, b"PSG\x1a")]), psg);

async fn psg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Magic", 4).emit()?;
    let version = f.u8("Version").emit()?;
    let rate = f.u8("Interrupt frequency (Hz)").emit()?;
    f.bytes("Reserved", 10).emit()?;
    let data = file.tail(16);
    let mut summary = size(data.len);
    let mut frames = None;
    if data.len <= cx.limits().max_read {
        let raw = cx.read(data).await?;
        let (mut i, mut n, mut writes) = (0usize, 0u64, 0u64);
        while let Some(&b) = raw.get(i) {
            match b {
                0xff => {
                    n = n.saturating_add(1);
                    i = i.saturating_add(1);
                }
                0xfe => {
                    n = n.saturating_add(u64::from(raw.get(i.saturating_add(1)).copied().unwrap_or(0)).saturating_mul(4));
                    i = i.saturating_add(2);
                }
                0xfd => break,
                _ => {
                    writes = writes.saturating_add(1);
                    i = i.saturating_add(2);
                }
            }
        }
        summary = format!("{n} frames, {writes} register writes");
        frames = Some(n);
    }
    cx.emit(Node::new("Register writes").span(data).summary(summary));
    let hz = if rate == 0 { 50 } else { u64::from(rate) };
    cx.annotate(format!(
        "PSG register dump v{version}, {hz} Hz{}",
        frames.map_or_else(String::new, |n| {
            let secs = n.checked_div(hz).unwrap_or(0);
            format!(", {n} frames ({}:{:02})", secs / 60, secs % 60)
        })
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// AHX (Abyss' Highest eXperience, Amiga)

fn ahx_probe(h: &Head<'_>) -> bool {
    h.at(0, b"THX") && matches!(h.data.get(3), Some(0 | 1)) && u16_be(h.data, 4).is_some_and(|o| u64::from(o) < h.len && o >= 14)
}

declare_format!(pub AHX = "ahx", "AHX module (Amiga)", ["ahx", "thx"],
    "audio/x-ahx", Probe::Custom(ahx_probe), ahx);

async fn ahx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 3).emit()?;
    let version = f.u8("Version").emit()?;
    let names = f.u16("Name table offset").hex().emit()?;
    let word = f.u16("Flags and position list length").hex().emit()?;
    f.node(Node::new("Position list length").span(file.sub(6, 2)).value(dec((word & 0x0fff).into(), 12)));
    f.node(Node::new("Speed multiplier").span(file.sub(6, 1)).value(dec((u64::from(word) >> 12 & 7).saturating_add(1), 3)));
    f.u16("Restart position").emit()?;
    let rows = f.u8("Track length (rows)").emit()?;
    let tracks = f.u8("Tracks").emit()?;
    let samples = f.u8("Samples").emit()?;
    let subsongs = f.u8("Subsongs").emit()?;
    let positions = u64::from(word & 0x0fff);
    let subsong_span = file.sub(14, u64::from(subsongs).saturating_mul(2));
    cx.emit(Node::new("Subsong list").span(subsong_span));
    let pos_span = file.sub(subsong_span.end().saturating_sub(file.offset), positions.saturating_mul(8));
    cx.emit(Node::new("Position list").span(pos_span).summary(format!("{positions} positions × 4 channels")));
    let name_span = file.tail(names.into());
    let raw = cx.read_avail(name_span.sub(0, 4096)).await?;
    let mut strings = raw.split(|&b| b == 0).map(|s| String::from_utf8_lossy(s).into_owned());
    let title = strings.next().unwrap_or_default();
    let sample_names: Vec<String> = strings.take(usize::from(samples)).collect();
    cx.emit(Node::new("Names").span(name_span).value(text(title.clone())).lazy(ahx_names, (name_span, sample_names)));
    cx.annotate(format!(
        "AHX{version} module {title:?}, {positions} positions, {tracks} tracks of {rows} rows, {samples} samples, {subsongs} subsongs"
    ));
    Ok(())
}

async fn ahx_names(cx: Cx, (span, names): (Span, Vec<String>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(names.len())));
    for (i, n) in names.into_iter().enumerate() {
        cx.push(Node::new(format!("Sample {}", i.saturating_add(1))).value(text(n)).target(span)).await;
    }
    Ok(())
}
