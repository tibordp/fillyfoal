//! Emulator save states, input movies and memory-card images: ZSNES,
//! Snes9x, FCEUX, RetroArch, Dolphin DTM, SMV, VBM, FCM, M64, GMV, FM2,
//! PlayStation and PlayStation 2 memory cards, DexDrive and GameCube GCI.

use super::util::{clean, hex, is_ascii_text, lines, size, text};
use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// Decodes the Shift-JIS subset used in save titles: ASCII and the
/// full-width Latin letters, digits and common punctuation.
fn sjis(data: &[u8]) -> String {
    let mut out = String::new();
    let mut it = data.iter().copied().peekable();
    while let Some(b) = it.next() {
        match b {
            0 => break,
            0x20..=0x7e => out.push(char::from(b)),
            0x81..=0x9f | 0xe0..=0xef => {
                let lo = it.next().unwrap_or(0);
                let c = match (b, lo) {
                    (0x81, 0x40) => ' ',
                    (0x81, 0x46) => ':',
                    (0x81, 0x5e) => '/',
                    (0x81, 0x69) => '(',
                    (0x81, 0x6a) => ')',
                    (0x81, 0x7c) => '-',
                    (0x81, 0x44) => '.',
                    (0x81, 0x43) => ',',
                    (0x82, 0x4f..=0x58) => char::from(b'0'.saturating_add(lo.saturating_sub(0x4f))),
                    (0x82, 0x60..=0x79) => char::from(b'A'.saturating_add(lo.saturating_sub(0x60))),
                    (0x82, 0x81..=0x9a) => char::from(b'a'.saturating_add(lo.saturating_sub(0x81))),
                    _ => '?',
                };
                out.push(c);
            }
            _ => out.push('?'),
        }
    }
    out
}

// ---------------------------------------------------------------------------
// ZSNES save state

declare_format!(pub ZSNES = "zsnes-state", "ZSNES save state", ["zst", "zs1", "zs2", "zs3"],
    "application/x-zsnes-state", Probe::Magic(&[(0, b"ZSNES Save State File")]), zsnes);

async fn zsnes(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 28)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.ascii("Signature", 26).emit()?;
    f.u8("End of text").hex().emit()?;
    let version = f.u8("Version").emit()?;
    cx.emit(Node::new("CPU, PPU and memory snapshot").span(file.tail(28)).summary(size(file.len.saturating_sub(28))));
    cx.annotate(format!("{}, version {version}, {}", sig.trim(), size(file.len)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Snes9x snapshot ("#!s9xsnp:NNNN" + named blocks)

declare_format!(pub SNES9X = "snes9x-state", "Snes9x snapshot", ["000", "001", "frz", "s9x"],
    "application/x-snes9x-state", Probe::Magic(&[(0, b"#!s9xsnp:"), (0, b"#!snes9x:")]), snes9x);

const SNES9X_BLOCKS: &[(&str, &str)] = &[
    ("NAM", "ROM file name"),
    ("CPU", "65C816 registers"),
    ("REG", "registers"),
    ("PPU", "PPU state"),
    ("DMA", "DMA channels"),
    ("VRA", "video RAM"),
    ("RAM", "work RAM"),
    ("SRA", "save RAM"),
    ("FIL", "extended RAM"),
    ("SND", "sound (SPC700/DSP)"),
    ("CTL", "controllers"),
    ("TIM", "timings"),
    ("SFX", "Super FX"),
    ("SA1", "SA-1"),
    ("SAR", "SA-1 registers"),
    ("DP1", "DSP-1"),
    ("RTC", "real-time clock"),
    ("BSX", "Satellaview"),
    ("SHO", "screenshot"),
    ("MOV", "movie"),
    ("MID", "movie input data"),
];

async fn snes9x(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 14)).await?;
    let version = String::from_utf8_lossy(head.get(9..13).unwrap_or_default()).into_owned();
    cx.emit(Node::new("Signature").span(file.sub(0, 14)).value(text(String::from_utf8_lossy(head.get(..13).unwrap_or_default()).into_owned())));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(14);
    let (mut blocks, mut rom) = (0u32, None);
    while cur.remaining() >= 11 {
        let start = cur.pos();
        let h = cur.bytes(11).await?;
        if h.get(3) != Some(&b':') || h.get(10) != Some(&b':') {
            cx.push(Node::new("Unrecognised data").span(file.tail(start)).diag(Diagnostic::malformed("expected a block header"))).await;
            break;
        }
        let name = String::from_utf8_lossy(h.get(..3).unwrap_or_default()).into_owned();
        let len: u64 = String::from_utf8_lossy(h.get(4..10).unwrap_or_default()).trim().parse().unwrap_or(0);
        let data = cur.span(len);
        cur.skip(len);
        blocks = blocks.saturating_add(1);
        let meaning = SNES9X_BLOCKS.iter().find(|b| b.0 == name).map_or("unknown block", |b| b.1);
        let mut node = Node::new(name.clone()).span(cur.since(start)).desc(meaning).target(data).summary(format!("{meaning}, {len} bytes"));
        if name == "NAM" {
            let s = crate::text::until_nul(&cx.read_avail(data.sub(0, 1024)).await?);
            node = node.value(text(s.clone()));
            rom = Some(s);
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "Snes9x snapshot v{}, {blocks} blocks{}",
        version.trim_start_matches('0'),
        rom.map_or_else(String::new, |r| format!(", ROM {r:?}"))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FCEUX save state

declare_format!(pub FCEUX = "fceux-state", "FCEUX save state", ["fc0", "fc1", "fc2", "fcs"],
    "application/x-fceux-state", Probe::Magic(&[(0, b"FCSX")]), fceux);

const FCEUX_SECTIONS: EnumTable = &[(1, "CPU"), (2, "CPU cycle counter"), (3, "PPU"), (4, "input"), (5, "sound"), (16, "mapper and game data"), (31, "new PPU")];

async fn fceux(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let total = f.u32("Uncompressed size").emit()?;
    let version = f.u32("FCEUX version").emit()?;
    let compressed = f.u32("Compressed size").with(|&v, n| if v == u32::MAX { n.summary("not compressed") } else { n }).emit()?;
    let body = if compressed == u32::MAX {
        file.sub(16, total.into())
    } else {
        let decoded = crate::codec::inflate_span(&cx, file.sub(16, compressed.into()), true, Some(total.into())).await?;
        if let Some(e) = decoded.error {
            cx.diag(e);
        }
        decoded.span
    };
    cx.emit(Node::new("Sections").span(body).summary(if compressed == u32::MAX { "stored".to_owned() } else { format!("zlib, {compressed} bytes compressed") }).lazy(fceux_sections, body));
    cx.annotate(format!(
        "FCEUX save state, emulator {}.{}.{}, {} of state{}",
        version / 10000,
        version / 100 % 100,
        version % 100,
        size(total.into()),
        if compressed == u32::MAX { "" } else { ", zlib-compressed" }
    ));
    Ok(())
}

async fn fceux_sections(cx: Cx, body: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, body, LE);
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        cx.push(
            Node::new(lookup(FCEUX_SECTIONS, kind.into()).map_or_else(|| format!("Section {kind}"), str::to_owned))
                .span(cur.since(start))
                .value(Value::Enum { raw: kind.into(), bits: 8, name: lookup(FCEUX_SECTIONS, kind.into()) })
                .summary(format!("{len} bytes"))
                .lazy(fceux_vars, data),
        )
        .await;
    }
    Ok(())
}

/// A section is a list of `(4-character name, u32 size, data)` variables.
async fn fceux_vars(cx: Cx, data: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, LE);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let name = crate::text::until_nul(&cur.bytes(4).await?);
        let len = u64::from(cur.u32().await?);
        let value = cur.span(len);
        cur.skip(len);
        let raw = cx.read_avail(value.sub(0, 8)).await?;
        let mut node = Node::new(if name.is_empty() { "(unnamed)".to_owned() } else { name }).span(cur.since(start)).target(value);
        node = match len {
            1 => node.value(hex(raw.first().copied().unwrap_or(0).into(), 8)),
            2 => node.value(hex(u16_le(&raw, 0).unwrap_or(0).into(), 16)),
            4 => node.value(hex(u32_le(&raw, 0).unwrap_or(0).into(), 32)),
            8 => node.value(hex(crate::bytes::u64_le(&raw, 0).unwrap_or(0), 64)),
            _ => node.summary(format!("{len} bytes")),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RetroArch save state

declare_format!(pub RETROARCH = "retroarch-state", "RetroArch save state", ["state", "state1", "state2", "state3"],
    "application/x-retroarch-state", Probe::Magic(&[(0, b"RASTATE")]), retroarch);

const RA_BLOCKS: &[(&str, &str)] = &[("MEM ", "core serialised state"), ("ACHV", "achievements state"), ("RPLY", "replay/movie"), ("END ", "end marker")];

async fn retroarch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 7).emit()?;
    let version = f.u8("Version").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let mut core = 0u64;
    let mut names = Vec::new();
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len.next_multiple_of(8));
        if id == "MEM " {
            core = len;
        }
        names.push(id.trim().to_owned());
        let meaning = RA_BLOCKS.iter().find(|b| b.0 == id).map_or("unknown block", |b| b.1);
        cx.push(Node::new(id.clone()).span(cur.since(start)).desc(meaning).summary(format!("{len} bytes")).target(data)).await;
        if id == "END " {
            break;
        }
    }
    cx.annotate(format!("RetroArch state v{version}, {} core state, blocks {}", size(core), names.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Dolphin TAS movie (DTM)

declare_format!(pub DTM = "dolphin-dtm", "Dolphin TAS movie (DTM)", ["dtm"],
    "application/x-dolphin-dtm", Probe::Magic(&[(0, b"DTM\x1a")]), dtm);

record! {
    pub struct DtmHeader {
        magic: bytes[4] "Signature",
        game_id: ascii[6] "Game ID",
        wii: u8 "Wii game" .enumeration(&[(0, "no"), (1, "yes")]),
        controllers: u8 "Controllers" .flags(DTM_CONTROLLERS),
        from_state: u8 "Starts from save state" .enumeration(&[(0, "no"), (1, "yes")]),
        frames: u64 "VI frames",
        inputs: u64 "Input polls",
        lag: u64 "Lag frames",
        unique: u64 "Unique ID" .hex(),
        rerecords: u32 "Rerecords",
        author: ascii[32] "Author",
        video: ascii[16] "Video backend",
        audio: ascii[16] "Audio emulator",
        md5: bytes[16] "Game MD5",
        start_time: u64 "Recording start time" .timestamp(),
        save_config: u8 "Config saved",
        skip_idle: u8 "Idle skipping",
        dual_core: u8 "Dual core",
        progressive: u8 "Progressive scan",
        dsp_hle: u8 "DSP HLE",
        fast_disc: u8 "Fast disc speed",
        cpu_core: u8 "CPU core" .enumeration(&[(0, "interpreter"), (1, "JIT x86-64"), (4, "JIT ARM64"), (5, "cached interpreter")]),
        efb_access: u8 "EFB access",
        efb_copy: u8 "EFB copy",
        efb_to_ram: u8 "Skip EFB copy to RAM",
        efb_cache: u8 "EFB copy cache",
        efb_format: u8 "Emulate EFB format changes",
        immediate_xfb: u8 "Immediate XFB",
        xfb_to_ram: u8 "Skip XFB copy to RAM",
        memcards: u8 "Memory cards" .hex(),
        clear_save: u8 "Clear save",
        bongos: u8 "Bongos" .hex(),
        sync_gpu: u8 "Sync GPU",
        netplay: u8 "Netplay",
        pal60: u8 "PAL60",
        language: u8 "Language",
        _reserved3: u8 "Reserved",
        follow_branch: u8 "Follow branch",
        fma: u8 "Use FMA",
        gba: u8 "GBA controllers" .hex(),
        widescreen: u8 "Widescreen",
        _reserved: bytes[6] "Reserved",
        disc_change: ascii[40] "Disc change file",
        revision: bytes[20] "Dolphin revision (git SHA-1)",
        dsp_irom: u32 "DSP IROM hash" .hex(),
        dsp_coef: u32 "DSP COEF hash" .hex(),
        ticks: u64 "CPU ticks",
        _reserved2: bytes[11] "Reserved",
    }
}

const DTM_CONTROLLERS: FlagTable = &[
    flag(0x01, "GC_PORT_1"),
    flag(0x02, "GC_PORT_2"),
    flag(0x04, "GC_PORT_3"),
    flag(0x08, "GC_PORT_4"),
    flag(0x10, "WIIMOTE_1"),
    flag(0x20, "WIIMOTE_2"),
    flag(0x40, "WIIMOTE_3"),
    flag(0x80, "WIIMOTE_4"),
];

async fn dtm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, DtmHeader::SIZE);
    let h: DtmHeader = read_record(&cx, span, LE).await?;
    cx.emit(DtmHeader::node("Header", span, LE));
    cx.emit(Node::new("Input data").span(file.tail(DtmHeader::SIZE)).summary(format!("{} polls", h.inputs)));
    let rev: String = h.revision.iter().take(4).map(|b| format!("{b:02x}")).collect();
    cx.annotate(format!(
        "Dolphin movie of {} ({}), {} frames, {} rerecords, by {:?}, revision {rev}",
        h.game_id,
        if h.wii != 0 { "Wii" } else { "GameCube" },
        h.frames,
        h.rerecords,
        clean(&h.author)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Snes9x movie (SMV)

declare_format!(pub SMV = "smv", "Snes9x movie", ["smv"],
    "application/x-smv", Probe::Magic(&[(0, b"SMV\x1a")]), smv);

const SMV_OPTIONS: FlagTable = &[flag(0x01, "FROM_SNAPSHOT"), flag(0x02, "PAL"), flag(0x04, "NO_SRAM")];
const SMV_CONTROLLERS: FlagTable = &[flag(0x01, "PAD_1"), flag(0x02, "PAD_2"), flag(0x04, "PAD_3"), flag(0x08, "PAD_4"), flag(0x10, "PAD_5")];
const SMV_PORTS: EnumTable = &[(0, "none"), (1, "joypad"), (2, "mouse"), (3, "Super Scope"), (4, "Justifier"), (5, "multitap")];

async fn smv(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x40)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    let version = f.u32("Version").enumeration(&[(1, "1.43"), (4, "1.51"), (5, "1.52+")]).emit()?;
    f.u32("Movie UID (recording time)").timestamp().emit()?;
    let rerecords = f.u32("Rerecords").emit()?;
    let frames = f.u32("Frames").emit()?;
    f.u8("Controllers").flags(SMV_CONTROLLERS).emit()?;
    let options = f.u8("Options").flags(SMV_OPTIONS).emit()?;
    f.u8("Sync options 1").hex().emit()?;
    f.u8("Sync options 2").hex().emit()?;
    let state = f.u32("Save state offset").hex().emit()?;
    let controller = f.u32("Controller data offset").hex().emit()?;
    let meta_start = if version >= 4 {
        f.u32("Input samples").emit()?;
        f.u8("Port 1 type").enumeration(SMV_PORTS).emit()?;
        f.u8("Port 2 type").enumeration(SMV_PORTS).emit()?;
        f.bytes("Port IDs and reserved", 26).emit()?;
        0x40u64
    } else {
        0x20
    };
    // Author metadata (UTF-16LE), then optionally 30 bytes of ROM info.
    let state = u64::from(state);
    let mut meta_end = state;
    let info = file.sub(state.saturating_sub(30), 30);
    let raw = cx.read_avail(info).await?;
    let mut rom = None;
    if state >= meta_start.saturating_add(30) && raw.get(..3) == Some(&[0, 0, 0]) {
        meta_end = state.saturating_sub(30);
        let name = crate::text::until_nul(raw.get(7..).unwrap_or_default());
        cx.emit(Node::new("ROM info").span(info).value(text(name.clone())).summary(format!("CRC-32 {:#010x}", u32_le(&raw, 3).unwrap_or(0))));
        rom = Some(name);
    }
    let meta = file.sub(meta_start, meta_end.saturating_sub(meta_start));
    let author = crate::text::utf16z(&cx.read_avail(meta.sub(0, 1024)).await?, LE).0;
    if meta.len > 0 {
        cx.emit(Node::new("Author").span(meta).value(text(author.clone())));
    }
    let what = if options & 1 != 0 { "Save state" } else { "SRAM" };
    cx.emit(Node::new(what).span(file.sub(state, u64::from(controller).saturating_sub(state))));
    cx.emit(Node::new("Controller data").span(file.tail(controller.into())));
    cx.annotate(format!(
        "Snes9x movie{}, {frames} frames ({}), {rerecords} rerecords{}",
        rom.map_or_else(String::new, |r| format!(" of {r:?}")),
        if options & 2 != 0 { "PAL" } else { "NTSC" },
        if author.is_empty() { String::new() } else { format!(", by {author:?}") }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// VisualBoyAdvance movie (VBM)

declare_format!(pub VBM = "vbm", "VisualBoyAdvance movie", ["vbm"],
    "application/x-vbm", Probe::Magic(&[(0, b"VBM\x1a")]), vbm);

const VBM_START: FlagTable = &[flag(0x01, "FROM_SNAPSHOT"), flag(0x02, "FROM_SRAM")];
const VBM_SYSTEM: FlagTable = &[flag(0x01, "GBA"), flag(0x02, "GBC"), flag(0x04, "SGB")];

record! {
    pub struct VbmHeader {
        magic: bytes[4] "Signature",
        version: u32 "Version",
        uid: u32 "Movie UID (recording time)" .timestamp(),
        frames: u32 "Frames",
        rerecords: u32 "Rerecords",
        start: u8 "Start flags" .flags(VBM_START),
        controllers: u8 "Controllers" .hex(),
        system: u8 "System" .flags(VBM_SYSTEM),
        options: u8 "Emulator options" .hex(),
        save_type: u32 "Save type",
        flash_size: u32 "Flash size",
        gb_type: u32 "Game Boy emulation type",
        title: ascii[12] "ROM title",
        minor: u8 "Minor version",
        crc: u8 "ROM header checksum" .hex(),
        checksum: u16 "ROM checksum" .hex(),
        game_code: u32 "Game code" .hex(),
        state: u32 "Save state offset" .hex(),
        controller: u32 "Controller data offset" .hex(),
        author: ascii[64] "Author",
        description: ascii[128] "Description",
    }
}

async fn vbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: VbmHeader = emit_record(&cx, file.sub(0, VbmHeader::SIZE), LE).await?;
    if h.start != 0 {
        cx.emit(Node::new(if h.start & 1 != 0 { "Save state" } else { "SRAM" }).span(file.sub(h.state.into(), u64::from(h.controller).saturating_sub(h.state.into()))));
    }
    cx.emit(Node::new("Controller data").span(file.tail(h.controller.into())).summary(format!("{} frames", h.frames)));
    let system = if h.system & 1 != 0 { "GBA" } else if h.system & 2 != 0 { "GBC" } else { "GB" };
    cx.annotate(format!(
        "VBA movie of {:?} ({system}), {} frames, {} rerecords, by {:?}",
        clean(&h.title),
        h.frames,
        h.rerecords,
        clean(&h.author)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FCE Ultra movie (FCM)

declare_format!(pub FCM = "fcm", "FCE Ultra movie (FCM)", ["fcm"],
    "application/x-fcm", Probe::Magic(&[(0, b"FCM\x1a")]), fcm);

const FCM_FLAGS: FlagTable = &[flag(0x02, "POWER_ON"), flag(0x04, "PAL"), flag(0x08, "RESET"), flag(0x10, "HAS_SAVESTATE")];

async fn fcm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x34)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 4).emit()?;
    f.u32("Version").emit()?;
    f.u8("Flags").flags(FCM_FLAGS).emit()?;
    f.bytes("Reserved", 3).emit()?;
    let frames = f.u32("Frames").emit()?;
    let rerecords = f.u32("Rerecords").emit()?;
    let data_len = f.u32("Controller data length").emit()?;
    let state = f.u32("Save state offset").hex().emit()?;
    let data = f.u32("Controller data offset").hex().emit()?;
    f.bytes("ROM MD5", 16).emit()?;
    f.u32("Emulator version").emit()?;
    let (rom, rom_span) = cx.cstr(file.sub(0x34, 256)).await?;
    cx.emit(Node::new("ROM name").span(rom_span).value(text(rom.clone())));
    let author_at = rom_span.end().saturating_sub(file.offset);
    let (author, author_span) = cx.cstr(file.sub(author_at, 256)).await.unwrap_or_else(|_| (String::new(), file.sub(author_at, 0)));
    cx.emit(Node::new("Author").span(author_span).value(text(author.clone())));
    if state != 0 {
        cx.emit(Node::new("Save state").span(file.sub(state.into(), u64::from(data).saturating_sub(state.into()))));
    }
    cx.emit(Node::new("Controller data").span(file.sub(data.into(), data_len.into())));
    cx.annotate(format!("FCM movie of {rom:?}, {frames} frames, {rerecords} rerecords, by {author:?}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Mupen64 movie (M64)

declare_format!(pub M64 = "m64", "Mupen64 movie (M64)", ["m64"],
    "application/x-m64", Probe::Magic(&[(0, b"M64\x1a")]), m64);

const M64_START: EnumTable = &[(1, "save state"), (2, "power-on"), (4, "EEPROM")];

record! {
    pub struct M64Header {
        magic: bytes[4] "Signature",
        version: u32 "Version",
        uid: u32 "Movie UID (recording time)" .timestamp(),
        frames: u32 "VI frames",
        rerecords: u32 "Rerecords",
        fps: u8 "VIs per second",
        controllers: u8 "Controllers",
        _reserved: u16 "Reserved",
        samples: u32 "Input samples",
        start: u16 "Start type" .enumeration(M64_START),
        _reserved2: u16 "Reserved",
        controller_flags: u32 "Controller flags" .hex(),
        _reserved3: bytes[160] "Reserved",
        rom_name: ascii[32] "ROM name",
        rom_crc: u32 "ROM CRC-32" .hex(),
        rom_country: u16 "ROM country code" .hex(),
        _reserved4: bytes[56] "Reserved",
        video: ascii[64] "Video plugin",
        sound: ascii[64] "Sound plugin",
        input: ascii[64] "Input plugin",
        rsp: ascii[64] "RSP plugin",
        author: ascii[222] "Author (UTF-8)",
        description: ascii[256] "Description (UTF-8)",
    }
}

async fn m64(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: M64Header = emit_record(&cx, file.sub(0, M64Header::SIZE), LE).await?;
    cx.emit(Node::new("Input data").span(file.tail(M64Header::SIZE)).summary(format!("{} samples", h.samples)));
    cx.annotate(format!(
        "Mupen64 movie of {:?}, {} frames at {} Hz, {} rerecords, from {}, by {:?}",
        clean(&h.rom_name),
        h.frames,
        h.fps,
        h.rerecords,
        lookup(M64_START, h.start.into()).unwrap_or("unknown start"),
        clean(&h.author)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Gens movie (GMV)

declare_format!(pub GMV = "gmv", "Gens movie (GMV)", ["gmv"],
    "application/x-gmv", Probe::Magic(&[(0, b"Gens Movie TEST")]), gmv);

const GMV_FLAGS: FlagTable = &[flag(0x20, "THREE_PLAYERS"), flag(0x40, "FROM_SAVESTATE"), flag(0x80, "PAL")];

async fn gmv(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 64)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 15).emit()?;
    let version = f.ascii("Version", 1).emit()?;
    let rerecords = f.u32("Rerecords").emit()?;
    let p1 = f.ascii("Controller 1 buttons", 1).emit()?;
    let p2 = f.ascii("Controller 2 buttons", 1).emit()?;
    let flags = f.u8("Flags").flags(GMV_FLAGS).emit()?;
    f.u8("Reserved").emit()?;
    let comment = f.ascii("Comment", 40).emit()?;
    let frames = file.len.saturating_sub(64) / 3;
    cx.emit(Node::new("Input frames").span(file.tail(64)).summary(format!("{frames} frames of 3 bytes")));
    cx.annotate(format!(
        "Gens movie v{version}, {frames} frames ({}), {rerecords} rerecords, {p1}/{p2}-button pads, {:?}",
        if flags & 0x80 != 0 { "PAL" } else { "NTSC" },
        clean(&comment)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// FCEUX movie (FM2, text)

fn fm2_probe(h: &Head<'_>) -> bool {
    let first = h.data.get(..h.data.len().min(2048)).unwrap_or_default();
    h.starts_with(b"version 3") && is_ascii_text(first) && first.windows(11).any(|w| w == b"emuVersion ")
}

declare_format!(pub FM2 = "fm2", "FCEUX movie (FM2)", ["fm2"],
    "text/x-fm2", Probe::Custom(fm2_probe), fm2);

async fn fm2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read(file.sub(0, file.len.min(1 << 20))).await?;
    let mut frames: Vec<Span> = Vec::new();
    let mut fields = Vec::new();
    for (line, span) in lines(&data, file) {
        if line.starts_with('|') {
            frames.push(span);
            continue;
        }
        let (key, value) = line.split_once(' ').unwrap_or((&line, ""));
        if key.is_empty() {
            continue;
        }
        fields.push((key.to_owned(), value.to_owned()));
        let v = value.parse::<i64>().map_or_else(|_| text(value.to_owned()), |n| Value::Int { value: n, bits: 64 });
        cx.emit(Node::new(key.to_owned()).span(span).value(v));
    }
    let get = |k: &str| fields.iter().find(|f| f.0 == k).map_or("", |f| f.1.as_str());
    let count = crate::bytes::to_u64(frames.len());
    if let (Some(first), Some(last)) = (frames.first(), frames.last()) {
        let span = Span { len: last.end().saturating_sub(first.offset), ..*first };
        cx.emit(Node::new("Input log").span(span).summary(format!("{count} frames")).lazy(fm2_frames, frames.clone()));
    }
    cx.annotate(format!(
        "FCEUX movie of {:?}, {count} frames, {} rerecords{}",
        get("romFilename"),
        get("rerecordCount"),
        if get("palFlag") == "1" { ", PAL" } else { "" }
    ));
    Ok(())
}

async fn fm2_frames(cx: Cx, frames: Vec<Span>) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(frames.len())));
    for (i, span) in frames.into_iter().enumerate() {
        let line = String::from_utf8_lossy(&cx.read(span).await?).into_owned();
        cx.push(Node::new(format!("Frame {i}")).span(span).value(text(line))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PlayStation memory card (raw 128 KiB) and DexDrive (.gme)

fn psx_mc_probe(h: &Head<'_>) -> bool {
    h.at(0, b"MC") && h.len == 0x20000 && h.data.get(127) == Some(&0x0e) && h.data.get(2..127).is_some_and(|r| r.iter().all(|&b| b == 0))
}

declare_format!(pub PSX_MEMCARD = "psx-memcard", "PlayStation memory card image", ["mcr", "mcd", "mc", "srm", "mem", "vgs", "ps"],
    "application/x-psx-memcard", Probe::Custom(psx_mc_probe), psx_memcard);

const PSX_ALLOC: EnumTable = &[
    (0x51, "in use, first block"),
    (0x52, "in use, middle block"),
    (0x53, "in use, last block"),
    (0xa0, "free"),
    (0xa1, "deleted, first block"),
    (0xa2, "deleted, middle block"),
    (0xa3, "deleted, last block"),
];
const PSX_REGIONS: &[(&str, &str)] = &[("BI", "Japan"), ("BA", "North America"), ("BE", "Europe")];

record! {
    pub struct PsxDirFrame {
        state: u32 "Allocation state" .enumeration(PSX_ALLOC),
        size: u32 "File size",
        next: u16 "Next block" .with(|&v, n| if v == 0xffff { n.summary("none") } else { n }),
        name: ascii[21] "File name",
        _padding: bytes[96] "Padding",
        checksum: u8 "XOR checksum" .hex(),
    }
}

async fn psx_memcard(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header frame").span(file.sub(0, 0x80)));
    let mut saves = Vec::new();
    let mut used = 0u32;
    for slot in 1..16u64 {
        let span = file.sub(slot.saturating_mul(0x80), 0x80);
        let d: PsxDirFrame = read_record(&cx, span, LE).await?;
        let raw = cx.read(span).await?;
        let xor = raw.iter().take(127).fold(0u8, |x, &b| x ^ b);
        let block = file.sub(slot.saturating_mul(0x2000), 0x2000);
        let mut node = PsxDirFrame::node(format!("Slot {slot}"), span, LE).target(block);
        if xor != d.checksum {
            node = node.diag(Diagnostic::warning(format!("checksum mismatch: computed {xor:#04x}")));
        }
        if matches!(d.state, 0x51..=0x53) {
            used = used.saturating_add(1);
        }
        if d.state == 0x51 {
            let head = cx.read_avail(block.sub(0, 0x44)).await?;
            let title = if head.starts_with(b"SC") { sjis(head.get(4..).unwrap_or_default()) } else { String::new() };
            let region = PSX_REGIONS.iter().find(|r| d.name.starts_with(r.0)).map_or("unknown region", |r| r.1);
            node = node.summary(format!("{} ({region}): {title}", d.name.get(2..12).unwrap_or(&d.name)));
            saves.push(title);
            cx.emit(node);
            cx.emit(Node::new(format!("Block {slot}")).span(block).summary(format!("{} KiB save", d.size / 1024)).lazy(psx_block, block));
        } else {
            cx.emit(node.summary(lookup(PSX_ALLOC, d.state.into()).unwrap_or("unknown").to_owned()));
        }
    }
    cx.emit(Node::new("Broken sector list and unused frames").span(file.sub(0x800, 0x1800)));
    cx.annotate(format!(
        "PlayStation memory card, {used}/15 blocks used, {} save(s){}",
        saves.len(),
        saves.first().map_or_else(String::new, |s| format!(": {s:?}"))
    ));
    Ok(())
}

async fn psx_block(cx: Cx, block: Span) -> Result<()> {
    let head = cx.block(block.sub(0, 0x80)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 2).emit()?;
    let icon = f.u8("Icon display").enumeration(&[(0x11, "1 frame"), (0x12, "2 frames"), (0x13, "3 frames")]).emit()?;
    f.u8("Blocks used").emit()?;
    let span = f.peek_span(64);
    let title = f.bytes("Title (Shift-JIS)", 64).get()?;
    f.node(Node::new("Title (Shift-JIS)").span(span).value(text(sjis(&title))));
    f.bytes("Reserved", 28).emit()?;
    f.bytes("Icon palette", 32).emit()?;
    let frames = u64::from(icon & 3);
    cx.emit(Node::new("Icon frames (16×16, 4-bit)").span(block.sub(0x80, frames.saturating_mul(0x80))));
    cx.emit(Node::new("Save data").span(block.tail(0x80u64.saturating_add(frames.saturating_mul(0x80)))));
    Ok(())
}

declare_format!(pub DEXDRIVE = "dexdrive", "DexDrive memory card image", ["gme"],
    "application/x-dexdrive", Probe::Magic(&[(0, b"123-456-STD")]), dexdrive);

async fn dexdrive(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 11)).value(text("123-456-STD")));
    let comments = file.sub(0x40, 15 * 256);
    let raw = cx.read_avail(comments).await?;
    let notes: Vec<String> = raw.chunks(256).map(crate::text::until_nul).filter(|s| !s.is_empty()).collect();
    cx.emit(Node::new("Slot comments").span(comments).summary(format!("{} non-empty", notes.len())));
    let card = file.sub(0xf40, 0x20000);
    cx.emit(embedded_as("Memory card", input.nested(card), &PSX_MEMCARD));
    cx.annotate(format!("DexDrive image, {} of card data{}", size(card.len), notes.first().map_or_else(String::new, |n| format!(", note {n:?}"))));
    Ok(())
}

// ---------------------------------------------------------------------------
// PlayStation 2 memory card

declare_format!(pub PS2_MEMCARD = "ps2-memcard", "PlayStation 2 memory card image", ["ps2", "mc2", "bin"],
    "application/x-ps2-memcard", Probe::Magic(&[(0, b"Sony PS2 Memory Card Format ")]), ps2_memcard);

record! {
    pub struct Ps2Superblock {
        magic: ascii[28] "Magic",
        version: ascii[12] "Version",
        page_len: u16 "Page size",
        pages_per_cluster: u16 "Pages per cluster",
        pages_per_block: u16 "Pages per erase block",
        _unused: u16 "Unused" .hex(),
        clusters: u32 "Clusters per card",
        alloc_offset: u32 "Allocatable clusters offset",
        alloc_end: u32 "Allocatable clusters end",
        root: u32 "Root directory cluster",
        backup1: u32 "Backup block 1",
        backup2: u32 "Backup block 2",
        _padding: bytes[8] "Padding",
        ifc: bytes[128] "Indirect FAT cluster list",
        bad: bytes[128] "Bad block list",
        card_type: u8 "Card type",
        flags: u8 "Card flags" .flags(PS2_FLAGS),
    }
}

const PS2_FLAGS: FlagTable = &[flag(0x01, "ECC"), flag(0x08, "BAD_BLOCKS"), flag(0x10, "ERASE_ZEROES")];

async fn ps2_memcard(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Ps2Superblock::SIZE);
    let h: Ps2Superblock = read_record(&cx, span, LE).await?;
    cx.emit(Ps2Superblock::node("Superblock", span, LE));
    let cluster = u64::from(h.page_len).saturating_mul(h.pages_per_cluster.into());
    let total = u64::from(h.clusters).saturating_mul(cluster);
    let raw_page = if h.flags & 1 != 0 { u64::from(h.page_len).saturating_add(u64::from(h.page_len) / 32) } else { u64::from(h.page_len) };
    let ifc0 = u32_le(&h.ifc, 0).unwrap_or(0);
    cx.emit(Node::new("Indirect FAT cluster 0").span(file.sub(u64::from(ifc0).saturating_mul(raw_page).saturating_mul(h.pages_per_cluster.into()), cluster)));
    cx.annotate(format!(
        "PS2 memory card v{}, {} ({} clusters of {} bytes){}, root at cluster {}",
        clean(&h.version),
        size(total),
        h.clusters,
        cluster,
        if h.flags & 1 != 0 { ", with ECC" } else { "" },
        h.root
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameCube save (GCI)

fn gci_probe(h: &Head<'_>) -> bool {
    let id_ok = h.data.get(..6).is_some_and(|s| s.iter().all(|b| b.is_ascii_uppercase() || b.is_ascii_digit()));
    let blocks = crate::bytes::u16_be(h.data, 0x38).unwrap_or(0);
    id_ok
        && h.data.get(6) == Some(&0xff)
        && h.at(0x3a, b"\xff\xff")
        && blocks > 0
        && h.len == u64::from(blocks).saturating_mul(0x2000).saturating_add(0x40)
}

declare_format!(pub GCI = "gci", "GameCube memory card save (GCI)", ["gci", "gcs", "sav"],
    "application/x-gci", Probe::Custom(gci_probe), gci);

const GCI_PERMISSIONS: FlagTable = &[flag(0x04, "PUBLIC"), flag(0x08, "NO_COPY"), flag(0x10, "NO_MOVE")];

record! {
    pub struct GciHeader {
        game: ascii[4] "Game code",
        maker: ascii[2] "Maker code",
        _unused: u8 "Unused" .hex(),
        banner: u8 "Banner format" .hex(),
        name: ascii[32] "File name",
        modified: u32 "Modified" .with(|&v, n| n.value(Value::Timestamp { unix_seconds: 946_684_800i64.saturating_add(v.into()) })),
        image: u32 "Image data offset" .hex(),
        icon_format: u16 "Icon formats" .hex(),
        anim_speed: u16 "Animation speed" .hex(),
        permissions: u8 "Permissions" .flags(GCI_PERMISSIONS),
        copies: u8 "Copy counter",
        first_block: u16 "First block",
        blocks: u16 "Block count",
        _unused2: u16 "Unused" .hex(),
        comments: u32 "Comments offset" .hex(),
    }
}

async fn gci(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, GciHeader::SIZE);
    let h: GciHeader = read_record(&cx, span, BE).await?;
    cx.emit(GciHeader::node("Directory entry", span, BE));
    let data = file.tail(0x40);
    let comments = data.sub(h.comments.into(), 64);
    let raw = cx.read_avail(comments).await?;
    let title = crate::text::until_nul(raw.get(..32).unwrap_or_default());
    let detail = crate::text::until_nul(raw.get(32..).unwrap_or_default());
    cx.emit(Node::new("Comments").span(comments).value(text(format!("{title} / {detail}"))));
    cx.emit(Node::new("Save data").span(data).summary(format!("{} blocks", h.blocks)));
    cx.annotate(format!("GameCube save {:?} for {}{}: {title}, {} blocks", clean(&h.name), h.game, h.maker, h.blocks));
    Ok(())
}
