//! Home-computer emulator snapshots and transfer formats: Amstrad CPC SNA,
//! ZX Spectrum SNA/SZX/RZX, C64 NIB, VICE snapshots, Atari 8-bit XEX, CAS
//! and ATX, Apple II ShrinkIt (NuFX), MacBinary and BinHex 4.0.

use super::util::{clean, dec, hex, size, text};
use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::codec::crc::crc16_xmodem;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Codec, Head, Input, Probe, content, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Amstrad CPC snapshot (SNA)

declare_format!(pub CPC_SNA = "cpc-sna", "Amstrad CPC snapshot", ["sna"],
    "application/x-cpc-sna", Probe::Magic(&[(0, b"MV - SNA")]), cpc_sna);

const CPC_MODELS: EnumTable = &[
    (0, "CPC 464"),
    (1, "CPC 664"),
    (2, "CPC 6128"),
    (3, "unknown"),
    (4, "6128 Plus"),
    (5, "464 Plus"),
    (6, "GX4000"),
];

record! {
    pub struct CpcSnaHeader {
        magic: ascii[8] "Signature",
        _unused: bytes[8] "Unused",
        version: u8 "Version",
        f: u8 "F",
        a: u8 "A",
        c: u8 "C",
        b: u8 "B",
        e: u8 "E",
        d: u8 "D",
        l: u8 "L",
        h: u8 "H",
        r: u8 "R",
        i: u8 "I",
        iff0: u8 "IFF0",
        iff1: u8 "IFF1",
        ix: u16 "IX" .hex(),
        iy: u16 "IY" .hex(),
        sp: u16 "SP" .hex(),
        pc: u16 "PC" .hex(),
        im: u8 "Interrupt mode",
        af2: u16 "AF'" .hex(),
        bc2: u16 "BC'" .hex(),
        de2: u16 "DE'" .hex(),
        hl2: u16 "HL'" .hex(),
        pen: u8 "Gate Array selected pen",
        palette: bytes[17] "Gate Array palette",
        multi: u8 "Gate Array multi-configuration" .hex(),
        ram_config: u8 "RAM configuration" .hex(),
        crtc_reg: u8 "CRTC selected register",
        crtc: bytes[18] "CRTC registers",
        rom_select: u8 "ROM select",
        ppi_a: u8 "PPI port A" .hex(),
        ppi_b: u8 "PPI port B" .hex(),
        ppi_c: u8 "PPI port C" .hex(),
        ppi_control: u8 "PPI control" .hex(),
        psg_reg: u8 "PSG selected register",
        psg: bytes[16] "PSG registers",
        dump_kb: u16 "Memory dump size (KiB)",
        model: u8 "CPC type" .enumeration(CPC_MODELS),
    }
}

async fn cpc_sna(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, CpcSnaHeader::SIZE);
    let h: CpcSnaHeader = read_record(&cx, span, LE).await?;
    cx.emit(CpcSnaHeader::node("Header", file.sub(0, 0x100), LE));
    let dump = file.sub(0x100, u64::from(h.dump_kb).saturating_mul(1024));
    cx.emit(Node::new("Memory dump").span(dump).summary(size(dump.len)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(dump.end().saturating_sub(file.offset));
    let mut chunks = Vec::new();
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        cur.skip(len);
        chunks.push(id.clone());
        cx.push(
            Node::new(id)
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "CPC snapshot v{}, {}, {} RAM, PC {:#06x}{}",
        h.version,
        if h.version >= 2 {
            lookup(CPC_MODELS, h.model.into()).unwrap_or("unknown model")
        } else {
            "CPC"
        },
        size(dump.len),
        h.pc,
        if chunks.is_empty() {
            String::new()
        } else {
            format!(", chunks {}", chunks.join(" "))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ZX Spectrum SNA (identified by its exact size)

fn zx_sna_probe(h: &Head<'_>) -> bool {
    matches!(h.len, 49_179 | 131_103 | 147_487)
        && h.data.get(25).is_some_and(|&im| im <= 2)
        && h.data.get(26).is_some_and(|&b| b <= 7)
}

declare_format!(pub ZX_SNA = "zx-sna", "ZX Spectrum snapshot (SNA)", ["sna"],
    "application/x-spectrum-sna", Probe::Custom(zx_sna_probe), zx_sna);

record! {
    pub struct ZxSnaHeader {
        i: u8 "I" .hex(),
        hl2: u16 "HL'" .hex(),
        de2: u16 "DE'" .hex(),
        bc2: u16 "BC'" .hex(),
        af2: u16 "AF'" .hex(),
        hl: u16 "HL" .hex(),
        de: u16 "DE" .hex(),
        bc: u16 "BC" .hex(),
        iy: u16 "IY" .hex(),
        ix: u16 "IX" .hex(),
        iff2: u8 "Interrupt (bit 2: IFF2)" .hex(),
        r: u8 "R" .hex(),
        af: u16 "AF" .hex(),
        sp: u16 "SP" .hex(),
        im: u8 "Interrupt mode",
        border: u8 "Border colour" .enumeration(&[(0, "black"), (1, "blue"), (2, "red"), (3, "magenta"), (4, "green"), (5, "cyan"), (6, "yellow"), (7, "white")]),
    }
}

async fn zx_sna(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, ZxSnaHeader::SIZE);
    let h: ZxSnaHeader = read_record(&cx, span, LE).await?;
    cx.emit(ZxSnaHeader::node("Registers", span, LE));
    cx.emit(
        Node::new("RAM 0x4000-0xFFFF")
            .span(file.sub(27, 49152))
            .summary("screen at 0x4000"),
    );
    let wide = file.len > 49_179;
    let pc = if wide {
        let raw = cx.read(file.sub(49_179, 4)).await?;
        cx.emit(
            Node::new("128K state")
                .span(file.sub(49_179, 4))
                .summary(format!(
                    "PC {:#06x}, port 0x7FFD = {:#04x}",
                    u16_le(&raw, 0).unwrap_or(0),
                    raw.get(2).copied().unwrap_or(0)
                )),
        );
        cx.emit(Node::new("Remaining RAM banks").span(file.tail(49_183)));
        u16_le(&raw, 0).unwrap_or(0)
    } else {
        // 48K snapshots keep PC on the stack.
        let at = u64::from(h.sp).saturating_sub(0x4000).saturating_add(27);
        u16_le(&cx.read_avail(file.sub(at, 2)).await?, 0).unwrap_or(0)
    };
    cx.annotate(format!(
        "ZX Spectrum {} snapshot, PC {pc:#06x}, SP {:#06x}, IM {}",
        if wide { "128K" } else { "48K" },
        h.sp,
        h.im
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ZX-State (SZX)

declare_format!(pub SZX = "szx", "ZX-State snapshot (SZX)", ["szx", "zx-state"],
    "application/x-spectrum-szx", Probe::Magic(&[(0, b"ZXST")]), szx);

const SZX_FLAGS: FlagTable = &[flag(1, "ALTERNATE_TIMINGS")];
const SZX_MACHINES: EnumTable = &[
    (0, "ZX Spectrum 16K"),
    (1, "ZX Spectrum 48K"),
    (2, "ZX Spectrum 128K"),
    (3, "ZX Spectrum +2"),
    (4, "ZX Spectrum +2A"),
    (5, "ZX Spectrum +3"),
    (6, "ZX Spectrum +3e"),
    (7, "Pentagon 128"),
    (8, "Timex TC2048"),
    (9, "Timex TC2068"),
    (10, "Scorpion"),
    (11, "ZX Spectrum SE"),
    (12, "Timex TS2068"),
    (13, "Pentagon 512"),
    (14, "Pentagon 1024"),
    (15, "ZX Spectrum 48K (NTSC)"),
    (16, "ZX Spectrum 128Ke"),
];
const SZX_BLOCKS: &[(&str, &str)] = &[
    ("CRTR", "creator"),
    ("Z80R", "Z80 registers"),
    ("SPCR", "Spectrum registers"),
    ("RAMP", "RAM page"),
    ("KEYB", "keyboard"),
    ("JOY\0", "joystick"),
    ("AY\0\0", "AY sound chip"),
    ("B128", "Beta 128 disk interface"),
    ("BDSK", "Beta disk"),
    ("DSK\0", "+3 disk"),
    ("TAPE", "tape"),
    ("IF1\0", "Interface 1"),
    ("IF2R", "Interface 2 ROM"),
    ("MCRT", "Microdrive"),
    ("MOUS", "mouse"),
    ("MFCE", "Multiface"),
    ("PLTT", "ULAplus palette"),
    ("ROM\0", "custom ROM"),
    ("SCLD", "Timex SCLD"),
    ("SIDE", "Simple IDE"),
    ("ZXPR", "ZX Printer"),
    ("COVX", "Covox"),
    ("DIDE", "DivIDE"),
    ("DOCK", "Timex dock"),
    ("GS\0\0", "General Sound"),
    ("GSRP", "General Sound RAM page"),
    ("ATRP", "ZXATASP RAM page"),
    ("ZXAT", "ZXATASP"),
    ("ZMMC", "ZXMMC"),
    ("OPUS", "Opus Discovery"),
    ("USPE", "uSpeech"),
];

async fn szx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let machine = f.u8("Machine").enumeration(SZX_MACHINES).emit()?;
    f.u8("Flags").flags(SZX_FLAGS).emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let (mut pages, mut creator) = (0u32, String::new());
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let raw_id = cur.bytes(4).await?;
        let id = String::from_utf8_lossy(&raw_id).into_owned();
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        let meaning = SZX_BLOCKS
            .iter()
            .find(|b| b.0 == id)
            .map_or("unknown block", |b| b.1);
        let mut node = Node::new(id.trim_end_matches('\0').to_owned())
            .span(cur.since(start))
            .desc(meaning)
            .summary(format!("{len} bytes"));
        if id == "RAMP" {
            pages = pages.saturating_add(1);
            let h = cx.read_avail(data.sub(0, 3)).await?;
            let flags = u16_le(&h, 0).unwrap_or(0);
            let page = h.get(2).copied().unwrap_or(0);
            let body = data.tail(3);
            node = if flags & 1 != 0 {
                content(
                    format!("RAMP page {page}"),
                    input,
                    body,
                    Codec::Zlib,
                    Some(0x4000),
                )
                .span(cur.since(start))
                .summary("zlib-compressed 16 KiB page")
            } else {
                node.summary(format!("page {page}, uncompressed"))
            };
        } else if id == "CRTR" {
            let h = cx.read_avail(data.sub(0, 36)).await?;
            creator = crate::text::until_nul(h.get(..32).unwrap_or_default());
            node = node.value(text(creator.clone())).summary(format!(
                "v{}.{}",
                u16_le(&h, 32).unwrap_or(0),
                u16_le(&h, 34).unwrap_or(0)
            ));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "SZX v{major}.{minor} snapshot, {}, {pages} RAM pages{}",
        lookup(SZX_MACHINES, machine.into()).unwrap_or("unknown machine"),
        if creator.is_empty() {
            String::new()
        } else {
            format!(", by {creator:?}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// RZX input recording

declare_format!(pub RZX = "rzx", "ZX Spectrum input recording (RZX)", ["rzx"],
    "application/x-rzx", Probe::Magic(&[(0, b"RZX!")]), rzx);

const RZX_FLAGS: FlagTable = &[flag(1, "SIGNED")];
const RZX_BLOCKS: EnumTable = &[
    (0x10, "creator information"),
    (0x20, "security information"),
    (0x21, "security signature"),
    (0x30, "snapshot"),
    (0x80, "input recording"),
];

async fn rzx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 10)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    f.u32("Flags").flags(RZX_FLAGS).emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(10);
    let (mut frames, mut snapshots, mut creator) = (0u64, 0u32, String::new());
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let id = cur.u8().await?;
        let len = u64::from(cur.u32().await?);
        if len < 5 {
            cx.push(
                Node::new(format!("Block {id:#04x}"))
                    .span(cur.since(start))
                    .diag(Diagnostic::malformed("block shorter than its header")),
            )
            .await;
            break;
        }
        let block = file.sub(start, len);
        cur.seek(start.saturating_add(len));
        let raw = cx.read_avail(block.sub(5, 32)).await?;
        let name = lookup(RZX_BLOCKS, id.into()).map_or_else(
            || format!("Block {id:#04x}"),
            |n| {
                let mut c = n.chars();
                c.next()
                    .map(|f| f.to_uppercase().chain(c).collect())
                    .unwrap_or_default()
            },
        );
        let mut node = Node::new(name).span(block).value(hex(id.into(), 8));
        match id {
            0x10 => {
                creator = crate::text::until_nul(raw.get(..20).unwrap_or_default());
                node = node.summary(format!(
                    "{creator} {}.{}",
                    u16_le(&raw, 20).unwrap_or(0),
                    u16_le(&raw, 22).unwrap_or(0)
                ));
            }
            0x30 => {
                snapshots = snapshots.saturating_add(1);
                let flags = u32_le(&raw, 0).unwrap_or(0);
                let ext = crate::text::until_nul(raw.get(4..8).unwrap_or_default());
                let unpacked = u64::from(u32_le(&raw, 8).unwrap_or(0));
                let data = block.tail(17);
                node = if flags & 1 != 0 {
                    node.summary(format!("external {ext} file"))
                } else if flags & 2 != 0 {
                    content(
                        format!("Snapshot ({ext})"),
                        input,
                        data,
                        Codec::Zlib,
                        Some(unpacked),
                    )
                    .value(text(ext.clone()))
                    .summary(format!("{ext}, zlib, {}", size(unpacked)))
                } else {
                    embedded(format!("Snapshot ({ext})"), input.nested(data))
                        .summary(format!("{ext}, {}", size(unpacked)))
                };
            }
            0x80 => {
                let n = u64::from(u32_le(&raw, 0).unwrap_or(0));
                frames = frames.saturating_add(n);
                let flags = u32_le(&raw, 9).unwrap_or(0);
                node = node.summary(format!(
                    "{n} frames, starting at T-state {}{}",
                    u32_le(&raw, 5).unwrap_or(0),
                    if flags & 2 != 0 {
                        ", zlib-compressed"
                    } else {
                        ""
                    }
                ));
            }
            _ => node = node.summary(format!("{len} bytes")),
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "RZX v{major}.{minor} recording, {frames} frames, {snapshots} snapshot(s){}",
        if creator.is_empty() {
            String::new()
        } else {
            format!(", by {creator}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MNIB raw 1541 nibble image (NIB)

declare_format!(pub NIB = "c64-nib", "Commodore 1541 nibbler image (NIB)", ["nib"],
    "application/x-c64-nib", Probe::Magic(&[(0, b"MNIB-1541-RAW")]), nib);

async fn nib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x100)).await?;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 13))
            .value(text("MNIB-1541-RAW")),
    );
    let version = head.get(13).copied().unwrap_or(0);
    cx.emit(
        Node::new("Version")
            .span(file.sub(13, 1))
            .value(dec(version.into(), 8)),
    );
    let mut tracks = 0u64;
    for (i, pair) in head.get(0x10..).unwrap_or_default().chunks(2).enumerate() {
        let halftrack = pair.first().copied().unwrap_or(0);
        if halftrack == 0 {
            break;
        }
        let density = pair.get(1).copied().unwrap_or(0);
        let data = file.sub(
            0x100u64.saturating_add(to_u64(i).saturating_mul(0x2000)),
            0x2000,
        );
        tracks = tracks.saturating_add(1);
        cx.push(
            Node::new(format!(
                "Track {}{}",
                halftrack / 2,
                if halftrack % 2 == 1 { ".5" } else { "" }
            ))
            .span(file.sub(0x10u64.saturating_add(to_u64(i).saturating_mul(2)), 2))
            .summary(format!(
                "density {}{}",
                density & 3,
                if density & 0x80 != 0 {
                    " (killer track)"
                } else {
                    ""
                }
            ))
            .target(data),
        )
        .await;
    }
    cx.annotate(format!("MNIB nibbler image v{version}, {tracks} tracks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// VICE snapshot

declare_format!(pub VICE = "vice-snapshot", "VICE emulator snapshot", ["vsf"],
    "application/x-vice-snapshot", Probe::Magic(&[(0, b"VICE Snapshot File\x1a")]), vice);

async fn vice(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 37)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 19).emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let machine = f.ascii("Machine", 16).emit()?;
    let mut at = 37u64;
    let mut emulator = String::new();
    if cx.read_avail(file.sub(37, 13)).await? == b"VICE Version\x1a" {
        let v = cx.read(file.sub(50, 8)).await?;
        emulator = format!(
            "{}.{}.{}",
            v.first().copied().unwrap_or(0),
            v.get(1).copied().unwrap_or(0),
            v.get(2).copied().unwrap_or(0)
        );
        cx.emit(
            Node::new("VICE version")
                .span(file.sub(37, 21))
                .value(text(emulator.clone()))
                .summary(format!("SVN r{}", u32_be(&v, 4).unwrap_or(0))),
        );
        at = 58;
    }
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(at);
    let mut modules = 0u32;
    while cur.remaining() >= 22 {
        let start = cur.pos();
        let name = crate::text::until_nul(&cur.bytes(16).await?);
        let mmaj = cur.u8().await?;
        let mmin = cur.u8().await?;
        let len = u64::from(cur.u32().await?);
        if len < 22 {
            break;
        }
        cur.seek(start.saturating_add(len));
        modules = modules.saturating_add(1);
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .summary(format!("v{mmaj}.{mmin}, {len} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "VICE snapshot v{major}.{minor} of {}{}, {modules} modules",
        clean(&machine),
        if emulator.is_empty() {
            String::new()
        } else {
            format!(" (VICE {emulator})")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari 8-bit executable (XEX / COM binary load file)

fn atari_xex_probe(h: &Head<'_>) -> bool {
    let start = u16_le(h.data, 2).unwrap_or(0);
    let end = u16_le(h.data, 4).unwrap_or(0);
    h.at(0, b"\xff\xff")
        && start <= end
        && end != 0xffff
        && u64::from(end.saturating_sub(start)).saturating_add(7) <= h.len
}

declare_format!(pub ATARI_XEX = "atari-xex", "Atari 8-bit executable (XEX)", ["xex", "com", "exe", "obx"],
    "application/x-atari-xex", Probe::Custom(atari_xex_probe), atari_xex);

async fn atari_xex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut segments, mut run, mut inits, mut bytes) = (0u32, None, 0u32, 0u64);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let mut first = cur.u16().await?;
        if first == 0xffff {
            if cur.remaining() < 4 {
                break;
            }
            first = cur.u16().await?;
        }
        let last = cur.u16().await?;
        if last < first {
            cx.push(
                Node::new("Invalid segment")
                    .span(cur.since(start))
                    .diag(Diagnostic::malformed("end address before start")),
            )
            .await;
            break;
        }
        let len = u64::from(last.saturating_sub(first)).saturating_add(1);
        let data = cur.span(len);
        let raw = cx.read_avail(data.sub(0, 2)).await?;
        cur.skip(len);
        segments = segments.saturating_add(1);
        let name = match (first, last) {
            (0x2e0, 0x2e1) => {
                run = u16_le(&raw, 0);
                format!("RUNAD → ${:04x}", run.unwrap_or(0))
            }
            (0x2e2, 0x2e3) => {
                inits = inits.saturating_add(1);
                format!("INITAD → ${:04x}", u16_le(&raw, 0).unwrap_or(0))
            }
            _ => {
                bytes = bytes.saturating_add(len);
                format!("${first:04x}-${last:04x}")
            }
        };
        cx.push(
            Node::new(format!("Segment {segments}"))
                .span(cur.since(start))
                .value(hex(first.into(), 16))
                .summary(name)
                .target(data),
        )
        .await;
    }
    cx.annotate(format!(
        "Atari 8-bit executable, {segments} segments, {bytes} bytes loaded{}{}",
        run.map_or_else(String::new, |r| format!(", runs at ${r:04x}")),
        if inits > 0 {
            format!(", {inits} init call(s)")
        } else {
            String::new()
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari 8-bit cassette (CAS)

declare_format!(pub ATARI_CAS = "atari-cas", "Atari 8-bit cassette image (CAS)", ["cas"],
    "application/x-atari-cas", Probe::Magic(&[(0, b"FUJI")]), atari_cas);

async fn atari_cas(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut records, mut data_bytes, mut description, mut baud) =
        (0u32, 0u64, String::new(), 600u16);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let kind = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u16().await?);
        let aux = cur.u16().await?;
        let data = cur.span(len);
        cur.skip(len);
        let summary = match kind.as_str() {
            "FUJI" => {
                description =
                    String::from_utf8_lossy(&cx.read_avail(data.sub(0, 256)).await?).into_owned();
                description.clone()
            }
            "baud" => {
                baud = aux;
                format!("{aux} baud")
            }
            "data" => {
                records = records.saturating_add(1);
                data_bytes = data_bytes.saturating_add(len);
                format!("{len} bytes after {aux} ms gap")
            }
            _ => format!("{len} bytes, aux {aux}"),
        };
        cx.push(
            Node::new(kind)
                .span(cur.since(start))
                .summary(summary)
                .target(data),
        )
        .await;
    }
    cx.annotate(format!(
        "Atari cassette{}, {records} records ({data_bytes} bytes) at {baud} baud",
        if description.is_empty() {
            String::new()
        } else {
            format!(" {:?}", description.trim())
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari 8-bit ATX (VAPI) disk image

declare_format!(pub ATX = "atx", "Atari 8-bit protected disk image (ATX)", ["atx"],
    "application/x-atari-atx", Probe::Magic(&[(0, b"AT8X")]), atx);

record! {
    pub struct AtxHeader {
        magic: ascii[4] "Signature",
        version: u16 "Version",
        min_version: u16 "Minimum version",
        creator: u16 "Creator" .hex(),
        creator_version: u16 "Creator version",
        flags: u32 "Flags" .hex(),
        image_type: u16 "Image type",
        density: u8 "Density" .enumeration(&[(0, "single"), (1, "medium (enhanced)"), (2, "double")]),
        _reserved: u8 "Reserved",
        image_id: u32 "Image ID" .hex(),
        image_version: u16 "Image version",
        _reserved2: u16 "Reserved",
        start: u32 "Start of track data" .hex(),
        end: u32 "End of track data" .hex(),
        _reserved3: bytes[12] "Reserved",
    }
}

async fn atx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, AtxHeader::SIZE);
    let h: AtxHeader = read_record(&cx, span, LE).await?;
    cx.emit(AtxHeader::node("Header", span, LE));
    let mut cur = Cursor::new(&cx, file.sub(0, u64::from(h.end).max(AtxHeader::SIZE)), LE);
    cur.seek(h.start.into());
    let (mut tracks, mut sectors) = (0u32, 0u64);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let len = u64::from(cur.u32().await?);
        let kind = cur.u16().await?;
        if len < 8 {
            break;
        }
        cur.seek(start.saturating_add(len));
        let raw = cx.read_avail(file.sub(start.saturating_add(8), 8)).await?;
        let node = if kind == 0 {
            tracks = tracks.saturating_add(1);
            let n = u16_le(&raw, 2).unwrap_or(0);
            sectors = sectors.saturating_add(n.into());
            Node::new(format!("Track {}", raw.first().copied().unwrap_or(0))).summary(format!(
                "{n} sectors, rate {}",
                u16_le(&raw, 4).unwrap_or(0)
            ))
        } else {
            Node::new(format!("Record type {kind}")).summary(format!("{len} bytes"))
        };
        cx.push(node.span(cur.since(start))).await;
    }
    cx.annotate(format!(
        "ATX v{} image, {} density, {tracks} tracks, {sectors} sectors",
        h.version,
        ["single", "medium", "double"]
            .get(usize::from(h.density))
            .copied()
            .unwrap_or("unknown")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ShrinkIt (NuFX) archive

const NUFILE: &[u8] = b"\x4e\xf5\x46\xe9\x6c\xe5";
const NUFX: &[u8] = b"\x4e\xf5\x46\xd8";

declare_format!(pub NUFX_ARCHIVE = "nufx", "ShrinkIt archive (NuFX)", ["shk", "sdk", "bxy", "sea"],
    "application/x-nufx", Probe::Magic(&[(0, NUFILE)]), nufx);

const NUFX_FORMATS: EnumTable = &[
    (0, "uncompressed"),
    (1, "Huffman squeeze"),
    (2, "LZW/1"),
    (3, "LZW/2"),
    (4, "LZC-12"),
    (5, "LZC-16"),
];
const NUFX_CLASSES: EnumTable = &[(0, "message"), (1, "control"), (2, "data"), (3, "filename")];

fn prodos_date(raw: &[u8]) -> String {
    // second, minute, hour, year (since 1900), day, month, filler, weekday
    let g = |i: usize| raw.get(i).copied().unwrap_or(0);
    format!(
        "{}-{:02}-{:02} {:02}:{:02}:{:02}",
        1900u32.saturating_add(g(3).into()),
        g(5).saturating_add(1),
        g(4).saturating_add(1),
        g(2),
        g(1),
        g(0)
    )
}

async fn nufx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 48)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature (NuFile)", 6).emit()?;
    f.u16("Master CRC").hex().emit()?;
    let total = f.u32("Total records").emit()?;
    let created = f
        .bytes("Created", 8)
        .with(|v, n| n.summary(prodos_date(v)))
        .emit()?;
    f.bytes("Modified", 8)
        .with(|v, n| n.summary(prodos_date(v)))
        .emit()?;
    f.u16("Master version").emit()?;
    f.bytes("Reserved", 8).emit()?;
    f.u32("Master EOF").emit()?;
    let mut at = 48u64;
    let mut names = Vec::new();
    for _ in 0..total.min(65_536) {
        let raw = cx.read_avail(file.sub(at, 64)).await?;
        if raw.get(..4) != Some(NUFX) {
            cx.diag(Diagnostic::malformed(format!(
                "expected a record at {at:#x}"
            )));
            break;
        }
        let attribs = u64::from(u16_le(&raw, 6).unwrap_or(0));
        let threads = u64::from(u32_le(&raw, 10).unwrap_or(0));
        let file_type = u32_le(&raw, 22).unwrap_or(0);
        let aux = u32_le(&raw, 26).unwrap_or(0);
        let name_len = u64::from(
            u16_le(
                &cx.read(file.sub(at.saturating_add(attribs).saturating_sub(2), 2))
                    .await?,
                0,
            )
            .unwrap_or(0),
        );
        let mut name = String::from_utf8_lossy(
            &cx.read_avail(file.sub(at.saturating_add(attribs), name_len))
                .await?,
        )
        .into_owned();
        let threads_at = at.saturating_add(attribs).saturating_add(name_len);
        let table = file.sub(threads_at, threads.min(64).saturating_mul(16));
        let traw = cx.read(table).await?;
        let mut data_at = table.end().saturating_sub(file.offset);
        let mut parts = Vec::new();
        for t in traw.chunks(16) {
            let class = u16_le(t, 0).unwrap_or(0);
            let format = u16_le(t, 2).unwrap_or(0);
            let kind = u16_le(t, 4).unwrap_or(0);
            let eof = u64::from(u32_le(t, 8).unwrap_or(0));
            let comp = u64::from(u32_le(t, 12).unwrap_or(0));
            let span = file.sub(data_at, comp);
            if class == 3 && name.is_empty() {
                name = crate::text::until_nul(
                    &cx.read_avail(span.sub(0, eof.min(comp).min(1024))).await?,
                );
            }
            parts.push((class, format, kind, eof, span));
            data_at = data_at.saturating_add(comp);
        }
        let record = file.sub(at, data_at.saturating_sub(at));
        names.push(name.clone());
        cx.push(
            Node::new(name.clone())
                .span(record)
                .value(hex(file_type.into(), 8))
                .summary(format!(
                    "type ${file_type:02x}/${aux:04x}, {} thread(s)",
                    parts.len()
                ))
                .lazy(nufx_threads, (input, parts)),
        )
        .await;
        at = data_at;
    }
    cx.annotate(format!(
        "ShrinkIt archive, {total} record(s), created {}{}",
        prodos_date(&created),
        if names.is_empty() {
            String::new()
        } else {
            format!(": {}", names.join(", "))
        }
    ));
    Ok(())
}

/// `(class, format, kind, uncompressed length, stored span)` per thread.
type NufxThreads = Vec<(u16, u16, u16, u64, Span)>;

async fn nufx_threads(cx: Cx, (input, parts): (Input, NufxThreads)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(parts.len())));
    for (class, format, kind, eof, span) in parts {
        let label = match (class, kind) {
            (2, 0) => "Data fork",
            (2, 1) => "Disk image",
            (2, 2) => "Resource fork",
            (3, _) => "Filename",
            (0, _) => "Comment",
            _ => lookup(NUFX_CLASSES, class.into()).unwrap_or("thread"),
        };
        let fmt = lookup(NUFX_FORMATS, format.into()).unwrap_or("unknown format");
        let node = if format == 0 && class == 2 {
            let span = Span {
                len: eof.min(span.len),
                ..span
            };
            embedded(label, input.nested(span))
        } else {
            let n = Node::new(label).span(span);
            if format == 0 {
                n
            } else {
                n.diag(Diagnostic::unsupported(format!("{fmt} compression")))
            }
        };
        cx.push(node.summary(format!("{fmt}, {eof} bytes"))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MacBinary (I, II, III)

fn macbinary_probe(h: &Head<'_>) -> bool {
    let Some(header) = h.data.get(..128) else {
        return false;
    };
    let name_len = header.get(1).copied().unwrap_or(0);
    let data = u64::from(u32_be(header, 83).unwrap_or(u32::MAX));
    let rsrc = u64::from(u32_be(header, 87).unwrap_or(u32::MAX));
    let crc_ok = u16_be(header, 124) == Some(crc16_xmodem(header.get(..124).unwrap_or_default()));
    header.first() == Some(&0)
        && header.get(74) == Some(&0)
        && header.get(82) == Some(&0)
        && (1..=63).contains(&name_len)
        && (crc_ok || h.at(102, b"mBIN"))
        && 128u64
            .saturating_add(data.next_multiple_of(128))
            .saturating_add(rsrc)
            <= h.len.saturating_add(128)
        && data.saturating_add(rsrc) > 0
}

declare_format!(pub MACBINARY = "macbinary", "MacBinary encoded Mac file", ["bin", "macbin"],
    "application/x-macbinary", Probe::Custom(macbinary_probe), macbinary);

const FINDER_FLAGS: FlagTable = &[
    flag(0x80, "IS_ALIAS"),
    flag(0x40, "IS_INVISIBLE"),
    flag(0x20, "HAS_BUNDLE"),
    flag(0x10, "NAME_LOCKED"),
    flag(0x08, "IS_STATIONERY"),
    flag(0x04, "HAS_CUSTOM_ICON"),
    flag(0x01, "HAS_BEEN_INITED"),
];

async fn macbinary(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 128)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Old version").emit()?;
    let name_len = f.u8("Name length").emit()?;
    let name = f
        .ascii("File name", 63)
        .map(|s| s.chars().take(usize::from(name_len)).collect::<String>())
        .emit()?;
    let kind = f.ascii("File type", 4).emit()?;
    let creator = f.ascii("Creator", 4).emit()?;
    f.u8("Finder flags (high)").flags(FINDER_FLAGS).emit()?;
    f.u8("Zero").emit()?;
    f.u16("Vertical position").emit()?;
    f.u16("Horizontal position").emit()?;
    f.u16("Window/folder ID").emit()?;
    f.u8("Protected").emit()?;
    f.u8("Zero").emit()?;
    let data_len = f.u32("Data fork length").emit()?;
    let rsrc_len = f.u32("Resource fork length").emit()?;
    f.u32("Created").mac_time().emit()?;
    f.u32("Modified").mac_time().emit()?;
    f.u16("Get Info comment length").emit()?;
    f.u8("Finder flags (low)").hex().emit()?;
    let sig = f.ascii("Signature (MacBinary III)", 4).emit()?;
    f.u8("Script").emit()?;
    f.u8("Extended Finder flags").hex().emit()?;
    f.bytes("Reserved", 8).emit()?;
    f.u32("Total unpacked length").emit()?;
    let secondary = f.u16("Secondary header length").emit()?;
    let version = f
        .u8("Version")
        .enumeration(&[(129, "MacBinary II"), (130, "MacBinary III")])
        .emit()?;
    f.u8("Minimum version").emit()?;
    let crc = f.u16("Header CRC").hex().emit()?;
    let computed = crc16_xmodem(head.data.get(..124).unwrap_or_default());
    if version >= 129 && computed != crc {
        cx.diag(Diagnostic::warning(format!(
            "header CRC mismatch: computed {computed:#06x}"
        )));
    }
    let mut at = 128u64.saturating_add(u64::from(secondary).next_multiple_of(128));
    if data_len > 0 {
        cx.emit(
            embedded("Data fork", input.nested(file.sub(at, data_len.into())))
                .summary(size(data_len.into())),
        );
        at = at.saturating_add(u64::from(data_len).next_multiple_of(128));
    }
    if rsrc_len > 0 {
        cx.emit(
            embedded_as(
                "Resource fork",
                input.nested(file.sub(at, rsrc_len.into())),
                &crate::formats::system::platform::MAC_RESOURCE,
            )
            .summary(size(rsrc_len.into())),
        );
    }
    let flavour = if sig == "mBIN" {
        "III"
    } else if version >= 129 {
        "II"
    } else {
        "I"
    };
    cx.annotate(format!(
        "MacBinary {flavour} {name:?} ({kind}/{creator}), data {}, resource {}",
        size(data_len.into()),
        size(rsrc_len.into())
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// BinHex 4.0

const BINHEX_BANNER: &[u8] = b"(This file must be converted with BinHex";
const BINHEX_ALPHABET: &[u8] = b"!\"#$%&'()*+,-012345689@ABCDEFGHIJKLMNPQRSTUVXYZ[`abcdefhijklmpqr";

fn binhex_probe(h: &Head<'_>) -> bool {
    h.data
        .get(..h.data.len().min(4096))
        .is_some_and(|d| d.windows(BINHEX_BANNER.len()).any(|w| w == BINHEX_BANNER))
}

declare_format!(pub BINHEX = "binhex", "BinHex 4.0 encoded Mac file", ["hqx"],
    "application/mac-binhex40", Probe::Custom(binhex_probe), binhex);

/// Decodes the 6-bit text and the 0x90 run-length encoding (in budgeted
/// steps: the input can be as large as a read).
async fn binhex_decode(cx: &Cx, encoded: &[u8], limit: usize) -> (Vec<u8>, Option<Diagnostic>) {
    let mut bits = Vec::new();
    let (mut acc, mut n) = (0u32, 0u32);
    for (i, &c) in encoded.iter().enumerate() {
        if i & 0xffff == 0xffff {
            cx.checkpoint().await;
        }
        if c == b':' {
            break;
        }
        let Some(v) = BINHEX_ALPHABET.iter().position(|&a| a == c) else {
            continue;
        };
        acc = (acc << 6 | u32::try_from(v).unwrap_or(0)) & 0x00ff_ffff;
        n = n.saturating_add(6);
        if n >= 8 {
            n = n.saturating_sub(8);
            bits.push(u8::try_from(acc >> n & 0xff).unwrap_or(0));
        }
    }
    let mut out: Vec<u8> = Vec::with_capacity(bits.len());
    let mut it = bits.iter().copied();
    let mut steps = 0u32;
    while let Some(b) = it.next() {
        steps = steps.wrapping_add(1);
        if steps & 0xffff == 0 {
            cx.checkpoint().await;
        }
        if b == 0x90 {
            match it.next() {
                Some(0) => out.push(0x90),
                Some(count) => {
                    let last = out.last().copied().unwrap_or(0);
                    for _ in 1..count {
                        out.push(last);
                    }
                }
                None => break,
            }
        } else {
            out.push(b);
        }
        if out.len() > limit {
            return (
                out,
                Some(Diagnostic::limit("decoded BinHex data too large")),
            );
        }
    }
    (out, None)
}

async fn binhex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let max = cx.limits().max_read;
    let raw = cx.read(file.sub(0, file.len.min(max))).await?;
    let banner_at = raw
        .windows(BINHEX_BANNER.len())
        .position(|w| w == BINHEX_BANNER)
        .unwrap_or(0);
    let banner_end = raw
        .get(banner_at..)
        .and_then(|r| r.iter().position(|&b| b == b')'))
        .map_or(banner_at, |p| banner_at.saturating_add(p).saturating_add(1));
    cx.emit(
        Node::new("Banner")
            .span(file.sub(
                to_u64(banner_at),
                to_u64(banner_end.saturating_sub(banner_at)),
            ))
            .value(text(
                String::from_utf8_lossy(raw.get(banner_at..banner_end).unwrap_or_default())
                    .into_owned(),
            )),
    );
    let start = raw
        .get(banner_end..)
        .and_then(|r| r.iter().position(|&b| b == b':'))
        .map(|p| banner_end.saturating_add(p).saturating_add(1))
        .ok_or_else(|| Diagnostic::malformed("no ':' starting the encoded data"))?;
    let end = raw
        .get(start..)
        .and_then(|r| r.iter().position(|&b| b == b':'))
        .map_or(raw.len(), |p| start.saturating_add(p));
    let encoded = file.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    let (decoded, error) = binhex_decode(
        &cx,
        raw.get(start..end).unwrap_or_default(),
        usize::try_from(cx.limits().max_derived / 4).unwrap_or(usize::MAX),
    )
    .await;
    let derived = cx.add_derived(
        Origin {
            parent: encoded,
            transform: "binhex",
        },
        decoded.clone(),
        encoded.len,
        error,
    )?;
    let body = derived.span;
    cx.emit(Node::new("Encoded data").span(encoded).summary(format!(
        "{} → {}",
        size(encoded.len),
        size(body.len)
    )));
    let name_len = u64::from(decoded.first().copied().unwrap_or(0));
    let hlen = name_len.saturating_add(22);
    let hspan = body.sub(0, hlen);
    let head = cx.block(hspan).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Name length").emit()?;
    let name = f.ascii("File name", name_len).emit()?;
    f.u8("Version").emit()?;
    let kind = f.ascii("File type", 4).emit()?;
    let creator = f.ascii("Creator", 4).emit()?;
    f.u16("Finder flags").hex().emit()?;
    let data_len = u64::from(f.u32("Data fork length").emit()?);
    let rsrc_len = u64::from(f.u32("Resource fork length").emit()?);
    let stored = f.u16("Header CRC").hex().emit()?;
    let mut status = Vec::new();
    // BinHex CRC: CRC-16/XMODEM over the section followed by two zero bytes.
    let check = |data: &[u8], stored: u16| {
        let mut v = data.to_vec();
        v.extend_from_slice(&[0, 0]);
        crc16_xmodem(&v) == stored
    };
    if !check(
        decoded
            .get(..usize::try_from(hlen.saturating_sub(2)).unwrap_or(0))
            .unwrap_or_default(),
        stored,
    ) {
        status.push("header CRC mismatch");
    }
    let data = body.sub(hlen, data_len);
    cx.emit(embedded("Data fork", input.nested(data)).summary(size(data_len)));
    let rsrc_at = hlen.saturating_add(data_len).saturating_add(2);
    if rsrc_len > 0 {
        cx.emit(
            embedded_as(
                "Resource fork",
                input.nested(body.sub(rsrc_at, rsrc_len)),
                &crate::formats::system::platform::MAC_RESOURCE,
            )
            .summary(size(rsrc_len)),
        );
    }
    let crc_at = |at: u64| u16_be(&decoded, usize::try_from(at).unwrap_or(usize::MAX));
    let section = |from: u64, len: u64| {
        decoded
            .get(
                usize::try_from(from).unwrap_or(0)
                    ..usize::try_from(from.saturating_add(len)).unwrap_or(0),
            )
            .unwrap_or_default()
    };
    if crc_at(hlen.saturating_add(data_len)).is_some_and(|c| !check(section(hlen, data_len), c)) {
        status.push("data CRC mismatch");
    }
    if crc_at(rsrc_at.saturating_add(rsrc_len))
        .is_some_and(|c| !check(section(rsrc_at, rsrc_len), c))
    {
        status.push("resource CRC mismatch");
    }
    for s in &status {
        cx.diag(Diagnostic::warning(*s));
    }
    cx.annotate(format!(
        "BinHex 4.0 {name:?} ({kind}/{creator}), data {}, resource {}{}",
        size(data_len),
        size(rsrc_len),
        if status.is_empty() {
            ", CRCs valid".to_owned()
        } else {
            format!(", {}", status.join(", "))
        }
    ));
    Ok(())
}
