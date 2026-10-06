//! Home-computer tapes, cartridges and program files: ZX Spectrum TAP, PZX,
//! CSW, C64 TAP, G64, PC64 P00, SCL, TR-DOS, MSX CAS, Oric TAP, Atari CAR
//! and Atari ST executables.

use super::util::{dec, hex, size, text};
use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// ZX Spectrum TAP

const ZX_TYPES: EnumTable = &[
    (0, "Program"),
    (1, "Number array"),
    (2, "Character array"),
    (3, "Bytes"),
];

fn zx_tap_probe(h: &Head<'_>) -> bool {
    // The first block is almost always a 17-byte header: length 19, flag 0.
    let Some(block) = h.data.get(2..21) else {
        return false;
    };
    let xor = block.iter().take(18).fold(0u8, |x, &b| x ^ b);
    u16_le(h.data, 0) == Some(19)
        && block.first() == Some(&0)
        && block.get(1).is_some_and(|&t| t <= 3)
        && block.get(18) == Some(&xor)
}

declare_format!(pub ZX_TAP = "zx-tap", "ZX Spectrum tape image (TAP)", ["tap"],
    "application/x-spectrum-tap", Probe::Custom(zx_tap_probe), zx_tap);

async fn zx_tap(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut blocks, mut names) = (0u32, Vec::new());
    while cur.remaining() >= 2 {
        let start = cur.pos();
        let len = u64::from(cur.u16().await?);
        let data = cur.span(len);
        cur.skip(len);
        blocks = blocks.saturating_add(1);
        let raw = cx.read_avail(data.sub(0, 0x10000)).await?;
        let flag = raw.first().copied().unwrap_or(0);
        let xor = raw
            .iter()
            .take(raw.len().saturating_sub(1))
            .fold(0u8, |x, &b| x ^ b);
        let stored = raw.last().copied().unwrap_or(0);
        let mut node = if flag == 0 && len == 19 {
            let kind = raw.get(1).copied().unwrap_or(0);
            let name = String::from_utf8_lossy(raw.get(2..12).unwrap_or_default())
                .trim_end()
                .to_owned();
            let length = u16_le(&raw, 12).unwrap_or(0);
            let p1 = u16_le(&raw, 14).unwrap_or(0);
            let detail = match kind {
                0 if p1 < 0x8000 => format!(", autostart line {p1}"),
                3 => format!(", load at {p1}"),
                _ => String::new(),
            };
            names.push(name.clone());
            Node::new(format!(
                "Header: {}",
                lookup(ZX_TYPES, kind.into()).unwrap_or("?")
            ))
            .value(text(name))
            .summary(format!("{length} bytes{detail}"))
            .lazy(zx_header, data)
        } else {
            Node::new(if flag == 0xff { "Data block" } else { "Block" })
                .summary(format!("flag {flag:#04x}, {} bytes", len.saturating_sub(2)))
        };
        node = node.span(cur.since(start));
        if len > 0 && to_u64(raw.len()) == len && xor != stored {
            node = node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {xor:#04x}"
            )));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "ZX Spectrum tape, {blocks} blocks{}",
        if names.is_empty() {
            String::new()
        } else {
            format!(": {}", names.join(", "))
        }
    ));
    Ok(())
}

async fn zx_header(cx: Cx, data: Span) -> Result<()> {
    let block = cx.block(data).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Flag").hex().emit()?;
    f.u8("Type").enumeration(ZX_TYPES).emit()?;
    f.ascii("File name", 10).emit()?;
    f.u16("Data length").emit()?;
    f.u16("Parameter 1").emit()?;
    f.u16("Parameter 2").emit()?;
    f.u8("Checksum").hex().emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// PZX (Perfect ZX tape)

declare_format!(pub PZX = "pzx", "PZX tape image (ZX Spectrum)", ["pzx"],
    "application/x-pzx", Probe::Magic(&[(0, b"PZXT")]), pzx);

const PZX_BLOCKS: &[(&str, &str)] = &[
    ("PZXT", "header"),
    ("PULS", "pulse sequence"),
    ("DATA", "data block"),
    ("PAUS", "pause"),
    ("BRWS", "browse point"),
    ("STOP", "stop tape"),
];

async fn pzx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut blocks, mut version, mut title) = (0u32, String::new(), String::new());
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let tag = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        blocks = blocks.saturating_add(1);
        let meaning = PZX_BLOCKS
            .iter()
            .find(|b| b.0 == tag)
            .map_or("unknown block", |b| b.1);
        let raw = cx.read_avail(data.sub(0, 4096)).await?;
        let summary = match tag.as_str() {
            "PZXT" => {
                version = format!(
                    "{}.{}",
                    raw.first().copied().unwrap_or(0),
                    raw.get(1).copied().unwrap_or(0)
                );
                let strings: Vec<String> = raw
                    .get(2..)
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                title = strings.first().cloned().unwrap_or_default();
                format!("v{version}, {}", strings.join(" / "))
            }
            "DATA" => {
                let bits = u32_le(&raw, 0).unwrap_or(0) & 0x7fff_ffff;
                format!(
                    "{bits} bits, tail {} T-states",
                    u16_le(&raw, 4).unwrap_or(0)
                )
            }
            "PAUS" => format!("{} T-states", u32_le(&raw, 0).unwrap_or(0) & 0x7fff_ffff),
            "BRWS" => String::from_utf8_lossy(&raw).into_owned(),
            _ => format!("{len} bytes"),
        };
        cx.push(
            Node::new(tag)
                .span(cur.since(start))
                .desc(meaning)
                .summary(summary)
                .target(data),
        )
        .await;
    }
    cx.annotate(format!(
        "PZX tape v{version}{}, {blocks} blocks",
        if title.is_empty() {
            String::new()
        } else {
            format!(" {title:?}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// CSW (compressed square wave)

declare_format!(pub CSW = "csw", "Compressed Square Wave tape image", ["csw"],
    "application/x-csw", Probe::Magic(&[(0, b"Compressed Square Wave\x1a")]), csw);

const CSW_FLAGS: FlagTable = &[flag(1, "INITIAL_HIGH")];
const CSW_COMPRESSION: EnumTable = &[(1, "RLE"), (2, "Z-RLE (zlib)")];

async fn csw(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x34)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 22).emit()?;
    f.u8("Terminator").hex().emit()?;
    let major = f.u8("Major version").emit()?;
    let minor = f.u8("Minor version").emit()?;
    let (rate, compression, pulses, data_at) = if major >= 2 {
        let rate = f.u32("Sample rate").emit()?;
        let pulses = f.u32("Total pulses").emit()?;
        let c = f.u8("Compression").enumeration(CSW_COMPRESSION).emit()?;
        f.u8("Flags").flags(CSW_FLAGS).emit()?;
        let ext = f.u8("Header extension length").emit()?;
        f.ascii("Encoding application", 16).emit()?;
        (rate, c, Some(pulses), 0x34u64.saturating_add(ext.into()))
    } else {
        let rate = u32::from(f.u16("Sample rate").emit()?);
        let c = f.u8("Compression").enumeration(CSW_COMPRESSION).emit()?;
        f.u8("Flags").flags(CSW_FLAGS).emit()?;
        f.bytes("Reserved", 3).emit()?;
        (rate, c, None, 0x20u64)
    };
    let data = file.tail(data_at);
    let node = Node::new("Pulse data").span(data).summary(size(data.len));
    cx.emit(if compression == 2 {
        crate::formats::content(
            "Pulse data (Z-RLE)",
            input,
            data,
            crate::formats::Codec::Zlib,
            None,
        )
    } else {
        node
    });
    cx.annotate(format!(
        "CSW v{major}.{minor} tape, {rate} Hz, {}{}",
        lookup(CSW_COMPRESSION, compression.into()).unwrap_or("unknown compression"),
        pulses.map_or_else(String::new, |p| format!(", {p} pulses"))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// C64 TAP (raw pulse lengths)

declare_format!(pub C64_TAP = "c64-tap", "Commodore tape image (TAP)", ["tap"],
    "application/x-c64-tap", Probe::Magic(&[(0, b"C64-TAPE-RAW"), (0, b"C16-TAPE-RAW")]), c64_tap);

const C64_PLATFORMS: EnumTable = &[(0, "C64"), (1, "VIC-20"), (2, "C16/Plus4")];
const C64_VIDEO: EnumTable = &[(0, "PAL"), (1, "NTSC"), (2, "old NTSC"), (3, "PAL-N")];

record! {
    pub struct C64TapHeader {
        magic: ascii[12] "Signature",
        version: u8 "Version" .desc("0: overflow pulses stored as 0; 1: as 0 + 24-bit length"),
        platform: u8 "Platform" .enumeration(C64_PLATFORMS),
        video: u8 "Video standard" .enumeration(C64_VIDEO),
        _reserved: u8 "Reserved",
        size: u32 "Data size",
    }
}

async fn c64_tap(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: C64TapHeader = emit_record(&cx, file.sub(0, C64TapHeader::SIZE), LE).await?;
    let data = file.sub(C64TapHeader::SIZE, h.size.into());
    let mut summary = size(data.len);
    if data.len <= cx.limits().max_read {
        let raw = cx.read_avail(data).await?;
        // Pulse length in cycles is 8 × byte; long pulses use a 0 escape.
        let (mut i, mut pulses, mut cycles) = (0usize, 0u64, 0u64);
        while let Some(&b) = raw.get(i) {
            if b == 0 && h.version >= 1 {
                cycles = cycles.saturating_add(u64::from(
                    crate::bytes::u24_le(&raw, i.saturating_add(1)).unwrap_or(0),
                ));
                i = i.saturating_add(4);
            } else {
                cycles = cycles.saturating_add(u64::from(b).saturating_mul(8));
                i = i.saturating_add(1);
            }
            pulses = pulses.saturating_add(1);
        }
        let secs = cycles / 985_248;
        summary = format!("{pulses} pulses, ~{}:{:02}", secs / 60, secs % 60);
    }
    cx.emit(Node::new("Pulses").span(data).summary(summary.clone()));
    cx.annotate(format!(
        "{} tape v{}, {}, {summary}",
        lookup(C64_PLATFORMS, h.platform.into()).unwrap_or("Commodore"),
        h.version,
        lookup(C64_VIDEO, h.video.into()).unwrap_or("unknown video")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// G64 (1541 GCR disk image)

declare_format!(pub G64 = "g64", "Commodore 1541 GCR disk image (G64)", ["g64", "g71"],
    "application/x-g64", Probe::Magic(&[(0, b"GCR-1541"), (0, b"GCR-1571")]), g64);

async fn g64(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let magic = f.ascii("Signature", 8).emit()?;
    f.u8("Version").emit()?;
    let tracks = f.u8("Track entries (half tracks)").emit()?;
    let max = f.u16("Maximum track size").emit()?;
    let offsets = file.sub_exact(12, u64::from(tracks).saturating_mul(4))?;
    let speeds = file.sub(
        offsets.end().saturating_sub(file.offset),
        u64::from(tracks).saturating_mul(4),
    );
    let raw = cx.read(offsets).await?;
    let used = raw.chunks(4).filter(|c| c.iter().any(|&b| b != 0)).count();
    cx.emit(Node::new("Speed zones").span(speeds));
    cx.emit(
        Node::new("Tracks")
            .span(offsets)
            .summary(format!("{used} of {tracks} half-tracks present"))
            .lazy(g64_tracks, (file, offsets, speeds)),
    );
    cx.annotate(format!("{magic} image, {used} tracks present of {tracks} half-track slots, max {max} bytes per track"));
    Ok(())
}

async fn g64_tracks(cx: Cx, (file, offsets, speeds): (Span, Span, Span)) -> Result<()> {
    let raw = cx.read(offsets).await?;
    let zones = cx.read_avail(speeds).await?;
    for (i, chunk) in raw.chunks(4).enumerate() {
        let at = u64::from(u32_le(chunk, 0).unwrap_or(0));
        if at == 0 {
            continue;
        }
        let len = u64::from(u16_le(&cx.read(file.sub(at, 2)).await?, 0).unwrap_or(0));
        let zone = u32_le(&zones, i.saturating_mul(4)).unwrap_or(0);
        let track = i.saturating_add(2);
        cx.push(
            Node::new(format!(
                "Track {}{}",
                track / 2,
                if track % 2 == 1 { ".5" } else { "" }
            ))
            .span(file.sub(at, len.saturating_add(2)))
            .value(dec(len, 16))
            .summary(format!("{len} GCR bytes, speed zone {zone}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PC64 emulator files (P00, S00, U00, R00)

declare_format!(pub P00 = "p00", "PC64 emulator file (P00)", ["p00", "s00", "u00", "r00"],
    "application/x-c64-p00", Probe::Magic(&[(0, b"C64File\0")]), p00);

async fn p00(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 28)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 8).emit()?;
    let name = f.ascii("Original file name (PETSCII)", 16).emit()?;
    f.u8("Reserved").emit()?;
    f.u8("REL record size").emit()?;
    let load = f.u16("Load address").hex().emit()?;
    cx.emit(
        Node::new("Program")
            .span(file.tail(28))
            .summary(size(file.len.saturating_sub(28))),
    );
    cx.annotate(format!(
        "PC64 file {name:?}, load at ${load:04x}, {}",
        size(file.len.saturating_sub(28))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SCL and TR-DOS (Beta Disk) images

declare_format!(pub SCL = "scl", "Sinclair SCL archive (TR-DOS)", ["scl"],
    "application/x-scl", Probe::Magic(&[(0, b"SINCLAIR")]), scl);

const TRDOS_TYPES: &[(u8, &str)] = &[
    (b'B', "BASIC"),
    (b'C', "code"),
    (b'D', "data array"),
    (b'#', "sequential"),
];

fn trdos_entry(raw: &[u8]) -> (String, String) {
    let name = String::from_utf8_lossy(raw.get(..8).unwrap_or_default())
        .trim_end()
        .to_owned();
    let ext = raw.get(8).copied().unwrap_or(b'?');
    let kind = TRDOS_TYPES
        .iter()
        .find(|t| t.0 == ext)
        .map_or("unknown", |t| t.1);
    let start = u16_le(raw, 9).unwrap_or(0);
    let len = u16_le(raw, 11).unwrap_or(0);
    let detail = if ext == b'C' {
        format!("{kind}, {len} bytes at {start}")
    } else {
        format!("{kind}, {len} bytes")
    };
    (format!("{name}.{}", char::from(ext)), detail)
}

async fn scl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 9)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 8).emit()?;
    let count = f.u8("Files").emit()?;
    let dir = file.sub_exact(9, u64::from(count).saturating_mul(14))?;
    let raw = cx.read(dir).await?;
    let mut at = dir.end().saturating_sub(file.offset);
    let mut names = Vec::new();
    for (i, entry) in raw.chunks(14).enumerate() {
        let (name, detail) = trdos_entry(entry);
        let sectors = u64::from(entry.get(13).copied().unwrap_or(0));
        let data = file.sub(at, sectors.saturating_mul(256));
        at = at.saturating_add(sectors.saturating_mul(256));
        names.push(name.clone());
        cx.push(
            Node::new(name)
                .span(dir.sub(to_u64(i).saturating_mul(14), 14))
                .summary(format!("{detail}, {sectors} sectors"))
                .target(data),
        )
        .await;
    }
    let sum_span = file.sub(at, 4);
    let stored = u32_le(&cx.read_avail(sum_span).await?, 0);
    if let Some(stored) = stored
        && at <= cx.limits().max_read
    {
        let all = cx.read(file.sub(0, at)).await?;
        let sum = all.iter().fold(0u32, |s, &b| s.wrapping_add(b.into()));
        let node = Node::new("Checksum")
            .span(sum_span)
            .value(hex(stored.into(), 32));
        cx.emit(if sum == stored {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {sum:#010x}"
            )))
        });
    }
    cx.annotate(format!(
        "SCL archive, {count} file(s): {}",
        names.join(", ")
    ));
    Ok(())
}

fn trd_probe(h: &Head<'_>) -> bool {
    h.data.get(0x8e7) == Some(&0x10)
        && h.data.get(0x8e3).is_some_and(|t| (0x16..=0x19).contains(t))
        && h.len.is_multiple_of(4096)
        && h.len <= 0xa0000
}

declare_format!(pub TRD = "trd", "TR-DOS disk image", ["trd"],
    "application/x-trd", Probe::Custom(trd_probe), trd);

const TRD_DISK_TYPES: EnumTable = &[
    (0x16, "80 tracks, double-sided"),
    (0x17, "40 tracks, double-sided"),
    (0x18, "80 tracks, single-sided"),
    (0x19, "40 tracks, single-sided"),
];

async fn trd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let info = cx.block(file.sub(0x8e1, 0x20)).await?;
    let mut f = Fields::emitting(&cx, &info, LE);
    f.u8("First free sector").emit()?;
    f.u8("First free track").emit()?;
    let kind = f.u8("Disk type").enumeration(TRD_DISK_TYPES).emit()?;
    let files = f.u8("Files").emit()?;
    let free = f.u16("Free sectors").emit()?;
    f.u8("TR-DOS ID").hex().emit()?;
    f.bytes("Reserved", 12).emit()?;
    let label = cx.read_avail(file.sub(0x8f5, 8)).await?;
    let label = String::from_utf8_lossy(&label).trim_end().to_owned();
    cx.emit(
        Node::new("Disk label")
            .span(file.sub(0x8f5, 8))
            .value(text(label.clone())),
    );
    let catalogue = file.sub(0, 0x800);
    cx.emit(
        Node::new("Catalogue")
            .span(catalogue)
            .summary(format!("{files} file(s)"))
            .lazy(trd_catalogue, (file, catalogue)),
    );
    cx.annotate(format!(
        "TR-DOS disk {label:?}, {}, {files} file(s), {free} free sectors",
        lookup(TRD_DISK_TYPES, kind.into()).unwrap_or("unknown geometry")
    ));
    Ok(())
}

async fn trd_catalogue(cx: Cx, (file, catalogue): (Span, Span)) -> Result<()> {
    let raw = cx.read(catalogue).await?;
    for (i, entry) in raw.chunks(16).enumerate() {
        match entry.first() {
            Some(0) | None => break,
            Some(1) => continue,
            Some(_) => {}
        }
        let (name, detail) = trdos_entry(entry);
        let sectors = u64::from(entry.get(13).copied().unwrap_or(0));
        let sector = u64::from(entry.get(14).copied().unwrap_or(0));
        let track = u64::from(entry.get(15).copied().unwrap_or(0));
        let data = file.sub(
            track
                .saturating_mul(16)
                .saturating_add(sector)
                .saturating_mul(256),
            sectors.saturating_mul(256),
        );
        cx.push(
            Node::new(name)
                .span(catalogue.sub(to_u64(i).saturating_mul(16), 16))
                .summary(format!("{detail}, track {track} sector {sector}"))
                .target(data),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MSX cassette (CAS)

const CAS_SYNC: &[u8] = b"\x1f\xa6\xde\xba\xcc\x13\x7d\x74";

declare_format!(pub MSX_CAS = "msx-cas", "MSX cassette image (CAS)", ["cas"],
    "application/x-msx-cas", Probe::Magic(&[(0, CAS_SYNC)]), msx_cas);

const CAS_TYPES: &[(u8, &str)] = &[(0xd0, "binary"), (0xd3, "tokenised BASIC"), (0xea, "ASCII")];

async fn msx_cas(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // Blocks start at 8-byte-aligned sync markers.
    let mut starts = Vec::new();
    let mut pos = 0u64;
    while pos < file.len && starts.len() < 10_000 {
        let chunk = cx.read_avail(file.sub(pos, 8)).await?;
        if chunk == CAS_SYNC {
            starts.push(pos);
        }
        pos = pos.saturating_add(8);
    }
    let mut files = Vec::new();
    for (i, &start) in starts.iter().enumerate() {
        let end = starts.get(i.saturating_add(1)).copied().unwrap_or(file.len);
        let span = file.sub(start, end.saturating_sub(start));
        let raw = cx.read_avail(span.sub(8, 16)).await?;
        let kind = raw.first().copied().unwrap_or(0);
        let header = raw.len() == 16
            && raw.iter().take(10).all(|&b| b == kind)
            && CAS_TYPES.iter().any(|t| t.0 == kind);
        let node = if header {
            let name = String::from_utf8_lossy(raw.get(10..16).unwrap_or_default())
                .trim_end()
                .to_owned();
            let label = CAS_TYPES.iter().find(|t| t.0 == kind).map_or("?", |t| t.1);
            files.push(format!("{name} ({label})"));
            Node::new(format!("Header: {name}"))
                .summary(label.to_owned())
                .value(text(name))
        } else {
            Node::new("Data block").summary(size(span.len.saturating_sub(8)))
        };
        cx.push(node.span(span)).await;
    }
    cx.annotate(format!(
        "MSX cassette, {} blocks, {} file(s){}",
        starts.len(),
        files.len(),
        if files.is_empty() {
            String::new()
        } else {
            format!(": {}", files.join(", "))
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Oric tape (TAP)

fn oric_probe(h: &Head<'_>) -> bool {
    let sync = h.data.iter().take_while(|&&b| b == 0x16).count();
    sync >= 3 && h.data.get(sync) == Some(&0x24)
}

declare_format!(pub ORIC_TAP = "oric-tap", "Oric tape image", ["tap"],
    "application/x-oric-tap", Probe::Custom(oric_probe), oric_tap);

async fn oric_tap(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 512)).await?;
    let sync = head.iter().take_while(|&&b| b == 0x16).count();
    cx.emit(
        Node::new("Synchronisation")
            .span(file.sub(0, to_u64(sync).saturating_add(1)))
            .summary(format!("{sync} × 0x16, then 0x24")),
    );
    let at = to_u64(sync).saturating_add(1);
    let block = cx.block(file.sub(at, 9)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Reserved").emit()?;
    let kind = f
        .u8("Type")
        .enumeration(&[(0x00, "BASIC"), (0x80, "machine code"), (0x40, "array")])
        .emit()?;
    let auto = f.u8("Autorun").emit()?;
    let end = f.u16("End address").hex().emit()?;
    let start = f.u16("Start address").hex().emit()?;
    f.u8("Reserved").emit()?;
    let (name, name_span) = cx.cstr(file.sub(at.saturating_add(9), 17)).await?;
    cx.emit(
        Node::new("File name")
            .span(name_span)
            .value(text(name.clone())),
    );
    let data_at = name_span.end().saturating_sub(file.offset);
    let len = u64::from(end.saturating_sub(start)).saturating_add(1);
    cx.emit(Node::new("Data").span(file.sub(data_at, len)));
    if data_at.saturating_add(len) < file.len {
        cx.emit(Node::new("Further files").span(file.tail(data_at.saturating_add(len))));
    }
    cx.annotate(format!(
        "Oric tape {name:?}, {} ${start:04x}-${end:04x}{}",
        if kind == 0 { "BASIC" } else { "code" },
        if auto != 0 { ", autorun" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari 8-bit cartridge (CAR)

declare_format!(pub ATARI_CAR = "atari-car", "Atari 8-bit cartridge image (CAR)", ["car"],
    "application/x-atari-car", Probe::Magic(&[(0, b"CART")]), atari_car);

const CAR_TYPES: EnumTable = &[
    (1, "Standard 8 KiB"),
    (2, "Standard 16 KiB"),
    (3, "OSS two-chip 16 KiB (034M)"),
    (4, "Standard 32 KiB (5200)"),
    (5, "DB 32 KiB"),
    (6, "5200 two-chip 16 KiB"),
    (7, "Bounty Bob 40 KiB (5200)"),
    (8, "Williams 64 KiB"),
    (9, "Express 64 KiB"),
    (10, "Diamond 64 KiB"),
    (11, "SpartaDOS X 64 KiB"),
    (12, "XEGS 32 KiB"),
    (13, "XEGS 64 KiB"),
    (14, "XEGS 128 KiB"),
    (15, "OSS one-chip 16 KiB"),
    (16, "5200 one-chip 16 KiB"),
    (17, "Atrax 128 KiB"),
    (18, "Bounty Bob 40 KiB"),
    (19, "Standard 8 KiB (5200)"),
    (20, "Standard 4 KiB (5200)"),
    (21, "Right slot 8 KiB"),
    (22, "Williams 32 KiB"),
    (23, "XEGS 256 KiB"),
];

record! {
    pub struct CarHeader {
        magic: ascii[4] "Signature",
        kind: u32 "Cartridge type" .enumeration(CAR_TYPES),
        checksum: u32 "Checksum" .hex(),
        _unused: u32 "Unused",
    }
}

async fn atari_car(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, CarHeader::SIZE);
    let h: CarHeader = read_record(&cx, span, BE).await?;
    let data = file.tail(CarHeader::SIZE);
    let mut node = CarHeader::node("Header", span, BE);
    let mut status = "";
    if data.len <= cx.limits().max_read {
        let raw = cx.read(data).await?;
        let sum = raw.iter().fold(0u32, |s, &b| s.wrapping_add(b.into()));
        if sum == h.checksum {
            status = ", checksum valid";
        } else {
            status = ", checksum mismatch";
            node = node.diag(Diagnostic::warning(format!(
                "checksum mismatch: computed {sum:#010x}"
            )));
        }
    }
    cx.emit(node);
    cx.emit(Node::new("ROM").span(data).summary(size(data.len)));
    cx.annotate(format!(
        "Atari cartridge, {}{status}",
        lookup(CAR_TYPES, h.kind.into()).map_or_else(|| format!("type {}", h.kind), str::to_owned)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Atari ST / TOS executable (PRG, TOS, TTP, APP, ACC)

fn st_prg_probe(h: &Head<'_>) -> bool {
    let sizes: Option<u64> = [2usize, 6, 14]
        .iter()
        .map(|&o| u32_be(h.data, o).map(u64::from))
        .sum();
    h.at(0, b"\x60\x1a")
        && sizes.is_some_and(|s| s.saturating_add(28) <= h.len && s > 0)
        && u16_be(h.data, 26).is_some_and(|a| a <= 1)
        && u32_be(h.data, 18).is_some_and(|r| r == 0 || r < 0x1000_0000)
}

declare_format!(pub ATARI_ST_PRG = "atari-st-prg", "Atari ST executable (GEMDOS)", ["prg", "tos", "ttp", "app", "acc", "gtp"],
    "application/x-atari-st-prg", Probe::Custom(st_prg_probe), st_prg);

const ST_FLAGS: FlagTable = &[
    flag(0x01, "FASTLOAD"),
    flag(0x02, "TTRAMLOAD"),
    flag(0x04, "TTRAMMEM"),
    flag(0x08, "MINIMUM"),
    flag(0x1000, "SHAREDTEXT"),
];

record! {
    pub struct StHeader {
        magic: u16 "Magic" .hex(),
        text: u32 "Text size",
        data: u32 "Data size",
        bss: u32 "BSS size",
        symbols: u32 "Symbol table size",
        _reserved: u32 "Reserved",
        flags: u32 "Program flags" .flags(ST_FLAGS),
        absolute: u16 "Absolute flag" .enumeration(&[(0, "relocatable"), (1, "absolute")]),
    }
}

async fn st_prg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, StHeader::SIZE);
    let h: StHeader = read_record(&cx, span, BE).await?;
    cx.emit(StHeader::node("Header", span, BE));
    let mut at = StHeader::SIZE;
    for (name, len) in [
        ("TEXT", h.text),
        ("DATA", h.data),
        ("Symbol table", h.symbols),
    ] {
        if len > 0 {
            cx.emit(
                Node::new(name)
                    .span(file.sub(at, len.into()))
                    .summary(size(len.into())),
            );
        }
        at = at.saturating_add(len.into());
    }
    let mut fixups = 0u64;
    if h.absolute == 0 && at < file.len {
        let reloc = file.tail(at);
        let raw = cx.read_avail(reloc.sub(0, 0x10000)).await?;
        if u32_be(&raw, 0).is_some_and(|v| v != 0) {
            fixups = 1u64.saturating_add(to_u64(
                raw.iter()
                    .skip(4)
                    .take_while(|&&b| b != 0)
                    .filter(|&&b| b != 1)
                    .count(),
            ));
        }
        cx.emit(
            Node::new("Relocation table")
                .span(reloc)
                .summary(format!("{fixups} fixups")),
        );
    }
    cx.annotate(format!(
        "Atari ST executable, text {}, data {}, bss {}{}",
        size(h.text.into()),
        size(h.data.into()),
        size(h.bss.into()),
        if h.absolute == 0 {
            format!(", {fixups} relocations")
        } else {
            ", absolute".to_owned()
        }
    ));
    Ok(())
}
