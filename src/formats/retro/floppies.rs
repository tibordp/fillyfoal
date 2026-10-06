//! Floppy, flux and hard-disk images from preservation tools and emulators:
//! HFE, SuperCard Pro, IPF (CAPS/SPS), Pasti STX, ImageDisk, Teledisk,
//! DiskCopy 4.2, Applesauce A2R and MOOF, D88 and Amiga RDB.

use super::util::{dec, hex, size, text};
use crate::bytes::{to_u64, u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn fourcc(raw: &[u8]) -> String {
    raw.iter()
        .map(|&b| {
            if b.is_ascii_graphic() || b == b' ' {
                char::from(b)
            } else {
                '.'
            }
        })
        .collect()
}

// ---------------------------------------------------------------------------
// HxC Floppy Emulator (HFE)

declare_format!(pub HFE = "hfe", "HxC floppy emulator image (HFE)", ["hfe"],
    "application/x-hfe", Probe::Magic(&[(0, b"HXCPICFE"), (0, b"HXCHFEV3")]), hfe);

const HFE_ENCODINGS: EnumTable = &[
    (0, "ISO/IBM MFM"),
    (1, "Amiga MFM"),
    (2, "ISO/IBM FM"),
    (3, "EMU FM"),
    (0xff, "unknown"),
];
const HFE_INTERFACES: EnumTable = &[
    (0, "IBM PC DD"),
    (1, "IBM PC HD"),
    (2, "Atari ST DD"),
    (3, "Atari ST HD"),
    (4, "Amiga DD"),
    (5, "Amiga HD"),
    (6, "Amstrad CPC DD"),
    (7, "generic Shugart DD"),
    (8, "IBM PC ED"),
    (9, "MSX2 DD"),
    (10, "C64 DD"),
    (11, "EMU Shugart"),
    (12, "Akai S950 DD"),
    (13, "Akai S950 HD"),
    (0xfe, "disabled"),
];

record! {
    pub struct HfeHeader {
        signature: ascii[8] "Signature",
        revision: u8 "Format revision",
        tracks: u8 "Tracks",
        sides: u8 "Sides",
        encoding: u8 "Track encoding" .enumeration(HFE_ENCODINGS),
        bitrate: u16 "Bit rate (kbit/s)",
        rpm: u16 "RPM",
        interface: u8 "Interface mode" .enumeration(HFE_INTERFACES),
        _dnu: u8 "Unused",
        track_list: u16 "Track list offset (512-byte blocks)",
        write_allowed: u8 "Write allowed" .enumeration(&[(0x00, "no"), (0xff, "yes")]),
        single_step: u8 "Single step" .enumeration(&[(0x00, "double step"), (0xff, "single step")]),
        t0s0_alt: u8 "Track 0 side 0 alternate encoding" .hex(),
        t0s0_enc: u8 "Track 0 side 0 encoding" .enumeration(HFE_ENCODINGS),
        t0s1_alt: u8 "Track 0 side 1 alternate encoding" .hex(),
        t0s1_enc: u8 "Track 0 side 1 encoding" .enumeration(HFE_ENCODINGS),
    }
}

async fn hfe(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, HfeHeader::SIZE);
    let h: HfeHeader = read_record(&cx, span, LE).await?;
    cx.emit(HfeHeader::node("Header", span, LE));
    let list = file.sub_exact(
        u64::from(h.track_list).saturating_mul(512),
        u64::from(h.tracks).saturating_mul(4),
    )?;
    cx.emit(
        Node::new("Track list")
            .span(list)
            .summary(format!("{} tracks", h.tracks))
            .lazy(hfe_tracks, (file, list)),
    );
    cx.annotate(format!(
        "HFE {} image, {} tracks × {} sides, {}, {} kbit/s, {} RPM, {}",
        if h.signature == "HXCHFEV3" {
            "v3"
        } else {
            "v1"
        },
        h.tracks,
        h.sides,
        lookup(HFE_ENCODINGS, h.encoding.into()).unwrap_or("unknown encoding"),
        h.bitrate,
        h.rpm,
        lookup(HFE_INTERFACES, h.interface.into()).unwrap_or("unknown interface")
    ));
    Ok(())
}

async fn hfe_tracks(cx: Cx, (file, list): (Span, Span)) -> Result<()> {
    let raw = cx.read(list).await?;
    cx.set_count(Count::Exact(to_u64(raw.len() / 4)));
    for (i, entry) in raw.chunks(4).enumerate() {
        let offset = u64::from(u16_le(entry, 0).unwrap_or(0)).saturating_mul(512);
        let len = u64::from(u16_le(entry, 2).unwrap_or(0));
        // Sides are interleaved in 256-byte halves of each 512-byte block.
        cx.push(
            Node::new(format!("Track {i}"))
                .span(list.sub(to_u64(i).saturating_mul(4), 4))
                .value(hex(offset, 32))
                .summary(format!(
                    "{len} bytes (both sides interleaved per 256 bytes)"
                ))
                .target(file.sub(offset, len)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// SuperCard Pro flux image (SCP)

fn scp_probe(h: &Head<'_>) -> bool {
    h.at(0, b"SCP")
        && h.data
            .get(6)
            .zip(h.data.get(7))
            .is_some_and(|(s, e)| s <= e && *e < 168)
}

declare_format!(pub SCP = "scp", "SuperCard Pro flux image", ["scp"],
    "application/x-scp", Probe::Custom(scp_probe), scp);

const SCP_DISKS: EnumTable = &[
    (0x00, "Commodore 64"),
    (0x04, "Amiga"),
    (0x08, "Amiga HD"),
    (0x10, "Atari 8-bit FM SS"),
    (0x11, "Atari 8-bit FM DS"),
    (0x12, "Atari 8-bit FM ES"),
    (0x14, "Atari ST SS"),
    (0x15, "Atari ST DS"),
    (0x20, "Apple II"),
    (0x21, "Apple II Pro"),
    (0x24, "Apple 400K"),
    (0x25, "Apple 800K"),
    (0x26, "Apple 1.44 MB"),
    (0x30, "PC 360K"),
    (0x31, "PC 720K"),
    (0x32, "PC 1.2 MB"),
    (0x33, "PC 1.44 MB"),
    (0x40, "TRS-80 SSSD"),
    (0x41, "TRS-80 SSDD"),
    (0x42, "TRS-80 DSSD"),
    (0x43, "TRS-80 DSDD"),
    (0x50, "TI-99/4A"),
    (0x60, "Roland D-20"),
    (0x70, "Amstrad CPC"),
    (0x80, "other 360K"),
    (0x81, "other 1.2 MB"),
    (0x84, "other 720K"),
    (0x85, "other 1.44 MB"),
];
const SCP_FLAGS: FlagTable = &[
    flag(0x01, "INDEX"),
    flag(0x02, "TPI_96"),
    flag(0x04, "RPM_360"),
    flag(0x08, "NORMALISED"),
    flag(0x10, "READ_WRITE"),
    flag(0x20, "FOOTER"),
    flag(0x40, "EXTENDED"),
    flag(0x80, "NON_SCP_CAPTURE"),
];

record! {
    pub struct ScpHeader {
        magic: ascii[3] "Signature",
        version: u8 "Version" .with(|&v, n| n.summary(format!("{}.{}", v >> 4, v & 0xf))),
        disk: u8 "Disk type" .enumeration(SCP_DISKS),
        revolutions: u8 "Revolutions",
        start: u8 "Start track",
        end: u8 "End track",
        flags: u8 "Flags" .flags(SCP_FLAGS),
        cell: u8 "Bit cell width" .desc("0 means 16 bits"),
        heads: u8 "Heads" .enumeration(&[(0, "both"), (1, "side 0"), (2, "side 1")]),
        resolution: u8 "Resolution" .with(|&v, n| n.summary(format!("{} ns", u32::from(v).saturating_add(1).saturating_mul(25)))),
        checksum: u32 "Checksum" .hex(),
    }
}

async fn scp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, ScpHeader::SIZE);
    let h: ScpHeader = read_record(&cx, span, LE).await?;
    let mut node = ScpHeader::node("Header", span, LE);
    let mut status = "";
    if h.flags & 0x10 == 0 && file.len <= cx.limits().max_read {
        let all = cx.read(file.tail(0x10)).await?;
        let sum = all.iter().fold(0u32, |s, &b| s.wrapping_add(b.into()));
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
    let table = file.sub(0x10, 168 * 4);
    let raw = cx.read_avail(table).await?;
    let present = raw
        .chunks(4)
        .filter(|c| u32_le(c, 0).is_some_and(|v| v != 0))
        .count();
    cx.emit(
        Node::new("Tracks")
            .span(table)
            .summary(format!("{present} tracks captured"))
            .lazy(scp_tracks, (file, table, h.revolutions)),
    );
    cx.annotate(format!(
        "SuperCard Pro flux image, {}, tracks {}-{}, {} revolution(s){status}",
        lookup(SCP_DISKS, h.disk.into()).unwrap_or("unknown disk"),
        h.start,
        h.end,
        h.revolutions
    ));
    Ok(())
}

async fn scp_tracks(cx: Cx, (file, table, revolutions): (Span, Span, u8)) -> Result<()> {
    let raw = cx.read_avail(table).await?;
    for (i, entry) in raw.chunks(4).enumerate() {
        let at = u64::from(u32_le(entry, 0).unwrap_or(0));
        if at == 0 {
            continue;
        }
        let head = file.sub(
            at,
            4u64.saturating_add(u64::from(revolutions).saturating_mul(12)),
        );
        cx.push(
            Node::new(format!("Track {i}"))
                .span(head)
                .value(hex(at, 32))
                .lazy(scp_track, (file, head, revolutions)),
        )
        .await;
    }
    Ok(())
}

async fn scp_track(cx: Cx, (file, head, revolutions): (Span, Span, u8)) -> Result<()> {
    let block = cx.block(head).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 3).emit()?;
    f.u8("Track number").emit()?;
    for r in 0..revolutions {
        let time = f.u32("Index time (25 ns units)").emit()?;
        let flux = f.u32("Flux transitions").emit()?;
        let offset = f.u32("Data offset").hex().emit()?;
        let rpm = if time > 0 {
            60.0 / (f64::from(time) * 25e-9)
        } else {
            0.0
        };
        cx.emit(
            Node::new(format!("Revolution {r}"))
                .span(
                    file.sub(
                        head.offset
                            .saturating_sub(file.offset)
                            .saturating_add(offset.into()),
                        u64::from(flux).saturating_mul(2),
                    ),
                )
                .summary(format!("{flux} flux transitions, {rpm:.1} RPM")),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// IPF (Interchangeable Preservation Format, CAPS/SPS)

declare_format!(pub IPF = "ipf", "Interchangeable Preservation Format (IPF)", ["ipf"],
    "application/x-ipf", Probe::Magic(&[(0, b"CAPS\0\0\0\x0c")]), ipf);

const IPF_PLATFORMS: EnumTable = &[
    (1, "Amiga"),
    (2, "Atari ST"),
    (3, "PC"),
    (4, "Amstrad CPC"),
    (5, "ZX Spectrum"),
    (6, "SAM Coupé"),
    (7, "Archimedes"),
    (8, "C64"),
    (9, "Atari 8-bit"),
];

record! {
    pub struct IpfInfo {
        kind: ascii[4] "Type",
        length: u32 "Length",
        crc: u32 "CRC-32" .hex(),
        media: u32 "Media type" .enumeration(&[(1, "floppy disk")]),
        encoder: u32 "Encoder" .enumeration(&[(1, "CAPS"), (2, "SPS")]),
        encoder_rev: u32 "Encoder revision",
        file_key: u32 "Release",
        file_rev: u32 "Revision",
        origin: u32 "Origin CRC" .hex(),
        min_track: u32 "First track",
        max_track: u32 "Last track",
        min_side: u32 "First side",
        max_side: u32 "Last side",
        date: u32 "Creation date (YYYYMMDD)",
        time: u32 "Creation time (HHMMSSmmm)",
        platform1: u32 "Platform 1" .enumeration(IPF_PLATFORMS),
        platform2: u32 "Platform 2" .enumeration(IPF_PLATFORMS),
        platform3: u32 "Platform 3" .enumeration(IPF_PLATFORMS),
        platform4: u32 "Platform 4" .enumeration(IPF_PLATFORMS),
        disk: u32 "Disk number",
        creator: u32 "Creator ID" .hex(),
        _reserved: bytes[12] "Reserved",
    }
}

async fn ipf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (mut records, mut tracks, mut bad) = (0u32, 0u32, 0u32);
    let mut info: Option<IpfInfo> = None;
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let kind = fourcc(&cur.bytes(4).await?);
        let len = u64::from(cur.u32().await?);
        let stored = cur.u32().await?;
        if len < 12 {
            cx.push(
                Node::new(kind)
                    .span(cur.since(start))
                    .diag(Diagnostic::malformed("record shorter than its header")),
            )
            .await;
            break;
        }
        let span = file.sub(start, len);
        cur.seek(start.saturating_add(len));
        let mut raw = cx.read_avail(span).await?;
        if let Some(c) = raw.get_mut(8..12) {
            c.fill(0);
        }
        let computed = crate::codec::crc32(&raw);
        let mut extra = None;
        if kind == "DATA" {
            let size = u64::from(u32_be(&raw, 12).unwrap_or(0));
            extra = Some(cur.span(size));
            cur.skip(size);
        }
        records = records.saturating_add(1);
        let mut node = Node::new(kind.clone()).span(cur.since(start));
        node = match kind.as_str() {
            "INFO" => {
                let i: IpfInfo = read_record(&cx, span.sub(0, IpfInfo::SIZE), BE).await?;
                let summary = format!(
                    "tracks {}-{}, sides {}-{}, {}",
                    i.min_track,
                    i.max_track,
                    i.min_side,
                    i.max_side,
                    lookup(IPF_PLATFORMS, i.platform1.into()).unwrap_or("unknown platform")
                );
                info = Some(i);
                IpfInfo::node("INFO", span.sub(0, IpfInfo::SIZE), BE)
                    .span(cur.since(start))
                    .summary(summary)
            }
            "IMGE" => {
                tracks = tracks.saturating_add(1);
                node.summary(format!(
                    "track {} side {}, {} data bits",
                    u32_be(&raw, 12).unwrap_or(0),
                    u32_be(&raw, 16).unwrap_or(0),
                    u32_be(&raw, 40).unwrap_or(0)
                ))
            }
            "DATA" => node.summary(format!(
                "key {}, {} bytes of block data",
                u32_be(&raw, 24).unwrap_or(0),
                extra.map_or(0, |e| e.len)
            )),
            _ => node.summary(format!("{len} bytes")),
        };
        if computed != stored {
            bad = bad.saturating_add(1);
            node = node.diag(Diagnostic::warning(format!(
                "record CRC mismatch: computed {computed:#010x}"
            )));
        }
        cx.push(node.value(hex(stored.into(), 32))).await;
    }
    let what = info.map_or_else(String::new, |i| {
        format!(
            ", {} release {} rev {}, {} disk {}",
            if i.encoder == 2 { "SPS" } else { "CAPS" },
            i.file_key,
            i.file_rev,
            lookup(IPF_PLATFORMS, i.platform1.into()).unwrap_or("unknown platform"),
            i.disk
        )
    });
    cx.annotate(format!(
        "IPF image{what}, {tracks} track descriptors, {records} records{}",
        if bad > 0 {
            format!(", {bad} bad CRCs")
        } else {
            String::new()
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Pasti (STX, Atari ST)

declare_format!(pub STX = "stx", "Pasti Atari ST disk image (STX)", ["stx"],
    "application/x-stx", Probe::Magic(&[(0, b"RSY\0")]), stx);

const STX_TRACK_FLAGS: FlagTable = &[
    flag(0x01, "SECTOR_DESCRIPTORS"),
    flag(0x20, "PROTECTED"),
    flag(0x40, "TRACK_IMAGE"),
    flag(0x80, "TRACK_IMAGE_SYNC"),
];

async fn stx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").emit()?;
    f.u16("Tool")
        .enumeration(&[(0x01, "Pasti (Atari)"), (0xcc, "Aufit")])
        .emit()?;
    f.u16("Reserved").emit()?;
    let count = f.u8("Tracks").emit()?;
    f.u8("Revision").emit()?;
    f.u32("Reserved").emit()?;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(16);
    let (mut sectors, mut fuzzy) = (0u64, 0u64);
    for _ in 0..count {
        if cur.remaining() < 16 {
            break;
        }
        let start = cur.pos();
        let len = u64::from(cur.u32().await?);
        let fz = cur.u32().await?;
        let n = cur.u16().await?;
        let flags = cur.u16().await?;
        let mfm = cur.u16().await?;
        let number = cur.u8().await?;
        let kind = cur.u8().await?;
        cur.seek(start.saturating_add(len.max(16)));
        sectors = sectors.saturating_add(n.into());
        fuzzy = fuzzy.saturating_add(fz.into());
        let (set, unknown) = crate::value::decode_flags(STX_TRACK_FLAGS, flags.into());
        cx.push(
            Node::new(format!("Track {} side {}", number & 0x7f, number >> 7))
                .span(cur.since(start))
                .value(Value::Flags {
                    raw: flags.into(),
                    bits: 16,
                    set,
                    unknown,
                })
                .summary(format!(
                    "{n} sectors, {mfm} MFM bytes, type {kind}{}",
                    if fz > 0 {
                        format!(", {fz} fuzzy bytes")
                    } else {
                        String::new()
                    }
                )),
        )
        .await;
    }
    cx.annotate(format!(
        "Pasti STX v{version}, {count} tracks, {sectors} sectors{}",
        if fuzzy > 0 {
            format!(", {fuzzy} fuzzy bytes (copy protection)")
        } else {
            String::new()
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// ImageDisk (IMD)

fn imd_probe(h: &Head<'_>) -> bool {
    h.at(0, b"IMD ")
        && h.data.get(4).is_some_and(u8::is_ascii_digit)
        && h.data.iter().take(4096).any(|&b| b == 0x1a)
}

declare_format!(pub IMD = "imd", "ImageDisk floppy image (IMD)", ["imd"],
    "application/x-imd", Probe::Custom(imd_probe), imd);

const IMD_MODES: EnumTable = &[
    (0, "500 kbps FM"),
    (1, "300 kbps FM"),
    (2, "250 kbps FM"),
    (3, "500 kbps MFM"),
    (4, "300 kbps MFM"),
    (5, "250 kbps MFM"),
];

async fn imd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 4096)).await?;
    let end = head
        .iter()
        .position(|&b| b == 0x1a)
        .ok_or_else(|| Diagnostic::malformed("comment not terminated"))?;
    let text_part = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let (banner, comment) = text_part.split_once('\n').unwrap_or((&text_part, ""));
    cx.emit(
        Node::new("Banner")
            .span(file.sub(0, to_u64(banner.len())))
            .value(text(banner.trim_end().to_owned())),
    );
    cx.emit(
        Node::new("Comment")
            .span(file.sub(
                to_u64(banner.len()).saturating_add(1),
                to_u64(comment.len()),
            ))
            .value(text(comment.trim_end().to_owned())),
    );
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(to_u64(end).saturating_add(1));
    let (mut tracks, mut total, mut compressed, mut errors) = (0u32, 0u64, 0u64, 0u64);
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let h = cur.bytes(5).await?;
        let [mode, cyl, head_byte, count, code] =
            [0usize, 1, 2, 3, 4].map(|i| h.get(i).copied().unwrap_or(0));
        let n = u64::from(count);
        cur.skip(n);
        if head_byte & 0x80 != 0 {
            cur.skip(n);
        }
        if head_byte & 0x40 != 0 {
            cur.skip(n);
        }
        let sizes: Vec<u64> = if code == 0xff {
            let raw = cur.bytes(n.saturating_mul(2)).await?;
            raw.chunks(2)
                .map(|c| u64::from(u16_le(c, 0).unwrap_or(0)))
                .collect()
        } else {
            vec![128u64.checked_shl(code.into()).unwrap_or(0); usize::from(count)]
        };
        for &s in &sizes {
            let kind = cur.u8().await?;
            match kind {
                0 => {}
                1 | 3 | 5 | 7 => cur.skip(s),
                2 | 4 | 6 | 8 => {
                    cur.skip(1);
                    compressed = compressed.saturating_add(1);
                }
                _ => {
                    return Err(
                        Diagnostic::malformed(format!("unknown sector record type {kind}"))
                            .at(cur.span(1)),
                    );
                }
            }
            if matches!(kind, 5..=8) {
                errors = errors.saturating_add(1);
            }
        }
        tracks = tracks.saturating_add(1);
        total = total.saturating_add(n);
        let bytes = sizes.first().copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Cylinder {cyl} head {}", head_byte & 1))
                .span(cur.since(start))
                .value(Value::Enum {
                    raw: mode.into(),
                    bits: 8,
                    name: lookup(IMD_MODES, mode.into()),
                })
                .summary(format!("{count} sectors of {bytes} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "ImageDisk {}, {tracks} tracks, {total} sectors ({compressed} compressed, {errors} with errors)",
        banner.trim_start_matches("IMD ").trim_end()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Teledisk (TD0)

fn td0_crc(data: &[u8]) -> u16 {
    let mut crc = 0u16;
    for &b in data {
        crc ^= u16::from(b) << 8;
        for _ in 0..8 {
            crc = if crc & 0x8000 != 0 {
                crc << 1 ^ 0xa097
            } else {
                crc << 1
            };
        }
    }
    crc
}

fn td0_probe(h: &Head<'_>) -> bool {
    (h.at(0, b"TD\0") || h.at(0, b"td\0"))
        && h.data
            .get(..10)
            .is_some_and(|d| Some(td0_crc(d)) == u16_le(h.data, 10))
}

declare_format!(pub TD0 = "td0", "Teledisk floppy image (TD0)", ["td0"],
    "application/x-teledisk", Probe::Custom(td0_probe), td0);

const TD0_STEPPING: FlagTable = &[flag(0x80, "COMMENT")];
const TD0_RATES: EnumTable = &[
    (0, "250 kbps MFM"),
    (1, "300 kbps MFM"),
    (2, "500 kbps MFM"),
    (0x80, "250 kbps FM"),
    (0x81, "300 kbps FM"),
    (0x82, "500 kbps FM"),
];
const TD0_DRIVES: EnumTable = &[
    (1, "360K 5.25\""),
    (2, "1.2M 5.25\""),
    (3, "720K 3.5\""),
    (4, "1.44M 3.5\""),
    (5, "8\""),
    (6, "3.5\""),
];

async fn td0(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.ascii("Signature", 2).emit()?;
    f.u8("Volume sequence").emit()?;
    f.u8("Check signature").hex().emit()?;
    let version = f.u8("Version").emit()?;
    let rate = f.u8("Data rate").enumeration(TD0_RATES).emit()?;
    let drive = f.u8("Drive type").enumeration(TD0_DRIVES).emit()?;
    let stepping = f.u8("Stepping").flags(TD0_STEPPING).emit()?;
    f.u8("DOS allocation only").emit()?;
    let sides = f.u8("Sides").emit()?;
    f.u16("Header CRC").hex().emit()?;
    let advanced = sig == "td";
    let mut at = 12u64;
    let mut comment = String::new();
    if advanced {
        cx.emit(
            Node::new("Compressed data")
                .span(file.tail(12))
                .diag(Diagnostic::unsupported(
                    "Teledisk advanced (LZSS-Huffman) compression",
                )),
        );
    } else {
        if stepping & 0x80 != 0 {
            let ch = cx.read(file.sub(12, 10)).await?;
            let len = u64::from(u16_le(&ch, 2).unwrap_or(0));
            let [y, mo, d, hh, mm, ss] =
                [4usize, 5, 6, 7, 8, 9].map(|i| ch.get(i).copied().unwrap_or(0));
            let body = cx.read_avail(file.sub(22, len)).await?;
            comment = body
                .split(|&b| b == 0)
                .filter(|s| !s.is_empty())
                .map(|s| String::from_utf8_lossy(s).into_owned())
                .collect::<Vec<_>>()
                .join(" / ");
            cx.emit(
                Node::new("Comment")
                    .span(file.sub(12, len.saturating_add(10)))
                    .value(text(comment.clone()))
                    .summary(format!(
                        "{}-{:02}-{:02} {hh:02}:{mm:02}:{ss:02}",
                        1900u32.saturating_add(y.into()),
                        mo.saturating_add(1),
                        d
                    )),
            );
            at = 22u64.saturating_add(len);
        }
        cx.emit(
            Node::new("Tracks")
                .span(file.tail(at))
                .lazy(td0_tracks, (file, at)),
        );
    }
    cx.annotate(format!(
        "Teledisk {}.{} image{}, {}, {}, {sides} side(s){}",
        version / 10,
        version % 10,
        if advanced {
            " (advanced compression)"
        } else {
            ""
        },
        lookup(TD0_DRIVES, drive.into()).unwrap_or("unknown drive"),
        lookup(TD0_RATES, rate.into()).unwrap_or("unknown rate"),
        if comment.is_empty() {
            String::new()
        } else {
            format!(", {comment:?}")
        }
    ));
    Ok(())
}

async fn td0_tracks(cx: Cx, (file, at): (Span, u64)) -> Result<()> {
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(at);
    while cur.remaining() >= 1 {
        let start = cur.pos();
        let count = cur.u8().await?;
        if count == 0xff {
            cx.push(Node::new("End of image").span(cur.since(start)))
                .await;
            break;
        }
        let cyl = cur.u8().await?;
        let head = cur.u8().await?;
        let _crc = cur.u8().await?;
        let mut repeated = 0u32;
        for _ in 0..count {
            let s = cur.bytes(6).await?;
            let code = s.get(3).copied().unwrap_or(0);
            let flags = s.get(4).copied().unwrap_or(0);
            if flags & 0x30 == 0 && code <= 6 {
                let len = u64::from(cur.u16().await?);
                let encoding = cur.peek(1).await?.first().copied().unwrap_or(0);
                if encoding != 0 {
                    repeated = repeated.saturating_add(1);
                }
                cur.skip(len);
            }
        }
        cx.push(
            Node::new(format!("Cylinder {cyl} head {}", head & 1))
                .span(cur.since(start))
                .value(dec(count.into(), 8))
                .summary(format!("{count} sectors, {repeated} run-length encoded")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple DiskCopy 4.2

fn dc42_probe(h: &Head<'_>) -> bool {
    let data = u32_be(h.data, 0x40).map(u64::from);
    let tags = u32_be(h.data, 0x44).map(u64::from);
    h.at(0x52, b"\x01\x00")
        && h.data.first().is_some_and(|&n| (1..=63).contains(&n))
        && matches!(data, Some(409_600 | 819_200 | 737_280 | 1_474_560))
        && data
            .zip(tags)
            .is_some_and(|(d, t)| d.saturating_add(t).saturating_add(0x54) == h.len)
}

declare_format!(pub DC42 = "dc42", "Apple DiskCopy 4.2 image", ["image", "dc42", "img", "dsk"],
    "application/x-dc42", Probe::Custom(dc42_probe), dc42);

const DC42_FORMATS: EnumTable = &[
    (0, "400K GCR"),
    (1, "800K GCR"),
    (2, "720K MFM"),
    (3, "1440K MFM"),
];

fn dc42_sum(data: &[u8]) -> u32 {
    data.chunks(2).fold(0u32, |sum, w| {
        sum.wrapping_add(u32::from(u16_be(w, 0).unwrap_or(0)))
            .rotate_right(1)
    })
}

async fn dc42(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x54)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    let name_len = f.u8("Name length").emit()?;
    let name = f
        .ascii("Disk name", 63)
        .map(|s| s.chars().take(usize::from(name_len)).collect::<String>())
        .emit()?;
    let data_len = f.u32("Data size").emit()?;
    let tag_len = f.u32("Tag size").emit()?;
    let data_sum = f.u32("Data checksum").hex().emit()?;
    f.u32("Tag checksum").hex().emit()?;
    let format = f.u8("Disk format").enumeration(DC42_FORMATS).emit()?;
    f.u8("Format byte").hex().emit()?;
    f.u16("Private (0x0100)").hex().emit()?;
    let data = file.sub(0x54, data_len.into());
    let mut node = embedded("Disk data", input.nested(data));
    let mut status = "";
    if data.len <= cx.limits().max_read {
        let sum = dc42_sum(&cx.read(data).await?);
        if sum == data_sum {
            status = ", checksum valid";
        } else {
            status = ", checksum mismatch";
            node = node.diag(Diagnostic::warning(format!(
                "data checksum mismatch: computed {sum:#010x}"
            )));
        }
    }
    cx.emit(node);
    if tag_len > 0 {
        cx.emit(
            Node::new("Tag data")
                .span(file.sub(0x54u64.saturating_add(data_len.into()), tag_len.into())),
        );
    }
    cx.annotate(format!(
        "DiskCopy 4.2 image {name:?}, {}{status}",
        lookup(DC42_FORMATS, format.into()).unwrap_or("unknown format")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Applesauce flux (A2R) and Macintosh (MOOF) images

declare_format!(pub A2R = "a2r", "Applesauce flux image (A2R)", ["a2r"],
    "application/x-a2r", Probe::Magic(&[(0, b"A2R2\xff\x0a\x0d\x0a"), (0, b"A2R3\xff\x0a\x0d\x0a")]), a2r);
declare_format!(pub MOOF = "moof", "Applesauce Macintosh disk image (MOOF)", ["moof"],
    "application/x-moof", Probe::Magic(&[(0, b"MOOF\xff\x0a\x0d\x0a")]), moof);

const A2R_DRIVES: EnumTable = &[
    (1, "5.25\" SS 40-track"),
    (2, "3.5\" DS 80-track CLV"),
    (3, "5.25\" DS 80-track"),
    (4, "5.25\" DS 40-track"),
    (5, "3.5\" DS 80-track"),
    (6, "8\" DS"),
];
const MOOF_DISKS: EnumTable = &[
    (1, "SSDD GCR (400K)"),
    (2, "DSDD GCR (800K)"),
    (3, "DSHD MFM (1.44M)"),
    (4, "Twiggy"),
];
const APPLESAUCE_CHUNKS: &[(&str, &str)] = &[
    ("INFO", "disk information"),
    ("STRM", "flux streams (v2)"),
    ("RWCP", "raw captures"),
    ("SLVD", "solved flux"),
    ("META", "metadata"),
    ("TMAP", "track map"),
    ("TRKS", "track data"),
    ("FLUX", "flux track map"),
];

/// Walks `id + u32 size` chunks from `start`; returns (chunks, META text).
async fn applesauce_chunks(
    cx: &Cx,
    file: Span,
    start: u64,
) -> Result<(u32, Option<String>, Option<Vec<u8>>)> {
    let mut cur = Cursor::new(cx, file, LE);
    cur.seek(start);
    let (mut count, mut meta, mut info) = (0u32, None, None);
    while cur.remaining() >= 8 {
        let at = cur.pos();
        let id = fourcc(&cur.bytes(4).await?);
        let len = u64::from(cur.u32().await?);
        let data = cur.span(len);
        cur.skip(len);
        count = count.saturating_add(1);
        let meaning = APPLESAUCE_CHUNKS
            .iter()
            .find(|c| c.0 == id)
            .map_or("unknown chunk", |c| c.1);
        let mut node = Node::new(id.clone())
            .span(cur.since(at))
            .desc(meaning)
            .summary(format!("{len} bytes"))
            .target(data);
        if id == "META" {
            let raw = cx.read_avail(data.sub(0, 4096)).await?;
            let s = String::from_utf8_lossy(&raw).into_owned();
            node = node.value(text(s.replace('\n', "; ")));
            meta = Some(s);
        } else if id == "INFO" {
            info = Some(cx.read_avail(data.sub(0, 64)).await?);
        }
        cx.push(node).await;
    }
    Ok((count, meta, info))
}

fn meta_title(meta: Option<&str>) -> String {
    meta.and_then(|m| {
        m.lines()
            .find_map(|l| l.strip_prefix("title\t"))
            .map(|t| format!(" {t:?}"))
    })
    .unwrap_or_default()
}

async fn a2r(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text(fourcc(&head))),
    );
    let (count, meta, info) = applesauce_chunks(&cx, file, 8).await?;
    let info = info.unwrap_or_default();
    let creator = String::from_utf8_lossy(info.get(1..33).unwrap_or_default())
        .trim_end()
        .to_owned();
    let drive = info.get(33).copied().unwrap_or(0);
    cx.annotate(format!(
        "Applesauce {} flux image{}, {}, {count} chunks, by {creator:?}",
        fourcc(&head),
        meta_title(meta.as_deref()),
        lookup(A2R_DRIVES, drive.into()).unwrap_or("unknown drive")
    ));
    Ok(())
}

async fn moof(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text("MOOF")),
    );
    let crc_raw = cx.read(file.sub(8, 4)).await?;
    let stored = u32_le(&crc_raw, 0).unwrap_or(0);
    let computed = super::util::crc32_of(&cx, file.tail(12)).await;
    cx.emit(super::util::crc_node(
        "CRC-32",
        file.sub(8, 4),
        stored,
        computed,
    ));
    let (count, meta, info) = applesauce_chunks(&cx, file, 12).await?;
    let info = info.unwrap_or_default();
    let disk = info.get(1).copied().unwrap_or(0);
    let creator = String::from_utf8_lossy(info.get(5..37).unwrap_or_default())
        .trim_end()
        .to_owned();
    cx.annotate(format!(
        "MOOF image{}, {}, {count} chunks, by {creator:?}{}",
        meta_title(meta.as_deref()),
        lookup(MOOF_DISKS, disk.into()).unwrap_or("unknown disk"),
        if computed == Some(stored) {
            ", CRC valid"
        } else {
            ""
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// D88 (PC-88/PC-98/X1/FM-7 floppy)

fn d88_probe(h: &Head<'_>) -> bool {
    let first = u32_le(h.data, 0x20).unwrap_or(0);
    u32_le(h.data, 0x1c).is_some_and(|s| u64::from(s) == h.len)
        && matches!(h.data.get(0x1b), Some(0x00 | 0x10 | 0x20 | 0x30 | 0x40))
        && matches!(h.data.get(0x1a), Some(0x00 | 0x10))
        && (first == 0x2b0 || first == 0x2a0)
        && h.data
            .get(..17)
            .is_some_and(|n| n.iter().all(|&b| b == 0 || b >= 0x20))
}

declare_format!(pub D88 = "d88", "D88 floppy image (PC-88/PC-98)", ["d88", "d77", "88d", "d98", "d68"],
    "application/x-d88", Probe::Custom(d88_probe), d88);

const D88_MEDIA: EnumTable = &[
    (0x00, "2D"),
    (0x10, "2DD"),
    (0x20, "2HD"),
    (0x30, "1D"),
    (0x40, "1DD"),
];

async fn d88(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let name = f.ascii("Disk name", 17).emit()?;
    f.bytes("Reserved", 9).emit()?;
    let protect = f
        .u8("Write protect")
        .enumeration(&[(0x00, "no"), (0x10, "yes")])
        .emit()?;
    let media = f.u8("Media type").enumeration(D88_MEDIA).emit()?;
    f.u32("Disk size").emit()?;
    let first = u64::from(u32_le(&cx.read(file.sub(0x20, 4)).await?, 0).unwrap_or(0x2b0));
    let table = file.sub(0x20, first.saturating_sub(0x20).min(164 * 4));
    let raw = cx.read(table).await?;
    let offsets: Vec<u64> = raw
        .chunks(4)
        .map(|c| u64::from(u32_le(c, 0).unwrap_or(0)))
        .collect();
    let used = offsets.iter().filter(|&&o| o != 0).count();
    cx.emit(
        Node::new("Tracks")
            .span(table)
            .summary(format!("{used} tracks"))
            .lazy(d88_tracks, (file, offsets)),
    );
    cx.annotate(format!(
        "D88 {} disk {:?}, {used} tracks{}",
        lookup(D88_MEDIA, media.into()).unwrap_or("unknown"),
        name,
        if protect != 0 {
            ", write-protected"
        } else {
            ""
        }
    ));
    Ok(())
}

async fn d88_tracks(cx: Cx, (file, offsets): (Span, Vec<u64>)) -> Result<()> {
    for (i, &at) in offsets.iter().enumerate() {
        if at == 0 {
            continue;
        }
        let first = cx.read(file.sub(at, 16)).await?;
        let sectors = u64::from(u16_le(&first, 4).unwrap_or(0));
        let mut pos = at;
        let mut ids = Vec::new();
        for _ in 0..sectors.min(64) {
            let s = cx.read(file.sub(pos, 16)).await?;
            let r = s.get(2).copied().unwrap_or(0);
            ids.push(r.to_string());
            pos = pos
                .saturating_add(16)
                .saturating_add(u16_le(&s, 14).unwrap_or(0).into());
        }
        let bytes = u16_le(&first, 14).unwrap_or(0);
        cx.push(
            Node::new(format!(
                "Track {} (cylinder {}, head {})",
                i,
                first.first().copied().unwrap_or(0),
                first.get(1).copied().unwrap_or(0)
            ))
            .span(file.sub(at, pos.saturating_sub(at)))
            .summary(format!(
                "{sectors} sectors of {bytes} bytes, IDs {}",
                ids.join(" ")
            )),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Amiga Rigid Disk Block (hard-disk images)

fn rdb_probe(h: &Head<'_>) -> bool {
    h.at(0, b"RDSK") && u32_be(h.data, 4).is_some_and(|n| (16..=128).contains(&n))
}

declare_format!(pub AMIGA_RDB = "amiga-rdb", "Amiga hard disk image (Rigid Disk Block)", ["hdf", "rdb", "hdz"],
    "application/x-amiga-rdb", Probe::Custom(rdb_probe), amiga_rdb);

/// Amiga block checksum: all `summed` longs add up to zero.
fn amiga_sum(raw: &[u8], summed: u32) -> bool {
    raw.chunks(4)
        .take(usize::try_from(summed).unwrap_or(0))
        .fold(0u32, |s, c| s.wrapping_add(u32_be(c, 0).unwrap_or(0)))
        == 0
}

record! {
    pub struct RdskBlock {
        id: ascii[4] "Identifier",
        summed: u32 "Summed longs",
        checksum: u32 "Checksum" .hex(),
        host: u32 "Host ID",
        block_bytes: u32 "Block size",
        flags: u32 "Flags" .hex(),
        bad_blocks: u32 "Bad block list" .hex(),
        partitions: u32 "Partition list",
        filesystems: u32 "File system header list" .hex(),
        drive_init: u32 "Drive init code" .hex(),
        _reserved: bytes[24] "Reserved",
        cylinders: u32 "Cylinders",
        sectors: u32 "Sectors per track",
        heads: u32 "Heads",
        interleave: u32 "Interleave",
        park: u32 "Park cylinder",
        _reserved2: bytes[12] "Reserved",
        precomp: u32 "Write precompensation cylinder",
        reduced_write: u32 "Reduced write cylinder",
        step_rate: u32 "Step rate",
        _reserved3: bytes[20] "Reserved",
        rdb_lo: u32 "RDB area first block",
        rdb_hi: u32 "RDB area last block",
        lo_cyl: u32 "First partitionable cylinder",
        hi_cyl: u32 "Last partitionable cylinder",
        cyl_blocks: u32 "Blocks per cylinder",
        auto_park: u32 "Auto-park seconds",
        high_rdsk: u32 "Highest RDB block used",
        _reserved4: u32 "Reserved",
        vendor: ascii[8] "Disk vendor",
        product: ascii[16] "Disk product",
        revision: ascii[4] "Disk revision",
    }
}

async fn amiga_rdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, RdskBlock::SIZE);
    let h: RdskBlock = read_record(&cx, span, BE).await?;
    let raw = cx.read_avail(file.sub(0, 512)).await?;
    let mut node = RdskBlock::node("Rigid disk block", file.sub(0, 512), BE);
    if !amiga_sum(&raw, h.summed) {
        node = node.diag(Diagnostic::warning("checksum mismatch"));
    }
    cx.emit(node);
    let bs = u64::from(h.block_bytes.clamp(256, 32768));
    let mut next = h.partitions;
    let mut seen = Vec::new();
    let mut names = Vec::new();
    while next != u32::MAX && seen.len() < 64 {
        if seen.contains(&next) {
            cx.diag(Diagnostic::malformed("partition list loops"));
            break;
        }
        seen.push(next);
        let block = file.sub(u64::from(next).saturating_mul(bs), bs);
        let p = cx.read_avail(block).await?;
        if !p.starts_with(b"PART") {
            break;
        }
        let name_len = usize::from(p.get(36).copied().unwrap_or(0).min(31));
        let name = String::from_utf8_lossy(
            p.get(37..37usize.saturating_add(name_len))
                .unwrap_or_default(),
        )
        .into_owned();
        let env = |i: usize| {
            u64::from(u32_be(&p, 128usize.saturating_add(i.saturating_mul(4))).unwrap_or(0))
        };
        let (surfaces, per_track, lo, hi) = (env(3), env(5), env(9), env(10));
        let size_block = env(1).saturating_mul(4).max(1);
        let dos = match p.get(192..196) {
            Some([a, b, c, d]) if *d < 0x10 => format!("{}{}", fourcc(&[*a, *b, *c]), d),
            Some(raw) => fourcc(raw),
            None => String::new(),
        };
        let cyl = surfaces
            .saturating_mul(per_track)
            .saturating_mul(size_block);
        let data = file.sub(
            lo.saturating_mul(cyl),
            hi.saturating_add(1).saturating_sub(lo).saturating_mul(cyl),
        );
        names.push(format!("{name} ({dos})"));
        let summed = u32_be(&p, 4).unwrap_or(0);
        let mut part = embedded(format!("Partition {name}"), input.nested(data))
            .summary(format!(
                "{dos}, cylinders {lo}-{hi}, {}, boot priority {}",
                size(data.len),
                crate::bytes::i32_be(&p, 188).unwrap_or(0)
            ))
            .target(block);
        if !amiga_sum(&p, summed) {
            part = part.diag(Diagnostic::warning("PART block checksum mismatch"));
        }
        cx.push(part).await;
        next = u32_be(&p, 16).unwrap_or(u32::MAX);
    }
    cx.annotate(format!(
        "Amiga RDB disk {} {}, {} cylinders × {} heads × {} sectors, partitions: {}",
        h.vendor.trim(),
        h.product.trim(),
        h.cylinders,
        h.heads,
        h.sectors,
        names.join(", ")
    ));
    Ok(())
}
