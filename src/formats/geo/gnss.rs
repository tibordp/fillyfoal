//! GNSS receiver streams: u-blox UBX, RTCM 3, Septentrio SBF and NovAtel
//! OEM binary logs, and NMEA 0183 sentence logs.
//!
//! The binary streams share a shape: a sync pattern, a small header with a
//! length, a payload and a checksum. Packets are listed in pages; bytes that
//! do not start a valid packet are skipped up to the next sync pattern and
//! shown as a gap. Common messages expand to decoded fields.

use super::{Bits, crc16_xmodem, crc24q, enumv, hex, int, leaf, text, uint};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::scan::{Lines, Scanner};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

/// Packets larger than this are not plausible in any of these protocols.
const MAX_PACKET: u64 = 1 << 16;

/// The next occurrence of `sync` at or after `from`.
async fn resync(cx: &Cx, region: Span, from: u64, sync: &[u8]) -> Result<Option<u64>> {
    Scanner::new(cx, region).find_seq(from, sync).await
}

/// Pushes a gap node for unparseable bytes and returns where to continue,
/// or `None` at the end.
async fn skip_gap(cx: &Cx, region: Span, at: u64, sync: &[u8]) -> Result<Option<u64>> {
    let next = resync(cx, region, at.saturating_add(1), sync).await?;
    let end = next.unwrap_or(region.len);
    cx.push(Node::new("Unrecognized bytes").span(region.sub(at, end.saturating_sub(at))))
        .await;
    Ok(next)
}

// ---------------------------------------------------------------------------
// u-blox UBX

/// The 8-bit Fletcher checksum over class, ID, length and payload.
fn fletcher(data: &[u8]) -> (u8, u8) {
    let (mut a, mut b) = (0u8, 0u8);
    for &x in data {
        a = a.wrapping_add(x);
        b = b.wrapping_add(a);
    }
    (a, b)
}

const UBX_CLASSES: &[u8] = &[
    0x01, 0x02, 0x04, 0x05, 0x06, 0x09, 0x0a, 0x0b, 0x0d, 0x10, 0x13, 0x21, 0x27, 0x28,
];

/// Whether a valid UBX packet starts at `at` in `data`.
fn ubx_at(data: &[u8], at: usize) -> Option<usize> {
    if data.get(at..at.saturating_add(2))? != b"\xb5\x62"
        || !UBX_CLASSES.contains(data.get(at.saturating_add(2))?)
    {
        return None;
    }
    let len = usize::from(u16_le(data, at.saturating_add(4))?);
    let body = data.get(at.saturating_add(2)..at.saturating_add(6).saturating_add(len))?;
    let ck = data
        .get(at.saturating_add(6).saturating_add(len)..at.saturating_add(8).saturating_add(len))?;
    let (a, b) = fletcher(body);
    (ck == [a, b]).then_some(len.saturating_add(8))
}

fn ubx_probe(h: &Head<'_>) -> bool {
    ubx_at(h.data, 0).is_some_and(|n| {
        n == h.data.len() || ubx_at(h.data, n).is_some() || h.data.len() < n.saturating_add(8)
    })
}

declare_format!(pub UBX = "ubx", "u-blox UBX binary log", ["ubx"], "application/x-ubx",
    Probe::Custom(ubx_probe), ubx);

const UBX_MESSAGES: EnumTable = &[
    (0x0102, "NAV-POSLLH"),
    (0x0103, "NAV-STATUS"),
    (0x0104, "NAV-DOP"),
    (0x0106, "NAV-SOL"),
    (0x0107, "NAV-PVT"),
    (0x0112, "NAV-VELNED"),
    (0x0120, "NAV-TIMEGPS"),
    (0x0121, "NAV-TIMEUTC"),
    (0x0135, "NAV-SAT"),
    (0x0213, "RXM-SFRBX"),
    (0x0215, "RXM-RAWX"),
    (0x0400, "INF-ERROR"),
    (0x0401, "INF-WARNING"),
    (0x0402, "INF-NOTICE"),
    (0x0403, "INF-TEST"),
    (0x0404, "INF-DEBUG"),
    (0x0500, "ACK-NAK"),
    (0x0501, "ACK-ACK"),
    (0x0600, "CFG-PRT"),
    (0x0601, "CFG-MSG"),
    (0x0608, "CFG-RATE"),
    (0x068a, "CFG-VALSET"),
    (0x068b, "CFG-VALGET"),
    (0x0a04, "MON-VER"),
    (0x0a09, "MON-HW"),
    (0x0d01, "TIM-TP"),
    (0x1002, "ESF-MEAS"),
];

const FIX_TYPES: EnumTable = &[
    (0, "no fix"),
    (1, "dead reckoning"),
    (2, "2D"),
    (3, "3D"),
    (4, "GNSS + dead reckoning"),
    (5, "time only"),
];

fn deg7(v: i32) -> String {
    format!("{}°", f64::from(v) / 1e7)
}

fn mm(v: i32) -> String {
    format!("{} m", f64::from(v) / 1e3)
}

record! {
    pub struct NavPvt {
        itow: u32 "iTOW (ms)",
        year: u16 "Year",
        month: u8 "Month",
        day: u8 "Day",
        hour: u8 "Hour",
        min: u8 "Minute",
        sec: u8 "Second",
        valid: u8 "Validity flags" .hex(),
        t_acc: u32 "Time accuracy (ns)",
        nano: i32 "Fraction of second (ns)",
        fix: u8 "Fix type" .enumeration(FIX_TYPES),
        flags: u8 "Flags" .hex(),
        flags2: u8 "Flags 2" .hex(),
        num_sv: u8 "Satellites used",
        lon: i32 "Longitude (1e-7°)" .with(|&v, n| n.summary(deg7(v))),
        lat: i32 "Latitude (1e-7°)" .with(|&v, n| n.summary(deg7(v))),
        height: i32 "Height above ellipsoid (mm)" .with(|&v, n| n.summary(mm(v))),
        h_msl: i32 "Height above MSL (mm)" .with(|&v, n| n.summary(mm(v))),
        h_acc: u32 "Horizontal accuracy (mm)",
        v_acc: u32 "Vertical accuracy (mm)",
        vel_n: i32 "Velocity north (mm/s)",
        vel_e: i32 "Velocity east (mm/s)",
        vel_d: i32 "Velocity down (mm/s)",
        g_speed: i32 "Ground speed (mm/s)",
        head_mot: i32 "Heading of motion (1e-5°)",
        s_acc: u32 "Speed accuracy (mm/s)",
        head_acc: u32 "Heading accuracy (1e-5°)",
        pdop: u16 "Position DOP (0.01)",
    }
}

record! {
    pub struct NavPosllh {
        itow: u32 "iTOW (ms)",
        lon: i32 "Longitude (1e-7°)" .with(|&v, n| n.summary(deg7(v))),
        lat: i32 "Latitude (1e-7°)" .with(|&v, n| n.summary(deg7(v))),
        height: i32 "Height above ellipsoid (mm)" .with(|&v, n| n.summary(mm(v))),
        h_msl: i32 "Height above MSL (mm)" .with(|&v, n| n.summary(mm(v))),
        h_acc: u32 "Horizontal accuracy (mm)",
        v_acc: u32 "Vertical accuracy (mm)",
    }
}

async fn ubx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut n = 0u64;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 6)).await?;
        let len = u64::from(u16_le(&head, 4).unwrap_or(0));
        let total = len.saturating_add(8);
        let packet = cx.read_avail(file.sub(pos, total)).await?;
        if head.len() < 6 || ubx_at(&packet, 0).is_none() {
            match skip_gap(&cx, file, pos, b"\xb5\x62").await? {
                Some(next) => {
                    pos = next;
                    continue;
                }
                None => break,
            }
        }
        let id = u16::from_be_bytes([
            head.get(2).copied().unwrap_or(0),
            head.get(3).copied().unwrap_or(0),
        ]);
        let span = file.sub(pos, total);
        let name =
            lookup(UBX_MESSAGES, id.into()).map_or_else(|| format!("UBX {id:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(span).summary(format!("{len} bytes"));
        let payload = packet
            .get(6..to_usize(len.saturating_add(6)))
            .unwrap_or_default();
        match id {
            0x0107 if len >= 92 => {
                let lat = crate::bytes::i32_le(payload, 28).unwrap_or(0);
                let lon = crate::bytes::i32_le(payload, 24).unwrap_or(0);
                let fix =
                    lookup(FIX_TYPES, payload.get(20).copied().unwrap_or(0).into()).unwrap_or("?");
                node = node.summary(format!("{fix}, {}, {}", deg7(lat), deg7(lon)));
            }
            0x0400..=0x0404 => node = node.summary(String::from_utf8_lossy(payload).into_owned()),
            _ => {}
        }
        cx.push(node.lazy(ubx_packet, (span, id))).await;
        pos = pos.saturating_add(total);
        n = n.saturating_add(1);
    }
    cx.annotate(format!("u-blox UBX, {n} packets"));
    Ok(())
}

async fn ubx_packet(cx: Cx, (span, id): (Span, u16)) -> Result<()> {
    cx.emit(leaf("Sync", span.sub(0, 2), hex(0xb562, 16)));
    cx.emit(leaf(
        "Message",
        span.sub(2, 2),
        enumv(UBX_MESSAGES, id.into(), 16),
    ));
    let len = span.len.saturating_sub(8);
    cx.emit(leaf("Length", span.sub(4, 2), uint(len, 16)));
    let payload = span.sub(6, len);
    match id {
        0x0107 if len >= NavPvt::SIZE => cx.emit(NavPvt::node("NAV-PVT", payload, LE)),
        0x0102 if len >= NavPosllh::SIZE => cx.emit(NavPosllh::node("NAV-POSLLH", payload, LE)),
        0x0400..=0x0404 => cx.emit(leaf(
            "Text",
            payload,
            text(String::from_utf8_lossy(&cx.read(payload).await?)),
        )),
        0x0a04 => {
            let b = cx.read(payload).await?;
            cx.emit(leaf(
                "Software version",
                payload.sub(0, 30),
                text(crate::text::until_nul(b.get(..30).unwrap_or_default())),
            ));
            cx.emit(leaf(
                "Hardware version",
                payload.sub(30, 10),
                text(crate::text::until_nul(b.get(30..40).unwrap_or_default())),
            ));
            for (i, ext) in b.get(40..).unwrap_or_default().chunks(30).enumerate() {
                cx.emit(leaf(
                    "Extension",
                    payload.sub(40u64.saturating_add(to_u64(i).saturating_mul(30)), 30),
                    text(crate::text::until_nul(ext)),
                ));
            }
        }
        0x0500 | 0x0501 => {
            let b = cx.read(payload).await?;
            let acked = u16::from_be_bytes([
                b.first().copied().unwrap_or(0),
                b.get(1).copied().unwrap_or(0),
            ]);
            cx.emit(leaf(
                "Acknowledged message",
                payload,
                enumv(UBX_MESSAGES, acked.into(), 16),
            ));
        }
        _ => cx.emit(Node::new("Payload").span(payload)),
    }
    let ck = span.sub(len.saturating_add(6), 2);
    cx.emit(leaf("Checksum", ck, Value::Bytes(cx.read(ck).await?)).summary("valid"));
    Ok(())
}

// ---------------------------------------------------------------------------
// RTCM 3

/// Whether a valid RTCM 3 frame starts at `at`; returns its length.
fn rtcm_at(data: &[u8], at: usize) -> Option<usize> {
    if *data.get(at)? != 0xd3 {
        return None;
    }
    let b1 = *data.get(at.saturating_add(1))?;
    if b1 & 0xfc != 0 {
        return None;
    }
    let len = usize::from(u16::from_be_bytes([
        b1 & 3,
        *data.get(at.saturating_add(2))?,
    ]));
    let frame = data.get(at..at.saturating_add(len).saturating_add(6))?;
    let body = frame.get(..len.saturating_add(3))?;
    let crc = frame.get(len.saturating_add(3)..)?;
    let c = crc24q(body);
    (crc == [(c >> 16) as u8, (c >> 8) as u8, c as u8] && len >= 2).then_some(len.saturating_add(6))
}

fn rtcm_probe(h: &Head<'_>) -> bool {
    rtcm_at(h.data, 0).is_some_and(|n| {
        n == h.data.len() || rtcm_at(h.data, n).is_some() || h.data.len() < n.saturating_add(1029)
    })
}

declare_format!(pub RTCM3 = "rtcm3", "RTCM 3 GNSS correction stream", ["rtcm3", "rtcm"], "application/x-rtcm3",
    Probe::Custom(rtcm_probe), rtcm3);

const RTCM_MESSAGES: EnumTable = &[
    (1001, "GPS L1 RTK observables"),
    (1002, "GPS L1 extended RTK observables"),
    (1003, "GPS L1/L2 RTK observables"),
    (1004, "GPS L1/L2 extended RTK observables"),
    (1005, "Reference station ARP"),
    (1006, "Reference station ARP with antenna height"),
    (1007, "Antenna descriptor"),
    (1008, "Antenna descriptor and serial number"),
    (1009, "GLONASS L1 RTK observables"),
    (1010, "GLONASS L1 extended RTK observables"),
    (1011, "GLONASS L1/L2 RTK observables"),
    (1012, "GLONASS L1/L2 extended RTK observables"),
    (1013, "System parameters"),
    (1019, "GPS ephemeris"),
    (1020, "GLONASS ephemeris"),
    (1029, "Unicode text"),
    (1033, "Receiver and antenna descriptors"),
    (1042, "BeiDou ephemeris"),
    (1044, "QZSS ephemeris"),
    (1045, "Galileo F/NAV ephemeris"),
    (1046, "Galileo I/NAV ephemeris"),
    (1071, "GPS MSM1"),
    (1072, "GPS MSM2"),
    (1073, "GPS MSM3"),
    (1074, "GPS MSM4"),
    (1075, "GPS MSM5"),
    (1076, "GPS MSM6"),
    (1077, "GPS MSM7"),
    (1081, "GLONASS MSM1"),
    (1084, "GLONASS MSM4"),
    (1085, "GLONASS MSM5"),
    (1087, "GLONASS MSM7"),
    (1094, "Galileo MSM4"),
    (1095, "Galileo MSM5"),
    (1097, "Galileo MSM7"),
    (1114, "QZSS MSM4"),
    (1117, "QZSS MSM7"),
    (1124, "BeiDou MSM4"),
    (1125, "BeiDou MSM5"),
    (1127, "BeiDou MSM7"),
    (1230, "GLONASS code-phase biases"),
];

async fn rtcm3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut n = 0u64;
    let mut station = None;
    while pos < file.len {
        let frame = cx.read_avail(file.sub(pos, 1029)).await?;
        let Some(total) = rtcm_at(&frame, 0) else {
            match skip_gap(&cx, file, pos, b"\xd3").await? {
                Some(next) => {
                    pos = next;
                    continue;
                }
                None => break,
            }
        };
        let payload = frame.get(3..total.saturating_sub(3)).unwrap_or_default();
        let mut bits = Bits::new(payload);
        let number = bits.u(12).unwrap_or(0);
        let id = bits.u(12).unwrap_or(0);
        if (1001..=1230).contains(&number) && station.is_none() {
            station = Some(id);
        }
        let span = file.sub(pos, to_u64(total));
        let name = format!(
            "{number}: {}",
            lookup(RTCM_MESSAGES, number).unwrap_or("message")
        );
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("station {id}, {} bytes", payload.len()))
                .lazy(rtcm_frame, span),
        )
        .await;
        pos = pos.saturating_add(to_u64(total));
        n = n.saturating_add(1);
    }
    cx.annotate(format!(
        "RTCM 3, {n} messages{}",
        station
            .map(|s| format!(", station {s}"))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn rtcm_frame(cx: Cx, span: Span) -> Result<()> {
    let frame = cx.read(span).await?;
    cx.emit(leaf("Preamble", span.sub(0, 1), hex(0xd3, 8)));
    let len = span.len.saturating_sub(6);
    cx.emit(leaf("Length", span.sub(1, 2), uint(len, 10)));
    let payload = frame
        .get(3..to_usize(len.saturating_add(3)))
        .unwrap_or_default();
    let pspan = span.sub(3, len);
    let mut bits = Bits::new(payload);
    let number = bits.u(12).unwrap_or(0);
    cx.emit(leaf(
        "Message number",
        pspan.sub(0, 2),
        enumv(RTCM_MESSAGES, number, 12),
    ));
    if matches!(number, 1005 | 1006) {
        let mut fields = Vec::new();
        let station = bits.u(12).unwrap_or(0);
        fields.push(("Reference station ID", uint(station, 12)));
        fields.push(("ITRF realization year", uint(bits.u(6).unwrap_or(0), 6)));
        let flags = bits.u(4).unwrap_or(0);
        fields.push(("GPS / GLONASS / Galileo / reference flags", hex(flags, 4)));
        let x = bits.i(38).unwrap_or(0);
        bits.u(2);
        let y = bits.i(38).unwrap_or(0);
        bits.u(2);
        let z = bits.i(38).unwrap_or(0);
        for (label, v) in [
            ("ECEF X (0.1 mm)", x),
            ("ECEF Y (0.1 mm)", y),
            ("ECEF Z (0.1 mm)", z),
        ] {
            fields.push((label, int(v, 38)));
        }
        if number == 1006 {
            fields.push(("Antenna height (0.1 mm)", uint(bits.u(16).unwrap_or(0), 16)));
        }
        for (label, value) in fields {
            cx.emit(Node::new(label).span(pspan).value(value));
        }
        cx.emit(Node::new("Position").span(pspan).summary(format!(
            "ECEF {:.4}, {:.4}, {:.4} m",
            x as f64 / 1e4,
            y as f64 / 1e4,
            z as f64 / 1e4
        )));
    } else {
        cx.emit(leaf(
            "Station ID",
            pspan.sub(1, 2),
            uint(bits.u(12).unwrap_or(0), 12),
        ));
        cx.emit(Node::new("Payload").span(pspan));
    }
    cx.emit(
        leaf(
            "CRC-24Q",
            span.sub(len.saturating_add(3), 3),
            Value::Bytes(
                frame
                    .get(to_usize(len.saturating_add(3))..)
                    .unwrap_or_default()
                    .to_vec(),
            ),
        )
        .summary("valid"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Septentrio SBF

/// Whether a valid SBF block starts at `at`; returns its length.
fn sbf_at(data: &[u8], at: usize) -> Option<usize> {
    if data.get(at..at.saturating_add(2))? != b"$@" {
        return None;
    }
    let crc = u16_le(data, at.saturating_add(2))?;
    let len = usize::from(u16_le(data, at.saturating_add(6))?);
    if len < 8 || len % 4 != 0 {
        return None;
    }
    let body = data.get(at.saturating_add(4)..at.saturating_add(len))?;
    (crc16_xmodem(body) == crc).then_some(len)
}

fn sbf_probe(h: &Head<'_>) -> bool {
    sbf_at(h.data, 0).is_some()
}

declare_format!(pub SBF = "septentrio-sbf", "Septentrio Binary Format log", ["sbf"], "application/x-septentrio-sbf",
    Probe::Custom(sbf_probe), sbf);

const SBF_BLOCKS: EnumTable = &[
    (4001, "DOP"),
    (4006, "PVTCartesian"),
    (4007, "PVTGeodetic"),
    (4013, "ChannelStatus"),
    (4014, "ReceiverStatus"),
    (4027, "MeasEpoch"),
    (4028, "MeasExtra"),
    (5891, "GPSNav"),
    (5902, "ReceiverSetup"),
    (5914, "ReceiverTime"),
];

async fn sbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut n = 0u64;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 8)).await?;
        let len = u64::from(u16_le(&head, 6).unwrap_or(0));
        let block = cx.read_avail(file.sub(pos, len.min(MAX_PACKET))).await?;
        let Some(total) = sbf_at(&block, 0) else {
            match skip_gap(&cx, file, pos, b"$@").await? {
                Some(next) => {
                    pos = next;
                    continue;
                }
                None => break,
            }
        };
        let raw_id = u16_le(&head, 4).unwrap_or(0);
        let (number, revision) = (raw_id & 0x1fff, raw_id >> 13);
        let span = file.sub(pos, to_u64(total));
        let tow = u32_le(&block, 8).unwrap_or(u32::MAX);
        let week = u16_le(&block, 12).unwrap_or(u16::MAX);
        let name = lookup(SBF_BLOCKS, number.into())
            .map_or_else(|| format!("Block {number}"), str::to_owned);
        let mut summary = format!(
            "rev {revision}, week {week}, TOW {} s",
            f64::from(tow) / 1e3
        );
        if number == 4007
            && let (Some(lat), Some(lon)) = (
                crate::bytes::u64_le(&block, 16),
                crate::bytes::u64_le(&block, 24),
            )
        {
            summary = format!(
                "{summary}, {:.7}°, {:.7}°",
                f64::from_bits(lat).to_degrees(),
                f64::from_bits(lon).to_degrees()
            );
        }
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(sbf_block, (span, number)),
        )
        .await;
        pos = pos.saturating_add(to_u64(total));
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Septentrio SBF, {n} blocks"));
    Ok(())
}

record! {
    pub struct PvtGeodetic {
        tow: u32 "TOW (ms)",
        wnc: u16 "Week number",
        mode: u8 "Mode",
        error: u8 "Error",
        lat: f64 "Latitude (rad)" .with(|&v, n| n.summary(format!("{:.7}°", v.to_degrees()))),
        lon: f64 "Longitude (rad)" .with(|&v, n| n.summary(format!("{:.7}°", v.to_degrees()))),
        height: f64 "Ellipsoidal height (m)",
        undulation: f32 "Geoid undulation (m)",
        vn: f32 "Velocity north (m/s)",
        ve: f32 "Velocity east (m/s)",
        vu: f32 "Velocity up (m/s)",
        cog: f32 "Course over ground (°)",
        clock_bias: f64 "Receiver clock bias (ms)",
        clock_drift: f32 "Receiver clock drift (ppm)",
        time_system: u8 "Time system",
        datum: u8 "Datum",
        nr_sv: u8 "Satellites used",
    }
}

async fn sbf_block(cx: Cx, (span, number): (Span, u16)) -> Result<()> {
    cx.emit(leaf("Sync", span.sub(0, 2), text("$@")));
    cx.emit(
        leaf(
            "CRC",
            span.sub(2, 2),
            hex(
                u16_le(&cx.read(span.sub(2, 2)).await?, 0)
                    .unwrap_or(0)
                    .into(),
                16,
            ),
        )
        .summary("valid"),
    );
    cx.emit(leaf(
        "Block number",
        span.sub(4, 2),
        enumv(SBF_BLOCKS, number.into(), 13),
    ));
    cx.emit(leaf("Length", span.sub(6, 2), uint(span.len, 16)));
    let body = span.tail(8);
    if number == 4007 && body.len >= PvtGeodetic::SIZE {
        emit_record::<PvtGeodetic>(&cx, body.sub(0, PvtGeodetic::SIZE), LE).await?;
        cx.emit(Node::new("Remaining fields").span(body.tail(PvtGeodetic::SIZE)));
    } else {
        let b = cx.read(body.sub(0, 6)).await?;
        cx.emit(leaf(
            "TOW (ms)",
            body.sub(0, 4),
            uint(u32_le(&b, 0).unwrap_or(0).into(), 32),
        ));
        cx.emit(leaf(
            "Week number",
            body.sub(4, 2),
            uint(u16_le(&b, 4).unwrap_or(0).into(), 16),
        ));
        cx.emit(Node::new("Body").span(body.tail(6)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NovAtel OEM binary

declare_format!(pub NOVATEL = "novatel", "NovAtel OEM binary log", ["gps", "bin"], "application/x-novatel",
    Probe::Custom(|h| h.starts_with(b"\xaa\x44\x12\x1c") && h.data.get(6).is_some_and(|t| t & 0x60 == 0)), novatel);

const NOVATEL_MESSAGES: EnumTable = &[
    (7, "GPSEPHEM"),
    (8, "IONUTC"),
    (37, "VERSION"),
    (41, "RAWEPHEM"),
    (42, "BESTPOS"),
    (43, "RANGE"),
    (47, "PSRPOS"),
    (99, "BESTVEL"),
    (101, "TIME"),
    (140, "RANGECMP"),
];

const SOLUTION_STATUS: EnumTable = &[
    (0, "SOL_COMPUTED"),
    (1, "INSUFFICIENT_OBS"),
    (2, "NO_CONVERGENCE"),
    (3, "SINGULARITY"),
    (4, "COV_TRACE"),
    (5, "TEST_DIST"),
    (6, "COLD_START"),
    (7, "V_H_LIMIT"),
    (8, "VARIANCE"),
    (9, "RESIDUALS"),
];

const POSITION_TYPES: EnumTable = &[
    (0, "NONE"),
    (1, "FIXEDPOS"),
    (2, "FIXEDHEIGHT"),
    (8, "DOPPLER_VELOCITY"),
    (16, "SINGLE"),
    (17, "PSRDIFF"),
    (18, "WAAS"),
    (19, "PROPAGATED"),
    (32, "L1_FLOAT"),
    (34, "NARROW_FLOAT"),
    (48, "L1_INT"),
    (50, "NARROW_INT"),
    (68, "PPP_CONVERGING"),
    (69, "PPP"),
];

/// NovAtel's CRC-32: the reflected IEEE polynomial with zero initial value
/// and no final inversion.
fn novatel_crc(data: &[u8]) -> u32 {
    crate::codec::crc::crc32_update(0, data)
}

record! {
    pub struct NovatelHeader {
        sync: bytes[3] "Sync",
        header_len: u8 "Header length",
        id: u16 "Message ID" .enumeration(NOVATEL_MESSAGES),
        kind: u8 "Message type" .hex(),
        port: u8 "Port address" .hex(),
        len: u16 "Message length",
        sequence: u16 "Sequence",
        idle: u8 "Idle time (0.5 %)",
        time_status: u8 "Time status",
        week: u16 "GPS week",
        ms: u32 "GPS milliseconds",
        status: u32 "Receiver status" .hex(),
        _reserved: u16 "Reserved",
        version: u16 "Receiver software build",
    }
}

record! {
    pub struct BestPos {
        sol: u32 "Solution status" .enumeration(SOLUTION_STATUS),
        pos_type: u32 "Position type" .enumeration(POSITION_TYPES),
        lat: f64 "Latitude (°)",
        lon: f64 "Longitude (°)",
        height: f64 "Height above MSL (m)",
        undulation: f32 "Undulation (m)",
        datum: u32 "Datum ID",
        lat_sd: f32 "Latitude σ (m)",
        lon_sd: f32 "Longitude σ (m)",
        height_sd: f32 "Height σ (m)",
        station: ascii[4] "Base station ID",
        diff_age: f32 "Differential age (s)",
        sol_age: f32 "Solution age (s)",
        svs: u8 "Satellites tracked",
        sol_svs: u8 "Satellites in solution",
    }
}

async fn novatel(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut n = 0u64;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 28)).await?;
        let hlen = u64::from(head.get(3).copied().unwrap_or(0));
        let mlen = u64::from(u16_le(&head, 8).unwrap_or(0));
        let total = hlen.saturating_add(mlen).saturating_add(4);
        if !head.starts_with(b"\xaa\x44\x12") || hlen < 28 || to_u64(head.len()) < 28 {
            match skip_gap(&cx, file, pos, b"\xaa\x44\x12").await? {
                Some(next) => {
                    pos = next;
                    continue;
                }
                None => break,
            }
        }
        let span = file.sub(pos, total);
        if span.len < total {
            return Err(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        let id = u16_le(&head, 4).unwrap_or(0);
        let mut node = Node::new(
            lookup(NOVATEL_MESSAGES, id.into())
                .map_or_else(|| format!("Message {id}"), str::to_owned),
        )
        .span(span);
        let week = u16_le(&head, 14).unwrap_or(0);
        let ms = u32_le(&head, 16).unwrap_or(0);
        let mut summary = format!("week {week}, {} s", f64::from(ms) / 1e3);
        if id == 42 && mlen >= BestPos::SIZE {
            let b = cx.read(span.sub(hlen.saturating_add(8), 16)).await?;
            let lat = crate::bytes::u64_le(&b, 0).map_or(0.0, f64::from_bits);
            let lon = crate::bytes::u64_le(&b, 8).map_or(0.0, f64::from_bits);
            summary = format!("{summary}, {lat:.7}°, {lon:.7}°");
        }
        let all = cx.read(span).await?;
        let stored = u32_le(&all, to_usize(total.saturating_sub(4))).unwrap_or(0);
        let computed = novatel_crc(
            all.get(..to_usize(total.saturating_sub(4)))
                .unwrap_or_default(),
        );
        if stored != computed {
            node = node.diag(Diagnostic::warning(format!(
                "CRC {stored:#010x}, computed {computed:#010x}"
            )));
        }
        cx.push(
            node.summary(summary)
                .lazy(novatel_message, (span, hlen, id)),
        )
        .await;
        pos = pos.saturating_add(total);
        n = n.saturating_add(1);
    }
    cx.annotate(format!("NovAtel binary log, {n} messages"));
    Ok(())
}

async fn novatel_message(cx: Cx, (span, hlen, id): (Span, u64, u16)) -> Result<()> {
    cx.emit(NovatelHeader::node("Header", span.sub(0, hlen), LE));
    let body = span.sub(hlen, span.len.saturating_sub(hlen).saturating_sub(4));
    if id == 42 && body.len >= BestPos::SIZE {
        cx.emit(BestPos::node("BESTPOS", body, LE));
    } else {
        cx.emit(Node::new("Message").span(body));
    }
    cx.emit(leaf(
        "CRC-32",
        span.tail(span.len.saturating_sub(4)),
        hex(
            u32_le(&cx.read(span.tail(span.len.saturating_sub(4))).await?, 0)
                .unwrap_or(0)
                .into(),
            32,
        ),
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// NMEA 0183

/// Checks a sentence: `$` or `!`, an address, fields, `*hh` checksum.
/// Returns the address on success.
fn nmea_sentence(line: &[u8]) -> Option<(&[u8], bool)> {
    let line = crate::formats::text::probe::trim(line);
    if !matches!(line.first(), Some(b'$' | b'!')) {
        return None;
    }
    let comma = line.iter().position(|&b| b == b',')?;
    let address = line.get(1..comma)?;
    if !(3..=6).contains(&address.len())
        || !address
            .iter()
            .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
    {
        return None;
    }
    let star = line.iter().rposition(|&b| b == b'*')?;
    let hex = std::str::from_utf8(line.get(star.saturating_add(1)..)?).ok()?;
    if hex.len() != 2 {
        return None;
    }
    let stored = u8::from_str_radix(hex, 16).ok()?;
    let computed = line.get(1..star)?.iter().fold(0u8, |a, &b| a ^ b);
    Some((address, stored == computed))
}

fn nmea_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 8);
    let mut good = 0u32;
    for l in lines
        .iter()
        .filter(|l| !crate::formats::text::probe::trim(l).is_empty())
    {
        match nmea_sentence(l) {
            Some((_, true)) => good = good.saturating_add(1),
            _ => return good >= 2,
        }
        if good >= 3 {
            return true;
        }
    }
    good >= 1 && crate::formats::text::probe::complete(h)
}

declare_format!(pub NMEA = "nmea", "NMEA 0183 sentence log", ["nmea", "nma", "gps", "log"], "text/x-nmea",
    Probe::Custom(nmea_probe), nmea);

const GGA: super::Labels = &[
    "Sentence",
    "UTC time",
    "Latitude",
    "N/S",
    "Longitude",
    "E/W",
    "Fix quality",
    "Satellites",
    "HDOP",
    "Altitude",
    "Altitude units",
    "Geoid separation",
    "Separation units",
    "DGPS age",
    "DGPS station",
];
const RMC: super::Labels = &[
    "Sentence",
    "UTC time",
    "Status",
    "Latitude",
    "N/S",
    "Longitude",
    "E/W",
    "Speed (knots)",
    "Course (°)",
    "Date",
    "Magnetic variation",
    "E/W",
    "Mode",
];
const GSA: super::Labels = &[
    "Sentence", "Mode", "Fix type", "SV 1", "SV 2", "SV 3", "SV 4", "SV 5", "SV 6", "SV 7", "SV 8",
    "SV 9", "SV 10", "SV 11", "SV 12", "PDOP", "HDOP", "VDOP",
];
const GSV: super::Labels = &[
    "Sentence",
    "Messages",
    "Message number",
    "Satellites in view",
    "PRN",
    "Elevation",
    "Azimuth",
    "SNR",
    "PRN",
    "Elevation",
    "Azimuth",
    "SNR",
    "PRN",
    "Elevation",
    "Azimuth",
    "SNR",
    "PRN",
    "Elevation",
    "Azimuth",
    "SNR",
];
const GLL: super::Labels = &[
    "Sentence",
    "Latitude",
    "N/S",
    "Longitude",
    "E/W",
    "UTC time",
    "Status",
    "Mode",
];
const VTG: super::Labels = &[
    "Sentence",
    "True track",
    "T",
    "Magnetic track",
    "M",
    "Speed (knots)",
    "N",
    "Speed (km/h)",
    "K",
    "Mode",
];
const ZDA: super::Labels = &[
    "Sentence",
    "UTC time",
    "Day",
    "Month",
    "Year",
    "Zone hours",
    "Zone minutes",
];
const VDM: super::Labels = &[
    "Sentence",
    "Fragments",
    "Fragment number",
    "Message ID",
    "Channel",
    "Payload",
    "Fill bits",
];

const SENTENCES: EnumTable = &[
    (0, "GGA: fix data"),
    (1, "RMC: recommended minimum"),
    (2, "GSA: DOP and active satellites"),
    (3, "GSV: satellites in view"),
    (4, "GLL: position"),
    (5, "VTG: track and speed"),
    (6, "ZDA: date and time"),
    (7, "VDM: AIS message"),
    (8, "VDO: own-ship AIS message"),
    (9, "TXT: text"),
    (10, "HDT: true heading"),
];

fn sentence_info(kind: &str) -> (super::Labels, Option<&'static str>) {
    let (labels, i) = match kind {
        "GGA" => (GGA, 0),
        "RMC" => (RMC, 1),
        "GSA" => (GSA, 2),
        "GSV" => (GSV, 3),
        "GLL" => (GLL, 4),
        "VTG" => (VTG, 5),
        "ZDA" => (ZDA, 6),
        "VDM" => (VDM, 7),
        "VDO" => (VDM, 8),
        "TXT" => (&[] as super::Labels, 9),
        "HDT" => (&[] as super::Labels, 10),
        _ => (&[] as super::Labels, 99),
    };
    (labels, lookup(SENTENCES, i))
}

/// `ddmm.mmmm` with a hemisphere as signed decimal degrees.
fn nmea_degrees(value: &str, hemi: &str) -> Option<f64> {
    let v: f64 = value.parse().ok()?;
    let deg = (v / 100.0).trunc();
    let d = deg + (v - deg * 100.0) / 60.0;
    Some(if matches!(hemi, "S" | "W") { -d } else { d })
}

async fn nmea(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut annotated = false;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let Some((address, valid)) = nmea_sentence(&line.bytes) else {
            cx.push(
                Node::new(format!("Line {}", line.number))
                    .span(line.span)
                    .value(text(line.text())),
            )
            .await;
            continue;
        };
        let address = String::from_utf8_lossy(address).into_owned();
        let (talker, kind) = if address.len() == 5 && !address.starts_with('P') {
            (
                address.get(..2).unwrap_or_default().to_owned(),
                address.get(2..).unwrap_or_default().to_owned(),
            )
        } else {
            (String::new(), address.clone())
        };
        if !annotated {
            cx.annotate(format!("NMEA 0183 log, first sentence {address}"));
            annotated = true;
        }
        let (labels, title) = sentence_info(&kind);
        let t = line.text();
        let fields: Vec<&str> = t.split('*').next().unwrap_or_default().split(',').collect();
        let get = |i: usize| fields.get(i).copied().unwrap_or_default();
        let position = match kind.as_str() {
            "GGA" => nmea_degrees(get(2), get(3)).zip(nmea_degrees(get(4), get(5))),
            "RMC" => nmea_degrees(get(3), get(4)).zip(nmea_degrees(get(5), get(6))),
            "GLL" => nmea_degrees(get(1), get(2)).zip(nmea_degrees(get(3), get(4))),
            _ => None,
        };
        let mut summary = title.map_or_else(|| kind.clone(), str::to_owned);
        if !talker.is_empty() {
            summary = format!("{summary} ({talker})");
        }
        if let Some((lat, lon)) = position {
            summary = format!("{summary}, {lat:.6}°, {lon:.6}°");
        }
        let body = line
            .bytes
            .iter()
            .rposition(|&b| b == b'*')
            .map_or(line.span, |star| line.span.sub(0, to_u64(star)));
        let mut node = super::delimited_span(address, body, b',', labels)
            .span(line.span)
            .summary(summary);
        if !valid {
            node = node.diag(Diagnostic::warning("checksum mismatch"));
        }
        cx.push(node).await;
    }
    Ok(())
}
