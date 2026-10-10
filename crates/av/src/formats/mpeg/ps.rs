//! MPEG program streams: MPEG-1 system streams (ISO 11172-1) and MPEG-2
//! program streams (ISO 13818-1, DVD VOB). A sequence of pack headers,
//! system headers and PES packets, listed in pages.
//!
//! PES packets decode their header; private stream 1 packets also their
//! DVD sub-stream header (AC-3, DTS, LPCM, subpictures), and private
//! stream 2 the DVD navigation packets. The first packet of each stream
//! gives its codec details for the file summary.

use std::collections::BTreeMap;

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::{self, flag_node, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

use super::{mpeg1_pts, pes_header, pes_times, seconds_90k, stream_id_name};

pub static MPEG2_PS: Format = Format {
    name: "mpeg-ps",
    title: "MPEG-2 program stream",
    extensions: &["vob", "mpg", "mpeg", "ps", "evo", "vro"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| pack_kind(h) == Some(2)),
    dissect: crate::expander!(dissect: Input),
};

pub static MPEG1_SYSTEM: Format = Format {
    name: "mpeg1-system",
    title: "MPEG-1 system stream",
    extensions: &["mpg", "mpeg", "m1s", "dat"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| pack_kind(h) == Some(1)),
    dissect: crate::expander!(dissect: Input),
};

/// 1 for an MPEG-1 pack header at offset 0, 2 for MPEG-2.
fn pack_kind(h: &Head<'_>) -> Option<u8> {
    if !h.starts_with(b"\x00\x00\x01\xba") {
        return None;
    }
    let b = *h.data.get(4)?;
    if b & 0xc4 == 0x44 {
        // MPEG-2: '01' + marker bits at fixed positions.
        let ok = h.data.get(6).is_some_and(|x| x & 4 != 0)
            && h.data.get(8).is_some_and(|x| x & 4 != 0)
            && h.data.get(9).is_some_and(|x| x & 1 != 0);
        return ok.then_some(2);
    }
    if b & 0xf1 == 0x21 {
        let ok = h.data.get(6).is_some_and(|x| x & 1 != 0)
            && h.data.get(8).is_some_and(|x| x & 1 != 0)
            && h.data.get(9).is_some_and(|x| x & 0x80 != 0);
        return ok.then_some(1);
    }
    None
}

/// SCR of a pack header (`d` starts at `00 00 01 BA`), in 90 kHz ticks,
/// with the MPEG-2 extension in 27 MHz units if present.
fn scr(d: &[u8]) -> Option<(u64, Option<u64>)> {
    let b4 = *d.get(4)?;
    if b4 & 0xc0 == 0x40 {
        let b = |i: usize| d.get(i).copied().map(u64::from);
        let base = ((b(4)? >> 3) & 7) << 30
            | (b(4)? & 3) << 28
            | b(5)? << 20
            | (b(6)? >> 3) << 15
            | (b(6)? & 3) << 13
            | b(7)? << 5
            | b(8)? >> 3;
        let ext = (b(8)? & 3) << 7 | b(9)? >> 1;
        Some((base, Some(ext)))
    } else {
        super::timestamp(d.get(4..9)?).map(|t| (t, None))
    }
}

/// Length of the unit starting with `d` (a start code).
fn unit_len(d: &[u8]) -> Option<u64> {
    let code = *d.get(3)?;
    match code {
        0xba => {
            let b4 = *d.get(4)?;
            if b4 & 0xc0 == 0x40 {
                Some(14u64.saturating_add(u64::from(d.get(13)? & 7)))
            } else {
                Some(12)
            }
        }
        0xb9 => Some(4),
        0xbb..=0xff => Some(6u64.saturating_add(u16_be(d, 4)?.into())),
        _ => None,
    }
}

/// Where the payload of a PES packet starting with `d` begins.
fn payload_offset(d: &[u8]) -> u64 {
    let id = d.get(3).copied().unwrap_or(0);
    if !super::has_optional_header(id) {
        return 6;
    }
    if d.get(6).is_some_and(|b| b & 0xc0 == 0x80) {
        return 9u64.saturating_add(d.get(8).copied().unwrap_or(0).into());
    }
    // MPEG-1: stuffing, STD buffer, timestamps.
    let mut at = 6usize;
    while d.get(at) == Some(&0xff) && at < 22 {
        at = at.saturating_add(1);
    }
    if d.get(at).is_some_and(|b| b & 0xc0 == 0x40) {
        at = at.saturating_add(2);
    }
    let skip = match d.get(at).map(|b| b >> 4) {
        Some(2) => 5,
        Some(3) => 10,
        _ => 1,
    };
    crate::bytes::to_u64(at.saturating_add(skip))
}

const SUBSTREAM_KINDS: EnumTable = &[
    (0x20, "subpicture"),
    (0x80, "AC-3"),
    (0x88, "DTS"),
    (0x90, "SDDS"),
    (0xa0, "LPCM"),
    (0xc0, "E-AC-3"),
];

/// The kind of a DVD private stream 1 sub-stream.
fn substream(id: u8) -> Option<(&'static str, u8)> {
    Some(match id {
        0x20..=0x3f => ("subpicture", id & 0x1f),
        0x80..=0x87 => ("AC-3", id & 7),
        0x88..=0x8f => ("DTS", id & 7),
        0x90..=0x97 => ("SDDS", id & 7),
        0xa0..=0xa7 => ("LPCM", id & 7),
        0xc0..=0xc7 => ("E-AC-3", id & 7),
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug)]
struct Unit {
    span: Span,
    code: u8,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.annotate(
        summary(&cx, file)
            .await?
            .unwrap_or_else(|| "MPEG program stream".to_owned()),
    );
    let mut pos = cx.resume::<u64>().unwrap_or(0);
    while pos < file.len {
        let d = cx.read_avail(file.sub(pos, 32)).await?;
        let len = if d.starts_with(&[0, 0, 1]) {
            unit_len(&d)
        } else {
            None
        };
        let at = pos;
        cx.mark(move || at);
        let Some(len) = len.filter(|&l| l > 0) else {
            // Resynchronise at the next start code.
            let next = vidutil::next_start_code(&cx, file, pos.saturating_add(1)).await?;
            let end = next.unwrap_or(file.len);
            cx.push(
                Node::new("Unparsed data")
                    .span(file.sub(pos, end.saturating_sub(pos)))
                    .diag(Diagnostic::malformed("expected a start code")),
            )
            .await;
            pos = end;
            continue;
        };
        let code = d.get(3).copied().unwrap_or(0);
        let unit = Unit {
            span: file.sub(pos, len),
            code,
        };
        let mut name = stream_id_name(code);
        if code == 0xbd
            && let Some((kind, n)) = d
                .get(vidutil::us(payload_offset(&d)))
                .and_then(|&b| substream(b))
        {
            name = format!("Private stream 1 ({kind} {n})");
        }
        if code == 0xbf {
            match d.get(6) {
                Some(0) => name = "Private stream 2 (PCI)".to_owned(),
                Some(1) => name = "Private stream 2 (DSI)".to_owned(),
                _ => {}
            }
        }
        let mut node = Node::new(name)
            .span(unit.span)
            .summary(unit_summary(&d, len))
            .lazy(expand_unit, unit);
        if unit.span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, unit.span.offset, len),
                unit.span.len,
            ));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(len);
        if code == 0xb9 && pos < file.len {
            cx.push(Node::new("Trailing data").span(file.tail(pos)))
                .await;
            break;
        }
    }
    Ok(())
}

fn unit_summary(d: &[u8], len: u64) -> String {
    let code = d.get(3).copied().unwrap_or(0);
    match code {
        0xba => match scr(d) {
            Some((base, _)) => {
                let mpeg2 = d.get(4).is_some_and(|b| b & 0xc0 == 0x40);
                let rate = if mpeg2 {
                    crate::bytes::u24_be(d, 10).unwrap_or(0) >> 2
                } else {
                    (crate::bytes::u24_be(d, 9).unwrap_or(0) >> 1) & 0x3f_ffff
                };
                format!(
                    "{}, SCR {}, mux rate {} kb/s",
                    if mpeg2 { "MPEG-2" } else { "MPEG-1" },
                    seconds_90k(base),
                    u64::from(rate).saturating_mul(400) / 1000
                )
            }
            None => String::new(),
        },
        0xbb => format!("{len} bytes"),
        0xb9 => "end".to_owned(),
        _ => {
            let pts = if d.get(6).is_some_and(|b| b & 0xc0 == 0x80) {
                pes_times(d).0
            } else if super::has_optional_header(code) {
                mpeg1_pts(d)
            } else {
                None
            };
            match pts {
                Some(p) => format!("{len} bytes, PTS {}", seconds_90k(p)),
                None => format!("{len} bytes"),
            }
        }
    }
}

async fn expand_unit(cx: Cx, unit: Unit) -> Result<()> {
    let span = unit.span;
    let d = cx.read_avail(span.sub(0, 0x400)).await?;
    match unit.code {
        0xba => pack_header(&cx, span, &d),
        0xbb => system_header(&cx, span, &d),
        0xbc => stream_map(&cx, span, &d),
        0xb9 => cx.emit(hex("End code", span, 0x1b9, 32)),
        0xbe => {
            cx.emit(hex("Start code", span.sub(0, 4), 0x1be, 32));
            cx.emit(uint(
                "PES packet length",
                span.sub(4, 2),
                u16_be(&d, 4).unwrap_or(0).into(),
                16,
            ));
            cx.emit(Node::new("Padding").span(span.tail(6)));
        }
        _ => {
            let (header, _) = pes_header(&cx, span, &d);
            let payload = span.tail(header);
            let data = d.get(vidutil::us(header)..).unwrap_or_default();
            if unit.code == 0xbd {
                private_1(&cx, payload, data);
            } else if unit.code == 0xbf {
                private_2(&cx, payload, data);
            } else {
                let mut node = Node::new("Payload")
                    .span(payload)
                    .summary(format!("{} bytes", payload.len));
                if let Some(s) = es_detail(unit.code, data) {
                    node = node.summary(format!("{s}, {} bytes", payload.len));
                }
                cx.emit(node);
            }
        }
    }
    Ok(())
}

/// A DVD private stream 1 payload: sub-stream header, then data.
fn private_1(cx: &Cx, payload: Span, d: &[u8]) {
    let Some(&id) = d.first() else {
        return;
    };
    let Some((kind, _)) = substream(id) else {
        cx.emit(
            Node::new("Payload")
                .span(payload)
                .summary(format!("{} bytes", payload.len)),
        );
        return;
    };
    let mut w = Walker::new(
        d.get(..d.len().min(16)).unwrap_or_default(),
        payload,
        false,
        true,
    );
    let header = (|| -> Option<u64> {
        w.en("substream_id", 8, SUBSTREAM_KINDS)?;
        w.with(|n| n.summary(format!("{kind} {}", id & 7)));
        match kind {
            "AC-3" | "DTS" | "E-AC-3" | "SDDS" => {
                w.u("number_of_frame_headers", 8)?;
                w.u("first_access_unit_pointer", 16)?;
                Some(4)
            }
            "LPCM" => {
                w.u("number_of_frame_headers", 8)?;
                w.u("first_access_unit_pointer", 16)?;
                w.flag("audio_emphasis")?;
                w.flag("audio_mute")?;
                w.u("reserved", 1)?;
                w.u("audio_frame_number", 5)?;
                w.en(
                    "quantization",
                    2,
                    &[(0, "16-bit"), (1, "20-bit"), (2, "24-bit")],
                )?;
                w.en("sampling_frequency", 2, &[(0, "48 kHz"), (1, "96 kHz")])?;
                w.u("reserved", 1)?;
                let ch = w.u("number_of_audio_channels_minus1", 3)?;
                w.summary(|| format!("{} channels", ch.saturating_add(1)));
                w.x("dynamic_range_control", 8)?;
                Some(7)
            }
            _ => Some(1),
        }
    })();
    let ok = header.is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    let skip = header.unwrap_or(1);
    let data = payload.tail(skip);
    let mut node = Node::new(format!("{kind} data"))
        .span(data)
        .summary(format!("{} bytes", data.len));
    if matches!(kind, "AC-3" | "DTS" | "E-AC-3")
        && let Some(s) = d
            .get(vidutil::us(skip)..)
            .and_then(vidutil::audio::es_summary)
    {
        node = node.summary(format!("{s}, {} bytes", data.len));
    }
    cx.emit(node);
}

/// A DVD navigation packet (private stream 2): PCI or DSI.
fn private_2(cx: &Cx, payload: Span, d: &[u8]) {
    let mut w = Walker::new(
        d.get(..d.len().min(32)).unwrap_or_default(),
        payload,
        false,
        true,
    );
    let ok = (|| -> Option<()> {
        let id = w.en("substream_id", 8, &[(0, "PCI"), (1, "DSI")])?;
        w.x(if id == 0 { "nv_pck_lbn" } else { "nv_pck_scr" }, 32)?;
        if id == 0 {
            w.x("vobu_cat", 16)?;
            w.x("reserved", 16)?;
            w.x("vobu_uop_ctl", 32)?;
            let s = w.u("vobu_s_ptm", 32)?;
            w.summary(|| seconds_90k(s));
            let e = w.u("vobu_e_ptm", 32)?;
            w.summary(|| seconds_90k(e));
        } else {
            w.x("nv_pck_lbn", 32)?;
            w.u("vobu_ea", 32)?;
        }
        Some(())
    })()
    .is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    cx.emit(
        Node::new("Navigation data")
            .span(payload)
            .summary(format!("{} bytes", payload.len)),
    );
}

fn pack_header(cx: &Cx, span: Span, d: &[u8]) {
    cx.emit(hex("Start code", span.sub(0, 4), 0x1ba, 32));
    let mpeg2 = d.get(4).is_some_and(|b| b & 0xc0 == 0x40);
    if let Some((base, ext)) = scr(d) {
        let scr_span = span.sub(4, if mpeg2 { 6 } else { 5 });
        cx.emit(uint("SCR base", scr_span, base, 33).summary(seconds_90k(base)));
        if let Some(e) = ext {
            cx.emit(uint("SCR extension", scr_span, e, 9).summary("27 MHz units"));
        }
    }
    if mpeg2 {
        let rate = crate::bytes::u24_be(d, 10).unwrap_or(0) >> 2;
        cx.emit(
            uint("Program mux rate", span.sub(10, 3), rate.into(), 22)
                .summary(format!("{} bytes/s", u64::from(rate).saturating_mul(50))),
        );
        let stuffing = d.get(13).copied().unwrap_or(0) & 7;
        cx.emit(uint("Stuffing length", span.sub(13, 1), stuffing.into(), 3));
        if stuffing > 0 {
            cx.emit(Node::new("Stuffing").span(span.sub(14, stuffing.into())));
        }
    } else {
        let rate = (crate::bytes::u24_be(d, 9).unwrap_or(0) >> 1) & 0x3f_ffff;
        cx.emit(
            uint("Mux rate", span.sub(9, 3), rate.into(), 22)
                .summary(format!("{} bytes/s", u64::from(rate).saturating_mul(50))),
        );
    }
}

fn system_header(cx: &Cx, span: Span, d: &[u8]) {
    cx.emit(hex("Start code", span.sub(0, 4), 0x1bb, 32));
    let len = u16_be(d, 4).unwrap_or(0);
    cx.emit(uint("Header length", span.sub(4, 2), len.into(), 16));
    let rate = (crate::bytes::u24_be(d, 6).unwrap_or(0) >> 1) & 0x3f_ffff;
    cx.emit(
        uint("Rate bound", span.sub(6, 3), rate.into(), 22)
            .summary(format!("{} bytes/s", u64::from(rate).saturating_mul(50))),
    );
    let b9 = d.get(9).copied().unwrap_or(0);
    cx.emit(uint("Audio bound", span.sub(9, 1), (b9 >> 2).into(), 6));
    cx.emit(flag_node("Fixed bitrate", span.sub(9, 1), b9 & 2 != 0));
    cx.emit(flag_node(
        "Constrained parameters",
        span.sub(9, 1),
        b9 & 1 != 0,
    ));
    let b10 = d.get(10).copied().unwrap_or(0);
    cx.emit(flag_node(
        "System audio lock",
        span.sub(10, 1),
        b10 & 0x80 != 0,
    ));
    cx.emit(flag_node(
        "System video lock",
        span.sub(10, 1),
        b10 & 0x40 != 0,
    ));
    cx.emit(uint("Video bound", span.sub(10, 1), (b10 & 0x1f).into(), 5));
    let b11 = d.get(11).copied().unwrap_or(0);
    cx.emit(flag_node(
        "Packet rate restriction",
        span.sub(11, 1),
        b11 & 0x80 != 0,
    ));
    let end = usize::from(len).saturating_add(6).min(d.len());
    let mut at = 12usize;
    while at.saturating_add(3) <= end {
        let id = d.get(at).copied().unwrap_or(0);
        if id & 0x80 == 0 {
            break;
        }
        let w = u16_be(d, at.saturating_add(1)).unwrap_or(0);
        let scale = if w & 0x2000 != 0 { 1024 } else { 128 };
        let name = match id {
            0xb8 => "All audio streams".to_owned(),
            0xb9 => "All video streams".to_owned(),
            _ => stream_id_name(id),
        };
        cx.emit(
            hex(name, vidutil::at(span, at, 3), id.into(), 8).summary(format!(
                "P-STD buffer {} bytes",
                u64::from(w & 0x1fff).saturating_mul(scale)
            )),
        );
        at = at.saturating_add(3);
    }
}

/// `program_stream_map()`.
fn stream_map(cx: &Cx, span: Span, d: &[u8]) {
    cx.emit(hex("Start code", span.sub(0, 4), 0x1bc, 32));
    let body = d.get(4..).unwrap_or_default();
    let mut w = Walker::new(body, span.tail(4), false, true);
    let ok = (|| -> Option<()> {
        let len = w.u("program_stream_map_length", 16)?;
        w.flag("current_next_indicator")?;
        w.u("single_extension_stream_flag", 1)?;
        w.u("reserved", 1)?;
        w.u("program_stream_map_version", 5)?;
        w.u("reserved", 7)?;
        w.u("marker_bit", 1)?;
        let info = usize::try_from(w.u("program_stream_info_length", 16)?).ok()?;
        super::si::descriptor_loop(&mut w, info)?;
        let map = usize::try_from(w.u("elementary_stream_map_length", 16)?).ok()?;
        let end = w.pos().saturating_add(map.saturating_mul(8));
        while w.pos().saturating_add(32) <= end {
            w.begin("Elementary stream");
            let t = w.en("stream_type", 8, super::si::STREAM_TYPES)?;
            let id = u8::try_from(w.x("elementary_stream_id", 8)?).ok()?;
            let n = usize::try_from(w.u("elementary_stream_info_length", 16)?).ok()?;
            super::si::descriptor_loop(&mut w, n)?;
            w.end_summary(|| {
                format!(
                    "{}: {}",
                    stream_id_name(id),
                    vidutil::lookup_or(super::si::STREAM_TYPES, t)
                )
            });
        }
        let crc_at = usize::try_from(len)
            .ok()?
            .saturating_add(2)
            .saturating_sub(4);
        w.seek(crc_at.saturating_mul(8));
        w.x("CRC_32", 32)?;
        Some(())
    })()
    .is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
}

/// Codec details from the start of a PES payload of stream `id`.
fn es_detail(id: u8, d: &[u8]) -> Option<String> {
    match id {
        0xe0..=0xef => super::video::es_summary(d)
            .or_else(|| super::mpeg4::es_summary(d).map(|s| format!("MPEG-4 Visual, {s}")))
            .or_else(|| h264_detail(d)),
        0xc0..=0xdf => vidutil::audio::es_summary(d),
        _ => None,
    }
}

/// "LPCM, 16-bit, 48 kHz, 2 channels" from a DVD LPCM sub-stream header
/// (`d` starts at the sub-stream ID).
fn lpcm_summary(d: &[u8]) -> Option<String> {
    let b = *d.get(5)?;
    let bits = [16, 20, 24].get(usize::from(b >> 6))?;
    let rate = [48, 96].get(usize::from((b >> 4) & 3))?;
    let channels = (b & 7).saturating_add(1);
    Some(format!(
        "LPCM, {bits}-bit, {rate} kHz, {}",
        vidutil::plural(channels, "channel")
    ))
}

/// An H.264 SPS among the first NAL units of `d`.
fn h264_detail(d: &[u8]) -> Option<String> {
    let mut at = 0usize;
    for _ in 0..32 {
        let i = vidutil::find(d.get(at..)?, &[0, 0, 1])?;
        let start = at.saturating_add(i).saturating_add(3);
        let unit = d.get(start..)?;
        if unit.first().is_some_and(|b| b & 0x1f == 7) {
            let len = vidutil::find(unit, &[0, 0, 1]).unwrap_or(unit.len());
            let sps = vidutil::h264_sps(unit.get(..len)?)?;
            return Some(format!("H.264, {}", sps.describe()));
        }
        at = start;
    }
    None
}

/// "MPEG-2 program stream, MPEG-2 video ... + AC-3 ..., 00:00:00.120".
async fn summary(cx: &Cx, file: Span) -> Result<Option<String>> {
    let mut streams: BTreeMap<(u8, u8), Option<String>> = BTreeMap::new();
    let mut first_scr = None;
    let mut pos = 0u64;
    let mut kind = "MPEG program stream";
    let mut dvd = false;
    for _ in 0..512 {
        let d = cx.read_avail(file.sub(pos, 32)).await?;
        if !d.starts_with(&[0, 0, 1]) {
            break;
        }
        let Some(&code) = d.get(3) else {
            break;
        };
        let Some(len) = unit_len(&d) else {
            break;
        };
        if code == 0xba {
            if first_scr.is_none() {
                first_scr = scr(&d).map(|s| s.0);
                kind = if d.get(4).is_some_and(|b| b & 0xc0 == 0x40) {
                    "MPEG-2 program stream"
                } else {
                    "MPEG-1 system stream"
                };
            }
        } else if code == 0xbf {
            dvd = true;
        } else if (0xbd..=0xef).contains(&code) && code != 0xbe {
            let header = payload_offset(&d);
            let sub = if code == 0xbd {
                d.get(vidutil::us(header)).copied().unwrap_or(0)
            } else {
                0
            };
            let key = (code, sub);
            if !streams.contains_key(&key) && streams.len() < 64 {
                let payload = file.sub(
                    pos.saturating_add(header),
                    len.saturating_sub(header).min(2048),
                );
                let data = cx.read_avail(payload).await?;
                let detail = if code == 0xbd {
                    substream(sub).map(|(k, n)| {
                        if k == "LPCM" {
                            return lpcm_summary(&data).unwrap_or_else(|| format!("LPCM {n}"));
                        }
                        match data.get(4..).and_then(vidutil::audio::es_summary) {
                            Some(s) if k != "subpicture" => s,
                            _ => format!("{k} {n}"),
                        }
                    })
                } else {
                    es_detail(code, &data)
                };
                streams.insert(key, detail);
            }
        }
        pos = pos.saturating_add(len);
        cx.checkpoint().await;
    }
    let mut parts = vec![if dvd {
        format!("{kind} (DVD)")
    } else {
        kind.to_owned()
    }];
    if !streams.is_empty() {
        let names: Vec<String> = streams
            .iter()
            .map(|(&(code, _), detail)| match detail {
                Some(d) => d.clone(),
                None => stream_id_name(code).to_lowercase(),
            })
            .collect();
        parts.push(names.join(" + "));
    }
    // The last SCR: search the tail for a pack header.
    let tail_start = file.len.saturating_sub(0x10000);
    let tail = cx.read_avail(file.tail(tail_start)).await?;
    let last = tail
        .windows(4)
        .enumerate()
        .rev()
        .filter(|(_, w)| *w == [0, 0, 1, 0xba])
        .find_map(|(i, _)| tail.get(i..).and_then(scr))
        .map(|s| s.0);
    if let (Some(a), Some(b)) = (first_scr, last)
        && b > a
    {
        parts.push(vidutil::seconds_f64(b.saturating_sub(a) as f64 / 90_000.0));
    }
    Ok(Some(parts.join(", ")))
}
