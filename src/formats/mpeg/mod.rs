//! MPEG-1/MPEG-2 systems and video: transport streams (`ts`), program
//! streams (`ps`) and elementary video streams (`video`). This module holds
//! what they share: stream IDs, PES headers and 90 kHz timestamps.

pub mod mpeg4;
pub mod ps;
pub mod ts;
pub mod video;

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::formats::vidutil::{enumerated, flag_node, hex, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

/// The name of a PES stream ID (the byte after `00 00 01`).
pub fn stream_id_name(id: u8) -> String {
    match id {
        0xb9 => "Program end".to_owned(),
        0xba => "Pack header".to_owned(),
        0xbb => "System header".to_owned(),
        0xbc => "Program stream map".to_owned(),
        0xbd => "Private stream 1".to_owned(),
        0xbe => "Padding stream".to_owned(),
        0xbf => "Private stream 2".to_owned(),
        0xc0..=0xdf => format!("Audio stream {}", id & 0x1f),
        0xe0..=0xef => format!("Video stream {}", id & 0x0f),
        0xf0 => "ECM stream".to_owned(),
        0xf1 => "EMM stream".to_owned(),
        0xf2 => "DSM-CC stream".to_owned(),
        0xf3 => "ISO/IEC 13522 stream".to_owned(),
        0xf8 => "H.222.1 type E stream".to_owned(),
        0xfd => "Extended stream ID".to_owned(),
        0xff => "Program stream directory".to_owned(),
        _ => format!("Stream {id:#04x}"),
    }
}

/// Whether a PES packet with this stream ID has the optional header.
fn has_optional_header(id: u8) -> bool {
    !matches!(id, 0xbc | 0xbe | 0xbf | 0xf0 | 0xf1 | 0xf2 | 0xf8 | 0xff)
}

/// A 33-bit timestamp from the 5-byte PTS/DTS encoding.
pub fn timestamp(d: &[u8]) -> Option<u64> {
    let b = |i: usize| d.get(i).copied().map(u64::from);
    Some(((b(0)? >> 1) & 7) << 30 | b(1)? << 22 | (b(2)? >> 1) << 15 | b(3)? << 7 | b(4)? >> 1)
}

/// 90 kHz ticks as seconds.
pub fn seconds_90k(ticks: u64) -> String {
    format!("{:.3} s", ticks as f64 / 90_000.0)
}

/// PTS and DTS of a PES header (`d` starts at `00 00 01`).
pub fn pes_times(d: &[u8]) -> (Option<u64>, Option<u64>) {
    let id = d.get(3).copied().unwrap_or(0);
    if !has_optional_header(id) || d.get(6).is_none_or(|b| b & 0xc0 != 0x80) {
        return (None, None);
    }
    let flags = d.get(7).copied().unwrap_or(0) >> 6;
    let pts = if flags & 2 != 0 {
        d.get(9..14).and_then(timestamp)
    } else {
        None
    };
    let dts = if flags == 3 {
        d.get(14..19).and_then(timestamp)
    } else {
        None
    };
    (pts, dts)
}

/// A one-line PES summary: stream and PTS.
pub fn pes_summary(d: &[u8]) -> String {
    let id = d.get(3).copied().unwrap_or(0);
    let mut s = stream_id_name(id);
    if let (Some(pts), _) = pes_times(d) {
        s = format!("{s}, PTS {}", seconds_90k(pts));
    }
    s
}

const SCRAMBLING: EnumTable = &[
    (0, "not scrambled"),
    (1, "user-defined"),
    (2, "user-defined"),
    (3, "user-defined"),
];

/// Emits the fields of a PES header at the start of `span` (whose first
/// bytes are `d`). Returns the length of the header (where the payload
/// starts) and the declared packet length.
pub fn pes_header(cx: &Cx, span: Span, d: &[u8]) -> (u64, u16) {
    let id = d.get(3).copied().unwrap_or(0);
    cx.emit(hex("Start code prefix", span.sub(0, 3), 1, 24));
    cx.emit(hex("Stream ID", span.sub(3, 1), id.into(), 8).summary(stream_id_name(id)));
    let len = u16_be(d, 4).unwrap_or(0);
    cx.emit(
        uint("PES packet length", span.sub(4, 2), len.into(), 16).summary(if len == 0 {
            "unbounded".to_owned()
        } else {
            format!("{len} bytes follow")
        }),
    );
    if !has_optional_header(id) {
        return (6, len);
    }
    let Some(&b6) = d.get(6) else {
        return (6, len);
    };
    if b6 & 0xc0 != 0x80 {
        // MPEG-1 style header: stuffing, STD buffer, timestamps.
        return (mpeg1_header(cx, span, d), len);
    }
    let s6 = span.sub(6, 1);
    cx.emit(enumerated(
        "Scrambling control",
        s6,
        ((b6 >> 4) & 3).into(),
        2,
        SCRAMBLING,
    ));
    cx.emit(flag_node("Priority", s6, b6 & 0x08 != 0));
    cx.emit(flag_node("Data alignment", s6, b6 & 0x04 != 0));
    cx.emit(flag_node("Copyright", s6, b6 & 0x02 != 0));
    cx.emit(flag_node("Original", s6, b6 & 0x01 != 0));
    let b7 = d.get(7).copied().unwrap_or(0);
    let mut set = Vec::new();
    for (bit, name) in [
        (0x80, "PTS"),
        (0x40, "DTS"),
        (0x20, "ESCR"),
        (0x10, "ES_RATE"),
        (0x08, "DSM_TRICK_MODE"),
        (0x04, "ADDITIONAL_COPY_INFO"),
        (0x02, "CRC"),
        (0x01, "EXTENSION"),
    ] {
        if b7 & bit != 0 {
            set.push(name);
        }
    }
    cx.emit(Node::new("Flags").span(span.sub(7, 1)).value(Value::Flags {
        raw: b7.into(),
        bits: 8,
        set,
        unknown: 0,
    }));
    let header_len = d.get(8).copied().unwrap_or(0);
    cx.emit(uint(
        "PES header data length",
        span.sub(8, 1),
        header_len.into(),
        8,
    ));
    let (pts, dts) = pes_times(d);
    if let Some(p) = pts {
        cx.emit(uint("PTS", span.sub(9, 5), p, 33).summary(seconds_90k(p)));
    }
    if let Some(t) = dts {
        cx.emit(uint("DTS", span.sub(14, 5), t, 33).summary(seconds_90k(t)));
    }
    let used = if dts.is_some() {
        10
    } else if pts.is_some() {
        5
    } else {
        0
    };
    if u64::from(header_len) > used {
        cx.emit(Node::new("Optional fields / stuffing").span(span.sub(
            9u64.saturating_add(used),
            u64::from(header_len).saturating_sub(used),
        )));
    }
    (9u64.saturating_add(header_len.into()), len)
}

/// MPEG-1 packet header after the length: stuffing bytes, optional STD
/// buffer size and PTS/DTS. Returns the payload offset.
fn mpeg1_header(cx: &Cx, span: Span, d: &[u8]) -> u64 {
    let mut at = 6usize;
    while d.get(at) == Some(&0xff) && at < 22 {
        at = at.saturating_add(1);
    }
    if at > 6 {
        cx.emit(
            Node::new("Stuffing").span(span.sub(6, crate::bytes::to_u64(at.saturating_sub(6)))),
        );
    }
    if d.get(at).is_some_and(|b| b & 0xc0 == 0x40) {
        let size = u16_be(d, at).unwrap_or(0);
        cx.emit(
            uint(
                "STD buffer size",
                span.sub(crate::bytes::to_u64(at), 2),
                (size & 0x1fff).into(),
                13,
            )
            .summary(format!("scale {}", (size >> 13) & 1)),
        );
        at = at.saturating_add(2);
    }
    let b = d.get(at).copied().unwrap_or(0);
    let pos = crate::bytes::to_u64(at);
    match b >> 4 {
        2 => {
            if let Some(p) = d.get(at..at.saturating_add(5)).and_then(timestamp) {
                cx.emit(uint("PTS", span.sub(pos, 5), p, 33).summary(seconds_90k(p)));
            }
            at = at.saturating_add(5);
        }
        3 => {
            if let Some(p) = d.get(at..at.saturating_add(5)).and_then(timestamp) {
                cx.emit(uint("PTS", span.sub(pos, 5), p, 33).summary(seconds_90k(p)));
            }
            if let Some(t) = d
                .get(at.saturating_add(5)..at.saturating_add(10))
                .and_then(timestamp)
            {
                cx.emit(
                    uint("DTS", span.sub(pos.saturating_add(5), 5), t, 33).summary(seconds_90k(t)),
                );
            }
            at = at.saturating_add(10);
        }
        _ => at = at.saturating_add(1),
    }
    crate::bytes::to_u64(at)
}

/// MPEG-1 style PTS for summaries (`d` starts at `00 00 01`).
pub fn mpeg1_pts(d: &[u8]) -> Option<u64> {
    let mut at = 6usize;
    while d.get(at) == Some(&0xff) && at < 22 {
        at = at.saturating_add(1);
    }
    if d.get(at).is_some_and(|b| b & 0xc0 == 0x40) {
        at = at.saturating_add(2);
    }
    let b = d.get(at).copied()?;
    if b >> 4 == 2 || b >> 4 == 3 {
        d.get(at..at.saturating_add(5)).and_then(timestamp)
    } else {
        None
    }
}
