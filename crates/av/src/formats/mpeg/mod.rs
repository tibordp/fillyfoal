//! MPEG-1/MPEG-2 systems and video: transport streams (`ts`), program
//! streams (`ps`) and elementary video streams (`video`). This module holds
//! what they share: stream IDs, PES headers and 90 kHz timestamps.

pub mod mpeg4;
pub mod ps;
pub mod si;
pub mod ts;
pub mod video;

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::formats::util::vidutil::{enumerated, flag_node, hex, uint};
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
        0xf4..=0xf8 => format!(
            "H.222.1 type {} stream",
            char::from(b'A'.saturating_add(id.saturating_sub(0xf4)))
        ),
        0xf9 => "Ancillary stream".to_owned(),
        0xfa => "SL-packetized stream".to_owned(),
        0xfb => "FlexMux stream".to_owned(),
        0xfc => "Metadata stream".to_owned(),
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
    let end = 9usize.saturating_add(header_len.into());
    let mut at = 9usize.saturating_add(if dts.is_some() {
        10
    } else if pts.is_some() {
        5
    } else {
        0
    });
    let pos = |a: usize| crate::bytes::to_u64(a);
    if b7 & 0x20 != 0 && at.saturating_add(6) <= end {
        if let Some(e) = d.get(at..at.saturating_add(6)) {
            let b = |i: usize| e.get(i).copied().map_or(0, u64::from);
            let base = ((b(0) >> 3) & 7) << 30
                | (b(0) & 3) << 28
                | b(1) << 20
                | (b(2) >> 3) << 15
                | (b(2) & 3) << 13
                | b(3) << 5
                | b(4) >> 3;
            let ext = (b(4) & 3) << 7 | b(5) >> 1;
            cx.emit(
                uint("ESCR", span.sub(pos(at), 6), base, 33)
                    .summary(format!("{}, extension {ext}", seconds_90k(base))),
            );
        }
        at = at.saturating_add(6);
    }
    if b7 & 0x10 != 0 && at.saturating_add(3) <= end {
        let rate = (crate::bytes::u24_be(d, at).unwrap_or(0) >> 1) & 0x3f_ffff;
        cx.emit(
            uint("ES rate", span.sub(pos(at), 3), rate.into(), 22)
                .summary(format!("{} bytes/s", u64::from(rate).saturating_mul(50))),
        );
        at = at.saturating_add(3);
    }
    if b7 & 0x08 != 0 && at < end {
        let t = d.get(at).copied().unwrap_or(0);
        cx.emit(enumerated(
            "Trick mode control",
            span.sub(pos(at), 1),
            (t >> 5).into(),
            3,
            TRICK_MODES,
        ));
        at = at.saturating_add(1);
    }
    if b7 & 0x04 != 0 && at < end {
        let c = d.get(at).copied().unwrap_or(0) & 0x7f;
        cx.emit(hex(
            "Additional copy info",
            span.sub(pos(at), 1),
            c.into(),
            7,
        ));
        at = at.saturating_add(1);
    }
    if b7 & 0x02 != 0 && at.saturating_add(2) <= end {
        let c = u16_be(d, at).unwrap_or(0);
        cx.emit(hex("Previous PES CRC", span.sub(pos(at), 2), c.into(), 16));
        at = at.saturating_add(2);
    }
    if b7 & 0x01 != 0 && at < end {
        at = pes_extension(cx, span, d, at, end);
    }
    if end > at {
        cx.emit(
            Node::new("Stuffing")
                .span(span.sub(pos(at), pos(end.saturating_sub(at))))
                .summary(format!("{} bytes", end.saturating_sub(at))),
        );
    }
    (pos(end), len)
}

const TRICK_MODES: EnumTable = &[
    (0, "fast forward"),
    (1, "slow motion"),
    (2, "freeze frame"),
    (3, "fast reverse"),
    (4, "slow reverse"),
];

/// The PES extension: flags, then the fields they announce. Returns where
/// it ends.
fn pes_extension(cx: &Cx, span: Span, d: &[u8], start: usize, end: usize) -> usize {
    let pos = |a: usize| crate::bytes::to_u64(a);
    let flags = d.get(start).copied().unwrap_or(0);
    let mut set = Vec::new();
    for (bit, name) in [
        (0x80, "PES_PRIVATE_DATA"),
        (0x40, "PACK_HEADER"),
        (0x20, "SEQUENCE_COUNTER"),
        (0x10, "P_STD_BUFFER"),
        (0x01, "EXTENSION_2"),
    ] {
        if flags & bit != 0 {
            set.push(name);
        }
    }
    cx.emit(
        Node::new("PES extension flags")
            .span(span.sub(pos(start), 1))
            .value(Value::Flags {
                raw: flags.into(),
                bits: 8,
                set,
                unknown: 0,
            }),
    );
    let mut at = start.saturating_add(1);
    if flags & 0x80 != 0 {
        cx.emit(Node::new("PES private data").span(span.sub(pos(at), 16)));
        at = at.saturating_add(16);
    }
    if flags & 0x40 != 0 {
        let n = usize::from(d.get(at).copied().unwrap_or(0));
        cx.emit(
            Node::new("Pack header field")
                .span(span.sub(pos(at), pos(n.saturating_add(1))))
                .summary(format!("{n} bytes")),
        );
        at = at.saturating_add(1).saturating_add(n);
    }
    if flags & 0x20 != 0 {
        let c = d.get(at).copied().unwrap_or(0) & 0x7f;
        cx.emit(uint(
            "Program packet sequence counter",
            span.sub(pos(at), 2),
            c.into(),
            7,
        ));
        at = at.saturating_add(2);
    }
    if flags & 0x10 != 0 {
        let w = u16_be(d, at).unwrap_or(0);
        let scale = if w & 0x2000 != 0 { 1024u64 } else { 128 };
        cx.emit(
            uint(
                "P-STD buffer size",
                span.sub(pos(at), 2),
                (w & 0x1fff).into(),
                13,
            )
            .summary(format!(
                "{} bytes",
                u64::from(w & 0x1fff).saturating_mul(scale)
            )),
        );
        at = at.saturating_add(2);
    }
    if flags & 0x01 != 0 && at < end {
        let n = usize::from(d.get(at).copied().unwrap_or(0) & 0x7f);
        let field = span.sub(pos(at), pos(n.saturating_add(1)));
        let mut node = Node::new("PES extension 2").span(field);
        if n > 0 && d.get(at.saturating_add(1)).is_some_and(|b| b & 0x80 == 0) {
            let id = d.get(at.saturating_add(1)).copied().unwrap_or(0) & 0x7f;
            node = node.summary(format!("stream ID extension {id:#04x}"));
        }
        cx.emit(node);
        at = at.saturating_add(1).saturating_add(n);
    }
    at.min(end)
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
