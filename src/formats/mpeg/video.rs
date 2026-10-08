//! MPEG-1 and MPEG-2 video elementary streams (ISO 11172-2, 13818-2).
//!
//! The stream is cut at start codes into units: sequence headers and
//! extensions, GOP headers, pictures, user data. Consecutive slices are
//! grouped into one node. Units are listed in pages.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::vidutil::{self, Bits, enumerated, flag_node, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static MPEG1_VIDEO: Format = Format {
    name: "mpeg1video",
    title: "MPEG-1 video elementary stream",
    extensions: &["m1v", "mpv"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| sequence_header(h) == Some(1)),
    dissect: crate::expander!(dissect: Input),
};

pub static MPEG2_VIDEO: Format = Format {
    name: "mpeg2video",
    title: "MPEG-2 video elementary stream",
    extensions: &["m2v", "mpv", "mp2v"],
    mime: "video/mpeg",
    probe: Probe::Custom(|h| sequence_header(h) == Some(2)),
    dissect: crate::expander!(dissect: Input),
};

/// 1 or 2 if the input starts with a plausible sequence header (2 when a
/// sequence extension follows).
fn sequence_header(h: &Head<'_>) -> Option<u8> {
    if !h.starts_with(b"\x00\x00\x01\xb3") {
        return None;
    }
    let info = SequenceHeader::parse(h.data.get(4..12)?)?;
    if info.width == 0
        || info.height == 0
        || !(1..=4).contains(&info.aspect)
        || !(1..=8).contains(&info.rate)
    {
        return None;
    }
    let window = h.data.get(..h.data.len().min(512))?;
    let ext = window.windows(5).any(|w| {
        w.get(..4) == Some(b"\x00\x00\x01\xb5".as_slice()) && w.get(4).is_some_and(|b| b >> 4 == 1)
    });
    Some(if ext { 2 } else { 1 })
}

const ASPECT: EnumTable = &[
    (1, "1:1 (square pixels)"),
    (2, "4:3"),
    (3, "16:9"),
    (4, "2.21:1"),
];
const FRAME_RATES: [&str; 9] = [
    "forbidden",
    "23.976",
    "24",
    "25",
    "29.97",
    "30",
    "50",
    "59.94",
    "60",
];
const PICTURE_TYPES: EnumTable = &[(1, "I"), (2, "P"), (3, "B"), (4, "D")];
const EXTENSIONS: EnumTable = &[
    (1, "sequence extension"),
    (2, "sequence display extension"),
    (3, "quant matrix extension"),
    (4, "copyright extension"),
    (5, "sequence scalable extension"),
    (7, "picture display extension"),
    (8, "picture coding extension"),
    (9, "picture spatial scalable extension"),
    (10, "picture temporal scalable extension"),
];
const PROFILES: EnumTable = &[
    (1, "High"),
    (2, "Spatially scalable"),
    (3, "SNR scalable"),
    (4, "Main"),
    (5, "Simple"),
];
const LEVELS: EnumTable = &[(4, "High"), (6, "High 1440"), (8, "Main"), (10, "Low")];
const CHROMA: EnumTable = &[(1, "4:2:0"), (2, "4:2:2"), (3, "4:4:4")];

#[derive(Clone, Copy, Debug)]
struct SequenceHeader {
    width: u64,
    height: u64,
    aspect: u64,
    rate: u64,
    bitrate: u64,
}

impl SequenceHeader {
    /// Parses the 8 bytes after the start code.
    fn parse(d: &[u8]) -> Option<Self> {
        let mut b = Bits::new(d);
        let width = b.bits(12)?;
        let height = b.bits(12)?;
        let aspect = b.bits(4)?;
        let rate = b.bits(4)?;
        let bitrate = b.bits(18)?;
        Some(SequenceHeader {
            width,
            height,
            aspect,
            rate,
            bitrate,
        })
    }

    fn describe(&self) -> String {
        format!(
            "{}×{}, {}, {} fps, {}",
            self.width,
            self.height,
            vidutil::lookup_or(ASPECT, self.aspect),
            FRAME_RATES
                .get(vidutil::us(self.rate))
                .copied()
                .unwrap_or("?"),
            bitrate(self.bitrate)
        )
    }
}

fn bitrate(v: u64) -> String {
    if v == 0x3ffff {
        "variable bit rate".to_owned()
    } else {
        format!("{} kb/s", v.saturating_mul(400) / 1000)
    }
}

/// The name of a start code's unit.
fn unit_name(code: u8) -> String {
    match code {
        0x00 => "Picture".to_owned(),
        0x01..=0xaf => "Slices".to_owned(),
        0xb2 => "User data".to_owned(),
        0xb3 => "Sequence header".to_owned(),
        0xb4 => "Sequence error".to_owned(),
        0xb5 => "Extension".to_owned(),
        0xb7 => "Sequence end".to_owned(),
        0xb8 => "Group of pictures".to_owned(),
        _ => format!("Start code {code:#04x}"),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 512)).await?;
    if let Some(seq) = head.get(4..12).and_then(SequenceHeader::parse) {
        let mut s = format!("MPEG video, {}", seq.describe());
        if let Some(at) = vidutil::find(&head, b"\x00\x00\x01\xb5")
            && let Some(&b) = head.get(at.saturating_add(4))
            && b >> 4 == 1
        {
            let pl2 = head.get(at.saturating_add(5)).copied().unwrap_or(0) >> 4;
            s = format!(
                "MPEG-2 video, {}@{}, {}",
                vidutil::lookup_or(PROFILES, (b & 7).into()),
                vidutil::lookup_or(LEVELS, pl2.into()),
                seq.describe()
            );
        } else {
            s = format!("MPEG-1 video, {}", seq.describe());
        }
        cx.annotate(s);
    }
    let mut pos = match vidutil::next_start_code(&cx, file, 0).await? {
        Some(p) => p,
        None => return Ok(()),
    };
    if pos > 0 {
        cx.emit(Node::new("Leading data").span(file.sub(0, pos)));
    }
    while pos < file.len {
        let code = cx
            .read_avail(file.sub(pos.saturating_add(3), 1))
            .await?
            .first()
            .copied()
            .unwrap_or(0);
        let mut end = vidutil::next_start_code(&cx, file, pos.saturating_add(3))
            .await?
            .unwrap_or(file.len);
        let mut slices = 1u64;
        if (0x01..=0xaf).contains(&code) {
            // Group consecutive slices.
            while end < file.len {
                let next = cx.read_avail(file.sub(end.saturating_add(3), 1)).await?;
                if !next.first().is_some_and(|c| (0x01..=0xaf).contains(c)) {
                    break;
                }
                end = vidutil::next_start_code(&cx, file, end.saturating_add(3))
                    .await?
                    .unwrap_or(file.len);
                slices = slices.saturating_add(1);
            }
        }
        let span = file.sub(pos, end.saturating_sub(pos));
        let d = cx.read_avail(span.sub(0, 16)).await?;
        let summary = summary(code, &d, slices);
        let mut node = Node::new(unit_name(code)).span(span);
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if matches!(code, 0x00 | 0xb3 | 0xb5 | 0xb8) {
            node = node.lazy(expand_unit, (span, code));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        pos = end.max(pos.saturating_add(4));
    }
    Ok(())
}

fn summary(code: u8, d: &[u8], slices: u64) -> String {
    let body = d.get(4..).unwrap_or_default();
    match code {
        0x00 => {
            let mut b = Bits::new(body);
            let tr = b.bits(10).unwrap_or(0);
            let t = b.bits(3).unwrap_or(0);
            format!(
                "{} picture, temporal reference {tr}",
                vidutil::lookup_or(PICTURE_TYPES, t)
            )
        }
        0x01..=0xaf => vidutil::plural(slices, "slice"),
        0xb3 => SequenceHeader::parse(body)
            .map(|s| s.describe())
            .unwrap_or_default(),
        0xb5 => vidutil::lookup_or(EXTENSIONS, (body.first().copied().unwrap_or(0) >> 4).into()),
        0xb8 => {
            let mut b = Bits::new(body);
            let drop = b.bit().unwrap_or(0);
            let h = b.bits(5).unwrap_or(0);
            let m = b.bits(6).unwrap_or(0);
            b.bit();
            let s = b.bits(6).unwrap_or(0);
            let f = b.bits(6).unwrap_or(0);
            let closed = b.bit().unwrap_or(0);
            format!(
                "{h:02}:{m:02}:{s:02}{}{f:02}{}",
                if drop == 1 { ";" } else { ":" },
                if closed == 1 { ", closed" } else { "" }
            )
        }
        _ => String::new(),
    }
}

async fn expand_unit(cx: Cx, (span, code): (Span, u8)) -> Result<()> {
    let d = cx.read_avail(span.sub(0, 256)).await?;
    cx.emit(hex(
        "Start code",
        span.sub(0, 4),
        0x100u64 | u64::from(code),
        32,
    ));
    let body = span.tail(4);
    let data = d.get(4..).unwrap_or_default();
    let mut b = Bits::new(data);
    // A field of `n` bits: its value and the span of the bytes it touches.
    let mut field = |name: &'static str, n: u32| -> Option<(Node, u64)> {
        let start = b.pos();
        let v = b.bits(n)?;
        let first = vidutil::at(body, start >> 3, 0).offset;
        let last = vidutil::at(body, b.pos().saturating_sub(1) >> 3, 1).end();
        let span = Span::new(body.source, first, last.saturating_sub(first));
        Some((uint(name, span, v, u8::try_from(n).unwrap_or(64)), v))
    };
    match code {
        0xb3 => {
            for (name, bits) in [("Horizontal size", 12), ("Vertical size", 12)] {
                if let Some((n, _)) = field(name, bits) {
                    cx.emit(n);
                }
            }
            if let Some((n, v)) = field("Aspect ratio", 4) {
                cx.emit(n.summary(vidutil::lookup_or(ASPECT, v)));
            }
            if let Some((n, v)) = field("Frame rate code", 4) {
                cx.emit(n.summary(format!(
                    "{} fps",
                    FRAME_RATES.get(vidutil::us(v)).copied().unwrap_or("?")
                )));
            }
            if let Some((n, v)) = field("Bit rate", 18) {
                cx.emit(n.summary(bitrate(v)));
            }
            let _ = field("Marker", 1);
            if let Some((n, v)) = field("VBV buffer size", 10) {
                cx.emit(n.summary(format!("{} bytes", v.saturating_mul(2048))));
            }
            if let Some((n, v)) = field("Constrained parameters", 1) {
                cx.emit(n.summary(if v == 1 { "yes" } else { "no" }));
            }
            if let Some((n, v)) = field("Load intra quantiser matrix", 1) {
                cx.emit(n);
                if v == 1 {
                    for _ in 0..64 {
                        let _ = field("q", 8);
                    }
                }
            }
            if let Some((n, _)) = field("Load non-intra quantiser matrix", 1) {
                cx.emit(n);
            }
        }
        0xb5 => {
            let Some((n, id)) = field("Extension ID", 4) else {
                return Ok(());
            };
            cx.emit(n.summary(vidutil::lookup_or(EXTENSIONS, id)));
            match id {
                1 => {
                    if let Some((n, v)) = field("Profile and level", 8) {
                        cx.emit(n.summary(format!(
                            "{}@{}",
                            vidutil::lookup_or(PROFILES, (v >> 4) & 7),
                            vidutil::lookup_or(LEVELS, v & 15)
                        )));
                    }
                    if let Some((n, v)) = field("Progressive sequence", 1) {
                        cx.emit(flag_node(
                            "Progressive sequence",
                            n.span.unwrap_or(body),
                            v == 1,
                        ));
                    }
                    if let Some((n, v)) = field("Chroma format", 2) {
                        cx.emit(enumerated(
                            "Chroma format",
                            n.span.unwrap_or(body),
                            v,
                            2,
                            CHROMA,
                        ));
                    }
                    for (name, bits) in [
                        ("Horizontal size extension", 2),
                        ("Vertical size extension", 2),
                        ("Bit rate extension", 12),
                    ] {
                        if let Some((n, _)) = field(name, bits) {
                            cx.emit(n);
                        }
                    }
                }
                8 => {
                    for (name, bits) in [
                        ("Forward horizontal f-code", 4),
                        ("Forward vertical f-code", 4),
                        ("Backward horizontal f-code", 4),
                        ("Backward vertical f-code", 4),
                        ("Intra DC precision", 2),
                        ("Picture structure", 2),
                        ("Top field first", 1),
                        ("Frame pred frame DCT", 1),
                        ("Concealment motion vectors", 1),
                        ("Q scale type", 1),
                        ("Intra VLC format", 1),
                        ("Alternate scan", 1),
                        ("Repeat first field", 1),
                        ("Chroma 4:2:0 type", 1),
                        ("Progressive frame", 1),
                    ] {
                        if let Some((n, _)) = field(name, bits) {
                            cx.emit(n);
                        }
                    }
                }
                _ => cx.emit(Node::new("Extension data").span(body)),
            }
        }
        0xb8 => {
            for (name, bits) in [
                ("Drop frame", 1),
                ("Hours", 5),
                ("Minutes", 6),
                ("Marker", 1),
                ("Seconds", 6),
                ("Pictures", 6),
                ("Closed GOP", 1),
                ("Broken link", 1),
            ] {
                if let Some((n, _)) = field(name, bits) {
                    cx.emit(n);
                }
            }
        }
        0x00 => {
            if let Some((n, _)) = field("Temporal reference", 10) {
                cx.emit(n);
            }
            if let Some((n, v)) = field("Picture coding type", 3) {
                cx.emit(enumerated(
                    "Picture coding type",
                    n.span.unwrap_or(body),
                    v,
                    3,
                    PICTURE_TYPES,
                ));
            }
            if let Some((n, _)) = field("VBV delay", 16) {
                cx.emit(n);
            }
            let rest = body.tail(4);
            if !rest.is_empty() {
                cx.emit(Node::new("Picture data").span(rest));
            }
        }
        _ => {}
    }
    Ok(())
}
