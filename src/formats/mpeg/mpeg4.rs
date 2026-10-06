//! MPEG-4 Part 2 (Visual) elementary streams: visual object sequence,
//! visual object, video object layer, GOV and VOP units cut at start codes.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::vidutil::{self, Bits, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "mpeg4video",
    title: "MPEG-4 Visual elementary stream",
    extensions: &["m4v", "cmp", "xvid"],
    mime: "video/mp4v-es",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    if d.starts_with(b"\x00\x00\x01\xb0") {
        // Visual object sequence, then a visual object or user data.
        return d
            .get(5..9)
            .is_some_and(|w| w == b"\x00\x00\x01\xb5" || w == b"\x00\x00\x01\xb2");
    }
    // A video object start code followed directly by a VOL header.
    d.get(..3) == Some(b"\x00\x00\x01")
        && d.get(3).is_some_and(|&c| c <= 0x1f)
        && d.get(4..7) == Some(b"\x00\x00\x01")
        && d.get(7).is_some_and(|&c| (0x20..=0x2f).contains(&c))
}

const PROFILES: EnumTable = &[
    (0x01, "Simple Profile L1"),
    (0x02, "Simple Profile L2"),
    (0x03, "Simple Profile L3"),
    (0x04, "Simple Profile L4a"),
    (0x05, "Simple Profile L5"),
    (0x06, "Simple Profile L6"),
    (0x08, "Simple Profile L0"),
    (0x09, "Simple Profile L0b"),
    (0x21, "Core Profile L1"),
    (0x22, "Core Profile L2"),
    (0x32, "Main Profile L2"),
    (0x33, "Main Profile L3"),
    (0x34, "Main Profile L4"),
    (0xf0, "Advanced Simple Profile L0"),
    (0xf1, "Advanced Simple Profile L1"),
    (0xf2, "Advanced Simple Profile L2"),
    (0xf3, "Advanced Simple Profile L3"),
    (0xf4, "Advanced Simple Profile L4"),
    (0xf5, "Advanced Simple Profile L5"),
    (0xf7, "Advanced Simple Profile L3b"),
];

const VOP_TYPES: [&str; 4] = ["I", "P", "B", "S"];
const SHAPES: [&str; 4] = ["rectangular", "binary", "binary only", "grayscale"];

fn unit_name(code: u8) -> String {
    match code {
        0x00..=0x1f => "Video object".to_owned(),
        0x20..=0x2f => "Video object layer".to_owned(),
        0xb0 => "Visual object sequence".to_owned(),
        0xb1 => "Visual object sequence end".to_owned(),
        0xb2 => "User data".to_owned(),
        0xb3 => "Group of VOPs".to_owned(),
        0xb5 => "Visual object".to_owned(),
        0xb6 => "VOP".to_owned(),
        _ => format!("Start code {code:#04x}"),
    }
}

/// Fields of a video object layer header that summaries need.
#[derive(Debug, Default)]
struct Vol {
    object_type: u64,
    aspect: u64,
    shape: u64,
    resolution: u64,
    width: u64,
    height: u64,
}

fn parse_vol(d: &[u8]) -> Option<Vol> {
    let mut b = Bits::new(d);
    let mut vol = Vol::default();
    b.bit()?;
    vol.object_type = b.bits(8)?;
    let mut verid = 1;
    if b.flag()? {
        verid = b.bits(4)?;
        b.bits(3)?;
    }
    vol.aspect = b.bits(4)?;
    if vol.aspect == 15 {
        b.bits(16)?;
    }
    if b.flag()? {
        b.bits(3)?;
        if b.flag()? {
            b.skip(79)?;
        }
    }
    vol.shape = b.bits(2)?;
    if vol.shape == 3 && verid != 1 {
        b.bits(4)?;
    }
    b.bit()?;
    vol.resolution = b.bits(16)?;
    b.bit()?;
    if b.flag()? {
        let bits = 64u32
            .saturating_sub(vol.resolution.saturating_sub(1).leading_zeros())
            .max(1);
        b.bits(bits)?;
    }
    if vol.shape == 0 {
        b.bit()?;
        vol.width = b.bits(13)?;
        b.bit()?;
        vol.height = b.bits(13)?;
    }
    Some(vol)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = match vidutil::next_start_code(&cx, file, 0).await? {
        Some(p) => p,
        None => return Ok(()),
    };
    if pos > 0 {
        cx.emit(Node::new("Leading data").span(file.sub(0, pos)));
    }
    let mut profile = None;
    let mut annotated = false;
    cx.annotate("MPEG-4 Visual");
    while pos < file.len {
        let end = vidutil::next_start_code(&cx, file, pos.saturating_add(3))
            .await?
            .unwrap_or(file.len);
        let span = file.sub(pos, end.saturating_sub(pos));
        let d = vidutil::read_small(&cx, span, 64).await?;
        let code = d.get(3).copied().unwrap_or(0);
        let body = d.get(4..).unwrap_or_default();
        let summary = match code {
            0xb0 => {
                let p = body.first().copied().unwrap_or(0);
                profile = Some(vidutil::lookup_or(PROFILES, p.into()));
                profile.clone()
            }
            0x20..=0x2f => parse_vol(body).map(|v| {
                let s = format!(
                    "{}×{}, {} shape, time resolution {}",
                    v.width,
                    v.height,
                    SHAPES.get(vidutil::us(v.shape)).copied().unwrap_or("?"),
                    v.resolution
                );
                if !annotated {
                    annotated = true;
                    let mut a = format!("MPEG-4 Visual, {}×{}", v.width, v.height);
                    if let Some(p) = &profile {
                        a = format!("{a}, {p}");
                    }
                    cx.annotate(a);
                }
                s
            }),
            0xb6 => {
                let t = body.first().copied().unwrap_or(0) >> 6;
                Some(format!(
                    "{}-VOP",
                    VOP_TYPES.get(usize::from(t)).copied().unwrap_or("?")
                ))
            }
            0xb2 => Some(format!("\"{}\"", crate::text::until_nul(body))),
            0xb3 => {
                let mut b = Bits::new(body);
                let h = b.bits(5).unwrap_or(0);
                let m = b.bits(6).unwrap_or(0);
                b.bit();
                let s = b.bits(6).unwrap_or(0);
                Some(format!("{h:02}:{m:02}:{s:02}"))
            }
            _ => None,
        };
        let mut node = Node::new(unit_name(code)).span(span);
        node = node.summary(match summary {
            Some(s) => format!("{s}, {} bytes", span.len),
            None => format!("{} bytes", span.len),
        });
        if matches!(code, 0xb0 | 0x20..=0x2f | 0xb6) {
            node = node.lazy(expand_unit, (span, code));
        }
        cx.push(node).await;
        pos = end.max(pos.saturating_add(4));
    }
    Ok(())
}

async fn expand_unit(cx: Cx, (span, code): (Span, u8)) -> Result<()> {
    let d = vidutil::read_small(&cx, span, 256).await?;
    cx.emit(hex(
        "Start code",
        span.sub(0, 4),
        0x100u64 | u64::from(code),
        32,
    ));
    let body = span.tail(4);
    let data = d.get(4..).unwrap_or_default();
    match code {
        0xb0 => {
            let p = data.first().copied().unwrap_or(0);
            cx.emit(vidutil::enumerated(
                "Profile and level",
                body.sub(0, 1),
                p.into(),
                8,
                PROFILES,
            ));
        }
        0xb6 => {
            let t = data.first().copied().unwrap_or(0) >> 6;
            cx.emit(
                uint("VOP coding type", body.sub(0, 1), t.into(), 2)
                    .summary(VOP_TYPES.get(usize::from(t)).copied().unwrap_or("?")),
            );
            cx.emit(Node::new("VOP data").span(body));
        }
        _ => {
            if let Some(v) = parse_vol(data) {
                cx.emit(uint("Video object type", body, v.object_type, 8));
                cx.emit(uint("Aspect ratio info", body, v.aspect, 4));
                cx.emit(
                    uint("Shape", body, v.shape, 2)
                        .summary(SHAPES.get(vidutil::us(v.shape)).copied().unwrap_or("?")),
                );
                cx.emit(uint(
                    "VOP time increment resolution",
                    body,
                    v.resolution,
                    16,
                ));
                cx.emit(uint("Width", body, v.width, 13));
                cx.emit(uint("Height", body, v.height, 13));
            }
        }
    }
    Ok(())
}
