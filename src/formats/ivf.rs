//! IVF: the simple container libvpx and libaom use for VP8, VP9 and AV1
//! test streams. A 32-byte header, then frames `size, pts, data`.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::vidutil;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "ivf",
    title: "IVF video",
    extensions: &["ivf"],
    mime: "video/x-ivf",
    probe: Probe::Custom(|h| h.starts_with(b"DKIF") && u16_le(h.data, 6).is_some_and(|s| s >= 32)),
    dissect: crate::expander!(dissect: Input),
};

/// AV1 low-overhead bitstream (Section 5 OBUs), as written by `ffmpeg -f obu`.
pub static OBU: Format = Format {
    name: "obu",
    title: "AV1 OBU stream",
    extensions: &["obu", "av1"],
    mime: "video/av1",
    // A temporal delimiter (type 2, has_size, size 0), then a sequence
    // header (type 1, has_size).
    probe: Probe::Custom(|h| {
        h.starts_with(b"\x12\x00") && h.data.get(2).is_some_and(|b| b & 0xfa == 0x0a)
    }),
    dissect: crate::expander!(dissect_obu: Input),
};

pub async fn dissect_obu(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("AV1 OBU stream");
    obus(&cx, input.span).await
}

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        version: u16 "Version",
        header_size: u16 "Header size",
        fourcc: ascii[4] "FourCC",
        width: u16 "Width",
        height: u16 "Height",
        rate: u32 "Time base denominator",
        scale: u32 "Time base numerator",
        frames: u32 "Frame count",
        unused: u32 "Unused",
    }
}

record! {
    pub struct FrameHeader {
        size: u32 "Frame size",
        pts: u64 "Timestamp",
    }
}

const OBU_TYPES: EnumTable = &[
    (1, "sequence header"),
    (2, "temporal delimiter"),
    (3, "frame header"),
    (4, "tile group"),
    (5, "metadata"),
    (6, "frame"),
    (7, "redundant frame header"),
    (8, "tile list"),
    (15, "padding"),
];

#[derive(Clone, Copy, Debug)]
struct Frame {
    span: Span,
    fourcc: [u8; 4],
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (h, _) = crate::dsl::Cursor::new(&cx, file, LE)
        .record::<Header>()
        .await?;
    let header_len = u64::from(h.header_size).max(32);
    cx.emit(Header::node("Header", file.sub(0, Header::SIZE), LE));
    if header_len > Header::SIZE {
        cx.emit(
            Node::new("Header extension")
                .span(file.sub(Header::SIZE, header_len.saturating_sub(Header::SIZE))),
        );
    }
    let fourcc: [u8; 4] = h
        .fourcc
        .as_bytes()
        .get(..4)
        .and_then(|b| b.try_into().ok())
        .unwrap_or([0; 4]);
    let codec = vidutil::codec_name(&fourcc).map_or_else(|| h.fourcc.clone(), str::to_owned);
    let fps = if h.scale > 0 {
        format!(
            ", {} fps",
            vidutil::num(f64::from(h.rate) / f64::from(h.scale))
        )
    } else {
        String::new()
    };
    cx.annotate(format!(
        "IVF, {codec} {}×{}, {}{fps}",
        h.width,
        h.height,
        vidutil::plural(h.frames, "frame")
    ));
    let mut pos = header_len;
    let mut index = 0u64;
    while pos < file.len {
        let head = cx.read_avail(file.sub(pos, 13)).await?;
        let Some(size) = u32_le(&head, 0) else {
            cx.emit(Node::new("Trailing bytes").span(file.tail(pos)));
            break;
        };
        let total = u64::from(size).saturating_add(12);
        let frame = Frame {
            span: file.sub(pos, total),
            fourcc,
        };
        let pts = crate::bytes::u64_le(&head, 4).unwrap_or(0);
        let data = cx.read_avail(frame.span.tail(12).sub(0, 16)).await?;
        let mut summary = format!("pts {pts}, {size} bytes");
        if let Some(s) = frame_summary(&fourcc, &data) {
            summary = format!("{s}, {summary}");
        }
        let mut node = Node::new(format!("Frame {index}"))
            .span(frame.span)
            .summary(summary)
            .lazy(expand_frame, frame);
        if frame.span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, frame.span.offset, total),
                frame.span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(total);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Frame type and size from the first bytes of a VP8/VP9/AV1 frame.
fn frame_summary(fourcc: &[u8; 4], d: &[u8]) -> Option<String> {
    let b0 = *d.first()?;
    match fourcc {
        b"VP80" => {
            if b0 & 1 == 0 && d.get(3..6) == Some(&[0x9d, 0x01, 0x2a]) {
                let w = u16_le(d, 6)? & 0x3fff;
                let h = u16_le(d, 8)? & 0x3fff;
                Some(format!("key frame {w}×{h}"))
            } else if b0 & 1 == 0 {
                Some("key frame".to_owned())
            } else {
                Some("inter frame".to_owned())
            }
        }
        b"VP90" => {
            if b0 >> 6 != 2 {
                return None;
            }
            let profile = ((b0 >> 5) & 1) | (((b0 >> 4) & 1) << 1);
            let shift = if profile == 3 { 1 } else { 0 };
            let show_existing = (b0 >> (3u8.saturating_sub(shift))) & 1;
            if show_existing == 1 {
                return Some("show existing frame".to_owned());
            }
            let key = (b0 >> (2u8.saturating_sub(shift))) & 1 == 0;
            Some(format!(
                "profile {profile}, {}",
                if key { "key frame" } else { "inter frame" }
            ))
        }
        b"AV01" => {
            let mut names = Vec::new();
            let mut at = 0usize;
            while let Some(&h) = d.get(at) {
                names.push(vidutil::lookup_or(OBU_TYPES, ((h >> 3) & 15).into()));
                let ext = usize::from((h >> 2) & 1);
                let sized = d
                    .get(at.saturating_add(1).saturating_add(ext)..)
                    .and_then(crate::bytes::uleb128);
                match sized {
                    Some((size, len)) if h & 2 != 0 => {
                        at = at
                            .saturating_add(1)
                            .saturating_add(ext)
                            .saturating_add(len)
                            .saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
                    }
                    _ => break,
                }
            }
            Some(format!("OBUs: {}", names.join(", ")))
        }
        _ => None,
    }
}

async fn expand_frame(cx: Cx, frame: Frame) -> Result<()> {
    cx.emit(FrameHeader::node("Frame header", frame.span.sub(0, 12), LE));
    let data = frame.span.tail(12);
    if &frame.fourcc == b"AV01" {
        obus(&cx, data).await?;
    } else {
        cx.emit(
            Node::new("Frame data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        );
    }
    Ok(())
}

/// Lists AV1 OBUs (low-overhead bitstream format).
pub async fn obus(cx: &Cx, data: Span) -> Result<()> {
    let mut pos = 0u64;
    while pos < data.len {
        let d = cx.read_avail(data.sub(pos, 10)).await?;
        let Some(&h) = d.first() else {
            break;
        };
        let t = (h >> 3) & 15;
        let ext = u64::from((h >> 2) & 1);
        let (size, len) = if h & 2 != 0 {
            match d
                .get(vidutil::us(1u64.saturating_add(ext))..)
                .and_then(crate::bytes::uleb128)
            {
                Some((s, l)) => (s, crate::bytes::to_u64(l)),
                None => {
                    cx.emit(Node::new("Invalid OBU").span(data.tail(pos)));
                    break;
                }
            }
        } else {
            (
                data.len
                    .saturating_sub(pos)
                    .saturating_sub(1)
                    .saturating_sub(ext),
                0,
            )
        };
        let header = 1u64.saturating_add(ext).saturating_add(len);
        let total = header.saturating_add(size);
        let span = data.sub(pos, total);
        let mut node = vidutil::enumerated("OBU", span, t.into(), 4, OBU_TYPES)
            .summary(format!("{size} bytes"));
        if h & 0x80 != 0 {
            node = node.diag(Diagnostic::malformed("forbidden bit set"));
        }
        cx.push(node).await;
        if total == 0 {
            break;
        }
        pos = pos.saturating_add(total);
    }
    Ok(())
}
