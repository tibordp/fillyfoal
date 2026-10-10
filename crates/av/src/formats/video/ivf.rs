//! IVF, the simple container libvpx and libaom use for VP8, VP9 and AV1
//! streams (a 32-byte header, then frames `size, pts, data`), and raw AV1
//! low-overhead bitstreams (Section 5 OBUs, as `ffmpeg -f obu` writes).
//!
//! Frames decode on expansion: the VP8 frame tag and key frame header, the
//! VP9 uncompressed header (and superframe index), or the AV1 OBUs with
//! the sequence header, frame header start and metadata.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::plural;
use crate::formats::util::vidutil::av1::{self, SeqInfo};
use crate::formats::util::vidutil::bitwalk::Walker;
use crate::formats::util::vidutil::nal::group;
use crate::formats::util::vidutil::{self, vp9};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;

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

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        version: u16 "Version",
        header_size: u16 "Header size",
        fourcc: ascii[4] "FourCC",
        width: u16 "Width",
        height: u16 "Height",
        rate: u32 "Time base denominator" .desc("Timestamps count in units of numerator/denominator seconds"),
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

/// Bytes of a frame or OBU read for its summary.
const PEEK: u64 = 0x1000;
/// Bytes of an OBU or VP9 frame read when it is expanded.
const EXPAND: u64 = 0x10000;

#[derive(Clone, Copy, Debug)]
struct Frame {
    span: Span,
    fourcc: [u8; 4],
    /// The AV1 sequence header in force before this frame.
    seq: Option<SeqInfo>,
}

#[derive(Clone, Copy, Debug)]
struct Walk {
    pos: u64,
    index: u64,
    seq: Option<SeqInfo>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (h, _) = crate::dsl::Cursor::new(&cx, file, LE)
        .record::<Header>()
        .await?;
    let header_len = u64::from(h.header_size).max(32);
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
    let detail = first_frame_detail(&cx, file, header_len, &fourcc).await?;
    cx.annotate(format!(
        "IVF, {codec} {}×{}{}{fps}, {}",
        h.width,
        h.height,
        detail.map(|d| format!(" ({d})")).unwrap_or_default(),
        plural(h.frames, "frame")
    ));
    let mut walk = match cx.resume::<Walk>() {
        Some(w) => w,
        None => {
            cx.emit(
                Header::node("Header", file.sub(0, Header::SIZE), LE)
                    .summary(format!("{codec}, {}×{}{fps}", h.width, h.height)),
            );
            if header_len > Header::SIZE {
                cx.emit(
                    Node::new("Header extension")
                        .span(file.sub(Header::SIZE, header_len.saturating_sub(Header::SIZE))),
                );
            }
            Walk {
                pos: header_len,
                index: 0,
                seq: None,
            }
        }
    };
    while walk.pos < file.len {
        let state = walk;
        cx.mark(move || state);
        let head = cx.read_avail(file.sub(walk.pos, 12)).await?;
        let Some(size) = u32_le(&head, 0).filter(|_| head.len() == 12) else {
            cx.push(Node::new("Trailing bytes").span(file.tail(walk.pos)))
                .await;
            break;
        };
        let total = u64::from(size).saturating_add(12);
        let frame = Frame {
            span: file.sub(walk.pos, total),
            fourcc,
            seq: walk.seq,
        };
        let pts = crate::bytes::u64_le(&head, 4).unwrap_or(0);
        let data = frame.span.tail(12);
        let peek = cx.read_avail(data.sub(0, PEEK)).await?;
        let tail = cx
            .read_avail(data.tail(data.len.saturating_sub(64)))
            .await?;
        let mut summary = format!("pts {pts}, {size} bytes");
        if let Some(s) = frame_summary(&fourcc, data, &peek, &tail, &mut walk.seq) {
            summary = format!("{s}, {summary}");
        }
        let mut node = Node::new(format!("Frame {}", walk.index))
            .span(frame.span)
            .summary(summary)
            .lazy(expand_frame, frame);
        if frame.span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, frame.span.offset, total),
                frame.span.len,
            ));
        }
        cx.progress_in(file, file.offset.saturating_add(walk.pos));
        cx.push(node).await;
        walk.pos = walk.pos.saturating_add(total);
        walk.index = walk.index.saturating_add(1);
    }
    Ok(())
}

/// What the first frame says about the stream (profile, format).
async fn first_frame_detail(
    cx: &Cx,
    file: Span,
    header_len: u64,
    fourcc: &[u8; 4],
) -> Result<Option<String>> {
    let head = cx.read_avail(file.sub(header_len, 12)).await?;
    let Some(size) = u32_le(&head, 0) else {
        return Ok(None);
    };
    let data = file.sub(header_len.saturating_add(12), size.into());
    let peek = cx.read_avail(data.sub(0, PEEK)).await?;
    Ok(match fourcc {
        b"AV01" => {
            let mut w = Walker::new(&peek, data, false, false);
            let mut seq = None;
            let _ = vidutil::nal::obus(&mut w, &mut seq);
            seq.map(|s| {
                let mut d = format!("{}, {}", s.profile_level(), s.format());
                if let Some((p, t, m)) = s.colour
                    && let Some(c) = vidutil::params::colour_summary(p, t, m)
                {
                    d = format!("{d}, {c}");
                }
                d
            })
        }
        b"VP90" => {
            let mut w = Walker::new(&peek, data, false, false);
            vp9::vp9_header(&mut w)
                .filter(|f| f.width > 0)
                .map(|f| format!("profile {}, {}", f.profile, f.format()))
        }
        _ => None,
    })
}

/// Frame type and size from the start (and end) of a VP8/VP9/AV1 frame.
fn frame_summary(
    fourcc: &[u8; 4],
    data: Span,
    peek: &[u8],
    tail: &[u8],
    seq: &mut Option<SeqInfo>,
) -> Option<String> {
    match fourcc {
        b"VP80" => {
            let mut w = Walker::new(peek, data, false, false);
            vp9::vp8_header(&mut w)
        }
        b"VP90" => {
            if let Some(sizes) = vp9::vp9_superframe(tail) {
                let mut kinds = Vec::new();
                let mut at = 0u64;
                for size in &sizes {
                    let part = peek.get(vidutil::us(at)..).unwrap_or_default();
                    let mut w = Walker::new(part, data, false, false);
                    if let Some(f) = vp9::vp9_header(&mut w) {
                        kinds.push(f.describe());
                    }
                    at = at.saturating_add(*size);
                }
                Some(format!(
                    "superframe of {}: {}",
                    plural(to_u64(sizes.len()), "frame"),
                    kinds.join("; ")
                ))
            } else {
                let mut w = Walker::new(peek, data, false, false);
                vp9::vp9_header(&mut w).map(|f| f.describe())
            }
        }
        b"AV01" => {
            let mut w = Walker::new(peek, data, false, false);
            let obus = vidutil::nal::obus(&mut w, seq).unwrap_or_default();
            let frames: Vec<String> = obus
                .iter()
                .filter(|o| matches!(o.kind, 3 | 6))
                .filter_map(|o| o.summary.clone())
                .collect();
            if frames.is_empty() {
                Some(plural(to_u64(obus.len()), "OBU"))
            } else {
                Some(frames.join("; "))
            }
        }
        _ => None,
    }
}

async fn expand_frame(cx: Cx, frame: Frame) -> Result<()> {
    cx.emit(FrameHeader::node("Frame header", frame.span.sub(0, 12), LE));
    let data = frame.span.tail(12);
    match &frame.fourcc {
        b"AV01" => {
            obu_list(&cx, data, frame.seq).await?;
        }
        b"VP80" => {
            let d = cx.read_avail(data.sub(0, 64)).await?;
            let mut w = Walker::new(&d, data, false, true);
            let r = vp9::vp8_header(&mut w);
            let ok = r.is_some();
            let mut node = group("VP8 frame header", data.sub(0, 10), w.finish(ok));
            if let Some(s) = r {
                node = node.summary(s);
            }
            cx.emit(node);
            cx.emit(
                Node::new("Frame data")
                    .span(data)
                    .summary(format!("{} bytes", data.len)),
            );
        }
        b"VP90" => {
            let tail = cx
                .read_avail(data.tail(data.len.saturating_sub(64)))
                .await?;
            match vp9::vp9_superframe(&tail) {
                Some(sizes) => {
                    let mut at = 0u64;
                    for (i, size) in sizes.iter().enumerate() {
                        let part = data.sub(at, *size);
                        cx.emit(vp9_frame(&cx, format!("Frame {i}"), part).await?);
                        at = at.saturating_add(*size);
                    }
                    let index = data.tail(at);
                    cx.emit(
                        Node::new("Superframe index")
                            .span(index)
                            .summary(format!(
                                "{} of {}",
                                plural(to_u64(sizes.len()), "frame"),
                                sizes
                                    .iter()
                                    .map(|s| format!("{s}"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            ))
                            .desc("Marker byte, frame sizes (little-endian), marker byte"),
                    );
                }
                None => {
                    let node = vp9_frame(&cx, "VP9 frame".to_owned(), data).await?;
                    cx.emit(node);
                }
            }
        }
        _ => cx.emit(
            Node::new("Frame data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        ),
    }
    Ok(())
}

/// A VP9 frame with its uncompressed header decoded.
async fn vp9_frame(cx: &Cx, name: String, span: Span) -> Result<Node> {
    let d = cx.read_avail(span.sub(0, 64)).await?;
    let mut w = Walker::new(&d, span, false, true);
    let r = vp9::vp9_header(&mut w);
    let mut nodes = w.finish(r.is_some());
    nodes.push(
        Node::new("Compressed data")
            .span(span)
            .summary(format!("{} bytes", span.len))
            .desc("The compressed header and tile data follow the uncompressed header"),
    );
    let summary = match r {
        Some(f) => format!("{}, {} bytes", f.describe(), span.len),
        None => format!("{} bytes", span.len),
    };
    Ok(group(name, span, nodes).summary(summary))
}

// ---------------------------------------------------------------------------
// AV1 OBUs

#[derive(Clone, Copy, Debug)]
struct ObuUnit {
    span: Span,
    seq: Option<SeqInfo>,
}

/// The header of the OBU at `pos` in `data`: (type, total length,
/// forbidden bit set).
async fn obu_extent(cx: &Cx, data: Span, pos: u64) -> Result<Option<(u8, u64, bool)>> {
    let d = cx.read_avail(data.sub(pos, 10)).await?;
    let Some(&h) = d.first() else {
        return Ok(None);
    };
    let t = (h >> 3) & 15;
    let ext = u64::from((h >> 2) & 1);
    let header = 1u64.saturating_add(ext);
    let total = if h & 2 != 0 {
        match d.get(vidutil::us(header)..).and_then(crate::bytes::uleb128) {
            Some((s, l)) => header.saturating_add(to_u64(l)).saturating_add(s),
            None => return Ok(None),
        }
    } else {
        data.len.saturating_sub(pos)
    };
    Ok(Some((t, total, h & 0x80 != 0)))
}

/// Pushes the OBUs of `data`, each decoded on expansion. Returns the
/// sequence header in force at the end.
async fn obu_list(cx: &Cx, data: Span, mut seq: Option<SeqInfo>) -> Result<Option<SeqInfo>> {
    let mut pos = 0u64;
    while pos < data.len {
        let Some((t, total, forbidden)) = obu_extent(cx, data, pos).await? else {
            cx.push(
                Node::new("Invalid OBU")
                    .span(data.tail(pos))
                    .diag(Diagnostic::malformed("OBU header or size cut short")),
            )
            .await;
            break;
        };
        let span = data.sub(pos, total);
        let unit = ObuUnit { span, seq };
        let peek = cx.read_avail(span.sub(0, PEEK)).await?;
        let mut w = Walker::new(&peek, span, false, false);
        let summary = av1::obu(&mut w, &mut seq).and_then(|o| o.summary);
        let name = vidutil::lookup_or(av1::OBU_TYPES, t.into());
        let mut node = Node::new(name)
            .span(span)
            .summary(match summary {
                Some(s) => format!("{s}, {} bytes", span.len),
                None => format!("{} bytes", span.len),
            })
            .lazy(expand_obu, unit);
        if forbidden {
            node = node.diag(Diagnostic::malformed("forbidden bit set"));
        }
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        cx.push(node).await;
        if total == 0 {
            break;
        }
        pos = pos.saturating_add(total);
    }
    Ok(seq)
}

async fn expand_obu(cx: Cx, unit: ObuUnit) -> Result<()> {
    let d = cx.read_avail(unit.span.sub(0, EXPAND)).await?;
    let mut w = Walker::new(&d, unit.span, false, true);
    let mut seq = unit.seq;
    let ok = av1::obu(&mut w, &mut seq).is_some();
    for node in w.finish(ok) {
        cx.emit(node);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct TemporalUnit {
    span: Span,
    seq: Option<SeqInfo>,
}

#[derive(Clone, Copy, Debug)]
struct ObuWalk {
    pos: u64,
    index: u64,
    seq: Option<SeqInfo>,
}

/// An AV1 OBU stream: OBUs grouped into temporal units (each starting
/// with a temporal delimiter).
pub async fn dissect_obu(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let peek = cx.read_avail(file.sub(0, PEEK)).await?;
    let mut first = None;
    let mut w = Walker::new(&peek, file, false, false);
    let _ = vidutil::nal::obus(&mut w, &mut first);
    cx.annotate(match first {
        Some(s) => format!("AV1 OBU stream, {}", s.describe()),
        None => "AV1 OBU stream".to_owned(),
    });
    let mut walk = cx.resume::<ObuWalk>().unwrap_or(ObuWalk {
        pos: 0,
        index: 0,
        seq: None,
    });
    while walk.pos < file.len {
        let state = walk;
        cx.mark(move || state);
        let start = walk.pos;
        let seq_before = walk.seq;
        let mut frames = Vec::new();
        let mut count = 0u32;
        while walk.pos < file.len && count < 4096 {
            let Some((t, total, _)) = obu_extent(&cx, file, walk.pos).await? else {
                if count == 0 {
                    // Not an OBU: show the rest as one unit.
                    walk.pos = file.len;
                }
                break;
            };
            if t == 2 && count > 0 {
                break;
            }
            let span = file.sub(walk.pos, total);
            if matches!(t, 1 | 3 | 5 | 6) {
                let peek = cx.read_avail(span.sub(0, PEEK)).await?;
                let mut w = Walker::new(&peek, span, false, false);
                if let Some(s) = av1::obu(&mut w, &mut walk.seq).and_then(|o| o.summary)
                    && matches!(t, 3 | 6)
                {
                    frames.push(s);
                }
            }
            count = count.saturating_add(1);
            walk.pos = walk.pos.saturating_add(total.max(1));
            cx.checkpoint().await;
        }
        let tu = TemporalUnit {
            span: file.sub(start, walk.pos.saturating_sub(start)),
            seq: seq_before,
        };
        let mut summary = frames.join("; ");
        if !summary.is_empty() {
            summary.push_str(", ");
        }
        summary.push_str(&format!("{}, {} bytes", plural(count, "OBU"), tu.span.len));
        cx.progress_in(file, file.offset.saturating_add(start));
        cx.push(
            Node::new(format!("Temporal unit {}", walk.index))
                .span(tu.span)
                .summary(summary)
                .lazy(expand_tu, tu),
        )
        .await;
        walk.index = walk.index.saturating_add(1);
    }
    Ok(())
}

async fn expand_tu(cx: Cx, tu: TemporalUnit) -> Result<()> {
    obu_list(&cx, tu.span, tu.seq).await?;
    Ok(())
}
