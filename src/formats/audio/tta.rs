//! TTA (True Audio) lossless audio: a `TTA1` header with a CRC, a seek
//! table of frame sizes (with its own CRC), then the frames, each ending
//! in a CRC-32 of its data.

use crate::bytes::u32_le;
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::audio::ape::trailing_tags;
use crate::formats::iff::wav::khz;
use crate::formats::util::sound::{channels, duration_of, hex, leaf, table};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "tta",
    title: "True Audio",
    extensions: &["tta"],
    mime: "audio/x-tta",
    probe: Probe::Magic(&[(0, b"TTA1")]),
    dissect: crate::expander!(dissect: Input),
};

const AUDIO_FORMAT: EnumTable = &[(1, "PCM"), (2, "encrypted PCM")];

record! {
    pub struct Header {
        magic: ascii[4] "Signature",
        format: u16 "Audio format" .enumeration(AUDIO_FORMAT),
        channels: u16 "Channels",
        bits: u16 "Bits per sample",
        rate: u32 "Sample rate",
        samples: u32 "Samples" .desc("Per channel"),
        crc: u32 "CRC" .hex() .desc("CRC-32 of the 18 bytes before it"),
    }
}

record! {
    pub struct FrameSize {
        size: u32 "Size",
    }
}

/// CRCs are checked over at most this many bytes (larger tables and frames
/// are left unchecked rather than hashed in one step).
const MAX_CHECKED: u64 = 1 << 20;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, tags) = trailing_tags(&cx, input).await?;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    let raw = cx.read(hspan).await?;
    let mut node = Header::node("Header", hspan, LE);
    node = if crc32(raw.get(..18).unwrap_or_default()) == h.crc {
        node.summary("CRC valid")
    } else {
        node.diag(Diagnostic::warning("header CRC mismatch"))
    };
    cx.emit(node);
    let layout = match h.channels {
        1 => "mono".to_owned(),
        2 => "stereo".to_owned(),
        n => channels(n),
    };
    let mut line = format!("TTA {}-bit, {}, {layout}", h.bits, khz(h.rate));
    if let Some(d) = duration_of(h.samples.into(), h.rate.into()) {
        line.push_str(&format!(", {d}"));
    }
    if h.format == 2 {
        line.push_str(", encrypted");
    }
    cx.annotate(line);
    // Frames hold 256/245 seconds of audio.
    let frame_len = u64::from(h.rate).saturating_mul(256) / 245;
    let frames = u64::from(h.samples)
        .saturating_add(frame_len.saturating_sub(1))
        .checked_div(frame_len)
        .unwrap_or(0);
    let seek = file.sub(Header::SIZE, frames.saturating_mul(4));
    cx.emit(table::<FrameSize>(
        "Seek table",
        seek,
        LE,
        "Frame",
        Some(|f| format!("{} bytes", f.size)),
    ));
    let crc_span = file.sub(seek.end().saturating_sub(file.offset), 4);
    let stored = cx.read_avail(crc_span).await?;
    let stored = u32_le(&stored, 0);
    let mut crc_node = leaf("Seek table CRC", crc_span, hex(stored.unwrap_or(0), 32));
    if seek.len <= MAX_CHECKED && stored.is_some() {
        let table = cx.read_avail(seek).await?;
        crc_node = if Some(crc32(&table)) == stored {
            crc_node.summary("valid")
        } else {
            crc_node.diag(Diagnostic::warning("seek table CRC mismatch"))
        };
    }
    cx.emit(crc_node);
    let start = crc_span.end().saturating_sub(file.offset);
    let data = file.sub(start, end.saturating_sub(start));
    cx.emit(
        Node::new("Frames")
            .span(data)
            .summary(format!("{frames} frames"))
            .lazy(
                list_frames,
                Frames {
                    seek,
                    data,
                    frames,
                    frame_len,
                    samples: h.samples.into(),
                },
            ),
    );
    for node in tags {
        cx.emit(node);
    }
    Ok(())
}

#[derive(Clone, Debug)]
struct Frames {
    seek: Span,
    data: Span,
    frames: u64,
    frame_len: u64,
    samples: u64,
}

async fn list_frames(cx: Cx, t: Frames) -> Result<()> {
    if t.frames <= t.seek.len / 4 {
        cx.set_count(Count::Exact(t.frames));
    }
    let (mut index, mut offset) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while index < t.frames && offset < t.data.len {
        let at = (index, offset);
        cx.mark(move || at);
        let entry = cx
            .read_avail(t.seek.sub(index.saturating_mul(4), 4))
            .await?;
        let Some(size) = u32_le(&entry, 0).map(u64::from) else {
            break;
        };
        let span = t.data.sub(offset, size);
        let first = index.saturating_mul(t.frame_len);
        let last = first.saturating_add(t.frame_len).min(t.samples);
        let mut node = Node::new(format!("Frame {index}"))
            .span(span)
            .summary(format!("{size} bytes, samples {first}..{last}"));
        if span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        cx.progress_in(t.data, span.offset);
        cx.push(node.lazy(frame, span)).await;
        offset = offset.saturating_add(size.max(1));
        index = index.saturating_add(1);
    }
    if offset < t.data.len {
        cx.emit(Node::new("Unused").span(t.data.tail(offset)));
    }
    Ok(())
}

async fn frame(cx: Cx, span: Span) -> Result<()> {
    let body = span.sub(0, span.len.saturating_sub(4));
    cx.emit(
        Node::new("Data")
            .span(body)
            .desc("Adaptive-filter residuals, Rice coded"),
    );
    let crc_span = span.tail(body.len);
    let stored = u32_le(&cx.read_avail(crc_span).await?, 0);
    let mut node = leaf("CRC", crc_span, hex(stored.unwrap_or(0), 32));
    if body.len <= MAX_CHECKED && stored.is_some() {
        let data = cx.read_avail(body).await?;
        node = if Some(crc32(&data)) == stored {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning("frame CRC mismatch"))
        };
    } else {
        node = node.summary(format!("not checked ({} bytes)", body.len));
    }
    cx.emit(node);
    Ok(())
}
