//! TTA (True Audio) lossless audio: a `TTA1` header with a CRC, a seek
//! table of frame sizes (with its own CRC), then the frames.

use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::audio::ape::trailing_tags;
use crate::formats::util::sound::{channels, duration_of, hex, leaf, table};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
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
        samples: u32 "Samples",
        crc: u32 "CRC" .hex(),
    }
}

record! {
    pub struct FrameSize {
        size: u32 "Size",
    }
}

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
    let mut line = format!(
        "TTA, {} Hz, {}, {}-bit",
        h.rate,
        channels(h.channels),
        h.bits
    );
    if let Some(d) = duration_of(h.samples.into(), h.rate.into()) {
        line.push_str(&format!(", {d}"));
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
    cx.emit(leaf(
        "Seek table CRC",
        crc_span,
        hex(crate::bytes::u32_le(&stored, 0).unwrap_or(0), 32),
    ));
    let start = crc_span.end().saturating_sub(file.offset);
    cx.emit(
        Node::new("Frames")
            .span(file.sub(start, end.saturating_sub(start)))
            .summary(format!("{frames} frames")),
    );
    for node in tags {
        cx.emit(node);
    }
    Ok(())
}
