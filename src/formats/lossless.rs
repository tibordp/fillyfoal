//! Lossless codecs with their own containers: TAK (metadata blocks with a
//! bit-packed stream info), OptimFROG and Shorten. APE and ID3v1 tags at
//! the end are shown too.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::ape::trailing_tags;
use crate::formats::sound::{Bits, bits_node, channels, duration_of, parse_bits, u24};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// TAK

pub static TAK: Format = Format {
    name: "tak",
    title: "Tom's lossless Audio Kompressor",
    extensions: &["tak"],
    mime: "audio/x-tak",
    probe: Probe::Magic(&[(0, b"tBaK")]),
    dissect: crate::expander!(tak: Input),
};

const TAK_BLOCK: EnumTable = &[
    (0, "End"),
    (1, "Stream info"),
    (2, "Seek table"),
    (3, "WAV metadata"),
    (4, "Encoder info"),
    (5, "Padding"),
    (6, "MD5"),
    (7, "Last frame"),
];

const FRAME_SIZE: EnumTable = &[
    (0, "94 ms"),
    (1, "125 ms"),
    (2, "188 ms"),
    (3, "250 ms"),
    (4, "4096 samples"),
    (5, "8192 samples"),
    (6, "16384 samples"),
    (7, "512 samples"),
    (8, "1024 samples"),
    (9, "2048 samples"),
];

#[derive(Clone, Copy, Debug, Default)]
struct TakInfo {
    samples: u64,
    rate: u64,
    bits: u64,
    channels: u64,
}

fn tak_info(b: &mut Bits<'_>) -> Result<TakInfo> {
    b.field("Codec", 6).emit()?;
    b.field("Profile", 4).emit()?;
    b.field("Frame size", 4).enumeration(FRAME_SIZE).emit()?;
    let samples = b.field("Samples", 35).emit()?;
    b.field("Data type", 3).emit()?;
    let rate = b
        .field("Sample rate − 6000", 18)
        .with(|v, n| n.summary(format!("{} Hz", v.saturating_add(6000))))
        .emit()?
        .saturating_add(6000);
    let bits = b
        .field("Bits per sample − 8", 5)
        .with(|v, n| n.summary(format!("{}-bit", v.saturating_add(8))))
        .emit()?
        .saturating_add(8);
    let channels = b
        .field("Channels − 1", 4)
        .with(|v, n| n.summary(channels(v.saturating_add(1))))
        .emit()?
        .saturating_add(1);
    Ok(TakInfo {
        samples,
        rate,
        bits,
        channels,
    })
}

pub async fn tak(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, tags) = trailing_tags(&cx, input).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let mut pos = 4u64;
    let mut info = None;
    while end.saturating_sub(pos) >= 4 {
        let h = cx.read(file.sub(pos, 4)).await?;
        let kind = h.first().copied().unwrap_or(0) & 0x7f;
        let size = u64::from(crate::bytes::u24_le(&h, 1).unwrap_or(0));
        let span = file.sub(pos, size.saturating_add(4));
        let name = crate::value::lookup(TAK_BLOCK, kind.into())
            .map_or_else(|| format!("Block type {kind}"), str::to_owned);
        let mut node = Node::new(name).span(span).summary(format!("{size} bytes"));
        if kind == 1 && info.is_none() {
            let parsed = parse_bits(&cx, span.sub(4, 16), tak_info, true).await.ok();
            if let Some(i) = parsed {
                node = node.summary(format!(
                    "{} Hz, {}, {}-bit",
                    i.rate,
                    channels(i.channels),
                    i.bits
                ));
            }
            info = parsed;
        }
        cx.push(node.lazy(tak_block, (input, span, kind))).await;
        pos = pos.saturating_add(size).saturating_add(4);
        if kind == 0 {
            break;
        }
    }
    cx.emit(Node::new("Frames").span(file.sub(pos, end.saturating_sub(pos))));
    for node in tags {
        cx.emit(node);
    }
    if let Some(i) = info {
        let mut line = format!(
            "TAK, {} Hz, {}, {}-bit",
            i.rate,
            channels(i.channels),
            i.bits
        );
        if let Some(d) = duration_of(i.samples, i.rate) {
            line.push_str(&format!(", {d}"));
        }
        cx.annotate(line);
    }
    Ok(())
}

async fn tak_block(cx: Cx, (input, span, kind): (Input, Span, u8)) -> Result<()> {
    let head = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u8("Type").enumeration(TAK_BLOCK).emit()?;
    u24(&mut f, "Size", LE).emit()?;
    let data = span.tail(4);
    match kind {
        1 => cx.emit(bits_node(
            "Stream info",
            data.sub(0, 16),
            |b| tak_info(b).map(|_| ()),
            true,
        )),
        3 => cx.emit(crate::formats::embedded(
            "Original header",
            input.nested(data),
        )),
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OptimFROG

pub static OFR: Format = Format {
    name: "optimfrog",
    title: "OptimFROG",
    extensions: &["ofr", "ofs"],
    mime: "audio/x-optimfrog",
    probe: Probe::Magic(&[(0, b"OFR ")]),
    dissect: crate::expander!(ofr: Input),
};

const SAMPLE_TYPE: EnumTable = &[
    (0, "8-bit unsigned"),
    (1, "8-bit signed"),
    (2, "16-bit unsigned"),
    (3, "16-bit signed"),
    (4, "24-bit unsigned"),
    (5, "24-bit signed"),
    (6, "32-bit unsigned"),
    (7, "32-bit signed"),
    (8, "32-bit float"),
];

pub async fn ofr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, tags) = trailing_tags(&cx, input).await?;
    let raw = cx.read_avail(file.sub(4, 4)).await?;
    let header = u64::from(u32_le(&raw, 0).unwrap_or(12));
    let span = file.sub(0, header.saturating_add(8));
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Header size").emit()?;
    let low = f.u32("Total samples (low)").emit()?;
    let high = f.u16("Total samples (high)").emit()?;
    let kind = f.u8("Sample type").enumeration(SAMPLE_TYPE).emit()?;
    let config = f
        .u8("Channel configuration")
        .enumeration(&[(0, "mono"), (1, "stereo")])
        .emit()?;
    let rate = f.u32("Sample rate").emit()?;
    if f.remaining() >= 3 {
        f.u16("Encoder ID").hex().emit()?;
        f.u8("Compression").emit()?;
    }
    let ch = u64::from(config).saturating_add(1);
    let samples = ((u64::from(high) << 32) | u64::from(low))
        .checked_div(ch)
        .unwrap_or(0);
    let start = span.end().saturating_sub(file.offset);
    cx.emit(Node::new("Compressed data").span(file.sub(start, end.saturating_sub(start))));
    for node in tags {
        cx.emit(node);
    }
    let mut line = format!(
        "OptimFROG, {}, {rate} Hz, {}",
        crate::value::lookup(SAMPLE_TYPE, kind.into()).unwrap_or("?"),
        channels(ch)
    );
    if let Some(d) = duration_of(samples, rate.into()) {
        line.push_str(&format!(", {d}"));
    }
    cx.annotate(line);
    Ok(())
}

// ---------------------------------------------------------------------------
// Shorten

pub static SHORTEN: Format = Format {
    name: "shorten",
    title: "Shorten",
    extensions: &["shn"],
    mime: "audio/x-shorten",
    probe: Probe::Custom(|h| {
        h.starts_with(b"ajkg") && h.data.get(4).is_some_and(|v| (1..=3).contains(v))
    }),
    dissect: crate::expander!(shorten: Input),
};

pub async fn shorten(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 5)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let version = f.u8("Version").emit()?;
    cx.emit(
        Node::new("Compressed stream")
            .span(file.tail(5))
            .desc("Rice-coded parameters (file type, channels, block size) and audio"),
    );
    cx.annotate(format!("Shorten v{version}"));
    Ok(())
}
