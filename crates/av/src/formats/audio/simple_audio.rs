//! Audio files that are one fixed header followed by sample data (or by a
//! simple sequence of blocks): SoX native, IRCAM/BICSF, CRI ADX, Simon &
//! Schuster KVAG, LEGO Mindstorms RSO, Nintendo AST, iLBC and QOA.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Layout, parse, struct_node};
use crate::formats::util::sound::{channels, duration, duration_of, hz, leaf, peek_text, u24};
use crate::formats::util::val::text;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

/// Emits a header, the sample data after it and the file summary.
async fn headed<R: 'static>(
    cx: &Cx,
    header: Span,
    endian: Endian,
    layout: Layout<(), R>,
) -> Result<R> {
    let value = parse(cx, header, endian, &(), layout).await?;
    cx.emit(struct_node("Header", header, endian, (), layout));
    Ok(value)
}

fn samples_node(span: Span, summary: Option<String>) -> Node {
    let node = Node::new("Samples").span(span);
    match summary {
        Some(s) => node.summary(s),
        None => node,
    }
}

// ---------------------------------------------------------------------------
// SoX native

pub static SOX: Format = Format {
    name: "sox",
    title: "SoX native audio",
    extensions: &["sox"],
    mime: "audio/x-sox",
    probe: Probe::Magic(&[(0, b".SoX"), (0, b"XoS.")]),
    dissect: crate::expander!(sox: Input),
};

struct SoxHeader {
    size: u32,
    samples: u64,
    rate: f64,
    channels: u32,
    comment: u32,
}

fn sox_header(f: &mut Fields<'_>, _: &()) -> Result<SoxHeader> {
    f.ascii("Magic", 4).emit()?;
    Ok(SoxHeader {
        size: f
            .u32("Header size")
            .desc("Bytes after the magic, including the comment")
            .emit()?,
        samples: f.u64("Samples").desc("Total over all channels").emit()?,
        rate: f.f64("Sample rate").emit()?,
        channels: f.u32("Channels").emit()?,
        comment: f.u32("Comment length").emit()?,
    })
}

pub async fn sox(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b".SoX" { LE } else { BE };
    let h = headed(&cx, file.sub(0, 32), endian, sox_header).await?;
    if h.comment > 0 {
        let span = file.sub(32, h.comment.into());
        let t = peek_text(&cx, span, span.len.min(1 << 16)).await?;
        cx.emit(leaf("Comment", span, text(t)));
    }
    let frames = h.samples.checked_div(h.channels.into()).unwrap_or(0);
    let d = duration_of(frames, h.rate as u64);
    cx.emit(samples_node(
        file.tail(u64::from(h.size).saturating_add(4)),
        d.clone(),
    ));
    cx.annotate(format!(
        "SoX, 32-bit PCM, {}, {}{}",
        hz(h.rate),
        channels(h.channels),
        d.map(|d| format!(", {d}")).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// IRCAM / BICSF

pub static IRCAM: Format = Format {
    name: "ircam",
    title: "IRCAM/BICSF sound",
    extensions: &["sf", "ircam"],
    mime: "audio/x-ircam",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\x64\xa3")
            && h.data.get(2).is_some_and(|v| (1..=4).contains(v))
            && h.at(3, b"\0")
    }),
    dissect: crate::expander!(ircam: Input),
};

const IRCAM_ENCODING: EnumTable = &[
    (0x10001, "A-law"),
    (0x20001, "µ-law"),
    (0x00001, "8-bit PCM"),
    (0x00002, "16-bit PCM"),
    (0x00003, "24-bit PCM"),
    (0x40004, "32-bit PCM"),
    (0x00004, "32-bit float"),
    (0x00008, "64-bit float"),
];

record! {
    pub struct IrcamHeader {
        magic: bytes[4] "Magic" .with(|b, n| n.summary(match b.get(2) {
            Some(1) => "VAX (little-endian)",
            Some(2) => "Sun (big-endian)",
            Some(3) => "MIPS (little-endian)",
            Some(4) => "NeXT (big-endian)",
            _ => "unknown",
        })),
        rate: f32 "Sample rate",
        channels: u32 "Channels",
        encoding: u32 "Encoding" .enumeration(IRCAM_ENCODING),
    }
}

pub async fn ircam(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic.get(2).is_some_and(|v| v % 2 == 1) {
        LE
    } else {
        BE
    };
    let h = headed(
        &cx,
        file.sub(0, IrcamHeader::SIZE),
        endian,
        IrcamHeader::layout,
    )
    .await?;
    cx.emit(Node::new("Header padding").span(file.sub(16, 1008)));
    let bytes = match h.encoding & 0xffff {
        1 => 1,
        2 => 2,
        3 => 3,
        4 => 4,
        8 => 8,
        _ => 0,
    };
    let data = file.tail(1024);
    let frames = data
        .len
        .checked_div(u64::from(h.channels).saturating_mul(bytes))
        .unwrap_or(0);
    let d = duration_of(frames, h.rate as u64);
    cx.emit(samples_node(data, d.clone()));
    let encoding =
        crate::value::lookup(IRCAM_ENCODING, h.encoding.into()).unwrap_or("unknown encoding");
    cx.annotate(format!(
        "IRCAM, {encoding}, {}, {}{}",
        hz(f64::from(h.rate)),
        channels(h.channels),
        d.map(|d| format!(", {d}")).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// CRI ADX

pub static ADX: Format = Format {
    name: "adx",
    title: "CRI ADX",
    extensions: &["adx"],
    mime: "audio/x-adx",
    probe: Probe::Custom(|h| {
        h.starts_with(b"\x80\x00")
            && u16_be(h.data, 2).is_some_and(|off| {
                let at = usize::from(off).saturating_sub(2);
                h.at(at, b"(c)CRI")
            })
    }),
    dissect: crate::expander!(adx: Input),
};

const ADX_ENCODING: EnumTable = &[
    (2, "ADPCM, fixed coefficients"),
    (3, "ADX"),
    (4, "ADX, exponential scale"),
    (0x10, "AHX"),
    (0x11, "AHX"),
];

record! {
    pub struct AdxHeader {
        magic: u16 "Magic" .hex(),
        offset: u16 "Copyright offset" .desc("Data starts 4 bytes after this offset"),
        encoding: u8 "Encoding" .enumeration(ADX_ENCODING),
        block_size: u8 "Block size",
        bits: u8 "Bits per sample",
        channels: u8 "Channels",
        rate: u32 "Sample rate",
        samples: u32 "Total samples",
        highpass: u16 "High-pass frequency",
        version: u8 "Version",
        flags: u8 "Flags" .hex(),
    }
}

pub async fn adx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = headed(&cx, file.sub(0, AdxHeader::SIZE), BE, AdxHeader::layout).await?;
    let data_start = u64::from(h.offset).saturating_add(4);
    let rest = file.sub(AdxHeader::SIZE, data_start.saturating_sub(AdxHeader::SIZE));
    if !rest.is_empty() {
        cx.emit(
            Node::new("Header extension")
                .span(rest)
                .desc("Loop data and the (c)CRI signature"),
        );
    }
    let d = duration_of(h.samples.into(), h.rate.into());
    cx.emit(samples_node(file.tail(data_start), d.clone()));
    cx.annotate(format!(
        "CRI ADX v{}, {} Hz, {}{}",
        h.version,
        h.rate,
        channels(h.channels),
        d.map(|d| format!(", {d}")).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// KVAG

pub static KVAG: Format = Format {
    name: "kvag",
    title: "Simon & Schuster Interactive VAG",
    extensions: &["vag"],
    mime: "audio/x-kvag",
    probe: Probe::Magic(&[(0, b"KVAG")]),
    dissect: crate::expander!(kvag: Input),
};

record! {
    pub struct KvagHeader {
        magic: ascii[4] "Magic",
        size: u32 "Data size",
        rate: u32 "Sample rate",
        stereo: u16 "Stereo",
    }
}

pub async fn kvag(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = headed(&cx, file.sub(0, KvagHeader::SIZE), LE, KvagHeader::layout).await?;
    let ch = if h.stereo != 0 { 2u64 } else { 1 };
    // IMA ADPCM: two samples per byte.
    let d = duration_of(
        u64::from(h.size)
            .saturating_mul(2)
            .checked_div(ch)
            .unwrap_or(0),
        h.rate.into(),
    );
    cx.emit(samples_node(
        file.sub(KvagHeader::SIZE, h.size.into()),
        d.clone(),
    ));
    cx.annotate(format!(
        "KVAG, IMA ADPCM, {} Hz, {}{}",
        h.rate,
        channels(ch),
        d.map(|d| format!(", {d}")).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// LEGO Mindstorms RSO

pub static RSO: Format = Format {
    name: "rso",
    title: "LEGO Mindstorms sound",
    extensions: &["rso"],
    mime: "audio/x-rso",
    probe: Probe::Custom(|h: &Head<'_>| {
        matches!(u16_be(h.data, 0), Some(0x0100 | 0x0101))
            && u16_be(h.data, 2).is_some_and(|n| u64::from(n).saturating_add(8) == h.len)
            && u16_be(h.data, 4).is_some_and(|r| (2000..=48000).contains(&r))
    }),
    dissect: crate::expander!(rso: Input),
};

record! {
    pub struct RsoHeader {
        format: u16 "Format" .enumeration(&[(0x100, "8-bit unsigned PCM"), (0x101, "IMA ADPCM")]),
        size: u16 "Data size",
        rate: u16 "Sample rate",
        mode: u16 "Play mode",
    }
}

pub async fn rso(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = headed(&cx, file.sub(0, RsoHeader::SIZE), BE, RsoHeader::layout).await?;
    let samples = if h.format == 0x101 {
        u64::from(h.size).saturating_mul(2)
    } else {
        h.size.into()
    };
    let d = duration_of(samples, h.rate.into());
    cx.emit(samples_node(file.sub(8, h.size.into()), d.clone()));
    cx.annotate(format!(
        "LEGO RSO, {} Hz{}",
        h.rate,
        d.map(|d| format!(", {d}")).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Nintendo AST

pub static AST: Format = Format {
    name: "ast",
    title: "Nintendo AST audio stream",
    extensions: &["ast"],
    mime: "audio/x-ast",
    probe: Probe::Magic(&[(0, b"STRM")]),
    dissect: crate::expander!(ast: Input),
};

record! {
    pub struct AstHeader {
        magic: ascii[4] "Magic",
        size: u32 "Data size",
        format: u16 "Codec" .enumeration(&[(0, "4-bit ADPCM"), (1, "16-bit PCM")]),
        bits: u16 "Bits per sample",
        channels: u16 "Channels",
        _unknown: u16 "Unknown" .hex(),
        rate: u32 "Sample rate",
        samples: u32 "Total samples",
        loop_start: u32 "Loop start",
        loop_end: u32 "Loop end",
        first_block: u32 "First block size",
        _unknown2: u32 "Unknown",
        volume: u32 "Volume" .hex(),
        _padding: bytes[20] "Padding",
    }
}

pub async fn ast(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = headed(&cx, file.sub(0, AstHeader::SIZE), BE, AstHeader::layout).await?;
    let d = duration_of(h.samples.into(), h.rate.into());
    cx.annotate(format!(
        "AST, {}-bit, {} Hz, {}{}",
        h.bits,
        h.rate,
        channels(h.channels),
        d.map(|d| format!(", {d}")).unwrap_or_default()
    ));
    let blocks = file.tail(AstHeader::SIZE);
    cx.emit(
        Node::new("Blocks")
            .span(blocks)
            .lazy(ast_blocks, (blocks, u64::from(h.channels))),
    );
    Ok(())
}

async fn ast_blocks(cx: Cx, (region, chans): (Span, u64)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while region.len.saturating_sub(pos) >= 32 {
        let head = cx.read(region.sub(pos, 8)).await?;
        if head.get(..4) != Some(b"BLCK") {
            cx.emit(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed("expected BLCK")),
            );
            return Ok(());
        }
        let size = u64::from(u32_be(&head, 4).unwrap_or(0));
        let len = size.saturating_mul(chans.max(1)).saturating_add(32);
        let span = region.sub(pos, len);
        cx.push(
            Node::new(format!("Block {index}"))
                .span(span)
                .summary(format!("{size} bytes per channel"))
                .lazy(ast_block, (span, size, chans)),
        )
        .await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn ast_block(cx: Cx, (span, size, chans): (Span, u64, u64)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Block size").desc("Per channel").emit()?;
    cx.emit(Node::new("Padding").span(span.sub(8, 24)));
    for c in 0..chans {
        cx.emit(
            Node::new(format!("Channel {c}"))
                .span(span.sub(32u64.saturating_add(c.saturating_mul(size)), size)),
        );
        cx.checkpoint().await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// iLBC

pub static ILBC: Format = Format {
    name: "ilbc",
    title: "iLBC speech",
    extensions: &["lbc", "ilbc"],
    mime: "audio/iLBC",
    probe: Probe::Magic(&[(0, b"#!iLBC20\n"), (0, b"#!iLBC30\n")]),
    dissect: crate::expander!(ilbc: Input),
};

pub async fn ilbc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 9)).await?;
    let thirty = magic.starts_with(b"#!iLBC30");
    let (frame, ms) = if thirty { (50u64, 30u64) } else { (38, 20) };
    cx.emit(leaf(
        "Magic",
        file.sub(0, 9),
        text(String::from_utf8_lossy(magic.get(..8).unwrap_or_default())),
    ));
    let data = file.tail(9);
    let frames = data.len.checked_div(frame).unwrap_or(0);
    cx.annotate(format!(
        "iLBC, {ms} ms frames, 8000 Hz, {}",
        duration(frames as f64 * ms as f64 / 1000.0)
    ));
    cx.emit(
        Node::new("Frames")
            .span(data)
            .summary(format!("{frames} frames of {frame} bytes"))
            .lazy(fixed_frames, (data, frame)),
    );
    Ok(())
}

async fn fixed_frames(cx: Cx, (region, size): (Span, u64)) -> Result<()> {
    cx.set_count(Count::Exact(region.len.checked_div(size).unwrap_or(0)));
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < region.len && size > 0 {
        cx.push(Node::new(format!("Frame {index}")).span(region.sub(pos, size)))
            .await;
        pos = pos.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// QOA

pub static QOA: Format = Format {
    name: "qoa",
    title: "Quite OK Audio",
    extensions: &["qoa"],
    mime: "audio/qoa",
    probe: Probe::Magic(&[(0, b"qoaf")]),
    dissect: crate::expander!(qoa: Input),
};

pub async fn qoa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let samples = f.u32("Samples per channel").desc("0 = streaming").emit()?;
    let ch = head.data.get(8).copied().unwrap_or(0);
    let rate = crate::bytes::u24_be(&head.data, 9).unwrap_or(0);
    cx.annotate(format!(
        "QOA, {rate} Hz, {}, {}",
        channels(ch),
        duration_of(samples.into(), rate.into()).unwrap_or_else(|| "streaming".to_owned())
    ));
    let frames = file.tail(8);
    cx.emit(Node::new("Frames").span(frames).lazy(qoa_frames, frames));
    Ok(())
}

async fn qoa_frames(cx: Cx, region: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while region.len.saturating_sub(pos) >= 8 {
        let head = cx.read(region.sub(pos, 8)).await?;
        let ch = head.first().copied().unwrap_or(0);
        let rate = crate::bytes::u24_be(&head, 1).unwrap_or(0);
        let samples = u16_be(&head, 4).unwrap_or(0);
        let size = u64::from(u16_be(&head, 6).unwrap_or(0));
        if size < 8 {
            cx.emit(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed("invalid frame size")),
            );
            return Ok(());
        }
        let span = region.sub(pos, size);
        cx.push(
            Node::new(format!("Frame {index}"))
                .span(span)
                .summary(format!(
                    "{samples} samples, {rate} Hz, {} ch, {size} bytes",
                    ch
                ))
                .lazy(qoa_frame, (span, ch)),
        )
        .await;
        pos = pos.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn qoa_frame(cx: Cx, (span, ch): (Span, u8)) -> Result<()> {
    let head = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Channels").emit()?;
    u24(&mut f, "Sample rate", BE).emit()?;
    f.u16("Samples per channel").emit()?;
    f.u16("Frame size").emit()?;
    let lms = u64::from(ch).saturating_mul(16);
    cx.emit(
        Node::new("LMS state")
            .span(span.sub(8, lms))
            .desc("History and weights per channel"),
    );
    cx.emit(
        Node::new("Slices")
            .span(span.tail(lms.saturating_add(8)))
            .desc("64-bit slices of 20 samples"),
    );
    Ok(())
}
