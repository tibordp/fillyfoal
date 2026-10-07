//! FLAC: the `fLaC` signature, metadata blocks (STREAMINFO, PADDING,
//! APPLICATION, SEEKTABLE, VORBIS_COMMENT, CUESHEET, PICTURE), then audio
//! frames. Frames have no length field: they are found by scanning for the
//! next frame header whose CRC-8 checks out.
//!
//! The metadata block decoders are shared with FLAC-in-Ogg.

use crate::bytes::{to_u64, to_usize, u32_be};
use crate::codec::crc::crc8;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::sound::{
    Bits, bits_node, channels, duration_of, enumerated, hex, leaf, parse_bits, table, text, uint,
};
use crate::formats::{Format, Input, Probe, audio::id3, audio::vorbis, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "flac",
    title: "Free Lossless Audio Codec",
    extensions: &["flac", "fla"],
    mime: "audio/flac",
    probe: Probe::Custom(|h| {
        h.starts_with(b"fLaC")
            || id3::v2_len(h.data)
                .and_then(|len| h.data.get(to_usize(len)..))
                .is_some_and(|rest| rest.starts_with(b"fLaC"))
    }),
    dissect: crate::expander!(dissect: Input),
};

pub const BLOCK_TYPE: EnumTable = &[
    (0, "STREAMINFO"),
    (1, "PADDING"),
    (2, "APPLICATION"),
    (3, "SEEKTABLE"),
    (4, "VORBIS_COMMENT"),
    (5, "CUESHEET"),
    (6, "PICTURE"),
    (127, "invalid"),
];

/// STREAMINFO, the values the file summary needs.
#[derive(Clone, Copy, Debug, Default)]
pub struct StreamInfo {
    pub rate: u64,
    pub channels: u64,
    pub bits: u64,
    pub samples: u64,
}

impl StreamInfo {
    /// "44100 Hz, 2 ch, 16-bit, 0:05".
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{} Hz, {}, {}-bit",
            self.rate,
            channels(self.channels),
            self.bits
        );
        if let Some(d) = duration_of(self.samples, self.rate) {
            s.push_str(&format!(", {d}"));
        }
        s
    }
}

pub fn streaminfo(b: &mut Bits<'_>) -> Result<StreamInfo> {
    b.field("Minimum block size", 16).emit()?;
    b.field("Maximum block size", 16).emit()?;
    b.field("Minimum frame size", 24).emit()?;
    b.field("Maximum frame size", 24).emit()?;
    let rate = b.field("Sample rate", 20).emit()?;
    let channels = b
        .field("Channels − 1", 3)
        .with(|v, n| n.summary(channels(v.saturating_add(1))))
        .emit()?
        .saturating_add(1);
    let bits = b
        .field("Bits per sample − 1", 5)
        .with(|v, n| n.summary(format!("{}-bit", v.saturating_add(1))))
        .emit()?
        .saturating_add(1);
    let samples = b
        .field("Total samples", 36)
        .with(|v, n| match duration_of(v, rate) {
            Some(d) => n.summary(d),
            None => n,
        })
        .emit()?;
    b.bytes("MD5 signature", 16)
        .desc("MD5 of the unencoded audio")
        .emit()?;
    Ok(StreamInfo {
        rate,
        channels,
        bits,
        samples,
    })
}

record! {
    pub struct SeekPoint {
        sample: u64 "Sample number" .desc("0xffffffffffffffff = placeholder"),
        offset: u64 "Offset" .hex() .desc("From the first frame header"),
        samples: u16 "Samples in target frame",
    }
}

/// One metadata block: its type and where it is.
#[derive(Clone, Copy, Debug)]
pub struct Block {
    pub input: Input,
    pub kind: u8,
    /// Header and data.
    pub span: Span,
}

/// A lazy node for the metadata block at `span` (header included).
pub async fn block_node(cx: &Cx, input: Input, span: Span) -> Result<Node> {
    let head = cx.read(span.sub(0, 4)).await?;
    let kind = head.first().copied().unwrap_or(0) & 0x7f;
    let name = crate::value::lookup(BLOCK_TYPE, kind.into())
        .map_or_else(|| format!("Block type {kind}"), str::to_owned);
    let data = span.tail(4);
    let summary = match kind {
        0 => parse_bits(cx, data.sub(0, 34), streaminfo, false)
            .await
            .map(|s| s.summary())
            .ok(),
        3 => Some(format!("{} seek points", data.len / SeekPoint::SIZE)),
        4 => vorbis::title(cx, data).await,
        6 => picture_summary(cx, data).await.ok(),
        2 => {
            let id = cx.read_avail(data.sub(0, 4)).await?;
            Some(crate::formats::util::sound::fourcc(&id))
        }
        _ => None,
    };
    let node = Node::new(name)
        .span(span)
        .summary(summary.unwrap_or_else(|| format!("{} bytes", data.len)));
    Ok(node.lazy(
        crate::expander!(self::block: Block),
        Block { input, kind, span },
    ))
}

pub async fn block(cx: Cx, b: Block) -> Result<()> {
    let head = cx.block(b.span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u8("Header")
        .with(|&v, n| {
            n.value(enumerated(v & 0x7f, 7, BLOCK_TYPE))
                .summary(if v & 0x80 != 0 {
                    "last metadata block"
                } else {
                    "more blocks follow"
                })
        })
        .emit()?;
    crate::formats::util::sound::u24(&mut f, "Length", BE).emit()?;
    let data = b.span.tail(4);
    match b.kind {
        0 => cx.emit(bits_node(
            "Stream info",
            data,
            |b| streaminfo(b).map(|_| ()),
            false,
        )),
        1 => cx.emit(Node::new("Padding").span(data)),
        2 => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, BE)
                .ascii("Application ID", 4)
                .emit()?;
            cx.emit(Node::new("Data").span(data.tail(4)));
        }
        3 => cx.emit(table::<SeekPoint>(
            "Seek points",
            data,
            BE,
            "Point",
            Some(|p| {
                if p.sample == u64::MAX {
                    "placeholder".to_owned()
                } else {
                    format!("sample {} at {:#x}", p.sample, p.offset)
                }
            }),
        )),
        4 => {
            vorbis::emit(&cx, data).await?;
        }
        5 => cuesheet(&cx, data).await?,
        6 => picture(&cx, b.input, data).await?,
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

async fn cuesheet(cx: &Cx, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, 396)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.ascii("Media catalog number", 128).emit()?;
    f.u64("Lead-in samples").emit()?;
    f.u8("Flags")
        .with(|&v, n| n.summary(if v & 0x80 != 0 { "CD-DA" } else { "not CD-DA" }))
        .emit()?;
    f.bytes("Reserved", 258).emit()?;
    let tracks = f.u8("Tracks").emit()?;
    cx.emit(
        Node::new("Track data")
            .span(data.tail(396))
            .summary(format!("{tracks} tracks")),
    );
    Ok(())
}

/// The fields of a PICTURE block (also used inside Ogg comments).
pub async fn picture(cx: &Cx, input: Input, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, data.len.min(1 << 16))).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.u32("Picture type")
        .with(|&v, n| n.value(enumerated(v, 32, id3::PICTURE_TYPE)))
        .emit()?;
    let len = f.u32("MIME type length").emit()?;
    crate::formats::util::sound::latin1_field(&mut f, "MIME type", len.into()).emit()?;
    let len = f.u32("Description length").emit()?;
    f.bytes("Description", len.into())
        .with(|b, n| n.value(text(String::from_utf8_lossy(b).into_owned())))
        .emit()?;
    f.u32("Width").emit()?;
    f.u32("Height").emit()?;
    f.u32("Color depth").emit()?;
    f.u32("Colors used")
        .desc("For indexed images; 0 otherwise")
        .emit()?;
    let len = f.u32("Data length").emit()?;
    let image = data.sub(f.pos(), len.into());
    cx.emit(embedded("Picture data", input.nested(image)).summary(format!("{} bytes", image.len)));
    Ok(())
}

async fn picture_summary(cx: &Cx, data: Span) -> Result<String> {
    let head = cx.read_avail(data.sub(0, 512)).await?;
    let kind = u32_be(&head, 0).unwrap_or(0);
    let mime_len = to_usize(u32_be(&head, 4).unwrap_or(0).into());
    let mime = head
        .get(8..8usize.saturating_add(mime_len))
        .map(crate::text::latin1)
        .unwrap_or_default();
    let kind = crate::value::lookup(id3::PICTURE_TYPE, kind.into()).unwrap_or("picture");
    Ok(format!("{kind}, {mime}"))
}

// ---------------------------------------------------------------------------
// File

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 10)).await?;
    let mut pos = 0u64;
    if let Some(len) = id3::v2_len(&head) {
        cx.emit(id3::tag_node(&cx, input, file.sub(0, len)).await);
        pos = len;
    }
    cx.emit(Node::new("Signature").span(file.sub(pos, 4)));
    pos = pos.saturating_add(4);
    let mut info = None;
    let mut title = None;
    loop {
        let head = cx.read(file.sub(pos, 4)).await?;
        let flags = head.first().copied().unwrap_or(0);
        let len = u64::from(crate::bytes::u24_be(&head, 1).unwrap_or(0));
        let span = file.sub(pos, len.saturating_add(4));
        let data = span.tail(4);
        match flags & 0x7f {
            0 if info.is_none() => {
                info = parse_bits(&cx, data.sub(0, 34), streaminfo, false)
                    .await
                    .ok();
            }
            4 if title.is_none() => title = vorbis::title(&cx, data).await,
            _ => {}
        }
        let mut node = block_node(&cx, input, span).await?;
        if span.len < len.saturating_add(4) {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len.saturating_add(4)),
                span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(4).saturating_add(len);
        if flags & 0x80 != 0 || pos >= file.len {
            break;
        }
    }
    let mut line = match &info {
        Some(i) => format!("FLAC, {}", i.summary()),
        None => "FLAC".to_owned(),
    };
    if let Some(t) = title {
        line.push_str(&format!(" — {t}"));
    }
    cx.annotate(line);
    let frames = file.tail(pos);
    if !frames.is_empty() {
        cx.emit(
            Node::new("Frames")
                .span(frames)
                .summary(format!("{} bytes", frames.len))
                .lazy(list_frames, (frames, info.unwrap_or_default())),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frames

const CHANNELS: EnumTable = &[
    (0, "mono"),
    (1, "left, right"),
    (2, "left, right, center"),
    (3, "front L/R, back L/R"),
    (4, "5 channels"),
    (5, "5.1"),
    (6, "6.1"),
    (7, "7.1"),
    (8, "left/side stereo"),
    (9, "side/right stereo"),
    (10, "mid/side stereo"),
];

const SAMPLE_SIZE: EnumTable = &[
    (0, "from STREAMINFO"),
    (1, "8-bit"),
    (2, "12-bit"),
    (4, "16-bit"),
    (5, "20-bit"),
    (6, "24-bit"),
    (7, "32-bit"),
];

const RATE_CODE: EnumTable = &[
    (0, "from STREAMINFO"),
    (1, "88.2 kHz"),
    (2, "176.4 kHz"),
    (3, "192 kHz"),
    (4, "8 kHz"),
    (5, "16 kHz"),
    (6, "22.05 kHz"),
    (7, "24 kHz"),
    (8, "32 kHz"),
    (9, "44.1 kHz"),
    (10, "48 kHz"),
    (11, "96 kHz"),
    (12, "8-bit kHz follows"),
    (13, "16-bit Hz follows"),
    (14, "16-bit tens of Hz follows"),
];

/// A decoded frame header.
#[derive(Clone, Copy, Debug)]
struct FrameHeader {
    len: usize,
    number: u64,
    block_size: u64,
    channels: u8,
}

/// Parses (and CRC-checks) the frame header at the start of `d`.
fn frame_header(d: &[u8]) -> Option<FrameHeader> {
    if *d.first()? != 0xff || d.get(1)? & 0xfe != 0xf8 {
        return None;
    }
    let size_code = d.get(2)? >> 4;
    let rate_code = d.get(2)? & 0xf;
    let chan = d.get(3)? >> 4;
    if size_code == 0
        || rate_code == 15
        || chan > 10
        || d.get(3)? & 1 != 0
        || (d.get(3)? >> 1) & 7 == 3
    {
        return None;
    }
    // UTF-8-style coded frame or sample number.
    let first = *d.get(4)?;
    let extra = first.leading_ones() as usize;
    let (mut number, extra) = match extra {
        0 => (u64::from(first), 0),
        2..=7 => (u64::from(first & (0x7f >> extra)), extra.saturating_sub(1)),
        _ => return None,
    };
    for i in 0..extra {
        let b = *d.get(5usize.saturating_add(i))?;
        if b & 0xc0 != 0x80 {
            return None;
        }
        number = (number << 6) | u64::from(b & 0x3f);
    }
    let mut at = 5usize.saturating_add(extra);
    let block_size = match size_code {
        1 => 192,
        2..=5 => 576u64 << size_code.saturating_sub(2),
        6 => {
            at = at.saturating_add(1);
            u64::from(*d.get(at.saturating_sub(1))?).saturating_add(1)
        }
        7 => {
            at = at.saturating_add(2);
            u64::from(crate::bytes::u16_be(d, at.saturating_sub(2))?).saturating_add(1)
        }
        _ => 256u64 << size_code.saturating_sub(8),
    };
    at = at.saturating_add(match rate_code {
        12 => 1,
        13 | 14 => 2,
        _ => 0,
    });
    let crc = *d.get(at)?;
    if crc8(d.get(..at)?) != crc {
        return None;
    }
    Some(FrameHeader {
        len: at.saturating_add(1),
        number,
        block_size,
        channels: chan,
    })
}

/// How far ahead to look for the next frame in one read.
const WINDOW: u64 = 0x10000;

/// The offset (relative to `region`) of the next frame header after `from`.
async fn next_frame(cx: &Cx, region: Span, from: u64, number: u64) -> Result<Option<u64>> {
    let mut pos = from;
    while pos < region.len {
        let window = cx
            .read_avail(region.sub(pos, WINDOW.saturating_add(16)))
            .await?;
        let limit = window.len().saturating_sub(16).max(1);
        for i in 0..limit {
            if window.get(i) == Some(&0xff)
                && let Some(h) = window.get(i..).and_then(frame_header)
                && h.number >= number
            {
                return Ok(Some(pos.saturating_add(to_u64(i))));
            }
        }
        if to_u64(window.len()) <= 16 {
            break;
        }
        pos = pos.saturating_add(to_u64(limit));
        cx.checkpoint().await;
    }
    Ok(None)
}

async fn list_frames(cx: Cx, (region, info): (Span, StreamInfo)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < region.len {
        let head = cx.read_avail(region.sub(pos, 16)).await?;
        let Some(h) = frame_header(&head) else {
            cx.emit(
                Node::new("Unparsed data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed("no valid frame header")),
            );
            return Ok(());
        };
        let next = next_frame(
            &cx,
            region,
            pos.saturating_add(to_u64(h.len)),
            h.number.saturating_add(1),
        )
        .await?
        .unwrap_or(region.len);
        let span = region.sub(pos, next.saturating_sub(pos));
        let chans = crate::value::lookup(CHANNELS, h.channels.into()).unwrap_or("?");
        cx.push(
            Node::new(format!("Frame {index}"))
                .span(span)
                .summary(format!(
                    "#{}, {} samples, {chans}, {} bytes",
                    h.number, h.block_size, span.len
                ))
                .lazy(frame, (span, h.len, info)),
        )
        .await;
        pos = next;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn frame(cx: Cx, (span, header_len, _info): (Span, usize, StreamInfo)) -> Result<()> {
    let header = span.sub(0, to_u64(header_len));
    cx.emit(bits_node("Header", header, frame_fields, false));
    let crc_at = span.len.saturating_sub(2);
    cx.emit(
        Node::new("Subframes")
            .span(span.sub(
                to_u64(header_len),
                crc_at.saturating_sub(to_u64(header_len)),
            ))
            .desc("One encoded subframe per channel"),
    );
    let crc = cx.read(span.sub(crc_at, 2)).await?;
    cx.emit(leaf(
        "CRC-16",
        span.sub(crc_at, 2),
        hex(crate::bytes::u16_be(&crc, 0).unwrap_or(0), 16),
    ));
    Ok(())
}

fn frame_fields(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync code", 14).hex().emit()?;
    b.field("Reserved", 1).emit()?;
    b.field("Blocking strategy", 1)
        .with(|v, n| n.summary(if v == 0 { "fixed" } else { "variable" }))
        .emit()?;
    let size_code = b
        .field("Block size code", 4)
        .with(|v, n| match v {
            1 => n.summary("192"),
            2..=5 => n.summary(format!("{}", 576u64 << v.saturating_sub(2))),
            6 => n.summary("8-bit value follows"),
            7 => n.summary("16-bit value follows"),
            8..=15 => n.summary(format!("{}", 256u64 << v.saturating_sub(8))),
            _ => n,
        })
        .emit()?;
    let rate_code = b
        .field("Sample rate code", 4)
        .enumeration(RATE_CODE)
        .emit()?;
    b.field("Channel assignment", 4)
        .enumeration(CHANNELS)
        .emit()?;
    b.field("Sample size", 3).enumeration(SAMPLE_SIZE).emit()?;
    b.field("Reserved", 1).emit()?;
    // The frame or sample number, UTF-8 style: the first byte's leading
    // ones count the bytes.
    let start = b.pos();
    let first = b.read(8).unwrap_or(0);
    let extra = u8::try_from(first).unwrap_or(0).leading_ones();
    let (mut number, extra) = if extra >= 2 {
        (first & (0x7f >> extra), extra.saturating_sub(1))
    } else {
        (first, 0)
    };
    for _ in 0..extra {
        number = (number << 6) | (b.read(8).unwrap_or(0) & 0x3f);
    }
    b.node(
        Node::new("Frame/sample number")
            .span(b.span_of(start, b.pos()))
            .value(uint(number, 64))
            .desc("Frame number (fixed blocking) or first sample number (variable)"),
    );
    match size_code {
        6 => {
            b.field("Block size − 1", 8).emit()?;
        }
        7 => {
            b.field("Block size − 1", 16).emit()?;
        }
        _ => {}
    }
    match rate_code {
        12 => {
            b.field("Sample rate (kHz)", 8).emit()?;
        }
        13 => {
            b.field("Sample rate (Hz)", 16).emit()?;
        }
        14 => {
            b.field("Sample rate (10 Hz)", 16).emit()?;
        }
        _ => {}
    }
    b.field("CRC-8", 8).hex().emit()?;
    Ok(())
}
