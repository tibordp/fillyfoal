//! MPEG-1/2/2.5 audio, layers I–III (MP1, MP2, MP3).
//!
//! The file is an optional ID3v2 tag, a sequence of frames each starting
//! with a 32-bit header, then optional APE and ID3v1 tags at the end. The
//! first frame may carry a Xing/Info (with LAME extension) or VBRI header
//! with the frame count of a VBR stream. Frames are listed lazily by
//! following the frame lengths computed from their headers.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::sound::{Bits, bits_node, duration, u24};
use crate::formats::{Format, Head, Input, Probe, audio::apetag, audio::id3};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "mp3",
    title: "MPEG audio (MP3, MP2, MP1)",
    extensions: &["mp3", "mp2", "mp1", "mpga", "m2a"],
    mime: "audio/mpeg",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    match id3::v2_len(h.data) {
        Some(len) => match h.data.get(to_usize(len)..) {
            Some(rest) if rest.len() >= 4 => find_sync(rest, 4096).is_some(),
            // The tag is larger than what the probe can see.
            _ => len < h.len,
        },
        // Without a tag, demand two consecutive frames: a lone sync-like
        // pair of bytes (e.g. a UTF-16LE BOM) is too weak.
        None => Header::parse(h.data)
            .and_then(|f| f.frame_len().map(|len| (f, len)))
            .is_some_and(|(f, len)| {
                let next = to_usize(len);
                h.data
                    .get(next..next.saturating_add(4))
                    .and_then(Header::parse)
                    .is_some_and(|n| {
                        n.version == f.version && n.layer == f.layer && n.rate == f.rate
                    })
            }),
    }
}

/// A valid frame header at `at`, followed by another one (if it is in
/// `data`).
fn plausible(data: &[u8], at: usize) -> bool {
    let Some(h) = data.get(at..).and_then(Header::parse) else {
        return false;
    };
    let Some(len) = h.frame_len() else {
        return false;
    };
    let next = at.saturating_add(to_usize(len));
    match data.get(next..next.saturating_add(4)) {
        Some(b) => {
            Header::parse(b).is_some_and(|n| n.version == h.version && n.layer == h.layer)
                || matches!(b, [b'T', b'A', b'G', _] | b"APET" | b"LYRI")
        }
        None => true,
    }
}

/// The first plausible frame within `limit` bytes of `data`.
pub fn find_sync(data: &[u8], limit: usize) -> Option<usize> {
    (0..data.len().min(limit)).find(|&i| data.get(i) == Some(&0xff) && plausible(data, i))
}

// ---------------------------------------------------------------------------
// Frame headers

const VERSION: EnumTable = &[
    (0, "MPEG-2.5"),
    (1, "reserved"),
    (2, "MPEG-2"),
    (3, "MPEG-1"),
];
const LAYER: EnumTable = &[
    (0, "reserved"),
    (1, "Layer III"),
    (2, "Layer II"),
    (3, "Layer I"),
];
const MODE: EnumTable = &[
    (0, "stereo"),
    (1, "joint stereo"),
    (2, "dual channel"),
    (3, "mono"),
];
const EMPHASIS: EnumTable = &[
    (0, "none"),
    (1, "50/15 µs"),
    (2, "reserved"),
    (3, "CCITT J.17"),
];

const BITRATES: [[[u16; 15]; 3]; 2] = [
    [
        [
            0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
        ],
        [
            0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
        ],
        [
            0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
        ],
    ],
    [
        [
            0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
        ],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
        [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
    ],
];

const RATES: [[u32; 3]; 3] = [
    [44100, 48000, 32000],
    [22050, 24000, 16000],
    [11025, 12000, 8000],
];

/// A decoded frame header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Header {
    /// 1 = MPEG-1, 2 = MPEG-2, 25 = MPEG-2.5.
    pub version: u8,
    /// 1, 2 or 3.
    pub layer: u8,
    pub crc: bool,
    /// kbit/s; 0 for free format.
    pub bitrate: u32,
    pub rate: u32,
    pub padding: bool,
    pub mode: u8,
}

impl Header {
    pub fn parse(b: &[u8]) -> Option<Header> {
        let w = crate::bytes::u32_be(b, 0)?;
        if w >> 21 != 0x7ff {
            return None;
        }
        let version = match (w >> 19) & 3 {
            0 => 25,
            2 => 2,
            3 => 1,
            _ => return None,
        };
        let layer: u8 = match (w >> 17) & 3 {
            1 => 3,
            2 => 2,
            3 => 1,
            _ => return None,
        };
        let bitrate_index = to_usize(u64::from((w >> 12) & 0xf));
        let rate_index = to_usize(u64::from((w >> 10) & 3));
        let table = usize::from(version != 1);
        let row = usize::from(layer.saturating_sub(1));
        let bitrate = *BITRATES.get(table)?.get(row)?.get(bitrate_index)?;
        let rate_row = match version {
            1 => 0,
            2 => 1,
            _ => 2,
        };
        let rate = *RATES.get(rate_row)?.get(rate_index)?;
        Some(Header {
            version,
            layer,
            crc: (w >> 16) & 1 == 0,
            bitrate: bitrate.into(),
            rate,
            padding: (w >> 9) & 1 == 1,
            mode: u8::try_from((w >> 6) & 3).unwrap_or(0),
        })
    }

    pub fn samples(&self) -> u32 {
        match (self.layer, self.version) {
            (1, _) => 384,
            (3, 2 | 25) => 576,
            _ => 1152,
        }
    }

    /// Frame length in bytes, including the header; `None` for free format.
    pub fn frame_len(&self) -> Option<u64> {
        if self.bitrate == 0 {
            return None;
        }
        let bits = u64::from(self.bitrate).checked_mul(1000)?;
        let pad = u64::from(self.padding);
        let rate = u64::from(self.rate);
        let len = match self.layer {
            1 => bits
                .checked_mul(12)?
                .checked_div(rate)?
                .checked_add(pad)?
                .checked_mul(4)?,
            _ => {
                let factor = if self.layer == 3 && self.version != 1 {
                    72
                } else {
                    144
                };
                bits.checked_mul(factor)?
                    .checked_div(rate)?
                    .checked_add(pad)?
            }
        };
        (len >= 4).then_some(len)
    }

    /// Size of the Layer III side information.
    fn side_info(&self) -> u64 {
        match (self.version == 1, self.mode == 3) {
            (true, true) => 17,
            (true, false) => 32,
            (false, true) => 9,
            (false, false) => 17,
        }
    }

    fn version_name(&self) -> &'static str {
        match self.version {
            1 => "MPEG-1",
            2 => "MPEG-2",
            _ => "MPEG-2.5",
        }
    }

    fn layer_name(&self) -> &'static str {
        match self.layer {
            1 => "Layer I",
            2 => "Layer II",
            _ => "Layer III",
        }
    }

    fn mode_name(&self) -> &'static str {
        crate::value::lookup(MODE, self.mode.into()).unwrap_or("?")
    }

    /// "MPEG-1 Layer III, 128 kbps, 44100 Hz, joint stereo".
    pub fn describe(&self) -> String {
        format!(
            "{} {}, {} kbps, {} Hz, {}",
            self.version_name(),
            self.layer_name(),
            self.bitrate,
            self.rate,
            self.mode_name()
        )
    }
}

fn header_fields(b: &mut Bits<'_>) -> Result<()> {
    b.field("Frame sync", 11).hex().emit()?;
    let version = b.field("Version", 2).enumeration(VERSION).emit()?;
    let layer = b.field("Layer", 2).enumeration(LAYER).emit()?;
    b.field("Protection", 1)
        .with(|v, n| n.summary(if v == 0 { "CRC follows" } else { "no CRC" }))
        .emit()?;
    let table = usize::from(version != 3);
    let row = to_usize(3u64.saturating_sub(layer));
    b.field("Bitrate index", 4)
        .with(|v, n| {
            let kbps = BITRATES
                .get(table)
                .and_then(|t| t.get(row))
                .and_then(|r| r.get(to_usize(v)))
                .copied();
            match kbps {
                Some(0) => n.summary("free format"),
                Some(k) => n.summary(format!("{k} kbps")),
                None => n.diag(Diagnostic::malformed("invalid bitrate index")),
            }
        })
        .emit()?;
    let rate_row = match version {
        3 => 0,
        2 => 1,
        _ => 2,
    };
    b.field("Sample rate index", 2)
        .with(
            |v, n| match RATES.get(rate_row).and_then(|r| r.get(to_usize(v))) {
                Some(r) => n.summary(format!("{r} Hz")),
                None => n.diag(Diagnostic::malformed("reserved sample rate")),
            },
        )
        .emit()?;
    b.field("Padding", 1).flag().emit()?;
    b.field("Private", 1).flag().emit()?;
    let mode = b.field("Channel mode", 2).enumeration(MODE).emit()?;
    b.field("Mode extension", 2)
        .desc("Joint stereo: intensity / M-S stereo bands")
        .with(|v, n| {
            if mode == 1 && layer == 1 {
                n.summary(format!(
                    "intensity {}, M/S {}",
                    if v & 1 != 0 { "on" } else { "off" },
                    if v & 2 != 0 { "on" } else { "off" }
                ))
            } else {
                n
            }
        })
        .emit()?;
    b.field("Copyright", 1).flag().emit()?;
    b.field("Original", 1).flag().emit()?;
    b.field("Emphasis", 2).enumeration(EMPHASIS).emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Xing / Info / LAME and VBRI

const XING_FLAGS: FlagTable = &[
    flag(0x1, "FRAMES"),
    flag(0x2, "BYTES"),
    flag(0x4, "TOC"),
    flag(0x8, "QUALITY"),
];

const VBR_METHOD: EnumTable = &[
    (0, "unknown"),
    (1, "CBR"),
    (2, "ABR"),
    (3, "VBR (old)"),
    (4, "VBR (mtrh)"),
    (5, "VBR (rh)"),
    (6, "VBR (mt)"),
    (8, "CBR (2 pass)"),
    (9, "ABR (2 pass)"),
];

#[derive(Clone, Copy, Debug, Default)]
struct Vbr {
    frames: Option<u32>,
    bytes: Option<u32>,
    /// Info headers mark CBR files.
    cbr: bool,
}

fn xing(f: &mut Fields<'_>, _: &()) -> Result<Vbr> {
    let id = f.ascii("ID", 4).emit()?;
    let flags = f.u32("Flags").flags(XING_FLAGS).emit()?;
    let mut v = Vbr {
        cbr: id == "Info",
        ..Vbr::default()
    };
    if flags & 1 != 0 {
        v.frames = Some(f.u32("Frames").emit()?);
    }
    if flags & 2 != 0 {
        v.bytes = Some(f.u32("Bytes").emit()?);
    }
    if flags & 4 != 0 {
        f.bytes("Table of contents", 100)
            .desc("Seek points: byte position (/256) at each percent of the duration")
            .emit()?;
    }
    if flags & 8 != 0 {
        f.u32("Quality").emit()?;
    }
    let peek = f.block().data.get(to_usize(f.pos())..).unwrap_or_default();
    if f.remaining() >= 36 && peek.first().is_some_and(u8::is_ascii_alphabetic) {
        f.ascii("Encoder", 9).emit()?;
        f.u8("Revision / VBR method")
            .with(|&b, n| {
                n.summary(format!(
                    "revision {}, {}",
                    b >> 4,
                    crate::value::lookup(VBR_METHOD, (b & 0xf).into()).unwrap_or("?")
                ))
            })
            .emit()?;
        f.u8("Lowpass")
            .with(|&b, n| n.summary(format!("{} Hz", u32::from(b).saturating_mul(100))))
            .emit()?;
        f.f32("Peak amplitude").emit()?;
        f.u16("Radio replay gain").hex().emit()?;
        f.u16("Audiophile replay gain").hex().emit()?;
        f.u8("Encoding flags / ATH type").hex().emit()?;
        f.u8("Bitrate")
            .desc("ABR: average; CBR: exact; VBR: minimum (kbps)")
            .emit()?;
        u24(f, "Encoder delay / padding", BE)
            .with(|&v, n| n.summary(format!("delay {}, padding {}", v >> 12, v & 0xfff)))
            .emit()?;
        f.u8("Misc").hex().emit()?;
        f.u8("MP3 gain").emit()?;
        f.u16("Preset / surround").hex().emit()?;
        f.u32("Music length").emit()?;
        f.u16("Music CRC").hex().emit()?;
        f.u16("Tag CRC").hex().emit()?;
    }
    Ok(v)
}

fn vbri(f: &mut Fields<'_>, _: &()) -> Result<Vbr> {
    f.ascii("ID", 4).emit()?;
    f.u16("Version").emit()?;
    f.u16("Delay").emit()?;
    f.u16("Quality").emit()?;
    let bytes = f.u32("Bytes").emit()?;
    let frames = f.u32("Frames").emit()?;
    let entries = f.u16("TOC entries").emit()?;
    f.u16("TOC scale").emit()?;
    let size = f.u16("TOC entry size").emit()?;
    f.u16("Frames per TOC entry").emit()?;
    let toc = u64::from(entries).saturating_mul(size.into());
    if toc > 0 {
        f.bytes("Table of contents", toc.min(f.remaining()))
            .emit()?;
    }
    Ok(Vbr {
        frames: Some(frames),
        bytes: Some(bytes),
        cbr: false,
    })
}

/// Where a Xing/Info or VBRI header sits in a frame, if one does.
async fn vbr_header(cx: &Cx, frame: Span, h: &Header) -> Result<Option<(Span, bool)>> {
    let crc = if h.crc { 2 } else { 0 };
    let xing_at = 4u64.saturating_add(crc).saturating_add(h.side_info());
    let magic = cx.read_avail(frame.sub(xing_at, 4)).await?;
    if magic == b"Xing" || magic == b"Info" {
        return Ok(Some((frame.tail(xing_at), true)));
    }
    let magic = cx.read_avail(frame.sub(36, 4)).await?;
    if magic == b"VBRI" {
        return Ok(Some((frame.tail(36), false)));
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 10)).await?;
    let mut start = 0u64;
    let mut tags = Vec::new();
    if let Some(len) = id3::v2_len(&head) {
        let span = file.sub(0, len);
        cx.emit(id3::tag_node(&cx, input, span).await);
        if let Some(t) = id3::title(&cx, span).await {
            tags.push(t);
        }
        start = len;
    }
    // Tags at the end: ID3v1, preceded by an optional APE tag.
    let mut end = file.len;
    let mut trailing = Vec::new();
    if let Some(v1) = id3::find_v1(&cx, file).await? {
        if let Some(t) = id3::v1_title(&cx, v1).await {
            tags.push(t);
        }
        trailing.push(id3::v1_node(&cx, v1).await?);
        end = end.saturating_sub(128);
    }
    if let Some(ape) = apetag::find(&cx, file, end).await? {
        trailing.push(apetag::node(&cx, input, ape).await);
        end = ape.offset.saturating_sub(file.offset);
    }
    let audio = file.sub(start, end.saturating_sub(start));

    let window = cx.read_avail(audio.sub(0, 0x10000)).await?;
    let Some(skip) = find_sync(&window, window.len()) else {
        cx.emit(
            Node::new("Data")
                .span(audio)
                .diag(Diagnostic::malformed("no MPEG audio frame found")),
        );
        for node in trailing.into_iter().rev() {
            cx.emit(node);
        }
        return Ok(());
    };
    if skip > 0 {
        cx.emit(
            Node::new("Unrecognised data")
                .span(audio.sub(0, to_u64(skip)))
                .summary(format!("{skip} bytes before the first frame")),
        );
    }
    let stream = audio.tail(to_u64(skip));
    let header = Header::parse(window.get(skip..).unwrap_or_default())
        .ok_or_else(|| Diagnostic::internal("frame header vanished"))?;
    let first = stream.sub(0, header.frame_len().unwrap_or(4));

    let mut vbr = None;
    if let Some((span, is_xing)) = vbr_header(&cx, first, &header).await? {
        let (name, layout) = if is_xing {
            ("Xing header", xing as crate::fields::Layout<(), Vbr>)
        } else {
            ("VBRI header", vbri as crate::fields::Layout<(), Vbr>)
        };
        match parse(&cx, span, BE, &(), layout).await {
            Ok(v) => {
                let mut node = struct_node(name, span, BE, (), layout);
                if let Some(n) = v.frames {
                    node =
                        node.summary(format!("{}, {n} frames", if v.cbr { "CBR" } else { "VBR" }));
                }
                cx.emit(node);
                vbr = Some(v);
            }
            Err(e) => cx.diag(e),
        }
    }

    // Summary line.
    let samples = u64::from(header.samples());
    let (seconds, rate) = match vbr.and_then(|v| v.frames.map(|f| (f, v))) {
        Some((frames, v)) if header.rate > 0 => {
            let seconds = (frames as f64) * (samples as f64) / f64::from(header.rate);
            let bytes = v.bytes.map_or(stream.len as f64, f64::from);
            let kbps = if seconds > 0.0 {
                bytes * 8.0 / seconds / 1000.0
            } else {
                0.0
            };
            let label = if v.cbr { "" } else { "VBR " };
            (seconds, format!("{label}{kbps:.0} kbps"))
        }
        _ if header.bitrate > 0 => (
            stream.len as f64 * 8.0 / (f64::from(header.bitrate) * 1000.0),
            format!("{} kbps", header.bitrate),
        ),
        _ => (0.0, "free format".to_owned()),
    };
    let mut line = format!(
        "{} {}, {rate}, {} Hz, {}, {}",
        header.version_name(),
        header.layer_name(),
        header.rate,
        header.mode_name(),
        duration(seconds)
    );
    if let Some(t) = tags.first() {
        line.push_str(&format!(" — {t}"));
    }
    cx.annotate(line);

    let frame_count = vbr.and_then(|v| v.frames);
    let mut frames = Node::new("Frames").span(stream);
    frames = match frame_count {
        Some(n) => frames.summary(format!("{n} frames")),
        None => frames.summary(format!("{} bytes", stream.len)),
    };
    cx.emit(frames.lazy(list_frames, stream));
    for node in trailing.into_iter().rev() {
        cx.emit(node);
    }
    Ok(())
}

/// Pushes one node per frame, following the lengths in the headers.
async fn list_frames(cx: Cx, region: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while region.len.saturating_sub(pos) >= 4 {
        let head = cx.read(region.sub(pos, 4)).await?;
        let Some((h, len)) = Header::parse(&head).and_then(|h| h.frame_len().map(|l| (h, l)))
        else {
            let rest = region.tail(pos);
            let mut node = Node::new("Unparsed data").span(rest);
            if head.iter().all(|&b| b == 0) {
                node = node.summary("padding");
            } else {
                node = node.diag(Diagnostic::malformed("lost frame sync"));
            }
            cx.emit(node);
            return Ok(());
        };
        let span = region.sub(pos, len);
        let mut node = Node::new(format!("Frame {index}"))
            .span(span)
            .summary(format!("{}, {len} bytes", h.describe()));
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.push(node.lazy(frame, (span, h))).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    if pos < region.len {
        cx.emit(Node::new("Trailing bytes").span(region.tail(pos)));
    }
    Ok(())
}

async fn frame(cx: Cx, (span, h): (Span, Header)) -> Result<()> {
    cx.emit(bits_node("Header", span.sub(0, 4), header_fields, false));
    let mut pos = 4u64;
    if h.crc {
        let block = cx.block(span.sub(4, 2)).await?;
        Fields::emitting(&cx, &block, BE).u16("CRC").hex().emit()?;
        pos = 6;
    }
    if h.layer == 3 {
        cx.emit(
            Node::new("Side information")
                .span(span.sub(pos, h.side_info()))
                .desc("Granule and channel parameters for Huffman decoding"),
        );
        pos = pos.saturating_add(h.side_info());
    }
    if let Some((at, is_xing)) = vbr_header(&cx, span, &h).await? {
        let (name, layout) = if is_xing {
            ("Xing header", xing as crate::fields::Layout<(), Vbr>)
        } else {
            ("VBRI header", vbri as crate::fields::Layout<(), Vbr>)
        };
        cx.emit(struct_node(name, at, BE, (), layout));
        return Ok(());
    }
    cx.emit(Node::new("Audio data").span(span.tail(pos)));
    Ok(())
}
