//! MPEG-1/2/2.5 audio, layers I–III (MP1, MP2, MP3).
//!
//! The file is an optional ID3v2 tag, a sequence of frames each starting
//! with a 32-bit header, then optional tags at the end (APE, Lyrics3, an
//! appended ID3v2 tag, Enhanced TAG+, ID3v1). The first frame may carry a
//! Xing/Info header (with a LAME extension) or a VBRI header with the frame
//! count of the stream, from which the duration is computed exactly (less
//! the encoder delay and padding the LAME tag records).
//!
//! Frames are listed lazily by following the lengths computed from their
//! headers; free-format streams, whose headers give no bitrate, by the
//! distance between the first two frames. Junk between frames is skipped
//! and reported, and ID3v2 tags between concatenated streams are shown.

use crate::bytes::{to_u64, to_usize, u16_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Layout, parse, struct_node};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{
    Bits, CRC16_MPEG, FrameSyntax, bits_node, duration, junk_node, leaf, resync, tail_node,
};
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Format, Head, Input, Probe, audio::id3};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

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
        None => {
            let Some(f) = Header::parse(h.data) else {
                return false;
            };
            let Some(len) = f.frame_len().or_else(|| free_stream(h.data)) else {
                return false;
            };
            let next = to_usize(len);
            h.data
                .get(next..next.saturating_add(4))
                .and_then(Header::parse)
                .is_some_and(|n| n.same_stream(&f))
        }
    }
}

/// A valid frame header at `at`, followed by another one (if it is in
/// `data`).
fn plausible(data: &[u8], at: usize) -> bool {
    let Some(rest) = data.get(at..) else {
        return false;
    };
    let Some(h) = Header::parse(rest) else {
        return false;
    };
    let Some(len) = h.frame_len().or_else(|| free_stream(rest)) else {
        return false;
    };
    let next = at.saturating_add(to_usize(len));
    match data.get(next..next.saturating_add(4)) {
        Some(b) => {
            Header::parse(b).is_some_and(|n| n.version == h.version && n.layer == h.layer)
                || matches!(
                    b,
                    [b'T', b'A', b'G', _] | b"APET" | b"LYRI" | [b'I', b'D', b'3', _]
                )
        }
        None => true,
    }
}

/// The first plausible frame within `limit` bytes of `data`.
pub fn find_sync(data: &[u8], limit: usize) -> Option<usize> {
    (0..data.len().min(limit)).find(|&i| data.get(i) == Some(&0xff) && plausible(data, i))
}

/// The length of the free-format frame at the start of `data`: the
/// distance to the next header of the same stream.
fn free_len(data: &[u8]) -> Option<u64> {
    let h = Header::parse(data)?;
    // Free-format Layer I is unheard of, and FF FF starts too many other
    // things.
    if h.bitrate != 0 || h.layer == 1 {
        return None;
    }
    let [b0, b1, b2, b3] = crate::bytes::array::<4>(data, 0)?;
    // The smallest free-format frame (Layer III at 8 kbps) is longer than
    // this; the largest (Layer I at 448+ kbps, 8 kHz) shorter than 8 KiB.
    (24usize..8192)
        .find(|&k| {
            data.get(k..k.saturating_add(4)).is_some_and(|n| {
                n.first() == Some(&b0)
                    && n.get(1) == Some(&b1)
                    && n.get(2).is_some_and(|&x| x & 0xfc == b2 & 0xfc)
                    && n.get(3).is_some_and(|&x| x & 0xc0 == b3 & 0xc0)
            })
        })
        .map(to_u64)
}

/// The length of a free-format frame at the start of `data` followed by
/// two more of (nearly) the same length: evidence enough for a probe.
fn free_stream(data: &[u8]) -> Option<u64> {
    let first = free_len(data)?;
    let second = free_len(data.get(to_usize(first)..)?)?;
    (first.abs_diff(second) <= 1).then_some(first)
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
    pub mode_ext: u8,
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
            mode_ext: u8::try_from((w >> 4) & 3).unwrap_or(0),
        })
    }

    /// Whether `other` can be the next frame of the same stream.
    fn same_stream(&self, other: &Header) -> bool {
        self.version == other.version && self.layer == other.layer && self.rate == other.rate
    }

    pub fn samples(&self) -> u32 {
        match (self.layer, self.version) {
            (1, _) => 384,
            (3, 2 | 25) => 576,
            _ => 1152,
        }
    }

    pub fn channels(&self) -> u64 {
        if self.mode == 3 { 1 } else { 2 }
    }

    /// Bytes per frame and kbit/s.
    fn factor(&self) -> u64 {
        match (self.layer, self.version) {
            (1, _) => 12,
            (3, 2 | 25) => 72,
            _ => 144,
        }
    }

    /// The padding added by the padding bit: one slot.
    fn pad_bytes(&self) -> u64 {
        match (self.padding, self.layer) {
            (false, _) => 0,
            (true, 1) => 4,
            (true, _) => 1,
        }
    }

    /// Frame length in bytes, including the header; `None` for free format.
    pub fn frame_len(&self) -> Option<u64> {
        if self.bitrate == 0 {
            return None;
        }
        let bits = u64::from(self.bitrate).checked_mul(1000)?;
        let rate = u64::from(self.rate);
        let len = match self.layer {
            1 => bits
                .checked_mul(12)?
                .checked_div(rate)?
                .checked_mul(4)?
                .checked_add(self.pad_bytes())?,
            _ => bits
                .checked_mul(self.factor())?
                .checked_div(rate)?
                .checked_add(self.pad_bytes())?,
        };
        (len >= 4).then_some(len)
    }

    /// The bitrate (kbit/s) a frame of `len` bytes has.
    fn kbps_of(&self, len: u64) -> f64 {
        let len = len.saturating_sub(self.pad_bytes()) as f64;
        let per = if self.layer == 1 { 4.0 } else { 1.0 };
        len / per * f64::from(self.rate) / self.factor() as f64 / 1000.0
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

    /// Bytes after the CRC that the CRC covers (with header bytes 2 and 3):
    /// the side information (Layer III) or the bit allocation (Layer I).
    /// Layer II also covers its scale factor selection, whose size depends
    /// on allocation tables; `None` there.
    fn protected(&self) -> Option<u64> {
        match self.layer {
            3 => Some(self.side_info()),
            1 => Some(match self.mode {
                3 => 16,
                1 => 16u64.saturating_add(
                    2u64.saturating_mul(u64::from(self.mode_ext).saturating_add(1)),
                ),
                _ => 32,
            }),
            _ => None,
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
        lookup(MODE, self.mode.into()).unwrap_or("?")
    }

    /// "MPEG-1 Layer III, 128 kbps, 44100 Hz, joint stereo".
    pub fn describe(&self) -> String {
        let bitrate = if self.bitrate == 0 {
            "free format".to_owned()
        } else {
            format!("{} kbps", self.bitrate)
        };
        format!(
            "{} {}, {bitrate}, {} Hz, {}",
            self.version_name(),
            self.layer_name(),
            self.rate,
            self.mode_name()
        )
    }
}

fn header_fields(b: &mut Bits<'_>) -> Result<()> {
    b.field("Frame sync", 11).hex().emit()?;
    let version = b
        .field("Version", 2)
        .enumeration(VERSION)
        .with(|v, n| {
            if v == 1 {
                n.diag(Diagnostic::malformed("reserved version"))
            } else {
                n
            }
        })
        .emit()?;
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
    b.field("Padding", 1)
        .flag()
        .desc(
            "One extra slot (4 bytes in Layer I, 1 byte otherwise) keeps the average bitrate exact",
        )
        .emit()?;
    b.field("Private", 1).flag().emit()?;
    let mode = b.field("Channel mode", 2).enumeration(MODE).emit()?;
    b.field("Mode extension", 2)
        .desc("Joint stereo: which stereo coding tools this frame uses")
        .with(|v, n| match (mode, layer) {
            // Layer III: intensity and M/S stereo switches.
            (1, 1) => n.summary(format!(
                "intensity stereo {}, M/S stereo {}",
                if v & 1 != 0 { "on" } else { "off" },
                if v & 2 != 0 { "on" } else { "off" }
            )),
            // Layers I and II: the first subband coded as intensity stereo.
            (1, _) => n.summary(format!(
                "intensity stereo in subbands {}–31",
                v.saturating_add(1).saturating_mul(4)
            )),
            _ => n,
        })
        .emit()?;
    b.field("Copyright", 1).flag().emit()?;
    b.field("Original", 1)
        .with(|v, n| {
            n.value(Value::Bool(v != 0))
                .summary(if v != 0 { "original" } else { "copy" })
        })
        .emit()?;
    b.field("Emphasis", 2)
        .enumeration(EMPHASIS)
        .with(|v, n| {
            if v == 2 {
                n.diag(Diagnostic::malformed("reserved emphasis"))
            } else {
                n
            }
        })
        .emit()?;
    Ok(())
}

/// For [`resync`]: frames whose length the header gives.
static SYNTAX: FrameSyntax = FrameSyntax {
    peek: 4,
    sync: &[0xff],
    parse: parse_frame,
    header: header_len,
    layout: header_fields,
    expand: None,
};

fn parse_frame(d: &[u8]) -> Option<(u64, String)> {
    let h = Header::parse(d)?;
    Some((h.frame_len()?, h.describe()))
}

fn header_len(_: &[u8]) -> u64 {
    4
}

// ---------------------------------------------------------------------------
// Layer III side information

const BLOCK_TYPE: EnumTable = &[
    (0, "reserved"),
    (1, "start"),
    (2, "short (3 windows)"),
    (3, "stop"),
];

/// What a granule's summary shows.
struct Granule {
    part23: u64,
    gain: u64,
    /// `None` without window switching (long blocks).
    block_type: Option<u64>,
    mixed: bool,
}

fn granule(b: &mut Bits<'_>, mpeg1: bool) -> Result<Granule> {
    let part23 = b
        .field("Part 2–3 length", 12)
        .desc("Bits of scale factors and Huffman-coded data in this granule and channel")
        .with(|v, n| n.summary(format!("{v} bits")))
        .emit()?;
    b.field("Big values", 9)
        .desc("Pairs of spectral values coded with the big-value Huffman tables")
        .emit()?;
    let gain = b
        .field("Global gain", 8)
        .desc("Quantiser step size")
        .emit()?;
    b.field("Scale factor compression", if mpeg1 { 4 } else { 9 })
        .desc("Bits per scale factor band group")
        .emit()?;
    let switching = b.field("Window switching", 1).flag().emit()? != 0;
    let mut g = Granule {
        part23,
        gain,
        block_type: None,
        mixed: false,
    };
    if switching {
        g.block_type = Some(
            b.field("Block type", 2)
                .enumeration(BLOCK_TYPE)
                .with(|v, n| {
                    if v == 0 {
                        n.diag(Diagnostic::malformed("block type 0 with window switching"))
                    } else {
                        n
                    }
                })
                .emit()?,
        );
        g.mixed = b
            .field("Mixed block", 1)
            .flag()
            .desc("The lowest subbands use long blocks")
            .emit()?
            != 0;
        for name in ["Table select (region 0)", "Table select (region 1)"] {
            b.field(name, 5).emit()?;
        }
        for name in [
            "Subblock gain (window 0)",
            "Subblock gain (window 1)",
            "Subblock gain (window 2)",
        ] {
            b.field(name, 3).emit()?;
        }
    } else {
        for name in [
            "Table select (region 0)",
            "Table select (region 1)",
            "Table select (region 2)",
        ] {
            b.field(name, 5).emit()?;
        }
        b.field("Region 0 count", 4)
            .desc("Scale factor bands in region 0, minus one")
            .emit()?;
        b.field("Region 1 count", 3)
            .desc("Scale factor bands in region 1, minus one")
            .emit()?;
    }
    if mpeg1 {
        b.field("Pre-emphasis", 1).flag().emit()?;
    }
    b.field("Scale factor scale", 1)
        .with(|v, n| n.summary(if v == 0 { "√2 steps" } else { "2× steps" }))
        .emit()?;
    b.field("Count1 table", 1)
        .with(|v, n| n.summary(if v == 0 { "table A" } else { "table B" }))
        .emit()?;
    Ok(g)
}

impl Granule {
    fn summary(&self) -> String {
        let blocks = match (self.block_type, self.mixed) {
            (None, _) => "long blocks",
            (Some(1), _) => "start block",
            (Some(2), true) => "mixed short blocks",
            (Some(2), false) => "short blocks",
            (Some(3), _) => "stop block",
            _ => "reserved block type",
        };
        format!("{blocks}, {} bits, global gain {}", self.part23, self.gain)
    }
}

fn side_info_node(span: Span, h: Header) -> Node {
    Node::new("Side information")
        .span(span)
        .desc("Where the main data starts and how each granule and channel is coded")
        .lazy(expand_side_info, (span, h))
}

const SCFSI: [&str; 2] = ["SCFSI (channel 0)", "SCFSI (channel 1)"];

async fn expand_side_info(cx: Cx, (span, h): (Span, Header)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut b = Bits::emitting(&cx, &data, span);
    let mpeg1 = h.version == 1;
    let channels = h.channels();
    b.field("Main data begin", if mpeg1 { 9 } else { 8 })
        .desc("Where this frame's main data starts: bytes back from the end of this side information, in earlier frames' main data (the bit reservoir)")
        .with(|v, n| {
            n.summary(if v == 0 {
                "starts in this frame".to_owned()
            } else {
                format!("{v} bytes back in the bit reservoir")
            })
        })
        .emit()?;
    let private = match (mpeg1, channels) {
        (true, 1) => 5,
        (true, _) => 3,
        (false, 1) => 1,
        (false, _) => 2,
    };
    b.field("Private bits", private).emit()?;
    if mpeg1 {
        for name in SCFSI.iter().copied().take(to_usize(channels)) {
            b.field(name, 4)
                .desc("Scale factor selection: band groups whose scale factors granule 1 reuses from granule 0")
                .with(|v, n| n.summary(format!("{v:04b}")))
                .emit()?;
        }
    }
    let granules = if mpeg1 { 2 } else { 1 };
    for gr in 0..granules {
        for ch in 0..channels {
            let start = b.pos();
            let mut silent = Bits::new(&data, span);
            silent.seek(start);
            let g = granule(&mut silent, mpeg1)?;
            let end = silent.pos();
            let name = if granules == 1 && channels == 1 {
                "Granule".to_owned()
            } else if channels == 1 {
                format!("Granule {gr}")
            } else {
                format!("Granule {gr}, channel {ch}")
            };
            b.node(
                Node::new(name)
                    .span(b.span_of(start, end))
                    .summary(g.summary())
                    .lazy(expand_granule, (span, mpeg1, start)),
            );
            b.seek(end);
        }
    }
    Ok(())
}

async fn expand_granule(cx: Cx, (span, mpeg1, start): (Span, bool, u64)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let mut b = Bits::emitting(&cx, &data, span);
    b.seek(start);
    granule(&mut b, mpeg1)?;
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
    (3, "VBR (old/rh)"),
    (4, "VBR (new/mtrh)"),
    (5, "VBR (mt)"),
    (6, "VBR (method 4)"),
    (8, "CBR (2 pass)"),
    (9, "ABR (2 pass)"),
    (15, "reserved"),
];

const ENCODING_FLAGS: FlagTable = &[
    flag(0x1, "NSPSYTUNE"),
    flag(0x2, "NSSAFEJOINT"),
    flag(0x4, "NOGAP_CONTINUED"),
    flag(0x8, "NOGAP_CONTINUATION"),
];

const SOURCE_RATE: EnumTable = &[
    (0, "32 kHz or less"),
    (1, "44.1 kHz"),
    (2, "48 kHz"),
    (3, "above 48 kHz"),
];

const STEREO_MODE: EnumTable = &[
    (0, "mono"),
    (1, "stereo"),
    (2, "dual channel"),
    (3, "joint stereo"),
    (4, "forced joint stereo"),
    (5, "auto"),
    (6, "intensity stereo"),
    (7, "other"),
];

const SURROUND: EnumTable = &[
    (0, "none"),
    (1, "Dolby Pro Logic"),
    (2, "Dolby Pro Logic II"),
    (3, "Ambisonic"),
];

const GAIN_NAME: EnumTable = &[
    (0, "not set"),
    (1, "radio (track)"),
    (2, "audiophile (album)"),
];

const GAIN_ORIGIN: EnumTable = &[
    (0, "not set"),
    (1, "set by the artist"),
    (2, "set by the user"),
    (3, "set automatically"),
    (4, "RMS average"),
];

/// What the LAME extension of a Xing/Info header says.
#[derive(Clone, Copy, Debug, Default)]
struct Lame {
    encoder: [u8; 9],
    method: u8,
    bitrate: u8,
    delay: u16,
    padding: u16,
    preset: u16,
}

impl Lame {
    fn parse(d: &[u8]) -> Option<Lame> {
        let byte = |i: usize| d.get(i).copied().unwrap_or(0);
        let encoder = crate::bytes::array::<9>(d, 0)?;
        d.get(35)?;
        Some(Lame {
            encoder,
            method: byte(9) & 0xf,
            bitrate: byte(20),
            delay: (u16::from(byte(21)) << 4) | u16::from(byte(22) >> 4),
            padding: (u16::from(byte(22) & 0xf) << 8) | u16::from(byte(23)),
            preset: u16_be(d, 26).unwrap_or(0) & 0x7ff,
        })
    }

    /// "LAME 3.100".
    fn encoder(&self) -> String {
        encoder_name(&self.encoder)
    }

    /// The command line options the tag suggests: "-V 2", "-b 128".
    fn settings(&self, quality: Option<u32>) -> Option<String> {
        if let Some(p) = preset_option(self.preset.into()) {
            return Some(p);
        }
        let plus = if self.bitrate == 255 { "+" } else { "" };
        match self.method {
            1 | 8 => Some(format!("-b {}{plus}", self.bitrate)),
            2 | 9 => Some(format!("--abr {}{plus}", self.bitrate)),
            3..=6 => quality
                .filter(|&q| q <= 100)
                .map(|q| format!("-V {}", 100u32.saturating_sub(q) / 10)),
            _ => None,
        }
    }
}

fn encoder_name(raw: &[u8]) -> String {
    let s = crate::text::latin1(crate::formats::util::sound::trim_nul(raw));
    match s.strip_prefix("LAME") {
        Some(v) if v.starts_with(|c: char| c.is_ascii_digit()) => format!("LAME {v}"),
        _ => s,
    }
}

/// The preset field as a command line option.
fn preset_option(v: u64) -> Option<String> {
    Some(match v {
        8..=320 => format!("--preset {v}"),
        410..=500 if v.is_multiple_of(10) => format!("-V {}", 500u64.saturating_sub(v) / 10),
        1000 => "--preset r3mix".to_owned(),
        1001 => "--preset standard".to_owned(),
        1002 => "--preset extreme".to_owned(),
        1003 => "--preset insane".to_owned(),
        1004 => "--preset fast standard".to_owned(),
        1005 => "--preset fast extreme".to_owned(),
        1006 => "--preset medium".to_owned(),
        1007 => "--preset fast medium".to_owned(),
        _ => return None,
    })
}

#[derive(Clone, Copy, Debug, Default)]
struct Vbr {
    frames: Option<u32>,
    bytes: Option<u32>,
    /// Info headers mark CBR (or ABR) files.
    cbr: bool,
    vbri: bool,
    quality: Option<u32>,
    lame: Option<Lame>,
}

impl Vbr {
    fn name(&self) -> &'static str {
        match (self.vbri, self.cbr) {
            (true, _) => "VBRI header",
            (false, true) => "Info header",
            (false, false) => "Xing header",
        }
    }

    /// "LAME 3.100, -V 2".
    fn encoder(&self) -> Option<String> {
        let lame = self.lame?;
        let mut s = lame.encoder();
        if let Some(opts) = lame.settings(self.quality) {
            s.push_str(&format!(" {opts}"));
        }
        Some(s)
    }

    fn summary(&self) -> String {
        let mut parts = vec![if self.cbr { "CBR" } else { "VBR" }.to_owned()];
        if let Some(n) = self.frames {
            parts.push(format!("{n} frames"));
        }
        if let Some(b) = self.bytes {
            parts.push(human_size(b.into()));
        }
        if let Some(e) = self.encoder() {
            parts.push(e);
        }
        parts.join(", ")
    }
}

/// Where a VBR header sits: the frame, for the LAME tag's CRC.
#[derive(Clone, Copy, Debug)]
struct VbrCtx {
    frame: Span,
}

fn xing(f: &mut Fields<'_>, ctx: &VbrCtx) -> Result<Vbr> {
    let id = f
        .ascii("ID", 4)
        .with(|id, n| {
            n.summary(if id == "Info" {
                "constant (or average) bitrate"
            } else {
                "variable bitrate"
            })
        })
        .emit()?;
    let flags = f.u32("Flags").flags(XING_FLAGS).emit()?;
    let mut v = Vbr {
        cbr: id == "Info",
        ..Vbr::default()
    };
    if flags & 1 != 0 {
        v.frames = Some(
            f.u32("Frames")
                .desc("Audio frames in the stream, not counting this one")
                .emit()?,
        );
    }
    if flags & 2 != 0 {
        v.bytes = Some(
            f.u32("Bytes")
                .desc("Length of the stream, this frame included")
                .with(|&b, n| n.summary(human_size(b.into())))
                .emit()?,
        );
    }
    if flags & 4 != 0 {
        let span = f.peek_span(100);
        f.bytes("Table of contents", 100).get()?;
        f.node(
            Node::new("Table of contents")
                .span(span)
                .summary("100 seek points")
                .desc("For each percent of the duration, where it starts as a fraction (/256) of the stream's bytes")
                .lazy(expand_toc, (span, v.bytes)),
        );
    }
    if flags & 8 != 0 {
        v.quality = Some(
            f.u32("Quality")
                .desc(
                    "VBR quality indicator, 0 (worst) to 100 (best); LAME writes 100 − 10 × V − q",
                )
                .emit()?,
        );
    }
    let rest = f.block().data.get(to_usize(f.pos())..).unwrap_or_default();
    if f.remaining() >= 36 && rest.first().is_some_and(u8::is_ascii_alphabetic) {
        let span = f.peek_span(36);
        let lame = Lame::parse(rest);
        // Before 3.90, LAME wrote only a version string here.
        let old = rest.starts_with(b"LAME3.")
            && rest
                .get(6..8)
                .and_then(|d| std::str::from_utf8(d).ok())
                .and_then(|d| d.parse::<u32>().ok())
                .is_some_and(|minor| minor < 90);
        if old {
            let span = f.peek_span(20);
            let s = encoder_name(rest.get(..20).unwrap_or_default());
            f.node(leaf("Encoder", span, text(s)));
        } else {
            let mut node = Node::new("LAME tag")
                .span(span)
                .desc("Encoder information, gapless playback data and ReplayGain")
                .lazy(expand_lame, (span, ctx.frame));
            if let Some(l) = lame {
                node = node.summary(match l.settings(v.quality) {
                    Some(o) => format!("{}, {o}", l.encoder()),
                    None => l.encoder(),
                });
                v.lame = lame;
            }
            f.node(node);
            f.skip(36);
        }
    }
    Ok(v)
}

async fn expand_toc(cx: Cx, (span, bytes): (Span, Option<u32>)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, &v) in data.iter().enumerate() {
        let mut node = leaf(format!("{i}%"), span.sub(to_u64(i), 1), uint(v, 8));
        node = match bytes {
            Some(b) => node.summary(format!(
                "byte {}",
                u64::from(b).saturating_mul(v.into()) / 256
            )),
            None => node.summary(format!("{:.1}% of the bytes", f64::from(v) / 2.56)),
        };
        cx.emit(node);
    }
    Ok(())
}

async fn expand_lame(cx: Cx, (span, frame): (Span, Span)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    // LAME's tag CRC covers the frame up to the CRC field; FFmpeg's the
    // first 190 bytes of the frame with the CRC field zeroed (the same
    // thing for MPEG-1 stereo, where the field is at byte 190).
    let crc_at = span.offset.saturating_add(34).saturating_sub(frame.offset);
    let mut covered = cx
        .read_avail(frame.sub(0, crc_at.saturating_add(2).max(190)))
        .await?;
    let lame_crc = covered
        .get(..to_usize(crc_at))
        .map(crate::codec::crc::crc16_arc);
    for i in [crc_at, crc_at.saturating_add(1)] {
        if let Some(b) = covered.get_mut(to_usize(i)) {
            *b = 0;
        }
    }
    let ffmpeg_crc = covered.get(..190).map(crate::codec::crc::crc16_arc);
    cx.emit(
        leaf(
            "Encoder",
            span.sub(0, 9),
            text(crate::text::latin1(crate::formats::util::sound::trim_nul(
                data.get(..9).unwrap_or_default(),
            ))),
        )
        .summary(encoder_name(data.get(..9).unwrap_or_default())),
    );
    let mut b = Bits::emitting(&cx, &data, span);
    b.skip(72);
    b.field("Tag revision", 4).emit()?;
    let method = b.field("VBR method", 4).enumeration(VBR_METHOD).emit()?;
    b.field("Lowpass", 8)
        .with(|v, n| {
            n.summary(if v == 0 {
                "unknown".to_owned()
            } else {
                format!("{} Hz", v.saturating_mul(100))
            })
        })
        .emit()?;
    b.field("Peak amplitude", 32)
        .desc("Largest decoded sample relative to full scale, fixed point with 23 fraction bits")
        .with(|v, n| {
            n.summary(if v == 0 {
                "unknown".to_owned()
            } else {
                format!("{:.6}", v as f64 / 8_388_608.0)
            })
        })
        .emit()?;
    for name in ["Track gain", "Album gain"] {
        b.field(name, 16)
            .hex()
            .desc("ReplayGain: name (3 bits), originator (3), sign (1), adjustment in 0.1 dB (9)")
            .with(|v, n| {
                let kind = v >> 13;
                if kind == 0 {
                    return n.summary("not set");
                }
                let tenths = (v & 0x1ff) as f64 / 10.0;
                let db = if v & 0x200 != 0 { -tenths } else { tenths };
                n.summary(format!(
                    "{:+.1} dB, {}, {}",
                    db,
                    lookup(GAIN_NAME, kind).unwrap_or("reserved"),
                    lookup(GAIN_ORIGIN, (v >> 10) & 7).unwrap_or("reserved")
                ))
            })
            .emit()?;
    }
    b.field("Encoding flags", 4).flags(ENCODING_FLAGS).emit()?;
    b.field("ATH type", 4)
        .desc("Absolute threshold of hearing model")
        .emit()?;
    b.field("Bitrate", 8)
        .with(|v, n| {
            let plus = if v == 255 { " or more" } else { "" };
            if v == 0 {
                return n.summary("unset");
            }
            n.summary(match method {
                2 | 9 => format!("{v} kbps average{plus}"),
                1 | 8 => format!("{v} kbps{plus}"),
                _ => format!("{v} kbps minimum{plus}"),
            })
        })
        .emit()?;
    b.field("Encoder delay", 12)
        .desc("Samples the encoder added at the start; players skip them (and the decoder's own delay) for gapless playback")
        .with(|v, n| n.summary(format!("{v} samples")))
        .emit()?;
    b.field("End padding", 12)
        .desc("Samples added at the end to fill the last frame")
        .with(|v, n| n.summary(format!("{v} samples")))
        .emit()?;
    b.field("Source sample rate", 2)
        .enumeration(SOURCE_RATE)
        .emit()?;
    b.field("Unwise settings", 1).flag().emit()?;
    b.field("Stereo mode", 3).enumeration(STEREO_MODE).emit()?;
    b.field("Noise shaping", 2).emit()?;
    b.field("MP3 gain", 8)
        .desc("Gain applied losslessly (by mp3gain), in 1.5 dB steps; sign and magnitude")
        .with(|v, n| {
            let steps = i64::try_from(v & 0x7f).unwrap_or(0);
            let steps = if v & 0x80 != 0 {
                steps.saturating_neg()
            } else {
                steps
            };
            n.value(Value::Int {
                value: steps,
                bits: 8,
            })
            .summary(format!("{:+.1} dB", steps as f64 * 1.5))
        })
        .emit()?;
    b.field("Unused", 2).emit()?;
    b.field("Surround", 3).enumeration(SURROUND).emit()?;
    b.field("Preset", 11)
        .with(|v, n| match preset_option(v) {
            Some(p) => n.summary(p),
            None if v == 0 => n.summary("none"),
            None => n,
        })
        .emit()?;
    b.field("Music length", 32)
        .desc("Bytes from the start of this frame to the end of the last one")
        .with(|v, n| n.summary(human_size(v)))
        .emit()?;
    b.field("Music CRC", 16)
        .hex()
        .desc("CRC-16 of the audio frames")
        .emit()?;
    b.field("Tag CRC", 16)
        .hex()
        .desc("CRC-16 of this frame up to this field")
        .with(|v, n| {
            let matches = |c: Option<u16>| c.is_some_and(|c| u64::from(c) == v);
            if matches(lame_crc) || matches(ffmpeg_crc) {
                n.summary("valid")
            } else if let Some(c) = lame_crc {
                n.diag(Diagnostic::warning(format!(
                    "CRC mismatch: computed {c:#06x}"
                )))
            } else {
                n
            }
        })
        .emit()?;
    Ok(())
}

fn vbri(f: &mut Fields<'_>, _: &VbrCtx) -> Result<Vbr> {
    f.ascii("ID", 4).emit()?;
    f.u16("Version").emit()?;
    f.u16("Delay").desc("Encoder delay, in samples").emit()?;
    let quality = f.u16("Quality").emit()?;
    let bytes = f
        .u32("Bytes")
        .desc("Length of the stream")
        .with(|&b, n| n.summary(human_size(b.into())))
        .emit()?;
    let frames = f.u32("Frames").emit()?;
    let entries = f.u16("TOC entries").emit()?;
    let scale = f.u16("TOC scale factor").emit()?;
    let size = f.u16("TOC entry size").desc("Bytes per entry").emit()?;
    let per = f.u16("Frames per TOC entry").emit()?;
    let toc = u64::from(entries).saturating_mul(size.into());
    if toc > 0 && (1..=4).contains(&size) {
        let span = f.peek_span(toc.min(f.remaining()));
        f.skip(span.len);
        f.node(
            Node::new("Table of contents")
                .span(span)
                .summary(format!("{entries} entries of {per} frames"))
                .desc("Bytes taken by each run of frames (entry × scale factor)")
                .lazy(expand_vbri_toc, (span, size, scale, per)),
        );
    }
    Ok(Vbr {
        frames: Some(frames),
        bytes: Some(bytes),
        cbr: false,
        vbri: true,
        quality: Some(quality.into()),
        lame: None,
    })
}

async fn expand_vbri_toc(cx: Cx, (span, size, scale, per): (Span, u16, u16, u16)) -> Result<()> {
    let size = u64::from(size).max(1);
    cx.set_count(Count::Exact(span.len.checked_div(size).unwrap_or(0)));
    let mut at = 0u64;
    let mut index = 0u64;
    while at.saturating_add(size) <= span.len {
        let entry = span.sub(at, size);
        let raw = cx.read(entry).await?;
        let v = raw.iter().fold(0u64, |a, &b| (a << 8) | u64::from(b));
        let first = index.saturating_mul(per.into());
        let node = leaf(format!("Entry {index}"), entry, uint(v, 32)).summary(format!(
            "frames {first}–{}: {} bytes",
            first.saturating_add(u64::from(per).saturating_sub(1)),
            v.saturating_mul(scale.into())
        ));
        cx.push(node).await;
        at = at.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Where a Xing/Info or VBRI header sits in a frame, if one does.
async fn vbr_header(cx: &Cx, frame: Span, h: &Header) -> Result<Option<(Span, bool)>> {
    if h.layer != 3 {
        return Ok(None);
    }
    // Encoders put the Xing header where the side information would end
    // without a CRC (LAME does so even when it writes CRCs); a writer that
    // counted the CRC would put it two bytes later.
    let after = 4u64.saturating_add(h.side_info());
    let candidates = [after, after.saturating_add(if h.crc { 2 } else { 0 })];
    for at in candidates {
        let magic = cx.read_avail(frame.sub(at, 4)).await?;
        if magic == b"Xing" || magic == b"Info" {
            return Ok(Some((frame.tail(at), true)));
        }
    }
    let magic = cx.read_avail(frame.sub(36, 4)).await?;
    if magic == b"VBRI" {
        return Ok(Some((frame.tail(36), false)));
    }
    Ok(None)
}

fn vbr_layout(is_xing: bool) -> Layout<VbrCtx, Vbr> {
    if is_xing {
        xing as Layout<VbrCtx, Vbr>
    } else {
        vbri
    }
}

// ---------------------------------------------------------------------------
// Dissection

/// Frames, bytes and bitrates of the frames at the start of a window.
#[derive(Default)]
struct Stats {
    frames: u64,
    bytes: u64,
    min_kbps: f64,
    max_kbps: f64,
    /// The window holds every frame of the stream.
    complete: bool,
}

fn window_stats(window: &[u8], skip_first: bool, free: u64, stream_len: u64) -> Stats {
    let mut s = Stats {
        min_kbps: f64::MAX,
        ..Stats::default()
    };
    let mut at = 0usize;
    while let Some(h) = window.get(at..).and_then(Header::parse) {
        let Some(len) = h
            .frame_len()
            .or_else(|| (free > 0).then(|| free.saturating_add(h.pad_bytes())))
        else {
            break;
        };
        let end = at.saturating_add(to_usize(len));
        if end > window.len() {
            break;
        }
        if !(skip_first && at == 0) {
            let kbps = h.kbps_of(len);
            s.frames = s.frames.saturating_add(1);
            s.bytes = s.bytes.saturating_add(len);
            s.min_kbps = s.min_kbps.min(kbps);
            s.max_kbps = s.max_kbps.max(kbps);
        }
        at = end;
    }
    s.complete = to_u64(at) == stream_len;
    s
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut start = 0u64;
    let mut titles = Vec::new();
    // Leading ID3v2 tags (some taggers leave an old one behind a new one).
    for _ in 0..4 {
        let head = cx.read_avail(file.sub(start, 10)).await?;
        let Some(len) = id3::v2_len(&head) else {
            break;
        };
        let span = file.sub(start, len);
        cx.emit(id3::tag_node(&cx, input, span).await);
        if let Some(t) = id3::title(&cx, span).await {
            titles.push(t);
        }
        start = start.saturating_add(len);
    }
    let trailing = id3::trailing_tags(&cx, input, file, start).await?;
    titles.extend(trailing.titles.iter().cloned());
    let audio = file.sub(start, trailing.end.saturating_sub(start));

    let window = cx.read_avail(audio.sub(0, 0x10000)).await?;
    let skip = match find_sync(&window, window.len()) {
        Some(skip) => Some(to_u64(skip)),
        None => resync(&cx, audio.sub(0, 1 << 22), 0, &SYNTAX).await?,
    };
    let Some(skip) = skip else {
        cx.emit(
            Node::new("Data")
                .span(audio)
                .diag(Diagnostic::malformed("no MPEG audio frame found")),
        );
        for node in trailing.nodes {
            cx.emit(node);
        }
        return Ok(());
    };
    if skip > 0 {
        cx.emit(
            Node::new("Junk")
                .span(audio.sub(0, skip))
                .summary(format!("{}, before the first frame", human_size(skip))),
        );
    }
    let stream = audio.tail(skip);
    let window = if to_usize(skip) < window.len() {
        window.get(to_usize(skip)..).unwrap_or_default().to_vec()
    } else {
        cx.read_avail(stream.sub(0, 0x10000)).await?
    };
    let header =
        Header::parse(&window).ok_or_else(|| Diagnostic::internal("frame header vanished"))?;
    // Free format: every frame has the length of the first, give or take
    // the padding slot.
    let free = if header.bitrate == 0 {
        free_len(&window).map_or(0, |l| l.saturating_sub(header.pad_bytes()))
    } else {
        0
    };
    let first_len = header
        .frame_len()
        .unwrap_or_else(|| free.saturating_add(header.pad_bytes()).max(4));
    let first = stream.sub(0, first_len);

    let mut vbr = None;
    if let Some((span, is_xing)) = vbr_header(&cx, first, &header).await? {
        let layout = vbr_layout(is_xing);
        let ctx = VbrCtx { frame: first };
        match parse(&cx, span, BE, &ctx, layout).await {
            Ok(v) => {
                cx.emit(struct_node(v.name(), span, BE, ctx, layout).summary(v.summary()));
                vbr = Some(v);
            }
            Err(e) => cx.diag(e),
        }
    }

    // Duration and bitrate.
    let spf = u64::from(header.samples());
    let rate = f64::from(header.rate);
    let stats = window_stats(&window, vbr.is_some(), free, stream.len);
    let (seconds, label) = match vbr.and_then(|v| v.frames.map(|f| (u64::from(f), v))) {
        Some((frames, v)) if rate > 0.0 => {
            let total = frames.saturating_mul(spf);
            let mut samples = total;
            if let Some(l) = v.lame {
                samples = samples
                    .saturating_sub(l.delay.into())
                    .saturating_sub(l.padding.into());
            }
            // The header frame is counted in the bytes but not the frames.
            let bytes = v
                .bytes
                .map_or(stream.len, u64::from)
                .saturating_sub(first_len);
            let kbps = if total > 0 {
                bytes as f64 * 8.0 * rate / total as f64 / 1000.0
            } else {
                0.0
            };
            let label = if v.cbr && header.bitrate > 0 {
                format!("{} kbps", header.bitrate)
            } else if v.cbr {
                format!("{kbps:.0} kbps")
            } else {
                format!("VBR {kbps:.0} kbps")
            };
            (samples as f64 / rate, label)
        }
        _ if stats.frames > 0 && rate > 0.0 => {
            let frames = if stats.complete {
                stats.frames as f64
            } else {
                stats.frames as f64 * stream.len as f64 / stats.bytes.max(1) as f64
            };
            let seconds = frames * spf as f64 / rate;
            let constant = stats.max_kbps - stats.min_kbps < 0.5;
            let label = if header.bitrate == 0 {
                format!("free format {:.0} kbps", stats.min_kbps)
            } else if constant {
                format!("{} kbps", header.bitrate)
            } else {
                let kbps =
                    stats.bytes as f64 * 8.0 * rate / (stats.frames as f64 * spf as f64) / 1000.0;
                format!("VBR {kbps:.0} kbps")
            };
            (seconds, label)
        }
        _ => (0.0, header.describe()),
    };
    let mut line = format!(
        "{} {}, {label}, {} Hz, {}, {}",
        header.version_name(),
        header.layer_name(),
        header.rate,
        header.mode_name(),
        duration(seconds)
    );
    if let Some(e) = vbr.and_then(|v| v.encoder()) {
        line.push_str(&format!(", {e}"));
    }
    if let Some(t) = titles.first() {
        line.push_str(&format!(" — {t}"));
    }
    cx.annotate(line);

    let mut frames = Node::new("Frames").span(stream);
    frames = match (vbr.and_then(|v| v.frames), stats.complete) {
        (Some(n), _) => frames.summary(format!(
            "{} frames ({} header frame + {n} audio)",
            u64::from(n).saturating_add(1),
            vbr.map_or("VBR", |v| v.name().trim_end_matches(" header"))
        )),
        (None, true) => frames.summary(format!("{} frames", stats.frames)),
        (None, false) => frames.summary(human_size(stream.len)),
    };
    let walk = Walk {
        input,
        region: stream,
        free,
        vbr: vbr.map(|v| v.name()),
    };
    cx.emit(frames.lazy(list_frames, walk));
    for node in trailing.nodes {
        cx.emit(node);
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Walk {
    input: Input,
    region: Span,
    /// Length of a free-format frame without padding; 0 if not free format.
    free: u64,
    /// The header the first frame holds instead of audio: "Xing header",
    /// "Info header" or "VBRI header".
    vbr: Option<&'static str>,
}

/// Pushes one node per frame, following the lengths in the headers.
async fn list_frames(cx: Cx, w: Walk) -> Result<()> {
    let region = w.region;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < region.len {
        let mark = (pos, index);
        let head = cx.read_avail(region.sub(pos, 10)).await?;
        let parsed = Header::parse(&head).and_then(|h| {
            let len = h.frame_len().or_else(|| {
                (w.free > 0 && h.bitrate == 0).then(|| w.free.saturating_add(h.pad_bytes()))
            })?;
            Some((h, len))
        });
        let Some((h, len)) = parsed else {
            // Concatenated files: another file's ID3v2 tag.
            if let Some(tag) = id3::v2_len(&head) {
                let node = id3::tag_node(&cx, w.input, region.sub(pos, tag)).await;
                cx.mark(move || mark);
                cx.push(node).await;
                pos = pos.saturating_add(tag);
                continue;
            }
            match resync(&cx, region, pos.saturating_add(1), &SYNTAX).await? {
                Some(next) => {
                    cx.mark(move || mark);
                    cx.push(junk_node(region.sub(pos, next.saturating_sub(pos))))
                        .await;
                    pos = next;
                }
                None => {
                    let node = tail_node(&cx, region.tail(pos)).await?;
                    cx.mark(move || mark);
                    cx.push(node).await;
                    return Ok(());
                }
            }
            continue;
        };
        let span = region.sub(pos, len);
        let first = index == 0 && w.vbr.is_some();
        let mut summary = format!("{}, {len} bytes", h.describe());
        if h.bitrate == 0 {
            summary = format!(
                "{} {}, free format {:.0} kbps, {} Hz, {}, {len} bytes",
                h.version_name(),
                h.layer_name(),
                h.kbps_of(len),
                h.rate,
                h.mode_name()
            );
        }
        if first {
            summary = format!("{} frame, {summary}", w.vbr.unwrap_or("VBR header"));
        }
        let mut node = Node::new(format!("Frame {index}"))
            .span(span)
            .summary(summary);
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.mark(move || mark);
        cx.push(node.lazy(frame, (span, h, first))).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn frame(cx: Cx, (span, h, first): (Span, Header, bool)) -> Result<()> {
    cx.emit(bits_node("Header", span.sub(0, 4), header_fields, false));
    let mut pos = 4u64;
    if h.crc {
        let protected = h.protected();
        let data = cx
            .read_avail(span.sub(2, 4u64.saturating_add(protected.unwrap_or(0))))
            .await?;
        let stored = u16_be(&data, 2).unwrap_or(0);
        let mut node = leaf("CRC", span.sub(4, 2), hex(stored, 16));
        match protected {
            Some(n) if to_u64(data.len()) >= n.saturating_add(4) => {
                let mut covered = data.get(..2).unwrap_or_default().to_vec();
                covered.extend_from_slice(data.get(4..).unwrap_or_default());
                let computed = CRC16_MPEG.checksum(&covered);
                node = if computed == u64::from(stored) {
                    node.summary("valid")
                } else {
                    node.diag(Diagnostic::warning(format!(
                        "CRC mismatch: computed {computed:#06x}"
                    )))
                };
            }
            Some(_) => {}
            None => {
                node = node.desc("Covers the bit allocation and scale factor selection (not checked for Layer II)");
            }
        }
        cx.emit(node);
        pos = 6;
    }
    if h.layer == 3 {
        cx.emit(side_info_node(span.sub(pos, h.side_info()), h));
        pos = pos.saturating_add(h.side_info());
    }
    if first && let Some((at, is_xing)) = vbr_header(&cx, span, &h).await? {
        let layout = vbr_layout(is_xing);
        let ctx = VbrCtx { frame: span };
        let mut node = struct_node("VBR header", at, BE, ctx, layout);
        if let Ok(v) = parse(&cx, at, BE, &ctx, layout).await {
            node = struct_node(v.name(), at, BE, ctx, layout).summary(v.summary());
        }
        if at.offset > span.offset.saturating_add(pos) {
            cx.emit(Node::new("Unused").span(span.sub(
                pos,
                at.offset.saturating_sub(span.offset).saturating_sub(pos),
            )));
        }
        cx.emit(node);
        return Ok(());
    }
    let data = span.tail(pos);
    let node = match h.layer {
        3 => Node::new("Main data").desc(
            "Scale factors and Huffman-coded samples; through the bit reservoir, part of it may belong to the following frames",
        ),
        2 => Node::new("Audio data")
            .desc("Bit allocation, scale factor selection, scale factors and quantised subband samples"),
        _ => Node::new("Audio data").desc("Bit allocation, scale factors and quantised subband samples"),
    };
    cx.emit(node.span(data).summary(human_size(data.len)));
    Ok(())
}
