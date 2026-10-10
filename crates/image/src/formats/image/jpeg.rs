//! JPEG (JFIF, Exif and friends), lossless JPEG, hierarchical JPEG and
//! JPEG-LS (ITU T.81 / T.87).
//!
//! A JPEG file is a sequence of marker segments. Most carry a 16-bit length;
//! SOI, EOI, TEM and RSTn do not, and any marker may be preceded by `FF`
//! fill bytes. After a start-of-scan (SOS) segment comes entropy-coded data,
//! which ends at the next marker that is not a stuffed `FF 00` (in JPEG-LS:
//! `FF` followed by a byte below `0x80`) or a restart marker.
//!
//! The top level lists segments (paged) and the entropy-coded data of each
//! scan; expanding a segment decodes it. Application segments are recognised
//! by their identifiers: JFIF/JFXX, Exif (handed to the TIFF dissector), XMP
//! and extended XMP (reassembled by GUID), ICC profiles (reassembled from
//! their chunks), MPF (the Multi-Picture index and the images it points
//! to), FlashPix, JPS, SPIFF, JUMBF (C2PA, reassembled by box instance),
//! Ducky, Photoshop resources (with IPTC-IIM) and Adobe. Data after EOI is
//! split into what can be recognised: MPF images, appended JPEGs and MP4
//! movies ("motion photos").

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Layout, Prim, struct_node};
use crate::formats::util::arcutil::human_size;
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::{ColorOrder, dims, palette, region, text, uint};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "jpeg",
    title: "JPEG image",
    extensions: &["jpg", "jpeg", "jpe", "jfif", "jif", "mpo", "jps", "jls"],
    mime: "image/jpeg",
    probe: Probe::Magic(&[(0, b"\xff\xd8\xff")]),
    dissect: crate::expander!(dissect: Input),
};

// ---------------------------------------------------------------------------
// Tables

const MARKERS: EnumTable = &[
    (0x01, "TEM"),
    (0xc0, "SOF0"),
    (0xc1, "SOF1"),
    (0xc2, "SOF2"),
    (0xc3, "SOF3"),
    (0xc4, "DHT"),
    (0xc5, "SOF5"),
    (0xc6, "SOF6"),
    (0xc7, "SOF7"),
    (0xc8, "JPG"),
    (0xc9, "SOF9"),
    (0xca, "SOF10"),
    (0xcb, "SOF11"),
    (0xcc, "DAC"),
    (0xcd, "SOF13"),
    (0xce, "SOF14"),
    (0xcf, "SOF15"),
    (0xd0, "RST0"),
    (0xd1, "RST1"),
    (0xd2, "RST2"),
    (0xd3, "RST3"),
    (0xd4, "RST4"),
    (0xd5, "RST5"),
    (0xd6, "RST6"),
    (0xd7, "RST7"),
    (0xd8, "SOI"),
    (0xd9, "EOI"),
    (0xda, "SOS"),
    (0xdb, "DQT"),
    (0xdc, "DNL"),
    (0xdd, "DRI"),
    (0xde, "DHP"),
    (0xdf, "EXP"),
    (0xe0, "APP0"),
    (0xe1, "APP1"),
    (0xe2, "APP2"),
    (0xe3, "APP3"),
    (0xe4, "APP4"),
    (0xe5, "APP5"),
    (0xe6, "APP6"),
    (0xe7, "APP7"),
    (0xe8, "APP8"),
    (0xe9, "APP9"),
    (0xea, "APP10"),
    (0xeb, "APP11"),
    (0xec, "APP12"),
    (0xed, "APP13"),
    (0xee, "APP14"),
    (0xef, "APP15"),
    (0xf7, "SOF55"),
    (0xf8, "LSE"),
    (0xfe, "COM"),
];

const FRAME_TYPES: EnumTable = &[
    (0xc0, "baseline DCT"),
    (0xc1, "extended sequential DCT"),
    (0xc2, "progressive DCT"),
    (0xc3, "lossless"),
    (0xc5, "differential sequential DCT"),
    (0xc6, "differential progressive DCT"),
    (0xc7, "differential lossless"),
    (0xc9, "extended sequential DCT, arithmetic"),
    (0xca, "progressive DCT, arithmetic"),
    (0xcb, "lossless, arithmetic"),
    (0xcd, "differential sequential DCT, arithmetic"),
    (0xce, "differential progressive DCT, arithmetic"),
    (0xcf, "differential lossless, arithmetic"),
    (0xf7, "JPEG-LS"),
];

const DENSITY_UNITS: EnumTable = &[
    (0, "aspect ratio only"),
    (1, "dots per inch"),
    (2, "dots per cm"),
];

const JFXX_CODES: EnumTable = &[
    (0x10, "JPEG thumbnail"),
    (0x11, "1-byte-per-pixel palettized thumbnail"),
    (0x13, "3-byte-per-pixel RGB thumbnail"),
];

const ADOBE_TRANSFORM: EnumTable = &[(0, "none (RGB or CMYK)"), (1, "YCbCr"), (2, "YCCK")];

const ADOBE_FLAGS0: FlagTable = &[flag(0x8000, "BLEND_DOWNSAMPLING")];

const PREDICTORS: EnumTable = &[
    (1, "Ra (left)"),
    (2, "Rb (above)"),
    (3, "Rc (above left)"),
    (4, "Ra + Rb − Rc"),
    (5, "Ra + (Rb − Rc)/2"),
    (6, "Rb + (Ra − Rc)/2"),
    (7, "(Ra + Rb)/2"),
];

const LS_INTERLEAVE: EnumTable = &[
    (0, "non-interleaved"),
    (1, "line-interleaved"),
    (2, "sample-interleaved"),
];

const LSE_IDS: EnumTable = &[
    (1, "preset coding parameters"),
    (2, "mapping table"),
    (3, "mapping table continuation"),
    (4, "oversize image dimensions"),
];

const AVI1_POLARITY: EnumTable = &[
    (0, "not interlaced"),
    (1, "odd field first"),
    (2, "even field first"),
];

const FPXR_TYPES: EnumTable = &[(1, "contents list"), (2, "stream data"), (3, "reserved")];

const SPIFF_PROFILES: EnumTable = &[
    (0, "none"),
    (1, "continuous-tone base"),
    (2, "continuous-tone progressive"),
    (3, "bi-level facsimile"),
    (4, "continuous-tone facsimile"),
];

const SPIFF_COLOR_SPACES: EnumTable = &[
    (0, "bi-level"),
    (1, "YCbCr (ITU-R BT.709, video)"),
    (2, "none"),
    (3, "YCbCr (ITU-R BT.601-1, RGB)"),
    (4, "YCbCr (ITU-R BT.601-1, video)"),
    (8, "grayscale"),
    (9, "PhotoYCC"),
    (10, "RGB"),
    (11, "CMY"),
    (12, "CMYK"),
    (13, "YCCK"),
    (14, "CIELab"),
];

const SPIFF_COMPRESSION: EnumTable = &[
    (0, "uncompressed"),
    (1, "Modified Huffman"),
    (2, "Modified READ"),
    (3, "Modified Modified READ"),
    (4, "JBIG"),
    (5, "JPEG"),
    (6, "JPEG-LS"),
];

const JUMD_TOGGLES: FlagTable = &[
    flag(0x01, "REQUESTABLE"),
    flag(0x02, "LABEL"),
    flag(0x04, "ID"),
    flag(0x08, "SIGNATURE"),
    flag(0x10, "PRIVATE"),
];

/// CIPA DC-007 Multi-Picture types (low 24 bits of the image attribute).
const MP_TYPES: EnumTable = &[
    (0x000000, "undefined"),
    (0x010001, "large thumbnail (VGA)"),
    (0x010002, "large thumbnail (full HD)"),
    (0x020001, "multi-frame panorama"),
    (0x020002, "multi-frame disparity (stereo)"),
    (0x020003, "multi-angle"),
    (0x030000, "baseline MP primary image"),
];

/// Zigzag position → natural (row-major) position in an 8×8 block.
const ZIGZAG: [u8; 64] = [
    0, 1, 8, 16, 9, 2, 3, 10, 17, 24, 32, 25, 18, 11, 4, 5, 12, 19, 26, 33, 40, 48, 41, 34, 27, 20,
    13, 6, 7, 14, 21, 28, 35, 42, 49, 56, 57, 50, 43, 36, 29, 22, 15, 23, 30, 37, 44, 51, 58, 59,
    52, 45, 38, 31, 39, 46, 53, 60, 61, 54, 47, 55, 62, 63,
];

/// ITU T.81 Annex K.1 quantization tables (natural order), the base of the
/// IJG quality scale.
const STD_LUMINANCE: [u8; 64] = [
    16, 11, 10, 16, 24, 40, 51, 61, 12, 12, 14, 19, 26, 58, 60, 55, 14, 13, 16, 24, 40, 57, 69, 56,
    14, 17, 22, 29, 51, 87, 80, 62, 18, 22, 37, 56, 68, 109, 103, 77, 24, 35, 55, 64, 81, 104, 113,
    92, 49, 64, 78, 87, 103, 121, 120, 101, 72, 92, 95, 98, 112, 100, 103, 99,
];
const STD_CHROMINANCE: [u8; 64] = [
    17, 18, 24, 47, 99, 99, 99, 99, 18, 21, 26, 66, 99, 99, 99, 99, 24, 26, 56, 99, 99, 99, 99, 99,
    47, 66, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
    99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99, 99,
];

/// Annex K.3 Huffman tables: code counts by length and the first symbols.
const STD_HUFFMAN: &[(u8, [u8; 16], [u8; 8], &str)] = &[
    (
        0,
        [0, 1, 5, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0, 0, 0],
        [0, 1, 2, 3, 4, 5, 6, 7],
        "standard luminance DC",
    ),
    (
        0,
        [0, 3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 0, 0, 0, 0, 0],
        [0, 1, 2, 3, 4, 5, 6, 7],
        "standard chrominance DC",
    ),
    (
        1,
        [0, 2, 1, 3, 3, 2, 4, 3, 5, 5, 4, 4, 0, 0, 1, 0x7d],
        [0x01, 0x02, 0x03, 0x00, 0x04, 0x11, 0x05, 0x12],
        "standard luminance AC",
    ),
    (
        1,
        [0, 2, 1, 2, 4, 4, 3, 4, 7, 5, 4, 4, 0, 1, 2, 0x77],
        [0x00, 0x01, 0x02, 0x03, 0x11, 0x04, 0x05, 0x21],
        "standard chrominance AC",
    ),
];

const EXIF: &[u8] = b"Exif\0";
const XMP: &[u8] = b"http://ns.adobe.com/xap/1.0/\0";
const XMP_EXTENSION: &[u8] = b"http://ns.adobe.com/xmp/extension/\0";
const ICC: &[u8] = b"ICC_PROFILE\0";
const PHOTOSHOP: &[u8] = b"Photoshop 3.0\0";
const GAIN_MAP: &[u8] = b"urn:iso:std:iso:ts:21496:-1\0";
/// The last 12 bytes of the ISO-registered UUIDs whose first four bytes are
/// a four-character code (JUMBF content types, C2PA).
const ISO_UUID_SUFFIX: [u8; 12] = [
    0x00, 0x11, 0x00, 0x10, 0x80, 0x00, 0x00, 0xaa, 0x00, 0x38, 0x9b, 0x71,
];

/// How many items after EOI are told apart before the rest is one blob.
const MAX_TRAILER_ITEMS: usize = 64;
/// How far into unrecognised trailing data to look for an appended file.
const TRAILER_SEARCH: u64 = 0x10000;
/// JUMBF superboxes nested deeper than this are not expanded.
const MAX_BOX_DEPTH: u8 = 16;

// ---------------------------------------------------------------------------
// Markers and segments

fn is_sof(marker: u8) -> bool {
    lookup(FRAME_TYPES, marker.into()).is_some()
}

fn progressive(process: u8) -> bool {
    matches!(process, 0xc2 | 0xc6 | 0xca | 0xce)
}

fn lossless(process: u8) -> bool {
    matches!(process, 0xc3 | 0xc7 | 0xcb | 0xcf)
}

fn standalone(marker: u8) -> bool {
    matches!(marker, 0x01 | 0xd0..=0xd9)
}

fn marker_name(marker: u8) -> String {
    if let Some(name) = lookup(MARKERS, marker.into()) {
        return name.to_owned();
    }
    match marker {
        0xf0..=0xfd => format!("JPG{}", marker.saturating_sub(0xf0)),
        0x02..=0xbf => format!("RES ({marker:#04x})"),
        _ => format!("Marker {marker:#04x}"),
    }
}

/// One marker segment, as found by the walker.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Segment {
    marker: u8,
    /// From the first `FF` (fill bytes included) to the end of the payload.
    span: Span,
    /// Fill bytes before the marker's own `FF`.
    fill: u64,
    /// The declared length (0 for markers without one).
    len: u16,
}

impl Segment {
    fn header_len(&self) -> u64 {
        self.fill
            .saturating_add(if standalone(self.marker) { 2 } else { 4 })
    }

    /// The payload after marker and length.
    fn payload(&self) -> Span {
        self.span.tail(self.header_len())
    }

    fn problem(&self) -> Option<Diagnostic> {
        if standalone(self.marker) {
            return None;
        }
        if self.len < 2 {
            return Some(
                Diagnostic::malformed(format!("segment length {} is less than 2", self.len))
                    .at(self.span),
            );
        }
        let wanted = self
            .header_len()
            .saturating_add(u64::from(self.len).saturating_sub(2));
        (self.span.len < wanted).then(|| {
            Diagnostic::truncated(
                Span::new(self.span.source, self.span.offset, wanted),
                self.span.len,
            )
        })
    }
}

/// Reads the segment starting at the cursor (which points at `FF`),
/// including fill bytes. Returns `None` (cursor unmoved) if the cursor does
/// not point at a marker.
async fn next_segment(cur: &mut Cursor<'_>) -> Result<Option<Segment>> {
    let start = cur.pos();
    let mut pos = start;
    let marker = loop {
        cur.seek(pos);
        let window = cur.peek(64).await?;
        let ffs = window.iter().take_while(|&&b| b == 0xff).count();
        if pos == start && ffs == 0 {
            return Ok(None);
        }
        match window.get(ffs) {
            Some(&m) => {
                pos = pos.saturating_add(to_u64(ffs));
                break m;
            }
            None if window.len() < 64 => {
                cur.seek(start);
                return Ok(None);
            }
            None => pos = pos.saturating_add(to_u64(ffs)),
        }
    };
    if marker == 0x00 {
        cur.seek(start);
        return Ok(None);
    }
    // `pos` is at the marker code; the byte before it is the marker's FF.
    let fill = pos.saturating_sub(start).saturating_sub(1);
    cur.seek(pos.saturating_add(1));
    let mut len = 0;
    if !standalone(marker) {
        len = cur.u16().await?;
        cur.skip(u64::from(len).saturating_sub(2));
    }
    let span = cur.region().sub(start, cur.pos().saturating_sub(start));
    Ok(Some(Segment {
        marker,
        span,
        fill,
        len,
    }))
}

/// The segments before the first scan, read once per file.
async fn header_segments(cx: &Cx, file: Span) -> Arc<Vec<Segment>> {
    const KIND: &str = "jpeg-header-segments";
    if let Some(segments) = cx.cached::<Vec<Segment>>(file, KIND) {
        return segments;
    }
    let mut out = Vec::new();
    let mut cur = Cursor::new(cx, file, BE);
    while let Ok(Some(seg)) = next_segment(&mut cur).await {
        if matches!(seg.marker, 0xda | 0xd9) {
            break;
        }
        out.push(seg);
        if cur.at_end() {
            break;
        }
    }
    let segments = Arc::new(out);
    cx.cache(file, KIND, Arc::clone(&segments));
    segments
}

// ---------------------------------------------------------------------------
// Entropy-coded data

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Stuffing {
    /// `FF 00` is data; RSTn separate restart intervals.
    Dct,
    /// JPEG-LS: `FF` followed by a byte below `0x80` is data.
    Ls,
    /// Not in a scan: only `FF 00` is skipped, every other `FF xx` stops.
    None,
}

struct EcsStep {
    /// Restart markers found (position relative to the region, code).
    restarts: Vec<(u64, u8)>,
    /// Where the next step starts.
    next: u64,
    /// The position of the marker that ends the data, if found.
    end: Option<u64>,
}

/// Looks at up to 16 KiB of entropy-coded data from `pos` (relative to
/// `region`).
async fn ecs_step(cx: &Cx, region: Span, pos: u64, stuffing: Stuffing) -> Result<EcsStep> {
    const STEP: u64 = 0x4000;
    let chunk = cx.read_avail(region.sub(pos, STEP)).await?;
    let mut restarts = Vec::new();
    if chunk.len() < 2 {
        return Ok(EcsStep {
            restarts,
            next: region.len,
            end: Some(region.len),
        });
    }
    let mut i = 0usize;
    while let Some(off) = chunk
        .get(i..)
        .and_then(|c| c.iter().position(|&b| b == 0xff))
    {
        let at = i.saturating_add(off);
        let abs = pos.saturating_add(to_u64(at));
        let Some(&next) = chunk.get(at.saturating_add(1)) else {
            // Look at this FF again with the byte after it.
            return Ok(EcsStep {
                restarts,
                next: abs,
                end: None,
            });
        };
        let data = match stuffing {
            Stuffing::Dct | Stuffing::None => next == 0x00,
            Stuffing::Ls => next < 0x80,
        };
        if data {
            i = at.saturating_add(2);
        } else if stuffing != Stuffing::None && (0xd0..=0xd7).contains(&next) {
            restarts.push((abs, next));
            i = at.saturating_add(2);
        } else {
            return Ok(EcsStep {
                restarts,
                next: abs,
                end: Some(abs),
            });
        }
    }
    Ok(EcsStep {
        restarts,
        next: pos.saturating_add(to_u64(chunk.len())),
        end: None,
    })
}

struct EcsScan {
    end: u64,
    restarts: u64,
    /// The first restart marker out of sequence: (position, found, expected).
    out_of_order: Option<(u64, u8, u8)>,
}

/// Finds the end of entropy-coded data starting at `start` (relative to
/// `region`): the position of the next marker that is not part of the data.
async fn scan_entropy(cx: &Cx, region: Span, start: u64, stuffing: Stuffing) -> Result<EcsScan> {
    let mut pos = start;
    let mut restarts = 0u64;
    let mut expected = 0xd0u8;
    let mut out_of_order = None;
    loop {
        let step = ecs_step(cx, region, pos, stuffing).await?;
        for &(at, code) in &step.restarts {
            if code != expected && out_of_order.is_none() {
                out_of_order = Some((at, code, expected));
            }
            expected = if code >= 0xd7 {
                0xd0
            } else {
                code.saturating_add(1)
            };
            restarts = restarts.saturating_add(1);
        }
        if let Some(end) = step.end {
            return Ok(EcsScan {
                end,
                restarts,
                out_of_order,
            });
        }
        pos = step.next;
    }
}

/// Lists the restart intervals of a scan's entropy-coded data.
async fn restart_intervals(cx: Cx, (data, stuffing): (Span, Stuffing)) -> Result<()> {
    let mut pos = 0u64;
    let mut start = 0u64;
    let mut index = 0u64;
    loop {
        let step = ecs_step(&cx, data, pos, stuffing).await?;
        for &(at, code) in &step.restarts {
            cx.push(
                Node::new(format!("Interval {index}"))
                    .span(data.sub(start, at.saturating_sub(start)))
                    .summary(human_size(at.saturating_sub(start))),
            )
            .await;
            cx.push(Node::new(marker_name(code)).span(data.sub(at, 2)))
                .await;
            start = at.saturating_add(2);
            index = index.saturating_add(1);
        }
        if step.end.is_some() {
            break;
        }
        pos = step.next;
    }
    if start < data.len {
        let len = data.len.saturating_sub(start);
        cx.push(
            Node::new(format!("Interval {index}"))
                .span(data.sub(start, len))
                .summary(human_size(len)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Frames and scans

#[derive(Clone, Copy, Debug, Default)]
struct Component {
    id: u8,
    h: u8,
    v: u8,
}

#[derive(Clone, Debug, Default)]
struct Frame {
    marker: u8,
    width: u16,
    height: u16,
    precision: u8,
    components: Vec<Component>,
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
enum Space {
    #[default]
    Unknown,
    Gray,
    YCbCr,
    Rgb,
    Cmyk,
    Ycck,
}

/// The components of the current frame, for naming them in scans.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Comps {
    ids: [u8; 4],
    n: u8,
    space: Space,
}

impl Comps {
    /// The colour model follows libjpeg's rules: one component is gray;
    /// three are YCbCr unless an Adobe segment says "no transform" or the
    /// IDs spell R, G, B; four are CMYK, or YCCK per Adobe.
    fn new(frame: &Frame, adobe: Option<u8>, jfif: bool) -> Comps {
        let mut ids = [0u8; 4];
        for (slot, c) in ids.iter_mut().zip(&frame.components) {
            *slot = c.id;
        }
        let n = frame.components.len();
        let rgb_ids = frame.components.iter().map(|c| c.id).eq(*b"RGB");
        let space = match n {
            1 => Space::Gray,
            // JPEG-LS implies no colour transform.
            3 if frame.marker == 0xf7 => Space::Unknown,
            3 if adobe == Some(0) || (rgb_ids && !jfif) => Space::Rgb,
            3 => Space::YCbCr,
            4 if frame.marker == 0xf7 => Space::Unknown,
            4 if adobe == Some(2) => Space::Ycck,
            4 => Space::Cmyk,
            _ => Space::Unknown,
        };
        Comps {
            ids,
            n: u8::try_from(n.min(4)).unwrap_or(4),
            space,
        }
    }

    fn name(&self, id: u8) -> String {
        let names: &[&str] = match self.space {
            Space::Gray => &["Y"],
            Space::YCbCr => &["Y", "Cb", "Cr"],
            Space::Rgb => &["R", "G", "B"],
            Space::Cmyk => &["C", "M", "Y", "K"],
            Space::Ycck => &["Y", "Cb", "Cr", "K"],
            Space::Unknown => &[],
        };
        self.ids
            .iter()
            .take(usize::from(self.n))
            .position(|&i| i == id)
            .and_then(|i| names.get(i))
            .map_or_else(|| id.to_string(), |s| (*s).to_owned())
    }
}

/// "4:2:0" and friends, from the sampling factors of Y, Cb and Cr.
fn subsampling(frame: &Frame) -> String {
    let c = &frame.components;
    let (Some(y), Some(cb), Some(cr)) = (c.first(), c.get(1), c.get(2)) else {
        return String::new();
    };
    let factors = || {
        c.iter()
            .take(3)
            .map(|c| format!("{}×{}", c.h, c.v))
            .collect::<Vec<_>>()
            .join(", ")
    };
    let hmax = c.iter().map(|c| c.h).max().unwrap_or(0);
    let vmax = c.iter().map(|c| c.v).max().unwrap_or(0);
    if cb.h != cr.h || cb.v != cr.v || y.h != hmax || y.v != vmax {
        return format!("sampling {}", factors());
    }
    let ratio = |a: u8, b: u8| a.checked_rem(b).filter(|&r| r == 0).and(a.checked_div(b));
    match (ratio(y.h, cb.h), ratio(y.v, cb.v)) {
        (Some(1), Some(1)) => "4:4:4".to_owned(),
        (Some(2), Some(1)) => "4:2:2".to_owned(),
        (Some(2), Some(2)) => "4:2:0".to_owned(),
        (Some(1), Some(2)) => "4:4:0".to_owned(),
        (Some(4), Some(1)) => "4:1:1".to_owned(),
        (Some(4), Some(2)) => "4:1:0".to_owned(),
        _ => format!("sampling {}", factors()),
    }
}

fn colors(frame: &Frame, space: Space) -> String {
    match space {
        Space::Gray => "grayscale".to_owned(),
        Space::YCbCr => format!("YCbCr {}", subsampling(frame)),
        Space::Rgb => match subsampling(frame).as_str() {
            "4:4:4" => "RGB".to_owned(),
            s => format!("RGB {s}"),
        },
        Space::Cmyk => "CMYK".to_owned(),
        Space::Ycck => "YCCK".to_owned(),
        Space::Unknown => format!("{} components", frame.components.len()),
    }
}

/// "640×480, progressive DCT, YCbCr 4:2:0".
fn describe_frame(frame: &Frame, space: Space, dnl: Option<u16>) -> String {
    let height = match (frame.height, dnl) {
        (0, Some(lines)) => lines.to_string(),
        (0, None) => "?".to_owned(),
        (h, _) => h.to_string(),
    };
    let kind = if frame.marker == 0xde {
        "hierarchical"
    } else {
        lookup(FRAME_TYPES, frame.marker.into()).unwrap_or("unknown process")
    };
    let mut out = format!("{}, {kind}", dims(frame.width, height));
    if frame.precision != 8 {
        out = format!("{out}, {}-bit", frame.precision);
    }
    format!("{out}, {}", colors(frame, space))
}

/// SOFn and DHP: frame header fields, each component as a group.
fn frame_header(f: &mut Fields<'_>, comps: &Comps) -> Result<Frame> {
    let precision = f.u8("Sample precision").desc("Bits per sample").emit()?;
    let height = f
        .u16("Height")
        .desc("Number of lines (0: given by a DNL segment after the first scan)")
        .emit()?;
    let width = f.u16("Width").desc("Samples per line").emit()?;
    let remaining = f.remaining();
    let count = f
        .u8("Components")
        .check(|&n| {
            (u64::from(n).saturating_mul(3) > remaining.saturating_sub(1))
                .then(|| Diagnostic::malformed("component list runs past the segment"))
        })
        .emit()?;
    let mut components = Vec::new();
    for _ in 0..count {
        if f.remaining() < 3 {
            break;
        }
        let span = f.peek_span(3);
        let id = f.u8("Component ID").get()?;
        let sampling = f.u8("Sampling factors").get()?;
        let tq = f.u8("Quantization table").get()?;
        let (h, v) = (sampling >> 4, sampling & 15);
        f.node(
            struct_node(
                format!("Component {}", comps.name(id)),
                span,
                BE,
                *comps,
                frame_component,
            )
            .summary(format!(
                "ID {id}, sampling {h}×{v}, quantization table {tq}"
            )),
        );
        components.push(Component { id, h, v });
    }
    Ok(Frame {
        marker: 0,
        width,
        height,
        precision,
        components,
    })
}

fn frame_component(f: &mut Fields<'_>, comps: &Comps) -> Result<()> {
    f.u8("Component ID")
        .with(|&id, n| n.summary(comps.name(id)))
        .emit()?;
    f.u8("Sampling factors")
        .hex()
        .with(|&s, n| n.summary(format!("{}×{} (horizontal × vertical)", s >> 4, s & 15)))
        .emit()?;
    f.u8("Quantization table").emit()?;
    Ok(())
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct ScanCtx {
    comps: Comps,
    /// The marker of the frame the scan belongs to.
    process: u8,
}

impl ScanCtx {
    fn ls(&self) -> bool {
        self.process == 0xf7
    }
}

#[derive(Clone, Debug, Default)]
struct Scan {
    ids: Vec<u8>,
    ss: u8,
    se: u8,
    ah: u8,
    al: u8,
}

fn scan_header(f: &mut Fields<'_>, ctx: &ScanCtx) -> Result<Scan> {
    let count = f.u8("Components in scan").emit()?;
    let mut ids = Vec::new();
    for _ in 0..count {
        if f.remaining() < 2 {
            break;
        }
        let span = f.peek_span(2);
        let id = f.u8("Component selector").get()?;
        let tables = f.u8("Table selectors").get()?;
        ids.push(id);
        let summary = if ctx.ls() {
            format!("ID {id}, mapping table {tables}")
        } else if lossless(ctx.process) {
            format!("ID {id}, DC table {}", tables >> 4)
        } else {
            format!(
                "ID {id}, DC table {}, AC table {}",
                tables >> 4,
                tables & 15
            )
        };
        f.node(
            struct_node(
                format!("Component {}", ctx.comps.name(id)),
                span,
                BE,
                *ctx,
                scan_component,
            )
            .summary(summary),
        );
    }
    let (ss, se, a) = if ctx.ls() {
        (
            f.u8("NEAR")
                .desc("Largest allowed sample error (0: lossless)")
                .emit()?,
            f.u8("Interleave mode").enumeration(LS_INTERLEAVE).emit()?,
            f.u8("Point transform")
                .desc("Low bits dropped before coding")
                .emit()?,
        )
    } else if lossless(ctx.process) {
        (
            f.u8("Predictor").enumeration(PREDICTORS).emit()?,
            f.u8("Spectral selection end")
                .desc("Unused in lossless mode (0)")
                .emit()?,
            f.u8("Point transform")
                .hex()
                .with(|&a, n| n.summary(format!("Pt {}", a & 15)))
                .emit()?,
        )
    } else {
        (
            f.u8("Spectral selection start")
                .desc("First coefficient of the band, in zigzag order (0: DC)")
                .emit()?,
            f.u8("Spectral selection end")
                .desc("Last coefficient of the band, in zigzag order")
                .emit()?,
            f.u8("Successive approximation")
                .hex()
                .with(|&a, n| n.summary(format!("Ah {}, Al {}", a >> 4, a & 15)))
                .desc("Ah: point transform of the previous scan of this band (0: first scan); Al: point transform of this one")
                .emit()?,
        )
    };
    Ok(Scan {
        ids,
        ss,
        se,
        ah: a >> 4,
        al: a & 15,
    })
}

fn scan_component(f: &mut Fields<'_>, ctx: &ScanCtx) -> Result<()> {
    f.u8("Component selector")
        .with(|&id, n| n.summary(ctx.comps.name(id)))
        .emit()?;
    if ctx.ls() {
        f.u8("Mapping table").desc("0: none").emit()?;
    } else {
        f.u8("Entropy tables")
            .hex()
            .with(|&t, n| n.summary(format!("DC {}, AC {}", t >> 4, t & 15)))
            .emit()?;
    }
    Ok(())
}

/// "Y, Cb, Cr: DC first, Al 1" (one line of the scan script).
fn scan_summary(scan: &Scan, ctx: &ScanCtx) -> String {
    let names = scan
        .ids
        .iter()
        .map(|&id| ctx.comps.name(id))
        .collect::<Vec<_>>()
        .join(", ");
    if ctx.ls() {
        let near = if scan.ss == 0 {
            "lossless".to_owned()
        } else {
            format!("NEAR {}", scan.ss)
        };
        let ilv = lookup(LS_INTERLEAVE, scan.se.into()).unwrap_or("unknown interleave");
        return format!("{names}: {near}, {ilv}");
    }
    if lossless(ctx.process) {
        return format!("{names}: predictor {}, Pt {}", scan.ss, scan.al);
    }
    if progressive(ctx.process) {
        let band = match (scan.ss, scan.se) {
            (0, 0) => "DC".to_owned(),
            (0, se) => format!("DC + AC 1–{se}"),
            (ss, se) => format!("AC {ss}–{se}"),
        };
        let pass = if scan.ah == 0 { "first" } else { "refine" };
        return format!("{names}: {band} {pass}, Al {}", scan.al);
    }
    names
}

// ---------------------------------------------------------------------------
// Tables: DQT, DHT, DAC

struct Dqt {
    offset: usize,
    wide: bool,
    dest: u8,
    quality: Option<(u32, bool)>,
}

/// Converts table values from zigzag to natural order.
fn natural(values: &[u8], wide: bool) -> [u16; 64] {
    let mut out = [0u16; 64];
    for (k, &nat) in ZIGZAG.iter().enumerate() {
        let v = if wide {
            u16_be(values, k.saturating_mul(2))
        } else {
            values.get(k).map(|&b| u16::from(b))
        };
        if let (Some(v), Some(slot)) = (v, out.get_mut(usize::from(nat))) {
            *slot = v;
        }
    }
    out
}

/// The IJG (libjpeg `jpeg_set_quality`) quality setting that produces this
/// table from one of the Annex K tables, and whether it is the luminance one.
fn ijg_quality(table: &[u16; 64], wide: bool) -> Option<(u32, bool)> {
    for (base, luminance) in [(&STD_LUMINANCE, true), (&STD_CHROMINANCE, false)] {
        for q in 1u32..=100 {
            let scale = if q < 50 {
                5000u32.checked_div(q).unwrap_or(5000)
            } else {
                200u32.saturating_sub(q.saturating_mul(2))
            };
            let matches = table.iter().zip(base.iter()).all(|(&v, &s)| {
                let t = u32::from(s)
                    .saturating_mul(scale)
                    .saturating_add(50)
                    .checked_div(100)
                    .unwrap_or(0)
                    .clamp(1, 32767);
                // Baseline-forced tables clamp at 255.
                u32::from(v) == t || (!wide && t > 255 && v == 255)
            });
            if matches {
                return Some((q, luminance));
            }
        }
    }
    None
}

fn parse_dqt(data: &[u8]) -> (Vec<Dqt>, bool) {
    let mut tables = Vec::new();
    let mut pos = 0usize;
    while let Some(&info) = data.get(pos) {
        let wide = info >> 4 != 0;
        let n = if wide { 128 } else { 64 };
        let start = pos.saturating_add(1);
        let Some(values) = data.get(start..start.saturating_add(n)) else {
            return (tables, true);
        };
        // Only the first few tables can be in use (destinations 0–3).
        let quality = if tables.len() < 4 {
            ijg_quality(&natural(values, wide), wide)
        } else {
            None
        };
        tables.push(Dqt {
            offset: pos,
            wide,
            dest: info & 15,
            quality,
        });
        pos = start.saturating_add(n);
    }
    (tables, false)
}

fn dqt_summary(tables: &[Dqt]) -> String {
    let list = tables
        .iter()
        .map(|t| t.dest.to_string())
        .collect::<Vec<_>>()
        .join(", ");
    let mut out = format!(
        "{} {list}",
        if tables.len() == 1 { "table" } else { "tables" }
    );
    if tables.iter().any(|t| t.wide) {
        out.push_str(", 16-bit");
    }
    if let Some((q, _)) = tables.iter().find_map(|t| t.quality) {
        out = format!("{out}, IJG quality {q}");
    }
    out
}

async fn quantization_tables(cx: &Cx, payload: Span) -> Result<()> {
    let data = cx.read(payload).await?;
    let (tables, truncated) = parse_dqt(&data);
    let mut end = 0u64;
    for t in &tables {
        let len = if t.wide { 129 } else { 65 };
        let span = payload.sub(to_u64(t.offset), len);
        end = to_u64(t.offset).saturating_add(len);
        let mut summary = if t.wide { "16-bit" } else { "8-bit" }.to_owned();
        if let Some((q, luminance)) = t.quality {
            let kind = if luminance {
                "luminance"
            } else {
                "chrominance"
            };
            summary = format!("{summary}, IJG quality {q} ({kind} scale)");
        }
        cx.emit(
            struct_node(
                format!("Table {}", t.dest),
                span,
                BE,
                t.wide,
                quantization_table,
            )
            .summary(summary),
        );
    }
    if truncated {
        let rest = payload.tail(end);
        cx.emit(
            Node::new("Table")
                .span(rest)
                .diag(Diagnostic::malformed("quantization table cut short").at(rest)),
        );
    }
    Ok(())
}

fn quantization_table(f: &mut Fields<'_>, wide: &bool) -> Result<()> {
    f.u8("Precision and destination")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}-bit, table {}",
                if v >> 4 == 0 { 8 } else { 16 },
                v & 15
            ))
        })
        .emit()?;
    let span = f.peek_span(if *wide { 128 } else { 64 });
    let values = f
        .bytes("Values (zigzag order)", if *wide { 128 } else { 64 })
        .emit()?;
    let table = natural(&values, *wide);
    f.node(
        Node::new("Matrix")
            .span(span)
            .summary(format!(
                "natural order, DC {}",
                table.first().copied().unwrap_or(0)
            ))
            .lazy(matrix_rows, table),
    );
    Ok(())
}

async fn matrix_rows(cx: Cx, table: [u16; 64]) -> Result<()> {
    for (r, row) in table.chunks(8).enumerate() {
        let line = row
            .iter()
            .map(|v| format!("{v:>3}"))
            .collect::<Vec<_>>()
            .join(" ");
        cx.emit(Node::new(format!("Row {r}")).value(text(line)));
    }
    Ok(())
}

struct Dht {
    offset: usize,
    ac: bool,
    dest: u8,
    symbols: usize,
    max_len: usize,
    standard: Option<&'static str>,
    overflow: bool,
}

fn parse_dht(data: &[u8]) -> (Vec<Dht>, bool) {
    let mut tables = Vec::new();
    let mut pos = 0usize;
    while let Some(&info) = data.get(pos) {
        let Some(counts) = crate::bytes::array::<16>(data, pos.saturating_add(1)) else {
            return (tables, true);
        };
        let symbols: usize = counts.iter().map(|&c| usize::from(c)).sum();
        let start = pos.saturating_add(17);
        let Some(syms) = data.get(start..start.saturating_add(symbols)) else {
            return (tables, true);
        };
        let ac = info >> 4 != 0;
        let class = u8::from(ac);
        let standard = STD_HUFFMAN
            .iter()
            .find(|(c, bits, first, _)| {
                *c == class && *bits == counts && syms.get(..8) == Some(first.as_slice())
            })
            .map(|t| t.3);
        // Canonical codes of each length must fit in that many bits.
        let mut code = 0u32;
        let mut overflow = false;
        for (i, &n) in counts.iter().enumerate() {
            code = code.saturating_add(u32::from(n));
            let limit = 1u32
                .checked_shl(u32::try_from(i).unwrap_or(31).saturating_add(1))
                .unwrap_or(u32::MAX);
            // As libjpeg: the all-ones code of a length is reserved.
            if n > 0 && code >= limit {
                overflow = true;
            }
            code = code.saturating_mul(2);
        }
        tables.push(Dht {
            offset: pos,
            ac,
            dest: info & 15,
            symbols,
            max_len: counts
                .iter()
                .rposition(|&c| c != 0)
                .map_or(0, |i| i.saturating_add(1)),
            standard,
            overflow,
        });
        pos = start.saturating_add(symbols);
    }
    (tables, false)
}

fn dht_summary(tables: &[Dht]) -> String {
    let list = tables
        .iter()
        .map(|t| format!("{} {}", if t.ac { "AC" } else { "DC" }, t.dest))
        .collect::<Vec<_>>()
        .join(", ");
    if !tables.is_empty() && tables.iter().all(|t| t.standard.is_some()) {
        format!("{list} (standard tables)")
    } else {
        list
    }
}

async fn huffman_tables(cx: &Cx, payload: Span) -> Result<()> {
    let data = cx.read(payload).await?;
    let (tables, truncated) = parse_dht(&data);
    let mut end = 0u64;
    for t in &tables {
        let len = to_u64(t.symbols).saturating_add(17);
        let span = payload.sub(to_u64(t.offset), len);
        end = to_u64(t.offset).saturating_add(len);
        let mut summary = format!(
            "{} {}, codes up to {} {}",
            t.symbols,
            if t.symbols == 1 { "symbol" } else { "symbols" },
            t.max_len,
            if t.max_len == 1 { "bit" } else { "bits" }
        );
        if let Some(s) = t.standard {
            summary = format!("{summary}, {s}");
        }
        let ctx = HuffCtx {
            symbols: t.symbols,
            ac: t.ac,
        };
        let mut node = struct_node(
            format!("{} table {}", if t.ac { "AC" } else { "DC" }, t.dest),
            span,
            BE,
            ctx,
            huffman_table,
        )
        .summary(summary);
        if t.overflow {
            node = node.diag(Diagnostic::malformed("more codes than their lengths allow").at(span));
        }
        if t.dest > 3 {
            node = node.diag(
                Diagnostic::malformed(format!("table destination {} (0–3)", t.dest)).at(span),
            );
        }
        cx.emit(node);
    }
    if truncated {
        let rest = payload.tail(end);
        cx.emit(
            Node::new("Table")
                .span(rest)
                .diag(Diagnostic::malformed("Huffman table cut short").at(rest)),
        );
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct HuffCtx {
    symbols: usize,
    ac: bool,
}

fn huffman_table(f: &mut Fields<'_>, ctx: &HuffCtx) -> Result<()> {
    f.u8("Class and destination")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{}, table {}",
                if v >> 4 == 0 { "DC" } else { "AC" },
                v & 15
            ))
        })
        .emit()?;
    let counts = f
        .bytes("Code counts by length", 16)
        .desc("Number of codes of each length, 1 to 16 bits")
        .emit()?;
    let span = f.peek_span(to_u64(ctx.symbols));
    f.bytes("Symbols", to_u64(ctx.symbols))
        .desc("In order of increasing code length")
        .emit()?;
    let mut lengths = [0u8; 16];
    for (slot, &c) in lengths.iter_mut().zip(&counts) {
        *slot = c;
    }
    f.node(
        Node::new("Codes by length")
            .span(span)
            .summary(if ctx.ac {
                "symbols as run/size (hex)"
            } else {
                "symbols are difference categories"
            })
            .lazy(
                huffman_codes,
                Codes {
                    symbols: span,
                    counts: lengths,
                    ac: ctx.ac,
                },
            ),
    );
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Codes {
    symbols: Span,
    counts: [u8; 16],
    ac: bool,
}

/// A Huffman symbol in the usual notation: DC categories (difference
/// sizes) as numbers, AC symbols as run/size in hex, EOB and ZRL by name.
fn symbol_label(symbol: u8, ac: bool) -> String {
    if !ac {
        return symbol.to_string();
    }
    match (symbol >> 4, symbol & 15) {
        (0, 0) => "EOB".to_owned(),
        (15, 0) => "ZRL".to_owned(),
        (r, 0) => format!("EOB{r}"),
        (r, s) => format!("{r:X}/{s:X}"),
    }
}

/// Lists the symbols of a Huffman table by code length, with the range of
/// canonical codes each length gets.
async fn huffman_codes(cx: Cx, c: Codes) -> Result<()> {
    let symbols = cx.read_avail(c.symbols).await?;
    let mut code = 0u32;
    let mut k = 0usize;
    for (i, &n) in c.counts.iter().enumerate() {
        let bits = i.saturating_add(1);
        if n > 0 {
            let first = code;
            let last = code.saturating_add(u32::from(n)).saturating_sub(1);
            let end = k.saturating_add(usize::from(n));
            let labels = symbols
                .get(k..end.min(symbols.len()))
                .unwrap_or_default()
                .iter()
                .map(|&s| symbol_label(s, c.ac))
                .collect::<Vec<_>>()
                .join(" ");
            let mut node = Node::new(format!("{bits}-bit codes"))
                .span(c.symbols.sub(to_u64(k), u64::from(n)))
                .value(text(labels))
                .summary(if n == 1 {
                    format!("{first:0bits$b}")
                } else {
                    format!("{first:0bits$b}–{last:0bits$b}")
                });
            let limit = 1u32
                .checked_shl(u32::try_from(bits).unwrap_or(31))
                .unwrap_or(u32::MAX);
            if last >= limit {
                node = node.diag(Diagnostic::malformed(format!(
                    "more {bits}-bit codes than fit in {bits} bits"
                )));
            }
            cx.emit(node);
            code = code.saturating_add(u32::from(n));
            k = end;
        }
        code = code.saturating_mul(2);
    }
    Ok(())
}

fn conditioning(f: &mut Fields<'_>, _: &()) -> Result<usize> {
    let mut n = 0usize;
    while f.remaining() >= 2 {
        let span = f.peek_span(2);
        let tc = f.u8("Class and destination").get()?;
        let cs = f.u8("Conditioning value").get()?;
        let (name, summary) = if tc >> 4 == 0 {
            (
                format!("DC table {}", tc & 15),
                format!("L = {}, U = {}", cs & 15, cs >> 4),
            )
        } else {
            (format!("AC table {}", tc & 15), format!("Kx = {cs}"))
        };
        f.node(Node::new(name).span(span).value(uint(cs)).summary(summary));
        n = n.saturating_add(1);
    }
    Ok(n)
}

fn jpeg_ls_parameters(f: &mut Fields<'_>, _: &()) -> Result<u8> {
    let id = f.u8("Parameter ID").enumeration(LSE_IDS).emit()?;
    match id {
        1 => {
            f.u16("MAXVAL").desc("Largest sample value").emit()?;
            f.u16("T1").desc("Gradient threshold 1").emit()?;
            f.u16("T2").desc("Gradient threshold 2").emit()?;
            f.u16("T3").desc("Gradient threshold 3").emit()?;
            f.u16("RESET").desc("Context counter reset value").emit()?;
        }
        2 | 3 => {
            f.u8("Table ID").emit()?;
            if id == 2 {
                f.u8("Entry width").desc("Bytes per table entry").emit()?;
            }
            let rest = f.peek_span(f.remaining());
            f.node(Node::new("Table data").span(rest));
        }
        4 => {
            let width = f.u8("Wxy").desc("Bytes per dimension").emit()?;
            let w = u64::from(width);
            f.bytes("Height (Y)", w).emit()?;
            f.bytes("Width (X)", w).emit()?;
        }
        _ => {
            let rest = f.peek_span(f.remaining());
            f.node(Node::new("Data").span(rest));
        }
    }
    Ok(id)
}

// ---------------------------------------------------------------------------
// In-memory TIFF structures (the MPF index)

fn tiff_endian(data: &[u8]) -> Option<Endian> {
    match data.get(..4)? {
        b"II*\0" => Some(Endian::Little),
        b"MM\0*" => Some(Endian::Big),
        _ => None,
    }
}

fn get<T: Prim>(data: &[u8], offset: usize, endian: Endian) -> Option<T> {
    T::decode(data.get(offset..offset.checked_add(T::SIZE)?)?, endian)
}

/// The entries of the IFD at `offset` in an in-memory TIFF stream: tag,
/// type, where the value is and its bytes.
fn ifd_entries(data: &[u8], endian: Endian, offset: u32) -> Vec<(u16, u16, usize, &[u8])> {
    let mut out = Vec::new();
    let Ok(at) = usize::try_from(offset) else {
        return out;
    };
    let Some(count) = get::<u16>(data, at, endian) else {
        return out;
    };
    for i in 0..usize::from(count) {
        let Some(e) = i
            .checked_mul(12)
            .and_then(|o| o.checked_add(at))
            .and_then(|o| o.checked_add(2))
        else {
            break;
        };
        let (Some(tag), Some(kind), Some(n)) = (
            get::<u16>(data, e, endian),
            get::<u16>(data, e.saturating_add(2), endian),
            get::<u32>(data, e.saturating_add(4), endian),
        ) else {
            break;
        };
        let unit: usize = match kind {
            1 | 2 | 6 | 7 => 1,
            3 | 8 => 2,
            4 | 9 | 11 | 13 => 4,
            5 | 10 | 12 => 8,
            _ => continue,
        };
        let Some(size) = usize::try_from(n).ok().and_then(|n| n.checked_mul(unit)) else {
            continue;
        };
        let at = if size <= 4 {
            Some(e.saturating_add(8))
        } else {
            get::<u32>(data, e.saturating_add(8), endian).and_then(|o| usize::try_from(o).ok())
        };
        if let Some(at) = at
            && let Some(value) = data.get(at..at.saturating_add(size))
        {
            out.push((tag, kind, at, value));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// MPF

#[derive(Clone, Copy, Debug)]
struct MpEntry {
    attribute: u32,
    size: u32,
    offset: u32,
    /// Where the 16-byte entry is, relative to the MP header.
    at: usize,
}

/// The MP entries of an MP index IFD (`data` starts at the MP header, the
/// byte order mark after "MPF\0").
fn parse_mpf(data: &[u8]) -> Option<(Endian, Vec<MpEntry>)> {
    let endian = tiff_endian(data)?;
    let ifd = get::<u32>(data, 4, endian)?;
    let mut entries = Vec::new();
    let Some((start, pointer)) = ifd_entries(data, endian, ifd)
        .into_iter()
        .find(|(tag, kind, _, _)| *tag == 0xb002 && *kind == 7)
        .map(|(_, _, at, value)| (at, value))
    else {
        return Some((endian, entries));
    };
    for (i, e) in pointer.as_chunks::<16>().0.iter().enumerate().take(256) {
        let (Some(attribute), Some(size), Some(offset)) = (
            get::<u32>(e, 0, endian),
            get::<u32>(e, 4, endian),
            get::<u32>(e, 8, endian),
        ) else {
            break;
        };
        entries.push(MpEntry {
            attribute,
            size,
            offset,
            at: start.saturating_add(i.saturating_mul(16)),
        });
    }
    Some((endian, entries))
}

fn mp_attribute(a: u32) -> String {
    let kind = a & 0x00ff_ffff;
    let mut parts = vec![
        lookup(MP_TYPES, kind.into()).map_or_else(|| format!("type {kind:#08x}"), str::to_owned),
    ];
    if a & 0x2000_0000 != 0 {
        parts.push("representative".to_owned());
    }
    if a & 0x8000_0000 != 0 {
        parts.push("dependent parent".to_owned());
    }
    if a & 0x4000_0000 != 0 {
        parts.push("dependent child".to_owned());
    }
    match (a >> 24) & 7 {
        0 => {}
        f => parts.push(format!("data format {f}")),
    }
    parts.join(", ")
}

/// An image listed by the MPF index, relative to the file.
#[derive(Clone, Copy, Debug)]
struct MpImage {
    index: usize,
    attribute: u32,
    at: u64,
    len: u64,
}

/// Where an MP entry's image is, relative to `file`. `header` is the MP
/// header (the payload after "MPF\0").
fn mp_image_at(file: Span, header: Span, e: &MpEntry) -> u64 {
    if e.offset == 0 {
        0
    } else {
        header
            .offset
            .saturating_sub(file.offset)
            .saturating_add(u64::from(e.offset))
    }
}

#[derive(Clone, Copy, Debug)]
struct MpState {
    input: Input,
    header: Span,
}

async fn mp_images(cx: Cx, st: MpState) -> Result<()> {
    let data = cx.read_avail(st.header).await?;
    let Some((endian, entries)) = parse_mpf(&data) else {
        return Err(Diagnostic::malformed("bad MP header").at(st.header));
    };
    cx.set_count(Count::Exact(to_u64(entries.len())));
    let file = st.input.span;
    for (i, e) in entries.iter().enumerate() {
        let at = mp_image_at(file, st.header, e);
        let image = file.sub(at, u64::from(e.size));
        let mut summary = format!(
            "{}, {}",
            mp_attribute(e.attribute),
            human_size(u64::from(e.size))
        );
        if e.offset == 0 {
            summary.push_str(" (this image)");
        } else {
            summary = format!("{summary} at {:#x}", image.offset);
        }
        let mut node = Node::new(format!("Image {}", i.saturating_add(1)))
            .span(st.header.sub(to_u64(e.at), 16))
            .target(image)
            .summary(summary)
            .lazy(
                mp_image,
                MpImageState {
                    entry: st.header.sub(to_u64(e.at), 16),
                    endian,
                },
            );
        if image.len < u64::from(e.size) {
            node = node.diag(Diagnostic::truncated(
                Span::new(image.source, image.offset, e.size.into()),
                image.len,
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct MpImageState {
    entry: Span,
    endian: Endian,
}

async fn mp_image(cx: Cx, st: MpImageState) -> Result<()> {
    let block = cx.block(st.entry).await?;
    let mut f = Fields::emitting(&cx, &block, st.endian);
    f.u32("Individual image attribute")
        .hex()
        .with(|&a, n| n.summary(mp_attribute(a)))
        .emit()?;
    f.u32("Image size").emit()?;
    f.u32("Image data offset")
        .hex()
        .desc("From the MP header (the byte order mark after \"MPF\\0\"); 0 for the first image")
        .emit()?;
    f.u16("Dependent image 1 entry").emit()?;
    f.u16("Dependent image 2 entry").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Application segments

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum App {
    Jfif,
    Jfxx,
    Avi1,
    Exif,
    Xmp,
    XmpExt,
    Icc,
    Mpf,
    Fpxr,
    GainMap,
    Jps,
    Meta,
    Spiff,
    Jumbf,
    Ducky,
    PictureInfo,
    Photoshop,
    Adobe,
    Other,
}

/// What an APPn segment holds, from its first bytes, and the length of its
/// identifier.
fn app_kind(marker: u8, head: &[u8]) -> (App, u64) {
    let p = |id: &[u8]| head.starts_with(id);
    let (kind, len) = match marker {
        0xe0 if p(b"JFIF\0") => (App::Jfif, 5),
        0xe0 if p(b"JFXX\0") => (App::Jfxx, 5),
        0xe0 if p(b"AVI1") => (App::Avi1, 4),
        0xe1 if p(EXIF) => (App::Exif, 6),
        0xe1 if p(XMP) => (App::Xmp, XMP.len()),
        0xe1 if p(XMP_EXTENSION) => (App::XmpExt, XMP_EXTENSION.len()),
        0xe2 if p(ICC) => (App::Icc, ICC.len()),
        0xe2 if p(b"MPF\0") => (App::Mpf, 4),
        0xe2 if p(b"FPXR\0") => (App::Fpxr, 5),
        0xe2 if p(GAIN_MAP) => (App::GainMap, GAIN_MAP.len()),
        0xe3 if p(b"_JPSJPS_") => (App::Jps, 8),
        0xe3 if p(b"META\0\0") || p(b"Meta\0\0") || p(b"Exif\0\0") => (App::Meta, 6),
        0xe8 if p(b"SPIFF\0") => (App::Spiff, 6),
        0xeb if p(b"JP") && head.len() >= 8 => (App::Jumbf, 2),
        0xec if p(b"Ducky") => (App::Ducky, 5),
        0xec if p(b"[picture info]") || p(b"PictureInfo") => (App::PictureInfo, 0),
        0xed if p(PHOTOSHOP) => (App::Photoshop, PHOTOSHOP.len()),
        0xee if p(b"Adobe") => (App::Adobe, 5),
        _ => (App::Other, generic_identifier(head)),
    };
    (kind, to_u64(len))
}

/// The length of a NUL-terminated printable identifier, or 0.
fn generic_identifier(head: &[u8]) -> usize {
    let Some(end) = head.iter().position(|&b| b == 0) else {
        return 0;
    };
    let id = head.get(..end).unwrap_or_default();
    if !id.is_empty() && id.iter().all(|b| b.is_ascii_graphic() || *b == b' ') {
        end.saturating_add(1)
    } else {
        0
    }
}

fn id_text(head: &[u8], len: u64) -> String {
    let id = head.get(..to_usize(len)).unwrap_or(head);
    let shown = id.split(|&b| b == 0).next().unwrap_or_default();
    String::from_utf8_lossy(shown).into_owned()
}

fn id_node(name: &'static str, payload: Span, head: &[u8], len: u64) -> Node {
    Node::new(name)
        .span(payload.sub(0, len))
        .value(text(id_text(head, len)))
}

/// A UUID: its four-character code for ISO-registered ones, else 8-4-4-4-12.
fn uuid_text(b: &[u8]) -> String {
    if b.get(4..16) == Some(ISO_UUID_SUFFIX.as_slice())
        && let Some(cc) = b.get(..4)
        && cc.iter().all(|c| c.is_ascii_graphic() || *c == b' ')
    {
        return format!("'{}'", String::from_utf8_lossy(cc));
    }
    let hex: String = b.iter().take(16).map(|x| format!("{x:02x}")).collect();
    let part = |a: usize, z: usize| hex.get(a..z).unwrap_or_default().to_owned();
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

fn jfif_summary(head: &[u8]) -> String {
    if head.len() < 14 {
        return "JFIF".to_owned();
    }
    let at = |i: usize| head.get(i).copied().unwrap_or(0);
    let mut s = format!("JFIF {}.{:02}", at(5), at(6));
    let (x, y) = (u16_be(head, 8).unwrap_or(0), u16_be(head, 10).unwrap_or(0));
    match at(7) {
        1 => s = format!("{s}, {x}×{y} dpi"),
        2 => s = format!("{s}, {x}×{y} dots/cm"),
        _ if x != y => s = format!("{s}, aspect {x}:{y}"),
        _ => {}
    }
    if at(12) > 0 && at(13) > 0 {
        s = format!("{s}, {} thumbnail", dims(at(12), at(13)));
    }
    s
}

fn jps_descriptor(d: u32) -> String {
    let media = match d & 0xff {
        0 => "monoscopic",
        1 => "stereoscopic",
        _ => "unknown media type",
    };
    let layout = match (d >> 16) & 0xff {
        1 => Some("interleaved"),
        2 => Some("side-by-side"),
        3 => Some("over/under"),
        4 => Some("anaglyph"),
        _ => None,
    };
    let mut parts = vec![media.to_owned()];
    parts.extend(layout.map(str::to_owned));
    let flags = (d >> 8) & 0xff;
    if flags & 1 != 0 {
        parts.push("half height".to_owned());
    }
    if flags & 2 != 0 {
        parts.push("half width".to_owned());
    }
    if flags & 4 != 0 {
        parts.push("left field first".to_owned());
    }
    parts.join(", ")
}

/// "C2PA manifest store" from the first packet of a JUMBF box.
fn jumbf_summary(head: &[u8]) -> String {
    let en = u16_be(head, 2).unwrap_or(0);
    let z = u32_be(head, 4).unwrap_or(0);
    if z == 1
        && head.get(12..16) == Some(b"jumb".as_slice())
        && head.get(20..24) == Some(b"jumd".as_slice())
    {
        let kind = uuid_text(head.get(24..40).unwrap_or_default());
        if kind == "'c2pa'" {
            return format!("JUMBF: C2PA manifest store, box {en}");
        }
        return format!("JUMBF {kind}, box {en}");
    }
    format!("JUMBF, box {en}, packet {z}")
}

fn ducky_summary(head: &[u8]) -> String {
    if u16_be(head, 5) == Some(1)
        && u16_be(head, 7) == Some(4)
        && let Some(q) = u32_be(head, 9)
    {
        return format!("Ducky, quality {q}");
    }
    "Ducky".to_owned()
}

/// A run of Photoshop APP13 payloads (after the identifier) that hold one
/// list of image resources: Photoshop splits the list over several
/// segments when it exceeds one, cutting a resource wherever the segment
/// ends.
#[derive(Clone, Debug, Default)]
struct IrbGroup {
    parts: Vec<Span>,
    /// Resources found, and whether one of them is IPTC-IIM (1028).
    count: usize,
    iptc: bool,
}

/// The Photoshop APP13 segments of `file`, grouped so that a resource that
/// continues into the next segment keeps the two together.
async fn irb_groups(cx: &Cx, file: Span) -> Arc<Vec<IrbGroup>> {
    const KIND: &str = "jpeg-photoshop-groups";
    if let Some(groups) = cx.cached::<Vec<IrbGroup>>(file, KIND) {
        return groups;
    }
    let groups = Arc::new(scan_irb_groups(cx, file).await.unwrap_or_default());
    cx.cache(file, KIND, Arc::clone(&groups));
    groups
}

async fn scan_irb_groups(cx: &Cx, file: Span) -> Result<Vec<IrbGroup>> {
    let segments = header_segments(cx, file).await;
    let mut parts = Vec::new();
    for seg in segments.iter().filter(|s| s.marker == 0xed) {
        let head = cx.read_avail(seg.payload().sub(0, 80)).await?;
        if let (App::Photoshop, id_len) = app_kind(seg.marker, &head) {
            parts.push(seg.payload().tail(id_len));
        }
    }
    group_irb_parts(cx, parts).await
}

/// Groups Photoshop APP13 payloads by walking the resources across them.
async fn group_irb_parts(cx: &Cx, parts: Vec<Span>) -> Result<Vec<IrbGroup>> {
    // Where each part starts in the parts joined end to end.
    let mut starts = Vec::with_capacity(parts.len());
    let mut total = 0u64;
    for p in &parts {
        starts.push(total);
        total = total.saturating_add(p.len);
    }
    // Whether part i continues part i - 1, and per part the resources that
    // start in it.
    let mut joined = vec![false; parts.len()];
    let mut counts = vec![(0usize, false); parts.len()];
    let mut pos = 0u64;
    let mut k = 0usize;
    while pos < total {
        cx.checkpoint().await;
        while starts.get(k.saturating_add(1)).is_some_and(|&s| s <= pos) {
            k = k.saturating_add(1);
        }
        let part_start = starts.get(k).copied().unwrap_or(0);
        let next_part = starts.get(k.saturating_add(1)).copied().unwrap_or(total);
        let head = read_joined(
            cx,
            parts.get(k..).unwrap_or_default(),
            pos.saturating_sub(part_start),
            268,
        )
        .await?;
        let Some(end) = irb_resource_end(&head).map(|n| pos.saturating_add(n)) else {
            // Not a resource: go on with the next segment.
            pos = next_part;
            continue;
        };
        if let Some((n, iptc)) = counts.get_mut(k) {
            *n = n.saturating_add(1);
            *iptc |= u16_be(&head, 4) == Some(1028);
        }
        if end > total {
            // Cut short at the end of the last segment: joins nothing.
            break;
        }
        // Segments this resource runs into continue the one it starts in.
        let mut j = k.saturating_add(1);
        while starts.get(j).is_some_and(|&s| s < end) {
            if let Some(flag) = joined.get_mut(j) {
                *flag = true;
            }
            j = j.saturating_add(1);
        }
        pos = end;
    }
    let mut groups: Vec<IrbGroup> = Vec::new();
    for ((part, join), (n, iptc)) in parts.into_iter().zip(joined).zip(counts) {
        match groups.last_mut() {
            Some(g) if join => {
                g.parts.push(part);
                g.count = g.count.saturating_add(n);
                g.iptc |= iptc;
            }
            _ => groups.push(IrbGroup {
                parts: vec![part],
                count: n,
                iptc,
            }),
        }
    }
    Ok(groups)
}

/// Up to `n` bytes at `pos` in `parts` joined end to end.
async fn read_joined(cx: &Cx, parts: &[Span], mut pos: u64, n: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for p in parts {
        let want = n.saturating_sub(to_u64(out.len()));
        if want == 0 {
            break;
        }
        if pos >= p.len {
            pos = pos.saturating_sub(p.len);
            continue;
        }
        out.extend(cx.read_avail(p.sub(pos, want)).await?);
        pos = 0;
    }
    Ok(out)
}

/// The size of the image resource (signature, id, padded Pascal name, size,
/// padded data) whose header starts `head`.
fn irb_resource_end(head: &[u8]) -> Option<u64> {
    if !matches!(
        head.get(..4)?,
        b"8BIM" | b"MeSa" | b"AgHg" | b"PHUT" | b"DCSR"
    ) {
        return None;
    }
    let name_len = u64::from(*head.get(6)?);
    // The Pascal name with its length byte, padded to even size.
    let name = name_len.saturating_add(1);
    let size_at = 6u64.saturating_add(name).saturating_add(name & 1);
    let size = u64::from(u32_be(head, to_usize(size_at))?);
    Some(
        size_at
            .saturating_add(4)
            .saturating_add(size)
            .saturating_add(size & 1),
    )
}

/// The group a Photoshop APP13 payload belongs to, and its place in it.
async fn irb_group(cx: &Cx, file: Span, rest: Span) -> Option<(IrbGroup, usize)> {
    let groups = irb_groups(cx, file).await;
    let found = groups.iter().find_map(|g| {
        g.parts
            .iter()
            .position(|p| p.offset == rest.offset)
            .map(|i| (g.clone(), i))
    });
    if found.is_some() {
        return found;
    }
    // A segment after the first scan: on its own.
    let alone = group_irb_parts(cx, vec![rest]).await.ok()?;
    Some((alone.into_iter().next()?, 0))
}

/// The image resources of a Photoshop APP13 segment (`rest`, after the
/// identifier), joined with the segments they continue into.
async fn photoshop_segment(cx: &Cx, input: Input, rest: Span) -> Result<()> {
    match irb_group(cx, input.span, rest).await {
        Some((g, 0)) if g.parts.len() > 1 => {
            let first = g.parts.first().copied().unwrap_or(rest);
            let last = g.parts.last().copied().unwrap_or(rest);
            let parent = Span::new(
                first.source,
                first.offset,
                last.end().saturating_sub(first.offset),
            );
            let n = g.parts.len();
            let joined = cx.add_pieces(
                Origin {
                    parent,
                    transform: "jpeg-photoshop-segments",
                },
                g.parts,
            )?;
            cx.emit(
                super::psd::resources_node("Image resources", input, joined)
                    .summary(format!("joined from {n} APP13 segments")),
            );
        }
        Some((g, index)) if index > 0 => {
            cx.emit(
                Node::new("Image resources (continued)")
                    .span(rest)
                    .summary(format!(
                        "segment {} of {}; the resources are shown under the first",
                        index.saturating_add(1),
                        g.parts.len()
                    )),
            );
        }
        _ => cx.emit(super::psd::resources_node("Image resources", input, rest)),
    }
    Ok(())
}

fn irb_summary(g: &IrbGroup, index: usize) -> String {
    if index > 0 {
        return "Photoshop 3.0, continued".to_owned();
    }
    let plural = if g.count == 1 { "" } else { "s" };
    let mut s = format!("Photoshop 3.0: {} resource{plural}", g.count);
    if g.iptc {
        s.push_str(", IPTC");
    }
    if g.parts.len() > 1 {
        s.push_str(&format!(", in {} segments", g.parts.len()));
    }
    s
}

#[derive(Clone, Copy, Debug)]
struct SegState {
    input: Input,
    seg: Segment,
    comps: Comps,
    process: u8,
}

async fn application(cx: &Cx, st: &SegState) -> Result<()> {
    let input = st.input;
    let seg = &st.seg;
    let payload = seg.payload();
    let head = cx.read_avail(payload.sub(0, 80)).await?;
    let (kind, id_len) = app_kind(seg.marker, &head);
    let rest = payload.tail(id_len);
    let ident = |name| id_node(name, payload, &head, id_len);
    match kind {
        App::Jfif => {
            let block = cx.block(payload.sub(0, 14)).await?;
            let (w, h) = jfif(&mut Fields::emitting(cx, &block, BE), &())?;
            if w > 0 && h > 0 {
                let len = u64::from(w).saturating_mul(u64::from(h)).saturating_mul(3);
                cx.emit(
                    region("Thumbnail", payload, 14, len)
                        .summary(format!("{}, 24-bit RGB", dims(w, h))),
                );
            }
        }
        App::Jfxx => {
            cx.emit(ident("Identifier"));
            let block = cx.block(payload.sub(5, 3)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            let code = f.u8("Extension code").enumeration(JFXX_CODES).emit()?;
            match code {
                0x10 => cx.emit(embedded("Thumbnail", input.nested(payload.tail(6)))),
                0x11 | 0x13 => {
                    let w = f.u8("Thumbnail width").emit()?;
                    let h = f.u8("Thumbnail height").emit()?;
                    let pixels = u64::from(w).saturating_mul(u64::from(h));
                    if code == 0x11 {
                        cx.emit(palette("Palette", payload.sub(8, 768), ColorOrder::Rgb));
                        cx.emit(
                            region("Pixels", payload, 776, pixels)
                                .summary(format!("{}, 8-bit palette indices", dims(w, h))),
                        );
                    } else {
                        cx.emit(
                            region("Pixels", payload, 8, pixels.saturating_mul(3))
                                .summary(format!("{}, 24-bit RGB", dims(w, h))),
                        );
                    }
                }
                _ => cx.emit(Node::new("Data").span(payload.tail(6))),
            }
        }
        App::Avi1 => {
            cx.emit(ident("Identifier"));
            let block = cx.block(rest.sub(0, 1)).await?;
            Fields::emitting(cx, &block, BE)
                .u8("Polarity")
                .enumeration(AVI1_POLARITY)
                .emit()?;
            if rest.len > 1 {
                cx.emit(Node::new("Data").span(rest.tail(1)));
            }
        }
        App::Exif => {
            cx.emit(
                ident("Identifier").desc("\"Exif\", a NUL and a pad byte; the TIFF stream follows"),
            );
            cx.emit(embedded_as(
                "Exif",
                input.nested(rest),
                &super::tiff::FORMAT,
            ));
        }
        App::Meta => {
            cx.emit(ident("Identifier"));
            cx.emit(embedded_as(
                "Metadata (TIFF)",
                input.nested(rest),
                &super::tiff::FORMAT,
            ));
        }
        App::Xmp => {
            cx.emit(ident("Namespace"));
            cx.emit(embedded("XMP packet", input.nested(rest)).summary(human_size(rest.len)));
        }
        App::XmpExt => extended_xmp_segment(cx, input, payload, rest, ident("Namespace")).await?,
        App::Icc => icc_segment(cx, input, rest, ident("Identifier")).await?,
        App::Mpf => {
            cx.emit(ident("Identifier"));
            cx.emit(
                embedded_as("MP index", input.nested(rest), &super::tiff::FORMAT)
                    .summary("TIFF structure: MP index IFD and MP attribute IFD"),
            );
            let data = cx.read_avail(rest).await?;
            if let Some((_, entries)) = parse_mpf(&data)
                && !entries.is_empty()
            {
                cx.emit(
                    Node::new("Images")
                        .span(rest)
                        .summary(format!("{} images", entries.len()))
                        .lazy(
                            mp_images,
                            MpState {
                                input,
                                header: rest,
                            },
                        ),
                );
            }
        }
        App::Fpxr => {
            cx.emit(ident("Identifier"));
            let block = cx.block(rest).await?;
            flashpix(cx, &block)?;
        }
        App::GainMap => {
            cx.emit(ident("Identifier"));
            let block = cx.block(rest.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, BE);
            f.u16("Minimum version").emit()?;
            f.u16("Writer version").emit()?;
            if rest.len > 4 {
                cx.emit(Node::new("Metadata").span(rest.tail(4)));
            }
        }
        App::Jps => {
            cx.emit(ident("Identifier"));
            let block = cx.block(rest).await?;
            jps(&mut Fields::emitting(cx, &block, BE), &())?;
        }
        App::Spiff => {
            let block = cx.block(payload.sub(0, 32)).await?;
            spiff(&mut Fields::emitting(cx, &block, BE), &())?;
            if payload.len > 32 {
                cx.emit(Node::new("Data").span(payload.tail(32)));
            }
        }
        App::Jumbf => jumbf_segment(cx, input, payload).await?,
        App::Ducky => {
            cx.emit(ident("Identifier"));
            ducky(cx, rest).await?;
        }
        App::PictureInfo => {
            let bytes = cx.read(payload).await?;
            cx.emit(
                Node::new("Text")
                    .span(payload)
                    .value(text(crate::text::latin1(&bytes))),
            );
        }
        App::Photoshop => {
            cx.emit(ident("Identifier"));
            photoshop_segment(cx, input, rest).await?;
        }
        App::Adobe => {
            cx.emit(struct_node("Adobe", payload, BE, (), adobe).summary("DCT colour transform"));
        }
        App::Other => {
            if id_len > 0 {
                cx.emit(ident("Identifier"));
            }
            cx.emit(Node::new("Data").span(rest));
        }
    }
    Ok(())
}

/// JFIF APP0 fields; returns the thumbnail dimensions.
fn jfif(f: &mut Fields<'_>, _: &()) -> Result<(u8, u8)> {
    f.ascii("Identifier", 5).emit()?;
    let major = f.u8("Major version").emit()?;
    f.u8("Minor version")
        .with(|&minor, n| n.summary(format!("version {major}.{minor:02}")))
        .emit()?;
    f.u8("Density units").enumeration(DENSITY_UNITS).emit()?;
    f.u16("X density").emit()?;
    f.u16("Y density").emit()?;
    let w = f.u8("Thumbnail width").emit()?;
    let h = f.u8("Thumbnail height").emit()?;
    Ok((w, h))
}

fn adobe(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Identifier", 5).emit()?;
    f.u16("Version")
        .desc("DCTEncode version (100 or 101)")
        .emit()?;
    f.u16("Flags 0").flags(ADOBE_FLAGS0).emit()?;
    f.u16("Flags 1").hex().emit()?;
    f.u8("Color transform")
        .enumeration(ADOBE_TRANSFORM)
        .desc("Colour conversion applied before DCT coding")
        .emit()?;
    Ok(())
}

fn spiff(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Identifier", 6).emit()?;
    f.u8("Major version").emit()?;
    f.u8("Minor version").emit()?;
    f.u8("Profile").enumeration(SPIFF_PROFILES).emit()?;
    f.u8("Components").emit()?;
    f.u32("Height").emit()?;
    f.u32("Width").emit()?;
    f.u8("Color space").enumeration(SPIFF_COLOR_SPACES).emit()?;
    f.u8("Bits per sample").emit()?;
    f.u8("Compression").enumeration(SPIFF_COMPRESSION).emit()?;
    f.u8("Resolution units").enumeration(DENSITY_UNITS).emit()?;
    f.u32("Vertical resolution").emit()?;
    f.u32("Horizontal resolution").emit()?;
    Ok(())
}

/// JPS (stereo JPEG) APP3 after its identifier.
fn jps(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let len = f.u16("Descriptor block length").emit()?;
    let mut used = 0u64;
    if len >= 4 {
        f.u32("Stereoscopic descriptor")
            .hex()
            .with(|&d, n| n.summary(jps_descriptor(d)))
            .desc("Bits 0–7: media type; 8–15: flags (half height, half width, left field first); 16–23: layout; 24–31: layout-specific")
            .emit()?;
        used = 4;
    }
    f.skip(u64::from(len).saturating_sub(used));
    if f.remaining() >= 2 {
        let n = f.u16("Comment block length").emit()?;
        f.ascii("Comment", n.into()).emit()?;
    }
    Ok(())
}

/// FlashPix-ready APP2 ("FPXR"): a contents list or a piece of a stream.
fn flashpix(cx: &Cx, block: &crate::cx::Block) -> Result<()> {
    let mut f = Fields::emitting(cx, block, BE);
    f.u8("Version").emit()?;
    let kind = f.u8("Segment type").enumeration(FPXR_TYPES).emit()?;
    match kind {
        1 => {
            let count = f.u16("Entries").emit()?;
            for i in 0..count {
                if f.remaining() < 7 {
                    break;
                }
                let start = f.pos();
                let size = f.u32("Entity size").get()?;
                f.skip(1);
                // UTF-16LE name, NUL-terminated.
                let at = to_usize(f.pos());
                let data = block.data.get(at..).unwrap_or_default();
                let (name, consumed, _) = crate::text::utf16z(data, Endian::Little);
                f.skip(to_u64(consumed));
                if size == u32::MAX {
                    f.skip(16);
                }
                let span = block.span.sub(start, f.pos().saturating_sub(start));
                let summary = if size == u32::MAX {
                    "storage".to_owned()
                } else {
                    format!("stream, {}", human_size(size.into()))
                };
                cx.emit(
                    Node::new(format!("Entry {i}"))
                        .span(span)
                        .value(text(name))
                        .summary(summary),
                );
            }
        }
        2 => {
            f.u16("Contents index").emit()?;
            f.u32("Stream offset").hex().emit()?;
            let rest = f.peek_span(f.remaining());
            cx.emit(Node::new("Stream data").span(rest));
        }
        _ => {
            let rest = f.peek_span(f.remaining());
            cx.emit(Node::new("Data").span(rest));
        }
    }
    Ok(())
}

/// Ducky APP12 (Photoshop "Save for Web"): tagged quality and text fields.
async fn ducky(cx: &Cx, rest: Span) -> Result<()> {
    let mut cur = Cursor::new(cx, rest, BE);
    while cur.remaining() >= 2 {
        let start = cur.pos();
        let tag = cur.u16().await?;
        if tag == 0 {
            cx.emit(Node::new("End").span(cur.since(start)));
            break;
        }
        let len = u64::from(cur.u16().await?);
        let data = cur.span(len);
        cur.skip(len);
        let bytes = cx.read_avail(data).await?;
        let (name, value) = match tag {
            1 => ("Quality", u32_be(&bytes, 0).map(uint)),
            2 => (
                "Comment",
                Some(text(crate::text::utf16(
                    bytes.get(4..).unwrap_or_default(),
                    BE,
                ))),
            ),
            3 => (
                "Copyright",
                Some(text(crate::text::utf16(
                    bytes.get(4..).unwrap_or_default(),
                    BE,
                ))),
            ),
            _ => ("Tag", None),
        };
        let mut node = Node::new(name).span(cur.since(start));
        if let Some(v) = value {
            node = node.value(v);
        } else {
            node = node.summary(format!("tag {tag}, {}", human_size(len)));
        }
        cx.emit(node);
    }
    Ok(())
}

async fn icc_segment(cx: &Cx, input: Input, rest: Span, ident: Node) -> Result<()> {
    cx.emit(ident);
    let block = cx.block(rest.sub(0, 2)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let seq = f.u8("Chunk number").desc("1-based").emit()?;
    let count = f.u8("Chunk count").emit()?;
    let data = rest.tail(2);
    if count <= 1 {
        cx.emit(embedded("ICC profile", input.nested(data)));
    } else if seq == 1 {
        match icc_profile(cx, input.span, count).await {
            Ok((profile, problems)) => {
                let mut node = embedded("ICC profile", input.nested(profile))
                    .summary(format!("reassembled from {count} chunks"));
                for d in problems {
                    node = node.diag(d);
                }
                cx.emit(node);
            }
            Err(e) => cx.emit(Node::new("Profile data").span(data).diag(e)),
        }
    } else {
        cx.emit(Node::new("Profile data").span(data).summary(format!(
            "chunk {seq} of {count}; the profile is shown under chunk 1"
        )));
    }
    Ok(())
}

/// Joins the APP2 ICC_PROFILE chunks of the file into one derived source.
async fn icc_profile(cx: &Cx, file: Span, count: u8) -> Result<(Span, Vec<Diagnostic>)> {
    let segments = header_segments(cx, file).await;
    // Chunks by sequence number, in file order.
    let mut chunks: Vec<Vec<Span>> = vec![Vec::new(); 256];
    for seg in segments.iter().filter(|s| s.marker == 0xe2) {
        let head = cx.read_avail(seg.payload().sub(0, 14)).await?;
        if head.starts_with(ICC)
            && let Some(&seq) = head.get(12)
            && let Some(list) = chunks.get_mut(usize::from(seq))
        {
            list.push(seg.payload().tail(14));
        }
    }
    let mut problems = Vec::new();
    let mut parts = Vec::new();
    for seq in 1..=usize::from(count) {
        match chunks.get(seq).map(Vec::as_slice) {
            Some([one]) => parts.push(*one),
            Some([first, ..]) => {
                problems.push(Diagnostic::warning(format!(
                    "ICC profile chunk {seq} appears more than once; the first is used"
                )));
                parts.push(*first);
            }
            _ => {
                return Err(Diagnostic::malformed(format!(
                    "ICC profile chunk {seq} of {count} is missing"
                )));
            }
        }
    }
    let extra = chunks
        .iter()
        .enumerate()
        .filter(|(seq, list)| (*seq == 0 || *seq > usize::from(count)) && !list.is_empty())
        .count();
    if extra > 0 {
        problems.push(Diagnostic::warning(format!(
            "{extra} ICC profile chunk numbers outside 1–{count}"
        )));
    }
    let parent = parts.first().copied().unwrap_or(file);
    let mut data = Vec::new();
    for span in parts {
        data.extend(cx.read(span).await?);
    }
    Ok((
        super::reassembled(cx, parent, "jpeg-icc-chunks", data)?,
        problems,
    ))
}

async fn extended_xmp_segment(
    cx: &Cx,
    input: Input,
    payload: Span,
    rest: Span,
    ident: Node,
) -> Result<()> {
    cx.emit(ident);
    let block = cx.block(rest.sub(0, 40)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let guid = f
        .ascii("GUID", 32)
        .desc("MD5 digest of the whole extended XMP, as 32 hex digits")
        .emit()?;
    let full = f
        .u32("Full length")
        .desc("Of the whole extended XMP")
        .emit()?;
    let offset = f
        .u32("Offset")
        .hex()
        .desc("Of this portion in the whole")
        .emit()?;
    let portion = rest.tail(40);
    if offset != 0 {
        cx.emit(Node::new("Portion").span(portion).summary(format!(
            "bytes {offset:#x}–{:#x} of {full:#x}; the whole is shown under the portion at offset 0",
            u64::from(offset).saturating_add(portion.len)
        )));
        return Ok(());
    }
    cx.emit(
        Node::new("Portion")
            .span(portion)
            .summary(format!("bytes 0–{:#x} of {full:#x}", portion.len)),
    );
    match extended_xmp(cx, input.span, guid.as_bytes(), full).await {
        Ok((whole, chunks, problems)) => {
            let mut node = embedded("Extended XMP", input.nested(whole)).summary(format!(
                "{}, reassembled from {chunks} portions",
                human_size(whole.len)
            ));
            for d in problems {
                node = node.diag(d);
            }
            cx.emit(node);
        }
        Err(e) => cx.emit(Node::new("Extended XMP").span(payload).diag(e)),
    }
    Ok(())
}

/// Joins the extended XMP portions with this GUID, in offset order.
async fn extended_xmp(
    cx: &Cx,
    file: Span,
    guid: &[u8],
    full: u32,
) -> Result<(Span, usize, Vec<Diagnostic>)> {
    let segments = header_segments(cx, file).await;
    let id_len = to_u64(XMP_EXTENSION.len());
    let mut portions = Vec::new();
    for seg in segments.iter().filter(|s| s.marker == 0xe1) {
        let payload = seg.payload();
        let head = cx
            .read_avail(payload.sub(0, id_len.saturating_add(40)))
            .await?;
        let at = XMP_EXTENSION.len();
        if head.starts_with(XMP_EXTENSION)
            && head.get(at..at.saturating_add(32)) == Some(guid)
            && let Some(offset) = u32_be(&head, at.saturating_add(36))
        {
            portions.push((offset, payload.tail(id_len.saturating_add(40))));
        }
    }
    portions.sort_by_key(|&(offset, _)| offset);
    let mut problems = Vec::new();
    let mut data = Vec::new();
    for &(offset, span) in &portions {
        if u64::from(offset) != to_u64(data.len()) {
            problems.push(Diagnostic::malformed(format!(
                "extended XMP portion at {offset:#x} does not follow the previous one (ends at {:#x})",
                data.len()
            )));
            break;
        }
        data.extend(cx.read(span).await?);
    }
    if to_u64(data.len()) != u64::from(full) && problems.is_empty() {
        problems.push(Diagnostic::warning(format!(
            "portions add up to {:#x} bytes, not the declared {full:#x}",
            data.len()
        )));
    }
    let parent = portions.first().map_or(file, |p| p.1);
    let n = portions.len();
    let span = if n == 1 {
        parent
    } else {
        super::reassembled(cx, parent, "jpeg-extended-xmp", data)?
    };
    Ok((span, n, problems))
}

async fn jumbf_segment(cx: &Cx, input: Input, payload: Span) -> Result<()> {
    let block = cx.block(payload.sub(0, 8)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.ascii("Common identifier", 2)
        .desc("\"JP\": JPEG systems (ISO 19566-5)")
        .emit()?;
    let en = f.u16("Box instance").emit()?;
    let z = f.u32("Packet sequence").desc("1-based").emit()?;
    let body = payload.tail(8);
    if z != 1 {
        cx.emit(Node::new("Box continuation").span(body).summary(format!(
            "packet {z} of box {en}; the box is shown under packet 1"
        )));
        return Ok(());
    }
    match jumbf_box(cx, input.span, en).await {
        Ok((span, packets)) => {
            let mut node = Node::new("JUMBF").span(span).lazy(
                crate::expander!(self::jumbf_boxes: Boxes),
                Boxes {
                    input: input.nested(span),
                    span,
                    depth: 0,
                },
            );
            if packets > 1 {
                node = node.summary(format!(
                    "{}, reassembled from {packets} packets",
                    human_size(span.len)
                ));
            }
            cx.emit(node);
        }
        Err(e) => cx.emit(Node::new("JUMBF").span(body).diag(e)),
    }
    Ok(())
}

/// Joins the APP11 packets of JUMBF box instance `en`, in sequence order.
/// Every packet after the first repeats the box header, which is dropped.
async fn jumbf_box(cx: &Cx, file: Span, en: u16) -> Result<(Span, usize)> {
    let segments = header_segments(cx, file).await;
    let mut packets = Vec::new();
    for seg in segments.iter().filter(|s| s.marker == 0xeb) {
        let payload = seg.payload();
        let head = cx.read_avail(payload.sub(0, 16)).await?;
        if head.starts_with(b"JP")
            && u16_be(&head, 2) == Some(en)
            && let Some(z) = u32_be(&head, 4)
        {
            let header = if u32_be(&head, 8) == Some(1) { 16 } else { 8 };
            packets.push((z, payload.tail(8), header));
        }
    }
    packets.sort_by_key(|&(z, _, _)| z);
    let first = packets
        .first()
        .map(|p| p.1)
        .ok_or_else(|| Diagnostic::malformed("JUMBF packet missing"))?;
    if packets.len() == 1 {
        return Ok((first, 1));
    }
    let mut data = Vec::new();
    for (i, &(_, span, header)) in packets.iter().enumerate() {
        let part = if i == 0 { span } else { span.tail(header) };
        data.extend(cx.read(part).await?);
    }
    let n = packets.len();
    Ok((
        super::reassembled(cx, first, "jpeg-jumbf-packets", data)?,
        n,
    ))
}

#[derive(Clone, Copy, Debug)]
struct Boxes {
    input: Input,
    span: Span,
    depth: u8,
}

fn box_name(kind: &[u8; 4]) -> &'static str {
    match kind {
        b"jumb" => "superbox",
        b"jumd" => "description",
        b"json" => "JSON",
        b"cbor" => "CBOR",
        b"xml " => "XML",
        b"uuid" => "UUID content",
        b"bfdb" => "embedded file description",
        b"bidb" => "binary data",
        b"c2sh" => "C2PA salt hash",
        _ => "box",
    }
}

/// Lists ISO BMFF-style boxes (JUMBF) in `span`.
async fn jumbf_boxes(cx: Cx, st: Boxes) -> Result<()> {
    let span = st.span;
    let mut pos = 0u64;
    while pos.saturating_add(8) <= span.len {
        let h = cx.read_avail(span.sub(pos, 16)).await?;
        let lbox = u32_be(&h, 0).unwrap_or(0);
        let kind = crate::bytes::array::<4>(&h, 4).unwrap_or_default();
        let (header, size) = match lbox {
            0 => (8, span.len.saturating_sub(pos)),
            1 => (16, u64_be(&h, 8).unwrap_or(0)),
            n => (8, u64::from(n)),
        };
        if size < header {
            cx.push(
                Node::new("Box")
                    .span(span.sub(pos, 8))
                    .diag(Diagnostic::malformed(format!(
                        "box size {size} is too small"
                    ))),
            )
            .await;
            return Ok(());
        }
        let whole = span.sub(pos, size);
        let body = whole.tail(header);
        let name = format!("'{}' {}", crate::text::latin1(&kind), box_name(&kind));
        let mut node = match &kind {
            b"jumb" => {
                let peek = cx.read_avail(body.sub(0, 160)).await?;
                let mut node = Node::new(name).span(whole);
                if peek.get(4..8) == Some(b"jumd".as_slice()) {
                    let uuid = uuid_text(peek.get(8..24).unwrap_or_default());
                    let toggles = peek.get(24).copied().unwrap_or(0);
                    let label = (toggles & 2 != 0)
                        .then(|| crate::text::until_nul(peek.get(25..).unwrap_or_default()));
                    node = node.summary(match label {
                        Some(l) => format!("{uuid} \"{l}\""),
                        None => uuid,
                    });
                }
                if st.depth < MAX_BOX_DEPTH {
                    node.lazy(
                        crate::expander!(self::jumbf_boxes: Boxes),
                        Boxes {
                            input: st.input,
                            span: body,
                            depth: st.depth.saturating_add(1),
                        },
                    )
                } else {
                    node.diag(Diagnostic::limit("JUMBF boxes nested too deeply"))
                }
            }
            b"jumd" => struct_node(name, whole, BE, header, jumbf_description),
            b"json" => embedded_as(
                name,
                st.input.nested(body),
                &crate::formats::text::json::FORMAT,
            ),
            b"cbor" => embedded_as(
                name,
                st.input.nested(body),
                &crate::formats::data::cbor::FORMAT,
            ),
            b"xml " | b"bidb" => embedded(name, st.input.nested(body)),
            b"uuid" => {
                let uuid = cx.read_avail(body.sub(0, 16)).await?;
                Node::new(name)
                    .span(whole)
                    .summary(uuid_text(&uuid))
                    .lazy(uuid_box, (st.input, body))
            }
            _ => Node::new(name).span(whole).summary(human_size(body.len)),
        };
        if whole.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(whole.source, whole.offset, size),
                whole.len,
            ));
        }
        cx.push(node).await;
        if whole.len < size {
            return Ok(());
        }
        pos = pos.saturating_add(size);
    }
    if pos < span.len {
        cx.push(Node::new("Data").span(span.tail(pos))).await;
    }
    Ok(())
}

fn jumbf_description(f: &mut Fields<'_>, header: &u64) -> Result<()> {
    f.u32("Box length").emit()?;
    f.ascii("Box type", 4).emit()?;
    if *header == 16 {
        f.u64("Extended length").emit()?;
    }
    f.bytes("Content type", 16)
        .with(|u, n| n.summary(uuid_text(u)))
        .emit()?;
    let toggles = f.u8("Toggles").flags(JUMD_TOGGLES).emit()?;
    if toggles & 2 != 0 {
        f.cstr("Label").emit()?;
    }
    if toggles & 4 != 0 {
        f.u32("ID").emit()?;
    }
    if toggles & 8 != 0 {
        f.bytes("Signature", 32)
            .desc("SHA-256 of the superbox's content boxes")
            .emit()?;
    }
    if toggles & 16 != 0 && f.remaining() > 0 {
        let rest = f.peek_span(f.remaining());
        f.node(Node::new("Private box").span(rest));
    }
    Ok(())
}

async fn uuid_box(cx: Cx, (input, body): (Input, Span)) -> Result<()> {
    let uuid = cx.read_avail(body.sub(0, 16)).await?;
    cx.emit(
        Node::new("UUID")
            .span(body.sub(0, 16))
            .value(text(uuid_text(&uuid))),
    );
    if body.len > 16 {
        cx.emit(embedded("Data", input.nested(body.tail(16))));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Segment expansion

/// UTF-8 if the bytes are (possibly cut short in a character), else
/// ISO 8859-1.
fn decode_text(bytes: &[u8]) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(e) if e.error_len().is_none() => {
            String::from_utf8_lossy(bytes.get(..e.valid_up_to()).unwrap_or_default()).into_owned()
        }
        Err(_) => crate::text::latin1(bytes),
    }
}

async fn emit_fields<C, R>(cx: &Cx, span: Span, ctx: C, layout: Layout<C, R>) -> Result<R>
where
    C: Send + Sync,
{
    let block = cx.block(span).await?;
    layout(&mut Fields::emitting(cx, &block, BE), &ctx)
}

async fn segment(cx: Cx, st: SegState) -> Result<()> {
    let seg = st.seg;
    if seg.fill > 0 {
        cx.emit(
            Node::new("Fill bytes")
                .span(seg.span.sub(0, seg.fill))
                .summary(format!("{} × 0xff", seg.fill))
                .desc("Optional 0xFF padding before a marker"),
        );
    }
    let head = seg
        .span
        .sub(seg.fill, if standalone(seg.marker) { 2 } else { 4 });
    let block = cx.block(head).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Marker")
        .hex()
        .with(|_, n| n.summary(marker_name(seg.marker)))
        .emit()?;
    if standalone(seg.marker) {
        return Ok(());
    }
    f.u16("Length")
        .desc("Of the segment, including these two bytes")
        .emit()?;
    let payload = seg.payload();
    match seg.marker {
        m if is_sof(m) || m == 0xde => {
            emit_fields(&cx, payload, st.comps, frame_header).await?;
        }
        0xda => {
            let ctx = ScanCtx {
                comps: st.comps,
                process: st.process,
            };
            emit_fields(&cx, payload, ctx, scan_header).await?;
        }
        0xdb => quantization_tables(&cx, payload).await?,
        0xc4 => huffman_tables(&cx, payload).await?,
        0xcc => {
            emit_fields(&cx, payload, (), conditioning).await?;
        }
        0xdd => {
            let block = cx.block(payload.sub(0, 2)).await?;
            Fields::emitting(&cx, &block, BE)
                .u16("Restart interval")
                .desc("MCUs between restart markers (0: none)")
                .emit()?;
        }
        0xdc => {
            let block = cx.block(payload.sub(0, 2)).await?;
            Fields::emitting(&cx, &block, BE)
                .u16("Number of lines")
                .desc("The image height, when the frame header left it 0")
                .emit()?;
        }
        0xdf => {
            let block = cx.block(payload.sub(0, 1)).await?;
            Fields::emitting(&cx, &block, BE)
                .u8("Expansion")
                .hex()
                .with(|&e, n| n.summary(format!("horizontal {}, vertical {}", e >> 4, e & 15)))
                .desc("Whether the reference components are upsampled 2× before the next frame")
                .emit()?;
        }
        0xf8 => {
            emit_fields(&cx, payload, (), jpeg_ls_parameters).await?;
        }
        0xfe => {
            let bytes = cx.read(payload).await?;
            cx.emit(
                Node::new("Comment")
                    .span(payload)
                    .value(text(decode_text(&bytes).trim_end_matches('\0'))),
            );
        }
        0xe0..=0xef => application(&cx, &st).await?,
        _ => cx.emit(Node::new("Data").span(payload)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The walker

/// What the walker learns about the image, for summaries.
#[derive(Clone, Debug, Default)]
struct Info {
    /// The first frame header (SOFn).
    frame: Option<Frame>,
    /// The hierarchical image's frame header (DHP).
    dhp: Option<Frame>,
    /// The latest frame's marker: the process of the scans that follow.
    process: u8,
    frames: u64,
    comps: Comps,
    jfif: bool,
    adobe: Option<u8>,
    /// The camera and date of the first Exif block.
    exif: Option<(Option<String>, Option<String>)>,
    scans: u64,
    dnl: Option<u16>,
    quality: Option<u32>,
    mpf: Option<Vec<MpImage>>,
    c2pa: bool,
}

impl Info {
    /// The file's summary, unless there is nothing to say (a fragment
    /// without a frame header keeps whatever its container said).
    fn summary(&self, notes: &[String]) -> Option<String> {
        let mut parts = Vec::new();
        if let Some(frame) = self.dhp.as_ref().or(self.frame.as_ref()) {
            let mut text = describe_frame(frame, self.comps.space, self.dnl);
            if self.dhp.is_some() {
                let process = self
                    .frame
                    .as_ref()
                    .and_then(|f| lookup(FRAME_TYPES, f.marker.into()))
                    .unwrap_or("no frames");
                text = format!("{text} ({} frames, {process})", self.frames);
            }
            parts.push(text);
        }
        if let Some(q) = self.quality {
            parts.push(format!("quality {q}"));
        }
        if self.frame.as_ref().is_some_and(|f| progressive(f.marker)) && self.scans > 0 {
            parts.push(format!("{} scans", self.scans));
        }
        if let Some((camera, date)) = &self.exif {
            parts.extend(camera.clone());
            parts.extend(date.clone());
        }
        if let Some(mpf) = &self.mpf
            && mpf.len() > 1
        {
            parts.push(format!("MPF: {} images", mpf.len()));
        }
        if self.c2pa {
            parts.push("C2PA manifest".to_owned());
        }
        parts.extend(notes.iter().cloned());
        (!parts.is_empty()).then(|| parts.join(", "))
    }

    fn stuffing(&self) -> Stuffing {
        if self.process == 0xf7 {
            Stuffing::Ls
        } else {
            Stuffing::Dct
        }
    }
}

/// Learns what a segment says about the image and returns its summary.
async fn observe(cx: &Cx, input: Input, seg: &Segment, info: &mut Info) -> Option<String> {
    let payload = seg.payload();
    let m = seg.marker;
    match m {
        _ if is_sof(m) || m == 0xde => {
            let block = cx.block(payload).await.ok()?;
            let mut frame = frame_header(&mut Fields::new(&block, BE), &Comps::default()).ok()?;
            frame.marker = m;
            info.comps = Comps::new(&frame, info.adobe, info.jfif);
            let summary = describe_frame(&frame, info.comps.space, None);
            if m == 0xde {
                if info.dhp.is_none() {
                    info.dhp = Some(frame);
                }
            } else {
                info.frames = info.frames.saturating_add(1);
                info.process = m;
                if info.frame.is_none() {
                    info.frame = Some(frame);
                }
            }
            Some(summary)
        }
        0xda => {
            let block = cx.block(payload).await.ok()?;
            let ctx = ScanCtx {
                comps: info.comps,
                process: info.process,
            };
            let scan = scan_header(&mut Fields::new(&block, BE), &ctx).ok()?;
            Some(scan_summary(&scan, &ctx))
        }
        0xdb => {
            let data = cx.read_avail(payload).await.ok()?;
            let (tables, _) = parse_dqt(&data);
            if info.quality.is_none() {
                info.quality = tables
                    .iter()
                    .find(|t| t.dest == 0)
                    .and_then(|t| t.quality)
                    .map(|q| q.0);
            }
            Some(dqt_summary(&tables))
        }
        0xc4 => {
            let data = cx.read_avail(payload).await.ok()?;
            Some(dht_summary(&parse_dht(&data).0))
        }
        0xcc => Some(format!(
            "{} conditioning entries",
            payload.len.checked_div(2).unwrap_or(0)
        )),
        0xdd => {
            let b = cx.read_avail(payload.sub(0, 2)).await.ok()?;
            let n = u16_be(&b, 0)?;
            Some(match n {
                0 => "no restart markers".to_owned(),
                1 => "restart after every MCU".to_owned(),
                n => format!("restart every {n} MCUs"),
            })
        }
        0xdc => {
            let b = cx.read_avail(payload.sub(0, 2)).await.ok()?;
            let n = u16_be(&b, 0)?;
            if info.dnl.is_none() {
                info.dnl = Some(n);
            }
            Some(format!("{n} lines"))
        }
        0xdf => {
            let b = cx.read_avail(payload.sub(0, 1)).await.ok()?;
            let e = *b.first()?;
            Some(match (e >> 4 != 0, e & 15 != 0) {
                (true, true) => "expand 2× both ways".to_owned(),
                (true, false) => "expand 2× horizontally".to_owned(),
                (false, true) => "expand 2× vertically".to_owned(),
                (false, false) => "no expansion".to_owned(),
            })
        }
        0xf8 => {
            let b = cx.read_avail(payload.sub(0, 1)).await.ok()?;
            lookup(LSE_IDS, (*b.first()?).into()).map(str::to_owned)
        }
        0xfe => {
            let bytes = cx.read_avail(payload.sub(0, 160)).await.ok()?;
            let comment = decode_text(&bytes);
            let line = comment.lines().next().unwrap_or_default();
            let line = line.trim_end_matches('\0');
            Some(line.chars().take(80).collect())
        }
        0xe0..=0xef => observe_app(cx, input, seg, info).await,
        _ => None,
    }
}

async fn observe_app(cx: &Cx, input: Input, seg: &Segment, info: &mut Info) -> Option<String> {
    let payload = seg.payload();
    let head = cx.read_avail(payload.sub(0, 80)).await.ok()?;
    let (kind, id_len) = app_kind(seg.marker, &head);
    let rest = payload.tail(id_len);
    let at = |i: usize| head.get(i).copied().unwrap_or(0);
    Some(match kind {
        App::Jfif => {
            info.jfif = true;
            jfif_summary(&head)
        }
        App::Jfxx => format!(
            "JFXX: {}",
            lookup(JFXX_CODES, at(5).into()).unwrap_or("thumbnail")
        ),
        App::Avi1 => "AVI1 (Motion JPEG)".to_owned(),
        App::Exif => {
            let shot = super::tiff::exif_shot(cx, input.nested(rest)).await;
            let described = shot.as_ref().map(|s| s.describe(true)).unwrap_or_default();
            if info.exif.is_none()
                && let Some(s) = &shot
            {
                info.exif = Some((s.camera().map(str::to_owned), s.date().map(str::to_owned)));
            }
            if described.is_empty() {
                "Exif".to_owned()
            } else {
                format!("Exif: {described}")
            }
        }
        App::Meta => "Kodak Meta (TIFF)".to_owned(),
        App::Xmp => format!("XMP, {}", human_size(rest.len)),
        App::XmpExt => {
            let id = XMP_EXTENSION.len();
            let full = u32_be(&head, id.saturating_add(32)).unwrap_or(0);
            let offset = u32_be(&head, id.saturating_add(36)).unwrap_or(0);
            format!(
                "Extended XMP, bytes {offset:#x}–{:#x} of {}",
                u64::from(offset).saturating_add(rest.len.saturating_sub(40)),
                human_size(full.into())
            )
        }
        App::Icc => format!("ICC profile, chunk {} of {}", at(12), at(13)),
        App::Mpf => {
            let data = cx.read_avail(rest).await.ok()?;
            let entries = parse_mpf(&data).map(|m| m.1).unwrap_or_default();
            if info.mpf.is_none() {
                let images = entries
                    .iter()
                    .enumerate()
                    .map(|(i, e)| MpImage {
                        index: i.saturating_add(1),
                        attribute: e.attribute,
                        at: mp_image_at(input.span, rest, e),
                        len: u64::from(e.size),
                    })
                    .collect();
                info.mpf = Some(images);
            }
            if entries.is_empty() {
                "MPF attributes".to_owned()
            } else {
                format!("MPF, {} images", entries.len())
            }
        }
        App::Fpxr => format!(
            "FlashPix ready: {}",
            lookup(FPXR_TYPES, at(6).into()).unwrap_or("unknown segment type")
        ),
        App::GainMap => "ISO 21496-1 gain map metadata".to_owned(),
        App::Jps => match (u16_be(&head, 8), u32_be(&head, 10)) {
            (Some(len), Some(d)) if len >= 4 => format!("JPS: {}", jps_descriptor(d)),
            _ => "JPS".to_owned(),
        },
        App::Spiff => format!("SPIFF {}.{}", at(6), at(7)),
        App::Jumbf => {
            let s = jumbf_summary(&head);
            if s.contains("C2PA") {
                info.c2pa = true;
            }
            s
        }
        App::Ducky => ducky_summary(&head),
        App::PictureInfo => "PictureInfo".to_owned(),
        App::Photoshop => match irb_group(cx, input.span, rest).await {
            Some((g, index)) => irb_summary(&g, index),
            None => "Photoshop 3.0".to_owned(),
        },
        App::Adobe => {
            info.adobe = head.get(11).copied();
            format!(
                "Adobe, transform: {}",
                lookup(ADOBE_TRANSFORM, at(11).into()).unwrap_or("unknown")
            )
        }
        App::Other if id_len > 0 => id_text(&head, id_len),
        App::Other => human_size(payload.len),
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut info = Info::default();
    let mut eoi = false;
    let mut annotated = false;
    while !cur.at_end() {
        let seg = match next_segment(&mut cur).await {
            Ok(Some(seg)) => seg,
            Ok(None) => {
                // libjpeg skips such bytes with a warning.
                let start = cur.pos();
                let end = scan_entropy(&cx, file, start.saturating_add(1), Stuffing::None)
                    .await?
                    .end;
                let span = file.sub(start, end.saturating_sub(start));
                cx.push(
                    Node::new("Extraneous data")
                        .span(span)
                        .summary(human_size(span.len))
                        .diag(Diagnostic::warning("bytes that are not a marker segment").at(span)),
                )
                .await;
                cur.seek(end);
                continue;
            }
            Err(e) => {
                let rest = file.tail(cur.pos());
                cx.push(Node::new("Truncated segment").span(rest).diag(e))
                    .await;
                cur.seek(file.len);
                break;
            }
        };
        let summary = observe(&cx, input, &seg, &mut info).await;
        let mut node = Node::new(marker_name(seg.marker)).span(seg.span);
        if let Some(s) = summary {
            node = node.summary(s);
        }
        if let Some(d) = seg.problem() {
            node = node.diag(d);
        }
        if !standalone(seg.marker) || seg.fill > 0 {
            node = node.lazy(
                segment,
                SegState {
                    input,
                    seg,
                    comps: info.comps,
                    process: info.process,
                },
            );
        }
        if is_sof(seg.marker) && !annotated {
            annotated = true;
            if let Some(s) = info.summary(&[]) {
                cx.annotate(s);
            }
        }
        cx.push(node).await;
        if seg.marker == 0xd9 {
            eoi = true;
            break;
        }
        if seg.marker == 0xda {
            let start = cur.pos();
            let scan = scan_entropy(&cx, file, start, info.stuffing()).await?;
            let data = file.sub(start, scan.end.saturating_sub(start));
            info.scans = info.scans.saturating_add(1);
            let mut summary = format!("scan {}, {}", info.scans, human_size(data.len));
            if scan.restarts > 0 {
                summary = format!(
                    "{summary}, {} restart intervals",
                    scan.restarts.saturating_add(1)
                );
            }
            let mut node = Node::new("Entropy-coded data").span(data).summary(summary);
            if scan.restarts > 0 {
                node = node.lazy(restart_intervals, (data, info.stuffing()));
            }
            if let Some((at, found, expected)) = scan.out_of_order {
                node = node.diag(
                    Diagnostic::warning(format!(
                        "{} where {} was expected",
                        marker_name(found),
                        marker_name(expected)
                    ))
                    .at(file.sub(at, 2)),
                );
            }
            cx.push(node).await;
            cur.seek(scan.end);
        }
    }
    if !eoi {
        cx.diag(Diagnostic::warning("no EOI marker"));
    }
    let mut notes = Vec::new();
    if !cur.at_end() {
        trailer(&cx, input, cur.pos(), &info, &mut notes).await?;
    }
    if let Some(s) = info.summary(&notes) {
        cx.annotate(s);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Data after EOI

/// The end (relative to `region`) of a JPEG stream starting at its start.
async fn jpeg_end(cx: &Cx, region: Span) -> Result<Option<u64>> {
    let mut cur = Cursor::new(cx, region, BE);
    let mut stuffing = Stuffing::Dct;
    while let Some(seg) = next_segment(&mut cur).await? {
        match seg.marker {
            0xd9 => return Ok(Some(cur.pos())),
            0xf7 => stuffing = Stuffing::Ls,
            0xda => {
                let scan = scan_entropy(cx, region, cur.pos(), stuffing).await?;
                cur.seek(scan.end);
            }
            _ => {}
        }
        if cur.at_end() {
            break;
        }
    }
    Ok(None)
}

/// Box types found at the top level of MP4/QuickTime files.
const BMFF_TOP_LEVEL: &[&[u8; 4]] = &[
    b"ftyp", b"moov", b"mdat", b"free", b"skip", b"wide", b"uuid", b"meta", b"moof", b"mfra",
    b"sidx", b"ssix", b"styp", b"pdin", b"emsg", b"prft", b"udta", b"junk", b"pnot",
];

/// The end (relative to `region`) of a run of ISO BMFF top-level boxes.
async fn bmff_end(cx: &Cx, region: Span) -> u64 {
    let mut pos = 0u64;
    for _ in 0..4096 {
        if pos >= region.len {
            return region.len;
        }
        let Ok(h) = cx.read_avail(region.sub(pos, 16)).await else {
            return pos;
        };
        let (Some(size), Some(kind)) = (u32_be(&h, 0), h.get(4..8)) else {
            return pos;
        };
        if !BMFF_TOP_LEVEL.iter().any(|t| t.as_slice() == kind) {
            return pos;
        }
        let size = match size {
            0 => region.len.saturating_sub(pos),
            1 => u64_be(&h, 8).unwrap_or(0),
            n => u64::from(n),
        };
        if size < 8 {
            return pos;
        }
        pos = pos.saturating_add(size);
    }
    pos.min(region.len)
}

fn looks_like_jpeg(b: &[u8]) -> bool {
    b.starts_with(&[0xff, 0xd8, 0xff])
        && b.get(3)
            .is_some_and(|&m| matches!(m, 0xc0..=0xcf | 0xdb..=0xfe) && m != 0xc8)
}

fn looks_like_bmff(b: &[u8]) -> bool {
    b.get(4..8) == Some(b"ftyp".as_slice())
        && u32_be(b, 0).is_some_and(|s| (12..=1024).contains(&s))
        && b.get(8..12).is_some_and(|brand| {
            brand
                .iter()
                .all(|&c| c.is_ascii_alphanumeric() || c == b' ')
        })
}

/// The next appended JPEG or MP4 within the first 64 KiB from `from`.
async fn find_embedded(cx: &Cx, file: Span, from: u64) -> Result<Option<u64>> {
    let data = cx.read_avail(file.sub(from, TRAILER_SEARCH)).await?;
    cx.checkpoint().await;
    let mut i = 0usize;
    while let Some(off) = data
        .get(i..)
        .and_then(|d| d.iter().position(|&b| b == 0xff || b == b'f'))
    {
        let at = i.saturating_add(off);
        let rest = data.get(at..).unwrap_or_default();
        if looks_like_jpeg(rest) {
            return Ok(Some(from.saturating_add(to_u64(at))));
        }
        if at >= 4
            && let Some(b) = data.get(at.saturating_sub(4)..)
            && looks_like_bmff(b)
        {
            return Ok(Some(from.saturating_add(to_u64(at)).saturating_sub(4)));
        }
        i = at.saturating_add(1);
    }
    Ok(None)
}

/// Splits the data after EOI into MPF images, appended JPEGs, MP4 movies
/// and the rest.
async fn trailer(
    cx: &Cx,
    input: Input,
    start: u64,
    info: &Info,
    notes: &mut Vec<String>,
) -> Result<()> {
    let file = input.span;
    let mpf = info.mpf.as_deref().unwrap_or_default();
    let mut pos = start;
    let mut unknown = 0u64;
    let mut jpegs = 0u64;
    for _ in 0..MAX_TRAILER_ITEMS {
        if pos >= file.len {
            break;
        }
        if let Some(img) = mpf.iter().find(|m| m.at == pos && m.len > 0) {
            let span = file.sub(pos, img.len);
            cx.push(
                embedded(format!("MPF image {}", img.index), input.nested(span)).summary(format!(
                    "{}, {}",
                    mp_attribute(img.attribute),
                    human_size(span.len)
                )),
            )
            .await;
            pos = pos.saturating_add(span.len);
            continue;
        }
        let head = cx.read_avail(file.sub(pos, 16)).await?;
        if looks_like_jpeg(&head) {
            let region = file.tail(pos);
            let end = match jpeg_end(cx, region).await {
                Ok(Some(end)) if end > 0 => end,
                _ => region.len,
            };
            let span = region.sub(0, end);
            cx.push(embedded("Embedded JPEG", input.nested(span)).summary(human_size(span.len)))
                .await;
            jpegs = jpegs.saturating_add(1);
            pos = pos.saturating_add(span.len);
            continue;
        }
        if looks_like_bmff(&head) {
            let region = file.tail(pos);
            let end = bmff_end(cx, region).await;
            if end > 0 {
                let span = region.sub(0, end);
                cx.push(
                    embedded("Embedded video", input.nested(span)).summary(format!(
                        "{}, appended movie (motion photo)",
                        human_size(span.len)
                    )),
                )
                .await;
                notes.push("MP4 trailer (motion photo)".to_owned());
                pos = pos.saturating_add(span.len);
                continue;
            }
        }
        // Anything else runs up to the next recognisable item.
        let next_mpf = mpf.iter().map(|m| m.at).filter(|&a| a > pos).min();
        let found = find_embedded(cx, file, pos.saturating_add(1)).await?;
        let end = next_mpf
            .into_iter()
            .chain(found)
            .min()
            .unwrap_or(file.len)
            .min(file.len);
        let span = file.sub(pos, end.saturating_sub(pos));
        let last = cx
            .read_avail(span.sub(span.len.saturating_sub(4), 4))
            .await?;
        let name = if last == b"SEFT" {
            "Samsung trailer"
        } else {
            "Trailing data"
        };
        cx.push(
            embedded(name, input.nested(span))
                .summary(format!("{} after EOI", human_size(span.len))),
        )
        .await;
        unknown = unknown.saturating_add(span.len);
        pos = end.max(pos.saturating_add(1));
    }
    if pos < file.len {
        let span = file.tail(pos);
        cx.push(
            embedded("Trailing data", input.nested(span))
                .summary(format!("{} after EOI", human_size(span.len))),
        )
        .await;
        unknown = unknown.saturating_add(span.len);
    }
    if jpegs > 0 {
        notes.push(if jpegs == 1 {
            "JPEG appended".to_owned()
        } else {
            format!("{jpegs} JPEGs appended")
        });
    }
    if unknown > 0 {
        notes.push(format!("{} after EOI", human_size(unknown)));
    }
    Ok(())
}
