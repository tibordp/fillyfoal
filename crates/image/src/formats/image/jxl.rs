//! JPEG XL: bare codestreams (`FF 0A`) and the ISO BMFF-style container
//! (`JXL ` signature box, then `ftyp`, `jxll`, `jxlc` or `jxlp`, `Exif`,
//! `xml `, `jbrd`, `brob` ... boxes).
//!
//! Of the codestream the headers are decoded: the size header and the image
//! metadata (orientation, preview, animation, bit depth, extra channels,
//! colour encoding, tone mapping), which are bit-packed bundles read least
//! significant bit first (ISO/IEC 18181-1, as libjxl implements it). The
//! ICC profile, if any, and the frames after them are shown as one region.
//! A codestream split over `jxlp` boxes is joined and dissected whole.

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::sound::Bits;
use crate::formats::util::val::{enumv, text, uint};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

use super::{dims, region};

const BE: Endian = Endian::Big;
const SIGNATURE: &[u8] = b"\0\0\0\x0cJXL \r\n\x87\n";

/// Bytes of a codestream read for its headers. The image metadata is
/// normally a few bytes; extra channel names and extensions can make it
/// longer, never in practice beyond this.
const HEADER_BYTES: u64 = 4096;

pub static FORMAT: Format = Format {
    name: "jxl",
    title: "JPEG XL image",
    extensions: &["jxl"],
    mime: "image/jxl",
    probe: Probe::Magic(&[(0, b"\xff\x0a"), (0, SIGNATURE)]),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 12)).await?;
    if head.starts_with(b"\xff\x0a") {
        codestream(&cx, input.span).await
    } else {
        container(&cx, input).await
    }
}

// ---------------------------------------------------------------------------
// Bundle reader

/// One of the four distributions of a `U32` field.
#[derive(Clone, Copy)]
enum D {
    /// A constant.
    V(u32),
    /// `u(n) + offset`.
    B(u32, u32),
}

/// `U32(Val(0), Val(1), BitsOffset(4, 2), BitsOffset(6, 18))`: enums.
const ENUM: [D; 4] = [D::V(0), D::V(1), D::B(4, 2), D::B(6, 18)];

const COLOUR_SPACES: EnumTable = &[(0, "RGB"), (1, "Grey"), (2, "XYB"), (3, "Unknown")];
const WHITE_POINTS: EnumTable = &[(1, "D65"), (2, "Custom"), (10, "E"), (11, "DCI")];
const PRIMARIES: EnumTable = &[(1, "sRGB"), (2, "Custom"), (9, "BT.2100"), (11, "P3")];
const TRANSFER: EnumTable = &[
    (1, "BT.709"),
    (2, "Unknown"),
    (8, "Linear"),
    (13, "sRGB"),
    (16, "PQ"),
    (17, "DCI"),
    (18, "HLG"),
];
const INTENTS: EnumTable = &[
    (0, "Perceptual"),
    (1, "Relative"),
    (2, "Saturation"),
    (3, "Absolute"),
];
const EXTRA_CHANNELS: EnumTable = &[
    (0, "Alpha"),
    (1, "Depth"),
    (2, "Spot colour"),
    (3, "Selection mask"),
    (4, "Black"),
    (5, "CFA"),
    (6, "Thermal"),
    (15, "Unknown"),
    (16, "Optional"),
];
const ORIENTATIONS: EnumTable = &[
    (1, "Normal"),
    (2, "Flipped horizontally"),
    (3, "Rotated 180°"),
    (4, "Flipped vertically"),
    (5, "Transposed"),
    (6, "Rotated 90° clockwise"),
    (7, "Transversed"),
    (8, "Rotated 90° counter-clockwise"),
];

/// The nested bundles of the image metadata, each shown as a group.
#[derive(Clone, Copy, Debug)]
enum Bundle {
    Size,
    Preview,
    Animation,
    BitDepth,
    ExtraChannel,
    Colour,
    ToneMapping,
    Metadata,
    /// CustomTransformData; whether the image is XYB-encoded.
    Transform(bool),
    OpsinInverse,
    /// Upsampling weights: how many.
    Weights(u16),
}

/// Reads (and, if emitting, shows) the fields of the codestream headers.
struct Jx<'a> {
    b: Bits<'a>,
}

impl<'a> Jx<'a> {
    fn new(data: &'a [u8], span: Span, cx: Option<&'a Cx>) -> Self {
        let b = match cx {
            Some(cx) => Bits::emitting(cx, data, span),
            None => Bits::new(data, span),
        };
        Jx { b: b.lsb_first() }
    }

    fn silent(&self) -> Jx<'a> {
        Jx { b: self.b.silent() }
    }

    fn pos(&self) -> u64 {
        self.b.pos()
    }

    fn show(&self, name: impl Into<std::borrow::Cow<'static, str>>, start: u64, value: Value) {
        self.b.node(
            Node::new(name)
                .span(self.b.span_of(start, self.pos()))
                .value(value),
        );
    }

    fn bool(&mut self, name: &'static str) -> Option<bool> {
        let start = self.pos();
        let v = self.b.read(1)? == 1;
        self.show(name, start, Value::Bool(v));
        Some(v)
    }

    /// `u(n) + offset`.
    fn bits(&mut self, name: &'static str, n: u32, offset: u64) -> Option<u64> {
        let start = self.pos();
        let v = self.b.read(n)?.checked_add(offset)?;
        self.show(name, start, uint(v, 64));
        Some(v)
    }

    fn u32_raw(&mut self, d: [D; 4]) -> Option<u64> {
        let selector = usize::try_from(self.b.read(2)?).ok()?;
        match *d.get(selector)? {
            D::V(v) => Some(v.into()),
            D::B(n, offset) => self.b.read(n)?.checked_add(offset.into()),
        }
    }

    fn u32(&mut self, name: &'static str, d: [D; 4]) -> Option<u64> {
        let start = self.pos();
        let v = self.u32_raw(d)?;
        self.show(name, start, uint(v, 32));
        Some(v)
    }

    fn enumeration(&mut self, name: &'static str, table: EnumTable) -> Option<u64> {
        let start = self.pos();
        let v = self.u32_raw(ENUM)?;
        self.show(name, start, enumv(v, 32, table));
        Some(v)
    }

    fn u64(&mut self, name: &'static str) -> Option<u64> {
        let start = self.pos();
        let v = match self.b.read(2)? {
            0 => 0,
            1 => self.b.read(4)?.checked_add(1)?,
            2 => self.b.read(8)?.checked_add(17)?,
            _ => {
                let mut v = self.b.read(12)?;
                let mut shift = 12u32;
                while self.b.read(1)? == 1 {
                    if shift >= 60 {
                        v |= self.b.read(4)?.checked_shl(60)?;
                        break;
                    }
                    v |= self.b.read(8)?.checked_shl(shift)?;
                    shift = shift.saturating_add(8);
                }
                v
            }
        };
        self.show(name, start, uint(v, 64));
        Some(v)
    }

    /// A binary16 float.
    fn f16(&mut self, name: impl Into<std::borrow::Cow<'static, str>>) -> Option<f64> {
        let start = self.pos();
        let raw = u16::try_from(self.b.read(16)?).ok()?;
        let v = half(raw);
        self.show(name, start, Value::f16(v));
        Some(v)
    }

    /// Decodes a nested bundle silently for its extent and summary, then
    /// shows it as a group whose fields are decoded on expansion.
    fn nested(
        &mut self,
        name: impl Into<String>,
        kind: Bundle,
        state: (Span, Span),
    ) -> Option<String> {
        let start = self.pos();
        let mut quiet = self.silent();
        let summary = bundle(&mut quiet, kind);
        let end = quiet.pos();
        self.b.seek(end);
        let span = self.b.span_of(start, end);
        let mut node = Node::new(name.into())
            .span(span)
            .lazy(bundle_fields, (state.0, state.1, start, kind));
        match &summary {
            Some(s) => node = node.summary(s.clone()),
            None => {
                node = node.diag(Diagnostic::truncated(span, span.len));
            }
        }
        self.b.node(node);
        summary
    }
}

/// An IEEE 754 binary16 value.
fn half(raw: u16) -> f64 {
    let sign = if raw & 0x8000 != 0 { -1.0 } else { 1.0 };
    let exponent = i32::from((raw >> 10) & 0x1f);
    let mantissa = f64::from(raw & 0x3ff);
    let magnitude = match exponent {
        0 => mantissa * 2f64.powi(-24),
        31 if mantissa == 0.0 => f64::INFINITY,
        31 => f64::NAN,
        e => (1.0 + mantissa / 1024.0) * 2f64.powi(e.saturating_sub(15)),
    };
    sign * magnitude
}

/// The fields of a nested bundle at bit `start` of the codestream header.
async fn bundle_fields(
    cx: Cx,
    (data_span, span, start, kind): (Span, Span, u64, Bundle),
) -> Result<()> {
    let data = cx.read_avail(data_span).await?;
    let mut j = Jx::new(&data, span, Some(&cx));
    j.b.seek(start);
    let _ = bundle(&mut j, kind);
    Ok(())
}

/// Reads one bundle; returns its summary, or `None` if it is truncated.
fn bundle(j: &mut Jx<'_>, kind: Bundle) -> Option<String> {
    match kind {
        Bundle::Size => size_header(j).map(|(w, h)| dims(w, h)),
        Bundle::Preview => preview_header(j),
        Bundle::Animation => animation_header(j),
        Bundle::BitDepth => bit_depth(j),
        Bundle::ExtraChannel => extra_channel(j),
        Bundle::Colour => colour_encoding(j),
        Bundle::ToneMapping => tone_mapping(j),
        Bundle::Metadata => image_metadata(j).map(|m| m.summary),
        Bundle::Transform(xyb) => transform_data(j, xyb),
        Bundle::OpsinInverse => opsin_inverse(j),
        Bundle::Weights(n) => weights(j, n),
    }
}

/// CustomTransformData (ISO/IEC 18181-1 A.6): the inverse opsin matrix of
/// an XYB image and custom upsampling weights.
fn transform_data(j: &mut Jx<'_>, xyb: bool) -> Option<String> {
    let st = state(j);
    if j.bool("All default")? {
        return Some("all default".to_owned());
    }
    let mut parts = Vec::new();
    if xyb {
        let opsin = j.nested("Opsin inverse matrix", Bundle::OpsinInverse, st)?;
        if opsin != "default" {
            parts.push("custom opsin inverse matrix".to_owned());
        }
    }
    let mask = j.bits("Custom weights mask", 3, 0)?;
    for (bit, n, name, label) in [
        (1, 15, "2× upsampling weights", "2×"),
        (2, 55, "4× upsampling weights", "4×"),
        (4, 210, "8× upsampling weights", "8×"),
    ] {
        if mask & bit != 0 {
            j.nested(name, Bundle::Weights(n), st)?;
            parts.push(format!("custom {label} upsampling weights"));
        }
    }
    if parts.is_empty() {
        parts.push("default".to_owned());
    }
    Some(parts.join(", "))
}

/// OpsinInverseMatrix: the inverse matrix, opsin biases and quantisation
/// biases, binary16 each.
fn opsin_inverse(j: &mut Jx<'_>) -> Option<String> {
    if j.bool("All default")? {
        return Some("default".to_owned());
    }
    for row in 0..3 {
        for col in 0..3 {
            j.f16(format!("Inverse matrix [{row}][{col}]"))?;
        }
    }
    for i in 0..3 {
        j.f16(format!("Opsin bias {i}"))?;
    }
    for i in 0..4 {
        j.f16(format!("Quantisation bias {i}"))?;
    }
    Some("custom".to_owned())
}

/// `n` binary16 upsampling weights.
fn weights(j: &mut Jx<'_>, n: u16) -> Option<String> {
    for i in 0..n {
        j.f16(format!("Weight {i}"))?;
    }
    Some(format!("{n} weights"))
}

/// SizeHeader: width and height.
fn size_header(j: &mut Jx<'_>) -> Option<(u64, u64)> {
    let small = j.bool("Small (multiple of 8)")?;
    let size = [D::B(9, 1), D::B(13, 1), D::B(18, 1), D::B(30, 1)];
    let height = if small {
        j.bits("Height / 8 − 1", 5, 0)?
            .checked_add(1)?
            .checked_mul(8)?
    } else {
        j.u32("Height", size)?
    };
    let start = j.pos();
    let ratio = j.b.read(3)?;
    j.show("Aspect ratio", start, enumv(ratio, 3, RATIOS));
    let width = match ratio {
        0 if small => j
            .bits("Width / 8 − 1", 5, 0)?
            .checked_add(1)?
            .checked_mul(8)?,
        0 => j.u32("Width", size)?,
        r => ratio_width(r, height)?,
    };
    Some((width, height))
}

const RATIOS: EnumTable = &[
    (0, "Width given"),
    (1, "1:1"),
    (2, "12:10"),
    (3, "4:3"),
    (4, "3:2"),
    (5, "16:9"),
    (6, "5:4"),
    (7, "2:1"),
];

fn ratio_width(ratio: u64, height: u64) -> Option<u64> {
    Some(match ratio {
        1 => height,
        2 => height.checked_mul(12)? / 10,
        3 => height.checked_mul(4)? / 3,
        4 => height.checked_mul(3)? / 2,
        5 => height.checked_mul(16)? / 9,
        6 => height.checked_mul(5)? / 4,
        _ => height.checked_mul(2)?,
    })
}

fn preview_header(j: &mut Jx<'_>) -> Option<String> {
    let div8 = j.bool("Multiple of 8")?;
    let d8 = [D::V(16), D::V(32), D::B(5, 1), D::B(9, 33)];
    let plain = [D::B(6, 1), D::B(8, 65), D::B(10, 321), D::B(12, 1345)];
    let height = if div8 {
        j.u32("Height / 8", d8)?.checked_mul(8)?
    } else {
        j.u32("Height", plain)?
    };
    let start = j.pos();
    let ratio = j.b.read(3)?;
    j.show("Aspect ratio", start, enumv(ratio, 3, RATIOS));
    let width = match ratio {
        0 if div8 => j.u32("Width / 8", d8)?.checked_mul(8)?,
        0 => j.u32("Width", plain)?,
        r => ratio_width(r, height)?,
    };
    Some(dims(width, height))
}

fn animation_header(j: &mut Jx<'_>) -> Option<String> {
    let num = j.u32(
        "Ticks per second numerator",
        [D::V(100), D::V(1000), D::B(10, 1), D::B(30, 1)],
    )?;
    let den = j.u32(
        "Ticks per second denominator",
        [D::V(1), D::V(1001), D::B(8, 1), D::B(10, 1)],
    )?;
    let loops = j.u32("Loops", [D::V(0), D::B(3, 0), D::B(16, 0), D::B(32, 0)])?;
    let timecodes = j.bool("Has timecodes")?;
    let loops = if loops == 0 {
        "looping forever".to_owned()
    } else {
        format!("{loops} loops")
    };
    let tc = if timecodes { ", timecodes" } else { "" };
    Some(format!("{num}/{den} ticks per second, {loops}{tc}"))
}

fn bit_depth(j: &mut Jx<'_>) -> Option<String> {
    if j.bool("Floating point")? {
        let bits = j.u32(
            "Bits per sample",
            [D::V(32), D::V(16), D::V(24), D::B(6, 1)],
        )?;
        let exponent = j.bits("Exponent bits", 4, 1)?;
        Some(format!("{bits}-bit float ({exponent}-bit exponent)"))
    } else {
        let bits = j.u32("Bits per sample", [D::V(8), D::V(10), D::V(12), D::B(6, 1)])?;
        Some(format!("{bits}-bit"))
    }
}

fn extra_channel(j: &mut Jx<'_>) -> Option<String> {
    if j.bool("All default (8-bit alpha)")? {
        return Some("Alpha, 8-bit".to_owned());
    }
    let kind = j.enumeration("Type", EXTRA_CHANNELS)?;
    let depth = j.nested("Bit depth", Bundle::BitDepth, state(j))?;
    j.u32("Dimension shift", [D::V(0), D::V(3), D::V(4), D::B(3, 1)])?;
    let name_len = j.u32(
        "Name length",
        [D::V(0), D::B(4, 0), D::B(5, 16), D::B(10, 48)],
    )?;
    let mut name = Vec::new();
    if name_len > 0 {
        let start = j.pos();
        for _ in 0..name_len {
            name.push(u8::try_from(j.b.read(8)?).ok()?);
        }
        j.show("Name", start, text(String::from_utf8_lossy(&name)));
    }
    match kind {
        0 => {
            j.bool("Alpha premultiplied")?;
        }
        2 => {
            for c in ["Red", "Green", "Blue", "Solidity"] {
                j.f16(c)?;
            }
        }
        5 => {
            j.u32(
                "CFA channel",
                [D::V(1), D::B(2, 0), D::B(4, 3), D::B(8, 19)],
            )?;
        }
        _ => {}
    }
    let kind = crate::formats::util::val::name_or(EXTRA_CHANNELS, kind, "type");
    let name = if name.is_empty() {
        String::new()
    } else {
        format!(" {:?}", String::from_utf8_lossy(&name))
    };
    Some(format!("{kind}{name}, {depth}"))
}

/// A custom white point or primary (two signed, packed coordinates).
fn customxy(j: &mut Jx<'_>, x: &'static str, y: &'static str) -> Option<()> {
    let d = [
        D::B(19, 0),
        D::B(19, 0x8_0000),
        D::B(20, 0x10_0000),
        D::B(21, 0x20_0000),
    ];
    for name in [x, y] {
        let start = j.pos();
        let raw = j.u32_raw(d)?;
        // UnpackSigned: the low bit is the sign.
        let v = if raw & 1 == 0 {
            i64::try_from(raw >> 1).ok()?
        } else {
            i64::try_from(raw >> 1)
                .ok()?
                .checked_add(1)?
                .checked_neg()?
        };
        j.show(name, start, Value::f64(v as f64 / 1e6));
    }
    Some(())
}

fn colour_encoding(j: &mut Jx<'_>) -> Option<String> {
    if j.bool("All default (sRGB)")? {
        return Some("sRGB".to_owned());
    }
    let icc = j.bool("Has ICC profile")?;
    let space = j.enumeration("Colour space", COLOUR_SPACES)?;
    let space_name = crate::formats::util::val::name_or(COLOUR_SPACES, space, "colour space");
    if icc {
        return Some(format!("{space_name}, ICC profile"));
    }
    let mut parts = vec![space_name];
    if space != 2 {
        let wp = j.enumeration("White point", WHITE_POINTS)?;
        if wp == 2 {
            customxy(j, "White x", "White y")?;
        }
        parts.push(crate::formats::util::val::name_or(
            WHITE_POINTS,
            wp,
            "white point",
        ));
    }
    if space != 1 && space != 2 {
        let p = j.enumeration("Primaries", PRIMARIES)?;
        if p == 2 {
            customxy(j, "Red x", "Red y")?;
            customxy(j, "Green x", "Green y")?;
            customxy(j, "Blue x", "Blue y")?;
        }
        let name = crate::formats::util::val::name_or(PRIMARIES, p, "primaries");
        parts.push(format!("{name} primaries"));
    }
    // The transfer function is implicit for XYB.
    if space != 2 {
        if j.bool("Has gamma")? {
            let start = j.pos();
            let g = j.b.read(24)?;
            j.show("Gamma", start, Value::f64(g as f64 / 1e7));
            parts.push(format!("gamma {}", g as f64 / 1e7));
        } else {
            let tf = j.enumeration("Transfer function", TRANSFER)?;
            let name = crate::formats::util::val::name_or(TRANSFER, tf, "transfer");
            parts.push(format!("{name} transfer"));
        }
    }
    let intent = j.enumeration("Rendering intent", INTENTS)?;
    parts.push(crate::formats::util::val::name_or(INTENTS, intent, "intent").to_lowercase());
    Some(parts.join(", "))
}

fn tone_mapping(j: &mut Jx<'_>) -> Option<String> {
    if j.bool("All default")? {
        return Some("default (255 nits)".to_owned());
    }
    let target = j.f16("Intensity target (nits)")?;
    j.f16("Min nits")?;
    j.bool("Relative to max display")?;
    j.f16("Linear below")?;
    Some(format!("{target} nits"))
}

/// What the image metadata says, for the file's summary.
struct Metadata {
    summary: String,
    icc: bool,
}

fn state(j: &Jx<'_>) -> (Span, Span) {
    // The bundle's lazy node reads the same bytes again: the reader's span
    // is the codestream from its signature.
    let span = j.b.span();
    (span, span)
}

/// ImageMetadata, then the CustomTransformData that follows it.
fn image_metadata(j: &mut Jx<'_>) -> Option<Metadata> {
    let st = state(j);
    if j.bool("All default")? {
        let transform = j.nested("Transform data", Bundle::Transform(true), st)?;
        let mut summary = "all default (8-bit sRGB, XYB)".to_owned();
        if !matches!(transform.as_str(), "all default" | "default") {
            summary = format!("{summary}, {transform}");
        }
        return Some(Metadata {
            summary,
            icc: false,
        });
    }
    let mut parts = Vec::new();
    let extra = j.bool("Has extra fields")?;
    if extra {
        let o = j.bits("Orientation", 3, 1)?;
        if o != 1 {
            parts.push(crate::formats::util::val::name_or(
                ORIENTATIONS,
                o,
                "orientation",
            ));
        }
        if j.bool("Has intrinsic size")? {
            let s = j.nested("Intrinsic size", Bundle::Size, st)?;
            parts.push(format!("intrinsic {s}"));
        }
        if j.bool("Has preview")? {
            let s = j.nested("Preview", Bundle::Preview, st)?;
            parts.push(format!("preview {s}"));
        }
        if j.bool("Has animation")? {
            j.nested("Animation", Bundle::Animation, st)?;
            parts.push("animated".to_owned());
        }
    }
    let depth = j.nested("Bit depth", Bundle::BitDepth, st)?;
    j.bool("16-bit buffers sufficient")?;
    let n = j.u32(
        "Extra channels",
        [D::V(0), D::V(1), D::B(4, 2), D::B(12, 1)],
    )?;
    let mut channels = Vec::new();
    for i in 0..n {
        channels.push(j.nested(format!("Extra channel {i}"), Bundle::ExtraChannel, st)?);
    }
    let xyb = j.bool("XYB encoded")?;
    let colour = j.nested("Colour encoding", Bundle::Colour, st)?;
    if extra {
        j.nested("Tone mapping", Bundle::ToneMapping, st)?;
    }
    let extensions = j.u64("Extensions")?;
    if extensions != 0 {
        // Each extension present gives its length in bits, then its bits.
        let mut total = 0u64;
        for _ in 0..extensions.count_ones() {
            total = total.saturating_add(j.u64("Extension bits")?);
        }
        let start = j.pos();
        j.b.skip(total);
        j.b.node(
            Node::new("Extension data")
                .span(j.b.span_of(start, j.pos()))
                .summary(format!("{total} bits")),
        );
    }
    let transform = j.nested("Transform data", Bundle::Transform(xyb), st)?;
    let icc = colour.contains("ICC profile");
    let mut summary = vec![depth, colour];
    summary.extend(channels.iter().map(|c| format!("+{c}")));
    summary.extend(parts);
    if !xyb {
        summary.push("not XYB (lossless-capable)".to_owned());
    }
    if !matches!(transform.as_str(), "all default" | "default") {
        summary.push(transform);
    }
    Some(Metadata {
        summary: summary.join(", "),
        icc,
    })
}

// ---------------------------------------------------------------------------
// Codestream

/// Width, height and the bit length of the size header, silently.
fn size_header_quick(data: &[u8], span: Span) -> Option<(u64, u64)> {
    let mut j = Jx::new(data, span, None);
    j.b.seek(16);
    size_header(&mut j)
}

async fn codestream(cx: &Cx, span: Span) -> Result<()> {
    let head_span = span.sub(0, HEADER_BYTES);
    let head = cx.read_avail(head_span).await?;
    cx.emit(Node::new("Signature").span(span.sub(0, 2)).summary("FF 0A"));
    let mut j = Jx::new(&head, head_span, None);
    j.b.seek(16);
    let Some((w, h)) = size_header(&mut j) else {
        return Err(Diagnostic::truncated(span.sub(0, 16), to_u64(head.len())));
    };
    let size_end = j.pos();
    cx.emit(
        Node::new("Size header")
            .span(j.b.span_of(16, size_end))
            .summary(dims(w, h))
            .lazy(bundle_fields, (head_span, head_span, 16, Bundle::Size)),
    );
    let meta = image_metadata(&mut j);
    let meta_end = j.pos();
    let mut node = Node::new("Image metadata")
        .span(j.b.span_of(size_end, meta_end))
        .lazy(
            bundle_fields,
            (head_span, head_span, size_end, Bundle::Metadata),
        );
    let rest_at = meta_end.div_ceil(8);
    match &meta {
        Some(m) => {
            node = node.summary(m.summary.clone());
            cx.annotate(format!("{}, {}", dims(w, h), m.summary));
        }
        None => {
            node = node.diag(Diagnostic::truncated(
                j.b.span_of(size_end, meta_end),
                to_u64(head.len()).saturating_sub(size_end / 8),
            ));
            cx.annotate(format!("{}, codestream", dims(w, h)));
        }
    }
    cx.emit(node);
    let rest = if meta.as_ref().is_some_and(|m| m.icc) {
        "ICC profile, frames"
    } else {
        "Frames"
    };
    cx.emit(region(
        rest,
        span,
        rest_at,
        span.len.saturating_sub(rest_at),
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Container

/// Boxes per listing before giving up on a bogus file.
const MAX_BOXES: usize = 4096;

async fn container(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut dims_found = false;
    let mut parts: Vec<Span> = Vec::new();
    for _ in 0..MAX_BOXES {
        if pos >= file.len {
            break;
        }
        let head = cx.read(file.sub(pos, 8)).await?;
        let size = u64::from(u32_be(&head, 0).unwrap_or(0));
        let kind = head.get(4..8).unwrap_or_default().to_vec();
        let (header_len, len) = match size {
            0 => (8, file.len.saturating_sub(pos)),
            1 => {
                let large = cx.read(file.sub(pos.saturating_add(8), 8)).await?;
                (16, u64_be(&large, 0).unwrap_or(0))
            }
            n => (8, n),
        };
        if len < header_len {
            return Err(
                Diagnostic::malformed(format!("box size {len} too small")).at(file.sub(pos, 8))
            );
        }
        let span = file.sub(pos, len);
        let name = crate::text::latin1(&kind);
        let payload = span.tail(header_len);
        let mut node = Node::new(name.clone()).span(span);
        if kind == b"jxlp" {
            parts.push(payload.tail(4));
        }
        if !dims_found && (kind == b"jxlc" || kind == b"jxlp") {
            let offset = if kind == b"jxlp" { 4 } else { 0 };
            let head = cx.read_avail(payload.sub(offset, 16)).await?;
            if let Some((w, h)) = head
                .starts_with(b"\xff\x0a")
                .then(|| size_header_quick(&head, payload.sub(offset, 16)))
                .flatten()
            {
                dims_found = true;
                cx.annotate(format!("{}, container", dims(w, h)));
                node = node.summary(dims(w, h));
            }
        }
        cx.push(node.lazy(jxl_box, (input, span, header_len, kind)))
            .await;
        pos = pos.saturating_add(len);
    }
    if let (Some(first), Some(last)) = (parts.first(), parts.last()) {
        let n = parts.len();
        let parent = Span::new(
            first.source,
            first.offset,
            last.end().saturating_sub(first.offset),
        );
        let joined = cx.add_pieces(
            Origin {
                parent,
                transform: "jxlp",
            },
            parts,
        )?;
        cx.push(
            embedded("Codestream (joined)", input.nested(joined))
                .summary(format!("from {n} jxlp boxes")),
        )
        .await;
    }
    Ok(())
}

async fn jxl_box(
    cx: Cx,
    (input, span, header_len, kind): (Input, Span, u64, Vec<u8>),
) -> Result<()> {
    let block = cx.block(span.sub(0, header_len)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Size")
        .desc("0: to the end of the file; 1: 64-bit size follows")
        .emit()?;
    f.ascii("Type", 4).emit()?;
    if header_len == 16 {
        f.u64("Large size").emit()?;
    }
    let payload = span.tail(header_len);
    match kind.as_slice() {
        b"JXL " => cx.emit(Node::new("Signature").span(payload)),
        b"ftyp" => {
            let block = cx.block(payload).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.ascii("Major brand", 4).emit()?;
            f.u32("Minor version").emit()?;
            let mut brands = 0u32;
            while f.remaining() >= 4 {
                f.ascii("Compatible brand", 4).emit()?;
                brands = brands.wrapping_add(1);
                if brands.is_multiple_of(1024) {
                    cx.checkpoint().await;
                }
            }
        }
        b"jxll" => {
            let block = cx.block(payload.sub(0, 1)).await?;
            Fields::emitting(&cx, &block, BE)
                .u8("Level")
                .desc("5 or 10")
                .emit()?;
        }
        b"jxlc" => cx.emit(embedded("Codestream", input.nested(payload))),
        b"jxlp" => {
            let block = cx.block(payload.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, BE)
                .u32("Index")
                .with(|&i, n| {
                    let last = if i & 0x8000_0000 != 0 { ", last" } else { "" };
                    n.summary(format!("part {}{last}", i & 0x7fff_ffff))
                })
                .emit()?;
            cx.emit(
                Node::new("Codestream part")
                    .span(payload.tail(4))
                    .desc("The parts are joined after the last box"),
            );
        }
        b"Exif" | b"xml " | b"jumb" => metadata_payload(&cx, input, &kind, span, payload).await?,
        b"brob" => {
            let inner = cx.read_avail(payload.sub(0, 4)).await?;
            cx.emit(
                Node::new("Brotli-compressed box")
                    .span(payload.tail(4))
                    .value(text(crate::text::latin1(&inner)))
                    .lazy(brob_content, (input, payload.tail(4), inner)),
            );
        }
        b"jbrd" => cx.emit(Node::new("JPEG reconstruction data").span(payload)),
        _ => cx.emit(Node::new("Data").span(payload)),
    }
    Ok(())
}

/// The content of an `Exif`, `xml ` or `jumb` box, stored or decoded from a
/// `brob` box: `whole` is the box with its header when there is one.
async fn metadata_payload(
    cx: &Cx,
    input: Input,
    kind: &[u8],
    whole: Span,
    payload: Span,
) -> Result<()> {
    match kind {
        b"Exif" => {
            let block = cx.block(payload.sub(0, 4)).await?;
            let offset = Fields::emitting(cx, &block, BE)
                .u32("TIFF header offset")
                .emit()?;
            let tiff = payload.tail(4u64.saturating_add(offset.into()));
            cx.emit(embedded_as(
                "Exif",
                input.nested(tiff),
                &super::tiff::FORMAT,
            ));
        }
        b"xml " => cx.emit(embedded_as(
            "XMP",
            input.nested(payload),
            &super::xmp::FORMAT,
        )),
        // A JUMBF superbox (C2PA): the box itself is the stream's first box;
        // decoded from `brob`, the payload is its description box and
        // content boxes.
        _ => cx.emit(embedded_as(
            "JUMBF",
            input.nested(whole),
            &super::jpeg::JUMBF,
        )),
    }
    Ok(())
}

/// A `brob` box's content: Brotli-decoded, then shown as the box type it
/// wraps when that is one this dissector knows (ISO/IEC 18181-2 9.1).
async fn brob_content(cx: Cx, (input, span, kind): (Input, Span, Vec<u8>)) -> Result<()> {
    if !matches!(kind.as_slice(), b"Exif" | b"xml " | b"jumb") {
        return crate::formats::expand_content(cx, (input, span, Codec::Brotli, None)).await;
    }
    let decoded = crate::codec::decode_span(&cx, span, &Codec::Brotli, None).await?;
    cx.annotate(format!(
        "{:#x} bytes {}",
        decoded.span.len,
        Codec::Brotli.verb()
    ));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    metadata_payload(&cx, input, &kind, decoded.span, decoded.span).await
}
