//! ICC color profiles (ICC.1, versions 2 and 4), as found on their own and
//! embedded in JPEG, PNG, TIFF, PSD, WebP and others.
//!
//! A 128-byte header, a tag table of `signature, offset, size` entries, and
//! tag data. Each tag's data starts with a type signature; common types
//! (text, descriptions, multi-localized Unicode, XYZ, curves) are decoded.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

use super::text;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "icc",
    title: "ICC color profile",
    extensions: &["icc", "icm"],
    mime: "application/vnd.iccprofile",
    probe: Probe::Magic(&[(36, b"acsp")]),
    dissect: crate::expander!(dissect: Input),
};

/// Four-character codes as big-endian numbers, for enumeration tables.
const fn sig(s: &[u8; 4]) -> u64 {
    u32::from_be_bytes(*s) as u64
}

const CLASSES: EnumTable = &[
    (sig(b"scnr"), "Input device"),
    (sig(b"mntr"), "Display device"),
    (sig(b"prtr"), "Output device"),
    (sig(b"link"), "Device link"),
    (sig(b"spac"), "Color space"),
    (sig(b"abst"), "Abstract"),
    (sig(b"nmcl"), "Named color"),
];

const SPACES: EnumTable = &[
    (sig(b"XYZ "), "XYZ"),
    (sig(b"Lab "), "CIELAB"),
    (sig(b"Luv "), "CIELUV"),
    (sig(b"YCbr"), "YCbCr"),
    (sig(b"Yxy "), "CIEYxy"),
    (sig(b"RGB "), "RGB"),
    (sig(b"GRAY"), "Gray"),
    (sig(b"HSV "), "HSV"),
    (sig(b"HLS "), "HLS"),
    (sig(b"CMYK"), "CMYK"),
    (sig(b"CMY "), "CMY"),
];

const PLATFORMS: EnumTable = &[
    (0, "None"),
    (sig(b"APPL"), "Apple"),
    (sig(b"MSFT"), "Microsoft"),
    (sig(b"SGI "), "Silicon Graphics"),
    (sig(b"SUNW"), "Sun Microsystems"),
];

const INTENTS: EnumTable = &[
    (0, "Perceptual"),
    (1, "Media-relative colorimetric"),
    (2, "Saturation"),
    (3, "ICC-absolute colorimetric"),
];

const PROFILE_FLAGS: FlagTable = &[flag(0x1, "EMBEDDED"), flag(0x2, "NOT_INDEPENDENT")];

const TAGS: EnumTable = &[
    (sig(b"A2B0"), "AToB0 (perceptual)"),
    (sig(b"A2B1"), "AToB1 (colorimetric)"),
    (sig(b"A2B2"), "AToB2 (saturation)"),
    (sig(b"B2A0"), "BToA0 (perceptual)"),
    (sig(b"B2A1"), "BToA1 (colorimetric)"),
    (sig(b"B2A2"), "BToA2 (saturation)"),
    (sig(b"bXYZ"), "Blue matrix column"),
    (sig(b"bTRC"), "Blue tone reproduction curve"),
    (sig(b"bkpt"), "Media black point"),
    (sig(b"calt"), "Calibration date and time"),
    (sig(b"chad"), "Chromatic adaptation"),
    (sig(b"chrm"), "Chromaticity"),
    (sig(b"cicp"), "Coding-independent code points"),
    (sig(b"cprt"), "Copyright"),
    (sig(b"desc"), "Profile description"),
    (sig(b"dmnd"), "Device manufacturer description"),
    (sig(b"dmdd"), "Device model description"),
    (sig(b"gXYZ"), "Green matrix column"),
    (sig(b"gTRC"), "Green tone reproduction curve"),
    (sig(b"gamt"), "Gamut"),
    (sig(b"kTRC"), "Gray tone reproduction curve"),
    (sig(b"lumi"), "Luminance"),
    (sig(b"meas"), "Measurement"),
    (sig(b"ncl2"), "Named color 2"),
    (sig(b"pre0"), "Preview 0"),
    (sig(b"rXYZ"), "Red matrix column"),
    (sig(b"rTRC"), "Red tone reproduction curve"),
    (sig(b"tech"), "Technology"),
    (sig(b"vued"), "Viewing conditions description"),
    (sig(b"view"), "Viewing conditions"),
    (sig(b"wtpt"), "Media white point"),
    (sig(b"mmod"), "Make and model (Apple)"),
    (sig(b"vcgt"), "Video card gamma table"),
    (sig(b"dscm"), "Localized description (Apple)"),
    (sig(b"arts"), "Absolute to media-relative transform (Apple)"),
];

record! {
    pub struct Header {
        size: u32 "Profile size",
        cmm: ascii[4] "Preferred CMM",
        version: u32 "Version" .hex() .with(|&v, n| n.summary(format!("{}.{}.{}", v >> 24, (v >> 20) & 15, (v >> 16) & 15))),
        class: u32 "Device class" .enumeration(CLASSES),
        space: u32 "Data color space" .enumeration(SPACES),
        pcs: u32 "Profile connection space" .enumeration(SPACES),
        year: u16 "Year",
        month: u16 "Month",
        day: u16 "Day",
        hour: u16 "Hour",
        minute: u16 "Minute",
        second: u16 "Second",
        signature: ascii[4] "Signature" .desc("\"acsp\""),
        platform: u32 "Primary platform" .enumeration(PLATFORMS),
        flags: u32 "Flags" .flags(PROFILE_FLAGS),
        manufacturer: ascii[4] "Device manufacturer",
        model: u32 "Device model" .hex(),
        attributes: u64 "Device attributes" .hex(),
        intent: u32 "Rendering intent" .enumeration(INTENTS),
        illuminant_x: i32 "Illuminant X" .with(|&v, n| n.summary(s15f16(v))),
        illuminant_y: i32 "Illuminant Y" .with(|&v, n| n.summary(s15f16(v))),
        illuminant_z: i32 "Illuminant Z" .with(|&v, n| n.summary(s15f16(v))),
        creator: ascii[4] "Profile creator",
        id: bytes[16] "Profile ID" .desc("MD5 of the profile (version 4)"),
        reserved: bytes[28] "Reserved",
    }
}

fn s15f16(v: i32) -> String {
    format!("{:.4}", f64::from(v) / 65536.0)
}

fn fourcc(v: u32) -> String {
    crate::text::latin1(&v.to_be_bytes())
}

/// Tags per profile before giving up.
const MAX_TAGS: u32 = 1024;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let class = crate::value::lookup(CLASSES, h.class.into()).unwrap_or("unknown class");
    let space =
        crate::value::lookup(SPACES, h.space.into()).map_or_else(|| fourcc(h.space), str::to_owned);
    let version = format!("{}.{}", h.version >> 24, (h.version >> 20) & 15);
    let mut summary = format!("ICC v{version}, {class}, {space}");
    let count_span = file.sub(Header::SIZE, 4);
    let count = u32_be(&cx.read(count_span).await?, 0).unwrap_or(0);
    let table = file.sub(
        Header::SIZE.saturating_add(4),
        u64::from(count.min(MAX_TAGS)).saturating_mul(12),
    );
    if let Some(desc) = description(&cx, file, table).await {
        summary = format!("{summary}, {desc:?}");
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Tag table")
            .span(file.sub(Header::SIZE, table.len.saturating_add(4)))
            .summary(format!("{count} tags"))
            .lazy(tags, (file, table)),
    );
    Ok(())
}

/// The profile description, for the summary.
async fn description(cx: &Cx, file: Span, table: Span) -> Option<String> {
    let entries = cx.read_avail(table).await.ok()?;
    let entry = entries
        .as_chunks::<12>()
        .0
        .iter()
        .find(|e| e.starts_with(b"desc"))?;
    let offset = u32_be(entry, 4)?;
    let size = u32_be(entry, 8)?;
    let data = file.sub(offset.into(), u64::from(size).min(512));
    match decode(cx, data).await {
        (Some(Value::Text(t)), _) => Some(t),
        _ => None,
    }
}

async fn tags(cx: Cx, (file, table): (Span, Span)) -> Result<()> {
    let n = table.len / 12;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let span = table.sub(i.saturating_mul(12), 12);
        let entry = cx.read(span).await?;
        let tag = u32_be(&entry, 0).unwrap_or(0);
        let offset = u32_be(&entry, 4).unwrap_or(0);
        let size = u32_be(&entry, 8).unwrap_or(0);
        let data = file.sub(offset.into(), size.into());
        let (value, kind) = decode(&cx, data).await;
        let mut node = Node::new(fourcc(tag)).span(span).target(data);
        let mut summary = crate::value::lookup(TAGS, tag.into())
            .unwrap_or("")
            .to_owned();
        if let Some(kind) = kind {
            summary = if summary.is_empty() {
                kind
            } else {
                format!("{summary} ({kind})")
            };
        }
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if let Some(v) = value {
            node = node.value(v);
        }
        cx.push(node.lazy(tag_data, (span, data))).await;
    }
    Ok(())
}

/// A value for well-known tag types, and the type signature.
async fn decode(cx: &Cx, data: Span) -> (Option<Value>, Option<String>) {
    let Ok(bytes) = cx.read_avail(data.sub(0, 512)).await else {
        return (None, None);
    };
    let Some(kind) = bytes.get(..4) else {
        return (None, None);
    };
    let kind_text = crate::text::latin1(kind).trim().to_owned();
    let body = bytes.get(8..).unwrap_or_default();
    let value = match kind {
        b"text" => Some(text(crate::text::until_nul(body))),
        b"desc" => {
            let len = u32_be(body, 0)
                .and_then(|l| usize::try_from(l).ok())
                .unwrap_or(0);
            let s = body.get(4..).unwrap_or_default();
            Some(text(crate::text::until_nul(
                s.get(..len.min(s.len())).unwrap_or_default(),
            )))
        }
        b"mluc" => {
            // First record: language, country, length, offset (from the tag start).
            let len = u32_be(body, 12)
                .and_then(|l| usize::try_from(l).ok())
                .unwrap_or(0);
            let off = u32_be(body, 16)
                .and_then(|o| usize::try_from(o).ok())
                .unwrap_or(0);
            let s = off
                .checked_add(len)
                .and_then(|end| bytes.get(off..end))
                .unwrap_or_default();
            Some(text(crate::text::utf16(s, Endian::Big)))
        }
        b"sig " => u32_be(body, 0).map(|v| text(fourcc(v))),
        b"XYZ " => {
            let v: Vec<String> = (0..3usize)
                .filter_map(|i| crate::bytes::i32_be(body, i.saturating_mul(4)).map(s15f16))
                .collect();
            Some(text(v.join(", ")))
        }
        b"curv" => match u32_be(body, 0) {
            Some(0) => Some(text("identity")),
            Some(1) => u16_be(body, 4).map(|g| text(format!("gamma {:.3}", f64::from(g) / 256.0))),
            Some(n) => Some(text(format!("{n} points"))),
            None => None,
        },
        b"para" => u16_be(body, 0).map(|f| text(format!("parametric curve, function {f}"))),
        _ => None,
    };
    (value, Some(kind_text))
}

async fn tag_data(cx: Cx, (entry, data): (Span, Span)) -> Result<()> {
    let block = cx.block(entry).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Signature", 4).emit()?;
    f.u32("Offset").hex().emit()?;
    f.u32("Size").emit()?;
    let head = cx.block(data.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Type", 4).emit()?;
    f.u32("Reserved").emit()?;
    cx.emit(Node::new("Data").span(data.tail(8)));
    Ok(())
}
