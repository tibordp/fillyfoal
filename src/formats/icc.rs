//! ICC colour profiles (`.icc`, `.icm`; also embedded in JPEG, PNG, TIFF).
//!
//! A 128-byte header (device class, colour spaces, rendering intent, date,
//! illuminant) is followed by a tag table; each tag points at typed data
//! (`desc`, `text`, `mluc`, `XYZ `, `curv`, `para`, ...). Tags are decoded
//! when expanded; the table summarises each with its type and a short value.

use crate::bytes::{i32_be, u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::datakit::{clip, fourcc};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const BE: Endian = Endian::Big;
const MAX_TAGS: u32 = 1000;

pub static FORMAT: Format = Format {
    name: "icc",
    title: "ICC colour profile",
    extensions: &["icc", "icm"],
    mime: "application/vnd.iccprofile",
    probe: Probe::Magic(&[(36, b"acsp")]),
    dissect: crate::expander!(dissect: Input),
};

const fn sig(s: &[u8; 4]) -> u64 {
    u32::from_be_bytes(*s) as u64
}

const CLASSES: EnumTable = &[
    (sig(b"scnr"), "Input device (scanner)"),
    (sig(b"mntr"), "Display device"),
    (sig(b"prtr"), "Output device (printer)"),
    (sig(b"link"), "Device link"),
    (sig(b"spac"), "Colour space conversion"),
    (sig(b"abst"), "Abstract"),
    (sig(b"nmcl"), "Named colour"),
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
    (sig(b"2CLR"), "2 colour"),
    (sig(b"3CLR"), "3 colour"),
    (sig(b"4CLR"), "4 colour"),
    (sig(b"5CLR"), "5 colour"),
    (sig(b"6CLR"), "6 colour"),
    (sig(b"7CLR"), "7 colour"),
    (sig(b"8CLR"), "8 colour"),
];

const PLATFORMS: EnumTable = &[
    (0, "none"),
    (sig(b"APPL"), "Apple"),
    (sig(b"MSFT"), "Microsoft"),
    (sig(b"SGI "), "Silicon Graphics"),
    (sig(b"SUNW"), "Sun Microsystems"),
    (sig(b"TGNT"), "Taligent"),
];

const INTENTS: EnumTable = &[
    (0, "Perceptual"),
    (1, "Media-relative colorimetric"),
    (2, "Saturation"),
    (3, "ICC-absolute colorimetric"),
];

const PROFILE_FLAGS: FlagTable = &[flag(1, "Embedded"), flag(2, "Not independent")];

const DEVICE_ATTRIBUTES: FlagTable = &[
    flag(1, "Transparency"),
    flag(2, "Matte"),
    flag(4, "Negative"),
    flag(8, "Black and white"),
];

const TAGS: EnumTable = &[
    (sig(b"A2B0"), "AToB0 (perceptual)"),
    (sig(b"A2B1"), "AToB1 (colorimetric)"),
    (sig(b"A2B2"), "AToB2 (saturation)"),
    (sig(b"B2A0"), "BToA0 (perceptual)"),
    (sig(b"B2A1"), "BToA1 (colorimetric)"),
    (sig(b"B2A2"), "BToA2 (saturation)"),
    (sig(b"D2B0"), "DToB0"),
    (sig(b"B2D0"), "BToD0"),
    (sig(b"bXYZ"), "Blue matrix column"),
    (sig(b"gXYZ"), "Green matrix column"),
    (sig(b"rXYZ"), "Red matrix column"),
    (sig(b"bTRC"), "Blue tone reproduction curve"),
    (sig(b"gTRC"), "Green tone reproduction curve"),
    (sig(b"rTRC"), "Red tone reproduction curve"),
    (sig(b"kTRC"), "Gray tone reproduction curve"),
    (sig(b"bkpt"), "Media black point"),
    (sig(b"wtpt"), "Media white point"),
    (sig(b"lumi"), "Luminance"),
    (sig(b"calt"), "Calibration date/time"),
    (sig(b"targ"), "Characterization target"),
    (sig(b"chad"), "Chromatic adaptation"),
    (sig(b"chrm"), "Chromaticity"),
    (sig(b"cicp"), "Coding-independent code points"),
    (sig(b"cprt"), "Copyright"),
    (sig(b"desc"), "Profile description"),
    (sig(b"dmnd"), "Device manufacturer description"),
    (sig(b"dmdd"), "Device model description"),
    (sig(b"gamt"), "Gamut"),
    (sig(b"meas"), "Measurement"),
    (sig(b"ncl2"), "Named colour 2"),
    (sig(b"pre0"), "Preview 0"),
    (sig(b"pre1"), "Preview 1"),
    (sig(b"pre2"), "Preview 2"),
    (sig(b"pseq"), "Profile sequence description"),
    (sig(b"psid"), "Profile sequence identifier"),
    (sig(b"resp"), "Output response"),
    (sig(b"rig0"), "Perceptual rendering intent gamut"),
    (sig(b"rig2"), "Saturation rendering intent gamut"),
    (sig(b"tech"), "Technology"),
    (sig(b"vued"), "Viewing conditions description"),
    (sig(b"view"), "Viewing conditions"),
    (sig(b"clro"), "Colorant order"),
    (sig(b"clrt"), "Colorant table"),
    (sig(b"ciis"), "Colorimetric intent image state"),
    (sig(b"MS00"), "Microsoft WCS profile"),
    (sig(b"vcgt"), "Video card gamma table (Apple)"),
    (sig(b"dscm"), "Localized description (Apple)"),
    (sig(b"arts"), "Absolute to media-relative transform (Apple)"),
];

record! {
    pub struct Header {
        size: u32 "Profile size",
        cmm: u32 "Preferred CMM type" .with(|&s, n| n.value(Value::Text(fourcc(&s.to_be_bytes())))),
        version: u32 "Version" .hex() .with(|&v, n| n.summary(version(v))),
        class: u32 "Device class" .enumeration(CLASSES),
        space: u32 "Data colour space" .enumeration(SPACES),
        pcs: u32 "Profile connection space" .enumeration(SPACES),
        year: u16 "Year",
        month: u16 "Month",
        day: u16 "Day",
        hour: u16 "Hour",
        minute: u16 "Minute",
        second: u16 "Second",
        magic: ascii[4] "Signature",
        platform: u32 "Primary platform" .enumeration(PLATFORMS),
        flags: u32 "Profile flags" .flags(PROFILE_FLAGS),
        manufacturer: u32 "Device manufacturer" .with(|&s, n| n.value(Value::Text(fourcc(&s.to_be_bytes())))),
        model: u32 "Device model" .hex(),
        attributes: u64 "Device attributes" .flags(DEVICE_ATTRIBUTES),
        intent: u32 "Rendering intent" .enumeration(INTENTS),
        illum_x: i32 "PCS illuminant X" .with(|&v, n| n.value(Value::Float(s15(v)))),
        illum_y: i32 "PCS illuminant Y" .with(|&v, n| n.value(Value::Float(s15(v)))),
        illum_z: i32 "PCS illuminant Z" .with(|&v, n| n.value(Value::Float(s15(v)))),
        creator: u32 "Profile creator" .with(|&s, n| n.value(Value::Text(fourcc(&s.to_be_bytes())))),
        id: bytes[16] "Profile ID" .desc("MD5 of the profile (with some header fields zeroed)"),
        _reserved: bytes[28] "Reserved",
    }
}

fn version(v: u32) -> String {
    format!("{}.{}.{}", v >> 24, (v >> 20) & 0xf, (v >> 16) & 0xf)
}

/// s15Fixed16Number.
fn s15(v: i32) -> f64 {
    f64::from(v) / 65536.0
}

fn space_name(v: u32) -> String {
    lookup(SPACES, v.into()).map_or_else(|| fourcc(&v.to_be_bytes()), str::to_owned)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, BE));
    let count_bytes = cx.read(file.sub_exact(Header::SIZE, 4)?).await?;
    let count = u32_be(&count_bytes, 0).unwrap_or(0);
    let table = file.sub(
        Header::SIZE,
        4u64.saturating_add(u64::from(count).saturating_mul(12)),
    );
    cx.emit(
        Node::new("Tag table")
            .span(table)
            .summary(format!("{count} tags"))
            .lazy(tags, (file, count)),
    );
    let class = lookup(CLASSES, h.class.into()).unwrap_or("unknown class");
    let mut summary = format!(
        "ICC profile v{}, {class}, {} → {}",
        version(h.version),
        space_name(h.space),
        space_name(h.pcs)
    );
    if let Ok(Some(desc)) = description(&cx, file, count).await {
        summary = format!("{summary}, {:?}", clip(&desc, 80));
    }
    cx.annotate(summary);
    if u64::from(h.size) != file.len {
        cx.diag(Diagnostic::warning(format!(
            "header says {} bytes, profile has {}",
            h.size, file.len
        )));
    }
    Ok(())
}

/// The text of the `desc` tag, if any.
async fn description(cx: &Cx, file: Span, count: u32) -> Result<Option<String>> {
    for i in 0..count.min(MAX_TAGS) {
        let entry = cx
            .read(
                file.sub_exact(
                    Header::SIZE
                        .saturating_add(4)
                        .saturating_add(u64::from(i).saturating_mul(12)),
                    12,
                )?,
            )
            .await?;
        if entry.get(..4) == Some(b"desc".as_slice()) {
            let at = u32_be(&entry, 4).unwrap_or(0);
            let len = u32_be(&entry, 8).unwrap_or(0);
            let data = cx
                .read_avail(file.sub(at.into(), u64::from(len).min(0x1000)))
                .await?;
            return Ok(text_of(&data));
        }
    }
    Ok(None)
}

/// A short text for textual tag types.
fn text_of(data: &[u8]) -> Option<String> {
    match data.get(..4)? {
        b"desc" => {
            let n = crate::bytes::to_usize(u32_be(data, 8)?.into());
            let text = data.get(12..12usize.saturating_add(n))?;
            Some(crate::text::until_nul(text))
        }
        b"text" => Some(crate::text::until_nul(data.get(8..)?)),
        b"mluc" => {
            let count = u32_be(data, 8)?;
            if count == 0 {
                return None;
            }
            let len = crate::bytes::to_usize(u32_be(data, 20)?.into());
            let at = crate::bytes::to_usize(u32_be(data, 24)?.into());
            let text = data.get(at..at.saturating_add(len))?;
            Some(crate::text::utf16(text, BE))
        }
        _ => None,
    }
}

async fn tags(cx: Cx, (file, count): (Span, u32)) -> Result<()> {
    let table = file.sub_exact(
        Header::SIZE.saturating_add(4),
        u64::from(count).saturating_mul(12),
    )?;
    cx.set_count(Count::Exact(count.into()));
    for i in 0..u64::from(count) {
        let span = table.sub(i.saturating_mul(12), 12);
        let entry = cx.read(span).await?;
        let tag = u32_be(&entry, 0).unwrap_or(0);
        let offset = u32_be(&entry, 4).unwrap_or(0);
        let size = u32_be(&entry, 8).unwrap_or(0);
        let data = file.sub(offset.into(), size.into());
        let head = cx.read_avail(data.sub(0, 0x200)).await?;
        let kind = head.get(..4).map(fourcc).unwrap_or_default();
        let mut summary = format!("'{kind}', {size} bytes");
        if let Some(short) = short_value(&head) {
            summary = format!("{summary}: {short}");
        }
        let name = format!("'{}'", fourcc(&tag.to_be_bytes()));
        let mut node = Node::new(name)
            .span(data)
            .summary(summary)
            .value(Value::Enum {
                raw: tag.into(),
                bits: 32,
                name: lookup(TAGS, tag.into()),
            })
            .lazy(tag_data, data);
        if data.len < u64::from(size) {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, size.into()),
                data.len,
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

fn short_value(head: &[u8]) -> Option<String> {
    if let Some(t) = text_of(head) {
        return Some(format!("{:?}", clip(&t, 60)));
    }
    match head.get(..4)? {
        b"XYZ " => {
            let x = s15(i32_be(head, 8)?);
            let y = s15(i32_be(head, 12)?);
            let z = s15(i32_be(head, 16)?);
            Some(format!("X {x:.4}, Y {y:.4}, Z {z:.4}"))
        }
        b"curv" => match u32_be(head, 8)? {
            0 => Some("identity".to_owned()),
            1 => Some(format!("gamma {:.3}", f64::from(u16_be(head, 12)?) / 256.0)),
            n => Some(format!("{n} entries")),
        },
        b"para" => Some(format!(
            "function {}, gamma {:.3}",
            u16_be(head, 8)?,
            s15(i32_be(head, 12)?)
        )),
        b"sig " => Some(fourcc(head.get(8..12)?)),
        _ => None,
    }
}

async fn tag_data(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let kind = f
        .bytes("Type", 4)
        .with(|b, n| n.value(Value::Text(fourcc(b))))
        .emit()?;
    f.u32("Reserved").emit()?;
    match kind.as_slice() {
        b"desc" => {
            let n = f.u32("ASCII count").emit()?;
            f.ascii("ASCII description", n.into()).emit()?;
            if f.remaining() >= 8 {
                f.u32("Unicode language").hex().emit()?;
                let n = f.u32("Unicode count").emit()?;
                if n > 0 {
                    f.utf16("Unicode description", n.into()).emit()?;
                }
            }
        }
        b"text" => {
            let n = f.remaining();
            f.ascii("Text", n).emit()?;
        }
        b"mluc" => {
            let count = f.u32("Records").emit()?;
            f.u32("Record size").emit()?;
            for _ in 0..count.min(MAX_TAGS) {
                let lang = f.ascii("Language", 2).emit()?;
                let country = f.ascii("Country", 2).emit()?;
                let len = f.u32("Length").emit()?;
                let offset = f.u32("Offset").hex().emit()?;
                let text = span.sub(offset.into(), len.into());
                let bytes = cx.read_avail(text).await?;
                cx.emit(
                    Node::new(format!("{lang}-{country}"))
                        .span(text)
                        .value(Value::Text(crate::text::utf16(&bytes, BE))),
                );
            }
        }
        b"XYZ " => {
            let mut i = 0u32;
            while f.remaining() >= 12 && i < MAX_TAGS {
                for name in ["X", "Y", "Z"] {
                    f.int::<i32>(name)
                        .with(|&v, n| n.value(Value::Float(s15(v))))
                        .emit()?;
                }
                i = i.saturating_add(1);
            }
        }
        b"sf32" => {
            let mut i = 0u32;
            while f.remaining() >= 4 && i < 64 {
                f.int::<i32>("Value")
                    .with(|&v, n| n.value(Value::Float(s15(v))))
                    .emit()?;
                i = i.saturating_add(1);
            }
        }
        b"curv" => {
            let n = f.u32("Entries").emit()?;
            match n {
                0 => f.node(Node::new("Curve").summary("identity")),
                1 => {
                    f.u16("Gamma")
                        .with(|&g, node| node.value(Value::Float(f64::from(g) / 256.0)))
                        .emit()?;
                }
                _ => {
                    let len = u64::from(n).saturating_mul(2);
                    f.node(
                        Node::new("Table")
                            .span(f.peek_span(len))
                            .summary(format!("{n} 16-bit entries")),
                    );
                }
            }
        }
        b"para" => {
            let function = f.u16("Function type").emit()?;
            f.u16("Reserved").emit()?;
            let params = match function {
                0 => 1,
                1 => 3,
                2 => 4,
                3 => 5,
                4 => 7,
                _ => 0,
            };
            for name in ["g", "a", "b", "c", "d", "e", "f"].into_iter().take(params) {
                f.int::<i32>(name)
                    .with(|&v, n| n.value(Value::Float(s15(v))))
                    .emit()?;
            }
        }
        b"sig " => {
            f.bytes("Signature", 4)
                .with(|b, n| n.value(Value::Text(fourcc(b))))
                .emit()?;
        }
        b"dtim" => {
            for name in ["Year", "Month", "Day", "Hour", "Minute", "Second"] {
                f.u16(name).emit()?;
            }
        }
        b"meas" => {
            f.u32("Standard observer").emit()?;
            for name in ["Backing X", "Backing Y", "Backing Z"] {
                f.int::<i32>(name)
                    .with(|&v, n| n.value(Value::Float(s15(v))))
                    .emit()?;
            }
            f.u32("Geometry").emit()?;
            f.u32("Flare").emit()?;
            f.u32("Illuminant").emit()?;
        }
        b"chrm" => {
            let channels = f.u16("Channels").emit()?;
            f.u16("Phosphor/colorant type").emit()?;
            for _ in 0..channels.min(16) {
                f.u32("x")
                    .with(|&v, n| n.value(Value::Float(f64::from(v) / 65536.0)))
                    .emit()?;
                f.u32("y")
                    .with(|&v, n| n.value(Value::Float(f64::from(v) / 65536.0)))
                    .emit()?;
            }
        }
        b"view" => {
            for name in [
                "Illuminant X",
                "Illuminant Y",
                "Illuminant Z",
                "Surround X",
                "Surround Y",
                "Surround Z",
            ] {
                f.int::<i32>(name)
                    .with(|&v, n| n.value(Value::Float(s15(v))))
                    .emit()?;
            }
            f.u32("Illuminant type").emit()?;
        }
        b"mAB " | b"mBA " => {
            f.u8("Input channels").emit()?;
            f.u8("Output channels").emit()?;
            f.u16("Padding").emit()?;
            for name in [
                "B curves offset",
                "Matrix offset",
                "M curves offset",
                "CLUT offset",
                "A curves offset",
            ] {
                f.u32(name).hex().emit()?;
            }
        }
        _ => {
            let rest = f.remaining();
            if rest > 0 {
                f.node(Node::new("Data").span(f.peek_span(rest)));
            }
        }
    }
    Ok(())
}
