//! ICC colour profiles (ICC.1 versions 2 and 4; `.icc`, `.icm`; also
//! embedded in JPEG, PNG, TIFF, WebP, HEIF, PSD and PDF).
//!
//! A 128-byte header (version, device class, colour space and PCS, date,
//! platform, flags, device, rendering intent, illuminant, creator and an
//! MD5 profile ID) is followed by a tag table of `signature, offset, size`
//! entries; each tag points at typed data. The table names every tag and
//! shows a short value; expanding a tag decodes its type (`desc`, `mluc`,
//! `text`, `XYZ `, `curv`, `para`, `chrm`, `sf32`, `meas`, `view`, `sig `,
//! `dtim`, `cicp`, `mft1`/`mft2`, `mAB `/`mBA `, `vcgt`, ...).

use crate::bytes::{i32_be, u16_be, u32_be};
use crate::codec::crypto::Md5;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::datakit::{clip, digest_paced, fourcc};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

const BE: Endian = Endian::Big;
const MAX_TAGS: u32 = 1000;
const HEADER: u64 = 128;
/// Profiles up to this size have their MD5 profile ID checked.
const MAX_CHECKED: u64 = 4 << 20;

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
    (sig(b"scnr"), "Input device (scanner, camera)"),
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
    (sig(b"9CLR"), "9 colour"),
    (sig(b"ACLR"), "10 colour"),
    (sig(b"BCLR"), "11 colour"),
    (sig(b"CCLR"), "12 colour"),
    (sig(b"DCLR"), "13 colour"),
    (sig(b"ECLR"), "14 colour"),
    (sig(b"FCLR"), "15 colour"),
];

const PLATFORMS: EnumTable = &[
    (0, "none"),
    (sig(b"APPL"), "Apple"),
    (sig(b"MSFT"), "Microsoft"),
    (sig(b"SGI "), "Silicon Graphics"),
    (sig(b"SUNW"), "Sun Microsystems"),
    (sig(b"TGNT"), "Taligent"),
];

/// Well-known CMM, manufacturer and creator signatures.
const VENDORS: EnumTable = &[
    (sig(b"ADBE"), "Adobe"),
    (sig(b"ACMS"), "Agfa"),
    (sig(b"appl"), "Apple"),
    (sig(b"APPL"), "Apple"),
    (sig(b"CCMS"), "ColorGear"),
    (sig(b"EFI "), "EFI"),
    (sig(b"FF  "), "Fuji Film"),
    (sig(b"HCMM"), "Harlequin"),
    (sig(b"argl"), "Argyll CMS"),
    (sig(b"LgoS"), "LogoSync"),
    (sig(b"HDM "), "Heidelberg"),
    (sig(b"lcms"), "Little CMS"),
    (sig(b"KCMS"), "Kodak"),
    (sig(b"KODA"), "Kodak"),
    (sig(b"MCML"), "Konica Minolta"),
    (sig(b"WCS "), "Windows Color System"),
    (sig(b"MSFT"), "Microsoft"),
    (sig(b"SIGN"), "Mutoh"),
    (sig(b"ONYX"), "Onyx Graphics"),
    (sig(b"RGMS"), "DeviceLink"),
    (sig(b"SICC"), "SampleICC"),
    (sig(b"TCMM"), "Toshiba"),
    (sig(b"32BT"), "the imaging factory"),
    (sig(b"vivo"), "Vivo"),
    (sig(b"WTG "), "Ware to Go"),
    (sig(b"zc00"), "Zoran"),
    (sig(b"HP  "), "Hewlett-Packard"),
    (sig(b"IEC "), "IEC"),
    (sig(b"GOOG"), "Google"),
];

const INTENTS: EnumTable = &[
    (0, "Perceptual"),
    (1, "Media-relative colorimetric"),
    (2, "Saturation"),
    (3, "ICC-absolute colorimetric"),
];

const PROFILE_FLAGS: FlagTable = &[flag(1, "EMBEDDED"), flag(2, "NOT_INDEPENDENT")];

/// Device attributes: each bit chooses between two alternatives.
const DEVICE_ATTRIBUTES: FlagTable = &[
    field(1, 0, "REFLECTIVE"),
    field(1, 1, "TRANSPARENCY"),
    field(2, 0, "GLOSSY"),
    field(2, 2, "MATTE"),
    field(4, 0, "POSITIVE"),
    field(4, 4, "NEGATIVE"),
    field(8, 0, "COLOUR"),
    field(8, 8, "BLACK_AND_WHITE"),
];

const TAGS: EnumTable = &[
    (sig(b"A2B0"), "AToB0 (perceptual)"),
    (sig(b"A2B1"), "AToB1 (colorimetric)"),
    (sig(b"A2B2"), "AToB2 (saturation)"),
    (sig(b"B2A0"), "BToA0 (perceptual)"),
    (sig(b"B2A1"), "BToA1 (colorimetric)"),
    (sig(b"B2A2"), "BToA2 (saturation)"),
    (sig(b"D2B0"), "DToB0 (perceptual)"),
    (sig(b"D2B1"), "DToB1 (colorimetric)"),
    (sig(b"D2B2"), "DToB2 (saturation)"),
    (sig(b"D2B3"), "DToB3 (absolute)"),
    (sig(b"B2D0"), "BToD0 (perceptual)"),
    (sig(b"B2D1"), "BToD1 (colorimetric)"),
    (sig(b"B2D2"), "BToD2 (saturation)"),
    (sig(b"B2D3"), "BToD3 (absolute)"),
    (sig(b"rXYZ"), "Red matrix column"),
    (sig(b"gXYZ"), "Green matrix column"),
    (sig(b"bXYZ"), "Blue matrix column"),
    (sig(b"rTRC"), "Red tone reproduction curve"),
    (sig(b"gTRC"), "Green tone reproduction curve"),
    (sig(b"bTRC"), "Blue tone reproduction curve"),
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
    (sig(b"meta"), "Metadata"),
    (sig(b"ncol"), "Named colour (v2)"),
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
    (sig(b"clot"), "Colorant table out"),
    (sig(b"ciis"), "Colorimetric intent image state"),
    (sig(b"bfd "), "UCR/BG (v2)"),
    (sig(b"crdi"), "CRD info (v2)"),
    (sig(b"devs"), "Device settings (v2)"),
    (sig(b"ps2s"), "PostScript CSA (v2)"),
    (sig(b"ps2i"), "PostScript rendering intent (v2)"),
    (sig(b"psd0"), "PostScript CRD 0 (v2)"),
    (sig(b"psd1"), "PostScript CRD 1 (v2)"),
    (sig(b"psd2"), "PostScript CRD 2 (v2)"),
    (sig(b"psd3"), "PostScript CRD 3 (v2)"),
    (sig(b"scrd"), "Screening description (v2)"),
    (sig(b"scrn"), "Screening (v2)"),
    (sig(b"MS00"), "Microsoft WCS profile"),
    (sig(b"MHC2"), "Microsoft HDR calibration"),
    (sig(b"vcgt"), "Video card gamma table (Apple)"),
    (sig(b"mmod"), "Make and model (Apple)"),
    (sig(b"ndin"), "Native display info (Apple)"),
    (sig(b"dscm"), "Localized description (Apple)"),
    (sig(b"arts"), "Absolute to media-relative transform (Apple)"),
    (sig(b"aabg"), "Blue adaptation (Apple)"),
    (sig(b"aagg"), "Green adaptation (Apple)"),
    (sig(b"aarg"), "Red adaptation (Apple)"),
];

const OBSERVERS: EnumTable = &[(0, "Unknown"), (1, "CIE 1931 (2°)"), (2, "CIE 1964 (10°)")];
const GEOMETRIES: EnumTable = &[(0, "Unknown"), (1, "0/45 or 45/0"), (2, "0/d or d/0")];
const ILLUMINANTS: EnumTable = &[
    (0, "Unknown"),
    (1, "D50"),
    (2, "D65"),
    (3, "D93"),
    (4, "F2"),
    (5, "D55"),
    (6, "A"),
    (7, "Equi-power (E)"),
    (8, "F8"),
];
const PHOSPHORS: EnumTable = &[
    (0, "Unknown"),
    (1, "ITU-R BT.709"),
    (2, "SMPTE RP145"),
    (3, "EBU Tech 3213-E"),
    (4, "P22"),
    (5, "P3"),
    (6, "ITU-R BT.2020"),
];
const TECHNOLOGIES: EnumTable = &[
    (sig(b"fscn"), "Film scanner"),
    (sig(b"dcam"), "Digital camera"),
    (sig(b"rscn"), "Reflective scanner"),
    (sig(b"ijet"), "Ink jet printer"),
    (sig(b"twax"), "Thermal wax printer"),
    (sig(b"epho"), "Electrophotographic printer"),
    (sig(b"esta"), "Electrostatic printer"),
    (sig(b"dsub"), "Dye sublimation printer"),
    (sig(b"rpho"), "Photographic paper printer"),
    (sig(b"fprn"), "Film writer"),
    (sig(b"vidm"), "Video monitor"),
    (sig(b"vidc"), "Video camera"),
    (sig(b"pjtv"), "Projection television"),
    (sig(b"CRT "), "Cathode ray tube display"),
    (sig(b"PMD "), "Passive matrix display"),
    (sig(b"AMD "), "Active matrix display"),
    (sig(b"LCD "), "Liquid crystal display"),
    (sig(b"OLED"), "Organic LED display"),
    (sig(b"KPCD"), "Photo CD"),
    (sig(b"imgs"), "Photographic image setter"),
    (sig(b"grav"), "Gravure"),
    (sig(b"offs"), "Offset lithography"),
    (sig(b"silk"), "Silkscreen"),
    (sig(b"flex"), "Flexography"),
    (sig(b"mpfs"), "Motion picture film scanner"),
    (sig(b"mpfr"), "Motion picture film recorder"),
    (sig(b"dmpc"), "Digital motion picture camera"),
    (sig(b"dcpj"), "Digital cinema projector"),
    (sig(b"scoe"), "Scene colorimetry estimates"),
    (sig(b"sape"), "Scene appearance estimates"),
    (sig(b"fpce"), "Focal plane colorimetry estimates"),
    (sig(b"rhoc"), "Reflection hardcopy original colorimetry"),
    (sig(b"rpoc"), "Reflection print output colorimetry"),
];
const CICP_PRIMARIES: EnumTable = &[
    (1, "BT.709"),
    (4, "BT.470 M"),
    (5, "BT.601 625"),
    (6, "BT.601 525"),
    (7, "SMPTE 240M"),
    (8, "Generic film"),
    (9, "BT.2020"),
    (10, "XYZ"),
    (11, "SMPTE RP 431-2 (DCI-P3)"),
    (12, "SMPTE EG 432-1 (Display P3)"),
    (22, "EBU Tech 3213-E"),
];
const CICP_TRANSFER: EnumTable = &[
    (1, "BT.709"),
    (4, "Gamma 2.2"),
    (5, "Gamma 2.8"),
    (6, "BT.601"),
    (7, "SMPTE 240M"),
    (8, "Linear"),
    (13, "sRGB"),
    (14, "BT.2020 10-bit"),
    (15, "BT.2020 12-bit"),
    (16, "PQ (SMPTE ST 2084)"),
    (17, "SMPTE ST 428-1"),
    (18, "HLG (ARIB STD-B67)"),
];
const CICP_MATRIX: EnumTable = &[
    (0, "Identity (RGB)"),
    (1, "BT.709"),
    (5, "BT.601 625"),
    (6, "BT.601 525"),
    (9, "BT.2020 non-constant"),
    (10, "BT.2020 constant"),
];

fn version(v: u32) -> String {
    format!("{}.{}.{}", v >> 24, (v >> 20) & 0xf, (v >> 16) & 0xf)
}

/// s15Fixed16Number.
fn s15(v: i32) -> f64 {
    f64::from(v) / 65536.0
}

/// u16Fixed16Number.
fn u16f16(v: u32) -> f64 {
    f64::from(v) / 65536.0
}

fn space_name(v: u32) -> String {
    lookup(SPACES, v.into()).map_or_else(|| fourcc(&v.to_be_bytes()), str::to_owned)
}

/// A signature as text, with the vendor's name when known.
fn signature(v: u32) -> (Value, Option<&'static str>) {
    if v == 0 {
        return (Value::Text("none".to_owned()), None);
    }
    (
        Value::Text(fourcc(&v.to_be_bytes())),
        lookup(VENDORS, v.into()),
    )
}

#[derive(Clone, Copy, Debug)]
struct HeaderCtx {
    /// Whether the MD5 profile ID matched (None: absent or not checked).
    id_ok: Option<bool>,
}

struct Header {
    size: u32,
    version: u32,
    class: u32,
    space: u32,
    pcs: u32,
    creator: u32,
    id_zero: bool,
}

fn sig_field(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    f.u32(name)
        .with(|&s, n| {
            let (value, vendor) = signature(s);
            let n = n.value(value);
            match vendor {
                Some(v) => n.summary(v),
                None => n,
            }
        })
        .emit()
}

fn header(f: &mut Fields<'_>, ctx: &HeaderCtx) -> Result<Header> {
    let size = f.u32("Profile size").emit()?;
    sig_field(f, "Preferred CMM type")?;
    let version = f
        .u32("Version")
        .hex()
        .with(|&v, n| n.summary(version(v)))
        .emit()?;
    let class = f.u32("Device class").enumeration(CLASSES).emit()?;
    let space = f.u32("Data colour space").enumeration(SPACES).emit()?;
    let pcs = f
        .u32("Profile connection space")
        .enumeration(SPACES)
        .emit()?;
    let at = f.peek_span(12);
    let mut date = [0u16; 6];
    for slot in &mut date {
        *slot = f.u16("Date field").get()?;
    }
    let [year, month, day, hour, minute, second] = date;
    let mut node = Node::new("Date and time").span(at);
    if year == 0 {
        node = node.value(Value::Text("not set".to_owned()));
    } else {
        node = node.value(Value::Timestamp {
            unix_seconds: crate::formats::disk::civil_to_unix(
                year.into(),
                month.into(),
                day.into(),
                hour.into(),
                minute.into(),
                second.into(),
            ),
        });
    }
    f.node(node);
    f.ascii("Signature", 4)
        .check(|s| (s != "acsp").then(|| Diagnostic::malformed("expected \"acsp\"")))
        .emit()?;
    f.u32("Primary platform").enumeration(PLATFORMS).emit()?;
    f.u32("Profile flags").flags(PROFILE_FLAGS).emit()?;
    sig_field(f, "Device manufacturer")?;
    f.u32("Device model").hex().emit()?;
    f.u64("Device attributes").flags(DEVICE_ATTRIBUTES).emit()?;
    f.u32("Rendering intent")
        .with(|&v, n| {
            n.value(Value::Enum {
                raw: (v & 0xffff).into(),
                bits: 16,
                name: lookup(INTENTS, (v & 0xffff).into()),
            })
        })
        .emit()?;
    for name in ["PCS illuminant X", "PCS illuminant Y", "PCS illuminant Z"] {
        f.int::<i32>(name)
            .with(|&v, n| n.value(Value::Float(s15(v))))
            .emit()?;
    }
    let creator = sig_field(f, "Profile creator")?;
    let id_ok = ctx.id_ok;
    let id = f
        .bytes("Profile ID", 16)
        .desc("MD5 of the profile with the flags, rendering intent and profile ID zeroed")
        .with(|_, n| match id_ok {
            Some(true) => n.summary("MD5 verified"),
            Some(false) => n.diag(Diagnostic::warning("does not match the profile's MD5")),
            None => n,
        })
        .emit()?;
    f.bytes("Reserved", 28).emit()?;
    Ok(Header {
        size,
        version,
        class,
        space,
        pcs,
        creator,
        id_zero: id.iter().all(|&b| b == 0),
    })
}

/// Checks the MD5 profile ID (version 4 profiles that set one).
async fn check_id(cx: &Cx, file: Span) -> Option<bool> {
    if file.len > MAX_CHECKED || file.len < HEADER {
        return None;
    }
    let mut data = cx.read(file).await.ok()?;
    let id: Vec<u8> = data.get(84..100)?.to_vec();
    if id.iter().all(|&b| b == 0) {
        return None;
    }
    for range in [44..48, 64..68, 84..100] {
        for b in data.get_mut(range)? {
            *b = 0;
        }
    }
    Some(digest_paced::<Md5>(cx, &data).await == id)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, HEADER);
    let unchecked = HeaderCtx { id_ok: None };
    let h = parse(&cx, hspan, BE, &unchecked, header).await?;
    let ctx = HeaderCtx {
        id_ok: if h.id_zero {
            None
        } else {
            check_id(&cx, file).await
        },
    };
    cx.emit(struct_node("Header", hspan, BE, ctx, header));
    let count_bytes = cx.read(file.sub_exact(HEADER, 4)?).await?;
    let count = u32_be(&count_bytes, 0).unwrap_or(0);
    let table = file.sub(
        HEADER,
        4u64.saturating_add(u64::from(count).saturating_mul(12)),
    );
    let mut node = Node::new("Tag table")
        .span(table)
        .summary(format!("{count} tags"))
        .lazy(tags, (file, count));
    if count > MAX_TAGS {
        node = node.diag(Diagnostic::limit(format!("more than {MAX_TAGS} tags")));
    }
    cx.emit(node);
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
    if let Some(creator) = lookup(VENDORS, h.creator.into()) {
        summary = format!("{summary}, by {creator}");
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
    let n = count.min(MAX_TAGS);
    let table = file.sub(HEADER.saturating_add(4), u64::from(n).saturating_mul(12));
    let bytes = cx.read_avail(table).await?;
    for entry in bytes.as_chunks::<12>().0 {
        if entry.get(..4) == Some(b"desc".as_slice()) {
            let at = u32_be(entry, 4).unwrap_or(0);
            let len = u32_be(entry, 8).unwrap_or(0);
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
            // Prefer English among the first records.
            let record = (0..count.min(64))
                .filter_map(|i| {
                    let at =
                        crate::bytes::to_usize(u64::from(i).saturating_mul(12)).saturating_add(16);
                    data.get(at..at.saturating_add(12))
                })
                .find(|r| r.starts_with(b"en"))
                .or_else(|| data.get(16..28))?;
            let len = crate::bytes::to_usize(u32_be(record, 4)?.into());
            let at = crate::bytes::to_usize(u32_be(record, 8)?.into());
            let text = data.get(at..at.saturating_add(len))?;
            Some(
                crate::text::utf16(text, BE)
                    .trim_end_matches('\0')
                    .to_owned(),
            )
        }
        _ => None,
    }
}

async fn tags(cx: Cx, (file, count): (Span, u32)) -> Result<()> {
    let n = count.min(MAX_TAGS);
    let table = file.sub_exact(HEADER.saturating_add(4), u64::from(n).saturating_mul(12))?;
    cx.set_count(Count::Exact(n.into()));
    for i in 0..u64::from(n) {
        let span = table.sub(i.saturating_mul(12), 12);
        let entry = cx.read(span).await?;
        let tag = u32_be(&entry, 0).unwrap_or(0);
        let offset = u32_be(&entry, 4).unwrap_or(0);
        let size = u32_be(&entry, 8).unwrap_or(0);
        let data = file.sub(offset.into(), size.into());
        let head = cx.read_avail(data.sub(0, 0x200)).await?;
        let kind = head.get(..4).map(fourcc).unwrap_or_default();
        let code = fourcc(&tag.to_be_bytes());
        let name = lookup(TAGS, tag.into()).map_or_else(|| format!("'{code}'"), str::to_owned);
        let mut node = Node::new(name)
            .span(data)
            .summary(format!(
                "'{code}', type '{kind}', {}",
                human_size(size.into())
            ))
            .lazy(tag_data, data);
        if let Some(short) = short_value(&head) {
            node = node.value(Value::Text(short));
        }
        if data.len < u64::from(size) {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, size.into()),
                data.len,
            ));
        }
        if u64::from(offset) % 4 != 0 {
            node = node.diag(Diagnostic::warning("tag data is not 4-byte aligned"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The decoded value shown next to a tag in the table.
fn short_value(head: &[u8]) -> Option<String> {
    if let Some(t) = text_of(head) {
        return Some(clip(&t, 60));
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
            n => Some(format!("{n}-point curve")),
        },
        b"para" => {
            let function = u16_be(head, 8)?;
            Some(format!(
                "function {function}, gamma {:.3}",
                s15(i32_be(head, 12)?)
            ))
        }
        b"sig " => {
            let s = u32_be(head, 8)?;
            Some(
                lookup(TECHNOLOGIES, s.into())
                    .map_or_else(|| fourcc(&s.to_be_bytes()), str::to_owned),
            )
        }
        b"sf32" => {
            let v: Vec<String> = (0..9usize)
                .map_while(|i| i32_be(head, 8usize.saturating_add(i.saturating_mul(4))))
                .map(|v| format!("{:.4}", s15(v)))
                .collect();
            Some(v.join(" "))
        }
        b"dtim" => {
            let g = |i: usize| u16_be(head, 8usize.saturating_add(i.saturating_mul(2)));
            Some(format!(
                "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
                g(0)?,
                g(1)?,
                g(2)?,
                g(3)?,
                g(4)?,
                g(5)?
            ))
        }
        b"chrm" => {
            let channels = u16_be(head, 8)?;
            let kind = u16_be(head, 10)?;
            Some(match lookup(PHOSPHORS, kind.into()) {
                Some(p) if kind != 0 => format!("{channels} channels, {p}"),
                _ => format!("{channels} channels"),
            })
        }
        b"cicp" => {
            let p = head.get(8).copied()?;
            let t = head.get(9).copied()?;
            Some(format!(
                "{}, {}",
                lookup(CICP_PRIMARIES, p.into())
                    .map_or_else(|| format!("primaries {p}"), str::to_owned),
                lookup(CICP_TRANSFER, t.into())
                    .map_or_else(|| format!("transfer {t}"), str::to_owned)
            ))
        }
        b"mft1" | b"mft2" | b"mAB " | b"mBA " => {
            Some(format!("{} → {} channels", head.get(8)?, head.get(9)?))
        }
        _ => None,
    }
}

fn fixed(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.int::<i32>(name)
        .with(|&v, n| n.value(Value::Float(s15(v))))
        .emit()?;
    Ok(())
}

fn ufixed(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    f.u32(name)
        .with(|&v, n| n.value(Value::Float(u16f16(v))))
        .emit()?;
    Ok(())
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
            if f.remaining() >= 3 {
                f.u16("ScriptCode code").emit()?;
                let n = f.u8("ScriptCode count").emit()?;
                if n > 0 {
                    f.ascii("ScriptCode description", n.into()).emit()?;
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
                let bytes = cx.read_avail(text.sub(0, 0x10000)).await?;
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
                    fixed(&mut f, name)?;
                }
                i = i.saturating_add(1);
            }
        }
        b"sf32" => {
            let mut i = 0u32;
            while f.remaining() >= 4 && i < 256 {
                fixed(&mut f, "Value")?;
                i = i.saturating_add(1);
            }
        }
        b"uf32" => {
            let mut i = 0u32;
            while f.remaining() >= 4 && i < 256 {
                ufixed(&mut f, "Value")?;
                i = i.saturating_add(1);
            }
        }
        b"ui32" => {
            let mut i = 0u32;
            while f.remaining() >= 4 && i < 256 {
                f.u32("Value").emit()?;
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
                        .desc("u8Fixed8Number")
                        .emit()?;
                }
                _ => {
                    let len = u64::from(n).saturating_mul(2);
                    let table = f.peek_span(len);
                    let at = crate::bytes::to_usize(f.pos());
                    let points = f.block().data.get(at..).unwrap_or_default();
                    let summary = match curve_gamma(points, n) {
                        Some(g) => format!("{n} 16-bit entries, about gamma {g:.2}"),
                        None => format!("{n} 16-bit entries"),
                    };
                    f.node(Node::new("Table").span(table).summary(summary));
                }
            }
        }
        b"para" => {
            let function = f
                .u16("Function type")
                .with(|&t, n| {
                    n.summary(match t {
                        0 => "Y = X^g",
                        1 => "Y = (aX+b)^g for X ≥ -b/a, else 0",
                        2 => "Y = (aX+b)^g + c for X ≥ -b/a, else c",
                        3 => "Y = (aX+b)^g for X ≥ d, else cX",
                        4 => "Y = (aX+b)^g + e for X ≥ d, else cX + f",
                        _ => "unknown function",
                    })
                })
                .emit()?;
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
                fixed(&mut f, name)?;
            }
        }
        b"sig " => {
            f.u32("Signature")
                .with(|&s, n| {
                    let n = n.value(Value::Text(fourcc(&s.to_be_bytes())));
                    match lookup(TECHNOLOGIES, s.into()) {
                        Some(t) => n.summary(t),
                        None => n,
                    }
                })
                .emit()?;
        }
        b"dtim" => {
            for name in ["Year", "Month", "Day", "Hour", "Minute", "Second"] {
                f.u16(name).emit()?;
            }
        }
        b"meas" => {
            f.u32("Standard observer").enumeration(OBSERVERS).emit()?;
            for name in ["Backing X", "Backing Y", "Backing Z"] {
                fixed(&mut f, name)?;
            }
            f.u32("Geometry").enumeration(GEOMETRIES).emit()?;
            f.u32("Flare")
                .with(|&v, n| n.summary(format!("{:.1}%", u16f16(v) * 100.0)))
                .emit()?;
            f.u32("Illuminant").enumeration(ILLUMINANTS).emit()?;
        }
        b"chrm" => {
            let channels = f.u16("Channels").emit()?;
            f.u16("Phosphor/colorant type")
                .enumeration(PHOSPHORS)
                .emit()?;
            for _ in 0..channels.min(16) {
                ufixed(&mut f, "x")?;
                ufixed(&mut f, "y")?;
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
                fixed(&mut f, name)?;
            }
            f.u32("Illuminant type").enumeration(ILLUMINANTS).emit()?;
        }
        b"cicp" => {
            f.u8("Colour primaries")
                .enumeration(CICP_PRIMARIES)
                .emit()?;
            f.u8("Transfer characteristics")
                .enumeration(CICP_TRANSFER)
                .emit()?;
            f.u8("Matrix coefficients")
                .enumeration(CICP_MATRIX)
                .emit()?;
            f.u8("Video full range flag").emit()?;
        }
        b"mft1" | b"mft2" => {
            let inputs = f.u8("Input channels").emit()?;
            let outputs = f.u8("Output channels").emit()?;
            let grid = f.u8("CLUT grid points").emit()?;
            f.u8("Padding").emit()?;
            for name in [
                "e00", "e01", "e02", "e10", "e11", "e12", "e20", "e21", "e22",
            ] {
                fixed(&mut f, name)?;
            }
            let (input_entries, output_entries, size) = if kind.as_slice() == b"mft2" {
                (
                    u64::from(f.u16("Input table entries").emit()?),
                    u64::from(f.u16("Output table entries").emit()?),
                    2u64,
                )
            } else {
                (256, 256, 1)
            };
            let clut = (0..inputs).fold(1u64, |acc, _| acc.saturating_mul(grid.into()));
            for (name, len) in [
                ("Input tables", input_entries.saturating_mul(inputs.into())),
                ("CLUT", clut.saturating_mul(outputs.into())),
                (
                    "Output tables",
                    output_entries.saturating_mul(outputs.into()),
                ),
            ] {
                let bytes = len.saturating_mul(size);
                let at = f.peek_span(bytes);
                f.node(Node::new(name).span(at).summary(human_size(bytes)));
                f.skip(bytes);
            }
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
        b"vcgt" => {
            let kind = f
                .u32("Gamma type")
                .with(|&t, n| {
                    n.summary(match t {
                        0 => "table",
                        1 => "formula",
                        _ => "unknown",
                    })
                })
                .emit()?;
            if kind == 0 {
                let channels = f.u16("Channels").emit()?;
                let count = f.u16("Entries per channel").emit()?;
                let size = f.u16("Entry size").emit()?;
                let len = u64::from(channels)
                    .saturating_mul(count.into())
                    .saturating_mul(size.into());
                f.node(
                    Node::new("Table")
                        .span(f.peek_span(len))
                        .summary(human_size(len)),
                );
            } else if kind == 1 {
                for colour in ["Red", "Green", "Blue"] {
                    for name in ["Gamma", "Minimum", "Maximum"] {
                        f.u32(name)
                            .with(|&v, n| n.value(Value::Float(u16f16(v))).summary(colour))
                            .emit()?;
                    }
                }
            }
        }
        b"ncl2" => {
            f.u32("Vendor flags").hex().emit()?;
            let count = f.u32("Colours").emit()?;
            let coords = f.u32("Device coordinates").emit()?;
            f.ascii("Prefix", 32).emit()?;
            f.ascii("Suffix", 32).emit()?;
            let each = 38u64.saturating_add(u64::from(coords).saturating_mul(2));
            let len = u64::from(count).saturating_mul(each);
            f.node(
                Node::new("Colours")
                    .span(f.peek_span(len))
                    .summary(format!("{count} named colours")),
            );
        }
        b"clrt" => {
            let count = f.u32("Colorants").emit()?;
            for _ in 0..count.min(64) {
                f.ascii("Name", 32).emit()?;
                f.u16("PCS 1").emit()?;
                f.u16("PCS 2").emit()?;
                f.u16("PCS 3").emit()?;
            }
        }
        b"clro" => {
            let count = f.u32("Colorants").emit()?;
            for _ in 0..count.min(64) {
                f.u8("Colorant").emit()?;
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

/// The gamma a sampled curve approximates, from its midpoint.
fn curve_gamma(points: &[u8], n: u32) -> Option<f64> {
    let i = n / 2;
    let y = f64::from(u16_be(
        points,
        crate::bytes::to_usize(u64::from(i).saturating_mul(2)),
    )?) / 65535.0;
    let x = f64::from(i) / f64::from(n.checked_sub(1)?);
    (x > 0.0 && x < 1.0 && y > 0.0 && y < 1.0).then(|| y.ln() / x.ln())
}
