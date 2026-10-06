//! Windows and OS/2 bitmaps (BMP) and device-independent bitmaps (DIB).
//!
//! A BMP is a 14-byte file header followed by a DIB: an info header whose
//! size identifies its version (CORE, OS/2 2.x, INFO, V2–V5), optional color
//! masks, an optional palette and the pixel array. ICO and CUR files embed
//! DIBs without the file header; [`dib`] serves both.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{ColorOrder, dims, palette, region};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "bmp",
    title: "Windows bitmap",
    extensions: &["bmp", "dib", "rle"],
    mime: "image/bmp",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const HEADER_SIZES: &[u32] = &[12, 16, 40, 52, 56, 64, 108, 124];

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"BM") && u32_le(h.data, 14).is_some_and(|s| HEADER_SIZES.contains(&s))
}

const COMPRESSION: EnumTable = &[
    (0, "BI_RGB"),
    (1, "BI_RLE8"),
    (2, "BI_RLE4"),
    (3, "BI_BITFIELDS"),
    (4, "BI_JPEG"),
    (5, "BI_PNG"),
    (6, "BI_ALPHABITFIELDS"),
    (11, "BI_CMYK"),
    (12, "BI_CMYKRLE8"),
    (13, "BI_CMYKRLE4"),
];

const OS2_COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "RLE8"),
    (2, "RLE4"),
    (3, "Huffman 1D"),
    (4, "RLE24"),
];

const COLOR_SPACE: EnumTable = &[
    (0, "LCS_CALIBRATED_RGB"),
    (0x7352_4742, "LCS_sRGB"),
    (0x5769_6e20, "LCS_WINDOWS_COLOR_SPACE"),
    (0x4c49_4e4b, "PROFILE_LINKED"),
    (0x4d42_4544, "PROFILE_EMBEDDED"),
];

const INTENT: EnumTable = &[
    (1, "LCS_GM_BUSINESS (saturation)"),
    (2, "LCS_GM_GRAPHICS (relative colorimetric)"),
    (4, "LCS_GM_IMAGES (perceptual)"),
    (8, "LCS_GM_ABS_COLORIMETRIC"),
];

const PROFILE_LINKED: u32 = 0x4c49_4e4b;
const PROFILE_EMBEDDED: u32 = 0x4d42_4544;

record! {
    /// BITMAPFILEHEADER
    pub struct FileHeader {
        magic: ascii[2] "bfType",
        size: u32 "bfSize" .desc("File size in bytes"),
        reserved1: u16 "bfReserved1",
        reserved2: u16 "bfReserved2",
        offset: u32 "bfOffBits" .hex() .desc("Offset of the pixel array"),
    }
}

/// What the rest of the dissection needs from an info header.
#[derive(Clone, Debug, Default)]
pub struct Info {
    pub size: u32,
    pub width: i64,
    pub height: i64,
    pub bit_count: u16,
    pub compression: u32,
    pub size_image: u32,
    pub colors_used: u32,
    pub color_space: u32,
    pub profile_offset: u32,
    pub profile_size: u32,
}

impl Info {
    fn is_core(&self) -> bool {
        self.size == 12
    }

    fn is_os2(&self) -> bool {
        self.size == 16 || self.size == 64
    }

    pub fn version(&self) -> &'static str {
        version_name(self.size)
    }

    pub fn compression_name(&self) -> String {
        let table = if self.is_os2() {
            OS2_COMPRESSION
        } else {
            COMPRESSION
        };
        lookup(table, self.compression.into())
            .map_or_else(|| format!("compression {}", self.compression), str::to_owned)
    }

    /// Bytes per row of the pixel array (rows are padded to 4 bytes).
    fn stride(&self) -> u64 {
        let bits = self
            .width
            .unsigned_abs()
            .saturating_mul(self.bit_count.into());
        (bits.saturating_add(31) / 32).saturating_mul(4)
    }

    fn palette_entries(&self) -> u64 {
        if self.colors_used != 0 {
            self.colors_used.into()
        } else if self.bit_count <= 8 {
            1u64.checked_shl(self.bit_count.into()).unwrap_or(0)
        } else {
            0
        }
    }

    /// Size of the color masks stored after a 40-byte header.
    fn mask_bytes(&self) -> u64 {
        match (self.size, self.compression) {
            (40, 3) => 12,
            (40, 6) => 16,
            _ => 0,
        }
    }
}

fn version_name(size: u32) -> &'static str {
    match size {
        12 => "BITMAPCOREHEADER",
        16 | 64 => "OS/2 BITMAPINFOHEADER2",
        40 => "BITMAPINFOHEADER",
        52 => "BITMAPV2INFOHEADER",
        56 => "BITMAPV3INFOHEADER",
        108 => "BITMAPV4HEADER",
        124 => "BITMAPV5HEADER",
        _ => "unknown header",
    }
}

/// Fixed-point 2.30, as in `CIEXYZ`.
fn fxpt2dot30(v: u32) -> String {
    format!("{:.4}", f64::from(v) / f64::from(1u32 << 30))
}

/// Fixed-point 16.16, as used for gamma.
fn fxpt16dot16(v: u32) -> String {
    format!("{:.4}", f64::from(v) / 65536.0)
}

fn info_header(f: &mut Fields<'_>, _: &()) -> Result<Info> {
    let size = f
        .u32("biSize")
        .with(|&s, n| n.summary(version_name(s)))
        .emit()?;
    let mut info = Info {
        size,
        ..Info::default()
    };
    if size == 12 {
        info.width = f.u16("bcWidth").emit()?.into();
        info.height = f.u16("bcHeight").emit()?.into();
        f.u16("bcPlanes").emit()?;
        info.bit_count = f.u16("bcBitCount").desc("Bits per pixel").emit()?;
        return Ok(info);
    }
    info.width = f.i32("biWidth").emit()?.into();
    info.height = f
        .i32("biHeight")
        .desc("Positive: bottom-up rows; negative: top-down")
        .emit()?
        .into();
    f.u16("biPlanes").emit()?;
    info.bit_count = f.u16("biBitCount").desc("Bits per pixel").emit()?;
    if f.remaining() < 4 {
        return Ok(info);
    }
    let table = if info.is_os2() {
        OS2_COMPRESSION
    } else {
        COMPRESSION
    };
    info.compression = f.u32("biCompression").enumeration(table).emit()?;
    info.size_image = f
        .u32("biSizeImage")
        .desc("Size of the pixel array (may be 0 for BI_RGB)")
        .emit()?;
    f.int::<i32>("biXPelsPerMeter").emit()?;
    f.int::<i32>("biYPelsPerMeter").emit()?;
    info.colors_used = f
        .u32("biClrUsed")
        .desc("Palette entries (0: the maximum for the bit depth)")
        .emit()?;
    f.u32("biClrImportant").emit()?;
    if size == 64 {
        f.u16("Units").desc("0 = pixels per metre").emit()?;
        f.u16("Reserved").emit()?;
        f.u16("Recording")
            .desc("0 = rows bottom-up")
            .emit()?;
        f.u16("Rendering").desc("Halftoning algorithm").emit()?;
        f.u32("Size1").desc("Halftoning parameter").emit()?;
        f.u32("Size2").desc("Halftoning parameter").emit()?;
        f.u32("Color encoding").desc("0 = RGB").emit()?;
        f.u32("Identifier").hex().emit()?;
        return Ok(info);
    }
    if size < 52 {
        return Ok(info);
    }
    f.u32("bV5RedMask").hex().emit()?;
    f.u32("bV5GreenMask").hex().emit()?;
    f.u32("bV5BlueMask").hex().emit()?;
    if size < 56 {
        return Ok(info);
    }
    f.u32("bV5AlphaMask").hex().emit()?;
    if size < 108 {
        return Ok(info);
    }
    info.color_space = f.u32("bV5CSType").enumeration(COLOR_SPACE).emit()?;
    for name in [
        "Red X", "Red Y", "Red Z", "Green X", "Green Y", "Green Z", "Blue X", "Blue Y", "Blue Z",
    ] {
        f.u32(name)
            .with(|&v, n| n.summary(fxpt2dot30(v)))
            .desc("CIEXYZ endpoint, fixed-point 2.30")
            .emit()?;
    }
    for name in ["bV5GammaRed", "bV5GammaGreen", "bV5GammaBlue"] {
        f.u32(name)
            .with(|&v, n| n.summary(fxpt16dot16(v)))
            .desc("Fixed-point 16.16")
            .emit()?;
    }
    if size < 124 {
        return Ok(info);
    }
    f.u32("bV5Intent").enumeration(INTENT).emit()?;
    info.profile_offset = f
        .u32("bV5ProfileData")
        .hex()
        .desc("Offset of the profile from the start of this header")
        .emit()?;
    info.profile_size = f.u32("bV5ProfileSize").emit()?;
    f.u32("bV5Reserved").emit()?;
    Ok(info)
}

fn masks(f: &mut Fields<'_>, _: &()) -> Result<()> {
    for name in ["Red mask", "Green mask", "Blue mask", "Alpha mask"] {
        if f.remaining() < 4 {
            break;
        }
        f.u32(name).hex().emit()?;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, FileHeader::SIZE);
    let header = parse(&cx, header_span, LE, &(), FileHeader::layout).await?;
    cx.emit(FileHeader::node("File Header", header_span, LE));
    let info = dib(
        &cx,
        input,
        file.tail(FileHeader::SIZE),
        Some(u64::from(header.offset).saturating_sub(FileHeader::SIZE)),
        false,
    )
    .await?;
    cx.annotate(describe(&info));
    let end = u64::from(header.size);
    if header.size != 0 && end < file.len && end > FileHeader::SIZE {
        let rest = file.tail(end);
        cx.emit(
            embedded("Trailing data", input.nested(rest))
                .summary(format!("{:#x} bytes after bfSize", rest.len)),
        );
    }
    Ok(())
}

/// "640×480, 24-bit, BI_RGB".
pub fn describe(info: &Info) -> String {
    let mut out = format!(
        "{}, {}-bit, {}",
        dims(info.width.unsigned_abs(), info.height.unsigned_abs()),
        info.bit_count,
        info.compression_name()
    );
    if info.height < 0 {
        out.push_str(", top-down");
    }
    out
}

/// Dissects a DIB in `span`: info header, masks, palette and pixels.
///
/// `pixels` is the offset of the pixel array relative to `span` when known
/// (from a file header); otherwise the pixels follow the palette. `icon`
/// DIBs store twice the height (an XOR image and an AND mask).
pub async fn dib(
    cx: &Cx,
    input: Input,
    span: Span,
    pixels: Option<u64>,
    icon: bool,
) -> Result<Info> {
    let size_bytes = cx.read(span.sub(0, 4)).await?;
    let size = u32_le(&size_bytes, 0).unwrap_or(0);
    if !(12..=124).contains(&size) {
        return Err(
            Diagnostic::malformed(format!("unsupported info header size {size}"))
                .at(span.sub(0, 4)),
        );
    }
    let header_span = span.sub(0, size.into());
    let info = parse(cx, header_span, LE, &(), info_header).await?;
    cx.emit(
        struct_node(info.version(), header_span, LE, (), info_header).summary(describe(&info)),
    );
    let mut pos = u64::from(size);

    let mask_len = info.mask_bytes();
    if mask_len > 0 {
        cx.emit(struct_node("Color masks", span.sub(pos, mask_len), LE, (), masks));
        pos = pos.saturating_add(mask_len);
    }

    let entry = if info.is_core() {
        ColorOrder::Bgr
    } else {
        ColorOrder::Bgrx
    };
    let mut palette_len = info.palette_entries().saturating_mul(entry.size());
    if let Some(end) = pixels {
        palette_len = palette_len.min(end.saturating_sub(pos));
    }
    if palette_len > 0 {
        cx.emit(palette("Palette", span.sub(pos, palette_len), entry));
        pos = pos.saturating_add(palette_len);
    }

    if info.color_space == PROFILE_EMBEDDED && info.profile_size > 0 {
        let profile = span.sub(info.profile_offset.into(), info.profile_size.into());
        cx.emit(embedded("ICC profile", input.nested(profile)));
    } else if info.color_space == PROFILE_LINKED && info.profile_size > 0 {
        let at = span.sub(info.profile_offset.into(), info.profile_size.into());
        let name = cx.read_avail(at).await?;
        cx.emit(
            Node::new("Linked profile")
                .span(at)
                .value(super::text(crate::text::until_nul(&name))),
        );
    }

    let start = pixels.unwrap_or(pos);
    let rows = if icon {
        info.height.unsigned_abs() / 2
    } else {
        info.height.unsigned_abs()
    };
    let computed = info.stride().saturating_mul(rows);
    match info.compression {
        4 | 5 if !info.is_os2() => {
            let len = if info.size_image != 0 {
                info.size_image.into()
            } else {
                span.len.saturating_sub(start)
            };
            let what = if info.compression == 4 { "JPEG" } else { "PNG" };
            cx.emit(
                embedded("Pixel data", input.nested(span.sub(start, len)))
                    .summary(format!("{what} stream")),
            );
        }
        0 | 3 | 6 => {
            cx.emit(region("Pixel array", span, start, computed).summary(format!(
                "{rows} rows of {:#x} bytes",
                info.stride()
            )));
        }
        _ => {
            let len = if info.size_image != 0 {
                info.size_image.into()
            } else {
                span.len.saturating_sub(start)
            };
            cx.emit(
                region("Pixel data", span, start, len).summary(info.compression_name()),
            );
        }
    }
    if icon {
        let mask_stride = (info.width.unsigned_abs().saturating_add(31) / 32).saturating_mul(4);
        let mask_start = start.saturating_add(computed);
        cx.emit(
            region(
                "AND mask",
                span,
                mask_start,
                mask_stride.saturating_mul(rows),
            )
            .summary("1-bit transparency mask"),
        );
    }
    Ok(info)
}
