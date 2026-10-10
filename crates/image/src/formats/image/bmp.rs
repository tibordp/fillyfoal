//! Windows and OS/2 bitmaps (BMP) and device-independent bitmaps (DIB).
//!
//! A BMP is a 14-byte file header followed by a DIB: an info header whose
//! size identifies its version (OS/2 1.x core, OS/2 2.x, INFO, V2–V5),
//! optional color masks, an optional palette and the pixel array (plain,
//! run-length encoded, or an embedded JPEG or PNG stream). ICO and CUR
//! files embed DIBs without the file header; [`dib`] serves both.
//!
//! OS/2 also wrote icons and pointers (`IC`, `PT`, `CI`, `CP`: an AND/XOR
//! mask bitmap, plus a color bitmap for the color kinds) and bitmap arrays
//! (`BA`: a linked list of such files, one per display resolution), whose
//! pixel offsets count from the start of the whole file.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::fmt::plural;
use crate::formats::util::val::text;
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
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

/// OS/2 file types besides `BM`.
const OS2_TYPES: &[&[u8; 2]] = &[b"BA", b"CI", b"CP", b"IC", b"PT"];

fn probe(h: &Head<'_>) -> bool {
    if h.starts_with(b"BM") {
        return u32_le(h.data, 14).is_some_and(|s| HEADER_SIZES.contains(&s));
    }
    // The OS/2 types are weaker magics: also check that the bitmap header
    // (after the 14-byte array header for `BA`) has one plane and a
    // plausible bit count.
    let Some(kind) = h.data.get(..2) else {
        return false;
    };
    if !OS2_TYPES.iter().any(|t| t.as_slice() == kind) {
        return false;
    }
    let at: usize = if kind == b"BA" { 14 } else { 0 };
    let inner = h.data.get(at..at.saturating_add(2));
    if kind == b"BA"
        && !inner.is_some_and(|t| {
            t == b"BM" || (t != b"BA" && OS2_TYPES.iter().any(|o| o.as_slice() == t))
        })
    {
        return false;
    }
    let header = at.saturating_add(14);
    let Some(size) = u32_le(h.data, header) else {
        return false;
    };
    let (planes, bits) = if size == 12 {
        (
            u16_le(h.data, header.saturating_add(8)),
            u16_le(h.data, header.saturating_add(10)),
        )
    } else {
        (
            u16_le(h.data, header.saturating_add(12)),
            u16_le(h.data, header.saturating_add(14)),
        )
    };
    HEADER_SIZES.contains(&size)
        && planes == Some(1)
        && bits.is_some_and(|b| matches!(b, 1 | 4 | 8 | 16 | 24 | 32))
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

const OS2_RENDERING: EnumTable = &[
    (0, "none"),
    (1, "error diffusion"),
    (2, "PANDA"),
    (3, "super-circle"),
];

const FILE_TYPES: EnumTable = &[
    (0x4d42, "Windows or OS/2 bitmap"),
    (0x4142, "OS/2 bitmap array"),
    (0x4943, "OS/2 color icon"),
    (0x5043, "OS/2 color pointer"),
    (0x4349, "OS/2 icon"),
    (0x5450, "OS/2 pointer"),
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

const FILE_HEADER_SIZE: u64 = 14;
const ARRAY_HEADER_SIZE: u64 = 14;
/// Bitmap array entries listed at most (each must also lie further into
/// the file than the one before).
const MAX_ARRAY_ENTRIES: u64 = 4096;

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
    /// Red, green, blue and alpha masks, where the header or the bitfields
    /// after it give them.
    pub masks: Option<[u32; 4]>,
    /// The end of the header, masks and palette, relative to the DIB.
    pub headers_end: u64,
}

impl Info {
    fn is_core(&self) -> bool {
        self.size == 12
    }

    /// OS/2 2.x headers are 16 to 64 bytes; 40 is read as Windows'
    /// BITMAPINFOHEADER, which it is laid out like.
    fn is_os2(&self) -> bool {
        is_os2_size(self.size)
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
        lookup(table, self.compression.into()).map_or_else(
            || format!("compression {}", self.compression),
            str::to_owned,
        )
    }

    /// The run-length encoding used, if any: bits per encoded value.
    fn rle(&self) -> Option<u8> {
        match (self.is_os2(), self.compression) {
            (_, 1) => Some(8),
            (_, 2) => Some(4),
            (true, 4) => Some(24),
            _ => None,
        }
    }

    /// Whether the pixels are an embedded JPEG (4) or PNG (5) stream.
    fn embedded_stream(&self) -> Option<&'static str> {
        match (self.is_os2(), self.compression) {
            (false, 4) => Some("JPEG"),
            (false, 5) => Some("PNG"),
            _ => None,
        }
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

    /// Whether the masks matter (bit fields compression, or a V4/V5
    /// header with 16 or 32 bits per pixel).
    fn uses_masks(&self) -> bool {
        matches!(self.compression, 3 | 6) && !self.is_os2()
    }
}

fn is_os2_size(size: u32) -> bool {
    (16..=64).contains(&size) && !matches!(size, 40 | 52 | 56)
}

fn version_name(size: u32) -> &'static str {
    match size {
        12 => "BITMAPCOREHEADER",
        40 => "BITMAPINFOHEADER",
        52 => "BITMAPV2INFOHEADER",
        56 => "BITMAPV3INFOHEADER",
        108 => "BITMAPV4HEADER",
        124 => "BITMAPV5HEADER",
        s if is_os2_size(s) => "OS/2 BITMAPINFOHEADER2",
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

/// "bits 11–15" for a channel mask; flags masks that are not contiguous.
fn mask_summary(&v: &u32, n: Node) -> Node {
    if v == 0 {
        return n.summary("none");
    }
    let low = v.trailing_zeros();
    let count = v.count_ones();
    let high = low.saturating_add(count).saturating_sub(1);
    let n = n.summary(format!("{count} bits ({low}–{high})"));
    if v.checked_shr(low)
        .is_some_and(|s| s.wrapping_add(1) & s != 0)
    {
        n.diag(Diagnostic::warning("the mask's bits are not contiguous"))
    } else {
        n
    }
}

/// "5-6-5", "8-8-8-8 RGBA".
fn mask_layout(masks: &[u32; 4]) -> String {
    let [r, g, b, a] = masks.map(u32::count_ones);
    if a == 0 {
        format!("{r}-{g}-{b}")
    } else {
        format!("{r}-{g}-{b}-{a} RGBA")
    }
}

fn info_header(f: &mut Fields<'_>, _: &()) -> Result<Info> {
    let peek = f.u32("Size").get().unwrap_or(0);
    f.seek(0);
    let core = peek == 12;
    let os2 = is_os2_size(peek);
    let size = f
        .u32(if core {
            "bcSize"
        } else if os2 {
            "cbFix"
        } else {
            "biSize"
        })
        .with(|&s, n| n.summary(version_name(s)))
        .desc("Size of this header, which identifies its version")
        .emit()?;
    let mut info = Info {
        size,
        ..Info::default()
    };
    if core {
        info.width = f.u16("bcWidth").emit()?.into();
        info.height = f
            .u16("bcHeight")
            .desc("Rows are stored bottom-up")
            .emit()?
            .into();
        f.u16("bcPlanes").check(one_plane).emit()?;
        info.bit_count = f
            .u16("bcBitCount")
            .desc("Bits per pixel: 1, 4, 8 or 24")
            .emit()?;
        return Ok(info);
    }
    let name = |windows: &'static str, os2_name: &'static str| if os2 { os2_name } else { windows };
    info.width = f.i32(name("biWidth", "cx")).emit()?.into();
    info.height = f
        .i32(name("biHeight", "cy"))
        .with(|&h, n| {
            n.summary(if h < 0 {
                "negative: rows stored top-down"
            } else {
                "positive: rows stored bottom-up"
            })
        })
        .emit()?
        .into();
    f.u16(name("biPlanes", "cPlanes")).check(one_plane).emit()?;
    info.bit_count = f
        .u16(name("biBitCount", "cBitCount"))
        .desc("Bits per pixel: 1, 4, 8, 16, 24 or 32 (0: given by the embedded JPEG or PNG)")
        .check(|&b| {
            (!matches!(b, 0 | 1 | 2 | 4 | 8 | 16 | 24 | 32 | 64))
                .then(|| Diagnostic::warning("unusual bit count"))
        })
        .emit()?;
    let table = if os2 { OS2_COMPRESSION } else { COMPRESSION };
    if f.remaining() < 4 {
        return Ok(info);
    }
    info.compression = f
        .u32(name("biCompression", "ulCompression"))
        .enumeration(table)
        .emit()?;
    if f.remaining() < 4 {
        return Ok(info);
    }
    info.size_image = f
        .u32(name("biSizeImage", "cbImage"))
        .desc("Size of the pixel data in bytes (may be 0 for uncompressed bitmaps)")
        .emit()?;
    let ppm = |&v: &i32, n: Node| {
        if v > 0 {
            n.summary(format!("{:.0} dpi", f64::from(v) * 0.0254))
        } else {
            n
        }
    };
    if f.remaining() < 4 {
        return Ok(info);
    }
    f.int::<i32>(name("biXPelsPerMeter", "cxResolution"))
        .with(ppm)
        .emit()?;
    if f.remaining() < 4 {
        return Ok(info);
    }
    f.int::<i32>(name("biYPelsPerMeter", "cyResolution"))
        .with(ppm)
        .emit()?;
    if f.remaining() < 4 {
        return Ok(info);
    }
    info.colors_used = f
        .u32(name("biClrUsed", "cclrUsed"))
        .desc("Palette entries (0: the maximum for the bit depth)")
        .emit()?;
    if f.remaining() < 4 {
        return Ok(info);
    }
    f.u32(name("biClrImportant", "cclrImportant"))
        .desc("Colors needed to display the image (0: all)")
        .emit()?;
    if os2 {
        os2_tail(f)?;
        return Ok(info);
    }
    if size < 52 {
        return Ok(info);
    }
    let red = f.u32("bV5RedMask").hex().with(mask_summary).emit()?;
    let green = f.u32("bV5GreenMask").hex().with(mask_summary).emit()?;
    let blue = f.u32("bV5BlueMask").hex().with(mask_summary).emit()?;
    let alpha = if size >= 56 {
        f.u32("bV5AlphaMask").hex().with(mask_summary).emit()?
    } else {
        0
    };
    info.masks = Some([red, green, blue, alpha]);
    if size < 108 {
        return Ok(info);
    }
    info.color_space = f
        .u32("bV5CSType")
        .enumeration(COLOR_SPACE)
        .desc("The color space: calibrated by the endpoints and gamma below, sRGB, the system default, or an ICC profile")
        .emit()?;
    for name in [
        "Red X", "Red Y", "Red Z", "Green X", "Green Y", "Green Z", "Blue X", "Blue Y", "Blue Z",
    ] {
        f.u32(name)
            .with(|&v, n| n.summary(fxpt2dot30(v)))
            .desc("CIEXYZ endpoint, fixed-point 2.30 (used with LCS_CALIBRATED_RGB)")
            .emit()?;
    }
    for name in ["bV5GammaRed", "bV5GammaGreen", "bV5GammaBlue"] {
        f.u32(name)
            .with(|&v, n| n.summary(fxpt16dot16(v)))
            .desc("Tone response, fixed-point 16.16 (used with LCS_CALIBRATED_RGB)")
            .emit()?;
    }
    if size < 124 {
        return Ok(info);
    }
    f.u32("bV5Intent").enumeration(INTENT).emit()?;
    info.profile_offset = f
        .u32("bV5ProfileData")
        .hex()
        .desc("Offset of the profile (embedded data or a linked file name) from the start of this header")
        .emit()?;
    info.profile_size = f.u32("bV5ProfileSize").emit()?;
    f.u32("bV5Reserved").emit()?;
    Ok(info)
}

/// The OS/2 2.x fields after `cclrImportant`, as far as the header goes.
fn os2_tail(f: &mut Fields<'_>) -> Result<()> {
    if f.remaining() < 2 {
        return Ok(());
    }
    f.u16("usUnits").desc("0 = pixels per metre").emit()?;
    if f.remaining() < 2 {
        return Ok(());
    }
    f.u16("usReserved").emit()?;
    if f.remaining() < 2 {
        return Ok(());
    }
    f.u16("usRecording")
        .desc("0 = rows bottom-up (the only defined value)")
        .emit()?;
    if f.remaining() < 2 {
        return Ok(());
    }
    f.u16("usRendering")
        .enumeration(OS2_RENDERING)
        .desc("Halftoning algorithm")
        .emit()?;
    if f.remaining() < 4 {
        return Ok(());
    }
    f.u32("cSize1").desc("Halftoning parameter").emit()?;
    if f.remaining() < 4 {
        return Ok(());
    }
    f.u32("cSize2").desc("Halftoning parameter").emit()?;
    if f.remaining() < 4 {
        return Ok(());
    }
    f.u32("ulColorEncoding").desc("0 = RGB").emit()?;
    if f.remaining() < 4 {
        return Ok(());
    }
    f.u32("ulIdentifier")
        .hex()
        .desc("For the application's use")
        .emit()?;
    Ok(())
}

fn one_plane(&v: &u16) -> Option<Diagnostic> {
    (v != 1).then(|| Diagnostic::warning("must be 1"))
}

fn masks(f: &mut Fields<'_>, _: &()) -> Result<()> {
    for name in ["Red mask", "Green mask", "Blue mask", "Alpha mask"] {
        if f.remaining() < 4 {
            break;
        }
        f.u32(name).hex().with(mask_summary).emit()?;
    }
    Ok(())
}

/// The 14-byte file header; OS/2 icons and pointers keep their hotspot in
/// what Windows calls the reserved fields.
fn file_header(f: &mut Fields<'_>, _: &()) -> Result<(u16, u32, u32)> {
    let peek = f.u16("Type").get().unwrap_or(0);
    f.seek(0);
    let os2 = peek != 0x4d42;
    let kind = f
        .u16(if os2 { "usType" } else { "bfType" })
        .with(|&t, n| {
            let b = t.to_le_bytes();
            n.value(text(String::from_utf8_lossy(&b).into_owned()))
                .summary(lookup(FILE_TYPES, t.into()).unwrap_or("unknown"))
        })
        .emit()?;
    let size = f
        .u32(if os2 { "cbSize" } else { "bfSize" })
        .desc("File size in bytes (OS/2: the size of this header, or of the bitmap)")
        .emit()?;
    if os2 {
        f.int::<i16>("xHotspot").desc("Pointer hotspot").emit()?;
        f.int::<i16>("yHotspot").desc("Pointer hotspot").emit()?;
    } else {
        f.u16("bfReserved1").emit()?;
        f.u16("bfReserved2").emit()?;
    }
    let offset = f
        .u32(if os2 { "offBits" } else { "bfOffBits" })
        .hex()
        .desc("Offset of the pixel array from the start of the file")
        .emit()?;
    Ok((kind, size, offset))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 2)).await?;
    if magic == b"BA" {
        return array(&cx, input).await;
    }
    let (kind, info) = bitmap_file(&cx, input, 0).await?;
    let mut line = describe(&info);
    if kind != 0x4d42 {
        line = format!(
            "{}, {line}",
            lookup(FILE_TYPES, kind.into()).unwrap_or("OS/2 bitmap")
        );
    }
    cx.annotate(line);
    Ok(())
}

/// A file header at `at` (relative to the input) and the bitmap(s) it
/// introduces: one for `BM`, `IC` and `PT`; for the color kinds `CI` and
/// `CP` a monochrome AND/XOR mask, then a second header and the color
/// bitmap. Pixel offsets count from the start of the input.
async fn bitmap_file(cx: &Cx, input: Input, at: u64) -> Result<(u16, Info)> {
    let file = input.span;
    let header_span = file.sub(at, FILE_HEADER_SIZE);
    let (kind, size, offset) = parse(cx, header_span, LE, &(), file_header).await?;
    let mut header = struct_node("File Header", header_span, LE, (), file_header);
    if kind == 0x4d42 && at == 0 && size != 0 && u64::from(size) != file.len {
        header = header.diag(Diagnostic::note(format!(
            "the header gives a file size of {size}, the file has {}",
            file.len
        )));
    }
    cx.emit(header);
    let dib_at = at.saturating_add(FILE_HEADER_SIZE);
    let dib_span = file.tail(dib_at);
    let pixels = Some(u64::from(offset).saturating_sub(dib_at));
    let mask = matches!(kind, 0x4943 | 0x5043 | 0x4349 | 0x5450);
    let info = dib_at_with(cx, input, dib_span, pixels, false, mask).await?;
    if !matches!(kind, 0x4943 | 0x5043) {
        if kind == 0x4d42 && at == 0 {
            let end = u64::from(size);
            if size != 0 && end < file.len && end > FILE_HEADER_SIZE {
                let rest = file.tail(end);
                cx.emit(
                    embedded("Trailing data", input.nested(rest))
                        .summary(format!("{} after bfSize", human_size(rest.len))),
                );
            }
        }
        return Ok((kind, info));
    }
    // Color icons and pointers: the color bitmap's header follows the
    // mask's header and palette.
    let next = dib_at.saturating_add(info.headers_end);
    let second = file.sub(next, FILE_HEADER_SIZE);
    let (_, _, color_offset) = parse(cx, second, LE, &(), file_header).await?;
    cx.emit(struct_node(
        "Color bitmap file header",
        second,
        LE,
        (),
        file_header,
    ));
    let color_at = next.saturating_add(FILE_HEADER_SIZE);
    let color = dib_at_with(
        cx,
        input,
        file.tail(color_at),
        Some(u64::from(color_offset).saturating_sub(color_at)),
        false,
        false,
    )
    .await?;
    Ok((kind, color))
}

/// An OS/2 bitmap array: a chain of 14-byte headers, each followed by a
/// bitmap (or icon/pointer) file, one per display resolution.
async fn array(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut index = 0u64;
    let mut first: Option<String> = None;
    loop {
        let head = cx
            .read(file.sub(pos, ARRAY_HEADER_SIZE.saturating_add(2)))
            .await?;
        if head.get(..2) != Some(b"BA") {
            cx.diag(
                Diagnostic::malformed("expected a bitmap array header (BA)").at(file.sub(pos, 2)),
            );
            break;
        }
        let next = u32_le(&head, 6).unwrap_or(0);
        let (cx_display, cy_display) = (
            u16_le(&head, 10).unwrap_or(0),
            u16_le(&head, 12).unwrap_or(0),
        );
        let inner = u16_le(&head, 14).unwrap_or(0);
        let end = if next == 0 { file.len } else { u64::from(next) };
        let span = file.sub(pos, end.saturating_sub(pos));
        let mut summary = lookup(FILE_TYPES, inner.into())
            .unwrap_or("unknown")
            .to_owned();
        if cx_display != 0 || cy_display != 0 {
            summary = format!("{summary}, for a {} display", dims(cx_display, cy_display));
        }
        if first.is_none() {
            first = Some(summary.clone());
        }
        cx.push(
            Node::new(format!("Array entry {index}"))
                .span(span)
                .summary(summary)
                .lazy(array_entry, (input, pos)),
        )
        .await;
        index = index.saturating_add(1);
        if next == 0 {
            break;
        }
        if u64::from(next) <= pos || u64::from(next) >= file.len {
            cx.diag(Diagnostic::malformed(format!(
                "bad offset of the next array entry: {next:#x}"
            )));
            break;
        }
        if index >= MAX_ARRAY_ENTRIES {
            cx.diag(Diagnostic::limit(format!(
                "more than {MAX_ARRAY_ENTRIES} array entries"
            )));
            break;
        }
        pos = next.into();
    }
    cx.annotate(format!(
        "OS/2 bitmap array, {}{}",
        if index == 1 {
            "1 entry".to_owned()
        } else {
            format!("{index} entries")
        },
        first.map(|f| format!("; first: {f}")).unwrap_or_default()
    ));
    Ok(())
}

async fn array_entry(cx: Cx, (input, pos): (Input, u64)) -> Result<()> {
    let span = input.span.sub(pos, ARRAY_HEADER_SIZE);
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Type", 2).emit()?;
    f.u32("Header size")
        .desc("Size of the array header with the file and info headers it introduces")
        .emit()?;
    f.u32("Next entry offset")
        .hex()
        .desc("Offset of the next array header from the start of the file; 0 for the last")
        .emit()?;
    f.u16("Display width")
        .desc("Width of the display this bitmap is for; 0 = any")
        .emit()?;
    f.u16("Display height")
        .desc("Height of the display this bitmap is for; 0 = any")
        .emit()?;
    let (_, info) = bitmap_file(&cx, input, pos.saturating_add(ARRAY_HEADER_SIZE)).await?;
    cx.annotate(describe(&info));
    Ok(())
}

/// "640×480, 24-bit, BI_RGB".
pub fn describe(info: &Info) -> String {
    let size = dims(info.width.unsigned_abs(), info.height.unsigned_abs());
    let mut out = if info.bit_count == 0 {
        // JPEG and PNG pixel data carry their own depth.
        format!("{size}, {}", info.compression_name())
    } else {
        format!(
            "{size}, {}-bit, {}",
            info.bit_count,
            info.compression_name()
        )
    };
    if let Some(m) = info.masks.as_ref().filter(|_| info.uses_masks()) {
        out = format!("{out} {}", mask_layout(m));
    } else if info.compression == 0 && info.bit_count == 16 && !info.is_os2() {
        // Without bit fields, 16-bit pixels are 5-5-5 with the top bit unused.
        out.push_str(" 5-5-5");
    }
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
    dib_at_with(cx, input, span, pixels, icon, false).await
}

/// [`dib`]; `mask` marks an OS/2 icon or pointer mask: one bitmap holding
/// the AND mask and the XOR mask, each half its height.
async fn dib_at_with(
    cx: &Cx,
    input: Input,
    span: Span,
    pixels: Option<u64>,
    icon: bool,
    mask: bool,
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
    let mut info = parse(cx, header_span, LE, &(), info_header).await?;
    let mut header =
        struct_node(info.version(), header_span, LE, (), info_header).summary(describe(&info));
    if mask {
        header = header.desc(
            "An OS/2 icon or pointer mask: the AND mask and the XOR mask stacked, so the height is twice the icon's",
        );
    }
    cx.emit(header);
    let mut pos = u64::from(size);

    let mask_len = info.mask_bytes();
    if mask_len > 0 {
        let block = cx.block(span.sub(pos, mask_len)).await?;
        let mut m = [0u32; 4];
        for (i, slot) in m.iter_mut().enumerate() {
            *slot = u32_le(&block.data, i.saturating_mul(4)).unwrap_or(0);
        }
        info.masks = Some(m);
        cx.emit(
            struct_node("Color masks", span.sub(pos, mask_len), LE, (), masks)
                .summary(mask_layout(&m)),
        );
        pos = pos.saturating_add(mask_len);
    }

    let entry = if info.is_core() {
        ColorOrder::Bgr
    } else {
        ColorOrder::Bgrx
    };
    let mut palette_len = info.palette_entries().saturating_mul(entry.size());
    if let Some(end) = pixels.filter(|&end| end >= pos) {
        palette_len = palette_len.min(end.saturating_sub(pos));
    }
    if palette_len > 0 {
        let mut node = palette("Palette", span.sub(pos, palette_len), entry);
        if info.bit_count > 8 {
            node = node
                .desc("A palette for displays with fewer colors; the pixels hold colors directly");
        }
        cx.emit(node);
        pos = pos.saturating_add(palette_len);
    }
    info.headers_end = pos;

    if info.color_space == PROFILE_EMBEDDED && info.profile_size > 0 {
        let profile = span.sub(info.profile_offset.into(), info.profile_size.into());
        cx.emit(embedded("ICC profile", input.nested(profile)));
    } else if info.color_space == PROFILE_LINKED && info.profile_size > 0 {
        let at = span.sub(info.profile_offset.into(), info.profile_size.into());
        let name = cx.read_avail(at).await?;
        cx.emit(
            Node::new("Linked profile")
                .span(at)
                .value(text(crate::text::latin1(
                    name.split(|&b| b == 0).next().unwrap_or_default(),
                )))
                .desc("File name of the ICC profile (Windows-1252, NUL-terminated)"),
        );
    }

    let start = pixels.unwrap_or(pos);
    let rows = if icon {
        info.height.unsigned_abs() / 2
    } else {
        info.height.unsigned_abs()
    };
    let computed = info.stride().saturating_mul(rows);
    let declared = |fallback: u64| {
        if info.size_image != 0 {
            u64::from(info.size_image)
        } else {
            fallback
        }
    };
    if let Some(what) = info.embedded_stream() {
        let len = declared(span.len.saturating_sub(start));
        cx.emit(
            embedded("Pixel data", input.nested(span.sub(start, len)))
                .summary(format!("{what} stream")),
        );
    } else if let Some(bits) = info.rle() {
        let len = declared(span.len.saturating_sub(start));
        let data = span.sub(start, len);
        cx.emit(
            region("Pixel data", span, start, len)
                .summary(format!("{}, {}", info.compression_name(), human_size(data.len)))
                .desc("Run-length encoded: runs of one value, literal runs, line and bitmap ends, and position deltas")
                .lazy(rle_records, (data, bits)),
        );
    } else if matches!(info.compression, 0 | 3 | 6) {
        let order = if info.height < 0 {
            "top-down"
        } else {
            "bottom-up"
        };
        let mut node = region("Pixel array", span, start, computed).summary(format!(
            "{} of {}, {order}",
            plural(rows, "row"),
            human_size(info.stride())
        ));
        if mask {
            node = node.desc("The AND mask rows, then the XOR mask rows");
        }
        cx.emit(node);
    } else {
        let len = declared(span.len.saturating_sub(start));
        cx.emit(region("Pixel data", span, start, len).summary(info.compression_name()));
    }
    if icon {
        let mask_stride = (info.width.unsigned_abs().saturating_add(31) / 32).saturating_mul(4);
        let mask_start = start.saturating_add(computed);
        if info.bit_count == 32 && mask_start >= span.len {
            cx.emit(
                Node::new("AND mask")
                    .summary("absent")
                    .diag(Diagnostic::note(
                        "no AND mask after the 32-bit image (its alpha channel gives the transparency); Windows expects one",
                    )),
            );
            return Ok(info);
        }
        cx.emit(
            region(
                "AND mask",
                span,
                mask_start,
                mask_stride.saturating_mul(rows),
            )
            .summary("1-bit transparency mask")
            .desc("1 = transparent (the XOR image is then combined with the screen), 0 = opaque; rows padded to 4 bytes"),
        );
    }
    Ok(info)
}

/// Lists the records of RLE4, RLE8 or OS/2 RLE24 pixel data (`bits` per
/// encoded value): `count, value` runs, and escapes (`0, 0` end of line,
/// `0, 1` end of bitmap, `0, 2, dx, dy` delta, `0, n` and `n` literal
/// values padded to an even length).
async fn rle_records(cx: Cx, (span, bits): (Span, u8)) -> Result<()> {
    let value_bytes: u64 = if bits == 24 { 3 } else { 1 };
    let (mut pos, mut row) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < span.len {
        let at = (pos, row);
        cx.mark(move || at);
        let head = cx.read_avail(span.sub(pos, 2)).await?;
        let (Some(&count), Some(&code)) = (head.first(), head.get(1)) else {
            cx.emit(Node::new("Truncated record").span(span.tail(pos)));
            break;
        };
        let (len, node) = if count > 0 {
            let len = 1u64.saturating_add(value_bytes);
            let value = cx
                .read_avail(span.sub(pos.saturating_add(1), value_bytes))
                .await?;
            let what = match bits {
                4 => format!("indices {} and {} alternating", code >> 4, code & 0x0f),
                24 => format!(
                    "color #{:02x}{:02x}{:02x}",
                    value.get(2).copied().unwrap_or(0),
                    value.get(1).copied().unwrap_or(0),
                    value.first().copied().unwrap_or(0)
                ),
                _ => format!("index {code}"),
            };
            (
                len,
                Node::new("Run").summary(format!("{count} pixels, {what}")),
            )
        } else {
            match code {
                0 => (2, Node::new("End of line").summary(format!("row {row}"))),
                1 => (2, Node::new("End of bitmap")),
                2 => {
                    let d = cx.read_avail(span.sub(pos.saturating_add(2), 2)).await?;
                    let (dx, dy) = (
                        d.first().copied().unwrap_or(0),
                        d.get(1).copied().unwrap_or(0),
                    );
                    (
                        4,
                        Node::new("Delta")
                            .summary(format!("skip {dx} pixels right and {dy} rows on")),
                    )
                }
                n => {
                    let data = match bits {
                        4 => u64::from(n).saturating_add(1) / 2,
                        24 => u64::from(n).saturating_mul(3),
                        _ => u64::from(n),
                    };
                    let padded = data.saturating_add(data & 1);
                    (
                        2u64.saturating_add(padded),
                        Node::new("Literal run").summary(format!("{n} pixels, {data} bytes")),
                    )
                }
            }
        };
        let record = span.sub(pos, len);
        let mut node = node.span(record);
        if record.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(record.source, record.offset, len),
                record.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len);
        if count == 0 && code == 0 {
            row = row.saturating_add(1);
        }
        if count == 0 && code == 1 {
            break;
        }
    }
    if pos < span.len {
        cx.emit(Node::new("After the end of bitmap").span(span.tail(pos)));
    }
    Ok(())
}
