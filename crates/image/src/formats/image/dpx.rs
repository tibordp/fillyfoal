//! Motion-picture film scan formats: SMPTE DPX and Kodak Cineon.
//!
//! DPX (SMPTE 268M): a file information header (magic `SDPX` big-endian or
//! `XPDS` little-endian), an image information header with up to eight
//! image elements and an orientation header (the generic header, 1664
//! bytes), then optionally the film and television headers (the industry
//! header, 384 bytes) and user data, then the image data at the offset
//! given in the first header. Cineon (magic `80 2A 5F D7`, either byte
//! order) has the same shape with a different layout: a 1024-byte generic
//! header and a 1024-byte film information header.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::value::{EnumTable, lookup};

use super::{dims, region};

pub static DPX: Format = Format {
    name: "dpx",
    title: "Digital Picture Exchange",
    extensions: &["dpx"],
    mime: "image/x-dpx",
    probe: Probe::Magic(&[(0, b"SDPX"), (0, b"XPDS")]),
    dissect: crate::expander!(dissect_dpx: Input),
};

pub static CINEON: Format = Format {
    name: "cineon",
    title: "Kodak Cineon image",
    extensions: &["cin"],
    mime: "image/cineon",
    probe: Probe::Magic(&[(0, b"\x80\x2a\x5f\xd7"), (0, b"\xd7\x5f\x2a\x80")]),
    dissect: crate::expander!(dissect_cineon: Input),
};

/// DPX and Cineon mark unset fields with all bits set.
const UNSET: u32 = u32::MAX;

const ORIENTATION: EnumTable = &[
    (0, "Left to right, top to bottom"),
    (1, "Right to left, top to bottom"),
    (2, "Left to right, bottom to top"),
    (3, "Right to left, bottom to top"),
    (4, "Top to bottom, left to right"),
    (5, "Top to bottom, right to left"),
    (6, "Bottom to top, left to right"),
    (7, "Bottom to top, right to left"),
];

const DESCRIPTORS: EnumTable = &[
    (0, "User-defined"),
    (1, "Red"),
    (2, "Green"),
    (3, "Blue"),
    (4, "Alpha"),
    (6, "Luma (Y)"),
    (7, "Color difference (CbCr)"),
    (8, "Depth (Z)"),
    (9, "Composite video"),
    (50, "RGB"),
    (51, "RGBA"),
    (52, "ABGR"),
    (100, "CbYCrY (4:2:2)"),
    (101, "CbYACrYA (4:2:2:4)"),
    (102, "CbYCr (4:4:4)"),
    (103, "CbYCrA (4:4:4:4)"),
    (150, "User-defined, 2 components"),
    (151, "User-defined, 3 components"),
    (152, "User-defined, 4 components"),
    (153, "User-defined, 5 components"),
    (154, "User-defined, 6 components"),
    (155, "User-defined, 7 components"),
    (156, "User-defined, 8 components"),
];

const TRANSFER: EnumTable = &[
    (0, "User-defined"),
    (1, "Printing density"),
    (2, "Linear"),
    (3, "Logarithmic"),
    (4, "Unspecified video"),
    (5, "SMPTE 274M"),
    (6, "ITU-R 709-4"),
    (7, "ITU-R 601-5 system B or G (625)"),
    (8, "ITU-R 601-5 system M (525)"),
    (9, "NTSC composite video"),
    (10, "PAL composite video"),
    (11, "Z (depth), linear"),
    (12, "Z (depth), homogeneous"),
];

/// Colorimetric specification: the transfer table, without the codes that
/// only describe a transfer.
const COLORIMETRIC: EnumTable = &[
    (0, "User-defined"),
    (1, "Printing density"),
    (2, "Not applicable"),
    (3, "Not applicable"),
    (4, "Unspecified video"),
    (5, "SMPTE 274M"),
    (6, "ITU-R 709-4"),
    (7, "ITU-R 601-5 system B or G (625)"),
    (8, "ITU-R 601-5 system M (525)"),
    (9, "NTSC composite video"),
    (10, "PAL composite video"),
    (11, "Not applicable"),
    (12, "Not applicable"),
];

const PACKING: EnumTable = &[
    (0, "Packed into 32-bit words"),
    (1, "Filled to 32-bit words, method A"),
    (2, "Filled to 32-bit words, method B"),
];

const ENCODING: EnumTable = &[(0, "None"), (1, "RLE")];

const SIGN: EnumTable = &[(0, "Unsigned"), (1, "Signed")];

const INTERLACE: EnumTable = &[(0, "Non-interlaced"), (1, "2:1 interlace")];

const VIDEO_SIGNAL: EnumTable = &[
    (0, "Undefined"),
    (1, "NTSC"),
    (2, "PAL"),
    (3, "PAL-M"),
    (4, "SECAM"),
    (50, "YCbCr ITU-R 601-5 525-line, 2:1 interlace, 4:3"),
    (51, "YCbCr ITU-R 601-5 625-line, 2:1 interlace, 4:3"),
    (100, "YCbCr ITU-R 601-5 525-line, 2:1 interlace, 16:9"),
    (101, "YCbCr ITU-R 601-5 625-line, 2:1 interlace, 16:9"),
    (150, "YCbCr 1050-line, 2:1 interlace, 16:9"),
    (151, "YCbCr 1125-line, 2:1 interlace, 16:9 (SMPTE 274M)"),
    (152, "YCbCr 1250-line, 2:1 interlace, 16:9"),
    (153, "YCbCr 1125-line, 2:1 interlace, 16:9 (SMPTE 240M)"),
    (200, "YCbCr 525-line, 1:1 progressive, 16:9"),
    (201, "YCbCr 625-line, 1:1 progressive, 16:9"),
    (202, "YCbCr 750-line, 1:1 progressive, 16:9 (SMPTE 296M)"),
    (203, "YCbCr 1125-line, 1:1 progressive, 16:9 (SMPTE 274M)"),
];

/// A SMPTE time code packed as BCD `hhmmssff`.
fn timecode(v: u32) -> Option<String> {
    if v == UNSET {
        return None;
    }
    let digit = |shift: u32| (v >> shift) & 0xf;
    let pair = |shift: u32| {
        let (hi, lo) = (digit(shift.saturating_add(4)), digit(shift));
        (hi < 10 && lo < 10).then(|| format!("{hi}{lo}"))
    };
    Some(format!(
        "{}:{}:{}:{}",
        pair(24)?,
        pair(16)?,
        pair(8)?,
        pair(0)?
    ))
}

fn file_info(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u32)> {
    f.ascii("Magic", 4).emit()?;
    let offset = f.u32("Image data offset").hex().emit()?;
    f.ascii("Version", 8).emit()?;
    f.u32("File size").emit()?;
    f.u32("Ditto key")
        .enumeration(&[(0, "Same as the previous frame"), (1, "New frame")])
        .emit()?;
    f.u32("Generic header size").emit()?;
    let industry = f.u32("Industry header size").emit()?;
    let user = f.u32("User data size").emit()?;
    f.ascii("File name", 100).emit()?;
    f.ascii("Creation time", 24)
        .desc("yyyy:mm:dd:hh:mm:ssLTZ")
        .emit()?;
    f.ascii("Creator", 100).emit()?;
    f.ascii("Project", 200).emit()?;
    f.ascii("Copyright", 200).emit()?;
    f.u32("Encryption key")
        .hex()
        .desc("0xffffffff: not encrypted")
        .emit()?;
    f.bytes("Reserved", 104).emit()?;
    Ok((offset, industry, user))
}

fn image_info(f: &mut Fields<'_>, endian: &Endian) -> Result<()> {
    f.u16("Orientation").enumeration(ORIENTATION).emit()?;
    let elements = f.u16("Number of elements").emit()?;
    f.u32("Pixels per line").emit()?;
    f.u32("Lines per element").emit()?;
    for i in 0..elements.min(8) {
        let block = f.block();
        let at = f.pos();
        let mut peek = Fields::new(block, *endian);
        peek.seek(at.saturating_add(20));
        let descriptor = peek.u8("").get().unwrap_or(0);
        peek.skip(2);
        let bits = peek.u8("").get().unwrap_or(0);
        f.node(
            struct_node(
                format!("Image element {i}"),
                f.peek_span(72),
                *endian,
                (),
                element,
            )
            .summary(format!(
                "{}, {bits}-bit",
                lookup(DESCRIPTORS, descriptor.into()).unwrap_or("unknown descriptor")
            )),
        );
        f.skip(72);
    }
    let unused = u64::from(8u16.saturating_sub(elements)).saturating_mul(72);
    if unused > 0 {
        f.node(Node::new("Unused image elements").span(f.peek_span(unused)));
        f.skip(unused);
    }
    f.bytes("Reserved", 52).emit()?;
    Ok(())
}

fn element(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Data sign").enumeration(SIGN).emit()?;
    f.u32("Reference low data code").emit()?;
    f.f32("Reference low quantity").emit()?;
    f.u32("Reference high data code").emit()?;
    f.f32("Reference high quantity").emit()?;
    f.u8("Descriptor").enumeration(DESCRIPTORS).emit()?;
    f.u8("Transfer characteristic")
        .enumeration(TRANSFER)
        .emit()?;
    f.u8("Colorimetric specification")
        .enumeration(COLORIMETRIC)
        .emit()?;
    f.u8("Bit depth").emit()?;
    f.u16("Packing").enumeration(PACKING).emit()?;
    f.u16("Encoding").enumeration(ENCODING).emit()?;
    f.u32("Data offset").hex().emit()?;
    f.u32("End-of-line padding").emit()?;
    f.u32("End-of-image padding").emit()?;
    f.ascii("Description", 32).emit()?;
    Ok(())
}

fn orientation(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("X offset").emit()?;
    f.u32("Y offset").emit()?;
    f.f32("X center").emit()?;
    f.f32("Y center").emit()?;
    f.u32("X original size").emit()?;
    f.u32("Y original size").emit()?;
    f.ascii("Source file name", 100).emit()?;
    f.ascii("Source creation time", 24).emit()?;
    f.ascii("Input device", 32).emit()?;
    f.ascii("Input device serial number", 32).emit()?;
    for name in ["Border left", "Border right", "Border top", "Border bottom"] {
        f.u16(name).emit()?;
    }
    f.u32("Pixel aspect ratio (horizontal)").emit()?;
    f.u32("Pixel aspect ratio (vertical)").emit()?;
    f.f32("X scanned size").desc("mm (DPX 2.0)").emit()?;
    f.f32("Y scanned size").desc("mm (DPX 2.0)").emit()?;
    f.bytes("Reserved", 20).emit()?;
    Ok(())
}

fn film(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Film manufacturer ID", 2).emit()?;
    f.ascii("Film type", 2).emit()?;
    f.ascii("Offset in perfs", 2).emit()?;
    f.ascii("Prefix", 6).emit()?;
    f.ascii("Count", 4).emit()?;
    f.ascii("Format", 32).emit()?;
    f.u32("Frame position in sequence").emit()?;
    f.u32("Sequence length").emit()?;
    f.u32("Held count").emit()?;
    f.f32("Frame rate").emit()?;
    f.f32("Shutter angle").desc("Degrees").emit()?;
    f.ascii("Frame identification", 32).emit()?;
    f.ascii("Slate information", 100).emit()?;
    f.bytes("Reserved", 56).emit()?;
    Ok(())
}

fn television(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Time code")
        .hex()
        .with(|&v, n| match timecode(v) {
            Some(t) => n.summary(t),
            None => n,
        })
        .emit()?;
    f.u32("User bits").hex().emit()?;
    f.u8("Interlace").enumeration(INTERLACE).emit()?;
    f.u8("Field number").emit()?;
    f.u8("Video signal standard")
        .enumeration(VIDEO_SIGNAL)
        .emit()?;
    f.u8("Padding").emit()?;
    f.f32("Horizontal sampling rate").desc("Hz").emit()?;
    f.f32("Vertical sampling rate").desc("Hz").emit()?;
    f.f32("Temporal sampling rate")
        .desc("Frames per second")
        .emit()?;
    f.f32("Time offset")
        .desc("ms from sync to first pixel")
        .emit()?;
    f.f32("Gamma").emit()?;
    f.f32("Black level code").emit()?;
    f.f32("Black gain").emit()?;
    f.f32("Breakpoint").emit()?;
    f.f32("Reference white level code").emit()?;
    f.f32("Integration time").desc("Seconds").emit()?;
    f.bytes("Reserved", 76).emit()?;
    Ok(())
}

fn endian_name(endian: Endian) -> &'static str {
    if endian == Endian::Big {
        "big-endian"
    } else {
        "little-endian"
    }
}

/// The user data region: a 32-byte user identification, then the data.
async fn user_data(cx: &Cx, file: crate::span::Span, at: u64, len: u64) -> Result<Node> {
    let id = cx.read_avail(file.sub(at, len.min(32))).await?;
    let id = crate::text::until_nul(&id);
    let node = region("User data", file, at, len);
    Ok(if id.trim().is_empty() {
        node
    } else {
        node.summary(format!("{:?}", id.trim()))
    })
}

pub async fn dissect_dpx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b"SDPX" {
        Endian::Big
    } else {
        Endian::Little
    };
    let fi = file.sub(0, 768);
    let block = cx.block(fi).await?;
    let (offset, industry_size, user_size) = file_info(&mut Fields::new(&block, endian), &())?;
    cx.emit(struct_node("File information", fi, endian, (), file_info));
    let ii = file.sub(768, 640);
    let block = cx.block(ii).await?;
    let mut f = Fields::new(&block, endian);
    f.skip(2);
    let elements = f.u16("").get()?;
    let width = f.u32("").get()?;
    let height = f.u32("").get()?;
    // The first element's descriptor, transfer and bit depth.
    f.skip(20);
    let descriptor = f.u8("").get()?;
    let transfer = f.u8("").get()?;
    f.skip(1);
    let bits = f.u8("").get()?;
    cx.emit(
        struct_node("Image information", ii, endian, endian, image_info).summary(format!(
            "{}, {}",
            dims(width, height),
            plural(elements, "element")
        )),
    );
    let offset = u64::from(offset);
    // The orientation header ends the generic header; the industry header
    // (film and television) is optional, and absent when the image data
    // starts right after the generic header (as FFmpeg writes it).
    let mut headers_end = 1408u64;
    if offset >= 1664 {
        cx.emit(struct_node(
            "Orientation header",
            file.sub(1408, 256),
            endian,
            (),
            orientation,
        ));
        headers_end = 1664;
    }
    let industry = offset >= 2048 && !(1..384).contains(&industry_size);
    if industry {
        let block = cx.block(file.sub(1664, 384)).await?;
        let mut f = Fields::new(&block, endian);
        f.seek(16);
        let format = f.ascii("", 32).get().unwrap_or_default();
        f.seek(60);
        let rate = f.f32("").get().unwrap_or(f32::NAN);
        let mut summary = format.trim().to_owned();
        if rate.is_finite() && rate > 0.0 {
            summary = if summary.is_empty() {
                format!("{rate} fps")
            } else {
                format!("{summary}, {rate} fps")
            };
        }
        let mut node = struct_node("Film header", file.sub(1664, 256), endian, (), film);
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        cx.emit(node);
        let tc = match endian {
            Endian::Big => u32_be(&block.data, 256),
            Endian::Little => u32_le(&block.data, 256),
        };
        let mut node = struct_node(
            "Television header",
            file.sub(1920, 128),
            endian,
            (),
            television,
        );
        if let Some(t) = tc.and_then(timecode) {
            node = node.summary(format!("time code {t}"));
        }
        cx.emit(node);
        headers_end = 2048;
    }
    if offset > headers_end {
        let len = if user_size > 0 && user_size != UNSET {
            u64::from(user_size).min(offset.saturating_sub(headers_end))
        } else {
            offset.saturating_sub(headers_end)
        };
        cx.emit(user_data(&cx, file, headers_end, len).await?);
    }
    let descriptor = lookup(DESCRIPTORS, descriptor.into()).unwrap_or("unknown descriptor");
    let mut summary = format!("{}, {descriptor}, {bits}-bit", dims(width, height));
    if let Some(t) = lookup(TRANSFER, transfer.into()).filter(|_| transfer != 0) {
        summary = format!("{summary}, {t}");
    }
    if elements > 1 {
        summary = format!("{summary}, {elements} elements");
    }
    cx.annotate(format!("{summary}, {}", endian_name(endian)));
    cx.emit(region(
        "Image data",
        file,
        offset,
        file.len.saturating_sub(offset),
    ));
    Ok(())
}

fn cineon_file_info(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    f.u32("Magic").hex().emit()?;
    let offset = f.u32("Image data offset").hex().emit()?;
    f.u32("Generic header length").emit()?;
    let industry = f.u32("Industry header length").emit()?;
    f.u32("User data length").emit()?;
    f.u32("File size").emit()?;
    f.ascii("Version", 8).emit()?;
    f.ascii("File name", 100).emit()?;
    f.ascii("Creation date", 12).emit()?;
    f.ascii("Creation time", 12).emit()?;
    f.bytes("Reserved", 36).emit()?;
    Ok((offset, industry))
}

fn cineon_image_info(f: &mut Fields<'_>, endian: &Endian) -> Result<()> {
    f.u8("Orientation").enumeration(ORIENTATION).emit()?;
    let channels = f.u8("Channels").emit()?;
    f.u16("Padding").emit()?;
    for i in 0..channels.min(8) {
        f.node(struct_node(
            format!("Channel {i}"),
            f.peek_span(28),
            *endian,
            (),
            cineon_channel,
        ));
        f.skip(28);
    }
    let unused = u64::from(8u8.saturating_sub(channels)).saturating_mul(28);
    if unused > 0 {
        f.node(Node::new("Unused channels").span(f.peek_span(unused)));
        f.skip(unused);
    }
    for name in [
        "White point x",
        "White point y",
        "Red primary x",
        "Red primary y",
        "Green primary x",
        "Green primary y",
        "Blue primary x",
        "Blue primary y",
    ] {
        f.f32(name).emit()?;
    }
    f.ascii("Label", 200).emit()?;
    f.bytes("Reserved", 28).emit()?;
    Ok(())
}

fn cineon_channel(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Designator byte 0")
        .desc("0 = universal metric")
        .emit()?;
    f.u8("Designator byte 1")
        .enumeration(&[
            (0, "B&W"),
            (1, "Red, printing density"),
            (2, "Green, printing density"),
            (3, "Blue, printing density"),
            (4, "Red, CCIR XA/11"),
            (5, "Green, CCIR XA/11"),
            (6, "Blue, CCIR XA/11"),
        ])
        .emit()?;
    f.u8("Bits per pixel").emit()?;
    f.u8("Padding").emit()?;
    f.u32("Pixels per line").emit()?;
    f.u32("Lines per image").emit()?;
    f.f32("Minimum data value").emit()?;
    f.f32("Minimum quantity").emit()?;
    f.f32("Maximum data value").emit()?;
    f.f32("Maximum quantity").emit()?;
    Ok(())
}

fn cineon_data_format(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Interleave")
        .enumeration(&[(0, "Pixel"), (1, "Line"), (2, "Channel")])
        .emit()?;
    f.u8("Packing")
        .enumeration(&[
            (0, "User-defined"),
            (1, "Packed, 8-bit boundaries"),
            (2, "Packed, 16-bit boundaries, left-justified"),
            (3, "Packed, 16-bit boundaries, right-justified"),
            (4, "Packed, 32-bit boundaries, left-justified"),
            (5, "Packed, 32-bit boundaries, right-justified"),
        ])
        .desc("Bit 7 set: data in words of the packing size")
        .emit()?;
    f.u8("Data signed").enumeration(SIGN).emit()?;
    f.u8("Image sense")
        .enumeration(&[(0, "Positive"), (1, "Negative")])
        .emit()?;
    f.u32("End-of-line padding").emit()?;
    f.u32("End-of-channel padding").emit()?;
    f.bytes("Reserved", 20).emit()?;
    Ok(())
}

fn cineon_origination(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.int::<i32>("X offset").emit()?;
    f.int::<i32>("Y offset").emit()?;
    f.ascii("Source file name", 100).emit()?;
    f.ascii("Source creation date", 12).emit()?;
    f.ascii("Source creation time", 12).emit()?;
    f.ascii("Input device", 64).emit()?;
    f.ascii("Input device model", 32).emit()?;
    f.ascii("Input device serial number", 32).emit()?;
    f.f32("X input pitch").desc("Samples per mm").emit()?;
    f.f32("Y input pitch").desc("Lines per mm").emit()?;
    f.f32("Gamma").emit()?;
    f.bytes("Reserved", 40).emit()?;
    Ok(())
}

fn cineon_film(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Film manufacturer ID").emit()?;
    f.u8("Film type").emit()?;
    f.u8("Offset in perfs").emit()?;
    f.u8("Padding").emit()?;
    f.u32("Prefix").emit()?;
    f.u32("Count").emit()?;
    f.ascii("Format", 32).emit()?;
    f.u32("Frame position in sequence").emit()?;
    f.f32("Frame rate").emit()?;
    f.ascii("Frame identification", 32).emit()?;
    f.ascii("Slate information", 200).emit()?;
    f.bytes("Reserved", 740).emit()?;
    Ok(())
}

pub async fn dissect_cineon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b"\x80\x2a\x5f\xd7" {
        Endian::Big
    } else {
        Endian::Little
    };
    let fi = file.sub(0, 192);
    let block = cx.block(fi).await?;
    let (offset, industry) = cineon_file_info(&mut Fields::new(&block, endian), &())?;
    cx.emit(struct_node(
        "File information",
        fi,
        endian,
        (),
        cineon_file_info,
    ));
    let ii = file.sub(192, 488);
    let block = cx.block(ii).await?;
    let mut f = Fields::new(&block, endian);
    f.skip(1);
    let channels = f.u8("").get()?;
    // The first channel's depth and size.
    f.skip(4);
    let bits = f.u8("").get()?;
    f.skip(1);
    let w = f.u32("").get()?;
    let h = f.u32("").get()?;
    cx.emit(
        struct_node("Image information", ii, endian, endian, cineon_image_info).summary(format!(
            "{}, {}, {bits}-bit",
            dims(w, h),
            plural(channels, "channel")
        )),
    );
    let offset = u64::from(offset);
    let mut headers_end = 680u64;
    if offset >= 712 {
        cx.emit(struct_node(
            "Image data format",
            file.sub(680, 32),
            endian,
            (),
            cineon_data_format,
        ));
        headers_end = 712;
    }
    if offset >= 1024 {
        cx.emit(struct_node(
            "Image origination",
            file.sub(712, 312),
            endian,
            (),
            cineon_origination,
        ));
        headers_end = 1024;
    }
    if offset >= 2048 && industry != 0 {
        cx.emit(struct_node(
            "Film information",
            file.sub(1024, 1024),
            endian,
            (),
            cineon_film,
        ));
        headers_end = 2048;
    }
    if offset > headers_end {
        cx.emit(user_data(&cx, file, headers_end, offset.saturating_sub(headers_end)).await?);
    }
    cx.annotate(format!(
        "{}, {}, {bits}-bit, {}",
        dims(w, h),
        plural(channels, "channel"),
        endian_name(endian)
    ));
    cx.emit(region(
        "Image data",
        file,
        offset,
        file.len.saturating_sub(offset),
    ));
    Ok(())
}
