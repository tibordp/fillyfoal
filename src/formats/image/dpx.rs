//! Motion-picture film scan formats: SMPTE DPX and Kodak Cineon.
//!
//! DPX: a file information header (magic `SDPX` big-endian or `XPDS`
//! little-endian), an image information header with up to eight image
//! elements, orientation, film and television headers, user data, then the
//! image data at the offset given in the first header. Cineon (magic
//! `80 2A 5F D7`) has the same shape with a different layout.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
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
    probe: Probe::Magic(&[(0, b"\x80\x2a\x5f\xd7")]),
    dissect: crate::expander!(dissect_cineon: Input),
};

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
];

const TRANSFER: EnumTable = &[
    (0, "User-defined"),
    (1, "Printing density"),
    (2, "Linear"),
    (3, "Logarithmic"),
    (4, "Unspecified video"),
    (5, "SMPTE 274M"),
    (6, "ITU-R 709-4"),
    (7, "ITU-R 601-5 B or G"),
    (8, "ITU-R 601-5 M"),
    (9, "NTSC composite"),
    (10, "PAL composite"),
    (11, "Z linear"),
    (12, "Z homogeneous"),
];

const PACKING: EnumTable = &[
    (0, "Packed into 32-bit words"),
    (1, "Filled to 32-bit words, method A"),
    (2, "Filled to 32-bit words, method B"),
];

const ENCODING: EnumTable = &[(0, "None"), (1, "RLE")];

fn file_info(f: &mut Fields<'_>, _: &()) -> Result<u32> {
    f.ascii("Magic", 4).emit()?;
    let offset = f.u32("Image data offset").hex().emit()?;
    f.ascii("Version", 8).emit()?;
    f.u32("File size").emit()?;
    f.u32("Ditto key").desc("0 = same as the previous frame, 1 = new").emit()?;
    f.u32("Generic header size").emit()?;
    f.u32("Industry header size").emit()?;
    f.u32("User data size").emit()?;
    f.ascii("File name", 100).emit()?;
    f.ascii("Creation time", 24).emit()?;
    f.ascii("Creator", 100).emit()?;
    f.ascii("Project", 200).emit()?;
    f.ascii("Copyright", 200).emit()?;
    f.u32("Encryption key").hex().emit()?;
    f.bytes("Reserved", 104).emit()?;
    Ok(offset)
}

fn image_info(f: &mut Fields<'_>, endian: &Endian) -> Result<()> {
    f.u16("Orientation").enumeration(ORIENTATION).emit()?;
    let elements = f.u16("Number of elements").emit()?;
    f.u32("Pixels per line").emit()?;
    f.u32("Lines per element").emit()?;
    for _ in 0..elements.min(8) {
        f.node(struct_node("Image element", f.peek_span(72), *endian, (), element));
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
    f.u32("Data sign").desc("0 = unsigned, 1 = signed").emit()?;
    f.u32("Reference low data code").emit()?;
    f.f32("Reference low quantity").emit()?;
    f.u32("Reference high data code").emit()?;
    f.f32("Reference high quantity").emit()?;
    f.u8("Descriptor").enumeration(DESCRIPTORS).emit()?;
    f.u8("Transfer characteristic").enumeration(TRANSFER).emit()?;
    f.u8("Colorimetric specification").enumeration(TRANSFER).emit()?;
    f.u8("Bit depth").emit()?;
    f.u16("Packing").enumeration(PACKING).emit()?;
    f.u16("Encoding").enumeration(ENCODING).emit()?;
    f.u32("Data offset").hex().emit()?;
    f.u32("End-of-line padding").emit()?;
    f.u32("End-of-image padding").emit()?;
    f.ascii("Description", 32).emit()?;
    Ok(())
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
    let offset = file_info(&mut Fields::new(&block, endian), &())?;
    cx.emit(struct_node("File information", fi, endian, (), file_info));
    let ii = file.sub(768, 640);
    let block = cx.block(ii).await?;
    let mut f = Fields::new(&block, endian);
    f.skip(2);
    let elements = f.u16("").get()?;
    let width = f.u32("").get()?;
    let height = f.u32("").get()?;
    // The first element's descriptor and bit depth.
    f.skip(20);
    let descriptor = f.u8("").get()?;
    f.skip(2);
    let bits = f.u8("").get()?;
    cx.emit(struct_node("Image information", ii, endian, endian, image_info));
    cx.emit(region("Orientation header", file, 1408, 256));
    cx.emit(region("Film header", file, 1664, 256));
    cx.emit(region("Television header", file, 1920, 128));
    let offset = u64::from(offset);
    if offset > 2048 {
        cx.emit(region("User data", file, 2048, offset.saturating_sub(2048)));
    }
    let descriptor = lookup(DESCRIPTORS, descriptor.into()).unwrap_or("unknown descriptor");
    cx.annotate(format!(
        "{}, {descriptor}, {bits}-bit, {elements} elements, {}",
        dims(width, height),
        if endian == Endian::Big { "big-endian" } else { "little-endian" }
    ));
    cx.emit(region("Image data", file, offset, file.len.saturating_sub(offset)));
    Ok(())
}

fn cineon_file_info(f: &mut Fields<'_>, _: &()) -> Result<u32> {
    f.u32("Magic").hex().emit()?;
    let offset = f.u32("Image data offset").hex().emit()?;
    f.u32("Generic header length").emit()?;
    f.u32("Industry header length").emit()?;
    f.u32("User data length").emit()?;
    f.u32("File size").emit()?;
    f.ascii("Version", 8).emit()?;
    f.ascii("File name", 100).emit()?;
    f.ascii("Creation date", 12).emit()?;
    f.ascii("Creation time", 12).emit()?;
    f.bytes("Reserved", 36).emit()?;
    Ok(offset)
}

fn cineon_image_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Orientation").enumeration(ORIENTATION).emit()?;
    let channels = f.u8("Channels").emit()?;
    f.u16("Padding").emit()?;
    for _ in 0..channels.min(8) {
        f.node(struct_node("Channel", f.peek_span(28), Endian::Big, (), cineon_channel));
        f.skip(28);
    }
    let unused = u64::from(8u8.saturating_sub(channels)).saturating_mul(28);
    if unused > 0 {
        f.node(Node::new("Unused channels").span(f.peek_span(unused)));
    }
    Ok(())
}

fn cineon_channel(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Designator byte 0").desc("0 = universal metric").emit()?;
    f.u8("Designator byte 1").desc("0 = B&W, 1–3 = R, G, B printing density").emit()?;
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

pub async fn dissect_cineon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let be = Endian::Big;
    let fi = file.sub(0, 192);
    let block = cx.block(fi).await?;
    let offset = cineon_file_info(&mut Fields::new(&block, be), &())?;
    cx.emit(struct_node("File information", fi, be, (), cineon_file_info));
    let ii = file.sub(192, 4 + 8 * 28);
    let block = cx.block(ii).await?;
    let mut f = Fields::new(&block, be);
    f.skip(1);
    let channels = f.u8("").get()?;
    // The first channel's depth and size.
    f.skip(4);
    let bits = f.u8("").get()?;
    f.skip(1);
    let w = f.u32("").get()?;
    let h = f.u32("").get()?;
    cx.emit(struct_node("Image information", ii, be, (), cineon_image_info));
    let header_end = ii.end().saturating_sub(file.offset);
    let offset = u64::from(offset);
    cx.emit(region("Remaining headers", file, header_end, offset.saturating_sub(header_end)));
    cx.annotate(format!("{}, {channels} channels, {bits}-bit", dims(w, h)));
    cx.emit(region("Image data", file, offset, file.len.saturating_sub(offset)));
    Ok(())
}
