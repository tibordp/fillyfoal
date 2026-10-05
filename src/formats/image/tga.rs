//! Truevision TGA (TARGA).
//!
//! An 18-byte header, an image ID, an optional color map and the image data.
//! Version 2 files end with a 26-byte footer (`TRUEVISION-XFILE.`) that
//! locates an extension area and a developer area; that footer is what the
//! probe relies on, as version 1 files have no magic at all.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, field, lookup};

use super::{ColorOrder, dims, palette, region, text};

const LE: Endian = Endian::Little;
const SIGNATURE: &[u8] = b"TRUEVISION-XFILE.\0";

pub static FORMAT: Format = Format {
    name: "tga",
    title: "Truevision TGA image",
    extensions: &["tga", "icb", "vda", "vst", "tpic"],
    mime: "image/x-tga",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let footer = h.len >= 44 && h.tail.ends_with(SIGNATURE);
    let kind_ok = matches!(h.data.get(2), Some(1..=3 | 9..=11 | 32 | 33));
    kind_ok && (footer || plausible_v1(h))
}

/// Version 1 files have no signature, so every header field must be
/// consistent: a known image type, a color map exactly when the type needs
/// one, a common pixel depth, and a file large enough for the image.
fn plausible_v1(h: &Head<'_>) -> bool {
    let d = h.data;
    let byte = |i: usize| d.get(i).copied().unwrap_or(0xff);
    let word = |i: usize| crate::bytes::u16_le(d, i).unwrap_or(0);
    let (id_len, cmap_type, kind) = (byte(0), byte(1), byte(2));
    let (cmap_len, cmap_bits) = (word(5), byte(7));
    let (width, height, depth, descriptor) = (word(12), word(14), byte(16), byte(17));
    let mapped = matches!(kind, 1 | 9);
    let cmap_ok = match cmap_type {
        0 => !mapped && cmap_len == 0 && cmap_bits == 0 && word(3) == 0,
        1 => mapped && cmap_len > 0 && matches!(cmap_bits, 15 | 16 | 24 | 32),
        _ => false,
    };
    let depth_ok = if mapped {
        depth == 8 || depth == 16
    } else {
        matches!(depth, 8 | 15 | 16 | 24 | 32)
    };
    let header = 18u64
        .saturating_add(id_len.into())
        .saturating_add(u64::from(cmap_len).saturating_mul(u64::from(cmap_bits).div_ceil(8)));
    let pixels = u64::from(width)
        .saturating_mul(height.into())
        .saturating_mul(u64::from(depth).div_ceil(8));
    let size_ok = if kind & 8 != 0 {
        h.len > header
    } else {
        h.len >= header.saturating_add(pixels)
    };
    cmap_ok
        && depth_ok
        && width > 0
        && height > 0
        && descriptor & 0xc0 == 0
        && u16::from(descriptor & 15) <= u16::from(depth)
        && size_ok
}

const IMAGE_TYPES: EnumTable = &[
    (0, "No image data"),
    (1, "Color-mapped"),
    (2, "True-color"),
    (3, "Grayscale"),
    (9, "Color-mapped, RLE"),
    (10, "True-color, RLE"),
    (11, "Grayscale, RLE"),
    (32, "Color-mapped, Huffman/delta/RLE"),
    (33, "Color-mapped, Huffman/delta/RLE, 4-pass quadtree"),
];

const DESCRIPTOR: FlagTable = &[
    field(0x30, 0x00, "BOTTOM_LEFT"),
    field(0x30, 0x10, "BOTTOM_RIGHT"),
    field(0x30, 0x20, "TOP_LEFT"),
    field(0x30, 0x30, "TOP_RIGHT"),
    field(0xc0, 0x40, "INTERLEAVE_2"),
    field(0xc0, 0x80, "INTERLEAVE_4"),
];

const ATTRIBUTES: EnumTable = &[
    (0, "No alpha"),
    (1, "Undefined alpha (ignore)"),
    (2, "Undefined alpha (retain)"),
    (3, "Alpha"),
    (4, "Premultiplied alpha"),
];

record! {
    pub struct Header {
        id_length: u8 "ID length",
        colormap_type: u8 "Color map type" .desc("1 = a color map is present"),
        image_type: u8 "Image type" .enumeration(IMAGE_TYPES),
        colormap_first: u16 "First color map entry",
        colormap_length: u16 "Color map length",
        colormap_bits: u8 "Color map entry size" .desc("Bits per entry"),
        x_origin: u16 "X origin",
        y_origin: u16 "Y origin",
        width: u16 "Width",
        height: u16 "Height",
        depth: u8 "Pixel depth",
        descriptor: u8 "Image descriptor" .flags(DESCRIPTOR)
            .with(|&d, n| n.summary(format!("{} alpha bits", d & 15))),
    }
}

record! {
    pub struct Footer {
        extension_offset: u32 "Extension area offset" .hex(),
        developer_offset: u32 "Developer directory offset" .hex(),
        signature: ascii[18] "Signature",
    }
}

fn extension_area(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Extension size").emit()?;
    f.ascii("Author name", 41).emit()?;
    f.ascii("Author comments", 324).emit()?;
    f.u16("Month").emit()?;
    f.u16("Day").emit()?;
    f.u16("Year").emit()?;
    f.u16("Hour").emit()?;
    f.u16("Minute").emit()?;
    f.u16("Second").emit()?;
    f.ascii("Job name", 41).emit()?;
    f.u16("Job hours").emit()?;
    f.u16("Job minutes").emit()?;
    f.u16("Job seconds").emit()?;
    f.ascii("Software ID", 41).emit()?;
    f.u16("Software version")
        .with(|&v, n| n.summary(format!("{}.{:02}", v / 100, v % 100)))
        .emit()?;
    f.ascii("Software version letter", 1).emit()?;
    f.u32("Key color").hex().emit()?;
    f.u16("Pixel aspect numerator").emit()?;
    f.u16("Pixel aspect denominator").emit()?;
    f.u16("Gamma numerator").emit()?;
    f.u16("Gamma denominator").emit()?;
    f.u32("Color correction offset").hex().emit()?;
    f.u32("Postage stamp offset").hex().emit()?;
    f.u32("Scan line table offset").hex().emit()?;
    f.u8("Attributes type").enumeration(ATTRIBUTES).emit()?;
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let kind = lookup(IMAGE_TYPES, h.image_type.into()).unwrap_or("unknown type");
    cx.annotate(format!("{}, {}-bit, {kind}", dims(h.width, h.height), h.depth));

    let mut pos = Header::SIZE;
    if h.id_length > 0 {
        let id = file.sub(pos, h.id_length.into());
        let bytes = cx.read_avail(id).await?;
        cx.emit(
            Node::new("Image ID")
                .span(id)
                .value(text(crate::text::latin1(&bytes))),
        );
        pos = pos.saturating_add(h.id_length.into());
    }
    if h.colormap_type == 1 {
        let entry_bytes = u64::from(h.colormap_bits).saturating_add(7) / 8;
        let len = u64::from(h.colormap_length).saturating_mul(entry_bytes);
        let span = file.sub(pos, len);
        cx.emit(match entry_bytes {
            3 => palette("Color map", span, ColorOrder::Bgr),
            4 => palette("Color map", span, ColorOrder::Bgrx),
            _ => region("Color map", file, pos, len),
        });
        pos = pos.saturating_add(len);
    }

    // The footer, if present, bounds the image data.
    let footer_span = file.tail(file.len.saturating_sub(Footer::SIZE));
    let footer = cx.read_avail(footer_span).await?;
    let mut end = file.len;
    let mut areas: Vec<Node> = Vec::new();
    if footer.ends_with(SIGNATURE) && file.len >= Footer::SIZE {
        end = footer_span.offset.saturating_sub(file.offset);
        let ext = u64::from(u32_le(&footer, 0).unwrap_or(0));
        let dev = u64::from(u32_le(&footer, 4).unwrap_or(0));
        if ext != 0 {
            areas.push(struct_node(
                "Extension area",
                file.sub(ext, 495),
                LE,
                (),
                extension_area,
            ));
            end = end.min(ext);
        }
        if dev != 0 {
            areas.push(
                Node::new("Developer directory")
                    .span(file.sub(dev, 2))
                    .lazy(developer_directory, (file, dev)),
            );
            end = end.min(dev);
        }
        areas.push(Footer::node("Footer", footer_span, LE));
    }
    let rle = h.image_type & 8 != 0;
    let raw_len = u64::from(h.width)
        .saturating_mul(h.height.into())
        .saturating_mul(u64::from(h.depth).saturating_add(7) / 8);
    let len = if rle { end.saturating_sub(pos) } else { raw_len };
    cx.emit(region("Image data", file, pos, len).summary(if rle {
        "run-length encoded".to_owned()
    } else {
        format!("{} rows", h.height)
    }));
    for node in areas {
        cx.emit(node);
    }
    Ok(())
}

async fn developer_directory(cx: Cx, (file, offset): (Span, u64)) -> Result<()> {
    let count_span = file.sub(offset, 2);
    let block = cx.block(count_span).await?;
    let count = Fields::emitting(&cx, &block, LE).u16("Tag count").emit()?;
    for i in 0..u64::from(count) {
        let at = offset.saturating_add(2).saturating_add(i.saturating_mul(10));
        let entry = file.sub(at, 10);
        let block = cx.block(entry).await?;
        let mut f = Fields::new(&block, LE);
        let tag = f.u16("Tag").get()?;
        let data_offset = f.u32("Offset").get()?;
        let size = f.u32("Size").get()?;
        cx.push(
            Node::new(format!("Tag {tag}"))
                .span(entry)
                .summary(format!("{size} bytes"))
                .target(file.sub(data_offset.into(), size.into())),
        )
        .await;
    }
    Ok(())
}
