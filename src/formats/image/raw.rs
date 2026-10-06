//! Camera raw formats with their own containers (TIFF-based ones live in
//! `tiff.rs`): Fujifilm RAF and Minolta MRW. Both wrap a JPEG preview
//! and/or TIFF metadata, handed to those dissectors.

use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{dims, region};

const BE: Endian = Endian::Big;

pub static RAF: Format = Format {
    name: "raf",
    title: "Fujifilm raw (RAF)",
    extensions: &["raf"],
    mime: "image/x-fuji-raf",
    probe: Probe::Magic(&[(0, b"FUJIFILMCCD-RAW ")]),
    dissect: crate::expander!(dissect_raf: Input),
};

pub static MRW: Format = Format {
    name: "mrw",
    title: "Minolta raw (MRW)",
    extensions: &["mrw"],
    mime: "image/x-minolta-mrw",
    probe: Probe::Magic(&[(0, b"\0MRM")]),
    dissect: crate::expander!(dissect_mrw: Input),
};

record! {
    pub struct RafHeader {
        magic: ascii[16] "Magic",
        format_version: ascii[4] "Format version",
        camera_id: ascii[8] "Camera ID",
        camera: ascii[32] "Camera",
        directory_version: ascii[4] "Directory version",
        unknown: bytes[20] "Unknown",
        jpeg_offset: u32 "JPEG offset" .hex(),
        jpeg_length: u32 "JPEG length",
        cfa_header_offset: u32 "CFA header offset" .hex(),
        cfa_header_length: u32 "CFA header length",
        cfa_offset: u32 "CFA offset" .hex(),
        cfa_length: u32 "CFA length",
    }
}

const RAF_TAGS: EnumTable = &[
    (0x0100, "Raw image full size"),
    (0x0110, "Raw image crop top-left"),
    (0x0111, "Raw image cropped size"),
    (0x0115, "Raw image aspect ratio"),
    (0x0121, "Raw image size"),
    (0x0130, "Fuji layout"),
    (0x0131, "X-Trans layout"),
    (0x2000, "White balance (auto)"),
    (0x2ff0, "White balance (as shot)"),
    (0x9650, "Raw exposure bias"),
    (0xc000, "RAF data"),
];

pub async fn dissect_raf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, RafHeader::SIZE);
    let h = parse(&cx, span, BE, &(), RafHeader::layout).await?;
    cx.emit(RafHeader::node("Header", span, BE));
    cx.annotate(format!("Fujifilm {}, format {}", h.camera.trim(), h.format_version));
    if h.jpeg_length > 0 {
        let jpeg = file.sub(h.jpeg_offset.into(), h.jpeg_length.into());
        cx.emit(embedded("JPEG preview", input.nested(jpeg)));
    }
    if h.cfa_header_length > 0 {
        let records = file.sub(h.cfa_header_offset.into(), h.cfa_header_length.into());
        cx.emit(
            Node::new("CFA header")
                .span(records)
                .lazy(raf_records, records),
        );
    }
    if h.cfa_length > 0 {
        let cfa = file.sub(h.cfa_offset.into(), h.cfa_length.into());
        let head = cx.read_avail(cfa.sub(0, 4)).await?;
        if head == b"II*\0" || head == b"MM\0*" {
            cx.emit(embedded_as("CFA (TIFF)", input.nested(cfa), &super::tiff::FORMAT));
        } else {
            cx.emit(Node::new("CFA data").span(cfa));
        }
    }
    Ok(())
}

async fn raf_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    let count = cur.u32().await?;
    cx.emit(Node::new("Record count").span(span.sub(0, 4)).value(super::uint(count)));
    for _ in 0..count {
        if cur.remaining() < 4 {
            break;
        }
        let start = cur.pos();
        let tag = cur.u16().await?;
        let size = cur.u16().await?;
        let data = cur.span(size.into());
        cur.skip(size.into());
        let mut node = Node::new(
            lookup(RAF_TAGS, tag.into()).map_or_else(|| format!("Tag {tag:#06x}"), str::to_owned),
        )
        .span(cur.since(start))
        .summary(format!("{size} bytes"));
        if size == 4 {
            let v = cx.read(data).await?;
            let (a, b) = (
                crate::bytes::u16_be(&v, 0).unwrap_or(0),
                crate::bytes::u16_be(&v, 2).unwrap_or(0),
            );
            node = node.summary(format!("{a}, {b}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

record! {
    pub struct Prd {
        version: ascii[8] "Firmware version",
        sensor_height: u16 "Sensor height",
        sensor_width: u16 "Sensor width",
        image_height: u16 "Image height",
        image_width: u16 "Image width",
        data_size: u8 "Data size" .desc("Bits per sample as stored"),
        pixel_size: u8 "Pixel size" .desc("Significant bits"),
        storage: u8 "Storage method" .hex() .desc("0x52 = unpacked, 0x59 = packed"),
        unknown: bytes[5] "Unknown",
        bayer: u16 "Bayer pattern" .hex() .desc("0x0001 = RGGB, 0x0004 = GBRG"),
    }
}

const MRW_BLOCKS: EnumTable = &[
    (0x0050_5244, "Picture raw dimensions (PRD)"),
    (0x0054_5457, "TIFF metadata (TTW)"),
    (0x0057_4247, "White balance gains (WBG)"),
    (0x0052_4946, "Requested image format (RIF)"),
    (0x0050_4144, "Padding (PAD)"),
];

pub async fn dissect_mrw(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.bytes("Magic", 4).emit()?;
    let len = f.u32("Header length").desc("Offset of the image data minus 8").emit()?;
    let header = file.sub(8, len.into());
    let mut cur = Cursor::new(&cx, header, BE);
    let mut summary = String::from("Minolta raw");
    for _ in 0..64 {
        if cur.remaining() < 8 {
            break;
        }
        let start = cur.pos();
        let tag = cur.u32().await?;
        let size = u64::from(cur.u32().await?);
        let data = cur.span(size);
        cur.skip(size);
        let span = cur.since(start);
        let name = lookup(MRW_BLOCKS, tag.into()).map_or_else(
            || format!("Block {}", crate::text::latin1(&tag.to_be_bytes())),
            str::to_owned,
        );
        match tag {
            0x0050_5244 => {
                if let Ok(prd) = parse(&cx, data.sub(0, Prd::SIZE), BE, &(), Prd::layout).await {
                    summary = format!(
                        "Minolta raw, {}, {}-bit",
                        dims(prd.image_width, prd.image_height),
                        prd.pixel_size
                    );
                }
                cx.emit(Prd::node(name, data, BE).span(span));
            }
            0x0054_5457 => cx.emit(embedded_as(name, input.nested(data), &super::tiff::FORMAT)),
            _ => cx.emit(Node::new(name).span(span).summary(format!("{size} bytes"))),
        }
    }
    cx.annotate(summary);
    let start = 8u64.saturating_add(len.into());
    cx.emit(region("Image data", file, start, file.len.saturating_sub(start)));
    Ok(())
}
