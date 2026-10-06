//! Sun raster images: a 32-byte big-endian header, an optional planar
//! color map and the pixel data.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, lookup};

use super::{dims, region};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "sunras",
    title: "Sun raster image",
    extensions: &["ras", "sun", "rs", "im1", "im8", "im24", "im32"],
    mime: "image/x-sun-raster",
    probe: Probe::Magic(&[(0, b"\x59\xa6\x6a\x95")]),
    dissect: crate::expander!(dissect: Input),
};

const TYPES: EnumTable = &[
    (0, "RT_OLD"),
    (1, "RT_STANDARD"),
    (2, "RT_BYTE_ENCODED (RLE)"),
    (3, "RT_FORMAT_RGB"),
    (4, "RT_FORMAT_TIFF"),
    (5, "RT_FORMAT_IFF"),
    (0xffff, "RT_EXPERIMENTAL"),
];

const MAP_TYPES: EnumTable = &[(0, "RMT_NONE"), (1, "RMT_EQUAL_RGB"), (2, "RMT_RAW")];

record! {
    pub struct Header {
        magic: u32 "Magic" .hex(),
        width: u32 "Width",
        height: u32 "Height",
        depth: u32 "Depth" .desc("Bits per pixel"),
        length: u32 "Length" .desc("Image data length (0 in old files)"),
        kind: u32 "Type" .enumeration(TYPES),
        map_type: u32 "Color map type" .enumeration(MAP_TYPES),
        map_length: u32 "Color map length",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let kind = lookup(TYPES, h.kind.into()).unwrap_or("unknown type");
    cx.annotate(format!("{}, {}-bit, {kind}", dims(h.width, h.height), h.depth));
    let mut pos = Header::SIZE;
    if h.map_length > 0 {
        let map = region("Color map", file, pos, h.map_length.into());
        cx.emit(if h.map_type == 1 {
            map.summary(format!("{} entries, planar R, G, B", h.map_length / 3))
        } else {
            map
        });
        pos = pos.saturating_add(h.map_length.into());
    }
    let stride = (u64::from(h.width)
        .saturating_mul(h.depth.into())
        .saturating_add(15)
        / 16)
        .saturating_mul(2);
    let len = if h.length != 0 {
        u64::from(h.length)
    } else if h.kind == 2 {
        file.len.saturating_sub(pos)
    } else {
        stride.saturating_mul(h.height.into())
    };
    let node = region("Pixel data", file, pos, len);
    cx.emit(if h.kind == 2 {
        node.summary("run-length encoded")
    } else {
        node.summary(format!("{} rows of {stride:#x} bytes", h.height))
    });
    let end = pos.saturating_add(len);
    if end < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(end)));
    }
    Ok(())
}
