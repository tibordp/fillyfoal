//! Windows icons (ICO) and cursors (CUR).
//!
//! A 6-byte header and a directory of 16-byte entries, each pointing at an
//! image that is either a PNG stream or a headerless DIB whose height covers
//! both the color (XOR) image and the 1-bit AND mask.

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

use super::dims;

const LE: Endian = Endian::Little;
const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";

pub static ICO: Format = Format {
    name: "ico",
    title: "Windows icon",
    extensions: &["ico"],
    mime: "image/vnd.microsoft.icon",
    probe: Probe::Custom(|h| probe(h, 1)),
    dissect: crate::expander!(dissect: Input),
};

pub static CUR: Format = Format {
    name: "cur",
    title: "Windows cursor",
    extensions: &["cur"],
    mime: "image/x-win-bitmap",
    probe: Probe::Custom(|h| probe(h, 2)),
    dissect: crate::expander!(dissect: Input),
};

/// The magic (`00 00 01 00`) is weak, so the first entry is checked too.
fn probe(h: &Head<'_>, kind: u16) -> bool {
    let d = h.data;
    let (Some(0), Some(k), Some(count)) = (u16_le(d, 0), u16_le(d, 2), u16_le(d, 4)) else {
        return false;
    };
    if k != kind || count == 0 {
        return false;
    }
    let directory_end = 6u64.saturating_add(u64::from(count).saturating_mul(16));
    let (Some(&reserved), Some(planes), Some(bits), Some(size), Some(offset)) = (
        d.get(9),
        u16_le(d, 10),
        u16_le(d, 12),
        u32_le(d, 14),
        u32_le(d, 18),
    ) else {
        return false;
    };
    let fields_ok = kind == 2 || (planes <= 1 && matches!(bits, 0 | 1 | 2 | 4 | 8 | 16 | 24 | 32));
    reserved == 0
        && fields_ok
        && size > 0
        && u64::from(offset) >= directory_end
        && u64::from(offset).saturating_add(size.into()) <= h.len
}

const TYPES: EnumTable = &[(1, "Icon"), (2, "Cursor")];

record! {
    pub struct Header {
        reserved: u16 "Reserved",
        kind: u16 "Type" .enumeration(TYPES),
        count: u16 "Image count",
    }
}

record! {
    pub struct IconEntry {
        width: u8 "Width" .desc("0 means 256"),
        height: u8 "Height" .desc("0 means 256"),
        colors: u8 "Color count" .desc("0 if 8 bits per pixel or more"),
        reserved: u8 "Reserved",
        planes: u16 "Planes",
        bit_count: u16 "Bits per pixel",
        size: u32 "Image size",
        offset: u32 "Image offset" .hex(),
    }
}

record! {
    pub struct CursorEntry {
        width: u8 "Width" .desc("0 means 256"),
        height: u8 "Height" .desc("0 means 256"),
        colors: u8 "Color count",
        reserved: u8 "Reserved",
        hotspot_x: u16 "Hotspot X",
        hotspot_y: u16 "Hotspot Y",
        size: u32 "Image size",
        offset: u32 "Image offset" .hex(),
    }
}

fn side(v: u8) -> u16 {
    if v == 0 { 256 } else { v.into() }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let header = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let what = if header.kind == 2 { "cursor" } else { "icon" };
    cx.annotate(format!("Windows {what}, {} images", header.count));
    cx.set_count(Count::Exact(u64::from(header.count).saturating_add(1)));
    for index in 0..u64::from(header.count) {
        let entry_span = file.sub(
            Header::SIZE.saturating_add(index.saturating_mul(IconEntry::SIZE)),
            IconEntry::SIZE,
        );
        let entry = parse(&cx, entry_span, LE, &(), IconEntry::layout).await?;
        let image = file.sub(entry.offset.into(), entry.size.into());
        let magic = cx.read_avail(image.sub(0, 8)).await?;
        let png = magic == PNG;
        let mut summary = dims(side(entry.width), side(entry.height));
        if png {
            summary.push_str(", PNG");
        } else if entry.bit_count != 0 && header.kind == 1 {
            summary = format!("{summary}, {}-bit", entry.bit_count);
        }
        cx.push(
            Node::new(format!("Image {index}"))
                .span(entry_span)
                .summary(summary)
                .target(image)
                .lazy(image_entry, (input, entry_span, image, header.kind, png)),
        )
        .await;
    }
    Ok(())
}

async fn image_entry(
    cx: Cx,
    (input, entry, image, kind, png): (Input, Span, Span, u16, bool),
) -> Result<()> {
    if kind == 2 {
        cx.emit(CursorEntry::node("Directory entry", entry, LE));
    } else {
        cx.emit(IconEntry::node("Directory entry", entry, LE));
    }
    if png {
        cx.emit(embedded("PNG image", input.nested(image)));
    } else {
        cx.emit(
            Node::new("DIB image")
                .span(image)
                .lazy(dib_image, (input, image)),
        );
    }
    Ok(())
}

async fn dib_image(cx: Cx, (input, image): (Input, Span)) -> Result<()> {
    let info = super::bmp::dib(&cx, input, image, None, true).await?;
    cx.annotate(super::bmp::describe(&super::bmp::Info {
        height: info.height / 2,
        ..info
    }));
    Ok(())
}
