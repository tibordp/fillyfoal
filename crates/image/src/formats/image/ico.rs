//! Windows icons (ICO) and cursors (CUR).
//!
//! A 6-byte header and a directory of 16-byte entries, each pointing at an
//! image that is either a PNG stream or a headerless DIB whose height covers
//! both the color (XOR) image and the 1-bit AND mask. Cursors keep their
//! hotspot where icons have planes and bit count.

use crate::bytes::{u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Head, Input, Probe, embedded_as};
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
        reserved: u16 "Reserved" .desc("Always 0"),
        kind: u16 "Type" .enumeration(TYPES),
        count: u16 "Image count",
    }
}

record! {
    pub struct IconEntry {
        width: u8 "Width" .desc("0 means 256") .with(|&v, n| if v == 0 { n.summary("256 px") } else { n }),
        height: u8 "Height" .desc("0 means 256") .with(|&v, n| if v == 0 { n.summary("256 px") } else { n }),
        colors: u8 "Color count" .desc("Palette entries; 0 for 8 bits per pixel or more"),
        reserved: u8 "Reserved",
        planes: u16 "Planes" .desc("0 or 1"),
        bit_count: u16 "Bits per pixel" .desc("Often 0 for PNG images; the image itself is authoritative"),
        size: u32 "Image size" .desc("Size of the image data in bytes"),
        offset: u32 "Image offset" .hex() .desc("Offset of the image data from the start of the file"),
    }
}

record! {
    pub struct CursorEntry {
        width: u8 "Width" .desc("0 means 256") .with(|&v, n| if v == 0 { n.summary("256 px") } else { n }),
        height: u8 "Height" .desc("0 means 256") .with(|&v, n| if v == 0 { n.summary("256 px") } else { n }),
        colors: u8 "Color count",
        reserved: u8 "Reserved",
        hotspot_x: u16 "Hotspot X" .desc("The click point, from the left"),
        hotspot_y: u16 "Hotspot Y" .desc("The click point, from the top"),
        size: u32 "Image size" .desc("Size of the image data in bytes"),
        offset: u32 "Image offset" .hex() .desc("Offset of the image data from the start of the file"),
    }
}

fn side(v: u8) -> u16 {
    if v == 0 { 256 } else { v.into() }
}

/// Sizes listed in the file summary at most.
const SUMMARY_SIZES: usize = 8;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let header = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let cursor = header.kind == 2;
    let what = if cursor { "cursor" } else { "icon" };
    let directory = file.sub(
        Header::SIZE,
        u64::from(header.count).saturating_mul(IconEntry::SIZE),
    );
    let entries = cx.read_avail(directory).await?;
    let mut sizes: Vec<String> = Vec::new();
    for entry in entries.as_chunks::<16>().0.iter().take(SUMMARY_SIZES) {
        let w = side(entry.first().copied().unwrap_or(0));
        let h = side(entry.get(1).copied().unwrap_or(0));
        let offset = u32_le(entry, 12).unwrap_or(0);
        let magic = cx.read_avail(file.sub(offset.into(), 8)).await?;
        let mut s = dims(w, h);
        if magic == PNG {
            s.push_str(" PNG");
        } else if !cursor && let Some(bits) = u16_le(entry, 6).filter(|&b| b != 0) {
            s = format!("{s} {bits}-bit");
        }
        sizes.push(s);
    }
    let mut line = format!("Windows {what}, {}", plural(header.count, "image"));
    if !sizes.is_empty() {
        line = format!("{line}: {}", sizes.join(", "));
        if usize::from(header.count) > SUMMARY_SIZES {
            line.push_str(", …");
        }
    }
    cx.annotate(line);
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
        } else if entry.bit_count != 0 && !cursor {
            summary = format!("{summary}, {}-bit", entry.bit_count);
        }
        if cursor {
            // planes and bit_count hold the hotspot.
            summary = format!("{summary}, hotspot ({}, {})", entry.planes, entry.bit_count);
        }
        summary = format!("{summary}, {}", human_size(entry.size.into()));
        let mut node = Node::new(format!("Image {index}"))
            .span(entry_span)
            .summary(summary)
            .target(image);
        if image.len < u64::from(entry.size) {
            node = node.diag(Diagnostic::truncated(
                Span::new(image.source, image.offset, entry.size.into()),
                image.len,
            ));
        }
        if u64::from(entry.offset) < Header::SIZE.saturating_add(directory.len) {
            node = node.diag(Diagnostic::malformed("the image overlaps the directory"));
        }
        cx.push(node.lazy(
            image_entry,
            Entry {
                input,
                entry: entry_span,
                image,
                cursor,
                png,
                width: side(entry.width),
                height: side(entry.height),
            },
        ))
        .await;
    }
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    input: Input,
    entry: Span,
    image: Span,
    cursor: bool,
    png: bool,
    width: u16,
    height: u16,
}

async fn image_entry(cx: Cx, e: Entry) -> Result<()> {
    if e.cursor {
        cx.emit(CursorEntry::node("Directory entry", e.entry, LE));
    } else {
        cx.emit(IconEntry::node("Directory entry", e.entry, LE));
    }
    if e.png {
        let ihdr = cx.read_avail(e.image.sub(16, 8)).await?;
        let mut node = embedded_as("PNG image", e.input.nested(e.image), &super::png::FORMAT)
            .desc("Stored as a complete PNG file (Windows Vista and later)");
        if let (Some(w), Some(h)) = (u32_be(&ihdr, 0), u32_be(&ihdr, 4))
            && (w != u32::from(e.width) || h != u32::from(e.height))
        {
            node = node.diag(Diagnostic::note(format!(
                "the directory says {}, the PNG is {}",
                dims(e.width, e.height),
                dims(w, h)
            )));
        }
        cx.emit(node);
    } else {
        let head = cx.read_avail(e.image.sub(4, 8)).await?;
        let mut node = Node::new("DIB image")
            .span(e.image)
            .desc(
                "A device-independent bitmap without file header. Its header's height \
                 is twice the icon's: the color (XOR) image is followed by a 1-bit AND \
                 mask of the same size, which marks transparent pixels",
            )
            .lazy(dib_image, (e.input, e.image));
        if let (Some(w), Some(h)) = (
            crate::bytes::i32_le(&head, 0),
            crate::bytes::i32_le(&head, 4),
        ) && (i64::from(w) != i64::from(e.width)
            || i64::from(h) != i64::from(e.height).saturating_mul(2))
        {
            node = node.diag(Diagnostic::note(format!(
                "the directory says {}, the bitmap header {}×{} (twice the height expected)",
                dims(e.width, e.height),
                w,
                h
            )));
        }
        cx.emit(node);
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
