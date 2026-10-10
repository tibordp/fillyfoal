//! X Window Dump (XWD, version 7): a big-endian header of 25 32-bit fields,
//! the window name, a color table of 12-byte entries and the image.

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::val::text;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{dims, region};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "xwd",
    title: "X Window Dump",
    extensions: &["xwd"],
    mime: "image/x-xwindowdump",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// No magic beyond the version, so several fields must be in range.
fn probe(h: &Head<'_>) -> bool {
    let field = |i: usize| u32_be(h.data, i.saturating_mul(4));
    let (Some(size), Some(7), Some(format), Some(depth), Some(order), Some(class)) =
        (field(0), field(1), field(2), field(3), field(7), field(13))
    else {
        return false;
    };
    (100..=4096).contains(&size)
        && format <= 2
        && (1..=32).contains(&depth)
        && order <= 1
        && class <= 5
}

const PIXMAP_FORMATS: EnumTable = &[(0, "XYBitmap"), (1, "XYPixmap"), (2, "ZPixmap")];
const BYTE_ORDER: EnumTable = &[(0, "LSBFirst"), (1, "MSBFirst")];
const VISUALS: EnumTable = &[
    (0, "StaticGray"),
    (1, "GrayScale"),
    (2, "StaticColor"),
    (3, "PseudoColor"),
    (4, "TrueColor"),
    (5, "DirectColor"),
];

record! {
    pub struct Header {
        header_size: u32 "Header size" .desc("Including the window name"),
        version: u32 "File version",
        pixmap_format: u32 "Pixmap format" .enumeration(PIXMAP_FORMATS),
        depth: u32 "Pixmap depth",
        width: u32 "Pixmap width",
        height: u32 "Pixmap height",
        xoffset: u32 "X offset",
        byte_order: u32 "Byte order" .enumeration(BYTE_ORDER),
        bitmap_unit: u32 "Bitmap unit",
        bit_order: u32 "Bitmap bit order" .enumeration(BYTE_ORDER),
        bitmap_pad: u32 "Bitmap pad",
        bits_per_pixel: u32 "Bits per pixel",
        bytes_per_line: u32 "Bytes per line",
        visual_class: u32 "Visual class" .enumeration(VISUALS),
        red_mask: u32 "Red mask" .hex(),
        green_mask: u32 "Green mask" .hex(),
        blue_mask: u32 "Blue mask" .hex(),
        bits_per_rgb: u32 "Bits per RGB",
        colormap_entries: u32 "Colormap entries",
        ncolors: u32 "Number of colors",
        window_width: u32 "Window width",
        window_height: u32 "Window height",
        window_x: u32 "Window X",
        window_y: u32 "Window Y",
        border: u32 "Window border width",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let name_len = u64::from(h.header_size).saturating_sub(Header::SIZE);
    let name_span = file.sub(Header::SIZE, name_len);
    let name = crate::text::until_nul(&cx.read_avail(name_span).await?);
    cx.emit(
        Node::new("Window name")
            .span(name_span)
            .value(text(name.clone())),
    );
    let visual = lookup(VISUALS, h.visual_class.into()).unwrap_or("unknown visual");
    let mut summary = format!("{}, {}-bit {visual}", dims(h.width, h.height), h.depth);
    if !name.is_empty() {
        summary = format!("{summary}, {name:?}");
    }
    cx.annotate(summary);
    let colors_at = u64::from(h.header_size);
    let colors = file.sub(colors_at, u64::from(h.ncolors).saturating_mul(12));
    if h.ncolors > 0 {
        cx.emit(
            Node::new("Colors")
                .span(colors)
                .summary(format!("{} entries", h.ncolors))
                .lazy(color_table, colors),
        );
    }
    let start = colors_at.saturating_add(u64::from(h.ncolors).saturating_mul(12));
    let len = u64::from(h.bytes_per_line).saturating_mul(h.height.into());
    cx.emit(region("Image data", file, start, len).summary(format!(
        "{} rows of {:#x} bytes",
        h.height, h.bytes_per_line
    )));
    Ok(())
}

async fn color_table(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 12;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let entry = span.sub(i.saturating_mul(12), 12);
        let b = cx.read(entry).await?;
        let get = |at: usize| crate::bytes::u16_be(&b, at).unwrap_or(0);
        let pixel = u32_be(&b, 0).unwrap_or(0);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(entry)
                .value(text(format!("#{:04x}{:04x}{:04x}", get(4), get(6), get(8))))
                .summary(format!("pixel {pixel}")),
        )
        .await;
    }
    Ok(())
}
