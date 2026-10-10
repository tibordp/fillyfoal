//! Apple icon images (ICNS): `icns`, the file length, then elements
//! `type, length, data`. Modern elements hold PNG or JPEG 2000 streams;
//! older ones hold raw, RLE-compressed or mask bitmaps.

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "icns",
    title: "Apple icon image",
    extensions: &["icns"],
    mime: "image/icns",
    probe: Probe::Magic(&[(0, b"icns")]),
    dissect: crate::expander!(dissect: Input),
};

/// What each element type holds.
fn describe(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"ICON" => "32×32 1-bit icon",
        b"ICN#" => "32×32 1-bit icon and mask",
        b"icm#" => "16×12 1-bit icon and mask",
        b"icm4" => "16×12 4-bit icon",
        b"icm8" => "16×12 8-bit icon",
        b"ics#" => "16×16 1-bit icon and mask",
        b"ics4" => "16×16 4-bit icon",
        b"ics8" => "16×16 8-bit icon",
        b"is32" => "16×16 24-bit RGB (RLE)",
        b"s8mk" => "16×16 8-bit mask",
        b"icl4" => "32×32 4-bit icon",
        b"icl8" => "32×32 8-bit icon",
        b"il32" => "32×32 24-bit RGB (RLE)",
        b"l8mk" => "32×32 8-bit mask",
        b"ich#" => "48×48 1-bit icon and mask",
        b"ich4" => "48×48 4-bit icon",
        b"ich8" => "48×48 8-bit icon",
        b"ih32" => "48×48 24-bit RGB (RLE)",
        b"h8mk" => "48×48 8-bit mask",
        b"it32" => "128×128 24-bit RGB (RLE)",
        b"t8mk" => "128×128 8-bit mask",
        b"icp4" => "16×16",
        b"icp5" => "32×32",
        b"icp6" => "64×64",
        b"ic07" => "128×128",
        b"ic08" => "256×256",
        b"ic09" => "512×512",
        b"ic10" => "1024×1024 (512×512@2x)",
        b"ic11" => "32×32 (16×16@2x)",
        b"ic12" => "64×64 (32×32@2x)",
        b"ic13" => "256×256 (128×128@2x)",
        b"ic14" => "512×512 (256×256@2x)",
        b"ic04" => "16×16 ARGB",
        b"ic05" => "32×32 ARGB",
        b"icsb" => "18×18",
        b"icsB" => "36×36 (18×18@2x)",
        b"sb24" => "24×24",
        b"SB24" => "48×48 (24×24@2x)",
        b"TOC " => "Table of contents",
        b"icnV" => "Icon Composer version",
        b"name" => "Name",
        b"info" => "Info dictionary (property list)",
        b"slct" => "Selected variant",
        b"\xfd\xd9\x2f\xa8" => "Dark mode variant",
        _ => return None,
    })
}

const PNG: &[u8] = b"\x89PNG\r\n\x1a\n";
const JP2: &[u8] = b"\0\0\0\x0cjP  \r\n\x87\n";

/// Elements per listing before giving up on a bogus file.
const MAX_ELEMENTS: u64 = 4096;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Magic", 4).emit()?;
    let declared = f.u32("File length").emit()?;
    let body = file.sub(8, u64::from(declared).saturating_sub(8));
    let icons = elements(&cx, input, body).await?;
    cx.annotate(format!("{} icons: {}", icons.len(), icons.join(", ")));
    Ok(())
}

/// Lists the elements in `body`; returns the types that hold icons.
async fn elements(cx: &Cx, input: Input, body: Span) -> Result<Vec<String>> {
    let mut cur = Cursor::new(cx, body, BE);
    let mut count = 0u64;
    let mut icons = Vec::new();
    while cur.remaining() >= 8 && count < MAX_ELEMENTS {
        let start = cur.pos();
        let kind = cur.bytes(4).await?;
        let len = u64::from(cur.u32().await?);
        if len < 8 {
            break;
        }
        cur.seek(start.saturating_add(len));
        let span = body.sub(start, len);
        let data = span.tail(8);
        let head = cx.read_avail(data.sub(0, 12)).await?;
        let mut summary = describe(&kind).unwrap_or("unknown element").to_owned();
        if head.starts_with(PNG) {
            summary.push_str(", PNG");
        } else if head.starts_with(JP2) {
            summary.push_str(", JPEG 2000");
        } else if head.starts_with(b"ARGB") {
            summary.push_str(" (RLE)");
        }
        if describe(&kind).is_some_and(|d| d.contains('×') && !d.contains("mask")) {
            icons.push(crate::text::latin1(&kind));
        }
        let name = crate::text::latin1(&kind);
        cx.push(Node::new(name).span(span).summary(summary).lazy(
            crate::expander!(self::element: (Input, Span, Vec<u8>)),
            (input, span, kind),
        ))
        .await;
        count = count.saturating_add(1);
    }
    Ok(icons)
}

/// How deeply variant element lists may nest.
const MAX_NESTING: u32 = 4;

async fn element(cx: Cx, (input, span, kind): (Input, Span, Vec<u8>)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.ascii("Type", 4).emit()?;
    f.u32("Length").desc("Includes this 8-byte header").emit()?;
    let data = span.tail(8);
    let head = cx.read_avail(data.sub(0, 12)).await?;
    match kind.as_slice() {
        b"TOC " => {
            cx.emit(Node::new("Entries").span(data).lazy(toc, data));
        }
        b"icnV" => {
            let v = crate::bytes::array::<4>(&head, 0).map(f32::from_be_bytes);
            let mut node = Node::new("Version").span(data);
            if let Some(v) = v {
                node = node.value(crate::value::Value::Float(v.into()));
            }
            cx.emit(node);
        }
        b"name" | b"slct" => {
            let bytes = cx.read_avail(data.sub(0, 256)).await?;
            cx.emit(
                Node::new("Value")
                    .span(data)
                    .value(super::text(crate::text::latin1(&bytes))),
            );
        }
        b"info" => cx.emit(embedded("Contents", input.nested(data))),
        b"\xfd\xd9\x2f\xa8" if input.nesting < MAX_NESTING => {
            cx.emit(Node::new("Elements").span(data).lazy(
                crate::expander!(self::variant: (Input, Span)),
                (input.nested(data), data),
            ));
        }
        _ if head.starts_with(PNG) || head.starts_with(JP2) => {
            cx.emit(embedded("Image", input.nested(data)));
        }
        b"it32" => {
            cx.emit(Node::new("Reserved").span(data.sub(0, 4)));
            cx.emit(Node::new("RLE data").span(data.tail(4)));
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

async fn variant(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    let icons = elements(&cx, input, data).await?;
    cx.annotate(format!("{} icons", icons.len()));
    Ok(())
}

async fn toc(cx: Cx, data: Span) -> Result<()> {
    let n = data.len / 8;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let span = data.sub(i.saturating_mul(8), 8);
        let bytes = cx.read(span).await?;
        let kind = crate::text::latin1(bytes.get(..4).unwrap_or_default());
        let len = u32_be(&bytes, 4).unwrap_or(0);
        cx.push(Node::new(kind).span(span).summary(format!("{len} bytes")))
            .await;
    }
    Ok(())
}
