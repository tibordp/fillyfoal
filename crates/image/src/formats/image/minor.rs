//! Less common raster formats: PGF, XV thumbnails and Khoros VIFF.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::val::{text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::text::until_nul;
use crate::value::Value;

const LE: Endian = Endian::Little;

use crate::formats::text::scan::head_lines as lines;

// ---------------------------------------------------------------------------
// Small image formats: PGF, XV thumbnails, Khoros VIFF

declare_format!(pub PGF = "pgf", "Progressive Graphics File", ["pgf"], "image/x-pgf",
    Probe::Magic(&[(0, b"PGF")]), pgf);

async fn pgf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 3).emit()?;
    let version = f.u8("Version").hex().emit()?;
    let size = f.u32("Header size").emit()?;
    let w = f.u32("Width").emit()?;
    let h = f.u32("Height").emit()?;
    let levels = f.u8("Levels").emit()?;
    f.u8("Quality").emit()?;
    let bpp = f.u8("Bits per pixel").emit()?;
    let channels = f.u8("Channels").emit()?;
    f.u8("Mode").emit()?;
    f.u8("Used bits per channel").emit()?;
    cx.emit(Node::new("Image data").span(file.tail(8u64.saturating_add(size.into()))));
    cx.annotate(format!(
        "PGF v{version:x}, {w}×{h}, {bpp} bpp, {channels} channel(s), {levels} levels"
    ));
    Ok(())
}

declare_format!(pub XV_THUMB = "xv-thumbnail", "XV thumbnail", [], "image/x-xv-thumbnail",
    Probe::Magic(&[(0, b"P7 332\n")]), xv_thumb);

async fn xv_thumb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let all = lines(&cx, file, 4096).await?;
    let mut dims = String::new();
    for (line, span) in &all {
        if line.starts_with("#IMGINFO:") {
            cx.emit(
                Node::new("Image info")
                    .span(*span)
                    .value(text(line.trim_start_matches("#IMGINFO:"))),
            );
        } else if !line.starts_with('#') && !line.starts_with("P7") && !line.is_empty() {
            dims = line.clone();
            cx.emit(
                Node::new("Dimensions")
                    .span(*span)
                    .value(text(line.clone())),
            );
            cx.emit(
                Node::new("Pixels (3-3-2 RGB)")
                    .span(file.tail(span.end().saturating_sub(file.offset).saturating_add(1))),
            );
            break;
        }
    }
    let wh: Vec<&str> = dims.split_whitespace().collect();
    cx.annotate(format!(
        "XV thumbnail, {}×{}",
        wh.first().unwrap_or(&"?"),
        wh.get(1).unwrap_or(&"?")
    ));
    Ok(())
}

fn viff_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\xab\x01") && h.data.get(2) == Some(&1) && h.data.get(3) == Some(&3)
}

declare_format!(pub VIFF = "viff", "Khoros VIFF image", ["xv", "viff"], "image/x-viff",
    Probe::Custom(viff_probe), viff);

async fn viff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 1024)).await?;
    let big = head.get(4).copied().unwrap_or(0) == 0x2;
    let int = |at: usize| {
        if big {
            u32_be(&head, at)
        } else {
            u32_le(&head, at)
        }
        .unwrap_or(0)
    };
    cx.emit(Node::new("Identifier").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Machine dependency")
            .span(file.sub(4, 1))
            .value(Value::Enum {
                raw: head.get(4).copied().unwrap_or(0).into(),
                bits: 8,
                name: Some(if big {
                    "big-endian (IEEE)"
                } else {
                    "little-endian"
                }),
            }),
    );
    let comment = until_nul(head.get(8..520).unwrap_or_default());
    cx.emit(
        Node::new("Comment")
            .span(file.sub(8, 512))
            .value(text(comment)),
    );
    let (w, h) = (int(520), int(524));
    cx.emit(Node::new("Width").span(file.sub(520, 4)).value(uint(w, 32)));
    cx.emit(
        Node::new("Height")
            .span(file.sub(524, 4))
            .value(uint(h, 32)),
    );
    cx.emit(Node::new("Image data").span(file.tail(1024)));
    cx.annotate(format!("VIFF image, {w}×{h}"));
    Ok(())
}
