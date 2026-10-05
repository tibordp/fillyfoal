//! WebP chunks: `VP8 ` (lossy), `VP8L` (lossless), `VP8X` (extended),
//! `ALPH`, `ANIM`, `ANMF` (whose data holds further chunks), `ICCP` and
//! `EXIF` (dissected as embedded content).

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::iff::{Chunk, Ctx, FourCc, scan, walk};
use crate::formats::sound::{Bits, bits_node, parse_bits, u24};
use crate::formats::embedded;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const VP8X_FLAGS: FlagTable = &[
    flag(0x20, "ICC"),
    flag(0x10, "ALPHA"),
    flag(0x08, "EXIF"),
    flag(0x04, "XMP"),
    flag(0x02, "ANIMATION"),
];

const FRAME_FLAGS: FlagTable = &[flag(0x2, "DO_NOT_BLEND"), flag(0x1, "DISPOSE_TO_BACKGROUND")];

const ALPHA_COMPRESSION: EnumTable = &[(0, "none"), (1, "lossless (VP8L)")];
const ALPHA_FILTER: EnumTable = &[(0, "none"), (1, "horizontal"), (2, "vertical"), (3, "gradient")];
const PREPROCESSING: EnumTable = &[(0, "none"), (1, "level reduction")];
const SCALE: EnumTable = &[(0, "none"), (1, "5/4"), (2, "5/3"), (3, "2")];

pub fn describe_id(id: &FourCc) -> Option<&'static str> {
    Some(match id {
        b"VP8 " => "Lossy image data (VP8 key frame)",
        b"VP8L" => "Lossless image data",
        b"VP8X" => "Extended format header",
        b"ALPH" => "Alpha channel",
        b"ANIM" => "Animation parameters",
        b"ANMF" => "Animation frame",
        b"ICCP" => "ICC color profile",
        b"EXIF" => "Exif metadata",
        b"XMP " => "XMP metadata",
        _ => return None,
    })
}

/// Image dimensions of a `VP8 ` key frame, `VP8L` or `VP8X` chunk.
#[derive(Clone, Copy, Debug)]
struct Size {
    width: u64,
    height: u64,
    alpha: bool,
}

/// VP8 frame header: a 3-byte little-endian tag, then (for key frames) a
/// start code and two 14-bit dimensions with 2-bit scales.
fn vp8(b: &mut Bits<'_>) -> Result<Option<Size>> {
    let key = b.field("Frame type", 1).with(|v, n| {
        n.summary(if v == 0 { "key frame" } else { "interframe" })
    });
    let key = key.emit()? == 0;
    b.field("Version", 3).emit()?;
    b.field("Show frame", 1).flag().emit()?;
    b.field("First partition size", 19).emit()?;
    if !key {
        return Ok(None);
    }
    // Stored as 9d 01 2a; read least significant bit first that is 0x2a019d.
    b.field("Start code", 24)
        .hex()
        .with(|v, n| {
            if v == 0x2a_019d {
                n.summary("9d 01 2a")
            } else {
                n.diag(Diagnostic::malformed("expected 9d 01 2a"))
            }
        })
        .emit()?;
    let width = b.field("Width", 14).emit()?;
    b.field("Horizontal scale", 2).enumeration(SCALE).emit()?;
    let height = b.field("Height", 14).emit()?;
    b.field("Vertical scale", 2).enumeration(SCALE).emit()?;
    Ok(Some(Size {
        width,
        height,
        alpha: false,
    }))
}

fn vp8l(b: &mut Bits<'_>) -> Result<Size> {
    b.field("Signature", 8)
        .hex()
        .with(|v, n| {
            if v == 0x2f {
                n
            } else {
                n.diag(Diagnostic::malformed("expected 0x2f"))
            }
        })
        .emit()?;
    let width = b
        .field("Width − 1", 14)
        .with(|v, n| n.summary(format!("{} px", v.saturating_add(1))))
        .emit()?;
    let height = b
        .field("Height − 1", 14)
        .with(|v, n| n.summary(format!("{} px", v.saturating_add(1))))
        .emit()?;
    let alpha = b.field("Alpha is used", 1).flag().emit()? != 0;
    b.field("Version", 3).emit()?;
    Ok(Size {
        width: width.saturating_add(1),
        height: height.saturating_add(1),
        alpha,
    })
}

fn alph(b: &mut Bits<'_>) -> Result<()> {
    b.field("Reserved", 2).emit()?;
    b.field("Preprocessing", 2)
        .enumeration(PREPROCESSING)
        .emit()?;
    b.field("Filtering method", 2)
        .enumeration(ALPHA_FILTER)
        .emit()?;
    b.field("Compression method", 2)
        .enumeration(ALPHA_COMPRESSION)
        .emit()?;
    Ok(())
}

struct Vp8x {
    size: Size,
}

fn vp8x(f: &mut Fields<'_>, _: &()) -> Result<Vp8x> {
    let flags = f.u8("Flags").flags(VP8X_FLAGS).emit()?;
    u24(f, "Reserved", crate::fields::Endian::Little).emit()?;
    let width = u24(f, "Canvas width − 1", crate::fields::Endian::Little)
        .with(|&v, n| n.summary(format!("{} px", v.saturating_add(1))))
        .emit()?;
    let height = u24(f, "Canvas height − 1", crate::fields::Endian::Little)
        .with(|&v, n| n.summary(format!("{} px", v.saturating_add(1))))
        .emit()?;
    Ok(Vp8x {
        size: Size {
            width: u64::from(width).saturating_add(1),
            height: u64::from(height).saturating_add(1),
            alpha: flags & 0x10 != 0,
        },
    })
}

struct Frame {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    duration: u32,
}

fn anmf(f: &mut Fields<'_>, _: &()) -> Result<Frame> {
    use crate::fields::Endian::Little as LE;
    let x = u24(f, "X offset / 2", LE).emit()?;
    let y = u24(f, "Y offset / 2", LE).emit()?;
    let width = u24(f, "Width − 1", LE).emit()?;
    let height = u24(f, "Height − 1", LE).emit()?;
    let duration = u24(f, "Duration", LE).desc("Milliseconds").emit()?;
    f.u8("Flags")
        .flags(FRAME_FLAGS)
        .emit()?;
    Ok(Frame {
        x: x.saturating_mul(2),
        y: y.saturating_mul(2),
        width: width.saturating_add(1),
        height: height.saturating_add(1),
        duration,
    })
}

async fn size_of(cx: &Cx, id: &FourCc, data: Span) -> Result<Option<Size>> {
    Ok(match id {
        b"VP8 " => parse_bits(cx, data.sub(0, 10), vp8, true).await?,
        b"VP8L" => Some(parse_bits(cx, data.sub(0, 5), vp8l, true).await?),
        b"VP8X" => Some(
            crate::fields::parse(cx, data.sub(0, 10), crate::fields::Endian::Little, &(), vp8x)
                .await?
                .size,
        ),
        _ => None,
    })
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    if let Some(size) = size_of(cx, &chunk.id, chunk.data).await? {
        let alpha = if size.alpha { ", alpha" } else { "" };
        return Ok(Some(format!("{}×{}{alpha}", size.width, size.height)));
    }
    Ok(match &chunk.id {
        b"ANMF" => {
            let fr = crate::fields::parse(
                cx,
                chunk.data.sub(0, 16),
                crate::fields::Endian::Little,
                &(),
                anmf,
            )
            .await?;
            Some(format!(
                "{}×{} at ({}, {}), {} ms",
                fr.width, fr.height, fr.x, fr.y, fr.duration
            ))
        }
        _ => None,
    })
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let data = chunk.data;
    let input = chunk.input();
    let e = chunk.endian();
    match &chunk.id {
        b"VP8 " => {
            cx.emit(bits_node("Frame header", data.sub(0, 10), |b| vp8(b).map(|_| ()), true));
            cx.emit(Node::new("Bitstream").span(data.tail(10)));
        }
        b"VP8L" => {
            cx.emit(bits_node("Header", data.sub(0, 5), |b| vp8l(b).map(|_| ()), true));
            cx.emit(Node::new("Bitstream").span(data.tail(5)));
        }
        b"VP8X" => {
            let block = cx.block(data.sub(0, 10)).await?;
            vp8x(&mut Fields::emitting(cx, &block, e), &())?;
        }
        b"ALPH" => {
            cx.emit(bits_node("Header", data.sub(0, 1), alph, false));
            cx.emit(Node::new("Alpha bitstream").span(data.tail(1)));
        }
        b"ANIM" => {
            let block = cx.block(data.sub(0, 6)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Background color")
                .hex()
                .desc("Blue, green, red, alpha")
                .emit()?;
            f.u16("Loop count").desc("0 = infinite").emit()?;
        }
        b"ANMF" => {
            let block = cx.block(data.sub(0, 16)).await?;
            anmf(&mut Fields::emitting(cx, &block, e), &())?;
            walk(cx, &chunk.ctx, data.tail(16), chunk.id).await?;
        }
        b"ICCP" => cx.emit(embedded("ICC profile", input.nested(data))),
        b"EXIF" => cx.emit(embedded("Exif", input.nested(data))),
        _ => return Ok(false),
    }
    Ok(true)
}

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let chunks = scan(cx, ctx, region, 4096).await?;
    let Some(first) = chunks.first() else {
        return Ok(None);
    };
    let kind = match &first.id {
        b"VP8 " => "lossy",
        b"VP8L" => "lossless",
        b"VP8X" => "extended",
        _ => return Ok(None),
    };
    let Some(size) = size_of(cx, &first.id, first.data).await? else {
        return Ok(Some(format!("WebP {kind}")));
    };
    let mut line = format!("WebP {kind}, {}×{}", size.width, size.height);
    if &first.id == b"VP8X" {
        let flags = cx.read_avail(first.data.sub(0, 1)).await?;
        let flags = flags.first().copied().unwrap_or(0);
        let frames = chunks.iter().filter(|c| &c.id == b"ANMF").count();
        if flags & 0x02 != 0 {
            line.push_str(&format!(", animated, {frames} frames"));
        } else if let Some(image) = chunks.iter().find(|c| matches!(&c.id, b"VP8 " | b"VP8L")) {
            line.push_str(if &image.id == b"VP8L" {
                ", lossless"
            } else {
                ", lossy"
            });
        }
        for (bit, name) in [(0x10, "alpha"), (0x20, "ICC"), (0x08, "Exif"), (0x04, "XMP")] {
            if flags & bit != 0 {
                line.push_str(&format!(", {name}"));
            }
        }
    } else if size.alpha {
        line.push_str(", alpha");
    }
    Ok(Some(line))
}
