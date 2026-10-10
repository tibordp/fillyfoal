//! WebP chunks: `VP8 ` (lossy), `VP8L` (lossless), `VP8X` (extended),
//! `ALPH`, `ANIM`, `ANMF` (whose data holds further chunks), `ICCP` and
//! `EXIF` (dissected as embedded content).
//!
//! The VP8 frame header and the VP8L header are decoded bit by bit, and the
//! VP8L stream (also the payload of lossless `ALPH`) up to the first
//! entropy-coded part: its transforms, color cache and prefix-code grouping.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::iff::{Chunk, Ctx, FourCc, scan, walk};
use crate::formats::util::sound::{Bits, bits_node, parse_bits, u24};
use crate::formats::{embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const LE: Endian = Endian::Little;

const VP8X_FLAGS: FlagTable = &[
    flag(0x20, "ICC"),
    flag(0x10, "ALPHA"),
    flag(0x08, "EXIF"),
    flag(0x04, "XMP"),
    flag(0x02, "ANIMATION"),
];

const FRAME_FLAGS: FlagTable = &[
    flag(0x2, "DO_NOT_BLEND"),
    flag(0x1, "DISPOSE_TO_BACKGROUND"),
];

const ALPHA_COMPRESSION: EnumTable = &[(0, "uncompressed"), (1, "lossless (VP8L)")];
const ALPHA_FILTER: EnumTable = &[
    (0, "none"),
    (1, "horizontal"),
    (2, "vertical"),
    (3, "gradient"),
];
const PREPROCESSING: EnumTable = &[(0, "none"), (1, "level reduction (quantized)")];
const SCALE: EnumTable = &[(0, "none"), (1, "5/4"), (2, "5/3"), (3, "2")];
const VP8_VERSION: EnumTable = &[
    (0, "bicubic reconstruction, normal loop filter"),
    (1, "bilinear reconstruction, simple loop filter"),
    (2, "bilinear reconstruction, no loop filter"),
    (3, "full-pixel reconstruction, no loop filter"),
];
const TRANSFORMS: EnumTable = &[
    (0, "predictor"),
    (1, "cross-color"),
    (2, "subtract green"),
    (3, "color indexing"),
];

/// Above this many frames the file summary does not total frame durations.
const MAX_SUMMED_FRAMES: usize = 4096;

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

/// VP8 frame header (RFC 6386, 9.1): a 3-byte little-endian frame tag,
/// then (for key frames) a start code and two 14-bit dimensions with 2-bit
/// upscaling factors.
fn vp8(b: &mut Bits<'_>) -> Result<Option<Size>> {
    let key = b
        .field("Frame type", 1)
        .with(|v, n| n.summary(if v == 0 { "key frame" } else { "interframe" }))
        .desc("0 = key frame; a WebP image is one key frame")
        .emit()?
        == 0;
    b.field("Version", 3)
        .enumeration(VP8_VERSION)
        .desc("Profile: reconstruction filter and loop filter type")
        .emit()?;
    b.field("Show frame", 1).flag().emit()?;
    b.field("First partition size", 19)
        .with(|v, n| n.summary(format!("{v} bytes")))
        .desc("Size of the first (mode and probability) partition, after this header")
        .emit()?;
    if !key {
        b.node(Node::new("Frame type").diag(Diagnostic::malformed(
            "a WebP VP8 chunk must hold a key frame",
        )));
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
    b.field("Horizontal scale", 2)
        .enumeration(SCALE)
        .desc("Upscaling factor the decoder should apply")
        .emit()?;
    let height = b.field("Height", 14).emit()?;
    b.field("Vertical scale", 2)
        .enumeration(SCALE)
        .desc("Upscaling factor the decoder should apply")
        .emit()?;
    Ok(Some(Size {
        width,
        height,
        alpha: false,
    }))
}

/// The VP8L header: signature, 14-bit width and height minus one, alpha
/// hint and version.
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
    let alpha = b
        .field("Alpha is used", 1)
        .flag()
        .desc("A hint: whether any pixel's alpha is not 255")
        .emit()?
        != 0;
    b.field("Version", 3)
        .with(|v, n| {
            if v == 0 {
                n
            } else {
                n.diag(Diagnostic::malformed("must be 0"))
            }
        })
        .emit()?;
    Ok(Size {
        width: width.saturating_add(1),
        height: height.saturating_add(1),
        alpha,
    })
}

/// The fields of a VP8L image stream that come before its first
/// entropy-coded part: the transforms (each at most once; predictor,
/// cross-color and color-indexing transforms are followed by an
/// entropy-coded sub-image, where this stops), the color cache and whether
/// meta prefix codes are used.
fn image_stream(b: &mut Bits<'_>) -> Result<()> {
    for index in 0..4u32 {
        let present = b
            .field("Transform present", 1)
            .flag()
            .desc("1: a transform follows; 0: the transforms end")
            .emit()?;
        if present == 0 {
            break;
        }
        let kind = b
            .field("Transform type", 2)
            .enumeration(TRANSFORMS)
            .with(|_, n| n.summary(format!("transform {}", index.saturating_add(1))))
            .emit()?;
        match kind {
            0 | 1 => {
                b.field("Block size bits", 3)
                    .with(|v, n| {
                        let size = 1u64
                            .checked_shl(u32::try_from(v).unwrap_or(0).saturating_add(2))
                            .unwrap_or(0);
                        n.summary(format!("{size}×{size} blocks"))
                    })
                    .desc("log2(block size) − 2")
                    .emit()?;
                b.node(Node::new("Transform data").summary(
                    "an entropy-coded sub-image of per-block parameters follows; the rest of the stream is entropy-coded",
                ));
                return Ok(());
            }
            3 => {
                b.field("Color table size − 1", 8)
                    .with(|v, n| {
                        let colors = v.saturating_add(1);
                        let bits = match colors {
                            0..=2 => "8 pixels per byte",
                            3..=4 => "4 pixels per byte",
                            5..=16 => "2 pixels per byte",
                            _ => "1 pixel per byte",
                        };
                        n.summary(format!("{colors} colors, {bits}"))
                    })
                    .emit()?;
                b.node(Node::new("Transform data").summary(
                    "the entropy-coded color table follows; the rest of the stream is entropy-coded",
                ));
                return Ok(());
            }
            _ => {}
        }
    }
    let cache = b
        .field("Color cache", 1)
        .flag()
        .desc("Whether recently used colors are coded by a cache index")
        .emit()?;
    if cache != 0 {
        b.field("Color cache bits", 4)
            .with(|v, n| {
                let size = 1u64.checked_shl(u32::try_from(v).unwrap_or(0)).unwrap_or(0);
                n.summary(format!("{size} entries"))
            })
            .emit()?;
    }
    let meta = b
        .field("Meta prefix codes", 1)
        .flag()
        .desc("Whether different image regions use different prefix-code groups")
        .emit()?;
    if meta != 0 {
        b.field("Prefix bits", 3)
            .with(|v, n| {
                let size = 1u64
                    .checked_shl(u32::try_from(v).unwrap_or(0).saturating_add(2))
                    .unwrap_or(0);
                n.summary(format!("{size}×{size} blocks"))
            })
            .desc("log2(block size) − 2 of the entropy image")
            .emit()?;
    }
    b.node(Node::new("Prefix codes").summary("entropy-coded data follows"));
    Ok(())
}

/// The one-byte `ALPH` header (most significant bits first).
fn alph(b: &mut Bits<'_>) -> Result<()> {
    b.field("Reserved", 2).emit()?;
    b.field("Preprocessing", 2)
        .enumeration(PREPROCESSING)
        .desc("1: the encoder reduced the number of alpha levels")
        .emit()?;
    b.field("Filtering method", 2)
        .enumeration(ALPHA_FILTER)
        .desc("Each alpha value is predicted from its neighbours; the difference is stored")
        .emit()?;
    b.field("Compression method", 2)
        .enumeration(ALPHA_COMPRESSION)
        .desc("0: raw width×height bytes; 1: a VP8L image stream without header, alpha in the green channel")
        .emit()?;
    Ok(())
}

struct Vp8x {
    size: Size,
}

fn vp8x(f: &mut Fields<'_>, _: &()) -> Result<Vp8x> {
    let flags = f
        .u8("Flags")
        .flags(VP8X_FLAGS)
        .desc("Which optional chunks the file uses; the two top bits and bit 0 are reserved")
        .emit()?;
    u24(f, "Reserved", LE).emit()?;
    let width = u24(f, "Canvas width − 1", LE)
        .with(|&v, n| n.summary(format!("{} px", v.saturating_add(1))))
        .emit()?;
    let height = u24(f, "Canvas height − 1", LE)
        .with(|&v, n| n.summary(format!("{} px", v.saturating_add(1))))
        .emit()?;
    let size = Size {
        width: u64::from(width).saturating_add(1),
        height: u64::from(height).saturating_add(1),
        alpha: flags & 0x10 != 0,
    };
    if size.width.saturating_mul(size.height) > u64::from(u32::MAX) {
        f.node(
            Node::new("Canvas").diag(Diagnostic::malformed("the canvas exceeds 2^32 − 1 pixels")),
        );
    }
    Ok(Vp8x { size })
}

struct Frame {
    x: u32,
    y: u32,
    width: u32,
    height: u32,
    duration: u32,
    flags: u8,
}

impl Frame {
    fn describe(&self) -> String {
        let mut out = format!(
            "{}×{} at ({}, {}), {} ms",
            self.width, self.height, self.x, self.y, self.duration
        );
        if self.flags & 2 != 0 {
            out.push_str(", no blending");
        }
        if self.flags & 1 != 0 {
            out.push_str(", dispose to background");
        }
        out
    }
}

fn anmf(f: &mut Fields<'_>, _: &()) -> Result<Frame> {
    let px = |&v: &u32, n: Node| n.summary(format!("{} px", v.saturating_mul(2)));
    let x = u24(f, "X offset / 2", LE).with(px).emit()?;
    let y = u24(f, "Y offset / 2", LE).with(px).emit()?;
    let minus = |&v: &u32, n: Node| n.summary(format!("{} px", v.saturating_add(1)));
    let width = u24(f, "Width − 1", LE).with(minus).emit()?;
    let height = u24(f, "Height − 1", LE).with(minus).emit()?;
    let duration = u24(f, "Duration", LE)
        .with(|&v, n| n.summary(format!("{v} ms")))
        .desc("Milliseconds before the next frame")
        .emit()?;
    let flags = f
        .u8("Flags")
        .flags(FRAME_FLAGS)
        .desc("Bit 1: draw without alpha-blending onto the canvas; bit 0: clear the frame's area to the background color after its duration")
        .emit()?;
    Ok(Frame {
        x: x.saturating_mul(2),
        y: y.saturating_mul(2),
        width: width.saturating_add(1),
        height: height.saturating_add(1),
        duration,
        flags,
    })
}

async fn size_of(cx: &Cx, id: &FourCc, data: Span) -> Result<Option<Size>> {
    Ok(match id {
        b"VP8 " => parse_bits(cx, data.sub(0, 10), vp8, true).await?,
        b"VP8L" => Some(parse_bits(cx, data.sub(0, 5), vp8l, true).await?),
        b"VP8X" => Some(
            crate::fields::parse(cx, data.sub(0, 10), LE, &(), vp8x)
                .await?
                .size,
        ),
        _ => None,
    })
}

/// The span of an `EXIF` chunk's TIFF stream: some writers put the JPEG
/// APP1 prefix `Exif\0\0` in front of it.
async fn exif_tiff(cx: &Cx, data: Span) -> Result<Span> {
    let head = cx.read_avail(data.sub(0, 6)).await?;
    Ok(if head == b"Exif\0\0" {
        data.tail(6)
    } else {
        data
    })
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    if let Some(size) = size_of(cx, &chunk.id, chunk.data).await? {
        let alpha = if size.alpha { ", alpha" } else { "" };
        return Ok(Some(format!("{}×{}{alpha}", size.width, size.height)));
    }
    Ok(match &chunk.id {
        b"ANMF" => {
            let fr = crate::fields::parse(cx, chunk.data.sub(0, 16), LE, &(), anmf).await?;
            Some(fr.describe())
        }
        b"ANIM" => {
            let b = cx.read_avail(chunk.data.sub(0, 6)).await?;
            let loops = crate::bytes::u16_le(&b, 4).unwrap_or(0);
            Some(format!(
                "background {}, {}",
                bgra(&b),
                if loops == 0 {
                    "loops forever".to_owned()
                } else {
                    format!("plays {loops} times")
                }
            ))
        }
        b"ALPH" => {
            let b = cx.read_avail(chunk.data.sub(0, 1)).await?;
            let v = b.first().copied().unwrap_or(0);
            let mut out = lookup(ALPHA_COMPRESSION, (v & 3).into())
                .unwrap_or("?")
                .to_owned();
            let filter = (v >> 2) & 3;
            if filter != 0 {
                out.push_str(&format!(
                    ", {} filter",
                    lookup(ALPHA_FILTER, filter.into()).unwrap_or("?")
                ));
            }
            if (v >> 4) & 3 == 1 {
                out.push_str(", quantized");
            }
            Some(out)
        }
        b"EXIF" => {
            let tiff = exif_tiff(cx, chunk.data).await?;
            crate::formats::image::tiff::camera(cx, chunk.input().nested(tiff))
                .await
                .map(|camera| format!("Exif, {camera}"))
        }
        _ => None,
    })
}

/// The `ANIM` background color, stored blue, green, red, alpha.
fn bgra(b: &[u8]) -> String {
    let at = |i: usize| b.get(i).copied().unwrap_or(0);
    format!("#{:02x}{:02x}{:02x}{:02x}", at(2), at(1), at(0), at(3))
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let data = chunk.data;
    let input = chunk.input();
    let e = chunk.endian();
    match &chunk.id {
        b"VP8 " => {
            cx.emit(bits_node(
                "Frame header",
                data.sub(0, 10),
                |b| vp8(b).map(|_| ()),
                true,
            ));
            let block = cx.read_avail(data.sub(0, 3)).await?;
            let first = crate::bytes::u24_le(&block, 0).map_or(0, |tag| u64::from(tag >> 5));
            let partition = data.sub(10, first);
            let mut node = Node::new("First partition")
                .span(partition)
                .summary("modes and probabilities (boolean-entropy-coded)");
            if partition.len < first {
                node = node.diag(Diagnostic::truncated(
                    Span::new(partition.source, partition.offset, first),
                    partition.len,
                ));
            }
            cx.emit(node);
            cx.emit(
                Node::new("Token partitions")
                    .span(data.tail(10u64.saturating_add(first)))
                    .summary("DCT coefficients (boolean-entropy-coded)"),
            );
        }
        b"VP8L" => {
            cx.emit(bits_node(
                "Header",
                data.sub(0, 5),
                |b| vp8l(b).map(|_| ()),
                true,
            ));
            cx.emit(
                bits_node("Image stream", data.tail(5), image_stream, true)
                    .summary("transforms, color cache, then entropy-coded pixels"),
            );
        }
        b"VP8X" => {
            let block = cx.block(data.sub(0, 10)).await?;
            vp8x(&mut Fields::emitting(cx, &block, e), &())?;
        }
        b"ALPH" => {
            cx.emit(bits_node("Header", data.sub(0, 1), alph, false));
            let head = cx.read_avail(data.sub(0, 1)).await?;
            let body = data.tail(1);
            if head.first().is_some_and(|v| v & 3 == 1) {
                cx.emit(
                    bits_node("Alpha bitstream", body, image_stream, true)
                        .summary("VP8L image stream without header"),
                );
            } else {
                cx.emit(
                    Node::new("Alpha bitstream")
                        .span(body)
                        .summary("raw alpha values"),
                );
            }
        }
        b"ANIM" => {
            let block = cx.block(data.sub(0, 6)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.bytes("Background color", 4)
                .with(|b, n| n.summary(bgra(b)))
                .desc("Blue, green, red, alpha; a hint, which viewers may ignore")
                .emit()?;
            f.u16("Loop count")
                .with(|&v, n| if v == 0 { n.summary("loop forever") } else { n })
                .desc("0 = infinite")
                .emit()?;
        }
        b"ANMF" => {
            let block = cx.block(data.sub(0, 16)).await?;
            anmf(&mut Fields::emitting(cx, &block, e), &())?;
            walk(cx, &chunk.ctx, data.tail(16), chunk.id).await?;
        }
        b"ICCP" => cx.emit(embedded("ICC profile", input.nested(data))),
        b"EXIF" => {
            let tiff = exif_tiff(cx, data).await?;
            if tiff.offset != data.offset {
                cx.emit(
                    Node::new("Exif prefix")
                        .span(data.sub(0, 6))
                        .desc("\"Exif\\0\\0\", as in JPEG APP1; the WebP specification stores the TIFF stream directly"),
                );
            }
            cx.emit(embedded_as(
                "Exif",
                input.nested(tiff),
                &crate::formats::image::tiff::FORMAT,
            ));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

/// "300 ms", "1.5 s", "2:05".
fn playing_time(ms: u64) -> String {
    if ms < 1000 {
        format!("{ms} ms")
    } else if ms < 60_000 {
        let s = format!("{:.2}", ms as f64 / 1000.0);
        format!("{} s", s.trim_end_matches('0').trim_end_matches('.'))
    } else {
        crate::formats::util::sound::duration(ms as f64 / 1000.0)
    }
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
        if flags & 0x02 != 0 {
            let frames: Vec<_> = chunks.iter().filter(|c| &c.id == b"ANMF").collect();
            line.push_str(&format!(", animated, {} frames", frames.len()));
            if frames.len() <= MAX_SUMMED_FRAMES {
                let mut total = 0u64;
                let (mut lossy, mut lossless) = (false, false);
                for frame in &frames {
                    let head = cx.read_avail(frame.data.sub(0, 20)).await?;
                    total =
                        total.saturating_add(crate::bytes::u24_le(&head, 12).map_or(0, u64::from));
                    match head.get(16..20) {
                        Some(b"VP8L") => lossless = true,
                        Some(b"VP8 " | b"ALPH") => lossy = true,
                        _ => {}
                    }
                }
                line.push_str(&format!(", {}", playing_time(total)));
                if let Some(anim) = chunks.iter().find(|c| &c.id == b"ANIM") {
                    let b = cx.read_avail(anim.data.sub(4, 2)).await?;
                    match crate::bytes::u16_le(&b, 0) {
                        Some(0) => line.push_str(", loops forever"),
                        Some(n) => line.push_str(&format!(", plays {n} times")),
                        None => {}
                    }
                }
                line.push_str(match (lossy, lossless) {
                    (true, true) => ", lossy and lossless frames",
                    (true, false) => ", lossy",
                    (false, true) => ", lossless",
                    (false, false) => "",
                });
            }
        } else if let Some(image) = chunks.iter().find(|c| matches!(&c.id, b"VP8 " | b"VP8L")) {
            line.push_str(if &image.id == b"VP8L" {
                ", lossless"
            } else {
                ", lossy"
            });
        }
        for (bit, name) in [
            (0x10, "alpha"),
            (0x20, "ICC"),
            (0x08, "Exif"),
            (0x04, "XMP"),
        ] {
            if flags & bit != 0 {
                line.push_str(&format!(", {name}"));
            }
        }
    } else if size.alpha {
        line.push_str(", alpha");
    }
    Ok(Some(line))
}
