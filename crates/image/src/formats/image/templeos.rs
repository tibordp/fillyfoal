//! TempleOS graphics: sprites and GR files.
//!
//! A **sprite** (`CSprite`, `Adam/Gr/Gr.HH`) is a list of drawing
//! elements, one after another, each led by a type byte (`SPT_*`, the top
//! bit `SPF_SEL` marks it selected in the editor) and ended by `SPT_END`
//! (0). The element structs are packed: `SPT_LINE` is the type byte and
//! four `I32` (x1, y1, x2, y2), `SPT_BITMAP` the type byte, x1, y1, width,
//! height and `((width+7)&~7)*height` pixel bytes (one 4-bit color per
//! byte, `TRANSPARENT` 0xFF), and so on. The sizes follow
//! `sprite_elem_base_sizes` and `SpriteElemSize` in `Adam/Gr/SpriteNew.HC`,
//! the meanings `Sprite3` in `Adam/Gr/GrSpritePlot.HC` and the summaries
//! `SpriteElem2Summary`. DolDoc documents carry sprites as their binary
//! data blocks (`$SP,"",BI=1$`), so sprites have no file of their own:
//! [`SPRITE`] is reached from a DolDoc bin (or "inspect as").
//!
//! A **GR file** (`GRWrite`/`DCSave` in `Adam/Gr/GrDC.HC`) is a saved
//! device context: the 32 bytes of `CDC` from `start` to `end` (a `CDate`,
//! the origin, width, padded width, height and flags), the 16-color palette
//! as 48-bit BGR if `DCF_PALETTE` is set (only when it differs from the
//! standard one), then the 8-bit pixels, raw or (`DCF_COMPRESSED`, the
//! default) as a `CArcCompress` block of TempleOS's LZW (`Kernel/
//! Compress.HC`). Terry Davis's `Linux/TOSZ.CPP` reads the same layout
//! (`DCLoad`). The files are usually stored as `.GR.Z`, so the whole file
//! is compressed again on disk; this dissector sees it after that layer.
//!
//! Ported from the public-domain TempleOS V5.03 source.

use crate::bytes::{i32_le, to_u64, to_usize, u32_le, u64_le};
use crate::codec::Codec;
use crate::codec::charset::Charset;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::civil;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

use super::dims;

const LE: Endian = Endian::Little;

pub static SPRITE: Format = Format {
    name: "templeos-sprite",
    title: "TempleOS sprite",
    extensions: &[],
    mime: "application/x-templeos-sprite",
    probe: Probe::Never,
    dissect: crate::expander!(sprite: Input),
};

pub static GR: Format = Format {
    name: "templeos-gr",
    title: "TempleOS GR graphics",
    extensions: &["gr"],
    mime: "image/x-templeos-gr",
    probe: Probe::Custom(gr_probe),
    dissect: crate::expander!(gr: Input),
};

/// The 16 colors (`BLACK`..`WHITE`, `Kernel/KernelA.HH`) and `TRANSPARENT`.
pub const COLORS: EnumTable = &[
    (0, "BLACK"),
    (1, "BLUE"),
    (2, "GREEN"),
    (3, "CYAN"),
    (4, "RED"),
    (5, "PURPLE"),
    (6, "BROWN"),
    (7, "LTGRAY"),
    (8, "DKGRAY"),
    (9, "LTBLUE"),
    (10, "LTGREEN"),
    (11, "LTCYAN"),
    (12, "LTRED"),
    (13, "LTPURPLE"),
    (14, "YELLOW"),
    (15, "WHITE"),
    (0xff, "TRANSPARENT"),
];

/// The name of color `c`, or its number.
pub fn color_name(c: u8) -> String {
    COLORS
        .iter()
        .find(|&&(v, _)| v == u64::from(c))
        .map_or_else(|| c.to_string(), |&(_, n)| n.to_owned())
}

// ---------------------------------------------------------------------------
// Sprite elements

/// What follows the type byte of an element.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    /// `CSpriteBase`: nothing.
    Base,
    /// `CSpriteColor`: a color byte.
    Color,
    /// `CSpriteDitherColor`: two color bytes.
    Dither,
    /// `CSpriteT`: a thickness.
    Thick,
    /// `CSpritePt`: one point.
    Pt,
    /// `CSpritePtRad`: center and radius.
    PtRad,
    /// `CSpritePtPt`: two points.
    PtPt,
    /// `CSpritePtPtAng`: two points and an angle.
    PtPtAng,
    /// `CSpritePtWHU8s`: a bitmap.
    Bitmap,
    /// `CSpritePtWHAng`: center, width, height, angle.
    PtWhAng,
    /// `CSpritePtWHAngSides`: and a number of sides.
    PtWhAngSides,
    /// `CSpriteNumU8s` with `CD2I32` points (polyline).
    Points2,
    /// `CSpriteNumU8s` with `CD3I32` control points (B-splines).
    Points3,
    /// `CSpriteNumPtU8s`: a start point and 3-bit steps.
    PolyPt,
    /// `CSpritePtStr`: a point and a NUL-terminated string.
    Text,
    /// `CSpriteMeshU8s`: vertices and triangles.
    Mesh,
    /// `CSpritePtMeshU8s`: an offset, vertices and triangles.
    ShiftMesh,
}

/// `SPT_*`: name, layout, `sprite_elem_base_sizes` entry.
const ELEMENTS: [(&str, Shape, u64); 30] = [
    ("End", Shape::Base, 1),
    ("Color", Shape::Color, 2),
    ("Dither Color", Shape::Dither, 3),
    ("Thick", Shape::Thick, 5),
    ("Planar Symmetry", Shape::PtPt, 17),
    ("Transform On", Shape::Base, 1),
    ("Transform Off", Shape::Base, 1),
    ("Shift", Shape::Pt, 9),
    ("Point", Shape::Pt, 9),
    ("PolyPoint", Shape::PolyPt, 13),
    ("Line", Shape::PtPt, 17),
    ("PolyLine", Shape::Points2, 5),
    ("Rect", Shape::PtPt, 17),
    ("Rotated Rect", Shape::PtPtAng, 25),
    ("Circle", Shape::PtRad, 13),
    ("Ellipse", Shape::PtWhAng, 25),
    ("Polygon", Shape::PtWhAngSides, 29),
    ("BSpline2", Shape::Points3, 5),
    ("BSpline2 Closed", Shape::Points3, 5),
    ("BSpline3", Shape::Points3, 5),
    ("BSpline3 Closed", Shape::Points3, 5),
    ("Flood Fill", Shape::Pt, 9),
    ("Flood Fill Not Color", Shape::Pt, 9),
    ("BitMap", Shape::Bitmap, 17),
    ("Mesh", Shape::Mesh, 9),
    ("Shiftable Mesh", Shape::ShiftMesh, 21),
    ("Arrow", Shape::PtPt, 17),
    ("Text", Shape::Text, 9),
    ("Text Box", Shape::Text, 9),
    ("Text Diamond", Shape::Text, 9),
];

const SPG_TYPE_MASK: u8 = 0x7f;
const SPF_SEL: u8 = 0x80;
/// Longest string kept for display; the element's span covers all of it.
const TEXT_CAP: u64 = 1024;
/// `CD3I32`, `CMeshTri`.
const VERTEX: u64 = 12;
const TRIANGLE: u64 = 16;

fn element(t: u8) -> Option<(&'static str, Shape, u64)> {
    ELEMENTS.get(usize::from(t & SPG_TYPE_MASK)).copied()
}

/// A count field: an `I32` that must not be negative.
fn count(hdr: &[u8], at: usize) -> Option<u64> {
    i32_le(hdr, at).and_then(|n| u64::try_from(n).ok())
}

/// The bytes after the fixed part of an element whose fixed part is `hdr`
/// (`SpriteElemSize`), except for text, whose length is found by reading.
/// `None` for a negative count.
fn extra(shape: Shape, hdr: &[u8]) -> Option<u64> {
    Some(match shape {
        Shape::Points2 => count(hdr, 1)?.saturating_mul(8),
        Shape::Points3 => count(hdr, 1)?.saturating_mul(VERTEX),
        Shape::PolyPt => count(hdr, 1)?.saturating_mul(3).saturating_add(7) / 8,
        Shape::Bitmap => padded(count(hdr, 9)?).saturating_mul(count(hdr, 13)?),
        Shape::Mesh => mesh_size(count(hdr, 1)?, count(hdr, 5)?),
        Shape::ShiftMesh => mesh_size(count(hdr, 13)?, count(hdr, 17)?),
        _ => 0,
    })
}

fn padded(width: u64) -> u64 {
    width.saturating_add(7) & !7
}

fn mesh_size(vertices: u64, triangles: u64) -> u64 {
    vertices
        .saturating_mul(VERTEX)
        .saturating_add(triangles.saturating_mul(TRIANGLE))
}

/// `SpriteElem2Summary`.
fn summary(shape: Shape, hdr: &[u8], text: &str) -> String {
    let i = |at: usize| i32_le(hdr, at).unwrap_or(0);
    let b = |at: usize| hdr.get(at).copied().unwrap_or(0);
    match shape {
        Shape::Base => String::new(),
        Shape::Color => color_name(b(1)),
        Shape::Dither => format!("{}/{}", color_name(b(1)), color_name(b(2))),
        Shape::Thick => i(1).to_string(),
        Shape::Pt => format!("({},{})", i(1), i(5)),
        Shape::PtPt | Shape::PtPtAng => format!("({},{}),({},{})", i(1), i(5), i(9), i(13)),
        Shape::PtRad => format!("({},{}):{}R", i(1), i(5), i(9)),
        Shape::Bitmap | Shape::PtWhAng | Shape::PtWhAngSides => {
            format!("({},{}):{}W,{}H", i(1), i(5), i(9), i(13))
        }
        Shape::Points2 => {
            let first = format!("({},{})", i(5), i(9));
            format!("{} {first}", i(1))
        }
        Shape::PolyPt => format!("{} ({},{})", i(1), i(5), i(9)),
        Shape::Points3 => i(1).to_string(),
        Shape::Text => format!("{},{}:{:?}", i(1), i(5), clip(text, 32)),
        Shape::Mesh => format!("{}V,{}T", i(1), i(5)),
        Shape::ShiftMesh => format!("{}V,{}T", i(13), i(17)),
    }
}

/// Counts of each element type, for the annotation.
type Tally = [u32; 30];

fn tally_text(tally: &Tally) -> String {
    let mut parts = Vec::new();
    for (n, (name, _, _)) in tally.iter().zip(ELEMENTS.iter()).skip(1) {
        if *n > 0 {
            parts.push(format!("{n} {name}"));
        }
    }
    parts.join(", ")
}

/// One decoded element: its span, type byte, fixed part and string.
struct Element {
    span: Span,
    t: u8,
    hdr: Vec<u8>,
    text: String,
}

/// Reads the element at `pos` in `data`; `Ok(None)` at `SPT_END`.
async fn read_element(cx: &Cx, data: Span, pos: u64) -> Result<Element> {
    let first = cx.read(data.sub_exact(pos, 1)?).await?;
    let t = first.first().copied().unwrap_or(0);
    let Some((name, shape, base)) = element(t) else {
        return Err(Diagnostic::malformed(format!(
            "unknown sprite element type {}",
            t & SPG_TYPE_MASK
        ))
        .at(data.sub(pos, 1)));
    };
    let mut hdr = cx.read(data.sub_exact(pos, base)?).await?;
    let mut text = String::new();
    let len = if shape == Shape::Text {
        let (bytes, len) = cstring(cx, data.tail(pos.saturating_add(base))).await?;
        text = Charset::Cp437.decode(&bytes);
        len
    } else {
        extra(shape, &hdr).ok_or_else(|| {
            Diagnostic::malformed(format!("{name}: negative count")).at(data.sub(pos, base))
        })?
    };
    let span = data.sub_exact(pos, base.saturating_add(len))?;
    if shape == Shape::Points2 && len >= 8 {
        // The summary shows the first point, which `SpriteElem2Summary`
        // reads just past the count (`&npu.x`): keep it with the fixed part.
        hdr = cx
            .read(data.sub_exact(pos, base.saturating_add(8))?)
            .await?;
    }
    Ok(Element { span, t, hdr, text })
}

/// A NUL-terminated string at the start of `span`: up to [`TEXT_CAP`] of
/// its bytes and its length with the terminator.
async fn cstring(cx: &Cx, span: Span) -> Result<(Vec<u8>, u64)> {
    const STEP: u64 = 256;
    let mut kept = Vec::new();
    let mut pos = 0u64;
    while pos < span.len {
        let window = span.sub(pos, STEP);
        let data = cx.read(window).await?;
        if let Some(n) = data.iter().position(|&b| b == 0) {
            let room = to_usize(TEXT_CAP.saturating_sub(to_u64(kept.len())));
            kept.extend(data.iter().take(n.min(room)));
            return Ok((kept, pos.saturating_add(to_u64(n)).saturating_add(1)));
        }
        let room = to_usize(TEXT_CAP.saturating_sub(to_u64(kept.len())));
        kept.extend(data.iter().take(room));
        pos = pos.saturating_add(window.len);
    }
    Err(Diagnostic::malformed("sprite text not terminated").at(span))
}

/// The sprite's elements, paged; the annotation counts them by type.
pub async fn sprite(cx: Cx, input: Input) -> Result<()> {
    let data = input.span;
    let (mut pos, mut index, mut tally) =
        cx.resume::<(u64, u64, Tally)>().unwrap_or((0, 0, [0; 30]));
    loop {
        if pos >= data.len {
            cx.diag(Diagnostic::malformed("no End element").at(data.sub(pos, 0)));
            break;
        }
        let at = (pos, index, tally);
        cx.mark(move || at);
        let e = match read_element(&cx, data, pos).await {
            Ok(e) => e,
            Err(d) => {
                cx.push(Node::new(format!("[{index}]")).span(data.tail(pos)).diag(d))
                    .await;
                break;
            }
        };
        let kind = e.t & SPG_TYPE_MASK;
        let (name, shape, _) = element(e.t).unwrap_or(("?", Shape::Base, 1));
        if let Some(n) = tally.get_mut(usize::from(kind)) {
            *n = n.saturating_add(1);
        }
        let mut node = Node::new(format!("[{index}] {name}")).span(e.span);
        let s = summary(shape, &e.hdr, &e.text);
        if !s.is_empty() {
            node = node.summary(s);
        }
        if kind != 0 {
            node = node.lazy(element_fields, (e.span, e.t));
        }
        cx.push(node).await;
        pos = pos.saturating_add(e.span.len);
        index = index.saturating_add(1);
        if kind == 0 {
            if pos < data.len {
                cx.push(
                    Node::new("Trailing data")
                        .span(data.tail(pos))
                        .summary(plural(data.len.saturating_sub(pos), "byte")),
                )
                .await;
            }
            break;
        }
    }
    let elements = index.saturating_sub(u64::from(tally.first().copied().unwrap_or(0)));
    let mut line = format!("TempleOS sprite, {}", plural(elements, "element"));
    let kinds = tally_text(&tally);
    if !kinds.is_empty() {
        line = format!("{line}: {kinds}");
    }
    cx.annotate(line);
    Ok(())
}

fn point(f: &mut Fields<'_>, x: &'static str, y: &'static str) -> Result<()> {
    f.i32(x).emit()?;
    f.i32(y).emit()?;
    Ok(())
}

async fn element_fields(cx: Cx, (span, t): (Span, u8)) -> Result<()> {
    let Some((_, shape, base)) = element(t) else {
        return Ok(());
    };
    let block = cx.block(span.sub(0, base)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Type")
        .desc("SPT_* in the low 7 bits; the top bit (SPF_SEL) marks it selected in the editor")
        .with(|&v, n| {
            let name = element(v).map_or("?", |e| e.0);
            if v & SPF_SEL != 0 {
                n.summary(format!("{name}, selected"))
            } else {
                n.summary(name)
            }
        })
        .emit()?;
    let rest = span.tail(base);
    match shape {
        Shape::Base => {}
        Shape::Color => {
            f.u8("Color").enumeration(COLORS).emit()?;
        }
        Shape::Dither => {
            f.u8("Color 1").enumeration(COLORS).emit()?;
            f.u8("Color 2").enumeration(COLORS).emit()?;
        }
        Shape::Thick => {
            f.i32("Thickness").emit()?;
        }
        Shape::Pt => point(&mut f, "X", "Y")?,
        Shape::PtRad => {
            point(&mut f, "X", "Y")?;
            f.i32("Radius").emit()?;
        }
        Shape::PtPt | Shape::PtPtAng => {
            point(&mut f, "X1", "Y1")?;
            point(&mut f, "X2", "Y2")?;
            if shape == Shape::PtPtAng {
                f.f64("Angle").desc("Radians").emit()?;
            }
        }
        Shape::Bitmap => {
            point(&mut f, "X", "Y")?;
            let w = f.i32("Width").emit()?;
            let h = f.i32("Height").emit()?;
            let (w, h) = (u64::try_from(w).unwrap_or(0), u64::try_from(h).unwrap_or(0));
            cx.emit(pixels("Pixels", rest, w, padded(w), h));
        }
        Shape::PtWhAng | Shape::PtWhAngSides => {
            point(&mut f, "X", "Y")?;
            f.i32("Width").emit()?;
            f.i32("Height").emit()?;
            f.f64("Angle").desc("Radians").emit()?;
            if shape == Shape::PtWhAngSides {
                f.i32("Sides").emit()?;
            }
        }
        Shape::Points2 | Shape::Points3 => {
            let n = f.i32("Count").emit()?;
            let dims = if shape == Shape::Points2 { 2 } else { 3 };
            cx.emit(points(rest, u64::try_from(n).unwrap_or(0), dims));
        }
        Shape::PolyPt => {
            let n = f.i32("Count").emit()?;
            let x = f.i32("X").emit()?;
            let y = f.i32("Y").emit()?;
            let n = u64::try_from(n).unwrap_or(0);
            cx.emit(
                Node::new("Steps")
                    .span(rest)
                    .summary(format!("{} of 3 bits", plural(n, "step")))
                    .lazy(polypt_steps, (rest, n, x, y)),
            );
        }
        Shape::Text => {
            point(&mut f, "X", "Y")?;
            let (bytes, len) = cstring(&cx, rest).await?;
            let text = Charset::Cp437.decode(&bytes);
            cx.emit(
                Node::new("Text")
                    .span(rest.sub(0, len))
                    .value(Value::Text(text)),
            );
        }
        Shape::Mesh | Shape::ShiftMesh => {
            if shape == Shape::ShiftMesh {
                point(&mut f, "X", "Y")?;
                f.i32("Z").emit()?;
            }
            let v = u64::try_from(f.i32("Vertices").emit()?).unwrap_or(0);
            let t = u64::try_from(f.i32("Triangles").emit()?).unwrap_or(0);
            let vspan = rest.sub(0, v.saturating_mul(VERTEX));
            cx.emit(points(vspan, v, 3).renamed("Vertices"));
            let tspan = rest.sub(vspan.len, t.saturating_mul(TRIANGLE));
            cx.emit(
                Node::new("Triangles")
                    .span(tspan)
                    .summary(plural(t, "triangle"))
                    .lazy(triangles, (tspan, t)),
            );
        }
    }
    Ok(())
}

/// Items listed per read in the paged lists below.
const BATCH: u64 = 256;

/// A lazy list of `n` points of `dims` `I32` coordinates in `span`.
fn points(span: Span, n: u64, dims: u64) -> Node {
    Node::new("Points")
        .span(span.sub(0, n.saturating_mul(dims).saturating_mul(4)))
        .summary(plural(n, "point"))
        .lazy(point_list, (span, n, dims))
}

async fn point_list(cx: Cx, (span, n, dims): (Span, u64, u64)) -> Result<()> {
    let size = dims.saturating_mul(4);
    let n = n.min(span.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(n));
    let mut i = 0u64;
    while i < n {
        let take = BATCH.min(n.saturating_sub(i));
        let chunk = span.sub(i.saturating_mul(size), take.saturating_mul(size));
        let data = cx.read(chunk).await?;
        for (k, p) in data.chunks_exact(to_usize(size)).enumerate() {
            let c: Vec<String> = p
                .as_chunks::<4>()
                .0
                .iter()
                .map(|b| i32::from_le_bytes(*b).to_string())
                .collect();
            let at = to_u64(k).saturating_mul(size);
            cx.push(
                Node::new(format!("[{}]", i.saturating_add(to_u64(k))))
                    .span(chunk.sub(at, size))
                    .value(Value::Text(format!("({})", c.join(", ")))),
            )
            .await;
        }
        i = i.saturating_add(take);
    }
    Ok(())
}

async fn triangles(cx: Cx, (span, n): (Span, u64)) -> Result<()> {
    let n = n.min(span.len / TRIANGLE);
    cx.set_count(Count::Exact(n));
    let mut i = 0u64;
    while i < n {
        let take = BATCH.min(n.saturating_sub(i));
        let chunk = span.sub(i.saturating_mul(TRIANGLE), take.saturating_mul(TRIANGLE));
        let data = cx.read(chunk).await?;
        for (k, t) in data.chunks_exact(to_usize(TRIANGLE)).enumerate() {
            let v = |at: usize| i32_le(t, at).unwrap_or(0);
            let color = u8::try_from(v(0)).map_or_else(|_| v(0).to_string(), color_name);
            let at = to_u64(k).saturating_mul(TRIANGLE);
            cx.push(
                Node::new(format!("[{}]", i.saturating_add(to_u64(k))))
                    .span(chunk.sub(at, TRIANGLE))
                    .value(Value::Text(format!("{}, {}, {}", v(4), v(8), v(12))))
                    .summary(color),
            )
            .await;
        }
        i = i.saturating_add(take);
    }
    Ok(())
}

/// `gr_x_offsets`/`gr_y_offsets` (`Adam/Gr/GrMath.HC`): the eight steps.
const STEPS: [(i64, i64, &str); 8] = [
    (-1, -1, "up-left"),
    (0, -1, "up"),
    (1, -1, "up-right"),
    (-1, 0, "left"),
    (1, 0, "right"),
    (-1, 1, "down-left"),
    (0, 1, "down"),
    (1, 1, "down-right"),
];

/// A PolyPoint's points: the start, then one step of 3 bits each
/// (`BFieldExtU32`, least significant bit first).
async fn polypt_steps(cx: Cx, (span, n, x, y): (Span, u64, i32, i32)) -> Result<()> {
    let n = n.min(span.len.saturating_mul(8) / 3);
    cx.set_count(Count::Exact(n));
    let (mut x, mut y) = (i64::from(x), i64::from(y));
    // Bytes are read a batch at a time; a step may straddle two bytes.
    let mut i = 0u64;
    let mut buf: Vec<u8> = Vec::new();
    let mut buf_start = 0u64;
    while i < n {
        let bit = i.saturating_mul(3);
        let byte = bit / 8;
        if byte.saturating_add(2) > buf_start.saturating_add(to_u64(buf.len())) {
            buf_start = byte;
            buf = cx.read_avail(span.sub(byte, BATCH)).await?;
        }
        let at = to_usize(byte.saturating_sub(buf_start));
        let lo = buf.get(at).copied().unwrap_or(0);
        let hi = buf.get(at.saturating_add(1)).copied().unwrap_or(0);
        let word = u16::from_le_bytes([lo, hi]);
        let code = usize::from((word >> (bit % 8)) & 7);
        let (dx, dy, name) = STEPS.get(code).copied().unwrap_or((0, 0, "?"));
        x = x.saturating_add(dx);
        y = y.saturating_add(dy);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(span.sub(byte, if bit % 8 > 5 { 2 } else { 1 }))
                .value(Value::Text(format!("({x}, {y})")))
                .summary(name),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Pixels shown per row at most; the row's span covers all of them.
const ROW_CAP: u64 = 1024;

/// A lazy list of the rows of an 8-bit image: one hex digit per color,
/// `.` for `TRANSPARENT`, `?` for anything else.
pub fn pixels(name: &'static str, span: Span, width: u64, stride: u64, height: u64) -> Node {
    let len = stride.saturating_mul(height);
    let mut node = Node::new(name)
        .span(span.sub(0, len))
        .summary(format!("{}, one byte per pixel", dims(width, height)));
    if span.len < len {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, len),
            span.len,
        ));
    }
    node.lazy(rows, (span, width, stride, height))
}

async fn rows(cx: Cx, (span, width, stride, height): (Span, u64, u64, u64)) -> Result<()> {
    let height = height.min(span.len.checked_div(stride).unwrap_or(0));
    cx.set_count(Count::Exact(height));
    for y in 0..height {
        let row = span.sub(y.saturating_mul(stride), stride);
        let data = cx.read(row.sub(0, width.min(ROW_CAP))).await?;
        let mut text: String = data
            .iter()
            .map(|&c| match c {
                0..=15 => char::from_digit(u32::from(c), 16).unwrap_or('?'),
                0xff => '.',
                _ => '?',
            })
            .collect();
        if width > ROW_CAP {
            text.push('…');
        }
        cx.push(
            Node::new(format!("Row {y}"))
                .span(row)
                .value(Value::Text(text)),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// GR files

/// `offset(CDC.end)-offset(CDC.start)`.
const DC_HEADER: u64 = 32;
const PALETTE: u64 = 16 * 8;
/// `CArcCompress` before its body.
const ARC_HEADER: u64 = 17;
const DCF_COMPRESSED: u32 = 1;
const DCF_PALETTE: u32 = 2;
/// The flags `DCSave` writes (`DCF_NO_TRANSPARENTS` is the third saved bit).
const SAVED_FLAGS: u32 = 7;
/// Sides larger than this are not believed (screens are 640×480).
const MAX_SIDE: u32 = 1 << 16;

const DC_FLAGS: FlagTable = &[
    flag(1, "DCF_COMPRESSED"),
    flag(2, "DCF_PALETTE"),
    flag(4, "DCF_NO_TRANSPARENTS"),
];

const COMPRESSION: EnumTable = &[(1, "CT_NONE"), (2, "CT_7_BIT"), (3, "CT_8_BIT")];

/// The header fields the probe and the dissector check: width, padded
/// width, height, flags.
fn dc_shape(d: &[u8]) -> Option<(u32, u32, u32, u32)> {
    let w = u32_le(d, 16)?;
    let wi = u32_le(d, 20)?;
    let h = u32_le(d, 24)?;
    let flags = u32_le(d, 28)?;
    let ok = (1..=MAX_SIDE).contains(&w)
        && (1..=MAX_SIDE).contains(&h)
        && u64::from(wi) == padded(w.into())
        && flags & !SAVED_FLAGS == 0;
    ok.then_some((w, wi, h, flags))
}

/// A device context header, then a body that matches it exactly: a
/// `CArcCompress` header whose expanded size is the pixel count, or the raw
/// pixels filling the file.
fn gr_probe(h: &Head<'_>) -> bool {
    let Some((_, wi, height, flags)) = dc_shape(h.data) else {
        return false;
    };
    let body = DC_HEADER.saturating_add(if flags & DCF_PALETTE != 0 { PALETTE } else { 0 });
    let pixels = u64::from(wi).saturating_mul(height.into());
    if flags & DCF_COMPRESSED == 0 {
        return h.len_known && h.len == body.saturating_add(pixels);
    }
    let at = to_usize(body);
    let (Some(csize), Some(xsize), Some(&kind)) = (
        u64_le(h.data, at),
        u64_le(h.data, at.saturating_add(8)),
        h.data.get(at.saturating_add(16)),
    ) else {
        return false;
    };
    xsize == pixels
        && (1..=3).contains(&kind)
        && csize >= ARC_HEADER
        && h.within(body.saturating_add(csize))
}

fn dc_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let time = f
        .u32("Time")
        .hex()
        .desc("CDate.time: fraction of the day, 2^-32 units")
        .emit()?;
    let date = f
        .int::<i32>("Date")
        .desc("CDate.date: days since 1 January of year 0 (TempleOS keeps local time)")
        .emit()?;
    // `DCSave` leaves a zero date when nothing set it.
    if time != 0 || date != 0 {
        f.node(
            Node::new("Timestamp")
                .span(f.peek_span(0))
                .value(Value::Timestamp(crate::value::Time::local(
                    civil::templeos_cdate(time, date),
                )))
                .desc("TempleOS keeps local time"),
        );
    }
    f.i32("X origin").emit()?;
    f.i32("Y origin").emit()?;
    f.i32("Width").emit()?;
    f.i32("Padded width")
        .desc("Width rounded up to a multiple of 8")
        .emit()?;
    f.i32("Height").emit()?;
    f.u32("Flags").flags(DC_FLAGS).emit()?;
    Ok(())
}

fn arc_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Compressed size")
        .desc("Including this 17-byte header")
        .emit()?;
    f.u64("Expanded size").emit()?;
    f.u8("Compression").enumeration(COMPRESSION).emit()?;
    Ok(())
}

/// `CBGR48` entries: 16-bit blue, green, red and padding.
async fn palette_entries(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    cx.set_count(Count::Exact(16));
    for (i, e) in data.as_chunks::<8>().0.iter().enumerate() {
        let c = |at: usize| u64::from(crate::bytes::u16_le(e, at).unwrap_or(0));
        let name = COLORS.get(i).map_or("?", |&(_, n)| n);
        cx.push(
            Node::new(format!("[{i}] {name}"))
                .span(span.sub(to_u64(i).saturating_mul(8), 8))
                .value(Value::color(crate::value::Color::rgb_bits(
                    16,
                    c(4),
                    c(2),
                    c(0),
                ))),
        )
        .await;
    }
    Ok(())
}

async fn gr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, DC_HEADER)?).await?;
    cx.emit(struct_node(
        "Device context",
        file.sub(0, DC_HEADER),
        LE,
        (),
        dc_layout,
    ));
    let Some((w, wi, h, flags)) = dc_shape(&head) else {
        return Err(
            Diagnostic::malformed("implausible device context header").at(file.sub(0, DC_HEADER))
        );
    };
    let mut pos = DC_HEADER;
    if flags & DCF_PALETTE != 0 {
        let span = file.sub_exact(pos, PALETTE)?;
        cx.emit(
            Node::new("Palette")
                .span(span)
                .summary("16 colors, 48-bit BGR")
                .lazy(palette_entries, span),
        );
        pos = pos.saturating_add(PALETTE);
    }
    let pixel_count = u64::from(wi).saturating_mul(h.into());
    let (w, h) = (u64::from(w), u64::from(h));
    let mut line = format!("TempleOS GR, {}", dims(w, h));
    if flags & DCF_PALETTE != 0 {
        line.push_str(", own palette");
    }
    let end = if flags & DCF_COMPRESSED != 0 {
        let hdr = cx.read(file.sub_exact(pos, ARC_HEADER)?).await?;
        let csize = u64_le(&hdr, 0).unwrap_or(0);
        let xsize = u64_le(&hdr, 8).unwrap_or(0);
        let arc = file.sub(pos, csize);
        let mut node = Node::new("Compressed pixels")
            .span(arc)
            .summary(format!(
                "TempleOS LZW, {} expanding to {}",
                plural(csize, "byte"),
                plural(xsize, "byte")
            ))
            .desc("A CArcCompress block, as in .Z files (Kernel/Compress.HC)");
        if arc.len < csize {
            node = node.diag(Diagnostic::truncated(
                Span::new(arc.source, arc.offset, csize),
                arc.len,
            ));
        }
        if xsize != pixel_count {
            node = node.diag(Diagnostic::malformed(format!(
                "expands to {xsize} bytes where the image has {pixel_count}"
            )));
        }
        cx.emit(node.lazy(arc_fields, arc));
        // The codec takes the whole `CArcCompress` block and expands only
        // as far as the rows read from it.
        let decoded = cx.decode_lazy(arc, &Codec::TempleOsZ, pixel_count)?;
        cx.emit(
            pixels("Pixels", decoded, w, wi.into(), h)
                .desc("Expanded from the compressed block on demand"),
        );
        line.push_str(", compressed");
        pos.saturating_add(arc.len)
    } else {
        cx.emit(pixels("Pixels", file.tail(pos), w, wi.into(), h));
        pos.saturating_add(pixel_count)
    };
    if end < file.len {
        cx.emit(
            Node::new("Trailing data")
                .span(file.tail(end))
                .summary(plural(file.len.saturating_sub(end), "byte"))
                .desc("A .MV screen recording is a sequence of device contexts"),
        );
    }
    cx.annotate(line);
    Ok(())
}

async fn arc_fields(cx: Cx, arc: Span) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        arc.sub(0, ARC_HEADER),
        LE,
        (),
        arc_layout,
    ));
    cx.emit(Node::new("Codes").span(arc.tail(ARC_HEADER)));
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn gr_probe_needs_a_known_length_or_the_head() {
        // An 8x8 compressed device context whose 1000-byte block runs past
        // the 61 bytes there are.
        let mut data = vec![0u8; 16];
        for v in [8u32, 8, 8, DCF_COMPRESSED] {
            data.extend_from_slice(&v.to_le_bytes());
        }
        data.extend_from_slice(&1000u64.to_le_bytes());
        data.extend_from_slice(&64u64.to_le_bytes());
        data.extend_from_slice(&[2, 0, 0, 0, 0]);
        let head = |len, len_known| Head {
            data: &data,
            tail: &data,
            len,
            len_known,
        };
        assert!(!gr_probe(&head(61, true)));
        assert!(!gr_probe(&head(1 << 20, false)));
        assert!(gr_probe(&head(1049, true)));
    }
}
