//! sfnt tables that need values from other tables: `hmtx`/`vmtx` (the
//! metric counts in `hhea`/`vhea`, the glyph count in `maxp`), `loca` and
//! `glyf` (`head`'s offset format, `maxp`), `sbix` (`maxp`), the bitmap data
//! tables `CBDT`/`EBDT` (located through `CBLC`/`EBLC`), and WOFF2's
//! transformed `glyf` and `hmtx`.
//!
//! [`FontCtx`] carries the spans of a font's tables so a table's decoder can
//! read the few values it needs from the others when it is expanded.

use std::sync::Arc;

use crate::bytes::{i16_be, to_u64, to_usize, u16_be, u32_be};
use crate::codec::inflate_span;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt::fourcc;
use crate::formats::{Input, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{FlagTable, flag};

const BE: Endian = Endian::Big;

const SBIX_FLAGS: FlagTable = &[flag(0x0001, "Set to 1"), flag(0x0002, "Draw outlines")];
const BITMAP_FLAGS: FlagTable = &[
    flag(0x01, "Horizontal metrics"),
    flag(0x02, "Vertical metrics"),
];
const GLYF_OPTIONS: FlagTable = &[flag(0x0001, "Overlap simple bitmap")];
const HMTX_FLAGS: FlagTable = &[
    flag(0x01, "Proportional LSBs omitted"),
    flag(0x02, "Monospaced LSBs omitted"),
];

/// One table of a font, as its directory gives it.
#[derive(Clone, Debug)]
pub struct FontTable {
    pub tag: String,
    pub span: Span,
    /// WOFF 1.0: the table is zlib-compressed to `span`, this many bytes
    /// uncompressed.
    pub zlib: Option<u32>,
}

/// The tables of the font a table belongs to.
#[derive(Clone, Debug, Default)]
pub struct FontCtx(Arc<Vec<FontTable>>);

impl FontCtx {
    pub fn new(tables: Vec<FontTable>) -> Self {
        FontCtx(Arc::new(tables))
    }

    /// The (decompressed) span of table `tag`.
    pub async fn table(&self, cx: &Cx, tag: &str) -> Option<Span> {
        let t = self.0.iter().find(|t| t.tag == tag)?;
        match t.zlib {
            None => Some(t.span),
            Some(orig) => inflate_span(cx, t.span, true, Some(orig.into()))
                .await
                .ok()
                .map(|d| d.span),
        }
    }

    async fn u16_at(&self, cx: &Cx, tag: &str, at: u64) -> Option<u16> {
        let span = self.table(cx, tag).await?;
        let b = cx.read_avail(span.sub(at, 2)).await.ok()?;
        u16_be(&b, 0)
    }

    /// `maxp.numGlyphs`.
    pub async fn num_glyphs(&self, cx: &Cx) -> Option<u16> {
        self.u16_at(cx, "maxp", 4).await
    }

    /// `hhea.numberOfHMetrics`, or `vhea.numOfLongVerMetrics`.
    pub async fn long_metrics(&self, cx: &Cx, vertical: bool) -> Option<u16> {
        self.u16_at(cx, if vertical { "vhea" } else { "hhea" }, 34)
            .await
    }

    /// `head.indexToLocFormat` is 1: `loca` holds 32-bit offsets.
    pub async fn long_loca(&self, cx: &Cx) -> Option<bool> {
        self.u16_at(cx, "head", 50).await.map(|v| v != 0)
    }
}

fn missing(span: Span, what: &str) -> Node {
    Node::new("Data")
        .span(span)
        .summary(format!("{} bytes", span.len))
        .diag(Diagnostic::warning(format!("not decoded: {what}")))
}

// ---------------------------------------------------------------------------
// hmtx / vmtx

/// `hmtx` or `vmtx`: `n` long metrics (advance and side bearing) for the
/// first glyphs, then side bearings alone for the rest.
pub async fn metrics(cx: &Cx, span: Span, ctx: &FontCtx, vertical: bool) -> Result<()> {
    let (Some(long), Some(glyphs)) = (
        ctx.long_metrics(cx, vertical).await,
        ctx.num_glyphs(cx).await,
    ) else {
        let need = if vertical {
            "vhea and maxp"
        } else {
            "hhea and maxp"
        };
        cx.emit(missing(
            span,
            &format!("needs the metric and glyph counts ({need})"),
        ));
        return Ok(());
    };
    let long_len = u64::from(long).saturating_mul(4);
    let rest = u64::from(glyphs.saturating_sub(long));
    let rest_len = rest.saturating_mul(2);
    let (advance, bearing) = if vertical {
        ("advance height", "top side bearing")
    } else {
        ("advance width", "left side bearing")
    };
    cx.emit(
        Node::new("Long metrics")
            .span(span.sub(0, long_len))
            .summary(format!("{long} × ({advance}, {bearing})"))
            .lazy(long_metrics, (span.sub(0, long_len), vertical)),
    );
    if rest > 0 {
        let bearings = span.sub(long_len, rest_len);
        cx.emit(
            Node::new(if vertical {
                "Top side bearings"
            } else {
                "Left side bearings"
            })
            .span(bearings)
            .summary(format!("{rest} glyphs"))
            .lazy(side_bearings, (bearings, u64::from(long))),
        );
    }
    let need = long_len.saturating_add(rest_len);
    if span.len < need {
        cx.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, need),
            span.len,
        ));
    } else if span.len > need {
        cx.emit(Node::new("Trailing data").span(span.tail(need)));
    }
    Ok(())
}

async fn long_metrics(cx: Cx, (span, vertical): (Span, bool)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let (advance, bearing) = if vertical {
        ("advance", "tsb")
    } else {
        ("advance", "lsb")
    };
    let n = to_u64(data.len()) / 4;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let at = to_usize(i.saturating_mul(4));
        let a = u16_be(&data, at).unwrap_or(0);
        let b = i16_be(&data, at.saturating_add(2)).unwrap_or(0);
        cx.push(
            Node::new(format!("Glyph {i}"))
                .span(span.sub(i.saturating_mul(4), 4))
                .summary(format!("{advance} {a}, {bearing} {b}")),
        )
        .await;
    }
    Ok(())
}

async fn side_bearings(cx: Cx, (span, first): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span).await?;
    let n = to_u64(data.len()) / 2;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let v = i16_be(&data, to_usize(i.saturating_mul(2))).unwrap_or(0);
        cx.push(
            Node::new(format!("Glyph {}", first.saturating_add(i)))
                .span(span.sub(i.saturating_mul(2), 2))
                .summary(v.to_string()),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// loca / glyf

/// Glyph offsets from `loca`: `glyphs + 1` entries, halved 16-bit or 32-bit.
struct Loca {
    data: Vec<u8>,
    long: bool,
    glyphs: u64,
}

impl Loca {
    async fn read(cx: &Cx, span: Span, ctx: &FontCtx) -> std::result::Result<Loca, String> {
        let long = ctx
            .long_loca(cx)
            .await
            .ok_or("needs the offset format (head)")?;
        let glyphs = ctx
            .num_glyphs(cx)
            .await
            .ok_or("needs the glyph count (maxp)")?;
        let entries = u64::from(glyphs).saturating_add(1);
        let len = entries.saturating_mul(if long { 4 } else { 2 });
        let data = cx
            .read_avail(span.sub(0, len))
            .await
            .map_err(|e| e.to_string())?;
        Ok(Loca {
            data,
            long,
            glyphs: glyphs.into(),
        })
    }

    fn offset(&self, i: u64) -> Option<u64> {
        let i = to_usize(i);
        if self.long {
            u32_be(&self.data, i.saturating_mul(4)).map(u64::from)
        } else {
            u16_be(&self.data, i.saturating_mul(2)).map(|v| u64::from(v).saturating_mul(2))
        }
    }

    /// Offset and length of glyph `i` in `glyf`.
    fn glyph(&self, i: u64) -> Option<(u64, u64)> {
        let start = self.offset(i)?;
        let end = self.offset(i.saturating_add(1))?;
        Some((start, end.saturating_sub(start)))
    }
}

pub async fn loca(cx: &Cx, span: Span, ctx: &FontCtx) -> Result<()> {
    let loca = match Loca::read(cx, span, ctx).await {
        Ok(l) => l,
        Err(e) => {
            cx.emit(missing(span, &e));
            return Ok(());
        }
    };
    let width = if loca.long { 4u64 } else { 2 };
    cx.set_count(Count::Exact(loca.glyphs.saturating_add(1)));
    for i in 0..=loca.glyphs {
        let Some(offset) = loca.offset(i) else {
            cx.diag(Diagnostic::truncated(
                span.sub(i.saturating_mul(width), width),
                0,
            ));
            break;
        };
        let summary = match loca.glyph(i) {
            Some((_, 0)) => format!("{offset:#x}, empty"),
            Some((_, len)) => format!("{offset:#x}, {len} bytes"),
            None => format!("{offset:#x}, end"),
        };
        cx.push(
            Node::new(if i == loca.glyphs {
                "End".to_owned()
            } else {
                format!("Glyph {i}")
            })
            .span(span.sub(i.saturating_mul(width), width))
            .summary(summary),
        )
        .await;
    }
    Ok(())
}

/// `glyf`: one node per glyph, located through `loca`.
pub async fn glyf(cx: &Cx, span: Span, ctx: &FontCtx) -> Result<()> {
    let Some(loca_span) = ctx.table(cx, "loca").await else {
        cx.emit(missing(span, "needs the glyph offsets (loca)"));
        return Ok(());
    };
    let loca = match Loca::read(cx, loca_span, ctx).await {
        Ok(l) => l,
        Err(e) => {
            cx.emit(missing(span, &e));
            return Ok(());
        }
    };
    cx.set_count(Count::Exact(loca.glyphs));
    let index: u64 = cx.resume::<u64>().unwrap_or(0);
    for i in index..loca.glyphs {
        cx.mark(move || i);
        let Some((offset, len)) = loca.glyph(i) else {
            cx.diag(Diagnostic::malformed(format!("loca ends before glyph {i}")));
            break;
        };
        let gspan = span.sub(offset, len);
        let mut node = Node::new(format!("Glyph {i}")).span(gspan);
        if len == 0 {
            node = node.summary("empty");
        } else if cx.skipping() {
            node = node.lazy(glyph, gspan);
        } else {
            let head = cx.read_avail(gspan.sub(0, 10)).await?;
            node = node.summary(glyph_summary(&head)).lazy(glyph, gspan);
            if gspan.len < len {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset.saturating_add(offset), len),
                    gspan.len,
                ));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

fn glyph_summary(head: &[u8]) -> String {
    let (Some(n), Some(x0), Some(y0), Some(x1), Some(y1)) = (
        i16_be(head, 0),
        i16_be(head, 2),
        i16_be(head, 4),
        i16_be(head, 6),
        i16_be(head, 8),
    ) else {
        return "truncated".to_owned();
    };
    let kind = if n >= 0 {
        format!("{n} contours")
    } else {
        "composite".to_owned()
    };
    format!("{kind}, ({x0}, {y0})–({x1}, {y1})")
}

const COMPOSITE_FLAGS: FlagTable = &[
    flag(0x0001, "ARG_1_AND_2_ARE_WORDS"),
    flag(0x0002, "ARGS_ARE_XY_VALUES"),
    flag(0x0004, "ROUND_XY_TO_GRID"),
    flag(0x0008, "WE_HAVE_A_SCALE"),
    flag(0x0020, "MORE_COMPONENTS"),
    flag(0x0040, "WE_HAVE_AN_X_AND_Y_SCALE"),
    flag(0x0080, "WE_HAVE_A_TWO_BY_TWO"),
    flag(0x0100, "WE_HAVE_INSTRUCTIONS"),
    flag(0x0200, "USE_MY_METRICS"),
    flag(0x0400, "OVERLAP_COMPOUND"),
    flag(0x0800, "SCALED_COMPONENT_OFFSET"),
    flag(0x1000, "UNSCALED_COMPONENT_OFFSET"),
];

async fn glyph(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let contours = f.int::<i16>("Number of contours").emit()?;
    for name in ["xMin", "yMin", "xMax", "yMax"] {
        f.int::<i16>(name).emit()?;
    }
    if contours >= 0 {
        simple_glyph(&cx, &mut f, contours.unsigned_abs()).await
    } else {
        composite_glyph(&cx, &mut f).await
    }
}

async fn simple_glyph(cx: &Cx, f: &mut Fields<'_>, contours: u16) -> Result<()> {
    let ends_len = u64::from(contours).saturating_mul(2);
    let ends_span = f.peek_span(ends_len);
    let data = &f.block().data;
    let last = contours.checked_sub(1).and_then(|i| {
        u16_be(
            data,
            to_usize(f.pos().saturating_add(u64::from(i).saturating_mul(2))),
        )
    });
    let points = last.map_or(0, |l| u64::from(l).saturating_add(1));
    f.node(
        Node::new("End points of contours")
            .span(ends_span)
            .summary(format!("{contours} contours, {points} points")),
    );
    f.skip(ends_len);
    let instructions = f.u16("Instruction length").emit()?;
    f.bytes("Instructions", instructions.into()).emit()?;
    // Flags (with repeats) give the size of each coordinate.
    let start = f.pos();
    let mut pos = to_usize(start);
    let (mut seen, mut xs, mut ys) = (0u64, 0u64, 0u64);
    let mut steps = 0u32;
    while seen < points {
        let Some(&flags) = data.get(pos) else {
            break;
        };
        pos = pos.saturating_add(1);
        let mut repeat = 1u64;
        if flags & 0x08 != 0 {
            let Some(&r) = data.get(pos) else {
                break;
            };
            pos = pos.saturating_add(1);
            repeat = repeat.saturating_add(r.into());
        }
        let repeat = repeat.min(points.saturating_sub(seen));
        let x = if flags & 0x02 != 0 {
            1
        } else if flags & 0x10 != 0 {
            0
        } else {
            2
        };
        let y = if flags & 0x04 != 0 {
            1
        } else if flags & 0x20 != 0 {
            0
        } else {
            2
        };
        xs = xs.saturating_add(repeat.saturating_mul(x));
        ys = ys.saturating_add(repeat.saturating_mul(y));
        seen = seen.saturating_add(repeat);
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
    }
    let flags_len = to_u64(pos).saturating_sub(start);
    f.node(
        Node::new("Flags")
            .span(f.peek_span(flags_len))
            .summary(format!("{flags_len} bytes")),
    );
    f.skip(flags_len);
    f.node(
        Node::new("X coordinates")
            .span(f.peek_span(xs))
            .summary(format!("{xs} bytes")),
    );
    f.skip(xs);
    f.node(
        Node::new("Y coordinates")
            .span(f.peek_span(ys))
            .summary(format!("{ys} bytes")),
    );
    f.skip(ys);
    if seen < points {
        f.node(Node::new("Outline").diag(Diagnostic::malformed(format!(
            "flags end after {seen} of {points} points"
        ))));
    } else if f.pos() > to_u64(data.len()) {
        f.node(
            Node::new("Outline").diag(Diagnostic::truncated(f.block().span, to_u64(data.len()))),
        );
    }
    // Glyphs are padded to 2 or 4 bytes.
    if f.remaining() > 0 && f.pos() <= to_u64(data.len()) {
        let rest = f.remaining();
        f.node(Node::new("Padding").span(f.peek_span(rest)));
    }
    Ok(())
}

async fn composite_glyph(cx: &Cx, f: &mut Fields<'_>) -> Result<()> {
    let mut index = 0u32;
    loop {
        let start = f.pos();
        let flags = f.u16("Flags").get()?;
        let glyph = f.u16("Glyph index").get()?;
        let args = if flags & 0x0001 != 0 { 4u64 } else { 2 };
        let transform = if flags & 0x0008 != 0 {
            2u64
        } else if flags & 0x0040 != 0 {
            4
        } else if flags & 0x0080 != 0 {
            8
        } else {
            0
        };
        let len = 4u64.saturating_add(args).saturating_add(transform);
        f.seek(start);
        let span = f.peek_span(len);
        f.node(
            struct_node(
                format!("Component {index}"),
                span,
                BE,
                (args, transform),
                component,
            )
            .summary(format!("glyph {glyph}")),
        );
        f.skip(len);
        if f.pos() > to_u64(f.block().data.len()) {
            return Err(Diagnostic::truncated(span, 0));
        }
        index = index.saturating_add(1);
        if index.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        if flags & 0x0020 == 0 {
            if flags & 0x0100 != 0 {
                let n = f.u16("Instruction length").emit()?;
                f.bytes("Instructions", n.into()).emit()?;
            }
            return Ok(());
        }
    }
}

fn component(f: &mut Fields<'_>, &(args, transform): &(u64, u64)) -> Result<()> {
    f.u16("Flags").flags(COMPOSITE_FLAGS).emit()?;
    f.u16("Glyph index").emit()?;
    if args == 4 {
        f.int::<i16>("Argument 1").emit()?;
        f.int::<i16>("Argument 2").emit()?;
    } else {
        f.int::<i8>("Argument 1").emit()?;
        f.int::<i8>("Argument 2").emit()?;
    }
    let names: &[&'static str] = match transform {
        2 => &["Scale"],
        4 => &["x scale", "y scale"],
        8 => &["x scale", "scale 01", "scale 10", "y scale"],
        _ => &[],
    };
    for &name in names {
        f.int::<i16>(name)
            .with(|&v, n| n.summary(format!("{}", f2dot14(v))))
            .emit()?;
    }
    Ok(())
}

/// A signed 2.14 fixed-point number.
fn f2dot14(v: i16) -> f64 {
    f64::from(v) / 16384.0
}

// ---------------------------------------------------------------------------
// sbix

pub async fn sbix(cx: &Cx, input: Input, span: Span, ctx: &FontCtx) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 8)?).await?;
    let strikes = u32_be(&head, 4).unwrap_or(0);
    let offsets_len = u64::from(strikes).saturating_mul(4);
    cx.emit(struct_node("Header", span.sub(0, 8), BE, (), |f, _| {
        f.u16("Version").emit()?;
        f.u16("Flags").flags(SBIX_FLAGS).emit()?;
        f.u32("Number of strikes").emit()?;
        Ok(())
    }));
    let Some(glyphs) = ctx.num_glyphs(cx).await else {
        cx.emit(missing(span.tail(8), "needs the glyph count (maxp)"));
        return Ok(());
    };
    let offsets = cx.read(span.sub_exact(8, offsets_len)?).await?;
    for i in 0..u64::from(strikes) {
        let at = u64::from(u32_be(&offsets, to_usize(i.saturating_mul(4))).unwrap_or(0));
        let strike = span.tail(at);
        let sh = cx.read_avail(strike.sub(0, 4)).await?;
        let ppem = u16_be(&sh, 0).unwrap_or(0);
        let ppi = u16_be(&sh, 2).unwrap_or(0);
        cx.push(
            Node::new(format!("Strike {i}"))
                .span(strike.sub(
                    0,
                    4u64.saturating_add(u64::from(glyphs).saturating_add(1).saturating_mul(4)),
                ))
                .summary(format!("{ppem} ppem, {ppi} ppi"))
                .lazy(sbix_strike, (input, strike, glyphs)),
        )
        .await;
    }
    Ok(())
}

async fn sbix_strike(cx: Cx, (input, strike, glyphs): (Input, Span, u16)) -> Result<()> {
    cx.emit(struct_node("Header", strike.sub(0, 4), BE, (), |f, _| {
        f.u16("ppem").emit()?;
        f.u16("ppi").emit()?;
        Ok(())
    }));
    let n = u64::from(glyphs).saturating_add(1);
    let offsets = cx.read(strike.sub_exact(4, n.saturating_mul(4))?).await?;
    for i in 0..u64::from(glyphs) {
        let at = to_usize(i.saturating_mul(4));
        let start = u64::from(u32_be(&offsets, at).unwrap_or(0));
        let end = u64::from(u32_be(&offsets, at.saturating_add(4)).unwrap_or(0));
        let len = end.saturating_sub(start);
        if len == 0 {
            if i % 1024 == 1023 {
                cx.checkpoint().await;
            }
            continue;
        }
        let gspan = strike.sub(start, len);
        let gh = cx.read_avail(gspan.sub(0, 8)).await?;
        let kind = fourcc(gh.get(4..8).unwrap_or_default());
        cx.push(
            Node::new(format!("Glyph {i}"))
                .span(gspan)
                .summary(format!("'{kind}', {} bytes", len.saturating_sub(8)))
                .lazy(sbix_glyph, (input, gspan)),
        )
        .await;
    }
    Ok(())
}

async fn sbix_glyph(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.int::<i16>("Origin x offset").emit()?;
    f.int::<i16>("Origin y offset").emit()?;
    let kind = f.ascii("Graphic type", 4).emit()?;
    let data = span.tail(8);
    match kind.as_str() {
        "dupe" => {
            let b = cx.read_avail(data.sub(0, 2)).await?;
            let g = u16_be(&b, 0).unwrap_or(0);
            cx.emit(
                Node::new("Duplicate of")
                    .span(data.sub(0, 2))
                    .summary(format!("glyph {g}")),
            );
        }
        "png " | "jpg " | "tiff" => cx.emit(embedded("Image", input.nested(data))),
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// CBLC/CBDT and EBLC/EBDT

/// One index subtable of a bitmap location table.
#[derive(Clone, Copy, Debug)]
struct SubTable {
    first: u16,
    last: u16,
    /// The subtable itself (header and offsets) in the location table.
    span: Span,
}

/// `CBLC` or `EBLC`: the strikes, each with its index subtables.
pub async fn bitmap_locations(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 8)?).await?;
    let sizes = u32_be(&head, 4).unwrap_or(0);
    cx.emit(struct_node("Header", span.sub(0, 8), BE, (), |f, _| {
        f.u16("Major version").emit()?;
        f.u16("Minor version").emit()?;
        f.u32("Number of sizes").emit()?;
        Ok(())
    }));
    let table = span.sub_exact(8, u64::from(sizes).saturating_mul(48))?;
    cx.set_count(Count::Exact(sizes.into()));
    for i in 0..u64::from(sizes) {
        let rspan = table.sub(i.saturating_mul(48), 48);
        let r = cx.read(rspan).await?;
        let first = u16_be(&r, 40).unwrap_or(0);
        let last = u16_be(&r, 42).unwrap_or(0);
        let ppem = r.get(44).copied().unwrap_or(0);
        let depth = r.get(46).copied().unwrap_or(0);
        cx.push(
            struct_node(format!("Strike {i}"), rspan, BE, span, bitmap_size)
                .summary(format!("{ppem} ppem, {depth}-bit, glyphs {first}–{last}")),
        )
        .await;
    }
    Ok(())
}

fn line_metrics(f: &mut Fields<'_>, which: &'static str) -> Result<()> {
    f.node(struct_node(which, f.peek_span(12), BE, (), |f, _| {
        f.int::<i8>("Ascender").emit()?;
        f.int::<i8>("Descender").emit()?;
        f.u8("Width max").emit()?;
        f.int::<i8>("Caret slope numerator").emit()?;
        f.int::<i8>("Caret slope denominator").emit()?;
        f.int::<i8>("Caret offset").emit()?;
        f.int::<i8>("Min origin SB").emit()?;
        f.int::<i8>("Min advance SB").emit()?;
        f.int::<i8>("Max before BL").emit()?;
        f.int::<i8>("Min after BL").emit()?;
        f.bytes("Padding", 2).emit()?;
        Ok(())
    }));
    f.skip(12);
    Ok(())
}

fn bitmap_size(f: &mut Fields<'_>, &table: &Span) -> Result<()> {
    let array = f.u32("Index subtable array offset").hex().emit()?;
    let size = f.u32("Index tables size").emit()?;
    let count = f.u32("Number of index subtables").emit()?;
    f.u32("Colour ref").emit()?;
    line_metrics(f, "Horizontal line metrics")?;
    line_metrics(f, "Vertical line metrics")?;
    f.u16("Start glyph index").emit()?;
    f.u16("End glyph index").emit()?;
    f.u8("ppem x").emit()?;
    f.u8("ppem y").emit()?;
    f.u8("Bit depth").emit()?;
    f.u8("Flags").flags(BITMAP_FLAGS).emit()?;
    let area = table.sub(array.into(), size.into());
    f.node(
        Node::new("Index subtables")
            .span(area)
            .summary(format!("{count}"))
            .lazy(index_subtables, (area, count)),
    );
    Ok(())
}

/// Reads a strike's index subtable array (8-byte records).
async fn read_subtables(cx: &Cx, area: Span, count: u32) -> Result<Vec<SubTable>> {
    let n = u64::from(count);
    let data = cx.read(area.sub_exact(0, n.saturating_mul(8))?).await?;
    let mut out = Vec::new();
    for rec in data.as_chunks::<8>().0 {
        let first = u16_be(rec, 0).unwrap_or(0);
        let last = u16_be(rec, 2).unwrap_or(0);
        let offset = u64::from(u32_be(rec, 4).unwrap_or(0));
        out.push(SubTable {
            first,
            last,
            span: area.tail(offset),
        });
    }
    Ok(out)
}

const INDEX_FORMATS: crate::value::EnumTable = &[
    (1, "variable size, 32-bit offsets"),
    (2, "constant size"),
    (3, "variable size, 16-bit offsets"),
    (4, "sparse, variable size"),
    (5, "sparse, constant size"),
];

async fn index_subtables(cx: Cx, (area, count): (Span, u32)) -> Result<()> {
    let subs = read_subtables(&cx, area, count).await?;
    cx.set_count(Count::Exact(to_u64(subs.len())));
    for (i, s) in subs.into_iter().enumerate() {
        let h = cx.read_avail(s.span.sub(0, 8)).await?;
        let index_format = u16_be(&h, 0).unwrap_or(0);
        let image_format = u16_be(&h, 2).unwrap_or(0);
        cx.push(
            Node::new(format!("Subtable {i}"))
                .span(s.span.sub(0, 8))
                .summary(format!(
                    "glyphs {}–{}, index format {index_format}, image format {image_format}",
                    s.first, s.last
                ))
                .lazy(index_subtable, s.span.sub(0, 8)),
        )
        .await;
    }
    Ok(())
}

async fn index_subtable(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Index format").enumeration(INDEX_FORMATS).emit()?;
    f.u16("Image format").emit()?;
    f.u32("Image data offset").hex().emit()?;
    Ok(())
}

/// A glyph's bitmap in the data table: its index, image format and span.
async fn subtable_glyphs(
    cx: &Cx,
    s: SubTable,
    data: Span,
    out: &mut Vec<(u16, u16, Span)>,
) -> Result<()> {
    let h = cx.read(s.span.sub_exact(0, 8)?).await?;
    let index_format = u16_be(&h, 0).unwrap_or(0);
    let image_format = u16_be(&h, 2).unwrap_or(0);
    let base = u64::from(u32_be(&h, 4).unwrap_or(0));
    let n = u64::from(s.last.saturating_sub(s.first)).saturating_add(1);
    let body = s.span.tail(8);
    let mut push = |glyph: u64, start: u64, len: u64| {
        let glyph = u16::try_from(glyph).unwrap_or(u16::MAX);
        out.push((
            glyph,
            image_format,
            data.sub(base.saturating_add(start), len),
        ));
    };
    match index_format {
        1 | 3 => {
            let w = if index_format == 1 { 4u64 } else { 2 };
            let offs = cx
                .read(body.sub_exact(0, n.saturating_add(1).saturating_mul(w))?)
                .await?;
            let at = |i: u64| -> u64 {
                let i = to_usize(i.saturating_mul(w));
                if w == 4 {
                    u32_be(&offs, i).map_or(0, u64::from)
                } else {
                    u16_be(&offs, i).map_or(0, u64::from)
                }
            };
            for i in 0..n {
                let (a, b) = (at(i), at(i.saturating_add(1)));
                if b > a {
                    push(u64::from(s.first).saturating_add(i), a, b.saturating_sub(a));
                }
            }
        }
        2 => {
            let b = cx.read(body.sub_exact(0, 4)?).await?;
            let size = u64::from(u32_be(&b, 0).unwrap_or(0));
            for i in 0..n {
                push(
                    u64::from(s.first).saturating_add(i),
                    i.saturating_mul(size),
                    size,
                );
            }
        }
        4 => {
            let b = cx.read(body.sub_exact(0, 4)?).await?;
            let count = u64::from(u32_be(&b, 0).unwrap_or(0));
            let pairs = cx
                .read(body.sub_exact(4, count.saturating_add(1).saturating_mul(4))?)
                .await?;
            for i in 0..count {
                let at = to_usize(i.saturating_mul(4));
                let glyph = u16_be(&pairs, at).unwrap_or(0);
                let a = u64::from(u16_be(&pairs, at.saturating_add(2)).unwrap_or(0));
                let b = u64::from(u16_be(&pairs, at.saturating_add(6)).unwrap_or(0));
                push(glyph.into(), a, b.saturating_sub(a));
            }
        }
        5 => {
            let b = cx.read(body.sub_exact(0, 16)?).await?;
            let size = u64::from(u32_be(&b, 0).unwrap_or(0));
            let count = u64::from(u32_be(&b, 12).unwrap_or(0));
            let ids = cx
                .read(body.sub_exact(16, count.saturating_mul(2))?)
                .await?;
            for i in 0..count {
                let glyph = u16_be(&ids, to_usize(i.saturating_mul(2))).unwrap_or(0);
                push(glyph.into(), i.saturating_mul(size), size);
            }
        }
        _ => {
            return Err(
                Diagnostic::unsupported(format!("index subtable format {index_format}"))
                    .at(s.span.sub(0, 2)),
            );
        }
    }
    Ok(())
}

/// `CBDT` or `EBDT`: the bitmaps, strike by strike as the location table
/// (`CBLC` or `EBLC`) lists them.
pub async fn bitmap_data(
    cx: &Cx,
    input: Input,
    span: Span,
    ctx: &FontCtx,
    colour: bool,
) -> Result<()> {
    cx.emit(struct_node("Header", span.sub(0, 4), BE, (), |f, _| {
        f.u16("Major version").emit()?;
        f.u16("Minor version").emit()?;
        Ok(())
    }));
    let loc_tag = if colour { "CBLC" } else { "EBLC" };
    let Some(loc) = ctx.table(cx, loc_tag).await else {
        cx.emit(missing(
            span.tail(4),
            &format!("needs the bitmap locations ({loc_tag})"),
        ));
        return Ok(());
    };
    let head = cx.read(loc.sub_exact(0, 8)?).await?;
    let sizes = u32_be(&head, 4).unwrap_or(0);
    let table = loc.sub_exact(8, u64::from(sizes).saturating_mul(48))?;
    for i in 0..u64::from(sizes) {
        let r = cx.read(table.sub(i.saturating_mul(48), 48)).await?;
        let array = u64::from(u32_be(&r, 0).unwrap_or(0));
        let size = u64::from(u32_be(&r, 4).unwrap_or(0));
        let count = u32_be(&r, 8).unwrap_or(0);
        let ppem = r.get(44).copied().unwrap_or(0);
        let depth = r.get(46).copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Strike {i}"))
                .summary(format!("{ppem} ppem, {depth}-bit"))
                .lazy(bitmap_strike, (input, span, loc.sub(array, size), count)),
        )
        .await;
    }
    Ok(())
}

async fn bitmap_strike(cx: Cx, (input, data, area, count): (Input, Span, Span, u32)) -> Result<()> {
    let subs = read_subtables(&cx, area, count).await?;
    let mut glyphs = Vec::new();
    for s in subs {
        if let Err(e) = subtable_glyphs(&cx, s, data, &mut glyphs).await {
            cx.diag(e);
        }
        cx.checkpoint().await;
    }
    cx.set_count(Count::Exact(to_u64(glyphs.len())));
    for (glyph, format, span) in glyphs {
        cx.push(
            Node::new(format!("Glyph {glyph}"))
                .span(span)
                .summary(format!("image format {format}, {} bytes", span.len))
                .lazy(bitmap_glyph, (input, span, format)),
        )
        .await;
    }
    Ok(())
}

fn small_metrics(f: &mut Fields<'_>) -> Result<()> {
    f.node(struct_node(
        "Small metrics",
        f.peek_span(5),
        BE,
        (),
        |f, _| {
            f.u8("Height").emit()?;
            f.u8("Width").emit()?;
            f.int::<i8>("Bearing x").emit()?;
            f.int::<i8>("Bearing y").emit()?;
            f.u8("Advance").emit()?;
            Ok(())
        },
    ));
    f.skip(5);
    Ok(())
}

fn big_metrics(f: &mut Fields<'_>) -> Result<()> {
    f.node(struct_node(
        "Big metrics",
        f.peek_span(8),
        BE,
        (),
        |f, _| {
            f.u8("Height").emit()?;
            f.u8("Width").emit()?;
            f.int::<i8>("Horizontal bearing x").emit()?;
            f.int::<i8>("Horizontal bearing y").emit()?;
            f.u8("Horizontal advance").emit()?;
            f.int::<i8>("Vertical bearing x").emit()?;
            f.int::<i8>("Vertical bearing y").emit()?;
            f.u8("Vertical advance").emit()?;
            Ok(())
        },
    ));
    f.skip(8);
    Ok(())
}

async fn bitmap_glyph(cx: Cx, (input, span, format): (Input, Span, u16)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    match format {
        1 | 2 | 8 => small_metrics(&mut f)?,
        6 | 7 | 9 | 18 => big_metrics(&mut f)?,
        17 => small_metrics(&mut f)?,
        _ => {}
    }
    match format {
        17..=19 => {
            let len = f.u32("Data length").emit()?;
            let data = f.peek_span(len.into());
            cx.emit(embedded("PNG image", input.nested(data)));
        }
        8 | 9 => {
            if format == 8 {
                f.u8("Padding").emit()?;
            }
            let n = f.u16("Number of components").emit()?;
            for _ in 0..n {
                f.node(struct_node("Component", f.peek_span(4), BE, (), |f, _| {
                    f.u16("Glyph").emit()?;
                    f.int::<i8>("x offset").emit()?;
                    f.int::<i8>("y offset").emit()?;
                    Ok(())
                }));
                f.skip(4);
            }
        }
        1 | 2 | 5 | 6 | 7 => {
            let rest = f.remaining();
            f.node(
                Node::new(if matches!(format, 1 | 6) {
                    "Bitmap (byte-aligned rows)"
                } else {
                    "Bitmap (bit-aligned)"
                })
                .span(f.peek_span(rest))
                .summary(format!("{rest} bytes")),
            );
        }
        _ => {
            f.node(
                Node::new("Data")
                    .span(span)
                    .diag(Diagnostic::unsupported(format!("image format {format}"))),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// WOFF2 transforms

const GLYF_STREAMS: [&str; 7] = [
    "nContour stream",
    "nPoints stream",
    "Flag stream",
    "Glyph stream",
    "Composite stream",
    "Bbox stream",
    "Instruction stream",
];

/// WOFF2's transformed `glyf` (version 0): a 36-byte header, then seven
/// streams the decoder interleaves to rebuild the glyphs, and an optional
/// overlap bitmap.
pub async fn woff2_glyf(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 36)?).await?;
    let options = u16_be(&head, 2).unwrap_or(0);
    let glyphs = u64::from(u16_be(&head, 4).unwrap_or(0));
    cx.emit(struct_node("Header", span.sub(0, 36), BE, (), |f, _| {
        f.u16("Reserved").emit()?;
        f.u16("Option flags").flags(GLYF_OPTIONS).emit()?;
        f.u16("Number of glyphs").emit()?;
        f.u16("Index format")
            .with(|&v, n| {
                n.summary(if v == 0 {
                    "short offsets"
                } else {
                    "long offsets"
                })
            })
            .emit()?;
        for name in [
            "nContour stream size",
            "nPoints stream size",
            "Flag stream size",
            "Glyph stream size",
            "Composite stream size",
            "Bbox stream size",
            "Instruction stream size",
        ] {
            f.u32(name).emit()?;
        }
        Ok(())
    }));
    let mut at = 36u64;
    for (i, name) in GLYF_STREAMS.iter().enumerate() {
        let len = u64::from(u32_be(&head, 8usize.saturating_add(i.saturating_mul(4))).unwrap_or(0));
        let stream = span.sub(at, len);
        let mut node = Node::new(*name)
            .span(stream)
            .summary(format!("{len} bytes"));
        if *name == "Bbox stream" {
            // A bitmap of glyphs with explicit boxes, then the boxes.
            let bitmap = (glyphs.saturating_add(31) / 32).saturating_mul(4);
            node = node.lazy(bbox_stream, (stream, bitmap));
        }
        if stream.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset.saturating_add(at), len),
                stream.len,
            ));
        }
        cx.emit(node);
        at = at.saturating_add(len);
    }
    if options & 1 != 0 {
        let len = glyphs.saturating_add(7) / 8;
        cx.emit(
            Node::new("Overlap simple bitmap")
                .span(span.sub(at, len))
                .summary(format!("{len} bytes")),
        );
        at = at.saturating_add(len);
    }
    if span.len > at {
        cx.emit(Node::new("Trailing data").span(span.tail(at)));
    }
    Ok(())
}

async fn bbox_stream(cx: Cx, (stream, bitmap): (Span, u64)) -> Result<()> {
    let bits = cx.read_avail(stream.sub(0, bitmap)).await?;
    let boxes: u32 = bits
        .iter()
        .map(|b| b.count_ones())
        .fold(0, u32::saturating_add);
    cx.emit(
        Node::new("Bbox bitmap")
            .span(stream.sub(0, bitmap))
            .summary(format!("{boxes} glyphs with explicit boxes")),
    );
    cx.emit(
        Node::new("Boxes")
            .span(stream.tail(bitmap))
            .summary(format!("{} bytes", stream.len.saturating_sub(bitmap))),
    );
    Ok(())
}

/// WOFF2's transformed `hmtx` (version 1): flags, the advance widths, and
/// whichever side bearings the decoder cannot take from the glyph boxes.
pub async fn woff2_hmtx(cx: &Cx, span: Span, ctx: &FontCtx) -> Result<()> {
    let b = cx.read(span.sub_exact(0, 1)?).await?;
    let flags = b.first().copied().unwrap_or(0);
    cx.emit(struct_node("Flags", span.sub(0, 1), BE, (), |f, _| {
        f.u8("Flags").flags(HMTX_FLAGS).emit()?;
        Ok(())
    }));
    let (Some(long), Some(glyphs)) = (ctx.long_metrics(cx, false).await, ctx.num_glyphs(cx).await)
    else {
        cx.emit(missing(
            span.tail(1),
            "needs the metric and glyph counts (hhea and maxp)",
        ));
        return Ok(());
    };
    let n = u64::from(long);
    let rest = u64::from(glyphs.saturating_sub(long));
    let mut at = 1u64;
    let widths = span.sub(at, n.saturating_mul(2));
    cx.emit(
        Node::new("Advance widths")
            .span(widths)
            .summary(format!("{n} glyphs")),
    );
    at = at.saturating_add(n.saturating_mul(2));
    if flags & 1 == 0 {
        cx.emit(
            Node::new("Proportional LSBs")
                .span(span.sub(at, n.saturating_mul(2)))
                .summary(format!("{n} glyphs")),
        );
        at = at.saturating_add(n.saturating_mul(2));
    }
    if flags & 2 == 0 && rest > 0 {
        cx.emit(
            Node::new("Monospaced LSBs")
                .span(span.sub(at, rest.saturating_mul(2)))
                .summary(format!("{rest} glyphs")),
        );
        at = at.saturating_add(rest.saturating_mul(2));
    }
    if span.len < at {
        cx.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, at),
            span.len,
        ));
    } else if span.len > at {
        cx.emit(Node::new("Trailing data").span(span.tail(at)));
    }
    Ok(())
}
