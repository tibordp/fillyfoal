//! HEIF item boxes (ISO 23008-12): `pitm`, `iinf`/`infe`, `iloc`, `iref`,
//! `ipma` and the image properties in `ipco` (`ispe`, `pixi`, `irot`, ...).
//! Item data located by `iloc` is offered for embedded dissection.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::fields::struct_node;
use crate::formats::util::vidutil::nal::{NalCodec, group, parse_nal};
use crate::formats::util::vidutil::{
    H264_NAL_TYPES, HEVC_NAL_TYPES, ParamSets, fourcc, hex, lookup_or, plural, uint,
};
use crate::formats::{Input, embedded};
use crate::node::{Count, Node};
use crate::span::Span;

use super::{BE, BoxState, children, find_child, full_box, small, version_flags};

async fn emit_fields(
    cx: &Cx,
    span: Span,
    layout: impl FnOnce(&mut Fields<'_>) -> Result<()>,
) -> Result<()> {
    let block = cx.block(span.sub(0, 0x10000)).await?;
    layout(&mut Fields::emitting(cx, &block, BE))
}

/// Decodes HEIF boxes. Returns `false` for other types.
pub async fn decode_item_box(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    let ctx = st.ctx;
    match &st.header.kind {
        b"pitm" => {
            emit_fields(cx, body, |f| {
                let (v, _) = full_box(f)?;
                item_id(f, v == 0, "Item ID")?;
                Ok(())
            })
            .await?;
        }
        b"iinf" => {
            let (v, _) = version_flags(cx, body).await?;
            let width = if v == 0 { 2 } else { 4 };
            emit_fields(cx, body.sub(0, 4u64.saturating_add(width)), |f| {
                full_box(f)?;
                item_id(f, v == 0, "Entry count")?;
                Ok(())
            })
            .await?;
            let rest = body.tail(4u64.saturating_add(width));
            children(cx, st.input, rest, ctx.child(*b"iinf", rest)).await?;
        }
        b"infe" => emit_fields(cx, body, infe).await?,
        b"iloc" => iloc(cx, st).await?,
        b"ipma" => ipma(cx, body, ctx.siblings).await?,
        b"iref" => {
            emit_fields(cx, body.sub(0, 4), |f| full_box(f).map(|_| ())).await?;
            let rest = body.tail(4);
            children(cx, st.input, rest, ctx.child(*b"iref", rest)).await?;
        }
        _ if &ctx.parent == b"iref" => {
            // The iref version decides the width of item IDs; it sits just
            // before the children region.
            let at = Span::new(
                ctx.siblings.source,
                ctx.siblings.offset.saturating_sub(4),
                1,
            );
            let narrow = cx.read_avail(at).await?.first().copied().unwrap_or(0) == 0;
            emit_fields(cx, body, |f| {
                item_id(f, narrow, "From item ID")?;
                let n = f.u16("Reference count").emit()?;
                for _ in 0..n {
                    item_id(f, narrow, "To item ID")?;
                }
                Ok(())
            })
            .await?;
        }
        b"ispe" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("Image width").emit()?;
                f.u32("Image height").emit()?;
                Ok(())
            })
            .await?;
        }
        b"pixi" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                let n = f.u8("Channel count").emit()?;
                for _ in 0..n {
                    f.u8("Bits per channel").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"irot" => {
            emit_fields(cx, body, |f| {
                f.u8("Angle")
                    .with(|&a, n| {
                        n.summary(format!(
                            "{}° anti-clockwise",
                            u16::from(a & 3).saturating_mul(90)
                        ))
                    })
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"imir" => {
            emit_fields(cx, body, |f| {
                f.u8("Axis")
                    .with(|&a, n| n.summary(mirror_name(a)))
                    .desc("ISO/IEC 23008-12:2022: bit 0; 0 exchanges top and bottom, 1 left and right")
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"auxC" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.cstr("Auxiliary type")
                    .with(|t, n| match aux_name(t) {
                        Some(name) => n.summary(name),
                        None => n,
                    })
                    .emit()?;
                let rest = f.remaining();
                if rest > 0 {
                    f.bytes("Subtype", rest).emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"rloc" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("Horizontal offset").emit()?;
                f.u32("Vertical offset").emit()?;
                Ok(())
            })
            .await?;
        }
        b"lsel" => {
            emit_fields(cx, body, |f| {
                f.u16("Layer ID").emit()?;
                Ok(())
            })
            .await?;
        }
        b"a1op" => {
            emit_fields(cx, body, |f| {
                f.u8("Operating point").emit()?;
                Ok(())
            })
            .await?;
        }
        b"altr" | b"ster" | b"brst" | b"eqiv" if &ctx.parent == b"grpl" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.u32("Group ID").emit()?;
                let n = f.u32("Entity count").emit()?;
                for _ in 0..n {
                    if f.remaining() < 4 {
                        break;
                    }
                    f.u32("Entity ID").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        _ => return Ok(false),
    }
    Ok(true)
}

fn mirror_name(axis: u8) -> &'static str {
    if axis & 1 == 0 {
        "top and bottom exchanged (vertical flip)"
    } else {
        "left and right exchanged (horizontal flip)"
    }
}

/// Well-known auxiliary image types.
fn aux_name(urn: &str) -> Option<&'static str> {
    Some(match urn {
        "urn:mpeg:mpegB:cicp:systems:auxiliary:alpha" | "urn:mpeg:hevc:2015:auxid:1" => {
            "alpha plane"
        }
        "urn:mpeg:mpegB:cicp:systems:auxiliary:depth" | "urn:mpeg:hevc:2015:auxid:2" => "depth map",
        "urn:com:apple:photo:2020:aux:hdrgainmap" => "Apple HDR gain map",
        "urn:com:apple:photo:2018:aux:portraiteffectsmatte" => "Apple portrait effects matte",
        "urn:com:apple:photo:2019:aux:semanticskinmatte" => "Apple skin matte",
        "urn:com:apple:photo:2019:aux:semantichairmatte" => "Apple hair matte",
        "urn:com:apple:photo:2019:aux:semanticteethmatte" => "Apple teeth matte",
        "urn:com:apple:photo:2020:aux:semanticskymatte" => "Apple sky matte",
        _ => return None,
    })
}

/// Kinds of item reference.
fn reference_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"dimg" => "derived from",
        b"thmb" => "thumbnail of",
        b"auxl" => "auxiliary image for",
        b"cdsc" => "describes",
        b"base" => "pre-derived from",
        b"prem" => "premultiplied by",
        b"exbl" => "scalability layer of",
        b"iloc" => "data located by",
        b"font" => "font for",
        b"tbas" => "tile base",
        _ => return None,
    })
}

fn item_id(f: &mut Fields<'_>, narrow: bool, name: &'static str) -> Result<u32> {
    if narrow {
        f.u16(name).emit().map(u32::from)
    } else {
        f.u32(name).emit()
    }
}

const INFE_FLAGS: crate::value::FlagTable = &[crate::value::flag(0x1, "HIDDEN")];

fn infe(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = super::full_box_flags(f, INFE_FLAGS)?;
    if v < 2 {
        f.u16("Item ID").emit()?;
        f.u16("Protection index").emit()?;
        f.cstr("Item name").emit()?;
        f.cstr("Content type").emit()?;
        if f.remaining() > 0 {
            f.cstr("Content encoding").emit()?;
        }
        return Ok(());
    }
    item_id(f, v == 2, "Item ID")?;
    f.u16("Protection index").emit()?;
    let kind = f
        .ascii("Item type", 4)
        .with(|t, n| match item_type_name(t.as_bytes()) {
            Some(name) => n.summary(name),
            None => n,
        })
        .emit()?;
    if f.remaining() > 0 {
        f.cstr("Item name").emit()?;
    }
    if kind == "mime" && f.remaining() > 0 {
        f.cstr("Content type").emit()?;
        if f.remaining() > 0 {
            f.cstr("Content encoding").emit()?;
        }
    } else if kind == "uri " && f.remaining() > 0 {
        f.cstr("Item URI type").emit()?;
    }
    Ok(())
}

fn item_type_name(kind: &[u8]) -> Option<&'static str> {
    Some(match kind {
        b"hvc1" => "HEVC image",
        b"vvc1" => "VVC image",
        b"avc3" => "H.264 image",
        b"av01" => "AV1 image",
        b"avc1" => "H.264 image",
        b"jpeg" => "JPEG image",
        b"j2k1" => "JPEG 2000 image",
        b"grid" => "image grid",
        b"iovl" => "image overlay",
        b"iden" => "identity transform",
        b"Exif" => "Exif metadata",
        b"mime" => "MIME content",
        b"uri " => "URI",
        b"hvt1" => "HEVC tile",
        b"unci" => "uncompressed image",
        b"tmap" => "tone map",
        _ => return None,
    })
}

/// Item ID → (type, name), parsed from an `iinf` body.
async fn item_types(cx: &Cx, meta: Span) -> Result<Vec<(u32, [u8; 4])>> {
    let mut out = Vec::new();
    let Some((h, span)) = find_child(cx, meta, b"iinf").await? else {
        return Ok(out);
    };
    let body = span.tail(h.header_len);
    let d = small(cx, body).await?;
    let v = d.first().copied().unwrap_or(0);
    let mut at = if v == 0 { 6usize } else { 8 };
    while let Some(size) = u32_be(&d, at) {
        let size = usize::try_from(size).unwrap_or(0);
        if size < 8 {
            break;
        }
        let e = at.saturating_add(8);
        let ev = d.get(e).copied().unwrap_or(0);
        let entry = match ev {
            2 => u16_be(&d, e.saturating_add(4))
                .map(u32::from)
                .zip(crate::bytes::array::<4>(&d, e.saturating_add(8))),
            3 => u32_be(&d, e.saturating_add(4))
                .zip(crate::bytes::array::<4>(&d, e.saturating_add(10))),
            _ => None,
        };
        if let Some(entry) = entry {
            out.push(entry);
        }
        at = at.saturating_add(size);
        if out.len() > 4096 {
            break;
        }
    }
    Ok(out)
}

#[derive(Clone, Debug)]
struct Iloc {
    input: Input,
    /// The `meta` children region (for `idat` and `iinf` lookups).
    meta: Span,
    body: Span,
    version: u8,
    offset_size: u8,
    length_size: u8,
    base_size: u8,
    index_size: u8,
    count: u32,
    /// Where the item list starts in `body`.
    start: u64,
    types: Arc<Vec<(u32, [u8; 4])>>,
}

async fn iloc(cx: &Cx, st: &BoxState) -> Result<()> {
    let body = st.body();
    let block = cx.block(body.sub(0, 12)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let (version, _) = full_box(&mut f)?;
    let sizes = f
        .u8("Offset size / length size")
        .with(|&v, n| n.summary(format!("{} / {} bytes", v >> 4, v & 15)))
        .emit()?;
    let sizes2 = f
        .u8("Base offset size / index size")
        .with(|&v, n| n.summary(format!("{} / {} bytes", v >> 4, v & 15)))
        .emit()?;
    let count = item_id(&mut f, version < 2, "Item count")?;
    let state = Iloc {
        input: st.input,
        meta: st.ctx.siblings,
        body,
        version,
        offset_size: sizes >> 4,
        length_size: sizes & 15,
        base_size: sizes2 >> 4,
        index_size: if version >= 1 { sizes2 & 15 } else { 0 },
        count,
        start: f.pos(),
        types: Arc::new(item_types(cx, st.ctx.siblings).await?),
    };
    cx.emit(
        Node::new("Items")
            .span(body.tail(state.start))
            .summary(crate::formats::util::vidutil::plural(count, "item"))
            .lazy(iloc_items, state),
    );
    Ok(())
}

#[derive(Clone, Copy, Debug, Default)]
struct Extent {
    offset: u64,
    length: u64,
}

#[derive(Clone, Debug)]
struct ItemLoc {
    id: u32,
    method: u16,
    base: u64,
    extents: Vec<Extent>,
    span: Span,
}

/// Reads a big-endian unsigned integer of `n` (0, 4 or 8) bytes.
fn sized(d: &[u8], at: &mut usize, n: u8) -> Option<u64> {
    let n = usize::from(n);
    let bytes = d.get(*at..at.checked_add(n)?)?;
    *at = at.checked_add(n)?;
    Some(bytes.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b)))
}

fn parse_item(d: &[u8], at: &mut usize, s: &Iloc, region: Span) -> Option<ItemLoc> {
    let start = *at;
    let id = if s.version < 2 {
        u32::from(u16_be(d, *at)?)
    } else {
        u32_be(d, *at)?
    };
    *at = at.checked_add(if s.version < 2 { 2 } else { 4 })?;
    let mut method = 0;
    if s.version >= 1 {
        method = u16_be(d, *at)? & 15;
        *at = at.checked_add(2)?;
    }
    *at = at.checked_add(2)?; // data reference index
    let base = sized(d, at, s.base_size)?;
    let n = u16_be(d, *at)?;
    *at = at.checked_add(2)?;
    let mut extents = Vec::new();
    for _ in 0..n {
        sized(d, at, s.index_size)?;
        let offset = sized(d, at, s.offset_size)?;
        let length = sized(d, at, s.length_size)?;
        extents.push(Extent { offset, length });
    }
    Some(ItemLoc {
        id,
        method,
        base,
        extents,
        span: region.sub(to_u64(start), to_u64(at.saturating_sub(start))),
    })
}

async fn iloc_items(cx: Cx, s: Iloc) -> Result<()> {
    let region = s.body.tail(s.start);
    let d = crate::formats::util::vidutil::read_small(&cx, region, 0x100000).await?;
    cx.set_count(Count::Exact(s.count.into()));
    let mut at = 0usize;
    for _ in 0..s.count {
        let Some(item) = parse_item(&d, &mut at, &s, region) else {
            cx.diag(Diagnostic::malformed("item location list ends early").at(region));
            break;
        };
        let kind = s
            .types
            .iter()
            .find(|(id, _)| *id == item.id)
            .map(|(_, t)| *t);
        let total: u64 = item
            .extents
            .iter()
            .fold(0u64, |acc, e| acc.saturating_add(e.length));
        let mut summary = format!(
            "{}{} extent(s), {total} bytes",
            kind.map(|k| format!("{}, ", fourcc(&k)))
                .unwrap_or_default(),
            item.extents.len()
        );
        if item.method == 1 {
            summary.push_str(" in idat");
        }
        cx.push(
            Node::new(format!("Item {}", item.id))
                .span(item.span)
                .summary(summary)
                .lazy(item_node, (s.clone(), item, kind)),
        )
        .await;
    }
    Ok(())
}

async fn item_node(cx: Cx, (s, item, kind): (Iloc, ItemLoc, Option<[u8; 4]>)) -> Result<()> {
    let span = item.span;
    let wide = s.version >= 2;
    let mut pos = if wide { 4 } else { 2 };
    cx.emit(uint("Item ID", span.sub(0, pos), item.id.into(), 32));
    if s.version >= 1 {
        cx.emit(
            uint(
                "Construction method",
                span.sub(pos, 2),
                item.method.into(),
                16,
            )
            .summary(match item.method {
                0 => "file offset",
                1 => "idat offset",
                2 => "item offset",
                _ => "unknown",
            }),
        );
        pos = pos.saturating_add(2);
    }
    pos = pos.saturating_add(2);
    if s.base_size > 0 {
        cx.emit(hex(
            "Base offset",
            span.sub(pos, s.base_size.into()),
            item.base,
            64,
        ));
    }
    // Where offsets are relative to.
    let origin = match item.method {
        0 => Some(s.input.span),
        1 => find_child(&cx, s.meta, b"idat")
            .await?
            .map(|(h, b)| b.tail(h.header_len)),
        _ => None,
    };
    let mut spans = Vec::new();
    for (i, e) in item.extents.iter().enumerate() {
        let name = format!("Extent {}", i.saturating_add(1));
        let mut node = Node::new(name).summary(format!("{} bytes at {:#x}", e.length, e.offset));
        if let Some(origin) = origin {
            let at = item.base.saturating_add(e.offset);
            let len = if e.length == 0 {
                origin.len.saturating_sub(at)
            } else {
                e.length
            };
            let target = origin.sub(at, len);
            spans.push(target);
            node = node.target(target);
        }
        cx.emit(node);
    }
    if let [data] = spans.as_slice() {
        let data = *data;
        let size = format!("{} bytes", data.len);
        let node = match kind.as_ref() {
            Some(b"Exif") => {
                // A 4-byte offset to the TIFF header precedes the payload.
                let skip = cx.read_avail(data.sub(0, 4)).await?;
                let skip = u32_be(&skip, 0).unwrap_or(0);
                embedded(
                    "Exif",
                    s.input.nested(data.tail(4u64.saturating_add(skip.into()))),
                )
                .summary(size)
            }
            Some(b"mime") | Some(b"jpeg") | Some(b"j2k1") | Some(b"uri ") => {
                embedded("Data", s.input.nested(data)).summary(size)
            }
            Some(b"grid") => {
                let d = cx.read_avail(data.sub(0, 12)).await?;
                let mut node = struct_node("Image grid", data, BE, (), grid_layout);
                if let Some(g) = grid_summary(&d) {
                    node = node.summary(g);
                }
                node
            }
            Some(b"iovl") => {
                struct_node("Image overlay", data, BE, (), overlay_layout).summary(size)
            }
            Some(b"av01") => Node::new("AV1 data")
                .span(data)
                .summary(size)
                .lazy(item_obus, data),
            Some(b"hvc1") | Some(b"avc1") | Some(b"hvt1") => {
                let hevc = kind.as_ref() != Some(b"avc1");
                Node::new(if hevc { "HEVC data" } else { "H.264 data" })
                    .span(data)
                    .summary(size)
                    .lazy(item_nals, (data, hevc))
            }
            _ => Node::new("Data").span(data).summary(size),
        };
        cx.emit(node);
    } else if spans.len() > 1 {
        cx.emit(Node::new("Data").summary("item data is split across extents"));
    }
    Ok(())
}

fn grid_summary(d: &[u8]) -> Option<String> {
    let flags = *d.get(1)?;
    let rows = u32::from(*d.get(2)?).saturating_add(1);
    let cols = u32::from(*d.get(3)?).saturating_add(1);
    let (w, h) = if flags & 1 != 0 {
        (u32_be(d, 4)?, u32_be(d, 8)?)
    } else {
        (u16_be(d, 4)?.into(), u16_be(d, 6)?.into())
    };
    Some(format!("{cols}×{rows} tiles, output {w}×{h}"))
}

fn grid_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Version").emit()?;
    let flags = f
        .u8("Flags")
        .hex()
        .with(|&v, n| {
            n.summary(if v & 1 != 0 {
                "32-bit sizes"
            } else {
                "16-bit sizes"
            })
        })
        .emit()?;
    f.u8("Rows minus one")
        .with(|&v, n| n.summary(format!("{} rows", u16::from(v).saturating_add(1))))
        .emit()?;
    f.u8("Columns minus one")
        .with(|&v, n| n.summary(format!("{} columns", u16::from(v).saturating_add(1))))
        .emit()?;
    if flags & 1 != 0 {
        f.u32("Output width").emit()?;
        f.u32("Output height").emit()?;
    } else {
        f.u16("Output width").emit()?;
        f.u16("Output height").emit()?;
    }
    Ok(())
}

fn overlay_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Version").emit()?;
    let flags = f.u8("Flags").hex().emit()?;
    let wide = flags & 1 != 0;
    for name in ["Fill red", "Fill green", "Fill blue", "Fill alpha"] {
        f.u16(name).emit()?;
    }
    f.uword("Output width", wide).emit()?;
    f.uword("Output height", wide).emit()?;
    let entry = if wide { 8 } else { 4 };
    while f.remaining() >= entry {
        if wide {
            f.i32("Horizontal offset").emit()?;
            f.i32("Vertical offset").emit()?;
        } else {
            f.int::<i16>("Horizontal offset").emit()?;
            f.int::<i16>("Vertical offset").emit()?;
        }
    }
    Ok(())
}

async fn item_obus(cx: Cx, span: Span) -> Result<()> {
    super::codec::obus(&cx, span).await
}

/// Lists the length-prefixed NAL units of an HEVC/H.264 image item,
/// decoding parameter sets and SEI messages.
async fn item_nals(cx: Cx, (span, hevc): (Span, bool)) -> Result<()> {
    let codec = if hevc { NalCodec::Hevc } else { NalCodec::Avc };
    let mut ps = ParamSets::default();
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos.saturating_add(4) <= span.len {
        let head = cx.read_avail(span.sub(pos, 6)).await?;
        let len = u64::from(u32_be(&head, 0).unwrap_or(0));
        let unit = span.sub(pos, len.saturating_add(4));
        let (name, kind) = if hevc {
            let t = head.get(4).map_or(0, |b| (b >> 1) & 0x3f);
            (lookup_or(HEVC_NAL_TYPES, t.into()), t)
        } else {
            let t = head.get(4).map_or(0, |b| b & 0x1f);
            (lookup_or(H264_NAL_TYPES, t.into()), t)
        };
        let mut node = Node::new(format!("NAL unit {}", index.saturating_add(1)))
            .span(unit)
            .summary(format!("{name}, {len} bytes"));
        let parameters = if hevc {
            matches!(kind, 32..=34 | 39 | 40)
        } else {
            matches!(kind, 6..=8)
        };
        if parameters && len > 0 && len < 0x1000 {
            let body = unit.tail(4);
            let nal = cx.read_avail(body).await?;
            let (info, nodes) = parse_nal(codec, &nal, body.sub(0, to_u64(nal.len())), &ps, true);
            ps.update(info.sps.as_ref(), info.pps.as_ref());
            node = group(format!("NAL unit {}", index.saturating_add(1)), unit, nodes).summary(
                match &info.summary {
                    Some(s) => format!("{s}, {len} bytes"),
                    None => format!("{name}, {len} bytes"),
                },
            );
        }
        cx.push(node).await;
        if len == 0 {
            break;
        }
        pos = pos.saturating_add(len).saturating_add(4);
        index = index.saturating_add(1);
    }
    if pos < span.len {
        cx.emit(Node::new("Trailing bytes").span(span.tail(pos)));
    }
    Ok(())
}

/// The boxes in `ipco` (property index − 1 → type and body).
async fn property_kinds(cx: &Cx, iprp: Span) -> Result<Vec<([u8; 4], Span)>> {
    let mut out = Vec::new();
    let Some((h, span)) = find_child(cx, iprp, b"ipco").await? else {
        return Ok(out);
    };
    let ipco = span.tail(h.header_len);
    let mut pos = 0u64;
    while let Ok(Some(h)) = super::read_header(cx, ipco, pos).await {
        out.push((h.kind, ipco.sub(pos, h.size).tail(h.header_len)));
        pos = pos.saturating_add(h.size);
        if out.len() >= 4096 || h.to_end {
            break;
        }
    }
    Ok(out)
}

async fn ipma(cx: &Cx, body: Span, iprp: Span) -> Result<()> {
    let kinds = property_kinds(cx, iprp).await.unwrap_or_default();
    let block = cx.block(body.sub(0, 0x100000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let (v, flags) = full_box(&mut f)?;
    let n = f.u32("Entry count").emit()?;
    for i in 0..n {
        if f.remaining() == 0 {
            break;
        }
        if i & 0xff == 0xff {
            cx.checkpoint().await;
        }
        let start = f.pos();
        let mut silent = Fields::new(&block, BE);
        silent.seek(start);
        let id = item_id(&mut silent, v < 1, "Item ID")?;
        let count = silent.u8("Association count").get()?;
        let mut parts = Vec::new();
        for _ in 0..count {
            let (essential, index) = if flags & 1 != 0 {
                let a = silent.u16("Association").get()?;
                (a >> 15 == 1, a & 0x7fff)
            } else {
                let a = silent.u8("Association").get()?;
                (a >> 7 == 1, u16::from(a & 0x7f))
            };
            let name = usize::from(index)
                .checked_sub(1)
                .and_then(|i| kinds.get(i))
                .map_or_else(|| format!("#{index}"), |(k, _)| fourcc(k));
            parts.push(format!("{name}{}", if essential { "*" } else { "" }));
        }
        let len = silent.pos().saturating_sub(start);
        let span = body.sub(start, len);
        f.node(
            struct_node(
                format!("Item {id}"),
                span,
                BE,
                (v < 1, flags & 1 != 0),
                association_layout,
            )
            .summary(parts.join(", "))
            .desc("Properties by type, in ipco order; * marks essential ones"),
        );
        f.skip(len);
    }
    Ok(())
}

fn association_layout(f: &mut Fields<'_>, &(narrow, wide): &(bool, bool)) -> Result<()> {
    item_id(f, narrow, "Item ID")?;
    let n = f.u8("Association count").emit()?;
    for _ in 0..n {
        let span = f.peek_span(if wide { 2 } else { 1 });
        let (essential, index) = if wide {
            let a = f.u16("Association").get()?;
            (a >> 15 == 1, a & 0x7fff)
        } else {
            let a = f.u8("Association").get()?;
            (a >> 7 == 1, u16::from(a & 0x7f))
        };
        f.node(
            uint(
                "Property index",
                span,
                index.into(),
                if wide { 15 } else { 7 },
            )
            .summary(if essential { "essential" } else { "optional" }),
        );
    }
    Ok(())
}

/// Summaries for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    if &st.ctx.parent == b"iref" {
        let at = Span::new(
            st.ctx.siblings.source,
            st.ctx.siblings.offset.saturating_sub(4),
            1,
        );
        let narrow = cx.read_avail(at).await.ok()?.first().copied().unwrap_or(0) == 0;
        let d = small(cx, st.body().sub(0, 512)).await.ok()?;
        let w = if narrow { 2usize } else { 4 };
        let id = |at: usize| {
            if narrow {
                u16_be(&d, at).map(u32::from)
            } else {
                u32_be(&d, at)
            }
        };
        let from = id(0)?;
        let n = u16_be(&d, w)?;
        let to: Vec<String> = (0..usize::from(n).min(64))
            .filter_map(|i| id(w.saturating_add(2).saturating_add(i.saturating_mul(w))))
            .map(|v| v.to_string())
            .collect();
        let what = reference_name(kind).unwrap_or("references");
        return Some(format!("item {from} {what} {}", to.join(", ")));
    }
    if !matches!(
        kind,
        b"pitm"
            | b"iinf"
            | b"infe"
            | b"iloc"
            | b"ipma"
            | b"ispe"
            | b"irot"
            | b"imir"
            | b"pixi"
            | b"auxC"
            | b"rloc"
            | b"lsel"
            | b"a1op"
    ) {
        return None;
    }
    let d = small(cx, st.body().sub(0, 128)).await.ok()?;
    let v = d.first().copied()?;
    let id = |at: usize, narrow: bool| {
        if narrow {
            u16_be(&d, at).map(u32::from)
        } else {
            u32_be(&d, at)
        }
    };
    match kind {
        b"pitm" => Some(format!("primary item {}", id(4, v == 0)?)),
        b"iinf" => Some(plural(id(4, v == 0)?, "item")),
        b"infe" if v >= 2 => {
            let item = id(4, v == 2)?;
            let at: usize = if v == 2 { 8 } else { 10 };
            let t = d.get(at..at.saturating_add(4))?;
            let name = crate::text::until_nul(d.get(at.saturating_add(4)..)?);
            let mut s = format!("item {item}: {}", fourcc(t));
            if let Some(n) = item_type_name(t) {
                s = format!("{s} ({n})");
            }
            if !name.is_empty() {
                s = format!("{s} \"{name}\"");
            }
            if u32_be(&d, 0).is_some_and(|f| f & 1 != 0) {
                s.push_str(", hidden");
            }
            Some(s)
        }
        b"iloc" => Some(plural(id(6, v < 2)?, "item")),
        b"ipma" => Some(plural(u32_be(&d, 4)?, "item")),
        b"ispe" => Some(format!("{}×{}", u32_be(&d, 4)?, u32_be(&d, 8)?)),
        b"irot" => Some(if v & 3 == 0 {
            "no rotation".to_owned()
        } else {
            format!("{}° anti-clockwise", u16::from(v & 3).saturating_mul(90))
        }),
        b"imir" => Some(mirror_name(v).to_owned()),
        b"pixi" => {
            let n = usize::from(*d.get(4)?);
            let bits: Vec<String> = d
                .get(5..5usize.saturating_add(n))?
                .iter()
                .map(u8::to_string)
                .collect();
            Some(format!(
                "{n} channel{}, {} bits",
                if n == 1 { "" } else { "s" },
                bits.join("/")
            ))
        }
        b"auxC" => {
            let urn = crate::text::until_nul(d.get(4..)?);
            Some(match aux_name(&urn) {
                Some(n) => n.to_owned(),
                None => urn,
            })
        }
        b"rloc" => Some(format!("at {}, {}", u32_be(&d, 4)?, u32_be(&d, 8)?)),
        b"lsel" => Some(format!("layer {}", u16_be(&d, 0)?)),
        b"a1op" => Some(format!("operating point {v}")),
        _ => None,
    }
}

/// Item references in `iref`: (type, from, to).
async fn references(cx: &Cx, meta: Span) -> Result<Vec<([u8; 4], u32, Vec<u32>)>> {
    let mut out = Vec::new();
    let Some((h, span)) = find_child(cx, meta, b"iref").await? else {
        return Ok(out);
    };
    let d = small(cx, span.tail(h.header_len)).await?;
    let narrow = d.first().copied().unwrap_or(0) == 0;
    let w = if narrow { 2usize } else { 4 };
    let id = |at: usize| {
        if narrow {
            u16_be(&d, at).map(u32::from)
        } else {
            u32_be(&d, at)
        }
    };
    let mut at = 4usize;
    while out.len() < 4096 {
        let Some(size) = u32_be(&d, at).and_then(|s| usize::try_from(s).ok()) else {
            break;
        };
        if size < 8 {
            break;
        }
        let Some(kind) = crate::bytes::array::<4>(&d, at.saturating_add(4)) else {
            break;
        };
        let body = at.saturating_add(8);
        let Some(from) = id(body) else { break };
        let n = u16_be(&d, body.saturating_add(w)).unwrap_or(0);
        let first = body.saturating_add(w).saturating_add(2);
        let to = (0..usize::from(n))
            .map_while(|i| id(first.saturating_add(i.saturating_mul(w))))
            .collect();
        out.push((kind, from, to));
        at = at.saturating_add(size);
    }
    Ok(out)
}

/// The properties associated with `item`: (type, body), via ipma and ipco.
async fn item_properties(cx: &Cx, meta: Span, item: u32) -> Result<Vec<([u8; 4], Span)>> {
    let Some(iprp) = super::find_path(cx, meta, &[b"iprp"]).await? else {
        return Ok(Vec::new());
    };
    let Some((h, span)) = find_child(cx, iprp, b"ipma").await? else {
        return Ok(Vec::new());
    };
    let d = small(cx, span.tail(h.header_len)).await?;
    let v = d.first().copied().unwrap_or(0);
    let wide_index = u32_be(&d, 0).unwrap_or(0) & 1 != 0;
    let n = u32_be(&d, 4).unwrap_or(0);
    let mut at = 8usize;
    let mut indices = Vec::new();
    for _ in 0..n.min(4096) {
        let id = if v < 1 {
            u16_be(&d, at).map(u32::from)
        } else {
            u32_be(&d, at)
        };
        let Some(id) = id else { break };
        at = at.saturating_add(if v < 1 { 2 } else { 4 });
        let count = d.get(at).copied().unwrap_or(0);
        at = at.saturating_add(1);
        for _ in 0..count {
            let index = if wide_index {
                u16_be(&d, at).map(|a| a & 0x7fff)
            } else {
                d.get(at).map(|a| u16::from(a & 0x7f))
            };
            at = at.saturating_add(if wide_index { 2 } else { 1 });
            if id == item
                && let Some(i) = index
            {
                indices.push(i);
            }
        }
        if id == item {
            break;
        }
    }
    let kinds = property_kinds(cx, iprp).await?;
    Ok(indices
        .iter()
        .filter_map(|&i| kinds.get(usize::from(i).checked_sub(1)?).copied())
        .collect())
}

/// The name of an image item type for summaries.
fn codec_of(kind: &[u8; 4]) -> String {
    match kind {
        b"hvc1" => "HEVC".to_owned(),
        b"av01" => "AV1".to_owned(),
        b"avc1" | b"avc3" => "H.264".to_owned(),
        b"jpeg" => "JPEG".to_owned(),
        b"j2k1" => "JPEG 2000".to_owned(),
        b"vvc1" => "VVC".to_owned(),
        b"unci" => "uncompressed".to_owned(),
        _ => fourcc(kind),
    }
}

/// What the file node says about a HEIF/AVIF `meta` box: the primary
/// image's size, codec and layout, what is attached to it, the item count.
pub async fn summary(cx: &Cx, meta: Span) -> Result<Option<String>> {
    let types = item_types(cx, meta).await?;
    let type_of = |id: u32| types.iter().find(|(i, _)| *i == id).map(|(_, t)| *t);
    let primary = match find_child(cx, meta, b"pitm").await? {
        Some((h, span)) => {
            let d = cx.read_avail(span.tail(h.header_len).sub(0, 8)).await?;
            if d.first().copied().unwrap_or(0) == 0 {
                u16_be(&d, 4).map(u32::from)
            } else {
                u32_be(&d, 4)
            }
        }
        None => None,
    };
    let refs = references(cx, meta).await?;
    let mut parts = Vec::new();
    if let Some(p) = primary {
        let props = item_properties(cx, meta, p).await?;
        let mut size = None;
        for (k, body) in &props {
            if k == b"ispe" {
                let d = cx.read_avail(body.sub(0, 12)).await?;
                size = u32_be(&d, 4).zip(u32_be(&d, 8));
            }
        }
        let codec = match type_of(p) {
            Some(k) if &k == b"grid" || &k == b"iovl" || &k == b"iden" => {
                let tiles: Vec<u32> = refs
                    .iter()
                    .filter(|(t, from, _)| t == b"dimg" && *from == p)
                    .flat_map(|(_, _, to)| to.iter().copied())
                    .collect();
                let base = tiles
                    .first()
                    .and_then(|&t| type_of(t))
                    .map_or_else(|| "?".to_owned(), |t| codec_of(&t));
                let n = crate::bytes::to_u64(tiles.len());
                match &k {
                    b"grid" => format!("{base} grid of {}", plural(n, "tile")),
                    b"iovl" => format!("{base} overlay of {}", plural(n, "image")),
                    _ => format!("{base} (derived)"),
                }
            }
            Some(k) => codec_of(&k),
            None => "?".to_owned(),
        };
        parts.push(match size {
            Some((w, h)) => format!("{w}×{h} {codec}"),
            None => codec,
        });
        for (k, body) in &props {
            let d = cx.read_avail(body.sub(0, 1)).await?;
            let v = d.first().copied().unwrap_or(0);
            match k {
                b"irot" if v & 3 != 0 => parts.push(format!(
                    "rotated {}° anti-clockwise",
                    u16::from(v & 3).saturating_mul(90)
                )),
                b"imir" => parts.push(if v & 1 == 0 {
                    "flipped vertically".to_owned()
                } else {
                    "flipped horizontally".to_owned()
                }),
                _ => {}
            }
        }
        // Attached items: auxiliary images, metadata, thumbnails.
        for (t, from, to) in &refs {
            if !to.contains(&p) {
                continue;
            }
            let label = match t {
                b"auxl" => {
                    let mut name = "auxiliary image".to_owned();
                    for (k, body) in item_properties(cx, meta, *from).await? {
                        if &k == b"auxC" {
                            let d = small(cx, body.sub(0, 256)).await?;
                            let urn = crate::text::until_nul(d.get(4..).unwrap_or_default());
                            if let Some(n) = aux_name(&urn) {
                                name = n.to_owned();
                            }
                        }
                    }
                    name
                }
                b"thmb" => "thumbnail".to_owned(),
                b"cdsc" => match type_of(*from) {
                    Some(k) if &k == b"Exif" => "Exif".to_owned(),
                    Some(k) if &k == b"mime" => "XMP".to_owned(),
                    Some(k) => fourcc(&k),
                    None => continue,
                },
                _ => continue,
            };
            if !parts.contains(&label) {
                parts.push(label);
            }
        }
    }
    parts.push(plural(crate::bytes::to_u64(types.len()), "item"));
    Ok(Some(parts.join(", ")))
}
