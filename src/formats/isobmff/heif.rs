//! HEIF item boxes (ISO 23008-12): `pitm`, `iinf`/`infe`, `iloc`, `iref`,
//! `ipma` and the image properties in `ipco` (`ispe`, `pixi`, `irot`, ...).
//! Item data located by `iloc` is offered for embedded dissection.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::vidutil::{fourcc, hex, uint};
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
            children(cx, st.input, rest, ctx.child_of(*b"iinf", rest)).await?;
        }
        b"infe" => emit_fields(cx, body, infe).await?,
        b"iloc" => iloc(cx, st).await?,
        b"ipma" => ipma(cx, body).await?,
        b"iref" => {
            emit_fields(cx, body.sub(0, 4), |f| full_box(f).map(|_| ())).await?;
            let rest = body.tail(4);
            children(cx, st.input, rest, ctx.child_of(*b"iref", rest)).await?;
        }
        _ if &ctx.parent == b"iref" => {
            // The iref version decides the width of item IDs; it sits just
            // before the children region.
            let at = Span::new(ctx.siblings.source, ctx.siblings.offset.saturating_sub(4), 1);
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
                    .with(|&a, n| n.summary(format!("{}° anti-clockwise", u16::from(a & 3).saturating_mul(90))))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"imir" => {
            emit_fields(cx, body, |f| {
                f.u8("Axis")
                    .with(|&a, n| n.summary(if a & 1 == 0 { "vertical" } else { "horizontal" }))
                    .emit()?;
                Ok(())
            })
            .await?;
        }
        b"auxC" => {
            emit_fields(cx, body, |f| {
                full_box(f)?;
                f.cstr("Auxiliary type").emit()?;
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

fn item_id(f: &mut Fields<'_>, narrow: bool, name: &'static str) -> Result<u32> {
    if narrow {
        f.u16(name).emit().map(u32::from)
    } else {
        f.u32(name).emit()
    }
}

fn infe(f: &mut Fields<'_>) -> Result<()> {
    let (v, _) = full_box(f)?;
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
            .summary(format!("{count} items"))
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
    let d = crate::formats::vidutil::read_small(&cx, region, 0x100000).await?;
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
            kind.map(|k| format!("{}, ", fourcc(&k))).unwrap_or_default(),
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
        cx.emit(uint("Construction method", span.sub(pos, 2), item.method.into(), 16).summary(
            match item.method {
                0 => "file offset",
                1 => "idat offset",
                2 => "item offset",
                _ => "unknown",
            },
        ));
        pos = pos.saturating_add(2);
    }
    pos = pos.saturating_add(2);
    if s.base_size > 0 {
        cx.emit(hex("Base offset", span.sub(pos, s.base_size.into()), item.base, 64));
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
        let node = match kind.as_ref() {
            Some(b"Exif") => {
                // A 4-byte offset to the TIFF header precedes the payload.
                let skip = cx.read_avail(data.sub(0, 4)).await?;
                let skip = u32_be(&skip, 0).unwrap_or(0);
                embedded("Exif", s.input.nested(data.tail(4u64.saturating_add(skip.into()))))
            }
            Some(b"mime") | Some(b"jpeg") | Some(b"j2k1") | Some(b"uri ") => {
                embedded("Data", s.input.nested(data))
            }
            _ => Node::new("Data").span(data),
        };
        cx.emit(node.summary(format!("{} bytes", data.len)));
    } else if spans.len() > 1 {
        cx.emit(Node::new("Data").summary("item data is split across extents"));
    }
    Ok(())
}

async fn ipma(cx: &Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 0x100000)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    let (v, flags) = full_box(&mut f)?;
    let n = f.u32("Entry count").emit()?;
    let mut silent = Fields::new(&block, BE);
    for _ in 0..n {
        if f.remaining() == 0 {
            break;
        }
        let start = f.pos();
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
            parts.push(format!("{index}{}", if essential { "*" } else { "" }));
        }
        let len = silent.pos().saturating_sub(start);
        f.skip(len);
        let span = body.sub(start, len);
        cx.emit(
            Node::new(format!("Item {id}"))
                .span(span)
                .summary(format!("properties {}", parts.join(", ")))
                .desc("Property indices are 1-based positions in ipco; * marks essential"),
        );
    }
    Ok(())
}

/// Summaries for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    if !matches!(
        kind,
        b"pitm" | b"iinf" | b"infe" | b"iloc" | b"ipma" | b"ispe" | b"irot" | b"pixi" | b"auxC"
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
        b"pitm" => Some(format!("item {}", id(4, v == 0)?)),
        b"iinf" => Some(format!("{} items", id(4, v == 0)?)),
        b"infe" if v >= 2 => {
            let item = id(4, v == 2)?;
            let at: usize = if v == 2 { 8 } else { 10 };
            let t = d.get(at..at.saturating_add(4))?;
            let name = crate::text::until_nul(d.get(at.saturating_add(4)..)?);
            Some(if name.is_empty() {
                format!("item {item}: {}", fourcc(t))
            } else {
                format!("item {item}: {} \"{name}\"", fourcc(t))
            })
        }
        b"iloc" => Some(format!("{} items", id(6, v < 2)?)),
        b"ipma" => Some(format!("{} items", u32_be(&d, 4)?)),
        b"ispe" => Some(format!("{}×{}", u32_be(&d, 4)?, u32_be(&d, 8)?)),
        b"irot" => Some(format!("{}°", u16::from(v & 3).saturating_mul(90))),
        b"pixi" => Some(format!(
            "{} channels, {} bits",
            d.get(4)?,
            d.get(5)?
        )),
        b"auxC" => Some(crate::text::until_nul(d.get(4..)?)),
        _ => None,
    }
}

/// What the file node says about a HEIF/AVIF `meta` box: item count and
/// the primary image's type and size.
pub async fn summary(cx: &Cx, meta: Span) -> Result<Option<String>> {
    let types = item_types(cx, meta).await?;
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
    let mut parts = vec![format!("{} items", types.len())];
    if let Some(p) = primary {
        let kind = types
            .iter()
            .find(|(id, _)| *id == p)
            .map_or_else(|| "?".to_owned(), |(_, t)| fourcc(t));
        let mut s = format!("primary {kind}");
        if let Some((w, h)) = primary_size(cx, meta, p).await? {
            s = format!("{s} {w}×{h}");
        }
        parts.push(s);
    }
    Ok(Some(parts.join(", ")))
}

/// The `ispe` property associated with `item`, via `ipma` and `ipco`.
async fn primary_size(cx: &Cx, meta: Span, item: u32) -> Result<Option<(u32, u32)>> {
    let Some(iprp) = super::find_path(cx, meta, &[b"iprp"]).await? else {
        return Ok(None);
    };
    let Some((h, span)) = find_child(cx, iprp, b"ipma").await? else {
        return Ok(None);
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
    let Some(ipco) = super::find_path(cx, iprp, &[b"ipco"]).await? else {
        return Ok(None);
    };
    // Walk ipco children, matching 1-based indices.
    let mut pos = 0u64;
    let mut index = 1u16;
    while let Some(h) = super::read_header(cx, ipco, pos).await? {
        if &h.kind == b"ispe" && indices.contains(&index) {
            let d = cx.read_avail(ipco.sub(pos.saturating_add(h.header_len), 12)).await?;
            return Ok(u32_be(&d, 4).zip(u32_be(&d, 8)));
        }
        pos = pos.saturating_add(h.size);
        index = index.saturating_add(1);
        if index > 1024 {
            break;
        }
    }
    Ok(None)
}
