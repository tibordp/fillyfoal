//! GIMP XCF.
//!
//! `gimp xcf <version>\0`, canvas size and base type, (from version 4) the
//! precision, a property list, then zero-terminated lists of layer and
//! channel pointers (64-bit from version 11). Layers have their own size,
//! type, name and properties, and point at tile hierarchies.

use crate::bytes::{u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{dims, hex, text};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "xcf",
    title: "GIMP image",
    extensions: &["xcf"],
    mime: "image/x-xcf",
    probe: Probe::Magic(&[(0, b"gimp xcf ")]),
    dissect: crate::expander!(dissect: Input),
};

const BASE_TYPES: EnumTable = &[(0, "RGB"), (1, "Grayscale"), (2, "Indexed")];

const LAYER_TYPES: EnumTable = &[
    (0, "RGB"),
    (1, "RGBA"),
    (2, "Grayscale"),
    (3, "Grayscale + alpha"),
    (4, "Indexed"),
    (5, "Indexed + alpha"),
];

const PRECISION: EnumTable = &[
    (100, "8-bit linear integer"),
    (150, "8-bit gamma integer"),
    (200, "16-bit linear integer"),
    (250, "16-bit gamma integer"),
    (300, "32-bit linear integer"),
    (350, "32-bit gamma integer"),
    (500, "16-bit linear float"),
    (550, "16-bit gamma float"),
    (600, "32-bit linear float"),
    (650, "32-bit gamma float"),
    (700, "64-bit linear float"),
    (750, "64-bit gamma float"),
];

const PROPERTIES: EnumTable = &[
    (0, "PROP_END"),
    (1, "PROP_COLORMAP"),
    (2, "PROP_ACTIVE_LAYER"),
    (3, "PROP_ACTIVE_CHANNEL"),
    (4, "PROP_SELECTION"),
    (5, "PROP_FLOATING_SELECTION"),
    (6, "PROP_OPACITY"),
    (7, "PROP_MODE"),
    (8, "PROP_VISIBLE"),
    (9, "PROP_LINKED"),
    (10, "PROP_LOCK_ALPHA"),
    (11, "PROP_APPLY_MASK"),
    (12, "PROP_EDIT_MASK"),
    (13, "PROP_SHOW_MASK"),
    (14, "PROP_SHOW_MASKED"),
    (15, "PROP_OFFSETS"),
    (16, "PROP_COLOR"),
    (17, "PROP_COMPRESSION"),
    (18, "PROP_GUIDES"),
    (19, "PROP_RESOLUTION"),
    (20, "PROP_TATTOO"),
    (21, "PROP_PARASITES"),
    (22, "PROP_UNIT"),
    (23, "PROP_PATHS"),
    (24, "PROP_USER_UNIT"),
    (25, "PROP_VECTORS"),
    (26, "PROP_TEXT_LAYER_FLAGS"),
    (27, "PROP_OLD_SAMPLE_POINTS"),
    (28, "PROP_LOCK_CONTENT"),
    (29, "PROP_GROUP_ITEM"),
    (30, "PROP_ITEM_PATH"),
    (31, "PROP_GROUP_ITEM_FLAGS"),
    (32, "PROP_LOCK_POSITION"),
    (33, "PROP_FLOAT_OPACITY"),
    (34, "PROP_COLOR_TAG"),
    (35, "PROP_COMPOSITE_MODE"),
    (36, "PROP_COMPOSITE_SPACE"),
    (37, "PROP_BLEND_SPACE"),
    (38, "PROP_FLOAT_COLOR"),
    (39, "PROP_SAMPLE_POINTS"),
    (40, "PROP_ITEM_SET"),
    (41, "PROP_ITEM_SET_ITEM"),
    (42, "PROP_LOCK_VISIBILITY"),
    (43, "PROP_SELECTED_PATH"),
    (44, "PROP_FILTER_REGION"),
    (45, "PROP_FILTER_ARGUMENT"),
    (46, "PROP_FILTER_CLIP"),
];

const COMPRESSION: EnumTable = &[(0, "None"), (1, "RLE"), (2, "zlib"), (3, "Fractal")];

/// The version number from `file` (0) or `vNNN`.
fn version(tag: &[u8]) -> u32 {
    if tag == b"file" {
        return 0;
    }
    std::str::from_utf8(tag.get(1..).unwrap_or_default())
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(0)
}

/// Upper bound on properties and pointers in one list.
const MAX_ITEMS: usize = 100_000;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 14)).await?;
    let v = version(head.get(9..13).unwrap_or_default());
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 14))
            .value(text(crate::text::until_nul(&head)))
            .summary(format!("version {v}")),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(14);
    let fixed = cur.span(if v >= 4 { 16 } else { 12 });
    let block = cx.block(fixed).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    let width = f.u32("Width").emit()?;
    let height = f.u32("Height").emit()?;
    let base = f.u32("Base type").enumeration(BASE_TYPES).emit()?;
    let precision = if v >= 4 {
        Some(f.u32("Precision").enumeration(PRECISION).emit()?)
    } else {
        None
    };
    cur.skip(fixed.len);
    let mut summary = format!(
        "{}, {}",
        dims(width, height),
        lookup(BASE_TYPES, base.into()).unwrap_or("unknown base type")
    );
    if let Some(p) = precision.and_then(|p| lookup(PRECISION, p.into())) {
        summary = format!("{summary}, {p}");
    }

    let props_start = cur.pos();
    skip_properties(&mut cur).await?;
    let props = cur.since(props_start);
    cx.emit(
        Node::new("Image properties")
            .span(props)
            .lazy(properties, props),
    );

    let wide = v >= 11;
    let (layers, layer_ptrs) = pointers(&mut cur, wide).await?;
    let (channels, channel_ptrs) = pointers(&mut cur, wide).await?;
    cx.annotate(format!("{summary}, {} layers", layer_ptrs.len()));
    cx.emit(
        Node::new("Layers")
            .span(layers)
            .summary(format!("{} layers", layer_ptrs.len()))
            .lazy(list_layers, (file, layers, wide)),
    );
    cx.emit(
        Node::new("Channels")
            .span(channels)
            .summary(format!("{} channels", channel_ptrs.len())),
    );
    Ok(())
}

/// Walks a property list up to and including `PROP_END`.
async fn skip_properties(cur: &mut Cursor<'_>) -> Result<()> {
    for _ in 0..MAX_ITEMS {
        let kind = cur.u32().await?;
        let len = cur.u32().await?;
        cur.skip(len.into());
        if kind == 0 {
            return Ok(());
        }
    }
    Err(Diagnostic::limit("too many properties"))
}

/// A zero-terminated pointer list: its span and the pointers.
async fn pointers(cur: &mut Cursor<'_>, wide: bool) -> Result<(Span, Vec<u64>)> {
    let start = cur.pos();
    let mut out = Vec::new();
    for _ in 0..MAX_ITEMS {
        let p = if wide {
            cur.u64().await?
        } else {
            cur.u32().await?.into()
        };
        if p == 0 {
            return Ok((cur.since(start), out));
        }
        out.push(p);
    }
    Err(Diagnostic::limit("too many pointers"))
}

async fn properties(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while !cur.at_end() {
        let start = cur.pos();
        let kind = cur.u32().await?;
        let len = cur.u32().await?;
        let payload = cur.span(len.into());
        cur.skip(len.into());
        let name = lookup(PROPERTIES, kind.into())
            .map_or_else(|| format!("Property {kind}"), str::to_owned);
        let data = cx.read_avail(payload.sub(0, 16)).await?;
        let summary = match (kind, len) {
            (17, 1) => data
                .first()
                .and_then(|&c| lookup(COMPRESSION, c.into()))
                .map(str::to_owned),
            (19, 8) => {
                let x = crate::bytes::array::<4>(&data, 0).map(f32::from_be_bytes);
                let y = crate::bytes::array::<4>(&data, 4).map(f32::from_be_bytes);
                x.zip(y).map(|(x, y)| format!("{x} × {y} dpi"))
            }
            (6 | 8 | 15 | 20 | 22, _) => {
                let a = u32_be(&data, 0);
                let b = u32_be(&data, 4).filter(|_| len >= 8);
                a.map(|a| match b {
                    Some(b) => format!("{a}, {b}"),
                    None => a.to_string(),
                })
            }
            (1, _) => u32_be(&data, 0).map(|n| format!("{n} colors")),
            _ => None,
        };
        let summary = summary.unwrap_or_else(|| format!("{len} bytes"));
        cx.push(Node::new(name).span(cur.since(start)).summary(summary))
            .await;
        if kind == 0 {
            break;
        }
    }
    Ok(())
}

async fn list_layers(cx: Cx, (file, list, wide): (Span, Span, bool)) -> Result<()> {
    let size = if wide { 8 } else { 4 };
    let count = list.len.saturating_sub(size).checked_div(size).unwrap_or(0);
    for i in 0..count {
        let span = list.sub(i.saturating_mul(size), size);
        let bytes = cx.read(span).await?;
        let offset = if wide {
            u64_be(&bytes, 0).unwrap_or(0)
        } else {
            u32_be(&bytes, 0).map(u64::from).unwrap_or(0)
        };
        let head = cx.read_avail(file.sub(offset, 16)).await?;
        let (w, h) = (u32_be(&head, 0).unwrap_or(0), u32_be(&head, 4).unwrap_or(0));
        let name_len = u64::from(u32_be(&head, 12).unwrap_or(0));
        let name = cx
            .read_avail(file.sub(offset.saturating_add(16), name_len.min(256)))
            .await?;
        cx.push(
            Node::new(format!("Layer {i}"))
                .span(span)
                .value(text(crate::text::until_nul(&name)))
                .summary(format!("{} at {offset:#x}", dims(w, h)))
                .target(file.sub(offset, 16))
                .lazy(layer, (file, offset, wide)),
        )
        .await;
    }
    Ok(())
}

async fn layer(cx: Cx, (file, offset, wide): (Span, u64, bool)) -> Result<()> {
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(offset);
    let fixed = cur.span(16);
    let block = cx.block(fixed).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Width").emit()?;
    f.u32("Height").emit()?;
    f.u32("Type").enumeration(LAYER_TYPES).emit()?;
    let name_len = f.u32("Name length").emit()?;
    cur.skip(16);
    let name_span = cur.span(name_len.into());
    let name = cx.read(name_span).await?;
    cx.emit(
        Node::new("Name")
            .span(name_span)
            .value(text(crate::text::until_nul(&name))),
    );
    cur.skip(name_len.into());
    let start = cur.pos();
    skip_properties(&mut cur).await?;
    let props = cur.since(start);
    cx.emit(Node::new("Properties").span(props).lazy(properties, props));
    for what in ["Hierarchy pointer", "Mask pointer"] {
        let at = cur.span(if wide { 8 } else { 4 });
        let ptr = if wide {
            cur.u64().await?
        } else {
            cur.u32().await?.into()
        };
        let mut node = Node::new(what).span(at).value(hex(ptr));
        if ptr != 0 {
            node = node.target(file.sub(ptr, 12));
        }
        cx.emit(node);
    }
    Ok(())
}
