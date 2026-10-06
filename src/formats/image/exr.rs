//! OpenEXR.
//!
//! Magic and a version field with feature flags, then one header (or, for
//! multi-part files, several headers and an empty one). A header is a list
//! of attributes `name NUL type NUL size value`, ended by an empty name.
//! Offset tables and pixel chunks follow.

use crate::bytes::{i32_le, to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

use super::{dims, hex, region, text};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "exr",
    title: "OpenEXR image",
    extensions: &["exr", "sxr", "mxr"],
    mime: "image/x-exr",
    probe: Probe::Magic(&[(0, b"\x76\x2f\x31\x01")]),
    dissect: crate::expander!(dissect: Input),
};

const VERSION_FLAGS: FlagTable = &[
    field(0xff, 0x02, "VERSION_2"),
    flag(0x200, "SINGLE_TILE"),
    flag(0x400, "LONG_NAMES"),
    flag(0x800, "NON_IMAGE (deep data)"),
    flag(0x1000, "MULTIPART"),
];

const COMPRESSION: EnumTable = &[
    (0, "NONE"),
    (1, "RLE"),
    (2, "ZIPS"),
    (3, "ZIP"),
    (4, "PIZ"),
    (5, "PXR24"),
    (6, "B44"),
    (7, "B44A"),
    (8, "DWAA"),
    (9, "DWAB"),
    (10, "HTJ2K"),
];

const LINE_ORDER: EnumTable = &[(0, "INCREASING_Y"), (1, "DECREASING_Y"), (2, "RANDOM_Y")];
const PIXEL_TYPES: EnumTable = &[(0, "UINT"), (1, "HALF"), (2, "FLOAT")];
const ENVMAP: EnumTable = &[(0, "LATLONG"), (1, "CUBE")];

/// Scanlines per chunk for each compression method.
fn lines_per_chunk(compression: u8) -> u64 {
    match compression {
        3 | 5 => 16,
        4 | 6 | 7 | 8 => 32,
        9 | 10 => 256,
        _ => 1,
    }
}

/// What later parts of the file need from a header.
#[derive(Clone, Debug, Default)]
struct Summary {
    data_window: Option<(i32, i32, i32, i32)>,
    compression: Option<u8>,
    channels: Vec<String>,
    tiled: bool,
    chunk_count: Option<u64>,
    kind: Option<String>,
}

#[derive(Clone, Copy, Debug)]
struct Attribute {
    span: Span,
    value: Span,
}

/// Reads one header's attributes starting at the cursor; returns them and
/// leaves the cursor after the terminating NUL.
async fn read_header(cur: &mut Cursor<'_>) -> Result<Vec<(String, String, Attribute)>> {
    let mut out = Vec::new();
    loop {
        let start = cur.pos();
        let (name, _) = cur.cstr(256).await?;
        if name.is_empty() {
            return Ok(out);
        }
        let (kind, _) = cur.cstr(256).await?;
        let size = u64::from(cur.u32().await?);
        let value = cur.span(size);
        cur.skip(size);
        out.push((
            name,
            kind,
            Attribute {
                span: cur.since(start),
                value,
            },
        ));
    }
}

async fn summarize(cx: &Cx, attrs: &[(String, String, Attribute)]) -> Summary {
    let mut s = Summary::default();
    for (name, kind, a) in attrs {
        let Ok(v) = cx.read_avail(a.value.sub(0, 64)).await else {
            continue;
        };
        match (name.as_str(), kind.as_str()) {
            ("dataWindow", "box2i") => {
                if let (Some(a), Some(b), Some(c), Some(d)) =
                    (i32_le(&v, 0), i32_le(&v, 4), i32_le(&v, 8), i32_le(&v, 12))
                {
                    s.data_window = Some((a, b, c, d));
                }
            }
            ("compression", _) => s.compression = v.first().copied(),
            ("tiles", _) => s.tiled = true,
            ("chunkCount", _) => s.chunk_count = u32_le(&v, 0).map(u64::from),
            ("type", _) => s.kind = Some(crate::text::latin1(&v)),
            ("channels", "chlist") => {
                if let Ok(all) = cx.read_avail(a.value.sub(0, 0x1000)).await {
                    s.channels = channel_names(&all);
                }
            }
            _ => {}
        }
    }
    s
}

fn channel_names(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some(rest) = data.get(pos..) {
        let Some(end) = rest.iter().position(|&b| b == 0) else {
            break;
        };
        if end == 0 {
            break;
        }
        out.push(crate::text::latin1(rest.get(..end).unwrap_or_default()));
        pos = pos.saturating_add(end).saturating_add(17);
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let block = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.bytes("Magic", 4).emit()?;
    let version = f.u32("Version").flags(VERSION_FLAGS).emit()?;
    let multipart = version & 0x1000 != 0;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let mut parts = Vec::new();
    loop {
        let start = cur.pos();
        let attrs = read_header(&mut cur).await?;
        let span = cur.since(start);
        if attrs.is_empty() {
            if multipart {
                cx.emit(Node::new("End of headers").span(span));
            }
            break;
        }
        let summary = summarize(&cx, &attrs).await;
        let name = if multipart {
            format!("Header {}", parts.len())
        } else {
            "Header".to_owned()
        };
        cx.emit(
            Node::new(name)
                .span(span)
                .summary(format!("{} attributes", attrs.len()))
                .lazy(header, attrs.iter().map(|(_, _, a)| a.span).collect::<Vec<_>>()),
        );
        parts.push(summary);
        if !multipart {
            break;
        }
        if parts.len() >= 1024 {
            return Err(Diagnostic::limit("more than 1024 parts").at(span));
        }
    }
    let first = parts.first().cloned().unwrap_or_default();
    let mut description = Vec::new();
    if let Some((x0, y0, x1, y1)) = first.data_window {
        let w = i64::from(x1).saturating_sub(x0.into()).saturating_add(1);
        let h = i64::from(y1).saturating_sub(y0.into()).saturating_add(1);
        description.push(dims(w, h));
    }
    if let Some(c) = first.compression {
        description.push(lookup(COMPRESSION, c.into()).unwrap_or("unknown compression").to_owned());
    }
    if !first.channels.is_empty() {
        description.push(format!("channels {}", first.channels.join(",")));
    }
    if first.tiled {
        description.push("tiled".to_owned());
    }
    if parts.len() > 1 {
        description.push(format!("{} parts", parts.len()));
    }
    cx.annotate(description.join(", "));

    // Offset tables: one per part, with chunkCount entries (or, for single-part
    // scanline images, one per block of scanlines).
    let mut pos = cur.pos();
    for (index, part) in parts.iter().enumerate() {
        let count = part.chunk_count.or_else(|| {
            let (_, y0, _, y1) = part.data_window?;
            if part.tiled {
                return None;
            }
            let lines = u64::try_from(i64::from(y1).saturating_sub(y0.into()).saturating_add(1)).ok()?;
            Some(lines.div_ceil(lines_per_chunk(part.compression.unwrap_or(0))))
        });
        let Some(count) = count else {
            cx.emit(region("Offset tables and chunks", file, pos, file.len.saturating_sub(pos)));
            return Ok(());
        };
        let table = file.sub(pos, count.saturating_mul(8));
        let name = if parts.len() > 1 {
            format!("Offset table {index}")
        } else {
            "Offset table".to_owned()
        };
        cx.emit(
            Node::new(name)
                .span(table)
                .summary(format!("{count} chunks"))
                .lazy(offsets, (file, table, multipart)),
        );
        pos = pos.saturating_add(table.len);
    }
    cx.emit(region("Chunks", file, pos, file.len.saturating_sub(pos)));
    Ok(())
}

async fn offsets(cx: Cx, (file, table, multipart): (Span, Span, bool)) -> Result<()> {
    let count = table.len / 8;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = table.sub(i.saturating_mul(8), 8);
        let bytes = cx.read(span).await?;
        let offset = u64_le(&bytes, 0).unwrap_or(0);
        // A chunk starts with the part number (multi-part), then the y
        // coordinate or tile coordinates.
        let target = file.sub(offset, if multipart { 8 } else { 4 });
        cx.push(
            Node::new(format!("[{i}]"))
                .span(span)
                .value(hex(offset))
                .target(target),
        )
        .await;
    }
    Ok(())
}

async fn header(cx: Cx, attrs: Vec<Span>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(attrs.len())));
    for span in attrs {
        let mut cur = Cursor::new(&cx, span, LE);
        let (name, _) = cur.cstr(256).await?;
        let (kind, _) = cur.cstr(256).await?;
        let size = u64::from(cur.u32().await?);
        let value = cur.span(size);
        let (v, summary) = describe(&cx, &kind, value).await;
        let mut node = Node::new(name).span(span).summary(match summary {
            Some(s) => format!("{kind}: {s}"),
            None => kind.clone(),
        });
        if let Some(v) = v {
            node = node.value(v);
        }
        cx.push(node.lazy(attribute, (span, kind))).await;
    }
    Ok(())
}

/// The value (and a summary) of an attribute of type `kind`.
async fn describe(cx: &Cx, kind: &str, span: Span) -> (Option<Value>, Option<String>) {
    let Ok(v) = cx.read_avail(span.sub(0, 256)).await else {
        return (None, None);
    };
    let f32_at = |i: usize| crate::bytes::array::<4>(&v, i).map(f32::from_le_bytes);
    let enum_of = |table: EnumTable| {
        v.first().map(|&raw| Value::Enum {
            raw: raw.into(),
            bits: 8,
            name: lookup(table, raw.into()),
        })
    };
    match kind {
        "int" => (i32_le(&v, 0).map(|x| Value::Int { value: x.into(), bits: 32 }), None),
        "float" => (f32_at(0).map(|x| Value::Float(x.into())), None),
        "double" => (
            crate::bytes::array::<8>(&v, 0).map(|b| Value::Float(f64::from_le_bytes(b))),
            None,
        ),
        "string" => (Some(text(String::from_utf8_lossy(&v))), None),
        "compression" => (enum_of(COMPRESSION), None),
        "lineOrder" => (enum_of(LINE_ORDER), None),
        "envmap" => (enum_of(ENVMAP), None),
        "box2i" => {
            let (Some(a), Some(b), Some(c), Some(d)) =
                (i32_le(&v, 0), i32_le(&v, 4), i32_le(&v, 8), i32_le(&v, 12))
            else {
                return (None, None);
            };
            let w = i64::from(c).saturating_sub(a.into()).saturating_add(1);
            let h = i64::from(d).saturating_sub(b.into()).saturating_add(1);
            (None, Some(format!("({a}, {b}) – ({c}, {d}), {}", dims(w, h))))
        }
        "v2f" | "v3f" | "box2f" | "chromaticities" | "m33f" | "m44f" => {
            let n = v.len() / 4;
            let list: Vec<String> = (0..n.min(16))
                .filter_map(|i| f32_at(i.saturating_mul(4)))
                .map(|x| format!("{x}"))
                .collect();
            (None, Some(format!("[{}]", list.join(", "))))
        }
        "v2i" | "v3i" => {
            let list: Vec<String> = (0..v.len() / 4)
                .filter_map(|i| i32_le(&v, i.saturating_mul(4)))
                .map(|x| x.to_string())
                .collect();
            (None, Some(format!("[{}]", list.join(", "))))
        }
        "chlist" => (None, Some(channel_names(&v).join(", "))),
        "rational" => {
            let (Some(n), Some(d)) = (i32_le(&v, 0), u32_le(&v, 4)) else {
                return (None, None);
            };
            (None, Some(format!("{n}/{d}")))
        }
        "tiledesc" => {
            let (Some(x), Some(y)) = (u32_le(&v, 0), u32_le(&v, 4)) else {
                return (None, None);
            };
            (None, Some(format!("{} tiles", dims(x, y))))
        }
        _ => (None, None),
    }
}

async fn attribute(cx: Cx, (span, kind): (Span, String)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let (name, name_span) = cur.cstr(256).await?;
    cx.emit(Node::new("Name").span(name_span).value(text(name)));
    let (_, kind_span) = cur.cstr(256).await?;
    cx.emit(Node::new("Type").span(kind_span).value(text(kind.clone())));
    let size_span = cur.span(4);
    let size = u64::from(cur.u32().await?);
    cx.emit(Node::new("Size").span(size_span).value(super::uint(size)));
    let value = cur.span(size);
    if kind == "chlist" {
        let mut c = Cursor::new(&cx, value, LE);
        while c.remaining() > 1 {
            let start = c.pos();
            let (channel, _) = c.cstr(256).await?;
            let rest = c.bytes(16).await?;
            let pixel = i32_le(&rest, 0).unwrap_or(0);
            let (xs, ys) = (i32_le(&rest, 8).unwrap_or(0), i32_le(&rest, 12).unwrap_or(0));
            let pixel_name = lookup(PIXEL_TYPES, u64::try_from(pixel).unwrap_or(u64::MAX)).unwrap_or("?");
            cx.emit(
                Node::new(format!("Channel {channel}"))
                    .span(c.since(start))
                    .summary(format!("{pixel_name}, sampling {xs}×{ys}")),
            );
        }
    } else {
        cx.emit(Node::new("Value").span(value));
    }
    Ok(())
}
