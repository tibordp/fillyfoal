//! 3D model and CAD formats.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;

fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

// ---------------------------------------------------------------------------
// STL

fn stl_binary_probe(h: &Head<'_>) -> bool {
    h.len >= 134
        && u32_le(h.data, 80)
            .is_some_and(|n| n > 0 && u64::from(n).saturating_mul(50).saturating_add(84) == h.len)
}

fn stl_ascii_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"solid") && h.data.windows(12).any(|w| w == b"facet normal")
}

declare_format!(pub STL = "stl", "Stereolithography mesh (binary)", ["stl"], "model/stl",
    Probe::Custom(stl_binary_probe), stl);
declare_format!(pub STL_ASCII = "stl-ascii", "Stereolithography mesh (ASCII)", ["stl"], "model/stl",
    Probe::Custom(stl_ascii_probe), stl_ascii);

record! {
    pub struct StlTriangle {
        nx: f32 "Normal X",
        ny: f32 "Normal Y",
        nz: f32 "Normal Z",
        ax: f32 "Vertex 1 X",
        ay: f32 "Vertex 1 Y",
        az: f32 "Vertex 1 Z",
        bx: f32 "Vertex 2 X",
        by: f32 "Vertex 2 Y",
        bz: f32 "Vertex 2 Z",
        cx: f32 "Vertex 3 X",
        cy: f32 "Vertex 3 Y",
        cz: f32 "Vertex 3 Z",
        attributes: u16 "Attribute byte count",
    }
}

async fn stl(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.read(file.sub(0, 84)).await?;
    let text = crate::text::until_nul(header.get(..80).unwrap_or_default());
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 80))
            .value(Value::Text(text.trim_end().to_owned())),
    );
    let count = u32_le(&header, 80).unwrap_or(0);
    cx.emit(
        Node::new("Triangle count")
            .span(file.sub(80, 4))
            .value(uint(count.into())),
    );
    let triangles = file.tail(84);
    cx.emit(
        Node::new("Triangles")
            .span(triangles)
            .summary(format!("{count} triangles"))
            .lazy(stl_triangles, triangles),
    );
    cx.annotate(format!("{count} triangles"));
    Ok(())
}

async fn stl_triangles(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / StlTriangle::SIZE;
    cx.set_count(Count::Exact(count));
    let mut cur = Cursor::new(&cx, span, LE);
    for i in 0..count {
        let (t, at) = cur.record::<StlTriangle>().await?;
        cx.push(StlTriangle::node(format!("#{i}"), at, LE).summary(format!(
            "({}, {}, {}) ({}, {}, {}) ({}, {}, {})",
            t.ax, t.ay, t.az, t.bx, t.by, t.bz, t.cx, t.cy, t.cz
        )))
        .await;
    }
    Ok(())
}

async fn stl_ascii(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let max = cx.limits().max_read;
    let text = cx.read_avail(file.sub(0, max)).await?;
    if to_u64(text.len()) < file.len {
        cx.diag(Diagnostic::limit(
            "only the beginning of the file was scanned",
        ));
    }
    let mut facets = 0u64;
    let mut name = String::new();
    let mut pos = 0u64;
    let mut current: Option<(u64, String)> = None;
    for line in text.split(|&b| b == b'\n') {
        let len = to_u64(line.len()).saturating_add(1);
        let trimmed = String::from_utf8_lossy(line).trim().to_owned();
        if let Some(rest) = trimmed.strip_prefix("solid") {
            if name.is_empty() {
                name = rest.trim().to_owned();
            }
        } else if trimmed.starts_with("facet") {
            current = Some((pos, trimmed.clone()));
        } else if trimmed == "endfacet"
            && let Some((start, normal)) = current.take()
        {
            facets = facets.saturating_add(1);
            cx.push(
                Node::new(format!("facet {facets}"))
                    .span(file.sub(start, pos.saturating_add(len).saturating_sub(start)))
                    .summary(normal),
            )
            .await;
        }
        pos = pos.saturating_add(len);
    }
    cx.annotate(format!("solid {name:?}, {facets} facets"));
    Ok(())
}

// ---------------------------------------------------------------------------
// PLY

declare_format!(pub PLY = "ply", "Polygon File Format", ["ply"], "model/ply",
    Probe::Magic(&[(0, b"ply\n"), (0, b"ply\r\n")]), ply);

fn ply_type_size(name: &str) -> Option<u64> {
    match name {
        "char" | "uchar" | "int8" | "uint8" => Some(1),
        "short" | "ushort" | "int16" | "uint16" => Some(2),
        "int" | "uint" | "float" | "int32" | "uint32" | "float32" => Some(4),
        "double" | "float64" => Some(8),
        _ => None,
    }
}

async fn ply(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 65536)).await?;
    let end = head
        .windows(10)
        .position(|w| w == b"end_header")
        .ok_or_else(|| Diagnostic::malformed("no end_header in the first 64 KiB"))?;
    let header_len = head
        .get(end..)
        .and_then(|rest| rest.iter().position(|&b| b == b'\n'))
        .map_or(to_u64(end).saturating_add(10), |nl| {
            to_u64(end.saturating_add(nl).saturating_add(1))
        });
    let text = String::from_utf8_lossy(head.get(..end).unwrap_or_default()).into_owned();
    let mut format = String::new();
    // (name, count, fixed record size if no list properties, properties)
    let mut elements: Vec<(String, u64, Option<u64>, Vec<String>)> = Vec::new();
    let mut pos = 0u64;
    let mut header_nodes = Vec::new();
    for line in text.split('\n') {
        let len = to_u64(line.len()).saturating_add(1);
        let words: Vec<&str> = line.split_whitespace().collect();
        match words.as_slice() {
            ["format", f, v] => format = format!("{f} {v}"),
            ["element", name, count] => elements.push((
                (*name).to_owned(),
                count.parse().unwrap_or(0),
                Some(0),
                Vec::new(),
            )),
            ["property", "list", ..] => {
                if let Some(e) = elements.last_mut() {
                    e.2 = None;
                    e.3.push(line.trim().to_owned());
                }
            }
            ["property", kind, name] => {
                if let Some(e) = elements.last_mut() {
                    e.2 =
                        e.2.and_then(|s| Some(s.saturating_add(ply_type_size(kind)?)));
                    e.3.push(format!("{name}: {kind}"));
                }
            }
            _ => {}
        }
        if !line.trim().is_empty() {
            header_nodes.push(Node::new(line.trim().to_owned()).span(file.sub(pos, len)));
        }
        pos = pos.saturating_add(len);
    }
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, header_len))
            .summary(format.clone())
            .lazy(emit_nodes, header_nodes),
    );
    let binary = format.starts_with("binary");
    let mut at = header_len;
    let mut summary = Vec::new();
    for (name, count, size, properties) in elements {
        summary.push(format!("{count} {name}"));
        let node =
            Node::new(name.clone()).summary(format!("{count} × [{}]", properties.join(", ")));
        match (binary, size) {
            (true, Some(size)) => {
                let len = size.saturating_mul(count);
                cx.emit(node.span(file.sub(at, len)));
                at = at.saturating_add(len);
            }
            (true, None) => {
                cx.emit(node.diag(Diagnostic::note("list properties: element size varies")));
                at = file.len;
            }
            (false, _) => cx.emit(node),
        }
    }
    cx.annotate(format!("PLY {format}: {}", summary.join(", ")));
    Ok(())
}

async fn emit_nodes(cx: Cx, nodes: Vec<Node>) -> Result<()> {
    for node in nodes {
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// glTF binary (GLB)

declare_format!(pub GLB = "glb", "glTF binary", ["glb", "vrm"], "model/gltf-binary",
    Probe::Magic(&[(0, b"glTF")]), glb);

record! {
    pub struct GlbHeader {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        length: u32 "Total length",
    }
}

async fn glb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: GlbHeader = read_record(&cx, file.sub(0, GlbHeader::SIZE), LE).await?;
    cx.emit(GlbHeader::node("Header", file.sub(0, GlbHeader::SIZE), LE));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(GlbHeader::SIZE);
    let mut generator = None;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let kind = cur.bytes(4).await?;
        let data = cur.span(len.into());
        cur.skip(len.into());
        let node = match kind.as_slice() {
            b"JSON" => {
                let json = cx.read_avail(data.sub(0, 65536)).await?;
                let text = String::from_utf8_lossy(&json);
                if let Some(at) = text.find("\"generator\"") {
                    generator = text
                        .get(at.saturating_add(11)..)
                        .and_then(|r| r.split('"').nth(1))
                        .map(str::to_owned);
                }
                embedded("JSON chunk", input.nested(data))
            }
            b"BIN\0" => Node::new("BIN chunk").span(data),
            _ => Node::new(format!("Chunk {}", String::from_utf8_lossy(&kind))).span(data),
        };
        cx.push(
            node.summary(format!("{len} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(match generator {
        Some(g) => format!("glTF {} by {g}", h.version),
        None => format!("glTF {}", h.version),
    });
    Ok(())
}

// ---------------------------------------------------------------------------
// FBX (binary)

declare_format!(pub FBX = "fbx", "Autodesk FBX (binary)", ["fbx"], "application/vnd.autodesk.fbx",
    Probe::Magic(&[(0, b"Kaydara FBX Binary  \0")]), fbx);

async fn fbx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.block(file.sub(0, 27)).await?;
    let mut f = Fields::emitting(&cx, &header, LE);
    f.ascii("Magic", 21).emit()?;
    f.bytes("Reserved", 2).emit()?;
    let version = f.u32("Version").emit()?;
    let wide = version >= 7500;
    cx.annotate(format!("FBX {}.{}", version / 1000, version % 1000 / 100));
    cx.emit(
        Node::new("Nodes")
            .span(file.tail(27))
            .lazy(fbx_nodes, (input, file.tail(27), wide)),
    );
    Ok(())
}

/// Lists the node records in `list` (ended by a null record).
async fn fbx_nodes(cx: Cx, (input, list, wide): (Input, Span, bool)) -> Result<()> {
    let file = input.span;
    let header_len: u64 = if wide { 25 } else { 13 };
    let mut pos = list.offset.saturating_sub(file.offset);
    let end = pos.saturating_add(list.len);
    while pos.saturating_add(header_len) <= end {
        let header = cx.read(file.sub(pos, header_len)).await?;
        let (end_offset, props, props_len, name_len) = if wide {
            (
                u64_le(&header, 0).unwrap_or(0),
                u64_le(&header, 8).unwrap_or(0),
                u64_le(&header, 16).unwrap_or(0),
                header.get(24).copied().unwrap_or(0),
            )
        } else {
            (
                u64::from(u32_le(&header, 0).unwrap_or(0)),
                u64::from(u32_le(&header, 4).unwrap_or(0)),
                u64::from(u32_le(&header, 8).unwrap_or(0)),
                header.get(12).copied().unwrap_or(0),
            )
        };
        if end_offset == 0 {
            break; // null record
        }
        if end_offset <= pos || end_offset > file.len {
            return Err(Diagnostic::malformed(format!(
                "node end offset {end_offset:#x} is out of order"
            ))
            .at(file.sub(pos, header_len)));
        }
        let name_span = file.sub(pos.saturating_add(header_len), name_len.into());
        let name = String::from_utf8_lossy(&cx.read(name_span).await?).into_owned();
        let record = file.sub(pos, end_offset.saturating_sub(pos));
        let props_span = file.sub(name_span.end().saturating_sub(file.offset), props_len);
        let nested = record.tail(props_span.end().saturating_sub(record.offset));
        cx.push(
            Node::new(if name.is_empty() {
                "(unnamed)".to_owned()
            } else {
                name
            })
            .span(record)
            .summary(format!("{props} properties"))
            .lazy(fbx_node, (input, props_span, props, nested, wide)),
        )
        .await;
        pos = end_offset;
    }
    Ok(())
}

async fn fbx_node(
    cx: Cx,
    (input, props_span, count, nested, wide): (Input, Span, u64, Span, bool),
) -> Result<()> {
    let mut cur = Cursor::new(&cx, props_span, LE);
    for i in 0..count.min(1 << 20) {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let kind = cur.u8().await?;
        let name = format!("[{i}] {}", char::from(kind));
        let node = match kind {
            b'Y' => Node::new(name).value(Value::Int {
                value: i64::from(cur.int::<i16>().await?),
                bits: 16,
            }),
            b'C' => Node::new(name).value(Value::Bool(cur.u8().await? != 0)),
            b'I' => Node::new(name).value(Value::Int {
                value: i64::from(cur.int::<i32>().await?),
                bits: 32,
            }),
            b'F' => Node::new(name).value(Value::Float(f64::from(cur.int::<f32>().await?))),
            b'D' => Node::new(name).value(Value::Float(cur.int::<f64>().await?)),
            b'L' => Node::new(name).value(Value::Int {
                value: cur.int::<i64>().await?,
                bits: 64,
            }),
            b'S' | b'R' => {
                let len = cur.u32().await?;
                let data = cur.span(len.into());
                cur.skip(len.into());
                if kind == b'S' {
                    let bytes = cx.read_avail(data.sub(0, 4096)).await?;
                    // Names are "Name\x00\x01Class".
                    let text = String::from_utf8_lossy(&bytes).replace("\u{0}\u{1}", "::");
                    Node::new(name).value(Value::Text(text))
                } else {
                    embedded(name, input.nested(data)).summary(format!("{len} raw bytes"))
                }
            }
            b'f' | b'd' | b'l' | b'i' | b'b' => {
                let elements = cur.u32().await?;
                let encoding = cur.u32().await?;
                let len = cur.u32().await?;
                let data = cur.span(len.into());
                cur.skip(len.into());
                let summary = format!("{elements} elements");
                if encoding == 1 {
                    content(name, input, data, Codec::Zlib, None)
                        .summary(format!("{summary}, zlib"))
                } else {
                    Node::new(name).span(data).summary(summary)
                }
            }
            _ => {
                cx.diag(
                    Diagnostic::malformed(format!("unknown property type {kind:#04x}"))
                        .at(cur.span(1)),
                );
                break;
            }
        };
        let span = cur.since(start);
        let node = if node.span.is_none() {
            node.span(span)
        } else {
            node.target(span)
        };
        cx.push(node).await;
    }
    if nested.len > 0 {
        cx.emit(Node::new("Children").span(nested).lazy(
            crate::expander!(self::fbx_nodes: (Input, Span, bool)),
            (input, nested, wide),
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Autodesk 3D Studio (.3ds)

fn three_ds_probe(h: &Head<'_>) -> bool {
    h.at(0, b"\x4d\x4d")
        && u32_le(h.data, 2)
            .is_some_and(|len| u64::from(len) <= h.len.saturating_add(16) && len > 16)
        && u16_le(h.data, 6).is_some_and(|id| id == 0x0002 || id == 0x3d3d)
}

declare_format!(pub THREE_DS = "3ds", "Autodesk 3D Studio mesh", ["3ds"], "application/x-3ds",
    Probe::Custom(three_ds_probe), three_ds);

const CHUNKS_3DS: EnumTable = &[
    (0x0002, "Version"),
    (0x0010, "Color (float)"),
    (0x0011, "Color (24-bit)"),
    (0x0030, "Percentage (int)"),
    (0x0100, "Master scale"),
    (0x3d3d, "Editor"),
    (0x3d3e, "Mesh version"),
    (0x4000, "Object"),
    (0x4100, "Triangle mesh"),
    (0x4110, "Vertices"),
    (0x4120, "Faces"),
    (0x4130, "Face materials"),
    (0x4140, "Texture coordinates"),
    (0x4150, "Smoothing groups"),
    (0x4160, "Local axes"),
    (0x4600, "Light"),
    (0x4700, "Camera"),
    (0x4d4d, "Main"),
    (0xa000, "Material name"),
    (0xa010, "Ambient color"),
    (0xa020, "Diffuse color"),
    (0xa030, "Specular color"),
    (0xa200, "Texture map"),
    (0xa300, "Map file name"),
    (0xafff, "Material"),
    (0xb000, "Keyframer"),
    (0xb002, "Object node"),
    (0xb008, "Frames"),
    (0xb010, "Node header"),
];

/// Chunks whose payload consists of sub-chunks (after a fixed prefix).
fn container_3ds(id: u16) -> Option<bool> {
    match id {
        0x4d4d | 0x3d3d | 0x4100 | 0xafff | 0xa200 | 0xb000 | 0xb002 | 0x4600 | 0xa010 | 0xa020
        | 0xa030 => Some(false),
        0x4000 => Some(true), // name first
        _ => None,
    }
}

async fn three_ds(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("3D Studio mesh");
    chunks_3ds(cx, input.span).await
}

async fn chunks_3ds(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 6 {
        let start = cur.pos();
        let id = cur.u16().await?;
        let len = cur.u32().await?;
        if len < 6 {
            cx.diag(Diagnostic::malformed("chunk shorter than its header").at(cur.since(start)));
            break;
        }
        let chunk = span.sub(start, len.into());
        cur.seek(start.saturating_add(len.into()));
        let name =
            lookup(CHUNKS_3DS, id.into()).map_or_else(|| format!("Chunk {id:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(chunk).value(Value::UInt {
            value: id.into(),
            bits: 16,
            radix: Radix::Hex,
        });
        match container_3ds(id) {
            Some(named) => {
                let mut body = chunk.tail(6);
                if named {
                    let (object, at) = cx.cstr(body.sub(0, 256)).await?;
                    node = node.summary(object);
                    body = body.tail(at.len);
                }
                node = node.lazy(crate::expander!(self::chunks_3ds: Span), body);
            }
            None => {
                if id == 0x4110 || id == 0x4120 {
                    let n = cx.read_avail(chunk.sub(6, 2)).await?;
                    node = node.summary(format!("{}", u16_le(&n, 0).unwrap_or(0)));
                } else if id == 0xa000 || id == 0xa300 {
                    let (text, _) = cx.cstr(chunk.tail(6).sub(0, 256)).await?;
                    node = node.summary(text);
                }
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Blender: see `blend.rs`.

pub use super::blend::FORMAT as BLEND;

// ---------------------------------------------------------------------------
// USD crate (binary .usdc)

declare_format!(pub USDC = "usdc", "Universal Scene Description (crate)", ["usdc", "usd"], "model/vnd.usd",
    Probe::Magic(&[(0, b"PXR-USDC")]), usdc);

record! {
    pub struct UsdcSection {
        name: ascii[16] "Name",
        start: u64 "Start" .hex(),
        size: u64 "Size",
    }
}

async fn usdc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &header, LE);
    f.ascii("Magic", 8).emit()?;
    let version = f.bytes("Version", 8).emit()?;
    let toc = f.u64("Table of contents offset").hex().emit()?;
    let count = u64_le(&cx.read(file.sub(toc, 8)).await?, 0).unwrap_or(0);
    let table = file.sub_exact(
        toc.saturating_add(8),
        count.saturating_mul(UsdcSection::SIZE),
    )?;
    let mut cur = Cursor::new(&cx, table, LE);
    for _ in 0..count {
        let (s, span) = cur.record::<UsdcSection>().await?;
        cx.push(
            UsdcSection::node(s.name.clone(), span, LE)
                .summary(format!("{} bytes", s.size))
                .target(file.sub(s.start, s.size)),
        )
        .await;
    }
    cx.annotate(format!(
        "USD crate {}.{}.{}, {count} sections",
        version.first().copied().unwrap_or(0),
        version.get(1).copied().unwrap_or(0),
        version.get(2).copied().unwrap_or(0)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// MagicaVoxel

declare_format!(pub VOX = "vox", "MagicaVoxel model", ["vox"], "model/x-vox",
    Probe::Magic(&[(0, b"VOX ")]), vox);

async fn vox(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 8))
            .summary(format!("version {}", u32_le(&head, 4).unwrap_or(0))),
    );
    cx.annotate(format!("MagicaVoxel v{}", u32_le(&head, 4).unwrap_or(0)));
    vox_chunks(cx, file.tail(8)).await
}

async fn vox_chunks(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let content_len = cur.u32().await?;
        let children_len = cur.u32().await?;
        let body = cur.span(content_len.into());
        cur.skip(content_len.into());
        let children = cur.span(children_len.into());
        cur.skip(children_len.into());
        let mut node = Node::new(id.clone()).span(cur.since(start));
        if id == "SIZE" {
            let b = cx.read_avail(body).await?;
            node = node.summary(format!(
                "{}×{}×{}",
                u32_le(&b, 0).unwrap_or(0),
                u32_le(&b, 4).unwrap_or(0),
                u32_le(&b, 8).unwrap_or(0)
            ));
        } else if id == "XYZI" {
            let b = cx.read_avail(body.sub(0, 4)).await?;
            node = node.summary(format!("{} voxels", u32_le(&b, 0).unwrap_or(0)));
        } else {
            node = node.summary(format!("{content_len} bytes"));
        }
        if children_len > 0 {
            node = node.lazy(crate::expander!(self::vox_chunks: Span), children);
        }
        cx.push(node).await;
    }
    Ok(())
}
