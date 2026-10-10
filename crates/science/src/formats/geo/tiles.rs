//! Map tiles and vector data: PMTiles archives, FlatGeobuf, Mapbox vector
//! tiles (protobuf) and OpenStreetMap o5m/o5c streams.

use super::emit_nodes;
use super::{enumv, hex, leaf, text, uint};
use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Path, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::pace::Pace;
use crate::formats::util::wire::flatbuffers::mem::{self as fb, Table as FbTable};
use crate::formats::util::wire::protobuf::{self as pb, varint, zigzag};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};
use std::sync::Arc;

const LE: Endian = Endian::Little;

/// Directories and tiles are read whole; larger ones are refused.
const MAX_BLOB: u64 = 16 << 20;
/// Enough of a gzip stream for any member header.
const GZIP_HEAD: u64 = 1 << 18;

// ---------------------------------------------------------------------------
// PMTiles v3

declare_format!(pub PMTILES = "pmtiles", "PMTiles tile archive", ["pmtiles"], "application/vnd.pmtiles",
    Probe::Magic(&[(0, b"PMTiles\x03")]), pmtiles);

const COMPRESSION: EnumTable = &[
    (0, "unknown"),
    (1, "none"),
    (2, "gzip"),
    (3, "brotli"),
    (4, "zstd"),
];
const TILE_TYPES: EnumTable = &[
    (0, "unknown"),
    (1, "mvt"),
    (2, "png"),
    (3, "jpeg"),
    (4, "webp"),
    (5, "avif"),
];

fn e7(v: i32) -> String {
    format!("{:.7}°", f64::from(v) / 1e7)
}

record! {
    pub struct PmHeader {
        magic: ascii[7] "Magic",
        version: u8 "Version",
        root_offset: u64 "Root directory offset" .hex(),
        root_len: u64 "Root directory length",
        meta_offset: u64 "Metadata offset" .hex(),
        meta_len: u64 "Metadata length",
        leaf_offset: u64 "Leaf directories offset" .hex(),
        leaf_len: u64 "Leaf directories length",
        data_offset: u64 "Tile data offset" .hex(),
        data_len: u64 "Tile data length",
        addressed: u64 "Addressed tiles",
        entries: u64 "Tile entries",
        contents: u64 "Tile contents",
        clustered: u8 "Clustered",
        internal: u8 "Internal compression" .enumeration(COMPRESSION),
        tile_compression: u8 "Tile compression" .enumeration(COMPRESSION),
        tile_type: u8 "Tile type" .enumeration(TILE_TYPES),
        min_zoom: u8 "Min zoom",
        max_zoom: u8 "Max zoom",
        min_lon: i32 "Min longitude (1e-7°)" .with(|&v, n| n.summary(e7(v))),
        min_lat: i32 "Min latitude (1e-7°)" .with(|&v, n| n.summary(e7(v))),
        max_lon: i32 "Max longitude (1e-7°)" .with(|&v, n| n.summary(e7(v))),
        max_lat: i32 "Max latitude (1e-7°)" .with(|&v, n| n.summary(e7(v))),
        center_zoom: u8 "Center zoom",
        center_lon: i32 "Center longitude (1e-7°)" .with(|&v, n| n.summary(e7(v))),
        center_lat: i32 "Center latitude (1e-7°)" .with(|&v, n| n.summary(e7(v))),
    }
}

/// Converts a PMTiles tile ID (Hilbert order per zoom level) to z/x/y.
fn zxy(id: u64) -> Option<(u8, u64, u64)> {
    let mut acc = 0u64;
    for z in 0u8..32 {
        let count = 1u64.checked_shl(u32::from(z).saturating_mul(2))?;
        if acc.checked_add(count)? > id {
            let n = 1u64.checked_shl(u32::from(z))?;
            let mut t = id.checked_sub(acc)?;
            let (mut x, mut y) = (0u64, 0u64);
            let mut s = 1u64;
            while s < n {
                let rx = 1 & (t / 2);
                let ry = 1 & (t ^ rx);
                if ry == 0 {
                    if rx == 1 {
                        x = s.saturating_sub(1).saturating_sub(x);
                        y = s.saturating_sub(1).saturating_sub(y);
                    }
                    std::mem::swap(&mut x, &mut y);
                }
                x = x.saturating_add(s.saturating_mul(rx));
                y = y.saturating_add(s.saturating_mul(ry));
                t /= 4;
                s = s.saturating_mul(2);
            }
            return Some((z, x, y));
        }
        acc = acc.checked_add(count)?;
    }
    None
}

/// What a directory points into.
#[derive(Clone, Copy)]
struct PmState {
    input: Input,
    data: Span,
    leaves: Span,
    /// The directories' compression (1 none, 2 gzip, 3 brotli, 4 zstd).
    internal: u8,
}

async fn pmtiles(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: PmHeader = read_record(&cx, file.sub(0, PmHeader::SIZE), LE).await?;
    cx.emit(PmHeader::node("Header", file.sub(0, PmHeader::SIZE), LE));
    let state = PmState {
        input,
        data: file.sub(h.data_offset, h.data_len),
        leaves: file.sub(h.leaf_offset, h.leaf_len),
        internal: h.internal,
    };
    let root = file.sub(h.root_offset, h.root_len);
    cx.emit(
        Node::new("Root directory")
            .span(root)
            .lazy(directory, (state, root, Path::new())),
    );
    if h.meta_len > 0 {
        cx.emit(embedded(
            "Metadata",
            input.nested(file.sub(h.meta_offset, h.meta_len)),
        ));
    }
    if h.leaf_len > 0 {
        cx.emit(Node::new("Leaf directories").span(state.leaves));
    }
    cx.emit(
        Node::new("Tile data")
            .span(state.data)
            .summary(format!("{} tiles", h.contents)),
    );
    let kind = crate::value::lookup(TILE_TYPES, h.tile_type.into()).unwrap_or("unknown");
    cx.annotate(format!(
        "PMTiles v{}, {} {kind} tiles, zoom {}–{}",
        h.version, h.addressed, h.min_zoom, h.max_zoom
    ));
    Ok(())
}

/// Varints (and other small items) decoded per unit of work.
const ITEMS_PER_UNIT: u64 = 256;

/// A directory entry: tile ID, offset, length, run length.
type DirEntry = (u64, u64, u64, u64);

/// Decodes a directory, charging its varints to `pace`.
async fn decode_directory(pace: &mut Pace<'_>, data: &[u8]) -> Option<Vec<DirEntry>> {
    let mut at = 0usize;
    let n = to_usize(varint(data, &mut at)?);
    // Every entry takes at least four bytes.
    if n > data.len() {
        return None;
    }
    let mut ids = Vec::with_capacity(n);
    let mut last = 0u64;
    for _ in 0..n {
        last = last.checked_add(varint(data, &mut at)?)?;
        ids.push(last);
        pace.step().await;
    }
    let mut runs = Vec::with_capacity(n);
    for _ in 0..n {
        runs.push(varint(data, &mut at)?);
        pace.step().await;
    }
    let mut lens = Vec::with_capacity(n);
    for _ in 0..n {
        lens.push(varint(data, &mut at)?);
        pace.step().await;
    }
    let mut out = Vec::with_capacity(n);
    let (mut prev_off, mut prev_len) = (0u64, 0u64);
    for i in 0..n {
        pace.step().await;
        let v = varint(data, &mut at)?;
        let len = *lens.get(i)?;
        let off = if v == 0 && i > 0 {
            prev_off.checked_add(prev_len)?
        } else {
            v.checked_sub(1)?
        };
        out.push((*ids.get(i)?, off, len, *runs.get(i)?));
        (prev_off, prev_len) = (off, len);
    }
    Some(out)
}

/// Reads, decompresses and decodes a directory.
async fn directory_entries(cx: &Cx, state: &PmState, dir: Span) -> Result<Vec<DirEntry>> {
    if dir.len > MAX_BLOB {
        return Err(Diagnostic::limit("directory too large").at(dir));
    }
    let data = match state.internal {
        1 => cx.read(dir).await?,
        compression => {
            let (span, codec) = match compression {
                // gzip: `Codec::Gzip` starts after the first member's header.
                2 => {
                    let head = cx.read_avail(dir.sub(0, GZIP_HEAD)).await?;
                    let header = crate::codec::gzip::header_len(&head).map_err(|e| e.at(dir))?;
                    (dir.tail(to_u64(header)), Codec::Gzip)
                }
                3 => (dir, Codec::Brotli),
                4 => (dir, Codec::Zstd),
                _ => return Err(Diagnostic::unsupported("directory compression").at(dir)),
            };
            let decoded = crate::codec::decode_span(cx, span, &codec, None).await?;
            if let Some(e) = decoded.error {
                return Err(e);
            }
            if decoded.span.len > MAX_BLOB {
                return Err(Diagnostic::limit("directory too large").at(dir));
            }
            cx.read(decoded.span).await?
        }
    };
    decode_directory(&mut Pace::new(cx, ITEMS_PER_UNIT), &data)
        .await
        .ok_or_else(|| Diagnostic::malformed("malformed directory").at(dir))
}

async fn directory(cx: Cx, (state, dir, path): (PmState, Span, Path)) -> Result<()> {
    // Decoded once: paging through a large directory re-runs this expansion.
    let entries = match cx.cached::<Vec<DirEntry>>(dir, "pmtiles-directory") {
        Some(entries) => entries,
        None => {
            let entries = Arc::new(directory_entries(&cx, &state, dir).await?);
            cx.cache(dir, "pmtiles-directory", entries.clone());
            entries
        }
    };
    cx.set_count(crate::node::Count::Exact(to_u64(entries.len())));
    for (i, &(id, off, len, run)) in entries.iter().enumerate() {
        if run == 0 {
            let span = state.leaves.sub(off, len);
            let node = match path.enter(to_u64(i).saturating_add(dir.offset), 4) {
                Ok(child) => Node::new(format!("Leaf directory from tile {id}"))
                    .span(span)
                    .lazy(
                        crate::expander!(self::directory: (PmState, Span, Path)),
                        (state, span, child),
                    ),
                Err(e) => Node::new(format!("Leaf directory from tile {id}"))
                    .span(span)
                    .diag(e),
            };
            cx.push(node).await;
            continue;
        }
        let span = state.data.sub(off, len);
        let name = match zxy(id) {
            Some((z, x, y)) => format!("Tile {z}/{x}/{y}"),
            None => format!("Tile {id}"),
        };
        let summary = if run > 1 {
            format!("{len} bytes, repeated for {run} tiles")
        } else {
            format!("{len} bytes")
        };
        cx.push(embedded(name, state.input.nested(span)).summary(summary))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// FlatGeobuf

declare_format!(pub FLATGEOBUF = "flatgeobuf", "FlatGeobuf", ["fgb"], "application/flatgeobuf",
    Probe::Custom(|h| h.starts_with(b"fgb\x03fgb") && h.data.get(7).is_some_and(|&b| b <= 4)), flatgeobuf);

const GEOMETRY_TYPES: EnumTable = &[
    (0, "Unknown"),
    (1, "Point"),
    (2, "LineString"),
    (3, "Polygon"),
    (4, "MultiPoint"),
    (5, "MultiLineString"),
    (6, "MultiPolygon"),
    (7, "GeometryCollection"),
    (8, "CircularString"),
    (9, "CompoundCurve"),
    (10, "CurvePolygon"),
    (11, "MultiCurve"),
    (12, "MultiSurface"),
    (13, "Curve"),
    (14, "Surface"),
    (15, "PolyhedralSurface"),
    (16, "TIN"),
    (17, "Triangle"),
];

const COLUMN_TYPES: EnumTable = &[
    (0, "Byte"),
    (1, "UByte"),
    (2, "Bool"),
    (3, "Short"),
    (4, "UShort"),
    (5, "Int"),
    (6, "UInt"),
    (7, "Long"),
    (8, "ULong"),
    (9, "Float"),
    (10, "Double"),
    (11, "String"),
    (12, "Json"),
    (13, "DateTime"),
    (14, "Binary"),
];

/// Column names and types from the header, for decoding properties.
type Columns = std::sync::Arc<Vec<(String, u8)>>;

/// The size of the packed Hilbert R-tree index.
fn index_size(features: u64, node_size: u16) -> Option<u64> {
    if node_size < 2 || features == 0 {
        return Some(0);
    }
    let node_size = u64::from(node_size);
    let mut n = features;
    let mut total = n;
    loop {
        n = n.div_ceil(node_size);
        total = total.checked_add(n)?;
        if n <= 1 {
            break;
        }
    }
    total.checked_mul(40)
}

async fn flatgeobuf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(leaf(
        "Magic",
        file.sub(0, 8),
        Value::Bytes(cx.read(file.sub(0, 8)).await?),
    ));
    let size = u64::from(u32_le(&cx.read(file.sub(8, 4)).await?, 0).unwrap_or(0));
    cx.emit(leaf("Header size", file.sub(8, 4), uint(size, 32)));
    if size > MAX_BLOB {
        return Err(Diagnostic::limit("header too large").at(file.sub(8, 4)));
    }
    let hspan = file.sub_exact(12, size)?;
    let buf = cx.read(hspan).await?;
    let root = fb::root(&buf).ok_or_else(|| Diagnostic::malformed("bad header table").at(hspan))?;
    let name = root.string(&buf, 0).map(|s| s.0).unwrap_or_default();
    let gtype = root.u8(&buf, 2).unwrap_or(0);
    let features = root.u64(&buf, 8).unwrap_or(0);
    let node_size = root.u16(&buf, 9).unwrap_or(16);
    let mut columns = Vec::new();
    if let Some((n, start)) = root.vector(&buf, 7, 4) {
        for j in 0..n.min(4096) {
            if let Some(t) = FbTable::vector_table(&buf, start, j) {
                columns.push((
                    t.string(&buf, 0).map(|s| s.0).unwrap_or_default(),
                    t.u8(&buf, 1).unwrap_or(0),
                ));
            }
        }
    }
    let columns: Columns = std::sync::Arc::new(columns);
    cx.emit(
        Node::new("Header")
            .span(hspan)
            .summary(format!("{} columns", columns.len()))
            .lazy(fgb_header, hspan),
    );

    let index = index_size(features, node_size).unwrap_or(u64::MAX);
    let index_at = 12u64.saturating_add(size);
    if index > 0 {
        cx.emit(
            Node::new("Spatial index")
                .span(file.sub(index_at, index))
                .summary(format!("packed Hilbert R-tree, node size {node_size}")),
        );
    }
    let data = file.tail(index_at.saturating_add(index));
    cx.emit(
        Node::new("Features")
            .span(data)
            .summary(format!("{features} features"))
            .lazy(fgb_features, (data, columns)),
    );
    let geom = crate::value::lookup(GEOMETRY_TYPES, gtype.into()).unwrap_or("unknown");
    cx.annotate(format!(
        "FlatGeobuf {}, {features} {geom} features",
        if name.is_empty() {
            "layer".to_owned()
        } else {
            format!("layer {name:?}")
        }
    ));
    Ok(())
}

async fn fgb_header(cx: Cx, hspan: Span) -> Result<()> {
    let buf = cx.read(hspan).await?;
    let root = fb::root(&buf).ok_or_else(|| Diagnostic::malformed("bad header table").at(hspan))?;
    let at = |pos: usize, len: usize| hspan.sub(to_u64(pos), to_u64(len));
    for (i, label) in [
        (0usize, "Name"),
        (11, "Title"),
        (12, "Description"),
        (13, "Metadata"),
    ] {
        if let Some((s, a, b)) = root.string(&buf, i) {
            cx.emit(leaf(label, at(a, b.saturating_sub(a)), text(s)));
        }
    }
    if let Some((n, start)) = root.vector(&buf, 1, 8) {
        let v: Vec<String> = (0..n.min(8))
            .filter_map(|j| u64_le(&buf, start.saturating_add(j.saturating_mul(8))))
            .map(|b| format!("{}", f64::from_bits(b)))
            .collect();
        cx.emit(
            Node::new("Envelope")
                .span(at(start, n.saturating_mul(8)))
                .summary(format!("[{}]", v.join(", "))),
        );
    }
    if let Some(p) = root.field(&buf, 2) {
        cx.emit(leaf(
            "Geometry type",
            at(p, 1),
            enumv(root.u8(&buf, 2).unwrap_or(0), 8, GEOMETRY_TYPES),
        ));
    }
    for (i, label) in [(3usize, "Has Z"), (4, "Has M"), (5, "Has T"), (6, "Has TM")] {
        if let Some(p) = root.field(&buf, i) {
            cx.emit(leaf(
                label,
                at(p, 1),
                Value::Bool(root.u8(&buf, i).unwrap_or(0) != 0),
            ));
        }
    }
    if let Some(p) = root.field(&buf, 8) {
        cx.emit(leaf(
            "Features count",
            at(p, 8),
            uint(root.u64(&buf, 8).unwrap_or(0), 64),
        ));
    }
    if let Some(p) = root.field(&buf, 9) {
        cx.emit(leaf(
            "Index node size",
            at(p, 2),
            uint(root.u16(&buf, 9).unwrap_or(0), 16),
        ));
    }
    if let Some(crs) = root.table(&buf, 10) {
        let org = crs
            .string(&buf, 0)
            .map(|s| s.0)
            .unwrap_or_else(|| "EPSG".to_owned());
        let code = crs.i32(&buf, 1).unwrap_or(0);
        let mut node = Node::new("CRS")
            .span(at(crs.pos, 4))
            .value(text(format!("{org}:{code}")));
        if let Some((name, _, _)) = crs.string(&buf, 2) {
            node = node.summary(name);
        }
        cx.emit(node);
    }
    if let Some((n, start)) = root.vector(&buf, 7, 4) {
        for j in 0..n.min(4096) {
            let Some(t) = FbTable::vector_table(&buf, start, j) else {
                continue;
            };
            let name = t.string(&buf, 0).map(|s| s.0).unwrap_or_default();
            let ty = t.u8(&buf, 1).unwrap_or(0);
            cx.emit(
                Node::new(format!("Column {name}"))
                    .span(at(t.pos, 4))
                    .value(enumv(ty, 8, COLUMN_TYPES)),
            );
        }
    }
    Ok(())
}

async fn fgb_features(cx: Cx, (data, columns): (Span, Columns)) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, LE);
    let mut i = 0u64;
    while cur.remaining() >= 4 {
        cx.progress_in(data, data.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        let size = u64::from(cur.u32().await?);
        let body = cur.span(size);
        if body.len < size {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, size),
                body.len,
            ));
        }
        cur.skip(size);
        let mut node = Node::new(format!("Feature {i}")).span(cur.since(start));
        if size <= MAX_BLOB {
            let buf = cx.read(body).await?;
            if let Some(summary) = feature_summary(&buf, &columns) {
                node = node.summary(summary);
            }
        }
        cx.push(node.lazy(fgb_feature, (body, columns.clone())))
            .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// Geometry type and coordinate count of a feature.
fn feature_summary(buf: &[u8], columns: &Columns) -> Option<String> {
    let f = fb::root(buf)?;
    let g = f.table(buf, 0)?;
    let ty = g.u8(buf, 6).unwrap_or(0);
    let points = g.vector(buf, 1, 8).map_or(0, |v| v.0 / 2);
    let mut s = format!(
        "{}, {points} points",
        crate::value::lookup(GEOMETRY_TYPES, ty.into()).unwrap_or("geometry")
    );
    let props = properties(buf, columns);
    if let Some((name, value, _)) = props.first() {
        s.push_str(&format!(", {name}={}", crate::render::value(value)));
    }
    Some(s)
}

/// Decodes a feature's properties: `(column, value, byte range)`.
fn properties(buf: &[u8], columns: &Columns) -> Vec<(String, Value, (usize, usize))> {
    let mut out = Vec::new();
    let Some(f) = fb::root(buf) else { return out };
    let Some((n, start)) = f.vector(buf, 1, 1) else {
        return out;
    };
    let props = buf.get(start..start.saturating_add(n)).unwrap_or_default();
    let mut at = 0usize;
    while at.saturating_add(2) <= props.len() && out.len() < 4096 {
        let begin = at;
        let Some(col) = crate::bytes::u16_le(props, at) else {
            break;
        };
        at = at.saturating_add(2);
        let Some((name, ty)) = columns.get(usize::from(col)) else {
            break;
        };
        let width = match ty {
            0..=2 => 1,
            3 | 4 => 2,
            5 | 6 | 9 => 4,
            7 | 8 | 10 => 8,
            _ => 0,
        };
        let value = if width == 0 {
            let Some(len) = u32_le(props, at) else { break };
            at = at.saturating_add(4);
            let end = at.saturating_add(to_usize(len.into()));
            let Some(bytes) = props.get(at..end) else {
                break;
            };
            at = end;
            if *ty == 14 {
                Value::Bytes(bytes.to_vec())
            } else {
                Value::Text(String::from_utf8_lossy(bytes).into_owned())
            }
        } else {
            let Some(bytes) = props.get(at..at.saturating_add(width)) else {
                break;
            };
            at = at.saturating_add(width);
            let mut raw = 0u64;
            for &b in bytes.iter().rev() {
                raw = (raw << 8) | u64::from(b);
            }
            let bits = u8::try_from(width.saturating_mul(8)).unwrap_or(64);
            match ty {
                2 => Value::Bool(raw != 0),
                9 => Value::Float(f32::from_bits(u32::try_from(raw).unwrap_or(0)).into()),
                10 => Value::Float(f64::from_bits(raw)),
                0 | 3 | 5 | 7 => {
                    let shift = 64u32.saturating_sub(u32::from(bits));
                    Value::Int {
                        value: (raw.cast_signed() << shift) >> shift,
                        bits,
                    }
                }
                _ => uint(raw, bits),
            }
        };
        out.push((
            name.clone(),
            value,
            (start.saturating_add(begin), start.saturating_add(at)),
        ));
    }
    out
}

async fn fgb_feature(cx: Cx, (body, columns): (Span, Columns)) -> Result<()> {
    if body.len > MAX_BLOB {
        return Err(Diagnostic::limit("feature too large").at(body));
    }
    let buf = cx.read(body).await?;
    let f = fb::root(&buf).ok_or_else(|| Diagnostic::malformed("bad feature table").at(body))?;
    if let Some(g) = f.table(&buf, 0) {
        let ty = g.u8(&buf, 6).unwrap_or(0);
        let mut node = Node::new("Geometry")
            .span(body.sub(to_u64(g.pos), 4))
            .value(enumv(ty, 8, GEOMETRY_TYPES));
        if let Some((n, start)) = g.vector(&buf, 1, 8) {
            let n = n / 2;
            let coords: Vec<String> = (0..n.min(4))
                .filter_map(|j| {
                    let p = start.saturating_add(j.saturating_mul(16));
                    Some(format!(
                        "({}, {})",
                        f64::from_bits(u64_le(&buf, p)?),
                        f64::from_bits(u64_le(&buf, p.saturating_add(8))?)
                    ))
                })
                .collect();
            let more = if n > 4 { ", …" } else { "" };
            node = node.summary(format!("{n} points: {}{more}", coords.join(", ")));
        }
        if let Some((n, _)) = g.vector(&buf, 7, 4) {
            node = node.summary(format!("{n} parts"));
        }
        cx.emit(node);
    }
    for (name, value, (a, b)) in properties(&buf, &columns) {
        cx.emit(leaf(
            name,
            body.sub(to_u64(a), to_u64(b.saturating_sub(a))),
            value,
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Mapbox vector tiles

/// Whether `layer` parses as a vector-tile layer (version and name).
fn is_layer(layer: &[u8]) -> bool {
    let Some(fields) = pb::all_fields(layer) else {
        return false;
    };
    let version = fields
        .iter()
        .any(|f| f.number == 15 && f.wire == 0 && matches!(f.value, 1 | 2));
    let name = fields.iter().any(|f| f.number == 1 && f.wire == 2);
    version
        && name
        && fields
            .iter()
            .all(|f| matches!((f.number, f.wire), (1..=4, 2) | (5 | 15, 0)))
}

fn mvt_probe(h: &Head<'_>) -> bool {
    if h.data.first() != Some(&0x1a) {
        return false;
    }
    let mut at = 0usize;
    let mut layers = 0u32;
    while at < h.data.len() {
        let Some(f) = pb::field(h.data, &mut at) else {
            // A layer cut off by the end of the head is fine after one
            // complete layer; otherwise the data is not a tile.
            return layers > 0 && to_u64(h.data.len()) < h.len;
        };
        if f.number != 3 || f.wire != 2 || !is_layer(f.payload(h.data)) {
            return false;
        }
        layers = layers.saturating_add(1);
    }
    layers > 0
}

declare_format!(pub MVT = "mvt", "Mapbox vector tile", ["mvt", "pbf"], "application/vnd.mapbox-vector-tile",
    Probe::Custom(mvt_probe), mvt);

const GEOM_TYPES: EnumTable = &[
    (0, "UNKNOWN"),
    (1, "POINT"),
    (2, "LINESTRING"),
    (3, "POLYGON"),
];

async fn mvt(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len > MAX_BLOB {
        return Err(Diagnostic::limit("tile too large").at(file));
    }
    let data = cx.read(file).await?;
    let mut pace = Pace::new(&cx, ITEMS_PER_UNIT);
    let mut at = 0usize;
    let mut names = Vec::new();
    while at < data.len() {
        let Some(f) = pb::field(&data, &mut at) else {
            return Err(Diagnostic::malformed("bad protobuf field").at(file.tail(to_u64(at))));
        };
        let span = file.sub(to_u64(f.start), to_u64(f.end.saturating_sub(f.start)));
        let body = file.sub(to_u64(f.body), to_u64(f.end.saturating_sub(f.body)));
        if f.number != 3 {
            cx.push(Node::new(format!("Field {}", f.number)).span(span))
                .await;
            continue;
        }
        let layer = all_fields_paced(&mut pace, f.payload(&data))
            .await
            .unwrap_or_default();
        let payload = f.payload(&data);
        let name = layer
            .iter()
            .find(|l| l.number == 1)
            .map(|l| String::from_utf8_lossy(l.payload(payload)).into_owned())
            .unwrap_or_default();
        let features = layer.iter().filter(|l| l.number == 2).count();
        names.push(name.clone());
        cx.push(
            Node::new(format!("Layer {name}"))
                .span(span)
                .summary(format!("{features} features"))
                .lazy(mvt_layer, body),
        )
        .await;
    }
    cx.annotate(format!(
        "vector tile, {} layers: {}",
        names.len(),
        names.join(", ")
    ));
    Ok(())
}

/// [`pb::all_fields`], charging the fields to `pace`.
async fn all_fields_paced(pace: &mut Pace<'_>, data: &[u8]) -> Option<Vec<pb::Field>> {
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < data.len() {
        out.push(pb::field(data, &mut at)?);
        pace.step().await;
    }
    Some(out)
}

/// Charges copying or converting `n` bytes: one item per 16 bytes.
async fn charge_bytes(pace: &mut Pace<'_>, n: usize) {
    pace.add(to_u64(n) / 16).await;
}

/// A tile value message as a value.
async fn mvt_value(pace: &mut Pace<'_>, v: &[u8]) -> Value {
    charge_bytes(pace, v.len()).await;
    let Some(f) = all_fields_paced(pace, v)
        .await
        .and_then(|f| f.into_iter().next())
    else {
        return Value::Bytes(v.to_vec());
    };
    match (f.number, f.wire) {
        (1, 2) => Value::Text(String::from_utf8_lossy(f.payload(v)).into_owned()),
        (2, 5) => Value::Float(f32::from_bits(u32::try_from(f.value).unwrap_or(0)).into()),
        (3, 1) => Value::Float(f64::from_bits(f.value)),
        (4, 0) => Value::Int {
            value: f.value.cast_signed(),
            bits: 64,
        },
        (5, 0) => uint(f.value, 64),
        (6, 0) => Value::Int {
            value: zigzag(f.value),
            bits: 64,
        },
        (7, 0) => Value::Bool(f.value != 0),
        _ => Value::Bytes(v.to_vec()),
    }
}

/// Packed varints (at most `max`), charged to `pace`.
async fn packed(pace: &mut Pace<'_>, data: &[u8], max: usize) -> Vec<u64> {
    let mut at = 0usize;
    let mut out = Vec::new();
    while at < data.len() && out.len() < max {
        let Some(v) = varint(data, &mut at) else {
            break;
        };
        out.push(v);
        pace.step().await;
    }
    out
}

/// Summarises geometry commands: command count and points.
async fn geometry_summary(pace: &mut Pace<'_>, cmds: &[u64]) -> String {
    let (mut i, mut ops, mut points) = (0usize, 0u64, 0u64);
    while let Some(&c) = cmds.get(i) {
        pace.step().await;
        let (id, count) = (c & 7, c >> 3);
        ops = ops.saturating_add(1);
        let params = if matches!(id, 1 | 2) {
            count.saturating_mul(2)
        } else {
            0
        };
        if matches!(id, 1 | 2) {
            points = points.saturating_add(count);
        }
        i = i.saturating_add(1).saturating_add(to_usize(params));
    }
    format!("{ops} commands, {points} points")
}

/// A layer's fields and its tables of keys and values.
struct MvtLayer {
    fields: Vec<pb::Field>,
    keys: Vec<String>,
    values: Vec<Value>,
}

async fn parse_layer(pace: &mut Pace<'_>, data: &[u8], body: Span) -> Result<MvtLayer> {
    let fields = all_fields_paced(pace, data)
        .await
        .ok_or_else(|| Diagnostic::malformed("bad layer").at(body))?;
    let mut keys = Vec::new();
    let mut values = Vec::new();
    for f in &fields {
        match f.number {
            3 => {
                charge_bytes(pace, f.value_len()).await;
                keys.push(String::from_utf8_lossy(f.payload(data)).into_owned());
            }
            4 => values.push(mvt_value(pace, f.payload(data)).await),
            _ => {}
        }
    }
    Ok(MvtLayer {
        fields,
        keys,
        values,
    })
}

async fn mvt_layer(cx: Cx, body: Span) -> Result<()> {
    let data = cx.read(body).await?;
    let mut pace = Pace::new(&cx, ITEMS_PER_UNIT);
    // Parsed once: paging through a large layer re-runs this expansion.
    let layer = match cx.cached::<MvtLayer>(body, "mvt-layer") {
        Some(layer) => layer,
        None => {
            let layer = Arc::new(parse_layer(&mut pace, &data, body).await?);
            cx.cache(body, "mvt-layer", layer.clone());
            layer
        }
    };
    let MvtLayer {
        fields,
        keys,
        values,
    } = &*layer;
    let mut index = 0u64;
    let (mut key, mut value) = (0usize, 0usize);
    for f in fields {
        let span = body.sub(to_u64(f.start), to_u64(f.end.saturating_sub(f.start)));
        match f.number {
            15 => cx.push(leaf("Version", span, uint(f.value, 32))).await,
            1 => {
                charge_bytes(&mut pace, f.value_len()).await;
                cx.push(leaf(
                    "Name",
                    span,
                    text(String::from_utf8_lossy(f.payload(&data))),
                ))
                .await
            }
            5 => cx.push(leaf("Extent", span, uint(f.value, 32))).await,
            3 => {
                let k = keys.get(key).cloned().unwrap_or_default();
                key = key.saturating_add(1);
                cx.push(leaf("Key", span, text(k))).await
            }
            4 => {
                let v = values
                    .get(value)
                    .cloned()
                    .unwrap_or(Value::Bytes(Vec::new()));
                value = value.saturating_add(1);
                cx.push(leaf("Value", span, v)).await
            }
            2 => {
                let payload = f.payload(&data);
                let feat = all_fields_paced(&mut pace, payload)
                    .await
                    .unwrap_or_default();
                let mut node = Node::new(format!("Feature {index}")).span(span);
                let mut parts = Vec::new();
                for g in &feat {
                    let gspan = body.sub(
                        to_u64(f.body.saturating_add(g.start)),
                        to_u64(g.end.saturating_sub(g.start)),
                    );
                    match g.number {
                        1 => parts.push(leaf("Id", gspan, uint(g.value, 64))),
                        3 => parts.push(leaf("Type", gspan, enumv(g.value, 8, GEOM_TYPES))),
                        2 => {
                            // Only the first 32 pairs are shown.
                            let tags = packed(&mut pace, g.payload(payload), 64).await;
                            let pairs: Vec<String> = tags
                                .chunks(2)
                                .take(32)
                                .map(|kv| {
                                    let k = kv
                                        .first()
                                        .and_then(|&k| keys.get(to_usize(k)))
                                        .map_or("?", String::as_str);
                                    let v = kv
                                        .get(1)
                                        .and_then(|&v| values.get(to_usize(v)))
                                        .map_or_else(|| "?".to_owned(), crate::render::value);
                                    format!("{k}={v}")
                                })
                                .collect();
                            parts.push(Node::new("Tags").span(gspan).summary(pairs.join(", ")));
                        }
                        4 => {
                            let cmds = packed(&mut pace, g.payload(payload), usize::MAX).await;
                            let summary = geometry_summary(&mut pace, &cmds).await;
                            parts.push(Node::new("Geometry").span(gspan).summary(summary));
                        }
                        _ => parts.push(Node::new(format!("Field {}", g.number)).span(gspan)),
                    }
                }
                if let Some(t) = feat.iter().find(|g| g.number == 3) {
                    node = node
                        .summary(crate::value::lookup(GEOM_TYPES, t.value).unwrap_or("UNKNOWN"));
                }
                cx.push(node.lazy(emit_nodes, std::sync::Arc::new(parts)))
                    .await;
                index = index.saturating_add(1);
            }
            n => cx.push(Node::new(format!("Field {n}")).span(span)).await,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// OpenStreetMap o5m / o5c

declare_format!(pub O5M = "o5m", "OpenStreetMap o5m/o5c", ["o5m", "o5c"], "application/x-o5m",
    Probe::Magic(&[(0, b"\xff\xe0\x04o5m2"), (0, b"\xff\xe0\x04o5c2")]), o5m);

const DATASETS: EnumTable = &[
    (0x10, "node"),
    (0x11, "way"),
    (0x12, "relation"),
    (0xdb, "bounding box"),
    (0xdc, "file timestamp"),
    (0xe0, "header"),
    (0xee, "sync"),
    (0xef, "jump"),
    (0xff, "reset"),
    (0xfe, "end of file"),
];

async fn o5m(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut nodes, mut ways, mut relations) = (0u64, 0u64, 0u64);
    let mut ids = [0i64; 3];
    while !cur.at_end() {
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        let kind = cur.u8().await?;
        if kind >= 0xf0 {
            if kind == 0xff {
                ids = [0; 3];
            }
            let name = crate::value::lookup(DATASETS, kind.into()).unwrap_or("marker");
            cx.push(Node::new(name).span(cur.since(start)).value(hex(kind, 8)))
                .await;
            if kind == 0xfe {
                break;
            }
            continue;
        }
        let peek = cur.peek(10).await?;
        let mut at = 0usize;
        let len = varint(&peek, &mut at)
            .ok_or_else(|| Diagnostic::malformed("bad length").at(cur.span(10)))?;
        cur.skip(to_u64(at));
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len);
        let span = cur.since(start);
        let name = crate::value::lookup(DATASETS, kind.into())
            .map_or_else(|| format!("dataset {kind:#04x}"), str::to_owned);
        let mut node = Node::new(name).span(span).summary(format!("{len} bytes"));
        if let Some(slot) = ids
            .get_mut(usize::from(kind.wrapping_sub(0x10)))
            .filter(|_| (0x10..=0x12).contains(&kind))
        {
            let b = cx.read(body.sub(0, 10)).await?;
            let mut p = 0usize;
            if let Some(delta) = varint(&b, &mut p) {
                *slot = slot.saturating_add(zigzag(delta));
                node = node.summary(format!("id {}, {len} bytes", *slot));
            }
            match kind {
                0x10 => nodes = nodes.saturating_add(1),
                0x11 => ways = ways.saturating_add(1),
                _ => relations = relations.saturating_add(1),
            }
        } else if kind == 0xe0 {
            node = node.value(text(String::from_utf8_lossy(
                &cx.read(body.sub(0, 16)).await?,
            )));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "o5m, {nodes} nodes, {ways} ways, {relations} relations"
    ));
    Ok(())
}
