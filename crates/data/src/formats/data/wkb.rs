//! Well-known binary geometry (OGC Simple Features / ISO 19125 WKB, and
//! PostGIS EWKB) and the GeoPackage binary geometry that wraps it.
//!
//! WKB is a byte-order byte (0 big-endian, 1 little-endian), a 32-bit
//! geometry type, then the coordinates: a point is 2 to 4 doubles, a line
//! string a count and points, a polygon a count of rings each with a count
//! and points, and the multi and collection types a count of complete WKB
//! geometries (each with its own byte order). ISO types add 1000 for Z,
//! 2000 for M and 3000 for ZM; EWKB sets 0x80000000 for Z, 0x40000000 for M
//! and 0x20000000 when a 32-bit SRID follows the type.
//!
//! A GeoPackage geometry (the blobs in a GeoPackage's feature tables) is
//! "GP", a version, a flags byte (byte order, envelope kind, empty,
//! extended), the SRS ID and an optional envelope of 4 to 8 doubles,
//! followed by the WKB.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::plural;
use crate::formats::util::{lines, val};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag};

pub static GPKG_GEOMETRY: Format = Format {
    name: "gpkg-geometry",
    title: "GeoPackage binary geometry",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Custom(gp_probe),
    dissect: crate::expander!(dissect_gp: Input),
};

pub static WKB: Format = Format {
    name: "wkb",
    title: "Well-known binary geometry",
    extensions: &["wkb", "ewkb"],
    mime: "application/octet-stream",
    probe: Probe::Never,
    dissect: crate::expander!(dissect_wkb: Input),
};

/// Nesting deeper than this is treated as malformed.
const MAX_DEPTH: u32 = 32;

const TYPES: EnumTable = &[
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

const BYTE_ORDERS: EnumTable = &[(0, "big-endian"), (1, "little-endian")];

const GP_FLAGS: FlagTable = &[
    flag(0x01, "LITTLE_ENDIAN"),
    field(0x0e, 0x02, "ENVELOPE_XY"),
    field(0x0e, 0x04, "ENVELOPE_XYZ"),
    field(0x0e, 0x06, "ENVELOPE_XYM"),
    field(0x0e, 0x08, "ENVELOPE_XYZM"),
    flag(0x10, "EMPTY"),
    flag(0x20, "EXTENDED"),
];

/// Doubles in the envelope for each envelope kind (flags bits 1-3).
fn envelope_doubles(kind: u8) -> Option<u64> {
    match kind {
        0 => Some(0),
        1 => Some(4),
        2 | 3 => Some(6),
        4 => Some(8),
        _ => None,
    }
}

/// A decoded geometry type.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Kind {
    base: u32,
    z: bool,
    m: bool,
    srid: bool,
}

impl Kind {
    fn parse(raw: u32) -> Option<Kind> {
        let ewkb = raw & 0xe000_0000;
        let iso = raw & 0x1fff_ffff;
        let (base, iso_z, iso_m) = match iso / 1000 {
            0 => (iso % 1000, false, false),
            1 => (iso % 1000, true, false),
            2 => (iso % 1000, false, true),
            3 => (iso % 1000, true, true),
            _ => return None,
        };
        if !(1..=17).contains(&base) {
            return None;
        }
        Some(Kind {
            base,
            z: iso_z || ewkb & 0x8000_0000 != 0,
            m: iso_m || ewkb & 0x4000_0000 != 0,
            srid: ewkb & 0x2000_0000 != 0,
        })
    }

    fn dims(self) -> u64 {
        2u64.saturating_add(u64::from(self.z))
            .saturating_add(u64::from(self.m))
    }

    fn name(self) -> String {
        let base = crate::value::lookup(TYPES, self.base.into()).unwrap_or("Geometry");
        match (self.z, self.m) {
            (false, false) => base.to_owned(),
            (true, false) => format!("{base} Z"),
            (false, true) => format!("{base} M"),
            (true, true) => format!("{base} ZM"),
        }
    }

    /// The layout of the body after the type (and SRID).
    fn shape(self) -> Shape {
        match self.base {
            1 => Shape::Point,
            2 | 8 => Shape::Points,
            3 | 17 => Shape::Rings,
            _ => Shape::Geometries,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Shape {
    Point,
    Points,
    Rings,
    Geometries,
}

fn u32_in(b: &[u8], le: bool) -> Option<u32> {
    let a: [u8; 4] = b.get(..4)?.try_into().ok()?;
    Some(if le {
        u32::from_le_bytes(a)
    } else {
        u32::from_be_bytes(a)
    })
}

fn f64_in(b: &[u8], le: bool) -> Option<f64> {
    let a: [u8; 8] = b.get(..8)?.try_into().ok()?;
    Some(if le {
        f64::from_le_bytes(a)
    } else {
        f64::from_be_bytes(a)
    })
}

/// A plausible WKB header at the start of `b`.
fn wkb_head_ok(b: &[u8]) -> bool {
    match b.first() {
        Some(&o @ (0 | 1)) => b
            .get(1..)
            .and_then(|t| u32_in(t, o == 1))
            .and_then(Kind::parse)
            .is_some(),
        _ => false,
    }
}

fn gp_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    if !h.starts_with(b"GP") || d.get(2) != Some(&0) {
        return false;
    }
    let Some(&flags) = d.get(3) else { return false };
    if flags & 0xc0 != 0 {
        return false;
    }
    let Some(env) = envelope_doubles((flags >> 1) & 7) else {
        return false;
    };
    let wkb = 8u64.saturating_add(env.saturating_mul(8));
    // Extended geometries carry their own format after the header.
    flags & 0x20 != 0 || (h.len > wkb && d.get(to_usize(wkb)..).is_some_and(wkb_head_ok))
}

pub async fn dissect_gp(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let head = cx.read(span.sub(0, 8)).await?;
    let flags = head.get(3).copied().unwrap_or(0);
    let le = flags & 1 != 0;
    let env_kind = (flags >> 1) & 7;
    let doubles = envelope_doubles(env_kind).ok_or_else(|| {
        Diagnostic::malformed(format!("envelope kind {env_kind}")).at(span.sub(3, 1))
    })?;
    cx.emit(
        Node::new("Magic")
            .span(span.sub(0, 2))
            .value(Value::Text("GP".into())),
    );
    cx.emit(
        Node::new("Version")
            .span(span.sub(2, 1))
            .value(val::uint(head.get(2).copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Flags")
            .span(span.sub(3, 1))
            .value(lines::flags(GP_FLAGS, flags.into(), 8)),
    );
    let srs = head.get(4..8).and_then(|b| u32_in(b, le)).unwrap_or(0);
    let srs = i32::from_ne_bytes(srs.to_ne_bytes());
    cx.emit(
        Node::new("SRS ID")
            .span(span.sub(4, 4))
            .value(val::int(srs, 32))
            .desc("The srs_id of a row in gpkg_spatial_ref_sys"),
    );
    let env_span = span.sub(8, doubles.saturating_mul(8));
    let mut summary = format!("SRS {srs}");
    if doubles > 0 {
        let env = cx.read(env_span).await?;
        const NAMES: [&str; 8] = [
            "Min X", "Max X", "Min Y", "Max Y", "Min Z", "Max Z", "Min M", "Max M",
        ];
        let names: &[&str] = match env_kind {
            3 => &["Min X", "Max X", "Min Y", "Max Y", "Min M", "Max M"],
            _ => NAMES.get(..to_usize(doubles)).unwrap_or(&NAMES),
        };
        let mut kids = Vec::new();
        for (i, name) in names.iter().enumerate() {
            let at = i.saturating_mul(8);
            if let Some(v) = env.get(at..).and_then(|b| f64_in(b, le)) {
                kids.push(
                    Node::new(*name)
                        .span(env_span.sub(to_u64(at), 8))
                        .value(Value::f64(v)),
                );
            }
        }
        cx.emit(Node::new("Envelope").span(env_span).lazy(
            crate::formats::util::arcutil::emit_nodes,
            std::sync::Arc::new(kids),
        ));
    }
    let body = span.tail(8u64.saturating_add(doubles.saturating_mul(8)));
    if flags & 0x20 != 0 {
        cx.emit(Node::new("Extended geometry").span(body));
        summary.push_str(", extended");
    } else if flags & 0x10 != 0 && body.is_empty() {
        summary.push_str(", empty");
    } else {
        let wkb = cx.read(body.sub(0, 5)).await?;
        if let Some(kind) = wkb
            .first()
            .and_then(|&o| wkb.get(1..).and_then(|t| u32_in(t, o == 1)))
            .and_then(Kind::parse)
        {
            summary = format!("{}, {summary}", kind.name());
        }
        cx.emit(embedded_as("Geometry", input.nested(body), &WKB));
    }
    if flags & 0x10 != 0 {
        summary.push_str(" (empty)");
    }
    cx.annotate(format!("GeoPackage geometry, {summary}"));
    Ok(())
}

pub async fn dissect_wkb(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let (_, kind, srid, _) = header(&cx, span, 0).await?;
    let mut summary = kind.name();
    if let Some(s) = srid {
        summary.push_str(&format!(", SRID {s}"));
    }
    cx.annotate(summary);
    let len = geometry(&cx, span, 0, 0).await?;
    if len < span.len {
        cx.diag(Diagnostic::warning(format!(
            "{} bytes after the geometry",
            span.len.saturating_sub(len)
        )));
    }
    Ok(())
}

/// The header of the geometry at `at`: byte order, kind, SRID and the
/// offset of its body.
async fn header(cx: &Cx, span: Span, at: u64) -> Result<(bool, Kind, Option<u32>, u64)> {
    let h = cx.read(span.sub(at, 9)).await?;
    let order = *h
        .first()
        .ok_or_else(|| Diagnostic::truncated(span.sub(at, 5), 0))?;
    if order > 1 {
        return Err(Diagnostic::malformed(format!("byte order {order}")).at(span.sub(at, 1)));
    }
    let le = order == 1;
    let raw = h
        .get(1..)
        .and_then(|t| u32_in(t, le))
        .ok_or_else(|| Diagnostic::truncated(span.sub(at, 5), to_u64(h.len())))?;
    let kind = Kind::parse(raw).ok_or_else(|| {
        Diagnostic::malformed(format!("geometry type {raw:#x}"))
            .at(span.sub(at.saturating_add(1), 4))
    })?;
    let (srid, body) = if kind.srid {
        let s = h
            .get(5..)
            .and_then(|t| u32_in(t, le))
            .ok_or_else(|| Diagnostic::truncated(span.sub(at, 9), to_u64(h.len())))?;
        (Some(s), at.saturating_add(9))
    } else {
        (None, at.saturating_add(5))
    };
    Ok((le, kind, srid, body))
}

/// The length of the geometry at `at`, walking nested geometries
/// iteratively: geometries are stored depth first, so it is enough to
/// count how many remain, with a checkpoint per element.
async fn length(cx: &Cx, span: Span, at: u64) -> Result<u64> {
    let mut pos = at;
    let mut pending: u64 = 1;
    while pending > 0 {
        cx.checkpoint().await;
        pending = pending.saturating_sub(1);
        let (le, kind, _, body) = header(cx, span, pos).await?;
        let point = kind.dims().saturating_mul(8);
        pos = match kind.shape() {
            Shape::Point => body.saturating_add(point),
            Shape::Points => {
                let n = count(cx, span, body, le).await?;
                body.saturating_add(4)
                    .saturating_add(n.saturating_mul(point))
            }
            Shape::Rings => {
                let rings = count(cx, span, body, le).await?;
                let mut p = body.saturating_add(4);
                for _ in 0..rings {
                    cx.checkpoint().await;
                    let n = count(cx, span, p, le).await?;
                    p = p.saturating_add(4).saturating_add(n.saturating_mul(point));
                    if p > span.len {
                        return Err(Diagnostic::truncated(
                            span.sub(body, p.saturating_sub(body)),
                            span.len.saturating_sub(body),
                        ));
                    }
                }
                p
            }
            Shape::Geometries => {
                let n = count(cx, span, body, le).await?;
                // At least 5 bytes each: a count past the end is rejected.
                if n.saturating_mul(5) > span.len.saturating_sub(body.saturating_add(4)) {
                    return Err(Diagnostic::malformed(format!("{n} geometries cannot fit"))
                        .at(span.sub(body, 4)));
                }
                pending = pending.saturating_add(n);
                body.saturating_add(4)
            }
        };
        if pos > span.len {
            return Err(Diagnostic::truncated(
                span.sub(at, pos.saturating_sub(at)),
                span.len.saturating_sub(at),
            ));
        }
    }
    Ok(pos.saturating_sub(at))
}

async fn count(cx: &Cx, span: Span, at: u64, le: bool) -> Result<u64> {
    let b = cx.read(span.sub(at, 4)).await?;
    u32_in(&b, le)
        .map(u64::from)
        .ok_or_else(|| Diagnostic::truncated(span.sub(at, 4), to_u64(b.len())))
}

fn coord_text(v: &[f64]) -> String {
    let parts: Vec<String> = v.iter().map(|x| x.to_string()).collect();
    parts.join(" ")
}

/// Emits the geometry at `at` (its header fields and body) and returns
/// its length; nested geometries become lazy children.
async fn geometry(cx: &Cx, span: Span, at: u64, depth: u32) -> Result<u64> {
    let (le, kind, srid, body) = header(cx, span, at).await?;
    cx.emit(
        Node::new("Byte order")
            .span(span.sub(at, 1))
            .value(val::enumv(u8::from(le), 8, BYTE_ORDERS)),
    );
    let raw = cx.read(span.sub(at.saturating_add(1), 4)).await?;
    cx.emit(
        Node::new("Type")
            .span(span.sub(at.saturating_add(1), 4))
            .value(val::hex(u32_in(&raw, le).unwrap_or(0), 32))
            .summary(kind.name()),
    );
    if let Some(s) = srid {
        cx.emit(
            Node::new("SRID")
                .span(span.sub(at.saturating_add(5), 4))
                .value(val::uint(s, 32)),
        );
    }
    let dims = kind.dims();
    let point = dims.saturating_mul(8);
    let len = length(cx, span, at).await?;
    let end = at.saturating_add(len);
    match kind.shape() {
        Shape::Point => {
            let b = cx.read(span.sub(body, point)).await?;
            let names: &[&str] = match (kind.z, kind.m) {
                (false, false) => &["X", "Y"],
                (true, false) => &["X", "Y", "Z"],
                (false, true) => &["X", "Y", "M"],
                (true, true) => &["X", "Y", "Z", "M"],
            };
            for (i, name) in names.iter().enumerate() {
                let o = i.saturating_mul(8);
                if let Some(v) = b.get(o..).and_then(|t| f64_in(t, le)) {
                    cx.emit(
                        Node::new(*name)
                            .span(span.sub(body.saturating_add(to_u64(o)), 8))
                            .value(Value::f64(v)),
                    );
                }
            }
        }
        Shape::Points => {
            let n = count(cx, span, body, le).await?;
            cx.emit(
                Node::new("Point count")
                    .span(span.sub(body, 4))
                    .value(val::uint(n, 32)),
            );
            let pts = span.sub(body.saturating_add(4), n.saturating_mul(point));
            cx.emit(
                Node::new("Points")
                    .span(pts)
                    .summary(format!("{n}"))
                    .lazy(points, (pts, le, dims)),
            );
        }
        Shape::Rings => {
            let rings = count(cx, span, body, le).await?;
            cx.emit(
                Node::new("Ring count")
                    .span(span.sub(body, 4))
                    .value(val::uint(rings, 32)),
            );
            let mut p = body.saturating_add(4);
            for r in 0..rings {
                let n = count(cx, span, p, le).await?;
                let ring = span.sub(p, n.saturating_mul(point).saturating_add(4));
                let pts = ring.tail(4);
                let label = if r == 0 {
                    "exterior".to_owned()
                } else {
                    "interior".to_owned()
                };
                cx.push(
                    Node::new(format!("Ring {r}"))
                        .span(ring)
                        .summary(format!("{label}, {n_point}", n_point = plural(n, "point")))
                        .lazy(points, (pts, le, dims)),
                )
                .await;
                p = p.saturating_add(ring.len);
            }
        }
        Shape::Geometries => {
            let n = count(cx, span, body, le).await?;
            cx.emit(
                Node::new("Geometry count")
                    .span(span.sub(body, 4))
                    .value(val::uint(n, 32)),
            );
            let mut p = body.saturating_add(4);
            for i in 0..n {
                if p >= end {
                    break;
                }
                let child = length(cx, span, p).await?;
                let (_, ck, _, _) = header(cx, span, p).await?;
                let cspan = span.sub(p, child);
                cx.push(
                    Node::new(format!("Geometry {i}"))
                        .span(cspan)
                        .summary(ck.name())
                        .lazy(nested, (span, p, depth.saturating_add(1))),
                )
                .await;
                p = p.saturating_add(child);
            }
        }
    }
    Ok(len)
}

async fn nested(cx: Cx, (span, at, depth): (Span, u64, u32)) -> Result<()> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::malformed("geometries nested too deeply"));
    }
    geometry_boxed(&cx, span, at, depth).await.map(|_| ())
}

fn geometry_boxed<'a>(
    cx: &'a Cx,
    span: Span,
    at: u64,
    depth: u32,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<u64>> + Send + 'a>> {
    Box::pin(geometry(cx, span, at, depth))
}

/// The points of a line string or ring.
async fn points(cx: Cx, (span, le, dims): (Span, bool, u64)) -> Result<()> {
    let point = dims.saturating_mul(8);
    let n = span.len.checked_div(point).unwrap_or(0);
    cx.set_count(Count::Exact(n));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < n {
        let at = i;
        cx.mark(move || at);
        let ps = span.sub(i.saturating_mul(point), point);
        let b = cx.read(ps).await?;
        let coords: Vec<f64> = (0..to_usize(dims))
            .filter_map(|k| b.get(k.saturating_mul(8)..).and_then(|t| f64_in(t, le)))
            .collect();
        cx.push(
            Node::new(format!("Point {i}"))
                .span(ps)
                .summary(format!("({})", coord_text(&coords))),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}
