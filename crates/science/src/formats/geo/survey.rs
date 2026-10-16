//! Survey and observation data: ESRI Shapefiles with their dBase tables,
//! LAS point clouds, and GRIB and BUFR meteorological messages.

use crate::bytes::{u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt;
use crate::formats::util::val::uint;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// ESRI Shapefile (.shp / .shx) and dBase tables (.dbf)

const SHAPE_TYPES: EnumTable = &[
    (0, "Null"),
    (1, "Point"),
    (3, "PolyLine"),
    (5, "Polygon"),
    (8, "MultiPoint"),
    (11, "PointZ"),
    (13, "PolyLineZ"),
    (15, "PolygonZ"),
    (18, "MultiPointZ"),
    (21, "PointM"),
    (23, "PolyLineM"),
    (25, "PolygonM"),
    (28, "MultiPointM"),
    (31, "MultiPatch"),
];

fn shape_header(h: &Head<'_>) -> bool {
    h.at(0, b"\x00\x00\x27\x0a") && u32_le(h.data, 28) == Some(1000)
}

/// A shapefile or index with no records: just the 100-byte header, the
/// same bytes in the `.shp` and the `.shx` (GDAL writes them identical).
/// Only the name tells them apart, so neither first-phase probe takes it;
/// the second phase does ([`SHX_DEEP`], then [`SHP_DEEP`]).
fn header_only(h: &Head<'_>) -> bool {
    h.len_known && h.len == 100
}

fn shx_probe(h: &Head<'_>) -> bool {
    shape_header(h)
        && h.len_known
        && h.len > 100
        && h.len.saturating_sub(100).is_multiple_of(8)
        && u32_be(h.data, 100) == Some(50)
}

fn shp_probe(h: &Head<'_>) -> bool {
    shape_header(h) && !header_only(h)
}

declare_format!(pub SHX = "shx", "ESRI shapefile index", ["shx"], "application/x-esri-shape-index",
    Probe::Custom(shx_probe), shx);
declare_format!(pub SHP = "shp", "ESRI shapefile", ["shp"], "application/x-esri-shape",
    Probe::Custom(shp_probe), shp);

/// The second phase: a header-only shapefile named `*.shx` is an index.
pub static SHX_DEEP: crate::formats::DeepProbe = crate::formats::DeepProbe {
    format: &SHX,
    tail: false,
    over: &[],
    probe: |d| shape_header(d.head) && header_only(d.head) && d.extension_is("shx"),
};

/// The second phase: any other header-only shapefile.
pub static SHP_DEEP: crate::formats::DeepProbe = crate::formats::DeepProbe {
    format: &SHP,
    tail: false,
    over: &[],
    probe: |d| shape_header(d.head) && header_only(d.head),
};

record! {
    pub struct ShapeHeader {
        code: u32 "File code" .desc("9994"),
        _unused: bytes[20] "Unused",
        length: u32 "File length (16-bit words)",
    }
}

record! {
    pub struct ShapeBounds {
        version: u32 "Version",
        shape: u32 "Shape type" .enumeration(SHAPE_TYPES),
        x_min: f64 "X min",
        y_min: f64 "Y min",
        x_max: f64 "X max",
        y_max: f64 "Y max",
        z_min: f64 "Z min",
        z_max: f64 "Z max",
        m_min: f64 "M min",
        m_max: f64 "M max",
    }
}

async fn shape_common(cx: &Cx, file: Span) -> Result<ShapeBounds> {
    cx.emit(ShapeHeader::node(
        "File header",
        file.sub(0, ShapeHeader::SIZE),
        BE,
    ));
    let span = file.sub(ShapeHeader::SIZE, ShapeBounds::SIZE);
    let b: ShapeBounds = read_record(cx, span, LE).await?;
    cx.emit(ShapeBounds::node("Bounds", span, LE));
    Ok(b)
}

async fn shp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let b = shape_common(&cx, file).await?;
    let records = file.tail(100);
    cx.emit(
        Node::new("Records")
            .span(records)
            .lazy(shp_records, records),
    );
    let kind = lookup(SHAPE_TYPES, b.shape.into()).unwrap_or("unknown shapes");
    cx.annotate(format!(
        "{kind}, x {}..{}, y {}..{}",
        b.x_min, b.x_max, b.y_min, b.y_max
    ));
    Ok(())
}

record! {
    pub struct ShpRecordHeader {
        number: u32 "Record number",
        words: u32 "Content length (16-bit words)",
    }
}

/// M values below this mean "no data" (ESRI Shapefile Technical
/// Description, 1998, p. 2).
const SHP_NO_DATA: f64 = -1e38;

/// Elements decoded per read when listing a coordinate array.
const SHP_BATCH: u64 = 256;

const MULTIPATCH_PARTS: EnumTable = &[
    (0, "Triangle strip"),
    (1, "Triangle fan"),
    (2, "Outer ring"),
    (3, "Inner ring"),
    (4, "First ring"),
    (5, "Ring"),
];

fn num(v: f64) -> String {
    crate::render::value(&Value::f64(v))
}

fn m_text(v: f64) -> String {
    if v < SHP_NO_DATA {
        "no data".to_owned()
    } else {
        num(v)
    }
}

/// The base shape of a type: 0 null, 1 point, 3 polyline, 5 polygon, 8
/// multipoint, 31 multipatch (Z and M variants map onto these).
fn shape_base(kind: u32) -> Option<u32> {
    match kind {
        0 => Some(0),
        1 | 11 | 21 => Some(1),
        3 | 13 | 23 => Some(3),
        5 | 15 | 25 => Some(5),
        8 | 18 | 28 => Some(8),
        31 => Some(31),
        _ => None,
    }
}

fn shape_has_z(kind: u32) -> bool {
    matches!(kind, 11 | 13 | 15 | 18 | 31)
}

fn shape_has_m(kind: u32) -> bool {
    matches!(kind, 21 | 23 | 25 | 28)
}

/// A record's one-line summary from the start of its content.
fn shp_summary(content: &[u8]) -> String {
    let f = |off: usize| crate::bytes::f64_le(content, off).map_or_else(|| "?".to_owned(), num);
    let Some(kind) = u32_le(content, 0) else {
        return "empty".to_owned();
    };
    let name = lookup(SHAPE_TYPES, kind.into()).unwrap_or("unknown shape");
    let count = |off: usize, noun: &str| {
        u32_le(content, off).map_or_else(|| format!("? {noun}s"), |n| fmt::plural(n, noun))
    };
    match shape_base(kind) {
        Some(1) if kind == 11 => format!("{name} ({}, {}, {})", f(4), f(12), f(20)),
        Some(1) => format!("{name} ({}, {})", f(4), f(12)),
        Some(8) => format!("{name}, {}", count(36, "point")),
        Some(3 | 5 | 31) => format!("{name}, {}, {}", count(36, "part"), count(40, "point")),
        _ => name.to_owned(),
    }
}

async fn shp_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    if let Some(pos) = cx.resume::<u64>() {
        cur.seek(pos);
    }
    while cur.remaining() >= 8 {
        cx.progress_in(span, span.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        cx.mark(move || start);
        let number = cur.u32().await?;
        let words = cur.u32().await?;
        let len = u64::from(words).saturating_mul(2);
        let content = cur.span(len);
        let head = cx.read_avail(content.sub(0, 44)).await?;
        cur.skip(len);
        let mut node = Node::new(format!("Record {number}"))
            .span(cur.since(start))
            .summary(shp_summary(&head))
            .lazy(shp_record, (cur.since(start), content));
        if content.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(content.source, content.offset, len),
                content.len,
            ));
        }
        cx.push(node).await;
    }
    if !cur.at_end() {
        cx.diag(Diagnostic::malformed("trailing bytes after the last record").at(cur.span(8)));
    }
    Ok(())
}

/// Reads a little-endian f64 and emits it as a field.
async fn shp_f64(cx: &Cx, cur: &mut Cursor<'_>, name: &'static str) -> Result<f64> {
    let span = cur.span(8);
    let v = f64::from_bits(cur.u64().await?);
    cx.emit(Node::new(name).span(span).value(Value::f64(v)));
    Ok(v)
}

/// Reads a little-endian u32 count and emits it as a field.
async fn shp_count(cx: &Cx, cur: &mut Cursor<'_>, name: &'static str) -> Result<u64> {
    let span = cur.span(4);
    let v = cur.u32().await?;
    cx.emit(Node::new(name).span(span).value(uint(v, 32)));
    Ok(u64::from(v))
}

/// Reads a (min, max) pair as one field.
async fn shp_range(cx: &Cx, cur: &mut Cursor<'_>, name: &'static str, m: bool) -> Result<()> {
    let span = cur.span(16);
    let lo = f64::from_bits(cur.u64().await?);
    let hi = f64::from_bits(cur.u64().await?);
    let text = if m {
        format!("{}..{}", m_text(lo), m_text(hi))
    } else {
        format!("{}..{}", num(lo), num(hi))
    };
    cx.emit(Node::new(name).span(span).summary(text));
    Ok(())
}

#[derive(Clone, Copy, Debug)]
enum ShpArray {
    /// Part start indices, given the total point count.
    Parts(u64),
    PartTypes,
    Points,
    Z,
    M,
}

impl ShpArray {
    fn size(self) -> u64 {
        match self {
            ShpArray::Parts(_) | ShpArray::PartTypes => 4,
            ShpArray::Points => 16,
            ShpArray::Z | ShpArray::M => 8,
        }
    }
}

/// Emits the node for an array of `n` elements at the cursor and skips it;
/// an array that overruns the record ends the decode with an error.
fn shp_array(
    cx: &Cx,
    cur: &mut Cursor<'_>,
    name: &'static str,
    n: u64,
    kind: ShpArray,
) -> Result<()> {
    let len = n.saturating_mul(kind.size());
    let region = cur.region();
    let span = region.sub_exact(cur.pos(), len).map_err(|_| {
        Diagnostic::truncated(
            Span::new(region.source, region.offset.saturating_add(cur.pos()), len),
            cur.remaining(),
        )
    })?;
    let mut node = Node::new(name).span(span).summary(match kind {
        ShpArray::Parts(_) | ShpArray::PartTypes => fmt::plural(n, "part"),
        ShpArray::Points => fmt::plural(n, "point"),
        ShpArray::Z | ShpArray::M => fmt::plural(n, "value"),
    });
    if n > 0 {
        node = node.lazy(shp_list, (span, kind));
    }
    cx.emit(node);
    cur.skip(len);
    Ok(())
}

/// Lists the elements of a coordinate array, a batch per read.
async fn shp_list(cx: Cx, (span, kind): (Span, ShpArray)) -> Result<()> {
    let size = kind.size();
    let n = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(n));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < n {
        let batch = SHP_BATCH.min(n.saturating_sub(i));
        // One element more, for the end of the batch's last part.
        let extra = u64::from(matches!(kind, ShpArray::Parts(_)) && i.saturating_add(batch) < n);
        let data = cx
            .read(span.sub(
                i.saturating_mul(size),
                batch.saturating_add(extra).saturating_mul(size),
            ))
            .await?;
        for k in 0..batch {
            let at = i;
            cx.mark(move || at);
            let off = crate::bytes::to_usize(k.saturating_mul(size));
            let espan = span.sub(i.saturating_mul(size), size);
            let f =
                |o: usize| crate::bytes::f64_le(&data, off.saturating_add(o)).unwrap_or(f64::NAN);
            let node =
                match kind {
                    ShpArray::Points => Node::new(format!("Point {i}"))
                        .span(espan)
                        .summary(format!("({}, {})", num(f(0)), num(f(8)))),
                    ShpArray::Z => Node::new(format!("Z {i}"))
                        .span(espan)
                        .value(Value::f64(f(0))),
                    ShpArray::M => {
                        let v = f(0);
                        let node = Node::new(format!("M {i}")).span(espan).value(Value::f64(v));
                        if v < SHP_NO_DATA {
                            node.summary("no data")
                        } else {
                            node
                        }
                    }
                    ShpArray::Parts(points) => {
                        let first = u32_le(&data, off).map_or(0, u64::from);
                        let end = if extra == 0 && k.saturating_add(1) == batch {
                            points
                        } else {
                            u32_le(&data, off.saturating_add(4)).map_or(points, u64::from)
                        };
                        Node::new(format!("Part {i}"))
                            .span(espan)
                            .value(uint(first, 32))
                            .summary(format!(
                                "points {first}..{end}, {}",
                                fmt::count(end.saturating_sub(first), "point", "points")
                            ))
                    }
                    ShpArray::PartTypes => {
                        let t = u32_le(&data, off).unwrap_or(u32::MAX);
                        Node::new(format!("Part {i} type"))
                            .span(espan)
                            .value(Value::Enum {
                                raw: t.into(),
                                bits: 32,
                                name: lookup(MULTIPATCH_PARTS, t.into()).map(Into::into),
                            })
                    }
                };
            cx.push(node).await;
            i = i.saturating_add(1);
        }
    }
    Ok(())
}

/// A record's header and geometry (ESRI Shapefile Technical Description,
/// 1998, pp. 5-21).
async fn shp_record(cx: Cx, (record, content): (Span, Span)) -> Result<()> {
    cx.emit(ShpRecordHeader::node("Record header", record.sub(0, 8), BE));
    let mut cur = Cursor::new(&cx, content, LE);
    let span = cur.span(4);
    let kind = cur.u32().await?;
    cx.emit(Node::new("Shape type").span(span).value(Value::Enum {
        raw: kind.into(),
        bits: 32,
        name: lookup(SHAPE_TYPES, kind.into()).map(Into::into),
    }));
    let Some(base) = shape_base(kind) else {
        return Err(Diagnostic::unsupported(format!("shape type {kind}")).at(span));
    };
    let z = shape_has_z(kind);
    let m = shape_has_m(kind);
    match base {
        0 => {}
        1 => {
            shp_f64(&cx, &mut cur, "X").await?;
            shp_f64(&cx, &mut cur, "Y").await?;
            if z {
                shp_f64(&cx, &mut cur, "Z").await?;
            }
            // M is optional in PointZ.
            if m || (z && cur.remaining() >= 8) {
                let span = cur.span(8);
                let v = f64::from_bits(cur.u64().await?);
                let node = Node::new("M").span(span).value(Value::f64(v));
                cx.emit(if v < SHP_NO_DATA {
                    node.summary("no data")
                } else {
                    node
                });
            }
        }
        _ => {
            let span = cur.span(32);
            let x_min = f64::from_bits(cur.u64().await?);
            let y_min = f64::from_bits(cur.u64().await?);
            let x_max = f64::from_bits(cur.u64().await?);
            let y_max = f64::from_bits(cur.u64().await?);
            cx.emit(Node::new("Box").span(span).summary(format!(
                "x {}..{}, y {}..{}",
                num(x_min),
                num(x_max),
                num(y_min),
                num(y_max)
            )));
            let parts = if base == 8 {
                0
            } else {
                shp_count(&cx, &mut cur, "Number of parts").await?
            };
            let points = shp_count(&cx, &mut cur, "Number of points").await?;
            if base != 8 {
                shp_array(&cx, &mut cur, "Parts", parts, ShpArray::Parts(points))?;
            }
            if base == 31 {
                shp_array(&cx, &mut cur, "Part types", parts, ShpArray::PartTypes)?;
            }
            shp_array(&cx, &mut cur, "Points", points, ShpArray::Points)?;
            if z {
                shp_range(&cx, &mut cur, "Z range", false).await?;
                shp_array(&cx, &mut cur, "Z values", points, ShpArray::Z)?;
            }
            // M is optional after Z.
            if m || (z && !cur.at_end()) {
                shp_range(&cx, &mut cur, "M range", true).await?;
                shp_array(&cx, &mut cur, "M values", points, ShpArray::M)?;
            }
        }
    }
    if !cur.at_end() {
        cx.emit(
            Node::new("Unused")
                .span(content.tail(cur.pos()))
                .diag(Diagnostic::warning("bytes after the shape")),
        );
    }
    Ok(())
}

async fn shx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let b = shape_common(&cx, file).await?;
    let count = file.len.saturating_sub(100) / 8;
    cx.emit(
        Node::new("Index")
            .span(file.tail(100))
            .summary(crate::formats::util::fmt::plural(count, "record"))
            .lazy(shx_index, file.tail(100)),
    );
    let kind = lookup(SHAPE_TYPES, b.shape.into()).unwrap_or("unknown shapes");
    cx.annotate(format!("index of {count} {kind} records"));
    Ok(())
}

async fn shx_index(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 8;
    cx.set_count(Count::Exact(count));
    let mut cur = Cursor::new(&cx, span, BE);
    for i in 0..count {
        let at = cur.span(8);
        let offset = cur.u32().await?;
        let words = cur.u32().await?;
        cx.push(
            Node::new(format!("Record {}", i.saturating_add(1)))
                .span(at)
                .summary(format!(
                    "offset {:#x}, {} bytes",
                    u64::from(offset).saturating_mul(2),
                    u64::from(words).saturating_mul(2)
                )),
        )
        .await;
    }
    Ok(())
}

const DBF_VERSIONS: EnumTable = &[
    (0x02, "FoxBASE"),
    (0x03, "dBase III"),
    (0x04, "dBase IV"),
    (0x05, "dBase V"),
    (0x30, "Visual FoxPro"),
    (0x31, "Visual FoxPro (autoincrement)"),
    (0x32, "Visual FoxPro (varchar)"),
    (0x43, "dBase IV SQL table"),
    (0x63, "dBase IV SQL system"),
    (0x83, "dBase III with memo"),
    (0x8b, "dBase IV with memo"),
    (0x8e, "dBase IV with SQL table"),
    (0xcb, "dBase IV SQL table with memo"),
    (0xf5, "FoxPro with memo"),
    (0xfb, "FoxBASE"),
];

/// Common language driver IDs (byte 29), as dbfread and GDAL map them.
const DBF_CODE_PAGES: EnumTable = &[
    (0x00, "none"),
    (0x01, "CP437 (US MS-DOS)"),
    (0x02, "CP850 (international MS-DOS)"),
    (0x03, "CP1252 (Windows ANSI)"),
    (0x04, "Mac Roman"),
    (0x57, "CP1252 (ANSI)"),
    (0x64, "CP852 (Eastern European MS-DOS)"),
    (0x65, "CP866 (Russian MS-DOS)"),
    (0x66, "CP865 (Nordic MS-DOS)"),
    (0x67, "CP861 (Icelandic MS-DOS)"),
    (0x6a, "CP737 (Greek MS-DOS)"),
    (0x6b, "CP857 (Turkish MS-DOS)"),
    (0x78, "CP950 (Traditional Chinese)"),
    (0x79, "CP949 (Korean)"),
    (0x7a, "CP936 (Simplified Chinese)"),
    (0x7b, "CP932 (Japanese)"),
    (0x7c, "CP874 (Thai)"),
    (0x7d, "CP1255 (Hebrew)"),
    (0x7e, "CP1256 (Arabic)"),
    (0xc8, "CP1250 (Eastern European Windows)"),
    (0xc9, "CP1251 (Russian Windows)"),
    (0xca, "CP1254 (Turkish Windows)"),
    (0xcb, "CP1253 (Greek Windows)"),
];

/// Visual FoxPro versions, whose header ends with a 263-byte database
/// backlink after the field terminator.
fn dbf_vfp(version: u8) -> bool {
    matches!(version, 0x30..=0x32)
}

/// Size of the VFP database backlink (the path of the owning .dbc).
const DBF_BACKLINK: u64 = 263;

/// Number of 32-byte field descriptors before the 0x0D terminator in a
/// header of `header` bytes (`head` holds at least its start), as
/// shapelib, GDAL and dbfread find them. `None` if no terminator is found
/// where a descriptor could start.
fn dbf_field_count(head: &[u8], header: u64) -> Option<u64> {
    let mut at = DbfHeader::SIZE;
    let mut n = 0u64;
    while at < header {
        match head.get(crate::bytes::to_usize(at))? {
            0x0d => return Some(n),
            _ => {
                at = at.saturating_add(DbfField::SIZE);
                n = n.saturating_add(1);
            }
        }
    }
    None
}

fn dbf_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(&v), Some(&mm), Some(&dd)) = (d.first(), d.get(2), d.get(3)) else {
        return false;
    };
    let header = u16_le(d, 8).unwrap_or(0);
    let record = u16_le(d, 10).unwrap_or(0);
    let records = u32_le(d, 4).unwrap_or(0);
    // The field terminator follows the last descriptor; in Visual FoxPro the
    // header goes on with the database backlink, elsewhere it ends there.
    let fits = |fields: u64| {
        let end = DbfHeader::SIZE
            .saturating_add(fields.saturating_mul(DbfField::SIZE))
            .saturating_add(1);
        let end = if dbf_vfp(v) {
            end.saturating_add(DBF_BACKLINK)
        } else {
            end
        };
        fields > 0 && end <= u64::from(header)
    };
    lookup(DBF_VERSIONS, v.into()).is_some()
        && (1..=12).contains(&mm)
        && (1..=31).contains(&dd)
        && header >= 65
        && record > 0
        && dbf_field_count(d, header.into()).is_some_and(fits)
        && u64::from(records)
            .saturating_mul(record.into())
            .saturating_add(header.into())
            <= h.len.saturating_add(1)
}

declare_format!(pub DBF = "dbf", "dBase table", ["dbf"], "application/x-dbf",
    Probe::Custom(dbf_probe), dbf);

/// The last-update year: dBase counts from 1900 (126 is 2026), Visual
/// FoxPro and Python's `dbf` for VFP tables store the year modulo 100 (26).
fn dbf_year(y: u8) -> u16 {
    if y < 80 {
        2000u16.saturating_add(y.into())
    } else {
        1900u16.saturating_add(y.into())
    }
}

record! {
    pub struct DbfHeader {
        version: u8 "Version" .enumeration(DBF_VERSIONS),
        year: u8 "Last update: year"
            .desc("Years since 1900 as dBase, shapelib and GDAL write it; Visual FoxPro writes the year modulo 100, so values below 80 are read as 20xx (as dbfread does)")
            .with(|&y, node| node.summary(dbf_year(y).to_string())),
        month: u8 "Last update: month",
        day: u8 "Last update: day",
        records: u32 "Records",
        header: u16 "Header size",
        record: u16 "Record size",
        _reserved: bytes[16] "Reserved",
        flags: u8 "Table flags" .hex(),
        code_page: u8 "Code page (language driver ID)" .enumeration(DBF_CODE_PAGES),
        _reserved2: bytes[2] "Reserved",
    }
}

record! {
    pub struct DbfField {
        name: ascii[11] "Name",
        kind: ascii[1] "Type",
        displacement: u32 "Displacement",
        length: u8 "Length",
        decimals: u8 "Decimal places",
        flags: u8 "Flags" .hex(),
        _reserved: bytes[13] "Reserved",
    }
}

async fn dbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: DbfHeader = read_record(&cx, file.sub(0, DbfHeader::SIZE), LE).await?;
    cx.emit(DbfHeader::node("Header", file.sub(0, DbfHeader::SIZE), LE));
    // Descriptors run up to the 0x0D terminator (not to the header size:
    // VFP adds a backlink after it, and some writers pad).
    let header_span = file.sub(0, h.header.into());
    let head = cx.read_avail(header_span).await?;
    let count = dbf_field_count(&head, h.header.into())
        .unwrap_or_else(|| u64::from(h.header).saturating_sub(33) / DbfField::SIZE);
    let mut fields = Vec::new();
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(DbfHeader::SIZE);
    for _ in 0..count {
        let (f, span) = cur.record::<DbfField>().await?;
        fields.push((f.name.clone(), f.kind.clone(), u64::from(f.length), span));
    }
    let descriptors = file.sub(DbfHeader::SIZE, count.saturating_mul(DbfField::SIZE));
    cx.emit(
        Node::new("Fields")
            .span(descriptors)
            .summary(crate::formats::util::fmt::plural(count, "field"))
            .lazy(dbf_fields, descriptors),
    );
    let after = DbfHeader::SIZE.saturating_add(count.saturating_mul(DbfField::SIZE));
    if head.get(crate::bytes::to_usize(after)) == Some(&0x0d) {
        cx.emit(Node::new("Field terminator").span(file.sub(after, 1)));
        let rest = u64::from(h.header).saturating_sub(after.saturating_add(1));
        if rest > 0 {
            let at = file.sub(after.saturating_add(1), rest);
            let name = if dbf_vfp(h.version) && rest >= DBF_BACKLINK {
                "Database backlink"
            } else {
                "Header padding"
            };
            let bytes = cx.read_avail(at).await?;
            let path = String::from_utf8_lossy(&bytes)
                .trim_end_matches('\0')
                .to_owned();
            let node = Node::new(name).span(at);
            cx.emit(if path.is_empty() || path.contains('\0') {
                node.summary(format!("{rest} bytes"))
            } else {
                node.value(crate::formats::util::val::text(path))
            });
        }
    }
    let records = file.sub(
        h.header.into(),
        u64::from(h.records).saturating_mul(h.record.into()),
    );
    cx.emit(
        Node::new("Records")
            .span(records)
            .summary(crate::formats::util::fmt::plural(h.records, "record"))
            .lazy(
                dbf_records,
                (
                    records,
                    u64::from(h.record),
                    dbf_vfp(h.version),
                    fields.clone(),
                ),
            ),
    );
    let version = lookup(DBF_VERSIONS, h.version.into()).unwrap_or("dBase");
    let names: Vec<String> = fields.iter().map(|f| f.0.clone()).collect();
    cx.annotate(format!(
        "{version}, {} × [{}]",
        crate::formats::util::fmt::plural(h.records, "record"),
        names.join(", ")
    ));
    Ok(())
}

async fn dbf_fields(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= DbfField::SIZE {
        let (f, at) = cur.record::<DbfField>().await?;
        cx.push(
            DbfField::node(f.name.clone(), at, LE).summary(format!("{} ({})", f.kind, f.length)),
        )
        .await;
    }
    Ok(())
}

/// Field name, type, length and descriptor span.
type DbfFields = Vec<(String, String, u64, Span)>;

/// The text of one field value. Visual FoxPro stores some types in binary:
/// Integer (i32), Double (f64), Currency (i64 in units of 1/10000),
/// DateTime (Julian day and milliseconds since midnight, u32 each) and
/// memo block numbers (u32); the rest are text in every dialect.
fn dbf_value(kind: &str, vfp: bool, b: &[u8]) -> String {
    use crate::bytes::{u32_le, u64_le};
    let binary = match (kind, b.len()) {
        (_, _) if !vfp => None,
        ("I", 4) => u32_le(b, 0).map(|v| (v as i32).to_string()),
        ("B", 8) => u64_le(b, 0).map(|v| f64::from_bits(v).to_string()),
        ("Y", 8) => u64_le(b, 0).map(|v| {
            let v = v as i64;
            let sign = if v < 0 { "-" } else { "" };
            let abs = v.unsigned_abs();
            format!("{sign}{}.{:04}", abs / 10_000, abs % 10_000)
        }),
        ("T", 8) => match (u32_le(b, 0), u32_le(b, 4)) {
            (Some(0), _) => Some(String::new()),
            (Some(jd), Some(ms)) => {
                let days =
                    i64::from(jd).saturating_sub(crate::formats::util::civil::UNIX_JULIAN_DAY);
                let secs = i64::from(ms / 1000);
                let date = crate::formats::util::civil::date(days.saturating_mul(86_400));
                Some(format!(
                    "{date} {:02}:{:02}:{:02}",
                    secs / 3600,
                    secs % 3600 / 60,
                    secs % 60
                ))
            }
            _ => None,
        },
        ("M" | "G" | "W", 4) => u32_le(b, 0).map(|v| {
            if v == 0 {
                String::new()
            } else {
                format!("memo block {v}")
            }
        }),
        _ => None,
    };
    binary.unwrap_or_else(|| String::from_utf8_lossy(b).trim().to_owned())
}

async fn dbf_records(
    cx: Cx,
    (span, size, vfp, fields): (Span, u64, bool, DbfFields),
) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let record = span.sub(i.saturating_mul(size), size);
        let bytes = cx.read(record).await?;
        let mut at = 1usize;
        let mut values = Vec::new();
        for (name, kind, len, _) in &fields {
            let len = crate::bytes::to_usize(*len);
            if vfp && kind == "0" {
                // _NullFlags, VFP's hidden bit map of null fields.
                at = at.saturating_add(len);
                continue;
            }
            let raw = bytes.get(at..at.saturating_add(len)).unwrap_or_default();
            let value = dbf_value(kind, vfp, raw);
            values.push(format!("{name}={value}"));
            at = at.saturating_add(len);
        }
        let deleted = bytes.first() == Some(&b'*');
        cx.push(
            Node::new(format!(
                "#{}{}",
                i.saturating_add(1),
                if deleted { " (deleted)" } else { "" }
            ))
            .span(record)
            .summary(values.join(", ")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LAS point clouds

declare_format!(pub LAS = "las", "LAS point cloud", ["las"], "application/vnd.las",
    Probe::Magic(&[(0, b"LASF")]), las);

record! {
    pub struct LasHeader {
        magic: ascii[4] "File signature",
        source: u16 "File source ID",
        encoding: u16 "Global encoding" .hex(),
        guid: guid "Project ID",
        major: u8 "Version major",
        minor: u8 "Version minor",
        system: ascii[32] "System identifier",
        software: ascii[32] "Generating software",
        day: u16 "Creation day of year",
        year: u16 "Creation year",
        header_size: u16 "Header size",
        points_offset: u32 "Offset to point data" .hex(),
        vlrs: u32 "Variable length records",
        point_format: u8 "Point data record format",
        point_length: u16 "Point data record length",
        points: u32 "Number of point records (legacy)",
        by_return: bytes[20] "Points by return (legacy)",
        x_scale: f64 "X scale factor",
        y_scale: f64 "Y scale factor",
        z_scale: f64 "Z scale factor",
        x_offset: f64 "X offset",
        y_offset: f64 "Y offset",
        z_offset: f64 "Z offset",
        x_max: f64 "Max X",
        x_min: f64 "Min X",
        y_max: f64 "Max Y",
        y_min: f64 "Min Y",
        z_max: f64 "Max Z",
        z_min: f64 "Min Z",
    }
}

/// The fields LAS 1.3 and 1.4 append to the public header block: the
/// waveform data start (1.3, offset 227), the extended VLRs and the 64-bit
/// point counts (1.4, offsets 235-375).
#[derive(Clone, Copy, Default)]
pub(crate) struct LasExtra {
    pub(crate) evlr_start: u64,
    pub(crate) evlrs: u32,
    pub(crate) points: Option<u64>,
}

pub(crate) async fn las_extra(cx: &Cx, file: Span, h: &LasHeader) -> Result<LasExtra> {
    let v14 = (h.major, h.minor) >= (1, 4) && h.header_size >= 375;
    if !v14 {
        return Ok(LasExtra::default());
    }
    let b = cx.read(file.sub(235, 20)).await?;
    Ok(LasExtra {
        evlr_start: crate::bytes::u64_le(&b, 0).unwrap_or(0),
        evlrs: u32_le(&b, 8).unwrap_or(0),
        points: crate::bytes::u64_le(&b, 12),
    })
}

/// The extended VLRs of a LAS 1.4 file (60-byte headers with 64-bit
/// lengths), after the point data.
pub(crate) async fn las_evlrs(cx: &Cx, file: Span, extra: LasExtra) -> Result<()> {
    if extra.evlrs > 0 && extra.evlr_start > 0 {
        let mut cur = Cursor::new(cx, file, LE);
        cur.seek(extra.evlr_start);
        for _ in 0..extra.evlrs.min(10_000) {
            if cur.remaining() < 60 {
                break;
            }
            let start = cur.pos();
            cur.skip(2);
            let user = crate::text::until_nul(&cur.bytes(16).await?);
            let record = cur.u16().await?;
            let len = cur.u64().await?;
            let description = crate::text::until_nul(&cur.bytes(32).await?);
            cur.skip(len);
            cx.push(
                Node::new(format!("Extended VLR {user}/{record}"))
                    .span(cur.since(start))
                    .summary(description),
            )
            .await;
        }
    }
    Ok(())
}

pub(crate) async fn las_header(cx: Cx, (span, major, minor): (Span, u8, u8)) -> Result<()> {
    let b = cx.block(span).await?;
    let mut f = crate::fields::Fields::emitting(&cx, &b, LE);
    LasHeader::read(&mut f)?;
    let len = span.len;
    if (major, minor) >= (1, 3) && len >= 235 {
        f.u64("Start of waveform data").hex().emit()?;
    }
    if (major, minor) >= (1, 4) && len >= 375 {
        f.u64("Start of first extended VLR").hex().emit()?;
        f.u32("Extended VLRs").emit()?;
        f.u64("Number of point records").emit()?;
        const BY_RETURN: [&str; 15] = [
            "Points by return 1",
            "Points by return 2",
            "Points by return 3",
            "Points by return 4",
            "Points by return 5",
            "Points by return 6",
            "Points by return 7",
            "Points by return 8",
            "Points by return 9",
            "Points by return 10",
            "Points by return 11",
            "Points by return 12",
            "Points by return 13",
            "Points by return 14",
            "Points by return 15",
        ];
        for name in BY_RETURN {
            f.u64(name).emit()?;
        }
    }
    Ok(())
}

async fn las(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: LasHeader = read_record(&cx, file.sub(0, LasHeader::SIZE), LE).await?;
    let header = file.sub(0, h.header_size.into());
    cx.emit(
        Node::new("Public header block")
            .span(header)
            .lazy(las_header, (header, h.major, h.minor)),
    );
    let extra = las_extra(&cx, file, &h).await?;
    // LAS 1.4 keeps the 32-bit count only for formats 0-5 (and as 0 when
    // the count does not fit); the 64-bit count is authoritative.
    let points = extra.points.unwrap_or(h.points.into());
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(h.header_size.into());
    for _ in 0..h.vlrs.min(10_000) {
        let start = cur.pos();
        cur.skip(2);
        let user = crate::text::until_nul(&cur.bytes(16).await?);
        let record = cur.u16().await?;
        let len = cur.u16().await?;
        let description = crate::text::until_nul(&cur.bytes(32).await?);
        cur.skip(len.into());
        cx.push(
            Node::new(format!("VLR {user}/{record}"))
                .span(cur.since(start))
                .summary(description),
        )
        .await;
    }
    // Points run from their offset for count × record length, before the
    // extended VLRs (which follow them in LAS 1.4).
    let offset = u64::from(h.points_offset);
    let mut end = file.len;
    if extra.evlrs > 0 && extra.evlr_start >= offset {
        end = end.min(extra.evlr_start);
    }
    let len = points
        .saturating_mul(h.point_length.into())
        .min(end.saturating_sub(offset));
    cx.emit(
        Node::new("Point records")
            .span(file.sub(offset, len))
            .summary(format!(
                "{points_point} × {} bytes (format {})",
                h.point_length,
                h.point_format & 0x3f,
                points_point = crate::formats::util::fmt::plural(points, "point")
            )),
    );
    las_evlrs(&cx, file, extra).await?;
    cx.annotate(format!(
        "LAS {}.{}, {points_point}, by {}",
        h.major,
        h.minor,
        h.software.trim_end(),
        points_point = crate::formats::util::fmt::plural(points, "point")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GRIB and BUFR (meteorological messages)

declare_format!(pub GRIB = "grib", "GRIB weather data", ["grib", "grb", "grib2", "grb2"], "application/x-grib",
    Probe::Magic(&[(0, b"GRIB")]), super::grib::dissect);

declare_format!(pub BUFR = "bufr", "BUFR observation data", ["bufr"], "application/x-bufr",
    Probe::Magic(&[(0, b"BUFR")]), super::bufr::dissect);
