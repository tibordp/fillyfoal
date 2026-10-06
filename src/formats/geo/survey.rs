//! Survey and observation data: ESRI Shapefiles with their dBase tables,
//! LAS point clouds, and GRIB and BUFR meteorological messages.

use crate::bytes::{u16_le, u32_be, u32_le, u64_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

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

fn shx_probe(h: &Head<'_>) -> bool {
    shape_header(h)
        && h.len >= 100
        && h.len.saturating_sub(100).is_multiple_of(8)
        && (h.len == 100 || u32_be(h.data, 100) == Some(50))
}

declare_format!(pub SHX = "shx", "ESRI shapefile index", ["shx"], "application/x-esri-shape-index",
    Probe::Custom(shx_probe), shx);
declare_format!(pub SHP = "shp", "ESRI shapefile", ["shp"], "application/x-esri-shape",
    Probe::Custom(shape_header), shp);

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

async fn shp_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let number = cur.u32().await?;
        let words = cur.u32().await?;
        let content = cur.span(u64::from(words).saturating_mul(2));
        let kind = u32_le(&cx.read_avail(content.sub(0, 4)).await?, 0).unwrap_or(0);
        cur.skip(u64::from(words).saturating_mul(2));
        let name = lookup(SHAPE_TYPES, kind.into()).unwrap_or("unknown");
        cx.push(
            Node::new(format!("Record {number}"))
                .span(cur.since(start))
                .summary(name),
        )
        .await;
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
            .summary(format!("{count} records"))
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

fn dbf_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(&v), Some(&mm), Some(&dd)) = (d.first(), d.get(2), d.get(3)) else {
        return false;
    };
    let header = u16_le(d, 8).unwrap_or(0);
    let record = u16_le(d, 10).unwrap_or(0);
    let records = u32_le(d, 4).unwrap_or(0);
    lookup(DBF_VERSIONS, v.into()).is_some()
        && (1..=12).contains(&mm)
        && (1..=31).contains(&dd)
        && header >= 65
        && record > 0
        && d.get(usize::from(header).saturating_sub(1)) == Some(&0x0d)
        && u64::from(records)
            .saturating_mul(record.into())
            .saturating_add(header.into())
            <= h.len.saturating_add(1)
}

declare_format!(pub DBF = "dbf", "dBase table", ["dbf"], "application/x-dbf",
    Probe::Custom(dbf_probe), dbf);

record! {
    pub struct DbfHeader {
        version: u8 "Version" .enumeration(DBF_VERSIONS),
        year: u8 "Last update: year (since 1900)",
        month: u8 "Last update: month",
        day: u8 "Last update: day",
        records: u32 "Records",
        header: u16 "Header size",
        record: u16 "Record size",
        _reserved: bytes[20] "Reserved",
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
    let count = (u64::from(h.header).saturating_sub(33)) / DbfField::SIZE;
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
            .summary(format!("{count} fields"))
            .lazy(dbf_fields, descriptors),
    );
    let records = file.sub(
        h.header.into(),
        u64::from(h.records).saturating_mul(h.record.into()),
    );
    cx.emit(
        Node::new("Records")
            .span(records)
            .summary(format!("{} records", h.records))
            .lazy(dbf_records, (records, u64::from(h.record), fields.clone())),
    );
    let version = lookup(DBF_VERSIONS, h.version.into()).unwrap_or("dBase");
    let names: Vec<String> = fields.iter().map(|f| f.0.clone()).collect();
    cx.annotate(format!(
        "{version}, {} records × [{}]",
        h.records,
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

async fn dbf_records(cx: Cx, (span, size, fields): (Span, u64, DbfFields)) -> Result<()> {
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
        for (name, _, len, _) in &fields {
            let len = crate::bytes::to_usize(*len);
            let value =
                String::from_utf8_lossy(bytes.get(at..at.saturating_add(len)).unwrap_or_default())
                    .trim()
                    .to_owned();
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

async fn las(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: LasHeader = read_record(&cx, file.sub(0, LasHeader::SIZE), LE).await?;
    cx.emit(LasHeader::node(
        "Public header block",
        file.sub(0, h.header_size.into()),
        LE,
    ));
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
    cx.emit(
        Node::new("Point records")
            .span(file.tail(h.points_offset.into()))
            .summary(format!(
                "{} points × {} bytes (format {})",
                h.points, h.point_length, h.point_format
            )),
    );
    cx.annotate(format!(
        "LAS {}.{}, {} points, by {}",
        h.major,
        h.minor,
        h.points,
        h.software.trim_end()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GRIB and BUFR (meteorological messages)

declare_format!(pub GRIB = "grib", "GRIB weather data", ["grib", "grb", "grib2", "grb2"], "application/x-grib",
    Probe::Magic(&[(0, b"GRIB")]), grib);

const GRIB2_SECTIONS: [&str; 9] = [
    "Indicator",
    "Identification",
    "Local use",
    "Grid definition",
    "Product definition",
    "Data representation",
    "Bit-map",
    "Data",
    "End",
];

async fn grib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut messages = 0u32;
    let mut edition = 0u8;
    while pos.saturating_add(16) <= file.len {
        let head = cx.read(file.sub(pos, 16)).await?;
        if !head.starts_with(b"GRIB") {
            break;
        }
        edition = head.get(7).copied().unwrap_or(0);
        let len = if edition == 2 {
            u64_be(&head, 8).unwrap_or(0)
        } else {
            u64::from(crate::bytes::u24_be(&head, 4).unwrap_or(0))
        };
        if len < 16 {
            cx.diag(Diagnostic::malformed("message shorter than its indicator"));
            break;
        }
        let span = file.sub(pos, len);
        let discipline = head.get(6).copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Message {}", messages.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "edition {edition}, discipline {discipline}, {len} bytes"
                ))
                .lazy(grib_sections, (span, edition)),
        )
        .await;
        messages = messages.saturating_add(1);
        pos = pos.saturating_add(len);
    }
    cx.annotate(format!("{messages} GRIB{edition} message(s)"));
    Ok(())
}

async fn grib_sections(cx: Cx, (span, edition): (Span, u8)) -> Result<()> {
    if edition != 2 {
        cx.emit(Node::new("Indicator").span(span.sub(0, 8)));
        cx.emit(Node::new("Sections").span(span.sub(8, span.len.saturating_sub(12))));
        cx.emit(Node::new("End (7777)").span(span.tail(span.len.saturating_sub(4))));
        return Ok(());
    }
    cx.emit(Node::new("Indicator").span(span.sub(0, 16)));
    let mut cur = Cursor::new(&cx, span, BE);
    cur.seek(16);
    while cur.remaining() > 4 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let number = cur.u8().await?;
        if len < 5 {
            break;
        }
        cur.seek(start.saturating_add(len.into()));
        let name = GRIB2_SECTIONS
            .get(usize::from(number))
            .unwrap_or(&"Unknown");
        cx.push(
            Node::new(format!("Section {number}: {name}"))
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    cx.emit(Node::new("End (7777)").span(cur.span(4)));
    Ok(())
}

declare_format!(pub BUFR = "bufr", "BUFR observation data", ["bufr"], "application/x-bufr",
    Probe::Magic(&[(0, b"BUFR")]), bufr);

async fn bufr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let len = u64::from(crate::bytes::u24_be(&head, 4).unwrap_or(0));
    let edition = head.get(7).copied().unwrap_or(0);
    cx.emit(
        Node::new("Section 0 (indicator)")
            .span(file.sub(0, 8))
            .value(Value::UInt {
                value: edition.into(),
                bits: 8,
                radix: Radix::Dec,
            }),
    );
    let mut cur = Cursor::new(&cx, file.sub(0, len), BE);
    cur.seek(8);
    for number in 1..=4u8 {
        if cur.remaining() < 3 {
            break;
        }
        let start = cur.pos();
        let section_len = u64::from(crate::bytes::u24_be(&cur.peek(3).await?, 0).unwrap_or(0));
        if section_len < 3 {
            break;
        }
        cur.skip(section_len);
        cx.emit(
            Node::new(format!("Section {number}"))
                .span(cur.since(start))
                .summary(format!("{section_len} bytes")),
        );
        // Section 2 is optional (flag in section 1); a 7777 here ends it.
        if cur.peek(4).await? == b"7777" {
            break;
        }
    }
    cx.emit(Node::new("Section 5 (7777)").span(cur.span(4)));
    cx.annotate(format!("BUFR edition {edition}, {len} bytes"));
    Ok(())
}
