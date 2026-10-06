//! Binary GIS formats: ESRI File Geodatabase tables, ISO 8211 (S-57
//! electronic navigational charts, SDTS), NTv2 and CTable2 datum grids,
//! LASzip point clouds, Garmin IMG maps and MapSource GDB databases, and
//! TomTom OV2 points of interest.

use std::sync::Arc;

use super::{enumv, fixed, hex, int, leaf, text, uint};
use crate::bytes::{to_u64, to_usize, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::science::LasHeader;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// ESRI File Geodatabase table (.gdbtable)

fn gdb_probe(h: &Head<'_>) -> bool {
    matches!(u32_le(h.data, 0), Some(3 | 4))
        && u32_le(h.data, 12) == Some(5)
        && u64_le(h.data, 16) == Some(0)
        && u64_le(h.data, 24) == Some(h.len)
        && u64_le(h.data, 32) == Some(40)
}

declare_format!(pub GDBTABLE = "gdbtable", "ESRI File Geodatabase table", ["gdbtable"], "application/x-esri-gdbtable",
    Probe::Custom(gdb_probe), gdbtable);

record! {
    pub struct GdbHeader {
        version: u32 "Version",
        rows: u32 "Valid rows",
        largest: u32 "Largest row size",
        magic: u32 "Magic",
        _reserved: u64 "Reserved",
        file_size: u64 "File size",
        fields_offset: u64 "Field descriptors offset" .hex(),
    }
}

const GDB_GEOMETRY: EnumTable = &[
    (0, "none"),
    (1, "point"),
    (2, "multipoint"),
    (3, "polyline"),
    (4, "polygon"),
    (9, "multipatch"),
];

const GDB_TYPES: EnumTable = &[
    (0, "int16"),
    (1, "int32"),
    (2, "float32"),
    (3, "float64"),
    (4, "string"),
    (5, "datetime"),
    (6, "objectid"),
    (7, "geometry"),
    (8, "binary"),
    (9, "raster"),
    (10, "GUID"),
    (11, "GlobalID"),
    (12, "XML"),
];

async fn gdbtable(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: GdbHeader = read_record(&cx, file.sub(0, GdbHeader::SIZE), LE).await?;
    cx.emit(GdbHeader::node("Header", file.sub(0, GdbHeader::SIZE), LE));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(h.fields_offset);
    let start = cur.pos();
    let size = u64::from(cur.u32().await?);
    let section = file.sub(start, size.saturating_add(4));
    cur.skip(4);
    let flags = cur.u32().await?;
    let count = cur.u16().await?;
    let geometry = crate::value::lookup(GDB_GEOMETRY, u64::from(flags & 0xff)).unwrap_or("unknown");
    cx.emit(
        Node::new("Field descriptors")
            .span(section)
            .summary(format!("{count} fields, {geometry} geometry"))
            .lazy(gdb_fields, section),
    );
    cx.emit(
        Node::new("Rows")
            .span(file.tail(start.saturating_add(size).saturating_add(4)))
            .summary(format!(
                "{} rows (located through the .gdbtablx index)",
                h.rows
            )),
    );
    cx.annotate(format!(
        "File Geodatabase table, {count} fields, {} rows, {geometry} geometry",
        h.rows
    ));
    Ok(())
}

async fn gdb_fields(cx: Cx, section: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, section, LE);
    let at = cur.pos();
    cur.skip(4);
    cx.emit(leaf(
        "Section size",
        cur.since(at),
        uint(section.len.saturating_sub(4), 32),
    ));
    let at = cur.pos();
    let version = cur.u32().await?;
    cx.emit(leaf("Version", cur.since(at), uint(version.into(), 32)));
    let at = cur.pos();
    let flags = cur.u32().await?;
    cx.emit(
        leaf("Layer flags", cur.since(at), hex(flags.into(), 32)).summary(
            crate::value::lookup(GDB_GEOMETRY, u64::from(flags & 0xff))
                .unwrap_or("unknown geometry"),
        ),
    );
    let at = cur.pos();
    let count = cur.u16().await?;
    cx.emit(leaf("Field count", cur.since(at), uint(count.into(), 16)));
    for _ in 0..count {
        let start = cur.pos();
        let name = utf16_counted(&mut cur).await?;
        let alias = utf16_counted(&mut cur).await?;
        let ty = cur.u8().await?;
        let mut node = Node::new(name.clone()).value(enumv(GDB_TYPES, ty.into(), 8));
        if !alias.is_empty() && alias != name {
            node = node.summary(format!("alias {alias:?}"));
        }
        match ty {
            4 => {
                let max = cur.u32().await?;
                let flag = cur.u8().await?;
                let peek = cur.peek(10).await?;
                let (len, n) = crate::bytes::uleb128(&peek).unwrap_or((0, 1));
                cur.skip(to_u64(n).saturating_add(len));
                node = node.summary(format!("max length {max}, {}", nullable(flag)));
            }
            6 | 8 | 10..=12 => {
                cur.skip(1);
                let flag = cur.u8().await?;
                node = node.summary(nullable(flag));
            }
            0..=3 | 5 => {
                let width = cur.u8().await?;
                let flag = cur.u8().await?;
                let default = cur.u8().await?;
                cur.skip(default.into());
                node = node.summary(format!("{width} bytes, {}", nullable(flag)));
            }
            _ => {
                // Geometry and raster fields carry spatial reference and
                // extent data whose layout depends on many flags.
                cx.emit(node.span(cur.since(start)).diag(Diagnostic::unsupported(
                    "field definition not decoded; later fields not shown",
                )));
                return Ok(());
            }
        }
        cx.emit(node.span(cur.since(start)));
        cx.checkpoint().await;
    }
    Ok(())
}

fn nullable(flag: u8) -> &'static str {
    if flag & 1 != 0 {
        "nullable"
    } else {
        "not null"
    }
}

/// A string as a character count (u8) and UTF-16LE characters.
async fn utf16_counted(cur: &mut Cursor<'_>) -> Result<String> {
    let n = cur.u8().await?;
    let raw = cur.bytes(u64::from(n).saturating_mul(2)).await?;
    Ok(crate::text::utf16(&raw, LE))
}

// ---------------------------------------------------------------------------
// ISO 8211

fn digits(b: &[u8]) -> bool {
    !b.is_empty() && b.iter().all(u8::is_ascii_digit)
}

fn iso8211_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    d.get(..5).is_some_and(digits)
        && matches!(d.get(5), Some(b'1'..=b'3'))
        && d.get(6) == Some(&b'L')
        && d.get(12..17).is_some_and(digits)
        && d.get(20..22).is_some_and(digits)
        && d.get(22) == Some(&b'0')
        && d.get(23).is_some_and(u8::is_ascii_digit)
}

declare_format!(pub ISO8211 = "iso8211", "ISO 8211 data (S-57 chart, SDTS)", ["000", "ddf", "001", "002"], "application/x-iso8211",
    Probe::Custom(iso8211_probe), iso8211);

fn num(b: &[u8]) -> u64 {
    std::str::from_utf8(b)
        .ok()
        .and_then(|s| s.trim().parse().ok())
        .unwrap_or(0)
}

/// A record's leader and directory.
struct Leader {
    len: u64,
    kind: u8,
    base: u64,
    /// `(tag, length, position)` of each field.
    entries: Vec<(String, u64, u64)>,
}

async fn read_leader(cx: &Cx, rec: Span) -> Result<Leader> {
    let l = cx.read(rec.sub_exact(0, 24)?).await?;
    let len = num(l.get(0..5).unwrap_or_default());
    let kind = l.get(6).copied().unwrap_or(b'?');
    let base = num(l.get(12..17).unwrap_or_default());
    let size_len = num(l.get(20..21).unwrap_or_default());
    let size_pos = num(l.get(21..22).unwrap_or_default());
    let size_tag = num(l.get(23..24).unwrap_or_default());
    let entry = size_len.saturating_add(size_pos).saturating_add(size_tag);
    if len < 24 || base < 24 || base > len || entry == 0 {
        return Err(Diagnostic::malformed("bad ISO 8211 leader").at(rec.sub(0, 24)));
    }
    let dir = cx.read(rec.sub_exact(24, base.saturating_sub(24))?).await?;
    let mut entries = Vec::new();
    for e in dir.chunks_exact(to_usize(entry)) {
        let tag =
            String::from_utf8_lossy(e.get(..to_usize(size_tag)).unwrap_or_default()).into_owned();
        let flen = num(e
            .get(to_usize(size_tag)..to_usize(size_tag.saturating_add(size_len)))
            .unwrap_or_default());
        let fpos = num(e
            .get(to_usize(size_tag.saturating_add(size_len))..)
            .unwrap_or_default());
        entries.push((tag, flen, fpos));
    }
    Ok(Leader {
        len,
        kind,
        base,
        entries,
    })
}

/// Field definitions from the DDR: tag → (name, subfield labels, formats).
type Ddr = Arc<Vec<(String, String, String, String)>>;

async fn iso8211(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut ddr: Ddr = Arc::new(Vec::new());
    let mut n = 0u64;
    while pos < file.len {
        let rec = file.tail(pos);
        let leader = read_leader(&cx, rec).await?;
        let span = file.sub(pos, leader.len);
        if span.len < leader.len {
            return Err(Diagnostic::truncated(
                Span::new(span.source, span.offset, leader.len),
                span.len,
            ));
        }
        if leader.kind == b'L' {
            let mut defs = Vec::new();
            for (tag, flen, fpos) in &leader.entries {
                let f = cx
                    .read(span.sub(leader.base.saturating_add(*fpos), *flen))
                    .await?;
                let parts: Vec<&[u8]> = f.split(|&b| b == 0x1f || b == 0x1e).collect();
                let first = parts.first().copied().unwrap_or_default();
                let name =
                    String::from_utf8_lossy(first.get(9.min(first.len())..).unwrap_or_default())
                        .into_owned();
                let labels =
                    String::from_utf8_lossy(parts.get(1).copied().unwrap_or_default()).into_owned();
                let formats =
                    String::from_utf8_lossy(parts.get(2).copied().unwrap_or_default()).into_owned();
                defs.push((tag.clone(), name, labels, formats));
            }
            let summary = format!("{} field definitions", defs.len());
            ddr = Arc::new(defs);
            cx.push(
                Node::new("Data descriptive record")
                    .span(span)
                    .summary(summary)
                    .lazy(ddr_record, (span, ddr.clone())),
            )
            .await;
        } else {
            let tags: Vec<&str> = leader
                .entries
                .iter()
                .map(|e| e.0.as_str())
                .filter(|t| *t != "0001")
                .collect();
            let summary = tags.join(", ");
            cx.push(
                Node::new(format!("Record {n}"))
                    .span(span)
                    .summary(summary)
                    .lazy(data_record, (span, ddr.clone())),
            )
            .await;
            n = n.saturating_add(1);
        }
        pos = pos.saturating_add(leader.len);
    }
    let s57 = ddr.iter().any(|d| d.0 == "DSID");
    cx.annotate(format!(
        "ISO 8211{}, {} field definitions, {n} data records",
        if s57 { " (S-57 chart)" } else { "" },
        ddr.len()
    ));
    Ok(())
}

async fn ddr_record(cx: Cx, (span, ddr): (Span, Ddr)) -> Result<()> {
    let leader = read_leader(&cx, span).await?;
    cx.emit(
        Node::new("Leader")
            .span(span.sub(0, 24))
            .value(text(String::from_utf8_lossy(
                &cx.read(span.sub(0, 24)).await?,
            ))),
    );
    cx.emit(
        Node::new("Directory")
            .span(span.sub(24, leader.base.saturating_sub(24)))
            .summary(format!("{} entries", leader.entries.len())),
    );
    for (tag, flen, fpos) in &leader.entries {
        let fspan = span.sub(leader.base.saturating_add(*fpos), *flen);
        let mut node = Node::new(tag.clone()).span(fspan);
        if let Some((_, name, labels, formats)) = ddr.iter().find(|d| &d.0 == tag) {
            node = node.value(text(name.clone()));
            let mut detail = Vec::new();
            if !labels.is_empty() {
                detail.push(labels.clone());
            }
            if !formats.is_empty() {
                detail.push(formats.clone());
            }
            if !detail.is_empty() {
                node = node.summary(detail.join(" "));
            }
        }
        cx.emit(node);
    }
    Ok(())
}

/// Expands a format control string like `(A(2),I(10),3b14,R)` into
/// `(type, width)` items; `None` widths are terminated by 0x1f.
fn parse_formats(f: &str) -> Vec<(char, Option<usize>)> {
    let inner = f.trim().trim_start_matches('(').trim_end_matches(')');
    let mut out = Vec::new();
    for item in inner.split(',') {
        let item = item.trim().trim_start_matches('(').trim_end_matches(')');
        let digits: String = item.chars().take_while(char::is_ascii_digit).collect();
        let rest = item.get(digits.len()..).unwrap_or_default();
        let repeat = digits.parse::<usize>().unwrap_or(1).min(256);
        let mut chars = rest.chars();
        let Some(kind) = chars.next() else { continue };
        let tail: String = chars.collect();
        let width = if kind == 'b' {
            // b1n / b2n: unsigned / signed binary of n bytes.
            tail.get(1..).and_then(|w| w.parse().ok())
        } else if kind == 'B' {
            tail.trim_matches(|c| c == '(' || c == ')')
                .parse::<usize>()
                .ok()
                .map(|bits| bits / 8)
        } else {
            tail.trim_matches(|c| c == '(' || c == ')').parse().ok()
        };
        let kind = if kind == 'b' && tail.starts_with('2') {
            's'
        } else {
            kind
        };
        for _ in 0..repeat {
            out.push((kind, width));
        }
        if out.len() > 4096 {
            break;
        }
    }
    out
}

fn subfield_value(kind: char, b: &[u8]) -> Value {
    match kind {
        'b' | 's' if b.len() <= 8 => {
            let mut raw = 0u64;
            for &x in b.iter().rev() {
                raw = (raw << 8) | u64::from(x);
            }
            let bits = u8::try_from(b.len().saturating_mul(8)).unwrap_or(64);
            if kind == 's' && bits > 0 {
                let shift = 64u32.saturating_sub(u32::from(bits));
                let v = raw
                    .cast_signed()
                    .checked_shl(shift)
                    .and_then(|v| v.checked_shr(shift))
                    .unwrap_or(0);
                int(v, bits)
            } else {
                uint(raw, bits)
            }
        }
        'B' | 'b' | 's' => Value::Bytes(b.to_vec()),
        _ => {
            let s = String::from_utf8_lossy(b).into_owned();
            crate::formats::text::number(&s)
                .filter(|_| matches!(kind, 'I' | 'R' | 'S'))
                .unwrap_or(Value::Text(s))
        }
    }
}

async fn data_record(cx: Cx, (span, ddr): (Span, Ddr)) -> Result<()> {
    let leader = read_leader(&cx, span).await?;
    for (tag, flen, fpos) in &leader.entries {
        let fspan = span.sub(leader.base.saturating_add(*fpos), *flen);
        let def = ddr.iter().find(|d| &d.0 == tag).cloned();
        let mut node = Node::new(tag.clone()).span(fspan);
        if let Some((_, name, _, _)) = &def {
            node = node.summary(name.clone());
        }
        cx.emit(node.lazy(field, (fspan, def)));
    }
    Ok(())
}

async fn field(
    cx: Cx,
    (fspan, def): (Span, Option<(String, String, String, String)>),
) -> Result<()> {
    let data = cx.read(fspan).await?;
    let Some((_, _, labels, formats)) = def else {
        cx.emit(leaf("Data", fspan, Value::Bytes(data)));
        return Ok(());
    };
    let repeating = labels.starts_with('*');
    let labels: Vec<&str> = match labels.trim_start_matches('*') {
        "" => vec!["Value"],
        l => l.split('!').collect(),
    };
    let formats = parse_formats(&formats);
    if labels.is_empty() || formats.is_empty() {
        cx.emit(leaf("Data", fspan, Value::Bytes(data)));
        return Ok(());
    }
    let mut at = 0usize;
    let mut group = 0u32;
    // The field terminator ends the data.
    let end = data
        .len()
        .saturating_sub(usize::from(data.last() == Some(&0x1e)));
    while at < end {
        for (i, label) in labels.iter().enumerate() {
            let (kind, width) = formats
                .get(i)
                .or_else(|| formats.last())
                .copied()
                .unwrap_or(('A', None));
            let start = at;
            let (value_end, next) = match width {
                Some(w) => (at.saturating_add(w).min(end), at.saturating_add(w)),
                None => {
                    let stop = data
                        .get(at..end)
                        .and_then(|d| d.iter().position(|&b| b == 0x1f))
                        .map_or(end, |p| at.saturating_add(p));
                    (stop, stop.saturating_add(1))
                }
            };
            let bytes = data.get(start..value_end).unwrap_or_default();
            let name = if repeating {
                format!("{label} [{group}]")
            } else {
                (*label).to_owned()
            };
            cx.emit(leaf(
                name,
                fspan.sub(to_u64(start), to_u64(value_end.saturating_sub(start))),
                subfield_value(kind, bytes),
            ));
            at = next.max(start.saturating_add(1));
            if at >= end {
                break;
            }
        }
        group = group.saturating_add(1);
        if !repeating || group >= 1024 {
            break;
        }
        cx.checkpoint().await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// NTv2 and CTable2 datum shift grids

fn ntv2_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"NUM_OREC") && h.at(16, b"NUM_SREC")
}

declare_format!(pub NTV2 = "ntv2", "NTv2 datum grid shift file", ["gsb"], "application/x-ntv2",
    Probe::Custom(ntv2_probe), ntv2);

/// A 16-byte header record: label and typed value.
fn ntv2_value(label: &str, v: &[u8], endian: Endian) -> Value {
    let i = match endian {
        Endian::Little => u32_le(v, 0),
        Endian::Big => u32_be(v, 0),
    }
    .unwrap_or(0);
    let d = match endian {
        Endian::Little => u64_le(v, 0),
        Endian::Big => crate::bytes::u64_be(v, 0),
    }
    .map_or(0.0, f64::from_bits);
    match label {
        "NUM_OREC" | "NUM_SREC" | "NUM_FILE" | "GS_COUNT" => uint(i.into(), 32),
        "MAJOR_F" | "MINOR_F" | "MAJOR_T" | "MINOR_T" | "S_LAT" | "N_LAT" | "E_LONG" | "W_LONG"
        | "LAT_INC" | "LONG_INC" => Value::Float(d),
        _ => text(fixed(v)),
    }
}

async fn ntv2_records(
    cx: &Cx,
    region: Span,
    count: u64,
    endian: Endian,
) -> Result<Vec<(String, Value, Span)>> {
    let data = cx
        .read(region.sub_exact(0, count.saturating_mul(16))?)
        .await?;
    Ok(data
        .as_chunks::<16>()
        .0
        .iter()
        .enumerate()
        .map(|(i, r)| {
            let label = fixed(r.get(..8).unwrap_or_default());
            let value = ntv2_value(&label, r.get(8..).unwrap_or_default(), endian);
            (label, value, region.sub(to_u64(i).saturating_mul(16), 16))
        })
        .collect())
}

fn get_uint(records: &[(String, Value, Span)], label: &str) -> u64 {
    records
        .iter()
        .find(|r| r.0 == label)
        .and_then(|r| match r.1 {
            Value::UInt { value, .. } => Some(value),
            _ => None,
        })
        .unwrap_or(0)
}

fn get_float(records: &[(String, Value, Span)], label: &str) -> f64 {
    records
        .iter()
        .find(|r| r.0 == label)
        .and_then(|r| match r.1 {
            Value::Float(f) => Some(f),
            _ => None,
        })
        .unwrap_or(0.0)
}

async fn ntv2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let endian = if u32_le(&head, 8) == Some(11) {
        LE
    } else {
        Endian::Big
    };
    let orec = match endian {
        Endian::Little => u32_le(&head, 8),
        Endian::Big => u32_be(&head, 8),
    }
    .unwrap_or(0)
    .min(64);
    let overview = ntv2_records(&cx, file, orec.into(), endian).await?;
    let srec = get_uint(&overview, "NUM_SREC").min(64);
    let files = get_uint(&overview, "NUM_FILE");
    let ospan = file.sub(0, u64::from(orec).saturating_mul(16));
    let from = overview
        .iter()
        .find(|r| r.0 == "SYSTEM_F")
        .map(|r| crate::render::value(&r.1))
        .unwrap_or_default();
    let to = overview
        .iter()
        .find(|r| r.0 == "SYSTEM_T")
        .map(|r| crate::render::value(&r.1))
        .unwrap_or_default();
    cx.emit(
        Node::new("Overview header").span(ospan).lazy(
            super::emit_nodes,
            overview
                .into_iter()
                .map(|(l, v, s)| leaf(l, s, v))
                .collect::<Vec<_>>(),
        ),
    );
    let mut pos = ospan.len;
    for _ in 0..files {
        let records = ntv2_records(&cx, file.tail(pos), srec, endian).await?;
        let name = records
            .iter()
            .find(|r| r.0 == "SUB_NAME")
            .map(|r| crate::render::value(&r.1))
            .unwrap_or_default();
        let count = get_uint(&records, "GS_COUNT");
        let rows = ((get_float(&records, "N_LAT") - get_float(&records, "S_LAT"))
            / get_float(&records, "LAT_INC"))
        .round()
            + 1.0;
        let cols = ((get_float(&records, "W_LONG") - get_float(&records, "E_LONG"))
            / get_float(&records, "LONG_INC"))
        .round()
            + 1.0;
        let hspan = file.sub(pos, srec.saturating_mul(16));
        let grid = file.sub(pos.saturating_add(hspan.len), count.saturating_mul(16));
        let mut nodes: Vec<Node> = records.into_iter().map(|(l, v, s)| leaf(l, s, v)).collect();
        nodes.push(Node::new("Grid").span(grid).summary(format!(
            "{count} nodes ({rows}×{cols}), 4 × f32 each: lat/long shift and accuracy"
        )));
        cx.push(
            Node::new(format!("Sub-grid {name}"))
                .span(file.sub(pos, hspan.len.saturating_add(grid.len)))
                .summary(format!("{count} nodes"))
                .lazy(super::emit_nodes, nodes),
        )
        .await;
        pos = pos.saturating_add(hspan.len).saturating_add(grid.len);
        if grid.len < count.saturating_mul(16) {
            return Err(Diagnostic::truncated(
                Span::new(grid.source, grid.offset, count.saturating_mul(16)),
                grid.len,
            ));
        }
    }
    let end = file.sub(pos, 16);
    if end.len == 16 {
        cx.push(leaf(
            "End",
            end,
            text(fixed(&cx.read(end.sub(0, 8)).await?)),
        ))
        .await;
    }
    cx.annotate(format!("NTv2 grid, {files} sub-grids, {from} → {to}"));
    Ok(())
}

declare_format!(pub CTABLE2 = "ctable2", "PROJ CTable2 datum grid", ["ct2"], "application/x-ctable2",
    Probe::Magic(&[(0, b"CTABLE V2.0")]), ctable2);

fn radians(v: f64) -> String {
    format!("{}°", super::round(v.to_degrees()))
}

record! {
    pub struct CtHeader {
        magic: ascii[16] "Magic",
        id: ascii[80] "Description",
        lam: f64 "Lower-left longitude (rad)" .with(|&v, n| n.summary(radians(v))),
        phi: f64 "Lower-left latitude (rad)" .with(|&v, n| n.summary(radians(v))),
        dlam: f64 "Longitude step (rad)" .with(|&v, n| n.summary(radians(v))),
        dphi: f64 "Latitude step (rad)" .with(|&v, n| n.summary(radians(v))),
        cols: i32 "Columns",
        rows: i32 "Rows",
    }
}

async fn ctable2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: CtHeader = read_record(&cx, file.sub(0, CtHeader::SIZE), LE).await?;
    cx.emit(CtHeader::node("Header", file.sub(0, 160), LE));
    let cells = u64::from(h.cols.unsigned_abs()).saturating_mul(h.rows.unsigned_abs().into());
    cx.emit(
        Node::new("Shifts")
            .span(file.sub(160, cells.saturating_mul(8)))
            .summary(format!("{}×{} pairs of f32 (radians)", h.cols, h.rows)),
    );
    cx.annotate(format!(
        "CTable2 grid {}×{}: {}",
        h.cols,
        h.rows,
        h.id.trim()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// LASzip compressed LAS

fn laz_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"LASF") && h.data.get(104).is_some_and(|b| b & 0x80 != 0)
}

declare_format!(pub LAZ = "laz", "LASzip compressed point cloud", ["laz"], "application/vnd.laszip",
    Probe::Custom(laz_probe), laz);

const LAZ_ITEMS: EnumTable = &[
    (0, "BYTE"),
    (1, "SHORT"),
    (2, "INT"),
    (3, "LONG"),
    (4, "FLOAT"),
    (5, "DOUBLE"),
    (6, "POINT10"),
    (7, "GPSTIME11"),
    (8, "RGB12"),
    (9, "WAVEPACKET13"),
    (10, "POINT14"),
    (11, "RGB14"),
    (12, "RGBNIR14"),
    (13, "WAVEPACKET14"),
    (14, "BYTE14"),
];

async fn laz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: LasHeader = read_record(&cx, file.sub(0, LasHeader::SIZE), LE).await?;
    cx.emit(LasHeader::node(
        "Public header block",
        file.sub(0, h.header_size.into()),
        LE,
    ));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(h.header_size.into());
    let mut chunk_size = 0u32;
    for _ in 0..h.vlrs.min(10_000) {
        let start = cur.pos();
        cur.skip(2);
        let user = crate::text::until_nul(&cur.bytes(16).await?);
        let record = cur.u16().await?;
        let len = cur.u16().await?;
        let description = crate::text::until_nul(&cur.bytes(32).await?);
        let body = cur.span(len.into());
        cur.skip(len.into());
        let mut node = Node::new(format!("VLR {user}/{record}"))
            .span(cur.since(start))
            .summary(description);
        if user == "laszip encoded" && record == 22204 {
            let b = cx.read(body).await?;
            chunk_size = u32_le(&b, 12).unwrap_or(0);
            node = node.lazy(laszip_vlr, body);
        }
        cx.push(node).await;
    }
    let points = file.tail(h.points_offset.into());
    let table = cx.read(points.sub(0, 8)).await?;
    let table_at = u64_le(&table, 0).unwrap_or(0);
    cx.push(leaf(
        "Chunk table offset",
        points.sub(0, 8),
        hex(table_at, 64),
    ))
    .await;
    cx.push(
        Node::new("Compressed points")
            .span(file.sub(
                u64::from(h.points_offset).saturating_add(8),
                table_at.saturating_sub(u64::from(h.points_offset).saturating_add(8)),
            ))
            .summary(format!("{} points, chunks of {chunk_size}", h.points)),
    )
    .await;
    let t = file.sub(table_at, 8);
    if table_at > 0 && t.len == 8 {
        let b = cx.read(t).await?;
        cx.push(
            Node::new("Chunk table")
                .span(file.tail(table_at))
                .summary(format!(
                    "version {}, {} chunks",
                    u32_le(&b, 0).unwrap_or(0),
                    u32_le(&b, 4).unwrap_or(0)
                )),
        )
        .await;
    }
    cx.annotate(format!(
        "LAZ (LAS {}.{}), {} points, by {}",
        h.major,
        h.minor,
        h.points,
        h.software.trim_end()
    ));
    Ok(())
}

record! {
    pub struct LaszipVlr {
        compressor: u16 "Compressor" .enumeration(&[(0, "none"), (1, "pointwise"), (2, "pointwise chunked"), (3, "layered chunked")]),
        coder: u16 "Coder",
        major: u8 "Version major",
        minor: u8 "Version minor",
        revision: u16 "Revision",
        options: u32 "Options" .hex(),
        chunk_size: u32 "Chunk size",
        special_count: i64 "Special EVLRs",
        special_offset: i64 "Special EVLR offset",
        items: u16 "Items",
    }
}

async fn laszip_vlr(cx: Cx, body: Span) -> Result<()> {
    let v = crate::dsl::emit_record::<LaszipVlr>(&cx, body.sub(0, LaszipVlr::SIZE), LE).await?;
    let mut cur = Cursor::new(&cx, body, LE);
    cur.seek(LaszipVlr::SIZE);
    for i in 0..v.items.min(64) {
        let at = cur.pos();
        let ty = cur.u16().await?;
        let size = cur.u16().await?;
        let version = cur.u16().await?;
        cx.emit(
            Node::new(format!("Item {i}"))
                .span(cur.since(at))
                .value(enumv(LAZ_ITEMS, ty.into(), 16))
                .summary(format!("{size} bytes, version {version}")),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Garmin IMG

fn img_probe(h: &Head<'_>) -> bool {
    let x = h.data.first().copied().unwrap_or(0);
    let unxor = |at: usize, sig: &[u8]| {
        sig.iter().enumerate().all(|(i, &s)| {
            h.data
                .get(at.saturating_add(i))
                .is_some_and(|&b| b ^ x == s)
        })
    };
    unxor(0x10, b"DSKIMG\0") && unxor(0x41, b"GARMIN\0")
}

declare_format!(pub GARMIN_IMG = "garmin-img", "Garmin IMG map", ["img"], "application/x-garmin-img",
    Probe::Custom(img_probe), garmin_img);

/// Reads `span` and undoes the image's XOR mask.
async fn read_xor(cx: &Cx, span: Span, x: u8) -> Result<Vec<u8>> {
    let mut b = cx.read(span).await?;
    if x != 0 {
        for v in &mut b {
            *v ^= x;
        }
    }
    Ok(b)
}

async fn garmin_img(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let x = cx.read(file.sub(0, 1)).await?.first().copied().unwrap_or(0);
    let h = read_xor(&cx, file.sub_exact(0, 0x200)?, x).await?;
    let byte = |at: usize| h.get(at).copied().unwrap_or(0);
    cx.emit(leaf("XOR mask", file.sub(0, 1), hex(x.into(), 8)));
    cx.emit(leaf(
        "Signature",
        file.sub(0x10, 7),
        text(fixed(h.get(0x10..0x17).unwrap_or_default())),
    ));
    let year = u16_le(&h, 0x39).unwrap_or(0);
    cx.emit(leaf(
        "Created",
        file.sub(0x39, 7),
        text(format!(
            "{year:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            byte(0x3b),
            byte(0x3c),
            byte(0x3d),
            byte(0x3e),
            byte(0x3f)
        )),
    ));
    let desc = format!(
        "{}{}",
        fixed(h.get(0x49..0x5d).unwrap_or_default()),
        fixed(h.get(0x65..0x83).unwrap_or_default())
    );
    cx.emit(leaf("Description", file.sub(0x49, 20), text(desc.clone())));
    let (e1, e2) = (byte(0x61), byte(0x62));
    let block = 1u64
        .checked_shl(u32::from(e1).saturating_add(e2.into()))
        .filter(|&b| (512..=1 << 24).contains(&b));
    let Some(block) = block else {
        return Err(
            Diagnostic::malformed(format!("bad block size exponents {e1}+{e2}"))
                .at(file.sub(0x61, 2)),
        );
    };
    cx.emit(leaf("Block size", file.sub(0x61, 2), uint(block, 32)));

    // The FAT: 512-byte entries from 0x600 (or 0x400) on, listing each
    // sub-file's blocks.
    let mut files: Vec<(String, u64, Vec<u16>, Span)> = Vec::new();
    let mut pos = 0x400u64;
    let mut first_data = u64::MAX;
    while pos.saturating_add(512) <= file.len.min(first_data) && files.len() < 4096 {
        let e = read_xor(&cx, file.sub(pos, 512), x).await?;
        let flag = e.first().copied().unwrap_or(0);
        let name = format!(
            "{}.{}",
            fixed(e.get(1..9).unwrap_or_default()),
            fixed(e.get(9..12).unwrap_or_default())
        );
        if flag == 1
            && e.get(1..12)
                .is_some_and(|n| n.iter().all(|&b| b.is_ascii_graphic() || b == b' '))
        {
            let size = u64::from(u32_le(&e, 12).unwrap_or(0));
            let part = u16_le(&e, 16).unwrap_or(0);
            let blocks: Vec<u16> = e
                .get(0x20..)
                .unwrap_or_default()
                .as_chunks::<2>()
                .0
                .iter()
                .map(|&c| u16::from_le_bytes(c))
                .take_while(|&b| b != 0xffff)
                .collect();
            let header_entry = name.trim_matches(|c| c == ' ' || c == '.').is_empty();
            if header_entry {
                // The image's own header blocks: the FAT ends where data begins.
                first_data = to_u64(blocks.len())
                    .saturating_mul(block)
                    .max(pos.saturating_add(512));
            } else if part == 0 {
                files.push((name, size, blocks, file.sub(pos, 512)));
            } else if let Some(last) = files.iter_mut().rev().find(|f| f.0 == name) {
                last.2.extend(blocks);
            }
        } else if pos >= 0x600 && flag != 0 && flag != 1 {
            break;
        }
        pos = pos.saturating_add(512);
        cx.checkpoint().await;
    }
    cx.set_count(Count::AtLeast(to_u64(files.len())));
    let n = files.len();
    for (name, size, blocks, fat) in files {
        let mut pieces = Vec::new();
        let mut left = size;
        for b in blocks {
            if left == 0 {
                break;
            }
            let take = left.min(block);
            pieces.push(file.sub(u64::from(b).saturating_mul(block), take));
            left = left.saturating_sub(take);
        }
        let node = match cx.add_pieces(
            Origin {
                parent: fat,
                transform: "garmin-img blocks",
            },
            pieces,
        ) {
            Ok(span) if x == 0 => Node::new(name)
                .span(span)
                .summary(format!("{size} bytes"))
                .lazy(subfile, span),
            Ok(span) => Node::new(name)
                .span(span)
                .summary(format!("{size} bytes, XOR-masked")),
            Err(e) => Node::new(name).span(fat).diag(e),
        };
        cx.push(node).await;
    }
    cx.annotate(format!("Garmin IMG map {desc:?}, {n} sub-files"));
    Ok(())
}

record! {
    pub struct SubHeader {
        length: u16 "Header length",
        kind: ascii[10] "Type",
        _unknown: u8 "Unknown",
        locked: u8 "Locked",
        year: u16 "Year",
        month: u8 "Month",
        day: u8 "Day",
        hour: u8 "Hour",
        minute: u8 "Minute",
        second: u8 "Second",
    }
}

async fn subfile(cx: Cx, span: Span) -> Result<()> {
    let h = crate::dsl::emit_record::<SubHeader>(&cx, span.sub(0, SubHeader::SIZE), LE).await?;
    let len = u64::from(h.length);
    if len > SubHeader::SIZE {
        cx.emit(
            Node::new("Type-specific header")
                .span(span.sub(SubHeader::SIZE, len.saturating_sub(SubHeader::SIZE))),
        );
    }
    cx.emit(Node::new("Data").span(span.tail(len)));
    Ok(())
}

// ---------------------------------------------------------------------------
// Garmin MapSource GDB

declare_format!(pub GARMIN_GDB = "garmin-gdb", "Garmin MapSource database", ["gdb"], "application/x-garmin-gdb",
    Probe::Custom(|h| h.starts_with(b"MsRcf\0") && h.data.get(10) == Some(&b'D')), garmin_gdb);

const GDB_RECORDS: EnumTable = &[
    (b'D' as u64, "header"),
    (b'A' as u64, "application"),
    (b'W' as u64, "waypoint"),
    (b'T' as u64, "track"),
    (b'R' as u64, "route"),
    (b'L' as u64, "map"),
    (b'V' as u64, "end"),
];

async fn garmin_gdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.push(leaf("Magic", file.sub(0, 6), text("MsRcf"))).await;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(6);
    let mut version = 0u8;
    let (mut w, mut t, mut r) = (0u32, 0u32, 0u32);
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let len = u64::from(cur.u32().await?);
        let kind = cur.u8().await?;
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len);
        let span = cur.since(start);
        let head = cx.read(body.sub(0, 256)).await?;
        let name = crate::text::until_nul(&head);
        let mut node = Node::new(
            crate::value::lookup(GDB_RECORDS, kind.into())
                .map_or_else(|| format!("record {:?}", char::from(kind)), str::to_owned),
        )
        .span(span);
        match kind {
            b'D' => {
                version = head
                    .first()
                    .map_or(0, |v| v.wrapping_sub(b'k').wrapping_add(1));
                node = node.summary(format!("format version {version}"));
            }
            b'W' | b'T' | b'R' | b'A' => node = node.value(text(name)),
            _ => {}
        }
        match kind {
            b'W' => w = w.saturating_add(1),
            b'T' => t = t.saturating_add(1),
            b'R' => r = r.saturating_add(1),
            _ => {}
        }
        if kind != b'D' {
            node = node.summary(format!("{len} bytes"));
        }
        cx.push(node).await;
        if kind == b'V' {
            break;
        }
    }
    cx.annotate(format!(
        "MapSource GDB v{version}, {w} waypoints, {t} tracks, {r} routes"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// TomTom OV2

/// Walks OV2 records in `data`; returns how many were valid and whether
/// they ended exactly at the end of `data`.
fn ov2_walk(data: &[u8]) -> (u32, bool) {
    let mut at = 0usize;
    let mut n = 0u32;
    while at < data.len() {
        let Some(&kind) = data.get(at) else { break };
        let size = match kind {
            1 => 21,
            0 | 2 | 3 => match u32_le(data, at.saturating_add(1)) {
                Some(s) if s >= 13 => to_usize(s.into()),
                _ => return (n, false),
            },
            _ => return (n, false),
        };
        if kind == 2 || kind == 3 {
            let Some(rec) = data.get(at..at.saturating_add(size)) else {
                return (n, false);
            };
            let lat = crate::bytes::i32_le(rec, 9).unwrap_or(i32::MAX);
            let lon = crate::bytes::i32_le(rec, 5).unwrap_or(i32::MAX);
            if lat.unsigned_abs() > 9_000_000
                || lon.unsigned_abs() > 18_000_000
                || rec.last() != Some(&0)
            {
                return (n, false);
            }
        }
        at = at.saturating_add(size);
        n = n.saturating_add(1);
    }
    (n, at == data.len())
}

fn ov2_probe(h: &Head<'_>) -> bool {
    if !matches!(h.data.first(), Some(1..=3)) {
        return false;
    }
    let (n, exact) = ov2_walk(h.data);
    if to_u64(h.data.len()) >= h.len {
        exact && n >= 2
    } else {
        n >= 8
    }
}

declare_format!(pub OV2 = "tomtom-ov2", "TomTom points of interest (OV2)", ["ov2"], "application/x-tomtom-ov2",
    Probe::Custom(ov2_probe), ov2);

fn deg5(v: i32) -> String {
    format!("{}°", f64::from(v) / 1e5)
}

async fn ov2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut n = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let kind = cur.u8().await?;
        let size = u64::from(cur.u32().await?);
        match kind {
            1 => {
                let b = cur.bytes(16).await?;
                let v = |i: usize| crate::bytes::i32_le(&b, i).unwrap_or(0);
                cx.push(Node::new("Skipper").span(cur.since(start)).summary(format!(
                    "block of {size} bytes, lon {}…{}, lat {}…{}",
                    deg5(v(8)),
                    deg5(v(0)),
                    deg5(v(12)),
                    deg5(v(4))
                )))
                .await;
            }
            0 | 2 | 3 if size >= 13 => {
                let rest = cur.bytes(size.saturating_sub(5)).await?;
                let lon = crate::bytes::i32_le(&rest, 0).unwrap_or(0);
                let lat = crate::bytes::i32_le(&rest, 4).unwrap_or(0);
                let strings: Vec<String> = rest
                    .get(8..)
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                let name = if kind == 0 {
                    "Deleted".to_owned()
                } else {
                    strings.first().cloned().unwrap_or_default()
                };
                cx.push(
                    Node::new(name).span(cur.since(start)).summary(format!(
                        "{}, {}{}",
                        deg5(lat),
                        deg5(lon),
                        strings
                            .get(1..)
                            .filter(|s| !s.is_empty())
                            .map(|s| format!(" ({})", s.join("; ")))
                            .unwrap_or_default()
                    )),
                )
                .await;
                n = n.saturating_add(1);
            }
            _ => {
                return Err(Diagnostic::malformed(format!("unknown record type {kind}"))
                    .at(file.sub(start, 1)));
            }
        }
    }
    cx.annotate(format!("TomTom OV2, {n} POIs"));
    Ok(())
}
