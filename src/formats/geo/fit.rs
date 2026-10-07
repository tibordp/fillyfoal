//! Garmin FIT (Flexible and Interoperable Data Transfer): activity, course,
//! workout and settings files from sports devices.
//!
//! A 12- or 14-byte header is followed by a stream of records and a CRC.
//! Definition messages bind a local message type (0–15) to a global message
//! number and a field layout; data messages use the most recent definition
//! of their local type. Records are listed in pages; data messages expand to
//! their decoded fields, named for common messages.

use std::sync::Arc;

use super::{enumv, hex, leaf, text, time, uint};
use crate::bytes::{to_u64, u16_le};
use crate::codec::crc::crc16_arc as crc16;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

/// Seconds from the Unix epoch to the FIT epoch (1989-12-31T00:00:00Z).
const FIT_EPOCH: i64 = 631_065_600;

fn probe(h: &Head<'_>) -> bool {
    h.at(8, b".FIT") && matches!(h.data.first(), Some(12 | 14))
}

declare_format!(pub FIT = "fit", "Garmin FIT activity/fitness file", ["fit"], "application/vnd.ant.fit",
    Probe::Custom(probe), dissect);

record! {
    pub struct Header {
        size: u8 "Header size",
        protocol: u8 "Protocol version" .with(|&v, n| n.summary(format!("{}.{}", v >> 4, v & 15))),
        profile: u16 "Profile version" .with(|&v, n| n.summary(format!("{}.{:02}", v / 100, v % 100))),
        data_size: u32 "Data size",
        magic: ascii[4] "Data type",
    }
}

const MESSAGES: EnumTable = &[
    (0, "file_id"),
    (1, "capabilities"),
    (2, "device_settings"),
    (3, "user_profile"),
    (4, "hrm_profile"),
    (5, "sdm_profile"),
    (6, "bike_profile"),
    (7, "zones_target"),
    (8, "hr_zone"),
    (9, "power_zone"),
    (10, "met_zone"),
    (12, "sport"),
    (15, "goal"),
    (18, "session"),
    (19, "lap"),
    (20, "record"),
    (21, "event"),
    (23, "device_info"),
    (26, "workout"),
    (27, "workout_step"),
    (28, "schedule"),
    (30, "weight_scale"),
    (31, "course"),
    (32, "course_point"),
    (33, "totals"),
    (34, "activity"),
    (35, "software"),
    (37, "file_capabilities"),
    (38, "mesg_capabilities"),
    (39, "field_capabilities"),
    (49, "file_creator"),
    (51, "blood_pressure"),
    (53, "speed_zone"),
    (55, "monitoring"),
    (72, "training_file"),
    (78, "hrv"),
    (101, "length"),
    (103, "monitoring_info"),
    (127, "connectivity"),
    (128, "weather_conditions"),
    (129, "weather_alert"),
    (131, "cadence_zone"),
    (132, "hr"),
    (142, "segment_lap"),
    (145, "memo_glob"),
    (148, "segment_id"),
    (150, "segment_point"),
    (151, "segment_file"),
    (160, "gps_metadata"),
    (206, "field_description"),
    (207, "developer_data_id"),
    (216, "time_in_zone"),
];

const FILE_TYPES: EnumTable = &[
    (1, "device"),
    (2, "settings"),
    (3, "sport"),
    (4, "activity"),
    (5, "workout"),
    (6, "course"),
    (7, "schedules"),
    (9, "weight"),
    (10, "totals"),
    (11, "goals"),
    (14, "blood_pressure"),
    (15, "monitoring_a"),
    (20, "activity_summary"),
    (28, "monitoring_daily"),
    (32, "monitoring_b"),
    (34, "segment"),
    (35, "segment_list"),
];

const MANUFACTURERS: EnumTable = &[
    (1, "garmin"),
    (13, "dynastream_oem"),
    (15, "dynastream"),
    (23, "suunto"),
    (32, "wahoo_fitness"),
    (255, "development"),
];

const BASE_TYPES: EnumTable = &[
    (0x00, "enum"),
    (0x01, "sint8"),
    (0x02, "uint8"),
    (0x83, "sint16"),
    (0x84, "uint16"),
    (0x85, "sint32"),
    (0x86, "uint32"),
    (0x07, "string"),
    (0x88, "float32"),
    (0x89, "float64"),
    (0x0a, "uint8z"),
    (0x8b, "uint16z"),
    (0x8c, "uint32z"),
    (0x0d, "byte"),
    (0x8e, "sint64"),
    (0x8f, "uint64"),
    (0x90, "uint64z"),
];

/// How a field is shown.
#[derive(Clone, Copy)]
enum Kind {
    Plain,
    /// FIT `date_time`: seconds since the FIT epoch.
    Time,
    /// Semicircles (2³¹ = 180°).
    Degrees,
    /// Divide by the scale, subtract the offset, append the unit.
    Scaled(f64, f64, &'static str),
    Enum(EnumTable),
}

/// Field names for common messages: `(message, field, name, kind)`.
const FIELDS: &[(u16, u8, &str, Kind)] = &[
    (0, 0, "type", Kind::Enum(FILE_TYPES)),
    (0, 1, "manufacturer", Kind::Enum(MANUFACTURERS)),
    (0, 2, "product", Kind::Plain),
    (0, 3, "serial_number", Kind::Plain),
    (0, 4, "time_created", Kind::Time),
    (0, 5, "number", Kind::Plain),
    (0, 8, "product_name", Kind::Plain),
    (18, 0, "event", Kind::Plain),
    (18, 1, "event_type", Kind::Plain),
    (18, 2, "start_time", Kind::Time),
    (18, 3, "start_position_lat", Kind::Degrees),
    (18, 4, "start_position_long", Kind::Degrees),
    (18, 5, "sport", Kind::Plain),
    (18, 6, "sub_sport", Kind::Plain),
    (18, 7, "total_elapsed_time", Kind::Scaled(1000.0, 0.0, "s")),
    (18, 8, "total_timer_time", Kind::Scaled(1000.0, 0.0, "s")),
    (18, 9, "total_distance", Kind::Scaled(100.0, 0.0, "m")),
    (18, 11, "total_calories", Kind::Scaled(1.0, 0.0, "kcal")),
    (18, 14, "avg_speed", Kind::Scaled(1000.0, 0.0, "m/s")),
    (18, 16, "avg_heart_rate", Kind::Scaled(1.0, 0.0, "bpm")),
    (18, 17, "max_heart_rate", Kind::Scaled(1.0, 0.0, "bpm")),
    (19, 0, "event", Kind::Plain),
    (19, 1, "event_type", Kind::Plain),
    (19, 2, "start_time", Kind::Time),
    (19, 3, "start_position_lat", Kind::Degrees),
    (19, 4, "start_position_long", Kind::Degrees),
    (19, 5, "end_position_lat", Kind::Degrees),
    (19, 6, "end_position_long", Kind::Degrees),
    (19, 7, "total_elapsed_time", Kind::Scaled(1000.0, 0.0, "s")),
    (19, 8, "total_timer_time", Kind::Scaled(1000.0, 0.0, "s")),
    (19, 9, "total_distance", Kind::Scaled(100.0, 0.0, "m")),
    (20, 0, "position_lat", Kind::Degrees),
    (20, 1, "position_long", Kind::Degrees),
    (20, 2, "altitude", Kind::Scaled(5.0, 500.0, "m")),
    (20, 3, "heart_rate", Kind::Scaled(1.0, 0.0, "bpm")),
    (20, 4, "cadence", Kind::Scaled(1.0, 0.0, "rpm")),
    (20, 5, "distance", Kind::Scaled(100.0, 0.0, "m")),
    (20, 6, "speed", Kind::Scaled(1000.0, 0.0, "m/s")),
    (20, 7, "power", Kind::Scaled(1.0, 0.0, "W")),
    (20, 13, "temperature", Kind::Scaled(1.0, 0.0, "°C")),
    (20, 73, "enhanced_speed", Kind::Scaled(1000.0, 0.0, "m/s")),
    (20, 78, "enhanced_altitude", Kind::Scaled(5.0, 500.0, "m")),
    (21, 0, "event", Kind::Plain),
    (21, 1, "event_type", Kind::Plain),
    (21, 3, "data", Kind::Plain),
    (21, 4, "event_group", Kind::Plain),
    (23, 0, "device_index", Kind::Plain),
    (23, 1, "device_type", Kind::Plain),
    (23, 2, "manufacturer", Kind::Enum(MANUFACTURERS)),
    (23, 3, "serial_number", Kind::Plain),
    (23, 4, "product", Kind::Plain),
    (23, 5, "software_version", Kind::Scaled(100.0, 0.0, "")),
    (34, 0, "total_timer_time", Kind::Scaled(1000.0, 0.0, "s")),
    (34, 1, "num_sessions", Kind::Plain),
    (34, 2, "type", Kind::Plain),
    (34, 3, "event", Kind::Plain),
    (34, 4, "event_type", Kind::Plain),
    (34, 5, "local_timestamp", Kind::Time),
    (49, 0, "software_version", Kind::Plain),
    (49, 1, "hardware_version", Kind::Plain),
];

fn field_info(global: u16, num: u8) -> Option<(&'static str, Kind)> {
    match num {
        253 => return Some(("timestamp", Kind::Time)),
        254 => return Some(("message_index", Kind::Plain)),
        250 => return Some(("part_index", Kind::Plain)),
        _ => {}
    }
    FIELDS
        .iter()
        .find(|f| f.0 == global && f.1 == num)
        .map(|f| (f.2, f.3))
}

/// A definition message: the layout of a local message type.
#[derive(Debug)]
struct Def {
    global: u16,
    endian: Endian,
    /// `(field number, size, base type)`.
    fields: Vec<(u8, u8, u8)>,
    /// `(field number, size, developer data index)`.
    dev: Vec<(u8, u8, u8)>,
}

impl Def {
    fn size(&self) -> u64 {
        self.fields
            .iter()
            .chain(&self.dev)
            .map(|f| u64::from(f.1))
            .sum()
    }

    fn name(&self) -> String {
        lookup(MESSAGES, self.global.into())
            .map_or_else(|| format!("message {}", self.global), str::to_owned)
    }
}

/// Parses a definition message body (after the record header byte).
async fn read_def(cur: &mut Cursor<'_>, developer: bool) -> Result<Def> {
    cur.skip(1);
    let arch = cur.u8().await?;
    let endian = if arch == 1 { Endian::Big } else { LE };
    let g = cur.bytes(2).await?;
    let global = match endian {
        Endian::Big => crate::bytes::u16_be(&g, 0),
        Endian::Little => u16_le(&g, 0),
    }
    .unwrap_or(0);
    let n = cur.u8().await?;
    let raw = cur.bytes(u64::from(n).saturating_mul(3)).await?;
    let fields = raw
        .as_chunks::<3>()
        .0
        .iter()
        .map(|&[a, b, c]| (a, b, c))
        .collect();
    let mut dev = Vec::new();
    if developer {
        let n = cur.u8().await?;
        let raw = cur.bytes(u64::from(n).saturating_mul(3)).await?;
        dev = raw
            .as_chunks::<3>()
            .0
            .iter()
            .map(|&[a, b, c]| (a, b, c))
            .collect();
    }
    Ok(Def {
        global,
        endian,
        fields,
        dev,
    })
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: Header = read_record(&cx, file.sub(0, Header::SIZE), LE).await?;
    let header_len = u64::from(h.size);
    let header_span = file.sub(0, header_len);
    let mut header = Header::node("Header", header_span, LE);
    if header_len >= 14 {
        let b = cx.read(file.sub(0, 14)).await?;
        let stored = u16_le(&b, 12).unwrap_or(0);
        if stored != 0 && stored != crc16(b.get(..12).unwrap_or_default()) {
            header = header.diag(
                Diagnostic::warning(format!("header CRC {stored:#06x} does not match"))
                    .at(file.sub(12, 2)),
            );
        }
    }
    cx.emit(header);
    let data = file.sub(header_len, h.data_size.into());
    if data.len < u64::from(h.data_size) {
        cx.diag(Diagnostic::truncated(
            Span::new(data.source, data.offset, h.data_size.into()),
            data.len,
        ));
    }

    // The file_id message (normally first) says what kind of file this is.
    let summary = file_id_summary(&cx, data).await.unwrap_or_default();
    cx.emit(
        Node::new("Records")
            .span(data)
            .summary(format!("{} bytes", data.len))
            .lazy(records, data),
    );

    let crc_at = header_len.saturating_add(h.data_size.into());
    let crc_span = file.sub(crc_at, 2);
    if crc_span.len == 2 {
        let stored = u16_le(&cx.read(crc_span).await?, 0).unwrap_or(0);
        let mut node = leaf("CRC", crc_span, hex(stored.into(), 16));
        // Checking the CRC reads the whole file; only do it for small files.
        if crc_at <= 4 << 20 {
            let all = cx.read(file.sub(0, crc_at)).await?;
            let computed = crc16(&all);
            node = if computed == stored {
                node.summary("valid")
            } else {
                node.diag(Diagnostic::warning(format!("computed CRC {computed:#06x}")))
            };
        }
        cx.emit(node);
        let rest = file.tail(crc_at.saturating_add(2));
        if rest.len >= 14 {
            cx.emit(embedded_as("Chained FIT file", input.nested(rest), &FIT));
        }
    }
    let kind = if summary.is_empty() {
        String::new()
    } else {
        format!(" ({summary})")
    };
    cx.annotate(format!(
        "FIT {}.{}{kind}, {} bytes of records",
        h.protocol >> 4,
        h.protocol & 15,
        h.data_size
    ));
    Ok(())
}

/// Type and manufacturer from the first file_id message, if it comes early.
async fn file_id_summary(cx: &Cx, data: Span) -> Result<String> {
    let mut cur = Cursor::new(cx, data, LE);
    let mut defs: [Option<Arc<Def>>; 16] = Default::default();
    for _ in 0..4 {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let rh = cur.u8().await?;
        if rh & 0xc0 == 0x40 {
            let def = read_def(&mut cur, rh & 0x20 != 0).await?;
            if let Some(slot) = defs.get_mut(usize::from(rh & 15)) {
                *slot = Some(Arc::new(def));
            }
            continue;
        }
        let local = if rh & 0x80 != 0 {
            (rh >> 5) & 3
        } else {
            rh & 15
        };
        let Some(Some(def)) = defs.get(usize::from(local)) else {
            break;
        };
        let size = def.size();
        cur.skip(size);
        if def.global != 0 {
            continue;
        }
        let body = cx.read(data.sub(start.saturating_add(1), size)).await?;
        let mut at = 0usize;
        let (mut kind, mut maker) = (None, None);
        for &(num, sz, base) in &def.fields {
            let bytes = body
                .get(at..at.saturating_add(usize::from(sz)))
                .unwrap_or_default();
            at = at.saturating_add(usize::from(sz));
            if let Some(Value::UInt { value, .. }) = decode(bytes, base, def.endian).first() {
                match num {
                    0 => kind = lookup(FILE_TYPES, *value),
                    1 => maker = lookup(MANUFACTURERS, *value),
                    _ => {}
                }
            }
        }
        return Ok(match (kind, maker) {
            (Some(k), Some(m)) => format!("{k} file from {m}"),
            (Some(k), None) => format!("{k} file"),
            (None, Some(m)) => format!("from {m}"),
            (None, None) => String::new(),
        });
    }
    Ok(String::new())
}

async fn records(cx: Cx, data: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, data, LE);
    let mut defs: [Option<Arc<Def>>; 16] = Default::default();
    let mut n = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let rh = cur.u8().await?;
        if rh & 0xc0 == 0x40 {
            let local = rh & 15;
            let def = Arc::new(read_def(&mut cur, rh & 0x20 != 0).await?);
            let span = cur.since(start);
            let name = format!("Definition {local}: {}", def.name());
            let summary = format!(
                "{} fields, {} bytes per message",
                def.fields.len().saturating_add(def.dev.len()),
                def.size()
            );
            cx.push(
                Node::new(name)
                    .span(span)
                    .summary(summary)
                    .lazy(definition, (span, rh)),
            )
            .await;
            if let Some(slot) = defs.get_mut(usize::from(local)) {
                *slot = Some(def);
            }
        } else {
            let (local, offset) = if rh & 0x80 != 0 {
                ((rh >> 5) & 3, Some(rh & 31))
            } else {
                (rh & 15, None)
            };
            let Some(Some(def)) = defs.get(usize::from(local)).cloned() else {
                return Err(Diagnostic::malformed(format!(
                    "data message for undefined local type {local}"
                ))
                .at(data.sub(start, 1)));
            };
            let size = def.size();
            cur.skip(size);
            let span = data.sub(start, size.saturating_add(1));
            if span.len < size.saturating_add(1) {
                return Err(Diagnostic::truncated(
                    Span::new(span.source, span.offset, size.saturating_add(1)),
                    span.len,
                ));
            }
            let summary = match offset {
                Some(o) => format!("local {local}, compressed timestamp +{o}"),
                None => format!("local {local}"),
            };
            cx.push(
                Node::new(def.name())
                    .span(span)
                    .summary(summary)
                    .lazy(message, (span, def)),
            )
            .await;
        }
        n = n.saturating_add(1);
    }
    cx.annotate(format!("{n} records"));
    Ok(())
}

async fn definition(cx: Cx, (span, rh): (Span, u8)) -> Result<()> {
    cx.emit(
        leaf("Record header", span.sub(0, 1), hex(rh.into(), 8)).summary(format!(
            "local type {}{}",
            rh & 15,
            if rh & 0x20 != 0 {
                ", developer data"
            } else {
                ""
            }
        )),
    );
    let mut cur = Cursor::new(&cx, span, LE);
    cur.seek(1);
    let def = read_def(&mut cur, rh & 0x20 != 0).await?;
    cx.emit(leaf(
        "Architecture",
        span.sub(2, 1),
        text(if def.endian == Endian::Big {
            "big-endian"
        } else {
            "little-endian"
        }),
    ));
    cx.emit(leaf(
        "Global message number",
        span.sub(3, 2),
        enumv(MESSAGES, def.global.into(), 16),
    ));
    cx.emit(leaf(
        "Fields",
        span.sub(5, 1),
        uint(to_u64(def.fields.len()), 8),
    ));
    let mut at = 6u64;
    for &(num, size, base) in &def.fields {
        let name = field_info(def.global, num)
            .map_or_else(|| format!("Field {num}"), |(n, _)| n.to_owned());
        let base_name = lookup(BASE_TYPES, base.into()).unwrap_or("unknown");
        cx.emit(
            Node::new(name)
                .span(span.sub(at, 3))
                .summary(format!("#{num}, {size} bytes, {base_name}")),
        );
        at = at.saturating_add(3);
    }
    if !def.dev.is_empty() {
        at = at.saturating_add(1);
        for &(num, size, index) in &def.dev {
            cx.emit(
                Node::new(format!("Developer field {num}"))
                    .span(span.sub(at, 3))
                    .summary(format!("{size} bytes, developer {index}")),
            );
            at = at.saturating_add(3);
        }
    }
    Ok(())
}

/// Decodes the values of a field (arrays when the size is a multiple of
/// the base type's size).
fn decode(bytes: &[u8], base: u8, endian: Endian) -> Vec<Value> {
    let width = match base & 0x1f {
        0x03 | 0x04 | 0x0b => 2,
        0x05 | 0x06 | 0x08 | 0x0c => 4,
        0x09 | 0x0e | 0x0f | 0x10 => 8,
        _ => 1,
    };
    if base & 0x1f == 0x07 {
        return vec![Value::Text(crate::text::until_nul(bytes))];
    }
    if base & 0x1f == 0x0d {
        return vec![Value::Bytes(bytes.to_vec())];
    }
    bytes
        .chunks_exact(width)
        .map(|c| {
            let mut raw = 0u64;
            let iter: Box<dyn Iterator<Item = &u8>> = match endian {
                Endian::Big => Box::new(c.iter()),
                Endian::Little => Box::new(c.iter().rev()),
            };
            for &b in iter {
                raw = (raw << 8) | u64::from(b);
            }
            let bits = u8::try_from(width.saturating_mul(8)).unwrap_or(64);
            match base & 0x1f {
                0x01 | 0x03 | 0x05 | 0x0e => {
                    let shift = 64u32.saturating_sub(u32::from(bits));
                    let v = i64::from_ne_bytes(raw.to_ne_bytes())
                        .checked_shl(shift)
                        .and_then(|v| v.checked_shr(shift))
                        .unwrap_or(0);
                    Value::Int { value: v, bits }
                }
                0x08 => Value::Float(f32::from_bits(u32::try_from(raw).unwrap_or(0)).into()),
                0x09 => Value::Float(f64::from_bits(raw)),
                _ => uint(raw, bits),
            }
        })
        .collect()
}

/// Whether a value is the base type's "invalid" marker.
fn invalid(v: &Value, base: u8) -> bool {
    match (v, base & 0x1f) {
        (Value::UInt { value, .. }, 0x0a | 0x0b | 0x0c | 0x10) => *value == 0,
        (Value::UInt { value, bits, .. }, _) => *value == u64::MAX >> 64u8.saturating_sub(*bits),
        (Value::Int { value, bits }, _) => {
            i64::MAX.checked_shr(64u32.saturating_sub(u32::from(*bits))) == Some(*value)
        }
        _ => false,
    }
}

fn present(v: &Value, kind: Kind) -> (Value, Option<String>) {
    let num = match v {
        Value::UInt { value, .. } => Some(*value as f64),
        Value::Int { value, .. } => Some(*value as f64),
        _ => None,
    };
    match (kind, num, v) {
        (Kind::Time, _, Value::UInt { value, .. }) => {
            if *value < 0x1000_0000 {
                (v.clone(), Some(format!("{value} s (relative)")))
            } else {
                (
                    time(FIT_EPOCH.saturating_add(i64::try_from(*value).unwrap_or(0))),
                    None,
                )
            }
        }
        (Kind::Degrees, Some(n), _) => (
            v.clone(),
            Some(format!("{:.6}°", n * 180.0 / 2_147_483_648.0)),
        ),
        (Kind::Scaled(scale, offset, unit), Some(n), _) => {
            let x = super::round(n / scale - offset);
            (
                v.clone(),
                Some(if unit.is_empty() {
                    format!("{x}")
                } else {
                    format!("{x} {unit}")
                }),
            )
        }
        (Kind::Enum(table), _, Value::UInt { value, bits, .. }) => {
            (enumv(table, *value, *bits), None)
        }
        _ => (v.clone(), None),
    }
}

async fn message(cx: Cx, (span, def): (Span, Arc<Def>)) -> Result<()> {
    let body = cx.read(span.sub(1, def.size())).await?;
    let mut at = 0u64;
    for &(num, size, base) in &def.fields {
        let fspan = span.sub(at.saturating_add(1), size.into());
        let bytes = body
            .get(crate::bytes::to_usize(at)..crate::bytes::to_usize(at.saturating_add(size.into())))
            .unwrap_or_default();
        at = at.saturating_add(size.into());
        let (name, kind) = field_info(def.global, num).map_or_else(
            || (format!("Field {num}"), Kind::Plain),
            |(n, k)| (n.to_owned(), k),
        );
        let values = decode(bytes, base, def.endian);
        let node = match values.as_slice() {
            [v] if invalid(v, base) => Node::new(name)
                .span(fspan)
                .value(v.clone())
                .summary("invalid"),
            [v] => {
                let (value, summary) = present(v, kind);
                let node = Node::new(name).span(fspan).value(value);
                match summary {
                    Some(s) => node.summary(s),
                    None => node,
                }
            }
            list => {
                let shown: Vec<String> = list.iter().take(16).map(crate::render::value).collect();
                Node::new(name)
                    .span(fspan)
                    .summary(format!("[{}]", shown.join(", ")))
            }
        };
        cx.emit(node);
    }
    for &(num, size, index) in &def.dev {
        let fspan = span.sub(at.saturating_add(1), size.into());
        at = at.saturating_add(size.into());
        cx.emit(
            Node::new(format!("Developer field {num}"))
                .span(fspan)
                .summary(format!("developer {index}")),
        );
    }
    Ok(())
}
