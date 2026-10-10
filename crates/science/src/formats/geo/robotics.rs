//! Drone, robot and flight-controller logs: PX4 ULog, ArduPilot DataFlash
//! (binary and text), MAVLink telemetry logs, GoPro GPMF telemetry, ROS 1
//! bags, MCAP recordings and Betaflight/Cleanflight blackbox logs.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::emit_nodes;
use super::{hex, leaf, text, uint};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Path};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::scan::{Lines, Scanner};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

/// Payloads read whole are capped at this size.
const MAX_RECORD: u64 = 16 << 20;

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---------------------------------------------------------------------------
// PX4 ULog

declare_format!(pub ULOG = "ulog", "PX4 ULog flight log", ["ulg"], "application/x-ulog",
    Probe::Magic(&[(0, b"ULog\x01\x12\x35")]), ulog);

const ULOG_TYPES: EnumTable = &[
    (b'B' as u64, "Flag bits"),
    (b'F' as u64, "Format"),
    (b'I' as u64, "Info"),
    (b'M' as u64, "Multi info"),
    (b'P' as u64, "Parameter"),
    (b'Q' as u64, "Default parameter"),
    (b'A' as u64, "Add logged message"),
    (b'R' as u64, "Remove logged message"),
    (b'D' as u64, "Data"),
    (b'L' as u64, "Log"),
    (b'C' as u64, "Tagged log"),
    (b'S' as u64, "Sync"),
    (b'O' as u64, "Dropout"),
];

/// Decodes a typed ULog value (`int32_t`, `float`, `char[n]`, …).
fn ulog_value(ty: &str, b: &[u8]) -> Value {
    if ty.starts_with("char") {
        return Value::Text(crate::text::until_nul(b));
    }
    let n = |w: usize| -> u64 {
        let mut v = 0u64;
        for &x in b.iter().take(w).rev() {
            v = (v << 8) | u64::from(x);
        }
        v
    };
    match ty {
        "int8_t" => Value::Int {
            value: i64::from(n(1) as u8 as i8),
            bits: 8,
        },
        "uint8_t" | "bool" => uint(n(1), 8),
        "int16_t" => Value::Int {
            value: i64::from(n(2) as u16 as i16),
            bits: 16,
        },
        "uint16_t" => uint(n(2), 16),
        "int32_t" => Value::Int {
            value: i64::from(n(4) as u32 as i32),
            bits: 32,
        },
        "uint32_t" => uint(n(4), 32),
        "int64_t" => Value::Int {
            value: n(8).cast_signed(),
            bits: 64,
        },
        "uint64_t" => uint(n(8), 64),
        "float" => Value::Float(f32::from_bits(n(4) as u32).into()),
        "double" => Value::Float(f64::from_bits(n(8))),
        _ => Value::Bytes(b.to_vec()),
    }
}

async fn ulog(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = cx.read(file.sub_exact(0, 16)?).await?;
    cx.emit(leaf(
        "Magic",
        file.sub(0, 7),
        Value::Bytes(h.get(..7).unwrap_or_default().to_vec()),
    ));
    cx.emit(leaf(
        "Version",
        file.sub(7, 1),
        uint(h.get(7).copied().unwrap_or(0), 8),
    ));
    let start = u64_le(&h, 8).unwrap_or(0);
    cx.emit(leaf("Timestamp (µs)", file.sub(8, 8), uint(start, 64)));
    cx.annotate(format!("PX4 ULog v{}", h.get(7).copied().unwrap_or(0)));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(16);
    let mut topics: BTreeMap<u16, String> = BTreeMap::new();
    while cur.remaining() >= 3 {
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        let at = cur.pos();
        let size = u64::from(cur.u16().await?);
        let kind = cur.u8().await?;
        let body = cur.span(size);
        if body.len < size {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, size),
                body.len,
            ));
        }
        cur.skip(size);
        let span = cur.since(at);
        let name = lookup(ULOG_TYPES, kind.into())
            .map_or_else(|| format!("Message {:?}", char::from(kind)), str::to_owned);
        let b = cx.read(body.sub(0, size.min(4096))).await?;
        let mut node = Node::new(name).span(span);
        match kind {
            b'F' => {
                let t = lossy(&b);
                node = node
                    .summary(t.split(':').next().unwrap_or_default().to_owned())
                    .lazy(ulog_format, body);
            }
            b'I' | b'P' | b'M' | b'Q' => {
                let skip = usize::from(matches!(kind, b'M' | b'Q'));
                let klen = usize::from(b.get(skip).copied().unwrap_or(0));
                let key = lossy(
                    b.get(skip.saturating_add(1)..skip.saturating_add(1).saturating_add(klen))
                        .unwrap_or_default(),
                );
                let value = b
                    .get(skip.saturating_add(1).saturating_add(klen)..)
                    .unwrap_or_default();
                let (ty, k) = key.split_once(' ').unwrap_or(("", key.as_str()));
                let v = ulog_value(ty, value);
                node = node.summary(format!("{k} = {}", crate::render::value(&v)));
            }
            b'A' => {
                let id = u16_le(&b, 1).unwrap_or(0);
                let topic = lossy(b.get(3..).unwrap_or_default());
                node = node.summary(format!(
                    "#{id}: {topic} (instance {})",
                    b.first().copied().unwrap_or(0)
                ));
                topics.insert(id, topic);
            }
            b'D' => {
                let id = u16_le(&b, 0).unwrap_or(0);
                let stamp = u64_le(&b, 2).unwrap_or(0);
                let topic = topics.get(&id).cloned().unwrap_or_else(|| format!("#{id}"));
                node = node.summary(format!("{topic} @ {stamp} µs"));
            }
            b'L' => {
                let stamp = u64_le(&b, 1).unwrap_or(0);
                node = node.summary(format!(
                    "{stamp} µs: {}",
                    lossy(b.get(9..).unwrap_or_default())
                ));
            }
            b'C' => {
                let stamp = u64_le(&b, 3).unwrap_or(0);
                node = node.summary(format!(
                    "{stamp} µs: {}",
                    lossy(b.get(11..).unwrap_or_default())
                ));
            }
            b'O' => node = node.summary(format!("{} ms", u16_le(&b, 0).unwrap_or(0))),
            _ => {}
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn ulog_format(cx: Cx, body: Span) -> Result<()> {
    let b = cx.read(body).await?;
    let t = lossy(&b);
    let (name, fields) = t.split_once(':').unwrap_or((&t, ""));
    cx.emit(leaf("Name", body.sub(0, to_u64(name.len())), text(name)));
    let mut at = to_u64(name.len()).saturating_add(1);
    for f in fields.split(';') {
        let len = to_u64(f.len());
        if !f.is_empty() {
            let (ty, field) = f.split_once(' ').unwrap_or((f, ""));
            cx.emit(leaf(field.to_owned(), body.sub(at, len), text(ty)));
        }
        at = at.saturating_add(len).saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ArduPilot DataFlash (binary)

declare_format!(pub DATAFLASH = "ardupilot-bin", "ArduPilot DataFlash log", ["bin"], "application/x-ardupilot-log",
    Probe::Custom(|h| h.starts_with(b"\xa3\x95\x80\x80\x59FMT\0")), dataflash);

/// A message format: name, length, format characters and column names.
#[derive(Clone, Debug)]
struct Fmt {
    name: String,
    len: u8,
    format: String,
    columns: Vec<String>,
}

fn df_width(c: char) -> usize {
    match c {
        'b' | 'B' | 'M' => 1,
        'h' | 'H' | 'c' | 'C' => 2,
        'i' | 'I' | 'f' | 'e' | 'E' | 'L' | 'n' => 4,
        'd' | 'q' | 'Q' => 8,
        'N' => 16,
        'Z' | 'a' => 64,
        _ => 0,
    }
}

fn df_value(c: char, b: &[u8]) -> (Value, Option<String>) {
    let n = |w: usize| -> u64 {
        let mut v = 0u64;
        for &x in b.iter().take(w).rev() {
            v = (v << 8) | u64::from(x);
        }
        v
    };
    let i = |w: usize| -> i64 {
        let shift = 64u32.saturating_sub(u32::try_from(w.saturating_mul(8)).unwrap_or(64));
        n(w).cast_signed()
            .checked_shl(shift)
            .and_then(|v| v.checked_shr(shift))
            .unwrap_or(0)
    };
    match c {
        'b' => (
            Value::Int {
                value: i(1),
                bits: 8,
            },
            None,
        ),
        'B' | 'M' => (uint(n(1), 8), None),
        'h' => (
            Value::Int {
                value: i(2),
                bits: 16,
            },
            None,
        ),
        'H' => (uint(n(2), 16), None),
        'i' => (
            Value::Int {
                value: i(4),
                bits: 32,
            },
            None,
        ),
        'I' => (uint(n(4), 32), None),
        'q' => (
            Value::Int {
                value: i(8),
                bits: 64,
            },
            None,
        ),
        'Q' => (uint(n(8), 64), None),
        'f' => (Value::Float(f32::from_bits(n(4) as u32).into()), None),
        'd' => (Value::Float(f64::from_bits(n(8))), None),
        'c' => (
            Value::Int {
                value: i(2),
                bits: 16,
            },
            Some(format!("{}", i(2) as f64 / 100.0)),
        ),
        'C' => (uint(n(2), 16), Some(format!("{}", n(2) as f64 / 100.0))),
        'e' => (
            Value::Int {
                value: i(4),
                bits: 32,
            },
            Some(format!("{}", i(4) as f64 / 100.0)),
        ),
        'E' => (uint(n(4), 32), Some(format!("{}", n(4) as f64 / 100.0))),
        'L' => (
            Value::Int {
                value: i(4),
                bits: 32,
            },
            Some(format!("{}°", i(4) as f64 / 1e7)),
        ),
        'n' | 'N' | 'Z' => (Value::Text(crate::text::until_nul(b)), None),
        _ => (Value::Bytes(b.to_vec()), None),
    }
}

fn parse_fmt(body: &[u8]) -> Option<(u8, Fmt)> {
    let ty = *body.first()?;
    let len = *body.get(1)?;
    let name = crate::text::until_nul(body.get(2..6)?);
    let format = crate::text::until_nul(body.get(6..22)?);
    let columns = crate::text::until_nul(body.get(22..86)?)
        .split(',')
        .map(str::to_owned)
        .collect();
    Some((
        ty,
        Fmt {
            name,
            len,
            format,
            columns,
        },
    ))
}

async fn dataflash(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut formats: BTreeMap<u8, Arc<Fmt>> = BTreeMap::new();
    formats.insert(
        0x80,
        Arc::new(Fmt {
            name: "FMT".into(),
            len: 89,
            format: "BBnNZ".into(),
            columns: ["Type", "Length", "Name", "Format", "Columns"]
                .map(str::to_owned)
                .to_vec(),
        }),
    );
    let mut pos = 0u64;
    let mut n = 0u64;
    while pos.saturating_add(3) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(pos));
        let h = cx.read(file.sub(pos, 3)).await?;
        let fmt = if h.starts_with(b"\xa3\x95") {
            h.get(2).and_then(|t| formats.get(t)).cloned()
        } else {
            None
        };
        let Some(fmt) = fmt else {
            let next = Scanner::new(&cx, file)
                .find_seq(pos.saturating_add(1), b"\xa3\x95")
                .await?;
            let end = next.unwrap_or(file.len);
            cx.push(Node::new("Unrecognized bytes").span(file.sub(pos, end.saturating_sub(pos))))
                .await;
            match next {
                Some(p) => {
                    pos = p;
                    continue;
                }
                None => break,
            }
        };
        let len = u64::from(fmt.len).max(3);
        let span = file.sub(pos, len);
        if span.len < len {
            return Err(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        let body = cx.read(span.tail(3)).await?;
        let mut node = Node::new(fmt.name.clone()).span(span);
        if fmt.name == "FMT"
            && let Some((ty, f)) = parse_fmt(&body)
        {
            node = node.summary(format!(
                "{} ({ty}): {} [{}]",
                f.name,
                f.format,
                f.columns.join(",")
            ));
            formats.insert(ty, Arc::new(f));
        } else if fmt.name == "MSG" || fmt.name == "PARM" {
            let mut parts = Vec::new();
            let mut at = 0usize;
            for (c, col) in fmt.format.chars().zip(&fmt.columns) {
                let w = df_width(c);
                let (v, s) = df_value(c, body.get(at..at.saturating_add(w)).unwrap_or_default());
                at = at.saturating_add(w);
                if col != "TimeUS" {
                    parts.push(s.unwrap_or_else(|| crate::render::value(&v)));
                }
            }
            node = node.summary(parts.join(" "));
        }
        cx.push(node.lazy(df_message, (span, fmt))).await;
        pos = pos.saturating_add(len);
        n = n.saturating_add(1);
        if n == 1 {
            cx.annotate("ArduPilot DataFlash log");
        }
    }
    Ok(())
}

async fn df_message(cx: Cx, (span, fmt): (Span, Arc<Fmt>)) -> Result<()> {
    let body = cx.read(span.tail(3)).await?;
    cx.emit(leaf("Header", span.sub(0, 2), hex(0xa395u16, 16)));
    cx.emit(leaf(
        "Message type",
        span.sub(2, 1),
        uint(
            cx.read(span.sub(2, 1)).await?.first().copied().unwrap_or(0),
            8,
        ),
    ));
    let mut at = 0usize;
    for (i, c) in fmt.format.chars().enumerate() {
        let w = df_width(c);
        let name = fmt
            .columns
            .get(i)
            .cloned()
            .unwrap_or_else(|| format!("Field {i}"));
        let (v, s) = df_value(c, body.get(at..at.saturating_add(w)).unwrap_or_default());
        let node = leaf(name, span.sub(to_u64(at).saturating_add(3), to_u64(w)), v);
        cx.emit(match s {
            Some(s) => node.summary(s),
            None => node,
        });
        at = at.saturating_add(w);
        if w == 0 {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ArduPilot text log

declare_format!(pub ARDUPILOT_LOG = "ardupilot-log", "ArduPilot text log", ["log"], "text/x-ardupilot-log",
    Probe::Custom(|h| h.starts_with(b"FMT, 128, 89, FMT, ")), ardupilot_log);

async fn ardupilot_log(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.annotate("ArduPilot text log");
    let mut lines = Lines::new(&cx, file);
    let mut columns: BTreeMap<String, Arc<Vec<String>>> = BTreeMap::new();
    while let Some(line) = lines.next().await? {
        cx.progress_in(file, file.offset.saturating_add(lines.pos()));
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        let fields: Vec<&str> = t.split(',').map(str::trim).collect();
        let name = fields.first().copied().unwrap_or_default().to_owned();
        if name == "FMT"
            && let (Some(n), Some(cols)) = (fields.get(3), fields.get(5..))
        {
            columns.insert(
                (*n).to_owned(),
                Arc::new(cols.iter().map(|c| (*c).to_owned()).collect()),
            );
        }
        let cols = columns.get(&name).cloned().unwrap_or_default();
        let summary: String = fields
            .get(1..)
            .unwrap_or_default()
            .join(", ")
            .chars()
            .take(100)
            .collect();
        cx.push(
            Node::new(name)
                .span(line.span)
                .summary(summary)
                .lazy(text_fields, (line.span, cols)),
        )
        .await;
    }
    Ok(())
}

/// Comma-separated fields labelled with runtime column names.
async fn text_fields(cx: Cx, (span, cols): (Span, Arc<Vec<String>>)) -> Result<()> {
    let bytes = cx.read(span).await?;
    let piece = crate::formats::text::piece::Piece::new(&bytes, span);
    for (i, f) in piece.split(b',').enumerate() {
        let name = match i {
            0 => "Message".to_owned(),
            _ => cols
                .get(i.saturating_sub(1))
                .cloned()
                .unwrap_or_else(|| format!("Field {i}")),
        };
        cx.emit(super::field_node(name, f));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MAVLink telemetry log (.tlog)

/// Length of the MAVLink packet at `at`, if one starts there.
fn mavlink_at(data: &[u8], at: usize) -> Option<usize> {
    let len = usize::from(*data.get(at.saturating_add(1))?);
    match *data.get(at)? {
        0xfe => Some(len.saturating_add(8)),
        0xfd => {
            let incompat = *data.get(at.saturating_add(2))?;
            if incompat & !1 != 0 {
                return None;
            }
            Some(
                len.saturating_add(12)
                    .saturating_add(if incompat & 1 != 0 { 13 } else { 0 }),
            )
        }
        _ => None,
    }
}

/// Whether a plausible timestamp (µs, years 2000–2100) is at `at`.
fn plausible_time(data: &[u8], at: usize) -> bool {
    u64_be(data, at).is_some_and(|t| (946_684_800_000_000..4_102_444_800_000_000).contains(&t))
}

fn tlog_probe(h: &Head<'_>) -> bool {
    if !plausible_time(h.data, 0) {
        return false;
    }
    let Some(n) = mavlink_at(h.data, 8) else {
        return false;
    };
    let next = n.saturating_add(8);
    next == h.data.len()
        || (plausible_time(h.data, next) && mavlink_at(h.data, next.saturating_add(8)).is_some())
}

declare_format!(pub TLOG = "mavlink-tlog", "MAVLink telemetry log", ["tlog"], "application/x-mavlink-tlog",
    Probe::Custom(tlog_probe), tlog);

const MAVLINK_MESSAGES: EnumTable = &[
    (0, "HEARTBEAT"),
    (1, "SYS_STATUS"),
    (2, "SYSTEM_TIME"),
    (22, "PARAM_VALUE"),
    (24, "GPS_RAW_INT"),
    (27, "RAW_IMU"),
    (29, "SCALED_PRESSURE"),
    (30, "ATTITUDE"),
    (33, "GLOBAL_POSITION_INT"),
    (35, "RC_CHANNELS_RAW"),
    (36, "SERVO_OUTPUT_RAW"),
    (42, "MISSION_CURRENT"),
    (62, "NAV_CONTROLLER_OUTPUT"),
    (65, "RC_CHANNELS"),
    (74, "VFR_HUD"),
    (76, "COMMAND_LONG"),
    (77, "COMMAND_ACK"),
    (111, "TIMESYNC"),
    (147, "BATTERY_STATUS"),
    (241, "VIBRATION"),
    (242, "HOME_POSITION"),
    (253, "STATUSTEXT"),
];

async fn tlog(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut n = 0u64;
    while pos.saturating_add(10) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(pos));
        let h = cx.read(file.sub(pos, 20)).await?;
        let Some(len) = mavlink_at(&h, 8) else {
            return Err(Diagnostic::malformed("expected a MAVLink packet")
                .at(file.sub(pos.saturating_add(8), 1)));
        };
        let total = to_u64(len).saturating_add(8);
        let span = file.sub(pos, total);
        if span.len < total {
            return Err(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        let stamp = u64_be(&h, 0).unwrap_or(0);
        let v2 = h.get(8) == Some(&0xfd);
        let (sys, comp, id) = if v2 {
            let id = u32::from(h.get(15).copied().unwrap_or(0))
                | u32::from(h.get(16).copied().unwrap_or(0)) << 8
                | u32::from(h.get(17).copied().unwrap_or(0)) << 16;
            (
                h.get(13).copied().unwrap_or(0),
                h.get(14).copied().unwrap_or(0),
                id,
            )
        } else {
            (
                h.get(11).copied().unwrap_or(0),
                h.get(12).copied().unwrap_or(0),
                u32::from(h.get(13).copied().unwrap_or(0)),
            )
        };
        let name = lookup(MAVLINK_MESSAGES, id.into())
            .map_or_else(|| format!("Message {id}"), str::to_owned);
        let secs = i64::try_from(stamp / 1_000_000).unwrap_or(0);
        let summary = format!(
            "{} UTC, system {sys}/{comp}, v{}",
            crate::render::value(&Value::Timestamp { unix_seconds: secs }).trim_end_matches(" UTC"),
            if v2 { 2 } else { 1 }
        );
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(mavlink_packet, (span, v2, id)),
        )
        .await;
        pos = pos.saturating_add(total);
        n = n.saturating_add(1);
        if n == 1 {
            cx.annotate(format!(
                "MAVLink telemetry log (MAVLink {})",
                if v2 { 2 } else { 1 }
            ));
        }
    }
    Ok(())
}

async fn mavlink_packet(cx: Cx, (span, v2, id): (Span, bool, u32)) -> Result<()> {
    let b = cx.read(span).await?;
    let stamp = u64_be(&b, 0).unwrap_or(0);
    cx.emit(
        leaf(
            "Timestamp",
            span.sub(0, 8),
            Value::Timestamp {
                unix_seconds: i64::try_from(stamp / 1_000_000).unwrap_or(0),
            },
        )
        .summary(format!("{stamp} µs")),
    );
    let len = u64::from(b.get(9).copied().unwrap_or(0));
    let header = if v2 { 10 } else { 6 };
    cx.emit(leaf(
        "Magic",
        span.sub(8, 1),
        hex(b.get(8).copied().unwrap_or(0), 8),
    ));
    cx.emit(leaf("Payload length", span.sub(9, 1), uint(len, 8)));
    if v2 {
        cx.emit(leaf(
            "Incompatibility flags",
            span.sub(10, 1),
            hex(b.get(10).copied().unwrap_or(0), 8),
        ));
        cx.emit(leaf(
            "Compatibility flags",
            span.sub(11, 1),
            hex(b.get(11).copied().unwrap_or(0), 8),
        ));
    }
    let s = if v2 { 12 } else { 10 };
    cx.emit(leaf(
        "Sequence",
        span.sub(s, 1),
        uint(b.get(to_usize(s)).copied().unwrap_or(0), 8),
    ));
    cx.emit(leaf(
        "System ID",
        span.sub(s.saturating_add(1), 1),
        uint(
            b.get(to_usize(s.saturating_add(1))).copied().unwrap_or(0),
            8,
        ),
    ));
    cx.emit(leaf(
        "Component ID",
        span.sub(s.saturating_add(2), 1),
        uint(
            b.get(to_usize(s.saturating_add(2))).copied().unwrap_or(0),
            8,
        ),
    ));
    let id_len = if v2 { 3 } else { 1 };
    cx.emit(leaf(
        "Message ID",
        span.sub(s.saturating_add(3), id_len),
        Value::Enum {
            raw: id.into(),
            bits: 24,
            name: lookup(MAVLINK_MESSAGES, id.into()),
        },
    ));
    let pstart = 8u64.saturating_add(header);
    let payload_span = span.sub(pstart, len);
    // MAVLink 2 trims trailing zero bytes; pad them back for decoding.
    let mut p = b
        .get(to_usize(pstart)..to_usize(pstart.saturating_add(len)))
        .unwrap_or_default()
        .to_vec();
    p.resize(p.len().max(64), 0);
    let i32_at = |o: usize| crate::bytes::i32_le(&p, o).unwrap_or(0);
    match id {
        0 => {
            cx.emit(leaf(
                "Custom mode",
                payload_span.sub(0, 4),
                uint(u32_le(&p, 0).unwrap_or(0), 32),
            ));
            cx.emit(leaf(
                "Vehicle type",
                payload_span.sub(4, 1),
                uint(p.get(4).copied().unwrap_or(0), 8),
            ));
            cx.emit(leaf(
                "Autopilot",
                payload_span.sub(5, 1),
                uint(p.get(5).copied().unwrap_or(0), 8),
            ));
            cx.emit(leaf(
                "Base mode",
                payload_span.sub(6, 1),
                hex(p.get(6).copied().unwrap_or(0), 8),
            ));
            cx.emit(leaf(
                "System status",
                payload_span.sub(7, 1),
                uint(p.get(7).copied().unwrap_or(0), 8),
            ));
        }
        33 => {
            cx.emit(leaf(
                "Time since boot (ms)",
                payload_span.sub(0, 4),
                uint(u32_le(&p, 0).unwrap_or(0), 32),
            ));
            cx.emit(
                leaf(
                    "Latitude (1e-7°)",
                    payload_span.sub(4, 4),
                    Value::Int {
                        value: i32_at(4).into(),
                        bits: 32,
                    },
                )
                .summary(format!("{}°", f64::from(i32_at(4)) / 1e7)),
            );
            cx.emit(
                leaf(
                    "Longitude (1e-7°)",
                    payload_span.sub(8, 4),
                    Value::Int {
                        value: i32_at(8).into(),
                        bits: 32,
                    },
                )
                .summary(format!("{}°", f64::from(i32_at(8)) / 1e7)),
            );
            cx.emit(leaf(
                "Altitude (mm)",
                payload_span.sub(12, 4),
                Value::Int {
                    value: i32_at(12).into(),
                    bits: 32,
                },
            ));
            cx.emit(leaf(
                "Relative altitude (mm)",
                payload_span.sub(16, 4),
                Value::Int {
                    value: i32_at(16).into(),
                    bits: 32,
                },
            ));
        }
        253 => {
            cx.emit(leaf(
                "Severity",
                payload_span.sub(0, 1),
                uint(p.first().copied().unwrap_or(0), 8),
            ));
            cx.emit(leaf(
                "Text",
                payload_span.sub(1, 50),
                text(crate::text::until_nul(p.get(1..51).unwrap_or_default())),
            ));
        }
        _ => cx.emit(Node::new("Payload").span(payload_span)),
    }
    cx.emit(leaf(
        "Checksum",
        span.sub(pstart.saturating_add(len), 2),
        hex(
            u16_le(&b, to_usize(pstart.saturating_add(len))).unwrap_or(0),
            16,
        ),
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GoPro GPMF

fn gpmf_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"DEVC\0")
        && h.data.get(8..12).is_some_and(|k| {
            k.iter()
                .all(|b| b.is_ascii_uppercase() || b.is_ascii_digit())
        })
}

declare_format!(pub GPMF = "gpmf", "GoPro GPMF telemetry", ["gpmf"], "application/x-gpmf",
    Probe::Custom(gpmf_probe), gpmf);

fn gpmf_key(key: &str) -> Option<&'static str> {
    Some(match key {
        "DEVC" => "device",
        "DVID" => "device ID",
        "DVNM" => "device name",
        "STRM" => "stream",
        "STNM" => "stream name",
        "RMRK" => "remark",
        "SCAL" => "scale",
        "SIUN" => "SI units",
        "UNIT" => "units",
        "TYPE" => "type definition",
        "TSMP" => "total samples",
        "TIMO" => "time offset",
        "STMP" => "timestamp (µs)",
        "EMPT" => "empty payloads",
        "ACCL" => "accelerometer",
        "GYRO" => "gyroscope",
        "MAGN" => "magnetometer",
        "GPS5" => "GPS (lat, lon, alt, 2D speed, 3D speed)",
        "GPSU" => "GPS time",
        "GPSF" => "GPS fix",
        "GPSP" => "GPS precision",
        "TMPC" => "temperature (°C)",
        "CORI" => "camera orientation",
        "IORI" => "image orientation",
        "GRAV" => "gravity vector",
        "SHUT" => "exposure time",
        "ISOE" => "sensor ISO",
        _ => return None,
    })
}

fn gpmf_values(ty: u8, size: usize, data: &[u8]) -> Option<String> {
    let width = match ty {
        b'c' | b'b' | b'B' => 1,
        b's' | b'S' => 2,
        b'l' | b'L' | b'f' | b'F' | b'q' => 4,
        b'd' | b'j' | b'J' | b'Q' => 8,
        b'U' => return Some(lossy(data.get(..16)?)),
        _ => return None,
    };
    if ty == b'c' {
        let end = data.iter().position(|&b| b == 0).unwrap_or(data.len());
        return Some(crate::text::latin1(data.get(..end).unwrap_or_default()));
    }
    if ty == b'F' {
        return Some(lossy(data.get(..4)?));
    }
    let mut out = Vec::new();
    for c in data.chunks_exact(width).take(12) {
        let mut v = 0u64;
        for &x in c {
            v = (v << 8) | u64::from(x);
        }
        let shift = 64u32.saturating_sub(u32::try_from(width.saturating_mul(8)).unwrap_or(64));
        let signed = v
            .cast_signed()
            .checked_shl(shift)
            .and_then(|x| x.checked_shr(shift))
            .unwrap_or(0);
        out.push(match ty {
            b'b' | b's' | b'l' | b'j' => signed.to_string(),
            b'f' => format!("{}", f32::from_bits(v as u32)),
            b'd' => format!("{}", f64::from_bits(v)),
            b'q' => format!("{}", signed as f64 / 65536.0),
            _ => v.to_string(),
        });
    }
    let total = data.len().checked_div(width).unwrap_or(0);
    let per = size.checked_div(width).unwrap_or(1).max(1);
    let more = if total > out.len() {
        format!(" … ({} samples)", total.checked_div(per).unwrap_or(0))
    } else {
        String::new()
    };
    Some(format!("[{}]{more}", out.join(", ")))
}

async fn gpmf(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("GoPro GPMF telemetry");
    gpmf_klv(cx, (input.span, 0)).await
}

async fn gpmf_klv(cx: Cx, (region, depth): (Span, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, Endian::Big);
    while cur.remaining() >= 8 {
        cx.progress_in(region, region.offset.saturating_add(cur.pos()));
        let at = cur.pos();
        let h = cur.bytes(8).await?;
        let key = lossy(h.get(..4).unwrap_or_default());
        let ty = h.get(4).copied().unwrap_or(0);
        let size = usize::from(h.get(5).copied().unwrap_or(0));
        let repeat = usize::from(u16::from_be_bytes([
            h.get(6).copied().unwrap_or(0),
            h.get(7).copied().unwrap_or(0),
        ]));
        let len = to_u64(size.saturating_mul(repeat));
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len.saturating_add((4u64.saturating_sub(len % 4)) % 4));
        let span = region.sub(at, len.saturating_add(8));
        let mut node = Node::new(key.clone()).span(span);
        if let Some(d) = gpmf_key(&key) {
            node = node.desc(d);
        }
        if ty == 0 {
            node = node.summary(gpmf_key(&key).unwrap_or("nested").to_owned());
            node = if depth < 16 {
                node.lazy(
                    crate::expander!(self::gpmf_klv: (Span, u32)),
                    (body, depth.saturating_add(1)),
                )
            } else {
                node.diag(Diagnostic::limit("nested too deeply"))
            };
        } else {
            let data = cx.read(body.sub(0, 4096)).await?;
            let shown = gpmf_values(ty, size, &data)
                .unwrap_or_else(|| format!("type {:?}, {size}×{repeat}", char::from(ty)));
            node = node.summary(shown);
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ROS 1 bag

declare_format!(pub ROSBAG = "rosbag", "ROS bag (v2.0)", ["bag"], "application/x-rosbag",
    Probe::Magic(&[(0, b"#ROSBAG V2.0\n")]), rosbag);

const ROS_OPS: EnumTable = &[
    (2, "Message data"),
    (3, "Bag header"),
    (4, "Index data"),
    (5, "Chunk"),
    (6, "Chunk info"),
    (7, "Connection"),
];

/// Parses `len, name=value` fields.
fn ros_fields(b: &[u8]) -> Vec<(String, Vec<u8>, usize, usize)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(len) = u32_le(b, at) {
        let start = at.saturating_add(4);
        let end = start.saturating_add(to_usize(len.into()));
        let Some(field) = b.get(start..end) else {
            break;
        };
        let eq = field.iter().position(|&c| c == b'=').unwrap_or(field.len());
        out.push((
            lossy(field.get(..eq).unwrap_or_default()),
            field
                .get(eq.saturating_add(1)..)
                .unwrap_or_default()
                .to_vec(),
            at,
            end,
        ));
        at = end;
        if out.len() >= 4096 {
            break;
        }
    }
    out
}

fn ros_field_value(name: &str, v: &[u8]) -> Value {
    match (name, v.len()) {
        ("op", 1) => Value::Enum {
            raw: v.first().copied().unwrap_or(0).into(),
            bits: 8,
            name: lookup(ROS_OPS, v.first().copied().unwrap_or(0).into()),
        },
        ("time" | "start_time" | "end_time", 8) => {
            let s = u32_le(v, 0).unwrap_or(0);
            Value::Timestamp {
                unix_seconds: s.into(),
            }
        }
        (_, 8) if !v.iter().all(|b| b.is_ascii_graphic()) => uint(u64_le(v, 0).unwrap_or(0), 64),
        (_, 4) if !v.iter().all(|b| b.is_ascii_graphic()) => uint(u32_le(v, 0).unwrap_or(0), 32),
        _ => Value::Text(lossy(v)),
    }
}

async fn rosbag(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(leaf("Magic", file.sub(0, 13), text("#ROSBAG V2.0")));
    cx.annotate("ROS bag 2.0");
    ros_records(cx, (file.tail(13), Path::new())).await
}

async fn ros_records(cx: Cx, (region, path): (Span, Path)) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, LE);
    while cur.remaining() >= 8 {
        cx.progress_in(region, region.offset.saturating_add(cur.pos()));
        let at = cur.pos();
        let hlen = u64::from(cur.u32().await?);
        if hlen > MAX_RECORD {
            return Err(Diagnostic::limit("record header too large").at(region.sub(at, 4)));
        }
        let header = cur.span(hlen);
        let hb = cur.bytes(hlen).await?;
        let dlen = u64::from(cur.u32().await?);
        let data = cur.span(dlen);
        if data.len < dlen {
            return Err(Diagnostic::truncated(
                Span::new(data.source, data.offset, dlen),
                data.len,
            ));
        }
        cur.skip(dlen);
        let span = cur.since(at);
        let fields = ros_fields(&hb);
        let get = |n: &str| fields.iter().find(|f| f.0 == n).map(|f| f.1.clone());
        let op = get("op").and_then(|v| v.first().copied()).unwrap_or(0);
        let name =
            lookup(ROS_OPS, op.into()).map_or_else(|| format!("Record op {op}"), str::to_owned);
        let mut node = Node::new(name).span(span);
        match op {
            7 => node = node.summary(lossy(&get("topic").unwrap_or_default())),
            2 => {
                let conn = get("conn").and_then(|v| u32_le(&v, 0)).unwrap_or(0);
                let time = get("time").and_then(|v| u32_le(&v, 0)).unwrap_or(0);
                node = node.summary(format!("connection {conn}, t={time} s, {dlen} bytes"));
            }
            5 => {
                node = node.summary(format!(
                    "{}, {} bytes",
                    lossy(&get("compression").unwrap_or_default()),
                    get("size").and_then(|v| u32_le(&v, 0)).unwrap_or(0)
                ))
            }
            3 => {
                node = node.summary(format!(
                    "{} connections, {} chunks",
                    get("conn_count").and_then(|v| u32_le(&v, 0)).unwrap_or(0),
                    get("chunk_count").and_then(|v| u32_le(&v, 0)).unwrap_or(0)
                ))
            }
            _ => {}
        }
        let compression = get("compression").map(|c| lossy(&c)).unwrap_or_default();
        let child = path.enter(span.offset, 2);
        cx.push(node.lazy(ros_record, (header, data, op, compression, child.ok())))
            .await;
    }
    Ok(())
}

async fn ros_record(
    cx: Cx,
    (header, data, op, compression, path): (Span, Span, u8, String, Option<Path>),
) -> Result<()> {
    let hb = cx.read(header).await?;
    for (name, value, a, b) in ros_fields(&hb) {
        let v = ros_field_value(&name, &value);
        cx.emit(leaf(
            name,
            header.sub(to_u64(a), to_u64(b.saturating_sub(a))),
            v,
        ));
    }
    match (op, compression.as_str(), path) {
        (5, "none", Some(path)) => cx.emit(Node::new("Records").span(data).lazy(
            crate::expander!(self::ros_records: (Span, Path)),
            (data, path),
        )),
        (5, c, _) => cx.emit(
            Node::new("Compressed records")
                .span(data)
                .diag(Diagnostic::unsupported(format!("{c} compression"))),
        ),
        (7, _, _) => {
            let db = cx.read(data.sub(0, MAX_RECORD)).await?;
            let nodes: Vec<Node> = ros_fields(&db)
                .into_iter()
                .map(|(n, v, a, b)| {
                    crate::formats::text::text_node(
                        n,
                        data.sub(to_u64(a), to_u64(b.saturating_sub(a))),
                        &lossy(&v),
                    )
                })
                .collect();
            cx.emit(
                Node::new("Connection header")
                    .span(data)
                    .lazy(emit_nodes, std::sync::Arc::new(nodes)),
            );
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MCAP

declare_format!(pub MCAP = "mcap", "MCAP recording", ["mcap"], "application/x-mcap",
    Probe::Magic(&[(0, b"\x89MCAP0\r\n")]), mcap);

const MCAP_OPS: EnumTable = &[
    (0x01, "Header"),
    (0x02, "Footer"),
    (0x03, "Schema"),
    (0x04, "Channel"),
    (0x05, "Message"),
    (0x06, "Chunk"),
    (0x07, "Message index"),
    (0x08, "Chunk index"),
    (0x09, "Attachment"),
    (0x0a, "Attachment index"),
    (0x0b, "Statistics"),
    (0x0c, "Metadata"),
    (0x0d, "Metadata index"),
    (0x0e, "Summary offset"),
    (0x0f, "Data end"),
];

/// A length-prefixed (u32) string at `*at`.
fn mcap_str(b: &[u8], at: &mut usize) -> Option<String> {
    let len = to_usize(u32_le(b, *at)?.into());
    let start = at.checked_add(4)?;
    let s = lossy(b.get(start..start.checked_add(len)?)?);
    *at = start.saturating_add(len);
    Some(s)
}

async fn mcap(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(leaf(
        "Magic",
        file.sub(0, 8),
        Value::Bytes(cx.read(file.sub(0, 8)).await?),
    ));
    let h = cx.read(file.sub(8, 256)).await?;
    let mut at = 9usize;
    let profile = mcap_str(&h, &mut at).unwrap_or_default();
    let library = mcap_str(&h, &mut at).unwrap_or_default();
    cx.annotate(format!(
        "MCAP{}{}",
        if profile.is_empty() {
            String::new()
        } else {
            format!(" ({profile})")
        },
        if library.is_empty() {
            String::new()
        } else {
            format!(", written by {library}")
        }
    ));
    mcap_records(cx, (file.tail(8), Path::new())).await
}

async fn mcap_records(cx: Cx, (region, path): (Span, Path)) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, LE);
    while cur.remaining() >= 9 {
        cx.progress_in(region, region.offset.saturating_add(cur.pos()));
        let at = cur.pos();
        let peek = cur.peek(8).await?;
        if peek.as_slice() == b"\x89MCAP0\r\n" {
            cur.skip(8);
            cx.push(leaf("Magic", cur.since(at), Value::Bytes(peek)))
                .await;
            continue;
        }
        let op = cur.u8().await?;
        let len = cur.u64().await?;
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len);
        let span = cur.since(at);
        let name =
            lookup(MCAP_OPS, op.into()).map_or_else(|| format!("Record {op:#04x}"), str::to_owned);
        let b = cx.read(body.sub(0, 512)).await?;
        let mut p = 0usize;
        let summary = match op {
            0x01 => {
                let profile = mcap_str(&b, &mut p).unwrap_or_default();
                format!(
                    "profile {profile:?}, library {:?}",
                    mcap_str(&b, &mut p).unwrap_or_default()
                )
            }
            0x03 => {
                p = 2;
                let name = mcap_str(&b, &mut p).unwrap_or_default();
                format!(
                    "#{} {name} ({})",
                    u16_le(&b, 0).unwrap_or(0),
                    mcap_str(&b, &mut p).unwrap_or_default()
                )
            }
            0x04 => {
                p = 4;
                let topic = mcap_str(&b, &mut p).unwrap_or_default();
                format!(
                    "#{} {topic} ({}), schema {}",
                    u16_le(&b, 0).unwrap_or(0),
                    mcap_str(&b, &mut p).unwrap_or_default(),
                    u16_le(&b, 2).unwrap_or(0)
                )
            }
            0x05 => format!(
                "channel {}, seq {}, log time {} ns, {} bytes",
                u16_le(&b, 0).unwrap_or(0),
                u32_le(&b, 2).unwrap_or(0),
                u64_le(&b, 6).unwrap_or(0),
                len.saturating_sub(22)
            ),
            0x06 => {
                p = 28;
                let comp = mcap_str(&b, &mut p).unwrap_or_default();
                format!(
                    "{} bytes uncompressed, compression {:?}",
                    u64_le(&b, 16).unwrap_or(0),
                    comp
                )
            }
            0x09 => {
                p = 16;
                format!("{:?}", mcap_str(&b, &mut p).unwrap_or_default())
            }
            0x0c => format!("{:?}", mcap_str(&b, &mut p).unwrap_or_default()),
            _ => format!("{len} bytes"),
        };
        let mut node = Node::new(name).span(span).summary(summary);
        if op == 0x06 {
            p = 28;
            let comp = mcap_str(&b, &mut p).unwrap_or_default();
            let records_at = to_u64(p).saturating_add(8);
            let records = body.tail(records_at);
            node = match (comp.as_str(), path.enter(span.offset, 2)) {
                ("", Ok(child)) => node.lazy(
                    crate::expander!(self::mcap_records: (Span, Path)),
                    (records, child),
                ),
                ("", Err(e)) => node.diag(e),
                (c, _) => node.diag(Diagnostic::unsupported(format!("{c} compression"))),
            };
        }
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Betaflight / Cleanflight blackbox

const BLACKBOX: &[u8] = b"H Product:Blackbox flight data recorder by Nicholas Sherlock";

declare_format!(pub BLACKBOX_LOG = "blackbox-log", "Betaflight/Cleanflight blackbox log", ["bbl", "bfl", "txt"], "application/x-blackbox",
    Probe::Custom(|h| h.starts_with(BLACKBOX)), blackbox);

async fn blackbox(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut scan = Scanner::new(&cx, file);
    let mut pos = 0u64;
    let mut n = 0u64;
    loop {
        let next = scan.find_seq(pos.saturating_add(1), BLACKBOX).await?;
        let end = next.unwrap_or(file.len);
        let span = file.sub(pos, end.saturating_sub(pos));
        cx.push(
            Node::new(format!("Log {}", n.saturating_add(1)))
                .span(span)
                .lazy(blackbox_log, span),
        )
        .await;
        n = n.saturating_add(1);
        match next {
            Some(p) => pos = p,
            None => break,
        }
    }
    cx.annotate(format!("Blackbox flight log, {n} logs"));
    Ok(())
}

async fn blackbox_log(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut end = 0u64;
    while let Some(line) = lines.peek().await? {
        cx.progress_in(span, span.offset.saturating_add(lines.pos()));
        if !line.bytes.starts_with(b"H ") {
            break;
        }
        let _ = lines.next().await?;
        end = line.next;
        let rest = line.piece().from(2);
        let node = match rest.split_once(b':') {
            Some((k, v)) => super::field_node(k.trim().text(), v).span(line.span),
            None => leaf("Header", line.span, text(rest.text())),
        };
        cx.push(node).await;
    }
    cx.push(
        Node::new("Frames")
            .span(span.tail(end))
            .summary("binary-encoded I/P/G/H/S/E frames"),
    )
    .await;
    Ok(())
}
