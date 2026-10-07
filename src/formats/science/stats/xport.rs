//! SAS transport files (XPORT, `.xpt`), versions 5 and 8.
//!
//! Everything comes in 80-byte records: a library header, then per member
//! (data set) a member header, a descriptor header and two descriptor
//! records (name, label, type, times), a NAMESTR header and one 140-byte
//! namestr per variable (type, length, name, label, formats, position),
//! version 8's optional long-label records, and an OBS header followed by
//! the observations, fixed-width rows of big-endian IBM 370 floating-point
//! numbers (possibly truncated) and blank-padded strings, the last record
//! padded with blanks. Layout per SAS's TS-140 note as remembered; checked
//! against files written by ReadStat (pyreadstat).

use std::sync::Arc;

use super::{Cell, Item, date_cell, decode_text, row_node, trim_end};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::{Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

const PREFIX: &[u8] = b"HEADER RECORD*******";

declare_format!(pub XPORT = "sas-xport", "SAS transport file", ["xpt", "xport"], "application/x-sas-xport",
    Probe::Magic(&[
        (0, b"HEADER RECORD*******LIBRARY HEADER RECORD!!!!!!!"),
        (0, b"HEADER RECORD*******LIBV8   HEADER RECORD!!!!!!!"),
    ]), dissect);

/// SAS dates count days from 1960-01-01.
const EPOCH: i64 = -315_619_200;

const DATE_FORMATS: &[&str] = &[
    "DATE", "MMDDYY", "DDMMYY", "YYMMDD", "E8601DA", "WEEKDATE", "WORDDATE", "MONYY",
];
const DATETIME_FORMATS: &[&str] = &["DATETIME", "E8601DT"];

#[derive(Clone, Debug)]
struct Var {
    name: String,
    label: String,
    format: String,
    numeric: bool,
    len: u64,
    pos: u64,
    span: Span,
}

#[derive(Clone, Debug)]
struct Member {
    name: String,
    vars: Vec<Var>,
    obs: Span,
    row: u64,
    rows: u64,
}

fn text(bytes: &[u8]) -> String {
    decode_text(None, trim_end(bytes))
}

/// The header record name (`MEMBER  `, `OBSV8   `, ...) if `rec` is one.
fn header_name(rec: &[u8]) -> Option<&[u8]> {
    if rec.starts_with(PREFIX) {
        rec.get(20..28)
    } else {
        None
    }
}

/// The digits in `rec[at..at+len]`, ignoring blanks.
fn digits(rec: &[u8], at: usize, len: usize) -> Option<u64> {
    let s = String::from_utf8_lossy(rec.get(at..at.saturating_add(len))?).into_owned();
    s.trim().parse().ok()
}

/// An IBM 370 hexadecimal float, big-endian, truncated to `bytes.len()`.
pub fn ibm_float(bytes: &[u8]) -> f64 {
    let mut full = [0u8; 8];
    for (o, b) in full.iter_mut().zip(bytes) {
        *o = *b;
    }
    let bits = u64::from_be_bytes(full);
    let fraction = bits & 0x00ff_ffff_ffff_ffff;
    if fraction == 0 {
        return 0.0;
    }
    let exponent = i32::from(((bits >> 56) & 0x7f) as u8).saturating_sub(64);
    let magnitude = fraction as f64 / 72_057_594_037_927_936.0 * 16f64.powi(exponent);
    if bits >> 63 == 1 {
        -magnitude
    } else {
        magnitude
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 240)).await?;
    let v8 = head.get(20..28) == Some(b"LIBV8   ");
    let rec = |i: usize| {
        head.get(i.saturating_mul(80)..i.saturating_add(1).saturating_mul(80))
            .unwrap_or_default()
    };
    let real = rec(1);
    let field = |name: &'static str, r: u64, at: u64, len: u64| {
        let start = to_usize(at);
        let raw = if r == 1 { real } else { rec(2) };
        Node::new(name)
            .span(file.sub(r.saturating_mul(80).saturating_add(at), len))
            .value(Value::Text(text(
                raw.get(start..start.saturating_add(to_usize(len)))
                    .unwrap_or_default(),
            )))
    };
    let version = text(real.get(24..32).unwrap_or_default());
    let os = text(real.get(32..40).unwrap_or_default());
    let created = text(real.get(64..80).unwrap_or_default());
    let header = vec![
        Node::new("Header record").span(file.sub(0, 80)),
        field("SAS symbol 1", 1, 0, 8),
        field("SAS symbol 2", 1, 8, 8),
        field("Library", 1, 16, 8),
        field("SAS version", 1, 24, 8),
        field("Operating system", 1, 32, 8),
        field("Created", 1, 64, 16),
        field("Modified", 2, 0, 16),
    ];
    cx.emit(
        Node::new("Library header")
            .span(file.sub(0, 240))
            .summary(format!("SAS {version} on {os}, {created}"))
            .lazy(emit_nodes, Arc::new(header)),
    );
    let mut pos = 240u64;
    let mut names = Vec::new();
    while pos < file.len {
        cx.checkpoint().await;
        let r = cx.read(file.sub(pos, 80)).await?;
        if !matches!(header_name(&r), Some(b"MEMBER  " | b"MEMBV8  ")) {
            cx.diag(Diagnostic::malformed("expected a member header").at(file.sub(pos, 80)));
            break;
        }
        let (member, next, node) = match member(&cx, file, pos, v8).await {
            Ok(m) => m,
            Err(e) => {
                cx.push(Node::new("Member").span(file.tail(pos)).diag(e))
                    .await;
                break;
            }
        };
        names.push(member.name.clone());
        cx.push(node).await;
        if next <= pos {
            break;
        }
        pos = next;
    }
    cx.annotate(format!(
        "SAS transport (XPORT v{}), {} member{}: {}",
        if v8 { 8 } else { 5 },
        names.len(),
        if names.len() == 1 { "" } else { "s" },
        names.join(", ")
    ));
    Ok(())
}

/// Parses the member at `pos`; returns it, the offset after its data, and
/// its node.
async fn member(cx: &Cx, file: Span, pos: u64, v8: bool) -> Result<(Member, u64, Node)> {
    let head = cx.read(file.sub_exact(pos, 80 * 5)?).await?;
    let rec = |i: usize| {
        head.get(i.saturating_mul(80)..i.saturating_add(1).saturating_mul(80))
            .unwrap_or_default()
    };
    let namestr_len = digits(rec(0), 74, 4)
        .filter(|&n| n == 136 || n == 140)
        .unwrap_or(140);
    let d1 = rec(2);
    let d2 = rec(3);
    let (name, version, os) = if v8 {
        (
            text(d1.get(8..40).unwrap_or_default()),
            text(d1.get(48..56).unwrap_or_default()),
            text(d1.get(56..64).unwrap_or_default()),
        )
    } else {
        (
            text(d1.get(8..16).unwrap_or_default()),
            text(d1.get(24..32).unwrap_or_default()),
            text(d1.get(32..40).unwrap_or_default()),
        )
    };
    let created = text(d1.get(64..80).unwrap_or_default());
    let modified = text(d2.get(0..16).unwrap_or_default());
    let label = text(d2.get(32..72).unwrap_or_default());
    let kind = text(d2.get(72..80).unwrap_or_default());
    let count = digits(rec(4), 54, 4).unwrap_or(0);
    let descriptor = |name: &'static str, r: u64, at: u64, len: u64, value: &str| {
        Node::new(name)
            .span(file.sub(
                pos.saturating_add(r.saturating_mul(80)).saturating_add(at),
                len,
            ))
            .value(Value::Text(value.to_owned()))
    };
    let mut fields = vec![
        Node::new("Member header").span(file.sub(pos, 80)),
        Node::new("Descriptor header").span(file.sub(pos.saturating_add(80), 80)),
        descriptor("Data set name", 2, 8, if v8 { 32 } else { 8 }, &name),
        descriptor("SAS version", 2, if v8 { 48 } else { 24 }, 8, &version),
        descriptor("Operating system", 2, if v8 { 56 } else { 32 }, 8, &os),
        descriptor("Created", 2, 64, 16, &created),
        descriptor("Modified", 3, 0, 16, &modified),
        descriptor("Label", 3, 32, 40, &label),
        descriptor("Type", 3, 72, 8, &kind),
        Node::new("Namestr header")
            .span(file.sub(pos.saturating_add(320), 80))
            .value(Value::UInt {
                value: count,
                bits: 32,
                radix: Radix::Dec,
            }),
    ];
    // Namestrs, padded to a whole record.
    let names_at = pos.saturating_add(400);
    let names_len = count.saturating_mul(namestr_len);
    let names = file.sub_exact(names_at, names_len)?;
    let raw = cx.read(names).await?;
    let mut vars = Vec::new();
    for i in 0..count {
        let at = to_usize(i.saturating_mul(namestr_len));
        let n = raw
            .get(at..at.saturating_add(to_usize(namestr_len)))
            .unwrap_or_default();
        let be16 = |o: usize| u64::from(crate::bytes::u16_be(n, o).unwrap_or(0));
        let long = if v8 {
            text(n.get(88..120).unwrap_or_default())
        } else {
            String::new()
        };
        let short = text(n.get(8..16).unwrap_or_default());
        vars.push(Var {
            name: if long.is_empty() { short } else { long },
            label: text(n.get(16..56).unwrap_or_default()),
            format: text(n.get(56..64).unwrap_or_default()),
            numeric: be16(0) == 1,
            len: be16(4),
            pos: u64::from(crate::bytes::u32_be(n, 84).unwrap_or(0)),
            span: names.sub(i.saturating_mul(namestr_len), namestr_len),
        });
    }
    let row = vars
        .iter()
        .map(|v| v.pos.saturating_add(v.len))
        .max()
        .unwrap_or(0);
    // Skip to the OBS header (past padding and any long-label records).
    let mut at = names_at.saturating_add(names_len.div_ceil(80).saturating_mul(80));
    let mut rows = None;
    loop {
        cx.checkpoint().await;
        let r = cx.read(file.sub_exact(at, 80)?).await?;
        let kind = header_name(&r);
        if matches!(kind, Some(b"OBS     " | b"OBSV8   ")) {
            fields.push(Node::new("Observation header").span(file.sub(at, 80)));
            if v8 {
                rows = digits(&r, 48, 15);
            }
            at = at.saturating_add(80);
            break;
        }
        if let Some(k) = kind {
            fields.push(
                Node::new(format!("{} header", String::from_utf8_lossy(k).trim()))
                    .span(file.sub(at, 80)),
            );
        }
        at = at.saturating_add(80);
    }
    // The data runs to the next member header or the end of the file.
    let start = at;
    let mut end = file.len;
    let mut scan = start;
    while scan.saturating_add(80) <= file.len {
        cx.checkpoint().await;
        let chunk_len = (file.len.saturating_sub(scan) / 80)
            .min(512)
            .saturating_mul(80);
        let chunk = cx.read(file.sub(scan, chunk_len)).await?;
        if let Some(k) = chunk
            .as_chunks::<80>()
            .0
            .iter()
            .position(|r| matches!(header_name(r), Some(b"MEMBER  " | b"MEMBV8  ")))
        {
            end = scan.saturating_add(to_u64(k).saturating_mul(80));
            break;
        }
        scan = scan.saturating_add(chunk_len.max(80));
    }
    let obs = file.sub(start, end.saturating_sub(start));
    let rows = match (rows, row) {
        (_, 0) => 0,
        (Some(n), _) => n.min(obs.len.checked_div(row).unwrap_or(0)),
        (None, _) => {
            // Trailing blank padding is not an observation.
            let mut n = obs.len.checked_div(row).unwrap_or(0);
            while n > 0 {
                let last = cx
                    .read(obs.sub(n.saturating_sub(1).saturating_mul(row), row))
                    .await?;
                if last.iter().all(|&b| b == b' ')
                    && obs
                        .len
                        .saturating_sub(n.saturating_sub(1).saturating_mul(row))
                        <= 80
                {
                    n = n.saturating_sub(1);
                } else {
                    break;
                }
            }
            n
        }
    };
    let m = Member {
        name: name.clone(),
        vars,
        obs,
        row,
        rows,
    };
    let m = Arc::new(m);
    let node = Node::new(format!("Member {name}"))
        .span(file.sub(pos, end.saturating_sub(pos)))
        .summary(format!(
            "{} variables × {rows} observations{}",
            m.vars.len(),
            if label.is_empty() {
                String::new()
            } else {
                format!(", {label:?}")
            }
        ))
        .lazy(member_nodes, (m.clone(), fields.into()));
    Ok(((*m).clone(), end, node))
}

async fn member_nodes(cx: Cx, (m, fields): (Arc<Member>, Arc<[Node]>)) -> Result<()> {
    cx.emit(Node::new("Descriptors").lazy(emit_nodes, Arc::new(fields.to_vec())));
    cx.emit(
        Node::new("Variables")
            .summary(format!("{} variables", m.vars.len()))
            .lazy(variables, m.clone()),
    );
    cx.emit(
        Node::new("Observations")
            .span(m.obs)
            .summary(format!("{} rows × {} bytes", m.rows, m.row))
            .lazy(observations, m.clone()),
    );
    Ok(())
}

async fn variables(cx: Cx, m: Arc<Member>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(m.vars.len())));
    for var in &m.vars {
        let kind = if var.numeric { "numeric" } else { "character" };
        let mut parts = vec![format!("{kind}({})", var.len)];
        if !var.format.is_empty() {
            parts.push(var.format.clone());
        }
        if !var.label.is_empty() {
            parts.push(format!("{:?}", var.label));
        }
        let s = var.span;
        let fields = vec![
            Node::new("Type")
                .span(s.sub(0, 2))
                .value(Value::Text(kind.to_owned())),
            Node::new("Length").span(s.sub(4, 2)).value(Value::UInt {
                value: var.len,
                bits: 16,
                radix: Radix::Dec,
            }),
            Node::new("Name")
                .span(s.sub(8, 8))
                .value(Value::Text(var.name.clone())),
            Node::new("Label")
                .span(s.sub(16, 40))
                .value(Value::Text(var.label.clone())),
            Node::new("Format")
                .span(s.sub(56, 8))
                .value(Value::Text(var.format.clone())),
            Node::new("Position").span(s.sub(84, 4)).value(Value::UInt {
                value: var.pos,
                bits: 32,
                radix: Radix::Dec,
            }),
        ];
        cx.push(
            Node::new(var.name.clone())
                .span(var.span)
                .summary(parts.join(", "))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

fn cell(var: &Var, raw: &[u8]) -> Cell {
    if !var.numeric {
        return Cell::Text(text(raw));
    }
    let first = raw.first().copied().unwrap_or(0);
    if raw.iter().skip(1).all(|&b| b == 0) && matches!(first, b'.' | b'_' | b'A'..=b'Z') {
        let name = if first == b'.' {
            ".".to_owned()
        } else {
            format!(".{}", char::from(first))
        };
        return Cell::Missing { name, raw: None };
    }
    let v = ibm_float(raw);
    let format = var.format.to_ascii_uppercase();
    if DATE_FORMATS.contains(&format.as_str()) {
        date_cell(v, 86_400.0, EPOCH, false)
    } else if DATETIME_FORMATS.contains(&format.as_str()) {
        date_cell(v, 1.0, EPOCH, true)
    } else {
        Cell::Number(v)
    }
}

async fn observations(cx: Cx, m: Arc<Member>) -> Result<()> {
    if m.row == 0 {
        return Ok(());
    }
    cx.set_count(Count::Exact(m.rows));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < m.rows {
        let at = i;
        cx.mark(move || at);
        let span = m.obs.sub(i.saturating_mul(m.row), m.row);
        let name = format!("Observation {}", i.saturating_add(1));
        i = i.saturating_add(1);
        if cx.skipping() {
            cx.push(Node::new(name)).await;
            continue;
        }
        let raw = cx.read(span).await?;
        let items = m
            .vars
            .iter()
            .map(|v| {
                let start = to_usize(v.pos);
                Item {
                    name: v.name.clone(),
                    cell: cell(
                        v,
                        raw.get(start..start.saturating_add(to_usize(v.len)))
                            .unwrap_or_default(),
                    ),
                    label: None,
                    span: span.sub(v.pos, v.len),
                }
            })
            .collect();
        cx.push(row_node(name, span, items)).await;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ibm_floats() {
        assert_eq!(ibm_float(&[0x41, 0x10, 0, 0, 0, 0, 0, 0]), 1.0);
        assert_eq!(ibm_float(&[0xc1, 0x10, 0, 0, 0, 0, 0, 0]), -1.0);
        assert_eq!(ibm_float(&[0x42, 0x64]), 100.0);
        assert_eq!(ibm_float(&[0x40, 0x80, 0, 0, 0, 0, 0, 0]), 0.5);
        assert_eq!(ibm_float(&[0; 8]), 0.0);
    }
}
