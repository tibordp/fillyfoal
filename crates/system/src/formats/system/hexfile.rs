//! Text firmware images: Intel HEX and Motorola S-records.
//!
//! One record per line: a start character, hex-encoded byte count, address,
//! record type, data and checksum. Records are listed in pages with their
//! absolute addresses (Intel extended segment/linear addresses applied) and
//! verified checksums; expanding a record shows its fields over the text.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::{count, emit_nodes, hex, human_size, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

/// Longest line considered (255 data bytes in hex plus framing).
const MAX_LINE: u64 = 600;

pub static IHEX: Format = Format {
    name: "ihex",
    title: "Intel HEX",
    extensions: &["hex", "ihex", "ihx", "h86", "a43", "a90"],
    mime: "text/x-hex",
    probe: Probe::Custom(|h| {
        first_line(h).is_some_and(|l| parse_ihex(l).is_some_and(|r| r.checksum_ok))
    }),
    dissect: crate::expander!(dissect_ihex: Input),
};

pub static SREC: Format = Format {
    name: "srec",
    title: "Motorola S-record",
    extensions: &["srec", "s19", "s28", "s37", "mot", "s", "sx", "exo"],
    mime: "text/x-srecord",
    probe: Probe::Custom(|h| {
        first_line(h).is_some_and(|l| parse_srec(l).is_some_and(|r| r.checksum_ok))
    }),
    dissect: crate::expander!(dissect_srec: Input),
};

fn first_line<'a>(h: &Head<'a>) -> Option<&'a [u8]> {
    let data = h.data;
    let end = data.iter().position(|&b| b == b'\n').unwrap_or(data.len());
    let line = data.get(..end)?;
    Some(line.strip_suffix(b"\r").unwrap_or(line))
}

const IHEX_TYPE: EnumTable = &[
    (0, "data"),
    (1, "end of file"),
    (2, "extended segment address"),
    (3, "start segment address"),
    (4, "extended linear address"),
    (5, "start linear address"),
];

const SREC_TYPE: EnumTable = &[
    (0, "header"),
    (1, "data, 16-bit address"),
    (2, "data, 24-bit address"),
    (3, "data, 32-bit address"),
    (5, "record count, 16-bit"),
    (6, "record count, 24-bit"),
    (7, "start address, 32-bit"),
    (8, "start address, 24-bit"),
    (9, "start address, 16-bit"),
];

/// A decoded record. Offsets are in characters within the line.
#[derive(Clone, Debug)]
struct Rec {
    kind: u8,
    address: u64,
    address_digits: usize,
    data: Vec<u8>,
    checksum: u8,
    checksum_ok: bool,
}

/// The bytes of a record's hex digits; whitespace inside a record is
/// rejected, so offsets in the line stay two characters per byte.
fn hex_bytes(text: &[u8]) -> Option<Vec<u8>> {
    crate::text::unhex(text).filter(|b| b.len().saturating_mul(2) == text.len())
}

/// `:LLAAAATT<data>CC`
fn parse_ihex(line: &[u8]) -> Option<Rec> {
    let body = line.strip_prefix(b":")?;
    let bytes = hex_bytes(body)?;
    let (&len, rest) = bytes.split_first()?;
    let rest_len = rest.len();
    if rest_len != usize::from(len).checked_add(4)? {
        return None;
    }
    let address = u64::from(u16::from_be_bytes([*rest.first()?, *rest.get(1)?]));
    let kind = *rest.get(2)?;
    let data = rest.get(3..rest_len.checked_sub(1)?)?.to_vec();
    let checksum = *rest.last()?;
    let sum = bytes.iter().fold(0u8, |a, &b| a.wrapping_add(b));
    Some(Rec {
        kind,
        address,
        address_digits: 4,
        data,
        checksum,
        checksum_ok: sum == 0,
    })
}

/// `S<t>CC<address><data>SS`
fn parse_srec(line: &[u8]) -> Option<Rec> {
    let body = line.strip_prefix(b"S")?;
    let kind = body
        .first()?
        .checked_sub(b'0')
        .filter(|&k| k <= 9 && k != 4)?;
    let bytes = hex_bytes(body.get(1..)?)?;
    let (&len, rest) = bytes.split_first()?;
    if rest.len() != usize::from(len) {
        return None;
    }
    let width = match kind {
        0 | 1 | 5 | 9 => 2usize,
        2 | 6 | 8 => 3,
        _ => 4,
    };
    let address = rest
        .get(..width)?
        .iter()
        .fold(0u64, |a, &b| a << 8 | u64::from(b));
    let data = rest.get(width..rest.len().checked_sub(1)?)?.to_vec();
    let checksum = *rest.last()?;
    let sum = bytes
        .get(..bytes.len().checked_sub(1)?)?
        .iter()
        .fold(0u8, |a, &b| a.wrapping_add(b));
    Some(Rec {
        kind,
        address,
        address_digits: width.saturating_mul(2),
        data,
        checksum,
        checksum_ok: !sum == checksum,
    })
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Intel,
    Motorola,
}

pub async fn dissect_ihex(cx: Cx, input: Input) -> Result<()> {
    dissect(&cx, input, Flavor::Intel).await
}

pub async fn dissect_srec(cx: Cx, input: Input) -> Result<()> {
    dissect(&cx, input, Flavor::Motorola).await
}

async fn dissect(cx: &Cx, input: Input, flavor: Flavor) -> Result<()> {
    let file = input.span;
    let name = match flavor {
        Flavor::Intel => "Intel HEX",
        Flavor::Motorola => "Motorola S-record",
    };
    cx.annotate(name);
    let mut pos = 0u64;
    let mut records = 0u64;
    let mut data_bytes = 0u64;
    let mut base = 0u64; // Intel extended address
    let mut low = u64::MAX;
    let mut high = 0u64;
    let mut bad = 0u64;
    while pos < file.len {
        let window = cx.read_avail(file.sub(pos, MAX_LINE)).await?;
        let nl = window.iter().position(|&b| b == b'\n');
        let line_len = nl.map_or(window.len(), |n| n.saturating_add(1));
        let raw = window.get(..line_len).unwrap_or_default();
        let text = raw.strip_suffix(b"\n").unwrap_or(raw);
        let text = text.strip_suffix(b"\r").unwrap_or(text);
        let span = file.sub(pos, to_u64(text.len()));
        pos = pos.saturating_add(to_u64(line_len.max(1)));
        if text.iter().all(u8::is_ascii_whitespace) {
            cx.checkpoint().await;
            continue;
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        let parsed = match flavor {
            Flavor::Intel => parse_ihex(text),
            Flavor::Motorola => parse_srec(text),
        };
        let Some(r) = parsed else {
            if nl.is_none() && to_u64(window.len()) >= MAX_LINE {
                cx.diag(Diagnostic::malformed("line too long").at(span));
                break;
            }
            cx.push(
                Node::new(format!("Line {}", records.saturating_add(1)))
                    .span(span)
                    .value(Value::Text(String::from_utf8_lossy(text).into_owned()))
                    .diag(Diagnostic::malformed("not a valid record")),
            )
            .await;
            records = records.saturating_add(1);
            continue;
        };
        records = records.saturating_add(1);
        let (kind_name, absolute, is_data) = match flavor {
            Flavor::Intel => {
                let abs = base.saturating_add(r.address);
                match r.kind {
                    2 => {
                        base = u64::from(u16::from_be_bytes([
                            r.data.first().copied().unwrap_or(0),
                            r.data.get(1).copied().unwrap_or(0),
                        ])) << 4
                    }
                    4 => {
                        base = u64::from(u16::from_be_bytes([
                            r.data.first().copied().unwrap_or(0),
                            r.data.get(1).copied().unwrap_or(0),
                        ])) << 16
                    }
                    _ => {}
                }
                (
                    crate::value::lookup(IHEX_TYPE, r.kind.into()),
                    abs,
                    r.kind == 0,
                )
            }
            Flavor::Motorola => (
                crate::value::lookup(SREC_TYPE, r.kind.into()),
                r.address,
                (1..=3).contains(&r.kind),
            ),
        };
        let kind_name = kind_name.unwrap_or("unknown");
        let summary = if is_data {
            data_bytes = data_bytes.saturating_add(to_u64(r.data.len()));
            low = low.min(absolute);
            high = high.max(absolute.saturating_add(to_u64(r.data.len())));
            format!("{}, {kind_name}", human_size(to_u64(r.data.len())))
        } else if flavor == Flavor::Motorola && r.kind == 0 {
            format!("{:?}", String::from_utf8_lossy(&r.data))
        } else if flavor == Flavor::Intel && (r.kind == 2 || r.kind == 4) {
            format!("base {base:#x}")
        } else if flavor == Flavor::Intel && r.kind == 1 {
            String::new()
        } else {
            format!(
                "{:#x}",
                r.data.iter().fold(r.address, |a, &b| a << 8 | u64::from(b))
            )
        };
        let name = if is_data {
            format!("{absolute:#06x}")
        } else {
            crate::formats::util::fmt::capitalize(kind_name)
        };
        let mut node = Node::new(name)
            .span(span)
            .lazy(record_fields, (span, flavor, Arc::new(r.clone())));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !r.data.is_empty() {
            node = node.value(Value::Bytes(r.data.clone()));
        }
        if !r.checksum_ok {
            bad = bad.saturating_add(1);
            node = node.diag(Diagnostic::warning("checksum mismatch"));
        }
        cx.push(node).await;
        if flavor == Flavor::Intel && r.kind == 1 {
            break;
        }
    }
    if pos < file.len {
        cx.emit(Node::new("After end of file").span(file.tail(pos)));
    }
    let mut summary = format!(
        "{name}, {}, {}",
        count(records, "record", "records"),
        human_size(data_bytes)
    );
    if low <= high && data_bytes > 0 {
        summary = format!("{summary} at {low:#x}..{high:#x}");
    }
    if bad > 0 {
        summary = format!("{summary}, {} bad checksums", bad);
    }
    cx.annotate(summary);
    Ok(())
}

async fn record_fields(cx: Cx, (span, flavor, r): (Span, Flavor, Arc<Rec>)) -> Result<()> {
    let digits = |from: usize, n: usize| span.sub(to_u64(from), to_u64(n));
    let data_chars = r.data.len().saturating_mul(2);
    let mut nodes = Vec::new();
    match flavor {
        Flavor::Intel => {
            nodes.push(Node::new("Start code").span(digits(0, 1)));
            nodes.push(
                Node::new("Byte count")
                    .span(digits(1, 2))
                    .value(uint(to_u64(r.data.len()))),
            );
            nodes.push(
                Node::new("Address")
                    .span(digits(3, 4))
                    .value(hex(r.address)),
            );
            nodes.push(
                Node::new("Record type")
                    .span(digits(7, 2))
                    .value(Value::Enum {
                        raw: r.kind.into(),
                        bits: 8,
                        name: crate::value::lookup(IHEX_TYPE, r.kind.into()),
                    }),
            );
            nodes.push(
                Node::new("Data")
                    .span(digits(9, data_chars))
                    .value(Value::Bytes(r.data.to_vec())),
            );
            let at = 9usize.saturating_add(data_chars);
            nodes.push(checksum_node(digits(at, 2), &r));
        }
        Flavor::Motorola => {
            nodes.push(
                Node::new("Record type")
                    .span(digits(0, 2))
                    .value(Value::Enum {
                        raw: r.kind.into(),
                        bits: 8,
                        name: crate::value::lookup(SREC_TYPE, r.kind.into()),
                    }),
            );
            let count = r
                .data
                .len()
                .saturating_add(r.address_digits / 2)
                .saturating_add(1);
            nodes.push(
                Node::new("Byte count")
                    .span(digits(2, 2))
                    .value(uint(to_u64(count))),
            );
            nodes.push(
                Node::new("Address")
                    .span(digits(4, r.address_digits))
                    .value(hex(r.address)),
            );
            let at = 4usize.saturating_add(r.address_digits);
            nodes.push(
                Node::new("Data")
                    .span(digits(at, data_chars))
                    .value(Value::Bytes(r.data.to_vec())),
            );
            nodes.push(checksum_node(digits(at.saturating_add(data_chars), 2), &r));
        }
    }
    emit_nodes(cx, Arc::new(nodes)).await
}

fn checksum_node(span: Span, r: &Rec) -> Node {
    let node = Node::new("Checksum")
        .span(span)
        .value(hex(r.checksum.into()));
    if r.checksum_ok {
        node.summary("valid")
    } else {
        node.diag(Diagnostic::warning("checksum mismatch"))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn records() {
        let r = parse_ihex(b":10010000214601360121470136007EFE09D2190140");
        assert!(r.is_some_and(|r| r.checksum_ok && r.address == 0x100 && r.data.len() == 16));
        let s = parse_srec(b"S1137AF00A0A0D0000000000000000000000000061");
        assert!(s.is_some_and(|s| s.checksum_ok && s.address == 0x7af0));
    }
}
