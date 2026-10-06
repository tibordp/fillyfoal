//! Vehicle bus logs and descriptions: Vector BLF (binary logging format)
//! and ASC (ASCII) traces, Linux `candump` logs, PEAK PCAN traces, CAN
//! databases (DBC), LIN description files (LDF) and ASAM A2L (ASAP2)
//! calibration descriptions.

use std::borrow::Cow;

use super::{hex, leaf, text, uint};
use crate::bytes::{u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Path, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::piece::Piece;
use crate::formats::text::probe;
use crate::formats::text::scan::Lines;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Vector BLF

declare_format!(pub BLF = "vector-blf", "Vector binary logging format (CAN log)", ["blf"], "application/x-vector-blf",
    Probe::Custom(|h| h.starts_with(b"LOGG") && u32_le(h.data, 4).is_some_and(|s| (72..=4096).contains(&s))), blf);

fn systemtime(raw: &[u8]) -> String {
    let w = |i: usize| u16_le(raw, i).unwrap_or(0);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        w(0),
        w(2),
        w(6),
        w(8),
        w(10),
        w(12),
        w(14)
    )
}

record! {
    pub struct BlfHeader {
        signature: ascii[4] "Signature",
        header_size: u32 "Header size",
        app: u8 "Application ID",
        app_major: u8 "Application major",
        app_minor: u8 "Application minor",
        app_build: u8 "Application build",
        bin_major: u8 "BL API major",
        bin_minor: u8 "BL API minor",
        bin_build: u8 "BL API build",
        bin_patch: u8 "BL API patch",
        file_size: u64 "File size",
        uncompressed: u64 "Uncompressed size",
        objects: u32 "Object count",
        objects_read: u32 "Objects read",
        start: bytes[16] "Start time" .with(|v, n| n.summary(systemtime(v))),
        stop: bytes[16] "Stop time" .with(|v, n| n.summary(systemtime(v))),
    }
}

const BLF_OBJECTS: EnumTable = &[
    (1, "CAN_MESSAGE"),
    (2, "CAN_ERROR"),
    (3, "CAN_OVERLOAD"),
    (4, "CAN_STATISTIC"),
    (5, "APP_TRIGGER"),
    (10, "LOG_CONTAINER"),
    (65, "APP_TEXT"),
    (73, "CAN_ERROR_EXT"),
    (86, "CAN_MESSAGE2"),
    (100, "CAN_FD_MESSAGE"),
    (101, "CAN_FD_MESSAGE_64"),
];

/// Decompressed containers larger than this are refused.
const MAX_CONTAINER: u64 = 64 << 20;

async fn blf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: BlfHeader = read_record(&cx, file.sub(0, BlfHeader::SIZE), LE).await?;
    cx.emit(BlfHeader::node(
        "File header",
        file.sub(0, h.header_size.into()),
        LE,
    ));
    cx.annotate(format!(
        "Vector BLF, {} objects, {}",
        h.objects,
        systemtime(&h.start)
    ));
    blf_objects(&cx, file.tail(h.header_size.into()), Path::new()).await
}

/// Walks the objects of a region (the file body or a container's data).
async fn blf_objects(cx: &Cx, region: Span, path: Path) -> Result<()> {
    let mut cur = Cursor::new(cx, region, LE);
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let base = cur.bytes(16).await?;
        if base.get(..4) != Some(b"LOBJ") {
            return Err(Diagnostic::malformed("expected LOBJ").at(region.sub(start, 4)));
        }
        let header_size = u64::from(u16_le(&base, 4).unwrap_or(0));
        let version = u16_le(&base, 6).unwrap_or(0);
        let size = u64::from(u32_le(&base, 8).unwrap_or(0));
        let kind = u32_le(&base, 12).unwrap_or(0);
        if size < header_size.max(16) {
            return Err(
                Diagnostic::malformed("object smaller than its header").at(region.sub(start, 16))
            );
        }
        let span = region.sub(start, size);
        if span.len < size {
            return Err(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        cur.seek(start.saturating_add(size).saturating_add(size % 4));
        let name = lookup(BLF_OBJECTS, kind.into())
            .map_or_else(|| format!("Object type {kind}"), str::to_owned);
        let body = span.tail(header_size);
        let mut node = Node::new(name).span(span);
        let head = cx
            .read(span.sub(16, header_size.saturating_sub(16)))
            .await?;
        let stamp = if matches!(version, 1 | 2) {
            u64_le(&head, 8)
        } else {
            None
        };
        let flags = u32_le(&head, 0).unwrap_or(0);
        let seconds = stamp.map(|t| {
            if flags & 2 != 0 {
                t as f64 / 1e9
            } else {
                t as f64 / 1e5
            }
        });
        if kind == 10 {
            let b = cx.read(body.sub(0, 16)).await?;
            let method = u16_le(&b, 0).unwrap_or(0);
            let size = u64::from(u32_le(&b, 8).unwrap_or(0));
            let data = body.tail(16);
            node = match path.enter(span.offset, 4) {
                Ok(child) => Node::new("LOG_CONTAINER")
                    .span(span)
                    .summary(format!(
                        "{} bytes, {}",
                        size,
                        if method == 2 { "zlib" } else { "stored" }
                    ))
                    .lazy(
                        crate::expander!(self::container: (Span, u16, u64, Path)),
                        (data, method, size, child),
                    ),
                Err(e) => node.diag(e),
            };
        } else if matches!(kind, 1 | 86) {
            let b = cx.read(body.sub(0, 16)).await?;
            node = node.summary(can_summary(&b, seconds, 8));
            node = node.lazy(can_message, (span, header_size));
        } else if matches!(kind, 100 | 101) {
            if let Some(t) = seconds {
                node = node.summary(format!("{t:.6} s"));
            }
        } else if kind == 65 {
            let b = cx.read(body.sub(0, 16)).await?;
            let len = u64::from(u32_le(&b, 8).unwrap_or(0));
            let t = cx.read(body.sub(16, len.min(4096))).await?;
            node = node.summary(crate::text::until_nul(&t));
        } else if let Some(t) = seconds {
            node = node.summary(format!("{t:.6} s"));
        }
        cx.push(node).await;
    }
    Ok(())
}

fn can_summary(b: &[u8], seconds: Option<f64>, max: usize) -> String {
    let channel = u16_le(b, 0).unwrap_or(0);
    let dlc = usize::from(b.get(3).copied().unwrap_or(0)).min(max);
    let id = u32_le(b, 4).unwrap_or(0);
    let data: Vec<String> = b
        .get(8..8usize.saturating_add(dlc))
        .unwrap_or_default()
        .iter()
        .map(|x| format!("{x:02X}"))
        .collect();
    let ext = if id & 0x8000_0000 != 0 { "x" } else { "" };
    let t = seconds.map(|s| format!("{s:.6} s, ")).unwrap_or_default();
    format!(
        "{t}ch {channel}, ID {:#x}{ext} [{dlc}] {}",
        id & 0x1fff_ffff,
        data.join(" ")
    )
}

async fn container(cx: Cx, (data, method, size, path): (Span, u16, u64, Path)) -> Result<()> {
    let inner = match method {
        0 => data,
        2 => {
            if size > MAX_CONTAINER {
                return Err(Diagnostic::limit("container too large").at(data));
            }
            let decoded = crate::codec::inflate_span(&cx, data, true, Some(size)).await?;
            if let Some(e) = decoded.error {
                cx.diag(e);
            }
            decoded.span
        }
        m => return Err(Diagnostic::unsupported(format!("compression method {m}")).at(data)),
    };
    blf_objects(&cx, inner, path).await
}

async fn can_message(cx: Cx, (span, header_size): (Span, u64)) -> Result<()> {
    let h = cx.read(span.sub(0, header_size)).await?;
    cx.emit(leaf("Header size", span.sub(4, 2), uint(header_size, 16)));
    cx.emit(leaf("Object size", span.sub(8, 4), uint(span.len, 32)));
    cx.emit(leaf(
        "Flags",
        span.sub(16, 4),
        hex(u32_le(&h, 16).unwrap_or(0).into(), 32),
    ));
    cx.emit(leaf(
        "Timestamp",
        span.sub(24, 8),
        uint(u64_le(&h, 24).unwrap_or(0), 64),
    ));
    let body = span.tail(header_size);
    let b = cx.read(body.sub(0, 16)).await?;
    cx.emit(leaf(
        "Channel",
        body.sub(0, 2),
        uint(u16_le(&b, 0).unwrap_or(0).into(), 16),
    ));
    cx.emit(
        leaf(
            "Flags",
            body.sub(2, 1),
            hex(b.get(2).copied().unwrap_or(0).into(), 8),
        )
        .summary(if b.get(2).is_some_and(|f| f & 1 != 0) {
            "Tx"
        } else {
            "Rx"
        }),
    );
    cx.emit(leaf(
        "DLC",
        body.sub(3, 1),
        uint(b.get(3).copied().unwrap_or(0).into(), 8),
    ));
    cx.emit(leaf(
        "ID",
        body.sub(4, 4),
        hex(u32_le(&b, 4).unwrap_or(0).into(), 32),
    ));
    cx.emit(leaf(
        "Data",
        body.sub(8, 8),
        Value::Bytes(b.get(8..).unwrap_or_default().to_vec()),
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Vector ASC

fn asc_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 3);
    lines.first().is_some_and(|l| l.starts_with(b"date "))
        && lines
            .get(1)
            .is_some_and(|l| l.starts_with(b"base hex") || l.starts_with(b"base dec"))
}

declare_format!(pub ASC = "vector-asc", "Vector ASCII CAN trace", ["asc"], "text/x-vector-asc",
    Probe::Custom(asc_probe), asc);

const ASC_LABELS: super::Labels = &[
    "Timestamp (s)",
    "Channel",
    "ID",
    "Direction",
    "Type",
    "DLC",
    "Data 0",
    "Data 1",
    "Data 2",
    "Data 3",
    "Data 4",
    "Data 5",
    "Data 6",
    "Data 7",
];

async fn asc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut first = true;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        if first {
            cx.annotate(format!("Vector ASC trace, {}", t.trim()));
            first = false;
        }
        let words: Vec<&str> = t.split_whitespace().collect();
        let is_frame =
            words.first().is_some_and(|w| w.parse::<f64>().is_ok()) && words.get(4) == Some(&"d");
        let node = if is_frame {
            let data = words
                .get(6..)
                .unwrap_or_default()
                .iter()
                .take_while(|w| w.len() == 2)
                .copied()
                .collect::<Vec<_>>()
                .join(" ");
            let summary = format!(
                "{} s, ch {}, ID {} {} [{}] {}",
                words.first().unwrap_or(&""),
                words.get(1).unwrap_or(&""),
                words.get(2).unwrap_or(&""),
                words.get(3).unwrap_or(&""),
                words.get(5).unwrap_or(&""),
                data
            );
            super::words_node("Frame", &line, ASC_LABELS).summary(summary)
        } else {
            leaf(format!("Line {}", line.number), line.span, text(t))
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// candump

/// The parts of a candump line: timestamp, interface, ID and data.
type CandumpFrame<'a> = (&'a [u8], &'a [u8], &'a [u8], &'a [u8]);

/// Parses `(seconds.micros) iface ID#DATA`.
fn candump_line(line: &[u8]) -> Option<CandumpFrame<'_>> {
    let line = probe::trim(line);
    let rest = line.strip_prefix(b"(")?;
    let close = rest.iter().position(|&b| b == b')')?;
    let stamp = rest.get(..close)?;
    if !stamp.iter().all(|b| b.is_ascii_digit() || *b == b'.') || !stamp.contains(&b'.') {
        return None;
    }
    let mut words = rest
        .get(close.saturating_add(1)..)?
        .split(|b| b.is_ascii_whitespace())
        .filter(|w| !w.is_empty());
    let iface = words.next()?;
    let frame = words.next()?;
    let hash = frame.iter().position(|&b| b == b'#')?;
    let id = frame.get(..hash)?;
    if id.is_empty() || !id.iter().all(u8::is_ascii_hexdigit) {
        return None;
    }
    Some((stamp, iface, id, frame.get(hash.saturating_add(1)..)?))
}

fn candump_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 4);
    let real: Vec<&Vec<u8>> = lines
        .iter()
        .filter(|l| !probe::trim(l).is_empty())
        .collect();
    !real.is_empty() && real.iter().take(3).all(|l| candump_line(l).is_some())
}

declare_format!(pub CANDUMP = "candump", "Linux candump log", ["log", "candump"], "text/x-candump",
    Probe::Custom(candump_probe), candump);

async fn candump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut first = true;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let Some((stamp, iface, id, data)) = candump_line(&line.bytes) else {
            cx.push(leaf(
                format!("Line {}", line.number),
                line.span,
                text(line.text()),
            ))
            .await;
            continue;
        };
        let iface = String::from_utf8_lossy(iface).into_owned();
        if first {
            cx.annotate(format!("candump log, interface {iface}"));
            first = false;
        }
        let (fd, payload) = match data.strip_prefix(b"#") {
            Some(rest) => (true, rest.get(1..).unwrap_or_default()),
            None => (false, data),
        };
        let remote = payload.first() == Some(&b'R');
        let bytes: Vec<String> = if remote {
            Vec::new()
        } else {
            payload
                .chunks(2)
                .map(|c| String::from_utf8_lossy(c).into_owned())
                .collect()
        };
        let kind = if fd {
            "CAN FD"
        } else if remote {
            "remote"
        } else {
            "CAN"
        };
        let summary = format!(
            "{} s, {iface}, ID {}, {kind} [{}] {}",
            String::from_utf8_lossy(stamp),
            String::from_utf8_lossy(id),
            bytes.len(),
            bytes.join(" ")
        );
        cx.push(
            Node::new("Frame")
                .span(line.span)
                .summary(summary)
                .lazy(candump_fields, line.span),
        )
        .await;
    }
    Ok(())
}

async fn candump_fields(cx: Cx, span: Span) -> Result<()> {
    let bytes = cx.read(span).await?;
    let piece = Piece::new(&bytes, span).trim();
    let Some((stamp, rest)) = piece.split_once(b')') else {
        return Ok(());
    };
    let stamp = stamp.from(1);
    let secs = stamp.text().parse::<f64>().unwrap_or(0.0);
    cx.emit(
        Node::new("Timestamp")
            .span(stamp.span())
            .value(Value::Timestamp {
                unix_seconds: secs as i64,
            })
            .summary(stamp.text()),
    );
    let mut words = rest.words();
    if let Some(iface) = words.next() {
        cx.emit(leaf("Interface", iface.span(), text(iface.text())));
    }
    if let Some(frame) = words.next()
        && let Some((id, data)) = frame.split_once(b'#')
    {
        let raw = u32::from_str_radix(&id.text(), 16).unwrap_or(0);
        cx.emit(leaf(
            "ID",
            id.span(),
            hex(raw.into(), if id.len() > 3 { 29 } else { 11 }),
        ));
        cx.emit(leaf("Data", data.span(), text(data.text())));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// PEAK PCAN trace

declare_format!(pub TRC = "pcan-trc", "PEAK PCAN trace", ["trc"], "text/x-pcan-trc",
    Probe::Custom(|h| h.starts_with(b";$FILEVERSION=")), trc);

const TRC1: super::Labels = &[
    "Message number",
    "Time offset (ms)",
    "Direction",
    "ID",
    "DLC",
    "Data 0",
    "Data 1",
    "Data 2",
    "Data 3",
    "Data 4",
    "Data 5",
    "Data 6",
    "Data 7",
];
const TRC2: super::Labels = &[
    "Message number",
    "Time offset (ms)",
    "Type",
    "ID",
    "Direction",
    "DLC",
    "Data 0",
    "Data 1",
    "Data 2",
    "Data 3",
    "Data 4",
    "Data 5",
    "Data 6",
    "Data 7",
];

async fn trc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut version = String::new();
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        if let Some(v) = t.strip_prefix(";$FILEVERSION=") {
            version = v.trim().to_owned();
            cx.annotate(format!("PCAN trace, file version {version}"));
        }
        if t.starts_with(';') {
            let node = super::key_value(&line, b'=')
                .filter(|_| t.starts_with(";$"))
                .unwrap_or_else(|| {
                    leaf("Comment", line.span, text(t.trim_start_matches(';').trim()))
                });
            cx.push(node).await;
            continue;
        }
        let labels = if version.starts_with('1') { TRC1 } else { TRC2 };
        let summary: String = t.split_whitespace().collect::<Vec<_>>().join(" ");
        cx.push(super::words_node("Message", &line, labels).summary(summary))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Statement-structured text (DBC, LDF): records are a top-level line plus
// its indented continuation lines, or a braced block.

/// Lists records: a line at column 0 starts one; indented lines and lines
/// inside braces belong to the current record.
pub(crate) async fn statements(
    cx: &Cx,
    file: Span,
    name: fn(&str) -> (Cow<'static, str>, Option<String>),
) -> Result<u64> {
    let mut lines = Lines::new(cx, file);
    let mut current: Option<(u64, String)> = None;
    let mut depth = 0i64;
    let mut n = 0u64;
    loop {
        let Some(line) = lines.peek().await? else {
            break;
        };
        let starts = depth <= 0
            && !line.is_blank()
            && line.bytes.first().is_some_and(|b| !b.is_ascii_whitespace())
            && !line.bytes.starts_with(b"}");
        if starts && let Some((from, first)) = current.take() {
            push_statement(
                cx,
                file.sub(from, line.start.saturating_sub(from)),
                &first,
                name,
            )
            .await;
            n = n.saturating_add(1);
        }
        let _ = lines.next().await?;
        if line.bytes.starts_with(b"//") && current.is_none() {
            continue;
        }
        for &b in &line.bytes {
            match b {
                b'{' => depth = depth.saturating_add(1),
                b'}' => depth = depth.saturating_sub(1),
                _ => {}
            }
        }
        if starts {
            current = Some((line.start, line.text()));
        }
    }
    if let Some((from, first)) = current {
        push_statement(cx, file.tail(from), &first, name).await;
        n = n.saturating_add(1);
    }
    Ok(n)
}

async fn push_statement(
    cx: &Cx,
    span: Span,
    first: &str,
    name: fn(&str) -> (Cow<'static, str>, Option<String>),
) {
    let (title, summary) = name(first.trim());
    let node = Node::new(title).span(span).lazy(statement_lines, span);
    cx.push(match summary {
        Some(s) => node.summary(s),
        None => node,
    })
    .await;
}

async fn statement_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        let trimmed = t.trim();
        let node = if let Some(sig) = trimmed.strip_prefix("SG_ ") {
            let (name, spec) = sig.split_once(':').unwrap_or((sig, ""));
            leaf(
                format!("Signal {}", name.trim()),
                line.span,
                text(spec.trim()),
            )
        } else {
            leaf(format!("Line {}", line.number), line.span, text(trimmed))
        };
        cx.push(node).await;
    }
    Ok(())
}

fn dbc_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let mut lines = probe::significant(&data, &[b"//"]);
    lines.next().is_some_and(|l| l.starts_with(b"VERSION \""))
        && (probe::contains(&data, b"\nBU_:")
            || probe::contains(&data, b"\nBO_ ")
            || probe::contains(&data, b"\nNS_ :"))
}

declare_format!(pub DBC = "can-dbc", "CAN database (DBC)", ["dbc"], "text/x-can-dbc",
    Probe::Custom(dbc_probe), dbc);

fn dbc_name(first: &str) -> (Cow<'static, str>, Option<String>) {
    let mut words = first.split_whitespace();
    let keyword = words.next().unwrap_or_default();
    match keyword {
        "BO_" => {
            let id = words.next().unwrap_or_default();
            let name = words.next().unwrap_or_default().trim_end_matches(':');
            let dlc = words.next().unwrap_or_default();
            let sender = words.next().unwrap_or_default();
            let raw = id.parse::<u64>().unwrap_or(0);
            let shown = if raw & 0x8000_0000 != 0 {
                format!("{:#x} (extended)", raw & 0x1fff_ffff)
            } else {
                format!("{raw:#x}")
            };
            (
                Cow::Owned(format!("Message {name}")),
                Some(format!("ID {shown}, {dlc} bytes, from {sender}")),
            )
        }
        "VERSION" => (
            Cow::Borrowed("Version"),
            Some(first.get(8..).unwrap_or_default().trim().to_owned()),
        ),
        "NS_" => (Cow::Borrowed("New symbols"), None),
        "BS_:" => (Cow::Borrowed("Bit timing"), None),
        "BU_:" => (
            Cow::Borrowed("Nodes"),
            Some(first.get(4..).unwrap_or_default().trim().to_owned()),
        ),
        "CM_" => (
            Cow::Borrowed("Comment"),
            Some(
                first
                    .get(4..)
                    .unwrap_or_default()
                    .chars()
                    .take(80)
                    .collect(),
            ),
        ),
        "BA_DEF_" | "BA_DEF_DEF_" | "BA_" => (
            Cow::Borrowed("Attribute"),
            Some(first.chars().take(80).collect()),
        ),
        "VAL_" => (
            Cow::Borrowed("Value table"),
            Some(first.chars().take(80).collect()),
        ),
        "VAL_TABLE_" => (
            Cow::Borrowed("Value table definition"),
            Some(first.chars().take(80).collect()),
        ),
        "SIG_VALTYPE_" => (
            Cow::Borrowed("Signal value type"),
            Some(first.chars().take(80).collect()),
        ),
        "BO_TX_BU_" => (
            Cow::Borrowed("Message transmitters"),
            Some(first.chars().take(80).collect()),
        ),
        _ => (
            Cow::Owned(keyword.trim_end_matches(':').to_owned()),
            Some(first.chars().take(80).collect()),
        ),
    }
}

async fn dbc(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("CAN database (DBC)");
    statements(&cx, input.span, dbc_name).await?;
    Ok(())
}

fn ldf_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    probe::significant(&data, &[b"//", b"/*"])
        .next()
        .is_some_and(|l| probe::trim(l).starts_with(b"LIN_description_file"))
}

declare_format!(pub LDF = "lin-ldf", "LIN description file", ["ldf"], "text/x-lin-ldf",
    Probe::Custom(ldf_probe), ldf);

fn ldf_name(first: &str) -> (Cow<'static, str>, Option<String>) {
    let head = first
        .split(['{', '=', ';'])
        .next()
        .unwrap_or_default()
        .trim()
        .to_owned();
    let value = first
        .split_once('=')
        .map(|(_, v)| v.trim().trim_end_matches(';').trim().to_owned());
    (Cow::Owned(head), value)
}

async fn ldf(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("LIN description file");
    statements(&cx, input.span, ldf_name).await?;
    Ok(())
}

// ---------------------------------------------------------------------------
// ASAM A2L

fn a2l_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let first = probe::significant(&data, &[b"//", b"/*", b"*"])
        .next()
        .map(probe::trim)
        .unwrap_or_default();
    (first.starts_with(b"ASAP2_VERSION") || first.starts_with(b"/begin PROJECT"))
        && probe::contains(&data, b"/begin PROJECT")
}

declare_format!(pub A2L = "a2l", "ASAM MCD-2 MC (A2L) description", ["a2l"], "text/x-a2l",
    Probe::Custom(a2l_probe), a2l);

/// Net `/begin` minus `/end` keywords on a line, and whether it begins one.
fn nesting(line: &[u8]) -> (i64, bool) {
    let t = String::from_utf8_lossy(line);
    let mut net = 0i64;
    let mut begins = false;
    for w in t.split_whitespace() {
        match w {
            "/begin" => {
                net = net.saturating_add(1);
                begins = true;
            }
            "/end" => net = net.saturating_sub(1),
            _ => {}
        }
    }
    (net, begins)
}

async fn a2l(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("ASAM A2L description");
    a2l_blocks(cx, (input.span, 0)).await
}

/// Lists the blocks of a region: each depth-0 `/begin` … `/end` becomes a
/// lazy node listing its own blocks in turn.
async fn a2l_blocks(cx: Cx, (region, depth_limit): (Span, u32)) -> Result<()> {
    let mut lines = Lines::new(&cx, region);
    let mut depth = 0i64;
    let mut start: Option<(u64, String)> = None;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let (net, begins) = nesting(&line.bytes);
        let t = line.text();
        if depth == 0 && begins && net > 0 && start.is_none() {
            start = Some((line.start, t.trim().to_owned()));
        } else if depth == 0 && start.is_none() && !t.trim().starts_with("/end") {
            let trimmed = t.trim();
            let name = trimmed.strip_prefix("/begin").map_or_else(
                || {
                    trimmed
                        .split_whitespace()
                        .next()
                        .unwrap_or("Line")
                        .to_owned()
                },
                |r| r.split_whitespace().next().unwrap_or_default().to_owned(),
            );
            cx.push(leaf(name, line.span, text(trimmed))).await;
        }
        depth = depth.saturating_add(net).max(0);
        if depth == 0
            && let Some((from, first)) = start.take()
        {
            let span = region.sub(from, line.next.saturating_sub(from));
            let mut words = first.split_whitespace().skip(1);
            let kind = words.next().unwrap_or_default().to_owned();
            let name = words.next().unwrap_or_default().to_owned();
            let body = Lines::new(&cx, span)
                .next()
                .await?
                .map_or(span, |l| span.tail(l.next));
            let mut node = Node::new(if name.is_empty() {
                kind.clone()
            } else {
                format!("{kind} {name}")
            })
            .span(span);
            node = if depth_limit < 32 {
                node.lazy(
                    crate::expander!(self::a2l_blocks: (Span, u32)),
                    (body, depth_limit.saturating_add(1)),
                )
            } else {
                node.diag(Diagnostic::limit("blocks nested too deeply"))
            };
            cx.push(node).await;
        }
    }
    if let Some((from, first)) = start {
        cx.push(
            Node::new(first)
                .span(region.tail(from))
                .diag(Diagnostic::malformed("unterminated /begin")),
        )
        .await;
    }
    Ok(())
}
