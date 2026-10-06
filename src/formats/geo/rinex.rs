//! GNSS geodesy text formats: RINEX observation, navigation, meteorological
//! and clock files, Hatanaka-compressed RINEX, ANTEX antenna calibrations,
//! IONEX ionosphere maps, SP3 precise orbits and SINEX solutions.
//!
//! The RINEX family labels each header line in columns 61–80; the header
//! ends at `END OF HEADER`. Bodies are grouped into records (an epoch, a
//! satellite's navigation message, an antenna, a map), listed in pages, and
//! expand to their lines.

use std::borrow::Cow;

use super::{leaf, text};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::text::piece::Piece;
use crate::formats::text::scan::Lines;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

/// The label of a RINEX-style header line (columns 61–80).
fn label(line: &[u8]) -> &[u8] {
    crate::formats::text::probe::trim(line.get(60..).unwrap_or_default())
}

/// The first line's label and the character at column 21 (the file type).
fn first(h: &Head<'_>) -> Option<(Vec<u8>, u8)> {
    let lines = super::head_lines(h, 1);
    let l = lines.first()?;
    Some((label(l).to_vec(), l.get(20).copied().unwrap_or(b' ')))
}

fn rinex_type(h: &Head<'_>, types: &[u8]) -> bool {
    first(h).is_some_and(|(l, t)| l == b"RINEX VERSION / TYPE" && types.contains(&t))
}

declare_format!(pub OBS = "rinex-obs", "RINEX observation file", ["obs", "rnx", "o", "24o", "23o"], "text/x-rinex",
    Probe::Custom(|h| rinex_type(h, b"O")), rinex);
declare_format!(pub NAV = "rinex-nav", "RINEX navigation file", ["nav", "rnx", "n", "g", "24n", "24g"], "text/x-rinex",
    Probe::Custom(|h| rinex_type(h, b"NGHLJ")), rinex);
declare_format!(pub MET = "rinex-met", "RINEX meteorological file", ["met", "m", "24m"], "text/x-rinex",
    Probe::Custom(|h| rinex_type(h, b"M")), rinex);
declare_format!(pub CLOCK = "rinex-clock", "RINEX clock file", ["clk", "clk_30s"], "text/x-rinex",
    Probe::Custom(|h| rinex_type(h, b"C")), rinex);
declare_format!(pub CRINEX = "crinex", "Hatanaka-compressed RINEX", ["crx", "24d", "23d", "d"], "text/x-crinex",
    Probe::Custom(|h| first(h).is_some_and(|(l, _)| l == b"CRINEX VERS   / TYPE")), crinex);
declare_format!(pub ANTEX = "antex", "ANTEX antenna calibration", ["atx"], "text/x-antex",
    Probe::Custom(|h| first(h).is_some_and(|(l, _)| l == b"ANTEX VERSION / SYST")), antex);
declare_format!(pub IONEX = "ionex", "IONEX ionosphere maps", ["inx", "i", "24i"], "text/x-ionex",
    Probe::Custom(|h| first(h).is_some_and(|(l, _)| l == b"IONEX VERSION / TYPE")), ionex);

fn sp3_probe(h: &Head<'_>) -> bool {
    let lines = super::head_lines(h, 2);
    let (Some(a), Some(b)) = (lines.first(), lines.get(1)) else { return false };
    matches!(a.get(..3), Some([b'#', b'a'..=b'd', b'P' | b'V'])) && b.starts_with(b"## ")
}

declare_format!(pub SP3 = "sp3", "SP3 precise orbit file", ["sp3", "eph"], "text/x-sp3",
    Probe::Custom(sp3_probe), sp3);
declare_format!(pub SINEX = "sinex", "SINEX solution file", ["snx", "ssc"], "text/x-sinex",
    Probe::Custom(|h| h.starts_with(b"%=SNX ")), sinex);

/// How a body is split into records.
#[derive(Clone, Copy)]
enum Style {
    /// RINEX 3 observations: epochs start with `>`.
    EpochMarker,
    /// RINEX 2 observations: ` YY MM DD HH MM SS.SSSSSSS  F NN…`.
    Epoch2,
    /// Navigation: a record starts with a satellite (`G01`, ` 1`, `12`).
    Nav,
    /// One record per line (meteorological and clock data).
    Line,
    /// Labelled `START OF …` / `END OF …` blocks (ANTEX, IONEX).
    Blocks,
    /// SP3: epochs start with `*`.
    Sp3,
    /// SINEX: `+BLOCK` … `-BLOCK`.
    Sinex,
}

fn starts_record(style: Style, line: &[u8]) -> bool {
    let at = |i: usize| line.get(i).copied().unwrap_or(b' ');
    match style {
        Style::EpochMarker => at(0) == b'>',
        Style::Epoch2 => at(0) == b' ' && at(1).is_ascii_digit() && at(2).is_ascii_digit() && at(3) == b' ' && at(28).is_ascii_digit(),
        Style::Nav => {
            (at(0).is_ascii_uppercase() && at(1).is_ascii_digit() && at(2).is_ascii_digit())
                || (at(1).is_ascii_digit() && (at(0) == b' ' || at(0).is_ascii_digit()) && at(2) == b' ' && at(3) != b' ')
        }
        Style::Line => true,
        Style::Blocks => label(line) == b"START OF ANTENNA" || (label(line).starts_with(b"START OF") && label(line).ends_with(b"MAP")),
        Style::Sp3 => at(0) == b'*' || line.starts_with(b"EOF"),
        Style::Sinex => at(0) == b'+' || line.starts_with(b"%ENDSNX"),
    }
}

fn record_name(style: Style, line: &str, index: u64) -> String {
    match style {
        Style::Sp3 if line.starts_with("EOF") => "End of file".to_owned(),
        Style::EpochMarker | Style::Epoch2 | Style::Sp3 => format!("Epoch {index}"),
        Style::Nav => {
            let sat = line.get(..3).unwrap_or_default().trim();
            format!("Satellite {sat}")
        }
        Style::Blocks => {
            let kind = line.get(60..).unwrap_or_default().trim().trim_start_matches("START OF ").to_lowercase();
            format!("{kind} {index}")
        }
        Style::Sinex if line.starts_with('%') => "End of file".to_owned(),
        Style::Sinex => line.trim_start_matches('+').trim().to_owned(),
        Style::Line => format!("Record {index}"),
    }
}

/// Walks the header (labelled lines up to `END OF HEADER`) and returns its
/// end and the labelled values the annotation needs.
async fn header(cx: &Cx, file: Span, skip: u64) -> Result<(u64, Vec<(String, String)>)> {
    let mut lines = Lines::new(cx, file);
    let mut out = Vec::new();
    let mut end = 0u64;
    while let Some(line) = lines.next().await? {
        if line.number <= skip {
            end = line.next;
            continue;
        }
        let l = String::from_utf8_lossy(label(&line.bytes)).into_owned();
        let value = String::from_utf8_lossy(line.bytes.get(..60.min(line.bytes.len())).unwrap_or_default()).into_owned();
        end = line.next;
        if l == "END OF HEADER" || out.len() >= 4096 {
            break;
        }
        out.push((l, value));
    }
    Ok((end, out))
}

/// Shows labelled header lines as `label: value` leaves.
async fn header_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let piece = line.piece();
        let l = label(&line.bytes);
        if l.is_empty() || line.bytes.len() <= 60 {
            cx.emit(leaf(format!("Line {}", line.number), line.span, text(line.text())));
            continue;
        }
        let value = piece.to(60).trim();
        let name = String::from_utf8_lossy(l).into_owned();
        cx.emit(Node::new(name).span(line.span).value(text(value.text())));
    }
    Ok(())
}

/// Shows a record's lines.
async fn record_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        cx.push(leaf(format!("Line {}", line.number), line.span, text(line.text()))).await;
    }
    Ok(())
}

/// Lists the records of `body`.
async fn records(cx: &Cx, body: Span, style: Style) -> Result<u64> {
    let mut lines = Lines::new(cx, body);
    let mut index = 0u64;
    let mut pending: Option<(u64, String)> = None;
    loop {
        let Some(line) = lines.peek().await? else { break };
        let start = starts_record(style, &line.bytes) || pending.is_none();
        if start && let Some((from, first)) = pending.take() {
            let span = body.sub(from, line.start.saturating_sub(from));
            push_record(cx, style, span, &first, index).await;
            index = index.saturating_add(1);
        }
        let _ = lines.next().await?;
        let comment = matches!(style, Style::Sinex) && line.bytes.first() == Some(&b'*');
        if (line.is_blank() || comment) && pending.is_none() {
            continue;
        }
        if start || pending.is_none() {
            pending = Some((line.start, line.text()));
        }
        // SINEX blocks end at their `-BLOCK` line.
        if matches!(style, Style::Sinex) && line.bytes.first() == Some(&b'-') && let Some((from, first)) = pending.take() {
            let span = body.sub(from, line.next.saturating_sub(from));
            push_record(cx, style, span, &first, index).await;
            index = index.saturating_add(1);
        }
    }
    if let Some((from, first)) = pending {
        push_record(cx, style, body.tail(from), &first, index).await;
        index = index.saturating_add(1);
    }
    Ok(index)
}

async fn push_record(cx: &Cx, style: Style, span: Span, first: &str, index: u64) {
    let name = record_name(style, first, index);
    let summary: String = match style {
        Style::Blocks => first.get(..60).unwrap_or(first).trim().to_owned(),
        Style::Sinex | Style::Nav => String::new(),
        _ => first.trim().chars().take(80).collect(),
    };
    let node = Node::new(Cow::Owned(name)).span(span).lazy(record_lines, span);
    cx.push(if summary.is_empty() { node } else { node.summary(summary) }).await;
}

fn find<'a>(values: &'a [(String, String)], l: &str) -> Option<&'a str> {
    values.iter().find(|v| v.0 == l).map(|v| v.1.as_str())
}

async fn rinex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, values) = header(&cx, file, 0).await?;
    let hspan = file.sub(0, end);
    cx.emit(Node::new("Header").span(hspan).summary(format!("{} lines", values.len())).lazy(header_lines, hspan));
    let vt = find(&values, "RINEX VERSION / TYPE").unwrap_or_default();
    let version = vt.get(..9).unwrap_or_default().trim().to_owned();
    let kind = vt.as_bytes().get(20).copied().unwrap_or(b' ');
    let system = vt.get(40..).unwrap_or_default().trim().to_owned();
    let major = version.split('.').next().and_then(|v| v.parse::<u32>().ok()).unwrap_or(3);
    let style = match kind {
        b'O' if major >= 3 => Style::EpochMarker,
        b'O' => Style::Epoch2,
        b'M' | b'C' => Style::Line,
        _ => Style::Nav,
    };
    let what = match kind {
        b'O' => "observations",
        b'M' => "meteorological data",
        b'C' => "clock data",
        _ => "navigation data",
    };
    let marker = find(&values, "MARKER NAME").map(|m| format!(", marker {}", m.trim())).unwrap_or_default();
    let sys = if system.is_empty() { String::new() } else { format!(" ({system})") };
    cx.annotate(format!("RINEX {version} {what}{sys}{marker}"));
    records(&cx, file.tail(end), style).await?;
    Ok(())
}

async fn crinex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, values) = header(&cx, file, 0).await?;
    let hspan = file.sub(0, end);
    cx.emit(Node::new("Header").span(hspan).summary(format!("{} lines", values.len())).lazy(header_lines, hspan));
    let version = find(&values, "CRINEX VERS   / TYPE").unwrap_or_default().get(..9).unwrap_or_default().trim().to_owned();
    let rinex = find(&values, "RINEX VERSION / TYPE").unwrap_or_default().get(..9).unwrap_or_default().trim().to_owned();
    cx.emit(Node::new("Compressed observations").span(file.tail(end)).lazy(record_lines, file.tail(end)));
    cx.annotate(format!("Compact RINEX {version} (RINEX {rinex} observations)"));
    Ok(())
}

async fn antex(cx: Cx, input: Input) -> Result<()> {
    labelled_blocks(cx, input, "ANTEX VERSION / SYST", "ANTEX", "antennas").await
}

async fn ionex(cx: Cx, input: Input) -> Result<()> {
    labelled_blocks(cx, input, "IONEX VERSION / TYPE", "IONEX", "maps").await
}

async fn labelled_blocks(cx: Cx, input: Input, version_label: &str, name: &str, what: &str) -> Result<()> {
    let file = input.span;
    let (end, values) = header(&cx, file, 0).await?;
    let hspan = file.sub(0, end);
    cx.emit(Node::new("Header").span(hspan).summary(format!("{} lines", values.len())).lazy(header_lines, hspan));
    let version = find(&values, version_label).unwrap_or_default().get(..9).unwrap_or_default().trim().to_owned();
    cx.annotate(format!("{name} {version}"));
    let n = records(&cx, file.tail(end), Style::Blocks).await?;
    cx.annotate(format!("{name} {version}, {n} {what}"));
    Ok(())
}

async fn sp3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut end = 0u64;
    let mut first = String::new();
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        if line.bytes.first() == Some(&b'*') {
            break;
        }
        if line.number == 1 {
            first = line.text();
        }
        end = line.next;
        count = count.saturating_add(1);
        if count >= 4096 {
            break;
        }
    }
    let hspan = file.sub(0, end);
    cx.emit(Node::new("Header").span(hspan).summary(format!("{count} lines")).lazy(sp3_header, hspan));
    let epochs = first.get(32..39).unwrap_or_default().trim().to_owned();
    let agency = first.get(56..60).unwrap_or_default().trim().to_owned();
    let kind = if first.as_bytes().get(2) == Some(&b'V') { "positions and velocities" } else { "positions" };
    cx.annotate(format!("SP3-{} orbits ({kind}), {epochs} epochs, {agency}", first.get(1..2).unwrap_or_default()));
    records(&cx, file.tail(end), Style::Sp3).await?;
    Ok(())
}

const SP3_FIRST: super::Columns = &[
    (0, 2, "Version"), (2, 1, "Position/velocity flag"), (3, 4, "Year"), (8, 2, "Month"), (11, 2, "Day"),
    (14, 2, "Hour"), (17, 2, "Minute"), (20, 11, "Second"), (32, 7, "Epochs"), (40, 5, "Data used"),
    (46, 5, "Coordinate system"), (52, 3, "Orbit type"), (56, 4, "Agency"),
];

async fn sp3_header(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let node = if line.number == 1 {
            super::columns_node("Line 1", line.span, SP3_FIRST).value(text(line.text()))
        } else {
            let kind = match line.bytes.get(..2) {
                Some(b"##") => "Time",
                Some(b"+ ") => "Satellites",
                Some(b"++") => "Accuracy",
                Some(b"%c") => "Characters",
                Some(b"%f") => "Floats",
                Some(b"%i") => "Integers",
                Some(b"/*") => "Comment",
                _ => "Line",
            };
            leaf(kind, line.span, text(line.text()))
        };
        cx.emit(node);
    }
    Ok(())
}

async fn sinex(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let Some(line) = lines.next().await? else { return Ok(()) };
    let piece = Piece::new(&line.bytes, line.span);
    let words: Vec<Piece<'_>> = piece.words().collect();
    let labels = ["Marker", "Version", "Agency", "Creation time", "Data agency", "Start", "End", "Technique", "Parameters", "Constraint", "Solution types"];
    let mut nodes = Vec::new();
    for (i, w) in words.iter().enumerate() {
        let name = labels.get(i).copied().unwrap_or("Field");
        nodes.push(super::field_node(name, *w));
    }
    cx.emit(Node::new("Header line").span(line.span).lazy(super::emit_nodes, nodes));
    let version = words.get(1).map(Piece::text).unwrap_or_default();
    let agency = words.get(2).map(Piece::text).unwrap_or_default();
    cx.annotate(format!("SINEX {version} from {agency}"));
    records(&cx, file.tail(line.next), Style::Sinex).await?;
    Ok(())
}
