//! FITS (Flexible Image Transport System, FITS Standard 4.0).
//!
//! A sequence of header-data units (HDUs). Each header is a run of 80-byte
//! ASCII cards (`KEYWORD = value / comment`) ending with `END`, padded to a
//! 2880-byte block; the data that follows (size from BITPIX, NAXISn,
//! PCOUNT and GCOUNT) is padded the same way. Extensions are images
//! (`IMAGE`), ASCII tables (`TABLE`) and binary tables (`BINTABLE`, whose
//! variable-length arrays live in a heap after the main table).

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::human_size;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::{dims, region, text};

pub static FORMAT: Format = Format {
    name: "fits",
    title: "Flexible Image Transport System",
    extensions: &["fits", "fit", "fts"],
    mime: "image/fits",
    probe: Probe::Magic(&[(0, b"SIMPLE  = ")]),
    dissect: crate::expander!(dissect: Input),
};

const BLOCK: u64 = 2880;
const CARD: u64 = 80;
/// Header blocks examined per HDU before giving up on finding `END`.
const MAX_HEADER_BLOCKS: u64 = 1000;
/// HDUs listed before giving up.
const MAX_HDUS: usize = 10_000;
/// Axes and table columns allowed by the standard.
const MAX_INDEX: usize = 999;

fn padded(len: u64) -> u64 {
    len.div_ceil(BLOCK).saturating_mul(BLOCK)
}

/// A card's value: its text (strings unquoted) and whether it was a string.
type CardValue = Option<(String, bool)>;

/// A parsed card: keyword, value (without comment) and comment.
fn card(raw: &[u8]) -> (String, CardValue, Option<String>) {
    let keyword = crate::text::latin1(raw.get(..8).unwrap_or_default())
        .trim_end()
        .to_owned();
    if raw.get(8..10) != Some(b"= ") {
        let rest = crate::text::latin1(raw.get(8..).unwrap_or_default())
            .trim()
            .to_owned();
        return (keyword, None, (!rest.is_empty()).then_some(rest));
    }
    let field: Vec<char> = crate::text::latin1(raw.get(10..).unwrap_or_default())
        .chars()
        .collect();
    let start = field.iter().position(|c| *c != ' ');
    let (value, comment) = match start {
        Some(start) if field.get(start) == Some(&'\'') => {
            // A string: up to the closing quote ('' escapes a quote);
            // trailing spaces are not significant.
            let mut out = String::new();
            let mut at = start.saturating_add(1);
            while let Some(&c) = field.get(at) {
                if c == '\'' {
                    if field.get(at.saturating_add(1)) == Some(&'\'') {
                        out.push('\'');
                        at = at.saturating_add(2);
                        continue;
                    }
                    break;
                }
                out.push(c);
                at = at.saturating_add(1);
            }
            let rest: String = field.iter().skip(at.saturating_add(1)).collect();
            let comment = rest.split_once('/').map(|(_, c)| c.trim().to_owned());
            ((out.trim_end().to_owned(), true), comment)
        }
        _ => {
            let field: String = field.into_iter().collect();
            match field.split_once('/') {
                Some((v, c)) => ((v.trim().to_owned(), false), Some(c.trim().to_owned())),
                None => ((field.trim().to_owned(), false), None),
            }
        }
    };
    (keyword, Some(value), comment.filter(|c| !c.is_empty()))
}

/// A card value as a typed value: logical, integer, real, else text.
fn typed(value: &str) -> Value {
    match value {
        "T" => return Value::Bool(true),
        "F" => return Value::Bool(false),
        _ => {}
    }
    if let Ok(i) = value.parse::<i64>() {
        return Value::Int { value: i, bits: 64 };
    }
    // Reals may use a Fortran D exponent.
    let real = value.replace(['D', 'd'], "E");
    if real.chars().any(|c| c.is_ascii_digit())
        && let Ok(f) = real.parse::<f64>()
    {
        return Value::Float(f);
    }
    text(value)
}

/// One table column's description.
#[derive(Clone, Debug, Default)]
struct Column {
    name: String,
    form: String,
    unit: String,
}

#[derive(Clone, Debug, Default)]
struct Hdu {
    header_len: u64,
    /// The data without its padding.
    data_len: u64,
    bitpix: i64,
    axes: Vec<u64>,
    pcount: u64,
    gcount: u64,
    groups: bool,
    bzero: Option<f64>,
    extension: Option<String>,
    name: Option<String>,
    object: Option<String>,
    columns: Vec<Column>,
}

/// The number `n` in `KEYn` (1-based), if `keyword` is one.
fn indexed(keyword: &str, prefix: &str) -> Option<usize> {
    let n: usize = keyword.strip_prefix(prefix)?.parse().ok()?;
    (1..=MAX_INDEX).contains(&n).then(|| n.saturating_sub(1))
}

/// Reads the header starting at `offset`.
async fn read_hdu(cx: &Cx, file: Span, offset: u64) -> Result<Hdu> {
    let mut hdu = Hdu {
        gcount: 1,
        ..Hdu::default()
    };
    for block in 0..MAX_HEADER_BLOCKS {
        let at = offset.saturating_add(block.saturating_mul(BLOCK));
        let data = cx.read(file.sub_exact(at, BLOCK)?).await?;
        for raw in data.chunks(80) {
            let (keyword, value, _) = card(raw);
            let value = value.map(|(v, _)| v).unwrap_or_default();
            let int = value.parse::<i64>().ok();
            let count = int.and_then(|v| u64::try_from(v).ok());
            match keyword.as_str() {
                "END" => {
                    hdu.header_len = block.saturating_add(1).saturating_mul(BLOCK);
                    // Random groups: NAXIS1 is 0 and does not count.
                    let axes = if hdu.groups && hdu.axes.first() == Some(&0) {
                        hdu.axes.get(1..).unwrap_or_default()
                    } else {
                        hdu.axes.as_slice()
                    };
                    let elements = if axes.is_empty() {
                        0
                    } else {
                        axes.iter().fold(1u64, |a, &n| a.saturating_mul(n))
                    };
                    hdu.data_len = elements
                        .saturating_add(hdu.pcount)
                        .saturating_mul(hdu.gcount)
                        .saturating_mul(hdu.bitpix.unsigned_abs() / 8);
                    return Ok(hdu);
                }
                "BITPIX" => hdu.bitpix = int.unwrap_or(0),
                "NAXIS" => {
                    let n = crate::bytes::to_usize(count.unwrap_or(0)).min(MAX_INDEX);
                    hdu.axes = vec![0; n];
                }
                "PCOUNT" => hdu.pcount = count.unwrap_or(0),
                "GCOUNT" => hdu.gcount = count.unwrap_or(1),
                "GROUPS" => hdu.groups = value == "T",
                "BZERO" => hdu.bzero = value.replace(['D', 'd'], "E").parse().ok(),
                "XTENSION" => hdu.extension = Some(value),
                "EXTNAME" => hdu.name = Some(value),
                "OBJECT" => hdu.object = Some(value),
                "TFIELDS" => {
                    let n = crate::bytes::to_usize(count.unwrap_or(0)).min(MAX_INDEX);
                    hdu.columns = vec![Column::default(); n];
                }
                k => {
                    if let Some(i) = indexed(k, "NAXIS") {
                        if let Some(slot) = hdu.axes.get_mut(i) {
                            *slot = count.unwrap_or(0);
                        }
                    } else if let Some(i) = indexed(k, "TTYPE") {
                        if let Some(c) = hdu.columns.get_mut(i) {
                            c.name = value;
                        }
                    } else if let Some(i) = indexed(k, "TFORM") {
                        if let Some(c) = hdu.columns.get_mut(i) {
                            c.form = value;
                        }
                    } else if let Some(i) = indexed(k, "TUNIT")
                        && let Some(c) = hdu.columns.get_mut(i)
                    {
                        c.unit = value;
                    }
                }
            }
        }
    }
    Err(Diagnostic::limit("header without END").at(file.sub(offset, BLOCK)))
}

/// What BITPIX (with BZERO's unsigned convention) means.
fn pixel_type(hdu: &Hdu) -> String {
    let bzero = hdu.bzero.unwrap_or(0.0);
    match hdu.bitpix {
        8 if bzero == -128.0 => "8-bit signed".to_owned(),
        8 => "8-bit unsigned".to_owned(),
        16 if bzero == 32768.0 => "16-bit unsigned".to_owned(),
        32 if bzero == 2_147_483_648.0 => "32-bit unsigned".to_owned(),
        64 if bzero == 9_223_372_036_854_775_808.0 => "64-bit unsigned".to_owned(),
        16 | 32 | 64 => format!("{}-bit integer", hdu.bitpix),
        -32 | -64 => format!("{}-bit float", hdu.bitpix.unsigned_abs()),
        other => format!("BITPIX {other}"),
    }
}

fn is_table(hdu: &Hdu) -> bool {
    matches!(hdu.extension.as_deref(), Some("BINTABLE" | "TABLE"))
}

fn describe(hdu: &Hdu) -> String {
    let kind = hdu.extension.as_deref().unwrap_or("Primary");
    let mut out = if is_table(hdu) {
        let rows = hdu.axes.get(1).copied().unwrap_or(0);
        format!(
            "{kind}, {rows} rows × {} columns, {}",
            hdu.columns.len(),
            human_size(hdu.data_len)
        )
    } else {
        let shape = match hdu.axes.as_slice() {
            [] => "no data".to_owned(),
            [w, h] => dims(w, h),
            axes => axes
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .join("×"),
        };
        if hdu.axes.is_empty() {
            format!("{kind}, {shape}")
        } else {
            format!("{kind}, {shape}, {}", pixel_type(hdu))
        }
    };
    if hdu.groups {
        out = format!("{out}, {} random groups", hdu.gcount);
    }
    if let Some(name) = &hdu.name {
        out = format!("{out}, {name:?}");
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut offset = 0u64;
    let mut index = 0usize;
    let mut first: Option<String> = None;
    let mut object = None;
    while offset < file.len && index < MAX_HDUS {
        cx.progress_in(file, file.offset.saturating_add(offset));
        let hdu = match read_hdu(&cx, file, offset).await {
            Ok(hdu) => hdu,
            Err(e) if index > 0 => {
                cx.push(
                    region(
                        "Trailing data",
                        file,
                        offset,
                        file.len.saturating_sub(offset),
                    )
                    .diag(e),
                )
                .await;
                break;
            }
            Err(e) => return Err(e),
        };
        let summary = describe(&hdu);
        // The file's summary: the first HDU with data.
        if first.is_none() && hdu.data_len > 0 {
            first = Some(summary.clone());
        }
        if object.is_none() {
            object.clone_from(&hdu.object);
        }
        let len = hdu.header_len.saturating_add(padded(hdu.data_len));
        let span = file.sub(offset, len);
        let name = if index == 0 {
            "Primary HDU".to_owned()
        } else {
            format!("Extension {index}")
        };
        cx.push(
            Node::new(name)
                .span(span)
                .summary(summary)
                .lazy(hdu_node, (span, hdu)),
        )
        .await;
        offset = offset.saturating_add(len.max(BLOCK));
        index = index.saturating_add(1);
    }
    let mut summary = first.unwrap_or_else(|| "no data".to_owned());
    if index > 1 {
        summary = format!("{summary}; {index} HDUs");
    }
    if let Some(object) = object {
        summary = format!("{summary}; object {object:?}");
    }
    cx.annotate(summary);
    Ok(())
}

async fn hdu_node(cx: Cx, (span, hdu): (Span, Hdu)) -> Result<()> {
    let header = span.sub(0, hdu.header_len);
    cx.emit(
        Node::new("Header")
            .span(header)
            .summary(format!("{} card slots", hdu.header_len / CARD))
            .lazy(cards, header),
    );
    if !hdu.columns.is_empty() {
        cx.emit(
            Node::new("Columns")
                .span(header)
                .summary(format!("{} columns", hdu.columns.len()))
                .lazy(columns, hdu.columns.clone()),
        );
    }
    if hdu.data_len > 0 {
        if hdu.extension.as_deref() == Some("BINTABLE") && hdu.pcount > 0 {
            // The main table, then the heap of variable-length arrays.
            let table = hdu.data_len.saturating_sub(hdu.pcount);
            let rows = hdu.axes.get(1).copied().unwrap_or(0);
            cx.emit(
                region("Table", span, hdu.header_len, table)
                    .summary(format!("{rows} rows, {}", human_size(table))),
            );
            cx.emit(
                region(
                    "Heap",
                    span,
                    hdu.header_len.saturating_add(table),
                    hdu.pcount,
                )
                .summary(human_size(hdu.pcount))
                .desc("Variable-length array data"),
            );
        } else {
            cx.emit(
                region("Data", span, hdu.header_len, hdu.data_len)
                    .summary(human_size(hdu.data_len)),
            );
        }
        let pad = padded(hdu.data_len).saturating_sub(hdu.data_len);
        if pad > 0 {
            let at = hdu.header_len.saturating_add(hdu.data_len);
            cx.emit(region("Padding", span, at, pad));
        }
    }
    Ok(())
}

async fn columns(cx: Cx, columns: Vec<Column>) -> Result<()> {
    for (i, c) in columns.iter().enumerate() {
        let mut summary = c.form.clone();
        if !c.unit.is_empty() {
            summary = format!("{summary}, {}", c.unit);
        }
        let name = if c.name.is_empty() {
            format!("Column {}", i.saturating_add(1))
        } else {
            c.name.clone()
        };
        cx.push(Node::new(name).summary(summary)).await;
    }
    Ok(())
}

async fn cards(cx: Cx, header: Span) -> Result<()> {
    let n = header.len / CARD;
    for i in 0..n {
        let span = header.sub(i.saturating_mul(CARD), CARD);
        let raw = cx.read(span).await?;
        let (keyword, value, comment) = card(&raw);
        if keyword.is_empty() && value.is_none() && comment.is_none() {
            continue;
        }
        let mut node = Node::new(if keyword.is_empty() {
            "(blank)".to_owned()
        } else {
            keyword.clone()
        })
        .span(span);
        match value {
            Some((v, true)) => node = node.value(text(v)),
            Some((v, false)) => node = node.value(typed(&v)),
            None => {}
        }
        if let Some(c) = comment {
            node = node.summary(c);
        }
        cx.push(node).await;
        if keyword == "END" {
            break;
        }
    }
    Ok(())
}
