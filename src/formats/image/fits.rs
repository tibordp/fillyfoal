//! FITS (Flexible Image Transport System).
//!
//! A sequence of header-data units (HDUs). Each header is a run of 80-byte
//! ASCII cards (`KEYWORD = value / comment`) ending with `END`, padded to a
//! 2880-byte block; the data that follows (size from BITPIX, NAXISn,
//! PCOUNT and GCOUNT) is padded the same way.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::{dims, region, text};

pub static FORMAT: Format = Format {
    name: "fits",
    title: "FITS image",
    extensions: &["fits", "fit", "fts"],
    mime: "image/fits",
    probe: Probe::Magic(&[(0, b"SIMPLE  =                    T")]),
    dissect: crate::expander!(dissect: Input),
};

const BLOCK: u64 = 2880;
const CARD: u64 = 80;
/// Header blocks examined per HDU before giving up on finding `END`.
const MAX_HEADER_BLOCKS: u64 = 1000;
/// HDUs listed before giving up.
const MAX_HDUS: usize = 10_000;

fn padded(len: u64) -> u64 {
    len.div_ceil(BLOCK).saturating_mul(BLOCK)
}

/// A parsed card: keyword and the value text (without comment).
fn card(raw: &[u8]) -> (String, Option<String>, Option<String>) {
    let keyword = crate::text::latin1(raw.get(..8).unwrap_or_default()).trim_end().to_owned();
    if raw.get(8..10) != Some(b"= ") {
        let rest = crate::text::latin1(raw.get(8..).unwrap_or_default()).trim().to_owned();
        return (keyword, None, (!rest.is_empty()).then_some(rest));
    }
    let field = crate::text::latin1(raw.get(10..).unwrap_or_default());
    let (value, comment) = if field.trim_start().starts_with('\'') {
        // A string: up to the closing quote ('' escapes a quote).
        let start = field.find('\'').unwrap_or(0).saturating_add(1);
        let mut end = start;
        let chars: Vec<char> = field.chars().collect();
        let mut out = String::new();
        while let Some(&c) = chars.get(end) {
            if c == '\'' {
                if chars.get(end.saturating_add(1)) == Some(&'\'') {
                    out.push('\'');
                    end = end.saturating_add(2);
                    continue;
                }
                break;
            }
            out.push(c);
            end = end.saturating_add(1);
        }
        let rest: String = chars.iter().skip(end.saturating_add(1)).collect();
        let comment = rest.split_once('/').map(|(_, c)| c.trim().to_owned());
        (out.trim_end().to_owned(), comment)
    } else {
        match field.split_once('/') {
            Some((v, c)) => (v.trim().to_owned(), Some(c.trim().to_owned())),
            None => (field.trim().to_owned(), None),
        }
    };
    (keyword, Some(value), comment.filter(|c| !c.is_empty()))
}

#[derive(Debug, Default)]
struct Hdu {
    header_len: u64,
    data_len: u64,
    bitpix: i64,
    axes: Vec<u64>,
    extension: Option<String>,
    name: Option<String>,
}

/// Reads the header starting at `offset`.
async fn read_hdu(cx: &Cx, file: Span, offset: u64) -> Result<Hdu> {
    let mut hdu = Hdu::default();
    let (mut pcount, mut gcount) = (0u64, 1u64);
    for block in 0..MAX_HEADER_BLOCKS {
        let at = offset.saturating_add(block.saturating_mul(BLOCK));
        let data = cx.read(file.sub_exact(at, BLOCK)?).await?;
        for raw in data.chunks(80) {
            let (keyword, value, _) = card(raw);
            let value = value.unwrap_or_default();
            let int = value.parse::<i64>().ok();
            match keyword.as_str() {
                "END" => {
                    hdu.header_len = block.saturating_add(1).saturating_mul(BLOCK);
                    let elements = if hdu.axes.is_empty() {
                        0
                    } else {
                        hdu.axes.iter().fold(1u64, |a, &n| a.saturating_mul(n))
                    };
                    let raw = elements
                        .saturating_add(pcount)
                        .saturating_mul(gcount)
                        .saturating_mul(hdu.bitpix.unsigned_abs() / 8);
                    hdu.data_len = padded(raw);
                    return Ok(hdu);
                }
                "BITPIX" => hdu.bitpix = int.unwrap_or(0),
                "PCOUNT" => pcount = int.and_then(|v| u64::try_from(v).ok()).unwrap_or(0),
                "GCOUNT" => gcount = int.and_then(|v| u64::try_from(v).ok()).unwrap_or(1),
                "XTENSION" => hdu.extension = Some(value.clone()),
                "EXTNAME" => hdu.name = Some(value.clone()),
                k if k.starts_with("NAXIS") && k.len() > 5 && hdu.axes.len() < 999 => {
                    hdu.axes.push(int.and_then(|v| u64::try_from(v).ok()).unwrap_or(0));
                }
                _ => {}
            }
        }
    }
    Err(Diagnostic::limit("header without END").at(file.sub(offset, BLOCK)))
}

fn describe(hdu: &Hdu) -> String {
    let kind = hdu.extension.clone().unwrap_or_else(|| "Primary".to_owned());
    let shape = match hdu.axes.as_slice() {
        [] => "no data".to_owned(),
        [w, h] => dims(w, h),
        axes => axes
            .iter()
            .map(ToString::to_string)
            .collect::<Vec<_>>()
            .join("×"),
    };
    let mut out = format!("{kind}, {shape}, BITPIX {}", hdu.bitpix);
    if let Some(name) = &hdu.name {
        out = format!("{out}, {name:?}");
    }
    out
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut offset = 0u64;
    let mut index = 0usize;
    let mut annotated = false;
    while offset < file.len && index < MAX_HDUS {
        let hdu = match read_hdu(&cx, file, offset).await {
            Ok(hdu) => hdu,
            Err(e) if index > 0 => {
                cx.push(region("Trailing data", file, offset, file.len.saturating_sub(offset)).diag(e))
                    .await;
                break;
            }
            Err(e) => return Err(e),
        };
        let summary = describe(&hdu);
        // Prefer the first HDU with data for the file's summary.
        if index == 0 || (!annotated && !hdu.axes.is_empty()) {
            cx.annotate(summary.clone());
            annotated = !hdu.axes.is_empty();
        }
        let len = hdu.header_len.saturating_add(hdu.data_len);
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
                .lazy(hdu_node, (span, hdu.header_len, hdu.data_len)),
        )
        .await;
        offset = offset.saturating_add(len.max(BLOCK));
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn hdu_node(cx: Cx, (span, header_len, data_len): (Span, u64, u64)) -> Result<()> {
    let header = span.sub(0, header_len);
    cx.emit(
        Node::new("Header")
            .span(header)
            .summary(format!("{} cards", header_len / CARD))
            .lazy(cards, header),
    );
    if data_len > 0 {
        cx.emit(region("Data", span, header_len, data_len));
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
        let mut node = Node::new(if keyword.is_empty() { "(blank)".to_owned() } else { keyword.clone() }).span(span);
        if let Some(v) = value {
            node = node.value(match v.parse::<i64>() {
                Ok(i) => Value::Int { value: i, bits: 64 },
                Err(_) => match v.as_str() {
                    "T" => Value::Bool(true),
                    "F" => Value::Bool(false),
                    _ => text(v),
                },
            });
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
