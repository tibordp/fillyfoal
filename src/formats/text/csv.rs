//! Delimiter-separated values: CSV (with `,`, `;` or `|`, sniffed) and TSV.
//!
//! Records are a paged collection at the top level; each expands into its
//! fields, named after the header row when there is one. Quoted fields may
//! contain delimiters, doubled quotes and line breaks.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::{decode_8bit, prepare};
use super::scan::Scanner;
use super::{count, plural, probe, text_node};

pub static CSV: Format = Format {
    name: "csv",
    title: "Comma-separated values",
    extensions: &["csv", "psv", "ssv"],
    mime: "text/csv",
    probe: Probe::Custom(|h| sniff_head(h, b",;|").is_some()),
    dissect: crate::expander!(dissect_csv: Input),
};

pub static TSV: Format = Format {
    name: "tsv",
    title: "Tab-separated values",
    extensions: &["tsv", "tab"],
    mime: "text/tab-separated-values",
    probe: Probe::Custom(|h| sniff_head(h, b"\t").is_some()),
    dissect: crate::expander!(dissect_tsv: Input),
};

/// Splits `data` into records (quote-aware); the last one may be partial.
fn sample_records(data: &[u8], delim: u8, max: usize) -> Vec<usize> {
    let mut counts = Vec::new();
    let mut fields = 1usize;
    let mut quoted = false;
    let mut at_field_start = true;
    let mut i = 0usize;
    while let Some(&b) = data.get(i) {
        i = i.saturating_add(1);
        if quoted {
            if b == b'"' {
                if data.get(i) == Some(&b'"') {
                    i = i.saturating_add(1);
                } else {
                    quoted = false;
                }
            }
            continue;
        }
        match b {
            b'"' if at_field_start => {
                quoted = true;
                at_field_start = false;
            }
            b'\n' | b'\r' => {
                if b == b'\r' && data.get(i) == Some(&b'\n') {
                    i = i.saturating_add(1);
                }
                counts.push(fields);
                if counts.len() >= max {
                    return counts;
                }
                fields = 1;
                at_field_start = true;
            }
            _ if b == delim => {
                fields = fields.saturating_add(1);
                at_field_start = true;
            }
            _ => at_field_start = false,
        }
    }
    counts
}

/// The best delimiter among `candidates` for `data`, with its field count.
fn sniff(data: &[u8], candidates: &[u8]) -> Option<(u8, usize)> {
    let mut best: Option<(u8, usize)> = None;
    for &delim in candidates {
        let counts = sample_records(data, delim, 50);
        // The most common field count must cover nearly all records.
        let Some(&first) = counts.first() else {
            continue;
        };
        let agree = counts.iter().filter(|&&c| c == first).count();
        let consistent = agree.saturating_mul(5) >= counts.len().saturating_mul(4);
        let enough = counts.len() >= 3 || (counts.len() == 2 && first >= 3 && agree == 2);
        if consistent && enough && first >= 2 && best.is_none_or(|(_, n)| first > n) {
            best = Some((delim, first));
        }
    }
    best
}

fn sniff_head(h: &Head<'_>, candidates: &[u8]) -> Option<(u8, usize)> {
    let head = probe::head(h);
    // Records of prose or code rarely have a constant number of separators;
    // still, require text that is not obviously something else.
    let first = probe::trim_start(&head);
    if first.starts_with(b"#!") || first.starts_with(b"<") || first.starts_with(b"{") {
        return None;
    }
    let found = sniff(&head, candidates)?;
    probe::is_text(h).then_some(found)
}

/// Field boundaries of one record.
struct Record {
    /// Relative start and end of the record's content.
    start: u64,
    end: u64,
    /// Where the next record starts.
    next: u64,
    /// Field ranges (relative), at most `MAX_FIELDS`.
    fields: Vec<(u64, u64)>,
    /// Total number of fields (may exceed `fields.len()`).
    count: u64,
    /// A quoted field ran to the end of the input.
    unterminated: bool,
}

/// The most fields kept per record; more are counted, not shown.
const MAX_FIELDS: usize = 10_000;

/// Reads the record starting at `pos`.
async fn record(scan: &mut Scanner<'_>, pos: u64, delim: u8) -> Result<Option<Record>> {
    if scan.byte(pos).await?.is_none() {
        return Ok(None);
    }
    let mut rec = Record {
        start: pos,
        end: pos,
        next: pos,
        fields: Vec::new(),
        count: 0,
        unterminated: false,
    };
    let mut field_start = pos;
    let mut at = pos;
    let mut quoted = false;
    let push = |rec: &mut Record, start: u64, end: u64| {
        if rec.fields.len() < MAX_FIELDS {
            rec.fields.push((start, end));
        }
        rec.count = rec.count.saturating_add(1);
    };
    loop {
        let Some(b) = scan.byte(at).await? else {
            rec.unterminated = quoted;
            push(&mut rec, field_start, at);
            rec.end = at;
            rec.next = at;
            return Ok(Some(rec));
        };
        let next = at.saturating_add(1);
        if quoted {
            if b == b'"' {
                if scan.byte(next).await? == Some(b'"') {
                    at = next.saturating_add(1);
                    continue;
                }
                quoted = false;
            }
            at = next;
            continue;
        }
        match b {
            b'"' if at == field_start => quoted = true,
            b'\n' | b'\r' => {
                push(&mut rec, field_start, at);
                rec.end = at;
                rec.next = if b == b'\r' && scan.byte(next).await? == Some(b'\n') {
                    next.saturating_add(1)
                } else {
                    next
                };
                return Ok(Some(rec));
            }
            _ if b == delim => {
                push(&mut rec, field_start, at);
                field_start = next;
            }
            _ => {}
        }
        at = next;
    }
}

/// A field's text: quotes removed and doubled quotes undone.
fn field_text(raw: &[u8]) -> (String, bool) {
    let trimmed = probe::trim(raw);
    if let Some(inner) = trimmed.strip_prefix(b"\"") {
        let inner = inner.strip_suffix(b"\"").unwrap_or(inner);
        return (decode_8bit(inner).replace("\"\"", "\""), true);
    }
    (decode_8bit(raw), false)
}

/// A typed value for an unquoted field that is a plain number (no leading
/// zeros, which usually mean an identifier such as a postal code).
fn field_value(text: &str) -> Option<Value> {
    let t = text.trim();
    let digits = t.trim_start_matches(['-', '+']);
    if digits.len() > 1 && digits.starts_with('0') && !digits.starts_with("0.") {
        return None;
    }
    super::number(t)
}

#[derive(Clone)]
struct Columns {
    names: Arc<Vec<String>>,
}

impl Columns {
    fn name(&self, i: usize) -> String {
        match self.names.get(i) {
            Some(n) if !n.is_empty() => n.clone(),
            _ => format!("Column {}", i.saturating_add(1)),
        }
    }
}

/// Whether the first record looks like a header: no numbers, all distinct
/// and non-empty, while some later record has a number.
fn looks_like_header(first: &[String], second: Option<&[String]>) -> bool {
    let no_numbers = first.iter().all(|f| super::number(f).is_none());
    let filled = first.iter().all(|f| !f.trim().is_empty());
    let mut sorted: Vec<&String> = first.iter().collect();
    sorted.sort();
    sorted.dedup();
    let distinct = sorted.len() == first.len();
    let later_numbers = second.is_some_and(|s| s.iter().any(|f| super::number(f).is_some()));
    no_numbers && filled && distinct && (later_numbers || second.is_none() || first.len() >= 2)
}

async fn texts(scan: &mut Scanner<'_>, rec: &Record) -> Result<Vec<String>> {
    let mut out = Vec::with_capacity(rec.fields.len().min(256));
    for &(a, b) in rec.fields.iter().take(256) {
        let raw = scan.bytes(a, b, 4096).await?;
        out.push(field_text(&raw).0);
    }
    Ok(out)
}

pub async fn dissect_csv(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, b",;|").await
}

pub async fn dissect_tsv(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, b"\t").await
}

async fn dissect(cx: Cx, input: Input, candidates: &[u8]) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let head = cx.read_avail(span.sub(0, crate::formats::HEAD_LEN)).await?;
    let fallback = candidates.first().copied().unwrap_or(b',');
    let (delim, _) = sniff(&head, candidates).unwrap_or((fallback, 1));
    let mut scan = Scanner::new(&cx, span);
    let Some(first) = record(&mut scan, 0, delim).await? else {
        cx.annotate("empty");
        return Ok(());
    };
    let first_texts = texts(&mut scan, &first).await?;
    let second = record(&mut scan, first.next, delim).await?;
    let second_texts = match &second {
        Some(r) => Some(texts(&mut scan, r).await?),
        None => None,
    };
    let header = looks_like_header(&first_texts, second_texts.as_deref());
    let columns = Columns {
        names: Arc::new(if header { first_texts.clone() } else { Vec::new() }),
    };

    // Annotation: dialect, columns, estimated records.
    let kind = if delim == b'\t' { "TSV" } else { "CSV" };
    let delim_name = match delim {
        b'\t' => "tab",
        b',' => "comma",
        b';' => "semicolon",
        b'|' => "pipe",
        _ => "other",
    };
    let per_record = first.next.saturating_sub(first.start).max(1);
    let estimate = span.len.checked_div(per_record).unwrap_or(0);
    let names = if header {
        format!(" ({})", preview(&first_texts.join(", "), 60))
    } else {
        String::new()
    };
    cx.annotate(format!(
        "{kind}{}, {}{names}, ~{} records",
        prepared.note(),
        plural(first.count, "column", "columns"),
        count(estimate)
    ));
    cx.emit(Node::new("Delimiter").value(Value::Text(delim_name.to_owned())));
    if header {
        let span = scan.span(first.start, first.end);
        cx.emit(
            Node::new("Header")
                .span(span)
                .summary(preview(&first_texts.join(", "), 100))
                .lazy(fields, (span, delim, Columns { names: Arc::default() }, true)),
        );
    }

    let mut pos = if header { first.next } else { 0 };
    let mut index = 0u64;
    while let Some(rec) = record(&mut scan, pos, delim).await? {
        cx.checkpoint().await;
        pos = rec.next.max(pos.saturating_add(1));
        if rec.start == rec.end {
            continue; // blank line
        }
        index = index.saturating_add(1);
        let span = scan.span(rec.start, rec.end);
        let raw = scan.bytes(rec.start, rec.end, 200).await?;
        let mut node = Node::new(format!("Record {index}"))
            .span(span)
            .summary(preview(&decode_8bit(&raw), 100))
            .lazy(fields, (span, delim, columns.clone(), false));
        if header && rec.count != first.count {
            node = node.diag(Diagnostic::warning(format!(
                "{} fields, header has {}",
                rec.count, first.count
            )));
        }
        if rec.unterminated {
            node = node.diag(Diagnostic::malformed("quoted field not closed"));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The fields of one record.
async fn fields(cx: Cx, (span, delim, columns, header): (Span, u8, Columns, bool)) -> Result<()> {
    let mut scan = Scanner::new(&cx, span);
    let Some(rec) = record(&mut scan, 0, delim).await? else {
        return Ok(());
    };
    for (i, &(a, b)) in rec.fields.iter().enumerate() {
        let raw = scan.bytes(a, b, super::VALUE_CAP.saturating_mul(4)).await?;
        let (text, quoted) = field_text(&raw);
        let name = if header {
            format!("Column {}", i.saturating_add(1))
        } else {
            columns.name(i)
        };
        let fspan = scan.span(a, b);
        let typed = (!quoted && !header).then(|| field_value(&text)).flatten();
        let node = match typed {
            Some(v) => Node::new(name).span(fspan).value(v),
            None => text_node(name, fspan, &text),
        };
        cx.push(node).await;
    }
    if to_u64(rec.fields.len()) < rec.count {
        cx.diag(Diagnostic::limit(format!(
            "only the first {} of {} fields are shown",
            rec.fields.len(),
            rec.count
        )));
    }
    Ok(())
}
