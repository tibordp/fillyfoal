//! vCard and iCalendar: content lines (`NAME;PARAM=value:value`, folded
//! across physical lines) grouped into nested `BEGIN:`/`END:` components.
//!
//! Components are lazy nodes summarised by their key property (a contact's
//! name, an event's summary and start). Properties carry typed values
//! (date-times as timestamps), their parameters and structured parts as
//! children, and inline binary data (photos, attachments) is decoded and
//! dissected.

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::{Transform, decoded_node, preview};
use super::encoding::{decode_8bit, prepare};
use super::scan::{LINE_CAP, Lines};
use super::{parse_datetime, plural, probe, text_node};

pub static VCARD: Format = Format {
    name: "vcard",
    title: "vCard contacts",
    extensions: &["vcf", "vcard"],
    mime: "text/vcard",
    probe: Probe::Custom(|h| first_begin(h).is_some_and(|c| c.eq_ignore_ascii_case(b"VCARD"))),
    dissect: crate::expander!(dissect_vcard: Input),
};

pub static ICALENDAR: Format = Format {
    name: "icalendar",
    title: "iCalendar",
    extensions: &["ics", "ical", "ifb", "vcs"],
    mime: "text/calendar",
    probe: Probe::Custom(|h| first_begin(h).is_some_and(|c| c.eq_ignore_ascii_case(b"VCALENDAR"))),
    dissect: crate::expander!(dissect_ical: Input),
};

/// The component named by the first line, if it is `BEGIN:X`.
fn first_begin(h: &Head<'_>) -> Option<Vec<u8>> {
    let head = probe::head(h);
    let line = probe::significant(&head, &[]).next()?;
    begin_name(line).map(String::into_bytes)
}

/// One unfolded content line.
struct Logical {
    /// Unfolded bytes (capped).
    bytes: Vec<u8>,
    /// The physical lines it spans.
    span: Span,
    start: u64,
    next: u64,
}

/// Reads a content line, unfolding continuation lines (leading space or
/// tab) and quoted-printable soft breaks (vCard 2.1).
async fn logical(lines: &mut Lines<'_>) -> Result<Option<Logical>> {
    let Some(first) = lines.next().await? else {
        return Ok(None);
    };
    let mut bytes = first.bytes.clone();
    let mut end = first.span.end();
    let mut next = first.next;
    let qp = probe::find_nocase(&first.bytes, b"QUOTED-PRINTABLE").is_some();
    loop {
        let soft = qp && bytes.last() == Some(&b'=');
        let Some(more) = lines.peek().await? else {
            break;
        };
        let folded = matches!(more.bytes.first(), Some(b' ' | b'\t'));
        if !(folded || soft) || more.bytes.is_empty() {
            break;
        }
        lines.next().await?;
        if soft {
            bytes.pop();
            bytes.extend_from_slice(&more.bytes);
        } else {
            bytes.extend_from_slice(more.bytes.get(1..).unwrap_or_default());
        }
        if bytes.len() > LINE_CAP {
            bytes.truncate(LINE_CAP);
        }
        end = more.span.end();
        next = more.next;
    }
    let span = Span::new(
        first.span.source,
        first.span.offset,
        end.saturating_sub(first.span.offset),
    );
    Ok(Some(Logical {
        bytes,
        span,
        start: first.start,
        next,
    }))
}

/// A parsed content line.
struct Property {
    name: String,
    params: Vec<(String, String)>,
    value: String,
}

/// The position of the `:` that starts the value (outside quoted params).
fn value_colon(line: &[u8]) -> Option<usize> {
    let mut quoted = false;
    for (i, &b) in line.iter().enumerate() {
        match b {
            b'"' => quoted = !quoted,
            b':' if !quoted => return Some(i),
            _ => {}
        }
    }
    None
}

fn parse_property(line: &[u8]) -> Option<Property> {
    let colon = value_colon(line)?;
    let head = decode_8bit(line.get(..colon)?);
    let value = decode_8bit(line.get(colon.saturating_add(1)..)?);
    let mut parts = head.split(';');
    let name = parts.next()?.trim().to_owned();
    if name.is_empty() {
        return None;
    }
    let params = parts
        .map(|p| match p.split_once('=') {
            Some((k, v)) => (
                k.trim().to_ascii_uppercase(),
                v.trim_matches('"').to_owned(),
            ),
            // vCard 2.1 bare parameters (`TEL;HOME:`) are types.
            None => ("TYPE".to_owned(), p.trim().to_owned()),
        })
        .collect();
    Some(Property {
        name,
        params,
        value,
    })
}

impl Property {
    fn param(&self, name: &str) -> Option<&str> {
        self.params
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, v)| v.as_str())
    }

    /// The name without a group prefix (`item1.EMAIL` → `EMAIL`).
    fn base(&self) -> String {
        self.name
            .rsplit('.')
            .next()
            .unwrap_or_default()
            .to_ascii_uppercase()
    }
}

/// Undoes text escapes (`\n`, `\,`, `\;`, `\\`).
fn unescape(text: &str) -> String {
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c == '\\' {
            match chars.next() {
                Some('n' | 'N') => out.push('\n'),
                Some(other) => out.push(other),
                None => out.push('\\'),
            }
        } else {
            out.push(c);
        }
    }
    out
}

/// Properties holding date-times.
const DATES: &[&str] = &[
    "DTSTART",
    "DTEND",
    "DTSTAMP",
    "CREATED",
    "LAST-MODIFIED",
    "DUE",
    "COMPLETED",
    "RECURRENCE-ID",
    "BDAY",
    "ANNIVERSARY",
    "REV",
    "EXDATE",
    "RDATE",
];

/// Names of the parts of structured values.
fn structure(base: &str) -> &'static [&'static str] {
    match base {
        "N" => &[
            "Family name",
            "Given name",
            "Additional names",
            "Prefix",
            "Suffix",
        ],
        "ADR" => &[
            "PO box",
            "Extended address",
            "Street",
            "Locality",
            "Region",
            "Postal code",
            "Country",
        ],
        "ORG" => &["Organisation", "Unit", "Subunit"],
        "GEO" => &["Latitude", "Longitude"],
        _ => &[],
    }
}

/// Splits a structured value at unescaped `;`.
fn split_structured(value: &str) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = String::new();
    let mut escaped = false;
    for c in value.chars() {
        if escaped {
            cur.push('\\');
            cur.push(c);
            escaped = false;
        } else if c == '\\' {
            escaped = true;
        } else if c == ';' {
            out.push(unescape(&std::mem::take(&mut cur)));
        } else {
            cur.push(c);
        }
    }
    out.push(unescape(&cur));
    out
}

#[derive(Clone, Debug)]
struct Component {
    input: Input,
    span: Span,
    depth: u32,
}

const MAX_DEPTH: u32 = 32;

/// The node for a property line (`span` covers its physical lines).
fn property_node(p: &Property, line: &[u8], span: Span, input: Input) -> Node {
    let base = p.base();
    let colon = value_colon(line).unwrap_or(line.len());
    // The value's span, when the line was not folded before the value.
    let value_span = span.sub(crate::bytes::to_u64(colon.saturating_add(1)), u64::MAX);
    let encoding = p.param("ENCODING").map(str::to_ascii_uppercase);
    let binary = matches!(encoding.as_deref(), Some("B" | "BASE64"));
    if binary {
        let what = p.param("TYPE").or(p.param("FMTTYPE")).unwrap_or("data");
        return decoded_node(p.name.clone(), input, value_span, Transform::Base64)
            .summary(format!("{what}, base64"));
    }
    if let Some(rest) = p.value.strip_prefix("data:")
        && let Some((meta, _)) = rest.split_once(',')
        && meta.ends_with(";base64")
    {
        let skip = crate::bytes::to_u64(meta.len().saturating_add(6));
        return decoded_node(
            p.name.clone(),
            input,
            value_span.sub(skip, u64::MAX),
            Transform::Base64,
        )
        .summary(format!("{}, data URI", meta.trim_end_matches(";base64")));
    }
    // Percent-encoded `data:` URIs (vCard 4 allows any URI).
    if !p.value.contains('\\')
        && line.ends_with(p.value.as_bytes())
        && let Some(node) =
            super::decode::data_url_node(p.name.clone(), input, value_span, &p.value)
    {
        return node;
    }
    let text = if encoding.as_deref() == Some("QUOTED-PRINTABLE") {
        decode_8bit(&super::decode::quoted_printable(p.value.as_bytes()).bytes)
    } else {
        unescape(&p.value)
    };
    let mut node = if DATES.contains(&base.as_str()) {
        let utc = p.value.ends_with('Z') || !p.value.contains('T');
        match parse_datetime(&p.value).filter(|_| utc) {
            Some(t) => Node::new(p.name.clone())
                .span(value_span)
                .value(Value::Timestamp { unix_seconds: t }),
            None => {
                let mut n = text_node(p.name.clone(), value_span, &text);
                if let Some(tz) = p.param("TZID") {
                    n = n.summary(format!("local time in {tz}"));
                }
                n
            }
        }
    } else {
        text_node(p.name.clone(), value_span, &text)
    };
    if !structure(&base).is_empty() || !p.params.is_empty() {
        node = node.lazy(property_parts, (span, base));
    }
    node
}

/// Parameters and structured parts of a property.
async fn property_parts(cx: Cx, (span, base): (Span, String)) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let Some(line) = logical(&mut lines).await? else {
        return Ok(());
    };
    let Some(p) = parse_property(&line.bytes) else {
        return Ok(());
    };
    for (k, v) in &p.params {
        cx.emit(Node::new(format!("{k} (parameter)")).value(Value::Text(v.clone())));
    }
    let names = structure(&base);
    if !names.is_empty() {
        for (i, part) in split_structured(&p.value).into_iter().enumerate() {
            if part.is_empty() {
                continue;
            }
            let name = names.get(i).map_or_else(
                || format!("Part {}", i.saturating_add(1)),
                |n| (*n).to_owned(),
            );
            cx.emit(Node::new(name).value(Value::Text(part)));
        }
    }
    Ok(())
}

/// What a component's summary is made of, gathered while scanning it.
#[derive(Default)]
struct Summary {
    title: Option<String>,
    when: Option<String>,
    children: u64,
}

impl Summary {
    fn note(&mut self, p: &Property) {
        let text = || preview(&unescape(&p.value), 60);
        match p.base().as_str() {
            "FN" | "SUMMARY" | "TZID" | "X-WR-CALNAME" => self.title = Some(text()),
            "N" if self.title.is_none() => {
                let parts = split_structured(&p.value);
                let name: Vec<&str> = [parts.get(1), parts.first()]
                    .into_iter()
                    .flatten()
                    .map(String::as_str)
                    .filter(|s| !s.is_empty())
                    .collect();
                self.title = Some(name.join(" "));
            }
            "ACTION" if self.title.is_none() => self.title = Some(text()),
            "DTSTART" => {
                self.when = Some(match parse_datetime(&p.value) {
                    Some(t) => crate::render::value(&Value::Timestamp { unix_seconds: t }),
                    None => p.value.clone(),
                });
            }
            _ => {}
        }
    }

    fn text(&self) -> Option<String> {
        let mut parts: Vec<String> = Vec::new();
        parts.extend(self.title.clone());
        parts.extend(self.when.clone());
        if self.children > 0 {
            parts.push(plural(self.children, "component", "components"));
        }
        (!parts.is_empty()).then(|| parts.join(", "))
    }
}

fn begin_name(line: &[u8]) -> Option<String> {
    let t = probe::trim(line);
    let name = t.get(6..).filter(|_| {
        t.get(..6)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"BEGIN:"))
    })?;
    Some(decode_8bit(name).to_ascii_uppercase())
}

fn is_end(line: &[u8], name: &str) -> bool {
    let t = probe::trim(line);
    t.get(..4).is_some_and(|p| p.eq_ignore_ascii_case(b"END:"))
        && t.get(4..)
            .is_some_and(|n| n.eq_ignore_ascii_case(name.as_bytes()))
}

/// Pushes the properties and sub-components of a component body (or of the
/// whole file at depth 0). `skip_begin` skips the component's own BEGIN.
async fn walk(cx: &Cx, c: &Component, skip_begin: bool) -> Result<u64> {
    if c.depth > MAX_DEPTH {
        return Err(Diagnostic::limit("components nested too deeply").at(c.span));
    }
    let mut lines = Lines::new(cx, c.span);
    if skip_begin {
        logical(&mut lines).await?;
    }
    let mut count = 0u64;
    while let Some(line) = logical(&mut lines).await? {
        if probe::trim(&line.bytes).is_empty() {
            continue;
        }
        if let Some(name) = begin_name(&line.bytes) {
            // Find the matching END, noting what summarises the component.
            let mut summary = Summary::default();
            let mut depth = 0u32;
            let mut closed = false;
            let mut end = lines.pos();
            while let Some(inner) = logical(&mut lines).await? {
                end = inner.next;
                if begin_name(&inner.bytes).is_some() {
                    if depth == 0 {
                        summary.children = summary.children.saturating_add(1);
                    }
                    depth = depth.saturating_add(1);
                    continue;
                }
                if depth == 0 && is_end(&inner.bytes, &name) {
                    closed = true;
                    break;
                }
                if probe::trim(&inner.bytes)
                    .get(..4)
                    .is_some_and(|p| p.eq_ignore_ascii_case(b"END:"))
                {
                    depth = depth.saturating_sub(1);
                    continue;
                }
                if depth == 0
                    && let Some(p) = parse_property(&inner.bytes)
                {
                    summary.note(&p);
                }
            }
            let span = c.span.sub(line.start, end.saturating_sub(line.start));
            let mut node = Node::new(name).span(span).lazy(
                crate::expander!(self::component: Component),
                Component {
                    input: c.input,
                    span,
                    depth: c.depth.saturating_add(1),
                },
            );
            if let Some(s) = summary.text() {
                node = node.summary(s);
            }
            if !closed {
                node = node.diag(Diagnostic::new(DiagKind::Truncated, "END line missing"));
            }
            count = count.saturating_add(1);
            lines.progress();
            cx.push(node).await;
            continue;
        }
        if probe::trim(&line.bytes)
            .get(..4)
            .is_some_and(|p| p.eq_ignore_ascii_case(b"END:"))
        {
            // Our own END line.
            continue;
        }
        match parse_property(&line.bytes) {
            Some(p) => {
                cx.push(property_node(&p, &line.bytes, line.span, c.input))
                    .await
            }
            None => {
                cx.push(
                    text_node("Line", line.span, &decode_8bit(&line.bytes))
                        .diag(Diagnostic::malformed("not a content line")),
                )
                .await;
            }
        }
    }
    Ok(count)
}

async fn component(cx: Cx, c: Component) -> Result<()> {
    walk(&cx, &c, true).await.map(|_| ())
}

async fn dissect(cx: Cx, input: Input, what: &str, unit: (&str, &str)) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    cx.annotate(what.to_owned());
    let c = Component {
        input: prepared.input(input),
        span: prepared.span,
        depth: 0,
    };
    let n = walk(&cx, &c, false).await?;
    cx.annotate(format!("{what}, {}", plural(n, unit.0, unit.1)));
    Ok(())
}

pub async fn dissect_vcard(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, "vCard", ("contact", "contacts")).await
}

pub async fn dissect_ical(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, "iCalendar", ("calendar", "calendars")).await
}
