//! LDIF (LDAP Data Interchange Format): entries and change records, each a
//! distinguished name with attributes (folded lines unfolded, base64 values
//! decoded).

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

use super::decode::{Transform, decoded_node, preview};
use super::encoding::prepare;
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "ldif",
    title: "LDAP Data Interchange Format",
    extensions: &["ldif"],
    mime: "text/x-ldif",
    probe: Probe::Custom(probe_ldif),
    dissect: crate::expander!(dissect: Input),
};

fn probe_ldif(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut lines = probe::significant(&head, &[b"#"]);
    let Some(first) = lines.next() else {
        return false;
    };
    let first = probe::trim(first);
    let ok = if first.starts_with(b"version:") {
        lines.next().is_some_and(|l| l.starts_with(b"dn:"))
    } else {
        first.starts_with(b"dn:")
    };
    ok && probe::is_text(h)
}

/// One attribute: name, value (decoded unless base64-binary), whether it
/// was base64, and the span of its lines.
struct Attr {
    name: String,
    value: String,
    base64: bool,
    span: Span,
    /// The span of the encoded value (for decoding).
    value_span: Span,
}

/// Unfolded attribute lines of a record (up to a blank line).
async fn record(lines: &mut Lines<'_>) -> Result<Vec<Attr>> {
    let mut out: Vec<Attr> = Vec::new();
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            if out.is_empty() {
                continue;
            }
            break;
        }
        let p = line.piece();
        if p.first() == Some(b' ') {
            if let Some(last) = out.last_mut() {
                if last.value.len() < super::VALUE_CAP.saturating_mul(16) {
                    last.value.push_str(&p.from(1).text());
                }
                let end = line.span.end();
                last.span = Span::new(last.span.source, last.span.offset, end.saturating_sub(last.span.offset));
                last.value_span = Span::new(
                    last.value_span.source,
                    last.value_span.offset,
                    end.saturating_sub(last.value_span.offset),
                );
            }
            continue;
        }
        if p.first() == Some(b'#') {
            continue;
        }
        let Some((name, rest)) = p.split_once(b':') else {
            continue;
        };
        let (base64, value) = match rest.strip_prefix(b":") {
            Some(v) => (true, v.trim()),
            None => (false, rest.strip_prefix(b"<").unwrap_or(rest).trim()),
        };
        out.push(Attr {
            name: name.text(),
            value: value.text(),
            base64,
            span: line.span,
            value_span: value.span(),
        });
        if out.len() > 100_000 {
            break;
        }
    }
    Ok(out)
}

/// Decodes a base64 value if it is text.
fn text_value(a: &Attr) -> Option<String> {
    if !a.base64 {
        return Some(a.value.clone());
    }
    let bytes = super::decode::base64(a.value.as_bytes()).bytes;
    let text = std::str::from_utf8(&bytes).ok()?;
    (!text.chars().any(|c| c.is_control() && c != '\n' && c != '\t')).then(|| text.to_owned())
}

#[derive(Clone, Debug)]
struct Entry {
    input: Input,
    span: Span,
}

async fn entry(cx: Cx, e: Entry) -> Result<()> {
    let mut lines = Lines::new(&cx, e.span);
    for a in record(&mut lines).await? {
        let node = match text_value(&a) {
            Some(text) => {
                let mut n = text_node(a.name.clone(), a.span, &text);
                if a.base64 {
                    n = n.summary("base64");
                }
                n
            }
            None => decoded_node(a.name.clone(), e.input, a.value_span, Transform::Base64)
                .summary("base64 binary"),
        };
        cx.push(node).await;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let inner = prepared.input(input);
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut entries = 0u64;
    loop {
        let before = lines.pos();
        let attrs = record(&mut lines).await?;
        let Some(first) = attrs.first() else {
            break;
        };
        if first.name.eq_ignore_ascii_case("version") && attrs.len() == 1 {
            cx.push(text_node("version", first.span, &first.value)).await;
            continue;
        }
        let start = first.span.offset.saturating_sub(span.offset).max(before);
        let end = attrs.last().map_or(start, |a| a.span.end().saturating_sub(span.offset));
        let s = span.sub(start, end.saturating_sub(start));
        // A `version:` line may share the first record.
        let dn = attrs
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case("dn"))
            .and_then(text_value)
            .unwrap_or_else(|| "(no dn)".to_owned());
        let classes: Vec<String> = attrs
            .iter()
            .filter(|a| a.name.eq_ignore_ascii_case("objectClass"))
            .map(|a| a.value.clone())
            .collect();
        let change = attrs
            .iter()
            .find(|a| a.name.eq_ignore_ascii_case("changetype"))
            .map(|a| a.value.clone());
        let summary = match change {
            Some(c) => format!("changetype {c}"),
            None => preview(&classes.join(", "), 80),
        };
        entries = entries.saturating_add(1);
        cx.push(
            Node::new(dn)
                .span(s)
                .summary(summary)
                .lazy(entry, Entry { input: inner, span: s }),
        )
        .await;
    }
    cx.annotate(format!("LDIF, {}", plural(entries, "entry", "entries")));
    Ok(())
}
