//! GNU gettext translation catalogs (`.po`, `.pot`): entries with their
//! comments, flags, context, source and translated strings (including plural
//! forms); the header entry's fields are shown individually.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::scan::{LineBuf, Lines};
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "gettext-po",
    title: "gettext translation catalog",
    extensions: &["po", "pot"],
    mime: "text/x-gettext-translation",
    probe: Probe::Custom(probe_po),
    dissect: crate::expander!(dissect: Input),
};

fn probe_po(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut id = false;
    for line in probe::significant(&head, &[b"#"]).take(40) {
        let t = probe::trim(line);
        if t.starts_with(b"msgid \"") || t.starts_with(b"msgctxt \"") {
            id = true;
        } else if t.starts_with(b"msgstr") {
            return id && probe::is_text(h);
        } else if !t.starts_with(b"\"") && !t.starts_with(b"msgid_plural") {
            return false;
        }
    }
    false
}

/// C-style escapes in a quoted string.
fn unquote(line: &[u8]) -> String {
    let t = probe::trim(line);
    let inner = t
        .strip_prefix(b"\"")
        .and_then(|s| s.strip_suffix(b"\""))
        .unwrap_or(t);
    let text = super::encoding::decode_8bit(inner);
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some(other) => out.push(other),
            None => {}
        }
    }
    out
}

/// One keyword (`msgid`, `msgstr[0]` ...) with its (continued) string.
struct Field {
    keyword: String,
    text: String,
    span: Span,
}

/// An entry parsed from its lines.
#[derive(Default)]
struct Entry {
    comments: Vec<(String, String, Span)>,
    fields: Vec<Field>,
    obsolete: bool,
}

impl Entry {
    fn parse(lines: &[LineBuf]) -> Entry {
        let mut e = Entry::default();
        for line in lines {
            let mut p = line.piece().trim();
            if let Some(rest) = p.strip_prefix(b"#~") {
                e.obsolete = true;
                p = rest.trim();
            } else if p.first() == Some(b'#') {
                let kind = match p.at(1) {
                    Some(b'.') => "Extracted comment",
                    Some(b':') => "Reference",
                    Some(b',') => "Flags",
                    Some(b'|') => "Previous",
                    _ => "Comment",
                };
                let body = if kind == "Comment" {
                    p.from(1)
                } else {
                    p.from(2)
                };
                e.comments
                    .push((kind.to_owned(), body.trim().text(), line.span));
                continue;
            }
            if p.first() == Some(b'"') {
                if let Some(f) = e.fields.last_mut() {
                    f.text.push_str(&unquote(p.bytes()));
                    f.span = Span::new(
                        f.span.source,
                        f.span.offset,
                        line.span.end().saturating_sub(f.span.offset),
                    );
                }
                continue;
            }
            let (keyword, rest) = p.split_word();
            e.fields.push(Field {
                keyword: keyword.text(),
                text: unquote(rest.bytes()),
                span: line.span,
            });
        }
        e
    }

    fn get(&self, keyword: &str) -> Option<&Field> {
        self.fields.iter().find(|f| f.keyword == keyword)
    }

    fn flags(&self) -> Vec<String> {
        self.comments
            .iter()
            .filter(|(k, _, _)| k == "Flags")
            .flat_map(|(_, v, _)| {
                v.split(',')
                    .map(|f| f.trim().to_owned())
                    .collect::<Vec<_>>()
            })
            .collect()
    }

    fn translated(&self) -> bool {
        self.fields
            .iter()
            .filter(|f| f.keyword.starts_with("msgstr"))
            .any(|f| !f.text.is_empty())
    }
}

/// Reads the next entry's lines (up to a blank line).
async fn block(lines: &mut Lines<'_>) -> Result<Vec<LineBuf>> {
    let mut out = Vec::new();
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            if out.is_empty() {
                continue;
            }
            break;
        }
        out.push(line);
        if out.len() > 10_000 {
            break;
        }
    }
    Ok(out)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lines = Lines::new(&cx, prepared.span);
    let (mut total, mut untranslated, mut fuzzy) = (0u64, 0u64, 0u64);
    let mut project = None;
    loop {
        let block = block(&mut lines).await?;
        let (Some(first), Some(last)) = (block.first(), block.last()) else {
            break;
        };
        let span = Span::new(
            first.span.source,
            first.span.offset,
            last.span.end().saturating_sub(first.span.offset),
        );
        let e = Entry::parse(&block);
        let id = e.get("msgid").map(|f| f.text.clone()).unwrap_or_default();
        let header = id.is_empty() && e.get("msgctxt").is_none();
        let flags = e.flags();
        let name = if header {
            "Header".to_owned()
        } else {
            total = total.saturating_add(1);
            if !e.translated() {
                untranslated = untranslated.saturating_add(1);
            }
            if flags.iter().any(|f| f == "fuzzy") {
                fuzzy = fuzzy.saturating_add(1);
            }
            preview(&id, 60)
        };
        let msgstr = e
            .get("msgstr")
            .or_else(|| e.get("msgstr[0]"))
            .map(|f| f.text.clone())
            .unwrap_or_default();
        if header {
            project = msgstr
                .lines()
                .find_map(|l| l.strip_prefix("Project-Id-Version:"))
                .map(|v| v.trim().to_owned());
        }
        let mut summary: Vec<String> = flags;
        if e.obsolete {
            summary.push("obsolete".to_owned());
        }
        let mut node = Node::new(name).span(span).lazy(entry, span);
        if !header {
            node = node.value(Value::Text(super::decode::cap(&msgstr, super::VALUE_CAP).0));
        }
        if !summary.is_empty() {
            node = node.summary(summary.join(", "));
        }
        cx.push(node).await;
    }
    let mut summary = String::from("gettext catalog");
    if let Some(p) = project.filter(|p| !p.is_empty()) {
        summary = format!("{summary}: {p}");
    }
    cx.annotate(format!(
        "{summary}, {} ({untranslated} untranslated, {fuzzy} fuzzy)",
        plural(total, "message", "messages")
    ));
    Ok(())
}

async fn entry(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let block = block(&mut lines).await?;
    let e = Entry::parse(&block);
    for (kind, text, span) in &e.comments {
        cx.emit(text_node(kind.clone(), *span, text));
    }
    for f in &e.fields {
        let header = f.keyword == "msgstr" && e.get("msgid").is_some_and(|m| m.text.is_empty());
        let mut node = text_node(f.keyword.clone(), f.span, &f.text);
        if header {
            // Header fields: `Name: value` per line.
            let fields: Vec<(String, String)> = f
                .text
                .lines()
                .filter_map(|l| l.split_once(':'))
                .map(|(k, v)| (k.trim().to_owned(), v.trim().to_owned()))
                .collect();
            node = node
                .summary(plural(
                    crate::bytes::to_u64(fields.len()),
                    "field",
                    "fields",
                ))
                .lazy(header_fields, f.span);
        }
        cx.emit(node);
    }
    Ok(())
}

async fn header_fields(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let block = block(&mut lines).await?;
    let mut text = String::new();
    for line in &block {
        let p = line.piece().trim();
        let p = p.strip_prefix(b"msgstr").unwrap_or(p).trim();
        text.push_str(&unquote(p.bytes()));
    }
    for l in text.lines() {
        if let Some((k, v)) = l.split_once(':') {
            cx.emit(Node::new(k.trim().to_owned()).value(Value::Text(v.trim().to_owned())));
        }
    }
    Ok(())
}
