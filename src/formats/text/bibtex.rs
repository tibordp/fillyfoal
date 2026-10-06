//! BibTeX bibliographies: entries (`@article{key, field = {value}, ...}`)
//! with their fields; `@string`, `@preamble` and `@comment` too.

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;

use super::decode::preview;
use super::encoding::prepare;
use super::piece::Piece;
use super::scan::Scanner;
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "bibtex",
    title: "BibTeX bibliography",
    extensions: &["bib", "bibtex"],
    mime: "application/x-bibtex",
    probe: Probe::Custom(probe_bib),
    dissect: crate::expander!(dissect: Input),
};

/// `@type{` or `@type(` at the start of `line`: the type.
fn entry_type(line: &[u8]) -> Option<&[u8]> {
    let rest = probe::trim_start(line).strip_prefix(b"@")?;
    let n = rest.iter().take_while(|b| b.is_ascii_alphabetic()).count();
    let after = probe::trim_start(rest.get(n..)?);
    (n > 0 && matches!(after.first(), Some(b'{' | b'('))).then(|| rest.get(..n).unwrap_or_default())
}

fn probe_bib(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    probe::significant(&head, &[b"%"])
        .next()
        .is_some_and(|l| entry_type(l).is_some())
        && probe::is_text(h)
}

/// The most of one entry read into memory.
const ENTRY_CAP: usize = 1 << 20;

/// Finds where the entry whose `@` is at `start` ends (after its closing
/// delimiter), by counting braces.
async fn entry_end(scan: &mut Scanner<'_>, start: u64) -> Result<(u64, bool)> {
    let Some(open) = scan.find(start, |b| b == b'{' || b == b'(').await? else {
        return Ok((scan.len(), false));
    };
    // `@type(...)` entries end at the matching parenthesis outside braces.
    let parens = scan.byte(open).await? == Some(b'(');
    let mut braces = 0u32;
    let mut depth = 0u32;
    let mut pos = open;
    loop {
        let Some(at) = scan
            .find(pos, |b| matches!(b, b'{' | b'}' | b'(' | b')'))
            .await?
        else {
            return Ok((scan.len(), false));
        };
        let b = scan.byte(at).await?.unwrap_or(0);
        pos = at.saturating_add(1);
        match b {
            b'{' => braces = braces.saturating_add(1),
            b'}' => {
                braces = braces.saturating_sub(1);
                if !parens && braces == 0 {
                    return Ok((pos, true));
                }
            }
            b'(' if parens && braces == 0 => depth = depth.saturating_add(1),
            b')' if parens && braces == 0 => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok((pos, true));
                }
            }
            _ => {}
        }
    }
}

/// Splits at top-level commas (outside braces and quotes).
fn split_fields(p: Piece<'_>) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut quoted = false;
    let mut start = 0usize;
    for (i, &b) in p.bytes().iter().enumerate() {
        match b {
            b'{' => depth = depth.saturating_add(1),
            b'}' => depth = depth.saturating_sub(1),
            b'"' if depth == 0 => quoted = !quoted,
            b',' if depth == 0 && !quoted => {
                out.push(p.slice(start, i));
                start = i.saturating_add(1);
            }
            _ => {}
        }
    }
    out.push(p.from(start));
    out.retain(|f| !f.trim().is_empty());
    out
}

/// A field value without its delimiters (`{...}`, `"..."`), with `#`
/// concatenation kept as written.
fn value_text(v: Piece<'_>) -> String {
    let t = v.trim();
    let inner = match (t.first(), t.last()) {
        (Some(b'{'), Some(b'}')) | (Some(b'"'), Some(b'"')) if t.len() >= 2 => {
            t.slice(1, t.len().saturating_sub(1))
        }
        _ => t,
    };
    let text = inner.text();
    // Inner braces protect capitalisation; drop them for display.
    let text: String = text.chars().filter(|&c| c != '{' && c != '}').collect();
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

#[derive(Clone, Debug)]
struct Entry {
    span: Span,
}

/// The body of an entry (between its delimiters) and its type.
fn body(p: Piece<'_>) -> Option<(String, Piece<'_>)> {
    let ty = entry_type(p.bytes())?;
    let ty = String::from_utf8_lossy(ty).to_ascii_lowercase();
    let open = p.find_by(|b| b == b'{' || b == b'(')?;
    let inner = p.from(open.saturating_add(1));
    let inner = inner.to(inner.len().saturating_sub(1));
    Some((ty, inner))
}

async fn entry(cx: Cx, e: Entry) -> Result<()> {
    let owned = Scanner::new(&cx, e.span)
        .owned(0, e.span.len, ENTRY_CAP)
        .await?;
    let Some((ty, inner)) = body(owned.piece()) else {
        return Ok(());
    };
    let mut fields = split_fields(inner).into_iter();
    if !matches!(ty.as_str(), "string" | "preamble" | "comment")
        && let Some(key) = fields.next()
    {
        cx.emit(text_node("Key", key.trim().span(), &key.trim().text()));
    }
    for f in fields {
        match f.split_once(b'=') {
            Some((name, value)) => {
                cx.emit(text_node(
                    name.trim().text().to_ascii_lowercase(),
                    value.trim().span(),
                    &value_text(value),
                ));
            }
            None => cx.emit(text_node("Text", f.trim().span(), &value_text(f))),
        }
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let mut scan = Scanner::new(&cx, span);
    let mut pos = 0u64;
    let mut count = 0u64;
    let mut types: Vec<(String, u64)> = Vec::new();
    while let Some(at) = scan.find(pos, |b| b == b'@').await? {
        cx.checkpoint().await;
        let (end, closed) = entry_end(&mut scan, at).await?;
        let end = end.max(at.saturating_add(1));
        pos = end;
        let head = scan.owned(at, end, 4096).await?;
        let Some((ty, inner)) = body(head.piece()) else {
            continue;
        };
        let entry_span = scan.span(at, end);
        let fields = split_fields(inner);
        let special = matches!(ty.as_str(), "string" | "preamble" | "comment");
        let name = match (special, fields.first()) {
            (false, Some(key)) => key.trim().text(),
            _ => format!("@{ty}"),
        };
        let title = fields.iter().find_map(|f| {
            let (k, v) = f.split_once(b'=')?;
            k.trim().eq_nocase(b"title").then(|| value_text(v))
        });
        let mut summary = ty.clone();
        if let Some(t) = title {
            summary = format!("{summary}: {}", preview(&t, 70));
        }
        let mut node = Node::new(name)
            .span(entry_span)
            .summary(summary)
            .lazy(entry, Entry { span: entry_span });
        if !closed {
            node = node.diag(Diagnostic::new(DiagKind::Truncated, "entry not closed"));
        }
        if !special {
            count = count.saturating_add(1);
            match types.iter_mut().find(|(t, _)| *t == ty) {
                Some((_, n)) => *n = n.saturating_add(1),
                None => types.push((ty, 1)),
            }
        }
        cx.push(node).await;
    }
    let kinds: Vec<String> = types
        .iter()
        .take(4)
        .map(|(t, n)| format!("{n} {t}"))
        .collect();
    cx.annotate(format!(
        "BibTeX, {} ({})",
        plural(count, "entry", "entries"),
        kinds.join(", ")
    ));
    Ok(())
}
