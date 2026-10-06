//! HTML: a tolerant tag tree (void elements, raw-text elements, implied end
//! tags), sharing the markup machinery of [`super::xml`]. Not a full HTML5
//! tree builder, but close enough to browse real pages.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, HEAD_LEN, Head, Input, Probe};

use super::probe;
use super::xml::{self, Mode};

pub static FORMAT: Format = Format {
    name: "html",
    title: "HTML document",
    extensions: &["html", "htm", "shtml", "xhtml", "hta"],
    mime: "text/html",
    probe: Probe::Custom(probe_html),
    dissect: crate::expander!(dissect: Input),
};

/// Tags that, as the first markup in a document, mean HTML.
const LEADING: &[&[u8]] = &[
    b"html", b"head", b"body", b"meta", b"title", b"link", b"base", b"style", b"script",
];

fn probe_html(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut rest = probe::trim_start(&head);
    // Skip leading comments.
    while rest.starts_with(b"<!--") {
        let Some(end) = probe::find(rest, b"-->") else {
            return false;
        };
        rest = probe::trim_start(rest.get(end.saturating_add(3)..).unwrap_or_default());
    }
    if probe::starts_with_nocase(rest, b"<!doctype html") {
        return probe::is_text(h);
    }
    let Some(tag) = rest.strip_prefix(b"<") else {
        return false;
    };
    let n = tag.iter().take_while(|b| b.is_ascii_alphanumeric()).count();
    let name = tag.get(..n).unwrap_or_default().to_ascii_lowercase();
    LEADING.contains(&name.as_slice()) && probe::is_text(h)
}

/// `charset` from `<meta charset=...>` or a `Content-Type` meta tag.
fn charset(head: &[u8]) -> Option<String> {
    let lower = head.to_ascii_lowercase();
    let at = probe::find(&lower, b"charset=")?;
    let rest = lower.get(at.saturating_add(8)..)?;
    let rest = rest
        .strip_prefix(b"\"")
        .or_else(|| rest.strip_prefix(b"'"))
        .unwrap_or(rest);
    let end = rest
        .iter()
        .position(|&b| !(b.is_ascii_alphanumeric() || b == b'-' || b == b'_'))
        .unwrap_or(rest.len());
    let name = rest.get(..end)?;
    (!name.is_empty()).then(|| String::from_utf8_lossy(name).into_owned())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let data = cx.read_avail(input.span.sub(0, HEAD_LEN)).await?;
    let head = super::encoding::probe_text(&data);
    let lower = head.to_ascii_lowercase();
    let title = probe::find(&lower, b"<title").and_then(|at| {
        xml::first_text(head.get(at..).unwrap_or_default(), b"title")
            .or_else(|| xml::first_text(head.get(at..).unwrap_or_default(), b"TITLE"))
    });
    let mut summary = String::from("HTML document");
    if let Some(t) = title {
        summary = format!("{summary}: {t}");
    }
    if let Some(c) = charset(&head) {
        summary = format!("{summary} ({c})");
    }
    cx.annotate(summary);
    xml::document(&cx, input, Mode::Html).await
}
