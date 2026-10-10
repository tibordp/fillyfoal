//! Markdown: an outline of sections by heading (ATX `#` and setext
//! underlines), each holding its blocks (paragraphs, fenced and indented
//! code, lists, quotes, tables, rules) and subsections. YAML or TOML front
//! matter is dissected as such.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;

use super::decode::preview;
use super::encoding::prepare;
use super::scan::{LineBuf, Lines};
use super::{plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "markdown",
    title: "Markdown document",
    extensions: &["md", "markdown", "mdown", "mkd", "mdx"],
    mime: "text/markdown",
    probe: Probe::Custom(probe_markdown),
    dissect: crate::expander!(dissect: Input),
};

/// The level of an ATX heading line (`## Title`).
fn atx(line: &[u8]) -> Option<u8> {
    let t = line
        .strip_prefix(b"   ")
        .or_else(|| line.strip_prefix(b"  "))
        .or_else(|| line.strip_prefix(b" "))
        .unwrap_or(line);
    let n = t.iter().take_while(|&&b| b == b'#').count();
    let after = t.get(n);
    ((1..=6).contains(&n) && matches!(after, None | Some(b' ' | b'\t')))
        .then(|| u8::try_from(n).unwrap_or(6))
}

/// A setext underline: `===` (level 1) or `---` (level 2).
fn setext(line: &[u8]) -> Option<u8> {
    let t = probe::trim(line);
    if t.len() < 2 {
        return None;
    }
    if t.iter().all(|&b| b == b'=') {
        Some(1)
    } else if t.iter().all(|&b| b == b'-') {
        Some(2)
    } else {
        None
    }
}

/// A code fence (```` ``` ```` or `~~~`), returning its marker.
fn fence(line: &[u8]) -> Option<&'static [u8]> {
    let t = probe::trim_start(line);
    if t.starts_with(b"```") {
        Some(b"```")
    } else if t.starts_with(b"~~~") {
        Some(b"~~~")
    } else {
        None
    }
}

fn probe_markdown(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut lines = probe::lines(&head).peekable();
    // Front matter followed by Markdown content.
    if let Some(first) = lines.peek().copied()
        && (probe::trim(first) == b"---" || probe::trim(first) == b"+++")
    {
        let marker = probe::trim(first).to_vec();
        lines.next();
        let closed = lines
            .by_ref()
            .take(100)
            .any(|l| probe::trim(l) == marker.as_slice());
        let next = lines.find(|l| !probe::trim(l).is_empty());
        return closed
            && next.is_some_and(|l| atx(l).is_some() || !l.contains(&b':'))
            && probe::is_text(h);
    }
    let mut headings = 0usize;
    let mut signals = 0usize;
    let mut code_like = 0usize;
    let mut total = 0usize;
    let mut first_heading = false;
    let mut mappings = 0usize;
    if head.starts_with(b"%YAML") {
        return false;
    }
    for (i, line) in probe::significant(&head, &[]).take(200).enumerate() {
        total = total.saturating_add(1);
        let t = probe::trim(line);
        if atx(line).is_some() {
            headings = headings.saturating_add(1);
            first_heading |= i == 0;
        }
        // `key: value` lines suggest YAML with `#` comments.
        if t.iter().position(|&b| b == b':').is_some_and(|c| {
            c > 0
                && t.get(..c).is_some_and(|k| {
                    k.iter()
                        .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-')
                })
                && matches!(t.get(c.saturating_add(1)), None | Some(b' '))
        }) {
            mappings = mappings.saturating_add(1);
        }
        if fence(line).is_some()
            || probe::contains(t, b"](")
            || t.starts_with(b"- ")
            || t.starts_with(b"* ")
            || t.starts_with(b"> ")
            || probe::contains(t, b"**")
        {
            signals = signals.saturating_add(1);
        }
        if t.ends_with(b";")
            || t.ends_with(b"{")
            || t.starts_with(b"#include")
            || t.starts_with(b"#!")
            || t.starts_with(b"import ")
        {
            code_like = code_like.saturating_add(1);
        }
    }
    first_heading
        && (headings >= 2 || signals >= 1)
        && mappings.saturating_mul(3) <= total
        && code_like.saturating_mul(10) <= total
        && probe::is_text(h)
}

// ---------------------------------------------------------------------------
// Sections

#[derive(Clone, Debug)]
struct Section {
    input: Input,
    span: Span,
    /// 0 for the document.
    level: u8,
}

/// The text of a heading line.
fn heading_text(line: &LineBuf) -> String {
    let t = line.piece().trim();
    let n = t.bytes().iter().take_while(|&&b| b == b'#').count();
    let t = t.from(n).trim();
    // Optional closing hashes.
    let t = t.trim_end_matches(|b| b == b'#').trim();
    t.text()
}

/// Lines classified for block structure.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Line {
    Blank,
    Heading(u8),
    Fence,
    Other,
}

/// Walks a section: its own blocks, then its subsections.
async fn section(cx: Cx, s: Section) -> Result<()> {
    let mut lines = Lines::new(&cx, s.span);
    if s.level > 0 {
        // The heading itself (and a setext underline).
        let first = lines.next().await?;
        if first.as_ref().is_some_and(|f| atx(&f.bytes).is_none())
            && lines
                .peek()
                .await?
                .is_some_and(|l| setext(&l.bytes).is_some())
        {
            lines.next().await?;
        }
    }
    let mut block: Vec<LineBuf> = Vec::new();
    let mut in_fence: Option<&'static [u8]> = None;
    // An open subsection: (start, level, title).
    let mut sub: Option<(u64, u8, String)> = None;
    loop {
        let before = lines.pos();
        let Some(line) = lines.next().await? else {
            break;
        };
        // Classify (setext needs the next line).
        let kind = if let Some(marker) = in_fence {
            if probe::trim_start(&line.bytes).starts_with(marker) {
                in_fence = None;
            }
            Line::Other
        } else if let Some(m) = fence(&line.bytes) {
            in_fence = Some(m);
            Line::Fence
        } else if line.is_blank() {
            Line::Blank
        } else if let Some(level) = atx(&line.bytes) {
            Line::Heading(level)
        } else if block.iter().all(|l: &LineBuf| l.is_blank())
            && sub.is_none()
            && let Some(next) = lines.peek().await?
            && let Some(level) = setext(&next.bytes)
            && level > s.level
        {
            Line::Heading(level)
        } else if let Some(next) = lines.peek().await?
            && sub.is_some()
            && setext(&next.bytes).is_some()
            && !line.is_blank()
        {
            Line::Heading(setext(&next.bytes).unwrap_or(2))
        } else {
            Line::Other
        };
        if let Line::Heading(level) = kind {
            // A heading at or above an open subsection's level closes it.
            let closes = sub.as_ref().is_some_and(|(_, l, _)| level <= *l);
            if sub.is_none() || closes {
                if let Some((start, l, title)) = sub.take() {
                    push_section(&cx, &s, start, before, l, &title).await;
                } else {
                    flush(&cx, &mut block).await;
                }
                let title = if atx(&line.bytes).is_some() {
                    heading_text(&line)
                } else {
                    line.piece().trim().text()
                };
                sub = Some((before, level, title));
                if atx(&line.bytes).is_none() {
                    lines.next().await?; // the underline
                }
            }
            continue;
        }
        if sub.is_some() {
            continue;
        }
        if kind == Line::Blank && in_fence.is_none() && !block.is_empty() {
            let fenced = block.first().is_some_and(|l| fence(&l.bytes).is_some());
            if !fenced {
                flush(&cx, &mut block).await;
                continue;
            }
        }
        block.push(line);
        // A closed fence ends its block.
        if in_fence.is_none()
            && block.len() > 1
            && block.first().is_some_and(|l| fence(&l.bytes).is_some())
            && block.last().is_some_and(|l| fence(&l.bytes).is_some())
        {
            flush(&cx, &mut block).await;
        }
        if block.len() > 10_000 {
            flush(&cx, &mut block).await;
        }
    }
    flush(&cx, &mut block).await;
    if let Some((start, l, title)) = sub.take() {
        push_section(&cx, &s, start, lines.pos(), l, &title).await;
    }
    Ok(())
}

async fn push_section(cx: &Cx, s: &Section, start: u64, end: u64, level: u8, title: &str) {
    let span = s.span.sub(start, end.saturating_sub(start));
    let name = if title.is_empty() {
        format!("(heading {level})")
    } else {
        title.to_owned()
    };
    cx.push(
        Node::new(name)
            .span(span)
            .summary(format!("{} heading", "#".repeat(usize::from(level))))
            .lazy(
                crate::expander!(self::section: Section),
                Section {
                    input: s.input,
                    span,
                    level,
                },
            ),
    )
    .await;
}

fn lines_span(block: &[LineBuf]) -> Option<Span> {
    let first = block.first()?.span;
    let last = block.last()?.span;
    Some(Span::new(
        first.source,
        first.offset,
        last.end().saturating_sub(first.offset),
    ))
}

fn is_item(line: &[u8]) -> bool {
    let t = probe::trim_start(line);
    if matches!(t.first(), Some(b'-' | b'*' | b'+')) && matches!(t.get(1), Some(b' ' | b'\t')) {
        return true;
    }
    let digits = t.iter().take_while(|b| b.is_ascii_digit()).count();
    digits > 0
        && digits < 10
        && matches!(t.get(digits), Some(b'.' | b')'))
        && matches!(t.get(digits.saturating_add(1)), Some(b' ' | b'\t'))
}

/// Pushes the node for a block of lines and clears it.
async fn flush(cx: &Cx, block: &mut Vec<LineBuf>) {
    while block.first().is_some_and(LineBuf::is_blank) {
        block.remove(0);
    }
    while block.last().is_some_and(LineBuf::is_blank) {
        block.pop();
    }
    let Some(span) = lines_span(block) else {
        block.clear();
        return;
    };
    let first = block.first().map(|l| l.bytes.clone()).unwrap_or_default();
    let joined = |sep: &str, strip: &dyn Fn(&LineBuf) -> String| {
        block.iter().map(strip).collect::<Vec<_>>().join(sep)
    };
    let node = if let Some(_marker) = fence(&first) {
        let info = super::encoding::decode_8bit(probe::trim(
            probe::trim_start(&first).get(3..).unwrap_or_default(),
        ));
        let body: Vec<String> = block
            .iter()
            .skip(1)
            .take(
                block
                    .len()
                    .saturating_sub(2)
                    .max(usize::from(block.len() == 1)),
            )
            .map(LineBuf::text)
            .collect();
        let name = if info.is_empty() {
            "Code".to_owned()
        } else {
            format!("Code ({info})")
        };
        text_node(name, span, &body.join("\n")).summary(plural(
            crate::bytes::to_u64(body.len()),
            "line",
            "lines",
        ))
    } else if first.starts_with(b"    ") || first.starts_with(b"\t") {
        text_node("Code", span, &joined("\n", &|l| l.text()))
    } else if probe::trim_start(&first).starts_with(b">") {
        let text = joined(" ", &|l| {
            let t = l.piece().trim();
            t.strip_prefix(b">").unwrap_or(t).trim().text()
        });
        text_node("Quote", span, &text)
    } else if is_item(&first) {
        let items = block.iter().filter(|l| is_item(&l.bytes)).count();
        Node::new("List")
            .span(span)
            .summary(format!(
                "{}: {}",
                plural(crate::bytes::to_u64(items), "item", "items"),
                preview(&String::from_utf8_lossy(probe::trim(&first)), 50)
            ))
            .lazy(list, span)
    } else if block.len() >= 2
        && first.contains(&b'|')
        && block.get(1).is_some_and(|l| {
            let t = probe::trim(&l.bytes);
            t.contains(&b'-')
                && t.iter()
                    .all(|&b| matches!(b, b'|' | b'-' | b':' | b' ' | b'\t'))
        })
    {
        let cols = probe::trim(&first)
            .split(|&b| b == b'|')
            .filter(|c| !probe::trim(c).is_empty())
            .count();
        Node::new("Table")
            .span(span)
            .summary(format!(
                "{} × {}",
                plural(
                    crate::bytes::to_u64(block.len().saturating_sub(2)),
                    "row",
                    "rows"
                ),
                plural(crate::bytes::to_u64(cols), "column", "columns")
            ))
            .lazy(table, span)
    } else if block.len() == 1 && {
        let t: Vec<u8> = first
            .iter()
            .copied()
            .filter(|b| !b.is_ascii_whitespace())
            .collect();
        t.len() >= 3
            && (t.iter().all(|&b| b == b'-')
                || t.iter().all(|&b| b == b'*')
                || t.iter().all(|&b| b == b'_'))
    } {
        Node::new("Rule").span(span)
    } else if probe::trim_start(&first).starts_with(b"<") {
        text_node("HTML", span, &joined("\n", &|l| l.text()))
    } else {
        text_node(
            "Paragraph",
            span,
            &joined(" ", &|l| l.piece().trim().text()),
        )
    };
    block.clear();
    cx.push(node).await;
}

/// The items of a list.
async fn list(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let mut item: Option<(Span, String)> = None;
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        if is_item(&line.bytes) {
            if let Some((s, text)) = item.take() {
                n = n.saturating_add(1);
                cx.push(text_node(format!("Item {n}"), s, &text)).await;
            }
            let t = line.piece().trim();
            let (_, rest) = t.split_word();
            item = Some((line.span, rest.text()));
        } else if let Some((s, text)) = item.as_mut() {
            *s = Span::new(s.source, s.offset, line.span.end().saturating_sub(s.offset));
            if !line.is_blank() {
                text.push(' ');
                text.push_str(&line.piece().trim().text());
            }
        }
    }
    if let Some((s, text)) = item {
        n = n.saturating_add(1);
        cx.push(text_node(format!("Item {n}"), s, &text)).await;
    }
    Ok(())
}

/// The rows of a pipe table, cells named by the header.
async fn table(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    let cells = |l: &LineBuf| -> Vec<String> {
        let t = l.piece().trim();
        let t = t.strip_prefix(b"|").unwrap_or(t);
        let t = t.strip_suffix(b"|").unwrap_or(t);
        t.split(b'|').map(|c| c.trim().text()).collect()
    };
    let header = match lines.next().await? {
        Some(l) => cells(&l),
        None => return Ok(()),
    };
    lines.next().await?; // separator
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        n = n.saturating_add(1);
        let row = cells(&line);
        let summary: Vec<String> = header
            .iter()
            .zip(row.iter())
            .map(|(h, v)| format!("{h}: {v}"))
            .collect();
        cx.push(
            text_node(format!("Row {n}"), line.span, &line.piece().trim().text())
                .summary(preview(&summary.join(", "), 100)),
        )
        .await;
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let inner = prepared.input(input);
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut body = 0u64;
    // Front matter.
    if let Some(first) = lines.next().await? {
        let marker = first.piece().trim().bytes().to_vec();
        if marker == b"---" || marker == b"+++" {
            while let Some(line) = lines.next().await? {
                if line.piece().trim().bytes() == marker.as_slice() {
                    let content = span.sub(first.next, line.start.saturating_sub(first.next));
                    let format = if marker == b"---" {
                        &super::yaml::FORMAT
                    } else {
                        &super::toml::FORMAT
                    };
                    cx.emit(
                        embedded_as("Front matter", inner.nested(content), format)
                            .summary(if marker == b"---" { "YAML" } else { "TOML" }),
                    );
                    body = line.next;
                    break;
                }
            }
        }
    }
    // Annotation: the first heading and a heading count from the head.
    let head = cx.read_avail(span.sub(body, 64 * 1024)).await?;
    let text = super::encoding::probe_text(&head);
    let headings: Vec<&[u8]> = probe::lines(&text).filter(|l| atx(l).is_some()).collect();
    let mut summary = String::from("Markdown");
    if let Some(first) = headings.first() {
        let t = String::from_utf8_lossy(probe::trim(first))
            .trim_start_matches('#')
            .trim()
            .to_owned();
        summary = format!("{summary}: {}", preview(&t, 60));
    }
    if headings.len() > 1 {
        summary = format!(
            "{summary}, {}",
            plural(crate::bytes::to_u64(headings.len()), "heading", "headings")
        );
    }
    cx.annotate(summary);
    section(
        cx,
        Section {
            input: inner,
            span: span.tail(body),
            level: 0,
        },
    )
    .await
}
