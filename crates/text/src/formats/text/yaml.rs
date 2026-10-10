//! YAML: documents, block mappings and sequences by indentation, block
//! scalars (`|`, `>`), multi-line plain scalars, flow collections (best
//! effort), anchors, aliases and tags.
//!
//! A block is a run of lines whose entries start at one indentation. An
//! entry extends until the next line indented as much or less; its nested
//! content becomes a lazy block. The first document's entries are the top
//! level; further documents are nodes of their own.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::encoding::{decode_8bit, prepare};
use super::piece::Piece;
use super::scan::{LineBuf, Lines, Scanner};
use super::{VALUE_CAP, parse_datetime, plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "yaml",
    title: "YAML document",
    extensions: &["yaml", "yml", "eyaml", "clang-format", "clang-tidy"],
    mime: "application/yaml",
    probe: Probe::Custom(probe_yaml),
    dissect: crate::expander!(dissect: Input),
};

/// `key:` or `key: value` at the start of `line` (after indentation).
fn probe_mapping(line: &[u8]) -> bool {
    let t = probe::trim_start(line);
    let t = t.strip_prefix(b"- ").unwrap_or(t);
    let Some(colon) = t.iter().position(|&b| b == b':') else {
        return false;
    };
    let key = t.get(..colon).unwrap_or_default();
    let after = t.get(colon.saturating_add(1)..).unwrap_or_default();
    !key.is_empty()
        && key.len() <= 80
        && !key.contains(&b'=')
        && !key.contains(&b'<')
        && (after.is_empty() || after.starts_with(b" ") || after.starts_with(b"\t"))
}

fn probe_yaml(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let start = probe::trim_start(&head);
    if start.starts_with(b"%YAML") || start.starts_with(b"%TAG") {
        return true;
    }
    let mut lines = probe::significant(&head, &[b"#"]);
    let Some(first) = lines.next() else {
        return false;
    };
    let mut rest = lines.take(30).peekable();
    if probe::trim(first) == b"---" {
        return rest.peek().is_some() && probe::is_text(h);
    }
    // Without a marker: a mapping at column 0, and every following line a
    // mapping, a sequence item, or an indented continuation.
    let top = first.first().is_some_and(|b| !b.is_ascii_whitespace());
    let mut entries = 0usize;
    for line in rest {
        let indented = line.first().is_some_and(u8::is_ascii_whitespace);
        let item = probe::trim_start(line).starts_with(b"- ") || probe::trim(line) == b"-";
        if probe_mapping(line) {
            entries = entries.saturating_add(1);
        } else if !(indented || item || is_marker(line)) {
            return false;
        }
    }
    top && probe_mapping(first) && entries >= 2 && probe::is_text(h)
}

// ---------------------------------------------------------------------------
// Scalars

/// The typed value of a plain (unquoted) scalar.
fn plain_value(text: &str) -> Option<Value> {
    match text {
        "" | "~" | "null" | "Null" | "NULL" => return None,
        "true" | "True" | "TRUE" => return Some(Value::Bool(true)),
        "false" | "False" | "FALSE" => return Some(Value::Bool(false)),
        ".inf" | ".Inf" | ".INF" | "+.inf" => return Some(Value::Float(f64::INFINITY)),
        "-.inf" | "-.Inf" | "-.INF" => return Some(Value::Float(f64::NEG_INFINITY)),
        ".nan" | ".NaN" | ".NAN" => return Some(Value::Float(f64::NAN)),
        _ => {}
    }
    if let Some(hex) = text.strip_prefix("0x") {
        return i64::from_str_radix(hex, 16)
            .ok()
            .map(|v| Value::Int { value: v, bits: 64 });
    }
    if let Some(oct) = text.strip_prefix("0o") {
        return i64::from_str_radix(oct, 8)
            .ok()
            .map(|v| Value::Int { value: v, bits: 64 });
    }
    let first = text.as_bytes().first().copied().unwrap_or(0);
    if first.is_ascii_digit() || matches!(first, b'-' | b'+' | b'.') {
        if let Some(v) = super::number(text) {
            return Some(v);
        }
        let b = text.as_bytes();
        if b.len() >= 10 && b.get(4) == Some(&b'-') && b.get(7) == Some(&b'-') {
            return parse_datetime(text).map(|t| Value::Timestamp { unix_seconds: t });
        }
    }
    Some(Value::Text(text.to_owned()))
}

/// Unescapes a double-quoted scalar.
fn double_quoted(raw: &str) -> String {
    let mut out = String::with_capacity(raw.len());
    let mut chars = raw.chars();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let hex = |n: usize, chars: &mut std::str::Chars<'_>| {
            let h: String = chars.by_ref().take(n).collect();
            u32::from_str_radix(&h, 16)
                .ok()
                .and_then(char::from_u32)
                .unwrap_or(char::REPLACEMENT_CHARACTER)
        };
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('0') => out.push('\0'),
            Some('e') => out.push('\u{1b}'),
            Some('x') => out.push(hex(2, &mut chars)),
            Some('u') => out.push(hex(4, &mut chars)),
            Some('U') => out.push(hex(8, &mut chars)),
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// Length of a quoted scalar at the start of `s` (including quotes).
fn quoted_len(s: &[u8]) -> usize {
    let q = s.first().copied().unwrap_or(b'"');
    let mut i = 1usize;
    while let Some(&b) = s.get(i) {
        i = i.saturating_add(1);
        if b == b'\\' && q == b'"' {
            i = i.saturating_add(1);
        } else if b == q {
            if q == b'\'' && s.get(i) == Some(&b'\'') {
                i = i.saturating_add(1);
                continue;
            }
            break;
        }
    }
    i.min(s.len())
}

/// `value` without a trailing ` # comment`.
fn strip_comment<'a>(value: Piece<'a>) -> Piece<'a> {
    let b = value.bytes();
    if matches!(b.first(), Some(b'"' | b'\'')) {
        let n = quoted_len(b);
        let rest = value.from(n);
        return match rest.find(b'#') {
            Some(_) => value.to(n),
            None => value,
        };
    }
    let mut prev_space = true;
    for (i, &c) in b.iter().enumerate() {
        if c == b'#' && prev_space {
            return value.to(i).trim_end();
        }
        prev_space = c == b' ' || c == b'\t';
    }
    value
}

/// Where the `:` of a `key: value` line is (relative to `t`).
fn key_colon(t: &Piece<'_>) -> Option<usize> {
    let b = t.bytes();
    let from = match b.first() {
        Some(b'"' | b'\'') => quoted_len(b),
        Some(b'[' | b'{' | b'#' | b'|' | b'>') => return None,
        _ => 0,
    };
    let mut i = from;
    while let Some(&c) = b.get(i) {
        let next = b.get(i.saturating_add(1)).copied();
        if c == b':' && matches!(next, None | Some(b' ' | b'\t')) {
            return Some(i);
        }
        if c == b'#' && i > 0 && matches!(b.get(i.saturating_sub(1)), Some(b' ' | b'\t')) {
            return None;
        }
        i = i.saturating_add(1);
    }
    None
}

fn key_text(key: Piece<'_>) -> String {
    let k = key.trim();
    match k.first() {
        Some(b'"') => double_quoted(&k.unquote().text()),
        Some(b'\'') => k.unquote().text().replace("''", "'"),
        _ => k.text(),
    }
}

/// Splits leading `&anchor` and `!tag` properties off a value.
fn properties<'a>(value: Piece<'a>) -> (Vec<String>, Piece<'a>) {
    let mut props = Vec::new();
    let mut rest = value;
    while matches!(rest.first(), Some(b'&' | b'!')) {
        let (word, tail) = rest.split_word();
        props.push(word.text());
        rest = tail;
    }
    (props, rest)
}

// ---------------------------------------------------------------------------
// Blocks

#[derive(Clone, Debug)]
struct Block {
    span: Span,
    /// Column of the span's first byte (non-zero for content that starts
    /// mid-line, after `- `).
    col: u64,
}

/// Indentation of a line (columns of leading spaces and tabs).
fn indent(line: &[u8]) -> u64 {
    to_u64(
        line.iter()
            .take_while(|&&b| b == b' ' || b == b'\t')
            .count(),
    )
}

fn is_marker(line: &[u8]) -> bool {
    (line.starts_with(b"---") || line.starts_with(b"..."))
        && matches!(line.get(3), None | Some(b' ' | b'\t' | b'\r'))
}

/// An entry being collected: its first line and where it starts.
struct Pending {
    first: LineBuf,
    /// Column at which the entry's content starts on its first line.
    col: u64,
    /// Relative start of the content on the first line.
    start: u64,
    /// Where the entry's continuation lines start.
    rest: u64,
}

/// Pushes the entries of a block; returns where it stopped (a document
/// marker or the end).
async fn block_entries(cx: &Cx, b: &Block) -> Result<u64> {
    let mut lines = Lines::new(cx, b.span);
    let mut base: Option<u64> = None;
    let mut sequence = false;
    let mut pending: Option<Pending> = None;
    let mut index = 0u64;
    let mut first_line = true;
    loop {
        let before = lines.pos();
        let Some(line) = lines.next().await? else {
            if let Some(p) = pending.take() {
                entry(cx, b, p, before, sequence, &mut index).await?;
            }
            return Ok(before);
        };
        let offset = if first_line { b.col } else { 0 };
        first_line = false;
        let content = line.piece().trim_start();
        if content.is_empty() || content.first() == Some(b'#') {
            continue;
        }
        if offset == 0 && is_marker(&line.bytes) {
            if let Some(p) = pending.take() {
                entry(cx, b, p, before, sequence, &mut index).await?;
            }
            return Ok(before);
        }
        let col = indent(&line.bytes).saturating_add(offset);
        let base_col = *base.get_or_insert_with(|| {
            sequence = content.starts_with(b"- ") || content.bytes() == b"-";
            col
        });
        let item = content.starts_with(b"- ") || content.bytes() == b"-";
        // In a mapping, a sequence may sit at the key's own indentation.
        let continues = col > base_col || (col == base_col && !sequence && item);
        if continues && pending.is_some() {
            continue;
        }
        if let Some(p) = pending.take() {
            entry(cx, b, p, before, sequence, &mut index).await?;
        }
        let start = line.start.saturating_add(indent(&line.bytes));
        pending = Some(Pending {
            first: line.clone(),
            col,
            start,
            rest: line.next,
        });
    }
}

/// Builds and pushes the node for one entry spanning `p.start..end`.
async fn entry(
    cx: &Cx,
    b: &Block,
    p: Pending,
    end: u64,
    sequence: bool,
    index: &mut u64,
) -> Result<()> {
    let scan = Scanner::new(cx, b.span);
    let line = p.first.piece().trim();
    let span = scan.span(p.start, end);
    let rest = scan.span(p.rest, end);
    let node = if sequence {
        let name = format!("[{index}]");
        *index = index.saturating_add(1);
        let content = line.strip_prefix(b"-").unwrap_or(line);
        let offset = to_u64(line.len().saturating_sub(content.trim_start().len()));
        let content = content.trim_start();
        if content.is_empty() {
            value_node(cx, name, content, span, rest).await?
        } else if key_colon(&content).is_some() || content.starts_with(b"- ") {
            // A mapping (or sequence) starting on the item's line.
            let inner = scan.span(p.start.saturating_add(offset), end);
            let kind = if content.starts_with(b"- ") {
                "sequence"
            } else {
                "mapping"
            };
            block_node(name, inner, p.col.saturating_add(offset), kind)
        } else {
            value_node(cx, name, content, span, rest).await?
        }
    } else {
        match key_colon(&line) {
            Some(colon) => {
                let key = key_text(line.to(colon));
                let value = line.from(colon.saturating_add(1)).trim();
                value_node(cx, key, value, span, rest).await?
            }
            None => text_node("?", span, &line.text())
                .diag(Diagnostic::malformed("expected `key: value`")),
        }
    };
    cx.progress_in(b.span, b.span.offset.saturating_add(end));
    cx.push(node).await;
    Ok(())
}

fn block_node(name: String, span: Span, col: u64, kind: &str) -> Node {
    let mut node = Node::new(name)
        .span(span)
        .lazy(expand_block, Block { span, col });
    if !kind.is_empty() {
        node = node.summary(kind.to_owned());
    }
    node
}

async fn expand_block(cx: Cx, b: Block) -> Result<()> {
    block_entries(&cx, &b).await.map(|_| ())
}

/// The node for a value whose inline part is `value` and whose following
/// lines are `rest`.
async fn value_node(
    cx: &Cx,
    name: String,
    value: Piece<'_>,
    span: Span,
    rest: Span,
) -> Result<Node> {
    let (props, value) = properties(value);
    let props = props.join(" ");
    let value = strip_comment(value.trim());
    let with_props = |node: Node| {
        if props.is_empty() {
            node
        } else {
            let summary = match &node.summary {
                Some(s) => format!("{props} {s}"),
                None => props.clone(),
            };
            node.summary(summary)
        }
    };
    let first = if rest.is_empty() {
        None
    } else {
        first_content(cx, rest).await?
    };
    let has_rest = first.is_some();
    if value.is_empty() {
        let kind = if first == Some(true) {
            "sequence"
        } else {
            "mapping"
        };
        return Ok(if has_rest {
            with_props(block_node(name, rest, 0, kind))
        } else {
            with_props(Node::new(name).span(span).summary("null"))
        });
    }
    match value.first() {
        Some(b'|' | b'>') => {
            let folded = value.first() == Some(b'>');
            let text = block_scalar(cx, rest, folded, value.bytes()).await?;
            let style = if folded { "folded" } else { "literal" };
            return Ok(with_props(
                text_node(name, span, &text).summary(format!("{style} block")),
            ));
        }
        Some(b'[' | b'{') => {
            let flow = Span::new(
                span.source,
                value.span().offset,
                span.end().saturating_sub(value.span().offset),
            );
            return Ok(with_props(flow_node(cx, name, flow).await?));
        }
        Some(b'*') => {
            return Ok(text_node(name, value.span(), &value.text()).summary("alias"));
        }
        _ => {}
    }
    // A scalar, possibly continued on the following lines.
    let mut text = match value.first() {
        Some(b'"') => double_quoted(&value.unquote().text()),
        Some(b'\'') => value.unquote().text().replace("''", "'"),
        _ => value.text(),
    };
    let quoted = matches!(value.first(), Some(b'"' | b'\''));
    if has_rest {
        let more = folded_lines(cx, rest).await?;
        if !more.is_empty() {
            text = format!("{text} {more}");
            if quoted {
                text = text.trim_end_matches(['"', '\'']).to_owned();
            }
        }
    }
    let value_span = if has_rest {
        Span::new(
            span.source,
            value.span().offset,
            span.end().saturating_sub(value.span().offset),
        )
    } else {
        value.span()
    };
    let node = if quoted {
        text_node(name, value_span, &text)
    } else {
        match plain_value(&text) {
            Some(Value::Text(t)) => text_node(name, value_span, &t),
            Some(v) => Node::new(name).span(value_span).value(v),
            None => Node::new(name).span(value_span).summary("null"),
        }
    };
    Ok(with_props(node))
}

async fn is_blank(cx: &Cx, span: Span) -> Result<bool> {
    Ok(first_content(cx, span).await?.is_none())
}

/// What the first significant line of `span` starts: `Some(true)` for a
/// sequence item, `Some(false)` for anything else, `None` if there is none.
async fn first_content(cx: &Cx, span: Span) -> Result<Option<bool>> {
    let mut lines = Lines::new(cx, span);
    while let Some(line) = lines.next().await? {
        let t = line.piece().trim();
        if !t.is_empty() && t.first() != Some(b'#') {
            return Ok(Some(t.starts_with(b"- ") || t.bytes() == b"-"));
        }
    }
    Ok(None)
}

/// Continuation lines of a plain scalar, folded into one line.
async fn folded_lines(cx: &Cx, span: Span) -> Result<String> {
    let mut lines = Lines::new(cx, span);
    let mut out = String::new();
    // Checked before every line, blank ones included.
    while out.len() <= VALUE_CAP.saturating_mul(4)
        && let Some(line) = lines.next().await?
    {
        let t = line.piece().trim();
        if t.is_empty() {
            out.push('\n');
            continue;
        }
        if !out.is_empty() && !out.ends_with('\n') {
            out.push(' ');
        }
        out.push_str(&t.text());
    }
    Ok(out.trim().to_owned())
}

/// The text of a `|` or `>` block scalar.
async fn block_scalar(cx: &Cx, span: Span, folded: bool, header: &[u8]) -> Result<String> {
    let mut lines = Lines::new(cx, span);
    let mut strip: Option<u64> = None;
    let mut out = String::new();
    // Checked before every line, blank ones included.
    while out.len() <= VALUE_CAP.saturating_mul(4)
        && let Some(line) = lines.next().await?
    {
        if line.piece().trim().is_empty() {
            out.push('\n');
            continue;
        }
        let n = *strip.get_or_insert_with(|| indent(&line.bytes));
        let content = decode_8bit(
            line.bytes
                .get(to_usize(n.min(indent(&line.bytes)))..)
                .unwrap_or_default(),
        );
        if folded && !out.is_empty() && !out.ends_with('\n') {
            out.push(' ');
        } else if !folded && !out.is_empty() && !out.ends_with('\n') {
            out.push('\n');
        }
        out.push_str(&content);
        if !folded {
            out.push('\n');
        }
    }
    // Chomping: `-` strips the final newlines, `+` keeps them, default clips
    // to one.
    if header.contains(&b'-') {
        out.truncate(out.trim_end_matches('\n').len());
    } else if !header.contains(&b'+') {
        out.truncate(out.trim_end_matches('\n').len());
        out.push('\n');
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Flow collections

/// Length of the flow collection at the start of `s` (brackets balanced,
/// quotes honoured).
fn flow_len(s: &[u8]) -> usize {
    let mut depth = 0u32;
    let mut i = 0usize;
    while let Some(&b) = s.get(i) {
        match b {
            b'[' | b'{' => depth = depth.saturating_add(1),
            b']' | b'}' => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return i.saturating_add(1);
                }
            }
            b'"' | b'\'' => {
                i = i.saturating_add(quoted_len(s.get(i..).unwrap_or_default()));
                continue;
            }
            b'#' if i > 0 && matches!(s.get(i.saturating_sub(1)), Some(b' ' | b'\n')) => {
                while s.get(i).is_some_and(|&c| c != b'\n') {
                    i = i.saturating_add(1);
                }
                continue;
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    s.len()
}

/// Items of the flow collection `s` (without its brackets): ranges of each
/// item, split at top-level commas.
fn flow_items(s: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut depth = 0u32;
    let mut start = 0usize;
    let mut i = 0usize;
    while let Some(&b) = s.get(i) {
        match b {
            b'[' | b'{' => depth = depth.saturating_add(1),
            b']' | b'}' => depth = depth.saturating_sub(1),
            b'"' | b'\'' => {
                i = i.saturating_add(quoted_len(s.get(i..).unwrap_or_default()));
                continue;
            }
            b',' if depth == 0 => {
                out.push((start, i));
                start = i.saturating_add(1);
            }
            _ => {}
        }
        i = i.saturating_add(1);
    }
    out.push((start, s.len()));
    out.retain(|&(a, b)| !probe::trim(s.get(a..b).unwrap_or_default()).is_empty());
    out
}

async fn flow_node(cx: &Cx, name: String, span: Span) -> Result<Node> {
    let owned = Scanner::new(cx, span).owned(0, span.len, 1 << 20).await?;
    let p = owned.piece();
    let len = flow_len(p.bytes());
    let whole = p.to(len);
    let mapping = whole.first() == Some(b'{');
    let inner = whole.slice(1, len.saturating_sub(1));
    let n = to_u64(flow_items(inner.bytes()).len());
    let summary = if mapping {
        format!("mapping, {}", plural(n, "key", "keys"))
    } else {
        format!("sequence, {}", plural(n, "item", "items"))
    };
    let mut node = Node::new(name).span(whole.span()).summary(summary);
    if whole.last() != Some(if mapping { b'}' } else { b']' }) {
        node = node.diag(Diagnostic::malformed("flow collection not closed"));
    }
    if n > 0 {
        node = node.lazy(crate::expander!(self::flow: Span), whole.span());
    }
    Ok(node)
}

async fn flow(cx: Cx, span: Span) -> Result<()> {
    let owned = Scanner::new(&cx, span).owned(0, span.len, 1 << 20).await?;
    let p = owned.piece();
    let mapping = p.first() == Some(b'{');
    let inner = p.slice(1, p.len().saturating_sub(1));
    for (i, (a, b)) in flow_items(inner.bytes()).into_iter().enumerate() {
        cx.checkpoint().await;
        let item = inner.slice(a, b).trim();
        let (name, value) = match key_colon(&item) {
            Some(c) if mapping || item.find(b'{').is_none() => {
                (key_text(item.to(c)), item.from(c.saturating_add(1)).trim())
            }
            _ => (format!("[{i}]"), item),
        };
        let node = match value.first() {
            Some(b'[' | b'{') => flow_node(&cx, name, value.span()).await?,
            Some(b'"') => text_node(name, value.span(), &double_quoted(&value.unquote().text())),
            Some(b'\'') => text_node(
                name,
                value.span(),
                &value.unquote().text().replace("''", "'"),
            ),
            _ => match plain_value(&value.text()) {
                Some(Value::Text(t)) => text_node(name, value.span(), &t),
                Some(v) => Node::new(name).span(value.span()).value(v),
                None => Node::new(name).span(value.span()).summary("null"),
            },
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Documents

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    document(cx, input, "YAML document", None).await
}

/// Extra detail for an annotation, scraped from the head.
type Detail = fn(&[u8]) -> Option<String>;

/// Top-level keys (`key:` at column 0) in a probe's head.
fn top_keys(head: &[u8]) -> impl Iterator<Item = &[u8]> {
    probe::lines(head).filter_map(|l| {
        let colon = l.iter().position(|&b| b == b':')?;
        let key = l.get(..colon)?;
        (!key.is_empty()
            && key
                .iter()
                .all(|&b| b.is_ascii_alphanumeric() || b == b'_' || b == b'-'))
        .then_some(key)
    })
}

/// A YAML vocabulary: a YAML document with all of `keys` at the top level.
fn has_top_keys(h: &Head<'_>, keys: &[&[u8]]) -> bool {
    let head = probe::head(h);
    probe_yaml(h) && keys.iter().all(|k| top_keys(&head).any(|t| t == *k))
}

/// The value of the first `key:` line (at any indentation) in the head.
fn scrape(head: &[u8], key: &[u8]) -> Option<String> {
    probe::lines(head).find_map(|l| {
        let t = probe::trim_start(l);
        let t = t.strip_prefix(b"- ").unwrap_or(t);
        let rest = t.strip_prefix(key)?.strip_prefix(b":")?;
        let v = probe::trim(rest);
        let v = v
            .strip_prefix(b"\"")
            .and_then(|v| v.strip_suffix(b"\""))
            .unwrap_or(v);
        (!v.is_empty()).then(|| decode_8bit(v))
    })
}

macro_rules! yaml_variant {
    ($id:ident, $f:ident, $name:literal, $title:literal, [$($ext:literal),*], [$($key:literal),*], $detail:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: "application/yaml",
            probe: Probe::Custom(|h| has_top_keys(h, &[$($key.as_slice()),*])),
            dissect: crate::expander!($f: Input),
        };
        async fn $f(cx: Cx, input: Input) -> Result<()> {
            document(cx, input, $title, Some($detail)).await
        }
    };
}

yaml_variant!(
    KUBERNETES,
    dissect_k8s,
    "kubernetes",
    "Kubernetes manifest",
    [],
    [b"apiVersion", b"kind"],
    |h: &[u8]| match (scrape(h, b"kind"), scrape(h, b"name")) {
        (Some(k), Some(n)) => Some(format!("{k} {n}")),
        (k, _) => k,
    }
);
yaml_variant!(
    COMPOSE,
    dissect_compose,
    "docker-compose",
    "Docker Compose file",
    ["compose.yaml", "docker-compose.yml"],
    [b"services"],
    |h: &[u8]| scrape(h, b"image").map(|i| format!("first image {i}"))
);
yaml_variant!(
    GITHUB_WORKFLOW,
    dissect_workflow,
    "github-workflow",
    "GitHub Actions workflow",
    [],
    [b"on", b"jobs"],
    |h: &[u8]| scrape(h, b"name")
);
yaml_variant!(
    OPENAPI,
    dissect_openapi,
    "openapi-yaml",
    "OpenAPI description (YAML)",
    [],
    [b"info", b"paths"],
    |h: &[u8]| scrape(h, b"title")
);

async fn document(cx: Cx, input: Input, title: &str, detail: Option<Detail>) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let head = cx.read_avail(span.sub(0, 16 * 1024)).await?;
    let title = match detail.and_then(|d| d(&head)) {
        Some(d) => format!("{title}: {d}"),
        None => title.to_owned(),
    };
    cx.annotate(format!("{title}{}", prepared.note()));
    let mut lines = Lines::new(&cx, span);
    // Directives and the first marker.
    let mut start = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.piece().trim();
        if t.starts_with(b"%") {
            cx.push(text_node("Directive", line.span, &t.text())).await;
            start = line.next;
            continue;
        }
        if t.is_empty() || t.first() == Some(b'#') {
            continue;
        }
        if line.bytes.starts_with(b"---") && is_marker(&line.bytes) {
            start = line.next;
        }
        break;
    }
    let first = Block {
        span: span.tail(start),
        col: 0,
    };
    let stop = start.saturating_add(block_entries(&cx, &first).await?);
    // Further documents.
    let mut lines = Lines::new(&cx, span);
    lines.seek(stop, 0);
    let mut number = 1u64;
    let mut doc: Option<u64> = None;
    loop {
        let before = lines.pos();
        let line = lines.next().await?;
        let marker = line.as_ref().is_some_and(|l| is_marker(&l.bytes));
        if line.is_some() && !marker {
            continue;
        }
        if let Some(begin) = doc.take() {
            let body = span.sub(begin, before.saturating_sub(begin));
            if !is_blank(&cx, body).await? {
                number = number.saturating_add(1);
                cx.push(
                    Node::new(format!("Document {number}"))
                        .span(body)
                        .lazy(expand_block, Block { span: body, col: 0 }),
                )
                .await;
            }
        }
        let Some(l) = line else {
            break;
        };
        if l.bytes.starts_with(b"---") {
            doc = Some(l.next);
        }
    }
    if number > 1 {
        cx.annotate(format!(
            "{title}{}, {}",
            prepared.note(),
            plural(number, "document", "documents")
        ));
    }
    Ok(())
}
