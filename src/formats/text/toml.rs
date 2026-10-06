//! TOML: tables (`[a.b]`, `[[array]]`), dotted keys and typed values
//! (strings in all four forms, integers in any radix, floats, booleans,
//! date-times, arrays and inline tables).
//!
//! Table headers are found by a line scanner that tracks multi-line strings
//! and brackets, so the top level lists tables without parsing values;
//! a table's entries are parsed when it is expanded.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::scan::{Lines, Scanner};
use super::{parse_datetime, plural, probe, text_node};

pub static FORMAT: Format = Format {
    name: "toml",
    title: "TOML document",
    extensions: &["toml", "lock"],
    mime: "application/toml",
    probe: Probe::Custom(probe_toml),
    dissect: crate::expander!(dissect: Input),
};

fn is_bare(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'-'
}

/// Whether `key` is a TOML key (bare, quoted or dotted).
fn valid_key(key: &[u8]) -> bool {
    let key = probe::trim(key);
    !key.is_empty()
        && key.split(|&b| b == b'.').all(|part| {
            let part = probe::trim(part);
            (!part.is_empty() && part.iter().all(|&b| is_bare(b)))
                || (part.len() >= 2
                    && (part.starts_with(b"\"") && part.ends_with(b"\"")
                        || part.starts_with(b"'") && part.ends_with(b"'")))
        })
}

/// Whether `value` starts like a TOML value.
fn valid_value(value: &[u8]) -> bool {
    let v = probe::trim(value);
    match v.first() {
        Some(b'"' | b'\'' | b'[' | b'{' | b'+' | b'-' | b'0'..=b'9') => true,
        _ => {
            v.starts_with(b"true")
                || v.starts_with(b"false")
                || v.starts_with(b"inf")
                || v.starts_with(b"nan")
        }
    }
}

fn probe_toml(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut entries = 0usize;
    let mut headers = 0usize;
    let mut strings = 0usize;
    let mut other = 0usize;
    for (n, line) in probe::significant(&head, &[b"#"]).take(60).enumerate() {
        let t = probe::trim(line);
        if t.starts_with(b"[") {
            let inner = t.trim_ascii_start();
            let body = inner
                .strip_prefix(b"[[")
                .and_then(|b| b.split(|&c| c == b']').next())
                .or_else(|| inner.strip_prefix(b"[").and_then(|b| b.split(|&c| c == b']').next()));
            if body.is_some_and(valid_key) {
                headers = headers.saturating_add(1);
                continue;
            }
        }
        match t.iter().position(|&b| b == b'=') {
            Some(eq) if valid_key(t.get(..eq).unwrap_or_default()) => {
                let value = t.get(eq.saturating_add(1)..).unwrap_or_default();
                if !valid_value(value) {
                    return false;
                }
                if matches!(probe::trim(value).first(), Some(b'"' | b'\'')) {
                    strings = strings.saturating_add(1);
                }
                entries = entries.saturating_add(1);
            }
            // The first line must be a header or an entry.
            _ if n == 0 => return false,
            // Continuation lines of multi-line values.
            _ => other = other.saturating_add(1),
        }
    }
    entries >= 1
        && (headers >= 1 || entries >= 2)
        && (strings >= 1 || headers >= 1)
        && other <= entries.saturating_add(headers).saturating_mul(4)
        && probe::is_text(h)
}

// ---------------------------------------------------------------------------
// Finding table headers

/// Tracks multi-line strings and bracket depth across lines.
#[derive(Default)]
struct Tracker {
    depth: u32,
    /// Inside `"""` or `'''`.
    multiline: Option<&'static [u8]>,
}

impl Tracker {
    /// Updates the state for `line`; returns whether it is a table header.
    fn line(&mut self, line: &[u8]) -> bool {
        let t = probe::trim(line);
        if self.depth == 0 && self.multiline.is_none() && t.starts_with(b"[") {
            return true;
        }
        let start = if self.depth == 0 && self.multiline.is_none() {
            // `key = value`: the key may hold quotes; scan the value.
            match key_end(line) {
                Some(eq) => eq.saturating_add(1),
                None => return false,
            }
        } else {
            0
        };
        self.scan(line.get(start..).unwrap_or_default());
        false
    }

    fn scan(&mut self, s: &[u8]) {
        let mut i = 0usize;
        while i < s.len() {
            let rest = s.get(i..).unwrap_or_default();
            if let Some(close) = self.multiline {
                match probe::find(rest, close) {
                    Some(n) => {
                        self.multiline = None;
                        i = i.saturating_add(n).saturating_add(3);
                        continue;
                    }
                    None => return,
                }
            }
            match rest.first().copied().unwrap_or(0) {
                b'#' => return,
                b'[' | b'{' => self.depth = self.depth.saturating_add(1),
                b']' | b'}' => self.depth = self.depth.saturating_sub(1),
                q @ (b'"' | b'\'') => {
                    let triple: &'static [u8] = if q == b'"' { b"\"\"\"" } else { b"'''" };
                    if rest.starts_with(triple) {
                        self.multiline = Some(triple);
                        i = i.saturating_add(3);
                        continue;
                    }
                    i = i.saturating_add(string_len(rest));
                    continue;
                }
                _ => {}
            }
            i = i.saturating_add(1);
        }
    }
}

/// Length of the single-line string at the start of `s`.
fn string_len(s: &[u8]) -> usize {
    let q = s.first().copied().unwrap_or(b'"');
    let mut i = 1usize;
    while let Some(&b) = s.get(i) {
        i = i.saturating_add(1);
        if b == b'\\' && q == b'"' {
            i = i.saturating_add(1);
        } else if b == q {
            break;
        }
    }
    i.min(s.len())
}

/// Position of the `=` after a key (quotes in keys are skipped).
fn key_end(line: &[u8]) -> Option<usize> {
    let mut i = 0usize;
    while let Some(&b) = line.get(i) {
        match b {
            b'=' => return Some(i),
            b'"' | b'\'' => i = i.saturating_add(string_len(line.get(i..).unwrap_or_default())),
            b'#' => return None,
            _ => i = i.saturating_add(1),
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Values

/// A parsed value: its kind and byte range.
#[derive(Clone, Debug)]
enum Val {
    Str(String),
    Int(i64),
    Float(f64),
    Bool(bool),
    DateTime(String),
    Array(u64),
    Table(u64),
    Invalid(String),
}

/// Deeper nesting is reported, not parsed.
const MAX_DEPTH: u32 = 64;

/// An in-memory parser over `s`.
struct Parser<'a> {
    s: &'a [u8],
    i: usize,
}

impl<'a> Parser<'a> {
    fn peek(&self) -> Option<u8> {
        self.s.get(self.i).copied()
    }

    fn at(&self, text: &[u8]) -> bool {
        self.s.get(self.i..).is_some_and(|r| r.starts_with(text))
    }

    fn bump(&mut self, n: usize) {
        self.i = self.i.saturating_add(n).min(self.s.len());
    }

    /// Spaces and tabs.
    fn ws(&mut self) {
        while matches!(self.peek(), Some(b' ' | b'\t')) {
            self.bump(1);
        }
    }

    /// Whitespace, newlines and comments (inside arrays, between entries).
    fn blank(&mut self) {
        loop {
            match self.peek() {
                Some(b' ' | b'\t' | b'\r' | b'\n') => self.bump(1),
                Some(b'#') => self.line_end(),
                _ => return,
            }
        }
    }

    /// Skips to the start of the next line.
    fn line_end(&mut self) {
        while let Some(b) = self.peek() {
            self.bump(1);
            if b == b'\n' {
                return;
            }
        }
    }

    fn key(&mut self) -> Option<(String, usize, usize)> {
        let start = self.i;
        let mut parts = Vec::new();
        loop {
            self.ws();
            match self.peek()? {
                q @ (b'"' | b'\'') => {
                    let len = string_len(self.s.get(self.i..).unwrap_or_default());
                    let raw = self.s.get(self.i.saturating_add(1)..self.i.saturating_add(len).saturating_sub(1))?;
                    parts.push(if q == b'"' { unescape(raw) } else { super::encoding::decode_8bit(raw) });
                    self.bump(len);
                }
                b if is_bare(b) => {
                    let n = self.s.get(self.i..)?.iter().take_while(|&&b| is_bare(b)).count();
                    parts.push(String::from_utf8_lossy(self.s.get(self.i..self.i.saturating_add(n))?).into_owned());
                    self.bump(n);
                }
                _ => return None,
            }
            self.ws();
            if self.peek() != Some(b'.') {
                break;
            }
            self.bump(1);
        }
        Some((parts.join("."), start, self.i))
    }

    fn value(&mut self, depth: u32) -> (Val, usize, usize) {
        let start = self.i;
        let val = self.value_inner(depth);
        (val, start, self.i)
    }

    fn value_inner(&mut self, depth: u32) -> Val {
        if depth > MAX_DEPTH {
            self.line_end();
            return Val::Invalid("nested too deeply".to_owned());
        }
        match self.peek() {
            Some(b'"') if self.at(b"\"\"\"") => self.multiline(b"\"\"\"", true),
            Some(b'\'') if self.at(b"'''") => self.multiline(b"'''", false),
            Some(q @ (b'"' | b'\'')) => {
                let len = string_len(self.s.get(self.i..).unwrap_or_default());
                let raw = self
                    .s
                    .get(self.i.saturating_add(1)..self.i.saturating_add(len).saturating_sub(1))
                    .unwrap_or_default();
                self.bump(len.max(1));
                Val::Str(if q == b'"' { unescape(raw) } else { super::encoding::decode_8bit(raw) })
            }
            Some(b'[') => {
                self.bump(1);
                let mut n = 0u64;
                loop {
                    self.blank();
                    match self.peek() {
                        None => return Val::Invalid("array not closed".to_owned()),
                        Some(b']') => {
                            self.bump(1);
                            return Val::Array(n);
                        }
                        Some(b',') => self.bump(1),
                        _ => {
                            let before = self.i;
                            self.value(depth.saturating_add(1));
                            n = n.saturating_add(1);
                            if self.i == before {
                                self.bump(1);
                            }
                        }
                    }
                }
            }
            Some(b'{') => {
                self.bump(1);
                let mut n = 0u64;
                loop {
                    self.ws();
                    match self.peek() {
                        None | Some(b'\n') => {
                            return Val::Invalid("inline table not closed".to_owned());
                        }
                        Some(b'}') => {
                            self.bump(1);
                            return Val::Table(n);
                        }
                        Some(b',') => self.bump(1),
                        _ => {
                            let before = self.i;
                            if self.key().is_some() {
                                self.ws();
                                if self.peek() == Some(b'=') {
                                    self.bump(1);
                                    self.ws();
                                    self.value(depth.saturating_add(1));
                                }
                                n = n.saturating_add(1);
                            }
                            if self.i == before {
                                self.bump(1);
                            }
                        }
                    }
                }
            }
            _ => self.scalar(),
        }
    }

    fn multiline(&mut self, delim: &[u8], basic: bool) -> Val {
        self.bump(3);
        // A newline right after the opening delimiter is not content.
        if self.at(b"\r\n") {
            self.bump(2);
        } else if self.at(b"\n") {
            self.bump(1);
        }
        let rest = self.s.get(self.i..).unwrap_or_default();
        let end = probe::find(rest, delim).unwrap_or(rest.len());
        let raw = rest.get(..end).unwrap_or_default();
        self.bump(end.saturating_add(3));
        // Up to two extra quotes may close the string.
        while self.peek() == delim.first().copied() {
            self.bump(1);
        }
        if basic {
            Val::Str(unescape(raw))
        } else {
            Val::Str(super::encoding::decode_8bit(raw))
        }
    }

    fn scalar(&mut self) -> Val {
        let rest = self.s.get(self.i..).unwrap_or_default();
        let n = rest
            .iter()
            .take_while(|&&b| !matches!(b, b',' | b']' | b'}' | b'\n' | b'\r' | b'#'))
            .count();
        let raw = probe::trim(rest.get(..n).unwrap_or_default());
        self.bump(raw.len().max(1).min(n.max(1)));
        let text = String::from_utf8_lossy(raw).into_owned();
        scalar(&text)
    }
}

fn scalar(text: &str) -> Val {
    match text {
        "true" => return Val::Bool(true),
        "false" => return Val::Bool(false),
        "inf" | "+inf" => return Val::Float(f64::INFINITY),
        "-inf" => return Val::Float(f64::NEG_INFINITY),
        "nan" | "+nan" | "-nan" => return Val::Float(f64::NAN),
        _ => {}
    }
    let clean = text.replace('_', "");
    let radix = [("0x", 16), ("0o", 8), ("0b", 2)]
        .into_iter()
        .find_map(|(p, r)| clean.strip_prefix(p).map(|d| (d.to_owned(), r)));
    if let Some((digits, r)) = radix {
        return i64::from_str_radix(&digits, r)
            .map_or_else(|_| Val::Invalid(text.to_owned()), Val::Int);
    }
    if let Ok(v) = clean.parse::<i64>() {
        return Val::Int(v);
    }
    let looks_float = clean
        .bytes()
        .all(|b| b.is_ascii_digit() || matches!(b, b'.' | b'e' | b'E' | b'+' | b'-'));
    if looks_float && let Ok(v) = clean.parse::<f64>() {
        return Val::Float(v);
    }
    if text.bytes().next().is_some_and(|b| b.is_ascii_digit()) && (text.contains('-') || text.contains(':')) {
        return Val::DateTime(text.to_owned());
    }
    Val::Invalid(text.to_owned())
}

/// TOML basic-string escapes.
fn unescape(raw: &[u8]) -> String {
    let text = super::encoding::decode_8bit(raw);
    if !text.contains('\\') {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        match chars.next() {
            Some('n') => out.push('\n'),
            Some('t') => out.push('\t'),
            Some('r') => out.push('\r'),
            Some('b') => out.push('\u{8}'),
            Some('f') => out.push('\u{c}'),
            Some('e') => out.push('\u{1b}'),
            Some(u @ ('u' | 'U')) => {
                let n = if u == 'u' { 4 } else { 8 };
                let hex: String = (0..n).filter_map(|_| chars.next()).collect();
                out.push(
                    u32::from_str_radix(&hex, 16)
                        .ok()
                        .and_then(char::from_u32)
                        .unwrap_or(char::REPLACEMENT_CHARACTER),
                );
            }
            // Line-ending backslash: trim the newline and leading space.
            Some('\n' | '\r' | ' ' | '\t') => {
                while chars.peek().is_some_and(|c| c.is_whitespace()) {
                    chars.next();
                }
            }
            Some(other) => out.push(other),
            None => out.push('\\'),
        }
    }
    out
}

/// A node for a value parsed from `base`'s bytes.
fn value_node(name: String, val: Val, span: Span) -> Node {
    match val {
        Val::Str(s) => text_node(name, span, &s),
        Val::Int(v) => Node::new(name).span(span).value(Value::Int { value: v, bits: 64 }),
        Val::Float(v) => Node::new(name).span(span).value(Value::Float(v)),
        Val::Bool(v) => Node::new(name).span(span).value(Value::Bool(v)),
        Val::DateTime(text) => match parse_datetime(&text) {
            Some(t) if text.contains(['Z', 'z', '+']) || text.rfind('-').is_some_and(|i| i > 10) => {
                Node::new(name).span(span).value(Value::Timestamp { unix_seconds: t })
            }
            _ => text_node(name, span, &text).summary("local date/time"),
        },
        Val::Array(n) => {
            let node = Node::new(name)
                .span(span)
                .summary(format!("array, {}", plural(n, "element", "elements")));
            if n == 0 { node } else { node.lazy(array, span) }
        }
        Val::Table(n) => {
            let node = Node::new(name)
                .span(span)
                .summary(format!("inline table, {}", plural(n, "key", "keys")));
            if n == 0 { node } else { node.lazy(inline_table, span) }
        }
        Val::Invalid(text) => text_node(name, span, &text).diag(Diagnostic::malformed("invalid value")),
    }
}

/// The most of a table body read into memory at once.
const BODY_CAP: usize = 8 << 20;

async fn read(cx: &Cx, span: Span) -> Result<Vec<u8>> {
    let mut scan = Scanner::new(cx, span);
    scan.bytes(0, span.len, BODY_CAP).await
}

fn sub(span: Span, start: usize, end: usize) -> Span {
    span.sub(to_u64(start), to_u64(end.saturating_sub(start)))
}

/// The `key = value` entries of a table body.
async fn entries(cx: Cx, span: Span) -> Result<()> {
    let data = read(&cx, span).await?;
    if to_u64(data.len()) < span.len {
        cx.diag(Diagnostic::limit("table too large; only its start is shown"));
    }
    let mut p = Parser { s: &data, i: 0 };
    loop {
        cx.checkpoint().await;
        p.blank();
        if p.peek().is_none() {
            return Ok(());
        }
        let line_start = p.i;
        let Some((key, _, _)) = p.key() else {
            p.line_end();
            let text = String::from_utf8_lossy(data.get(line_start..p.i).unwrap_or_default()).into_owned();
            cx.push(
                text_node("Line", sub(span, line_start, p.i), text.trim())
                    .diag(Diagnostic::malformed("expected `key = value`")),
            )
            .await;
            continue;
        };
        p.ws();
        if p.peek() != Some(b'=') {
            p.line_end();
            cx.push(
                Node::new(key)
                    .span(sub(span, line_start, p.i))
                    .diag(Diagnostic::malformed("expected `=`")),
            )
            .await;
            continue;
        }
        p.bump(1);
        p.ws();
        let (val, a, b) = p.value(0);
        cx.push(value_node(key, val, sub(span, a, b))).await;
        p.ws();
        if p.peek() == Some(b'#') || matches!(p.peek(), Some(b'\r' | b'\n')) {
            p.line_end();
        } else if p.peek().is_some() {
            let junk = p.i;
            p.line_end();
            cx.diag(Diagnostic::malformed("unexpected text after a value").at(sub(span, junk, p.i)));
        }
    }
}

async fn array(cx: Cx, span: Span) -> Result<()> {
    let data = read(&cx, span).await?;
    let mut p = Parser { s: &data, i: 1 };
    let mut index = 0u64;
    loop {
        cx.checkpoint().await;
        p.blank();
        match p.peek() {
            None | Some(b']') => return Ok(()),
            Some(b',') => p.bump(1),
            _ => {
                let before = p.i;
                let (val, a, b) = p.value(0);
                cx.push(value_node(format!("[{index}]"), val, sub(span, a, b))).await;
                index = index.saturating_add(1);
                if p.i == before {
                    p.bump(1);
                }
            }
        }
    }
}

async fn inline_table(cx: Cx, span: Span) -> Result<()> {
    let data = read(&cx, span).await?;
    let mut p = Parser { s: &data, i: 1 };
    loop {
        cx.checkpoint().await;
        p.ws();
        match p.peek() {
            None | Some(b'}') => return Ok(()),
            Some(b',') => p.bump(1),
            _ => {
                let before = p.i;
                if let Some((key, _, _)) = p.key() {
                    p.ws();
                    if p.peek() == Some(b'=') {
                        p.bump(1);
                        p.ws();
                        let (val, a, b) = p.value(0);
                        cx.push(value_node(key, val, sub(span, a, b))).await;
                    }
                }
                if p.i == before {
                    p.bump(1);
                }
            }
        }
    }
}

// ---------------------------------------------------------------------------
// Documents

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let span = prepared.span;
    let head = cx.read_avail(span.sub(0, 16 * 1024)).await?;
    cx.annotate(annotation(&head));
    let mut lines = Lines::new(&cx, span);
    let mut tracker = Tracker::default();
    // (header start, header text, body start)
    let mut current: Option<(u64, String, u64)> = None;
    let mut root_end = None;
    loop {
        let before = lines.pos();
        let line = lines.next().await?;
        let header = match &line {
            Some(l) if tracker.line(&l.bytes) => Some(l),
            Some(_) => continue,
            None => None,
        };
        // Close what is open.
        match current.take() {
            Some((start, name, body)) => {
                push_table(&cx, span, start, &name, body, before).await;
            }
            None if root_end.is_none() => {
                root_end = Some(before);
                if before > 0 {
                    entries(cx.clone(), span.sub(0, before)).await?;
                }
            }
            None => {}
        }
        let Some(l) = header else {
            return Ok(());
        };
        let text = l.piece().trim();
        let text = match text.find(b'#') {
            Some(i) if !text.to(i).contains(b"\"") => text.to(i).trim(),
            _ => text,
        };
        current = Some((l.start, text.text(), l.next));
    }
}

async fn push_table(cx: &Cx, span: Span, start: u64, header: &str, body: u64, end: u64) {
    let table = span.sub(start, end.saturating_sub(start));
    let body_span = span.sub(body, end.saturating_sub(body));
    let n = count_entries(cx, body_span).await.unwrap_or(0);
    let mut node = Node::new(header.to_owned())
        .span(table)
        .summary(plural(n, "entry", "entries"));
    if n > 0 {
        node = node.lazy(entries, body_span);
    }
    cx.push(node).await;
}

/// Entries in a table body: lines that start a `key =` at depth zero.
async fn count_entries(cx: &Cx, span: Span) -> Result<u64> {
    let mut lines = Lines::new(cx, span);
    let mut tracker = Tracker::default();
    let mut n = 0u64;
    while let Some(line) = lines.next().await? {
        let top = tracker.depth == 0 && tracker.multiline.is_none();
        tracker.line(&line.bytes);
        if top && key_end(&line.bytes).is_some() {
            n = n.saturating_add(1);
        }
    }
    Ok(n)
}

fn annotation(head: &[u8]) -> String {
    let text = super::encoding::probe_text(head);
    let tables = probe::lines(&text)
        .filter(|l| probe::trim(l).starts_with(b"["))
        .count();
    let name = ["[package]", "[project]", "[tool.poetry]", "[workspace]"]
        .iter()
        .find_map(|section| {
            let at = probe::find(&text, section.as_bytes())?;
            let rest = text.get(at..)?;
            probe::lines(rest).skip(1).take(20).find_map(|l| {
                let l = probe::trim(l);
                let v = l.strip_prefix(b"name")?;
                let v = probe::trim(probe::trim(v).strip_prefix(b"=")?);
                let v = v.strip_prefix(b"\"")?;
                let end = v.iter().position(|&b| b == b'"')?;
                Some(format!("{} {}", section, String::from_utf8_lossy(v.get(..end)?)))
            })
        });
    let mut out = String::from("TOML document");
    if let Some(n) = name {
        out = format!("{out}: {}", preview(&n, 60));
    }
    if tables > 0 {
        let complete = to_usize(to_u64(head.len())) < 16 * 1024;
        let count = to_u64(tables);
        out = if complete {
            format!("{out}, {}", plural(count, "table", "tables"))
        } else {
            format!("{out}, {}+ tables", count)
        };
    }
    out
}
