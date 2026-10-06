//! JSON, JSON Lines, and formats built on JSON (Jupyter notebooks, GeoJSON,
//! HTTP archives).
//!
//! A tolerant streaming tokenizer reads the text in windows. Objects and
//! arrays are lazy nodes: expanding one walks only its own members, skipping
//! over nested containers (which become lazy nodes in turn), and pushes them
//! as a paged collection. Keys become node names; scalars become typed
//! values. Comments, unquoted keys, missing commas and truncation are
//! tolerated and reported as diagnostics.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::probe;
use super::scan::{Lines, Scanner};
use super::{VALUE_CAP, plural, text_node};

pub static FORMAT: Format = Format {
    name: "json",
    title: "JSON",
    extensions: &["json", "jsonc", "json5", "webmanifest", "babelrc", "eslintrc"],
    mime: "application/json",
    probe: Probe::Custom(probe_json),
    dissect: crate::expander!(dissect: Input),
};

pub static NDJSON: Format = Format {
    name: "ndjson",
    title: "JSON Lines",
    extensions: &["jsonl", "ndjson", "ldjson"],
    mime: "application/x-ndjson",
    probe: Probe::Custom(probe_ndjson),
    dissect: crate::expander!(dissect_lines: Input),
};

pub static IPYNB: Format = Format {
    name: "ipynb",
    title: "Jupyter notebook",
    extensions: &["ipynb"],
    mime: "application/x-ipynb+json",
    probe: Probe::Custom(|h| {
        probe_json(h)
            && (probe::contains(&probe::head(h), b"\"cell_type\"")
                || probe::contains(h.tail, b"\"nbformat\""))
    }),
    dissect: crate::expander!(dissect_notebook: Input),
};

pub static GEOJSON: Format = Format {
    name: "geojson",
    title: "GeoJSON",
    extensions: &["geojson"],
    mime: "application/geo+json",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        let start = head.get(..head.len().min(4096)).unwrap_or_default();
        probe_json(h)
            && probe::contains(start, b"\"type\"")
            && (probe::contains(start, b"\"FeatureCollection\"")
                || (probe::contains(start, b"\"Feature\"")
                    && probe::contains(start, b"\"geometry\"")))
    }),
    dissect: crate::expander!(dissect_geojson: Input),
};

pub static HAR: Format = Format {
    name: "har",
    title: "HTTP Archive",
    extensions: &["har"],
    mime: "application/json",
    probe: Probe::Custom(|h| {
        let head = probe::head(h);
        let start = head.get(..head.len().min(1024)).unwrap_or_default();
        probe_json(h)
            && probe::contains(start, b"\"log\"")
            && probe::contains(start, b"\"creator\"")
    }),
    dissect: crate::expander!(dissect_har: Input),
};

// ---------------------------------------------------------------------------
// Probes: a synchronous mini-lexer over the head.

/// Checks that `data` starts with up to `max` well-formed JSON tokens with
/// balanced nesting. Returns the depth reached and the bytes consumed, or
/// `None` on an invalid token.
fn probe_tokens(data: &[u8], max: usize) -> Option<(u32, usize)> {
    let mut i = 0usize;
    let mut depth = 0u32;
    let mut prev = 0u8;
    for _ in 0..max {
        while data.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        let Some(&b) = data.get(i) else {
            return Some((depth, i));
        };
        match b {
            b'{' | b'[' => {
                depth = depth.saturating_add(1);
                i = i.saturating_add(1);
            }
            b'}' | b']' => {
                depth = depth.checked_sub(1)?;
                i = i.saturating_add(1);
                if depth == 0 {
                    return Some((0, i));
                }
            }
            b':' | b',' => i = i.saturating_add(1),
            b'"' => {
                let mut j = i.saturating_add(1);
                loop {
                    match data.get(j) {
                        None => return Some((depth, j)),
                        Some(b'"') => break,
                        Some(b'\\') => j = j.saturating_add(2),
                        Some(b'\n') => return None,
                        Some(_) => j = j.saturating_add(1),
                    }
                }
                i = j.saturating_add(1);
            }
            b'/' if matches!(data.get(i.saturating_add(1)), Some(b'/' | b'*')) => {
                let rest = data.get(i..).unwrap_or_default();
                let skip = if rest.starts_with(b"//") {
                    rest.iter().position(|&c| c == b'\n')
                } else {
                    probe::find(rest, b"*/").map(|n| n.saturating_add(2))
                };
                match skip {
                    Some(n) => i = i.saturating_add(n),
                    None => return Some((depth, data.len())),
                }
                continue;
            }
            b'-' | b'0'..=b'9' => {
                let n = data
                    .get(i..)
                    .unwrap_or_default()
                    .iter()
                    .take_while(|c| c.is_ascii_digit() || matches!(c, b'-' | b'+' | b'.' | b'e' | b'E'))
                    .count();
                i = i.saturating_add(n);
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' => {
                let rest = data.get(i..).unwrap_or_default();
                let n = rest
                    .iter()
                    .take_while(|c| c.is_ascii_alphanumeric() || matches!(c, b'_' | b'$'))
                    .count();
                let word = rest.get(..n).unwrap_or_default();
                // Literals, or an unquoted (JSON5-style) key.
                let key = || {
                    probe::trim_start(rest.get(n..).unwrap_or_default()).starts_with(b":")
                };
                if !matches!(word, b"true" | b"false" | b"null") && !(prev != b'[' && key()) {
                    return None;
                }
                i = i.saturating_add(n);
            }
            _ => return None,
        }
        // An object must start with a key or end.
        if prev == b'{' && !(matches!(b, b'"' | b'}' | b'/' | b'_' | b'$') || b.is_ascii_alphabetic()) {
            return None;
        }
        prev = b;
    }
    Some((depth, i))
}

/// `data` after leading whitespace and comments.
fn skip_space(mut data: &[u8]) -> &[u8] {
    loop {
        data = probe::trim_start(data);
        let skip = if data.starts_with(b"//") {
            data.iter().position(|&c| c == b'\n')
        } else if data.starts_with(b"/*") {
            probe::find(data, b"*/").map(|n| n.saturating_add(2))
        } else {
            return data;
        };
        data = data.get(skip.unwrap_or(data.len())..).unwrap_or_default();
    }
}

fn probe_json(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let data = skip_space(&head);
    matches!(data.first(), Some(b'{' | b'[')) && probe_tokens(data, 256).is_some()
}

fn probe_ndjson(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let mut lines = probe::significant(&head, &[]);
    let complete = |line: &[u8]| {
        let line = probe::trim(line);
        matches!(line.first(), Some(b'{' | b'['))
            && probe_tokens(line, usize::MAX).is_some_and(|(depth, used)| {
                depth == 0 && probe::trim_start(line.get(used..).unwrap_or_default()).is_empty()
            })
    };
    let (Some(first), Some(second)) = (lines.next(), lines.next()) else {
        return false;
    };
    complete(first) && matches!(probe::trim_start(second).first(), Some(b'{' | b'['))
}

// ---------------------------------------------------------------------------
// Tokenizer

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    ObjOpen,
    ObjClose,
    ArrOpen,
    ArrClose,
    Colon,
    Comma,
    Str,
    /// A string that ends at a line break or the end of the input.
    BadStr,
    Num,
    True,
    False,
    Null,
    Invalid,
    Eof,
}

#[derive(Clone, Copy, Debug)]
struct Token {
    kind: Kind,
    start: u64,
    end: u64,
}

struct Lexer<'a> {
    scan: Scanner<'a>,
    pos: u64,
}

impl<'a> Lexer<'a> {
    fn new(cx: &'a Cx, region: Span) -> Self {
        Lexer {
            scan: Scanner::new(cx, region),
            pos: 0,
        }
    }

    fn span(&self, t: &Token) -> Span {
        self.scan.span(t.start, t.end)
    }

    async fn skip_space(&mut self) -> Result<()> {
        loop {
            let Some(at) = self
                .scan
                .find(self.pos, |b| !b.is_ascii_whitespace())
                .await?
            else {
                self.pos = self.scan.len();
                return Ok(());
            };
            self.pos = at;
            if self.scan.byte(at).await? != Some(b'/') {
                return Ok(());
            }
            let after = at.saturating_add(1);
            self.pos = match self.scan.byte(after).await? {
                Some(b'/') => self
                    .scan
                    .find(after, |b| b == b'\n')
                    .await?
                    .unwrap_or(self.scan.len()),
                Some(b'*') => self
                    .scan
                    .find_seq(after.saturating_add(1), b"*/")
                    .await?
                    .map_or(self.scan.len(), |e| e.saturating_add(2)),
                _ => return Ok(()),
            };
        }
    }

    async fn next(&mut self) -> Result<Token> {
        self.skip_space().await?;
        let start = self.pos;
        let Some(b) = self.scan.byte(start).await? else {
            return Ok(Token {
                kind: Kind::Eof,
                start,
                end: start,
            });
        };
        let one = start.saturating_add(1);
        let (kind, end) = match b {
            b'{' => (Kind::ObjOpen, one),
            b'}' => (Kind::ObjClose, one),
            b'[' => (Kind::ArrOpen, one),
            b']' => (Kind::ArrClose, one),
            b':' => (Kind::Colon, one),
            b',' => (Kind::Comma, one),
            b'"' => self.string(start).await?,
            b'-' | b'+' | b'.' | b'0'..=b'9' => {
                let end = self
                    .scan
                    .find(start, |c| {
                        !(c.is_ascii_alphanumeric() || matches!(c, b'-' | b'+' | b'.'))
                    })
                    .await?
                    .unwrap_or(self.scan.len());
                (Kind::Num, end)
            }
            b'a'..=b'z' | b'A'..=b'Z' | b'_' | b'$' => {
                let end = self
                    .scan
                    .find(start, |c| !(c.is_ascii_alphanumeric() || c == b'_' || c == b'$'))
                    .await?
                    .unwrap_or(self.scan.len());
                let word = self.scan.bytes(start, end, 16).await?;
                let kind = match word.as_slice() {
                    b"true" => Kind::True,
                    b"false" => Kind::False,
                    b"null" => Kind::Null,
                    b"NaN" | b"Infinity" => Kind::Num,
                    _ => Kind::Invalid,
                };
                (kind, end)
            }
            _ => (Kind::Invalid, one),
        };
        self.pos = end.max(one);
        Ok(Token { kind, start, end })
    }

    /// A string starting at the quote at `start`; returns its kind and end.
    async fn string(&mut self, start: u64) -> Result<(Kind, u64)> {
        let mut p = start.saturating_add(1);
        loop {
            let Some(i) = self
                .scan
                .find(p, |b| b == b'"' || b == b'\\' || b == b'\n')
                .await?
            else {
                return Ok((Kind::BadStr, self.scan.len()));
            };
            match self.scan.byte(i).await? {
                Some(b'"') => return Ok((Kind::Str, i.saturating_add(1))),
                Some(b'\\') => p = i.saturating_add(2),
                _ => return Ok((Kind::BadStr, i)),
            }
        }
    }

    /// The decoded text of a string token (capped).
    async fn text(&mut self, t: &Token) -> Result<(String, bool)> {
        let inner_start = t.start.saturating_add(1);
        let inner_end = if t.kind == Kind::Str {
            t.end.saturating_sub(1)
        } else {
            t.end
        };
        let cap = VALUE_CAP.saturating_mul(4);
        let raw = self.scan.bytes(inner_start, inner_end, cap).await?;
        let cut = to_u64(raw.len()) < inner_end.saturating_sub(inner_start);
        Ok((unescape(&raw), cut))
    }

    /// The raw text of a token (capped).
    async fn raw(&mut self, t: &Token) -> Result<String> {
        let raw = self.scan.bytes(t.start, t.end, 256).await?;
        Ok(String::from_utf8_lossy(&raw).into_owned())
    }

    /// Skips the rest of a container whose opening token was just read.
    /// Returns its end, how many members it has, and whether it was closed.
    async fn skip_container(&mut self, open: &Token) -> Result<(u64, u64, bool)> {
        let object = open.kind == Kind::ObjOpen;
        let mut depth = 1u32;
        let mut members = 0u64;
        loop {
            self.scan.tick().await;
            let t = self.next().await?;
            let top = depth == 1;
            match t.kind {
                Kind::Eof => return Ok((t.start, members, false)),
                Kind::ObjOpen | Kind::ArrOpen => {
                    if top && !object {
                        members = members.saturating_add(1);
                    }
                    depth = depth.saturating_add(1);
                }
                Kind::ObjClose | Kind::ArrClose => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok((t.end, members, true));
                    }
                }
                Kind::Colon if top && object => members = members.saturating_add(1),
                Kind::Colon | Kind::Comma => {}
                _ if top && !object => members = members.saturating_add(1),
                _ => {}
            }
        }
    }
}

/// Decodes JSON string escapes.
fn unescape(raw: &[u8]) -> String {
    let text = super::encoding::decode_8bit(raw);
    if !text.contains('\\') {
        return text;
    }
    let mut out = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();
    let mut pending_high: Option<u32> = None;
    while let Some(c) = chars.next() {
        if c != '\\' {
            out.push(c);
            continue;
        }
        let Some(e) = chars.next() else {
            out.push('\\');
            break;
        };
        let decoded = match e {
            'n' => '\n',
            't' => '\t',
            'r' => '\r',
            'b' => '\u{8}',
            'f' => '\u{c}',
            'u' => {
                let hex: String = (0..4).filter_map(|_| chars.next()).collect();
                let Ok(unit) = u32::from_str_radix(&hex, 16) else {
                    out.push(char::REPLACEMENT_CHARACTER);
                    continue;
                };
                if (0xd800..0xdc00).contains(&unit) {
                    pending_high = Some(unit);
                    continue;
                }
                let code = match pending_high.take() {
                    Some(high) if (0xdc00..0xe000).contains(&unit) => 0x10000u32
                        .saturating_add((high.saturating_sub(0xd800)) << 10)
                        .saturating_add(unit.saturating_sub(0xdc00)),
                    _ => unit,
                };
                char::from_u32(code).unwrap_or(char::REPLACEMENT_CHARACTER)
            }
            other => other,
        };
        out.push(decoded);
    }
    out
}

/// A number's value: an integer if it is one, else a float.
fn number(text: &str) -> Option<Value> {
    if let Ok(v) = text.parse::<i64>() {
        return Some(Value::Int { value: v, bits: 64 });
    }
    if let Ok(v) = text.parse::<u64>() {
        return Some(Value::UInt {
            value: v,
            bits: 64,
            radix: crate::value::Radix::Dec,
        });
    }
    match text {
        "NaN" => Some(Value::Float(f64::NAN)),
        "Infinity" | "+Infinity" => Some(Value::Float(f64::INFINITY)),
        "-Infinity" => Some(Value::Float(f64::NEG_INFINITY)),
        _ => text.parse::<f64>().ok().map(Value::Float),
    }
}

// ---------------------------------------------------------------------------
// Values and containers

/// Which JSON-based format a container belongs to, for richer summaries.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Flavor {
    Plain,
    Notebook,
    NotebookCells,
    GeoJson,
    GeoFeatures,
    Har,
    HarLog,
    HarEntries,
}

impl Flavor {
    fn child(self, key: &str) -> Flavor {
        match (self, key) {
            (Flavor::Notebook, "cells") => Flavor::NotebookCells,
            (Flavor::GeoJson, "features") => Flavor::GeoFeatures,
            (Flavor::Har, "log") => Flavor::HarLog,
            (Flavor::HarLog, "entries") => Flavor::HarEntries,
            _ => Flavor::Plain,
        }
    }
}

/// A parsed value.
enum Item {
    Str(String, bool),
    BadStr(String),
    Num(Option<Value>, String),
    Bool(bool),
    Null,
    Container {
        object: bool,
        members: u64,
        closed: bool,
    },
    Invalid(String),
}

/// Parses the value starting with token `t`, skipping nested content.
/// Returns the value and its span.
async fn parse_value(lex: &mut Lexer<'_>, t: Token) -> Result<(Item, Span)> {
    let item = match t.kind {
        Kind::Str => {
            let (text, cut) = lex.text(&t).await?;
            Item::Str(text, cut)
        }
        Kind::BadStr => Item::BadStr(lex.text(&t).await?.0),
        Kind::Num => {
            let raw = lex.raw(&t).await?;
            Item::Num(number(&raw), raw)
        }
        Kind::True => Item::Bool(true),
        Kind::False => Item::Bool(false),
        Kind::Null => Item::Null,
        Kind::ObjOpen | Kind::ArrOpen => {
            let (end, members, closed) = lex.skip_container(&t).await?;
            let span = lex.scan.span(t.start, end);
            return Ok((
                Item::Container {
                    object: t.kind == Kind::ObjOpen,
                    members,
                    closed,
                },
                span,
            ));
        }
        _ => Item::Invalid(lex.raw(&t).await?),
    };
    Ok((item, lex.span(&t)))
}

#[derive(Clone, Debug)]
struct Walk {
    input: Input,
    /// Starts at the opening bracket; may extend past the closing one.
    span: Span,
    flavor: Flavor,
}

fn item_node(name: String, item: Item, span: Span, walk: &Walk) -> Node {
    match item {
        Item::Str(text, false) => text_node(name, span, &text),
        Item::Str(text, true) => text_node(name, span, &text)
            .summary(format!("{:#x} bytes, truncated", span.len)),
        Item::BadStr(text) => text_node(name, span, &text)
            .diag(Diagnostic::malformed("unterminated string").at(span)),
        Item::Num(Some(v), _) => Node::new(name).span(span).value(v),
        Item::Num(None, raw) => Node::new(name)
            .span(span)
            .value(Value::Text(raw))
            .diag(Diagnostic::malformed("invalid number")),
        Item::Bool(b) => Node::new(name).span(span).value(Value::Bool(b)),
        Item::Null => Node::new(name).span(span).summary("null"),
        Item::Container {
            object,
            members,
            closed,
        } => {
            let mut summary = if object {
                format!("object, {}", plural(members, "member", "members"))
            } else {
                format!("array, {}", plural(members, "element", "elements"))
            };
            if !closed {
                // The expansion reports where the input ends.
                summary.push_str(", unclosed");
            }
            let flavor = walk.flavor.child(&name);
            if members == 0 && closed {
                return Node::new(name).span(span).summary(summary);
            }
            Node::new(name).span(span).summary(summary).lazy(
                crate::expander!(self::walk: Walk),
                Walk {
                    input: walk.input,
                    span,
                    flavor,
                },
            )
        }
        Item::Invalid(raw) => Node::new(name)
            .span(span)
            .value(Value::Text(raw))
            .diag(Diagnostic::malformed("not a JSON value")),
    }
}

async fn walk(cx: Cx, w: Walk) -> Result<()> {
    walk_members(&cx, &w).await.map(|_| ())
}

/// What walking a container found.
struct Walked {
    /// End of the container, relative to the walked span.
    end: u64,
    members: u64,
    /// Members of the flavored collection inside (cells, features), if any.
    collection: Option<u64>,
}

/// Pushes the members of the container at the start of `w.span`.
async fn walk_members(cx: &Cx, w: &Walk) -> Result<Walked> {
    let mut lex = Lexer::new(cx, w.span);
    let open = lex.next().await?;
    let object = match open.kind {
        Kind::ObjOpen => true,
        Kind::ArrOpen => false,
        _ => return Err(Diagnostic::malformed("expected an object or array").at(lex.span(&open))),
    };
    let mut walked = Walked {
        end: 0,
        members: 0,
        collection: None,
    };
    loop {
        let mut t = lex.next().await?;
        while t.kind == Kind::Comma {
            t = lex.next().await?;
        }
        if let Some(end) = closes(cx, &lex, &t, object) {
            walked.end = end;
            cx.set_count(Count::Exact(walked.members));
            return Ok(walked);
        }
        let (name, value) = if object {
            let key = match t.kind {
                Kind::Str | Kind::BadStr => lex.text(&t).await?.0,
                _ => {
                    cx.diag(Diagnostic::malformed("expected a quoted key").at(lex.span(&t)));
                    lex.raw(&t).await?
                }
            };
            let mut v = lex.next().await?;
            if v.kind == Kind::Colon {
                v = lex.next().await?;
            } else {
                cx.diag(Diagnostic::malformed("expected ':'").at(lex.span(&v)));
            }
            if let Some(end) = closes(cx, &lex, &v, object) {
                cx.push(
                    Node::new(key)
                        .span(lex.span(&t))
                        .diag(Diagnostic::malformed("member without a value")),
                )
                .await;
                walked.members = walked.members.saturating_add(1);
                walked.end = end;
                return Ok(walked);
            }
            (key, v)
        } else {
            (format!("[{}]", walked.members), t)
        };
        let (item, span) = parse_value(&mut lex, value).await?;
        if let Item::Container { members, .. } = item
            && w.flavor.child(&name) != Flavor::Plain
        {
            walked.collection = Some(members);
        }
        let summary = match (w.flavor, &item) {
            (
                Flavor::NotebookCells | Flavor::GeoFeatures | Flavor::HarEntries,
                Item::Container { object: true, .. },
            ) => describe(cx, w.flavor, span).await?,
            _ => None,
        };
        let mut node = item_node(name, item, span, w);
        if let Some(s) = summary {
            node = node.summary(s);
        }
        cx.push(node).await;
        walked.members = walked.members.saturating_add(1);
    }
}

fn unclosed() -> Diagnostic {
    Diagnostic::new(
        crate::error::DiagKind::Truncated,
        "not closed before the end of the input",
    )
}

/// If `t` ends the container (or the input), reports it and returns the end.
fn closes(cx: &Cx, lex: &Lexer<'_>, t: &Token, object: bool) -> Option<u64> {
    match t.kind {
        Kind::Eof => {
            cx.diag(unclosed().at(lex.scan.span(0, t.start)));
            Some(t.start)
        }
        Kind::ObjClose | Kind::ArrClose => {
            if (t.kind == Kind::ObjClose) != object {
                cx.diag(Diagnostic::malformed("mismatched closing bracket").at(lex.span(t)));
            }
            Some(t.end)
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Looking up members (for summaries of notebook cells, features, entries)

/// The value of `key` in the object at the start of `span`.
async fn member(cx: &Cx, span: Span, key: &str) -> Result<Option<(Item, Span)>> {
    let mut lex = Lexer::new(cx, span);
    if lex.next().await?.kind != Kind::ObjOpen {
        return Ok(None);
    }
    let mut depth = 1u32;
    let mut prev = Kind::ObjOpen;
    loop {
        cx.checkpoint().await;
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => return Ok(None),
            Kind::ObjOpen | Kind::ArrOpen => depth = depth.saturating_add(1),
            Kind::ObjClose | Kind::ArrClose => {
                depth = depth.saturating_sub(1);
                if depth == 0 {
                    return Ok(None);
                }
            }
            Kind::Str if depth == 1 && matches!(prev, Kind::ObjOpen | Kind::Comma) => {
                let (name, _) = lex.text(&t).await?;
                let mut v = lex.next().await?;
                if v.kind == Kind::Colon {
                    v = lex.next().await?;
                }
                if name == key {
                    return parse_value(&mut lex, v).await.map(Some);
                }
                parse_value(&mut lex, v).await?;
                prev = Kind::Str;
                continue;
            }
            _ => {}
        }
        prev = t.kind;
    }
}

/// A string member, or the first string of an array member (notebook
/// sources are arrays of lines).
async fn string_member(cx: &Cx, span: Span, key: &str) -> Result<Option<String>> {
    match member(cx, span, key).await? {
        Some((Item::Str(s, _), _)) => Ok(Some(s)),
        Some((Item::Num(_, raw), _)) => Ok(Some(raw)),
        Some((Item::Container { object: false, .. }, inner)) => {
            let mut lex = Lexer::new(cx, inner);
            lex.next().await?;
            let t = lex.next().await?;
            if t.kind == Kind::Str {
                Ok(Some(lex.text(&t).await?.0))
            } else {
                Ok(None)
            }
        }
        _ => Ok(None),
    }
}

async fn object_member(cx: &Cx, span: Span, key: &str) -> Result<Option<Span>> {
    Ok(match member(cx, span, key).await? {
        Some((Item::Container { object: true, .. }, s)) => Some(s),
        _ => None,
    })
}

/// A summary for an element of a flavored collection.
async fn describe(cx: &Cx, flavor: Flavor, span: Span) -> Result<Option<String>> {
    Ok(match flavor {
        Flavor::NotebookCells => {
            let kind = string_member(cx, span, "cell_type").await?;
            let source = string_member(cx, span, "source").await?;
            let source = source.map(|s| preview(s.lines().next().unwrap_or_default(), 60));
            match (kind, source) {
                (Some(k), Some(s)) => Some(format!("{k}: {s}")),
                (Some(k), None) => Some(k),
                _ => None,
            }
        }
        Flavor::GeoFeatures => {
            let geometry = match object_member(cx, span, "geometry").await? {
                Some(g) => string_member(cx, g, "type").await?,
                None => None,
            };
            let name = match object_member(cx, span, "properties").await? {
                Some(p) => string_member(cx, p, "name").await?,
                None => None,
            };
            match (geometry, name) {
                (Some(g), Some(n)) => Some(format!("{g}: {}", preview(&n, 60))),
                (g, n) => g.or(n),
            }
        }
        Flavor::HarEntries => {
            let mut parts = Vec::new();
            if let Some(req) = object_member(cx, span, "request").await? {
                parts.extend(string_member(cx, req, "method").await?);
                parts.extend(string_member(cx, req, "url").await?.map(|u| preview(&u, 80)));
            }
            if let Some(resp) = object_member(cx, span, "response").await? {
                parts.extend(
                    string_member(cx, resp, "status")
                        .await?
                        .map(|s| format!("→ {s}")),
                );
            }
            (!parts.is_empty()).then(|| parts.join(" "))
        }
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// Entry points

/// Dissects a JSON document: the members of the top-level value are the
/// top-level nodes. Returns the walk result, if the value was a container.
async fn document(cx: &Cx, input: Input, flavor: Flavor) -> Result<Option<Walked>> {
    let prepared = prepare(cx, input).await?;
    let mut lex = Lexer::new(cx, prepared.span);
    let first = lex.next().await?;
    let walked = match first.kind {
        Kind::ObjOpen | Kind::ArrOpen => {
            let walk = Walk {
                input: prepared.input(input),
                span: prepared.span.tail(first.start),
                flavor,
            };
            let walked = walk_members(cx, &walk).await?;
            lex.pos = first.start.saturating_add(walked.end);
            Some(walked)
        }
        Kind::Eof => {
            cx.annotate("empty JSON document");
            return Ok(None);
        }
        _ => {
            let (item, span) = parse_value(&mut lex, first).await?;
            let walk = Walk {
                input,
                span,
                flavor,
            };
            cx.emit(item_node("Value".to_owned(), item, span, &walk));
            None
        }
    };
    let rest = lex.next().await?;
    if rest.kind != Kind::Eof {
        let span = lex.scan.span(rest.start, lex.scan.len());
        cx.diag(Diagnostic::warning("data after the top-level value").at(span));
        cx.emit(Node::new("Trailing data").span(span));
    }
    Ok(walked)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    let kind = match skip_space(&super::encoding::probe_text(&head)).first() {
        Some(b'{') => "JSON object",
        Some(b'[') => "JSON array",
        _ => "JSON value",
    };
    cx.annotate(kind);
    if let Some(w) = document(&cx, input, Flavor::Plain).await? {
        let what = if kind == "JSON object" {
            plural(w.members, "member", "members")
        } else {
            plural(w.members, "element", "elements")
        };
        cx.annotate(format!("{kind}, {what}"));
    }
    Ok(())
}

/// Finds `"key": "value"` or `"key": number` textually (for annotations
/// from the tail, without parsing).
fn scrape(data: &[u8], key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = probe::find(data, needle.as_bytes())?;
    let rest = data.get(at.saturating_add(needle.len())..)?;
    let rest = probe::trim_start(rest).strip_prefix(b":")?;
    let rest = probe::trim_start(rest);
    if let Some(s) = rest.strip_prefix(b"\"") {
        let end = s.iter().position(|&b| b == b'"')?;
        return Some(String::from_utf8_lossy(s.get(..end)?).into_owned());
    }
    let end = rest
        .iter()
        .position(|b| !b.is_ascii_alphanumeric())
        .unwrap_or(rest.len());
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}

pub async fn dissect_notebook(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let tail = cx
        .read_avail(span.tail(span.len.saturating_sub(16 * 1024)))
        .await?;
    let mut summary = String::from("Jupyter notebook");
    let version = match (scrape(&tail, "nbformat"), scrape(&tail, "nbformat_minor")) {
        (Some(major), Some(minor)) => Some(format!("nbformat {major}.{minor}")),
        (Some(major), None) => Some(format!("nbformat {major}")),
        _ => None,
    };
    let kernel = scrape(&tail, "display_name");
    let details: Vec<String> = version.into_iter().chain(kernel).collect();
    if !details.is_empty() {
        summary = format!("{summary} ({})", details.join(", "));
    }
    cx.annotate(summary.clone());
    if let Some(cells) = document(&cx, input, Flavor::Notebook)
        .await?
        .and_then(|w| w.collection)
    {
        cx.annotate(format!("{summary}, {}", plural(cells, "cell", "cells")));
    }
    Ok(())
}

pub async fn dissect_geojson(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    let kind = scrape(&head, "type").unwrap_or_else(|| "object".to_owned());
    cx.annotate(format!("GeoJSON {kind}"));
    if let Some(n) = document(&cx, input, Flavor::GeoJson)
        .await?
        .and_then(|w| w.collection)
    {
        cx.annotate(format!("GeoJSON {kind}, {}", plural(n, "feature", "features")));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Vocabularies recognised by the keys near the top of the document

/// Whether the start of a JSON document contains all of `needles`, one of
/// `any` (if given) and none of `absent`.
fn has_keys(h: &Head<'_>, needles: &[&[u8]], any: &[&[u8]], absent: &[&[u8]]) -> bool {
    let head = probe::head(h);
    let start = head.get(..head.len().min(4096)).unwrap_or_default();
    probe_json(h)
        && needles.iter().all(|n| probe::contains(start, n))
        && (any.is_empty() || any.iter().any(|n| probe::contains(start, n)))
        && !absent.iter().any(|n| probe::contains(start, n))
}

/// Annotates `title` with the first of `keys` found textually near the top,
/// then dissects the document as JSON.
async fn dissect_keyed(cx: Cx, input: Input, title: &str, keys: &[&str]) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 16 * 1024)).await?;
    let text = super::encoding::probe_text(&head);
    let detail = keys.iter().find_map(|k| scrape(&text, k));
    cx.annotate(match detail {
        Some(d) if !d.is_empty() => format!("{title}: {}", preview(&d, 60)),
        _ => title.to_owned(),
    });
    document(&cx, input, Flavor::Plain).await.map(|_| ())
}

/// A JSON vocabulary: all of `needles`, one of `any`, none of `absent` near
/// the top; annotated with the first of `keys` found.
macro_rules! json_variant {
    ($id:ident, $f:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal,
     all [$($needle:literal),*], any [$($any:literal),*], none [$($absent:literal),*],
     keys [$($key:literal),*]) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| {
                has_keys(h, &[$($needle.as_slice()),*], &[$($any.as_slice()),*], &[$($absent.as_slice()),*])
            }),
            dissect: crate::expander!($f: Input),
        };
        async fn $f(cx: Cx, input: Input) -> Result<()> {
            dissect_keyed(cx, input, $title, &[$($key),*]).await
        }
    };
}

json_variant!(GLTF, dissect_gltf, "gltf", "glTF 3D asset (JSON)", ["gltf"], "model/gltf+json",
    all [b"\"asset\"", b"\"version\""],
    any [b"\"meshes\"", b"\"scenes\"", b"\"buffers\"", b"\"nodes\""], none [],
    keys ["generator", "version"]);
json_variant!(JSON_SCHEMA, dissect_schema, "json-schema", "JSON Schema", ["schema.json"],
    "application/schema+json", all [b"\"$schema\"", b"json-schema.org"], any [], none [],
    keys ["title", "$id"]);
json_variant!(TOPOJSON, dissect_topojson, "topojson", "TopoJSON", ["topojson"], "application/json",
    all [b"\"type\"", b"\"Topology\"", b"\"arcs\""], any [], none [], keys []);
json_variant!(WEB_MANIFEST, dissect_webmanifest, "web-manifest", "Web app manifest",
    ["webmanifest"], "application/manifest+json",
    all [b"\"start_url\""], any [], none [b"\"manifest_version\""], keys ["name", "short_name"]);
json_variant!(EXTENSION_MANIFEST, dissect_extension, "browser-extension-manifest",
    "Browser extension manifest", [], "application/json",
    all [b"\"manifest_version\""], any [], none [], keys ["name", "version"]);
json_variant!(LOTTIE, dissect_lottie, "lottie", "Lottie animation", ["lottie"], "application/json",
    all [b"\"fr\"", b"\"ip\"", b"\"op\"", b"\"layers\""], any [], none [], keys ["nm"]);
json_variant!(EXCALIDRAW, dissect_excalidraw, "excalidraw", "Excalidraw drawing", ["excalidraw"],
    "application/json", all [b"\"type\"", b"\"excalidraw\"", b"\"elements\""], any [], none [],
    keys ["source"]);
json_variant!(SARIF, dissect_sarif, "sarif", "SARIF analysis results", ["sarif"],
    "application/sarif+json", all [b"\"runs\"", b"sarif"], any [], none [], keys ["version"]);
json_variant!(OPENAPI, dissect_openapi, "openapi", "OpenAPI description", [], "application/json",
    all [b"\"paths\"", b"\"info\""], any [b"\"openapi\"", b"\"swagger\""], none [],
    keys ["title", "openapi", "swagger"]);
json_variant!(NPM_PACKAGE, dissect_npm, "npm-package", "npm package manifest", [], "application/json",
    all [b"\"name\"", b"\"version\""],
    any [b"\"dependencies\"", b"\"devDependencies\"", b"\"scripts\"", b"\"main\""],
    none [b"\"manifest_version\"", b"\"start_url\""], keys ["name"]);
json_variant!(TSCONFIG, dissect_tsconfig, "tsconfig", "TypeScript configuration", [],
    "application/json", all [b"\"compilerOptions\""], any [], none [], keys ["extends"]);

pub async fn dissect_har(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    let mut summary = String::from("HTTP Archive");
    if let Some(v) = scrape(&head, "version") {
        summary = format!("{summary} {v}");
    }
    if let Some(creator) = scrape(&head, "name") {
        summary = format!("{summary}, created by {creator}");
    }
    cx.annotate(summary);
    document(&cx, input, Flavor::Har).await?;
    Ok(())
}

/// JSON Lines: one document per line, as a paged collection.
pub async fn dissect_lines(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let walk_input = prepared.input(input);
    cx.annotate(format!("JSON Lines{}", prepared.note()));
    let mut lines = Lines::new(&cx, prepared.span);
    let mut records = 0u64;
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        records = records.saturating_add(1);
        let mut lex = Lexer::new(&cx, line.span);
        let first = lex.next().await?;
        let (item, span) = parse_value(&mut lex, first).await?;
        let walk = Walk {
            input: walk_input,
            span,
            flavor: Flavor::Plain,
        };
        let name = format!("Line {}", line.number);
        let preview = preview(&line.text(), 80);
        let mut node = item_node(name, item, span, &walk);
        if matches!(line.piece().trim().first(), Some(b'{' | b'[')) {
            node = node.summary(preview);
        }
        if lex.next().await?.kind != Kind::Eof {
            node = node.diag(Diagnostic::warning("more than one value on this line"));
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "JSON Lines{}, {}",
        prepared.note(),
        plural(records, "record", "records")
    ));
    Ok(())
}
