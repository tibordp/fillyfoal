//! Graphviz DOT graphs: statements (nodes, edges, attribute defaults, graph
//! attributes) and subgraphs, read with a small streaming tokenizer.

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::decode::preview;
use super::encoding::prepare;
use super::scan::Scanner;
use super::{count, probe};

pub static FORMAT: Format = Format {
    name: "dot",
    title: "Graphviz DOT graph",
    extensions: &["dot", "gv"],
    mime: "text/vnd.graphviz",
    probe: Probe::Custom(probe_dot),
    dissect: crate::expander!(dissect: Input),
};

/// Skips whitespace and comments in a probe.
fn skip(mut data: &[u8]) -> &[u8] {
    loop {
        data = probe::trim_start(data);
        let n = if data.starts_with(b"//") || data.starts_with(b"#") {
            data.iter().position(|&b| b == b'\n')
        } else if data.starts_with(b"/*") {
            probe::find(data, b"*/").map(|n| n.saturating_add(2))
        } else {
            return data;
        };
        data = data.get(n.unwrap_or(data.len())..).unwrap_or_default();
    }
}

fn word(data: &[u8]) -> (&[u8], &[u8]) {
    let n = data
        .iter()
        .take_while(|b| b.is_ascii_alphanumeric() || **b == b'_')
        .count();
    (data.get(..n).unwrap_or_default(), data.get(n..).unwrap_or_default())
}

fn probe_dot(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let (mut w, mut rest) = word(skip(&head));
    if w.eq_ignore_ascii_case(b"strict") {
        (w, rest) = word(skip(rest));
    }
    if !(w.eq_ignore_ascii_case(b"graph") || w.eq_ignore_ascii_case(b"digraph")) {
        return false;
    }
    let mut rest = skip(rest);
    if rest.first() == Some(&b'"') {
        let end = rest.get(1..).and_then(|r| r.iter().position(|&b| b == b'"'));
        rest = rest.get(end.map_or(rest.len(), |e| e.saturating_add(2))..).unwrap_or_default();
    } else {
        rest = word(rest).1;
    }
    skip(rest).first() == Some(&b'{') && probe::is_text(h)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Id,
    Open,
    Close,
    BracketOpen,
    BracketClose,
    Equals,
    Edge,
    Separator,
    Colon,
    Other,
    Eof,
}

#[derive(Clone, Copy, Debug)]
struct Tok {
    kind: Kind,
    start: u64,
    end: u64,
}

struct Lexer<'a> {
    scan: Scanner<'a>,
    pos: u64,
}

impl<'a> Lexer<'a> {
    async fn skip_space(&mut self) -> Result<()> {
        loop {
            let Some(at) = self.scan.find(self.pos, |b| !b.is_ascii_whitespace()).await? else {
                self.pos = self.scan.len();
                return Ok(());
            };
            self.pos = at;
            let b = self.scan.byte(at).await?;
            let next = self.scan.byte(at.saturating_add(1)).await?;
            self.pos = match (b, next) {
                (Some(b'/'), Some(b'/')) | (Some(b'#'), _) => {
                    self.scan.find(at, |c| c == b'\n').await?.unwrap_or(self.scan.len())
                }
                (Some(b'/'), Some(b'*')) => self
                    .scan
                    .find_seq(at.saturating_add(2), b"*/")
                    .await?
                    .map_or(self.scan.len(), |e| e.saturating_add(2)),
                _ => return Ok(()),
            };
        }
    }

    async fn next(&mut self) -> Result<Tok> {
        self.scan.tick().await;
        self.skip_space().await?;
        let start = self.pos;
        let Some(b) = self.scan.byte(start).await? else {
            return Ok(Tok { kind: Kind::Eof, start, end: start });
        };
        let one = start.saturating_add(1);
        let (kind, end) = match b {
            b'{' => (Kind::Open, one),
            b'}' => (Kind::Close, one),
            b'[' => (Kind::BracketOpen, one),
            b']' => (Kind::BracketClose, one),
            b'=' => (Kind::Equals, one),
            b';' | b',' => (Kind::Separator, one),
            b':' => (Kind::Colon, one),
            b'-' if matches!(self.scan.byte(one).await?, Some(b'>' | b'-')) => (Kind::Edge, start.saturating_add(2)),
            b'"' => {
                let mut p = one;
                loop {
                    match self.scan.find(p, |c| c == b'"' || c == b'\\').await? {
                        Some(i) if self.scan.byte(i).await? == Some(b'\\') => p = i.saturating_add(2),
                        Some(i) => break (Kind::Id, i.saturating_add(1)),
                        None => break (Kind::Id, self.scan.len()),
                    }
                }
            }
            b'<' => {
                // HTML-like label: nested angle brackets.
                let mut depth = 0u32;
                let mut p = start;
                loop {
                    match self.scan.find(p, |c| c == b'<' || c == b'>').await? {
                        Some(i) => {
                            p = i.saturating_add(1);
                            if self.scan.byte(i).await? == Some(b'<') {
                                depth = depth.saturating_add(1);
                            } else {
                                depth = depth.saturating_sub(1);
                                if depth == 0 {
                                    break (Kind::Id, p);
                                }
                            }
                        }
                        None => break (Kind::Id, self.scan.len()),
                    }
                }
            }
            c if c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c == b'-' || c >= 0x80 => {
                let end = self
                    .scan
                    .find(one, |c| !(c.is_ascii_alphanumeric() || c == b'_' || c == b'.' || c >= 0x80))
                    .await?
                    .unwrap_or(self.scan.len());
                (Kind::Id, end)
            }
            _ => (Kind::Other, one),
        };
        self.pos = end.max(one);
        Ok(Tok { kind, start, end })
    }

    async fn peek(&mut self) -> Result<Tok> {
        let pos = self.pos;
        let t = self.next().await?;
        self.pos = pos;
        Ok(t)
    }

    async fn text(&mut self, t: &Tok) -> Result<String> {
        let raw = self.scan.bytes(t.start, t.end, 1024).await?;
        let s = super::encoding::decode_8bit(&raw);
        Ok(match s.strip_prefix('"').and_then(|s| s.strip_suffix('"')) {
            Some(inner) => inner.replace("\\\"", "\""),
            None => s,
        })
    }

    /// Skips a `{ ... }` block whose `{` was just read; returns its end.
    async fn skip_block(&mut self) -> Result<(u64, bool)> {
        let mut depth = 1u32;
        loop {
            let t = self.next().await?;
            match t.kind {
                Kind::Eof => return Ok((t.start, false)),
                Kind::Open => depth = depth.saturating_add(1),
                Kind::Close => {
                    depth = depth.saturating_sub(1);
                    if depth == 0 {
                        return Ok((t.end, true));
                    }
                }
                _ => {}
            }
        }
    }

    /// An attribute list after its `[`: `k=v` pairs as text.
    async fn attributes(&mut self) -> Result<Vec<(String, String)>> {
        let mut out = Vec::new();
        loop {
            let t = self.next().await?;
            match t.kind {
                Kind::Eof | Kind::BracketClose => return Ok(out),
                Kind::Id => {
                    let key = self.text(&t).await?;
                    if self.peek().await?.kind == Kind::Equals {
                        self.next().await?;
                        let v = self.next().await?;
                        let value = self.text(&v).await?;
                        if out.len() < 256 {
                            out.push((key, value));
                        }
                    } else if out.len() < 256 {
                        out.push((key, "true".to_owned()));
                    }
                }
                _ => {}
            }
        }
    }
}

fn attr_text(attrs: &[(String, String)]) -> String {
    let parts: Vec<String> = attrs.iter().map(|(k, v)| format!("{k}={v}")).collect();
    preview(&parts.join(", "), 100)
}

#[derive(Clone, Debug)]
struct Body {
    /// Starts at the `{`.
    span: Span,
}

/// Counts from walking statements.
#[derive(Default)]
struct Stats {
    nodes: u64,
    edges: u64,
}

async fn body(cx: Cx, b: Body) -> Result<()> {
    let mut lex = Lexer {
        scan: Scanner::new(&cx, b.span),
        pos: 0,
    };
    lex.next().await?; // `{`
    statements(&cx, &mut lex).await.map(|_| ())
}

async fn statements(cx: &Cx, lex: &mut Lexer<'_>) -> Result<Stats> {
    let mut stats = Stats::default();
    loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => {
                cx.diag(Diagnostic::new(DiagKind::Truncated, "graph not closed"));
                return Ok(stats);
            }
            Kind::Close => return Ok(stats),
            Kind::Open => {
                let (end, _) = lex.skip_block().await?;
                let span = lex.scan.span(t.start, end);
                cx.push(Node::new("Subgraph").span(span).lazy(crate::expander!(self::body: Body), Body { span })).await;
            }
            Kind::Id => {
                let word = lex.text(&t).await?;
                let lower = word.to_ascii_lowercase();
                if lower == "subgraph" {
                    let mut name = String::from("Subgraph");
                    let mut open = lex.next().await?;
                    if open.kind == Kind::Id {
                        name = format!("Subgraph {}", lex.text(&open).await?);
                        open = lex.next().await?;
                    }
                    if open.kind != Kind::Open {
                        continue;
                    }
                    let (end, closed) = lex.skip_block().await?;
                    let span = lex.scan.span(open.start, end);
                    let mut node = Node::new(name)
                        .span(lex.scan.span(t.start, end))
                        .lazy(crate::expander!(self::body: Body), Body { span });
                    if !closed {
                        node = node.diag(Diagnostic::new(DiagKind::Truncated, "subgraph not closed"));
                    }
                    cx.push(node).await;
                    continue;
                }
                if matches!(lower.as_str(), "graph" | "node" | "edge")
                    && lex.peek().await?.kind == Kind::BracketOpen
                {
                    lex.next().await?;
                    let attrs = lex.attributes().await?;
                    let span = lex.scan.span(t.start, lex.pos);
                    cx.push(Node::new(format!("Default {lower} attributes")).span(span).value(Value::Text(attr_text(&attrs))))
                        .await;
                    continue;
                }
                if lex.peek().await?.kind == Kind::Equals {
                    lex.next().await?;
                    let v = lex.next().await?;
                    let value = lex.text(&v).await?;
                    let span = lex.scan.span(t.start, v.end);
                    cx.push(Node::new(format!("Graph attribute {word}")).span(span).value(Value::Text(value))).await;
                    continue;
                }
                // A node or an edge chain.
                let mut ends = vec![word];
                loop {
                    let p = lex.peek().await?;
                    if p.kind == Kind::Colon {
                        lex.next().await?;
                        lex.next().await?; // port
                        continue;
                    }
                    if p.kind != Kind::Edge {
                        break;
                    }
                    lex.next().await?;
                    let target = lex.next().await?;
                    match target.kind {
                        Kind::Id => ends.push(lex.text(&target).await?),
                        Kind::Open => {
                            lex.skip_block().await?;
                            ends.push("{…}".to_owned());
                        }
                        _ => break,
                    }
                    if ends.len() > 1024 {
                        break;
                    }
                }
                let mut attrs = Vec::new();
                while lex.peek().await?.kind == Kind::BracketOpen {
                    lex.next().await?;
                    attrs.extend(lex.attributes().await?);
                }
                let span = lex.scan.span(t.start, lex.pos);
                let mut node = if ends.len() > 1 {
                    stats.edges = stats.edges.saturating_add(crate::bytes::to_u64(ends.len().saturating_sub(1)));
                    Node::new(ends.join(" → ")).span(span).summary("edge")
                } else {
                    stats.nodes = stats.nodes.saturating_add(1);
                    Node::new(ends.join("")).span(span).summary("node")
                };
                if !attrs.is_empty() {
                    node = node.value(Value::Text(attr_text(&attrs)));
                }
                cx.push(node).await;
            }
            _ => {}
        }
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let mut lex = Lexer {
        scan: Scanner::new(&cx, prepared.span),
        pos: 0,
    };
    // Header: [strict] graph|digraph [ID] {
    let mut words = Vec::new();
    let open = loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Open => break t,
            Kind::Eof => return Err(Diagnostic::malformed("no graph body").at(prepared.span)),
            _ => {
                if words.len() < 4 {
                    words.push(lex.text(&t).await?);
                }
            }
        }
    };
    let header = lex.scan.span(0, open.start);
    cx.emit(Node::new("Header").span(header).value(Value::Text(words.join(" "))));
    let stats = statements(&cx, &mut lex).await?;
    let kind = words
        .iter()
        .find(|w| w.eq_ignore_ascii_case("digraph") || w.eq_ignore_ascii_case("graph"))
        .cloned()
        .unwrap_or_else(|| "graph".to_owned());
    let name = words.last().filter(|w| !w.eq_ignore_ascii_case(&kind)).cloned();
    let mut summary = format!("Graphviz {kind}");
    if let Some(n) = name {
        summary = format!("{summary} {n}");
    }
    cx.annotate(format!(
        "{summary}: {} node statements, {} edges",
        count(stats.nodes),
        count(stats.edges)
    ));
    Ok(())
}
