//! Content streams: the drawing operators of a page, form or pattern.

use super::syntax::{self, Parser};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

/// Operands kept per operator (more are counted, not shown).
const MAX_OPERANDS: usize = 32;

const OPERATORS: &[(&str, &str)] = &[
    ("b", "close, fill and stroke"),
    ("B", "fill and stroke"),
    ("b*", "close, fill (even-odd) and stroke"),
    ("B*", "fill (even-odd) and stroke"),
    ("BDC", "begin marked content with properties"),
    ("BI", "begin inline image"),
    ("BMC", "begin marked content"),
    ("BT", "begin text"),
    ("BX", "begin compatibility section"),
    ("c", "curve to"),
    ("cm", "concatenate matrix"),
    ("CS", "set stroking color space"),
    ("cs", "set non-stroking color space"),
    ("d", "set dash pattern"),
    ("d0", "glyph width"),
    ("d1", "glyph width and bounding box"),
    ("Do", "paint XObject"),
    ("DP", "marked-content point with properties"),
    ("EMC", "end marked content"),
    ("ET", "end text"),
    ("EX", "end compatibility section"),
    ("f", "fill"),
    ("F", "fill"),
    ("f*", "fill (even-odd)"),
    ("G", "set stroking gray"),
    ("g", "set non-stroking gray"),
    ("gs", "set graphics state"),
    ("h", "close path"),
    ("i", "set flatness"),
    ("j", "set line join"),
    ("J", "set line cap"),
    ("K", "set stroking CMYK"),
    ("k", "set non-stroking CMYK"),
    ("l", "line to"),
    ("m", "move to"),
    ("M", "set miter limit"),
    ("MP", "marked-content point"),
    ("n", "end path"),
    ("q", "save graphics state"),
    ("Q", "restore graphics state"),
    ("re", "rectangle"),
    ("RG", "set stroking RGB"),
    ("rg", "set non-stroking RGB"),
    ("ri", "set rendering intent"),
    ("s", "close and stroke"),
    ("S", "stroke"),
    ("SC", "set stroking color"),
    ("sc", "set non-stroking color"),
    ("SCN", "set stroking color"),
    ("scn", "set non-stroking color"),
    ("sh", "paint shading"),
    ("T*", "next line"),
    ("Tc", "set character spacing"),
    ("Td", "move text position"),
    ("TD", "move text position, set leading"),
    ("Tf", "set font"),
    ("Tj", "show text"),
    ("TJ", "show text with positioning"),
    ("TL", "set leading"),
    ("Tm", "set text matrix"),
    ("Tr", "set text rendering mode"),
    ("Ts", "set text rise"),
    ("Tw", "set word spacing"),
    ("Tz", "set horizontal scaling"),
    ("v", "curve to (initial point replicated)"),
    ("w", "set line width"),
    ("W", "clip"),
    ("W*", "clip (even-odd)"),
    ("y", "curve to (final point replicated)"),
    ("'", "next line, show text"),
    ("\"", "set spacing, next line, show text"),
];

fn describe(op: &str) -> Option<&'static str> {
    OPERATORS.iter().find(|(o, _)| *o == op).map(|(_, d)| *d)
}

/// Lists the operators of the content stream decoded into `span`.
pub async fn operators(cx: &Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut p = Parser::new(&data, true);
    let mut operands: Vec<String> = Vec::new();
    let mut extra = 0usize;
    let mut start: Option<usize> = None;
    loop {
        cx.checkpoint().await;
        p.skip_ws();
        let at = p.pos;
        if at >= data.len() {
            break;
        }
        let word = p.peek_word();
        let is_operator = !word.is_empty()
            && !matches!(word.first(), Some(b'+' | b'-' | b'.' | b'0'..=b'9'))
            && !matches!(word, b"true" | b"false" | b"null");
        if !is_operator {
            match p.object() {
                Ok(item) => {
                    start.get_or_insert(at);
                    if operands.len() < MAX_OPERANDS {
                        operands.push(short(&item));
                    } else {
                        extra = extra.saturating_add(1);
                    }
                }
                Err(syntax::Error::Malformed(msg, at)) => {
                    cx.diag(Diagnostic::malformed(msg).at(span.sub(to_u64(at), 1)));
                    break;
                }
                Err(syntax::Error::Incomplete) => break,
            }
            continue;
        }
        let op = String::from_utf8_lossy(p.word()).into_owned();
        let from = start.take().unwrap_or(at);
        let mut end = p.pos;
        if op == "BI" {
            // Inline image: key/value pairs, ID, data, EI.
            match syntax::find(&data, b"ID", end) {
                Some(id) => {
                    let data_start = id.saturating_add(3);
                    let ei = (data_start..data.len())
                        .find(|&i| {
                            data.get(i..i.saturating_add(2)) == Some(b"EI")
                                && i.checked_sub(1)
                                    .and_then(|j| data.get(j))
                                    .is_some_and(|&b| syntax::is_white(b))
                                && data
                                    .get(i.saturating_add(2))
                                    .is_none_or(|&b| syntax::is_white(b))
                        })
                        .unwrap_or(data.len());
                    end = ei.saturating_add(2).min(data.len());
                    p.pos = end;
                    cx.push(
                        Node::new("BI … ID … EI")
                            .span(span.sub(to_u64(from), to_u64(end.saturating_sub(from))))
                            .summary(format!(
                                "inline image, {} bytes of data",
                                ei.saturating_sub(data_start)
                            )),
                    )
                    .await;
                }
                None => {
                    cx.diag(
                        Diagnostic::malformed("inline image without ID")
                            .at(span.sub(to_u64(from), 2)),
                    );
                    break;
                }
            }
            operands.clear();
            continue;
        }
        let mut text = operands.join(" ");
        if extra > 0 {
            text = format!("{text} … (+{extra})");
        }
        let mut node =
            Node::new(op.clone()).span(span.sub(to_u64(from), to_u64(end.saturating_sub(from))));
        if !text.is_empty() {
            node = node.value(Value::Text(text));
        }
        if let Some(d) = describe(&op) {
            node = node.summary(d);
        } else {
            node = node.diag(Diagnostic::warning("unknown operator"));
        }
        cx.push(node).await;
        operands.clear();
        extra = 0;
    }
    Ok(())
}

fn short(item: &syntax::Item) -> String {
    use syntax::Obj;
    match &item.obj {
        Obj::Str { bytes, .. } => format!("({})", syntax::text(bytes)),
        Obj::Array(items) => {
            let inner: Vec<String> = items.iter().take(16).map(short).collect();
            let more = if items.len() > 16 { " …" } else { "" };
            format!("[{}{more}]", inner.join(" "))
        }
        _ => super::short(item),
    }
}
