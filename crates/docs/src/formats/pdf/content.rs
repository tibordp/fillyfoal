//! Content streams: the drawing operators of a page, form or pattern.

use super::syntax::{self, Reader};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

/// Operands kept per operator (more are counted, not shown).
const MAX_OPERANDS: usize = 32;
/// Bytes of a string operand shown.
const MAX_SHOWN: usize = 1 << 16;

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

/// The operators of CMaps (ToUnicode and CID maps), PostScript-like
/// programs that define a code-to-Unicode or code-to-CID mapping.
const CMAP_OPERATORS: &[(&str, &str)] = &[
    ("begin", "push dictionary"),
    ("beginbfchar", "begin character-to-Unicode mappings"),
    ("beginbfrange", "begin range-to-Unicode mappings"),
    ("begincidchar", "begin character-to-CID mappings"),
    ("begincidrange", "begin range-to-CID mappings"),
    ("begincmap", "begin CMap"),
    ("begincodespacerange", "begin code space ranges"),
    ("beginnotdefchar", "begin notdef character mappings"),
    ("beginnotdefrange", "begin notdef range mappings"),
    ("currentdict", "push the current dictionary"),
    ("def", "define"),
    ("defineresource", "define resource"),
    ("dict", "create dictionary"),
    ("end", "pop dictionary"),
    ("endbfchar", "end character-to-Unicode mappings"),
    ("endbfrange", "end range-to-Unicode mappings"),
    ("endcidchar", "end character-to-CID mappings"),
    ("endcidrange", "end range-to-CID mappings"),
    ("endcmap", "end CMap"),
    ("endcodespacerange", "end code space ranges"),
    ("endnotdefchar", "end notdef character mappings"),
    ("endnotdefrange", "end notdef range mappings"),
    ("findresource", "find resource"),
    ("pop", "discard"),
    ("usecmap", "use another CMap"),
    ("usefont", "use font"),
];

/// The syntax a stream is read as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Syntax {
    /// A content stream (page, form, pattern, glyph).
    Content,
    /// A CMap.
    CMap,
}

fn describe(op: &str, syntax: Syntax) -> Option<&'static str> {
    let table = match syntax {
        Syntax::Content => OPERATORS,
        Syntax::CMap => CMAP_OPERATORS,
    };
    table.iter().find(|(o, _)| *o == op).map(|(_, d)| *d)
}

/// Lists the operators of the content stream decoded into `span`, reading
/// it as it goes: each operand and operator is a bounded step.
pub async fn operators(cx: &Cx, span: Span, syntax: Syntax) -> Result<()> {
    // A parse error ends the listing (reported); a read error fails it.
    macro_rules! attempt {
        ($e:expr) => {
            match $e {
                Ok(v) => v,
                Err(syntax::Error::Malformed(msg, at)) => {
                    cx.diag(Diagnostic::malformed(msg).at(span.sub(to_u64(at), 1)));
                    return Ok(());
                }
                Err(syntax::Error::Stop(e)) => return Err(e),
            }
        };
    }
    let mut p = Reader::pieces(cx, span);
    let mut operands: Vec<String> = Vec::new();
    let mut extra = 0usize;
    let mut start: Option<usize> = None;
    let mut steps = 0u32;
    loop {
        cx.checkpoint().await;
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(256) {
            cx.progress_in(span, span.offset.saturating_add(to_u64(p.pos)));
        }
        p.release(p.pos);
        attempt!(p.skip_ws().await);
        let at = p.pos;
        if !attempt!(p.ensure(at).await) {
            break;
        }
        let word_end = attempt!(p.word_end(at).await);
        let word = p.slice(at, word_end);
        let is_operator = !word.is_empty()
            && !matches!(word.first(), Some(b'+' | b'-' | b'.' | b'0'..=b'9'))
            && !matches!(word, b"true" | b"false" | b"null");
        if !is_operator {
            let item = attempt!(p.object().await);
            start.get_or_insert(at);
            if operands.len() < MAX_OPERANDS {
                operands.push(short(&item));
            } else {
                extra = extra.saturating_add(1);
            }
            continue;
        }
        let op = String::from_utf8_lossy(word).into_owned();
        p.pos = word_end;
        let from = start.take().unwrap_or(at);
        let mut end = p.pos;
        if op == "BI" {
            // Inline image: key/value pairs, ID, data, EI.
            match attempt!(p.find(b"ID", end).await) {
                Some(id) => {
                    let data_start = id.saturating_add(3);
                    let ei = attempt!(
                        p.scan(data_start, 2, |before, w, after| {
                            w == b"EI"
                                && before.is_some_and(syntax::is_white)
                                && after.is_none_or(syntax::is_white)
                        })
                        .await
                    );
                    end = ei.saturating_add(2).min(p.end());
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
        if let Some(d) = describe(&op, syntax) {
            node = node.summary(d);
        } else if syntax == Syntax::Content {
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
        Obj::Str { bytes, hex: true } => {
            let shown = bytes.get(..MAX_SHOWN / 2).unwrap_or(bytes);
            let more = if shown.len() < bytes.len() {
                " …"
            } else {
                ""
            };
            let digits: String = shown.iter().map(|b| format!("{b:02x}")).collect();
            format!("<{digits}{more}>")
        }
        Obj::Str { bytes, .. } => match bytes.get(..MAX_SHOWN) {
            // Very long strings are shown in part.
            Some(shown) if bytes.len() > MAX_SHOWN => format!("({} …)", syntax::text(shown)),
            _ => format!("({})", syntax::text(bytes)),
        },
        Obj::Array(items) => {
            let inner: Vec<String> = items.iter().take(16).map(short).collect();
            let more = if items.len() > 16 { " …" } else { "" };
            format!("[{}{more}]", inner.join(" "))
        }
        _ => super::short(item),
    }
}
