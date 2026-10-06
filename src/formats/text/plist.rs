//! Apple property lists in XML form, decoded into a typed tree: dictionary
//! keys become node names, `<integer>`/`<real>`/`<date>`/`<true/>` become
//! typed values, and `<data>` (base64) is decoded into a derived source and
//! dissected (often a nested binary plist, an image or a certificate).

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::decode::{Transform, decoded_node, preview};
use super::encoding::prepare;
use super::xml::{self, Extent, Kind, Lexer, Mode, Tok};
use super::{number, parse_datetime, plural, text_node};

pub static FORMAT: Format = Format {
    name: "plist-xml",
    title: "Property list (XML)",
    extensions: &[
        "plist",
        "webloc",
        "entitlements",
        "xcprivacy",
        "scriptSuite",
        "strings",
    ],
    mime: "application/x-plist",
    probe: Probe::Custom(|h| {
        xml::root(h).is_some_and(|r| r.is(b"plist")) && super::probe::is_text(h)
    }),
    dissect: crate::expander!(dissect: Input),
};

/// One child element: its start tag, extent and name.
struct Child {
    open: Tok,
    ext: Extent,
    name: Vec<u8>,
}

/// Iterates the child elements of the element at the start of a lexer's
/// region (whose start tag has been read).
async fn next_child(lex: &mut Lexer<'_>) -> Result<Option<Child>> {
    loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof | Kind::End => return Ok(None),
            Kind::Start => {
                let name = lex.name(&t).await?;
                let ext = xml::skip_element(lex, &t, &[]).await?;
                return Ok(Some(Child { open: t, ext, name }));
            }
            _ => {}
        }
    }
}

/// The text content of a simple element (`<key>`, `<string>`, ...).
async fn text_of(lex: &mut Lexer<'_>, c: &Child) -> Result<String> {
    match c.ext.text {
        Some(t) => xml::token_text(lex, &t).await,
        None => Ok(String::new()),
    }
}

/// The span of an element's content (between its tags).
fn inner(lex: &Lexer<'_>, c: &Child) -> Span {
    let end_tag = 3u64.saturating_add(crate::bytes::to_u64(c.name.len()));
    let end = if c.ext.closure == xml::Closure::Explicit {
        c.ext.end.saturating_sub(end_tag)
    } else {
        c.ext.end
    };
    lex.scan.span(c.open.end, end.max(c.open.end))
}

#[derive(Clone, Debug)]
struct Container {
    input: Input,
    span: Span,
}

/// The node for a plist value element.
async fn value_node(lex: &mut Lexer<'_>, c: &Child, name: String, input: Input) -> Result<Node> {
    let span = lex.scan.span(c.open.start, c.ext.end);
    let node = match c.name.as_slice() {
        b"dict" | b"array" => {
            let dict = c.name == b"dict";
            let count = if dict {
                plural(c.ext.elements / 2, "key", "keys")
            } else {
                plural(c.ext.elements, "element", "elements")
            };
            let node = Node::new(name)
                .span(span)
                .summary(format!("{}, {count}", String::from_utf8_lossy(&c.name)));
            if c.ext.elements == 0 {
                node
            } else {
                node.lazy(
                    crate::expander!(self::container: Container),
                    Container { input, span },
                )
            }
        }
        b"string" => text_node(name, span, &text_of(lex, c).await?),
        b"integer" | b"real" => {
            let text = text_of(lex, c).await?;
            let value = if c.name == b"real" {
                text.trim().parse::<f64>().ok().map(Value::Float)
            } else {
                number(&text)
            };
            match value {
                Some(v) => Node::new(name).span(span).value(v),
                None => text_node(name, span, &text).diag(Diagnostic::malformed("invalid number")),
            }
        }
        b"true" | b"false" => Node::new(name)
            .span(span)
            .value(Value::Bool(c.name == b"true")),
        b"date" => {
            let text = text_of(lex, c).await?;
            match parse_datetime(&text) {
                Some(t) => Node::new(name)
                    .span(span)
                    .value(Value::Timestamp { unix_seconds: t }),
                None => text_node(name, span, &text).diag(Diagnostic::malformed("invalid date")),
            }
        }
        b"data" => {
            let body = inner(lex, c);
            let size = body.len.saturating_mul(3) / 4;
            decoded_node(name, input, body, Transform::Base64)
                .summary(format!("base64, about {size} bytes"))
        }
        other => {
            let text = text_of(lex, c).await?;
            text_node(name, span, &text).diag(Diagnostic::warning(format!(
                "unknown plist element <{}>",
                String::from_utf8_lossy(other)
            )))
        }
    };
    Ok(node)
}

/// Expands a `<dict>` or `<array>`.
async fn container(cx: Cx, c: Container) -> Result<()> {
    let mut lex = Lexer::new(&cx, c.span, Mode::Xml);
    let open = lex.next().await?;
    let dict = lex.name(&open).await? == b"dict";
    members(&cx, &mut lex, dict, c.input).await
}

async fn members(cx: &Cx, lex: &mut Lexer<'_>, dict: bool, input: Input) -> Result<()> {
    let mut index = 0u64;
    while let Some(child) = next_child(lex).await? {
        let name = if dict {
            if child.name != b"key" {
                cx.push(
                    value_node(lex, &child, format!("[{index}]"), input)
                        .await?
                        .diag(Diagnostic::malformed("value without a <key>")),
                )
                .await;
                index = index.saturating_add(1);
                continue;
            }
            let key = text_of(lex, &child).await?;
            match next_child(lex).await? {
                Some(value) => {
                    cx.push(value_node(lex, &value, key, input).await?).await;
                }
                None => {
                    let span = lex.scan.span(child.open.start, child.ext.end);
                    cx.push(
                        Node::new(key)
                            .span(span)
                            .diag(Diagnostic::malformed("key without a value")),
                    )
                    .await;
                    break;
                }
            }
            index = index.saturating_add(1);
            continue;
        } else {
            format!("[{index}]")
        };
        cx.push(value_node(lex, &child, name, input).await?).await;
        index = index.saturating_add(1);
    }
    cx.set_count(Count::Exact(index));
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("Property list (XML)");
    let prepared = prepare(&cx, input).await?;
    let input = prepared.input(input);
    let mut lex = Lexer::new(&cx, prepared.span, Mode::Xml);
    // Prolog: up to the <plist> start tag.
    let plist = loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => return Err(Diagnostic::malformed("no <plist> element").at(prepared.span)),
            Kind::Start => break t,
            Kind::Decl | Kind::Doctype => {
                let name = if t.kind == Kind::Decl {
                    "XML declaration"
                } else {
                    "DOCTYPE"
                };
                let text = lex.owned(&t, 1024).await?.piece().text();
                cx.emit(text_node(name, lex.span(&t), &text));
            }
            _ => {}
        }
    };
    let version = {
        let tag = lex.owned(&plist, 1024).await?;
        xml::attributes(tag.piece())
            .into_iter()
            .find(|a| a.name.bytes() == b"version")
            .and_then(|a| a.value.map(|v| v.text()))
    };
    if let Some(v) = &version {
        cx.emit(Node::new("Version").value(Value::Text(v.clone())));
    }
    let Some(top) = next_child(&mut lex).await? else {
        return Ok(());
    };
    let kind = String::from_utf8_lossy(&top.name).into_owned();
    match top.name.as_slice() {
        b"dict" | b"array" => {
            let dict = top.name == b"dict";
            let count = if dict {
                plural(top.ext.elements / 2, "key", "keys")
            } else {
                plural(top.ext.elements, "element", "elements")
            };
            cx.annotate(format!("Property list (XML), {kind} with {count}"));
            let span = lex.scan.span(top.open.start, top.ext.end);
            let mut inner = Lexer::new(&cx, span, Mode::Xml);
            inner.next().await?;
            members(&cx, &mut inner, dict, input).await
        }
        _ => {
            let node = value_node(&mut lex, &top, "Value".to_owned(), input).await?;
            if let Some(Value::Text(t)) = &node.value {
                cx.annotate(format!("Property list (XML), {kind}: {}", preview(t, 60)));
            }
            cx.emit(node);
            Ok(())
        }
    }
}
