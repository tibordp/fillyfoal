//! XMP metadata (ISO 16684-1): sidecar `.xmp` files and the packets
//! embedded in JPEG, TIFF, PNG, WebP, HEIF, JPEG XL, PSD, PDF and others.
//!
//! An XMP packet is RDF/XML. Beside the plain XML tree, the packet is read
//! as XMP's data model: properties grouped by schema (namespace prefix),
//! with simple values, arrays (`rdf:Seq`, `rdf:Bag`, `rdf:Alt`, with
//! language alternatives) and structures (nested `rdf:Description` or
//! `rdf:parseType="Resource"`), including properties written as
//! attributes. The XML lexer of `text::xml` does the tokenizing.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::text::probe;
use crate::formats::text::scan::Scanner;
use crate::formats::text::xml::{self, Kind, Lexer, Mode};
use crate::formats::util::fmt::{clip, plural};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

pub static FORMAT: Format = Format {
    name: "xmp",
    title: "XMP metadata",
    extensions: &["xmp"],
    mime: "application/rdf+xml",
    probe: Probe::Custom(probe_xmp),
    dissect: crate::expander!(dissect: Input),
};

fn probe_xmp(h: &Head<'_>) -> bool {
    probe::is_text(h)
        && xml::root(h).is_some_and(|r| r.local() == b"xmpmeta" || r.local() == b"xapmeta")
}

/// Properties read before giving up.
const MAX_PROPS: usize = 20_000;
/// Element nesting followed.
const MAX_DEPTH: usize = 64;
/// Text kept per value.
const TEXT_CAP: usize = 4096;

#[derive(Clone, Debug)]
struct Prop {
    name: String,
    value: Val,
    span: Span,
    lang: Option<String>,
}

#[derive(Clone, Debug)]
enum Val {
    Text(String),
    Uri(String),
    Array(&'static str, Arc<Vec<Prop>>),
    Struct(Arc<Vec<Prop>>),
}

enum Frame {
    /// Outside the RDF data (`x:xmpmeta`, `rdf:RDF`, unknown markup).
    Other,
    /// A node element: `rdf:Description`, a typed node or an array.
    Node {
        container: Option<&'static str>,
        props: Vec<Prop>,
    },
    /// A property element.
    Prop {
        name: String,
        lang: Option<String>,
        start: u64,
        text: String,
        value: Option<Val>,
        /// Its content is a structure's fields (parseType="Resource", or
        /// fields given as attributes).
        resource: bool,
        props: Vec<Prop>,
    },
}

struct Attr {
    name: String,
    value: String,
    span: Span,
}

/// Attributes that are RDF syntax rather than properties.
fn is_syntax(name: &str) -> bool {
    name.starts_with("xmlns")
        || matches!(
            name,
            "rdf:about"
                | "rdf:ID"
                | "rdf:nodeID"
                | "rdf:parseType"
                | "rdf:resource"
                | "rdf:datatype"
                | "xml:lang"
                | "x:xmptk"
                | "x:xaptk"
        )
}

fn attr_props(attrs: &[Attr]) -> Vec<Prop> {
    attrs
        .iter()
        .filter(|a| !is_syntax(&a.name))
        .map(|a| Prop {
            name: a.name.clone(),
            value: Val::Text(a.value.clone()),
            span: a.span,
            lang: None,
        })
        .collect()
}

fn attr<'a>(attrs: &'a [Attr], name: &str) -> Option<&'a str> {
    attrs
        .iter()
        .find(|a| a.name == name)
        .map(|a| a.value.as_str())
}

fn property(name: String, attrs: &[Attr], start: u64) -> Frame {
    let props = attr_props(attrs);
    Frame::Prop {
        name,
        lang: attr(attrs, "xml:lang").map(str::to_owned),
        start,
        text: String::new(),
        value: attr(attrs, "rdf:resource").map(|r| Val::Uri(r.to_owned())),
        resource: attr(attrs, "rdf:parseType") == Some("Resource") || !props.is_empty(),
        props,
    }
}

/// The frame a start tag opens, given the enclosing one.
fn open(parent: Option<&Frame>, name: String, attrs: &[Attr], start: u64) -> Frame {
    match parent {
        None | Some(Frame::Other) => {
            if name == "rdf:Description" {
                Frame::Node {
                    container: None,
                    props: attr_props(attrs),
                }
            } else {
                Frame::Other
            }
        }
        Some(Frame::Node { .. } | Frame::Prop { resource: true, .. }) => {
            property(name, attrs, start)
        }
        Some(Frame::Prop { .. }) => {
            let container = match name.as_str() {
                "rdf:Seq" => Some("Seq"),
                "rdf:Bag" => Some("Bag"),
                "rdf:Alt" => Some("Alt"),
                _ => None,
            };
            Frame::Node {
                container,
                props: if container.is_some() {
                    Vec::new()
                } else {
                    attr_props(attrs)
                },
            }
        }
    }
}

/// Closes the innermost frame at `end`, handing its value to its parent.
fn close(stack: &mut Vec<Frame>, out: &mut Vec<Prop>, scan: &Scanner<'_>, end: u64) {
    let Some(frame) = stack.pop() else {
        return;
    };
    match frame {
        Frame::Other => {}
        Frame::Node { container, props } => match stack.last_mut() {
            Some(Frame::Prop { value, .. }) => {
                *value = Some(match container {
                    Some(kind) => Val::Array(kind, Arc::new(props)),
                    None => Val::Struct(Arc::new(props)),
                });
            }
            _ => out.extend(props),
        },
        Frame::Prop {
            name,
            lang,
            start,
            text,
            value,
            resource,
            props,
        } => {
            let value = value.unwrap_or_else(|| {
                if resource {
                    Val::Struct(Arc::new(props))
                } else {
                    Val::Text(text.trim().to_owned())
                }
            });
            let prop = Prop {
                name,
                value,
                span: scan.span(start, end),
                lang,
            };
            match stack.last_mut() {
                Some(Frame::Node { props, .. } | Frame::Prop { props, .. }) => props.push(prop),
                _ => out.push(prop),
            }
        }
    }
}

struct Parsed {
    props: Vec<Prop>,
    /// Namespace prefixes declared in the packet.
    ns: BTreeMap<String, String>,
}

async fn parse(cx: &Cx, span: Span) -> Result<Parsed> {
    let mut lex = Lexer::new(cx, span, Mode::Xml);
    let mut stack: Vec<Frame> = Vec::new();
    let mut out = Vec::new();
    let mut ns = BTreeMap::new();
    let mut tokens = 0u32;
    loop {
        tokens = tokens.wrapping_add(1);
        if tokens.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => break,
            Kind::Start => {
                let name = String::from_utf8_lossy(&lex.name(&t).await?).into_owned();
                let owned = lex.owned(&t, 0x10000).await?;
                let attrs: Vec<Attr> = xml::attributes(owned.piece())
                    .iter()
                    .map(|a| Attr {
                        name: a.name.text(),
                        value: a
                            .value
                            .as_ref()
                            .map(|v| xml::decode_entities(&v.text(), false))
                            .unwrap_or_default(),
                        span: a.whole.span(),
                    })
                    .collect();
                for a in &attrs {
                    if let Some(prefix) = a.name.strip_prefix("xmlns:") {
                        ns.entry(prefix.to_owned())
                            .or_insert_with(|| a.value.clone());
                    }
                }
                let frame = if stack.len() >= MAX_DEPTH {
                    Frame::Other
                } else {
                    open(stack.last(), name, &attrs, t.start)
                };
                stack.push(frame);
                if t.empty {
                    close(&mut stack, &mut out, &lex.scan, t.end);
                }
            }
            Kind::End => close(&mut stack, &mut out, &lex.scan, t.end),
            Kind::Text | Kind::Cdata => {
                if let Some(Frame::Prop { text, .. }) = stack.last()
                    && text.len() < TEXT_CAP
                {
                    let piece = xml::token_text(&mut lex, &t).await?;
                    if let Some(Frame::Prop { text, .. }) = stack.last_mut() {
                        text.push_str(&piece);
                    }
                }
            }
            _ => {}
        }
        if out.len() >= MAX_PROPS {
            break;
        }
    }
    while !stack.is_empty() {
        let end = lex.scan.len();
        close(&mut stack, &mut out, &lex.scan, end);
    }
    Ok(Parsed { props: out, ns })
}

/// Schema names by namespace URI.
const SCHEMAS: &[(&str, &str)] = &[
    ("http://purl.org/dc/elements/1.1/", "Dublin Core"),
    ("http://ns.adobe.com/xap/1.0/", "XMP Basic"),
    (
        "http://ns.adobe.com/xap/1.0/rights/",
        "XMP Rights Management",
    ),
    ("http://ns.adobe.com/xap/1.0/mm/", "XMP Media Management"),
    ("http://ns.adobe.com/xap/1.0/bj/", "XMP Basic Job Ticket"),
    ("http://ns.adobe.com/xap/1.0/t/pg/", "XMP Paged-Text"),
    (
        "http://ns.adobe.com/xmp/1.0/DynamicMedia/",
        "XMP Dynamic Media",
    ),
    ("http://ns.adobe.com/xmp/note/", "XMP Note"),
    ("http://ns.adobe.com/photoshop/1.0/", "Photoshop"),
    ("http://ns.adobe.com/camera-raw-settings/1.0/", "Camera Raw"),
    ("http://ns.adobe.com/lightroom/1.0/", "Lightroom"),
    ("http://ns.adobe.com/tiff/1.0/", "TIFF"),
    ("http://ns.adobe.com/exif/1.0/", "Exif"),
    ("http://cipa.jp/exif/1.0/", "Exif 2.3 (CIPA)"),
    ("http://ns.adobe.com/exif/1.0/aux/", "Exif auxiliary"),
    ("http://ns.adobe.com/pdf/1.3/", "Adobe PDF"),
    ("http://ns.adobe.com/hdr-gain-map/1.0/", "HDR gain map"),
    ("http://ns.apple.com/HDRGainMap/1.0/", "Apple HDR gain map"),
    ("http://iptc.org/std/Iptc4xmpCore/1.0/xmlns/", "IPTC Core"),
    (
        "http://iptc.org/std/Iptc4xmpExt/2008-02-29/",
        "IPTC Extension",
    ),
    ("http://ns.useplus.org/ldf/xmp/1.0/", "PLUS"),
    ("http://ns.google.com/photos/1.0/camera/", "Google Camera"),
    ("http://ns.google.com/photos/1.0/image/", "Google Image"),
    (
        "http://ns.google.com/photos/1.0/container/",
        "Google Container",
    ),
    (
        "http://ns.google.com/photos/1.0/panorama/",
        "Google Photo Sphere",
    ),
    ("http://ns.microsoft.com/photo/1.0/", "Microsoft Photo"),
    ("http://creativecommons.org/ns#", "Creative Commons"),
];

/// A property's value as one line of text.
fn text_of(p: &Prop) -> Option<String> {
    match &p.value {
        Val::Text(t) | Val::Uri(t) => Some(t.clone()),
        Val::Array("Alt", items) => items
            .iter()
            .find(|i| i.lang.as_deref() == Some("x-default"))
            .or_else(|| items.first())
            .and_then(text_of),
        Val::Array(_, items) => {
            let shown: Vec<String> = items.iter().take(3).filter_map(text_of).collect();
            let more = if items.len() > 3 { ", …" } else { "" };
            (!shown.is_empty()).then(|| format!("{}{more}", shown.join(", ")))
        }
        Val::Struct(_) => None,
    }
}

fn find<'a>(props: &'a [Prop], name: &str) -> Option<&'a Prop> {
    props.iter().find(|p| p.name == name)
}

fn summarize(props: &[Prop]) -> String {
    let get = |name: &str| {
        find(props, name)
            .and_then(text_of)
            .filter(|t| !t.is_empty())
    };
    let mut parts = Vec::new();
    if let Some(title) = get("dc:title") {
        parts.push(format!("{:?}", clip(&title, 60)));
    }
    if let Some(creator) = get("dc:creator") {
        parts.push(format!("by {}", clip(&creator, 60)));
    }
    if let Some(rating) = get("xmp:Rating") {
        parts.push(format!("rated {rating}"));
    }
    if let Some(n) = find(props, "dc:subject").and_then(|p| match &p.value {
        Val::Array(_, items) => Some(items.len()),
        _ => None,
    }) {
        parts.push(format!("{n} keywords"));
    }
    match (get("tiff:Make"), get("tiff:Model")) {
        (Some(make), Some(model)) if !model.starts_with(&make) => {
            parts.push(format!("{make} {model}"));
        }
        (_, Some(model)) => parts.push(model),
        (Some(make), None) => parts.push(make),
        (None, None) => {}
    }
    if let Some(date) = [
        "exif:DateTimeOriginal",
        "photoshop:DateCreated",
        "xmp:CreateDate",
    ]
    .into_iter()
    .find_map(get)
    {
        parts.push(date);
    }
    if let Some(tool) = get("xmp:CreatorTool") {
        parts.push(clip(&tool, 60));
    }
    let n = props.len();
    let count = if n == 1 {
        "1 property".to_owned()
    } else {
        format!("{n} properties")
    };
    if parts.is_empty() {
        format!("XMP metadata, {count}")
    } else {
        format!("XMP metadata, {count}: {}", parts.join(", "))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let parsed = parse(&cx, input.span).await?;
    cx.annotate(summarize(&parsed.props));
    // Group by namespace prefix, in order of first appearance.
    let mut order: Vec<(String, Vec<Prop>)> = Vec::new();
    let mut index: BTreeMap<String, usize> = BTreeMap::new();
    for (i, p) in parsed.props.into_iter().enumerate() {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        let prefix = p.name.split_once(':').map_or("", |(a, _)| a).to_owned();
        let slot = *index.entry(prefix.clone()).or_insert_with(|| {
            order.push((prefix, Vec::new()));
            order.len().saturating_sub(1)
        });
        if let Some((_, group)) = order.get_mut(slot) {
            group.push(p);
        }
    }
    for (prefix, props) in order {
        let uri = parsed.ns.get(&prefix).cloned().unwrap_or_default();
        let schema = SCHEMAS
            .iter()
            .find(|(u, _)| *u == uri)
            .map(|(_, name)| *name);
        let name = match schema {
            Some(s) => format!("{s} ({prefix})"),
            None if prefix.is_empty() => "Properties".to_owned(),
            None => prefix.clone(),
        };
        let n = props.len();
        let mut node = Node::new(name)
            .summary(if n == 1 {
                "1 property".to_owned()
            } else {
                format!("{n} properties")
            })
            .lazy(list, Arc::new(props));
        if !uri.is_empty() {
            node = node.desc(uri);
        }
        cx.emit(node);
    }
    cx.emit(
        Node::new("XML")
            .span(input.span)
            .summary("the packet as an XML tree")
            .lazy(tree, input),
    );
    Ok(())
}

async fn tree(cx: Cx, input: Input) -> Result<()> {
    xml::document(&cx, input, Mode::Xml).await
}

fn prop_node(p: &Prop, name: String) -> Node {
    let mut node = Node::new(name).span(p.span);
    let lang = p.lang.as_ref().map(|l| format!("xml:lang={l}"));
    match &p.value {
        Val::Text(t) => {
            node = node.value(Value::Text(t.clone()));
            if let Some(l) = lang {
                node = node.summary(l);
            }
        }
        Val::Uri(u) => {
            node = node.value(Value::Text(u.clone())).summary("resource");
        }
        Val::Array(kind, items) => {
            let count = items.len();
            let mut summary = format!("{kind}, {}", plural(to_u64(count), "item"));
            if *kind == "Alt"
                && let Some(t) = text_of(p)
            {
                node = node.value(Value::Text(t));
                summary = plural(to_u64(count), "language alternative");
            } else if let Some(t) = text_of(p) {
                summary = format!("{summary}: {}", clip(&t, 80));
            }
            node = node.summary(summary).lazy(list, items.clone());
        }
        Val::Struct(fields) => {
            let count = fields.len();
            node = node
                .summary(format!("structure, {}", plural(to_u64(count), "field")))
                .lazy(list, fields.clone());
        }
    }
    node
}

async fn list(cx: Cx, props: Arc<Vec<Prop>>) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(props.len())));
    for (i, p) in props.iter().enumerate() {
        let name = if p.name == "rdf:li" {
            format!("[{}]", i.saturating_add(1))
        } else {
            p.name.clone()
        };
        cx.push(prop_node(p, name)).await;
    }
    Ok(())
}
