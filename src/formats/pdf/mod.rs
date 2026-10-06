//! PDF documents.
//!
//! Expanding the file reads the header, `startxref`, and the chain of
//! cross-reference sections (classic tables and cross-reference streams,
//! newest first, following `/Prev` and `/XRefStm`). If that fails, objects
//! are found by scanning for `N G obj`. Everything else is lazy:
//!
//! - the trailer, catalog and info dictionaries, whose references expand
//!   into the objects they point to (the path of objects above a node is
//!   carried along, so `/Parent` loops end instead of recursing);
//! - the page tree, walked with a visited set;
//! - every object by number, including those inside object streams;
//! - each revision (incremental update) with its entries and trailer.
//!
//! Stream data is decompressed (FlateDecode, with PNG predictors) into
//! derived sources on demand; JPEG and JPEG 2000 data is dissected as is.

mod content;
mod objects;
mod syntax;

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::sync::Arc;

use objects::{Loc, Located, Section, SectionKind, Xref};
use syntax::{Item, Obj};

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Codec, Format, Head, Input, Probe, content};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

/// References followed below one another.
const MAX_DEPTH: usize = 48;
/// Where `%PDF-` may start (some files have junk before it).
const HEADER_WINDOW: u64 = 1024;

pub static FORMAT: Format = Format {
    name: "pdf",
    title: "Portable Document Format",
    extensions: &["pdf", "ai", "fdf"],
    mime: "application/pdf",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let window = h.data.get(..1024).unwrap_or(h.data);
    syntax::find(window, b"%PDF-", 0).is_some_and(|at| {
        h.data
            .get(at.saturating_add(5))
            .is_some_and(u8::is_ascii_digit)
    })
}

pub struct Doc {
    input: Input,
    /// The input from `%PDF-` on: offsets in the file are relative to it.
    region: Span,
    xref: Xref,
    /// Newest first.
    sections: Vec<Section>,
    trailer: Option<Located>,
}

pub type DocRef = Arc<Doc>;

/// Reads object `num`, wherever the cross-reference data says it is.
async fn resolve(cx: &Cx, doc: &Doc, num: u32) -> Result<Located> {
    match doc.xref.get(&num) {
        Some(&Loc::Offset { offset, .. }) => {
            let (found, _, located) =
                objects::object_at(cx, doc.region, offset, Some(&doc.xref)).await?;
            if found != num {
                return Err(Diagnostic::malformed(format!(
                    "cross-reference entry for object {num} points at object {found}"
                ))
                .at(located.whole));
            }
            Ok(located)
        }
        Some(&Loc::Compressed { stream, index }) => Ok(objects::in_object_stream(
            cx, doc.region, &doc.xref, stream, index,
        )
        .await?
        .1),
        Some(Loc::Free) => Err(Diagnostic::note(format!("object {num} is free"))),
        None => Err(Diagnostic::malformed(format!(
            "object {num} is not in the cross-reference data"
        ))),
    }
}

/// Resolves `item` if it is a reference; otherwise returns it as is.
async fn deref(cx: &Cx, doc: &Doc, item: &Item) -> Option<Item> {
    match item.reference() {
        Some((num, _)) => resolve(cx, doc, num).await.ok().map(|l| l.item),
        None => Some(item.clone()),
    }
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, HEADER_WINDOW)).await?;
    let start = syntax::find(&head, b"%PDF-", 0)
        .ok_or_else(|| Diagnostic::malformed("no %PDF- header").at(file.sub(0, 8)))?;
    let start = to_u64(start);
    let region = file.tail(start);
    let line_end = head
        .iter()
        .skip(crate::bytes::to_usize(start))
        .position(|&b| b == b'\r' || b == b'\n')
        .map_or(8, to_u64);
    let version = String::from_utf8_lossy(
        head.get(
            crate::bytes::to_usize(start).saturating_add(5)
                ..crate::bytes::to_usize(start.saturating_add(line_end)),
        )
        .unwrap_or_default(),
    )
    .trim()
    .to_owned();
    if start > 0 {
        cx.emit(Node::new("Leading data").span(file.sub(0, start)));
    }
    cx.emit(
        Node::new("Header")
            .span(region.sub(0, line_end))
            .value(Value::Text(version.clone()))
            .desc("PDF version"),
    );

    // startxref, near the end.
    let tail_len = region.len.min(2048);
    let tail_at = region.len.saturating_sub(tail_len);
    let tail = cx.read_avail(region.sub(tail_at, tail_len)).await?;
    let startxref = syntax::rfind(&tail, b"startxref").and_then(|at| {
        let mut p = syntax::Parser::at(&tail, at.saturating_add(9), true);
        p.uint()
            .ok()
            .map(|v| (tail_at.saturating_add(to_u64(at)), v))
    });

    let mut diags = Vec::new();
    let (sections, chain_error) = match startxref {
        Some((_, offset)) => objects::chain(&cx, region, offset).await,
        None => (Vec::new(), Some(Diagnostic::malformed("no startxref"))),
    };
    let mut xref = Xref::new();
    for section in &sections {
        for &(num, loc) in &section.entries {
            xref.entry(num).or_insert(loc);
        }
    }
    let mut trailer = sections.first().and_then(|s| s.trailer.clone());
    let mut scanned = false;
    if let Some(e) = chain_error {
        diags.push(e);
    }
    if sections.is_empty() || trailer.as_ref().and_then(|t| t.item.get("Root")).is_none() {
        let (found, scanned_trailer) = objects::scan(&cx, region).await?;
        for (num, loc) in found {
            xref.entry(num).or_insert(loc);
        }
        if trailer.as_ref().and_then(|t| t.item.get("Root")).is_none() {
            trailer = scanned_trailer.or(trailer);
        }
        scanned = true;
        diags.push(Diagnostic::warning(
            "cross-reference data unusable; objects were found by scanning",
        ));
    }
    let doc: DocRef = Arc::new(Doc {
        input,
        region,
        xref,
        sections,
        trailer,
    });
    for d in diags {
        cx.diag(d);
    }

    cx.annotate(annotation(&cx, &doc, &version).await);

    let path: Arc<Vec<u32>> = Arc::new(Vec::new());
    if let Some(trailer) = &doc.trailer {
        let item = &trailer.item;
        cx.emit(item_node(&doc, "Trailer".into(), item, trailer.base, &path).span(trailer.whole));
        if let Some(root) = item.get("Root") {
            cx.emit(item_node(
                &doc,
                "Document Catalog".into(),
                root,
                trailer.base,
                &path,
            ));
        }
        if let Some(info) = item.get("Info") {
            cx.emit(item_node(
                &doc,
                "Document Information".into(),
                info,
                trailer.base,
                &path,
            ));
        }
        if item.get("Encrypt").is_some() {
            cx.diag(Diagnostic::unsupported(
                "encrypted document: strings and streams are shown as stored",
            ));
        }
    }
    cx.emit(
        Node::new("Pages")
            .desc("The page tree, in reading order")
            .lazy(pages, doc.clone()),
    );
    cx.emit(
        Node::new("Objects")
            .summary(format!("{} entries", doc.xref.len()))
            .desc("Every object in the cross-reference data, by number")
            .lazy(objects_list, doc.clone()),
    );
    if !doc.sections.is_empty() {
        cx.emit(
            Node::new("Revisions")
                .summary(format!(
                    "{} cross-reference section{}",
                    doc.sections.len(),
                    if doc.sections.len() == 1 { "" } else { "s" }
                ))
                .desc("The original file and its incremental updates, oldest first")
                .lazy(revisions, doc.clone()),
        );
    }
    if let Some((at, offset)) = startxref {
        let len = tail
            .len()
            .saturating_sub(crate::bytes::to_usize(at.saturating_sub(tail_at)));
        let mut node = Node::new("startxref")
            .span(region.sub(at, to_u64(len)))
            .value(Value::UInt {
                value: offset,
                bits: 64,
                radix: Radix::Hex,
            });
        if !scanned {
            node = node.target(region.sub(offset, 4));
        }
        cx.emit(node);
    }
    Ok(())
}

async fn annotation(cx: &Cx, doc: &Doc, version: &str) -> String {
    let mut out = format!("PDF {version}");
    let Some(trailer) = &doc.trailer else {
        return out;
    };
    if let Some(root) = trailer.item.get("Root")
        && let Some(catalog) = deref(cx, doc, root).await
    {
        if let Some(v) = catalog.get("Version").and_then(Item::name) {
            out = format!("PDF {v} (header {version})");
        }
        if let Some(pages) = catalog.get("Pages")
            && let Some(pages) = deref(cx, doc, pages).await
            && let Some(count) = pages.get("Count").and_then(Item::int)
        {
            out = format!("{out}, {count} page{}", if count == 1 { "" } else { "s" });
        }
    }
    if doc.sections.len() > 1 {
        out = format!("{out}, {} revisions", doc.sections.len());
    }
    if let Some(info) = trailer.item.get("Info")
        && let Some(info) = deref(cx, doc, info).await
    {
        for key in ["Title", "Producer"] {
            if let Some(Obj::Str { bytes, .. }) = info.get(key).map(|i| &i.obj) {
                let text = syntax::text(bytes);
                if !text.is_empty() {
                    out = format!("{out}, {} {text:?}", key.to_lowercase());
                }
            }
        }
    }
    if trailer.item.get("Encrypt").is_some() {
        out.push_str(", encrypted");
    }
    out
}

// ---------------------------------------------------------------------------
// Objects as nodes

#[derive(Clone)]
struct ItemState {
    doc: DocRef,
    item: Item,
    base: Span,
    path: Arc<Vec<u32>>,
}

#[derive(Clone)]
struct ObjState {
    doc: DocRef,
    num: u32,
    path: Arc<Vec<u32>>,
}

/// A one-line rendering for summaries.
fn short(item: &Item) -> String {
    match &item.obj {
        Obj::Null => "null".to_owned(),
        Obj::Bool(b) => b.to_string(),
        Obj::Int(v) => v.to_string(),
        Obj::Real(v) => v.to_string(),
        Obj::Name(n) => format!("/{n}"),
        Obj::Ref(n, g) => format!("{n} {g} R"),
        Obj::Str { bytes, .. } => {
            let text: String = syntax::text(bytes).chars().take(24).collect();
            format!("({text})")
        }
        Obj::Array(items) => format!("[{} items]", items.len()),
        Obj::Dict(entries) => format!("<<{} entries>>", entries.len()),
    }
}

fn dict_summary(item: &Item) -> String {
    let Obj::Dict(entries) = &item.obj else {
        return short(item);
    };
    let kind: Vec<String> = ["Type", "Subtype", "S"]
        .iter()
        .filter_map(|k| item.get(k).and_then(Item::name).map(|n| format!("/{n}")))
        .collect();
    if kind.is_empty() {
        format!("{} entries", entries.len())
    } else {
        format!("{}, {} entries", kind.join(" "), entries.len())
    }
}

fn array_summary(items: &[Item]) -> String {
    let preview: Vec<String> = items.iter().take(6).map(short).collect();
    let more = if items.len() > 6 { " …" } else { "" };
    format!("[{}{more}]", preview.join(" "))
}

fn item_node(
    doc: &DocRef,
    name: Cow<'static, str>,
    item: &Item,
    base: Span,
    path: &Arc<Vec<u32>>,
) -> Node {
    let span = base.sub(to_u64(item.start), syntax::len_u64(item));
    let node = Node::new(name).span(span);
    let state = || ItemState {
        doc: doc.clone(),
        item: item.clone(),
        base,
        path: path.clone(),
    };
    match &item.obj {
        Obj::Null => node.summary("null"),
        Obj::Bool(b) => node.value(Value::Bool(*b)),
        Obj::Int(v) => node.value(Value::Int {
            value: *v,
            bits: 64,
        }),
        Obj::Real(v) => node.value(Value::Float(*v)),
        Obj::Name(n) => node.value(Value::Text(format!("/{n}"))),
        Obj::Str { bytes, hex } => {
            let node = if syntax::is_text(bytes) {
                node.value(Value::Text(syntax::text(bytes)))
            } else {
                node.value(Value::Bytes(bytes.iter().take(64).copied().collect()))
                    .summary(format!("{} bytes", bytes.len()))
            };
            if *hex && node.summary.is_none() {
                node.summary("hex string")
            } else {
                node
            }
        }
        Obj::Ref(num, generation) => reference(doc, node, *num, *generation, path),
        Obj::Array(items) => node
            .summary(array_summary(items))
            .lazy(crate::expander!(self::array_children: ItemState), state()),
        Obj::Dict(_) => node
            .summary(dict_summary(item))
            .lazy(crate::expander!(self::dict_children: ItemState), state()),
    }
}

/// A reference: expands into the object it points to, unless that object is
/// already open above (a cycle such as `/Parent`) or the path is too deep.
fn reference(doc: &DocRef, node: Node, num: u32, generation: u16, path: &Arc<Vec<u32>>) -> Node {
    let mut node = node.value(Value::Text(format!("{num} {generation} R")));
    match doc.xref.get(&num) {
        Some(&Loc::Offset { offset, .. }) => node = node.target(doc.region.sub(offset, 0)),
        Some(Loc::Compressed { stream, .. }) => {
            node = node.summary(format!("in object stream {stream}"))
        }
        Some(Loc::Free) => return node.summary("free object"),
        None => return node.diag(Diagnostic::warning(format!("object {num} does not exist"))),
    }
    if path.contains(&num) {
        return node.summary("already open above");
    }
    if path.len() >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "references followed deeper than {MAX_DEPTH}"
        )));
    }
    let mut path = path.to_vec();
    path.push(num);
    node.lazy(
        crate::expander!(self::object_children: ObjState),
        ObjState {
            doc: doc.clone(),
            num,
            path: Arc::new(path),
        },
    )
}

async fn array_children(cx: Cx, state: ItemState) -> Result<()> {
    let Some(items) = state.item.array() else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(items.len())));
    for (i, item) in items.iter().enumerate() {
        cx.push(item_node(
            &state.doc,
            format!("[{i}]").into(),
            item,
            state.base,
            &state.path,
        ))
        .await;
    }
    Ok(())
}

async fn dict_children(cx: Cx, state: ItemState) -> Result<()> {
    let Obj::Dict(entries) = &state.item.obj else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for entry in entries.iter() {
        let node = item_node(
            &state.doc,
            format!("/{}", entry.key).into(),
            &entry.value,
            state.base,
            &state.path,
        );
        // The span covers the key too.
        let span = state.base.sub(
            to_u64(entry.key_start),
            to_u64(entry.value.end.saturating_sub(entry.key_start)),
        );
        cx.push(node.span(span)).await;
    }
    Ok(())
}

/// One line describing an object.
fn describe(located: &Located) -> String {
    let base = match &located.item.obj {
        Obj::Dict(_) => dict_summary(&located.item),
        _ => short(&located.item),
    };
    match located.data {
        Some(data) => {
            let filters = objects::filters(&located.item);
            let filters = if filters.is_empty() {
                String::new()
            } else {
                format!(
                    ", {}",
                    filters
                        .iter()
                        .map(|f| format!("/{f}"))
                        .collect::<Vec<_>>()
                        .join(" ")
                )
            };
            format!("stream, {base}, {} bytes{filters}", data.len)
        }
        None => base,
    }
}

/// The contents of object `num`: a dictionary's entries (and stream data),
/// an array's items, or the value.
async fn object_children(cx: Cx, state: ObjState) -> Result<()> {
    let located = resolve(&cx, &state.doc, state.num).await?;
    cx.annotate(describe(&located));
    emit_object(&cx, &state.doc, &located, &state.path).await
}

async fn emit_object(cx: &Cx, doc: &DocRef, located: &Located, path: &Arc<Vec<u32>>) -> Result<()> {
    let item = &located.item;
    match &item.obj {
        Obj::Dict(entries) => {
            for entry in entries.iter() {
                let span = located.base.sub(
                    to_u64(entry.key_start),
                    to_u64(entry.value.end.saturating_sub(entry.key_start)),
                );
                cx.emit(
                    item_node(
                        doc,
                        format!("/{}", entry.key).into(),
                        &entry.value,
                        located.base,
                        path,
                    )
                    .span(span),
                );
            }
        }
        Obj::Array(items) => {
            for (i, it) in items.iter().enumerate() {
                cx.emit(item_node(
                    doc,
                    format!("[{i}]").into(),
                    it,
                    located.base,
                    path,
                ));
            }
        }
        _ => cx.emit(item_node(doc, "Value".into(), item, located.base, path)),
    }
    if located.data.is_some() {
        cx.emit(stream_data(doc, located));
        if looks_like_content(item) {
            cx.emit(
                Node::new("Content operators")
                    .desc("The stream read as a content stream (page or form drawing operators)")
                    .lazy(content_operators, located.clone()),
            );
        }
        if item.get("Type").and_then(Item::name) == Some("ObjStm") {
            cx.emit(
                Node::new("Contained objects")
                    .summary(format!(
                        "{} objects",
                        item.get("N").and_then(Item::int).unwrap_or(0)
                    ))
                    .lazy(
                        contained_objects,
                        (doc.clone(), located.clone(), path.clone()),
                    ),
            );
        }
    }
    Ok(())
}

/// The data of a stream, decoded on expansion.
fn stream_data(doc: &DocRef, located: &Located) -> Node {
    let Some(data) = located.data else {
        return Node::new("Stream data");
    };
    let input = doc.input;
    let names = objects::filters(&located.item);
    let expected = located
        .item
        .get("DL")
        .and_then(Item::int)
        .and_then(|n| u64::try_from(n).ok());
    let has_predictor = located
        .item
        .get("DecodeParms")
        .is_some_and(|p| p.get("Predictor").and_then(Item::int).unwrap_or(1) > 1);
    let name = "Stream data";
    match names
        .iter()
        .map(String::as_str)
        .collect::<Vec<_>>()
        .as_slice()
    {
        [] => {
            content(name, input, data, Codec::Stored, None).summary(format!("{} bytes", data.len))
        }
        ["FlateDecode" | "Fl"] if !has_predictor => {
            content(name, input, data, Codec::Zlib, expected)
                .summary(format!("{} bytes, FlateDecode", data.len))
        }
        ["FlateDecode" | "Fl"] => Node::new(name)
            .span(data)
            .summary(format!("{} bytes, FlateDecode with predictor", data.len))
            .lazy(decoded_stream, (input, located.clone())),
        ["DCTDecode" | "DCT"] => {
            content(name, input, data, Codec::Stored, None).summary("JPEG image")
        }
        ["JPXDecode"] => content(name, input, data, Codec::Stored, None).summary("JPEG 2000 image"),
        _ => Node::new(name)
            .span(data)
            .summary(format!("{} bytes", data.len))
            .diag(Diagnostic::unsupported(format!(
                "stream filter {}",
                names
                    .iter()
                    .map(|f| format!("/{f}"))
                    .collect::<Vec<_>>()
                    .join(" ")
            ))),
    }
}

/// Streams without a type are usually page contents; forms say /Form.
fn looks_like_content(dict: &Item) -> bool {
    let subtype = dict.get("Subtype").and_then(Item::name);
    let typed = dict.get("Type").is_some() || subtype.is_some();
    let other = ["Length1", "Length2", "N", "Width"]
        .iter()
        .any(|k| dict.get(k).is_some());
    (!typed && !other) || subtype == Some("Form")
}

async fn content_operators(cx: Cx, located: Located) -> Result<()> {
    let span = objects::decode(&cx, &located).await?;
    content::operators(&cx, span).await
}

async fn decoded_stream(cx: Cx, (input, located): (Input, Located)) -> Result<()> {
    let span = objects::decode(&cx, &located).await?;
    cx.annotate(format!("{:#x} bytes decoded", span.len));
    crate::formats::dissect_or_data(cx, input.nested(span)).await
}

async fn contained_objects(
    cx: Cx,
    (doc, objstm, path): (DocRef, Located, Arc<Vec<u32>>),
) -> Result<()> {
    let decoded = objects::decode(&cx, &objstm).await?;
    let index = objects::object_stream_index(&cx, &objstm, decoded).await?;
    cx.set_count(Count::Exact(to_u64(index.len())));
    for (num, offset) in index {
        let num = u32::try_from(num).unwrap_or(u32::MAX);
        let node = Node::new(format!("Object {num}")).span(decoded.sub(offset, 0));
        cx.push(
            reference(&doc, node, num, 0, &path)
                .summary(format!("at {offset:#x} in the decoded stream")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Collections

async fn objects_list(cx: Cx, doc: DocRef) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(doc.xref.len())));
    for (&num, &loc) in &doc.xref {
        let label = match loc {
            Loc::Offset { generation, .. } => format!("Object {num} {generation}"),
            _ => format!("Object {num}"),
        };
        let path = Arc::new(vec![num]);
        let node = match loc {
            Loc::Free => Node::new(label).summary("free"),
            _ => match resolve(&cx, &doc, num).await {
                Ok(located) => {
                    let summary = match loc {
                        Loc::Compressed { stream, .. } => {
                            format!("{} (in object stream {stream})", describe(&located))
                        }
                        _ => describe(&located),
                    };
                    Node::new(label).span(located.whole).summary(summary).lazy(
                        object_children,
                        ObjState {
                            doc: doc.clone(),
                            num,
                            path,
                        },
                    )
                }
                Err(e) => Node::new(label).diag(e),
            },
        };
        cx.push(node).await;
    }
    Ok(())
}

/// The page tree in order: a depth-first walk from the catalog's /Pages,
/// skipping nodes already visited.
async fn pages(cx: Cx, doc: DocRef) -> Result<()> {
    let Some(trailer) = &doc.trailer else {
        return Ok(());
    };
    let root = trailer
        .item
        .get("Root")
        .ok_or_else(|| Diagnostic::malformed("trailer has no /Root"))?;
    let catalog = deref(&cx, &doc, root)
        .await
        .ok_or_else(|| Diagnostic::malformed("document catalog is unreadable"))?;
    let top = catalog
        .get("Pages")
        .and_then(Item::reference)
        .ok_or_else(|| Diagnostic::malformed("catalog has no /Pages reference"))?;
    let mut stack = vec![top.0];
    let mut seen = BTreeSet::new();
    let mut number = 0u64;
    while let Some(num) = stack.pop() {
        cx.checkpoint().await;
        if !seen.insert(num) {
            cx.diag(Diagnostic::malformed(format!(
                "page tree visits object {num} twice"
            )));
            continue;
        }
        if seen.len() > doc.xref.len().saturating_add(1) {
            break;
        }
        let located = match resolve(&cx, &doc, num).await {
            Ok(l) => l,
            Err(e) => {
                cx.diag(e);
                continue;
            }
        };
        let kind = located.item.get("Type").and_then(Item::name);
        let kids = located.item.get("Kids").and_then(Item::array);
        match (kind, kids) {
            (Some("Pages"), Some(kids)) | (None, Some(kids)) => {
                stack.extend(
                    kids.iter()
                        .rev()
                        .filter_map(Item::reference)
                        .map(|(n, _)| n),
                );
            }
            _ => {
                number = number.saturating_add(1);
                let mut summary = format!("object {num}");
                if let Some(mb) = located.item.get("MediaBox").and_then(Item::array) {
                    let v: Vec<f64> = mb
                        .iter()
                        .filter_map(|i| match i.obj {
                            Obj::Int(n) => Some(n as f64),
                            Obj::Real(r) => Some(r),
                            _ => None,
                        })
                        .collect();
                    if let [x0, y0, x1, y1] = v.as_slice() {
                        summary = format!("{summary}, {}×{} pt", x1 - x0, y1 - y0);
                    }
                }
                let path = Arc::new(vec![num]);
                cx.push(
                    Node::new(format!("Page {number}"))
                        .span(located.whole)
                        .summary(summary)
                        .lazy(
                            object_children,
                            ObjState {
                                doc: doc.clone(),
                                num,
                                path,
                            },
                        ),
                )
                .await;
            }
        }
    }
    Ok(())
}

async fn revisions(cx: Cx, doc: DocRef) -> Result<()> {
    let count = doc.sections.len();
    cx.set_count(Count::Exact(to_u64(count)));
    for (i, section) in doc.sections.iter().rev().enumerate() {
        let kind = match section.kind {
            SectionKind::Table => "cross-reference table",
            SectionKind::Stream => "cross-reference stream",
        };
        let label = if i == 0 {
            "original".to_owned()
        } else {
            format!("update {i}")
        };
        cx.push(
            Node::new(format!("Revision {}", i.saturating_add(1)))
                .span(section.span)
                .summary(format!(
                    "{label}: {kind} at {:#x}, {} entries",
                    section.offset,
                    section.entries.len()
                ))
                .lazy(
                    revision,
                    (doc.clone(), count.saturating_sub(i).saturating_sub(1)),
                ),
        )
        .await;
    }
    Ok(())
}

async fn revision(cx: Cx, (doc, index): (DocRef, usize)) -> Result<()> {
    let Some(section) = doc.sections.get(index) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Entries")
            .span(section.span)
            .summary(format!("{} objects", section.entries.len()))
            .lazy(section_entries, (doc.clone(), index)),
    );
    if let Some(trailer) = &section.trailer {
        let path = Arc::new(Vec::new());
        let name = match section.kind {
            SectionKind::Table => "Trailer",
            SectionKind::Stream => "Stream dictionary",
        };
        cx.emit(
            item_node(&doc, name.into(), &trailer.item, trailer.base, &path).span(trailer.whole),
        );
        if section.kind == SectionKind::Stream {
            cx.emit(stream_data(&doc, trailer));
        }
    }
    Ok(())
}

async fn section_entries(cx: Cx, (doc, index): (DocRef, usize)) -> Result<()> {
    let Some(section) = doc.sections.get(index) else {
        return Ok(());
    };
    cx.set_count(Count::Exact(to_u64(section.entries.len())));
    for &(num, loc) in &section.entries {
        let node = Node::new(format!("Object {num}"));
        let node = match loc {
            Loc::Free => node.summary("free"),
            Loc::Offset { offset, generation } => node
                .value(Value::UInt {
                    value: offset,
                    bits: 64,
                    radix: Radix::Hex,
                })
                .summary(format!("in use, generation {generation}"))
                .target(doc.region.sub(offset, 0)),
            Loc::Compressed { stream, index } => {
                node.summary(format!("object stream {stream}, index {index}"))
            }
        };
        cx.push(node).await;
    }
    Ok(())
}
