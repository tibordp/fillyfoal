//! PDF documents (ISO 32000-2), structure rather than layout.
//!
//! Expanding the file reads the header, `startxref`, and the chain of
//! cross-reference sections (classic tables and cross-reference streams,
//! newest first, following `/Prev` and `/XRefStm`). If that fails, objects
//! are found by scanning for `N G obj`. Everything else is lazy:
//!
//! - the file as written: each revision (the original and every
//!   incremental update) with its body objects in file order, its
//!   cross-reference table (subsections and 20-byte entries) or stream
//!   (decoded rows), its trailer, `startxref` and `%%EOF`;
//! - the linearization dictionary and the primary hint stream's page offset
//!   and shared object hint tables;
//! - the trailer, catalog and information dictionaries, whose references
//!   expand into the objects they point to (the path of objects above a
//!   node is carried along, so `/Parent` loops end instead of recursing);
//!   physical views (bodies, object streams) show references as links
//!   instead, so each object is dissected where it is written;
//! - the page tree (sizes, inherited media boxes), outlines, form fields,
//!   signatures (`/ByteRange` coverage and the PKCS #7 `/Contents`) and the
//!   encryption dictionary (permissions, crypt filters, key check).
//!
//! Stream data is decoded on demand through its filter chain (Flate and
//! LZW with predictors, ASCII85, ASCIIHex, RunLength, decryption) and handed
//! to the dissector for what it holds: JPEG and JPEG 2000 images, ICC
//! profiles, XMP packets, CFF, TrueType and OpenType font programs, Type 1
//! fonts (clear text and decrypted private part), embedded files, object
//! streams, cross-reference streams; content streams and CMaps are split
//! into operators.

mod content;
mod crypt;
mod document;
mod hints;
mod objects;
mod streams;
mod syntax;

use std::borrow::Cow;
use std::collections::{BTreeMap, BTreeSet};
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use objects::{Loc, Located, Section, SectionKind, Tail, Xref};
use syntax::{Item, Obj};

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{self, plural};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Radix, Value};

/// References followed below one another.
const MAX_DEPTH: usize = 48;
/// Where `%PDF-` may start (some files have junk before it).
const HEADER_WINDOW: u64 = 1024;
/// Bytes of a string shown as its value.
const MAX_SHOWN_TEXT: usize = 64 << 10;

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
    crate::bytes::find(window, b"%PDF-", 0).is_some_and(|at| {
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
    /// The standard security handler, for encrypted documents.
    security: Option<Arc<crypt::Security>>,
    /// The linearization parameter dictionary (the first object), if any.
    linearized: Option<Located>,
    /// The revisions in file order.
    revisions: Vec<Revision>,
    /// Every object stored at a file offset (by any section), by offset:
    /// its number and generation.
    by_offset: BTreeMap<u64, (u32, u16)>,
}

pub type DocRef = Arc<Doc>;

/// One revision as written: the bytes from the end of the previous one to
/// its `%%EOF`.
#[derive(Clone, Copy, Debug)]
struct Revision {
    /// Its cross-reference section (an index in `Doc::sections`).
    section: usize,
    start: u64,
    end: u64,
    tail: Option<Tail>,
}

/// How references below a node behave: a logical view follows them into
/// the objects they point to; a physical view (where objects are listed as
/// written) shows them as links.
#[derive(Clone)]
struct Walk {
    /// Objects open above (to stop at cycles).
    path: Arc<Vec<u32>>,
    follow: bool,
}

impl Walk {
    fn logical() -> Self {
        Walk {
            path: Arc::new(Vec::new()),
            follow: true,
        }
    }

    fn physical() -> Self {
        Walk {
            path: Arc::new(Vec::new()),
            follow: false,
        }
    }
}

/// Reads object `num`, wherever the cross-reference data says it is.
async fn resolve(cx: &Cx, doc: &Doc, num: u32) -> Result<Located> {
    match doc.xref.get(&num) {
        Some(&Loc::Offset { offset, .. }) => {
            let located = located_at(cx, doc, offset).await?;
            match located.id {
                Some((found, _)) if found != num => Err(Diagnostic::malformed(format!(
                    "cross-reference entry for object {num} points at object {found}"
                ))
                .at(located.whole)),
                _ => Ok(located),
            }
        }
        Some(&Loc::Compressed { stream, index }) => Ok(objects::in_object_stream(
            cx,
            doc.region,
            &doc.xref,
            stream,
            index,
            doc.security.as_ref(),
        )
        .await?
        .1),
        Some(Loc::Free { .. }) => Err(Diagnostic::note(format!("object {num} is free"))),
        None => Err(Diagnostic::malformed(format!(
            "object {num} is not in the cross-reference data"
        ))),
    }
}

/// The indirect object at `offset`, with its strings decrypted.
async fn located_at(cx: &Cx, doc: &Doc, offset: u64) -> Result<Located> {
    let (_, _, mut located) = objects::object_at(cx, doc.region, offset, Some(&doc.xref)).await?;
    decrypt_strings(cx, doc, &mut located).await;
    Ok(located)
}

/// Replaces the strings of an encrypted object with their plaintext, when
/// the key is known without asking (the empty password, or one entered
/// earlier). Spans still cover the encrypted bytes.
async fn decrypt_strings(cx: &Cx, doc: &Doc, located: &mut Located) {
    let (Some(security), Some(id)) = (&doc.security, located.id) else {
        return;
    };
    if security.strings == crypt::Method::Identity {
        return;
    }
    // The encryption dictionary's own strings are not encrypted.
    if let Some(trailer) = &doc.trailer
        && trailer.item.get("Encrypt").and_then(Item::reference) == Some(id)
    {
        return;
    }
    let Some(key) = crypt::file_key(cx, security, false).await else {
        return;
    };
    let key = security.string_key(&key, id);
    let mut visited = 0u32;
    decrypt_walk(cx, security, &key, &mut located.item, 0, &mut visited).await;
}

/// Decrypts the strings in `item`, suspending every few hundred items (and
/// within long strings).
fn decrypt_walk<'a>(
    cx: &'a Cx,
    security: &'a crypt::Security,
    key: &'a [u8],
    item: &'a mut Item,
    depth: u32,
    visited: &'a mut u32,
) -> Pin<Box<dyn Future<Output = ()> + Send + 'a>> {
    Box::pin(async move {
        if depth > 64 {
            return;
        }
        *visited = visited.wrapping_add(1);
        if visited.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        match &mut item.obj {
            Obj::Str { bytes, .. } => *bytes = security.decrypt_string(cx, key, bytes).await,
            Obj::Array(items) => {
                for it in Arc::make_mut(items) {
                    decrypt_walk(cx, security, key, it, depth.saturating_add(1), visited).await;
                }
            }
            Obj::Dict(entries) => {
                for value in Arc::make_mut(entries).values_mut() {
                    decrypt_walk(cx, security, key, value, depth.saturating_add(1), visited).await;
                }
            }
            _ => {}
        }
    })
}

/// Resolves `item` if it is a reference; otherwise returns it as is.
async fn deref(cx: &Cx, doc: &Doc, item: &Item) -> Option<Item> {
    match item.reference() {
        Some((num, _)) => resolve(cx, doc, num).await.ok().map(|l| l.item),
        None => Some(item.clone()),
    }
}

/// Like [`deref`], with the span that positions in the result are relative to
/// (`base` for a direct object).
async fn deref_at(cx: &Cx, doc: &Doc, item: &Item, base: Span) -> Option<(Item, Span)> {
    match item.reference() {
        Some((num, _)) => resolve(cx, doc, num).await.ok().map(|l| (l.item, l.base)),
        None => Some((item.clone(), base)),
    }
}

/// An integer, directly or through a reference.
async fn int_of(cx: &Cx, doc: &Doc, item: Option<&Item>) -> Option<i64> {
    let item = item?;
    match item.int() {
        Some(v) => Some(v),
        None => deref(cx, doc, item).await?.int(),
    }
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, HEADER_WINDOW)).await?;
    let start = crate::bytes::find(&head, b"%PDF-", 0)
        .ok_or_else(|| Diagnostic::malformed("no %PDF- header").at(file.sub(0, 8)))?;
    let region = file.tail(to_u64(start));
    let rest = head.get(start..).unwrap_or_default();
    let is_eol = |b: &u8| *b == b'\r' || *b == b'\n';
    let line_end = rest.iter().position(is_eol).unwrap_or(8.min(rest.len()));
    let version = String::from_utf8_lossy(rest.get(5..line_end).unwrap_or_default())
        .trim()
        .to_owned();
    if start > 0 {
        cx.emit(Node::new("Leading data").span(file.sub(0, to_u64(start))));
    }
    cx.emit(
        Node::new("Header")
            .span(region.sub(0, to_u64(line_end)))
            .value(Value::Text(version.clone()))
            .desc("PDF version"),
    );
    // Comment lines after the header (the binary marker), up to the first
    // object.
    let mut pos = line_end;
    let mut first_object = None;
    loop {
        pos = pos.saturating_add(
            rest.get(pos..)
                .unwrap_or_default()
                .iter()
                .take_while(|&&b| syntax::is_white(b))
                .count(),
        );
        match rest.get(pos) {
            Some(b'%') => {}
            Some(_) => {
                first_object = Some(to_u64(pos));
                break;
            }
            None => break,
        }
        let line = rest.get(pos..).unwrap_or_default();
        let len = line.iter().position(is_eol).unwrap_or(line.len());
        let text = line.get(1..len).unwrap_or_default();
        if text.iter().filter(|&&b| b >= 0x80).count() >= 4 {
            cx.emit(
                Node::new("Binary marker")
                    .span(region.sub(to_u64(pos), to_u64(len)))
                    .value(Value::Bytes(text.iter().take(16).copied().collect()))
                    .desc("A comment of bytes above 127, so transfer programs treat the file as binary"),
            );
        } else {
            cx.emit(
                Node::new("Comment")
                    .span(region.sub(to_u64(pos), to_u64(len)))
                    .value(Value::Text(crate::text::latin1(
                        text.get(..256).unwrap_or(text),
                    ))),
            );
        }
        pos = pos.saturating_add(len);
    }

    // startxref, near the end.
    let tail_len = region.len.min(2048);
    let tail_at = region.len.saturating_sub(tail_len);
    let tail = cx.read_avail(region.sub(tail_at, tail_len)).await?;
    let startxref = crate::bytes::rfind(&tail, b"startxref").and_then(|at| {
        let mut p = syntax::Parser::at(&tail, at.saturating_add(9));
        p.uint().map(|v| (tail_at.saturating_add(to_u64(at)), v))
    });

    let mut diags = Vec::new();
    let (mut sections, chain_error) = match startxref {
        Some((_, offset)) => objects::chain(&cx, region, offset).await,
        None => (Vec::new(), Some(Diagnostic::malformed("no startxref"))),
    };
    let mut xref = Xref::new();
    let mut by_offset = BTreeMap::new();
    let mut n = 0u32;
    for section in &sections {
        for &(num, loc) in section.all_entries() {
            n = n.wrapping_add(1);
            if n.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            xref.entry(num).or_insert(loc);
            if let Loc::Offset { offset, generation } = loc {
                by_offset.entry(offset).or_insert((num, generation));
            }
        }
    }
    let mut trailer = sections.first().and_then(|s| s.trailer.clone());
    let mut scanned = false;
    if let Some(e) = chain_error {
        diags.push(e);
    }
    if sections.is_empty() || trailer.as_ref().and_then(|t| t.item.get("Root")).is_none() {
        let (found, scanned_trailer, tables) = objects::scan(&cx, region).await?;
        // Tables found by scanning are shown as written (their entries are
        // not trusted over the objects found).
        if sections.is_empty() {
            for &offset in tables.iter().rev() {
                if let Ok(section) = objects::section(&cx, region, offset).await {
                    sections.push(section);
                }
            }
        }
        for (i, (num, loc)) in found.into_iter().enumerate() {
            if i % 1024 == 1023 {
                cx.checkpoint().await;
            }
            xref.entry(num).or_insert(loc);
            if let Loc::Offset { offset, generation } = loc {
                by_offset.entry(offset).or_insert((num, generation));
            }
        }
        if trailer.as_ref().and_then(|t| t.item.get("Root")).is_none() {
            trailer = scanned_trailer.or(trailer);
        }
        scanned = true;
        diags.push(Diagnostic::warning(
            "cross-reference data unusable; objects were found by scanning",
        ));
    }

    // The linearization dictionary is the first object, if any.
    let mut linearized = None;
    if let Some(at) = first_object
        && let Ok((_, _, located)) = objects::object_at(&cx, region, at, Some(&xref)).await
        && located.item.get("Linearized").is_some()
    {
        linearized = Some(located);
    }

    // Revisions in file order, each up to its %%EOF.
    let mut order: Vec<(u64, usize)> = sections
        .iter()
        .enumerate()
        .map(|(i, s)| (s.offset, i))
        .collect();
    order.sort_unstable();
    let mut revisions = Vec::with_capacity(order.len());
    let mut from = 0u64;
    for (_, i) in order {
        let Some(section) = sections.get(i) else {
            continue;
        };
        let after = match (section.kind, &section.trailer) {
            (SectionKind::Table, Some(trailer)) => trailer.whole.end(),
            _ => section.span.end(),
        }
        .saturating_sub(region.offset);
        let tail = objects::tail_at(&cx, region, after).await;
        let end = tail.map_or(after, |t| t.end).max(from);
        revisions.push(Revision {
            section: i,
            start: from,
            end,
            tail,
        });
        from = end;
    }

    let mut doc = Doc {
        input,
        region,
        xref,
        sections,
        trailer,
        security: None,
        linearized,
        revisions,
        by_offset,
    };
    if let Some(trailer) = &doc.trailer
        && let Some(encrypt) = trailer.item.get("Encrypt")
    {
        let id0 = match trailer.item.get("ID").map(|i| &i.obj) {
            Some(Obj::Array(ids)) => match ids.first().map(|i| &i.obj) {
                Some(Obj::Str { bytes, .. }) => bytes.clone(),
                _ => Vec::new(),
            },
            _ => Vec::new(),
        };
        match deref(&cx, &doc, encrypt).await {
            Some(dict) => match crypt::Security::parse(&dict, id0, trailer.whole) {
                Ok(security) => doc.security = Some(Arc::new(security)),
                Err(e) => diags.push(Diagnostic::unsupported(format!("encrypted with {e}"))),
            },
            None => diags.push(Diagnostic::malformed("unreadable /Encrypt dictionary")),
        }
    }
    let doc: DocRef = Arc::new(doc);
    for d in diags {
        cx.diag(d);
    }

    // The catalog, for the summary and the document-level nodes.
    let catalog = match doc.trailer.as_ref().and_then(|t| t.item.get("Root")) {
        Some(root) => match &doc.trailer {
            Some(trailer) => deref_at(&cx, &doc, root, trailer.base).await,
            None => None,
        },
        None => None,
    };
    let pages = match &catalog {
        Some((catalog, _)) => match catalog.get("Pages") {
            Some(pages) => match deref(&cx, &doc, pages).await {
                Some(pages) => int_of(&cx, &doc, pages.get("Count")).await,
                None => None,
            },
            None => None,
        },
        None => None,
    };
    cx.annotate(annotation(&cx, &doc, &version, catalog.as_ref().map(|c| &c.0), pages).await);

    let walk = Walk::logical();
    if let Some(node) = document::linearization_node(&doc) {
        cx.emit(node);
    }
    if let Some(trailer) = &doc.trailer {
        let item = &trailer.item;
        cx.emit(
            item_node(
                &doc,
                "Trailer".into(),
                item,
                trailer.base,
                &Walk::physical(),
            )
            .span(trailer.whole),
        );
        if let Some(root) = item.get("Root") {
            cx.emit(item_node(
                &doc,
                "Document Catalog".into(),
                root,
                trailer.base,
                &walk,
            ));
        }
        if let Some(info) = item.get("Info") {
            cx.emit(item_node(
                &doc,
                "Document Information".into(),
                info,
                trailer.base,
                &walk,
            ));
        }
    }
    if let Some(node) = document::encryption_node(&doc) {
        cx.emit(node);
    }
    let mut pages_node = Node::new("Pages")
        .desc("The page tree, in reading order")
        .lazy(crate::expander!(self::pages: DocRef), doc.clone());
    if let Some(count) = pages {
        pages_node = pages_node.summary(plural(count.unsigned_abs(), "page"));
    }
    cx.emit(pages_node);
    if let Some((catalog, base)) = &catalog {
        for node in document::catalog_nodes(&cx, &doc, catalog, *base).await {
            cx.emit(node);
        }
    }
    cx.emit(
        Node::new("Objects")
            .summary(format!("{} entries", doc.xref.len()))
            .desc("Every object in the cross-reference data, by number, with where it is")
            .lazy(crate::expander!(self::objects_list: DocRef), doc.clone()),
    );
    if doc.revisions.is_empty() {
        if !doc.by_offset.is_empty() {
            cx.emit(
                Node::new("Body")
                    .summary(format!(
                        "{} found",
                        plural(to_u64(doc.by_offset.len()), "object")
                    ))
                    .desc("The objects found in the file, in file order")
                    .lazy(
                        crate::expander!(self::body: (DocRef, u64, u64)),
                        (doc.clone(), 0, region.len),
                    ),
            );
        }
        if let Some((at, offset)) = startxref {
            let len = tail
                .len()
                .saturating_sub(to_usize(at.saturating_sub(tail_at)));
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
    } else {
        let count = doc.revisions.len();
        cx.emit(
            Node::new("Revisions")
                .summary(plural(to_u64(count), "cross-reference section"))
                .desc(
                    "The file as written: the original and its incremental updates, in file order",
                )
                .lazy(crate::expander!(self::revisions: DocRef), doc.clone()),
        );
    }
    Ok(())
}

/// The number of revisions: sections, less the first-page section of a
/// linearized file (which belongs to the original).
fn revision_count(doc: &Doc) -> usize {
    let n = doc.sections.len();
    if doc.linearized.is_some() && n > 1 {
        n.saturating_sub(1)
    } else {
        n
    }
}

async fn annotation(
    cx: &Cx,
    doc: &Doc,
    version: &str,
    catalog: Option<&Item>,
    pages: Option<i64>,
) -> String {
    let mut out = format!("PDF {version}");
    if let Some(v) = catalog.and_then(|c| c.get("Version")).and_then(Item::name) {
        out = format!("PDF {v} (header {version})");
    }
    if let Some(count) = pages {
        out = format!("{out}, {}", plural(count.unsigned_abs(), "page"));
    }
    let revisions = revision_count(doc);
    if revisions > 1 {
        out = format!("{out}, {revisions} revisions");
    }
    if doc.linearized.is_some() {
        out.push_str(", linearized");
    }
    let Some(trailer) = &doc.trailer else {
        return out;
    };
    let locked = match &doc.security {
        Some(security) => crypt::file_key(cx, security, false).await.is_none(),
        None => false,
    };
    if trailer.item.get("Encrypt").is_some() {
        let cipher = doc
            .security
            .as_ref()
            .map(|s| format!(" ({})", s.describe()))
            .unwrap_or_default();
        out = format!(
            "{out}, encrypted{cipher}{}",
            if locked { ", password required" } else { "" }
        );
    }
    if let Some(form) = catalog.and_then(|c| c.get("AcroForm"))
        && let Some(form) = deref(cx, doc, form).await
        && int_of(cx, doc, form.get("SigFlags"))
            .await
            .is_some_and(|f| f & 1 != 0)
    {
        out.push_str(", signed");
    }
    if let Some(info) = trailer.item.get("Info")
        && !locked
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
    out
}

// ---------------------------------------------------------------------------
// Objects as nodes

#[derive(Clone)]
struct ItemState {
    doc: DocRef,
    item: Item,
    base: Span,
    walk: Walk,
}

#[derive(Clone)]
struct ObjState {
    doc: DocRef,
    num: u32,
    walk: Walk,
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
            // 24 characters take at most 4 bytes each (and a byte order mark).
            let prefix = bytes.get(..128).unwrap_or(bytes);
            let text: String = syntax::text(prefix).chars().take(24).collect();
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

fn item_node(doc: &DocRef, name: Cow<'static, str>, item: &Item, base: Span, walk: &Walk) -> Node {
    let span = base.sub(to_u64(item.start), syntax::len_u64(item));
    let node = Node::new(name).span(span);
    let state = || ItemState {
        doc: doc.clone(),
        item: item.clone(),
        base,
        walk: walk.clone(),
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
            // Only a prefix of a huge string is examined and shown, so the
            // node costs a bounded amount of work.
            let shown = bytes.get(..MAX_SHOWN_TEXT).unwrap_or(bytes);
            let node = if shown.len() < bytes.len() && syntax::is_text(shown) {
                node.value(Value::Text(format!("{}…", syntax::text(shown))))
                    .summary(format!(
                        "{} bytes, the first {MAX_SHOWN_TEXT} shown",
                        bytes.len()
                    ))
            } else if syntax::is_text(bytes) {
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
        Obj::Ref(num, generation) => reference(doc, node, *num, *generation, walk),
        Obj::Array(items) => node
            .summary(array_summary(items))
            .lazy(crate::expander!(self::array_children: ItemState), state()),
        Obj::Dict(_) => node
            .summary(dict_summary(item))
            .lazy(crate::expander!(self::dict_children: ItemState), state()),
    }
}

/// A reference: a link to the object it points to, which a logical view
/// also expands into, unless that object is already open above (a cycle
/// such as `/Parent`) or the path is too deep.
fn reference(doc: &DocRef, node: Node, num: u32, generation: u16, walk: &Walk) -> Node {
    let mut node = node.value(Value::Text(format!("{num} {generation} R")));
    match doc.xref.get(&num) {
        Some(&Loc::Offset { offset, .. }) => node = node.target(doc.region.sub(offset, 0)),
        Some(Loc::Compressed { stream, .. }) => {
            node = node.summary(format!("in object stream {stream}"))
        }
        Some(Loc::Free { .. }) => return node.summary("free object"),
        None => return node.diag(Diagnostic::warning(format!("object {num} does not exist"))),
    }
    if !walk.follow {
        return node;
    }
    if walk.path.contains(&num) {
        return node.summary("already open above");
    }
    if walk.path.len() >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "references followed deeper than {MAX_DEPTH}"
        )));
    }
    let mut path = walk.path.to_vec();
    path.push(num);
    node.lazy(
        crate::expander!(self::object_children: ObjState),
        ObjState {
            doc: doc.clone(),
            num,
            walk: Walk {
                path: Arc::new(path),
                follow: true,
            },
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
            &state.walk,
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
        cx.push(entry_node(&state.doc, entry, state.base, &state.walk))
            .await;
    }
    Ok(())
}

/// A dictionary entry: the value's node, spanning the key too.
/// Keys whose references point back or across the document's tree (a
/// page's parent, an annotation's page, a destination): a logical view
/// shows them as links rather than expanding the same objects again.
const BACK_LINKS: &[&str] = &["Parent", "P", "Prev", "Last", "Dest", "D", "Pg"];

fn entry_node(doc: &DocRef, entry: &syntax::Entry, base: Span, walk: &Walk) -> Node {
    let link = Walk {
        path: walk.path.clone(),
        follow: false,
    };
    let walk = if walk.follow && BACK_LINKS.contains(&entry.key.as_str()) {
        &link
    } else {
        walk
    };
    let span = base.sub(
        to_u64(entry.key_start),
        to_u64(entry.value.end.saturating_sub(entry.key_start)),
    );
    item_node(
        doc,
        format!("/{}", entry.key).into(),
        &entry.value,
        base,
        walk,
    )
    .span(span)
}

/// One line describing an object.
fn describe(located: &Located) -> String {
    let base = match &located.item.obj {
        Obj::Dict(_) => dict_summary(&located.item),
        _ => short(&located.item),
    };
    match located.data {
        Some(data) => {
            let kind = streams::kind(&located.item)
                .map(|k| format!("{k}, "))
                .unwrap_or_default();
            let filters = streams::filters_summary(&located.item)
                .map(|f| format!(", {f}"))
                .unwrap_or_default();
            format!("stream, {kind}{base}, {} bytes{filters}", data.len)
        }
        None => base,
    }
}

/// The contents of object `num`: a dictionary's entries (and stream data),
/// an array's items, or the value.
async fn object_children(cx: Cx, state: ObjState) -> Result<()> {
    let located = resolve(&cx, &state.doc, state.num).await?;
    cx.annotate(describe(&located));
    emit_object(&cx, &state.doc, &located, &state.walk).await
}

/// The contents of an object already read (a body object, an object in an
/// object stream).
async fn located_children(cx: Cx, (doc, located, walk): (DocRef, Located, Walk)) -> Result<()> {
    emit_object(&cx, &doc, &located, &walk).await
}

/// A node for an object read at a known place, listed where it is written.
fn located_node(doc: &DocRef, name: String, located: Located) -> Node {
    Node::new(name)
        .span(located.whole)
        .summary(describe(&located))
        .lazy(
            crate::expander!(self::located_children: (DocRef, Located, Walk)),
            (doc.clone(), located, Walk::physical()),
        )
}

/// Where an indirect object is written: its `N G obj` line.
fn header_node(located: &Located) -> Option<Node> {
    let (num, generation) = located.id?;
    let start = located
        .base
        .offset
        .saturating_add(to_u64(located.item.start));
    Some(
        Node::new("Object header")
            .span(
                located
                    .whole
                    .sub(0, start.saturating_sub(located.whole.offset)),
            )
            .value(Value::Text(format!("{num} {generation} obj"))),
    )
}

async fn emit_object(cx: &Cx, doc: &DocRef, located: &Located, walk: &Walk) -> Result<()> {
    let item = &located.item;
    if !walk.follow
        && let Some(node) = header_node(located)
    {
        cx.emit(node);
    }
    match &item.obj {
        Obj::Dict(entries) => {
            for (i, entry) in entries.iter().enumerate() {
                if i % 256 == 255 {
                    cx.checkpoint().await;
                }
                cx.emit(entry_node(doc, entry, located.base, walk));
            }
        }
        Obj::Array(items) => {
            for (i, it) in items.iter().enumerate() {
                if i % 256 == 255 {
                    cx.checkpoint().await;
                }
                cx.emit(item_node(
                    doc,
                    format!("[{i}]").into(),
                    it,
                    located.base,
                    walk,
                ));
            }
        }
        _ => cx.emit(item_node(doc, "Value".into(), item, located.base, walk)),
    }
    let physical = !walk.follow && located.id.is_some();
    let item_end = located.base.offset.saturating_add(to_u64(item.end));
    if let Some(data) = located.data {
        if physical {
            cx.emit(
                Node::new("Stream keyword")
                    .span(Span::new(
                        data.source,
                        item_end,
                        data.offset.saturating_sub(item_end),
                    ))
                    .value(Value::Text("stream".to_owned())),
            );
        }
        for node in streams::nodes(doc, located) {
            cx.emit(node);
        }
    }
    if physical {
        // `endstream` and `endobj`.
        let from = located.data.map_or(item_end, |d| d.end());
        let len = located.whole.end().saturating_sub(from);
        if len > 0 {
            let span = Span::new(located.whole.source, from, len.min(64));
            let bytes = cx.read_avail(span).await?;
            let keywords: Vec<String> = bytes
                .split(|&b| syntax::is_white(b))
                .filter(|w| !w.is_empty())
                .map(crate::text::latin1)
                .collect();
            cx.emit(
                Node::new("End keywords")
                    .span(span)
                    .value(Value::Text(keywords.join(" "))),
            );
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Collections

/// Where an object is, as a value and a summary.
fn loc_value(loc: Loc) -> (Value, String) {
    match loc {
        Loc::Free { next, generation } => (
            Value::UInt {
                value: next,
                bits: 64,
                radix: Radix::Dec,
            },
            format!("free, next free object {next}, generation {generation}"),
        ),
        Loc::Offset { offset, generation } => (
            Value::UInt {
                value: offset,
                bits: 64,
                radix: Radix::Hex,
            },
            format!("in use, generation {generation}"),
        ),
        Loc::Compressed { stream, index } => (
            Value::UInt {
                value: u64::from(stream),
                bits: 32,
                radix: Radix::Dec,
            },
            format!("in object stream {stream}, index {index}"),
        ),
    }
}

/// Every object by number: where it is and what it is, linked to it.
async fn objects_list(cx: Cx, doc: DocRef) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(doc.xref.len())));
    for (&num, &loc) in &doc.xref {
        let label = match loc {
            Loc::Offset { generation, .. } => format!("Object {num} {generation}"),
            _ => format!("Object {num}"),
        };
        let (value, place) = loc_value(loc);
        let node = Node::new(label).value(value);
        let node = match loc {
            Loc::Free { .. } => node.summary(place),
            _ => match resolve(&cx, &doc, num).await {
                Ok(located) => node
                    .summary(format!("{} ({place})", describe(&located)))
                    .target(located.whole),
                Err(e) => node.summary(place).diag(e),
            },
        };
        cx.push(node).await;
    }
    Ok(())
}

/// The objects written in `start..end`, in file order.
async fn body(cx: Cx, (doc, start, end): (DocRef, u64, u64)) -> Result<()> {
    let objects: Vec<(u64, u32)> = doc
        .by_offset
        .range(start..end)
        .map(|(&offset, &(num, _))| (offset, num))
        .collect();
    cx.set_count(Count::Exact(to_u64(objects.len())));
    for (offset, num) in objects {
        let node = match located_at(&cx, &doc, offset).await {
            Ok(located) => {
                let name = match located.id {
                    Some((n, g)) => format!("Object {n} {g}"),
                    None => format!("Object {num}"),
                };
                located_node(&doc, name, located)
            }
            Err(e) => Node::new(format!("Object {num}"))
                .span(doc.region.sub(offset, 0))
                .diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A common paper size, for page summaries.
fn paper(w: f64, h: f64) -> Option<&'static str> {
    const SIZES: &[(f64, f64, &str)] = &[
        (595.0, 842.0, "A4"),
        (612.0, 792.0, "US Letter"),
        (612.0, 1008.0, "US Legal"),
        (842.0, 1191.0, "A3"),
        (420.0, 595.0, "A5"),
        (499.0, 709.0, "B5"),
        (792.0, 1224.0, "Tabloid"),
    ];
    let (a, b) = if w <= h { (w, h) } else { (h, w) };
    SIZES
        .iter()
        .find(|(x, y, _)| (a - x).abs() < 1.5 && (b - y).abs() < 1.5)
        .map(|(_, _, name)| *name)
}

fn rectangle(item: Option<&Item>) -> Option<[f64; 4]> {
    let v: Vec<f64> = item?
        .array()?
        .iter()
        .filter_map(|i| match i.obj {
            Obj::Int(n) => Some(n as f64),
            Obj::Real(r) => Some(r),
            _ => None,
        })
        .collect();
    v.try_into().ok()
}

/// The page tree in order: a depth-first walk from the catalog's /Pages,
/// skipping nodes already visited. `/MediaBox` and `/Rotate` are inherited.
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
    let mut stack: Vec<(u32, Option<[f64; 4]>, Option<i64>)> = vec![(top.0, None, None)];
    let mut seen = BTreeSet::new();
    let mut number = 0u64;
    while let Some((num, media, rotate)) = stack.pop() {
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
        let item = &located.item;
        let media = rectangle(item.get("MediaBox")).or(media);
        let rotate = item.get("Rotate").and_then(Item::int).or(rotate);
        let kind = item.get("Type").and_then(Item::name);
        let kids = item.get("Kids").and_then(Item::array);
        match (kind, kids) {
            (Some("Pages"), Some(kids)) | (None, Some(kids)) => {
                stack.extend(
                    kids.iter()
                        .rev()
                        .filter_map(Item::reference)
                        .map(|(n, _)| (n, media, rotate)),
                );
            }
            _ => {
                number = number.saturating_add(1);
                let mut summary = format!("object {num}");
                if let Some([x0, y0, x1, y1]) = media {
                    let (w, h) = ((x1 - x0).abs(), (y1 - y0).abs());
                    summary = format!("{summary}, {w}×{h} pt");
                    if let Some(name) = paper(w, h) {
                        summary = format!(
                            "{summary} ({name}{})",
                            if w > h { " landscape" } else { "" }
                        );
                    }
                }
                if let Some(r) = rotate.filter(|&r| r.rem_euclid(360) != 0) {
                    summary = format!("{summary}, rotated {r}°");
                }
                let walk = Walk {
                    path: Arc::new(vec![num]),
                    follow: true,
                };
                cx.push(
                    Node::new(format!("Page {number}"))
                        .span(located.whole)
                        .summary(summary)
                        .lazy(
                            crate::expander!(self::object_children: ObjState),
                            ObjState {
                                doc: doc.clone(),
                                num,
                                walk,
                            },
                        ),
                )
                .await;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Revisions: the file as written

async fn revisions(cx: Cx, doc: DocRef) -> Result<()> {
    let count = doc.revisions.len();
    cx.set_count(Count::Exact(to_u64(count)));
    let linearized = doc.linearized.is_some() && count > 1;
    for (i, revision) in doc.revisions.iter().enumerate() {
        let Some(section) = doc.sections.get(revision.section) else {
            continue;
        };
        let kind = match (section.kind, section.hybrid.is_some()) {
            (SectionKind::Table, false) => "cross-reference table",
            (SectionKind::Table, true) => "hybrid cross-reference table and stream",
            (SectionKind::Stream, _) => "cross-reference stream",
        };
        let label = match (linearized, i) {
            (true, 0) => "linearized, first-page section".to_owned(),
            (true, 1) | (false, 0) => "original".to_owned(),
            (true, _) => format!("update {}", i.saturating_sub(1)),
            (false, _) => format!("update {i}"),
        };
        let objects = doc
            .by_offset
            .range(revision.start..section.offset.max(revision.start))
            .count();
        let entries = section.all_entries().count();
        cx.push(
            Node::new(format!("Revision {}", i.saturating_add(1)))
                .span(
                    doc.region
                        .sub(revision.start, revision.end.saturating_sub(revision.start)),
                )
                .summary(format!(
                    "{label}: {}, {kind} at {:#x} with {}",
                    plural(to_u64(objects), "object"),
                    section.offset,
                    fmt::count(to_u64(entries), "entry", "entries")
                ))
                .lazy(
                    crate::expander!(self::revision_children: (DocRef, usize)),
                    (doc.clone(), i),
                ),
        )
        .await;
    }
    Ok(())
}

async fn revision_children(cx: Cx, (doc, index): (DocRef, usize)) -> Result<()> {
    let Some(revision) = doc.revisions.get(index).copied() else {
        return Ok(());
    };
    let Some(section) = doc.sections.get(revision.section) else {
        return Ok(());
    };
    let body_end = section.offset.max(revision.start);
    let objects = doc.by_offset.range(revision.start..body_end).count();
    if objects > 0 {
        cx.emit(
            Node::new("Body")
                .span(
                    doc.region
                        .sub(revision.start, body_end.saturating_sub(revision.start)),
                )
                .summary(plural(to_u64(objects), "object"))
                .desc("The objects of this revision, in file order")
                .lazy(
                    crate::expander!(self::body: (DocRef, u64, u64)),
                    (doc.clone(), revision.start, body_end),
                ),
        );
    }
    let walk = Walk::physical();
    match section.kind {
        SectionKind::Table => {
            cx.emit(table_node(&doc, revision.section, false));
            if let Some(trailer) = &section.trailer {
                cx.emit(
                    item_node(&doc, "Trailer".into(), &trailer.item, trailer.base, &walk)
                        .span(trailer.whole),
                );
            }
            if let Some(hybrid) = &section.hybrid
                && let Some(stream) = &hybrid.trailer
            {
                cx.emit(
                    located_node(
                        &doc,
                        "Cross-reference stream (/XRefStm)".to_owned(),
                        stream.clone(),
                    )
                    .desc("The stream of a hybrid-reference file: entries readers of PDF 1.5 and later add to the table's"),
                );
            }
        }
        SectionKind::Stream => {
            if let Some(stream) = &section.trailer {
                cx.emit(
                    located_node(&doc, "Cross-reference stream".to_owned(), stream.clone()).desc(
                        "The cross-reference entries and the trailer dictionary, as a stream",
                    ),
                );
            }
        }
    }
    if let Some(tail) = revision.tail {
        let mut node = Node::new("startxref")
            .span(tail.startxref)
            .value(Value::UInt {
                value: tail.value,
                bits: 64,
                radix: Radix::Hex,
            });
        if tail.value == section.offset {
            node = node.target(doc.region.sub(tail.value, 4));
        } else if tail.value == 0 && doc.linearized.is_some() {
            node = node.summary("0 in the first-page trailer of a linearized file");
        } else if doc.linearized.is_some() && doc.sections.iter().any(|s| s.offset == tail.value) {
            // A linearized file's last startxref names the first-page
            // section (ISO 32000-1 F.3.11).
            node = node
                .target(doc.region.sub(tail.value, 4))
                .summary("the first-page cross-reference section of a linearized file");
        } else {
            node = node.diag(Diagnostic::warning(format!(
                "points at {:#x}, but this section is at {:#x}",
                tail.value, section.offset
            )));
        }
        cx.emit(node);
        if let Some(eof) = tail.eof {
            cx.emit(
                Node::new("End-of-file marker")
                    .span(eof)
                    .value(Value::Text("%%EOF".to_owned())),
            );
        }
    }
    Ok(())
}

/// A classic cross-reference table (or, for a stream section, its rows).
fn table_node(doc: &DocRef, section: usize, hybrid: bool) -> Node {
    let Some(s) = doc.sections.get(section) else {
        return Node::new("Cross-reference table");
    };
    let s = if hybrid {
        match s.hybrid.as_deref() {
            Some(h) => h,
            None => return Node::new("Cross-reference table"),
        }
    } else {
        s
    };
    let entries = s.entries.len();
    let subsections = s.subsections.len();
    Node::new("Cross-reference table")
        .span(s.span)
        .summary(format!(
            "{} in {}",
            fmt::count(to_u64(entries), "entry", "entries"),
            plural(to_u64(subsections), "subsection")
        ))
        .lazy(
            crate::expander!(self::subsections_list: (DocRef, usize, bool)),
            (doc.clone(), section, hybrid),
        )
}

/// The section `section` of `doc` (or its hybrid stream).
fn section_of(doc: &Doc, section: usize, hybrid: bool) -> Option<&Section> {
    let s = doc.sections.get(section)?;
    if hybrid { s.hybrid.as_deref() } else { Some(s) }
}

async fn subsections_list(cx: Cx, (doc, section, hybrid): (DocRef, usize, bool)) -> Result<()> {
    let Some(s) = section_of(&doc, section, hybrid) else {
        return Ok(());
    };
    if s.kind == SectionKind::Table {
        cx.emit(
            Node::new("Keyword")
                .span(doc.region.sub(s.offset, 4))
                .value(Value::Text("xref".to_owned())),
        );
    }
    cx.set_count(Count::Exact(to_u64(s.subsections.len())));
    for (i, sub) in s.subsections.iter().enumerate() {
        let last = sub.first.saturating_add(to_u64(sub.len)).saturating_sub(1);
        let name = match sub.len {
            0 => format!("Subsection at {}", sub.first),
            1 => format!("Object {}", sub.first),
            _ => format!("Objects {}–{last}", sub.first),
        };
        cx.push(
            Node::new(name)
                .span(sub.span)
                .summary(format!(
                    "{} entr{}",
                    sub.len,
                    if sub.len == 1 { "y" } else { "ies" }
                ))
                .lazy(
                    crate::expander!(self::subsection_entries: (DocRef, usize, bool, usize)),
                    (doc.clone(), section, hybrid, i),
                ),
        )
        .await;
    }
    Ok(())
}

async fn subsection_entries(
    cx: Cx,
    (doc, section, hybrid, index): (DocRef, usize, bool, usize),
) -> Result<()> {
    let Some(s) = section_of(&doc, section, hybrid) else {
        return Ok(());
    };
    let Some(sub) = s.subsections.get(index) else {
        return Ok(());
    };
    if let Some(header) = sub.header {
        cx.emit(
            Node::new("Header")
                .span(header)
                .value(Value::Text(format!("{} {}", sub.first, sub.len)))
                .desc("The first object number and the number of entries"),
        );
    }
    let entries = s
        .entries
        .get(sub.index..sub.index.saturating_add(sub.len))
        .unwrap_or_default();
    cx.set_count(Count::Exact(to_u64(entries.len())));
    let spans = s
        .spans
        .get(sub.index..sub.index.saturating_add(sub.len))
        .unwrap_or_default();
    for (i, &(num, loc)) in entries.iter().enumerate() {
        let (value, summary) = loc_value(loc);
        let mut node = Node::new(format!("Object {num}"))
            .value(value)
            .summary(summary);
        if let Some(&span) = spans.get(i) {
            node = node.span(span);
        }
        if let Loc::Offset { offset, .. } = loc {
            node = node.target(doc.region.sub(offset, 0));
        }
        cx.push(node).await;
    }
    Ok(())
}
