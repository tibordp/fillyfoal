//! Document-level structures: the linearization dictionary, the encryption
//! dictionary, outlines, form fields and signatures.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::objects::Located;
use super::syntax::{self, Entry, Item, Obj};
use super::{
    DocRef, MAX_DEPTH, Walk, crypt, deref, deref_at, entry_node, header_node, int_of, located_at,
    located_node, plural, resolve, short,
};
use crate::bytes::{to_u64, u16_be, u32_be};
use crate::codec::{self, Codec};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::embedded_as;
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, field, flag, lookup};

/// Form fields walked.
const MAX_FIELDS: usize = 10_000;
/// Outline items listed per level.
const MAX_OUTLINE_ITEMS: usize = 100_000;

// ---------------------------------------------------------------------------
// Linearization

pub(super) fn linearization_node(doc: &DocRef) -> Option<Node> {
    let lin = doc.linearized.as_ref()?;
    let int = |k: &str| lin.item.get(k).and_then(Item::int);
    let mut parts = Vec::new();
    if let Some(n) = int("N") {
        parts.push(format!("{n} page{}", plural(n.unsigned_abs())));
    }
    if let Some(e) = int("E") {
        parts.push(format!("first page ends at {e:#x}"));
    }
    let mut node = Node::new("Linearization")
        .span(lin.whole)
        .summary(parts.join(", "))
        .desc("Parameters for showing the first page before the whole file has arrived")
        .lazy(crate::expander!(self::linearization: DocRef), doc.clone());
    if let Some(len) = int("L").and_then(|l| u64::try_from(l).ok())
        && len != doc.region.len
    {
        node = node.diag(Diagnostic::warning(format!(
            "/L says {len:#x} bytes, the file has {:#x}: changed after linearization",
            doc.region.len
        )));
    }
    Some(node)
}

async fn linearization(cx: Cx, doc: DocRef) -> Result<()> {
    let Some(lin) = &doc.linearized else {
        return Ok(());
    };
    let walk = Walk::physical();
    if let Some(node) = header_node(lin) {
        cx.emit(node);
    }
    let Obj::Dict(entries) = &lin.item.obj else {
        return Ok(());
    };
    let offset = |item: &Item| item.int().and_then(|n| u64::try_from(n).ok());
    for entry in entries.iter() {
        let node = entry_node(&doc, entry, lin.base, &walk);
        let node = match entry.key.as_str() {
            "Linearized" => node.desc("Linearization version"),
            "L" => {
                let node = node.desc("Length of the file");
                match offset(&entry.value) {
                    Some(len) if len == doc.region.len => node.summary("matches the file"),
                    _ => node,
                }
            }
            "H" => node.desc(
                "Offset and length of the primary hint stream (and of the overflow hint stream)",
            ),
            "O" => node.desc("Object number of the first page's page object"),
            "E" => {
                let node = node.desc("Offset of the end of the first page");
                match offset(&entry.value) {
                    Some(at) => node.target(doc.region.sub(at, 0)),
                    None => node,
                }
            }
            "N" => node.desc("Number of pages"),
            "T" => {
                let node = node.desc(
                    "Offset of the white space before the first entry of the main cross-reference table",
                );
                match offset(&entry.value) {
                    Some(at) => node.target(doc.region.sub(at, 0)),
                    None => node,
                }
            }
            "P" => node.desc("Page number of the first page"),
            _ => node,
        };
        cx.emit(node);
    }
    let hints = lin.item.get("H").and_then(Item::array).unwrap_or_default();
    let names = ["Primary hint stream", "Overflow hint stream"];
    for (name, pair) in names.iter().zip(hints.chunks(2)) {
        let Some(at) = pair.first().and_then(offset) else {
            continue;
        };
        cx.emit(match located_at(&cx, &doc, at).await {
            Ok(located) => located_node(&doc, (*name).to_owned(), located),
            Err(e) => Node::new(*name).span(doc.region.sub(at, 0)).diag(e),
        });
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Encryption

const VERSIONS: EnumTable = &[
    (0, "undocumented"),
    (1, "RC4, 40-bit key"),
    (2, "RC4, key longer than 40 bits"),
    (3, "unpublished algorithm"),
    (4, "crypt filters (RC4 or AES-128)"),
    (5, "crypt filters (AES-256)"),
];

const REVISIONS: EnumTable = &[
    (2, "RC4, 40-bit key"),
    (3, "RC4, up to 128-bit key"),
    (4, "crypt filters"),
    (5, "AES-256 (Adobe extension level 3, deprecated)"),
    (6, "AES-256"),
];

const PERMISSIONS: FlagTable = &[
    flag(0x4, "print"),
    flag(0x8, "modify"),
    flag(0x10, "copy"),
    flag(0x20, "annotate"),
    flag(0x100, "fill forms"),
    flag(0x200, "extract for accessibility"),
    flag(0x400, "assemble"),
    flag(0x800, "print high quality"),
    field(0xffff_f0c0, 0xffff_f0c0, "(reserved bits)"),
];

pub(super) fn encryption_node(doc: &DocRef) -> Option<Node> {
    let trailer = doc.trailer.as_ref()?;
    trailer.item.get("Encrypt")?;
    let summary = match &doc.security {
        Some(security) => security.describe(),
        None => "not supported".to_owned(),
    };
    Some(
        Node::new("Encryption")
            .summary(summary)
            .desc("The encryption dictionary: security handler, algorithm, permissions")
            .lazy(crate::expander!(self::encryption: DocRef), doc.clone()),
    )
}

fn enum_value(item: &Item, table: EnumTable) -> Option<Value> {
    let raw = u64::try_from(item.int()?).ok()?;
    Some(Value::Enum {
        raw,
        bits: 8,
        name: lookup(table, raw),
    })
}

async fn encryption(cx: Cx, doc: DocRef) -> Result<()> {
    let Some(trailer) = &doc.trailer else {
        return Ok(());
    };
    let Some(encrypt) = trailer.item.get("Encrypt") else {
        return Ok(());
    };
    let located = match encrypt.reference() {
        Some((num, _)) => resolve(&cx, &doc, num).await?,
        None => Located {
            id: None,
            item: encrypt.clone(),
            base: trailer.base,
            data: None,
            whole: trailer
                .base
                .sub(to_u64(encrypt.start), syntax::len_u64(encrypt)),
        },
    };
    let key = match &doc.security {
        Some(security) => crypt::file_key(&cx, security, false).await,
        None => None,
    };
    if let Some(node) = header_node(&located) {
        cx.emit(node);
    }
    let walk = Walk::physical();
    let Obj::Dict(entries) = &located.item.obj else {
        return Ok(());
    };
    for entry in entries.iter() {
        let node = entry_node(&doc, entry, located.base, &walk);
        let node = match entry.key.as_str() {
            "Filter" => node.desc("Security handler"),
            "SubFilter" => node.desc("Encoding of the public-key handler's data"),
            "V" => match enum_value(&entry.value, VERSIONS) {
                Some(v) => node.value(v),
                None => node,
            }
            .desc("Encryption algorithm"),
            "R" => match enum_value(&entry.value, REVISIONS) {
                Some(v) => node.value(v),
                None => node,
            }
            .desc("Revision of the standard security handler"),
            "Length" => match entry.value.int() {
                Some(bits) => node.summary(format!("{bits}-bit key")),
                None => node,
            }
            .desc("Key length in bits"),
            "P" => permissions(node, &entry.value),
            "O" => node.desc("Owner password check (and, before R5, the user password encrypted with the owner's)"),
            "U" => node.desc("User password check"),
            "OE" => node.desc("The file key, encrypted with a key from the owner password"),
            "UE" => node.desc("The file key, encrypted with a key from the user password"),
            "Perms" => {
                let node = node.desc("The permissions, encrypted with the file key (to detect tampering)");
                match (&doc.security, &key) {
                    (Some(security), Some(key)) => match security.perms_match(key) {
                        Some(true) => node.summary("matches /P"),
                        Some(false) => node.diag(Diagnostic::warning(
                            "does not match /P (or the file key is wrong)",
                        )),
                        None => node,
                    },
                    _ => node,
                }
            }
            "CF" => node.desc("Crypt filters, by name"),
            "StmF" => node.desc("Crypt filter for streams"),
            "StrF" => node.desc("Crypt filter for strings"),
            "EFF" => node.desc("Crypt filter for embedded files"),
            "EncryptMetadata" => node.desc("Whether metadata streams are encrypted"),
            _ => node,
        };
        cx.emit(node);
    }
    if let Some(security) = &doc.security {
        let status = if key.is_some() {
            "unlocked: the empty user password (or the one entered) opens it"
        } else {
            "locked: a user password is needed"
        };
        cx.emit(
            Node::new("Status")
                .value(Value::Text(status.to_owned()))
                .summary(security.describe()),
        );
    }
    Ok(())
}

fn permissions(node: Node, item: &Item) -> Node {
    let node =
        node.desc("Permissions granted to users who open the document with the user password");
    let Some(p) = item.int() else {
        return node;
    };
    // A 32-bit signed value: its bits as written.
    let raw = u64::try_from(p & 0xffff_ffff).unwrap_or(0);
    let (set, unknown) = decode_flags(PERMISSIONS, raw);
    let denied: Vec<&str> = PERMISSIONS
        .iter()
        .filter(|f| f.mask == f.value && raw & f.mask == 0)
        .map(|f| f.name)
        .collect();
    let summary = if denied.is_empty() {
        "everything allowed".to_owned()
    } else {
        format!("denies {}", denied.join(", "))
    };
    node.value(Value::Flags {
        raw,
        bits: 32,
        set,
        unknown,
    })
    .summary(summary)
}

// ---------------------------------------------------------------------------
// Catalog: outlines, form fields, signatures

pub(super) async fn catalog_nodes(cx: &Cx, doc: &DocRef, catalog: &Item, base: Span) -> Vec<Node> {
    let mut out = Vec::new();
    if let Some(outlines) = catalog.get("Outlines")
        && let Some((item, _)) = deref_at(cx, doc, outlines, base).await
    {
        let mut node = Node::new("Outlines")
            .desc("The document outline (bookmarks)")
            .lazy(
                crate::expander!(self::outline_root: (DocRef, Item)),
                (doc.clone(), item.clone()),
            );
        if let Some(count) = int_of(cx, doc, item.get("Count")).await {
            node = node.summary(format!(
                "{count} visible item{}",
                plural(count.unsigned_abs())
            ));
        }
        out.push(node);
    }
    if let Some(form) = catalog.get("AcroForm")
        && let Some((form, _)) = deref_at(cx, doc, form, base).await
    {
        let top = match form.get("Fields") {
            Some(fields) => deref(cx, doc, fields)
                .await
                .and_then(|f| f.array().map(<[Item]>::len))
                .unwrap_or(0),
            None => 0,
        };
        out.push(
            Node::new("Form fields")
                .summary(format!("{top} top-level field{}", plural(to_u64(top))))
                .desc("The interactive form's fields (terminal fields, by full name)")
                .lazy(crate::expander!(self::fields_list: DocRef), doc.clone()),
        );
        let flags = int_of(cx, doc, form.get("SigFlags")).await.unwrap_or(0);
        if flags & 1 != 0 {
            let mut node = Node::new("Signatures")
                .desc("Signature fields and what their signatures cover")
                .lazy(crate::expander!(self::signatures: DocRef), doc.clone());
            if flags & 2 != 0 {
                node = node.summary("append only: updates must be incremental");
            }
            out.push(node);
        }
    }
    out
}

/// The outline's top-level items.
async fn outline_root(cx: Cx, (doc, root): (DocRef, Item)) -> Result<()> {
    let first = root.get("First").and_then(Item::reference).map(|r| r.0);
    outline_items(cx, (doc, first, Arc::new(Vec::new()))).await
}

/// A chain of outline items from `first` along `/Next`.
async fn outline_items(
    cx: Cx,
    (doc, first, path): (DocRef, Option<u32>, Arc<Vec<u32>>),
) -> Result<()> {
    let mut next = first;
    let mut seen = BTreeSet::new();
    while let Some(num) = next {
        cx.checkpoint().await;
        if !seen.insert(num) || path.contains(&num) {
            cx.diag(Diagnostic::malformed(format!(
                "outline items loop at object {num}"
            )));
            break;
        }
        if seen.len() > MAX_OUTLINE_ITEMS {
            cx.diag(Diagnostic::limit(format!(
                "more than {MAX_OUTLINE_ITEMS} outline items"
            )));
            break;
        }
        let located = match resolve(&cx, &doc, num).await {
            Ok(l) => l,
            Err(e) => {
                cx.diag(e);
                break;
            }
        };
        let item = &located.item;
        let title = match item.get("Title").map(|t| &t.obj) {
            Some(Obj::Str { bytes, .. }) => {
                let text = syntax::text(bytes.get(..512).unwrap_or(bytes));
                text.chars().take(120).collect::<String>()
            }
            _ => String::new(),
        };
        let mut parts = Vec::new();
        if let Some(dest) = item.get("Dest") {
            parts.push(format!("destination {}", short(dest)));
        }
        if let Some(action) = item.get("A") {
            match action.get("S").and_then(Item::name) {
                Some(kind) => parts.push(format!("/{kind} action")),
                None => parts.push(format!("action {}", short(action))),
            }
        }
        if let Some(count) = item.get("Count").and_then(Item::int)
            && count != 0
        {
            parts.push(format!(
                "{} descendant{} {}",
                count.unsigned_abs(),
                plural(count.unsigned_abs()),
                if count > 0 { "open" } else { "closed" }
            ));
        }
        let name = if title.is_empty() {
            format!("Item {num}")
        } else {
            title
        };
        let mut child_path = path.to_vec();
        child_path.push(num);
        let node = Node::new(name)
            .span(located.whole)
            .summary(parts.join(", "))
            .lazy(
                crate::expander!(self::outline_item: (DocRef, Located, Arc<Vec<u32>>)),
                (doc.clone(), located.clone(), Arc::new(child_path)),
            );
        cx.push(node).await;
        next = item.get("Next").and_then(Item::reference).map(|r| r.0);
    }
    Ok(())
}

/// An outline item: its dictionary, and its children.
async fn outline_item(
    cx: Cx,
    (doc, located, path): (DocRef, Located, Arc<Vec<u32>>),
) -> Result<()> {
    let walk = Walk::physical();
    if let Some(node) = header_node(&located) {
        cx.emit(node);
    }
    if let Obj::Dict(entries) = &located.item.obj {
        for entry in entries.iter() {
            cx.emit(entry_node(&doc, entry, located.base, &walk));
        }
    }
    if let Some((first, _)) = located.item.get("First").and_then(Item::reference) {
        if path.len() >= MAX_DEPTH {
            cx.diag(Diagnostic::limit(format!(
                "outline nested deeper than {MAX_DEPTH}"
            )));
        } else {
            cx.emit(Node::new("Children").lazy(
                crate::expander!(self::outline_items: (DocRef, Option<u32>, Arc<Vec<u32>>)),
                (doc.clone(), Some(first), path.clone()),
            ));
        }
    }
    Ok(())
}

/// A terminal form field.
struct Field {
    name: String,
    /// `/FT`, inherited from the parent fields.
    kind: Option<String>,
    flags: i64,
    located: Located,
}

/// The terminal fields of the interactive form, depth first.
async fn walk_fields(cx: &Cx, doc: &DocRef) -> Result<Vec<Field>> {
    let trailer = doc
        .trailer
        .as_ref()
        .ok_or_else(|| Diagnostic::malformed("no trailer"))?;
    let root = trailer
        .item
        .get("Root")
        .ok_or_else(|| Diagnostic::malformed("trailer has no /Root"))?;
    let catalog = deref(cx, doc, root)
        .await
        .ok_or_else(|| Diagnostic::malformed("document catalog is unreadable"))?;
    let form = match catalog.get("AcroForm") {
        Some(form) => deref(cx, doc, form).await,
        None => None,
    }
    .ok_or_else(|| Diagnostic::malformed("no interactive form"))?;
    let fields = match form.get("Fields") {
        Some(fields) => deref(cx, doc, fields).await,
        None => None,
    };
    let mut stack: Vec<(u32, String, Option<String>, i64)> = fields
        .as_ref()
        .and_then(Item::array)
        .unwrap_or_default()
        .iter()
        .rev()
        .filter_map(Item::reference)
        .map(|(n, _)| (n, String::new(), None, 0))
        .collect();
    let mut seen = BTreeSet::new();
    let mut out = Vec::new();
    while let Some((num, parent, kind, flags)) = stack.pop() {
        cx.checkpoint().await;
        if !seen.insert(num) {
            continue;
        }
        if seen.len() > MAX_FIELDS {
            cx.diag(Diagnostic::limit(format!("more than {MAX_FIELDS} fields")));
            break;
        }
        let located = match resolve(cx, doc, num).await {
            Ok(l) => l,
            Err(e) => {
                cx.diag(e);
                continue;
            }
        };
        let item = &located.item;
        let partial = match item.get("T").map(|t| &t.obj) {
            Some(Obj::Str { bytes, .. }) => Some(syntax::text(bytes.get(..256).unwrap_or(bytes))),
            _ => None,
        };
        let name = match (&partial, parent.is_empty()) {
            (Some(p), true) => p.clone(),
            (Some(p), false) => format!("{parent}.{p}"),
            (None, _) => parent.clone(),
        };
        let kind = item
            .get("FT")
            .and_then(Item::name)
            .map(str::to_owned)
            .or(kind);
        let flags = item.get("Ff").and_then(Item::int).unwrap_or(flags);
        let kids: Vec<u32> = item
            .get("Kids")
            .and_then(Item::array)
            .unwrap_or_default()
            .iter()
            .filter_map(Item::reference)
            .map(|(n, _)| n)
            .collect();
        // Kids with names are fields; kids without are its widgets.
        let mut field_kids = false;
        if let Some(&kid) = kids.first()
            && let Ok(kid) = resolve(cx, doc, kid).await
        {
            field_kids = kid.item.get("T").is_some();
        }
        if field_kids {
            stack.extend(
                kids.iter()
                    .rev()
                    .map(|&k| (k, name.clone(), kind.clone(), flags)),
            );
        } else if partial.is_some() || kind.is_some() {
            out.push(Field {
                name,
                kind,
                flags,
                located,
            });
        }
    }
    Ok(out)
}

fn field_kind(kind: Option<&str>, flags: i64) -> String {
    match kind {
        Some("Tx") => "text field".to_owned(),
        Some("Btn") if flags & 0x1_0000 != 0 => "push button".to_owned(),
        Some("Btn") if flags & 0x8000 != 0 => "radio buttons".to_owned(),
        Some("Btn") => "check box".to_owned(),
        Some("Ch") if flags & 0x2_0000 != 0 => "combo box".to_owned(),
        Some("Ch") => "list box".to_owned(),
        Some("Sig") => "signature".to_owned(),
        Some(other) => format!("/{other}"),
        None => "field".to_owned(),
    }
}

async fn fields_list(cx: Cx, doc: DocRef) -> Result<()> {
    let fields = walk_fields(&cx, &doc).await?;
    cx.annotate(format!(
        "{} field{}",
        fields.len(),
        plural(to_u64(fields.len()))
    ));
    cx.set_count(Count::Exact(to_u64(fields.len())));
    for field in fields {
        let mut summary = field_kind(field.kind.as_deref(), field.flags);
        if field.flags & 1 != 0 {
            summary.push_str(", read-only");
        }
        if field.flags & 2 != 0 {
            summary.push_str(", required");
        }
        let value = field.located.item.get("V").map(short);
        let mut node = located_node(&doc, field.name, field.located).summary(summary);
        if let Some(v) = value {
            node = node.value(Value::Text(v));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn signatures(cx: Cx, doc: DocRef) -> Result<()> {
    let fields = walk_fields(&cx, &doc).await?;
    let mut count = 0usize;
    for field in fields {
        if field.kind.as_deref() != Some("Sig") {
            continue;
        }
        let Some(value) = field.located.item.get("V") else {
            cx.push(
                Node::new(format!("Signature field {}", field.name))
                    .span(field.located.whole)
                    .summary("not signed"),
            )
            .await;
            continue;
        };
        let sig = match value.reference() {
            Some((num, _)) => match resolve(&cx, &doc, num).await {
                Ok(l) => l,
                Err(e) => {
                    cx.push(Node::new(format!("Signature {}", field.name)).diag(e))
                        .await;
                    continue;
                }
            },
            None => Located {
                id: None,
                item: value.clone(),
                base: field.located.base,
                data: None,
                whole: field
                    .located
                    .base
                    .sub(to_u64(value.start), syntax::len_u64(value)),
            },
        };
        count = count.saturating_add(1);
        let summary = signature_summary(&doc, &sig);
        cx.push(
            Node::new(format!("Signature {}", field.name))
                .span(sig.whole)
                .summary(summary)
                .lazy(
                    crate::expander!(self::signature: (DocRef, Located)),
                    (doc.clone(), sig),
                ),
        )
        .await;
    }
    cx.annotate(format!("{count} signature{}", plural(to_u64(count))));
    Ok(())
}

/// The `/ByteRange` pairs, as offsets and lengths.
fn byte_range(sig: &Item) -> Vec<(u64, u64)> {
    let values: Vec<u64> = sig
        .get("ByteRange")
        .and_then(Item::array)
        .unwrap_or_default()
        .iter()
        .take(64)
        .filter_map(|i| i.int().and_then(|n| u64::try_from(n).ok()))
        .collect();
    values
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&[offset, len]| (offset, len))
        .collect()
}

/// The `/Contents` string's place in the file (with its `<` and `>`).
fn contents_span(sig: &Located) -> Option<Span> {
    let contents = sig.item.get("Contents")?;
    Some(
        sig.base
            .sub(to_u64(contents.start), syntax::len_u64(contents)),
    )
}

fn signature_summary(doc: &DocRef, sig: &Located) -> String {
    let mut parts = Vec::new();
    if let Some(sub) = sig.item.get("SubFilter").and_then(Item::name) {
        parts.push(format!("/{sub}"));
    }
    let ranges = byte_range(&sig.item);
    let contents = contents_span(sig).map(|s| {
        let start = s.offset.saturating_sub(doc.region.offset);
        (start, start.saturating_add(s.len))
    });
    match (ranges.as_slice(), contents) {
        ([(0, a), (b, c)], Some((start, end))) if *a == start && *b == end => {
            let covered = b.saturating_add(*c);
            if covered == doc.region.len {
                parts.push("covers the whole file except /Contents".to_owned());
            } else if covered < doc.region.len {
                parts.push(format!(
                    "covers the file up to {covered:#x}; {} bytes were appended later",
                    doc.region.len.saturating_sub(covered)
                ));
            } else {
                parts.push("covers bytes beyond the end of the file".to_owned());
            }
        }
        ([], _) => parts.push("no /ByteRange".to_owned()),
        _ => parts.push("/ByteRange does not exclude exactly /Contents".to_owned()),
    }
    parts.join(", ")
}

async fn signature(cx: Cx, (doc, sig): (DocRef, Located)) -> Result<()> {
    let walk = Walk::physical();
    if let Some(node) = header_node(&sig) {
        cx.emit(node);
    }
    let Obj::Dict(entries) = &sig.item.obj else {
        return Ok(());
    };
    for entry in entries.iter() {
        cx.emit(signature_entry(&doc, &sig, entry, &walk));
    }
    let ranges = byte_range(&sig.item);
    if !ranges.is_empty() {
        cx.emit(
            Node::new("Signed bytes")
                .summary(format!(
                    "{} range{}, {} bytes",
                    ranges.len(),
                    plural(to_u64(ranges.len())),
                    ranges.iter().fold(0u64, |a, r| a.saturating_add(r.1))
                ))
                .lazy(
                    crate::expander!(self::signed_ranges: (DocRef, Vec<(u64, u64)>)),
                    (doc.clone(), ranges),
                ),
        );
    }
    Ok(())
}

fn signature_entry(doc: &DocRef, sig: &Located, entry: &Entry, walk: &Walk) -> Node {
    let node = entry_node(doc, entry, sig.base, walk);
    match entry.key.as_str() {
        "ByteRange" => node.desc("The signed byte ranges: offset and length pairs"),
        "Contents" => {
            let node = node
                .desc("The signature value: a DER-encoded PKCS #7 / CMS object, padded with zeros");
            match (&entry.value.obj, contents_span(sig)) {
                (Obj::Str { hex: true, .. }, Some(span)) if span.len >= 2 => node.lazy(
                    crate::expander!(self::signature_value: (DocRef, Span)),
                    (doc.clone(), span.sub(1, span.len.saturating_sub(1))),
                ),
                _ => node,
            }
        }
        "Filter" => node.desc("Signature handler"),
        "SubFilter" => node.desc("Signature encoding"),
        "M" => node.desc("Signing time"),
        "Name" => node.desc("Signer"),
        "Reference" => node.desc("Signature references (document modification detection)"),
        _ => node,
    }
}

async fn signed_ranges(cx: Cx, (doc, ranges): (DocRef, Vec<(u64, u64)>)) -> Result<()> {
    for (i, &(offset, len)) in ranges.iter().enumerate() {
        cx.emit(
            Node::new(format!("Range {}", i.saturating_add(1)))
                .value(Value::UInt {
                    value: offset,
                    bits: 64,
                    radix: crate::value::Radix::Hex,
                })
                .summary(format!(
                    "{len} bytes, up to {:#x}",
                    offset.saturating_add(len)
                ))
                .target(doc.region.sub(offset, len)),
        );
    }
    Ok(())
}

/// The total length of the DER element at the start of `head`.
fn der_length(head: &[u8]) -> Option<u64> {
    let first = *head.get(1)?;
    if first < 0x80 {
        return Some(u64::from(first).saturating_add(2));
    }
    let n = usize::from(first & 0x7f);
    let len = match n {
        1 => u64::from(*head.get(2)?),
        2 => u64::from(u16_be(head, 2)?),
        3 => u64::from(u32_be(head, 1)? & 0x00ff_ffff),
        4 => u64::from(u32_be(head, 2)?),
        _ => return None,
    };
    Some(len.saturating_add(to_u64(n)).saturating_add(2))
}

/// The hex string of `/Contents`, decoded: the DER object, then padding.
async fn signature_value(cx: Cx, (doc, hex): (DocRef, Span)) -> Result<()> {
    let decoded = codec::decode_span(&cx, hex, &Codec::AsciiHex, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    let data = decoded.span;
    let head = cx.read_avail(data.sub(0, 8)).await?;
    let der = match der_length(&head) {
        Some(len) if head.first() == Some(&0x30) && len <= data.len => len,
        _ => {
            cx.annotate(format!("{} bytes", data.len));
            cx.emit(Node::new("Data").span(data));
            return Ok(());
        }
    };
    let padding = data.len.saturating_sub(der);
    cx.annotate(format!("{der} bytes of DER, {padding} bytes of padding"));
    cx.emit(embedded_as(
        "PKCS #7 signature",
        doc.input.nested(data.sub(0, der)),
        &crate::formats::asn1::PKCS7,
    ));
    if padding > 0 {
        cx.emit(
            Node::new("Padding")
                .span(data.tail(der))
                .summary(format!("{padding} bytes"))
                .desc("Space reserved for the signature, unused"),
        );
    }
    Ok(())
}
