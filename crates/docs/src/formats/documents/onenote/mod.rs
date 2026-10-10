//! Microsoft OneNote sections (`.one`) and tables of contents (`.onetoc2`):
//! the revision store file format of [MS-ONESTORE] with the OneNote object
//! model of [MS-ONE] on top.
//!
//! Shown: the 1 KiB header (all fields, chunk references pointing at what
//! they reference); the transaction log, whose committed entries say how
//! many file nodes each file node list holds; file node lists as chained
//! fragments (header, nodes, next-fragment reference, footer) and every file
//! node typed by its FileNodeID with its body and what it references
//! (another list, an object's property set, a file data store object, an
//! ObjectInfoDependencyOverrideData); the free and hashed chunk lists; the
//! file data store with each stored file as embedded content.
//!
//! On top of that, the model: object spaces (one per page plus the
//! section's own), their revision manifests (dependencies, revision roles
//! and contexts, root objects, object groups, global identification tables)
//! and the objects visible in a revision, inherited along `ridDependent`.
//! Object property sets (ObjectSpaceObjectPropSet: the OID / OSID /
//! ContextID streams and the PropertySet) are decoded with property names
//! and typed values. "Pages" lists the pages in the order of the section's
//! page series, titled from the page metadata (CachedTitleString), with the
//! paragraphs (RichEditTextUnicode / TextExtendedAscii), images and attached
//! files found by walking the page's object graph from its content root.
//!
//! Provenance: written from memory of [MS-ONESTORE] and [MS-ONE] (no copy
//! of either was at hand), cross-checked against pyOneNote, an independent
//! reader. No OneNote writer was available, so the fixtures come from our
//! own generator; they do not prove agreement with files OneNote writes.
//! In particular from memory: the transaction log fragment layout, the
//! free chunk list layout, whether a ChunkTerminatorFND counts towards a
//! list's committed node count (here it does not), the FileDataStoreObject
//! header and footer GUIDs, and the JCIDs and property IDs (which match
//! pyOneNote's tables). Not handled: password-protected sections (object
//! data is encrypted; shown as unsupported), global identification table
//! entries copied from a dependency revision (GlobalIdTableEntry2FNDX and
//! 3FNDX, used by `.onetoc2`), and files referenced outside the section
//! (`<file>` references into the `onefiles` folder).

mod model;
mod props;
mod store;
mod tables;

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::datakit::guid_le;
use crate::formats::util::fmt::preview;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Value, lookup};

use model::{Model, Page, Space};
use props::{ObjectPropSet, PValue, PropSet};
use store::{Fcr, Hdr, IdTable, Store, fcr32, fcr64, fcr64x32, jcid_flags, jcid_name, jcid_value};
use tables::Kind;

const LE: Endian = Endian::Little;
const MAGIC_ONE: &[u8] = b"\xe4\x52\x5c\x7b\x8c\xd8\xa7\x4d\xae\xb1\x53\x78\xd0\x29\x96\xd3";
const MAGIC_TOC: &[u8] = b"\xa1\x2f\xff\x43\xd9\xef\x76\x4c\x9e\xe2\x10\xea\x57\x22\x76\x5f";
/// {109ADD3F-911B-49F5-A5D0-1791EDC8AED8}
const FILE_FORMAT: &str = "{109add3f-911b-49f5-a5d0-1791edc8aed8}";
/// FileDataStoreObject header and footer GUIDs.
const FDSO_HEADER: &str = "{bde316e7-2665-4511-a4c4-8d4d0b7a9eac}";
const FDSO_FOOTER: &str = "{71fba722-0f79-4a0b-bb13-899256426b24}";
/// How deeply file node list references are followed.
const MAX_LIST_DEPTH: usize = 32;
/// Seconds from 1970-01-01 to 1980-01-01 (Time32 epoch).
const TIME32_EPOCH: i64 = 315_532_800;

declare_format!(pub ONENOTE = "onenote", "Microsoft OneNote section", ["one"], "application/onenote",
    Probe::Magic(&[(0, MAGIC_ONE)]), dissect);

declare_format!(pub ONETOC2 = "onetoc2", "Microsoft OneNote table of contents", ["onetoc2"], "application/onenote",
    Probe::Magic(&[(0, MAGIC_TOC)]), dissect);

// ---------------------------------------------------------------------------
// Shared, cached state

async fn load_store(cx: &Cx, file: Span) -> Result<Arc<Store>> {
    if let Some(s) = cx.cached::<Store>(file, "onenote-store") {
        return Ok(s);
    }
    let head = cx.read(file.sub_exact(0, 0x400)?).await?;
    let mut store = Store::parse_header(file, &head);
    store.log =
        Arc::new(store::read_log(cx, file, store.transaction_log, store.transactions).await);
    let store = Arc::new(store);
    cx.cache(file, "onenote-store", store.clone());
    Ok(store)
}

async fn load_model(cx: &Cx, store: &Store) -> Arc<Model> {
    if let Some(m) = cx.cached::<Model>(store.file, "onenote-model") {
        return m;
    }
    let m = Arc::new(model::build(cx, store).await);
    cx.cache(store.file, "onenote-model", m.clone());
    m
}

type Pages = (Vec<Page>, Vec<Diagnostic>);

async fn load_pages(cx: &Cx, store: &Store, model: &Model) -> Arc<Pages> {
    if let Some(p) = cx.cached::<Pages>(store.file, "onenote-pages") {
        return p;
    }
    let p = Arc::new(model::pages(cx, store.file, model).await);
    cx.cache(store.file, "onenote-pages", p.clone());
    p
}

async fn context(cx: &Cx, file: Span) -> Result<(Arc<Store>, Arc<Model>)> {
    let store = load_store(cx, file).await?;
    let model = load_model(cx, &store).await;
    Ok((store, model))
}

fn page_title(p: &Page) -> String {
    p.title.clone().unwrap_or_else(|| "(untitled)".to_owned())
}

// ---------------------------------------------------------------------------
// Top level

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(struct_node(
        "Header",
        file.sub(0, 0x400),
        LE,
        file,
        header_layout,
    ));
    let (store, model) = context(&cx, file).await?;
    let mut annotation = if store.toc {
        "OneNote table of contents".to_owned()
    } else {
        "OneNote section".to_owned()
    };

    if !store.toc {
        let pages = load_pages(&cx, &store, &model).await;
        let titles: Vec<String> = pages.0.iter().map(page_title).collect();
        let mut node = Node::new("Pages")
            .value(uint(to_u64(titles.len()), 32))
            .summary(preview(&titles.join(" · "), 120))
            .lazy(pages_view, input);
        for d in &pages.1 {
            node = node.diag(d.clone());
        }
        cx.emit(node);
        annotation = match titles.len() {
            0 => format!("{annotation}, no pages"),
            1 => format!("{annotation}, 1 page: {}", preview(&titles.join(""), 60)),
            n => format!(
                "{annotation}, {n} pages: {}",
                preview(&titles.join(", "), 80)
            ),
        };
    }

    let mut spaces = Node::new("Object spaces")
        .value(uint(to_u64(model.spaces.len()), 32))
        .lazy(spaces_view, input);
    if model.spaces.iter().any(|s| s.encrypted) {
        annotation = format!("{annotation}, password-protected");
        spaces = spaces.diag(Diagnostic::unsupported(
            "password-protected section: object data is encrypted",
        ));
    }
    for d in &model.diags {
        spaces = spaces.diag(d.clone());
    }
    cx.emit(spaces);

    cx.emit(list_node(
        "Root file node list",
        input,
        store.root,
        &Path::new(),
    ));

    if !store.transaction_log.is_null() {
        let log = &store.log;
        let mut node = Node::new("Transaction log")
            .span(store.transaction_log.span(file))
            .summary(format!(
                "{} transactions, {} entries, {} lists",
                log.committed,
                log.entries.len(),
                log.counts.len()
            ))
            .lazy(txlog_view, input);
        for d in &log.diags {
            node = node.diag(d.clone());
        }
        cx.emit(node);
    }
    if !store.hashed_chunks.is_null() {
        cx.emit(list_node(
            "Hashed chunk list",
            input,
            store.hashed_chunks,
            &Path::new(),
        ));
    }
    if !store.free_chunks.is_null() {
        cx.emit(
            Node::new("Free chunk list")
                .span(store.free_chunks.span(file))
                .lazy(free_view, input),
        );
    }
    if let Some(fcr) = model.file_store.filter(|f| !f.is_null()) {
        let files = model.files.len();
        cx.emit(
            Node::new("File data store")
                .span(fcr.span(file))
                .value(uint(to_u64(files), 32))
                .summary(if files == 1 {
                    "1 file".to_owned()
                } else {
                    format!("{files} files")
                })
                .lazy(files_view, input),
        );
    }
    cx.annotate(annotation);
    Ok(())
}

fn fcr_node(name: &'static str, span: Span, fcr: Option<Fcr>, file: Span) -> Node {
    let mut node = Node::new(name).span(span);
    if let Some(fcr) = fcr {
        node = node.value(text(fcr.label()));
        if !fcr.is_null() {
            node = node.target(fcr.span(file));
        }
    }
    node
}

/// A FileChunkReference of `len` bytes (8: 32/32, 12: 64x32, 16: 64/64).
fn fcr_field(f: &mut Fields<'_>, name: &'static str, len: u64, file: Span) -> Result<Fcr> {
    let span = f.peek_span(len);
    let b = f.bytes(name, len).get()?;
    let fcr = match len {
        8 => fcr32(&b, 0),
        12 => fcr64x32(&b, 0),
        _ => fcr64(&b, 0),
    }
    .ok_or_else(|| Diagnostic::truncated(span, to_u64(b.len())))?;
    f.node(fcr_node(name, span, Some(fcr), file));
    Ok(fcr)
}

fn header_layout(f: &mut Fields<'_>, file: &Span) -> Result<()> {
    let file = *file;
    f.guid("guidFileType")
        .with(|g, n| {
            let s = g.to_string();
            n.summary(if s == "{7b5c52e4-d88c-4da7-aeb1-5378d02996d3}" {
                ".one section"
            } else if s == "{43ff2fa1-efd9-4c76-9ee2-10ea5722765f}" {
                ".onetoc2 table of contents"
            } else {
                "unknown"
            })
        })
        .emit()?;
    f.guid("guidFile").emit()?;
    f.guid("guidLegacyFileVersion").emit()?;
    f.guid("guidFileFormat")
        .check(|g| {
            (g.to_string() != FILE_FORMAT)
                .then(|| Diagnostic::warning("not the revision store file format GUID"))
        })
        .emit()?;
    f.u32("ffvLastCodeThatWroteToThisFile").hex().emit()?;
    f.u32("ffvOldestCodeThatHasWrittenToThisFile")
        .hex()
        .emit()?;
    f.u32("ffvNewestCodeThatHasWrittenToThisFile")
        .hex()
        .emit()?;
    f.u32("ffvOldestCodeThatMayReadThisFile").hex().emit()?;
    fcr_field(f, "fcrLegacyFreeChunkList", 8, file)?;
    fcr_field(f, "fcrLegacyTransactionLog", 8, file)?;
    f.u32("cTransactionsInLog").emit()?;
    f.u32("cbLegacyExpectedFileLength").hex().emit()?;
    f.u64("rgbPlaceholder").hex().emit()?;
    fcr_field(f, "fcrLegacyFileNodeListRoot", 8, file)?;
    f.u32("cbLegacyFreeSpaceInFreeChunkList").hex().emit()?;
    f.u8("fNeedsDefrag").emit()?;
    f.u8("fRepairedFile").emit()?;
    f.u8("fNeedsGarbageCollect").emit()?;
    f.u8("fHasNoEmbeddedFileObjects").emit()?;
    f.guid("guidAncestor").emit()?;
    f.u32("crcName").hex().desc("CRC of the file name").emit()?;
    fcr_field(f, "fcrHashedChunkList", 12, file)?;
    fcr_field(f, "fcrTransactionLog", 12, file)?;
    fcr_field(f, "fcrFileNodeListRoot", 12, file)?;
    fcr_field(f, "fcrFreeChunkList", 12, file)?;
    f.u64("cbExpectedFileLength")
        .hex()
        .check(|&v| {
            (v != file.len)
                .then(|| Diagnostic::warning(format!("the file is {:#x} bytes", file.len)))
        })
        .emit()?;
    f.u64("cbFreeSpaceInFreeChunkList").hex().emit()?;
    f.guid("guidFileVersion").emit()?;
    f.u64("nFileVersionGeneration").emit()?;
    f.guid("guidDenyReadFileVersion").emit()?;
    f.u32("grfDebugLogFlags").hex().emit()?;
    fcr_field(f, "fcrDebugLog", 12, file)?;
    fcr_field(f, "fcrAllocVerificationFreeChunkList", 12, file)?;
    f.u32("bnCreated")
        .desc("Build number of the application that created the file")
        .emit()?;
    f.u32("bnLastWroteToThisFile").emit()?;
    f.u32("bnOldestWritten").emit()?;
    f.u32("bnNewestWritten").emit()?;
    let rest = f.remaining();
    f.node(Node::new("rgbReserved").span(f.peek_span(rest)));
    Ok(())
}

// ---------------------------------------------------------------------------
// File node lists

#[derive(Clone)]
struct ListState {
    input: Input,
    fcr: Fcr,
    path: Path,
}

fn list_node(name: &'static str, input: Input, fcr: Fcr, path: &Path) -> Node {
    let node = fcr_node(name, fcr.span(input.span), Some(fcr), input.span);
    if fcr.is_null() {
        return node;
    }
    match path.enter(fcr.stp, MAX_LIST_DEPTH) {
        Ok(path) => node.lazy(
            crate::expander!(self::list_view: ListState),
            ListState { input, fcr, path },
        ),
        Err(d) => node.diag(d),
    }
}

/// Keeps the global identification table current while walking a list.
#[derive(Clone, Default)]
struct Tables {
    frozen: Arc<IdTable>,
    building: IdTable,
}

impl Tables {
    fn update(&mut self, hdr: &Hdr, body: &store::Body) {
        match hdr.id {
            0x01B | 0x01E | 0x01F | 0x021 | 0x022 => {
                self.building.clear();
                if hdr.id != 0x021 && hdr.id != 0x022 {
                    self.frozen = Arc::default();
                }
            }
            0x024 => {
                if let (Some(i), Some(g)) = (body.index, body.guid) {
                    self.building.insert(i, g);
                }
            }
            0x028 => self.frozen = Arc::new(self.building.clone()),
            _ => {}
        }
    }
}

async fn list_view(cx: Cx, st: ListState) -> Result<()> {
    let file = st.input.span;
    let store = load_store(&cx, file).await?;
    let list = store::read_list(&cx, &store, st.fcr).await;
    for d in &list.diags {
        cx.diag(d.clone());
    }
    let (start, mut tables) = match cx.resume::<(usize, Tables)>() {
        Some(r) => r,
        None => {
            cx.emit(
                Node::new("Fragments")
                    .value(uint(to_u64(list.fragments.len()), 32))
                    .summary(match list.id {
                        Some(id) => format!("FileNodeListID {id:#x}"),
                        None => String::new(),
                    })
                    .lazy(fragments_view, st.clone()),
            );
            (0, Tables::default())
        }
    };
    for (i, node) in list.nodes.iter().enumerate().skip(start) {
        cx.mark(|| (i, tables.clone()));
        let body = node.body(file, Some(&tables.frozen));
        let summary = body
            .as_ref()
            .map(|b| node_summary(&node.hdr, b, &tables.frozen))
            .unwrap_or_default();
        let state = NodeState {
            input: st.input,
            span: node.span,
            table: tables.frozen.clone(),
            path: st.path.clone(),
        };
        let mut n = Node::new(node.hdr.name()).span(node.span);
        if !summary.is_empty() {
            n = n.summary(summary);
        }
        n = n.lazy(crate::expander!(self::file_node_view: NodeState), state);
        if let Err(e) = &body {
            n = n.diag(e.clone());
        }
        if lookup(tables::FILE_NODE_IDS, node.hdr.id.into()).is_none() {
            n = n.diag(Diagnostic::warning(format!(
                "unknown FileNodeID {:#05x}",
                node.hdr.id
            )));
        }
        if let Ok(b) = &body {
            tables.update(&node.hdr, b);
        }
        cx.push(n).await;
    }
    Ok(())
}

fn node_summary(hdr: &Hdr, b: &store::Body, table: &IdTable) -> String {
    let oid = |b: &store::Body| {
        b.oid
            .map(|o| match o.resolve(Some(table)) {
                Some(ex) => ex.label(),
                None => match o {
                    store::Oid::Compact(c) => c.label(None),
                    store::Oid::Full(ex) => ex.label(),
                },
            })
            .unwrap_or_default()
    };
    let target = b
        .fcr
        .map(|f| format!(" → {}", f.label()))
        .unwrap_or_default();
    match hdr.id {
        0x004 | 0x00C | 0x014 => format!("gosid {}", b.id.unwrap_or_default().label()),
        0x008 => format!("gosid {}{target}", b.id.unwrap_or_default().label()),
        0x01B | 0x01E | 0x01F => {
            let mut s = format!(
                "rid {}, role {}",
                b.rid.unwrap_or_default().label(),
                b.role.unwrap_or(0)
            );
            if let Some(d) = b.dependent.filter(|d| !d.is_nil()) {
                s = format!("{s}, depends on {}", d.label());
            }
            s
        }
        0x05C | 0x05D => format!(
            "rid {} has role {}",
            b.rid.unwrap_or_default().label(),
            b.role.unwrap_or(0)
        ),
        0x024 => format!(
            "{} → {}",
            b.index.unwrap_or(0),
            guid_le(&b.guid.unwrap_or_default())
        ),
        0x059 | 0x05A => format!(
            "{} root {}",
            lookup(tables::ROOT_ROLES, b.role.unwrap_or(0).into()).unwrap_or("role ?"),
            oid(b)
        ),
        0x02D | 0x02E | 0x041 | 0x042 | 0x0A4 | 0x0A5 | 0x0C4 | 0x0C5 => {
            let j = b.jcid.map(jcid_name).unwrap_or_default();
            format!("{j} {}{target}", oid(b)).trim().to_owned()
        }
        0x072 | 0x073 => format!(
            "{} {} {}",
            b.jcid.map(jcid_name).unwrap_or_default(),
            b.file_ref.clone().unwrap_or_default(),
            b.extension.clone().unwrap_or_default()
        ),
        0x094 => format!("{}{target}", guid_le(&b.guid.unwrap_or_default())),
        0x0B0 | 0x0B4 | 0x08C => {
            format!("{}{target}", b.id.unwrap_or_default().label())
        }
        _ => target.trim_start().to_owned(),
    }
}

async fn fragments_view(cx: Cx, st: ListState) -> Result<()> {
    let store = load_store(&cx, st.input.span).await?;
    let list = store::read_list(&cx, &store, st.fcr).await;
    for (i, frag) in list.fragments.iter().enumerate() {
        let mut node = Node::new(format!("Fragment {i}"));
        if frag.magic != store::LIST_MAGIC || frag.footer != Some(store::LIST_FOOTER) {
            node = node.diag(Diagnostic::malformed("bad fragment magic or footer"));
        }
        cx.push(
            node.span(frag.span)
                .summary(format!(
                    "list {:#x}, sequence {}, {} file nodes, next {}",
                    frag.list_id,
                    frag.sequence,
                    frag.nodes,
                    frag.next.map(|n| n.label()).unwrap_or_default()
                ))
                .lazy(fragment_view, (st.input, frag.span)),
        )
        .await;
    }
    Ok(())
}

async fn fragment_view(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let head = cx.block(span.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u64("uintMagic")
        .hex()
        .check(|&v| (v != store::LIST_MAGIC).then(|| Diagnostic::malformed("bad magic")))
        .emit()?;
    f.u32("FileNodeListID").hex().emit()?;
    f.u32("nFragmentSequence").emit()?;
    let tail_at = span.len.saturating_sub(20);
    cx.emit(Node::new("rgFileNodes").span(span.sub(16, tail_at.saturating_sub(16))));
    let tail = cx.block(span.sub(tail_at, 20)).await?;
    let mut f = Fields::emitting(&cx, &tail, LE);
    fcr_field(&mut f, "nextFragment", 12, input.span)?;
    f.u64("footer")
        .hex()
        .check(|&v| (v != store::LIST_FOOTER).then(|| Diagnostic::malformed("bad footer")))
        .emit()?;
    Ok(())
}

#[derive(Clone)]
struct NodeState {
    input: Input,
    span: Span,
    table: Arc<IdTable>,
    path: Path,
}

async fn file_node_view(cx: Cx, st: NodeState) -> Result<()> {
    let file = st.input.span;
    let block = cx.block(st.span).await?;
    let raw = u32_le(&block.data, 0)
        .ok_or_else(|| Diagnostic::truncated(st.span.sub(0, 4), to_u64(block.data.len())))?;
    let hdr = Hdr::new(raw);
    let hspan = st.span.sub(0, 4);
    cx.emit(Node::new("FileNodeID").span(hspan).value(Value::Enum {
        raw: hdr.id.into(),
        bits: 10,
        name: lookup(tables::FILE_NODE_IDS, hdr.id.into()),
    }));
    cx.emit(Node::new("Size").span(hspan).value(uint(hdr.size, 13)));
    cx.emit(Node::new("StpFormat").span(hspan).value(Value::Enum {
        raw: hdr.stp_format.into(),
        bits: 2,
        name: lookup(tables::STP_FORMATS, hdr.stp_format.into()),
    }));
    cx.emit(Node::new("CbFormat").span(hspan).value(Value::Enum {
        raw: hdr.cb_format.into(),
        bits: 2,
        name: lookup(tables::CB_FORMATS, hdr.cb_format.into()),
    }));
    cx.emit(Node::new("BaseType").span(hspan).value(Value::Enum {
        raw: hdr.base_type.into(),
        bits: 4,
        name: lookup(tables::BASE_TYPES, hdr.base_type.into()),
    }));
    let mut reserved = Node::new("Reserved")
        .span(hspan)
        .value(Value::Bool(raw >> 31 == 1));
    if raw >> 31 != 1 {
        reserved = reserved.diag(Diagnostic::warning("must be 1"));
    }
    cx.emit(reserved);
    let mut f = Fields::emitting(&cx, &block, LE);
    f.seek(4);
    let body = store::body(&mut f, &hdr, file, Some(&st.table))?;
    if f.pos() < st.span.len {
        let rest = st.span.len.saturating_sub(f.pos());
        cx.emit(Node::new("Unparsed").span(f.peek_span(rest)));
    }
    let Some(fcr) = body.fcr.filter(|f| !f.is_null()) else {
        return Ok(());
    };
    if matches!(hdr.id, 0x0C2 | 0x0C4 | 0x0C5) {
        // guidHash / md5Hash: the MD5 of the referenced data.
        let stored = block
            .data
            .get(block.data.len().saturating_sub(16)..)
            .unwrap_or_default();
        let data = cx.read(file.sub_exact(fcr.stp, fcr.cb)?).await?;
        let digest =
            crate::formats::util::datakit::digest_paced::<crate::codec::crypto::Md5>(&cx, &data)
                .await;
        let mut node = Node::new("MD5 of the referenced data")
            .span(st.span.sub(st.span.len.saturating_sub(16), 16))
            .value(Value::Bool(digest == stored));
        if digest != stored {
            node = node.diag(Diagnostic::warning("does not match"));
        }
        cx.emit(node);
    }
    if hdr.base_type == 2 {
        cx.emit(list_node("Referenced list", st.input, fcr, &st.path));
    } else if body.has_property_set(hdr.id) {
        cx.emit(Node::new("Property set").span(fcr.span(file)).lazy(
            propset_view,
            PropState::new(st.input, fcr, st.table.clone()),
        ));
    } else if hdr.id == 0x094 {
        cx.emit(
            Node::new("File data store object")
                .span(fcr.span(file))
                .lazy(fdso_view, (st.input, fcr)),
        );
    } else if hdr.id == 0x084 {
        cx.emit(struct_node(
            "ObjectInfoDependencyOverrideData",
            fcr.span(file),
            LE,
            st.table.clone(),
            overrides_layout,
        ));
    } else {
        cx.emit(Node::new("Referenced data").span(fcr.span(file)));
    }
    Ok(())
}

fn overrides_layout(f: &mut Fields<'_>, table: &Arc<IdTable>) -> Result<()> {
    store::overrides(f, Some(table))
}

// ---------------------------------------------------------------------------
// Property sets

#[derive(Clone)]
struct PropState {
    input: Input,
    fcr: Fcr,
    table: Arc<IdTable>,
    /// Nested set: (property index, element index) steps from the body.
    path: Arc<Vec<(usize, usize)>>,
    /// Show the elements of this ArrayOfPropertyValues property.
    array: Option<usize>,
}

impl PropState {
    fn new(input: Input, fcr: Fcr, table: Arc<IdTable>) -> Self {
        PropState {
            input,
            fcr,
            table,
            path: Arc::default(),
            array: None,
        }
    }
}

fn nested<'a>(set: &'a PropSet, path: &[(usize, usize)]) -> Option<&'a PropSet> {
    let mut cur = set;
    for &(p, k) in path {
        cur = match &cur.props.get(p)?.value {
            PValue::Array(v) => v.get(k)?,
            PValue::Set(s) => s,
            _ => return None,
        };
    }
    Some(cur)
}

async fn propset_view(cx: Cx, st: PropState) -> Result<()> {
    let (data, ps, span) = model::property_set(&cx, st.input.span, st.fcr).await?;
    if st.path.is_empty() && st.array.is_none() {
        emit_streams(&cx, &ps, span, &st.table);
    }
    let set = nested(&ps.body, &st.path)
        .ok_or_else(|| Diagnostic::internal("nested property set not found"))?;
    if let Some(pi) = st.array {
        if let Some(PValue::Array(sets)) = set.props.get(pi).map(|p| &p.value) {
            for (k, s) in sets.iter().enumerate() {
                let mut path = st.path.as_ref().clone();
                path.push((pi, k));
                cx.push(
                    Node::new(format!("Element {k}"))
                        .span(model::inner(span, s.at, s.len))
                        .summary(format!("{} properties", s.props.len()))
                        .lazy(
                            crate::expander!(self::propset_view: PropState),
                            PropState {
                                path: Arc::new(path),
                                array: None,
                                ..st.clone()
                            },
                        ),
                )
                .await;
            }
        }
        return Ok(());
    }
    for (pi, p) in set.props.iter().enumerate() {
        let node = prop_node(p, &data, span, &st.table, &st, pi);
        cx.push(node).await;
    }
    Ok(())
}

fn emit_streams(cx: &Cx, ps: &ObjectPropSet, span: Span, table: &IdTable) {
    let streams = [
        ("OIDs", Some(&ps.oids)),
        ("OSIDs", ps.osids.as_ref()),
        ("ContextIDs", ps.contexts.as_ref()),
    ];
    for (name, s) in streams {
        let Some(s) = s else { continue };
        let mut flags = Vec::new();
        if s.header & 0x4000_0000 != 0 {
            flags.push("ExtendedStreamsPresent");
        }
        if s.header & 0x8000_0000 != 0 {
            flags.push("OsidStreamNotPresent");
        }
        let labels: Vec<String> = s.ids.iter().take(8).map(|c| c.label(Some(table))).collect();
        let more = if s.ids.len() > 8 { ", …" } else { "" };
        let mut summary = format!("{}{more}", labels.join("; "));
        if !flags.is_empty() {
            summary = format!("[{}] {summary}", flags.join(", "))
                .trim_end()
                .to_owned();
        }
        cx.emit(
            Node::new(name)
                .span(model::inner(span, s.at, s.len()))
                .value(uint(to_u64(s.ids.len()), 24))
                .summary(summary),
        );
    }
    cx.emit(
        Node::new("cProperties")
            .span(model::inner(span, ps.body.at, 2))
            .value(uint(to_u64(ps.body.props.len()), 16)),
    );
}

fn ids_summary(ids: &[Option<store::CompactId>], table: &IdTable) -> String {
    let labels: Vec<String> = ids
        .iter()
        .take(8)
        .map(|c| match c {
            Some(c) => c.label(Some(table)),
            None => "missing from the ID stream".to_owned(),
        })
        .collect();
    let more = if ids.len() > 8 { "; …" } else { "" };
    format!("{}{more}", labels.join("; "))
}

fn prop_node(
    p: &props::Prop,
    data: &[u8],
    span: Span,
    table: &IdTable,
    st: &PropState,
    pi: usize,
) -> Node {
    let raw = p.raw_id;
    let (name, kind) = match tables::property(raw) {
        Some((n, k)) => (n.to_owned(), k),
        None => (format!("Property {:#x}", raw & 0x03FF_FFFF), Kind::Plain),
    };
    let type_name = lookup(tables::PROPERTY_TYPES, p.kind().into()).unwrap_or("unknown type");
    let node_span = if p.data_len > 0 {
        model::inner(span, p.data_at, p.data_len)
    } else {
        model::inner(span, p.id_at, 4)
    };
    let node = Node::new(name)
        .span(node_span)
        .desc(format!("PropertyID {raw:#010x} ({type_name})"));
    match &p.value {
        PValue::NoData => node.summary("no data"),
        PValue::Bool(b) => node.value(Value::Bool(*b)),
        PValue::Int(v, width) => {
            let bits = width.saturating_mul(8);
            match kind {
                Kind::Float if *width == 4 => {
                    node.value(Value::Float(f64::from(f32::from_bits(*v as u32))))
                }
                Kind::Time32 => node.value(Value::Timestamp {
                    unix_seconds: i64::try_from(*v).unwrap_or(0).saturating_add(TIME32_EPOCH),
                }),
                Kind::FileTime => node.value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(*v),
                }),
                Kind::Color => {
                    let summary = if *v == 0xFFFF_FFFF {
                        "automatic".to_owned()
                    } else {
                        format!(
                            "#{:02x}{:02x}{:02x}",
                            v & 0xFF,
                            (v >> 8) & 0xFF,
                            (v >> 16) & 0xFF
                        )
                    };
                    node.value(hex(*v, bits)).summary(summary)
                }
                _ => node.value(uint(*v, bits)),
            }
        }
        PValue::Bytes(at, len) => {
            let bytes = data.get(*at..at.saturating_add(*len)).unwrap_or_default();
            match kind {
                Kind::Utf16 => node.value(text(props::utf16(bytes))),
                Kind::Ansi => node.value(text(props::ansi(bytes))),
                Kind::Guid if bytes.len() == 16 => node.value(Value::Guid(guid_le(bytes))),
                _ if tables::property(raw).is_none() && looks_like_utf16(bytes) => node
                    .value(text(props::utf16(bytes)))
                    .summary("unknown property, looks like UTF-16 text"),
                _ if bytes.len() <= 64 => node.value(Value::Bytes(bytes.to_vec())),
                _ => node.summary(format!("{} bytes", bytes.len())),
            }
        }
        PValue::Ids { stream, array, ids } => {
            let what = match stream {
                props::Stream::Objects => "object",
                props::Stream::Spaces => "object space",
                props::Stream::Contexts => "context",
            };
            if *array {
                node.value(uint(to_u64(ids.len()), 32))
                    .summary(format!("{what}s: {}", ids_summary(ids, table)))
            } else {
                node.value(text(ids_summary(ids, table))).summary(what)
            }
        }
        PValue::Array(sets) => node
            .value(uint(to_u64(sets.len()), 32))
            .summary("property sets")
            .lazy(
                crate::expander!(self::propset_view: PropState),
                PropState {
                    array: Some(pi),
                    ..st.clone()
                },
            ),
        PValue::Set(s) => {
            let mut path = st.path.as_ref().clone();
            path.push((pi, 0));
            node.summary(format!("{} properties", s.props.len())).lazy(
                crate::expander!(self::propset_view: PropState),
                PropState {
                    path: Arc::new(path),
                    array: None,
                    ..st.clone()
                },
            )
        }
    }
}

/// Whether bytes plausibly hold UTF-16LE text (at least two printable
/// characters, nothing but a trailing NUL otherwise).
fn looks_like_utf16(b: &[u8]) -> bool {
    let units: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&c| u16::from_le_bytes(c))
        .collect();
    let body = units.strip_suffix(&[0]).unwrap_or(&units);
    b.len().is_multiple_of(2)
        && body.len() >= 2
        && char::decode_utf16(body.iter().copied())
            .all(|c| c.is_ok_and(|c| !c.is_control() || matches!(c, '\t' | '\r' | '\n')))
}

// ---------------------------------------------------------------------------
// Object spaces, revisions, objects

/// `pages`: the first page of each object space (`None` in a table of
/// contents).
fn space_label(
    model: &Model,
    pages: Option<&BTreeMap<usize, &Page>>,
    i: usize,
    space: &Space,
) -> String {
    if model.root == Some(space.gosid) {
        return if pages.is_some() { "section" } else { "root" }.to_owned();
    }
    if let Some(p) = pages.and_then(|p| p.get(&i)) {
        return format!("page “{}”", page_title(p));
    }
    String::new()
}

async fn spaces_view(cx: Cx, input: Input) -> Result<()> {
    let (store, model) = context(&cx, input.span).await?;
    let pages = if store.toc {
        None
    } else {
        Some(load_pages(&cx, &store, &model).await)
    };
    let mut by_space = BTreeMap::new();
    for (k, p) in pages.iter().flat_map(|p| p.0.iter()).enumerate() {
        if k % 1024 == 1023 {
            cx.checkpoint().await;
        }
        by_space.entry(p.space).or_insert(p);
    }
    let by_space = pages.is_some().then_some(&by_space);
    for (i, space) in model.spaces.iter().enumerate() {
        let mut parts = vec![space_label(&model, by_space, i, space)];
        parts.push(format!("{} revisions", space.revisions.len()));
        if space.encrypted {
            parts.push("encrypted".to_owned());
        }
        parts.retain(|p| !p.is_empty());
        let mut node = Node::new("Object space")
            .value(text(space.gosid.label()))
            .summary(parts.join(", "))
            .lazy(space_view, (input, i));
        if let Some(fcr) = space.manifest {
            node = node.span(fcr.span(input.span));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn space_view(cx: Cx, (input, si): (Input, usize)) -> Result<()> {
    let (_, model) = context(&cx, input.span).await?;
    let space = model
        .spaces
        .get(si)
        .ok_or_else(|| Diagnostic::internal("object space not found"))?;
    if space.encrypted {
        cx.diag(Diagnostic::unsupported(
            "password-protected: object data is encrypted",
        ));
    }
    cx.emit(Node::new("gosid").value(text(space.gosid.label())));
    if let Some(fcr) = space.manifest {
        cx.emit(list_node(
            "Object space manifest list",
            input,
            fcr,
            &Path::new(),
        ));
    }
    if let Some(fcr) = space.revision_list {
        cx.emit(list_node(
            "Revision manifest list",
            input,
            fcr,
            &Path::new(),
        ));
    }
    let current = space.current(&cx, 1).await;
    for (ri, r) in space.revisions.iter().enumerate() {
        let mut parts = vec![format!("role {}", r.role)];
        if !r.context.is_nil() {
            parts.push(format!("context {}", r.context.label()));
        }
        if !r.dependent.is_nil() {
            parts.push(format!("depends on {}", r.dependent.label()));
        }
        parts.push(format!("{} objects", r.objects.len()));
        if current == Some(ri) {
            parts.push("current content".to_owned());
        }
        let mut node = Node::new("Revision")
            .value(text(r.rid.label()))
            .summary(parts.join(", "))
            .lazy(revision_view, (input, si, ri));
        if let Some(span) = r.decl {
            node = node.span(span);
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn revision_view(cx: Cx, (input, si, ri): (Input, usize, usize)) -> Result<()> {
    let (_, model) = context(&cx, input.span).await?;
    let (space, r) = model
        .spaces
        .get(si)
        .and_then(|s| Some((s, s.revisions.get(ri)?)))
        .ok_or_else(|| Diagnostic::internal("revision not found"))?;
    cx.emit(Node::new("rid").value(text(r.rid.label())));
    cx.emit(Node::new("ridDependent").value(text(r.dependent.label())));
    cx.emit(Node::new("RevisionRole").value(uint(r.role, 32)));
    if !r.context.is_nil() {
        cx.emit(Node::new("gctxid").value(text(r.context.label())));
    }
    let view = space.view(&cx, Some(ri)).await;
    for (role, oid) in &r.roots {
        let name = match lookup(tables::ROOT_ROLES, (*role).into()) {
            Some(n) => format!("Root ({n})"),
            None => format!("Root (role {role})"),
        };
        let summary = view
            .objects
            .get(oid)
            .and_then(|&at| space.object(at))
            .map(|o| jcid_name(o.jcid))
            .unwrap_or_else(|| "not declared".to_owned());
        cx.emit(Node::new(name).value(text(oid.label())).summary(summary));
    }
    for (id, fcr) in &r.groups {
        let mut node = list_node("Object group", input, *fcr, &Path::new());
        node = node.summary(id.label());
        cx.emit(node);
    }
    let mut objects = Node::new("Objects")
        .value(uint(to_u64(r.objects.len()), 32))
        .lazy(objects_view, (input, si, ri));
    if view.objects.len() > r.objects.len() {
        objects = objects.summary(format!(
            "{} visible including inherited",
            view.objects.len()
        ));
    }
    cx.emit(objects);
    Ok(())
}

async fn objects_view(cx: Cx, (input, si, ri): (Input, usize, usize)) -> Result<()> {
    let (_, model) = context(&cx, input.span).await?;
    let r = model
        .spaces
        .get(si)
        .and_then(|s| s.revisions.get(ri))
        .ok_or_else(|| Diagnostic::internal("revision not found"))?;
    let start = cx.resume::<usize>().unwrap_or(0);
    for (oi, o) in r.objects.iter().enumerate().skip(start) {
        cx.mark(move || oi);
        let mut node = Node::new(jcid_name(o.jcid))
            .span(o.decl)
            .value(text(o.oid.label()))
            .lazy(object_view, (input, si, ri, oi));
        if let Some(f) = &o.file_ref {
            node = node.summary(format!("{f} {}", o.extension.clone().unwrap_or_default()));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn object_view(cx: Cx, (input, si, ri, oi): (Input, usize, usize, usize)) -> Result<()> {
    let file = input.span;
    let (_, model) = context(&cx, file).await?;
    let o = model
        .spaces
        .get(si)
        .and_then(|s| s.object((ri, oi)))
        .ok_or_else(|| Diagnostic::internal("object not found"))?;
    cx.emit(Node::new("oid").value(text(o.oid.label())));
    cx.emit(
        Node::new("jcid")
            .value(jcid_value(o.jcid))
            .summary(jcid_flags(o.jcid)),
    );
    cx.emit(
        Node::new("Declaration")
            .span(o.decl)
            .summary(lookup(tables::FILE_NODE_IDS, o.node_id.into()).unwrap_or(""))
            .lazy(
                crate::expander!(self::file_node_view: NodeState),
                NodeState {
                    input,
                    span: o.decl,
                    table: o.table.clone(),
                    path: Path::new(),
                },
            ),
    );
    if let Some(r) = &o.file_ref {
        match model.file(r) {
            Some(df) => cx.emit(
                Node::new("File data store object")
                    .span(df.fcr.span(file))
                    .summary(o.extension.clone().unwrap_or_default())
                    .lazy(fdso_view, (input, df.fcr)),
            ),
            None => cx.emit(Node::new("File data").value(text(r.clone())).diag(
                Diagnostic::unsupported("the file is stored outside the section or is missing"),
            )),
        }
    }
    if let Some(fcr) = o.data {
        if space_encrypted(&model, si) {
            cx.emit(
                Node::new("Property set")
                    .span(fcr.span(file))
                    .diag(Diagnostic::unsupported("encrypted")),
            );
            return Ok(());
        }
        // The properties are the object's content: show them inline.
        propset_view(cx.clone(), PropState::new(input, fcr, o.table.clone())).await?;
    }
    Ok(())
}

fn space_encrypted(model: &Model, si: usize) -> bool {
    model.spaces.get(si).is_some_and(|s| s.encrypted)
}

// ---------------------------------------------------------------------------
// Pages

async fn pages_view(cx: Cx, input: Input) -> Result<()> {
    let (store, model) = context(&cx, input.span).await?;
    let pages = load_pages(&cx, &store, &model).await;
    for (k, p) in pages.0.iter().enumerate() {
        let mut node = Node::new(format!("Page {}", k.saturating_add(1)))
            .value(text(page_title(p)))
            .lazy(page_view, (input, k));
        if let Some(level) = p.level.filter(|&l| l > 1) {
            node = node.summary(format!("subpage, level {level}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn page_view(cx: Cx, (input, k): (Input, usize)) -> Result<()> {
    let file = input.span;
    let (store, model) = context(&cx, file).await?;
    let pages = load_pages(&cx, &store, &model).await;
    let page = pages
        .0
        .get(k)
        .ok_or_else(|| Diagnostic::internal("page not found"))?;
    let space = model
        .spaces
        .get(page.space)
        .ok_or_else(|| Diagnostic::internal("object space not found"))?;
    cx.emit(Node::new("Title").value(text(page_title(page))));
    if space.encrypted {
        return Err(Diagnostic::unsupported(
            "password-protected section: the page is encrypted",
        ));
    }
    // Timestamps from the metadata and content roots.
    for role in [2u32, 1] {
        let Some((obj, _)) = space.root(&cx, role).await else {
            continue;
        };
        let Some(fcr) = obj.data else { continue };
        let Ok((data, ps, span)) = model::property_set(&cx, file, fcr).await else {
            continue;
        };
        for &id in tables::PAGE_TIMES {
            if let Some((pi, p)) = ps
                .body
                .props
                .iter()
                .enumerate()
                .find(|(_, p)| p.raw_id == id)
            {
                let st = PropState::new(input, fcr, obj.table.clone());
                cx.emit(prop_node(p, &data, span, &obj.table, &st, pi));
            }
        }
    }
    let view = space.content(&cx).await;
    let Some(root) = view.roots.get(&1).copied() else {
        return Err(Diagnostic::malformed("the page has no content root"));
    };
    let (visits, diags) = model::walk(&cx, file, space, &view, root).await;
    for d in diags {
        cx.diag(d);
    }
    let mut title_depth: Option<u32> = None;
    for v in &visits {
        cx.checkpoint().await;
        if title_depth.is_some_and(|d| v.depth <= d) {
            title_depth = None;
        }
        let Some(obj) = space.object(v.at) else {
            continue;
        };
        if obj.jcid == tables::JCID_TITLE {
            title_depth = Some(v.depth);
            continue;
        }
        let Some((data, ps, span)) = &v.data else {
            continue;
        };
        match obj.jcid {
            tables::JCID_RICH_TEXT => {
                if let Some((t, at, len)) = ps.body.text(data) {
                    let name = if title_depth.is_some() {
                        "Title text"
                    } else {
                        "Paragraph"
                    };
                    cx.push(
                        Node::new(name)
                            .span(model::inner(*span, at, len))
                            .value(text(t)),
                    )
                    .await;
                }
            }
            tables::JCID_IMAGE | tables::JCID_EMBEDDED_FILE => {
                let image = obj.jcid == tables::JCID_IMAGE;
                let (container, name_prop) = if image {
                    (tables::PICTURE_CONTAINER, tables::IMAGE_FILENAME)
                } else {
                    (tables::EMBEDDED_FILE_CONTAINER, tables::EMBEDDED_FILE_NAME)
                };
                let label = if image { "Image" } else { "Attachment" };
                let filename = ps.body.string(data, name_prop);
                let file_obj = ps
                    .body
                    .object(container)
                    .and_then(|c| c.resolve(&obj.table))
                    .and_then(|oid| view.objects.get(&oid))
                    .and_then(|&at| space.object(at));
                let df = file_obj
                    .and_then(|o| o.file_ref.as_deref())
                    .and_then(|r| model.file(r));
                let mut node = match df {
                    Some(df) => match model::file_data(&cx, file, df.fcr).await {
                        Ok(data_span) => embedded(label, input.nested(data_span)),
                        Err(e) => Node::new(label).diag(e),
                    },
                    None => Node::new(label).diag(Diagnostic::unsupported(
                        "the file data is not in this section",
                    )),
                };
                let display = filename
                    .or_else(|| {
                        file_obj
                            .and_then(|o| o.extension.clone())
                            .map(|e| format!("({e})"))
                    })
                    .unwrap_or_default();
                node = node.value(text(display));
                if image && let Some(alt) = ps.body.string(data, tables::IMAGE_ALT_TEXT) {
                    node = node.summary(format!("alt text: {alt}"));
                } else if let Some(src) = ps.body.string(data, tables::SOURCE_FILEPATH) {
                    node = node.summary(format!("from {src}"));
                }
                cx.push(node).await;
            }
            _ => {}
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// File data store

async fn files_view(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (_, model) = context(&cx, file).await?;
    let mut extensions = std::collections::BTreeMap::new();
    for (n, o) in model
        .spaces
        .iter()
        .flat_map(|s| s.revisions.iter())
        .flat_map(|r| r.objects.iter())
        .enumerate()
    {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if let (Some(r), Some(e)) = (&o.file_ref, &o.extension)
            && let Some(guid) = r.strip_prefix("<ifndf>").and_then(store::parse_guid)
        {
            extensions.entry(guid).or_insert_with(|| e.clone());
        }
    }
    for df in &model.files {
        let ext = extensions.get(&df.guid).cloned();
        let size = match cx
            .read(file.sub_exact(df.fcr.stp, 36).unwrap_or(file.sub(0, 0)))
            .await
        {
            Ok(h) => u64_le(&h, 16),
            Err(_) => None,
        };
        let mut parts = Vec::new();
        if let Some(s) = size {
            parts.push(format!("{s} bytes"));
        }
        if let Some(e) = ext {
            parts.push(e);
        }
        cx.push(
            Node::new("File")
                .span(df.fcr.span(file))
                .value(Value::Guid(guid_le(&df.guid)))
                .summary(parts.join(", "))
                .lazy(fdso_view, (input, df.fcr)),
        )
        .await;
    }
    Ok(())
}

async fn fdso_view(cx: Cx, (input, fcr): (Input, Fcr)) -> Result<()> {
    let file = input.span;
    let span = file.sub_exact(fcr.stp, fcr.cb)?;
    let head = cx.block(span.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.guid("guidHeader")
        .check(|g| (g.to_string() != FDSO_HEADER).then(|| Diagnostic::malformed("bad header GUID")))
        .emit()?;
    let len = f.u64("cbLength").emit()?;
    f.u32("unused").emit()?;
    f.u64("reserved").emit()?;
    let room = fcr.cb.saturating_sub(36 + 16);
    let mut data = embedded("FileData", input.nested(span.sub(36, len.min(room))));
    if len > room {
        data = data.diag(Diagnostic::malformed(format!(
            "{len:#x} bytes do not fit the {:#x}-byte object",
            fcr.cb
        )));
    }
    cx.emit(data);
    let pad_at = 36u64.saturating_add(len.min(room));
    let footer_at = fcr.cb.saturating_sub(16);
    if footer_at > pad_at {
        cx.emit(Node::new("Padding").span(span.sub(pad_at, footer_at.saturating_sub(pad_at))));
    }
    let tail = cx.block(span.sub(footer_at, 16)).await?;
    let mut f = Fields::emitting(&cx, &tail, LE);
    f.guid("guidFooter")
        .check(|g| (g.to_string() != FDSO_FOOTER).then(|| Diagnostic::malformed("bad footer GUID")))
        .emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Transaction log and free chunk list

async fn txlog_view(cx: Cx, input: Input) -> Result<()> {
    let store = load_store(&cx, input.span).await?;
    let log = &store.log;
    for entries in log.entries.chunk_by(|a, b| a.transaction == b.transaction) {
        let Some(t) = entries.first().map(|e| e.transaction) else {
            continue;
        };
        // Enough entries to fill the clipped summary (each is at least
        // seven characters plus a separator).
        let lists: Vec<String> = entries
            .iter()
            .filter(|e| e.src > 1)
            .take(16)
            .map(|e| format!("{:#x} → {}", e.src, e.switch))
            .collect();
        let span = match (entries.first(), entries.last()) {
            (Some(a), Some(b))
                if a.span.source == b.span.source && b.span.end() >= a.span.offset =>
            {
                Span::new(
                    a.span.source,
                    a.span.offset,
                    b.span.end().saturating_sub(a.span.offset),
                )
            }
            _ => Span::new(input.span.source, 0, 0),
        };
        cx.push(
            Node::new(format!("Transaction {}", t.saturating_add(1)))
                .span(span)
                .summary(preview(&format!("node counts: {}", lists.join(", ")), 100))
                .lazy(tx_view, (input, t)),
        )
        .await;
    }
    Ok(())
}

async fn tx_view(cx: Cx, (input, t): (Input, u32)) -> Result<()> {
    let store = load_store(&cx, input.span).await?;
    for (n, e) in store.log.entries.iter().enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if e.transaction != t {
            continue;
        }
        let node = if e.src == 1 {
            Node::new("End of transaction")
                .value(hex(e.switch, 32))
                .desc("srcID 1; TransactionEntrySwitch is a CRC of the transaction")
        } else {
            Node::new(format!("List {:#x}", e.src))
                .value(uint(e.switch, 32))
                .summary("file nodes committed")
        };
        cx.push(node.span(e.span)).await;
    }
    Ok(())
}

async fn free_view(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let store = load_store(&cx, file).await?;
    let mut fcr = store.free_chunks;
    let mut seen = std::collections::BTreeSet::new();
    let mut fragment = 0u32;
    while !fcr.is_null() {
        if fragment >= 1024 || !seen.insert(fcr.stp) {
            cx.diag(Diagnostic::malformed(
                "free chunk list fragments form a cycle",
            ));
            break;
        }
        let span = file.sub_exact(fcr.stp, fcr.cb)?;
        let data = cx.read(span).await?;
        let next = fcr64x32(&data, 4);
        cx.push(
            Node::new(format!("Fragment {fragment}"))
                .span(span.sub(0, 16))
                .value(hex(u32_le(&data, 0).unwrap_or(0), 32))
                .summary(format!(
                    "crc; next {}",
                    next.map(|n| n.label()).unwrap_or_default()
                )),
        )
        .await;
        let mut at = 16usize;
        while let Some(chunk) = fcr64(&data, at) {
            cx.push(fcr_node(
                "Free chunk",
                span.sub(to_u64(at), 16),
                Some(chunk),
                file,
            ))
            .await;
            at = at.saturating_add(16);
        }
        fragment = fragment.saturating_add(1);
        match next {
            Some(n) => fcr = n,
            None => break,
        }
    }
    Ok(())
}
