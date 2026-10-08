//! bbolt (etcd's maintained fork of BoltDB): a single-file copy-on-write
//! B+tree of nested buckets.
//!
//! Layout, as written by `go.etcd.io/bbolt` (from its source, `page.go`,
//! `meta.go`, `freelist.go`, `bucket.go`; native byte order, little-endian
//! on every platform etcd ships on):
//!
//! - Every page starts with a 16-byte header: page ID (u64), flags (u16:
//!   branch 0x01, leaf 0x02, meta 0x04, freelist 0x10), element count (u16)
//!   and overflow (u32, the number of extra pages the page spans).
//! - Pages 0 and 1 are meta pages: magic `0xED0CDAED`, version 2, page
//!   size, flags, the root bucket (root page, sequence), the freelist page
//!   (`u64::MAX` when the freelist is not synced), the high-water page ID,
//!   the transaction ID, and an FNV-1a 64-bit checksum of the preceding 56
//!   bytes. The valid meta with the higher transaction ID is the current one.
//! - The freelist page holds its count in the header (or, when the count is
//!   0xFFFF, in the first u64) followed by the free page IDs.
//! - Branch elements are `pos u32, ksize u32, pgid u64`; leaf elements are
//!   `flags u32, pos u32, ksize u32, vsize u32`; `pos` is relative to the
//!   element itself. A leaf element with flag 0x01 is a nested bucket whose
//!   value is a bucket header (root page u64, sequence u64); a root of 0 means
//!   an inline bucket, whose leaf page follows the header inside the value.
//!
//! etcd stores its keyspace in the bucket `key`: 17-byte revision keys (main
//! and sub revision, big-endian, joined by `_`) mapping to `mvccpb.KeyValue`
//! protobuf messages, which are shown through the schemaless protobuf
//! dissector.

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{plural, read_label, uint, value_node};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Input, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;
const HEADER: u64 = 16;
const ELEMENT: u64 = 16;
const META_LEN: u64 = 64;
const BRANCH: u16 = 0x01;
const LEAF: u16 = 0x02;
const META: u16 = 0x04;
const FREELIST: u16 = 0x10;
const BUCKET_LEAF: u32 = 0x01;
const MAGIC: u32 = 0xED0C_DAED;
const NO_FREELIST: u64 = u64::MAX;
/// Bytes of the meta covered by its checksum.
const CHECKSUMMED: usize = 56;
/// Deepest B-tree followed.
const MAX_DEPTH: usize = 32;
/// Deepest bucket nesting followed.
const MAX_NESTING: usize = 64;
/// Pages one walk may visit.
const MAX_VISITED: usize = 1 << 20;

const PAGE_FLAGS: FlagTable = &[
    flag(0x01, "branch"),
    flag(0x02, "leaf"),
    flag(0x04, "meta"),
    flag(0x10, "freelist"),
];
const ELEMENT_FLAGS: FlagTable = &[flag(0x01, "bucket")];

fn fnv64a(data: &[u8]) -> u64 {
    data.iter().fold(0xcbf2_9ce4_8422_2325, |h: u64, &b| {
        (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
    })
}

fn sane_page_size(size: u64) -> bool {
    size.is_power_of_two() && (512..=1 << 20).contains(&size)
}

/// A decoded meta page.
#[derive(Clone, Copy)]
struct Meta {
    magic: u32,
    version: u32,
    page_size: u32,
    root: u64,
    sequence: u64,
    freelist: u64,
    high: u64,
    txid: u64,
    checksum: u64,
    computed: u64,
}

impl Meta {
    /// `data` is the whole page from its header on.
    fn parse(data: &[u8]) -> Option<Meta> {
        let m = data.get(to_usize(HEADER)..to_usize(HEADER.saturating_add(META_LEN)))?;
        Some(Meta {
            magic: u32_le(m, 0)?,
            version: u32_le(m, 4)?,
            page_size: u32_le(m, 8)?,
            root: u64_le(m, 16)?,
            sequence: u64_le(m, 24)?,
            freelist: u64_le(m, 32)?,
            high: u64_le(m, 40)?,
            txid: u64_le(m, 48)?,
            checksum: u64_le(m, 56)?,
            computed: fnv64a(m.get(..CHECKSUMMED)?),
        })
    }

    fn valid(&self) -> bool {
        self.magic == MAGIC && self.version == 2 && self.checksum == self.computed
    }

    fn problem(&self) -> Option<&'static str> {
        if self.magic != MAGIC {
            Some("bad magic")
        } else if self.version != 2 {
            Some("unknown version")
        } else if self.checksum != self.computed {
            Some("checksum mismatch")
        } else {
            None
        }
    }
}

/// What every expansion needs to find pages.
struct Db {
    input: Input,
    page_size: u64,
    /// Whole pages in the file.
    pages: u64,
}

type DbRef = Arc<Db>;

impl Db {
    fn offset(&self, pgid: u64) -> Result<u64> {
        if pgid >= self.pages {
            return Err(Diagnostic::malformed(format!(
                "page {pgid} lies outside the file ({} pages)",
                self.pages
            )));
        }
        Ok(pgid.saturating_mul(self.page_size))
    }

    /// The first page of `pgid` (without its overflow pages), for links.
    fn page_span(&self, pgid: u64) -> Option<Span> {
        let off = self.offset(pgid).ok()?;
        Some(self.input.span.sub(off, self.page_size))
    }
}

/// A branch or leaf page (on disk or inline in a bucket value), with its
/// element array read.
struct Page {
    /// `None` for an inline bucket page.
    pgid: Option<u64>,
    span: Span,
    flags: u16,
    count: u16,
    elements: Vec<u8>,
}

/// A leaf element, with spans of its parts.
struct LeafElem {
    header: Span,
    flags: u32,
    key: Span,
    value: Span,
}

impl Page {
    async fn load(cx: &Cx, db: &Db, pgid: u64) -> Result<Page> {
        let off = db.offset(pgid)?;
        let head = cx.read(db.input.span.sub_exact(off, HEADER)?).await?;
        let overflow = u32_le(&head, 12).unwrap_or(0);
        let len = u64::from(overflow)
            .saturating_add(1)
            .saturating_mul(db.page_size);
        let span = db.input.span.sub(off, len);
        let page = Page::at(cx, Some(pgid), span).await?;
        let id = u64_le(&head, 0).unwrap_or(0);
        if id != pgid {
            cx.diag(
                Diagnostic::warning(format!("page {pgid} says it is page {id}")).at(span.sub(0, 8)),
            );
        }
        Ok(page)
    }

    async fn at(cx: &Cx, pgid: Option<u64>, span: Span) -> Result<Page> {
        let head = cx.read(span.sub_exact(0, HEADER)?).await?;
        let flags = u16_le(&head, 8).unwrap_or(0);
        let count = u16_le(&head, 10).unwrap_or(0);
        if flags & (BRANCH | LEAF) == 0 {
            return Err(Diagnostic::malformed(format!(
                "{} is not a branch or leaf page (flags {flags:#x})",
                Page::describe(pgid)
            ))
            .at(span.sub(8, 2)));
        }
        let elements = cx
            .read(span.sub_exact(HEADER, u64::from(count).saturating_mul(ELEMENT))?)
            .await?;
        Ok(Page {
            pgid,
            span,
            flags,
            count,
            elements,
        })
    }

    fn describe(pgid: Option<u64>) -> String {
        pgid.map_or_else(|| "inline page".to_owned(), |p| format!("page {p}"))
    }

    fn is_leaf(&self) -> bool {
        self.flags & LEAF != 0
    }

    fn elem_at(i: u16) -> u64 {
        HEADER.saturating_add(u64::from(i).saturating_mul(ELEMENT))
    }

    fn word(&self, i: u16, at: usize) -> Option<u32> {
        u32_le(
            &self.elements,
            usize::from(i).saturating_mul(16).saturating_add(at),
        )
    }

    /// Key span and child page of branch element `i`.
    fn branch(&self, i: u16) -> Option<(Span, u64)> {
        let pos = self.word(i, 0)?;
        let ksize = self.word(i, 4)?;
        let child = u64_le(
            &self.elements,
            usize::from(i).saturating_mul(16).saturating_add(8),
        )?;
        let key_at = Page::elem_at(i).checked_add(pos.into())?;
        let key = self.span.sub_exact(key_at, ksize.into()).ok()?;
        Some((key, child))
    }

    fn leaf(&self, i: u16) -> Option<LeafElem> {
        let flags = self.word(i, 0)?;
        let pos = self.word(i, 4)?;
        let ksize = self.word(i, 8)?;
        let vsize = self.word(i, 12)?;
        let at = Page::elem_at(i);
        let key_at = at.checked_add(pos.into())?;
        let key = self.span.sub_exact(key_at, ksize.into()).ok()?;
        let value = self
            .span
            .sub_exact(key_at.checked_add(ksize.into())?, vsize.into())
            .ok()?;
        Some(LeafElem {
            header: self.span.sub(at, ELEMENT),
            flags,
            key,
            value,
        })
    }

    fn bad_element(&self, i: u16) -> Diagnostic {
        Diagnostic::malformed(format!(
            "element {i} of {} points outside the page",
            Page::describe(self.pgid)
        ))
        .at(self.span.sub(Page::elem_at(i), ELEMENT))
    }
}

// ---------------------------------------------------------------------------
// Top level

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let first = cx
        .read_avail(file.sub(0, HEADER.saturating_add(META_LEN)))
        .await?;
    let m0 = Meta::parse(&first);
    let guess = m0
        .map(|m| u64::from(m.page_size))
        .filter(|&s| sane_page_size(s))
        .unwrap_or(4096);
    let second = cx
        .read_avail(file.sub(guess, HEADER.saturating_add(META_LEN)))
        .await?;
    let m1 = Meta::parse(&second);
    let metas = [m0, m1];
    // The current meta: valid, with the higher transaction ID.
    let newest = |ok: fn(&Meta) -> bool| {
        metas
            .iter()
            .enumerate()
            .filter_map(|(i, m)| m.filter(ok).map(|m| (i, m)))
            .fold(None, |best: Option<(usize, Meta)>, (i, m)| match best {
                Some((_, b)) if b.txid >= m.txid => best,
                _ => Some((i, m)),
            })
    };
    let valid = newest(Meta::valid);
    // With no valid meta (bbolt refuses to open the file), fall back to one
    // that at least has the magic, so the tree can still be inspected.
    let active = valid.or_else(|| newest(|m| m.magic == MAGIC && m.version == 2));
    let page_size = active
        .map(|(_, m)| u64::from(m.page_size))
        .filter(|&s| sane_page_size(s))
        .unwrap_or(guess);
    let db: DbRef = Arc::new(Db {
        input,
        page_size,
        pages: file.len.checked_div(page_size).unwrap_or(0),
    });

    for (i, meta) in metas.iter().enumerate() {
        let off = to_u64(i).saturating_mul(page_size);
        let span = file.sub(off, page_size);
        let mut node = Node::new(if i == 0 { "Meta page 0" } else { "Meta page 1" }).span(span);
        if let Some(m) = meta {
            let state = match m.problem() {
                Some(p) => p,
                None if valid.is_some_and(|(a, _)| a == i) => "current",
                None => "previous",
            };
            node = node
                .summary(format!("txid {}, {state}", m.txid))
                .lazy(page_detail, (db.clone(), to_u64(i)));
        } else {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, HEADER.saturating_add(META_LEN)),
                span.len,
            ));
        }
        cx.emit(node);
    }

    let Some((current, meta)) = active else {
        cx.annotate("bbolt database (no valid meta page)");
        return Err(Diagnostic::malformed("neither meta page is valid").at(file.sub(0, 80)));
    };
    if valid.is_none() {
        cx.diag(
            Diagnostic::malformed(format!(
                "neither meta page is valid; showing meta page {current} anyway"
            ))
            .at(file.sub(to_u64(current).saturating_mul(page_size), 80)),
        );
    }

    if meta.freelist == NO_FREELIST {
        cx.emit(Node::new("Freelist").summary("not synced (rebuilt on open)"));
    } else {
        let mut node = Node::new("Freelist").summary(format!("page {}", meta.freelist));
        if let Some(span) = db.page_span(meta.freelist) {
            node = node.span(span);
        }
        cx.emit(node.lazy(freelist, (db.clone(), meta.freelist)));
    }

    let root_at = to_u64(current)
        .saturating_mul(page_size)
        .saturating_add(HEADER)
        .saturating_add(16);
    cx.emit(
        Node::new("Root bucket")
            .span(file.sub(root_at, 16))
            .summary(format!(
                "root page {}, sequence {}",
                meta.root, meta.sequence
            ))
            .lazy(
                bucket,
                Bucket {
                    db: db.clone(),
                    root: Root::Page(meta.root),
                    path: Path::new(),
                    etcd_keys: false,
                },
            ),
    );

    cx.emit(
        Node::new("Pages")
            .span(file)
            .summary(format!("{} pages of {page_size} bytes", db.pages))
            .lazy(pages, db.clone()),
    );

    let mut summary = format!(
        "bbolt v{}, {} pages of {page_size} bytes, txid {}",
        meta.version, meta.high, meta.txid
    );
    if let Some(problem) = meta.problem() {
        summary.push_str(&format!(", meta {current}: {problem}"));
    } else if let Some(problem) = metas
        .get(1usize.saturating_sub(current))
        .copied()
        .flatten()
        .and_then(|m| m.problem())
    {
        summary.push_str(&format!(", other meta: {problem}"));
    }
    cx.annotate(summary);
    Ok(())
}

// ---------------------------------------------------------------------------
// Buckets

#[derive(Clone, Copy)]
enum Root {
    Page(u64),
    Inline(Span),
}

#[derive(Clone)]
struct Bucket {
    db: DbRef,
    root: Root,
    /// Buckets on the way here (by root page or inline offset).
    path: Path,
    /// Whether this is etcd's `key` bucket (values are mvccpb.KeyValue).
    etcd_keys: bool,
}

struct Frame {
    page: Arc<Page>,
    next: u16,
}

/// Walks a bucket's B+tree in key order, yielding leaf elements.
struct Walk {
    db: DbRef,
    frames: Vec<Frame>,
    visited: BTreeSet<u64>,
}

/// Restart point: each frame's page ID (the root's is ignored) and next
/// element.
type WalkState = Vec<(u64, u16)>;

impl Walk {
    async fn start(cx: &Cx, b: &Bucket, resume: Option<WalkState>) -> Result<Walk> {
        let root = match b.root {
            Root::Page(pgid) => Page::load(cx, &b.db, pgid).await?,
            Root::Inline(span) => {
                let page = Page::at(cx, None, span).await?;
                if !page.is_leaf() {
                    return Err(Diagnostic::malformed("inline bucket page is not a leaf")
                        .at(span.sub(8, 2)));
                }
                page
            }
        };
        let mut walk = Walk {
            db: b.db.clone(),
            frames: Vec::new(),
            visited: root.pgid.into_iter().collect(),
        };
        walk.frames.push(Frame {
            page: Arc::new(root),
            next: 0,
        });
        if let Some(state) = resume {
            let mut levels = state.into_iter();
            if let (Some((_, next)), Some(frame)) = (levels.next(), walk.frames.last_mut()) {
                frame.next = next;
            }
            for (pgid, next) in levels {
                let page = Page::load(cx, &walk.db, pgid).await?;
                walk.visited.insert(pgid);
                walk.frames.push(Frame {
                    page: Arc::new(page),
                    next,
                });
            }
        }
        Ok(walk)
    }

    fn state(&self) -> WalkState {
        self.frames
            .iter()
            .map(|f| (f.page.pgid.unwrap_or(0), f.next))
            .collect()
    }

    async fn next(&mut self, cx: &Cx) -> Result<Option<(Arc<Page>, u16)>> {
        loop {
            cx.checkpoint().await;
            let Some(frame) = self.frames.last_mut() else {
                return Ok(None);
            };
            if frame.next >= frame.page.count {
                self.frames.pop();
                continue;
            }
            let i = frame.next;
            frame.next = i.saturating_add(1);
            let page = frame.page.clone();
            if page.is_leaf() {
                return Ok(Some((page, i)));
            }
            let Some((_, child)) = page.branch(i) else {
                cx.diag(page.bad_element(i));
                continue;
            };
            if let Err(e) = self.descend(cx, child).await {
                cx.diag(e);
            }
        }
    }

    async fn descend(&mut self, cx: &Cx, child: u64) -> Result<()> {
        if self.frames.len() >= MAX_DEPTH {
            return Err(Diagnostic::limit(format!(
                "B+tree deeper than {MAX_DEPTH} levels"
            )));
        }
        if self.visited.len() >= MAX_VISITED {
            return Err(Diagnostic::limit(format!(
                "more than {MAX_VISITED} pages in one bucket"
            )));
        }
        if !self.visited.insert(child) {
            return Err(Diagnostic::malformed(format!(
                "page {child} is referenced more than once in the bucket"
            )));
        }
        let page = Page::load(cx, &self.db, child).await?;
        self.frames.push(Frame {
            page: Arc::new(page),
            next: 0,
        });
        Ok(())
    }
}

/// Expands a bucket: its entries in key order, nested buckets included.
async fn bucket(cx: Cx, b: Bucket) -> Result<()> {
    let resume = cx.resume::<WalkState>();
    let mut walk = Walk::start(&cx, &b, resume).await?;
    loop {
        let state = walk.state();
        let Some((page, i)) = walk.next(&cx).await? else {
            break;
        };
        cx.mark(move || state);
        let node = match page.leaf(i) {
            Some(elem) => entry_node(&cx, &b, elem).await?,
            None => Node::new(format!("Element {i}"))
                .span(page.span.sub(Page::elem_at(i), ELEMENT))
                .diag(page.bad_element(i)),
        };
        cx.push(node).await;
    }
    Ok(())
}

#[derive(Clone)]
struct Entry {
    input: Input,
    header: Span,
    key: Span,
    value: Span,
    etcd: bool,
}

async fn entry_node(cx: &Cx, b: &Bucket, elem: LeafElem) -> Result<Node> {
    let name = read_label(cx, elem.key).await?;
    let span = Span::new(
        elem.key.source,
        elem.key.offset,
        elem.key.len.saturating_add(elem.value.len),
    );
    let node = Node::new(name).span(span);
    if elem.flags & BUCKET_LEAF != 0 {
        let head = cx.read_avail(elem.value.sub(0, 16)).await?;
        let (Some(root), Some(sequence)) = (u64_le(&head, 0), u64_le(&head, 8)) else {
            return Ok(node.diag(
                Diagnostic::malformed("bucket value is shorter than a bucket header")
                    .at(elem.value),
            ));
        };
        let (root, id, summary) = if root == 0 {
            (
                Root::Inline(elem.value.tail(16)),
                elem.value.offset | 1 << 63,
                format!("inline bucket, sequence {sequence}"),
            )
        } else {
            (
                Root::Page(root),
                root,
                format!("bucket, root page {root}, sequence {sequence}"),
            )
        };
        let key = cx.read_avail(elem.key.sub(0, 4)).await?;
        let node = node.summary(summary);
        return Ok(match b.path.enter(id, MAX_NESTING) {
            Ok(path) => node.lazy(
                crate::expander!(self::bucket: Bucket),
                Bucket {
                    db: b.db.clone(),
                    root,
                    path,
                    etcd_keys: b.path.depth() == 0 && elem.key.len == 3 && key == b"key",
                },
            ),
            Err(d) => node.diag(d),
        });
    }
    let data = cx.read_avail(elem.value.sub(0, 64)).await?;
    let revision = if b.etcd_keys {
        etcd_revision(&cx.read_avail(elem.key.sub(0, 18)).await?)
    } else {
        None
    };
    let etcd = revision.is_some();
    let node = match revision {
        Some(r) => Node::new(r).span(span),
        None => node,
    };
    Ok(node
        .value(super::preview(&data, elem.value.len))
        .summary(format!("{} bytes", elem.value.len))
        .lazy(
            entry,
            Entry {
                input: b.db.input,
                header: elem.header,
                key: elem.key,
                value: elem.value,
                etcd,
            },
        ))
}

/// An etcd revision key: main and sub revision (big-endian u64s) joined
/// by `_`, with a trailing `t` on tombstones (deletions).
fn etcd_revision(key: &[u8]) -> Option<String> {
    let main = crate::bytes::u64_be(key, 0)?;
    let sub = crate::bytes::u64_be(key, 9)?;
    match (key.get(8), key.get(17), key.len()) {
        (Some(b'_'), None, 17) => Some(format!("revision {main}_{sub}")),
        (Some(b'_'), Some(b't'), 18) => Some(format!("revision {main}_{sub} (tombstone)")),
        _ => None,
    }
}

async fn entry(cx: Cx, e: Entry) -> Result<()> {
    let key = cx.read_avail(e.key.sub(0, 256)).await?;
    cx.emit(
        Node::new("Key")
            .span(e.key)
            .value(super::preview(&key, e.key.len))
            .summary(format!("{} bytes", e.key.len)),
    );
    if e.etcd {
        cx.emit(
            embedded_as(
                "Value",
                e.input.nested(e.value),
                &crate::formats::data::wire::protobuf::FORMAT,
            )
            .summary("mvccpb.KeyValue"),
        );
    } else {
        cx.emit(value_node(&cx, "Value", &e.input, e.value).await?);
    }
    cx.emit(struct_node(
        "Element",
        e.header,
        LE,
        (),
        leaf_element_layout,
    ));
    Ok(())
}

fn leaf_element_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Flags").flags(ELEMENT_FLAGS).emit()?;
    f.u32("Position")
        .desc("Offset of the key from this element")
        .emit()?;
    f.u32("Key size").emit()?;
    f.u32("Value size").emit()?;
    Ok(())
}

fn branch_element_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Position")
        .desc("Offset of the key from this element")
        .emit()?;
    f.u32("Key size").emit()?;
    f.u64("Child page").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pages

fn page_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Page ID").emit()?;
    f.u16("Flags").flags(PAGE_FLAGS).emit()?;
    f.u16("Count").emit()?;
    f.u32("Overflow")
        .desc("Additional pages this page spans")
        .emit()?;
    Ok(())
}

fn meta_layout(f: &mut Fields<'_>, computed: &u64) -> Result<()> {
    let computed = *computed;
    f.u32("Magic")
        .hex()
        .check(|&m| (m != MAGIC).then(|| Diagnostic::malformed("bad bbolt magic")))
        .emit()?;
    f.u32("Version").emit()?;
    f.u32("Page size").emit()?;
    f.u32("Flags").hex().emit()?;
    f.u64("Root bucket page").emit()?;
    f.u64("Root bucket sequence").emit()?;
    f.u64("Freelist page")
        .with(|&p, n| {
            if p == NO_FREELIST {
                n.summary("not synced")
            } else {
                n
            }
        })
        .emit()?;
    f.u64("High water mark")
        .desc("First page ID past the end of the used pages")
        .emit()?;
    f.u64("Transaction ID").emit()?;
    f.u64("Checksum")
        .hex()
        .desc("FNV-1a 64 of the meta fields before it")
        .check(|&c| {
            (c != computed).then(|| {
                Diagnostic::malformed(format!("checksum mismatch (computed {computed:#018x})"))
            })
        })
        .emit()?;
    Ok(())
}

fn type_name(flags: u16) -> &'static str {
    match flags {
        BRANCH => "branch",
        LEAF => "leaf",
        META => "meta",
        FREELIST => "freelist",
        0 => "unused",
        _ => "unknown",
    }
}

/// Lists every page of the file with its header.
async fn pages(cx: Cx, db: DbRef) -> Result<()> {
    let mut pgid = cx.resume::<u64>().unwrap_or(0);
    while pgid < db.pages {
        cx.mark(move || pgid);
        cx.progress(pgid, db.pages);
        let off = pgid.saturating_mul(db.page_size);
        let head = cx.read(db.input.span.sub_exact(off, HEADER)?).await?;
        let flags = u16_le(&head, 8).unwrap_or(0);
        let count = u16_le(&head, 10).unwrap_or(0);
        let overflow = u64::from(u32_le(&head, 12).unwrap_or(0));
        let left = db.pages.saturating_sub(pgid);
        // Pages bbolt has freed are not cleared, so without a synced
        // freelist the walk meets stale bytes: the middle of an old overflow
        // run, say. Only a header that names this page, one page type and an
        // extent inside the file is believed; anything else is one page of
        // leftovers.
        let id = u64_le(&head, 0).unwrap_or(0);
        let known = matches!(flags, BRANCH | LEAF | META | FREELIST);
        if flags != 0 && !(known && id == pgid && overflow < left) {
            let span = db.input.span.sub(off, db.page_size);
            cx.push(
                Node::new(format!("Page {pgid}"))
                    .span(span)
                    .summary("no page header (free, or part of an old overflow run)"),
            )
            .await;
            pgid = pgid.saturating_add(1);
            continue;
        }
        // An unused (zeroed) page never spans more than itself.
        let extent = if flags == 0 {
            1
        } else {
            overflow.saturating_add(1)
        };
        let span = db.input.span.sub(off, extent.saturating_mul(db.page_size));
        let mut summary = type_name(flags).to_owned();
        if flags & (BRANCH | LEAF | FREELIST) != 0 {
            summary.push_str(&format!(", {}", plural(count.into(), "element")));
        }
        if extent > 1 {
            summary.push_str(&format!(", {}", plural(overflow, "overflow page")));
        }
        let mut node = Node::new(format!("Page {pgid}"))
            .span(span)
            .summary(summary);
        if flags != 0 {
            node = node.lazy(page_detail, (db.clone(), pgid));
        }
        cx.push(node).await;
        pgid = pgid.saturating_add(extent.max(1));
    }
    Ok(())
}

/// One page's header and raw elements.
async fn page_detail(cx: Cx, (db, pgid): (DbRef, u64)) -> Result<()> {
    let off = db.offset(pgid)?;
    let page = db.input.span.sub(off, db.page_size);
    cx.emit(struct_node(
        "Page header",
        page.sub(0, HEADER),
        LE,
        (),
        page_header_layout,
    ));
    let head = cx.read(page.sub_exact(0, HEADER)?).await?;
    let flags = u16_le(&head, 8).unwrap_or(0);
    match flags {
        META => {
            let data = cx
                .read_avail(page.sub(0, HEADER.saturating_add(META_LEN)))
                .await?;
            let computed = Meta::parse(&data).map_or(0, |m| m.computed);
            cx.emit(struct_node(
                "Meta",
                page.sub(HEADER, META_LEN),
                LE,
                computed,
                meta_layout,
            ));
        }
        FREELIST => freelist_ids(&cx, &db, pgid).await?,
        _ if flags & (BRANCH | LEAF) != 0 => {
            let page = Page::load(&cx, &db, pgid).await?;
            elements(&cx, &db, &page).await?;
        }
        _ => {}
    }
    Ok(())
}

/// The raw elements of a branch or leaf page.
async fn elements(cx: &Cx, db: &Db, page: &Page) -> Result<()> {
    for i in 0..page.count {
        let header = page.span.sub(Page::elem_at(i), ELEMENT);
        let node = Node::new(format!("Element {i}")).span(header);
        let node = if page.is_leaf() {
            match page.leaf(i) {
                Some(e) => {
                    let key = read_label(cx, e.key).await?;
                    let kind = if e.flags & BUCKET_LEAF != 0 {
                        "bucket"
                    } else {
                        "value"
                    };
                    node.summary(format!("{key} ({kind}, {} bytes)", e.value.len))
                        .lazy(raw_leaf_element, (header, e.key, e.value))
                }
                None => node.diag(page.bad_element(i)),
            }
        } else {
            match page.branch(i) {
                Some((key, child)) => {
                    let label = read_label(cx, key).await?;
                    let mut node = node
                        .summary(format!("{label} → page {child}"))
                        .lazy(raw_branch_element, (header, key));
                    if let Some(target) = db.page_span(child) {
                        node = node.target(target);
                    }
                    node
                }
                None => node.diag(page.bad_element(i)),
            }
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn raw_leaf_element(cx: Cx, (header, key, value): (Span, Span, Span)) -> Result<()> {
    let block = cx.block(header).await?;
    leaf_element_layout(&mut Fields::emitting(&cx, &block, LE), &())?;
    cx.emit(Node::new("Key").span(key));
    cx.emit(Node::new("Value").span(value));
    Ok(())
}

async fn raw_branch_element(cx: Cx, (header, key): (Span, Span)) -> Result<()> {
    let block = cx.block(header).await?;
    branch_element_layout(&mut Fields::emitting(&cx, &block, LE), &())?;
    cx.emit(Node::new("Key").span(key));
    Ok(())
}

// ---------------------------------------------------------------------------
// Freelist

async fn freelist(cx: Cx, (db, pgid): (DbRef, u64)) -> Result<()> {
    let off = db.offset(pgid)?;
    cx.emit(struct_node(
        "Page header",
        db.input.span.sub(off, HEADER),
        LE,
        (),
        page_header_layout,
    ));
    freelist_ids(&cx, &db, pgid).await
}

async fn freelist_ids(cx: &Cx, db: &Db, pgid: u64) -> Result<()> {
    let off = db.offset(pgid)?;
    let head = cx.read(db.input.span.sub_exact(off, HEADER)?).await?;
    let flags = u16_le(&head, 8).unwrap_or(0);
    if flags != FREELIST {
        return Err(Diagnostic::malformed(format!(
            "page {pgid} is not a freelist page (flags {flags:#x})"
        ))
        .at(db.input.span.sub(off.saturating_add(8), 2)));
    }
    let overflow = u64::from(u32_le(&head, 12).unwrap_or(0));
    let page = db
        .input
        .span
        .sub(off, overflow.saturating_add(1).saturating_mul(db.page_size));
    let mut count = u64::from(u16_le(&head, 10).unwrap_or(0));
    let mut start = HEADER;
    if count == 0xffff {
        let span = page.sub_exact(HEADER, 8)?;
        count = u64_le(&cx.read(span).await?, 0).unwrap_or(0);
        cx.emit(uint("Count", count, span).desc("Free page count (the header holds 0xFFFF)"));
        start = HEADER.saturating_add(8);
    }
    let ids = page.sub_exact(start, count.saturating_mul(8))?;
    let mut done = 0u64;
    const CHUNK: u64 = 512;
    while done < count {
        let n = (count.saturating_sub(done)).min(CHUNK);
        let data = cx
            .read(ids.sub(done.saturating_mul(8), n.saturating_mul(8)))
            .await?;
        for (k, raw) in data.as_chunks::<8>().0.iter().enumerate() {
            let id = u64::from_le_bytes(*raw);
            let at = done.saturating_add(to_u64(k)).saturating_mul(8);
            let mut node = uint("Free page", id, ids.sub(at, 8));
            if let Some(target) = db.page_span(id) {
                node = node.target(target);
            }
            cx.push(node).await;
        }
        done = done.saturating_add(n);
    }
    Ok(())
}
