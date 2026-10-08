//! LMDB (Lightning Memory-Mapped Database, 0.9.x data format version 1).
//!
//! Layout, from the LMDB sources (`mdb.c`) as built for 64-bit
//! little-endian hosts (the probe only matches that layout; 32-bit builds
//! use 4-byte page numbers and sizes and are not handled):
//!
//! - Every page starts with a 16-byte header: page number (u64), pad (u16;
//!   the key size on LEAF2 pages), flags (u16: branch 0x01, leaf 0x02,
//!   overflow 0x04, meta 0x08, LEAF2 0x20, sub-page 0x40), then either the
//!   lower and upper free-space bounds (u16 each) or, on overflow pages, the
//!   number of pages (u32). Branch and leaf pages continue with an array of
//!   u16 node offsets (from the page start); the number of nodes is
//!   `(lower - 16) / 2`.
//! - Pages 0 and 1 are meta pages: magic `0xBEEFC0DE`, version, the fixed
//!   map address, the map size, two database records (FREE_DBI and
//!   MAIN_DBI), the last used page and the transaction ID. The meta with the
//!   higher transaction ID is current. The free database record's pad field
//!   holds the page size.
//! - A database record is 48 bytes: pad (u32; the fixed value size for
//!   DUPFIXED), flags (u16), depth (u16), branch, leaf and overflow page
//!   counts, entries and the root page (u64 each; `u64::MAX` when empty).
//! - A node is `lo u16, hi u16, flags u16, ksize u16`, the key, then the
//!   data. On branch pages the child page is `lo | hi << 16 | flags << 32`;
//!   on leaf pages the data size is `lo | hi << 16`. Node flags: BIGDATA
//!   (0x01: the data is the page number of an overflow page), SUBDATA (0x02:
//!   the data is a database record, a named database in the main DB), and
//!   DUPDATA (0x04: the data holds the key's sorted duplicates, as a sub-page
//!   or, with SUBDATA, as a sub-database whose keys are the values).
//! - Named databases are SUBDATA entries of the main database. The free
//!   database maps transaction IDs to the list of pages they freed (a count
//!   followed by page numbers).

use std::collections::BTreeSet;
use std::sync::Arc;

use super::{label, plural, preview, read_label, uint, value_node};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;
const HEADER: u64 = 16;
const NODE_HEADER: u64 = 8;
const DB_LEN: u64 = 48;
const META_LEN: u64 = 136;
const MAGIC: u32 = 0xBEEF_C0DE;
const P_INVALID: u64 = u64::MAX;

const P_BRANCH: u16 = 0x01;
const P_LEAF: u16 = 0x02;
const P_OVERFLOW: u16 = 0x04;
const P_META: u16 = 0x08;
const P_LEAF2: u16 = 0x20;
const P_SUBP: u16 = 0x40;
/// Flags that describe a page's kind (the rest are runtime bookkeeping).
const P_KIND: u16 = P_BRANCH | P_LEAF | P_OVERFLOW | P_META | P_LEAF2 | P_SUBP;

const F_BIGDATA: u16 = 0x01;
const F_SUBDATA: u16 = 0x02;
const F_DUPDATA: u16 = 0x04;

const MDB_INTEGERKEY: u16 = 0x08;
const MDB_INTEGERDUP: u16 = 0x20;

/// Deepest B+tree followed.
const MAX_DEPTH: usize = 32;
/// Deepest nesting of databases followed (main → named → duplicates).
const MAX_NESTING: usize = 8;
/// Pages one walk may visit.
const MAX_VISITED: usize = 1 << 20;

const PAGE_FLAGS: FlagTable = &[
    flag(0x01, "BRANCH"),
    flag(0x02, "LEAF"),
    flag(0x04, "OVERFLOW"),
    flag(0x08, "META"),
    flag(0x10, "DIRTY"),
    flag(0x20, "LEAF2"),
    flag(0x40, "SUBP"),
    flag(0x4000, "LOOSE"),
    flag(0x8000, "KEEP"),
];
const NODE_FLAGS: FlagTable = &[
    flag(0x01, "BIGDATA"),
    flag(0x02, "SUBDATA"),
    flag(0x04, "DUPDATA"),
];
const DB_FLAGS: FlagTable = &[
    flag(0x02, "REVERSEKEY"),
    flag(0x04, "DUPSORT"),
    flag(0x08, "INTEGERKEY"),
    flag(0x10, "DUPFIXED"),
    flag(0x20, "INTEGERDUP"),
    flag(0x40, "REVERSEDUP"),
];

const ENV_FLAGS: FlagTable = &[
    flag(0x01, "FIXEDMAP"),
    flag(0x08, "INTEGERKEY"),
    flag(0x4000, "NOSUBDIR"),
];

fn sane_page_size(size: u64) -> bool {
    size.is_power_of_two() && (512..=1 << 16).contains(&size)
}

/// A database record (`MDB_db`).
#[derive(Clone, Copy, Debug)]
struct DbRecord {
    pad: u32,
    flags: u16,
    depth: u16,
    entries: u64,
    root: u64,
}

impl DbRecord {
    fn parse(d: &[u8], at: usize) -> Option<DbRecord> {
        Some(DbRecord {
            pad: u32_le(d, at)?,
            flags: u16_le(d, at.checked_add(4)?)?,
            depth: u16_le(d, at.checked_add(6)?)?,
            entries: u64_le(d, at.checked_add(32)?)?,
            root: u64_le(d, at.checked_add(40)?)?,
        })
    }

    fn summary(&self) -> String {
        let mut s = format!("{} entries, depth {}", self.entries, self.depth);
        let names: Vec<&str> = DB_FLAGS
            .iter()
            .filter(|f| u64::from(self.flags) & f.mask == f.value)
            .map(|f| f.name)
            .collect();
        if !names.is_empty() {
            s.push_str(&format!(", {}", names.join("|")));
        }
        s
    }
}

#[derive(Clone, Copy)]
struct Meta {
    magic: u32,
    version: u32,
    map_size: u64,
    free: DbRecord,
    main: DbRecord,
    last_page: u64,
    txnid: u64,
}

impl Meta {
    /// `data` is the page from its header on.
    fn parse(data: &[u8]) -> Option<Meta> {
        let m = data.get(to_usize(HEADER)..to_usize(HEADER.saturating_add(META_LEN)))?;
        Some(Meta {
            magic: u32_le(m, 0)?,
            version: u32_le(m, 4)?,
            map_size: u64_le(m, 16)?,
            free: DbRecord::parse(m, 24)?,
            main: DbRecord::parse(m, 72)?,
            last_page: u64_le(m, 120)?,
            txnid: u64_le(m, 128)?,
        })
    }

    fn problem(&self) -> Option<&'static str> {
        if self.magic != MAGIC {
            Some("bad magic")
        } else if self.version != 1 {
            Some("unknown version")
        } else {
            None
        }
    }
}

struct Env {
    input: Input,
    page_size: u64,
    /// Whole pages in the file.
    pages: u64,
}

type EnvRef = Arc<Env>;

impl Env {
    fn offset(&self, pgno: u64) -> Result<u64> {
        if pgno >= self.pages {
            return Err(Diagnostic::malformed(format!(
                "page {pgno} lies outside the file ({} pages)",
                self.pages
            )));
        }
        Ok(pgno.saturating_mul(self.page_size))
    }

    fn page_span(&self, pgno: u64) -> Option<Span> {
        let off = self.offset(pgno).ok()?;
        Some(self.input.span.sub(off, self.page_size))
    }
}

/// A branch, leaf or sub-page read into memory.
struct Page {
    /// `None` for a sub-page.
    pgno: Option<u64>,
    span: Span,
    data: Vec<u8>,
    flags: u16,
    pad: u16,
    count: u16,
}

/// A node on a branch or leaf page.
struct PNode {
    /// Offset of the node header within the page.
    at: u64,
    flags: u16,
    /// Data size (leaf) or the low bits of the child page (branch).
    lo_hi: u64,
    key: Span,
    /// Offset of the data within the page.
    data_at: u64,
}

impl Page {
    async fn load(cx: &Cx, env: &Env, pgno: u64) -> Result<Page> {
        let off = env.offset(pgno)?;
        let span = env.input.span.sub_exact(off, env.page_size)?;
        let page = Page::at(cx, Some(pgno), span).await?;
        let id = u64_le(&page.data, 0).unwrap_or(0);
        if id != pgno {
            cx.diag(
                Diagnostic::warning(format!("page {pgno} says it is page {id}")).at(span.sub(0, 8)),
            );
        }
        Ok(page)
    }

    async fn at(cx: &Cx, pgno: Option<u64>, span: Span) -> Result<Page> {
        let data = cx.read(span).await?;
        let flags = u16_le(&data, 10).unwrap_or(0);
        let pad = u16_le(&data, 8).unwrap_or(0);
        let lower = u16_le(&data, 12).unwrap_or(0);
        if flags & (P_BRANCH | P_LEAF) == 0 {
            return Err(Diagnostic::malformed(format!(
                "{} is not a branch or leaf page (flags {flags:#x})",
                Page::describe(pgno)
            ))
            .at(span.sub(10, 2)));
        }
        let count = lower.saturating_sub(16) / 2;
        Ok(Page {
            pgno,
            span,
            data,
            flags,
            pad,
            count,
        })
    }

    fn describe(pgno: Option<u64>) -> String {
        pgno.map_or_else(|| "sub-page".to_owned(), |p| format!("page {p}"))
    }

    fn is_leaf(&self) -> bool {
        self.flags & P_LEAF != 0
    }

    fn is_leaf2(&self) -> bool {
        self.flags & P_LEAF2 != 0
    }

    fn pointer_span(&self, i: u16) -> Span {
        self.span
            .sub(HEADER.saturating_add(u64::from(i).saturating_mul(2)), 2)
    }

    fn node(&self, i: u16) -> Option<PNode> {
        let at = u16_le(
            &self.data,
            to_usize(HEADER).saturating_add(usize::from(i).saturating_mul(2)),
        )?;
        let a = usize::from(at);
        let lo = u16_le(&self.data, a)?;
        let hi = u16_le(&self.data, a.checked_add(2)?)?;
        let flags = u16_le(&self.data, a.checked_add(4)?)?;
        let ksize = u16_le(&self.data, a.checked_add(6)?)?;
        let key_at = u64::from(at).checked_add(NODE_HEADER)?;
        let key = self.span.sub_exact(key_at, ksize.into()).ok()?;
        Some(PNode {
            at: at.into(),
            flags,
            lo_hi: u64::from(lo) | u64::from(hi) << 16,
            key,
            data_at: key_at.checked_add(ksize.into())?,
        })
    }

    /// The child page of branch node `n`.
    fn child(n: &PNode) -> u64 {
        n.lo_hi | u64::from(n.flags) << 32
    }

    /// The inline data of leaf node `n` (for BIGDATA, the overflow page
    /// number).
    fn node_data(&self, n: &PNode) -> Option<Span> {
        let len = if n.flags & F_BIGDATA != 0 { 8 } else { n.lo_hi };
        self.span.sub_exact(n.data_at, len).ok()
    }

    fn leaf2_key(&self, i: u16) -> Option<Span> {
        let size = u64::from(self.pad);
        self.span
            .sub_exact(HEADER.checked_add(u64::from(i).checked_mul(size)?)?, size)
            .ok()
    }

    fn bad_node(&self, i: u16) -> Diagnostic {
        Diagnostic::malformed(format!(
            "node {i} of {} lies outside the page",
            Page::describe(self.pgno)
        ))
        .at(self.pointer_span(i))
    }
}

// ---------------------------------------------------------------------------
// Top level

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let want = HEADER.saturating_add(META_LEN);
    let m0 = Meta::parse(&cx.read_avail(file.sub(0, want)).await?);
    let guess = m0
        .map(|m| u64::from(m.free.pad))
        .filter(|&s| sane_page_size(s));
    let page_size = guess.unwrap_or(4096);
    let m1 = Meta::parse(&cx.read_avail(file.sub(page_size, want)).await?);
    let metas = [m0, m1];
    let active = metas
        .iter()
        .enumerate()
        .filter_map(|(i, m)| m.filter(|m| m.problem().is_none()).map(|m| (i, m)))
        .fold(None, |best: Option<(usize, Meta)>, (i, m)| match best {
            Some((_, b)) if b.txnid >= m.txnid => best,
            _ => Some((i, m)),
        });
    let env: EnvRef = Arc::new(Env {
        input,
        page_size,
        pages: file.len.checked_div(page_size).unwrap_or(0),
    });

    for (i, meta) in metas.iter().enumerate() {
        let span = file.sub(to_u64(i).saturating_mul(page_size), page_size);
        let mut node = Node::new(if i == 0 { "Meta page 0" } else { "Meta page 1" }).span(span);
        match meta {
            Some(m) => {
                let state = match m.problem() {
                    Some(p) => p,
                    None if active.is_some_and(|(a, _)| a == i) => "current",
                    None => "previous",
                };
                node = node
                    .summary(format!("txn {}, {state}", m.txnid))
                    .lazy(page_detail, (env.clone(), to_u64(i)));
            }
            None => {
                node = node.diag(Diagnostic::truncated(
                    Span::new(span.source, span.offset, want),
                    span.len,
                ));
            }
        }
        cx.emit(node);
    }
    if guess.is_none() {
        cx.diag(
            Diagnostic::warning("page size not recorded in meta page 0; assuming 4096")
                .at(file.sub(HEADER.saturating_add(24), 4)),
        );
    }

    let Some((current, meta)) = active else {
        cx.annotate("LMDB database (no valid meta page)");
        return Err(Diagnostic::malformed("neither meta page is valid").at(file.sub(0, want)));
    };
    let meta_at = to_u64(current)
        .saturating_mul(page_size)
        .saturating_add(HEADER);
    for (name, record, at, kind) in [
        ("Main database", meta.main, 72u64, Kind::Main),
        ("Free database", meta.free, 24, Kind::Free),
    ] {
        cx.emit(
            Node::new(name)
                .span(file.sub(meta_at.saturating_add(at), DB_LEN))
                .summary(record.summary())
                .lazy(
                    database,
                    Database {
                        env: env.clone(),
                        record,
                        kind,
                        path: Path::new(),
                        int_values: false,
                    },
                ),
        );
    }
    cx.emit(
        Node::new("Pages")
            .span(file)
            .summary(format!("{} pages of {page_size} bytes", env.pages))
            .lazy(pages, env.clone()),
    );
    cx.annotate(format!(
        "LMDB v{}, {page_size}-byte pages, last page {}, txn {}, map size {} bytes",
        meta.version, meta.last_page, meta.txnid, meta.map_size
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Databases

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Main,
    Free,
    Named,
    /// A DUPSORT key's sub-database: its keys are the values.
    Dups,
}

#[derive(Clone)]
struct Database {
    env: EnvRef,
    record: DbRecord,
    kind: Kind,
    path: Path,
    /// Values are native integers (the parent is INTEGERDUP).
    int_values: bool,
}

struct Frame {
    page: Arc<Page>,
    next: u16,
}

struct Walk {
    env: EnvRef,
    frames: Vec<Frame>,
    visited: BTreeSet<u64>,
}

type WalkState = Vec<(u64, u16)>;

impl Walk {
    async fn start(cx: &Cx, env: &EnvRef, root: u64, resume: Option<WalkState>) -> Result<Walk> {
        let mut walk = Walk {
            env: env.clone(),
            frames: Vec::new(),
            visited: BTreeSet::new(),
        };
        if root == P_INVALID {
            return Ok(walk);
        }
        let levels = resume.unwrap_or_else(|| vec![(root, 0)]);
        for (pgno, next) in levels {
            let page = Page::load(cx, env, pgno).await?;
            walk.visited.insert(pgno);
            walk.frames.push(Frame {
                page: Arc::new(page),
                next,
            });
        }
        Ok(walk)
    }

    fn state(&self) -> WalkState {
        self.frames
            .iter()
            .map(|f| (f.page.pgno.unwrap_or(0), f.next))
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
            let Some(node) = page.node(i) else {
                cx.diag(page.bad_node(i));
                continue;
            };
            if let Err(e) = self.descend(cx, Page::child(&node)).await {
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
                "more than {MAX_VISITED} pages in one database"
            )));
        }
        if !self.visited.insert(child) {
            return Err(Diagnostic::malformed(format!(
                "page {child} is referenced more than once in the database"
            )));
        }
        let page = Page::load(cx, &self.env, child).await?;
        self.frames.push(Frame {
            page: Arc::new(page),
            next: 0,
        });
        Ok(())
    }
}

/// Expands a database: its records in key order.
async fn database(cx: Cx, db: Database) -> Result<()> {
    let resume = cx.resume::<WalkState>();
    let mut walk = Walk::start(&cx, &db.env, db.record.root, resume).await?;
    loop {
        let state = walk.state();
        let Some((page, i)) = walk.next(&cx).await? else {
            break;
        };
        cx.mark(move || state);
        let node = record_node(&cx, &db, &page, i).await?;
        cx.push(node).await;
    }
    Ok(())
}

/// A native integer (INTEGERKEY / INTEGERDUP) of 4 or 8 bytes.
fn integer(data: &[u8]) -> Option<u64> {
    match data.len() {
        4 => u32_le(data, 0).map(u64::from),
        8 => u64_le(data, 0),
        _ => None,
    }
}

fn int_value(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

/// A duplicate value (a key of a sub-page or sub-database).
async fn dup_value(cx: &Cx, env: &Env, span: Span, int: bool) -> Result<Node> {
    if int {
        let data = cx.read_avail(span.sub(0, 8)).await?;
        if let Some(v) = integer(&data) {
            return Ok(Node::new("Value").span(span).value(int_value(v)));
        }
    }
    value_node(cx, "Value", &env.input, span).await
}

async fn record_node(cx: &Cx, db: &Database, page: &Arc<Page>, i: u16) -> Result<Node> {
    let env = &db.env;
    if page.is_leaf2() {
        // Fixed-size keys: only in DUPFIXED sub-databases.
        return match page.leaf2_key(i) {
            Some(span) => dup_value(cx, env, span, db.int_values).await,
            None => Ok(Node::new(format!("Key {i}")).diag(page.bad_node(i))),
        };
    }
    let Some(n) = page.node(i) else {
        return Ok(Node::new(format!("Node {i}"))
            .span(page.pointer_span(i))
            .diag(page.bad_node(i)));
    };
    let Some(data) = page.node_data(&n) else {
        return Ok(Node::new(format!("Node {i}"))
            .span(page.span.sub(n.at, NODE_HEADER))
            .diag(page.bad_node(i)));
    };
    let span = page.span.sub(
        n.at,
        n.data_at.saturating_sub(n.at).saturating_add(data.len),
    );
    if db.kind == Kind::Dups {
        return dup_value(cx, env, n.key, db.int_values).await;
    }
    let key = cx.read_avail(n.key.sub(0, 96)).await?;
    let int_key = db.kind == Kind::Free || db.record.flags & MDB_INTEGERKEY != 0;
    let name = match integer(&key).filter(|_| int_key) {
        Some(v) if db.kind == Kind::Free => format!("Transaction {v}"),
        Some(v) => v.to_string(),
        None => label(&key, n.key.len),
    };
    let node = Node::new(name).span(span);

    if n.flags & F_SUBDATA != 0 {
        let raw = cx.read(data.sub(0, DB_LEN)).await?;
        let Some(record) = DbRecord::parse(&raw, 0) else {
            return Ok(node
                .diag(Diagnostic::malformed("database record is shorter than 48 bytes").at(data)));
        };
        let (kind, summary) = if n.flags & F_DUPDATA != 0 {
            (
                Kind::Dups,
                format!("{} values (sub-database)", record.entries),
            )
        } else {
            (Kind::Named, format!("database: {}", record.summary()))
        };
        let child = Database {
            env: env.clone(),
            record,
            kind,
            path: Path::new(),
            int_values: db.record.flags & MDB_INTEGERDUP != 0,
        };
        let node = node.summary(summary);
        return Ok(match db.path.enter(data.offset, MAX_NESTING) {
            Ok(path) => node.lazy(
                crate::expander!(self::database: Database),
                Database { path, ..child },
            ),
            Err(d) => node.diag(d),
        });
    }
    if n.flags & F_DUPDATA != 0 {
        let sub = Page::at(cx, None, data).await;
        return Ok(match sub {
            Ok(sub) => node
                .summary(format!("{} values (sub-page)", sub.count))
                .lazy(
                    subpage,
                    (env.clone(), data, db.record.flags & MDB_INTEGERDUP != 0),
                ),
            Err(d) => node.diag(d),
        });
    }

    let (value, overflow) = if n.flags & F_BIGDATA != 0 {
        let pg = u64_le(&cx.read(data).await?, 0).unwrap_or(0);
        let value = env.offset(pg).and_then(|off| {
            env.input
                .span
                .sub_exact(off.saturating_add(HEADER), n.lo_hi)
        });
        match value {
            Ok(v) => (v, Some((pg, data))),
            Err(d) => return Ok(node.diag(d)),
        }
    } else {
        (data, None)
    };
    let entry = Entry {
        env: env.clone(),
        header: page.span.sub(n.at, NODE_HEADER),
        key: n.key,
        value,
        overflow,
        free: db.kind == Kind::Free,
    };
    if entry.free {
        let count = u64_le(&cx.read_avail(value.sub(0, 8)).await?, 0).unwrap_or(0);
        return Ok(node
            .summary(format!("{} freed", plural(count, "page")))
            .lazy(self::entry, entry));
    }
    let head = cx.read_avail(value.sub(0, 64)).await?;
    Ok(node
        .value(preview(&head, value.len))
        .summary(format!("{} bytes", value.len))
        .lazy(self::entry, entry))
}

/// The values of a DUPSORT key kept in a sub-page.
async fn subpage(cx: Cx, (env, span, int): (EnvRef, Span, bool)) -> Result<()> {
    let page = Page::at(&cx, None, span).await?;
    for i in 0..page.count {
        let value = if page.is_leaf2() {
            page.leaf2_key(i)
        } else {
            page.node(i).map(|n| n.key)
        };
        let node = match value {
            Some(v) => dup_value(&cx, &env, v, int).await?,
            None => Node::new(format!("Value {i}")).diag(page.bad_node(i)),
        };
        cx.push(node).await;
    }
    Ok(())
}

#[derive(Clone)]
struct Entry {
    env: EnvRef,
    header: Span,
    key: Span,
    value: Span,
    /// The overflow page and the span of its number.
    overflow: Option<(u64, Span)>,
    free: bool,
}

async fn entry(cx: Cx, e: Entry) -> Result<()> {
    let key = cx.read_avail(e.key.sub(0, 256)).await?;
    let key_value = match integer(&key) {
        Some(v) if e.free => int_value(v),
        _ => preview(&key, e.key.len),
    };
    cx.emit(
        Node::new("Key")
            .span(e.key)
            .value(key_value)
            .summary(format!("{} bytes", e.key.len)),
    );
    if e.free {
        cx.emit(
            Node::new("Freed pages")
                .span(e.value)
                .lazy(page_list, (e.env.clone(), e.value)),
        );
    } else {
        cx.emit(value_node(&cx, "Value", &e.env.input, e.value).await?);
    }
    cx.emit(struct_node(
        "Node header",
        e.header,
        LE,
        (),
        leaf_node_layout,
    ));
    if let Some((pg, at)) = e.overflow {
        let mut node = uint("Overflow page", pg, at);
        if let Some(target) = e.env.page_span(pg) {
            node = node.target(target);
            let head = cx.read_avail(target.sub(0, HEADER)).await?;
            let flags = u16_le(&head, 10).unwrap_or(0);
            let pages = u32_le(&head, 12).unwrap_or(0);
            node = if flags & P_OVERFLOW == 0 {
                node.diag(Diagnostic::malformed(format!(
                    "page {pg} is not an overflow page (flags {flags:#x})"
                )))
            } else {
                node.summary(plural(pages.into(), "page"))
            };
        }
        cx.emit(node);
    }
    Ok(())
}

/// A free-list record's page numbers: a count, then the pages.
async fn page_list(cx: Cx, (env, span): (EnvRef, Span)) -> Result<()> {
    let head = cx.read(span.sub_exact(0, 8)?).await?;
    let count = u64_le(&head, 0).unwrap_or(0);
    cx.emit(uint("Count", count, span.sub(0, 8)));
    let ids = span.sub_exact(8, count.saturating_mul(8))?;
    const CHUNK: u64 = 512;
    let mut done = 0u64;
    while done < count {
        let n = count.saturating_sub(done).min(CHUNK);
        let data = cx
            .read(ids.sub(done.saturating_mul(8), n.saturating_mul(8)))
            .await?;
        for (k, raw) in data.as_chunks::<8>().0.iter().enumerate() {
            let pg = u64::from_le_bytes(*raw);
            let at = done.saturating_add(to_u64(k)).saturating_mul(8);
            let mut node = uint("Page", pg, ids.sub(at, 8));
            if let Some(target) = env.page_span(pg) {
                node = node.target(target);
            }
            cx.push(node).await;
        }
        done = done.saturating_add(n);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Layouts

fn page_header_layout(f: &mut Fields<'_>, overflow: &bool) -> Result<()> {
    f.u64("Page number").emit()?;
    f.u16("Pad").desc("Key size on LEAF2 pages").emit()?;
    f.u16("Flags").flags(PAGE_FLAGS).emit()?;
    if *overflow {
        f.u32("Pages").desc("Pages in this overflow run").emit()?;
    } else {
        f.u16("Lower bound")
            .desc("End of the node offset array")
            .emit()?;
        f.u16("Upper bound").desc("Start of the node data").emit()?;
    }
    Ok(())
}

fn db_layout(f: &mut Fields<'_>, free: &bool) -> Result<()> {
    if *free {
        f.u32("Page size")
            .desc("Kept in the free database's pad field")
            .emit()?;
        f.u16("Flags")
            .flags(ENV_FLAGS)
            .desc("The free database's flags and the environment's persistent flags")
            .emit()?;
    } else {
        f.u32("Pad")
            .desc("Value size of DUPFIXED databases")
            .emit()?;
        f.u16("Flags").flags(DB_FLAGS).emit()?;
    }
    f.u16("Depth").emit()?;
    f.u64("Branch pages").emit()?;
    f.u64("Leaf pages").emit()?;
    f.u64("Overflow pages").emit()?;
    f.u64("Entries").emit()?;
    f.u64("Root page")
        .with(|&r, n| {
            if r == P_INVALID {
                n.summary("empty")
            } else {
                n
            }
        })
        .emit()?;
    Ok(())
}

fn meta_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Magic")
        .hex()
        .check(|&m| (m != MAGIC).then(|| Diagnostic::malformed("bad LMDB magic")))
        .emit()?;
    f.u32("Version").emit()?;
    f.u64("Fixed map address").hex().emit()?;
    f.u64("Map size").emit()?;
    for (name, free) in [("Free database", true), ("Main database", false)] {
        f.node(struct_node(name, f.peek_span(DB_LEN), LE, free, db_layout));
        f.skip(DB_LEN);
    }
    f.u64("Last page").emit()?;
    f.u64("Transaction ID").emit()?;
    Ok(())
}

fn leaf_node_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Data size (bits 0-15)").emit()?;
    f.u16("Data size (bits 16-31)").emit()?;
    f.u16("Flags").flags(NODE_FLAGS).emit()?;
    f.u16("Key size").emit()?;
    Ok(())
}

fn branch_node_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Child page (bits 0-15)").emit()?;
    f.u16("Child page (bits 16-31)").emit()?;
    f.u16("Child page (bits 32-47)").emit()?;
    f.u16("Key size").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Pages

fn type_name(flags: u16) -> &'static str {
    match flags & P_KIND {
        P_BRANCH => "branch",
        P_LEAF => "leaf",
        x if x == P_LEAF | P_LEAF2 => "leaf (LEAF2)",
        P_OVERFLOW => "overflow",
        P_META => "meta",
        0 => "unused",
        _ => "unknown",
    }
}

async fn pages(cx: Cx, env: EnvRef) -> Result<()> {
    let mut pgno = cx.resume::<u64>().unwrap_or(0);
    while pgno < env.pages {
        cx.mark(move || pgno);
        cx.progress(pgno, env.pages);
        let off = pgno.saturating_mul(env.page_size);
        let head = cx.read(env.input.span.sub_exact(off, HEADER)?).await?;
        let flags = u16_le(&head, 10).unwrap_or(0);
        let lower = u16_le(&head, 12).unwrap_or(0);
        let mut extent = 1u64;
        let mut summary = type_name(flags).to_owned();
        if flags & P_OVERFLOW != 0 {
            let n = u64::from(u32_le(&head, 12).unwrap_or(1));
            extent = n.clamp(1, env.pages.saturating_sub(pgno).max(1));
            summary.push_str(&format!(", {}", plural(n, "page")));
        } else if flags & (P_BRANCH | P_LEAF) != 0 {
            summary.push_str(&format!(", {} keys", lower.saturating_sub(16) / 2));
        }
        let span = env
            .input
            .span
            .sub(off, extent.saturating_mul(env.page_size));
        let mut node = Node::new(format!("Page {pgno}"))
            .span(span)
            .summary(summary);
        if flags & P_KIND != 0 {
            node = node.lazy(page_detail, (env.clone(), pgno));
        }
        cx.push(node).await;
        pgno = pgno.saturating_add(extent);
    }
    Ok(())
}

async fn page_detail(cx: Cx, (env, pgno): (EnvRef, u64)) -> Result<()> {
    let off = env.offset(pgno)?;
    let span = env.input.span.sub(off, env.page_size);
    let head = cx.read(span.sub_exact(0, HEADER)?).await?;
    let flags = u16_le(&head, 10).unwrap_or(0);
    let overflow = flags & P_OVERFLOW != 0;
    cx.emit(struct_node(
        "Page header",
        span.sub(0, HEADER),
        LE,
        overflow,
        page_header_layout,
    ));
    if flags & P_META != 0 {
        cx.emit(struct_node(
            "Meta",
            span.sub(HEADER, META_LEN),
            LE,
            (),
            meta_layout,
        ));
    } else if overflow {
        let pages = u64::from(u32_le(&head, 12).unwrap_or(1));
        let len = pages.saturating_mul(env.page_size).saturating_sub(HEADER);
        cx.emit(Node::new("Data").span(env.input.span.sub(off.saturating_add(HEADER), len)));
    } else if flags & (P_BRANCH | P_LEAF) != 0 {
        let page = Page::load(&cx, &env, pgno).await?;
        raw_nodes(&cx, &env, &page).await?;
    }
    Ok(())
}

async fn raw_nodes(cx: &Cx, env: &Env, page: &Page) -> Result<()> {
    for i in 0..page.count {
        if page.is_leaf2() {
            let node = match page.leaf2_key(i) {
                Some(span) => Node::new(format!("Key {i}"))
                    .span(span)
                    .summary(read_label(cx, span).await?),
                None => Node::new(format!("Key {i}")).diag(page.bad_node(i)),
            };
            cx.push(node).await;
            continue;
        }
        let Some(n) = page.node(i) else {
            cx.push(
                Node::new(format!("Node {i}"))
                    .span(page.pointer_span(i))
                    .diag(page.bad_node(i)),
            )
            .await;
            continue;
        };
        let header = page.span.sub(n.at, NODE_HEADER);
        let key = read_label(cx, n.key).await?;
        let node = if page.is_leaf() {
            let data = page.node_data(&n).unwrap_or(page.span.sub(n.data_at, 0));
            let mut kinds = Vec::new();
            for (bit, name) in [
                (F_BIGDATA, "overflow"),
                (F_SUBDATA, "database"),
                (F_DUPDATA, "duplicates"),
            ] {
                if n.flags & bit != 0 {
                    kinds.push(name);
                }
            }
            let kind = if kinds.is_empty() {
                format!("{} bytes", n.lo_hi)
            } else {
                kinds.join(", ")
            };
            Node::new(format!("Node {i}"))
                .span(page.span.sub(
                    n.at,
                    n.data_at.saturating_sub(n.at).saturating_add(data.len),
                ))
                .summary(format!("{key} ({kind})"))
                .lazy(raw_node, (header, n.key, data, true))
        } else {
            let child = Page::child(&n);
            let key = if n.key.len == 0 {
                "(lowest)".to_owned()
            } else {
                key
            };
            let mut node = Node::new(format!("Node {i}"))
                .span(page.span.sub(n.at, NODE_HEADER.saturating_add(n.key.len)))
                .summary(format!("{key} → page {child}"))
                .lazy(raw_node, (header, n.key, n.key.sub(n.key.len, 0), false));
            if let Some(target) = env.page_span(child) {
                node = node.target(target);
            }
            node
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn raw_node(cx: Cx, (header, key, data, leaf): (Span, Span, Span, bool)) -> Result<()> {
    let block = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    if leaf {
        leaf_node_layout(&mut f, &())?;
    } else {
        branch_node_layout(&mut f, &())?;
    }
    cx.emit(Node::new("Key").span(key));
    if leaf {
        cx.emit(Node::new("Data").span(data));
    }
    Ok(())
}
