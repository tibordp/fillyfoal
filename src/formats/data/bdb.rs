//! Berkeley DB databases (B-tree, hash, recno and queue access methods):
//! the metadata page, every page by number, and the records — a B-tree is
//! walked from its root (with a visited set), hash pages are listed in
//! order, and overflow items are reassembled from their page chains as
//! piecewise sources.

use std::collections::BTreeSet;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value, lookup};

const BTREE: u32 = 0x0005_3162;
const HASH: u32 = 0x0006_1561;
const QUEUE: u32 = 0x0004_2253;
const HEAP: u32 = 0x0007_4582;
/// Page header size.
const HEADER: u64 = 26;
/// B-tree depth followed.
const MAX_DEPTH: usize = 64;

pub static FORMAT: Format = Format {
    name: "bdb",
    title: "Berkeley DB database",
    extensions: &["db", "bdb"],
    mime: "application/x-berkeley-db",
    probe: Probe::Custom(|h| endian(h.data).is_some() && pagesize(h).is_some()),
    dissect: crate::expander!(dissect: Input),
};

fn read_u32(data: &[u8], at: usize, e: Endian) -> Option<u32> {
    match e {
        Endian::Little => crate::bytes::u32_le(data, at),
        Endian::Big => crate::bytes::u32_be(data, at),
    }
}

fn read_u16(data: &[u8], at: usize, e: Endian) -> Option<u16> {
    match e {
        Endian::Little => crate::bytes::u16_le(data, at),
        Endian::Big => crate::bytes::u16_be(data, at),
    }
}

/// The byte order whose magic number matches at offset 12.
fn endian(data: &[u8]) -> Option<Endian> {
    [Endian::Little, Endian::Big]
        .into_iter()
        .find(|&e| read_u32(data, 12, e).is_some_and(|m| matches!(m, BTREE | HASH | QUEUE | HEAP)))
}

fn pagesize(h: &Head<'_>) -> Option<u32> {
    let e = endian(h.data)?;
    let size = read_u32(h.data, 20, e)?;
    let version = read_u32(h.data, 16, e)?;
    (size.is_power_of_two() && (512..=65536).contains(&size) && (1..=20).contains(&version))
        .then_some(size)
}

const PAGE_TYPES: EnumTable = &[
    (0, "invalid"),
    (1, "duplicate (old)"),
    (2, "hash (unsorted)"),
    (3, "B-tree internal"),
    (4, "recno internal"),
    (5, "B-tree leaf"),
    (6, "recno leaf"),
    (7, "overflow"),
    (8, "hash metadata"),
    (9, "B-tree metadata"),
    (10, "queue metadata"),
    (11, "queue data"),
    (12, "duplicate leaf"),
    (13, "hash"),
    (14, "heap metadata"),
    (15, "heap"),
    (16, "heap internal"),
];

const MAGICS: EnumTable = &[
    (0x0005_3162, "B-tree"),
    (0x0006_1561, "hash"),
    (0x0004_2253, "queue"),
    (0x0007_4582, "heap"),
];

struct Db {
    input: Input,
    endian: Endian,
    pagesize: u64,
    last: u32,
}

type DbRef = Arc<Db>;

impl Db {
    fn page(&self, no: u32) -> Span {
        self.input
            .span
            .sub(u64::from(no).saturating_mul(self.pagesize), self.pagesize)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 512)).await?;
    let e =
        endian(&head).ok_or_else(|| Diagnostic::malformed("unknown magic").at(file.sub(12, 4)))?;
    let u32v = |at: usize| read_u32(&head, at, e).unwrap_or(0);
    let magic = u32v(12);
    let pagesize = u64::from(u32v(20));
    if !pagesize.is_power_of_two() || !(512..=65536).contains(&pagesize) {
        return Err(
            Diagnostic::malformed(format!("invalid page size {pagesize}")).at(file.sub(20, 4)),
        );
    }
    let in_file = u32::try_from(file.len.checked_div(pagesize).unwrap_or(0))
        .unwrap_or(u32::MAX)
        .saturating_sub(1);
    let last = match u32v(32) {
        0 => in_file,
        n => n.min(in_file),
    };
    let db: DbRef = Arc::new(Db {
        input,
        endian: e,
        pagesize,
        last,
    });
    let meta = file.sub(0, 72);
    let num = |name: &'static str, at: u64, radix: Radix| {
        Node::new(name).span(meta.sub(at, 4)).value(Value::UInt {
            value: u32v(to_usize(at)).into(),
            bits: 32,
            radix,
        })
    };
    let mut fields = vec![
        Node::new("LSN")
            .span(meta.sub(0, 8))
            .value(Value::Text(format!("{}/{}", u32v(0), u32v(4)))),
        num("Page number", 8, Radix::Dec),
        Node::new("Magic").span(meta.sub(12, 4)).value(Value::Enum {
            raw: magic.into(),
            bits: 32,
            name: lookup(MAGICS, magic.into()),
        }),
        num("Version", 16, Radix::Dec),
        num("Page size", 20, Radix::Dec),
        Node::new("Encryption algorithm")
            .span(meta.sub(24, 1))
            .value(Value::UInt {
                value: head.get(24).copied().unwrap_or(0).into(),
                bits: 8,
                radix: Radix::Dec,
            }),
        Node::new("Page type")
            .span(meta.sub(25, 1))
            .value(Value::Enum {
                raw: head.get(25).copied().unwrap_or(0).into(),
                bits: 8,
                name: lookup(PAGE_TYPES, head.get(25).copied().unwrap_or(0).into()),
            }),
        num("Free list page", 28, Radix::Dec),
        num("Last page", 32, Radix::Dec),
        num("Partitions", 36, Radix::Dec).desc("Unused before 4.8"),
        num("Key count", 40, Radix::Dec),
        num("Record count", 44, Radix::Dec),
        num("Flags", 48, Radix::Hex),
        Node::new("File ID")
            .span(meta.sub(52, 20))
            .value(Value::Bytes(head.get(52..72).unwrap_or_default().to_vec())),
    ];
    let kind = lookup(MAGICS, magic.into()).unwrap_or("unknown");
    let mut root = None;
    if magic == BTREE {
        fields.push(num("Minimum keys per page", 76, Radix::Dec).span(file.sub(76, 4)));
        fields.push(num("Root page", 88, Radix::Dec).span(file.sub(88, 4)));
        root = Some(u32v(88));
    } else if magic == HASH {
        for (name, at) in [
            ("Maximum bucket", 72u64),
            ("High mask", 76),
            ("Low mask", 80),
            ("Fill factor", 84),
            ("Number of elements", 88),
        ] {
            fields.push(num(name, at, Radix::Dec).span(file.sub(at, 4)));
        }
    }
    cx.annotate(format!(
        "Berkeley DB {kind} database, version {}, {} pages of {pagesize} bytes",
        u32v(16),
        u64::from(db.last).saturating_add(1)
    ));
    cx.emit(
        Node::new("Metadata page")
            .span(file.sub(0, pagesize))
            .lazy(emit_nodes, Arc::new(fields)),
    );
    if magic == BTREE || magic == HASH {
        cx.emit(Node::new("Records").lazy(records, (db.clone(), root)));
    }
    cx.emit(
        Node::new("Pages")
            .summary(format!("{}", u64::from(db.last).saturating_add(1)))
            .lazy(pages, db.clone()),
    );
    Ok(())
}

async fn emit_nodes(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.emit(n.clone());
    }
    Ok(())
}

/// A page read into memory with its header decoded.
struct Page {
    span: Span,
    data: Vec<u8>,
    next: u32,
    entries: u16,
    hf_offset: u16,
    level: u8,
    kind: u8,
}

async fn load(cx: &Cx, db: &Db, no: u32) -> Result<Page> {
    let span = db.page(no);
    let data = cx.read(span).await?;
    let e = db.endian;
    Ok(Page {
        span,
        next: read_u32(&data, 16, e).unwrap_or(0),
        entries: read_u16(&data, 20, e).unwrap_or(0),
        hf_offset: read_u16(&data, 22, e).unwrap_or(0),
        level: data.get(24).copied().unwrap_or(0),
        kind: data.get(25).copied().unwrap_or(0),
        data,
    })
}

/// One item on a page: its range and type, plus overflow or child pointers.
struct Item {
    range: (usize, usize),
    kind: u8,
    data: (usize, usize),
    /// Overflow: first page and total length. Internal: child page.
    page: Option<u32>,
    total: u32,
}

fn items(db: &Db, page: &Page) -> Vec<Item> {
    let e = db.endian;
    let size = page.data.len();
    let mut out = Vec::new();
    let mut prev = size;
    for i in 0..usize::from(page.entries) {
        let Some(off) = read_u16(
            &page.data,
            to_usize(HEADER).saturating_add(i.saturating_mul(2)),
            e,
        ) else {
            break;
        };
        let off = usize::from(off);
        if off >= size {
            break;
        }
        let item = match page.kind {
            // B-tree and recno leaves, duplicate pages: BKEYDATA / BOVERFLOW.
            1 | 5 | 6 | 12 => {
                let len = usize::from(read_u16(&page.data, off, e).unwrap_or(0));
                let kind = page.data.get(off.saturating_add(2)).copied().unwrap_or(0) & 0x7f;
                if kind == 3 {
                    Item {
                        range: (off, off.saturating_add(12).min(size)),
                        kind,
                        data: (off, off),
                        page: read_u32(&page.data, off.saturating_add(4), e),
                        total: read_u32(&page.data, off.saturating_add(8), e).unwrap_or(0),
                    }
                } else {
                    let start = off.saturating_add(3);
                    let end = start.saturating_add(len).min(size);
                    Item {
                        range: (off, end),
                        kind,
                        data: (start, end),
                        page: None,
                        total: 0,
                    }
                }
            }
            // Internal pages: BINTERNAL (length, type, unused, child, records, data).
            3 | 4 => {
                let len = usize::from(read_u16(&page.data, off, e).unwrap_or(0));
                let start = off.saturating_add(12);
                let end = if page.kind == 4 {
                    start
                } else {
                    start.saturating_add(len).min(size)
                };
                Item {
                    range: (off, end),
                    kind: page.data.get(off.saturating_add(2)).copied().unwrap_or(0) & 0x7f,
                    data: (start, end),
                    page: read_u32(&page.data, off.saturating_add(4), e),
                    total: read_u32(&page.data, off.saturating_add(8), e).unwrap_or(0),
                }
            }
            // Hash pages: HKEYDATA (type, data) up to the previous item.
            2 | 13 => {
                let end = prev.max(off);
                let kind = page.data.get(off).copied().unwrap_or(0);
                if kind == 3 {
                    Item {
                        range: (off, end),
                        kind,
                        data: (off, off),
                        page: read_u32(&page.data, off.saturating_add(4), e),
                        total: read_u32(&page.data, off.saturating_add(8), e).unwrap_or(0),
                    }
                } else {
                    Item {
                        range: (off, end),
                        kind,
                        data: (off.saturating_add(1), end),
                        page: None,
                        total: 0,
                    }
                }
            }
            _ => break,
        };
        prev = off;
        out.push(item);
    }
    out
}

fn text(bytes: &[u8]) -> Value {
    match std::str::from_utf8(bytes) {
        Ok(s) if !s.chars().any(|c| c.is_control() && c != '\n' && c != '\t') => {
            Value::Text(s.to_owned())
        }
        _ => Value::Bytes(bytes.iter().take(32).copied().collect()),
    }
}

/// An item's value: inline bytes, or an overflow chain joined into a
/// piecewise source.
async fn item_value(
    cx: &Cx,
    db: &Db,
    page: &Page,
    item: &Item,
) -> Result<(Span, Option<Diagnostic>)> {
    if item.kind != 3 {
        return Ok((
            page.span.sub(
                to_u64(item.data.0),
                to_u64(item.data.1.saturating_sub(item.data.0)),
            ),
            None,
        ));
    }
    let mut pieces = Vec::new();
    let mut remaining = u64::from(item.total);
    let mut next = item.page.unwrap_or(0);
    let mut seen = BTreeSet::new();
    let mut diag = None;
    while remaining > 0 {
        cx.checkpoint().await;
        if next == 0 || next > db.last || !seen.insert(next) {
            diag = Some(Diagnostic::malformed("overflow chain is broken or loops"));
            break;
        }
        let p = load(cx, db, next).await?;
        let len = u64::from(p.hf_offset)
            .min(remaining)
            .min(db.pagesize.saturating_sub(HEADER));
        pieces.push(p.span.sub(HEADER, len));
        remaining = remaining.saturating_sub(len);
        if len == 0 {
            break;
        }
        next = p.next;
    }
    let item_span = page.span.sub(
        to_u64(item.range.0),
        to_u64(item.range.1.saturating_sub(item.range.0)),
    );
    let span = cx.add_pieces(
        Origin {
            parent: item_span,
            transform: "bdb-overflow",
        },
        pieces,
    )?;
    Ok((span, diag))
}

async fn value_node(
    cx: &Cx,
    db: &Db,
    page: &Page,
    key: &Item,
    value: Option<&Item>,
) -> Result<Node> {
    let (key_span, _) = item_value(cx, db, page, key).await?;
    let key_bytes = cx.read_avail(key_span.sub(0, 256)).await?;
    let label = crate::render::value(&text(&key_bytes));
    let mut node = Node::new(label).span(page.span.sub(
        to_u64(key.range.0),
        to_u64(key.range.1.saturating_sub(key.range.0)),
    ));
    if let Some(v) = value {
        let (span, diag) = item_value(cx, db, page, v).await?;
        let bytes = cx.read_avail(span.sub(0, 256)).await?;
        node = node.value(text(&bytes)).summary(format!(
            "{} bytes{}",
            span.len,
            if v.kind == 3 { ", overflow" } else { "" }
        ));
        if let Some(d) = diag {
            node = node.diag(d);
        }
        if span.len >= 16 {
            node = node.lazy(crate::formats::dissect_or_data, db.input.nested(span));
        }
    }
    Ok(node)
}

async fn records(cx: Cx, (db, root): (DbRef, Option<u32>)) -> Result<()> {
    match root {
        Some(root) => {
            // Depth-first from the root; leaves hold key/value pairs.
            let mut stack = vec![(root, 0usize)];
            let mut seen = BTreeSet::new();
            while let Some((no, depth)) = stack.pop() {
                cx.checkpoint().await;
                if no > db.last || !seen.insert(no) || depth > MAX_DEPTH {
                    cx.diag(Diagnostic::malformed(format!(
                        "B-tree revisits or leaves the file at page {no}"
                    )));
                    continue;
                }
                // Pages visited, out of all pages (an upper bound).
                cx.progress(to_u64(seen.len()), u64::from(db.last).saturating_add(1));
                let page = load(&cx, &db, no).await?;
                let list = items(&db, &page);
                match page.kind {
                    3 | 4 => stack.extend(
                        list.iter()
                            .rev()
                            .filter_map(|i| i.page)
                            .map(|p| (p, depth.saturating_add(1))),
                    ),
                    5 => {
                        for pair in list.chunks(2) {
                            if let Some(key) = pair.first() {
                                let node = value_node(&cx, &db, &page, key, pair.get(1)).await?;
                                cx.push(node).await;
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
        None => {
            for no in 1..=db.last {
                cx.progress(u64::from(no), u64::from(db.last));
                let page = load(&cx, &db, no).await?;
                if !matches!(page.kind, 2 | 13) {
                    continue;
                }
                let list = items(&db, &page);
                for pair in list.chunks(2) {
                    if let Some(key) = pair.first() {
                        let node = value_node(&cx, &db, &page, key, pair.get(1)).await?;
                        cx.push(node).await;
                    }
                }
            }
        }
    }
    Ok(())
}

async fn pages(cx: Cx, db: DbRef) -> Result<()> {
    cx.set_count(Count::Exact(u64::from(db.last).saturating_add(1)));
    for no in 0..=db.last {
        let span = db.page(no);
        let head = cx.read_avail(span.sub(0, HEADER)).await?;
        let kind = head.get(25).copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Page {no}"))
                .span(span)
                .summary(
                    lookup(PAGE_TYPES, kind.into())
                        .unwrap_or("unknown")
                        .to_owned(),
                )
                .lazy(page_contents, (db.clone(), no)),
        )
        .await;
    }
    Ok(())
}

async fn page_contents(cx: Cx, (db, no): (DbRef, u32)) -> Result<()> {
    let page = load(&cx, &db, no).await?;
    let e = db.endian;
    let h = page.span;
    let u = |v: u64, bits| Value::UInt {
        value: v,
        bits,
        radix: Radix::Dec,
    };
    if no == 0 {
        cx.emit(Node::new("Metadata").span(h.sub(0, 72)));
        return Ok(());
    }
    cx.emit(
        Node::new("LSN")
            .span(h.sub(0, 8))
            .value(Value::Text(format!(
                "{}/{}",
                read_u32(&page.data, 0, e).unwrap_or(0),
                read_u32(&page.data, 4, e).unwrap_or(0)
            ))),
    );
    cx.emit(
        Node::new("Page number")
            .span(h.sub(8, 4))
            .value(u(read_u32(&page.data, 8, e).unwrap_or(0).into(), 32)),
    );
    cx.emit(
        Node::new("Previous page")
            .span(h.sub(12, 4))
            .value(u(read_u32(&page.data, 12, e).unwrap_or(0).into(), 32)),
    );
    cx.emit(
        Node::new("Next page")
            .span(h.sub(16, 4))
            .value(u(page.next.into(), 32)),
    );
    cx.emit(
        Node::new("Entries")
            .span(h.sub(20, 2))
            .value(u(page.entries.into(), 16)),
    );
    cx.emit(
        Node::new("High free offset")
            .span(h.sub(22, 2))
            .value(u(page.hf_offset.into(), 16)),
    );
    cx.emit(
        Node::new("Level")
            .span(h.sub(24, 1))
            .value(u(page.level.into(), 8)),
    );
    cx.emit(Node::new("Type").span(h.sub(25, 1)).value(Value::Enum {
        raw: page.kind.into(),
        bits: 8,
        name: lookup(PAGE_TYPES, page.kind.into()),
    }));
    if page.kind == 7 {
        cx.emit(Node::new("Overflow data").span(h.sub(HEADER, u64::from(page.hf_offset))));
        return Ok(());
    }
    for (i, item) in items(&db, &page).iter().enumerate() {
        let span = h.sub(
            to_u64(item.range.0),
            to_u64(item.range.1.saturating_sub(item.range.0)),
        );
        let bytes = page.data.get(item.data.0..item.data.1).unwrap_or_default();
        let mut node = Node::new(format!("Item {i}")).span(span);
        node = match (page.kind, item.page) {
            (3 | 4, Some(child)) => node
                .value(text(bytes))
                .summary(format!("child page {child}"))
                .target(db.page(child)),
            (_, Some(first)) if item.kind == 3 => node
                .summary(format!("overflow, {} bytes from page {first}", item.total))
                .target(db.page(first)),
            _ => node.value(text(bytes)),
        };
        cx.push(node).await;
    }
    Ok(())
}
