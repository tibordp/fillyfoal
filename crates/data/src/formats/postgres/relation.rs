//! PostgreSQL relation files: a table's heap, an index, or a table's free
//! space map (`_fsm`) or visibility map (`_vm`), as 8 KiB pages.
//!
//! Every page starts with the same header (LSN, data checksum, flags, and
//! the bounds of the line pointer array, the free space and the special
//! space); the checksum is verified when the cluster has data checksums.
//! Line pointers lead to the items, which grow down from the end: heap
//! tuples (header, null bitmap, data) or index tuples (heap TID, size,
//! data). The special space at the end tells the access method apart:
//! none for heaps, the B-tree, hash, GiST, SP-GiST, GIN or BRIN opaque
//! data otherwise. Column values need the table's definition from the
//! system catalogs, which a single file does not have, so tuple data is
//! shown as bytes. Map forks have no items: their bytes fill the page.

use super::{BLCKSZ, page_checksum};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{grouped_count, size};
use crate::formats::util::val::flagsv;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag};

pub static FORMAT: Format = Format {
    name: "pg-relation",
    title: "PostgreSQL relation file",
    extensions: &[],
    mime: "application/x-postgresql-relation",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// A page image from a WAL record (its checksum is not maintained there).
pub static IMAGE: Format = Format {
    name: "pg-page-image",
    title: "PostgreSQL page image",
    extensions: &[],
    mime: "application/x-postgresql-page",
    probe: Probe::Never,
    dissect: crate::expander!(dissect_image: Input),
};

const HEADER: u64 = 24;
/// Page layout version 4 (PostgreSQL 8.3 and later) and an 8 KiB page.
const PAGESIZE_VERSION: u16 = 0x2004;

/// A page header whose bounds nest (`24 <= lower <= upper <= special <=
/// 8192`), with the 8 KiB, layout 4 tag, known flags only, and normal line
/// pointers inside the item area.
fn page_ok(p: &[u8]) -> bool {
    let (Some(flags), Some(lower), Some(upper), Some(special), Some(version)) = (
        u16_le(p, 10),
        u16_le(p, 12),
        u16_le(p, 14),
        u16_le(p, 16),
        u16_le(p, 18),
    ) else {
        return false;
    };
    if version != PAGESIZE_VERSION || flags & !7 != 0 {
        return false;
    }
    let (lower, upper, special) = (u64::from(lower), u64::from(upper), u64::from(special));
    if !(HEADER <= lower && lower <= upper && upper <= special && special <= BLCKSZ) {
        return false;
    }
    if !lower.saturating_sub(HEADER).is_multiple_of(4)
        || !BLCKSZ.saturating_sub(special).is_multiple_of(8)
    {
        return false;
    }
    (HEADER..lower).step_by(4).all(|at| {
        let lp = u32_le(p, to_usize(at)).unwrap_or(0);
        let (off, fl, len) = line_pointer(lp);
        fl != 1 || (off >= upper && off.saturating_add(len) <= special && len >= 4)
    })
}

fn probe(h: &Head<'_>) -> bool {
    if h.len < BLCKSZ || (h.len_known && !h.len.is_multiple_of(BLCKSZ)) {
        return false;
    }
    let Some(first) = h.data.get(..to_usize(BLCKSZ)) else {
        return false;
    };
    page_ok(first)
}

/// Offset, flags and length of a line pointer.
fn line_pointer(lp: u32) -> (u64, u8, u64) {
    (
        u64::from(lp & 0x7fff),
        u8::try_from((lp >> 15) & 3).unwrap_or(0),
        u64::from(lp >> 17),
    )
}

const LP_FLAGS: EnumTable = &[(0, "unused"), (1, "normal"), (2, "redirect"), (3, "dead")];

const PAGE_FLAGS: FlagTable = &[
    flag(1, "HAS_FREE_LINES"),
    flag(2, "PAGE_FULL"),
    flag(4, "ALL_VISIBLE"),
];

const BTREE_FLAGS: FlagTable = &[
    flag(0x1, "LEAF"),
    flag(0x2, "ROOT"),
    flag(0x4, "DELETED"),
    flag(0x8, "META"),
    flag(0x10, "HALF_DEAD"),
    flag(0x20, "SPLIT_END"),
    flag(0x40, "HAS_GARBAGE"),
    flag(0x80, "INCOMPLETE_SPLIT"),
    flag(0x100, "HAS_FULLXID"),
];

const INFOMASK: FlagTable = &[
    flag(0x0001, "HASNULL"),
    flag(0x0002, "HASVARWIDTH"),
    flag(0x0004, "HASEXTERNAL"),
    flag(0x0008, "HASOID_OLD"),
    flag(0x0010, "XMAX_KEYSHR_LOCK"),
    flag(0x0020, "COMBOCID"),
    flag(0x0040, "XMAX_EXCL_LOCK"),
    flag(0x0080, "XMAX_LOCK_ONLY"),
    flag(0x0100, "XMIN_COMMITTED"),
    flag(0x0200, "XMIN_INVALID"),
    flag(0x0400, "XMAX_COMMITTED"),
    flag(0x0800, "XMAX_INVALID"),
    flag(0x1000, "XMAX_IS_MULTI"),
    flag(0x2000, "UPDATED"),
    flag(0x4000, "MOVED_OFF"),
    flag(0x8000, "MOVED_IN"),
];

const INFOMASK2: FlagTable = &[
    flag(0x2000, "KEYS_UPDATED"),
    flag(0x4000, "HOT_UPDATED"),
    flag(0x8000, "ONLY_TUPLE"),
];

/// What a page holds, from its special space.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Heap,
    BtreeMeta,
    Btree,
    Hash,
    Gist,
    SpGist,
    Gin,
    Brin,
    Fsm,
    Vm,
    Other,
    Empty,
}

/// Which map fork the file is, by its name.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Fork {
    Main,
    Fsm,
    Vm,
}

fn kind(p: &[u8], fork: Fork) -> Kind {
    if p.iter().all(|&b| b == 0) {
        return Kind::Empty;
    }
    let special = u64::from(u16_le(p, 16).unwrap_or(0));
    let lower = u64::from(u16_le(p, 12).unwrap_or(0));
    let size = BLCKSZ.saturating_sub(special);
    let id = u16_le(p, to_usize(BLCKSZ.saturating_sub(2))).unwrap_or(0);
    match size {
        0 if lower == HEADER && fork == Fork::Fsm => Kind::Fsm,
        0 if lower == HEADER && fork == Fork::Vm => Kind::Vm,
        0 => Kind::Heap,
        16 => match id {
            0xff80 => Kind::Hash,
            0xff81 => Kind::Gist,
            _ => {
                let flags = u16_le(p, to_usize(special.saturating_add(12))).unwrap_or(0);
                if flags & 8 != 0 {
                    Kind::BtreeMeta
                } else {
                    Kind::Btree
                }
            }
        },
        8 => match id {
            0xff82 => Kind::SpGist,
            0xf091..=0xf093 => Kind::Brin,
            _ => Kind::Gin,
        },
        _ => Kind::Other,
    }
}

fn kind_name(k: Kind) -> &'static str {
    match k {
        Kind::Heap => "heap",
        Kind::BtreeMeta => "B-tree metapage",
        Kind::Btree => "B-tree",
        Kind::Hash => "hash index",
        Kind::Gist => "GiST index",
        Kind::SpGist => "SP-GiST index",
        Kind::Gin => "GIN index",
        Kind::Brin => "BRIN index",
        Kind::Fsm => "free space map",
        Kind::Vm => "visibility map",
        Kind::Other => "unknown access method",
        Kind::Empty => "empty",
    }
}

/// An LSN as PostgreSQL prints it.
pub(crate) fn lsn(v: u64) -> String {
    format!("{:X}/{:X}", v >> 32, v & 0xffff_ffff)
}

/// The page LSN (two 32-bit halves, high first).
fn page_lsn(p: &[u8]) -> u64 {
    (u64::from(u32_le(p, 0).unwrap_or(0)) << 32) | u64::from(u32_le(p, 4).unwrap_or(0))
}

#[derive(Clone)]
struct Rel {
    input: Input,
    pages: u64,
    fork: Fork,
    /// Check data checksums (not for page images in WAL records).
    verify: bool,
}

fn fork_of(cx: &Cx) -> Fork {
    let name = cx.node_name();
    if name.ends_with("_fsm") {
        Fork::Fsm
    } else if name.ends_with("_vm") {
        Fork::Vm
    } else {
        Fork::Main
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let pages = file.len / BLCKSZ;
    let fork = fork_of(&cx);
    let rel = Rel {
        input,
        pages,
        fork,
        verify: true,
    };
    let first = cx.read(file.sub(0, BLCKSZ)).await?;
    let k = kind(&first, fork);
    cx.emit(
        Node::new("Pages")
            .span(file.sub(0, pages.saturating_mul(BLCKSZ)))
            .summary(grouped_count(pages, "page", "pages"))
            .lazy(pages_list, rel),
    );
    let rest = file.len % BLCKSZ;
    if rest != 0 {
        cx.emit(
            Node::new("Trailing bytes")
                .span(file.tail(pages.saturating_mul(BLCKSZ)))
                .diag(Diagnostic::warning(format!(
                    "{rest} bytes after the last page"
                ))),
        );
    }
    let what = match k {
        Kind::BtreeMeta | Kind::Btree => "B-tree index".to_owned(),
        Kind::Heap => "table (heap)".to_owned(),
        Kind::Fsm => "free space map".to_owned(),
        Kind::Vm => "visibility map".to_owned(),
        other => kind_name(other).to_owned(),
    };
    let checksums = u16_le(&first, 8).unwrap_or(0) != 0;
    cx.annotate(format!(
        "PostgreSQL {what}, {}{}",
        grouped_count(pages, "page", "pages"),
        if checksums { ", data checksums" } else { "" }
    ));
    Ok(())
}

async fn dissect_image(cx: Cx, input: Input) -> Result<()> {
    let rel = Rel {
        input,
        pages: 1,
        fork: Fork::Main,
        verify: false,
    };
    let p = cx.read(input.span.sub(0, BLCKSZ)).await?;
    cx.annotate(format!(
        "PostgreSQL {} page image",
        kind_name(kind(&p, Fork::Main))
    ));
    page(cx, (rel, 0)).await
}

async fn pages_list(cx: Cx, rel: Rel) -> Result<()> {
    cx.set_count(Count::Exact(rel.pages));
    let start = cx.resume::<u64>().unwrap_or(0);
    for n in start..rel.pages {
        cx.mark(move || n);
        let span = rel.input.span.sub(n.saturating_mul(BLCKSZ), BLCKSZ);
        let summary = if cx.skipping() {
            String::new()
        } else {
            let p = cx.read(span).await?;
            page_summary(&p, rel.fork)
        };
        cx.push(
            Node::new(format!("Page {n}"))
                .span(span)
                .summary(summary)
                .lazy(page, (rel.clone(), n)),
        )
        .await;
    }
    Ok(())
}

fn page_summary(p: &[u8], fork: Fork) -> String {
    let k = kind(p, fork);
    if k == Kind::Empty {
        return "new (all zero)".to_owned();
    }
    let lower = u64::from(u16_le(p, 12).unwrap_or(0));
    let upper = u64::from(u16_le(p, 14).unwrap_or(0));
    let items = lower.saturating_sub(HEADER) / 4;
    let mut s = format!("{}, LSN {}", kind_name(k), lsn(page_lsn(p)));
    if !matches!(k, Kind::Fsm | Kind::Vm | Kind::BtreeMeta) {
        s.push_str(&format!(
            ", {}, {} free",
            grouped_count(items, "item", "items"),
            size(upper.saturating_sub(lower))
        ));
    }
    if !page_ok(p) {
        s.push_str(", bad header");
    }
    s
}

async fn page(cx: Cx, (rel, n): (Rel, u64)) -> Result<()> {
    let span = rel.input.span.sub(n.saturating_mul(BLCKSZ), BLCKSZ);
    let p = cx.read(span).await?;
    cx.charge(BLCKSZ / 512).await;
    let k = kind(&p, rel.fork);
    if k == Kind::Empty {
        cx.emit(
            Node::new("Unused")
                .span(span)
                .summary("a page extended but never initialised"),
        );
        return Ok(());
    }
    let at = |o: u64, l: u64| span.sub(o, l);
    let u16_at = |o: usize| u16_le(&p, o).unwrap_or(0);
    let mut header = Node::new("Page header").span(at(0, HEADER)).lazy(
        header_fields,
        (span, u32::try_from(n).unwrap_or(0), rel.verify),
    );
    let stored = u16_at(8);
    if rel.verify && stored != 0 && page_checksum(&p, u32::try_from(n).unwrap_or(0)) != Some(stored)
    {
        header = header.diag(Diagnostic::warning("data checksum mismatch"));
    }
    if !page_ok(&p) {
        header = header.diag(Diagnostic::malformed("page bounds do not nest"));
    }
    cx.emit(header);
    let lower = u64::from(u16_at(12)).clamp(HEADER, BLCKSZ);
    let upper = u64::from(u16_at(14)).clamp(lower, BLCKSZ);
    let special = u64::from(u16_at(16)).clamp(upper, BLCKSZ);
    match k {
        Kind::Fsm => fsm_page(&cx, span, &p),
        Kind::Vm => vm_page(&cx, span, &p),
        _ => {
            if k == Kind::BtreeMeta {
                btree_meta(&cx, span, lower);
            }
            let items = lower.saturating_sub(HEADER) / 4;
            if items != 0 && k != Kind::BtreeMeta {
                cx.emit(
                    Node::new("Line pointers")
                        .span(at(HEADER, items.saturating_mul(4)))
                        .summary(grouped_count(items, "item", "items"))
                        .lazy(line_pointers, (span, items)),
                );
            }
            if upper > lower {
                cx.emit(
                    Node::new("Free space")
                        .span(at(lower, upper.saturating_sub(lower)))
                        .summary(size(upper.saturating_sub(lower))),
                );
            }
            if items != 0 && k != Kind::BtreeMeta {
                cx.emit(
                    Node::new(if k == Kind::Heap {
                        "Tuples"
                    } else {
                        "Index tuples"
                    })
                    .span(at(upper, special.saturating_sub(upper)))
                    .lazy(tuples, (span, items, k == Kind::Heap)),
                );
            }
        }
    }
    if special < BLCKSZ {
        cx.emit(special_node(span, &p, special, k));
    }
    Ok(())
}

async fn header_fields(cx: Cx, (span, block, verify): (Span, u32, bool)) -> Result<()> {
    let p = cx.read(span).await?;
    let at = |o: u64, l: u64| span.sub(o, l);
    let v = page_lsn(&p);
    cx.emit(
        Node::new("LSN")
            .span(at(0, 8))
            .value(hex(v, 64))
            .summary(lsn(v))
            .desc("The end of the last WAL record that changed the page"),
    );
    let stored = u16_le(&p, 8).unwrap_or(0);
    let mut ck = Node::new("Checksum").span(at(8, 2)).value(hex(stored, 16));
    ck = if stored == 0 {
        ck.summary("none (data checksums off)")
    } else if !verify {
        ck.summary("not maintained in page images")
    } else {
        match page_checksum(&p, block) {
            Some(c) if c == stored => ck.summary("valid"),
            Some(c) => ck.diag(Diagnostic::warning(format!(
                "checksum mismatch (computed {c:#06x} for block {block}; blocks of later segment files are numbered from the relation's start)"
            ))),
            None => ck,
        }
    };
    cx.emit(ck);
    let flags = u16_le(&p, 10).unwrap_or(0);
    cx.emit(
        Node::new("Flags")
            .span(at(10, 2))
            .value(flagsv(flags, 16, PAGE_FLAGS)),
    );
    cx.emit(
        Node::new("Lower")
            .span(at(12, 2))
            .value(hex(u16_le(&p, 12).unwrap_or(0), 16))
            .desc("End of the line pointer array"),
    );
    cx.emit(
        Node::new("Upper")
            .span(at(14, 2))
            .value(hex(u16_le(&p, 14).unwrap_or(0), 16))
            .desc("Start of the item area"),
    );
    cx.emit(
        Node::new("Special")
            .span(at(16, 2))
            .value(hex(u16_le(&p, 16).unwrap_or(0), 16))
            .desc("Start of the access method's special space"),
    );
    let ver = u16_le(&p, 18).unwrap_or(0);
    cx.emit(
        Node::new("Page size and layout version")
            .span(at(18, 2))
            .value(hex(ver, 16))
            .summary(format!(
                "{} bytes, layout version {}",
                ver & 0xff00,
                ver & 0xff
            )),
    );
    cx.emit(
        Node::new("Prune XID")
            .span(at(20, 4))
            .value(uint(u32_le(&p, 20).unwrap_or(0), 32))
            .desc("Oldest transaction whose deletions may make pruning worthwhile (0: none)"),
    );
    Ok(())
}

async fn line_pointers(cx: Cx, (span, items): (Span, u64)) -> Result<()> {
    let b = cx.read(span.sub(HEADER, items.saturating_mul(4))).await?;
    cx.set_count(Count::Exact(items));
    for i in 0..items {
        let lp = u32_le(&b, to_usize(i.saturating_mul(4))).unwrap_or(0);
        let (off, fl, len) = line_pointer(lp);
        let mut n = Node::new(format!("Item {}", i.saturating_add(1)))
            .span(span.sub(HEADER.saturating_add(i.saturating_mul(4)), 4))
            .value(hex(lp, 32));
        let fname = crate::value::lookup(LP_FLAGS, fl.into()).unwrap_or("?");
        n = match fl {
            1 => n
                .summary(format!("{fname}: {len} bytes at {off:#x}"))
                .target(span.sub(off, len)),
            2 => n.summary(format!("redirect to item {off}")),
            _ => n.summary(fname),
        };
        cx.push(n).await;
    }
    Ok(())
}

async fn tuples(cx: Cx, (span, items, heap): (Span, u64, bool)) -> Result<()> {
    let p = cx.read(span).await?;
    let normal = (0..items)
        .filter(|&i| {
            let lp = u32_le(&p, to_usize(HEADER.saturating_add(i.saturating_mul(4)))).unwrap_or(0);
            let (_, fl, len) = line_pointer(lp);
            fl == 1 && len != 0
        })
        .count();
    cx.set_count(Count::Exact(to_u64(normal)));
    for i in 0..items {
        let lp = u32_le(&p, to_usize(HEADER.saturating_add(i.saturating_mul(4)))).unwrap_or(0);
        let (off, fl, len) = line_pointer(lp);
        if fl != 1 || len == 0 {
            continue;
        }
        if off.saturating_add(len) > BLCKSZ {
            cx.push(
                Node::new(format!("Item {}", i.saturating_add(1)))
                    .diag(Diagnostic::malformed("item runs past the page")),
            )
            .await;
            continue;
        }
        let t = span.sub(off, len);
        let b = p
            .get(to_usize(off)..to_usize(off.saturating_add(len)))
            .unwrap_or_default();
        let summary = if heap {
            heap_summary(b)
        } else {
            index_summary(b)
        };
        cx.push(
            Node::new(format!("Item {}", i.saturating_add(1)))
                .span(t)
                .summary(summary)
                .lazy(tuple_fields, (t, heap)),
        )
        .await;
    }
    Ok(())
}

fn ctid(b: &[u8], at: usize) -> String {
    let hi = u32::from(u16_le(b, at).unwrap_or(0));
    let lo = u32::from(u16_le(b, at.saturating_add(2)).unwrap_or(0));
    let off = u16_le(b, at.saturating_add(4)).unwrap_or(0);
    format!("({},{off})", (hi << 16) | lo)
}

fn heap_summary(b: &[u8]) -> String {
    let xmin = u32_le(b, 0).unwrap_or(0);
    let xmax = u32_le(b, 4).unwrap_or(0);
    let mask2 = u16_le(b, 18).unwrap_or(0);
    let mask = u16_le(b, 20).unwrap_or(0);
    let hoff = u64::from(b.get(22).copied().unwrap_or(0));
    let mut s = format!(
        "xmin {xmin}, xmax {xmax}, {} attributes, {} of data",
        mask2 & 0x7ff,
        size(to_u64(b.len()).saturating_sub(hoff))
    );
    if mask2 & 0x4000 != 0 {
        s.push_str(", HOT updated");
    }
    if mask & 0x0800 == 0 && xmax != 0 && mask & 0x0080 == 0 {
        s.push_str(&format!(
            ", deleted or updated (newer version at {})",
            ctid(b, 12)
        ));
    }
    s
}

fn index_summary(b: &[u8]) -> String {
    let info = u16_le(b, 6).unwrap_or(0);
    format!("heap TID {}, {} bytes", ctid(b, 0), info & 0x1fff)
}

async fn tuple_fields(cx: Cx, (t, heap): (Span, bool)) -> Result<()> {
    let b = cx.read(t).await?;
    let at = |o: u64, l: u64| t.sub(o, l);
    if !heap {
        cx.emit(Node::new("Heap TID").span(at(0, 6)).summary(ctid(&b, 0)));
        let info = u16_le(&b, 6).unwrap_or(0);
        let mut flags = Vec::new();
        if info & 0x8000 != 0 {
            flags.push("has nulls");
        }
        if info & 0x4000 != 0 {
            flags.push("has variable-width attributes");
        }
        if info & 0x2000 != 0 {
            flags.push("access method flag");
        }
        cx.emit(
            Node::new("Info")
                .span(at(6, 2))
                .value(hex(info, 16))
                .summary(format!(
                    "{} bytes{}{}",
                    info & 0x1fff,
                    if flags.is_empty() { "" } else { ", " },
                    flags.join(", ")
                )),
        );
        let mut data_at = 8u64;
        if info & 0x8000 != 0 {
            cx.emit(Node::new("Null bitmap").span(at(8, 4)));
            data_at = 16;
        }
        if t.len > data_at {
            cx.emit(
                Node::new("Key data")
                    .span(at(data_at, t.len.saturating_sub(data_at)))
                    .value(Value::Bytes(
                        b.get(to_usize(data_at)..).unwrap_or_default().to_vec(),
                    )),
            );
        }
        return Ok(());
    }
    cx.emit(
        Node::new("xmin")
            .span(at(0, 4))
            .value(uint(u32_le(&b, 0).unwrap_or(0), 32))
            .desc("Inserting transaction"),
    );
    cx.emit(
        Node::new("xmax")
            .span(at(4, 4))
            .value(uint(u32_le(&b, 4).unwrap_or(0), 32))
            .desc("Deleting or locking transaction (0: none)"),
    );
    cx.emit(
        Node::new("cid / xvac")
            .span(at(8, 4))
            .value(uint(u32_le(&b, 8).unwrap_or(0), 32))
            .desc("Command ID within the transaction"),
    );
    cx.emit(
        Node::new("ctid")
            .span(at(12, 6))
            .summary(ctid(&b, 12))
            .desc("This tuple's position, or that of its newer version"),
    );
    let mask2 = u16_le(&b, 18).unwrap_or(0);
    cx.emit(
        Node::new("infomask2")
            .span(at(18, 2))
            .value(flagsv(u64::from(mask2 & 0xf800), 16, INFOMASK2))
            .summary(format!("{} attributes", mask2 & 0x7ff)),
    );
    let mask = u16_le(&b, 20).unwrap_or(0);
    cx.emit(
        Node::new("infomask")
            .span(at(20, 2))
            .value(flagsv(mask, 16, INFOMASK)),
    );
    let hoff = u64::from(b.get(22).copied().unwrap_or(0));
    cx.emit(
        Node::new("Header length")
            .span(at(22, 1))
            .value(uint(hoff, 8)),
    );
    let mut pos = 23u64;
    if mask & 1 != 0 {
        let natts = u64::from(mask2 & 0x7ff);
        let bytes = natts.div_ceil(8);
        let bits = b
            .get(23..to_usize(23u64.saturating_add(bytes)))
            .unwrap_or_default();
        let nulls = (0..natts)
            .filter(|&i| {
                bits.get(to_usize(i / 8))
                    .is_some_and(|x| x & (1 << (i % 8)) == 0)
            })
            .count();
        cx.emit(
            Node::new("Null bitmap")
                .span(at(23, bytes))
                .value(Value::Bytes(bits.to_vec()))
                .summary(format!("{nulls} null")),
        );
        pos = pos.saturating_add(bytes);
    }
    if hoff > pos {
        cx.emit(Node::new("Padding").span(at(pos, hoff.saturating_sub(pos))));
    }
    if t.len > hoff {
        cx.emit(
            Node::new("Data")
                .span(at(hoff, t.len.saturating_sub(hoff)))
                .summary(size(t.len.saturating_sub(hoff)))
                .desc("The columns, aligned per their types; decoding them needs the table's definition from pg_attribute"),
        );
    }
    Ok(())
}

fn btree_meta(cx: &Cx, span: Span, lower: u64) {
    let len = lower.saturating_sub(HEADER).max(24);
    cx.emit(
        Node::new("B-tree metadata")
            .span(span.sub(HEADER, len))
            .lazy(meta_fields, span),
    );
}

async fn meta_fields(cx: Cx, span: Span) -> Result<()> {
    let p = cx.read(span).await?;
    let at = |o: u64, l: u64| span.sub(o, l);
    let u = |o: usize| u32_le(&p, o).unwrap_or(0);
    let magic = u(24);
    let mut m = Node::new("Magic").span(at(24, 4)).value(hex(magic, 32));
    if magic != 0x0005_3162 {
        m = m.diag(Diagnostic::malformed("expected 0x053162"));
    }
    cx.emit(m);
    cx.emit(Node::new("Version").span(at(28, 4)).value(uint(u(28), 32)));
    cx.emit(
        Node::new("Root page")
            .span(at(32, 4))
            .value(uint(u(32), 32))
            .target(span.sub(0, 0)),
    );
    cx.emit(
        Node::new("Root level")
            .span(at(36, 4))
            .value(uint(u(36), 32)),
    );
    cx.emit(
        Node::new("Fast root page")
            .span(at(40, 4))
            .value(uint(u(40), 32)),
    );
    cx.emit(
        Node::new("Fast root level")
            .span(at(44, 4))
            .value(uint(u(44), 32)),
    );
    cx.emit(
        Node::new("Deleted pages at last cleanup")
            .span(at(48, 4))
            .value(uint(u(48), 32)),
    );
    cx.emit(
        Node::new("Heap tuples at last cleanup")
            .span(at(56, 8))
            .value(Value::Float(f64::from_bits(u64_le(&p, 56).unwrap_or(0)))),
    );
    cx.emit(
        Node::new("All equal image")
            .span(at(64, 1))
            .value(Value::Bool(p.get(64).copied().unwrap_or(0) != 0))
            .desc("Deduplication is safe for this index"),
    );
    Ok(())
}

fn special_node(span: Span, p: &[u8], special: u64, k: Kind) -> Node {
    let len = BLCKSZ.saturating_sub(special);
    let s = to_usize(special);
    let n = Node::new("Special space").span(span.sub(special, len));
    match k {
        Kind::Btree | Kind::BtreeMeta => {
            let prev = u32_le(p, s).unwrap_or(0);
            let next = u32_le(p, s.saturating_add(4)).unwrap_or(0);
            let level = u32_le(p, s.saturating_add(8)).unwrap_or(0);
            let flags = u16_le(p, s.saturating_add(12)).unwrap_or(0);
            let set = decode_flags(BTREE_FLAGS, flags.into()).0.join(", ");
            n.summary(format!(
                "B-tree: level {level}, left sibling {prev}, right sibling {next}, {set}"
            ))
        }
        Kind::Hash => n.summary(format!(
            "hash index: bucket {}, flags {:#x}",
            u32_le(p, s.saturating_add(8)).unwrap_or(0),
            u16_le(p, s.saturating_add(12)).unwrap_or(0)
        )),
        Kind::Gist => n.summary(format!(
            "GiST: right link {}, flags {:#x}",
            u32_le(p, s.saturating_add(8)).unwrap_or(0),
            u16_le(p, s.saturating_add(12)).unwrap_or(0)
        )),
        Kind::SpGist => n.summary("SP-GiST"),
        Kind::Gin => n.summary(format!(
            "GIN: right link {}, flags {:#x}",
            u32_le(p, s).unwrap_or(0),
            u16_le(p, s.saturating_add(6)).unwrap_or(0)
        )),
        Kind::Brin => n.summary("BRIN"),
        _ => n.summary(size(len)),
    }
}

/// A free space map page: a binary tree of one-byte free space categories
/// (1/256 of a page each), the leaves for heap pages or lower FSM pages.
fn fsm_page(cx: &Cx, span: Span, p: &[u8]) {
    let nodes = BLCKSZ.saturating_sub(HEADER).saturating_sub(4);
    let inner = BLCKSZ / 2 - 1;
    let leaves = nodes.saturating_sub(inner);
    cx.emit(
        Node::new("Next slot")
            .span(span.sub(HEADER, 4))
            .value(uint(u32_le(p, 24).unwrap_or(0), 32))
            .desc("Where the next search for free space starts"),
    );
    let root = p.get(28).copied().unwrap_or(0);
    cx.emit(
        Node::new("Inner nodes")
            .span(span.sub(28, inner))
            .summary(format!(
                "root category {root}: up to {} free",
                size(u64::from(root).saturating_mul(32))
            )),
    );
    let leaf_bytes = p
        .get(to_usize(28u64.saturating_add(inner))..to_usize(28u64.saturating_add(nodes)))
        .unwrap_or_default();
    let used = leaf_bytes.iter().filter(|&&b| b != 0).count();
    cx.emit(
        Node::new("Leaf nodes")
            .span(span.sub(28u64.saturating_add(inner), leaves))
            .summary(format!("{used} of {leaves} with free space")),
    );
}

/// A visibility map page: two bits per heap page, all-visible and
/// all-frozen.
fn vm_page(cx: &Cx, span: Span, p: &[u8]) {
    let bytes = p.get(to_usize(HEADER)..).unwrap_or_default();
    let visible: u32 = bytes.iter().map(|b| (b & 0x55).count_ones()).sum();
    let frozen: u32 = bytes.iter().map(|b| (b & 0xaa).count_ones()).sum();
    cx.emit(
        Node::new("Visibility bits")
            .span(span.tail(HEADER))
            .summary(format!(
                "{} heap pages, {visible} all-visible, {frozen} all-frozen",
                grouped_count(to_u64(bytes.len()).saturating_mul(4), "", "").trim()
            ))
            .desc("Two bits per heap page: all tuples visible to everyone, and all frozen"),
    );
}
