//! PostgreSQL write-ahead log segments (`pg_wal/000000010000000000000003`):
//! pages (8 KiB by default) with a header each (a long one on the
//! segment's first page, with the system identifier and the segment and
//! page sizes), holding a stream of records that run across page
//! boundaries.
//!
//! Records are walked from the first page's first record on: a 24-byte
//! header (total length, transaction, previous record, info bits, resource
//! manager, CRC-32C, which is verified), then block references (the
//! relation, fork and block a change applies to, with an optional full
//! page image, rebuilt into a page with its hole and dissected as a
//! relation page), and the resource manager's main data. A record split
//! over pages is reassembled into one piecewise source. The walk stops at
//! a zero length, at a page whose address belongs to an older segment (a
//! recycled file), and after a log switch.

use super::relation::{self, lsn};
use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::crc::crc32c_update;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{grouped_count, size};
use crate::formats::util::val::flagsv;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

pub static FORMAT: Format = Format {
    name: "pg-wal",
    title: "PostgreSQL WAL segment",
    extensions: &[],
    mime: "application/x-postgresql-wal",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const SHORT_HEADER: u64 = 24;
const LONG_HEADER: u64 = 40;
const RECORD_HEADER: u64 = 24;
/// Largest record read whole (`XLogRecordMaxSize` is 1 GiB).
const MAX_RECORD: u64 = 16 << 20;

const MAGICS: EnumTable = &[
    (0xd097, "PostgreSQL 10"),
    (0xd098, "PostgreSQL 11"),
    (0xd101, "PostgreSQL 12"),
    (0xd106, "PostgreSQL 13"),
    (0xd10d, "PostgreSQL 14"),
    (0xd110, "PostgreSQL 15"),
    (0xd113, "PostgreSQL 16"),
    (0xd116, "PostgreSQL 17"),
    (0xd118, "PostgreSQL 18"),
];

const PAGE_INFO: FlagTable = &[
    flag(1, "FIRST_IS_CONTRECORD"),
    flag(2, "LONG_HEADER"),
    flag(4, "BKP_REMOVABLE"),
    flag(8, "FIRST_IS_OVERWRITE_CONTRECORD"),
];

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(magic), Some(info), Some(addr), Some(seg), Some(blck)) = (
        u16_le(d, 0),
        u16_le(d, 2),
        u64_le(d, 8),
        u32_le(d, 32),
        u32_le(d, 36),
    ) else {
        return false;
    };
    (0xd000..=0xd1ff).contains(&magic)
        && info & 2 != 0
        && info & !0xf == 0
        && seg.is_power_of_two()
        && (1 << 20..=1 << 30).contains(&seg)
        && blck.is_power_of_two()
        && (1024..=65536).contains(&blck)
        && blck <= seg
        && addr.is_multiple_of(u64::from(seg))
}

/// What the walk needs to know about the segment.
#[derive(Clone, Copy)]
struct Seg {
    input: Input,
    magic: u16,
    page: u64,
    start: u64,
}

impl Seg {
    fn header_len(&self, page_no: u64) -> u64 {
        if page_no == 0 {
            LONG_HEADER
        } else {
            SHORT_HEADER
        }
    }

    /// The file spans of `n` record bytes from `pos`, skipping page
    /// headers, and the position after them.
    fn spans(&self, mut pos: u64, mut n: u64) -> (Vec<Span>, u64) {
        let file = self.input.span;
        let mut out = Vec::new();
        while n > 0 && pos < file.len {
            let page_no = pos.checked_div(self.page).unwrap_or(0);
            let in_page = pos.checked_rem(self.page).unwrap_or(0);
            let hl = self.header_len(page_no);
            if in_page < hl {
                pos = page_no.saturating_mul(self.page).saturating_add(hl);
                continue;
            }
            let take = n
                .min(self.page.saturating_sub(in_page))
                .min(file.len.saturating_sub(pos));
            out.push(file.sub(pos, take));
            pos = pos.saturating_add(take);
            n = n.saturating_sub(take);
        }
        (out, pos)
    }

    fn page_valid(&self, page_head: &[u8], page_no: u64) -> bool {
        u16_le(page_head, 0) == Some(self.magic)
            && u64_le(page_head, 8)
                == Some(self.start.saturating_add(page_no.saturating_mul(self.page)))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, LONG_HEADER)).await?;
    let magic = u16_le(&head, 0).unwrap_or(0);
    let tli = u32_le(&head, 4).unwrap_or(0);
    let start = u64_le(&head, 8).unwrap_or(0);
    let page = u64::from(u32_le(&head, 36).unwrap_or(8192)).max(1024);
    let seg_size = u64::from(u32_le(&head, 32).unwrap_or(0));
    let seg = Seg {
        input,
        magic,
        page,
        start,
    };
    cx.emit(
        Node::new("Long page header")
            .span(file.sub(0, LONG_HEADER))
            .lazy(page_header, (file.sub(0, LONG_HEADER), true)),
    );
    cx.emit(
        Node::new("Records")
            .summary(format!("from {}", lsn(start)))
            .lazy(records, seg),
    );
    let pages = file.len.checked_div(page).unwrap_or(0);
    cx.emit(
        Node::new("Pages")
            .span(file.sub(0, pages.saturating_mul(page)))
            .summary(grouped_count(pages, "page", "pages"))
            .lazy(pages_list, seg),
    );
    if seg_size != 0 && file.len != seg_size {
        cx.diag(Diagnostic::warning(format!(
            "the segment size is {}, the file {}",
            size(seg_size),
            size(file.len)
        )));
    }
    let segno = start.checked_div(seg_size).unwrap_or(0);
    let per_xlogid = 0x1_0000_0000u64.checked_div(seg_size).unwrap_or(1).max(1);
    cx.annotate(format!(
        "{} WAL segment {:08X}{:08X}{:08X} from {}, {} of {} pages",
        lookup(MAGICS, magic.into()).unwrap_or("PostgreSQL"),
        tli,
        segno.checked_div(per_xlogid).unwrap_or(0),
        segno.checked_rem(per_xlogid).unwrap_or(0),
        lsn(start),
        size(seg_size),
        size(page)
    ));
    Ok(())
}

async fn page_header(cx: Cx, (span, long): (Span, bool)) -> Result<()> {
    let b = cx.read(span).await?;
    let magic = u16_le(&b, 0).unwrap_or(0);
    cx.emit(Node::new("Magic").span(span.sub(0, 2)).value(Value::Enum {
        raw: magic.into(),
        bits: 16,
        name: lookup(MAGICS, magic.into()).map(Into::into),
    }));
    cx.emit(Node::new("Info").span(span.sub(2, 2)).value(flagsv(
        u16_le(&b, 2).unwrap_or(0),
        16,
        PAGE_INFO,
    )));
    cx.emit(
        Node::new("Timeline")
            .span(span.sub(4, 4))
            .value(uint(u32_le(&b, 4).unwrap_or(0), 32)),
    );
    let addr = u64_le(&b, 8).unwrap_or(0);
    cx.emit(
        Node::new("Page address")
            .span(span.sub(8, 8))
            .value(hex(addr, 64))
            .summary(lsn(addr)),
    );
    cx.emit(
        Node::new("Remaining length")
            .span(span.sub(16, 4))
            .value(uint(u32_le(&b, 16).unwrap_or(0), 32))
            .desc("Bytes of a record continued from the previous page"),
    );
    cx.emit(Node::new("Padding").span(span.sub(20, 4)));
    if long {
        cx.emit(
            Node::new("System identifier")
                .span(span.sub(24, 8))
                .value(uint(u64_le(&b, 24).unwrap_or(0), 64)),
        );
        cx.emit(
            Node::new("Segment size")
                .span(span.sub(32, 4))
                .value(uint(u32_le(&b, 32).unwrap_or(0), 32)),
        );
        cx.emit(
            Node::new("Page size")
                .span(span.sub(36, 4))
                .value(uint(u32_le(&b, 36).unwrap_or(0), 32)),
        );
    }
    Ok(())
}

async fn pages_list(cx: Cx, seg: Seg) -> Result<()> {
    let file = seg.input.span;
    let pages = file.len.checked_div(seg.page).unwrap_or(0);
    cx.set_count(Count::Exact(pages));
    let start = cx.resume::<u64>().unwrap_or(0);
    for n in start..pages {
        cx.mark(move || n);
        let span = file.sub(n.saturating_mul(seg.page), seg.page);
        let hl = seg.header_len(n);
        let summary = if cx.skipping() {
            String::new()
        } else {
            let h = cx.read(span.sub(0, hl)).await?;
            if h.iter().all(|&b| b == 0) {
                "never written".to_owned()
            } else if seg.page_valid(&h, n) {
                let rem = u32_le(&h, 16).unwrap_or(0);
                if rem != 0 {
                    format!("{} continue a record", size(rem.into()))
                } else {
                    "written".to_owned()
                }
            } else {
                format!("stale page of {}", lsn(u64_le(&h, 8).unwrap_or(0)))
            }
        };
        cx.push(
            Node::new(format!("Page {n}"))
                .span(span)
                .summary(summary)
                .lazy(page_node, (span, hl)),
        )
        .await;
    }
    Ok(())
}

async fn page_node(cx: Cx, (span, hl): (Span, u64)) -> Result<()> {
    cx.emit(
        Node::new(if hl == LONG_HEADER {
            "Long page header"
        } else {
            "Page header"
        })
        .span(span.sub(0, hl))
        .lazy(page_header, (span.sub(0, hl), hl == LONG_HEADER)),
    );
    cx.emit(Node::new("Record data").span(span.tail(hl)));
    Ok(())
}

const RMGRS: EnumTable = &[
    (0, "XLOG"),
    (1, "Transaction"),
    (2, "Storage"),
    (3, "CLOG"),
    (4, "Database"),
    (5, "Tablespace"),
    (6, "MultiXact"),
    (7, "RelMap"),
    (8, "Standby"),
    (9, "Heap2"),
    (10, "Heap"),
    (11, "Btree"),
    (12, "Hash"),
    (13, "Gin"),
    (14, "Gist"),
    (15, "Sequence"),
    (16, "SPGist"),
    (17, "BRIN"),
    (18, "CommitTs"),
    (19, "ReplicationOrigin"),
    (20, "Generic"),
    (21, "LogicalMessage"),
];

/// The record type a resource manager's info bits name.
fn info_name(rmgr: u8, info: u8, magic: u16) -> Option<&'static str> {
    let hi = info & 0xf0;
    let low3 = info & 0x70;
    Some(match rmgr {
        0 => match hi {
            0x00 => "CHECKPOINT_SHUTDOWN",
            0x10 => "CHECKPOINT_ONLINE",
            0x20 => "NOOP",
            0x30 => "NEXTOID",
            0x40 => "SWITCH",
            0x50 => "BACKUP_END",
            0x60 => "PARAMETER_CHANGE",
            0x70 => "RESTORE_POINT",
            0x80 => "FPW_CHANGE",
            0x90 => "END_OF_RECOVERY",
            0xa0 => "FPI_FOR_HINT",
            0xb0 => "FPI",
            0xd0 => "OVERWRITE_CONTRECORD",
            0xe0 => "CHECKPOINT_REDO",
            _ => return None,
        },
        1 => match low3 {
            0x00 => "COMMIT",
            0x10 => "PREPARE",
            0x20 => "ABORT",
            0x30 => "COMMIT_PREPARED",
            0x40 => "ABORT_PREPARED",
            0x50 => "ASSIGNMENT",
            0x60 => "INVALIDATION",
            _ => return None,
        },
        2 => match hi {
            0x10 => "CREATE",
            0x20 => "TRUNCATE",
            _ => return None,
        },
        3 => match hi {
            0x00 => "ZEROPAGE",
            0x10 => "TRUNCATE",
            _ => return None,
        },
        4 => match hi {
            0x00 => "CREATE_FILE_COPY",
            0x10 => "DROP",
            0x20 => "CREATE_WAL_LOG",
            _ => return None,
        },
        6 => match low3 {
            0x00 => "ZERO_OFF_PAGE",
            0x10 => "ZERO_MEM_PAGE",
            0x20 => "CREATE_ID",
            0x30 => "TRUNCATE_ID",
            _ => return None,
        },
        7 => "UPDATE",
        8 => match hi {
            0x00 => "LOCK",
            0x10 => "RUNNING_XACTS",
            0x20 => "INVALIDATIONS",
            _ => return None,
        },
        9 => match (low3, magic >= 0xd116) {
            (0x00, _) => "REWRITE",
            (0x10, true) => "PRUNE_ON_ACCESS",
            (0x20, true) => "PRUNE_VACUUM_SCAN",
            (0x30, true) => "PRUNE_VACUUM_CLEANUP",
            (0x10, false) => "PRUNE",
            (0x20, false) => "VACUUM",
            (0x30, false) => "FREEZE_PAGE",
            (0x40, _) => "VISIBLE",
            (0x50, _) => "MULTI_INSERT",
            (0x60, _) => "LOCK_UPDATED",
            (0x70, _) => "NEW_CID",
            _ => return None,
        },
        10 => match low3 {
            0x00 => "INSERT",
            0x10 => "DELETE",
            0x20 => "UPDATE",
            0x30 => "TRUNCATE",
            0x40 => "HOT_UPDATE",
            0x50 => "CONFIRM",
            0x60 => "LOCK",
            0x70 => "INPLACE",
            _ => return None,
        },
        11 => match hi {
            0x00 => "INSERT_LEAF",
            0x10 => "INSERT_UPPER",
            0x20 => "INSERT_META",
            0x30 => "SPLIT_L",
            0x40 => "SPLIT_R",
            0x50 => "INSERT_POST",
            0x60 => "DEDUP",
            0x70 => "DELETE",
            0x80 => "UNLINK_PAGE",
            0x90 => "UNLINK_PAGE_META",
            0xa0 => "NEWROOT",
            0xb0 => "MARK_PAGE_HALFDEAD",
            0xc0 => "VACUUM",
            0xd0 => "REUSE_PAGE",
            0xe0 => "META_CLEANUP",
            _ => return None,
        },
        15 => "LOG",
        _ => return None,
    })
}

/// A record's place: its file spans (more than one when it crosses pages).
#[derive(Clone)]
struct RecState {
    seg: Seg,
    pos: u64,
    len: u64,
}

/// Reads up to `n` bytes of a record from its spans.
async fn read_spans(cx: &Cx, spans: &[Span], n: u64) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    for s in spans {
        let have = to_u64(out.len());
        if have >= n {
            break;
        }
        let b = cx.read(s.sub(0, n.saturating_sub(have))).await?;
        out.extend_from_slice(&b);
    }
    Ok(out)
}

async fn records(cx: Cx, seg: Seg) -> Result<()> {
    let file = seg.input.span;
    let resumed = cx.resume::<(u64, u64)>();
    let (mut pos, mut i) = match resumed {
        Some(r) => r,
        None => {
            let head = cx.read(file.sub(0, LONG_HEADER)).await?;
            let info = u16_le(&head, 2).unwrap_or(0);
            let rem = u64::from(u32_le(&head, 16).unwrap_or(0));
            let mut pos = LONG_HEADER;
            if info & 1 != 0 && rem != 0 {
                let (spans, end) = seg.spans(LONG_HEADER, rem);
                let first = spans
                    .first()
                    .map_or(LONG_HEADER, |s| s.offset.saturating_sub(file.offset));
                cx.emit(
                    Node::new("Continued record")
                        .span(file.sub(first, end.saturating_sub(first)))
                        .summary(format!(
                            "the last {} of a record from the previous segment",
                            size(rem)
                        )),
                );
                pos = end.saturating_add(7) & !7;
            }
            (pos, 0)
        }
    };
    cx.set_count(Count::Unknown);
    loop {
        if pos >= file.len {
            break;
        }
        let page_no = pos.checked_div(seg.page).unwrap_or(0);
        if pos.checked_rem(seg.page).unwrap_or(0) < seg.header_len(page_no) {
            pos = page_no
                .saturating_mul(seg.page)
                .saturating_add(seg.header_len(page_no));
        }
        let page_head = cx
            .read(file.sub(page_no.saturating_mul(seg.page), SHORT_HEADER))
            .await?;
        if !seg.page_valid(&page_head, page_no) {
            if !page_head.iter().all(|&b| b == 0) {
                cx.push(
                    Node::new("Stale data")
                        .span(file.tail(page_no.saturating_mul(seg.page)))
                        .summary(format!(
                            "from page {page_no}: left over from {}, before the file was recycled",
                            lsn(u64_le(&page_head, 8).unwrap_or(0))
                        )),
                )
                .await;
            } else {
                cx.push(
                    Node::new("Unused")
                        .span(file.tail(pos))
                        .summary("never written"),
                )
                .await;
            }
            break;
        }
        let (hspans, _) = seg.spans(pos, RECORD_HEADER);
        let h = read_spans(&cx, &hspans, RECORD_HEADER).await?;
        let tot = u64::from(u32_le(&h, 0).unwrap_or(0));
        if tot == 0 {
            cx.push(
                Node::new("Unused")
                    .span(file.tail(pos))
                    .summary("end of the log: no record has been written here"),
            )
            .await;
            break;
        }
        if !(RECORD_HEADER..=1 << 30).contains(&tot) {
            cx.push(
                Node::new("Unparsed data")
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed(format!("record length {tot}"))),
            )
            .await;
            break;
        }
        let (spans, end) = seg.spans(pos, tot);
        let got: u64 = spans.iter().map(|s| s.len).sum();
        let at = (pos, i);
        cx.mark(move || at);
        let rmid = h.get(17).copied().unwrap_or(0);
        let info = h.get(16).copied().unwrap_or(0);
        let head = read_spans(&cx, &spans, tot.min(512)).await?;
        let blocks = parse_blocks(&head, tot, seg.magic);
        let mut summary = format!(
            "{} {}, {} bytes, xid {}",
            lookup(RMGRS, rmid.into()).unwrap_or("?"),
            info_name(rmid, info, seg.magic).unwrap_or("?"),
            tot,
            u32_le(&h, 4).unwrap_or(0)
        );
        for b in &blocks.refs {
            summary.push_str(&format!(
                ", block {}/{}/{} {}",
                b.rel.0, b.rel.1, b.rel.2, b.block
            ));
            if b.image.is_some() {
                summary.push_str(" (page image)");
            }
        }
        let lsn_here = seg.start.saturating_add(pos);
        let mut node = Node::new(format!("Record {}", lsn(lsn_here)))
            .span(file.sub(pos, end.saturating_sub(pos)))
            .summary(summary)
            .lazy(record, RecState { seg, pos, len: tot });
        if got < tot {
            node = node.diag(Diagnostic::truncated(
                Span::new(file.source, file.offset.saturating_add(pos), tot),
                file.len.saturating_sub(pos),
            ));
        }
        cx.push(node).await;
        i = i.saturating_add(1);
        cx.progress_in(file, end);
        if got < tot {
            break;
        }
        if rmid == 0 && info & 0xf0 == 0x40 {
            let next = end.saturating_add(7) & !7;
            if next < file.len {
                cx.push(
                    Node::new("Unused")
                        .span(file.tail(next))
                        .summary("after a log switch: the rest of the segment is not used"),
                )
                .await;
            }
            break;
        }
        pos = end.saturating_add(7) & !7;
    }
    Ok(())
}

/// One block reference.
#[derive(Clone, Copy, Debug, Default)]
struct BlockRef {
    id: u8,
    fork: u8,
    flags: u8,
    data_len: u64,
    /// Image length, hole offset, hole length, image flags.
    image: Option<(u64, u64, u64, u8)>,
    rel: (u32, u32, u32),
    block: u32,
    /// Where its header is.
    at: u64,
    len: u64,
}

#[derive(Debug, Default)]
struct Blocks {
    refs: Vec<BlockRef>,
    main: u64,
    /// Where the headers end.
    end: u64,
    origin: Option<u16>,
    toplevel: Option<u32>,
    problem: Option<String>,
}

fn image_compressed(info: u8, magic: u16) -> bool {
    if magic >= 0xd110 {
        info & 0x1c != 0
    } else {
        info & 0x02 != 0
    }
}

/// Decodes the block headers after the record header (only the first
/// bytes of the record are needed).
fn parse_blocks(b: &[u8], tot: u64, magic: u16) -> Blocks {
    let mut out = Blocks::default();
    let mut pos = RECORD_HEADER;
    let mut rel = (0u32, 0u32, 0u32);
    let byte = |p: u64| b.get(to_usize(p)).copied();
    while pos < tot {
        let Some(id) = byte(pos) else {
            out.problem = Some("block headers run past what was read".to_owned());
            break;
        };
        match id {
            255 => {
                out.main = byte(pos.saturating_add(1)).unwrap_or(0).into();
                pos = pos.saturating_add(2);
                break;
            }
            254 => {
                out.main = u32_le(b, to_usize(pos.saturating_add(1)))
                    .unwrap_or(0)
                    .into();
                pos = pos.saturating_add(5);
                break;
            }
            253 => {
                out.origin = u16_le(b, to_usize(pos.saturating_add(1)));
                pos = pos.saturating_add(3);
            }
            252 => {
                out.toplevel = u32_le(b, to_usize(pos.saturating_add(1)));
                pos = pos.saturating_add(5);
            }
            0..=32 => {
                let start = pos;
                let flags = byte(pos.saturating_add(1)).unwrap_or(0);
                let mut r = BlockRef {
                    id,
                    fork: flags & 0x0f,
                    flags,
                    data_len: u16_le(b, to_usize(pos.saturating_add(2)))
                        .unwrap_or(0)
                        .into(),
                    ..BlockRef::default()
                };
                pos = pos.saturating_add(4);
                if flags & 0x10 != 0 {
                    let len = u64::from(u16_le(b, to_usize(pos)).unwrap_or(0));
                    let hole_off =
                        u64::from(u16_le(b, to_usize(pos.saturating_add(2))).unwrap_or(0));
                    let info = byte(pos.saturating_add(4)).unwrap_or(0);
                    pos = pos.saturating_add(5);
                    let compressed = image_compressed(info, magic);
                    let hole = if info & 1 != 0 && compressed {
                        let h = u64::from(u16_le(b, to_usize(pos)).unwrap_or(0));
                        pos = pos.saturating_add(2);
                        h
                    } else if info & 1 != 0 {
                        super::BLCKSZ.saturating_sub(len)
                    } else {
                        0
                    };
                    r.image = Some((len, hole_off, hole, info));
                }
                if flags & 0x80 == 0 {
                    rel = (
                        u32_le(b, to_usize(pos)).unwrap_or(0),
                        u32_le(b, to_usize(pos.saturating_add(4))).unwrap_or(0),
                        u32_le(b, to_usize(pos.saturating_add(8))).unwrap_or(0),
                    );
                    pos = pos.saturating_add(12);
                }
                r.rel = rel;
                r.block = u32_le(b, to_usize(pos)).unwrap_or(0);
                pos = pos.saturating_add(4);
                r.at = start;
                r.len = pos.saturating_sub(start);
                out.refs.push(r);
            }
            _ => {
                out.problem = Some(format!("unknown block ID {id}"));
                break;
            }
        }
    }
    out.end = pos;
    out
}

const FORKS: EnumTable = &[(0, "main"), (1, "fsm"), (2, "vm"), (3, "init")];

async fn record(cx: Cx, rs: RecState) -> Result<()> {
    let seg = rs.seg;
    let file = seg.input.span;
    let (spans, end) = seg.spans(rs.pos, rs.len);
    let span = if spans.len() == 1 {
        spans.first().copied().unwrap_or(file.sub(rs.pos, 0))
    } else {
        cx.add_pieces(
            Origin {
                parent: file.sub(rs.pos, end.saturating_sub(rs.pos)),
                transform: "pg-wal-record",
            },
            spans.clone(),
        )?
    };
    let tot = rs.len.min(span.len);
    let whole = tot <= MAX_RECORD;
    let b = cx.read(span.sub(0, if whole { tot } else { 4096 })).await?;
    cx.charge(to_u64(b.len()) / 1024).await;
    let at = |o: u64, l: u64| span.sub(o, l);
    cx.emit(
        Node::new("Total length")
            .span(at(0, 4))
            .value(uint(u32_le(&b, 0).unwrap_or(0), 32)),
    );
    cx.emit(
        Node::new("Transaction ID")
            .span(at(4, 4))
            .value(uint(u32_le(&b, 4).unwrap_or(0), 32)),
    );
    let prev = u64_le(&b, 8).unwrap_or(0);
    cx.emit(
        Node::new("Previous record")
            .span(at(8, 8))
            .value(hex(prev, 64))
            .summary(lsn(prev)),
    );
    let info = b.get(16).copied().unwrap_or(0);
    let rmid = b.get(17).copied().unwrap_or(0);
    let mut flags = Vec::new();
    if info & 0x01 != 0 {
        flags.push("special: block images apply");
    }
    if info & 0x02 != 0 {
        flags.push("consistency check");
    }
    cx.emit(
        Node::new("Info")
            .span(at(16, 1))
            .value(hex(info, 8))
            .summary(format!(
                "{}{}{}",
                info_name(rmid, info, seg.magic).unwrap_or("?"),
                if flags.is_empty() { "" } else { ", " },
                flags.join(", ")
            )),
    );
    cx.emit(
        Node::new("Resource manager")
            .span(at(17, 1))
            .value(Value::Enum {
                raw: rmid.into(),
                bits: 8,
                name: lookup(RMGRS, rmid.into()).map(Into::into),
            }),
    );
    cx.emit(Node::new("Padding").span(at(18, 2)));
    let stored = u32_le(&b, 20).unwrap_or(0);
    let mut crc = Node::new("CRC").span(at(20, 4)).value(hex(stored, 32));
    if whole && to_u64(b.len()) == tot {
        let body = b.get(24..).unwrap_or_default();
        let head = b.get(..20).unwrap_or_default();
        let computed = !crc32c_update(crc32c_update(u32::MAX, body), head);
        crc = if computed == stored {
            crc.summary("CRC-32C, valid")
        } else {
            crc.diag(Diagnostic::warning(format!(
                "CRC mismatch (computed {computed:#010x})"
            )))
        };
    }
    cx.emit(crc);
    let blocks = parse_blocks(&b, tot, seg.magic);
    if let Some(p) = &blocks.problem {
        cx.diag(Diagnostic::malformed(p.clone()));
    }
    let mut data_pos = blocks.end;
    for r in &blocks.refs {
        let mut summary = format!(
            "rel {}/{}/{} fork {} block {}",
            r.rel.0,
            r.rel.1,
            r.rel.2,
            lookup(FORKS, r.fork.into()).unwrap_or("?"),
            r.block
        );
        if let Some((len, hole_off, hole, _)) = r.image {
            summary.push_str(&format!(
                ", page image of {len} bytes, hole of {hole} at {hole_off}"
            ));
        }
        if r.data_len != 0 {
            summary.push_str(&format!(", {} bytes of data", r.data_len));
        }
        cx.emit(
            Node::new(format!("Block reference {}", r.id))
                .span(at(r.at, r.len))
                .summary(summary)
                .value(flagsv(u64::from(r.flags & 0xf0), 8, BLOCK_FLAGS)),
        );
    }
    if blocks.main != 0 || data_pos < tot {
        let main_hdr = if blocks.main > 255 { 5 } else { 2 };
        if blocks.main != 0 {
            cx.emit(
                Node::new("Main data length")
                    .span(at(blocks.end.saturating_sub(main_hdr), main_hdr))
                    .value(uint(blocks.main, 32)),
            );
        }
    }
    for r in &blocks.refs {
        if let Some((len, hole_off, hole, info)) = r.image {
            let img = at(data_pos, len);
            if image_compressed(info, seg.magic) {
                cx.emit(
                    Node::new(format!("Page image {}", r.id))
                        .span(img)
                        .summary(format!("compressed ({} bytes)", len))
                        .diag(Diagnostic::unsupported("compressed full page images")),
                );
            } else {
                let pieces = vec![
                    img.sub(0, hole_off),
                    Span::zeros(hole),
                    img.sub(hole_off, len.saturating_sub(hole_off)),
                ];
                let node = match cx.add_pieces(
                    Origin {
                        parent: img,
                        transform: "pg-page-image",
                    },
                    pieces,
                ) {
                    Ok(page) => embedded_as(
                        format!("Page image {}", r.id),
                        seg.input.nested(page),
                        &relation::IMAGE,
                    )
                    .summary(format!(
                        "block {}, {} bytes with a hole of {hole}",
                        r.block, len
                    )),
                    Err(e) => Node::new(format!("Page image {}", r.id)).span(img).diag(e),
                };
                cx.emit(node);
            }
            data_pos = data_pos.saturating_add(len);
        }
        if r.data_len != 0 {
            cx.emit(
                Node::new(format!("Block data {}", r.id))
                    .span(at(data_pos, r.data_len))
                    .summary(size(r.data_len)),
            );
            data_pos = data_pos.saturating_add(r.data_len);
        }
    }
    if blocks.main != 0 {
        let main = at(data_pos, blocks.main);
        let mut n = Node::new("Main data").span(main).summary(size(blocks.main));
        if rmid == 1 && matches!(info & 0x70, 0x00 | 0x20) {
            // COMMIT and ABORT start with the transaction's time
            // (microseconds since 2000-01-01).
            if let Some(us) = b.get(to_usize(data_pos)..).and_then(|d| u64_le(d, 0)) {
                let us = i64::from_le_bytes(us.to_le_bytes());
                n = n.value(Value::Timestamp {
                    unix_seconds: us.div_euclid(1_000_000).saturating_add(946_684_800),
                });
            }
        }
        cx.emit(n);
        data_pos = data_pos.saturating_add(blocks.main);
    }
    if data_pos < tot {
        cx.diag(Diagnostic::malformed(format!(
            "{} bytes after the main data",
            tot.saturating_sub(data_pos)
        )));
    }
    if !whole {
        cx.diag(Diagnostic::limit("record too large to check its CRC"));
    }
    Ok(())
}

const BLOCK_FLAGS: FlagTable = &[
    flag(0x10, "HAS_IMAGE"),
    flag(0x20, "HAS_DATA"),
    flag(0x40, "WILL_INIT"),
    flag(0x80, "SAME_REL"),
];
