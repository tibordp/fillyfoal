//! One InnoDB page: the FIL header and trailer (with the checksum
//! verified), and the body by page type. Index pages are in `index`.

use std::sync::Arc;

use super::dict::Dict;
use super::{
    BE, FIL_HEADER, FIL_NULL, FspHeader, PAGE_TYPES, Space, SpaceRef, Sum, file_addr, fseg_header,
    list_base, mysql_version,
};
use crate::bytes::{to_u64, to_usize, u16_be, u32_be, u64_be};
use crate::codec::crc::crc32c;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{grouped_count, plural, size};
use crate::formats::util::val::{hex, text, uint};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Check, EnumTable, Value, lookup};

pub const ALLOCATED: u16 = 0;
pub const UNDO_LOG: u16 = 2;
pub const INODE: u16 = 3;
pub const IBUF_BITMAP: u16 = 5;
pub const SYS: u16 = 6;
pub const TRX_SYS: u16 = 7;
pub const FSP_HDR: u16 = 8;
pub const XDES: u16 = 9;
pub const BLOB: u16 = 10;
pub const SDI_BLOB: u16 = 18;
pub const RSEG_ARRAY: u16 = 21;
pub const LOB_INDEX: u16 = 22;
pub const LOB_DATA: u16 = 23;
pub const LOB_FIRST: u16 = 24;
pub const SDI: u16 = 17853;
pub const RTREE: u16 = 17854;
pub const INDEX: u16 = 17855;

/// Bytes read per page for its summary: the FIL header and an index
/// page's header.
pub const SUMMARY_BYTES: u64 = 94;
/// Deepest chain of page links followed from one page.
pub const MAX_DEPTH: usize = 64;

/// Index pages (MariaDB marks the root page of a table altered with
/// instant ADD COLUMN with type 18, MySQL's SDI BLOB type).
pub fn is_index(kind: u16, page: &[u8]) -> bool {
    match kind {
        INDEX | SDI | RTREE => true,
        SDI_BLOB => page.get(99..106) == Some(b"infimum") || page.get(101..108) == Some(b"infimum"),
        _ => false,
    }
}

/// The type name of a page.
pub fn type_name(kind: u16) -> String {
    lookup(PAGE_TYPES, kind.into()).map_or_else(|| format!("type {kind}"), str::to_owned)
}

/// A page's summary from its first `SUMMARY_BYTES`.
pub fn summary(space: &Space, no: u32, head: &[u8], dict: Option<&Dict>) -> String {
    if head.iter().all(|&b| b == 0) {
        return "never written".to_owned();
    }
    let kind = u16_be(head, 24).unwrap_or(0);
    let mut s = type_name(kind);
    if is_index(kind, head) {
        let level = u16_be(head, 64).unwrap_or(0);
        let records = u16_be(head, 54).unwrap_or(0);
        let id = u64_be(head, 66).unwrap_or(0);
        let name = if kind == SDI {
            "dictionary".to_owned()
        } else if id >> 32 == 0xffff_ffff {
            format!("change buffer of space {}", id & 0xffff_ffff)
        } else {
            dict.and_then(|d| d.index(id)).map_or_else(
                || format!("index {id}"),
                |i| format!("{}.{}", i.table, i.name),
            )
        };
        s = format!(
            "{s}: {name}, {}, {}",
            if level == 0 {
                "leaf".to_owned()
            } else {
                format!("level {level}")
            },
            grouped_count(records, "record", "records")
        );
    }
    let stored = u32_be(head, 4).unwrap_or(0);
    if stored != no {
        s.push_str(&format!(" (page number {stored} in its header)"));
    }
    let _ = space;
    s
}

/// What a page expansion needs: the page and the pages above it.
#[derive(Clone)]
pub struct PageState {
    pub space: SpaceRef,
    pub no: u32,
    pub path: Arc<Vec<u32>>,
    /// A compressed page's rebuilt uncompressed page, when the expansion
    /// is about that rather than the page in the file.
    pub view: Option<Span>,
}

impl PageState {
    /// The bytes the expansion is about: the rebuilt page, or the page.
    pub fn span(&self) -> Option<Span> {
        self.view.or_else(|| self.space.page(self.no))
    }

    /// The trailer after the page directory (a rebuilt page has the
    /// uncompressed page's).
    pub fn trailer(&self) -> u64 {
        if self.view.is_some() {
            super::FIL_TRAILER
        } else {
            self.space.geo.trailer()
        }
    }
}

/// A node for page `no`, expanded lazily; `path` holds the pages whose
/// links led here (for cycles).
pub fn node(space: &SpaceRef, name: String, no: u32, path: Arc<Vec<u32>>) -> Node {
    let node = Node::new(name);
    let Some(span) = space.page(no) else {
        let file = space.input.span;
        let at = u64::from(no).saturating_mul(space.geo.phys);
        return node.value(uint(no, 32)).diag(Diagnostic::truncated(
            Span::new(file.source, file.offset.saturating_add(at), space.geo.phys),
            file.len.saturating_sub(at),
        ));
    };
    node.span(span).lazy(
        crate::expander!(self::expand: PageState),
        PageState {
            space: space.clone(),
            no,
            path,
            view: None,
        },
    )
}

/// A link to another page (a sibling, a child, the next BLOB part).
pub fn link(name: &'static str, state: &PageState, no: u32, at: Span) -> Node {
    if no == FIL_NULL {
        return Node::new(name).span(at).value(hex(no, 32)).summary("none");
    }
    if state.path.contains(&no) || no == state.no {
        return Node::new(name)
            .span(at)
            .value(uint(no, 32))
            .diag(Diagnostic::malformed(format!(
                "page {no_link} back to a page that led here",
                no_link = plural(no, "link")
            )));
    }
    if state.path.len() >= MAX_DEPTH {
        return Node::new(name)
            .span(at)
            .value(uint(no, 32))
            .diag(Diagnostic::limit(format!(
                "page links nested deeper than {MAX_DEPTH}"
            )));
    }
    let mut path = (*state.path).clone();
    path.push(state.no);
    let target = state.space.page(no);
    let mut n = node(&state.space, name.to_owned(), no, Arc::new(path)).value(uint(no, 32));
    if let Some(t) = target {
        n = n.target(t).span(at);
    } else {
        n = n.span(at);
    }
    n
}

/// A page number that is shown but not followed (sibling pointers, which
/// would let a walk wander along a whole level).
pub fn page_ref(name: &'static str, space: &Space, no: u32, at: Span) -> Node {
    let n = Node::new(name).span(at);
    if no == FIL_NULL {
        return n.value(hex(no, 32)).summary("none");
    }
    let n = n.value(uint(no, 32));
    match space.page(no) {
        Some(t) => n.target(t),
        None => n.diag(Diagnostic::malformed(format!(
            "page {no} is past the end of the file"
        ))),
    }
}

/// The result of checking a page's checksum.
pub enum PageSum {
    /// Valid, by this algorithm.
    Valid(&'static str),
    /// The "none" algorithm's magic.
    NoChecksum,
    Empty,
    /// The CRC-32C the page should have.
    Mismatch(u32),
}

const HASH_MASK: u64 = 1_463_735_687;
const HASH_MASK2: u64 = 1_653_893_711;

/// InnoDB's legacy page checksum (`ut_fold_binary` over a range).
fn fold(data: &[u8]) -> u64 {
    data.iter().fold(0u64, |acc, &b| {
        let n2 = u64::from(b);
        ((acc ^ n2 ^ HASH_MASK2).wrapping_shl(8).wrapping_add(acc) ^ HASH_MASK).wrapping_add(n2)
    })
}

/// The CRC-32C variant of compressed pages (`page_zip_calc_checksum`):
/// the header without the checksum, LSN and flush LSN, and the rest.
pub fn zip_checksum(page: &[u8]) -> u32 {
    let range = |a: usize, b: usize| page.get(a..b).unwrap_or_default();
    crc32c(range(4, 16)) ^ crc32c(range(24, 26)) ^ crc32c(range(34, page.len()))
}

/// Checks a whole page's checksum.
pub fn verify(space: &Space, page: &[u8]) -> PageSum {
    if page.iter().all(|&b| b == 0) {
        return PageSum::Empty;
    }
    let len = page.len();
    let range = |a: usize, b: usize| page.get(a..b).unwrap_or_default();
    match space.geo.sum {
        Sum::FullCrc32 => {
            let stored = u32_be(page, len.saturating_sub(4)).unwrap_or(0);
            let crc = crc32c(range(0, len.saturating_sub(4)));
            if crc == stored {
                PageSum::Valid("CRC-32C")
            } else {
                PageSum::Mismatch(crc)
            }
        }
        Sum::Zip => {
            let stored = u32_be(page, 0).unwrap_or(0);
            if stored == 0xdead_beef {
                return PageSum::NoChecksum;
            }
            let crc = zip_checksum(page);
            if crc == stored {
                PageSum::Valid("CRC-32C")
            } else {
                PageSum::Mismatch(crc)
            }
        }
        Sum::Classic => {
            let stored = u32_be(page, 0).unwrap_or(0);
            if stored == 0xdead_beef {
                return PageSum::NoChecksum;
            }
            let end = len.saturating_sub(8);
            let crc = crc32c(range(4, 26)) ^ crc32c(range(38, end));
            if crc == stored {
                return PageSum::Valid("CRC-32C");
            }
            let legacy = fold(range(4, 26)).wrapping_add(fold(range(38, end))) & 0xffff_ffff;
            if legacy == u64::from(stored) {
                return PageSum::Valid("InnoDB legacy");
            }
            PageSum::Mismatch(crc)
        }
    }
}

/// Expands a page.
pub async fn expand(cx: Cx, state: PageState) -> Result<()> {
    let space = &state.space;
    let Some(span) = space.page(state.no) else {
        return Err(Diagnostic::malformed("page past the end of the file"));
    };
    let page = cx.read(span).await?;
    // The checksums below run over the whole page.
    cx.charge(to_u64(page.len()) / 512).await;
    let kind = u16_be(&page, 24).unwrap_or(0);
    fil_header(&cx, &state, span, &page);
    let trailer = space.geo.trailer();
    let body = span.sub(
        FIL_HEADER,
        span.len.saturating_sub(FIL_HEADER).saturating_sub(trailer),
    );
    if page.iter().all(|&b| b == 0) {
        cx.emit(
            Node::new("Unused")
                .span(body)
                .summary("all zero: allocated but never written"),
        );
    } else if is_index(kind, &page) {
        super::index::body(&cx, &state, span, &page).await?;
    } else {
        match kind {
            FSP_HDR | XDES => descriptor_page(&cx, &state, span, &page, kind),
            INODE => inode_page(&cx, &state, span, &page),
            IBUF_BITMAP => bitmap_page(&cx, space, span),
            TRX_SYS => trx_sys_page(&cx, space, span, &page),
            SYS => sys_page(&cx, &state, span, &page),
            UNDO_LOG => undo_page(&cx, space, span, &page),
            RSEG_ARRAY => rseg_array_page(&cx, &state, span, &page),
            BLOB | SDI_BLOB => blob_page(&cx, &state, span, &page),
            LOB_FIRST | LOB_DATA | LOB_INDEX => lob_page(&cx, space, span, &page, kind),
            ALLOCATED => cx.emit(Node::new("Unused").span(body).summary("free page")),
            _ => cx.emit(Node::new("Page body").span(body).summary(type_name(kind))),
        }
    }
    fil_trailer(&cx, space, span, &page);
    Ok(())
}

fn fil_header(cx: &Cx, state: &PageState, span: Span, page: &[u8]) {
    let space = &state.space;
    let at = |o: u64, n: u64| span.sub(o, n);
    let u32_at = |o: usize| u32_be(page, o).unwrap_or(0);
    let mut node = Node::new("FIL header")
        .span(at(0, FIL_HEADER))
        .lazy(fil_fields, state.clone());
    if let PageSum::Mismatch(computed) = verify(space, page) {
        let stored = match space.geo.sum {
            Sum::FullCrc32 => u32_at(page.len().saturating_sub(4)),
            _ => u32_at(0),
        };
        if let Some(message) = Check::new("CRC-32C", stored)
            .verify(computed)
            .mismatch_text()
        {
            node = node.diag(Diagnostic::warning(message));
        }
    }
    if u32_at(4) != state.no && !page.iter().all(|&b| b == 0) {
        node = node.diag(Diagnostic::malformed(format!(
            "page {} holds page number {}",
            state.no,
            u32_at(4)
        )));
    }
    cx.emit(node);
}

async fn fil_fields(cx: Cx, state: PageState) -> Result<()> {
    let space = &state.space;
    let Some(span) = space.page(state.no) else {
        return Ok(());
    };
    let page = cx.read(span).await?;
    let at = |o: u64, n: u64| span.sub(o, n);
    let u32_at = |o: usize| u32_be(&page, o).unwrap_or(0);
    let stored = u32_at(0);
    let checksum = Node::new(if space.geo.sum == Sum::FullCrc32 {
        "Key version"
    } else {
        "Checksum"
    })
    .span(at(0, 4));
    let kind = if space.geo.sum == Sum::Zip {
        "CRC-32C of a compressed page"
    } else {
        "CRC-32C, or InnoDB's legacy fold"
    };
    cx.emit(match (space.geo.sum, verify(space, &page)) {
        (Sum::FullCrc32, _) => checksum.value(hex(stored, 32)).desc("With full_crc32 the checksum is at the end of the page; this field holds the encryption key version"),
        (_, PageSum::Valid(algorithm)) => checksum.checksum(Check::new(algorithm, stored).verified(true)).desc(kind),
        (_, PageSum::NoChecksum) => checksum.value(hex(stored, 32)).summary("no checksum (innodb_checksum_algorithm=none)"),
        (_, PageSum::Empty) => checksum.checksum(Check::new("CRC-32C", stored).skipped("empty page")),
        (_, PageSum::Mismatch(c)) => checksum.checksum(Check::new("CRC-32C", stored).verify(c)).desc(kind),
    });
    let mut no = Node::new("Page number")
        .span(at(4, 4))
        .value(uint(u32_at(4), 32));
    if u32_at(4) != state.no && !page.iter().all(|&b| b == 0) {
        no = no.diag(Diagnostic::malformed(format!(
            "expected page number {}",
            state.no
        )));
    }
    cx.emit(no);
    if state.no == 0 && space.server_version.is_some() {
        cx.emit(
            Node::new("Server version")
                .span(at(8, 4))
                .value(uint(u32_at(8), 32))
                .summary(mysql_version(u32_at(8)))
                .desc("MySQL 8 records the version that created the tablespace on page 0"),
        );
        cx.emit(
            Node::new("Space version")
                .span(at(12, 4))
                .value(uint(u32_at(12), 32)),
        );
    } else {
        let kind = u16_be(&page, 24).unwrap_or(0);
        let linked = is_index(kind, &page) || matches!(kind, UNDO_LOG);
        for (name, o) in [("Previous page", 8u64), ("Next page", 12)] {
            let v = u32_at(to_usize(o));
            cx.emit(if linked || (v != 0 && v != FIL_NULL) {
                page_ref(name, space, v, at(o, 4))
            } else {
                Node::new(name)
                    .span(at(o, 4))
                    .value(hex(v, 32))
                    .summary("unused")
            });
        }
    }
    cx.emit(
        Node::new("LSN")
            .span(at(16, 8))
            .value(uint(u64_be(&page, 16).unwrap_or(0), 64))
            .desc("Log sequence number of the last change written to the page"),
    );
    let kind = u16_be(&page, 24).unwrap_or(0);
    cx.emit(Node::new("Page type").span(at(24, 2)).value(Value::Enum {
        raw: kind.into(),
        bits: 16,
        name: lookup(PAGE_TYPES, kind.into()).map(Into::into),
    }));
    cx.emit(
        Node::new("Flush LSN")
            .span(at(26, 8))
            .value(uint(u64_be(&page, 26).unwrap_or(0), 64))
            .desc("Page 0 of the system tablespace: the LSN of the last checkpoint at shutdown; elsewhere unused, or the compression and encryption header of transformed pages"),
    );
    let mut sid = Node::new("Space ID")
        .span(at(34, 4))
        .value(uint(u32_at(34), 32));
    if u32_at(34) != space.space_id && !page.iter().all(|&b| b == 0) {
        sid = sid.diag(Diagnostic::malformed(format!(
            "page of space {}, not {}",
            u32_at(34),
            space.space_id
        )));
    }
    cx.emit(sid);
    Ok(())
}

fn fil_trailer(cx: &Cx, space: &Space, span: Span, page: &[u8]) {
    let len = span.len;
    let lsn_low = u32_be(page, 20).unwrap_or(0);
    let empty = page.iter().all(|&b| b == 0);
    let low_at = |o: u64| {
        let v = u32_be(page, to_usize(o)).unwrap_or(0);
        let n = Node::new("LSN (low 32 bits)")
            .span(span.sub(o, 4))
            .value(hex(v, 32));
        if v != lsn_low && !empty {
            n.diag(Diagnostic::malformed(
                "does not match the header's LSN: the page was torn while being written",
            ))
        } else {
            n
        }
    };
    match space.geo.sum {
        Sum::Zip => {}
        Sum::Classic => {
            let old = u32_be(page, to_usize(len.saturating_sub(8))).unwrap_or(0);
            cx.emit(
                Node::new("Old-style checksum")
                    .span(span.sub(len.saturating_sub(8), 4))
                    .value(hex(old, 32))
                    .desc("The same CRC-32C as the header with the crc32 algorithm; the legacy fold of the header with the innodb one"),
            );
            cx.emit(low_at(len.saturating_sub(4)));
        }
        Sum::FullCrc32 => {
            cx.emit(low_at(len.saturating_sub(8)));
            let stored = u32_be(page, to_usize(len.saturating_sub(4))).unwrap_or(0);
            let check = Check::new("CRC-32C", stored);
            cx.emit(
                Node::new("Checksum")
                    .span(span.sub(len.saturating_sub(4), 4))
                    .checksum(match verify(space, page) {
                        PageSum::Valid(_) => check.verified(true),
                        PageSum::Mismatch(c) => check.verify(c),
                        _ => check,
                    }),
            );
        }
    }
}

// ---------------------------------------------------------------------------
// File space header and extent descriptors

const XDES_STATES: EnumTable = &[
    (0, "not initialised"),
    (1, "free"),
    (2, "free fragment"),
    (3, "full fragment"),
    (4, "segment"),
    (5, "segment fragment"),
];

fn descriptor_page(cx: &Cx, state: &PageState, span: Span, page: &[u8], kind: u16) {
    let space = &state.space;
    let geo = space.geo;
    if kind == FSP_HDR {
        cx.emit(FspHeader::node(
            "File space header",
            span.sub(FIL_HEADER, FspHeader::SIZE),
            BE,
        ));
    } else {
        cx.emit(
            Node::new("Unused")
                .span(span.sub(FIL_HEADER, FspHeader::SIZE))
                .summary("where page 0 has the file space header"),
        );
    }
    let start = FIL_HEADER.saturating_add(FspHeader::SIZE);
    let n = geo.xdes_per_page();
    let len = n.saturating_mul(geo.xdes_size());
    let used = (0..n)
        .filter(|&i| {
            let at = to_usize(
                start
                    .saturating_add(i.saturating_mul(geo.xdes_size()))
                    .saturating_add(20),
            );
            u32_be(page, at).unwrap_or(0) != 0
        })
        .count();
    cx.emit(
        Node::new("Extent descriptors")
            .span(span.sub(start, len))
            .summary(format!(
                "{} of {} pages each, {used} initialised (listed)",
                grouped_count(n, "extent", "extents"),
                geo.pages_per_extent()
            ))
            .lazy(extents, (state.clone(), start)),
    );
    let mut end = start.saturating_add(len);
    if kind == FSP_HDR && space.server_version.is_some() {
        let info = span.sub(end, super::ENCRYPTION_INFO);
        let magic = page
            .get(to_usize(end)..to_usize(end).saturating_add(3))
            .unwrap_or_default();
        let encrypted = magic.starts_with(b"lC");
        cx.emit(
            Node::new("Encryption information")
                .span(info)
                .summary(if encrypted {
                    "master key and tablespace key"
                } else {
                    "not encrypted"
                }),
        );
        end = end.saturating_add(super::ENCRYPTION_INFO);
        if let Some(root) = space.sdi_root {
            cx.emit(
                Node::new("SDI version")
                    .span(span.sub(end, 4))
                    .value(uint(u32_be(page, to_usize(end)).unwrap_or(0), 32)),
            );
            cx.emit(link(
                "SDI root page",
                state,
                root,
                span.sub(end.saturating_add(4), 4),
            ));
            end = end.saturating_add(8);
        }
    }
    let rest = span.len.saturating_sub(geo.trailer()).saturating_sub(end);
    if rest != 0 {
        cx.emit(Node::new("Unused").span(span.sub(end, rest)));
    }
}

async fn extents(cx: Cx, (state, start): (PageState, u64)) -> Result<()> {
    let space = &state.space;
    let geo = space.geo;
    let Some(span) = space.page(state.no) else {
        return Ok(());
    };
    let page = cx.read(span).await?;
    let n = geo.xdes_per_page();
    let per = geo.pages_per_extent();
    let state_of = |i: u64| {
        let o = to_usize(start.saturating_add(i.saturating_mul(geo.xdes_size())));
        u32_be(&page, o.saturating_add(20)).unwrap_or(0)
    };
    // Extents past the free limit are not initialised: only the others
    // are listed.
    let used = (0..n).filter(|&i| state_of(i) != 0).count();
    cx.set_count(Count::Exact(to_u64(used)));
    for i in 0..n {
        if i % 256 == 0 {
            cx.checkpoint().await;
        }
        let off = start.saturating_add(i.saturating_mul(geo.xdes_size()));
        let o = to_usize(off);
        let first = u64::from(state.no).saturating_add(i.saturating_mul(per));
        let st = state_of(i);
        if st == 0 {
            continue;
        }
        let bitmap = page
            .get(o.saturating_add(24)..o.saturating_add(to_usize(geo.xdes_size())))
            .unwrap_or_default();
        let free = (0..per)
            .filter(|&p| {
                let bit = to_usize(p.saturating_mul(2));
                bitmap
                    .get(bit / 8)
                    .is_some_and(|b| b & (1 << (bit % 8)) != 0)
            })
            .count();
        let mut summary = format!(
            "pages {first}..{}: {}",
            first.saturating_add(per).saturating_sub(1),
            lookup(XDES_STATES, st.into()).unwrap_or("unknown state")
        );
        if st != 0 {
            summary.push_str(&format!(", {free} free"));
        }
        if st == 4 || st == 5 {
            summary.push_str(&format!(", segment {}", u64_be(&page, o).unwrap_or(0)));
        }
        cx.push(
            Node::new(format!("Extent {i}"))
                .span(span.sub(off, geo.xdes_size()))
                .summary(summary)
                .lazy(extent_fields, (span.sub(off, geo.xdes_size()), per)),
        )
        .await;
    }
    Ok(())
}

async fn extent_fields(cx: Cx, (span, per): (Span, u64)) -> Result<()> {
    let b = cx.read(span).await?;
    cx.emit(
        Node::new("Segment ID")
            .span(span.sub(0, 8))
            .value(uint(u64_be(&b, 0).unwrap_or(0), 64)),
    );
    cx.emit(
        Node::new("List node")
            .span(span.sub(8, 12))
            .summary(format!(
                "previous {}, next {}",
                file_addr(&b, 8),
                file_addr(&b, 14)
            )),
    );
    let st = u32_be(&b, 20).unwrap_or(0);
    cx.emit(Node::new("State").span(span.sub(20, 4)).value(Value::Enum {
        raw: st.into(),
        bits: 32,
        name: lookup(XDES_STATES, st.into()).map(Into::into),
    }));
    let bitmap = b.get(24..).unwrap_or_default();
    let free = (0..per)
        .filter(|&p| {
            let bit = to_usize(p.saturating_mul(2));
            bitmap
                .get(bit / 8)
                .is_some_and(|x| x & (1 << (bit % 8)) != 0)
        })
        .count();
    cx.emit(
        Node::new("Page bitmap")
            .span(span.tail(24))
            .value(Value::Bytes(bitmap.to_vec()))
            .summary(format!("{free} of {per} pages free"))
            .desc("Two bits per page: free, and clean (unused)"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Segment inodes

const FSEG_MAGIC: u32 = 97_937_874;

fn inode_size(space: &Space) -> u64 {
    // ID, used count, three lists, magic, half an extent of fragment pages.
    64u64.saturating_add(space.geo.pages_per_extent().saturating_mul(2))
}

fn inode_page(cx: &Cx, state: &PageState, span: Span, page: &[u8]) {
    let space = &state.space;
    cx.emit(
        Node::new("List node")
            .span(span.sub(FIL_HEADER, 12))
            .summary(format!(
                "previous {}, next {}",
                file_addr(page, 38),
                file_addr(page, 44)
            ))
            .desc("Links the page into the space's full or free inode page list"),
    );
    let size_each = inode_size(space);
    let start = FIL_HEADER.saturating_add(12);
    let room = span
        .len
        .saturating_sub(start)
        .saturating_sub(space.geo.trailer());
    let n = room.checked_div(size_each).unwrap_or(0);
    let used = (0..n)
        .filter(|&i| {
            let o = to_usize(start.saturating_add(i.saturating_mul(size_each)));
            u64_be(page, o).unwrap_or(0) != 0
        })
        .count();
    cx.emit(
        Node::new("Inodes")
            .span(span.sub(start, n.saturating_mul(size_each)))
            .summary(format!("{used} of {n} slots used (listed)"))
            .lazy(inodes, (state.clone(), start, n)),
    );
    let end = start.saturating_add(n.saturating_mul(size_each));
    let rest = room.saturating_sub(n.saturating_mul(size_each));
    if rest != 0 {
        cx.emit(Node::new("Unused").span(span.sub(end, rest)));
    }
}

async fn inodes(cx: Cx, (state, start, n): (PageState, u64, u64)) -> Result<()> {
    let space = &state.space;
    let Some(span) = space.page(state.no) else {
        return Ok(());
    };
    let page = cx.read(span).await?;
    let size_each = inode_size(space);
    let id_of = |i: u64| {
        u64_be(
            &page,
            to_usize(start.saturating_add(i.saturating_mul(size_each))),
        )
        .unwrap_or(0)
    };
    // Only the slots in use (with a segment ID) are listed.
    let used = (0..n).filter(|&i| id_of(i) != 0).count();
    cx.set_count(Count::Exact(to_u64(used)));
    for i in 0..n {
        let off = start.saturating_add(i.saturating_mul(size_each));
        let o = to_usize(off);
        let id = id_of(i);
        let ispan = span.sub(off, size_each);
        let mut node = Node::new(format!("Inode {i}")).span(ispan);
        if id == 0 {
            continue;
        } else {
            let frags = (0..space.geo.pages_per_extent() / 2)
                .filter(|&k| {
                    let at = o
                        .saturating_add(64)
                        .saturating_add(to_usize(k.saturating_mul(4)));
                    u32_be(&page, at).is_some_and(|p| p != FIL_NULL)
                })
                .count();
            let extents: u32 = [12usize, 28, 44]
                .iter()
                .map(|&l| u32_be(&page, o.saturating_add(l)).unwrap_or(0))
                .fold(0, u32::saturating_add);
            node = node
                .summary(format!(
                    "segment {id}: {extents_extent}, {frags} fragment pages",
                    extents_extent = plural(extents, "extent")
                ))
                .lazy(inode_fields, (state.clone(), off));
            if u32_be(&page, o.saturating_add(60)) != Some(FSEG_MAGIC) {
                node = node.diag(Diagnostic::malformed("bad inode magic number"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn inode_fields(cx: Cx, (state, off): (PageState, u64)) -> Result<()> {
    let space = &state.space;
    let Some(page_span) = space.page(state.no) else {
        return Ok(());
    };
    let span = page_span.sub(off, inode_size(space));
    let b = cx.read(span).await?;
    cx.emit(
        Node::new("Segment ID")
            .span(span.sub(0, 8))
            .value(uint(u64_be(&b, 0).unwrap_or(0), 64)),
    );
    cx.emit(
        Node::new("Used pages in partly full extents")
            .span(span.sub(8, 4))
            .value(uint(u32_be(&b, 8).unwrap_or(0), 32)),
    );
    for (name, at) in [
        ("Free extents", 12u64),
        ("Partly full extents", 28),
        ("Full extents", 44),
    ] {
        cx.emit(
            Node::new(name)
                .span(span.sub(at, 16))
                .summary(list_base(b.get(to_usize(at)..).unwrap_or_default())),
        );
    }
    let magic = u32_be(&b, 60).unwrap_or(0);
    let mut m = Node::new("Magic")
        .span(span.sub(60, 4))
        .value(uint(magic, 32));
    if magic != FSEG_MAGIC {
        m = m.diag(Diagnostic::malformed(format!("expected {FSEG_MAGIC}")));
    }
    cx.emit(m);
    let slots = space.geo.pages_per_extent() / 2;
    let used: Vec<String> = (0..slots)
        .filter_map(|k| u32_be(&b, to_usize(64u64.saturating_add(k.saturating_mul(4)))))
        .filter(|&p| p != FIL_NULL)
        .map(|p| p.to_string())
        .collect();
    cx.emit(
        Node::new("Fragment pages")
            .span(span.sub(64, slots.saturating_mul(4)))
            .summary(if used.is_empty() {
                "none".to_owned()
            } else {
                used.join(", ")
            })
            .desc("Single pages the segment holds before it is given whole extents"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Other page types

fn bitmap_page(cx: &Cx, space: &Space, span: Span) {
    // Four bits per page of the descriptor range, after the FIL header and
    // a page header's worth of space.
    let start = 94u64;
    let len = space.geo.phys / 2;
    cx.emit(Node::new("Unused").span(span.sub(FIL_HEADER, start.saturating_sub(FIL_HEADER))));
    cx.emit(
        Node::new("Change buffer bitmap")
            .span(span.sub(start, len))
            .summary(format!(
                "4 bits for each of {}",
                grouped_count(space.geo.phys, "page", "pages")
            ))
            .desc("Per page: free space class (2 bits), buffered changes exist, page belongs to the change buffer"),
    );
    let end = start.saturating_add(len);
    let rest = span
        .len
        .saturating_sub(space.geo.trailer())
        .saturating_sub(end);
    if rest != 0 {
        cx.emit(Node::new("Unused").span(span.sub(end, rest)));
    }
}

const BINLOG_MAGIC: u32 = 873_422_344;
const DOUBLEWRITE_MAGIC: u32 = 536_853_855;
const DOUBLEWRITE_SPACE_IDS: u32 = 1_783_657_386;

fn trx_sys_page(cx: &Cx, space: &Space, span: Span, page: &[u8]) {
    let at = |o: u64, n: u64| span.sub(o, n);
    cx.emit(
        Node::new("Maximum transaction ID")
            .span(at(38, 8))
            .value(uint(u64_be(page, 38).unwrap_or(0), 64))
            .desc("Transaction IDs are allocated above this (written every 256 transactions)"),
    );
    cx.emit(
        Node::new("Segment header")
            .span(at(46, 10))
            .summary(fseg_header(page.get(46..).unwrap_or_default())),
    );
    let slots: Vec<String> = (0..128usize)
        .filter_map(|i| {
            let o = 56usize.saturating_add(i.saturating_mul(8));
            let page_no = u32_be(page, o.saturating_add(4))?;
            (page_no != FIL_NULL)
                .then(|| format!("{i}: space {} page {page_no}", u32_be(page, o).unwrap_or(0)))
        })
        .collect();
    cx.emit(
        Node::new("Rollback segment slots")
            .span(at(56, 128 * 8))
            .summary(if slots.is_empty() {
                "none".to_owned()
            } else {
                slots.join(", ")
            }),
    );
    let len = span.len;
    let binlog = len.saturating_sub(1000);
    let b = to_usize(binlog);
    if u32_be(page, b) == Some(BINLOG_MAGIC) {
        let name = crate::text::until_nul(
            page.get(b.saturating_add(12)..b.saturating_add(524))
                .unwrap_or_default(),
        );
        let offset = u32_be(page, b.saturating_add(4))
            .map(u64::from)
            .unwrap_or(0)
            .wrapping_shl(32)
            | u64::from(u32_be(page, b.saturating_add(8)).unwrap_or(0));
        cx.emit(
            Node::new("Binary log position")
                .span(at(binlog, 524))
                .value(text(name.clone()))
                .summary(format!("{name} at {offset}"))
                .desc("The binary log position of the last committed transaction"),
        );
    }
    let dw = len.saturating_sub(200);
    let d = to_usize(dw);
    if u32_be(page, d.saturating_add(10)) == Some(DOUBLEWRITE_MAGIC) {
        let b1 = u32_be(page, d.saturating_add(14)).unwrap_or(0);
        let b2 = u32_be(page, d.saturating_add(18)).unwrap_or(0);
        let mut n = Node::new("Doublewrite buffer")
            .span(at(dw, 34))
            .summary(format!(
                "blocks at pages {b1} and {b2}, {} each",
                plural(space.geo.pages_per_extent(), "page")
            ))
            .desc("Pages are written here first so a torn write can be repaired (MySQL 8.0.20 moved it to #ib_*.dblwr files)");
        if u32_be(page, d.saturating_add(30)) == Some(DOUBLEWRITE_SPACE_IDS) {
            n = n.diag(Diagnostic::note("pages in it carry their space IDs"));
        }
        cx.emit(n);
    }
}

fn sys_page(cx: &Cx, state: &PageState, span: Span, page: &[u8]) {
    let space = &state.space;
    let at = |o: u64, n: u64| span.sub(o, n);
    let u32_at = |o: usize| u32_be(page, o).unwrap_or(0);
    if space.space_id == 0 && state.no == 7 {
        // The data dictionary header.
        for (name, o) in [
            ("Next row ID", 38u64),
            ("Next table ID", 46),
            ("Next index ID", 54),
        ] {
            cx.emit(
                Node::new(name)
                    .span(at(o, 8))
                    .value(uint(u64_be(page, to_usize(o)).unwrap_or(0), 64)),
            );
        }
        cx.emit(
            Node::new("Largest space ID")
                .span(at(62, 4))
                .value(uint(u32_at(62), 32)),
        );
        cx.emit(Node::new("Unused").span(at(66, 4)));
        for (name, o) in [
            ("SYS_TABLES root", 70u64),
            ("SYS_TABLE_IDS root", 74),
            ("SYS_COLUMNS root", 78),
            ("SYS_INDEXES root", 82),
            ("SYS_FIELDS root", 86),
        ] {
            let no = u32_at(to_usize(o));
            cx.emit(if no == 0 {
                Node::new(name)
                    .span(at(o, 4))
                    .value(uint(no, 32))
                    .summary("none")
            } else {
                link(name, state, no, at(o, 4))
            });
        }
        cx.emit(
            Node::new("Segment header")
                .span(at(94, 10))
                .summary(fseg_header(page.get(94..).unwrap_or_default())),
        );
        return;
    }
    // A rollback segment header: the segment's inode is in this space and
    // the undo slots name pages of it (or none).
    let slots = space.geo.phys / 16;
    let slots_end = 72u64.saturating_add(slots.saturating_mul(4));
    let plausible = u32_at(62) == space.space_id
        && u32_at(38) != 0
        && slots_end <= span.len
        && (0..slots).all(|i| {
            let p = u32_at(to_usize(72u64.saturating_add(i.saturating_mul(4))));
            p == FIL_NULL || u64::from(p) < space.pages.max(space.declared)
        });
    if plausible {
        cx.emit(
            Node::new("Maximum size")
                .span(at(38, 4))
                .value(uint(u32_at(38), 32))
                .desc("Pages the rollback segment may use"),
        );
        cx.emit(
            Node::new("History size")
                .span(at(42, 4))
                .value(uint(u32_at(42), 32))
                .desc("Pages of committed undo logs waiting to be purged"),
        );
        cx.emit(
            Node::new("History list")
                .span(at(46, 16))
                .summary(list_base(page.get(46..).unwrap_or_default())),
        );
        cx.emit(
            Node::new("Segment header")
                .span(at(62, 10))
                .summary(fseg_header(page.get(62..).unwrap_or_default())),
        );
        let used: Vec<String> = (0..slots)
            .filter_map(|i| {
                let p = u32_at(to_usize(72u64.saturating_add(i.saturating_mul(4))));
                (p != FIL_NULL).then(|| format!("{i}: page {p}"))
            })
            .collect();
        cx.emit(
            Node::new("Undo slots")
                .span(at(72, slots.saturating_mul(4)))
                .summary(if used.is_empty() {
                    format!(
                        "{slots_slot}, none in use",
                        slots_slot = plural(slots, "slot")
                    )
                } else {
                    used.join(", ")
                }),
        );
        let rest = span
            .len
            .saturating_sub(space.geo.trailer())
            .saturating_sub(slots_end);
        cx.emit(
            Node::new("Rollback segment header")
                .span(at(38, slots_end.saturating_sub(38)))
                .summary("history list, segment and undo log slots"),
        );
        if rest != 0 {
            cx.emit(Node::new("Unused").span(at(slots_end, rest)));
        }
        return;
    }
    cx.emit(
        Node::new("System data")
            .span(at(
                38,
                span.len
                    .saturating_sub(38)
                    .saturating_sub(space.geo.trailer()),
            ))
            .summary("system page"),
    );
}

const UNDO_TYPES: EnumTable = &[(1, "insert"), (2, "update")];

fn undo_page(cx: &Cx, space: &Space, span: Span, page: &[u8]) {
    let at = |o: u64, n: u64| span.sub(o, n);
    let u16_at = |o: usize| u16_be(page, o).unwrap_or(0);
    let kind = u16_at(38);
    cx.emit(Node::new("Undo type").span(at(38, 2)).value(Value::Enum {
        raw: kind.into(),
        bits: 16,
        name: lookup(UNDO_TYPES, kind.into()).map(Into::into),
    }));
    let start = u16_at(40);
    let free = u16_at(42);
    cx.emit(
        Node::new("First record")
            .span(at(40, 2))
            .value(hex(start, 16))
            .desc("Offset of the first undo record of the latest log on this page"),
    );
    cx.emit(
        Node::new("Free offset")
            .span(at(42, 2))
            .value(hex(free, 16))
            .desc("Where the next undo record goes"),
    );
    cx.emit(Node::new("List node").span(at(44, 12)).summary(format!(
        "previous {}, next {}",
        file_addr(page, 44),
        file_addr(page, 50)
    )));
    let end = span.len.saturating_sub(space.geo.trailer());
    let free = u64::from(free).clamp(56, end);
    if free > 56 {
        cx.emit(
            Node::new("Undo log data")
                .span(at(56, free.saturating_sub(56)))
                .summary("segment and log headers, undo records"),
        );
    }
    if end > free {
        cx.emit(Node::new("Free space").span(at(free, end.saturating_sub(free))));
    }
}

fn rseg_array_page(cx: &Cx, state: &PageState, span: Span, page: &[u8]) {
    let space = &state.space;
    let at = |o: u64, n: u64| span.sub(o, n);
    cx.emit(Node::new("Magic").span(at(38, 4)).value(text(
        String::from_utf8_lossy(page.get(38..42).unwrap_or_default()).into_owned(),
    )));
    cx.emit(
        Node::new("Size")
            .span(at(42, 4))
            .value(uint(u32_be(page, 42).unwrap_or(0), 32)),
    );
    cx.emit(
        Node::new("Segment header")
            .span(at(46, 10))
            .summary(fseg_header(page.get(46..).unwrap_or_default())),
    );
    let mut n = 0u64;
    while n < 128 {
        let o = 56u64.saturating_add(n.saturating_mul(4));
        match u32_be(page, to_usize(o)) {
            Some(p) if p != FIL_NULL && p != 0 => n = n.saturating_add(1),
            _ => break,
        }
    }
    cx.emit(
        Node::new("Rollback segment pages")
            .span(at(56, n.saturating_mul(4)))
            .summary(grouped_count(n, "rollback segment", "rollback segments"))
            .lazy(rseg_slots, (state.clone(), n)),
    );
    let end = 56u64.saturating_add(n.saturating_mul(4));
    let rest = span
        .len
        .saturating_sub(space.geo.trailer())
        .saturating_sub(end);
    if rest != 0 {
        cx.emit(Node::new("Unused").span(at(end, rest)));
    }
}

async fn rseg_slots(cx: Cx, (state, n): (PageState, u64)) -> Result<()> {
    let Some(span) = state.space.page(state.no) else {
        return Ok(());
    };
    let b = cx.read(span.sub(56, n.saturating_mul(4))).await?;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let no = u32_be(&b, to_usize(i.saturating_mul(4))).unwrap_or(0);
        cx.push(
            link(
                "Rollback segment",
                &state,
                no,
                span.sub(56u64.saturating_add(i.saturating_mul(4)), 4),
            )
            .renamed(format!("Rollback segment {i}")),
        )
        .await;
    }
    Ok(())
}

/// Old-style BLOB pages: part length, next page, data.
fn blob_page(cx: &Cx, state: &PageState, span: Span, page: &[u8]) {
    let space = &state.space;
    let at = |o: u64, n: u64| span.sub(o, n);
    let part = u32_be(page, 38).unwrap_or(0);
    let next = u32_be(page, 42).unwrap_or(FIL_NULL);
    cx.emit(
        Node::new("Part length")
            .span(at(38, 4))
            .value(uint(part, 32)),
    );
    cx.emit(link("Next page", state, next, at(42, 4)));
    let room = span
        .len
        .saturating_sub(46)
        .saturating_sub(space.geo.trailer());
    let len = u64::from(part).min(room);
    let mut data = Node::new("Data").span(at(46, len)).summary(size(len));
    if u64::from(part) > room {
        data = data.diag(Diagnostic::malformed(format!(
            "part length {part} is larger than the page"
        )));
    }
    cx.emit(data);
    if room > len {
        cx.emit(Node::new("Unused").span(at(46u64.saturating_add(len), room.saturating_sub(len))));
    }
}

/// MySQL 8 LOB pages: first page (header, index entries, data), data
/// pages and index pages.
fn lob_page(cx: &Cx, space: &Space, span: Span, page: &[u8], kind: u16) {
    let at = |o: u64, n: u64| span.sub(o, n);
    let end = span.len.saturating_sub(space.geo.trailer());
    cx.emit(
        Node::new("Version")
            .span(at(38, 1))
            .value(uint(page.get(38).copied().unwrap_or(0), 8)),
    );
    let (entries_at, entries, data_at) = match kind {
        LOB_FIRST => {
            cx.emit(
                Node::new("Flags")
                    .span(at(39, 1))
                    .value(hex(page.get(39).copied().unwrap_or(0), 8)),
            );
            cx.emit(
                Node::new("LOB version")
                    .span(at(40, 4))
                    .value(uint(u32_be(page, 40).unwrap_or(0), 32)),
            );
            cx.emit(Node::new("Last transaction ID").span(at(44, 6)));
            cx.emit(
                Node::new("Last undo number")
                    .span(at(50, 4))
                    .value(uint(u32_be(page, 50).unwrap_or(0), 32)),
            );
            cx.emit(
                Node::new("Data length")
                    .span(at(54, 4))
                    .value(uint(u32_be(page, 54).unwrap_or(0), 32)),
            );
            cx.emit(Node::new("Transaction ID").span(at(58, 6)));
            cx.emit(
                Node::new("Index list")
                    .span(at(64, 16))
                    .summary(list_base(page.get(64..).unwrap_or_default())),
            );
            cx.emit(
                Node::new("Free list")
                    .span(at(80, 16))
                    .summary(list_base(page.get(80..).unwrap_or_default())),
            );
            (96u64, 10u64, 96u64 + 600)
        }
        LOB_INDEX => {
            cx.emit(
                Node::new("Data length")
                    .span(at(39, 4))
                    .value(uint(u32_be(page, 39).unwrap_or(0), 32)),
            );
            cx.emit(Node::new("Transaction ID").span(at(43, 6)));
            let n = end.saturating_sub(49) / 60;
            (49u64, n, 49u64.saturating_add(n.saturating_mul(60)))
        }
        _ => {
            cx.emit(
                Node::new("Data length")
                    .span(at(39, 4))
                    .value(uint(u32_be(page, 39).unwrap_or(0), 32)),
            );
            cx.emit(Node::new("Transaction ID").span(at(43, 6)));
            (49u64, 0, 49u64)
        }
    };
    if entries != 0 {
        let list: Vec<String> = (0..entries)
            .filter_map(|i| {
                let o = to_usize(entries_at.saturating_add(i.saturating_mul(60)));
                let no = u32_be(page, o.saturating_add(48))?;
                let len = u16_be(page, o.saturating_add(52))?;
                (len != 0).then(|| format!("page {no}: {len} bytes"))
            })
            .collect();
        cx.emit(
            Node::new("Index entries")
                .span(at(entries_at, entries.saturating_mul(60)))
                .summary(if list.is_empty() {
                    format!(
                        "{entries_slot}, none used",
                        entries_slot = plural(entries, "slot")
                    )
                } else {
                    list.join(", ")
                }),
        );
    }
    let data_len = match kind {
        LOB_FIRST => u64::from(u32_be(page, 54).unwrap_or(0)),
        LOB_DATA => u64::from(u32_be(page, 39).unwrap_or(0)),
        _ => 0,
    };
    let room = end.saturating_sub(data_at);
    let len = data_len.min(room);
    if len != 0 {
        cx.emit(Node::new("Data").span(at(data_at, len)).summary(size(len)));
    }
    if room > len {
        cx.emit(
            Node::new("Unused").span(at(data_at.saturating_add(len), room.saturating_sub(len))),
        );
    }
}
