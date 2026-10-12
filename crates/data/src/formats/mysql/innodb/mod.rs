//! InnoDB tablespaces: file-per-table `.ibd` files, the system tablespace
//! (`ibdata1`), MySQL 8's data dictionary tablespace (`mysql.ibd`), undo
//! (`undo_001`, `.ibu`) and temporary tablespaces, as MySQL and MariaDB
//! write them.
//!
//! A tablespace is an array of pages (4 to 64 KiB; 1 to 16 KiB on disk for
//! compressed tables). Page 0 holds the file space header with the
//! tablespace's flags (page size, row format features, MariaDB's
//! `full_crc32`), from which the geometry follows. Every page has a 38-byte
//! FIL header (checksum, page number, sibling links, LSN, type, space ID)
//! and, except compressed pages, an 8-byte trailer; checksums are verified
//! (CRC-32C as MySQL 5.7+ and MariaDB write them, MariaDB's `full_crc32`,
//! compressed pages' CRC-32C variant, and the legacy InnoDB fold).
//!
//! MySQL 8 stores the table definitions in the tablespace itself, as
//! zlib-compressed JSON in an SDI B-tree whose root page 0 names. Those are
//! decoded (`dict`) and used to split records into typed columns; without
//! them (MariaDB, MySQL 5.7) records of the redundant format still split
//! into fields, compact ones show their header and data.
//!
//! Expanding the file reads page 0 and the dictionary; everything else is
//! lazy: the index B-trees from their roots, and every page by number
//! (`page`, `index`).

mod dict;
mod index;
mod page;

use std::sync::Arc;

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::fmt::{grouped_count, size};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

pub(crate) const BE: Endian = Endian::Big;
/// The FIL header.
pub(crate) const FIL_HEADER: u64 = 38;
/// The FIL trailer (old-style checksum and low LSN bits).
pub(crate) const FIL_TRAILER: u64 = 8;
/// "No page".
pub(crate) const FIL_NULL: u32 = 0xffff_ffff;
/// Where the SDI header sits after the extent descriptors on page 0: the
/// encryption information comes first (`Encryption::INFO_MAX_SIZE`).
const ENCRYPTION_INFO: u64 = 115;

pub static FORMAT: Format = Format {
    name: "innodb",
    title: "InnoDB tablespace",
    extensions: &["ibd", "ibu", "ibt"],
    mime: "application/x-innodb-tablespace",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Page 0 of a tablespace: page number 0, the file space header type,
/// the same space ID in the FIL header and the file space header, flags
/// that give a page size, and a trailer that repeats the LSN.
fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(no), Some(kind), Some(space), Some(fsp_space), Some(flags), Some(pages)) = (
        u32_be(d, 4),
        u16_be(d, 24),
        u32_be(d, 34),
        u32_be(d, 38),
        u32_be(d, 54),
        u32_be(d, 46),
    ) else {
        return false;
    };
    if no != 0 || kind != page::FSP_HDR || space != fsp_space || pages == 0 {
        return false;
    }
    let Some(geo) = Geometry::from_flags(flags) else {
        return false;
    };
    let lsn = u32_be(d, 20);
    let end = crate::bytes::to_usize(geo.phys);
    match geo.sum {
        Sum::Classic => lsn.is_some() && u32_be(d, end.saturating_sub(4)) == lsn,
        Sum::FullCrc32 => lsn.is_some() && u32_be(d, end.saturating_sub(8)) == lsn,
        // No trailer: the page's own checksum (or the "none" magic).
        Sum::Zip => d.get(..end).is_some_and(|page| {
            let stored = u32_be(page, 0);
            stored == Some(0xdead_beef) || stored == Some(page::zip_checksum(page))
        }),
    }
}

/// How pages are checksummed and whether they have a trailer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Sum {
    /// CRC-32C (or the legacy fold) in the header and the trailer.
    Classic,
    /// MariaDB's `full_crc32`: a CRC-32C of the whole page at its end.
    FullCrc32,
    /// Compressed tablespaces: no trailer, a CRC-32C variant in the header.
    Zip,
}

#[derive(Clone, Copy, Debug)]
pub(crate) struct Geometry {
    /// Bytes per page on disk.
    pub phys: u64,
    /// Bytes per page in memory (the server's page size).
    pub logical: u64,
    pub sum: Sum,
}

impl Geometry {
    /// The geometry the file space header's flags give (MySQL's layout,
    /// shared by MariaDB's original one, or MariaDB's `full_crc32`).
    pub fn from_flags(flags: u32) -> Option<Geometry> {
        if flags & 0x10 != 0 {
            // MariaDB full_crc32: bit 4 is the marker (a MySQL compressed
            // page size never sets it), bits 0-3 the page size.
            let ssize = flags & 0xf;
            let size = (3..=7).contains(&ssize).then(|| 512u64 << ssize)?;
            return Some(Geometry {
                phys: size,
                logical: size,
                sum: Sum::FullCrc32,
            });
        }
        let zip = (flags >> 1) & 0xf;
        let page = (flags >> 6) & 0xf;
        let logical = match page {
            0 => 16384,
            3..=7 => 512u64 << page,
            _ => return None,
        };
        match zip {
            0 => Some(Geometry {
                phys: logical,
                logical,
                sum: Sum::Classic,
            }),
            1..=5 => {
                let phys = 512u64 << zip;
                (phys <= logical).then_some(Geometry {
                    phys,
                    logical,
                    sum: Sum::Zip,
                })
            }
            _ => None,
        }
    }

    /// Pages per extent: 1 MiB for pages up to 16 KiB, 64 pages above.
    pub fn pages_per_extent(&self) -> u64 {
        match self.logical {
            4096 => 256,
            8192 => 128,
            _ => 64,
        }
    }

    /// Bytes per extent descriptor: segment ID, list node, state and two
    /// bits per page.
    pub fn xdes_size(&self) -> u64 {
        24u64.saturating_add(self.pages_per_extent() / 4)
    }

    /// Extent descriptors per descriptor page (each describes as many
    /// pages as a page has bytes).
    pub fn xdes_per_page(&self) -> u64 {
        self.phys.checked_div(self.pages_per_extent()).unwrap_or(0)
    }

    pub fn trailer(&self) -> u64 {
        match self.sum {
            Sum::Zip => 0,
            _ => FIL_TRAILER,
        }
    }
}

/// What every expansion knows about the tablespace.
pub(crate) struct Space {
    pub input: Input,
    pub geo: Geometry,
    /// Whole pages in the file.
    pub pages: u64,
    /// Pages the file space header says the tablespace has.
    pub declared: u64,
    pub space_id: u32,
    /// MySQL 8 records the server version on page 0.
    pub server_version: Option<u32>,
    /// The SDI B-tree's root page (MySQL 8).
    pub sdi_root: Option<u32>,
}

pub(crate) type SpaceRef = Arc<Space>;

impl Space {
    /// The span of page `no`, if the file holds it.
    pub fn page(&self, no: u32) -> Option<Span> {
        (u64::from(no) < self.pages).then(|| {
            self.input
                .span
                .sub(u64::from(no).saturating_mul(self.geo.phys), self.geo.phys)
        })
    }
}

pub(crate) fn mysql_version(v: u32) -> String {
    format!("{}.{}.{}", v / 10000, v / 100 % 100, v % 100)
}

/// What a tablespace ID says about the tablespace.
fn space_kind(space: &Space) -> Option<&'static str> {
    match space.space_id {
        0 => Some("system tablespace"),
        0xffff_fffe if space.server_version.is_some() => Some("data dictionary tablespace"),
        0xffff_fffd => Some("temporary tablespace"),
        0xffff_0000..=0xffff_ffef if space.server_version.is_some() => Some("undo tablespace"),
        _ => None,
    }
}

/// A human reading of the tablespace flags.
pub(crate) fn describe_flags(flags: u32) -> String {
    let Some(geo) = Geometry::from_flags(flags) else {
        return "unknown page size".to_owned();
    };
    let mut parts = vec![format!("{} pages", size(geo.logical))];
    if geo.sum == Sum::FullCrc32 {
        parts.push("full_crc32".to_owned());
        let algorithm = (flags >> 5) & 7;
        if algorithm != 0 {
            parts.push(format!("page compression {}", algorithm_name(algorithm)));
        }
        return parts.join(", ");
    }
    if geo.sum == Sum::Zip {
        parts.push(format!("compressed to {}", size(geo.phys)));
    }
    let flag = |bit: u32| flags & (1 << bit) != 0;
    if flag(0) {
        parts.push("post-Antelope".to_owned());
    }
    if flag(5) {
        parts.push("atomic BLOBs".to_owned());
    }
    if flag(10) {
        parts.push("DATA DIRECTORY".to_owned());
    }
    if flag(11) {
        parts.push("shared".to_owned());
    }
    if flag(12) {
        parts.push("temporary".to_owned());
    }
    if flag(13) {
        parts.push("encrypted".to_owned());
    }
    if flag(14) {
        parts.push("SDI".to_owned());
    }
    parts.join(", ")
}

/// MariaDB's page compression algorithms.
fn algorithm_name(n: u32) -> &'static str {
    match n {
        1 => "zlib",
        2 => "LZ4",
        3 => "LZO",
        4 => "LZMA",
        5 => "bzip2",
        6 => "Snappy",
        _ => "unknown",
    }
}

/// A list base node: length, first and last entry.
pub(crate) fn list_base(b: &[u8]) -> String {
    let len = u32_be(b, 0).unwrap_or(0);
    if len == 0 {
        return "empty".to_owned();
    }
    format!(
        "{len} entries, first at {}, last at {}",
        file_addr(b, 4),
        file_addr(b, 10)
    )
}

/// A file address (page number and byte offset).
pub(crate) fn file_addr(b: &[u8], at: usize) -> String {
    match (u32_be(b, at), u16_be(b, at.saturating_add(4))) {
        (Some(FIL_NULL), _) => "none".to_owned(),
        (Some(page), Some(offset)) => format!("page {page}:{offset:#x}"),
        _ => "?".to_owned(),
    }
}

/// A segment header: the inode of a file segment.
pub(crate) fn fseg_header(b: &[u8]) -> String {
    match (u32_be(b, 0), u32_be(b, 4), u16_be(b, 8)) {
        (Some(space), Some(page), Some(offset)) => {
            format!("inode in space {space}, page {page}:{offset:#x}")
        }
        _ => "?".to_owned(),
    }
}

record! {
    /// The file space header, on page 0 after the FIL header.
    pub struct FspHeader {
        space_id: u32 "Space ID",
        _unused: u32 "Unused",
        size: u32 "Size" .desc("Pages in the tablespace, as allocated"),
        free_limit: u32 "Free limit"
            .desc("Pages below this have been initialised; extents above it are free"),
        flags: u32 "Flags" .hex() .with(|&v, n| n.summary(describe_flags(v))),
        frag_n_used: u32 "Fragment pages used"
            .desc("Used pages in the extents on the partly free fragment list"),
        free: bytes[16] "Free extents" .with(|v, n| n.summary(list_base(v))),
        free_frag: bytes[16] "Partly free fragment extents" .with(|v, n| n.summary(list_base(v))),
        full_frag: bytes[16] "Full fragment extents" .with(|v, n| n.summary(list_base(v))),
        next_segment: u64 "Next segment ID",
        inodes_full: bytes[16] "Full inode pages" .with(|v, n| n.summary(list_base(v))),
        inodes_free: bytes[16] "Inode pages with free slots" .with(|v, n| n.summary(list_base(v))),
    }
}

pub(crate) const PAGE_TYPES: EnumTable = &[
    (0, "allocated"),
    (2, "undo log"),
    (3, "file segment inodes"),
    (4, "change buffer free list"),
    (5, "change buffer bitmap"),
    (6, "system"),
    (7, "transaction system"),
    (8, "file space header"),
    (9, "extent descriptors"),
    (10, "BLOB"),
    (11, "compressed BLOB"),
    (12, "compressed BLOB (later part)"),
    (13, "unknown"),
    (14, "compressed"),
    (15, "encrypted"),
    (16, "compressed and encrypted"),
    (17, "encrypted R-tree"),
    (18, "SDI BLOB"),
    (19, "compressed SDI BLOB"),
    (20, "legacy doublewrite"),
    (21, "rollback segment array"),
    (22, "LOB index"),
    (23, "LOB data"),
    (24, "LOB first page"),
    (25, "compressed LOB first page"),
    (26, "compressed LOB data"),
    (27, "compressed LOB index"),
    (28, "compressed LOB fragment"),
    (29, "compressed LOB fragment index"),
    (17853, "SDI index"),
    (17854, "R-tree index"),
    (17855, "B-tree index"),
    (34354, "page-compressed"),
    (37401, "page-compressed and encrypted"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx
        .read(file.sub(0, FIL_HEADER.saturating_add(FspHeader::SIZE)))
        .await?;
    let flags = u32_be(&head, 54).unwrap_or(0);
    let geo = Geometry::from_flags(flags).ok_or_else(|| {
        Diagnostic::malformed(format!("tablespace flags {flags:#x} give no page size"))
            .at(file.sub(54, 4))
    })?;
    let pages = file.len.checked_div(geo.phys).unwrap_or(0);
    let space_id = u32_be(&head, 34).unwrap_or(0);
    let declared = u32_be(&head, 46).unwrap_or(0);
    let server_version = u32_be(&head, 8).filter(|v| (50000..1_000_000).contains(v));
    let mut space = Space {
        input,
        geo,
        pages,
        declared: declared.into(),
        space_id,
        server_version,
        sdi_root: None,
    };
    let sdi_at = FIL_HEADER
        .saturating_add(FspHeader::SIZE)
        .saturating_add(geo.xdes_per_page().saturating_mul(geo.xdes_size()))
        .saturating_add(ENCRYPTION_INFO);
    if server_version.is_some() && sdi_at.saturating_add(8) <= geo.phys {
        let b = cx.read(file.sub(sdi_at, 8)).await?;
        if u32_be(&b, 0) == Some(1) {
            space.sdi_root = u32_be(&b, 4).filter(|&r| r != 0 && u64::from(r) < pages);
        }
    }
    let space: SpaceRef = Arc::new(space);

    cx.emit(FspHeader::node(
        "File space header",
        file.sub(FIL_HEADER, FspHeader::SIZE),
        BE,
    ));
    let dictionary = match space.sdi_root {
        Some(_) => Some(dict::load(&cx, &space).await),
        None => None,
    };
    if let (Some(root), Some(d)) = (
        space.sdi_root,
        dictionary.as_ref().filter(|d| d.objects != 0),
    ) {
        cx.emit(
            Node::new("Serialized dictionary (SDI)")
                .summary(format!(
                    "{}, root page {root}",
                    grouped_count(d.objects, "object", "objects")
                ))
                .desc("MySQL 8 keeps the definitions of the tablespace's tables in it, as JSON")
                .lazy(dict::sdi_objects, space.clone()),
        );
        cx.emit(
            Node::new("Indexes")
                .summary(grouped_count(
                    crate::bytes::to_u64(d.indexes.len()),
                    "index",
                    "indexes",
                ))
                .desc("The B-trees of the tables' indexes, from their root pages")
                .lazy(dict::index_list, space.clone()),
        );
    }
    let mut node = Node::new("Pages")
        .span(file.sub(0, pages.saturating_mul(geo.phys)))
        .summary(format!(
            "{} of {}",
            grouped_count(pages, "page", "pages"),
            size(geo.phys)
        ))
        .lazy(pages_list, space.clone());
    if u64::from(declared) > pages {
        node = node.diag(Diagnostic::truncated(
            Span::new(
                file.source,
                file.offset,
                u64::from(declared).saturating_mul(geo.phys),
            ),
            file.len,
        ));
    }
    cx.emit(node);
    let rest = file.len.checked_rem(geo.phys).unwrap_or(0);
    if rest != 0 {
        cx.emit(
            Node::new("Trailing bytes")
                .span(file.tail(pages.saturating_mul(geo.phys)))
                .diag(Diagnostic::warning(format!(
                    "{rest} bytes after the last whole page"
                ))),
        );
    }

    let mut summary = format!("InnoDB {}", space_kind(&space).unwrap_or("tablespace"));
    if let Some(name) = dictionary.as_ref().and_then(|d| d.space_name.clone()) {
        summary.push_str(&format!(" {name}"));
    }
    summary.push_str(&format!(
        " (space {space_id}), {}, {}",
        grouped_count(pages, "page", "pages"),
        describe_flags(flags)
    ));
    if let Some(v) = server_version {
        summary.push_str(&format!(", MySQL {}", mysql_version(v)));
    } else if geo.sum == Sum::FullCrc32 {
        summary.push_str(", MariaDB");
    }
    cx.annotate(summary);
    Ok(())
}

/// Every page by number, with its type.
async fn pages_list(cx: Cx, space: SpaceRef) -> Result<()> {
    cx.set_count(Count::Exact(space.pages));
    let names = match space.sdi_root {
        Some(_) => Some(dict::load(&cx, &space).await),
        None => None,
    };
    let start = cx.resume::<u64>().unwrap_or(0);
    for n in start..space.pages {
        let Ok(no) = u32::try_from(n) else {
            break;
        };
        cx.mark(move || n);
        let Some(span) = space.page(no) else {
            break;
        };
        let summary = if cx.skipping() {
            String::new()
        } else {
            let head = cx.read(span.sub(0, page::SUMMARY_BYTES)).await?;
            page::summary(&space, no, &head, names.as_deref())
        };
        cx.push(
            page::node(&space, format!("Page {no}"), no, Arc::new(Vec::new())).summary(summary),
        )
        .await;
    }
    Ok(())
}
