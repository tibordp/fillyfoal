//! Microsoft SQL Server database files: data files (`.mdf`, the primary
//! file, and `.ndf`, secondary ones) and transaction logs (`.ldf`).
//!
//! Data files are arrays of 8 KiB pages, each with a 96-byte header (type,
//! the page's own file and page number, sibling links, slot count, free
//! space, LSN, and a checksum, which is verified) and a slot array at the
//! end pointing at its records. Records use the FixedVar format: status
//! bits, the end of the fixed-length columns, a column count and null
//! bitmap, and the end offsets of the variable-length columns, so they
//! split into fixed and variable parts without the table's definition.
//! The allocation pages are decoded: the file header (page 0), PFS (one
//! byte per page), GAM, SGAM, differential and minimally-logged change maps
//! (one bit per extent), IAM pages, and the primary file's boot page
//! (page 9) with the database's name, ID, creation time and version.
//!
//! A log file starts with the same file header page; virtual log files
//! follow, each with a header giving its sequence number, size and offset.
//! Log blocks and records are not decoded.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::guid_le;
use crate::formats::util::fmt::{grouped_count, plural, size};
use crate::formats::util::val::{enumv, flagsv, hex, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{Check, EnumTable, FlagTable, Value, flag, lookup};

const PAGE: u64 = 8192;
const HEADER: u64 = 96;

pub static DATA: Format = Format {
    name: "mssql-data",
    title: "SQL Server data file",
    extensions: &["mdf", "ndf"],
    mime: "application/x-mssql-data",
    probe: Probe::Custom(|h| file_header(h) && page1_is_pfs(h)),
    dissect: crate::expander!(dissect_data: Input),
};

pub static LOG: Format = Format {
    name: "mssql-log",
    title: "SQL Server transaction log",
    extensions: &["ldf"],
    mime: "application/x-mssql-log",
    probe: Probe::Custom(|h| file_header(h) && !page1_is_pfs(h) && log_vlf_at(h, PAGE)),
    dissect: crate::expander!(dissect_log: Input),
};

/// Page 0: header version 1, the file header type, page ID 0 of a file
/// numbered from 1, one slot, and a valid checksum.
fn file_header(h: &Head<'_>) -> bool {
    let d = h.data;
    let Some(page) = d.get(..to_usize(PAGE)) else {
        return false;
    };
    page.first() == Some(&1)
        && page.get(1) == Some(&15)
        && u32_le(page, 32) == Some(0)
        && u16_le(page, 36).is_some_and(|f| f != 0)
        && u16_le(page, 22).is_some_and(|n| (1..=4).contains(&n))
        && checksum_ok(page) != Some(false)
}

fn page1_is_pfs(h: &Head<'_>) -> bool {
    let p = h
        .data
        .get(to_usize(PAGE)..to_usize(PAGE.saturating_mul(2)))
        .unwrap_or_default();
    p.first() == Some(&1) && p.get(1) == Some(&11) && u32_le(p, 32) == Some(1)
}

/// A virtual log file header at `at`.
fn log_vlf_at(h: &Head<'_>, at: u64) -> bool {
    let d = h.data.get(to_usize(at)..).unwrap_or_default();
    d.first() == Some(&0xab) && u16_le(d, 2) == Some(5) && u64_le(d, 24) == Some(at)
}

/// The page checksum (when the header's flags say there is one): XOR of
/// each 512-byte sector's words, rotated by the sector number, the
/// checksum field itself left out. `None` when the page has none.
fn checksum_ok(page: &[u8]) -> Option<bool> {
    let flags = u16_le(page, 4)?;
    if flags & 0x200 == 0 {
        return None;
    }
    Some(compute_checksum(page)? == u32_le(page, 60)?)
}

/// SQL Server's page checksum (PAGE_VERIFY CHECKSUM).
const MSSQL_SUM: &str = "page checksum";

fn compute_checksum(page: &[u8]) -> Option<u32> {
    if page.len() != to_usize(PAGE) {
        return None;
    }
    let mut sum = 0u32;
    for (i, sector) in page.as_chunks::<512>().0.iter().enumerate() {
        let mut x = 0u32;
        for (j, w) in sector.as_chunks::<4>().0.iter().enumerate() {
            if i == 0 && j == 15 {
                continue;
            }
            x ^= u32::from_le_bytes(*w);
        }
        sum ^= x.rotate_left(u32::try_from(15usize.saturating_sub(i)).ok()?);
    }
    Some(sum)
}

const PAGE_TYPES: EnumTable = &[
    (1, "data"),
    (2, "index"),
    (3, "text mix"),
    (4, "text tree"),
    (7, "sort"),
    (8, "GAM"),
    (9, "SGAM"),
    (10, "IAM"),
    (11, "PFS"),
    (13, "boot"),
    (15, "file header"),
    (16, "differential change map"),
    (17, "minimally logged change map"),
    (18, "deallocated (sort)"),
    (19, "unlinked reorganisation"),
    (20, "bulk-operation preallocation"),
];

const PAGE_FLAGS: FlagTable = &[flag(0x100, "TORN_PAGE_DETECTION"), flag(0x200, "CHECKSUM")];

fn page_id(b: &[u8], at: usize) -> String {
    format!(
        "({}:{})",
        u16_le(b, at.saturating_add(4)).unwrap_or(0),
        u32_le(b, at).unwrap_or(0)
    )
}

fn lsn(b: &[u8], at: usize) -> String {
    format!(
        "({}:{}:{})",
        u32_le(b, at).unwrap_or(0),
        u32_le(b, at.saturating_add(4)).unwrap_or(0),
        u16_le(b, at.saturating_add(8)).unwrap_or(0)
    )
}

fn type_name(t: u8) -> String {
    lookup(PAGE_TYPES, t.into()).map_or_else(|| format!("type {t}"), str::to_owned)
}

#[derive(Clone, Copy)]
struct File {
    input: Input,
    pages: u64,
}

impl File {
    fn page(&self, no: u64) -> Span {
        self.input.span.sub(no.saturating_mul(PAGE), PAGE)
    }
}

/// SQL Server version from the database version number in the boot page.
fn release(v: u16) -> &'static str {
    match v {
        539 => "SQL Server 2000",
        611 | 612 => "SQL Server 2005",
        655 => "SQL Server 2008",
        660 | 661 => "SQL Server 2008 R2",
        706 => "SQL Server 2012",
        782 => "SQL Server 2014",
        852 => "SQL Server 2016",
        869 => "SQL Server 2017",
        895..=904 => "SQL Server 2019",
        950..=957 => "SQL Server 2022",
        _ => "SQL Server",
    }
}

/// The variable-length columns of the file header record that are known
/// for certain (by position; the rest are shown by number).
const FILE_HEADER_COLUMNS: &[(usize, &str)] = &[
    (0, "Binding ID"),
    (2, "File ID"),
    (3, "File group ID"),
    (4, "Size"),
    (5, "Maximum size"),
    (6, "Growth"),
    (12, "Minimum size"),
    (15, "Sector size"),
    (23, "File GUID"),
    (27, "Logical name"),
];

pub async fn dissect_data(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let pages = file.len / PAGE;
    let f = File { input, pages };
    let p0 = cx.read(file.sub(0, PAGE)).await?;
    let fid = u16_le(&p0, 36).unwrap_or(0);
    let hdr = header_record(&cx, f.page(0)).await;
    cx.emit(
        Node::new("File header")
            .span(f.page(0))
            .summary(hdr.summary.clone())
            .lazy(page_node, (f, 0u64)),
    );
    let mut boot = None;
    if pages > 9 {
        let p9 = cx.read(f.page(9)).await?;
        if p9.get(1) == Some(&13) {
            boot = Some(boot_summary(&p9));
            cx.emit(
                Node::new("Boot page")
                    .span(f.page(9))
                    .summary(boot.clone().unwrap_or_default())
                    .lazy(page_node, (f, 9u64)),
            );
        }
    }
    cx.emit(
        Node::new("Pages")
            .span(file.sub(0, pages.saturating_mul(PAGE)))
            .summary(grouped_count(pages, "page", "pages"))
            .lazy(pages_list, f),
    );
    if let Some(declared) = hdr.size.filter(|&s| s > pages) {
        cx.diag(Diagnostic::truncated(
            Span::new(file.source, file.offset, declared.saturating_mul(PAGE)),
            file.len,
        ));
    }
    let mut s = format!(
        "SQL Server data file {}, file {fid}, {}",
        hdr.name
            .as_deref()
            .map_or(String::new(), |n| format!("{n:?}")),
        grouped_count(pages, "page", "pages")
    );
    if let Some(b) = boot {
        s.push_str(&format!(", {b}"));
    }
    cx.annotate(s);
    Ok(())
}

/// What the file header record says.
#[derive(Default)]
struct HeaderInfo {
    name: Option<String>,
    size: Option<u64>,
    summary: String,
}

async fn header_record(cx: &Cx, page: Span) -> HeaderInfo {
    let Ok(p) = cx.read(page).await else {
        return HeaderInfo::default();
    };
    let Some(off) = u16_le(&p, to_usize(PAGE.saturating_sub(2))) else {
        return HeaderInfo::default();
    };
    let rec = record(&p, off.into());
    let col = |i: usize| -> &[u8] {
        rec.var
            .get(i)
            .and_then(|&(o, l)| p.get(to_usize(o)..to_usize(o.saturating_add(l))))
            .unwrap_or_default()
    };
    let name = String::from_utf16_lossy(
        &col(27)
            .as_chunks::<2>()
            .0
            .iter()
            .map(|c| u16::from_le_bytes(*c))
            .collect::<Vec<_>>(),
    );
    let size = u32_le(col(4), 0).map(u64::from);
    let group = u16_le(col(3), 0);
    let mut summary = format!("logical name {name:?}");
    if let Some(s) = size {
        summary.push_str(&format!(", {}", grouped_count(s, "page", "pages")));
    }
    if let Some(g) = group {
        summary.push_str(&format!(", file group {g}"));
    }
    HeaderInfo {
        name: (!name.is_empty()).then_some(name),
        size,
        summary,
    }
}

async fn pages_list(cx: Cx, f: File) -> Result<()> {
    cx.set_count(Count::Exact(f.pages));
    let start = cx.resume::<u64>().unwrap_or(0);
    for n in start..f.pages {
        cx.mark(move || n);
        let span = f.page(n);
        let summary = if cx.skipping() {
            String::new()
        } else {
            let h = cx.read(span.sub(0, HEADER)).await?;
            page_summary(&h, n)
        };
        cx.push(
            Node::new(format!("Page {n}"))
                .span(span)
                .summary(summary)
                .lazy(page_node, (f, n)),
        )
        .await;
    }
    Ok(())
}

fn page_summary(h: &[u8], n: u64) -> String {
    if h.iter().all(|&b| b == 0) {
        return "never written".to_owned();
    }
    let t = h.get(1).copied().unwrap_or(0);
    let mut s = type_name(t);
    let slots = u16_le(h, 22).unwrap_or(0);
    if matches!(t, 1..=4) {
        s.push_str(&format!(
            ", allocation unit {}:{}, {}",
            u32_le(h, 24).unwrap_or(0),
            u16_le(h, 6).unwrap_or(0),
            grouped_count(slots, "record", "records")
        ));
        let level = h.get(3).copied().unwrap_or(0);
        if t == 2 {
            s.push_str(&format!(", level {level}"));
        }
    }
    if u64::from(u32_le(h, 32).unwrap_or(0)) != n {
        s.push_str(&format!(", page ID {}", page_id(h, 32)));
    }
    s
}

async fn page_node(cx: Cx, (f, n): (File, u64)) -> Result<()> {
    let span = f.page(n);
    let p = cx.read(span).await?;
    cx.charge(PAGE / 512).await;
    if p.iter().all(|&b| b == 0) {
        cx.emit(Node::new("Unused").span(span).summary("never written"));
        return Ok(());
    }
    let mut hn = Node::new("Page header")
        .span(span.sub(0, HEADER))
        .lazy(header_fields, span);
    if checksum_ok(&p) == Some(false) {
        let check = Check::new(MSSQL_SUM, u32_le(&p, 60).unwrap_or(0));
        hn = hn.check_diag(&match compute_checksum(&p) {
            Some(c) => check.verify(c),
            None => check.verified(false),
        });
    }
    if u64::from(u32_le(&p, 32).unwrap_or(0)) != n {
        hn = hn.diag(Diagnostic::malformed(format!(
            "page {n} holds page {}",
            page_id(&p, 32)
        )));
    }
    cx.emit(hn);
    let t = p.get(1).copied().unwrap_or(0);
    let slots = u64::from(u16_le(&p, 22).unwrap_or(0));
    let slot_start = PAGE.saturating_sub(slots.saturating_mul(2));
    let slot_at = |i: u64| {
        u64::from(
            u16_le(
                &p,
                to_usize(PAGE.saturating_sub(i.saturating_add(1).saturating_mul(2))),
            )
            .unwrap_or(0),
        )
    };
    match t {
        11 => pfs(&cx, span, &p),
        8 | 9 | 16 | 17 => bitmap_page(&cx, span, &p, t),
        10 => iam(&cx, span, &p),
        13 => boot(&cx, span, &p),
        15 => file_header_page(&cx, span, &p, slot_at(0)),
        _ => {
            cx.emit(
                Node::new("Records")
                    .span(span.sub(
                        HEADER,
                        u64::from(u16_le(&p, 30).unwrap_or(0)).saturating_sub(HEADER),
                    ))
                    .summary(grouped_count(slots, "record", "records"))
                    .lazy(records_list, (span, slots)),
            );
        }
    }
    let free_data = u64::from(u16_le(&p, 30).unwrap_or(0));
    if !matches!(t, 8..=11 | 13 | 15..=17) && slot_start > free_data {
        cx.emit(
            Node::new("Free space")
                .span(span.sub(free_data, slot_start.saturating_sub(free_data)))
                .summary(size(slot_start.saturating_sub(free_data))),
        );
    }
    if slots != 0 {
        cx.emit(
            Node::new("Slot array")
                .span(span.sub(slot_start, slots.saturating_mul(2)))
                .summary(grouped_count(slots, "slot", "slots"))
                .desc("Record offsets, slot 0 last, from the end of the page backwards")
                .lazy(slot_array, (span, slots)),
        );
    }
    Ok(())
}

async fn header_fields(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span.sub(0, HEADER)).await?;
    let at = |o: u64, l: u64| span.sub(o, l);
    cx.emit(
        Node::new("Header version")
            .span(at(0, 1))
            .value(uint(b.first().copied().unwrap_or(0), 8)),
    );
    cx.emit(Node::new("Type").span(at(1, 1)).value(enumv(
        b.get(1).copied().unwrap_or(0),
        8,
        PAGE_TYPES,
    )));
    cx.emit(
        Node::new("Type flag bits")
            .span(at(2, 1))
            .value(hex(b.get(2).copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Level")
            .span(at(3, 1))
            .value(uint(b.get(3).copied().unwrap_or(0), 8))
            .desc("Index pages: 0 for leaves"),
    );
    cx.emit(Node::new("Flags").span(at(4, 2)).value(flagsv(
        u16_le(&b, 4).unwrap_or(0),
        16,
        PAGE_FLAGS,
    )));
    cx.emit(
        Node::new("Index ID (allocation unit)")
            .span(at(6, 2))
            .value(uint(u16_le(&b, 6).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Previous page")
            .span(at(8, 6))
            .summary(page_id(&b, 8)),
    );
    cx.emit(
        Node::new("Fixed-length size")
            .span(at(14, 2))
            .value(uint(u16_le(&b, 14).unwrap_or(0), 16))
            .desc("pminlen: the fixed-length part of the records"),
    );
    cx.emit(
        Node::new("Next page")
            .span(at(16, 6))
            .summary(page_id(&b, 16)),
    );
    cx.emit(
        Node::new("Slot count")
            .span(at(22, 2))
            .value(uint(u16_le(&b, 22).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Object ID (allocation unit)")
            .span(at(24, 4))
            .value(uint(u32_le(&b, 24).unwrap_or(0), 32)),
    );
    cx.emit(
        Node::new("Free bytes")
            .span(at(28, 2))
            .value(uint(u16_le(&b, 28).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Free data offset")
            .span(at(30, 2))
            .value(hex(u16_le(&b, 30).unwrap_or(0), 16))
            .desc("Where the next record goes"),
    );
    cx.emit(
        Node::new("Page ID")
            .span(at(32, 6))
            .summary(page_id(&b, 32)),
    );
    cx.emit(
        Node::new("Reserved bytes")
            .span(at(38, 2))
            .value(uint(u16_le(&b, 38).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("LSN")
            .span(at(40, 10))
            .summary(lsn(&b, 40))
            .desc("Log record of the last change: virtual log file, block, slot"),
    );
    cx.emit(
        Node::new("Transaction reserved bytes")
            .span(at(50, 2))
            .value(uint(u16_le(&b, 50).unwrap_or(0), 16)),
    );
    cx.emit(Node::new("Transaction descriptor").span(at(52, 6)));
    cx.emit(
        Node::new("Ghost records")
            .span(at(58, 2))
            .value(uint(u16_le(&b, 58).unwrap_or(0), 16)),
    );
    let stored = u32_le(&b, 60).unwrap_or(0);
    let ck = Node::new("Checksum or torn bits").span(at(60, 4));
    let full = cx.read(span).await?;
    let check = Check::new(MSSQL_SUM, stored);
    cx.emit(match (checksum_ok(&full), compute_checksum(&full)) {
        (Some(true), _) => ck.checksum(check.verified(true)),
        (Some(false), Some(c)) => ck.checksum(check.verify(c)),
        _ => ck.value(hex(stored, 32)).summary("torn-page bits or none"),
    });
    cx.emit(Node::new("Reserved").span(at(64, 32)));
    Ok(())
}

async fn slot_array(cx: Cx, (span, slots): (Span, u64)) -> Result<()> {
    let start = PAGE.saturating_sub(slots.saturating_mul(2));
    let b = cx.read(span.sub(start, slots.saturating_mul(2))).await?;
    cx.set_count(Count::Exact(slots));
    for i in 0..slots {
        let at = slots.saturating_sub(1).saturating_sub(i).saturating_mul(2);
        let off = u16_le(&b, to_usize(at)).unwrap_or(0);
        let mut n = Node::new(format!("Slot {i}"))
            .span(span.sub(start.saturating_add(at), 2))
            .value(hex(off, 16));
        if u64::from(off) < PAGE {
            n = n.target(span.sub(off.into(), 1));
        }
        cx.push(n).await;
    }
    Ok(())
}

/// A FixedVar record's layout.
#[derive(Debug, Default)]
struct Rec {
    status: u8,
    fixed_end: u64,
    columns: Option<u64>,
    nulls: Option<(u64, u64)>,
    var_count: Option<u64>,
    /// Variable-length columns: offset and length in the page.
    var: Vec<(u64, u64)>,
    end: u64,
    problem: Option<String>,
}

const RECORD_TYPES: EnumTable = &[
    (0, "primary"),
    (1, "forwarded"),
    (2, "forwarding stub"),
    (3, "index"),
    (4, "BLOB fragment"),
    (5, "ghost index"),
    (6, "ghost data"),
    (7, "ghost version"),
];

fn record(p: &[u8], off: u64) -> Rec {
    let mut r = Rec::default();
    let o = to_usize(off);
    r.status = p.get(o).copied().unwrap_or(0);
    let kind = (r.status >> 1) & 7;
    r.fixed_end = u64::from(u16_le(p, o.saturating_add(2)).unwrap_or(0));
    r.end = off.saturating_add(r.fixed_end);
    if kind == 2 {
        // A forwarding stub: status byte and the new location.
        r.end = off.saturating_add(9);
        return r;
    }
    if r.fixed_end < 4 || off.saturating_add(r.fixed_end) > PAGE {
        r.problem = Some("fixed-length size out of range".to_owned());
        r.end = off.saturating_add(4).min(PAGE);
        return r;
    }
    let mut pos = off.saturating_add(r.fixed_end);
    if r.status & 0x10 != 0 {
        let cols = u64::from(u16_le(p, to_usize(pos)).unwrap_or(0));
        r.columns = Some(cols);
        let bytes = cols.div_ceil(8);
        r.nulls = Some((pos.saturating_add(2), bytes));
        pos = pos.saturating_add(2).saturating_add(bytes);
    }
    if r.status & 0x20 != 0 {
        let n = u64::from(u16_le(p, to_usize(pos)).unwrap_or(0));
        r.var_count = Some(n);
        let mut data = pos.saturating_add(2).saturating_add(n.saturating_mul(2));
        for i in 0..n {
            let e = u16_le(
                p,
                to_usize(pos.saturating_add(2).saturating_add(i.saturating_mul(2))),
            )
            .unwrap_or(0);
            let end = off.saturating_add(u64::from(e & 0x7fff));
            if end < data || end > PAGE {
                r.problem = Some(format!("variable column {i} ends out of order"));
                break;
            }
            r.var.push((data, end.saturating_sub(data)));
            data = end;
        }
        pos = data;
    }
    r.end = pos.min(PAGE);
    r
}

async fn records_list(cx: Cx, (span, slots): (Span, u64)) -> Result<()> {
    let p = cx.read(span).await?;
    cx.set_count(Count::Exact(slots));
    for i in 0..slots {
        let off = u64::from(
            u16_le(
                &p,
                to_usize(PAGE.saturating_sub(i.saturating_add(1).saturating_mul(2))),
            )
            .unwrap_or(0),
        );
        if !(HEADER..PAGE).contains(&off) {
            cx.push(
                Node::new(format!("Record {i}"))
                    .diag(Diagnostic::malformed(format!("slot offset {off:#x}"))),
            )
            .await;
            continue;
        }
        let r = record(&p, off);
        let kind = (r.status >> 1) & 7;
        let mut s = format!(
            "{} record, {} bytes",
            lookup(RECORD_TYPES, kind.into()).unwrap_or("?"),
            r.end.saturating_sub(off)
        );
        if let Some(c) = r.columns {
            s.push_str(&format!(", {c} columns"));
        }
        if let Some(v) = r.var_count {
            s.push_str(&format!(", {v} variable-length"));
        }
        let mut n = Node::new(format!("Record {i}"))
            .span(span.sub(off, r.end.saturating_sub(off)))
            .summary(s)
            .lazy(record_fields, (span, off));
        if let Some(pr) = &r.problem {
            n = n.diag(Diagnostic::malformed(pr.clone()));
        }
        cx.push(n).await;
    }
    Ok(())
}

async fn record_fields(cx: Cx, (span, off): (Span, u64)) -> Result<()> {
    let p = cx.read(span).await?;
    let r = record(&p, off);
    let at = |o: u64, l: u64| span.sub(o, l);
    let kind = (r.status >> 1) & 7;
    let mut attrs = Vec::new();
    if r.status & 0x10 != 0 {
        attrs.push("null bitmap");
    }
    if r.status & 0x20 != 0 {
        attrs.push("variable columns");
    }
    if r.status & 0x40 != 0 {
        attrs.push("version information");
    }
    cx.emit(
        Node::new("Status A")
            .span(at(off, 1))
            .value(hex(r.status, 8))
            .summary(format!(
                "{} record{}{}",
                lookup(RECORD_TYPES, kind.into()).unwrap_or("?"),
                if attrs.is_empty() { "" } else { ": " },
                attrs.join(", ")
            )),
    );
    cx.emit(
        Node::new("Status B")
            .span(at(off.saturating_add(1), 1))
            .value(hex(
                p.get(to_usize(off.saturating_add(1))).copied().unwrap_or(0),
                8,
            )),
    );
    if kind == 2 {
        cx.emit(
            Node::new("Forwarded to")
                .span(at(off.saturating_add(1), 8))
                .summary(format!(
                    "page {}, slot {}",
                    page_id(&p, to_usize(off.saturating_add(1))),
                    u16_le(&p, to_usize(off.saturating_add(7))).unwrap_or(0)
                )),
        );
        return Ok(());
    }
    cx.emit(
        Node::new("Fixed-length end")
            .span(at(off.saturating_add(2), 2))
            .value(uint(r.fixed_end, 16)),
    );
    if r.fixed_end > 4 {
        let s = off.saturating_add(4);
        cx.emit(
            Node::new("Fixed-length columns")
                .span(at(s, r.fixed_end.saturating_sub(4)))
                .value(Value::Bytes(
                    p.get(to_usize(s)..to_usize(off.saturating_add(r.fixed_end)))
                        .unwrap_or_default()
                        .to_vec(),
                )),
        );
    }
    if let (Some(cols), Some((o, l))) = (r.columns, r.nulls) {
        cx.emit(
            Node::new("Column count")
                .span(at(o.saturating_sub(2), 2))
                .value(uint(cols, 16)),
        );
        let bits = p
            .get(to_usize(o)..to_usize(o.saturating_add(l)))
            .unwrap_or_default();
        let nulls = (0..cols)
            .filter(|&i| {
                bits.get(to_usize(i / 8))
                    .is_some_and(|b| b & (1 << (i % 8)) != 0)
            })
            .count();
        cx.emit(
            Node::new("Null bitmap")
                .span(at(o, l))
                .value(Value::Bytes(bits.to_vec()))
                .summary(format!("{nulls} null")),
        );
    }
    if let Some(n) = r.var_count {
        let first = r.var.first().map_or(r.end, |v| v.0);
        let arr = first.saturating_sub(n.saturating_mul(2)).saturating_sub(2);
        cx.emit(
            Node::new("Variable column count")
                .span(at(arr, 2))
                .value(uint(n, 16)),
        );
        cx.emit(
            Node::new("Variable column offsets")
                .span(at(arr.saturating_add(2), n.saturating_mul(2))),
        );
        for (i, &(o, l)) in r.var.iter().enumerate() {
            let b = p
                .get(to_usize(o)..to_usize(o.saturating_add(l)))
                .unwrap_or_default();
            cx.emit(
                Node::new(format!("Variable column {}", i.saturating_add(1)))
                    .span(at(o, l))
                    .value(Value::Bytes(b.to_vec())),
            );
        }
    }
    if let Some(pr) = r.problem {
        cx.diag(Diagnostic::malformed(pr));
    }
    Ok(())
}

fn record_header(cx: &Cx, span: Span, off: u64, len: u64) {
    cx.emit(
        Node::new("Record header")
            .span(span.sub(off, 4))
            .summary(format!("{len}-byte record")),
    );
}

const PFS_CLASSES: [&str; 8] = [
    "empty",
    "1-50% full",
    "51-80% full",
    "81-95% full",
    "96-100% full",
    "?",
    "?",
    "?",
];

fn pfs(cx: &Cx, span: Span, p: &[u8]) {
    let len = u64::from(u16_le(p, 98).unwrap_or(0)).clamp(4, PAGE.saturating_sub(HEADER));
    record_header(cx, span, HEADER, len);
    let bytes = p
        .get(100..to_usize(HEADER.saturating_add(len)))
        .unwrap_or_default();
    let allocated = bytes.iter().filter(|&&b| b & 0x40 != 0).count();
    let iam = bytes.iter().filter(|&&b| b & 0x10 != 0).count();
    cx.emit(
        Node::new("Page free space")
            .span(span.sub(100, len.saturating_sub(4)))
            .summary(format!(
                "one byte for each of {}: {allocated} allocated, {iam} IAM pages",
                grouped_count(to_u64(bytes.len()), "page", "pages")
            ))
            .desc("Per page: free space class (bits 0-2), ghost records (3), IAM page (4), mixed extent (5), allocated (6); pages whose byte is zero are not listed")
            .lazy(pfs_bytes, span.sub(100, len.saturating_sub(4))),
    );
}

async fn pfs_bytes(cx: Cx, span: Span) -> Result<()> {
    let b = cx.read(span).await?;
    // Only pages with a non-zero byte (allocated or used before) are
    // listed.
    cx.set_count(Count::Exact(to_u64(b.iter().filter(|&&v| v != 0).count())));
    for (i, &v) in b.iter().enumerate() {
        if i % 1024 == 0 {
            cx.checkpoint().await;
        }
        if v == 0 {
            continue;
        }
        let mut parts = vec![*PFS_CLASSES.get(usize::from(v & 7)).unwrap_or(&"?")];
        if v & 0x40 != 0 {
            parts.insert(0, "allocated");
        }
        if v & 0x20 != 0 {
            parts.push("mixed extent");
        }
        if v & 0x10 != 0 {
            parts.push("IAM page");
        }
        if v & 0x08 != 0 {
            parts.push("ghost records");
        }
        cx.push(
            Node::new(format!("Page {i}"))
                .span(span.sub(to_u64(i), 1))
                .value(hex(v, 8))
                .summary(parts.join(", ")),
        )
        .await;
    }
    Ok(())
}

/// GAM, SGAM and the change maps: a 94-byte header record, then one bit
/// per extent.
fn bitmap_page(cx: &Cx, span: Span, p: &[u8], t: u8) {
    record_header(cx, span, HEADER, 94);
    cx.emit(Node::new("Map header").span(span.sub(100, 90)));
    let off = 190u64;
    let len = u64::from(u16_le(p, 192).unwrap_or(0)).clamp(4, PAGE.saturating_sub(off));
    record_header(cx, span, off, len);
    let bits = p
        .get(194..to_usize(off.saturating_add(len)))
        .unwrap_or_default();
    let set: u32 = bits.iter().map(|b| b.count_ones()).sum();
    let meaning = match t {
        8 => "free (bit set) or allocated",
        9 => "mixed extents with free pages",
        16 => "changed since the last full backup",
        _ => "changed by minimally logged operations since the last log backup",
    };
    cx.emit(
        Node::new("Extent bitmap")
            .span(span.sub(194, len.saturating_sub(4)))
            .summary(format!(
                "{}, {set} set: {meaning}",
                plural(to_u64(bits.len()).saturating_mul(8), "extent")
            )),
    );
}

fn iam(cx: &Cx, span: Span, p: &[u8]) {
    record_header(cx, span, HEADER, 94);
    cx.emit(
        Node::new("IAM header")
            .span(span.sub(100, 36))
            .summary("sequence number, status, object and index"),
    );
    cx.emit(
        Node::new("Start page")
            .span(span.sub(136, 6))
            .summary(page_id(p, 136))
            .desc("The first page of the GAM interval this IAM page maps"),
    );
    let singles: Vec<String> = (0..8usize)
        .map(|i| page_id(p, 142usize.saturating_add(i.saturating_mul(6))))
        .filter(|s| s != "(0:0)")
        .collect();
    cx.emit(
        Node::new("Single page allocations")
            .span(span.sub(142, 48))
            .summary(if singles.is_empty() {
                "none".to_owned()
            } else {
                singles.join(", ")
            }),
    );
    let off = 190u64;
    let len = u64::from(u16_le(p, 192).unwrap_or(0)).clamp(4, PAGE.saturating_sub(off));
    record_header(cx, span, off, len);
    let bits = p
        .get(194..to_usize(off.saturating_add(len)))
        .unwrap_or_default();
    let set: u32 = bits.iter().map(|b| b.count_ones()).sum();
    cx.emit(
        Node::new("Extent bitmap")
            .span(span.sub(194, len.saturating_sub(4)))
            .summary(format!(
                "{set_extent} allocated to the allocation unit",
                set_extent = plural(set, "extent")
            )),
    );
}

/// A SQL Server `datetime`: 1/300-second ticks since midnight, days since
/// 1900-01-01.
fn datetime(p: &[u8], at: usize) -> Value {
    let ticks = i64::from(u32_le(p, at).unwrap_or(0));
    let days = i64::from(u32_le(p, at.saturating_add(4)).unwrap_or(0));
    Value::utc(
        days.saturating_sub(25567)
            .saturating_mul(86400)
            .saturating_add(ticks / 300),
    )
}

fn db_name(p: &[u8]) -> String {
    let units: Vec<u16> = p
        .get(148..404)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&u| u != 0 && u != 0x2020)
        .collect();
    String::from_utf16_lossy(&units).trim_end().to_owned()
}

fn boot_summary(p: &[u8]) -> String {
    let v = u16_le(p, 100).unwrap_or(0);
    format!(
        "database {:?} (ID {}), version {v} ({}), compatibility level {}",
        db_name(p),
        u16_le(p, 408).unwrap_or(0),
        release(v),
        u16_le(p, 410).unwrap_or(0)
    )
}

fn boot(cx: &Cx, span: Span, p: &[u8]) {
    let len = u64::from(u16_le(p, 98).unwrap_or(0)).clamp(4, PAGE.saturating_sub(HEADER));
    record_header(cx, span, HEADER, len);
    let at = |o: u64, l: u64| span.sub(o, l);
    let v = u16_le(p, 100).unwrap_or(0);
    cx.emit(
        Node::new("Database version")
            .span(at(100, 2))
            .value(uint(v, 16))
            .summary(release(v)),
    );
    let cv = u16_le(p, 102).unwrap_or(0);
    cx.emit(
        Node::new("Created by version")
            .span(at(102, 2))
            .value(uint(cv, 16))
            .summary(release(cv)),
    );
    cx.emit(
        Node::new("Created")
            .span(at(140, 8))
            .value(datetime(p, 140)),
    );
    cx.emit(Node::new("Name").span(at(148, 256)).value(text(db_name(p))));
    cx.emit(
        Node::new("Database ID")
            .span(at(408, 2))
            .value(uint(u16_le(p, 408).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Compatibility level")
            .span(at(410, 2))
            .value(uint(u16_le(p, 410).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Collation")
            .span(at(488, 4))
            .value(hex(u32_le(p, 488).unwrap_or(0), 32)),
    );
    if let Some(b) = p.get(504..520) {
        let g = guid_le(b);
        cx.emit(
            Node::new("Family GUID")
                .span(at(504, 16))
                .value(Value::Guid(g))
                .desc("Shared by the database and its backups"),
        );
    }
    cx.emit(
        Node::new("Largest log space used")
            .span(at(520, 8))
            .value(uint(u64_le(p, 520).unwrap_or(0), 64)),
    );
    cx.emit(
        Node::new("Database information")
            .span(at(100, len.saturating_sub(4)))
            .summary("DBINFO: the rest of its fields are not decoded"),
    );
}

fn file_header_page(cx: &Cx, span: Span, p: &[u8], off: u64) {
    let r = record(p, off);
    let mut n = Node::new("File header record")
        .span(span.sub(off, r.end.saturating_sub(off)))
        .summary(grouped_count(
            r.var_count.unwrap_or(0),
            "property",
            "properties",
        ))
        .lazy(file_header_props, (span, off));
    if let Some(pr) = &r.problem {
        n = n.diag(Diagnostic::malformed(pr.clone()));
    }
    cx.emit(n);
}

async fn file_header_props(cx: Cx, (span, off): (Span, u64)) -> Result<()> {
    let p = cx.read(span).await?;
    let r = record(&p, off);
    for (i, &(o, l)) in r.var.iter().enumerate() {
        let b = p
            .get(to_usize(o)..to_usize(o.saturating_add(l)))
            .unwrap_or_default();
        let name = FILE_HEADER_COLUMNS
            .iter()
            .find(|(k, _)| *k == i)
            .map(|(_, n)| *n);
        let mut n = Node::new(name.map_or_else(|| format!("Property {i}"), str::to_owned))
            .span(span.sub(o, l));
        n = match (i, l) {
            (0 | 23, 16) => n.value(Value::Guid(guid_le(b))),
            (27, _) => n.value(text(String::from_utf16_lossy(
                &b.as_chunks::<2>()
                    .0
                    .iter()
                    .map(|c| u16::from_le_bytes(*c))
                    .collect::<Vec<_>>(),
            ))),
            (_, 2) => n.value(uint(u16_le(b, 0).unwrap_or(0), 16)),
            (4 | 5 | 6 | 12, 4) => n
                .value(uint(u32_le(b, 0).unwrap_or(0), 32))
                .summary("pages"),
            (_, 4) => n.value(uint(u32_le(b, 0).unwrap_or(0), 32)),
            (_, 10) => n.summary(lsn(b, 0)),
            (_, 0) => n.summary("NULL"),
            _ => n.value(Value::Bytes(b.to_vec())),
        };
        cx.emit(n);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Transaction logs

pub async fn dissect_log(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let f = File {
        input,
        pages: file.len / PAGE,
    };
    let hdr = header_record(&cx, f.page(0)).await;
    cx.emit(
        Node::new("File header")
            .span(f.page(0))
            .summary(hdr.summary.clone())
            .lazy(page_node, (f, 0u64)),
    );
    cx.emit(
        Node::new("Virtual log files")
            .span(file.tail(PAGE))
            .lazy(vlfs, input),
    );
    cx.annotate(format!(
        "SQL Server transaction log{}, {}",
        hdr.name
            .as_deref()
            .map_or(String::new(), |n| format!(" {n:?}")),
        size(file.len)
    ));
    Ok(())
}

const VLF_STATUS: EnumTable = &[(1, "inactive"), (2, "active")];

async fn vlfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = PAGE;
    let mut i = 0u64;
    while pos.saturating_add(32) <= file.len {
        let h = cx.read(file.sub(pos, 32)).await?;
        let size_v = u64_le(&h, 16).unwrap_or(0);
        if h.first() != Some(&0xab) || u64_le(&h, 24) != Some(pos) || size_v < PAGE {
            cx.push(
                Node::new("Unparsed data")
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("not a virtual log file header")),
            )
            .await;
            break;
        }
        let seq = u32_le(&h, 4).unwrap_or(0);
        let status = u32_le(&h, 12).unwrap_or(0);
        let span = file.sub(pos, size_v);
        let mut n = Node::new(format!("VLF {i}"))
            .span(span)
            .summary(format!(
                "sequence {seq}, {}, {}",
                size(size_v),
                lookup(VLF_STATUS, status.into()).unwrap_or("unknown status")
            ))
            .lazy(vlf_fields, span);
        if pos.saturating_add(size_v) > file.len {
            n = n.diag(Diagnostic::truncated(
                Span::new(file.source, file.offset.saturating_add(pos), size_v),
                file.len.saturating_sub(pos),
            ));
        }
        cx.push(n).await;
        pos = pos.saturating_add(size_v);
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn vlf_fields(cx: Cx, span: Span) -> Result<()> {
    let h = cx.read(span.sub(0, 32)).await?;
    cx.emit(
        Node::new("Signature")
            .span(span.sub(0, 1))
            .value(hex(h.first().copied().unwrap_or(0), 8)),
    );
    cx.emit(
        Node::new("Parity")
            .span(span.sub(1, 1))
            .value(hex(h.get(1).copied().unwrap_or(0), 8))
            .desc("Flips between 0x40 and 0x80 each time the VLF is reused"),
    );
    cx.emit(
        Node::new("Version")
            .span(span.sub(2, 2))
            .value(uint(u16_le(&h, 2).unwrap_or(0), 16)),
    );
    cx.emit(
        Node::new("Sequence number")
            .span(span.sub(4, 4))
            .value(uint(u32_le(&h, 4).unwrap_or(0), 32))
            .desc("The first part of the LSNs of the log records in it"),
    );
    cx.emit(Node::new("Status").span(span.sub(12, 4)).value(enumv(
        u32_le(&h, 12).unwrap_or(0),
        32,
        VLF_STATUS,
    )));
    cx.emit(
        Node::new("Size")
            .span(span.sub(16, 8))
            .value(uint(u64_le(&h, 16).unwrap_or(0), 64)),
    );
    cx.emit(
        Node::new("Offset")
            .span(span.sub(24, 8))
            .value(hex(u64_le(&h, 24).unwrap_or(0), 64)),
    );
    cx.emit(Node::new("Header rest").span(span.sub(32, PAGE.saturating_sub(32))));
    cx.emit(
        Node::new("Log blocks")
            .span(span.tail(PAGE))
            .summary("512-byte sectors of log blocks (not decoded)"),
    );
    Ok(())
}
