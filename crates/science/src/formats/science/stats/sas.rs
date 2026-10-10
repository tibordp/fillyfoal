//! SAS data sets (`.sas7bdat`) and catalogs (`.sas7bcat`).
//!
//! A header (magic, alignment and byte order flags, encoding, dataset name,
//! times, page size and count, SAS release and host), then pages: metadata
//! pages hold subheaders (row size, column size, column text, names,
//! attributes, formats and labels) addressed by pointers after the page
//! header; data pages hold rows; mixed pages both. Compressed data sets
//! (`SASYZCRL` run-length or `SASYZCR2` RDC) keep each row in its own
//! subheader. Numbers are IEEE doubles, possibly truncated to their first
//! 3–7 bytes; missing values are NaNs whose tag byte names `.`, `._` or
//! `.A`–`.Z`.
//!
//! The format is undocumented. This follows the open readers (ReadStat,
//! pandas' `sas7bdat.py`, after Matt Shotwell's reverse-engineering notes)
//! as remembered; no free writer exists, so the fixtures are synthetic
//! (`tests/data/sas7bdat/make.py`) and were checked to read the same in
//! pandas and ReadStat. Fields whose meaning is unknown are shown raw.
//! Catalogs share the header and page layout; their subheaders are listed
//! without interpretation.

use std::sync::Arc;

use super::{Cell, Item, date_cell, decode_text, row_node, trim_end};
use crate::bytes::{to_u64, to_usize};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::civil::SAS_EPOCH;
use crate::formats::{Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const MAGIC: &[u8] = b"\0\0\0\0\0\0\0\0\0\0\0\0\xc2\xea\x81\x60\xb3\x14\x11\xcf\xbd\x92\x08\0\x09\xc7\x31\x8c\x18\x1f\x10\x11";

declare_format!(pub SAS7BDAT = "sas7bdat", "SAS data set", ["sas7bdat", "sas7bcat"], "application/x-sas-data",
    Probe::Magic(&[(0, MAGIC)]), dissect);

/// The encoding byte at offset 70 (ReadStat's and pandas' tables, as
/// remembered), as WHATWG labels where one exists.
const ENCODINGS: EnumTable = &[
    (0, "default"),
    (20, "utf-8"),
    (28, "us-ascii"),
    (29, "iso-8859-1"),
    (30, "iso-8859-2"),
    (31, "iso-8859-3"),
    (32, "iso-8859-4"),
    (33, "iso-8859-5"),
    (34, "iso-8859-6"),
    (35, "iso-8859-7"),
    (36, "iso-8859-8"),
    (37, "iso-8859-9"),
    (40, "iso-8859-15"),
    (60, "windows-1250"),
    (61, "windows-1251"),
    (62, "windows-1252"),
    (63, "windows-1253"),
    (64, "windows-1254"),
    (65, "windows-1255"),
    (66, "windows-1256"),
    (67, "windows-1257"),
    (68, "windows-1258"),
    (123, "big5"),
    (125, "gb2312"),
    (134, "euc-jp"),
    (138, "shift_jis"),
    (140, "euc-kr"),
];

const PAGE_TYPES: EnumTable = &[
    (0x0000, "meta"),
    (0x0100, "data"),
    (0x0200, "mix"),
    (0x0280, "mix"),
    (0x0400, "amd"),
    (0x4000, "meta"),
    (0x9000, "comp"),
];

/// Subheader signatures (32-bit, sign-extended in 64-bit files).
const SIGNATURES: EnumTable = &[
    (0xF7F7_F7F7, "Row size"),
    (0xF6F6_F6F6, "Column size"),
    (0xFFFF_FC00, "Subheader counts"),
    (0xFFFF_FFFD, "Column text"),
    (0xFFFF_FFFF, "Column names"),
    (0xFFFF_FFFC, "Column attributes"),
    (0xFFFF_FBFE, "Format and label"),
    (0xFFFF_FFFE, "Column list"),
];

/// Formats that show days since 1960 as dates, and seconds as date-times.
const DATE_FORMATS: &[&str] = &[
    "DATE", "DAY", "DDMMYY", "DOWNAME", "JULDAY", "JULIAN", "MMDDYY", "MMYY", "MONNAME", "MONTH",
    "MONYY", "QTR", "WEEKDATE", "WEEKDATX", "WEEKDAY", "WORDDATE", "WORDDATX", "YEAR", "YYMM",
    "YYMMDD", "YYMON", "YYQ", "E8601DA", "B8601DA", "IS8601DA", "NLDATE",
];
const DATETIME_FORMATS: &[&str] = &[
    "DATETIME", "DTDATE", "DTMONYY", "DTWKDATX", "DTYEAR", "E8601DT", "B8601DT", "IS8601DT",
    "MDYAMPM", "NLDATM",
];

#[derive(Clone, Copy, Debug)]
struct Layout {
    u64: bool,
    endian: Endian,
}

impl Layout {
    fn w(self) -> u64 {
        if self.u64 { 8 } else { 4 }
    }

    fn page_header(self) -> u64 {
        if self.u64 { 40 } else { 24 }
    }

    fn pointer(self) -> u64 {
        if self.u64 { 24 } else { 12 }
    }

    fn uint(self, b: &[u8], at: u64, n: u64) -> u64 {
        let at = to_usize(at);
        let bytes = b
            .get(at..at.saturating_add(to_usize(n)))
            .unwrap_or_default();
        match self.endian {
            Endian::Big => crate::formats::util::datakit::be_uint(bytes),
            Endian::Little => crate::formats::util::datakit::le_uint(bytes),
        }
    }

    fn f64(self, b: &[u8], at: u64) -> f64 {
        f64::from_bits(self.uint(b, at, 8))
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    RowSize,
    ColumnSize,
    Counts,
    ColumnText,
    ColumnNames,
    ColumnAttributes,
    FormatLabel,
    ColumnList,
    /// A row stored in a subheader, compressed or not.
    Row {
        compressed: bool,
    },
    Truncated,
    Unknown(u32),
}

#[derive(Clone, Copy, Debug)]
struct Pointer {
    span: Span,
    compression: u8,
    kind: Kind,
}

#[derive(Clone, Debug)]
struct Page {
    kind: u16,
    blocks: u16,
    pointers: Vec<Pointer>,
    /// Rows stored after the pointers (mixed pages) or after the header
    /// (data pages).
    rows_at: u64,
}

#[derive(Clone, Debug, Default)]
struct Column {
    name: String,
    label: String,
    format: String,
    format_width: u64,
    format_decimals: u64,
    offset: u64,
    width: u64,
    numeric: bool,
}

#[derive(Clone, Debug)]
struct Sas {
    lay: Layout,
    file: Span,
    header_size: u64,
    page_size: u64,
    page_count: u64,
    encoding: Option<&'static str>,
    row_length: u64,
    row_count: u64,
    mix_rows: u64,
    codec: Option<Codec>,
    columns: Vec<Column>,
}

impl Sas {
    fn page_span(&self, i: u64) -> Span {
        self.file.sub(
            self.header_size
                .saturating_add(i.saturating_mul(self.page_size)),
            self.page_size,
        )
    }

    fn text(&self, bytes: &[u8]) -> String {
        decode_text(self.encoding, bytes)
    }
}

/// Parses a page header and its subheader pointers.
fn parse_page(lay: Layout, span: Span, raw: &[u8], compressed: bool) -> Page {
    let base = lay.page_header().saturating_sub(8);
    let kind = lay.uint(raw, base, 2) as u16;
    let blocks = lay.uint(raw, base.saturating_add(2), 2) as u16;
    let count = lay.uint(raw, base.saturating_add(4), 2);
    let mut pointers = Vec::new();
    let meta_like = kind & 0x9000 != 0x9000 && kind & 0x0f00 != 0x0100;
    let mut at = lay.page_header();
    if meta_like {
        for _ in 0..count {
            let p = lay.pointer();
            if at.saturating_add(p) > to_u64(raw.len()) {
                break;
            }
            let w = lay.w();
            let offset = lay.uint(raw, at, w);
            let len = lay.uint(raw, at.saturating_add(w), w);
            let compression = raw
                .get(to_usize(at.saturating_add(w.saturating_mul(2))))
                .copied()
                .unwrap_or(0);
            let typ = raw
                .get(to_usize(
                    at.saturating_add(w.saturating_mul(2)).saturating_add(1),
                ))
                .copied()
                .unwrap_or(0);
            at = at.saturating_add(p);
            if len == 0 {
                continue;
            }
            let sub = span.sub(offset, len);
            let kind = if compression == 1 {
                Kind::Truncated
            } else if compression == 4 {
                Kind::Row { compressed: true }
            } else {
                let sig = lay.uint(raw, offset, w) as u32;
                match sig {
                    0xF7F7_F7F7 => Kind::RowSize,
                    0xF6F6_F6F6 => Kind::ColumnSize,
                    0xFFFF_FC00 => Kind::Counts,
                    0xFFFF_FFFD => Kind::ColumnText,
                    0xFFFF_FFFF => Kind::ColumnNames,
                    0xFFFF_FFFC => Kind::ColumnAttributes,
                    0xFFFF_FBFE => Kind::FormatLabel,
                    0xFFFF_FFFE => Kind::ColumnList,
                    _ if compressed && typ == 1 => Kind::Row { compressed: false },
                    other => Kind::Unknown(other),
                }
            };
            pointers.push(Pointer {
                span: sub,
                compression,
                kind,
            });
        }
    }
    let mut rows_at = lay.page_header();
    if kind & 0x0f00 == 0x0200 {
        let end = lay
            .page_header()
            .saturating_add(count.saturating_mul(lay.pointer()));
        rows_at = end.saturating_add(end % 8);
    }
    Page {
        kind,
        blocks,
        pointers,
        rows_at,
    }
}

/// `(index, offset, length)` of a string in the column text blobs.
fn text_ref(lay: Layout, raw: &[u8], at: u64) -> (u64, u64, u64) {
    (
        lay.uint(raw, at, 2),
        lay.uint(raw, at.saturating_add(2), 2),
        lay.uint(raw, at.saturating_add(4), 2),
    )
}

fn resolve(sas: &Sas, blobs: &[Vec<u8>], r: (u64, u64, u64)) -> String {
    let (index, offset, len) = r;
    let start = to_usize(offset);
    blobs
        .get(to_usize(index))
        .and_then(|b| b.get(start..start.saturating_add(to_usize(len))))
        .map(|b| sas.text(trim_end(b)))
        .unwrap_or_default()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 288)).await?;
    let u64 = head.get(32) == Some(&0x33);
    let pad1: u64 = if head.get(35) == Some(&0x33) { 4 } else { 0 };
    let endian = if head.get(37) == Some(&0x01) {
        Endian::Little
    } else {
        Endian::Big
    };
    let lay = Layout { u64, endian };
    let w = lay.w();
    let encoding_byte = head.get(70).copied().unwrap_or(0);
    let name =
        String::from_utf8_lossy(trim_end(head.get(92..156).unwrap_or_default())).into_owned();
    let file_type =
        String::from_utf8_lossy(trim_end(head.get(156..164).unwrap_or_default())).into_owned();
    let t0 = 164u64.saturating_add(pad1);
    let created = lay.f64(&head, t0);
    let modified = lay.f64(&head, t0.saturating_add(8));
    let sizes = t0.saturating_add(32);
    let header_size = lay.uint(&head, sizes, 4);
    let page_size = lay.uint(&head, sizes.saturating_add(4), 4);
    let page_count = lay.uint(&head, sizes.saturating_add(8), w);
    let release_at = sizes.saturating_add(8).saturating_add(w).saturating_add(8);
    let tail = cx.read_avail(file.sub(release_at, 72)).await?;
    let field = |at: usize, len: usize| {
        String::from_utf8_lossy(trim_end(
            tail.get(at..at.saturating_add(len)).unwrap_or_default(),
        ))
        .into_owned()
    };
    let release = field(0, 8);
    let host = field(8, 16);
    let os_version = field(24, 16);
    let os_maker = field(40, 16);
    let os_name = field(56, 16);
    let time = |v: f64, name: &'static str, at: u64| {
        let node = Node::new(name).span(file.sub(at, 8));
        match date_cell(v, 1.0, SAS_EPOCH, true) {
            Cell::Date { unix_seconds, .. } => node.value(Value::Timestamp { unix_seconds }),
            _ => node.value(Value::Float(v)),
        }
    };
    let text = |name: &'static str, at: u64, len: u64, s: &str| {
        Node::new(name)
            .span(file.sub(at, len))
            .value(Value::Text(s.to_owned()))
    };
    let int = |name: &'static str, at: u64, len: u64, v: u64| {
        Node::new(name).span(file.sub(at, len)).value(Value::UInt {
            value: v,
            bits: u8::try_from(len.saturating_mul(8).min(64)).unwrap_or(64),
            radix: Radix::Dec,
        })
    };
    let header = vec![
        Node::new("Magic").span(file.sub(0, 32)),
        Node::new("Alignment (64-bit)")
            .span(file.sub(32, 1))
            .value(Value::Bool(u64))
            .summary(if u64 {
                "8-byte pointers"
            } else {
                "4-byte pointers"
            }),
        Node::new("Alignment (padding)")
            .span(file.sub(35, 1))
            .value(Value::Bool(pad1 != 0)),
        Node::new("Byte order")
            .span(file.sub(37, 1))
            .value(Value::Enum {
                raw: head.get(37).copied().unwrap_or(0).into(),
                bits: 8,
                name: Some(if endian == Endian::Little {
                    "little-endian"
                } else {
                    "big-endian"
                }),
            }),
        Node::new("Platform")
            .span(file.sub(39, 1))
            .value(Value::Enum {
                raw: head.get(39).copied().unwrap_or(0).into(),
                bits: 8,
                name: match head.get(39) {
                    Some(b'1') => Some("Unix"),
                    Some(b'2') => Some("Windows"),
                    _ => None,
                },
            }),
        Node::new("Encoding")
            .span(file.sub(70, 1))
            .value(Value::Enum {
                raw: encoding_byte.into(),
                bits: 8,
                name: lookup(ENCODINGS, encoding_byte.into()),
            }),
        text(
            "Format",
            84,
            8,
            &String::from_utf8_lossy(head.get(84..92).unwrap_or_default()),
        ),
        text("Dataset name", 92, 64, &name),
        text("File type", 156, 8, &file_type),
        time(created, "Created", t0),
        time(modified, "Modified", t0.saturating_add(8)),
        int("Header size", sizes, 4, header_size),
        int("Page size", sizes.saturating_add(4), 4, page_size),
        int("Page count", sizes.saturating_add(8), w, page_count),
        text("SAS release", release_at, 8, &release),
        text("Host", release_at.saturating_add(8), 16, &host),
        text("OS version", release_at.saturating_add(24), 16, &os_version),
        text("OS maker", release_at.saturating_add(40), 16, &os_maker),
        text("OS name", release_at.saturating_add(56), 16, &os_name),
    ];
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, header_size))
            .summary(format!("{name:?}, release {release}"))
            .lazy(emit_nodes, Arc::new(header)),
    );
    let encoding = match encoding_byte {
        0 => None,
        b => lookup(ENCODINGS, b.into()),
    };
    // Pages that lie beyond the end of the file are not walked.
    let fits = file
        .len
        .saturating_sub(header_size)
        .div_ceil(page_size.max(1));
    let mut sas = Sas {
        lay,
        file,
        header_size,
        page_size,
        page_count: page_count.min(fits),
        encoding,
        row_length: 0,
        row_count: 0,
        mix_rows: 0,
        codec: None,
        columns: Vec::new(),
    };
    let problem = if page_size < lay.page_header() || header_size < 288 {
        Some(
            Diagnostic::malformed(format!(
                "implausible header size {header_size:#x} or page size {page_size:#x}"
            ))
            .at(file.sub(sizes, 8)),
        )
    } else {
        metadata(&cx, &mut sas).await.err()
    };
    let sas = Arc::new(sas);
    cx.emit(
        Node::new("Pages")
            .span(file.tail(header_size))
            .summary(format!("{page_count} × {page_size} bytes"))
            .lazy(pages, sas.clone()),
    );
    let mut columns = Node::new("Columns")
        .summary(format!("{} columns", sas.columns.len()))
        .lazy(columns, sas.clone());
    if let Some(p) = problem {
        columns = columns.diag(p);
    }
    cx.emit(columns);
    if file_type == "DATA" {
        cx.emit(
            Node::new("Rows")
                .summary(format!("{} rows × {} bytes", sas.row_count, sas.row_length))
                .lazy(rows, sas.clone()),
        );
    }
    let compression = match &sas.codec {
        Some(Codec::SasRle) => ", RLE-compressed",
        Some(Codec::SasRdc) => ", RDC-compressed",
        _ => "",
    };
    cx.annotate(format!(
        "SAS {file_type} {name:?}, {} columns × {} rows{compression}, release {release}, {}-bit {}{}",
        sas.columns.len(),
        sas.row_count,
        if u64 { 64 } else { 32 },
        if endian == Endian::Little {
            "little-endian"
        } else {
            "big-endian"
        },
        match date_cell(created, 1.0, SAS_EPOCH, true) {
            Cell::Date { unix_seconds, .. } => format!(", created {}", super::date_string(unix_seconds, true)),
            _ => String::new(),
        }
    ));
    Ok(())
}

/// Collects the row size, column descriptions and compression from the
/// metadata pages (stopping at the first data page, or once all columns
/// are described).
async fn metadata(cx: &Cx, sas: &mut Sas) -> Result<()> {
    let lay = sas.lay;
    let w = lay.w();
    let mut blobs: Vec<Vec<u8>> = Vec::new();
    let mut names = Vec::new();
    let mut attrs: Vec<(u64, u64, bool)> = Vec::new();
    let mut formats = Vec::new();
    let mut columns_expected = None;
    let mut refs = None;
    let mut done = false;
    for i in 0..sas.page_count {
        cx.checkpoint().await;
        let span = sas.page_span(i);
        let raw = cx.read(span).await?;
        let page = parse_page(lay, span, &raw, false);
        if page.kind & 0x0f00 == 0x0100 {
            break;
        }
        for p in &page.pointers {
            let at = p.span.offset.saturating_sub(span.offset);
            let len = p.span.len;
            let sub = raw
                .get(to_usize(at)..to_usize(at.saturating_add(len)))
                .unwrap_or_default();
            match p.kind {
                Kind::RowSize => {
                    sas.row_length = lay.uint(sub, w.saturating_mul(5), w);
                    sas.row_count = lay.uint(sub, w.saturating_mul(6), w);
                    columns_expected = Some(
                        lay.uint(sub, w.saturating_mul(9), w)
                            .saturating_add(lay.uint(sub, w.saturating_mul(10), w)),
                    );
                    sas.mix_rows = lay.uint(sub, w.saturating_mul(15), w);
                    refs = Some(text_ref(lay, sub, len.saturating_sub(118)));
                }
                Kind::ColumnSize => columns_expected = Some(lay.uint(sub, w, w)),
                Kind::ColumnText => blobs.push(sub.get(to_usize(w)..).unwrap_or_default().to_vec()),
                Kind::ColumnNames => {
                    let n = len.saturating_sub(w.saturating_mul(2).saturating_add(12)) / 8;
                    for k in 0..n {
                        names.push(text_ref(
                            lay,
                            sub,
                            w.saturating_add(8).saturating_add(k.saturating_mul(8)),
                        ));
                    }
                }
                Kind::ColumnAttributes => {
                    let size = w.saturating_add(8);
                    let n = len
                        .saturating_sub(w.saturating_mul(2).saturating_add(12))
                        .checked_div(size)
                        .unwrap_or(0);
                    for k in 0..n {
                        let base = w.saturating_add(8).saturating_add(k.saturating_mul(size));
                        attrs.push((
                            lay.uint(sub, base, w),
                            lay.uint(sub, base.saturating_add(w), 4),
                            sub.get(to_usize(base.saturating_add(w).saturating_add(6))) == Some(&1),
                        ));
                    }
                }
                Kind::FormatLabel => {
                    let base = w.saturating_mul(3);
                    formats.push((
                        lay.uint(sub, base.saturating_add(12), 2),
                        lay.uint(sub, base.saturating_add(14), 2),
                        text_ref(lay, sub, base.saturating_add(22)),
                        text_ref(lay, sub, base.saturating_add(28)),
                    ));
                }
                _ => {}
            }
        }
        if let Some(n) = columns_expected
            && sas.row_length != 0
            && to_u64(names.len()) >= n
            && to_u64(attrs.len()) >= n
            && to_u64(formats.len()) >= n
        {
            done = true;
            break;
        }
    }
    if let Some(r) = refs {
        let method = resolve(sas, &blobs, r);
        sas.codec = match method.as_str() {
            "SASYZCRL" => Some(Codec::SasRle),
            "SASYZCR2" => Some(Codec::SasRdc),
            _ => None,
        };
    }
    if sas.codec.is_none() {
        // pandas looks for the literal anywhere in the first text blob.
        let first = blobs.first().map(Vec::as_slice).unwrap_or_default();
        if crate::bytes::contains(first, b"SASYZCRL") {
            sas.codec = Some(Codec::SasRle);
        } else if crate::bytes::contains(first, b"SASYZCR2") {
            sas.codec = Some(Codec::SasRdc);
        }
    }
    let n = names.len().max(attrs.len());
    for k in 0..n {
        if k.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let mut col = Column {
            name: names
                .get(k)
                .map(|r| resolve(sas, &blobs, *r))
                .unwrap_or_default(),
            ..Column::default()
        };
        if let Some(&(offset, width, numeric)) = attrs.get(k) {
            col.offset = offset;
            col.width = width;
            col.numeric = numeric;
        }
        if let Some(&(fw, fd, fmt, label)) = formats.get(k) {
            col.format = resolve(sas, &blobs, fmt);
            col.label = resolve(sas, &blobs, label);
            col.format_width = fw;
            col.format_decimals = fd;
        }
        sas.columns.push(col);
    }
    if !done && sas.page_count > 0 && sas.columns.is_empty() {
        return Err(Diagnostic::malformed("no column descriptions found").at(sas.file));
    }
    Ok(())
}

fn kind_name(kind: Kind) -> String {
    match kind {
        Kind::RowSize => "Row size".to_owned(),
        Kind::ColumnSize => "Column size".to_owned(),
        Kind::Counts => "Subheader counts".to_owned(),
        Kind::ColumnText => "Column text".to_owned(),
        Kind::ColumnNames => "Column names".to_owned(),
        Kind::ColumnAttributes => "Column attributes".to_owned(),
        Kind::FormatLabel => "Format and label".to_owned(),
        Kind::ColumnList => "Column list".to_owned(),
        Kind::Row { compressed: true } => "Compressed row".to_owned(),
        Kind::Row { compressed: false } => "Row".to_owned(),
        Kind::Truncated => "Truncated subheader".to_owned(),
        Kind::Unknown(sig) => lookup(SIGNATURES, sig.into())
            .map_or_else(|| format!("Subheader {sig:#010x}"), str::to_owned),
    }
}

async fn pages(cx: Cx, sas: Arc<Sas>) -> Result<()> {
    cx.set_count(Count::Exact(sas.page_count));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..sas.page_count {
        cx.mark(move || i);
        let span = sas.page_span(i);
        let name = format!("Page {}", i.saturating_add(1));
        if cx.skipping() {
            cx.push(Node::new(name)).await;
            continue;
        }
        let raw = cx
            .read_avail(span.sub(0, sas.page_size.min(1 << 20)))
            .await?;
        let page = parse_page(sas.lay, span, &raw, sas.codec.is_some());
        let kind = lookup(PAGE_TYPES, page.kind.into()).unwrap_or("unknown");
        let mut node = Node::new(name).span(span).summary(format!(
            "{kind}, {} blocks, {} subheaders",
            page.blocks,
            page.pointers.len()
        ));
        if to_u64(raw.len()) < span.len {
            node = node.diag(Diagnostic::truncated(span, to_u64(raw.len())));
        }
        cx.push(node.lazy(page_nodes, (sas.clone(), i))).await;
    }
    Ok(())
}

async fn page_nodes(cx: Cx, (sas, i): (Arc<Sas>, u64)) -> Result<()> {
    let lay = sas.lay;
    let span = sas.page_span(i);
    let raw = cx
        .read_avail(span.sub(0, sas.page_size.min(1 << 20)))
        .await?;
    let page = parse_page(lay, span, &raw, sas.codec.is_some());
    let base = lay.page_header().saturating_sub(8);
    cx.emit(
        Node::new("Page type")
            .span(span.sub(base, 2))
            .value(Value::Enum {
                raw: page.kind.into(),
                bits: 16,
                name: lookup(PAGE_TYPES, page.kind.into()),
            }),
    );
    cx.emit(
        Node::new("Block count")
            .span(span.sub(base.saturating_add(2), 2))
            .value(Value::UInt {
                value: page.blocks.into(),
                bits: 16,
                radix: Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Subheader count")
            .span(span.sub(base.saturating_add(4), 2))
            .value(Value::UInt {
                value: to_u64(page.pointers.len()),
                bits: 16,
                radix: Radix::Dec,
            }),
    );
    for (k, p) in page.pointers.iter().enumerate() {
        let ptr = span.sub(
            lay.page_header()
                .saturating_add(to_u64(k).saturating_mul(lay.pointer())),
            lay.pointer(),
        );
        let mut node = Node::new(kind_name(p.kind))
            .span(p.span)
            .target(p.span)
            .summary(format!(
                "{} bytes, pointer at {:#x}, compression {}",
                p.span.len, ptr.offset, p.compression
            ));
        if let Kind::Row { compressed } = p.kind {
            node = node.lazy(row_in_subheader, (sas.clone(), p.span, compressed));
        } else if p.kind == Kind::RowSize {
            node = node.lazy(row_size_fields, (sas.clone(), p.span));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn row_size_fields(cx: Cx, (sas, span): (Arc<Sas>, Span)) -> Result<()> {
    let w = sas.lay.w();
    let raw = cx.read(span).await?;
    for (name, mult) in [
        ("Row length", 5),
        ("Row count", 6),
        ("Column count (part 1)", 9),
        ("Column count (part 2)", 10),
        ("Rows on a mixed page", 15),
    ] {
        let at = w.saturating_mul(mult);
        cx.emit(Node::new(name).span(span.sub(at, w)).value(Value::UInt {
            value: sas.lay.uint(&raw, at, w),
            bits: 64,
            radix: Radix::Dec,
        }));
    }
    for (name, back) in [
        ("File label (text reference)", 130u64),
        ("Compression (text reference)", 118),
        ("Creator procedure (text reference)", 106),
    ] {
        let at = span.len.saturating_sub(back);
        let (i, o, l) = text_ref(sas.lay, &raw, at);
        cx.emit(
            Node::new(name)
                .span(span.sub(at, 6))
                .summary(format!("blob {i}, offset {o}, {l} bytes")),
        );
    }
    Ok(())
}

async fn row_in_subheader(cx: Cx, (sas, span, compressed): (Arc<Sas>, Span, bool)) -> Result<()> {
    if let Some(node) = decode_row(&cx, &sas, "Row".to_owned(), span, compressed).await? {
        cx.emit(node);
    }
    Ok(())
}

async fn columns(cx: Cx, sas: Arc<Sas>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(sas.columns.len())));
    for col in &sas.columns {
        let kind = if col.numeric { "numeric" } else { "character" };
        let mut parts = vec![format!("{kind}({})", col.width)];
        if !col.format.is_empty() {
            parts.push(format_name(col));
        }
        if !col.label.is_empty() {
            parts.push(format!("{:?}", col.label));
        }
        let uint = |v: u64| Value::UInt {
            value: v,
            bits: 64,
            radix: Radix::Dec,
        };
        let fields = vec![
            Node::new("Name").value(Value::Text(col.name.clone())),
            Node::new("Label").value(Value::Text(col.label.clone())),
            Node::new("Type").value(Value::Text(kind.to_owned())),
            Node::new("Width").value(uint(col.width)),
            Node::new("Offset in row").value(uint(col.offset)),
            Node::new("Format").value(Value::Text(format_name(col))),
        ];
        cx.push(
            Node::new(col.name.clone())
                .summary(parts.join(", "))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

/// `DATE9.`, `DOLLAR12.2`, `$`.
fn format_name(col: &Column) -> String {
    let mut s = col.format.clone();
    if s.is_empty() {
        return s;
    }
    if col.format_width != 0 {
        s.push_str(&col.format_width.to_string());
    }
    s.push('.');
    if col.format_decimals != 0 {
        s.push_str(&col.format_decimals.to_string());
    }
    s
}

fn cell(sas: &Sas, col: &Column, raw: &[u8]) -> Cell {
    if !col.numeric {
        return Cell::Text(sas.text(trim_end(raw)));
    }
    let width = raw.len().min(8);
    let mut full = [0u8; 8];
    let src = raw.get(..width).unwrap_or_default();
    match sas.lay.endian {
        Endian::Little => {
            for (o, b) in full.iter_mut().skip(8usize.saturating_sub(width)).zip(src) {
                *o = *b;
            }
        }
        Endian::Big => {
            for (o, b) in full.iter_mut().zip(src) {
                *o = *b;
            }
        }
    }
    let bits = match sas.lay.endian {
        Endian::Little => u64::from_le_bytes(full),
        Endian::Big => u64::from_be_bytes(full),
    };
    let v = f64::from_bits(bits);
    if v.is_nan() {
        let tag = !((bits >> 40) as u8);
        let name = match tag {
            b'A'..=b'Z' | b'_' => format!(".{}", char::from(tag)),
            _ => ".".to_owned(),
        };
        return Cell::Missing { name, raw: None };
    }
    let upper = col.format.to_ascii_uppercase();
    if DATE_FORMATS.contains(&upper.as_str()) {
        date_cell(v, 86_400.0, SAS_EPOCH, false)
    } else if DATETIME_FORMATS.contains(&upper.as_str()) {
        date_cell(v, 1.0, SAS_EPOCH, true)
    } else {
        Cell::Number(v)
    }
}

/// Decodes the row in `span` (decompressing it first if needed); `None`
/// if it is a deleted or empty slot.
async fn decode_row(
    cx: &Cx,
    sas: &Sas,
    name: String,
    span: Span,
    compressed: bool,
) -> Result<Option<Node>> {
    let (span, raw) = if compressed && span.len < sas.row_length {
        let codec = sas.codec.clone().unwrap_or(Codec::SasRle);
        let decoded = crate::codec::decode_span(cx, span, &codec, Some(sas.row_length)).await?;
        let raw = cx.read(decoded.span).await?;
        if let Some(e) = decoded.error
            && e.kind != crate::error::DiagKind::Warning
        {
            return Ok(Some(Node::new(name).span(span).diag(e)));
        }
        (decoded.span, raw)
    } else {
        (span, cx.read(span).await?)
    };
    let mut items = Vec::new();
    for (i, col) in sas.columns.iter().enumerate() {
        if i > 0 && i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let start = to_usize(col.offset);
        let bytes = raw
            .get(start..start.saturating_add(to_usize(col.width)))
            .unwrap_or_default();
        items.push(Item {
            name: col.name.clone(),
            cell: cell(sas, col, bytes),
            label: None,
            span: span.sub(col.offset, col.width),
        });
    }
    Ok(Some(row_node(name, span, items)))
}

/// Where rows are on a page: the rows that subheader pointers locate
/// ((span, compressed) in order), then `regular` uncompressed rows from
/// `page.rows_at`.
struct PageRows {
    pointed: Vec<(Span, bool)>,
    regular: u64,
}

impl PageRows {
    fn len(&self) -> u64 {
        to_u64(self.pointed.len()).saturating_add(self.regular)
    }

    /// The `k`th row on the page.
    fn get(&self, sas: &Sas, span: Span, page: &Page, k: u64) -> Option<(Span, bool)> {
        match k.checked_sub(to_u64(self.pointed.len())) {
            None => self.pointed.get(to_usize(k)).copied(),
            Some(r) if r < self.regular => Some((
                span.sub(
                    page.rows_at
                        .saturating_add(r.saturating_mul(sas.row_length)),
                    sas.row_length,
                ),
                false,
            )),
            Some(_) => None,
        }
    }
}

/// Where rows are on a page (at most `remaining`), without listing the
/// regular rows, which may be many.
fn page_rows(sas: &Sas, span: Span, page: &Page, remaining: u64) -> PageRows {
    let mut out = Vec::new();
    for p in &page.pointers {
        if let Kind::Row { compressed } = p.kind {
            out.push((p.span, compressed));
        }
    }
    let on_page = match page.kind & 0x0f00 {
        _ if page.kind & 0x9000 == 0x9000 => 0,
        0x0100 => u64::from(page.blocks),
        0x0200 => sas.mix_rows.min(remaining),
        _ => 0,
    };
    let fit = span
        .len
        .saturating_sub(page.rows_at)
        .checked_div(sas.row_length)
        .unwrap_or(0);
    out.truncate(to_usize(remaining));
    let regular = on_page
        .min(fit)
        .min(remaining.saturating_sub(to_u64(out.len())));
    PageRows {
        pointed: out,
        regular,
    }
}

async fn rows(cx: Cx, sas: Arc<Sas>) -> Result<()> {
    if sas.row_length == 0 {
        return Ok(());
    }
    cx.set_count(Count::Exact(sas.row_count));
    let (mut page_index, mut first, mut row) =
        cx.resume::<(u64, usize, u64)>().unwrap_or((0, 0, 0));
    while page_index < sas.page_count && row < sas.row_count {
        cx.checkpoint().await;
        let span = sas.page_span(page_index);
        let raw = cx
            .read_avail(span.sub(0, sas.page_size.min(1 << 20)))
            .await?;
        let page = parse_page(sas.lay, span, &raw, sas.codec.is_some());
        let found = page_rows(&sas, span, &page, sas.row_count.saturating_sub(row));
        for k in to_u64(first)..found.len() {
            let Some((rspan, compressed)) = found.get(&sas, span, &page, k) else {
                break;
            };
            let k = to_usize(k);
            let state = (page_index, k, row);
            cx.mark(move || state);
            let name = format!("Row {}", row.saturating_add(1));
            row = row.saturating_add(1);
            if cx.skipping() {
                cx.push(Node::new(name)).await;
                continue;
            }
            let node = match decode_row(&cx, &sas, name.clone(), rspan, compressed).await {
                Ok(Some(n)) => n,
                Ok(None) => continue,
                Err(e) => Node::new(name).span(rspan).diag(e),
            };
            cx.push(node).await;
        }
        first = 0;
        page_index = page_index.saturating_add(1);
    }
    if row < sas.row_count {
        cx.diag(Diagnostic::malformed(format!(
            "found {row} of {} rows",
            sas.row_count
        )));
    }
    Ok(())
}
