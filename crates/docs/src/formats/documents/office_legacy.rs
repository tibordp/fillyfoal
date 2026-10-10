//! Legacy office and productivity formats: Lotus 1-2-3, Quattro Pro, Works
//! and Excel 2–4 worksheets (record streams; Excel's decoded by the BIFF
//! code in `cfb::biff`), ClarisWorks/AppleWorks and
//! SketchUp headers, and the text interchange formats of the era: SYLK, DIF,
//! Quicken QIF, OFX, Microsoft Project MPX and Ami Pro documents.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::clip;
use crate::formats::util::val::{hex, text};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

/// Spreadsheet column letters (0 = A, 26 = AA).
fn column_name(mut col: u32) -> String {
    let mut out = Vec::new();
    loop {
        out.push(char::from(
            b'A'.saturating_add(u8::try_from(col % 26).unwrap_or(0)),
        ));
        if col < 26 {
            break;
        }
        col = (col / 26).saturating_sub(1);
    }
    out.iter().rev().collect()
}

fn cell_name(col: u32, row: u32) -> String {
    format!("{}{}", column_name(col), row.saturating_add(1))
}

fn float(v: f64) -> Value {
    Value::Float(v)
}

/// An 80-bit x87 extended float (Lotus WK3+ numbers).
fn extended(b: &[u8]) -> f64 {
    let mantissa = u64_le(b, 0).unwrap_or(0);
    let se = u16_le(b, 8).unwrap_or(0);
    let exp = i32::from(se & 0x7fff);
    if mantissa == 0 && exp == 0 {
        return 0.0;
    }
    let v = mantissa as f64 * 2f64.powi(exp.saturating_sub(16383 + 63));
    if se & 0x8000 != 0 { -v } else { v }
}

/// Lines of a text file with their offsets (terminators excluded from the
/// text, included in the length).
fn lines(data: &[u8]) -> impl Iterator<Item = (u64, u64, &[u8])> {
    let mut at = 0usize;
    data.split_inclusive(|&b| b == b'\n').map(move |line| {
        let start = at;
        at = at.saturating_add(line.len());
        let mut body = line;
        while let Some((&last, rest)) = body.split_last() {
            if last == b'\n' || last == b'\r' {
                body = rest;
            } else {
                break;
            }
        }
        (to_u64(start), to_u64(line.len()), body)
    })
}

fn lossy(b: &[u8]) -> String {
    String::from_utf8_lossy(b).into_owned()
}

// ---------------------------------------------------------------------------
// Lotus 1-2-3 WKS/WK1, Symphony, Quattro Pro (DOS) and Works spreadsheets

fn lotus_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x00\x00\x02\x00")
        && u16_le(h.data, 4).is_some_and(|v| (0x0404..=0x0406).contains(&v))
}

fn quattro_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x00\x00\x02\x00")
        && u16_le(h.data, 4).is_some_and(|v| matches!(v, 0x5120 | 0x5121 | 0x1001 | 0x1002))
}

fn lotus3_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x00\x00\x1a\x00")
        && u16_le(h.data, 4).is_some_and(|v| (0x1000..=0x1005).contains(&v))
}

declare_format!(pub LOTUS = "lotus123", "Lotus 1-2-3 worksheet (WKS/WK1)", ["wks", "wk1", "wrk", "wr1"], "application/vnd.lotus-1-2-3",
    Probe::Custom(lotus_probe), lotus);
declare_format!(pub LOTUS3 = "lotus123-wk3", "Lotus 1-2-3 worksheet (WK3/WK4/123)", ["wk3", "wk4", "123"], "application/vnd.lotus-1-2-3",
    Probe::Custom(lotus3_probe), lotus);
declare_format!(pub QUATTRO = "quattro-pro", "Quattro Pro spreadsheet (WQ1/WQ2/WB1/WB2)", ["wq1", "wq2", "wb1", "wb2"], "application/x-quattro-pro",
    Probe::Custom(quattro_probe), lotus);
declare_format!(pub WORKS_WKS = "works-spreadsheet", "Microsoft Works spreadsheet", ["wks"], "application/vnd.ms-works",
    Probe::Magic(&[(0, b"\xff\x00\x02\x00\x04\x04")]), lotus);

const LOTUS_VERSIONS: EnumTable = &[
    (0x0404, "1-2-3 release 1A (WKS)"),
    (0x0405, "Symphony 1.0 (WRK)"),
    (0x0406, "1-2-3 release 2 / Symphony 1.1 (WK1/WR1)"),
    (0x1000, "1-2-3 release 3 (WK3)"),
    (0x1002, "1-2-3 release 4/5 (WK4)"),
    (0x1003, "1-2-3 97"),
    (0x1005, "1-2-3 Millennium"),
];

const QUATTRO_VERSIONS: EnumTable = &[
    (0x5120, "Quattro Pro for DOS (WQ1)"),
    (0x5121, "Quattro Pro 5 for DOS (WQ2)"),
    (0x1001, "Quattro Pro for Windows 1.0 (WB1)"),
    (0x1002, "Quattro Pro for Windows 5 (WB2)"),
];

const LOTUS_RECORDS: EnumTable = &[
    (0x00, "BOF"),
    (0x01, "EOF"),
    (0x02, "CALCMODE"),
    (0x03, "CALCORDER"),
    (0x04, "SPLIT"),
    (0x05, "SYNC"),
    (0x06, "RANGE"),
    (0x07, "WINDOW1"),
    (0x08, "COLW1"),
    (0x09, "WINTWO"),
    (0x0a, "COLW2"),
    (0x0b, "NAME"),
    (0x0c, "BLANK"),
    (0x0d, "INTEGER"),
    (0x0e, "NUMBER"),
    (0x0f, "LABEL"),
    (0x10, "FORMULA"),
    (0x18, "TABLE"),
    (0x19, "ORANGE"),
    (0x1a, "PRANGE"),
    (0x1b, "SRANGE"),
    (0x1c, "FRANGE"),
    (0x1d, "KRANGE"),
    (0x20, "HRANGE"),
    (0x23, "KRANGE2"),
    (0x24, "PROTEC"),
    (0x25, "FOOTER"),
    (0x26, "HEADER"),
    (0x27, "SETUP"),
    (0x28, "MARGINS"),
    (0x29, "LABELFMT"),
    (0x2a, "TITLES"),
    (0x2d, "GRAPH"),
    (0x2e, "NGRAPH"),
    (0x2f, "CALCCOUNT"),
    (0x30, "UNFORMATTED"),
    (0x31, "CURSORW12"),
    (0x32, "WINDOW"),
    (0x33, "STRING"),
    (0x37, "PASSWORD"),
    (0x38, "LOCKED"),
    (0x3c, "QUERY"),
    (0x3d, "QUERYNAME"),
    (0x3e, "PRINT"),
    (0x3f, "PRINTNAME"),
    (0x40, "GRAPH2"),
    (0x41, "GRAPHNAME"),
    (0x42, "ZOOM"),
    (0x43, "SYMSPLIT"),
    (0x44, "NSROWS"),
    (0x45, "NSCOLS"),
    (0x46, "RULER"),
    (0x47, "NNAME"),
    (0x48, "ACOMM"),
    (0x49, "AMACRO"),
    (0x4a, "PARSE"),
    (0x64, "HIDVEC1"),
    (0x65, "HIDVEC2"),
    (0x66, "PARSERANGES"),
    (0x67, "RRANGES"),
    (0x69, "MATRIXRANGES"),
    (0xff, "BOF (Works)"),
];

/// WK3 and later reuse the framing but renumber the cell records.
const LOTUS3_RECORDS: EnumTable = &[
    (0x00, "BOF"),
    (0x01, "EOF"),
    (0x02, "PASSWORD"),
    (0x03, "CALCSET"),
    (0x04, "WINDOWSET"),
    (0x05, "SHEETCELLPTR"),
    (0x06, "SHEETLAYOUT"),
    (0x07, "COLUMNWIDTH"),
    (0x09, "NAMEDRANGE"),
    (0x0a, "SYSTEMRANGE"),
    (0x0b, "ZEROFORCE"),
    (0x0c, "SORTKEYDIR"),
    (0x0d, "FILESEAL"),
    (0x0e, "DATAFILLNUMS"),
    (0x0f, "PRINTMAIN"),
    (0x10, "PRINTSTRING"),
    (0x11, "GRAPHMAIN"),
    (0x12, "GRAPHSTRING"),
    (0x13, "FORMAT"),
    (0x14, "ERRCELL"),
    (0x15, "NACELL"),
    (0x16, "LABEL"),
    (0x17, "NUMBER"),
    (0x18, "SMALLNUMBER"),
    (0x19, "FORMULA"),
    (0x1a, "FORMULASTRING"),
    (0x1b, "EXTENDED"),
    (0x1c, "DTLABELMISC"),
    (0x1d, "DTLABELCELL"),
    (0x1e, "GRAPHWINDOW"),
    (0x1f, "CPA"),
    (0x20, "LPLAUTO"),
    (0x21, "QUERY"),
    (0x22, "HIDDENSHEET"),
    (0x23, "NAMEDSHEET"),
];

/// A decoded cell: (address, value, label prefix or formula note).
fn lotus_cell(kind: u16, wk3: bool, data: &[u8]) -> Option<(String, Value)> {
    if wk3 {
        let row = u32::from(u16_le(data, 0)?);
        let sheet = data.get(2).copied()?;
        let col = u32::from(data.get(3).copied()?);
        let addr = if sheet == 0 {
            cell_name(col, row)
        } else {
            format!("{}:{}", column_name(u32::from(sheet)), cell_name(col, row))
        };
        let rest = data.get(4..)?;
        let value = match kind {
            0x16 => text(lotus_label(rest)),
            0x17 | 0x19 => float(extended(rest)),
            0x18 => {
                let raw = u16_le(rest, 0)?;
                if raw & 1 == 0 {
                    Value::Int {
                        value: i64::from(i16::from_le_bytes(raw.to_le_bytes()) >> 1),
                        bits: 16,
                    }
                } else {
                    hex(raw, 16)
                }
            }
            _ => return None,
        };
        return Some((addr, value));
    }
    let col = u32::from(u16_le(data, 1)?);
    let row = u32::from(u16_le(data, 3)?);
    let rest = data.get(5..)?;
    let value = match kind {
        0x0c => text(""),
        0x0d => Value::Int {
            value: i64::from(crate::bytes::i16_le(rest, 0)?),
            bits: 16,
        },
        0x0e | 0x10 => float(f64::from_bits(u64_le(rest, 0)?)),
        0x0f | 0x33 => text(lotus_label(rest)),
        _ => return None,
    };
    Some((cell_name(col, row), value))
}

/// A label: alignment prefix (', ", ^ or \) and NUL-terminated text.
fn lotus_label(b: &[u8]) -> String {
    let s = crate::text::latin1(b.split(|&c| c == 0).next().unwrap_or_default());
    match s.chars().next() {
        Some('\'' | '"' | '^' | '\\' | '|') => s.chars().skip(1).collect(),
        _ => s,
    }
}

async fn lotus(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 6)).await?;
    let version = u16_le(&head, 4).unwrap_or(0);
    let wk3 = u16_le(&head, 2) == Some(0x1a);
    let works = head.first() == Some(&0xff);
    let table = if wk3 { LOTUS3_RECORDS } else { LOTUS_RECORDS };
    let versions = if !wk3 && matches!(version, 0x5120 | 0x5121 | 0x1001 | 0x1002) {
        QUATTRO_VERSIONS
    } else {
        LOTUS_VERSIONS
    };
    let mut cur = Cursor::new(&cx, file, LE);
    let (mut records, mut cells) = (0u64, 0u64);
    let mut dims = None;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let kind = cur.u16().await?;
        let len = u64::from(cur.u16().await?);
        let body = cur.span(len);
        let data = cur.bytes(len).await?;
        records = records.saturating_add(1);
        let name =
            lookup(table, kind.into()).map_or_else(|| format!("Record {kind:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start)).target(body);
        if let Some((addr, value)) = lotus_cell(kind, wk3, &data) {
            cells = cells.saturating_add(1);
            node = Node::new(addr)
                .span(cur.since(start))
                .target(body)
                .value(value)
                .desc(lookup(table, kind.into()).unwrap_or("cell"));
        } else {
            match (kind, wk3) {
                (0x00 | 0xff, _) => {
                    node = node.value(Value::Enum {
                        raw: u16_le(&data, 0).unwrap_or(0).into(),
                        bits: 16,
                        name: lookup(versions, u16_le(&data, 0).unwrap_or(0).into()),
                    })
                }
                (0x06, false) => {
                    let c = |i: usize| u32::from(u16_le(&data, i).unwrap_or(0));
                    let range = format!("{}:{}", cell_name(c(0), c(2)), cell_name(c(4), c(6)));
                    dims = Some(range.clone());
                    node = node.value(text(range));
                }
                (0x0b | 0x47, false) => {
                    node = node.value(text(crate::text::until_nul(
                        data.get(..16).unwrap_or(&data),
                    )))
                }
                (0x25 | 0x26, false) => node = node.value(text(crate::text::until_nul(&data))),
                _ => node = node.summary(format!("{len} bytes")),
            }
        }
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(node).await;
        if kind == 0x01 {
            break;
        }
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    let product = lookup(versions, version.into()).unwrap_or("unknown version");
    cx.annotate(format!(
        "{}{product}, {records} records, {cells} cells{}",
        if works {
            "Microsoft Works spreadsheet, "
        } else {
            ""
        },
        dims.map(|d| format!(", range {d}")).unwrap_or_default()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Excel 2.x–4.0 worksheets (standalone BIFF2/3/4 streams)

fn biff_probe(h: &Head<'_>) -> bool {
    let doc_type =
        |at: usize| u16_le(h.data, at).is_some_and(|t| matches!(t, 0x10 | 0x20 | 0x40 | 0x100));
    (h.starts_with(b"\x09\x00\x04\x00") && doc_type(6))
        || ((h.starts_with(b"\x09\x02\x06\x00") || h.starts_with(b"\x09\x04\x06\x00"))
            && doc_type(6))
}

declare_format!(pub XLS_BIFF = "xls-biff", "Excel 2.x–4.0 worksheet (BIFF2–4)", ["xls", "xlw", "xlc", "xlm"], "application/vnd.ms-excel",
    Probe::Custom(biff_probe), biff);

/// The records are named, summarised and decoded by the workbook-stream
/// code, version by version.
async fn biff(cx: Cx, input: Input) -> Result<()> {
    crate::formats::cfb::biff::early_stream(cx, input).await
}

// ---------------------------------------------------------------------------
// ClarisWorks / AppleWorks 5–6

fn cwk_probe(h: &Head<'_>) -> bool {
    h.at(4, b"BOBO") && h.data.first().is_some_and(|&v| (1..=6).contains(&v))
}

declare_format!(pub CLARISWORKS = "clarisworks", "ClarisWorks / AppleWorks document", ["cwk", "cws"], "application/x-appleworks",
    Probe::Custom(cwk_probe), clarisworks);

async fn clarisworks(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, Endian::Big);
    let version = f.u8("Version").emit()?;
    f.bytes("Version details", 3).emit()?;
    f.ascii("Signature", 4).emit()?;
    cx.emit(
        Node::new("Document data")
            .span(file.tail(8))
            .diag(Diagnostic::note("zones are not dissected")),
    );
    let product = match version {
        1..=4 => "ClarisWorks",
        5 => "AppleWorks 5",
        _ => "AppleWorks 6",
    };
    cx.annotate(format!("{product} document (format version {version})"));
    Ok(())
}

// ---------------------------------------------------------------------------
// SYLK (symbolic link interchange: Multiplan, Excel)

declare_format!(pub SYLK = "sylk", "Symbolic Link spreadsheet (SYLK)", ["slk", "sylk"], "application/x-sylk",
    Probe::Magic(&[(0, b"ID;P")]), sylk);

const SYLK_RECORDS: &[(&str, &str)] = &[
    ("ID", "Identification"),
    ("C", "Cell"),
    ("F", "Format"),
    ("B", "Bounds"),
    ("O", "Options"),
    ("P", "Picture format"),
    ("NN", "Name"),
    ("NE", "External link"),
    ("NU", "Filename substitution"),
    ("W", "Window"),
    ("E", "End"),
];

/// Splits a SYLK record into fields at unescaped ';' (";;" is a literal).
fn sylk_fields(line: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut i = 0usize;
    while let Some(&c) = line.get(i) {
        if c == b';' {
            if line.get(i.saturating_add(1)) == Some(&b';') {
                cur.push(b';');
                i = i.saturating_add(2);
                continue;
            }
            out.push(crate::text::latin1(&cur));
            cur.clear();
        } else {
            cur.push(c);
        }
        i = i.saturating_add(1);
    }
    out.push(crate::text::latin1(&cur));
    out
}

async fn sylk(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let (mut x, mut y) = (1u32, 1u32);
    let (mut cells, mut program, mut bounds) = (0u64, String::new(), String::new());
    for (n, (at, len, line)) in lines(&data).enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if line.is_empty() {
            continue;
        }
        let fields = sylk_fields(line);
        let kind = fields.first().cloned().unwrap_or_default();
        let span = file.sub(at, len);
        let name = SYLK_RECORDS
            .iter()
            .find(|(k, _)| *k == kind)
            .map_or_else(|| format!("Record {kind}"), |(_, n)| (*n).to_owned());
        let mut node = Node::new(name).span(span).value(text(lossy(line)));
        match kind.as_str() {
            "ID" => {
                program = fields
                    .iter()
                    .find_map(|f| f.strip_prefix('P'))
                    .unwrap_or_default()
                    .to_owned()
            }
            "B" => {
                let rows = fields
                    .iter()
                    .find_map(|f| f.strip_prefix('Y'))
                    .unwrap_or("?");
                let cols = fields
                    .iter()
                    .find_map(|f| f.strip_prefix('X'))
                    .unwrap_or("?");
                bounds = format!("{rows} rows × {cols} columns");
            }
            "C" | "F" => {
                for f in fields.iter().skip(1) {
                    if let Some(v) = f.strip_prefix('X') {
                        x = v.parse().unwrap_or(x);
                    } else if let Some(v) = f.strip_prefix('Y') {
                        y = v.parse().unwrap_or(y);
                    }
                }
                if kind == "C" {
                    cells = cells.saturating_add(1);
                    let value = fields
                        .iter()
                        .find_map(|f| f.strip_prefix('K'))
                        .map(|v| v.trim_matches('"').to_owned());
                    let formula = fields.iter().find_map(|f| f.strip_prefix('E'));
                    node = Node::new(cell_name(x.saturating_sub(1), y.saturating_sub(1)))
                        .span(span)
                        .desc("Cell");
                    node = match value {
                        Some(v) => {
                            node.value(v.parse::<f64>().map_or_else(|_| text(v.clone()), float))
                        }
                        None => node,
                    };
                    if let Some(e) = formula {
                        node = node.summary(format!("={e}"));
                    }
                }
            }
            _ => {}
        }
        cx.progress_in(file, file.offset.saturating_add(at));
        cx.push(node).await;
        if kind == "E" {
            break;
        }
    }
    cx.annotate(format!(
        "SYLK spreadsheet from {}, {cells} cells{}",
        if program.is_empty() {
            "unknown program"
        } else {
            &program
        },
        if bounds.is_empty() {
            String::new()
        } else {
            format!(", {bounds}")
        }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// DIF (Data Interchange Format, VisiCalc)

declare_format!(pub DIF = "dif", "Data Interchange Format (DIF)", ["dif"], "text/x-dif",
    Probe::Magic(&[(0, b"TABLE\r\n0,1\r\n\""), (0, b"TABLE\n0,1\n\"")]), dif);

/// The DIF stream as (header item | data value) entries.
#[derive(Clone, Debug)]
struct DifItem {
    start: u64,
    end: u64,
    topic: String,
    number: String,
    string: String,
}

async fn dif_items(cx: &Cx, data: &[u8]) -> Vec<DifItem> {
    let mut all: Vec<(u64, u64, &[u8])> = Vec::new();
    for line in lines(data) {
        if all.len() % 4096 == 4095 {
            cx.checkpoint().await;
        }
        all.push(line);
    }
    let mut out = Vec::new();
    let mut i = 0usize;
    let mut in_data = false;
    // Header items are three lines (topic, "vector,value", string); data
    // values are two ("type,number", string or keyword).
    while let Some(&(start, _, first)) = all.get(i) {
        let take = if in_data { 2 } else { 3 };
        let Some(&(last_at, last_len, _)) = all.get(i.saturating_add(take).saturating_sub(1))
        else {
            break;
        };
        let get = |k: usize| {
            all.get(i.saturating_add(k))
                .map(|l| crate::text::latin1(l.2))
                .unwrap_or_default()
        };
        let item = if in_data {
            DifItem {
                start,
                end: last_at.saturating_add(last_len),
                topic: String::new(),
                number: get(0),
                string: get(1),
            }
        } else {
            DifItem {
                start,
                end: last_at.saturating_add(last_len),
                topic: crate::text::latin1(first),
                number: get(1),
                string: get(2),
            }
        };
        if item.topic == "DATA" {
            in_data = true;
        }
        let end_of_data = in_data && item.string == "EOD";
        if out.len() % 1024 == 1023 {
            cx.checkpoint().await;
        }
        out.push(item);
        i = i.saturating_add(take);
        if end_of_data || out.len() > 1_000_000 {
            break;
        }
    }
    out
}

async fn dif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let items = Arc::new(dif_items(&cx, &data).await);
    let header_end = items
        .iter()
        .position(|it| it.topic == "DATA")
        .map_or(items.len(), |p| p.saturating_add(1));
    let (mut vectors, mut tuples, mut title) = (String::new(), String::new(), String::new());
    for it in items.iter().take(header_end) {
        let value = it.number.split(',').nth(1).unwrap_or_default().to_owned();
        match it.topic.as_str() {
            "VECTORS" => vectors = value.clone(),
            "TUPLES" => tuples = value.clone(),
            "TABLE" => title = it.string.trim_matches('"').to_owned(),
            _ => {}
        }
        let mut node = Node::new(it.topic.clone())
            .span(file.sub(it.start, it.end.saturating_sub(it.start)))
            .value(text(value));
        let label = it.string.trim_matches('"');
        if !label.is_empty() {
            node = node.summary(label.to_owned());
        }
        cx.push(node).await;
    }
    // Rows start at a BOT marker ("-1,0" then "BOT").
    let mut rows = Vec::new();
    for (i, it) in items.iter().enumerate().skip(header_end) {
        if i % 4096 == 4095 {
            cx.checkpoint().await;
        }
        if it.number.starts_with("-1") && it.string == "BOT" {
            rows.push(i);
        }
    }
    for (r, &first) in rows.iter().enumerate() {
        let last = rows
            .get(r.saturating_add(1))
            .copied()
            .unwrap_or(items.len());
        let start = items.get(first).map_or(0, |it| it.start);
        let end = items.get(last.saturating_sub(1)).map_or(start, |it| it.end);
        cx.push(
            Node::new(format!("Row {}", r.saturating_add(1)))
                .span(file.sub(start, end.saturating_sub(start)))
                .lazy(dif_row, (file, items.clone(), first, last)),
        )
        .await;
    }
    cx.annotate(format!(
        "DIF table {title:?}, {vectors} columns × {tuples} rows"
    ));
    Ok(())
}

async fn dif_row(
    cx: Cx,
    (file, items, first, last): (Span, Arc<Vec<DifItem>>, usize, usize),
) -> Result<()> {
    let mut col = 0u32;
    for it in items.iter().take(last).skip(first.saturating_add(1)) {
        cx.checkpoint().await;
        let (kind, number) = it.number.split_once(',').unwrap_or((&it.number, ""));
        let value = match kind {
            "0" if it.string == "V" => number.parse::<f64>().map_or_else(|_| text(number), float),
            "0" => text(format!("{number} ({})", it.string)),
            "1" => text(it.string.trim_matches('"')),
            _ => continue,
        };
        cx.push(
            Node::new(format!("Column {}", column_name(col)))
                .span(file.sub(it.start, it.end.saturating_sub(it.start)))
                .value(value),
        )
        .await;
        col = col.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Quicken Interchange Format (QIF)

fn qif_probe(h: &Head<'_>) -> bool {
    let d = h.data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h.data);
    d.starts_with(b"!Type:")
        || d.starts_with(b"!Account")
        || d.starts_with(b"!Option:")
        || d.starts_with(b"!Clear:")
}

declare_format!(pub QIF = "qif", "Quicken Interchange Format", ["qif"], "application/x-qif",
    Probe::Custom(qif_probe), qif);

const QIF_FIELDS: &[(u8, &str)] = &[
    (b'D', "Date"),
    (b'T', "Amount"),
    (b'U', "Amount (alternate)"),
    (b'C', "Cleared status"),
    (b'N', "Number / action"),
    (b'P', "Payee"),
    (b'M', "Memo"),
    (b'A', "Address"),
    (b'L', "Category / transfer"),
    (b'S', "Split category"),
    (b'E', "Split memo"),
    (b'$', "Split amount"),
    (b'%', "Split percentage"),
    (b'Y', "Security"),
    (b'I', "Price"),
    (b'Q', "Quantity"),
    (b'O', "Commission"),
    (b'B', "Balance / budget"),
];

async fn qif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let mut section: Option<(String, u64)> = None;
    let mut entry_start: Option<u64> = None;
    let mut entry: Vec<(u64, u64)> = Vec::new();
    let mut summary = (String::new(), String::new(), String::new());
    let (mut entries, mut sections) = (0u64, Vec::new());
    for (n, (at, len, line)) in lines(&data).enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if let Some(header) = line.strip_prefix(b"!") {
            let name = lossy(header);
            cx.push(
                Node::new(format!("!{name}"))
                    .span(file.sub(at, len))
                    .desc("Section header"),
            )
            .await;
            sections.push(name.clone());
            section = Some((name, at));
            continue;
        }
        if line.first() == Some(&b'^') {
            let start = entry_start.take().unwrap_or(at);
            let span = file.sub(start, at.saturating_add(len).saturating_sub(start));
            let (date, amount, payee) = std::mem::take(&mut summary);
            let name = if payee.is_empty() {
                format!("Entry {entries}")
            } else {
                payee
            };
            let mut node = Node::new(name)
                .span(span)
                .lazy(qif_entry, (file, std::mem::take(&mut entry)));
            if !amount.is_empty() {
                node = node.value(text(amount));
            }
            if !date.is_empty() {
                node = node.summary(date);
            }
            cx.progress_in(file, file.offset.saturating_add(at));
            cx.push(node).await;
            entries = entries.saturating_add(1);
            continue;
        }
        if line.is_empty() {
            continue;
        }
        entry_start.get_or_insert(at);
        entry.push((at, len));
        let value = lossy(line.get(1..).unwrap_or_default());
        match line.first() {
            Some(b'D') => summary.0 = value,
            Some(b'T') => summary.1 = value,
            Some(b'P') => summary.2 = value,
            Some(b'N') if summary.2.is_empty() => summary.2 = value,
            _ => {}
        }
    }
    let _ = section;
    cx.annotate(format!(
        "Quicken QIF, {entries} entries ({})",
        sections.join(", ")
    ));
    Ok(())
}

async fn qif_entry(cx: Cx, (file, list): (Span, Vec<(u64, u64)>)) -> Result<()> {
    for (at, len) in list {
        let line = cx.read(file.sub(at, len)).await?;
        let code = line.first().copied().unwrap_or(b'?');
        let name = QIF_FIELDS.iter().find(|(c, _)| *c == code).map_or_else(
            || format!("Field {}", char::from(code)),
            |(_, n)| (*n).to_owned(),
        );
        let value = lossy(line.get(1..).unwrap_or_default());
        cx.push(
            Node::new(name)
                .span(file.sub(at, len))
                .value(text(value.trim_end())),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Open Financial Exchange (OFX 1.x SGML and 2.x XML; QFX, QBO)

fn ofx_probe(h: &Head<'_>) -> bool {
    let d = h.data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h.data);
    let d = d
        .get(d.iter().position(|b| !b.is_ascii_whitespace()).unwrap_or(0)..)
        .unwrap_or_default();
    d.starts_with(b"OFXHEADER:")
        || (d.starts_with(b"<?xml")
            && d.get(..512)
                .unwrap_or(d)
                .windows(16)
                .any(|w| w == b"<?OFX OFXHEADER="))
}

declare_format!(pub OFX = "ofx", "Open Financial Exchange statement", ["ofx", "qfx", "qbo"], "application/x-ofx",
    Probe::Custom(ofx_probe), ofx);

#[derive(Clone, Debug, Default)]
struct MarkupElement {
    name: String,
    start: u64,
    end: u64,
    value: Option<String>,
    children: Vec<usize>,
}

#[derive(Debug, Default)]
struct Markup {
    elements: Vec<MarkupElement>,
    roots: Vec<usize>,
    /// Where the body starts (`<OFX>`).
    body: usize,
}

/// Parses SGML-style markup where leaf elements may lack end tags.
async fn markup_parse(cx: &Cx, data: &[u8], from: usize) -> Markup {
    let mut doc = Markup {
        body: from,
        ..Markup::default()
    };
    let mut stack: Vec<usize> = Vec::new();
    let mut i = from;
    let mut steps = 0u32;
    while let Some(lt) = data
        .get(i..)
        .and_then(|r| r.iter().position(|&b| b == b'<'))
    {
        let open = i.saturating_add(lt);
        let Some(gt) = data
            .get(open..)
            .and_then(|r| r.iter().position(|&b| b == b'>'))
        else {
            break;
        };
        let close = open.saturating_add(gt);
        let tag = data.get(open.saturating_add(1)..close).unwrap_or_default();
        i = close.saturating_add(1);
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        if tag.starts_with(b"?") || tag.starts_with(b"!") {
            continue;
        }
        // A leaf on top of the stack ends where the next tag begins.
        let pop_leaf = |doc: &mut Markup, stack: &mut Vec<usize>| {
            if let Some(&top) = stack.last()
                && doc.elements.get(top).is_some_and(|e| e.value.is_some())
            {
                stack.pop();
            }
        };
        if let Some(name) = tag.strip_prefix(b"/") {
            let name = lossy(name);
            while let Some(top) = stack.pop() {
                let Some(e) = doc.elements.get_mut(top) else {
                    break;
                };
                e.end = to_u64(i);
                if e.name == name {
                    break;
                }
            }
            continue;
        }
        pop_leaf(&mut doc, &mut stack);
        let name = lossy(tag.split(|&b| b == b' ').next().unwrap_or_default());
        let text_end = data
            .get(i..)
            .and_then(|r| r.iter().position(|&b| b == b'<'))
            .map_or(data.len(), |p| i.saturating_add(p));
        let value = crate::text::latin1(data.get(i..text_end).unwrap_or_default())
            .trim()
            .to_owned();
        let index = doc.elements.len();
        doc.elements.push(MarkupElement {
            name,
            start: to_u64(open),
            end: to_u64(text_end),
            value: (!value.is_empty()).then_some(value),
            children: Vec::new(),
        });
        match stack.last().and_then(|&p| doc.elements.get_mut(p)) {
            Some(parent) => parent.children.push(index),
            None => doc.roots.push(index),
        }
        stack.push(index);
        if doc.elements.len() > 1_000_000 {
            break;
        }
    }
    doc
}

fn markup_find<'a>(doc: &'a Markup, name: &str) -> impl Iterator<Item = &'a MarkupElement> {
    let name = name.to_owned();
    doc.elements.iter().filter(move |e| e.name == name)
}

fn markup_child<'a>(doc: &'a Markup, e: &MarkupElement, name: &str) -> Option<&'a str> {
    e.children
        .iter()
        .filter_map(|&c| doc.elements.get(c))
        .find(|c| c.name == name)
        .and_then(|c| c.value.as_deref())
}

/// The node of element `i`.
fn markup_node(file: Span, doc: &Markup, i: usize) -> Option<Node> {
    let e = doc.elements.get(i)?;
    let node = Node::new(e.name.clone()).span(file.sub(e.start, e.end.saturating_sub(e.start)));
    if e.children.is_empty() {
        return Some(node.value(text(e.value.clone().unwrap_or_default())));
    }
    let mut node = node.lazy(ofx_element, (file, i));
    if e.name == "STMTTRN" {
        let get = |k: &str| markup_child(doc, e, k).unwrap_or_default();
        node = node.value(text(get("TRNAMT"))).summary(
            format!(
                "{} {} {}",
                ofx_date(get("DTPOSTED")),
                get("TRNTYPE"),
                get("NAME")
            )
            .trim()
            .to_owned(),
        );
    }
    Some(node)
}

/// OFX dates: YYYYMMDD[HHMMSS[.XXX]][[tz]].
fn ofx_date(s: &str) -> String {
    let d = |a: usize, b: usize| s.get(a..b).unwrap_or("");
    if s.len() < 8 {
        return s.to_owned();
    }
    let mut out = format!("{}-{}-{}", d(0, 4), d(4, 6), d(6, 8));
    if s.len() >= 14 {
        out.push_str(&format!(" {}:{}:{}", d(8, 10), d(10, 12), d(12, 14)));
    }
    out
}

async fn ofx_doc(cx: &Cx, file: Span) -> Result<(Arc<Markup>, usize)> {
    if let Some(d) = cx.cached::<Markup>(file, "ofx") {
        let body = d.body;
        return Ok((d, body));
    }
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    // The body starts at <OFX> (after the SGML header or XML prolog).
    let body = data.windows(5).position(|w| w == b"<OFX>").unwrap_or(0);
    let doc = Arc::new(markup_parse(cx, &data, body).await);
    cx.cache(file, "ofx", doc.clone());
    Ok((doc, body))
}

async fn ofx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x1000)).await?;
    let (doc, body) = ofx_doc(&cx, file).await?;
    let mut version = String::new();
    let header = head.get(..body.min(head.len())).unwrap_or_default();
    let header_node = Node::new("Header").span(file.sub(0, to_u64(body)));
    let mut keys = Vec::new();
    for (at, len, line) in lines(header) {
        let s = lossy(line);
        if let Some((k, v)) = s.split_once(':') {
            if k == "VERSION" {
                version = v.to_owned();
            }
            keys.push((k.to_owned(), v.to_owned(), file.sub(at, len)));
        } else if let Some(attrs) = s.strip_prefix("<?OFX ") {
            // OFX 2: the header is a processing instruction of KEY="VALUE" pairs.
            for pair in attrs.trim_end_matches("?>").split_whitespace() {
                if let Some((k, v)) = pair.split_once('=') {
                    let v = v.trim_matches('"');
                    if k == "VERSION" {
                        version = v.to_owned();
                    }
                    keys.push((k.to_owned(), v.to_owned(), file.sub(at, len)));
                }
            }
        }
    }
    cx.emit(
        header_node
            .summary(format!("{} keys", keys.len()))
            .lazy(ofx_header, keys),
    );
    for &i in &doc.roots {
        match markup_node(file, &doc, i) {
            Some(node) => cx.push(node).await,
            None => cx.checkpoint().await,
        }
    }
    let transactions = markup_find(&doc, "STMTTRN").count();
    let account = markup_find(&doc, "ACCTID")
        .next()
        .and_then(|e| e.value.clone())
        .unwrap_or_default();
    let currency = markup_find(&doc, "CURDEF")
        .next()
        .and_then(|e| e.value.clone())
        .unwrap_or_default();
    let balance = markup_find(&doc, "LEDGERBAL")
        .next()
        .and_then(|e| markup_child(&doc, e, "BALAMT").map(str::to_owned));
    cx.annotate(format!(
        "OFX {version} statement{}, {transactions} transactions{}",
        if account.is_empty() {
            String::new()
        } else {
            format!(" for account {account}")
        },
        balance
            .map(|b| format!(", balance {b} {currency}"))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn ofx_header(cx: Cx, keys: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in keys {
        cx.push(Node::new(k).span(span).value(text(v))).await;
    }
    Ok(())
}

async fn ofx_element(cx: Cx, (file, index): (Span, usize)) -> Result<()> {
    let (doc, _) = ofx_doc(&cx, file).await?;
    let Some(e) = doc.elements.get(index) else {
        return Ok(());
    };
    for &i in &e.children {
        match markup_node(file, &doc, i) {
            Some(node) => cx.push(node).await,
            None => cx.checkpoint().await,
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Microsoft Project exchange (MPX)

declare_format!(pub MPX = "mpx", "Microsoft Project exchange file (MPX)", ["mpx"], "application/x-project",
    Probe::Magic(&[(0, b"MPX,")]), mpx);

const MPX_RECORDS: EnumTable = &[
    (0, "Comments"),
    (10, "Currency settings"),
    (11, "Default settings"),
    (12, "Date and time settings"),
    (20, "Base calendar"),
    (25, "Base calendar hours"),
    (26, "Base calendar exception"),
    (30, "Project header"),
    (40, "Resource field names"),
    (41, "Resource field numbers"),
    (50, "Resource"),
    (51, "Resource notes"),
    (55, "Resource calendar"),
    (56, "Resource calendar hours"),
    (57, "Resource calendar exception"),
    (60, "Task field names"),
    (61, "Task field numbers"),
    (70, "Task"),
    (71, "Task notes"),
    (72, "Recurring task"),
    (75, "Resource assignment"),
    (76, "Resource assignment workgroup fields"),
    (80, "Project names"),
    (81, "DDE and OLE client links"),
];

const MPX_TASK_FIELDS: EnumTable = &[
    (1, "Name"),
    (2, "WBS"),
    (3, "Outline level"),
    (20, "Cost"),
    (21, "Baseline cost"),
    (22, "Actual cost"),
    (30, "Work"),
    (40, "Duration"),
    (41, "Baseline duration"),
    (42, "Actual duration"),
    (44, "% complete"),
    (50, "Start"),
    (51, "Finish"),
    (70, "Predecessors"),
    (80, "Fixed"),
    (90, "ID"),
    (91, "Constraint type"),
    (98, "Unique ID"),
];

/// Splits a comma-separated MPX record (double quotes protect commas).
fn mpx_fields(line: &[u8]) -> Vec<String> {
    mpx_field_spans(line)
        .into_iter()
        .map(|(s, _, _)| s)
        .collect()
}

/// Fields with their byte ranges in the line.
fn mpx_field_spans(line: &[u8]) -> Vec<(String, usize, usize)> {
    let mut out = Vec::new();
    let mut cur = Vec::new();
    let mut quoted = false;
    let mut start = 0usize;
    for (i, &c) in line.iter().enumerate() {
        match c {
            b'"' => quoted = !quoted,
            b',' if !quoted => {
                out.push((crate::text::latin1(&std::mem::take(&mut cur)), start, i));
                start = i.saturating_add(1);
            }
            _ => cur.push(c),
        }
    }
    out.push((crate::text::latin1(&cur), start, line.len()));
    out
}

async fn mpx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let mut task_fields: Arc<Vec<u64>> = Arc::new(Vec::new());
    let (mut tasks, mut resources, mut program, mut title) =
        (0u64, 0u64, String::new(), String::new());
    for (i, (at, len, line)) in lines(&data).enumerate() {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if line.is_empty() {
            continue;
        }
        let fields = mpx_fields(line);
        let span = file.sub(at, len);
        if i == 0 {
            program = format!(
                "{} {}",
                fields.get(1).cloned().unwrap_or_default(),
                fields.get(2).cloned().unwrap_or_default()
            );
            cx.push(
                Node::new("File creation record")
                    .span(span)
                    .value(text(lossy(line))),
            )
            .await;
            continue;
        }
        let kind: u64 = fields
            .first()
            .and_then(|k| k.trim().parse().ok())
            .unwrap_or(u64::MAX);
        let name = lookup(MPX_RECORDS, kind).map_or_else(
            || format!("Record {}", fields.first().cloned().unwrap_or_default()),
            str::to_owned,
        );
        let mut node = Node::new(name).span(span);
        match kind {
            61 => {
                task_fields = Arc::new(
                    fields
                        .iter()
                        .skip(1)
                        .filter_map(|f| f.trim().parse().ok())
                        .collect(),
                );
                node = node.value(text(lossy(line)));
            }
            70 => {
                tasks = tasks.saturating_add(1);
                let pos = task_fields.iter().position(|&f| f == 1);
                let task = pos
                    .and_then(|p| fields.get(p.saturating_add(1)))
                    .cloned()
                    .unwrap_or_default();
                node = Node::new(format!("Task {task:?}"))
                    .span(span)
                    .lazy(mpx_task, (span, task_fields.clone()));
            }
            50 => {
                resources = resources.saturating_add(1);
                node = node.value(text(fields.get(1..).unwrap_or_default().join(", ")));
            }
            30 => {
                title = fields.get(1).cloned().unwrap_or_default();
                node = node.value(text(fields.get(1..).unwrap_or_default().join(", ")));
            }
            _ => node = node.value(text(fields.get(1..).unwrap_or_default().join(", "))),
        }
        cx.progress_in(file, file.offset.saturating_add(at));
        cx.push(node).await;
    }
    cx.annotate(format!(
        "MPX from {}{}, {tasks} tasks, {resources} resources",
        program.trim(),
        if title.is_empty() {
            String::new()
        } else {
            format!(" ({title})")
        }
    ));
    Ok(())
}

async fn mpx_task(cx: Cx, (span, order): (Span, Arc<Vec<u64>>)) -> Result<()> {
    let line = cx.read(span).await?;
    let line = line.strip_suffix(b"\n").unwrap_or(&line);
    let line = line.strip_suffix(b"\r").unwrap_or(line);
    for (i, (value, start, end)) in mpx_field_spans(line).into_iter().skip(1).enumerate() {
        if value.is_empty() {
            continue;
        }
        let name = order.get(i).map_or_else(
            || format!("Field {}", i.saturating_add(1)),
            |&f| lookup(MPX_TASK_FIELDS, f).map_or_else(|| format!("Field {f}"), str::to_owned),
        );
        let field = span.sub(to_u64(start), to_u64(end.saturating_sub(start)));
        cx.push(Node::new(name).span(field).value(text(value)))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Lotus Ami Pro documents (.sam)

declare_format!(pub AMIPRO = "ami-pro", "Lotus Ami Pro document", ["sam"], "application/x-amipro",
    Probe::Magic(&[(0, b"[ver]\r\n\t"), (0, b"[ver]\n\t")]), ami_pro);

const AMI_SECTIONS: &[(&str, &str)] = &[
    ("ver", "Version"),
    ("sty", "Style sheet"),
    ("compat", "Compatibility"),
    ("lay", "Layout"),
    ("fnt", "Fonts"),
    ("doc", "Document info"),
    ("docinfo", "Document info"),
    ("tag", "Paragraph style"),
    ("frm", "Frame"),
    ("edoc", "End of document"),
];

/// A section: name, offset, and the lines it holds (offset, length).
type AmiSection = (String, u64, Vec<(u64, u64)>);

async fn ami_pro(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file.sub(0, cx.limits().max_read)).await?;
    let mut sections: Vec<AmiSection> = Vec::new();
    let mut version = String::new();
    let mut body_lines = 0u64;
    for (n, (at, len, line)) in lines(&data).enumerate() {
        if n % 1024 == 1023 {
            cx.checkpoint().await;
        }
        let s = crate::text::latin1(line);
        if let Some(name) = s.strip_prefix('[').and_then(|r| r.strip_suffix(']'))
            && !name.is_empty()
            && name.chars().all(|c| c.is_ascii_alphanumeric())
        {
            sections.push((name.to_owned(), at, Vec::new()));
            continue;
        }
        if let Some((name, _, list)) = sections.last_mut() {
            if name == "ver" && version.is_empty() {
                version = s.trim().to_owned();
            }
            if name == "edoc" {
                body_lines = body_lines.saturating_add(1);
            }
            list.push((at, len));
        }
    }
    cx.set_count(Count::Exact(to_u64(sections.len())));
    let ends: Vec<u64> = sections
        .iter()
        .skip(1)
        .map(|(_, s, _)| *s)
        .chain(std::iter::once(to_u64(data.len())))
        .collect();
    for ((name, start, list), end) in sections.iter().zip(ends) {
        let title = AMI_SECTIONS
            .iter()
            .find(|(k, _)| k == name)
            .map(|(_, t)| *t);
        let mut node = Node::new(format!("[{name}]"))
            .span(file.sub(*start, end.saturating_sub(*start)))
            .summary(format!("{} lines", list.len()));
        if let Some(t) = title {
            node = node.desc(t);
        }
        cx.push(node.lazy(ami_lines, (file, list.clone()))).await;
    }
    cx.annotate(format!(
        "Ami Pro document (format {version}), {} sections, {body_lines} text lines",
        sections.len()
    ));
    Ok(())
}

async fn ami_lines(cx: Cx, (file, list): (Span, Vec<(u64, u64)>)) -> Result<()> {
    for (i, (at, len)) in list.into_iter().enumerate() {
        let line = cx.read(file.sub(at, len)).await?;
        let s = crate::text::latin1(&line);
        cx.push(
            Node::new(format!("Line {i}"))
                .span(file.sub(at, len))
                .value(text(clip(s.trim_end(), 200))),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Microsoft Money (MSISAM: Jet 4 pages with their own format ID)

fn money_probe(h: &Head<'_>) -> bool {
    h.starts_with(&[0, 1, 0, 0]) && h.at(4, b"MSISAM Database\0")
}

declare_format!(pub MONEY = "ms-money", "Microsoft Money file (MSISAM)", ["mny", "mbf"], "application/x-msmoney",
    Probe::Custom(money_probe), money);

async fn money(cx: Cx, input: Input) -> Result<()> {
    crate::formats::data::jet::dissect(cx.clone(), input).await?;
    let pages = input.span.len / 4096;
    cx.annotate(format!(
        "Microsoft Money file (MSISAM, Jet 4 pages), {pages} pages of 4 KiB"
    ));
    Ok(())
}

/// Printable runs of at least four characters (version strings in headers).
fn printable_runs(data: &[u8]) -> Vec<(usize, String)> {
    let mut out = Vec::new();
    let mut start = None;
    for (i, &b) in data.iter().chain(std::iter::once(&0)).enumerate() {
        if (0x20..0x7f).contains(&b) {
            start.get_or_insert(i);
        } else if let Some(s) = start.take()
            && i.saturating_sub(s) >= 4
        {
            out.push((s, crate::text::latin1(data.get(s..i).unwrap_or_default())));
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Lotus Word Pro (.lwp)

declare_format!(pub WORDPRO = "lotus-wordpro", "Lotus Word Pro document", ["lwp"], "application/vnd.lotus-wordpro",
    Probe::Magic(&[(0, b"WordPro")]), wordpro);

async fn wordpro(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 7))
            .value(text("WordPro")),
    );
    let head = cx.read_avail(file.sub(0, 0x400)).await?;
    let strings = printable_runs(head.get(7..).unwrap_or_default());
    let mut node = Node::new("Document objects")
        .span(file.tail(7))
        .diag(Diagnostic::note("the object stream is not dissected"));
    if !strings.is_empty() {
        node = node.summary(clip(
            &strings
                .iter()
                .map(|(_, s)| s.as_str())
                .collect::<Vec<_>>()
                .join(", "),
            120,
        ));
    }
    cx.emit(node);
    cx.annotate("Lotus Word Pro document");
    Ok(())
}

// ---------------------------------------------------------------------------
// Word for Windows 1.x and 2.0 (pre-OLE .doc)

fn winword_probe(h: &Head<'_>) -> bool {
    let fc_min = u32_le(h.data, 0x18).map_or(0, u64::from);
    let fc_mac = u32_le(h.data, 0x1c).map_or(0, u64::from);
    u16_le(h.data, 0).is_some_and(|w| w == 0xa59b || w == 0xa5db)
        && fc_min >= 0x20
        && fc_mac >= fc_min
        && fc_mac <= h.len
}

declare_format!(pub WINWORD2 = "winword2", "Word for Windows 1.x/2.0 document", ["doc"], "application/msword",
    Probe::Custom(winword_probe), winword2);

const WINWORD_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x0001, "fDot"),
    crate::value::flag(0x0002, "fGlsy"),
    crate::value::flag(0x0004, "fComplex"),
    crate::value::flag(0x0008, "fHasPic"),
    crate::value::field(0x00f0, 0x0000, "cQuickSaves=0"),
    crate::value::flag(0x0100, "fEncrypted"),
];

fn winword_fib(f: &mut Fields<'_>, _: &()) -> Result<(u16, u16, u32, u32)> {
    let ident = f.u16("wIdent").hex().emit()?;
    f.u16("nFib").emit()?;
    f.u16("nProduct").hex().emit()?;
    let lid = f
        .u16("Language")
        .enumeration(crate::formats::util::lcid::DISPLAY_NAMES)
        .emit()?;
    f.int::<i16>("pnNext").emit()?;
    f.u16("Flags").flags(WINWORD_FLAGS).emit()?;
    f.u16("nFibBack").emit()?;
    f.u32("Encryption key").hex().emit()?;
    f.u8("Environment").emit()?;
    f.u8("Reserved").emit()?;
    f.u16("Character set").emit()?;
    f.u16("Character set (tables)").emit()?;
    let fc_min = f.u32("fcMin (text start)").hex().emit()?;
    let fc_mac = f.u32("fcMac (text end)").hex().emit()?;
    Ok((ident, lid, fc_min, fc_mac))
}

async fn winword2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fib = file.sub(0, 0x20);
    let block = cx.block(fib).await?;
    let (ident, lid, fc_min, fc_mac) = winword_fib(&mut Fields::new(&block, LE), &())?;
    cx.emit(crate::fields::struct_node(
        "File information block",
        fib,
        LE,
        (),
        winword_fib,
    ));
    let body = file.sub(fc_min.into(), u64::from(fc_mac.saturating_sub(fc_min)));
    let raw = cx.read_avail(body.sub(0, 0x10000)).await?;
    let txt = crate::text::latin1(&raw).replace('\r', "\n");
    let words = txt.split_whitespace().count();
    cx.emit(
        Node::new("Text")
            .span(body)
            .value(text(clip(&txt, 2000)))
            .summary(format!("{} characters", body.len)),
    );
    cx.emit(Node::new("Formatting and tables").span(file.tail(u64::from(fc_mac))));
    cx.annotate(format!(
        "Word for Windows {} document, {}, {words} words",
        if ident == 0xa5db { "2.0" } else { "1.x" },
        crate::formats::util::lcid::display_name(lid.into()).unwrap_or("unknown language")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Hangul Word Processor 3.0 (.hwp) and the HWP 5 FileHeader stream

declare_format!(pub HWP3 = "hwp3", "Hangul Word Processor 3.0 document", ["hwp"], "application/x-hwp",
    Probe::Magic(&[(0, b"HWP Document File V3.00 \x1a\x01\x02\x03\x04\x05")]), hwp3);

/// HWP 3 text is 2-byte "hchar" codes; ASCII is stored as itself.
fn hchar_text(raw: &[u8]) -> String {
    raw.as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .take_while(|&c| c != 0)
        .map(|c| {
            if c < 0x80 {
                char::from(u8::try_from(c).unwrap_or(b'?'))
            } else {
                '\u{fffd}'
            }
        })
        .collect()
}

const HWP3_SUMMARY: [&str; 9] = [
    "Title",
    "Subject",
    "Author",
    "Date",
    "Keyword 1",
    "Keyword 2",
    "Other 1",
    "Other 2",
    "Other 3",
];

async fn hwp3(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 30))
            .value(text("HWP Document File V3.00")),
    );
    let info = file.sub(30, 128);
    let raw = cx.read_avail(info).await?;
    let encrypted = u16_le(&raw, 96).unwrap_or(0) != 0;
    let compressed = raw.get(124).copied().unwrap_or(0) != 0;
    cx.emit(
        Node::new("Document information")
            .span(info)
            .summary(format!(
                "{}{}",
                if compressed {
                    "compressed"
                } else {
                    "uncompressed"
                },
                if encrypted {
                    ", password-protected"
                } else {
                    ""
                }
            )),
    );
    let summary = file.sub(158, 1008);
    let mut title = String::new();
    for (i, name) in HWP3_SUMMARY.iter().enumerate() {
        let span = summary.sub(crate::bytes::to_u64(i).saturating_mul(112), 112);
        let s = hchar_text(&cx.read_avail(span).await?);
        if i == 0 {
            title = s.clone();
        }
        cx.push(Node::new(*name).span(span).value(text(s))).await;
    }
    cx.emit(
        Node::new("Body")
            .span(file.tail(1166))
            .diag(Diagnostic::note("paragraph records are not dissected")),
    );
    cx.annotate(format!(
        "Hangul 3.0 document{}",
        if title.is_empty() {
            String::new()
        } else {
            format!(" {title:?}")
        }
    ));
    Ok(())
}

fn hwp5_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"HWP Document File\0") && h.len == 256
}

declare_format!(pub HWP5_HEADER = "hwp5-fileheader", "Hangul Word Processor 5 FileHeader stream", [], "application/x-hwp5-fileheader",
    Probe::Custom(hwp5_probe), hwp5_header);

const HWP5_FLAGS: crate::value::FlagTable = &[
    crate::value::flag(0x001, "COMPRESSED"),
    crate::value::flag(0x002, "PASSWORD"),
    crate::value::flag(0x004, "DISTRIBUTION"),
    crate::value::flag(0x008, "SCRIPT"),
    crate::value::flag(0x010, "DRM"),
    crate::value::flag(0x020, "XML_TEMPLATE"),
    crate::value::flag(0x040, "HISTORY"),
    crate::value::flag(0x080, "SIGNATURE"),
    crate::value::flag(0x100, "CERT_ENCRYPTED"),
    crate::value::flag(0x200, "SIGNATURE_RESERVED"),
    crate::value::flag(0x400, "CERT_DRM"),
    crate::value::flag(0x800, "CCL"),
];

async fn hwp5_header(cx: Cx, input: Input) -> Result<()> {
    let block = cx.block(input.span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.ascii("Signature", 32).emit()?;
    let v = f
        .u32("Version")
        .with(|&v, n| {
            n.summary(format!(
                "{}.{}.{}.{}",
                v >> 24,
                (v >> 16) & 0xff,
                (v >> 8) & 0xff,
                v & 0xff
            ))
        })
        .emit()?;
    let flags = f.u32("Properties").flags(HWP5_FLAGS).emit()?;
    f.u32("License").hex().emit()?;
    f.u32("Encryption version").emit()?;
    f.u8("KOGL license country").emit()?;
    f.bytes("Reserved", 207).emit()?;
    cx.annotate(format!(
        "HWP {}.{}.{}.{} file header{}{}",
        v >> 24,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff,
        v & 0xff,
        if flags & 1 != 0 { ", compressed" } else { "" },
        if flags & 2 != 0 {
            ", password-protected"
        } else {
            ""
        }
    ));
    Ok(())
}
