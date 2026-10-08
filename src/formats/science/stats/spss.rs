//! SPSS system files (`.sav`, and `.zsav` with zlib-compressed data).
//!
//! A 176-byte header, then dictionary records (type 2 variables, 3 and 4
//! value labels and the variables they apply to, 6 documents, 7 extension
//! records by subtype, 999 the end of the dictionary), then the cases: 8-byte
//! slots, a number or 8 bytes of a string each, stored raw, with SPSS
//! bytecode compression, or (`.zsav`) as bytecode in zlib blocks listed by a
//! trailer. Layout as documented by GNU PSPP ("System File Format");
//! checked against files written by ReadStat (pyreadstat). Very long
//! strings (over 255 bytes, record 7/14) are shown as their 255-byte
//! segments, and long-string value labels and missing values (7/21, 7/22)
//! as raw extension records.

use std::sync::Arc;

use super::{Cell, Item, date_cell, decode_text, number, row_node, trim_end};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::Input;
use crate::formats::Probe;
use crate::formats::util::arcutil::emit_nodes;
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};

declare_format!(pub SPSS = "spss-sav", "SPSS data file", ["sav", "zsav"], "application/x-spss-sav",
    Probe::Magic(&[(0, b"$FL2"), (0, b"$FL3")]), dissect);

record! {
    pub struct SpssHeader {
        magic: ascii[4] "Record type",
        product: ascii[60] "Product name",
        layout: i32 "Layout code",
        nominal_case_size: i32 "Nominal case size" .desc("8-byte slots per case"),
        compression: i32 "Compression" .enumeration(COMPRESSION),
        weight: i32 "Weight variable index",
        cases: i32 "Number of cases",
        bias: f64 "Compression bias",
        date: ascii[9] "Creation date",
        time: ascii[8] "Creation time",
        label: ascii[64] "File label",
        _padding: bytes[3] "Padding",
    }
}

const COMPRESSION: EnumTable = &[(0, "none"), (1, "bytecode"), (2, "zlib")];

/// The system-missing value, `-DBL_MAX`.
const SYSMIS: u64 = 0xffef_ffff_ffff_ffff;
/// SPSS times count seconds from 1582-10-14.
pub(super) const EPOCH: i64 = -12_219_379_200;

/// Print and write format types (PSPP's numbering).
const FORMATS: EnumTable = &[
    (1, "A"),
    (2, "AHEX"),
    (3, "COMMA"),
    (4, "DOLLAR"),
    (5, "F"),
    (6, "IB"),
    (7, "PIBHEX"),
    (8, "P"),
    (9, "PIB"),
    (10, "PK"),
    (11, "RB"),
    (12, "RBHEX"),
    (15, "Z"),
    (16, "N"),
    (17, "E"),
    (20, "DATE"),
    (21, "TIME"),
    (22, "DATETIME"),
    (23, "ADATE"),
    (24, "JDATE"),
    (25, "DTIME"),
    (26, "WKDAY"),
    (27, "MONTH"),
    (28, "MOYR"),
    (29, "QYR"),
    (30, "WKYR"),
    (31, "PCT"),
    (32, "DOT"),
    (33, "CCA"),
    (34, "CCB"),
    (35, "CCC"),
    (36, "CCD"),
    (37, "CCE"),
    (38, "EDATE"),
    (39, "SDATE"),
    (40, "MTIME"),
    (41, "YMDHMS"),
];

const MEASURES: EnumTable = &[(0, "unknown"), (1, "nominal"), (2, "ordinal"), (3, "scale")];
const ALIGNMENTS: EnumTable = &[(0, "left"), (1, "right"), (2, "centre")];

const SUBTYPES: EnumTable = &[
    (3, "Machine integer info"),
    (4, "Machine floating-point info"),
    (5, "Variable sets"),
    (6, "Trends date info"),
    (7, "Multiple response sets"),
    (8, "Extra product info"),
    (10, "Extra product info"),
    (11, "Variable display parameters"),
    (13, "Long variable names"),
    (14, "Very long string variables"),
    (16, "Extended number of cases"),
    (17, "Data file attributes"),
    (18, "Variable attributes"),
    (19, "Multiple response sets (extended)"),
    (20, "Character encoding"),
    (21, "Long string value labels"),
    (22, "Long string missing values"),
    (24, "XML"),
];

/// `F8.2`, `A22`, `DATE11`.
fn format_name(packed: i32) -> String {
    let p = packed as u32;
    format_parts((p >> 16) & 0xff, (p >> 8) & 0xff, p & 0xff)
}

/// A format from its type, width and decimals (also used by `.por`).
pub(super) fn format_parts(kind: u32, width: u32, decimals: u32) -> String {
    let name = lookup(FORMATS, kind.into()).map_or_else(|| format!("format{kind}"), str::to_owned);
    if decimals != 0 {
        format!("{name}{width}.{decimals}")
    } else {
        format!("{name}{width}")
    }
}

/// Whether a format shows a date (`Some(false)`) or a date and time
/// (`Some(true)`).
fn date_kind(packed: i32) -> Option<bool> {
    date_type((packed >> 16) & 0xff)
}

/// [`date_kind`] by format type (also used by `.por`).
pub(super) fn date_type(kind: i32) -> Option<bool> {
    match kind {
        20 | 23 | 24 | 28 | 29 | 30 | 38 | 39 => Some(false),
        22 | 41 => Some(true),
        _ => None,
    }
}

#[derive(Clone, Debug)]
enum Missing {
    None,
    Values(Vec<[u8; 8]>),
    Range {
        low: f64,
        high: f64,
        extra: Option<f64>,
    },
}

#[derive(Clone, Debug)]
struct Var {
    short: String,
    name: String,
    /// 0 for numeric, else the string width.
    width: i32,
    label: String,
    print: i32,
    write: i32,
    missing: Missing,
    /// First 8-byte slot of the case.
    slot: u64,
    slots: u64,
    /// The variable record (continuation records excluded).
    record: Span,
    /// Value label sets naming this variable.
    sets: Vec<usize>,
    /// Measure, display width, alignment (record 7/11).
    display: Option<(i32, Option<i32>, i32)>,
}

#[derive(Clone, Debug)]
struct LabelSet {
    span: Span,
    entries: Vec<([u8; 8], String, Span)>,
    vars: Vec<usize>,
}

#[derive(Clone, Debug)]
enum Rec {
    Var(usize),
    Continuation,
    Labels(usize),
    LabelVars(usize),
    Document(u32),
    Ext { subtype: i32, size: u32, count: u32 },
    End,
}

#[derive(Clone, Debug, Default)]
struct Dict {
    endian: Option<Endian>,
    vars: Vec<Var>,
    sets: Vec<LabelSet>,
    records: Vec<(Rec, Span)>,
    documents: Vec<String>,
    encoding: Option<String>,
    sysmis: Option<u64>,
    cases: Option<u64>,
    slots: u64,
    /// Where the case data starts (after the 999 record).
    data: Option<u64>,
}

impl Dict {
    fn endian(&self) -> Endian {
        self.endian.unwrap_or(Endian::Little)
    }

    fn f64(&self, raw: [u8; 8]) -> f64 {
        match self.endian() {
            Endian::Big => f64::from_be_bytes(raw),
            Endian::Little => f64::from_le_bytes(raw),
        }
    }

    fn text(&self, bytes: &[u8]) -> String {
        decode_text(self.encoding.as_deref(), bytes)
    }

    /// The label of `raw` among `var`'s value labels; `work` counts the
    /// entries compared.
    fn label_for(&self, var: &Var, raw: &[u8], work: &mut u64) -> Option<String> {
        for &set in &var.sets {
            for (value, label, _) in &self.sets.get(set)?.entries {
                *work = work.saturating_add(1);
                let hit = if var.width == 0 {
                    raw.get(..8) == Some(value.as_slice())
                        || self.f64(*value) == self.f64(eight(raw))
                } else {
                    trim_end(value) == trim_end(raw)
                };
                if hit {
                    return Some(label.clone());
                }
            }
        }
        None
    }

    fn value_text(&self, var: &Var, raw: [u8; 8]) -> String {
        if var.width == 0 {
            number(self.f64(raw))
        } else {
            format!("{:?}", self.text(trim_end(&raw)))
        }
    }
}

fn eight(bytes: &[u8]) -> [u8; 8] {
    let mut out = [0u8; 8];
    for (o, b) in out.iter_mut().zip(bytes) {
        *o = *b;
    }
    out
}

fn i32_of(bytes: &[u8], at: usize, endian: Endian) -> i32 {
    let b = [
        bytes.get(at).copied().unwrap_or(0),
        bytes.get(at.saturating_add(1)).copied().unwrap_or(0),
        bytes.get(at.saturating_add(2)).copied().unwrap_or(0),
        bytes.get(at.saturating_add(3)).copied().unwrap_or(0),
    ];
    match endian {
        Endian::Big => i32::from_be_bytes(b),
        Endian::Little => i32::from_le_bytes(b),
    }
}

/// Reads an `i32` count and the span of `count * unit` bytes after it,
/// rejecting counts the region cannot hold.
async fn counted(cur: &mut Cursor<'_>, unit: u64) -> Result<(u32, Span)> {
    let n = cur.int::<i32>().await?;
    let count = u32::try_from(n)
        .map_err(|_| Diagnostic::malformed(format!("negative count {n}")).at(cur.span(0)))?;
    let len = u64::from(count).saturating_mul(unit);
    let span = cur.region().sub_exact(cur.pos(), len)?;
    Ok((count, span))
}

/// Parses the dictionary; on a malformed record, returns what was read
/// and the problem.
async fn parse_dict(cx: &Cx, file: Span, endian: Endian) -> (Dict, Option<Diagnostic>) {
    let mut dict = Dict {
        endian: Some(endian),
        ..Dict::default()
    };
    let result = walk_dict(cx, file, &mut dict).await;
    (dict, result.err())
}

async fn walk_dict(cx: &Cx, file: Span, dict: &mut Dict) -> Result<()> {
    let endian = dict.endian();
    let mut cur = Cursor::new(cx, file, endian);
    cur.seek(SpssHeader::SIZE);
    let mut long_names = None;
    let mut display = None;
    while !cur.at_end() {
        cx.checkpoint().await;
        let start = cur.pos();
        let kind = cur.int::<i32>().await?;
        let rec = match kind {
            2 => {
                let head = cur.bytes(28).await?;
                let width = i32_of(&head, 0, endian);
                let has_label = i32_of(&head, 4, endian);
                let n_missing = i32_of(&head, 8, endian);
                let name = String::from_utf8_lossy(trim_end(head.get(20..28).unwrap_or_default()))
                    .into_owned();
                let mut label = String::new();
                if has_label == 1 {
                    let (len, span) = counted(&mut cur, 1).await?;
                    let bytes = cx.read(span).await?;
                    label = dict.text(&bytes);
                    cur.skip(u64::from(len).saturating_add(3) & !3);
                }
                let mut missing = Missing::None;
                if n_missing != 0 {
                    let n = n_missing.unsigned_abs().min(3);
                    let raw = cur.bytes(u64::from(n).saturating_mul(8)).await?;
                    let values: Vec<[u8; 8]> = raw.as_chunks::<8>().0.to_vec();
                    missing = if n_missing < 0 {
                        let v = |i: usize| values.get(i).map_or(0.0, |r| dict.f64(*r));
                        Missing::Range {
                            low: v(0),
                            high: v(1),
                            extra: (n_missing == -3).then(|| v(2)),
                        }
                    } else {
                        Missing::Values(values)
                    };
                }
                let span = cur.since(start);
                if width == -1 {
                    if let Some(var) = dict.vars.last_mut() {
                        var.slots = var.slots.saturating_add(1);
                    }
                    dict.slots = dict.slots.saturating_add(1);
                    Rec::Continuation
                } else {
                    dict.vars.push(Var {
                        short: name.clone(),
                        name,
                        width,
                        label,
                        print: i32_of(&head, 12, endian),
                        write: i32_of(&head, 16, endian),
                        missing,
                        slot: dict.slots,
                        slots: 1,
                        record: span,
                        sets: Vec::new(),
                        display: None,
                    });
                    dict.slots = dict.slots.saturating_add(1);
                    Rec::Var(dict.vars.len().saturating_sub(1))
                }
            }
            3 => {
                let (count, _) = counted(&mut cur, 9).await?;
                let mut entries = Vec::new();
                for _ in 0..count {
                    cx.checkpoint().await;
                    let at = cur.pos();
                    let value = eight(&cur.bytes(8).await?);
                    let len = cur.u8().await?;
                    let text = cur.bytes(u64::from(len)).await?;
                    // The label and its length byte are padded to 8 bytes.
                    cur.skip(u64::from(len).saturating_add(1).wrapping_neg() & 7);
                    entries.push((value, dict.text(&text), cur.since(at)));
                }
                dict.sets.push(LabelSet {
                    span: cur.since(start),
                    entries,
                    vars: Vec::new(),
                });
                Rec::Labels(dict.sets.len().saturating_sub(1))
            }
            4 => {
                let (count, span) = counted(&mut cur, 4).await?;
                let raw = cx.read(span).await?;
                cur.skip(span.len);
                let set = dict.sets.len().saturating_sub(1);
                let indexes: Vec<i32> = (0..count)
                    .map(|i| {
                        i32_of(
                            &raw,
                            crate::bytes::to_usize(u64::from(i).saturating_mul(4)),
                            endian,
                        )
                    })
                    .collect();
                for (i, index) in indexes.into_iter().enumerate() {
                    if i.is_multiple_of(1024) {
                        cx.checkpoint().await;
                    }
                    let slot = u64::try_from(index.saturating_sub(1)).unwrap_or(u64::MAX);
                    // Slots increase with each variable.
                    if let Ok(v) = dict.vars.binary_search_by_key(&slot, |v| v.slot) {
                        if let Some(s) = dict.sets.get_mut(set) {
                            s.vars.push(v);
                        }
                        if let Some(var) = dict.vars.get_mut(v) {
                            var.sets.push(set);
                        }
                    }
                }
                Rec::LabelVars(set)
            }
            6 => {
                let (count, span) = counted(&mut cur, 80).await?;
                let raw = cx.read(span).await?;
                cur.skip(span.len);
                for line in raw.chunks(80) {
                    dict.documents.push(dict.text(trim_end(line)));
                }
                Rec::Document(count)
            }
            7 => {
                let subtype = cur.int::<i32>().await?;
                let size = cur.int::<i32>().await?;
                let size = u32::try_from(size).unwrap_or(0);
                let (count, span) = counted(&mut cur, u64::from(size)).await?;
                cur.skip(span.len);
                let read_small = span.len <= 1 << 20;
                match subtype {
                    3 if read_small => {
                        let raw = cx.read(span).await?;
                        let code = i32_of(&raw, 28, endian);
                        if dict.encoding.is_none() {
                            dict.encoding = code_page(code).map(str::to_owned);
                        }
                    }
                    4 if read_small => {
                        let raw = cx.read(span).await?;
                        dict.sysmis = Some(u64::from_le_bytes(eight(&raw))).map(|v| {
                            if endian == Endian::Big {
                                v.swap_bytes()
                            } else {
                                v
                            }
                        });
                    }
                    11 if read_small => display = Some((cx.read(span).await?, count)),
                    13 if read_small => long_names = Some(cx.read(span).await?),
                    16 if read_small => {
                        let raw = cx.read(span).await?;
                        let n = match endian {
                            Endian::Big => crate::bytes::u64_be(&raw, 8),
                            Endian::Little => crate::bytes::u64_le(&raw, 8),
                        };
                        dict.cases = n.filter(|&n| n != u64::MAX);
                    }
                    20 if read_small => {
                        let raw = cx.read(span).await?;
                        dict.encoding = Some(String::from_utf8_lossy(trim_end(&raw)).into_owned());
                    }
                    _ => {}
                }
                Rec::Ext {
                    subtype,
                    size,
                    count,
                }
            }
            999 => {
                cur.skip(4);
                dict.records.push((Rec::End, cur.since(start)));
                dict.data = Some(cur.pos());
                break;
            }
            other => {
                return Err(Diagnostic::malformed(format!(
                    "unknown dictionary record type {other}"
                ))
                .at(file.sub(start, 4)));
            }
        };
        dict.records.push((rec, cur.since(start)));
    }
    if let Some(raw) = long_names {
        let text = dict.text(&raw);
        // Short name to the first variable that has it.
        let mut by_short = std::collections::BTreeMap::new();
        for (i, v) in dict.vars.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            by_short.entry(v.short.clone()).or_insert(i);
        }
        for (i, pair) in text.split('\t').enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            if let Some((short, long)) = pair.split_once('=')
                && let Some(var) = by_short.get(short).and_then(|&v| dict.vars.get_mut(v))
            {
                long.clone_into(&mut var.name);
            }
        }
    }
    if let Some((raw, count)) = display {
        let n = dict.vars.len();
        let per = if u64::from(count) == crate::bytes::to_u64(n).saturating_mul(3) {
            3
        } else {
            2
        };
        for (i, var) in dict.vars.iter_mut().enumerate() {
            let at = |k: usize| {
                i32_of(
                    &raw,
                    i.saturating_mul(per).saturating_add(k).saturating_mul(4),
                    endian,
                )
            };
            if crate::bytes::to_u64(i.saturating_add(1).saturating_mul(per)) <= u64::from(count) {
                var.display = Some(if per == 3 {
                    (at(0), Some(at(1)), at(2))
                } else {
                    (at(0), None, at(1))
                });
            }
        }
    }
    Ok(())
}

/// The character set of an SPSS code page number (record 7/3).
fn code_page(code: i32) -> Option<&'static str> {
    Some(match code {
        65001 => "utf-8",
        20127 | 2 => "us-ascii",
        28591 => "iso-8859-1",
        28592 => "iso-8859-2",
        28605 => "iso-8859-15",
        1250 => "windows-1250",
        1251 => "windows-1251",
        1252 => "windows-1252",
        1253 => "windows-1253",
        1254 => "windows-1254",
        1255 => "windows-1255",
        1256 => "windows-1256",
        1257 => "windows-1257",
        1258 => "windows-1258",
        _ => return None,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, SpssHeader::SIZE)).await?;
    let layout = crate::bytes::u32_le(&head, 64).unwrap_or(0);
    let endian = if matches!(layout, 2 | 3) {
        Endian::Little
    } else {
        Endian::Big
    };
    let h: SpssHeader = emit_record(&cx, file.sub(0, SpssHeader::SIZE), endian).await?;
    let (mut dict, problem) = parse_dict(&cx, file, endian).await;
    if dict.cases.is_none() {
        dict.cases = u64::try_from(h.cases).ok();
    }
    let dict = Arc::new(dict);
    let dict_span = file.sub(
        SpssHeader::SIZE,
        dict.data
            .unwrap_or(file.len)
            .saturating_sub(SpssHeader::SIZE),
    );
    let mut records = Node::new("Dictionary")
        .span(dict_span)
        .summary(format!("{} records", dict.records.len()))
        .lazy(dictionary, dict.clone());
    if let Some(d) = problem {
        records = records.diag(d);
    }
    cx.emit(records);
    cx.emit(
        Node::new("Variables")
            .summary(format!("{} variables", dict.vars.len()))
            .lazy(variables, dict.clone()),
    );
    if !dict.sets.is_empty() {
        cx.emit(
            Node::new("Value labels")
                .summary(format!("{} sets", dict.sets.len()))
                .lazy(label_sets, dict.clone()),
        );
    }
    if !dict.documents.is_empty() {
        let mut lines = Vec::with_capacity(dict.documents.len());
        for (i, l) in dict.documents.iter().enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            lines.push(
                Node::new(format!("Line {}", i.saturating_add(1))).value(Value::Text(l.clone())),
            );
        }
        cx.emit(
            Node::new("Documents")
                .summary(format!("{} lines", lines.len()))
                .lazy(emit_nodes, Arc::new(lines)),
        );
    }
    let mut kind = "uncompressed";
    if let Some(at) = dict.data {
        let data = file.tail(at);
        let bias = h.bias.to_bits();
        let bytecode = Codec::SpssBytecode {
            bias,
            big_endian: endian == Endian::Big,
        };
        let case_bytes = dict.slots.saturating_mul(8);
        let expected = |len: u64| {
            dict.cases
                .map_or(len.saturating_mul(8), |n| n.saturating_mul(case_bytes))
        };
        let source = match h.compression {
            0 => Ok(data),
            1 => {
                kind = "bytecode-compressed";
                cx.decode_lazy(data, &bytecode, expected(data.len))
            }
            2 => {
                kind = "zlib-compressed";
                zsav(&cx, file, data, &dict, &bytecode)
                    .await
                    .and_then(|(blocks, span)| cx.decode_lazy(span, &bytecode, expected(blocks)))
            }
            other => Err(Diagnostic::unsupported(format!("compression code {other}")).at(data)),
        };
        let mut node = Node::new("Cases").span(data);
        node = match &dict.cases {
            Some(n) => node.summary(format!("{n} cases × {} slots", dict.slots)),
            None => node.summary(format!("{} slots per case", dict.slots)),
        };
        node = match source {
            Ok(span) => node.lazy(cases, (dict.clone(), span)),
            Err(d) => node.diag(d),
        };
        cx.emit(node);
    }
    let product = h.product.trim().trim_start_matches("@(#) ").to_owned();
    cx.annotate(format!(
        "SPSS{}, {} variables × {} cases, {kind}{}, {} ({} {})",
        if h.magic == "$FL3" { " (zsav)" } else { "" },
        dict.vars.len(),
        dict.cases.map_or_else(|| "?".to_owned(), |n| n.to_string()),
        if h.label.trim().is_empty() {
            String::new()
        } else {
            format!(", {:?}", h.label.trim())
        },
        product,
        h.date,
        h.time
    ));
    Ok(())
}

/// The `.zsav` header, block table and blocks; returns the total
/// uncompressed size and a span over the concatenated decompressed blocks.
async fn zsav(cx: &Cx, file: Span, data: Span, dict: &Dict, _: &Codec) -> Result<(u64, Span)> {
    let endian = dict.endian();
    let mut cur = Cursor::new(cx, data, endian);
    let header_at = cur.int::<i64>().await?;
    let trailer_at = cur.int::<i64>().await?;
    let trailer_len = cur.int::<i64>().await?;
    let header = data.sub(0, 24);
    cx.emit(Node::new("zlib header").span(header).summary(format!(
        "header at {header_at:#x}, trailer at {trailer_at:#x} ({trailer_len} bytes)"
    )));
    let trailer = file.sub_exact(
        u64::try_from(trailer_at).unwrap_or(u64::MAX),
        u64::try_from(trailer_len).unwrap_or(u64::MAX),
    )?;
    let raw = cx.read(trailer).await?;
    let get32 = |at: usize| i32_of(&raw, at, endian);
    let get64 = |at: usize| {
        match endian {
            Endian::Big => crate::bytes::u64_be(&raw, at),
            Endian::Little => crate::bytes::u64_le(&raw, at),
        }
        .unwrap_or(0)
    };
    let blocks = u32::try_from(get32(20)).unwrap_or(0);
    let mut pieces = Vec::new();
    let mut nodes = Vec::new();
    let mut total = 0u64;
    for i in 0..blocks {
        let at = crate::bytes::to_usize(u64::from(i).saturating_mul(24).saturating_add(24));
        if raw.len() < at.saturating_add(24) {
            break;
        }
        cx.checkpoint().await;
        let uncompressed_at = get64(at);
        let compressed_at = get64(at.saturating_add(8));
        let size = u64::from(get32(at.saturating_add(16)) as u32);
        let packed = u64::from(get32(at.saturating_add(20)) as u32);
        let span = file.sub(compressed_at, packed);
        nodes.push(
            Node::new(format!("Block {}", i.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "{packed} → {size} bytes, data offset {uncompressed_at:#x}"
                )),
        );
        pieces.push(cx.decode_lazy(span, &Codec::Zlib, size)?);
        total = total.saturating_add(size);
    }
    let fields = vec![
        Node::new("Bias").span(trailer.sub(0, 8)).value(Value::Int {
            value: get64(0) as i64,
            bits: 64,
        }),
        Node::new("Zero").span(trailer.sub(8, 8)).value(Value::Int {
            value: get64(8) as i64,
            bits: 64,
        }),
        Node::new("Block size")
            .span(trailer.sub(16, 4))
            .value(Value::Int {
                value: get32(16).into(),
                bits: 32,
            }),
        Node::new("Blocks")
            .span(trailer.sub(20, 4))
            .value(Value::Int {
                value: get32(20).into(),
                bits: 32,
            }),
    ];
    let mut all = fields;
    all.extend(nodes);
    cx.emit(
        Node::new("zlib trailer")
            .span(trailer)
            .summary(format!("{blocks} blocks, {total} bytes uncompressed"))
            .lazy(emit_nodes, Arc::new(all)),
    );
    let span = cx.add_pieces(
        Origin {
            parent: data,
            transform: "zsav blocks",
        },
        pieces,
    )?;
    Ok((total, span))
}

async fn dictionary(cx: Cx, dict: Arc<Dict>) -> Result<()> {
    let endian = dict.endian();
    for (rec, span) in &dict.records {
        let span = *span;
        let node = match rec {
            Rec::Var(i) => {
                let var = dict.vars.get(*i);
                Node::new("Variable")
                    .span(span)
                    .summary(var.map_or_else(String::new, |v| v.short.clone()))
                    .lazy(variable_fields, (dict.clone(), *i))
            }
            Rec::Continuation => Node::new("Variable (string continuation)").span(span),
            Rec::Labels(i) => Node::new("Value labels")
                .span(span)
                .summary(format!(
                    "{} labels",
                    dict.sets.get(*i).map_or(0, |s| s.entries.len())
                ))
                .lazy(label_entries, (dict.clone(), *i)),
            Rec::LabelVars(i) => Node::new("Value label variables").span(span).summary(
                dict.sets
                    .get(*i)
                    .map(|s| {
                        s.vars
                            .iter()
                            .filter_map(|v| dict.vars.get(*v).map(|v| v.name.clone()))
                            .collect::<Vec<_>>()
                            .join(", ")
                    })
                    .unwrap_or_default(),
            ),
            Rec::Document(n) => Node::new("Document")
                .span(span)
                .summary(format!("{n} lines")),
            Rec::Ext {
                subtype,
                size,
                count,
            } => {
                let name = lookup(SUBTYPES, u64::from(*subtype as u32))
                    .map_or_else(|| format!("Extension {subtype}"), str::to_owned);
                Node::new(name)
                    .span(span)
                    .summary(format!("subtype {subtype}, {count} × {size} bytes"))
                    .lazy(extension, (dict.clone(), span, *subtype, endian))
            }
            Rec::End => Node::new("End of dictionary").span(span),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn extension(
    cx: Cx,
    (dict, span, subtype, endian): (Arc<Dict>, Span, i32, Endian),
) -> Result<()> {
    let data = span.tail(16);
    let raw = cx.read_avail(data.sub(0, 1 << 16)).await?;
    let int = |name: &'static str, at: u64, table: Option<EnumTable>| {
        let v = i32_of(&raw, crate::bytes::to_usize(at), endian);
        let node = Node::new(name).span(data.sub(at, 4));
        match table {
            Some(t) => node.value(Value::Enum {
                raw: u64::from(v as u32),
                bits: 32,
                name: lookup(t, u64::from(v as u32)),
            }),
            None => node.value(Value::Int {
                value: v.into(),
                bits: 32,
            }),
        }
    };
    match subtype {
        3 => {
            for (i, name) in [
                "Version major",
                "Version minor",
                "Version revision",
                "Machine code",
                "Floating-point representation",
                "Compression code",
                "Endianness",
                "Character code",
            ]
            .into_iter()
            .enumerate()
            {
                let table: Option<EnumTable> = match i {
                    4 => Some(&[(1, "IEEE 754"), (2, "IBM 370"), (3, "DEC VAX E")]),
                    6 => Some(&[(1, "big-endian"), (2, "little-endian")]),
                    _ => None,
                };
                let mut node = int(name, crate::bytes::to_u64(i).saturating_mul(4), table);
                if i == 7 {
                    let code = i32_of(&raw, 28, endian);
                    if let Some(cp) = code_page(code) {
                        node = node.summary(cp);
                    }
                }
                cx.emit(node);
            }
        }
        4 => {
            for (i, name) in ["System-missing value", "Highest value", "Lowest value"]
                .into_iter()
                .enumerate()
            {
                let at = i.saturating_mul(8);
                let v = dict.f64(eight(raw.get(at..).unwrap_or_default()));
                cx.emit(
                    Node::new(name)
                        .span(data.sub(crate::bytes::to_u64(at), 8))
                        .value(Value::Float(v))
                        .summary(format!("{v:e}")),
                );
            }
        }
        11 => {
            for var in &dict.vars {
                if let Some((measure, width, align)) = var.display {
                    let mut parts = vec![
                        lookup(MEASURES, u64::from(measure as u32))
                            .unwrap_or("?")
                            .to_owned(),
                    ];
                    if let Some(w) = width {
                        parts.push(format!("width {w}"));
                    }
                    parts.push(
                        lookup(ALIGNMENTS, u64::from(align as u32))
                            .unwrap_or("?")
                            .to_owned(),
                    );
                    cx.push(Node::new(var.name.clone()).summary(parts.join(", ")))
                        .await;
                }
            }
        }
        16 => {
            for (i, name) in ["Unknown (1)", "Number of cases"].into_iter().enumerate() {
                let at = i.saturating_mul(8);
                let v = match endian {
                    Endian::Big => crate::bytes::u64_be(&raw, at),
                    Endian::Little => crate::bytes::u64_le(&raw, at),
                }
                .unwrap_or(0);
                cx.emit(
                    Node::new(name)
                        .span(data.sub(crate::bytes::to_u64(at), 8))
                        .value(Value::Int {
                            value: v as i64,
                            bits: 64,
                        }),
                );
            }
        }
        13 | 14 | 20 | 17 | 18 => {
            let text = dict.text(&raw);
            let sep = if subtype == 20 { '\u{0}' } else { '\t' };
            let mut pos = 0u64;
            for part in text.split(sep) {
                let len = crate::bytes::to_u64(part.len());
                let clean = part.trim_end_matches(['\0', ' ']);
                if !clean.is_empty() {
                    cx.push(
                        Node::new("Entry")
                            .span(data.sub(pos, len))
                            .value(Value::Text(clean.to_owned())),
                    )
                    .await;
                }
                pos = pos.saturating_add(len).saturating_add(1);
            }
        }
        _ => {
            cx.emit(Node::new("Data").span(data));
        }
    }
    Ok(())
}

async fn variable_fields(cx: Cx, (dict, i): (Arc<Dict>, usize)) -> Result<()> {
    let Some(var) = dict.vars.get(i) else {
        return Ok(());
    };
    let r = var.record;
    let int = |name: &'static str, at: u64, v: i32| {
        Node::new(name).span(r.sub(at, 4)).value(Value::Int {
            value: v.into(),
            bits: 32,
        })
    };
    cx.emit(int("Record type", 0, 2));
    cx.emit(int("Type", 4, var.width).summary(if var.width == 0 {
        "numeric".to_owned()
    } else {
        format!("string, {} bytes", var.width)
    }));
    cx.emit(int("Has label", 8, i32::from(!var.label.is_empty())));
    let n_missing = match &var.missing {
        Missing::None => 0,
        Missing::Values(v) => crate::bytes::to_u64(v.len()) as i32,
        Missing::Range { extra, .. } => {
            if extra.is_some() {
                -3
            } else {
                -2
            }
        }
    };
    cx.emit(int("Missing values", 12, n_missing));
    cx.emit(
        Node::new("Print format")
            .span(r.sub(16, 4))
            .value(Value::Text(format_name(var.print))),
    );
    cx.emit(
        Node::new("Write format")
            .span(r.sub(20, 4))
            .value(Value::Text(format_name(var.write))),
    );
    cx.emit(
        Node::new("Name")
            .span(r.sub(24, 8))
            .value(Value::Text(var.short.clone())),
    );
    let mut at = 32u64;
    if !var.label.is_empty() {
        let len = crate::bytes::to_u64(var.label.len());
        cx.emit(int("Label length", at, len as i32));
        cx.emit(
            Node::new("Label")
                .span(r.sub(at.saturating_add(4), len))
                .value(Value::Text(var.label.clone())),
        );
        at = at
            .saturating_add(4)
            .saturating_add(len.saturating_add(3) & !3);
    }
    match &var.missing {
        Missing::None => {}
        Missing::Values(values) => {
            for v in values {
                cx.emit(
                    Node::new("Missing value")
                        .span(r.sub(at, 8))
                        .value(Value::Text(dict.value_text(var, *v))),
                );
                at = at.saturating_add(8);
            }
        }
        Missing::Range { low, high, extra } => {
            cx.emit(
                Node::new("Missing range low")
                    .span(r.sub(at, 8))
                    .value(Value::Float(*low)),
            );
            cx.emit(
                Node::new("Missing range high")
                    .span(r.sub(at.saturating_add(8), 8))
                    .value(Value::Float(*high)),
            );
            if let Some(x) = extra {
                cx.emit(
                    Node::new("Missing value")
                        .span(r.sub(at.saturating_add(16), 8))
                        .value(Value::Float(*x)),
                );
            }
        }
    }
    Ok(())
}

fn missing_summary(dict: &Dict, var: &Var) -> Option<String> {
    match &var.missing {
        Missing::None => None,
        Missing::Values(values) => Some(
            values
                .iter()
                .map(|v| dict.value_text(var, *v))
                .collect::<Vec<_>>()
                .join(", "),
        ),
        Missing::Range { low, high, extra } => {
            let mut s = format!("{} thru {}", number(*low), number(*high));
            if let Some(x) = extra {
                s.push_str(&format!(", {}", number(*x)));
            }
            Some(s)
        }
    }
}

async fn variables(cx: Cx, dict: Arc<Dict>) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(dict.vars.len())));
    for (i, var) in dict.vars.iter().enumerate() {
        let kind = if var.width == 0 {
            "numeric".to_owned()
        } else {
            format!("string({})", var.width)
        };
        let mut parts = vec![kind, format_name(var.print)];
        if !var.label.is_empty() {
            parts.push(format!("{:?}", var.label));
        }
        let mut fields = vec![
            Node::new("Name").value(Value::Text(var.name.clone())),
            Node::new("Short name")
                .span(var.record.sub(24, 8))
                .value(Value::Text(var.short.clone())),
            Node::new("Label").value(Value::Text(var.label.clone())),
            Node::new("Type").value(Value::Text(parts.first().cloned().unwrap_or_default())),
            Node::new("Print format")
                .span(var.record.sub(16, 4))
                .value(Value::Text(format_name(var.print))),
            Node::new("Write format")
                .span(var.record.sub(20, 4))
                .value(Value::Text(format_name(var.write))),
            Node::new("Case slots")
                .value(Value::Text(format!("{} (from {})", var.slots, var.slot))),
        ];
        if let Some(m) = missing_summary(&dict, var) {
            fields.push(Node::new("Missing values").value(Value::Text(m)));
        }
        if let Some((measure, width, align)) = var.display {
            fields.push(Node::new("Measure").value(Value::Enum {
                raw: u64::from(measure as u32),
                bits: 32,
                name: lookup(MEASURES, u64::from(measure as u32)),
            }));
            if let Some(w) = width {
                fields.push(Node::new("Display width").value(Value::Int {
                    value: w.into(),
                    bits: 32,
                }));
            }
            fields.push(Node::new("Alignment").value(Value::Enum {
                raw: u64::from(align as u32),
                bits: 32,
                name: lookup(ALIGNMENTS, u64::from(align as u32)),
            }));
        }
        for &set in &var.sets {
            if let Some(s) = dict.sets.get(set) {
                fields.push(
                    Node::new("Value labels")
                        .span(s.span)
                        .summary(set_summary(&dict, var, s)),
                );
            }
        }
        cx.push(
            Node::new(var.name.clone())
                .span(var.record)
                .summary(parts.join(", "))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
        let _ = i;
    }
    Ok(())
}

fn set_summary(dict: &Dict, var: &Var, set: &LabelSet) -> String {
    set.entries
        .iter()
        .take(8)
        .map(|(v, l, _)| format!("{} = {l:?}", dict.value_text(var, *v)))
        .chain((set.entries.len() > 8).then(|| "…".to_owned()))
        .collect::<Vec<_>>()
        .join(", ")
}

async fn label_sets(cx: Cx, dict: Arc<Dict>) -> Result<()> {
    for (i, set) in dict.sets.iter().enumerate() {
        let names: Vec<String> = set
            .vars
            .iter()
            .filter_map(|v| dict.vars.get(*v).map(|v| v.name.clone()))
            .collect();
        let summary = match set.vars.first().and_then(|v| dict.vars.get(*v)) {
            Some(var) => set_summary(&dict, var, set),
            None => format!("{} labels", set.entries.len()),
        };
        cx.push(
            Node::new(format!(
                "Set {} ({})",
                i.saturating_add(1),
                names.join(", ")
            ))
            .span(set.span)
            .summary(summary)
            .lazy(label_entries, (dict.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn label_entries(cx: Cx, (dict, i): (Arc<Dict>, usize)) -> Result<()> {
    let Some(set) = dict.sets.get(i) else {
        return Ok(());
    };
    let numeric = Var {
        short: String::new(),
        name: String::new(),
        width: 0,
        label: String::new(),
        print: 0,
        write: 0,
        missing: Missing::None,
        slot: 0,
        slots: 0,
        record: set.span,
        sets: Vec::new(),
        display: None,
    };
    let var = set
        .vars
        .first()
        .and_then(|v| dict.vars.get(*v))
        .unwrap_or(&numeric);
    for (value, label, span) in &set.entries {
        cx.push(
            Node::new(dict.value_text(var, *value))
                .span(*span)
                .value(Value::Text(label.clone())),
        )
        .await;
    }
    Ok(())
}

/// Decodes one case into items (yielding between variables when there are
/// many, or many value labels to compare).
async fn decode_case(cx: &Cx, dict: &Dict, span: Span, bytes: &[u8]) -> Vec<Item> {
    let mut work = 0u64;
    let sysmis = dict.sysmis.unwrap_or(SYSMIS);
    let mut items = Vec::new();
    for var in &dict.vars {
        // One unit of work per 4096 variables or labels compared.
        work = work.saturating_add(1);
        while work >= 4096 {
            cx.checkpoint().await;
            work = work.saturating_sub(4096);
        }
        let at = var.slot.saturating_mul(8);
        let start = crate::bytes::to_usize(at);
        if var.width == 0 {
            let raw = eight(bytes.get(start..).unwrap_or_default());
            let v = dict.f64(raw);
            let bits = match dict.endian() {
                Endian::Big => u64::from_be_bytes(raw),
                Endian::Little => u64::from_le_bytes(raw),
            };
            let user = match &var.missing {
                Missing::None => false,
                Missing::Values(values) => values.iter().any(|m| dict.f64(*m) == v),
                Missing::Range { low, high, extra } => {
                    (*low <= v && v <= *high) || *extra == Some(v)
                }
            };
            let cell = if bits == sysmis {
                Cell::Missing {
                    name: "sysmis".to_owned(),
                    raw: None,
                }
            } else if user {
                Cell::Missing {
                    name: "user-missing".to_owned(),
                    raw: Some(v),
                }
            } else if let Some(time) = date_kind(var.print) {
                date_cell(v, 1.0, EPOCH, time)
            } else {
                Cell::Number(v)
            };
            let label = if bits == sysmis {
                None
            } else {
                dict.label_for(var, &raw, &mut work)
            };
            items.push(Item {
                name: var.name.clone(),
                cell,
                label,
                span: span.sub(at, 8),
            });
        } else {
            let width = usize::try_from(var.width).unwrap_or(0);
            let raw = bytes
                .get(start..start.saturating_add(width))
                .unwrap_or_default();
            items.push(Item {
                name: var.name.clone(),
                cell: Cell::Text(dict.text(trim_end(raw))),
                label: dict.label_for(var, raw, &mut work),
                span: span.sub(at, crate::bytes::to_u64(width)),
            });
        }
    }
    items
}

async fn cases(cx: Cx, (dict, data): (Arc<Dict>, Span)) -> Result<()> {
    let size = dict.slots.saturating_mul(8);
    if size == 0 {
        return Ok(());
    }
    let total = match dict.cases {
        Some(n) => {
            cx.set_count(Count::Exact(n));
            n
        }
        None => data.len.checked_div(size).unwrap_or(0),
    };
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < total {
        let at = i;
        cx.mark(move || at);
        let span = data.sub(i.saturating_mul(size), size);
        let name = format!("Case {}", i.saturating_add(1));
        if cx.skipping() {
            cx.push(Node::new(name)).await;
            i = i.saturating_add(1);
            continue;
        }
        let bytes = cx.read_avail(span).await?;
        if crate::bytes::to_u64(bytes.len()) < size {
            if dict.cases.is_some() || !bytes.is_empty() {
                cx.diag(Diagnostic::truncated(span, crate::bytes::to_u64(bytes.len())).at(span));
            }
            break;
        }
        let items = decode_case(&cx, &dict, span, &bytes).await;
        cx.push(row_node(name, span, items)).await;
        i = i.saturating_add(1);
    }
    Ok(())
}
