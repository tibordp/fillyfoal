//! OLE property sets ([MS-OLEPS]): `\x05SummaryInformation`,
//! `\x05DocumentSummaryInformation` (with its user-defined second set) and
//! any other `\x05` stream. A stream holds a header and a list of sets; a
//! set holds a size, a table of (property ID, offset) pairs, and typed
//! values, each padded to 4 bytes. Strings are in the set's code page
//! (property 1); property 0 is a dictionary naming the others.

use std::sync::Arc;

use super::rec::{LE, codepage_text, quoted};
use crate::bytes::{align_up, i16_le, i32_le, to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::guid_le;
use crate::formats::util::val::{hex, uint};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Guid, Value, lookup};

/// Property sets per stream looked at (there are one or two in practice).
const MAX_SETS: u32 = 16;
/// Elements of a vector shown.
const MAX_ELEMENTS: u32 = 1024;
/// Nesting of variants within vectors followed.
const MAX_DEPTH: u32 = 4;

const OS_KINDS: EnumTable = &[(0, "Win16"), (1, "Macintosh"), (2, "Win32")];

record! {
    pub struct StreamHeader {
        byte_order: u16 "ByteOrder" .hex() .desc("0xFFFE"),
        version: u16 "Version" .desc("0 or 1 (1 allows more types)"),
        system: u32 "SystemIdentifier" .hex() .with(|&v, n| n.summary(format!("{} {}.{}", lookup(OS_KINDS, (v >> 16).into()).unwrap_or("OS"), v & 0xff, (v >> 8) & 0xff))),
        clsid: guid "CLSID",
        sets: u32 "NumPropertySets",
    }
}

const SUMMARY: Guid = Guid {
    data1: 0xf29f_85e0,
    data2: 0x4ff9,
    data3: 0x1068,
    data4: [0xab, 0x91, 0x08, 0x00, 0x2b, 0x27, 0xb3, 0xd9],
};
const DOC_SUMMARY: Guid = Guid {
    data1: 0xd5cd_d502,
    data2: 0x2e9c,
    data3: 0x101b,
    data4: [0x93, 0x97, 0x08, 0x00, 0x2b, 0x2c, 0xf9, 0xae],
};
const USER_DEFINED: Guid = Guid {
    data1: 0xd5cd_d505,
    data2: 0x2e9c,
    data3: 0x101b,
    data4: [0x93, 0x97, 0x08, 0x00, 0x2b, 0x2c, 0xf9, 0xae],
};

const COMMON: &[(u32, &str)] = &[
    (0, "Dictionary"),
    (1, "CodePage"),
    (0x8000_0000, "Locale"),
    (0x8000_0003, "Behavior"),
];

const SUMMARY_NAMES: &[(u32, &str)] = &[
    (2, "Title"),
    (3, "Subject"),
    (4, "Author"),
    (5, "Keywords"),
    (6, "Comments"),
    (7, "Template"),
    (8, "LastAuthor"),
    (9, "RevNumber"),
    (10, "EditTime"),
    (11, "LastPrinted"),
    (12, "Created"),
    (13, "LastSaved"),
    (14, "PageCount"),
    (15, "WordCount"),
    (16, "CharCount"),
    (17, "Thumbnail"),
    (18, "AppName"),
    (19, "DocSecurity"),
];

const DOC_SUMMARY_NAMES: &[(u32, &str)] = &[
    (2, "Category"),
    (3, "PresentationFormat"),
    (4, "ByteCount"),
    (5, "LineCount"),
    (6, "ParagraphCount"),
    (7, "SlideCount"),
    (8, "NoteCount"),
    (9, "HiddenCount"),
    (10, "MMClipCount"),
    (11, "Scale"),
    (12, "HeadingPairs"),
    (13, "DocParts"),
    (14, "Manager"),
    (15, "Company"),
    (16, "LinksDirty"),
    (17, "CharacterCountWithSpaces"),
    (19, "SharedDoc"),
    (20, "LinkBase"),
    (21, "HLinks"),
    (22, "HyperlinksChanged"),
    (23, "AppVersion"),
    (24, "DigSig"),
    (26, "ContentType"),
    (27, "ContentStatus"),
    (28, "Language"),
    (29, "DocVersion"),
];

pub const TYPES: EnumTable = &[
    (0x0000, "VT_EMPTY"),
    (0x0001, "VT_NULL"),
    (0x0002, "VT_I2"),
    (0x0003, "VT_I4"),
    (0x0004, "VT_R4"),
    (0x0005, "VT_R8"),
    (0x0006, "VT_CY"),
    (0x0007, "VT_DATE"),
    (0x0008, "VT_BSTR"),
    (0x000a, "VT_ERROR"),
    (0x000b, "VT_BOOL"),
    (0x000c, "VT_VARIANT"),
    (0x000e, "VT_DECIMAL"),
    (0x0010, "VT_I1"),
    (0x0011, "VT_UI1"),
    (0x0012, "VT_UI2"),
    (0x0013, "VT_UI4"),
    (0x0014, "VT_I8"),
    (0x0015, "VT_UI8"),
    (0x0016, "VT_INT"),
    (0x0017, "VT_UINT"),
    (0x001e, "VT_LPSTR"),
    (0x001f, "VT_LPWSTR"),
    (0x0040, "VT_FILETIME"),
    (0x0041, "VT_BLOB"),
    (0x0042, "VT_STREAM"),
    (0x0043, "VT_STORAGE"),
    (0x0044, "VT_STREAMED_OBJECT"),
    (0x0045, "VT_STORED_OBJECT"),
    (0x0046, "VT_BLOB_OBJECT"),
    (0x0047, "VT_CF"),
    (0x0048, "VT_CLSID"),
    (0x0049, "VT_VERSIONED_STREAM"),
];

const CLIPBOARD: EnumTable = &[
    (2, "CF_BITMAP"),
    (3, "CF_METAFILEPICT"),
    (8, "CF_DIB"),
    (14, "CF_ENHMETAFILE"),
];

/// A set's kind: its name and its property names.
#[derive(Clone, Copy)]
enum SetKind {
    Summary,
    DocSummary,
    UserDefined,
    Other,
}

fn set_kind(fmtid: &Guid) -> SetKind {
    if *fmtid == SUMMARY {
        SetKind::Summary
    } else if *fmtid == DOC_SUMMARY {
        SetKind::DocSummary
    } else if *fmtid == USER_DEFINED {
        SetKind::UserDefined
    } else {
        SetKind::Other
    }
}

fn set_title(kind: SetKind) -> &'static str {
    match kind {
        SetKind::Summary => "SummaryInformation",
        SetKind::DocSummary => "DocumentSummaryInformation",
        SetKind::UserDefined => "User-defined properties",
        SetKind::Other => "Property set",
    }
}

fn property_name(kind: SetKind, id: u32, dictionary: &[(u32, String)]) -> String {
    if let Some((_, n)) = dictionary.iter().find(|(i, _)| *i == id) {
        return n.clone();
    }
    let table = match kind {
        SetKind::Summary => SUMMARY_NAMES,
        SetKind::DocSummary => DOC_SUMMARY_NAMES,
        _ => &[],
    };
    COMMON
        .iter()
        .chain(table)
        .find(|(i, _)| *i == id)
        .map_or_else(|| format!("Property {id}"), |(_, n)| (*n).to_owned())
}

fn guid_at(data: &[u8], at: usize) -> Option<Guid> {
    data.get(at..)?.get(..16).map(guid_le)
}

/// The property sets of a stream.
pub async fn emit(cx: &Cx, span: Span) -> Result<()> {
    let header_span = span.sub(0, StreamHeader::SIZE);
    cx.emit(StreamHeader::node("Header", header_span, LE));
    let header = crate::fields::parse(cx, header_span, LE, &(), StreamHeader::layout).await?;
    if header.byte_order != 0xfffe {
        return Err(Diagnostic::malformed("not a property set stream").at(header_span.sub(0, 2)));
    }
    let count = header.sets.min(MAX_SETS);
    let list = span.sub_exact(StreamHeader::SIZE, u64::from(count).saturating_mul(20))?;
    let data = cx.read(list).await?;
    let mut end = list.end().saturating_sub(span.offset);
    for i in 0..to_usize(count.into()) {
        let at = i.saturating_mul(20);
        let (Some(fmtid), Some(offset)) =
            (guid_at(&data, at), u32_le(&data, at.saturating_add(16)))
        else {
            break;
        };
        let entry = list.sub(to_u64(at), 20);
        cx.emit(
            Node::new(format!("FMTID/Offset {i}"))
                .span(entry)
                .value(Value::Guid(fmtid))
                .summary(format!("{} at {offset:#x}", set_title(set_kind(&fmtid)))),
        );
        let size_bytes = cx.read_avail(span.sub(offset.into(), 4)).await?;
        let size = u32_le(&size_bytes, 0).unwrap_or(0);
        let set = span.sub(offset.into(), size.into());
        let parsed = parse_set(cx, set).await;
        let mut node = Node::new(set_title(set_kind(&fmtid)))
            .span(set)
            .value(Value::Guid(fmtid));
        match &parsed {
            Ok(p) => {
                node = node.summary(format!(
                    "{} properties, code page {}",
                    p.entries.len(),
                    p.codepage
                ));
            }
            Err(e) => node = node.diag(e.clone()),
        }
        if let Ok(p) = parsed {
            node = node.lazy(properties, (set, fmtid, Arc::new(p)));
        }
        cx.emit(node);
        end = end.max(set.end().saturating_sub(span.offset));
    }
    if end < span.len {
        let rest = span.tail(end);
        let data = cx.read_avail(rest.sub(0, 4096)).await?;
        cx.emit(Node::new("Padding").span(rest).summary(format!(
            "{} bytes after the last set{}",
            rest.len,
            if data.iter().all(|&b| b == 0) {
                ", zeros"
            } else {
                ""
            }
        )));
    }
    Ok(())
}

/// A parsed set: its property table, code page and dictionary.
pub struct Set {
    entries: Vec<(u32, u32)>,
    codepage: u16,
    dictionary: Vec<(u32, String)>,
}

async fn parse_set(cx: &Cx, set: Span) -> Result<Set> {
    let head = cx.read(set.sub(0, 8)).await?;
    let count = u32_le(&head, 4).unwrap_or(0);
    let table = set.sub_exact(8, u64::from(count).saturating_mul(8))?;
    let ids = cx.read(table).await?;
    let entries: Vec<(u32, u32)> = ids
        .as_chunks::<8>()
        .0
        .iter()
        .map(|c| {
            let [a, b, c2, d, e, f, g, h] = *c;
            (
                u32::from_le_bytes([a, b, c2, d]),
                u32::from_le_bytes([e, f, g, h]),
            )
        })
        .collect();
    let mut codepage = 1252u16;
    if let Some(&(_, offset)) = entries.iter().find(|(id, _)| *id == 1) {
        let data = cx.read_avail(set.sub(offset.into(), 8)).await?;
        codepage = u16_le(&data, 4).unwrap_or(codepage);
    }
    let mut dictionary = Vec::new();
    if let Some(&(_, offset)) = entries.iter().find(|(id, _)| *id == 0) {
        let data = cx.read_avail(set.sub(offset.into(), 0x10000)).await?;
        dictionary = parse_dictionary(&data, codepage)
            .0
            .into_iter()
            .map(|(id, name, _, _)| (id, name))
            .collect();
    }
    Ok(Set {
        entries,
        codepage,
        dictionary,
    })
}

/// A dictionary: (id, name) pairs and the bytes they take.
fn parse_dictionary(data: &[u8], codepage: u16) -> (Vec<(u32, String, usize, usize)>, usize) {
    let n = u32_le(data, 0).unwrap_or(0).min(4096);
    let mut out = Vec::new();
    let mut at = 4usize;
    for _ in 0..n {
        let (Some(id), Some(cch)) = (u32_le(data, at), u32_le(data, at.saturating_add(4))) else {
            break;
        };
        let wide = codepage == 1200;
        let bytes = to_usize(cch.into()).saturating_mul(if wide { 2 } else { 1 });
        let start = at.saturating_add(8);
        let raw = data
            .get(start..start.saturating_add(bytes))
            .unwrap_or_default();
        let name = codepage_text(codepage, raw)
            .trim_end_matches('\0')
            .to_owned();
        let mut end = start.saturating_add(bytes);
        if wide {
            end = to_usize(align_up(to_u64(end), 4));
        }
        out.push((id, name, at, end.saturating_sub(at)));
        at = end;
    }
    let total = at.saturating_add(3) & !3;
    (out, total)
}

/// A decoded value: its value or summary, its size in bytes (padded), and
/// child nodes for vectors.
struct Decoded {
    value: Option<Value>,
    summary: Option<String>,
    len: usize,
    children: Vec<Child>,
}

/// Decodes a value of type `vt` at `data[at..]` (after the type field).
fn decode(
    vt: u16,
    data: &[u8],
    at: usize,
    codepage: u16,
    name: &str,
    depth: u32,
) -> Option<Decoded> {
    let int = |value: i64, bits| Some(Value::Int { value, bits });
    let simple = |value: Option<Value>, len: usize| {
        Some(Decoded {
            value,
            summary: None,
            len,
            children: Vec::new(),
        })
    };
    if vt & 0x1000 != 0 {
        if depth >= MAX_DEPTH {
            return None;
        }
        let base = vt & 0x0fff;
        let count = u32_le(data, at)?.min(MAX_ELEMENTS);
        let mut pos = at.checked_add(4)?;
        let mut children = Vec::new();
        let mut texts = Vec::new();
        for i in 0..count {
            let start = pos;
            let (elem_vt, value_at) = if base == 0x000c {
                (u16_le(data, pos)?, pos.checked_add(4)?)
            } else {
                (base, pos)
            };
            let d = decode(
                elem_vt,
                data,
                value_at,
                codepage,
                "",
                depth.saturating_add(1),
            )?;
            // Vector elements of 2-byte types are not padded individually.
            let len = if base != 0x000c && matches!(base, 0x0002 | 0x000b | 0x0012) {
                2
            } else {
                d.len
            };
            let end = value_at.checked_add(len)?;
            if let Some(Value::Text(t)) = &d.value {
                texts.push(quoted(t, 30));
            } else if let Some(Value::Int { value, .. }) = &d.value {
                texts.push(value.to_string());
            }
            let label = if base == 0x000c {
                lookup(TYPES, elem_vt.into())
                    .unwrap_or("variant")
                    .to_owned()
            } else {
                String::new()
            };
            children.push((
                format!("Element {i}"),
                start,
                end.saturating_sub(start),
                d.value,
                if label.is_empty() {
                    d.summary
                } else {
                    Some(label)
                },
            ));
            pos = end;
        }
        let total = to_usize(align_up(to_u64(pos), 4)).saturating_sub(at);
        let mut summary = format!("{count} elements");
        if !texts.is_empty() {
            summary = format!(
                "{summary}: {}",
                texts.iter().take(8).cloned().collect::<Vec<_>>().join(", ")
            );
        }
        return Some(Decoded {
            value: None,
            summary: Some(summary),
            len: total,
            children,
        });
    }
    match vt {
        0x0000 | 0x0001 => simple(None, 0),
        0x0002 => simple(int(i64::from(i16_le(data, at)?), 16), 4),
        0x0003 | 0x0016 => simple(int(i64::from(i32_le(data, at)?), 32), 4),
        0x0004 => simple(
            Some(Value::Float(f64::from(f32::from_bits(u32_le(data, at)?)))),
            4,
        ),
        0x0005 => simple(Some(Value::Float(f64::from_bits(u64_le(data, at)?))), 8),
        0x0006 => {
            let v = u64_le(data, at)?.cast_signed();
            Some(Decoded {
                value: int(v, 64),
                summary: Some(crate::formats::data::valuetree::decimal_string(
                    v < 0,
                    &v.unsigned_abs().to_string(),
                    -4,
                )),
                len: 8,
                children: Vec::new(),
            })
        }
        0x0007 => {
            let days = f64::from_bits(u64_le(data, at)?);
            let value = match crate::formats::util::civil::ole_date(days) {
                Some(unix_seconds) => Value::Timestamp { unix_seconds },
                None => Value::Float(days),
            };
            Some(Decoded {
                value: Some(value),
                summary: Some(format!("{days} days since 1899-12-30")),
                len: 8,
                children: Vec::new(),
            })
        }
        0x000a => simple(Some(hex(u32_le(data, at)?, 32)), 4),
        0x000b => simple(Some(Value::Bool(u16_le(data, at)? != 0)), 4),
        0x0010 => simple(int(i64::from(data.get(at)?.cast_signed()), 8), 4),
        0x0011 => simple(Some(uint(*data.get(at)?, 8)), 4),
        0x0012 => simple(Some(uint(u16_le(data, at)?, 16)), 4),
        0x0013 | 0x0017 => simple(Some(uint(u32_le(data, at)?, 32)), 4),
        0x0014 => simple(int(u64_le(data, at)?.cast_signed(), 64), 8),
        0x0015 => simple(Some(uint(u64_le(data, at)?, 64)), 8),
        0x001e | 0x0008 => {
            let size = to_usize(u32_le(data, at)?.into());
            let start = at.checked_add(4)?;
            let raw = data.get(start..start.checked_add(size)?)?;
            let text = codepage_text(codepage, raw)
                .trim_end_matches('\0')
                .to_owned();
            simple(
                Some(Value::Text(text)),
                to_usize(align_up(to_u64(size.saturating_add(4)), 4)),
            )
        }
        0x001f => {
            let cch = to_usize(u32_le(data, at)?.into());
            let start = at.checked_add(4)?;
            let raw = data.get(start..start.checked_add(cch.checked_mul(2)?)?)?;
            let text = crate::text::utf16_trimmed(raw, LE);
            simple(
                Some(Value::Text(text)),
                to_usize(align_up(to_u64(cch.saturating_mul(2).saturating_add(4)), 4)),
            )
        }
        0x0040 => {
            let t = u64_le(data, at)?;
            // EditTime is a duration; times before 1601 + 100 days are too.
            if name == "EditTime" || t < 864_000_000_000_000 {
                Some(Decoded {
                    value: Some(uint(t / 10_000_000, 64)),
                    summary: Some("seconds".to_owned()),
                    len: 8,
                    children: Vec::new(),
                })
            } else {
                simple(
                    Some(Value::Timestamp {
                        unix_seconds: crate::text::filetime_to_unix(t),
                    }),
                    8,
                )
            }
        }
        0x0041 | 0x0046 => {
            let size = to_usize(u32_le(data, at)?.into());
            let raw = data.get(at.checked_add(4)?..at.checked_add(4)?.checked_add(size)?)?;
            Some(Decoded {
                value: Some(Value::Bytes(raw.get(..64).unwrap_or(raw).to_vec())),
                summary: Some(format!("{size} bytes")),
                len: to_usize(align_up(to_u64(size.saturating_add(4)), 4)),
                children: Vec::new(),
            })
        }
        0x0047 => {
            let size = to_usize(u32_le(data, at)?.into());
            let format = i32_le(data, at.checked_add(4)?)?;
            let summary = match format {
                -1 => {
                    let cf = u32_le(data, at.checked_add(8)?)?;
                    format!(
                        "{size} bytes, Windows clipboard format {}",
                        lookup(CLIPBOARD, cf.into()).map_or_else(|| cf.to_string(), str::to_owned)
                    )
                }
                -2 => format!("{size} bytes, Macintosh clipboard format"),
                -3 => format!("{size} bytes, format identified by FMTID"),
                0 => format!("{size} bytes, no format"),
                n => format!("{size} bytes, named format ({n} characters)"),
            };
            Some(Decoded {
                value: None,
                summary: Some(summary),
                len: to_usize(align_up(to_u64(size.saturating_add(4)), 4)),
                children: Vec::new(),
            })
        }
        0x0048 => simple(guid_at(data, at).map(Value::Guid), 16),
        0x0042..=0x0045 | 0x0049 => {
            let size = to_usize(u32_le(data, at)?.into());
            let raw = data.get(at.checked_add(4)?..at.checked_add(4)?.checked_add(size)?)?;
            Some(Decoded {
                value: Some(Value::Text(
                    codepage_text(codepage, raw)
                        .trim_end_matches('\0')
                        .to_owned(),
                )),
                summary: Some("name of a stream or storage".to_owned()),
                len: to_usize(align_up(to_u64(size.saturating_add(4)), 4)),
                children: Vec::new(),
            })
        }
        _ => None,
    }
}

async fn properties(cx: Cx, (set, fmtid, parsed): (Span, Guid, Arc<Set>)) -> Result<()> {
    let kind = set_kind(&fmtid);
    let dictionary: Vec<(u32, String)> = parsed.dictionary.clone();
    let count = parsed.entries.len();
    cx.emit(
        Node::new("Size")
            .span(set.sub(0, 4))
            .value(uint(set.len, 32)),
    );
    cx.emit(
        Node::new("NumProperties")
            .span(set.sub(4, 4))
            .value(uint(to_u64(count), 32)),
    );
    cx.emit(
        Node::new("PropertyIdentifierAndOffset")
            .span(set.sub(8, to_u64(count).saturating_mul(8)))
            .summary(format!("{count} entries"))
            .lazy(
                id_table,
                (
                    set,
                    kind,
                    Arc::new(parsed.entries.clone()),
                    Arc::new(dictionary.clone()),
                ),
            ),
    );
    cx.set_count(Count::Exact(to_u64(count).saturating_add(3)));
    for &(id, offset) in &parsed.entries {
        let at = set.sub(offset.into(), u64::MAX);
        let data = cx.read_avail(at.sub(0, 0x10000)).await?;
        let name = property_name(kind, id, &dictionary);
        if id == 0 {
            let (entries, len) = parse_dictionary(&data, parsed.codepage);
            let span = at.sub(0, to_u64(len));
            cx.push(
                Node::new("Dictionary")
                    .span(span)
                    .summary(format!("{} names", entries.len()))
                    .lazy(dictionary_node, (span, Arc::new(entries))),
            )
            .await;
            continue;
        }
        let vt = u16_le(&data, 0).unwrap_or(0);
        let type_name = lookup(TYPES, (vt & 0x0fff).into())
            .map_or_else(|| format!("type {vt:#06x}"), str::to_owned);
        let type_name = if vt & 0x1000 != 0 {
            format!("VT_VECTOR | {type_name}")
        } else {
            type_name
        };
        let mut node = Node::new(name.clone());
        match decode(vt, &data, 4, parsed.codepage, &name, 0) {
            Some(d) => {
                let span = at.sub(0, to_u64(d.len.saturating_add(4)));
                node = node.span(span);
                if let Some(v) = d.value.clone() {
                    node = node.value(v);
                }
                node = node.summary(match &d.summary {
                    Some(s) => format!("{type_name}, {s}"),
                    None => type_name.clone(),
                });
                if id == 1 {
                    node = node.desc("Code page of the set's 8-bit strings");
                }
                node = node.lazy(value_node, (span, vt, Arc::new(d.children)));
            }
            None => {
                node = node
                    .span(at.sub(0, 4))
                    .summary(type_name)
                    .diag(Diagnostic::malformed("the value could not be decoded"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn id_table(
    cx: Cx,
    (set, kind, entries, dictionary): (Span, SetKind, Entries, Names),
) -> Result<()> {
    for (i, &(id, offset)) in entries.iter().enumerate() {
        let span = set.sub(8u64.saturating_add(to_u64(i).saturating_mul(8)), 8);
        cx.push(
            Node::new(property_name(kind, id, &dictionary))
                .span(span)
                .value(hex(id, 32))
                .summary(format!("value at {offset:#x}"))
                .target(set.sub(offset.into(), 4)),
        )
        .await;
    }
    Ok(())
}

async fn dictionary_node(cx: Cx, (span, entries): (Span, DictEntries)) -> Result<()> {
    cx.emit(
        Node::new("NumEntries")
            .span(span.sub(0, 4))
            .value(uint(to_u64(entries.len()), 32)),
    );
    for (id, name, at, len) in entries.iter() {
        cx.push(
            Node::new(format!("Property {id}"))
                .span(span.sub(to_u64(*at), to_u64(*len)))
                .value(Value::Text(name.clone())),
        )
        .await;
    }
    Ok(())
}

type Children = Arc<Vec<Child>>;

/// A vector element: name, offset, length, value and summary.
type Child = (String, usize, usize, Option<Value>, Option<String>);
/// Property IDs and offsets.
type Entries = Arc<Vec<(u32, u32)>>;
/// Dictionary names.
type Names = Arc<Vec<(u32, String)>>;
/// Dictionary entries: ID, name, offset, length.
type DictEntries = Arc<Vec<(u32, String, usize, usize)>>;

async fn value_node(cx: Cx, (span, vt, children): (Span, u16, Children)) -> Result<()> {
    let mut type_node = Node::new("Type")
        .span(span.sub(0, 2))
        .value(crate::formats::util::val::enumv(vt & 0x0fff, 16, TYPES));
    if vt & 0x1000 != 0 {
        type_node = type_node.summary("VT_VECTOR");
    }
    cx.emit(type_node);
    cx.emit(
        Node::new("Padding")
            .span(span.sub(2, 2))
            .value(uint(0u8, 16)),
    );
    if children.is_empty() {
        let body = span.tail(4);
        if !body.is_empty() {
            cx.emit(Node::new("Value").span(body));
        }
        return Ok(());
    }
    cx.emit(
        Node::new("Count")
            .span(span.sub(4, 4))
            .value(uint(to_u64(children.len()), 32)),
    );
    for (name, at, len, value, summary) in children.iter() {
        let mut node = Node::new(name.clone()).span(span.sub(to_u64(*at), to_u64(*len)));
        if let Some(v) = value {
            node = node.value(v.clone());
        }
        if let Some(s) = summary {
            node = node.summary(s.clone());
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The Title property of the first set, for the file summary.
pub async fn title(cx: &Cx, span: Span) -> Option<String> {
    let head = cx.read_avail(span.sub(0, 48)).await.ok()?;
    let offset = u32_le(&head, 44)?;
    let set = span.sub(offset.into(), u64::MAX);
    let parsed = parse_set(cx, set).await.ok()?;
    let &(_, at) = parsed.entries.iter().find(|(id, _)| *id == 2)?;
    let data = cx.read_avail(set.sub(at.into(), 1024)).await.ok()?;
    let vt = u16_le(&data, 0)?;
    match decode(vt, &data, 4, parsed.codepage, "Title", 0)?.value {
        Some(Value::Text(t)) => Some(t),
        _ => None,
    }
}
