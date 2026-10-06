//! OLE property sets (MS-OLEPS): `\x05SummaryInformation` and
//! `\x05DocumentSummaryInformation`.

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Guid, Radix, Value, lookup};

const LE: Endian = Endian::Little;
/// Property sets per stream we look at (there are one or two in practice).
const MAX_SETS: u32 = 16;
/// Bytes of one property value read for display.
const VALUE_READ: u64 = 4096;

record! {
    pub struct StreamHeader {
        byte_order: u16 "Byte order" .hex(),
        version: u16 "Version",
        system: u32 "System identifier" .hex(),
        clsid: guid "CLSID",
        sets: u32 "Number of property sets",
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

const SUMMARY_NAMES: EnumTable = &[
    (1, "CodePage"),
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
    (19, "Security"),
];

const DOC_SUMMARY_NAMES: EnumTable = &[
    (1, "CodePage"),
    (2, "Category"),
    (3, "PresentationTarget"),
    (4, "Bytes"),
    (5, "Lines"),
    (6, "Paragraphs"),
    (7, "Slides"),
    (8, "Notes"),
    (9, "HiddenSlides"),
    (10, "MMClips"),
    (11, "ScaleCrop"),
    (12, "HeadingPairs"),
    (13, "TitlesOfParts"),
    (14, "Manager"),
    (15, "Company"),
    (16, "LinksUpToDate"),
    (17, "CharCountWithSpaces"),
    (19, "SharedDoc"),
    (22, "HyperlinksChanged"),
    (23, "Version"),
];

const TYPES: EnumTable = &[
    (0x0002, "VT_I2"),
    (0x0003, "VT_I4"),
    (0x0004, "VT_R4"),
    (0x0005, "VT_R8"),
    (0x000b, "VT_BOOL"),
    (0x0010, "VT_I1"),
    (0x0011, "VT_UI1"),
    (0x0012, "VT_UI2"),
    (0x0013, "VT_UI4"),
    (0x0014, "VT_I8"),
    (0x0015, "VT_UI8"),
    (0x001e, "VT_LPSTR"),
    (0x001f, "VT_LPWSTR"),
    (0x0040, "VT_FILETIME"),
    (0x0041, "VT_BLOB"),
    (0x0047, "VT_CF"),
    (0x0048, "VT_CLSID"),
    (0x100c, "VT_VECTOR | VT_VARIANT"),
    (0x101e, "VT_VECTOR | VT_LPSTR"),
    (0x101f, "VT_VECTOR | VT_LPWSTR"),
];

fn set_name(fmtid: &Guid) -> (&'static str, EnumTable) {
    if *fmtid == SUMMARY {
        ("SummaryInformation", SUMMARY_NAMES)
    } else if *fmtid == DOC_SUMMARY {
        ("DocumentSummaryInformation", DOC_SUMMARY_NAMES)
    } else if *fmtid == USER_DEFINED {
        ("User-defined properties", &[(1, "CodePage")])
    } else {
        ("Property set", &[(1, "CodePage")])
    }
}

fn guid_at(data: &[u8], at: usize) -> Option<Guid> {
    let mut data4 = [0u8; 8];
    data4.copy_from_slice(data.get(at.checked_add(8)?..at.checked_add(16)?)?);
    Some(Guid {
        data1: u32_le(data, at)?,
        data2: u16_le(data, at.checked_add(4)?)?,
        data3: u16_le(data, at.checked_add(6)?)?,
        data4,
    })
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
    for i in 0..to_usize(count.into()) {
        let at = i.saturating_mul(20);
        let (Some(fmtid), Some(offset)) =
            (guid_at(&data, at), u32_le(&data, at.saturating_add(16)))
        else {
            break;
        };
        let size_bytes = cx.read_avail(span.sub(offset.into(), 4)).await?;
        let size = u32_le(&size_bytes, 0).unwrap_or(0);
        let set = span.sub(offset.into(), size.into());
        let (name, _) = set_name(&fmtid);
        cx.emit(
            Node::new(name)
                .span(set)
                .value(Value::Guid(fmtid))
                .lazy(properties, (set, fmtid)),
        );
    }
    Ok(())
}

/// A string property's text, by code page.
fn text(data: &[u8], wide: bool, codepage: u16) -> String {
    let s = if wide || codepage == 1200 {
        crate::text::utf16(data, Endian::Little)
    } else if codepage == 65001 {
        String::from_utf8_lossy(data).into_owned()
    } else {
        crate::text::latin1(data)
    };
    s.trim_end_matches('\0').to_owned()
}

/// Decodes a typed value (`data` starts at the type field).
fn value(data: &[u8], codepage: u16) -> (Option<Value>, Option<String>) {
    let kind = u16_le(data, 0).unwrap_or(0);
    let body = data.get(4..).unwrap_or_default();
    let int = |v: Option<i64>, bits| v.map(|value| Value::Int { value, bits });
    match kind {
        0x0002 => (int(crate::bytes::i16_le(body, 0).map(i64::from), 16), None),
        0x0003 => (int(crate::bytes::i32_le(body, 0).map(i64::from), 32), None),
        0x0012 => (int(u16_le(body, 0).map(i64::from), 16), None),
        0x0013 => (int(u32_le(body, 0).map(i64::from), 32), None),
        0x0014 | 0x0015 => (
            u64_le(body, 0).map(|v| Value::Int {
                value: v.cast_signed(),
                bits: 64,
            }),
            None,
        ),
        0x0004 => (
            crate::bytes::u32_le(body, 0).map(|v| Value::Float(f64::from(f32::from_bits(v)))),
            None,
        ),
        0x0005 => (
            u64_le(body, 0).map(|v| Value::Float(f64::from_bits(v))),
            None,
        ),
        0x000b => (u16_le(body, 0).map(|v| Value::Bool(v != 0)), None),
        0x0040 => {
            let raw = u64_le(body, 0);
            match raw {
                // Durations (EditTime) are small; real dates are after 1601.
                Some(t) if t < 864_000_000_000_000 => (
                    Some(Value::UInt {
                        value: t / 10_000_000,
                        bits: 64,
                        radix: Radix::Dec,
                    }),
                    Some("seconds".to_owned()),
                ),
                Some(t) => (
                    Some(Value::Timestamp {
                        unix_seconds: crate::text::filetime_to_unix(t),
                    }),
                    None,
                ),
                None => (None, None),
            }
        }
        0x001e | 0x001f => {
            let count = to_usize(u32_le(body, 0).unwrap_or(0).into());
            let bytes = if kind == 0x001f {
                count.saturating_mul(2)
            } else {
                count
            };
            let raw = body
                .get(4..4usize.saturating_add(bytes))
                .unwrap_or(body.get(4..).unwrap_or_default());
            (Some(Value::Text(text(raw, kind == 0x001f, codepage))), None)
        }
        0x0041 | 0x0047 => {
            let len = u32_le(body, 0).unwrap_or(0);
            (None, Some(format!("{len} bytes")))
        }
        0x0048 => (guid_at(body, 0).map(Value::Guid), None),
        0x100c | 0x101e | 0x101f => {
            let n = u32_le(body, 0).unwrap_or(0);
            (None, Some(format!("{n} elements")))
        }
        _ => (None, None),
    }
}

async fn properties(cx: Cx, (set, fmtid): (Span, Guid)) -> Result<()> {
    let (_, names) = set_name(&fmtid);
    let head = cx.read(set.sub(0, 8)).await?;
    let count = u32_le(&head, 4).unwrap_or(0);
    cx.emit(Node::new("Size").span(set.sub(0, 4)).value(Value::UInt {
        value: u32_le(&head, 0).unwrap_or(0).into(),
        bits: 32,
        radix: Radix::Dec,
    }));
    let table = set.sub_exact(8, u64::from(count).saturating_mul(8))?;
    let ids = cx.read(table).await?;
    cx.set_count(Count::Exact(u64::from(count).saturating_add(1)));
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
    // The code page (property 1) decides how 8-bit strings are decoded.
    let mut codepage = 1252u16;
    if let Some(&(_, offset)) = entries.iter().find(|(id, _)| *id == 1) {
        let data = cx.read_avail(set.sub(offset.into(), 8)).await?;
        codepage = u16_le(&data, 4).unwrap_or(codepage);
    }
    for (id, offset) in entries {
        let at = set.sub(offset.into(), VALUE_READ);
        let data = cx.read_avail(at).await?;
        let kind = u16_le(&data, 0).unwrap_or(0);
        let name = if id == 0 {
            "Dictionary".to_owned()
        } else {
            lookup(names, id.into()).map_or_else(|| format!("Property {id}"), str::to_owned)
        };
        let (value, detail) = if id == 0 {
            (None, None)
        } else {
            value(&data, codepage)
        };
        let type_name =
            lookup(TYPES, kind.into()).map_or_else(|| format!("type {kind:#06x}"), str::to_owned);
        let mut node = Node::new(name)
            .span(set.sub(offset.into(), to_u64(data.len()).min(property_len(&data))))
            .summary(match detail {
                Some(d) => format!("{type_name}, {d}"),
                None => type_name,
            });
        if let Some(v) = value {
            node = node.value(v);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The length of a property value (type, padding and data), for its span.
fn property_len(data: &[u8]) -> u64 {
    let kind = u16_le(data, 0).unwrap_or(0);
    let len = |n: u64| n.saturating_add(4);
    match kind {
        0x0002 | 0x0012 | 0x000b | 0x0003 | 0x0013 | 0x0004 => len(4),
        0x0005 | 0x0014 | 0x0015 | 0x0040 => len(8),
        0x0048 => len(16),
        0x001e | 0x0041 | 0x0047 => len(u64::from(u32_le(data, 4).unwrap_or(0)).saturating_add(4)),
        0x001f => len(u64::from(u32_le(data, 4).unwrap_or(0))
            .saturating_mul(2)
            .saturating_add(4)),
        _ => len(0),
    }
}

/// The Title property of the first set, for the file summary.
pub async fn title(cx: &Cx, span: Span) -> Option<String> {
    let head = cx.read_avail(span.sub(0, 48)).await.ok()?;
    let offset = u32_le(&head, 44)?;
    let set = span.sub(offset.into(), u64::MAX);
    let set_head = cx.read_avail(set.sub(0, 8)).await.ok()?;
    let count = u32_le(&set_head, 4)?.min(256);
    let ids = cx
        .read_avail(set.sub(8, u64::from(count).saturating_mul(8)))
        .await
        .ok()?;
    let mut codepage = 1252;
    let mut title = None;
    for c in ids.as_chunks::<8>().0 {
        let [a, b, c2, d, e, f, g, h] = *c;
        let id = u32::from_le_bytes([a, b, c2, d]);
        let offset = u32::from_le_bytes([e, f, g, h]);
        if id == 1 {
            let data = cx.read_avail(set.sub(offset.into(), 8)).await.ok()?;
            codepage = u16_le(&data, 4).unwrap_or(codepage);
        } else if id == 2 {
            title = Some(offset);
        }
    }
    let data = cx.read_avail(set.sub(title?.into(), 1024)).await.ok()?;
    match value(&data, codepage) {
        (Some(Value::Text(t)), _) => Some(t),
        _ => None,
    }
}
