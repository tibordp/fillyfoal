//! Canon CRW: the Camera Image File Format (CIFF).
//!
//! A short header, then a heap: a data area whose last four bytes give the
//! offset of its directory (`count, entries`). Each 10-byte entry has a tag
//! (storage location in bits 14-15, data type in bits 11-13, the id below),
//! a size and an offset; small values are stored in the entry itself.
//! Subdirectory entries point at nested heaps. Values are decoded by type
//! (strings, 16- and 32-bit arrays) and, for the well-known records (image
//! info, capture time, exposure info, camera settings, shot info), by
//! meaning; the camera settings and shot info arrays are the ones Canon's
//! later maker notes carry.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Prim};
use crate::formats::util::arcutil::human_size;
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

use super::tiff::maker::{Note, array_enum, array_fields};
use super::tiff::render::{exposure_time, fnumber, trim};
use super::{dims, text, uint};

pub static FORMAT: Format = Format {
    name: "crw",
    title: "Canon raw (CRW)",
    extensions: &["crw"],
    mime: "image/x-canon-crw",
    probe: Probe::Magic(&[(6, b"HEAPCCDR")]),
    dissect: crate::expander!(dissect: Input),
};

const TAGS: EnumTable = &[
    (0x0000, "Null record"),
    (0x0001, "Free bytes"),
    (0x0032, "Color info"),
    (0x0805, "User comment"),
    (0x080a, "Make and model"),
    (0x080b, "Firmware version"),
    (0x080c, "Component version"),
    (0x080d, "ROM operation mode"),
    (0x0810, "Owner name"),
    (0x0815, "Image type"),
    (0x0816, "Original file name"),
    (0x0817, "Thumbnail file name"),
    (0x100a, "Target image type"),
    (0x1010, "Shutter release method"),
    (0x1011, "Shutter release timing"),
    (0x1016, "Release setting"),
    (0x101c, "Base ISO"),
    (0x1028, "Canon flash info"),
    (0x1029, "Focal length"),
    (0x102a, "Shot info"),
    (0x102c, "Canon color info 2"),
    (0x102d, "Camera settings"),
    (0x1030, "White sample"),
    (0x1031, "Sensor info"),
    (0x1033, "Custom functions"),
    (0x1038, "AF info"),
    (0x1093, "File info"),
    (0x10a9, "White balance table"),
    (0x10b4, "Color space"),
    (0x10b5, "Raw JPEG info"),
    (0x1803, "Image format"),
    (0x1804, "Record ID"),
    (0x1806, "Self-timer time"),
    (0x1807, "Target distance setting"),
    (0x180b, "Serial number"),
    (0x180e, "Capture time"),
    (0x1810, "Image info"),
    (0x1813, "Flash info"),
    (0x1814, "Measured EV"),
    (0x1817, "File number"),
    (0x1818, "Exposure info"),
    (0x1834, "Canon model ID"),
    (0x1835, "Decoder table"),
    (0x183b, "Serial number format"),
    (0x2005, "Raw data"),
    (0x2007, "JPEG from raw"),
    (0x2008, "Thumbnail"),
    (0x2804, "Image description"),
    (0x2807, "Camera object"),
    (0x3002, "Shooting record"),
    (0x3003, "Measured info"),
    (0x3004, "Camera specification"),
    (0x300a, "Image properties"),
    (0x300b, "Exif information"),
];

const TYPES: EnumTable = &[
    (0x0000, "bytes"),
    (0x0800, "ASCII"),
    (0x1000, "16-bit words"),
    (0x1800, "32-bit words"),
    (0x2000, "structure"),
    (0x2800, "subdirectory"),
    (0x3000, "subdirectory"),
];

const COLOR_SPACE: EnumTable = &[(1, "sRGB"), (2, "Adobe RGB"), (0xffff, "Uncalibrated")];
const TARGET_IMAGE_TYPE: EnumTable = &[(0, "Real-world subject"), (1, "Written document")];
const RELEASE_METHOD: EnumTable = &[(0, "Single shot"), (2, "Continuous shooting")];
const RELEASE_TIMING: EnumTable = &[(0, "Priority on shutter"), (1, "Priority on focus")];

/// How deeply heaps may nest.
const MAX_DEPTH: u32 = 8;
/// Directories searched for the summary.
const MAX_SEARCH: usize = 64;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 2)).await?;
    let endian = if head == b"MM" {
        Endian::Big
    } else {
        Endian::Little
    };
    let block = cx.block(file.sub(0, 26)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.ascii("Byte order", 2).emit()?;
    let header_len = f.u32("Header length").emit()?;
    f.ascii("Signature", 8).emit()?;
    f.u32("Version")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}", v >> 16, v & 0xffff)))
        .emit()?;
    f.bytes("Reserved", 8).emit()?;
    let heap = file.tail(header_len.into());
    cx.annotate(summary(&cx, heap, endian).await);
    cx.emit(heap_node("Root heap", input, heap, endian, 0));
    Ok(())
}

fn heap_node(name: &'static str, input: Input, heap: Span, endian: Endian, depth: u32) -> Node {
    Node::new(name).span(heap).lazy(
        crate::expander!(self::list: (Input, Span, Endian, u32)),
        (input, heap, endian, depth),
    )
}

#[derive(Clone, Copy, Debug)]
struct Entry {
    span: Span,
    id: u16,
    kind: u16,
    in_record: bool,
    data: Span,
}

impl Entry {
    fn is_heap(&self) -> bool {
        matches!(self.kind, 0x2800 | 0x3000) && !self.in_record
    }
}

/// The directory of a heap.
async fn directory(cx: &Cx, heap: Span, endian: Endian) -> Result<(Span, Vec<Entry>)> {
    let tail = cx.read(heap.sub(heap.len.saturating_sub(4), 4)).await?;
    let offset = u64::from(u32::decode(&tail, endian).unwrap_or(0));
    let count_span = heap.sub_exact(offset, 2)?;
    let count = u16::decode(&cx.read(count_span).await?, endian).unwrap_or(0);
    let table = heap.sub_exact(
        offset.saturating_add(2),
        u64::from(count).saturating_mul(10),
    )?;
    let bytes = cx.read(table).await?;
    let mut entries = Vec::new();
    for (i, b) in bytes.as_chunks::<10>().0.iter().enumerate() {
        let get16 = |at: usize| {
            b.get(at..at.saturating_add(2))
                .and_then(|s| u16::decode(s, endian))
                .unwrap_or(0)
        };
        let get32 = |at: usize| {
            b.get(at..at.saturating_add(4))
                .and_then(|s| u32::decode(s, endian))
                .unwrap_or(0)
        };
        let tag = get16(0);
        let span = table.sub(crate::bytes::to_u64(i).saturating_mul(10), 10);
        let in_record = tag & 0xc000 == 0x4000;
        let data = if in_record {
            span.sub(2, 8)
        } else {
            heap.sub(get32(6).into(), get32(2).into())
        };
        entries.push(Entry {
            span,
            id: tag & 0x3fff,
            kind: tag & 0x3800,
            in_record,
            data,
        });
    }
    Ok((count_span, entries))
}

/// The entries with the given ids, searched breadth-first through nested
/// heaps.
async fn find(cx: &Cx, heap: Span, endian: Endian, ids: &[u16]) -> Vec<Entry> {
    let mut found = Vec::new();
    let mut queue = vec![heap];
    let mut searched = 0usize;
    while let Some(h) = queue.pop() {
        searched = searched.saturating_add(1);
        if searched > MAX_SEARCH {
            break;
        }
        let Ok((_, entries)) = directory(cx, h, endian).await else {
            continue;
        };
        for e in entries {
            if ids.contains(&e.id) && !found.iter().any(|f: &Entry| f.id == e.id) {
                found.push(e);
            }
            if e.is_heap() && queue.len() < MAX_SEARCH {
                queue.insert(0, e.data);
            }
        }
    }
    found
}

/// "Canon PowerShot G2, 2272×1704, f/4, 1/250 s, 2004-05-01 12:00, CIFF".
async fn summary(cx: &Cx, heap: Span, endian: Endian) -> String {
    let entries = find(cx, heap, endian, &[0x080a, 0x1810, 0x1818, 0x180e]).await;
    let mut parts = Vec::new();
    for id in [0x080a, 0x1810, 0x1818, 0x180e] {
        let Some(e) = entries.iter().find(|e| e.id == id) else {
            continue;
        };
        let bytes = cx.read_avail(e.data.sub(0, 256)).await.unwrap_or_default();
        match id {
            0x080a => {
                if let Some(model) = strings(&bytes).pop() {
                    parts.push(model);
                }
            }
            0x1810 => {
                if let (Some(w), Some(h)) = (u32_at(&bytes, 0, endian), u32_at(&bytes, 4, endian)) {
                    parts.push(dims(w, h));
                }
            }
            0x1818 => parts.extend(exposure(&bytes, endian)),
            _ => {
                if let Some(t) = u32_at(&bytes, 0, endian).filter(|&t| t > 0) {
                    parts.push(date(t.into()));
                }
            }
        }
    }
    parts.push("CIFF".to_owned());
    parts.join(", ")
}

fn u32_at(b: &[u8], at: usize, endian: Endian) -> Option<u32> {
    u32::decode(b.get(at..at.checked_add(4)?)?, endian)
}

fn f32_at(b: &[u8], at: usize, endian: Endian) -> Option<f32> {
    f32::decode(b.get(at..at.checked_add(4)?)?, endian)
}

/// "f/4, 1/250 s" from the exposure info record (APEX values).
fn exposure(b: &[u8], endian: Endian) -> Vec<String> {
    let mut parts = Vec::new();
    if let Some(av) = f32_at(b, 8, endian).filter(|v| v.is_finite() && *v != 0.0) {
        parts.push(fnumber(2f64.powf(f64::from(av) / 2.0)));
    }
    if let Some(tv) = f32_at(b, 4, endian).filter(|v| v.is_finite() && *v != 0.0) {
        parts.push(exposure_time(2f64.powf(-f64::from(tv))));
    }
    parts
}

/// Unix seconds as "YYYY-MM-DD HH:MM" (the camera's local time).
fn date(t: i64) -> String {
    let days = t.div_euclid(86_400);
    let secs = t.rem_euclid(86_400);
    let (y, m, d) = crate::formats::util::civil::civil(days);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60
    )
}

fn strings(bytes: &[u8]) -> Vec<String> {
    bytes
        .split(|&c| c == 0)
        .filter(|s| !s.is_empty())
        .map(crate::text::latin1)
        .collect()
}

async fn list(cx: Cx, (input, heap, endian, depth): (Input, Span, Endian, u32)) -> Result<()> {
    let (count_span, entries) = directory(&cx, heap, endian).await?;
    cx.emit(
        Node::new("Entry count")
            .span(count_span)
            .value(uint(crate::bytes::to_u64(entries.len()))),
    );
    for e in entries {
        let name =
            lookup(TAGS, e.id.into()).map_or_else(|| format!("Tag {:#06x}", e.id), str::to_owned);
        let kind = lookup(TYPES, e.kind.into()).unwrap_or("?");
        let mut node = Node::new(name)
            .span(e.span)
            .summary(format!("{kind}, {}", human_size(e.data.len)))
            .target(e.data);
        if !e.is_heap() && e.data.len > 0 {
            let bytes = cx.read_avail(e.data.sub(0, 256)).await?;
            node = describe(node, &e, &bytes, endian);
        }
        if e.is_heap() {
            node = if depth < MAX_DEPTH {
                node.lazy(
                    crate::expander!(self::list: (Input, Span, Endian, u32)),
                    (input, e.data, endian, depth.saturating_add(1)),
                )
            } else {
                node.diag(Diagnostic::limit(format!(
                    "heaps nested deeper than {MAX_DEPTH}"
                )))
            };
        } else if matches!(e.id, 0x2007 | 0x2008) && e.data.len > 0 {
            node = node.lazy(jpeg, (input, e.data));
        } else if matches!(e.kind, 0x1000 | 0x1800)
            && e.data.len > 4
            && !matches!(e.id, 0x180e | 0x1810 | 0x1813 | 0x1818)
        {
            node = node.lazy(words, (e, endian));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The value and meaning of a record.
fn describe(node: Node, e: &Entry, bytes: &[u8], endian: Endian) -> Node {
    let u16s = || -> Vec<u16> {
        bytes
            .as_chunks::<2>()
            .0
            .iter()
            .filter_map(|c| u16::decode(c, endian))
            .collect()
    };
    match (e.id, e.kind) {
        (_, 0x0800) => node.value(text(strings(bytes).join(" / "))),
        (0x1810, _) => {
            let (Some(w), Some(h)) = (u32_at(bytes, 0, endian), u32_at(bytes, 4, endian)) else {
                return node;
            };
            let rotation = u32_at(bytes, 12, endian).unwrap_or(0);
            let bits = u32_at(bytes, 16, endian).unwrap_or(0);
            let node = node.value(text(dims(w, h)));
            if bits > 0 {
                node.summary(format!("{bits}-bit components, rotated {rotation}°"))
            } else {
                node.summary(format!("rotated {rotation}°"))
            }
        }
        (0x180e, _) => match u32_at(bytes, 0, endian) {
            Some(t) => node
                .value(Value::Timestamp {
                    unix_seconds: t.into(),
                })
                .summary("camera local time"),
            None => node,
        },
        (0x1818, _) => {
            let comp = f32_at(bytes, 0, endian).unwrap_or(0.0);
            let mut parts = vec![format!("{} EV compensation", trim(comp.into(), 2))];
            parts.extend(exposure(bytes, endian));
            node.summary(parts.join(", "))
        }
        (0x1807 | 0x1814, _) => match f32_at(bytes, 0, endian) {
            Some(v) => node.value(Value::Float(v.into())),
            None => node,
        },
        (0x10b4 | 0x100a | 0x1010 | 0x1011, 0x1000) => {
            let table = match e.id {
                0x10b4 => COLOR_SPACE,
                0x100a => TARGET_IMAGE_TYPE,
                0x1010 => RELEASE_METHOD,
                _ => RELEASE_TIMING,
            };
            match u16s().first() {
                Some(&v) => node.value(Value::Enum {
                    raw: v.into(),
                    bits: 16,
                    name: lookup(table, v.into()),
                }),
                None => node,
            }
        }
        (_, 0x1000) => {
            let v = u16s();
            match v.as_slice() {
                [one] => node.value(uint(*one)),
                many => node.summary(format!(
                    "[{}{}]",
                    many.iter()
                        .take(8)
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    if many.len() > 8 { ", …" } else { "" }
                )),
            }
        }
        (_, 0x1800) => {
            let v: Vec<u32> = bytes
                .as_chunks::<4>()
                .0
                .iter()
                .filter_map(|c| u32::decode(c, endian))
                .collect();
            match v.as_slice() {
                [one] => node.value(uint(*one)),
                many => node.summary(format!(
                    "[{}{}]",
                    many.iter()
                        .take(8)
                        .map(u32::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                    if many.len() > 8 { ", …" } else { "" }
                )),
            }
        }
        _ => node,
    }
}

/// The elements of a 16- or 32-bit array, named where Canon's maker notes
/// name them.
async fn words(cx: Cx, (e, endian): (Entry, Endian)) -> Result<()> {
    let size: u64 = if e.kind == 0x1000 { 2 } else { 4 };
    let n = e.data.len.checked_div(size).unwrap_or(0);
    // The CIFF records that Canon's maker notes later carried as tags.
    let tag = match e.id {
        0x102d => Some(0x0001),
        0x1029 => Some(0x0002),
        0x102a => Some(0x0004),
        _ => None,
    };
    let names = tag.and_then(|t| array_fields(Note::Canon, t));
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let span = e.data.sub(i.saturating_mul(size), size);
        let b = cx.read(span).await?;
        let v: u64 = if size == 2 {
            u16::decode(&b, endian).map_or(0, u64::from)
        } else {
            u32::decode(&b, endian).map_or(0, u64::from)
        };
        let name = names
            .and_then(|t| lookup(t, i))
            .map_or_else(|| format!("[{i}]"), str::to_owned);
        let value = match tag.and_then(|t| array_enum(Note::Canon, t, i)) {
            Some(table) => Value::Enum {
                raw: v,
                bits: 16,
                name: lookup(table, v),
            },
            None => uint(v),
        };
        cx.push(Node::new(name).span(span).value(value)).await;
    }
    Ok(())
}

async fn jpeg(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    cx.emit(embedded("Image", input.nested(data)));
    Ok(())
}
