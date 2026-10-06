//! Canon CRW: the Camera Image File Format (CIFF).
//!
//! A short header, then a heap: a data area whose last four bytes give the
//! offset of its directory (`count, entries`). Each 10-byte entry has a tag
//! (with storage and type bits), a size and an offset; subdirectory entries
//! point at nested heaps, and two entries hold JPEG images.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields, Prim};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{text, uint};

pub static FORMAT: Format = Format {
    name: "crw",
    title: "Canon raw (CRW)",
    extensions: &["crw"],
    mime: "image/x-canon-crw",
    probe: Probe::Magic(&[(6, b"HEAPCCDR")]),
    dissect: crate::expander!(dissect: Input),
};

const TAGS: EnumTable = &[
    (0x0032, "Color space"),
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
    (0x1029, "Focal length"),
    (0x102a, "Shot info"),
    (0x102d, "Camera settings"),
    (0x1031, "Sensor info"),
    (0x1033, "Custom functions"),
    (0x1038, "AF info"),
    (0x10a9, "White balance table"),
    (0x10b4, "Color space"),
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
    (0x1835, "Decoder table"),
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

/// How deeply heaps may nest.
const MAX_DEPTH: u32 = 8;

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
    f.u32("Version").hex().emit()?;
    f.bytes("Reserved", 8).emit()?;
    let heap = file.tail(header_len.into());
    if let Some(model) = make_and_model(&cx, heap, endian).await {
        cx.annotate(format!("{model}, CIFF"));
    }
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

/// The model ("Canon EOS ...") from the make-and-model entry, searched one
/// level deep.
async fn make_and_model(cx: &Cx, heap: Span, endian: Endian) -> Option<String> {
    let (_, entries) = directory(cx, heap, endian).await.ok()?;
    for e in &entries {
        if e.id == 0x080a {
            return strings(cx, e.data).await.pop();
        }
    }
    for e in entries
        .iter()
        .filter(|e| matches!(e.kind, 0x2800 | 0x3000) && !e.in_record)
    {
        let (_, inner) = directory(cx, e.data, endian).await.ok()?;
        if let Some(found) = inner.iter().find(|i| i.id == 0x080a) {
            let parts = strings(cx, found.data).await;
            return Some(parts.last().cloned().unwrap_or_default());
        }
    }
    None
}

async fn strings(cx: &Cx, data: Span) -> Vec<String> {
    let bytes = cx.read_avail(data.sub(0, 256)).await.unwrap_or_default();
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
        let mut node = Node::new(name.clone())
            .span(e.span)
            .summary(format!("{kind}, {} bytes", e.data.len))
            .target(e.data);
        if e.kind == 0x0800 {
            node = node.value(text(strings(&cx, e.data).await.join(" / ")));
        }
        let subheap = matches!(e.kind, 0x2800 | 0x3000) && !e.in_record;
        if subheap && depth < MAX_DEPTH {
            node = node.lazy(
                crate::expander!(self::list: (Input, Span, Endian, u32)),
                (input, e.data, endian, depth.saturating_add(1)),
            );
        } else if matches!(e.id, 0x2007 | 0x2008) && e.data.len > 0 {
            node = node.lazy(jpeg, (input, e.data));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn jpeg(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    cx.emit(embedded("Image", input.nested(data)));
    Ok(())
}
