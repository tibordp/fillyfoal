//! Windows Imaging Format (`.wim`, `.esd`, `.swm`).
//!
//! A 208-byte header points at resources through 24-byte resource headers:
//! the lookup table (one entry per stored stream), the XML description of
//! the images (UTF-16), boot metadata and the integrity table. Resources
//! are XPRESS/LZX/LZMS-compressed unless flagged otherwise; uncompressed
//! ones (normally the XML data) are dissected in place.

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::arcutil::{count, emit_nodes, hex, human_size, uint, unsupported};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const LOOKUP_ENTRY: u64 = 50;

pub static FORMAT: Format = Format {
    name: "wim",
    title: "Windows Imaging Format",
    extensions: &["wim", "swm", "esd"],
    mime: "application/x-ms-wim",
    probe: Probe::Magic(&[(0, b"MSWIM\0\0\0"), (0, b"WLPWM\0\0\0")]),
    dissect: crate::expander!(dissect: Input),
};

const HEADER_FLAGS: FlagTable = &[
    flag(0x0000_0002, "COMPRESSION"),
    flag(0x0000_0004, "READONLY"),
    flag(0x0000_0008, "SPANNED"),
    flag(0x0000_0010, "RESOURCE_ONLY"),
    flag(0x0000_0020, "METADATA_ONLY"),
    flag(0x0000_0040, "WRITE_IN_PROGRESS"),
    flag(0x0000_0080, "RP_FIX"),
    flag(0x0002_0000, "COMPRESS_XPRESS"),
    flag(0x0004_0000, "COMPRESS_LZX"),
    flag(0x0008_0000, "COMPRESS_LZMS"),
    flag(0x0020_0000, "COMPRESS_XPRESS2"),
];

const RESOURCE_FLAGS: FlagTable = &[
    flag(0x01, "FREE"),
    flag(0x02, "METADATA"),
    flag(0x04, "COMPRESSED"),
    flag(0x08, "SPANNED"),
    flag(0x10, "SOLID"),
];

/// A decoded resource header.
#[derive(Clone, Copy, Debug, Default)]
struct Resource {
    size: u64,
    flags: u8,
    offset: u64,
    original: u64,
}

fn resource(b: &[u8], at: usize) -> Option<Resource> {
    let size = u64_le(b, at)?;
    Some(Resource {
        size: size & 0x00ff_ffff_ffff_ffff,
        flags: u8::try_from(size >> 56).ok()?,
        offset: u64_le(b, at.checked_add(8)?)?,
        original: u64_le(b, at.checked_add(16)?)?,
    })
}

fn resource_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let block = f.block().data.clone();
    let r = resource(&block, 0).unwrap_or_default();
    let span = f.peek_span(8);
    f.node(
        Node::new("Compressed size")
            .span(span.sub(0, 7))
            .value(uint(r.size))
            .summary(human_size(r.size)),
    );
    let (set, unknown) = crate::value::decode_flags(RESOURCE_FLAGS, r.flags.into());
    f.node(
        Node::new("Flags")
            .span(Span::new(span.source, span.offset.saturating_add(7), 1))
            .value(Value::Flags {
                raw: r.flags.into(),
                bits: 8,
                set,
                unknown,
            }),
    );
    f.skip(8);
    f.u64("Offset").hex().emit()?;
    f.u64("Original size")
        .with(|&s, n| n.summary(human_size(s)))
        .emit()?;
    Ok(())
}

record! {
    pub struct Header {
        magic: ascii[8] "Magic",
        size: u32 "Header size",
        version: u32 "Version" .hex(),
        flags: u32 "Flags" .flags(HEADER_FLAGS),
        chunk: u32 "Chunk size" .with(|&c, n| n.summary(human_size(c.into()))),
        guid: guid "GUID",
        part: u16 "Part number",
        parts: u16 "Total parts",
        images: u32 "Image count",
    }
}

fn compression(flags: u32) -> &'static str {
    if flags & 0x2 == 0 {
        "uncompressed"
    } else if flags & 0x0002_0000 != 0 {
        "XPRESS"
    } else if flags & 0x0004_0000 != 0 {
        "LZX"
    } else if flags & 0x0008_0000 != 0 {
        "LZMS"
    } else if flags & 0x0020_0000 != 0 {
        "XPRESS2"
    } else {
        "unknown compression"
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = crate::fields::parse(&cx, file.sub(0, Header::SIZE), LE, &(), Header::layout).await?;
    let raw = cx.read(file.sub(0, 208)).await?;
    let codec = compression(h.flags);
    cx.emit(
        Header::node("Header", file.sub(0, 208), LE)
            .summary(format!("version {:#x}, {codec}", h.version)),
    );
    let names = [
        ("Lookup table", 48usize),
        ("XML data", 72),
        ("Boot metadata", 96),
        ("Integrity table", 124),
    ];
    for (name, at) in names {
        let Some(r) = resource(&raw, at) else {
            continue;
        };
        let header = file.sub(to_u64(at), 24);
        let data = file.sub(r.offset, r.size);
        let mut children = vec![struct_node(
            "Resource header",
            header,
            LE,
            (),
            resource_layout,
        )];
        if r.size == 0 {
            cx.emit(
                Node::new(name)
                    .span(header)
                    .summary("absent")
                    .lazy(emit_nodes, Arc::new(children)),
            );
            continue;
        }
        let compressed = r.flags & 0x04 != 0;
        let payload = match (name, compressed) {
            (_, true) => unsupported("Data", data, codec),
            ("Lookup table", false) => Node::new("Entries")
                .span(data)
                .summary(count(r.size / LOOKUP_ENTRY, "entry", "entries"))
                .lazy(lookup_table, (input, data, codec)),
            ("XML data", false) => Node::new("XML").span(data).lazy(xml_text, data),
            _ => embedded("Data", input.nested(data)),
        };
        children.push(payload);
        cx.emit(
            Node::new(name)
                .span(data)
                .summary(human_size(r.original))
                .lazy(emit_nodes, Arc::new(children)),
        );
    }
    if let Some(boot) = u32_le(&raw, 120) {
        cx.emit(
            Node::new("Boot index")
                .span(file.sub(120, 4))
                .value(uint(boot.into())),
        );
    }
    cx.annotate(format!(
        "Windows image, {}, {codec}, part {} of {}",
        count(h.images.into(), "image", "images"),
        h.part,
        h.parts
    ));
    Ok(())
}

async fn lookup_table(cx: Cx, (input, span, codec): (Input, Span, &'static str)) -> Result<()> {
    let n = span.len / LOOKUP_ENTRY;
    cx.set_count(Count::Exact(n));
    let data = cx.read(span.sub(0, n.saturating_mul(LOOKUP_ENTRY))).await?;
    for i in 0..n {
        let at = crate::bytes::to_usize(i.saturating_mul(LOOKUP_ENTRY));
        let Some(r) = resource(&data, at) else {
            break;
        };
        let entry = span.sub(i.saturating_mul(LOOKUP_ENTRY), LOOKUP_ENTRY);
        let part = u16_le(&data, at.saturating_add(24)).unwrap_or(0);
        let refs = u32_le(&data, at.saturating_add(26)).unwrap_or(0);
        let hash = data
            .get(at.saturating_add(30)..at.saturating_add(50))
            .unwrap_or_default()
            .to_vec();
        let file = input.span;
        let stream = file.sub(r.offset, r.size);
        let content = if r.flags & 0x04 != 0 {
            unsupported("Data", stream, codec)
        } else {
            embedded("Data", input.nested(stream))
        };
        let children = vec![
            struct_node("Resource header", entry.sub(0, 24), LE, (), resource_layout),
            Node::new("Part number")
                .span(entry.sub(24, 2))
                .value(uint(part.into())),
            Node::new("Reference count")
                .span(entry.sub(26, 4))
                .value(uint(refs.into())),
            Node::new("SHA-1")
                .span(entry.sub(30, 20))
                .value(Value::Bytes(hash.clone())),
            content,
        ];
        let hex_hash: String = hash.iter().take(6).map(|b| format!("{b:02x}")).collect();
        let kind = if r.flags & 0x02 != 0 {
            "metadata"
        } else {
            "stream"
        };
        cx.push(
            Node::new(format!("{kind} {hex_hash}…"))
                .span(entry)
                .value(hex(r.offset))
                .summary(format!(
                    "{} → {}",
                    human_size(r.size),
                    human_size(r.original)
                ))
                .lazy(emit_nodes, Arc::new(children)),
        )
        .await;
    }
    Ok(())
}

/// The image description: UTF-16LE XML, usually with a byte order mark.
async fn xml_text(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span.sub(0, 1 << 20)).await?;
    let body = data.strip_prefix(b"\xff\xfe".as_slice()).unwrap_or(&data);
    let text = crate::text::utf16(body, LE);
    cx.emit(Node::new("Text").span(span).value(Value::Text(text)));
    Ok(())
}
