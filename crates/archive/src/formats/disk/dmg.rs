//! Apple disk images (UDIF `.dmg`).
//!
//! The 512-byte `koly` trailer at the end locates the data fork and an XML
//! property list. The plist's `blkx` entries are base64-encoded `mish`
//! tables, one per partition, mapping sector ranges to chunks of the data
//! fork (zero fill, raw, zlib, bzip2, ADC, LZFSE, LZMA). zlib chunks are
//! decompressed on expansion; raw, bzip2 and LZMA (.xz) chunks are dissected
//! in place, which decompresses them; ADC and LZFSE are unsupported.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::decode::{Decoded, base64};
use crate::formats::text::scan::Owned;
use crate::formats::text::xml::{Kind, Lexer, Mode, token_text};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Codec, Format, Head, Input, Probe, content, embedded, embedded_named};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag};

const BE: Endian = Endian::Big;
const TRAILER: u64 = 512;
const MISH_HEADER: u64 = 204;
const CHUNK: u64 = 40;

pub static FORMAT: Format = Format {
    name: "dmg",
    title: "Apple disk image (UDIF)",
    extensions: &["dmg", "smi", "img"],
    mime: "application/x-apple-diskimage",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let tail = h.tail;
    let at = tail.len().saturating_sub(512);
    h.len >= 512
        && tail.get(at..at.saturating_add(4)) == Some(b"koly")
        && u32_be(tail, at.saturating_add(8)) == Some(512)
}

const FLAGS: FlagTable = &[flag(0x1, "FLATTENED"), flag(0x4, "INTERNET_ENABLED")];
const CHECKSUM: EnumTable = &[(0, "none"), (2, "CRC-32"), (4, "MD5")];
const VARIANT: EnumTable = &[(1, "device image"), (2, "partition image")];

const CHUNK_TYPE: EnumTable = &[
    (0x0000_0000, "zero fill"),
    (0x0000_0001, "raw"),
    (0x0000_0002, "ignore"),
    (0x8000_0004, "ADC"),
    (0x8000_0005, "zlib"),
    (0x8000_0006, "bzip2"),
    (0x8000_0007, "LZFSE"),
    (0x8000_0008, "LZMA"),
    (0x7fff_fffe, "comment"),
    (0xffff_ffff, "end"),
];

record! {
    pub struct Koly {
        magic: ascii[4] "Signature",
        version: u32 "Version",
        header_size: u32 "Header size",
        flags: u32 "Flags" .flags(FLAGS),
        running: u64 "Running data fork offset" .hex(),
        data_offset: u64 "Data fork offset" .hex(),
        data_length: u64 "Data fork length" .with(|&l, n| n.summary(fmt::size(l))),
        rsrc_offset: u64 "Resource fork offset" .hex(),
        rsrc_length: u64 "Resource fork length",
        segment: u32 "Segment number",
        segments: u32 "Segment count",
        segment_id: bytes[16] "Segment ID",
        data_checksum_type: u32 "Data checksum type" .enumeration(CHECKSUM),
        data_checksum_bits: u32 "Data checksum size (bits)",
        data_checksum: bytes[128] "Data checksum",
        xml_offset: u64 "XML offset" .hex(),
        xml_length: u64 "XML length" .with(|&l, n| n.summary(fmt::size(l))),
        reserved: bytes[120] "Reserved",
        checksum_type: u32 "Master checksum type" .enumeration(CHECKSUM),
        checksum_bits: u32 "Master checksum size (bits)",
        checksum: bytes[128] "Master checksum",
        variant: u32 "Image variant" .enumeration(VARIANT),
        sectors: u64 "Sector count" .with(|&s, n| n.summary(fmt::size(s.saturating_mul(512)))),
        reserved2: bytes[12] "Reserved",
    }
}

record! {
    pub struct Mish {
        signature: ascii[4] "Signature",
        version: u32 "Version",
        first_sector: u64 "First sector",
        sectors: u64 "Sector count",
        data_offset: u64 "Data offset" .hex(),
        buffers: u32 "Buffers needed",
        descriptors: u32 "Block descriptors",
        reserved: bytes[24] "Reserved",
        checksum_type: u32 "Checksum type" .enumeration(CHECKSUM),
        checksum_bits: u32 "Checksum size (bits)",
        checksum: bytes[128] "Checksum",
        chunks: u32 "Chunk count",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let trailer = file.tail(file.len.saturating_sub(TRAILER));
    let koly = crate::fields::parse(&cx, trailer, BE, &(), Koly::layout).await?;
    let data = file.sub(koly.data_offset, koly.data_length);
    cx.emit(
        Node::new("Data fork")
            .span(data)
            .summary(fmt::size(data.len)),
    );
    if koly.rsrc_length > 0 {
        let rsrc = file.sub(koly.rsrc_offset, koly.rsrc_length);
        cx.emit(embedded_named(
            "Resource fork",
            input.nested(rsrc),
            "mac-rsrc",
        ));
    }
    let xml = file.sub(koly.xml_offset, koly.xml_length);
    if koly.xml_length > 0 {
        cx.emit(
            Node::new("Partitions")
                .span(xml)
                .lazy(partitions, (input, xml, data)),
        );
        cx.emit(embedded("Property list", input.nested(xml)).summary(fmt::size(xml.len)));
    }
    cx.emit(Koly::node("Trailer (koly)", trailer, BE));
    cx.annotate(format!(
        "Apple disk image (UDIF), {} ({} sectors)",
        fmt::size(koly.sectors.saturating_mul(512)),
        koly.sectors
    ));
    Ok(())
}

/// One `blkx` entry: its name and its base64 `<data>` text.
struct Blkx {
    name: String,
    data: Owned,
}

/// Where the walk over the property list is.
#[derive(Default)]
struct Walk {
    depth: usize,
    /// Inside a `<key>`: its text comes next.
    in_key: bool,
    key: Vec<u8>,
    /// The depth of the `blkx` array.
    array: Option<usize>,
    /// The depth of the current entry's dict.
    entry: Option<usize>,
    /// Inside the entry's `<string>` or `<data>` value for this key.
    value: Option<Vec<u8>>,
    name: Option<String>,
    cf_name: Option<String>,
    data: Option<Owned>,
}

/// The `blkx` entries of the resource-fork dict
/// (`resource-fork` → `blkx` → array of dicts with `Name`/`CFName` and
/// `Data`), with the spans of their base64 payloads.
async fn blkx_entries(cx: &Cx, xml: Span) -> Result<Vec<Blkx>> {
    let mut lex = Lexer::new(cx, xml, Mode::Xml);
    let mut w = Walk::default();
    let mut out = Vec::new();
    loop {
        let t = lex.next().await?;
        match t.kind {
            Kind::Eof => break,
            Kind::Start => {
                let name = lex.name(&t).await?;
                // A key names the value element that follows it.
                let key = std::mem::take(&mut w.key);
                if t.empty {
                    continue;
                }
                w.depth = w.depth.saturating_add(1);
                match name.as_slice() {
                    b"key" => w.in_key = true,
                    b"array" if w.array.is_none() && key == b"blkx" => w.array = Some(w.depth),
                    b"dict" if w.array.is_some_and(|a| a.saturating_add(1) == w.depth) => {
                        cx.checkpoint().await;
                        w.entry = Some(w.depth);
                        (w.name, w.cf_name, w.data) = (None, None, None);
                    }
                    b"string" | b"data"
                        if w.entry.is_some_and(|e| e.saturating_add(1) == w.depth) =>
                    {
                        w.value = Some(key);
                    }
                    _ => {}
                }
            }
            Kind::Text | Kind::Cdata if w.in_key => {
                w.key = token_text(&mut lex, &t).await?.trim().as_bytes().to_vec();
            }
            Kind::Text => match w.value.as_deref() {
                Some(b"Name") => w.name = Some(token_text(&mut lex, &t).await?),
                Some(b"CFName") => w.cf_name = Some(token_text(&mut lex, &t).await?),
                Some(b"Data") => {
                    let len = to_usize(t.end.saturating_sub(t.start));
                    w.data = Some(lex.owned(&t, len).await?);
                }
                _ => {}
            },
            Kind::End => {
                let name = lex.name(&t).await?;
                match name.as_slice() {
                    b"key" => w.in_key = false,
                    b"string" | b"data" => w.value = None,
                    b"dict" if w.entry == Some(w.depth) => {
                        w.entry = None;
                        if let Some(data) = w.data.take() {
                            let name = w.name.take().or(w.cf_name.take()).unwrap_or_default();
                            out.push(Blkx { name, data });
                        }
                    }
                    b"array" if w.array == Some(w.depth) => break,
                    _ => {}
                }
                w.depth = w.depth.saturating_sub(1);
            }
            _ => {}
        }
    }
    Ok(out)
}

async fn partitions(cx: Cx, (input, xml_span, data_fork): (Input, Span, Span)) -> Result<()> {
    let entries = blkx_entries(&cx, xml_span).await?;
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (i, e) in entries.into_iter().enumerate() {
        let b64_span = e.data.span;
        let decoded = base64(&e.data.bytes);
        let name = if e.name.is_empty() {
            format!("Partition {i}")
        } else {
            e.name
        };
        let mut node = Node::new(name).span(b64_span);
        match decoded {
            Decoded { bytes, error: None } if bytes.starts_with(b"mish") => {
                let sectors = u64_be(&bytes, 16).unwrap_or(0);
                let chunks = u32_be(&bytes, 200).unwrap_or(0);
                let origin = Origin {
                    parent: b64_span,
                    transform: "base64",
                };
                let mish = cx.add_derived(origin, bytes, b64_span.len, None)?;
                node = node
                    .summary(format!(
                        "{}, {}",
                        fmt::size(sectors.saturating_mul(512)),
                        count(chunks, "chunk", "chunks")
                    ))
                    .lazy(partition, (input, mish.span, data_fork));
            }
            _ => {
                node = node.diag(Diagnostic::malformed(
                    "blkx data is not a base64 mish table",
                ))
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn partition(cx: Cx, (input, mish, data_fork): (Input, Span, Span)) -> Result<()> {
    let header = crate::fields::parse(&cx, mish.sub(0, MISH_HEADER), BE, &(), Mish::layout).await?;
    cx.emit(Mish::node(
        "Block table header (mish)",
        mish.sub(0, MISH_HEADER),
        BE,
    ));
    let table = mish.sub_exact(MISH_HEADER, u64::from(header.chunks).saturating_mul(CHUNK))?;
    let raw = cx.read(table).await?;
    for i in 0..header.chunks {
        let at = to_usize(u64::from(i).saturating_mul(CHUNK));
        let kind = u32_be(&raw, at).unwrap_or(0);
        let first = u64_be(&raw, at.saturating_add(8)).unwrap_or(0);
        let sectors = u64_be(&raw, at.saturating_add(16)).unwrap_or(0);
        let offset = u64_be(&raw, at.saturating_add(24)).unwrap_or(0);
        let length = u64_be(&raw, at.saturating_add(32)).unwrap_or(0);
        let span = table.sub(to_u64(at), CHUNK);
        let kind_name = crate::value::lookup(CHUNK_TYPE, kind.into()).unwrap_or("unknown");
        let data = data_fork.sub(header.data_offset.saturating_add(offset), length);
        let size = sectors.saturating_mul(512);
        let mut fields = vec![
            Node::new("Type").span(span.sub(0, 4)).value(Value::Enum {
                raw: kind.into(),
                bits: 32,
                name: crate::value::lookup(CHUNK_TYPE, kind.into()),
            }),
            Node::new("Comment")
                .span(span.sub(4, 4))
                .value(hex(u32_be(&raw, at.saturating_add(4)).unwrap_or(0), 64)),
            Node::new("First sector")
                .span(span.sub(8, 8))
                .value(uint(first, 64)),
            Node::new("Sector count")
                .span(span.sub(16, 8))
                .value(uint(sectors, 64)),
            Node::new("Compressed offset")
                .span(span.sub(24, 8))
                .value(hex(offset, 64))
                .target(data),
            Node::new("Compressed length")
                .span(span.sub(32, 8))
                .value(uint(length, 64)),
        ];
        match kind {
            0x8000_0005 => fields.push(content("Data", input, data, Codec::Zlib, Some(size))),
            // bzip2 streams and (ULMO) libcompression's LZMA, which is an
            // .xz stream: their dissectors show the structure and content.
            0x0000_0001 | 0x8000_0006 | 0x8000_0008 => {
                fields.push(embedded("Data", input.nested(data)))
            }
            0x8000_0004 => fields.push(content("Data", input, data, Codec::Adc, Some(size))),
            0x8000_0007 => fields.push(content("Data", input, data, Codec::Lzfse, Some(size))),
            _ => {}
        }
        let mut summary = format!(
            "{kind_name}, sectors {first}..+{sectors} ({})",
            fmt::size(size)
        );
        if length > 0 {
            summary = format!("{summary} from {}", fmt::size(length));
        }
        cx.push(
            Node::new(format!("Chunk {i}"))
                .span(span)
                .summary(summary)
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}
