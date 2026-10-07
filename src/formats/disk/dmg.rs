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
use crate::formats::util::arcutil::{count, emit_nodes, hex, human_size, uint};
use crate::formats::{Codec, Format, Head, Input, Probe, content, embedded};
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
        data_length: u64 "Data fork length" .with(|&l, n| n.summary(human_size(l))),
        rsrc_offset: u64 "Resource fork offset" .hex(),
        rsrc_length: u64 "Resource fork length",
        segment: u32 "Segment number",
        segments: u32 "Segment count",
        segment_id: bytes[16] "Segment ID",
        data_checksum_type: u32 "Data checksum type" .enumeration(CHECKSUM),
        data_checksum_bits: u32 "Data checksum size (bits)",
        data_checksum: bytes[128] "Data checksum",
        xml_offset: u64 "XML offset" .hex(),
        xml_length: u64 "XML length" .with(|&l, n| n.summary(human_size(l))),
        reserved: bytes[120] "Reserved",
        checksum_type: u32 "Master checksum type" .enumeration(CHECKSUM),
        checksum_bits: u32 "Master checksum size (bits)",
        checksum: bytes[128] "Master checksum",
        variant: u32 "Image variant" .enumeration(VARIANT),
        sectors: u64 "Sector count" .with(|&s, n| n.summary(human_size(s.saturating_mul(512)))),
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
            .summary(human_size(data.len)),
    );
    if koly.rsrc_length > 0 {
        cx.emit(Node::new("Resource fork").span(file.sub(koly.rsrc_offset, koly.rsrc_length)));
    }
    let xml = file.sub(koly.xml_offset, koly.xml_length);
    if koly.xml_length > 0 {
        cx.emit(
            Node::new("Partitions")
                .span(xml)
                .lazy(partitions, (input, xml, data)),
        );
        cx.emit(embedded("Property list", input.nested(xml)).summary(human_size(xml.len)));
    }
    cx.emit(Koly::node("Trailer (koly)", trailer, BE));
    cx.annotate(format!(
        "Apple disk image (UDIF), {} ({} sectors)",
        human_size(koly.sectors.saturating_mul(512)),
        koly.sectors
    ));
    Ok(())
}

/// Standard base64, ignoring whitespace. Returns `None` on other bytes.
fn base64(data: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity((data.len() / 4).saturating_mul(3));
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in data {
        let v = match c {
            b'A'..=b'Z' => c.wrapping_sub(b'A'),
            b'a'..=b'z' => c.wrapping_sub(b'a').wrapping_add(26),
            b'0'..=b'9' => c.wrapping_sub(b'0').wrapping_add(52),
            b'+' => 62,
            b'/' => 63,
            b'=' => break,
            b' ' | b'\t' | b'\r' | b'\n' => continue,
            _ => return None,
        };
        acc = (acc << 6 | u32::from(v)) & 0x00ff_ffff;
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    Some(out)
}

fn find(hay: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    let rest = hay.get(from..)?;
    rest.windows(needle.len())
        .position(|w| w == needle)
        .and_then(|p| p.checked_add(from))
}

/// The text of the `<tag>` element following `<key>key</key>` within
/// `range` of `xml`, with its offsets.
fn keyed(xml: &[u8], range: (usize, usize), key: &[u8], tag: &[u8]) -> Option<(usize, usize)> {
    let mut k = b"<key>".to_vec();
    k.extend_from_slice(key);
    k.extend_from_slice(b"</key>");
    let at = find(xml, &k, range.0).filter(|&a| a < range.1)?;
    let mut open = b"<".to_vec();
    open.extend_from_slice(tag);
    open.push(b'>');
    let mut close = b"</".to_vec();
    close.extend_from_slice(tag);
    close.push(b'>');
    let start = find(xml, &open, at)?.checked_add(open.len())?;
    let end = find(xml, &close, start)?;
    (end <= range.1).then_some((start, end))
}

/// One `blkx` entry: its name and the span of its base64 data.
struct Blkx {
    name: String,
    data: (usize, usize),
}

fn blkx_entries(xml: &[u8]) -> Vec<Blkx> {
    let mut out = Vec::new();
    let Some(key) = find(xml, b"<key>blkx</key>", 0) else {
        return out;
    };
    let Some(array_end) = find(xml, b"</array>", key) else {
        return out;
    };
    let mut at = key;
    while let Some(start) = find(xml, b"<dict>", at).filter(|&s| s < array_end) {
        let Some(end) = find(xml, b"</dict>", start) else {
            break;
        };
        let range = (start, end);
        let name = keyed(xml, range, b"Name", b"string")
            .or_else(|| keyed(xml, range, b"CFName", b"string"))
            .and_then(|(s, e)| xml.get(s..e))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default();
        if let Some(data) = keyed(xml, range, b"Data", b"data") {
            out.push(Blkx { name, data });
        }
        at = end;
    }
    out
}

async fn partitions(cx: Cx, (input, xml_span, data_fork): (Input, Span, Span)) -> Result<()> {
    let xml = cx.read(xml_span).await?;
    let entries = blkx_entries(&xml);
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (i, e) in entries.into_iter().enumerate() {
        let b64_span = xml_span.sub(to_u64(e.data.0), to_u64(e.data.1.saturating_sub(e.data.0)));
        let decoded = xml.get(e.data.0..e.data.1).and_then(base64);
        let name = if e.name.is_empty() {
            format!("Partition {i}")
        } else {
            e.name.clone()
        };
        let mut node = Node::new(name).span(b64_span);
        match decoded {
            Some(bytes) if bytes.starts_with(b"mish") => {
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
                        human_size(sectors.saturating_mul(512)),
                        count(chunks.into(), "chunk", "chunks")
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
            Node::new("Comment").span(span.sub(4, 4)).value(hex(u32_be(
                &raw,
                at.saturating_add(4),
            )
            .unwrap_or(0)
            .into())),
            Node::new("First sector")
                .span(span.sub(8, 8))
                .value(uint(first)),
            Node::new("Sector count")
                .span(span.sub(16, 8))
                .value(uint(sectors)),
            Node::new("Compressed offset")
                .span(span.sub(24, 8))
                .value(hex(offset))
                .target(data),
            Node::new("Compressed length")
                .span(span.sub(32, 8))
                .value(uint(length)),
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
            human_size(size)
        );
        if length > 0 {
            summary = format!("{summary} from {}", human_size(length));
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
