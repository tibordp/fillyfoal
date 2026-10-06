//! Microsoft Compiled HTML Help (`.chm`, ITSF).
//!
//! An `ITSF` header points at a directory (`ITSP`) made of fixed-size
//! chunks; listing chunks (`PMGL`) hold file entries `name, section,
//! offset, length` with variable-length integers. Files in section 0 are
//! stored uncompressed in the content area; section 1 is LZX-compressed
//! (not decoded).

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::datakit::{clip, size};
use crate::formats::{Codec, Format, Input, Probe, content};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
/// Chunks followed in the listing chain before giving up.
const MAX_CHUNKS: u32 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "chm",
    title: "Microsoft Compiled HTML Help",
    extensions: &["chm", "chi", "chw"],
    mime: "application/vnd.ms-htmlhelp",
    probe: Probe::Magic(&[(0, b"ITSF\x03\x00\x00\x00"), (0, b"ITSF\x02\x00\x00\x00")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Header {
        signature: ascii[4] "Signature",
        version: u32 "Version",
        header_len: u32 "Header length" .hex(),
        _unknown: u32 "Unknown",
        timestamp: u32 "Timestamp" .hex(),
        language: u32 "Language ID" .hex(),
        guid1: guid "GUID 1",
        guid2: guid "GUID 2",
        section0_offset: u64 "Section 0 offset" .hex(),
        section0_len: u64 "Section 0 length",
        dir_offset: u64 "Directory offset" .hex(),
        dir_len: u64 "Directory length",
    }
}

record! {
    pub struct Directory {
        signature: ascii[4] "Signature",
        version: u32 "Version",
        header_len: u32 "Header length" .hex(),
        _unknown1: u32 "Unknown",
        chunk_size: u32 "Chunk size" .hex(),
        density: u32 "Quickref density",
        depth: u32 "Index depth",
        root_index: i32 "Root index chunk",
        first_listing: u32 "First listing chunk",
        last_listing: u32 "Last listing chunk",
        _unknown2: i32 "Unknown",
        chunks: u32 "Number of chunks",
        language: u32 "Language ID" .hex(),
        guid: guid "GUID",
        header_len2: u32 "Header length (again)" .hex(),
        _unknown3: bytes[12] "Unknown",
    }
}

/// ENCINT: big-endian base-128 with continuation bits.
fn encint(data: &[u8], at: &mut usize) -> Option<u64> {
    let mut value = 0u64;
    for _ in 0..10 {
        let b = *data.get(*at)?;
        *at = at.saturating_add(1);
        value = value.checked_shl(7)? | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some(value);
        }
    }
    None
}

#[derive(Clone, Copy, Debug)]
struct Chm {
    input: Input,
    dir: Span,
    chunk_size: u64,
    first: u32,
    chunks: u32,
    /// Start of section 0 content (file offsets of section-0 files are
    /// relative to it).
    content: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, LE));
    let content_offset = if h.version >= 3 {
        let span = file.sub(Header::SIZE, 8);
        let b = cx.read(span).await?;
        cx.emit(
            Node::new("Content offset")
                .span(span)
                .value(crate::formats::datakit::hex(
                    crate::bytes::u64_le(&b, 0).unwrap_or(0),
                    64,
                )),
        );
        crate::bytes::u64_le(&b, 0).unwrap_or(0)
    } else {
        h.dir_offset.saturating_add(h.dir_len)
    };
    cx.emit(Node::new("Section 0 (file size)").span(file.sub(h.section0_offset, h.section0_len)));
    let dir = file.sub(h.dir_offset, h.dir_len);
    let d = parse(&cx, dir.sub(0, Directory::SIZE), LE, &(), Directory::layout).await?;
    cx.emit(Directory::node(
        "Directory header",
        dir.sub(0, Directory::SIZE),
        LE,
    ));
    if d.chunk_size < 32 {
        return Err(Diagnostic::malformed(format!("chunk size {}", d.chunk_size)).at(dir));
    }
    let chm = Chm {
        input,
        dir: dir.tail(u64::from(d.header_len)),
        chunk_size: d.chunk_size.into(),
        first: d.first_listing,
        chunks: d.chunks,
        content: content_offset,
    };
    cx.annotate(format!(
        "Compiled HTML Help, {} directory chunks, language {:#06x}",
        d.chunks, h.language
    ));
    cx.emit(Node::new("Files").span(chm.dir).lazy(files, chm));
    cx.emit(
        Node::new("Content")
            .span(file.tail(content_offset))
            .summary(size(file.len.saturating_sub(content_offset))),
    );
    Ok(())
}

async fn files(cx: Cx, chm: Chm) -> Result<()> {
    let mut chunk = chm.first;
    let mut seen = 0u32;
    while chunk != u32::MAX && seen < chm.chunks.min(MAX_CHUNKS) {
        seen = seen.saturating_add(1);
        let span = chm.dir.sub_exact(
            u64::from(chunk).saturating_mul(chm.chunk_size),
            chm.chunk_size,
        )?;
        let data = cx.read(span).await?;
        if data.get(..4) != Some(b"PMGL".as_slice()) {
            return Err(Diagnostic::malformed("expected a PMGL listing chunk").at(span.sub(0, 4)));
        }
        let free = to_usize(u32_le(&data, 4).unwrap_or(0).into());
        let next = u32_le(&data, 16).unwrap_or(u32::MAX);
        let end = data.len().saturating_sub(free);
        let mut at = 20usize;
        while at < end {
            let start = at;
            let Some(len) = encint(&data, &mut at) else {
                break;
            };
            let name_end = at.saturating_add(to_usize(len));
            let name =
                String::from_utf8_lossy(data.get(at..name_end).unwrap_or_default()).into_owned();
            at = name_end;
            let (Some(section), Some(offset), Some(length)) = (
                encint(&data, &mut at),
                encint(&data, &mut at),
                encint(&data, &mut at),
            ) else {
                break;
            };
            if name_end > end {
                break;
            }
            let entry = span.sub(to_u64(start), to_u64(at.saturating_sub(start)));
            let mut node = Node::new(clip(&name, 200))
                .span(entry)
                .value(Value::UInt {
                    value: length,
                    bits: 64,
                    radix: crate::value::Radix::Dec,
                })
                .summary(format!("section {section}, offset {offset:#x}"));
            if section == 0 && length > 0 {
                let data_span = chm
                    .input
                    .span
                    .sub(chm.content.saturating_add(offset), length);
                node = content(clip(&name, 200), chm.input, data_span, Codec::Stored, None)
                    .value(Value::UInt {
                        value: length,
                        bits: 64,
                        radix: crate::value::Radix::Dec,
                    })
                    .summary(format!("section 0, offset {offset:#x}"))
                    .target(entry);
            } else if section != 0 {
                node = node.desc("In the LZX-compressed section (not decoded)");
            }
            cx.push(node).await;
        }
        if next == chunk {
            break;
        }
        chunk = next;
    }
    Ok(())
}
