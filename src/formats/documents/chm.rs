//! Microsoft Compiled HTML Help (`.chm`, ITSF).
//!
//! An `ITSF` header points at a directory (`ITSP`) made of fixed-size
//! chunks; listing chunks (`PMGL`) hold file entries `name, section,
//! offset, length` with variable-length integers. Files in section 0 are
//! stored uncompressed in the content area. Section 1 (`MSCompressed`) is
//! the section-0 file `::DataSpace/Storage/MSCompressed/Content`, an LZX
//! stream whose window and reset interval come from the `LZXC` control
//! data and whose length comes from the reset table; it is decoded on
//! demand, and its files are ranges of it.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::codec::lzx;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::datakit::{clip, size};
use crate::formats::{Codec, Format, Input, Probe, content, dissect_or_data};
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
    let content_offset =
        if h.version >= 3 {
            let span = file.sub(Header::SIZE, 8);
            let b = cx.read(span).await?;
            cx.emit(Node::new("Content offset").span(span).value(
                crate::formats::util::datakit::hex(crate::bytes::u64_le(&b, 0).unwrap_or(0), 64),
            ));
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
        Node::new("Compressed section")
            .span(file.tail(content_offset))
            .summary("MSCompressed, LZX")
            .lazy(section1_content, chm),
    );
    cx.emit(
        Node::new("Content")
            .span(file.tail(content_offset))
            .summary(size(file.len.saturating_sub(content_offset))),
    );
    Ok(())
}

/// A directory entry.
struct Entry {
    name: String,
    section: u64,
    offset: u64,
    length: u64,
    /// The entry's bytes within its chunk.
    at: usize,
    end: usize,
}

/// The entries of one `PMGL` chunk (`data`), and the next chunk's index.
fn listing(data: &[u8]) -> (Vec<Entry>, u32) {
    let free = to_usize(u32_le(data, 4).unwrap_or(0).into());
    let next = u32_le(data, 16).unwrap_or(u32::MAX);
    let end = data.len().saturating_sub(free);
    let mut at = 20usize;
    let mut out = Vec::new();
    while at < end {
        let start = at;
        let Some(len) = encint(data, &mut at) else {
            break;
        };
        let name_end = at.saturating_add(to_usize(len));
        let name = String::from_utf8_lossy(data.get(at..name_end).unwrap_or_default()).into_owned();
        at = name_end;
        let (Some(section), Some(offset), Some(length)) = (
            encint(data, &mut at),
            encint(data, &mut at),
            encint(data, &mut at),
        ) else {
            break;
        };
        if name_end > end {
            break;
        }
        out.push(Entry {
            name,
            section,
            offset,
            length,
            at: start,
            end: at,
        });
    }
    (out, next)
}

/// Reads listing chunk `chunk`: its span, entries and the next chunk.
async fn chunk(cx: &Cx, chm: &Chm, chunk: u32) -> Result<(Span, Vec<Entry>, u32)> {
    let span = chm.dir.sub_exact(
        u64::from(chunk).saturating_mul(chm.chunk_size),
        chm.chunk_size,
    )?;
    let data = cx.read(span).await?;
    if data.get(..4) != Some(b"PMGL".as_slice()) {
        return Err(Diagnostic::malformed("expected a PMGL listing chunk").at(span.sub(0, 4)));
    }
    let (entries, next) = listing(&data);
    Ok((span, entries, next))
}

/// The listing chain: the next chunk to read, if any.
struct Chain {
    index: u32,
    seen: u32,
}

impl Chain {
    fn new(chm: &Chm) -> Self {
        Chain {
            index: chm.first,
            seen: 0,
        }
    }

    async fn next(&mut self, cx: &Cx, chm: &Chm) -> Result<Option<(Span, Vec<Entry>)>> {
        if self.index == u32::MAX || self.seen >= chm.chunks.min(MAX_CHUNKS) {
            return Ok(None);
        }
        self.seen = self.seen.saturating_add(1);
        let (span, entries, next) = chunk(cx, chm, self.index).await?;
        self.index = if next == self.index { u32::MAX } else { next };
        Ok(Some((span, entries)))
    }
}

const FRAME: u32 = 32 * 1024;
const STORAGE: &str = "::DataSpace/Storage/MSCompressed/";
const CONTROL: &str = "ControlData";
const CONTENT: &str = "Content";
const RESET_TABLE: &str =
    "Transform/{7FC28940-9D31-11D0-9B27-00A0C91E9C7C}/InstanceData/ResetTable";

/// The decoded LZX section (section 1), decoded on demand.
async fn section1(cx: &Cx, chm: &Chm) -> Result<Span> {
    let mut found: [Option<(u64, u64)>; 3] = [None; 3];
    let mut chain = Chain::new(chm);
    while let Some((_, entries)) = chain.next(cx, chm).await? {
        for e in entries {
            let Some(rest) = e.name.strip_prefix(STORAGE) else {
                continue;
            };
            let slot = [CONTROL, CONTENT, RESET_TABLE]
                .iter()
                .position(|&n| n == rest);
            if let Some(slot) = slot.and_then(|i| found.get_mut(i))
                && e.section == 0
            {
                *slot = Some((e.offset, e.length));
            }
        }
    }
    let file = chm.input.span;
    let at = |(offset, length): (u64, u64)| file.sub(chm.content.saturating_add(offset), length);
    let [Some(control), Some(content), Some(reset)] = found else {
        return Err(Diagnostic::malformed(
            "no LZX control data, content or reset table",
        ));
    };
    let control_span = at(control);
    let c = cx.read(control_span.sub(0, 28)).await?;
    if c.get(4..8) != Some(b"LZXC".as_slice()) {
        return Err(
            Diagnostic::unsupported("section 1 is not LZX (no LZXC control data)").at(control_span),
        );
    }
    let version = u32_le(&c, 8).unwrap_or(0);
    let (mut interval, mut window) = (u32_le(&c, 12).unwrap_or(0), u32_le(&c, 16).unwrap_or(0));
    match version {
        1 => {}
        2 => {
            interval = interval.saturating_mul(FRAME);
            window = window.saturating_mul(FRAME);
        }
        _ => {
            return Err(
                Diagnostic::unsupported(format!("LZXC control data version {version}"))
                    .at(control_span),
            );
        }
    }
    let window_bits = (15..=21u8).find(|&b| window == 1u32 << b).ok_or_else(|| {
        Diagnostic::malformed(format!("LZX window size {window:#x}")).at(control_span)
    })?;
    if interval == 0 || !interval.is_multiple_of(FRAME) {
        return Err(
            Diagnostic::malformed(format!("LZX reset interval {interval:#x}")).at(control_span),
        );
    }
    let r = cx.read(at(reset).sub(0, 40)).await?;
    let len = crate::bytes::u64_le(&r, 16).unwrap_or(0);
    let params = lzx::Params {
        window_bits,
        reset_interval: interval / FRAME,
        variant: lzx::Variant::Cab,
        len: Some(len),
    };
    // The claimed length, whatever decoding finds (see `cab::folder_stream`).
    let stream = cx.decode_lazy(at(content), &Codec::Lzx(params), len)?;
    Ok(Span::new(stream.source, 0, len))
}

async fn section1_content(cx: Cx, chm: Chm) -> Result<()> {
    let stream = section1(&cx, &chm).await?;
    cx.annotate(format!("{:#x} bytes, decoded on demand", stream.len));
    dissect_or_data(cx, chm.input.nested(stream)).await
}

async fn section1_file(cx: Cx, (chm, offset, length): (Chm, u64, u64)) -> Result<()> {
    let stream = section1(&cx, &chm).await?;
    if offset.saturating_add(length) > stream.len {
        return Err(Diagnostic::malformed(
            "file lies beyond the compressed section",
        ));
    }
    dissect_or_data(cx, chm.input.nested(stream.sub(offset, length))).await
}

async fn files(cx: Cx, chm: Chm) -> Result<()> {
    let mut chain = Chain::new(&chm);
    while let Some((span, entries)) = chain.next(&cx, &chm).await? {
        for e in entries {
            let entry = span.sub(to_u64(e.at), to_u64(e.end.saturating_sub(e.at)));
            let value = Value::UInt {
                value: e.length,
                bits: 64,
                radix: crate::value::Radix::Dec,
            };
            let name = clip(&e.name, 200);
            let node = if e.section == 0 && e.length > 0 {
                let data_span = chm
                    .input
                    .span
                    .sub(chm.content.saturating_add(e.offset), e.length);
                content(name, chm.input, data_span, Codec::Stored, None)
                    .value(value)
                    .summary(format!("section 0, offset {:#x}", e.offset))
                    .target(entry)
            } else if e.section == 1 && e.length > 0 {
                Node::new(name)
                    .span(entry)
                    .value(value)
                    .summary(format!("section 1 (LZX), offset {:#x}", e.offset))
                    .lazy(section1_file, (chm, e.offset, e.length))
            } else {
                Node::new(name)
                    .span(entry)
                    .value(value)
                    .summary(format!("section {}, offset {:#x}", e.section, e.offset))
            };
            cx.push(node).await;
        }
    }
    Ok(())
}
