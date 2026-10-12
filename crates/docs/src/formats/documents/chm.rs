//! Microsoft Compiled HTML Help (`.chm`, ITSF).
//!
//! An `ITSF` header points at a directory (`ITSP`) made of fixed-size
//! chunks; listing chunks (`PMGL`) hold file entries `name, section,
//! offset, length` with variable-length integers. Files in section 0 are
//! stored uncompressed in the content area. Section 1 (`MSCompressed`) is
//! the section-0 file `::DataSpace/Storage/MSCompressed/Content`, an LZX
//! stream whose window and reset interval come from the `LZXC` control
//! data and whose length comes from the reset table; it is decoded on
//! demand, starting at the nearest reset interval the reset table
//! records (as libmspack does), and its files are ranges of it. The
//! `/#SYSTEM` file's records (title, default topic, contents and index
//! files, compiler) are shown, and the title annotates the file.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::codec::lzx;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::datakit::size;
use crate::formats::util::fmt::clip;
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
    let (value, len) = crate::bytes::vlq_be(data.get(*at..)?, 10)?;
    *at = at.saturating_add(len);
    Some(value)
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
                .value(crate::formats::util::val::hex(
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
    let mut annotation = format!(
        "Compiled HTML Help, {} directory chunks, language {:#06x}",
        d.chunks, h.language
    );
    // `/#SYSTEM` sorts near the start of the listing: look for it in the
    // first chunk only, so opening the file stays one chunk read.
    if let Ok((_, entries, _)) = chunk(&cx, &chm, chm.first).await
        && let Some(e) = entries
            .iter()
            .find(|e| e.name == "/#SYSTEM" && e.section == 0)
    {
        let span = file.sub(chm.content.saturating_add(e.offset), e.length);
        let data = cx.read_avail(span.sub(0, 0x10000)).await?;
        let records = system_records(&data);
        let mut node = Node::new("System").span(span).lazy(system, span);
        if let Some(title) = records
            .iter()
            .find_map(|r| (r.code == 3).then(|| r.text(&data)))
        {
            node = node.summary(clip(&title, 120));
            annotation = format!("{annotation}: {:?}", clip(&title, 80));
        }
        cx.emit(node);
    }
    cx.annotate(annotation);
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

/// `#SYSTEM` record codes (as chmspec's "Internal files" page lists them;
/// written by hhc.exe and chmcmd). Codes 0-3, 5, 6, 9 and 16
/// hold NUL-terminated text (13 and 14 binary data), 7, 10, 11, 12 and 15
/// a u32.
const SYSTEM_CODES: crate::value::EnumTable = &[
    (0, "Contents file"),
    (1, "Index file"),
    (2, "Default topic"),
    (3, "Title"),
    (4, "Locale and flags"),
    (5, "Default window"),
    (6, "Compiled file"),
    (7, "Binary index"),
    (9, "Compiler version"),
    (10, "Timestamp"),
    (11, "Binary TOC"),
    (12, "Information types"),
    (13, "#IDXHDR copy"),
    (14, "MS Office extension"),
    (15, "Information type checksum"),
    (16, "Default font"),
];

/// One `#SYSTEM` record: code and the data's place in the file's bytes.
struct SystemRecord {
    code: u16,
    at: usize,
    len: usize,
}

impl SystemRecord {
    fn bytes<'a>(&self, data: &'a [u8]) -> &'a [u8] {
        data.get(self.at..self.at.saturating_add(self.len))
            .unwrap_or_default()
    }

    fn text(&self, data: &[u8]) -> String {
        let b = self.bytes(data);
        let b = b.split(|&c| c == 0).next().unwrap_or_default();
        match std::str::from_utf8(b) {
            Ok(s) => s.to_owned(),
            Err(_) => crate::text::latin1(b),
        }
    }
}

/// The records of `#SYSTEM` (a u32 version, then code, length, data;
/// `data` is at most 64 KiB, so this is a bounded step).
fn system_records(data: &[u8]) -> Vec<SystemRecord> {
    let mut out = Vec::new();
    let mut at = 4usize;
    while let (Some(code), Some(len)) = (
        crate::bytes::u16_le(data, at),
        crate::bytes::u16_le(data, at.saturating_add(2)),
    ) {
        let start = at.saturating_add(4);
        out.push(SystemRecord {
            code,
            at: start,
            len: usize::from(len),
        });
        at = start.saturating_add(usize::from(len));
    }
    out
}

async fn system(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x10000)).await?;
    cx.emit(
        Node::new("Version")
            .span(span.sub(0, 4))
            .value(crate::formats::util::val::uint(
                u32_le(&data, 0).unwrap_or(0),
                32,
            )),
    );
    for r in system_records(&data) {
        let rspan = span.sub(
            to_u64(r.at).saturating_sub(4),
            to_u64(r.len).saturating_add(4),
        );
        let name = crate::value::lookup(SYSTEM_CODES, r.code.into())
            .map_or_else(|| format!("Code {}", r.code), str::to_owned);
        let bytes = r.bytes(&data);
        let mut node = Node::new(name).span(rspan);
        node = match r.code {
            0..=3 | 5 | 6 | 9 | 16 => node.value(Value::Text(r.text(&data))),
            7 | 10 | 11 | 12 | 15 if bytes.len() == 4 => node.value(
                crate::formats::util::val::hex(u32_le(bytes, 0).unwrap_or(0), 32),
            ),
            4 => {
                let lcid = u32_le(bytes, 0).unwrap_or(0);
                node.summary(format!("LCID {lcid:#06x}"))
                    .value(Value::Bytes(bytes.to_vec()))
            }
            _ => node.value(Value::Bytes(bytes.to_vec())),
        };
        if to_u64(r.at.saturating_add(r.len)) > span.len {
            node = node.diag(Diagnostic::truncated(rspan, rspan.len));
        }
        cx.push(node).await;
    }
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
async fn listing(cx: &Cx, data: &[u8]) -> (Vec<Entry>, u32) {
    let free = to_usize(u32_le(data, 4).unwrap_or(0).into());
    let next = u32_le(data, 16).unwrap_or(u32::MAX);
    let end = data.len().saturating_sub(free);
    let mut at = 20usize;
    let mut out = Vec::new();
    while at < end {
        // The chunk size is the file's to choose (up to the read limit).
        if out.len() % 256 == 255 {
            cx.checkpoint().await;
        }
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
    let (entries, next) = listing(cx, &data).await;
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

/// Where the section-0 files `ControlData`, `Content` and `ResetTable` of
/// the LZX section lie (offset and length, each if found).
type Storage = [Option<(u64, u64)>; 3];

/// Finds the [`Storage`] files: one walk of the listing chain per file,
/// shared by every section-1 node through the cache.
async fn storage(cx: &Cx, chm: &Chm) -> Result<Storage> {
    const KIND: &str = "chm-mscompressed-storage";
    if let Some(found) = cx.cached::<Storage>(chm.dir, KIND) {
        return Ok(*found);
    }
    let mut found: Storage = [None; 3];
    let mut chain = Chain::new(chm);
    while let Some((_, entries)) = chain.next(cx, chm).await? {
        for (i, e) in entries.into_iter().enumerate() {
            if i % 1024 == 1023 {
                cx.checkpoint().await;
            }
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
    cx.cache(chm.dir, KIND, std::sync::Arc::new(found));
    Ok(found)
}

/// The decoded LZX section (section 1), decoded on demand; registered
/// once per file.
async fn section1(cx: &Cx, chm: &Chm) -> Result<Span> {
    const KIND: &str = "chm-section1";
    if let Some(span) = cx.cached::<Span>(chm.dir, KIND) {
        return Ok(*span);
    }
    let span = register_section1(cx, chm).await?;
    cx.cache(chm.dir, KIND, std::sync::Arc::new(span));
    Ok(span)
}

async fn register_section1(cx: &Cx, chm: &Chm) -> Result<Span> {
    let found = storage(cx, chm).await?;
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
    let reset_span = at(reset);
    let r = cx.read(reset_span.sub(0, 40)).await?;
    let len = crate::bytes::u64_le(&r, 16).unwrap_or(0);
    let params = lzx::Params {
        window_bits,
        reset_interval: interval / FRAME,
        variant: lzx::Variant::Cab,
        len: Some(len),
    };
    let seeds = reset_seeds(cx, reset_span, &r, params).await;
    // The claimed length, whatever decoding finds (see `cab::folder_stream`).
    let stream = cx.decode_lazy_seeded(at(content), &Codec::Lzx(params), len, seeds)?;
    Ok(Span::new(stream.source, 0, len))
}

/// Seeds for the LZX section from its reset table (`head`: its first 40
/// bytes): the table holds the compressed offset of every 32 KiB frame
/// (entry count at 4, entry size 4 or 8 at 8, table offset at 12, frame
/// length at 0x20), and a fresh decoder can start at every frame that
/// begins a reset interval, as libmspack's `chmd_init_decomp` does. A
/// table that does not fit gives no seeds (decoding then starts at 0).
async fn reset_seeds(
    cx: &Cx,
    table: Span,
    head: &[u8],
    params: lzx::Params,
) -> Vec<crate::cx::Seed> {
    let n = u64::from(u32_le(head, 4).unwrap_or(0));
    let size = u64::from(u32_le(head, 8).unwrap_or(0));
    let offset = u64::from(u32_le(head, 12).unwrap_or(0));
    let frame_len = crate::bytes::u64_le(head, 0x20).unwrap_or(0);
    let interval = u64::from(params.reset_interval);
    if !matches!(size, 4 | 8) || frame_len != u64::from(FRAME) || interval == 0 {
        return Vec::new();
    }
    let Ok(entries) = table.sub_exact(offset, n.saturating_mul(size)) else {
        return Vec::new();
    };
    let Ok(data) = cx.read(entries).await else {
        return Vec::new();
    };
    let step = usize::try_from(size.saturating_mul(interval)).unwrap_or(usize::MAX);
    let mut seeds = Vec::new();
    let mut frame = interval;
    for chunk in data.chunks(step).skip(1) {
        let in_pos = if size == 8 {
            crate::bytes::u64_le(chunk, 0)
        } else {
            u32_le(chunk, 0).map(u64::from)
        };
        let Some(in_pos) = in_pos else { break };
        seeds.push(crate::cx::Seed {
            out_pos: frame.saturating_mul(u64::from(FRAME)),
            in_pos,
            decoder: Box::new(lzx::LzxStream::at_reset(params, frame)),
        });
        frame = frame.saturating_add(interval);
        if seeds.len() % 1024 == 1023 {
            cx.checkpoint().await;
        }
    }
    seeds
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
