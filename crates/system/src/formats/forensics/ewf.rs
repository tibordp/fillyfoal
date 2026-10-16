//! Expert Witness Compression Format: EWF1 (EnCase 1 to 7 `.E01`, logical
//! `.L01`, also written by FTK Imager and libewf) and EWF2 (EnCase 7 and
//! later `.Ex01`/`.Lx01`).
//!
//! EWF1 chains 76-byte section descriptors forwards from the 13-byte file
//! header; EWF2 puts a 64-byte descriptor after each section's data and
//! chains them backwards from the end of the segment file. Both store the
//! media in chunks (zlib-compressed or stored with an Adler-32) listed by
//! table sections, and case information as tab-separated text in
//! zlib-compressed sections. The chunks of a segment file are assembled into
//! a "Media" source, decoded lazily, so the disk inside can be dissected.

use std::collections::BTreeMap;

use crate::bytes::{to_u64, to_usize, u32_le, u64_le};
use crate::codec::adler32;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::disk::PieceList;
use crate::formats::util::datakit::{hex, size, text};
use crate::formats::util::fmt::plural;
use crate::formats::{Codec, Input, Probe, content, dissect_or_data};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Shared: case information text, media assembly

const EWF_MEDIA: EnumTable = &[
    (0, "removable"),
    (1, "fixed disk"),
    (3, "optical"),
    (0x0e, "logical evidence"),
    (0x10, "memory"),
];
const EWF_COMPRESSION: EnumTable = &[(0, "none"), (1, "fast"), (2, "best")];
const EWF_MEDIA_FLAGS: FlagTable = &[
    flag(1, "IMAGE"),
    flag(2, "PHYSICAL"),
    flag(4, "FASTBLOC"),
    flag(8, "TABLEAU"),
];

/// The values of a header table: `1`, `main`, a line of tab-separated keys
/// and a line of values. Early EnCase headers have no `main` line; their
/// keys start with `c` or `a`.
fn header_values(text_data: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text_data.lines().take(64).collect();
    let keys_at = match lines.iter().position(|l| l.trim_end() == "main") {
        Some(main) => main.saturating_add(1),
        None => match lines
            .iter()
            .position(|l| l.starts_with("c\t") || l.starts_with("a\t"))
        {
            Some(at) => at,
            None => return Vec::new(),
        },
    };
    let split = |at: usize| {
        lines
            .get(at)
            .map(|l| l.split('\t').map(str::trim_end).collect::<Vec<_>>())
            .unwrap_or_default()
    };
    let (keys, values) = (split(keys_at), split(keys_at.saturating_add(1)));
    keys.iter()
        .zip(values.iter())
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
}

/// Inflates a zlib-compressed header section (at most 64 KiB of it) and
/// decodes it: UTF-16 little-endian after a byte order mark, else Latin-1.
async fn header_text(cx: &Cx, data: Span) -> Result<String> {
    let decoded = crate::codec::inflate_span(cx, data, true, None).await?;
    let raw = cx.read_avail(decoded.span.sub(0, 0x10000)).await?;
    Ok(match raw.strip_prefix(b"\xff\xfe") {
        Some(rest) => crate::text::utf16(rest, LE),
        None => crate::text::latin1(&raw),
    })
}

/// Pushes one node per header value, named by `names` (or the raw key);
/// `dates` are seconds since 1970 (EWF1 `header` sections write them as
/// `2026 10 12 3 47 15` text instead, shown as it is).
async fn push_header_values(
    cx: &Cx,
    values: Vec<(String, String)>,
    names: &[(&str, &str)],
    dates: &[&str],
) {
    for (k, v) in values {
        let name = names
            .iter()
            .find(|(key, _)| *key == k)
            .map_or_else(|| k.clone(), |(_, n)| (*n).to_owned());
        let value = match (k.as_str(), v.parse::<i64>()) {
            (key, Ok(t)) if dates.contains(&key) => Value::utc(t),
            _ => text(v),
        };
        cx.push(Node::new(name).value(value)).await;
    }
}

/// Where a chunk's bytes are.
#[derive(Clone, Copy, Debug)]
enum Chunk {
    /// A compressed stream (zlib, or bzip2 in EWF2).
    Packed(Span, bool),
    /// Stored bytes (without their checksum).
    Stored(Span),
    /// An 8-byte pattern repeated over the chunk (EWF2).
    Pattern(u64),
}

/// Builds the media of one segment file from its chunks, `chunk` bytes
/// each, up to `media` bytes (0: unknown, then all chunks).
struct Assembler {
    list: PieceList,
    chunk: u64,
    media: u64,
    patterns: BTreeMap<u64, Span>,
}

impl Assembler {
    fn new(anchor: Span, chunk: u64, media: u64) -> Self {
        Assembler {
            list: PieceList::new(anchor),
            chunk: chunk.max(1),
            media,
            patterns: BTreeMap::new(),
        }
    }

    /// Room left for the next chunk.
    fn want(&self) -> u64 {
        if self.media == 0 {
            self.chunk
        } else {
            self.chunk.min(self.media.saturating_sub(self.list.len()))
        }
    }

    fn full(&self) -> bool {
        self.want() == 0
    }

    fn add(&mut self, cx: &Cx, chunk: Chunk, at: Span) -> Result<()> {
        let want = self.want();
        if want == 0 {
            return Ok(());
        }
        match chunk {
            Chunk::Packed(data, bzip2) => {
                let codec = if bzip2 { Codec::Bzip2 } else { Codec::Zlib };
                self.list.data(cx.decode_lazy(data, &codec, want)?);
            }
            Chunk::Stored(data) => {
                let data = data.sub(0, want);
                self.list.data(data);
                self.list.hole(cx, want.saturating_sub(data.len))?;
            }
            Chunk::Pattern(0) => self.list.hole(cx, want)?,
            Chunk::Pattern(p) => {
                let span = match self.patterns.get(&p) {
                    Some(s) => *s,
                    None => {
                        let bytes: Vec<u8> = p
                            .to_le_bytes()
                            .iter()
                            .copied()
                            .cycle()
                            .take(to_usize(self.chunk.min(1 << 20)))
                            .collect();
                        let len = to_u64(bytes.len());
                        let origin = Origin {
                            parent: at,
                            transform: "ewf-pattern",
                        };
                        let s = cx.add_derived(origin, bytes, len, None)?.span;
                        self.patterns.insert(p, s);
                        s
                    }
                };
                self.list.data(span.sub(0, want));
            }
        }
        Ok(())
    }

    async fn finish(self, cx: &Cx, input: Input, missing: bool) -> Result<()> {
        if missing && self.media > self.list.len() {
            cx.diag(Diagnostic::note(format!(
                "this segment holds {} of the {} media; the rest is in other segment files",
                size(self.list.len()),
                size(self.media)
            )));
        }
        let span = self.list.finish(cx, "ewf-media").await?;
        dissect_or_data(cx.clone(), input.nested(span)).await
    }
}

// ---------------------------------------------------------------------------
// EWF1 (EnCase .E01 / logical .L01)

declare_format!(pub EWF = "ewf", "Expert Witness evidence file (EnCase E01/L01)", ["e01", "l01", "s01", "ewf"], "application/x-ewf",
    Probe::Magic(&[(0, b"EVF\x09\x0d\x0a\xff\x00"), (0, b"LVF\x09\x0d\x0a\xff\x00")]), ewf);

record! {
    pub struct EwfSection {
        kind: ascii[16] "Section type",
        next: u64 "Next section offset" .hex(),
        size: u64 "Section size",
        _padding: bytes[40] "Padding",
        checksum: u32 "Adler-32" .hex(),
    }
}

fn ewf_volume(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u64)> {
    f.u8("Media type").enumeration(EWF_MEDIA).emit()?;
    f.bytes("Padding", 3).emit()?;
    let chunks = f.u32("Number of chunks").emit()?;
    let per_chunk = f.u32("Sectors per chunk").emit()?;
    let sector = f.u32("Bytes per sector").emit()?;
    let sectors = f.u64("Number of sectors").emit()?;
    f.u32("Cylinders").emit()?;
    f.u32("Heads").emit()?;
    f.u32("Sectors per track").emit()?;
    f.u8("Media flags").flags(EWF_MEDIA_FLAGS).emit()?;
    f.bytes("Padding", 3).emit()?;
    f.u32("PALM volume start sector").emit()?;
    f.bytes("Padding", 4).emit()?;
    f.u32("SMART logs start sector").emit()?;
    f.u8("Compression level")
        .enumeration(EWF_COMPRESSION)
        .emit()?;
    f.bytes("Padding", 3).emit()?;
    f.u32("Error granularity").emit()?;
    f.bytes("Padding", 4).emit()?;
    f.guid("Set identifier").emit()?;
    Ok((
        chunks,
        per_chunk.saturating_mul(sector),
        sectors.saturating_mul(sector.into()),
    ))
}

const EWF_HEADER_KEYS: &[(&str, &str)] = &[
    ("a", "Description"),
    ("c", "Case number"),
    ("n", "Evidence number"),
    ("e", "Examiner"),
    ("t", "Notes"),
    ("av", "Acquisition software version"),
    ("ov", "Acquisition platform"),
    ("m", "Acquisition date"),
    ("u", "System date"),
    ("p", "Password hash"),
    ("md", "Model"),
    ("sn", "Serial number"),
    ("l", "Device label"),
    ("dc", "Unknown (dc)"),
    ("pid", "Process identifier"),
    ("r", "Compression"),
];

/// The sections of an EWF1 segment file, following the chain from the file
/// header; calls `visit` with each (offset, descriptor) until it returns
/// false. Stops at `done`/`next`, a loop or the end of the file.
async fn ewf1_walk<F>(cx: &Cx, file: Span, mut visit: F) -> Result<()>
where
    F: FnMut(u64, &EwfSection) -> bool,
{
    let mut at = 13u64;
    let mut count = 0u32;
    while at.saturating_add(EwfSection::SIZE) <= file.len {
        if count > 100_000 {
            cx.diag(Diagnostic::malformed("section chain loops").at(file.sub(at, 16)));
            break;
        }
        count = count.saturating_add(1);
        let s: EwfSection = read_record(cx, file.sub(at, EwfSection::SIZE), LE).await?;
        if !visit(at, &s) {
            break;
        }
        let kind = s.kind.trim();
        // Offsets only grow, so the chain cannot loop.
        if kind == "done" || kind == "next" || s.next <= at {
            break;
        }
        at = s.next;
    }
    Ok(())
}

async fn ewf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 13)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.bytes("Signature", 8).emit()?;
    f.u8("Fields start").emit()?;
    let segment = f.u16("Segment number").emit()?;
    f.u16("Fields end").emit()?;
    let logical = sig.first() == Some(&b'L');
    cx.emit(
        Node::new("Media")
            .summary(if logical {
                "the chunks of this segment (logical evidence: file data)"
            } else {
                "the chunks of this segment, assembled"
            })
            .lazy(ewf1_media, input),
    );
    let mut sections = Vec::new();
    ewf1_walk(&cx, file, |at, s| {
        sections.push((at, s.clone()));
        true
    })
    .await?;
    let mut info: Vec<(String, String)> = Vec::new();
    let mut media = 0u64;
    let mut sectors_end = None;
    for (at, s) in sections {
        cx.progress_in(file, file.offset.saturating_add(at));
        let desc_span = file.sub(at, EwfSection::SIZE);
        let data = file.sub(
            at.saturating_add(EwfSection::SIZE),
            s.size.saturating_sub(EwfSection::SIZE),
        );
        let kind = s.kind.trim().to_owned();
        let mut node = Node::new(kind.clone())
            .span(file.sub(at, s.size.max(EwfSection::SIZE)))
            .lazy(
                ewf_section,
                (input, desc_span, data, kind.clone(), sectors_end),
            );
        if kind == "sectors" {
            sectors_end = Some(at.saturating_add(s.size));
        }
        match kind.as_str() {
            "header" | "header2" => {
                if info.is_empty()
                    && let Ok(txt) = header_text(&cx, data).await
                {
                    info = header_values(&txt);
                }
                node = node.summary("zlib-compressed case information");
            }
            "volume" | "disk" => {
                let block = cx.block(data.sub(0, 94)).await?;
                if let Ok((chunks, chunk_size, bytes)) =
                    ewf_volume(&mut Fields::new(&block, LE), &())
                {
                    media = bytes;
                    node = node.summary(format!(
                        "{chunks_chunk} of {}, media {}",
                        size(chunk_size.into()),
                        size(bytes),
                        chunks_chunk = plural(chunks, "chunk")
                    ));
                }
            }
            "table" | "table2" => {
                let t = cx.read_avail(data.sub(0, 4)).await?;
                node = node.summary(format!("{} chunk offsets", u32_le(&t, 0).unwrap_or(0)));
            }
            "next" | "done" => {}
            _ => node = node.summary(size(data.len)),
        }
        cx.push(node).await;
    }
    let get = |k: &str| {
        info.iter()
            .find(|(key, _)| key == k)
            .map(|(_, v)| v.clone())
            .filter(|v| !v.is_empty())
    };
    let mut parts = vec![format!(
        "{} segment {segment}",
        if logical {
            "EnCase logical evidence (L01)"
        } else {
            "EnCase evidence (E01)"
        }
    )];
    if media > 0 {
        parts.push(format!("{} media", size(media)));
    }
    for (key, label) in [("c", "case"), ("n", "evidence"), ("e", "examiner")] {
        if let Some(v) = get(key) {
            parts.push(format!("{label} {v}"));
        }
    }
    cx.annotate(parts.join(", "));
    Ok(())
}

async fn ewf_section(
    cx: Cx,
    (input, desc, data, kind, sectors_end): (Input, Span, Span, String, Option<u64>),
) -> Result<()> {
    cx.emit(EwfSection::node("Descriptor", desc, LE));
    match kind.as_str() {
        "header" | "header2" | "ltree" => {
            cx.emit(content("Text (zlib)", input, data, Codec::Zlib, None));
            if kind != "ltree"
                && let Ok(txt) = header_text(&cx, data).await
            {
                push_header_values(&cx, header_values(&txt), EWF_HEADER_KEYS, &["m", "u"]).await;
            }
        }
        "volume" | "disk" | "data" => {
            cx.emit(struct_node("Volume", data.sub(0, 94), LE, (), ewf_volume));
        }
        "table" | "table2" => {
            let block = cx.block(data.sub(0, 24)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let count = f.u32("Number of entries").emit()?;
            f.u32("Padding").emit()?;
            let base = f.u64("Table base offset").hex().emit()?;
            f.u32("Padding").emit()?;
            f.u32("Adler-32").hex().emit()?;
            let entries = data.sub_exact(24, u64::from(count).saturating_mul(4))?;
            let file = input.span;
            let ends = ChunkEnds {
                table: desc.offset.saturating_sub(file.offset),
                table_end: data.end().saturating_sub(file.offset),
                sectors_end,
            };
            cx.emit(
                Node::new("Chunks")
                    .span(entries)
                    .summary(plural(count, "chunk"))
                    .lazy(ewf_chunks, (input, entries, base, ends)),
            );
        }
        "hash" => {
            let block = cx.block(data.sub(0, 16)).await?;
            Fields::emitting(&cx, &block, LE).bytes("MD5", 16).emit()?;
        }
        "digest" => {
            let block = cx.block(data.sub(0, 36)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.bytes("MD5", 16).emit()?;
            f.bytes("SHA-1", 20).emit()?;
        }
        "sectors" => cx.emit(Node::new("Chunk data").span(data)),
        _ if !data.is_empty() => cx.emit(Node::new("Data").span(data)),
        _ => {}
    }
    Ok(())
}

/// Where the chunks a table lists can end: the table section (start and
/// end) and the end of the `sectors` section before it, if any.
#[derive(Clone, Copy, Debug)]
struct ChunkEnds {
    table: u64,
    table_end: u64,
    sectors_end: Option<u64>,
}

impl ChunkEnds {
    /// The end of the last chunk, which starts at `start`: the end of the
    /// `sectors` section that holds it (EnCase 6 and later), or of the table
    /// section when the chunks follow the offsets (EnCase 1 to 5).
    fn last(&self, start: u64) -> u64 {
        if start >= self.table {
            self.table_end
        } else {
            self.sectors_end
                .filter(|&e| e > start && e <= self.table)
                .unwrap_or(self.table)
        }
    }
}

/// The chunks of an EWF1 table: offsets relative to `base`, the high bit
/// set for a zlib-compressed chunk; each chunk extends to the next one's
/// offset, the last as [`ChunkEnds::last`] says. Stored chunks carry a
/// trailing Adler-32.
fn ewf1_chunks(
    raw: &[u8],
    base: u64,
    ends: ChunkEnds,
) -> impl Iterator<Item = (u64, u64, bool)> + '_ {
    let offsets = raw.as_chunks::<4>().0;
    offsets.iter().enumerate().map(move |(i, o)| {
        let o = u32::from_le_bytes(*o);
        let start = base.saturating_add(u64::from(o & 0x7fff_ffff));
        let end = offsets.get(i.saturating_add(1)).map_or_else(
            || ends.last(start),
            |n| base.saturating_add(u64::from(u32::from_le_bytes(*n) & 0x7fff_ffff)),
        );
        (start, end.saturating_sub(start), o & 0x8000_0000 != 0)
    })
}

async fn ewf_chunks(
    cx: Cx,
    (input, entries, base, ends): (Input, Span, u64, ChunkEnds),
) -> Result<()> {
    let file = input.span;
    let raw = cx.read(entries).await?;
    cx.set_count(Count::Exact(to_u64(raw.len() / 4)));
    for (i, (start, len, compressed)) in ewf1_chunks(&raw, base, ends).enumerate() {
        let span = file.sub(start, len);
        let node = if compressed {
            content(format!("Chunk {i}"), input, span, Codec::Zlib, None).summary("zlib")
        } else {
            let data = span.sub(0, span.len.saturating_sub(4));
            content(
                format!("Chunk {i}"),
                input,
                data,
                Codec::Stored,
                Some(data.len),
            )
            .summary("stored, Adler-32 after the data")
        };
        cx.push(node.target(entries.sub(to_u64(i).saturating_mul(4), 4)))
            .await;
    }
    Ok(())
}

/// The media of an EWF1 segment: the chunks of its `table` sections in
/// order (`table2` repeats them).
async fn ewf1_media(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut tables = Vec::new();
    let (mut chunk, mut media, mut volume) = (32 * 1024u64, 0u64, None);
    let mut sectors_end = None;
    ewf1_walk(&cx, file, |at, s| {
        match s.kind.trim() {
            "table" => tables.push((at, s.size, sectors_end)),
            "sectors" => sectors_end = Some(at.saturating_add(s.size)),
            "volume" | "disk" if volume.is_none() => volume = Some(at),
            _ => {}
        }
        true
    })
    .await?;
    if let Some(at) = volume {
        let block = cx
            .block(file.sub(at.saturating_add(EwfSection::SIZE), 94))
            .await?;
        if let Ok((_, chunk_size, bytes)) = ewf_volume(&mut Fields::new(&block, LE), &()) {
            (chunk, media) = (chunk_size.into(), bytes);
        }
    }
    let mut asm = Assembler::new(file.sub(13, 0), chunk, media);
    let mut segments_missing = false;
    for (at, len, sectors_end) in tables {
        let data = file.sub(
            at.saturating_add(EwfSection::SIZE),
            len.saturating_sub(EwfSection::SIZE),
        );
        let head = cx.read_avail(data.sub(0, 24)).await?;
        let count = u64::from(u32_le(&head, 0).unwrap_or(0));
        let base = u64_le(&head, 8).unwrap_or(0);
        let entries = data.sub_exact(24, count.saturating_mul(4))?;
        let raw = cx.read(entries).await?;
        let ends = ChunkEnds {
            table: at,
            table_end: at.saturating_add(len),
            sectors_end,
        };
        for (i, (start, len, compressed)) in ewf1_chunks(&raw, base, ends).enumerate() {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            if asm.full() {
                break;
            }
            let span = file.sub(start, len);
            let piece = if compressed {
                Chunk::Packed(span, false)
            } else {
                Chunk::Stored(span.sub(0, len.saturating_sub(4)))
            };
            asm.add(&cx, piece, entries.sub(to_u64(i).saturating_mul(4), 4))?;
        }
        segments_missing = true;
    }
    asm.finish(&cx, input, segments_missing).await
}

// ---------------------------------------------------------------------------
// EWF2 (EnCase 7 .Ex01 / logical .Lx01)

declare_format!(pub EWF2 = "ewf2", "Expert Witness 2 evidence file (EnCase 7 Ex01/Lx01)", ["ex01", "lx01"], "application/x-ewf2",
    Probe::Magic(&[(0, b"EVF2\x0d\x0a\x81\x00"), (0, b"LEF2\x0d\x0a\x81\x00")]), ewf2);

const EWF2_COMPRESSION: EnumTable = &[(0, "none"), (1, "deflate"), (2, "bzip2")];

record! {
    pub struct Ewf2Header {
        signature: bytes[8] "Signature",
        major: u8 "Major version",
        minor: u8 "Minor version",
        compression: u16 "Compression method" .enumeration(EWF2_COMPRESSION),
        segment: u32 "Segment number",
        set: guid "Set identifier",
    }
}

const EWF2_SECTIONS: EnumTable = &[
    (0x01, "Device information"),
    (0x02, "Case data"),
    (0x03, "Sector data"),
    (0x04, "Sector table"),
    (0x05, "Error table"),
    (0x06, "Session table"),
    (0x07, "Increment data"),
    (0x08, "MD5 hash"),
    (0x09, "SHA-1 hash"),
    (0x0a, "Restart data"),
    (0x0b, "Encryption keys"),
    (0x0c, "Memory extents table"),
    (0x0d, "Next"),
    (0x0e, "Final information"),
    (0x0f, "Done"),
    (0x10, "Analytical data"),
    (0x20, "Single files data"),
];
const EWF2_DATA_FLAGS: FlagTable = &[flag(1, "HAS_INTEGRITY_HASH"), flag(2, "ENCRYPTED")];

record! {
    pub struct Ewf2Section {
        kind: u32 "Section type" .enumeration(EWF2_SECTIONS),
        flags: u32 "Data flags" .flags(EWF2_DATA_FLAGS),
        previous: u64 "Previous section offset" .hex(),
        size: u64 "Data size",
        descriptor_size: u32 "Descriptor size",
        padding: u32 "Padding size",
        hash: bytes[16] "Data integrity hash (MD5)",
        _reserved: bytes[12] "Padding",
        checksum: u32 "Adler-32" .hex(),
    }
}

const EWF2_CASE_KEYS: &[(&str, &str)] = &[
    ("nm", "Description"),
    ("cn", "Case number"),
    ("en", "Evidence number"),
    ("ex", "Examiner"),
    ("nt", "Notes"),
    ("av", "Acquisition software version"),
    ("os", "Acquisition platform"),
    ("tt", "System date"),
    ("at", "Acquisition date"),
    ("tb", "Number of chunks"),
    ("cp", "Compression level"),
    ("sb", "Sectors per chunk"),
    ("gr", "Error granularity"),
    ("wb", "Write blocker"),
];

const EWF2_DEVICE_KEYS: &[(&str, &str)] = &[
    ("sn", "Serial number"),
    ("md", "Model"),
    ("lb", "Label"),
    ("ts", "Number of sectors"),
    ("hs", "HPA-protected sectors"),
    ("dc", "DCO-protected sectors"),
    ("dt", "Drive type"),
    ("pid", "Process identifier"),
    ("rs", "PALM RAM sectors"),
    ("ls", "SMART log sectors"),
    ("bp", "Bytes per sector"),
    ("ph", "Physical"),
];

/// A section: its descriptor's offset, and the descriptor.
type Ewf2Entry = (u64, Ewf2Section);

/// The sections of an EWF2 segment file in file order, walked back from the
/// descriptor that ends the file. Each section's data precedes its
/// descriptor, and offsets only shrink, so the walk ends.
async fn ewf2_sections(cx: &Cx, file: Span) -> Result<Vec<Ewf2Entry>> {
    let mut out = Vec::new();
    let mut at = file.len.saturating_sub(Ewf2Section::SIZE);
    while at >= Ewf2Header::SIZE {
        if out.len().is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let span = file.sub(at, Ewf2Section::SIZE);
        let raw = cx.read(span).await?;
        let s: Ewf2Section = read_record(cx, span, LE).await?;
        if raw.get(..60).map(adler32) != Some(s.checksum) {
            let what = if out.is_empty() {
                "no section descriptor ends the file (truncated?)"
            } else {
                "a section descriptor's checksum does not match"
            };
            cx.diag(Diagnostic::malformed(what).at(span));
            break;
        }
        let previous = s.previous;
        out.push((at, s));
        if previous == 0 || previous >= at {
            break;
        }
        at = previous;
    }
    out.reverse();
    Ok(out)
}

/// The data of a section: what precedes its descriptor.
fn ewf2_data(file: Span, at: u64, s: &Ewf2Section) -> Span {
    let len = s.size.min(at);
    file.sub(at.saturating_sub(len), len)
}

/// Case and device information that sizes the media.
#[derive(Default)]
struct Ewf2Info {
    case: Vec<(String, String)>,
    device: Vec<(String, String)>,
}

impl Ewf2Info {
    fn get(&self, key: &str) -> Option<&str> {
        self.case
            .iter()
            .chain(self.device.iter())
            .find(|(k, v)| k == key && !v.is_empty())
            .map(|(_, v)| v.as_str())
    }

    fn number(&self, key: &str) -> Option<u64> {
        self.get(key).and_then(|v| v.parse().ok())
    }

    /// Chunk size and media size in bytes.
    fn geometry(&self) -> (u64, u64) {
        let sector = self.number("bp").filter(|&b| b > 0).unwrap_or(512);
        let per_chunk = self.number("sb").filter(|&s| s > 0).unwrap_or(64);
        let media = self.number("ts").unwrap_or(0).saturating_mul(sector);
        (per_chunk.saturating_mul(sector), media)
    }
}

async fn ewf2_info(cx: &Cx, file: Span, sections: &[Ewf2Entry]) -> Ewf2Info {
    let mut info = Ewf2Info::default();
    for (at, s) in sections {
        let slot = match s.kind {
            1 if info.device.is_empty() => &mut info.device,
            2 if info.case.is_empty() => &mut info.case,
            _ => continue,
        };
        if s.flags & 2 != 0 {
            continue;
        }
        if let Ok(txt) = header_text(cx, ewf2_data(file, *at, s)).await {
            *slot = header_values(&txt);
        }
    }
    info
}

async fn ewf2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Ewf2Header::SIZE);
    let header: Ewf2Header = read_record(&cx, hspan, LE).await?;
    cx.emit(Ewf2Header::node("File header", hspan, LE));
    let logical = header.signature.first() == Some(&b'L');
    let sections = ewf2_sections(&cx, file).await?;
    let info = ewf2_info(&cx, file, &sections).await;
    let (chunk, media) = info.geometry();
    cx.emit(
        Node::new("Media")
            .summary(if logical {
                "the chunks of this segment (logical evidence: file data)".to_owned()
            } else if media > 0 {
                format!("the chunks of this segment, assembled ({})", size(media))
            } else {
                "the chunks of this segment, assembled".to_owned()
            })
            .lazy(ewf2_media, (input, header.compression)),
    );
    for (at, s) in &sections {
        cx.progress_in(file, file.offset.saturating_add(*at));
        let data = ewf2_data(file, *at, s);
        let name = crate::value::lookup(EWF2_SECTIONS, s.kind.into())
            .map_or_else(|| format!("Section {:#x}", s.kind), str::to_owned);
        let mut node = Node::new(name)
            .span(file.sub(
                data.offset.saturating_sub(file.offset),
                data.len.saturating_add(Ewf2Section::SIZE),
            ))
            .lazy(
                ewf2_section,
                (
                    input,
                    file.sub(*at, Ewf2Section::SIZE),
                    data,
                    s.kind,
                    s.flags,
                    chunk,
                ),
            );
        node = match s.kind {
            1 | 2 => node.summary("zlib-compressed text"),
            3 => node.summary(format!("{} of chunks", size(data.len))),
            4 => {
                let t = cx.read_avail(data.sub(0, 16)).await?;
                node.summary(format!(
                    "chunks {}.., {}",
                    u64_le(&t, 0).unwrap_or(0),
                    plural(u32_le(&t, 8).unwrap_or(0), "entry")
                ))
            }
            0x0d | 0x0f => node,
            _ => node.summary(size(data.len)),
        };
        if s.flags & 2 != 0 {
            node = node.diag(Diagnostic::unsupported("encrypted section data"));
        }
        cx.push(node).await;
    }
    let mut parts = vec![format!(
        "{} segment {}",
        if logical {
            "EnCase 7 logical evidence (Lx01)"
        } else {
            "EnCase 7 evidence (Ex01)"
        },
        header.segment
    )];
    if media > 0 {
        parts.push(format!("{} media", size(media)));
    }
    for (key, label) in [("cn", "case"), ("en", "evidence"), ("ex", "examiner")] {
        if let Some(v) = info.get(key) {
            parts.push(format!("{label} {v}"));
        }
    }
    cx.annotate(parts.join(", "));
    Ok(())
}

async fn ewf2_section(
    cx: Cx,
    (input, desc, data, kind, flags, chunk): (Input, Span, Span, u32, u32, u64),
) -> Result<()> {
    cx.emit(Ewf2Section::node("Descriptor", desc, LE));
    if flags & 2 != 0 {
        cx.emit(Node::new("Data (encrypted)").span(data));
        return Ok(());
    }
    match kind {
        1 | 2 => {
            // The text is padded to 16 bytes.
            let padding = u32_le(&cx.read(desc.sub(28, 4)).await?, 0).unwrap_or(0);
            let data = data.sub(0, data.len.saturating_sub(padding.into()));
            cx.emit(content("Text (zlib)", input, data, Codec::Zlib, None));
            if let Ok(txt) = header_text(&cx, data).await {
                let names = if kind == 1 {
                    EWF2_DEVICE_KEYS
                } else {
                    EWF2_CASE_KEYS
                };
                push_header_values(&cx, header_values(&txt), names, &["tt", "at"]).await;
            }
        }
        3 => cx.emit(Node::new("Chunk data").span(data)),
        4 => {
            let block = cx.block(data.sub(0, 32)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.u64("First chunk").emit()?;
            let count = f.u32("Number of entries").emit()?;
            f.u32("Unknown").emit()?;
            f.u32("Adler-32").hex().emit()?;
            f.bytes("Padding", 12).emit()?;
            let entries = data.sub_exact(32, u64::from(count).saturating_mul(16))?;
            cx.emit(
                Node::new("Chunks")
                    .span(entries)
                    .summary(plural(count, "chunk"))
                    .lazy(ewf2_chunks, (input, entries, chunk)),
            );
            let footer = data.sub(entries.end().saturating_sub(data.offset), 16);
            if !footer.is_empty() {
                let block = cx.block(footer).await?;
                let mut f = Fields::emitting(&cx, &block, LE);
                f.u32("Entries Adler-32").hex().emit()?;
                f.bytes("Padding", 12).emit()?;
            }
        }
        5 | 6 => {
            let block = cx.block(data.sub(0, 32)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let count = f.u32("Number of entries").emit()?;
            f.bytes("Unknown", 12).emit()?;
            f.u32("Adler-32").hex().emit()?;
            f.bytes("Padding", 12).emit()?;
            let width = if kind == 5 { 16 } else { 32 };
            let entries = data.sub_exact(32, u64::from(count).saturating_mul(width))?;
            cx.emit(
                Node::new(if kind == 5 { "Errors" } else { "Sessions" })
                    .span(entries)
                    .summary(plural(count, "entry"))
                    .lazy(ewf2_ranges, (entries, kind)),
            );
        }
        8 | 9 => {
            let len: u64 = if kind == 8 { 16 } else { 20 };
            let block = cx.block(data.sub(0, len.saturating_add(4))).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            f.bytes(if kind == 8 { "MD5" } else { "SHA-1" }, len)
                .emit()?;
            f.u32("Adler-32").hex().emit()?;
        }
        _ if !data.is_empty() => cx.emit(Node::new("Data").span(data)),
        _ => {}
    }
    Ok(())
}

/// Error table entries (first sector, sector count) and session table
/// entries (first sector, flags).
async fn ewf2_ranges(cx: Cx, (entries, kind): (Span, u32)) -> Result<()> {
    let width = if kind == 5 { 16u64 } else { 32 };
    let raw = cx.read(entries).await?;
    let count = raw.len().checked_div(to_usize(width)).unwrap_or(0);
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(to_usize(width));
        let start = u64_le(&raw, at).unwrap_or(0);
        let second = u32_le(&raw, at.saturating_add(8)).unwrap_or(0);
        let summary = if kind == 5 {
            format!(
                "sectors {start}.., {second_sector}",
                second_sector = plural(second, "sector")
            )
        } else {
            format!("first sector {start}, flags {second:#x}")
        };
        cx.push(
            Node::new(format!("Entry {i}"))
                .span(entries.sub(to_u64(at), width))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

/// One sector table entry: offset, size and flags; a pattern-fill entry
/// holds the 8-byte pattern in its offset.
fn ewf2_chunk(raw: &[u8], at: usize) -> (u64, u64, u32) {
    (
        u64_le(raw, at).unwrap_or(0),
        u32_le(raw, at.saturating_add(8)).unwrap_or(0).into(),
        u32_le(raw, at.saturating_add(12)).unwrap_or(0),
    )
}

fn ewf2_piece(file: Span, (offset, len, flags): (u64, u64, u32), bzip2: bool) -> Chunk {
    if flags & 4 != 0 {
        Chunk::Pattern(offset)
    } else if flags & 1 != 0 {
        Chunk::Packed(file.sub(offset, len), bzip2)
    } else if flags & 2 != 0 {
        Chunk::Stored(file.sub(offset, len.saturating_sub(4)))
    } else {
        Chunk::Stored(file.sub(offset, len))
    }
}

async fn ewf2_chunks(cx: Cx, (input, entries, chunk): (Input, Span, u64)) -> Result<()> {
    let file = input.span;
    let raw = cx.read(entries).await?;
    let header = cx.read_avail(file.sub(10, 2)).await?;
    let bzip2 = header.first() == Some(&2);
    let count = raw.len() / 16;
    cx.set_count(Count::Exact(to_u64(count)));
    for i in 0..count {
        let at = i.saturating_mul(16);
        let entry = ewf2_chunk(&raw, at);
        let target = entries.sub(to_u64(at), 16);
        let name = format!("Chunk {i}");
        let node = match ewf2_piece(file, entry, bzip2) {
            Chunk::Pattern(p) => Node::new(name).value(hex(p, 64)).summary("pattern fill"),
            Chunk::Packed(span, bz) => {
                let codec = if bz { Codec::Bzip2 } else { Codec::Zlib };
                content(name, input, span, codec, Some(chunk)).summary(if bz {
                    "bzip2"
                } else {
                    "zlib"
                })
            }
            Chunk::Stored(span) => content(name, input, span, Codec::Stored, Some(span.len))
                .summary(if entry.2 & 2 != 0 {
                    "stored, Adler-32 after the data"
                } else {
                    "stored"
                }),
        };
        let unknown = entry.2 & !7;
        let node = if unknown != 0 {
            node.diag(Diagnostic::note(format!(
                "unknown chunk flags {unknown:#x}"
            )))
        } else {
            node
        };
        cx.push(node.target(target)).await;
    }
    Ok(())
}

/// The media of an EWF2 segment: the chunks of its sector tables in order.
async fn ewf2_media(cx: Cx, (input, compression): (Input, u16)) -> Result<()> {
    let file = input.span;
    let sections = ewf2_sections(&cx, file).await?;
    let info = ewf2_info(&cx, file, &sections).await;
    let (chunk, media) = info.geometry();
    let mut asm = Assembler::new(file.sub(0, Ewf2Header::SIZE), chunk, media);
    let mut tables = false;
    for (at, s) in sections
        .iter()
        .filter(|(_, s)| s.kind == 4 && s.flags & 2 == 0)
    {
        tables = true;
        let data = ewf2_data(file, *at, s);
        let head = cx.read_avail(data.sub(0, 16)).await?;
        let count = u64::from(u32_le(&head, 8).unwrap_or(0));
        let entries = data.sub_exact(32, count.saturating_mul(16))?;
        let raw = cx.read(entries).await?;
        for i in 0..raw.len() / 16 {
            if i.is_multiple_of(1024) {
                cx.checkpoint().await;
            }
            if asm.full() {
                break;
            }
            let at = i.saturating_mul(16);
            let piece = ewf2_piece(file, ewf2_chunk(&raw, at), compression == 2);
            asm.add(&cx, piece, entries.sub(to_u64(at), 16))?;
        }
    }
    asm.finish(&cx, input, tables).await
}

#[cfg(test)]
mod tests {
    use super::header_values;

    #[test]
    fn header_tables() {
        let ewf2 = "1\nmain\nnm\tcn\ten\n\tcase-1\tev-1\n\n";
        let v = header_values(ewf2);
        assert_eq!(v.len(), 3);
        assert_eq!(
            v.get(1).map(|(k, v)| (k.as_str(), v.as_str())),
            Some(("cn", "case-1"))
        );
        // EnCase 1-3 headers: no `main` line.
        let old = "1\r\nc\tn\ta\r\n7\t1\tdisk\r\n";
        let v = header_values(old);
        assert_eq!(
            v.get(2).map(|(k, v)| (k.as_str(), v.as_str())),
            Some(("a", "disk"))
        );
    }
}
