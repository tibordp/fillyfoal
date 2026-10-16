//! Windows Imaging Format (`.wim`, `.esd`, `.swm`).
//!
//! A 208-byte header points at resources through 24-byte resource headers:
//! the lookup table (one entry per stored stream), the XML description of
//! the images (UTF-16), boot metadata and the integrity table. Resources
//! are XPRESS/LZX/LZMS-compressed unless flagged otherwise; uncompressed
//! ones (normally the XML data) are dissected in place.
//!
//! Version 0xe00 images (ESD files, `wimlib-imagex --solid`) may also hold
//! solid resources: several streams compressed together, with their own
//! header (decoded size, chunk size, codec). In the lookup table a run of
//! entries flagged SOLID describes them: entries with an original size of
//! 0x100000000 are the resources themselves, and every other entry is a
//! stream at an offset into the run's resources' decoded data, one after
//! another (wimlib's `blob_table.c`).

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::codec::{Codec, wim};
use crate::cx::Cx;
use crate::dsl::{Path, Record};
use crate::error::Diagnostic;
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::arcutil::{emit_nodes, unsupported};
use crate::formats::util::fmt;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Input, Probe, content, dissect_or_data, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const LOOKUP_ENTRY: u64 = 50;
/// The original size that marks a solid resource's own lookup entry.
const SOLID_RESOURCE: u64 = 1 << 32;
/// The only version whose SOLID flags count (wimlib ignores them
/// elsewhere).
const VERSION_SOLID: u32 = 0xe00;
const FLAG_COMPRESSED: u8 = 0x04;
const FLAG_SOLID: u8 = 0x10;

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

/// A resource header; `true` for a stream in solid resources, whose size
/// and offset are in the solid data.
fn resource_layout(f: &mut Fields<'_>, in_solid: &bool) -> Result<()> {
    let block = f.block().data.clone();
    let r = resource(&block, 0).unwrap_or_default();
    let span = f.peek_span(8);
    f.node(
        Node::new(if *in_solid { "Size" } else { "Compressed size" })
            .span(span.sub(0, 7))
            .value(uint(r.size, 64))
            .summary(fmt::size(r.size)),
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
    if *in_solid {
        f.u64("Offset")
            .hex()
            .desc("In the decoded data of the run's solid resources")
            .emit()?;
    } else {
        f.u64("Offset").hex().emit()?;
    }
    f.u64("Original size")
        .with(|&s, n| {
            if s == SOLID_RESOURCE {
                n.summary("solid resource")
            } else {
                n.summary(fmt::size(s))
            }
        })
        .emit()?;
    Ok(())
}

const SOLID_FORMATS: EnumTable = &[(0, "none"), (1, "XPRESS"), (2, "LZX"), (3, "LZMS")];

record! {
    /// The header a solid resource starts with.
    pub struct SolidHeader {
        size: u64 "Decoded size" .with(|&s, n| n.summary(fmt::size(s))),
        chunk: u32 "Chunk size" .with(|&c, n| n.summary(fmt::size(c.into()))),
        format: u32 "Compression" .enumeration(SOLID_FORMATS),
    }
}

impl SolidHeader {
    /// The codec of the resource it heads (header included).
    fn codec(&self) -> Option<Codec> {
        Some(Codec::WimResource(wim::Resource {
            kind: wim::Kind::from_solid_format(self.format)?,
            chunk: self.chunk,
            original: self.size,
            solid: true,
        }))
    }
}

record! {
    pub struct Header {
        magic: ascii[8] "Magic",
        size: u32 "Header size",
        version: u32 "Version" .hex(),
        flags: u32 "Flags" .flags(HEADER_FLAGS),
        chunk: u32 "Chunk size" .with(|&c, n| n.summary(fmt::size(c.into()))),
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

/// How the image's resources are compressed: the header flags and chunk
/// size, and the version (whether SOLID flags count).
#[derive(Clone, Copy, Debug)]
struct Scheme {
    flags: u32,
    chunk: u32,
    version: u32,
}

impl Scheme {
    /// Whether a lookup entry is part of a solid run.
    fn solid(self, r: &Resource) -> bool {
        self.version == VERSION_SOLID && r.flags & FLAG_SOLID != 0
    }

    /// The codec for a compressed non-solid resource, if we decode its
    /// scheme (XPRESS, LZX or LZMS).
    fn codec(self, r: &Resource) -> Option<Codec> {
        let kind = if self.flags & 0x0002_0000 != 0 {
            wim::Kind::Xpress
        } else if self.flags & 0x0004_0000 != 0 {
            wim::Kind::Lzx
        } else if self.flags & 0x0008_0000 != 0 {
            wim::Kind::Lzms
        } else {
            return None;
        };
        (!self.solid(r)).then_some(Codec::WimResource(wim::Resource {
            kind,
            chunk: self.chunk,
            original: r.original,
            solid: false,
        }))
    }

    /// A node for a resource's (possibly compressed) data.
    fn data(
        self,
        input: Input,
        data: Span,
        r: &Resource,
        name: &'static str,
        label: &'static str,
    ) -> Node {
        if r.flags & FLAG_COMPRESSED == 0 {
            // Like a stream in a solid resource: unrecognised content is plain data.
            return content(label, input, data, Codec::Stored, Some(r.original));
        }
        match self.codec(r) {
            Some(codec) => Node::new(label)
                .span(data)
                .lazy(resource_content, (input, data, codec, r.original)),
            None => unsupported(label, data, name),
        }
    }
}

/// Seeds at most this many chunk starts of a resource decoded on demand.
const MAX_SEEDS: u64 = 4096;

/// Expander: a compressed non-solid resource, decoded on demand from the
/// nearest chunk start when large (see [`resource_seeds`]).
async fn resource_content(
    cx: Cx,
    (input, data, codec, original): (Input, Span, Codec, u64),
) -> Result<()> {
    if !crate::formats::decodes_lazily(data, &codec, original) {
        return crate::formats::expand_content(cx, (input, data, codec, Some(original))).await;
    }
    let seeds = resource_seeds(&cx, data, &codec).await;
    crate::formats::expand_content_seeded(cx, (input, data, codec, original), seeds).await
}

/// Where a WIM resource can be decoded from: chunks are compressed on
/// their own, so every chunk start in its chunk table is a point to start
/// a decoder (at most [`MAX_SEEDS`], evenly spread). A read deep into a
/// large resource (a file late in a solid ESD resource, the end of a big
/// file) then decodes from the chunk before it, not from the start.
async fn resource_seeds(cx: &Cx, span: Span, codec: &Codec) -> Vec<crate::cx::Seed> {
    let Codec::WimResource(r) = codec else {
        return Vec::new();
    };
    let chunks = r.original.div_ceil(u64::from(r.chunk.max(1)));
    let (entry, header) = if r.solid {
        (4u64, to_u64(wim::SOLID_HEADER))
    } else if r.original > u64::from(u32::MAX) {
        (8, 0)
    } else {
        (4, 0)
    };
    let table = chunks.saturating_mul(entry).saturating_add(header);
    let Ok(head) = cx.read(span.sub(0, table)).await else {
        return Vec::new();
    };
    let every = (chunks / MAX_SEEDS).max(1);
    wim::WimDecoder::seeds(*r, &head, every)
        .into_iter()
        .map(|(out_pos, in_pos, decoder)| crate::cx::Seed {
            out_pos,
            in_pos,
            decoder: Box::new(decoder),
        })
        .collect()
}

/// A compressed lookup table: decompressed, then listed.
async fn compressed_lookup(
    cx: Cx,
    (input, data, name, scheme, codec): (Input, Span, &'static str, Scheme, Codec),
) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, data, &codec, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    lookup_table(cx, (input, decoded.span, name, scheme)).await
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h = crate::fields::parse(&cx, file.sub(0, Header::SIZE), LE, &(), Header::layout).await?;
    let raw = cx.read(file.sub(0, 208)).await?;
    let codec = compression(h.flags);
    let scheme = Scheme {
        flags: h.flags,
        chunk: h.chunk,
        version: h.version,
    };
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
            false,
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
        let compressed = r.flags & FLAG_COMPRESSED != 0;
        let payload = match (name, compressed) {
            // The bootable image's metadata resource (usually a copy of
            // that image's lookup table entry): the same view.
            ("Boot metadata", _) if r.flags & 0x02 != 0 => Node::new("Image metadata")
                .span(data)
                .summary("security data and directory tree")
                .lazy(
                    boot_metadata,
                    (input, data, r, scheme, codec, resource(&raw, 48)),
                ),
            ("Lookup table", true) => match scheme.codec(&r) {
                Some(c) => Node::new("Entries")
                    .span(data)
                    .lazy(compressed_lookup, (input, data, codec, scheme, c)),
                None => unsupported("Data", data, codec),
            },
            (_, true) => scheme.data(input, data, &r, codec, "Data"),
            ("Lookup table", false) => Node::new("Entries")
                .span(data)
                .summary(count(r.size / LOOKUP_ENTRY, "entry", "entries"))
                .lazy(lookup_table, (input, data, codec, scheme)),
            // UTF-16LE, usually with a byte order mark; the XML dissector
            // transcodes it.
            ("XML data", false) => embedded_as(
                "XML",
                input.nested(data),
                &crate::formats::text::xml::FORMAT,
            ),
            _ => embedded("Data", input.nested(data)),
        };
        children.push(payload);
        cx.emit(
            Node::new(name)
                .span(data)
                .summary(fmt::size(r.original))
                .lazy(emit_nodes, Arc::new(children)),
        );
    }
    if let Some(boot) = u32_le(&raw, 120) {
        cx.emit(
            Node::new("Boot index")
                .span(file.sub(120, 4))
                .value(uint(boot, 64)),
        );
    }
    cx.annotate(format!(
        "Windows image, {}, {codec}, part {} of {}",
        count(h.images, "image", "images"),
        h.part,
        h.parts
    ));
    Ok(())
}

/// The solid resources of a run of solid lookup entries: where each one
/// is (in the order of their entries), and the entries' span (which keys
/// the cached [`SolidRun`]).
#[derive(Clone, Debug)]
struct Run {
    entries: Span,
    resources: Arc<[Span]>,
}

/// A run's resources with their headers read: each one's span, header, and
/// where its decoded data starts in the run's.
struct SolidRun {
    resources: Vec<(Span, Option<SolidHeader>, u64)>,
}

/// One lookup table entry.
#[derive(Clone, Debug)]
struct Entry {
    r: Resource,
    part: u16,
    refs: u32,
    hash: [u8; 20],
    /// Whether it is part of a solid run.
    solid: bool,
    /// The solid run it is in (an index into [`Table::runs`]).
    run: Option<usize>,
}

impl Entry {
    /// Whether it is a stream in solid resources (not a resource).
    fn in_solid(&self) -> bool {
        self.solid && self.r.original != SOLID_RESOURCE
    }

    /// The stream's decoded size.
    fn size(&self) -> u64 {
        if self.in_solid() {
            self.r.size
        } else {
            self.r.original
        }
    }
}

/// A lookup table, read once per expansion that needs it: its entries,
/// solid runs, and the streams by SHA-1.
struct Table {
    file: Span,
    entries: Vec<Entry>,
    runs: Vec<Run>,
    by_hash: BTreeMap<[u8; 20], usize>,
}

impl Table {
    fn find(&self, hash: &[u8; 20]) -> Option<&Entry> {
        self.entries.get(*self.by_hash.get(hash)?)
    }

    /// A node for an entry's data.
    fn content(
        &self,
        e: &Entry,
        input: Input,
        scheme: Scheme,
        codec: &'static str,
        label: &'static str,
    ) -> Node {
        let r = e.r;
        let stream = self.file.sub(r.offset, r.size);
        match e.run.and_then(|i| self.runs.get(i)) {
            Some(run) if e.in_solid() => Node::new(label)
                .summary(fmt::size(r.size))
                .lazy(solid_stream, (input, run.clone(), r.offset, r.size)),
            _ if e.solid => Node::new("Solid resource")
                .span(stream)
                .lazy(solid_resource, (input, stream)),
            _ => scheme.data(input, stream, &r, codec, label),
        }
    }
}

/// The lookup table decoded at `span` (cached).
async fn table(cx: &Cx, file: Span, span: Span, scheme: Scheme) -> Result<Arc<Table>> {
    if let Some(t) = cx.cached::<Table>(span, "wim-lookup") {
        return Ok(t);
    }
    let n = span.len / LOOKUP_ENTRY;
    let data = cx.read(span.sub(0, n.saturating_mul(LOOKUP_ENTRY))).await?;
    let entry_at = |i: u64| crate::bytes::to_usize(i.saturating_mul(LOOKUP_ENTRY));
    let mut entries = Vec::new();
    let mut runs: Vec<Run> = Vec::new();
    let mut by_hash = BTreeMap::new();
    // The run the current entry is in, and the index after its last entry.
    let mut run: Option<(u64, usize)> = None;
    for i in 0..n {
        let at = entry_at(i);
        let Some(r) = resource(&data, at) else {
            break;
        };
        let solid = scheme.solid(&r);
        if solid && run.is_none_or(|(end, _)| i >= end) {
            // A new run: find its end and its resources.
            let mut resources = Vec::new();
            let mut j = i;
            while j < n
                && let Some(rj) = resource(&data, entry_at(j))
                && scheme.solid(&rj)
            {
                if rj.original == SOLID_RESOURCE {
                    resources.push(file.sub(rj.offset, rj.size));
                }
                j = j.saturating_add(1);
                if j.saturating_sub(i).is_multiple_of(1024) {
                    cx.checkpoint().await;
                }
            }
            let entries = span.sub(
                i.saturating_mul(LOOKUP_ENTRY),
                j.saturating_sub(i).saturating_mul(LOOKUP_ENTRY),
            );
            runs.push(Run {
                entries,
                resources: resources.into(),
            });
            run = Some((j, runs.len().saturating_sub(1)));
        }
        let e = Entry {
            r,
            part: u16_le(&data, at.saturating_add(24)).unwrap_or(0),
            refs: u32_le(&data, at.saturating_add(26)).unwrap_or(0),
            hash: hash20(&data, at.saturating_add(30)),
            solid,
            run: run.filter(|_| solid).map(|(_, k)| k),
        };
        if !(solid && r.original == SOLID_RESOURCE) && e.hash != [0; 20] {
            by_hash.entry(e.hash).or_insert(entries.len());
        }
        entries.push(e);
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    let t = Arc::new(Table {
        file,
        entries,
        runs,
        by_hash,
    });
    cx.cache(span, "wim-lookup", Arc::clone(&t));
    Ok(t)
}

async fn lookup_table(
    cx: Cx,
    (input, span, codec, scheme): (Input, Span, &'static str, Scheme),
) -> Result<()> {
    let table = table(&cx, input.span, span, scheme).await?;
    cx.set_count(Count::Exact(to_u64(table.entries.len())));
    for (i, e) in table.entries.iter().enumerate() {
        let r = e.r;
        let entry = span.sub(to_u64(i).saturating_mul(LOOKUP_ENTRY), LOOKUP_ENTRY);
        let in_solid = e.in_solid();
        let content = if r.flags & 0x02 != 0 && !e.solid {
            let stream = input.span.sub(r.offset, r.size);
            Node::new("Image metadata")
                .span(stream)
                .summary("security data and directory tree")
                .lazy(metadata, (input, stream, r, scheme, codec, span))
        } else {
            table.content(e, input, scheme, codec, "Data")
        };
        let children = vec![
            struct_node(
                "Resource header",
                entry.sub(0, 24),
                LE,
                in_solid,
                resource_layout,
            ),
            Node::new("Part number")
                .span(entry.sub(24, 2))
                .value(uint(e.part, 64)),
            Node::new("Reference count")
                .span(entry.sub(26, 4))
                .value(uint(e.refs, 64)),
            Node::new("SHA-1")
                .span(entry.sub(30, 20))
                .checksum(crate::value::Check::new("SHA-1", e.hash.to_vec())),
            content,
        ];
        let hex_hash: String = e.hash.iter().take(6).map(|b| format!("{b:02x}")).collect();
        let (name, summary) = if e.solid && !in_solid {
            (
                "solid resource".to_string(),
                format!("{} compressed", fmt::size(r.size)),
            )
        } else {
            let kind = if r.flags & 0x02 != 0 {
                "metadata"
            } else {
                "stream"
            };
            let summary = if in_solid {
                format!("{} in solid resources", fmt::size(r.size))
            } else {
                format!("{} → {}", fmt::size(r.size), fmt::size(r.original))
            };
            (format!("{kind} {hex_hash}…"), summary)
        };
        cx.push(
            Node::new(name)
                .span(entry)
                .value(hex(r.offset, 64))
                .summary(summary)
                .lazy(emit_nodes, Arc::new(children)),
        )
        .await;
    }
    Ok(())
}

/// A solid resource: its header, chunk table and decoded data.
async fn solid_resource(cx: Cx, (input, data): (Input, Span)) -> Result<()> {
    let header = data.sub(0, SolidHeader::SIZE);
    let h = crate::fields::parse(&cx, header, LE, &(), SolidHeader::layout).await?;
    cx.emit(SolidHeader::node("Solid header", header, LE));
    let chunks = if h.chunk == 0 {
        0
    } else {
        h.size.div_ceil(u64::from(h.chunk))
    };
    cx.emit(
        Node::new("Chunk table")
            .span(data.sub(SolidHeader::SIZE, chunks.saturating_mul(4)))
            .summary(count(chunks, "chunk", "chunks")),
    );
    cx.emit(match h.codec() {
        Some(codec) => content("Data", input, data, codec, Some(h.size)),
        None => unsupported("Data", data, &format!("solid compression {}", h.format)),
    });
    Ok(())
}

/// A stream in solid resources: found in its run by offset, and dissected
/// from the resource's lazily decoded data.
async fn solid_stream(cx: Cx, (input, run, offset, size): (Input, Run, u64, u64)) -> Result<()> {
    let solid = match cx.cached::<SolidRun>(run.entries, "wim-solid-run") {
        Some(solid) => solid,
        None => {
            let mut resources = Vec::with_capacity(run.resources.len());
            let mut start = 0u64;
            for &span in run.resources.iter() {
                let header = span.sub(0, SolidHeader::SIZE);
                let h = crate::fields::parse(&cx, header, LE, &(), SolidHeader::layout)
                    .await
                    .ok();
                let len = h.as_ref().map_or(0, |h| h.size);
                resources.push((span, h, start));
                start = start.saturating_add(len);
            }
            let solid = Arc::new(SolidRun { resources });
            cx.cache(run.entries, "wim-solid-run", Arc::clone(&solid));
            solid
        }
    };
    let at = solid
        .resources
        .partition_point(|&(_, _, start)| start <= offset)
        .checked_sub(1);
    let Some((span, Some(h), start)) = at.and_then(|i| solid.resources.get(i)) else {
        return Err(Diagnostic::malformed(format!(
            "stream at {offset:#x} is in no solid resource"
        )));
    };
    let within = offset.saturating_sub(*start);
    if within.saturating_add(size) > h.size {
        return Err(Diagnostic::malformed(format!(
            "stream at {offset:#x} runs past its solid resource"
        )));
    }
    let Some(codec) = h.codec() else {
        return Err(Diagnostic::unsupported(format!("solid compression {}", h.format)).at(*span));
    };
    let seeds = resource_seeds(&cx, *span, &codec).await;
    let decoded = cx.decode_lazy_seeded(*span, &codec, h.size, seeds)?;
    dissect_or_data(cx, input.nested(decoded.sub(within, size))).await
}

// ---------------------------------------------------------------------------
// Metadata resources: an image's security data and directory tree
// (wimlib's `security.c` and `dentry.c`; Microsoft documents neither).
//
// The decoded resource starts with the security data: a 32-bit total
// length, a 32-bit descriptor count, a 64-bit size per descriptor, then the
// self-relative security descriptors back to back. The root directory
// entry follows at the total length rounded up to 8. A directory entry is
// a 102-byte fixed part (its length, attributes, security ID, the offset of
// its children's list, three FILETIMEs, the SHA-1 of its unnamed stream,
// reparse tag or hard link group, the count of extra stream entries and the
// sizes of its UTF-16 names), the long and short names (each followed by a
// NUL unit), padding to 8 bytes, then the extra stream entries (length,
// reserved, SHA-1, name size, name; each padded to 8). A list of children
// is a run of entries ended by one whose length is under 102 (0 or 8).

/// Size of the fixed part of a directory entry.
const DENTRY: u64 = 102;
/// Size of the fixed part of an extra stream entry.
const STREAM_ENTRY: u64 = 38;
/// Deepest directory nesting followed.
const MAX_DEPTH: usize = 256;

fn align8(n: u64) -> u64 {
    n.saturating_add(7) & !7
}

/// What the expanders of a metadata resource share.
#[derive(Clone)]
struct Meta {
    input: Input,
    /// The decoded resource.
    data: Span,
    table: Arc<Table>,
    scheme: Scheme,
    codec: &'static str,
}

/// Expander: a metadata resource, decoded, with its security data and
/// directory tree.
async fn metadata(
    cx: Cx,
    (input, stream, r, scheme, codec, lookup): (Input, Span, Resource, Scheme, &'static str, Span),
) -> Result<()> {
    let data = if r.flags & FLAG_COMPRESSED == 0 {
        stream
    } else {
        let Some(c) = scheme.codec(&r) else {
            return Err(Diagnostic::unsupported(format!("{codec} compression")).at(stream));
        };
        if crate::formats::decodes_lazily(stream, &c, r.original) {
            cx.decode_lazy(stream, &c, r.original)?
        } else {
            let decoded = crate::codec::decode_span(&cx, stream, &c, Some(r.original)).await?;
            if let Some(e) = decoded.error {
                cx.diag(e);
            }
            decoded.span
        }
    };
    let table = table(&cx, input.span, lookup, scheme).await?;
    let meta = Meta {
        input,
        data,
        table,
        scheme,
        codec,
    };
    let head = cx.read(data.sub_exact(0, 8)?).await?;
    let total = u64::from(u32_le(&head, 0).unwrap_or(0));
    let entries = u64::from(u32_le(&head, 4).unwrap_or(0));
    cx.emit(
        Node::new("Security data")
            .span(data.sub(0, total))
            .summary(count(entries, "descriptor", "descriptors"))
            .lazy(security_data, data),
    );
    let root = align8(total);
    let d = read_dentry(&cx, data, root)
        .await?
        .ok_or_else(|| Diagnostic::malformed("no root directory entry").at(data.sub(root, 8)))?;
    cx.emit(dentry_node(&meta, &d, "Root directory", Path::new()));
    Ok(())
}

/// Expander: the boot metadata resource, read like an image's metadata
/// resource (its streams are found in the lookup table, decoded first if
/// it is compressed).
async fn boot_metadata(
    cx: Cx,
    (input, stream, r, scheme, codec, lookup): (
        Input,
        Span,
        Resource,
        Scheme,
        &'static str,
        Option<Resource>,
    ),
) -> Result<()> {
    let Some(l) = lookup else {
        return Err(Diagnostic::malformed("no lookup table").at(stream));
    };
    let raw = input.span.sub(l.offset, l.size);
    let table = if l.flags & FLAG_COMPRESSED == 0 {
        raw
    } else {
        let Some(c) = scheme.codec(&l) else {
            return Err(Diagnostic::unsupported(format!("{codec} compression")).at(raw));
        };
        crate::codec::decode_span(&cx, raw, &c, None).await?.span
    };
    metadata(cx, (input, stream, r, scheme, codec, table)).await
}

/// Expander: the security data at the start of a metadata resource.
async fn security_data(cx: Cx, data: Span) -> Result<()> {
    let head = cx.read(data.sub_exact(0, 8)?).await?;
    let total = u64::from(u32_le(&head, 0).unwrap_or(0));
    let n = u64::from(u32_le(&head, 4).unwrap_or(0));
    cx.emit(
        Node::new("Total length")
            .span(data.sub(0, 4))
            .value(uint(total, 64)),
    );
    cx.emit(
        Node::new("Descriptor count")
            .span(data.sub(4, 4))
            .value(uint(n, 64)),
    );
    let sizes_span = data.sub_exact(8, n.saturating_mul(8))?;
    if n.saturating_mul(8).saturating_add(8) > total {
        return Err(
            Diagnostic::malformed("descriptor sizes run past the security data").at(sizes_span),
        );
    }
    let sizes = cx.read(sizes_span).await?;
    cx.emit(Node::new("Descriptor sizes").span(sizes_span));
    cx.set_count(Count::Exact(n.saturating_add(3)));
    let mut at = sizes_span.len.saturating_add(8);
    for (i, size) in sizes
        .as_chunks::<8>()
        .0
        .iter()
        .map(|b| u64::from_le_bytes(*b))
        .enumerate()
    {
        let span = data.sub(at, size);
        if at.saturating_add(size) > total {
            cx.push(
                Node::new(format!("Descriptor {i}"))
                    .span(span)
                    .diag(Diagnostic::malformed("runs past the security data")),
            )
            .await;
            break;
        }
        // Descriptors are small (at most 64 KiB); read each one for its summary.
        let bytes = cx.read(span.sub(0, 0x1_0000)).await?;
        cx.push(
            Node::new(format!("Descriptor {i}"))
                .span(span)
                .summary(crate::formats::util::winsec::sd_summary(&bytes))
                .lazy(
                    crate::formats::util::winsec::security_descriptor,
                    (span, crate::formats::util::winsec::FILE_RIGHTS),
                ),
        )
        .await;
        at = at.saturating_add(size);
    }
    Ok(())
}

/// The span of security descriptor `id` of a metadata resource.
async fn descriptor_span(cx: &Cx, data: Span, id: u32) -> Option<Span> {
    let head = cx.read(data.sub_exact(0, 8).ok()?).await.ok()?;
    let total = u64::from(u32_le(&head, 0)?);
    let n = u32_le(&head, 4)?;
    if id >= n {
        return None;
    }
    let count = u64::from(id).saturating_add(1);
    let sizes = cx
        .read(data.sub_exact(8, count.saturating_mul(8)).ok()?)
        .await
        .ok()?;
    let mut at = u64::from(n).saturating_mul(8).saturating_add(8);
    let mut size = 0;
    for (i, chunk) in sizes.as_chunks::<8>().0.iter().enumerate() {
        size = u64::from_le_bytes(*chunk);
        if to_u64(i) < u64::from(id) {
            at = at.saturating_add(size);
        }
    }
    (at.saturating_add(size) <= total).then(|| data.sub(at, size))
}

/// An extra stream entry of a directory entry.
#[derive(Clone, Debug)]
struct ExtraStream {
    span: Span,
    hash: [u8; 20],
    name: String,
}

/// A directory entry, as read.
#[derive(Clone, Debug)]
struct Dentry {
    /// The fixed part, names and padding (not the extra stream entries).
    span: Span,
    attributes: u32,
    security_id: i32,
    subdir: u64,
    hash: [u8; 20],
    name: String,
    streams: Vec<ExtraStream>,
    /// Offset of the next entry in the list.
    next: u64,
}

impl Dentry {
    fn is_dir(&self) -> bool {
        self.attributes & 0x10 != 0
    }

    /// The SHA-1 of the unnamed data stream: the default one, or (when
    /// there are named streams, as wimlib writes them) the extra stream
    /// entry with no name.
    fn unnamed(&self) -> [u8; 20] {
        if self.hash != [0; 20] {
            return self.hash;
        }
        self.streams
            .iter()
            .find(|s| s.name.is_empty())
            .map_or([0; 20], |s| s.hash)
    }
}

fn hash20(b: &[u8], at: usize) -> [u8; 20] {
    b.get(at..at.saturating_add(20))
        .and_then(|h| h.try_into().ok())
        .unwrap_or([0; 20])
}

/// The directory entry at `offset` of `data`, or `None` for the end of a
/// list.
async fn read_dentry(cx: &Cx, data: Span, offset: u64) -> Result<Option<Dentry>> {
    let first = cx.read(data.sub(offset, 8)).await?;
    let length = u64_le(&first, 0).unwrap_or(0);
    if length < DENTRY {
        return Ok(None);
    }
    let span = data.sub_exact(offset, length)?;
    let b = cx.read(span.sub(0, DENTRY)).await?;
    let name_len = u64::from(u16_le(&b, 100).unwrap_or(0));
    let name_bytes = cx.read(span.sub(DENTRY, name_len)).await?;
    let mut next = offset.saturating_add(align8(length));
    let mut streams = Vec::new();
    for _ in 0..u16_le(&b, 96).unwrap_or(0) {
        let head = cx.read(data.sub(next, STREAM_ENTRY)).await?;
        let len = u64_le(&head, 0).unwrap_or(0);
        if len < STREAM_ENTRY {
            return Err(
                Diagnostic::malformed("extra stream entry shorter than 38 bytes")
                    .at(data.sub(next, 8)),
            );
        }
        let s = data.sub_exact(next, len)?;
        let n = u64::from(u16_le(&head, 36).unwrap_or(0));
        let name = crate::text::utf16(&cx.read(s.sub(STREAM_ENTRY, n)).await?, Endian::Little);
        streams.push(ExtraStream {
            span: s,
            hash: hash20(&head, 16),
            name,
        });
        next = next.saturating_add(align8(len));
    }
    Ok(Some(Dentry {
        span,
        attributes: u32_le(&b, 8).unwrap_or(0),
        security_id: u32_le(&b, 12).unwrap_or(u32::MAX).cast_signed(),
        subdir: u64_le(&b, 16).unwrap_or(0),
        hash: hash20(&b, 64),
        name: crate::text::utf16(&name_bytes, Endian::Little),
        streams,
        next,
    }))
}

/// A lazy node for a directory entry, named `name` (its own name if empty).
fn dentry_node(meta: &Meta, d: &Dentry, name: &str, path: Path) -> Node {
    let label = if name.is_empty() {
        d.name.clone()
    } else {
        name.to_owned()
    };
    let summary = if d.is_dir() {
        "directory".to_owned()
    } else {
        meta.table
            .find(&d.unnamed())
            .map_or_else(|| "empty".to_owned(), |e| fmt::size(e.size()))
    };
    let offset = d.span.offset.saturating_sub(meta.data.offset);
    Node::new(label).span(d.span).summary(summary).lazy(
        crate::expander!(self::dentry: (Meta, u64, Path)),
        (meta.clone(), offset, path),
    )
}

/// Expander: a directory entry's fields, security descriptor and streams,
/// then (for a directory) its children.
async fn dentry(cx: Cx, (meta, offset, path): (Meta, u64, Path)) -> Result<()> {
    let Some(d) = read_dentry(&cx, meta.data, offset).await? else {
        return Err(Diagnostic::malformed("not a directory entry").at(meta.data.sub(offset, 8)));
    };
    cx.emit(struct_node("Entry", d.span, LE, (), dentry_layout));
    if let Ok(id) = u32::try_from(d.security_id)
        && let Some(span) = descriptor_span(&cx, meta.data, id).await
    {
        cx.emit(
            Node::new("Security descriptor")
                .span(span)
                .value(uint(id, 64))
                .lazy(
                    crate::formats::util::winsec::security_descriptor,
                    (span, crate::formats::util::winsec::FILE_RIGHTS),
                ),
        );
    }
    if !d.is_dir() && d.hash != [0; 20] {
        cx.emit(stream_node(&meta, "Content", &d.hash));
    }
    for s in &d.streams {
        let name = if s.name.is_empty() {
            "Unnamed stream".to_owned()
        } else {
            format!("Stream \"{}\"", s.name)
        };
        let mut node = struct_node(name, s.span, LE, (), stream_entry_layout);
        if s.hash != [0; 20] {
            node = node.summary(meta.table.find(&s.hash).map_or_else(
                || "not in the lookup table".to_owned(),
                |e| fmt::size(e.size()),
            ));
        }
        cx.emit(node);
        if s.hash != [0; 20] {
            let label = if s.name.is_empty() {
                "Content"
            } else {
                "Stream content"
            };
            cx.emit(stream_node(&meta, label, &s.hash));
        }
    }
    if !d.is_dir() || d.subdir == 0 {
        return Ok(());
    }
    let path = path.enter(d.subdir, MAX_DEPTH)?;
    let mut at = d.subdir;
    while at < meta.data.len {
        let Some(child) = read_dentry(&cx, meta.data, at).await? else {
            break;
        };
        cx.push(dentry_node(&meta, &child, "", path.clone())).await;
        if child.next <= at {
            break;
        }
        at = child.next;
    }
    Ok(())
}

/// A node for the stream with SHA-1 `hash`, from the lookup table.
fn stream_node(meta: &Meta, name: &'static str, hash: &[u8; 20]) -> Node {
    match meta.table.find(hash) {
        Some(e) => meta
            .table
            .content(e, meta.input, meta.scheme, meta.codec, name),
        None => Node::new(name).diag(Diagnostic::malformed("stream not in the lookup table")),
    }
}

fn dentry_layout(f: &mut Fields<'_>, (): &()) -> Result<()> {
    f.u64("Length").emit()?;
    let attributes = f
        .u32("Attributes")
        .flags(crate::formats::disk::ntfs::FILE_ATTRIBUTES)
        .emit()?;
    f.i32("Security ID")
        .with(|&id, n| if id < 0 { n.summary("none") } else { n })
        .emit()?;
    f.u64("Subdirectory offset").hex().emit()?;
    f.u64("Unused 1").emit()?;
    f.u64("Unused 2").emit()?;
    f.u64("Creation time").filetime().emit()?;
    f.u64("Last access time").filetime().emit()?;
    f.u64("Last write time").filetime().emit()?;
    f.bytes("SHA-1 of the unnamed stream", 20)
        .checksum("SHA-1")
        .emit()?;
    f.u32("Unknown").hex().emit()?;
    if attributes & 0x400 != 0 {
        f.u32("Reparse tag").hex().emit()?;
        f.u16("Reparse reserved").emit()?;
        f.u16("Reparse flags").hex().emit()?;
    } else {
        f.u64("Hard link group").hex().emit()?;
    }
    f.u16("Extra stream entries").emit()?;
    let short = f.u16("Short name size").emit()?;
    let long = f.u16("Name size").emit()?;
    if long > 0 {
        f.utf16("Name", u64::from(long / 2)).emit()?;
        f.skip(2);
    }
    if short > 0 {
        f.utf16("Short name", u64::from(short / 2)).emit()?;
        f.skip(2);
    }
    Ok(())
}

fn stream_entry_layout(f: &mut Fields<'_>, (): &()) -> Result<()> {
    f.u64("Length").emit()?;
    f.u64("Reserved").emit()?;
    f.bytes("SHA-1", 20).checksum("SHA-1").emit()?;
    let n = f.u16("Name size").emit()?;
    if n > 0 {
        f.utf16("Name", u64::from(n / 2)).emit()?;
    }
    Ok(())
}
