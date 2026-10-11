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

use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::codec::{Codec, wim};
use crate::cx::Cx;
use crate::dsl::Record;
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
    fn data(self, input: Input, data: Span, r: &Resource, name: &'static str) -> Node {
        if r.flags & FLAG_COMPRESSED == 0 {
            return embedded("Data", input.nested(data));
        }
        match self.codec(r) {
            Some(codec) => content("Data", input, data, codec, Some(r.original)),
            None => unsupported("Data", data, name),
        }
    }
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
            ("Lookup table", true) => match scheme.codec(&r) {
                Some(c) => Node::new("Entries")
                    .span(data)
                    .lazy(compressed_lookup, (input, data, codec, scheme, c)),
                None => unsupported("Data", data, codec),
            },
            (_, true) => scheme.data(input, data, &r, codec),
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

async fn lookup_table(
    cx: Cx,
    (input, span, codec, scheme): (Input, Span, &'static str, Scheme),
) -> Result<()> {
    let n = span.len / LOOKUP_ENTRY;
    cx.set_count(Count::Exact(n));
    let data = cx.read(span.sub(0, n.saturating_mul(LOOKUP_ENTRY))).await?;
    let file = input.span;
    let entry_at = |i: u64| crate::bytes::to_usize(i.saturating_mul(LOOKUP_ENTRY));
    // The run the current entry is in, and the index after its last entry.
    let mut run: Option<(u64, Run)> = None;
    for i in 0..n {
        let at = entry_at(i);
        let Some(r) = resource(&data, at) else {
            break;
        };
        let solid = scheme.solid(&r);
        if solid && run.as_ref().is_none_or(|(end, _)| i >= *end) {
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
            run = Some((
                j,
                Run {
                    entries,
                    resources: resources.into(),
                },
            ));
        }
        let entry = span.sub(i.saturating_mul(LOOKUP_ENTRY), LOOKUP_ENTRY);
        let part = u16_le(&data, at.saturating_add(24)).unwrap_or(0);
        let refs = u32_le(&data, at.saturating_add(26)).unwrap_or(0);
        let hash = data
            .get(at.saturating_add(30)..at.saturating_add(50))
            .unwrap_or_default()
            .to_vec();
        let stream = file.sub(r.offset, r.size);
        let in_solid = solid && r.original != SOLID_RESOURCE;
        let content = match &run {
            Some((_, run)) if in_solid => Node::new("Data")
                .summary(fmt::size(r.size))
                .lazy(solid_stream, (input, run.clone(), r.offset, r.size)),
            _ if solid => Node::new("Solid resource")
                .span(stream)
                .lazy(solid_resource, (input, stream)),
            _ => scheme.data(input, stream, &r, codec),
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
                .value(uint(part, 64)),
            Node::new("Reference count")
                .span(entry.sub(26, 4))
                .value(uint(refs, 64)),
            Node::new("SHA-1")
                .span(entry.sub(30, 20))
                .value(Value::Bytes(hash.clone())),
            content,
        ];
        let hex_hash: String = hash.iter().take(6).map(|b| format!("{b:02x}")).collect();
        let (name, summary) = if solid && !in_solid {
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
    let decoded = cx.decode_lazy(*span, &codec, h.size)?;
    dissect_or_data(cx, input.nested(decoded.sub(within, size))).await
}
