//! Forensic evidence containers and memory captures: Expert Witness (EnCase
//! E01/L01), AFF, LiME and makedumpfile (kdump) memory dumps, VMware
//! suspended-state files and VirtualBox saved states.

use crate::bytes::{to_u64, u16_le, u32_le, u64_be, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::datakit::{clip, hex, size, text};
use crate::formats::{Codec, Head, Input, Probe, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Expert Witness Compression Format (EnCase .E01 / logical .L01)

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

const EWF_MEDIA: EnumTable = &[
    (0, "removable"),
    (1, "fixed disk"),
    (3, "optical"),
    (0x0e, "logical evidence"),
    (0x10, "memory"),
];
const EWF_COMPRESSION: EnumTable = &[(0, "none"), (1, "fast"), (2, "best")];

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

const EWF_MEDIA_FLAGS: FlagTable = &[
    flag(1, "IMAGE"),
    flag(2, "PHYSICAL"),
    flag(4, "FASTBLOC"),
    flag(8, "TABLEAU"),
];

/// Header text fields (EnCase 'c\tn\ta\te\tt...' table) by key.
fn ewf_header_values(text_data: &str) -> Vec<(String, String)> {
    let lines: Vec<&str> = text_data.lines().collect();
    let Some(keys_at) = lines
        .iter()
        .position(|l| l.starts_with("c\t") || l.starts_with("a\t"))
    else {
        return Vec::new();
    };
    let keys = lines
        .get(keys_at)
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .unwrap_or_default();
    let values = lines
        .get(keys_at.saturating_add(1))
        .map(|l| l.split('\t').collect::<Vec<_>>())
        .unwrap_or_default();
    keys.iter()
        .zip(values.iter())
        .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
        .collect()
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
];

async fn ewf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 13)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let sig = f.bytes("Signature", 8).emit()?;
    f.u8("Fields start").emit()?;
    let segment = f.u16("Segment number").emit()?;
    f.u16("Fields end").emit()?;
    let logical = sig.first() == Some(&b'L');
    let mut at = 13u64;
    let mut seen = Vec::new();
    let mut info: Vec<(String, String)> = Vec::new();
    let mut media = 0u64;
    let mut table_base = None;
    while at.saturating_add(EwfSection::SIZE) <= file.len {
        if seen.contains(&at) || seen.len() > 100_000 {
            cx.diag(Diagnostic::malformed("section chain loops").at(file.sub(at, 16)));
            break;
        }
        seen.push(at);
        cx.progress_in(file, file.offset.saturating_add(at));
        let desc_span = file.sub(at, EwfSection::SIZE);
        let s: EwfSection = read_record(&cx, desc_span, LE).await?;
        let data = file.sub(
            at.saturating_add(EwfSection::SIZE),
            s.size.saturating_sub(EwfSection::SIZE),
        );
        let kind = s.kind.trim().to_owned();
        let mut node = Node::new(kind.clone())
            .span(file.sub(at, s.size.max(EwfSection::SIZE)))
            .lazy(ewf_section, (input, desc_span, data, kind.clone()));
        match kind.as_str() {
            "header" | "header2" => {
                if info.is_empty()
                    && let Ok(decoded) = crate::codec::inflate_span(&cx, data, true, None).await
                {
                    let raw = cx.read_avail(decoded.span.sub(0, 0x10000)).await?;
                    let txt = if kind == "header2" {
                        crate::text::utf16(raw.get(2..).unwrap_or_default(), LE)
                    } else {
                        crate::text::latin1(&raw)
                    };
                    info = ewf_header_values(&txt);
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
                        "{chunks} chunks of {}, media {}",
                        size(chunk_size.into()),
                        size(bytes)
                    ));
                }
            }
            "table" | "table2" => {
                let t = cx.read_avail(data.sub(0, 24)).await?;
                table_base = Some(u64_le(&t, 8).unwrap_or(0));
                node = node.summary(format!("{} chunk offsets", u32_le(&t, 0).unwrap_or(0)));
            }
            "next" | "done" => {}
            _ => node = node.summary(size(data.len)),
        }
        cx.push(node).await;
        if kind == "done" || kind == "next" || s.next == 0 || s.next <= at {
            break;
        }
        at = s.next;
    }
    let _ = table_base;
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
    if let Some(c) = get("c") {
        parts.push(format!("case {c}"));
    }
    if let Some(n) = get("n") {
        parts.push(format!("evidence {n}"));
    }
    if let Some(e) = get("e") {
        parts.push(format!("examiner {e}"));
    }
    cx.annotate(parts.join(", "));
    Ok(())
}

async fn ewf_section(cx: Cx, (input, desc, data, kind): (Input, Span, Span, String)) -> Result<()> {
    cx.emit(EwfSection::node("Descriptor", desc, LE));
    match kind.as_str() {
        "header" | "header2" | "ltree" => {
            cx.emit(content("Text (zlib)", input, data, Codec::Zlib, None));
            if kind != "ltree"
                && let Ok(decoded) = crate::codec::inflate_span(&cx, data, true, None).await
            {
                let raw = cx.read_avail(decoded.span.sub(0, 0x10000)).await?;
                let txt = if kind == "header2" {
                    crate::text::utf16(raw.get(2..).unwrap_or_default(), LE)
                } else {
                    crate::text::latin1(&raw)
                };
                for (k, v) in ewf_header_values(&txt) {
                    let name = EWF_HEADER_KEYS
                        .iter()
                        .find(|(key, _)| *key == k)
                        .map_or_else(|| k.clone(), |(_, n)| (*n).to_owned());
                    cx.push(Node::new(name).value(text(v))).await;
                }
            }
        }
        "volume" | "disk" => cx.emit(struct_node("Volume", data.sub(0, 94), LE, (), ewf_volume)),
        "table" | "table2" => {
            let block = cx.block(data.sub(0, 24)).await?;
            let mut f = Fields::emitting(&cx, &block, LE);
            let count = f.u32("Number of entries").emit()?;
            f.u32("Padding").emit()?;
            let base = f.u64("Table base offset").hex().emit()?;
            f.u32("Padding").emit()?;
            f.u32("Adler-32").hex().emit()?;
            let entries = data.sub_exact(24, u64::from(count).saturating_mul(4))?;
            cx.emit(
                Node::new("Chunks")
                    .span(entries)
                    .summary(format!("{count} chunks"))
                    .lazy(ewf_chunks, (input, entries, base)),
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

/// Lists the chunks of a table; each is zlib-compressed (high bit set) or
/// stored, and extends to the next chunk's offset.
async fn ewf_chunks(cx: Cx, (input, entries, base): (Input, Span, u64)) -> Result<()> {
    let file = input.span;
    let raw = cx.read(entries).await?;
    let offsets: Vec<u32> = raw
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_le_bytes(*c))
        .collect();
    cx.set_count(Count::Exact(to_u64(offsets.len())));
    for (i, &o) in offsets.iter().enumerate() {
        let start = base.saturating_add(u64::from(o & 0x7fff_ffff));
        // The last chunk ends where the table section begins.
        let end = offsets.get(i.saturating_add(1)).map_or_else(
            || {
                entries
                    .offset
                    .saturating_sub(file.offset)
                    .saturating_sub(24)
                    .saturating_sub(EwfSection::SIZE)
            },
            |n| base.saturating_add(u64::from(n & 0x7fff_ffff)),
        );
        let span = file.sub(start, end.saturating_sub(start));
        let compressed = o & 0x8000_0000 != 0;
        let node = if compressed {
            content(format!("Chunk {i}"), input, span, Codec::Zlib, None).summary("zlib")
        } else {
            // Stored chunks carry a trailing Adler-32.
            embedded(
                format!("Chunk {i}"),
                input.nested(span.sub(0, span.len.saturating_sub(4))),
            )
            .summary("stored")
        };
        cx.push(node.target(entries.sub(to_u64(i).saturating_mul(4), 4)))
            .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Advanced Forensic Format (AFF v1)

declare_format!(pub AFF = "aff", "Advanced Forensic Format image (AFF)", ["aff"], "application/x-aff",
    Probe::Magic(&[(0, b"AFF10\r\n\0")]), aff);

/// Data pages are named `page<N>` (also `seg<N>` in early versions).
fn aff_page(name: &str) -> Option<&str> {
    name.strip_prefix("page")
        .or_else(|| name.strip_prefix("seg"))
        .filter(|n| !n.is_empty() && n.chars().all(|c| c.is_ascii_digit()))
}

const AFF_PAGE_FLAGS: FlagTable = &[
    flag(1, "COMPRESSED"),
    flag(2, "COMPRESSED_MAX"),
    flag(0x10, "ALG_BZIP"),
    flag(0x20, "ALG_LZMA"),
];
const AFF_ALG_ZLIB: u32 = 0x00;
const AFF_ALG_LZMA: u32 = 0x20;
const AFF_ALG_ZERO: u32 = 0x30;

async fn aff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text("AFF10")),
    );
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(8);
    let (mut pages, mut image, mut segments) = (0u64, None, 0u64);
    while cur.remaining() >= 16 {
        let start = cur.pos();
        cx.progress_in(file, file.offset.saturating_add(start));
        let magic = cur.bytes(4).await?;
        if magic != b"AFF\0" {
            cx.diag(
                Diagnostic::malformed("expected a segment header (AFF\\0)").at(cur.since(start)),
            );
            break;
        }
        let name_len = u64::from(cur.u32().await?);
        let data_len = u64::from(cur.u32().await?);
        let arg = cur.u32().await?;
        let name_span = cur.span(name_len);
        let name = crate::text::latin1(&cur.bytes(name_len.min(1024)).await?);
        cur.seek(name_span.end().saturating_sub(file.offset));
        let data = cur.span(data_len);
        cur.skip(data_len);
        let tail = cur.bytes(8).await?;
        if tail.get(..4) != Some(b"ATT\0") {
            cx.diag(Diagnostic::malformed("segment trailer is not ATT\\0").at(cur.since(start)));
            break;
        }
        segments = segments.saturating_add(1);
        let mut node = Node::new(name.clone())
            .span(cur.since(start))
            .target(data)
            .lazy(
                aff_segment,
                (input, cur.since(start), name_span, data, arg, name.clone()),
            );
        if let Some(n) = aff_page(&name) {
            pages = pages.saturating_add(1);
            node = node.summary(format!("page {n}, {} stored", size(data_len)));
        } else if data_len == 8 && name == "imagesize" {
            let raw = cx.read(data).await?;
            let v = u64_be(&raw, 0).unwrap_or(0);
            image = Some(v);
            node = node
                .value(Value::UInt {
                    value: v,
                    bits: 64,
                    radix: Radix::Dec,
                })
                .summary(size(v));
        } else if data_len == 0 {
            node = node.value(Value::UInt {
                value: arg.into(),
                bits: 32,
                radix: Radix::Dec,
            });
        } else {
            let raw = cx.read_avail(data.sub(0, 256)).await?;
            if crate::text::looks_like_text(&raw) {
                node = node.value(text(clip(&crate::text::until_nul(&raw), 120)));
            } else {
                node = node.summary(size(data_len));
            }
        }
        cx.push(node).await;
    }
    cx.annotate(format!(
        "AFF image, {segments} segments, {pages} pages{}",
        image
            .map(|i| format!(", {} image", size(i)))
            .unwrap_or_default()
    ));
    Ok(())
}

async fn aff_segment(
    cx: Cx,
    (input, seg, name_span, data, arg, name): (Input, Span, Span, Span, u32, String),
) -> Result<()> {
    let head = cx.block(seg.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Name length").emit()?;
    f.u32("Data length").emit()?;
    let page = aff_page(&name).is_some();
    if page {
        f.u32("Flags").flags(AFF_PAGE_FLAGS).emit()?;
    } else {
        f.u32("Argument").emit()?;
    }
    cx.emit(Node::new("Name").span(name_span).value(text(name.clone())));
    // afflib: bit 0 marks a compressed page, bits 4..8 the algorithm.
    if page && arg & 1 != 0 {
        cx.emit(match arg & 0xf0 {
            AFF_ALG_ZLIB => content("Data (zlib)", input, data, Codec::Zlib, None),
            // afflib's LZMA pages are `.lzma` streams (properties, size).
            AFF_ALG_LZMA => content("Data (LZMA)", input, data, Codec::LzmaAlone, None),
            AFF_ALG_ZERO => Node::new("Data").span(data).summary("count of zero bytes"),
            _ => Node::new("Data")
                .span(data)
                .diag(Diagnostic::unsupported(format!(
                    "compression algorithm {:#x}",
                    arg & 0xf0
                ))),
        });
    } else if page {
        cx.emit(embedded("Data", input.nested(data)));
    } else {
        cx.emit(Node::new("Data").span(data));
    }
    let trailer = cx.block(seg.sub(seg.len.saturating_sub(8), 8)).await?;
    let mut f = Fields::emitting(&cx, &trailer, BE);
    f.ascii("Trailer", 4).emit()?;
    f.u32("Segment length").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// LiME memory captures

fn lime_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"EMiL")
        && u32_le(h.data, 4) == Some(1)
        && matches!((u64_le(h.data, 8), u64_le(h.data, 16)), (Some(s), Some(e)) if e >= s)
}

declare_format!(pub LIME = "lime", "LiME memory capture", ["lime", "mem"], "application/x-lime",
    Probe::Custom(lime_probe), lime);

record! {
    pub struct LimeHeader {
        magic: u32 "Magic" .hex(),
        version: u32 "Version",
        start: u64 "Start address" .hex(),
        end: u64 "End address (inclusive)" .hex(),
        _reserved: bytes[8] "Reserved",
    }
}

async fn lime(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut at = 0u64;
    let (mut ranges, mut total) = (0u64, 0u64);
    while at.saturating_add(LimeHeader::SIZE) <= file.len {
        cx.progress_in(file, file.offset.saturating_add(at));
        let hspan = file.sub(at, LimeHeader::SIZE);
        let h: LimeHeader = read_record(&cx, hspan, LE).await?;
        if h.magic != 0x4c69_4d45 {
            cx.diag(Diagnostic::malformed("expected a LiME range header").at(file.sub(at, 4)));
            break;
        }
        let len = h.end.saturating_sub(h.start).saturating_add(1);
        let data = file.sub(at.saturating_add(LimeHeader::SIZE), len);
        cx.push(
            Node::new(format!("{:#x}–{:#x}", h.start, h.end))
                .span(file.sub(at, LimeHeader::SIZE.saturating_add(len)))
                .summary(size(len))
                .lazy(lime_range, (hspan, data)),
        )
        .await;
        ranges = ranges.saturating_add(1);
        total = total.saturating_add(len);
        at = at.saturating_add(LimeHeader::SIZE).saturating_add(len);
    }
    cx.annotate(format!(
        "LiME memory capture, {ranges} ranges, {} of physical memory",
        size(total)
    ));
    Ok(())
}

async fn lime_range(cx: Cx, (header, data): (Span, Span)) -> Result<()> {
    cx.emit(LimeHeader::node("Header", header, LE));
    cx.emit(Node::new("Memory").span(data));
    Ok(())
}

// ---------------------------------------------------------------------------
// makedumpfile / diskdump compressed kernel dumps

fn kdump_probe(h: &Head<'_>) -> bool {
    (h.starts_with(b"KDUMP   ") || h.starts_with(b"DISKDUMP"))
        && u32_le(h.data, 8).is_some_and(|v| (1..=10).contains(&v))
}

declare_format!(pub KDUMP = "kdump-compressed", "Linux compressed kernel dump (makedumpfile)", ["vmcore", "kdump"], "application/x-kdump",
    Probe::Custom(kdump_probe), kdump);

const KDUMP_STATUS: FlagTable = &[
    flag(0x01, "COMPRESSED_ZLIB"),
    flag(0x02, "COMPRESSED_LZO"),
    flag(0x04, "COMPRESSED_SNAPPY"),
    flag(0x08, "COMPRESSED_INCOMPLETE"),
    flag(0x10, "EXCLUDED_VMEMMAP"),
    flag(0x20, "COMPRESSED_ZSTD"),
];

fn kdump_header(f: &mut Fields<'_>, _: &()) -> Result<(String, String, u32, u32, u32)> {
    f.ascii("Signature", 8).emit()?;
    f.int::<i32>("Header version").emit()?;
    f.ascii("System name", 65).emit()?;
    let node = f.ascii("Node name", 65).emit()?;
    let release = f.ascii("Release", 65).emit()?;
    f.ascii("Version", 65).emit()?;
    f.ascii("Machine", 65).emit()?;
    f.ascii("Domain name", 65).emit()?;
    f.seek(408);
    f.u64("Timestamp").timestamp().emit()?;
    f.u64("Microseconds").emit()?;
    f.u32("Status").flags(KDUMP_STATUS).emit()?;
    let block = f.u32("Block size").emit()?;
    let sub = f.u32("Sub-header size (blocks)").emit()?;
    let bitmap = f.u32("Bitmap size (blocks)").emit()?;
    f.u32("Maximum PFN (32-bit)").emit()?;
    f.u32("Total RAM blocks").emit()?;
    f.u32("Device blocks").emit()?;
    f.u32("Written blocks").emit()?;
    f.u32("Current CPU").emit()?;
    f.int::<i32>("Number of CPUs").emit()?;
    let _ = sub;
    Ok((node, release, block, sub, bitmap))
}

fn kdump_sub_header(f: &mut Fields<'_>, _: &()) -> Result<(u64, u64)> {
    f.u64("Physical base").hex().emit()?;
    f.int::<i32>("Dump level").emit()?;
    f.int::<i32>("Split").emit()?;
    f.u64("Start PFN").emit()?;
    f.u64("End PFN").emit()?;
    let info = f.u64("vmcoreinfo offset").hex().emit()?;
    let info_len = f.u64("vmcoreinfo size").emit()?;
    f.u64("ELF notes offset").hex().emit()?;
    f.u64("ELF notes size").emit()?;
    f.u64("Erase info offset").hex().emit()?;
    f.u64("Erase info size").emit()?;
    f.u64("Start PFN (64-bit)").emit()?;
    f.u64("End PFN (64-bit)").emit()?;
    f.u64("Maximum PFN (64-bit)").emit()?;
    Ok((info, info_len))
}

async fn kdump(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, 468);
    let block = cx.block(hspan).await?;
    let (node, release, block_size, sub_blocks, bitmap_blocks) =
        kdump_header(&mut Fields::new(&block, LE), &())?;
    cx.emit(struct_node("Disk dump header", hspan, LE, (), kdump_header));
    let bs = u64::from(block_size).max(1);
    let sub = file.sub(bs, u64::from(sub_blocks).saturating_mul(bs));
    let sblock = cx.block(sub.sub(0, 112)).await?;
    let (info_at, info_len) =
        kdump_sub_header(&mut Fields::new(&sblock, LE), &()).unwrap_or((0, 0));
    cx.emit(struct_node("Sub-header", sub, LE, (), kdump_sub_header));
    let mut osrelease = String::new();
    if info_at != 0 && info_len > 0 {
        let info = file.sub(info_at, info_len);
        let raw = cx.read_avail(info.sub(0, 0x10000)).await?;
        let txt = crate::text::latin1(&raw);
        osrelease = txt
            .lines()
            .find_map(|l| l.strip_prefix("OSRELEASE="))
            .unwrap_or_default()
            .to_owned();
        let entries: Vec<(String, String)> = txt
            .lines()
            .filter_map(|l| l.split_once('='))
            .map(|(k, v)| (k.to_owned(), v.to_owned()))
            .collect();
        cx.emit(
            Node::new("vmcoreinfo")
                .span(info)
                .summary(format!("{} entries", entries.len()))
                .lazy(kdump_info, entries),
        );
    }
    let bitmap_at = bs.saturating_mul(1u64.saturating_add(sub_blocks.into()));
    let bitmap = file.sub(bitmap_at, u64::from(bitmap_blocks).saturating_mul(bs));
    cx.emit(
        Node::new("Page bitmaps")
            .span(bitmap)
            .summary("valid and dumpable pages"),
    );
    let descs = file.tail(bitmap.end().saturating_sub(file.offset));
    cx.emit(
        Node::new("Page descriptors and data")
            .span(descs)
            .diag(Diagnostic::note("pages are compressed individually")),
    );
    let release = if osrelease.is_empty() {
        release
    } else {
        osrelease
    };
    cx.annotate(format!(
        "Linux kernel dump of {}, kernel {release}, {} blocks",
        node.trim(),
        size(bs)
    ));
    Ok(())
}

async fn kdump_info(cx: Cx, entries: Vec<(String, String)>) -> Result<()> {
    for (k, v) in entries {
        cx.push(Node::new(k).value(text(v))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VMware suspended state and snapshot memory (.vmss, .vmsn)

fn vmss_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0)
        .is_some_and(|m| matches!(m, 0xbed2_bed0 | 0xbad1_bad1 | 0xbed2_bed2 | 0xbed3_bed3))
        && u32_le(h.data, 8).is_some_and(|n| (1..=1024).contains(&n))
        && h.data
            .get(12..16)
            .is_some_and(|n| n.iter().all(|&b| b.is_ascii_graphic()))
}

declare_format!(pub VMSS = "vmware-state", "VMware suspended state / snapshot (vmss, vmsn)", ["vmss", "vmsn"], "application/x-vmware-vmss",
    Probe::Custom(vmss_probe), vmss);

const VMSS_GROUP: u64 = 80;

async fn vmss(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Magic").hex().emit()?;
    f.u32("Unknown").emit()?;
    let count = f.u32("Number of groups").emit()?;
    let table = file.sub_exact(12, u64::from(count).saturating_mul(VMSS_GROUP))?;
    let raw = cx.read(table).await?;
    let mut names = Vec::new();
    for (i, g) in raw.as_chunks::<80>().0.iter().enumerate() {
        let name = crate::text::until_nul(g.get(..64).unwrap_or_default());
        let tags = u64_le(g, 64).unwrap_or(0);
        let len = u64_le(g, 72).unwrap_or(0);
        names.push(name.clone());
        cx.push(
            Node::new(name)
                .span(table.sub(to_u64(i).saturating_mul(VMSS_GROUP), VMSS_GROUP))
                .target(file.sub(tags, len))
                .summary(size(len))
                .lazy(vmss_tags, file.sub(tags, len)),
        )
        .await;
    }
    cx.annotate(format!(
        "VMware saved state, {count} groups: {}",
        clip(&names.join(", "), 120)
    ));
    Ok(())
}

/// Walks the tags of a group: flags (data size in the low 6 bits, index
/// count in the top 2), name, indices, then inline or sized data.
async fn vmss_tags(cx: Cx, group: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, group, LE);
    while cur.remaining() >= 2 {
        let start = cur.pos();
        cx.progress_in(group, group.offset.saturating_add(start));
        let flags = cur.u8().await?;
        let name_len = cur.u8().await?;
        if flags == 0 && name_len == 0 {
            break;
        }
        let name = crate::text::latin1(&cur.bytes(name_len.into()).await?);
        let indices: Vec<u32> = {
            let mut v = Vec::new();
            for _ in 0..(flags >> 6) {
                v.push(cur.u32().await?);
            }
            v
        };
        let small = u64::from(flags & 0x3f);
        let (data, note) = if small >= 62 {
            let disk = cur.u64().await?;
            let mem = cur.u64().await?;
            if small == 63 {
                cur.skip(2);
            }
            let span = cur.span(disk);
            cur.skip(disk);
            (
                span,
                Some(format!("{} on disk, {} in memory", size(disk), size(mem))),
            )
        } else {
            let span = cur.span(small);
            cur.skip(small);
            (span, None)
        };
        let label = if indices.is_empty() {
            name.clone()
        } else {
            format!(
                "{name}[{}]",
                indices
                    .iter()
                    .map(u32::to_string)
                    .collect::<Vec<_>>()
                    .join("][")
            )
        };
        let mut node = Node::new(label).span(cur.since(start)).target(data);
        let raw = if data.len <= 256 {
            cx.read(data).await?
        } else {
            Vec::new()
        };
        let printable = raw.iter().filter(|&&b| b.is_ascii_alphabetic()).count() >= 3
            && raw.iter().all(|&b| b == 0 || (0x20..0x7f).contains(&b));
        node = match (note, data.len) {
            (Some(n), _) => node.summary(n),
            _ if printable => node.value(text(crate::text::until_nul(&raw))),
            (None, 1) => node.value(Value::UInt {
                value: u64::from(raw.first().copied().unwrap_or(0)),
                bits: 8,
                radix: Radix::Dec,
            }),
            (None, 2) => node.value(Value::UInt {
                value: u16_le(&raw, 0).unwrap_or(0).into(),
                bits: 16,
                radix: Radix::Dec,
            }),
            (None, 4) => node.value(hex(u32_le(&raw, 0).unwrap_or(0), 32)),
            (None, 8) => node.value(hex(u64_le(&raw, 0).unwrap_or(0), 64)),
            _ => node.summary(size(data.len)),
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// VirtualBox saved state (.sav)

declare_format!(pub VBOX_SAV = "vbox-saved-state", "VirtualBox saved state", ["sav"], "application/x-virtualbox-sav",
    Probe::Magic(&[(0, b"\x7fVirtualBox SavedState V")]), vbox_sav);

record! {
    pub struct SsmHeader {
        magic: ascii[32] "Magic",
        major: u16 "VirtualBox major version",
        minor: u16 "VirtualBox minor version",
        build: u32 "VirtualBox build",
        revision: u32 "SVN revision",
        host_bits: u8 "Host bits",
        gc_phys: u8 "Guest physical address size",
        gc_ptr: u8 "Guest pointer size",
        _reserved: u8 "Reserved",
        units: u32 "Number of units",
        flags: u32 "Flags" .hex(),
        max_decompressed: u32 "Maximum decompressed record size",
        crc: u32 "CRC-32" .hex(),
    }
}

const SSM_UNIT: &[u8] = b"\nUnit\n\0\0";

async fn vbox_sav(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, SsmHeader::SIZE);
    let h: SsmHeader = read_record(&cx, hspan, LE).await?;
    cx.emit(SsmHeader::node("Header", hspan, LE));
    // Units are found by their magic and the stream offset they record.
    let mut at = SsmHeader::SIZE;
    let mut names = Vec::new();
    const WINDOW: u64 = 0x10000;
    while at < file.len && names.len() < 4096 {
        cx.progress_in(file, file.offset.saturating_add(at));
        let window = cx
            .read_avail(file.sub(at, WINDOW.saturating_add(64)))
            .await?;
        let mut found = None;
        let mut i = 0usize;
        while let Some(p) = window
            .get(i..)
            .and_then(|w| w.windows(8).position(|x| x == SSM_UNIT))
        {
            let pos = i.saturating_add(p);
            let off = at.saturating_add(to_u64(pos));
            if u64_le(&window, pos.saturating_add(8)) == Some(off) {
                found = Some(off);
                break;
            }
            i = pos.saturating_add(1);
        }
        let Some(unit) = found else {
            at = at.saturating_add(WINDOW);
            cx.checkpoint().await;
            continue;
        };
        let uh = cx.read_avail(file.sub(unit, 40)).await?;
        let name_len = u64::from(u32_le(&uh, 36).unwrap_or(0)).min(256);
        let (name, _) = cx.cstr(file.sub(unit.saturating_add(40), name_len)).await?;
        let version = u32_le(&uh, 20).unwrap_or(0);
        let instance = u32_le(&uh, 24).unwrap_or(0);
        names.push(name.clone());
        cx.push(
            struct_node(
                name,
                file.sub(unit, 40u64.saturating_add(name_len)),
                LE,
                (),
                ssm_unit,
            )
            .summary(format!("version {version}, instance {instance}")),
        )
        .await;
        at = unit.saturating_add(8);
    }
    cx.annotate(format!(
        "VirtualBox {}.{}.{} saved state, {} units ({})",
        h.major,
        h.minor,
        h.build,
        names.len(),
        clip(&names.join(", "), 100)
    ));
    Ok(())
}

fn ssm_unit(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.ascii("Magic", 8).emit()?;
    f.u64("Stream offset").hex().emit()?;
    f.u32("Stream CRC").hex().emit()?;
    f.u32("Unit version").emit()?;
    f.u32("Instance").emit()?;
    f.u32("Pass").emit()?;
    f.u32("Flags").hex().emit()?;
    let n = f.u32("Name length").emit()?;
    f.ascii("Name", n.into()).emit()?;
    Ok(())
}
