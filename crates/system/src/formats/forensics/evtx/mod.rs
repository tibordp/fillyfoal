//! Windows XML event logs (`.evtx`, Vista and later).
//!
//! A 4 KiB file header is followed by 64 KiB chunks. Each chunk has a
//! 512-byte header (with a hash table of the names and one of the template
//! definitions used in the chunk) and event records; a record holds its
//! number, the time it was written and the event as Binary XML
//! ([`binxml`]): a template instance whose definition is stored inline the
//! first time a chunk uses it, with an array of typed substitution values.
//! Records are summarised from their rendered XML (event ID, level,
//! provider) and show the XML text and the token tree.

mod binxml;

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::util::binutil::Tree;
use crate::formats::util::datakit::hex;
use crate::formats::util::pace::{Pace, STEPS_PER_UNIT};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

use binxml::{Facts, Parser, parse_record};

const LE: Endian = Endian::Little;
const HEADER_BLOCK: u64 = 0x1000;
const CHUNK: u64 = 0x10000;
const RECORDS_START: u64 = 0x200;
const STRING_TABLE: u64 = 0x80;
const TEMPLATE_TABLE: u64 = 0x180;

pub static FORMAT: Format = Format {
    name: "evtx",
    title: "Windows XML event log",
    extensions: &["evtx"],
    mime: "application/x-ms-evtx",
    probe: Probe::Magic(&[(0, b"ElfFile\0")]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_FLAGS: FlagTable = &[flag(1, "DIRTY"), flag(2, "FULL")];
const CHUNK_FLAGS: FlagTable = &[flag(1, "DIRTY"), flag(4, "NO_CRC32")];

/// Event levels (the `Level` element; ETW event headers use the same).
pub(crate) const LEVELS: EnumTable = &[
    (0, "LogAlways"),
    (1, "Critical"),
    (2, "Error"),
    (3, "Warning"),
    (4, "Information"),
    (5, "Verbose"),
];

record! {
    pub struct FileHeader {
        signature: ascii[8] "Signature",
        first_chunk: u64 "First chunk number",
        last_chunk: u64 "Last chunk number",
        next_record: u64 "Next record identifier",
        header_size: u32 "Header size",
        minor: u16 "Minor version",
        major: u16 "Major version",
        block_size: u16 "Header block size" .hex(),
        chunks: u16 "Number of chunks",
        _unknown: bytes[76] "Reserved",
        flags: u32 "File flags" .flags(FILE_FLAGS),
        checksum: u32 "Checksum" .hex() .desc("CRC-32 of the first 120 bytes"),
    }
}

record! {
    pub struct ChunkHeader {
        signature: ascii[8] "Signature",
        first_number: u64 "First event record number",
        last_number: u64 "Last event record number",
        first_id: u64 "First event record identifier",
        last_id: u64 "Last event record identifier",
        header_size: u32 "Header size",
        last_offset: u32 "Last event record offset" .hex(),
        free_offset: u32 "Free space offset" .hex(),
        records_crc: u32 "Event records checksum" .hex() .desc("CRC-32 of the records (0x200 up to the free space offset)"),
        _unknown: bytes[64] "Reserved",
        flags: u32 "Flags" .flags(CHUNK_FLAGS),
        header_crc: u32 "Header checksum" .hex() .desc("CRC-32 of bytes 0–0x78 and 0x80–0x200"),
    }
}

record! {
    pub struct RecordHeader {
        signature: bytes[4] "Signature",
        size: u32 "Size",
        id: u64 "Event record identifier",
        written: u64 "Written" .filetime(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, FileHeader::SIZE);
    let header = parse(&cx, header_span, LE, &(), FileHeader::layout).await?;
    let mut node = FileHeader::node("File header", header_span, LE);
    let bytes = cx.read(file.sub(0, 120)).await?;
    let computed = crc32(&bytes);
    node = if computed == header.checksum {
        node.summary(format!(
            "version {}.{}, {} chunks, checksum valid",
            header.major, header.minor, header.chunks
        ))
    } else {
        node.diag(Diagnostic::warning(format!(
            "header checksum mismatch: computed {computed:#010x}"
        )))
    };
    cx.emit(node);
    let block = u64::from(header.block_size).clamp(FileHeader::SIZE, HEADER_BLOCK);
    if file.len > FileHeader::SIZE {
        cx.emit(
            Node::new("Header block padding")
                .span(file.sub(FileHeader::SIZE, block.saturating_sub(FileHeader::SIZE)))
                .desc("Rest of the header block (unused)"),
        );
    }

    let chunks = file.tail(block.min(file.len));
    let count = chunks.len.div_ceil(CHUNK);
    // Records held: from the first chunk's first to the last chunk's last.
    let mut range = None;
    let last_chunk = header.last_chunk.min(count.saturating_sub(1));
    if let (Ok(first), Ok(last)) = (
        cx.read_avail(chunks.sub(0, 0x30)).await,
        cx.read_avail(chunks.sub(last_chunk.saturating_mul(CHUNK), 0x30))
            .await,
    ) && first.starts_with(b"ElfChnk\0")
        && last.starts_with(b"ElfChnk\0")
    {
        range = Some((
            u64_le(&first, 8).unwrap_or(0),
            u64_le(&last, 16).unwrap_or(0),
        ));
    }
    let mut summary = format!(
        "Windows event log {}.{}, {} chunks",
        header.major, header.minor, header.chunks
    );
    if let Some((a, b)) = range {
        summary.push_str(&format!(
            ", records {a}–{b} ({} events)",
            b.saturating_sub(a).saturating_add(1)
        ));
    }
    if header.flags & 1 != 0 {
        summary.push_str(", dirty");
    }
    cx.annotate(summary);

    let fixed = if file.len > FileHeader::SIZE { 2 } else { 1 };
    cx.set_count(Count::Exact(count.saturating_add(fixed)));
    for i in 0..count {
        let span = chunks.sub(i.saturating_mul(CHUNK), CHUNK);
        let head = cx.read_avail(span.sub(0, 0x30)).await?;
        let mut node = Node::new(format!("Chunk {i}")).span(span);
        if !head.starts_with(b"ElfChnk\0") {
            node = if head.iter().all(|&b| b == 0) {
                node.summary("unused (empty)")
            } else {
                node.summary("unused")
            };
        } else {
            let first = u64_le(&head, 8).unwrap_or(0);
            let last = u64_le(&head, 16).unwrap_or(0);
            node = node
                .summary(format!(
                    "records {first}–{last} ({} events)",
                    last.saturating_sub(first).saturating_add(1)
                ))
                .lazy(chunk, span);
        }
        if span.len < CHUNK {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, CHUNK),
                span.len,
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// The bytes of a chunk, read once and shared by its record nodes.
async fn chunk_data(cx: &Cx, span: Span) -> Result<Arc<Vec<u8>>> {
    if let Some(d) = cx.cached::<Vec<u8>>(span, "evtx-chunk") {
        return Ok(d);
    }
    let d = Arc::new(cx.read_avail(span).await?);
    cx.cache(span, "evtx-chunk", d.clone());
    Ok(d)
}

async fn chunk(cx: Cx, span: Span) -> Result<()> {
    let header_span = span.sub(0, ChunkHeader::SIZE);
    let header = parse(&cx, header_span, LE, &(), ChunkHeader::layout).await?;
    let data = chunk_data(&cx, span).await?;
    let mut node = ChunkHeader::node("Chunk header", header_span, LE);
    if to_u64(data.len()) >= RECORDS_START {
        let mut covered = data.get(..120).unwrap_or_default().to_vec();
        covered.extend_from_slice(data.get(128..512).unwrap_or_default());
        let computed = crc32(&covered);
        node = if computed == header.header_crc {
            node.summary("header checksum valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "header checksum mismatch: computed {computed:#010x}"
            )))
        };
    }
    cx.emit(node);
    cx.emit(
        Node::new("String table")
            .span(span.sub(STRING_TABLE, 64 * 4))
            .value(Value::Text(bucket_usage(&data, STRING_TABLE, 64)))
            .desc("Hash table of the element and attribute names stored in the chunk: 64 bucket heads, chained through each name's next offset")
            .lazy(string_table, span),
    );
    cx.emit(
        Node::new("Template table")
            .span(span.sub(TEMPLATE_TABLE, 32 * 4))
            .value(Value::Text(bucket_usage(&data, TEMPLATE_TABLE, 32)))
            .desc("Hash table of the template definitions stored in the chunk: 32 bucket heads, chained through each definition's next offset")
            .lazy(template_table, span),
    );
    let end = u64::from(header.free_offset).clamp(RECORDS_START, CHUNK);
    let records = span.sub(RECORDS_START, end.saturating_sub(RECORDS_START));
    let body = data
        .get(to_usize(RECORDS_START)..to_usize(end))
        .unwrap_or_default();
    let mut crc_node = Node::new("Event records checksum")
        .span(records)
        .value(hex(header.records_crc, 32));
    crc_node = if to_u64(body.len()) < records.len {
        crc_node.diag(Diagnostic::truncated(records, to_u64(body.len())))
    } else {
        let computed = crate::formats::util::datakit::crc32_paced(&cx, body).await;
        if computed == header.records_crc {
            crc_node.summary("valid")
        } else {
            crc_node.diag(Diagnostic::warning(format!(
                "mismatch: computed {computed:#010x}"
            )))
        }
    };
    cx.emit(crc_node);

    let mut parser = Parser::new(data.as_slice(), span);
    let mut pace = Pace::new(&cx, STEPS_PER_UNIT);
    let mut pos = RECORDS_START;
    while end.saturating_sub(pos) >= RecordHeader::SIZE {
        let at = to_usize(pos);
        let (Some(magic), Some(size), Some(id), Some(written)) = (
            data.get(at..at.saturating_add(4)),
            u32_le(&data, at.saturating_add(4)),
            u64_le(&data, at.saturating_add(8)),
            u64_le(&data, at.saturating_add(16)),
        ) else {
            break;
        };
        if magic != b"**\0\0" {
            cx.diag(Diagnostic::malformed("expected an event record").at(span.sub(pos, 4)));
            break;
        }
        let size = u64::from(size);
        if size < 28 || pos.saturating_add(size) > end {
            cx.diag(
                Diagnostic::malformed(format!("bad event record size {size}")).at(span.sub(pos, 8)),
            );
            break;
        }
        let rspan = span.sub(pos, size);
        let body_end = to_usize(pos.saturating_add(size).saturating_sub(4));
        parser.steps = 0;
        let (_, items) = parse_record(&mut parser, at.saturating_add(24), body_end, false);
        let mut facts = Facts::default();
        let summary = match &items {
            Ok(items) => {
                parser.render(items, &mut facts);
                record_summary(&facts)
            }
            Err(_) => None,
        };
        pace.add(parser.steps).await;
        let mut node = Node::new(format!("Record {id}"))
            .span(rspan)
            .value(Value::Timestamp {
                unix_seconds: crate::text::filetime_to_unix(written),
            })
            .summary(summary.unwrap_or_else(|| format!("{size} bytes")))
            .lazy(record, (span, pos, size));
        if let Err(e) = items {
            node = node.diag(e);
        }
        cx.push(node).await;
        pos = pos.saturating_add(size);
    }
    let free = span.sub(end, CHUNK.saturating_sub(end));
    if free.len > 0 {
        cx.push(
            Node::new("Free space")
                .span(free)
                .summary(format!("{} bytes", free.len))
                .desc("Unused space after the last record (may hold remnants of older records)"),
        )
        .await;
    }
    Ok(())
}

/// "Event 1000, Information, Microsoft-Windows-..."
fn record_summary(facts: &Facts) -> Option<String> {
    let mut parts = Vec::new();
    if let Some(id) = &facts.event_id {
        parts.push(format!("Event {id}"));
    }
    if let Some(level) = &facts.level {
        let name = level.parse::<u64>().ok().and_then(|l| lookup(LEVELS, l));
        parts.push(match name {
            Some(n) => n.to_owned(),
            None => format!("level {level}"),
        });
    }
    parts.extend(facts.provider.clone());
    (!parts.is_empty()).then(|| parts.join(", "))
}

/// "12 of 64 buckets used".
fn bucket_usage(data: &[u8], table: u64, buckets: u64) -> String {
    let used = (0..buckets)
        .filter(|i| {
            u32_le(data, to_usize(table.saturating_add(i.saturating_mul(4)))).unwrap_or(0) != 0
        })
        .count();
    format!("{used} of {buckets} buckets used")
}

/// The name at chunk offset `at`: (hash, text, size).
fn name_at(data: &[u8], at: usize) -> Option<(u16, String, usize)> {
    let hash = u16_le(data, at.checked_add(4)?)?;
    let count = usize::from(u16_le(data, at.checked_add(6)?)?);
    let start = at.checked_add(8)?;
    let chars = data.get(start..start.checked_add(count.checked_mul(2)?)?)?;
    Some((
        hash,
        crate::text::utf16(chars, LE),
        count.checked_mul(2)?.checked_add(10)?,
    ))
}

async fn string_table(cx: Cx, span: Span) -> Result<()> {
    let data = chunk_data(&cx, span).await?;
    for i in 0..64u64 {
        let at = STRING_TABLE.saturating_add(i.saturating_mul(4));
        let head = u32_le(&data, to_usize(at)).unwrap_or(0);
        if head == 0 {
            continue;
        }
        // Follow the chain (bounded: names are at least 10 bytes apart).
        let mut names = Vec::new();
        let mut next = head;
        let mut seen = 0u32;
        while next != 0 && seen < 0x2000 {
            cx.checkpoint().await;
            let Some((_, name, _)) = name_at(&data, to_usize(next.into())) else {
                break;
            };
            names.push(name);
            next = u32_le(&data, to_usize(next.into())).unwrap_or(0);
            seen = seen.saturating_add(1);
        }
        let target = name_at(&data, to_usize(head.into()))
            .map(|(_, _, size)| span.sub(head.into(), to_u64(size)));
        let mut node = Node::new(format!("Bucket {i}"))
            .span(span.sub(at, 4))
            .value(hex(head, 32))
            .summary(names.join(", "));
        if let Some(t) = target {
            node = node.target(t);
        }
        cx.emit(node);
    }
    Ok(())
}

async fn template_table(cx: Cx, span: Span) -> Result<()> {
    let data = chunk_data(&cx, span).await?;
    for i in 0..32u64 {
        let at = TEMPLATE_TABLE.saturating_add(i.saturating_mul(4));
        let head = u32_le(&data, to_usize(at)).unwrap_or(0);
        if head == 0 {
            continue;
        }
        let mut found = Vec::new();
        let mut next = head;
        let mut seen = 0u32;
        while next != 0 && seen < 0x1000 {
            cx.checkpoint().await;
            let n = to_usize(next.into());
            let (Some(id), Some(size)) = (
                u32_le(&data, n.saturating_add(4)),
                u32_le(&data, n.saturating_add(20)),
            ) else {
                break;
            };
            found.push(format!("{id:#010x} at {next:#x} ({size} bytes)"));
            next = u32_le(&data, n).unwrap_or(0);
            seen = seen.saturating_add(1);
        }
        let size = u32_le(&data, to_usize(head.into()).saturating_add(20)).unwrap_or(0);
        cx.emit(
            Node::new(format!("Bucket {i}"))
                .span(span.sub(at, 4))
                .value(hex(head, 32))
                .summary(found.join(", "))
                .target(span.sub(head.into(), u64::from(size).saturating_add(24))),
        );
    }
    Ok(())
}

async fn record(cx: Cx, (chunk, pos, size): (Span, u64, u64)) -> Result<()> {
    let data = chunk_data(&cx, chunk).await?;
    let span = chunk.sub(pos, size);
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    RecordHeader::read(&mut f)?;
    let at = to_usize(pos);
    let body_end = to_usize(pos.saturating_add(size).saturating_sub(4));
    let body = span.sub(
        RecordHeader::SIZE,
        size.saturating_sub(RecordHeader::SIZE.saturating_add(4)),
    );
    let mut parser = Parser::new(data.as_slice(), chunk);
    let (root, items) = parse_record(&mut parser, at.saturating_add(24), body_end, true);
    let mut facts = Facts::default();
    let xml = items.as_ref().ok().map(|i| parser.render(i, &mut facts));
    Pace::new(&cx, STEPS_PER_UNIT).add(parser.steps).await;
    if let Some(xml) = xml {
        cx.emit(
            Node::new("Event XML")
                .value(Value::Text(xml))
                .desc("The event rendered as XML: the template applied to the substitution values"),
        );
    }
    let mut tree = std::mem::take(&mut parser.tree);
    if let Some(root) = root {
        let err = items.err();
        tree.update(root, |n| {
            let n = n
                .span(body)
                .summary(format!("{} bytes", body.len))
                .desc("The event as Binary XML tokens");
            match err {
                Some(e) => n.diag(e),
                None => n,
            }
        });
        let tree = Arc::new(tree);
        cx.emit(Tree::node(&tree, root));
    }
    f.seek(size.saturating_sub(4));
    let copy = f.u32("Size copy").emit()?;
    if u64::from(copy) != size {
        cx.diag(Diagnostic::malformed("size copy differs from size"));
    }
    Ok(())
}
