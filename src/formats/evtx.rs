//! Windows XML event logs (`.evtx`, Vista and later).
//!
//! A 4 KiB file header is followed by 64 KiB chunks. Each chunk has a 512-byte
//! header (with string and template tables) and event records; a record holds
//! its ID, time written and the event as Binary XML (shown as a span).

use crate::bytes::{to_u64, u64_le};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::datakit::hex;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const LE: Endian = Endian::Little;
const HEADER_BLOCK: u64 = 0x1000;
const CHUNK: u64 = 0x10000;
const RECORDS_START: u64 = 0x200;

pub static FORMAT: Format = Format {
    name: "evtx",
    title: "Windows XML event log",
    extensions: &["evtx"],
    mime: "application/x-ms-evtx",
    probe: Probe::Magic(&[(0, b"ElfFile\0")]),
    dissect: crate::expander!(dissect: Input),
};

const FILE_FLAGS: FlagTable = &[flag(1, "DIRTY"), flag(2, "FULL")];

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
        _unknown: bytes[76] "Unknown",
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
        records_crc: u32 "Event records checksum" .hex(),
        _unknown: bytes[64] "Unknown",
        flags: u32 "Flags" .hex(),
        header_crc: u32 "Header checksum" .hex(),
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
    if crc32(&bytes) != header.checksum {
        node = node.diag(Diagnostic::warning(format!(
            "header checksum mismatch: computed {:#010x}",
            crc32(&bytes)
        )));
    }
    cx.emit(node);
    let mut summary = format!(
        "Windows event log {}.{}, {} chunks, next record {}",
        header.major, header.minor, header.chunks, header.next_record
    );
    if header.flags & 1 != 0 {
        summary.push_str(", dirty");
    }
    cx.annotate(summary);

    let chunks = file.tail(HEADER_BLOCK.min(file.len));
    let count = chunks.len.div_ceil(CHUNK);
    cx.set_count(Count::Exact(count.saturating_add(1)));
    for i in 0..count {
        let span = chunks.sub(i.saturating_mul(CHUNK), CHUNK);
        let head = cx.read_avail(span.sub(0, 0x30)).await?;
        let mut node = Node::new(format!("Chunk {i}")).span(span);
        if !head.starts_with(b"ElfChnk\0") {
            node = node.summary("unused");
        } else {
            let first = u64_le(&head, 24).unwrap_or(0);
            let last = u64_le(&head, 32).unwrap_or(0);
            node = node
                .summary(format!("records {first}–{last}"))
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

async fn chunk(cx: Cx, span: Span) -> Result<()> {
    let header_span = span.sub(0, ChunkHeader::SIZE);
    let header = parse(&cx, header_span, LE, &(), ChunkHeader::layout).await?;
    let mut node = ChunkHeader::node("Chunk header", header_span, LE);
    let head = cx.read_avail(span.sub(0, RECORDS_START)).await?;
    if to_u64(head.len()) == RECORDS_START {
        let mut covered = head.get(..120).unwrap_or_default().to_vec();
        covered.extend_from_slice(head.get(128..).unwrap_or_default());
        let computed = crc32(&covered);
        if computed != header.header_crc {
            node = node.diag(Diagnostic::warning(format!(
                "header checksum mismatch: computed {computed:#010x}"
            )));
        }
    }
    cx.emit(node);
    cx.emit(
        Node::new("String and template tables")
            .span(span.sub(ChunkHeader::SIZE, RECORDS_START.saturating_sub(ChunkHeader::SIZE)))
            .desc("64 string offsets and 32 template offsets used by Binary XML"),
    );
    let end = u64::from(header.free_offset).clamp(RECORDS_START, CHUNK);
    let records = span.sub(RECORDS_START, end.saturating_sub(RECORDS_START));
    let data = cx.read_avail(records).await?;
    let mut crc_node = Node::new("Event records checksum")
        .span(records)
        .value(hex(header.records_crc, 32));
    crc_node = if to_u64(data.len()) == records.len && crc32(&data) == header.records_crc {
        crc_node.summary("valid")
    } else if to_u64(data.len()) < records.len {
        crc_node.diag(Diagnostic::truncated(records, to_u64(data.len())))
    } else {
        crc_node.diag(Diagnostic::warning(format!(
            "mismatch: computed {:#010x}",
            crc32(&data)
        )))
    };
    cx.emit(crc_node);

    let mut cur = Cursor::new(&cx, records, LE);
    while cur.remaining() >= RecordHeader::SIZE {
        let start = cur.pos();
        let (rec, _) = cur.record::<RecordHeader>().await?;
        if rec.signature != b"**\0\0" {
            cx.diag(Diagnostic::malformed("expected an event record").at(records.sub(start, 4)));
            break;
        }
        if rec.size < 28 {
            cx.diag(Diagnostic::malformed("event record too small").at(records.sub(start, 8)));
            break;
        }
        cur.seek(start.saturating_add(rec.size.into()));
        let rspan = records.sub(start, rec.size.into());
        cx.push(
            Node::new(format!("Record {}", rec.id))
                .span(rspan)
                .value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(rec.written),
                })
                .summary(format!("{} bytes", rec.size))
                .lazy(record, rspan),
        )
        .await;
    }
    Ok(())
}

async fn record(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    RecordHeader::read(&mut f)?;
    let body = span.sub(RecordHeader::SIZE, span.len.saturating_sub(RecordHeader::SIZE.saturating_add(4)));
    cx.emit(
        Node::new("Event (Binary XML)")
            .span(body)
            .summary(format!("{} bytes", body.len))
            .desc("The event as Binary XML (not decoded)"),
    );
    f.seek(span.len.saturating_sub(4));
    let copy = f.u32("Size copy").emit()?;
    if u64::from(copy) != span.len {
        cx.diag(Diagnostic::malformed("size copy differs from size"));
    }
    Ok(())
}
