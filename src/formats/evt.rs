//! Legacy Windows event logs (`.evt`, NT to XP/2003).
//!
//! A 48-byte header is followed by `EVENTLOGRECORD`s, each framed by its
//! length at both ends and tagged `LfLe`. The log is a ring buffer; records
//! are listed from the start of the file up to the end-of-file record.

use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::datakit::clip;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const EOF_MAGIC: [u8; 16] = [
    0x11, 0x11, 0x11, 0x11, 0x22, 0x22, 0x22, 0x22, 0x33, 0x33, 0x33, 0x33, 0x44, 0x44, 0x44, 0x44,
];

pub static FORMAT: Format = Format {
    name: "evt",
    title: "Windows event log (legacy)",
    extensions: &["evt"],
    mime: "application/x-ms-evt",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x30\x00\x00\x00LfLe") && h.at(8, b"\x01\x00\x00\x00\x01\x00\x00\x00")
}

const LOG_FLAGS: FlagTable = &[
    flag(1, "ELF_LOGFILE_HEADER_DIRTY"),
    flag(2, "ELF_LOGFILE_HEADER_WRAP"),
    flag(4, "ELF_LOGFILE_LOGFULL_WRITTEN"),
    flag(8, "ELF_LOGFILE_ARCHIVE_SET"),
];

const EVENT_TYPES: EnumTable = &[
    (0, "EVENTLOG_SUCCESS"),
    (1, "EVENTLOG_ERROR_TYPE"),
    (2, "EVENTLOG_WARNING_TYPE"),
    (4, "EVENTLOG_INFORMATION_TYPE"),
    (8, "EVENTLOG_AUDIT_SUCCESS"),
    (16, "EVENTLOG_AUDIT_FAILURE"),
];

record! {
    pub struct Header {
        size: u32 "HeaderSize",
        signature: ascii[4] "Signature",
        major: u32 "MajorVersion",
        minor: u32 "MinorVersion",
        start: u32 "StartOffset" .hex() .desc("Offset of the oldest record"),
        end: u32 "EndOffset" .hex() .desc("Offset of the end-of-file record"),
        current: u32 "CurrentRecordNumber",
        oldest: u32 "OldestRecordNumber",
        max_size: u32 "MaxSize" .hex(),
        flags: u32 "Flags" .flags(LOG_FLAGS),
        retention: u32 "Retention" .desc("Seconds records are kept"),
        end_size: u32 "EndHeaderSize",
    }
}

record! {
    pub struct EventRecord {
        length: u32 "Length",
        signature: ascii[4] "Reserved",
        number: u32 "RecordNumber",
        generated: u32 "TimeGenerated" .timestamp(),
        written: u32 "TimeWritten" .timestamp(),
        event_id: u32 "EventID" .hex() .with(|&id, n| n.summary(format!("event {}", id & 0xffff))),
        event_type: u16 "EventType" .enumeration(EVENT_TYPES),
        strings: u16 "NumStrings",
        category: u16 "EventCategory",
        _flags: u16 "ReservedFlags",
        closing: u32 "ClosingRecordNumber",
        string_offset: u32 "StringOffset" .hex(),
        sid_length: u32 "UserSidLength",
        sid_offset: u32 "UserSidOffset" .hex(),
        data_length: u32 "DataLength",
        data_offset: u32 "DataOffset" .hex(),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let header = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let mut summary = format!(
        "Windows event log (legacy) {}.{}, records {}–{}",
        header.major,
        header.minor,
        header.oldest,
        header.current.saturating_sub(1)
    );
    if header.flags & 2 != 0 {
        summary.push_str(", wrapped");
    }
    cx.annotate(summary);

    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(Header::SIZE);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let head = cur.peek(0x38).await?;
        let length = crate::bytes::u32_le(&head, 0).unwrap_or(0);
        if head.get(4..20) == Some(EOF_MAGIC.as_slice()) {
            let span = file.sub(start, length.into());
            cx.emit(
                Node::new("End-of-file record")
                    .span(span)
                    .lazy(eof_record, span),
            );
            break;
        }
        if head.get(4..8) != Some(b"LfLe".as_slice()) || length < 0x38 || !length.is_multiple_of(4) {
            // Slack space of the ring buffer.
            let rest = file.tail(start);
            cx.emit(Node::new("Unused space").span(rest));
            break;
        }
        cur.seek(start.saturating_add(length.into()));
        let span = file.sub(start, length.into());
        let rec = crate::fields::parse(&cx, span.sub(0, EventRecord::SIZE), LE, &(), EventRecord::layout).await?;
        let source = source_name(&cx, span).await.unwrap_or_default();
        let kind = lookup(EVENT_TYPES, rec.event_type.into())
            .unwrap_or("?")
            .trim_start_matches("EVENTLOG_")
            .trim_end_matches("_TYPE");
        cx.push(
            Node::new(format!("Record {}", rec.number))
                .span(span)
                .value(Value::Timestamp {
                    unix_seconds: rec.generated.into(),
                })
                .summary(format!(
                    "{}, event {}, {kind}",
                    clip(&source, 60),
                    rec.event_id & 0xffff
                ))
                .lazy(record, span),
        )
        .await;
    }
    Ok(())
}

async fn source_name(cx: &Cx, span: Span) -> Result<String> {
    let data = cx.read_avail(span.sub(EventRecord::SIZE, 0x200)).await?;
    Ok(crate::text::utf16z(&data, LE).0)
}

fn eof_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("RecordSizeBeginning").emit()?;
    f.bytes("Signature", 16).emit()?;
    f.u32("BeginRecord").hex().emit()?;
    f.u32("EndRecord").hex().emit()?;
    f.u32("CurrentRecordNumber").emit()?;
    f.u32("OldestRecordNumber").emit()?;
    f.u32("RecordSizeEnd").emit()?;
    Ok(())
}

async fn eof_record(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    eof_layout(&mut Fields::emitting(&cx, &block, LE), &())
}

async fn record(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    let rec = EventRecord::read(&mut f)?;
    f.utf16z("SourceName").emit()?;
    f.utf16z("Computername").emit()?;
    if rec.sid_length > 0 {
        f.seek(rec.sid_offset.into());
        f.bytes("UserSid", rec.sid_length.into())
            .with(|b, n| n.value(Value::Text(sid(b))))
            .emit()?;
    }
    if rec.strings > 0 {
        let at = u64::from(rec.string_offset);
        let end = if rec.data_offset > rec.string_offset {
            u64::from(rec.data_offset)
        } else {
            span.len.saturating_sub(4)
        };
        let strings = span.sub(at, end.saturating_sub(at));
        cx.emit(
            Node::new("Strings")
                .span(strings)
                .summary(format!("{}", rec.strings))
                .lazy(strings_list, (strings, rec.strings)),
        );
    }
    if rec.data_length > 0 {
        cx.emit(
            Node::new("Data")
                .span(span.sub(rec.data_offset.into(), rec.data_length.into()))
                .summary(format!("{} bytes", rec.data_length)),
        );
    }
    f.seek(span.len.saturating_sub(4));
    f.u32("Length (trailer)").emit()?;
    Ok(())
}

async fn strings_list(cx: Cx, (span, count): (Span, u16)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    for _ in 0..count {
        if f.remaining() == 0 {
            break;
        }
        if f.utf16z("String").emit().is_err() {
            cx.diag(Diagnostic::malformed("unterminated string"));
            break;
        }
    }
    Ok(())
}

/// A binary SID as `S-1-5-21-...`.
pub fn sid(b: &[u8]) -> String {
    let revision = b.first().copied().unwrap_or(0);
    let count = usize::from(b.get(1).copied().unwrap_or(0));
    let authority = crate::formats::datakit::be_uint(b.get(2..8).unwrap_or_default());
    let mut out = format!("S-{revision}-{authority}");
    for i in 0..count {
        match crate::bytes::u32_le(b, 8usize.saturating_add(i.saturating_mul(4))) {
            Some(v) => out.push_str(&format!("-{v}")),
            None => break,
        }
    }
    out
}
