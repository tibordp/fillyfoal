//! Legacy Windows event logs (`.evt`, NT to XP/2003).
//!
//! A 48-byte header is followed by `EVENTLOGRECORD`s, each framed by its
//! length at both ends and tagged `LfLe`. The log is a ring buffer; records
//! are listed from the oldest (StartOffset), wrapping from the end of the
//! file back to the header, up to the end-of-file record.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::forensics::winsec::sid_node;
use crate::formats::util::datakit::clip;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::{Origin, Span};
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

    // The records form a ring buffer over the rest of the file: the oldest
    // is at StartOffset, and a record that reaches the end of the file
    // continues right after the header. Walk from the oldest record, wrap
    // once, and stop at the end-of-file record or after a full circle.
    let ring = Ring {
        file,
        start: u64::from(header.start),
    };
    let ring = if ring.start >= Header::SIZE && ring.start < file.len {
        ring
    } else {
        Ring {
            file,
            start: Header::SIZE,
        }
    };
    let mut pos = ring.start;
    let mut wrapped = false;
    loop {
        let to_end = file.len.saturating_sub(pos);
        // Space at the end too small for a record header is padding.
        if to_end == 0
            || (to_end < 0x38
                && ring.can_wrap(wrapped)
                && is_padding(&cx.read_avail(file.sub(pos, to_end)).await?))
        {
            if ring.can_wrap(wrapped) {
                wrapped = true;
                pos = Header::SIZE;
                continue;
            }
            break;
        }
        if wrapped && pos >= ring.start {
            break;
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        let head = ring.read(&cx, pos, 0x38, wrapped).await?;
        if head.len() < 8 {
            break;
        }
        let length = crate::bytes::u32_le(&head, 0).unwrap_or(0);
        if head.get(4..20) == Some(EOF_MAGIC.as_slice()) {
            let span = ring.span(&cx, pos, length.into(), wrapped)?;
            cx.emit(
                Node::new("End-of-file record")
                    .span(span)
                    .lazy(eof_record, span),
            );
            // What lies between the end-of-file record and the oldest
            // record is slack: older records, partly overwritten.
            let (end, wraps) = ring.advance(pos, length.into());
            for slack in ring.slack(end, wrapped || wraps) {
                cx.emit(Node::new("Unused space").span(slack));
            }
            break;
        }
        if head.get(4..8) != Some(b"LfLe".as_slice()) || length < 0x38 || !length.is_multiple_of(4)
        {
            // Slack space of the ring buffer.
            for rest in ring.slack(pos, wrapped) {
                cx.emit(Node::new("Unused space").span(rest));
            }
            break;
        }
        let span = ring.span(&cx, pos, length.into(), wrapped)?;
        let (next, wraps) = ring.advance(pos, length.into());
        if wraps {
            if !ring.can_wrap(wrapped) {
                break;
            }
            wrapped = true;
        }
        pos = next;
        let rec = crate::fields::parse(
            &cx,
            span.sub(0, EventRecord::SIZE),
            LE,
            &(),
            EventRecord::layout,
        )
        .await?;
        let source = source_name(&cx, span).await.unwrap_or_default();
        let kind = lookup(EVENT_TYPES, rec.event_type.into())
            .unwrap_or("?")
            .trim_start_matches("EVENTLOG_")
            .trim_end_matches("_TYPE");
        cx.push(
            Node::new(format!("Record {}", rec.number))
                .span(span)
                .value(Value::utc(rec.generated.into()))
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

/// The ring buffer of records: from the end of the header to the end of
/// the file, the oldest record at `start`.
#[derive(Clone, Copy)]
struct Ring {
    file: Span,
    start: u64,
}

impl Ring {
    /// Whether the walk may still go from the end of the file back to the
    /// header: once, and only if the oldest record is not the first.
    fn can_wrap(&self, wrapped: bool) -> bool {
        !wrapped && self.start > Header::SIZE
    }

    /// The position `len` bytes after `pos`, and whether it wrapped.
    fn advance(&self, pos: u64, len: u64) -> (u64, bool) {
        let end = pos.saturating_add(len);
        match end.checked_sub(self.file.len) {
            Some(over) if over > 0 => (Header::SIZE.saturating_add(over), true),
            _ => (end, false),
        }
    }

    /// The unused part of the ring from `pos` (where the walk stopped) up
    /// to the oldest record: just before it if the walk has wrapped, else
    /// to the end of the file and from the header to the oldest record.
    fn slack(&self, pos: u64, wrapped: bool) -> Vec<Span> {
        let file = self.file;
        let pieces = if wrapped {
            vec![file.sub(pos, self.start.saturating_sub(pos))]
        } else {
            vec![
                file.tail(pos),
                file.sub(Header::SIZE, self.start.saturating_sub(Header::SIZE)),
            ]
        };
        pieces.into_iter().filter(|s| s.len > 0).collect()
    }

    /// The two pieces of `len` bytes at `pos`, if they wrap.
    fn pieces(&self, pos: u64, len: u64, wrapped: bool) -> Option<(Span, Span)> {
        let to_end = self.file.len.saturating_sub(pos);
        (len > to_end && self.can_wrap(wrapped)).then(|| {
            (
                self.file.sub(pos, to_end),
                self.file.sub(Header::SIZE, len.saturating_sub(to_end)),
            )
        })
    }

    async fn read(&self, cx: &Cx, pos: u64, len: u64, wrapped: bool) -> Result<Vec<u8>> {
        match self.pieces(pos, len, wrapped) {
            Some((a, b)) => {
                let mut data = cx.read_avail(a).await?;
                data.extend(cx.read_avail(b).await?);
                Ok(data)
            }
            None => cx.read_avail(self.file.sub(pos, len)).await,
        }
    }

    /// The span of `len` bytes at `pos`: a joined source for a record split
    /// across the end of the file.
    fn span(&self, cx: &Cx, pos: u64, len: u64, wrapped: bool) -> Result<Span> {
        match self.pieces(pos, len, wrapped) {
            Some((a, b)) => cx.add_pieces(
                Origin {
                    parent: a,
                    transform: "evt-ring",
                },
                vec![a, b],
            ),
            None => Ok(self.file.sub(pos, len)),
        }
    }
}

/// Unused space at the end of the file: `0x00000027` words or zeros.
fn is_padding(data: &[u8]) -> bool {
    data.chunks(4)
        .all(|w| [0x27, 0, 0, 0].starts_with(w) || w.iter().all(|&b| b == 0))
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
        let span = f.peek_span(rec.sid_length.into());
        let b = f.bytes("UserSid", rec.sid_length.into()).get()?;
        f.node(sid_node("UserSid", span, &b));
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
        cx.checkpoint().await;
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
