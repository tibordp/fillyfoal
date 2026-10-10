//! Windows Event Trace Logs (`.etl`), as written by ETW sessions (`xperf`,
//! `wpr`, `logman`, `tracelog`, Windows' own autologgers).
//!
//! A log is a sequence of buffers, each `BufferSize` bytes and starting
//! with a 72-byte `WMI_BUFFER_HEADER` (sizes and offsets of the data in
//! use, a timestamp, sequence number, clock type, the processor and logger
//! in `ClientContext`, state, flags and type, and a reference clock). The
//! events follow, 8-byte aligned, up to `SavedOffset`; the rest is `0xFF`
//! filler. The first event of the first buffer is the log's header: a
//! system event (group `EventTrace`, type 0) whose payload is a
//! `TRACE_LOGFILE_HEADER` (buffer size, versions, processor count, start
//! and end times, timer resolution, file mode, pointer size, events and
//! buffers lost, time zone, boot time, performance counter frequency and
//! clock type) followed by the logger and log file names.
//!
//! Events start with one of several headers, told apart by the header type
//! in their third byte: `SYSTEM_TRACE_HEADER` (kernel events: hook ID =
//! group and type, thread and process, timestamp, CPU times; also a compact
//! form without CPU times), `PERFINFO_TRACE_HEADER` (hook ID and timestamp
//! only), `EVENT_HEADER` (manifest and TraceLogging events: provider GUID,
//! event descriptor, thread, process, timestamp, activity ID, then extended
//! data items when flagged), and the classic `EVENT_TRACE_HEADER` and
//! `EVENT_INSTANCE_HEADER` of MOF events. User data follows the header and
//! is shown as bytes, except for TraceLogging events: their schema
//! (extended item type 11) is decoded into the event name and fields, and
//! simple field values are decoded from the user data. Timestamps in
//! performance-counter or CPU-cycle units are converted with the header's
//! frequency, relative to its start time and the header event's own
//! timestamp.
//!
//! Sources: the field layouts of `TRACE_LOGFILE_HEADER`, `EVENT_HEADER`,
//! `EVENT_DESCRIPTOR`, `EVENT_TRACE_HEADER`, `EVENT_INSTANCE_HEADER` and
//! `TIME_ZONE_INFORMATION` are those of Microsoft's public headers
//! (`evntrace.h`, `evntcons.h`, `evntprov.h`), and the TraceLogging schema
//! encoding that of `TraceLoggingProvider.h`. `WMI_BUFFER_HEADER`, the
//! in-file forms of the system, perfinfo and compact headers, the header
//! type and marker byte values, the extended data item framing in the file
//! (`Reserved1`, `ExtType`, linkage, `DataSize`, then data padded to 8
//! bytes), buffer types/flags/states and the kernel group and event type
//! names are from memory of documented ETL parsing knowledge (`ntwmi.h`
//! as reproduced by public ETL parsers), not checked against a real log:
//! there is no ETL writer on macOS, and the fixture is our own encoding of
//! these layouts. Compressed buffers (Windows 8 and later) are reported,
//! not decoded. WPP (`MESSAGE_TRACE_HEADER`) and other rare header types
//! stop the walk of their buffer with an `Unsupported` note.

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::datakit::guid_le;
use crate::formats::util::datakit::{hex, text, uint};
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BUFFER_HEADER: u64 = 0x48;

const HEADER_TYPES: EnumTable = &[
    (0x01, "SYSTEM32"),
    (0x02, "SYSTEM64"),
    (0x03, "COMPACT32"),
    (0x04, "COMPACT64"),
    (0x0a, "FULL_HEADER32"),
    (0x0b, "INSTANCE32"),
    (0x0c, "TIMED"),
    (0x0d, "ERROR"),
    (0x0e, "WNODE_HEADER"),
    (0x0f, "MESSAGE"),
    (0x10, "PERFINFO32"),
    (0x11, "PERFINFO64"),
    (0x12, "EVENT_HEADER32"),
    (0x13, "EVENT_HEADER64"),
    (0x14, "FULL_HEADER64"),
    (0x15, "INSTANCE64"),
];

const MARKER_FLAGS: FlagTable = &[
    flag(0x80, "TRACE_HEADER_FLAG"),
    flag(0x40, "TRACE_HEADER_EVENT_TRACE"),
    flag(0x20, "TRACE_HEADER_PROCESSOR_INDEX"),
    flag(0x10, "TRACE_MESSAGE"),
];

const BUFFER_TYPES: EnumTable = &[
    (0, "Generic"),
    (1, "Rundown"),
    (2, "Context swap"),
    (3, "Reference time"),
    (4, "Header"),
    (5, "Batched"),
    (6, "Empty marker"),
    (7, "Debug info"),
];

const BUFFER_FLAGS: FlagTable = &[
    flag(0x0001, "FLUSH_MARKER"),
    flag(0x0002, "EVENTS_LOST"),
    flag(0x0004, "BUFFER_LOST"),
    flag(0x0008, "RTBACKUP_CORRUPT"),
    flag(0x0010, "RTBACKUP"),
    flag(0x0020, "PROC_INDEX"),
    flag(0x0040, "COMPRESSED"),
];

const BUFFER_STATES: EnumTable = &[
    (0, "Free"),
    (1, "General logging"),
    (2, "Context switch"),
    (3, "Flush"),
];

const CLOCK_TYPES: EnumTable = &[
    (1, "Performance counter"),
    (2, "System time"),
    (3, "CPU cycle counter"),
];

const LOG_FILE_MODE: FlagTable = &[
    flag(0x0000_0001, "FILE_MODE_SEQUENTIAL"),
    flag(0x0000_0002, "FILE_MODE_CIRCULAR"),
    flag(0x0000_0004, "FILE_MODE_APPEND"),
    flag(0x0000_0008, "FILE_MODE_NEWFILE"),
    flag(0x0000_0020, "FILE_MODE_PREALLOCATE"),
    flag(0x0000_0040, "NONSTOPPABLE_MODE"),
    flag(0x0000_0080, "SECURE_MODE"),
    flag(0x0000_0100, "REAL_TIME_MODE"),
    flag(0x0000_0200, "DELAY_OPEN_FILE_MODE"),
    flag(0x0000_0400, "BUFFERING_MODE"),
    flag(0x0000_0800, "PRIVATE_LOGGER_MODE"),
    flag(0x0000_1000, "ADD_HEADER_MODE"),
    flag(0x0000_2000, "USE_KBYTES_FOR_SIZE"),
    flag(0x0000_4000, "USE_GLOBAL_SEQUENCE"),
    flag(0x0000_8000, "USE_LOCAL_SEQUENCE"),
    flag(0x0001_0000, "RELOG_MODE"),
    flag(0x0002_0000, "PRIVATE_IN_PROC"),
    flag(0x0040_0000, "STOP_ON_HYBRID_SHUTDOWN"),
    flag(0x0080_0000, "PERSIST_ON_HYBRID_SHUTDOWN"),
    flag(0x0200_0000, "SYSTEM_LOGGER_MODE"),
    flag(0x0400_0000, "COMPRESSED_MODE"),
    flag(0x0800_0000, "INDEPENDENT_SESSION_MODE"),
    flag(0x1000_0000, "NO_PER_PROCESSOR_BUFFERING"),
    flag(0x8000_0000, "ADDTO_TRIAGE"),
];

const EVENT_HEADER_FLAGS: FlagTable = &[
    flag(0x0001, "EXTENDED_INFO"),
    flag(0x0002, "PRIVATE_SESSION"),
    flag(0x0004, "STRING_ONLY"),
    flag(0x0008, "TRACE_MESSAGE"),
    flag(0x0010, "NO_CPUTIME"),
    flag(0x0020, "32_BIT_HEADER"),
    flag(0x0040, "64_BIT_HEADER"),
    flag(0x0080, "DECODE_GUID"),
    flag(0x0100, "CLASSIC_HEADER"),
    flag(0x0200, "PROCESSOR_INDEX"),
];

const EVENT_PROPERTIES: FlagTable = &[
    flag(0x0001, "XML"),
    flag(0x0002, "FORWARDED_XML"),
    flag(0x0004, "LEGACY_EVENTLOG"),
    flag(0x0008, "RELOGGABLE"),
];

const LEVELS: EnumTable = &[
    (0, "Log always"),
    (1, "Critical"),
    (2, "Error"),
    (3, "Warning"),
    (4, "Information"),
    (5, "Verbose"),
];

const EXT_TYPES: EnumTable = &[
    (1, "RELATED_ACTIVITYID"),
    (2, "SID"),
    (3, "TS_ID"),
    (4, "INSTANCE_INFO"),
    (5, "STACK_TRACE32"),
    (6, "STACK_TRACE64"),
    (7, "PEBS_INDEX"),
    (8, "PMC_COUNTERS"),
    (9, "PSM_KEY"),
    (10, "EVENT_KEY"),
    (11, "EVENT_SCHEMA_TL"),
    (12, "PROV_TRAITS"),
    (13, "PROCESS_START_KEY"),
    (14, "CONTROL_GUID"),
    (15, "QPC_DELTA"),
    (16, "CONTAINER_ID"),
    (17, "STACK_KEY32"),
    (18, "STACK_KEY64"),
];

/// Kernel event groups (high byte of the hook ID).
const GROUPS: EnumTable = &[
    (0x00, "EventTrace"),
    (0x01, "DiskIo"),
    (0x02, "PageFault"),
    (0x03, "Process"),
    (0x04, "FileIo"),
    (0x05, "Thread"),
    (0x06, "TcpIp"),
    (0x07, "Job"),
    (0x08, "UdpIp"),
    (0x09, "Registry"),
    (0x0a, "DbgPrint"),
    (0x0b, "Config"),
    (0x0d, "Wnf"),
    (0x0e, "Pool"),
    (0x0f, "PerfInfo"),
    (0x10, "Heap"),
    (0x11, "Object"),
    (0x12, "Power"),
    (0x13, "Modbound"),
    (0x14, "Image"),
    (0x15, "Dpc"),
    (0x16, "CacheManager"),
    (0x17, "CritSec"),
    (0x18, "StackWalk"),
    (0x19, "Ums"),
    (0x1a, "ALPC"),
    (0x1b, "SplitIo"),
    (0x1c, "ThreadPool"),
    (0x1d, "Hypervisor"),
    (0x1e, "HypervisorX"),
];

/// Kernel event types by hook ID (group << 8 | type).
const HOOKS: EnumTable = &[
    (0x0000, "Header"),
    (0x0301, "Start"),
    (0x0302, "End"),
    (0x0303, "DCStart"),
    (0x0304, "DCEnd"),
    (0x0327, "Defunct"),
    (0x0501, "Start"),
    (0x0502, "End"),
    (0x0503, "DCStart"),
    (0x0504, "DCEnd"),
    (0x0524, "CSwitch"),
    (0x0532, "ReadyThread"),
    (0x010a, "Read"),
    (0x010b, "Write"),
    (0x010c, "ReadInit"),
    (0x010d, "WriteInit"),
    (0x010e, "FlushBuffers"),
    (0x1402, "Unload"),
    (0x1403, "DCStart"),
    (0x1404, "DCEnd"),
    (0x140a, "Load"),
    (0x0f2e, "SampleProf"),
    (0x0f33, "SysClEnter"),
    (0x0f34, "SysClExit"),
    (0x0f43, "ISR"),
    (0x0f44, "DPC"),
    (0x060a, "Send"),
    (0x060b, "Recv"),
    (0x060c, "Connect"),
    (0x060d, "Disconnect"),
];

/// TraceLogging field input types (`TlgIn_t`).
const TL_IN_TYPES: EnumTable = &[
    (0, "NULL"),
    (1, "UNICODESTRING"),
    (2, "ANSISTRING"),
    (3, "INT8"),
    (4, "UINT8"),
    (5, "INT16"),
    (6, "UINT16"),
    (7, "INT32"),
    (8, "UINT32"),
    (9, "INT64"),
    (10, "UINT64"),
    (11, "FLOAT"),
    (12, "DOUBLE"),
    (13, "BOOL32"),
    (14, "BINARY"),
    (15, "GUID"),
    (16, "POINTER"),
    (17, "FILETIME"),
    (18, "SYSTEMTIME"),
    (19, "SID"),
    (20, "HEXINT32"),
    (21, "HEXINT64"),
    (22, "COUNTEDSTRING"),
    (23, "COUNTEDANSISTRING"),
    (24, "STRUCT"),
    (25, "COUNTEDBINARY"),
];

// ---------------------------------------------------------------------------
// Probe

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(size), Some(saved)) = (u32_le(d, 0), u32_le(d, 4)) else {
        return false;
    };
    let size = u64::from(size);
    let saved = u64::from(saved);
    // A sane buffer size, used space within it.
    if !(0x400..=0x0100_0000).contains(&size)
        || !size.is_multiple_of(8)
        || saved > size
        || saved < BUFFER_HEADER.saturating_add(0x20)
    {
        return false;
    }
    // The first event is a system header (32- or 64-bit) of the EventTrace
    // group, type 0 (the logfile header), whose payload repeats the buffer
    // size.
    let first = usize::try_from(BUFFER_HEADER).unwrap_or(0);
    let at = |o: usize| first.saturating_add(o);
    matches!(d.get(at(2)), Some(1 | 2))
        && d.get(at(3)).is_some_and(|f| f & 0xc0 == 0xc0)
        && u16_le(d, at(6)) == Some(0)
        && u16_le(d, at(4)).is_some_and(|s| {
            u64::from(s) >= 0x130 && u64::from(s) <= saved.saturating_sub(BUFFER_HEADER)
        })
        && u32_le(d, at(0x20)).is_some_and(|b| u64::from(b) == size)
}

declare_format!(pub FORMAT = "etl", "Windows Event Trace Log", ["etl"], "application/x-ms-etl",
    Probe::Custom(probe), dissect);

// ---------------------------------------------------------------------------
// Logfile header

/// What later events need from the logfile header.
#[derive(Clone, Copy, Debug, Default, PartialEq)]
struct Clock {
    pointer: u8,
    kind: u32,
    frequency: u64,
    start: u64,
    /// The header event's timestamp, taken at `start`.
    reference: u64,
}

impl Clock {
    /// A raw event timestamp as Unix seconds, if it can be converted.
    fn unix(&self, raw: u64) -> Option<i64> {
        let filetime = match self.kind {
            2 => raw,
            1 | 3 if self.frequency > 0 && self.start > 0 => {
                let delta = i128::from(raw).saturating_sub(i128::from(self.reference));
                let ticks = delta
                    .saturating_mul(10_000_000)
                    .checked_div(i128::from(self.frequency))?;
                u64::try_from(i128::from(self.start).saturating_add(ticks)).ok()?
            }
            _ => return None,
        };
        (filetime > 0).then(|| crate::text::filetime_to_unix(filetime))
    }
}

#[derive(Clone, Debug, Default)]
struct Logfile {
    buffer_size: u32,
    version: u32,
    build: u32,
    processors: u32,
    events_lost: u32,
    buffers_lost: u32,
    buffers_written: u32,
    clock: Clock,
    logger: String,
}

fn logfile_layout(f: &mut Fields<'_>, pointer: &u8) -> Result<Logfile> {
    let wide = *pointer == 8;
    let mut l = Logfile {
        buffer_size: f.u32("BufferSize").hex().emit()?,
        ..Logfile::default()
    };
    l.version = f
        .u32("Version")
        .hex()
        .with(|&v, n| {
            let b = v.to_le_bytes();
            n.summary(format!("{}.{}.{}.{}", b[0], b[1], b[2], b[3]))
        })
        .emit()?;
    l.build = f
        .u32("ProviderVersion")
        .desc("Windows build number")
        .emit()?;
    l.processors = f.u32("NumberOfProcessors").emit()?;
    f.u64("EndTime").filetime().emit()?;
    f.u32("TimerResolution")
        .desc("In 100-nanosecond units")
        .emit()?;
    f.u32("MaximumFileSize")
        .desc("In megabytes (or kilobytes with USE_KBYTES_FOR_SIZE)")
        .emit()?;
    f.u32("LogFileMode").flags(LOG_FILE_MODE).emit()?;
    l.buffers_written = f.u32("BuffersWritten").emit()?;
    f.u32("StartBuffers").emit()?;
    let declared = f.u32("PointerSize").emit()?;
    l.events_lost = f.u32("EventsLost").emit()?;
    let mhz = f.u32("CpuSpeedInMHz").emit()?;
    f.uword("LoggerName", wide)
        .hex()
        .desc("Pointer in the logging process")
        .emit()?;
    f.uword("LogFileName", wide)
        .hex()
        .desc("Pointer in the logging process")
        .emit()?;
    let tz = f.pos();
    f.node(struct_node("TimeZone", f.peek_span(172), LE, (), time_zone));
    f.seek(tz.saturating_add(172).next_multiple_of(8));
    f.u64("BootTime").filetime().emit()?;
    let frequency = f.u64("PerfFreq").emit()?;
    l.clock.start = f.u64("StartTime").filetime().emit()?;
    l.clock.kind = f
        .u32("ReservedFlags")
        .enumeration(CLOCK_TYPES)
        .desc("Clock type")
        .emit()?;
    l.buffers_lost = f.u32("BuffersLost").emit()?;
    l.clock.frequency = if l.clock.kind == 3 {
        u64::from(mhz).saturating_mul(1_000_000)
    } else {
        frequency
    };
    l.clock.pointer = if matches!(declared, 4 | 8) {
        u8::try_from(declared).unwrap_or(8)
    } else {
        *pointer
    };
    if f.remaining() > 0 {
        l.logger = f.utf16z("Logger name").emit().unwrap_or_default();
        if f.remaining() > 0 {
            f.utf16z("Log file name").emit().ok();
        }
    }
    Ok(l)
}

fn system_time(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let span = f.peek_span(16);
    let b = f.bytes(name, 16).get()?;
    let w = |i: usize| u16_le(&b, i).unwrap_or(0);
    let node = Node::new(name).span(span);
    f.node(if b.iter().all(|&x| x == 0) {
        node.summary("not set")
    } else if w(0) == 0 {
        // Transition rule: month, week of the month, day of the week.
        node.summary(format!(
            "month {}, week {}, weekday {}, {:02}:{:02}",
            w(2),
            w(8),
            w(4),
            w(10),
            w(12)
        ))
    } else {
        node.summary(format!(
            "{:04}-{:02}-{:02} {:02}:{:02}:{:02}",
            w(0),
            w(2),
            w(6),
            w(8),
            w(10),
            w(12)
        ))
    });
    Ok(())
}

fn time_zone(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.i32("Bias")
        .desc("Minutes; UTC = local time + bias")
        .emit()?;
    f.utf16("StandardName", 32).emit()?;
    system_time(f, "StandardDate")?;
    f.i32("StandardBias").emit()?;
    f.utf16("DaylightName", 32).emit()?;
    system_time(f, "DaylightDate")?;
    f.i32("DaylightBias").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Buffers

fn buffer_layout(f: &mut Fields<'_>, _: &()) -> Result<u32> {
    let size = f.u32("BufferSize").hex().emit()?;
    f.u32("SavedOffset")
        .hex()
        .desc("End of the data in use")
        .emit()?;
    f.u32("CurrentOffset").hex().emit()?;
    f.i32("ReferenceCount").emit()?;
    f.u64("TimeStamp")
        .desc("When the buffer was flushed, in clock units")
        .emit()?;
    f.u64("SequenceNumber").emit()?;
    f.u64("ClockType/Frequency")
        .hex()
        .with(|&v, n| n.summary(format!("clock type {}, frequency {}", v & 7, v >> 3)))
        .emit()?;
    f.u8("ProcessorNumber").emit()?;
    f.u8("Alignment").emit()?;
    f.u16("LoggerId").emit()?;
    f.u32("State").enumeration(BUFFER_STATES).emit()?;
    f.u32("Offset").hex().emit()?;
    f.u16("BufferFlag").flags(BUFFER_FLAGS).emit()?;
    f.u16("BufferType").enumeration(BUFFER_TYPES).emit()?;
    f.u64("ReferenceTime.StartTime").filetime().emit()?;
    f.u64("ReferenceTime.StartPerfClock").emit()?;
    Ok(size)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx
        .read(file.sub(0, BUFFER_HEADER.saturating_add(0x20)))
        .await?;
    let size = u64::from(u32_le(&head, 0).unwrap_or(0));
    if size < BUFFER_HEADER.saturating_add(0x20) {
        return Err(Diagnostic::malformed("buffer size too small").at(file.sub(0, 4)));
    }
    let header_type = head.get(0x4a).copied().unwrap_or(2);
    let event_size = u64::from(u16_le(&head, 0x4c).unwrap_or(0));
    let reference = u64_le(&head, 0x58).unwrap_or(0);
    let pointer = if header_type == 1 { 4 } else { 8 };
    let lf_span = file.sub(
        BUFFER_HEADER.saturating_add(0x20),
        event_size.saturating_sub(0x20),
    );
    let mut lf = parse(&cx, lf_span, LE, &pointer, logfile_layout).await?;
    lf.clock.reference = reference;
    let b = lf.version.to_le_bytes();
    let mut summary = format!(
        "Event trace log, version {}.{}, build {}, {} processor{}",
        b[0],
        b[1],
        lf.build,
        lf.processors,
        if lf.processors == 1 { "" } else { "s" }
    );
    if !lf.logger.is_empty() {
        summary = format!("{summary}, logger \"{}\"", lf.logger);
    }
    let buffers = file.len.div_ceil(size);
    summary = format!(
        "{summary}, {buffers} buffer{} of {size:#x} bytes",
        if buffers == 1 { "" } else { "s" }
    );
    if lf.events_lost > 0 {
        summary = format!("{summary}, {} events lost", lf.events_lost);
    }
    cx.annotate(summary);
    let mut node = struct_node("Logfile header", lf_span, LE, pointer, logfile_layout);
    if lf.clock.start > 0 {
        node = node.value(Value::Timestamp {
            unix_seconds: crate::text::filetime_to_unix(lf.clock.start),
        });
    }
    if u64::from(lf.buffer_size) != size {
        node = node.diag(Diagnostic::warning(format!(
            "BufferSize {:#x} differs from the first buffer's {size:#x}",
            lf.buffer_size
        )));
    }
    cx.emit(node.desc("TRACE_LOGFILE_HEADER, the payload of the first event"));
    if lf.buffers_lost > 0 {
        cx.emit(Node::new("Buffers lost").value(uint(lf.buffers_lost, 32)));
    }
    cx.emit(
        Node::new("Buffers")
            .span(file)
            .summary(format!("{} written", lf.buffers_written))
            .lazy(walk_buffers, (input, lf.clock)),
    );
    Ok(())
}

async fn walk_buffers(cx: Cx, (input, clock): (Input, Clock)) -> Result<()> {
    let file = input.span;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < file.len {
        let at = (pos, index);
        cx.mark(move || at);
        cx.progress_in(file, file.offset.saturating_add(pos));
        let head = cx.read(file.sub(pos, BUFFER_HEADER)).await?;
        let size = u64::from(u32_le(&head, 0).unwrap_or(0));
        let mut node = Node::new(format!("Buffer {index}"));
        if !(BUFFER_HEADER..=0x0100_0000).contains(&size) {
            cx.push(
                node.span(file.sub(pos, BUFFER_HEADER))
                    .diag(Diagnostic::malformed(format!("bad buffer size {size:#x}"))),
            )
            .await;
            break;
        }
        let span = file.sub(pos, size);
        let saved = u64::from(u32_le(&head, 4).unwrap_or(0));
        let cpu = head.get(0x28).copied().unwrap_or(0);
        let flags = u16_le(&head, 0x34).unwrap_or(0);
        let kind = u16_le(&head, 0x36).unwrap_or(0);
        let mut parts = vec![format!("CPU {cpu}")];
        if let Some(t) = lookup(BUFFER_TYPES, kind.into()) {
            parts.push(t.to_owned());
        }
        parts.push(format!("{saved:#x} bytes used"));
        if flags & 0x40 != 0 {
            parts.push("compressed".to_owned());
        }
        if flags & 0x02 != 0 {
            parts.push("events lost".to_owned());
        }
        node = node
            .span(span)
            .summary(parts.join(", "))
            .lazy(walk_buffer, (input, pos, clock, index == 0));
        if span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        cx.push(node).await;
        index = index.saturating_add(1);
        pos = pos.saturating_add(size);
    }
    cx.set_count(Count::Exact(index));
    Ok(())
}

// ---------------------------------------------------------------------------
// Events

/// The parts of an event header the walker needs.
#[derive(Clone, Copy, Debug)]
struct EventHead {
    header_type: u8,
    size: u64,
    header_len: u64,
    timestamp: u64,
    pid: Option<u32>,
    tid: Option<u32>,
    hook: Option<u16>,
}

fn event_head(d: &[u8]) -> Option<EventHead> {
    let header_type = *d.get(2)?;
    let marker = *d.get(3)?;
    if marker & 0x80 == 0 {
        return None;
    }
    let u16_at = |o| u16_le(d, o);
    let u32_at = |o| u32_le(d, o);
    let u64_at = |o| u64_le(d, o);
    Some(match header_type {
        0x01..=0x04 => EventHead {
            header_type,
            size: u64::from(u16_at(4)?),
            header_len: if header_type <= 2 { 0x20 } else { 0x18 },
            timestamp: u64_at(0x10)?,
            tid: u32_at(8),
            pid: u32_at(12),
            hook: u16_at(6),
        },
        0x10 | 0x11 => EventHead {
            header_type,
            size: u64::from(u16_at(4)?),
            header_len: 0x10,
            timestamp: u64_at(8)?,
            tid: None,
            pid: None,
            hook: u16_at(6),
        },
        0x12 | 0x13 => EventHead {
            header_type,
            size: u64::from(u16_at(0)?),
            header_len: 0x50,
            timestamp: u64_at(16)?,
            tid: u32_at(8),
            pid: u32_at(12),
            hook: None,
        },
        0x0a | 0x14 => EventHead {
            header_type,
            size: u64::from(u16_at(0)?),
            header_len: 0x30,
            timestamp: u64_at(16)?,
            tid: u32_at(8),
            pid: u32_at(12),
            hook: None,
        },
        0x0b | 0x15 => EventHead {
            header_type,
            size: u64::from(u16_at(0)?),
            header_len: 0x38,
            timestamp: u64_at(16)?,
            tid: u32_at(8),
            pid: u32_at(12),
            hook: None,
        },
        _ => return None,
    })
}

fn hook_name(hook: u16) -> String {
    let group = lookup(GROUPS, u64::from(hook >> 8));
    let kind = lookup(HOOKS, u64::from(hook));
    match (group, kind) {
        (Some(g), Some(k)) => format!("{g}/{k}"),
        (Some(g), None) => format!("{g}/type {}", hook & 0xff),
        _ => format!("Hook {hook:#06x}"),
    }
}

async fn walk_buffer(cx: Cx, (input, pos, clock, first): (Input, u64, Clock, bool)) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(pos, BUFFER_HEADER)).await?;
    let size = u64::from(u32_le(&head, 0).unwrap_or(0));
    let span = file.sub(pos, size);
    let saved =
        u64::from(u32_le(&head, 4).unwrap_or(0)).clamp(BUFFER_HEADER, size.max(BUFFER_HEADER));
    let flags = u16_le(&head, 0x34).unwrap_or(0);
    let (mut at, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    if at == 0 {
        cx.mark(|| (0u64, 0u64));
        cx.push(struct_node(
            "Buffer header",
            span.sub(0, BUFFER_HEADER),
            LE,
            (),
            buffer_layout,
        ))
        .await;
        if flags & 0x40 != 0 {
            cx.push(
                Node::new("Compressed data")
                    .span(span.sub(BUFFER_HEADER, saved.saturating_sub(BUFFER_HEADER)))
                    .diag(Diagnostic::unsupported("compressed ETW buffer")),
            )
            .await;
            cx.set_count(Count::Exact(2));
            return Ok(());
        }
        at = BUFFER_HEADER;
    }
    while at.saturating_add(8) <= saved {
        let mark = (at, index);
        cx.mark(move || mark);
        cx.progress_in(span, span.offset.saturating_add(at));
        let d = cx.read(span.sub(at, 0x18)).await?;
        if d.len() < 8 || u32_le(&d, 0) == Some(0xffff_ffff) || u32_le(&d, 0) == Some(0) {
            break;
        }
        let Some(h) = event_head(&d) else {
            cx.push(
                Node::new("Unknown event header")
                    .span(span.sub(at, saved.saturating_sub(at)))
                    .value(hex(d.get(2).copied().unwrap_or(0), 8))
                    .diag(Diagnostic::unsupported(format!(
                        "header type {:#04x}",
                        d.get(2).copied().unwrap_or(0)
                    ))),
            )
            .await;
            index = index.saturating_add(1);
            break;
        };
        if h.size < h.header_len {
            cx.push(
                Node::new("Event")
                    .span(span.sub(at, 8))
                    .diag(Diagnostic::malformed(format!(
                        "event size {:#x} below its header",
                        h.size
                    ))),
            )
            .await;
            index = index.saturating_add(1);
            break;
        }
        let espan = span.sub(at, h.size);
        let node = event_node(&cx, espan, &h, clock, first && at == BUFFER_HEADER).await?;
        cx.push(node).await;
        index = index.saturating_add(1);
        at = at.saturating_add(h.size).next_multiple_of(8);
    }
    cx.set_count(Count::Exact(index.saturating_add(1)));
    Ok(())
}

async fn event_node(
    cx: &Cx,
    span: Span,
    h: &EventHead,
    clock: Clock,
    logfile: bool,
) -> Result<Node> {
    let mut name = match h.hook {
        Some(hook) => hook_name(hook),
        None => "Event".to_owned(),
    };
    let mut parts = Vec::new();
    match h.header_type {
        0x12 | 0x13 => {
            let d = cx.read(span.sub(0, 0x50)).await?;
            let id = u16_le(&d, 40).unwrap_or(0);
            let provider = guid_le(d.get(24..40).unwrap_or_default());
            let flags = u16_le(&d, 4).unwrap_or(0);
            name = format!("Event {id}");
            if flags & 1 != 0 {
                let ext = read_ext(cx, span, h).await?;
                if let Some(tl) = ext
                    .iter()
                    .find(|e| e.kind == 11)
                    .and_then(|e| tl_schema(&e.data))
                {
                    name = tl.name;
                }
                if let Some(p) = ext
                    .iter()
                    .find(|e| e.kind == 12)
                    .and_then(|e| provider_name(&e.data))
                {
                    parts.push(p);
                } else {
                    parts.push(format!("{provider}"));
                }
            } else {
                parts.push(format!("{provider}"));
            }
            if let Some(level) = d.get(44).and_then(|&l| lookup(LEVELS, l.into())) {
                parts.push(level.to_owned());
            }
        }
        0x0a | 0x14 | 0x0b | 0x15 => {
            let d = cx.read(span.sub(0, 0x30)).await?;
            let kind = d.get(4).copied().unwrap_or(0);
            if h.header_type == 0x0a || h.header_type == 0x14 {
                let g = guid_le(d.get(24..40).unwrap_or_default());
                parts.push(format!("{g}"));
            }
            name = format!("Classic event type {kind}");
        }
        _ => {}
    }
    if logfile {
        name = "EventTrace/Header (logfile header)".to_owned();
    }
    if let (Some(pid), Some(tid)) = (h.pid, h.tid) {
        parts.push(format!("pid {pid}, tid {tid}"));
    }
    parts.push(format!("{:#x} bytes", h.size));
    let mut node = Node::new(name)
        .span(span)
        .summary(parts.join(", "))
        .lazy(expand_event, (span, clock, logfile));
    node = match clock.unix(h.timestamp) {
        Some(t) => node.value(Value::Timestamp { unix_seconds: t }),
        None => node.value(uint(h.timestamp, 64)),
    };
    Ok(node)
}

fn system_layout(f: &mut Fields<'_>, compact: &bool) -> Result<()> {
    f.u16("Version").emit()?;
    f.u8("HeaderType").enumeration(HEADER_TYPES).emit()?;
    f.u8("Flags").flags(MARKER_FLAGS).emit()?;
    f.u16("Size").hex().emit()?;
    f.u16("HookId")
        .hex()
        .with(|&v, n| n.summary(hook_name(v)))
        .emit()?;
    f.u32("ThreadId").emit()?;
    f.u32("ProcessId").emit()?;
    f.u64("SystemTime").emit()?;
    if !compact {
        f.u32("KernelTime").emit()?;
        f.u32("UserTime").emit()?;
    }
    Ok(())
}

fn perfinfo_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Version").emit()?;
    f.u8("HeaderType").enumeration(HEADER_TYPES).emit()?;
    f.u8("Flags").flags(MARKER_FLAGS).emit()?;
    f.u16("Size").hex().emit()?;
    f.u16("HookId")
        .hex()
        .with(|&v, n| n.summary(hook_name(v)))
        .emit()?;
    f.u64("SystemTime").emit()?;
    Ok(())
}

fn event_header_layout(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Size").hex().emit()?;
    f.u8("HeaderType").enumeration(HEADER_TYPES).emit()?;
    f.u8("MarkerFlags").flags(MARKER_FLAGS).emit()?;
    f.u16("Flags").flags(EVENT_HEADER_FLAGS).emit()?;
    f.u16("EventProperty").flags(EVENT_PROPERTIES).emit()?;
    f.u32("ThreadId").emit()?;
    f.u32("ProcessId").emit()?;
    f.u64("TimeStamp").emit()?;
    f.guid("ProviderId").emit()?;
    f.u16("Id").emit()?;
    f.u8("Version").emit()?;
    f.u8("Channel")
        .with(|&v, n| {
            if v == 11 {
                n.summary("TraceLogging")
            } else {
                n
            }
        })
        .emit()?;
    f.u8("Level").enumeration(LEVELS).emit()?;
    f.u8("Opcode").emit()?;
    f.u16("Task").emit()?;
    f.u64("Keyword").hex().emit()?;
    f.u32("KernelTime").emit()?;
    f.u32("UserTime").emit()?;
    f.guid("ActivityId").emit()?;
    Ok(())
}

fn classic_layout(f: &mut Fields<'_>, instance: &bool) -> Result<()> {
    f.u16("Size").hex().emit()?;
    f.u8("HeaderType").enumeration(HEADER_TYPES).emit()?;
    f.u8("MarkerFlags").flags(MARKER_FLAGS).emit()?;
    f.u8("Class.Type").emit()?;
    f.u8("Class.Level").enumeration(LEVELS).emit()?;
    f.u16("Class.Version").emit()?;
    f.u32("ThreadId").emit()?;
    f.u32("ProcessId").emit()?;
    f.u64("TimeStamp").emit()?;
    if *instance {
        f.u64("RegHandle").hex().emit()?;
        f.u32("InstanceId").emit()?;
        f.u32("ParentInstanceId").emit()?;
        f.u32("KernelTime").emit()?;
        f.u32("UserTime").emit()?;
        f.u64("ParentRegHandle").hex().emit()?;
    } else {
        f.guid("Guid").emit()?;
        f.u32("KernelTime").emit()?;
        f.u32("UserTime").emit()?;
    }
    Ok(())
}

/// An extended data item: type, span of the whole item, and its data.
#[derive(Clone, Debug)]
struct Ext {
    kind: u16,
    span: Span,
    data_span: Span,
    data: Vec<u8>,
}

/// Most extended data items followed.
const MAX_EXT: usize = 64;

async fn read_ext(cx: &Cx, span: Span, h: &EventHead) -> Result<Vec<Ext>> {
    let mut out = Vec::new();
    let mut at = h.header_len;
    while out.len() < MAX_EXT && at.saturating_add(8) <= span.len {
        let d = cx.read(span.sub(at, 8)).await?;
        let kind = u16_le(&d, 2).unwrap_or(0);
        let linkage = u16_le(&d, 4).unwrap_or(0);
        let size = u64::from(u16_le(&d, 6).unwrap_or(0));
        let data_span = span.sub(at.saturating_add(8), size);
        let data = cx.read(data_span).await?;
        let total = size.saturating_add(8).next_multiple_of(8);
        out.push(Ext {
            kind,
            span: span.sub(at, total),
            data_span,
            data,
        });
        at = at.saturating_add(total);
        if linkage & 1 == 0 {
            break;
        }
    }
    Ok(out)
}

fn ext_end(exts: &[Ext], span: Span, h: &EventHead) -> u64 {
    exts.last()
        .map_or(h.header_len, |e| e.span.end().saturating_sub(span.offset))
}

async fn expand_event(cx: Cx, (span, clock, logfile): (Span, Clock, bool)) -> Result<()> {
    let d = cx.read(span.sub(0, 0x18)).await?;
    let h = event_head(&d)
        .ok_or_else(|| Diagnostic::malformed("not an event header").at(span.sub(0, 4)))?;
    let header = span.sub(0, h.header_len);
    let mut node = match h.header_type {
        0x01..=0x04 => struct_node("Header", header, LE, h.header_type > 2, system_layout),
        0x10 | 0x11 => struct_node("Header", header, LE, (), perfinfo_layout),
        0x12 | 0x13 => struct_node("Header", header, LE, (), event_header_layout),
        0x0b | 0x15 => struct_node("Header", header, LE, true, classic_layout),
        _ => struct_node("Header", header, LE, false, classic_layout),
    };
    node = node.summary(lookup(HEADER_TYPES, h.header_type.into()).unwrap_or("header"));
    cx.emit(node);
    if let Some(t) = clock.unix(h.timestamp) {
        cx.emit(
            Node::new("Time")
                .value(Value::Timestamp { unix_seconds: t })
                .summary(format!("raw {}", h.timestamp)),
        );
    }
    let mut data_at = h.header_len;
    let mut schema = None;
    if matches!(h.header_type, 0x12 | 0x13) && u16_le(&d, 4).unwrap_or(0) & 1 != 0 {
        let exts = read_ext(&cx, span, &h).await?;
        data_at = ext_end(&exts, span, &h);
        for e in &exts {
            cx.emit(ext_node(e));
            if e.kind == 11 {
                schema = tl_schema(&e.data).map(|s| (s, e.data_span));
            }
        }
    }
    let user = span.sub(data_at, span.len.saturating_sub(data_at));
    if logfile {
        let pointer = if h.header_type == 1 { 4 } else { 8 };
        cx.emit(struct_node(
            "TRACE_LOGFILE_HEADER",
            user,
            LE,
            pointer,
            logfile_layout,
        ));
        return Ok(());
    }
    let mut node = Node::new("User data")
        .span(user)
        .summary(format!("{:#x} bytes", user.len));
    if let Some((s, _)) = schema {
        node = node
            .desc("TraceLogging fields")
            .lazy(tl_values, (user, s.fields, clock.pointer));
    } else if user.len > 0 && user.len <= 256 {
        let bytes = cx.read(user).await?;
        node = node.value(Value::Bytes(bytes));
    }
    cx.emit(node);
    Ok(())
}

fn ext_node(e: &Ext) -> Node {
    let name = lookup(EXT_TYPES, e.kind.into())
        .map_or_else(|| format!("Extended data {}", e.kind), str::to_owned);
    let mut node = Node::new(name)
        .span(e.span)
        .summary(format!("{:#x} bytes", e.data.len()));
    match e.kind {
        1 | 14 if e.data.len() == 16 => {
            node = node.value(Value::Guid(guid_le(&e.data)));
        }
        3 | 13 | 9 | 10 | 15 | 16 if e.data.len() == 4 || e.data.len() == 8 => {
            let v = u64_le(&e.data, 0)
                .or_else(|| u32_le(&e.data, 0).map(u64::from))
                .unwrap_or(0);
            node = node.value(hex(v, 64));
        }
        11 => {
            if let Some(s) = tl_schema(&e.data) {
                node = node
                    .value(text(s.name.clone()))
                    .summary(format!("TraceLogging schema, {} fields", s.fields.len()))
                    .lazy(tl_fields_node, (e.data_span, s.fields));
            }
        }
        12 => {
            if let Some(p) = provider_name(&e.data) {
                node = node.value(text(p)).summary("provider traits");
            }
        }
        _ => {
            if e.data.len() <= 64 {
                node = node.value(Value::Bytes(e.data.clone()));
            }
        }
    }
    node
}

// ---------------------------------------------------------------------------
// TraceLogging

/// A field of a TraceLogging schema.
#[derive(Clone, Debug, PartialEq)]
struct TlField {
    name: String,
    in_type: u8,
    out_type: u8,
    /// 0: single value, 0x20: variable count, 0x40: constant count,
    /// 0x60: custom.
    count_kind: u8,
    count: u16,
    /// Offsets of the field's metadata within the schema blob.
    meta: (u64, u64),
}

#[derive(Clone, Debug)]
struct TlSchema {
    name: String,
    fields: Vec<TlField>,
}

fn cstr_at(d: &[u8], at: usize) -> Option<(String, usize)> {
    let rest = d.get(at..)?;
    let n = rest.iter().position(|&b| b == 0)?;
    Some((
        String::from_utf8_lossy(rest.get(..n)?).into_owned(),
        at.saturating_add(n).saturating_add(1),
    ))
}

/// Decodes TraceLogging event metadata: `UINT16 size`, extension bytes
/// (until one without the high bit), the event name, then fields (name,
/// in-type with chain flag, out-type with chain flag, extension, counts).
fn tl_schema(d: &[u8]) -> Option<TlSchema> {
    let size = usize::from(u16_le(d, 0)?);
    let d = d.get(..size.min(d.len()))?;
    let mut at = 2usize;
    while d.get(at)? & 0x80 != 0 {
        at = at.saturating_add(1);
    }
    at = at.saturating_add(1);
    let (name, mut at) = cstr_at(d, at)?;
    let mut fields = Vec::new();
    while at < d.len() && fields.len() < 256 {
        let start = at;
        let (fname, next) = cstr_at(d, at)?;
        at = next;
        let in_raw = *d.get(at)?;
        at = at.saturating_add(1);
        let mut out_type = 0u8;
        if in_raw & 0x80 != 0 {
            let out_raw = *d.get(at)?;
            at = at.saturating_add(1);
            out_type = out_raw & 0x7f;
            if out_raw & 0x80 != 0 {
                while d.get(at)? & 0x80 != 0 {
                    at = at.saturating_add(1);
                }
                at = at.saturating_add(1);
            }
        }
        let count_kind = in_raw & 0x60;
        let mut count = 1u16;
        match count_kind {
            0x40 => {
                count = u16_le(d, at)?;
                at = at.saturating_add(2);
            }
            0x60 => {
                let n = usize::from(u16_le(d, at)?);
                at = at.saturating_add(2).saturating_add(n);
            }
            _ => {}
        }
        fields.push(TlField {
            name: fname,
            in_type: in_raw & 0x1f,
            out_type,
            count_kind,
            count,
            meta: (to_u64(start), to_u64(at.saturating_sub(start))),
        });
    }
    Some(TlSchema { name, fields })
}

/// Provider traits: `UINT16 size`, then the provider name.
fn provider_name(d: &[u8]) -> Option<String> {
    let (name, _) = cstr_at(d, 2)?;
    (!name.is_empty()).then_some(name)
}

fn tl_type(f: &TlField) -> String {
    let base = lookup(TL_IN_TYPES, f.in_type.into())
        .map_or_else(|| format!("type {}", f.in_type), str::to_owned);
    match f.count_kind {
        0x20 => format!("{base}[]"),
        0x40 => format!("{base}[{}]", f.count),
        0x60 => format!("{base} (custom)"),
        _ if f.in_type == 24 => format!("STRUCT of {} fields", f.out_type),
        _ => base,
    }
}

async fn tl_fields_node(cx: Cx, (span, fields): (Span, Vec<TlField>)) -> Result<()> {
    for f in fields {
        cx.emit(
            Node::new(f.name.clone())
                .span(span.sub(f.meta.0, f.meta.1))
                .value(text(tl_type(&f))),
        );
    }
    Ok(())
}

/// The size of one fixed-size value of a TraceLogging type.
fn tl_fixed(in_type: u8, pointer: u8) -> Option<usize> {
    Some(match in_type {
        3 | 4 => 1,
        5 | 6 => 2,
        7 | 8 | 11 | 13 | 20 => 4,
        9 | 10 | 12 | 17 | 21 => 8,
        15 | 18 => 16,
        16 => usize::from(pointer),
        _ => return None,
    })
}

fn tl_scalar(in_type: u8, b: &[u8]) -> Value {
    let u = |n: usize| {
        let mut buf = [0u8; 8];
        for (dst, &x) in buf.iter_mut().zip(b.iter().take(n)) {
            *dst = x;
        }
        u64::from_le_bytes(buf)
    };
    match in_type {
        3 => Value::Int {
            value: i64::from(b.first().copied().unwrap_or(0) as i8),
            bits: 8,
        },
        5 => Value::Int {
            value: i64::from(u(2) as u16 as i16),
            bits: 16,
        },
        7 => Value::Int {
            value: i64::from(u(4) as u32 as i32),
            bits: 32,
        },
        9 => Value::Int {
            value: u(8) as i64,
            bits: 64,
        },
        4 => uint(u(1), 8),
        6 => uint(u(2), 16),
        8 => uint(u(4), 32),
        10 => uint(u(8), 64),
        20 => hex(u(4), 32),
        21 | 16 => hex(u(8), 64),
        11 => Value::Float(f64::from(f32::from_bits(u(4) as u32))),
        12 => Value::Float(f64::from_bits(u(8))),
        13 => Value::Bool(u(4) != 0),
        15 => Value::Guid(guid_le(b)),
        17 => Value::Timestamp {
            unix_seconds: crate::text::filetime_to_unix(u(8)),
        },
        _ => Value::Bytes(b.to_vec()),
    }
}

/// A short rendering of an array element.
fn show(v: &Value) -> String {
    match v {
        Value::UInt {
            value,
            radix: crate::value::Radix::Hex,
            ..
        } => format!("{value:#x}"),
        Value::UInt { value, .. } => value.to_string(),
        Value::Int { value, .. } => value.to_string(),
        Value::Float(f) => f.to_string(),
        Value::Bool(b) => b.to_string(),
        Value::Text(t) => format!("{t:?}"),
        Value::Guid(g) => format!("{g}"),
        _ => "…".to_owned(),
    }
}

/// Decodes TraceLogging field values from user data, as far as the types
/// allow (unknown or custom types stop the decoding).
async fn tl_values(cx: Cx, (span, fields, pointer): (Span, Vec<TlField>, u8)) -> Result<()> {
    let data = cx.read(span.sub(0, 0x1_0000)).await?;
    let mut at = 0usize;
    let node_at =
        |start: usize, end: usize| span.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    for f in &fields {
        cx.checkpoint().await;
        if f.in_type == 24 {
            cx.emit(Node::new(f.name.clone()).summary(tl_type(f)));
            continue;
        }
        let count = match f.count_kind {
            0 => 1usize,
            0x40 => usize::from(f.count),
            0x20 => {
                let n = usize::from(u16_le(&data, at).unwrap_or(0));
                at = at.saturating_add(2);
                n
            }
            _ => {
                cx.diag(Diagnostic::unsupported(format!(
                    "custom-typed field {}",
                    f.name
                )));
                return Ok(());
            }
        };
        let start = at;
        let mut values = Vec::new();
        for _ in 0..count.min(4096) {
            let (value, next) = match f.in_type {
                1 => {
                    let rest = data.get(at..).unwrap_or_default();
                    let (s, len, _) = crate::text::utf16z(rest, LE);
                    (text(s), at.saturating_add(len))
                }
                2 => match cstr_at(&data, at) {
                    Some((s, next)) => (text(s), next),
                    None => break,
                },
                22 | 23 | 14 | 25 => {
                    let n = usize::from(u16_le(&data, at).unwrap_or(0));
                    let body = data
                        .get(at.saturating_add(2)..at.saturating_add(2).saturating_add(n))
                        .unwrap_or_default();
                    let v = match f.in_type {
                        22 => text(crate::text::utf16z(body, LE).0),
                        23 => text(String::from_utf8_lossy(body).into_owned()),
                        _ => Value::Bytes(body.to_vec()),
                    };
                    (v, at.saturating_add(2).saturating_add(n))
                }
                19 => {
                    let n = 8usize.saturating_add(
                        usize::from(data.get(at.saturating_add(1)).copied().unwrap_or(0))
                            .saturating_mul(4),
                    );
                    let b = data.get(at..at.saturating_add(n)).unwrap_or_default();
                    (Value::Bytes(b.to_vec()), at.saturating_add(n))
                }
                t => match tl_fixed(t, pointer) {
                    Some(n) => {
                        let Some(b) = data.get(at..at.saturating_add(n)) else {
                            break;
                        };
                        (tl_scalar(t, b), at.saturating_add(n))
                    }
                    None => {
                        cx.diag(Diagnostic::unsupported(format!("TraceLogging type {t}")));
                        return Ok(());
                    }
                },
            };
            if next > data.len() {
                break;
            }
            values.push(value);
            at = next;
        }
        let node = Node::new(f.name.clone()).span(node_at(start, at));
        let node = if f.count_kind == 0 {
            match values.into_iter().next() {
                Some(v) => node.value(v),
                None => node.diag(Diagnostic::truncated(
                    node_at(start, start.saturating_add(1)),
                    0,
                )),
            }
        } else {
            let shown: Vec<String> = values.iter().map(show).collect();
            node.value(text(shown.join(", "))).summary(tl_type(f))
        };
        cx.emit(node);
    }
    if at < data.len() {
        cx.emit(
            Node::new("Remaining data")
                .span(span.sub(to_u64(at), span.len.saturating_sub(to_u64(at)))),
        );
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn tracelogging_schema() {
        // Size, one extension byte, "E", fields "a" (UINT32) and "b"
        // (UINT16[2], constant count) and "c" (ANSISTRING with an out-type).
        let mut d = vec![0, 0, 0x00];
        d.extend_from_slice(b"E\0a\0\x08b\0\x46\x02\x00c\0\x82\x01");
        let n = d.len() as u16;
        d[..2].copy_from_slice(&n.to_le_bytes());
        let s = tl_schema(&d).unwrap();
        assert_eq!(s.name, "E");
        assert_eq!(s.fields.len(), 3);
        assert_eq!((s.fields[1].in_type, s.fields[1].count), (6, 2));
        assert_eq!((s.fields[2].in_type, s.fields[2].out_type), (2, 1));
    }

    #[test]
    fn clock_conversion() {
        let start = 116_444_736_000_000_000 + 1_741_944_413 * 10_000_000;
        let c = Clock {
            pointer: 8,
            kind: 1,
            frequency: 10_000_000,
            start,
            reference: 1_000_000_000,
        };
        assert_eq!(c.unix(1_000_000_000), Some(1_741_944_413));
        assert_eq!(c.unix(1_030_000_000), Some(1_741_944_416));
    }
}
