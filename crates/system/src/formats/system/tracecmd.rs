//! trace-cmd trace files (`trace.dat`): Linux ftrace ring-buffer data with
//! the metadata needed to read it, as written by `trace-cmd record`.
//!
//! Both layouts are read, following the file format manual pages shipped
//! with trace-cmd (`trace-cmd.dat.v6(5)`, `trace-cmd.dat.v7(5)`):
//!
//! - Version 6 is a sequence: the magic (`17 08 44 "tracing"`), the version
//!   as text, the byte order, the user-space long size and the page size;
//!   the ring-buffer page and event header descriptions (`header_page`,
//!   `header_event`); the ftrace event format files; the other event format
//!   files grouped by system; `/proc/kallsyms`; the `trace_printk` formats;
//!   the saved command lines; the CPU count; options; then `flyrecord`
//!   (an offset and size of each CPU's data, at page-aligned offsets) or
//!   `latency` (text).
//! - Version 7 adds a compression header (algorithm name and version) and
//!   the offset of the first options section, then consists of sections,
//!   each with a 16-byte header (ID, flags, description string ID, size)
//!   and optionally compressed (a 4-byte compressed and uncompressed size,
//!   then the stream); trace data is compressed in chunks. Options sections
//!   chain through their `DONE` option; `BUFFER` options locate each CPU's
//!   data. The sections are walked in file order, which reaches all of them
//!   (the section holding the description strings is not referenced by any
//!   option in the files trace-cmd 3.3 writes).
//!
//! CPU data is a sequence of ring-buffer pages: a timestamp, a commit count
//! and records whose 32-bit header packs a 5-bit type and length with a
//! 27-bit time delta (padding, time extends and absolute timestamps are
//! types 29 to 31). Each event is named from the format files by its
//! `common_type`, and its fields are decoded from the offsets, sizes and
//! types those files declare (`__data_loc` strings included). Timestamps
//! are in the trace clock's units (nanoseconds for `local`).

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::plain;
use crate::formats::util::binutil::{cstrings, get};
use crate::formats::util::fmt::{clip, plural, size};
use crate::formats::util::val::{hex, int, text, uint};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "tracecmd-dat",
    title: "trace-cmd trace data",
    extensions: &["dat"],
    mime: "application/x-trace-cmd",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const MAGIC: &[u8] = b"\x17\x08\x44tracing";
/// Longest format file, option or text read whole.
const MAX_TEXT: u64 = 1 << 20;
/// Largest page size accepted.
const MAX_PAGE: u64 = 1 << 20;

fn probe(h: &Head) -> bool {
    if !h.starts_with(MAGIC) {
        return false;
    }
    let rest = h.data.get(MAGIC.len()..).unwrap_or_default();
    let digits = rest.iter().take_while(|b| b.is_ascii_digit()).count();
    (1..=3).contains(&digits) && rest.get(digits) == Some(&0)
}

const OPTIONS: EnumTable = &[
    (0, "DONE"),
    (1, "DATE"),
    (2, "CPUSTAT"),
    (3, "BUFFER"),
    (4, "TRACECLOCK"),
    (5, "UNAME"),
    (6, "HOOK"),
    (7, "OFFSET"),
    (8, "CPUCOUNT"),
    (9, "VERSION"),
    (10, "PROCMAPS"),
    (11, "TRACEID"),
    (12, "TIME_SHIFT"),
    (13, "GUEST"),
    (14, "TSC2NSEC"),
    (15, "STRINGS"),
    (16, "HEADER_INFO"),
    (17, "FTRACE_EVENTS"),
    (18, "EVENT_FORMATS"),
    (19, "KALLSYMS"),
    (20, "PRINTK"),
    (21, "CMDLINES"),
    (22, "BUFFER_TEXT"),
];

/// Section IDs (version 7) reuse the option IDs; these are the ones with
/// their own contents.
const SEC_OPTIONS: u16 = 0;
const SEC_BUFFER: u16 = 3;
const SEC_STRINGS: u16 = 15;
const SEC_HEADER_INFO: u16 = 16;
const SEC_FTRACE: u16 = 17;
const SEC_EVENTS: u16 = 18;
const SEC_KALLSYMS: u16 = 19;
const SEC_PRINTK: u16 = 20;
const SEC_CMDLINES: u16 = 21;
const SEC_BUFFER_TEXT: u16 = 22;

const SECTIONS: EnumTable = &[
    (0, "OPTIONS"),
    (3, "BUFFER FLYRECORD"),
    (15, "STRINGS"),
    (16, "HEADER INFO"),
    (17, "FTRACE EVENT FORMATS"),
    (18, "EVENT FORMATS"),
    (19, "KALLSYMS"),
    (20, "TRACE_PRINTK"),
    (21, "SAVED COMMAND LINES"),
    (22, "BUFFER TEXT"),
];

const SECTION_FLAGS: crate::value::FlagTable = &[crate::value::flag(1, "COMPRESSED")];

/// What every node of one trace file shares.
#[derive(Clone)]
struct Trace {
    input: Input,
    endian: Endian,
    /// The kernel's long size (from `header_page`), else the user-space one.
    long: u64,
    page: u64,
    codec: Option<Codec>,
    meta: Meta,
}

/// Where the metadata the CPU data needs to be read is.
#[derive(Clone, Default)]
struct Meta {
    header: Option<Span>,
    ftrace: Option<Span>,
    events: Option<Span>,
    /// The saved command lines, with their 8-byte size.
    cmdlines: Option<Span>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    let ver_len = head
        .get(MAGIC.len()..)
        .unwrap_or_default()
        .iter()
        .position(|&b| b == 0)
        .ok_or_else(|| Diagnostic::malformed("version string not terminated"))?;
    let version: u32 = head
        .get(MAGIC.len()..MAGIC.len().saturating_add(ver_len))
        .and_then(|b| std::str::from_utf8(b).ok())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    let after_ver = to_u64(MAGIC.len().saturating_add(ver_len).saturating_add(1));
    let endian = match head.get(to_usize(after_ver)) {
        Some(1) => Endian::Big,
        _ => Endian::Little,
    };
    let user_long = u64::from(
        head.get(to_usize(after_ver).saturating_add(1))
            .copied()
            .unwrap_or(8),
    );
    let page = get::<u32>(&head, to_usize(after_ver.saturating_add(2)), endian).unwrap_or(4096);
    let mut pos = after_ver.saturating_add(6);
    let mut trace = Trace {
        input,
        endian,
        long: user_long,
        page: u64::from(page),
        codec: None,
        meta: Meta::default(),
    };
    if version >= 7 {
        let (name, nspan) = cx.cstr(file.sub(pos, 64)).await?;
        let (_, vspan) = cx
            .cstr(file.sub(nspan.end().saturating_sub(file.offset), 64))
            .await?;
        pos = vspan.end().saturating_sub(file.offset);
        trace.codec = match name.as_str() {
            "none" => None,
            "zstd" => Some(Codec::Zstd),
            "zlib" => Some(Codec::Zlib),
            _ => {
                cx.diag(Diagnostic::unsupported(format!("{name} compression")));
                None
            }
        };
        pos = pos.saturating_add(8);
    }
    let hspan = file.sub(0, pos);
    cx.emit(
        Node::new("File Header")
            .span(hspan)
            .lazy(file_header, (hspan, endian, version)),
    );
    if !(page > 0 && u64::from(page) <= MAX_PAGE && page.is_power_of_two()) {
        cx.diag(Diagnostic::malformed(format!(
            "implausible page size {page}"
        )));
        trace.page = 4096;
    }
    let summary = format!(
        "trace-cmd trace, version {version}, {}-endian{}",
        match endian {
            Endian::Little => "little",
            Endian::Big => "big",
        },
        match &trace.codec {
            Some(Codec::Zstd) => ", zstd-compressed",
            Some(Codec::Zlib) => ", zlib-compressed",
            _ => "",
        }
    );
    cx.annotate(summary);
    if version >= 7 {
        v7(&cx, trace, pos).await
    } else {
        v6(&cx, trace, pos).await
    }
}

async fn file_header(cx: Cx, (span, endian, version): (Span, Endian, u32)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.bytes("Magic", to_u64(MAGIC.len())).emit()?;
    f.cstr("Version").emit()?;
    f.u8("Endianness")
        .enumeration(&[(0, "little-endian"), (1, "big-endian")])
        .emit()?;
    f.u8("Long size")
        .desc("Size of a long in the tracing host's user space")
        .emit()?;
    f.u32("Page size").emit()?;
    if version >= 7 {
        f.cstr("Compression").emit()?;
        f.cstr("Compression version").emit()?;
        f.u64("First options section").hex().emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Version 6: a sequence.

async fn v6(cx: &Cx, mut trace: Trace, start: u64) -> Result<()> {
    let file = trace.input.span;
    let input = trace.input;
    let mut cur = Cursor::new(cx, file, trace.endian);
    cur.seek(start);
    let at = cur.pos();
    let len = header_info_len(&mut cur).await?;
    let header = file.sub(at, len);
    trace.meta.header = Some(header);
    trace.long = kernel_long(cx, header, trace.endian)
        .await
        .unwrap_or(trace.long);
    cx.emit(
        Node::new("Header Info")
            .span(header)
            .lazy(header_info, (input, header, trace.endian)),
    );

    let at = cur.pos();
    let n = ftrace_len(&mut cur).await?;
    let ftrace = file.sub(at, n.1);
    trace.meta.ftrace = Some(ftrace);
    cx.emit(
        Node::new("Ftrace Event Formats")
            .span(ftrace)
            .summary(plural(n.0, "format"))
            .lazy(ftrace_list, (input, ftrace, trace.endian)),
    );

    let at = cur.pos();
    let n = events_len(cx, &mut cur).await?;
    let events = file.sub(at, n.1);
    trace.meta.events = Some(events);
    cx.emit(
        Node::new("Event Formats")
            .span(events)
            .summary(plural(n.0, "system"))
            .lazy(event_systems, (input, events, trace.endian)),
    );

    for (name, width) in [
        ("Kallsyms", 4u64),
        ("Trace Printk Formats", 4),
        ("Saved Command Lines", 8),
    ] {
        let at = cur.pos();
        let n = if width == 4 {
            u64::from(cur.u32().await?)
        } else {
            cur.u64().await?
        };
        let span = file.sub(at, width.saturating_add(n));
        cur.skip(n);
        if width == 8 {
            trace.meta.cmdlines = Some(span);
        }
        if span.len < width.saturating_add(n) {
            cx.emit(
                Node::new(name)
                    .span(span)
                    .diag(Diagnostic::truncated(span, span.len)),
            );
            return Ok(());
        }
        cx.emit(sized_text(name, input, span, width, trace.endian));
    }

    let at = cur.pos();
    let cpus = cur.u32().await?;
    cx.emit(
        Node::new("CPUs")
            .span(file.sub(at, 4))
            .value(uint(cpus, 32))
            .desc("CPUs with trace data"),
    );
    loop {
        let at = cur.pos();
        let tag = cur.bytes(10).await?;
        match tag.as_slice() {
            b"options  \0" => {
                let opts = cur.pos();
                loop {
                    let id = cur.u16().await?;
                    if id == 0 {
                        break;
                    }
                    let n = cur.u32().await?;
                    if u64::from(n) > cur.remaining() {
                        return Err(Diagnostic::truncated(cur.span(n.into()), cur.remaining()));
                    }
                    cur.skip(n.into());
                    cx.checkpoint().await;
                }
                let span = file.sub(at, cur.pos().saturating_sub(at));
                cx.emit(
                    Node::new("Options")
                        .span(span)
                        .lazy(options_list, (trace.clone(), span.tail(10), false, opts)),
                );
            }
            b"flyrecord\0" => {
                let table = cur.since(at);
                let n = u64::from(cpus).saturating_mul(16);
                let table = file.sub(at, table.len.saturating_add(n));
                let mut cpus_list = Vec::new();
                for i in 0..cpus {
                    let off = cur.u64().await?;
                    let len = cur.u64().await?;
                    cpus_list.push((i, file.sub(off, len)));
                    cx.checkpoint().await;
                }
                cx.emit(
                    Node::new("Flyrecord")
                        .span(table)
                        .summary(plural(cpus, "CPU"))
                        .lazy(flyrecord_table, (table, trace.endian, cpus)),
                );
                for (i, span) in cpus_list {
                    if span.len == 0 {
                        continue;
                    }
                    cx.emit(cpu_node(&trace, format!("CPU {i}"), span));
                }
                break;
            }
            b"latency  \0" => {
                let rest = file.tail(cur.pos());
                cx.emit(embedded_as(
                    "Latency Trace",
                    input.nested(rest),
                    &plain::FORMAT,
                ));
                break;
            }
            _ => {
                cx.diag(
                    Diagnostic::malformed("expected options, flyrecord or latency")
                        .at(file.sub(at, 10)),
                );
                break;
            }
        }
    }
    Ok(())
}

async fn flyrecord_table(cx: Cx, (span, endian, cpus): (Span, Endian, u32)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.ascii("Tag", 10).emit()?;
    for _ in 0..cpus.min(4096) {
        f.u64("CPU data offset").hex().emit()?;
        f.u64("CPU data size").emit()?;
    }
    Ok(())
}

/// Length of the header info region (`header_page`, `header_event`).
async fn header_info_len(cur: &mut Cursor<'_>) -> Result<u64> {
    let start = cur.pos();
    for tag in [&b"header_page\0"[..], &b"header_event\0"[..]] {
        let got = cur.bytes(to_u64(tag.len())).await?;
        if got != tag {
            return Err(Diagnostic::malformed(format!(
                "expected {:?}",
                String::from_utf8_lossy(tag.get(..tag.len().saturating_sub(1)).unwrap_or_default())
            )));
        }
        let n = cur.u64().await?;
        cur.skip(n);
    }
    Ok(cur.pos().saturating_sub(start))
}

/// Count and length of an ftrace format list.
async fn ftrace_len(cur: &mut Cursor<'_>) -> Result<(u32, u64)> {
    let start = cur.pos();
    let n = cur.u32().await?;
    for _ in 0..n {
        let len = cur.u64().await?;
        if len > cur.remaining() {
            return Err(Diagnostic::truncated(cur.span(len), cur.remaining()));
        }
        cur.skip(len);
    }
    Ok((n, cur.pos().saturating_sub(start)))
}

/// Count of systems and length of the event formats region.
async fn events_len(cx: &Cx, cur: &mut Cursor<'_>) -> Result<(u32, u64)> {
    let start = cur.pos();
    let systems = cur.u32().await?;
    for _ in 0..systems {
        cur.cstr(4096).await?;
        let n = cur.u32().await?;
        for _ in 0..n {
            let len = cur.u64().await?;
            if len > cur.remaining() {
                return Err(Diagnostic::truncated(cur.span(len), cur.remaining()));
            }
            cur.skip(len);
            cx.checkpoint().await;
        }
    }
    Ok((systems, cur.pos().saturating_sub(start)))
}

/// The kernel's long size, from the size of `commit` in `header_page`.
async fn kernel_long(cx: &Cx, header: Span, endian: Endian) -> Option<u64> {
    let text = header_page_text(cx, header, endian).await?;
    let fields = parse_fields(&text);
    fields
        .iter()
        .find(|f| f.name == "commit")
        .map(|f| u64::from(f.size))
        .filter(|&s| s == 4 || s == 8)
}

async fn header_page_text(cx: &Cx, header: Span, endian: Endian) -> Option<String> {
    let b = cx.read(header.sub(12, 8)).await.ok()?;
    let n = get::<u64>(&b, 0, endian)?;
    let t = cx.read(header.sub(20, n.min(MAX_TEXT))).await.ok()?;
    Some(String::from_utf8_lossy(&t).into_owned())
}

/// Offset of the data in a ring-buffer page.
async fn page_data_offset(cx: &Cx, trace: &Trace) -> u64 {
    if let Some(header) = trace.meta.header
        && let Some(text) = header_page_text(cx, header, trace.endian).await
        && let Some(f) = parse_fields(&text).iter().find(|f| f.name == "data")
    {
        return u64::from(f.offset);
    }
    8u64.saturating_add(trace.long)
}

async fn header_info(cx: Cx, (input, span, endian): (Input, Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    for (tag, name) in [(12u64, "header_page"), (13, "header_event")] {
        let at = cur.pos();
        cur.skip(tag);
        let n = cur.u64().await?;
        cur.skip(n);
        let whole = cur.since(at);
        cx.emit(
            Node::new(name)
                .span(whole)
                .summary(plural(n, "byte"))
                .lazy(tagged_text, (input, whole, endian, tag)),
        );
    }
    Ok(())
}

async fn tagged_text(cx: Cx, (input, span, endian, tag): (Input, Span, Endian, u64)) -> Result<()> {
    let block = cx.block(span.sub(0, tag.saturating_add(8))).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    f.cstr("Name").emit()?;
    f.u64("Size").emit()?;
    let text = span.tail(tag.saturating_add(8));
    cx.emit(format_fields_node(input, text));
    Ok(())
}

/// A text region preceded by its size (`width` bytes).
fn sized_text(name: &'static str, input: Input, span: Span, width: u64, endian: Endian) -> Node {
    let body = span.tail(width);
    Node::new(name)
        .span(span)
        .summary(size(body.len))
        .lazy(sized_text_fields, (input, span, width, endian))
}

async fn sized_text_fields(
    cx: Cx,
    (input, span, width, endian): (Input, Span, u64, Endian),
) -> Result<()> {
    let block = cx.block(span.sub(0, width)).await?;
    let mut f = Fields::emitting(&cx, &block, endian);
    if width == 4 {
        f.u32("Size").emit()?;
    } else {
        f.u64("Size").emit()?;
    }
    let body = span.tail(width);
    if !body.is_empty() {
        cx.emit(embedded_as("Text", input.nested(body), &plain::FORMAT));
    }
    Ok(())
}

async fn ftrace_list(cx: Cx, (input, span, endian): (Input, Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    let n = cur.u32().await?;
    cx.set_count(Count::Exact(u64::from(n)));
    format_files(&cx, input, &mut cur, n, endian).await
}

/// `n` format files, each an 8-byte size and the text, pushed as nodes.
async fn format_files(
    cx: &Cx,
    input: Input,
    cur: &mut Cursor<'_>,
    n: u32,
    endian: Endian,
) -> Result<()> {
    for _ in 0..n {
        let at = cur.pos();
        let len = cur.u64().await?;
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(body, body.len));
        }
        cur.skip(len);
        let whole = cur.since(at);
        let head = cx.read(body.sub(0, 256)).await?;
        let head = String::from_utf8_lossy(&head);
        let name = head
            .lines()
            .find_map(|l| l.strip_prefix("name: "))
            .unwrap_or("(unnamed)")
            .to_string();
        let id = head.lines().find_map(|l| l.strip_prefix("ID: "));
        let mut node = Node::new(name)
            .span(whole)
            .lazy(format_file, (input, whole, endian));
        if let Some(id) = id {
            node = node.summary(format!("ID {id}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn format_file(cx: Cx, (input, span, endian): (Input, Span, Endian)) -> Result<()> {
    let block = cx.block(span.sub(0, 8)).await?;
    Fields::emitting(&cx, &block, endian).u64("Size").emit()?;
    cx.emit(format_fields_node(input, span.tail(8)));
    Ok(())
}

/// A format file's text, with its fields listed as children.
fn format_fields_node(input: Input, text: Span) -> Node {
    Node::new("Format")
        .span(text)
        .summary(size(text.len))
        .lazy(format_text, (input, text))
}

async fn format_text(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let t = cx.read(span.sub(0, MAX_TEXT)).await?;
    cx.charge(to_u64(t.len()) / 64).await;
    let s = String::from_utf8_lossy(&t);
    for line in s.lines() {
        let l = line.trim();
        if let Some(v) = l.strip_prefix("name: ") {
            cx.emit(Node::new("Name").value(text(v)));
        } else if let Some(v) = l.strip_prefix("ID: ") {
            cx.emit(Node::new("ID").value(text(v)));
        } else if let Some(v) = l.strip_prefix("print fmt: ") {
            cx.emit(Node::new("Print format").value(text(clip(v, 4096))));
        }
    }
    let fields = parse_fields(&s);
    if !fields.is_empty() {
        cx.emit(
            Node::new("Fields")
                .summary(plural(fields.len(), "field"))
                .lazy(field_defs, Arc::new(fields)),
        );
    }
    cx.emit(embedded_as("Text", input.nested(span), &plain::FORMAT));
    Ok(())
}

async fn field_defs(cx: Cx, fields: Arc<Vec<FieldDef>>) -> Result<()> {
    for f in fields.iter() {
        cx.push(
            Node::new(f.name.clone())
                .value(text(f.decl.clone()))
                .summary(format!(
                    "offset {}, {}, {}",
                    f.offset,
                    plural(f.size, "byte"),
                    if f.signed { "signed" } else { "unsigned" }
                )),
        )
        .await;
    }
    Ok(())
}

async fn event_systems(cx: Cx, (input, span, endian): (Input, Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    let systems = cur.u32().await?;
    cx.set_count(Count::Exact(u64::from(systems)));
    for _ in 0..systems {
        let at = cur.pos();
        let (name, _) = cur.cstr(4096).await?;
        let n = cur.u32().await?;
        let list = cur.pos();
        for _ in 0..n {
            let len = cur.u64().await?;
            if len > cur.remaining() {
                return Err(Diagnostic::truncated(cur.span(len), cur.remaining()));
            }
            cur.skip(len);
            cx.checkpoint().await;
        }
        let whole = cur.since(at);
        cx.push(
            Node::new(name)
                .span(whole)
                .summary(plural(n, "event"))
                .lazy(
                    system_events,
                    (input, whole, endian, list.saturating_sub(at), n),
                ),
        )
        .await;
    }
    Ok(())
}

async fn system_events(
    cx: Cx,
    (input, span, endian, list, n): (Input, Span, Endian, u64, u32),
) -> Result<()> {
    cx.set_count(Count::Exact(u64::from(n)));
    let mut cur = Cursor::new(&cx, span, endian);
    cur.seek(list);
    format_files(&cx, input, &mut cur, n, endian).await
}

// ---------------------------------------------------------------------------
// Event formats.

#[derive(Clone, Debug)]
struct FieldDef {
    decl: String,
    name: String,
    offset: u32,
    size: u32,
    signed: bool,
}

/// The `field:` lines of a format file.
fn parse_fields(s: &str) -> Vec<FieldDef> {
    let mut out = Vec::new();
    for line in s.lines() {
        let Some(rest) = line.trim().strip_prefix("field:") else {
            continue;
        };
        let mut decl = None;
        let (mut offset, mut fsize, mut signed) = (None, None, false);
        for part in rest.split(';') {
            let part = part.trim();
            if decl.is_none() {
                decl = Some(part.trim().to_string());
            } else if let Some(v) = part.strip_prefix("offset:") {
                offset = v.trim().parse().ok();
            } else if let Some(v) = part.strip_prefix("size:") {
                fsize = v.trim().parse().ok();
            } else if let Some(v) = part.strip_prefix("signed:") {
                signed = v.trim() == "1";
            }
        }
        let (Some(decl), Some(offset), Some(fsize)) = (decl, offset, fsize) else {
            continue;
        };
        let name = decl
            .rsplit(|c: char| c.is_whitespace() || c == '*')
            .next()
            .unwrap_or("")
            .split('[')
            .next()
            .unwrap_or("")
            .to_string();
        out.push(FieldDef {
            decl,
            name,
            offset,
            size: fsize,
            signed,
        });
    }
    out
}

struct EventFormat {
    system: String,
    name: String,
    fields: Vec<FieldDef>,
}

/// Event formats by ID, and task names by PID.
struct EventMap {
    by_id: std::collections::BTreeMap<u32, Arc<EventFormat>>,
    /// From the saved command lines (`<pid> <comm>` per line).
    comms: std::collections::BTreeMap<u32, String>,
}

async fn event_map(cx: &Cx, trace: &Trace) -> Arc<EventMap> {
    let key = trace.input.span;
    if let Some(m) = cx.cached::<EventMap>(key, "tracecmd-events") {
        return m;
    }
    let mut by_id = std::collections::BTreeMap::new();
    let mut add = |system: &str, text: &str| {
        let name = text.lines().find_map(|l| l.strip_prefix("name: "));
        let id = text
            .lines()
            .find_map(|l| l.strip_prefix("ID: "))
            .and_then(|v| v.trim().parse::<u32>().ok());
        if let (Some(name), Some(id)) = (name, id) {
            by_id.insert(
                id,
                Arc::new(EventFormat {
                    system: system.to_string(),
                    name: name.to_string(),
                    fields: parse_fields(text),
                }),
            );
        }
    };
    if let Some(span) = trace.meta.ftrace {
        let mut cur = Cursor::new(cx, span, trace.endian);
        if let Ok(n) = cur.u32().await {
            for _ in 0..n {
                let Ok(t) = read_format(cx, &mut cur).await else {
                    break;
                };
                add("ftrace", &t);
            }
        }
    }
    if let Some(span) = trace.meta.events {
        let mut cur = Cursor::new(cx, span, trace.endian);
        if let Ok(systems) = cur.u32().await {
            'outer: for _ in 0..systems {
                let Ok((system, _)) = cur.cstr(4096).await else {
                    break;
                };
                let Ok(n) = cur.u32().await else {
                    break;
                };
                for _ in 0..n {
                    let Ok(t) = read_format(cx, &mut cur).await else {
                        break 'outer;
                    };
                    add(&system, &t);
                }
            }
        }
    }
    let mut comms = std::collections::BTreeMap::new();
    if let Some(span) = trace.meta.cmdlines {
        let body = span.tail(8);
        if let Ok(b) = cx.read(body.sub(0, MAX_TEXT)).await {
            cx.charge(to_u64(b.len()) / 256).await;
            for line in String::from_utf8_lossy(&b).lines() {
                if let Some((pid, comm)) = line.split_once(' ')
                    && let Ok(pid) = pid.trim().parse::<u32>()
                {
                    comms.insert(pid, comm.to_string());
                }
            }
        }
    }
    let map = Arc::new(EventMap { by_id, comms });
    cx.cache(key, "tracecmd-events", map.clone());
    map
}

async fn read_format(cx: &Cx, cur: &mut Cursor<'_>) -> Result<String> {
    let len = cur.u64().await?;
    let body = cur.span(len);
    cur.skip(len);
    let t = cx.read(body.sub(0, MAX_TEXT)).await?;
    cx.charge(to_u64(t.len()) / 64).await;
    Ok(String::from_utf8_lossy(&t).into_owned())
}

// ---------------------------------------------------------------------------
// Version 7: sections.

struct Section {
    offset: u64,
    id: u16,
    flags: u16,
    string: u32,
    /// The section header and data in the file.
    whole: Span,
    /// The data in the file (after the header).
    data: Span,
    /// The contents: `data`, or decoded from it.
    contents: Span,
    error: Option<Diagnostic>,
}

/// A CPU's data located by a `BUFFER` option.
#[derive(Clone)]
struct CpuData {
    section: u64,
    cpu: u32,
    offset: u64,
    size: u64,
}

async fn v7(cx: &Cx, mut trace: Trace, start: u64) -> Result<()> {
    let file = trace.input.span;
    let mut sections = Vec::new();
    let mut pos = start;
    while pos < file.len {
        let hdr = cx.read(file.sub(pos, 16)).await?;
        let e = trace.endian;
        let (Some(id), Some(flags), Some(string), Some(len)) = (
            get::<u16>(&hdr, 0, e),
            get::<u16>(&hdr, 2, e),
            get::<u32>(&hdr, 4, e),
            get::<u64>(&hdr, 8, e),
        ) else {
            cx.diag(Diagnostic::truncated(file.sub(pos, 16), to_u64(hdr.len())));
            break;
        };
        let data = file.sub(pos.saturating_add(16), len);
        let whole = file.sub(pos, len.saturating_add(16));
        let mut error = None;
        if data.len < len {
            error = Some(Diagnostic::truncated(data, data.len));
        }
        let compressed = flags & 1 != 0;
        let contents = if compressed && id != SEC_BUFFER && id != SEC_BUFFER_TEXT {
            match (&trace.codec, cx.read(data.sub(0, 8)).await) {
                (Some(codec), Ok(b)) => {
                    let csize = get::<u32>(&b, 0, e).unwrap_or(0);
                    let usize_ = get::<u32>(&b, 4, e).unwrap_or(0);
                    match cx.decode_lazy(data.sub(8, csize.into()), codec, usize_.into()) {
                        Ok(s) => s,
                        Err(err) => {
                            error = Some(err);
                            data
                        }
                    }
                }
                _ => {
                    error = Some(Diagnostic::unsupported("compressed section"));
                    data
                }
            }
        } else {
            data
        };
        match id {
            SEC_HEADER_INFO => trace.meta.header = Some(contents),
            SEC_FTRACE => trace.meta.ftrace = Some(contents),
            SEC_EVENTS => trace.meta.events = Some(contents),
            SEC_CMDLINES => trace.meta.cmdlines = Some(contents),
            _ => {}
        }
        sections.push(Section {
            offset: pos,
            id,
            flags,
            string,
            whole,
            data,
            contents,
            error,
        });
        pos = pos.saturating_add(16).saturating_add(len);
        cx.checkpoint().await;
    }
    if let Some(header) = trace.meta.header {
        trace.long = kernel_long(cx, header, trace.endian)
            .await
            .unwrap_or(trace.long);
    }
    // Description strings, from the strings sections in file order.
    let mut strings: Vec<u8> = Vec::new();
    for s in sections.iter().filter(|s| s.id == SEC_STRINGS) {
        if let Ok(b) = cx.read(s.contents.sub(0, MAX_TEXT)).await {
            strings.extend_from_slice(&b);
        }
    }
    let describe = |id: u32| -> String {
        let tail = strings.get(to_usize(u64::from(id))..).unwrap_or_default();
        let end = tail.iter().position(|&b| b == 0).unwrap_or(tail.len());
        String::from_utf8_lossy(tail.get(..end).unwrap_or_default())
            .trim()
            .to_string()
    };
    // CPU data located by BUFFER options.
    let mut cpus = Vec::new();
    for s in sections.iter().filter(|s| s.id == SEC_OPTIONS) {
        buffer_options(cx, &trace, s.contents, &mut cpus).await;
    }
    for s in &sections {
        let desc = describe(s.string);
        let kind = lookup(SECTIONS, s.id.into()).unwrap_or("unknown");
        let title = if desc.is_empty() {
            format!("Section {kind}")
        } else {
            format!("Section {desc}")
        };
        let mut node = Node::new(title)
            .span(s.whole)
            .summary(format!(
                "ID {} ({kind}), {}{}",
                s.id,
                size(s.data.len),
                if s.flags & 1 != 0 { ", compressed" } else { "" }
            ))
            .lazy(
                section_node,
                (
                    trace.clone(),
                    s.whole,
                    s.data,
                    s.contents,
                    s.id,
                    s.flags,
                    s.offset,
                    Arc::new(cpus.clone()),
                ),
            );
        if let Some(e) = &s.error {
            node = node.diag(e.clone());
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Collects the CPUs of the `BUFFER` options in one options section.
async fn buffer_options(cx: &Cx, trace: &Trace, span: Span, out: &mut Vec<CpuData>) {
    let mut cur = Cursor::new(cx, span, trace.endian);
    while cur.remaining() >= 6 {
        let (Ok(id), Ok(n)) = (cur.u16().await, cur.u32().await) else {
            break;
        };
        let body = cur.span(n.into());
        cur.skip(n.into());
        if id == 3 {
            let mut b = Cursor::new(cx, body, trace.endian);
            let Ok(section) = b.u64().await else {
                continue;
            };
            if b.cstr(4096).await.is_err() || b.cstr(4096).await.is_err() {
                continue;
            }
            let (Ok(_page), Ok(count)) = (b.u32().await, b.u32().await) else {
                continue;
            };
            for _ in 0..count {
                let (Ok(cpu), Ok(offset), Ok(size)) = (b.u32().await, b.u64().await, b.u64().await)
                else {
                    break;
                };
                out.push(CpuData {
                    section,
                    cpu,
                    offset,
                    size,
                });
            }
        }
        if id == 0 {
            break;
        }
        cx.checkpoint().await;
    }
}

type SectionState = (Trace, Span, Span, Span, u16, u16, u64, Arc<Vec<CpuData>>);

async fn section_node(
    cx: Cx,
    (trace, whole, data, contents, id, flags, offset, cpus): SectionState,
) -> Result<()> {
    let block = cx.block(whole.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &block, trace.endian);
    f.u16("ID").enumeration(SECTIONS).emit()?;
    f.u16("Flags").flags(SECTION_FLAGS).emit()?;
    f.u32("Description")
        .hex()
        .desc("Offset of the description in the strings")
        .emit()?;
    f.u64("Size").emit()?;
    let compressed = flags & 1 != 0;
    if compressed && id != SEC_BUFFER && id != SEC_BUFFER_TEXT {
        let block = cx.block(data.sub(0, 8)).await?;
        let mut f = Fields::emitting(&cx, &block, trace.endian);
        f.u32("Compressed size").emit()?;
        f.u32("Uncompressed size").emit()?;
    }
    let input = trace.input;
    let e = trace.endian;
    match id {
        SEC_OPTIONS => cx.emit(
            Node::new("Options")
                .span(contents)
                .lazy(options_list, (trace.clone(), contents, true, 0u64)),
        ),
        SEC_HEADER_INFO => cx.emit(
            Node::new("Header Info")
                .span(contents)
                .lazy(header_info, (input, contents, e)),
        ),
        SEC_FTRACE => cx.emit(
            Node::new("Ftrace Event Formats")
                .span(contents)
                .lazy(ftrace_list, (input, contents, e)),
        ),
        SEC_EVENTS => cx.emit(
            Node::new("Event Formats")
                .span(contents)
                .lazy(event_systems, (input, contents, e)),
        ),
        SEC_KALLSYMS => cx.emit(sized_text("Kallsyms", input, contents, 4, e)),
        SEC_PRINTK => cx.emit(sized_text("Trace Printk Formats", input, contents, 4, e)),
        SEC_CMDLINES => cx.emit(sized_text("Saved Command Lines", input, contents, 8, e)),
        SEC_STRINGS => cx.emit(Node::new("Strings").span(contents).lazy(cstrings, contents)),
        SEC_BUFFER => {
            let file = input.span;
            for c in cpus.iter().filter(|c| c.section == offset) {
                let span = file.sub(c.offset, c.size);
                let name = format!("CPU {}", c.cpu);
                if compressed {
                    match chunked(&cx, &trace, span).await {
                        Ok(decoded) => cx.emit(
                            cpu_node(&trace, name, decoded)
                                .summary(format!("{} compressed", size(span.len))),
                        ),
                        Err(err) => cx.emit(Node::new(name).span(span).diag(err)),
                    }
                } else {
                    cx.emit(cpu_node(&trace, name, span));
                }
            }
        }
        SEC_BUFFER_TEXT => cx.emit(embedded_as(
            "Latency Trace",
            input.nested(contents),
            &plain::FORMAT,
        )),
        _ => cx.emit(Node::new("Data").span(contents)),
    }
    Ok(())
}

/// A CPU's compressed trace data: a chunk count, then chunks (compressed
/// size, uncompressed size, stream), decoded into one source.
async fn chunked(cx: &Cx, trace: &Trace, span: Span) -> Result<Span> {
    let Some(codec) = &trace.codec else {
        return Err(Diagnostic::unsupported(
            "compressed trace data without a codec",
        ));
    };
    let mut cur = Cursor::new(cx, span, trace.endian);
    let n = cur.u32().await?;
    let mut pieces = Vec::new();
    for _ in 0..n {
        let csize = cur.u32().await?;
        let usize_ = cur.u32().await?;
        let stream = cur.span(csize.into());
        if stream.len < u64::from(csize) {
            return Err(Diagnostic::truncated(stream, stream.len));
        }
        cur.skip(csize.into());
        pieces.push(cx.decode_lazy(stream, codec, usize_.into())?);
        cx.checkpoint().await;
    }
    cx.add_pieces(
        Origin {
            parent: span,
            transform: "trace-cmd chunks",
        },
        pieces,
    )
}

// ---------------------------------------------------------------------------
// Options.

async fn options_list(cx: Cx, (trace, span, v7, _start): (Trace, Span, bool, u64)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, trace.endian);
    while cur.remaining() >= 2 {
        let at = cur.pos();
        let id = cur.u16().await?;
        if id == 0 && !v7 {
            cx.push(Node::new("End").span(cur.since(at)).value(uint(0u8, 16)))
                .await;
            break;
        }
        let n = cur.u32().await?;
        let body = cur.span(n.into());
        if body.len < u64::from(n) {
            return Err(Diagnostic::truncated(body, body.len));
        }
        cur.skip(n.into());
        let whole = cur.since(at);
        let name = lookup(OPTIONS, id.into()).unwrap_or("unknown");
        let node = option_node(&cx, &trace, id, name, whole, body).await;
        cx.push(node).await;
        if id == 0 {
            break;
        }
    }
    Ok(())
}

async fn option_node(cx: &Cx, trace: &Trace, id: u16, name: &str, whole: Span, body: Span) -> Node {
    let node = Node::new(name.to_string()).span(whole);
    let b = cx.read(body.sub(0, MAX_TEXT)).await.unwrap_or_default();
    let e = trace.endian;
    match id {
        1 | 2 | 4 | 5 | 6 | 7 | 9 | 10 => {
            let s = crate::text::until_nul(&b);
            let s = s.trim_end();
            let summary = s.lines().next().unwrap_or("").to_string();
            node.value(text(clip(s, 4096))).summary(clip(&summary, 80))
        }
        0 | 16..=21 => match get::<u64>(&b, 0, e) {
            Some(off) => {
                let mut n = node.value(hex(off, 64));
                if off != 0 {
                    n = n.target(trace.input.span.sub(off, 16));
                }
                if id == 0 {
                    n.summary(if off == 0 {
                        "no more options sections".to_string()
                    } else {
                        "offset of the next options section".to_string()
                    })
                } else {
                    n.summary("section offset")
                }
            }
            None => node,
        },
        8 => node.value(get::<u32>(&b, 0, e).map_or(Value::Bytes(Vec::new()), |v| uint(v, 32))),
        11 => node.value(get::<u64>(&b, 0, e).map_or(Value::Bytes(Vec::new()), |v| hex(v, 64))),
        3 => node.lazy(buffer_option, (body, e)),
        14 => node.lazy(tsc2nsec, (body, e)),
        _ => node.summary(size(body.len)),
    }
}

async fn buffer_option(cx: Cx, (body, e): (Span, Endian)) -> Result<()> {
    let block = cx.block(body).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    // Version 6 writes only an offset and a name.
    f.u64("Offset").hex().emit()?;
    f.cstr("Instance").emit()?;
    if f.remaining() == 0 {
        return Ok(());
    }
    f.cstr("Clock").emit()?;
    f.u32("Page size").emit()?;
    let n = f.u32("CPUs").emit()?;
    for _ in 0..n.min(4096) {
        if f.remaining() < 20 {
            break;
        }
        f.u32("CPU").emit()?;
        f.u64("Data offset").hex().emit()?;
        f.u64("Data size").emit()?;
    }
    Ok(())
}

async fn tsc2nsec(cx: Cx, (body, e): (Span, Endian)) -> Result<()> {
    let block = cx.block(body).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.u32("Multiplier").emit()?;
    f.u32("Shift").emit()?;
    f.u64("Offset").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// CPU data: ring-buffer pages and events.

fn cpu_node(trace: &Trace, name: String, span: Span) -> Node {
    let pages = span.len.div_ceil(trace.page.max(1));
    Node::new(name)
        .span(span)
        .summary(plural(pages, "page"))
        .lazy(cpu_pages, (trace.clone(), span))
}

async fn cpu_pages(cx: Cx, (trace, span): (Trace, Span)) -> Result<()> {
    let page = trace.page.max(1);
    let count = span.len.div_ceil(page);
    cx.set_count(Count::Exact(count));
    let data_off = page_data_offset(&cx, &trace).await;
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let pspan = span.sub(i.saturating_mul(page), page);
        let h = cx.read(pspan.sub(0, data_off)).await?;
        let ts = get::<u64>(&h, 0, trace.endian).unwrap_or(0);
        let commit = read_long(&h, 8, &trace);
        let content = commit & 0x0fff_ffff;
        let missed = commit & (1 << 31) != 0;
        let node = Node::new(format!("Page {i}"))
            .span(pspan)
            .summary(format!(
                "at {}, {} of events{}",
                timestamp(ts),
                size(content),
                if missed { ", events missed before" } else { "" }
            ))
            .lazy(page_events, (trace.clone(), pspan, data_off));
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

fn read_long(b: &[u8], off: usize, trace: &Trace) -> u64 {
    if trace.long == 4 {
        get::<u32>(b, off, trace.endian).map_or(0, u64::from)
    } else {
        get::<u64>(b, off, trace.endian).unwrap_or(0)
    }
}

/// Seconds and nanoseconds, as trace-cmd shows them.
fn timestamp(ns: u64) -> String {
    format!("{}.{:09}", ns / 1_000_000_000, ns % 1_000_000_000)
}

const TYPE_PADDING: u32 = 29;
const TYPE_TIME_EXTEND: u32 = 30;
const TYPE_TIME_STAMP: u32 = 31;

async fn page_events(cx: Cx, (trace, page, data_off): (Trace, Span, u64)) -> Result<()> {
    let block = cx.read(page).await?;
    cx.charge(to_u64(block.len()) / 16).await;
    let e = trace.endian;
    let hblock = cx.block(page.sub(0, data_off)).await?;
    let mut f = Fields::emitting(&cx, &hblock, e);
    f.u64("Timestamp")
        .with(|&v, n| n.summary(timestamp(v)))
        .emit()?;
    let commit = read_long(&block, 8, &trace);
    if trace.long == 4 {
        f.u32("Commit").hex().emit()?;
    } else {
        f.u64("Commit").hex().emit()?;
    }
    let content = (commit & 0x0fff_ffff).min(page.len.saturating_sub(data_off));
    let events = event_map(&cx, &trace).await;
    let mut ts = get::<u64>(&block, 0, e).unwrap_or(0);
    let mut pos = data_off;
    let end = data_off.saturating_add(content);
    let mut index = 0u64;
    while pos.saturating_add(4) <= end {
        let word = get::<u32>(&block, to_usize(pos), e).unwrap_or(0);
        let (type_len, delta) = match e {
            Endian::Little => (word & 0x1f, word >> 5),
            Endian::Big => (word >> 27, word & 0x07ff_ffff),
        };
        let array0 = get::<u32>(&block, to_usize(pos.saturating_add(4)), e).unwrap_or(0);
        let (total, data) = match type_len {
            TYPE_PADDING => {
                let total = if delta == 0 {
                    end.saturating_sub(pos)
                } else {
                    u64::from(array0).saturating_add(4).max(8)
                };
                (total, None)
            }
            TYPE_TIME_EXTEND => {
                ts = ts.saturating_add((u64::from(array0) << 27).saturating_add(delta.into()));
                (8, None)
            }
            TYPE_TIME_STAMP => {
                ts = (u64::from(array0) << 27) | u64::from(delta);
                (8, None)
            }
            0 => {
                let len = u64::from(array0).saturating_sub(4);
                ts = ts.saturating_add(delta.into());
                (
                    8u64.saturating_add(len.next_multiple_of(4)),
                    Some((8u64, len)),
                )
            }
            n => {
                ts = ts.saturating_add(delta.into());
                let len = u64::from(n).saturating_mul(4);
                (4u64.saturating_add(len), Some((4u64, len)))
            }
        };
        let rspan = page.sub(pos, total.min(end.saturating_sub(pos)));
        let node = match data {
            None => Node::new(match type_len {
                TYPE_PADDING => "Padding",
                TYPE_TIME_EXTEND => "Time Extend",
                _ => "Time Stamp",
            })
            .span(rspan)
            .summary(timestamp(ts)),
            Some((hdr, len)) => {
                let payload = page.sub(pos.saturating_add(hdr), len);
                let bytes = block
                    .get(to_usize(payload.offset.saturating_sub(page.offset))..)
                    .and_then(|b| b.get(..to_usize(len)))
                    .unwrap_or_default();
                let id = get::<u16>(bytes, 0, e).unwrap_or(0);
                let fmt = events.by_id.get(&u32::from(id)).cloned();
                let title = match &fmt {
                    Some(f) => format!("[{index}] {}", f.name),
                    None => format!("[{index}] event {id}"),
                };
                let summary = match &fmt {
                    Some(f) => {
                        let mut s = match task(f, &events, bytes, e) {
                            Some(t) => format!("{t} {}", timestamp(ts)),
                            None => timestamp(ts),
                        };
                        let preview = field_preview(f, bytes, e);
                        if !preview.is_empty() {
                            s.push_str(": ");
                            s.push_str(&preview);
                        }
                        s
                    }
                    None => timestamp(ts),
                };
                index = index.saturating_add(1);
                Node::new(title).span(rspan).summary(summary).lazy(
                    event_fields,
                    (trace.clone(), rspan, hdr, fmt.map(|f| (f, ts))),
                )
            }
        };
        cx.push(node).await;
        if total == 0 {
            break;
        }
        pos = pos.saturating_add(total);
    }
    Ok(())
}

/// The task an event was recorded in, as trace-cmd shows it: `comm-pid`
/// (`<idle>-0`, `<...>-pid` when the command line was not saved).
fn task(f: &EventFormat, events: &EventMap, bytes: &[u8], e: Endian) -> Option<String> {
    let fd = f.fields.iter().find(|fd| fd.name == "common_pid")?;
    let pid = match field_value(fd, bytes, e) {
        Value::Int { value, .. } => u32::try_from(value).ok()?,
        Value::UInt { value, .. } => u32::try_from(value).ok()?,
        _ => return None,
    };
    let comm = match events.comms.get(&pid) {
        Some(c) => c.as_str(),
        None if pid == 0 => "<idle>",
        None => "<...>",
    };
    Some(format!("{comm}-{pid}"))
}

/// The first few non-common fields, `name=value`.
fn field_preview(f: &EventFormat, bytes: &[u8], e: Endian) -> String {
    let mut parts = Vec::new();
    for fd in f
        .fields
        .iter()
        .filter(|fd| !fd.name.starts_with("common_"))
        .take(4)
    {
        let v = field_value(fd, bytes, e);
        parts.push(format!("{}={}", fd.name, value_text(&v)));
    }
    clip(&parts.join(" "), 120)
}

fn value_text(v: &Value) -> String {
    match v {
        Value::UInt { value, radix, .. } => match radix {
            crate::value::Radix::Hex => format!("{value:#x}"),
            _ => value.to_string(),
        },
        Value::Int { value, .. } => value.to_string(),
        Value::Text(s) => s.clone(),
        Value::Bytes(b) => format!("{} bytes", b.len()),
        _ => String::new(),
    }
}

/// A field's value from the event's bytes.
fn field_value(fd: &FieldDef, bytes: &[u8], e: Endian) -> Value {
    let off = to_usize(u64::from(fd.offset));
    let sz = to_usize(u64::from(fd.size));
    let raw = bytes.get(off..off.saturating_add(sz)).unwrap_or_default();
    let dynamic = fd.decl.starts_with("__data_loc") || fd.decl.starts_with("__rel_loc");
    if dynamic && fd.size == 4 {
        let v = get::<u32>(raw, 0, e).unwrap_or(0);
        let mut start = to_usize(u64::from(v & 0xffff));
        if fd.decl.starts_with("__rel_loc") {
            start = start.saturating_add(off).saturating_add(sz);
        }
        let len = to_usize(u64::from(v >> 16));
        let data = bytes
            .get(start..start.saturating_add(len))
            .unwrap_or_default();
        return if fd.decl.contains("char") {
            text(crate::text::until_nul(data))
        } else {
            Value::Bytes(data.to_vec())
        };
    }
    if fd.decl.contains('[') {
        if fd.decl.contains("char") {
            return text(crate::text::until_nul(raw));
        }
        let count = fd
            .decl
            .split('[')
            .nth(1)
            .and_then(|r| r.split(']').next())
            .and_then(|n| n.trim().parse::<usize>().ok())
            .filter(|&n| n > 0);
        if let Some(n) = count {
            let w = sz.checked_div(n).unwrap_or(0);
            if matches!(w, 1 | 2 | 4 | 8) {
                let items: Vec<String> = raw
                    .chunks_exact(w)
                    .map(|c| format!("{:#x}", uint_of(c, e)))
                    .collect();
                return text(items.join(", "));
            }
        }
        return Value::Bytes(raw.to_vec());
    }
    if !matches!(sz, 1 | 2 | 4 | 8) || raw.len() != sz {
        return Value::Bytes(raw.to_vec());
    }
    let u = uint_of(raw, e);
    let bits = u8::try_from(sz.saturating_mul(8)).unwrap_or(64);
    if fd.decl.contains('*') {
        hex(u, bits)
    } else if fd.signed {
        let shift = 64u32.saturating_sub(u32::from(bits));
        int(((u << shift) as i64) >> shift, bits)
    } else {
        uint(u, bits)
    }
}

fn uint_of(b: &[u8], e: Endian) -> u64 {
    match b.len() {
        1 => b.first().copied().map_or(0, u64::from),
        2 => get::<u16>(b, 0, e).map_or(0, u64::from),
        4 => get::<u32>(b, 0, e).map_or(0, u64::from),
        8 => get::<u64>(b, 0, e).unwrap_or(0),
        _ => 0,
    }
}

type EventState = (Trace, Span, u64, Option<(Arc<EventFormat>, u64)>);

async fn event_fields(cx: Cx, (trace, span, hdr, fmt): EventState) -> Result<()> {
    let e = trace.endian;
    let b = cx.read(span).await?;
    let word = get::<u32>(&b, 0, e).unwrap_or(0);
    let (type_len, delta) = match e {
        Endian::Little => (word & 0x1f, word >> 5),
        Endian::Big => (word >> 27, word & 0x07ff_ffff),
    };
    cx.emit(
        Node::new("Header")
            .span(span.sub(0, 4))
            .value(hex(word, 32))
            .summary(format!(
                "type_len {type_len}{}, time_delta {delta}",
                if type_len == 0 {
                    " (length follows)"
                } else {
                    ""
                }
            )),
    );
    if hdr == 8 {
        cx.emit(
            Node::new("Length")
                .span(span.sub(4, 4))
                .value(uint(get::<u32>(&b, 4, e).unwrap_or(0), 32)),
        );
    }
    let payload = span.tail(hdr);
    let bytes = b.get(to_usize(hdr)..).unwrap_or_default();
    let Some((fmt, ts)) = fmt else {
        cx.emit(Node::new("Data").span(payload));
        return Ok(());
    };
    cx.emit(
        Node::new("Event")
            .value(text(format!("{}:{}", fmt.system, fmt.name)))
            .summary(timestamp(ts)),
    );
    for fd in &fmt.fields {
        let v = field_value(fd, bytes, e);
        cx.emit(
            Node::new(fd.name.clone())
                .span(payload.sub(fd.offset.into(), fd.size.into()))
                .value(v)
                .desc(fd.decl.clone()),
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used, clippy::indexing_slicing)]
    use super::*;

    #[test]
    fn fields_parse() {
        let f = parse_fields(
            "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
             \tfield:__data_loc char[] filename;\toffset:8;\tsize:4;\tsigned:0;\n\
             \tfield:char comm[16];\toffset:12;\tsize:16;\tsigned:0;\n",
        );
        assert_eq!(f.len(), 3);
        assert_eq!(f[0].name, "common_type");
        assert_eq!(f[1].name, "filename");
        assert_eq!(f[2].name, "comm");
        assert_eq!(f[2].size, 16);
    }

    /// Events name their task the way `trace-cmd report` does.
    #[test]
    fn events_name_their_task() {
        let fmt = EventFormat {
            system: "raw_syscalls".to_string(),
            name: "sys_enter".to_string(),
            fields: parse_fields(
                "\tfield:unsigned short common_type;\toffset:0;\tsize:2;\tsigned:0;\n\
                 \tfield:int common_pid;\toffset:4;\tsize:4;\tsigned:1;\n",
            ),
        };
        let mut comms = std::collections::BTreeMap::new();
        comms.insert(118, "ffls".to_string());
        let map = EventMap {
            by_id: std::collections::BTreeMap::new(),
            comms,
        };
        let event = |pid: u32| {
            let mut b = vec![24, 0, 0, 0];
            b.extend_from_slice(&pid.to_le_bytes());
            task(&fmt, &map, &b, Endian::Little)
        };
        assert_eq!(event(118).as_deref(), Some("ffls-118"));
        assert_eq!(event(0).as_deref(), Some("<idle>-0"));
        assert_eq!(event(7).as_deref(), Some("<...>-7"));
    }
}
