//! .NET EventPipe traces (`.nettrace`), as written by the runtime
//! (`DOTNET_EnableEventPipe`, `dotnet-trace`) and by TraceEvent.
//!
//! Formats 4 and 5 are a `FastSerialization` object stream: after the
//! `Nettrace` magic and the `!FastSerialization.1` header come objects,
//! each a begin tag, a type (its own small object: version, minimum reader
//! version, name), a payload and an end tag; a null tag ends the stream.
//! The first object is the `Trace` (start time, clock, pointer size,
//! process); then `MetadataBlock`, `StackBlock`, `EventBlock` and `SPBlock`
//! (sequence point) objects, whose payloads are a size, padding to a
//! 4-byte stream offset and the block. Event and metadata blocks hold
//! events with a header (thread, stack, timestamp, sequence number,
//! activity IDs) that is usually compressed: a flags byte says which
//! fields differ from the previous event's, and those follow as LEB128
//! deltas. A metadata event's payload describes an event type: provider,
//! event ID and name, keywords, level and payload fields (format 5 adds
//! tags: opcode, and field lists with arrays).
//!
//! Format 6 drops `FastSerialization`: a 12-byte version header, then
//! blocks with a 24-bit size and a kind byte; metadata rows have their own
//! UTF-8 encoding, thread, label-list and remove-thread blocks are new, and
//! an end-of-stream block closes the trace.
//!
//! Events are named from the metadata (indexed once per file); payloads
//! are decoded field by field while the field types are plain (integers,
//! floats, GUIDs, strings), the rest shown raw. Stacks are lists of
//! instruction pointers.
//!
//! Layouts from TraceEvent's `NetTraceFormat_v5.md` and `NetTraceFormat.md`
//! (MIT, PerfView repository). Formats 4/5 were checked against traces the
//! .NET 8 runtime wrote; no writer of format 6 was at hand (the runtime
//! still writes format 4/5), so the format 6 path follows the document
//! only and its fixture is synthetic.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::Reader;
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const LE: Endian = Endian::Little;
/// Largest metadata block read whole when indexing.
const MAX_META_BLOCK: u64 = 64 << 20;
/// Bytes read for one event header (a compressed one is at most ~90).
const HEADER_WINDOW: u64 = 128;
/// Payload fields decoded per event.
const MAX_FIELDS: usize = 256;
/// Characters of a string field shown.
const TEXT_MAX: usize = 512;

pub static FORMAT: Format = Format {
    name: "nettrace",
    title: ".NET EventPipe trace",
    extensions: &["nettrace"],
    mime: "application/x-nettrace",
    probe: Probe::Magic(&[(0, b"Nettrace")]),
    dissect: crate::expander!(dissect: Input),
};

/// The two container layouts.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ver {
    /// Formats 4 and 5: `FastSerialization` objects.
    Fs,
    /// Format 6: plain blocks.
    V6,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Trace,
    Event,
    Metadata,
    Stack,
    SequencePoint,
    Thread,
    RemoveThread,
    LabelList,
    End,
    Other,
}

impl Kind {
    fn name(self) -> &'static str {
        match self {
            Kind::Trace => "Trace",
            Kind::Event => "EventBlock",
            Kind::Metadata => "MetadataBlock",
            Kind::Stack => "StackBlock",
            Kind::SequencePoint => "SequencePointBlock",
            Kind::Thread => "ThreadBlock",
            Kind::RemoveThread => "RemoveThreadBlock",
            Kind::LabelList => "LabelListBlock",
            Kind::End => "End of stream",
            Kind::Other => "Unknown block",
        }
    }
}

const V6_KIND: EnumTable = &[
    (0, "EndOfStream"),
    (1, "Trace"),
    (2, "Event"),
    (3, "Metadata"),
    (4, "SequencePoint"),
    (5, "StackBlock"),
    (6, "Thread"),
    (7, "RemoveThread"),
    (8, "LabelList"),
];

/// A block (format 6) or object (formats 4/5).
#[derive(Clone, Copy, Debug)]
struct Blk {
    kind: Kind,
    /// The whole block or object, tags included.
    span: Span,
    /// Its content.
    body: Span,
    /// Where the content starts relative to the block (header, type, size,
    /// padding).
    head: u64,
    /// Format 4/5: the padding before the content.
    pad: u64,
}

/// What every expander needs to know about the trace.
#[derive(Clone, Copy, Debug)]
struct Ctx {
    input: Input,
    ver: Ver,
    /// Pointer size, for stacks.
    ptr: u64,
    /// The clock: sync timestamp and ticks per second.
    sync: u64,
    freq: u64,
}

impl Ctx {
    /// Seconds from the trace's start.
    fn seconds(&self, ts: u64) -> Option<f64> {
        if self.freq == 0 {
            return None;
        }
        let delta = i128::from(ts).saturating_sub(i128::from(self.sync));
        Some(delta as f64 / self.freq as f64)
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 40)).await?;
    let ver = if u32_le(&head, 8) == Some(0) {
        Ver::V6
    } else {
        Ver::Fs
    };
    let first = match ver {
        Ver::V6 => {
            cx.emit(struct_node(
                "Stream header",
                file.sub(0, 20),
                LE,
                (),
                |f: &mut Fields<'_>, _: &()| {
                    f.ascii("Magic", 8).emit()?;
                    f.u32("Reserved").emit()?;
                    f.u32("MajorVersion").emit()?;
                    f.u32("MinorVersion").emit()?;
                    Ok(())
                },
            ));
            20
        }
        Ver::Fs => {
            let len = u32_le(&head, 8).unwrap_or(0).min(64);
            let end = 12u64.saturating_add(len.into());
            cx.emit(struct_node(
                "Stream header",
                file.sub(0, end),
                LE,
                len,
                |f: &mut Fields<'_>, &len: &u32| {
                    f.ascii("Magic", 8).emit()?;
                    f.u32("Serializer name length").emit()?;
                    f.ascii("Serializer", len.into())
                        .desc("FastSerialization version the object stream follows")
                        .emit()?;
                    Ok(())
                },
            ));
            end
        }
    };

    // The trace object comes first; it sets the clock and pointer size.
    let mut ctx = Ctx {
        input,
        ver,
        ptr: 8,
        sync: 0,
        freq: 0,
    };
    let mut pos = first;
    let mut summary = match ver {
        Ver::V6 => {
            let major = u32_le(&head, 12).unwrap_or(0);
            let minor = u32_le(&head, 16).unwrap_or(0);
            format!(".NET EventPipe trace, NetTrace {major}.{minor}")
        }
        Ver::Fs => ".NET EventPipe trace, NetTrace 4/5 (FastSerialization)".to_owned(),
    };
    let mut blocks = 0u64;
    let mut ended = false;
    while pos < file.len {
        cx.progress_in(file, pos);
        let blk = match read_block(&cx, file, ver, pos).await {
            Ok(b) => b,
            Err(e) => {
                cx.diag(e);
                break;
            }
        };
        if blk.kind == Kind::Trace {
            let t = trace_info(&cx, &ctx, blk).await?;
            ctx.ptr = t.ptr;
            ctx.sync = t.sync;
            ctx.freq = t.freq;
            summary.push_str(&t.summary);
        }
        let node = block_node(&cx, ctx, blk).await?;
        cx.push(node).await;
        blocks = blocks.saturating_add(1);
        let next = blk
            .span
            .offset
            .saturating_sub(file.offset)
            .saturating_add(blk.span.len);
        if next <= pos {
            break;
        }
        pos = next;
        if blk.kind == Kind::End {
            ended = true;
            break;
        }
    }
    if ended && pos < file.len {
        cx.diag(
            Diagnostic::note(format!(
                "{} bytes after the end of the stream",
                file.len.saturating_sub(pos)
            ))
            .at(file.sub(pos, file.len.saturating_sub(pos))),
        );
    } else if !ended {
        cx.diag(Diagnostic::note(
            "the stream has no end marker (trace cut short?)",
        ));
    }
    cx.annotate(format!("{summary}, {}", plural(blocks, "block")));
    Ok(())
}

/// Reads the block or object at `pos`.
async fn read_block(cx: &Cx, file: Span, ver: Ver, pos: u64) -> Result<Blk> {
    match ver {
        Ver::V6 => {
            let h = cx.read(file.sub_exact(pos, 4)?).await?;
            let x = u32_le(&h, 0).unwrap_or(0);
            let size = u64::from(x & 0x00ff_ffff);
            let kind = match x >> 24 {
                0 => Kind::End,
                1 => Kind::Trace,
                2 => Kind::Event,
                3 => Kind::Metadata,
                4 => Kind::SequencePoint,
                5 => Kind::Stack,
                6 => Kind::Thread,
                7 => Kind::RemoveThread,
                8 => Kind::LabelList,
                _ => Kind::Other,
            };
            let span = file.sub_exact(pos, size.saturating_add(4))?;
            Ok(Blk {
                kind,
                span,
                body: span.sub(4, size),
                head: 4,
                pad: 0,
            })
        }
        Ver::Fs => {
            let h = cx.read(file.sub(pos, 96)).await?;
            match h.first() {
                Some(1) => {
                    return Ok(Blk {
                        kind: Kind::End,
                        span: file.sub(pos, 1),
                        body: file.sub(pos.saturating_add(1), 0),
                        head: 1,
                        pad: 0,
                    });
                }
                Some(5) => {}
                Some(&t) => {
                    return Err(Diagnostic::malformed(format!(
                        "unexpected tag {t} where an object starts"
                    ))
                    .at(file.sub(pos, 1)));
                }
                None => return Err(Diagnostic::truncated(file.sub(pos, 1), 0)),
            }
            if h.get(1) != Some(&5) || h.get(2) != Some(&1) {
                return Err(Diagnostic::malformed(
                    "object type does not start with a begin tag and a null type",
                )
                .at(file.sub(pos, 3)));
            }
            let nlen = u32_le(&h, 11).unwrap_or(0);
            if nlen > 64 {
                return Err(Diagnostic::malformed(format!("type name of {nlen} bytes"))
                    .at(file.sub(pos.saturating_add(11), 4)));
            }
            let name_end = 15usize.saturating_add(to_usize(nlen.into()));
            let name = h.get(15..name_end).unwrap_or_default();
            if h.get(name_end) != Some(&6) {
                return Err(Diagnostic::malformed("type object without its end tag")
                    .at(file.sub(pos, to_u64(name_end))));
            }
            let after_type = pos.saturating_add(to_u64(name_end)).saturating_add(1);
            let kind = match name {
                b"Trace" => Kind::Trace,
                b"EventBlock" => Kind::Event,
                b"MetadataBlock" => Kind::Metadata,
                b"StackBlock" => Kind::Stack,
                b"SPBlock" => Kind::SequencePoint,
                _ => Kind::Other,
            };
            if kind == Kind::Trace {
                // The trace object's fields, then its end tag.
                let span =
                    file.sub_exact(pos, after_type.saturating_sub(pos).saturating_add(49))?;
                return Ok(Blk {
                    kind,
                    span,
                    body: file.sub(after_type, 48),
                    head: after_type.saturating_sub(pos),
                    pad: 0,
                });
            }
            let sb = cx.read(file.sub_exact(after_type, 4)?).await?;
            let size = u64::from(u32_le(&sb, 0).unwrap_or(0));
            let content = after_type.saturating_add(4);
            // Padding to a 4-byte stream offset.
            let pad = (4u64.saturating_sub(content % 4)) % 4;
            let body_at = content.saturating_add(pad);
            let total = body_at
                .saturating_add(size)
                .saturating_add(1)
                .saturating_sub(pos);
            let span = file.sub_exact(pos, total)?;
            Ok(Blk {
                kind,
                span,
                body: file.sub(body_at, size),
                head: body_at.saturating_sub(pos),
                pad,
            })
        }
    }
}

struct TraceInfo {
    ptr: u64,
    sync: u64,
    freq: u64,
    summary: String,
}

/// The fields of the trace object that the rest of the dissection needs.
async fn trace_info(cx: &Cx, ctx: &Ctx, blk: Blk) -> Result<TraceInfo> {
    let b = cx.read(blk.body.sub(0, 52)).await?;
    let short = |i: usize| u16_le(&b, i.saturating_mul(2)).unwrap_or(0);
    let ptr = u64::from(u32_le(&b, 32).unwrap_or(8));
    let mut summary = String::new();
    summary.push_str(&format!(
        ", started {:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03} UTC",
        short(0),
        short(1),
        short(3),
        short(4),
        short(5),
        short(6),
        short(7)
    ));
    if ctx.ver == Ver::Fs {
        summary.push_str(&format!(", process {}", u32_le(&b, 36).unwrap_or(0)));
    }
    Ok(TraceInfo {
        ptr: if ptr == 4 || ptr == 8 { ptr } else { 8 },
        sync: u64_le(&b, 16).unwrap_or(0),
        freq: u64_le(&b, 24).unwrap_or(0),
        summary,
    })
}

/// A top-level node for a block, with a summary from its header.
async fn block_node(cx: &Cx, ctx: Ctx, blk: Blk) -> Result<Node> {
    let mut node = Node::new(blk.kind.name()).span(blk.span);
    let summary = match blk.kind {
        Kind::Event | Kind::Metadata => {
            let h = cx.read(blk.body.sub(0, 20)).await?;
            let flags = u16_le(&h, 2).unwrap_or(0);
            let (min, max) = (u64_le(&h, 4).unwrap_or(0), u64_le(&h, 12).unwrap_or(0));
            let mut s = format!("{} bytes", blk.body.len);
            if blk.kind == Kind::Event
                && let (Some(a), Some(b)) = (ctx.seconds(min), ctx.seconds(max))
            {
                s.push_str(&format!(", {a:.6}–{b:.6} s"));
            }
            if ctx.ver == Ver::Fs || blk.kind == Kind::Event {
                s.push_str(if flags & 1 != 0 {
                    ", compressed headers"
                } else {
                    ", uncompressed headers"
                });
            }
            Some(s)
        }
        Kind::Stack => {
            let h = cx.read(blk.body.sub(0, 8)).await?;
            let first = u32_le(&h, 0).unwrap_or(0);
            let count = u32_le(&h, 4).unwrap_or(0);
            Some(format!(
                "{}, IDs {first}–{}",
                plural(count, "stack"),
                u64::from(first)
                    .saturating_add(u64::from(count))
                    .saturating_sub(1)
            ))
        }
        Kind::SequencePoint => {
            let h = cx.read(blk.body.sub(0, 16)).await?;
            let ts = u64_le(&h, 0).unwrap_or(0);
            let threads = match ctx.ver {
                Ver::Fs => u32_le(&h, 8).unwrap_or(0),
                Ver::V6 => u32_le(&h, 12).unwrap_or(0),
            };
            Some(match ctx.seconds(ts) {
                Some(s) => format!("{s:.6} s, {}", plural(threads, "thread")),
                None => plural(threads, "thread"),
            })
        }
        Kind::End => None,
        _ => Some(format!("{} bytes", blk.body.len)),
    };
    if let Some(s) = summary {
        node = node.summary(s);
    }
    if blk.kind == Kind::End {
        return Ok(node.desc(match ctx.ver {
            Ver::Fs => "The null tag that ends the object stream",
            Ver::V6 => "The block that ends the stream",
        }));
    }
    if blk.kind == Kind::Other {
        node = node.diag(Diagnostic::unsupported("unknown block or object type").at(blk.span));
    }
    Ok(node.lazy(block, (ctx, blk)))
}

/// Expands a block: its framing, then its content.
async fn block(cx: Cx, (ctx, blk): (Ctx, Blk)) -> Result<()> {
    match ctx.ver {
        Ver::Fs => {
            let type_len = blk.head.saturating_sub(4).saturating_sub(blk.pad);
            let type_span = blk.span.sub(
                0,
                if blk.kind == Kind::Trace {
                    blk.head
                } else {
                    type_len
                },
            );
            cx.emit(struct_node(
                "Object header",
                type_span,
                LE,
                (),
                |f: &mut Fields<'_>, _: &()| {
                    f.u8("BeginPrivateObject").emit()?;
                    f.u8("BeginPrivateObject (type)").emit()?;
                    f.u8("NullReference (type of type)").emit()?;
                    f.u32("Version").emit()?;
                    f.u32("MinimumReaderVersion").emit()?;
                    let n = f.u32("Type name length").emit()?;
                    f.ascii("Type name", n.into()).emit()?;
                    f.u8("EndObject (type)").emit()?;
                    Ok(())
                },
            ));
            if blk.kind != Kind::Trace {
                cx.emit(
                    Node::new("BlockSize")
                        .span(blk.span.sub(type_len, 4))
                        .value(Value::UInt {
                            value: blk.body.len,
                            bits: 32,
                            radix: Radix::Dec,
                        }),
                );
                if blk.pad > 0 {
                    cx.emit(
                        Node::new("Padding")
                            .span(blk.span.sub(type_len.saturating_add(4), blk.pad))
                            .desc("Aligns the block to a 4-byte stream offset"),
                    );
                }
            }
        }
        Ver::V6 => {
            cx.emit(struct_node(
                "Block header",
                blk.span.sub(0, 4),
                LE,
                (),
                |f: &mut Fields<'_>, _: &()| {
                    f.u32("BlockSize and BlockKind")
                        .hex()
                        .with(|&v, n| {
                            let kind = crate::value::lookup(V6_KIND, (v >> 24).into())
                                .unwrap_or("unknown");
                            n.summary(format!("{kind}, {} bytes", v & 0x00ff_ffff))
                        })
                        .emit()?;
                    Ok(())
                },
            ));
        }
    }
    let body = blk.body;
    match blk.kind {
        Kind::Trace => cx.emit(struct_node("Trace", body, LE, ctx.ver, trace_fields)),
        Kind::Event | Kind::Metadata => {
            let h = cx.read(body.sub(0, 2)).await?;
            let hsize = u64::from(u16_le(&h, 0).unwrap_or(20));
            let fixed = if ctx.ver == Ver::V6 && blk.kind == Kind::Metadata {
                // Metadata blocks in format 6: a size and an opaque header.
                hsize.saturating_add(2)
            } else {
                hsize.max(20)
            };
            if ctx.ver == Ver::V6 && blk.kind == Kind::Metadata {
                cx.emit(
                    Node::new("HeaderSize")
                        .span(body.sub(0, 2))
                        .value(Value::UInt {
                            value: hsize,
                            bits: 16,
                            radix: Radix::Dec,
                        }),
                );
                if hsize > 0 {
                    cx.emit(Node::new("Header").span(body.sub(2, hsize)));
                }
                cx.emit(
                    Node::new("Metadata rows")
                        .span(body.tail(fixed))
                        .lazy(meta_rows_v6, (ctx, body, fixed)),
                );
            } else {
                cx.emit(struct_node(
                    "Header",
                    body.sub(0, fixed),
                    LE,
                    (),
                    |f: &mut Fields<'_>, _: &()| {
                        let size = f.u16("HeaderSize").emit()?;
                        f.u16("Flags")
                            .with(|&v, n| {
                                n.summary(if v & 1 != 0 {
                                    "compressed event headers"
                                } else {
                                    "uncompressed event headers"
                                })
                            })
                            .emit()?;
                        f.u64("MinTimestamp").emit()?;
                        f.u64("MaxTimestamp").emit()?;
                        if size > 20 {
                            f.bytes("Reserved", u64::from(size).saturating_sub(20))
                                .emit()?;
                        }
                        Ok(())
                    },
                ));
                let flags = u16_le(&cx.read(body.sub(2, 2)).await?, 0).unwrap_or(0);
                let label = if blk.kind == Kind::Metadata {
                    "Metadata events"
                } else {
                    "Events"
                };
                cx.emit(
                    Node::new(label)
                        .span(body.tail(fixed))
                        .lazy(events, (ctx, blk, fixed, flags & 1 != 0)),
                );
            }
        }
        Kind::Stack => {
            cx.emit(struct_node(
                "Header",
                body.sub(0, 8),
                LE,
                (),
                |f: &mut Fields<'_>, _: &()| {
                    f.u32("FirstId").emit()?;
                    f.u32("Count").emit()?;
                    Ok(())
                },
            ));
            cx.emit(
                Node::new("Stacks")
                    .span(body.tail(8))
                    .lazy(stacks, (ctx, body)),
            );
        }
        Kind::SequencePoint => cx.emit(
            Node::new("Sequence point")
                .span(body)
                .lazy(sequence_point, (ctx, body)),
        ),
        Kind::Thread => cx.emit(Node::new("Threads").span(body).lazy(threads_v6, body)),
        Kind::RemoveThread => cx.emit(
            Node::new("Removed threads")
                .span(body)
                .lazy(remove_threads_v6, body),
        ),
        Kind::LabelList => cx.emit(
            Node::new("Label lists")
                .span(body)
                .lazy(label_lists_v6, body),
        ),
        Kind::End | Kind::Other => {
            if body.len > 0 {
                cx.emit(Node::new("Content").span(body));
            }
        }
    }
    if ctx.ver == Ver::Fs && blk.kind != Kind::End {
        cx.emit(
            Node::new("EndObject")
                .span(blk.span.sub(blk.span.len.saturating_sub(1), 1))
                .value(Value::UInt {
                    value: u64::from(u8_at(
                        &cx.read(blk.span.sub(blk.span.len.saturating_sub(1), 1))
                            .await?,
                        0,
                    )),
                    bits: 8,
                    radix: Radix::Dec,
                })
                .check_tag(6),
        );
    }
    Ok(())
}

fn u8_at(b: &[u8], at: usize) -> u8 {
    b.get(at).copied().unwrap_or(0)
}

trait CheckTag {
    fn check_tag(self, want: u64) -> Self;
}

impl CheckTag for Node {
    fn check_tag(self, want: u64) -> Self {
        match self.value {
            Some(Value::UInt { value, .. }) if value != want => {
                let span = self.span;
                let d = Diagnostic::malformed(format!("expected tag {want}"));
                self.diag(match span {
                    Some(s) => d.at(s),
                    None => d,
                })
            }
            _ => self,
        }
    }
}

fn trace_fields(f: &mut Fields<'_>, ver: &Ver) -> Result<()> {
    f.u16("SyncTimeUTC.Year").emit()?;
    f.u16("SyncTimeUTC.Month").emit()?;
    f.u16("SyncTimeUTC.DayOfWeek").emit()?;
    f.u16("SyncTimeUTC.Day").emit()?;
    f.u16("SyncTimeUTC.Hour").emit()?;
    f.u16("SyncTimeUTC.Minute").emit()?;
    f.u16("SyncTimeUTC.Second").emit()?;
    f.u16("SyncTimeUTC.Millisecond").emit()?;
    f.u64("SyncTimeQPC")
        .desc("Timestamp (in ticks) of the sync time; event timestamps count from the same clock")
        .emit()?;
    f.u64("QPCFrequency").desc("Ticks per second").emit()?;
    f.u32("PointerSize").emit()?;
    match ver {
        Ver::Fs => {
            f.u32("ProcessId").emit()?;
            f.u32("NumberOfProcessors").emit()?;
            f.u32("ExpectedCPUSamplingRate").emit()?;
        }
        Ver::V6 => {
            let n = f.u32("KeyValueCount").emit()?;
            for _ in 0..n.min(4096) {
                let data = f.block().data.get(to_usize(f.pos())..).unwrap_or_default();
                let mut r = Reader::new(data);
                let (key, value) = match (string_v6(&mut r), string_v6(&mut r)) {
                    (Some(k), Some(v)) => (k, v),
                    _ => return Err(Diagnostic::truncated(f.peek_span(1), 0)),
                };
                let span = f.peek_span(to_u64(r.pos()));
                f.node(Node::new(key).span(span).value(Value::Text(value)));
                f.skip(to_u64(r.pos()));
            }
        }
    }
    Ok(())
}

/// A format 6 string: a LEB128 byte count and UTF-8.
fn string_v6(r: &mut Reader<'_>) -> Option<String> {
    let n = usize::try_from(r.uleb()?).ok()?;
    let b = r.bytes(n)?;
    Some(String::from_utf8_lossy(b).into_owned())
}

// ---------------------------------------------------------------------------
// Event headers

/// A decoded event header: the running state of compressed headers.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
struct Header {
    meta: u32,
    seq: u32,
    capture: u64,
    processor: u32,
    thread: u64,
    stack: u32,
    ts: u64,
    activity: [u8; 16],
    related: [u8; 16],
    label: u32,
    size: u32,
    sorted: bool,
}

/// Where a header field was read: name, offset, length.
type Pos = (&'static str, usize, usize);

/// Decodes one event header from `buf`, given the previous one. Returns
/// the header, its length (to the payload) and the positions of the fields
/// present.
fn decode_header(
    buf: &[u8],
    prev: &Header,
    ver: Ver,
    compressed: bool,
) -> Option<(Header, usize, Vec<Pos>)> {
    let mut r = Reader::new(buf);
    let mut h = *prev;
    let mut at = Vec::new();
    let field = |r: &Reader<'_>, name: &'static str, start: usize, at: &mut Vec<Pos>| {
        at.push((name, start, r.pos().saturating_sub(start)));
    };
    if compressed {
        let s = r.pos();
        let flags = r.u8()?;
        field(&r, "Flags", s, &mut at);
        if flags & 1 != 0 {
            let s = r.pos();
            h.meta = u32::try_from(r.uleb()?).ok()?;
            field(&r, "MetadataId", s, &mut at);
        }
        if flags & 2 != 0 {
            let s = r.pos();
            let delta = r.uleb()?;
            h.seq = h.seq.wrapping_add(delta as u32);
            field(&r, "SequenceNumber (delta)", s, &mut at);
            let s = r.pos();
            h.capture = r.uleb()?;
            field(&r, "CaptureThread", s, &mut at);
            let s = r.pos();
            h.processor = r.uleb()? as u32;
            field(&r, "ProcessorNumber", s, &mut at);
        }
        if ver == Ver::V6 || h.meta != 0 {
            h.seq = h.seq.wrapping_add(1);
        }
        if flags & 4 != 0 {
            let s = r.pos();
            h.thread = r.uleb()?;
            field(&r, "Thread", s, &mut at);
        }
        if flags & 8 != 0 {
            let s = r.pos();
            h.stack = r.uleb()? as u32;
            field(&r, "StackId", s, &mut at);
        }
        let s = r.pos();
        h.ts = h.ts.wrapping_add(r.uleb()?);
        field(&r, "TimeStamp (delta)", s, &mut at);
        match ver {
            Ver::Fs => {
                if flags & 16 != 0 {
                    let s = r.pos();
                    h.activity.copy_from_slice(r.bytes(16)?);
                    field(&r, "ActivityId", s, &mut at);
                }
                if flags & 32 != 0 {
                    let s = r.pos();
                    h.related.copy_from_slice(r.bytes(16)?);
                    field(&r, "RelatedActivityId", s, &mut at);
                }
            }
            Ver::V6 => {
                if flags & 16 != 0 {
                    let s = r.pos();
                    h.label = r.uleb()? as u32;
                    field(&r, "LabelListId", s, &mut at);
                }
            }
        }
        h.sorted = flags & 64 != 0;
        if flags & 128 != 0 {
            let s = r.pos();
            h.size = u32::try_from(r.uleb()?).ok()?;
            field(&r, "PayloadSize", s, &mut at);
        }
        return Some((h, r.pos(), at));
    }
    // Uncompressed: fixed fields after the event size.
    let s = r.pos();
    r.int::<u32>(LE)?;
    field(&r, "EventSize", s, &mut at);
    let s = r.pos();
    let meta = r.int::<u32>(LE)?;
    h.meta = meta & 0x7fff_ffff;
    h.sorted = meta & 0x8000_0000 != 0;
    field(&r, "MetadataId", s, &mut at);
    let s = r.pos();
    h.seq = r.int::<u32>(LE)?;
    field(&r, "SequenceNumber", s, &mut at);
    let s = r.pos();
    h.thread = r.int::<u64>(LE)?;
    field(&r, "Thread", s, &mut at);
    let s = r.pos();
    h.capture = r.int::<u64>(LE)?;
    field(&r, "CaptureThread", s, &mut at);
    let s = r.pos();
    h.processor = r.int::<u32>(LE)?;
    field(&r, "ProcessorNumber", s, &mut at);
    let s = r.pos();
    h.stack = r.int::<u32>(LE)?;
    field(&r, "StackId", s, &mut at);
    let s = r.pos();
    h.ts = r.int::<u64>(LE)?;
    field(&r, "TimeStamp", s, &mut at);
    match ver {
        Ver::Fs => {
            let s = r.pos();
            h.activity.copy_from_slice(r.bytes(16)?);
            field(&r, "ActivityId", s, &mut at);
            let s = r.pos();
            h.related.copy_from_slice(r.bytes(16)?);
            field(&r, "RelatedActivityId", s, &mut at);
        }
        Ver::V6 => {
            let s = r.pos();
            h.label = r.int::<u32>(LE)?;
            field(&r, "LabelListId", s, &mut at);
        }
    }
    let s = r.pos();
    h.size = r.int::<u32>(LE)?;
    field(&r, "PayloadSize", s, &mut at);
    Some((h, r.pos(), at))
}

fn guid_text(b: &[u8; 16]) -> String {
    let d1 = u32_le(b, 0).unwrap_or(0);
    let d2 = u16_le(b, 4).unwrap_or(0);
    let d3 = u16_le(b, 6).unwrap_or(0);
    let rest: Vec<String> = b.iter().skip(8).map(|x| format!("{x:02x}")).collect();
    format!(
        "{d1:08x}-{d2:04x}-{d3:04x}-{}-{}",
        rest.get(..2).unwrap_or_default().concat(),
        rest.get(2..).unwrap_or_default().concat()
    )
}

/// One event's header values as a node's children.
fn header_value(h: &Header, name: &str) -> Value {
    let uint = |value: u64, bits: u8| Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    };
    match name {
        "MetadataId" => uint(h.meta.into(), 32),
        "SequenceNumber" | "SequenceNumber (delta)" => uint(h.seq.into(), 32),
        "CaptureThread" => uint(h.capture, 64),
        "ProcessorNumber" => uint(h.processor.into(), 32),
        "Thread" => uint(h.thread, 64),
        "StackId" => uint(h.stack.into(), 32),
        "TimeStamp" | "TimeStamp (delta)" => uint(h.ts, 64),
        "ActivityId" => Value::Text(guid_text(&h.activity)),
        "RelatedActivityId" => Value::Text(guid_text(&h.related)),
        "LabelListId" => uint(h.label.into(), 32),
        "PayloadSize" => uint(h.size.into(), 32),
        _ => Value::Text(String::new()),
    }
}

// ---------------------------------------------------------------------------
// Metadata

/// A payload field's description.
#[derive(Clone, Debug)]
struct FieldDesc {
    name: String,
    ty: u32,
}

/// An event type.
#[derive(Clone, Debug, Default)]
struct Meta {
    provider: String,
    event_id: u32,
    name: String,
    keywords: u64,
    version: u32,
    level: u32,
    opcode: Option<u8>,
    fields: Vec<FieldDesc>,
}

impl Meta {
    fn title(&self) -> String {
        if self.name.is_empty() {
            format!("{}/{}", self.provider, self.event_id)
        } else {
            format!("{}/{}", self.provider, self.name)
        }
    }
}

const LEVEL: EnumTable = &[
    (0, "LogAlways"),
    (1, "Critical"),
    (2, "Error"),
    (3, "Warning"),
    (4, "Informational"),
    (5, "Verbose"),
];

const TYPE_CODE: EnumTable = &[
    (1, "Object"),
    (3, "Boolean"),
    (4, "Char"),
    (5, "SByte"),
    (6, "Byte"),
    (7, "Int16"),
    (8, "UInt16"),
    (9, "Int32"),
    (10, "UInt32"),
    (11, "Int64"),
    (12, "UInt64"),
    (13, "Single"),
    (14, "Double"),
    (15, "Decimal"),
    (16, "DateTime"),
    (17, "Guid"),
    (18, "String"),
    (19, "Array"),
    (20, "VarInt"),
    (21, "VarUInt"),
    (22, "FixedLengthArray"),
    (23, "UTF8CodeUnit"),
    (24, "RelLoc"),
    (25, "DataLoc"),
    (26, "Boolean8"),
];

/// A record of what was parsed, for rendering: label, offset, length,
/// value, nesting level.
type Item = (String, usize, usize, Value, u8);

fn utf16z_at(r: &mut Reader<'_>) -> Option<String> {
    let (s, n, found) = crate::text::utf16z(r.rest(), LE);
    if !found {
        return None;
    }
    r.bytes(n)?;
    Some(s)
}

fn text(s: String) -> Value {
    Value::Text(s)
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

/// A format 4/5 field list (V1 parameters); objects nest.
fn fields_fs(
    r: &mut Reader<'_>,
    out: &mut Vec<FieldDesc>,
    items: &mut Vec<Item>,
    depth: u8,
) -> Option<()> {
    if depth > 8 {
        return None;
    }
    let s = r.pos();
    let count = r.int::<u32>(LE)?;
    items.push(("FieldCount".into(), s, 4, uint(count.into(), 32), depth));
    for _ in 0..count.min(4096) {
        let s = r.pos();
        let ty = r.int::<u32>(LE)?;
        let tname = crate::value::lookup(TYPE_CODE, ty.into()).unwrap_or("?");
        if ty == 1 {
            items.push((
                "TypeCode".into(),
                s,
                4,
                text(format!("{tname} ({ty})")),
                depth,
            ));
            let mut nested = Vec::new();
            fields_fs(r, &mut nested, items, depth.saturating_add(1))?;
        }
        let ns = r.pos();
        let name = utf16z_at(r)?;
        if ty != 1 {
            items.push((
                "Field".into(),
                s,
                r.pos().saturating_sub(s),
                text(format!("{name}: {tname}")),
                depth,
            ));
        } else {
            items.push((
                "FieldName".into(),
                ns,
                r.pos().saturating_sub(ns),
                text(name.clone()),
                depth,
            ));
        }
        if depth == 0 {
            out.push(FieldDesc { name, ty });
        }
    }
    Some(())
}

/// A format 4/5 metadata event's payload.
fn parse_meta_fs(payload: &[u8], items: &mut Vec<Item>) -> Option<(u32, Meta)> {
    let mut r = Reader::new(payload);
    let mut m = Meta::default();
    let s = r.pos();
    let id = r.int::<u32>(LE)?;
    items.push(("MetaDataId".into(), s, 4, uint(id.into(), 32), 0));
    let s = r.pos();
    m.provider = utf16z_at(&mut r)?;
    items.push((
        "ProviderName".into(),
        s,
        r.pos().saturating_sub(s),
        text(m.provider.clone()),
        0,
    ));
    let s = r.pos();
    m.event_id = r.int::<u32>(LE)?;
    items.push(("EventId".into(), s, 4, uint(m.event_id.into(), 32), 0));
    let s = r.pos();
    m.name = utf16z_at(&mut r)?;
    items.push((
        "EventName".into(),
        s,
        r.pos().saturating_sub(s),
        text(m.name.clone()),
        0,
    ));
    let s = r.pos();
    m.keywords = r.int::<u64>(LE)?;
    items.push((
        "Keywords".into(),
        s,
        8,
        Value::UInt {
            value: m.keywords,
            bits: 64,
            radix: Radix::Hex,
        },
        0,
    ));
    let s = r.pos();
    m.version = r.int::<u32>(LE)?;
    items.push(("Version".into(), s, 4, uint(m.version.into(), 32), 0));
    let s = r.pos();
    m.level = r.int::<u32>(LE)?;
    items.push((
        "Level".into(),
        s,
        4,
        Value::Enum {
            raw: m.level.into(),
            bits: 32,
            name: crate::value::lookup(LEVEL, m.level.into()),
        },
        0,
    ));
    if r.at_end() {
        return Some((id, m));
    }
    let mut fields = Vec::new();
    fields_fs(&mut r, &mut fields, items, 0)?;
    m.fields = fields;
    // Format 5 tags: a size, a kind, the payload.
    while r.rest().len() >= 5 {
        let s = r.pos();
        let size = r.int::<u32>(LE)?;
        let kind = r.u8()?;
        let body = r.bytes(usize::try_from(size).ok()?)?;
        match kind {
            1 => {
                m.opcode = body.first().copied();
                items.push((
                    "Tag: OpCode".into(),
                    s,
                    r.pos().saturating_sub(s),
                    uint(m.opcode.unwrap_or(0).into(), 8),
                    0,
                ));
            }
            2 => {
                let mut v2 = Reader::new(body);
                let count = v2.int::<u32>(LE)?;
                let mut list = Vec::new();
                for _ in 0..count.min(4096) {
                    let start = v2.pos();
                    let fsize = usize::try_from(v2.int::<u32>(LE)?).ok()?;
                    let name = utf16z_at(&mut v2)?;
                    let ty = v2.int::<u32>(LE)?;
                    list.push(FieldDesc { name, ty });
                    let end = start.checked_add(fsize)?;
                    if end < v2.pos() {
                        return None;
                    }
                    v2 = Reader::at(body, end);
                }
                items.push((
                    "Tag: V2Params".into(),
                    s,
                    r.pos().saturating_sub(s),
                    text(plural(list.len(), "field")),
                    0,
                ));
                m.fields = list;
            }
            k => items.push((
                format!("Tag {k}"),
                s,
                r.pos().saturating_sub(s),
                text(format!("{size} bytes")),
                0,
            )),
        }
    }
    Some((id, m))
}

/// A format 6 type: the code, then element types, counts or fields.
fn type_v6(r: &mut Reader<'_>, depth: u8) -> Option<u32> {
    if depth > 8 {
        return None;
    }
    let code = u32::from(r.u8()?);
    match code {
        19 | 24 | 25 => {
            type_v6(r, depth.saturating_add(1))?;
        }
        22 => {
            type_v6(r, depth.saturating_add(1))?;
            r.int::<u16>(LE)?;
        }
        1 => {
            let count = r.int::<u16>(LE)?;
            for _ in 0..count {
                let size = usize::from(r.int::<u16>(LE)?);
                r.bytes(size)?;
            }
        }
        _ => {}
    }
    Some(code)
}

/// A format 6 metadata row (after its size).
fn parse_meta_v6(row: &[u8], items: &mut Vec<Item>) -> Option<(u32, Meta)> {
    let mut r = Reader::new(row);
    let mut m = Meta::default();
    let s = r.pos();
    let id = u32::try_from(r.uleb()?).ok()?;
    items.push((
        "MetaDataId".into(),
        s,
        r.pos().saturating_sub(s),
        uint(id.into(), 32),
        0,
    ));
    let s = r.pos();
    m.provider = string_v6(&mut r)?;
    items.push((
        "ProviderName".into(),
        s,
        r.pos().saturating_sub(s),
        text(m.provider.clone()),
        0,
    ));
    let s = r.pos();
    m.event_id = u32::try_from(r.uleb()?).ok()?;
    items.push((
        "EventId".into(),
        s,
        r.pos().saturating_sub(s),
        uint(m.event_id.into(), 32),
        0,
    ));
    let s = r.pos();
    m.name = string_v6(&mut r)?;
    items.push((
        "EventName".into(),
        s,
        r.pos().saturating_sub(s),
        text(m.name.clone()),
        0,
    ));
    let s = r.pos();
    let count = r.int::<u16>(LE)?;
    items.push(("FieldCount".into(), s, 2, uint(count.into(), 16), 0));
    for _ in 0..count {
        let s = r.pos();
        let size = usize::from(r.int::<u16>(LE)?);
        let body = r.bytes(size)?;
        let mut fr = Reader::new(body);
        let name = string_v6(&mut fr)?;
        let ty = type_v6(&mut fr, 0)?;
        let tname = crate::value::lookup(TYPE_CODE, ty.into()).unwrap_or("?");
        items.push((
            "Field".into(),
            s,
            r.pos().saturating_sub(s),
            text(format!("{name}: {tname}")),
            0,
        ));
        m.fields.push(FieldDesc { name, ty });
    }
    let s = r.pos();
    let osize = usize::from(r.int::<u16>(LE)?);
    let opt = r.bytes(osize)?;
    let mut o = Reader::new(opt);
    while !o.at_end() {
        let os = o.pos();
        let kind = o.u8()?;
        let (label, value) = match kind {
            1 => {
                m.opcode = Some(o.u8()?);
                ("OpCode".to_owned(), uint(m.opcode.unwrap_or(0).into(), 8))
            }
            3 => {
                m.keywords = o.int::<u64>(LE)?;
                (
                    "Keywords".to_owned(),
                    Value::UInt {
                        value: m.keywords,
                        bits: 64,
                        radix: Radix::Hex,
                    },
                )
            }
            4 => ("MessageTemplate".to_owned(), text(string_v6(&mut o)?)),
            5 => ("Description".to_owned(), text(string_v6(&mut o)?)),
            6 => {
                let k = string_v6(&mut o)?;
                let v = string_v6(&mut o)?;
                (k, text(v))
            }
            7 => {
                let mut g = [0u8; 16];
                g.copy_from_slice(o.bytes(16)?);
                ("ProviderGuid".to_owned(), text(guid_text(&g)))
            }
            8 => {
                m.level = o.u8()?.into();
                (
                    "Level".to_owned(),
                    Value::Enum {
                        raw: m.level.into(),
                        bits: 8,
                        name: crate::value::lookup(LEVEL, m.level.into()),
                    },
                )
            }
            9 => {
                m.version = o.u8()?.into();
                ("Version".to_owned(), uint(m.version.into(), 8))
            }
            _ => return Some((id, m)),
        };
        let base = s.saturating_add(2);
        items.push((
            label,
            base.saturating_add(os),
            o.pos().saturating_sub(os),
            value,
            0,
        ));
    }
    Some((id, m))
}

/// Every event type in the trace, by ID and the offset of the block that
/// defined it (format 6 may reuse IDs after a metadata flush).
#[derive(Default)]
struct MetaIndex {
    map: BTreeMap<(u32, u64), Arc<Meta>>,
}

impl MetaIndex {
    fn find(&self, id: u32, before: u64) -> Option<Arc<Meta>> {
        self.map
            .range(..(id, before))
            .next_back()
            .filter(|((i, _), _)| *i == id)
            .map(|(_, m)| m.clone())
    }
}

/// Builds (once) the metadata index: walks the blocks and parses the
/// metadata ones.
async fn meta_index(cx: &Cx, ctx: &Ctx) -> Result<Arc<MetaIndex>> {
    let file = ctx.input.span;
    if let Some(found) = cx.cached::<MetaIndex>(file, "nettrace-meta") {
        return Ok(found);
    }
    let head = cx.read(file.sub(0, 16)).await?;
    let mut pos = match ctx.ver {
        Ver::V6 => 20,
        Ver::Fs => 12u64.saturating_add(u32_le(&head, 8).unwrap_or(0).min(64).into()),
    };
    let mut index = MetaIndex::default();
    while pos < file.len {
        let Ok(blk) = read_block(cx, file, ctx.ver, pos).await else {
            break;
        };
        if blk.kind == Kind::Metadata && blk.body.len <= MAX_META_BLOCK {
            let body = cx.read(blk.body).await?;
            let at = blk.span.offset;
            match ctx.ver {
                Ver::Fs => {
                    let hsize = usize::from(u16_le(&body, 0).unwrap_or(20)).max(20);
                    let compressed = u16_le(&body, 2).unwrap_or(0) & 1 != 0;
                    let mut p = hsize;
                    let mut prev = Header::default();
                    while p < body.len() {
                        let Some((h, hl, _)) = decode_header(
                            body.get(p..).unwrap_or_default(),
                            &prev,
                            ctx.ver,
                            compressed,
                        ) else {
                            break;
                        };
                        let start = p.saturating_add(hl);
                        let end = start.saturating_add(to_usize(h.size.into()));
                        let Some(payload) = body.get(start..end) else {
                            break;
                        };
                        if let Some((id, m)) = parse_meta_fs(payload, &mut Vec::new()) {
                            index.map.insert((id, at), Arc::new(m));
                        }
                        p = if compressed {
                            end
                        } else {
                            align4(end, blk.body.offset, file.offset)
                        };
                        prev = h;
                        cx.charge((to_u64(payload.len()) / 16).saturating_add(1))
                            .await;
                    }
                }
                Ver::V6 => {
                    let hsize = usize::from(u16_le(&body, 0).unwrap_or(0));
                    let mut p = hsize.saturating_add(2);
                    while let Some(size) = u16_le(&body, p) {
                        let start = p.saturating_add(2);
                        let end = start.saturating_add(usize::from(size));
                        let Some(row) = body.get(start..end) else {
                            break;
                        };
                        if let Some((id, m)) = parse_meta_v6(row, &mut Vec::new()) {
                            index.map.insert((id, at), Arc::new(m));
                        }
                        p = end;
                        cx.charge((to_u64(row.len()) / 16).saturating_add(1)).await;
                    }
                }
            }
        }
        cx.checkpoint().await;
        let next = blk
            .span
            .offset
            .saturating_sub(file.offset)
            .saturating_add(blk.span.len);
        if next <= pos || blk.kind == Kind::End {
            break;
        }
        pos = next;
    }
    let index = Arc::new(index);
    cx.cache(file, "nettrace-meta", index.clone());
    Ok(index)
}

/// The offset after `end` (relative to the block body at `body_off`)
/// padded to a 4-byte stream offset.
fn align4(end: usize, body_off: u64, file_off: u64) -> usize {
    let abs = body_off
        .saturating_sub(file_off)
        .saturating_add(to_u64(end));
    let pad = (4u64.saturating_sub(abs % 4)) % 4;
    end.saturating_add(to_usize(pad))
}

// ---------------------------------------------------------------------------
// Events

type EventsState = (Ctx, Blk, u64, bool);

/// The events of an event or metadata block.
async fn events(cx: Cx, (ctx, blk, start, compressed): EventsState) -> Result<()> {
    let body = blk.body;
    let index = if blk.kind == Kind::Event {
        Some(meta_index(&cx, &ctx).await?)
    } else {
        None
    };
    let (mut pos, mut prev, mut n) =
        cx.resume::<(u64, Header, u64)>()
            .unwrap_or((start, Header::default(), 0));
    while pos < body.len {
        let at = (pos, prev, n);
        cx.mark(move || at);
        let window = cx.read(body.sub(pos, HEADER_WINDOW)).await?;
        let Some((h, hl, _)) = decode_header(&window, &prev, ctx.ver, compressed) else {
            return Err(Diagnostic::malformed("event header cut short")
                .at(body.sub(pos, to_u64(window.len()))));
        };
        let payload_at = pos.saturating_add(to_u64(hl));
        let end = payload_at.saturating_add(h.size.into());
        if end > body.len {
            return Err(Diagnostic::truncated(
                body.sub(pos, end.saturating_sub(pos)),
                body.len.saturating_sub(pos),
            ));
        }
        let next = if compressed || ctx.ver == Ver::V6 {
            end
        } else {
            to_u64(align4(to_usize(end), body.offset, ctx.input.span.offset))
        };
        let span = body.sub(pos, end.saturating_sub(pos));
        let payload = body.sub(payload_at, u64::from(h.size));
        let node = if blk.kind == Kind::Metadata {
            let bytes = cx.read(payload).await?;
            let parsed = parse_meta_fs(&bytes, &mut Vec::new());
            let name = match &parsed {
                Some((id, m)) => format!("Metadata {id}: {}", m.title()),
                None => format!("Metadata event {n}"),
            };
            let summary = parsed.map(|(_, m)| {
                let fields: Vec<String> = m.fields.iter().map(|f| f.name.clone()).collect();
                if fields.is_empty() {
                    format!("level {}, keywords {:#x}", m.level, m.keywords)
                } else {
                    format!(
                        "level {}, keywords {:#x}, fields: {}",
                        m.level,
                        m.keywords,
                        fields.join(", ")
                    )
                }
            });
            let node = Node::new(name).span(span);
            match summary {
                Some(s) => node.summary(s),
                None => node,
            }
        } else {
            let meta = index.as_ref().and_then(|i| i.find(h.meta, blk.span.offset));
            let name = match &meta {
                Some(m) => m.title(),
                None => format!("Event (metadata {})", h.meta),
            };
            let mut summary = match ctx.seconds(h.ts) {
                Some(s) => format!("{s:.6} s, thread {}", h.thread),
                None => format!("thread {}", h.thread),
            };
            if h.stack != 0 {
                summary.push_str(&format!(", stack {}", h.stack));
            }
            if let Some(m) = &meta
                && !m.fields.is_empty()
            {
                let bytes = cx.read(payload.sub(0, 4096)).await?;
                let items = decode_payload(&bytes, &m.fields, ctx.ver);
                let shown: Vec<String> = items
                    .iter()
                    .take(4)
                    .map(|(label, _, _, v, _)| format!("{label}={}", short_value(v)))
                    .collect();
                if !shown.is_empty() {
                    summary.push_str(&format!("; {}", shown.join(" ")));
                }
            } else {
                summary.push_str(&format!(", {} bytes", h.size));
            }
            Node::new(name).span(span).summary(summary)
        };
        cx.push(node.lazy(event, (ctx, blk, pos, prev, compressed)))
            .await;
        prev = h;
        n = n.saturating_add(1);
        if next <= pos {
            break;
        }
        pos = next;
    }
    Ok(())
}

fn short_value(v: &Value) -> String {
    match v {
        Value::Text(s) => format!("{s:?}"),
        Value::UInt { value, .. } => value.to_string(),
        Value::Int { value, .. } => value.to_string(),
        Value::Float(f) => format!("{f}"),
        Value::Bool(b) => b.to_string(),
        _ => "…".to_owned(),
    }
}

type EventState = (Ctx, Blk, u64, Header, bool);

/// One event: its header fields, then its payload.
async fn event(cx: Cx, (ctx, blk, pos, prev, compressed): EventState) -> Result<()> {
    let body = blk.body;
    let window = cx.read(body.sub(pos, HEADER_WINDOW)).await?;
    let Some((h, hl, at)) = decode_header(&window, &prev, ctx.ver, compressed) else {
        return Err(Diagnostic::malformed("event header cut short").at(body.sub(pos, 1)));
    };
    let hspan = body.sub(pos, to_u64(hl));
    let mut header = Node::new("Header").span(hspan);
    let mut parts = Vec::new();
    for (name, off, len) in &at {
        let span = body.sub(pos.saturating_add(to_u64(*off)), to_u64(*len));
        let node = if *name == "Flags" {
            let flags = window.get(*off).copied().unwrap_or(0);
            Node::new(*name)
                .span(span)
                .value(crate::formats::util::val::flagsv(
                    flags,
                    8,
                    if ctx.ver == Ver::Fs {
                        FLAGS_FS
                    } else {
                        FLAGS_V6
                    },
                ))
        } else if *name == "EventSize" {
            Node::new(*name)
                .span(span)
                .value(uint(u32_le(&window, *off).unwrap_or(0).into(), 32))
                .desc("Bytes after this field")
        } else if name.ends_with("(delta)") {
            // The delta as stored: added to the previous value, wrapping,
            // so a "negative" delta is a large number.
            let raw = window
                .get(*off..)
                .and_then(crate::bytes::uleb128)
                .map_or(0, |(v, _)| v);
            let value = if *name == "TimeStamp (delta)" {
                Value::Int {
                    value: i64::from_ne_bytes(raw.to_ne_bytes()),
                    bits: 64,
                }
            } else {
                Value::Int {
                    value: i64::from(i32::from_ne_bytes((raw as u32).to_ne_bytes())),
                    bits: 32,
                }
            };
            Node::new(*name).span(span).value(value)
        } else {
            Node::new(*name).span(span).value(header_value(&h, name))
        };
        parts.push(node);
    }
    if compressed {
        // The values the header implies (deltas applied, fields carried
        // over from the previous event).
        parts.push(Node::new("SequenceNumber").value(header_value(&h, "SequenceNumber")));
        parts.push(Node::new("TimeStamp").value(header_value(&h, "TimeStamp")));
        if !at.iter().any(|(n, _, _)| *n == "Thread") {
            parts.push(
                Node::new("Thread")
                    .value(header_value(&h, "Thread"))
                    .summary("as the previous event"),
            );
        }
        if !at.iter().any(|(n, _, _)| *n == "StackId") {
            parts.push(
                Node::new("StackId")
                    .value(header_value(&h, "StackId"))
                    .summary("as the previous event"),
            );
        }
        if !at.iter().any(|(n, _, _)| *n == "PayloadSize") {
            parts.push(
                Node::new("PayloadSize")
                    .value(header_value(&h, "PayloadSize"))
                    .summary("as the previous event"),
            );
        }
    }
    parts.push(Node::new("IsSorted").value(Value::Bool(h.sorted)));
    if let Some(s) = ctx.seconds(h.ts) {
        parts.push(
            Node::new("Time")
                .value(Value::Float(s))
                .summary("seconds from the trace's sync time"),
        );
    }
    header = header.summary(format!("thread {}, sequence {}", h.thread, h.seq));
    let header_children = parts;
    cx.emit(header.lazy(emit_all, Arc::new(Nodes(header_children))));

    let payload = body.sub(pos.saturating_add(to_u64(hl)), h.size.into());
    if blk.kind == Kind::Metadata {
        let bytes = cx.read(payload).await?;
        let mut items = Vec::new();
        let parsed = parse_meta_fs(&bytes, &mut items);
        let node = Node::new("Metadata").span(payload);
        let node = if parsed.is_none() {
            node.diag(Diagnostic::malformed("metadata payload cut short").at(payload))
        } else {
            node
        };
        cx.emit(node.lazy(emit_items, (payload, Arc::new(items))));
        return Ok(());
    }
    let index = meta_index(&cx, &ctx).await?;
    let meta = index.find(h.meta, blk.span.offset);
    match meta {
        Some(m) if !m.fields.is_empty() => {
            let bytes = cx.read(payload).await?;
            let items = decode_payload(&bytes, &m.fields, ctx.ver);
            cx.charge(to_u64(items.len())).await;
            let used = items
                .iter()
                .map(|(_, o, l, _, _)| o.saturating_add(*l))
                .max()
                .unwrap_or(0);
            let node = Node::new("Payload")
                .span(payload)
                .summary(plural(items.len(), "field"));
            cx.emit(node.lazy(emit_items, (payload, Arc::new(items))));
            if to_u64(used) < payload.len {
                cx.emit(
                    Node::new("Undecoded payload")
                        .span(payload.tail(to_u64(used)))
                        .desc(
                            "Fields of types not decoded here, or data beyond the described fields",
                        ),
                );
            }
        }
        _ => {
            let node = Node::new("Payload")
                .span(payload)
                .summary(format!("{} bytes", payload.len));
            cx.emit(match meta {
                Some(_) => node.desc("The event's metadata describes no fields"),
                None => node.diag(Diagnostic::note(format!("no metadata with ID {}", h.meta))),
            });
        }
    }
    Ok(())
}

const FLAGS_FS: crate::value::FlagTable = &[
    crate::value::flag(1, "MetadataId"),
    crate::value::flag(2, "CaptureThreadAndSequence"),
    crate::value::flag(4, "ThreadId"),
    crate::value::flag(8, "StackId"),
    crate::value::flag(16, "ActivityId"),
    crate::value::flag(32, "RelatedActivityId"),
    crate::value::flag(64, "Sorted"),
    crate::value::flag(128, "DataLength"),
];

const FLAGS_V6: crate::value::FlagTable = &[
    crate::value::flag(1, "MetadataId"),
    crate::value::flag(2, "CaptureThreadAndSequence"),
    crate::value::flag(4, "ThreadIndex"),
    crate::value::flag(8, "StackId"),
    crate::value::flag(16, "LabelListId"),
    crate::value::flag(64, "Sorted"),
    crate::value::flag(128, "DataLength"),
];

/// Decodes payload fields while their types are plain; stops at the first
/// that is not.
fn decode_payload(bytes: &[u8], fields: &[FieldDesc], ver: Ver) -> Vec<Item> {
    let mut r = Reader::new(bytes);
    let mut out = Vec::new();
    for f in fields.iter().take(MAX_FIELDS) {
        let s = r.pos();
        let v = match f.ty {
            3 => r.int::<u32>(LE).map(|v| Value::Bool(v != 0)),
            26 => r.u8().map(|v| Value::Bool(v != 0)),
            4 => r
                .int::<u16>(LE)
                .map(|v| text(String::from_utf16_lossy(&[v]))),
            23 => r.u8().map(|v| text(char::from(v).to_string())),
            5 => r.u8().map(|v| Value::Int {
                value: i64::from(v as i8),
                bits: 8,
            }),
            6 => r.u8().map(|v| uint(v.into(), 8)),
            7 => r.int::<i16>(LE).map(|v| Value::Int {
                value: v.into(),
                bits: 16,
            }),
            8 => r.int::<u16>(LE).map(|v| uint(v.into(), 16)),
            9 => r.int::<i32>(LE).map(|v| Value::Int {
                value: v.into(),
                bits: 32,
            }),
            10 => r.int::<u32>(LE).map(|v| uint(v.into(), 32)),
            11 => r.int::<i64>(LE).map(|v| Value::Int { value: v, bits: 64 }),
            12 => r.int::<u64>(LE).map(|v| uint(v, 64)),
            13 => r.int::<f32>(LE).map(|v| Value::Float(f64::from(v))),
            14 => r.int::<f64>(LE).map(Value::Float),
            17 => r.bytes(16).map(|b| {
                let mut g = [0u8; 16];
                g.copy_from_slice(b);
                text(guid_text(&g))
            }),
            18 => utf16z_at(&mut r).map(|s| text(s.chars().take(TEXT_MAX).collect())),
            20 if ver == Ver::V6 => r.uleb().map(|v| Value::Int {
                value: crate::formats::util::wire::protobuf::zigzag(v),
                bits: 64,
            }),
            21 if ver == Ver::V6 => r.uleb().map(|v| uint(v, 64)),
            _ => None,
        };
        let Some(v) = v else {
            break;
        };
        out.push((f.name.clone(), s, r.pos().saturating_sub(s), v, 0));
    }
    out
}

/// Nodes built in advance, emitted on expansion.
struct Nodes(Vec<Node>);

impl std::fmt::Debug for Nodes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{} nodes", self.0.len())
    }
}

async fn emit_all(cx: Cx, nodes: Arc<Nodes>) -> Result<()> {
    for n in &nodes.0 {
        cx.emit(n.clone());
    }
    Ok(())
}

/// Emits parsed items (label, offset, length, value) as nodes over `base`;
/// items nested in an object description are indented by their level in
/// the label.
async fn emit_items(cx: Cx, (base, items): (Span, Arc<Vec<Item>>)) -> Result<()> {
    for (label, off, len, value, depth) in items.iter() {
        let label = if *depth > 0 {
            format!("{}{label}", "  ".repeat(usize::from(*depth)))
        } else {
            label.clone()
        };
        cx.push(
            Node::new(label)
                .span(base.sub(to_u64(*off), to_u64(*len)))
                .value(value.clone()),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Other blocks

/// Format 6 metadata rows.
async fn meta_rows_v6(cx: Cx, (ctx, body, start): (Ctx, Span, u64)) -> Result<()> {
    let _ = ctx;
    let mut pos = start;
    while pos < body.len {
        let sb = cx.read(body.sub_exact(pos, 2)?).await?;
        let size = u64::from(u16_le(&sb, 0).unwrap_or(0));
        let row = body.sub_exact(pos.saturating_add(2), size)?;
        let bytes = cx.read(row).await?;
        let mut items = vec![("Size".to_owned(), 0usize, 2usize, uint(size, 16), 0u8)];
        let parsed = parse_meta_v6(&bytes, &mut items);
        // Offsets of the row's items are relative to the row; shift them
        // past the size.
        let items: Vec<Item> = items
            .into_iter()
            .enumerate()
            .map(|(i, (l, o, n, v, d))| {
                if i == 0 {
                    (l, o, n, v, d)
                } else {
                    (l, o.saturating_add(2), n, v, d)
                }
            })
            .collect();
        let span = body.sub(pos, size.saturating_add(2));
        let mut node = Node::new(match &parsed {
            Some((id, m)) => format!("Metadata {id}: {}", m.title()),
            None => "Metadata row".to_owned(),
        })
        .span(span);
        if parsed.is_none() {
            node = node.diag(Diagnostic::malformed("metadata row cut short").at(span));
        }
        cx.push(node.lazy(emit_items, (span, Arc::new(items))))
            .await;
        pos = pos.saturating_add(size).saturating_add(2);
    }
    Ok(())
}

async fn stacks(cx: Cx, (ctx, body): (Ctx, Span)) -> Result<()> {
    let h = cx.read(body.sub(0, 8)).await?;
    let first = u32_le(&h, 0).unwrap_or(0);
    let count = u32_le(&h, 4).unwrap_or(0);
    let (mut pos, mut i) = cx.resume::<(u64, u32)>().unwrap_or((8, 0));
    while i < count && pos < body.len {
        let at = (pos, i);
        cx.mark(move || at);
        let sb = cx.read(body.sub_exact(pos, 4)?).await?;
        let size = u64::from(u32_le(&sb, 0).unwrap_or(0));
        let ips = body.sub_exact(pos.saturating_add(4), size)?;
        let frames = size.checked_div(ctx.ptr).unwrap_or(0);
        let id = first.wrapping_add(i);
        cx.push(
            Node::new(format!("Stack {id}"))
                .span(body.sub(pos, size.saturating_add(4)))
                .summary(plural(frames, "frame"))
                .lazy(frames_of, (ips, ctx.ptr)),
        )
        .await;
        pos = pos.saturating_add(4).saturating_add(size);
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn frames_of(cx: Cx, (ips, ptr): (Span, u64)) -> Result<()> {
    let mut pos = 0u64;
    let mut i = 0u64;
    while pos.saturating_add(ptr) <= ips.len {
        let b = cx.read(ips.sub(pos, ptr)).await?;
        let ip = if ptr == 4 {
            u32_le(&b, 0).map(u64::from)
        } else {
            u64_le(&b, 0)
        }
        .unwrap_or(0);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(ips.sub(pos, ptr))
                .value(Value::UInt {
                    value: ip,
                    bits: if ptr == 4 { 32 } else { 64 },
                    radix: Radix::Hex,
                }),
        )
        .await;
        pos = pos.saturating_add(ptr);
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn sequence_point(cx: Cx, (ctx, body): (Ctx, Span)) -> Result<()> {
    let head_len = if ctx.ver == Ver::Fs { 12 } else { 16 };
    cx.emit(struct_node(
        "Header",
        body.sub(0, head_len),
        LE,
        ctx.ver,
        |f: &mut Fields<'_>, ver: &Ver| {
            f.u64("TimeStamp").emit()?;
            if *ver == Ver::V6 {
                f.u32("Flags")
                    .with(|&v, n| {
                        let mut s = Vec::new();
                        if v & 1 != 0 {
                            s.push("flush threads");
                        }
                        if v & 2 != 0 {
                            s.push("flush metadata");
                        }
                        if s.is_empty() {
                            n
                        } else {
                            n.summary(s.join(", "))
                        }
                    })
                    .emit()?;
            }
            f.u32("ThreadCount").emit()?;
            Ok(())
        },
    ));
    let b = cx.read(body.tail(head_len)).await?;
    let mut r = Reader::new(&b);
    let mut i = 0u64;
    while !r.at_end() {
        let s = r.pos();
        let (thread, seq) = match ctx.ver {
            Ver::Fs => (r.int::<u64>(LE), r.int::<u32>(LE).map(u64::from)),
            Ver::V6 => (r.uleb(), r.uleb()),
        };
        let (Some(thread), Some(seq)) = (thread, seq) else {
            cx.diag(Diagnostic::truncated(
                body.tail(head_len.saturating_add(to_u64(s))),
                0,
            ));
            break;
        };
        cx.push(
            Node::new(format!("Thread {thread}"))
                .span(body.sub(
                    head_len.saturating_add(to_u64(s)),
                    to_u64(r.pos().saturating_sub(s)),
                ))
                .summary(format!("sequence number {seq}")),
        )
        .await;
        i = i.saturating_add(1);
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
    }
    Ok(())
}

async fn threads_v6(cx: Cx, body: Span) -> Result<()> {
    let mut pos = 0u64;
    while pos < body.len {
        let sb = cx.read(body.sub_exact(pos, 2)?).await?;
        let size = u64::from(u16_le(&sb, 0).unwrap_or(0));
        let row = body.sub_exact(pos.saturating_add(2), size)?;
        let b = cx.read(row).await?;
        let mut r = Reader::new(&b);
        let index = r.uleb().unwrap_or(0);
        let mut items: Vec<Item> = vec![("Index".into(), 2, r.pos(), uint(index, 64), 0)];
        let mut name = None;
        while !r.at_end() {
            let s = r.pos();
            let Some(kind) = r.u8() else { break };
            let (label, value) = match kind {
                1 => {
                    let n = string_v6(&mut r);
                    name.clone_from(&n);
                    ("Name".to_owned(), n.map(text))
                }
                2 => ("OSProcessId".to_owned(), r.uleb().map(|v| uint(v, 64))),
                3 => ("OSThreadId".to_owned(), r.uleb().map(|v| uint(v, 64))),
                4 => match (string_v6(&mut r), string_v6(&mut r)) {
                    (Some(k), Some(v)) => (k, Some(text(v))),
                    _ => (String::new(), None),
                },
                _ => (String::new(), None),
            };
            let Some(value) = value else { break };
            items.push((
                label,
                s.saturating_add(2),
                r.pos().saturating_sub(s),
                value,
                0,
            ));
        }
        let span = body.sub(pos, size.saturating_add(2));
        let mut node = Node::new(format!("Thread {index}")).span(span);
        if let Some(n) = name {
            node = node.summary(n);
        }
        cx.push(node.lazy(emit_items, (span, Arc::new(items))))
            .await;
        pos = pos.saturating_add(2).saturating_add(size);
    }
    Ok(())
}

async fn remove_threads_v6(cx: Cx, body: Span) -> Result<()> {
    let b = cx.read(body).await?;
    let mut r = Reader::new(&b);
    while !r.at_end() {
        let s = r.pos();
        let (Some(index), Some(seq)) = (r.uleb(), r.uleb()) else {
            cx.diag(Diagnostic::truncated(body.tail(to_u64(s)), 0));
            break;
        };
        cx.push(
            Node::new(format!("Thread {index}"))
                .span(body.sub(to_u64(s), to_u64(r.pos().saturating_sub(s))))
                .summary(format!("last sequence number {seq}")),
        )
        .await;
    }
    Ok(())
}

async fn label_lists_v6(cx: Cx, body: Span) -> Result<()> {
    let b = cx.read(body).await?;
    let first = u32_le(&b, 0).unwrap_or(0);
    let count = u32_le(&b, 4).unwrap_or(0);
    cx.emit(struct_node(
        "Header",
        body.sub(0, 8),
        LE,
        (),
        |f: &mut Fields<'_>, _: &()| {
            f.u32("FirstIndex").emit()?;
            f.u32("Count").emit()?;
            Ok(())
        },
    ));
    let mut r = Reader::at(&b, 8);
    for i in 0..count {
        let start = r.pos();
        let mut items: Vec<Item> = Vec::new();
        loop {
            let s = r.pos();
            let Some(kind) = r.u8() else { break };
            let (label, value) = match kind & 0x7f {
                1 | 2 => {
                    let mut g = [0u8; 16];
                    let ok = r.bytes(16).map(|x| g.copy_from_slice(x));
                    (
                        if kind & 0x7f == 1 {
                            "ActivityId"
                        } else {
                            "RelatedActivityId"
                        }
                        .to_owned(),
                        ok.map(|()| text(guid_text(&g))),
                    )
                }
                3 => (
                    "TraceId".to_owned(),
                    r.bytes(16)
                        .map(|x| text(x.iter().map(|c| format!("{c:02x}")).collect())),
                ),
                4 => (
                    "SpanId".to_owned(),
                    r.int::<u64>(LE).map(|v| Value::UInt {
                        value: v,
                        bits: 64,
                        radix: Radix::Hex,
                    }),
                ),
                5 => match (string_v6(&mut r), string_v6(&mut r)) {
                    (Some(k), Some(v)) => (k, Some(text(v))),
                    _ => (String::new(), None),
                },
                6 => match (string_v6(&mut r), r.uleb()) {
                    (Some(k), Some(v)) => (
                        k,
                        Some(Value::Int {
                            value: crate::formats::util::wire::protobuf::zigzag(v),
                            bits: 64,
                        }),
                    ),
                    _ => (String::new(), None),
                },
                7 => ("OpCode".to_owned(), r.u8().map(|v| uint(v.into(), 8))),
                8 => (
                    "Keywords".to_owned(),
                    r.int::<u64>(LE).map(|v| Value::UInt {
                        value: v,
                        bits: 64,
                        radix: Radix::Hex,
                    }),
                ),
                9 => ("Level".to_owned(), r.u8().map(|v| uint(v.into(), 8))),
                10 => ("Version".to_owned(), r.u8().map(|v| uint(v.into(), 8))),
                _ => (String::new(), None),
            };
            let Some(value) = value else {
                cx.diag(
                    Diagnostic::malformed("unknown or truncated label").at(body.sub(to_u64(s), 1)),
                );
                return Ok(());
            };
            items.push((
                label,
                s.saturating_sub(start),
                r.pos().saturating_sub(s),
                value,
                0,
            ));
            if kind & 0x80 != 0 {
                break;
            }
        }
        let span = body.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.push(
            Node::new(format!("Label list {}", first.wrapping_add(i)))
                .span(span)
                .summary(plural(items.len(), "label"))
                .lazy(emit_items, (span, Arc::new(items))),
        )
        .await;
        if r.at_end() {
            break;
        }
    }
    Ok(())
}
