//! Common Trace Format (CTF): the trace format of LTTng, barectf and
//! babeltrace. A CTF trace is a directory: a metadata file describing every
//! structure in TSDL (CTF 1.8) or JSON (CTF 2), and data stream files made
//! of packets.
//!
//! - **Data streams** (`ctf-packet`): each packet starts with a header whose
//!   first field is the magic `0xc1fc1fc1` in the trace's byte order, then
//!   (usually) the trace UUID and stream IDs, followed by a packet context
//!   (packet and content sizes in bits, timestamps, discarded events, CPU),
//!   the event records and padding. The layout of the header and context is
//!   declared in the metadata, which is a separate file, so it is inferred
//!   here: the layouts LTTng 2.8 and later (64- and 32-bit tracers), older
//!   LTTng and babeltrace2's `sink.ctf.fs` write (with a clock and LTTng's
//!   `cpu_id`, with a clock, without) are each tried. A layout must have
//!   packet and content sizes that fit the file and lead from packet to
//!   packet, a CPU number below 4096, a 64-bit discarded count below 2^32
//!   (a 32-bit tracer's narrower count read as 64-bit takes in the CPU),
//!   and packet sequence numbers that start small and count up; of the
//!   layouts that do, one whose stream instance ID is its CPU (an LTTng
//!   per-CPU stream) wins, else the first. Event records are shown as data:
//!   decoding them needs the event classes of the metadata.
//! - **Metadata** (`ctf-metadata`): plain TSDL text (starting with the
//!   `/* CTF 1.8` comment the specification requires), packetized TSDL (each
//!   packet a 37-byte header with the magic `0x75d11d57`, the UUID, a
//!   checksum, content and packet sizes in bits, compression, encryption and
//!   checksum schemes and the CTF version, then text; the text of all
//!   packets is joined into one source), or a CTF 2 JSON text sequence
//!   (fragments each preceded by the record separator 0x1e, the first a
//!   preamble), shown fragment by fragment.
//!
//! Written from the CTF 1.8.3 and CTF 2 specifications; the packet layouts
//! checked against LTTng-UST 2.13 and babeltrace2 2.1 output.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::text::{json, plain};
use crate::formats::util::binutil::get;
use crate::formats::util::fmt::{plural, size, uuid};
use crate::formats::util::val::{text, uint};
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::{Origin, Span};

pub static PACKET: Format = Format {
    name: "ctf-packet",
    title: "Common Trace Format data stream",
    extensions: &[],
    mime: "application/x-ctf-stream",
    probe: Probe::Custom(probe_packet),
    dissect: crate::expander!(dissect_stream: Input),
};

pub static METADATA: Format = Format {
    name: "ctf-metadata",
    title: "Common Trace Format metadata",
    extensions: &[],
    mime: "application/x-ctf-metadata",
    probe: Probe::Custom(probe_metadata),
    dissect: crate::expander!(dissect_metadata: Input),
};

const PACKET_MAGIC: u32 = 0xc1fc_1fc1;
const METADATA_MAGIC: u32 = 0x75d1_1d57;
const METADATA_HEADER: u64 = 37;
const TSDL_SIGNATURE: &[u8] = b"/* CTF 1.8";

fn magic_endian(data: &[u8], magic: u32) -> Option<Endian> {
    if data.starts_with(&magic.to_le_bytes()) {
        Some(Endian::Little)
    } else if data.starts_with(&magic.to_be_bytes()) {
        Some(Endian::Big)
    } else {
        None
    }
}

fn probe_packet(h: &Head) -> bool {
    magic_endian(h.data, PACKET_MAGIC).is_some() && h.data.len() >= 24
}

fn probe_metadata(h: &Head) -> bool {
    if let Some(e) = magic_endian(h.data, METADATA_MAGIC) {
        let content = get::<u32>(h.data, 24, e).unwrap_or(0);
        let packet = get::<u32>(h.data, 28, e).unwrap_or(0);
        return h.at(35, &[1, 8])
            && packet.is_multiple_of(8)
            && content <= packet
            && u64::from(content) >= METADATA_HEADER.saturating_mul(8);
    }
    if h.starts_with(TSDL_SIGNATURE) {
        return true;
    }
    // CTF 2: a JSON text sequence whose first fragment is the preamble.
    if h.starts_with(b"\x1e{") {
        let first = h.data.get(1..).unwrap_or_default();
        let end = first.iter().position(|&b| b == 0x1e).unwrap_or(first.len());
        let frag = first.get(..end.min(4096)).unwrap_or_default();
        return contains(frag, b"\"type\":\"preamble\"")
            || contains(frag, b"\"type\": \"preamble\"");
    }
    false
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

// ---------------------------------------------------------------------------
// Data streams.

#[derive(Clone, Copy, PartialEq, Eq)]
enum Role {
    Magic,
    Uuid,
    StreamId,
    StreamInstanceId,
    TimestampBegin,
    TimestampEnd,
    ContentSize,
    PacketSize,
    PacketSeqNum,
    EventsDiscarded,
    CpuId,
}

use Role::*;

/// A packet header and context layout: fields, their sizes in bytes, and
/// how many of them belong to the header.
struct Layout {
    name: &'static str,
    fields: &'static [(Role, &'static str, u64)],
    header: usize,
}

const LAYOUTS: &[Layout] = &[
    Layout {
        name: "LTTng 2.8+ (64-bit tracer)",
        fields: &[
            (Magic, "magic", 4),
            (Uuid, "uuid", 16),
            (StreamId, "stream_id", 4),
            (StreamInstanceId, "stream_instance_id", 8),
            (TimestampBegin, "timestamp_begin", 8),
            (TimestampEnd, "timestamp_end", 8),
            (ContentSize, "content_size", 8),
            (PacketSize, "packet_size", 8),
            (PacketSeqNum, "packet_seq_num", 8),
            (EventsDiscarded, "events_discarded", 8),
            (CpuId, "cpu_id", 4),
        ],
        header: 4,
    },
    Layout {
        name: "LTTng 2.8+ (32-bit tracer)",
        fields: &[
            (Magic, "magic", 4),
            (Uuid, "uuid", 16),
            (StreamId, "stream_id", 4),
            (StreamInstanceId, "stream_instance_id", 8),
            (TimestampBegin, "timestamp_begin", 8),
            (TimestampEnd, "timestamp_end", 8),
            (ContentSize, "content_size", 8),
            (PacketSize, "packet_size", 8),
            (PacketSeqNum, "packet_seq_num", 8),
            (EventsDiscarded, "events_discarded", 4),
            (CpuId, "cpu_id", 4),
        ],
        header: 4,
    },
    Layout {
        name: "LTTng before 2.8",
        fields: &[
            (Magic, "magic", 4),
            (Uuid, "uuid", 16),
            (StreamId, "stream_id", 4),
            (TimestampBegin, "timestamp_begin", 8),
            (TimestampEnd, "timestamp_end", 8),
            (ContentSize, "content_size", 8),
            (PacketSize, "packet_size", 8),
            (EventsDiscarded, "events_discarded", 8),
            (CpuId, "cpu_id", 4),
        ],
        header: 3,
    },
    Layout {
        name: "babeltrace2 sink.ctf.fs (clock, CPU)",
        fields: &[
            (Magic, "magic", 4),
            (Uuid, "uuid", 16),
            (StreamId, "stream_id", 8),
            (StreamInstanceId, "stream_instance_id", 8),
            (PacketSize, "packet_size", 8),
            (ContentSize, "content_size", 8),
            (TimestampBegin, "timestamp_begin", 8),
            (TimestampEnd, "timestamp_end", 8),
            (EventsDiscarded, "events_discarded", 8),
            (PacketSeqNum, "packet_seq_num", 8),
            (CpuId, "cpu_id", 4),
        ],
        header: 4,
    },
    Layout {
        name: "babeltrace2 sink.ctf.fs (clock)",
        fields: &[
            (Magic, "magic", 4),
            (Uuid, "uuid", 16),
            (StreamId, "stream_id", 8),
            (StreamInstanceId, "stream_instance_id", 8),
            (PacketSize, "packet_size", 8),
            (ContentSize, "content_size", 8),
            (TimestampBegin, "timestamp_begin", 8),
            (TimestampEnd, "timestamp_end", 8),
            (EventsDiscarded, "events_discarded", 8),
            (PacketSeqNum, "packet_seq_num", 8),
        ],
        header: 4,
    },
    Layout {
        name: "babeltrace2 sink.ctf.fs",
        fields: &[
            (Magic, "magic", 4),
            (Uuid, "uuid", 16),
            (StreamId, "stream_id", 8),
            (StreamInstanceId, "stream_instance_id", 8),
            (PacketSize, "packet_size", 8),
            (ContentSize, "content_size", 8),
            (PacketSeqNum, "packet_seq_num", 8),
        ],
        header: 4,
    },
];

impl Layout {
    fn len(&self) -> u64 {
        self.fields.iter().map(|f| f.2).sum()
    }

    fn offset(&self, role: Role) -> Option<(u64, u64)> {
        let mut off = 0u64;
        for &(r, _, n) in self.fields {
            if r == role {
                return Some((off, n));
            }
            off = off.saturating_add(n);
        }
        None
    }

    fn get(&self, b: &[u8], role: Role, e: Endian) -> Option<u64> {
        let (off, n) = self.offset(role)?;
        let off = to_usize(off);
        match n {
            4 => get::<u32>(b, off, e).map(u64::from),
            8 => get::<u64>(b, off, e),
            _ => None,
        }
    }

    /// Packet and content sizes in bytes, if they are sane for a packet of
    /// at most `avail` bytes.
    fn sizes(&self, b: &[u8], e: Endian, avail: u64) -> Option<(u64, u64)> {
        let packet = self.get(b, PacketSize, e)?;
        let content = self.get(b, ContentSize, e)?;
        let ctx_bits = self.len().saturating_mul(8);
        let fits = packet.is_multiple_of(8)
            && content <= packet
            && content >= ctx_bits
            && packet / 8 <= avail;
        let ordered = match (self.get(b, TimestampBegin, e), self.get(b, TimestampEnd, e)) {
            (Some(a), Some(z)) => a <= z,
            _ => true,
        };
        (fits && ordered).then_some((packet / 8, content.div_ceil(8)))
    }

    /// Whether the CPU and discarded-event fields hold what they could: a
    /// CPU number below 4096, and (where the count is 64-bit next to a CPU,
    /// as LTTng's 64-bit tracer writes it) a count below 2^32. A 32-bit
    /// tracer's 32-bit count read as 64-bit takes in the CPU number.
    fn plausible(&self, b: &[u8], e: Endian) -> bool {
        let Some(cpu) = self.get(b, CpuId, e) else {
            return true;
        };
        let wide = matches!(self.offset(EventsDiscarded), Some((_, 8)));
        let discarded = self.get(b, EventsDiscarded, e).unwrap_or(0);
        cpu < 4096 && !(wide && discarded >> 32 != 0)
    }

    /// LTTng's per-CPU streams number their instances by CPU.
    fn cpu_is_instance(&self, b: &[u8], e: Endian) -> bool {
        match (self.get(b, StreamInstanceId, e), self.get(b, CpuId, e)) {
            (Some(i), Some(c)) => i == c,
            _ => false,
        }
    }
}

/// Packet sequence numbers count packets: the first is small, and the next
/// packet's follows it closely. A timestamp read in their place is neither.
fn seq_plausible(first: u64, next: Option<u64>) -> bool {
    first < 1 << 32 && next.is_none_or(|n| n > first && n.saturating_sub(first) < 1 << 16)
}

/// Picks the layout whose first packet fits, is followed by another packet
/// or the end of the file, and holds plausible values; of those, one whose
/// stream instance is its CPU (an LTTng per-CPU stream) wins, else the first.
async fn infer_layout(cx: &Cx, file: Span, e: Endian) -> Option<usize> {
    let head = cx.read(file.sub(0, 128)).await.ok()?;
    let mut first = None;
    for (i, l) in LAYOUTS.iter().enumerate() {
        let Some((packet, _)) = l.sizes(&head, e, file.len) else {
            continue;
        };
        if packet == 0 || !l.plausible(&head, e) {
            continue;
        }
        let mut next_seq = None;
        if packet < file.len {
            let next = cx.read(file.sub(packet, l.len())).await.ok()?;
            if magic_endian(&next, PACKET_MAGIC) != Some(e) {
                continue;
            }
            next_seq = l.get(&next, PacketSeqNum, e);
        }
        if let Some(seq) = l.get(&head, PacketSeqNum, e)
            && !seq_plausible(seq, next_seq)
        {
            continue;
        }
        if l.cpu_is_instance(&head, e) {
            return Some(i);
        }
        first = first.or(Some(i));
    }
    first
}

pub async fn dissect_stream(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let e = magic_endian(&head, PACKET_MAGIC).unwrap_or(Endian::Little);
    let Some(li) = infer_layout(&cx, file, e).await else {
        cx.annotate("CTF data stream, packet layout unknown");
        cx.emit(
            Node::new("Magic")
                .span(file.sub(0, 4))
                .value(uint(PACKET_MAGIC, 32)),
        );
        cx.emit(
            Node::new("Packets")
                .span(file.tail(4))
                .diag(Diagnostic::unsupported(
                    "packet layout not one of those known; it is declared in the trace's metadata",
                )),
        );
        return Ok(());
    };
    let layout = LAYOUTS
        .get(li)
        .ok_or_else(|| Diagnostic::internal("layout"))?;
    let b = cx.read(file.sub(0, layout.len())).await?;
    let id = uuid(b.get(4..20).unwrap_or_default());
    cx.annotate(format!(
        "CTF data stream, {}-endian, trace {id}, layout of {}",
        match e {
            Endian::Little => "little",
            Endian::Big => "big",
        },
        layout.name
    ));
    cx.emit(
        Node::new("Packets")
            .span(file)
            .summary(format!(
                "packet header and context as written by {}",
                layout.name
            ))
            .lazy(packets, (file, e, li)),
    );
    Ok(())
}

async fn packets(cx: Cx, (file, e, li): (Span, Endian, usize)) -> Result<()> {
    let layout = LAYOUTS
        .get(li)
        .ok_or_else(|| Diagnostic::internal("layout"))?;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < file.len {
        let at = (pos, index);
        cx.mark(move || at);
        let rest = file.len.saturating_sub(pos);
        let b = cx.read(file.sub(pos, layout.len())).await?;
        if magic_endian(&b, PACKET_MAGIC) != Some(e) {
            cx.push(
                Node::new("Trailing Data")
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("no packet magic here")),
            )
            .await;
            break;
        }
        let Some((packet, content)) = layout.sizes(&b, e, rest) else {
            cx.push(
                Node::new(format!("Packet {index}"))
                    .span(file.tail(pos))
                    .diag(Diagnostic::malformed("packet sizes do not fit the layout")),
            )
            .await;
            break;
        };
        let span = file.sub(pos, packet);
        let mut parts = Vec::new();
        if let Some(seq) = layout.get(&b, PacketSeqNum, e) {
            parts.push(format!("seq {seq}"));
        }
        if let Some(cpu) = layout.get(&b, CpuId, e) {
            parts.push(format!("CPU {cpu}"));
        }
        if let (Some(a), Some(z)) = (
            layout.get(&b, TimestampBegin, e),
            layout.get(&b, TimestampEnd, e),
        ) {
            parts.push(format!("cycles {a} to {z}"));
        }
        parts.push(format!(
            "{} of event records",
            size(content.saturating_sub(layout.len()))
        ));
        if let Some(d) = layout.get(&b, EventsDiscarded, e).filter(|&d| d > 0) {
            parts.push(format!("{} discarded", plural(d, "event")));
        }
        cx.push(
            Node::new(format!("Packet {index}"))
                .span(span)
                .summary(parts.join(", "))
                .lazy(packet_node, (span, e, li, content)),
        )
        .await;
        cx.progress_in(file, file.offset.saturating_add(pos));
        if packet == 0 {
            break;
        }
        pos = pos.saturating_add(packet);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn packet_node(cx: Cx, (span, e, li, content): (Span, Endian, usize, u64)) -> Result<()> {
    let layout = LAYOUTS
        .get(li)
        .ok_or_else(|| Diagnostic::internal("layout"))?;
    let header_len: u64 = layout.fields.iter().take(layout.header).map(|f| f.2).sum();
    let ctx_len = layout.len().saturating_sub(header_len);
    cx.emit(
        Node::new("Packet Header")
            .span(span.sub(0, header_len))
            .lazy(
                packet_fields,
                (span.sub(0, header_len), e, li, 0usize, layout.header),
            ),
    );
    cx.emit(
        Node::new("Packet Context")
            .span(span.sub(header_len, ctx_len))
            .lazy(
                packet_fields,
                (
                    span.sub(header_len, ctx_len),
                    e,
                    li,
                    layout.header,
                    layout.fields.len(),
                ),
            ),
    );
    let events = span.sub(layout.len(), content.saturating_sub(layout.len()));
    cx.emit(
        Node::new("Event Records")
            .span(events)
            .summary(size(events.len))
            .desc("Decoding the records needs the event classes declared in the trace's metadata"),
    );
    let pad = span.tail(content);
    if !pad.is_empty() {
        cx.emit(Node::new("Padding").span(pad));
    }
    Ok(())
}

async fn packet_fields(
    cx: Cx,
    (span, e, li, from, to): (Span, Endian, usize, usize, usize),
) -> Result<()> {
    let layout = LAYOUTS
        .get(li)
        .ok_or_else(|| Diagnostic::internal("layout"))?;
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    for &(role, name, n) in layout.fields.iter().take(to).skip(from) {
        match (role, n) {
            (Uuid, _) => {
                let b = f.bytes(name, 16);
                let s = b.span();
                let v = b.get()?;
                cx.emit(Node::new(name).span(s).value(text(uuid(&v))));
            }
            (Magic, _) => {
                f.u32(name).hex().emit()?;
            }
            (ContentSize | PacketSize, 8) => {
                f.u64(name)
                    .with(|&v, node| node.summary(format!("bits, {}", plural(v / 8, "byte"))))
                    .emit()?;
            }
            (_, 4) => {
                f.u32(name).emit()?;
            }
            _ => {
                f.u64(name).emit()?;
            }
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Metadata.

pub async fn dissect_metadata(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 64)).await?;
    if let Some(e) = magic_endian(&head, METADATA_MAGIC) {
        return packetized(&cx, input, e).await;
    }
    if head.starts_with(b"\x1e") {
        cx.annotate("CTF 2 metadata (JSON text sequence)");
        cx.emit(Node::new("Fragments").span(file).lazy(fragments, input));
        return Ok(());
    }
    let t = cx.read(file.sub(0, 64 * 1024)).await?;
    cx.charge(to_u64(t.len()) / 64).await;
    let s = String::from_utf8_lossy(&t);
    cx.annotate(tsdl_summary(&s, "CTF 1.8 metadata (TSDL)"));
    cx.emit(embedded_as("TSDL", input.nested(file), &plain::FORMAT));
    Ok(())
}

/// A summary naming the trace's UUID and byte order, if the text gives them.
fn tsdl_summary(s: &str, what: &str) -> String {
    let mut out = what.to_string();
    let value = |key: &str| {
        s.lines().find_map(|l| {
            let l = l.trim();
            let rest = l.strip_prefix(key)?.trim_start().strip_prefix('=')?;
            Some(
                rest.trim()
                    .trim_end_matches(';')
                    .trim()
                    .trim_matches('"')
                    .to_string(),
            )
        })
    };
    if let Some(bo) = value("byte_order") {
        out.push_str(&format!(", byte order {bo}"));
    }
    if let Some(u) = value("uuid") {
        out.push_str(&format!(", trace {u}"));
    }
    out
}

async fn packetized(cx: &Cx, input: Input, e: Endian) -> Result<()> {
    let file = input.span;
    // Walk the packets once for their text, joined into one source.
    let mut pieces = Vec::new();
    let mut pos = 0u64;
    let mut count = 0u64;
    let mut problem = None;
    while pos < file.len {
        let b = cx.read(file.sub(pos, METADATA_HEADER)).await?;
        if magic_endian(&b, METADATA_MAGIC) != Some(e) || to_u64(b.len()) < METADATA_HEADER {
            problem =
                Some(Diagnostic::malformed("no metadata packet magic here").at(file.sub(pos, 4)));
            break;
        }
        let content = u64::from(get::<u32>(&b, 24, e).unwrap_or(0)) / 8;
        let packet = u64::from(get::<u32>(&b, 28, e).unwrap_or(0)) / 8;
        if packet < METADATA_HEADER || content < METADATA_HEADER || content > packet {
            problem = Some(
                Diagnostic::malformed("implausible metadata packet sizes")
                    .at(file.sub(pos, METADATA_HEADER)),
            );
            break;
        }
        if b.get(32..35).is_some_and(|s| s.iter().any(|&x| x != 0)) {
            problem = Some(Diagnostic::unsupported(
                "compressed, encrypted or checksummed metadata packets",
            ));
        }
        pieces.push(file.sub(
            pos.saturating_add(METADATA_HEADER),
            content.saturating_sub(METADATA_HEADER),
        ));
        count = count.saturating_add(1);
        pos = pos.saturating_add(packet);
        cx.checkpoint().await;
    }
    cx.emit(
        Node::new("Packets")
            .span(file)
            .summary(plural(count, "packet"))
            .lazy(metadata_packets, (file, e)),
    );
    let text_span = cx.add_pieces(
        Origin {
            parent: file,
            transform: "ctf-metadata-packets",
        },
        pieces,
    )?;
    let first = cx.read(text_span.sub(0, 64 * 1024)).await?;
    cx.charge(to_u64(first.len()) / 64).await;
    let s = String::from_utf8_lossy(&first);
    cx.annotate(format!(
        "{}, {}",
        tsdl_summary(&s, "CTF 1.8 packetized metadata"),
        plural(count, "packet")
    ));
    cx.emit(embedded_as("TSDL", input.nested(text_span), &plain::FORMAT));
    if let Some(p) = problem {
        cx.diag(p);
    }
    Ok(())
}

async fn metadata_packets(cx: Cx, (file, e): (Span, Endian)) -> Result<()> {
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos < file.len {
        let at = (pos, index);
        cx.mark(move || at);
        let b = cx.read(file.sub(pos, METADATA_HEADER)).await?;
        let content = u64::from(get::<u32>(&b, 24, e).unwrap_or(0)) / 8;
        let packet = u64::from(get::<u32>(&b, 28, e).unwrap_or(0)) / 8;
        if magic_endian(&b, METADATA_MAGIC) != Some(e)
            || packet < METADATA_HEADER
            || content < METADATA_HEADER
            || content > packet
        {
            break;
        }
        let span = file.sub(pos, packet);
        cx.push(
            Node::new(format!("Packet {index}"))
                .span(span)
                .summary(format!(
                    "{} of text",
                    size(content.saturating_sub(METADATA_HEADER))
                ))
                .lazy(metadata_packet, (span, e, content)),
        )
        .await;
        pos = pos.saturating_add(packet);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn metadata_packet(cx: Cx, (span, e, content): (Span, Endian, u64)) -> Result<()> {
    let block = cx.block(span.sub(0, METADATA_HEADER)).await?;
    let mut f = Fields::emitting(&cx, &block, e);
    f.u32("magic").hex().emit()?;
    let b = f.bytes("uuid", 16);
    let s = b.span();
    let v = b.get()?;
    cx.emit(Node::new("uuid").span(s).value(text(uuid(&v))));
    f.u32("checksum").hex().emit()?;
    f.u32("content_size")
        .with(|&v, n| n.summary(format!("bits, {}", plural(v / 8, "byte"))))
        .emit()?;
    f.u32("packet_size")
        .with(|&v, n| n.summary(format!("bits, {}", plural(v / 8, "byte"))))
        .emit()?;
    f.u8("compression_scheme").emit()?;
    f.u8("encryption_scheme").emit()?;
    f.u8("checksum_scheme").emit()?;
    f.u8("major").emit()?;
    f.u8("minor").emit()?;
    let text_span = span.sub(METADATA_HEADER, content.saturating_sub(METADATA_HEADER));
    cx.emit(
        Node::new("Text")
            .span(text_span)
            .summary(size(text_span.len)),
    );
    let pad = span.tail(content);
    if !pad.is_empty() {
        cx.emit(Node::new("Padding").span(pad));
    }
    Ok(())
}

/// The fragments of a CTF 2 JSON text sequence.
async fn fragments(cx: Cx, input: Input) -> Result<()> {
    const CHUNK: u64 = 64 * 1024;
    let file = input.span;
    let (mut start, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while start < file.len {
        let at = (start, index);
        cx.mark(move || at);
        // Find the next record separator after `start`.
        let mut end = file.len;
        let mut pos = start.saturating_add(1);
        while pos < file.len {
            let b = cx.read(file.sub(pos, CHUNK)).await?;
            if b.is_empty() {
                break;
            }
            if let Some(i) = b.iter().position(|&c| c == 0x1e) {
                end = pos.saturating_add(to_u64(i));
                break;
            }
            pos = pos.saturating_add(to_u64(b.len()));
        }
        let span = file.sub(start, end.saturating_sub(start));
        let body = span.tail(1);
        let head = cx.read(body.sub(0, 4096)).await?;
        let kind = fragment_type(&head).unwrap_or_else(|| "fragment".to_string());
        let node = embedded_as(
            format!("[{index}] {kind}"),
            input.nested(body),
            &json::FORMAT,
        )
        .span(span);
        cx.push(node).await;
        start = end;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The value of a fragment's top-level `"type"` member, found by a simple
/// scan (the member is a short string in every fragment kind).
fn fragment_type(head: &[u8]) -> Option<String> {
    let s = String::from_utf8_lossy(head);
    let mut search = s.as_ref();
    while let Some(i) = search.find("\"type\"") {
        let rest = search.get(i.saturating_add(6)..)?.trim_start();
        if let Some(v) = rest.strip_prefix(':') {
            let v = v.trim_start().strip_prefix('"')?;
            let end = v.find('"')?;
            let value = v.get(..end)?;
            // Field classes have types too; the fragment's own type names a
            // fragment kind.
            if matches!(
                value,
                "preamble"
                    | "trace-class"
                    | "clock-class"
                    | "data-stream-class"
                    | "event-record-class"
                    | "field-class-alias"
            ) {
                return Some(value.to_string());
            }
        }
        search = search.get(i.saturating_add(6)..)?;
    }
    None
}

#[cfg(test)]
mod tests {
    #![allow(clippy::unwrap_used)]
    use super::*;

    #[test]
    fn fragment_types() {
        assert_eq!(
            fragment_type(br#"{"attributes":{},"type":"preamble","version":2}"#).as_deref(),
            Some("preamble")
        );
        assert_eq!(
            fragment_type(br#"{"field-class":{"type":"structure"},"type":"trace-class"}"#)
                .as_deref(),
            Some("trace-class")
        );
    }
}
