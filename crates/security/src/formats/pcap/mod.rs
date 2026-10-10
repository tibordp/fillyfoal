//! Packet captures: classic libpcap files (both byte orders, microsecond
//! and nanosecond timestamps, Kuznetzov's modified format), pcapng (see
//! [`ng`]), Solaris snoop ([`snoop`]) and Bluetooth btsnoop and Network
//! Monitor ([`captures`]).
//!
//! A classic capture is a 24-byte global header followed by records, each a
//! 16-byte header and the captured bytes. Records are listed in pages with
//! their time relative to the first packet, length, addresses and an Info
//! line like Wireshark's; the capture's summary counts packets, bytes,
//! duration and protocols once the listing reaches the end. Expanding a
//! packet decodes its protocol stack (see [`net`], [`app`], [`dns`], [`tls`],
//! [`wlan`]) from the packet's bytes alone: TCP streams are not reassembled.

pub mod app;
pub mod captures;
pub mod dec;
pub mod dns;
pub mod hci;
pub mod net;
pub mod ng;
pub mod snoop;
pub mod tls;
pub mod wlan;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::Tree;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::lookup;
use dec::{Dec, MAX_DECODE, SUMMARY_WINDOW};

pub static FORMAT: Format = Format {
    name: "pcap",
    title: "libpcap packet capture",
    extensions: &["pcap", "cap", "dmp"],
    mime: "application/vnd.tcpdump.pcap",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const MAGIC_MICRO: u32 = 0xa1b2_c3d4;
const MAGIC_NANO: u32 = 0xa1b2_3c4d;
/// Alexey Kuznetzov's patched libpcap: 8 more bytes per record header.
const MAGIC_KUZNETZOV: u32 = 0xa1b2_cd34;

fn probe(h: &Head<'_>) -> bool {
    magic(h.data).is_some_and(|(endian, _, _)| {
        let major = match endian {
            Endian::Little => crate::bytes::u16_le(h.data, 4),
            Endian::Big => crate::bytes::u16_be(h.data, 4),
        };
        major == Some(2)
    })
}

/// Byte order, whether timestamps are in nanoseconds, and whether records
/// have Kuznetzov's extended header.
fn magic(data: &[u8]) -> Option<(Endian, bool, bool)> {
    let le = crate::bytes::u32_le(data, 0)?;
    let be = crate::bytes::u32_be(data, 0)?;
    match (le, be) {
        (MAGIC_MICRO, _) => Some((Endian::Little, false, false)),
        (MAGIC_NANO, _) => Some((Endian::Little, true, false)),
        (MAGIC_KUZNETZOV, _) => Some((Endian::Little, false, true)),
        (_, MAGIC_MICRO) => Some((Endian::Big, false, false)),
        (_, MAGIC_NANO) => Some((Endian::Big, true, false)),
        (_, MAGIC_KUZNETZOV) => Some((Endian::Big, false, true)),
        _ => None,
    }
}

record! {
    pub struct GlobalHeader {
        magic: u32 "Magic" .hex(),
        major: u16 "Version major",
        minor: u16 "Version minor",
        zone: i32 "Time zone offset" .desc("GMT to local correction in seconds (always 0 in practice)"),
        sigfigs: u32 "Timestamp accuracy",
        snaplen: u32 "Snapshot length" .desc("Maximum bytes captured per packet"),
        network: u32 "Link type" .with(|&v, n| {
            let n = n.value(crate::formats::util::val::enumv(v & 0xffff, 16, net::LINKTYPES));
            if v & 0x0400_0000 != 0 {
                n.summary(format!("frames end with a {}-byte FCS", (v >> 28).saturating_mul(2)))
            } else {
                n
            }
        }) .desc("Link-layer header type (low 16 bits); bit 26 and the top four bits give the FCS length"),
    }
}

record! {
    pub struct RecordHeader {
        seconds: u32 "Timestamp (seconds)" .timestamp(),
        fraction: u32 "Timestamp (fraction)" .desc("Microseconds, or nanoseconds for the nanosecond variant"),
        captured: u32 "Captured length",
        original: u32 "Original length",
    }
}

record! {
    /// The extra fields of Kuznetzov's patched libpcap.
    pub struct KuznetzovHeader {
        ifindex: u32 "Interface index",
        protocol: u16 "Protocol" .hex(),
        pkt_type: u8 "Packet type",
        pad: u8 "Padding",
    }
}

#[derive(Clone, Copy)]
struct Capture {
    input: Input,
    endian: Endian,
    link: u32,
    nano: bool,
    extended: bool,
}

/// `seconds.fraction` formatted like a timestamp.
pub fn time_text(seconds: i64, fraction: u64, digits: usize) -> String {
    let base = crate::render::value(&crate::value::Value::Timestamp {
        unix_seconds: seconds,
    });
    let date = base.trim_end_matches(" UTC");
    format!("{date}.{fraction:0digits$} UTC")
}

pub fn link_name(link: u32) -> String {
    lookup(net::LINKTYPES, link.into()).map_or_else(|| format!("link type {link}"), str::to_owned)
}

/// Capture-wide counts, for the summary once the listing is complete.
#[derive(Clone, Default)]
pub struct Stats {
    pub packets: u64,
    pub bytes: u64,
    /// First and last timestamps, in nanoseconds since the epoch.
    pub first: Option<i128>,
    pub last: Option<i128>,
    protos: Vec<(&'static str, u64)>,
}

impl Stats {
    /// Records one packet; returns its time relative to the first packet.
    pub fn add(&mut self, len: u64, ns: Option<i128>, proto: &'static str) -> Option<i128> {
        self.packets = self.packets.saturating_add(1);
        self.bytes = self.bytes.saturating_add(len);
        let rel = ns.map(|t| {
            let first = *self.first.get_or_insert(t);
            self.last = Some(self.last.map_or(t, |l| l.max(t)));
            t.saturating_sub(first)
        });
        let proto = if proto.is_empty() { "other" } else { proto };
        // Few distinct protocols: a short list, kept in first-seen order.
        match self.protos.iter().position(|(p, _)| *p == proto) {
            Some(i) => {
                if let Some((_, n)) = self.protos.get_mut(i) {
                    *n = n.saturating_add(1);
                }
            }
            None if self.protos.len() < 64 => self.protos.push((proto, 1)),
            None => {}
        }
        rel
    }

    pub fn summary(&self) -> String {
        let mut s = format!(
            "{}, {}",
            crate::formats::util::fmt::grouped_count(self.packets, "packet", "packets"),
            crate::formats::util::fmt::size(self.bytes)
        );
        if let (Some(f), Some(l)) = (self.first, self.last) {
            s.push_str(&format!(" over {}", seconds(l.saturating_sub(f))));
        }
        if !self.protos.is_empty() {
            let mut protos = self.protos.clone();
            protos.sort_by(|a, b| b.1.cmp(&a.1).then(a.0.cmp(b.0)));
            let list: Vec<String> = protos
                .iter()
                .take(8)
                .map(|(p, n)| format!("{p} {n}"))
                .collect();
            s.push_str(&format!("; {}", list.join(", ")));
            if protos.len() > 8 {
                s.push_str(", …");
            }
        }
        s
    }
}

/// Nanoseconds as seconds with six decimals.
pub fn seconds(ns: i128) -> String {
    let neg = ns < 0;
    let ns = ns.unsigned_abs();
    let micros = ns / 1000;
    format!(
        "{}{}.{:06} s",
        if neg { "-" } else { "" },
        micros / 1_000_000,
        micros % 1_000_000
    )
}

/// A time relative to the first packet: `+0.000474 s` or `-0.1 s`.
pub fn offset(ns: i128) -> String {
    if ns < 0 {
        seconds(ns)
    } else {
        format!("+{}", seconds(ns))
    }
}

/// The one-line summary of a packet: protocol, addresses and Info.
pub struct Line {
    pub text: String,
    pub proto: &'static str,
}

/// Summarises the packet at `data` (link type `link`) from its first bytes.
pub async fn summarize(cx: &Cx, input: Input, data: Span, link: u32) -> Result<Line> {
    let head = cx.read_avail(data.sub(0, SUMMARY_WINDOW)).await?;
    let complete = to_u64(head.len()) >= data.len;
    let mut b = Dec::new(&head, data, input, false, complete);
    net::decode(&mut b, 0, link);
    let text = match (b.src.is_empty(), b.info.is_empty()) {
        (_, true) => String::new(),
        (true, false) => b.info.clone(),
        (false, false) => format!("{} → {}, {}", b.src, b.dst, b.info),
    };
    Ok(Line {
        text,
        proto: b.proto,
    })
}

/// Expands a packet: `header` nodes first, then its decoded layers.
pub async fn emit_packet(
    cx: &Cx,
    input: Input,
    data: Span,
    link: u32,
    header: Vec<Node>,
    trailer: Vec<Node>,
) -> Result<()> {
    let n = data.len.min(MAX_DECODE);
    let bytes = cx.read_avail(data.sub(0, n)).await?;
    let complete = to_u64(bytes.len()) >= data.len;
    let mut b = Dec::new(&bytes, data, input, true, complete);
    for node in header {
        b.push_node(0, node);
    }
    let used = net::decode(&mut b, 0, link);
    let len = bytes.len();
    if used < len {
        b.data(0, if used == 0 { "Data" } else { "Trailer" }, used, len);
    }
    if to_u64(bytes.len()) < data.len {
        let rest = data.tail(to_u64(bytes.len()));
        b.push_node(
            0,
            Node::new("Not decoded").span(rest).summary(format!(
                "{} beyond the first {} of the packet",
                crate::formats::util::fmt::size(rest.len),
                crate::formats::util::fmt::size(MAX_DECODE)
            )),
        );
    }
    for node in trailer {
        b.push_node(0, node);
    }
    if b.overflow {
        cx.diag(Diagnostic::limit(format!(
            "only the first {} fields of this packet are shown",
            dec::MAX_NODES
        )));
    }
    let tree = b.finish().unwrap_or_default();
    cx.checkpoint().await;
    Tree::emit_children(cx, &tree, 0).await;
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read(input.span.sub(0, 4)).await?;
    let (endian, nano, extended) = magic(&head)
        .ok_or_else(|| Diagnostic::malformed("not a pcap file").at(input.span.sub(0, 4)))?;
    let mut cur = Cursor::new(&cx, input.span, endian);
    let (header, span) = cur.record::<GlobalHeader>().await?;
    let resumed = cx.resume::<(u64, u64, Stats)>();
    if resumed.is_none() {
        cx.emit(GlobalHeader::node("Global Header", span, endian));
    }
    let link = header.network & 0xffff;
    let title = format!(
        "pcap {}.{}{}, {}, {}-endian, {} timestamps, snaplen {}",
        header.major,
        header.minor,
        if extended { " (Kuznetzov)" } else { "" },
        link_name(link),
        if endian == Endian::Little {
            "little"
        } else {
            "big"
        },
        if nano { "ns" } else { "µs" },
        header.snaplen
    );
    cx.annotate(title.clone());
    let capture = Capture {
        input,
        endian,
        link,
        nano,
        extended,
    };
    let rec_len = if extended {
        RecordHeader::SIZE.saturating_add(KuznetzovHeader::SIZE)
    } else {
        RecordHeader::SIZE
    };
    let (pos, mut index, mut stats) = resumed.unwrap_or((cur.pos(), 0, Stats::default()));
    cur.seek(pos);
    while !cur.at_end() {
        let start = cur.pos();
        cx.mark(|| (start, index, stats.clone()));
        let (rec, _) = cur.record::<RecordHeader>().await?;
        if extended {
            cur.skip(KuznetzovHeader::SIZE);
        }
        let data = cur.span(rec.captured.into());
        cur.skip(rec.captured.into());
        let span = cur.since(start);
        let line = summarize(&cx, input, data, link).await?;
        let frac = if nano {
            i128::from(rec.fraction)
        } else {
            i128::from(rec.fraction).saturating_mul(1000)
        };
        let ns = i128::from(rec.seconds)
            .saturating_mul(1_000_000_000)
            .saturating_add(frac);
        let rel = stats.add(rec.original.into(), Some(ns), line.proto);
        let mut summary = format!("{}, {} bytes", offset(rel.unwrap_or(0)), rec.captured);
        if rec.captured < rec.original {
            summary.push_str(&format!(" of {}", rec.original));
        }
        if !line.text.is_empty() {
            summary.push_str(&format!(", {}", line.text));
        }
        let mut node = Node::new(format!("Packet {index}"))
            .span(span)
            .summary(summary)
            .lazy(packet, (capture, span, rec_len));
        if data.len < u64::from(rec.captured) {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, rec.captured.into()),
                data.len,
            ));
        }
        cx.progress_in(input.span, input.span.offset.saturating_add(cur.pos()));
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    cx.annotate(format!("{title}; {}", stats.summary()));
    Ok(())
}

async fn packet(cx: Cx, (capture, span, rec_len): (Capture, Span, u64)) -> Result<()> {
    let header = span.sub(0, RecordHeader::SIZE);
    let rec = crate::fields::parse(&cx, header, capture.endian, &(), RecordHeader::layout).await?;
    let digits = if capture.nano { 9 } else { 6 };
    let mut nodes = vec![
        RecordHeader::node("Record Header", header, capture.endian).summary(time_text(
            rec.seconds.into(),
            rec.fraction.into(),
            digits,
        )),
    ];
    if capture.extended {
        nodes.push(KuznetzovHeader::node(
            "Extended record header",
            span.sub(RecordHeader::SIZE, KuznetzovHeader::SIZE),
            capture.endian,
        ));
    }
    if rec.captured < rec.original {
        cx.diag(Diagnostic::note(format!(
            "only {} of {} bytes were captured",
            rec.captured, rec.original
        )));
    }
    let data = span.tail(rec_len);
    emit_packet(&cx, capture.input, data, capture.link, nodes, Vec::new()).await
}
