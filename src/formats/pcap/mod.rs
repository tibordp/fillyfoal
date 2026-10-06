//! Packet captures: classic libpcap files (both byte orders, microsecond and
//! nanosecond timestamps) and pcapng (see [`ng`]).
//!
//! A classic capture is a 24-byte global header followed by records, each a
//! 16-byte header and the captured bytes. Records are listed in pages with
//! their timestamp and a one-line protocol summary; expanding one decodes its
//! link, network and transport headers (see [`net`]).

pub mod net;
pub mod ng;

use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::lookup;

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

fn probe(h: &Head<'_>) -> bool {
    magic(h.data).is_some_and(|(endian, _)| {
        let major = match endian {
            Endian::Little => crate::bytes::u16_le(h.data, 4),
            Endian::Big => crate::bytes::u16_be(h.data, 4),
        };
        major == Some(2)
    })
}

/// Byte order and whether timestamps are in nanoseconds.
fn magic(data: &[u8]) -> Option<(Endian, bool)> {
    let le = crate::bytes::u32_le(data, 0)?;
    let be = crate::bytes::u32_be(data, 0)?;
    match (le, be) {
        (MAGIC_MICRO, _) => Some((Endian::Little, false)),
        (MAGIC_NANO, _) => Some((Endian::Little, true)),
        (_, MAGIC_MICRO) => Some((Endian::Big, false)),
        (_, MAGIC_NANO) => Some((Endian::Big, true)),
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
        network: u32 "Link type" .with(|&v, n| n.value(crate::formats::util::datakit::enumv(v & 0xffff, 16, net::LINKTYPES))),
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

#[derive(Clone, Copy)]
struct Capture {
    endian: Endian,
    link: u32,
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

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read(input.span.sub(0, 4)).await?;
    let (endian, nano) = magic(&head)
        .ok_or_else(|| Diagnostic::malformed("not a pcap file").at(input.span.sub(0, 4)))?;
    let mut cur = Cursor::new(&cx, input.span, endian);
    let (header, span) = cur.record::<GlobalHeader>().await?;
    cx.emit(GlobalHeader::node("Global Header", span, endian));
    let link = header.network & 0xffff;
    cx.annotate(format!(
        "pcap {}.{}, {}, {}-endian, {} timestamps, snaplen {}",
        header.major,
        header.minor,
        link_name(link),
        if endian == Endian::Little {
            "little"
        } else {
            "big"
        },
        if nano { "ns" } else { "µs" },
        header.snaplen
    ));
    let capture = Capture { endian, link };
    let mut index = 0u64;
    while !cur.at_end() {
        let start = cur.pos();
        let (rec, _) = cur.record::<RecordHeader>().await?;
        let data = cur.span(rec.captured.into());
        cur.skip(rec.captured.into());
        let span = cur.since(start);
        let head = cx.read_avail(data.sub(0, net::HEADER_WINDOW)).await?;
        let digits = if nano { 9 } else { 6 };
        let mut summary = format!(
            "{} bytes, {}",
            rec.captured,
            time_text(rec.seconds.into(), rec.fraction.into(), digits)
        );
        if let Some(proto) = net::summarize(&head, link) {
            summary = format!("{summary}, {proto}");
        }
        let mut node = Node::new(format!("Packet {index}"))
            .span(span)
            .summary(summary)
            .lazy(packet, (capture, span));
        if data.len < u64::from(rec.captured) {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, rec.captured.into()),
                data.len,
            ));
        }
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn packet(cx: Cx, (capture, span): (Capture, Span)) -> Result<()> {
    let header = span.sub(0, RecordHeader::SIZE);
    let rec = crate::fields::parse(&cx, header, capture.endian, &(), RecordHeader::layout).await?;
    cx.emit(RecordHeader::node("Record Header", header, capture.endian));
    if rec.captured < rec.original {
        cx.diag(Diagnostic::note(format!(
            "only {} of {} bytes were captured",
            rec.captured, rec.original
        )));
    }
    let data = span.tail(RecordHeader::SIZE);
    let head = cx.read_avail(data.sub(0, net::HEADER_WINDOW)).await?;
    net::emit(&cx, data, &head, capture.link);
    Ok(())
}
