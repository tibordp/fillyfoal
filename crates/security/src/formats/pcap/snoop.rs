//! Solaris snoop captures (RFC 1761): a 16-byte header (`snoop\0\0\0`,
//! version, datalink type), then records of original length, included
//! length, record length, cumulative drops and a seconds/microseconds
//! timestamp, each padded to a multiple of four bytes. Packets are decoded
//! like pcap's.

use super::{Stats, emit_packet, offset, summarize, time_text};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

declare_format!(pub SNOOP = "snoop", "Solaris snoop capture", ["snoop", "cap"], "application/x-snoop",
    Probe::Magic(&[(0, b"snoop\0\0\0")]), snoop);

const LINKS: EnumTable = &[
    (0, "IEEE 802.3"),
    (1, "IEEE 802.4"),
    (2, "IEEE 802.5"),
    (3, "IEEE 802.6"),
    (4, "Ethernet"),
    (5, "HDLC"),
    (6, "Character synchronous"),
    (7, "IBM channel-to-channel"),
    (8, "FDDI"),
    (9, "Other"),
    (18, "InfiniBand"),
    (26, "IP over InfiniBand"),
];

/// The pcap link type for a snoop datalink type, when decoded.
fn pcap_link(link: u32) -> u32 {
    match link {
        0 | 4 => 1,
        _ => u32::MAX,
    }
}

const RECORD_HEADER: u64 = 24;

async fn snoop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let resumed = cx.resume::<(u64, u32, Stats)>();
    let mut f = if resumed.is_none() {
        Fields::emitting(&cx, &head, Endian::Big)
    } else {
        Fields::new(&head, Endian::Big)
    };
    f.ascii("Magic", 8).emit()?;
    let version = f.u32("Version").emit()?;
    let link = f.u32("Datalink type").enumeration(LINKS).emit()?;
    let title = format!(
        "snoop v{version}, {}",
        lookup(LINKS, link.into()).unwrap_or("unknown link")
    );
    cx.annotate(title.clone());
    let mut cur = Cursor::new(&cx, file, Endian::Big);
    let (pos, mut packets, mut stats) = resumed.unwrap_or((16, 0, Stats::default()));
    cur.seek(pos);
    while cur.remaining() >= RECORD_HEADER {
        let start = cur.pos();
        cx.mark(|| (start, packets, stats.clone()));
        let original = cur.u32().await?;
        let included = cur.u32().await?;
        let record = cur.u32().await?;
        let _drops = cur.u32().await?;
        let secs = cur.u32().await?;
        let micros = cur.u32().await?;
        if u64::from(record) < RECORD_HEADER {
            break;
        }
        let data = file.sub(start.saturating_add(RECORD_HEADER), included.into());
        cur.seek(start.saturating_add(record.into()));
        let span = cur.since(start);
        let line = summarize(&cx, input, data, pcap_link(link)).await?;
        let ns = i128::from(secs)
            .saturating_mul(1_000_000_000)
            .saturating_add(i128::from(micros).saturating_mul(1000));
        let rel = stats.add(original.into(), Some(ns), line.proto);
        let mut summary = format!("{}, {included} bytes", offset(rel.unwrap_or(0)));
        if included < original {
            summary.push_str(&format!(" of {original}"));
        }
        if !line.text.is_empty() {
            summary.push_str(&format!(", {}", line.text));
        }
        cx.progress_in(file, file.offset.saturating_add(start));
        cx.push(
            Node::new(format!("Packet {packets}"))
                .span(span)
                .summary(summary)
                .lazy(packet, (input, span, link)),
        )
        .await;
        packets = packets.saturating_add(1);
    }
    cx.annotate(format!("{title}; {}", stats.summary()));
    Ok(())
}

async fn packet(cx: Cx, (input, span, link): (Input, Span, u32)) -> Result<()> {
    let head = cx.block(span.sub(0, RECORD_HEADER)).await?;
    let mut f = Fields::new(&head, Endian::Big);
    let original = f.u32("Original length").get()?;
    let included = f.u32("Included length").get()?;
    let record = f.u32("Record length").get()?;
    f.u32("Cumulative drops").get()?;
    let secs = f.u32("Seconds").get()?;
    let micros = f.u32("Microseconds").get()?;
    let header = crate::fields::struct_node(
        "Record Header",
        span.sub(0, RECORD_HEADER),
        Endian::Big,
        (),
        record_header,
    )
    .summary(time_text(secs.into(), micros.into(), 6));
    if included < original {
        cx.diag(crate::error::Diagnostic::note(format!(
            "only {included} of {original} bytes were captured"
        )));
    }
    let data = span.sub(RECORD_HEADER, included.into());
    let pad_at = RECORD_HEADER.saturating_add(included.into());
    let mut trailer = Vec::new();
    if pad_at < span.len && pad_at < u64::from(record) {
        trailer.push(Node::new("Padding").span(span.tail(pad_at)));
    }
    emit_packet(&cx, input, data, pcap_link(link), vec![header], trailer).await
}

fn record_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Original length").emit()?;
    f.u32("Included length").emit()?;
    f.u32("Record length").emit()?;
    f.u32("Cumulative drops").emit()?;
    f.u32("Timestamp (seconds)").timestamp().emit()?;
    f.u32("Timestamp (microseconds)").emit()?;
    Ok(())
}
