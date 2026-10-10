//! Other packet captures: Bluetooth btsnoop and Microsoft Network Monitor.
//!
//! btsnoop (RFC 1761's snoop adapted by Symbian and Android) is a 16-byte
//! header and big-endian records with a 64-bit microsecond timestamp since
//! year 0; packets are HCI (see [`super::hci`]). Network Monitor 1.x and
//! 2.x files are a header with a SYSTEMTIME start time, then frames found
//! through a frame table of offsets; each frame has a time offset from the
//! start and, from version 2.1 on, a trailer with its own media type.

use super::{Stats, emit_packet, offset, summarize, time_text};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::get;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Bluetooth btsnoop

declare_format!(pub BTSNOOP = "btsnoop", "Bluetooth HCI capture (btsnoop)", ["log", "cfa", "btsnoop"], "application/x-btsnoop",
    Probe::Magic(&[(0, b"btsnoop\0")]), btsnoop);

const BTSNOOP_LINKS: EnumTable = &[
    (1001, "HCI unencapsulated (H1)"),
    (1002, "HCI UART (H4)"),
    (1003, "HCI BSCP"),
    (1004, "HCI three-wire UART (H5)"),
    (2001, "Android monitor"),
];

const BTSNOOP_FLAGS: FlagTable = &[flag(1, "RECEIVED"), flag(2, "COMMAND_OR_EVENT")];

/// Microseconds from year 0 to the Unix epoch, as btsnoop counts them.
const BTSNOOP_EPOCH: i128 = 0x00dc_ddb3_0f2f_8000;
const BTSNOOP_RECORD: u64 = 24;

/// The decoder link for a btsnoop record: H4 (the indicator is in the
/// data), or the HCI packet type implied by the H1 flags.
fn btsnoop_link(link: u32, flags: u32) -> u32 {
    match link {
        1002 => 187,
        1001 => {
            let kind = match (flags & 2 != 0, flags & 1 != 0) {
                (true, true) => 4,
                (true, false) => 1,
                _ => 2,
            };
            0x1_0000 | kind
        }
        _ => u32::MAX,
    }
}

async fn btsnoop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let resumed = cx.resume::<(u64, u64, Stats)>();
    let mut f = if resumed.is_none() {
        Fields::emitting(&cx, &head, BE)
    } else {
        Fields::new(&head, BE)
    };
    f.ascii("Magic", 8).emit()?;
    let version = f.u32("Version").emit()?;
    let link = f.u32("Datalink").enumeration(BTSNOOP_LINKS).emit()?;
    let title = format!(
        "btsnoop v{version}, {}",
        lookup(BTSNOOP_LINKS, link.into()).unwrap_or("unknown link")
    );
    cx.annotate(title.clone());
    let mut cur = Cursor::new(&cx, file, BE);
    let (pos, mut index, mut stats) = resumed.unwrap_or((16, 0, Stats::default()));
    cur.seek(pos);
    while cur.remaining() >= BTSNOOP_RECORD {
        let start = cur.pos();
        cx.mark(|| (start, index, stats.clone()));
        let original = cur.u32().await?;
        let included = cur.u32().await?;
        let flags = cur.u32().await?;
        let _drops = cur.u32().await?;
        let micros = cur.u64().await?;
        let data = cur.span(included.into());
        cur.skip(included.into());
        let span = cur.since(start);
        let ns = i128::from(micros)
            .saturating_sub(BTSNOOP_EPOCH)
            .saturating_mul(1000);
        let dlink = btsnoop_link(link, flags);
        let line = summarize(&cx, input, data, dlink).await?;
        let rel = stats.add(original.into(), Some(ns), line.proto);
        let mut summary = format!(
            "{}, {}, {included} bytes",
            offset(rel.unwrap_or(0)),
            if flags & 1 == 0 { "sent" } else { "received" }
        );
        if included < original {
            summary.push_str(&format!(" of {original}"));
        }
        if !line.text.is_empty() {
            summary.push_str(&format!(", {}", line.text));
        }
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(
            Node::new(format!("Packet {index}"))
                .span(span)
                .summary(summary)
                .lazy(btsnoop_packet, (input, span, dlink)),
        )
        .await;
        index = index.saturating_add(1);
    }
    cx.annotate(format!("{title}; {}", stats.summary()));
    Ok(())
}

async fn btsnoop_packet(cx: Cx, (input, span, link): (Input, Span, u32)) -> Result<()> {
    let head = cx.block(span.sub(0, BTSNOOP_RECORD)).await?;
    let mut f = Fields::new(&head, BE);
    let original = f.u32("Original length").get()?;
    let included = f.u32("Included length").get()?;
    f.u32("Flags").get()?;
    f.u32("Drops").get()?;
    let micros = f.u64("Timestamp").get()?;
    let ns = i128::from(micros)
        .saturating_sub(BTSNOOP_EPOCH)
        .saturating_mul(1000);
    let secs = i64::try_from(ns.div_euclid(1_000_000_000)).unwrap_or(0);
    let frac = u64::try_from(ns.rem_euclid(1_000_000_000) / 1000).unwrap_or(0);
    let header = struct_node(
        "Record Header",
        span.sub(0, BTSNOOP_RECORD),
        BE,
        (),
        btsnoop_record,
    )
    .summary(time_text(secs, frac, 6));
    if included < original {
        cx.diag(Diagnostic::note(format!(
            "only {included} of {original} bytes were captured"
        )));
    }
    let data = span.tail(BTSNOOP_RECORD);
    emit_packet(&cx, input, data, link, vec![header], Vec::new()).await
}

fn btsnoop_record(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Original length").emit()?;
    f.u32("Included length").emit()?;
    f.u32("Flags").flags(BTSNOOP_FLAGS).emit()?;
    f.u32("Cumulative drops").emit()?;
    f.u64("Timestamp (µs since year 0)").emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Microsoft Network Monitor

declare_format!(pub NETMON = "netmon", "Microsoft Network Monitor capture", ["cap"], "application/x-netmon",
    Probe::Magic(&[(0, b"GMBU"), (0, b"RTSS")]), netmon);

const NETMON_MEDIA: EnumTable = &[
    (0, "NDIS (raw)"),
    (1, "Ethernet"),
    (2, "Token Ring"),
    (3, "FDDI"),
    (4, "ATM"),
    (5, "IEEE 1394"),
    (6, "IEEE 802.11"),
    (7, "Tunnel"),
    (8, "WWAN"),
    (9, "Raw IP"),
    (0xfffb, "Network info (extended)"),
    (0xfffc, "Payload header"),
    (0xfffd, "Network info"),
    (0xfffe, "DNS cache"),
    (0xffff, "Netmon filter"),
];

/// The decoder link for a Network Monitor media type.
fn netmon_link(media: u16) -> u32 {
    match media {
        1 => 1,
        2 => 6,
        3 => 10,
        9 => 101,
        0xe000..=0xefff => u32::from(media & 0x0fff),
        _ => u32::MAX,
    }
}

#[derive(Clone, Copy)]
struct Netmon {
    input: Input,
    major: u8,
    minor: u8,
    media: u16,
    start: i64,
    start_ms: u16,
}

impl Netmon {
    fn record_len(&self) -> u64 {
        if self.major >= 2 { 16 } else { 8 }
    }

    fn trailer_len(&self) -> u64 {
        match (self.major, self.minor) {
            (2, 1) => 2,
            (2, 2) => 6,
            (2, 3..) => 15,
            _ => 0,
        }
    }
}

async fn netmon(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x38)).await?;
    let resumed = cx.resume::<(u64, Stats)>();
    let mut f = if resumed.is_none() {
        Fields::emitting(&cx, &head, LE)
    } else {
        Fields::new(&head, LE)
    };
    let magic = f.ascii("Magic", 4).emit()?;
    let minor = f.u8("Minor version").emit()?;
    let major = f.u8("Major version").emit()?;
    let media = f.u16("Media type").enumeration(NETMON_MEDIA).emit()?;
    let st_span = f.peek_span(16);
    let mut st = [0u16; 8];
    for slot in &mut st {
        *slot = f.u16("SYSTEMTIME word").get()?;
    }
    let start = crate::formats::util::civil::systemtime(st).unwrap_or(0);
    let [year, month, _, day, hour, min, sec, ms] = st;
    let node = Node::new("Capture start time").span(st_span);
    f.node(if st.iter().all(|&w| w == 0) {
        node.summary("unset")
    } else {
        node.value(Value::Timestamp {
            unix_seconds: start,
        })
        .summary(format!(
            "{year:04}-{month:02}-{day:02} {hour:02}:{min:02}:{sec:02}.{ms:03} (SYSTEMTIME, no time zone)"
        ))
    });
    let table = f.u32("Frame table offset").hex().emit()?;
    let table_len = f.u32("Frame table length").emit()?;
    let user = f.u32("User data offset").hex().emit()?;
    let user_len = f.u32("User data length").emit()?;
    let comment = f.u32("Comment data offset").hex().emit()?;
    let comment_len = f.u32("Comment data length").emit()?;
    if major >= 2 {
        f.u32("Process info offset").hex().emit()?;
        f.u32("Process info count").emit()?;
    }
    let frames = u64::from(table_len / 4);
    let table_span = file.sub(table.into(), table_len.into());
    if resumed.is_none() {
        if user_len > 0 {
            cx.emit(Node::new("User data").span(file.sub(user.into(), user_len.into())));
        }
        if comment_len > 0 {
            cx.emit(Node::new("Comment data").span(file.sub(comment.into(), comment_len.into())));
        }
        cx.emit(
            Node::new("Frame table")
                .span(table_span)
                .summary(crate::formats::util::fmt::plural(frames, "frame offset"))
                .lazy(frame_table, table_span),
        );
    }
    let title = format!(
        "Network Monitor {major}.{minor} ({magic}), {}",
        lookup(NETMON_MEDIA, media.into()).unwrap_or("unknown media")
    );
    cx.annotate(title.clone());
    let nm = Netmon {
        input,
        major,
        minor,
        media,
        start,
        start_ms: ms,
    };
    let (first, mut stats) = resumed.unwrap_or((0, Stats::default()));
    let mut cur = Cursor::new(&cx, table_span, LE);
    cur.seek(first.saturating_mul(4));
    let mut index = first;
    while cur.remaining() >= 4 {
        cx.mark(|| (index, stats.clone()));
        let entry_at = cur.pos();
        let at = u64::from(cur.u32().await?);
        let entry = cur.since(entry_at);
        let header_len = if major >= 2 { 0x38 } else { 0x30 };
        if at < header_len || at >= file.len {
            cx.push(
                Node::new(format!("Frame {index}"))
                    .span(entry)
                    .diag(Diagnostic::malformed(format!(
                        "frame offset {at:#x} is outside the frame area"
                    ))),
            )
            .await;
            index = index.saturating_add(1);
            continue;
        }
        let rec = cx.read_avail(file.sub(at, nm.record_len())).await?;
        let (delta_us, original, included) = if major >= 2 {
            (
                get::<u64>(&rec, 0, LE).unwrap_or(0),
                get::<u32>(&rec, 8, LE).unwrap_or(0),
                get::<u32>(&rec, 12, LE).unwrap_or(0),
            )
        } else {
            (
                u64::from(get::<u32>(&rec, 0, LE).unwrap_or(0)).saturating_mul(1000),
                u32::from(get::<u16>(&rec, 4, LE).unwrap_or(0)),
                u32::from(get::<u16>(&rec, 6, LE).unwrap_or(0)),
            )
        };
        let data = file.sub(at.saturating_add(nm.record_len()), included.into());
        let mut frame_media = media;
        let tlen = nm.trailer_len();
        if tlen > 0 {
            let t = cx
                .read_avail(
                    file.sub(
                        at.saturating_add(nm.record_len())
                            .saturating_add(included.into()),
                        2,
                    ),
                )
                .await?;
            frame_media = get::<u16>(&t, 0, LE).unwrap_or(media);
        }
        let span = file.sub(
            at,
            nm.record_len()
                .saturating_add(included.into())
                .saturating_add(tlen),
        );
        let link = netmon_link(frame_media);
        let line = summarize(&cx, input, data, link).await?;
        let ns = i128::from(start)
            .saturating_mul(1_000_000_000)
            .saturating_add(i128::from(ms).saturating_mul(1_000_000))
            .saturating_add(i128::from(delta_us).saturating_mul(1000));
        let rel = stats.add(original.into(), Some(ns), line.proto);
        let mut summary = format!("{}, {included} bytes", offset(rel.unwrap_or(0)));
        if included < original {
            summary.push_str(&format!(" of {original}"));
        }
        if !line.text.is_empty() {
            summary.push_str(&format!(", {}", line.text));
        }
        cx.progress((index.saturating_add(1)).min(frames), frames);
        cx.push(
            Node::new(format!("Frame {index}"))
                .span(span)
                .summary(summary)
                .lazy(netmon_frame, (nm, span, link, included)),
        )
        .await;
        index = index.saturating_add(1);
    }
    cx.annotate(format!("{title}; {}", stats.summary()));
    Ok(())
}

async fn frame_table(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let mut i = 0u64;
    while cur.remaining() >= 4 {
        let at = cur.pos();
        let v = cur.u32().await?;
        cx.push(
            Node::new(format!("Frame {i}"))
                .span(span.sub(at, 4))
                .value(crate::formats::util::val::hex(v, 32)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn netmon_frame(cx: Cx, (nm, span, link, included): (Netmon, Span, u32, u32)) -> Result<()> {
    let rl = nm.record_len();
    let rec = cx.read(span.sub(0, rl)).await?;
    let delta_us = if nm.major >= 2 {
        get::<u64>(&rec, 0, LE).unwrap_or(0)
    } else {
        u64::from(get::<u32>(&rec, 0, LE).unwrap_or(0)).saturating_mul(1000)
    };
    let total_us = i128::from(nm.start_ms)
        .saturating_mul(1000)
        .saturating_add(i128::from(delta_us));
    let secs = nm
        .start
        .saturating_add(i64::try_from(total_us / 1_000_000).unwrap_or(0));
    let frac = u64::try_from(total_us % 1_000_000).unwrap_or(0);
    let layout: crate::fields::Layout<(), ()> = if nm.major >= 2 {
        netmon2_record
    } else {
        netmon1_record
    };
    let header = struct_node("Frame header", span.sub(0, rl), LE, (), layout)
        .summary(time_text(secs, frac, 6));
    let data = span.sub(rl, included.into());
    let mut trailer = Vec::new();
    let tlen = nm.trailer_len();
    if tlen > 0 {
        trailer.push(struct_node(
            "Frame trailer",
            span.sub(rl.saturating_add(included.into()), tlen),
            LE,
            tlen,
            netmon_trailer,
        ));
    }
    let _ = nm.media;
    emit_packet(&cx, nm.input, data, link, vec![header], trailer).await
}

fn netmon1_record(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Time offset (ms)").emit()?;
    f.u16("Frame length").emit()?;
    f.u16("Captured length").emit()?;
    Ok(())
}

fn netmon2_record(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u64("Time offset (µs)").emit()?;
    f.u32("Frame length").emit()?;
    f.u32("Captured length").emit()?;
    Ok(())
}

fn netmon_trailer(f: &mut Fields<'_>, len: &u64) -> Result<()> {
    f.u16("Media type").enumeration(NETMON_MEDIA).emit()?;
    if *len >= 6 {
        f.u32("Process info index").emit()?;
    }
    if *len >= 15 {
        f.u64("UTC timestamp").filetime().emit()?;
        f.u8("Time zone index").emit()?;
    }
    Ok(())
}
