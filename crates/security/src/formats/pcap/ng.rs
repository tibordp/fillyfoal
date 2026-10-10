//! pcapng: a sequence of typed blocks `type, length, body, length`.
//!
//! A Section Header Block starts each section and fixes its byte order;
//! Interface Description Blocks declare link types, timestamp resolutions
//! and offsets that later packet blocks refer to by interface number. Blocks
//! are listed in pages; packet blocks (enhanced, simple and the obsolete
//! packet block) carry the same one-line summary as pcap records, and
//! expanding a block decodes its fields, its options (by block type) and
//! the packet. Name resolution, interface statistics, decryption secrets
//! (TLS key logs as lines), custom and systemd journal blocks are decoded
//! too. The capture's summary counts sections, interfaces and packets once
//! the listing reaches the end.

use crate::bytes::{u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::pcap::dec::{ipv4, ipv6, mac};
use crate::formats::pcap::{Stats, emit_packet, link_name, net, offset, summarize, time_text};
use crate::formats::util::binutil::get;
use crate::formats::util::val::{enumv, hex, int, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "pcapng",
    title: "pcapng packet capture",
    extensions: &["pcapng", "ntar", "scap"],
    mime: "application/x-pcapng",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const SHB: u32 = 0x0a0d_0d0a;
const BOM: u32 = 0x1a2b_3c4d;
/// Interfaces remembered per section (for timestamps and link types).
const MAX_INTERFACES: usize = 4096;

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x0a\x0d\x0d\x0a")
        && (h.at(8, b"\x1a\x2b\x3c\x4d") || h.at(8, b"\x4d\x3c\x2b\x1a"))
}

const BLOCK_TYPES: EnumTable = &[
    (0x0000_0001, "Interface Description Block"),
    (0x0000_0002, "Packet Block (obsolete)"),
    (0x0000_0003, "Simple Packet Block"),
    (0x0000_0004, "Name Resolution Block"),
    (0x0000_0005, "Interface Statistics Block"),
    (0x0000_0006, "Enhanced Packet Block"),
    (0x0000_0007, "IRIG Timestamp Block"),
    (0x0000_0008, "ARINC 429 Block"),
    (0x0000_0009, "systemd Journal Export Block"),
    (0x0000_000a, "Decryption Secrets Block"),
    (0x0000_0101, "Hone Project Machine Info Block"),
    (0x0000_0102, "Hone Project Connection Event Block"),
    (0x0000_0201, "Sysdig Machine Info Block"),
    (0x0000_0202, "Sysdig Process Info Block"),
    (0x0000_0203, "Sysdig FD List Block"),
    (0x0000_0204, "Sysdig Event Block"),
    (0x0000_0205, "Sysdig Interface List Block"),
    (0x0000_0206, "Sysdig User List Block"),
    (0x0000_0bad, "Custom Block (copyable)"),
    (0x4000_0bad, "Custom Block"),
    (0x0a0d_0d0a, "Section Header Block"),
];

const SECRETS_TYPES: EnumTable = &[
    (0x544c_534b, "TLS key log"),
    (0x5747_4b4c, "WireGuard key log"),
    (0x5a4e_574b, "ZigBee NWK key"),
    (0x5a41_5053, "ZigBee APS key"),
    (0x5353_484b, "SSH key log"),
    (0x4f50_4355, "OPC UA key log"),
];

const NRB_TYPES: EnumTable = &[
    (0, "end"),
    (1, "IPv4"),
    (2, "IPv6"),
    (3, "EUI-48"),
    (4, "EUI-64"),
];

const RECEPTION_TYPES: EnumTable = &[
    (0, "not specified"),
    (1, "unicast"),
    (2, "multicast"),
    (3, "broadcast"),
    (4, "promiscuous"),
];

const HASH_ALGORITHMS: EnumTable = &[
    (0, "2's complement"),
    (1, "XOR"),
    (2, "CRC32"),
    (3, "MD5"),
    (4, "SHA-1"),
    (5, "Toeplitz"),
];

const VERDICT_TYPES: EnumTable = &[(0, "hardware"), (1, "Linux eBPF TC"), (2, "Linux eBPF XDP")];

#[derive(Clone, Copy, Debug)]
struct Interface {
    link: u32,
    resol: u8,
    /// Seconds added to every timestamp (`if_tsoffset`).
    offset: i64,
    snaplen: u32,
}

#[derive(Clone, Copy)]
struct Block {
    input: Input,
    span: Span,
    endian: Endian,
    kind: u32,
    iface: Option<Interface>,
}

/// The walker's state (for resume marks).
#[derive(Clone)]
struct Walk {
    pos: u64,
    endian: Endian,
    interfaces: Vec<Interface>,
    stats: Stats,
    sections: u32,
    total_interfaces: u64,
}

/// Units per second for a timestamp resolution.
fn units(resol: u8) -> u64 {
    if resol & 0x80 != 0 {
        1u64.checked_shl(u32::from(resol & 0x7f)).unwrap_or(0)
    } else {
        10u64.checked_pow(u32::from(resol)).unwrap_or(0)
    }
}

/// Splits a timestamp in units of `resol` into seconds, fraction and digits.
fn split_ts(ts: u64, resol: u8, offset: i64) -> (i64, u64, usize) {
    let u = units(resol);
    let Some(secs) = ts.checked_div(u) else {
        return (0, 0, 0);
    };
    let frac = ts.checked_rem(u).unwrap_or(0);
    let secs = i64::try_from(secs)
        .unwrap_or(i64::MAX)
        .saturating_add(offset);
    if resol & 0x80 == 0 && resol <= 9 {
        (secs, frac, usize::from(resol))
    } else {
        let nanos = u128::from(frac)
            .saturating_mul(1_000_000_000)
            .checked_div(u128::from(u))
            .unwrap_or(0);
        (secs, u64::try_from(nanos).unwrap_or(0), 9)
    }
}

/// A timestamp in nanoseconds since the epoch.
fn ts_nanos(ts: u64, resol: u8, offset: i64) -> i128 {
    let (s, f, digits) = split_ts(ts, resol, offset);
    let scale = 10i128
        .checked_pow(9u32.saturating_sub(u32::try_from(digits).unwrap_or(9)))
        .unwrap_or(1);
    i128::from(s)
        .saturating_mul(1_000_000_000)
        .saturating_add(i128::from(f).saturating_mul(scale))
}

fn ts_text(ts: u64, iface: Option<Interface>) -> String {
    let (resol, offset) = iface.map_or((6, 0), |i| (i.resol, i.offset));
    let (s, f, digits) = split_ts(ts, resol, offset);
    time_text(s, f, digits)
}

/// An Interface Statistics Block time: (seconds, text, note). dumpcap
/// writes these in microseconds whatever the interface's resolution; such
/// values are recognised (implausible in the stated unit, plausible in µs).
fn isb_time(ts: u64, iface: Option<Interface>) -> (i64, String, Option<Diagnostic>) {
    let (resol, offset) = iface.map_or((6, 0), |i| (i.resol, i.offset));
    let (secs, _, _) = split_ts(ts, resol, offset);
    // 1990-01-01 and 2100-01-01.
    let plausible = |s: i64| (631_152_000..4_102_444_800).contains(&s);
    if resol != 6 && ts != 0 && !plausible(secs) {
        let (us, f, digits) = split_ts(ts, 6, offset);
        if plausible(us) {
            return (
                us,
                time_text(us, f, digits),
                Some(Diagnostic::note(
                    "in microseconds, not the interface's resolution (as dumpcap writes it)",
                )),
            );
        }
    }
    (secs, ts_text(ts, iface), None)
}

fn endian_name(endian: Endian) -> &'static str {
    match endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut w = cx.resume::<Walk>().unwrap_or(Walk {
        pos: 0,
        endian: Endian::Little,
        interfaces: Vec::new(),
        stats: Stats::default(),
        sections: 0,
        total_interfaces: 0,
    });
    let mut cur = Cursor::new(&cx, input.span, Endian::Little);
    cur.seek(w.pos);
    let mut title = String::new();
    while !cur.at_end() {
        let start = cur.pos();
        w.pos = start;
        cx.mark(|| w.clone());
        let head = cur.peek(28).await?;
        let raw_type = u32_le(&head, 0).unwrap_or(0);
        if raw_type == SHB {
            w.endian = match u32_le(&head, 8) {
                Some(BOM) => Endian::Little,
                _ if u32_be(&head, 8) == Some(BOM) => Endian::Big,
                _ => {
                    return Err(Diagnostic::malformed("bad byte-order magic")
                        .at(input.span.sub(start.saturating_add(8), 4)));
                }
            };
            w.interfaces.clear();
            w.sections = w.sections.saturating_add(1);
        }
        let endian = w.endian;
        let kind = get::<u32>(&head, 0, endian).unwrap_or(0);
        let len = u64::from(get::<u32>(&head, 4, endian).unwrap_or(0));
        if len < 12 || !len.is_multiple_of(4) {
            return Err(Diagnostic::malformed(format!("bad block length {len:#x}"))
                .at(input.span.sub(start, 8)));
        }
        let span = input.span.sub(start, len);
        cur.seek(start.saturating_add(len));

        let name = lookup(BLOCK_TYPES, kind.into())
            .map_or_else(|| format!("Block {kind:#010x}"), str::to_owned);
        let mut summary = String::new();
        let mut iface = None;
        match kind {
            SHB => {
                let major = get::<u16>(&head, 12, endian).unwrap_or(0);
                let minor = get::<u16>(&head, 14, endian).unwrap_or(0);
                summary = format!(
                    "section {}, version {major}.{minor}, {}",
                    w.sections,
                    endian_name(endian)
                );
                if title.is_empty() {
                    title = format!("pcapng {major}.{minor}, {}", endian_name(endian));
                    cx.annotate(title.clone());
                }
            }
            1 => {
                let link = u32::from(get::<u16>(&head, 8, endian).unwrap_or(0));
                let snaplen = get::<u32>(&head, 12, endian).unwrap_or(0);
                let (resol, offset) = idb_options(&cx, span, endian).await;
                summary = format!(
                    "interface {}, {}, snaplen {snaplen}",
                    w.interfaces.len(),
                    link_name(link)
                );
                if w.interfaces.len() < MAX_INTERFACES {
                    w.interfaces.push(Interface {
                        link,
                        resol,
                        offset,
                        snaplen,
                    });
                }
                w.total_interfaces = w.total_interfaces.saturating_add(1);
            }
            6 | 2 | 3 => {
                let (id, data, original, ts) = match kind {
                    3 => {
                        let original = get::<u32>(&head, 8, endian).unwrap_or(0);
                        let first = w.interfaces.first().copied();
                        let snap = first.map_or(u32::MAX, |i| {
                            if i.snaplen == 0 { u32::MAX } else { i.snaplen }
                        });
                        let room = len.saturating_sub(16);
                        let captured = room.min(original.into()).min(snap.into());
                        (0u32, span.sub(12, captured), original, None)
                    }
                    _ => {
                        let id = if kind == 6 {
                            get::<u32>(&head, 8, endian).unwrap_or(0)
                        } else {
                            u32::from(get::<u16>(&head, 8, endian).unwrap_or(0))
                        };
                        let high = u64::from(get::<u32>(&head, 12, endian).unwrap_or(0));
                        let low = u64::from(get::<u32>(&head, 16, endian).unwrap_or(0));
                        let captured = get::<u32>(&head, 20, endian).unwrap_or(0);
                        let original = get::<u32>(&head, 24, endian).unwrap_or(0);
                        (
                            id,
                            span.sub(28, captured.into()),
                            original,
                            Some(high << 32 | low),
                        )
                    }
                };
                iface = w.interfaces.get(crate::bytes::to_usize(id.into())).copied();
                let (line, proto) = match iface {
                    Some(i) => {
                        let l = summarize(&cx, input, data, i.link).await?;
                        (l.text, l.proto)
                    }
                    None => (String::new(), ""),
                };
                let ns = ts.zip(iface).map(|(t, i)| ts_nanos(t, i.resol, i.offset));
                let index = w.stats.packets;
                let rel = w.stats.add(original.into(), ns, proto);
                summary = format!("packet {index}");
                if let Some(rel) = rel {
                    summary.push_str(&format!(", {}", offset(rel)));
                }
                summary.push_str(&format!(", {} bytes", data.len));
                if data.len < u64::from(original) {
                    summary.push_str(&format!(" of {original}"));
                }
                if iface.is_some_and(|_| w.total_interfaces > 1 || id > 0) {
                    summary.push_str(&format!(", interface {id}"));
                }
                if !line.is_empty() {
                    summary.push_str(&format!(", {line}"));
                }
            }
            5 => {
                let id = get::<u32>(&head, 8, endian).unwrap_or(0);
                iface = w.interfaces.get(crate::bytes::to_usize(id.into())).copied();
                summary = format!("interface {id}");
            }
            4 => {
                let data = cx.read_avail(span.sub(8, 0x400)).await?;
                summary = nrb_summary(&data, endian);
            }
            10 => {
                let t = get::<u32>(&head, 8, endian).unwrap_or(0);
                let n = get::<u32>(&head, 12, endian).unwrap_or(0);
                summary = format!(
                    "{}, {}",
                    lookup(SECRETS_TYPES, t.into()).unwrap_or("unknown secrets"),
                    crate::formats::util::fmt::size(n.into())
                );
            }
            0x0bad | 0x4000_0bad => {
                let pen = get::<u32>(&head, 8, endian).unwrap_or(0);
                summary = format!("private enterprise number {pen}");
            }
            _ => {}
        }
        let mut node = Node::new(name).span(span).lazy(
            block,
            Block {
                input,
                span,
                endian,
                kind,
                iface,
            },
        );
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if span.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, len),
                span.len,
            ));
        }
        cx.progress_in(input.span, input.span.offset.saturating_add(cur.pos()));
        cx.push(node).await;
    }
    if title.is_empty() {
        title = "pcapng".to_owned();
    }
    cx.annotate(format!(
        "{title}; {}, {}; {}",
        crate::formats::util::fmt::count(w.sections, "section", "sections"),
        crate::formats::util::fmt::count(w.total_interfaces, "interface", "interfaces"),
        w.stats.summary()
    ));
    Ok(())
}

/// `if_tsresol` and `if_tsoffset` of an Interface Description Block
/// (defaults: microseconds, no offset).
async fn idb_options(cx: &Cx, span: Span, endian: Endian) -> (u8, i64) {
    let mut out = (6u8, 0i64);
    let Ok(data) = cx.read_avail(span.sub(0, 0x1000)).await else {
        return out;
    };
    let end = crate::bytes::to_usize(span.len.saturating_sub(4)).min(data.len());
    let mut at = 16usize;
    while at.saturating_add(4) <= end {
        let code = get::<u16>(&data, at, endian).unwrap_or(0);
        let len = usize::from(get::<u16>(&data, at.saturating_add(2), endian).unwrap_or(0));
        if code == 0 {
            break;
        }
        let v = at.saturating_add(4);
        match (code, len) {
            (9, 1) => out.0 = data.get(v).copied().unwrap_or(6),
            (14, 8) => out.1 = get::<u64>(&data, v, endian).map_or(0, |x| x as i64),
            _ => {}
        }
        at = v.saturating_add(len.checked_next_multiple_of(4).unwrap_or(usize::MAX));
    }
    out
}

async fn block(cx: Cx, b: Block) -> Result<()> {
    let data = cx.block(b.span).await?;
    let mut f = Fields::emitting(&cx, &data, b.endian);
    f.u32("Block type").enumeration(BLOCK_TYPES).emit()?;
    let len = f.u32("Block total length").emit()?;
    let body_end = u64::from(len).saturating_sub(4);
    let mut options_from = None;
    match b.kind {
        SHB => {
            f.u32("Byte-order magic").hex().emit()?;
            f.u16("Major version").emit()?;
            f.u16("Minor version").emit()?;
            f.u64("Section length")
                .hex()
                .with(|&v, n| {
                    if v == u64::MAX {
                        n.summary("unspecified")
                    } else {
                        n.summary(crate::formats::util::fmt::size(v))
                    }
                })
                .emit()?;
            options_from = Some(f.pos());
        }
        1 => {
            f.u16("Link type").enumeration(net::LINKTYPES).emit()?;
            f.u16("Reserved").emit()?;
            f.u32("Snapshot length")
                .with(|&v, n| if v == 0 { n.summary("unlimited") } else { n })
                .emit()?;
            options_from = Some(f.pos());
        }
        6 | 2 => {
            if b.kind == 6 {
                f.u32("Interface ID").emit()?;
            } else {
                f.u16("Interface ID").emit()?;
                f.u16("Drops count").emit()?;
            }
            let ts_span = f.peek_span(8);
            let high = f.u32("Timestamp (high)").hex().emit()?;
            let low = f.u32("Timestamp (low)").hex().emit()?;
            let ts = u64::from(high) << 32 | u64::from(low);
            let (resol, offset) = b.iface.map_or((6, 0), |i| (i.resol, i.offset));
            let (secs, _, _) = split_ts(ts, resol, offset);
            f.node(
                Node::new("Timestamp")
                    .span(ts_span)
                    .value(Value::Timestamp { unix_seconds: secs })
                    .summary(ts_text(ts, b.iface))
                    .desc("From the high and low words, in the interface's resolution plus its offset"),
            );
            let captured = f.u32("Captured length").emit()?;
            f.u32("Original length").emit()?;
            let start = f.pos();
            let packet = b.span.sub(start, captured.into());
            emit_packet_node(&cx, b.input, packet, b.iface);
            let padded = u64::from(captured)
                .checked_next_multiple_of(4)
                .unwrap_or(u64::MAX);
            if padded > u64::from(captured) {
                cx.emit(Node::new("Padding").span(b.span.sub(
                    start.saturating_add(captured.into()),
                    padded.saturating_sub(captured.into()),
                )));
            }
            options_from = Some(start.saturating_add(padded));
        }
        3 => {
            let original = f.u32("Original length").emit()?;
            let room = body_end.saturating_sub(f.pos());
            let snap = b.iface.map_or(
                u32::MAX,
                |i| if i.snaplen == 0 { u32::MAX } else { i.snaplen },
            );
            let captured = room.min(original.into()).min(snap.into());
            let packet = b.span.sub(f.pos(), captured);
            emit_packet_node(&cx, b.input, packet, b.iface);
            let after = f.pos().saturating_add(captured);
            if after < body_end {
                cx.emit(
                    Node::new("Padding").span(b.span.sub(after, body_end.saturating_sub(after))),
                );
            }
        }
        4 => {
            let start = f.pos();
            let records = b.span.sub(start, body_end.saturating_sub(start));
            let end = name_records_end(&cx, &data, start, body_end, b.endian).await;
            cx.emit(
                Node::new("Records")
                    .span(b.span.sub(start, end.saturating_sub(start)))
                    .lazy(name_records, (records, b.endian)),
            );
            options_from = Some(end);
        }
        5 => {
            f.u32("Interface ID").emit()?;
            let ts_span = f.peek_span(8);
            let high = f.u32("Timestamp (high)").hex().emit()?;
            let low = f.u32("Timestamp (low)").hex().emit()?;
            let ts = u64::from(high) << 32 | u64::from(low);
            let (secs, text, note) = isb_time(ts, b.iface);
            let mut node = Node::new("Timestamp")
                .span(ts_span)
                .value(Value::Timestamp { unix_seconds: secs })
                .summary(text);
            if let Some(d) = note {
                node = node.diag(d);
            }
            f.node(node);
            options_from = Some(f.pos());
        }
        10 => {
            let t = f.u32("Secrets type").enumeration(SECRETS_TYPES).emit()?;
            let n = f.u32("Secrets length").emit()?;
            let secrets = b.span.sub(f.pos(), n.into());
            let node = Node::new("Secrets data")
                .span(secrets)
                .summary(crate::formats::util::fmt::size(secrets.len));
            cx.emit(match t {
                0x544c_534b | 0x5747_4b4c | 0x5353_484b | 0x4f50_4355 => {
                    node.lazy(key_log, secrets)
                }
                _ => node,
            });
            let padded = u64::from(n).checked_next_multiple_of(4).unwrap_or(u64::MAX);
            options_from = Some(f.pos().saturating_add(padded));
        }
        0x0bad | 0x4000_0bad => {
            f.u32("Private enterprise number").emit()?;
            let start = f.pos();
            cx.emit(
                Node::new("Custom data").span(b.span.sub(start, body_end.saturating_sub(start))),
            );
        }
        9 => {
            let start = f.pos();
            let entry = b.span.sub(start, body_end.saturating_sub(start));
            cx.emit(Node::new("Journal entry").span(entry).lazy(key_log, entry));
        }
        _ => {
            let start = f.pos();
            cx.emit(Node::new("Body").span(b.span.sub(start, body_end.saturating_sub(start))));
        }
    }
    if let Some(from) = options_from
        && from < body_end
    {
        let span = b.span.sub(from, body_end.saturating_sub(from));
        cx.emit(
            Node::new("Options")
                .span(span)
                .lazy(options, (span, b.endian, b.kind, b.iface)),
        );
    }
    f.seek(body_end);
    let trailer = f.u32("Block total length (trailer)").emit()?;
    if trailer != len {
        cx.diag(Diagnostic::malformed(format!(
            "trailing length {trailer:#x} differs from {len:#x}"
        )));
    }
    Ok(())
}

fn emit_packet_node(cx: &Cx, input: Input, packet: Span, iface: Option<Interface>) {
    match iface {
        Some(i) => {
            let group = Node::new("Packet data")
                .span(packet)
                .summary(format!("{}, {} bytes", link_name(i.link), packet.len))
                .lazy(packet_layers, (input, packet, i.link));
            cx.emit(group);
        }
        None => cx.emit(
            Node::new("Packet data")
                .span(packet)
                .diag(Diagnostic::malformed("refers to an undeclared interface")),
        ),
    }
}

async fn packet_layers(cx: Cx, (input, packet, link): (Input, Span, u32)) -> Result<()> {
    emit_packet(&cx, input, packet, link, Vec::new(), Vec::new()).await
}

/// Text secrets (key log files) and journal entries, one node per line.
async fn key_log(cx: Cx, span: Span) -> Result<()> {
    let mut lines = crate::formats::util::lines::Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        let text = line.text();
        let trimmed = text.trim_end_matches('\0');
        if trimmed.is_empty() {
            continue;
        }
        let (label, rest) = match trimmed.split_once([' ', '=']) {
            Some((l, r)) if !l.is_empty() && l.len() <= 64 => (l.to_owned(), r.to_owned()),
            _ => ("Line".to_owned(), trimmed.to_owned()),
        };
        cx.push(Node::new(label).span(line.span).value(Value::Text(rest)))
            .await;
    }
    Ok(())
}

/// The first records of a Name Resolution Block, for its summary.
fn nrb_summary(data: &[u8], endian: Endian) -> String {
    let mut at = 0usize;
    let mut parts = Vec::new();
    while parts.len() < 3 {
        let kind = get::<u16>(data, at, endian).unwrap_or(0);
        let len = usize::from(get::<u16>(data, at.saturating_add(2), endian).unwrap_or(0));
        let Some(v) = data.get(at.saturating_add(4)..at.saturating_add(4).saturating_add(len))
        else {
            break;
        };
        let (addr, rest) = match kind {
            1 => (v.get(..4).map(ipv4), v.get(4..)),
            2 => (v.get(..16).map(ipv6), v.get(16..)),
            _ => break,
        };
        let name = rest
            .unwrap_or_default()
            .split(|&b| b == 0)
            .find(|s| !s.is_empty())
            .map(|s| String::from_utf8_lossy(s).into_owned())
            .unwrap_or_default();
        parts.push(format!("{} = {name}", addr.unwrap_or_default()));
        at = at
            .saturating_add(4)
            .saturating_add(len.checked_next_multiple_of(4).unwrap_or(usize::MAX));
    }
    parts.join(", ")
}

/// The end of the Name Resolution records (after the end record).
async fn name_records_end(
    cx: &Cx,
    data: &crate::cx::Block,
    start: u64,
    end: u64,
    endian: Endian,
) -> u64 {
    let mut at = start;
    let mut n = 0u32;
    while at.saturating_add(4) <= end {
        if n.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        n = n.wrapping_add(1);
        let i = crate::bytes::to_usize(at);
        let kind = get::<u16>(&data.data, i, endian).unwrap_or(0);
        let len = u64::from(get::<u16>(&data.data, i.saturating_add(2), endian).unwrap_or(0));
        at = at
            .saturating_add(4)
            .saturating_add(len.checked_next_multiple_of(4).unwrap_or(u64::MAX));
        if kind == 0 {
            break;
        }
    }
    at.min(end)
}

async fn name_records(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let kind = cur.u16().await?;
        let len = cur.u16().await?;
        let value = cur.span(len.into());
        cur.skip(
            u64::from(len)
                .checked_next_multiple_of(4)
                .unwrap_or(u64::MAX),
        );
        let name = lookup(NRB_TYPES, kind.into())
            .map_or_else(|| format!("Record type {kind}"), |n| format!("{n} record"));
        let node = Node::new(name)
            .span(cur.since(start))
            .value(enumv(kind, 16, NRB_TYPES));
        let node = match kind {
            0 => {
                cx.push(node.renamed("End of records")).await;
                break;
            }
            1..=4 => {
                let bytes = cx.read(value).await?;
                let addr_len = match kind {
                    1 => 4,
                    2 => 16,
                    3 => 6,
                    _ => 8,
                };
                let addr = bytes.get(..addr_len).unwrap_or_default();
                let addr = match kind {
                    1 => ipv4(addr),
                    2 => ipv6(addr),
                    _ => mac(addr),
                };
                let names: Vec<String> = bytes
                    .get(addr_len..)
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                node.value(Value::Text(addr)).summary(names.join(", "))
            }
            _ => node.summary(format!("{len} bytes")),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// Option names: common ones first, then per block type.
fn option_name(kind: u32, code: u16) -> Option<&'static str> {
    let common = match code {
        0 => Some("opt_endofopt"),
        1 => Some("opt_comment"),
        2988 => Some("opt_custom (UTF-8, copyable)"),
        2989 => Some("opt_custom (binary, copyable)"),
        19372 => Some("opt_custom (UTF-8)"),
        19373 => Some("opt_custom (binary)"),
        _ => None,
    };
    if common.is_some() {
        return common;
    }
    let table: EnumTable = match kind {
        SHB => &[(2, "shb_hardware"), (3, "shb_os"), (4, "shb_userappl")],
        1 => &[
            (2, "if_name"),
            (3, "if_description"),
            (4, "if_IPv4addr"),
            (5, "if_IPv6addr"),
            (6, "if_MACaddr"),
            (7, "if_EUIaddr"),
            (8, "if_speed"),
            (9, "if_tsresol"),
            (10, "if_tzone"),
            (11, "if_filter"),
            (12, "if_os"),
            (13, "if_fcslen"),
            (14, "if_tsoffset"),
            (15, "if_hardware"),
            (16, "if_txspeed"),
            (17, "if_rxspeed"),
            (18, "if_iana_tzname"),
        ],
        6 | 2 | 3 => &[
            (2, "epb_flags"),
            (3, "epb_hash"),
            (4, "epb_dropcount"),
            (5, "epb_packetid"),
            (6, "epb_queue"),
            (7, "epb_verdict"),
            (8, "epb_processid_threadid"),
        ],
        4 => &[
            (2, "ns_dnsname"),
            (3, "ns_dnsIP4addr"),
            (4, "ns_dnsIP6addr"),
        ],
        5 => &[
            (2, "isb_starttime"),
            (3, "isb_endtime"),
            (4, "isb_ifrecv"),
            (5, "isb_ifdrop"),
            (6, "isb_filteraccept"),
            (7, "isb_osdrop"),
            (8, "isb_usrdeliv"),
        ],
        _ => &[],
    };
    lookup(table, code.into())
}

fn is_text(kind: u32, code: u16) -> bool {
    matches!(
        (kind, code),
        (_, 1 | 2988 | 19372) | (SHB, 2..=4) | (1, 2 | 3 | 12 | 15 | 18) | (4, 2)
    )
}

async fn options(
    cx: Cx,
    (span, endian, kind, iface): (Span, Endian, u32, Option<Interface>),
) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let code = cur.u16().await?;
        let len = cur.u16().await?;
        let value_span = cur.span(len.into());
        let bytes = cx.read(value_span).await?;
        cur.skip(
            u64::from(len)
                .checked_next_multiple_of(4)
                .unwrap_or(u64::MAX),
        );
        let name = option_name(kind, code).map_or_else(|| format!("option {code}"), str::to_owned);
        let mut node = Node::new(name).span(cur.since(start));
        let rd64 = |b: &[u8]| get::<u64>(b, 0, endian);
        let rd32 = |b: &[u8], at: usize| get::<u32>(b, at, endian);
        node = if code == 0 {
            node
        } else if is_text(kind, code) {
            node.value(Value::Text(
                String::from_utf8_lossy(&bytes)
                    .trim_end_matches('\0')
                    .to_owned(),
            ))
        } else {
            match (kind, code, bytes.len()) {
                (_, 2988 | 2989 | 19372 | 19373, n) if n >= 4 => {
                    let pen = rd32(&bytes, 0).unwrap_or(0);
                    node.value(Value::Bytes(
                        bytes.get(4..36.min(n)).unwrap_or_default().to_vec(),
                    ))
                    .summary(format!("private enterprise number {pen}"))
                }
                (1, 9, 1) => {
                    let r = bytes.first().copied().unwrap_or(6);
                    let unit = if r & 0x80 != 0 {
                        format!("2^-{} s", r & 0x7f)
                    } else {
                        format!("10^-{r} s")
                    };
                    node.value(uint(r, 8)).summary(unit)
                }
                (1, 13, 1) => node
                    .value(uint(bytes.first().copied().unwrap_or(0), 8))
                    .summary("bytes of FCS"),
                (1, 4, 8) => node.value(Value::Text(format!(
                    "{}/{}",
                    ipv4(bytes.get(..4).unwrap_or_default()),
                    ipv4(bytes.get(4..).unwrap_or_default())
                ))),
                (1, 5, 17) => node.value(Value::Text(format!(
                    "{}/{}",
                    ipv6(bytes.get(..16).unwrap_or_default()),
                    bytes.get(16).copied().unwrap_or(0)
                ))),
                (1, 6, 6) | (1, 7, 8) => node.value(Value::Text(mac(&bytes))),
                (1, 8 | 16 | 17, 8) => {
                    let bps = rd64(&bytes).unwrap_or(0);
                    node.value(uint(bps, 64)).summary(bit_rate(bps))
                }
                (1, 10, 4) => {
                    let v = rd32(&bytes, 0).unwrap_or(0) as i32;
                    node.value(int(v, 32)).summary("seconds east of UTC")
                }
                (1, 11, n) if n >= 1 => {
                    let t = bytes.first().copied().unwrap_or(0);
                    let rest = bytes.get(1..).unwrap_or_default();
                    match t {
                        0 => node
                            .value(Value::Text(String::from_utf8_lossy(rest).into_owned()))
                            .summary("libpcap filter string"),
                        1 => node
                            .value(Value::Bytes(rest.get(..32).unwrap_or(rest).to_vec()))
                            .summary(format!("BPF program, {} instructions", rest.len() / 8)),
                        _ => node.value(Value::Bytes(rest.get(..32).unwrap_or(rest).to_vec())),
                    }
                }
                (1, 14, 8) => {
                    let v = rd64(&bytes).map_or(0, |v| v as i64);
                    node.value(int(v, 64))
                        .summary("seconds added to timestamps")
                }
                (6 | 2 | 3, 2, 4) => {
                    let v = rd32(&bytes, 0).unwrap_or(0);
                    let dir = match v & 3 {
                        1 => "inbound",
                        2 => "outbound",
                        _ => "direction unknown",
                    };
                    let mut parts = vec![dir.to_owned()];
                    let rx = (v >> 2) & 7;
                    if rx != 0 {
                        parts.push(
                            lookup(RECEPTION_TYPES, rx.into())
                                .unwrap_or("reception ?")
                                .to_owned(),
                        );
                    }
                    let fcs = (v >> 5) & 15;
                    if fcs != 0 {
                        parts.push(format!("{fcs}-byte FCS"));
                    }
                    if v >> 16 != 0 {
                        parts.push(format!("link-layer errors {:#06x}", v >> 16));
                    }
                    node.value(hex(v, 32)).summary(parts.join(", "))
                }
                (6 | 2 | 3, 3, n) if n >= 1 => {
                    let alg = bytes.first().copied().unwrap_or(0);
                    node.value(Value::Bytes(
                        bytes.get(1..33.min(n)).unwrap_or_default().to_vec(),
                    ))
                    .summary(
                        lookup(HASH_ALGORITHMS, alg.into())
                            .unwrap_or("unknown hash")
                            .to_owned(),
                    )
                }
                (6 | 2 | 3, 7, n) if n >= 1 => {
                    let t = bytes.first().copied().unwrap_or(0);
                    node.value(Value::Bytes(
                        bytes.get(1..33.min(n)).unwrap_or_default().to_vec(),
                    ))
                    .summary(
                        lookup(VERDICT_TYPES, t.into())
                            .unwrap_or("unknown verdict")
                            .to_owned(),
                    )
                }
                (6 | 2 | 3, 8, 8) => {
                    let pid = rd32(&bytes, 0).unwrap_or(0);
                    let tid = rd32(&bytes, 4).unwrap_or(0);
                    node.value(uint(pid, 32))
                        .summary(format!("process {pid}, thread {tid}"))
                }
                (4, 3, 4) => node.value(Value::Text(ipv4(&bytes))),
                (4, 4, 16) => node.value(Value::Text(ipv6(&bytes))),
                (5, 2 | 3, 8) => {
                    let high = u64::from(rd32(&bytes, 0).unwrap_or(0));
                    let low = u64::from(rd32(&bytes, 4).unwrap_or(0));
                    let ts = high << 32 | low;
                    let (secs, text, note) = isb_time(ts, iface);
                    let node = node
                        .value(Value::Timestamp { unix_seconds: secs })
                        .summary(text);
                    match note {
                        Some(d) => node.diag(d),
                        None => node,
                    }
                }
                (_, _, 8) => node.value(uint(rd64(&bytes).unwrap_or(0), 64)),
                (_, _, 4) => node.value(uint(rd32(&bytes, 0).unwrap_or(0), 32)),
                _ => node.value(Value::Bytes(bytes.get(..32).unwrap_or(&bytes).to_vec())),
            }
        };
        cx.push(node).await;
        if code == 0 {
            break;
        }
    }
    Ok(())
}

fn bit_rate(bps: u64) -> String {
    match bps {
        0..1_000 => format!("{bps} bit/s"),
        1_000..1_000_000 if bps.is_multiple_of(1_000) => format!("{} kbit/s", bps / 1_000),
        1_000_000..1_000_000_000 if bps.is_multiple_of(1_000_000) => {
            format!("{} Mbit/s", bps / 1_000_000)
        }
        1_000_000_000.. if bps.is_multiple_of(1_000_000_000) => {
            format!("{} Gbit/s", bps / 1_000_000_000)
        }
        _ => format!("{bps} bit/s"),
    }
}
