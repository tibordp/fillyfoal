//! pcapng: a sequence of typed blocks `type, length, body, length`.
//!
//! A Section Header Block starts each section and fixes its byte order;
//! Interface Description Blocks declare link types and timestamp
//! resolutions that later packet blocks refer to by interface number. Blocks
//! are listed in pages; packet blocks carry a protocol summary, and expanding
//! a block decodes its fields, options and packet headers.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::pcap::{link_name, net, time_text};
use crate::formats::util::datakit::{enumv, hex, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

pub static FORMAT: Format = Format {
    name: "pcapng",
    title: "pcapng packet capture",
    extensions: &["pcapng", "ntar"],
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
];

const NRB_TYPES: EnumTable = &[
    (0, "end"),
    (1, "IPv4"),
    (2, "IPv6"),
    (3, "EUI-48"),
    (4, "EUI-64"),
];

#[derive(Clone, Copy, Debug)]
struct Interface {
    link: u32,
    resol: u8,
}

#[derive(Clone, Copy)]
struct Block {
    span: Span,
    endian: Endian,
    kind: u32,
    iface: Option<Interface>,
}

fn rd32(endian: Endian, data: &[u8], at: usize) -> Option<u32> {
    match endian {
        Endian::Little => u32_le(data, at),
        Endian::Big => u32_be(data, at),
    }
}

fn rd16(endian: Endian, data: &[u8], at: usize) -> Option<u16> {
    match endian {
        Endian::Little => u16_le(data, at),
        Endian::Big => u16_be(data, at),
    }
}

/// Splits a timestamp in units of `resol` into seconds, fraction and digits.
fn split_ts(ts: u64, resol: u8) -> (i64, u64, usize) {
    let units: u64 = if resol & 0x80 != 0 {
        1u64.checked_shl(u32::from(resol & 0x7f)).unwrap_or(0)
    } else {
        10u64.checked_pow(u32::from(resol)).unwrap_or(0)
    };
    let Some(seconds) = ts.checked_div(units) else {
        return (0, 0, 0);
    };
    let frac = ts.checked_rem(units).unwrap_or(0);
    let seconds = i64::try_from(seconds).unwrap_or(i64::MAX);
    if resol & 0x80 == 0 && resol <= 9 {
        (seconds, frac, usize::from(resol))
    } else {
        let nanos = u128::from(frac)
            .saturating_mul(1_000_000_000)
            .checked_div(u128::from(units))
            .unwrap_or(0);
        (seconds, u64::try_from(nanos).unwrap_or(0), 9)
    }
}

fn ts_text(ts: u64, resol: u8) -> String {
    let (s, f, digits) = split_ts(ts, resol);
    time_text(s, f, digits)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, Endian::Little);
    let mut endian = Endian::Little;
    let mut interfaces: Vec<Interface> = Vec::new();
    let mut packets = 0u64;
    let mut first = true;
    while !cur.at_end() {
        let start = cur.pos();
        let head = cur.peek(28).await?;
        let raw_type = u32_le(&head, 0).unwrap_or(0);
        if raw_type == SHB {
            endian = match u32_le(&head, 8) {
                Some(BOM) => Endian::Little,
                _ if u32_be(&head, 8) == Some(BOM) => Endian::Big,
                _ => {
                    return Err(Diagnostic::malformed("bad byte-order magic")
                        .at(input.span.sub(start.saturating_add(8), 4)));
                }
            };
            interfaces.clear();
        }
        let kind = rd32(endian, &head, 0).unwrap_or(0);
        let len = u64::from(rd32(endian, &head, 4).unwrap_or(0));
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
                let major = rd16(endian, &head, 12).unwrap_or(0);
                let minor = rd16(endian, &head, 14).unwrap_or(0);
                summary = format!(
                    "version {major}.{minor}, {}-endian",
                    if endian == Endian::Little {
                        "little"
                    } else {
                        "big"
                    }
                );
                if first {
                    cx.annotate(format!("pcapng {major}.{minor}, {}", summary_tail(endian)));
                }
            }
            1 => {
                let link = u32::from(rd16(endian, &head, 8).unwrap_or(0));
                let snaplen = rd32(endian, &head, 12).unwrap_or(0);
                let resol = idb_resolution(&cx, span, endian).await;
                let i = Interface { link, resol };
                summary = format!(
                    "interface {}, {}, snaplen {snaplen}",
                    interfaces.len(),
                    link_name(link)
                );
                if interfaces.len() < MAX_INTERFACES {
                    interfaces.push(i);
                }
            }
            6 | 2 => {
                let id = if kind == 6 {
                    rd32(endian, &head, 8).unwrap_or(0)
                } else {
                    u32::from(rd16(endian, &head, 8).unwrap_or(0))
                };
                iface = interfaces.get(crate::bytes::to_usize(id.into())).copied();
                let high = u64::from(rd32(endian, &head, 12).unwrap_or(0));
                let low = u64::from(rd32(endian, &head, 16).unwrap_or(0));
                let captured = rd32(endian, &head, 20).unwrap_or(0);
                let resol = iface.map_or(6, |i| i.resol);
                summary = format!(
                    "packet {packets}, {captured} bytes, {}",
                    ts_text(high << 32 | low, resol)
                );
                if let Some(i) = iface {
                    let data = span.sub(28, captured.into());
                    let bytes = cx.read_avail(data.sub(0, net::HEADER_WINDOW)).await?;
                    if let Some(proto) = net::summarize(&bytes, i.link) {
                        summary = format!("{summary}, {proto}");
                    }
                }
                packets = packets.saturating_add(1);
            }
            3 => {
                iface = interfaces.first().copied();
                let original = rd32(endian, &head, 8).unwrap_or(0);
                summary = format!("packet {packets}, {original} bytes");
                if let Some(i) = iface {
                    let data = span.sub(12, len.saturating_sub(16));
                    let bytes = cx.read_avail(data.sub(0, net::HEADER_WINDOW)).await?;
                    if let Some(proto) = net::summarize(&bytes, i.link) {
                        summary = format!("{summary}, {proto}");
                    }
                }
                packets = packets.saturating_add(1);
            }
            5 => {
                let id = rd32(endian, &head, 8).unwrap_or(0);
                iface = interfaces.get(crate::bytes::to_usize(id.into())).copied();
                summary = format!("interface {id}");
            }
            _ => {}
        }
        first = false;
        let mut node = Node::new(name).span(span).lazy(
            block,
            Block {
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
        cx.push(node).await;
    }
    Ok(())
}

fn summary_tail(endian: Endian) -> &'static str {
    match endian {
        Endian::Little => "little-endian",
        Endian::Big => "big-endian",
    }
}

/// `if_tsresol` of an Interface Description Block (default: microseconds).
async fn idb_resolution(cx: &Cx, span: Span, endian: Endian) -> u8 {
    let Ok(data) = cx.read_avail(span.sub(0, 0x1000)).await else {
        return 6;
    };
    let end = crate::bytes::to_usize(span.len.saturating_sub(4)).min(data.len());
    let mut at = 16usize;
    while at.saturating_add(4) <= end {
        let code = rd16(endian, &data, at).unwrap_or(0);
        let len = usize::from(rd16(endian, &data, at.saturating_add(2)).unwrap_or(0));
        if code == 0 {
            break;
        }
        if code == 9 && len >= 1 {
            return data.get(at.saturating_add(4)).copied().unwrap_or(6);
        }
        at = at
            .saturating_add(4)
            .saturating_add(len.checked_next_multiple_of(4).unwrap_or(usize::MAX));
    }
    6
}

async fn block(cx: Cx, b: Block) -> Result<()> {
    let data = cx.block(b.span).await?;
    let mut f = Fields::emitting(&cx, &data, b.endian);
    f.u32("Block type").enumeration(BLOCK_TYPES).emit()?;
    let len = f.u32("Block total length").emit()?;
    let body_end = u64::from(len).saturating_sub(4);
    let resol = b.iface.map_or(6, |i| i.resol);
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
                        n
                    }
                })
                .emit()?;
            options_from = Some(f.pos());
        }
        1 => {
            f.u16("Link type").enumeration(net::LINKTYPES).emit()?;
            f.u16("Reserved").emit()?;
            f.u32("Snapshot length").emit()?;
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
            let (secs, _, _) = split_ts(ts, resol);
            f.node(
                Node::new("Timestamp")
                    .span(ts_span)
                    .value(Value::Timestamp { unix_seconds: secs })
                    .summary(ts_text(ts, resol))
                    .desc("From the high and low words, in the interface's resolution"),
            );
            let captured = f.u32("Captured length").emit()?;
            f.u32("Original length").emit()?;
            let start = f.pos();
            let packet = b.span.sub(start, captured.into());
            emit_packet(&cx, packet, b.iface);
            let padded = u64::from(captured)
                .checked_next_multiple_of(4)
                .unwrap_or(u64::MAX);
            options_from = Some(start.saturating_add(padded));
        }
        3 => {
            let original = f.u32("Original length").emit()?;
            let room = body_end.saturating_sub(f.pos());
            let packet = b.span.sub(f.pos(), room.min(original.into()));
            emit_packet(&cx, packet, b.iface);
        }
        4 => {
            let start = f.pos();
            let records = b.span.sub(start, body_end.saturating_sub(start));
            let end = name_records_end(&data, start, body_end, b.endian);
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
            f.node(
                Node::new("Timestamp")
                    .span(ts_span)
                    .summary(ts_text(ts, resol)),
            );
            options_from = Some(f.pos());
        }
        10 => {
            f.u32("Secrets type").enumeration(SECRETS_TYPES).emit()?;
            let n = f.u32("Secrets length").emit()?;
            let secrets = b.span.sub(f.pos(), n.into());
            cx.emit(Node::new("Secrets data").span(secrets));
            let padded = u64::from(n).checked_next_multiple_of(4).unwrap_or(u64::MAX);
            options_from = Some(f.pos().saturating_add(padded));
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
                .lazy(options, (span, b.endian, b.kind)),
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

fn emit_packet(cx: &Cx, packet: Span, iface: Option<Interface>) {
    match iface {
        Some(i) => {
            let group = Node::new("Packet data")
                .span(packet)
                .summary(format!("{}, {} bytes", link_name(i.link), packet.len))
                .lazy(packet_layers, (packet, i.link));
            cx.emit(group);
        }
        None => cx.emit(
            Node::new("Packet data")
                .span(packet)
                .diag(Diagnostic::malformed("refers to an undeclared interface")),
        ),
    }
}

async fn packet_layers(cx: Cx, (packet, link): (Span, u32)) -> Result<()> {
    let head = cx.read_avail(packet.sub(0, net::HEADER_WINDOW)).await?;
    net::emit(&cx, packet, &head, link);
    Ok(())
}

/// The end of the Name Resolution records (after the end record).
fn name_records_end(data: &crate::cx::Block, start: u64, end: u64, endian: Endian) -> u64 {
    let mut at = start;
    while at.saturating_add(4) <= end {
        let i = crate::bytes::to_usize(at);
        let kind = rd16(endian, &data.data, i).unwrap_or(0);
        let len = u64::from(rd16(endian, &data.data, i.saturating_add(2)).unwrap_or(0));
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
        let node = Node::new("Record")
            .span(cur.since(start))
            .value(enumv(kind, 16, NRB_TYPES));
        let node = match kind {
            0 => {
                cx.push(node).await;
                break;
            }
            1 | 2 => {
                let bytes = cx.read(value).await?;
                let addr_len = if kind == 1 { 4 } else { 16 };
                let addr = bytes.get(..addr_len).unwrap_or_default();
                let addr = if kind == 1 {
                    net::ipv4(addr)
                } else {
                    net::ipv6(addr)
                };
                let names: Vec<String> = bytes
                    .get(addr_len..)
                    .unwrap_or_default()
                    .split(|&b| b == 0)
                    .filter(|s| !s.is_empty())
                    .map(|s| String::from_utf8_lossy(s).into_owned())
                    .collect();
                node.summary(format!("{addr} = {}", names.join(", ")))
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
        6 | 2 => &[
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

async fn options(cx: Cx, (span, endian, kind): (Span, Endian, u32)) -> Result<()> {
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
        let rd64 = |b: &[u8]| match endian {
            Endian::Little => crate::bytes::u64_le(b, 0),
            Endian::Big => crate::bytes::u64_be(b, 0),
        };
        node = if code == 0 {
            node
        } else if is_text(kind, code) {
            node.value(Value::Text(String::from_utf8_lossy(&bytes).into_owned()))
        } else {
            match (kind, code, bytes.len()) {
                (1, 9, 1) => {
                    let r = bytes.first().copied().unwrap_or(6);
                    let unit = if r & 0x80 != 0 {
                        format!("2^-{} s", r & 0x7f)
                    } else {
                        format!("10^-{r} s")
                    };
                    node.value(uint(r, 8)).summary(unit)
                }
                (1, 13, 1) => node.value(uint(bytes.first().copied().unwrap_or(0), 8)),
                (1, 4, 8) => node.value(Value::Text(format!(
                    "{}/{}",
                    net::ipv4(bytes.get(..4).unwrap_or_default()),
                    net::ipv4(bytes.get(4..).unwrap_or_default())
                ))),
                (1, 5, 17) => node.value(Value::Text(format!(
                    "{}/{}",
                    net::ipv6(bytes.get(..16).unwrap_or_default()),
                    bytes.get(16).copied().unwrap_or(0)
                ))),
                (1, 6, 6) => node.value(Value::Text(net::mac(&bytes))),
                (1, 8 | 16 | 17, 8) => {
                    let bps = rd64(&bytes).unwrap_or(0);
                    node.value(uint(bps, 64)).summary(format!("{bps} bit/s"))
                }
                (1, 14, 8) => node.value(Value::Int {
                    value: rd64(&bytes).map_or(0, |v| v as i64),
                    bits: 64,
                }),
                (6 | 2, 2, 4) => {
                    let v = rd32(endian, &bytes, 0).unwrap_or(0);
                    let dir = match v & 3 {
                        1 => "inbound",
                        2 => "outbound",
                        _ => "direction unknown",
                    };
                    node.value(hex(v, 32)).summary(dir)
                }
                (_, _, 8) => node.value(uint(rd64(&bytes).unwrap_or(0), 64)),
                (_, _, 4) => node.value(uint(rd32(endian, &bytes, 0).unwrap_or(0), 32)),
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
