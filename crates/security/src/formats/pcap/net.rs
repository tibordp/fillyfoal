//! A small decoder for the link, network and transport headers of captured
//! packets: Ethernet (with VLAN tags), Linux cooked capture, BSD loopback,
//! raw IP, ARP, IPv4, IPv6, TCP, UDP and ICMP.
//!
//! Headers are located synchronously from the first bytes of a packet; each
//! layer then becomes a lazy struct node over its exact span.

use crate::bytes::{to_u64, u16_be, u32_be, u32_le};
use crate::error::Result;
use crate::fields::{Endian, Fields, struct_node};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, field, flag, lookup};

/// Bytes of a packet looked at to find its headers.
pub const HEADER_WINDOW: u64 = 256;

pub const LINKTYPES: EnumTable = &[
    (0, "NULL (BSD loopback)"),
    (1, "ETHERNET"),
    (6, "IEEE802_5"),
    (8, "SLIP"),
    (9, "PPP"),
    (10, "FDDI"),
    (12, "RAW (DLT 12)"),
    (101, "RAW"),
    (104, "C_HDLC"),
    (105, "IEEE802_11"),
    (108, "LOOP"),
    (113, "LINUX_SLL"),
    (127, "IEEE802_11_RADIOTAP"),
    (147, "USER0"),
    (187, "BLUETOOTH_HCI_H4"),
    (189, "USB_LINUX"),
    (192, "PPI"),
    (195, "IEEE802_15_4"),
    (201, "BLUETOOTH_HCI_H4_WITH_PHDR"),
    (220, "USB_LINUX_MMAPPED"),
    (228, "IPV4"),
    (229, "IPV6"),
    (249, "NETLINK"),
    (263, "BLUETOOTH_LE_LL"),
    (276, "LINUX_SLL2"),
];

const ETHERTYPES: EnumTable = &[
    (0x0800, "IPv4"),
    (0x0806, "ARP"),
    (0x8035, "RARP"),
    (0x8100, "802.1Q VLAN"),
    (0x86dd, "IPv6"),
    (0x8847, "MPLS"),
    (0x8863, "PPPoE discovery"),
    (0x8864, "PPPoE session"),
    (0x888e, "EAPOL"),
    (0x88a8, "802.1ad"),
    (0x88cc, "LLDP"),
    (0x88f7, "PTP"),
];

pub const IP_PROTOCOLS: EnumTable = &[
    (0, "IPv6 hop-by-hop"),
    (1, "ICMP"),
    (2, "IGMP"),
    (4, "IPv4-in-IP"),
    (6, "TCP"),
    (17, "UDP"),
    (41, "IPv6"),
    (43, "IPv6 routing"),
    (44, "IPv6 fragment"),
    (47, "GRE"),
    (50, "ESP"),
    (51, "AH"),
    (58, "ICMPv6"),
    (59, "IPv6 no next header"),
    (60, "IPv6 destination options"),
    (89, "OSPF"),
    (132, "SCTP"),
];

const IPV4_FLAGS: FlagTable = &[
    flag(0x8000, "RESERVED"),
    flag(0x4000, "DF"),
    flag(0x2000, "MF"),
];

const TCP_FLAGS: FlagTable = &[
    flag(0x001, "FIN"),
    flag(0x002, "SYN"),
    flag(0x004, "RST"),
    flag(0x008, "PSH"),
    flag(0x010, "ACK"),
    flag(0x020, "URG"),
    flag(0x040, "ECE"),
    flag(0x080, "CWR"),
    flag(0x100, "AE"),
    field(0xf000, 0x5000, "DOFF=5"),
    field(0xf000, 0x6000, "DOFF=6"),
    field(0xf000, 0x7000, "DOFF=7"),
    field(0xf000, 0x8000, "DOFF=8"),
    field(0xf000, 0x9000, "DOFF=9"),
    field(0xf000, 0xa000, "DOFF=10"),
    field(0xf000, 0xb000, "DOFF=11"),
    field(0xf000, 0xc000, "DOFF=12"),
    field(0xf000, 0xd000, "DOFF=13"),
    field(0xf000, 0xe000, "DOFF=14"),
    field(0xf000, 0xf000, "DOFF=15"),
];

const ICMP_TYPES: EnumTable = &[
    (0, "Echo reply"),
    (3, "Destination unreachable"),
    (5, "Redirect"),
    (8, "Echo request"),
    (11, "Time exceeded"),
    (12, "Parameter problem"),
    (13, "Timestamp"),
    (14, "Timestamp reply"),
];

const ICMPV6_TYPES: EnumTable = &[
    (1, "Destination unreachable"),
    (2, "Packet too big"),
    (3, "Time exceeded"),
    (128, "Echo request"),
    (129, "Echo reply"),
    (133, "Router solicitation"),
    (134, "Router advertisement"),
    (135, "Neighbor solicitation"),
    (136, "Neighbor advertisement"),
];

const ARP_OPS: EnumTable = &[
    (1, "request"),
    (2, "reply"),
    (3, "RARP request"),
    (4, "RARP reply"),
];

const SLL_PACKET_TYPES: EnumTable = &[
    (0, "to us"),
    (1, "broadcast"),
    (2, "multicast"),
    (3, "to someone else"),
    (4, "sent by us"),
];

const LOOPBACK_FAMILIES: EnumTable = &[
    (2, "IPv4"),
    (24, "IPv6 (NetBSD/OpenBSD)"),
    (28, "IPv6 (FreeBSD)"),
    (30, "IPv6 (Darwin)"),
];

const PORTS: EnumTable = &[
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (67, "bootps"),
    (68, "bootpc"),
    (80, "http"),
    (110, "pop3"),
    (123, "ntp"),
    (143, "imap"),
    (161, "snmp"),
    (443, "https"),
    (514, "syslog"),
    (853, "domain-s"),
    (993, "imaps"),
    (1900, "ssdp"),
    (3306, "mysql"),
    (5353, "mdns"),
    (5432, "postgresql"),
    (8080, "http-alt"),
];

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Ethernet,
    Vlan,
    Sll,
    Loopback(Endian),
    Arp,
    Ipv4,
    Ipv6,
    Tcp,
    Udp,
    Icmp,
    Icmpv6,
}

/// One located header, relative to the packet start.
struct Layer {
    kind: Kind,
    offset: usize,
    len: usize,
}

pub fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn ipv4(b: &[u8]) -> String {
    b.iter().map(u8::to_string).collect::<Vec<_>>().join(".")
}

pub fn ipv6(b: &[u8]) -> String {
    let groups: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&p| u16::from_be_bytes(p))
        .collect();
    // Compress the longest run of zero groups.
    let (mut best, mut best_len, mut run, mut run_len) = (0usize, 0usize, 0usize, 0usize);
    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if run_len == 0 {
                run = i;
            }
            run_len = run_len.saturating_add(1);
            if run_len > best_len {
                best = run;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    let hexes = |gs: &[u16]| {
        gs.iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return hexes(&groups);
    }
    let head = groups.get(..best).unwrap_or_default();
    let tail = groups
        .get(best.saturating_add(best_len)..)
        .unwrap_or_default();
    format!("{}::{}", hexes(head), hexes(tail))
}

/// Locates the headers in `data` (the first bytes of a packet).
fn layers(data: &[u8], link: u32) -> Vec<Layer> {
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut next: Option<u16> = None; // ethertype
    let push = |out: &mut Vec<Layer>, kind, offset, len| out.push(Layer { kind, offset, len });
    match link {
        1 => {
            if data.len() >= 14 {
                push(&mut out, Kind::Ethernet, 0, 14);
                next = u16_be(data, 12);
                at = 14;
                // Up to two VLAN tags.
                for _ in 0..2 {
                    if matches!(next, Some(0x8100 | 0x88a8)) && data.len() >= at.saturating_add(4) {
                        push(&mut out, Kind::Vlan, at, 4);
                        next = u16_be(data, at.saturating_add(2));
                        at = at.saturating_add(4);
                    }
                }
            }
        }
        113 => {
            if data.len() >= 16 {
                push(&mut out, Kind::Sll, 0, 16);
                next = u16_be(data, 14);
                at = 16;
            }
        }
        0 | 108 => {
            if data.len() >= 4 {
                // The family is in host byte order (NULL) or network order (LOOP).
                let le = u32_le(data, 0).unwrap_or(0);
                let endian = if link == 0 && le < 0x100 {
                    Endian::Little
                } else {
                    Endian::Big
                };
                let family = match endian {
                    Endian::Little => le,
                    Endian::Big => u32_be(data, 0).unwrap_or(0),
                };
                push(&mut out, Kind::Loopback(endian), 0, 4);
                next = match family {
                    2 => Some(0x0800),
                    24 | 28 | 30 => Some(0x86dd),
                    _ => None,
                };
                at = 4;
            }
        }
        12 | 101 | 228 | 229 => {
            next = match data.first().map(|b| b >> 4) {
                Some(4) => Some(0x0800),
                Some(6) => Some(0x86dd),
                _ => None,
            };
        }
        _ => {}
    }
    let rest = data.get(at..).unwrap_or_default();
    let protocol = match next {
        Some(0x0800) if rest.len() >= 20 => {
            let ihl = usize::from(rest.first().copied().unwrap_or(0) & 0x0f).saturating_mul(4);
            push(&mut out, Kind::Ipv4, at, ihl.max(20));
            at = at.saturating_add(ihl.max(20));
            rest.get(9).copied()
        }
        Some(0x86dd) if rest.len() >= 40 => {
            push(&mut out, Kind::Ipv6, at, 40);
            at = at.saturating_add(40);
            rest.get(6).copied()
        }
        Some(0x0806) if rest.len() >= 8 => {
            let hlen = usize::from(rest.get(4).copied().unwrap_or(0));
            let plen = usize::from(rest.get(5).copied().unwrap_or(0));
            let len = hlen
                .saturating_add(plen)
                .saturating_mul(2)
                .saturating_add(8);
            push(&mut out, Kind::Arp, at, len);
            None
        }
        _ => None,
    };
    let rest = data.get(at..).unwrap_or_default();
    match protocol {
        Some(6) if rest.len() >= 20 => {
            let off = usize::from(rest.get(12).copied().unwrap_or(0) >> 4).saturating_mul(4);
            push(&mut out, Kind::Tcp, at, off.max(20));
        }
        Some(17) if rest.len() >= 8 => push(&mut out, Kind::Udp, at, 8),
        Some(1) if rest.len() >= 4 => push(&mut out, Kind::Icmp, at, 8.min(rest.len())),
        Some(58) if rest.len() >= 4 => push(&mut out, Kind::Icmpv6, at, 8.min(rest.len())),
        _ => {}
    }
    out
}

fn port(p: u16) -> String {
    lookup(PORTS, p.into()).map_or_else(|| p.to_string(), |name| format!("{p} ({name})"))
}

/// One line describing a packet, from its first bytes.
pub fn summarize(data: &[u8], link: u32) -> Option<String> {
    let layers = layers(data, link);
    let mut parts: Vec<String> = Vec::new();
    for layer in &layers {
        let b = data.get(layer.offset..).unwrap_or_default();
        match layer.kind {
            Kind::Ipv4 => {
                let src = b.get(12..16).map(ipv4).unwrap_or_default();
                let dst = b.get(16..20).map(ipv4).unwrap_or_default();
                parts.push(format!("IPv4 {src} → {dst}"));
            }
            Kind::Ipv6 => {
                let src = b.get(8..24).map(ipv6).unwrap_or_default();
                let dst = b.get(24..40).map(ipv6).unwrap_or_default();
                parts.push(format!("IPv6 {src} → {dst}"));
            }
            Kind::Tcp => {
                let flags = u16_be(b, 12).unwrap_or(0) & 0x1ff;
                let (set, _) = crate::value::decode_flags(TCP_FLAGS, flags.into());
                parts.push(format!(
                    "TCP {} → {} [{}]",
                    port(u16_be(b, 0).unwrap_or(0)),
                    port(u16_be(b, 2).unwrap_or(0)),
                    set.join(", ")
                ));
            }
            Kind::Udp => parts.push(format!(
                "UDP {} → {}",
                port(u16_be(b, 0).unwrap_or(0)),
                port(u16_be(b, 2).unwrap_or(0))
            )),
            Kind::Icmp => parts.push(format!(
                "ICMP {}",
                lookup(ICMP_TYPES, b.first().copied().unwrap_or(0).into()).unwrap_or("message")
            )),
            Kind::Icmpv6 => parts.push(format!(
                "ICMPv6 {}",
                lookup(ICMPV6_TYPES, b.first().copied().unwrap_or(0).into()).unwrap_or("message")
            )),
            Kind::Arp => parts.push(format!(
                "ARP {}",
                lookup(ARP_OPS, u16_be(b, 6).unwrap_or(0).into()).unwrap_or("?")
            )),
            _ => {}
        }
    }
    if parts.is_empty() {
        if let Some(layer) = layers.first()
            && layer.kind == Kind::Ethernet
        {
            let t = u16_be(data, 12).unwrap_or(0);
            return Some(format!(
                "Ethernet, {}",
                lookup(ETHERTYPES, t.into())
                    .map_or_else(|| format!("type {t:#06x}"), str::to_owned)
            ));
        }
        return None;
    }
    // Drop the IP layer when a transport layer follows, for brevity.
    Some(parts.join(", "))
}

/// Emits a node per decoded header of the packet at `data`, then the payload.
pub fn emit(cx: &crate::cx::Cx, data: Span, head: &[u8], link: u32) {
    let mut end = 0usize;
    for layer in layers(head, link) {
        let span = data.sub(to_u64(layer.offset), to_u64(layer.len));
        let (name, layout): (&'static str, crate::fields::Layout<(), ()>) = match layer.kind {
            Kind::Ethernet => ("Ethernet II", ethernet),
            Kind::Vlan => ("802.1Q VLAN tag", vlan),
            Kind::Sll => ("Linux cooked capture", sll),
            Kind::Loopback(Endian::Little) => ("Loopback (host order)", loopback),
            Kind::Loopback(Endian::Big) => ("Loopback", loopback),
            Kind::Arp => ("ARP", arp),
            Kind::Ipv4 => ("IPv4", ipv4_header),
            Kind::Ipv6 => ("IPv6", ipv6_header),
            Kind::Tcp => ("TCP", tcp),
            Kind::Udp => ("UDP", udp),
            Kind::Icmp => ("ICMP", icmp),
            Kind::Icmpv6 => ("ICMPv6", icmpv6),
        };
        let endian = match layer.kind {
            Kind::Loopback(e) => e,
            _ => Endian::Big,
        };
        cx.emit(struct_node(name, span, endian, (), layout));
        end = layer.offset.saturating_add(layer.len);
    }
    let payload = data.tail(to_u64(end));
    if !payload.is_empty() {
        cx.emit(
            Node::new(if end == 0 { "Data" } else { "Payload" })
                .span(payload)
                .summary(format!("{} bytes", payload.len)),
        );
    }
}

fn mac_field(f: &mut Fields<'_>, name: &'static str) -> Result<Vec<u8>> {
    f.bytes(name, 6)
        .with(|b, n| n.value(Value::Text(mac(b))))
        .emit()
}

fn ethernet(f: &mut Fields<'_>, _: &()) -> Result<()> {
    mac_field(f, "Destination")?;
    mac_field(f, "Source")?;
    f.u16("EtherType").enumeration(ETHERTYPES).emit()?;
    Ok(())
}

fn vlan(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("TCI")
        .hex()
        .with(|&t, n| n.summary(format!("priority {}, VLAN {}", t >> 13, t & 0x0fff)))
        .emit()?;
    f.u16("EtherType").enumeration(ETHERTYPES).emit()?;
    Ok(())
}

fn sll(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Packet type").enumeration(SLL_PACKET_TYPES).emit()?;
    f.u16("ARPHRD type").emit()?;
    let len = f.u16("Address length").emit()?;
    f.bytes("Address", 8)
        .with(|b, n| {
            n.value(Value::Text(mac(b
                .get(..usize::from(len.min(8)))
                .unwrap_or_default())))
        })
        .emit()?;
    f.u16("Protocol").enumeration(ETHERTYPES).emit()?;
    Ok(())
}

fn loopback(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Address family")
        .enumeration(LOOPBACK_FAMILIES)
        .emit()?;
    Ok(())
}

fn arp(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("Hardware type").emit()?;
    f.u16("Protocol type").enumeration(ETHERTYPES).emit()?;
    let hlen = f.u8("Hardware size").emit()?;
    let plen = f.u8("Protocol size").emit()?;
    f.u16("Opcode").enumeration(ARP_OPS).emit()?;
    let addr = |f: &mut Fields<'_>, name: &'static str, len: u8, hw: bool| {
        f.bytes(name, len.into())
            .with(|b, n| {
                n.value(Value::Text(if hw {
                    mac(b)
                } else if b.len() == 4 {
                    ipv4(b)
                } else {
                    crate::formats::util::datakit::hex_string(b)
                }))
            })
            .emit()
    };
    addr(f, "Sender hardware address", hlen, true)?;
    addr(f, "Sender protocol address", plen, false)?;
    addr(f, "Target hardware address", hlen, true)?;
    addr(f, "Target protocol address", plen, false)?;
    Ok(())
}

fn ipv4_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Version / IHL")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "version {}, header {} bytes",
                v >> 4,
                (v & 0x0f).saturating_mul(4)
            ))
        })
        .emit()?;
    f.u8("DSCP / ECN")
        .hex()
        .with(|&v, n| n.summary(format!("DSCP {}, ECN {}", v >> 2, v & 3)))
        .emit()?;
    f.u16("Total length").emit()?;
    f.u16("Identification").hex().emit()?;
    f.u16("Flags / fragment offset")
        .flags(IPV4_FLAGS)
        .with(|&v, n| {
            n.summary(format!(
                "fragment offset {}",
                (v & 0x1fff).saturating_mul(8)
            ))
        })
        .emit()?;
    f.u8("TTL").emit()?;
    f.u8("Protocol").enumeration(IP_PROTOCOLS).emit()?;
    f.u16("Header checksum").hex().emit()?;
    for name in ["Source", "Destination"] {
        f.bytes(name, 4)
            .with(|b, n| n.value(Value::Text(ipv4(b))))
            .emit()?;
    }
    if f.remaining() > 0 {
        f.bytes("Options", f.remaining()).emit()?;
    }
    Ok(())
}

fn ipv6_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Version / class / flow label")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "version {}, traffic class {:#04x}, flow {:#07x}",
                v >> 28,
                (v >> 20) & 0xff,
                v & 0xfffff
            ))
        })
        .emit()?;
    f.u16("Payload length").emit()?;
    f.u8("Next header").enumeration(IP_PROTOCOLS).emit()?;
    f.u8("Hop limit").emit()?;
    for name in ["Source", "Destination"] {
        f.bytes(name, 16)
            .with(|b, n| n.value(Value::Text(ipv6(b))))
            .emit()?;
    }
    Ok(())
}

fn port_field(f: &mut Fields<'_>, name: &'static str) -> Result<u16> {
    f.u16(name)
        .with(|&p, n| match lookup(PORTS, p.into()) {
            Some(s) => n.summary(s),
            None => n,
        })
        .emit()
}

fn tcp(f: &mut Fields<'_>, _: &()) -> Result<()> {
    port_field(f, "Source port")?;
    port_field(f, "Destination port")?;
    f.u32("Sequence number").emit()?;
    f.u32("Acknowledgment number").emit()?;
    f.u16("Data offset / flags")
        .flags(TCP_FLAGS)
        .with(|&v, n| n.summary(format!("header {} bytes", (v >> 12).saturating_mul(4))))
        .emit()?;
    f.u16("Window").emit()?;
    f.u16("Checksum").hex().emit()?;
    f.u16("Urgent pointer").emit()?;
    if f.remaining() > 0 {
        f.bytes("Options", f.remaining()).emit()?;
    }
    Ok(())
}

fn udp(f: &mut Fields<'_>, _: &()) -> Result<()> {
    port_field(f, "Source port")?;
    port_field(f, "Destination port")?;
    f.u16("Length").emit()?;
    f.u16("Checksum").hex().emit()?;
    Ok(())
}

fn icmp(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Type").enumeration(ICMP_TYPES).emit()?;
    f.u8("Code").emit()?;
    f.u16("Checksum").hex().emit()?;
    if f.remaining() >= 4 {
        f.u16("Identifier").emit()?;
        f.u16("Sequence").emit()?;
    }
    Ok(())
}

fn icmpv6(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Type").enumeration(ICMPV6_TYPES).emit()?;
    f.u8("Code").emit()?;
    f.u16("Checksum").hex().emit()?;
    if f.remaining() >= 4 {
        f.u32("Message body").hex().emit()?;
    }
    Ok(())
}
