//! Link, network and transport layers of captured packets: Ethernet (with
//! 802.1Q/802.1ad tags, 802.3 LLC/SNAP), Linux cooked captures (SLL and
//! SLL2), BSD loopback, raw IP, MPLS, ARP, IPv4 (options, fragments, header
//! checksum), IPv6 (extension headers), ICMP, ICMPv6 (with NDP options and
//! MLD), IGMP, GRE, ESP, TCP (options, checksum), UDP (checksum) and SCTP.
//! Payloads are handed to the application decoders in [`super::app`].
//!
//! Each decoder takes the parent node, the offset of its header and the end
//! of the bytes it may use, and returns the end of what it accounted for.

use super::app;
use super::dec::{Dec, Ix, inet_sum, ipv4, ipv6, mac};
use super::wlan;
use crate::error::Diagnostic;
use crate::value::{EnumTable, FlagTable, field, flag, lookup};

pub const LINKTYPES: EnumTable = &[
    (0, "NULL (BSD loopback)"),
    (1, "ETHERNET"),
    (6, "IEEE802_5"),
    (8, "SLIP"),
    (9, "PPP"),
    (10, "FDDI"),
    (12, "RAW (DLT 12)"),
    (14, "RAW (DLT 14)"),
    (50, "PPP_HDLC"),
    (51, "PPP_ETHER"),
    (101, "RAW"),
    (104, "C_HDLC"),
    (105, "IEEE802_11"),
    (107, "FRELAY"),
    (108, "LOOP"),
    (113, "LINUX_SLL"),
    (119, "IEEE802_11_PRISM"),
    (122, "IP_OVER_FC"),
    (127, "IEEE802_11_RADIOTAP"),
    (147, "USER0"),
    (163, "IEEE802_11_AVS"),
    (187, "BLUETOOTH_HCI_H4"),
    (189, "USB_LINUX"),
    (192, "PPI"),
    (195, "IEEE802_15_4"),
    (201, "BLUETOOTH_HCI_H4_WITH_PHDR"),
    (220, "USB_LINUX_MMAPPED"),
    (227, "CAN_SOCKETCAN"),
    (228, "IPV4"),
    (229, "IPV6"),
    (249, "NETLINK"),
    (251, "BLUETOOTH_LE_LL"),
    (252, "WIRESHARK_UPPER_PDU"),
    (254, "BLUETOOTH_LINUX_MONITOR"),
    (256, "BLUETOOTH_LE_LL_WITH_PHDR"),
    (263, "BLUETOOTH_LE_LL"),
    (276, "LINUX_SLL2"),
];

const ETHERTYPES: EnumTable = &[
    (0x0800, "IPv4"),
    (0x0806, "ARP"),
    (0x0842, "Wake-on-LAN"),
    (0x22f0, "AVTP"),
    (0x22f3, "TRILL"),
    (0x6558, "Transparent Ethernet bridging"),
    (0x8035, "RARP"),
    (0x809b, "AppleTalk"),
    (0x8100, "802.1Q VLAN"),
    (0x8137, "IPX"),
    (0x86dd, "IPv6"),
    (0x8808, "Ethernet flow control"),
    (0x8809, "Slow protocols (LACP)"),
    (0x8847, "MPLS unicast"),
    (0x8848, "MPLS multicast"),
    (0x8863, "PPPoE discovery"),
    (0x8864, "PPPoE session"),
    (0x886d, "Intel ANS"),
    (0x8892, "PROFINET"),
    (0x888e, "EAPOL"),
    (0x88a4, "EtherCAT"),
    (0x88a8, "802.1ad service VLAN"),
    (0x88cc, "LLDP"),
    (0x88e5, "MACsec"),
    (0x88f7, "PTP"),
    (0x8902, "CFM"),
    (0x8906, "FCoE"),
    (0x9000, "Loopback"),
    (0x9100, "VLAN double tagging"),
];

pub const IP_PROTOCOLS: EnumTable = &[
    (0, "IPv6 hop-by-hop options"),
    (1, "ICMP"),
    (2, "IGMP"),
    (4, "IPv4 encapsulation"),
    (6, "TCP"),
    (8, "EGP"),
    (17, "UDP"),
    (27, "RDP"),
    (33, "DCCP"),
    (41, "IPv6 encapsulation"),
    (43, "IPv6 routing header"),
    (44, "IPv6 fragment header"),
    (46, "RSVP"),
    (47, "GRE"),
    (50, "ESP"),
    (51, "AH"),
    (58, "ICMPv6"),
    (59, "IPv6 no next header"),
    (60, "IPv6 destination options"),
    (88, "EIGRP"),
    (89, "OSPF"),
    (103, "PIM"),
    (112, "VRRP"),
    (115, "L2TP"),
    (132, "SCTP"),
    (135, "Mobility header"),
    (136, "UDP-Lite"),
    (137, "MPLS-in-IP"),
    (139, "HIP"),
    (140, "Shim6"),
    (143, "Ethernet"),
    (253, "Experimental"),
    (254, "Experimental"),
];

const IPV4_FLAGS: FlagTable = &[
    flag(0x8000, "RESERVED"),
    flag(0x4000, "DF"),
    flag(0x2000, "MF"),
];

const DSCP: EnumTable = &[
    (0, "CS0"),
    (8, "CS1"),
    (10, "AF11"),
    (12, "AF12"),
    (14, "AF13"),
    (16, "CS2"),
    (18, "AF21"),
    (20, "AF22"),
    (22, "AF23"),
    (24, "CS3"),
    (26, "AF31"),
    (28, "AF32"),
    (30, "AF33"),
    (32, "CS4"),
    (34, "AF41"),
    (36, "AF42"),
    (38, "AF43"),
    (40, "CS5"),
    (44, "VOICE-ADMIT"),
    (46, "EF"),
    (48, "CS6"),
    (56, "CS7"),
];

const ECN: EnumTable = &[(0, "Not-ECT"), (1, "ECT(1)"), (2, "ECT(0)"), (3, "CE")];

const IPV4_OPTIONS: EnumTable = &[
    (0, "End of options list"),
    (1, "No operation"),
    (7, "Record route"),
    (25, "Quick-start"),
    (68, "Timestamp"),
    (82, "Traceroute"),
    (130, "Security"),
    (131, "Loose source route"),
    (133, "Extended security"),
    (134, "Commercial security"),
    (136, "Stream ID"),
    (137, "Strict source route"),
    (148, "Router alert"),
];

const IPV6_OPTIONS: EnumTable = &[
    (0x00, "Pad1"),
    (0x01, "PadN"),
    (0x04, "Tunnel encapsulation limit"),
    (0x05, "Router alert"),
    (0x07, "CALIPSO"),
    (0x08, "SMF_DPD"),
    (0x11, "IOAM"),
    (0x26, "Quick-start"),
    (0x31, "IOAM"),
    (0x63, "RPL option"),
    (0x6d, "MPL option"),
    (0x8b, "ILNP nonce"),
    (0xc2, "Jumbo payload"),
    (0xc9, "Home address"),
    (0xee, "IPv6 DFF header"),
    (0x1e, "Experimental"),
    (0x3e, "Experimental"),
    (0x5e, "Experimental"),
    (0x7e, "Experimental"),
    (0x9e, "Experimental"),
    (0xbe, "Experimental"),
    (0xde, "Experimental"),
    (0xfe, "Experimental"),
];

const ROUTER_ALERTS: EnumTable = &[(0, "MLD"), (1, "RSVP"), (2, "Active networks")];

const ROUTING_TYPES: EnumTable = &[
    (0, "Source route (deprecated)"),
    (2, "Type 2 (Mobile IPv6)"),
    (3, "RPL source route"),
    (4, "Segment routing (SRH)"),
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
    field(0x0e00, 0x0200, "RESERVED=1"),
    field(0x0e00, 0x0400, "RESERVED=2"),
    field(0x0e00, 0x0600, "RESERVED=3"),
    field(0x0e00, 0x0800, "RESERVED=4"),
    field(0x0e00, 0x0a00, "RESERVED=5"),
    field(0x0e00, 0x0c00, "RESERVED=6"),
    field(0x0e00, 0x0e00, "RESERVED=7"),
];

const TCP_OPTIONS: EnumTable = &[
    (0, "End of option list"),
    (1, "No operation"),
    (2, "Maximum segment size"),
    (3, "Window scale"),
    (4, "SACK permitted"),
    (5, "SACK"),
    (6, "Echo (obsolete)"),
    (7, "Echo reply (obsolete)"),
    (8, "Timestamps"),
    (14, "Alternate checksum request (obsolete)"),
    (15, "Alternate checksum data (obsolete)"),
    (19, "MD5 signature"),
    (27, "Quick-start response"),
    (28, "User timeout"),
    (29, "TCP authentication (TCP-AO)"),
    (30, "Multipath TCP"),
    (34, "TCP Fast Open cookie"),
    (69, "Encryption negotiation (TCP-ENO)"),
    (172, "Accurate ECN order 0"),
    (174, "Accurate ECN order 1"),
    (253, "Experimental"),
    (254, "Experimental"),
];

const MPTCP_SUBTYPES: EnumTable = &[
    (0, "MP_CAPABLE"),
    (1, "MP_JOIN"),
    (2, "DSS"),
    (3, "ADD_ADDR"),
    (4, "REMOVE_ADDR"),
    (5, "MP_PRIO"),
    (6, "MP_FAIL"),
    (7, "MP_FASTCLOSE"),
    (8, "MP_TCPRST"),
];

const ICMP_TYPES: EnumTable = &[
    (0, "Echo reply"),
    (3, "Destination unreachable"),
    (4, "Source quench"),
    (5, "Redirect"),
    (8, "Echo request"),
    (9, "Router advertisement"),
    (10, "Router solicitation"),
    (11, "Time exceeded"),
    (12, "Parameter problem"),
    (13, "Timestamp request"),
    (14, "Timestamp reply"),
    (15, "Information request"),
    (16, "Information reply"),
    (17, "Address mask request"),
    (18, "Address mask reply"),
    (42, "Extended echo request"),
    (43, "Extended echo reply"),
];

const ICMP_UNREACH: EnumTable = &[
    (0, "Network unreachable"),
    (1, "Host unreachable"),
    (2, "Protocol unreachable"),
    (3, "Port unreachable"),
    (4, "Fragmentation needed"),
    (5, "Source route failed"),
    (6, "Destination network unknown"),
    (7, "Destination host unknown"),
    (8, "Source host isolated"),
    (9, "Network administratively prohibited"),
    (10, "Host administratively prohibited"),
    (11, "Network unreachable for TOS"),
    (12, "Host unreachable for TOS"),
    (13, "Communication administratively prohibited"),
    (14, "Host precedence violation"),
    (15, "Precedence cutoff in effect"),
];

const ICMP_REDIRECT: EnumTable = &[
    (0, "Redirect for network"),
    (1, "Redirect for host"),
    (2, "Redirect for TOS and network"),
    (3, "Redirect for TOS and host"),
];

const ICMP_TIME_EXCEEDED: EnumTable = &[
    (0, "TTL exceeded in transit"),
    (1, "Fragment reassembly time exceeded"),
];

const ICMP_PARAM: EnumTable = &[
    (0, "Pointer indicates the error"),
    (1, "Missing a required option"),
    (2, "Bad length"),
];

const ICMPV6_TYPES: EnumTable = &[
    (1, "Destination unreachable"),
    (2, "Packet too big"),
    (3, "Time exceeded"),
    (4, "Parameter problem"),
    (128, "Echo request"),
    (129, "Echo reply"),
    (130, "Multicast listener query"),
    (131, "Multicast listener report"),
    (132, "Multicast listener done"),
    (133, "Router solicitation"),
    (134, "Router advertisement"),
    (135, "Neighbor solicitation"),
    (136, "Neighbor advertisement"),
    (137, "Redirect"),
    (138, "Router renumbering"),
    (139, "Node information query"),
    (140, "Node information response"),
    (141, "Inverse neighbor discovery solicitation"),
    (142, "Inverse neighbor discovery advertisement"),
    (143, "Multicast listener report v2"),
    (151, "Multicast router advertisement"),
    (152, "Multicast router solicitation"),
    (153, "Multicast router termination"),
    (155, "RPL control message"),
    (160, "Extended echo request"),
    (161, "Extended echo reply"),
];

const ICMPV6_UNREACH: EnumTable = &[
    (0, "No route to destination"),
    (1, "Administratively prohibited"),
    (2, "Beyond scope of source address"),
    (3, "Address unreachable"),
    (4, "Port unreachable"),
    (5, "Source address failed ingress/egress policy"),
    (6, "Reject route to destination"),
    (7, "Error in source routing header"),
];

const ICMPV6_TIME_EXCEEDED: EnumTable = &[
    (0, "Hop limit exceeded in transit"),
    (1, "Fragment reassembly time exceeded"),
];

const ICMPV6_PARAM: EnumTable = &[
    (0, "Erroneous header field"),
    (1, "Unrecognized next header type"),
    (2, "Unrecognized IPv6 option"),
    (3, "First fragment has incomplete header chain"),
];

const NDP_OPTIONS: EnumTable = &[
    (1, "Source link-layer address"),
    (2, "Target link-layer address"),
    (3, "Prefix information"),
    (4, "Redirected header"),
    (5, "MTU"),
    (7, "Advertisement interval"),
    (8, "Home agent information"),
    (14, "Nonce"),
    (24, "Route information"),
    (25, "Recursive DNS server"),
    (31, "DNS search list"),
    (37, "Captive portal"),
    (38, "PREF64"),
];

const RA_FLAGS: FlagTable = &[
    flag(0x80, "MANAGED"),
    flag(0x40, "OTHER"),
    flag(0x20, "HOME_AGENT"),
    field(0x18, 0x08, "PRF=HIGH"),
    field(0x18, 0x18, "PRF=LOW"),
    field(0x18, 0x10, "PRF=RESERVED"),
    flag(0x04, "PROXY"),
];

const NA_FLAGS: FlagTable = &[
    flag(0x8000_0000, "ROUTER"),
    flag(0x4000_0000, "SOLICITED"),
    flag(0x2000_0000, "OVERRIDE"),
];

const PREFIX_FLAGS: FlagTable = &[
    flag(0x80, "ON_LINK"),
    flag(0x40, "AUTONOMOUS"),
    flag(0x20, "ROUTER_ADDRESS"),
];

const GROUP_RECORD_TYPES: EnumTable = &[
    (1, "MODE_IS_INCLUDE"),
    (2, "MODE_IS_EXCLUDE"),
    (3, "CHANGE_TO_INCLUDE_MODE"),
    (4, "CHANGE_TO_EXCLUDE_MODE"),
    (5, "ALLOW_NEW_SOURCES"),
    (6, "BLOCK_OLD_SOURCES"),
];

const IGMP_TYPES: EnumTable = &[
    (0x11, "Membership query"),
    (0x12, "IGMPv1 membership report"),
    (0x16, "IGMPv2 membership report"),
    (0x17, "Leave group"),
    (0x22, "IGMPv3 membership report"),
];

const ARP_OPS: EnumTable = &[
    (1, "request"),
    (2, "reply"),
    (3, "RARP request"),
    (4, "RARP reply"),
    (8, "InARP request"),
    (9, "InARP reply"),
];

const ARP_HARDWARE: EnumTable = &[
    (1, "Ethernet"),
    (6, "IEEE 802"),
    (15, "Frame Relay"),
    (16, "ATM"),
    (18, "Fibre Channel"),
    (20, "Serial line"),
    (24, "IEEE 1394"),
    (32, "InfiniBand"),
];

const ARPHRD: EnumTable = &[
    (1, "Ethernet"),
    (24, "IEEE 1394"),
    (32, "InfiniBand"),
    (280, "CAN"),
    (512, "PPP"),
    (768, "IPIP tunnel"),
    (769, "IP6IP6 tunnel"),
    (772, "Loopback"),
    (776, "SIT tunnel"),
    (778, "GRE tunnel"),
    (783, "IrDA"),
    (801, "IEEE 802.11"),
    (803, "IEEE 802.11 + radiotap"),
    (804, "IEEE 802.15.4"),
    (823, "IP6GRE tunnel"),
    (824, "Netlink"),
    (825, "6LoWPAN"),
    (826, "VSOCK monitor"),
    (65534, "None (tun)"),
    (65535, "Void"),
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
    (7, "OSI"),
    (16, "AppleTalk"),
    (23, "IPX"),
    (24, "IPv6 (NetBSD/OpenBSD/BSD/OS)"),
    (28, "IPv6 (FreeBSD/DragonFly)"),
    (30, "IPv6 (Darwin)"),
];

const LLC_SAPS: EnumTable = &[
    (0x00, "Null"),
    (0x04, "SNA"),
    (0x06, "IP"),
    (0x42, "Spanning tree (BPDU)"),
    (0x7e, "X.25"),
    (0x98, "ARP"),
    (0xaa, "SNAP"),
    (0xe0, "IPX"),
    (0xf0, "NetBIOS"),
    (0xfe, "ISO network layer"),
    (0xff, "Global"),
];

const GRE_FLAGS: FlagTable = &[
    flag(0x8000, "CHECKSUM"),
    flag(0x2000, "KEY"),
    flag(0x1000, "SEQUENCE"),
    field(0x0007, 0x0001, "VERSION=1 (PPTP)"),
];

const SCTP_CHUNKS: EnumTable = &[
    (0, "DATA"),
    (1, "INIT"),
    (2, "INIT ACK"),
    (3, "SACK"),
    (4, "HEARTBEAT"),
    (5, "HEARTBEAT ACK"),
    (6, "ABORT"),
    (7, "SHUTDOWN"),
    (8, "SHUTDOWN ACK"),
    (9, "ERROR"),
    (10, "COOKIE ECHO"),
    (11, "COOKIE ACK"),
    (14, "SHUTDOWN COMPLETE"),
    (15, "AUTH"),
    (64, "I-DATA"),
    (128, "ASCONF ACK"),
    (130, "RE-CONFIG"),
    (192, "FORWARD TSN"),
    (193, "ASCONF"),
];

const EAPOL_TYPES: EnumTable = &[
    (0, "EAP packet"),
    (1, "EAPOL-Start"),
    (2, "EAPOL-Logoff"),
    (3, "EAPOL-Key"),
    (4, "EAPOL-Encapsulated-ASF-Alert"),
    (5, "EAPOL-MKA"),
];

pub const PORTS: EnumTable = &[
    (7, "echo"),
    (20, "ftp-data"),
    (21, "ftp"),
    (22, "ssh"),
    (23, "telnet"),
    (25, "smtp"),
    (53, "domain"),
    (67, "bootps"),
    (68, "bootpc"),
    (69, "tftp"),
    (80, "http"),
    (88, "kerberos"),
    (110, "pop3"),
    (111, "sunrpc"),
    (123, "ntp"),
    (135, "epmap"),
    (137, "netbios-ns"),
    (138, "netbios-dgm"),
    (139, "netbios-ssn"),
    (143, "imap"),
    (161, "snmp"),
    (162, "snmp-trap"),
    (179, "bgp"),
    (389, "ldap"),
    (443, "https"),
    (445, "microsoft-ds"),
    (465, "submissions"),
    (500, "isakmp"),
    (514, "syslog"),
    (546, "dhcpv6-client"),
    (547, "dhcpv6-server"),
    (587, "submission"),
    (636, "ldaps"),
    (853, "domain-s"),
    (993, "imaps"),
    (995, "pop3s"),
    (1194, "openvpn"),
    (1812, "radius"),
    (1883, "mqtt"),
    (1900, "ssdp"),
    (3306, "mysql"),
    (3389, "ms-wbt-server"),
    (3478, "stun"),
    (4500, "ipsec-nat-t"),
    (4789, "vxlan"),
    (5060, "sip"),
    (5353, "mdns"),
    (5355, "llmnr"),
    (5432, "postgresql"),
    (6379, "redis"),
    (8080, "http-alt"),
    (8443, "https-alt"),
    (51820, "wireguard"),
];

/// The address family of an IP pseudo-header, for transport checksums.
#[derive(Clone, Copy)]
pub enum Pseudo {
    V4([u8; 4], [u8; 4]),
    V6([u8; 16], [u8; 16]),
}

impl Pseudo {
    /// The pseudo-header for `proto` and an upper-layer length of `len`.
    fn header(&self, proto: u8, len: usize) -> Vec<u8> {
        let mut h = Vec::with_capacity(40);
        match self {
            Pseudo::V4(s, d) => {
                h.extend_from_slice(s);
                h.extend_from_slice(d);
                h.push(0);
                h.push(proto);
                h.extend_from_slice(&u16::try_from(len).unwrap_or(u16::MAX).to_be_bytes());
            }
            Pseudo::V6(s, d) => {
                h.extend_from_slice(s);
                h.extend_from_slice(d);
                h.extend_from_slice(&u32::try_from(len).unwrap_or(u32::MAX).to_be_bytes());
                h.extend_from_slice(&[0, 0, 0, proto]);
            }
        }
        h
    }
}

/// What the IP layer tells the transport layer.
#[derive(Clone, Copy)]
pub struct Ip {
    pub pseudo: Pseudo,
    /// A fragment: the transport payload is incomplete.
    pub fragment: bool,
}

/// Decodes a packet of link type `link` under `p`; returns the end of what
/// was accounted for.
pub fn decode(b: &mut Dec, p: Ix, link: u32) -> usize {
    let end = b.len();
    match link {
        1 => ethernet(b, p, 0, end),
        113 => sll(b, p, 0, end),
        276 => sll2(b, p, 0, end),
        0 => null(b, p, 0, end, false),
        108 => null(b, p, 0, end, true),
        12 | 14 | 101 | 228 | 229 => raw_ip(b, p, 0, end),
        105 => wlan::ieee80211(b, p, 0, end, false),
        127 => wlan::radiotap(b, p, 0, end),
        187 => h4(b, p, 0, end),
        // btsnoop H1 records: the packet type comes from the record flags.
        0x1_0000..=0x1_00ff => {
            super::hci::packet(b, p, u8::try_from(link & 0xff).unwrap_or(0), 0, end)
        }
        201 => {
            if end < 4 {
                return 0;
            }
            let ix = b.group(p, "Bluetooth pseudo-header", 0, 4);
            let dir = b.num(ix, "Direction", 0, 4).unwrap_or(0);
            b.tail(|n| n.summary(if dir == 0 { "sent" } else { "received" }));
            h4(b, p, 4, end).max(4)
        }
        _ => 0,
    }
}

/// An HCI packet behind its H4 packet-type indicator.
pub fn h4(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let Some(t) = b.u8(off) else {
        return off;
    };
    let ix = b.group(p, "H4", off, 1);
    b.enm(ix, "Packet type", off, 1, super::hci::H4_TYPES);
    b.summary(ix, || {
        lookup(super::hci::H4_TYPES, t.into())
            .unwrap_or("unknown")
            .to_owned()
    });
    let body = off.saturating_add(1);
    super::hci::packet(b, p, t, body, end).max(body)
}

pub fn port(p: u16) -> String {
    lookup(PORTS, p.into()).map_or_else(|| p.to_string(), |name| format!("{p} ({name})"))
}

fn ethertype_name(t: u16) -> String {
    lookup(ETHERTYPES, t.into()).map_or_else(|| format!("type {t:#06x}"), str::to_owned)
}

/// Covers `used..end` after a layer: "Data" when nothing was decoded,
/// otherwise a trailer (link-layer padding, frame check sequence).
fn rest(b: &mut Dec, p: Ix, start: usize, used: usize, end: usize) -> usize {
    if used <= start {
        b.data(p, "Data", start, end)
    } else {
        b.data(p, "Trailer", used, end)
    }
}

pub fn ethernet(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 14 || !b.enter() {
        return off;
    }
    let ix = b.group(p, "Ethernet II", off, 14);
    let dst = b.mac(ix, "Destination", off.saturating_add(0));
    let src = b.mac(ix, "Source", off.saturating_add(6));
    let t = b.be16(off.saturating_add(12)).unwrap_or(0);
    let body = off.saturating_add(14);
    if t >= 0x600 {
        b.enm(ix, "EtherType", off.saturating_add(12), 2, ETHERTYPES);
    } else {
        b.num(ix, "Length", off.saturating_add(12), 2);
        b.update(ix, |n| n.renamed("IEEE 802.3 Ethernet"));
    }
    let (s, d) = (src.map(|a| mac(&a)), dst.map(|a| mac(&a)));
    b.summary(ix, || {
        let what = if t >= 0x600 {
            ethertype_name(t)
        } else {
            format!("802.3, length {t}")
        };
        format!(
            "{} → {}, {what}",
            s.clone().unwrap_or_default(),
            d.clone().unwrap_or_default()
        )
    });
    b.set_addrs(|| s.unwrap_or_default(), || d.unwrap_or_default());
    b.set_info("Ethernet", || {
        if t >= 0x600 {
            format!("Ethernet, {}", ethertype_name(t))
        } else {
            format!("IEEE 802.3, length {t}")
        }
    });
    let used = if t >= 0x600 {
        ether(b, p, t, body, end)
    } else {
        let llc_end = body.saturating_add(usize::from(t)).min(end);
        llc(b, p, body, llc_end)
    };
    b.leave();
    rest(b, p, body, used, end)
}

/// Dispatches on an EtherType.
pub fn ether(b: &mut Dec, p: Ix, t: u16, off: usize, end: usize) -> usize {
    match t {
        0x0800 => ipv4_packet(b, p, off, end),
        0x86dd => ipv6_packet(b, p, off, end),
        0x0806 | 0x8035 => arp(b, p, off, end),
        0x8100 | 0x88a8 | 0x9100 => vlan(b, p, t, off, end),
        0x8847 | 0x8848 => mpls(b, p, off, end),
        0x888e => eapol(b, p, off, end),
        0x6558 => ethernet(b, p, off, end),
        _ => off,
    }
}

fn vlan(b: &mut Dec, p: Ix, tpid: u16, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 4 || !b.enter() {
        return off;
    }
    let name = if tpid == 0x8100 {
        "802.1Q VLAN tag"
    } else {
        "802.1ad service tag"
    };
    let ix = b.group(p, name, off, 4);
    let tci = b.numx(ix, "Tag control information", off, 2).unwrap_or(0);
    let (pcp, dei, vid) = (tci >> 13, (tci >> 12) & 1, tci & 0x0fff);
    b.tail(|n| n.summary(format!("priority {pcp}, DEI {dei}, VLAN {vid}")));
    let t = b.be16(off.saturating_add(2)).unwrap_or(0);
    b.enm(ix, "EtherType", off.saturating_add(2), 2, ETHERTYPES);
    b.summary(ix, || {
        format!("VLAN {vid}, priority {pcp}, {}", ethertype_name(t))
    });
    let used = ether(b, p, t, off.saturating_add(4), end);
    b.leave();
    used.max(off.saturating_add(4))
}

fn llc(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 3 {
        return off;
    }
    let ix = b.group(p, "Logical-Link Control", off, 3);
    let dsap = b.enm(ix, "DSAP", off, 1, LLC_SAPS).unwrap_or(0);
    let ssap = b
        .enm(ix, "SSAP", off.saturating_add(1), 1, LLC_SAPS)
        .unwrap_or(0);
    b.numx(ix, "Control", off.saturating_add(2), 1);
    let mut at = off.saturating_add(3);
    if dsap == 0xaa && ssap == 0xaa && end.saturating_sub(at) >= 5 {
        let sp = b.sp(off, 8);
        b.update(ix, |n| n.span(sp));
        let oui = b.numx(ix, "Organization code", at, 3).unwrap_or(0);
        let t = b.be16(at.saturating_add(3)).unwrap_or(0);
        b.enm(ix, "Protocol ID", at.saturating_add(3), 2, ETHERTYPES);
        b.summary(ix, || format!("SNAP, OUI {oui:06x}, {}", ethertype_name(t)));
        at = at.saturating_add(5);
        b.set_info("LLC", || format!("LLC SNAP, {}", ethertype_name(t)));
        if oui == 0 {
            return ether(b, p, t, at, end).max(at);
        }
        return at;
    }
    let s = lookup(LLC_SAPS, dsap).unwrap_or("unknown SAP");
    b.summary(ix, || format!("DSAP {dsap:#04x} ({s}), SSAP {ssap:#04x}"));
    b.set_info("LLC", || format!("LLC {s}"));
    if dsap == 0x42 {
        return b.data(p, "Spanning tree BPDU", at, end);
    }
    at
}

fn sll(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 16 || !b.enter() {
        return off;
    }
    let ix = b.group(p, "Linux cooked capture", off, 16);
    let kind = b
        .enm(ix, "Packet type", off, 2, SLL_PACKET_TYPES)
        .unwrap_or(0);
    let hw = b
        .enm(ix, "ARPHRD type", off.saturating_add(2), 2, ARPHRD)
        .unwrap_or(0);
    let alen = b
        .num(ix, "Address length", off.saturating_add(4), 2)
        .unwrap_or(0);
    let addr = sll_addr(b, ix, off.saturating_add(6), alen);
    let proto = b.be16(off.saturating_add(14)).unwrap_or(0);
    b.enm(ix, "Protocol", off.saturating_add(14), 2, ETHERTYPES);
    let body = off.saturating_add(16);
    let used = sll_body(b, p, ix, (hw, kind, proto), addr, String::new(), body, end);
    b.leave();
    rest(b, p, body, used, end)
}

fn sll2(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 20 || !b.enter() {
        return off;
    }
    let ix = b.group(p, "Linux cooked capture v2", off, 20);
    let proto = b.be16(off).unwrap_or(0);
    b.enm(ix, "Protocol", off, 2, ETHERTYPES);
    b.num(ix, "Reserved", off.saturating_add(2), 2);
    let ifindex = b
        .num(ix, "Interface index", off.saturating_add(4), 4)
        .unwrap_or(0);
    let hw = b
        .enm(ix, "ARPHRD type", off.saturating_add(8), 2, ARPHRD)
        .unwrap_or(0);
    let kind = b
        .enm(
            ix,
            "Packet type",
            off.saturating_add(10),
            1,
            SLL_PACKET_TYPES,
        )
        .unwrap_or(0);
    let alen = b
        .num(ix, "Address length", off.saturating_add(11), 1)
        .unwrap_or(0);
    let addr = sll_addr(b, ix, off.saturating_add(12), alen);
    let body = off.saturating_add(20);
    let extra = format!(", interface {ifindex}");
    let used = sll_body(b, p, ix, (hw, kind, proto), addr, extra, body, end);
    b.leave();
    rest(b, p, body, used, end)
}

fn sll_addr(b: &mut Dec, ix: Ix, off: usize, alen: u64) -> String {
    let n = usize::try_from(alen.min(8)).unwrap_or(8);
    let a = b.bytes(off, n).map(mac).unwrap_or_default();
    let shown = a.clone();
    b.text(ix, "Address", off, 8, || shown);
    a
}

#[allow(clippy::too_many_arguments)]
fn sll_body(
    b: &mut Dec,
    p: Ix,
    ix: Ix,
    (hw, kind, proto): (u64, u64, u16),
    addr: String,
    extra: String,
    body: usize,
    end: usize,
) -> usize {
    let dir = lookup(SLL_PACKET_TYPES, kind).unwrap_or("unknown direction");
    let what = match hw {
        803 | 801 | 824 => lookup(ARPHRD, hw).unwrap_or("").to_owned(),
        _ => ethertype_name(proto),
    };
    b.summary(ix, || format!("{dir}, {addr}, {what}{extra}"));
    match hw {
        803 => wlan::radiotap(b, p, body, end),
        801 => wlan::ieee80211(b, p, body, end, false),
        824 => b.data(p, "Netlink message", body, end),
        _ => match proto {
            0x0004 => llc(b, p, body, end),
            _ => ether(b, p, proto, body, end),
        },
    }
}

fn null(b: &mut Dec, p: Ix, off: usize, end: usize, network_order: bool) -> usize {
    if end.saturating_sub(off) < 4 || !b.enter() {
        return off;
    }
    // NULL stores the family in the capturing host's byte order, LOOP in
    // network order.
    let raw_le = crate::bytes::u32_le(b.d, off).unwrap_or(0);
    let little = !network_order && raw_le < 0x100;
    let saved = b.endian;
    b.endian = if little {
        crate::fields::Endian::Little
    } else {
        crate::fields::Endian::Big
    };
    let ix = b.group(
        p,
        if network_order {
            "Loopback (OpenBSD)"
        } else {
            "Null/Loopback"
        },
        off,
        4,
    );
    let family = b
        .enm(ix, "Address family", off, 4, LOOPBACK_FAMILIES)
        .unwrap_or(0);
    b.endian = saved;
    b.summary(ix, || {
        format!(
            "{}, {}",
            lookup(LOOPBACK_FAMILIES, family).unwrap_or("unknown family"),
            if little {
                "host byte order (little-endian)"
            } else {
                "network byte order"
            }
        )
    });
    let body = off.saturating_add(4);
    let used = match family {
        2 => ipv4_packet(b, p, body, end),
        24 | 28 | 30 => ipv6_packet(b, p, body, end),
        _ => body,
    };
    b.leave();
    rest(b, p, body, used, end)
}

fn raw_ip(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    match b.u8(off).map(|v| v >> 4) {
        Some(4) => ipv4_packet(b, p, off, end),
        Some(6) => ipv6_packet(b, p, off, end),
        _ => off,
    }
}

fn mpls(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let mut at = off;
    let mut n = 0u32;
    while end.saturating_sub(at) >= 4 && n < 16 {
        let v = b.be32(at).unwrap_or(0);
        let ix = b.group(p, "MPLS label", at, 4);
        let (label, tc, bottom, ttl) = (v >> 12, (v >> 9) & 7, (v >> 8) & 1, v & 0xff);
        b.numx(ix, "Label stack entry", at, 4);
        b.tail(|n| {
            n.summary(format!(
                "label {label}, TC {tc}, bottom {bottom}, TTL {ttl}"
            ))
        });
        b.summary(ix, || format!("label {label}, TTL {ttl}"));
        at = at.saturating_add(4);
        n = n.saturating_add(1);
        if bottom == 1 {
            return raw_ip(b, p, at, end).max(at);
        }
    }
    at
}

fn eapol(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 4 {
        return off;
    }
    let len = usize::from(b.be16(off.saturating_add(2)).unwrap_or(0));
    let total = len.saturating_add(4).min(end.saturating_sub(off));
    let ix = b.group(p, "802.1X authentication", off, total);
    b.num(ix, "Version", off, 1);
    let t = b
        .enm(ix, "Type", off.saturating_add(1), 1, EAPOL_TYPES)
        .unwrap_or(0);
    b.num(ix, "Length", off.saturating_add(2), 2);
    let body = off.saturating_add(4);
    b.data(ix, "Body", body, off.saturating_add(total));
    let name = lookup(EAPOL_TYPES, t).unwrap_or("EAPOL");
    b.summary(ix, || name.to_owned());
    b.set_info("EAPOL", || format!("EAPOL {name}"));
    off.saturating_add(total)
}

fn arp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 8 {
        return off;
    }
    let hlen = usize::from(b.u8(off.saturating_add(4)).unwrap_or(0));
    let plen = usize::from(b.u8(off.saturating_add(5)).unwrap_or(0));
    let len = hlen
        .saturating_add(plen)
        .saturating_mul(2)
        .saturating_add(8);
    let ix = b.group(p, "ARP", off, len);
    b.enm(ix, "Hardware type", off, 2, ARP_HARDWARE);
    b.enm(ix, "Protocol type", off.saturating_add(2), 2, ETHERTYPES);
    b.num(ix, "Hardware size", off.saturating_add(4), 1);
    b.num(ix, "Protocol size", off.saturating_add(5), 1);
    let op = b
        .enm(ix, "Opcode", off.saturating_add(6), 2, ARP_OPS)
        .unwrap_or(0);
    let mut at = off.saturating_add(8);
    let mut addr = |b: &mut Dec, name: &'static str, len: usize, hw: bool| {
        let s = b
            .bytes(at, len)
            .map(|x| {
                if hw {
                    mac(x)
                } else if x.len() == 4 {
                    ipv4(x)
                } else {
                    crate::text::hex_lower(x)
                }
            })
            .unwrap_or_default();
        let shown = s.clone();
        b.text(ix, name, at, len, || shown);
        at = at.saturating_add(len);
        s
    };
    let sha = addr(b, "Sender hardware address", hlen, true);
    let spa = addr(b, "Sender protocol address", plen, false);
    let _tha = addr(b, "Target hardware address", hlen, true);
    let tpa = addr(b, "Target protocol address", plen, false);
    let info = match op {
        1 if spa == tpa => format!("Gratuitous ARP for {spa}"),
        1 => format!("Who has {tpa}? Tell {spa}"),
        2 => format!("{spa} is at {sha}"),
        _ => lookup(ARP_OPS, op).unwrap_or("unknown opcode").to_owned(),
    };
    let shown = info.clone();
    b.summary(ix, || shown);
    b.set_info("ARP", || format!("ARP {info}"));
    off.saturating_add(len).min(end)
}

// ---------------------------------------------------------------------------
// IPv4

/// An IPv4 packet: header, then its payload; returns the datagram's end.
pub fn ipv4_packet(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 20 || b.u8(off).map(|v| v >> 4) != Some(4) || !b.enter() {
        return off;
    }
    let used = ipv4_inner(b, p, off, end);
    b.leave();
    used
}

fn ipv4_inner(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let vihl = b.u8(off).unwrap_or(0);
    let ihl = usize::from(vihl & 0x0f).saturating_mul(4);
    let total = usize::from(b.be16(off.saturating_add(2)).unwrap_or(0));
    let ip_end = if total >= ihl.max(20) {
        off.saturating_add(total).min(end)
    } else {
        end
    };
    let ix = b.group(p, "IPv4", off, ihl.max(20));
    b.numx(ix, "Version / header length", off, 1);
    b.tail(|n| n.summary(format!("version {}, header {} bytes", vihl >> 4, ihl)));
    let tos = b
        .numx(ix, "Differentiated services", off.saturating_add(1), 1)
        .unwrap_or(0);
    b.tail(|n| {
        n.summary(format!(
            "DSCP {} ({}), ECN {}",
            tos >> 2,
            lookup(DSCP, tos >> 2).unwrap_or("unassigned"),
            lookup(ECN, tos & 3).unwrap_or("?")
        ))
    });
    b.num(ix, "Total length", off.saturating_add(2), 2);
    if total < ihl.max(20) {
        b.tail(|n| {
            n.diag(Diagnostic::malformed(
                "shorter than the header (TSO or bad length)",
            ))
        });
    } else if off.saturating_add(total) > end && b.complete {
        b.tail(|n| n.diag(Diagnostic::note("longer than the captured frame")));
    }
    let id = b
        .numx(ix, "Identification", off.saturating_add(4), 2)
        .unwrap_or(0);
    let ff = b
        .flg(
            ix,
            "Flags / fragment offset",
            off.saturating_add(6),
            2,
            IPV4_FLAGS,
        )
        .unwrap_or(0);
    let foff = (ff & 0x1fff).saturating_mul(8);
    let mf = ff & 0x2000 != 0;
    b.tail(|n| n.summary(format!("fragment offset {foff}")));
    let ttl = b
        .num(ix, "Time to live", off.saturating_add(8), 1)
        .unwrap_or(0);
    let proto = b.u8(off.saturating_add(9)).unwrap_or(0);
    b.enm(ix, "Protocol", off.saturating_add(9), 1, IP_PROTOCOLS);
    let stored = b.be16(off.saturating_add(10)).unwrap_or(0);
    b.numx(ix, "Header checksum", off.saturating_add(10), 2);
    if ihl >= 20
        && let Some(hdr) = b.bytes(off, ihl)
    {
        let computed = inet_sum(&[
            hdr.get(..10).unwrap_or_default(),
            hdr.get(12..).unwrap_or_default(),
        ]);
        if computed == stored {
            b.tail(|n| n.summary("correct"));
        } else {
            b.tail(|n| {
                n.diag(Diagnostic::warning(format!(
                    "should be {computed:#06x} (bad header, or computed by the NIC after capture)"
                )))
            });
        }
    }
    let src = b.ip4(ix, "Source", off.saturating_add(12));
    let dst = b.ip4(ix, "Destination", off.saturating_add(16));
    if ihl > 20 {
        ipv4_options(
            b,
            ix,
            off.saturating_add(20),
            off.saturating_add(ihl).min(end),
        );
    } else if ihl < 20 {
        b.diag(
            ix,
            Diagnostic::malformed(format!("header length {ihl} is below 20")),
        );
        return off.saturating_add(20);
    }
    let (s, d) = (
        src.map(|a| ipv4(&a)).unwrap_or_default(),
        dst.map(|a| ipv4(&a)).unwrap_or_default(),
    );
    let pname = lookup(IP_PROTOCOLS, proto.into()).unwrap_or("unknown protocol");
    b.summary(ix, || {
        let mut s = format!("{s} → {d}, {pname}, TTL {ttl}");
        if mf || foff > 0 {
            s.push_str(&format!(
                ", fragment at {foff}{}, ID {id:#06x}",
                if mf { " (more follow)" } else { " (last)" }
            ));
        }
        s
    });
    let (s2, d2) = (s.clone(), d.clone());
    b.set_addrs(|| s2, || d2);
    let body = off.saturating_add(ihl);
    b.set_info("IPv4", || format!("IPv4 {pname}"));
    if foff > 0 {
        b.set_info("IPv4", || {
            format!("IPv4 fragment of {pname} at offset {foff}, ID {id:#06x}")
        });
        return b.data(p, "Fragment data", body, ip_end);
    }
    let (Some(src), Some(dst)) = (src, dst) else {
        return body;
    };
    let ip = Ip {
        pseudo: Pseudo::V4(src, dst),
        fragment: mf,
    };
    let used = transport(b, p, proto, body, ip_end, ip);
    if mf {
        b.set_info("IPv4", || {
            format!("IPv4 first fragment of {pname}, ID {id:#06x}")
        });
    }
    if used <= body {
        b.data(p, "Payload", body, ip_end);
    } else if used < ip_end {
        b.data(p, "Payload", used, ip_end);
    }
    ip_end.max(body)
}

fn ipv4_options(b: &mut Dec, p: Ix, off: usize, end: usize) {
    let ix = b.group(p, "Options", off, end.saturating_sub(off));
    let mut at = off;
    let mut names = Vec::new();
    while at < end {
        let t = b.u8(at).unwrap_or(0);
        let name = lookup(IPV4_OPTIONS, t.into()).unwrap_or("Unknown option");
        if t == 0 || t == 1 {
            b.num(ix, name, at, 1);
            at = at.saturating_add(1);
            if t == 0 {
                b.data(ix, "Padding", at, end);
                break;
            }
            continue;
        }
        let len = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0));
        if len < 2 || at.saturating_add(len) > end {
            b.diag(
                ix,
                Diagnostic::malformed(format!("option {t} has bad length {len}")),
            );
            b.data(ix, "Rest", at, end);
            break;
        }
        names.push(name);
        let o = b.group(ix, name, at, len);
        b.enm(o, "Type", at, 1, IPV4_OPTIONS);
        b.num(o, "Length", at.saturating_add(1), 1);
        let body = at.saturating_add(2);
        let oend = at.saturating_add(len);
        match t {
            7 | 131 | 137 => {
                let ptr = b.num(o, "Pointer", body, 1).unwrap_or(0);
                let mut a = body.saturating_add(1);
                let mut route = Vec::new();
                let mut i = 0u64;
                while a.saturating_add(4) <= oend {
                    // The pointer (1-based, from the option start) marks the
                    // next free slot.
                    let used = i.saturating_mul(4).saturating_add(4) < ptr;
                    let addr = b.ip4(o, "Address", a);
                    if used && let Some(x) = addr {
                        route.push(ipv4(&x));
                    } else if !used {
                        b.tail(|n| n.summary("empty slot"));
                    }
                    a = a.saturating_add(4);
                    i = i.saturating_add(1);
                }
                b.summary(o, || {
                    if route.is_empty() {
                        "no hops recorded".to_owned()
                    } else {
                        route.join(" → ")
                    }
                });
            }
            68 => {
                b.num(o, "Pointer", body, 1);
                let fl = b.u8(body.saturating_add(1)).unwrap_or(0);
                b.numx(o, "Overflow / flags", body.saturating_add(1), 1);
                b.tail(|n| n.summary(format!("overflow {}, flag {}", fl >> 4, fl & 15)));
                let mut a = body.saturating_add(2);
                while a.saturating_add(4) <= oend {
                    if fl & 15 != 0 && a.saturating_add(8) <= oend {
                        b.ip4(o, "Address", a);
                        a = a.saturating_add(4);
                    }
                    b.num(o, "Timestamp (ms since midnight UT)", a, 4);
                    a = a.saturating_add(4);
                }
            }
            148 => {
                let v = b.num(o, "Value", body, 2).unwrap_or(0);
                b.summary(o, || {
                    if v == 0 {
                        "every router examines the packet".to_owned()
                    } else {
                        format!("value {v}")
                    }
                });
            }
            _ => {
                b.raw(o, "Data", body, oend.saturating_sub(body));
            }
        }
        at = oend;
    }
    b.summary(ix, || names.join(", "));
}

// ---------------------------------------------------------------------------
// IPv6

pub fn ipv6_packet(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 40 || b.u8(off).map(|v| v >> 4) != Some(6) || !b.enter() {
        return off;
    }
    let used = ipv6_inner(b, p, off, end);
    b.leave();
    used
}

fn ipv6_inner(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let plen = usize::from(b.be16(off.saturating_add(4)).unwrap_or(0));
    let ip_end = off.saturating_add(40).saturating_add(plen).min(end);
    let ix = b.group(p, "IPv6", off, 40);
    let v = b
        .numx(ix, "Version / traffic class / flow label", off, 4)
        .unwrap_or(0);
    let tc = (v >> 20) & 0xff;
    b.tail(|n| {
        n.summary(format!(
            "version {}, DSCP {} ({}), ECN {}, flow label {:#07x}",
            v >> 28,
            tc >> 2,
            lookup(DSCP, tc >> 2).unwrap_or("unassigned"),
            lookup(ECN, tc & 3).unwrap_or("?"),
            v & 0xfffff
        ))
    });
    b.num(ix, "Payload length", off.saturating_add(4), 2);
    if plen == 0 {
        b.tail(|n| n.summary("0 (jumbogram or TSO)"));
    }
    let mut nh = b.u8(off.saturating_add(6)).unwrap_or(59);
    b.enm(ix, "Next header", off.saturating_add(6), 1, IP_PROTOCOLS);
    let hops = b
        .num(ix, "Hop limit", off.saturating_add(7), 1)
        .unwrap_or(0);
    let src = b.ip6(ix, "Source", off.saturating_add(8));
    let dst = b.ip6(ix, "Destination", off.saturating_add(24));
    let (s, d) = (
        src.map(|a| ipv6(&a)).unwrap_or_default(),
        dst.map(|a| ipv6(&a)).unwrap_or_default(),
    );
    let (s2, d2) = (s.clone(), d.clone());
    b.set_addrs(|| s2, || d2);
    let ip_end = if plen == 0 { end } else { ip_end };
    let mut at = off.saturating_add(40);
    let mut fragment = false;
    let mut chain = Vec::new();
    // Extension headers.
    for _ in 0..16 {
        match nh {
            0 | 43 | 44 | 60 | 51 | 135 | 139 | 140 => {}
            _ => break,
        }
        let (next, len) = ipv6_ext(b, p, nh, at, ip_end);
        if len == 0 {
            break;
        }
        chain.push(lookup(IP_PROTOCOLS, nh.into()).unwrap_or("extension"));
        if nh == 44 {
            let fo = b.be16(at.saturating_add(2)).unwrap_or(0);
            fragment = true;
            if fo >> 3 != 0 {
                let off8 = usize::from(fo >> 3).saturating_mul(8);
                let pname = lookup(IP_PROTOCOLS, next.into()).unwrap_or("unknown protocol");
                b.summary(ix, || {
                    format!("{s} → {d}, fragment of {pname}, hop limit {hops}")
                });
                b.set_info("IPv6", || {
                    format!("IPv6 fragment of {pname} at offset {off8}")
                });
                let body = at.saturating_add(len);
                return b.data(p, "Fragment data", body, ip_end);
            }
        }
        nh = next;
        at = at.saturating_add(len);
    }
    let pname = lookup(IP_PROTOCOLS, nh.into()).unwrap_or("unknown protocol");
    b.summary(ix, || {
        let mut t = format!("{s} → {d}, {pname}, hop limit {hops}");
        if !chain.is_empty() {
            t.push_str(&format!(" (via {})", chain.join(", ")));
        }
        t
    });
    b.set_info("IPv6", || format!("IPv6 {pname}"));
    let (Some(src), Some(dst)) = (src, dst) else {
        return at;
    };
    let ip = Ip {
        pseudo: Pseudo::V6(src, dst),
        fragment,
    };
    let used = transport(b, p, nh, at, ip_end, ip);
    if fragment {
        b.set_info("IPv6", || format!("IPv6 first fragment of {pname}"));
    }
    if used <= at {
        b.data(p, "Payload", at, ip_end);
    } else if used < ip_end {
        b.data(p, "Payload", used, ip_end);
    }
    ip_end.max(at)
}

/// One extension header; returns its next header and length (0 if absent).
fn ipv6_ext(b: &mut Dec, p: Ix, kind: u8, at: usize, end: usize) -> (u8, usize) {
    if end.saturating_sub(at) < 8 {
        return (59, 0);
    }
    let next = b.u8(at).unwrap_or(59);
    let units = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0));
    let len = match kind {
        44 => 8,
        51 => units.saturating_add(2).saturating_mul(4),
        _ => units.saturating_add(1).saturating_mul(8),
    };
    let len = len.min(end.saturating_sub(at));
    let name = match kind {
        0 => "IPv6 hop-by-hop options",
        43 => "IPv6 routing header",
        44 => "IPv6 fragment header",
        60 => "IPv6 destination options",
        51 => "Authentication header",
        _ => "IPv6 extension header",
    };
    let ix = b.group(p, name, at, len);
    b.enm(ix, "Next header", at, 1, IP_PROTOCOLS);
    let hend = at.saturating_add(len);
    match kind {
        44 => {
            b.num(ix, "Reserved", at.saturating_add(1), 1);
            let fo = b
                .numx(ix, "Fragment offset / flags", at.saturating_add(2), 2)
                .unwrap_or(0);
            let (o, m) = ((fo >> 3).saturating_mul(8), fo & 1);
            b.tail(|n| n.summary(format!("offset {o}, more fragments {m}")));
            let id = b
                .numx(ix, "Identification", at.saturating_add(4), 4)
                .unwrap_or(0);
            b.summary(ix, || {
                format!(
                    "offset {o}{}, ID {id:#010x}",
                    if m == 1 { ", more follow" } else { "" }
                )
            });
        }
        51 => {
            b.num(ix, "Payload length", at.saturating_add(1), 1);
            b.num(ix, "Reserved", at.saturating_add(2), 2);
            let spi = b
                .numx(ix, "Security parameters index", at.saturating_add(4), 4)
                .unwrap_or(0);
            b.num(ix, "Sequence number", at.saturating_add(8), 4);
            b.raw(
                ix,
                "Integrity check value",
                at.saturating_add(12),
                hend.saturating_sub(at.saturating_add(12)),
            );
            b.summary(ix, || format!("SPI {spi:#010x}"));
        }
        43 => {
            b.num(ix, "Header extension length", at.saturating_add(1), 1);
            let rt = b
                .enm(ix, "Routing type", at.saturating_add(2), 1, ROUTING_TYPES)
                .unwrap_or(0);
            let left = b
                .num(ix, "Segments left", at.saturating_add(3), 1)
                .unwrap_or(0);
            let mut a = at.saturating_add(4);
            let mut addrs = Vec::new();
            match rt {
                0 | 2 => {
                    b.num(ix, "Reserved", a, 4);
                    a = a.saturating_add(4);
                }
                4 => {
                    b.num(ix, "Last entry", a, 1);
                    b.numx(ix, "Flags", a.saturating_add(1), 1);
                    b.numx(ix, "Tag", a.saturating_add(2), 2);
                    a = a.saturating_add(4);
                }
                _ => {}
            }
            if matches!(rt, 0 | 2 | 4) {
                while a.saturating_add(16) <= hend {
                    if let Some(x) = b.ip6(ix, "Address", a) {
                        addrs.push(ipv6(&x));
                    }
                    a = a.saturating_add(16);
                }
            }
            b.data(ix, "Type-specific data", a, hend);
            let rname = lookup(ROUTING_TYPES, rt).unwrap_or("unknown type");
            b.summary(ix, || {
                let mut s = format!("{rname}, {left} segments left");
                if !addrs.is_empty() {
                    s.push_str(&format!(", {}", addrs.join(", ")));
                }
                s
            });
        }
        0 | 60 => {
            b.num(ix, "Header extension length", at.saturating_add(1), 1);
            let names = ipv6_options(b, ix, at.saturating_add(2), hend);
            b.summary(ix, || {
                if names.is_empty() {
                    "padding only".to_owned()
                } else {
                    names.join(", ")
                }
            });
        }
        _ => {
            b.num(ix, "Header extension length", at.saturating_add(1), 1);
            b.data(ix, "Data", at.saturating_add(2), hend);
        }
    }
    (next, len)
}

fn ipv6_options(b: &mut Dec, p: Ix, off: usize, end: usize) -> Vec<&'static str> {
    let mut at = off;
    let mut names = Vec::new();
    while at < end {
        let t = b.u8(at).unwrap_or(0);
        let name = lookup(IPV6_OPTIONS, t.into()).unwrap_or("Unknown option");
        if t == 0 {
            b.num(p, "Pad1", at, 1);
            at = at.saturating_add(1);
            continue;
        }
        let len = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0));
        let oend = at.saturating_add(2).saturating_add(len);
        if oend > end {
            b.diag(
                p,
                Diagnostic::malformed(format!("option {t:#04x} overruns the header")),
            );
            b.data(p, "Rest", at, end);
            break;
        }
        let o = b.group(p, name, at, oend.saturating_sub(at));
        let action = match t >> 6 {
            0 => "skip if unknown",
            1 => "discard if unknown",
            2 => "discard and send ICMP if unknown",
            _ => "discard and send ICMP unless multicast if unknown",
        };
        b.enm(o, "Type", at, 1, IPV6_OPTIONS);
        b.tail(|n| {
            n.summary(format!(
                "{action}{}",
                if t & 0x20 != 0 {
                    ", may change en route"
                } else {
                    ""
                }
            ))
        });
        b.num(o, "Length", at.saturating_add(1), 1);
        let body = at.saturating_add(2);
        match (t, len) {
            (5, 2) => {
                let v = b.enm(o, "Value", body, 2, ROUTER_ALERTS).unwrap_or(0);
                b.summary(o, || {
                    lookup(ROUTER_ALERTS, v).unwrap_or("unassigned").to_owned()
                });
            }
            (0xc2, 4) => {
                let v = b.num(o, "Jumbo payload length", body, 4).unwrap_or(0);
                b.summary(o, || format!("{v} bytes"));
            }
            (0xc9, 16) => {
                b.ip6(o, "Home address", body);
            }
            (4, 1) => {
                b.num(o, "Limit", body, 1);
            }
            (1, _) => {
                b.data(o, "Padding", body, oend);
            }
            _ => {
                b.raw(o, "Data", body, len);
            }
        }
        if t != 1 {
            names.push(name);
        }
        at = oend;
    }
    names
}

// ---------------------------------------------------------------------------
// Transport

/// Dispatches on an IP protocol number.
fn transport(b: &mut Dec, p: Ix, proto: u8, off: usize, end: usize, ip: Ip) -> usize {
    match proto {
        6 => tcp(b, p, off, end, ip),
        17 | 136 => udp(b, p, off, end, ip),
        1 => icmp(b, p, off, end, ip),
        58 => icmpv6(b, p, off, end, ip),
        2 => igmp(b, p, off, end),
        4 => ipv4_packet(b, p, off, end),
        41 => ipv6_packet(b, p, off, end),
        47 => gre(b, p, off, end),
        50 => esp(b, p, off, end),
        132 => sctp(b, p, off, end),
        _ => off,
    }
}

/// Checks a transport checksum; returns the computed value when it differs.
/// Checks a transport checksum: (stored, computed, the pseudo-header-only
/// sum that checksum offload leaves in captured outgoing packets).
fn verify(
    b: &Dec,
    ip: &Ip,
    proto: u8,
    off: usize,
    end: usize,
    at: usize,
) -> Option<(u16, u16, Option<u16>)> {
    if !b.building() || ip.fragment || !b.complete || end > b.len() {
        return None;
    }
    let seg = b.range(off, end);
    let rel = at.saturating_sub(off);
    let stored = b.be16(at)?;
    let before = seg.get(..rel)?;
    let after = seg.get(rel.saturating_add(2)..)?;
    let pseudo = match proto {
        1 | 2 => Vec::new(),
        _ => ip.pseudo.header(proto, seg.len()),
    };
    let mut computed = inet_sum(&[&pseudo, before, &[0, 0], after]);
    if proto == 17 && computed == 0 {
        computed = 0xffff;
    }
    let partial = (!pseudo.is_empty()).then(|| !inet_sum(&[&pseudo]));
    Some((stored, computed, partial))
}

fn checksum_field(b: &mut Dec, ix: Ix, ip: &Ip, proto: u8, off: usize, end: usize, at: usize) {
    b.numx(ix, "Checksum", at, 2);
    let stored = b.be16(at).unwrap_or(0);
    if proto == 17 && stored == 0 && matches!(ip.pseudo, Pseudo::V4(..)) {
        b.tail(|n| n.summary("none"));
        return;
    }
    match verify(b, ip, proto, off, end, at) {
        Some((s, c, _)) if s == c => b.tail(|n| n.summary("correct")),
        Some((s, c, Some(p))) if s == p => b.tail(|n| {
            n.summary(format!(
                "pseudo-header sum only (checksum offload: the NIC computes {c:#06x})"
            ))
        }),
        Some((_, c, _)) => b.tail(|n| {
            n.diag(Diagnostic::warning(format!(
                "incorrect, should be {c:#06x}"
            )))
        }),
        None => {}
    }
}

fn tcp(b: &mut Dec, p: Ix, off: usize, end: usize, ip: Ip) -> usize {
    if end.saturating_sub(off) < 20 {
        return off;
    }
    let doff = usize::from(b.u8(off.saturating_add(12)).unwrap_or(0) >> 4).saturating_mul(4);
    let hlen = doff.max(20).min(end.saturating_sub(off));
    let ix = b.group(p, "TCP", off, hlen);
    let sp = port_field(b, ix, "Source port", off);
    let dp = port_field(b, ix, "Destination port", off.saturating_add(2));
    let seq = b
        .num(ix, "Sequence number", off.saturating_add(4), 4)
        .unwrap_or(0);
    let ack = b
        .num(ix, "Acknowledgment number", off.saturating_add(8), 4)
        .unwrap_or(0);
    let fl = b.u16(off.saturating_add(12)).unwrap_or(0);
    b.add(ix, "Data offset", off.saturating_add(12), 1, |n| {
        n.value(crate::formats::util::val::uint(u64::from(fl >> 12), 4))
            .summary(format!("header {doff} bytes"))
            .desc("The header length in 32-bit words (high nibble)")
    });
    b.add(ix, "Flags", off.saturating_add(12), 2, |n| {
        n.value(super::dec::flags(u64::from(fl & 0x0fff), 12, TCP_FLAGS))
    });
    let win = b.num(ix, "Window", off.saturating_add(14), 2).unwrap_or(0);
    checksum_field(b, ix, &ip, 6, off, end, off.saturating_add(16));
    b.num(ix, "Urgent pointer", off.saturating_add(18), 2);
    if doff < 20 {
        b.diag(
            ix,
            Diagnostic::malformed(format!("data offset {doff} is below 20")),
        );
    } else if doff > 20 {
        tcp_options(b, ix, off.saturating_add(20), off.saturating_add(hlen));
    }
    let body = off.saturating_add(hlen);
    let len = end.saturating_sub(body);
    let (set, _) = crate::value::decode_flags(TCP_FLAGS, u64::from(fl & 0x1ff));
    let flags = set.join(", ");
    b.summary(ix, || {
        format!(
            "{} → {} [{flags}], seq {seq}, ack {ack}, window {win}, {len} bytes",
            port(sp),
            port(dp)
        )
    });
    b.set_info("TCP", || {
        let mut s = format!("TCP {sp} → {dp} [{flags}] Seq={seq}");
        if fl & 0x10 != 0 {
            s.push_str(&format!(" Ack={ack}"));
        }
        s.push_str(&format!(" Win={win} Len={len}"));
        s
    });
    if body >= end {
        return body;
    }
    if ip.fragment {
        return b.data(p, "TCP payload (first fragment)", body, end);
    }
    let used = app::tcp(b, p, sp, dp, body, end);
    if used <= body {
        b.data(p, "TCP payload", body, end)
    } else {
        used
    }
}

fn port_field(b: &mut Dec, ix: Ix, name: &'static str, off: usize) -> u16 {
    let v = b.num(ix, name, off, 2).unwrap_or(0);
    let v = u16::try_from(v).unwrap_or(0);
    if let Some(s) = lookup(PORTS, v.into()) {
        b.tail(|n| n.summary(s));
    }
    v
}

fn tcp_options(b: &mut Dec, p: Ix, off: usize, end: usize) {
    let ix = b.group(p, "Options", off, end.saturating_sub(off));
    let mut at = off;
    let mut names = Vec::new();
    while at < end {
        let t = b.u8(at).unwrap_or(0);
        let name = lookup(TCP_OPTIONS, t.into()).unwrap_or("Unknown option");
        if t <= 1 {
            b.num(ix, name, at, 1);
            at = at.saturating_add(1);
            if t == 0 {
                b.data(ix, "Padding", at, end);
                break;
            }
            continue;
        }
        let len = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0));
        if len < 2 || at.saturating_add(len) > end {
            b.diag(
                ix,
                Diagnostic::malformed(format!("option {t} has bad length {len}")),
            );
            b.data(ix, "Rest", at, end);
            break;
        }
        let o = b.group(ix, name, at, len);
        b.enm(o, "Kind", at, 1, TCP_OPTIONS);
        b.num(o, "Length", at.saturating_add(1), 1);
        let body = at.saturating_add(2);
        let oend = at.saturating_add(len);
        let short = match (t, len) {
            (2, 4) => {
                let v = b.num(o, "MSS", body, 2).unwrap_or(0);
                format!("MSS={v}")
            }
            (3, 3) => {
                let v = b.num(o, "Shift count", body, 1).unwrap_or(0);
                let m = 1u64
                    .checked_shl(u32::try_from(v).unwrap_or(64))
                    .unwrap_or(0);
                b.tail(|n| n.summary(format!("multiply by {m}")));
                format!("WS={m}")
            }
            (4, 2) => "SACK_PERM".to_owned(),
            (5, _) => {
                let mut a = body;
                let mut blocks = Vec::new();
                while a.saturating_add(8) <= oend {
                    let l = b.num(o, "Left edge", a, 4).unwrap_or(0);
                    let r = b.num(o, "Right edge", a.saturating_add(4), 4).unwrap_or(0);
                    blocks.push(format!("{l}-{r}"));
                    a = a.saturating_add(8);
                }
                format!("SACK {}", blocks.join(" "))
            }
            (8, 10) => {
                let v = b.num(o, "Timestamp value", body, 4).unwrap_or(0);
                let e = b
                    .num(o, "Timestamp echo reply", body.saturating_add(4), 4)
                    .unwrap_or(0);
                format!("TSval={v} TSecr={e}")
            }
            (28, 4) => {
                let v = b.u16(body).unwrap_or(0);
                b.numx(o, "Granularity / timeout", body, 2);
                let unit = if v & 0x8000 != 0 { "min" } else { "s" };
                b.tail(|n| n.summary(format!("{} {unit}", v & 0x7fff)));
                format!("UTO={} {unit}", v & 0x7fff)
            }
            (30, _) => {
                let st = b.u8(body).map(|v| v >> 4).unwrap_or(0);
                b.numx(o, "Subtype / version", body, 1);
                let sname = lookup(MPTCP_SUBTYPES, st.into()).unwrap_or("unknown subtype");
                b.tail(|n| n.summary(sname));
                b.raw(
                    o,
                    "Data",
                    body.saturating_add(1),
                    oend.saturating_sub(body.saturating_add(1)),
                );
                format!("MPTCP {sname}")
            }
            (34, _) => {
                b.raw(o, "Cookie", body, oend.saturating_sub(body));
                "TFO".to_owned()
            }
            (253 | 254, _) if len >= 4 => {
                b.numx(o, "Experiment ID", body, 2);
                b.raw(
                    o,
                    "Data",
                    body.saturating_add(2),
                    oend.saturating_sub(body.saturating_add(2)),
                );
                "Experimental".to_owned()
            }
            _ => {
                b.raw(o, "Data", body, oend.saturating_sub(body));
                name.to_owned()
            }
        };
        let shown = short.clone();
        b.summary(o, || shown);
        names.push(short);
        at = oend;
    }
    b.summary(ix, || names.join(", "));
}

fn udp(b: &mut Dec, p: Ix, off: usize, end: usize, ip: Ip) -> usize {
    if end.saturating_sub(off) < 8 {
        return off;
    }
    let ix = b.group(p, "UDP", off, 8);
    let sp = port_field(b, ix, "Source port", off);
    let dp = port_field(b, ix, "Destination port", off.saturating_add(2));
    let len = usize::from(b.be16(off.saturating_add(4)).unwrap_or(0));
    b.num(ix, "Length", off.saturating_add(4), 2);
    let uend = if len >= 8 && !ip.fragment {
        off.saturating_add(len).min(end)
    } else {
        end
    };
    if len < 8 && !ip.fragment {
        b.tail(|n| n.diag(Diagnostic::malformed("below the 8-byte header")));
    }
    checksum_field(b, ix, &ip, 17, off, uend, off.saturating_add(6));
    let body = off.saturating_add(8);
    let plen = uend.saturating_sub(body);
    b.summary(ix, || format!("{} → {}, {plen} bytes", port(sp), port(dp)));
    b.set_info("UDP", || format!("UDP {sp} → {dp} Len={plen}"));
    if body >= uend {
        return body;
    }
    if ip.fragment {
        return b.data(p, "UDP payload (first fragment)", body, uend);
    }
    let used = app::udp(b, p, sp, dp, body, uend);
    if used <= body {
        b.data(p, "UDP payload", body, uend);
    } else if used < uend {
        b.data(p, "Unparsed", used, uend);
    }
    uend
}

fn icmp(b: &mut Dec, p: Ix, off: usize, end: usize, ip: Ip) -> usize {
    if end.saturating_sub(off) < 4 {
        return off;
    }
    let hlen = 8.min(end.saturating_sub(off));
    let ix = b.group(p, "ICMP", off, hlen);
    let t = b.enm(ix, "Type", off, 1, ICMP_TYPES).unwrap_or(0);
    let codes: EnumTable = match t {
        3 => ICMP_UNREACH,
        5 => ICMP_REDIRECT,
        11 => ICMP_TIME_EXCEEDED,
        12 => ICMP_PARAM,
        _ => &[],
    };
    let code = code_field(b, ix, off.saturating_add(1), codes);
    checksum_field(b, ix, &ip, 1, off, end, off.saturating_add(2));
    let tname = lookup(ICMP_TYPES, t).unwrap_or("unknown type");
    let cname = lookup(codes, code);
    let r = off.saturating_add(4);
    let mut detail = String::new();
    let used;
    match t {
        0 | 8 | 13 | 14 | 15 | 16 | 17 | 18 => {
            let id = b.numx(ix, "Identifier", r, 2).unwrap_or(0);
            let seq = b
                .num(ix, "Sequence number", r.saturating_add(2), 2)
                .unwrap_or(0);
            detail = format!("id={id:#06x}, seq={seq}");
            let body = r.saturating_add(4);
            match t {
                13 | 14 if end.saturating_sub(body) >= 12 => {
                    let g = b.group(ix, "Timestamps", body, 12);
                    for (i, name) in ["Originate", "Receive", "Transmit"].into_iter().enumerate() {
                        let at = body.saturating_add(i.saturating_mul(4));
                        b.num(g, name, at, 4);
                        b.tail(|n| n.summary("ms since midnight UT"));
                    }
                    used = body.saturating_add(12);
                }
                17 | 18 if end.saturating_sub(body) >= 4 => {
                    b.ip4(ix, "Address mask", body);
                    used = body.saturating_add(4);
                }
                _ => {
                    if body < end {
                        b.raw(ix, "Data", body, end.saturating_sub(body));
                    }
                    used = end.max(body);
                }
            }
        }
        3 | 4 | 5 | 11 | 12 => {
            match t {
                5 => {
                    if let Some(g) = b.ip4(ix, "Gateway address", r) {
                        detail = format!("gateway {}", ipv4(&g));
                    }
                }
                12 => {
                    b.num(ix, "Pointer", r, 1);
                    b.raw(ix, "Unused", r.saturating_add(1), 3);
                }
                3 if code == 4 => {
                    b.num(ix, "Unused", r, 2);
                    let mtu = b
                        .num(ix, "Next-hop MTU", r.saturating_add(2), 2)
                        .unwrap_or(0);
                    detail = format!("MTU {mtu}");
                }
                _ => {
                    b.numx(ix, "Unused", r, 4);
                }
            }
            used = quoted(b, ix, r.saturating_add(4), end, 228);
        }
        9 => {
            let n = b.num(ix, "Number of addresses", r, 1).unwrap_or(0);
            b.num(ix, "Address entry size", r.saturating_add(1), 1);
            b.num(ix, "Lifetime (s)", r.saturating_add(2), 2);
            let mut at = r.saturating_add(4);
            for _ in 0..n {
                if end.saturating_sub(at) < 8 {
                    break;
                }
                b.ip4(ix, "Router address", at);
                b.num(ix, "Preference level", at.saturating_add(4), 4);
                at = at.saturating_add(8);
            }
            used = at;
        }
        _ => {
            b.raw(ix, "Rest of header", r, 4.min(end.saturating_sub(r)));
            used = b.data(ix, "Data", r.saturating_add(4), end);
        }
    }
    // The ICMP node covers the whole message.
    let total = used.max(off.saturating_add(hlen)).saturating_sub(off);
    let span = b.sp(off, total);
    b.update(ix, |n| n.span(span));
    let text = match cname {
        Some(c) => format!("{tname} ({c})"),
        None => tname.to_owned(),
    };
    let shown = if detail.is_empty() {
        text.clone()
    } else {
        format!("{text}, {detail}")
    };
    let s2 = shown.clone();
    b.summary(ix, || s2);
    b.set_info("ICMP", || format!("ICMP {shown}"));
    off.saturating_add(total)
}

/// An ICMP code: named when the type defines codes.
fn code_field(b: &mut Dec, ix: Ix, at: usize, codes: EnumTable) -> u64 {
    if codes.is_empty() {
        b.num(ix, "Code", at, 1)
    } else {
        b.enm(ix, "Code", at, 1, codes)
    }
    .unwrap_or(0)
}

/// The datagram quoted by an ICMP error, decoded as raw IP.
fn quoted(b: &mut Dec, p: Ix, off: usize, end: usize, link: u32) -> usize {
    if off >= end {
        return off;
    }
    let g = b.group(p, "Original datagram", off, end.saturating_sub(off));
    b.quoted = b.quoted.saturating_add(1);
    let saved_complete = b.complete;
    // The quote is usually cut short: do not check its checksums.
    b.complete = false;
    let used = match link {
        229 => ipv6_packet(b, g, off, end),
        _ => ipv4_packet(b, g, off, end),
    };
    b.complete = saved_complete;
    b.quoted = b.quoted.saturating_sub(1);
    if used <= off {
        b.data(g, "Data", off, end);
    }
    end
}

fn icmpv6(b: &mut Dec, p: Ix, off: usize, end: usize, ip: Ip) -> usize {
    if end.saturating_sub(off) < 4 {
        return off;
    }
    let ix = b.group(p, "ICMPv6", off, end.saturating_sub(off));
    let t = b.enm(ix, "Type", off, 1, ICMPV6_TYPES).unwrap_or(0);
    let codes: EnumTable = match t {
        1 => ICMPV6_UNREACH,
        3 => ICMPV6_TIME_EXCEEDED,
        4 => ICMPV6_PARAM,
        _ => &[],
    };
    let code = code_field(b, ix, off.saturating_add(1), codes);
    checksum_field(b, ix, &ip, 58, off, end, off.saturating_add(2));
    let tname = lookup(ICMPV6_TYPES, t).unwrap_or("unknown type");
    let r = off.saturating_add(4);
    let mut detail = String::new();
    match t {
        1 | 3 => {
            b.numx(ix, "Unused", r, 4);
            quoted(b, ix, r.saturating_add(4), end, 229);
        }
        2 => {
            let mtu = b.num(ix, "MTU", r, 4).unwrap_or(0);
            detail = format!("MTU {mtu}");
            quoted(b, ix, r.saturating_add(4), end, 229);
        }
        4 => {
            b.num(ix, "Pointer", r, 4);
            quoted(b, ix, r.saturating_add(4), end, 229);
        }
        128 | 129 => {
            let id = b.numx(ix, "Identifier", r, 2).unwrap_or(0);
            let seq = b
                .num(ix, "Sequence number", r.saturating_add(2), 2)
                .unwrap_or(0);
            detail = format!("id={id:#06x}, seq={seq}");
            let d = r.saturating_add(4);
            if d < end {
                b.raw(ix, "Data", d, end.saturating_sub(d));
            }
        }
        130..=132 => {
            b.num(ix, "Maximum response delay (ms)", r, 2);
            b.num(ix, "Reserved", r.saturating_add(2), 2);
            if let Some(a) = b.ip6(ix, "Multicast address", r.saturating_add(4)) {
                detail = ipv6(&a);
            }
            let at = r.saturating_add(20);
            if t == 130 && end.saturating_sub(at) >= 4 {
                b.numx(ix, "Flags / robustness", at, 1);
                b.num(ix, "Querier's query interval code", at.saturating_add(1), 1);
                let n = b
                    .num(ix, "Number of sources", at.saturating_add(2), 2)
                    .unwrap_or(0);
                let mut a = at.saturating_add(4);
                for _ in 0..n {
                    if end.saturating_sub(a) < 16 {
                        break;
                    }
                    b.ip6(ix, "Source address", a);
                    a = a.saturating_add(16);
                }
                b.data(ix, "Rest", a, end);
            } else {
                b.data(ix, "Rest", at, end);
            }
        }
        143 => {
            b.num(ix, "Reserved", r, 2);
            let n = b
                .num(ix, "Number of records", r.saturating_add(2), 2)
                .unwrap_or(0);
            let (at, groups) = group_records(b, ix, r.saturating_add(4), end, n, true);
            detail = groups.join(", ");
            b.data(ix, "Rest", at, end);
        }
        133 => {
            b.num(ix, "Reserved", r, 4);
            ndp_options(b, ix, r.saturating_add(4), end);
        }
        134 => {
            b.num(ix, "Current hop limit", r, 1);
            b.flg(ix, "Flags", r.saturating_add(1), 1, RA_FLAGS);
            let life = b
                .num(ix, "Router lifetime (s)", r.saturating_add(2), 2)
                .unwrap_or(0);
            b.num(ix, "Reachable time (ms)", r.saturating_add(4), 4);
            b.num(ix, "Retransmission timer (ms)", r.saturating_add(8), 4);
            detail = format!("router lifetime {life} s");
            ndp_options(b, ix, r.saturating_add(12), end);
        }
        135 | 136 => {
            if t == 136 {
                b.flg(ix, "Flags", r, 4, NA_FLAGS);
            } else {
                b.num(ix, "Reserved", r, 4);
            }
            if let Some(a) = b.ip6(ix, "Target address", r.saturating_add(4)) {
                detail = ipv6(&a);
            }
            ndp_options(b, ix, r.saturating_add(20), end);
        }
        137 => {
            b.num(ix, "Reserved", r, 4);
            if let Some(a) = b.ip6(ix, "Target address", r.saturating_add(4)) {
                detail = format!("target {}", ipv6(&a));
            }
            b.ip6(ix, "Destination address", r.saturating_add(20));
            ndp_options(b, ix, r.saturating_add(36), end);
        }
        _ => {
            b.data(ix, "Message body", r, end);
        }
    }
    let text = match lookup(codes, code) {
        Some(c) => format!("{tname} ({c})"),
        None => tname.to_owned(),
    };
    let shown = if detail.is_empty() {
        text
    } else {
        format!("{text}, {detail}")
    };
    let s2 = shown.clone();
    b.summary(ix, || s2);
    b.set_info("ICMPv6", || format!("ICMPv6 {shown}"));
    end
}

/// IGMPv3 / MLDv2 group records; returns the end and the group addresses.
fn group_records(
    b: &mut Dec,
    p: Ix,
    off: usize,
    end: usize,
    n: u64,
    v6: bool,
) -> (usize, Vec<String>) {
    let alen = if v6 { 16 } else { 4 };
    let mut at = off;
    let mut groups = Vec::new();
    for _ in 0..n {
        let head = 4usize.saturating_add(alen);
        if end.saturating_sub(at) < head {
            break;
        }
        let aux = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0)).saturating_mul(4);
        let nsrc = usize::from(b.be16(at.saturating_add(2)).unwrap_or(0));
        let len = head
            .saturating_add(nsrc.saturating_mul(alen))
            .saturating_add(aux)
            .min(end.saturating_sub(at));
        let g = b.group(p, "Group record", at, len);
        let rt = b
            .enm(g, "Record type", at, 1, GROUP_RECORD_TYPES)
            .unwrap_or(0);
        b.num(g, "Aux data length", at.saturating_add(1), 1);
        b.num(g, "Number of sources", at.saturating_add(2), 2);
        let ga = at.saturating_add(4);
        let addr = if v6 {
            b.ip6(g, "Multicast address", ga).map(|a| ipv6(&a))
        } else {
            b.ip4(g, "Multicast address", ga).map(|a| ipv4(&a))
        }
        .unwrap_or_default();
        let mut a = at.saturating_add(head);
        for _ in 0..nsrc {
            if end.saturating_sub(a) < alen {
                break;
            }
            if v6 {
                b.ip6(g, "Source address", a);
            } else {
                b.ip4(g, "Source address", a);
            }
            a = a.saturating_add(alen);
        }
        b.data(g, "Aux data", a, at.saturating_add(len));
        let rname = lookup(GROUP_RECORD_TYPES, rt).unwrap_or("unknown");
        let shown = addr.clone();
        b.summary(g, || format!("{shown}, {rname}, {nsrc} sources"));
        groups.push(addr);
        at = at.saturating_add(len);
        if len == 0 {
            break;
        }
    }
    (at, groups)
}

fn ndp_options(b: &mut Dec, p: Ix, off: usize, end: usize) {
    let mut at = off;
    while end.saturating_sub(at) >= 2 {
        let t = b.u8(at).unwrap_or(0);
        let len = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0)).saturating_mul(8);
        if len == 0 || at.saturating_add(len) > end {
            b.diag(
                p,
                Diagnostic::malformed(format!("NDP option {t} has bad length {len}")),
            );
            b.data(p, "Rest", at, end);
            return;
        }
        let name = lookup(NDP_OPTIONS, t.into()).unwrap_or("Unknown option");
        let o = b.group(p, name, at, len);
        b.enm(o, "Type", at, 1, NDP_OPTIONS);
        b.num(o, "Length (8-byte units)", at.saturating_add(1), 1);
        let body = at.saturating_add(2);
        let oend = at.saturating_add(len);
        match t {
            1 | 2 if len == 8 => {
                if let Some(m) = b.mac(o, "Link-layer address", body) {
                    let s = mac(&m);
                    b.summary(o, || s);
                }
            }
            3 if len == 32 => {
                let pl = b.num(o, "Prefix length", body, 1).unwrap_or(0);
                b.flg(o, "Flags", body.saturating_add(1), 1, PREFIX_FLAGS);
                b.num(o, "Valid lifetime (s)", body.saturating_add(2), 4);
                b.num(o, "Preferred lifetime (s)", body.saturating_add(6), 4);
                b.num(o, "Reserved", body.saturating_add(10), 4);
                if let Some(a) = b.ip6(o, "Prefix", body.saturating_add(14)) {
                    let s = format!("{}/{pl}", ipv6(&a));
                    b.summary(o, || s);
                }
            }
            4 => {
                b.raw(o, "Reserved", body, 6);
                quoted(b, o, body.saturating_add(6), oend, 229);
            }
            5 if len == 8 => {
                b.num(o, "Reserved", body, 2);
                let mtu = b.num(o, "MTU", body.saturating_add(2), 4).unwrap_or(0);
                b.summary(o, || format!("{mtu}"));
            }
            25 => {
                b.num(o, "Reserved", body, 2);
                b.num(o, "Lifetime (s)", body.saturating_add(2), 4);
                let mut a = body.saturating_add(6);
                let mut list = Vec::new();
                while a.saturating_add(16) <= oend {
                    if let Some(x) = b.ip6(o, "DNS server", a) {
                        list.push(ipv6(&x));
                    }
                    a = a.saturating_add(16);
                }
                b.summary(o, || list.join(", "));
            }
            _ => {
                b.raw(o, "Data", body, oend.saturating_sub(body));
            }
        }
        at = oend;
    }
    b.data(p, "Rest", at, end);
}

fn igmp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 8 {
        return off;
    }
    let ix = b.group(p, "IGMP", off, end.saturating_sub(off));
    let t = b.enm(ix, "Type", off, 1, IGMP_TYPES).unwrap_or(0);
    b.num(ix, "Max response code", off.saturating_add(1), 1);
    let ip = Ip {
        pseudo: Pseudo::V4([0; 4], [0; 4]),
        fragment: false,
    };
    checksum_field(b, ix, &ip, 2, off, end, off.saturating_add(2));
    let tname = lookup(IGMP_TYPES, t).unwrap_or("unknown type");
    let detail = match t {
        0x22 => {
            b.num(ix, "Reserved", off.saturating_add(4), 2);
            let n = b
                .num(ix, "Number of records", off.saturating_add(6), 2)
                .unwrap_or(0);
            let (at, groups) = group_records(b, ix, off.saturating_add(8), end, n, false);
            b.data(ix, "Rest", at, end);
            groups.join(", ")
        }
        _ => {
            let g = b.ip4(ix, "Group address", off.saturating_add(4));
            if t == 0x11 && end.saturating_sub(off) >= 12 {
                b.numx(ix, "Flags / robustness", off.saturating_add(8), 1);
                b.num(
                    ix,
                    "Querier's query interval code",
                    off.saturating_add(9),
                    1,
                );
                let n = b
                    .num(ix, "Number of sources", off.saturating_add(10), 2)
                    .unwrap_or(0);
                let mut a = off.saturating_add(12);
                for _ in 0..n {
                    if end.saturating_sub(a) < 4 {
                        break;
                    }
                    b.ip4(ix, "Source address", a);
                    a = a.saturating_add(4);
                }
                b.data(ix, "Rest", a, end);
            } else {
                b.data(ix, "Rest", off.saturating_add(8), end);
            }
            g.map(|a| ipv4(&a)).unwrap_or_default()
        }
    };
    let shown = format!("{tname}, {detail}");
    let s2 = shown.clone();
    b.summary(ix, || s2);
    b.set_info("IGMP", || {
        if shown.starts_with("IGMP") {
            shown
        } else {
            format!("IGMP {shown}")
        }
    });
    end
}

fn gre(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 4 {
        return off;
    }
    let fl = b.be16(off).unwrap_or(0);
    let mut len = 4usize;
    for bit in [0x8000u16, 0x2000, 0x1000] {
        if fl & bit != 0 {
            len = len.saturating_add(4);
        }
    }
    let ix = b.group(p, "GRE", off, len.min(end.saturating_sub(off)));
    b.flg(ix, "Flags / version", off, 2, GRE_FLAGS);
    let t = b.be16(off.saturating_add(2)).unwrap_or(0);
    b.enm(ix, "Protocol type", off.saturating_add(2), 2, ETHERTYPES);
    let mut at = off.saturating_add(4);
    if fl & 0x8000 != 0 {
        b.numx(ix, "Checksum", at, 2);
        b.num(ix, "Reserved", at.saturating_add(2), 2);
        at = at.saturating_add(4);
    }
    if fl & 0x2000 != 0 {
        b.numx(ix, "Key", at, 4);
        at = at.saturating_add(4);
    }
    if fl & 0x1000 != 0 {
        b.num(ix, "Sequence number", at, 4);
        at = at.saturating_add(4);
    }
    b.summary(ix, || ethertype_name(t));
    b.set_info("GRE", || format!("GRE {}", ethertype_name(t)));
    if fl & 7 != 0 {
        return b.data(p, "GRE payload", at, end);
    }
    ether(b, p, t, at, end).max(at)
}

fn esp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 8 {
        return off;
    }
    let ix = b.group(p, "ESP", off, end.saturating_sub(off));
    let spi = b.numx(ix, "Security parameters index", off, 4).unwrap_or(0);
    let seq = b
        .num(ix, "Sequence number", off.saturating_add(4), 4)
        .unwrap_or(0);
    b.data(ix, "Encrypted payload", off.saturating_add(8), end);
    b.summary(ix, || format!("SPI {spi:#010x}, seq {seq}"));
    b.set_info("ESP", || format!("ESP SPI={spi:#010x} Seq={seq}"));
    end
}

fn sctp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 12 {
        return off;
    }
    let ix = b.group(p, "SCTP", off, end.saturating_sub(off));
    let sp = port_field(b, ix, "Source port", off);
    let dp = port_field(b, ix, "Destination port", off.saturating_add(2));
    b.numx(ix, "Verification tag", off.saturating_add(4), 4);
    b.numx(ix, "Checksum (CRC-32C)", off.saturating_add(8), 4);
    let mut at = off.saturating_add(12);
    let mut names = Vec::new();
    while end.saturating_sub(at) >= 4 {
        let t = b.u8(at).unwrap_or(0);
        let len = usize::from(b.be16(at.saturating_add(2)).unwrap_or(0));
        if len < 4 {
            b.data(ix, "Rest", at, end);
            break;
        }
        let padded = len.next_multiple_of(4);
        let name = lookup(SCTP_CHUNKS, t.into()).unwrap_or("Unknown chunk");
        names.push(name);
        let c = b.group(ix, name, at, padded.min(end.saturating_sub(at)));
        b.enm(c, "Type", at, 1, SCTP_CHUNKS);
        b.numx(c, "Flags", at.saturating_add(1), 1);
        b.num(c, "Length", at.saturating_add(2), 2);
        let cend = at.saturating_add(len).min(end);
        b.data(c, "Value", at.saturating_add(4), cend);
        at = at.saturating_add(padded);
    }
    b.summary(ix, || {
        format!("{} → {}, {}", port(sp), port(dp), names.join(", "))
    });
    b.set_info("SCTP", || format!("SCTP {}", names.join(", ")));
    end
}
