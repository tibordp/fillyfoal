//! nfdump flow files (`nfcapd.YYYYMMDDhhmm`), as nfcapd, nfpcapd and
//! nfdump write them: NetFlow v5/v9, IPFIX and sFlow records collected into
//! blocks. Everything is in the writer's byte order; the magic `0xA50C`
//! tells which (no big-endian file was at hand to check that path).
//!
//! - **Layout 2** (nfdump 1.7): a 40-byte header (nfdump version, creation
//!   time, compression, creator, where the appendix is, the block count),
//!   data blocks, then the appendix: blocks holding the ident string and
//!   the statistics record. Flows are V3 records: a 12-byte header
//!   (element count, engine type and ID, exporter, flags, NetFlow version)
//!   and extension elements, each a type and a length (generic flow with
//!   times, ports, protocol and counters; IPv4 or IPv6 addresses; next
//!   hops, AS numbers, MAC addresses, NSEL/NEL, ...). Exporter, exporter
//!   statistics and sampler records sit among them.
//! - **Layout 1** (nfdump 1.6): a 140-byte header (flags with the
//!   compression, block count, ident), the statistics record, then data
//!   blocks of extension maps and common records: fixed fields, the
//!   addresses and counters (32- or 64-bit as the flags say), then the
//!   optional extensions the record's map lists. A map is read from the
//!   block being listed; a record whose map is in an earlier block shows
//!   its required fields only.
//!
//! Each block (a 12-byte header: record count, size, type, flags) is
//! compressed on its own with the file's codec, unless its flags say
//! otherwise: LZO1X, bzip2, raw LZ4 blocks or Zstandard.
//!
//! IPv4 addresses are stored as host-order 32-bit words, IPv6 addresses
//! as two host-order 64-bit words, MAC addresses in the low 48 bits of a
//! host-order 64-bit word. Element 18 and elements 34 and 35 changed
//! meaning between nfdump 1.7.1 and 1.7.5 and are shown as bytes.
//!
//! The probe wants the magic in either byte order and a known layout,
//! then sane header fields: a known compression and no encryption, an
//! appendix inside the file and a known type for the first block (layout
//! 2), or known flags and a NUL-padded printable ident (layout 1).
//!
//! Layouts from nfdump's headers (`nffileV2.h`, `nfxV3.h`, `nffile.h`,
//! `nfx.h`, `exporter.h`, BSD licence) of 1.6.22, 1.7.1 and 1.7.5, read
//! for facts; checked against files Debian's nfdump 1.7.5 and 1.6.22
//! wrote and their `nfdump -o raw` listings.

use std::sync::Arc;

use super::dec::{ipv4, ipv6, mac};
use super::net::{IP_PROTOCOLS, TCP_FLAGS};
use super::time_text;
use crate::bytes::{to_u64, to_usize};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::get;
use crate::formats::util::fmt::plural;
use crate::formats::util::val;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

pub static FORMAT: Format = Format {
    name: "nfdump",
    title: "nfdump NetFlow capture",
    extensions: &["nfcapd"],
    mime: "application/x-nfdump",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const HEADER_V2: u64 = 40;
const HEADER_V1: u64 = 140;
const STAT_V1: u64 = 136;
const BLOCK_HEADER: u64 = 12;
/// Blocks listed from a file, records from a block, extension maps kept.
const MAX_BLOCKS: u32 = 1 << 24;
const MAX_RECORDS: u32 = 1 << 24;
const MAX_MAPS: usize = 4096;
/// Appendix blocks read for the summary.
const MAX_APPENDIX: u16 = 16;

const COMPRESSIONS: EnumTable = &[
    (0, "none"),
    (1, "LZO"),
    (2, "bzip2"),
    (3, "LZ4"),
    (4, "Zstandard"),
];

const CREATORS: EnumTable = &[
    (0, "unknown"),
    (1, "nfcapd"),
    (2, "nfpcapd"),
    (3, "sfcapd"),
    (4, "nfdump"),
    (5, "nfanon"),
    (6, "nfprofile"),
    (7, "geolookup"),
    (8, "ft2nfdump"),
    (9, "torlookup"),
];

const V1_FLAGS: FlagTable = &[
    flag(0x1, "LZO_COMPRESSED"),
    flag(0x2, "ANONYMIZED"),
    flag(0x8, "BZ2_COMPRESSED"),
    flag(0x10, "LZ4_COMPRESSED"),
];

const BLOCK_TYPES: EnumTable = &[
    (1, "data block 1 (nfdump 1.5)"),
    (2, "data block 2 (nfdump 1.6)"),
    (3, "data block 3"),
    (4, "data block 4 (arrays)"),
];

const BLOCK_FLAGS: FlagTable = &[
    flag(0x1, "UNCOMPRESSED"),
    flag(0x2, "UNENCRYPTED"),
    flag(0x4, "AUTOREAD"),
];

const V3_FLAGS: FlagTable = &[flag(0x1, "EVENT"), flag(0x2, "SAMPLED"), flag(0x4, "ANON")];

const COMMON_FLAGS: FlagTable = &[
    flag(0x1, "IPV6_ADDR"),
    flag(0x2, "PKG_64"),
    flag(0x4, "BYTES_64"),
    flag(0x8, "IPV6_NH"),
    flag(0x10, "IPV6_NHB"),
    flag(0x20, "IPV6_EXP"),
    flag(0x40, "EVENT"),
    flag(0x80, "SAMPLED"),
];

const RECORD_TYPES: EnumTable = &[
    (1, "common record v0"),
    (2, "extension map"),
    (3, "port histogram"),
    (4, "bpp histogram"),
    (5, "legacy record 1"),
    (6, "legacy record 2"),
    (7, "exporter info"),
    (8, "exporter statistics"),
    (9, "sampler (legacy)"),
    (10, "common record"),
    (11, "flow record (V3)"),
    (12, "NBAR record"),
    (13, "interface names"),
    (14, "VRF names"),
    (15, "sampler"),
    (0x8001, "ident"),
    (0x8002, "statistics"),
];

const FAMILIES: EnumTable = &[
    (2, "IPv4"),
    (10, "IPv6"),
    (28, "IPv6 (BSD)"),
    (30, "IPv6 (macOS)"),
];

/// V3 extension elements: ID and name (nfdump 1.7.5's names).
const ELEMENTS: EnumTable = &[
    (1, "generic flow"),
    (2, "IPv4 flow"),
    (3, "IPv6 flow"),
    (4, "flow misc"),
    (5, "out counters"),
    (6, "VLAN"),
    (7, "AS routing"),
    (8, "BGP next hop IPv4"),
    (9, "BGP next hop IPv6"),
    (10, "IP next hop IPv4"),
    (11, "IP next hop IPv6"),
    (12, "IP received IPv4"),
    (13, "IP received IPv6"),
    (14, "MPLS labels"),
    (15, "MAC addresses"),
    (16, "AS adjacent"),
    (17, "latency"),
    (18, "sampler info"),
    (19, "NSEL common"),
    (20, "NAT translated IPv4"),
    (21, "NAT translated IPv6"),
    (22, "NAT translated ports"),
    (23, "NSEL ACL"),
    (24, "NSEL user"),
    (25, "NAT common"),
    (26, "NAT port block"),
    (27, "NBAR application"),
    (28, "label"),
    (29, "in payload"),
    (30, "out payload"),
    (31, "tunnel IPv4"),
    (32, "tunnel IPv6"),
    (33, "observation"),
    (34, "inmon meta / interface name"),
    (35, "inmon frame / VRF name"),
    (36, "VRF"),
    (37, "pf info"),
    (38, "layer 2"),
    (39, "flow ID"),
    (40, "Nokia NAT"),
    (41, "Nokia NAT string"),
    (42, "IP info"),
];

/// Layout 1 optional extensions: ID, size and name (nfdump 1.6.22's
/// `extension_descriptor`).
const V1_EXTENSIONS: &[(u16, u64, &str)] = &[
    (4, 4, "2-byte input/output interface"),
    (5, 8, "4-byte input/output interface"),
    (6, 4, "2-byte src/dst AS"),
    (7, 8, "4-byte src/dst AS"),
    (8, 4, "dst ToS, direction, masks"),
    (9, 4, "IPv4 next hop"),
    (10, 16, "IPv6 next hop"),
    (11, 4, "IPv4 BGP next hop"),
    (12, 16, "IPv6 BGP next hop"),
    (13, 4, "src/dst VLAN"),
    (14, 4, "4-byte output packets"),
    (15, 8, "8-byte output packets"),
    (16, 4, "4-byte output bytes"),
    (17, 8, "8-byte output bytes"),
    (18, 4, "4-byte aggregated flows"),
    (19, 8, "8-byte aggregated flows"),
    (20, 16, "in src/out dst MAC"),
    (21, 16, "in dst/out src MAC"),
    (22, 40, "MPLS labels"),
    (23, 4, "IPv4 router IP"),
    (24, 16, "IPv6 router IP"),
    (25, 4, "router ID"),
    (26, 8, "BGP adjacent AS"),
    (27, 8, "time received"),
    (37, 20, "NSEL common"),
    (38, 4, "NSEL translated ports"),
    (39, 8, "NSEL translated IPv4"),
    (40, 32, "NSEL translated IPv6"),
    (41, 24, "NSEL ACL"),
    (42, 24, "NSEL user"),
    (43, 72, "NSEL user (max)"),
    (45, 24, "latency"),
    (46, 12, "NEL common"),
    (48, 8, "NAT port block"),
];

// ---------------------------------------------------------------------------
// Probe

fn endian(d: &[u8]) -> Option<Endian> {
    match d.get(..2)? {
        [0x0c, 0xa5] => Some(Endian::Little),
        [0xa5, 0x0c] => Some(Endian::Big),
        _ => None,
    }
}

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let Some(e) = endian(d) else {
        return false;
    };
    match get::<u16>(d, 2, e) {
        Some(2) => probe_v2(h, e),
        Some(1) => probe_v1(d, e),
        _ => false,
    }
}

fn probe_v2(h: &Head<'_>, e: Endian) -> bool {
    let d = h.data;
    let (Some(&compression), Some(&encryption), Some(appendix), Some(off), Some(blocks)) = (
        d.get(16),
        d.get(17),
        get::<u16>(d, 18, e),
        get::<u64>(d, 24, e),
        get::<u32>(d, 36, e),
    ) else {
        return false;
    };
    if compression > 4 || encryption != 0 || appendix > MAX_APPENDIX {
        return false;
    }
    if off != 0 && (off < HEADER_V2 || (h.len_known && off > h.len)) {
        return false;
    }
    // The first block, when there is one, has a known type.
    if blocks > 0 || appendix > 0 {
        let first = if blocks > 0 { HEADER_V2 } else { off };
        let at = to_usize(first.saturating_add(8));
        if let Some(kind) = get::<u16>(d, at, e) {
            return (2..=4).contains(&kind);
        }
    }
    true
}

fn probe_v1(d: &[u8], e: Endian) -> bool {
    let (Some(flags), Some(ident)) = (get::<u32>(d, 4, e), d.get(12..140)) else {
        return false;
    };
    if flags & !0x1b != 0 {
        return false;
    }
    let Some(end) = ident.iter().position(|&b| b == 0) else {
        return false;
    };
    let (text, pad) = ident.split_at(end);
    text.iter().all(|&b| (0x20..0x7f).contains(&b)) && pad.iter().all(|&b| b == 0)
}

// ---------------------------------------------------------------------------
// Values

/// An IPv4 address stored as a host-order word.
fn ip4_text(v: u32) -> String {
    ipv4(&v.to_be_bytes())
}

/// An IPv6 address stored as two host-order 64-bit words.
fn ip6_text(b: &[u8], e: Endian) -> String {
    let hi = get::<u64>(b, 0, e).unwrap_or(0);
    let lo = get::<u64>(b, 8, e).unwrap_or(0);
    let mut bytes = hi.to_be_bytes().to_vec();
    bytes.extend_from_slice(&lo.to_be_bytes());
    ipv6(&bytes)
}

/// A MAC address in the low 48 bits of a host-order word.
fn mac_text(v: u64) -> String {
    mac(v.to_be_bytes().get(2..).unwrap_or_default())
}

/// Milliseconds since the epoch, as text.
fn ms_text(ms: u64) -> String {
    let secs = i64::try_from(ms / 1000).unwrap_or(i64::MAX);
    time_text(secs, ms % 1000, 3)
}

fn nfd_version(v: u32) -> String {
    let git = if v >> 28 == 0xf { " (git)" } else { "" };
    format!(
        "{}.{}.{}{git}",
        (v >> 24) & 0x0f,
        (v >> 16) & 0xff,
        (v >> 8) & 0xff
    )
}

fn proto_name(p: u8) -> String {
    lookup(IP_PROTOCOLS, p.into()).map_or_else(|| format!("protocol {p}"), str::to_owned)
}

/// "TCP 192.0.2.1:80 → 192.0.2.2:1024" (ICMP: type and code instead of ports).
fn flow_text(proto: u8, src: &str, dst: &str, sport: u16, dport: u16) -> String {
    let name = proto_name(proto);
    match proto {
        6 | 17 | 132 => {
            let with_port = |a: &str, p: u16| {
                if a.contains(':') {
                    format!("[{a}]:{p}")
                } else {
                    format!("{a}:{p}")
                }
            };
            format!(
                "{name} {} → {}",
                with_port(src, sport),
                with_port(dst, dport)
            )
        }
        1 | 58 => format!(
            "{name} {src} → {dst}, type {} code {}",
            dport >> 8,
            dport & 0xff
        ),
        _ => format!("{name} {src} → {dst}"),
    }
}

// ---------------------------------------------------------------------------
// Structures

record! {
    /// The layout 2 file header.
    struct HeaderV2 {
        magic: u16 "Magic" .hex(),
        version: u16 "Layout version",
        nfdversion: u32 "nfdump version" .hex() .with(|&v, n| n.summary(nfd_version(v))),
        created: u64 "Created" .timestamp(),
        compression: u8 "Compression" .enumeration(COMPRESSIONS),
        encryption: u8 "Encryption",
        appendix_blocks: u16 "Appendix blocks",
        creator: u32 "Creator" .enumeration(CREATORS),
        off_appendix: u64 "Appendix offset" .hex(),
        block_size: u32 "Block size" .desc("Largest data block (0: not recorded)"),
        num_blocks: u32 "Data blocks",
    }
}

record! {
    /// The layout 1 file header.
    struct HeaderV1 {
        magic: u16 "Magic" .hex(),
        version: u16 "Layout version",
        flags: u32 "Flags" .flags(V1_FLAGS),
        num_blocks: u32 "Data blocks",
        ident: ascii[128] "Ident",
    }
}

record! {
    /// A data block header.
    struct BlockHeader {
        num_records: u32 "Records",
        size: u32 "Size" .desc("Bytes after this header (compressed, if the block is)"),
        kind: u16 "Type" .enumeration(BLOCK_TYPES),
        flags: u16 "Flags" .flags(BLOCK_FLAGS),
    }
}

record! {
    /// The layout 2 statistics record (after its record header).
    struct StatV2 {
        flows: u64 "Flows",
        bytes: u64 "Bytes",
        packets: u64 "Packets",
        flows_tcp: u64 "TCP flows",
        flows_udp: u64 "UDP flows",
        flows_icmp: u64 "ICMP flows",
        flows_other: u64 "Other flows",
        bytes_tcp: u64 "TCP bytes",
        bytes_udp: u64 "UDP bytes",
        bytes_icmp: u64 "ICMP bytes",
        bytes_other: u64 "Other bytes",
        packets_tcp: u64 "TCP packets",
        packets_udp: u64 "UDP packets",
        packets_icmp: u64 "ICMP packets",
        packets_other: u64 "Other packets",
        first: u64 "First seen" .unix_millis(),
        last: u64 "Last seen" .unix_millis(),
        sequence_failures: u64 "Sequence failures",
    }
}

record! {
    /// The layout 1 statistics record.
    struct StatV1 {
        flows: u64 "Flows",
        bytes: u64 "Bytes",
        packets: u64 "Packets",
        flows_tcp: u64 "TCP flows",
        flows_udp: u64 "UDP flows",
        flows_icmp: u64 "ICMP flows",
        flows_other: u64 "Other flows",
        bytes_tcp: u64 "TCP bytes",
        bytes_udp: u64 "UDP bytes",
        bytes_icmp: u64 "ICMP bytes",
        bytes_other: u64 "Other bytes",
        packets_tcp: u64 "TCP packets",
        packets_udp: u64 "UDP packets",
        packets_icmp: u64 "ICMP packets",
        packets_other: u64 "Other packets",
        first: u32 "First seen" .timestamp(),
        last: u32 "Last seen" .timestamp(),
        msec_first: u16 "First seen (ms)",
        msec_last: u16 "Last seen (ms)",
        sequence_failures: u32 "Sequence failures",
    }
}

record! {
    /// A V3 flow record's header.
    struct V3Header {
        kind: u16 "Type" .enumeration(RECORD_TYPES),
        size: u16 "Size",
        num_elements: u16 "Elements",
        engine_type: u8 "Engine type",
        engine_id: u8 "Engine ID",
        exporter: u16 "Exporter" .desc("System ID of the exporter record"),
        flags: u8 "Flags" .flags(V3_FLAGS),
        nfversion: u8 "NetFlow version" .hex() .desc("NetFlow/IPFIX version; 0x40 and up: from nfpcapd"),
    }
}

record! {
    /// A layout 1 common record's fixed fields.
    struct CommonRecord {
        kind: u16 "Type" .enumeration(RECORD_TYPES),
        size: u16 "Size",
        flags: u8 "Flags" .flags(COMMON_FLAGS),
        nfversion: u8 "NetFlow version",
        ext_map: u16 "Extension map",
        msec_first: u16 "First (ms)",
        msec_last: u16 "Last (ms)",
        first: u32 "First" .timestamp(),
        last: u32 "Last" .timestamp(),
        fwd_status: u8 "Forwarding status",
        tcp_flags: u8 "TCP flags" .flags(TCP_FLAGS),
        proto: u8 "Protocol" .enumeration(IP_PROTOCOLS),
        tos: u8 "Source ToS",
        src_port: u16 "Source port",
        dst_port: u16 "Destination port" .desc("ICMP: type × 256 + code"),
        exporter: u16 "Exporter",
        reserved: u16 "Reserved",
    }
}

record! {
    /// A sampler record (layout 2).
    struct Sampler {
        kind: u16 "Type" .enumeration(RECORD_TYPES),
        size: u16 "Size",
        exporter: u16 "Exporter",
        algorithm: u16 "Algorithm",
        id: i64 "Selector ID",
        packet_interval: u32 "Packet interval",
        space_interval: u32 "Packet space",
    }
}

record! {
    /// A legacy sampler record.
    struct SamplerV0 {
        kind: u16 "Type" .enumeration(RECORD_TYPES),
        size: u16 "Size",
        id: i32 "Sampler ID",
        interval: u32 "Interval",
        mode: u16 "Mode",
        exporter: u16 "Exporter",
    }
}

record! {
    /// One exporter's counters in an exporter statistics record.
    struct ExporterStat {
        sysid: u32 "Exporter",
        sequence_failures: u32 "Sequence failures",
        packets: u64 "Packets",
        flows: u64 "Flows",
    }
}

// ---------------------------------------------------------------------------
// The file

#[derive(Clone, Copy)]
struct File {
    endian: Endian,
    layout: u16,
    /// 0 none, 1 LZO, 2 bzip2, 3 LZ4, 4 Zstandard.
    codec: u8,
}

/// Totals from a statistics record, for the summary.
struct Totals {
    flows: u64,
    packets: u64,
    bytes: u64,
    first_ms: u64,
    last_ms: u64,
}

impl Totals {
    fn text(&self) -> String {
        let mut s = format!(
            "{}, {}, {}",
            plural(self.flows, "flow"),
            plural(self.packets, "packet"),
            plural(self.bytes, "byte")
        );
        if self.first_ms > 0 {
            s.push_str(&format!(
                ", {} – {}",
                ms_text(self.first_ms),
                ms_text(self.last_ms)
            ));
        }
        s
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let span = input.span;
    let head = cx.read_avail(span.sub(0, 4)).await?;
    let endian =
        endian(&head).ok_or_else(|| Diagnostic::malformed("not an nfdump file").at(span))?;
    match get::<u16>(&head, 2, endian) {
        Some(2) => v2(cx, input, endian).await,
        Some(1) => v1(cx, input, endian).await,
        other => Err(
            Diagnostic::unsupported(format!("nfdump layout {}", other.unwrap_or(0)))
                .at(span.sub(2, 2)),
        ),
    }
}

async fn v2(cx: Cx, input: Input, endian: Endian) -> Result<()> {
    let span = input.span;
    let header_span = span.sub(0, HEADER_V2);
    let h: HeaderV2 = read_record(&cx, header_span, endian).await?;
    cx.emit(
        HeaderV2::node("Header", header_span, endian).summary(format!(
            "nfdump {}, {}",
            nfd_version(h.nfdversion),
            val::name_or(CREATORS, h.creator.into(), "creator")
        )),
    );
    let file = File {
        endian,
        layout: 2,
        codec: h.compression,
    };
    let codec = val::name_or(COMPRESSIONS, h.compression.into(), "compression");
    let mut title = format!("nfdump flows (layout 2, {codec})");
    let data_end = if h.off_appendix >= HEADER_V2 && h.off_appendix <= span.len {
        h.off_appendix
    } else {
        span.len
    };
    if h.encryption != 0 {
        cx.diag(Diagnostic::unsupported(format!(
            "encryption {}",
            h.encryption
        )));
    }
    if h.off_appendix >= HEADER_V2 && h.appendix_blocks > 0 {
        let appendix = span.sub(h.off_appendix, span.len.saturating_sub(h.off_appendix));
        let (ident, totals) = appendix_info(&cx, file, appendix, h.appendix_blocks).await;
        if let Some(ident) = &ident {
            title.push_str(&format!(", ident {ident}"));
        }
        if let Some(t) = &totals {
            title.push_str(&format!(": {}", t.text()));
        }
        cx.emit(
            Node::new("Appendix")
                .span(appendix)
                .summary(plural(h.appendix_blocks, "block"))
                .lazy(blocks, (file, appendix, u32::from(h.appendix_blocks))),
        );
    }
    cx.annotate(title);
    let data = span.sub(HEADER_V2, data_end.saturating_sub(HEADER_V2));
    cx.emit(
        Node::new("Data blocks")
            .span(data)
            .summary(plural(h.num_blocks, "block"))
            .lazy(blocks, (file, data, h.num_blocks.min(MAX_BLOCKS))),
    );
    Ok(())
}

async fn v1(cx: Cx, input: Input, endian: Endian) -> Result<()> {
    let span = input.span;
    let header_span = span.sub(0, HEADER_V1);
    let h: HeaderV1 = read_record(&cx, header_span, endian).await?;
    cx.emit(HeaderV1::node("Header", header_span, endian));
    let codec = if h.flags & 0x1 != 0 {
        1
    } else if h.flags & 0x8 != 0 {
        2
    } else if h.flags & 0x10 != 0 {
        3
    } else {
        0
    };
    let file = File {
        endian,
        layout: 1,
        codec,
    };
    let mut title = format!(
        "nfdump flows (layout 1, {})",
        val::name_or(COMPRESSIONS, codec.into(), "compression")
    );
    if !h.ident.is_empty() {
        title.push_str(&format!(", ident {}", h.ident));
    }
    let stat_span = span.sub(HEADER_V1, STAT_V1);
    if stat_span.len == STAT_V1 {
        let s: StatV1 = read_record(&cx, stat_span, endian).await?;
        let totals = Totals {
            flows: s.flows,
            packets: s.packets,
            bytes: s.bytes,
            first_ms: u64::from(s.first)
                .saturating_mul(1000)
                .saturating_add(s.msec_first.into()),
            last_ms: u64::from(s.last)
                .saturating_mul(1000)
                .saturating_add(s.msec_last.into()),
        };
        title.push_str(&format!(": {}", totals.text()));
        cx.emit(StatV1::node("Statistics", stat_span, endian).summary(totals.text()));
    }
    cx.annotate(title);
    let start = HEADER_V1.saturating_add(STAT_V1);
    let data = span.tail(start);
    cx.emit(
        Node::new("Data blocks")
            .span(data)
            .summary(plural(h.num_blocks, "block"))
            .lazy(blocks, (file, data, h.num_blocks.min(MAX_BLOCKS))),
    );
    Ok(())
}

/// The ident and totals from the appendix, for the summary.
async fn appendix_info(
    cx: &Cx,
    file: File,
    appendix: Span,
    count: u16,
) -> (Option<String>, Option<Totals>) {
    let mut ident = None;
    let mut totals = None;
    let mut pos = 0u64;
    for _ in 0..count.min(MAX_APPENDIX) {
        let Ok(head) = cx.read(appendix.sub(pos, BLOCK_HEADER)).await else {
            break;
        };
        let e = file.endian;
        let (Some(n), Some(size), Some(flags)) = (
            get::<u32>(&head, 0, e),
            get::<u32>(&head, 4, e),
            get::<u16>(&head, 10, e),
        ) else {
            break;
        };
        let body = appendix.sub(pos.saturating_add(BLOCK_HEADER), size.into());
        pos = pos.saturating_add(BLOCK_HEADER).saturating_add(size.into());
        let Ok(region) = payload(cx, file, body, flags).await else {
            continue;
        };
        let mut at = 0u64;
        for _ in 0..n.min(64) {
            let Ok(rh) = cx.read(region.sub(at, 4)).await else {
                break;
            };
            let (Some(kind), Some(len)) = (get::<u16>(&rh, 0, e), get::<u16>(&rh, 2, e)) else {
                break;
            };
            if len < 4 {
                break;
            }
            let rec = region.sub(at, len.into());
            match kind {
                0x8001 => {
                    if let Ok(b) = cx.read(rec.sub(4, 256)).await {
                        let end = b.iter().position(|&c| c == 0).unwrap_or(b.len());
                        ident = Some(
                            String::from_utf8_lossy(b.get(..end).unwrap_or_default()).into_owned(),
                        );
                    }
                }
                0x8002 => {
                    if let Ok(s) = read_record::<StatV2>(cx, rec.sub(4, StatV2::SIZE), e).await {
                        totals = Some(Totals {
                            flows: s.flows,
                            packets: s.packets,
                            bytes: s.bytes,
                            first_ms: s.first,
                            last_ms: s.last,
                        });
                    }
                }
                _ => {}
            }
            at = at.saturating_add(len.into());
        }
    }
    (ident, totals)
}

/// The records of a block: the block's own bytes, or decoded from them
/// with the file's codec.
async fn payload(cx: &Cx, file: File, body: Span, flags: u16) -> Result<Span> {
    let uncompressed = match file.layout {
        1 => flags == 1,
        _ => flags & 1 != 0,
    };
    let codec = match file.codec {
        _ if uncompressed => return Ok(body),
        0 => return Ok(body),
        1 => Codec::Lzo1x,
        2 => Codec::Bzip2,
        3 => Codec::Lz4Block,
        4 => Codec::Zstd,
        other => {
            return Err(Diagnostic::unsupported(format!("compression {other}")).at(body));
        }
    };
    if body.len > crate::formats::UNSIZED_LAZY_THRESHOLD {
        return cx.decode_lazy_unsized(body, &codec);
    }
    let decoded = crate::codec::decode_span(cx, body, &codec, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    Ok(decoded.span)
}

/// Lists the blocks in `region`.
async fn blocks(cx: Cx, (file, region, count): (File, Span, u32)) -> Result<()> {
    let e = file.endian;
    let (mut pos, mut index) = cx.resume::<(u64, u32)>().unwrap_or((0, 0));
    while pos < region.len && index < MAX_BLOCKS {
        // Past the blocks the header counts (a file whose writer stopped
        // before updating the count): further blocks are shown while they
        // look like blocks, though nfdump reads only the counted ones.
        let uncounted = index >= count;
        let at = (pos, index);
        cx.mark(move || at);
        let head = cx.read_avail(region.sub(pos, BLOCK_HEADER)).await?;
        let fields = (
            get::<u32>(&head, 0, e),
            get::<u32>(&head, 4, e),
            get::<u16>(&head, 8, e),
            get::<u16>(&head, 10, e),
        );
        if uncounted {
            let plausible = match fields {
                (Some(n), Some(size), Some(kind), Some(_)) => {
                    n > 0
                        && (1..=4).contains(&kind)
                        && BLOCK_HEADER.saturating_add(size.into())
                            <= region.len.saturating_sub(pos)
                }
                _ => false,
            };
            if !plausible {
                break;
            }
        }
        let (Some(n), Some(size), Some(kind), Some(flags)) = fields else {
            cx.push(
                Node::new("Trailing data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::truncated(
                        region.sub(pos, BLOCK_HEADER),
                        to_u64(head.len()),
                    )),
            )
            .await;
            return Ok(());
        };
        let total = BLOCK_HEADER.saturating_add(size.into());
        let span = region.sub(pos, total);
        let compressed = file.codec != 0
            && match file.layout {
                1 => flags != 1,
                _ => flags & 1 == 0,
            };
        let mut summary = format!("{}, {} bytes", plural(n, "record"), size);
        if compressed {
            summary.push_str(&format!(
                ", {}",
                val::name_or(COMPRESSIONS, file.codec.into(), "compression")
            ));
        }
        let mut node = Node::new(format!("Block {index}"))
            .span(span)
            .summary(summary)
            .lazy(block, (file, span));
        if !(1..=4).contains(&kind) {
            node = node.diag(Diagnostic::warning(format!("unknown block type {kind}")));
        }
        if uncounted {
            node = node.diag(Diagnostic::warning(format!(
                "not counted in the header, which counts {}: nfdump does not read it",
                plural(count, "block")
            )));
        }
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(total);
        index = index.saturating_add(1);
    }
    if pos < region.len {
        cx.push(
            Node::new("Trailing data")
                .span(region.tail(pos))
                .diag(Diagnostic::note("bytes after the last block")),
        )
        .await;
    }
    Ok(())
}

async fn block(cx: Cx, (file, span): (File, Span)) -> Result<()> {
    let header = span.sub(0, BLOCK_HEADER);
    let h: BlockHeader = read_record(&cx, header, file.endian).await?;
    cx.emit(BlockHeader::node("Block header", header, file.endian));
    let body = span.tail(BLOCK_HEADER);
    let region = payload(&cx, file, body, h.flags).await?;
    let mut node = Node::new("Records")
        .span(region)
        .summary(plural(h.num_records, "record"));
    if h.num_records > 0 {
        node = node.lazy(records, (file, region, h.num_records.min(MAX_RECORDS)));
    }
    cx.emit(node);
    Ok(())
}

// ---------------------------------------------------------------------------
// Records

/// Extension maps seen so far in a block: ID and extension list.
type Maps = std::collections::BTreeMap<u16, Arc<Vec<u16>>>;

async fn records(cx: Cx, (file, region, count): (File, Span, u32)) -> Result<()> {
    let e = file.endian;
    let (mut pos, mut index, mut maps) = cx.resume::<(u64, u32, Maps)>().unwrap_or_default();
    while index < count {
        cx.mark(|| (pos, index, maps.clone()));
        let rh = cx.read_avail(region.sub(pos, 4)).await?;
        let (Some(kind), Some(size)) = (get::<u16>(&rh, 0, e), get::<u16>(&rh, 2, e)) else {
            if !rh.is_empty() || pos < region.len {
                cx.push(
                    Node::new("Trailing data")
                        .span(region.sub(pos, to_u64(rh.len())))
                        .diag(Diagnostic::truncated(region.sub(pos, 4), to_u64(rh.len()))),
                )
                .await;
            }
            break;
        };
        if size < 4 {
            cx.push(
                Node::new("Unrecognised data")
                    .span(region.tail(pos))
                    .diag(Diagnostic::malformed(format!("record size {size}"))),
            )
            .await;
            break;
        }
        let span = region.sub(pos, size.into());
        let bytes = cx.read(span).await?;
        let mut map = None;
        let summary = match kind {
            11 => v3_summary(&bytes, e),
            10 => {
                let ext = get::<u16>(&bytes, 6, e).unwrap_or(0);
                map = maps.get(&ext).cloned();
                common_summary(&bytes, e)
            }
            2 => {
                let (id, list) = parse_map(&bytes, e);
                let text = format!(
                    "map {id}: extensions {}",
                    list.iter()
                        .map(u16::to_string)
                        .collect::<Vec<_>>()
                        .join(", ")
                );
                if maps.len() < MAX_MAPS || maps.contains_key(&id) {
                    maps.insert(id, Arc::new(list));
                }
                text
            }
            7 => exporter_summary(&bytes, e),
            8 => plural(get::<u32>(&bytes, 4, e).unwrap_or(0), "exporter"),
            9 => format!(
                "sampler {}, interval {}",
                get::<i32>(&bytes, 4, e).unwrap_or(0),
                get::<u32>(&bytes, 8, e).unwrap_or(0)
            ),
            15 => format!(
                "sampler {}, packet interval {}",
                get::<i64>(&bytes, 8, e).unwrap_or(0),
                get::<u32>(&bytes, 16, e).unwrap_or(0)
            ),
            0x8001 => {
                let text = bytes.get(4..).unwrap_or_default();
                let end = text.iter().position(|&c| c == 0).unwrap_or(text.len());
                format!(
                    "\"{}\"",
                    String::from_utf8_lossy(text.get(..end).unwrap_or_default())
                )
            }
            0x8002 => match get::<u64>(&bytes, 4, e) {
                Some(n) => plural(n, "flow"),
                None => String::new(),
            },
            _ => String::new(),
        };
        let name = lookup(RECORD_TYPES, kind.into()).map_or_else(
            || format!("Record type {kind:#x}"),
            crate::formats::util::fmt::capitalize,
        );
        let mut node = Node::new(name).span(span).summary(summary);
        if span.len < u64::from(size) {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size.into()),
                span.len,
            ));
        }
        node = node.lazy(record, (file, span, kind, map));
        cx.push(node).await;
        pos = pos.saturating_add(size.into());
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The ID and extension list of an extension map record.
fn parse_map(b: &[u8], e: Endian) -> (u16, Vec<u16>) {
    let id = get::<u16>(b, 4, e).unwrap_or(0);
    let mut list = Vec::new();
    let mut at = 8usize;
    while let Some(x) = get::<u16>(b, at, e) {
        if x == 0 {
            break;
        }
        list.push(x);
        at = at.saturating_add(2);
    }
    (id, list)
}

/// The elements of a V3 record: type, offset and length of each.
fn elements(b: &[u8], e: Endian) -> Vec<(u16, usize, usize)> {
    let count = get::<u16>(b, 4, e).unwrap_or(0);
    let mut out = Vec::new();
    let mut at = 12usize;
    for _ in 0..count {
        let (Some(kind), Some(len)) =
            (get::<u16>(b, at, e), get::<u16>(b, at.saturating_add(2), e))
        else {
            break;
        };
        let len = usize::from(len);
        if len < 4 {
            break;
        }
        out.push((kind, at, len));
        at = at.saturating_add(len);
    }
    out
}

fn v3_summary(b: &[u8], e: Endian) -> String {
    let mut proto = None;
    let (mut src, mut dst) = (String::new(), String::new());
    let (mut sport, mut dport, mut packets, mut bytes) = (0u16, 0u16, 0u64, 0u64);
    let mut first = 0u64;
    for (kind, at, _) in elements(b, e) {
        let body = at.saturating_add(4);
        match kind {
            1 => {
                first = get::<u64>(b, body, e).unwrap_or(0);
                packets = get::<u64>(b, body.saturating_add(24), e).unwrap_or(0);
                bytes = get::<u64>(b, body.saturating_add(32), e).unwrap_or(0);
                sport = get::<u16>(b, body.saturating_add(40), e).unwrap_or(0);
                dport = get::<u16>(b, body.saturating_add(42), e).unwrap_or(0);
                proto = b.get(body.saturating_add(44)).copied();
            }
            2 => {
                src = ip4_text(get::<u32>(b, body, e).unwrap_or(0));
                dst = ip4_text(get::<u32>(b, body.saturating_add(4), e).unwrap_or(0));
            }
            3 => {
                src = ip6_text(b.get(body..).unwrap_or_default(), e);
                dst = ip6_text(b.get(body.saturating_add(16)..).unwrap_or_default(), e);
            }
            _ => {}
        }
    }
    let Some(proto) = proto else {
        return String::new();
    };
    format!(
        "{}, {}, {}, {}",
        flow_text(proto, &src, &dst, sport, dport),
        plural(packets, "packet"),
        plural(bytes, "byte"),
        ms_text(first)
    )
}

fn common_summary(b: &[u8], e: Endian) -> String {
    let flags = b.get(4).copied().unwrap_or(0);
    let proto = b.get(22).copied().unwrap_or(0);
    let sport = get::<u16>(b, 24, e).unwrap_or(0);
    let dport = get::<u16>(b, 26, e).unwrap_or(0);
    let first = u64::from(get::<u32>(b, 12, e).unwrap_or(0))
        .saturating_mul(1000)
        .saturating_add(get::<u16>(b, 8, e).unwrap_or(0).into());
    let mut at = 32usize;
    let (src, dst) = if flags & 1 != 0 {
        let s = ip6_text(b.get(at..).unwrap_or_default(), e);
        let d = ip6_text(b.get(at.saturating_add(16)..).unwrap_or_default(), e);
        at = at.saturating_add(32);
        (s, d)
    } else {
        let s = ip4_text(get::<u32>(b, at, e).unwrap_or(0));
        let d = ip4_text(get::<u32>(b, at.saturating_add(4), e).unwrap_or(0));
        at = at.saturating_add(8);
        (s, d)
    };
    let (packets, n) = counter(b, at, e, flags & 2 != 0);
    at = at.saturating_add(n);
    let (bytes, _) = counter(b, at, e, flags & 4 != 0);
    format!(
        "{}, {}, {}, {}",
        flow_text(proto, &src, &dst, sport, dport),
        plural(packets, "packet"),
        plural(bytes, "byte"),
        ms_text(first)
    )
}

/// A 32- or 64-bit counter at `at`, and its size.
fn counter(b: &[u8], at: usize, e: Endian, wide: bool) -> (u64, usize) {
    if wide {
        (get::<u64>(b, at, e).unwrap_or(0), 8)
    } else {
        (get::<u32>(b, at, e).unwrap_or(0).into(), 4)
    }
}

/// The address of an exporter record's `ip_addr_t` for its family.
fn exporter_ip(ip: &[u8], family: u16, e: Endian) -> String {
    match family {
        2 => {
            // IPv4 sits in the third word (little-endian) or the fourth.
            let at = if matches!(e, Endian::Little) { 8 } else { 12 };
            ip4_text(get::<u32>(ip, at, e).unwrap_or(0))
        }
        _ => ip6_text(ip, e),
    }
}

fn exporter_summary(b: &[u8], e: Endian) -> String {
    let version = get::<u32>(b, 4, e).unwrap_or(0);
    let family = get::<u16>(b, 24, e).unwrap_or(0);
    let sysid = get::<u16>(b, 26, e).unwrap_or(0);
    let ip = exporter_ip(b.get(8..24).unwrap_or_default(), family, e);
    let kind = if version == 9999 {
        "sFlow".to_owned()
    } else {
        format!("NetFlow v{version}")
    };
    format!("{kind} exporter {ip}, system ID {sysid}")
}

type RecordState = (File, Span, u16, Option<Arc<Vec<u16>>>);

async fn record(cx: Cx, (file, span, kind, map): RecordState) -> Result<()> {
    let e = file.endian;
    match kind {
        11 => v3_record(&cx, file, span).await,
        10 => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            common_record(&mut f, e, map.as_deref().map(Vec::as_slice))
        }
        2 => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            header_fields(&mut f)?;
            f.u16("Map ID").emit()?;
            f.u16("Extensions size").emit()?;
            while f.remaining() >= 2 {
                let id = f.u16("Extension").get()?;
                f.seek(f.pos().saturating_sub(2));
                if id == 0 {
                    f.u16("End of list").emit()?;
                    break;
                }
                f.u16("Extension")
                    .with(|&v, n| match v1_extension(v) {
                        Some((_, name)) => n.summary(name),
                        None => n.summary("unknown"),
                    })
                    .emit()?;
            }
            rest(&mut f, "Padding");
            Ok(())
        }
        7 => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            header_fields(&mut f)?;
            f.u32("Version")
                .with(|&v, n| if v == 9999 { n.summary("sFlow") } else { n })
                .emit()?;
            let raw = block.data.get(8..24).unwrap_or_default().to_vec();
            let family = get::<u16>(&block.data, 24, e).unwrap_or(0);
            let ip = exporter_ip(&raw, family, e);
            f.bytes("IP address", 16)
                .with(move |_, n| n.value(Value::Text(ip)))
                .emit()?;
            f.u16("Address family").enumeration(FAMILIES).emit()?;
            f.u16("System ID").emit()?;
            f.u32("Exporter ID")
                .desc("Source ID / observation domain")
                .emit()?;
            rest(&mut f, "Padding");
            Ok(())
        }
        8 => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            header_fields(&mut f)?;
            let count = f.u32("Exporters").emit()?;
            for i in 0..count {
                if f.remaining() < ExporterStat::SIZE {
                    break;
                }
                let at = f.peek_span(ExporterStat::SIZE);
                f.node(ExporterStat::node(format!("Exporter {i}"), at, e));
                f.skip(ExporterStat::SIZE);
            }
            rest(&mut f, "Padding");
            Ok(())
        }
        9 => {
            cx.emit(SamplerV0::node("Sampler", span, e));
            Ok(())
        }
        15 => {
            cx.emit(Sampler::node("Sampler", span, e));
            Ok(())
        }
        0x8001 => {
            let block = cx.block(span).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            header_fields(&mut f)?;
            f.cstr("Ident").emit()?;
            rest(&mut f, "Padding");
            Ok(())
        }
        0x8002 => {
            let block = cx.block(span.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            header_fields(&mut f)?;
            cx.emit(StatV2::node("Statistics", span.sub(4, StatV2::SIZE), e));
            if span.len > StatV2::SIZE.saturating_add(4) {
                cx.emit(Node::new("Padding").span(span.tail(StatV2::SIZE.saturating_add(4))));
            }
            Ok(())
        }
        _ => {
            let block = cx.block(span.sub(0, 4)).await?;
            let mut f = Fields::emitting(&cx, &block, e);
            header_fields(&mut f)?;
            cx.emit(Node::new("Data").span(span.tail(4)));
            Ok(())
        }
    }
}

fn header_fields(f: &mut Fields<'_>) -> Result<()> {
    f.u16("Type").enumeration(RECORD_TYPES).emit()?;
    f.u16("Size").emit()?;
    Ok(())
}

/// Whatever is left of a structure, as one node.
fn rest(f: &mut Fields<'_>, name: &'static str) {
    let n = f.remaining();
    if n > 0 {
        f.node(Node::new(name).span(f.peek_span(n)));
        f.skip(n);
    }
}

async fn v3_record(cx: &Cx, file: File, span: Span) -> Result<()> {
    let e = file.endian;
    let bytes = cx.read(span).await?;
    cx.emit(V3Header::node("Header", span.sub(0, V3Header::SIZE), e));
    let mut end = to_usize(V3Header::SIZE);
    for (i, (kind, at, len)) in elements(&bytes, e).into_iter().enumerate() {
        let espan = span.sub(to_u64(at), to_u64(len));
        let name = lookup(ELEMENTS, kind.into()).map_or_else(
            || format!("Element {kind}"),
            crate::formats::util::fmt::capitalize,
        );
        cx.emit(
            struct_node(name, espan, e, (kind, e), element)
                .summary(format!("element {i}, type {kind}")),
        );
        end = at.saturating_add(len);
        if i.is_multiple_of(64) {
            cx.checkpoint().await;
        }
    }
    if to_u64(end) < span.len {
        cx.emit(
            Node::new("Trailing data")
                .span(span.tail(to_u64(end)))
                .diag(Diagnostic::malformed("bytes after the last element")),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Field helpers

fn ms_field(f: &mut Fields<'_>, name: &'static str) -> Result<u64> {
    f.u64(name).unix_millis().emit()
}

fn ip4_field(f: &mut Fields<'_>, name: &'static str) -> Result<u32> {
    f.u32(name)
        .with(|&v, n| n.value(Value::Text(ip4_text(v))))
        .emit()
}

fn ip6_field(f: &mut Fields<'_>, name: &'static str, e: Endian) -> Result<()> {
    f.bytes(name, 16)
        .with(move |b, n| n.value(Value::Text(ip6_text(b, e))))
        .emit()?;
    Ok(())
}

fn mac_field(f: &mut Fields<'_>, name: &'static str) -> Result<u64> {
    f.u64(name)
        .with(|&v, n| n.value(Value::Text(mac_text(v))))
        .emit()
}

/// The rest of a structure as text up to its first NUL.
fn text_rest(f: &mut Fields<'_>, name: &'static str) -> Result<()> {
    let n = f.remaining();
    if n > 0 {
        f.ascii(name, n).emit()?;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// V3 elements

fn element(f: &mut Fields<'_>, &(kind, e): &(u16, Endian)) -> Result<()> {
    f.u16("Type").enumeration(ELEMENTS).emit()?;
    f.u16("Length").emit()?;
    match kind {
        1 => {
            ms_field(f, "First")?;
            ms_field(f, "Last")?;
            ms_field(f, "Received")?;
            f.u64("Packets").emit()?;
            f.u64("Bytes").emit()?;
            f.u16("Source port").emit()?;
            f.u16("Destination port")
                .desc("ICMP: type × 256 + code")
                .emit()?;
            f.u8("Protocol").enumeration(IP_PROTOCOLS).emit()?;
            f.u8("TCP flags").flags(TCP_FLAGS).emit()?;
            f.u8("Forwarding status").emit()?;
            f.u8("Source ToS").emit()?;
        }
        2 => {
            ip4_field(f, "Source address")?;
            ip4_field(f, "Destination address")?;
        }
        3 => {
            ip6_field(f, "Source address", e)?;
            ip6_field(f, "Destination address", e)?;
        }
        4 => {
            f.u32("Input interface").emit()?;
            f.u32("Output interface").emit()?;
            f.u8("Source mask").emit()?;
            f.u8("Destination mask").emit()?;
            f.u8("Direction").emit()?;
            f.u8("Destination ToS").emit()?;
            f.u8("Biflow direction").emit()?;
            f.u8("Flow end reason").emit()?;
        }
        5 => {
            f.u64("Flows").emit()?;
            f.u64("Out packets").emit()?;
            f.u64("Out bytes").emit()?;
        }
        6 => {
            f.u32("Source VLAN").emit()?;
            f.u32("Destination VLAN").emit()?;
        }
        7 => {
            f.u32("Source AS").emit()?;
            f.u32("Destination AS").emit()?;
        }
        8 => {
            ip4_field(f, "BGP next hop")?;
        }
        9 => ip6_field(f, "BGP next hop", e)?,
        10 => {
            ip4_field(f, "Next hop")?;
        }
        11 => ip6_field(f, "Next hop", e)?,
        12 => {
            ip4_field(f, "Received from")?;
        }
        13 => ip6_field(f, "Received from", e)?,
        14 => {
            for _ in 0..10 {
                if f.remaining() < 4 {
                    break;
                }
                f.u32("MPLS label")
                    .with(|&v, n| {
                        n.summary(format!(
                            "label {}, exp {}, {}",
                            v >> 4,
                            (v >> 1) & 7,
                            if v & 1 != 0 { "bottom" } else { "not bottom" }
                        ))
                    })
                    .emit()?;
            }
        }
        15 => {
            mac_field(f, "In source MAC")?;
            mac_field(f, "Out destination MAC")?;
            mac_field(f, "In destination MAC")?;
            mac_field(f, "Out source MAC")?;
        }
        16 => {
            f.u32("Next adjacent AS").emit()?;
            f.u32("Previous adjacent AS").emit()?;
        }
        17 => {
            f.u64("Client network delay (µs)").emit()?;
            f.u64("Server network delay (µs)").emit()?;
            f.u64("Application latency (µs)").emit()?;
        }
        19 => {
            ms_field(f, "Event time")?;
            f.u32("Connection ID").emit()?;
            f.u16("Extended event").emit()?;
            f.u8("Event").emit()?;
            f.u8("Fill").emit()?;
        }
        20 => {
            ip4_field(f, "Translated source")?;
            ip4_field(f, "Translated destination")?;
        }
        21 => {
            ip6_field(f, "Translated source", e)?;
            ip6_field(f, "Translated destination", e)?;
        }
        22 => {
            f.u16("Translated source port").emit()?;
            f.u16("Translated destination port").emit()?;
        }
        23 => {
            for name in [
                "Ingress ACL",
                "Ingress ACE",
                "Ingress hash",
                "Egress ACL",
                "Egress ACE",
                "Egress hash",
            ] {
                f.u32(name).emit()?;
            }
        }
        24 | 28 | 41 => text_rest(f, "Text")?,
        25 => {
            ms_field(f, "Event time")?;
            f.u32("NAT pool ID").emit()?;
            f.u8("NAT event").emit()?;
        }
        26 => {
            f.u16("Block start").emit()?;
            f.u16("Block end").emit()?;
            f.u16("Block step").emit()?;
            f.u16("Block size").emit()?;
        }
        31 => {
            ip4_field(f, "Tunnel source")?;
            ip4_field(f, "Tunnel destination")?;
            f.u32("Tunnel protocol").emit()?;
        }
        32 => {
            ip6_field(f, "Tunnel source", e)?;
            ip6_field(f, "Tunnel destination", e)?;
            f.u32("Tunnel protocol").emit()?;
        }
        33 => {
            f.u64("Observation point ID").emit()?;
            f.u32("Observation domain ID").emit()?;
        }
        36 => {
            f.u32("Egress VRF").emit()?;
            f.u32("Ingress VRF").emit()?;
        }
        37 => {
            f.u8("Action").emit()?;
            f.u8("Reason").emit()?;
            f.u8("Direction").emit()?;
            f.u8("Rewritten").emit()?;
            f.u32("Rule").emit()?;
            f.u32("Subrule").emit()?;
            f.u32("UID").emit()?;
            f.u32("PID").emit()?;
            text_rest(f, "Interface")?;
        }
        38 => {
            f.u16("VLAN ID").emit()?;
            f.u16("Customer VLAN ID").emit()?;
            f.u16("Post VLAN ID").emit()?;
            f.u16("Post customer VLAN ID").emit()?;
            f.u32("Ingress interface").emit()?;
            f.u32("Egress interface").emit()?;
            f.u64("VXLAN").emit()?;
            f.u16("EtherType").hex().emit()?;
            f.u8("IP version").emit()?;
        }
        39 => {
            f.u64("Flow ID").emit()?;
        }
        40 => {
            f.u16("Inside service ID").emit()?;
            f.u16("Outside service ID").emit()?;
        }
        42 => {
            f.u8("TTL").emit()?;
            f.u8("Fragment flags").hex().emit()?;
        }
        _ => {}
    }
    rest(
        f,
        if matches!(kind, 18 | 27 | 29 | 30 | 34 | 35) {
            "Data"
        } else {
            "Padding"
        },
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Layout 1 common records

fn v1_extension(id: u16) -> Option<(u64, &'static str)> {
    V1_EXTENSIONS
        .iter()
        .find(|(x, _, _)| *x == id)
        .map(|&(_, size, name)| (size, name))
}

fn common_record(f: &mut Fields<'_>, e: Endian, map: Option<&[u16]>) -> Result<()> {
    let c = CommonRecord::read(&mut Fields::new(f.block(), e))?;
    let fixed = f.peek_span(CommonRecord::SIZE);
    f.node(CommonRecord::node("Common fields", fixed, e));
    f.skip(CommonRecord::SIZE);
    if c.flags & 1 != 0 {
        ip6_field(f, "Source address", e)?;
        ip6_field(f, "Destination address", e)?;
    } else {
        ip4_field(f, "Source address")?;
        ip4_field(f, "Destination address")?;
    }
    if c.flags & 2 != 0 {
        f.u64("Packets").emit()?;
    } else {
        f.u32("Packets").emit()?;
    }
    if c.flags & 4 != 0 {
        f.u64("Bytes").emit()?;
    } else {
        f.u32("Bytes").emit()?;
    }
    let Some(map) = map else {
        if f.remaining() > 0 {
            f.node(
                Node::new("Extensions")
                    .span(f.peek_span(f.remaining()))
                    .diag(Diagnostic::note(format!(
                        "extension map {} is not in this block",
                        c.ext_map
                    ))),
            );
            f.skip(f.remaining());
        }
        return Ok(());
    };
    for &id in map {
        let Some((size, name)) = v1_extension(id) else {
            f.node(
                Node::new(format!("Extension {id}"))
                    .span(f.peek_span(f.remaining()))
                    .diag(Diagnostic::unsupported(format!("extension {id}"))),
            );
            f.skip(f.remaining());
            return Ok(());
        };
        if f.remaining() < size {
            break;
        }
        let at = f.peek_span(size);
        f.node(struct_node(name, at, e, (id, e), v1_ext).summary(format!("extension {id}")));
        f.skip(size);
    }
    rest(f, "Padding");
    Ok(())
}

fn v1_ext(f: &mut Fields<'_>, &(id, e): &(u16, Endian)) -> Result<()> {
    match id {
        4 => {
            f.u16("Input interface").emit()?;
            f.u16("Output interface").emit()?;
        }
        5 => {
            f.u32("Input interface").emit()?;
            f.u32("Output interface").emit()?;
        }
        6 => {
            f.u16("Source AS").emit()?;
            f.u16("Destination AS").emit()?;
        }
        7 | 26 => {
            f.u32(if id == 7 {
                "Source AS"
            } else {
                "Next adjacent AS"
            })
            .emit()?;
            f.u32(if id == 7 {
                "Destination AS"
            } else {
                "Previous adjacent AS"
            })
            .emit()?;
        }
        8 => {
            f.u8("Destination ToS").emit()?;
            f.u8("Direction").emit()?;
            f.u8("Source mask").emit()?;
            f.u8("Destination mask").emit()?;
        }
        9 | 11 | 23 => {
            ip4_field(f, "Address")?;
        }
        10 | 12 | 24 => ip6_field(f, "Address", e)?,
        13 => {
            f.u16("Source VLAN").emit()?;
            f.u16("Destination VLAN").emit()?;
        }
        14 | 16 | 18 => {
            f.u32("Count").emit()?;
        }
        15 | 17 | 19 => {
            f.u64("Count").emit()?;
        }
        20 => {
            mac_field(f, "In source MAC")?;
            mac_field(f, "Out destination MAC")?;
        }
        21 => {
            mac_field(f, "In destination MAC")?;
            mac_field(f, "Out source MAC")?;
        }
        22 => {
            for _ in 0..10 {
                f.u32("MPLS label").emit()?;
            }
        }
        25 => {
            f.u16("Fill").emit()?;
            f.u8("Engine type").emit()?;
            f.u8("Engine ID").emit()?;
        }
        27 => {
            ms_field(f, "Received")?;
        }
        _ => {}
    }
    rest(f, "Data");
    Ok(())
}
