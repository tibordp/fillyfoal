//! IEEE 802.11 frames and the radiotap header that precedes them in
//! monitor-mode captures: radiotap fields of the default namespace (with
//! their alignment rules), the 802.11 MAC header (frame control, addresses,
//! sequence control, QoS), management frame bodies with their information
//! elements (SSID, rates, DS parameter set, TIM, country, RSN, HT, vendor),
//! and data frames carried over LLC/SNAP. Protected frames stay opaque.
//! All fields are little-endian.

use super::dec::{Dec, Ix, flags, mac};
use super::net;
use crate::error::Diagnostic;
use crate::fields::Endian;
use crate::value::{EnumTable, FlagTable, field, flag, lookup};

const RADIOTAP_FLAGS: FlagTable = &[
    flag(0x01, "CFP"),
    flag(0x02, "SHORT_PREAMBLE"),
    flag(0x04, "WEP"),
    flag(0x08, "FRAGMENTED"),
    flag(0x10, "FCS_AT_END"),
    flag(0x20, "DATA_PAD"),
    flag(0x40, "BAD_FCS"),
    flag(0x80, "SHORT_GI"),
];

const CHANNEL_FLAGS: FlagTable = &[
    flag(0x0010, "TURBO"),
    flag(0x0020, "CCK"),
    flag(0x0040, "OFDM"),
    flag(0x0080, "2GHZ"),
    flag(0x0100, "5GHZ"),
    flag(0x0200, "PASSIVE"),
    flag(0x0400, "DYNAMIC_CCK_OFDM"),
    flag(0x0800, "GFSK"),
    flag(0x1000, "GSM"),
    flag(0x2000, "STATIC_TURBO"),
    flag(0x4000, "HALF_RATE"),
    flag(0x8000, "QUARTER_RATE"),
];

/// Radiotap fields of the default namespace: (bit, alignment, size, name).
const RADIOTAP_FIELDS: &[(u32, usize, usize, &str)] = &[
    (0, 8, 8, "TSFT"),
    (1, 1, 1, "Flags"),
    (2, 1, 1, "Rate"),
    (3, 2, 4, "Channel"),
    (4, 2, 2, "FHSS"),
    (5, 1, 1, "Antenna signal (dBm)"),
    (6, 1, 1, "Antenna noise (dBm)"),
    (7, 2, 2, "Lock quality"),
    (8, 2, 2, "TX attenuation"),
    (9, 2, 2, "TX attenuation (dB)"),
    (10, 1, 1, "TX power (dBm)"),
    (11, 1, 1, "Antenna"),
    (12, 1, 1, "Antenna signal (dB)"),
    (13, 1, 1, "Antenna noise (dB)"),
    (14, 2, 2, "RX flags"),
    (15, 2, 2, "TX flags"),
    (16, 1, 1, "RTS retries"),
    (17, 1, 1, "Data retries"),
    (18, 4, 8, "XChannel"),
    (19, 1, 3, "MCS"),
    (20, 4, 8, "A-MPDU status"),
    (21, 2, 12, "VHT"),
    (22, 8, 12, "Timestamp"),
    (23, 2, 12, "HE"),
    (24, 2, 12, "HE-MU"),
    (25, 2, 6, "HE-MU other user"),
    (26, 1, 1, "Zero-length PSDU"),
    (27, 2, 4, "L-SIG"),
];

const PRESENT: FlagTable = &[
    flag(1 << 0, "TSFT"),
    flag(1 << 1, "FLAGS"),
    flag(1 << 2, "RATE"),
    flag(1 << 3, "CHANNEL"),
    flag(1 << 4, "FHSS"),
    flag(1 << 5, "DBM_ANTSIGNAL"),
    flag(1 << 6, "DBM_ANTNOISE"),
    flag(1 << 7, "LOCK_QUALITY"),
    flag(1 << 8, "TX_ATTENUATION"),
    flag(1 << 9, "DB_TX_ATTENUATION"),
    flag(1 << 10, "DBM_TX_POWER"),
    flag(1 << 11, "ANTENNA"),
    flag(1 << 12, "DB_ANTSIGNAL"),
    flag(1 << 13, "DB_ANTNOISE"),
    flag(1 << 14, "RX_FLAGS"),
    flag(1 << 15, "TX_FLAGS"),
    flag(1 << 16, "RTS_RETRIES"),
    flag(1 << 17, "DATA_RETRIES"),
    flag(1 << 18, "XCHANNEL"),
    flag(1 << 19, "MCS"),
    flag(1 << 20, "AMPDU_STATUS"),
    flag(1 << 21, "VHT"),
    flag(1 << 22, "TIMESTAMP"),
    flag(1 << 23, "HE"),
    flag(1 << 24, "HE_MU"),
    flag(1 << 25, "HE_MU_OTHER_USER"),
    flag(1 << 26, "ZERO_LEN_PSDU"),
    flag(1 << 27, "LSIG"),
    flag(1 << 28, "TLV"),
    flag(1 << 29, "RADIOTAP_NAMESPACE"),
    flag(1 << 30, "VENDOR_NAMESPACE"),
    flag(1 << 31, "EXT"),
];

const FRAME_TYPES: EnumTable = &[
    (0, "Management"),
    (1, "Control"),
    (2, "Data"),
    (3, "Extension"),
];

const MGMT_SUBTYPES: EnumTable = &[
    (0, "Association request"),
    (1, "Association response"),
    (2, "Reassociation request"),
    (3, "Reassociation response"),
    (4, "Probe request"),
    (5, "Probe response"),
    (6, "Timing advertisement"),
    (8, "Beacon"),
    (9, "ATIM"),
    (10, "Disassociation"),
    (11, "Authentication"),
    (12, "Deauthentication"),
    (13, "Action"),
    (14, "Action no ack"),
];

const CTRL_SUBTYPES: EnumTable = &[
    (2, "Trigger"),
    (4, "Beamforming report poll"),
    (5, "VHT NDP announcement"),
    (7, "Control wrapper"),
    (8, "Block ack request"),
    (9, "Block ack"),
    (10, "PS-Poll"),
    (11, "RTS"),
    (12, "CTS"),
    (13, "ACK"),
    (14, "CF-End"),
    (15, "CF-End + CF-Ack"),
];

const DATA_SUBTYPES: EnumTable = &[
    (0, "Data"),
    (4, "Null function"),
    (8, "QoS data"),
    (12, "QoS null function"),
];

const FC_FLAGS: FlagTable = &[
    flag(0x0100, "TO_DS"),
    flag(0x0200, "FROM_DS"),
    flag(0x0400, "MORE_FRAGMENTS"),
    flag(0x0800, "RETRY"),
    flag(0x1000, "POWER_MGMT"),
    flag(0x2000, "MORE_DATA"),
    flag(0x4000, "PROTECTED"),
    flag(0x8000, "HTC_ORDER"),
    field(0x0003, 0x0001, "VERSION=1"),
];

const CAPABILITIES: FlagTable = &[
    flag(0x0001, "ESS"),
    flag(0x0002, "IBSS"),
    flag(0x0010, "PRIVACY"),
    flag(0x0020, "SHORT_PREAMBLE"),
    flag(0x0100, "SPECTRUM_MGMT"),
    flag(0x0200, "QOS"),
    flag(0x0400, "SHORT_SLOT_TIME"),
    flag(0x0800, "APSD"),
    flag(0x1000, "RADIO_MEASUREMENT"),
    flag(0x4000, "DELAYED_BLOCK_ACK"),
    flag(0x8000, "IMMEDIATE_BLOCK_ACK"),
];

const ELEMENTS: EnumTable = &[
    (0, "SSID"),
    (1, "Supported rates"),
    (3, "DS parameter set"),
    (4, "CF parameter set"),
    (5, "Traffic indication map"),
    (6, "IBSS parameter set"),
    (7, "Country"),
    (11, "BSS load"),
    (32, "Power constraint"),
    (33, "Power capability"),
    (35, "TPC report"),
    (36, "Supported channels"),
    (37, "Channel switch announcement"),
    (42, "ERP information"),
    (45, "HT capabilities"),
    (46, "QoS capability"),
    (48, "RSN"),
    (50, "Extended supported rates"),
    (51, "AP channel report"),
    (54, "Mobility domain"),
    (59, "Supported operating classes"),
    (61, "HT operation"),
    (70, "RM enabled capabilities"),
    (74, "Overlapping BSS scan parameters"),
    (107, "Interworking"),
    (108, "Advertisement protocol"),
    (127, "Extended capabilities"),
    (191, "VHT capabilities"),
    (192, "VHT operation"),
    (195, "Transmit power envelope"),
    (221, "Vendor specific"),
    (255, "Element ID extension"),
];

const ERP_FLAGS: FlagTable = &[
    flag(1, "NON_ERP_PRESENT"),
    flag(2, "USE_PROTECTION"),
    flag(4, "BARKER_PREAMBLE_MODE"),
];

const CIPHER_SUITES: EnumTable = &[
    (1, "WEP-40"),
    (2, "TKIP"),
    (4, "CCMP-128"),
    (5, "WEP-104"),
    (6, "BIP-CMAC-128"),
    (8, "GCMP-128"),
    (9, "GCMP-256"),
    (10, "CCMP-256"),
    (11, "BIP-GMAC-128"),
    (12, "BIP-GMAC-256"),
    (13, "BIP-CMAC-256"),
];

const AKM_SUITES: EnumTable = &[
    (1, "802.1X"),
    (2, "PSK"),
    (3, "FT-802.1X"),
    (4, "FT-PSK"),
    (5, "802.1X-SHA256"),
    (6, "PSK-SHA256"),
    (8, "SAE"),
    (9, "FT-SAE"),
    (12, "802.1X-Suite-B-192"),
    (18, "OWE"),
    (24, "SAE-EXT-KEY"),
];

const REASONS: EnumTable = &[
    (1, "Unspecified"),
    (2, "Previous authentication no longer valid"),
    (3, "Leaving the BSS"),
    (4, "Inactivity"),
    (5, "AP unable to handle all associated stations"),
    (6, "Class 2 frame from nonauthenticated station"),
    (7, "Class 3 frame from nonassociated station"),
    (8, "Leaving the BSS (disassociated)"),
    (15, "4-way handshake timeout"),
];

const AUTH_ALGORITHMS: EnumTable = &[
    (0, "Open system"),
    (1, "Shared key"),
    (2, "Fast BSS transition"),
    (3, "SAE"),
    (4, "FILS shared key"),
];

/// A radiotap header, then the 802.11 frame it describes.
pub fn radiotap(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 8 || b.u8(off) != Some(0) || !b.enter() {
        return off;
    }
    let saved = b.endian;
    b.endian = Endian::Little;
    let len = usize::from(b.u16(off.saturating_add(2)).unwrap_or(0));
    let hend = off.saturating_add(len).min(end);
    let ix = b.group(p, "Radiotap header", off, hend.saturating_sub(off));
    b.num(ix, "Version", off, 1);
    b.num(ix, "Pad", off.saturating_add(1), 1);
    b.num(ix, "Length", off.saturating_add(2), 2);
    // Presence words.
    let mut words = Vec::new();
    let mut at = off.saturating_add(4);
    while let Some(w) = b.u32(at) {
        b.flg(ix, "Present flags", at, 4, PRESENT);
        words.push(w);
        at = at.saturating_add(4);
        if w & 0x8000_0000 == 0 || words.len() >= 16 || at >= hend {
            break;
        }
    }
    let mut fcs = false;
    let mut parts = Vec::new();
    // Fields: each word's bits 0..28 are fields of the namespace in force;
    // only the default (radiotap) namespace is decoded.
    let mut radiotap_ns = true;
    'words: for &w in &words {
        if radiotap_ns {
            for &(bit, align, sz, name) in RADIOTAP_FIELDS {
                if w & (1u32 << bit) == 0 {
                    continue;
                }
                let rel = at.saturating_sub(off).next_multiple_of(align);
                at = off.saturating_add(rel);
                if at.saturating_add(sz) > hend {
                    b.diag(
                        ix,
                        Diagnostic::malformed(format!("{name} overruns the header")),
                    );
                    break 'words;
                }
                if let Some(s) = radiotap_field(b, ix, bit, name, at, sz, &mut fcs) {
                    parts.push(s);
                }
                at = at.saturating_add(sz);
            }
            if w & (1 << 28) != 0 {
                b.data(ix, "TLV fields", at, hend);
                at = hend;
                break;
            }
        } else if w & 0x1fff_ffff != 0 {
            // A vendor namespace: its skip length was in its header.
            b.data(ix, "Vendor namespace data", at, hend);
            at = hend;
            break;
        }
        if w & (1 << 30) != 0 {
            radiotap_ns = false;
            let rel = at.saturating_sub(off).next_multiple_of(2);
            at = off.saturating_add(rel);
            if hend.saturating_sub(at) >= 6 {
                let g = b.group(ix, "Vendor namespace", at, 6);
                b.raw(g, "OUI", at, 3);
                b.num(g, "Sub-namespace", at.saturating_add(3), 1);
                let skip = usize::from(b.u16(at.saturating_add(4)).unwrap_or(0));
                b.num(g, "Skip length", at.saturating_add(4), 2);
                at = at.saturating_add(6);
                b.data(ix, "Vendor data", at, at.saturating_add(skip).min(hend));
                at = at.saturating_add(skip).min(hend);
            }
        } else if w & (1 << 29) != 0 {
            radiotap_ns = true;
        }
    }
    if at < hend {
        b.data(ix, "Unparsed fields", at, hend);
    }
    b.summary(ix, || parts.join(", "));
    b.endian = saved;
    let fend = if fcs {
        end.saturating_sub(4).max(hend)
    } else {
        end
    };
    let used = ieee80211(b, p, hend, fend, false);
    if fcs && fend < end {
        fcs_field(b, p, hend, fend);
    }
    b.leave();
    if fcs && used >= fend {
        end
    } else {
        used.max(hend)
    }
}

fn fcs_field(b: &mut Dec, p: Ix, start: usize, at: usize) {
    let stored = crate::bytes::u32_le(b.d, at);
    let computed = crate::codec::crc32(b.range(start, at));
    b.endian = Endian::Little;
    b.numx(p, "Frame check sequence", at, 4);
    b.endian = Endian::Big;
    if let Some(s) = stored {
        if s == computed {
            b.tail(|n| n.summary("correct"));
        } else if b.complete {
            b.tail(|n| n.diag(Diagnostic::warning(format!("should be {computed:#010x}"))));
        }
    }
}

fn radiotap_field(
    b: &mut Dec,
    p: Ix,
    bit: u32,
    name: &'static str,
    at: usize,
    sz: usize,
    fcs: &mut bool,
) -> Option<String> {
    let signed = |v: u8| i64::from(v as i8);
    match bit {
        0 => {
            b.num(p, name, at, 8);
            b.tail(|n| n.summary("µs"));
            None
        }
        1 => {
            let v = b.flg(p, name, at, 1, RADIOTAP_FLAGS).unwrap_or(0);
            *fcs = v & 0x10 != 0;
            None
        }
        2 => {
            let v = b.num(p, name, at, 1).unwrap_or(0);
            let s = format!("{}.{} Mb/s", v / 2, if v % 2 == 1 { 5 } else { 0 });
            let shown = s.clone();
            b.tail(|n| n.summary(shown));
            Some(s)
        }
        3 => {
            let g = b.group(p, name, at, 4);
            let f = b.num(g, "Frequency (MHz)", at, 2).unwrap_or(0);
            b.flg(g, "Flags", at.saturating_add(2), 2, CHANNEL_FLAGS);
            let ch = channel(f);
            let s = format!("{f} MHz (channel {ch})");
            let shown = s.clone();
            b.summary(g, || shown);
            Some(s)
        }
        5 | 6 | 10 => {
            let v = signed(b.u8(at).unwrap_or(0));
            b.add(p, name, at, 1, |n| {
                n.value(crate::formats::util::val::int(v, 8)).summary("dBm")
            });
            (bit == 5).then(|| format!("{v} dBm"))
        }
        19 => {
            let g = b.group(p, name, at, 3);
            b.numx(g, "Known", at, 1);
            b.numx(g, "Flags", at.saturating_add(1), 1);
            let mcs = b.num(g, "MCS index", at.saturating_add(2), 1).unwrap_or(0);
            b.summary(g, || format!("MCS {mcs}"));
            Some(format!("MCS {mcs}"))
        }
        _ => {
            if sz <= 2 {
                b.num(p, name, at, sz);
            } else {
                b.raw(p, name, at, sz);
            }
            None
        }
    }
}

fn channel(mhz: u64) -> u64 {
    match mhz {
        2484 => 14,
        2412..=2472 => mhz.saturating_sub(2407) / 5,
        5000..=5900 => mhz.saturating_sub(5000) / 5,
        5955..=7115 => mhz.saturating_sub(5950) / 5,
        _ => 0,
    }
}

/// An 802.11 MAC frame (`fcs`: the last four bytes are its FCS).
pub fn ieee80211(b: &mut Dec, p: Ix, off: usize, end: usize, fcs: bool) -> usize {
    if end.saturating_sub(off) < 10 || !b.enter() {
        return off;
    }
    let saved = b.endian;
    b.endian = Endian::Little;
    let end = if fcs { end.saturating_sub(4) } else { end };
    let used = frame(b, p, off, end);
    b.endian = saved;
    if fcs {
        fcs_field(b, p, off, end);
    }
    b.leave();
    if fcs { end.saturating_add(4) } else { used }
}

fn frame(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let fc = b.u16(off).unwrap_or(0);
    let (kind, sub) = ((fc >> 2) & 3, (fc >> 4) & 15);
    let to_ds = fc & 0x0100 != 0;
    let from_ds = fc & 0x0200 != 0;
    let protected = fc & 0x4000 != 0;
    let subtypes = match kind {
        0 => MGMT_SUBTYPES,
        1 => CTRL_SUBTYPES,
        _ => DATA_SUBTYPES,
    };
    let sname = lookup(subtypes, sub.into()).unwrap_or("Reserved");
    // Header length.
    let mut hlen: usize = match (kind, sub) {
        (1, 12 | 13) => 10,
        (1, 4 | 5 | 8 | 9 | 10 | 11 | 14 | 15) => 16,
        (1, _) => 10,
        _ => 24,
    };
    if kind == 2 && to_ds && from_ds {
        hlen = 30;
    }
    let qos = kind == 2 && sub & 8 != 0;
    if qos {
        hlen = hlen.saturating_add(2);
    }
    if fc & 0x8000 != 0 && (qos || kind == 0) {
        hlen = hlen.saturating_add(4);
    }
    let hlen = hlen.min(end.saturating_sub(off));
    let ix = b.group(p, "IEEE 802.11", off, hlen);
    let fcg = b.group(ix, "Frame control", off, 2);
    b.add(fcg, "Version / type / subtype", off, 1, |n| {
        n.value(crate::formats::util::val::hex(u64::from(fc & 0xff), 8))
            .summary(format!(
                "version {}, {} ({kind}), {sname} ({sub})",
                fc & 3,
                lookup(FRAME_TYPES, kind.into()).unwrap_or("?")
            ))
    });
    b.add(fcg, "Flags", off.saturating_add(1), 1, |n| {
        n.value(flags(u64::from(fc & 0xff00), 16, FC_FLAGS))
    });
    let tname = lookup(FRAME_TYPES, kind.into()).unwrap_or("?");
    b.summary(fcg, || format!("{tname}, {sname}"));
    b.num(
        ix,
        if kind == 1 && sub == 10 {
            "Association ID"
        } else {
            "Duration (µs)"
        },
        off.saturating_add(2),
        2,
    );
    let a1 = b.mac(
        ix,
        address_name(kind, to_ds, from_ds, 1),
        off.saturating_add(4),
    );
    let mut a2 = None;
    let mut a3 = None;
    if hlen >= 16 {
        a2 = b.mac(
            ix,
            address_name(kind, to_ds, from_ds, 2),
            off.saturating_add(10),
        );
    }
    if hlen >= 24 && kind != 1 {
        a3 = b.mac(
            ix,
            address_name(kind, to_ds, from_ds, 3),
            off.saturating_add(16),
        );
        let sc = b.u16(off.saturating_add(22)).unwrap_or(0);
        b.numx(ix, "Sequence control", off.saturating_add(22), 2);
        b.tail(|n| n.summary(format!("sequence {}, fragment {}", sc >> 4, sc & 15)));
    }
    let mut at = off.saturating_add(24);
    if kind == 2 && to_ds && from_ds {
        b.mac(ix, "Source address", at);
        at = at.saturating_add(6);
    }
    if qos {
        let q = b.u16(at).unwrap_or(0);
        b.numx(ix, "QoS control", at, 2);
        b.tail(|n| n.summary(format!("TID {}", q & 15)));
        at = at.saturating_add(2);
    }
    if fc & 0x8000 != 0 && (qos || kind == 0) {
        b.numx(ix, "HT control", at, 4);
        at = at.saturating_add(4);
    }
    let at = at
        .min(off.saturating_add(hlen))
        .max(off.saturating_add(hlen));
    let (s1, s2, s3) = (
        a1.map(|a| mac(&a)).unwrap_or_default(),
        a2.map(|a| mac(&a)).unwrap_or_default(),
        a3.map(|a| mac(&a)).unwrap_or_default(),
    );
    let tx = if s2.is_empty() {
        String::new()
    } else {
        s2.clone()
    };
    let line = if tx.is_empty() {
        format!("{sname}, to {s1}")
    } else {
        format!("{sname}, {tx} → {s1}")
    };
    let shown = line.clone();
    b.summary(ix, || shown);
    let (src, dst) = (tx, s1);
    b.set_addrs(|| src, || dst);
    b.set_info("802.11", || format!("802.11 {line}"));
    let _ = s3;
    if at >= end {
        return at;
    }
    if protected {
        let g = b.group(p, "Protected payload", at, end.saturating_sub(at));
        if end.saturating_sub(at) >= 8 {
            let ext = b.u8(at.saturating_add(3)).unwrap_or(0) & 0x20 != 0;
            if ext {
                b.raw(g, "CCMP/GCMP header", at, 8);
                b.data(g, "Encrypted data", at.saturating_add(8), end);
            } else {
                b.raw(g, "WEP IV / key ID", at, 4);
                b.data(g, "Encrypted data", at.saturating_add(4), end);
            }
        }
        b.set_info("802.11", || format!("802.11 {sname}, protected"));
        return end;
    }
    match kind {
        0 => management(b, p, sub, at, end),
        2 if sub & 4 == 0 => llc_snap(b, p, at, end),
        _ => b.data(p, "Frame body", at, end),
    }
}

fn address_name(kind: u16, to_ds: bool, from_ds: bool, n: u8) -> &'static str {
    match (kind, to_ds, from_ds, n) {
        (1, _, _, 1) => "Receiver address",
        (1, _, _, _) => "Transmitter address",
        (0, _, _, 1) | (2, false, false, 1) | (2, true, false, 3) => "Destination address",
        (0, _, _, 2) | (2, false, false, 2) | (2, false, true, 3) => "Source address",
        (0, _, _, _) | (2, false, false, _) | (2, true, false, 1) | (2, false, true, 2) => "BSSID",
        (2, false, true, _) => "Destination address",
        (2, true, false, _) => "Source address",
        (_, _, _, 1) => "Receiver address",
        (_, _, _, 2) => "Transmitter address",
        _ => "Destination address",
    }
}

fn llc_snap(b: &mut Dec, p: Ix, at: usize, end: usize) -> usize {
    if end.saturating_sub(at) >= 8 && b.bytes(at, 3) == Some(&[0xaa, 0xaa, 0x03][..]) {
        let g = b.group(p, "Logical-Link Control", at, 8);
        b.numx(g, "DSAP", at, 1);
        b.numx(g, "SSAP", at.saturating_add(1), 1);
        b.numx(g, "Control", at.saturating_add(2), 1);
        b.raw(g, "Organization code", at.saturating_add(3), 3);
        let t = b.be16(at.saturating_add(6)).unwrap_or(0);
        b.add(g, "Type", at.saturating_add(6), 2, |n| {
            n.value(crate::formats::util::val::hex(t, 16))
        });
        b.summary(g, || format!("SNAP, type {t:#06x}"));
        let body = at.saturating_add(8);
        let saved = b.endian;
        b.endian = Endian::Big;
        let used = net::ether(b, p, t, body, end);
        b.endian = saved;
        return if used <= body {
            b.data(p, "Data", body, end)
        } else {
            used
        };
    }
    b.data(p, "Frame body", at, end)
}

fn management(b: &mut Dec, p: Ix, sub: u16, at: usize, end: usize) -> usize {
    let ix = b.group(p, "Management frame body", at, end.saturating_sub(at));
    let mut a = at;
    match sub {
        8 | 5 => {
            b.num(ix, "Timestamp (µs)", a, 8);
            let bi = b
                .num(ix, "Beacon interval", a.saturating_add(8), 2)
                .unwrap_or(0);
            b.tail(|n| n.summary(format!("{bi} TU ({} ms)", bi.saturating_mul(1024) / 1000)));
            b.flg(ix, "Capabilities", a.saturating_add(10), 2, CAPABILITIES);
            a = a.saturating_add(12);
        }
        0 | 2 => {
            b.flg(ix, "Capabilities", a, 2, CAPABILITIES);
            b.num(ix, "Listen interval", a.saturating_add(2), 2);
            a = a.saturating_add(4);
            if sub == 2 {
                b.mac(ix, "Current AP", a);
                a = a.saturating_add(6);
            }
        }
        1 | 3 => {
            b.flg(ix, "Capabilities", a, 2, CAPABILITIES);
            b.num(ix, "Status code", a.saturating_add(2), 2);
            b.numx(ix, "Association ID", a.saturating_add(4), 2);
            a = a.saturating_add(6);
        }
        11 => {
            b.enm(ix, "Algorithm", a, 2, AUTH_ALGORITHMS);
            b.num(ix, "Sequence number", a.saturating_add(2), 2);
            b.num(ix, "Status code", a.saturating_add(4), 2);
            a = a.saturating_add(6);
        }
        10 | 12 => {
            b.enm(ix, "Reason code", a, 2, REASONS);
            a = a.saturating_add(2);
        }
        13 | 14 => {
            b.num(ix, "Category", a, 1);
            return b
                .data(ix, "Action details", a.saturating_add(1), end)
                .max(end);
        }
        _ => {}
    }
    let ssid = elements(b, ix, a, end);
    if let Some(s) = ssid {
        let shown = s.clone();
        b.summary(ix, || format!("SSID {shown:?}"));
        b.set_info("802.11", || {
            let mut line = b_info_prefix(sub);
            line.push_str(&format!(", SSID {s:?}"));
            line
        });
    }
    end
}

fn b_info_prefix(sub: u16) -> String {
    format!(
        "802.11 {}",
        lookup(MGMT_SUBTYPES, sub.into()).unwrap_or("management")
    )
}

/// Information elements; returns the SSID if present.
fn elements(b: &mut Dec, p: Ix, off: usize, end: usize) -> Option<String> {
    let mut at = off;
    let mut ssid = None;
    let mut n = 0u32;
    while end.saturating_sub(at) >= 2 && n < 512 {
        let id = b.u8(at).unwrap_or(0);
        let len = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0));
        let body = at.saturating_add(2);
        let eend = body.saturating_add(len);
        if eend > end {
            b.data(p, "Truncated element", at, end);
            break;
        }
        let name = lookup(ELEMENTS, id.into()).unwrap_or("Unknown element");
        let e = b.group(p, name, at, eend.saturating_sub(at));
        b.enm(e, "Element ID", at, 1, ELEMENTS);
        b.num(e, "Length", at.saturating_add(1), 1);
        let s = element(b, e, id, body, eend);
        if id == 0 {
            ssid = Some(s.clone());
        }
        if !s.is_empty() {
            b.summary(e, || s);
        }
        at = eend;
        n = n.saturating_add(1);
    }
    if at < end {
        b.data(p, "Rest", at, end);
    }
    ssid
}

fn element(b: &mut Dec, e: Ix, id: u8, body: usize, end: usize) -> String {
    let len = end.saturating_sub(body);
    match id {
        0 => {
            let s = String::from_utf8_lossy(b.range(body, end)).into_owned();
            let shown = s.clone();
            b.text(e, "SSID", body, len, || shown);
            s
        }
        1 | 50 => {
            let mut rates = Vec::new();
            for i in 0..len {
                let v = b.u8(body.saturating_add(i)).unwrap_or(0);
                let r = u64::from(v & 0x7f);
                let s = format!(
                    "{}{}{}",
                    r / 2,
                    if r % 2 == 1 { ".5" } else { "" },
                    if v & 0x80 != 0 { " (basic)" } else { "" }
                );
                let shown = format!("{s} Mb/s");
                b.add(e, "Rate", body.saturating_add(i), 1, |n| {
                    n.value(crate::formats::util::val::hex(v, 8)).summary(shown)
                });
                rates.push(s);
            }
            format!("{} Mb/s", rates.join(", "))
        }
        3 if len == 1 => {
            let ch = b.num(e, "Current channel", body, 1).unwrap_or(0);
            format!("channel {ch}")
        }
        5 if len >= 4 => {
            b.num(e, "DTIM count", body, 1);
            let period = b
                .num(e, "DTIM period", body.saturating_add(1), 1)
                .unwrap_or(0);
            b.numx(e, "Bitmap control", body.saturating_add(2), 1);
            b.raw(
                e,
                "Partial virtual bitmap",
                body.saturating_add(3),
                len.saturating_sub(3),
            );
            format!("DTIM period {period}")
        }
        7 if len >= 3 => {
            let cc = String::from_utf8_lossy(b.range(body, body.saturating_add(2))).into_owned();
            let shown = cc.clone();
            b.text(e, "Country code", body, 2, || shown);
            b.num(e, "Environment", body.saturating_add(2), 1);
            let mut at = body.saturating_add(3);
            while at.saturating_add(3) <= end {
                let g = b.group(e, "Channel triplet", at, 3);
                let first = b.num(g, "First channel", at, 1).unwrap_or(0);
                let count = b
                    .num(g, "Number of channels", at.saturating_add(1), 1)
                    .unwrap_or(0);
                let power = b
                    .num(g, "Maximum transmit power (dBm)", at.saturating_add(2), 1)
                    .unwrap_or(0);
                b.summary(g, || format!("channels {first}+{count}, {power} dBm"));
                at = at.saturating_add(3);
            }
            b.data(e, "Padding", at, end);
            cc
        }
        48 if len >= 2 => rsn(b, e, body, end),
        42 if len == 1 => {
            b.flg(e, "Flags", body, 1, ERP_FLAGS);
            String::new()
        }
        61 if len >= 1 => {
            let ch = b.num(e, "Primary channel", body, 1).unwrap_or(0);
            b.raw(
                e,
                "HT operation information",
                body.saturating_add(1),
                len.saturating_sub(1),
            );
            format!("primary channel {ch}")
        }
        221 if len >= 3 => {
            let oui = b
                .bytes(body, 3)
                .map(crate::text::hex_lower)
                .unwrap_or_default();
            let shown = oui.clone();
            b.text(e, "OUI", body, 3, || shown);
            if len >= 4 {
                b.num(e, "Vendor type", body.saturating_add(3), 1);
                b.raw(e, "Data", body.saturating_add(4), len.saturating_sub(4));
            }
            format!("OUI {oui}")
        }
        255 if len >= 1 => {
            let ext = b.num(e, "Extension ID", body, 1).unwrap_or(0);
            b.raw(e, "Data", body.saturating_add(1), len.saturating_sub(1));
            format!("extension {ext}")
        }
        _ => {
            if len > 0 {
                b.raw(e, "Data", body, len);
            }
            String::new()
        }
    }
}

fn suite(b: &mut Dec, p: Ix, name: &'static str, at: usize, table: EnumTable) -> String {
    let oui = b
        .bytes(at, 3)
        .map(crate::text::hex_lower)
        .unwrap_or_default();
    let t = b.u8(at.saturating_add(3)).unwrap_or(0);
    let s = if oui == "000fac" {
        lookup(table, t.into()).map_or_else(|| format!("type {t}"), str::to_owned)
    } else {
        format!("{oui}:{t}")
    };
    let shown = s.clone();
    b.text(p, name, at, 4, || shown);
    s
}

fn rsn(b: &mut Dec, e: Ix, body: usize, end: usize) -> String {
    b.num(e, "Version", body, 2);
    let mut at = body.saturating_add(2);
    if at.saturating_add(4) > end {
        return String::new();
    }
    let group = suite(b, e, "Group cipher suite", at, CIPHER_SUITES);
    at = at.saturating_add(4);
    let mut pairwise = Vec::new();
    let mut akms = Vec::new();
    for (label, item, table, out) in [
        (
            "Pairwise cipher suite count",
            "Pairwise cipher suite",
            CIPHER_SUITES,
            &mut pairwise,
        ),
        ("AKM suite count", "AKM suite", AKM_SUITES, &mut akms),
    ] {
        let Some(n) = b.num(e, label, at, 2) else {
            break;
        };
        at = at.saturating_add(2);
        for _ in 0..n {
            if at.saturating_add(4) > end {
                break;
            }
            out.push(suite(b, e, item, at, table));
            at = at.saturating_add(4);
        }
    }
    if at.saturating_add(2) <= end {
        b.numx(e, "RSN capabilities", at, 2);
        at = at.saturating_add(2);
    }
    b.data(e, "Rest", at, end);
    format!(
        "group {group}, pairwise {}, AKM {}",
        pairwise.join("/"),
        akms.join("/")
    )
}
