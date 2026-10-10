//! Application protocols carried in one TCP segment or UDP datagram,
//! recognised by port and content: DNS (with mDNS and LLMNR, see
//! [`super::dns`]), TLS ([`super::tls`]), HTTP/1.x and SSDP, DHCP/BOOTP,
//! NTP, QUIC long headers, syslog, SNMP (as DER) and VXLAN.
//!
//! TCP streams are not reassembled: a message is decoded when it starts in
//! the segment, and whatever continues past the segment is marked as such.

use super::dec::{Dec, Ix, ipv4, mac};
use super::{dns, net, tls};
use crate::error::Diagnostic;
use crate::formats::util::fmt::{preview, size};
use crate::value::{EnumTable, FlagTable, flag, lookup};

/// Decodes a TCP payload; returns the end of what was accounted for.
pub fn tcp(b: &mut Dec, p: Ix, sp: u16, dp: u16, off: usize, end: usize) -> usize {
    // A datagram quoted by an ICMP error is cut short: no application layer.
    if !b.top() {
        return off;
    }
    let has = |port: u16| sp == port || dp == port;
    if has(53) || has(5353) {
        return dns::message(b, p, off, end, true, dns::Flavor::Dns);
    }
    if tls::looks_like(b, off) {
        return tls::records(b, p, off, end);
    }
    if http_start(b.range(off, end)) {
        return http(b, p, off, end, "HTTP");
    }
    off
}

/// Decodes a UDP payload; returns the end of what was accounted for.
pub fn udp(b: &mut Dec, p: Ix, sp: u16, dp: u16, off: usize, end: usize) -> usize {
    if !b.top() {
        return off;
    }
    let has = |port: u16| sp == port || dp == port;
    if has(53) {
        dns::message(b, p, off, end, false, dns::Flavor::Dns)
    } else if has(5353) {
        dns::message(b, p, off, end, false, dns::Flavor::Mdns)
    } else if has(5355) {
        dns::message(b, p, off, end, false, dns::Flavor::Llmnr)
    } else if has(67) || has(68) {
        dhcp(b, p, off, end)
    } else if has(123) {
        ntp(b, p, off, end)
    } else if has(514) {
        syslog(b, p, off, end)
    } else if has(161) || has(162) {
        snmp(b, p, off, end)
    } else if has(1900) && http_start(b.range(off, end)) {
        http(b, p, off, end, "SSDP")
    } else if has(4789) {
        vxlan(b, p, off, end)
    } else if (has(443) || has(4433) || has(8443)) && quic_long(b, off) {
        quic(b, p, off, end)
    } else {
        off
    }
}

// ---------------------------------------------------------------------------
// HTTP/1.x and SSDP

const METHODS: &[&[u8]] = &[
    b"GET ",
    b"POST ",
    b"HEAD ",
    b"PUT ",
    b"DELETE ",
    b"OPTIONS ",
    b"PATCH ",
    b"CONNECT ",
    b"TRACE ",
    b"PROPFIND ",
    b"M-SEARCH ",
    b"NOTIFY ",
    b"SUBSCRIBE ",
    b"PRI * HTTP/2",
];

fn http_start(d: &[u8]) -> bool {
    d.starts_with(b"HTTP/1.") || METHODS.iter().any(|m| d.starts_with(m))
}

/// The end of the line starting at `at` (index of `\n` + 1) within `end`.
fn line_end(d: &[u8], at: usize, end: usize) -> Option<usize> {
    let rest = d.get(at..end.min(d.len()))?;
    rest.iter()
        .position(|&c| c == b'\n')
        .map(|i| at.saturating_add(i).saturating_add(1))
}

fn trim_crlf(s: &[u8]) -> &[u8] {
    let s = s.strip_suffix(b"\n").unwrap_or(s);
    s.strip_suffix(b"\r").unwrap_or(s)
}

fn http(b: &mut Dec, p: Ix, off: usize, end: usize, proto: &'static str) -> usize {
    let d = b.d;
    let ix = b.group(p, proto, off, end.saturating_sub(off));
    let Some(first) = line_end(d, off, end) else {
        let s = String::from_utf8_lossy(b.range(off, end)).into_owned();
        b.text(
            ix,
            "Start line (incomplete)",
            off,
            end.saturating_sub(off),
            || s,
        );
        b.set_info(proto, || format!("{proto} (continued)"));
        return end;
    };
    let line = String::from_utf8_lossy(trim_crlf(b.range(off, first))).into_owned();
    let mut parts = line.splitn(3, ' ');
    let (a, m, c) = (
        parts.next().unwrap_or_default().to_owned(),
        parts.next().unwrap_or_default().to_owned(),
        parts.next().unwrap_or_default().to_owned(),
    );
    let response = a.starts_with("HTTP/");
    let l = b.text(
        ix,
        if response {
            "Status line"
        } else {
            "Request line"
        },
        off,
        first.saturating_sub(off),
        || line.clone(),
    );
    let info = if response {
        format!("{proto} {m} {c}")
    } else {
        format!("{proto} {a} {m}")
    };
    if b.building() {
        // Sub-fields at their exact offsets.
        let mut at = off;
        let names: [&'static str; 3] = if response {
            ["Version", "Status code", "Reason phrase"]
        } else {
            ["Method", "Target", "Version"]
        };
        for (name, val) in names.into_iter().zip([&a, &m, &c]) {
            let n = val.len();
            let v = val.clone();
            b.text(l, name, at, n, || v);
            at = at.saturating_add(n).saturating_add(1);
        }
    }
    // Header fields up to the empty line.
    let mut at = first;
    let mut content_length: Option<usize> = None;
    let mut chunked = false;
    let mut content_type = String::new();
    let mut headers = 0u32;
    let mut complete = false;
    let hdr = b.group(ix, "Header fields", first, 0);
    while let Some(next) = line_end(d, at, end) {
        let raw = trim_crlf(b.range(at, next));
        if raw.is_empty() {
            b.add(ix, "End of header", at, next.saturating_sub(at), |n| n);
            at = next;
            complete = true;
            break;
        }
        let text = String::from_utf8_lossy(raw).into_owned();
        let (name, value) = match text.split_once(':') {
            Some((n, v)) => (n.trim().to_owned(), v.trim().to_owned()),
            None => (String::new(), text.trim().to_owned()),
        };
        let lname = name.to_ascii_lowercase();
        match lname.as_str() {
            "content-length" => content_length = value.parse().ok(),
            "transfer-encoding" => chunked |= value.to_ascii_lowercase().contains("chunked"),
            "content-type" => content_type = value.clone(),
            _ => {}
        }
        if b.building() {
            let label = if name.is_empty() {
                "Header".to_owned()
            } else {
                name
            };
            b.text(hdr, label, at, next.saturating_sub(at), || value);
        }
        headers = headers.saturating_add(1);
        at = next;
    }
    let hspan = b.sp(first, at.saturating_sub(first));
    b.update(hdr, |n| n.span(hspan));
    b.summary(hdr, || crate::formats::util::fmt::plural(headers, "field"));
    if !complete {
        b.diag(
            ix,
            Diagnostic::note(
                "the header continues in a later segment (TCP reassembly is not implemented)",
            ),
        );
        if at < end {
            b.data(ix, "Partial header line", at, end);
        }
        b.summary(ix, || line.clone());
        b.set_info(proto, || info);
        return end;
    }
    // The body, when this segment holds it.
    if at < end {
        let have = end.saturating_sub(at);
        match content_length {
            Some(n) if n <= have && n > 0 && !chunked => {
                let span = b.sp(at, n);
                let node = crate::formats::embedded("Body", b.input.nested(span));
                let ct = content_type.clone();
                if b.building() {
                    b.push_node(ix, node.summary(format!("{}, {}", size(n as u64), ct)));
                }
                at = at.saturating_add(n);
            }
            _ => {
                let note = if chunked {
                    "chunked transfer coding (not decoded)".to_owned()
                } else if let Some(n) = content_length {
                    format!(
                        "{} of {} (the rest is in later segments)",
                        size(have as u64),
                        size(n as u64)
                    )
                } else {
                    size(have as u64)
                };
                b.add(ix, "Body", at, have, |n| n.summary(note));
                at = end;
            }
        }
    } else if content_length.is_some_and(|n| n > 0) {
        b.diag(ix, Diagnostic::note("the body follows in later segments"));
    }
    let shown = line.clone();
    b.summary(ix, || shown);
    b.set_info(proto, || {
        if content_type.is_empty() {
            info
        } else {
            format!(
                "{info} ({})",
                content_type.split(';').next().unwrap_or_default()
            )
        }
    });
    at
}

// ---------------------------------------------------------------------------
// DHCP / BOOTP

const BOOTP_OPS: EnumTable = &[(1, "BOOTREQUEST"), (2, "BOOTREPLY")];
const BOOTP_FLAGS: FlagTable = &[flag(0x8000, "BROADCAST")];

const DHCP_MESSAGES: EnumTable = &[
    (1, "Discover"),
    (2, "Offer"),
    (3, "Request"),
    (4, "Decline"),
    (5, "ACK"),
    (6, "NAK"),
    (7, "Release"),
    (8, "Inform"),
    (9, "Force renew"),
    (10, "Lease query"),
    (11, "Lease unassigned"),
    (12, "Lease unknown"),
    (13, "Lease active"),
];

const DHCP_OPTIONS: EnumTable = &[
    (0, "Pad"),
    (1, "Subnet mask"),
    (2, "Time offset"),
    (3, "Router"),
    (4, "Time server"),
    (5, "Name server"),
    (6, "Domain name server"),
    (7, "Log server"),
    (12, "Host name"),
    (13, "Boot file size"),
    (15, "Domain name"),
    (16, "Swap server"),
    (17, "Root path"),
    (19, "IP forwarding"),
    (23, "Default IP TTL"),
    (26, "Interface MTU"),
    (28, "Broadcast address"),
    (31, "Perform router discovery"),
    (33, "Static route"),
    (35, "ARP cache timeout"),
    (40, "NIS domain"),
    (41, "NIS servers"),
    (42, "NTP servers"),
    (43, "Vendor-specific information"),
    (44, "NetBIOS name server"),
    (46, "NetBIOS node type"),
    (47, "NetBIOS scope"),
    (50, "Requested IP address"),
    (51, "IP address lease time"),
    (52, "Option overload"),
    (53, "DHCP message type"),
    (54, "Server identifier"),
    (55, "Parameter request list"),
    (56, "Message"),
    (57, "Maximum DHCP message size"),
    (58, "Renewal time (T1)"),
    (59, "Rebinding time (T2)"),
    (60, "Vendor class identifier"),
    (61, "Client identifier"),
    (66, "TFTP server name"),
    (67, "Boot file name"),
    (77, "User class"),
    (80, "Rapid commit"),
    (81, "Client FQDN"),
    (82, "Relay agent information"),
    (90, "Authentication"),
    (93, "Client system architecture"),
    (94, "Client network interface identifier"),
    (97, "Client machine identifier"),
    (108, "IPv6-only preferred"),
    (114, "Captive portal"),
    (116, "Auto-configure"),
    (118, "Subnet selection"),
    (119, "Domain search"),
    (121, "Classless static route"),
    (125, "Vendor-identifying vendor-specific information"),
    (150, "TFTP server address"),
    (249, "Classless static route (Microsoft)"),
    (252, "Web proxy auto-discovery"),
    (255, "End"),
];

fn dhcp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 236 {
        return off;
    }
    let ix = b.group(p, "DHCP", off, end.saturating_sub(off));
    let op = b.enm(ix, "Message op", off, 1, BOOTP_OPS).unwrap_or(0);
    b.enm(
        ix,
        "Hardware type",
        off.saturating_add(1),
        1,
        &[(1, "Ethernet"), (6, "IEEE 802"), (32, "InfiniBand")],
    );
    let hlen = b
        .num(ix, "Hardware address length", off.saturating_add(2), 1)
        .unwrap_or(0);
    b.num(ix, "Hops", off.saturating_add(3), 1);
    let xid = b
        .numx(ix, "Transaction ID", off.saturating_add(4), 4)
        .unwrap_or(0);
    b.num(ix, "Seconds elapsed", off.saturating_add(8), 2);
    b.flg(ix, "Flags", off.saturating_add(10), 2, BOOTP_FLAGS);
    b.ip4(ix, "Client IP address", off.saturating_add(12));
    let yi = b.ip4(ix, "Your IP address", off.saturating_add(16));
    b.ip4(ix, "Next server IP address", off.saturating_add(20));
    b.ip4(ix, "Relay agent IP address", off.saturating_add(24));
    let ch = off.saturating_add(28);
    let n = usize::try_from(hlen.min(16)).unwrap_or(16);
    let chaddr = if hlen == 6 {
        b.bytes(ch, 6).map(mac).unwrap_or_default()
    } else {
        b.bytes(ch, n)
            .map(crate::text::hex_lower)
            .unwrap_or_default()
    };
    let shown = chaddr.clone();
    b.text(ix, "Client hardware address", ch, 16, || shown);
    let sname = cstring(b.range(off.saturating_add(44), off.saturating_add(108)));
    b.text(ix, "Server host name", off.saturating_add(44), 64, || sname);
    let file = cstring(b.range(off.saturating_add(108), off.saturating_add(236)));
    b.text(ix, "Boot file name", off.saturating_add(108), 128, || file);
    let mut at = off.saturating_add(236);
    let mut kind = None;
    if b.be32(at) == Some(0x6382_5363) {
        b.numx(ix, "Magic cookie", at, 4);
        b.tail(|n| n.summary("DHCP"));
        at = at.saturating_add(4);
        let (k, used) = dhcp_options(b, ix, at, end);
        kind = k;
        at = used;
    }
    b.data(ix, "Padding", at, end);
    let what = match kind {
        Some(k) => format!("DHCP {}", lookup(DHCP_MESSAGES, k).unwrap_or("message")),
        None => format!("BOOTP {}", lookup(BOOTP_OPS, op).unwrap_or("message")),
    };
    let your = yi
        .filter(|a| a != &[0; 4])
        .map(|a| format!(", your address {}", ipv4(&a)));
    let shown = format!(
        "{what}, transaction {xid:#010x}, client {chaddr}{}",
        your.unwrap_or_default()
    );
    let s2 = shown.clone();
    b.summary(ix, || s2);
    b.set_info("DHCP", || format!("{what} - Transaction ID {xid:#010x}"));
    end
}

fn cstring(d: &[u8]) -> String {
    let n = d.iter().position(|&c| c == 0).unwrap_or(d.len());
    String::from_utf8_lossy(d.get(..n).unwrap_or_default()).into_owned()
}

/// DHCP options; returns the message type and the end of the options.
fn dhcp_options(b: &mut Dec, p: Ix, off: usize, end: usize) -> (Option<u64>, usize) {
    let ix = b.group(p, "Options", off, end.saturating_sub(off));
    let mut at = off;
    let mut kind = None;
    let mut count = 0u32;
    while at < end {
        let code = b.u8(at).unwrap_or(0);
        if code == 0 {
            let start = at;
            while at < end && b.u8(at) == Some(0) {
                at = at.saturating_add(1);
            }
            b.add(ix, "Pad", start, at.saturating_sub(start), |n| n);
            continue;
        }
        let name = lookup(DHCP_OPTIONS, code.into()).unwrap_or("Unknown option");
        if code == 255 {
            b.enm(ix, "End", at, 1, DHCP_OPTIONS);
            at = at.saturating_add(1);
            break;
        }
        let len = usize::from(b.u8(at.saturating_add(1)).unwrap_or(0));
        let body = at.saturating_add(2);
        let oend = body.saturating_add(len);
        if oend > end {
            b.diag(
                ix,
                Diagnostic::malformed(format!("option {code} overruns the message")),
            );
            b.data(ix, "Rest", at, end);
            return (kind, end);
        }
        count = count.saturating_add(1);
        let o = b.group(ix, name, at, oend.saturating_sub(at));
        b.enm(o, "Option", at, 1, DHCP_OPTIONS);
        b.num(o, "Length", at.saturating_add(1), 1);
        let value = dhcp_option(b, o, code, body, len);
        if code == 53 {
            kind = b.u8(body).map(u64::from);
        }
        b.summary(o, || value);
        at = oend;
    }
    b.summary(ix, || crate::formats::util::fmt::plural(count, "option"));
    let span = b.sp(off, at.saturating_sub(off));
    b.update(ix, |n| n.span(span));
    (kind, at)
}

/// Decodes one option value under `o`; returns its one-line rendering.
fn dhcp_option(b: &mut Dec, o: Ix, code: u8, body: usize, len: usize) -> String {
    let vend = body.saturating_add(len);
    match code {
        53 if len == 1 => {
            let v = b.enm(o, "Value", body, 1, DHCP_MESSAGES).unwrap_or(0);
            lookup(DHCP_MESSAGES, v).unwrap_or("unknown").to_owned()
        }
        1 | 16 | 28 | 32 | 50 | 54 | 118 if len == 4 => b
            .ip4(o, "Address", body)
            .map(|a| ipv4(&a))
            .unwrap_or_default(),
        3..=11 | 41 | 42 | 44 | 45 | 48 | 49 | 150 if len.is_multiple_of(4) => {
            let mut list = Vec::new();
            let mut a = body;
            while a.saturating_add(4) <= vend {
                if let Some(x) = b.ip4(o, "Address", a) {
                    list.push(ipv4(&x));
                }
                a = a.saturating_add(4);
            }
            list.join(", ")
        }
        51 | 58 | 59 | 35 if len == 4 => {
            let v = b.num(o, "Seconds", body, 4).unwrap_or(0);
            if v == u64::from(u32::MAX) {
                "infinite".to_owned()
            } else {
                format!("{v} s")
            }
        }
        2 if len == 4 => {
            let v = b.u32(body).unwrap_or(0) as i32;
            b.add(o, "Offset (s)", body, 4, |n| {
                n.value(crate::formats::util::val::int(i64::from(v), 32))
            });
            format!("{v} s")
        }
        13 | 22 | 26 | 57 if len == 2 => {
            let v = b.num(o, "Value", body, 2).unwrap_or(0);
            v.to_string()
        }
        19 | 23 | 31 | 46 | 52 | 80 | 116 if len <= 1 => {
            if len == 1 {
                b.num(o, "Value", body, 1).unwrap_or(0).to_string()
            } else {
                "set".to_owned()
            }
        }
        12 | 14 | 15 | 17 | 18 | 40 | 47 | 56 | 60 | 64 | 66 | 67 | 114 | 252 => {
            let s = String::from_utf8_lossy(b.range(body, vend)).into_owned();
            let shown = s.clone();
            b.text(o, "Value", body, len, || shown);
            s
        }
        55 => {
            let mut names = Vec::new();
            for i in 0..len {
                let at = body.saturating_add(i);
                let c = b.enm(o, "Parameter", at, 1, DHCP_OPTIONS).unwrap_or(0);
                names.push(lookup(DHCP_OPTIONS, c).map_or_else(|| c.to_string(), str::to_owned));
            }
            names.join(", ")
        }
        61 if len >= 1 => {
            let t = b.num(o, "Type", body, 1).unwrap_or(0);
            let rest = b.range(body.saturating_add(1), vend);
            let s = if t == 1 && rest.len() == 6 {
                mac(rest)
            } else {
                crate::text::hex_lower(rest)
            };
            let shown = s.clone();
            b.text(
                o,
                "Identifier",
                body.saturating_add(1),
                len.saturating_sub(1),
                || shown,
            );
            s
        }
        81 if len >= 3 => {
            b.numx(o, "Flags", body, 1);
            b.num(o, "A-RR result", body.saturating_add(1), 1);
            b.num(o, "PTR-RR result", body.saturating_add(2), 1);
            let s = String::from_utf8_lossy(b.range(body.saturating_add(3), vend)).into_owned();
            let shown = s.clone();
            b.text(
                o,
                "Name",
                body.saturating_add(3),
                len.saturating_sub(3),
                || shown,
            );
            s
        }
        119 => {
            // DNS names, possibly compressed against this option.
            let data = b.range(body, vend);
            let mut names = Vec::new();
            let mut a = 0usize;
            while a < data.len() && names.len() < 64 {
                match dns::name_at(data, a) {
                    Some((name, next)) if next > a => {
                        let shown = name.clone();
                        b.text(
                            o,
                            "Domain",
                            body.saturating_add(a),
                            next.saturating_sub(a),
                            || shown,
                        );
                        names.push(name);
                        a = next;
                    }
                    _ => break,
                }
            }
            names.join(", ")
        }
        121 | 249 => {
            let mut a = body;
            let mut routes = Vec::new();
            while a < vend {
                let width = usize::from(b.u8(a).unwrap_or(0));
                let octets = width.div_ceil(8);
                let rlen = 1usize.saturating_add(octets).saturating_add(4);
                if width > 32 || a.saturating_add(rlen) > vend {
                    b.data(o, "Rest", a, vend);
                    break;
                }
                let mut net = [0u8; 4];
                for (i, slot) in net.iter_mut().enumerate().take(octets) {
                    *slot = b.u8(a.saturating_add(1).saturating_add(i)).unwrap_or(0);
                }
                let gw = b
                    .bytes(a.saturating_add(1).saturating_add(octets), 4)
                    .map(ipv4)
                    .unwrap_or_default();
                let r = format!("{}/{width} via {gw}", ipv4(&net));
                let shown = r.clone();
                b.text(o, "Route", a, rlen, || shown);
                routes.push(r);
                a = a.saturating_add(rlen);
            }
            routes.join(", ")
        }
        _ => {
            b.raw(o, "Value", body, len);
            size(len as u64)
        }
    }
}

// ---------------------------------------------------------------------------
// NTP

const NTP_MODES: EnumTable = &[
    (0, "reserved"),
    (1, "symmetric active"),
    (2, "symmetric passive"),
    (3, "client"),
    (4, "server"),
    (5, "broadcast"),
    (6, "control"),
    (7, "private"),
];

const NTP_LEAP: EnumTable = &[
    (0, "no warning"),
    (1, "last minute has 61 seconds"),
    (2, "last minute has 59 seconds"),
    (3, "unsynchronized"),
];

/// Seconds from 1900-01-01 (the NTP era 0 epoch) to the Unix epoch.
const NTP_UNIX: u64 = 2_208_988_800;

fn ntp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 48 {
        return off;
    }
    let ix = b.group(p, "NTP", off, end.saturating_sub(off));
    let first = b.u8(off).unwrap_or(0);
    let (li, vn, mode) = (first >> 6, (first >> 3) & 7, first & 7);
    b.numx(ix, "Leap / version / mode", off, 1);
    b.tail(|n| {
        n.summary(format!(
            "leap {} ({}), version {vn}, mode {mode} ({})",
            li,
            lookup(NTP_LEAP, li.into()).unwrap_or("?"),
            lookup(NTP_MODES, mode.into()).unwrap_or("?")
        ))
    });
    let stratum = b.num(ix, "Stratum", off.saturating_add(1), 1).unwrap_or(0);
    b.tail(|n| {
        n.summary(match stratum {
            0 => "unspecified or kiss-o'-death".to_owned(),
            1 => "primary reference".to_owned(),
            2..=15 => "secondary reference".to_owned(),
            16 => "unsynchronized".to_owned(),
            _ => "reserved".to_owned(),
        })
    });
    let poll = b.u8(off.saturating_add(2)).unwrap_or(0) as i8;
    b.add(ix, "Poll interval", off.saturating_add(2), 1, |n| {
        n.value(crate::formats::util::val::int(i64::from(poll), 8))
            .summary(format!("2^{poll} s"))
    });
    let prec = b.u8(off.saturating_add(3)).unwrap_or(0) as i8;
    b.add(ix, "Precision", off.saturating_add(3), 1, |n| {
        n.value(crate::formats::util::val::int(i64::from(prec), 8))
            .summary(format!("2^{prec} s"))
    });
    for (i, name) in ["Root delay", "Root dispersion"].into_iter().enumerate() {
        let at = off.saturating_add(4).saturating_add(i.saturating_mul(4));
        let v = b.numx(ix, name, at, 4).unwrap_or(0);
        let secs = v as f64 / 65536.0;
        b.tail(|n| n.summary(format!("{secs:.6} s")));
    }
    let rid = off.saturating_add(12);
    let refid = b.bytes(rid, 4).unwrap_or_default().to_vec();
    let rtext = if stratum <= 1 {
        String::from_utf8_lossy(&refid)
            .trim_end_matches('\0')
            .to_owned()
    } else {
        ipv4(&refid)
    };
    let shown = rtext.clone();
    b.text(ix, "Reference ID", rid, 4, || shown);
    for (i, name) in [
        "Reference timestamp",
        "Origin timestamp",
        "Receive timestamp",
        "Transmit timestamp",
    ]
    .into_iter()
    .enumerate()
    {
        let at = off.saturating_add(16).saturating_add(i.saturating_mul(8));
        ntp_time(b, ix, name, at);
    }
    let mut at = off.saturating_add(48);
    if end.saturating_sub(at) >= 4 {
        // Extension fields (v4) or a MAC (key ID + digest).
        let rest = end.saturating_sub(at);
        if rest == 20 || rest == 24 {
            b.num(ix, "Key ID", at, 4);
            b.raw(
                ix,
                "Message digest",
                at.saturating_add(4),
                rest.saturating_sub(4),
            );
            at = end;
        } else {
            at = b.data(ix, "Extension fields", at, end);
        }
    }
    let m = lookup(NTP_MODES, mode.into()).unwrap_or("?");
    b.summary(ix, || {
        format!("version {vn}, {m}, stratum {stratum}, reference {rtext}")
    });
    b.set_info("NTP", || format!("NTP version {vn}, {m}"));
    at.max(off.saturating_add(48))
}

fn ntp_time(b: &mut Dec, p: Ix, name: &'static str, at: usize) {
    let secs = b.be32(at).map(u64::from);
    let frac = b.be32(at.saturating_add(4)).map(u64::from);
    let (Some(secs), Some(frac)) = (secs, frac) else {
        b.truncated(p, name, at, 8);
        return;
    };
    if secs == 0 && frac == 0 {
        b.add(p, name, at, 8, |n| {
            n.value(crate::formats::util::val::hex(0u64, 64))
                .summary("unset")
        });
        return;
    }
    // Era 0 until 2036; values below 1968 are taken as era 1.
    let era = if secs < 0x8000_0000 { 1u64 << 32 } else { 0 };
    let unix = secs.saturating_add(era).saturating_sub(NTP_UNIX);
    let nanos = frac.saturating_mul(1_000_000_000) >> 32;
    let unix = i64::try_from(unix).unwrap_or(0);
    let text = super::time_text(unix, nanos, 9);
    b.add(p, name, at, 8, |n| {
        n.value(crate::value::Value::Timestamp { unix_seconds: unix })
            .summary(text)
    });
}

// ---------------------------------------------------------------------------
// Syslog, SNMP, VXLAN

const SYSLOG_FACILITIES: EnumTable = &[
    (0, "kern"),
    (1, "user"),
    (2, "mail"),
    (3, "daemon"),
    (4, "auth"),
    (5, "syslog"),
    (6, "lpr"),
    (7, "news"),
    (8, "uucp"),
    (9, "cron"),
    (10, "authpriv"),
    (11, "ftp"),
    (12, "ntp"),
    (13, "security"),
    (14, "console"),
    (15, "solaris-cron"),
    (16, "local0"),
    (17, "local1"),
    (18, "local2"),
    (19, "local3"),
    (20, "local4"),
    (21, "local5"),
    (22, "local6"),
    (23, "local7"),
];

const SYSLOG_SEVERITIES: EnumTable = &[
    (0, "emerg"),
    (1, "alert"),
    (2, "crit"),
    (3, "err"),
    (4, "warning"),
    (5, "notice"),
    (6, "info"),
    (7, "debug"),
];

fn syslog(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let d = b.range(off, end);
    if d.first() != Some(&b'<') {
        return off;
    }
    let Some(close) = d.iter().take(5).position(|&c| c == b'>') else {
        return off;
    };
    let Some(pri) = std::str::from_utf8(d.get(1..close).unwrap_or_default())
        .ok()
        .and_then(|s| s.parse::<u64>().ok())
    else {
        return off;
    };
    let ix = b.group(p, "Syslog", off, end.saturating_sub(off));
    let (fac, sev) = (pri >> 3, pri & 7);
    let (f, s) = (
        lookup(SYSLOG_FACILITIES, fac).unwrap_or("?"),
        lookup(SYSLOG_SEVERITIES, sev).unwrap_or("?"),
    );
    b.add(ix, "Priority", off, close.saturating_add(1), |n| {
        n.value(crate::formats::util::val::uint(pri, 8))
            .summary(format!("{f}.{s}"))
    });
    let body = off.saturating_add(close).saturating_add(1);
    let msg = String::from_utf8_lossy(b.range(body, end)).into_owned();
    let msg = msg.trim_end_matches(['\n', '\r', '\0']).to_owned();
    let shown = msg.clone();
    b.text(ix, "Message", body, end.saturating_sub(body), || shown);
    let short = preview(&msg, 80);
    let s2 = short.clone();
    b.summary(ix, || format!("{f}.{s}: {s2}"));
    b.set_info("Syslog", || format!("Syslog {f}.{s}: {short}"));
    end
}

const SNMP_PDUS: EnumTable = &[
    (0xa0, "get-request"),
    (0xa1, "get-next-request"),
    (0xa2, "get-response"),
    (0xa3, "set-request"),
    (0xa4, "trap (v1)"),
    (0xa5, "get-bulk-request"),
    (0xa6, "inform-request"),
    (0xa7, "trap (v2)"),
    (0xa8, "report"),
];

/// A BER TLV at `r`: tag, content offset and length.
fn tlv(d: &[u8], r: usize) -> Option<(u8, usize, usize)> {
    let tag = *d.get(r)?;
    let l0 = *d.get(r.checked_add(1)?)?;
    let (len, hdr) = if l0 < 0x80 {
        (usize::from(l0), 2usize)
    } else {
        let n = usize::from(l0 & 0x7f);
        if n == 0 || n > 3 {
            return None;
        }
        let mut v = 0usize;
        for i in 0..n {
            v = v << 8 | usize::from(*d.get(r.checked_add(2)?.checked_add(i)?)?);
        }
        (v, n.checked_add(2)?)
    };
    Some((tag, r.checked_add(hdr)?, len))
}

fn snmp(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let d = b.range(off, end);
    if d.first() != Some(&0x30) {
        return off;
    }
    // A light look at SEQUENCE { version, community, PDU } for the summary;
    // the whole message is shown by the DER dissector.
    let mut summary = String::from("SNMP");
    if let Some((_, start, _)) = tlv(d, 0)
        && let Some((0x02, vs, vl)) = tlv(d, start)
    {
        let ver = d
            .get(vs..vs.saturating_add(vl))
            .and_then(|x| x.last())
            .copied();
        if let Some((0x04, cs, cl)) = tlv(d, vs.saturating_add(vl)) {
            let community =
                String::from_utf8_lossy(d.get(cs..cs.saturating_add(cl)).unwrap_or_default())
                    .into_owned();
            let pdu = tlv(d, cs.saturating_add(cl))
                .map(|(t, _, _)| t)
                .unwrap_or(0);
            summary = format!(
                "SNMP{} {}, community {community:?}",
                match ver {
                    Some(0) => "v1",
                    Some(1) => "v2c",
                    Some(3) => "v3",
                    _ => "",
                },
                lookup(SNMP_PDUS, pdu.into()).unwrap_or("message")
            );
        }
    }
    let span = b.sp(off, end.saturating_sub(off));
    let node =
        crate::formats::embedded_as("SNMP", b.input.nested(span), &crate::formats::asn1::DER);
    let shown = summary.clone();
    b.add(p, "SNMP", off, end.saturating_sub(off), |_| {
        node.summary(shown)
    });
    b.set_info("SNMP", || summary);
    end
}

const VXLAN_FLAGS: FlagTable = &[flag(0x08, "VNI_VALID")];

fn vxlan(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    if end.saturating_sub(off) < 8 {
        return off;
    }
    let ix = b.group(p, "VXLAN", off, 8);
    b.flg(ix, "Flags", off, 1, VXLAN_FLAGS);
    b.raw(ix, "Reserved", off.saturating_add(1), 3);
    let vni = b.be32(off.saturating_add(4)).unwrap_or(0) >> 8;
    b.add(
        ix,
        "VXLAN network identifier",
        off.saturating_add(4),
        3,
        |n| n.value(crate::formats::util::val::uint(vni, 24)),
    );
    b.num(ix, "Reserved", off.saturating_add(7), 1);
    b.summary(ix, || format!("VNI {vni}"));
    b.set_info("VXLAN", || format!("VXLAN VNI {vni}"));
    net::ethernet(b, p, off.saturating_add(8), end).max(off.saturating_add(8))
}

// ---------------------------------------------------------------------------
// QUIC

const QUIC_VERSIONS: EnumTable = &[
    (0, "version negotiation"),
    (1, "QUIC v1"),
    (0x6b33_43cf, "QUIC v2"),
    (0xff00_001d, "draft-29"),
    (0xff00_0020, "draft-32"),
    (0xff00_0022, "draft-34"),
    (0x5130_3530, "Google Q050"),
    (0x5430_3531, "Google T051"),
];

fn quic_long(b: &Dec, off: usize) -> bool {
    let first = b.u8(off).unwrap_or(0);
    let version = b.be32(off.saturating_add(1)).unwrap_or(0);
    first & 0x80 != 0 && (version == 0 || lookup(QUIC_VERSIONS, version.into()).is_some())
}

/// A variable-length integer: value and length.
fn varint(b: &Dec, at: usize) -> Option<(u64, usize)> {
    let first = b.u8(at)?;
    let len = 1usize << (first >> 6);
    let mut v = u64::from(first & 0x3f);
    for i in 1..len {
        v = v << 8 | u64::from(b.u8(at.checked_add(i)?)?);
    }
    Some((v, len))
}

fn quic(b: &mut Dec, p: Ix, off: usize, end: usize) -> usize {
    let mut at = off;
    let mut infos = Vec::new();
    // Coalesced packets.
    for _ in 0..8 {
        if end.saturating_sub(at) < 7 || !quic_long(b, at) {
            break;
        }
        let start = at;
        let first = b.u8(at).unwrap_or(0);
        let version = b.be32(at.saturating_add(1)).unwrap_or(0);
        let v2 = version == 0x6b33_43cf;
        let kind = (first >> 4) & 3;
        let tname = match (version, v2, kind) {
            (0, _, _) => "Version negotiation",
            (_, false, 0) | (_, true, 1) => "Initial",
            (_, false, 1) | (_, true, 2) => "0-RTT",
            (_, false, 2) | (_, true, 3) => "Handshake",
            _ => "Retry",
        };
        let ix = b.group(p, "QUIC long header packet", at, end.saturating_sub(at));
        b.numx(ix, "Header form / type", at, 1);
        b.tail(|n| n.summary(format!("long header, {tname} (low bits are protected)")));
        b.enm(ix, "Version", at.saturating_add(1), 4, QUIC_VERSIONS);
        at = at.saturating_add(5);
        let dlen = usize::from(b.u8(at).unwrap_or(0));
        b.num(ix, "Destination connection ID length", at, 1);
        let dcid = crate::text::hex_lower(b.range(
            at.saturating_add(1),
            at.saturating_add(1).saturating_add(dlen),
        ));
        b.raw(ix, "Destination connection ID", at.saturating_add(1), dlen);
        at = at.saturating_add(1).saturating_add(dlen);
        let slen = usize::from(b.u8(at).unwrap_or(0));
        b.num(ix, "Source connection ID length", at, 1);
        if slen > 0 {
            b.raw(ix, "Source connection ID", at.saturating_add(1), slen);
        }
        at = at.saturating_add(1).saturating_add(slen);
        let mut pend = end;
        if version == 0 {
            while end.saturating_sub(at) >= 4 {
                b.enm(ix, "Supported version", at, 4, QUIC_VERSIONS);
                at = at.saturating_add(4);
            }
        } else if tname == "Retry" {
            let tag = end.saturating_sub(16).max(at);
            b.raw(ix, "Retry token", at, tag.saturating_sub(at));
            b.raw(ix, "Retry integrity tag", tag, end.saturating_sub(tag));
            at = end;
        } else {
            if tname == "Initial"
                && let Some((tl, n)) = varint(b, at)
            {
                {
                    b.add(ix, "Token length", at, n, |x| {
                        x.value(crate::formats::util::val::uint(tl, 64))
                    });
                    at = at.saturating_add(n);
                    let tl = usize::try_from(tl)
                        .unwrap_or(usize::MAX)
                        .min(end.saturating_sub(at));
                    if tl > 0 {
                        b.raw(ix, "Token", at, tl);
                    }
                    at = at.saturating_add(tl);
                }
            }
            if let Some((len, n)) = varint(b, at) {
                b.add(ix, "Length", at, n, |x| {
                    x.value(crate::formats::util::val::uint(len, 64))
                        .summary("packet number and payload")
                });
                at = at.saturating_add(n);
                pend = at
                    .saturating_add(usize::try_from(len).unwrap_or(usize::MAX))
                    .min(end);
            }
            b.add(ix, "Protected payload", at, pend.saturating_sub(at), |x| {
                x.summary(format!(
                    "{}, packet number and frames under header and packet protection",
                    size(pend.saturating_sub(at) as u64)
                ))
            });
            at = pend;
        }
        let span = b.sp(start, at.saturating_sub(start));
        b.update(ix, |n| n.span(span));
        let vname = lookup(QUIC_VERSIONS, version.into()).unwrap_or("unknown version");
        let s = format!("{tname}, {vname}, DCID={dcid}");
        let shown = s.clone();
        b.summary(ix, || shown);
        infos.push(s);
        if at <= start {
            break;
        }
    }
    if at > off {
        b.set_info("QUIC", || format!("QUIC {}", infos.join("; ")));
        if at < end {
            b.data(p, "Padding or short-header packet", at, end);
        }
        return end;
    }
    off
}
