//! DNS messages (RFC 1035) over UDP and TCP, and the same wire format as
//! Multicast DNS (RFC 6762) and LLMNR (RFC 4795): header and flags,
//! questions, and resource records with name compression, decoded for the
//! common types (A, AAAA, CNAME, NS, PTR, MX, TXT, SOA, SRV, CAA, OPT with
//! EDNS options, SVCB/HTTPS with service parameters, DS, DNSKEY, RRSIG, …).

use super::dec::{Dec, Ix, ipv4, ipv6};
use crate::error::Diagnostic;
use crate::value::{EnumTable, FlagTable, field, flag, lookup};

#[derive(Clone, Copy, PartialEq, Eq)]
pub enum Flavor {
    Dns,
    Mdns,
    Llmnr,
}

pub const TYPES: EnumTable = &[
    (1, "A"),
    (2, "NS"),
    (5, "CNAME"),
    (6, "SOA"),
    (12, "PTR"),
    (13, "HINFO"),
    (15, "MX"),
    (16, "TXT"),
    (17, "RP"),
    (18, "AFSDB"),
    (24, "SIG"),
    (25, "KEY"),
    (28, "AAAA"),
    (29, "LOC"),
    (33, "SRV"),
    (35, "NAPTR"),
    (36, "KX"),
    (37, "CERT"),
    (39, "DNAME"),
    (41, "OPT"),
    (42, "APL"),
    (43, "DS"),
    (44, "SSHFP"),
    (45, "IPSECKEY"),
    (46, "RRSIG"),
    (47, "NSEC"),
    (48, "DNSKEY"),
    (49, "DHCID"),
    (50, "NSEC3"),
    (51, "NSEC3PARAM"),
    (52, "TLSA"),
    (53, "SMIMEA"),
    (55, "HIP"),
    (59, "CDS"),
    (60, "CDNSKEY"),
    (61, "OPENPGPKEY"),
    (62, "CSYNC"),
    (63, "ZONEMD"),
    (64, "SVCB"),
    (65, "HTTPS"),
    (99, "SPF"),
    (108, "EUI48"),
    (109, "EUI64"),
    (249, "TKEY"),
    (250, "TSIG"),
    (251, "IXFR"),
    (252, "AXFR"),
    (255, "ANY"),
    (256, "URI"),
    (257, "CAA"),
];

const CLASSES: EnumTable = &[(1, "IN"), (3, "CH"), (4, "HS"), (254, "NONE"), (255, "ANY")];

const OPCODES: EnumTable = &[
    (0, "QUERY"),
    (1, "IQUERY"),
    (2, "STATUS"),
    (4, "NOTIFY"),
    (5, "UPDATE"),
    (6, "DSO"),
];

const RCODES: EnumTable = &[
    (0, "No error"),
    (1, "Format error"),
    (2, "Server failure"),
    (3, "No such name"),
    (4, "Not implemented"),
    (5, "Refused"),
    (6, "Name exists"),
    (7, "RR set exists"),
    (8, "RR set does not exist"),
    (9, "Not authoritative"),
    (10, "Not in zone"),
    (16, "Bad OPT version"),
    (17, "Bad key"),
    (18, "Bad time"),
    (19, "Bad mode"),
    (20, "Bad name"),
    (21, "Bad algorithm"),
    (22, "Bad truncation"),
    (23, "Bad cookie"),
];

const FLAGS: FlagTable = &[
    flag(0x8000, "QR"),
    field(0x7800, 0x0800, "OPCODE=IQUERY"),
    field(0x7800, 0x1000, "OPCODE=STATUS"),
    field(0x7800, 0x2000, "OPCODE=NOTIFY"),
    field(0x7800, 0x2800, "OPCODE=UPDATE"),
    flag(0x0400, "AA"),
    flag(0x0200, "TC"),
    flag(0x0100, "RD"),
    flag(0x0080, "RA"),
    flag(0x0040, "Z"),
    flag(0x0020, "AD"),
    flag(0x0010, "CD"),
    field(0x000f, 0x0001, "RCODE=FORMERR"),
    field(0x000f, 0x0002, "RCODE=SERVFAIL"),
    field(0x000f, 0x0003, "RCODE=NXDOMAIN"),
    field(0x000f, 0x0004, "RCODE=NOTIMP"),
    field(0x000f, 0x0005, "RCODE=REFUSED"),
];

const LLMNR_FLAGS: FlagTable = &[
    flag(0x8000, "QR"),
    flag(0x0400, "C"),
    flag(0x0200, "TC"),
    flag(0x0100, "T"),
];

const EDNS_FLAGS: FlagTable = &[flag(0x8000, "DO")];
const CAA_FLAGS: FlagTable = &[flag(0x80, "CRITICAL")];

const EDNS_OPTIONS: EnumTable = &[
    (3, "NSID"),
    (5, "DAU"),
    (6, "DHU"),
    (7, "N3U"),
    (8, "Client subnet"),
    (9, "EDNS expire"),
    (10, "Cookie"),
    (11, "TCP keepalive"),
    (12, "Padding"),
    (13, "CHAIN"),
    (14, "Key tag"),
    (15, "Extended DNS error"),
    (18, "Report-Channel"),
    (19, "ZONEVERSION"),
];

const SVC_PARAMS: EnumTable = &[
    (0, "mandatory"),
    (1, "alpn"),
    (2, "no-default-alpn"),
    (3, "port"),
    (4, "ipv4hint"),
    (5, "ech"),
    (6, "ipv6hint"),
    (7, "dohpath"),
    (8, "ohttp"),
    (9, "tls-supported-groups"),
];

const DNSSEC_ALGORITHMS: EnumTable = &[
    (1, "RSA/MD5"),
    (3, "DSA/SHA-1"),
    (5, "RSA/SHA-1"),
    (6, "DSA-NSEC3-SHA1"),
    (7, "RSASHA1-NSEC3-SHA1"),
    (8, "RSA/SHA-256"),
    (10, "RSA/SHA-512"),
    (12, "GOST R 34.10-2001"),
    (13, "ECDSA P-256/SHA-256"),
    (14, "ECDSA P-384/SHA-384"),
    (15, "Ed25519"),
    (16, "Ed448"),
];

const DIGEST_TYPES: EnumTable = &[
    (1, "SHA-1"),
    (2, "SHA-256"),
    (3, "GOST R 34.11-94"),
    (4, "SHA-384"),
];

/// Records decoded per message (a hostile count is bounded by the bytes).
const MAX_RECORDS: u64 = 4096;

/// A DNS name at `at` in `msg`, following compression pointers; returns the
/// name and the offset just past it in place.
pub fn name_at(msg: &[u8], at: usize) -> Option<(String, usize)> {
    let mut out = String::new();
    let mut pos = at;
    let mut end = None;
    let mut jumps = 0u32;
    let mut total = 0usize;
    loop {
        let len = *msg.get(pos)?;
        match len >> 6 {
            0 => {
                let n = usize::from(len);
                if n == 0 {
                    let end = end.unwrap_or(pos.checked_add(1)?);
                    if out.is_empty() {
                        out.push('.');
                    }
                    return Some((out, end));
                }
                let label = msg.get(pos.checked_add(1)?..pos.checked_add(1)?.checked_add(n)?)?;
                total = total.saturating_add(n).saturating_add(1);
                if total > 255 {
                    return None;
                }
                if !out.is_empty() {
                    out.push('.');
                }
                for &c in label {
                    match c {
                        b'.' | b'\\' => {
                            out.push('\\');
                            out.push(char::from(c));
                        }
                        0x21..=0x7e => out.push(char::from(c)),
                        _ => out.push_str(&format!("\\{c:03}")),
                    }
                }
                pos = pos.checked_add(1)?.checked_add(n)?;
            }
            3 => {
                let ptr = usize::from(u16::from_be_bytes([
                    len & 0x3f,
                    *msg.get(pos.checked_add(1)?)?,
                ]));
                if end.is_none() {
                    end = Some(pos.checked_add(2)?);
                }
                jumps = jumps.saturating_add(1);
                // Pointers go backwards; a bounded number of them.
                if jumps > 64 || ptr >= pos {
                    return None;
                }
                pos = ptr;
            }
            _ => return None,
        }
    }
}

/// A DNS message at `off..end` (with a two-byte length prefix over TCP).
pub fn message(b: &mut Dec, p: Ix, off: usize, end: usize, tcp: bool, flavor: Flavor) -> usize {
    let (proto, title) = match flavor {
        Flavor::Dns => ("DNS", "DNS"),
        Flavor::Mdns => ("MDNS", "Multicast DNS"),
        Flavor::Llmnr => ("LLMNR", "LLMNR"),
    };
    let mut mo = off;
    let mut me = end;
    let ix;
    if tcp {
        let Some(len) = b.be16(off) else {
            return off;
        };
        mo = off.saturating_add(2);
        me = mo.saturating_add(usize::from(len)).min(end);
        if me.saturating_sub(mo) < 12 {
            return off;
        }
        ix = b.group(p, title, off, me.saturating_sub(off));
        b.num(ix, "Length", off, 2);
        if mo.saturating_add(usize::from(len)) > end {
            b.tail(|n| n.diag(Diagnostic::note("the message continues in a later segment")));
        }
    } else {
        if end.saturating_sub(off) < 12 {
            return off;
        }
        ix = b.group(p, title, off, end.saturating_sub(off));
    }
    let msg = b.range(mo, me);
    let id = b.numx(ix, "Transaction ID", mo, 2).unwrap_or(0);
    let fl = b.u16(mo.saturating_add(2)).unwrap_or(0);
    let response = fl & 0x8000 != 0;
    let opcode = (fl >> 11) & 15;
    let mut rcode = u64::from(fl & 15);
    if flavor == Flavor::Llmnr {
        b.flg(ix, "Flags", mo.saturating_add(2), 2, LLMNR_FLAGS);
    } else {
        b.flg(ix, "Flags", mo.saturating_add(2), 2, FLAGS);
        b.tail(|n| {
            n.summary(format!(
                "{}, {}, {}",
                if response { "response" } else { "query" },
                lookup(OPCODES, opcode.into()).unwrap_or("unknown opcode"),
                lookup(RCODES, rcode).unwrap_or("unknown rcode")
            ))
        });
    }
    let counts: Vec<u64> = ["Questions", "Answer RRs", "Authority RRs", "Additional RRs"]
        .into_iter()
        .enumerate()
        .map(|(i, name)| {
            b.num(
                ix,
                name,
                mo.saturating_add(4).saturating_add(i.saturating_mul(2)),
                2,
            )
            .unwrap_or(0)
        })
        .collect();
    let mut at = 12usize;
    let mut budget = MAX_RECORDS;
    let mut question = String::new();
    let mut answers: Vec<String> = Vec::new();
    // Questions.
    let qd = counts.first().copied().unwrap_or(0);
    if qd > 0 {
        let g = b.group(ix, "Questions", mo.saturating_add(at), 0);
        let start = at;
        for _ in 0..qd.min(budget) {
            budget = budget.saturating_sub(1);
            let Some((name, next)) = name_at(msg, at) else {
                b.diag(g, Diagnostic::malformed("bad question name"));
                if question.is_empty() {
                    question = "(malformed name)".to_owned();
                }
                break;
            };
            let qtype = crate::bytes::u16_be(msg, next);
            let qclass = crate::bytes::u16_be(msg, next.saturating_add(2));
            let (Some(qtype), Some(qclass)) = (qtype, qclass) else {
                b.truncated(
                    g,
                    "Question",
                    mo.saturating_add(at),
                    next.saturating_add(4).saturating_sub(at),
                );
                at = msg.len();
                break;
            };
            let tname = type_name(qtype);
            if question.is_empty() {
                question = format!("{tname} {name}");
            }
            if b.building() {
                let q = b.group(
                    g,
                    format!("{name}: {tname}"),
                    mo.saturating_add(at),
                    next.saturating_add(4).saturating_sub(at),
                );
                let shown = name.clone();
                b.text(
                    q,
                    "Name",
                    mo.saturating_add(at),
                    next.saturating_sub(at),
                    || shown,
                );
                b.enm(q, "Type", mo.saturating_add(next), 2, TYPES);
                class_field(
                    b,
                    q,
                    mo.saturating_add(next).saturating_add(2),
                    qclass,
                    flavor,
                    true,
                );
                let cname = lookup(CLASSES, u64::from(qclass & 0x7fff)).unwrap_or("?");
                b.summary(q, || format!("type {tname}, class {cname}"));
            }
            at = next.saturating_add(4);
        }
        let span = b.sp(mo.saturating_add(start), at.saturating_sub(start));
        b.update(g, |n| n.span(span));
        b.summary(g, || crate::formats::util::fmt::plural(qd, "question"));
    }
    // Answer, authority and additional sections.
    for (i, title) in ["Answers", "Authority", "Additional records"]
        .into_iter()
        .enumerate()
    {
        let n = counts.get(i.saturating_add(1)).copied().unwrap_or(0);
        if n == 0 || at >= msg.len() {
            continue;
        }
        let g = b.group(ix, title, mo.saturating_add(at), 0);
        let start = at;
        for _ in 0..n.min(budget) {
            budget = budget.saturating_sub(1);
            match record(b, g, mo, msg, at, flavor, &mut rcode) {
                Some((next, text)) => {
                    if i == 0 && answers.len() < 4 {
                        answers.push(text);
                    }
                    at = next;
                }
                None => {
                    at = msg.len();
                    break;
                }
            }
        }
        let span = b.sp(mo.saturating_add(start), at.saturating_sub(start));
        b.update(g, |x| x.span(span));
        b.summary(g, || crate::formats::util::fmt::plural(n, "record"));
    }
    if at < msg.len() {
        b.data(ix, "Trailing data", mo.saturating_add(at), me);
    }
    let rname = lookup(RCODES, rcode).unwrap_or("unknown rcode");
    let what = if response { "response" } else { "query" };
    let mut info = format!("{proto} {what} {id:#06x} {question}");
    if response {
        if rcode != 0 {
            info.push_str(&format!(" — {rname}"));
        }
        for a in &answers {
            info.push_str(&format!(", {a}"));
        }
    }
    let shown = info.clone();
    b.summary(ix, || {
        shown.trim_start_matches(proto).trim_start().to_owned()
    });
    b.set_info(proto, || info);
    me
}

fn type_name(t: u16) -> String {
    lookup(TYPES, t.into()).map_or_else(|| format!("TYPE{t}"), str::to_owned)
}

fn class_field(b: &mut Dec, p: Ix, at: usize, class: u16, flavor: Flavor, question: bool) {
    if flavor == Flavor::Mdns && class & 0x8000 != 0 {
        b.add(p, "Class", at, 2, |n| {
            n.value(crate::formats::util::val::enumv(
                class & 0x7fff,
                15,
                CLASSES,
            ))
            .summary(if question {
                "unicast response requested (QU)"
            } else {
                "cache flush"
            })
        });
    } else {
        b.enm(p, "Class", at, 2, CLASSES);
    }
}

/// One resource record at `at` (relative to the message at `mo`); returns
/// the offset past it and a short rendering of its data.
fn record(
    b: &mut Dec,
    g: Ix,
    mo: usize,
    msg: &[u8],
    at: usize,
    flavor: Flavor,
    rcode: &mut u64,
) -> Option<(usize, String)> {
    let Some((name, next)) = name_at(msg, at) else {
        b.diag(g, Diagnostic::malformed("bad record name"));
        return None;
    };
    let rtype = crate::bytes::u16_be(msg, next);
    let class = crate::bytes::u16_be(msg, next.saturating_add(2));
    let ttl = crate::bytes::u32_be(msg, next.saturating_add(4));
    let rdlen = crate::bytes::u16_be(msg, next.saturating_add(8));
    let (Some(rtype), Some(class), Some(ttl), Some(rdlen)) = (rtype, class, ttl, rdlen) else {
        b.truncated(
            g,
            "Record",
            mo.saturating_add(at),
            next.saturating_add(10).saturating_sub(at),
        );
        return None;
    };
    let rd = next.saturating_add(10);
    let rend = rd.saturating_add(usize::from(rdlen));
    let tname = type_name(rtype);
    let r = b.group(
        g,
        format!("{name}: {tname}"),
        mo.saturating_add(at),
        rend.saturating_sub(at),
    );
    let shown = name.clone();
    b.text(
        r,
        "Name",
        mo.saturating_add(at),
        next.saturating_sub(at),
        || shown,
    );
    b.enm(r, "Type", mo.saturating_add(next), 2, TYPES);
    let base = mo.saturating_add(next);
    if rtype == 41 {
        // OPT: class is the UDP payload size, TTL the extended RCODE,
        // version and flags.
        b.num(r, "UDP payload size", base.saturating_add(2), 2);
        let ext = u64::from(ttl >> 24);
        b.num(r, "Extended RCODE", base.saturating_add(4), 1);
        *rcode |= ext << 4;
        b.num(r, "EDNS version", base.saturating_add(5), 1);
        b.flg(r, "Flags", base.saturating_add(6), 2, EDNS_FLAGS);
    } else {
        class_field(b, r, base.saturating_add(2), class, flavor, false);
        b.num(r, "Time to live", base.saturating_add(4), 4);
        b.tail(|n| n.summary(duration(ttl)));
    }
    b.num(r, "Data length", base.saturating_add(8), 2);
    if rend > msg.len() {
        b.truncated(r, "Data", mo.saturating_add(rd), usize::from(rdlen));
        return None;
    }
    let text = rdata(b, r, mo, msg, rtype, rd, rend);
    let shown = text.clone();
    b.summary(r, || {
        if rtype == 41 {
            format!(
                "EDNS0, UDP payload size {class}{}",
                if shown.is_empty() {
                    String::new()
                } else {
                    format!(", {shown}")
                }
            )
        } else {
            format!("{tname} {shown}, TTL {}", duration(ttl))
        }
    });
    Some((rend, format!("{tname} {text}")))
}

fn duration(s: u32) -> String {
    match s {
        0..60 => format!("{s} s"),
        60..3600 if s.is_multiple_of(60) => format!("{} min", s / 60),
        3600..86400 if s.is_multiple_of(3600) => format!("{} h", s / 3600),
        86400.. if s.is_multiple_of(86400) => format!("{} d", s / 86400),
        _ => format!("{s} s"),
    }
}

/// Decodes RDATA at `rd..rend`; returns a one-line rendering.
fn rdata(b: &mut Dec, r: Ix, mo: usize, msg: &[u8], rtype: u16, rd: usize, rend: usize) -> String {
    let abs = |o: usize| mo.saturating_add(o);
    let len = rend.saturating_sub(rd);
    let name_field = |b: &mut Dec, label: &'static str, at: usize| -> Option<(String, usize)> {
        let (n, next) = name_at(msg, at)?;
        let shown = n.clone();
        b.text(r, label, abs(at), next.saturating_sub(at), || shown);
        Some((n, next))
    };
    match rtype {
        1 if len == 4 => b
            .ip4(r, "Address", abs(rd))
            .map(|a| ipv4(&a))
            .unwrap_or_default(),
        28 if len == 16 => b
            .ip6(r, "Address", abs(rd))
            .map(|a| ipv6(&a))
            .unwrap_or_default(),
        2 | 5 | 12 | 39 => name_field(
            b,
            match rtype {
                2 => "Name server",
                5 => "Canonical name",
                12 => "Domain name",
                _ => "Target",
            },
            rd,
        )
        .map(|x| x.0)
        .unwrap_or_default(),
        15 => {
            let pref = b.num(r, "Preference", abs(rd), 2).unwrap_or(0);
            let ex = name_field(b, "Mail exchange", rd.saturating_add(2))
                .map(|x| x.0)
                .unwrap_or_default();
            format!("{pref} {ex}")
        }
        16 | 99 => {
            let mut at = rd;
            let mut parts = Vec::new();
            while at < rend {
                let n = usize::from(msg.get(at).copied().unwrap_or(0));
                let s = String::from_utf8_lossy(
                    msg.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n).min(rend))
                        .unwrap_or_default(),
                )
                .into_owned();
                let shown = s.clone();
                b.text(r, "Text", abs(at), n.saturating_add(1), || shown);
                parts.push(format!("{s:?}"));
                at = at.saturating_add(1).saturating_add(n);
            }
            parts.join(" ")
        }
        6 => {
            let mname = name_field(b, "Primary name server", rd);
            let Some((mname, n1)) = mname else {
                return String::new();
            };
            let rname = name_field(b, "Responsible mailbox", n1)
                .map(|x| x.0)
                .unwrap_or_default();
            let after = name_at(msg, n1).map_or(rend, |x| x.1);
            let serial = b.num(r, "Serial number", abs(after), 4).unwrap_or(0);
            for (i, label) in [
                "Refresh interval",
                "Retry interval",
                "Expire limit",
                "Minimum TTL",
            ]
            .into_iter()
            .enumerate()
            {
                let at = after.saturating_add(4).saturating_add(i.saturating_mul(4));
                let v = b.num(r, label, abs(at), 4).unwrap_or(0);
                b.tail(|n| n.summary(duration(u32::try_from(v).unwrap_or(0))));
            }
            format!("{mname} {rname} serial {serial}")
        }
        33 => {
            let pr = b.num(r, "Priority", abs(rd), 2).unwrap_or(0);
            let w = b
                .num(r, "Weight", abs(rd.saturating_add(2)), 2)
                .unwrap_or(0);
            let port = b.num(r, "Port", abs(rd.saturating_add(4)), 2).unwrap_or(0);
            let t = name_field(b, "Target", rd.saturating_add(6))
                .map(|x| x.0)
                .unwrap_or_default();
            format!("{pr} {w} {port} {t}")
        }
        257 if len >= 2 => {
            b.flg(r, "Flags", abs(rd), 1, CAA_FLAGS);
            let tl = usize::from(msg.get(rd.saturating_add(1)).copied().unwrap_or(0));
            b.num(r, "Tag length", abs(rd.saturating_add(1)), 1);
            let tag = String::from_utf8_lossy(
                msg.get(rd.saturating_add(2)..rd.saturating_add(2).saturating_add(tl).min(rend))
                    .unwrap_or_default(),
            )
            .into_owned();
            let shown = tag.clone();
            b.text(r, "Tag", abs(rd.saturating_add(2)), tl, || shown);
            let vs = rd.saturating_add(2).saturating_add(tl);
            let value = String::from_utf8_lossy(msg.get(vs..rend).unwrap_or_default()).into_owned();
            let shown = value.clone();
            b.text(r, "Value", abs(vs), rend.saturating_sub(vs), || shown);
            format!("{tag} {value:?}")
        }
        41 => {
            let mut at = rd;
            let mut names = Vec::new();
            while rend.saturating_sub(at) >= 4 {
                let code = crate::bytes::u16_be(msg, at).unwrap_or(0);
                let olen =
                    usize::from(crate::bytes::u16_be(msg, at.saturating_add(2)).unwrap_or(0));
                let oend = at.saturating_add(4).saturating_add(olen).min(rend);
                let oname = lookup(EDNS_OPTIONS, code.into()).unwrap_or("Unknown option");
                names.push(oname);
                let o = b.group(r, oname, abs(at), oend.saturating_sub(at));
                b.enm(o, "Code", abs(at), 2, EDNS_OPTIONS);
                b.num(o, "Length", abs(at.saturating_add(2)), 2);
                let body = at.saturating_add(4);
                match code {
                    10 => {
                        b.raw(o, "Client cookie", abs(body), 8.min(olen));
                        if olen > 8 {
                            b.raw(
                                o,
                                "Server cookie",
                                abs(body.saturating_add(8)),
                                olen.saturating_sub(8),
                            );
                        }
                    }
                    8 if olen >= 4 => {
                        let fam = b.num(o, "Family", abs(body), 2).unwrap_or(0);
                        let src = b
                            .num(o, "Source prefix length", abs(body.saturating_add(2)), 1)
                            .unwrap_or(0);
                        b.num(o, "Scope prefix length", abs(body.saturating_add(3)), 1);
                        let a = msg.get(body.saturating_add(4)..oend).unwrap_or_default();
                        let mut full = vec![0u8; if fam == 2 { 16 } else { 4 }];
                        for (slot, &x) in full.iter_mut().zip(a) {
                            *slot = x;
                        }
                        let s =
                            format!("{}/{src}", if fam == 2 { ipv6(&full) } else { ipv4(&full) });
                        b.text(o, "Address", abs(body.saturating_add(4)), a.len(), || s);
                    }
                    15 if olen >= 2 => {
                        b.num(o, "Info code", abs(body), 2);
                        let t = String::from_utf8_lossy(
                            msg.get(body.saturating_add(2)..oend).unwrap_or_default(),
                        )
                        .into_owned();
                        b.text(
                            o,
                            "Extra text",
                            abs(body.saturating_add(2)),
                            olen.saturating_sub(2),
                            || t,
                        );
                    }
                    12 => {
                        b.data(o, "Padding", abs(body), abs(oend));
                    }
                    _ => {
                        b.raw(o, "Data", abs(body), oend.saturating_sub(body));
                    }
                }
                at = oend;
            }
            names.join(", ")
        }
        64 | 65 => {
            let pr = b.num(r, "Priority", abs(rd), 2).unwrap_or(0);
            let Some((target, mut at)) = name_field(b, "Target", rd.saturating_add(2)) else {
                return String::new();
            };
            let mut params = Vec::new();
            while rend.saturating_sub(at) >= 4 {
                let key = crate::bytes::u16_be(msg, at).unwrap_or(0);
                let plen =
                    usize::from(crate::bytes::u16_be(msg, at.saturating_add(2)).unwrap_or(0));
                let pend = at.saturating_add(4).saturating_add(plen).min(rend);
                let kname = lookup(SVC_PARAMS, key.into())
                    .map_or_else(|| format!("key{key}"), str::to_owned);
                let o = b.group(r, kname.clone(), abs(at), pend.saturating_sub(at));
                b.enm(o, "Key", abs(at), 2, SVC_PARAMS);
                b.num(o, "Length", abs(at.saturating_add(2)), 2);
                let body = at.saturating_add(4);
                let val = svc_param(b, o, mo, msg, key, body, pend);
                let shown = val.clone();
                b.summary(o, || shown);
                params.push(if val.is_empty() {
                    kname
                } else {
                    format!("{kname}={val}")
                });
                at = pend;
            }
            format!("{pr} {target} {}", params.join(" "))
        }
        43 | 59 if len >= 4 => {
            let tag = b.num(r, "Key tag", abs(rd), 2).unwrap_or(0);
            let alg = b
                .enm(
                    r,
                    "Algorithm",
                    abs(rd.saturating_add(2)),
                    1,
                    DNSSEC_ALGORITHMS,
                )
                .unwrap_or(0);
            b.enm(r, "Digest type", abs(rd.saturating_add(3)), 1, DIGEST_TYPES);
            b.raw(
                r,
                "Digest",
                abs(rd.saturating_add(4)),
                len.saturating_sub(4),
            );
            format!(
                "key tag {tag}, {}",
                lookup(DNSSEC_ALGORITHMS, alg).unwrap_or("?")
            )
        }
        48 | 60 if len >= 4 => {
            let fl = b.numx(r, "Flags", abs(rd), 2).unwrap_or(0);
            b.num(r, "Protocol", abs(rd.saturating_add(2)), 1);
            let alg = b
                .enm(
                    r,
                    "Algorithm",
                    abs(rd.saturating_add(3)),
                    1,
                    DNSSEC_ALGORITHMS,
                )
                .unwrap_or(0);
            b.raw(
                r,
                "Public key",
                abs(rd.saturating_add(4)),
                len.saturating_sub(4),
            );
            format!(
                "{}, {}",
                if fl & 1 != 0 { "KSK" } else { "ZSK" },
                lookup(DNSSEC_ALGORITHMS, alg).unwrap_or("?")
            )
        }
        46 if len >= 18 => {
            let covered = b.enm(r, "Type covered", abs(rd), 2, TYPES).unwrap_or(0);
            b.enm(
                r,
                "Algorithm",
                abs(rd.saturating_add(2)),
                1,
                DNSSEC_ALGORITHMS,
            );
            b.num(r, "Labels", abs(rd.saturating_add(3)), 1);
            b.num(r, "Original TTL", abs(rd.saturating_add(4)), 4);
            for (i, label) in ["Signature expiration", "Signature inception"]
                .into_iter()
                .enumerate()
            {
                let at = rd.saturating_add(8).saturating_add(i.saturating_mul(4));
                let t = crate::bytes::u32_be(msg, at).unwrap_or(0);
                b.add(r, label, abs(at), 4, |n| {
                    n.value(crate::value::Value::Timestamp {
                        unix_seconds: i64::from(t),
                    })
                });
            }
            b.num(r, "Key tag", abs(rd.saturating_add(16)), 2);
            let after = name_field(b, "Signer's name", rd.saturating_add(18)).map_or(rend, |x| x.1);
            b.raw(r, "Signature", abs(after), rend.saturating_sub(after));
            format!(
                "covering {}",
                type_name(u16::try_from(covered).unwrap_or(0))
            )
        }
        13 => {
            let mut at = rd;
            let mut parts = Vec::new();
            for label in ["CPU", "OS"] {
                let n = usize::from(msg.get(at).copied().unwrap_or(0));
                let s = String::from_utf8_lossy(
                    msg.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n).min(rend))
                        .unwrap_or_default(),
                )
                .into_owned();
                let shown = s.clone();
                b.text(r, label, abs(at), n.saturating_add(1), || shown);
                parts.push(s);
                at = at.saturating_add(1).saturating_add(n);
            }
            parts.join(" ")
        }
        _ => {
            b.raw(r, "Data", abs(rd), len);
            format!("{len} bytes")
        }
    }
}

fn svc_param(
    b: &mut Dec,
    o: Ix,
    mo: usize,
    msg: &[u8],
    key: u16,
    body: usize,
    end: usize,
) -> String {
    let abs = |x: usize| mo.saturating_add(x);
    match key {
        0 => {
            let mut keys = Vec::new();
            let mut at = body;
            while at.saturating_add(2) <= end {
                let k = b.enm(o, "Key", abs(at), 2, SVC_PARAMS).unwrap_or(0);
                keys.push(lookup(SVC_PARAMS, k).map_or_else(|| format!("key{k}"), str::to_owned));
                at = at.saturating_add(2);
            }
            keys.join(",")
        }
        1 => {
            let mut ids = Vec::new();
            let mut at = body;
            while at < end {
                let n = usize::from(msg.get(at).copied().unwrap_or(0));
                let s = String::from_utf8_lossy(
                    msg.get(at.saturating_add(1)..at.saturating_add(1).saturating_add(n).min(end))
                        .unwrap_or_default(),
                )
                .into_owned();
                let shown = s.clone();
                b.text(o, "Protocol", abs(at), n.saturating_add(1), || shown);
                ids.push(s);
                at = at.saturating_add(1).saturating_add(n);
            }
            ids.join(",")
        }
        3 => b.num(o, "Port", abs(body), 2).unwrap_or(0).to_string(),
        4 | 6 => {
            let w = if key == 4 { 4 } else { 16 };
            let mut list = Vec::new();
            let mut at = body;
            while at.saturating_add(w) <= end {
                let a = if key == 4 {
                    b.ip4(o, "Address", abs(at)).map(|a| ipv4(&a))
                } else {
                    b.ip6(o, "Address", abs(at)).map(|a| ipv6(&a))
                };
                list.extend(a);
                at = at.saturating_add(w);
            }
            list.join(",")
        }
        7 => {
            let s = String::from_utf8_lossy(msg.get(body..end).unwrap_or_default()).into_owned();
            let shown = s.clone();
            b.text(
                o,
                "Path template",
                abs(body),
                end.saturating_sub(body),
                || shown,
            );
            s
        }
        2 | 8 => String::new(),
        _ => {
            b.raw(o, "Value", abs(body), end.saturating_sub(body));
            format!("{} bytes", end.saturating_sub(body))
        }
    }
}
