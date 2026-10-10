//! Summaries of X.509 structures (names, extensions, keys) from their DER
//! content, in the style of `openssl x509 -text`, and the decoders of the
//! primitives that hold a structure of their own (EC points, IP addresses,
//! RFC 6962 SCT lists).
//!
//! The summary functions see at most a few KiB of an element's content
//! (`PREVIEW` in `mod.rs`), so their work is bounded.

use super::der::{self, Tlv};
use super::oids;
use super::schema::{
    CRL_REASONS, KEY_USAGE_BITS, NS_CERT_TYPE_BITS, REASON_FLAGS_BITS, TLS_EXTENSIONS,
};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::civil::date;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::util::val;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

/// Names listed in a summary before "…".
const MAX_NAMES: usize = 6;
/// Longest summary built from a list.
const MAX_SUMMARY: usize = 200;

fn oid_name(content: &[u8]) -> String {
    let dotted = der::oid(content).unwrap_or_default();
    oids::name(&dotted).map_or(dotted, str::to_owned)
}

/// Colon-separated upper-case hex, as OpenSSL prints key identifiers.
pub fn colon_hex(data: &[u8]) -> String {
    let mut out = String::with_capacity(data.len().saturating_mul(3));
    for (i, b) in data.iter().enumerate() {
        if i > 0 {
            out.push(':');
        }
        out.push_str(&format!("{b:02X}"));
    }
    out
}

/// An IP address (4 or 16 bytes), or an address and mask (8 or 32 bytes,
/// in name constraints).
pub fn ip_address(data: &[u8]) -> Option<String> {
    let v4 = |b: &[u8]| -> Option<String> {
        let a: [u8; 4] = b.try_into().ok()?;
        Some(std::net::Ipv4Addr::from(a).to_string())
    };
    let v6 = |b: &[u8]| -> Option<String> {
        let a: [u8; 16] = b.try_into().ok()?;
        Some(std::net::Ipv6Addr::from(a).to_string())
    };
    match data.len() {
        4 => v4(data),
        16 => v6(data),
        8 => Some(format!("{}/{}", v4(data.get(..4)?)?, v4(data.get(4..)?)?)),
        32 => Some(format!("{}/{}", v6(data.get(..16)?)?, v6(data.get(16..)?)?)),
        _ => None,
    }
}

/// One GeneralName, as OpenSSL writes it (`DNS:example.com`).
pub fn general_name(tlv: &Tlv, content: &[u8]) -> String {
    let text = || String::from_utf8_lossy(content).into_owned();
    match tlv.id {
        0xa0 => {
            let mut parts = der::elements(content);
            let kind = parts.next().map(|(_, o)| oid_name(o)).unwrap_or_default();
            let value = parts
                .next()
                .and_then(|(_, v)| der::first(v))
                .and_then(|(t, v)| der::display(&t, v))
                .unwrap_or_else(|| "…".into());
            format!("othername:{kind}:{value}")
        }
        0x81 => format!("email:{}", text()),
        0x82 => format!("DNS:{}", text()),
        0x86 => format!("URI:{}", text()),
        0x87 => format!(
            "IP:{}",
            ip_address(content).unwrap_or_else(|| colon_hex(content))
        ),
        0x88 => format!("RID:{}", oid_name(content)),
        0xa4 => format!("DirName:{}", explicit_name(content).unwrap_or_default()),
        _ => tlv.label(),
    }
}

/// The names of a GeneralNames sequence's content.
pub fn general_names(content: &[u8]) -> Option<String> {
    let names: Vec<String> = der::elements(content)
        .take(MAX_NAMES.saturating_add(1))
        .map(|(t, c)| general_name(&t, c))
        .collect();
    list(names, der::elements(content).count())
}

/// Joins up to `MAX_NAMES` items, noting how many more there are.
fn list(mut items: Vec<String>, total: usize) -> Option<String> {
    if items.is_empty() {
        return None;
    }
    items.truncate(MAX_NAMES);
    let mut out = items.join(", ");
    if total > MAX_NAMES {
        out = format!("{out}, … ({total} in all)");
    }
    Some(clip(&out, MAX_SUMMARY))
}

/// The content of an EXPLICIT tag holding a Name.
pub fn explicit_name(content: &[u8]) -> Option<String> {
    let (t, name) = der::first(content)?;
    (t.id == 0x30).then(|| der::name(name))
}

/// A GeneralSubtree: its base name, and the distances if given.
pub fn general_subtree(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (t, base) = parts.next()?;
    let mut out = general_name(&t, base);
    for (t, v) in parts {
        let n = der::integer(v).unwrap_or_default();
        match t.id {
            0x80 => out = format!("{out}, minimum {n}"),
            0x81 => out = format!("{out}, maximum {n}"),
            _ => {}
        }
    }
    Some(out)
}

fn bit_names(content: &[u8], names: &[&str]) -> Vec<String> {
    let body = content.get(1..).unwrap_or_default();
    let mut out = Vec::new();
    for (i, &b) in body.iter().enumerate().take(8) {
        for bit in 0..8usize {
            if b & (0x80 >> bit) != 0 {
                let n = i.saturating_mul(8).saturating_add(bit);
                out.push(match names.get(n).filter(|s| !s.is_empty()) {
                    Some(name) => (*name).to_owned(),
                    None => format!("bit {n}"),
                });
            }
        }
    }
    out
}

/// The value of a named-bit BIT STRING (bit `n` as `1 << n`) and the names
/// of the bits set.
pub fn bits_value(content: &[u8], names: &'static [&'static str]) -> Value {
    let body = content.get(1..).unwrap_or_default();
    let mut raw = 0u64;
    let mut set = Vec::new();
    let mut unknown = 0u64;
    for (i, &b) in body.iter().enumerate().take(8) {
        for bit in 0..8usize {
            if b & (0x80 >> bit) == 0 {
                continue;
            }
            let n = i.saturating_mul(8).saturating_add(bit);
            let mask = 1u64
                .checked_shl(u32::try_from(n).unwrap_or(64))
                .unwrap_or(0);
            raw |= mask;
            match names.get(n).filter(|s| !s.is_empty()) {
                Some(name) => set.push(*name),
                None => unknown |= mask,
            }
        }
    }
    let bits = u8::try_from(body.len().saturating_mul(8).clamp(8, 64)).unwrap_or(64);
    Value::Flags {
        raw,
        bits,
        set,
        unknown,
    }
}

fn lookup(table: EnumTable, n: i64) -> String {
    u64::try_from(n)
        .ok()
        .and_then(|n| crate::value::lookup(table, n))
        .map_or_else(|| n.to_string(), str::to_owned)
}

/// The content of an Extension: its name, criticality and, for the common
/// extensions, what its value says.
pub fn extension(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content).peekable();
    let (t, oid) = parts.next()?;
    if !t.is_universal(der::OID) {
        return None;
    }
    let dotted = der::oid(oid)?;
    let mut out = oids::name(&dotted).map_or_else(|| dotted.clone(), str::to_owned);
    if let Some((t, v)) = parts.peek()
        && t.is_universal(der::BOOLEAN)
    {
        if v.first().is_some_and(|&b| b != 0) {
            out.push_str(" (critical)");
        }
        parts.next();
    }
    let value = parts
        .next()
        .filter(|(t, _)| t.is_universal(der::OCTET_STRING))
        .and_then(|(_, v)| extension_value(&dotted, v));
    Some(match value {
        Some(v) => format!("{out}: {v}"),
        None => out,
    })
}

/// What an extension's value says, by its OID.
fn extension_value(oid: &str, value: &[u8]) -> Option<String> {
    let (t, c) = der::first(value)?;
    let names = |c: &[u8]| -> Option<String> {
        let items = der::elements(c)
            .take(MAX_NAMES.saturating_add(1))
            .map(|(_, o)| oid_name(o))
            .collect();
        list(items, der::elements(c).count())
    };
    Some(match oid {
        "2.5.29.19" => {
            let mut ca = false;
            let mut path = None;
            for (t, v) in der::elements(c) {
                if t.is_universal(der::BOOLEAN) {
                    ca = v.first().is_some_and(|&b| b != 0);
                } else if t.is_universal(der::INTEGER) {
                    path = der::integer(v);
                }
            }
            match path {
                Some(n) => format!("CA:{}, pathlen:{n}", if ca { "TRUE" } else { "FALSE" }),
                None => format!("CA:{}", if ca { "TRUE" } else { "FALSE" }),
            }
        }
        "2.5.29.15" => bit_names(c, KEY_USAGE_BITS).join(", "),
        "2.16.840.1.113730.1.1" => bit_names(c, NS_CERT_TYPE_BITS).join(", "),
        "2.5.29.37" => names(c)?,
        "2.5.29.32" | "1.3.6.1.4.1.311.21.10" => {
            let items = der::elements(c)
                .take(MAX_NAMES.saturating_add(1))
                .filter_map(|(_, p)| der::first(p).map(|(_, o)| oid_name(o)))
                .collect();
            list(items, der::elements(c).count())?
        }
        "2.5.29.14" | "1.3.6.1.4.1.311.21.2" | "1.3.6.1.5.5.7.48.1.2" => colon_hex(c),
        "2.5.29.35" => {
            let items = der::elements(c)
                .map(|(t, v)| match t.id {
                    0x80 => format!("keyid:{}", colon_hex(v)),
                    0xa1 => general_names(v).unwrap_or_default(),
                    0x82 => format!("serial:{}", colon_hex(v)),
                    _ => t.label(),
                })
                .collect();
            list(items, 0)?
        }
        "2.5.29.17" | "2.5.29.18" | "2.5.29.29" => general_names(c)?,
        "2.5.29.31" | "2.5.29.46" => {
            let items: Vec<String> = der::elements(c)
                .take(MAX_NAMES.saturating_add(1))
                .filter_map(|(_, dp)| distribution_point(dp))
                .collect();
            list(items, der::elements(c).count())?
        }
        "2.5.29.28" => distribution_point(c)?,
        "1.3.6.1.5.5.7.1.1" | "1.3.6.1.5.5.7.1.11" => {
            let items = der::elements(c)
                .take(MAX_NAMES.saturating_add(1))
                .filter_map(|(_, ad)| {
                    let mut parts = der::elements(ad);
                    let (_, method) = parts.next()?;
                    let (t, location) = parts.next()?;
                    Some(format!(
                        "{} - {}",
                        oid_name(method),
                        general_name(&t, location)
                    ))
                })
                .collect();
            list(items, der::elements(c).count())?
        }
        "2.5.29.30" => {
            let mut items = Vec::new();
            for (t, subtrees) in der::elements(c) {
                let kind = if t.id == 0xa0 {
                    "permitted"
                } else {
                    "excluded"
                };
                for (_, subtree) in der::elements(subtrees).take(MAX_NAMES) {
                    items.push(format!("{kind} {}", general_subtree(subtree)?));
                }
            }
            list(items, 0)?
        }
        "2.5.29.36" => {
            let items = der::elements(c)
                .map(|(t, v)| {
                    let n = der::integer(v).unwrap_or_default();
                    if t.id == 0x80 {
                        format!("requireExplicitPolicy:{n}")
                    } else {
                        format!("inhibitPolicyMapping:{n}")
                    }
                })
                .collect();
            list(items, 0)?
        }
        "1.3.6.1.5.5.7.1.24" => {
            let items = der::elements(c)
                .map(|(_, v)| lookup(TLS_EXTENSIONS, der::integer(v).unwrap_or(-1)))
                .collect();
            list(items, 0)?
        }
        "1.3.6.1.4.1.11129.2.4.2" | "1.3.6.1.4.1.11129.2.4.5" => {
            plural(to_u64(sct_entries(c).len()), "SCT")
        }
        "1.3.6.1.4.1.11129.2.4.3" => "poison".into(),
        "2.5.29.21" => lookup(CRL_REASONS, der::integer(c)?),
        "1.3.6.1.4.1.311.21.7" => {
            let mut parts = der::elements(c);
            let id = parts.next().map(|(_, o)| oid_name(o))?;
            let major = parts.next().and_then(|(_, v)| der::integer(v));
            let minor = parts.next().and_then(|(_, v)| der::integer(v));
            match (major, minor) {
                (Some(a), Some(b)) => format!("{id} v{a}.{b}"),
                (Some(a), None) => format!("{id} v{a}"),
                _ => id,
            }
        }
        _ if !t.constructed => der::display(&t, c)?,
        _ => return None,
    })
}

/// A DistributionPoint's names and reasons.
fn distribution_point(content: &[u8]) -> Option<String> {
    let mut parts = Vec::new();
    for (t, v) in der::elements(content) {
        match t.id {
            0xa0 => {
                for (t, name) in der::elements(v) {
                    if t.id == 0xa0 {
                        parts.extend(general_names(name));
                    }
                }
            }
            0x81 | 0x83 => parts.push(format!(
                "reasons: {}",
                bit_names(v, REASON_FLAGS_BITS).join(", ")
            )),
            0xa2 => parts.push(format!(
                "CRL issuer {}",
                general_names(v).unwrap_or_default()
            )),
            0x81..=0x85 if v.first().is_some_and(|&b| b != 0) => parts.push(
                match t.id {
                    0x81 => "only user certificates",
                    0x82 => "only CA certificates",
                    0x84 => "indirect CRL",
                    _ => "only attribute certificates",
                }
                .to_owned(),
            ),
            _ => {}
        }
    }
    list(parts, 0)
}

/// An AlgorithmIdentifier's content: its name, and what its parameters
/// select (a curve, the hashes and salt of RSASSA-PSS, a PBE scheme).
pub fn algorithm(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (t, oid) = parts.next()?;
    if !t.is_universal(der::OID) {
        return None;
    }
    let dotted = der::oid(oid)?;
    let name = oids::name(&dotted).map_or_else(|| dotted.clone(), str::to_owned);
    let params = parts.next();
    let hash = |explicit: &[u8]| -> Option<String> {
        der::first(explicit)
            .and_then(|(_, alg)| der::first(alg))
            .map(|(_, o)| oid_name(o))
    };
    Some(match (dotted.as_str(), params) {
        ("1.2.840.113549.1.1.10" | "1.2.840.113549.1.1.7", Some((pt, p))) if pt.id == 0x30 => {
            // Defaults: SHA-1, MGF1 with SHA-1, salt 20.
            let (mut h, mut mgf, mut salt) = ("sha1".to_owned(), "sha1".to_owned(), None);
            for (t, v) in der::elements(p) {
                match t.id {
                    0xa0 => h = hash(v).unwrap_or(h),
                    0xa1 => {
                        mgf = der::first(v)
                            .and_then(|(_, alg)| der::elements(alg).nth(1))
                            .and_then(|(_, inner)| der::first(inner))
                            .map(|(_, o)| oid_name(o))
                            .unwrap_or(mgf);
                    }
                    0xa2 if dotted.ends_with(".10") => {
                        salt = der::first(v).and_then(|(_, n)| der::integer(n));
                    }
                    _ => {}
                }
            }
            match salt.or_else(|| dotted.ends_with(".10").then_some(20)) {
                Some(s) => format!("{name} ({h}, MGF1 {mgf}, salt {s})"),
                None => format!("{name} ({h}, MGF1 {mgf})"),
            }
        }
        ("1.2.840.113549.1.5.13" | "1.2.840.113549.1.12.1.3" | "1.2.840.113549.1.12.1.6", _) => {
            super::pbe::describe(content)
        }
        (_, Some((pt, p))) if pt.is_universal(der::OID) => format!("{name} = {}", oid_name(p)),
        _ => name,
    })
}

/// An Attribute's content: its type and first value.
pub fn attribute(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (t, oid) = parts.next()?;
    if !t.is_universal(der::OID) {
        return None;
    }
    let name = oid_name(oid);
    let value = parts
        .next()
        .and_then(|(_, set)| der::first(set))
        .and_then(|(t, v)| {
            if t.is_universal(der::OCTET_STRING) && v.len() <= 64 {
                Some(colon_hex(v))
            } else if t.constructed {
                None
            } else {
                der::display(&t, v)
            }
        });
    Some(match value {
        Some(v) => format!("{name}: {v}"),
        None => name,
    })
}

/// A SignerInfo's content: who signed, with what, and when.
pub fn signer_info(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content).skip(1);
    let (t, sid) = parts.next()?;
    let mut out = match t.id {
        0x30 => {
            let mut fields = der::elements(sid);
            let issuer = fields.next().map(|(_, n)| der::name(n)).unwrap_or_default();
            let serial = fields.next().map(|(_, s)| colon_hex(s)).unwrap_or_default();
            format!("{issuer}, serial {serial}")
        }
        _ => format!("key {}", colon_hex(sid)),
    };
    let digest = parts
        .next()
        .and_then(|(_, a)| der::first(a))
        .map(|(_, o)| oid_name(o));
    let mut signing_time = None;
    let mut signature = None;
    for (t, v) in parts {
        match t.id {
            0xa0 => {
                for (_, attr) in der::elements(v) {
                    let mut fields = der::elements(attr);
                    if fields.next().and_then(|(_, o)| der::oid(o)).as_deref()
                        == Some("1.2.840.113549.1.9.5")
                    {
                        signing_time = fields
                            .next()
                            .and_then(|(_, set)| der::first(set))
                            .and_then(|(t, c)| der::time(t.tag, c));
                    }
                }
            }
            0x30 => signature = der::first(v).map(|(_, o)| oid_name(o)),
            _ => {}
        }
    }
    if let Some(alg) = signature.or(digest) {
        out = format!("{out}, {alg}");
    }
    if let Some(time) = signing_time {
        out = format!("{out}, signed {}", date(time));
    }
    Some(out)
}

/// A curve's NIST name, for the common ones.
fn nist_curve(oid: &str) -> Option<&'static str> {
    Some(match oid {
        "1.2.840.10045.3.1.1" => "P-192",
        "1.3.132.0.33" => "P-224",
        "1.2.840.10045.3.1.7" => "P-256",
        "1.3.132.0.34" => "P-384",
        "1.3.132.0.35" => "P-521",
        _ => return None,
    })
}

/// Bits in a big-endian unsigned INTEGER's content.
pub fn integer_bits(data: &[u8]) -> u64 {
    let trimmed = data
        .iter()
        .position(|&b| b != 0)
        .map_or(&[][..], |i| data.get(i..).unwrap_or_default());
    let Some(&lead) = trimmed.first() else {
        return 0;
    };
    to_u64(trimmed.len())
        .saturating_sub(1)
        .saturating_mul(8)
        .saturating_add(u64::from(8u32.saturating_sub(lead.leading_zeros())))
}

/// A SubjectPublicKeyInfo's content: "RSA 2048-bit", "EC P-256", "Ed25519".
pub fn public_key_info(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (_, alg) = parts.next()?;
    let (_, key) = parts.next()?;
    let mut alg_parts = der::elements(alg);
    let oid = alg_parts.next().and_then(|(_, o)| der::oid(o))?;
    let params = alg_parts.next();
    let body = key.get(1..).unwrap_or_default();
    Some(match oid.as_str() {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" | "1.2.840.113549.1.1.7" => {
            let kind = if oid.ends_with(".1.1") {
                "RSA"
            } else {
                "RSA-PSS"
            };
            let kind = if oid.ends_with(".7") {
                "RSA-OAEP"
            } else {
                kind
            };
            match der::first(body).and_then(|(_, k)| rsa_public_key(k)) {
                Some(detail) => format!("{kind} {detail}"),
                None => kind.to_owned(),
            }
        }
        "1.2.840.10045.2.1" => {
            let curve = params
                .filter(|(t, _)| t.is_universal(der::OID))
                .and_then(|(_, o)| der::oid(o));
            match curve {
                Some(c) => match (nist_curve(&c), oids::name(&c)) {
                    (Some(nist), Some(name)) => format!("EC {nist} ({name})"),
                    (None, Some(name)) => format!("EC {name}"),
                    _ => format!("EC {c}"),
                },
                None => "EC (explicit curve parameters)".into(),
            }
        }
        "1.2.840.10040.4.1" | "1.2.840.10046.2.1" | "1.2.840.113549.1.3.1" => {
            let kind = if oid.ends_with("4.1") { "DSA" } else { "DH" };
            let p = params
                .and_then(|(_, p)| der::first(p))
                .map(|(_, p)| integer_bits(p));
            match p {
                Some(bits) => format!("{kind} {bits}-bit"),
                None => kind.to_owned(),
            }
        }
        _ => oids::name(&oid).map_or(oid.clone(), str::to_owned),
    })
}

/// An RSAPublicKey's content: "2048-bit, e=65537".
pub fn rsa_public_key(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (_, n) = parts.next()?;
    let (_, e) = parts.next()?;
    let bits = integer_bits(n);
    Some(match der::integer(e) {
        Some(e) => format!("{bits}-bit, e={e}"),
        None => format!("{bits}-bit"),
    })
}

/// A Validity: "2026-10-10 to 2027-10-10 (365 days)".
pub fn validity(content: &[u8]) -> Option<String> {
    let mut times = der::elements(content).filter_map(|(t, c)| der::time(t.tag, c));
    let (from, until) = (times.next()?, times.next()?);
    let days = until.saturating_sub(from).div_euclid(86_400);
    Some(format!(
        "{} to {} ({})",
        date(from),
        date(until),
        plural(u64::try_from(days).unwrap_or(0), "day")
    ))
}

/// A revoked certificate entry: serial, date and reason.
pub fn revoked(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (_, serial) = parts.next()?;
    let (t, when) = parts.next()?;
    let mut out = format!("serial {}", colon_hex(serial));
    if let Some(time) = der::time(t.tag, when) {
        out = format!("{out}, {}", date(time));
    }
    if let Some((_, extensions)) = parts.next() {
        for (_, ext) in der::elements(extensions) {
            let mut fields = der::elements(ext);
            let Some((_, oid)) = fields.next() else {
                continue;
            };
            if der::oid(oid).as_deref() == Some("2.5.29.21")
                && let Some((_, value)) = fields.find(|(t, _)| t.is_universal(der::OCTET_STRING))
                && let Some((_, reason)) = der::first(value)
            {
                out = format!(
                    "{out}, {}",
                    lookup(CRL_REASONS, der::integer(reason).unwrap_or(-1))
                );
            }
        }
    }
    Some(out)
}

/// An OCSP CertID: the serial number and hash algorithm.
pub fn cert_id(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (_, alg) = parts.next()?;
    let serial = parts.nth(2).map(|(_, s)| colon_hex(s))?;
    let hash = der::first(alg)
        .map(|(_, o)| oid_name(o))
        .unwrap_or_default();
    Some(format!("serial {serial}, {hash}"))
}

/// An OCSP SingleResponse: the status of a serial number.
pub fn single_response(content: &[u8]) -> Option<String> {
    let mut parts = der::elements(content);
    let (_, id) = parts.next()?;
    let (status, info) = parts.next()?;
    let serial = der::elements(id).nth(3).map(|(_, s)| colon_hex(s))?;
    let state = match status.id {
        0x80 => "good".to_owned(),
        0xa1 => {
            let mut fields = der::elements(info);
            let when = fields
                .next()
                .and_then(|(t, c)| der::time(t.tag, c))
                .map(date)
                .unwrap_or_default();
            let reason = fields
                .next()
                .and_then(|(_, r)| der::first(r))
                .and_then(|(_, r)| der::integer(r))
                .map(|r| format!(", {}", lookup(CRL_REASONS, r)))
                .unwrap_or_default();
            format!("revoked {when}{reason}")
        }
        0x82 => "unknown".to_owned(),
        _ => status.label(),
    };
    Some(format!("serial {serial}: {state}"))
}

// ---------------------------------------------------------------------------
// Special primitives

fn be16(data: &[u8], at: usize) -> Option<u16> {
    data.get(at..at.saturating_add(2))
        .and_then(|b| <[u8; 2]>::try_from(b).ok())
        .map(u16::from_be_bytes)
}

/// The SCTs of a TLS-encoded SignedCertificateTimestampList: offsets and
/// lengths (after their 2-byte length prefixes) within `data`.
fn sct_entries(data: &[u8]) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let total = usize::from(be16(data, 0).unwrap_or(0));
    let end = total.saturating_add(2).min(data.len());
    let mut pos = 2usize;
    while pos.saturating_add(2) <= end {
        let Some(len) = be16(data, pos).map(usize::from) else {
            break;
        };
        let start = pos.saturating_add(2);
        if start.saturating_add(len) > end {
            break;
        }
        out.push((start, len));
        pos = start.saturating_add(len);
    }
    out
}

const TLS_HASHES: EnumTable = &[
    (0, "none"),
    (1, "md5"),
    (2, "sha1"),
    (3, "sha224"),
    (4, "sha256"),
    (5, "sha384"),
    (6, "sha512"),
    (8, "intrinsic"),
];

const TLS_SIGNATURES: EnumTable = &[
    (0, "anonymous"),
    (1, "rsa"),
    (2, "dsa"),
    (3, "ecdsa"),
    (7, "ed25519"),
    (8, "ed448"),
];

/// Lists the SCTs of a SignedCertificateTimestampList at `span`.
pub async fn sct_list(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x1_0000)).await?;
    let entries = sct_entries(&data);
    cx.emit(
        Node::new("list length")
            .span(span.sub(0, 2))
            .value(val::uint(be16(&data, 0).unwrap_or(0), 16)),
    );
    let mut end = 2u64;
    for (i, (start, len)) in entries.into_iter().enumerate() {
        let at = to_u64(start).saturating_sub(2);
        let whole = span.sub(at, to_u64(len).saturating_add(2));
        let body = data
            .get(start..start.saturating_add(len))
            .unwrap_or_default();
        let log = body.get(1..33).map(colon_hex).unwrap_or_default();
        let ms = body
            .get(33..41)
            .and_then(|b| <[u8; 8]>::try_from(b).ok())
            .map_or(0, u64::from_be_bytes);
        let secs = i64::try_from(ms / 1000).unwrap_or(0);
        let summary = format!("log {}…, {}", log.get(..11).unwrap_or_default(), date(secs));
        end = at.saturating_add(whole.len);
        cx.push(
            Node::new(format!("SignedCertificateTimestamp {i}"))
                .span(whole)
                .summary(summary)
                .lazy(crate::expander!(sct: Span), whole),
        )
        .await;
    }
    if end < span.len {
        cx.emit(
            Node::new("Trailing data")
                .span(span.tail(end))
                .summary(format!("{} bytes", span.len.saturating_sub(end))),
        );
    }
    Ok(())
}

/// The fields of one SCT (with its length prefix) at `span`.
async fn sct(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x1_0000)).await?;
    let u16_at = |at: usize| be16(&data, at);
    let field = |name: &'static str, at: usize, len: usize| {
        Node::new(name).span(span.sub(to_u64(at), to_u64(len)))
    };
    cx.emit(field("length", 0, 2).value(val::uint(u16_at(0).unwrap_or(0), 16)));
    let Some(&version) = data.get(2) else {
        return Ok(());
    };
    cx.emit(field("version", 2, 1).value(val::enumv(version, 8, &[(0, "v1")])));
    if let Some(log) = data.get(3..35) {
        cx.emit(field("logID", 3, 32).value(Value::Text(colon_hex(log))));
    }
    if let Some(b) = data.get(35..43).and_then(|b| <[u8; 8]>::try_from(b).ok()) {
        let ms = u64::from_be_bytes(b);
        cx.emit(
            field("timestamp", 35, 8)
                .value(Value::Timestamp {
                    unix_seconds: i64::try_from(ms / 1000).unwrap_or(0),
                })
                .summary(format!("{ms} ms since 1970")),
        );
    }
    let Some(ext_len) = u16_at(43).map(usize::from) else {
        return Ok(());
    };
    cx.emit(
        field("extensions length", 43, 2).value(val::uint(u64::try_from(ext_len).unwrap_or(0), 16)),
    );
    let mut pos = 45usize;
    if ext_len > 0 {
        cx.emit(
            field("extensions", pos, ext_len).value(Value::Bytes(
                data.get(pos..pos.saturating_add(ext_len))
                    .unwrap_or_default()
                    .iter()
                    .take(32)
                    .copied()
                    .collect(),
            )),
        );
    }
    pos = pos.saturating_add(ext_len);
    if let (Some(&hash), Some(&sig)) = (data.get(pos), data.get(pos.saturating_add(1))) {
        cx.emit(field("hash", pos, 1).value(val::enumv(hash, 8, TLS_HASHES)));
        cx.emit(
            field("signature algorithm", pos.saturating_add(1), 1).value(val::enumv(
                sig,
                8,
                TLS_SIGNATURES,
            )),
        );
    }
    pos = pos.saturating_add(2);
    if let Some(len) = u16_at(pos).map(usize::from) {
        cx.emit(
            field("signature length", pos, 2).value(val::uint(u64::try_from(len).unwrap_or(0), 16)),
        );
        let at = pos.saturating_add(2);
        let sig = data.get(at..at.saturating_add(len)).unwrap_or_default();
        let mut node = field("signature", at, len)
            .value(Value::Bytes(sig.iter().take(32).copied().collect()))
            .summary(format!("{len} bytes"));
        if super::der::is_nested_der(sig) {
            node = node.summary(format!("{len} bytes, DER (r, s)"));
        }
        cx.emit(node);
    }
    Ok(())
}

const POINT_FORMATS: EnumTable = &[
    (2, "compressed, even y"),
    (3, "compressed, odd y"),
    (4, "uncompressed"),
    (6, "hybrid, even y"),
    (7, "hybrid, odd y"),
];

/// A summary of an EC point's encoding.
pub fn ec_point_summary(point: &[u8]) -> Option<String> {
    let (&format, rest) = point.split_first()?;
    let name = crate::value::lookup(POINT_FORMATS, u64::from(format))?;
    let coordinate = if format == 2 || format == 3 {
        rest.len()
    } else {
        rest.len() / 2
    };
    Some(format!(
        "{name} point, {}-bit coordinates",
        coordinate.saturating_mul(8)
    ))
}

/// The fields of an EC point at `span`.
pub async fn ec_point(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 1024)).await?;
    let Some((&format, rest)) = data.split_first() else {
        return Ok(());
    };
    cx.emit(
        Node::new("format")
            .span(span.sub(0, 1))
            .value(val::enumv(format, 8, POINT_FORMATS)),
    );
    let n = to_u64(rest.len());
    match format {
        2 | 3 => cx.emit(
            Node::new("x")
                .span(span.sub(1, n))
                .value(Value::Bytes(rest.iter().take(32).copied().collect()))
                .summary(format!("{} bytes", n)),
        ),
        4 | 6 | 7 => {
            let half = n / 2;
            let x = rest.get(..rest.len() / 2).unwrap_or_default();
            let y = rest.get(rest.len() / 2..).unwrap_or_default();
            cx.emit(
                Node::new("x")
                    .span(span.sub(1, half))
                    .value(Value::Bytes(x.iter().take(32).copied().collect()))
                    .summary(format!("{half} bytes")),
            );
            cx.emit(
                Node::new("y")
                    .span(span.sub(1u64.saturating_add(half), half))
                    .value(Value::Bytes(y.iter().take(32).copied().collect()))
                    .summary(format!("{half} bytes")),
            );
        }
        _ => {}
    }
    Ok(())
}
