//! Summaries for the file node of each ASN.1 format, from the first bytes
//! of the input (bounded by `SUMMARY_READ`).

use super::der::{self, Tlv};
use super::schema::{OCSP_STATUS, PKI_STATUS};
use super::{Kind, oids, pbe, x509};
use crate::bytes::to_u64;
use crate::formats::util::civil::date;
use crate::formats::util::fmt::plural;

pub(super) fn annotation(kind: Kind, head: &[u8], len: u64) -> String {
    if kind == Kind::Provision {
        return match provision(head) {
            Some(d) => format!("Apple provisioning profile, {d}"),
            None => "Apple provisioning profile".into(),
        };
    }
    let outer = der::first(head);
    let detail = outer.and_then(|(tlv, content)| match kind {
        Kind::Generic => Some(format!("{}, {} bytes", tlv.label(), len)),
        Kind::Certificate => certificate(content),
        Kind::Crl => crl(content),
        Kind::Csr => csr(content),
        Kind::Pkcs7 => pkcs7(content),
        Kind::Provision => None,
        Kind::Pkcs12 => pkcs12(content),
        Kind::EncryptedKey => {
            der::first(content).map(|(_, alg)| format!("encrypted with {}", pbe::describe(alg)))
        }
        Kind::OcspRequest => ocsp_request(content),
        Kind::OcspResponse => ocsp_response(content),
        Kind::TsQuery => ts_query(content),
        Kind::TsReply => ts_reply(content),
        Kind::Pkcs8 => pkcs8(content),
        Kind::RsaPrivateKey => {
            let mut ints = der::elements(content).skip(1);
            let n = ints.next()?;
            let e = ints.next()?;
            let mut seq = Vec::new();
            for (t, c) in [n, e] {
                seq.extend(encode(&t, c));
            }
            x509::rsa_public_key(&seq)
        }
        Kind::RsaPublicKey => x509::rsa_public_key(content),
        Kind::EcPrivateKey => ec_private_key(content),
        Kind::DsaPrivateKey | Kind::DsaParams => {
            let skip = usize::from(kind == Kind::DsaPrivateKey);
            let mut ints = der::elements(content).skip(skip);
            let p = ints.next().map(|(_, p)| x509::integer_bits(p))?;
            let q = ints.next().map(|(_, q)| x509::integer_bits(q))?;
            Some(format!("{p}-bit p, {q}-bit q"))
        }
        Kind::Spki => x509::public_key_info(content),
        Kind::KrbTicket => krb_ticket(content),
        Kind::DhParams => {
            let mut ints = der::elements(content);
            let p = ints.next().map(|(_, p)| x509::integer_bits(p))?;
            let g = ints.next().and_then(|(_, g)| der::integer(g))?;
            Some(format!("{p}-bit prime, generator {g}"))
        }
    });
    let title = match kind {
        Kind::Generic => "ASN.1 DER",
        Kind::Certificate => "X.509 certificate",
        Kind::Crl => "X.509 CRL",
        Kind::Csr => "PKCS#10 certificate request",
        Kind::Pkcs7 => "PKCS#7",
        Kind::Provision => "Apple provisioning profile",
        Kind::Pkcs12 => "PKCS#12 key store",
        Kind::EncryptedKey => "Encrypted private key (PKCS#8)",
        Kind::OcspRequest => "OCSP request",
        Kind::OcspResponse => "OCSP response",
        Kind::TsQuery => "Time-stamp request",
        Kind::TsReply => "Time-stamp response",
        Kind::Pkcs8 => "Private key (PKCS#8)",
        Kind::RsaPrivateKey => "RSA private key",
        Kind::RsaPublicKey => "RSA public key",
        Kind::EcPrivateKey => "EC private key",
        Kind::DsaPrivateKey => "DSA private key",
        Kind::Spki => "Public key",
        Kind::DhParams => "DH parameters",
        Kind::DsaParams => "DSA parameters",
        Kind::KrbTicket => "Kerberos ticket",
    };
    match detail {
        Some(d) => format!("{title}, {d}"),
        None => title.to_owned(),
    }
}

/// Re-encodes a TLV (for handing a few elements to a summary function).
fn encode(t: &Tlv, content: &[u8]) -> Vec<u8> {
    let mut out = vec![t.id];
    let len = content.len();
    if len < 0x80 {
        out.push(u8::try_from(len).unwrap_or(0));
    } else {
        let bytes = to_u64(len).to_be_bytes();
        let skip = bytes.iter().take_while(|&&b| b == 0).count();
        let used = bytes.get(skip..).unwrap_or_default();
        out.push(0x80 | u8::try_from(used.len()).unwrap_or(0));
        out.extend_from_slice(used);
    }
    out.extend_from_slice(content);
    out
}

fn oid_name(content: &[u8]) -> String {
    let dotted = der::oid(content).unwrap_or_default();
    oids::name(&dotted).map_or(dotted, str::to_owned)
}

/// The algorithm named by an AlgorithmIdentifier's content.
fn algorithm(content: &[u8]) -> Option<String> {
    der::first(content)
        .filter(|(t, _)| t.is_universal(der::OID))
        .map(|(_, oid)| oid_name(oid))
}

/// The common name of an X.500 name, or the whole name.
fn short_name(name: &[u8]) -> String {
    for (_, rdn) in der::elements(name) {
        for (_, atv) in der::elements(rdn) {
            let mut fields = der::elements(atv);
            if let (Some((_, oid)), Some((vt, value))) = (fields.next(), fields.next())
                && der::oid(oid).as_deref() == Some("2.5.4.3")
                && let Some(text) = der::display(&vt, value)
            {
                return format!("CN={text}");
            }
        }
    }
    der::name(name)
}

pub(super) fn certificate(cert: &[u8]) -> Option<String> {
    let (_, tbs) = der::first(cert)?;
    let mut fields = der::elements(tbs).peekable();
    let mut version = 1;
    if let Some((t, v)) = fields.peek()
        && t.id == 0xa0
    {
        version = der::first(v)
            .and_then(|(_, n)| der::integer(n))
            .map_or(1, |n| n.saturating_add(1));
        fields.next();
    }
    let _serial = fields.next()?;
    let _signature = fields.next()?;
    let (_, issuer) = fields.next()?;
    let (_, validity) = fields.next()?;
    let (_, subject) = fields.next()?;
    let spki = fields.next().map(|(_, s)| s);
    let extensions = fields
        .find(|(t, _)| t.id == 0xa3)
        .and_then(|(_, e)| der::first(e));
    let mut out = short_name(subject);
    if version != 3 {
        out = format!("v{version}, {out}");
    }
    if issuer == subject {
        out.push_str(", self-signed");
    } else {
        out = format!("{out}, issued by {}", short_name(issuer));
    }
    let mut times = der::elements(validity).filter_map(|(t, c)| der::time(t.tag, c));
    if let (Some(from), Some(until)) = (times.next(), times.next()) {
        out = format!("{out}, valid {} to {}", date(from), date(until));
    }
    if let Some(key) = spki.and_then(x509::public_key_info) {
        out = format!("{out}, {key}");
    }
    let mut ca = false;
    let mut san = None;
    for (_, ext) in extensions
        .map(|(_, e)| der::elements(e))
        .into_iter()
        .flatten()
    {
        let mut parts = der::elements(ext);
        let Some((_, oid)) = parts.next() else {
            continue;
        };
        let value = parts
            .find(|(t, _)| t.is_universal(der::OCTET_STRING))
            .and_then(|(_, v)| der::first(v));
        match der::oid(oid).as_deref() {
            Some("2.5.29.19") => {
                ca = value.is_some_and(|(_, c)| {
                    der::first(c).is_some_and(|(t, b)| {
                        t.is_universal(der::BOOLEAN) && b.first().is_some_and(|&b| b != 0)
                    })
                });
            }
            Some("2.5.29.17") => san = value.and_then(|(_, c)| x509::general_names(c)),
            _ => {}
        }
    }
    if ca {
        out.push_str(", CA");
    }
    if let Some(san) = san {
        out = format!("{out}, SAN: {san}");
    }
    Some(out)
}

fn crl(list: &[u8]) -> Option<String> {
    let (_, tbs) = der::first(list)?;
    let mut fields = der::elements(tbs).peekable();
    if fields.peek().is_some_and(|(t, _)| t.id == 0x02) {
        fields.next();
    }
    let _signature = fields.next()?;
    let (_, issuer) = fields.next()?;
    let (t, this_update) = fields.next()?;
    let mut out = format!("issued by {}", short_name(issuer));
    if let Some(time) = der::time(t.tag, this_update) {
        out = format!("{out}, updated {}", date(time));
    }
    let revoked = fields
        .find(|(t, _)| t.id == 0x30)
        .map_or(0, |(_, list)| der::elements(list).count());
    Some(format!("{out}, {revoked} revoked"))
}

fn csr(request: &[u8]) -> Option<String> {
    let (_, info) = der::first(request)?;
    let mut fields = der::elements(info);
    let _version = fields.next()?;
    let (_, subject) = fields.next()?;
    let (_, spki) = fields.next()?;
    let mut out = format!("for {}", der::name(subject));
    if let Some(key) = x509::public_key_info(spki) {
        out = format!("{out}, {key}");
    }
    Some(out)
}

fn pkcs7(info: &[u8]) -> Option<String> {
    let mut fields = der::elements(info);
    let (_, oid) = fields.next()?;
    let kind = oid_name(oid);
    let dotted = der::oid(oid).unwrap_or_default();
    let (_, explicit) = fields.next()?;
    let (_, body) = der::first(explicit)?;
    match dotted.as_str() {
        "1.2.840.113549.1.7.2" => Some(signed_data(&kind, body)),
        "1.2.840.113549.1.7.3" | "1.2.840.113549.1.9.16.1.2" | "1.2.840.113549.1.9.16.1.23" => {
            let mut out = kind;
            for (t, c) in der::elements(body) {
                match t.id {
                    0x31 => {
                        out = format!(
                            "{out}, {}",
                            plural(to_u64(der::elements(c).count()), "recipient")
                        );
                    }
                    // EncryptedContentInfo, or AuthenticatedData's MAC algorithm.
                    0x30 => {
                        let mut parts = der::elements(c);
                        if let Some((t, first)) = parts.next() {
                            let alg = if t.is_universal(der::OID) {
                                parts.next().and_then(|(_, a)| algorithm(a))
                            } else {
                                None
                            }
                            .or_else(|| (t.is_universal(der::OID)).then(|| oid_name(first)));
                            if let Some(alg) = alg {
                                out = format!("{out}, {alg}");
                            }
                        }
                        break;
                    }
                    _ => {}
                }
            }
            Some(out)
        }
        "1.2.840.113549.1.7.6" => {
            let info = der::elements(body).nth(1)?.1;
            let alg = der::elements(info).nth(1).and_then(|(_, a)| algorithm(a));
            Some(alg.map_or(kind.clone(), |a| format!("{kind}, {a}")))
        }
        _ => Some(kind),
    }
}

fn signed_data(kind: &str, signed: &[u8]) -> String {
    let mut certificates = Vec::new();
    let mut signers = 0;
    let mut content = None;
    for (t, c) in der::elements(signed) {
        match t.id {
            0x30 => content = encapsulated(c),
            0xa0 => certificates = der::elements(c).collect(),
            0x31 => signers = der::elements(c).count(),
            _ => {}
        }
    }
    let count = plural(to_u64(certificates.len()), "certificate");
    if signers == 0 && !certificates.is_empty() {
        // A certificate bundle (.p7b, .p7c).
        let names: Vec<String> = certificates
            .iter()
            .take(4)
            .filter_map(|(_, cert)| {
                let (_, tbs) = der::first(cert)?;
                let mut fields = der::elements(tbs).skip_while(|(t, _)| t.id == 0xa0);
                fields.nth(4).map(|(_, subject)| short_name(subject))
            })
            .collect();
        let more = if certificates.len() > 4 { ", …" } else { "" };
        return format!("certificates only: {count} ({}{more})", names.join("; "));
    }
    let mut out = kind.to_owned();
    if let Some(content) = content {
        out = format!("{out} ({content})");
    }
    format!("{out}, {count}, {}", plural(to_u64(signers), "signer"))
}

/// The content type of an EncapsulatedContentInfo, and for Authenticode
/// (SpcIndirectDataContent) the algorithm of the signed file digest.
fn encapsulated(info: &[u8]) -> Option<String> {
    let mut fields = der::elements(info);
    let (_, oid) = fields.next()?;
    let kind = oid_name(oid);
    if der::oid(oid).as_deref() != Some("1.3.6.1.4.1.311.2.1.4") {
        return Some(kind);
    }
    let digest = fields
        .next()
        .and_then(|(_, explicit)| der::first(explicit))
        .filter(|(t, _)| t.id == 0x30)
        .and_then(|(_, indirect)| der::elements(indirect).nth(1))
        .and_then(|(_, digest_info)| der::first(digest_info))
        .and_then(|(_, alg)| algorithm(alg));
    Some(match digest {
        Some(alg) => format!("{kind}, {alg} digest"),
        None => kind,
    })
}

fn pkcs12(pfx: &[u8]) -> Option<String> {
    let mut fields = der::elements(pfx);
    let (_, version) = fields.next()?;
    let mut out = format!("version {}", der::integer(version)?);
    let _auth_safe = fields.next()?;
    if let Some((_, mac)) = fields.next()
        && let Some((_, digest_info)) = der::first(mac)
        && let Some((_, alg)) = der::first(digest_info)
        && let Some(name) = algorithm(alg)
    {
        out = format!("{out}, MAC {name}");
    }
    Some(out)
}

fn ocsp_request(request: &[u8]) -> Option<String> {
    let (_, tbs) = der::first(request)?;
    let mut out = Vec::new();
    for (t, c) in der::elements(tbs) {
        match t.id {
            0x30 => {
                let n = der::elements(c).count();
                out.push(plural(to_u64(n), "certificate"));
                if let Some(id) = der::first(c)
                    .and_then(|(_, r)| der::first(r))
                    .and_then(|(_, id)| x509::cert_id(id))
                {
                    out.push(id);
                }
            }
            0xa2 => {
                let names: Vec<String> = der::first(c)
                    .map(|(_, exts)| {
                        der::elements(exts)
                            .filter_map(|(_, e)| der::first(e).map(|(_, o)| oid_name(o)))
                            .collect()
                    })
                    .unwrap_or_default();
                out.extend(names);
            }
            _ => {}
        }
    }
    if der::elements(request).nth(1).is_some() {
        out.push("signed".into());
    }
    Some(out.join(", "))
}

fn ocsp_response(response: &[u8]) -> Option<String> {
    let mut fields = der::elements(response);
    let (_, status) = fields.next()?;
    let status = der::integer(status)?;
    let mut out = u64::try_from(status)
        .ok()
        .and_then(|s| crate::value::lookup(OCSP_STATUS, s))
        .map_or_else(|| format!("status {status}"), str::to_owned);
    let basic = fields
        .next()
        .and_then(|(_, e)| der::first(e))
        .and_then(|(_, rb)| der::elements(rb).nth(1))
        .and_then(|(_, octets)| der::first(octets))
        .and_then(|(_, basic)| der::first(basic));
    if let Some((_, data)) = basic {
        for (t, c) in der::elements(data) {
            match t.id {
                0x18 => {
                    if let Some(time) = der::time(t.tag, c) {
                        out = format!("{out}, produced {}", date(time));
                    }
                }
                0x30 => {
                    for (_, single) in der::elements(c).take(4) {
                        if let Some(s) = x509::single_response(single) {
                            out = format!("{out}, {s}");
                        }
                    }
                }
                _ => {}
            }
        }
    }
    Some(out)
}

fn ts_query(request: &[u8]) -> Option<String> {
    let mut fields = der::elements(request);
    let _version = fields.next()?;
    let (_, imprint) = fields.next()?;
    let mut out = vec![der::first(imprint).and_then(|(_, a)| algorithm(a))?];
    for (t, c) in fields {
        match t.tag {
            6 => out.push(format!("policy {}", oid_name(c))),
            2 => out.push("nonce".into()),
            1 if c.first().is_some_and(|&b| b != 0) => out.push("certificate requested".into()),
            _ => {}
        }
    }
    Some(out.join(", "))
}

fn ts_reply(response: &[u8]) -> Option<String> {
    let mut fields = der::elements(response);
    let (_, info) = fields.next()?;
    let status = der::first(info).and_then(|(_, s)| der::integer(s))?;
    let mut out = u64::try_from(status)
        .ok()
        .and_then(|s| crate::value::lookup(PKI_STATUS, s))
        .map_or_else(|| format!("status {status}"), str::to_owned);
    // timeStampToken → SignedData → encapContentInfo → [0] → OCTETS → TSTInfo.
    let tst = fields
        .next()
        .and_then(|(_, ci)| der::elements(ci).nth(1))
        .and_then(|(_, explicit)| der::first(explicit))
        .and_then(|(_, signed)| der::elements(signed).nth(2))
        .and_then(|(_, encap)| der::elements(encap).nth(1))
        .and_then(|(_, explicit)| der::first(explicit))
        .and_then(|(_, octets)| der::first(octets));
    if let Some((_, tst)) = tst {
        let mut parts = der::elements(tst).skip(1);
        let policy = parts.next().map(|(_, p)| oid_name(p));
        let hash = parts
            .next()
            .and_then(|(_, mi)| der::first(mi))
            .and_then(|(_, a)| algorithm(a));
        let serial = parts.next().map(|(_, s)| x509::colon_hex(s));
        let time = parts.next().and_then(|(t, c)| der::time(t.tag, c));
        if let Some(time) = time {
            out = format!("{out}, {}", date(time));
        }
        if let Some(serial) = serial {
            out = format!("{out}, serial {serial}");
        }
        if let Some(hash) = hash {
            out = format!("{out}, {hash}");
        }
        if let Some(policy) = policy {
            out = format!("{out}, policy {policy}");
        }
    }
    Some(out)
}

fn pkcs8(info: &[u8]) -> Option<String> {
    let mut fields = der::elements(info);
    let _version = fields.next()?;
    let (_, alg) = fields.next()?;
    let mut parts = der::elements(alg);
    let oid = parts.next().and_then(|(_, o)| der::oid(o))?;
    let name = oids::name(&oid).map_or(oid.clone(), str::to_owned);
    let (_, key) = fields.next()?;
    let detail = match oid.as_str() {
        "1.2.840.113549.1.1.1" | "1.2.840.113549.1.1.10" => der::first(key).and_then(|(_, k)| {
            let mut ints = der::elements(k).skip(1);
            Some(format!("{}-bit", x509::integer_bits(ints.next()?.1)))
        }),
        "1.2.840.10045.2.1" => parts
            .next()
            .filter(|(t, _)| t.is_universal(der::OID))
            .map(|(_, c)| oid_name(c)),
        _ => None,
    };
    Some(match detail {
        Some(d) => format!("{name}, {d}"),
        None => name,
    })
}

fn ec_private_key(key: &[u8]) -> Option<String> {
    let mut out = None;
    let mut has_public = false;
    for (t, c) in der::elements(key) {
        match t.id {
            0x04 => out = out.or(Some(format!("{}-bit", to_u64(c.len()).saturating_mul(8)))),
            0xa0 => {
                if let Some((t, o)) = der::first(c)
                    && t.is_universal(der::OID)
                {
                    out = Some(format!("{}, {}", oid_name(o), out.unwrap_or_default()));
                }
            }
            0xa1 => has_public = true,
            _ => {}
        }
    }
    let mut out = out?;
    if has_public {
        out.push_str(", with public key");
    }
    Some(out)
}

/// The value element after `<key>name</key>` in a property list's XML.
fn plist_value(xml: &[u8], name: &str) -> Option<String> {
    let key = format!("<key>{name}</key>");
    let at = crate::bytes::find(xml, key.as_bytes(), 0)?.saturating_add(key.len());
    let rest = xml.get(at..)?;
    let open = crate::bytes::find(rest, b"<", 0)?;
    let tag_end = crate::bytes::find(rest, b">", open)?;
    let tag = rest.get(open.saturating_add(1)..tag_end)?;
    if tag.ends_with(b"/") {
        return Some(String::from_utf8_lossy(tag.get(..tag.len().saturating_sub(1))?).into_owned());
    }
    let close = format!("</{}>", String::from_utf8_lossy(tag));
    let start = tag_end.saturating_add(1);
    let end = crate::bytes::find(rest, close.as_bytes(), start)?;
    let text = String::from_utf8_lossy(rest.get(start..end)?)
        .trim()
        .to_owned();
    Some(crate::formats::util::fmt::clip(&text, 80))
}

/// What a provisioning profile's property list says about itself.
fn provision(head: &[u8]) -> Option<String> {
    let at = crate::bytes::find(head, b"<plist", 0)?;
    let xml = head.get(at..)?;
    let mut out = Vec::new();
    if let Some(name) = plist_value(xml, "Name") {
        out.push(format!("\"{name}\""));
    }
    if let Some(team) = plist_value(xml, "TeamName") {
        out.push(format!("team {team}"));
    }
    if let Some(app) = plist_value(xml, "AppIDName") {
        out.push(format!("app {app}"));
    }
    if let Some(date) = plist_value(xml, "ExpirationDate") {
        out.push(format!("expires {}", date.get(..10).unwrap_or(&date)));
    }
    (!out.is_empty()).then(|| out.join(", "))
}

/// A Kerberos ticket (the content of its `[APPLICATION 1]`): service,
/// realm and encryption type.
fn krb_ticket(content: &[u8]) -> Option<String> {
    let (_, fields) = der::first(content)?;
    let mut realm = String::new();
    let mut sname = String::new();
    let mut etype = None;
    for (t, v) in der::elements(fields) {
        match t.id {
            0xa1 => {
                realm = der::first(v)
                    .and_then(|(t, s)| der::display(&t, s))
                    .unwrap_or_default();
            }
            0xa2 => {
                sname = der::first(v)
                    .and_then(|(_, p)| x509::krb_principal(p))
                    .unwrap_or_default();
            }
            0xa3 => {
                etype = der::first(v)
                    .and_then(|(_, e)| der::first(e))
                    .and_then(|(_, w)| der::first(w))
                    .and_then(|(_, n)| der::integer(n));
            }
            _ => {}
        }
    }
    let mut out = format!("for {sname}@{realm}");
    if let Some(e) = etype.and_then(|e| u64::try_from(e).ok()) {
        let name = crate::value::lookup(super::schema::KRB_ETYPES, e).unwrap_or("unknown enctype");
        out = format!("{out}, {name}");
    }
    Some(out)
}
