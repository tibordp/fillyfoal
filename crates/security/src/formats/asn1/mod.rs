//! ASN.1 BER/DER: a generic TLV dissector, plus the formats built on it
//! (X.509 certificates, CRLs, PKCS#10 requests, PKCS#7/CMS, PKCS#12).
//!
//! Elements are listed lazily, one constructed level per expansion. Names
//! come from a small schema of the well-known modules (`schema.rs`); values
//! are decoded by universal type. OCTET and BIT STRINGs that contain DER are
//! expandable in place. Lengths come from the headers, so nesting is strictly
//! decreasing and cannot cycle; depth is capped anyway.

pub mod der;
pub mod oids;
mod p12;
mod pbe;
mod schema;
mod summary;
mod x509;

use std::borrow::Cow;

use der::Tlv;
use schema::{Context, Matcher, Schema, Special};
use summary::annotation;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

/// Deepest nesting of constructed elements shown.
const MAX_DEPTH: u32 = 64;
/// Largest primitive content read in full for its value.
const PREVIEW: u64 = 4096;
/// Bytes kept for a `Value::Bytes` preview.
const PREVIEW_BYTES: usize = 32;
/// OCTET and BIT STRINGs up to this size are checked for nested DER.
const NESTED_MAX: u64 = 64 * 1024;
/// Longest TLV header (identifier with a long tag, 8 length octets).
const HEADER_MAX: u64 = 20;
/// Bytes read from the start of the input to summarise it.
const SUMMARY_READ: u64 = 64 * 1024;

// ---------------------------------------------------------------------------
// Formats

macro_rules! asn1_format {
    ($id:ident, $fn:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $probe:expr, $schema:expr, $kind:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom($probe),
            dissect: crate::expander!($fn: Input),
        };

        async fn $fn(cx: Cx, input: Input) -> Result<()> {
            dissect_with(cx, input, $schema, $kind).await
        }
    };
}

asn1_format!(
    X509,
    dissect_x509,
    "x509",
    "X.509 certificate (DER)",
    ["cer", "crt", "der"],
    "application/pkix-cert",
    probe_x509,
    &schema::TOP_CERTIFICATE,
    Kind::Certificate
);
asn1_format!(
    CRL,
    dissect_crl,
    "crl",
    "X.509 certificate revocation list (DER)",
    ["crl"],
    "application/pkix-crl",
    probe_crl,
    &schema::TOP_CRL,
    Kind::Crl
);
asn1_format!(
    CSR,
    dissect_csr,
    "csr",
    "PKCS#10 certification request (DER)",
    ["csr", "p10", "req"],
    "application/pkcs10",
    probe_csr,
    &schema::TOP_CSR,
    Kind::Csr
);
asn1_format!(
    PKCS7,
    dissect_pkcs7,
    "pkcs7",
    "PKCS#7 / CMS message (DER)",
    ["p7b", "p7s", "p7m", "p7c", "spc", "cat"],
    "application/pkcs7-mime",
    probe_pkcs7,
    &schema::TOP_PKCS7,
    Kind::Pkcs7
);
asn1_format!(
    PROVISIONING_PROFILE,
    dissect_provisioning_profile,
    "mobileprovision",
    "Apple provisioning profile",
    ["mobileprovision", "provisionprofile"],
    "application/x-apple-aspen-mobileprovision",
    probe_provision,
    &schema::TOP_PKCS7,
    Kind::Provision
);
asn1_format!(
    PKCS12,
    dissect_pkcs12,
    "pkcs12",
    "PKCS#12 key store",
    ["p12", "pfx"],
    "application/x-pkcs12",
    probe_pkcs12,
    &schema::TOP_PKCS12,
    Kind::Pkcs12
);
asn1_format!(
    PKCS8_ENCRYPTED,
    dissect_pkcs8_encrypted,
    "pkcs8-encrypted",
    "Encrypted private key (PKCS#8)",
    ["p8", "key", "der"],
    "application/pkcs8-encrypted",
    probe_pkcs8_encrypted,
    &schema::UNKNOWN,
    Kind::EncryptedKey
);
asn1_format!(
    OCSP_REQUEST,
    dissect_ocsp_request,
    "ocsp-request",
    "OCSP request (DER)",
    ["ocsp", "orq", "req", "der"],
    "application/ocsp-request",
    probe_ocsp_request,
    &schema::TOP_OCSP_REQUEST,
    Kind::OcspRequest
);
asn1_format!(
    OCSP_RESPONSE,
    dissect_ocsp_response,
    "ocsp-response",
    "OCSP response (DER)",
    ["ocsp", "ors", "resp", "der"],
    "application/ocsp-response",
    probe_ocsp_response,
    &schema::TOP_OCSP_RESPONSE,
    Kind::OcspResponse
);
asn1_format!(
    TS_QUERY,
    dissect_ts_query,
    "tsq",
    "RFC 3161 time-stamp request",
    ["tsq"],
    "application/timestamp-query",
    probe_ts_query,
    &schema::TOP_TIME_STAMP_REQ,
    Kind::TsQuery
);
asn1_format!(
    TS_REPLY,
    dissect_ts_reply,
    "tsr",
    "RFC 3161 time-stamp response",
    ["tsr"],
    "application/timestamp-reply",
    probe_ts_reply,
    &schema::TOP_TIME_STAMP_RESP,
    Kind::TsReply
);
asn1_format!(
    PKCS8,
    dissect_pkcs8,
    "pkcs8",
    "Private key (PKCS#8, DER)",
    ["p8", "pk8", "key", "der"],
    "application/pkcs8",
    probe_pkcs8,
    &schema::TOP_PRIVATE_KEY_INFO,
    Kind::Pkcs8
);
asn1_format!(
    RSA_PRIVATE_KEY,
    dissect_rsa_private_key,
    "rsa-private-key",
    "RSA private key (PKCS#1, DER)",
    ["key", "der"],
    "application/octet-stream",
    probe_rsa_private_key,
    &schema::TOP_RSA_PRIVATE_KEY,
    Kind::RsaPrivateKey
);
asn1_format!(
    RSA_PUBLIC_KEY,
    dissect_rsa_public_key,
    "rsa-public-key",
    "RSA public key (PKCS#1, DER)",
    ["pub", "der"],
    "application/octet-stream",
    probe_rsa_public_key,
    &schema::TOP_RSA_PUBLIC_KEY,
    Kind::RsaPublicKey
);
asn1_format!(
    EC_PRIVATE_KEY,
    dissect_ec_private_key,
    "ec-private-key",
    "EC private key (SEC 1, DER)",
    ["key", "der"],
    "application/octet-stream",
    probe_ec_private_key,
    &schema::TOP_EC_PRIVATE_KEY,
    Kind::EcPrivateKey
);
asn1_format!(
    DSA_PRIVATE_KEY,
    dissect_dsa_private_key,
    "dsa-private-key",
    "DSA private key (OpenSSL, DER)",
    ["key", "der"],
    "application/octet-stream",
    probe_dsa_private_key,
    &schema::TOP_DSA_PRIVATE_KEY,
    Kind::DsaPrivateKey
);
asn1_format!(
    SPKI,
    dissect_spki,
    "spki",
    "Public key (SubjectPublicKeyInfo, DER)",
    ["pub", "der"],
    "application/octet-stream",
    probe_spki,
    &schema::TOP_SPKI,
    Kind::Spki
);
asn1_format!(
    DH_PARAMS,
    dissect_dh_params,
    "dh-params",
    "Diffie-Hellman parameters (PKCS#3, DER)",
    ["dh", "der"],
    "application/octet-stream",
    probe_dh_params,
    &schema::TOP_DH_PARAMETER,
    Kind::DhParams
);
asn1_format!(
    DSA_PARAMS,
    dissect_dsa_params,
    "dsa-params",
    "DSA parameters (DER)",
    ["der"],
    "application/octet-stream",
    probe_dsa_params,
    &schema::TOP_DSA_PARAMETERS,
    Kind::DsaParams
);
asn1_format!(
    DER,
    dissect_der,
    "der",
    "ASN.1 DER/BER data",
    ["der", "ber", "asn1"],
    "application/octet-stream",
    probe_der,
    &schema::UNKNOWN,
    Kind::Generic
);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Generic,
    Certificate,
    Crl,
    Csr,
    Pkcs7,
    Provision,
    Pkcs12,
    EncryptedKey,
    OcspRequest,
    OcspResponse,
    TsQuery,
    TsReply,
    Pkcs8,
    RsaPrivateKey,
    RsaPublicKey,
    EcPrivateKey,
    DsaPrivateKey,
    Spki,
    DhParams,
    DsaParams,
}

/// The content of the single outer SEQUENCE spanning the whole input (as
/// far as the probe window shows it).
fn outer<'a>(h: &Head<'a>) -> Option<&'a [u8]> {
    let tlv = der::header(h.data)?;
    if tlv.id != 0x30 || tlv.total()? != h.len || tlv.len? < 2 {
        return None;
    }
    h.data.get(to_usize(tlv.header)..)
}

fn ids(data: &[u8]) -> Vec<u8> {
    der::elements(data).map(|(t, _)| t.id).take(12).collect()
}

/// The children of the first element of the outer SEQUENCE, if it is a
/// SEQUENCE (a TBS structure).
fn tbs_ids(h: &Head<'_>) -> Option<Vec<u8>> {
    let outer = outer(h)?;
    let (tlv, tbs) = der::first(outer)?;
    (tlv.id == 0x30).then(|| ids(tbs))
}

fn probe_x509(h: &Head<'_>) -> bool {
    let Some(ids) = tbs_ids(h) else {
        return false;
    };
    let ids = ids.strip_prefix(&[0xa0]).unwrap_or(&ids);
    ids.starts_with(&[0x02, 0x30, 0x30, 0x30, 0x30])
}

fn probe_crl(h: &Head<'_>) -> bool {
    let Some(ids) = tbs_ids(h) else {
        return false;
    };
    let ids = ids.strip_prefix(&[0x02]).unwrap_or(&ids);
    matches!(ids, [0x30, 0x30, 0x17 | 0x18, ..])
}

fn probe_csr(h: &Head<'_>) -> bool {
    tbs_ids(h).is_some_and(|ids| ids.starts_with(&[0x02, 0x30, 0x30, 0xa0]))
}

/// The content of a ContentInfo, definite or (BER) indefinite length, and
/// its content type: the start of a PKCS#7 / CMS message.
fn content_info<'a>(h: &Head<'a>) -> Option<(String, &'a [u8])> {
    let outer = match outer(h) {
        Some(outer) => outer,
        None => {
            let tlv = der::header(h.data)?;
            if tlv.id != 0x30 || tlv.len.is_some() {
                return None;
            }
            h.data.get(to_usize(tlv.header)..)?
        }
    };
    let (t, oid) = der::first(outer)?;
    // The content may extend beyond the probe window: check its header only.
    let rest = outer.get(first_len(outer)..).unwrap_or_default();
    let oid = der::oid(oid).filter(|o| {
        o.starts_with("1.2.840.113549.1.7.")
            || matches!(
                o.as_str(),
                "1.2.840.113549.1.9.16.1.2"
                    | "1.2.840.113549.1.9.16.1.9"
                    | "1.2.840.113549.1.9.16.1.23"
            )
    })?;
    (t.id == 0x06 && der::header(rest).is_some_and(|next| next.id == 0xa0)).then_some((oid, rest))
}

fn probe_pkcs7(h: &Head<'_>) -> bool {
    content_info(h).is_some()
}

/// Apple provisioning profiles: CMS SignedData over a property list.
fn probe_provision(h: &Head<'_>) -> bool {
    content_info(h).is_some_and(|(oid, rest)| {
        let window = rest.get(..4096).unwrap_or(rest);
        oid == "1.2.840.113549.1.7.2"
            && crate::bytes::find(window, b"<plist", 0).is_some()
            && crate::bytes::find(window, b"<key>", 0).is_some()
    })
}

/// Length of the first element of `data` (0 if unknown).
fn first_len(data: &[u8]) -> usize {
    der::header(data)
        .and_then(|t| t.total())
        .map_or(0, to_usize)
}

fn probe_pkcs12(h: &Head<'_>) -> bool {
    let Some(outer) = outer(h) else {
        return false;
    };
    let mut kids = der::elements(outer);
    let version = kids
        .next()
        .is_some_and(|(t, v)| t.id == 0x02 && der::integer(v) == Some(3));
    let auth_safe = kids.next().is_some_and(|(t, c)| {
        t.id == 0x30
            && der::first(c).is_some_and(|(t, oid)| {
                t.id == 0x06 && der::oid(oid).is_some_and(|o| o.starts_with("1.2.840.113549.1.7."))
            })
    });
    version && auth_safe
}

/// Generic DER: a single SEQUENCE spanning the whole input, and, when the
/// whole input is visible, valid all the way down.
/// EncryptedPrivateKeyInfo: SEQUENCE { AlgorithmIdentifier (a PBE scheme),
/// OCTET STRING }, filling the input.
fn probe_pkcs8_encrypted(h: &Head<'_>) -> bool {
    let Some(content) = outer(h) else {
        return false;
    };
    let mut it = der::elements(content);
    let (Some((alg, alg_content)), Some((data, _)), None) = (it.next(), it.next(), it.next())
    else {
        return false;
    };
    alg.tag == 16
        && data.tag == 4
        && der::first(alg_content)
            .filter(|(t, _)| t.tag == 6)
            .and_then(|(_, oid)| der::oid(oid))
            .is_some_and(|o| {
                o == "1.2.840.113549.1.5.13" || o.starts_with("1.2.840.113549.1.12.1.")
            })
}

/// The complete elements of the outer SEQUENCE (the first few).
fn outer_elements<'a>(h: &Head<'a>) -> Vec<(der::Tlv, &'a [u8])> {
    outer(h).map_or_else(Vec::new, |o| der::elements(o).take(16).collect())
}

/// Whether the whole input is visible (so a count of elements is final).
fn outer_complete(h: &Head<'_>) -> bool {
    to_u64(h.data.len()) == h.len
}

fn int_value(el: Option<&(der::Tlv, &[u8])>) -> Option<i64> {
    el.filter(|(t, _)| t.id == 0x02)
        .and_then(|(_, v)| der::integer(v))
}

/// Byte length of an INTEGER's magnitude (0 if not an INTEGER).
fn int_len(el: Option<&(der::Tlv, &[u8])>) -> usize {
    el.filter(|(t, _)| t.id == 0x02)
        .map_or(0, |(_, v)| v.strip_prefix(&[0]).unwrap_or(v).len())
}

/// Whether a SEQUENCE's content starts with an OBJECT IDENTIFIER (an
/// AlgorithmIdentifier).
fn is_algorithm(content: &[u8]) -> bool {
    der::first(content).is_some_and(|(t, o)| t.id == 0x06 && der::oid(o).is_some())
}

/// OCSPRequest: tbsRequest { [0]? [1]? requestList { Request { CertID {
/// AlgorithmIdentifier, OCTET STRING, OCTET STRING, INTEGER } } } }.
fn probe_ocsp_request(h: &Head<'_>) -> bool {
    let Some((t, tbs)) = outer(h).and_then(der::first) else {
        return false;
    };
    let list = der::elements(tbs)
        .find(|(t, _)| t.id != 0xa0 && t.id != 0xa1)
        .filter(|(t, _)| t.id == 0x30);
    let Some((tr, request)) = list.and_then(|(_, l)| der::first(l)) else {
        return false;
    };
    let Some((tc, cert_id)) = der::first(request) else {
        return false;
    };
    let ids: Vec<u8> = der::elements(cert_id).map(|(t, _)| t.id).take(5).collect();
    t.id == 0x30
        && tr.id == 0x30
        && tc.id == 0x30
        && ids == [0x30, 0x04, 0x04, 0x02]
        && der::first(cert_id).is_some_and(|(_, alg)| is_algorithm(alg))
}

/// OCSPResponse: { ENUMERATED status, [0] { ResponseBytes { OID, OCTETS } } }.
fn probe_ocsp_response(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    let Some((t, status)) = els.first() else {
        return false;
    };
    let status = der::integer(status);
    if t.id != 0x0a || !status.is_some_and(|s| (0..=6).contains(&s) && s != 4) {
        return false;
    }
    match els.get(1) {
        Some((t, bytes)) => {
            t.id == 0xa0
                && der::first(bytes)
                    .and_then(|(_, rb)| der::first(rb))
                    .is_some_and(|(t, o)| {
                        t.id == 0x06
                            && der::oid(o).is_some_and(|o| o.starts_with("1.3.6.1.5.5.7.48.1."))
                    })
        }
        None => outer_complete(h) && els.len() == 1 && status != Some(0),
    }
}

/// TimeStampReq: { INTEGER 1, MessageImprint { AlgorithmIdentifier, OCTETS }, ... }.
fn probe_ts_query(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    int_value(els.first()) == Some(1)
        && els.get(1).is_some_and(|(t, imprint)| {
            let ids: Vec<u8> = der::elements(imprint).map(|(t, _)| t.id).take(3).collect();
            t.id == 0x30
                && ids == [0x30, 0x04]
                && der::first(imprint).is_some_and(|(_, alg)| is_algorithm(alg))
        })
}

/// TimeStampResp: { PKIStatusInfo { INTEGER status, ... }, ContentInfo? }.
fn probe_ts_reply(h: &Head<'_>) -> bool {
    let Some(outer) = outer(h) else {
        return false;
    };
    let Some((t, info)) = der::first(outer) else {
        return false;
    };
    let status = der::first(info)
        .filter(|(t, _)| t.id == 0x02)
        .and_then(|(_, v)| der::integer(v));
    if t.id != 0x30 || !status.is_some_and(|s| (0..=5).contains(&s)) {
        return false;
    }
    // The token may extend beyond the probe window: check its start only.
    let rest = outer.get(first_len(outer)..).unwrap_or_default();
    match der::header(rest) {
        Some(token) if token.id == 0x30 => {
            let start = rest.get(to_usize(token.header)..).unwrap_or_default();
            der::first(start).is_some_and(|(t, o)| {
                t.id == 0x06 && der::oid(o).as_deref() == Some("1.2.840.113549.1.7.2")
            })
        }
        Some(_) => false,
        None => outer_complete(h) && rest.is_empty() && status.is_some_and(|s| s >= 2),
    }
}

/// PrivateKeyInfo: { INTEGER 0|1, AlgorithmIdentifier, OCTET STRING, [0]?, [1]? }.
fn probe_pkcs8(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    matches!(int_value(els.first()), Some(0 | 1))
        && els
            .get(1)
            .is_some_and(|(t, alg)| t.id == 0x30 && is_algorithm(alg))
        && els.get(2).is_some_and(|(t, _)| t.id == 0x04)
        && els
            .iter()
            .skip(3)
            .all(|(t, _)| t.id == 0xa0 || t.id == 0x81)
}

/// RSAPrivateKey: nine INTEGERs (two primes), version 0 or 1, a modulus
/// of 512 bits or more.
fn probe_rsa_private_key(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    els.len() >= 9
        && els.iter().take(9).all(|(t, _)| t.id == 0x02)
        && matches!(int_value(els.first()), Some(0 | 1))
        && int_len(els.get(1)) >= 64
}

/// RSAPublicKey: { modulus (512 bits or more), odd public exponent }.
fn probe_rsa_public_key(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    outer_complete(h)
        && els.len() == 2
        && int_len(els.first()) >= 64
        && int_value(els.get(1)).is_some_and(|e| e >= 3 && e % 2 == 1 && e != 5)
}

/// ECPrivateKey: { INTEGER 1, OCTET STRING, [0]?, [1]? }.
fn probe_ec_private_key(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    outer_complete(h)
        && els.len() <= 4
        && int_value(els.first()) == Some(1)
        && els
            .get(1)
            .is_some_and(|(t, k)| t.id == 0x04 && (16..=72).contains(&k.len()))
        && els
            .iter()
            .skip(2)
            .all(|(t, _)| t.id == 0xa0 || t.id == 0xa1)
}

/// OpenSSL's DSA private key: { 0, p, q, g, y, x }.
fn probe_dsa_private_key(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    els.len() == 6
        && els.iter().all(|(t, _)| t.id == 0x02)
        && int_value(els.first()) == Some(0)
        && int_len(els.get(1)) >= 64
        && (20..=32).contains(&int_len(els.get(2)))
}

/// SubjectPublicKeyInfo: { AlgorithmIdentifier, BIT STRING }.
fn probe_spki(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    outer_complete(h)
        && els.len() == 2
        && els
            .first()
            .is_some_and(|(t, alg)| t.id == 0x30 && is_algorithm(alg))
        && els.get(1).is_some_and(|(t, _)| t.id == 0x03)
}

/// DHParameter: { prime (512 bits or more), generator 2 or 5, length? }.
fn probe_dh_params(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    outer_complete(h)
        && (els.len() == 2 || (els.len() == 3 && int_len(els.get(2)) <= 4))
        && int_len(els.first()) >= 64
        && matches!(int_value(els.get(1)), Some(2 | 5))
}

/// Dss-Parms: { p (512 bits or more), q (160 to 256 bits), g }.
fn probe_dsa_params(h: &Head<'_>) -> bool {
    let els = outer_elements(h);
    outer_complete(h)
        && els.len() == 3
        && int_len(els.first()) >= 64
        && (20..=32).contains(&int_len(els.get(1)))
        && int_len(els.get(2)) >= 64
}

fn probe_der(h: &Head<'_>) -> bool {
    if outer(h).is_none() || h.len < 4 {
        return false;
    }
    if to_u64(h.data.len()) == h.len {
        der::is_der(h.data)
    } else {
        // Only the start is visible: its first child must at least parse.
        outer(h)
            .and_then(der::header)
            .is_some_and(|t| t.len.is_some())
    }
}

// ---------------------------------------------------------------------------
// Dissection

/// One constructed level being listed.
#[derive(Clone, Copy)]
struct Level {
    input: Input,
    /// The contents to list.
    span: Span,
    depth: u32,
    schema: &'static Schema,
}

/// Dissects `input` as DER with the generic schema (also used for nested
/// DER found elsewhere).
pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    dissect_with(cx, input, &schema::UNKNOWN, Kind::Generic).await
}

async fn dissect_with(cx: Cx, input: Input, schema: &'static Schema, kind: Kind) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, SUMMARY_READ)).await?;
    cx.annotate(annotation(kind, &head, input.span.len));
    match kind {
        Kind::Pkcs12 => cx.emit(p12::contents_node(input)),
        Kind::EncryptedKey => cx.emit(p12::decrypted_key_node(input)),
        _ => {}
    }
    elements(
        cx,
        Level {
            input,
            span: input.span,
            depth: 0,
            schema,
        },
    )
    .await
}

async fn elements(cx: Cx, level: Level) -> Result<()> {
    let region = level.span;
    let mut matcher = Matcher::new(level.schema);
    // The last object identifier among the children, for ANY DEFINED BY.
    let mut last_oid: Option<String> = None;
    // The algorithm of the last AlgorithmIdentifier among the children.
    let mut last_alg: Option<String> = None;
    let in_seq = matches!(level.schema, Schema::Seq(_));
    let mut pos = 0u64;
    while pos < region.len {
        let peek = cx.read_avail(region.sub(pos, HEADER_MAX)).await?;
        if level.depth == 0 && peek.first() == Some(&0) {
            cx.push(trailing(&cx, region.tail(pos)).await?).await;
            break;
        }
        let tlv = der::header(&peek).ok_or_else(|| {
            Diagnostic::malformed("invalid identifier or length octets")
                .at(region.sub(pos, to_u64(peek.len())))
        })?;
        let content_start = pos.saturating_add(tlv.header);
        let (content_len, eoc) = match tlv.len {
            Some(len) => (len, 0),
            None => (indefinite_len(&cx, region, content_start).await?, 2),
        };
        let total = tlv.header.saturating_add(content_len).saturating_add(eoc);
        let whole = region.sub(pos, total);
        let content = region.sub(content_start, content_len);
        let (mut name, schema) = matcher.child(tlv.id);
        let (renamed, schema) = schema.resolve(&Context {
            oid: last_oid.as_deref(),
            algorithm: last_alg.as_deref(),
            id: tlv.id,
        });
        name = renamed.or(name);
        if tlv.id == 0x06 && in_seq {
            let oid = cx.read_avail(content.sub(0, PREVIEW)).await?;
            last_oid = der::oid(&oid);
        }
        if tlv.id == 0x30 && in_seq {
            let head = cx.read_avail(content.sub(0, 64)).await?;
            if let Some((t, oid)) = der::first(&head)
                && t.is_universal(der::OID)
            {
                last_alg = der::oid(oid);
            }
        }
        let mut node = element(&cx, &level, &tlv, whole, content, name, schema).await?;
        if whole.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(whole.source, whole.offset, total),
                whole.len,
            ));
        }
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(total.max(1));
    }
    Ok(())
}

/// Bytes after the top-level element: zero padding (as in PE certificate
/// tables) or something else.
async fn trailing(cx: &Cx, span: Span) -> Result<Node> {
    let data = cx.read_avail(span.sub(0, PREVIEW)).await?;
    let zeros = span.len <= PREVIEW && data.iter().all(|&b| b == 0);
    let node = Node::new(if zeros { "Padding" } else { "Trailing data" })
        .span(span)
        .summary(format!("{:#x} bytes", span.len));
    Ok(node)
}

/// Content length of an indefinite-length element whose content starts at
/// `start`: everything up to the matching end-of-contents octets.
async fn indefinite_len(cx: &Cx, region: Span, start: u64) -> Result<u64> {
    let mut pos = start;
    let mut depth = 1u32;
    loop {
        cx.checkpoint().await;
        let peek = cx.read_avail(region.sub(pos, HEADER_MAX)).await?;
        if peek.len() < 2 {
            return Err(
                Diagnostic::truncated(region.sub(start, pos.saturating_sub(start)), 0)
                    .at(region.sub(pos, 2)),
            );
        }
        if peek.starts_with(&[0, 0]) {
            depth = depth.saturating_sub(1);
            if depth == 0 {
                return Ok(pos.saturating_sub(start));
            }
            pos = pos.saturating_add(2);
            continue;
        }
        let tlv = der::header(&peek).ok_or_else(|| {
            Diagnostic::malformed("invalid element inside indefinite-length content")
                .at(region.sub(pos, 2))
        })?;
        match tlv.len {
            Some(len) => pos = pos.saturating_add(tlv.header).saturating_add(len),
            None => {
                depth = depth.saturating_add(1);
                if depth > MAX_DEPTH {
                    return Err(Diagnostic::limit(format!(
                        "indefinite lengths nested deeper than {MAX_DEPTH}"
                    ))
                    .at(region.sub(pos, 2)));
                }
                pos = pos.saturating_add(tlv.header);
            }
        }
        if pos > region.len {
            return Err(Diagnostic::malformed("end-of-contents octets not found")
                .at(region.sub(start, region.len)));
        }
    }
}

async fn element(
    cx: &Cx,
    level: &Level,
    tlv: &Tlv,
    whole: Span,
    content: Span,
    name: Option<&'static str>,
    schema: &'static Schema,
) -> Result<Node> {
    let label = tlv.label();
    let node_name: Cow<'static, str> = match name {
        Some(name) => Cow::Borrowed(name),
        None => Cow::Owned(label.clone()),
    };
    let mut node = Node::new(node_name).span(whole);
    let mut summary = name.map(|_| label);
    let mut detail = None;
    if tlv.constructed && matches!(schema, Schema::Special(Special::Embedded)) {
        // A BER constructed OCTET STRING: its chunks, joined, are the content.
        node = node.lazy(
            crate::expander!(self::joined_octets: (Input, Span)),
            (level.input, content),
        );
        detail = Some("constructed, chunked".into());
    } else if tlv.constructed {
        detail = constructed_summary(cx, content, schema).await?;
        node = nested(node, level, content, schema);
    } else {
        let (n, d) = primitive(cx, level, tlv, content, node, schema).await?;
        node = n;
        detail = detail.or(d);
    }
    summary = match (summary, detail) {
        (Some(s), Some(d)) => Some(format!("{s}, {d}")),
        (s, d) => s.or(d),
    };
    if let Some(s) = summary {
        node = node.summary(s);
    }
    Ok(node)
}

/// Most chunks a constructed OCTET STRING is joined from.
const MAX_CHUNKS: usize = 1 << 16;

/// Joins the primitive chunks of a constructed (BER) OCTET STRING whose
/// content is `span` and dissects the result.
async fn joined_octets(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut pieces = Vec::new();
    // Regions being walked (innermost last) and the position in each.
    let mut stack = vec![(span, 0u64)];
    while let Some(&(region, pos)) = stack.last() {
        cx.checkpoint().await;
        if pos >= region.len {
            stack.pop();
            continue;
        }
        let peek = cx.read_avail(region.sub(pos, HEADER_MAX)).await?;
        if peek.starts_with(&[0, 0]) {
            stack.pop();
            continue;
        }
        let tlv = der::header(&peek).ok_or_else(|| {
            Diagnostic::malformed("invalid chunk of a constructed OCTET STRING")
                .at(region.sub(pos, 2))
        })?;
        let start = pos.saturating_add(tlv.header);
        let len = match tlv.len {
            Some(len) => len,
            None => indefinite_len(&cx, region, start).await?,
        };
        let eoc = if tlv.len.is_none() { 2 } else { 0 };
        if let Some(top) = stack.last_mut() {
            top.1 = start
                .saturating_add(len)
                .saturating_add(eoc)
                .max(pos.saturating_add(1));
        }
        if tlv.constructed {
            if stack.len() > to_usize(u64::from(MAX_DEPTH)) {
                return Err(Diagnostic::limit("chunks nested too deeply").at(region));
            }
            stack.push((region.sub(start, len), 0));
        } else {
            pieces.push(region.sub(start, len));
            if pieces.len() > MAX_CHUNKS {
                return Err(Diagnostic::limit("too many chunks").at(span));
            }
        }
    }
    let joined = cx
        .add_pieces_stepped(
            crate::span::Origin {
                parent: span,
                transform: "ber-octets",
            },
            &pieces,
        )
        .await?;
    cx.emit(crate::formats::embedded("Content", input.nested(joined)));
    Ok(())
}

/// Makes `node` expandable into the elements of `content`.
fn nested(node: Node, level: &Level, content: Span, schema: &'static Schema) -> Node {
    if level.depth >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "elements nested deeper than {MAX_DEPTH}"
        )));
    }
    node.lazy(
        crate::expander!(self::elements: Level),
        Level {
            input: level.input,
            span: content,
            depth: level.depth.saturating_add(1),
            schema: schema.body(),
        },
    )
}

/// A summary for a constructed element: the X.500 name it holds, or the
/// object identifier it starts with (an algorithm, attribute or extension),
/// with the value that follows it.
async fn constructed_summary(
    cx: &Cx,
    content: Span,
    schema: &'static Schema,
) -> Result<Option<String>> {
    if let Schema::Summary(summarize, _) = schema {
        let data = cx.read_avail(content.sub(0, PREVIEW)).await?;
        return Ok(summarize(&data));
    }
    if matches!(schema, Schema::Name) {
        let data = cx.read_avail(content.sub(0, PREVIEW)).await?;
        let name = der::name(&data);
        return Ok((!name.is_empty()).then_some(name));
    }
    if matches!(schema, Schema::SeqOf(..)) {
        // A list of object identifiers (purposes, capabilities): their names.
        let data = cx.read_avail(content.sub(0, 512)).await?;
        let oids: Option<Vec<String>> = der::elements(&data)
            .take(7)
            .map(|(t, o)| {
                t.is_universal(der::OID)
                    .then(|| der::display(&t, o))
                    .flatten()
            })
            .collect();
        return Ok(oids.filter(|o| !o.is_empty()).map(|o| {
            let more = if o.len() > 6 { ", …" } else { "" };
            format!(
                "{}{more}",
                o.iter().take(6).cloned().collect::<Vec<_>>().join(", ")
            )
        }));
    }
    let data = cx.read_avail(content.sub(0, 512)).await?;
    let mut kids = der::elements(&data);
    // "type = value" pairs only: longer sequences say more than that.
    let pair = data.len() < 512 && der::elements(&data).count() == 2;
    let Some((t, oid)) = kids.next() else {
        return Ok(None);
    };
    if !t.is_universal(der::OID) {
        return Ok(None);
    }
    let Some(dotted) = der::oid(oid) else {
        return Ok(None);
    };
    let mut out = oids::name(&dotted).map_or(dotted, str::to_owned);
    if let Some((vt, value)) = kids.next()
        && pair
        && !vt.constructed
        && !vt.is_universal(der::OCTET_STRING)
        && let Some(text) = der::display(&vt, value)
    {
        out = format!("{out} = {text}");
    }
    Ok(Some(out))
}

fn preview(data: &[u8]) -> Value {
    Value::Bytes(data.iter().take(PREVIEW_BYTES).copied().collect())
}

/// Decodes a primitive element's value onto `node`; returns it and a
/// detail for the summary.
async fn primitive(
    cx: &Cx,
    level: &Level,
    tlv: &Tlv,
    content: Span,
    node: Node,
    schema: &'static Schema,
) -> Result<(Node, Option<String>)> {
    // An IMPLICIT tag stands for the universal type the schema implies.
    let mut tlv = *tlv;
    let mut schema = schema;
    if tlv.class != der::CLASS_UNIVERSAL
        && let Some(tag) = schema.implied_tag()
    {
        tlv.class = der::CLASS_UNIVERSAL;
        tlv.tag = tag;
        if matches!(schema, Schema::Implicit(_)) {
            schema = &schema::UNKNOWN;
        }
    }
    let tlv = &tlv;
    if let Schema::Special(kind) = schema {
        return special(cx, level, tlv, content, node, *kind).await;
    }
    let is_string = tlv.is_universal(der::OCTET_STRING) || tlv.is_universal(der::BIT_STRING);
    if is_string && content.len > NESTED_MAX {
        // Large blobs (signed content, ...): detect their format on demand.
        let node = node.lazy(crate::formats::dissect_or_data, level.input.nested(content));
        return Ok((node, Some(format!("{:#x} bytes", content.len))));
    }
    let read = if is_string { NESTED_MAX } else { PREVIEW };
    let data = cx.read_avail(content.sub(0, read)).await?;
    let complete = to_u64(data.len()) == content.len;
    let len_detail = format!("{} bytes", content.len);
    if tlv.class != der::CLASS_UNIVERSAL {
        return Ok(match der::printable(&data) {
            // dNSName, rfc822Name, URI: internationalised host names.
            Some(text) if complete => {
                let unicode = crate::text::url::hosts_to_unicode(&text);
                (node.value(Value::Text(text)), unicode)
            }
            _ => (node.value(preview(&data)), Some(len_detail)),
        });
    }
    let out = match tlv.tag {
        der::BOOLEAN => (
            match data.first() {
                Some(&b) => node.value(Value::Bool(b != 0)),
                None => node,
            },
            None,
        ),
        der::NULL => (node, None),
        der::INTEGER | der::ENUMERATED => match der::integer(&data) {
            Some(v) => match (schema, u64::try_from(v)) {
                (Schema::Enum(table), Ok(raw)) => (
                    node.value(crate::formats::util::val::enumv(raw, 32, table)),
                    None,
                ),
                _ => (node.value(Value::Int { value: v, bits: 64 }), None),
            },
            None => (
                node.value(preview(data.strip_prefix(&[0]).unwrap_or(&data))),
                Some(format!("{}-bit", significant_bits(&data))),
            ),
        },
        der::OID => match der::oid(&data) {
            Some(dotted) => {
                let name = oids::name(&dotted);
                let node = node.value(Value::Text(dotted));
                (node, name.map(str::to_owned))
            }
            None => (
                node.diag(Diagnostic::malformed("invalid object identifier")),
                None,
            ),
        },
        der::BIT_STRING => {
            let unused = data.first().copied().unwrap_or(0);
            let bits = content
                .len
                .saturating_sub(1)
                .saturating_mul(8)
                .saturating_sub(unused.into());
            let body = data.get(1..).unwrap_or_default();
            let detail = Some(format!("{bits} bits"));
            if let Schema::Bits(names) = schema {
                (node.value(x509::bits_value(&data, names)), None)
            } else if let Schema::Encap(inner) = schema
                && complete
                && unused == 0
                && !body.is_empty()
                && der::is_der(body)
            {
                (
                    nested(node, level, content.tail(1), inner),
                    Some(format!("{bits} bits, encapsulates DER")),
                )
            } else if complete && unused == 0 && der::is_nested_der(body) {
                let inner = content.tail(1);
                (
                    nested(node, level, inner, &schema::UNKNOWN),
                    Some(format!("{bits} bits, encapsulates DER")),
                )
            } else {
                (node.value(preview(body)), detail)
            }
        }
        der::OCTET_STRING => {
            if let Schema::Encap(inner) = schema
                && complete
                && !data.is_empty()
                && der::is_der(&data)
            {
                (
                    nested(node, level, content, inner),
                    Some(format!("{len_detail}, encapsulates DER")),
                )
            } else if complete && der::is_nested_der(&data) {
                (
                    nested(node, level, content, &schema::UNKNOWN),
                    Some(format!("{len_detail}, encapsulates DER")),
                )
            } else {
                (node.value(preview(&data)), Some(len_detail))
            }
        }
        der::UTC_TIME | der::GENERALIZED_TIME => match der::time(tlv.tag, &data) {
            Some(t) => (node.value(Value::Timestamp { unix_seconds: t }), None),
            None => (
                node.value(Value::Text(String::from_utf8_lossy(&data).into_owned())),
                None,
            ),
        },
        tag => match der::string(tag, &data) {
            Some(text) => {
                let unicode = crate::text::url::hosts_to_unicode(&text);
                (node.value(Value::Text(text)), unicode)
            }
            None => (node.value(preview(&data)), Some(len_detail)),
        },
    };
    Ok(out)
}

/// Bits in a big-endian unsigned magnitude, for "2048-bit" summaries.
fn significant_bits(data: &[u8]) -> u64 {
    x509::integer_bits(data)
}

/// Decodes a primitive with a special decoder.
async fn special(
    cx: &Cx,
    level: &Level,
    tlv: &Tlv,
    content: Span,
    node: Node,
    kind: Special,
) -> Result<(Node, Option<String>)> {
    // A BIT STRING's content starts with its count of unused bits.
    let span = if tlv.is_universal(der::BIT_STRING) {
        content.tail(1)
    } else {
        content
    };
    let data = cx.read_avail(span.sub(0, PREVIEW)).await?;
    let complete = to_u64(data.len()) == span.len;
    let bytes = |n: usize| Value::Bytes(data.iter().take(n).copied().collect());
    Ok(match kind {
        Special::EcPoint => (
            node.value(bytes(PREVIEW_BYTES))
                .lazy(crate::expander!(x509::ec_point: Span), span),
            x509::ec_point_summary(&data),
        ),
        Special::RawKey => (
            node.value(bytes(64)),
            Some(format!("{}-byte key", span.len)),
        ),
        Special::IpAddress => match x509::ip_address(&data) {
            Some(ip) => (node.value(Value::Text(ip)), None),
            None => (
                node.value(bytes(PREVIEW_BYTES)),
                Some(format!("{} bytes", span.len)),
            ),
        },
        Special::KeyId if complete && data.len() <= 64 => (
            node.value(Value::Text(x509::colon_hex(&data))),
            Some(format!("{} bytes", span.len)),
        ),
        Special::KeyId => (
            node.value(bytes(PREVIEW_BYTES)),
            Some(format!("{} bytes", span.len)),
        ),
        Special::SctList => (
            node.lazy(crate::expander!(x509::sct_list: Span), span),
            Some(format!("{} bytes", span.len)),
        ),
        Special::Embedded => (
            node.lazy(crate::formats::dissect_or_data, level.input.nested(span)),
            Some(format!("{} bytes", span.len)),
        ),
    })
}
