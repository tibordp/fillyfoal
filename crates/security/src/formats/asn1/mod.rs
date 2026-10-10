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

use std::borrow::Cow;

use der::Tlv;
use schema::{Matcher, Schema};

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::civil::date;
use crate::formats::util::fmt::plural;
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
    Pkcs12,
    EncryptedKey,
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

fn probe_pkcs7(h: &Head<'_>) -> bool {
    let Some(outer) = outer(h) else {
        return false;
    };
    let Some((t, oid)) = der::first(outer) else {
        return false;
    };
    // The content may extend beyond the probe window: check its header only.
    let rest = outer.get(first_len(outer)..).unwrap_or_default();
    t.id == 0x06
        && der::oid(oid).is_some_and(|o| o.starts_with("1.2.840.113549.1.7."))
        && der::header(rest).is_some_and(|next| next.id == 0xa0)
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
        let (renamed, schema) = schema.resolve(last_oid.as_deref());
        name = renamed.or(name);
        if tlv.id == 0x06 && matches!(level.schema, Schema::Seq(_)) {
            let oid = cx.read_avail(content.sub(0, PREVIEW)).await?;
            last_oid = der::oid(&oid);
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
    if tlv.constructed {
        detail = constructed_summary(cx, content, schema).await?;
        node = nested(node, level, content, schema);
    } else {
        let (n, d) = primitive(cx, level, tlv, content, node).await?;
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
            schema,
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
    if matches!(schema, Schema::Name) {
        let data = cx.read_avail(content.sub(0, PREVIEW)).await?;
        let name = der::name(&data);
        return Ok((!name.is_empty()).then_some(name));
    }
    let data = cx.read_avail(content.sub(0, 512)).await?;
    let mut kids = der::elements(&data);
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
) -> Result<(Node, Option<String>)> {
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
            Some(v) => (node.value(Value::Int { value: v, bits: 64 }), None),
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
            if complete && unused == 0 && der::is_nested_der(body) {
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
            if complete && der::is_nested_der(&data) {
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

// ---------------------------------------------------------------------------
// Summaries for the file node

fn annotation(kind: Kind, head: &[u8], len: u64) -> String {
    let outer = der::first(head);
    let detail = outer.and_then(|(tlv, content)| match kind {
        Kind::Generic => Some(format!("{}, {} bytes", tlv.label(), len)),
        Kind::Certificate => certificate_summary(content),
        Kind::Crl => crl_summary(content),
        Kind::Csr => csr_summary(content),
        Kind::Pkcs7 => pkcs7_summary(content),
        Kind::Pkcs12 => pkcs12_summary(content),
        Kind::EncryptedKey => {
            der::first(content).map(|(_, alg)| format!("encrypted with {}", pbe::describe(alg)))
        }
    });
    let title = match kind {
        Kind::Generic => "ASN.1 DER",
        Kind::Certificate => "X.509 certificate",
        Kind::Crl => "X.509 CRL",
        Kind::Csr => "PKCS#10 certificate request",
        Kind::Pkcs7 => "PKCS#7",
        Kind::Pkcs12 => "PKCS#12 key store",
        Kind::EncryptedKey => "Encrypted private key (PKCS#8)",
    };
    match detail {
        Some(d) => format!("{title}, {d}"),
        None => title.to_owned(),
    }
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

fn certificate_summary(cert: &[u8]) -> Option<String> {
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
    let (_, signature) = fields.next()?;
    let (_, issuer) = fields.next()?;
    let (_, validity) = fields.next()?;
    let (_, subject) = fields.next()?;
    let mut times = der::elements(validity).filter_map(|(t, c)| der::time(t.tag, c));
    let (from, until) = (times.next(), times.next());
    let subject_name = der::name(subject);
    let mut out = format!("v{version}, {subject_name}");
    if issuer == subject {
        out.push_str(", self-signed");
    } else {
        out = format!("{out}, issued by {}", der::name(issuer));
    }
    if let (Some(from), Some(until)) = (from, until) {
        out = format!("{out}, valid {} to {}", date(from), date(until));
    }
    if let Some(alg) = algorithm(signature) {
        out = format!("{out}, {alg}");
    }
    Some(out)
}

fn crl_summary(list: &[u8]) -> Option<String> {
    let (_, tbs) = der::first(list)?;
    let mut fields = der::elements(tbs).peekable();
    if fields.peek().is_some_and(|(t, _)| t.id == 0x02) {
        fields.next();
    }
    let _signature = fields.next()?;
    let (_, issuer) = fields.next()?;
    let (t, this_update) = fields.next()?;
    let mut out = format!("issued by {}", der::name(issuer));
    if let Some(time) = der::time(t.tag, this_update) {
        out = format!("{out}, updated {}", date(time));
    }
    let revoked = fields
        .find(|(t, _)| t.id == 0x30)
        .map_or(0, |(_, list)| der::elements(list).count());
    Some(format!("{out}, {revoked} revoked"))
}

fn csr_summary(request: &[u8]) -> Option<String> {
    let (_, info) = der::first(request)?;
    let mut fields = der::elements(info);
    let _version = fields.next()?;
    let (_, subject) = fields.next()?;
    let (_, spki) = fields.next()?;
    let key = der::first(spki).and_then(|(_, alg)| algorithm(alg));
    let mut out = format!("for {}", der::name(subject));
    if let Some(key) = key {
        out = format!("{out}, {key}");
    }
    Some(out)
}

fn pkcs7_summary(info: &[u8]) -> Option<String> {
    let mut fields = der::elements(info);
    let (_, oid) = fields.next()?;
    let kind = oid_name(oid);
    if der::oid(oid).as_deref() != Some("1.2.840.113549.1.7.2") {
        return Some(kind);
    }
    let (_, explicit) = fields.next()?;
    let (_, signed) = der::first(explicit)?;
    let mut certificates = 0;
    let mut signers = 0;
    let mut content = None;
    for (t, c) in der::elements(signed) {
        match t.id {
            0x30 => content = encapsulated_summary(c),
            0xa0 => certificates = der::elements(c).count(),
            0x31 => signers = der::elements(c).count(),
            _ => {}
        }
    }
    let mut out = kind;
    if let Some(content) = content {
        out = format!("{out} ({content})");
    }
    Some(format!(
        "{out}, {}, {}",
        plural(to_u64(certificates), "certificate"),
        plural(to_u64(signers), "signer")
    ))
}

/// The content type of an EncapsulatedContentInfo, and for Authenticode
/// (SpcIndirectDataContent) the algorithm of the signed file digest.
fn encapsulated_summary(info: &[u8]) -> Option<String> {
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

fn pkcs12_summary(pfx: &[u8]) -> Option<String> {
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
