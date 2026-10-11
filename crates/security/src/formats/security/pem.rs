//! PEM (RFC 7468) and the ASCII armor it shares with OpenPGP: blocks of
//! base64 between `-----BEGIN LABEL-----` and `-----END LABEL-----` lines.
//!
//! Each block is decoded into a derived source when expanded and dissected
//! by its label: certificates, CRLs, requests and PKCS#7 by their formats,
//! keys and anything else as generic DER.

use std::ops::Range;

use crate::bytes::{find, to_u64};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::Value;

/// Largest armored input we look through for blocks.
const MAX_TEXT: u64 = 16 << 20;
/// Blocks listed per file.
const MAX_BLOCKS: usize = 4096;

pub static FORMAT: Format = Format {
    name: "pem",
    title: "PEM encoded data (certificates, keys)",
    extensions: &["pem", "crt", "cer", "key", "csr", "pub"],
    mime: "application/x-pem-file",
    probe: Probe::Custom(|h| probe_armor(h, false)),
    dissect: crate::expander!(dissect: Input),
};

/// Whether the input starts (after blank lines and comments) with an
/// armor block: PEM (`pgp == false`) or OpenPGP.
pub fn probe_armor(h: &Head<'_>, pgp: bool) -> bool {
    let window = h.data.get(..4096).unwrap_or(h.data);
    let Some(at) = find_begin(window, 0) else {
        return false;
    };
    let before = window.get(..at).unwrap_or_default();
    let label_start = at.saturating_add(11);
    let is_pgp = window
        .get(label_start..)
        .is_some_and(|l| l.starts_with(b"PGP "));
    is_pgp == pgp
        && before.iter().all(|&b| b.is_ascii() && b != 0)
        && window
            .get(label_start..)
            .and_then(|l| l.iter().position(|&b| b == b'\n'))
            .is_some_and(|eol| {
                window
                    .get(label_start..label_start.saturating_add(eol))
                    .is_some_and(|line| line.trim_ascii_end().ends_with(b"-----"))
            })
}

/// The next `-----BEGIN ` at the start of a line, from `from`.
fn find_begin(text: &[u8], from: usize) -> Option<usize> {
    let mut at = from;
    loop {
        let i = find(text, b"-----BEGIN ", at)?;
        if i == 0 || text.get(i.saturating_sub(1)) == Some(&b'\n') {
            return Some(i);
        }
        at = i.saturating_add(1);
    }
}

/// One armored block, as ranges of the text.
#[derive(Clone, Debug)]
pub struct Block {
    pub label: String,
    pub whole: Range<usize>,
    pub headers: Vec<(String, String, Range<usize>)>,
    pub body: Range<usize>,
    /// OpenPGP's `=XXXX` CRC-24 line.
    pub checksum: Option<Range<usize>>,
    pub complete: bool,
    /// An OpenPGP cleartext signature's text (`PGP SIGNED MESSAGE`): the
    /// body is dash-escaped text, not base64, and the block ends where the
    /// `PGP SIGNATURE` block begins (RFC 4880 §7).
    pub cleartext: bool,
}

/// The label of an OpenPGP cleartext-signed message.
pub const SIGNED_MESSAGE: &str = "PGP SIGNED MESSAGE";
const SIGNATURE_BEGIN: &[u8] = b"-----BEGIN PGP SIGNATURE-----";

/// The line of `text` starting at `start` (before `end`): its range,
/// with its line ending.
fn line_at(text: &[u8], start: usize, end: usize) -> Option<Range<usize>> {
    if start >= end {
        return None;
    }
    let e = text
        .get(start..end)?
        .iter()
        .position(|&b| b == b'\n')
        .map_or(end, |e| start.saturating_add(e).saturating_add(1));
    Some(start..e)
}

/// `Key: value` header lines from `pos` up to a blank line (consumed) or
/// `end`; the headers and where the lines after them start.
fn header_lines(
    text: &[u8],
    mut pos: usize,
    end: usize,
) -> (Vec<(String, String, Range<usize>)>, usize) {
    let mut headers = Vec::new();
    while let Some(r) = line_at(text, pos, end) {
        let l = text.get(r.clone()).unwrap_or_default().trim_ascii();
        pos = r.end;
        if l.is_empty() {
            break;
        }
        if let Some(colon) = l.iter().position(|&b| b == b':') {
            let key = String::from_utf8_lossy(l.get(..colon).unwrap_or_default()).into_owned();
            let value =
                String::from_utf8_lossy(l.get(colon.saturating_add(1)..).unwrap_or_default())
                    .trim()
                    .to_owned();
            headers.push((key, value, r));
        }
    }
    (headers, pos)
}

/// A cleartext-signed message from its BEGIN line: hash headers, a blank
/// line, then the text up to the line ending before the signature block.
fn cleartext_block(text: &[u8], begin: usize, line_end: usize) -> Block {
    let mut sig = None;
    let mut from = line_end;
    while let Some(at) = find_begin(text, from) {
        if text
            .get(at..)
            .is_some_and(|t| t.starts_with(SIGNATURE_BEGIN))
        {
            sig = Some(at);
            break;
        }
        from = at.saturating_add(1);
    }
    let end = sig.unwrap_or(text.len());
    let (headers, body_start) = header_lines(text, line_end, end);
    // The line ending before the signature belongs to the separator.
    let mut body_end = end.max(body_start);
    if sig.is_some() {
        if text.get(..body_end).is_some_and(|t| t.ends_with(b"\r\n")) {
            body_end = body_end.saturating_sub(2);
        } else if text.get(..body_end).is_some_and(|t| t.ends_with(b"\n")) {
            body_end = body_end.saturating_sub(1);
        }
    }
    Block {
        label: SIGNED_MESSAGE.to_owned(),
        whole: begin..end,
        headers,
        body: body_start..body_end.max(body_start),
        checksum: None,
        complete: sig.is_some(),
        cleartext: true,
    }
}

/// Splits armored text into blocks.
pub async fn blocks(cx: &Cx, text: &[u8]) -> Vec<Block> {
    let mut out = Vec::new();
    let mut from = 0usize;
    while out.len() < MAX_BLOCKS {
        cx.checkpoint().await;
        let Some(block) = next_block(text, from) else {
            break;
        };
        from = block.whole.end.max(block.whole.start.saturating_add(1));
        out.push(block);
    }
    out
}

/// The next armored block of `text`, from `from`.
fn next_block(text: &[u8], from: usize) -> Option<Block> {
    let begin = find_begin(text, from)?;
    let line_end = text
        .get(begin..)
        .and_then(|t| t.iter().position(|&b| b == b'\n'))
        .map_or(text.len(), |e| begin.saturating_add(e).saturating_add(1));
    let line = text
        .get(begin..line_end)
        .unwrap_or_default()
        .trim_ascii_end();
    let label = line
        .get(11..line.len().saturating_sub(5))
        .map(|l| String::from_utf8_lossy(l).into_owned())
        .unwrap_or_default();
    if label == SIGNED_MESSAGE {
        return Some(cleartext_block(text, begin, line_end));
    }
    let end_marker = format!("-----END {label}-----");
    let end = find(text, end_marker.as_bytes(), line_end);
    let content_end = end.unwrap_or(text.len());
    // Headers ("Key: value") until a blank line, if any line has a colon.
    let mut headers = Vec::new();
    let mut pos = line_end;
    if let Some(r) = line_at(text, pos, content_end)
        && text.get(r).is_some_and(|l| l.contains(&b':'))
    {
        (headers, pos) = header_lines(text, pos, content_end);
    }
    let body_start = pos;
    let mut body_end = content_end;
    let mut checksum = None;
    // OpenPGP: a final line "=XXXX" is a CRC-24, not base64 data.
    let mut scan = body_start;
    while let Some(r) = line_at(text, scan, content_end) {
        if text.get(r.start) == Some(&b'=') {
            body_end = r.start;
            checksum = Some(r);
            break;
        }
        scan = r.end;
    }
    let whole_end = end.map_or(text.len(), |e| {
        let after = e.saturating_add(end_marker.len());
        match text.get(after) {
            Some(b'\r') if text.get(after.saturating_add(1)) == Some(&b'\n') => {
                after.saturating_add(2)
            }
            Some(b'\n') => after.saturating_add(1),
            _ => after,
        }
    });
    Some(Block {
        label,
        whole: begin..whole_end,
        headers,
        body: body_start..body_end,
        checksum,
        complete: end.is_some(),
        cleartext: false,
    })
}

/// Decodes a block's body into a derived source.
pub async fn decode_block(cx: &Cx, text: &[u8], span: Span, block: &Block) -> Result<Span> {
    let body = span.sub(to_u64(block.body.start), to_u64(block.body.len()));
    if block.cleartext {
        return Err(Diagnostic::malformed("cleartext-signed text, not base64").at(body));
    }
    let origin = Origin {
        parent: body,
        transform: "base64",
    };
    if let Some(found) = cx.derived(origin) {
        return Ok(found.span);
    }
    let bytes = text.get(block.body.clone()).unwrap_or_default();
    let decoded = crate::formats::text::decode::base64_strict(cx, bytes)
        .await
        .map_err(|at| Diagnostic::malformed("invalid base64").at(body.sub(to_u64(at), 1)))?;
    Ok(cx.add_derived(origin, decoded, body.len, None)?.span)
}

/// Reads the text of an armored input.
pub async fn read_text(cx: &Cx, span: Span) -> Result<Vec<u8>> {
    if span.len > MAX_TEXT {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_TEXT:#x} bytes are searched for blocks"
        )));
    }
    crate::codec::read_all(cx, span.sub(0, MAX_TEXT)).await
}

pub fn sub(span: Span, range: &Range<usize>) -> Span {
    span.sub(
        to_u64(range.start),
        to_u64(range.end.saturating_sub(range.start)),
    )
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let text = read_text(&cx, input.span).await?;
    let blocks = blocks(&cx, &text).await;
    let mut labels: Vec<(String, usize)> = Vec::new();
    for b in &blocks {
        match labels.iter_mut().find(|(l, _)| *l == b.label) {
            Some((_, n)) => *n = n.saturating_add(1),
            None => labels.push((b.label.clone(), 1)),
        }
    }
    let parts: Vec<String> = labels.iter().map(|(l, n)| format!("{n} × {l}")).collect();
    cx.annotate(format!("PEM, {}", parts.join(", ")));
    cx.set_count(Count::Exact(to_u64(blocks.len())));
    let mut last = 0usize;
    for block in blocks {
        if block.whole.start > last {
            let gap = text.get(last..block.whole.start).unwrap_or_default();
            if !gap.trim_ascii().is_empty() {
                cx.push(
                    Node::new("Text")
                        .span(sub(input.span, &(last..block.whole.start)))
                        .summary("text outside of blocks"),
                )
                .await;
            }
        }
        last = block.whole.end;
        let mut node = Node::new(block.label.clone())
            .span(sub(input.span, &block.whole))
            .lazy(expand_block, (input, block.clone()));
        if !block.complete {
            node = node.diag(
                Diagnostic::truncated(sub(input.span, &block.whole), 0)
                    .at(sub(input.span, &block.whole)),
            );
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn expand_block(cx: Cx, (input, block): (Input, Block)) -> Result<()> {
    let text = cx.read(sub(input.span, &(0..block.whole.end))).await?;
    for (key, value, range) in &block.headers {
        cx.emit(
            Node::new(key.clone())
                .span(sub(input.span, range))
                .value(Value::Text(value.clone())),
        );
    }
    let decoded = decode_block(&cx, &text, input.span, &block).await?;
    let inner = input.nested(decoded);
    let format = match block.label.as_str() {
        "CERTIFICATE" | "X509 CERTIFICATE" | "TRUSTED CERTIFICATE" => {
            Some(&crate::formats::asn1::X509)
        }
        "X509 CRL" => Some(&crate::formats::asn1::CRL),
        "CERTIFICATE REQUEST" | "NEW CERTIFICATE REQUEST" => Some(&crate::formats::asn1::CSR),
        "PKCS7" | "CMS" => Some(&crate::formats::asn1::PKCS7),
        "OPENSSH PRIVATE KEY" => Some(&super::openssh::OPENSSH_KEY),
        "PUBLIC KEY" => Some(&crate::formats::asn1::SPKI),
        "PRIVATE KEY" => Some(&crate::formats::asn1::PKCS8),
        "ENCRYPTED PRIVATE KEY" => Some(&crate::formats::asn1::PKCS8_ENCRYPTED),
        "RSA PRIVATE KEY" => Some(&crate::formats::asn1::RSA_PRIVATE_KEY),
        "RSA PUBLIC KEY" => Some(&crate::formats::asn1::RSA_PUBLIC_KEY),
        "EC PRIVATE KEY" => Some(&crate::formats::asn1::EC_PRIVATE_KEY),
        "DSA PRIVATE KEY" => Some(&crate::formats::asn1::DSA_PRIVATE_KEY),
        "DH PARAMETERS" => Some(&crate::formats::asn1::DH_PARAMS),
        "DSA PARAMETERS" => Some(&crate::formats::asn1::DSA_PARAMS),
        "OCSP REQUEST" => Some(&crate::formats::asn1::OCSP_REQUEST),
        "OCSP RESPONSE" => Some(&crate::formats::asn1::OCSP_RESPONSE),
        "AGE ENCRYPTED FILE" => Some(&super::age::AGE),
        _ => None,
    };
    let node = match format {
        _ if block
            .headers
            .iter()
            .any(|(k, v, _)| k == "Proc-Type" && v.contains("ENCRYPTED")) =>
        {
            Node::new("Encrypted data")
                .span(decoded)
                .diag(Diagnostic::unsupported("encrypted PEM block"))
        }
        Some(format) => crate::formats::embedded_as("Contents", inner, format),
        None => crate::formats::embedded_as("Contents", inner, &crate::formats::asn1::DER),
    };
    cx.emit(node.summary(format!("{} bytes", decoded.len)));
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::indexing_slicing)]
mod tests {
    use super::*;

    #[test]
    fn blocks() {
        let text = b"junk\n-----BEGIN A B-----\nK: v\n\nAAAA\n=abcd\n-----END A B-----\n";
        let b: Vec<Block> = next_block(text, 0).into_iter().collect();
        assert_eq!(b.len(), 1);
        assert!(next_block(text, b[0].whole.end).is_none());
        assert_eq!(b[0].label, "A B");
        assert_eq!(b[0].headers.len(), 1);
        assert_eq!(&text[b[0].body.clone()], b"AAAA\n");
        assert!(b[0].checksum.is_some() && b[0].complete);
    }

    #[test]
    fn cleartext_signed_message() {
        let text = b"-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nhello\n- -dash\n\
            -----BEGIN PGP SIGNATURE-----\n\nAAAA\n=abcd\n-----END PGP SIGNATURE-----\n";
        let first = next_block(text, 0).unwrap();
        assert!(first.cleartext && first.complete);
        assert_eq!(first.headers.len(), 1);
        assert_eq!(&text[first.body.clone()], b"hello\n- -dash");
        let second = next_block(text, first.whole.end).unwrap();
        assert_eq!(second.label, "PGP SIGNATURE");
        assert_eq!(second.whole.start, first.whole.end);
        assert_eq!(text[second.body.clone()].trim_ascii(), b"AAAA");
        assert!(!second.cleartext && second.checksum.is_some());
    }
}
