//! ASCII armor: PEM (`-----BEGIN CERTIFICATE-----`), OpenPGP armor (with
//! its CRC-24 checksum and clear-signed messages) and RFC 4716 SSH2 public
//! keys (`---- BEGIN SSH2 PUBLIC KEY ----`).
//!
//! Blocks are a paged collection. Expanding one shows its headers and
//! base64 body; the body is decoded into a derived source and dissected
//! (a DER certificate, an OpenSSH key, OpenPGP packets ...).

use crate::cx::Cx;
use crate::error::{DiagKind, Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

use super::decode::{Transform, derive_with, preview};
use super::encoding::prepare;
use super::scan::Lines;
use super::{probe, text_node};

pub static FORMAT: Format = Format {
    name: "pem",
    title: "PEM (Privacy-Enhanced Mail) armor",
    extensions: &["pem", "crt", "cer", "csr", "key", "pub", "p7b", "p7c", "crl"],
    mime: "application/x-pem-file",
    probe: Probe::Custom(|h| armor(h).is_some_and(|k| k == Kind::Pem)),
    dissect: crate::expander!(dissect: Input),
};

pub static PGP: Format = Format {
    name: "pgp-armor",
    title: "OpenPGP ASCII armor",
    extensions: &["asc", "sig", "gpg"],
    mime: "application/pgp-encrypted",
    probe: Probe::Custom(|h| armor(h).is_some_and(|k| k == Kind::Pgp)),
    dissect: crate::expander!(dissect: Input),
};

pub static SSH2: Format = Format {
    name: "ssh2-public-key",
    title: "SSH2 public key (RFC 4716)",
    extensions: &["pub"],
    mime: "text/plain",
    probe: Probe::Custom(|h| armor(h).is_some_and(|k| k == Kind::Ssh2)),
    dissect: crate::expander!(dissect: Input),
};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum Kind {
    Pem,
    Pgp,
    Ssh2,
}

/// The label of a `-----BEGIN X-----` (or `---- BEGIN X ----`) line.
fn begin(line: &[u8]) -> Option<(Kind, &[u8])> {
    let t = probe::trim(line);
    if let Some(rest) = t.strip_prefix(b"-----BEGIN ") {
        let label = rest.strip_suffix(b"-----")?;
        let kind = if label.starts_with(b"PGP ") {
            Kind::Pgp
        } else {
            Kind::Pem
        };
        return Some((kind, label));
    }
    let label = t.strip_prefix(b"---- BEGIN ")?.strip_suffix(b" ----")?;
    Some((Kind::Ssh2, label))
}

fn end(line: &[u8], kind: Kind, label: &[u8]) -> bool {
    let t = probe::trim(line);
    let rest = match kind {
        Kind::Ssh2 => t.strip_prefix(b"---- END ").and_then(|r| r.strip_suffix(b" ----")),
        _ => t.strip_prefix(b"-----END ").and_then(|r| r.strip_suffix(b"-----")),
    };
    rest == Some(label)
}

/// The kind of the first armor block, if one begins at a line start near
/// the top of the input.
fn armor(h: &Head<'_>) -> Option<Kind> {
    let head = probe::head(h);
    let top = head.get(..head.len().min(4096)).unwrap_or_default();
    let found = probe::lines(top).find_map(begin)?;
    probe::is_text(h).then_some(found.0)
}

#[derive(Clone, Debug)]
struct Block {
    input: Input,
    span: Span,
    kind: Kind,
    label: String,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let input = prepared.input(input);
    let span = prepared.span;
    let mut lines = Lines::new(&cx, span);
    let mut labels: Vec<String> = Vec::new();
    let mut text: Option<(u64, u64)> = None;
    while let Some(line) = lines.next().await? {
        let Some((kind, label)) = begin(&line.bytes) else {
            if !line.is_blank() {
                let start = text.map_or(line.start, |(s, _)| s);
                text = Some((start, line.next));
            }
            continue;
        };
        if let Some((s, e)) = text.take() {
            push_text(&cx, span.sub(s, e.saturating_sub(s))).await?;
        }
        let label = String::from_utf8_lossy(label).into_owned();
        let label_bytes = label.as_bytes().to_vec();
        let start = line.start;
        // A clear-signed message ends where its signature begins.
        let signed = kind == Kind::Pgp && label == "PGP SIGNED MESSAGE";
        let mut closed = false;
        let stop = loop {
            let before = lines.pos();
            let Some(l) = lines.next().await? else {
                break before;
            };
            if signed && begin(&l.bytes).is_some() {
                lines.seek(before, l.number.saturating_sub(1));
                closed = true;
                break before;
            }
            if end(&l.bytes, kind, &label_bytes) {
                closed = true;
                break l.next;
            }
        };
        let block = span.sub(start, stop.saturating_sub(start));
        let mut node = Node::new(label.clone()).span(block).lazy(
            expand,
            Block {
                input,
                span: block,
                kind,
                label: label.clone(),
            },
        );
        node = node.summary(match kind {
            Kind::Pem => format!("PEM block, {:#x} bytes", block.len),
            Kind::Pgp => format!("OpenPGP armor, {:#x} bytes", block.len),
            Kind::Ssh2 => "RFC 4716 public key".to_owned(),
        });
        if !closed {
            node = node.diag(Diagnostic::new(DiagKind::Truncated, "END line missing"));
        }
        labels.push(label);
        cx.push(node).await;
    }
    if let Some((s, e)) = text.take() {
        push_text(&cx, span.sub(s, e.saturating_sub(s))).await?;
    }
    cx.annotate(annotation(&labels));
    Ok(())
}

async fn push_text(cx: &Cx, span: Span) -> Result<()> {
    let first = super::scan::Scanner::new(cx, span)
        .owned(0, span.len, 200)
        .await?;
    cx.push(
        Node::new("Text")
            .span(span)
            .summary(preview(&first.piece().text(), 80))
            .desc("Explanatory text outside the armored blocks"),
    )
    .await;
    Ok(())
}

fn annotation(labels: &[String]) -> String {
    let mut counts: Vec<(&str, u64)> = Vec::new();
    for l in labels {
        match counts.iter_mut().find(|(n, _)| *n == l.as_str()) {
            Some((_, c)) => *c = c.saturating_add(1),
            None => counts.push((l.as_str(), 1)),
        }
    }
    let parts: Vec<String> = counts
        .iter()
        .map(|(n, c)| if *c == 1 { (*n).to_owned() } else { format!("{c} × {n}") })
        .collect();
    match parts.as_slice() {
        [] => "ASCII armor (no blocks)".to_owned(),
        _ => preview(&parts.join(", "), 100),
    }
}

/// Whether `line` is an armor header (`Name: value`).
fn header_line(line: &[u8]) -> bool {
    let Some(colon) = line.iter().position(|&b| b == b':') else {
        return false;
    };
    let name = line.get(..colon).unwrap_or_default();
    !name.is_empty()
        && name.iter().all(|&b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
        && line.get(colon.saturating_add(1)).is_none_or(|&b| b == b' ')
}

/// OpenPGP's CRC-24 (RFC 4880, section 6.1).
fn crc24(data: &[u8]) -> u32 {
    let mut crc = 0x00b7_04ceu32;
    for &b in data {
        crc ^= u32::from(b) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x0100_0000 != 0 {
                crc ^= 0x0186_4cfb;
            }
        }
    }
    crc & 0x00ff_ffff
}

async fn expand(cx: Cx, b: Block) -> Result<()> {
    let mut lines = Lines::new(&cx, b.span);
    let Some(first) = lines.next().await? else {
        return Ok(());
    };
    cx.emit(Node::new("Begin").span(first.span).value(Value::Text(b.label.clone())));
    let label_bytes = b.label.as_bytes().to_vec();
    // Headers: `Name: value`, continued by indented lines (PEM, SSH2) or a
    // trailing backslash (SSH2).
    let mut body: Option<(u64, u64)> = None;
    let mut checksum = None;
    let mut end_line = None;
    let mut in_headers = true;
    // The previous header continues: on indented lines (RFC 1421) or after
    // a trailing backslash (RFC 4716).
    let mut after_header = false;
    let mut backslash = false;
    while let Some(line) = lines.next().await? {
        let p = line.piece();
        if end(&line.bytes, b.kind, &label_bytes) {
            end_line = Some(line);
            break;
        }
        if in_headers {
            let t = p.trim_end();
            let indented = p.first().is_some_and(|c| c == b' ' || c == b'\t');
            if backslash || (after_header && indented && !t.is_empty()) {
                backslash = t.last() == Some(b'\\');
                continue;
            }
            if header_line(t.bytes()) {
                let (name, value) = t.split_once(b':').unwrap_or((t, t.to(0)));
                let value = value.trim();
                after_header = true;
                // RFC 4716: a trailing backslash continues the value.
                let mut text = value.text();
                let mut value_span = value.span();
                while text.ends_with('\\') {
                    text.pop();
                    let Some(more) = lines.next().await? else {
                        break;
                    };
                    let m = more.piece().trim();
                    text.push_str(&m.text());
                    value_span = Span::new(
                        value_span.source,
                        value_span.offset,
                        m.span().end().saturating_sub(value_span.offset),
                    );
                }
                let text = text
                    .strip_prefix('"')
                    .and_then(|t| t.strip_suffix('"'))
                    .unwrap_or(&text)
                    .to_owned();
                cx.emit(text_node(name.text(), value_span, &text));
                continue;
            }
            in_headers = false;
            if t.is_empty() {
                continue;
            }
        }
        if b.kind == Kind::Pgp && p.trim().starts_with(b"=") && p.trim().len() == 5 {
            checksum = Some(line);
            continue;
        }
        if b.label == "PGP SIGNED MESSAGE" || !p.trim().is_empty() {
            let start = body.map_or(line.start, |(s, _)| s);
            body = Some((start, line.start.saturating_add(line.span.len)));
        }
    }
    let Some((start, stop)) = body else {
        if let Some(l) = end_line {
            cx.emit(Node::new("End").span(l.span));
        }
        return Ok(());
    };
    let body_span = b.span.sub(start, stop.saturating_sub(start));
    if b.label == "PGP SIGNED MESSAGE" {
        let text = super::scan::Scanner::new(&cx, body_span)
            .owned(0, body_span.len, super::VALUE_CAP)
            .await?;
        cx.emit(text_node("Signed text", body_span, &text.piece().text()));
        return Ok(());
    }
    let (decoded, error) = derive_with(&cx, body_span, Transform::Base64).await?;
    let mut data = Node::new("Data")
        .span(body_span)
        .summary(format!("base64, {:#x} bytes decoded", decoded.len))
        .lazy(crate::formats::dissect_or_data, b.input.nested(decoded));
    if let Some(e) = error {
        data = data.diag(e);
    }
    cx.emit(data);
    if let Some(line) = checksum {
        let text = line.piece().trim().from(1);
        let stored = super::decode::base64(text.bytes()).bytes;
        let stored = stored
            .iter()
            .fold(0u32, |acc, &x| (acc << 8) | u32::from(x));
        let mut node = Node::new("Checksum").span(text.span()).value(Value::UInt {
            value: stored.into(),
            bits: 24,
            radix: Radix::Hex,
        });
        if decoded.len <= cx.limits().max_read {
            let bytes = cx.read(decoded).await?;
            let computed = crc24(&bytes);
            node = if computed == stored {
                node.summary("CRC-24, valid")
            } else {
                node.diag(Diagnostic::warning(format!(
                    "CRC-24 mismatch: computed {computed:#08x}"
                )))
            };
        }
        cx.emit(node);
    }
    // A missing END line is flagged on the block's node.
    if let Some(l) = end_line {
        cx.emit(Node::new("End").span(l.span));
    }
    Ok(())
}
