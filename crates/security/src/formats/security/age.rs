//! age encrypted files (`age-encryption.org/v1`, <https://age-encryption.org/v1>):
//! a text header of recipient stanzas (each a type, arguments and a
//! base64 body wrapping the file key) closed by an HMAC line, then the
//! binary payload: a 16-byte nonce and ChaCha20-Poly1305 STREAM chunks of
//! 64 KiB plaintext, each with a 16-byte tag. ASCII-armored files are PEM
//! blocks (`AGE ENCRYPTED FILE`), handed here by the PEM dissector.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{text, uint};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

declare_format!(pub AGE = "age", "age-encrypted file", ["age"], "application/x-age",
    Probe::Magic(&[(0, b"age-encryption.org/v1\n")]), age);

/// Most header bytes read (the header is a few hundred bytes per stanza).
const HEADER_MAX: u64 = 1 << 20;
/// Payload plaintext per STREAM chunk, and the Poly1305 tag after it.
const CHUNK: u64 = 64 * 1024;
const TAG: u64 = 16;
/// Most chunks listed.
const MAX_CHUNKS: u64 = 1 << 24;

/// Decodes unpadded standard base64 (as age writes it).
fn base64(s: &[u8]) -> Option<Vec<u8>> {
    let mut out = Vec::with_capacity(s.len().saturating_mul(3) / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &b in s {
        let v = crate::codec::filters::base64_value(b)?;
        acc = (acc << 6) | u32::from(v);
        bits = bits.saturating_add(6);
        if bits >= 8 {
            bits = bits.saturating_sub(8);
            out.push(u8::try_from((acc >> bits) & 0xff).unwrap_or(0));
        }
    }
    Some(out)
}

/// One header line: its text and span (without the newline).
struct Line<'a> {
    text: &'a [u8],
    at: u64,
}

fn line_span(file: Span, line: &Line<'_>) -> Span {
    file.sub(line.at, to_u64(line.text.len()))
}

async fn age(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, HEADER_MAX)).await?;
    // Split the header into lines up to the MAC line.
    let mut lines = Vec::new();
    let mut at = 0usize;
    let mut mac = None;
    while at < head.len() {
        let end = head
            .get(at..)
            .and_then(|r| r.iter().position(|&b| b == b'\n'))
            .map(|p| at.saturating_add(p));
        let Some(end) = end else {
            break;
        };
        let text = head.get(at..end).unwrap_or_default();
        let line = Line {
            text,
            at: to_u64(at),
        };
        if text.starts_with(b"---") {
            mac = Some(line);
            at = end.saturating_add(1);
            break;
        }
        lines.push(line);
        at = end.saturating_add(1);
        if lines.len().is_multiple_of(1024) {
            cx.checkpoint().await;
        }
    }
    let Some(mac) = mac else {
        return Err(
            Diagnostic::malformed("no header MAC line (---)").at(file.sub(0, to_u64(head.len())))
        );
    };
    let mut it = lines.into_iter().peekable();
    if let Some(version) = it.next() {
        cx.emit(
            Node::new("Version")
                .span(line_span(file, &version))
                .value(text(String::from_utf8_lossy(version.text).into_owned())),
        );
    }
    let mut kinds = Vec::new();
    while let Some(first) = it.next() {
        let Some(args) = first.text.strip_prefix(b"-> ") else {
            cx.push(
                Node::new("Unexpected line")
                    .span(line_span(file, &first))
                    .diag(Diagnostic::malformed("expected a stanza (-> type ...)")),
            )
            .await;
            continue;
        };
        // The body: lines of 64 columns, ending with a shorter one.
        let mut body = Vec::new();
        while let Some(next) = it.peek() {
            if next.text.starts_with(b"-> ") {
                break;
            }
            let full = next.text.len() == 64;
            if let Some(l) = it.next() {
                body.push(l);
            }
            if !full {
                break;
            }
        }
        let words: Vec<String> = args
            .split(|&b| b == b' ')
            .map(|w| String::from_utf8_lossy(w).into_owned())
            .collect();
        let kind = words.first().cloned().unwrap_or_default();
        kinds.push(kind.clone());
        let end = body.last().map_or_else(
            || first.at.saturating_add(to_u64(first.text.len())),
            |l| l.at.saturating_add(to_u64(l.text.len())),
        );
        let span = file.sub(first.at, end.saturating_add(1).saturating_sub(first.at));
        let body_text: Vec<u8> = body.iter().flat_map(|l| l.text.iter().copied()).collect();
        let body_span = body
            .first()
            .map(|l| file.sub(l.at, end.saturating_sub(l.at)));
        let summary = stanza_summary(&kind, &words);
        cx.push(
            Node::new(format!("Recipient stanza ({kind})"))
                .span(span)
                .summary(summary)
                .lazy(
                    crate::expander!(self::stanza: (Span, Option<Span>, Vec<String>, Vec<u8>)),
                    (line_span(file, &first), body_span, words, body_text),
                ),
        )
        .await;
    }
    let mac_span = line_span(file, &mac);
    let mac_b64 = mac.text.strip_prefix(b"--- ").unwrap_or_default();
    let mut mac_node = Node::new("Header MAC").span(mac_span);
    match base64(mac_b64) {
        Some(m) if m.len() == 32 => {
            mac_node = mac_node
                .value(Value::Bytes(m))
                .summary("HMAC-SHA-256 of the header under a key derived from the file key");
        }
        _ => mac_node = mac_node.diag(Diagnostic::malformed("not a 32-byte base64 MAC")),
    }
    cx.emit(mac_node);
    let payload = file.tail(to_u64(at));
    let chunks = chunk_count(payload.len.saturating_sub(16));
    cx.emit(
        Node::new("Payload")
            .span(payload)
            .summary(format!(
                "{}, {} of plaintext",
                plural(chunks, "chunk"),
                size(plaintext(payload.len.saturating_sub(16)))
            ))
            .lazy(crate::expander!(self::payload: Span), payload),
    );
    cx.annotate(format!(
        "age, {} ({}), {} of plaintext",
        plural(to_u64(kinds.len()), "recipient"),
        kinds.join(", "),
        size(plaintext(payload.len.saturating_sub(16)))
    ));
    Ok(())
}

/// STREAM chunks in `len` bytes of ciphertext (at least one, possibly a
/// final chunk holding only its tag).
fn chunk_count(len: u64) -> u64 {
    len.div_ceil(CHUNK.saturating_add(TAG)).max(1)
}

/// Plaintext bytes in `len` bytes of ciphertext.
fn plaintext(len: u64) -> u64 {
    len.saturating_sub(chunk_count(len).saturating_mul(TAG))
}

fn stanza_summary(kind: &str, words: &[String]) -> String {
    match (kind, words.get(1), words.get(2)) {
        ("X25519", _, _) => "X25519 recipient".into(),
        ("scrypt", _, Some(n)) => format!("passphrase, scrypt work factor 2^{n}"),
        ("ssh-ed25519", Some(tag), _) => format!("SSH Ed25519 key, tag {tag}"),
        ("ssh-rsa", Some(tag), _) => format!("SSH RSA key, tag {tag}"),
        ("piv-p256", Some(tag), _) => format!("PIV P-256 key, tag {tag}"),
        (k, _, _) if k.ends_with("-grease") => "grease (ignored)".into(),
        _ => format!("{} arguments", words.len().saturating_sub(1)),
    }
}

/// What a stanza argument is, by stanza type and position.
fn argument(kind: &str, i: usize) -> (&'static str, Option<usize>) {
    match (kind, i) {
        ("X25519", 0) => ("Ephemeral share", Some(32)),
        ("scrypt", 0) => ("Salt", Some(16)),
        ("scrypt", 1) => ("Work factor (log2 N)", None),
        ("ssh-ed25519", 0) | ("ssh-rsa", 0) | ("piv-p256", 0) => ("Key tag", Some(4)),
        ("ssh-ed25519", 1) => ("Ephemeral share", Some(32)),
        ("piv-p256", 1) => ("Ephemeral share", Some(33)),
        _ => ("Argument", None),
    }
}

async fn stanza(
    cx: Cx,
    (line, body, words, body_text): (Span, Option<Span>, Vec<String>, Vec<u8>),
) -> Result<()> {
    let kind = words.first().cloned().unwrap_or_default();
    cx.emit(
        Node::new("Type")
            .span(line.sub(3, to_u64(kind.len())))
            .value(text(kind.clone())),
    );
    let mut pos = 3u64.saturating_add(to_u64(kind.len())).saturating_add(1);
    for (i, word) in words.iter().skip(1).enumerate() {
        let span = line.sub(pos, to_u64(word.len()));
        pos = pos.saturating_add(to_u64(word.len())).saturating_add(1);
        let (name, bytes) = argument(&kind, i);
        let mut node = Node::new(name).span(span);
        node = match (bytes, base64(word.as_bytes())) {
            (Some(n), Some(raw)) if raw.len() == n => {
                node.value(Value::Bytes(raw)).summary(format!("{n} bytes"))
            }
            (Some(n), _) => node
                .value(text(word.clone()))
                .diag(Diagnostic::malformed(format!(
                    "expected {n} bytes of base64"
                ))),
            (None, _) => match word.parse::<u64>() {
                Ok(v) if name.starts_with("Work") => {
                    node.value(uint(v, 8)).summary(format!("N = 2^{v}"))
                }
                _ => node.value(text(word.clone())),
            },
        };
        cx.emit(node);
    }
    let Some(body) = body else {
        return Ok(());
    };
    let decoded = base64(&body_text);
    let mut node = Node::new("Body").span(body);
    node = match decoded {
        Some(raw) => {
            let what = match kind.as_str() {
                "X25519" | "ssh-ed25519" | "scrypt" | "piv-p256" if raw.len() == 32 => {
                    "file key wrapped with ChaCha20-Poly1305 (16 bytes and a tag)"
                }
                "ssh-rsa" => "file key encrypted with RSA-OAEP (SHA-256)",
                _ => "base64",
            };
            let n = raw.len();
            node.value(Value::Bytes(raw.into_iter().take(64).collect()))
                .summary(format!("{n} bytes, {what}"))
        }
        None => node.diag(Diagnostic::malformed("invalid base64 body")),
    };
    cx.emit(node);
    Ok(())
}

async fn payload(cx: Cx, payload: Span) -> Result<()> {
    cx.emit(
        Node::new("Nonce")
            .span(payload.sub(0, 16))
            .value(Value::Bytes(cx.read_avail(payload.sub(0, 16)).await?))
            .desc("with the file key, derives the payload key (HKDF-SHA-256)"),
    );
    let body = payload.tail(16);
    let chunks = chunk_count(body.len).min(MAX_CHUNKS);
    let step = CHUNK.saturating_add(TAG);
    for i in 0..chunks {
        let span = body.sub(i.saturating_mul(step), step);
        let last = i.saturating_add(1) == chunks;
        cx.push(
            Node::new(format!("Chunk {i}"))
                .span(span)
                .summary(format!(
                    "{} plaintext + 16-byte tag{}",
                    size(span.len.saturating_sub(TAG)),
                    if last { ", final" } else { "" }
                ))
                .diag(Diagnostic::note("ChaCha20-Poly1305 (needs the file key)")),
        )
        .await;
    }
    Ok(())
}
