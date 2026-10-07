//! OpenSSH keys: `authorized_keys`, `known_hosts` and `.pub` files (one key
//! per line) and the binary public key blob inside them (also used by
//! certificates and by `openssh-key-v1` private keys, `security::openssh`).

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Format, Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

use super::decode::{Transform, decoded_node};
use super::encoding::prepare;
use super::piece::Piece;
use super::scan::Lines;
use super::{plural, probe, text_node};

pub static KEYS: Format = Format {
    name: "openssh-keys",
    title: "OpenSSH public keys",
    extensions: &["pub"],
    mime: "text/plain",
    probe: Probe::Custom(probe_keys),
    dissect: crate::expander!(dissect_keys: Input),
};

pub static BLOB: Format = Format {
    name: "ssh-key-blob",
    title: "SSH public key blob",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe_blob),
    dissect: crate::expander!(dissect_blob: Input),
};

const BE: Endian = Endian::Big;

/// Whether `t` names an SSH public key algorithm.
fn is_key_type(t: &[u8]) -> bool {
    const TYPES: &[&[u8]] = &[
        b"ssh-rsa",
        b"ssh-dss",
        b"ssh-ed25519",
        b"ssh-ed448",
        b"ecdsa-sha2-nistp256",
        b"ecdsa-sha2-nistp384",
        b"ecdsa-sha2-nistp521",
        b"sk-ssh-ed25519@openssh.com",
        b"sk-ecdsa-sha2-nistp256@openssh.com",
        b"rsa-sha2-256",
        b"rsa-sha2-512",
    ];
    TYPES.contains(&t)
        || t.strip_suffix(b"-cert-v01@openssh.com")
            .is_some_and(|base| TYPES.iter().any(|ty| ty.starts_with(base)))
}

// ---------------------------------------------------------------------------
// Key lines

/// Whitespace-separated words, keeping quoted parts (`command="a b"`)
/// together.
fn words(line: Piece<'_>) -> Vec<Piece<'_>> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let b = line.bytes();
    while i < b.len() {
        while b.get(i).is_some_and(u8::is_ascii_whitespace) {
            i = i.saturating_add(1);
        }
        let start = i;
        let mut quoted = false;
        while let Some(&c) = b.get(i) {
            if c == b'\\' && quoted {
                i = i.saturating_add(2);
                continue;
            }
            if c == b'"' {
                quoted = !quoted;
            } else if c.is_ascii_whitespace() && !quoted {
                break;
            }
            i = i.saturating_add(1);
        }
        if i > start {
            out.push(line.slice(start, i));
        }
    }
    out
}

/// A parsed key line: prefix words, type, base64 key, comment.
struct KeyLine<'a> {
    prefix: Vec<Piece<'a>>,
    kind: Piece<'a>,
    key: Piece<'a>,
    comment: Option<Piece<'a>>,
}

fn key_line(line: Piece<'_>) -> Option<KeyLine<'_>> {
    let w = words(line);
    let at = w.iter().enumerate().position(|(i, word)| {
        is_key_type(word.bytes())
            && w.get(i.saturating_add(1))
                .is_some_and(|k| k.starts_with(b"AAAA"))
    })?;
    let kind = *w.get(at)?;
    let key = *w.get(at.saturating_add(1))?;
    let comment = w
        .get(at.saturating_add(2))
        .map(|_| line.after(&key).trim())
        .filter(|c| !c.is_empty());
    Some(KeyLine {
        prefix: w.get(..at).unwrap_or_default().to_vec(),
        kind,
        key,
        comment,
    })
}

fn probe_keys(h: &Head<'_>) -> bool {
    let head = probe::head(h);
    let Some(first) = probe::significant(&head, &[b"#"]).next() else {
        return false;
    };
    let span = Span::new(crate::span::SourceId(0), 0, 0);
    key_line(Piece::new(first, span)).is_some() && probe::is_text(h)
}

/// Whether the words before the key are known_hosts host patterns.
fn hosts_like(prefix: &[Piece<'_>]) -> bool {
    prefix.iter().any(|p| {
        let b = p.bytes();
        b.starts_with(b"|1|")
            || (!b.starts_with(b"@")
                && !b.contains(&b'=')
                && (b.contains(&b'.') || b.contains(&b',') || b.starts_with(b"[")))
    })
}

pub async fn dissect_keys(cx: Cx, input: Input) -> Result<()> {
    let prepared = prepare(&cx, input).await?;
    let input = prepared.input(input);
    let mut lines = Lines::new(&cx, prepared.span);
    let mut keys = 0u64;
    let mut known_hosts = false;
    while let Some(line) = lines.next().await? {
        let p = line.piece().trim();
        if p.is_empty() || p.first() == Some(b'#') {
            continue;
        }
        let Some(k) = key_line(p) else {
            cx.push(
                text_node(format!("Line {}", line.number), line.span, &p.text())
                    .diag(Diagnostic::malformed("not a public key line")),
            )
            .await;
            continue;
        };
        keys = keys.saturating_add(1);
        let hosts = hosts_like(&k.prefix);
        known_hosts |= hosts;
        let name = match (&k.comment, hosts, k.prefix.last()) {
            (_, true, Some(h)) if h.starts_with(b"|1|") => "(hashed host)".to_owned(),
            (_, true, Some(h)) => h.text(),
            (Some(c), _, _) => c.text(),
            _ => k.kind.text(),
        };
        let bits = key_bits(k.kind.bytes(), &super::decode::base64(k.key.bytes()).bytes);
        let mut summary = k.kind.text();
        if let Some(bits) = bits {
            summary = format!("{summary}, {bits} bits");
        }
        cx.push(
            Node::new(name)
                .span(line.span)
                .summary(summary)
                .lazy(key_fields, (input, line.span)),
        )
        .await;
    }
    let what = if known_hosts {
        "OpenSSH known hosts"
    } else {
        "OpenSSH public keys"
    };
    cx.annotate(format!("{what}, {}", plural(keys, "key", "keys")));
    Ok(())
}

async fn key_fields(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let owned = super::scan::Scanner::new(&cx, span)
        .owned(0, span.len, super::scan::LINE_CAP)
        .await?;
    let Some(k) = key_line(owned.piece()) else {
        return Ok(());
    };
    let hosts = hosts_like(&k.prefix);
    for p in &k.prefix {
        let name = if p.starts_with(b"@") {
            "Marker"
        } else if hosts {
            "Hosts"
        } else {
            "Options"
        };
        let mut node = text_node(name, p.span(), &p.text());
        if p.starts_with(b"|1|") {
            node = node.summary("hashed host name");
        }
        cx.emit(node);
    }
    cx.emit(text_node("Key type", k.kind.span(), &k.kind.text()));
    cx.emit(decoded_node("Key", input, k.key.span(), Transform::Base64).summary("base64"));
    if let Some(c) = k.comment {
        cx.emit(text_node("Comment", c.span(), &c.text()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Binary key blobs (RFC 4253 wire encoding)

fn probe_blob(h: &Head<'_>) -> bool {
    let Some(len) = crate::bytes::u32_be(h.data, 0) else {
        return false;
    };
    let len = crate::bytes::to_usize(len.into());
    (7..=64).contains(&len)
        && h.data
            .get(4..4usize.saturating_add(len))
            .is_some_and(is_key_type)
}

/// Key size in bits, from a decoded blob.
pub fn key_bits(kind: &[u8], blob: &[u8]) -> Option<u64> {
    let base = kind.strip_suffix(b"-cert-v01@openssh.com").unwrap_or(kind);
    match base {
        b"ssh-ed25519" | b"sk-ssh-ed25519@openssh.com" => Some(256),
        b"ssh-ed448" => Some(448),
        b"ecdsa-sha2-nistp256" | b"sk-ecdsa-sha2-nistp256@openssh.com" => Some(256),
        b"ecdsa-sha2-nistp384" => Some(384),
        b"ecdsa-sha2-nistp521" => Some(521),
        b"ssh-rsa" | b"ssh-dss" if kind == base => {
            // type, then e (RSA) or p (DSA): the modulus is the 2nd/1st mpint.
            let mut at = 0usize;
            let mut field = || {
                let len = crate::bytes::to_usize(crate::bytes::u32_be(blob, at)?.into());
                let data =
                    blob.get(at.saturating_add(4)..at.saturating_add(4).saturating_add(len))?;
                at = at.saturating_add(4).saturating_add(len);
                Some(data)
            };
            field()?;
            let first = field()?;
            let n = if base == b"ssh-rsa" { field()? } else { first };
            Some(mpint_bits(n))
        }
        _ => None,
    }
}

pub fn mpint_bits(n: &[u8]) -> u64 {
    let n: Vec<u8> = n.iter().copied().skip_while(|&b| b == 0).collect();
    let lead = n.first().map_or(0, |b| b.leading_zeros());
    to_u64(n.len())
        .saturating_mul(8)
        .saturating_sub(u64::from(lead))
}

/// Reads an SSH `string`: returns its data and the span of length + data.
pub async fn ssh_string(cur: &mut Cursor<'_>) -> Result<(Vec<u8>, Span)> {
    let start = cur.pos();
    let len = cur.u32().await?;
    let data = cur.bytes(len.into()).await?;
    Ok((data, cur.since(start)))
}

/// Emits a string field: text if printable, else bytes.
pub fn string_node(name: &'static str, data: &[u8], span: Span) -> Node {
    let printable = !data.is_empty() && data.iter().all(|b| b.is_ascii_graphic() || *b == b' ');
    if printable {
        text_node(name, span, &String::from_utf8_lossy(data))
    } else {
        Node::new(name)
            .span(span)
            .value(Value::Bytes(
                data.get(..data.len().min(64)).unwrap_or_default().to_vec(),
            ))
            .summary(format!("{} bytes", data.len()))
    }
}

pub fn mpint_node(name: &'static str, data: &[u8], span: Span) -> Node {
    let bits = mpint_bits(data);
    let node = string_node(name, data, span).summary(format!("{bits}-bit integer"));
    if data.len() <= 8 {
        let v = data.iter().fold(0u64, |acc, &b| (acc << 8) | u64::from(b));
        return node.value(Value::UInt {
            value: v,
            bits: 64,
            radix: Radix::Dec,
        });
    }
    node
}

/// Field names of a public key, by algorithm (after the type string).
fn public_fields(base: &[u8]) -> &'static [(&'static str, bool)] {
    // (name, is mpint)
    match base {
        b"ssh-rsa" => &[("Public exponent (e)", true), ("Modulus (n)", true)],
        b"ssh-dss" => &[("p", true), ("q", true), ("g", true), ("y", true)],
        b"ssh-ed25519" | b"ssh-ed448" => &[("Public key", false)],
        b"sk-ssh-ed25519@openssh.com" => &[("Public key", false), ("Application", false)],
        b"sk-ecdsa-sha2-nistp256@openssh.com" => &[
            ("Curve", false),
            ("Public point (Q)", false),
            ("Application", false),
        ],
        _ if base.starts_with(b"ecdsa-sha2-") => &[("Curve", false), ("Public point (Q)", false)],
        _ => &[],
    }
}

pub async fn dissect_blob(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    let (kind, span) = ssh_string(&mut cur).await?;
    cx.emit(string_node("Key type", &kind, span));
    let cert = kind.ends_with(b"-cert-v01@openssh.com");
    let base = kind
        .strip_suffix(b"-cert-v01@openssh.com")
        .unwrap_or(&kind)
        .to_vec();
    let mut summary = String::from_utf8_lossy(&kind).into_owned();
    if cert {
        let (nonce, span) = ssh_string(&mut cur).await?;
        cx.emit(string_node("Nonce", &nonce, span));
    }
    for &(name, mpint) in public_fields(&base) {
        let (data, span) = ssh_string(&mut cur).await?;
        if name == "Modulus (n)" || (name == "p" && base == b"ssh-dss") {
            summary = format!("{summary}, {} bits", mpint_bits(&data));
        }
        cx.emit(if mpint {
            mpint_node(name, &data, span)
        } else {
            string_node(name, &data, span)
        });
    }
    if let Some(bits) = key_bits(&base, &[]) {
        summary = format!("{summary}, {bits} bits");
    }
    cx.annotate(summary);
    if cert {
        certificate(&cx, &mut cur, input).await?;
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(cur.span(cur.remaining())));
    }
    Ok(())
}

/// The rest of an OpenSSH certificate after the public key fields.
async fn certificate(cx: &Cx, cur: &mut Cursor<'_>, input: Input) -> Result<()> {
    let start = cur.pos();
    let serial = cur.u64().await?;
    cx.emit(
        Node::new("Serial")
            .span(cur.since(start))
            .value(Value::UInt {
                value: serial,
                bits: 64,
                radix: Radix::Dec,
            }),
    );
    let start = cur.pos();
    let kind = cur.u32().await?;
    cx.emit(
        Node::new("Certificate type")
            .span(cur.since(start))
            .value(Value::Enum {
                raw: kind.into(),
                bits: 32,
                name: match kind {
                    1 => Some("user"),
                    2 => Some("host"),
                    _ => None,
                },
            }),
    );
    let (id, span) = ssh_string(cur).await?;
    cx.emit(string_node("Key ID", &id, span));
    let (principals, span) = ssh_string(cur).await?;
    let names = ssh_strings(&principals);
    cx.emit(text_node("Valid principals", span, &names.join(", ")));
    for name in ["Valid after", "Valid before"] {
        let start = cur.pos();
        let t = cur.u64().await?;
        let node = Node::new(name).span(cur.since(start));
        cx.emit(if t == u64::MAX {
            node.summary("forever")
        } else {
            node.value(Value::Timestamp {
                unix_seconds: i64::try_from(t).unwrap_or(i64::MAX),
            })
        });
    }
    for name in ["Critical options", "Extensions"] {
        let (data, span) = ssh_string(cur).await?;
        let items = ssh_strings(&data);
        // Name/value pairs: show the names.
        let keys: Vec<String> = items.iter().step_by(2).cloned().collect();
        cx.emit(text_node(name, span, &keys.join(", ")));
    }
    let (_, span) = ssh_string(cur).await?;
    cx.emit(Node::new("Reserved").span(span));
    let (_, span) = ssh_string(cur).await?;
    let key = span.sub(4, span.len.saturating_sub(4));
    cx.emit(embedded_as("Signature key", input.nested(key), &BLOB));
    let (_, span) = ssh_string(cur).await?;
    cx.emit(Node::new("Signature").span(span));
    Ok(())
}

/// A sequence of SSH strings packed in a buffer.
fn ssh_strings(data: &[u8]) -> Vec<String> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while let Some(len) = crate::bytes::u32_be(data, at) {
        let start = at.saturating_add(4);
        let end = start.saturating_add(crate::bytes::to_usize(len.into()));
        let Some(s) = data.get(start..end) else {
            break;
        };
        out.push(String::from_utf8_lossy(s).into_owned());
        at = end;
        if out.len() >= 1024 {
            break;
        }
    }
    out
}
