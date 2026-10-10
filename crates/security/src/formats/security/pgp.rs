//! OpenPGP (RFC 4880 / RFC 9580): binary packet streams and ASCII armor.
//!
//! Packets are listed in pages; each is decoded when expanded. Key packets
//! show their algorithm fields and v4 fingerprint (SHA-1, computed here),
//! signatures their subpackets, literal data its contents (dissected), and
//! compressed packets are inflated and listed recursively. Partial body
//! lengths become piecewise sources.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::sha1;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::text::hex_upper;
use crate::value::{EnumTable, FlagTable, Radix, Value, flag, lookup};

/// Compressed packets nested inside each other.
const MAX_DEPTH: u32 = 8;
/// Bodies read whole for decoding (keys and signatures are far smaller).
const MAX_BODY: u64 = 1 << 20;
/// Partial-length chunks followed per packet.
const MAX_CHUNKS: usize = 1 << 16;

pub static FORMAT: Format = Format {
    name: "pgp",
    title: "OpenPGP data (binary)",
    extensions: &["gpg", "pgp", "sig", "asc", "pub", "key", "kbx"],
    mime: "application/pgp-encrypted",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

pub static ARMOR: Format = Format {
    name: "pgp-armor",
    title: "OpenPGP data (ASCII armor)",
    extensions: &["asc", "sig", "pub", "key"],
    mime: "application/pgp-keys",
    probe: Probe::Custom(|h| crate::formats::security::pem::probe_armor(h, true)),
    dissect: crate::expander!(dissect_armor: Input),
};

pub const TAGS: EnumTable = &[
    (1, "Public-Key Encrypted Session Key"),
    (2, "Signature"),
    (3, "Symmetric-Key Encrypted Session Key"),
    (4, "One-Pass Signature"),
    (5, "Secret-Key"),
    (6, "Public-Key"),
    (7, "Secret-Subkey"),
    (8, "Compressed Data"),
    (9, "Symmetrically Encrypted Data"),
    (10, "Marker"),
    (11, "Literal Data"),
    (12, "Trust"),
    (13, "User ID"),
    (14, "Public-Subkey"),
    (17, "User Attribute"),
    (18, "Symmetrically Encrypted Integrity Protected Data"),
    (19, "Modification Detection Code"),
    (20, "AEAD Encrypted Data"),
    (21, "Padding"),
];

const PK_ALGOS: EnumTable = &[
    (1, "RSA"),
    (2, "RSA (encrypt only)"),
    (3, "RSA (sign only)"),
    (16, "Elgamal"),
    (17, "DSA"),
    (18, "ECDH"),
    (19, "ECDSA"),
    (20, "Elgamal (sign and encrypt)"),
    (22, "EdDSA (legacy)"),
    (25, "X25519"),
    (26, "X448"),
    (27, "Ed25519"),
    (28, "Ed448"),
];

const HASHES: EnumTable = &[
    (1, "MD5"),
    (2, "SHA-1"),
    (3, "RIPEMD-160"),
    (8, "SHA-256"),
    (9, "SHA-384"),
    (10, "SHA-512"),
    (11, "SHA-224"),
    (12, "SHA3-256"),
    (14, "SHA3-512"),
];

const CIPHERS: EnumTable = &[
    (0, "plaintext"),
    (1, "IDEA"),
    (2, "TripleDES"),
    (3, "CAST5"),
    (4, "Blowfish"),
    (7, "AES-128"),
    (8, "AES-192"),
    (9, "AES-256"),
    (10, "Twofish"),
    (11, "Camellia-128"),
    (12, "Camellia-192"),
    (13, "Camellia-256"),
];

const COMPRESSION: EnumTable = &[(0, "uncompressed"), (1, "ZIP"), (2, "ZLIB"), (3, "BZip2")];

const SIG_TYPES: EnumTable = &[
    (0x00, "binary document"),
    (0x01, "text document"),
    (0x02, "standalone"),
    (0x10, "generic certification"),
    (0x11, "persona certification"),
    (0x12, "casual certification"),
    (0x13, "positive certification"),
    (0x18, "subkey binding"),
    (0x19, "primary key binding"),
    (0x1f, "direct key"),
    (0x20, "key revocation"),
    (0x28, "subkey revocation"),
    (0x30, "certification revocation"),
    (0x40, "timestamp"),
    (0x50, "third-party confirmation"),
];

const SUBPACKETS: EnumTable = &[
    (2, "Signature Creation Time"),
    (3, "Signature Expiration Time"),
    (4, "Exportable Certification"),
    (5, "Trust Signature"),
    (6, "Regular Expression"),
    (7, "Revocable"),
    (9, "Key Expiration Time"),
    (11, "Preferred Symmetric Ciphers"),
    (12, "Revocation Key"),
    (16, "Issuer Key ID"),
    (20, "Notation Data"),
    (21, "Preferred Hash Algorithms"),
    (22, "Preferred Compression Algorithms"),
    (23, "Key Server Preferences"),
    (24, "Preferred Key Server"),
    (25, "Primary User ID"),
    (26, "Policy URI"),
    (27, "Key Flags"),
    (28, "Signer's User ID"),
    (29, "Reason for Revocation"),
    (30, "Features"),
    (31, "Signature Target"),
    (32, "Embedded Signature"),
    (33, "Issuer Fingerprint"),
    (34, "Preferred AEAD Algorithms"),
    (35, "Intended Recipient Fingerprint"),
    (39, "Preferred AEAD Ciphersuites"),
];

const KEY_FLAGS: FlagTable = &[
    flag(0x01, "certify"),
    flag(0x02, "sign"),
    flag(0x04, "encrypt communications"),
    flag(0x08, "encrypt storage"),
    flag(0x10, "split key"),
    flag(0x20, "authenticate"),
    flag(0x80, "group key"),
];

const CURVES: &[(&[u8], &str)] = &[
    (
        &[0x2a, 0x86, 0x48, 0xce, 0x3d, 0x03, 0x01, 0x07],
        "NIST P-256",
    ),
    (&[0x2b, 0x81, 0x04, 0x00, 0x22], "NIST P-384"),
    (&[0x2b, 0x81, 0x04, 0x00, 0x23], "NIST P-521"),
    (
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0xda, 0x47, 0x0f, 0x01],
        "Ed25519 (legacy)",
    ),
    (
        &[0x2b, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01],
        "Curve25519 (legacy)",
    ),
    (
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x07],
        "brainpoolP256r1",
    ),
    (
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0b],
        "brainpoolP384r1",
    ),
    (
        &[0x2b, 0x24, 0x03, 0x03, 0x02, 0x08, 0x01, 0x01, 0x0d],
        "brainpoolP512r1",
    ),
];

// ---------------------------------------------------------------------------
// Packet headers

#[derive(Clone, Copy, Debug)]
struct Header {
    tag: u8,
    new_format: bool,
    header_len: u64,
    /// `None`: to the end of the input (old format, indeterminate).
    len: Option<u64>,
    /// New format partial body length: this first chunk's length.
    partial: bool,
}

/// A new-format length at the start of `data`: (length, octets, partial).
fn new_length(data: &[u8]) -> Option<(u64, u64, bool)> {
    let &o1 = data.first()?;
    Some(match o1 {
        0..192 => (u64::from(o1), 1, false),
        192..224 => {
            let o2 = *data.get(1)?;
            let len = (u64::from(o1).saturating_sub(192) << 8)
                .saturating_add(u64::from(o2))
                .saturating_add(192);
            (len, 2, false)
        }
        255 => (u64::from(u32_be(data, 1)?), 5, false),
        _ => (1u64 << (o1 & 0x1f), 1, true),
    })
}

fn header(data: &[u8]) -> Option<Header> {
    let &b = data.first()?;
    if b & 0x80 == 0 {
        return None;
    }
    if b & 0x40 != 0 {
        let (len, n, partial) = new_length(data.get(1..)?)?;
        return Some(Header {
            tag: b & 0x3f,
            new_format: true,
            header_len: n.saturating_add(1),
            len: Some(len),
            partial,
        });
    }
    let tag = (b >> 2) & 0x0f;
    let (len, n) = match b & 3 {
        0 => (Some(u64::from(*data.get(1)?)), 1),
        1 => (Some(u64::from(u16_be(data, 1)?)), 2),
        2 => (Some(u64::from(u32_be(data, 1)?)), 4),
        _ => (None, 0),
    };
    Some(Header {
        tag,
        new_format: false,
        header_len: 1u64.saturating_add(n),
        len,
        partial: false,
    })
}

/// A plausible first packet: a known tag whose body starts as expected.
fn probe(h: &Head<'_>) -> bool {
    let Some(hd) = header(h.data) else {
        return false;
    };
    let len = hd.len.unwrap_or(0);
    let total = hd.header_len.saturating_add(len);
    if hd.len.is_some() && !hd.partial && total > h.len {
        return false;
    }
    let body = h.data.get(to_usize(hd.header_len)..).unwrap_or_default();
    let at = |i: usize| body.get(i).copied();
    let known_pk = |b: Option<u8>| b.is_some_and(|b| lookup(PK_ALGOS, b.into()).is_some());
    let ok = match hd.tag {
        5 | 6 => {
            matches!(at(0), Some(4..=6)) && known_pk(at(5)) || at(0) == Some(3) && known_pk(at(7))
        }
        2 => match at(0) {
            Some(4..=6) => {
                at(1).is_some_and(|t| lookup(SIG_TYPES, t.into()).is_some())
                    && known_pk(at(2))
                    && at(3).is_some_and(|x| lookup(HASHES, x.into()).is_some())
            }
            Some(3) => at(1) == Some(5) && known_pk(at(15)),
            _ => false,
        },
        1 => matches!(at(0), Some(3)) && known_pk(at(9)),
        3 => {
            matches!(at(0), Some(4..=6))
                && at(1).is_some_and(|c| lookup(CIPHERS, c.into()).is_some())
        }
        4 => {
            at(0) == Some(3)
                && at(1).is_some_and(|t| lookup(SIG_TYPES, t.into()).is_some())
                && known_pk(at(3))
        }
        8 => matches!(at(0), Some(0..=3)) && len > 1,
        10 => body.starts_with(b"PGP"),
        11 => matches!(at(0), Some(b'b' | b't' | b'u' | b'l' | b'1' | b'm')),
        18 => matches!(at(0), Some(1 | 2)) && len > 20,
        _ => false,
    };
    // A short packet must be followed by another packet header or the end.
    let next_ok = h
        .data
        .get(to_usize(total))
        .is_none_or(|&b| b & 0x80 != 0 || hd.partial || hd.len.is_none());
    ok && next_ok && h.len >= 3
}

// ---------------------------------------------------------------------------
// Packet stream

#[derive(Clone, Copy)]
struct Stream {
    input: Input,
    span: Span,
    depth: u32,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 4096)).await?;
    cx.annotate(summary(&head, input.span.len));
    packets(
        cx,
        Stream {
            input,
            span: input.span,
            depth: 0,
        },
    )
    .await
}

/// A one-line description of what a packet stream holds, from its start.
fn summary(head: &[u8], len: u64) -> String {
    let mut at = 0usize;
    let mut tags = Vec::new();
    let mut user = None;
    let mut algo = None;
    while let Some(h) = header(head.get(at..).unwrap_or_default()) {
        let body_at = at.saturating_add(to_usize(h.header_len));
        let body_len = to_usize(h.len.unwrap_or(len));
        tags.push(h.tag);
        let body = head
            .get(body_at..body_at.saturating_add(body_len))
            .unwrap_or_default();
        if h.tag == 13 && user.is_none() {
            user = Some(String::from_utf8_lossy(body).into_owned());
        }
        if matches!(h.tag, 5 | 6) && algo.is_none() {
            let i = if body.first() == Some(&3) { 7 } else { 5 };
            algo = body.get(i).and_then(|&a| lookup(PK_ALGOS, a.into()));
        }
        if h.partial || h.len.is_none() || tags.len() > 64 {
            break;
        }
        at = body_at.saturating_add(body_len);
    }
    let kind = match tags.first() {
        Some(5) => "OpenPGP secret key",
        Some(6) => "OpenPGP public key",
        Some(2) => "OpenPGP signature",
        Some(1 | 3) => "OpenPGP encrypted message",
        Some(4 | 8 | 11) => "OpenPGP message",
        _ => "OpenPGP data",
    };
    let mut out = kind.to_owned();
    if let Some(a) = algo {
        out = format!("{out}, {a}");
    }
    if let Some(u) = user {
        out = format!("{out}, {u:?}");
    }
    out
}

async fn packets(cx: Cx, stream: Stream) -> Result<()> {
    let span = stream.span;
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 6)).await?;
        let Some(h) = header(&head) else {
            cx.push(
                Node::new("Trailing data")
                    .span(span.tail(pos))
                    .diag(Diagnostic::malformed("not an OpenPGP packet header")),
            )
            .await;
            break;
        };
        let header_span = span.sub(pos, h.header_len);
        let (body, next) = if h.partial {
            partial_body(&cx, span, pos, &h).await?
        } else {
            let len = h
                .len
                .unwrap_or_else(|| span.len.saturating_sub(pos).saturating_sub(h.header_len));
            let body_at = pos.saturating_add(h.header_len);
            (span.sub(body_at, len), body_at.saturating_add(len))
        };
        let whole = span.sub(pos, next.saturating_sub(pos));
        let name = lookup(TAGS, h.tag.into()).map_or_else(
            || format!("Packet type {}", h.tag),
            |n| format!("{n} Packet"),
        );
        let mut node = Node::new(name).span(whole);
        let data = cx.read_avail(body.sub(0, 512)).await?;
        if let Some(s) = packet_summary(h.tag, &data) {
            node = node.summary(s);
        }
        let expected = h.len.unwrap_or(0);
        if !h.partial && h.len.is_some() && body.len < expected {
            node = node.diag(Diagnostic::truncated(
                Span::new(body.source, body.offset, expected),
                body.len,
            ));
        }
        cx.progress_in(span, span.offset.saturating_add(pos));
        cx.push(node.lazy(
            crate::expander!(self::packet: PacketState),
            PacketState {
                stream,
                tag: h.tag,
                new_format: h.new_format,
                header: header_span,
                body,
            },
        ))
        .await;
        index = index.saturating_add(1);
        pos = next.max(pos.saturating_add(1));
    }
    Ok(())
}

/// Collects the chunks of a partial-length body into one piecewise source.
async fn partial_body(cx: &Cx, span: Span, pos: u64, first: &Header) -> Result<(Span, u64)> {
    let mut pieces = Vec::new();
    let mut at = pos.saturating_add(first.header_len);
    let mut len = first.len.unwrap_or(0);
    loop {
        pieces.push(span.sub(at, len));
        at = at.saturating_add(len);
        if pieces.len() >= MAX_CHUNKS {
            cx.diag(Diagnostic::limit("too many partial body chunks"));
            break;
        }
        cx.checkpoint().await;
        let head = cx.read_avail(span.sub(at, 5)).await?;
        let Some((next, n, partial)) = new_length(&head) else {
            break;
        };
        at = at.saturating_add(n);
        len = next;
        if !partial {
            pieces.push(span.sub(at, len));
            at = at.saturating_add(len);
            break;
        }
    }
    let body = cx
        .add_pieces_stepped(
            Origin {
                parent: span.sub(pos, first.header_len),
                transform: "pgp-partial",
            },
            &pieces,
        )
        .await?;

    Ok((body, at))
}

fn packet_summary(tag: u8, data: &[u8]) -> Option<String> {
    let at = |i: usize| data.get(i).copied();
    match tag {
        5..=7 | 14 => {
            let version = at(0)?;
            let (time, algo) = if version == 3 {
                (u32_be(data, 1)?, at(7)?)
            } else {
                (u32_be(data, 1)?, at(5)?)
            };
            Some(format!(
                "v{version} {}, created {}",
                lookup(PK_ALGOS, algo.into()).unwrap_or("unknown algorithm"),
                crate::formats::util::civil::date(time.into())
            ))
        }
        2 => {
            let version = at(0)?;
            let (kind, algo, hash) = if version == 3 {
                (at(2)?, at(15)?, at(16)?)
            } else {
                (at(1)?, at(2)?, at(3)?)
            };
            Some(format!(
                "v{version} {}, {} with {}",
                lookup(SIG_TYPES, kind.into()).unwrap_or("unknown type"),
                lookup(PK_ALGOS, algo.into()).unwrap_or("unknown"),
                lookup(HASHES, hash.into()).unwrap_or("unknown hash")
            ))
        }
        13 => Some(format!("{:?}", String::from_utf8_lossy(data))),
        8 => lookup(COMPRESSION, at(0)?.into()).map(str::to_owned),
        11 => {
            let n = usize::from(at(1)?);
            let name = data.get(2..2usize.saturating_add(n))?;
            Some(format!("{:?}", String::from_utf8_lossy(name)))
        }
        1 => Some(format!("for key {}", hex_upper(data.get(1..9)?))),
        4 => Some(format!("by key {}", hex_upper(data.get(4..12)?))),
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Packet bodies

#[derive(Clone, Copy)]
struct PacketState {
    stream: Stream,
    tag: u8,
    new_format: bool,
    header: Span,
    body: Span,
}

/// Emits fields of a body held in memory; positions are relative to `span`.
struct Body<'a> {
    cx: &'a Cx,
    span: Span,
    data: &'a [u8],
    pos: usize,
}

impl<'a> Body<'a> {
    fn span(&self, len: usize) -> Span {
        self.span.sub(to_u64(self.pos), to_u64(len))
    }

    fn take(&mut self, len: usize) -> Option<(&'a [u8], Span)> {
        let data: &'a [u8] = self.data;
        let bytes = data.get(self.pos..self.pos.checked_add(len)?)?;
        let span = self.span(len);
        self.pos = self.pos.saturating_add(len);
        Some((bytes, span))
    }

    fn u8(&mut self, name: &'static str, table: Option<EnumTable>) -> Option<u8> {
        let (b, span) = self.take(1)?;
        let v = *b.first()?;
        let value = match table {
            Some(t) => Value::Enum {
                raw: v.into(),
                bits: 8,
                name: lookup(t, v.into()),
            },
            None => Value::UInt {
                value: v.into(),
                bits: 8,
                radix: Radix::Dec,
            },
        };
        self.cx.emit(Node::new(name).span(span).value(value));
        Some(v)
    }

    fn u16(&mut self, name: &'static str) -> Option<u16> {
        let (b, span) = self.take(2)?;
        let v = u16_be(b, 0)?;
        self.cx.emit(Node::new(name).span(span).value(Value::UInt {
            value: v.into(),
            bits: 16,
            radix: Radix::Dec,
        }));
        Some(v)
    }

    fn u32(&mut self, name: &'static str) -> Option<u32> {
        let (b, span) = self.take(4)?;
        let v = u32_be(b, 0)?;
        self.cx.emit(Node::new(name).span(span).value(Value::UInt {
            value: v.into(),
            bits: 32,
            radix: Radix::Dec,
        }));
        Some(v)
    }

    fn time(&mut self, name: &'static str) -> Option<u32> {
        let (b, span) = self.take(4)?;
        let v = u32_be(b, 0)?;
        self.cx
            .emit(Node::new(name).span(span).value(Value::Timestamp {
                unix_seconds: v.into(),
            }));
        Some(v)
    }

    fn bytes(&mut self, name: &'static str, len: usize) -> Option<Vec<u8>> {
        let (b, span) = self.take(len)?;
        let b = b.to_vec();
        self.cx.emit(
            Node::new(name)
                .span(span)
                .value(Value::Bytes(b.iter().take(32).copied().collect())),
        );
        Some(b)
    }

    fn key_id(&mut self, name: &'static str) -> Option<()> {
        let (b, span) = self.take(8)?;
        self.cx
            .emit(Node::new(name).span(span).value(Value::Text(hex_upper(b))));
        Some(())
    }

    /// A multiprecision integer: bit count and big-endian magnitude.
    fn mpi(&mut self, name: &'static str) -> Option<()> {
        let bits = u16_be(self.data, self.pos)?;
        let len = usize::from(bits).div_ceil(8);
        let (b, span) = self.take(len.saturating_add(2))?;
        let magnitude = b.get(2..).unwrap_or_default();
        self.cx.emit(
            Node::new(name)
                .span(span)
                .value(Value::Bytes(magnitude.iter().take(32).copied().collect()))
                .summary(format!("{bits}-bit")),
        );
        Some(())
    }

    /// A curve OID (length byte and DER content without tag).
    fn curve(&mut self) -> Option<()> {
        let len = usize::from(*self.data.get(self.pos)?);
        let (b, span) = self.take(len.saturating_add(1))?;
        let oid = b.get(1..).unwrap_or_default();
        let name = CURVES.iter().find(|(o, _)| *o == oid).map(|(_, n)| *n);
        let dotted = crate::formats::asn1::der::oid(oid).unwrap_or_default();
        let mut node = Node::new("Curve").span(span).value(Value::Text(dotted));
        if let Some(n) = name {
            node = node.summary(n);
        }
        self.cx.emit(node);
        Some(())
    }

    fn rest(&mut self, name: &'static str) {
        let len = self.data.len().saturating_sub(self.pos);
        if self.span.len > to_u64(self.pos) {
            let span = self.span.tail(to_u64(self.pos));
            self.cx.emit(
                Node::new(name)
                    .span(span)
                    .summary(format!("{} bytes", span.len)),
            );
        }
        self.pos = self.pos.saturating_add(len);
    }
}

async fn packet(cx: Cx, state: PacketState) -> Result<()> {
    let tag_value = Value::Enum {
        raw: state.tag.into(),
        bits: 8,
        name: lookup(TAGS, state.tag.into()),
    };
    cx.emit(
        Node::new("Packet header")
            .span(state.header)
            .value(tag_value)
            .summary(format!(
                "{} format, {} body bytes",
                if state.new_format { "new" } else { "old" },
                state.body.len
            )),
    );
    match state.tag {
        8 => return compressed(&cx, &state).await,
        11 => return literal(&cx, &state).await,
        9 | 18 | 20 => {
            let data = cx.read_avail(state.body.sub(0, 1)).await?;
            if state.tag != 9 {
                let mut b = Body {
                    cx: &cx,
                    span: state.body,
                    data: &data,
                    pos: 0,
                };
                b.u8("Version", None);
                b.rest("Encrypted data");
            } else {
                cx.emit(Node::new("Encrypted data").span(state.body));
            }
            return Ok(());
        }
        _ => {}
    }
    let data = cx.read(state.body.sub(0, MAX_BODY)).await?;
    let mut b = Body {
        cx: &cx,
        span: state.body,
        data: &data,
        pos: 0,
    };
    let done = match state.tag {
        5..=7 | 14 => key(&mut b, matches!(state.tag, 5 | 7)),
        2 => signature(&mut b),
        13 => {
            cx.emit(
                Node::new("User ID")
                    .span(state.body)
                    .value(Value::Text(String::from_utf8_lossy(&data).into_owned())),
            );
            b.pos = data.len();
            Some(())
        }
        1 => pkesk(&mut b),
        3 => skesk(&mut b),
        4 => one_pass(&mut b),
        10 => {
            cx.emit(
                Node::new("Marker")
                    .span(state.body)
                    .value(Value::Text(String::from_utf8_lossy(&data).into_owned())),
            );
            b.pos = data.len();
            Some(())
        }
        19 => b.bytes("SHA-1 hash", 20).map(|_| ()),
        _ => None,
    };
    if done.is_none() && b.pos == 0 {
        cx.emit(Node::new("Body").span(state.body));
    } else if done.is_none() {
        cx.diag(Diagnostic::truncated(state.body, to_u64(b.pos)));
    } else if b.pos < data.len() {
        b.rest("Remaining data");
    }
    Ok(())
}

/// Algorithm-specific public key fields.
fn public_fields(b: &mut Body<'_>, algo: u8) -> Option<()> {
    match algo {
        1..=3 => {
            b.mpi("n (modulus)")?;
            b.mpi("e (exponent)")
        }
        16 | 20 => {
            b.mpi("p")?;
            b.mpi("g")?;
            b.mpi("y")
        }
        17 => {
            b.mpi("p")?;
            b.mpi("q")?;
            b.mpi("g")?;
            b.mpi("y")
        }
        19 | 22 => {
            b.curve()?;
            b.mpi("Public point")
        }
        18 => {
            b.curve()?;
            b.mpi("Public point")?;
            let len = usize::from(*b.data.get(b.pos)?);
            b.bytes("KDF parameters", len.saturating_add(1)).map(|_| ())
        }
        25 => b.bytes("Public key", 32).map(|_| ()),
        26 => b.bytes("Public key", 56).map(|_| ()),
        27 => b.bytes("Public key", 32).map(|_| ()),
        28 => b.bytes("Public key", 57).map(|_| ()),
        _ => None,
    }
}

fn key(b: &mut Body<'_>, secret: bool) -> Option<()> {
    let start = b.pos;
    let version = b.u8("Version", None)?;
    b.time("Creation time")?;
    if version == 3 {
        b.u16("Validity (days)")?;
    }
    let algo = b.u8("Public-key algorithm", Some(PK_ALGOS))?;
    if version >= 5 {
        b.u32("Key material length")?;
    }
    public_fields(b, algo)?;
    let public = b.data.get(start..b.pos)?;
    if version == 4 {
        let mut hashed = vec![0x99];
        hashed.extend_from_slice(
            &u16::try_from(public.len())
                .unwrap_or(u16::MAX)
                .to_be_bytes(),
        );
        hashed.extend_from_slice(public);
        let fingerprint = sha1(&hashed);
        let span = b.span.sub(to_u64(start), to_u64(public.len()));
        b.cx.emit(
            Node::new("Fingerprint")
                .span(span)
                .value(Value::Text(hex_upper(&fingerprint)))
                .summary(format!(
                    "key ID {}",
                    hex_upper(fingerprint.get(12..).unwrap_or_default())
                )),
        );
    }
    if secret {
        let usage = b.u8("S2K usage", None)?;
        if matches!(usage, 253..=255) {
            b.u8("Symmetric cipher", Some(CIPHERS))?;
            s2k(b)?;
        }
        b.rest(if usage == 0 {
            "Secret key material"
        } else {
            "Encrypted secret key material"
        });
    }
    Some(())
}

fn s2k(b: &mut Body<'_>) -> Option<()> {
    const S2K: EnumTable = &[
        (0, "simple"),
        (1, "salted"),
        (3, "iterated and salted"),
        (4, "Argon2"),
    ];
    let kind = b.u8("S2K specifier", Some(S2K))?;
    match kind {
        0 => b.u8("Hash algorithm", Some(HASHES)).map(|_| ()),
        1 => {
            b.u8("Hash algorithm", Some(HASHES))?;
            b.bytes("Salt", 8).map(|_| ())
        }
        3 => {
            b.u8("Hash algorithm", Some(HASHES))?;
            b.bytes("Salt", 8)?;
            let c = b.u8("Coded count", None)?;
            let count = (16u64 + u64::from(c & 15)) << ((c >> 4).saturating_add(6));
            b.cx.emit(Node::new("Iterations").value(Value::UInt {
                value: count,
                bits: 64,
                radix: Radix::Dec,
            }));
            Some(())
        }
        4 => {
            b.bytes("Salt", 16)?;
            b.u8("Passes", None)?;
            b.u8("Parallelism", None)?;
            b.u8("Memory exponent", None).map(|_| ())
        }
        _ => None,
    }
}

fn signature(b: &mut Body<'_>) -> Option<()> {
    let version = b.u8("Version", None)?;
    let algo;
    if version == 3 {
        b.u8("Hashed length", None)?;
        b.u8("Signature type", Some(SIG_TYPES))?;
        b.time("Creation time")?;
        b.key_id("Issuer key ID")?;
        algo = b.u8("Public-key algorithm", Some(PK_ALGOS))?;
        b.u8("Hash algorithm", Some(HASHES))?;
    } else {
        b.u8("Signature type", Some(SIG_TYPES))?;
        algo = b.u8("Public-key algorithm", Some(PK_ALGOS))?;
        b.u8("Hash algorithm", Some(HASHES))?;
        for name in ["Hashed subpackets", "Unhashed subpackets"] {
            let wide = version >= 6;
            let len = if wide {
                let (l, _) = b.take(4).map(|(d, s)| (u32_be(d, 0), s))?;
                usize::try_from(l?).ok()?
            } else {
                let (l, _) = b.take(2).map(|(d, s)| (u16_be(d, 0), s))?;
                usize::from(l?)
            };
            let header = if wide { 4 } else { 2 };
            let span = b.span.sub(
                to_u64(b.pos.saturating_sub(header)),
                to_u64(len.saturating_add(header)),
            );
            let data = b.data.get(b.pos..b.pos.checked_add(len)?)?.to_vec();
            let body_span = b.span(len);
            b.cx.emit(
                Node::new(name)
                    .span(span)
                    .summary(format!("{len} bytes"))
                    .lazy(subpackets, (body_span, Arc::new(data))),
            );
            b.pos = b.pos.saturating_add(len);
        }
    }
    b.bytes("Hash prefix", 2)?;
    if version == 6 {
        let n = usize::from(*b.data.get(b.pos)?);
        b.bytes("Salt", n.saturating_add(1))?;
    }
    match algo {
        1..=3 => b.mpi("Signature (m^d mod n)"),
        17 | 19 | 22 => {
            b.mpi("r")?;
            b.mpi("s")
        }
        27 => b.bytes("Signature", 64).map(|_| ()),
        28 => b.bytes("Signature", 114).map(|_| ()),
        _ => {
            b.rest("Signature data");
            Some(())
        }
    }
}

async fn subpackets(cx: Cx, (span, data): (Span, Arc<Vec<u8>>)) -> Result<()> {
    let mut at = 0usize;
    while at < data.len() {
        let Some((len, n, _)) = new_length(data.get(at..).unwrap_or_default()) else {
            break;
        };
        let n = to_usize(n);
        let whole = to_usize(len).saturating_add(n);
        let start = at;
        let body_at = at.saturating_add(n);
        let Some(&kind) = data.get(body_at) else {
            break;
        };
        let critical = kind & 0x80 != 0;
        let kind = kind & 0x7f;
        let body = data
            .get(body_at.saturating_add(1)..start.saturating_add(whole))
            .unwrap_or_default();
        let name = lookup(SUBPACKETS, kind.into())
            .map_or_else(|| format!("Subpacket {kind}"), str::to_owned);
        let mut node = Node::new(name).span(span.sub(to_u64(start), to_u64(whole)));
        node = match kind {
            2 => match u32_be(body, 0) {
                Some(t) => node.value(Value::Timestamp {
                    unix_seconds: t.into(),
                }),
                None => node,
            },
            3 | 9 => match u32_be(body, 0) {
                Some(s) => node
                    .value(Value::UInt {
                        value: s.into(),
                        bits: 32,
                        radix: Radix::Dec,
                    })
                    .summary("seconds"),
                None => node,
            },
            16 => node.value(Value::Text(hex_upper(body))),
            33 | 35 => node
                .value(Value::Text(hex_upper(body.get(1..).unwrap_or_default())))
                .summary(format!("v{}", body.first().copied().unwrap_or(0))),
            27 => {
                let raw = u64::from(body.first().copied().unwrap_or(0));
                let (set, unknown) = crate::value::decode_flags(KEY_FLAGS, raw);
                node.value(Value::Flags {
                    raw,
                    bits: 8,
                    set,
                    unknown,
                })
            }
            11 | 21 | 22 => {
                let table = match kind {
                    11 => CIPHERS,
                    21 => HASHES,
                    _ => COMPRESSION,
                };
                let names: Vec<String> = body
                    .iter()
                    .map(|&a| lookup(table, a.into()).map_or_else(|| a.to_string(), str::to_owned))
                    .collect();
                node.value(Value::Text(names.join(", ")))
            }
            25 | 4 | 7 => node.value(Value::Bool(body.first().is_some_and(|&b| b != 0))),
            28 | 24 | 26 => node.value(Value::Text(String::from_utf8_lossy(body).into_owned())),
            _ => node.value(Value::Bytes(body.iter().take(32).copied().collect())),
        };
        if critical {
            node = node.summary("critical");
        }
        cx.push(node).await;
        at = start.saturating_add(whole.max(1));
    }
    Ok(())
}

fn pkesk(b: &mut Body<'_>) -> Option<()> {
    let version = b.u8("Version", None)?;
    if version != 3 {
        b.rest("Data");
        return Some(());
    }
    b.key_id("Key ID")?;
    let algo = b.u8("Public-key algorithm", Some(PK_ALGOS))?;
    match algo {
        1..=3 => b.mpi("m^e mod n"),
        16 | 20 => {
            b.mpi("g^k mod p")?;
            b.mpi("m * y^k mod p")
        }
        18 => {
            b.mpi("Ephemeral point")?;
            let len = usize::from(*b.data.get(b.pos)?);
            b.bytes("Wrapped session key", len.saturating_add(1))
                .map(|_| ())
        }
        _ => {
            b.rest("Encrypted session key");
            Some(())
        }
    }
}

fn skesk(b: &mut Body<'_>) -> Option<()> {
    let version = b.u8("Version", None)?;
    if version != 4 {
        b.rest("Data");
        return Some(());
    }
    b.u8("Symmetric cipher", Some(CIPHERS))?;
    s2k(b)?;
    b.rest("Encrypted session key");
    Some(())
}

fn one_pass(b: &mut Body<'_>) -> Option<()> {
    b.u8("Version", None)?;
    b.u8("Signature type", Some(SIG_TYPES))?;
    b.u8("Hash algorithm", Some(HASHES))?;
    b.u8("Public-key algorithm", Some(PK_ALGOS))?;
    b.key_id("Key ID")?;
    b.u8("Nested", None).map(|_| ())
}

async fn literal(cx: &Cx, state: &PacketState) -> Result<()> {
    let data = cx.read_avail(state.body.sub(0, 262)).await?;
    let mut b = Body {
        cx,
        span: state.body,
        data: &data,
        pos: 0,
    };
    const FORMATS: EnumTable = &[
        (0x62, "binary"),
        (0x74, "text"),
        (0x75, "UTF-8 text"),
        (0x6d, "MIME"),
        (0x6c, "local"),
    ];
    let parsed = (|| {
        b.u8("Format", Some(FORMATS))?;
        let n = usize::from(*b.data.get(b.pos)?);
        let (name, span) = b.take(n.saturating_add(1))?;
        let name = String::from_utf8_lossy(name.get(1..).unwrap_or_default()).into_owned();
        b.cx.emit(Node::new("File name").span(span).value(Value::Text(name)));
        b.time("Date")
    })();
    if parsed.is_none() {
        return Err(Diagnostic::truncated(state.body, to_u64(data.len())));
    }
    let content = state.body.tail(to_u64(b.pos));
    cx.emit(
        Node::new("Literal data")
            .span(content)
            .summary(format!("{} bytes", content.len))
            .lazy(
                crate::formats::dissect_or_data,
                state.stream.input.nested(content),
            ),
    );
    Ok(())
}

async fn compressed(cx: &Cx, state: &PacketState) -> Result<()> {
    let data = cx.read(state.body.sub(0, 1)).await?;
    let algo = data.first().copied().unwrap_or(0);
    cx.emit(
        Node::new("Algorithm")
            .span(state.body.sub(0, 1))
            .value(Value::Enum {
                raw: algo.into(),
                bits: 8,
                name: lookup(COMPRESSION, algo.into()),
            }),
    );
    let content = state.body.tail(1);
    if state.stream.depth >= MAX_DEPTH {
        cx.emit(
            Node::new("Compressed data")
                .span(content)
                .diag(Diagnostic::limit("compressed packets nested too deeply")),
        );
        return Ok(());
    }
    let next = |span: Span| Stream {
        input: state.stream.input.nested(span),
        span,
        depth: state.stream.depth.saturating_add(1),
    };
    match algo {
        0 => cx.emit(
            Node::new("Packets")
                .span(content)
                .lazy(crate::expander!(self::packets: Stream), next(content)),
        ),
        1 | 2 => cx.emit(
            Node::new("Packets")
                .span(content)
                .summary(format!("{} compressed bytes", content.len))
                .lazy(inflate_packets, (next(content), algo == 2)),
        ),
        _ => cx.emit(
            Node::new("Compressed data")
                .span(content)
                .diag(Diagnostic::unsupported(format!(
                    "{} compression",
                    lookup(COMPRESSION, algo.into()).unwrap_or("unknown")
                ))),
        ),
    }
    Ok(())
}

async fn inflate_packets(cx: Cx, (stream, zlib): (Stream, bool)) -> Result<()> {
    let decoded = crate::codec::inflate_span(&cx, stream.span, zlib, None).await?;
    cx.annotate(format!("{:#x} bytes decompressed", decoded.span.len));
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    let inner = Stream {
        input: stream.input.nested(decoded.span),
        span: decoded.span,
        depth: stream.depth,
    };
    packets(cx, inner).await
}

// ---------------------------------------------------------------------------
// ASCII armor

async fn dissect_armor(cx: Cx, input: Input) -> Result<()> {
    let text = crate::formats::security::pem::read_text(&cx, input.span).await?;
    let blocks = crate::formats::security::pem::blocks(&cx, &text).await;
    let labels: Vec<&str> = blocks.iter().map(|b| b.label.as_str()).collect();
    let mut summary = format!("OpenPGP armor: {}", labels.join(", "));
    if let Some(block) = blocks.first()
        && let Ok(decoded) =
            crate::formats::security::pem::decode_block(&cx, &text, input.span, block).await
    {
        let head = cx.read_avail(decoded.sub(0, 4096)).await?;
        summary = format!("{} (armored)", self::summary(&head, decoded.len));
    }
    cx.annotate(summary);
    for block in blocks {
        let whole = crate::formats::security::pem::sub(input.span, &block.whole);
        cx.push(
            Node::new(block.label.clone())
                .span(whole)
                .lazy(armor_block, (input, block)),
        )
        .await;
    }
    Ok(())
}

async fn armor_block(
    cx: Cx,
    (input, block): (Input, crate::formats::security::pem::Block),
) -> Result<()> {
    use crate::formats::security::pem;
    let text = cx.read(pem::sub(input.span, &(0..block.whole.end))).await?;
    for (key, value, range) in &block.headers {
        cx.emit(
            Node::new(key.clone())
                .span(pem::sub(input.span, range))
                .value(Value::Text(value.clone())),
        );
    }
    let decoded = pem::decode_block(&cx, &text, input.span, &block).await?;
    if let Some(range) = &block.checksum {
        let line = text.get(range.clone()).unwrap_or_default();
        let mut node = Node::new("Checksum").span(pem::sub(input.span, range));
        if let crate::formats::text::decode::Decoded {
            bytes: sum,
            error: None,
        } = crate::formats::text::decode::base64(line.get(1..).unwrap_or_default())
            && let [a, b, c] = sum.as_slice()
        {
            let stored = u32::from_be_bytes([0, *a, *b, *c]);
            node = node.value(Value::UInt {
                value: stored.into(),
                bits: 24,
                radix: Radix::Hex,
            });
            let data = crate::codec::read_all(&cx, decoded).await?;
            let computed = crate::formats::util::datakit::crc24_paced(&cx, &data).await;
            if computed != stored {
                node = node.diag(Diagnostic::warning(format!(
                    "CRC-24 mismatch (computed {computed:#08x})"
                )));
            }
        }
        cx.emit(node);
    }
    cx.emit(
        Node::new("Packets")
            .span(decoded)
            .summary(format!("{} bytes", decoded.len))
            .lazy(
                crate::expander!(self::packets: Stream),
                Stream {
                    input: input.nested(decoded),
                    span: decoded,
                    depth: 0,
                },
            ),
    );
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn hashes_and_headers() {
        assert_eq!(
            hex_upper(&sha1(b"abc")),
            "A9993E364706816ABA3E25717850C26C9CD0D89D"
        );
        assert_eq!(
            hex_upper(&sha1(&[0x61; 1000])),
            "291E9A6C66994949B57BA5E650361E98FC36B1BA"
        );
        assert_eq!(crate::codec::crc::crc24(b""), 0xb704ce);
        let h = header(&[0x99, 0x01, 0x0d]).unwrap();
        assert_eq!((h.tag, h.len, h.header_len), (6, Some(269), 3));
        let h = header(&[0xc6, 0xc1, 0x00]).unwrap();
        assert_eq!((h.tag, h.len), (6, Some(448)));
        let h = header(&[0xcb, 0xe1]).unwrap();
        assert!(h.partial && h.len == Some(2));
    }
}
