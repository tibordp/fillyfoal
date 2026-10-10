//! Kerberos keytabs and credential caches.

use crate::bytes::{u16_be, u32_be, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::asn1::DER;
use crate::formats::util::val::{hex, text, uint};
use crate::formats::{Head, Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn time(secs: u32) -> Value {
    Value::Timestamp {
        unix_seconds: secs.into(),
    }
}

/// Kerberos encryption types (RFC 3961 and successors).
const ENCTYPES: EnumTable = &[
    (1, "des-cbc-crc"),
    (3, "des-cbc-md5"),
    (16, "des3-cbc-sha1"),
    (17, "aes128-cts-hmac-sha1-96"),
    (18, "aes256-cts-hmac-sha1-96"),
    (19, "aes128-cts-hmac-sha256-128"),
    (20, "aes256-cts-hmac-sha384-192"),
    (23, "rc4-hmac"),
    (24, "rc4-hmac-exp"),
    (25, "camellia128-cts-cmac"),
    (26, "camellia256-cts-cmac"),
];

fn enctype(e: u16) -> &'static str {
    ENCTYPES
        .iter()
        .find(|(k, _)| *k == u64::from(e))
        .map_or("unknown", |(_, v)| v)
}

// ---------------------------------------------------------------------------
// Kerberos keytab

fn keytab_probe(h: &Head<'_>) -> bool {
    // Version 0x0502 (big-endian) or 0x0501 (native), then the first entry's
    // length: a plausible, non-zero size.
    let size = if h.at(1, b"\x02") {
        u32_be(h.data, 2)
    } else {
        u32_le(h.data, 2)
    };
    h.data.first() == Some(&5)
        && matches!(h.data.get(1), Some(1 | 2))
        && size.is_some_and(|s| {
            let s = i32::from_ne_bytes(s.to_ne_bytes()).unsigned_abs();
            (16..=0x10000).contains(&s)
        })
}

declare_format!(pub KEYTAB = "krb5-keytab", "Kerberos keytab", ["keytab", "kt"], "application/x-krb5-keytab",
    Probe::Custom(keytab_probe), keytab);

async fn keytab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let v = cx.read(file.sub(0, 2)).await?;
    let endian = if v.get(1) == Some(&2) { BE } else { LE };
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 2))
            .value(hex(u16_be(&v, 0).unwrap_or(0), 16)),
    );
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(2);
    let mut n = 0u32;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let size = cur.u32().await?;
        let signed = i32::from_ne_bytes(size.to_ne_bytes());
        let len = u64::from(signed.unsigned_abs());
        let entry = cur.span(len);
        if entry.len < len {
            return Err(Diagnostic::truncated(
                Span::new(entry.source, entry.offset, len),
                entry.len,
            ));
        }
        cur.skip(len);
        if signed < 0 {
            cx.push(
                Node::new("Hole")
                    .span(cur.since(start))
                    .summary(format!("{len} bytes free")),
            )
            .await;
            continue;
        }
        if len == 0 {
            break;
        }
        // Parse the entry for its summary; the node expands to its fields.
        let mut e = Cursor::new(&cx, entry, endian);
        let mut count = u64::from(e.u16().await?);
        if endian == LE {
            count = count.saturating_sub(1);
        }
        let realm_len = u64::from(e.u16().await?);
        let realm = String::from_utf8_lossy(&e.bytes(realm_len).await?).into_owned();
        let mut parts = Vec::new();
        for _ in 0..count.min(16) {
            let l = u64::from(e.u16().await?);
            parts.push(String::from_utf8_lossy(&e.bytes(l).await?).into_owned());
        }
        e.skip(8);
        let kvno = e.u8().await?;
        let etype = e.u16().await?;
        let principal = format!("{}@{realm}", parts.join("/"));
        cx.push(
            Node::new(principal)
                .span(cur.since(start))
                .summary(format!("kvno {kvno}, {}", enctype(etype)))
                .lazy(keytab_entry, (entry, endian)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!("Kerberos keytab, {n} keys"));
    Ok(())
}

async fn keytab_entry(cx: Cx, (entry, endian): (Span, Endian)) -> Result<()> {
    let mut e = Cursor::new(&cx, entry, endian);
    let at = e.pos();
    let count = e.u16().await?;
    cx.emit(
        Node::new("Components")
            .span(e.since(at))
            .value(uint(count, 16)),
    );
    let mut n = u64::from(count);
    if endian == LE {
        n = n.saturating_sub(1);
    }
    for i in 0..=n.min(16) {
        let at = e.pos();
        let l = u64::from(e.u16().await?);
        let s = String::from_utf8_lossy(&e.bytes(l).await?).into_owned();
        cx.emit(
            Node::new(if i == 0 {
                "Realm".to_owned()
            } else {
                format!("Component {i}")
            })
            .span(e.since(at))
            .value(text(s)),
        );
    }
    let at = e.pos();
    let kind = e.u32().await?;
    cx.emit(
        Node::new("Name type")
            .span(e.since(at))
            .value(uint(kind, 32)),
    );
    let at = e.pos();
    let stamp = e.u32().await?;
    cx.emit(Node::new("Timestamp").span(e.since(at)).value(time(stamp)));
    let at = e.pos();
    let kvno = e.u8().await?;
    cx.emit(
        Node::new("Key version (8-bit)")
            .span(e.since(at))
            .value(uint(kvno, 8)),
    );
    let at = e.pos();
    let etype = e.u16().await?;
    cx.emit(
        Node::new("Encryption type")
            .span(e.since(at))
            .value(Value::Enum {
                raw: etype.into(),
                bits: 16,
                name: Some(enctype(etype)),
            }),
    );
    let at = e.pos();
    let klen = u64::from(e.u16().await?);
    e.skip(klen);
    cx.emit(
        Node::new("Key")
            .span(e.since(at))
            .summary(format!("{klen} bytes")),
    );
    if e.remaining() >= 4 {
        let at = e.pos();
        let v = e.u32().await?;
        cx.emit(
            Node::new("Key version (32-bit)")
                .span(e.since(at))
                .value(uint(v, 32)),
        );
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Kerberos credential cache

declare_format!(pub CCACHE = "krb5-ccache", "Kerberos credential cache", ["ccache"], "application/x-krb5-ccache",
    Probe::Custom(ccache_probe), ccache);

fn ccache_probe(h: &Head<'_>) -> bool {
    // v4 has a header-tag length (usually 12); v3 starts with a principal.
    (h.starts_with(b"\x05\x04") && u16_be(h.data, 2).is_some_and(|l| l <= 64 && l % 4 == 0))
        || (h.starts_with(b"\x05\x03") && u32_be(h.data, 2).is_some_and(|t| t <= 10))
}

/// A principal: name type, component count, realm, components.
async fn principal(cur: &mut Cursor<'_>, v3: bool) -> Result<String> {
    let _kind = cur.u32().await?;
    let mut count = u64::from(cur.u32().await?);
    if !v3 {
        count = count.min(64);
    }
    let l = u64::from(cur.u32().await?);
    let realm = String::from_utf8_lossy(&cur.bytes(l).await?).into_owned();
    let mut parts = Vec::new();
    for _ in 0..count.min(64) {
        let l = u64::from(cur.u32().await?);
        parts.push(String::from_utf8_lossy(&cur.bytes(l).await?).into_owned());
    }
    Ok(format!("{}@{realm}", parts.join("/")))
}

async fn counted(cur: &mut Cursor<'_>) -> Result<Span> {
    let l = u64::from(cur.u32().await?);
    let span = cur.span(l);
    if span.len < l {
        return Err(Diagnostic::truncated(
            Span::new(span.source, span.offset, l),
            span.len,
        ));
    }
    cur.skip(l);
    Ok(span)
}

async fn ccache(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let version = cur.u16().await?;
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 2))
            .value(hex(version, 16)),
    );
    if version == 0x0504 {
        let at = cur.pos();
        let len = u64::from(cur.u16().await?);
        cur.skip(len);
        cx.emit(
            Node::new("Header tags")
                .span(cur.since(at))
                .summary(format!("{len} bytes")),
        );
    }
    let at = cur.pos();
    let default = principal(&mut cur, false).await?;
    cx.emit(
        Node::new("Default principal")
            .span(cur.since(at))
            .value(text(default.clone())),
    );
    let mut n = 0u32;
    while cur.remaining() > 0 {
        let start = cur.pos();
        let client = principal(&mut cur, false).await?;
        let server = principal(&mut cur, false).await?;
        let etype = cur.u16().await?;
        let key = counted(&mut cur).await?;
        let auth = cur.u32().await?;
        let _start_time = cur.u32().await?;
        let end = cur.u32().await?;
        let _renew = cur.u32().await?;
        let _skey = cur.u8().await?;
        let flags = cur.u32().await?;
        let addresses = cur.u32().await?;
        for _ in 0..addresses.min(64) {
            cur.skip(2);
            counted(&mut cur).await?;
        }
        let authdata = cur.u32().await?;
        for _ in 0..authdata.min(64) {
            cur.skip(2);
            counted(&mut cur).await?;
        }
        let ticket = counted(&mut cur).await?;
        let second = counted(&mut cur).await?;
        let span = cur.since(start);
        cx.push(
            Node::new(server.clone())
                .span(span)
                .summary(format!(
                    "for {client}, {}, flags {flags:#x}",
                    enctype(etype)
                ))
                .lazy(ccache_cred, (input, auth, end, etype, key, ticket, second)),
        )
        .await;
        n = n.saturating_add(1);
    }
    cx.annotate(format!(
        "Kerberos credential cache v{}, {default}, {n} credentials",
        version & 0xff
    ));
    Ok(())
}

async fn ccache_cred(
    cx: Cx,
    (input, auth, end, etype, key, ticket, second): (Input, u32, u32, u16, Span, Span, Span),
) -> Result<()> {
    cx.emit(Node::new("Authenticated").value(time(auth)));
    cx.emit(Node::new("Expires").value(time(end)));
    cx.emit(Node::new("Session key").span(key).summary(format!(
        "{}, {} bytes",
        enctype(etype),
        key.len
    )));
    // Tickets are DER (ASN.1 application tag 1).
    cx.emit(embedded_as("Ticket", input.nested(ticket), &DER));
    if second.len > 0 {
        cx.emit(embedded_as("Second ticket", input.nested(second), &DER));
    }
    Ok(())
}
