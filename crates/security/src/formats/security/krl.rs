//! OpenSSH key revocation lists (`ssh-keygen -k`; PROTOCOL.krl): a header,
//! then sections revoking certificates by serial number or key ID under a
//! CA, explicit keys, and key hashes, optionally signed.

use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::text::ssh::{BLOB, ssh_string, string_node};
use crate::formats::util::fmt::plural;
use crate::formats::util::val;
use crate::formats::{Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value};

declare_format!(pub KRL = "openssh-krl", "OpenSSH key revocation list", ["krl"],
    "application/octet-stream", Probe::Magic(&[(0, b"SSHKRL\n\0\0\0\0\x01")]), dissect);

const SECTIONS: EnumTable = &[
    (1, "CERTIFICATES"),
    (2, "EXPLICIT_KEY"),
    (3, "FINGERPRINT_SHA1"),
    (4, "SIGNATURE"),
    (5, "FINGERPRINT_SHA256"),
];

const CERT_SECTIONS: EnumTable = &[
    (0x20, "CERT_SERIAL_LIST"),
    (0x21, "CERT_SERIAL_RANGE"),
    (0x22, "CERT_SERIAL_BITMAP"),
    (0x23, "CERT_KEY_ID"),
];

/// Most entries listed in one section.
const MAX_ENTRIES: u64 = 1 << 20;

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, Endian::Big);
    let start = cur.pos();
    let magic = cur.bytes(8).await?;
    cx.emit(string_node(
        "Magic",
        magic.get(..6).unwrap_or_default(),
        cur.since(start),
    ));
    let u32_field =
        |name: &'static str, v: u32, span: Span| Node::new(name).span(span).value(val::uint(v, 32));
    let start = cur.pos();
    let format = cur.u32().await?;
    cx.emit(u32_field("Format version", format, cur.since(start)));
    let start = cur.pos();
    let version = cur.u64().await?;
    cx.emit(
        Node::new("KRL version")
            .span(cur.since(start))
            .value(val::uint(version, 64)),
    );
    let start = cur.pos();
    let date = cur.u64().await?;
    cx.emit(
        Node::new("Generated")
            .span(cur.since(start))
            .value(Value::Timestamp {
                unix_seconds: i64::try_from(date).unwrap_or(i64::MAX),
            }),
    );
    let start = cur.pos();
    let flags = cur.u64().await?;
    cx.emit(
        Node::new("Flags")
            .span(cur.since(start))
            .value(val::hex(flags, 64)),
    );
    let (reserved, span) = ssh_string(&mut cur).await?;
    cx.emit(string_node("Reserved", &reserved, span));
    let (comment, span) = ssh_string(&mut cur).await?;
    cx.emit(string_node("Comment", &comment, span));
    let mut kinds = Vec::new();
    while !cur.at_end() {
        cx.checkpoint().await;
        let start = cur.pos();
        let kind = cur.u8().await?;
        let name = crate::value::lookup(SECTIONS, kind.into());
        kinds.push(name.unwrap_or("unknown").to_owned());
        if kind == 4 {
            // Not wrapped: the signing key and the signature follow.
            let (_, key) = ssh_string(&mut cur).await?;
            let (sig, sig_span) = ssh_string(&mut cur).await?;
            let node = Node::new("Section SIGNATURE")
                .span(cur.since(start))
                .lazy(
                    crate::expander!(self::signature: (Input, Span, Span)),
                    (input, key, sig_span),
                )
                .summary(format!("{} bytes", sig.len()));
            cx.push(node).await;
            continue;
        }
        let (body, span) = ssh_string(&mut cur).await?;
        let data = span.sub(4, span.len.saturating_sub(4));
        let mut node = Node::new(format!("Section {}", name.unwrap_or("unknown")))
            .span(cur.since(start))
            .summary(format!("{} bytes", body.len()));
        node = match kind {
            1 => node.lazy(
                crate::expander!(self::certificates: (Input, Span)),
                (input, data),
            ),
            2 => node.lazy(crate::expander!(self::keys: (Input, Span)), (input, data)),
            3 | 5 => node.lazy(crate::expander!(self::hashes: Span), data),
            _ => node.diag(Diagnostic::note(format!("unknown section type {kind}"))),
        };
        cx.push(node).await;
    }
    let mut summary = format!("OpenSSH KRL version {version}");
    if !comment.is_empty() {
        summary = format!("{summary}, \"{}\"", String::from_utf8_lossy(&comment));
    }
    cx.annotate(format!("{summary}, sections: {}", kinds.join(", ")));
    Ok(())
}

/// A CERTIFICATES section: the CA key, then sub-sections.
async fn certificates(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Big);
    let (_, key) = ssh_string(&mut cur).await?;
    if key.len > 4 {
        cx.emit(embedded_as(
            "CA key",
            input.nested(key.sub(4, key.len.saturating_sub(4))),
            &BLOB,
        ));
    } else {
        cx.emit(Node::new("CA key").span(key).summary("any CA"));
    }
    let (reserved, rspan) = ssh_string(&mut cur).await?;
    cx.emit(string_node("Reserved", &reserved, rspan));
    while !cur.at_end() {
        cx.checkpoint().await;
        let start = cur.pos();
        let kind = u64::from(cur.u8().await?);
        let (body, sspan) = ssh_string(&mut cur).await?;
        let data = sspan.sub(4, sspan.len.saturating_sub(4));
        let name = crate::value::lookup(CERT_SECTIONS, kind).unwrap_or("unknown");
        let summary = match kind {
            0x20 => plural(u64::try_from(body.len() / 8).unwrap_or(0), "serial"),
            0x21 => {
                let n = |at: usize| crate::bytes::u64_be(&body, at).unwrap_or(0);
                format!("serials {} to {}", n(0), n(8))
            }
            _ => format!("{} bytes", body.len()),
        };
        cx.push(
            Node::new(name.to_owned())
                .span(cur.since(start))
                .summary(summary)
                .lazy(
                    crate::expander!(self::cert_section: (Span, u64)),
                    (data, kind),
                ),
        )
        .await;
    }
    Ok(())
}

/// The entries of a certificate sub-section.
async fn cert_section(cx: Cx, (span, kind): (Span, u64)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Big);
    let mut n = 0u64;
    match kind {
        0x20 => {
            while cur.remaining() >= 8 && n < MAX_ENTRIES {
                let start = cur.pos();
                let serial = cur.u64().await?;
                cx.push(
                    Node::new("Serial")
                        .span(cur.since(start))
                        .value(val::uint(serial, 64)),
                )
                .await;
                n = n.saturating_add(1);
            }
        }
        0x21 => {
            for name in ["Minimum serial", "Maximum serial"] {
                let start = cur.pos();
                let serial = cur.u64().await?;
                cx.emit(
                    Node::new(name)
                        .span(cur.since(start))
                        .value(val::uint(serial, 64)),
                );
            }
        }
        0x22 => {
            let start = cur.pos();
            let offset = cur.u64().await?;
            cx.emit(
                Node::new("Serial offset")
                    .span(cur.since(start))
                    .value(val::uint(offset, 64)),
            );
            let (bitmap, bspan) = ssh_string(&mut cur).await?;
            let set: u32 = bitmap.iter().map(|b| b.count_ones()).sum();
            cx.emit(
                Node::new("Revoked bitmap")
                    .span(bspan)
                    .value(Value::Bytes(bitmap.iter().take(64).copied().collect()))
                    .summary(plural(u64::from(set), "serial")),
            );
        }
        0x23 => {
            while !cur.at_end() && n < MAX_ENTRIES {
                let (id, ispan) = ssh_string(&mut cur).await?;
                cx.push(string_node("Key ID", &id, ispan)).await;
                n = n.saturating_add(1);
            }
        }
        _ => {}
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(cur.span(cur.remaining())));
    }
    Ok(())
}

/// An EXPLICIT_KEY section: public key blobs.
async fn keys(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Big);
    let mut n = 0u64;
    while !cur.at_end() && n < MAX_ENTRIES {
        let (_, kspan) = ssh_string(&mut cur).await?;
        let blob = kspan.sub(4, kspan.len.saturating_sub(4));
        cx.push(embedded_as("Key", input.nested(blob), &BLOB)).await;
        n = n.saturating_add(1);
    }
    Ok(())
}

/// A FINGERPRINT section: key hashes.
async fn hashes(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Big);
    let mut n = 0u64;
    while !cur.at_end() && n < MAX_ENTRIES {
        let (hash, hspan) = ssh_string(&mut cur).await?;
        cx.push(
            Node::new("Hash")
                .span(hspan)
                .value(Value::Bytes(hash.iter().take(64).copied().collect())),
        )
        .await;
        n = n.saturating_add(1);
    }
    Ok(())
}

/// A SIGNATURE section: the signing key and the signature.
async fn signature(cx: Cx, (input, key, sig): (Input, Span, Span)) -> Result<()> {
    cx.emit(embedded_as(
        "Signing key",
        input.nested(key.sub(4, key.len.saturating_sub(4))),
        &BLOB,
    ));
    cx.emit(Node::new("Signature").span(sig));
    Ok(())
}
