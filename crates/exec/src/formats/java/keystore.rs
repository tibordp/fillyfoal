//! Java KeyStore files: JKS (`FEEDFEED`) and JCEKS (`CECECECE`).
//!
//! A header, then entries (private keys with certificate chains, trusted
//! certificates, and in JCEKS sealed secret keys), then a SHA-1 integrity
//! digest. Keys and certificates are DER blobs, shown as embedded content.

use super::serialization;
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::util::binutil::mutf8;
use crate::formats::util::fmt::clip;
use crate::formats::util::val::{name_or, text};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
/// Largest entry we read in one block.
const MAX_ENTRY: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "jks",
    title: "Java KeyStore",
    extensions: &["jks", "jceks", "keystore", "ks", "truststore"],
    mime: "application/x-java-keystore",
    probe: Probe::Magic(&[(0, b"\xfe\xed\xfe\xed"), (0, b"\xce\xce\xce\xce")]),
    dissect: crate::expander!(dissect: Input),
};

const TAG: EnumTable = &[
    (1, "PrivateKeyEntry"),
    (2, "TrustedCertificateEntry"),
    (3, "SecretKeyEntry"),
];

#[derive(Clone, Copy, Debug)]
struct Ctx {
    input: Input,
    version: u32,
    jceks: bool,
}

struct EntryInfo {
    tag: u32,
    alias: String,
    certificates: u32,
}

fn header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u32)> {
    let magic = f
        .u32("magic")
        .hex()
        .with(|&v, n| n.summary(if v == 0xcece_cece { "JCEKS" } else { "JKS" }))
        .emit()?;
    let version = f.u32("version").emit()?;
    let count = f.u32("count").desc("Number of entries").emit()?;
    Ok((magic, version, count))
}

/// A modified-UTF-8 string with a two-byte length.
fn utf(f: &mut Fields<'_>, label: &'static str) -> Result<String> {
    let len = f.u16(label).get()?;
    f.bytes(label, len.into())
        .with(|v, n| n.value(text(mutf8(v))))
        .emit()
        .map(|b| mutf8(&b))
}

fn certificate(f: &mut Fields<'_>, c: &Ctx, label: &'static str) -> Result<()> {
    // Version 1 key stores hold X.509 certificates only.
    let kind = if c.version == 2 {
        utf(f, "certificate type")?
    } else {
        "X.509".to_owned()
    };
    let len = f.u32("certificate length").emit()?;
    let span = f.peek_span(len.into());
    let inner = c.input.nested(span);
    f.node(if kind == "X.509" {
        embedded_as(label, inner, &crate::formats::asn1::X509)
    } else {
        embedded(label, inner).summary(format!("{len} bytes, {kind}"))
    });
    f.skip(len.into());
    if f.pos() > f.block().span.len {
        return Err(Diagnostic::truncated(span, 0));
    }
    Ok(())
}

/// An entry, decoded (and emitted, if `f` is emitting). Async because a
/// sealed key's length is only known by decoding its serialized object.
async fn entry(cx: &Cx, f: &mut Fields<'_>, c: &Ctx) -> Result<EntryInfo> {
    let tag = f.u32("tag").enumeration(TAG).emit()?;
    let alias = utf(f, "alias")?;
    f.u64("timestamp")
        .with(|&v, n| {
            n.value(Value::Timestamp {
                unix_seconds: i64::try_from(v / 1000).unwrap_or(i64::MAX),
            })
        })
        .desc("Creation time (milliseconds since 1970)")
        .emit()?;
    let mut certificates = 0;
    match tag {
        1 => {
            let len = f.u32("key length").emit()?;
            let span = f.peek_span(len.into());
            f.node(embedded_as(
                "Protected key",
                c.input.nested(span),
                &crate::formats::asn1::PKCS8_ENCRYPTED,
            ));
            f.skip(len.into());
            certificates = f.u32("chain length").emit()?;
            for _ in 0..certificates {
                certificate(f, c, "Certificate")?;
            }
        }
        2 => {
            certificates = 1;
            certificate(f, c, "Certificate")?;
        }
        3 if c.jceks => {
            // A serialized javax.crypto.SealedObject, without a length.
            let rest = f
                .block()
                .data
                .get(crate::bytes::to_usize(f.pos())..)
                .unwrap_or_default();
            let len = serialization::stream_len(cx, rest)
                .await
                .ok_or_else(|| Diagnostic::malformed("unreadable sealed key").at(f.peek_span(1)))?;
            let span = f.peek_span(to_u64(len));
            f.node(
                embedded("Sealed key", c.input.nested(span))
                    .summary(format!("{len} bytes, serialized SealedObject")),
            );
            f.skip(to_u64(len));
        }
        _ => {
            return Err(Diagnostic::unsupported(format!("entry tag {tag}")));
        }
    }
    if f.pos() > f.block().span.len {
        return Err(Diagnostic::truncated(f.block().span, f.block().span.len));
    }
    Ok(EntryInfo {
        tag,
        alias,
        certificates,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = file.sub(0, 12);
    cx.emit(struct_node("Header", head, BE, (), header));
    let (magic, version, count) = parse(&cx, head, BE, &(), header).await?;
    let ctx = Ctx {
        input,
        version,
        jceks: magic == 0xcece_cece,
    };
    let kind = if ctx.jceks { "JCEKS" } else { "JKS" };
    let mut offset = 12u64;
    let mut entries = Vec::new();
    for _ in 0..count {
        if offset >= file.len {
            break;
        }
        let region = file.sub(offset, MAX_ENTRY);
        let block = cx.block(region).await?;
        let mut f = Fields::new(&block, BE);
        match entry(&cx, &mut f, &ctx).await {
            Ok(info) => {
                let span = file.sub(offset, f.pos());
                entries.push((span, info));
                offset = offset.saturating_add(f.pos());
            }
            Err(e) => {
                cx.diag(e);
                break;
            }
        }
    }
    // 64 aliases join to more than the 100 characters shown.
    let aliases: Vec<&str> = entries
        .iter()
        .take(64)
        .map(|(_, e)| e.alias.as_str())
        .collect();
    cx.annotate(format!(
        "Java KeyStore ({kind} v{version}), {count} entries: {}",
        clip(&aliases.join(", "), 100)
    ));
    let table = file.sub(12, offset.saturating_sub(12));
    cx.emit(
        Node::new("Entries")
            .span(table)
            .summary(format!("{} entries", entries.len()))
            .lazy(
                entry_list,
                (ctx, entries.iter().map(|(s, _)| *s).collect::<Vec<_>>()),
            ),
    );
    let digest = file.sub(offset, 20);
    let bytes = cx.read_avail(digest).await?;
    cx.emit(
        Node::new("Digest")
            .span(digest)
            .value(text(crate::text::hex_lower(&bytes)))
            .desc("SHA-1 over the password (UTF-16), \"Mighty Aphrodite\" and the keystore")
            .lazy(verify_digest, (input, offset)),
    );
    if offset.saturating_add(20) < file.len {
        cx.emit(
            Node::new("Trailing data")
                .span(file.tail(offset.saturating_add(20)))
                .diag(Diagnostic::warning("data after the integrity digest")),
        );
    }
    Ok(())
}

async fn entry_list(cx: Cx, (ctx, spans): (Ctx, Vec<Span>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(spans.len())));
    for span in spans {
        let block = cx.block(span).await?;
        let info = entry(&cx, &mut Fields::new(&block, BE), &ctx).await?;
        let mut summary = name_or(TAG, info.tag.into(), "tag");
        if info.tag == 1 {
            summary.push_str(&format!(", chain of {}", info.certificates));
        }
        let node = Node::new(info.alias)
            .span(span)
            .lazy(entry_view, (ctx, span))
            .summary(summary);
        cx.push(node).await;
    }
    Ok(())
}

/// An entry's fields.
async fn entry_view(cx: Cx, (ctx, span): (Ctx, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    entry(&cx, &mut Fields::emitting(&cx, &block, BE), &ctx).await?;
    Ok(())
}

/// Largest key store whose digest is checked.
const MAX_CHECKED: u64 = 16 << 20;

/// The integrity digest for `password`: SHA-1 of the password as UTF-16BE,
/// "Mighty Aphrodite" and the store, hashed a piece at a time.
async fn store_digest(cx: &Cx, password: &[u8], data: &[u8]) -> Vec<u8> {
    use crate::codec::crypto::{Hash, Sha1};
    let pw: Vec<u8> = String::from_utf8_lossy(password)
        .encode_utf16()
        .flat_map(u16::to_be_bytes)
        .collect();
    let mut h = Sha1::new();
    h.update(&pw);
    h.update(b"Mighty Aphrodite");
    for piece in data.chunks(4096) {
        h.update(piece);
        cx.checkpoint().await;
    }
    h.finish()
}

/// Checks the integrity digest with the store password.
async fn verify_digest(cx: Cx, (input, offset): (Input, u64)) -> Result<()> {
    let file = input.span;
    let node = Node::new("Integrity check").span(file.sub(offset, 20));
    if offset > MAX_CHECKED {
        cx.emit(node.diag(Diagnostic::limit("key store too large to check")));
        return Ok(());
    }
    let data = cx.read(file.sub(0, offset)).await?;
    let expected = cx.read(file.sub(offset, 20)).await?;
    let mut verified =
        (store_digest(&cx, b"", &data).await == expected).then_some("verified (empty password)");
    let mut attempt = 0;
    while verified.is_none() && attempt < crate::secret::MAX_ATTEMPTS {
        let request = crate::secret::SecretRequest::password(
            file,
            "Password for the Java key store",
            attempt,
        );
        let Some(secret) = cx.secret(request).await else {
            break;
        };
        if store_digest(&cx, secret.expose(), &data).await == expected {
            verified = Some("verified with the store password");
        }
        attempt = attempt.saturating_add(1);
    }
    cx.emit(match verified {
        Some(how) => node.summary(how),
        None => node.diag(Diagnostic::note(
            "not checked (no password, or a wrong one)",
        )),
    });
    Ok(())
}
