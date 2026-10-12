//! GnuPG keybox (`pubring.kbx`), the key store of GnuPG 2.1+ and gpgsm.
//!
//! A sequence of blobs, each `u32` length (big-endian, counting itself) and
//! a type byte: a 32-byte header blob (`KBXf`), then one blob per OpenPGP
//! keyblock or X.509 certificate. A key blob carries an index of the keys
//! (fingerprint, key ID offset), the serial number, the user IDs (offsets
//! into the keyblock for OpenPGP; issuer, subject and e-mail strings in the
//! blob for X.509), signature expiry slots, trust bytes and times, then the
//! keyblock or certificate itself and a SHA-1 of everything before it.
//! Layout as documented in GnuPG's `kbx/keybox-blob.c` and checked against
//! `kbxutil` on files written by GnuPG 2.2 and 2.4.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::codec::crypto::Md5;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::datakit::{digest_paced, sha1_paced};
use crate::formats::util::fmt::clip;
use crate::formats::{Input, Probe, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::text::hex_upper;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

const BE: Endian = Endian::Big;

/// Fixed part of a key blob, before the key table.
const KEY_BLOB_HEAD: u64 = 20;
/// The SHA-1 at the end of every blob.
const CHECKSUM: u64 = 20;
/// Bytes of a blob read for its summary in the listing.
const SUMMARY_READ: u64 = 4096;

fn keybox_probe(h: &crate::formats::Head<'_>) -> bool {
    h.at(8, b"KBXf")
}

declare_format!(pub KEYBOX = "keybox", "GnuPG keybox", ["kbx"], "application/x-gnupg-keybox",
    Probe::Custom(keybox_probe), keybox);

const KEYBOX_TYPES: EnumTable = &[(0, "empty"), (1, "header"), (2, "OpenPGP"), (3, "X.509")];

const HEADER_FLAGS: FlagTable = &[flag(0x2, "OPENPGP")];

const BLOB_FLAGS: FlagTable = &[flag(0x1, "SECRET"), flag(0x2, "EPHEMERAL")];

const KEY_FLAGS: FlagTable = &[flag(0x1, "QUALIFIED")];

/// Signature expiry slots: special values, else a time.
const SIG_EXPIRY: EnumTable = &[
    (0, "not checked"),
    (1, "missing key"),
    (2, "bad signature"),
    (0xffff_ffff, "valid, does not expire"),
];

async fn keybox(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    let mut counts = [0u32; 4];
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let kind = cur.u8().await?;
        if len < 5 {
            cx.diag(Diagnostic::malformed("blob shorter than its header").at(cur.since(start)));
            break;
        }
        cur.seek(start.saturating_add(len.into()));
        if let Some(c) = counts.get_mut(usize::from(kind)) {
            *c = c.saturating_add(1);
        }
        let name = lookup(KEYBOX_TYPES, kind.into()).unwrap_or("unknown");
        let span = input.span.sub(start, len.into());
        cx.progress_in(input.span, input.span.offset.saturating_add(start));
        let mut summary = None;
        if kind == 2 || kind == 3 {
            let head = cx.read_avail(span.sub(0, SUMMARY_READ)).await?;
            summary = blob_summary(&head, kind);
        }
        cx.push(
            Node::new(format!("{name} blob"))
                .span(span)
                .summary(summary.unwrap_or_else(|| format!("{len} bytes")))
                .lazy(blob, (input, span)),
        )
        .await;
    }
    cx.annotate(format!(
        "{} OpenPGP and {} X.509 blob(s)",
        counts[2], counts[3]
    ));
    Ok(())
}

/// The listing's summary of a key blob from its first bytes: the primary
/// user ID (the subject for X.509) and the first fingerprint.
fn blob_summary(p: &[u8], kind: u8) -> Option<String> {
    let keys = usize::from(u16_be(p, 16)?);
    let key_size = usize::from(u16_be(p, 18)?);
    let fpr = (keys > 0 && key_size >= 20)
        .then(|| p.get(20..40))
        .flatten()
        .map(hex_upper);
    let uid = (|| {
        let serial_at = keys.checked_mul(key_size)?.checked_add(20)?;
        let uids_at = serial_at
            .checked_add(2)?
            .checked_add(usize::from(u16_be(p, serial_at)?))?;
        let uids = usize::from(u16_be(p, uids_at)?);
        let uid_size = usize::from(u16_be(p, uids_at.checked_add(2)?)?);
        let pick = usize::from(kind == 3 && uids > 1);
        if uids == 0 || uid_size < 8 {
            return None;
        }
        let entry = uids_at
            .checked_add(4)?
            .checked_add(pick.checked_mul(uid_size)?)?;
        let off = to_usize(u32_be(p, entry)?.into());
        let len = to_usize(u32_be(p, entry.checked_add(4)?)?.into());
        let text = p.get(off..off.checked_add(len)?)?;
        Some(clip(&String::from_utf8_lossy(text), 80))
    })();
    match (uid, fpr) {
        (Some(u), Some(f)) => Some(format!("{u}, {f}")),
        (u, f) => u.or(f),
    }
}

async fn blob(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Length").emit()?;
    let kind = f
        .u8("Type")
        .enumeration(KEYBOX_TYPES)
        .desc("Blob type")
        .emit()?;
    f.u8("Version").emit()?;
    match kind {
        1 => {
            f.u16("Flags").flags(HEADER_FLAGS).emit()?;
            f.ascii("Magic", 4).emit()?;
            f.u32("Reserved").emit()?;
            f.u32("Created").timestamp().emit()?;
            f.u32("Last maintenance").timestamp().emit()?;
            f.u32("Reserved").emit()?;
            f.u32("Reserved").emit()?;
            Ok(())
        }
        2 | 3 => key_blob(&cx, &input, span, f, kind == 3).await,
        _ => {
            // Type 0 marks a deleted blob; its bytes are left as they were.
            let rest = span.tail(f.pos());
            if rest.len > 0 {
                cx.emit(Node::new("Unused").span(rest));
            }
            Ok(())
        }
    }
}

async fn key_blob(cx: &Cx, input: &Input, span: Span, mut f: Fields<'_>, x509: bool) -> Result<()> {
    let version = f.block().data.get(5).copied().unwrap_or(0);
    f.u16("Blob flags").flags(BLOB_FLAGS).emit()?;
    let data_off = f
        .u32("Data offset")
        .hex()
        .desc(if x509 {
            "Offset of the DER certificate in the blob"
        } else {
            "Offset of the OpenPGP keyblock in the blob"
        })
        .emit()?;
    let data_len = f.u32("Data length").emit()?;
    let data = span.sub(data_off.into(), data_len.into());

    // The index; a damaged table stops it, the keyblock and checksum still show.
    if let Err(e) = tables(cx, &mut f, span, version, x509).await {
        cx.diag(e);
    }

    let end = to_u64(f.block().data.len()).saturating_sub(CHECKSUM);
    let data_end = u64::from(data_off).saturating_add(data_len.into());
    if u64::from(data_off) < KEY_BLOB_HEAD || data_end > end {
        cx.diag(Diagnostic::malformed("keyblock outside the blob").at(span.sub(8, 8)));
    } else {
        let (name, format) = if x509 {
            ("Certificate", &crate::formats::asn1::X509)
        } else {
            ("Keyblock", &crate::formats::security::pgp::FORMAT)
        };
        cx.emit(embedded_as(name, input.nested(data), format));
        if data_end < end {
            cx.emit(
                Node::new("Unused")
                    .span(span.sub(data_end, end.saturating_sub(data_end)))
                    .desc("Space between the keyblock and the checksum"),
            );
        }
    }

    let body = f.block().data.get(..to_usize(end)).unwrap_or_default();
    let stored = f.block().data.get(to_usize(end)..).unwrap_or_default();
    if body.is_empty() || stored.len() != to_usize(CHECKSUM) {
        return Ok(());
    }
    let sha1 = sha1_paced(cx, body).await;
    let mut node = Node::new("Checksum")
        .span(span.sub(end, CHECKSUM))
        .value(Value::Bytes(stored.to_vec()));
    if stored == sha1 {
        node = node.summary("SHA-1, valid");
    } else if stored.get(..4) == Some(&[0, 0, 0, 0])
        && stored.get(4..) == Some(digest_paced::<Md5>(cx, body).await.as_slice())
    {
        // GnuPG before 2.1 wrote an MD5 here (and never checked it).
        node = node.summary("MD5 (GnuPG before 2.1), valid");
    } else {
        node = node
            .summary("SHA-1, mismatch")
            .diag(Diagnostic::malformed(format!(
                "checksum mismatch: computed SHA-1 {}",
                hex_upper(&sha1)
            )));
    }
    cx.emit(node.desc("Hash of the blob before it"));
    Ok(())
}

/// The key, serial number, user ID and signature tables, and the fixed
/// fields after them.
async fn tables(cx: &Cx, f: &mut Fields<'_>, span: Span, version: u8, x509: bool) -> Result<()> {
    let keys = f.u16("Key count").emit()?;
    let key_size = f
        .u16("Key info size")
        .desc("Bytes per key table entry")
        .emit()?;
    for i in 0..keys {
        let at = f.pos();
        let entry = span.sub(at, key_size.into());
        let fpr = f
            .block()
            .data
            .get(to_usize(at)..to_usize(at).saturating_add(20));
        let mut node = Node::new(format!("Key {i}")).span(entry);
        if version == 1 && key_size >= 28 {
            let fpr = fpr.unwrap_or_default();
            node = node
                .summary(hex_upper(fpr))
                .lazy(key_entry, (entry, span, x509));
        } else {
            node = node.desc("Key table entry of a blob version or size not decoded");
        }
        f.node(node);
        f.seek(at.saturating_add(key_size.into()));
        if key_size == 0 || f.remaining() == 0 {
            break;
        }
        cx.checkpoint().await;
    }
    let serial_len = f.u16("Serial number size").emit()?;
    if serial_len > 0 {
        let serial = f.bytes("Serial number", serial_len.into());
        if x509 {
            serial.desc("The certificate's serial number").emit()?;
        } else {
            serial.desc("The card serial number").emit()?;
        }
    }
    let uids = f.u16("User ID count").emit()?;
    let uid_size = f.u16("User ID info size").emit()?;
    for i in 0..uids {
        let at = f.pos();
        let data = &f.block().data;
        let uat = to_usize(at);
        let off = u32_be(data, uat).unwrap_or(0);
        let len = u32_be(data, uat.saturating_add(4)).unwrap_or(0);
        let text = data
            .get(to_usize(off.into())..to_usize(off.into()).saturating_add(to_usize(len.into())))
            .map(|t| String::from_utf8_lossy(t).into_owned());
        let name = match (x509, i) {
            (true, 0) => "Issuer".to_owned(),
            (true, 1) => "Subject".to_owned(),
            _ => format!("User ID {i}"),
        };
        let entry = span.sub(at, uid_size.into());
        let mut node = Node::new(name).span(entry);
        if let Some(t) = text {
            node = node.value(Value::Text(t));
        }
        if uid_size >= 12 {
            node = node.lazy(uid_entry, entry);
        }
        f.node(node.target(span.sub(off.into(), len.into())));
        f.seek(at.saturating_add(uid_size.into()));
        if uid_size == 0 || f.remaining() == 0 {
            break;
        }
        cx.checkpoint().await;
    }
    let sigs = f.u16("Signature count").emit()?;
    let sig_size = f.u16("Signature info size").emit()?;
    for _ in 0..sigs {
        let at = f.pos();
        let raw = u32_be(&f.block().data, to_usize(at));
        let field = f.u32("Signature expiry");
        if raw.is_some_and(|v| lookup(SIG_EXPIRY, v.into()).is_some()) {
            field.enumeration(SIG_EXPIRY).emit()?;
        } else {
            field.timestamp().emit()?;
        }
        f.seek(at.saturating_add(sig_size.max(4).into()));
        if f.remaining() == 0 {
            break;
        }
        cx.checkpoint().await;
    }
    f.u8("Ownertrust").emit()?;
    f.u8("All validity")
        .hex()
        .desc(if x509 {
            "0x20: the certificate is revoked"
        } else {
            "Validity of the key (unused)"
        })
        .emit()?;
    f.u16("Reserved").emit()?;
    f.u32("Recheck after").timestamp().emit()?;
    f.u32("Latest timestamp")
        .timestamp()
        .desc("Newest time in the keyblock (unused)")
        .emit()?;
    f.u32("Created").timestamp().emit()?;
    let reserved = f.u32("Reserved space size").emit()?;
    if reserved > 0 {
        f.bytes("Reserved space", reserved.into()).emit()?;
    }
    Ok(())
}

async fn key_entry(cx: Cx, (entry, blob, x509): (Span, Span, bool)) -> Result<()> {
    let block = cx.block(entry).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.bytes("Fingerprint", 20)
        .desc(if x509 {
            "SHA-1 of the certificate"
        } else {
            "OpenPGP v4 fingerprint"
        })
        .emit()?;
    let kid = u32_be(&block.data, 20).unwrap_or(0);
    let mut field = f
        .u32("Key ID offset")
        .hex()
        .desc("Offset of the 8-byte key ID in the blob (0 for X.509)");
    if kid != 0 {
        field = field.target(blob.sub(kid.into(), 8));
    }
    field.emit()?;
    f.u16("Key flags").flags(KEY_FLAGS).emit()?;
    f.u16("Reserved").emit()?;
    if f.remaining() > 0 {
        f.bytes("Filler", f.remaining()).emit()?;
    }
    Ok(())
}

async fn uid_entry(cx: Cx, entry: Span) -> Result<()> {
    let block = cx.block(entry).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Offset").hex().emit()?;
    f.u32("Length").emit()?;
    f.u16("Flags").hex().emit()?;
    f.u8("Validity").emit()?;
    f.u8("Reserved").emit()?;
    if f.remaining() > 0 {
        f.bytes("Filler", f.remaining()).emit()?;
    }
    Ok(())
}
