//! Proxmox Backup Server data blobs: the `.blob` files of a backup
//! snapshot (`index.json.blob`, `client.log.blob`, ...) and every chunk in
//! a datastore's `.chunks` directory.
//!
//! An 8-byte magic (the first bytes of the SHA-256 of a description)
//! names one of four kinds: uncompressed, zstd-compressed, encrypted
//! (AES-256-GCM), and compressed then encrypted. A little-endian CRC-32
//! of everything after the header follows; encrypted blobs then hold the
//! 16-byte IV and the 16-byte GCM tag. The rest is the data.
//!
//! Plain blobs are decompressed and their content dissected (a JSON
//! manifest, a pxar archive or part of one, a catalog, a slice of a disk
//! image). Encrypted blobs need the key from the client's key file, which
//! is not in the datastore; they are shown as ciphertext. Chunks of
//! larger archives are slices cut at content-defined boundaries, so only
//! the first chunk of an archive is identified as that archive.
//!
//! The layout is from Proxmox Backup's `docs/file-formats.rst` and
//! `pbs-datastore/src/file_formats.rs` / `data_blob.rs` (AGPL-3.0), read
//! for facts only; checked against blobs written by Proxmox Backup Server
//! 3.4.9.

use crate::bytes::{to_u64, u32_le};
use crate::codec::crc::crc32_update;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::size;
use crate::formats::util::val::{hex, text};
use crate::formats::{Codec, Format, Input, Probe, content, embedded};
use crate::node::Node;
use crate::span::Span;

const UNCOMPRESSED: [u8; 8] = [66, 171, 56, 7, 190, 131, 112, 161];
const COMPRESSED: [u8; 8] = [49, 185, 88, 66, 111, 182, 163, 127];
const ENCRYPTED: [u8; 8] = [123, 103, 133, 190, 34, 45, 76, 240];
const ENCRYPTED_COMPRESSED: [u8; 8] = [230, 89, 27, 191, 11, 191, 216, 11];
/// `MAX_BLOB_SIZE` of the reference implementation.
const MAX_BLOB: u64 = 128 * 1024 * 1024;
/// Blobs up to this size have their CRC checked at once.
const EAGER_CRC: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "pbs-blob",
    title: "Proxmox Backup Server data blob",
    extensions: &["blob"],
    mime: "application/x-proxmox-backup-blob",
    probe: Probe::Magic(&[
        (0, &UNCOMPRESSED),
        (0, &COMPRESSED),
        (0, &ENCRYPTED),
        (0, &ENCRYPTED_COMPRESSED),
    ]),
    dissect: crate::expander!(dissect: Input),
};

/// The CRC-32 of `span`, read in pieces.
async fn crc_of(cx: &Cx, span: Span) -> Result<u32> {
    let mut crc = u32::MAX;
    let mut off = 0u64;
    while off < span.len {
        let piece = cx.read(span.sub(off, 1 << 16)).await?;
        if piece.is_empty() {
            break;
        }
        crc = crc32_update(crc, &piece);
        off = off.saturating_add(to_u64(piece.len()));
        cx.checkpoint().await;
    }
    Ok(!crc)
}

fn check(node: Node, stored: u32, computed: u32) -> Node {
    if stored == computed {
        node.summary("valid")
    } else {
        node.diag(Diagnostic::malformed(format!(
            "CRC mismatch: computed {computed:#010x}"
        )))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 12)).await?;
    let magic = head.get(..8).unwrap_or_default();
    let (kind, encrypted, compressed) = if magic == UNCOMPRESSED {
        ("uncompressed", false, false)
    } else if magic == COMPRESSED {
        ("zstd-compressed", false, true)
    } else if magic == ENCRYPTED {
        ("encrypted", true, false)
    } else {
        ("encrypted, zstd-compressed", true, true)
    };
    cx.emit(Node::new("Magic").span(file.sub(0, 8)).value(text(kind)));
    let Some(stored) = u32_le(&head, 8) else {
        return Err(Diagnostic::truncated(
            file.sub(8, 4),
            file.len.saturating_sub(8),
        ));
    };
    let header = if encrypted { 44 } else { 12 };
    let data = file.tail(header);
    let crc_span = file.sub(8, 4);
    let crc = Node::new("CRC32")
        .span(crc_span)
        .value(hex(stored, 32))
        .desc("CRC-32 of everything after the header");
    cx.emit(if data.len <= EAGER_CRC {
        check(crc, stored, crc_of(&cx, data).await?)
    } else {
        crc.lazy(crc_expand, (data, stored))
    });
    if data.len > MAX_BLOB {
        cx.diag(Diagnostic::warning(format!(
            "larger than Proxmox Backup's maximum blob size ({})",
            size(MAX_BLOB)
        )));
    }
    cx.annotate(format!(
        "Proxmox Backup data blob, {kind}, {}",
        size(data.len)
    ));
    if encrypted {
        cx.emit(Node::new("IV").span(file.sub(12, 16)));
        cx.emit(
            Node::new("Tag")
                .span(file.sub(28, 16))
                .desc("AES-256-GCM authentication tag"),
        );
        cx.emit(
            Node::new("Ciphertext")
                .span(data)
                .summary(size(data.len))
                .diag(Diagnostic::unsupported(
                    "AES-256-GCM with the key from the backup client's key file (not in the datastore)",
                )),
        );
    } else if compressed {
        cx.emit(content("Data", input, data, Codec::Zstd, None).summary(size(data.len)));
    } else {
        cx.emit(embedded("Data", input.nested(data)).summary(size(data.len)));
    }
    Ok(())
}

async fn crc_expand(cx: Cx, (data, stored): (Span, u32)) -> Result<()> {
    let computed = crc_of(&cx, data).await?;
    cx.emit(check(
        Node::new("Computed").span(data).value(hex(computed, 32)),
        stored,
        computed,
    ));
    Ok(())
}
