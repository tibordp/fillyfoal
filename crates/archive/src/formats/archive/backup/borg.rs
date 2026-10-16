//! BorgBackup (1.x) repository segments: the files under `data/<n>/<m>`
//! of a Borg repository, each a log of objects.
//!
//! A segment is the magic `BORG_SEG` (`ATTICSEG` in repositories from
//! Attic, Borg's predecessor) followed by entries. Each entry starts with a
//! CRC-32 (of everything after it), a little-endian size (of the whole
//! entry) and a tag: `PUT` (0) and `DELETE` (1) carry a 32-byte object ID,
//! `PUT` then the object's data; `COMMIT` (2) ends a transaction and has
//! nothing more.
//!
//! An object's data starts with a byte naming the key type. Unencrypted
//! (`none`) and `authenticated` repositories store the compressed chunk
//! right after it; the encrypted types store a 32-byte MAC, an 8-byte
//! nonce (the low 64 bits of the AES-CTR counter) and the ciphertext, which
//! is shown as such: the key lives in the repository's `config` file (or a
//! key file), not in the segment. The compressed chunk starts with a 2-byte
//! compressor ID: none, LZ4 (one raw block), LZMA (an `.xz` stream), zstd,
//! or zlib, which has no ID and is recognised by its own 2-byte header.
//! `obfuscate` wraps another compressor with a big-endian length and
//! random-length padding.
//!
//! The content is decompressed with the codecs we have and dissected.
//! Chunks of file data are identified as usual; Borg's own metadata
//! (manifest, archive and item records) is MessagePack, and a chunk that
//! decodes to an unidentified MessagePack map with a string key is shown as
//! MessagePack (item streams are sequences of maps, which the MessagePack
//! probe does not claim), the way Borg writes it (`borg-msgpack`: IDs and
//! other binary strings as hex, nanosecond times as timestamps). Item
//! streams are cut into chunks of at most 512 KiB (Borg's items chunker),
//! so they are always small enough for that check. The repository index
//! and the chunks cache are `borg_index`. Which chunk belongs to which file is recorded in
//! those item records, in other segments; a single segment does not say.
//!
//! The layout follows Borg 1.2's `repository.py` and `crypto/key.py`
//! (BSD-3-Clause), read for facts; fixtures were made with Borg 1.2.4. The
//! compressor IDs are from memory of `compress.pyx` and agree with the
//! fixtures. Borg 2's repository format (no segments) is not handled.

use crate::bytes::{u32_be, u32_le};
use crate::codec::crc::crc32_update;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::{plural, size};
use crate::formats::util::val::{enumv, hex, text, uint};
use crate::formats::{
    Codec, Format, HEAD_LEN, Head, Input, Probe, dissect_named, dissect_or_data, expand_content,
};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Check, EnumTable, Value};

pub static FORMAT: Format = Format {
    name: "borg-segment",
    title: "BorgBackup repository segment",
    extensions: &[],
    mime: "application/x-borg-segment",
    probe: Probe::Magic(&[(0, b"BORG_SEG"), (0, b"ATTICSEG")]),
    dissect: crate::expander!(dissect: Input),
};

const PUT: u8 = 0;
const DELETE: u8 = 1;
const COMMIT: u8 = 2;
const TAGS: EnumTable = &[(0, "PUT"), (1, "DELETE"), (2, "COMMIT")];
/// The header of a `COMMIT` (CRC, size, tag).
const HEADER: u64 = 9;
/// The header of a `PUT` or `DELETE` (plus the object ID).
const KEYED_HEADER: u64 = 41;
/// Borg's `MAX_OBJECT_SIZE`: the largest entry it writes.
const MAX_OBJECT: u64 = 20 * 1024 * 1024;

const KEY_TYPES: EnumTable = &[
    (0x00, "key file (AES-CTR, HMAC-SHA256)"),
    (0x01, "passphrase (AES-CTR, HMAC-SHA256; obsolete)"),
    (0x02, "none (plaintext)"),
    (0x03, "repokey (AES-CTR, HMAC-SHA256)"),
    (0x04, "key file (AES-CTR, BLAKE2b)"),
    (0x05, "repokey (AES-CTR, BLAKE2b)"),
    (0x06, "authenticated (BLAKE2b)"),
    (0x07, "authenticated (HMAC-SHA256)"),
];

/// The MAC algorithm of a key type.
fn mac_name(key_type: u8) -> &'static str {
    match key_type {
        0x04..=0x06 => "keyed BLAKE2b-256",
        _ => "HMAC-SHA-256",
    }
}

/// Why keyed IDs and MACs are not verified.
const NEEDS_KEY: &str = "needs the repository's key";

/// An object's ID: the plaintext chunk's SHA-256 (unencrypted), or its MAC
/// under the repository's ID key. Not checked: the chunk would have to be
/// decompressed, or the key is not in the segments.
fn id_check(key_type: Option<u8>, id: Vec<u8>) -> Check {
    match key_type {
        Some(0x02) => Check::new("SHA-256", id),
        Some(k) => Check::new(mac_name(k), id).skipped(NEEDS_KEY),
        None => Check::new("chunk ID", id),
    }
}

/// Whether objects of this key type are stored unencrypted.
fn plaintext(key_type: u8) -> bool {
    matches!(key_type, 0x02 | 0x06 | 0x07)
}

fn key_name(key_type: u8) -> &'static str {
    match key_type {
        0x00 | 0x04 => "key file",
        0x01 => "passphrase",
        0x02 => "plaintext",
        0x03 | 0x05 => "repokey",
        0x06 | 0x07 => "authenticated",
        _ => "unknown key type",
    }
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Compressor {
    None,
    Lz4,
    Lzma,
    Zstd,
    Zlib,
    Obfuscate,
}

impl Compressor {
    /// The compressor of a chunk starting with `b`, and its header length.
    fn detect(b: &[u8]) -> Option<(Compressor, u64)> {
        match b {
            [0, 0, ..] => Some((Compressor::None, 2)),
            [1, 0, ..] => Some((Compressor::Lz4, 2)),
            [2, 0, ..] => Some((Compressor::Lzma, 2)),
            [3, 0, ..] => Some((Compressor::Zstd, 2)),
            [4, 0, ..] => Some((Compressor::Obfuscate, 2)),
            // zlib streams carry no ID: Borg recognises their header.
            &[a, b, ..]
                if a & 0x0f == 8 && (u16::from(a) << 8 | u16::from(b)).is_multiple_of(31) =>
            {
                Some((Compressor::Zlib, 0))
            }
            _ => None,
        }
    }

    fn name(self) -> &'static str {
        match self {
            Compressor::None => "none",
            Compressor::Lz4 => "lz4",
            Compressor::Lzma => "lzma",
            Compressor::Zstd => "zstd",
            Compressor::Zlib => "zlib",
            Compressor::Obfuscate => "obfuscate",
        }
    }

    fn codec(self) -> Codec {
        match self {
            Compressor::None | Compressor::Obfuscate => Codec::Stored,
            Compressor::Lz4 => Codec::Lz4Block,
            Compressor::Lzma => Codec::Xz,
            Compressor::Zstd => Codec::Zstd,
            Compressor::Zlib => Codec::Zlib,
        }
    }
}

/// A short description of an object's data from its first bytes.
fn describe(data: &[u8]) -> String {
    let Some((&key_type, rest)) = data.split_first() else {
        return "empty".to_owned();
    };
    if !plaintext(key_type) {
        return format!("{}, encrypted", key_name(key_type));
    }
    let mut out = key_name(key_type).to_owned();
    match Compressor::detect(rest) {
        Some((Compressor::Obfuscate, _)) => {
            out.push_str(", obfuscated");
            if let Some((inner, _)) = rest.get(6..).and_then(Compressor::detect) {
                out.push_str(", ");
                out.push_str(inner.name());
            }
        }
        Some((c, _)) => {
            out.push_str(", ");
            out.push_str(c.name());
        }
        None => out.push_str(", unknown compression"),
    }
    out
}

fn hex_string(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = file.sub(0, 8);
    let m = cx.read(magic).await?;
    let attic = m == b"ATTICSEG";
    cx.emit(
        Node::new("Magic")
            .span(magic)
            .value(text(String::from_utf8_lossy(&m)))
            .summary(if attic {
                "Attic segment"
            } else {
                "Borg segment"
            }),
    );
    let (mut pos, mut index, mut counts) = cx
        .resume::<(u64, u64, [u64; 3])>()
        .unwrap_or((8, 0, [0; 3]));
    while pos < file.len {
        let at = (pos, index, counts);
        cx.mark(move || at);
        cx.progress_in(file, pos);
        // The entry header, the key type and the compressor header (for
        // `obfuscate`, the wrapped compressor's ID, 7 bytes on).
        let head = cx
            .read(file.sub(pos, KEYED_HEADER.saturating_add(16)))
            .await?;
        let (Some(crc), Some(len), Some(&tag)) = (u32_le(&head, 0), u32_le(&head, 4), head.get(8))
        else {
            cx.push(
                Node::new("Truncated entry")
                    .span(file.tail(pos))
                    .diag(Diagnostic::truncated(
                        file.sub(pos, HEADER),
                        file.len.saturating_sub(pos),
                    )),
            )
            .await;
            break;
        };
        let len = u64::from(len);
        let keyed = tag == PUT || tag == DELETE;
        let fixed = if keyed { KEYED_HEADER } else { HEADER };
        let span = file.sub(pos, len);
        let tag_name = crate::value::lookup(TAGS, tag.into())
            .map_or_else(|| format!("Tag {tag}"), str::to_owned);
        if len < fixed {
            cx.push(
                Node::new(format!("Entry {index}"))
                    .span(file.sub(pos, HEADER))
                    .diag(
                        Diagnostic::malformed(format!("{tag_name} entry of {len} bytes"))
                            .at(file.sub(pos, HEADER)),
                    ),
            )
            .await;
            break;
        }
        let mut node = Node::new(format!("{tag_name} {index}")).span(span);
        if keyed {
            let id = head.get(9..41).unwrap_or_default();
            let short = hex_string(id.get(..8).unwrap_or_default());
            node = node.renamed(format!("{tag_name} {short}…"));
            if tag == PUT {
                let data = head.get(41..).unwrap_or_default();
                let manifest = id.iter().all(|&b| b == 0);
                node = node.summary(format!(
                    "{}{}, {}",
                    if manifest { "manifest, " } else { "" },
                    size(len.saturating_sub(KEYED_HEADER)),
                    describe(data)
                ));
            }
        } else if tag != COMMIT {
            node = node.diag(Diagnostic::warning(format!("unknown tag {tag}")));
        }
        if len > MAX_OBJECT {
            node = node.diag(Diagnostic::warning(format!(
                "entry larger than Borg's maximum object size ({})",
                size(MAX_OBJECT)
            )));
        }
        if let Some(slot) = counts.get_mut(usize::from(tag)) {
            *slot = slot.saturating_add(1);
        }
        let short = span.len < len;
        if short {
            node = node.diag(Diagnostic::truncated(file.sub(pos, len), span.len));
        }
        cx.push(node.lazy(entry, (input, span, tag, crc, len)))
            .await;
        if short {
            break;
        }
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
    }
    let [puts, deletes, commits] = counts;
    cx.annotate(format!(
        "{} segment, {}: {puts} PUT, {deletes} DELETE, {commits} COMMIT",
        if attic { "Attic" } else { "Borg" },
        plural(index, "entry")
    ));
    Ok(())
}

async fn entry(cx: Cx, (input, span, tag, crc, len): (Input, Span, u8, u32, u64)) -> Result<()> {
    // The CRC covers the size, the tag, the ID and the data.
    let body = span.tail(4);
    let mut computed = u32::MAX;
    let mut off = 0u64;
    while off < body.len {
        let piece = cx.read(body.sub(off, 1 << 16)).await?;
        if piece.is_empty() {
            break;
        }
        computed = crc32_update(computed, &piece);
        off = off.saturating_add(crate::bytes::to_u64(piece.len()));
        cx.checkpoint().await;
    }
    let computed = !computed;
    cx.emit(
        Node::new("CRC32")
            .span(span.sub(0, 4))
            .checksum(Check::new("CRC-32", crc).verify(computed)),
    );
    cx.emit(
        Node::new("Size")
            .span(span.sub(4, 4))
            .value(uint(len, 32))
            .desc("Size of the whole entry, header included"),
    );
    cx.emit(
        Node::new("Tag")
            .span(span.sub(8, 1))
            .value(enumv(tag, 8, TAGS)),
    );
    if tag != PUT && tag != DELETE {
        return Ok(());
    }
    let id_span = span.sub(9, 32);
    let id = cx.read(id_span).await?;
    let manifest = id.iter().all(|&b| b == 0);
    // The ID's algorithm follows the key type, the object's first byte.
    let key_type = if tag == PUT {
        cx.read(span.sub(KEYED_HEADER, 1)).await?.first().copied()
    } else {
        None
    };
    let mut id_node = Node::new("Object ID")
        .span(id_span)
        .desc("MAC (HMAC-SHA256 or BLAKE2b) of the plaintext chunk, keyed by the repository's ID key; SHA-256 when unencrypted");
    id_node = if manifest {
        id_node.value(text(hex_string(&id))).summary("manifest")
    } else {
        id_node.checksum(id_check(key_type, id))
    };
    cx.emit(id_node);
    if tag == PUT {
        object(&cx, input, span.tail(KEYED_HEADER), manifest).await?;
    }
    Ok(())
}

/// The nodes of a `PUT`'s data.
async fn object(cx: &Cx, input: Input, data: Span, manifest: bool) -> Result<()> {
    let head = cx.read(data.sub(0, 16)).await?;
    let Some(&key_type) = head.first() else {
        cx.emit(
            Node::new("Data")
                .span(data)
                .diag(Diagnostic::malformed("empty object")),
        );
        return Ok(());
    };
    cx.emit(
        Node::new("Key type")
            .span(data.sub(0, 1))
            .value(enumv(key_type, 8, KEY_TYPES)),
    );
    let rest = data.tail(1);
    if !plaintext(key_type) {
        if crate::value::lookup(KEY_TYPES, key_type.into()).is_none() {
            cx.emit(
                Node::new("Data")
                    .span(rest)
                    .diag(Diagnostic::unsupported(format!("key type {key_type:#04x}"))),
            );
            return Ok(());
        }
        let mac = cx.read(rest.sub(0, 32)).await?;
        cx.emit(
            Node::new("MAC")
                .span(rest.sub(0, 32))
                .checksum(Check::new(mac_name(key_type), mac).skipped(NEEDS_KEY))
                .desc(
                    "HMAC-SHA256 or BLAKE2b of the nonce and ciphertext, keyed by the repository's MAC key",
                ),
        );
        let nonce = rest.sub(32, 8);
        let n = cx.read(nonce).await?;
        cx.emit(
            Node::new("Nonce")
                .span(nonce)
                .value(hex(crate::formats::util::datakit::be_uint(&n), 64))
                .desc("Low 64 bits of the AES-CTR counter (big-endian)"),
        );
        cx.emit(
            Node::new("Ciphertext")
                .span(rest.tail(40))
                .summary(size(rest.len.saturating_sub(40)))
                .diag(Diagnostic::unsupported(
                    "encrypted with the repository's key (kept in its config or a key file, not in segments)",
                )),
        );
        return Ok(());
    }
    compressed(cx, input, rest, manifest, true).await
}

/// A compressed chunk: compressor header, content (and for `obfuscate`,
/// the wrapped chunk and its padding).
async fn compressed(cx: &Cx, input: Input, chunk: Span, manifest: bool, outer: bool) -> Result<()> {
    let head = cx.read(chunk.sub(0, 8)).await?;
    let Some((comp, header)) = Compressor::detect(&head) else {
        cx.emit(
            Node::new("Chunk")
                .span(chunk)
                .diag(Diagnostic::unsupported("unknown compressor ID")),
        );
        return Ok(());
    };
    let mut id = Node::new("Compressor")
        .span(chunk.sub(0, header.max(2)))
        .value(Value::Text(comp.name().to_owned()));
    if comp == Compressor::Zlib {
        id = id.desc("zlib has no ID; this is the zlib stream's own header");
    }
    cx.emit(id);
    if comp == Compressor::Obfuscate {
        let len_span = chunk.sub(2, 4);
        let Some(inner_len) = u32_be(&head, 2) else {
            return Err(Diagnostic::truncated(len_span, chunk.len.saturating_sub(2)));
        };
        cx.emit(
            Node::new("Compressed size")
                .span(len_span)
                .value(uint(inner_len, 32))
                .desc("Size of the wrapped compressed chunk; random padding follows it"),
        );
        let inner = chunk.sub(6, inner_len.into());
        if inner.len < u64::from(inner_len) {
            cx.diag(Diagnostic::truncated(inner, chunk.len.saturating_sub(6)));
        }
        if !outer {
            cx.emit(
                Node::new("Wrapped chunk")
                    .span(inner)
                    .diag(Diagnostic::malformed("nested obfuscation")),
            );
        } else {
            cx.emit(Node::new("Wrapped chunk").span(inner).lazy(
                crate::expander!(self::wrapped: (Input, Span, bool)),
                (input, inner, manifest),
            ));
        }
        let padding = chunk.tail(6u64.saturating_add(inner_len.into()));
        if !padding.is_empty() {
            cx.emit(
                Node::new("Padding")
                    .span(padding)
                    .summary(size(padding.len)),
            );
        }
        return Ok(());
    }
    let body = chunk.tail(header);
    cx.emit(
        Node::new("Content")
            .span(body)
            .summary(format!("{}, {}", size(body.len), comp.name()))
            .lazy(chunk_content, (input, body, comp.codec(), manifest)),
    );
    Ok(())
}

async fn wrapped(cx: Cx, (input, inner, manifest): (Input, Span, bool)) -> Result<()> {
    compressed(&cx, input, inner, manifest, false).await
}

/// Whether decoded content starts like Borg's MessagePack metadata: a map
/// whose first key is a short string.
fn looks_msgpack(b: &[u8]) -> bool {
    matches!(
        b,
        [0x81..=0x8f, 0xa1..=0xbf, ..] | [0xde, _, _, 0xa1..=0xbf, ..]
    )
}

/// Decodes a chunk and dissects what it holds.
async fn chunk_content(
    cx: Cx,
    (input, span, codec, manifest): (Input, Span, Codec, bool),
) -> Result<()> {
    let inner = match codec {
        Codec::Stored => input.nested(span),
        // Borg's chunks are at most a few MiB; anything bigger than this
        // is decoded on demand and identified as usual.
        _ if span.len > (1 << 20) => {
            return expand_content(cx, (input, span, codec, None)).await;
        }
        _ => {
            let decoded = crate::codec::decode_span(&cx, span, &codec, None).await?;
            cx.annotate(format!("{:#x} bytes {}", decoded.span.len, codec.verb()));
            if let Some(e) = decoded.error {
                cx.diag(e);
            }
            input.nested(decoded.span)
        }
    };
    let head = cx.read(inner.span.sub(0, HEAD_LEN)).await?;
    let tail = cx
        .read(
            inner
                .span
                .tail(inner.span.len.saturating_sub(crate::formats::TAIL_LEN)),
        )
        .await?;
    let (format, units) = cx.registry().identify_costed(&Head {
        data: &head,
        tail: &tail,
        len: inner.span.len,
        len_known: true,
    });
    cx.charge(units).await;
    if format.is_none() && (manifest || looks_msgpack(&head)) {
        return dissect_named(cx, (inner, "borg-msgpack")).await;
    }
    dissect_or_data(cx, inner).await
}
