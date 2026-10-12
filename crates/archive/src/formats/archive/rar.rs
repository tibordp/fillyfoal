//! RAR archives, versions 1.5–4.x and 5.0.
//!
//! Both are a signature followed by blocks, each a header (with a CRC) and
//! an optional data area: RAR 4 headers are fixed little-endian fields, RAR 5
//! headers are built from variable-length integers and carry "extra area"
//! records. Blocks are listed in pages; expanding one decodes its header and
//! shows its data. File contents are embedded children: stored ones in
//! place, compressed ones (RAR 2.9 LZ/PPMd and RAR 5.0, see
//! [`crate::codec::rar`]) decoded on demand, with their CRC32 checked.
//!
//! In a solid archive the files of a run share one dictionary: the run is
//! decoded as one stream over its files' packed data (a pieces source), and
//! each file is a span of the output. Multi-volume members and RAR 4
//! encryption remain unsupported leaves; RAR 5 BLAKE2sp hashes are shown
//! but not checked.
//!
//! RAR 5 encryption is decrypted with the archive's password: file data
//! (AES-256-CBC with each file's IV) and encrypted headers (`-hp`: each
//! header after the archive encryption header is an IV and the header
//! encrypted, padded to whole blocks). The record layouts are those of
//! RARLAB's RAR 5.0 technote; the key is PBKDF2-HMAC-SHA256 of the
//! password (UTF-8) with the record's salt and 2^KDF-count iterations, and
//! the same PBKDF2 chain run 16 and 32 iterations further gives the key of
//! the tweaked checksums and the value folded into the 8-byte password
//! check (the technote's "additional PBKDF2 rounds"). This was written
//! without unRAR's source, checked against RAR 6.23's own archives (the
//! password check, the decrypted data and the tweaked CRC32s all match).
//!
//! Members compressed by RAR 1.5–2.x (compression versions 15, 20 and 26)
//! and RAR 7.0 streams (algorithm version 1, used only for dictionaries over
//! 4 GB) are listed with their headers but not decompressed. The decoders
//! follow libarchive, which reads neither; the other implementations
//! (unRAR, 7-Zip's RAR code) are under licences that aren't GPL-compatible,
//! so a decoder for these needs a clean, GPL-compatible source.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::codec::crc32;
use crate::codec::rar::{Algorithm, Member, Params};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::{ByteReader, emit_nodes, unsupported};
use crate::formats::util::fmt;
use crate::formats::util::fmt::capitalize;
use crate::formats::util::fmt::count;
use crate::formats::util::val::{hex, text};
use crate::formats::{Codec, Format, Input, Probe, dissect_or_data};
use crate::node::Node;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Value, field, flag};

const LE: Endian = Endian::Little;
const SIG5: &[u8] = b"Rar!\x1a\x07\x01\x00";
/// RAR 5 limits headers to 2 MiB.
const MAX_HEADER5: u64 = 2 << 20;

pub static FORMAT: Format = Format {
    name: "rar",
    title: "RAR archive",
    extensions: &["rar", "cbr"],
    mime: "application/vnd.rar",
    probe: Probe::Magic(&[(0, b"Rar!\x1a\x07\x00"), (0, b"Rar!\x1a\x07\x01\x00")]),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let sig = cx.read_avail(input.span.sub(0, 8)).await?;
    if sig.starts_with(SIG5) {
        dissect5(&cx, input).await
    } else {
        dissect4(&cx, input).await
    }
}

// ---------------------------------------------------------------------------
// RAR 1.5–4.x

const BLOCK4: EnumTable = &[
    (0x72, "marker block"),
    (0x73, "archive header"),
    (0x74, "file header"),
    (0x75, "old comment"),
    (0x76, "old authenticity"),
    (0x77, "old subblock"),
    (0x78, "old recovery record"),
    (0x79, "old authenticity 2"),
    (0x7a, "subblock"),
    (0x7b, "end of archive"),
];

const ARCHIVE_FLAGS4: FlagTable = &[
    flag(0x0001, "VOLUME"),
    flag(0x0002, "COMMENT"),
    flag(0x0004, "LOCK"),
    flag(0x0008, "SOLID"),
    flag(0x0010, "NEW_NUMBERING"),
    flag(0x0020, "AUTHENTICITY"),
    flag(0x0040, "RECOVERY"),
    flag(0x0080, "ENCRYPTED_HEADERS"),
    flag(0x0100, "FIRST_VOLUME"),
    flag(0x8000, "LONG_BLOCK"),
];

const FILE_FLAGS4: FlagTable = &[
    flag(0x0001, "SPLIT_BEFORE"),
    flag(0x0002, "SPLIT_AFTER"),
    flag(0x0004, "PASSWORD"),
    flag(0x0008, "COMMENT"),
    flag(0x0010, "SOLID"),
    field(0x00e0, 0x0000, "DICT_64K"),
    field(0x00e0, 0x0020, "DICT_128K"),
    field(0x00e0, 0x0040, "DICT_256K"),
    field(0x00e0, 0x0060, "DICT_512K"),
    field(0x00e0, 0x0080, "DICT_1M"),
    field(0x00e0, 0x00a0, "DICT_2M"),
    field(0x00e0, 0x00c0, "DICT_4M"),
    field(0x00e0, 0x00e0, "DIRECTORY"),
    flag(0x0100, "LARGE"),
    flag(0x0200, "UNICODE"),
    flag(0x0400, "SALT"),
    flag(0x0800, "VERSION"),
    flag(0x1000, "EXT_TIME"),
    flag(0x8000, "LONG_BLOCK"),
];

const HOST_OS4: EnumTable = &[
    (0, "MS-DOS"),
    (1, "OS/2"),
    (2, "Windows"),
    (3, "Unix"),
    (4, "Mac OS"),
    (5, "BeOS"),
];

const METHOD4: EnumTable = &[
    (0x30, "store"),
    (0x31, "fastest"),
    (0x32, "fast"),
    (0x33, "normal"),
    (0x34, "good"),
    (0x35, "best"),
];

/// What the listing needs from a RAR 4 block.
struct Block4 {
    span: Span,
    kind: u8,
    flags: u16,
    name: Option<String>,
    unpacked: u64,
    crc_ok: bool,
    part: Option<Part>,
}

/// A file's packed data and how it decodes.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Part {
    /// Offset of the file's block in the archive (identifies the file).
    block: u64,
    data: Span,
    unpacked: u64,
    crc: Option<u32>,
    how: How,
    /// Continues the dictionary of the file before (solid archives).
    solid: bool,
    dict: u64,
    rar5: bool,
    /// RAR 5 file encryption: the data is AES-256-CBC ciphertext.
    crypt: Option<Crypt5>,
}

/// A RAR 5 file encryption record (RARLAB's RAR 5.0 technote, "File
/// encryption record"): AES-256 in CBC mode with this file's IV, the key
/// derived from the password by PBKDF2-HMAC-SHA256 with this salt and
/// 2^`kdf` iterations.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Crypt5 {
    kdf: u8,
    salt: [u8; 16],
    iv: [u8; 16],
    /// The password check value (8 bytes, then a 4-byte SHA-256 checksum
    /// of them), if recorded.
    check: Option<[u8; 12]>,
    /// The file's checksums are "tweaked" (MACs keyed by the password)
    /// rather than plain.
    tweaked: bool,
}

/// What a file header's extra area says about encryption.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Encryption {
    None,
    Aes(Crypt5),
    /// An encryption record we cannot use (unknown version, damaged).
    Unsupported,
}

/// The largest KDF count (binary logarithm of the PBKDF2 iterations) we
/// accept; the technote lets readers refuse large ones, and RAR itself
/// writes 15.
const MAX_KDF5: u8 = 24;

/// Parses a file encryption record's body (after its type).
fn crypt5(body: &[u8]) -> Option<Crypt5> {
    let (version, l1) = crate::bytes::uleb128(body)?;
    let rest = body.get(l1..)?;
    let (flags, l2) = crate::bytes::uleb128(rest)?;
    let rest = rest.get(l2..)?;
    if version != 0 {
        return None;
    }
    let kdf = *rest.first()?;
    let salt: [u8; 16] = rest.get(1..17)?.try_into().ok()?;
    let iv: [u8; 16] = rest.get(17..33)?.try_into().ok()?;
    let check = if flags & 0x01 != 0 {
        Some(rest.get(33..45)?.try_into().ok()?)
    } else {
        None
    };
    Some(Crypt5 {
        kdf,
        salt,
        iv,
        check,
        tweaked: flags & 0x02 != 0,
    })
}

/// The encryption of a file header with extra area `data`.
fn encryption5(data: &[u8]) -> Encryption {
    let mut at = 0usize;
    while at < data.len() {
        let Some((size, l1)) = crate::bytes::uleb128(data.get(at..).unwrap_or_default()) else {
            break;
        };
        let body_at = at.saturating_add(l1);
        let end = body_at.saturating_add(to_usize(size));
        let Some(body) = data.get(body_at..end) else {
            break;
        };
        if let Some((1, l2)) = crate::bytes::uleb128(body) {
            return match crypt5(body.get(l2..).unwrap_or_default()) {
                Some(c) if c.kdf <= MAX_KDF5 => Encryption::Aes(c),
                _ => Encryption::Unsupported,
            };
        }
        if size == 0 {
            break;
        }
        at = end;
    }
    Encryption::None
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum How {
    Stored,
    Lz(Algorithm),
    Unsupported(&'static str),
}

impl How {
    fn name(self) -> &'static str {
        match self {
            How::Stored => "stored",
            How::Lz(Algorithm::V29) => "RAR 2.9",
            How::Lz(Algorithm::V50) => "RAR 5.0",
            How::Lz(Algorithm::V70) => "RAR 7.0",
            How::Unsupported(n) => n,
        }
    }
}

/// The part of a RAR 4 file block (`None` for directories and for data that
/// cannot be shown: encrypted, split across volumes). `block` is the whole
/// block, `packed` its data size.
fn part4(header: &[u8], block: Span, flags: u16, packed: u64, unpacked: u64) -> Option<Part> {
    if flags & 0xe0 == 0xe0 || flags & 0x07 != 0 {
        return None;
    }
    let size = u16_le(header, 5)?;
    let ver = *header.get(24)?;
    let method = *header.get(25)?;
    let how = match (method, ver) {
        (0x30, _) => How::Stored,
        (_, 29) => How::Lz(Algorithm::V29),
        (_, 20 | 26) => How::Unsupported("RAR 2.0"),
        (_, 15) => How::Unsupported("RAR 1.5"),
        _ => How::Unsupported("unknown RAR version"),
    };
    Some(Part {
        block: block.offset,
        data: block.sub(size.into(), packed),
        unpacked,
        crc: u32_le(header, 16),
        how,
        solid: flags & 0x10 != 0,
        dict: 0x1_0000u64 << ((flags >> 5) & 7),
        rar5: false,
        crypt: None,
    })
}

async fn next_block4(cx: &Cx, cur: &mut Cursor<'_>) -> Result<Block4> {
    let start = cur.pos();
    let base = cur.peek(7).await?;
    let (Some(kind), Some(flags), Some(size)) =
        (base.get(2).copied(), u16_le(&base, 3), u16_le(&base, 5))
    else {
        return Err(Diagnostic::truncated(cur.span(7), to_u64(base.len())));
    };
    if size < 7 {
        return Err(Diagnostic::malformed("block header shorter than 7 bytes").at(cur.span(7)));
    }
    let header = cx.read_avail(cur.span(size.into())).await?;
    let long = flags & 0x8000 != 0 || kind == 0x74 || kind == 0x7a;
    let mut add = if long {
        u64::from(u32_le(&header, 7).unwrap_or(0))
    } else {
        0
    };
    let mut name = None;
    let mut unpacked = 0;
    let mut part = None;
    if kind == 0x74 || kind == 0x7a {
        unpacked = u64::from(u32_le(&header, 11).unwrap_or(0));
        let mut name_at = 32usize;
        if flags & 0x100 != 0 {
            let high_pack = u64::from(u32_le(&header, 32).unwrap_or(0));
            let high_unp = u64::from(u32_le(&header, 36).unwrap_or(0));
            add |= high_pack << 32;
            unpacked |= high_unp << 32;
            name_at = 40;
        }
        let len = usize::from(u16_le(&header, 26).unwrap_or(0));
        let bytes = header
            .get(name_at..name_at.saturating_add(len))
            .unwrap_or_default();
        name = Some(name4(bytes, flags));
        if kind == 0x74 {
            let block = cur.span(u64::from(size).saturating_add(add));
            part = part4(&header, block, flags, add, unpacked);
        }
    }
    let crc_ok = header
        .get(2..)
        .zip(u16_le(&header, 0))
        .is_some_and(|(covered, stored)| (crc32(covered) & 0xffff) as u16 == stored);
    cur.skip(u64::from(size).saturating_add(add));
    Ok(Block4 {
        span: cur.since(start),
        kind,
        flags,
        name,
        unpacked,
        crc_ok,
        part,
    })
}

async fn dissect4(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 7))
            .value(text("Rar!"))
            .summary("RAR 1.5–4.x"),
    );
    cx.annotate("RAR archive (v4)");
    let mut cur = Cursor::new(cx, file, LE);
    cur.seek(7);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut solid = false;
    let mut encrypted = false;
    while cur.remaining() >= 7 {
        let b = next_block4(cx, &mut cur).await?;
        let kind_name = crate::value::lookup(BLOCK4, b.kind.into()).unwrap_or("unknown block");
        let (name, summary) = match (b.kind, &b.name) {
            (0x74, Some(n)) => {
                files = files.saturating_add(1);
                total = total.saturating_add(b.unpacked);
                let s = if b.flags & 0xe0 == 0xe0 {
                    "directory".to_owned()
                } else {
                    fmt::size(b.unpacked)
                };
                (n.clone(), s)
            }
            (0x7a, Some(n)) => (format!("Subblock {n}"), fmt::size(b.span.len)),
            (0x73, _) => {
                solid = b.flags & 0x0008 != 0;
                encrypted = b.flags & 0x0080 != 0;
                ("Archive header".to_owned(), String::new())
            }
            (0x7b, _) => ("End of archive".to_owned(), String::new()),
            _ => (capitalize(kind_name), String::new()),
        };
        let mut node = Node::new(name).span(b.span).lazy(block4, (input, b.span));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !b.crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(node).await;
        if b.kind == 0x7b || encrypted {
            break;
        }
    }
    if encrypted {
        cx.diag(Diagnostic::unsupported("encrypted headers"));
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    let solid = if solid { "solid, " } else { "" };
    cx.annotate(format!(
        "RAR archive (v4), {solid}{}, {} uncompressed",
        count(files, "file", "files"),
        fmt::size(total)
    ));
    Ok(())
}

async fn block4(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let base = cx.read(span.sub(0, 7)).await?;
    let size = u16_le(&base, 5).unwrap_or(7);
    let header_span = span.sub(0, size.into());
    let header = cx.read(header_span).await?;
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::malformed("truncated block header").at(header_span);
    let stored_crc = r.u16("Header CRC", LE).ok_or_else(bad)?;
    let computed = (crc32(header.get(2..).unwrap_or_default()) & 0xffff) as u16;
    r.with(|n| {
        let n = n.value(hex(stored_crc, 64));
        if computed == stored_crc {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#06x}"
            )))
        }
    });
    let kind = r.u8("Header type").ok_or_else(bad)?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind.into(),
            bits: 8,
            name: crate::value::lookup(BLOCK4, kind.into()),
        })
    });
    let flags = r.u16("Flags", LE).ok_or_else(bad)?;
    let table = match kind {
        0x73 => Some(ARCHIVE_FLAGS4),
        0x74 | 0x7a => Some(FILE_FLAGS4),
        _ => None,
    };
    r.with(|n| match table {
        Some(t) => {
            let (set, unknown) = crate::value::decode_flags(t, flags.into());
            n.value(Value::Flags {
                raw: flags.into(),
                bits: 16,
                set,
                unknown,
            })
        }
        None => n.value(hex(flags, 64)),
    });
    r.u16("Header size", LE).ok_or_else(bad)?;
    let mut data = None;
    match kind {
        0x73 => {
            r.u16("Reserved 1", LE);
            r.u32("Reserved 2", LE);
        }
        0x74 | 0x7a => {
            let pack = r.u32("Packed size", LE).ok_or_else(bad)?;
            r.with(|n| n.summary(fmt::size(pack.into())));
            let unp = r.u32("Unpacked size", LE).ok_or_else(bad)?;
            r.with(|n| n.summary(fmt::size(unp.into())));
            let os = r.u8("Host OS").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: os.into(),
                    bits: 8,
                    name: crate::value::lookup(HOST_OS4, os.into()),
                })
            });
            let crc = r.u32("File CRC", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(crc, 64)));
            let time = r.u32("Modification time (DOS)", LE).ok_or_else(bad)?;
            r.with(|n| {
                let date = u16::try_from(time >> 16).unwrap_or(0);
                let t = u16::try_from(time & 0xffff).unwrap_or(0);
                n.value(hex(time, 64))
                    .summary(crate::text::dos_datetime(date, t))
            });
            let ver = r.u8("Version needed").ok_or_else(bad)?;
            r.with(|n| n.summary(format!("{}.{}", ver / 10, ver % 10)));
            let method = r.u8("Method").ok_or_else(bad)?;
            r.with(|n| {
                n.value(Value::Enum {
                    raw: method.into(),
                    bits: 8,
                    name: crate::value::lookup(METHOD4, method.into()),
                })
            });
            let name_len = r.u16("Name size", LE).ok_or_else(bad)?;
            let attr = r.u32("Attributes", LE).ok_or_else(bad)?;
            r.with(|n| n.value(hex(attr, 64)));
            let mut packed = u64::from(pack);
            let mut unpacked = u64::from(unp);
            if flags & 0x100 != 0 {
                let hp = r.u32("High packed size", LE).ok_or_else(bad)?;
                let hu = r.u32("High unpacked size", LE).ok_or_else(bad)?;
                packed |= u64::from(hp) << 32;
                unpacked |= u64::from(hu) << 32;
            }
            let part = if kind == 0x74 {
                part4(&header, span, flags, packed, unpacked)
            } else {
                None
            };
            let raw = r.bytes("Name", name_len.into()).ok_or_else(bad)?;
            let name = name4(raw, flags);
            r.with(|n| n.value(text(name.clone())));
            if flags & 0x400 != 0 {
                r.bytes("Salt", 8);
            }
            let data_span = span.sub(size.into(), packed);
            let directory = flags & 0xe0 == 0xe0 && kind == 0x74;
            data = Some(if directory || packed == 0 {
                None
            } else if kind == 0x7a {
                Some(Node::new("Data").span(data_span))
            } else if flags & 0x04 != 0 {
                Some(
                    Node::new("Encrypted data")
                        .span(data_span)
                        .diag(Diagnostic::unsupported("encrypted file")),
                )
            } else if flags & 0x03 != 0 {
                Some(
                    Node::new("Data (split across volumes)")
                        .span(data_span)
                        .diag(Diagnostic::unsupported("multi-volume member")),
                )
            } else if let Some(p) = part.filter(|p| !matches!(p.how, How::Unsupported(_))) {
                Some(content_node("Content", input, p))
            } else {
                let name = crate::value::lookup(METHOD4, method.into()).unwrap_or("unknown");
                Some(unsupported(
                    "Compressed data",
                    data_span,
                    &format!("RAR {}.{} ({name})", ver / 10, ver % 10),
                ))
            });
        }
        _ => {
            if flags & 0x8000 != 0 {
                let add = r.u32("Data size", LE).ok_or_else(bad)?;
                data = Some(Some(
                    Node::new("Data").span(span.sub(size.into(), add.into())),
                ));
            }
        }
    }
    if r.remaining() > 0 {
        let start = r.at;
        r.skip(to_u64(r.remaining()));
        let rest = r.since(start);
        r.push(Node::new("Extended header data").span(rest));
    }
    let nodes = r.into_nodes();
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, nodes),
    );
    if let Some(Some(node)) = data {
        cx.emit(node);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// RAR 5.0

const HEADER5: EnumTable = &[
    (1, "main archive header"),
    (2, "file header"),
    (3, "service header"),
    (4, "encryption header"),
    (5, "end of archive"),
];

const COMMON_FLAGS5: FlagTable = &[
    flag(0x01, "EXTRA_AREA"),
    flag(0x02, "DATA_AREA"),
    flag(0x04, "SKIP_IF_UNKNOWN"),
    flag(0x08, "SPLIT_BEFORE"),
    flag(0x10, "SPLIT_AFTER"),
    flag(0x20, "DEPENDS_ON_PRECEDING"),
    flag(0x40, "PRESERVE_CHILD"),
];

const ARCHIVE_FLAGS5: FlagTable = &[
    flag(0x01, "VOLUME"),
    flag(0x02, "VOLUME_NUMBER"),
    flag(0x04, "SOLID"),
    flag(0x08, "RECOVERY"),
    flag(0x10, "LOCKED"),
];

const FILE_FLAGS5: FlagTable = &[
    flag(0x01, "DIRECTORY"),
    flag(0x02, "MTIME"),
    flag(0x04, "CRC32"),
    flag(0x08, "UNKNOWN_SIZE"),
];

const HOST_OS5: EnumTable = &[(0, "Windows"), (1, "Unix")];

const FILE_EXTRA5: EnumTable = &[
    (1, "encryption"),
    (2, "file hash"),
    (3, "file time"),
    (4, "file version"),
    (5, "redirection"),
    (6, "Unix owner"),
    (7, "service data"),
];

const MAIN_EXTRA5: EnumTable = &[(1, "locator"), (2, "metadata")];

/// What the listing needs from a RAR 5 block.
struct Block5 {
    span: Span,
    kind: u64,
    name: Option<String>,
    unpacked: u64,
    directory: bool,
    crc_ok: bool,
    /// For file headers (type 2) only.
    part: Option<Part>,
    /// The header's bytes (in the file, or decrypted).
    header: Span,
    /// Bytes of the file the header takes (with encrypted headers: the IV
    /// and the padded ciphertext).
    header_file_len: u64,
    /// For the archive encryption header (type 4): its parameters.
    crypt: Option<Crypt5>,
}

/// A RAR 5 header's bytes and where they are.
struct Raw5 {
    span: Span,
    bytes: Vec<u8>,
    /// Length of the header size field.
    vlen: usize,
    file_len: u64,
}

/// Reads the RAR 5 header at the cursor. With encrypted headers (`key`
/// from the archive encryption header), each is a 16-byte IV and the
/// header AES-256-CBC encrypted, zero-padded to whole blocks; it is
/// decrypted into a derived source, so its fields have spans of their own.
async fn raw_header5(cx: &Cx, cur: &Cursor<'_>, key: Option<&Keys5>) -> Result<Raw5> {
    let Some(key) = key else {
        let head = cur.peek(4 + 3).await?;
        let (size, vlen) = crate::bytes::uleb128(head.get(4..).unwrap_or_default())
            .ok_or_else(|| Diagnostic::malformed("bad header size").at(cur.span(7)))?;
        if size > MAX_HEADER5 || size == 0 {
            return Err(Diagnostic::malformed(format!("header size {size:#x}")).at(cur.span(7)));
        }
        let len = 4u64.saturating_add(to_u64(vlen)).saturating_add(size);
        let span = cur.span(len);
        let bytes = cx.read(span).await?;
        return Ok(Raw5 {
            span,
            bytes,
            vlen,
            file_len: len,
        });
    };
    let aes = crate::codec::crypto::Aes::new(&key.key)
        .ok_or_else(|| Diagnostic::internal("RAR 5 header key length"))?;
    let first = cx.read(cur.span(32)).await?;
    let (iv, block) = first.split_at(first.len().min(16));
    let head = crate::codec::crypto::cbc_decrypt(&aes, iv, block);
    let (size, vlen) =
        crate::bytes::uleb128(head.get(4..).unwrap_or_default()).ok_or_else(|| {
            Diagnostic::malformed("bad header size (wrong password?)").at(cur.span(32))
        })?;
    if size > MAX_HEADER5 || size == 0 {
        return Err(
            Diagnostic::malformed(format!("header size {size:#x} (wrong password?)"))
                .at(cur.span(32)),
        );
    }
    let len = 4u64.saturating_add(to_u64(vlen)).saturating_add(size);
    let file_len = (len.saturating_add(15) & !15).saturating_add(16);
    let enc_span = cur.span(file_len);
    let enc = cx.read(enc_span).await?;
    let mut bytes = crate::codec::crypto::cbc_decrypt(&aes, iv, enc.get(16..).unwrap_or_default());
    bytes.truncate(to_usize(len));
    let span = cx
        .add_derived(
            Origin {
                parent: enc_span,
                transform: "rar5 header",
            },
            bytes.clone(),
            file_len,
            None,
        )?
        .span;
    Ok(Raw5 {
        span,
        bytes,
        vlen,
        file_len,
    })
}

/// The parameters of an archive encryption header (type 4) body.
fn header_crypt5(r: &mut ByteReader<'_>) -> Option<Crypt5> {
    let version = r.vint("Encryption version")?;
    r.with(|n| n.summary(if version == 0 { "AES-256" } else { "unknown" }));
    let flags = r.vint("Encryption flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(CRYPT_FLAGS5, flags);
        n.value(Value::Flags {
            raw: flags,
            bits: 64,
            set,
            unknown,
        })
    });
    let kdf = r.u8("KDF count")?;
    r.with(|n| n.summary(format!("2^{kdf} PBKDF2 iterations")));
    let salt: [u8; 16] = r.bytes("Salt", 16)?.try_into().ok()?;
    let check = if flags & 0x01 != 0 {
        Some(r.bytes("Password check value", 12)?.try_into().ok()?)
    } else {
        None
    };
    (version == 0 && kdf <= MAX_KDF5).then_some(Crypt5 {
        kdf,
        salt,
        iv: [0; 16],
        check,
        tweaked: false,
    })
}

/// The fields of a RAR 5 file or service header after the common part.
struct FileFields {
    flags: u64,
    unpacked: u64,
    method: u64,
    name: String,
    crc: Option<u32>,
    info: u64,
}

/// The dictionary size of RAR 5 compression information: 128 KiB << n,
/// and for RAR 7.0 (version 1) a fraction of 1/32 steps on top.
fn dict5(info: u64) -> u64 {
    if info & 0x3f == 0 {
        0x2_0000u64 << ((info >> 10) & 0xf)
    } else {
        let base = 0x2_0000u64 << ((info >> 10) & 0x1f);
        base.saturating_add((base / 32).saturating_mul((info >> 15) & 0x1f))
    }
}

/// The part of a RAR 5 file header (`None` for directories and for data
/// that cannot be shown: encrypted in a way we cannot decrypt, split
/// across volumes).
fn part5(
    block: Span,
    header_len: u64,
    c: &Common,
    f: &FileFields,
    encryption: Encryption,
) -> Option<Part> {
    let crypt = match encryption {
        Encryption::None => None,
        Encryption::Aes(c) => Some(c),
        Encryption::Unsupported => return None,
    };
    if f.flags & 0x01 != 0 || c.flags & 0x18 != 0 || c.flags & 0x02 == 0 {
        return None;
    }
    let how = match (f.method, f.info & 0x3f) {
        (0, _) => How::Stored,
        (_, 0) => How::Lz(Algorithm::V50),
        (_, 1) => How::Lz(Algorithm::V70),
        _ => How::Unsupported("unknown RAR 5 algorithm version"),
    };
    Some(Part {
        block: block.offset,
        data: block.sub(header_len, c.data),
        unpacked: f.unpacked,
        crc: f.crc,
        how,
        solid: f.info & 0x40 != 0,
        dict: dict5(f.info),
        rar5: true,
        crypt,
    })
}

fn file_fields(r: &mut ByteReader<'_>) -> Option<FileFields> {
    let flags = r.vint("File flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(FILE_FLAGS5, flags);
        n.value(Value::Flags {
            raw: flags,
            bits: 64,
            set,
            unknown,
        })
    });
    let unpacked = r.vint("Unpacked size")?;
    r.with(|n| n.summary(fmt::size(unpacked)));
    let attr = r.vint("Attributes")?;
    r.with(|n| n.value(hex(attr, 64)));
    if flags & 0x02 != 0 {
        let t = r.u32("Modification time", LE)?;
        r.with(|n| {
            n.value(Value::Timestamp {
                unix_seconds: t.into(),
            })
        });
    }
    let mut crc = None;
    if flags & 0x04 != 0 {
        let c = r.u32("Data CRC32", LE)?;
        r.with(|n| n.value(hex(c, 64)));
        crc = Some(c);
    }
    let info = r.vint("Compression information")?;
    r.with(|n| {
        n.value(hex(info, 64)).summary(format!(
            "version {}, method {}{}, dictionary {}",
            info & 0x3f,
            (info >> 7) & 7,
            if info & 0x40 != 0 { ", solid" } else { "" },
            fmt::size(dict5(info))
        ))
    });
    let os = r.vint("Host OS")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: os,
            bits: 64,
            name: crate::value::lookup(HOST_OS5, os),
        })
    });
    let len = r.vint("Name length")?;
    let name = r.text("Name", len)?;
    Some(FileFields {
        flags,
        unpacked,
        method: (info >> 7) & 7,
        name,
        crc,
        info,
    })
}

/// The common part of a RAR 5 header: type, flags, extra and data sizes.
struct Common {
    kind: u64,
    flags: u64,
    extra: u64,
    data: u64,
}

fn common5(r: &mut ByteReader<'_>) -> Option<Common> {
    let kind = r.vint("Header type")?;
    r.with(|n| {
        n.value(Value::Enum {
            raw: kind,
            bits: 64,
            name: crate::value::lookup(HEADER5, kind),
        })
    });
    let flags = r.vint("Header flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(COMMON_FLAGS5, flags);
        n.value(Value::Flags {
            raw: flags,
            bits: 64,
            set,
            unknown,
        })
    });
    let extra = if flags & 0x01 != 0 {
        r.vint("Extra area size")?
    } else {
        0
    };
    let data = if flags & 0x02 != 0 {
        let d = r.vint("Data size")?;
        r.with(|n| n.summary(fmt::size(d)));
        d
    } else {
        0
    };
    Some(Common {
        kind,
        flags,
        extra,
        data,
    })
}

async fn next_block5(cx: &Cx, cur: &mut Cursor<'_>, key: Option<&Keys5>) -> Result<Block5> {
    let start = cur.pos();
    let Raw5 {
        span: header_span,
        bytes: header,
        vlen,
        file_len,
    } = raw_header5(cx, cur, key).await?;
    let header_len = to_u64(header.len());
    let crc_ok = header
        .get(4..)
        .zip(u32_le(&header, 0))
        .is_some_and(|(covered, stored)| crc32(covered) == stored);
    let mut r = ByteReader::new(&header, header_span);
    r.at = 4usize.saturating_add(vlen);
    let c = common5(&mut r).ok_or_else(|| Diagnostic::malformed("bad header").at(header_span))?;
    let mut name = None;
    let mut unpacked = 0;
    let mut directory = false;
    let mut part = None;
    let mut crypt = None;
    if c.kind == 4 {
        crypt = header_crypt5(&mut r);
    }
    if (c.kind == 2 || c.kind == 3)
        && let Some(f) = file_fields(&mut r)
    {
        let extra = header
            .get(to_usize(header_len.saturating_sub(c.extra))..)
            .unwrap_or_default();
        let encryption = if c.extra > 0 {
            encryption5(extra)
        } else {
            Encryption::None
        };
        let block = cur.span(file_len.saturating_add(c.data));
        part = part5(block, file_len, &c, &f, encryption);
        name = Some(f.name);
        unpacked = f.unpacked;
        directory = f.flags & 1 != 0;
    }
    cur.skip(file_len.saturating_add(c.data));
    Ok(Block5 {
        span: cur.since(start),
        kind: c.kind,
        name,
        unpacked,
        directory,
        crc_ok,
        part,
        header: header_span,
        header_file_len: file_len,
        crypt,
    })
}

async fn dissect5(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 8))
            .value(text("Rar!"))
            .summary("RAR 5.0"),
    );
    cx.annotate("RAR archive (v5)");
    list5(cx, input, 8, None).await
}

/// Lists the RAR 5 blocks from `pos`, their headers decrypted with `key`
/// if the archive's headers are encrypted.
async fn list5(cx: &Cx, input: Input, pos: u64, key: Option<Arc<Keys5>>) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(cx, file, LE);
    cur.seek(pos);
    let mut files = 0u64;
    let mut total = 0u64;
    let mut solid = false;
    while cur.remaining() >= 6 {
        let b = next_block5(cx, &mut cur, key.as_deref()).await?;
        solid |= b.part.is_some_and(|p| p.solid);
        let (name, summary) = match (b.kind, b.name) {
            (2, Some(n)) => {
                files = files.saturating_add(1);
                total = total.saturating_add(b.unpacked);
                let s = if b.directory {
                    "directory".to_owned()
                } else {
                    fmt::size(b.unpacked)
                };
                (n, s)
            }
            (3, Some(n)) => (format!("Service {n}"), fmt::size(b.unpacked)),
            (k, _) => (
                capitalize(crate::value::lookup(HEADER5, k).unwrap_or("unknown header")),
                String::new(),
            ),
        };
        let mut node = Node::new(name)
            .span(b.span)
            .lazy(block5, (input, b.span, b.header, b.header_file_len));
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        if !b.crc_ok {
            node = node.diag(Diagnostic::warning("header CRC mismatch"));
        }
        cx.progress_in(file, file.offset.saturating_add(cur.pos()));
        cx.push(node).await;
        if b.kind == 4 && key.is_none() {
            // Everything after is encrypted: listed when expanded, with
            // the password.
            let rest = file.tail(cur.pos());
            let node = Node::new("Encrypted headers").span(rest);
            cx.emit(match b.crypt {
                Some(c) => node.lazy(
                    crate::expander!(self::encrypted5: (Input, u64, Crypt5)),
                    (input, cur.pos(), c),
                ),
                None => node.diag(Diagnostic::unsupported("encryption version")),
            });
            cx.annotate("RAR archive (v5), encrypted headers");
            return Ok(());
        }
        if b.kind == 5 {
            break;
        }
    }
    if !cur.at_end() {
        cx.emit(Node::new("Trailing data").span(file.tail(cur.pos())));
    }
    if key.is_none() {
        cx.annotate(format!(
            "RAR archive (v5), {}{}, {} uncompressed",
            if solid { "solid, " } else { "" },
            count(files, "file", "files"),
            fmt::size(total)
        ));
    }
    Ok(())
}

/// Expander: the blocks after an archive encryption header, once the
/// password is known.
async fn encrypted5(cx: Cx, (input, pos, c): (Input, u64, Crypt5)) -> Result<()> {
    match rar5_keys(&cx, input.span, &c).await {
        Some(keys) => list5(&cx, input, pos, Some(keys)).await,
        None => Err(Diagnostic::unsupported(
            "encrypted archive headers (no password, or a wrong one)",
        )),
    }
}

async fn block5(
    cx: Cx,
    (input, span, header_span, file_len): (Input, Span, Span, u64),
) -> Result<()> {
    let header = cx.read(header_span).await?;
    let header_len = to_u64(header.len());
    let mut r = ByteReader::new(&header, header_span);
    let bad = || Diagnostic::malformed("truncated header").at(header_span);
    let stored = r.u32("Header CRC32", LE).ok_or_else(bad)?;
    let computed = crc32(header.get(4..).unwrap_or_default());
    r.with(|n| {
        let n = n.value(hex(stored, 64));
        if computed == stored {
            n.summary("valid")
        } else {
            n.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#010x}"
            )))
        }
    });
    r.vint("Header size").ok_or_else(bad)?;
    let c = common5(&mut r).ok_or_else(bad)?;
    let mut fields = None;
    match c.kind {
        1 => {
            let flags = r.vint("Archive flags").ok_or_else(bad)?;
            r.with(|n| {
                let (set, unknown) = crate::value::decode_flags(ARCHIVE_FLAGS5, flags);
                n.value(Value::Flags {
                    raw: flags,
                    bits: 64,
                    set,
                    unknown,
                })
            });
            if flags & 0x02 != 0 {
                r.vint("Volume number").ok_or_else(bad)?;
            }
        }
        2 | 3 => fields = Some(file_fields(&mut r).ok_or_else(bad)?),
        4 => {
            header_crypt5(&mut r);
        }
        5 => {
            let f = r.vint("End of archive flags").ok_or_else(bad)?;
            r.with(|n| {
                n.summary(if f & 1 != 0 {
                    "not the last volume"
                } else {
                    "last volume"
                })
            });
        }
        _ => {}
    }
    let extra_at = to_usize(header_len.saturating_sub(c.extra));
    let mut encryption = Encryption::None;
    if c.extra > 0 && extra_at >= r.at {
        let extra = header.get(extra_at..).unwrap_or_default();
        let extra_span = header_span.sub(to_u64(extra_at), c.extra);
        let records = extra_records(extra, extra_span, c.kind == 1);
        if c.kind != 1 {
            encryption = encryption5(extra);
        }
        let nodes: Vec<Node> = records.into_iter().map(|(_, n)| n).collect();
        r.at = to_usize(header_len);
        r.push(
            Node::new("Extra area")
                .span(extra_span)
                .summary(count(to_u64(nodes.len()), "record", "records"))
                .lazy(emit_nodes, std::sync::Arc::new(nodes)),
        );
    }
    cx.emit(
        Node::new("Header")
            .span(header_span)
            .lazy(emit_nodes, r.into_nodes()),
    );
    if c.flags & 0x02 != 0 {
        let data = span.sub(file_len, c.data);
        let part = fields
            .as_ref()
            .and_then(|f| part5(span, file_len, &c, f, encryption))
            .map(|p| Part {
                // Service data (comments, ...) is never part of a solid run.
                solid: p.solid && c.kind == 2,
                ..p
            });
        let node = match &fields {
            _ if encryption == Encryption::Unsupported => Node::new("Encrypted data")
                .span(data)
                .diag(Diagnostic::unsupported("encryption version or record")),
            _ if c.flags & 0x18 != 0 => Node::new("Data (split across volumes)")
                .span(data)
                .diag(Diagnostic::unsupported("multi-volume member")),
            Some(_) => match part {
                Some(p) if !matches!(p.how, How::Unsupported(_)) => {
                    content_node(if c.kind == 3 { "Data" } else { "Content" }, input, p)
                }
                _ => unsupported(
                    "Compressed data",
                    data,
                    &format!(
                        "RAR 5 (version {})",
                        fields.as_ref().map_or(0, |f| f.info & 0x3f)
                    ),
                ),
            },
            None => Node::new("Data").span(data),
        };
        cx.emit(crate::formats::util::arcutil::check_len(node, data, c.data));
    }
    Ok(())
}

/// Extra area records: size, type, data. Returns (type, node) pairs.
fn extra_records(data: &[u8], span: Span, main: bool) -> Vec<(u64, Node)> {
    let mut out = Vec::new();
    let mut at = 0usize;
    while at < data.len() {
        let Some((size, l1)) = crate::bytes::uleb128(data.get(at..).unwrap_or_default()) else {
            break;
        };
        let body_at = at.saturating_add(l1);
        let end = body_at.saturating_add(to_usize(size));
        let Some(body) = data.get(body_at..end) else {
            break;
        };
        let record_span = span.sub(to_u64(at), to_u64(end.saturating_sub(at)));
        let mut r = ByteReader::new(body, span.sub(to_u64(body_at), size));
        let kind = r.vint("Type").unwrap_or(0);
        let table = if main { MAIN_EXTRA5 } else { FILE_EXTRA5 };
        r.with(|n| {
            n.value(Value::Enum {
                raw: kind,
                bits: 64,
                name: crate::value::lookup(table, kind),
            })
        });
        if !main && kind == 3 {
            time_record(&mut r);
        } else if !main && kind == 2 {
            r.vint("Hash type");
            r.bytes("BLAKE2sp hash", 32);
        } else if !main && kind == 1 {
            crypt_record(&mut r);
        } else if r.remaining() > 0 {
            r.bytes("Data", to_u64(r.remaining()));
        }
        let name = crate::value::lookup(table, kind)
            .map_or_else(|| format!("Record type {kind}"), capitalize);
        out.push((
            kind,
            Node::new(name)
                .span(record_span)
                .lazy(emit_nodes, r.into_nodes()),
        ));
        at = end;
    }
    out
}

const CRYPT_FLAGS5: FlagTable = &[
    flag(0x01, "PASSWORD_CHECK"),
    flag(0x02, "TWEAKED_CHECKSUMS"),
];

/// The fields of a file encryption record.
fn crypt_record(r: &mut ByteReader<'_>) -> Option<()> {
    let version = r.vint("Encryption version")?;
    r.with(|n| n.summary(if version == 0 { "AES-256" } else { "unknown" }));
    let flags = r.vint("Encryption flags")?;
    r.with(|n| {
        let (set, unknown) = crate::value::decode_flags(CRYPT_FLAGS5, flags);
        n.value(Value::Flags {
            raw: flags,
            bits: 64,
            set,
            unknown,
        })
    });
    let kdf = r.u8("KDF count")?;
    r.with(|n| n.summary(format!("2^{kdf} PBKDF2 iterations")));
    r.bytes("Salt", 16)?;
    r.bytes("IV", 16)?;
    if flags & 0x01 != 0 {
        r.bytes("Password check value", 12)?;
    }
    Some(())
}

fn time_record(r: &mut ByteReader<'_>) -> Option<()> {
    let flags = r.vint("Flags")?;
    let unix = flags & 1 != 0;
    for (bit, name) in [
        (2u64, "Modification time"),
        (4, "Creation time"),
        (8, "Access time"),
    ] {
        if flags & bit == 0 {
            continue;
        }
        if unix {
            let t = r.u32(name, LE)?;
            r.with(|n| {
                n.value(Value::Timestamp {
                    unix_seconds: t.into(),
                })
            });
        } else {
            let t = r.u64(name, LE)?;
            r.with(|n| {
                n.value(Value::Timestamp {
                    unix_seconds: crate::text::filetime_to_unix(t),
                })
            });
        }
    }
    Some(())
}

// ---------------------------------------------------------------------------
// File contents

/// Files whose CRC32 is checked when their content is expanded (larger ones
/// would be read in full just for that).
pub(crate) const CRC_LIMIT: u64 = 32 << 20;

/// A node for a file's content, decoded and checked when expanded.
fn content_node(name: &'static str, input: Input, part: Part) -> Node {
    let mut summary = format!("{}, {}", part.how.name(), fmt::size(part.unpacked));
    if part.solid {
        summary.push_str(", solid");
    }
    Node::new(name)
        .span(part.data)
        .summary(summary)
        .lazy(content, (input, part))
}

/// The runs of files decoded together: one per non-solid compressed file
/// and the solid files after it.
struct Groups {
    groups: Vec<Vec<Part>>,
    /// Each compressed file's run and index in it, by `Part::block`.
    at: BTreeMap<u64, (usize, usize)>,
}

/// Walks all headers of the archive for its file parts.
async fn walk_parts(cx: &Cx, input: Input, rar5: bool) -> Result<Vec<Part>> {
    let mut cur = Cursor::new(cx, input.span, LE);
    let mut parts = Vec::new();
    if rar5 {
        cur.seek(8);
        let mut key = None;
        while cur.remaining() >= 6 {
            let b = next_block5(cx, &mut cur, key.as_deref()).await?;
            if b.kind == 2
                && let Some(p) = b.part
            {
                parts.push(p);
            }
            if b.kind == 4 && key.is_none() {
                match b.crypt {
                    Some(c) => key = rar5_keys(cx, input.span, &c).await,
                    None => break,
                }
                if key.is_none() {
                    break;
                }
            }
            if b.kind == 5 {
                break;
            }
            cx.checkpoint().await;
        }
    } else {
        cur.seek(7);
        while cur.remaining() >= 7 {
            let b = next_block4(cx, &mut cur).await?;
            if let Some(p) = b.part {
                parts.push(p);
            }
            if b.kind == 0x7b || (b.kind == 0x73 && b.flags & 0x0080 != 0) {
                break;
            }
            cx.checkpoint().await;
        }
    }
    Ok(parts)
}

async fn groups(cx: &Cx, input: Input, rar5: bool) -> Result<Arc<Groups>> {
    if let Some(g) = cx.cached::<Groups>(input.span, "rar groups") {
        return Ok(g);
    }
    let mut groups: Vec<Vec<Part>> = Vec::new();
    let mut at = BTreeMap::new();
    let mut open = false;
    for p in walk_parts(cx, input, rar5).await? {
        cx.checkpoint().await;
        match p.how {
            How::Stored => {}
            How::Lz(_) => {
                let last = groups.len().saturating_sub(1);
                match groups.last_mut() {
                    Some(g) if open && p.solid => {
                        at.entry(p.block).or_insert((last, g.len()));
                        g.push(p);
                    }
                    _ => {
                        at.entry(p.block).or_insert((groups.len(), 0));
                        groups.push(vec![p]);
                    }
                }
                open = true;
            }
            // A run cannot continue past what we cannot decode.
            How::Unsupported(_) => open = false,
        }
    }
    let g = Arc::new(Groups { groups, at });
    cx.cache(input.span, "rar groups", g.clone());
    Ok(g)
}

/// A run's decoded stream and where each of its files starts in it.
struct RunStream {
    stream: Span,
    offsets: Vec<u64>,
}

/// The decoded output of a run of files, and where file `index` starts in it.
async fn group_stream(cx: &Cx, parts: &[Part], index: usize, realm: Span) -> Result<(Span, u64)> {
    let (Some(first), Some(last)) = (parts.first(), parts.last()) else {
        return Err(Diagnostic::malformed("empty solid run"));
    };
    let parent = Span::new(
        first.data.source,
        first.data.offset,
        last.data.end().saturating_sub(first.data.offset),
    );
    // Built once per run, not once per file of it.
    let run = match cx.cached::<RunStream>(parent, "rar run stream") {
        Some(run) => run,
        None => {
            let run = Arc::new(run_stream(cx, parts, parent, realm).await?);
            cx.cache(parent, "rar run stream", run.clone());
            run
        }
    };
    Ok((run.stream, run.offsets.get(index).copied().unwrap_or(0)))
}

/// `realm` is the archive, which encrypted files ask the password for.
async fn run_stream(cx: &Cx, parts: &[Part], parent: Span, realm: Span) -> Result<RunStream> {
    let Some(first) = parts.first() else {
        return Err(Diagnostic::malformed("empty solid run"));
    };
    // A solid run can hold millions of files: build its tables with yields.
    let mut pieces = Vec::with_capacity(parts.len());
    let mut members = Vec::with_capacity(parts.len());
    let mut offsets = Vec::with_capacity(parts.len());
    let mut total = 0u64;
    let mut dict = 0;
    for (i, p) in parts.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        offsets.push(total);
        pieces.push(match p.crypt {
            None => p.data,
            Some(c) => {
                let keys = rar5_keys(cx, realm, &c).await.ok_or_else(|| {
                    Diagnostic::unsupported("encrypted file (no password, or a wrong one)")
                })?;
                decrypt5(cx, p.data, &c, &keys)?
            }
        });
        members.push(Member {
            packed: p.data.len,
            unpacked: p.unpacked,
            algorithm: match p.how {
                How::Lz(a) => a,
                _ => Algorithm::V29,
            },
        });
        total = total.saturating_add(p.unpacked);
        dict = dict.max(p.dict);
    }
    let data = if parts.len() == 1 {
        pieces.first().copied().unwrap_or(first.data)
    } else {
        cx.add_pieces_stepped(
            Origin {
                parent,
                transform: "rar-solid",
            },
            &pieces,
        )
        .await?
    };
    let codec = Codec::Rar(Params {
        dict,
        members: members.into(),
    });
    let stream = cx.decode_lazy(data, &codec, total)?;
    Ok(RunStream {
        stream: Span::new(stream.source, 0, total),
        offsets,
    })
}

/// Expander: a file's content (decoded with the files of its solid run),
/// its CRC32 checked, dissected.
async fn content(cx: Cx, (input, part): (Input, Part)) -> Result<()> {
    // An encrypted file: decrypt its data first (and every file of its
    // solid run, see `run_stream`).
    let mut hash_key = None;
    let encrypted = part.crypt.is_some();
    let part =
        match part.crypt {
            None => part,
            Some(c) => match rar5_keys(&cx, input.span, &c).await {
                Some(keys) => {
                    hash_key = c.tweaked.then(|| keys.hash_key.clone());
                    Part {
                        data: decrypt5(&cx, part.data, &c, &keys)?,
                        crypt: None,
                        ..part
                    }
                }
                None => {
                    cx.emit(Node::new("Encrypted data").span(part.data).diag(
                        Diagnostic::unsupported("encrypted file (no password, or a wrong one)"),
                    ));
                    return Ok(());
                }
            },
        };
    let span = match part.how {
        How::Stored if encrypted => part.data.sub(0, part.unpacked),
        How::Stored => part.data,
        How::Lz(_) => {
            let g;
            let single = [part];
            let (run, index): (&[Part], usize) = if part.solid {
                g = groups(&cx, input, part.rar5).await?;
                g.at.get(&part.block)
                    .and_then(|&(r, i)| Some((g.groups.get(r)?.as_slice(), i)))
                    .ok_or_else(|| Diagnostic::malformed("file not found in its solid run"))?
            } else {
                (&single, 0)
            };
            let (stream, offset) = group_stream(&cx, run, index, input.span).await?;

            if run.len() > 1 {
                cx.emit(Node::new("Solid run").span(stream).summary(format!(
                    "file {} of {}, at {offset:#x}",
                    index.saturating_add(1),
                    count(to_u64(run.len()), "file", "files")
                )));
            }
            stream.sub(offset, part.unpacked)
        }
        How::Unsupported(what) => {
            return Err(Diagnostic::unsupported(format!("{what} compression")));
        }
    };
    if let Some(want) = part.crc
        && span.len <= CRC_LIMIT
    {
        let (got, len) = crc_of(&cx, span).await?;
        // With tweaked checksums the header holds a MAC of the CRC32.
        let got = match &hash_key {
            Some(k) => tweak_crc5(k, got),
            None => got,
        };
        let node = Node::new("CRC32").value(hex(got, 64));
        cx.emit(if len < part.unpacked {
            node.diag(Diagnostic::malformed(format!(
                "decoded {len:#x} of {:#x} bytes",
                part.unpacked
            )))
        } else if got != want {
            node.diag(Diagnostic::warning(format!(
                "CRC32 mismatch: stored {want:#010x}"
            )))
        } else {
            node.summary("valid")
        });
    }
    dissect_or_data(cx, input.nested(span)).await
}

/// The keys PBKDF2 derives for a RAR 5 password and salt.
struct Keys5 {
    key: Vec<u8>,
    hash_key: Vec<u8>,
}

/// PBKDF2-HMAC-SHA256 as RAR 5 runs it: one output block, whose running
/// value after 2^kdf iterations is the AES key, after 16 more the key of
/// the tweaked checksums, and after 16 more the value folded into the
/// password check. One unit of work is one HMAC.
struct Kdf5 {
    prf: crate::codec::crypto::Hmac<crate::codec::crypto::Sha256>,
    salt: [u8; 16],
    count: u32,
    round: u32,
    u: Vec<u8>,
    t: Vec<u8>,
    key: Vec<u8>,
    hash_key: Vec<u8>,
    check: Vec<u8>,
}

impl Kdf5 {
    fn new(password: &[u8], c: &Crypt5) -> Self {
        Kdf5 {
            prf: crate::codec::crypto::Hmac::new(password),
            salt: c.salt,
            count: 1u32 << c.kdf.min(MAX_KDF5),
            round: 0,
            u: Vec::new(),
            t: Vec::new(),
            key: Vec::new(),
            hash_key: Vec::new(),
            check: Vec::new(),
        }
    }

    /// The 8-byte password check value: the last value folded by XOR.
    fn password_check(&self) -> [u8; 8] {
        let mut out = [0u8; 8];
        for (i, b) in self.check.iter().enumerate() {
            if let Some(o) = out.get_mut(i % 8) {
                *o ^= b;
            }
        }
        out
    }
}

impl crate::codec::crypto::Stepped for Kdf5 {
    fn done(&self) -> bool {
        !self.check.is_empty()
    }

    fn advance(&mut self, units: u32) -> u32 {
        let mut used = 0u32;
        while used < units.max(1) && !self.done() {
            let mut mac = self.prf.clone();
            if self.round == 0 {
                mac.update(&self.salt);
                mac.update(&1u32.to_be_bytes());
                self.u = mac.finish();
                self.t.clone_from(&self.u);
            } else {
                mac.update(&self.u);
                self.u = mac.finish();
                for (x, y) in self.t.iter_mut().zip(&self.u) {
                    *x ^= y;
                }
            }
            used = used.saturating_add(1);
            self.round = self.round.saturating_add(1);
            if self.round == self.count {
                self.key.clone_from(&self.t);
            } else if self.round == self.count.saturating_add(16) {
                self.hash_key.clone_from(&self.t);
            } else if self.round == self.count.saturating_add(32) {
                self.check.clone_from(&self.t);
            }
        }
        used
    }
}

/// Derived keys already verified, by salt and KDF count (a RAR archive
/// usually reuses one salt for all its files).
type KeyCache = std::sync::Mutex<Vec<([u8; 16], u8, Arc<Keys5>)>>;

/// The keys for an encrypted RAR 5 file: asks for the archive's password
/// (realm: the archive) and derives in budgeted steps until the password
/// check value matches. `None` if declined or every attempt failed.
async fn rar5_keys(cx: &Cx, realm: Span, c: &Crypt5) -> Option<Arc<Keys5>> {
    use crate::secret::{MAX_ATTEMPTS, SecretRequest};
    const PROMPT: &str = "Password for the encrypted RAR files";
    let cache = match cx.cached::<KeyCache>(realm, "rar5 keys") {
        Some(cache) => cache,
        None => {
            let cache = Arc::new(KeyCache::default());
            cx.cache(realm, "rar5 keys", cache.clone());
            cache
        }
    };
    if let Ok(found) = cache.lock()
        && let Some((_, _, keys)) = found.iter().find(|(s, k, _)| *s == c.salt && *k == c.kdf)
    {
        return Some(keys.clone());
    }
    // A damaged check value (its checksum fails) cannot tell passwords
    // apart; decrypt with the first answer then.
    let check = c.check.filter(|v| {
        let (value, sum) = v.split_at(8);
        <crate::codec::crypto::Sha256 as crate::codec::crypto::Hash>::digest(value).get(..4)
            == Some(sum)
    });
    for attempt in 0..MAX_ATTEMPTS {
        let secret = cx
            .secret(SecretRequest::password(realm, PROMPT, attempt))
            .await?;
        let mut kdf = Kdf5::new(secret.expose(), c);
        crate::codec::crypto::run(cx, &mut kdf).await;
        if let Some(v) = check
            && v.get(..8) != Some(&kdf.password_check()[..])
        {
            continue;
        }
        let keys = Arc::new(Keys5 {
            key: kdf.key,
            hash_key: kdf.hash_key,
        });
        if let Ok(mut found) = cache.lock() {
            found.push((c.salt, c.kdf, keys.clone()));
        }
        return Some(keys);
    }
    None
}

/// The plaintext of an encrypted file's data (all of its blocks; the
/// packed size is rounded up to a block, and the file's sizes say how
/// much of it counts).
fn decrypt5(cx: &Cx, data: Span, c: &Crypt5, keys: &Keys5) -> Result<Span> {
    let mut key = keys.key.clone();
    key.extend_from_slice(&c.iv);
    let codec = Codec::AesCbcRaw(crate::codec::crypto::Key::new(key));
    cx.decode_lazy(data, &codec, data.len & !15)
}

/// A CRC32 as RAR 5 stores it with tweaked checksums: HMAC-SHA256 of its
/// little-endian bytes keyed by the password-derived hash key, folded to
/// 32 bits by XOR.
fn tweak_crc5(hash_key: &[u8], crc: u32) -> u32 {
    let mac =
        crate::codec::crypto::hmac::<crate::codec::crypto::Sha256>(hash_key, &crc.to_le_bytes());
    let mut out = [0u8; 4];
    for (i, b) in mac.iter().enumerate() {
        if let Some(o) = out.get_mut(i % 4) {
            *o ^= b;
        }
    }
    u32::from_le_bytes(out)
}

/// CRC32 and length of what `span` holds.
pub(crate) async fn crc_of(cx: &Cx, span: Span) -> Result<(u32, u64)> {
    let mut crc = 0xffff_ffffu32;
    let mut pos = 0u64;
    while pos < span.len {
        let data = cx.read(span.sub(pos, 1 << 20)).await?;
        if data.is_empty() {
            break;
        }
        crate::formats::util::datakit::feed_paced(cx, &data, |piece| {
            crc = crate::codec::crc::crc32_update(crc, piece);
        })
        .await;
        pos = pos.saturating_add(to_u64(data.len()));
    }
    Ok((crc ^ 0xffff_ffff, pos))
}

/// A RAR 4.x file name. With flag 0x200 and a NUL in the field, the field
/// holds the name in the archiver's 8-bit code page, the NUL, then the
/// Unicode name compressed against it; this follows libarchive's
/// `read_header` (`archive_read_support_format_rar.c`, BSD-2-Clause, see
/// `THIRD-PARTY.md`): a high byte, then 2-bit opcodes taken from the top of
/// a flag byte for a low byte with high byte 0, a low byte with the stored
/// high byte, a whole UTF-16 unit, or a run of bytes copied from the field
/// at the current unit index (with a correction added and the high byte
/// when the top bit of the run length is set). With 0x200 and no NUL the
/// field is UTF-8, as libarchive reads it. Otherwise the 8-bit name is
/// UTF-8 when valid (RAR for Unix writes the locale's encoding) and the IBM
/// OEM code page otherwise (RAR for DOS and Windows).
fn name4(field: &[u8], flags: u16) -> String {
    let end = field.iter().position(|&b| b == 0);
    let oem = field.get(..end.unwrap_or(field.len())).unwrap_or_default();
    if flags & 0x200 != 0
        && let Some(nul) = end
        && let Some(name) = decode_unicode_name(field, nul.saturating_add(1))
    {
        return name;
    }
    match std::str::from_utf8(oem) {
        Ok(s) => s.to_owned(),
        Err(_) => crate::codec::charset::Charset::Cp437.decode(oem),
    }
}

/// The compressed Unicode part of a RAR 4.x name field, starting at byte
/// `start` (after the NUL). As in libarchive, the output is at most as
/// many UTF-16 units as the field has bytes, and a run copies the field's
/// byte at the index of the unit it produces. Where libarchive would read
/// past the field for a truncated opcode, this stops; an empty result (no
/// encoded bytes) falls back to the 8-bit name.
fn decode_unicode_name(field: &[u8], start: usize) -> Option<String> {
    let max = field.len();
    let mut units: Vec<u16> = Vec::new();
    let mut it = field.get(start..)?.iter().copied();
    let high = it.next()?;
    let mut flag_byte = 0u8;
    let mut flag_bits = 0u32;
    while units.len() < max {
        if flag_bits == 0 {
            let Some(f) = it.next() else { break };
            flag_byte = f;
            flag_bits = 8;
        }
        flag_bits = flag_bits.saturating_sub(2);
        match flag_byte.checked_shr(flag_bits).unwrap_or(0) & 3 {
            0 => {
                let Some(b) = it.next() else { break };
                units.push(u16::from_be_bytes([0, b]));
            }
            1 => {
                let Some(b) = it.next() else { break };
                units.push(u16::from_be_bytes([high, b]));
            }
            2 => {
                let (Some(lo), Some(hi)) = (it.next(), it.next()) else {
                    break;
                };
                units.push(u16::from_be_bytes([hi, lo]));
            }
            _ => {
                let Some(length) = it.next() else { break };
                let (extra, hi) = if length & 0x80 != 0 {
                    let Some(e) = it.next() else { break };
                    (e, high)
                } else {
                    (0, 0)
                };
                for _ in 0..(length & 0x7f).saturating_add(2) {
                    if units.len() >= max {
                        break;
                    }
                    let b = field.get(units.len()).copied().unwrap_or(0);
                    units.push(u16::from_be_bytes([hi, b.wrapping_add(extra)]));
                }
            }
        }
    }
    if units.is_empty() {
        return None;
    }
    Some(String::from_utf16_lossy(&units))
}

#[cfg(test)]
mod name_tests {
    use super::name4;

    #[test]
    fn unicode_names() {
        // From RAR 6.23 (`rar a -ma4`): tests/fixtures/external/rar/v4-unicode.rar.
        let mut field = b"docs\\Gr\xc3\xbc\xc3\x9fe.txt\0".to_vec();
        field.extend_from_slice(&[
            0x01, 0xc0, 0x05, 0xfc, 0xdf, 0x65, 0x00, 0x2e, 0x74, 0x78, 0x74,
        ]);
        assert_eq!(name4(&field, 0x200), "docs\\Grüße.txt");
        let mut field = "日本語.txt\0".as_bytes().to_vec();
        field.extend_from_slice(&[
            0x65, 0x68, 0xe5, 0x2c, 0x67, 0x9e, 0x8a, 0x2e, 0x00, 0x74, 0x78, 0x74,
        ]);
        assert_eq!(name4(&field, 0x200), "日本語.txt");
        // A run with a correction: OEM 0x80 0x81 plus 0x50, high byte 0x04.
        let field = [0x80, 0x81, 0, 0x04, 0xc0, 0x80, 0x50];
        assert_eq!(name4(&field, 0x200), "\u{4d0}\u{4d1}");
        // As in libarchive: a run copies the field's bytes by unit index
        // (past the 8-bit name too), and the output stops at as many units
        // as the field has bytes.
        let field = [b'a', 0, 0x00, 0xc0, 0x05];
        assert_eq!(name4(&field, 0x200), "a\0\0\u{c0}\u{5}");
        // 0x200 without a NUL: the field is UTF-8.
        assert_eq!(name4("Grüße".as_bytes(), 0x200), "Grüße");
        // No Unicode part: UTF-8, else code page 437.
        assert_eq!(name4(b"plain.txt", 0), "plain.txt");
        assert_eq!(name4(b"\x8e\x99.txt", 0), "ÄÖ.txt");
    }
}
