//! Unity asset bundles and serialized files.
//!
//! - **Asset bundles.** `UnityFS` (Unity 5.3 and later; also `UnityWeb` and
//!   `UnityRaw` with format 6): a big-endian header, a compressed *blocks
//!   info* (a data hash, the block list and the directory), then the data
//!   blocks, each compressed on its own (none, LZMA, LZ4, LZ4HC; LZHAM is
//!   unsupported). The decompressed blocks form one stream that the
//!   directory's nodes (serialized files, `.resS`/`.resource` data) are cut
//!   from; here it is a piece list over lazily decoded blocks, so opening one
//!   node decodes only the blocks it touches. The older `UnityWeb` (LZMA,
//!   with the decoded size, as in `.lzma` files) and `UnityRaw` formats 1–3
//!   have a level table and one stream that starts with the directory.
//! - **Serialized files** (the `CAB-…` nodes of bundles, `.assets`,
//!   `level0`, `globalgamemanagers`): a big-endian header (versions 9–23),
//!   then metadata in the file's byte order: Unity version, target platform,
//!   the types (each with its type tree: a flat node table and string buffer
//!   from version 12, recursive records before), the object table, script
//!   types, externals, reference types and user information; then the
//!   object data. Objects whose type has a type tree are decoded field by
//!   field (numbers, strings, vectors, nested structs); strings and byte
//!   arrays become embedded content.
//!
//! Layouts are from memory of Unity's formats, checked against UnityPy 1.25
//! (its reader, and its writer, which produced the external fixtures). Where
//! the two disagree with nothing to settle it, UnityPy is followed: the
//! version rule that decides whether bundle flag 0x200 means "block info
//! padded" (newer engines) or "encrypted" (UnityCN, older ones); the
//! cumulative level table of `UnityWeb`/`UnityRaw`, read as one stream. The
//! directory node flags (1 directory, 2 deleted, 4 serialized file) are from
//! memory; the 8 bytes after the version-22 header's data offset are shown
//! raw. Objects without a type tree (stripped player builds) are listed
//! with their class and size but not decoded.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u64_be};
use crate::codec::{Codec, lzma};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, Prim, struct_node};
use crate::formats::{Head, Input, Probe, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, FlagTable, Radix, Value, field, flag, lookup};

const BE: Endian = Endian::Big;

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

fn align(pos: u64, to: u64) -> u64 {
    pos.checked_next_multiple_of(to).unwrap_or(pos)
}

// ---------------------------------------------------------------------------
// Asset bundles

declare_format!(pub UNITYFS = "unityfs", "Unity asset bundle", ["unity3d", "bundle", "assetbundle"], "application/x-unityfs",
    Probe::Magic(&[(0, b"UnityFS\0"), (0, b"UnityWeb\0"), (0, b"UnityRaw\0")]), bundle);

const COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "LZMA"),
    (2, "LZ4"),
    (3, "LZ4HC"),
    (4, "LZHAM"),
];

/// Archive flags of engines from 2020.3.34, 2021.3.2 and 2022.1.1 on.
const ARCHIVE_FLAGS: FlagTable = &[
    field(0x3f, 0, "uncompressed blocks info"),
    field(0x3f, 1, "LZMA"),
    field(0x3f, 2, "LZ4"),
    field(0x3f, 3, "LZ4HC"),
    field(0x3f, 4, "LZHAM"),
    flag(0x40, "BlocksAndDirectoryInfoCombined"),
    flag(0x80, "BlocksInfoAtTheEnd"),
    flag(0x100, "OldWebPluginCompatibility"),
    flag(0x200, "BlockInfoNeedPaddingAtStart"),
    flag(0x400, "encrypted (UnityCN)"),
    flag(0x1000, "encrypted (UnityCN)"),
];

/// Archive flags of older engines.
const ARCHIVE_FLAGS_OLD: FlagTable = &[
    field(0x3f, 0, "uncompressed blocks info"),
    field(0x3f, 1, "LZMA"),
    field(0x3f, 2, "LZ4"),
    field(0x3f, 3, "LZ4HC"),
    field(0x3f, 4, "LZHAM"),
    flag(0x40, "BlocksAndDirectoryInfoCombined"),
    flag(0x80, "BlocksInfoAtTheEnd"),
    flag(0x100, "OldWebPluginCompatibility"),
    flag(0x200, "encrypted (UnityCN)"),
];

const BLOCK_FLAGS: FlagTable = &[
    field(0x3f, 0, "uncompressed"),
    field(0x3f, 1, "LZMA"),
    field(0x3f, 2, "LZ4"),
    field(0x3f, 3, "LZ4HC"),
    field(0x3f, 4, "LZHAM"),
    flag(0x40, "streamed"),
];

const NODE_FLAGS: FlagTable = &[
    flag(1, "directory"),
    flag(2, "deleted"),
    flag(4, "serialized file"),
];

/// `major.minor.patch` of an engine version string such as `2022.3.10f1`.
fn engine_version(s: &str) -> (u32, u32, u32) {
    let mut parts = s.split('.').map(|p| {
        let digits: String = p.chars().take_while(char::is_ascii_digit).collect();
        digits.parse::<u32>().unwrap_or(0)
    });
    (
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
        parts.next().unwrap_or(0),
    )
}

/// Whether the engine uses the newer flag layout (0x200 = block info
/// padding), by UnityPy's rule.
fn new_flags(engine: &str) -> bool {
    let (major, minor, patch) = engine_version(engine);
    !(major < 2020
        || (major == 2020 && (minor, patch) < (3, 34))
        || (major == 2021 && (minor, patch) < (3, 2))
        || (major == 2022 && (minor, patch) < (1, 1)))
}

fn compression_name(scheme: u32) -> &'static str {
    lookup(COMPRESSION, scheme.into()).unwrap_or("unknown compression")
}

/// The stream and codec of a block (or blocks info) compressed with
/// `scheme` and decoding to `size` bytes. LZMA blocks start with the
/// 5-byte properties header and have no size field.
async fn block_codec(cx: &Cx, span: Span, scheme: u32, size: u64) -> Result<(Span, Codec)> {
    match scheme {
        0 => Ok((span, Codec::Stored)),
        1 => {
            let head = cx.read(span.sub(0, 5)).await?;
            if head.len() < 5 {
                return Err(Diagnostic::truncated(span.sub(0, 5), to_u64(head.len())));
            }
            let props = lzma::Props::from_byte(head.first().copied().unwrap_or(0xff))
                .map_err(|e| e.at(span.sub(0, 1)))?;
            Ok((
                span.tail(5),
                Codec::LzmaRaw {
                    props,
                    size: Some(to_usize(size)),
                    dict: crate::bytes::u32_le(&head, 1),
                },
            ))
        }
        2 | 3 => Ok((span, Codec::Lz4Block)),
        _ => Err(
            Diagnostic::unsupported(format!("{} compression", compression_name(scheme))).at(span),
        ),
    }
}

async fn bundle(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (signature, s1) = cur.cstr(16).await?;
    cx.emit(
        Node::new("Signature")
            .span(s1)
            .value(Value::Text(signature.clone())),
    );
    let vspan = cur.span(4);
    let version = cur.u32().await?;
    cx.emit(
        Node::new("Format version")
            .span(vspan)
            .value(uint(version.into(), 32)),
    );
    let (player, s2) = cur.cstr(64).await?;
    cx.emit(
        Node::new("Player version")
            .span(s2)
            .value(Value::Text(player)),
    );
    let (engine, s3) = cur.cstr(64).await?;
    cx.emit(
        Node::new("Engine version")
            .span(s3)
            .value(Value::Text(engine.clone())),
    );
    let title = format!("{signature} v{version}, Unity {engine}");
    cx.annotate(title.clone());
    let more = if signature == "UnityFS" || version >= 6 {
        fs_bundle(
            &cx,
            input,
            &mut cur,
            signature != "UnityFS",
            version,
            &engine,
        )
        .await?
    } else {
        web_bundle(&cx, input, &mut cur, signature == "UnityWeb", version).await?
    };
    cx.annotate(format!("{title}{more}"));
    Ok(())
}

fn fs_header(f: &mut Fields<'_>, &(new, extra): &(bool, bool)) -> Result<(u64, u32, u32, u32)> {
    let size = f.u64("Bundle size").emit()?;
    let compressed = f.u32("Blocks info size (compressed)").emit()?;
    let uncompressed = f.u32("Blocks info size").emit()?;
    let flags = f
        .u32("Flags")
        .hex()
        .flags(if new {
            ARCHIVE_FLAGS
        } else {
            ARCHIVE_FLAGS_OLD
        })
        .emit()?;
    if extra {
        f.u8("Padding byte").emit()?;
    }
    Ok((size, compressed, uncompressed, flags))
}

struct Block {
    size: u32,
    compressed: u32,
    flags: u16,
}

struct DirEntry {
    offset: u64,
    size: u64,
    flags: u32,
    path: String,
}

/// UnityFS (and format 6 of the older signatures).
async fn fs_bundle(
    cx: &Cx,
    input: Input,
    cur: &mut Cursor<'_>,
    extra: bool,
    version: u32,
    engine: &str,
) -> Result<String> {
    let file = input.span;
    let new = new_flags(engine);
    let start = cur.pos();
    let hspan = file.sub(start, if extra { 21 } else { 20 });
    let block = cx.block(hspan).await?;
    let (_, compressed, uncompressed, flags) =
        fs_header(&mut Fields::new(&block, BE), &(new, extra))?;
    cx.emit(struct_node(
        "Bundle header",
        hspan,
        BE,
        (new, extra),
        fs_header,
    ));
    cur.seek(start.saturating_add(hspan.len));
    if version >= 7 {
        cur.seek(align(cur.pos(), 16));
    }
    let scheme = flags & 0x3f;
    let encrypted = if new {
        flags & 0x1400 != 0
    } else {
        flags & 0x200 != 0
    };
    if encrypted {
        cx.emit(
            Node::new("Blocks and directory")
                .span(file.tail(cur.pos()))
                .diag(Diagnostic::unsupported("UnityCN-encrypted bundle")),
        );
        return Ok(", encrypted".into());
    }
    let header_end = cur.pos();
    let at_end = flags & 0x80 != 0;
    let info_span = if at_end {
        file.sub(
            file.len.saturating_sub(compressed.into()),
            compressed.into(),
        )
    } else {
        file.sub(header_end, compressed.into())
    };
    let mut data_start = if at_end {
        header_end
    } else {
        header_end.saturating_add(compressed.into())
    };
    if new && flags & 0x200 != 0 {
        data_start = align(data_start, 16);
    }
    let info_node = Node::new("Blocks info").span(info_span).summary(format!(
        "{}, {compressed} → {uncompressed} bytes",
        compression_name(scheme)
    ));
    let info = match block_codec(cx, info_span, scheme, uncompressed.into()).await {
        Ok((span, Codec::Stored)) => span,
        Ok((stream, codec)) => {
            let decoded =
                crate::codec::decode_span(cx, stream, &codec, Some(uncompressed.into())).await?;
            if let Some(e) = decoded.error {
                cx.emit(info_node.diag(e));
                return Ok(String::new());
            }
            decoded.span
        }
        Err(e) => {
            cx.emit(info_node.diag(e));
            return Ok(String::new());
        }
    };
    cx.emit(info_node.lazy(blocks_info, (info, file, data_start)));

    let (blocks, entries) = read_blocks_info(cx, info).await?;
    // The data: each block decoded lazily, all joined into one stream.
    let mut pieces = Vec::with_capacity(blocks.len());
    let mut pos = data_start;
    let mut total = 0u64;
    let mut problem = None;
    for b in &blocks {
        let cspan = file.sub(pos, b.compressed.into());
        pos = pos.saturating_add(b.compressed.into());
        total = total.saturating_add(b.size.into());
        let scheme = u32::from(b.flags & 0x3f);
        let piece = match block_codec(cx, cspan, scheme, b.size.into()).await {
            Ok((span, Codec::Stored)) => Ok(span.sub(0, b.size.into())),
            Ok((stream, codec)) => cx.decode_lazy(stream, &codec, b.size.into()),
            Err(e) => Err(e),
        };
        match piece {
            Ok(p) => pieces.push(p),
            Err(e) => {
                problem.get_or_insert(e);
                pieces.push(Span::zeros(b.size.into()));
            }
        }
    }
    let data = file.sub(data_start, pos.saturating_sub(data_start));
    let scheme = blocks.first().map_or(0, |b| u32::from(b.flags & 0x3f));
    let mut node = Node::new("Data").span(data).summary(format!(
        "{} blocks, {}, {} → {total} bytes",
        blocks.len(),
        compression_name(scheme),
        data.len
    ));
    if let Some(e) = problem {
        node = node.diag(e);
    }
    cx.emit(node);
    let stream = cx.add_pieces(
        Origin {
            parent: data,
            transform: "unityfs-blocks",
        },
        pieces,
    )?;
    let count = entries.len();
    cx.set_count(Count::AtLeast(to_u64(count)));
    for e in entries {
        push_entry(
            cx,
            input,
            stream,
            e.offset,
            e.size,
            e.flags & 4 != 0,
            &e.path,
        )
        .await;
    }
    Ok(format!(", {}, {count} files", compression_name(scheme)))
}

async fn push_entry(
    cx: &Cx,
    input: Input,
    stream: Span,
    offset: u64,
    size: u64,
    serialized: bool,
    path: &str,
) {
    let span = stream.sub(offset, size);
    let name = path.to_owned();
    let mut node = if serialized {
        embedded_as(name, input.nested(span), &UNITY_SERIALIZED)
    } else {
        embedded(name, input.nested(span))
    };
    node = node.summary(format!(
        "{size} bytes{}",
        if serialized { ", serialized file" } else { "" }
    ));
    if span.len < size {
        node = node.diag(Diagnostic::malformed(format!(
            "node {offset:#x}+{size:#x} runs past the end of the data ({:#x} bytes)",
            stream.len
        )));
    }
    cx.push(node).await;
}

async fn read_blocks_info(cx: &Cx, info: Span) -> Result<(Vec<Block>, Vec<DirEntry>)> {
    let mut cur = Cursor::new(cx, info, BE);
    cur.skip(16);
    let n = u64::from(cur.u32().await?);
    let table = info.sub_exact(cur.pos(), n.saturating_mul(10))?;
    let bytes = cx.read(table).await?;
    let blocks = bytes
        .as_chunks::<10>()
        .0
        .iter()
        .map(|c| Block {
            size: u32_be(c, 0).unwrap_or(0),
            compressed: u32_be(c, 4).unwrap_or(0),
            flags: crate::bytes::u16_be(c, 8).unwrap_or(0),
        })
        .collect();
    cur.skip(table.len);
    let n = cur.u32().await?;
    let mut entries = Vec::new();
    for _ in 0..n {
        let offset = cur.u64().await?;
        let size = cur.u64().await?;
        let flags = cur.u32().await?;
        let (path, _) = cur.cstr(4096).await?;
        entries.push(DirEntry {
            offset,
            size,
            flags,
            path,
        });
    }
    Ok((blocks, entries))
}

/// The decoded blocks info: hash, block table, directory.
async fn blocks_info(cx: Cx, (info, file, data_start): (Span, Span, u64)) -> Result<()> {
    let mut cur = Cursor::new(&cx, info, BE);
    let hash = cur.span(16);
    let bytes = cur.bytes(16).await?;
    cx.emit(
        Node::new("Uncompressed data hash")
            .span(hash)
            .value(Value::Bytes(bytes)),
    );
    let cspan = cur.span(4);
    let n = cur.u32().await?;
    cx.emit(
        Node::new("Block count")
            .span(cspan)
            .value(uint(n.into(), 32)),
    );
    let table = info.sub_exact(cur.pos(), u64::from(n).saturating_mul(10))?;
    cx.emit(
        Node::new("Blocks")
            .span(table)
            .summary(format!("{n} blocks"))
            .lazy(block_list, (table, file, data_start)),
    );
    cur.skip(table.len);
    let start = cur.pos();
    let n = cur.u32().await?;
    let mut end = cur.pos();
    for _ in 0..n {
        cur.skip(20);
        cur.cstr(4096).await?;
        end = cur.pos();
    }
    cx.emit(
        Node::new("Directory")
            .span(info.sub(start, end.saturating_sub(start)))
            .summary(format!("{n} nodes"))
            .lazy(directory_list, info.tail(start)),
    );
    Ok(())
}

fn block_entry(f: &mut Fields<'_>, target: &Span) -> Result<u16> {
    let size = f.u32("Uncompressed size").emit()?;
    f.u32("Compressed size").target(*target).emit()?;
    let flags = f.u16("Flags").hex().flags(BLOCK_FLAGS).emit()?;
    let _ = size;
    Ok(flags)
}

async fn block_list(cx: Cx, (table, file, data_start): (Span, Span, u64)) -> Result<()> {
    let bytes = cx.read(table).await?;
    let mut pos = data_start;
    for (i, c) in bytes.as_chunks::<10>().0.iter().enumerate() {
        let size = u32_be(c, 0).unwrap_or(0);
        let compressed = u32_be(c, 4).unwrap_or(0);
        let flags = crate::bytes::u16_be(c, 8).unwrap_or(0);
        let target = file.sub(pos, compressed.into());
        pos = pos.saturating_add(compressed.into());
        let span = table.sub(to_u64(i).saturating_mul(10), 10);
        cx.push(
            struct_node(format!("Block {i}"), span, BE, target, block_entry)
                .target(target)
                .summary(format!(
                    "{}, {compressed} → {size} bytes",
                    compression_name(u32::from(flags & 0x3f))
                )),
        )
        .await;
    }
    Ok(())
}

async fn directory_list(cx: Cx, region: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, region, BE);
    let n = cur.u32().await?;
    for _ in 0..n {
        let start = cur.pos();
        let o = cur.span(8);
        let offset = cur.u64().await?;
        let s = cur.span(8);
        let size = cur.u64().await?;
        let fspan = cur.span(4);
        let flags = cur.u32().await?;
        let (path, pspan) = cur.cstr(4096).await?;
        let state = (o, offset, s, size, fspan, flags, pspan, path.clone());
        cx.push(
            Node::new(path)
                .span(cur.since(start))
                .summary(format!("offset {offset:#x}, {size} bytes"))
                .lazy(directory_entry, state),
        )
        .await;
    }
    Ok(())
}

type DirState = (Span, u64, Span, u64, Span, u32, Span, String);

async fn directory_entry(
    cx: Cx,
    (o, offset, s, size, fspan, flags, pspan, path): DirState,
) -> Result<()> {
    cx.emit(Node::new("Offset").span(o).value(Value::UInt {
        value: offset,
        bits: 64,
        radix: Radix::Hex,
    }));
    cx.emit(Node::new("Size").span(s).value(uint(size, 64)));
    let (set, unknown) = crate::value::decode_flags(NODE_FLAGS, flags.into());
    cx.emit(Node::new("Flags").span(fspan).value(Value::Flags {
        raw: flags.into(),
        bits: 32,
        set,
        unknown,
    }));
    cx.emit(Node::new("Path").span(pspan).value(Value::Text(path)));
    Ok(())
}

struct WebHeader {
    header_size: u32,
    last: (u32, u32),
}

fn web_header(f: &mut Fields<'_>, &version: &u32) -> Result<WebHeader> {
    if version >= 4 {
        f.bytes("Hash", 16).emit()?;
        f.u32("CRC").hex().emit()?;
    }
    f.u32("Minimum streamed bytes").emit()?;
    let header_size = f.u32("Header size").emit()?;
    f.u32("Levels to download before streaming").emit()?;
    let levels = f.u32("Level count").emit()?;
    let mut last = (0, 0);
    for _ in 0..levels {
        if f.remaining() < 8 {
            break;
        }
        let c = f.u32("Level end (compressed)").emit()?;
        let u = f.u32("Level end (uncompressed)").emit()?;
        last = (c, u);
    }
    if version >= 2 {
        f.u32("Complete file size").emit()?;
    }
    if version >= 3 {
        f.u32("File info header size").emit()?;
    }
    Ok(WebHeader { header_size, last })
}

/// `UnityWeb` / `UnityRaw` formats 1–3.
async fn web_bundle(
    cx: &Cx,
    input: Input,
    cur: &mut Cursor<'_>,
    lzma: bool,
    version: u32,
) -> Result<String> {
    let file = input.span;
    let start = cur.pos();
    let block = cx.block(file.sub(start, 4096)).await?;
    let mut f = Fields::new(&block, BE);
    let header = web_header(&mut f, &version)?;
    let hspan = file.sub(start, f.pos());
    cx.emit(struct_node("Bundle header", hspan, BE, version, web_header));
    let data = file.tail(header.header_size.into());
    let (compressed, size) = header.last;
    let stream = if lzma {
        let span = data.sub(0, compressed.into());
        cx.emit(
            Node::new("Data")
                .span(span)
                .summary(format!("LZMA, {compressed} → {size} bytes")),
        );
        cx.decode_lazy(span, &Codec::LzmaAlone, size.into())?
    } else {
        cx.emit(
            Node::new("Data")
                .span(data)
                .summary(format!("{} bytes", data.len)),
        );
        data
    };
    let mut dir = Cursor::new(cx, stream, BE);
    let n = dir.u32().await?;
    cx.set_count(Count::AtLeast(n.into()));
    let mut files = 0u32;
    for _ in 0..n {
        let (path, _) = dir.cstr(4096).await?;
        let offset = dir.u32().await?;
        let size = dir.u32().await?;
        files = files.saturating_add(1);
        push_entry(cx, input, stream, offset.into(), size.into(), false, &path).await;
    }
    Ok(format!(
        ", {}, {files} files",
        if lzma { "LZMA" } else { "uncompressed" }
    ))
}

// ---------------------------------------------------------------------------
// Serialized files

declare_format!(pub UNITY_SERIALIZED = "unity-serialized", "Unity serialized file", ["assets", "sharedassets", "resource"], "application/x-unity-serialized",
    Probe::Custom(serialized_probe), serialized);

/// A plausible Unity version string (`2022.3.10f1`, `5.6.7p1`, `0.0.0`).
fn version_string(data: &[u8]) -> bool {
    let Some(end) = data.iter().take(32).position(|&b| b == 0) else {
        return false;
    };
    let s = data.get(..end).unwrap_or_default();
    s.first().is_some_and(u8::is_ascii_digit)
        && s.contains(&b'.')
        && s.iter().all(|b| b.is_ascii_alphanumeric() || *b == b'.')
}

fn serialized_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let Some(version) = u32_be(d, 8) else {
        return false;
    };
    let reserved_ok = d.get(16..20).is_some_and(|r| matches!(r, [0 | 1, 0, 0, 0]));
    if !reserved_ok {
        return false;
    }
    let (meta, size, data, header) = match version {
        9..=21 => (
            u64::from(u32_be(d, 0).unwrap_or(0)),
            u64::from(u32_be(d, 4).unwrap_or(0)),
            u64::from(u32_be(d, 12).unwrap_or(0)),
            20u64,
        ),
        22 | 23 => {
            if d.get(0..8) != Some(&[0; 8]) {
                return false;
            }
            (
                u64::from(u32_be(d, 20).unwrap_or(0)),
                u64_be(d, 24).unwrap_or(0),
                u64_be(d, 32).unwrap_or(0),
                48,
            )
        }
        _ => return false,
    };
    meta > 0
        && data >= header.saturating_add(meta)
        && size >= data
        && d.get(to_usize(header)..).is_some_and(version_string)
}

const PLATFORMS: EnumTable = &[
    (1, "DashboardWidget"),
    (2, "StandaloneOSX"),
    (3, "StandaloneOSXPPC"),
    (4, "StandaloneOSXIntel"),
    (5, "StandaloneWindows"),
    (6, "WebPlayer"),
    (7, "WebPlayerStreamed"),
    (8, "Wii"),
    (9, "iOS"),
    (10, "PS3"),
    (11, "XBOX360"),
    (13, "Android"),
    (14, "StandaloneGLESEmu"),
    (16, "NaCl"),
    (17, "StandaloneLinux"),
    (18, "FlashPlayer"),
    (19, "StandaloneWindows64"),
    (20, "WebGL"),
    (21, "WSAPlayer"),
    (24, "StandaloneLinux64"),
    (25, "StandaloneLinuxUniversal"),
    (26, "WP8Player"),
    (27, "StandaloneOSXIntel64"),
    (28, "BlackBerry"),
    (29, "Tizen"),
    (30, "PSP2"),
    (31, "PS4"),
    (32, "PSM"),
    (33, "XboxOne"),
    (34, "SamsungTV"),
    (35, "N3DS"),
    (36, "WiiU"),
    (37, "tvOS"),
    (38, "Switch"),
    (0xffff_fffe, "NoTarget"),
];

const ENDIANNESS: EnumTable = &[(0, "little-endian"), (1, "big-endian")];

/// Where a type's tree is and how it is encoded.
#[derive(Clone, Copy)]
enum TreeAt {
    /// Node table and string buffer (versions 10 and 12+).
    Blob(Span),
    /// Recursive records (versions 9 and 11).
    Records(Span),
}

#[derive(Clone)]
struct TypeEntry {
    span: Span,
    class_id: i32,
    tree: Option<TreeAt>,
    /// `Namespace.Class` of a reference type.
    ref_name: Option<String>,
}

/// What object expansions need of a serialized file.
struct Sf {
    input: Input,
    version: u32,
    endian: Endian,
    data_offset: u64,
    big_ids: bool,
    /// Types carry type trees (always before version 13).
    trees: bool,
    types: Vec<TypeEntry>,
}

fn sf_header(f: &mut Fields<'_>, &wide: &bool) -> Result<(u64, u32, u64, Endian)> {
    let (m, s, d) = if wide {
        (
            "Metadata size (legacy, 0)",
            "File size (legacy, 0)",
            "Data offset (legacy, 0)",
        )
    } else {
        ("Metadata size", "File size", "Data offset")
    };
    let meta = f.u32(m).emit()?;
    let size = f.u32(s).emit()?;
    let version = f.u32("Version").emit()?;
    let data = f.u32(d).hex().emit()?;
    let endian = f.u8("Endianness").enumeration(ENDIANNESS).emit()?;
    f.bytes("Reserved", 3).emit()?;
    let endian = if endian == 0 {
        Endian::Little
    } else {
        Endian::Big
    };
    if version >= 22 {
        f.u32("Metadata size").emit()?;
        f.u64("File size").emit()?;
        let data = f.u64("Data offset").hex().emit()?;
        f.u64("Unknown").hex().emit()?;
        return Ok((data, version, 0, endian));
    }
    let _ = (meta, size);
    Ok((data.into(), version, 0, endian))
}

async fn serialized(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 12)).await?;
    let version = u32_be(&head, 8).unwrap_or(0);
    let hspan = file.sub(0, if version >= 22 { 48 } else { 20 });
    let block = cx.block(hspan).await?;
    let wide = version >= 22;
    let (data_offset, version, _, endian) = sf_header(&mut Fields::new(&block, BE), &wide)?;
    cx.emit(struct_node("Header", hspan, BE, wide, sf_header));
    if !(9..=23).contains(&version) {
        return Err(
            Diagnostic::unsupported(format!("serialized file version {version}")).at(hspan),
        );
    }
    let mut cur = Cursor::new(&cx, file, endian);
    cur.seek(hspan.len);
    let mut unity = String::new();
    if version >= 7 {
        let (v, span) = cur.cstr(256).await?;
        cx.emit(
            Node::new("Unity version")
                .span(span)
                .value(Value::Text(v.clone())),
        );
        unity = v;
    }
    cx.annotate(format!("Unity {unity} serialized file v{version}"));
    let mut platform = None;
    if version >= 8 {
        let span = cur.span(4);
        let p = cur.u32().await?;
        let name = lookup(PLATFORMS, p.into());
        platform = name;
        cx.emit(Node::new("Target platform").span(span).value(Value::Enum {
            raw: p.into(),
            bits: 32,
            name,
        }));
    }
    let mut trees = true;
    if version >= 13 {
        let span = cur.span(1);
        trees = cur.u8().await? != 0;
        cx.emit(
            Node::new("Type trees")
                .span(span)
                .value(Value::Bool(trees))
                .desc("Whether each type carries its type tree"),
        );
    }
    let start = cur.pos();
    let n = cur.int::<i32>().await?;
    let mut types = Vec::new();
    for _ in 0..n.max(0) {
        types.push(read_type(&cx, &mut cur, endian, version, trees, false, false).await?);
    }
    let tspan = cur.since(start);
    let mut big_ids = false;
    let mut big_node = None;
    if (7..14).contains(&version) {
        let span = cur.span(4);
        big_ids = cur.int::<i32>().await? != 0;
        big_node = Some(Node::new("Big IDs").span(span).value(Value::Bool(big_ids)));
    }
    let sf = Arc::new(Sf {
        input,
        version,
        endian,
        data_offset,
        big_ids,
        trees,
        types,
    });
    let type_count = sf.types.len();
    cx.emit(
        Node::new("Types")
            .span(tspan)
            .summary(format!("{type_count} types"))
            .lazy(type_list, (sf.clone(), start, false)),
    );
    if let Some(node) = big_node {
        cx.emit(node);
    }

    // Objects: fixed-size records, so the list pages by index.
    let ospan = cur.span(4);
    let count = u64::from(cur.u32().await?);
    if version >= 14 {
        cur.seek(align(cur.pos(), 4));
    }
    let at = cur.pos();
    let stride = object_stride(version, big_ids);
    let table = file.sub(at, count.saturating_mul(stride));
    let mut objects = Node::new("Objects")
        .span(file.sub(
            ospan.offset.saturating_sub(file.offset),
            table.end().saturating_sub(ospan.offset),
        ))
        .summary(format!("{count} objects"));
    let fits = table.len >= count.saturating_mul(stride);
    if !fits {
        objects = objects.diag(Diagnostic::truncated(
            file.sub(at, count.saturating_mul(stride)),
            table.len,
        ));
    }
    let listed = table.len.checked_div(stride).unwrap_or(0).min(count);
    cx.emit(objects.lazy(object_list, (sf.clone(), at, listed)));
    if !fits {
        return Ok(());
    }
    cur.seek(at.saturating_add(table.len));

    if version >= 11 {
        let start = cur.pos();
        let n = u64::from(cur.u32().await?);
        // Entries are 8 bytes (an index and a 32-bit ID) or, from version 14,
        // an index and an aligned 64-bit ID.
        let mut end = cur.pos();
        if n > 0 {
            if version >= 14 {
                end = align(end.saturating_add(4), 4).saturating_add(8);
                end = end.saturating_add(n.saturating_sub(1).saturating_mul(12));
            } else {
                end = end.saturating_add(n.saturating_mul(8));
            }
        }
        let span = file.sub_exact(start, end.saturating_sub(start))?;
        cx.emit(
            Node::new("Script types")
                .span(span)
                .summary(format!("{n} scripts"))
                .lazy(script_list, (sf.clone(), start)),
        );
        cur.seek(end);
    }

    let start = cur.pos();
    let n = cur.u32().await?;
    for _ in 0..n {
        external(&mut cur, version).await?;
    }
    cx.emit(
        Node::new("Externals")
            .span(cur.since(start))
            .summary(format!("{n} files"))
            .lazy(external_list, (sf.clone(), start)),
    );

    if version >= 20 {
        let start = cur.pos();
        let n = cur.int::<i32>().await?;
        for _ in 0..n.max(0) {
            read_type(&cx, &mut cur, endian, version, trees, true, false).await?;
        }
        cx.emit(
            Node::new("Reference types")
                .span(cur.since(start))
                .summary(format!("{n} types"))
                .lazy(type_list, (sf.clone(), start, true)),
        );
    }
    if version >= 5 {
        let (info, span) = cur.cstr(4096).await?;
        cx.emit(
            Node::new("User information")
                .span(span)
                .value(Value::Text(info)),
        );
    }
    let data = file.tail(data_offset);
    cx.emit(
        Node::new("Object data")
            .span(data)
            .summary(format!("{} bytes", data.len)),
    );
    cx.annotate(format!(
        "Unity {unity} serialized file v{version}{}, {count} objects, {type_count} types",
        platform.map_or(String::new(), |p| format!(", {p}"))
    ));
    Ok(())
}

fn object_stride(version: u32, big_ids: bool) -> u64 {
    match version {
        22.. => 24,
        17..=21 => 20,
        16 => 24,
        15 => 28,
        14 => 24,
        _ if big_ids => 24,
        _ => 20,
    }
}

/// One entry of the type table (or the reference type table). Emits its
/// fields as it reads them when `emit` is set.
async fn read_type(
    cx: &Cx,
    cur: &mut Cursor<'_>,
    endian: Endian,
    version: u32,
    trees: bool,
    is_ref: bool,
    emit: bool,
) -> Result<TypeEntry> {
    let start = cur.pos();
    let show = |node: Node| {
        if emit {
            cx.emit(node);
        }
    };
    let span = cur.span(4);
    let class_id = cur.int::<i32>().await?;
    show(
        Node::new("Class ID").span(span).value(Value::Enum {
            raw: u64::from(class_id as u32),
            bits: 32,
            name: u64::try_from(class_id)
                .ok()
                .and_then(|c| lookup(CLASSES, c)),
        }),
    );
    if version >= 16 {
        let span = cur.span(1);
        let stripped = cur.u8().await?;
        show(
            Node::new("Stripped")
                .span(span)
                .value(Value::Bool(stripped != 0)),
        );
    }
    let mut script = -1i16;
    if version >= 17 {
        let span = cur.span(2);
        script = cur.int::<i16>().await?;
        show(Node::new("Script type index").span(span).value(Value::Int {
            value: script.into(),
            bits: 16,
        }));
    }
    if version >= 13 {
        if (is_ref && script >= 0)
            || (version < 16 && class_id < 0)
            || (version >= 16 && class_id == 114)
        {
            let span = cur.span(16);
            let id = cur.bytes(16).await?;
            show(Node::new("Script ID").span(span).value(Value::Bytes(id)));
        }
        let span = cur.span(16);
        let hash = cur.bytes(16).await?;
        show(Node::new("Type hash").span(span).value(Value::Bytes(hash)));
    }
    let mut tree = None;
    let mut ref_name = None;
    if trees {
        let mut size = None;
        if version >= 23 {
            let span = cur.span(16);
            let hash = cur.bytes(16).await?;
            show(
                Node::new("Type tree hash")
                    .span(span)
                    .value(Value::Bytes(hash)),
            );
            let span = cur.span(4);
            let n = cur.int::<i32>().await?;
            show(Node::new("Type tree size").span(span).value(Value::Int {
                value: n.into(),
                bits: 32,
            }));
            size = Some(n);
        }
        if version >= 12 || version == 10 {
            if size != Some(0) {
                let bstart = cur.pos();
                if version >= 23 {
                    cur.skip(8); // "mhtt", format version
                }
                let nodes = u64::from(cur.u32().await?);
                let strings = u64::from(cur.u32().await?);
                let len = nodes
                    .saturating_mul(if version >= 19 { 32 } else { 24 })
                    .saturating_add(strings);
                cur.region().sub_exact(cur.pos(), len)?;
                cur.skip(len);
                tree = Some(TreeAt::Blob(cur.since(bstart)));
            }
        } else {
            let bstart = cur.pos();
            skip_records(cur, version).await?;
            tree = Some(TreeAt::Records(cur.since(bstart)));
        }
        if let Some(at) = tree {
            let span = match at {
                TreeAt::Blob(s) | TreeAt::Records(s) => s,
            };
            show(
                Node::new("Type tree")
                    .span(span)
                    .lazy(tree_root, (at, endian, version)),
            );
        }
        if version >= 21 {
            if is_ref {
                let (class, s1) = cur.cstr(1024).await?;
                show(
                    Node::new("Class name")
                        .span(s1)
                        .value(Value::Text(class.clone())),
                );
                let (ns, s2) = cur.cstr(1024).await?;
                show(
                    Node::new("Namespace")
                        .span(s2)
                        .value(Value::Text(ns.clone())),
                );
                let (asm, s3) = cur.cstr(1024).await?;
                show(Node::new("Assembly").span(s3).value(Value::Text(asm)));
                ref_name = Some(if ns.is_empty() {
                    class
                } else {
                    format!("{ns}.{class}")
                });
            } else {
                let dstart = cur.pos();
                let n = u64::from(cur.u32().await?);
                let len = n.saturating_mul(4);
                cur.region().sub_exact(cur.pos(), len)?;
                cur.skip(len);
                show(
                    Node::new("Type dependencies")
                        .span(cur.since(dstart))
                        .summary(format!("{n} types")),
                );
            }
        }
    }
    Ok(TypeEntry {
        span: cur.since(start),
        class_id,
        tree,
        ref_name,
    })
}

/// Skips a recursive (pre-version-12) type tree.
async fn skip_records(cur: &mut Cursor<'_>, version: u32) -> Result<()> {
    let mut pending = 1u64;
    while pending > 0 {
        pending = pending.saturating_sub(1);
        let children = old_node(cur, version).await?.children;
        pending = pending.saturating_add(children);
        if pending > cur.remaining() {
            return Err(
                Diagnostic::malformed("type tree has more nodes than bytes").at(cur.span(0))
            );
        }
    }
    Ok(())
}

struct OldNode {
    ty: String,
    name: String,
    size: i32,
    index: i32,
    flags: u32,
    version: i32,
    meta: u32,
    children: u64,
}

async fn old_node(cur: &mut Cursor<'_>, version: u32) -> Result<OldNode> {
    let (ty, _) = cur.cstr(1024).await?;
    let (name, _) = cur.cstr(1024).await?;
    let size = cur.int::<i32>().await?;
    if version == 2 {
        cur.skip(4); // variable count
    }
    let index = if version != 3 {
        cur.int::<i32>().await?
    } else {
        -1
    };
    let flags = cur.u32().await?;
    let node_version = cur.int::<i32>().await?;
    let meta = if version != 3 { cur.u32().await? } else { 0 };
    let children = u64::from(cur.u32().await?);
    Ok(OldNode {
        ty,
        name,
        size,
        index,
        flags,
        version: node_version,
        meta,
        children,
    })
}

// ---------------------------------------------------------------------------
// Type trees

const ALIGN: u32 = 0x4000;
const MAX_DEPTH: u32 = 64;

struct TNode {
    ty: String,
    name: String,
    level: u32,
    flags: u32,
    size: i32,
    index: i32,
    version: i32,
    meta: u32,
    span: Span,
    children: Vec<usize>,
}

struct Tree {
    nodes: Vec<TNode>,
}

impl Tree {
    fn get(&self, i: usize) -> Option<&TNode> {
        self.nodes.get(i)
    }

    fn child(&self, i: usize, n: usize) -> Option<usize> {
        self.get(i).and_then(|t| t.children.get(n).copied())
    }

    /// Links nodes to their parents by level (preorder).
    fn link(mut nodes: Vec<TNode>) -> Tree {
        let mut stack: Vec<usize> = Vec::new();
        for i in 0..nodes.len() {
            let level = nodes.get(i).map_or(0, |n| n.level);
            while stack
                .last()
                .and_then(|&p| nodes.get(p))
                .is_some_and(|p| p.level >= level)
            {
                stack.pop();
            }
            if let Some(parent) = stack.last().and_then(|&p| nodes.get_mut(p)) {
                parent.children.push(i);
            } else if i > 0 {
                // A second root: ignore it (and what hangs below it).
                continue;
            }
            stack.push(i);
        }
        Tree { nodes }
    }
}

/// Unity's built-in string table (type and field names shared by all type
/// trees), addressed by offset with the high bit set.
const COMMON_STRINGS: &str = "AABB\0AnimationClip\0AnimationCurve\0AnimationState\0Array\0Base\0BitField\0bitset\0bool\0char\0ColorRGBA\0Component\0data\0deque\0double\0dynamic_array\0FastPropertyName\0first\0float\0Font\0GameObject\0Generic Mono\0GradientNEW\0GUID\0GUIStyle\0int\0list\0long long\0map\0Matrix4x4f\0MdFour\0MonoBehaviour\0MonoScript\0m_ByteSize\0m_Curve\0m_EditorClassIdentifier\0m_EditorHideFlags\0m_Enabled\0m_ExtensionPtr\0m_GameObject\0m_Index\0m_IsArray\0m_IsStatic\0m_MetaFlag\0m_Name\0m_ObjectHideFlags\0m_PrefabInternal\0m_PrefabParentObject\0m_Script\0m_StaticEditorFlags\0m_Type\0m_Version\0Object\0pair\0PPtr<Component>\0PPtr<GameObject>\0PPtr<Material>\0PPtr<MonoBehaviour>\0PPtr<MonoScript>\0PPtr<Object>\0PPtr<Prefab>\0PPtr<Sprite>\0PPtr<TextAsset>\0PPtr<Texture>\0PPtr<Texture2D>\0PPtr<Transform>\0Prefab\0Quaternionf\0Rectf\0RectInt\0RectOffset\0second\0set\0short\0size\0SInt16\0SInt32\0SInt64\0SInt8\0staticvector\0string\0TextAsset\0TextMesh\0Texture\0Texture2D\0Transform\0TypelessData\0UInt16\0UInt32\0UInt64\0UInt8\0unsigned int\0unsigned long long\0unsigned short\0vector\0Vector2f\0Vector3f\0Vector4f\0m_ScriptingClassIdentifier\0Gradient\0Type*\0int2_storage\0int3_storage\0BoundsInt\0m_CorrespondingSourceObject\0m_PrefabInstance\0m_PrefabAsset\0FileSize\0Hash128\0RenderingLayerMask\0fixed_array\0EntityId\0LoadableObjectId\0LoadableSceneId\0";

fn tree_string(local: &[u8], raw: u32) -> String {
    let (table, offset) = if raw & 0x8000_0000 != 0 {
        (COMMON_STRINGS.as_bytes(), raw & 0x7fff_ffff)
    } else {
        (local, raw)
    };
    match table.get(to_usize(offset.into())..) {
        Some(rest) => {
            let end = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
            String::from_utf8_lossy(rest.get(..end).unwrap_or_default()).into_owned()
        }
        None => format!("<string {raw:#x}>"),
    }
}

/// Parses (once per span) the type tree at `at`.
async fn load_tree(cx: &Cx, at: TreeAt, endian: Endian, version: u32) -> Result<Arc<Tree>> {
    let key = match at {
        TreeAt::Blob(s) | TreeAt::Records(s) => s,
    };
    if let Some(tree) = cx.cached::<Tree>(key, "unity-type-tree") {
        return Ok(tree);
    }
    let tree = Arc::new(match at {
        TreeAt::Blob(span) => blob_tree(cx, span, endian, version).await?,
        TreeAt::Records(span) => records_tree(cx, span, endian, version).await?,
    });
    cx.cache(key, "unity-type-tree", tree.clone());
    Ok(tree)
}

async fn blob_tree(cx: &Cx, span: Span, endian: Endian, version: u32) -> Result<Tree> {
    let data = cx.read(span).await?;
    let base = if version >= 23 { 8usize } else { 0 };
    let int = |at: usize| -> u32 {
        let b = data
            .get(at..at.saturating_add(4))
            .and_then(|b| <[u8; 4]>::try_from(b).ok())
            .unwrap_or_default();
        match endian {
            Endian::Little => u32::from_le_bytes(b),
            Endian::Big => u32::from_be_bytes(b),
        }
    };
    let count = to_usize(int(base).into());
    let strings = to_usize(int(base.saturating_add(4)).into());
    let size = if version >= 19 { 32usize } else { 24 };
    let table = base.saturating_add(8);
    let local_at = table.saturating_add(count.saturating_mul(size));
    let local = data
        .get(local_at..local_at.saturating_add(strings))
        .unwrap_or_default();
    let mut nodes = Vec::new();
    for i in 0..count {
        let at = table.saturating_add(i.saturating_mul(size));
        let Some(rec) = data.get(at..at.saturating_add(size)) else {
            break;
        };
        let u16v = match endian {
            Endian::Little => u16::from_le_bytes([
                rec.first().copied().unwrap_or(0),
                rec.get(1).copied().unwrap_or(0),
            ]),
            Endian::Big => u16::from_be_bytes([
                rec.first().copied().unwrap_or(0),
                rec.get(1).copied().unwrap_or(0),
            ]),
        };
        nodes.push(TNode {
            version: i32::from(u16v),
            level: rec.get(2).copied().unwrap_or(0).into(),
            flags: rec.get(3).copied().unwrap_or(0).into(),
            ty: tree_string(local, int(at.saturating_add(4))),
            name: tree_string(local, int(at.saturating_add(8))),
            size: int(at.saturating_add(12)) as i32,
            index: int(at.saturating_add(16)) as i32,
            meta: int(at.saturating_add(20)),
            span: span.sub(to_u64(at), to_u64(size)),
            children: Vec::new(),
        });
    }
    Ok(Tree::link(nodes))
}

async fn records_tree(cx: &Cx, span: Span, endian: Endian, version: u32) -> Result<Tree> {
    let mut cur = Cursor::new(cx, span, endian);
    let mut nodes = Vec::new();
    // Children still to read at each open level.
    let mut open: Vec<u64> = vec![1];
    while let Some(&left) = open.last() {
        if left == 0 {
            open.pop();
            continue;
        }
        if let Some(l) = open.last_mut() {
            *l = left.saturating_sub(1);
        }
        let level = to_u64(open.len()).saturating_sub(1);
        if level > MAX_DEPTH.into() {
            return Err(Diagnostic::limit("type tree nested too deeply").at(cur.span(0)));
        }
        let start = cur.pos();
        let n = old_node(&mut cur, version).await?;
        nodes.push(TNode {
            ty: n.ty,
            name: n.name,
            level: u32::try_from(level).unwrap_or(u32::MAX),
            flags: n.flags,
            size: n.size,
            index: n.index,
            version: n.version,
            meta: n.meta,
            span: cur.since(start),
            children: Vec::new(),
        });
        if n.children > cur.remaining() {
            return Err(
                Diagnostic::malformed("type tree has more nodes than bytes").at(cur.since(start))
            );
        }
        if n.children > 0 {
            open.push(n.children);
        }
    }
    Ok(Tree::link(nodes))
}

async fn tree_root(cx: Cx, (at, endian, version): (TreeAt, Endian, u32)) -> Result<()> {
    let tree = load_tree(&cx, at, endian, version).await?;
    if tree.get(0).is_some() {
        cx.emit(tree_node(&tree, 0));
    }
    Ok(())
}

fn tree_node(tree: &Arc<Tree>, i: usize) -> Node {
    let Some(n) = tree.get(i) else {
        return Node::new("?");
    };
    let mut notes = Vec::new();
    if n.size >= 0 {
        notes.push(format!("{} bytes", n.size));
    }
    if n.meta & ALIGN != 0 {
        notes.push("aligned".into());
    }
    if n.flags & 1 != 0 {
        notes.push("array".into());
    }
    let mut node = Node::new(n.name.clone())
        .span(n.span)
        .value(Value::Text(n.ty.clone()));
    if !notes.is_empty() {
        node = node.summary(notes.join(", "));
    }
    node = node.desc(format!(
        "index {}, version {}, meta flags {:#x}",
        n.index, n.version, n.meta
    ));
    if !n.children.is_empty() {
        node = node.lazy(tree_children, (tree.clone(), i));
    }
    node
}

async fn tree_children(cx: Cx, (tree, i): (Arc<Tree>, usize)) -> Result<()> {
    let children = tree.get(i).map(|n| n.children.clone()).unwrap_or_default();
    for c in children {
        cx.push(tree_node(&tree, c)).await;
    }
    Ok(())
}

async fn type_list(cx: Cx, (sf, start, is_ref): (Arc<Sf>, u64, bool)) -> Result<()> {
    let mut cur = Cursor::new(&cx, sf.input.span, sf.endian);
    cur.seek(start);
    let n = cur.int::<i32>().await?;
    cx.set_count(Count::Exact(u64::try_from(n).unwrap_or(0)));
    for i in 0..n.max(0) {
        let t = read_type(
            &cx, &mut cur, sf.endian, sf.version, sf.trees, is_ref, false,
        )
        .await?;
        let name = match (&t.ref_name, t.tree) {
            (Some(n), _) => n.clone(),
            (None, Some(at)) => match load_tree(&cx, at, sf.endian, sf.version).await {
                Ok(tree) => tree
                    .get(0)
                    .map_or_else(|| class_name(t.class_id), |r| r.ty.clone()),
                Err(_) => class_name(t.class_id),
            },
            (None, None) => class_name(t.class_id),
        };
        let at = t.span.offset.saturating_sub(sf.input.span.offset);
        cx.push(
            Node::new(name)
                .span(t.span)
                .summary(format!("type {i}, class ID {}", t.class_id))
                .lazy(type_detail, (sf.clone(), at, is_ref)),
        )
        .await;
    }
    Ok(())
}

async fn type_detail(cx: Cx, (sf, at, is_ref): (Arc<Sf>, u64, bool)) -> Result<()> {
    let mut cur = Cursor::new(&cx, sf.input.span, sf.endian);
    cur.seek(at);
    read_type(&cx, &mut cur, sf.endian, sf.version, sf.trees, is_ref, true).await?;
    Ok(())
}

/// The name of a well-known class ID.
fn class_name(class_id: i32) -> String {
    u64::try_from(class_id)
        .ok()
        .and_then(|c| lookup(CLASSES, c))
        .map_or_else(|| format!("class {class_id}"), str::to_owned)
}

struct ObjEntry {
    path_id: i64,
    start: u64,
    size: u32,
    type_id: i32,
    class_id: Option<u16>,
}

fn object_entry(f: &mut Fields<'_>, &(version, big_ids): &(u32, bool)) -> Result<ObjEntry> {
    let path_id = if version >= 14 || big_ids {
        f.int::<i64>("Path ID").emit()?
    } else {
        f.int::<i32>("Path ID").emit()?.into()
    };
    let start = if version >= 22 {
        f.u64("Data offset").hex().emit()?
    } else {
        f.u32("Data offset").hex().emit()?.into()
    };
    let size = f.u32("Size").emit()?;
    let type_id = f
        .int::<i32>(if version >= 16 {
            "Type index"
        } else {
            "Type ID"
        })
        .emit()?;
    let mut class_id = None;
    if version < 16 {
        class_id = Some(f.u16("Class ID").emit()?);
    }
    if version < 11 {
        f.u16("Destroyed").emit()?;
    }
    if (11..17).contains(&version) {
        f.int::<i16>("Script type index").emit()?;
    }
    if version == 15 || version == 16 {
        f.u8("Stripped").emit()?;
    }
    Ok(ObjEntry {
        path_id,
        start,
        size,
        type_id,
        class_id,
    })
}

impl Sf {
    /// The type of an object: by index from version 16, by class ID before.
    fn type_of(&self, e: &ObjEntry) -> Option<&TypeEntry> {
        if self.version >= 16 {
            usize::try_from(e.type_id)
                .ok()
                .and_then(|i| self.types.get(i))
        } else {
            self.types.iter().find(|t| t.class_id == e.type_id)
        }
    }
}

async fn object_list(cx: Cx, (sf, at, count): (Arc<Sf>, u64, u64)) -> Result<()> {
    let file = sf.input.span;
    let stride = object_stride(sf.version, sf.big_ids);
    cx.set_count(Count::Exact(count));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let here = i;
        cx.mark(move || here);
        let espan = file.sub(at.saturating_add(i.saturating_mul(stride)), stride);
        let block = cx.block(espan).await?;
        let e = object_entry(
            &mut Fields::new(&block, sf.endian),
            &(sf.version, sf.big_ids),
        )?;
        let data = file.sub(sf.data_offset.saturating_add(e.start), e.size.into());
        let ty = sf.type_of(&e).cloned();
        let class_id = ty
            .as_ref()
            .map_or_else(|| e.class_id.map_or(e.type_id, i32::from), |t| t.class_id);
        let mut class = class_name(class_id);
        let mut tree = None;
        if let Some(at) = ty.as_ref().and_then(|t| t.tree)
            && let Ok(t) = load_tree(&cx, at, sf.endian, sf.version).await
        {
            if let Some(root) = t.get(0) {
                class = root.ty.clone();
            }
            tree = Some(t);
        }
        let name = match &tree {
            Some(t) if !cx.skipping() => peek_name(&cx, t, data, sf.endian).await,
            _ => None,
        };
        let title = match name {
            Some(n) if !n.is_empty() => format!("{class} {n:?}"),
            _ => class,
        };
        let mut node = Node::new(title)
            .span(data)
            .summary(format!("path ID {}, {} bytes", e.path_id, e.size));
        if data.len < u64::from(e.size) {
            node = node.diag(Diagnostic::malformed(
                "object data runs past the end of the file",
            ));
        }
        cx.push(node.lazy(object, (sf.clone(), espan, data, tree)))
            .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn object(
    cx: Cx,
    (sf, espan, data, tree): (Arc<Sf>, Span, Span, Option<Arc<Tree>>),
) -> Result<()> {
    cx.emit(struct_node(
        "Object info",
        espan,
        sf.endian,
        (sf.version, sf.big_ids),
        object_entry,
    ));
    let Some(tree) = tree else {
        cx.emit(
            Node::new("Data")
                .span(data)
                .summary(format!("{} bytes", data.len))
                .diag(Diagnostic::note("no type tree: fields not decoded")),
        );
        return Ok(());
    };
    let st = Value_ {
        tree,
        input: sf.input,
        data,
        endian: sf.endian,
    };
    struct_fields(cx, (st, 0, 0, 0)).await
}

/// Reads `m_Name` if it is among the first fields of the root.
async fn peek_name(cx: &Cx, tree: &Arc<Tree>, data: Span, endian: Endian) -> Option<String> {
    let root = tree.get(0)?;
    let at = root
        .children
        .iter()
        .take(8)
        .position(|&c| tree.get(c).is_some_and(|n| n.name == "m_Name"))?;
    let mut cur = Cursor::new(cx, data, endian);
    for &c in root.children.get(..at)? {
        skip(&mut cur, tree, c, 1).await.ok()?;
    }
    let len = u64::try_from(cur.int::<i32>().await.ok()?).ok()?;
    let bytes = cur.peek(len.min(128)).await.ok()?;
    let mut s = String::from_utf8_lossy(&bytes).into_owned();
    if len > 128 {
        s.push('…');
    }
    Some(s)
}

// ---------------------------------------------------------------------------
// Values by type tree

#[derive(Clone)]
#[allow(non_camel_case_types)]
struct Value_ {
    tree: Arc<Tree>,
    input: Input,
    /// The object's data; positions (and alignment) are relative to it.
    data: Span,
    endian: Endian,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Int {
        size: u8,
        signed: bool,
    },
    Float(u8),
    Bool,
    Str,
    Bytes,
    /// `Hash128`: sixteen bytes.
    Hash,
    Vector,
    Struct,
    Unsupported,
}

fn kind(tree: &Tree, i: usize) -> Kind {
    let Some(n) = tree.get(i) else {
        return Kind::Unsupported;
    };
    match n.ty.as_str() {
        "SInt8" => Kind::Int {
            size: 1,
            signed: true,
        },
        "UInt8" | "char" => Kind::Int {
            size: 1,
            signed: false,
        },
        "short" | "SInt16" => Kind::Int {
            size: 2,
            signed: true,
        },
        "unsigned short" | "UInt16" => Kind::Int {
            size: 2,
            signed: false,
        },
        "int" | "SInt32" => Kind::Int {
            size: 4,
            signed: true,
        },
        "unsigned int" | "UInt32" | "Type*" => Kind::Int {
            size: 4,
            signed: false,
        },
        "long long" | "SInt64" => Kind::Int {
            size: 8,
            signed: true,
        },
        "unsigned long long" | "UInt64" | "FileSize" => Kind::Int {
            size: 8,
            signed: false,
        },
        "float" => Kind::Float(4),
        "double" => Kind::Float(8),
        "bool" => Kind::Bool,
        "string" => Kind::Str,
        "TypelessData" => Kind::Bytes,
        "Hash128" if n.children.len() == 16 => Kind::Hash,
        "ManagedReferencesRegistry" | "ReferencedObject" | "ReferencedObjectData" => {
            Kind::Unsupported
        }
        _ if tree
            .child(i, 0)
            .and_then(|c| tree.get(c))
            .is_some_and(|c| c.ty == "Array") =>
        {
            let elem = tree.child(i, 0).and_then(|a| tree.child(a, 1));
            match elem.map(|e| kind(tree, e)) {
                Some(Kind::Int { size: 1, .. })
                    if elem
                        .and_then(|e| tree.get(e))
                        .is_some_and(|e| e.meta & ALIGN == 0) =>
                {
                    Kind::Bytes
                }
                _ => Kind::Vector,
            }
        }
        _ => Kind::Struct,
    }
}

fn fixed_size(k: Kind) -> Option<u64> {
    match k {
        Kind::Int { size, .. } | Kind::Float(size) => Some(size.into()),
        Kind::Bool => Some(1),
        Kind::Hash => Some(16),
        _ => None,
    }
}

fn aligned(tree: &Tree, i: usize) -> bool {
    tree.get(i).is_some_and(|n| n.meta & ALIGN != 0)
}

/// Whether the vector at `i` aligns after its elements (its own flag or its
/// `Array` child's).
fn vector_aligned(tree: &Tree, i: usize) -> bool {
    aligned(tree, i) || tree.child(i, 0).is_some_and(|a| aligned(tree, a))
}

fn check_end(cur: &Cursor<'_>) -> Result<()> {
    if cur.pos() > cur.region().len {
        return Err(Diagnostic::truncated(
            cur.region().sub(0, cur.pos()),
            cur.region().len,
        ));
    }
    Ok(())
}

async fn length(cur: &mut Cursor<'_>) -> Result<u64> {
    let span = cur.span(4);
    let n = cur.int::<i32>().await?;
    let n = u64::try_from(n)
        .map_err(|_| Diagnostic::malformed(format!("negative length {n}")).at(span))?;
    if n > cur.remaining() {
        return Err(Diagnostic::malformed(format!("length {n} exceeds the object")).at(span));
    }
    Ok(n)
}

type SkipFuture<'a> = std::pin::Pin<Box<dyn std::future::Future<Output = Result<()>> + Send + 'a>>;

/// Advances past the value of node `i`.
fn skip<'a>(cur: &'a mut Cursor<'_>, tree: &'a Tree, i: usize, depth: u32) -> SkipFuture<'a> {
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("value nested too deeply").at(cur.span(0)));
        }
        let mut align_after = aligned(tree, i);
        match kind(tree, i) {
            Kind::Int { size, .. } | Kind::Float(size) => cur.skip(size.into()),
            Kind::Bool => cur.skip(1),
            Kind::Hash => cur.skip(16),
            Kind::Str => {
                let n = length(cur).await?;
                cur.skip(n);
                align_after = true;
            }
            Kind::Bytes => {
                let n = length(cur).await?;
                cur.skip(n);
                align_after |= vector_aligned(tree, i);
            }
            Kind::Vector => {
                align_after |= vector_aligned(tree, i);
                let n = length(cur).await?;
                let elem = tree.child(i, 0).and_then(|a| tree.child(a, 1));
                let Some(elem) = elem else {
                    return Err(
                        Diagnostic::malformed("vector without element type").at(cur.span(0))
                    );
                };
                match fixed_size(kind(tree, elem)) {
                    Some(size) if !aligned(tree, elem) => cur.skip(n.saturating_mul(size)),
                    _ => {
                        for _ in 0..n {
                            let before = cur.pos();
                            skip(cur, tree, elem, depth.saturating_add(1)).await?;
                            if cur.pos() == before {
                                break;
                            }
                            check_end(cur)?;
                        }
                    }
                }
            }
            Kind::Struct => {
                let children = tree
                    .get(i)
                    .map(|n| n.children.as_slice())
                    .unwrap_or_default();
                for &c in children {
                    skip(cur, tree, c, depth.saturating_add(1)).await?;
                }
            }
            Kind::Unsupported => {
                let ty = tree.get(i).map(|n| n.ty.clone()).unwrap_or_default();
                return Err(Diagnostic::unsupported(format!("{ty} values")).at(cur.span(0)));
            }
        }
        if align_after {
            cur.seek(align(cur.pos(), 4));
        }
        check_end(cur)
    })
}

/// A primitive's value and a short text for summaries.
async fn primitive(cur: &mut Cursor<'_>, k: Kind) -> Result<(Value, String)> {
    Ok(match k {
        Kind::Int { size, signed } => {
            let (v, raw) = match (size, signed) {
                (1, true) => {
                    let v = cur.int::<i8>().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (1, false) => {
                    let v = cur.u8().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (2, true) => {
                    let v = cur.int::<i16>().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (2, false) => {
                    let v = cur.u16().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (4, true) => {
                    let v = cur.int::<i32>().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (4, false) => {
                    let v = cur.u32().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (_, true) => {
                    let v = cur.int::<i64>().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
                (_, false) => {
                    let v = cur.u64().await?;
                    (v.value(Radix::Dec), v.to_string())
                }
            };
            (v, raw)
        }
        Kind::Float(4) => {
            let v = cur.int::<f32>().await?;
            (Value::Float(v.into()), v.to_string())
        }
        Kind::Float(_) => {
            let v = cur.int::<f64>().await?;
            (Value::Float(v), v.to_string())
        }
        _ => {
            let v = cur.u8().await? != 0;
            (Value::Bool(v), v.to_string())
        }
    })
}

/// The fields of the struct at node `i`, whose value starts at `pos`.
async fn struct_fields(cx: Cx, (st, i, pos, depth): (Value_, usize, u64, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, st.data, st.endian);
    cur.seek(pos);
    let children = st
        .tree
        .get(i)
        .map(|n| n.children.clone())
        .unwrap_or_default();
    for c in children {
        let name = st.tree.get(c).map(|n| n.name.clone()).unwrap_or_default();
        let node = value_node(&cx, &st, &mut cur, c, name, depth).await?;
        cx.push(node).await;
    }
    Ok(())
}

/// The elements of the vector at node `i`, whose value starts at `pos`.
async fn vector_items(cx: Cx, (st, i, pos, depth): (Value_, usize, u64, u32)) -> Result<()> {
    let mut cur = Cursor::new(&cx, st.data, st.endian);
    cur.seek(pos);
    let n = length(&mut cur).await?;
    cx.set_count(Count::Exact(n));
    let Some(elem) = st.tree.child(i, 0).and_then(|a| st.tree.child(a, 1)) else {
        return Ok(());
    };
    let (at, mut index) = cx.resume::<(u64, u64)>().unwrap_or((cur.pos(), 0));
    cur.seek(at);
    while index < n {
        let state = (cur.pos(), index);
        cx.mark(move || state);
        let before = cur.pos();
        let node = value_node(&cx, &st, &mut cur, elem, format!("[{index}]"), depth).await?;
        cx.push(node).await;
        if cur.pos() == before {
            break;
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

type NodeFuture<'a> =
    std::pin::Pin<Box<dyn std::future::Future<Output = Result<Node>> + Send + 'a>>;

/// Reads the value of node `i` at the cursor into a node named `name`.
/// (Boxed: its lazy children refer back to it.)
fn value_node<'a>(
    cx: &'a Cx,
    st: &'a Value_,
    cur: &'a mut Cursor<'_>,
    i: usize,
    name: String,
    depth: u32,
) -> NodeFuture<'a> {
    Box::pin(value_node_inner(cx, st, cur, i, name, depth))
}

async fn value_node_inner(
    cx: &Cx,
    st: &Value_,
    cur: &mut Cursor<'_>,
    i: usize,
    name: String,
    depth: u32,
) -> Result<Node> {
    let tree = &*st.tree;
    let ty = tree.get(i).map(|n| n.ty.clone()).unwrap_or_default();
    let start = cur.pos();
    let k = kind(tree, i);
    let node = match k {
        Kind::Int { .. } | Kind::Float(_) | Kind::Bool => {
            let (v, _) = primitive(cur, k).await?;
            if aligned(tree, i) {
                cur.seek(align(cur.pos(), 4));
            }
            Node::new(name)
                .span(st.data.sub(start, cur.pos().saturating_sub(start)))
                .value(v)
        }
        Kind::Hash => {
            let bytes = cur.bytes(16).await?;
            if aligned(tree, i) {
                cur.seek(align(cur.pos(), 4));
            }
            Node::new(name)
                .span(st.data.sub(start, cur.pos().saturating_sub(start)))
                .value(Value::Bytes(bytes))
        }
        Kind::Str | Kind::Bytes => {
            let n = length(cur).await?;
            let body = st.data.sub(cur.pos(), n);
            cur.skip(n);
            if k == Kind::Str || vector_aligned(tree, i) {
                cur.seek(align(cur.pos(), 4));
            }
            check_end(cur)?;
            let span = st.data.sub(start, cur.pos().saturating_sub(start));
            if k == Kind::Str {
                let preview = cx.read(body.sub(0, 256)).await?;
                let binary = std::str::from_utf8(&preview)
                    .err()
                    .is_some_and(|e| e.error_len().is_some())
                    || preview.iter().any(|&b| b < 0x20 && !b"\t\n\r".contains(&b));
                let mut text = String::from_utf8_lossy(&preview).into_owned();
                if n > 256 {
                    text.push('…');
                }
                // Long or binary strings (TextAsset contents) are files of
                // their own.
                if n > 256 || binary {
                    embedded(name, st.input.nested(body))
                        .span(span)
                        .value(Value::Text(text))
                        .summary(format!("{n} bytes"))
                } else {
                    Node::new(name).span(span).value(Value::Text(text))
                }
            } else if n > 0 {
                embedded(name, st.input.nested(body))
                    .span(span)
                    .summary(format!("{n} bytes"))
            } else {
                Node::new(name).span(span).summary("empty")
            }
        }
        Kind::Vector => {
            let mut probe = Cursor::new(cx, st.data, st.endian);
            probe.seek(start);
            let n = length(&mut probe).await?;
            skip(cur, tree, i, depth).await?;
            let elem = tree
                .child(i, 0)
                .and_then(|a| tree.child(a, 1))
                .and_then(|e| tree.get(e))
                .map(|e| e.ty.clone())
                .unwrap_or_default();
            let mut node = Node::new(name)
                .span(st.data.sub(start, cur.pos().saturating_sub(start)))
                .summary(format!("{n} × {elem}"));
            if n > 0 {
                node = node.lazy(
                    vector_items,
                    (st.clone(), i, start, depth.saturating_add(1)),
                );
            }
            node
        }
        Kind::Struct => {
            let summary = small_summary(cx, st, start, i).await.unwrap_or(ty);
            skip(cur, tree, i, depth).await?;
            let mut node = Node::new(name)
                .span(st.data.sub(start, cur.pos().saturating_sub(start)))
                .summary(summary);
            if tree.get(i).is_some_and(|n| !n.children.is_empty()) {
                node = node.lazy(
                    struct_fields,
                    (st.clone(), i, start, depth.saturating_add(1)),
                );
            }
            node
        }
        Kind::Unsupported => {
            return Err(Diagnostic::unsupported(format!("{ty} values")).at(cur.span(0)));
        }
    };
    Ok(node)
}

/// `a: 1, b: 2` for a struct of at most four numbers and short strings
/// (vectors, colours, PPtrs).
async fn small_summary(cx: &Cx, st: &Value_, start: u64, i: usize) -> Option<String> {
    let tree = &*st.tree;
    let children = &tree.get(i)?.children;
    let pair = tree.get(i)?.ty == "pair";
    if children.is_empty() || children.len() > 4 {
        return None;
    }
    let mut cur = Cursor::new(cx, st.data, st.endian);
    cur.seek(start);
    let mut parts = Vec::new();
    for &c in children {
        let k = kind(tree, c);
        let text = match k {
            Kind::Int { .. } | Kind::Float(_) | Kind::Bool => primitive(&mut cur, k).await.ok()?.1,
            Kind::Str => {
                let n = length(&mut cur).await.ok()?;
                if n > 64 {
                    return None;
                }
                let b = cur.bytes(n).await.ok()?;
                format!("{:?}", String::from_utf8_lossy(&b))
            }
            _ if pair && !parts.is_empty() => {
                parts.push("…".into());
                break;
            }
            _ => return None,
        };
        if aligned(tree, c) || k == Kind::Str {
            cur.seek(align(cur.pos(), 4));
        }
        if pair {
            parts.push(text);
            continue;
        }
        let name = &tree.get(c)?.name;
        parts.push(format!("{name}: {text}"));
    }
    Some(parts.join(if pair { " → " } else { ", " }))
}

// ---------------------------------------------------------------------------
// Script types and externals

async fn script_list(cx: Cx, (sf, start): (Arc<Sf>, u64)) -> Result<()> {
    let mut cur = Cursor::new(&cx, sf.input.span, sf.endian);
    cur.seek(start);
    let n = cur.u32().await?;
    cx.set_count(Count::Exact(n.into()));
    for i in 0..n {
        let s = cur.pos();
        let file = cur.int::<i32>().await?;
        let id = if sf.version >= 14 {
            cur.seek(align(cur.pos(), 4));
            cur.int::<i64>().await?
        } else {
            cur.int::<i32>().await?.into()
        };
        cx.push(
            Node::new(format!("Script {i}"))
                .span(cur.since(s))
                .summary(format!("file {file}, path ID {id}")),
        )
        .await;
    }
    Ok(())
}

const EXTERNAL_TYPES: EnumTable = &[
    (0, "non-asset"),
    (1, "deprecated cached asset"),
    (2, "serialized asset"),
    (3, "meta asset"),
];

/// One external reference: (GUID, type, path, span).
async fn external(
    cur: &mut Cursor<'_>,
    version: u32,
) -> Result<(Option<Vec<u8>>, Option<u32>, String)> {
    if version >= 6 {
        cur.cstr(4096).await?;
    }
    let mut guid = None;
    let mut kind = None;
    if version >= 5 {
        guid = Some(cur.bytes(16).await?);
        kind = Some(cur.u32().await?);
    }
    let (path, _) = cur.cstr(4096).await?;
    Ok((guid, kind, path))
}

async fn external_list(cx: Cx, (sf, start): (Arc<Sf>, u64)) -> Result<()> {
    let mut cur = Cursor::new(&cx, sf.input.span, sf.endian);
    cur.seek(start);
    let n = cur.u32().await?;
    cx.set_count(Count::Exact(n.into()));
    for i in 0..n {
        let s = cur.pos();
        let (guid, kind, path) = external(&mut cur, sf.version).await?;
        let mut notes = Vec::new();
        if let Some(k) = kind {
            notes.push(
                lookup(EXTERNAL_TYPES, k.into()).map_or_else(|| format!("type {k}"), str::to_owned),
            );
        }
        if let Some(g) = guid.filter(|g| g.iter().any(|&b| b != 0)) {
            notes.push(format!(
                "GUID {}",
                g.iter().map(|b| format!("{b:02x}")).collect::<String>()
            ));
        }
        cx.push(
            Node::new(format!("File {}", i.saturating_add(1)))
                .span(cur.since(s))
                .value(Value::Text(path))
                .summary(notes.join(", ")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Class IDs (runtime classes and the common editor ones)

const CLASSES: EnumTable = &[
    (0, "Object"),
    (1, "GameObject"),
    (2, "Component"),
    (3, "LevelGameManager"),
    (4, "Transform"),
    (5, "TimeManager"),
    (6, "GlobalGameManager"),
    (8, "Behaviour"),
    (9, "GameManager"),
    (11, "AudioManager"),
    (12, "ParticleAnimator"),
    (13, "InputManager"),
    (15, "EllipsoidParticleEmitter"),
    (17, "Pipeline"),
    (18, "EditorExtension"),
    (19, "Physics2DSettings"),
    (20, "Camera"),
    (21, "Material"),
    (23, "MeshRenderer"),
    (25, "Renderer"),
    (26, "ParticleRenderer"),
    (27, "Texture"),
    (28, "Texture2D"),
    (29, "OcclusionCullingSettings"),
    (30, "GraphicsSettings"),
    (33, "MeshFilter"),
    (41, "OcclusionPortal"),
    (43, "Mesh"),
    (45, "Skybox"),
    (47, "QualitySettings"),
    (48, "Shader"),
    (49, "TextAsset"),
    (50, "Rigidbody2D"),
    (51, "Physics2DManager"),
    (53, "Collider2D"),
    (54, "Rigidbody"),
    (55, "PhysicsManager"),
    (56, "Collider"),
    (57, "Joint"),
    (58, "CircleCollider2D"),
    (59, "HingeJoint"),
    (60, "PolygonCollider2D"),
    (61, "BoxCollider2D"),
    (62, "PhysicsMaterial2D"),
    (64, "MeshCollider"),
    (65, "BoxCollider"),
    (66, "CompositeCollider2D"),
    (68, "EdgeCollider2D"),
    (70, "CapsuleCollider2D"),
    (72, "ComputeShader"),
    (74, "AnimationClip"),
    (75, "ConstantForce"),
    (76, "WorldParticleCollider"),
    (78, "TagManager"),
    (81, "AudioListener"),
    (82, "AudioSource"),
    (83, "AudioClip"),
    (84, "RenderTexture"),
    (86, "CustomRenderTexture"),
    (87, "MeshParticleEmitter"),
    (88, "ParticleEmitter"),
    (89, "Cubemap"),
    (90, "Avatar"),
    (91, "AnimatorController"),
    (92, "GUILayer"),
    (93, "RuntimeAnimatorController"),
    (94, "ScriptMapper"),
    (95, "Animator"),
    (96, "TrailRenderer"),
    (98, "DelayedCallManager"),
    (102, "TextMesh"),
    (104, "RenderSettings"),
    (108, "Light"),
    (109, "CGProgram"),
    (110, "BaseAnimationTrack"),
    (111, "Animation"),
    (114, "MonoBehaviour"),
    (115, "MonoScript"),
    (116, "MonoManager"),
    (117, "Texture3D"),
    (118, "NewAnimationTrack"),
    (119, "Projector"),
    (120, "LineRenderer"),
    (121, "Flare"),
    (122, "Halo"),
    (123, "LensFlare"),
    (124, "FlareLayer"),
    (125, "HaloLayer"),
    (126, "NavMeshProjectSettings"),
    (127, "HaloManager"),
    (128, "Font"),
    (129, "PlayerSettings"),
    (130, "NamedObject"),
    (131, "GUITexture"),
    (132, "GUIText"),
    (133, "GUIElement"),
    (134, "PhysicMaterial"),
    (135, "SphereCollider"),
    (136, "CapsuleCollider"),
    (137, "SkinnedMeshRenderer"),
    (138, "FixedJoint"),
    (140, "RaycastCollider"),
    (141, "BuildSettings"),
    (142, "AssetBundle"),
    (143, "CharacterController"),
    (144, "CharacterJoint"),
    (145, "SpringJoint"),
    (146, "WheelCollider"),
    (147, "ResourceManager"),
    (148, "NetworkView"),
    (149, "NetworkManager"),
    (150, "PreloadData"),
    (152, "MovieTexture"),
    (153, "ConfigurableJoint"),
    (154, "TerrainCollider"),
    (155, "MasterServerInterface"),
    (156, "TerrainData"),
    (157, "LightmapSettings"),
    (158, "WebCamTexture"),
    (159, "EditorSettings"),
    (160, "InteractiveCloth"),
    (161, "ClothRenderer"),
    (162, "EditorUserSettings"),
    (163, "SkinnedCloth"),
    (164, "AudioReverbFilter"),
    (165, "AudioHighPassFilter"),
    (166, "AudioChorusFilter"),
    (167, "AudioReverbZone"),
    (168, "AudioEchoFilter"),
    (169, "AudioLowPassFilter"),
    (170, "AudioDistortionFilter"),
    (171, "SparseTexture"),
    (180, "AudioBehaviour"),
    (181, "AudioFilter"),
    (182, "WindZone"),
    (183, "Cloth"),
    (184, "SubstanceArchive"),
    (185, "ProceduralMaterial"),
    (186, "ProceduralTexture"),
    (187, "Texture2DArray"),
    (188, "CubemapArray"),
    (191, "OffMeshLink"),
    (192, "OcclusionArea"),
    (193, "Tree"),
    (194, "NavMeshObsolete"),
    (195, "NavMeshAgent"),
    (196, "NavMeshSettings"),
    (197, "LightProbesLegacy"),
    (198, "ParticleSystem"),
    (199, "ParticleSystemRenderer"),
    (200, "ShaderVariantCollection"),
    (205, "LODGroup"),
    (206, "BlendTree"),
    (207, "Motion"),
    (208, "NavMeshObstacle"),
    (210, "SortingGroup"),
    (212, "SpriteRenderer"),
    (213, "Sprite"),
    (214, "CachedSpriteAtlas"),
    (215, "ReflectionProbe"),
    (216, "ReflectionProbes"),
    (218, "Terrain"),
    (220, "LightProbeGroup"),
    (221, "AnimatorOverrideController"),
    (222, "CanvasRenderer"),
    (223, "Canvas"),
    (224, "RectTransform"),
    (225, "CanvasGroup"),
    (226, "BillboardAsset"),
    (227, "BillboardRenderer"),
    (228, "SpeedTreeWindAsset"),
    (229, "AnchoredJoint2D"),
    (230, "Joint2D"),
    (231, "SpringJoint2D"),
    (232, "DistanceJoint2D"),
    (233, "HingeJoint2D"),
    (234, "SliderJoint2D"),
    (235, "WheelJoint2D"),
    (236, "ClusterInputManager"),
    (237, "BaseVideoTexture"),
    (238, "NavMeshData"),
    (240, "AudioMixer"),
    (241, "AudioMixerController"),
    (243, "AudioMixerGroupController"),
    (244, "AudioMixerEffectController"),
    (245, "AudioMixerSnapshotController"),
    (246, "PhysicsUpdateBehaviour2D"),
    (247, "ConstantForce2D"),
    (248, "Effector2D"),
    (249, "AreaEffector2D"),
    (250, "PointEffector2D"),
    (251, "PlatformEffector2D"),
    (252, "SurfaceEffector2D"),
    (253, "BuoyancyEffector2D"),
    (254, "RelativeJoint2D"),
    (255, "FixedJoint2D"),
    (256, "FrictionJoint2D"),
    (257, "TargetJoint2D"),
    (258, "LightProbes"),
    (259, "LightProbeProxyVolume"),
    (271, "SampleClip"),
    (272, "AudioMixerSnapshot"),
    (273, "AudioMixerGroup"),
    (280, "NScreenBridge"),
    (290, "AssetBundleManifest"),
    (292, "UnityAdsManager"),
    (300, "RuntimeInitializeOnLoadManager"),
    (301, "CloudWebServicesManager"),
    (303, "UnityAnalyticsManager"),
    (304, "CrashReportManager"),
    (305, "PerformanceReportingManager"),
    (310, "UnityConnectSettings"),
    (319, "AvatarMask"),
    (320, "PlayableDirector"),
    (328, "VideoPlayer"),
    (329, "VideoClip"),
    (330, "ParticleSystemForceField"),
    (331, "SpriteMask"),
    (362, "WorldAnchor"),
    (363, "OcclusionCullingData"),
    (1000, "SmallestEditorClassID"),
    (1001, "PrefabInstance"),
    (1002, "EditorExtensionImpl"),
    (1003, "AssetImporter"),
    (1004, "AssetDatabaseV1"),
    (1005, "Mesh3DSImporter"),
    (1006, "TextureImporter"),
    (1007, "ShaderImporter"),
    (1008, "ComputeShaderImporter"),
    (1020, "AudioImporter"),
    (1026, "HierarchyState"),
    (1027, "GUIDSerializer"),
    (1028, "AssetMetaData"),
    (1029, "DefaultAsset"),
    (1030, "DefaultImporter"),
    (1031, "TextScriptImporter"),
    (1032, "SceneAsset"),
    (1034, "NativeFormatImporter"),
    (1035, "MonoImporter"),
    (1037, "AssetServerCache"),
    (1038, "LibraryAssetImporter"),
    (1040, "ModelImporter"),
    (1041, "FBXImporter"),
    (1042, "TrueTypeFontImporter"),
    (1044, "MovieImporter"),
    (1045, "EditorBuildSettings"),
    (1046, "DDSImporter"),
    (1048, "InspectorExpandedState"),
    (1049, "AnnotationManager"),
    (1050, "PluginImporter"),
    (1051, "EditorUserBuildSettings"),
    (1052, "PVRImporter"),
    (1053, "ASTCImporter"),
    (1054, "KTXImporter"),
    (1055, "IHVImageFormatImporter"),
    (1101, "AnimatorStateTransition"),
    (1102, "AnimatorState"),
    (1105, "HumanTemplate"),
    (1107, "AnimatorStateMachine"),
    (1108, "PreviewAnimationClip"),
    (1109, "AnimatorTransition"),
    (1110, "SpeedTreeImporter"),
    (1111, "AnimatorTransitionBase"),
    (1112, "SubstanceImporter"),
    (1113, "LightmapParameters"),
    (1120, "LightingDataAsset"),
    (1121, "GISRaster"),
    (1122, "GISRasterImporter"),
    (1123, "CadImporter"),
    (1124, "SketchUpImporter"),
    (1125, "BuildReport"),
    (1126, "PackedAssets"),
    (1127, "VideoClipImporter"),
];
