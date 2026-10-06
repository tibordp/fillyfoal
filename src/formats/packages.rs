//! Engine packages and less common compression containers.

use crate::bytes::{u16_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Godot PCK

declare_format!(pub GODOT_PCK = "godot-pck", "Godot resource pack", ["pck"], "application/x-godot-pck",
    Probe::Magic(&[(0, b"GDPC")]), godot_pck);

async fn godot_pck(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let format = f.u32("Pack format version").emit()?;
    let major = f.u32("Godot major").emit()?;
    let minor = f.u32("Godot minor").emit()?;
    f.u32("Godot patch").emit()?;
    let mut at = 20u64;
    let mut base = 0u64;
    if format >= 2 {
        // Pack flags, then the offset files are relative to.
        let v2 = cx.read(file.sub(20, 12)).await?;
        base = u64_le(&v2, 4).unwrap_or(0);
        at = 32;
    }
    at = at.saturating_add(64); // reserved
    let count = u32_le(&cx.read(file.sub(at, 4)).await?, 0).unwrap_or(0);
    at = at.saturating_add(4);
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(at);
    cx.set_count(Count::AtLeast(count.into()));
    for _ in 0..count.min(1_000_000) {
        let start = cur.pos();
        let len = cur.u32().await?;
        let path = crate::text::until_nul(&cur.bytes(len.into()).await?);
        let offset = cur.u64().await?;
        let size = cur.u64().await?;
        cur.skip(16); // MD5
        if format >= 2 {
            cur.skip(4); // flags
        }
        let data = file.sub(base.saturating_add(offset), size);
        cx.push(
            embedded(path, input.nested(data))
                .summary(format!("{size} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("Godot {major}.{minor} pack, {count} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unity asset bundles (UnityFS)

declare_format!(pub UNITYFS = "unityfs", "Unity asset bundle", ["unity3d", "bundle", "assetbundle"], "application/x-unityfs",
    Probe::Magic(&[(0, b"UnityFS\0"), (0, b"UnityWeb\0"), (0, b"UnityRaw\0")]), unityfs);

const UNITY_COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "LZMA"),
    (2, "LZ4"),
    (3, "LZ4HC"),
    (4, "LZHAM"),
];

async fn unityfs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let (signature, s1) = cur.cstr(16).await?;
    let version = cur.u32().await?;
    let (player, s2) = cur.cstr(64).await?;
    let (engine, s3) = cur.cstr(64).await?;
    cx.emit(
        Node::new("Signature")
            .span(s1)
            .value(Value::Text(signature.clone())),
    );
    cx.emit(
        Node::new("Format version")
            .span(file.sub(s1.len, 4))
            .value(Value::UInt {
                value: version.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Player version")
            .span(s2)
            .value(Value::Text(player)),
    );
    cx.emit(
        Node::new("Engine version")
            .span(s3)
            .value(Value::Text(engine.clone())),
    );
    if signature == "UnityFS" {
        let start = cur.pos();
        let size = cur.u64().await?;
        let compressed = cur.u32().await?;
        let uncompressed = cur.u32().await?;
        let flags = cur.u32().await?;
        let scheme = flags & 0x3f;
        cx.emit(
            Node::new("Bundle header")
                .span(cur.since(start))
                .summary(format!(
                    "{size} bytes; blocks info {compressed} → {uncompressed} bytes, {}",
                    lookup(UNITY_COMPRESSION, scheme.into()).unwrap_or("unknown compression")
                )),
        );
        let rest = file.tail(cur.pos());
        let mut node = Node::new("Blocks and directory").span(rest);
        if scheme != 0 {
            node = node.diag(Diagnostic::unsupported(format!(
                "{} compression",
                lookup(UNITY_COMPRESSION, scheme.into()).unwrap_or("unknown")
            )));
        }
        cx.emit(node);
    }
    cx.annotate(format!("{signature} v{version}, Unity {engine}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// GameMaker data (IFF-like, little-endian lengths)

fn gamemaker_probe(h: &crate::formats::Head<'_>) -> bool {
    h.starts_with(b"FORM") && h.at(8, b"GEN8")
}

declare_format!(pub GAMEMAKER = "gamemaker", "GameMaker data file", ["win", "unx", "ios", "droid"], "application/x-gamemaker",
    Probe::Custom(gamemaker_probe), gamemaker);

async fn gamemaker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(8);
    let mut chunks = 0u32;
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let id = String::from_utf8_lossy(&cur.bytes(4).await?).into_owned();
        let len = cur.u32().await?;
        cur.skip(len.into());
        chunks = chunks.saturating_add(1);
        cx.push(
            Node::new(id)
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    let gen8 = cx.read_avail(file.sub(16, 0x40)).await?;
    let name_offset = u32_le(&gen8, 0x28).unwrap_or(0);
    let name = if name_offset > 0 {
        cx.cstr(file.sub(name_offset.into(), 128))
            .await
            .map(|(n, _)| n)
            .unwrap_or_default()
    } else {
        String::new()
    };
    cx.annotate(format!("GameMaker data {name:?}, {chunks} chunks"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Ren'Py archives (RPA)

declare_format!(pub RPA = "rpa", "Ren'Py archive", ["rpa", "rpi"], "application/x-renpy-archive",
    Probe::Magic(&[(0, b"RPA-3.0 "), (0, b"RPA-3.2 "), (0, b"RPA-2.0 ")]), rpa);

async fn rpa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let line = cx.read_avail(file.sub(0, 128)).await?;
    let end = line.iter().position(|&b| b == b'\n').unwrap_or(line.len());
    let text = String::from_utf8_lossy(line.get(..end).unwrap_or_default()).into_owned();
    let mut parts = text.split_whitespace();
    let version = parts.next().unwrap_or_default().to_owned();
    let offset = u64::from_str_radix(parts.next().unwrap_or("0"), 16).unwrap_or(0);
    let key = parts.next().map(str::to_owned);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, crate::bytes::to_u64(end).saturating_add(1)))
            .value(Value::Text(text.clone())),
    );
    // The index is a zlib-compressed Python pickle.
    let index = file.tail(offset);
    cx.emit(crate::formats::content(
        "Index (pickle)",
        input,
        index,
        crate::formats::Codec::Zlib,
        None,
    ));
    cx.annotate(format!(
        "{version}{}",
        key.map_or(String::new(), |k| format!(", key {k}"))
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Apple Archive, LZFSE, pbzx

declare_format!(pub APPLE_ARCHIVE = "apple-archive", "Apple Archive", ["aar", "yaa"], "application/x-apple-archive",
    Probe::Magic(&[(0, b"AA01"), (0, b"YAA1")]), apple_archive);

async fn apple_archive(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut entries = 0u32;
    while cur.remaining() >= 6 {
        let start = cur.pos();
        let magic = cur.bytes(4).await?;
        if magic != b"AA01" && magic != b"YAA1" {
            cx.diag(Diagnostic::malformed("expected an entry header").at(cur.since(start)));
            break;
        }
        let header_len = u64::from(cur.u16().await?);
        let fields = cx
            .read_avail(file.sub(start.saturating_add(6), header_len.saturating_sub(6)))
            .await?;
        // Fields are 3-letter keys plus a type letter; we pick out PAT and
        // the data size (DAT with a B-type size).
        let mut path = String::new();
        let mut data_len = 0u64;
        let mut at = 0usize;
        while at.saturating_add(4) <= fields.len() {
            let key = fields.get(at..at.saturating_add(3)).unwrap_or_default();
            let kind = fields.get(at.saturating_add(3)).copied().unwrap_or(0);
            at = at.saturating_add(4);
            let size = match kind {
                b'*' => 0,
                b'1' => 1,
                b'2' => 2,
                b'4' => 4,
                b'8' => 8,
                b'P' => {
                    usize::from(crate::bytes::u16_le(&fields, at).unwrap_or(0)).saturating_add(2)
                }
                b'A' => 2,
                b'B' => 4,
                b'C' => 8,
                b'F' => 4,
                b'G' => 8,
                b'H' => 12,
                b'S' => 8,
                b'T' => 12,
                _ => break,
            };
            if key == b"PAT" && kind == b'P' {
                let len = usize::from(crate::bytes::u16_le(&fields, at).unwrap_or(0));
                path = String::from_utf8_lossy(
                    fields
                        .get(at.saturating_add(2)..at.saturating_add(2).saturating_add(len))
                        .unwrap_or_default(),
                )
                .into_owned();
            }
            if key == b"DAT" {
                data_len = match kind {
                    b'A' => u64::from(crate::bytes::u16_le(&fields, at).unwrap_or(0)),
                    b'B' => u64::from(u32_le(&fields, at).unwrap_or(0)),
                    b'C' => u64_le(&fields, at).unwrap_or(0),
                    _ => 0,
                };
            }
            at = at.saturating_add(size);
        }
        cur.seek(start.saturating_add(header_len));
        let data = cur.span(data_len);
        cur.skip(data_len);
        entries = entries.saturating_add(1);
        let name = if path.is_empty() {
            "(root)".to_owned()
        } else {
            path
        };
        let node = if data_len > 0 {
            embedded(name, input.nested(data))
        } else {
            Node::new(name)
        };
        cx.push(
            node.summary(format!("{data_len} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("Apple Archive, {entries} entries"));
    Ok(())
}

declare_format!(pub LZFSE = "lzfse", "LZFSE compressed data", ["lzfse"], "application/x-lzfse",
    Probe::Magic(&[(0, b"bvx2"), (0, b"bvx1"), (0, b"bvxn"), (0, b"bvx-")]), lzfse);

async fn lzfse(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    let mut blocks = 0u32;
    let mut total = 0u64;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let magic = cur.bytes(4).await?;
        let (name, header, payload): (&str, u64, u64) = match magic.as_slice() {
            b"bvx$" => {
                cx.push(Node::new("End of stream").span(cur.since(start)))
                    .await;
                break;
            }
            b"bvx-" => {
                let raw = cur.u32().await?;
                total = total.saturating_add(raw.into());
                ("Uncompressed block", 8, raw.into())
            }
            b"bvxn" => {
                let raw = cur.u32().await?;
                let payload = cur.u32().await?;
                total = total.saturating_add(raw.into());
                ("LZVN block", 12, payload.into())
            }
            b"bvx1" => {
                let raw = cur.u32().await?;
                let header = cx.read_avail(file.sub(start, 36)).await?;
                let payload = [8usize, 12, 16, 20, 24]
                    .iter()
                    .map(|&at| u64::from(u32_le(&header, at).unwrap_or(0)))
                    .fold(0u64, u64::saturating_add)
                    .saturating_sub(raw.into());
                total = total.saturating_add(raw.into());
                ("LZFSE v1 block", 762, payload)
            }
            b"bvx2" => {
                let raw = cur.u32().await?;
                let fields = cx.read_avail(file.sub(start.saturating_add(8), 24)).await?;
                let f0 = crate::bytes::u64_le(&fields, 0).unwrap_or(0);
                let f2 = crate::bytes::u64_le(&fields, 16).unwrap_or(0);
                let header_size = (f2 >> 32) & 0xffff_ffff;
                let literal_bytes = (f0 >> 20) & 0xf_ffff;
                let lmd_bytes = (f2 >> 40) & 0xf_ffff;
                total = total.saturating_add(raw.into());
                (
                    "LZFSE v2 block",
                    header_size,
                    literal_bytes.saturating_add(lmd_bytes),
                )
            }
            _ => {
                cx.diag(Diagnostic::malformed("unknown block magic").at(cur.since(start)));
                break;
            }
        };
        cur.seek(start.saturating_add(header).saturating_add(payload));
        blocks = blocks.saturating_add(1);
        cx.push(
            Node::new(name)
                .span(cur.since(start))
                .summary(format!("{payload} payload bytes"))
                .diag(Diagnostic::unsupported("LZFSE decoding")),
        )
        .await;
    }
    cx.annotate(format!(
        "LZFSE, {blocks} block(s), {total} bytes uncompressed"
    ));
    Ok(())
}

declare_format!(pub PBZX = "pbzx", "Apple pbzx payload", ["pbzx"], "application/x-pbzx",
    Probe::Magic(&[(0, b"pbzx")]), pbzx);

async fn pbzx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    cur.skip(4);
    let flags = cur.u64().await?;
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 12))
            .summary(format!("chunk size {flags:#x}")),
    );
    let mut chunks = 0u32;
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let _chunk_flags = cur.u64().await?;
        let len = cur.u64().await?;
        let data = cur.span(len);
        cur.skip(len);
        chunks = chunks.saturating_add(1);
        cx.push(
            crate::formats::embedded(format!("Chunk {chunks}"), input.nested(data))
                .summary(format!("{len} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("pbzx, {chunks} chunk(s)"));
    Ok(())
}

// ---------------------------------------------------------------------------
// lzop, lrzip, zstd dictionaries, PowerPacker, ZPAQ

declare_format!(pub LZOP = "lzop", "lzop compressed file", ["lzo", "tzo"], "application/x-lzop",
    Probe::Magic(&[(0, b"\x89LZO\0\r\n\x1a\n")]), lzop);

const LZO_METHODS: EnumTable = &[(1, "LZO1X-1"), (2, "LZO1X-1(15)"), (3, "LZO1X-999")];

async fn lzop(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(9, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u16("Version").hex().emit()?;
    f.u16("Library version").hex().emit()?;
    let needed = f.u16("Version needed").hex().emit()?;
    f.u8("Method").enumeration(LZO_METHODS).emit()?;
    if needed >= 0x0940 {
        f.u8("Level").emit()?;
    }
    let flags = f.u32("Flags").hex().emit()?;
    if flags & 0x40 != 0 {
        f.u32("Filter").emit()?;
    }
    f.u32("Mode").hex().emit()?;
    let mtime = f.u32("Modification time").timestamp().emit()?;
    f.u32("Modification time (high)").emit()?;
    let name_len = f.u8("Name length").emit()?;
    let pos = f.pos();
    let name = cx
        .read_avail(file.sub(9u64.saturating_add(pos), name_len.into()))
        .await?;
    let name = String::from_utf8_lossy(&name).into_owned();
    cx.emit(
        Node::new("Original name")
            .span(file.sub(9u64.saturating_add(pos), name_len.into()))
            .value(Value::Text(name.clone())),
    );
    cx.emit(
        Node::new("Compressed blocks")
            .span(
                file.tail(
                    9u64.saturating_add(pos)
                        .saturating_add(name_len.into())
                        .saturating_add(4),
                ),
            )
            .diag(Diagnostic::unsupported("LZO decoding")),
    );
    cx.annotate(format!(
        "lzop, originally {name:?} ({})",
        crate::render::value(&Value::Timestamp {
            unix_seconds: mtime.into()
        })
    ));
    Ok(())
}

declare_format!(pub LRZIP = "lrzip", "lrzip compressed file", ["lrz"], "application/x-lrzip",
    Probe::Magic(&[(0, b"LRZI")]), lrzip);

async fn lrzip(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 24)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    let major = f.u8("Version major").emit()?;
    let minor = f.u8("Version minor").emit()?;
    let size = f.u64("Uncompressed size").emit()?;
    cx.emit(
        Node::new("Streams")
            .span(file.tail(24))
            .diag(Diagnostic::unsupported("lrzip decoding")),
    );
    cx.annotate(format!("lrzip {major}.{minor}, {size} bytes uncompressed"));
    Ok(())
}

declare_format!(pub ZSTD_DICT = "zstd-dict", "Zstandard dictionary", ["dict", "zdict"], "application/x-zstd-dictionary",
    Probe::Magic(&[(0, b"\x37\xa4\x30\xec")]), zstd_dict);

async fn zstd_dict(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u32("Magic").hex().emit()?;
    let id = f.u32("Dictionary ID").emit()?;
    cx.emit(Node::new("Entropy tables and content").span(file.tail(8)));
    cx.annotate(format!("zstd dictionary {id}, {} bytes", file.len));
    Ok(())
}

declare_format!(pub POWERPACKER = "powerpacker", "Amiga PowerPacker data", ["pp"], "application/x-powerpacker",
    Probe::Magic(&[(0, b"PP20")]), powerpacker);

async fn powerpacker(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    cx.emit(
        Node::new("Efficiency table")
            .span(file.sub(4, 4))
            .value(Value::Bytes(head.get(4..8).unwrap_or_default().to_vec())),
    );
    let tail = cx.read(file.sub(file.len.saturating_sub(4), 4)).await?;
    let size = crate::bytes::u24_be(&tail, 0).unwrap_or(0);
    cx.emit(
        Node::new("Compressed data")
            .span(file.sub(8, file.len.saturating_sub(12)))
            .diag(Diagnostic::unsupported("PowerPacker decoding")),
    );
    cx.emit(
        Node::new("Trailer")
            .span(file.tail(file.len.saturating_sub(4)))
            .summary(format!("{size} bytes uncompressed")),
    );
    cx.annotate(format!("PowerPacker, {size} bytes uncompressed"));
    Ok(())
}

declare_format!(pub ZPAQ = "zpaq", "ZPAQ archive", ["zpaq"], "application/x-zpaq",
    Probe::Magic(&[(0, b"7kSt"), (0, b"zPQ")]), zpaq);

async fn zpaq(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 16)).await?;
    let journaling = head.starts_with(b"7kSt");
    let at = if journaling { 13u64 } else { 0 };
    let block = cx.read_avail(file.sub(at, 4)).await?;
    let level = block.get(3).copied().unwrap_or(0);
    cx.emit(
        Node::new(if journaling {
            "Locator tag"
        } else {
            "Block header"
        })
        .span(file.sub(0, at.max(4))),
    );
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(at))
            .diag(Diagnostic::unsupported("ZPAQ decoding")),
    );
    cx.annotate(format!(
        "ZPAQ level {level}{}",
        if journaling { ", journaling" } else { "" }
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// Blu-ray PGS subtitles (SUP)

/// "PG" is weak: also require a known segment type and a second segment
/// right after the first.
fn pgs_probe(h: &crate::formats::Head<'_>) -> bool {
    let kind = h.data.get(10).copied().unwrap_or(0);
    let size = usize::from(u16_be(h.data, 11).unwrap_or(0));
    h.starts_with(b"PG")
        && lookup(PGS_SEGMENTS, kind.into()).is_some()
        && (h.at(13usize.saturating_add(size), b"PG") || h.len == 13u64.saturating_add(size as u64))
}

declare_format!(pub PGS = "pgs", "Blu-ray PGS subtitles", ["sup"], "application/x-pgs",
    Probe::Custom(pgs_probe), pgs);

const PGS_SEGMENTS: EnumTable = &[
    (0x14, "Palette definition"),
    (0x15, "Object definition"),
    (0x16, "Presentation composition"),
    (0x17, "Window definition"),
    (0x80, "End of display set"),
];

record! {
    pub struct PgsHeader {
        magic: ascii[2] "Magic",
        pts: u32 "Presentation timestamp (90 kHz)",
        dts: u32 "Decoding timestamp (90 kHz)",
        kind: u8 "Segment type" .enumeration(PGS_SEGMENTS),
        size: u16 "Segment size",
    }
}

async fn pgs(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut sets = 0u32;
    let mut last = 0u32;
    while cur.remaining() >= PgsHeader::SIZE {
        let (h, span) = cur.record::<PgsHeader>().await?;
        if h.magic != "PG" {
            cx.diag(Diagnostic::malformed("expected a PG segment").at(span));
            break;
        }
        let body = cur.span(h.size.into());
        cur.skip(h.size.into());
        if h.kind == 0x80 {
            sets = sets.saturating_add(1);
        }
        last = h.pts;
        let seconds = h.pts / 90_000;
        let name = lookup(PGS_SEGMENTS, h.kind.into()).unwrap_or("Unknown segment");
        cx.push(
            PgsHeader::node(
                name,
                Span::new(span.source, span.offset, span.len.saturating_add(body.len)),
                BE,
            )
            .summary(format!(
                "{}:{:02}:{:02}.{:03}",
                seconds / 3600,
                seconds / 60 % 60,
                seconds % 60,
                h.pts % 90_000 / 90
            )),
        )
        .await;
    }
    let seconds = last / 90_000;
    cx.annotate(format!(
        "{sets} display set(s), until {}:{:02}:{:02}",
        seconds / 3600,
        seconds / 60 % 60,
        seconds % 60
    ));
    Ok(())
}
