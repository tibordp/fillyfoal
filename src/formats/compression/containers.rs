//! Less common compression containers: Apple Archive, LZFSE and pbzx;
//! lzop, LZF, lrzip, zstd dictionaries, PowerPacker and ZPAQ.

use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded};
use crate::node::Node;
use crate::value::{EnumTable, FlagTable, Value, field, flag};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

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
        if header_len < 6 {
            cx.diag(Diagnostic::malformed("entry header too short").at(cur.since(start)));
            break;
        }
        let fields = cx
            .read_avail(file.sub(start.saturating_add(6), header_len.saturating_sub(6)))
            .await?;
        // Fields are 3-letter keys plus a type letter; we pick out PAT and
        // the blob sizes (A/B/C types): blobs follow the header in field
        // order, DAT being the file's contents.
        let mut path = String::new();
        let mut data_at = 0u64;
        let mut data_len = 0u64;
        let mut blobs = 0u64;
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
            let blob = match kind {
                b'A' => u64::from(crate::bytes::u16_le(&fields, at).unwrap_or(0)),
                b'B' => u64::from(u32_le(&fields, at).unwrap_or(0)),
                b'C' => u64_le(&fields, at).unwrap_or(0),
                _ => 0,
            };
            if key == b"DAT" {
                data_at = blobs;
                data_len = blob;
            }
            blobs = blobs.saturating_add(blob);
            at = at.saturating_add(size);
        }
        cur.seek(start.saturating_add(header_len).saturating_add(data_at));
        let data = cur.span(data_len);
        cur.seek(start.saturating_add(header_len).saturating_add(blobs));
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
                let f1 = crate::bytes::u64_le(&fields, 8).unwrap_or(0);
                let f2 = crate::bytes::u64_le(&fields, 16).unwrap_or(0);
                let header_size = f2 & 0xffff_ffff;
                let literal_bytes = (f0 >> 20) & 0xf_ffff;
                let lmd_bytes = (f1 >> 40) & 0xf_ffff;
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
        let end = start.saturating_add(header).saturating_add(payload);
        if end <= cur.pos() {
            cx.diag(Diagnostic::malformed("block header too short").at(cur.since(start)));
            break;
        }
        cur.seek(end);
        blocks = blocks.saturating_add(1);
        let mut node = Node::new(name)
            .span(cur.since(start))
            .summary(format!("{payload} payload bytes"));
        if magic == b"bvx1" {
            node = node.diag(Diagnostic::unsupported("LZFSE v1 blocks"));
        }
        cx.push(node).await;
    }
    cx.emit(crate::formats::content(
        "Decompressed",
        input,
        file,
        crate::codec::Codec::Lzfse,
        Some(total),
    ));
    cx.annotate(format!(
        "LZFSE, {blocks} block(s), {total} bytes uncompressed"
    ));
    Ok(())
}

declare_format!(pub PBZX = "pbzx", "Apple chunked compressed data (pbzx, pbze, pbz4, pbzz)", ["pbzx"], "application/x-pbzx",
    Probe::Magic(&[(0, b"pbzx"), (0, b"pbze"), (0, b"pbz4"), (0, b"pbzz")]), pbzx);

async fn pbzx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let magic = cur.bytes(4).await?;
    let algorithm = match magic.get(3) {
        Some(b'x') => "xz",
        Some(b'e') => "LZFSE",
        Some(b'4') => "LZ4",
        _ => "zlib",
    };
    let chunk_size = cur.u64().await?;
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 12))
            .summary(format!("{algorithm}, chunk size {chunk_size:#x}")),
    );
    let mut chunks = 0u32;
    let mut total = 0u64;
    let mut any_compressed = false;
    while cur.remaining() >= 16 {
        let start = cur.pos();
        let raw = cur.u64().await?;
        let len = cur.u64().await?;
        let data = cur.span(len);
        let head = cx.read_avail(data.sub(0, 6)).await?;
        let compressed = raw != len
            && crate::codec::pbz::looks_compressed(magic.get(3).copied().unwrap_or(0), &head);
        any_compressed |= compressed;
        cur.skip(len);
        chunks = chunks.saturating_add(1);
        total = total.saturating_add(if compressed { raw } else { len });
        let summary = if !compressed {
            format!("{len} bytes, stored")
        } else {
            format!("{len} bytes, {raw} uncompressed")
        };
        cx.push(
            crate::formats::embedded(format!("Chunk {chunks}"), input.nested(data))
                .summary(summary)
                .target(cur.since(start)),
        )
        .await;
    }
    if any_compressed {
        cx.emit(crate::formats::content(
            "Decompressed",
            input,
            file,
            crate::codec::Codec::Pbz,
            Some(total),
        ));
    }
    cx.annotate(format!(
        "{}, {algorithm}, {chunks} chunk(s), {total} bytes uncompressed",
        String::from_utf8_lossy(&magic)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// lzop, lrzip, zstd dictionaries, PowerPacker, ZPAQ

declare_format!(pub LZOP = "lzop", "lzop compressed file", ["lzo", "tzo"], "application/x-lzop",
    Probe::Magic(&[(0, b"\x89LZO\0\r\n\x1a\n")]), lzop);

const LZO_METHODS: EnumTable = &[(1, "LZO1X-1"), (2, "LZO1X-1(15)"), (3, "LZO1X-999")];

const LZOP_FLAGS: FlagTable = &[
    flag(0x1, "ADLER32_D"),
    flag(0x2, "ADLER32_C"),
    flag(0x4, "STDIN"),
    flag(0x8, "STDOUT"),
    flag(0x10, "NAME_DEFAULT"),
    flag(0x20, "DOSISH"),
    flag(0x40, "H_EXTRA_FIELD"),
    flag(0x80, "H_GMTDIFF"),
    flag(0x100, "CRC32_D"),
    flag(0x200, "CRC32_C"),
    flag(0x400, "MULTIPART"),
    flag(0x800, "H_FILTER"),
    flag(0x1000, "H_CRC32"),
    flag(0x2000, "H_PATH"),
    field(0xff00_0000, 0x0000_0000, "OS_FAT"),
    field(0xff00_0000, 0x0300_0000, "OS_UNIX"),
    field(0xff00_0000, 0x0b00_0000, "OS_NTFS"),
];

async fn lzop(cx: Cx, input: Input) -> Result<()> {
    use crate::codec::lzo;
    let file = input.span;
    // The largest header: fixed fields, a 255-byte name, the checksum and
    // an extra field's length.
    let raw = cx.read_avail(file.sub(0, 9 + 33 + 255 + 8)).await?;
    let parsed = lzo::lzop_header(&raw).map_err(|e| e.at(file))?;
    let head = cx.block(file.sub(9, 33 + 255 + 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u16("Version").hex().emit()?;
    f.u16("Library version").hex().emit()?;
    if parsed.version >= 0x0940 {
        f.u16("Version needed").hex().emit()?;
    }
    f.u8("Method").enumeration(LZO_METHODS).emit()?;
    if parsed.version >= 0x0940 {
        f.u8("Level").emit()?;
    }
    let flags = f.u32("Flags").flags(LZOP_FLAGS).emit()?;
    if flags & lzo::F_H_FILTER != 0 {
        f.u32("Filter").emit()?;
    }
    f.u32("Mode").hex().emit()?;
    let mtime = f.u32("Modification time").timestamp().emit()?;
    if parsed.version >= 0x0940 {
        f.u32("Modification time (high)").emit()?;
    }
    let name_len = f.u8("Name length").emit()?;
    let name_span = f.peek_span(name_len.into());
    let name = f.bytes("Original name", name_len.into()).get()?;
    let name = String::from_utf8_lossy(&name).into_owned();
    f.node(
        Node::new("Original name")
            .span(name_span)
            .value(Value::Text(name.clone())),
    );
    let kind = if flags & lzo::F_H_CRC32 != 0 {
        "CRC-32"
    } else {
        "Adler-32"
    };
    let ok = parsed.checksum_ok;
    f.u32("Header checksum")
        .hex()
        .summary(kind)
        .check(|_| (!ok).then(|| Diagnostic::warning("header checksum mismatch")))
        .emit()?;
    if flags & lzo::F_H_EXTRA_FIELD != 0 {
        let len = f.u32("Extra field length").emit()?;
        f.bytes("Extra field", len.into()).emit()?;
        f.u32("Extra field checksum").hex().emit()?;
    }
    let mut cur = Cursor::new(&cx, file, BE);
    cur.seek(u64::try_from(parsed.len).unwrap_or(u64::MAX));
    let mut blocks = 0u32;
    let mut total = 0u64;
    let mut ended = false;
    while cur.remaining() >= 4 {
        let start = cur.pos();
        let raw_len = cur.u32().await?;
        if raw_len == 0 {
            cx.push(Node::new("End of stream").span(cur.since(start)))
                .await;
            ended = true;
            break;
        }
        let packed = cur.u32().await?;
        let compressed = packed < raw_len;
        let checks = lzo::lzop_block_header_len(flags, compressed).saturating_sub(8);
        cur.skip(
            u64::try_from(checks)
                .unwrap_or(0)
                .saturating_add(packed.into()),
        );
        blocks = blocks.saturating_add(1);
        total = total.saturating_add(raw_len.into());
        let summary = if compressed {
            format!("{packed} bytes, {raw_len} uncompressed")
        } else {
            format!("{raw_len} bytes, stored")
        };
        let node = Node::new(format!("Block {blocks}"))
            .span(cur.since(start))
            .summary(summary);
        if packed > raw_len || raw_len > lzo::LZOP_MAX_BLOCK {
            cx.push(node.diag(Diagnostic::malformed("bad block size")))
                .await;
            break;
        }
        cx.push(node).await;
    }
    if !ended {
        cx.diag(Diagnostic::malformed("lzop stream has no end marker").at(file));
    }
    if !matches!(parsed.method, 1..=3) {
        cx.emit(
            Node::new("Decompressed")
                .span(file)
                .diag(Diagnostic::unsupported(format!(
                    "lzop method {}",
                    parsed.method
                ))),
        );
    } else if flags & lzo::F_H_FILTER != 0 {
        cx.emit(
            Node::new("Decompressed")
                .span(file)
                .diag(Diagnostic::unsupported("lzop filters")),
        );
    } else {
        cx.emit(crate::formats::content(
            "Decompressed",
            input,
            file,
            crate::codec::Codec::Lzop,
            Some(total),
        ));
    }
    cx.annotate(format!(
        "lzop, originally {name:?} ({}), {blocks} block(s), {total} bytes uncompressed",
        crate::render::value(&Value::Timestamp {
            unix_seconds: mtime.into()
        })
    ));
    Ok(())
}

fn lzf_probe(h: &crate::formats::Head<'_>) -> bool {
    match crate::codec::legacy::zv_block(h.data) {
        Some((_, clen, ulen, compressed)) => clen > 0 && (!compressed || clen < ulen),
        None => false,
    }
}

declare_format!(pub LZF = "lzf", "LZF compressed data", ["lzf"], "application/x-lzf",
    Probe::Custom(lzf_probe), lzf);

/// The `lzf` tool's output: `ZV` blocks of up to 64 KiB, each compressed
/// alone or stored.
async fn lzf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut blocks = 0u32;
    let mut total = 0u64;
    while cur.remaining() >= 5 {
        let start = cur.pos();
        let head = cx.read_avail(file.sub(start, 7)).await?;
        let Some((hlen, clen, ulen, compressed)) = crate::codec::legacy::zv_block(&head) else {
            cx.diag(Diagnostic::malformed("bad ZV block header").at(file.tail(start)));
            break;
        };
        cur.skip(u64::try_from(hlen.saturating_add(clen)).unwrap_or(u64::MAX));
        blocks = blocks.saturating_add(1);
        total = total.saturating_add(u64::try_from(ulen).unwrap_or(0));
        let summary = if compressed {
            format!("{clen} bytes, {ulen} uncompressed")
        } else {
            format!("{ulen} bytes, stored")
        };
        cx.push(
            Node::new(format!("Block {blocks}"))
                .span(cur.since(start))
                .summary(summary),
        )
        .await;
    }
    cx.emit(crate::formats::content(
        "Decompressed",
        input,
        file,
        crate::codec::Codec::LzfFramed,
        Some(total),
    ));
    cx.annotate(format!(
        "LZF, {blocks} block(s), {total} bytes uncompressed"
    ));
    Ok(())
}

declare_format!(pub LRZIP ="lrzip", "lrzip compressed file", ["lrz"], "application/x-lrzip",
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
