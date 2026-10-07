//! Game and console archive formats: Nintendo SARC and Yaz0, Wii U8 and DS
//! NARC, Sony PSARC, XNA XNB, Unreal Engine `.pak`, Bethesda BSA/BA2,
//! Blizzard MPQ and RPG Maker RGSSAD.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Nintendo SARC (with SFAT/SFNT) and Yaz0

declare_format!(pub SARC = "sarc", "Nintendo SARC archive", ["sarc", "pack", "bars"], "application/x-sarc",
    Probe::Magic(&[(0, b"SARC")]), sarc);

async fn sarc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 20)).await?;
    let little = u16_be(&head, 6) == Some(0xfffe);
    let endian = if little { LE } else { BE };
    let u16_at =
        |d: &[u8], at: usize| if little { u16_le(d, at) } else { u16_be(d, at) }.unwrap_or(0);
    let u32_at =
        |d: &[u8], at: usize| if little { u32_le(d, at) } else { u32_be(d, at) }.unwrap_or(0);
    let header_len = u64::from(u16_at(&head, 4));
    let data_offset = u64::from(u32_at(&head, 12));
    let block = cx.block(file.sub(0, header_len)).await?;
    {
        let mut f = Fields::emitting(&cx, &block, endian);
        f.ascii("Magic", 4).emit()?;
        f.u16("Header size").emit()?;
        f.u16("Byte order mark").hex().emit()?;
        f.u32("File size").emit()?;
        f.u32("Data offset").hex().emit()?;
        f.u16("Version").hex().emit()?;
    }
    let sfat = cx.read(file.sub(header_len, 12)).await?;
    if sfat.get(..4) != Some(b"SFAT") {
        return Err(Diagnostic::malformed("expected SFAT").at(file.sub(header_len, 4)));
    }
    let count = u16_at(&sfat, 6);
    let entries = file.sub_exact(
        header_len.saturating_add(12),
        u64::from(count).saturating_mul(16),
    )?;
    let table = cx.read(entries).await?;
    let names_at = entries.end().saturating_sub(file.offset).saturating_add(8);
    cx.set_count(Count::AtLeast(count.into()));
    for i in 0..usize::from(count) {
        let at = i.saturating_mul(16);
        let attrs = u32_at(&table, at.saturating_add(4));
        let start = u32_at(&table, at.saturating_add(8));
        let end = u32_at(&table, at.saturating_add(12));
        let name = if attrs & 0x0100_0000 != 0 {
            let offset = u64::from(attrs & 0xffff).saturating_mul(4);
            cx.cstr(file.sub(names_at.saturating_add(offset), 256))
                .await
                .map(|(n, _)| n)
                .unwrap_or_default()
        } else {
            format!("#{i:08x}")
        };
        let data = file.sub(
            data_offset.saturating_add(start.into()),
            u64::from(end.saturating_sub(start)),
        );
        cx.push(embedded(name, input.nested(data)).summary(format!("{} bytes", data.len)))
            .await;
    }
    cx.annotate(format!(
        "SARC, {count} files, {} endian",
        if little { "little" } else { "big" }
    ));
    Ok(())
}

declare_format!(pub YAZ0 = "yaz0", "Nintendo Yaz0 compressed data", ["szs", "yaz0"], "application/x-yaz0",
    Probe::Magic(&[(0, b"Yaz0"), (0, b"Yaz1")]), yaz0);

/// Yaz0 is a simple LZ77 variant: decode it into a derived source.
fn decode_yaz0(src: &[u8], size: usize, limit: usize) -> Result<Vec<u8>> {
    let mut out = Vec::with_capacity(size.min(limit));
    let mut at = 0usize;
    while out.len() < size {
        let group = *src
            .get(at)
            .ok_or_else(|| Diagnostic::malformed("Yaz0 stream ends early"))?;
        at = at.saturating_add(1);
        for bit in (0..8).rev() {
            if out.len() >= size {
                break;
            }
            if out.len() >= limit {
                return Err(Diagnostic::limit("Yaz0 output exceeds the limit"));
            }
            if group >> bit & 1 == 1 {
                out.push(
                    *src.get(at)
                        .ok_or_else(|| Diagnostic::malformed("Yaz0 stream ends early"))?,
                );
                at = at.saturating_add(1);
            } else {
                let b1 = usize::from(
                    *src.get(at)
                        .ok_or_else(|| Diagnostic::malformed("Yaz0 stream ends early"))?,
                );
                let b2 = usize::from(
                    *src.get(at.saturating_add(1))
                        .ok_or_else(|| Diagnostic::malformed("Yaz0 stream ends early"))?,
                );
                at = at.saturating_add(2);
                let distance = ((b1 & 0x0f) << 8 | b2).saturating_add(1);
                let len = if b1 >> 4 == 0 {
                    let b3 = usize::from(
                        *src.get(at)
                            .ok_or_else(|| Diagnostic::malformed("Yaz0 stream ends early"))?,
                    );
                    at = at.saturating_add(1);
                    b3.saturating_add(0x12)
                } else {
                    (b1 >> 4).saturating_add(2)
                };
                let from = out
                    .len()
                    .checked_sub(distance)
                    .ok_or_else(|| Diagnostic::malformed("Yaz0 back-reference before start"))?;
                for i in 0..len {
                    let byte = out.get(from.saturating_add(i)).copied().unwrap_or(0);
                    out.push(byte);
                }
            }
        }
    }
    out.truncate(size);
    Ok(out)
}

async fn yaz0(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 16)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Magic", 4).emit()?;
    let size = f.u32("Uncompressed size").emit()?;
    f.u32("Alignment").emit()?;
    let body = file.tail(16);
    cx.emit(
        Node::new("Compressed data")
            .span(body)
            .lazy(yaz0_content, (input, body, size)),
    );
    cx.annotate(format!("Yaz0, {size} bytes uncompressed"));
    Ok(())
}

async fn yaz0_content(cx: Cx, (input, body, size): (Input, Span, u32)) -> Result<()> {
    let origin = crate::span::Origin {
        parent: body,
        transform: "yaz0",
    };
    let decoded = match cx.derived(origin) {
        Some(found) => found,
        None => {
            let src = crate::codec::read_all(&cx, body).await?;
            let limit = crate::bytes::to_usize(cx.limits().max_derived);
            let out = decode_yaz0(&src, usize::try_from(size).unwrap_or(0), limit)?;
            cx.add_derived(origin, out, body.len, None)?
        }
    };
    crate::formats::dissect_or_data(cx, input.nested(decoded.span)).await
}

// ---------------------------------------------------------------------------
// Wii U8 archives and DS NARC

declare_format!(pub U8 = "u8", "Nintendo U8 archive", ["arc", "app", "szs"], "application/x-u8",
    Probe::Magic(&[(0, b"\x55\xaa\x38\x2d")]), u8_archive);

async fn u8_archive(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let root = u64::from(u32_be(&head, 4).unwrap_or(0));
    let first = cx.read(file.sub(root, 12)).await?;
    let count = u32_be(&first, 8).unwrap_or(0);
    let table = file.sub_exact(root, u64::from(count).saturating_mul(12))?;
    let nodes = cx.read(table).await?;
    let names = table.end().saturating_sub(file.offset);
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 32))
            .summary(format!("{count} nodes")),
    );
    for i in 1..usize::try_from(count).unwrap_or(0) {
        let at = i.saturating_mul(12);
        let kind = nodes.get(at).copied().unwrap_or(0);
        let name_off = u64::from(crate::bytes::u24_be(&nodes, at.saturating_add(1)).unwrap_or(0));
        let offset = u64::from(u32_be(&nodes, at.saturating_add(4)).unwrap_or(0));
        let size = u64::from(u32_be(&nodes, at.saturating_add(8)).unwrap_or(0));
        let name = cx
            .cstr(file.sub(names.saturating_add(name_off), 256))
            .await
            .map(|(n, _)| n)
            .unwrap_or_default();
        let node = if kind == 1 {
            Node::new(format!("{name}/")).summary("directory")
        } else {
            embedded(name, input.nested(file.sub(offset, size))).summary(format!("{size} bytes"))
        };
        cx.push(node).await;
    }
    cx.annotate(format!("U8 archive, {} entries", count.saturating_sub(1)));
    Ok(())
}

declare_format!(pub NARC = "narc", "Nintendo DS archive (NARC)", ["narc", "carc"], "application/x-narc",
    Probe::Magic(&[(0, b"NARC")]), narc);

async fn narc(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 16)).await?;
    let header_len = u64::from(u16_le(&head, 12).unwrap_or(16));
    let btaf = cx.read(file.sub(header_len, 12)).await?;
    if btaf.get(..4) != Some(b"BTAF") {
        return Err(Diagnostic::malformed("expected BTAF").at(file.sub(header_len, 4)));
    }
    let btaf_len = u64::from(u32_le(&btaf, 4).unwrap_or(0));
    let count = u16_le(&btaf, 8).unwrap_or(0);
    let table = cx
        .read(file.sub_exact(
            header_len.saturating_add(12),
            u64::from(count).saturating_mul(8),
        )?)
        .await?;
    let btnf = header_len.saturating_add(btaf_len);
    let btnf_len = u64::from(u32_le(&cx.read(file.sub(btnf, 8)).await?, 4).unwrap_or(0));
    let gmif = btnf.saturating_add(btnf_len).saturating_add(8);
    cx.emit(Node::new("Header").span(file.sub(0, header_len)));
    for i in 0..usize::from(count) {
        let start = u64::from(u32_le(&table, i.saturating_mul(8)).unwrap_or(0));
        let end = u64::from(u32_le(&table, i.saturating_mul(8).saturating_add(4)).unwrap_or(0));
        let data = file.sub(gmif.saturating_add(start), end.saturating_sub(start));
        cx.push(
            embedded(format!("File {i}"), input.nested(data))
                .summary(format!("{} bytes", data.len)),
        )
        .await;
    }
    cx.annotate(format!("NARC, {count} files"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Sony PSARC, XNA XNB

declare_format!(pub PSARC = "psarc", "PlayStation archive (PSARC)", ["psarc", "pak"], "application/x-psarc",
    Probe::Magic(&[(0, b"PSAR")]), psarc);

record! {
    pub struct PsarcHeader {
        magic: ascii[4] "Magic",
        major: u16 "Version major",
        minor: u16 "Version minor",
        compression: ascii[4] "Compression",
        toc_length: u32 "TOC length",
        entry_size: u32 "TOC entry size",
        entries: u32 "TOC entries",
        block_size: u32 "Block size",
        flags: u32 "Archive flags" .hex(),
    }
}

/// Archive flag: the table of contents is encrypted (PS Vita).
const PSARC_TOC_ENCRYPTED: u32 = 4;
/// Bytes of the manifest read to name the entries.
const PSARC_MANIFEST_MAX: u64 = 1 << 20;

fn be40(b: &[u8]) -> u64 {
    b.iter().take(5).fold(0u64, |v, &x| v << 8 | u64::from(x))
}

/// A TOC entry: MD5 of the name, first block, size and offset (40-bit).
fn psarc_entry(f: &mut Fields<'_>, _: &()) -> Result<(u32, u64, u64)> {
    f.bytes("Name digest (MD5)", 16).emit()?;
    let block = f.u32("First block").emit()?;
    let size = f
        .bytes("Uncompressed size", 5)
        .map(|b| be40(&b))
        .with(|&v, n| {
            n.value(Value::UInt {
                value: v,
                bits: 40,
                radix: crate::value::Radix::Dec,
            })
            .summary(crate::formats::util::arcutil::human_size(v))
        })
        .emit()?;
    let offset = f
        .bytes("Offset", 5)
        .map(|b| be40(&b))
        .with(|&v, n| n.value(crate::formats::util::arcutil::hex(v)))
        .emit()?;
    Ok((block, size, offset))
}

async fn psarc_toc(cx: Cx, (span, entry_size, count): (Span, u64, u32)) -> Result<()> {
    cx.set_count(Count::Exact(count.into()));
    for i in 0..u64::from(count) {
        let at = span.sub(i.saturating_mul(entry_size), entry_size);
        let label = if i == 0 {
            "Entry 0 (manifest)".to_owned()
        } else {
            format!("Entry {i}")
        };
        cx.push(crate::fields::struct_node(label, at, BE, (), psarc_entry))
            .await;
    }
    Ok(())
}

/// PSARC: a header, the table of contents (entries, then the block-size
/// table), and the entries' blocks. Entry 0 is the manifest, the other
/// entries' paths one per line; entries are decoded through
/// [`crate::codec::psarc`]. From memory of the community documentation.
async fn psarc(cx: Cx, input: Input) -> Result<()> {
    use crate::codec::{Codec, psarc::Entry};
    use crate::formats::util::arcutil::human_size;
    let file = input.span;
    let h: PsarcHeader = emit_record(&cx, file.sub(0, PsarcHeader::SIZE), BE).await?;
    let summary = format!(
        "PSARC {}.{}, {} entries, {}",
        h.major, h.minor, h.entries, h.compression
    );
    cx.annotate(summary.clone());
    let toc = file.sub(
        PsarcHeader::SIZE,
        u64::from(h.toc_length).saturating_sub(PsarcHeader::SIZE),
    );
    if h.flags & PSARC_TOC_ENCRYPTED != 0 {
        cx.emit(
            Node::new("Table of contents")
                .span(toc)
                .diag(Diagnostic::unsupported("encrypted table of contents")),
        );
        return Ok(());
    }
    let entry_size = u64::from(h.entry_size);
    if entry_size < 30 {
        return Err(
            Diagnostic::malformed(format!("TOC entry size {entry_size}")).at(file.sub(20, 4)),
        );
    }
    let entries_span = file.sub_exact(
        PsarcHeader::SIZE,
        entry_size.saturating_mul(h.entries.into()),
    )?;
    cx.emit(
        Node::new("Table of contents")
            .span(entries_span)
            .summary(format!("{} entries", h.entries))
            .lazy(psarc_toc, (entries_span, entry_size, h.entries)),
    );
    // The block-size table fills the rest of the TOC, in the fewest bytes
    // that hold a block size.
    let width: u64 = match h.block_size {
        0..=0x1_0000 => 2,
        0x1_0001..=0x100_0000 => 3,
        _ => 4,
    };
    let table_at = PsarcHeader::SIZE.saturating_add(entries_span.len);
    let table_len = u64::from(h.toc_length).saturating_sub(table_at);
    let table_span = file.sub_exact(
        table_at,
        table_len.saturating_sub(table_len.checked_rem(width).unwrap_or(0)),
    )?;
    let table = cx.read(table_span).await?;
    let sizes: Vec<u32> = table
        .chunks_exact(usize::try_from(width).unwrap_or(2))
        .map(|c| u32::try_from(be40(c)).unwrap_or(u32::MAX))
        .collect();
    cx.emit(
        Node::new("Block sizes")
            .span(table_span)
            .summary(format!("{} blocks, {width}-byte entries", sizes.len())),
    );
    let raw = cx.read(entries_span).await?;
    let entries: Vec<(u32, u64, u64)> = raw
        .chunks_exact(usize::try_from(entry_size).unwrap_or(30))
        .map(|e| {
            (
                u32_be(e, 16).unwrap_or(0),
                be40(e.get(20..25).unwrap_or_default()),
                be40(e.get(25..30).unwrap_or_default()),
            )
        })
        .collect();
    let block_size = h.block_size.max(1);
    // An entry's data: its blocks, back to back from its offset.
    let entry_content = |block: u32, size: u64, offset: u64| -> (Span, Codec) {
        let count = size.div_ceil(block_size.into());
        let first = usize::try_from(block).unwrap_or(usize::MAX);
        let last = first.saturating_add(usize::try_from(count).unwrap_or(usize::MAX));
        let blocks: Vec<u32> = sizes
            .get(first..last.min(sizes.len()))
            .unwrap_or_default()
            .to_vec();
        let stored = blocks.iter().fold(0u64, |a, &b| {
            a.saturating_add(if b == 0 { block_size.into() } else { b.into() })
        });
        let codec = Codec::Psarc(Entry {
            block_size,
            size,
            blocks: blocks.into(),
        });
        (file.sub(offset, stored), codec)
    };
    let mut names: Vec<String> = Vec::new();
    if let Some(&(block, size, offset)) = entries.first() {
        let (span, codec) = entry_content(block, size, offset);
        cx.emit(
            crate::formats::content("Manifest", input, span, codec.clone(), Some(size))
                .summary(human_size(size)),
        );
        if size <= PSARC_MANIFEST_MAX {
            match crate::codec::decode_span(&cx, span, &codec, Some(size)).await {
                Ok(decoded) => {
                    let text = cx.read(decoded.span).await?;
                    names = String::from_utf8_lossy(&text)
                        .split(['\n', '\0'])
                        .map(str::to_owned)
                        .collect();
                }
                Err(e) => cx.diag(e),
            }
        }
    }
    let mut total = 0u64;
    for (i, &(block, size, offset)) in entries.iter().enumerate().skip(1) {
        let name = names
            .get(i.saturating_sub(1))
            .filter(|n| !n.is_empty())
            .cloned()
            .unwrap_or_else(|| format!("Entry {i}"));
        total = total.saturating_add(size);
        let (span, codec) = entry_content(block, size, offset);
        cx.push(
            crate::formats::content(name, input, span, codec, Some(size)).summary(human_size(size)),
        )
        .await;
    }
    cx.annotate(format!("{summary}, {} uncompressed", human_size(total)));
    Ok(())
}

declare_format!(pub XNB = "xnb", "XNA content file", ["xnb"], "application/x-xnb",
    Probe::Magic(&[(0, b"XNBw"), (0, b"XNBx"), (0, b"XNBm"), (0, b"XNBa"), (0, b"XNBi"), (0, b"XNBd")]), xnb);

async fn xnb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 10)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 3).emit()?;
    let platform = f.ascii("Target platform", 1).emit()?;
    let version = f.u8("Format version").emit()?;
    let flags = f.u8("Flags").hex().emit()?;
    let size = f.u32("File size").emit()?;
    if flags & 0x40 != 0 {
        // MonoGame LZ4: the decompressed size, then one raw LZ4 block.
        let head = cx.block(file.sub(10, 4)).await?;
        let mut f = Fields::emitting(&cx, &head, LE);
        let decoded = f.u32("Decompressed size").emit()?;
        cx.emit(crate::formats::content(
            "Content",
            input,
            file.tail(14),
            crate::codec::Codec::Lz4Block,
            Some(decoded.into()),
        ));
    } else {
        let mut node = Node::new("Content").span(file.tail(10));
        if flags & 0x80 != 0 {
            node = node.diag(Diagnostic::unsupported("LZX-compressed content"));
        }
        cx.emit(node);
    }
    let platform = match platform.as_str() {
        "w" => "Windows",
        "x" => "Xbox 360",
        "m" => "Windows Phone",
        "a" => "Android",
        "i" => "iOS",
        "d" => "macOS",
        _ => "unknown platform",
    };
    cx.annotate(format!("XNB v{version} for {platform}, {size} bytes"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Unreal Engine 4/5 .pak (footer at the end)

fn upak_probe(h: &Head<'_>) -> bool {
    // The footer's magic sits 44 bytes (or more, for newer versions) before
    // the end; check the common positions.
    [44usize, 61, 189, 221].iter().any(|&back| {
        h.tail.len() >= back
            && h.tail.get(
                h.tail.len().saturating_sub(back)
                    ..h.tail.len().saturating_sub(back).saturating_add(4),
            ) == Some(b"\xe1\x12\x6f\x5a")
    })
}

declare_format!(pub UNREAL_PAK = "unreal-pak", "Unreal Engine pak file", ["pak"], "application/x-unreal-pak",
    Probe::Custom(upak_probe), unreal_pak);

async fn unreal_pak(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let tail = cx.read(file.sub(file.len.saturating_sub(256), 256)).await?;
    let at = tail
        .windows(4)
        .rposition(|w| w == b"\xe1\x12\x6f\x5a")
        .ok_or_else(|| Diagnostic::malformed("no pak footer"))?;
    let footer = file.sub(
        file.len
            .saturating_sub(256)
            .saturating_add(crate::bytes::to_u64(at)),
        file.len,
    );
    let version = u32_le(&tail, at.saturating_add(4)).unwrap_or(0);
    let index_offset = u64_le(&tail, at.saturating_add(8)).unwrap_or(0);
    let index_size = u64_le(&tail, at.saturating_add(16)).unwrap_or(0);
    cx.emit(Node::new("Data").span(file.sub(0, index_offset)));
    cx.emit(Node::new("Index").span(file.sub(index_offset, index_size)));
    cx.emit(
        Node::new("Footer")
            .span(footer)
            .summary(format!("version {version}")),
    );
    cx.annotate(format!("Unreal pak v{version}, index {index_size} bytes"));
    Ok(())
}

// ---------------------------------------------------------------------------
// Bethesda BSA / BA2, Blizzard MPQ, RPG Maker RGSSAD

declare_format!(pub BSA = "bsa", "Bethesda archive (BSA)", ["bsa"], "application/x-bsa",
    Probe::Magic(&[(0, b"BSA\0")]), bsa);

record! {
    pub struct BsaHeader {
        magic: ascii[4] "Magic",
        version: u32 "Version" .enumeration(&[(103, "Oblivion"), (104, "Fallout 3 / Skyrim"), (105, "Skyrim SE")]),
        offset: u32 "Folder records offset",
        flags: u32 "Archive flags" .hex(),
        folders: u32 "Folders",
        files: u32 "Files",
        folder_names: u32 "Total folder name length",
        file_names: u32 "Total file name length",
        content: u16 "Content flags" .hex(),
        _padding: u16 "Padding",
    }
}

async fn bsa(cx: Cx, input: Input) -> Result<()> {
    let h: BsaHeader = emit_record(&cx, input.span.sub(0, BsaHeader::SIZE), LE).await?;
    cx.emit(Node::new("Records and data").span(input.span.tail(BsaHeader::SIZE)));
    let game = match h.version {
        103 => "Oblivion",
        104 => "Fallout 3 / Skyrim",
        105 => "Skyrim SE",
        _ => "unknown game",
    };
    cx.annotate(format!(
        "BSA v{} ({game}), {} folders, {} files{}",
        h.version,
        h.folders,
        h.files,
        if h.flags & 4 != 0 { ", compressed" } else { "" }
    ));
    Ok(())
}

declare_format!(pub BA2 = "ba2", "Bethesda archive 2 (BA2)", ["ba2"], "application/x-ba2",
    Probe::Magic(&[(0, b"BTDX")]), ba2);

record! {
    pub struct Ba2Header {
        magic: ascii[4] "Magic",
        version: u32 "Version",
        kind: ascii[4] "Type" .desc("GNRL (general) or DX10 (textures)"),
        files: u32 "Files",
        names: u64 "Name table offset" .hex(),
    }
}

async fn ba2(cx: Cx, input: Input) -> Result<()> {
    let h: Ba2Header = emit_record(&cx, input.span.sub(0, Ba2Header::SIZE), LE).await?;
    cx.emit(
        Node::new("File records and data").span(
            input
                .span
                .sub(Ba2Header::SIZE, h.names.saturating_sub(Ba2Header::SIZE)),
        ),
    );
    cx.emit(Node::new("Name table").span(input.span.tail(h.names)));
    cx.annotate(format!("BA2 v{} {}, {} files", h.version, h.kind, h.files));
    Ok(())
}

declare_format!(pub MPQ = "mpq", "Blizzard MPQ archive", ["mpq", "sc2map", "w3x", "w3m"], "application/x-mpq",
    Probe::Magic(&[(0, b"MPQ\x1a"), (0, b"MPQ\x1b")]), mpq);

record! {
    pub struct MpqHeader {
        magic: bytes[4] "Magic",
        header_size: u32 "Header size",
        archive_size: u32 "Archive size",
        version: u16 "Format version",
        block_size: u16 "Sector size shift",
        hash_table: u32 "Hash table offset" .hex(),
        block_table: u32 "Block table offset" .hex(),
        hash_entries: u32 "Hash table entries",
        block_entries: u32 "Block table entries",
    }
}

async fn mpq(cx: Cx, input: Input) -> Result<()> {
    use crate::codec::crypto::mpq::{HASH_FILE_KEY, decrypt, hash_string};
    let file = input.span;
    let magic = cx.read(file.sub(0, 16)).await?;
    let mut base = 0u64;
    if magic.get(3) == Some(&0x1b) {
        // A user data header precedes the real one (StarCraft II maps).
        let offset = u64::from(u32_le(&magic, 8).unwrap_or(0));
        cx.emit(Node::new("User data").span(file.sub(0, offset)));
        base = offset;
    }
    let h: MpqHeader = read_record(&cx, file.sub(base, MpqHeader::SIZE), LE).await?;
    cx.emit(MpqHeader::node(
        "Header",
        file.sub(base, MpqHeader::SIZE),
        LE,
    ));
    let archive = file.tail(base);
    let sector = 512u32.checked_shl(h.block_size.into()).unwrap_or(4096);
    let table = |offset: u32, entries: u32| {
        archive.sub(offset.into(), u64::from(entries).saturating_mul(16))
    };
    let hash_span = table(h.hash_table, h.hash_entries);
    let block_span = table(h.block_table, h.block_entries);
    let mut hashes = cx.read(hash_span).await?;
    decrypt(&mut hashes, hash_string("(hash table)", HASH_FILE_KEY));
    let mut blocks = cx.read(block_span).await?;
    decrypt(&mut blocks, hash_string("(block table)", HASH_FILE_KEY));
    let hashes = std::sync::Arc::new(hashes);
    let blocks: Vec<MpqBlock> = blocks
        .as_chunks::<16>()
        .0
        .iter()
        .map(|b| MpqBlock {
            offset: u32_le(b, 0).unwrap_or(0),
            packed: u32_le(b, 4).unwrap_or(0),
            size: u32_le(b, 8).unwrap_or(0),
            flags: u32_le(b, 12).unwrap_or(0),
        })
        .collect();
    cx.emit(
        Node::new("Hash table")
            .span(hash_span)
            .summary(format!("{} entries, decrypted", h.hash_entries)),
    );
    cx.emit(
        Node::new("Block table")
            .span(block_span)
            .summary(format!("{} entries, decrypted", h.block_entries)),
    );
    let state = MpqState {
        input,
        archive,
        sector,
        hashes,
        blocks: std::sync::Arc::new(blocks),
    };
    cx.emit(
        Node::new("Files")
            .summary(format!("{} blocks", h.block_entries))
            .lazy(mpq_files, state),
    );
    cx.annotate(format!(
        "MPQ v{}, {} blocks, {sector}-byte sectors",
        u32::from(h.version).saturating_add(1),
        h.block_entries,
    ));
    Ok(())
}

#[derive(Clone, Copy, Debug)]
struct MpqBlock {
    offset: u32,
    packed: u32,
    size: u32,
    flags: u32,
}

const MPQ_IMPLODE: u32 = 0x100;
const MPQ_COMPRESS: u32 = 0x200;
const MPQ_ENCRYPTED: u32 = 0x1_0000;
const MPQ_FIX_KEY: u32 = 0x2_0000;
const MPQ_SINGLE_UNIT: u32 = 0x100_0000;
const MPQ_EXISTS: u32 = 0x8000_0000;

#[derive(Clone)]
struct MpqState {
    input: Input,
    archive: Span,
    sector: u32,
    hashes: std::sync::Arc<Vec<u8>>,
    blocks: std::sync::Arc<Vec<MpqBlock>>,
}

impl MpqState {
    /// The block index of `name`, through the hash table.
    fn lookup(&self, name: &str) -> Option<usize> {
        use crate::codec::crypto::mpq::{HASH_NAME_A, HASH_NAME_B, HASH_OFFSET, hash_string};
        let entries = self.hashes.len() / 16;
        if entries == 0 {
            return None;
        }
        let (a, b) = (
            hash_string(name, HASH_NAME_A),
            hash_string(name, HASH_NAME_B),
        );
        let start = usize::try_from(hash_string(name, HASH_OFFSET))
            .unwrap_or(0)
            .checked_rem(entries)
            .unwrap_or(0);
        for i in 0..entries {
            let at = start.wrapping_add(i).checked_rem(entries).unwrap_or(0);
            let e = self
                .hashes
                .get(at.saturating_mul(16)..at.saturating_mul(16).saturating_add(16))?;
            let block = u32_le(e, 12)?;
            if block == 0xffff_ffff {
                return None;
            }
            if u32_le(e, 0) == Some(a) && u32_le(e, 4) == Some(b) && block != 0xffff_fffe {
                return usize::try_from(block).ok();
            }
        }
        None
    }

    /// Reads a file's contents: decrypted and decompressed sector by sector.
    async fn read_file(&self, cx: &Cx, block: &MpqBlock, name: Option<&str>) -> Result<Vec<u8>> {
        use crate::codec::crypto::mpq::{decrypt, file_key};
        let data = self.archive.sub(block.offset.into(), block.packed.into());
        let encrypted = block.flags & MPQ_ENCRYPTED != 0;
        let key = match (encrypted, name) {
            (false, _) => 0,
            (true, Some(n)) => {
                file_key(n, block.offset, block.size, block.flags & MPQ_FIX_KEY != 0)
            }
            (true, None) => {
                return Err(
                    Diagnostic::unsupported("encrypted file whose name is unknown").at(data),
                );
            }
        };
        // Imploded files (an older flag) hold bare DCL streams; compressed
        // ones a mask byte naming the codec.
        let imploded = block.flags & MPQ_IMPLODE != 0;
        let packed = imploded || block.flags & MPQ_COMPRESS != 0;
        let raw = crate::codec::read_all(cx, data).await?;
        let limit = crate::bytes::to_usize(cx.limits().max_derived);
        let unit = |bytes: &[u8], index: u32, expected: usize| -> Result<Vec<u8>> {
            let mut bytes = bytes.to_vec();
            if encrypted {
                decrypt(&mut bytes, key.wrapping_add(index));
            }
            if !packed || bytes.len() >= expected {
                return Ok(bytes);
            }
            let decode = |codec: crate::codec::Codec, body: &[u8]| {
                let mut decoder = codec
                    .decoder()
                    .ok_or_else(|| Diagnostic::internal("no decoder"))?;
                crate::codec::pipeline::decode_all(decoder.as_mut(), body, limit)
            };
            if imploded {
                return decode(crate::codec::Codec::DclImplode, &bytes);
            }
            let (&mask, body) = bytes
                .split_first()
                .ok_or_else(|| Diagnostic::malformed("empty compressed sector"))?;
            match mask {
                0x02 => decode(crate::codec::Codec::Zlib, body),
                0x08 => decode(crate::codec::Codec::DclImplode, body),
                0x10 => decode(crate::codec::Codec::Bzip2, body),
                // StormLib: a 0 (no filter) byte, the 5 LZMA properties
                // bytes and the 8-byte decoded size, then raw LZMA.
                0x12 => {
                    let props = match body.first() {
                        Some(0) => crate::codec::lzma::Props::from_byte(
                            body.get(1).copied().unwrap_or(0xff),
                        )?,
                        _ => return Err(Diagnostic::unsupported("LZMA sector with a filter")),
                    };
                    let codec = crate::codec::Codec::LzmaRaw {
                        props,
                        size: Some(expected),
                        dict: crate::bytes::u32_le(body, 2),
                    };
                    decode(codec, body.get(14..).unwrap_or_default())
                }
                m => Err(Diagnostic::unsupported(format!(
                    "compression mask {m:#04x}"
                ))),
            }
        };
        if block.flags & MPQ_SINGLE_UNIT != 0 {
            return unit(&raw, 0, crate::bytes::to_usize(block.size.into()));
        }
        let sector = crate::bytes::to_usize(self.sector.into()).max(1);
        let size = crate::bytes::to_usize(block.size.into());
        let count = size.div_ceil(sector);
        if !packed {
            // Uncompressed sectors: decrypt each in turn.
            let mut out = Vec::with_capacity(size);
            for (i, chunk) in raw.chunks(sector).enumerate() {
                out.extend(unit(chunk, u32::try_from(i).unwrap_or(0), sector)?);
                cx.checkpoint().await;
            }
            out.truncate(size);
            return Ok(out);
        }
        // A sector offset table (count + 1 entries) precedes the sectors.
        let mut table = raw
            .get(..count.saturating_add(1).saturating_mul(4))
            .ok_or_else(|| Diagnostic::truncated(data.sub(0, 4), 0))?
            .to_vec();
        if encrypted {
            decrypt(&mut table, key.wrapping_sub(1));
        }
        let offsets: Vec<usize> = table
            .as_chunks::<4>()
            .0
            .iter()
            .map(|w| crate::bytes::to_usize(u32::from_le_bytes(*w).into()))
            .collect();
        let mut out = Vec::with_capacity(size);
        for (i, pair) in offsets.windows(2).enumerate() {
            let (&[from, to], expected) = (
                pair,
                sector.min(size.saturating_sub(i.saturating_mul(sector))),
            ) else {
                break;
            };
            let bytes = raw
                .get(from..to)
                .ok_or_else(|| Diagnostic::malformed("sector outside the file").at(data))?;
            out.extend(unit(bytes, u32::try_from(i).unwrap_or(0), expected)?);
            if out.len() > limit {
                return Err(Diagnostic::limit("file exceeds the decoded-data limit"));
            }
            cx.checkpoint().await;
        }
        Ok(out)
    }
}

async fn mpq_files(cx: Cx, state: MpqState) -> Result<()> {
    // Names come from the (listfile), when there is one.
    let mut names: Vec<Option<String>> = vec![None; state.blocks.len()];
    for special in ["(listfile)", "(attributes)", "(signature)"] {
        if let Some(slot) = state.lookup(special).and_then(|i| names.get_mut(i)) {
            *slot = Some(special.to_owned());
        }
    }
    if let Some(block) = state.lookup("(listfile)").and_then(|i| state.blocks.get(i))
        && let Ok(list) = state.read_file(&cx, block, Some("(listfile)")).await
    {
        {
            for name in String::from_utf8_lossy(&list)
                .split([';', '\r', '\n'])
                .filter(|n| !n.is_empty())
            {
                if let Some(i) = state.lookup(name)
                    && let Some(slot) = names.get_mut(i)
                {
                    *slot = Some(name.to_owned());
                }
                cx.checkpoint().await;
            }
        }
    }
    for (i, block) in state.blocks.iter().enumerate() {
        if block.flags & MPQ_EXISTS == 0 {
            continue;
        }
        let name = names.get(i).cloned().flatten();
        let label = name.clone().unwrap_or_else(|| format!("File #{i}"));
        let span = state.archive.sub(block.offset.into(), block.packed.into());
        if span.len < u64::from(block.packed) || span.len == 0 && block.size > 0 {
            cx.push(
                Node::new(name.unwrap_or_else(|| format!("File #{i}")))
                    .span(span)
                    .diag(Diagnostic::malformed(
                        "block outside the archive (a corrupt or wrongly decrypted block table)",
                    )),
            )
            .await;
            continue;
        }
        let mut how = Vec::new();
        if block.flags & MPQ_COMPRESS != 0 {
            how.push("compressed");
        }
        if block.flags & MPQ_IMPLODE != 0 {
            how.push("imploded");
        }
        if block.flags & MPQ_ENCRYPTED != 0 {
            how.push("encrypted");
        }
        let summary = format!(
            "{} → {} bytes{}",
            block.packed,
            block.size,
            if how.is_empty() {
                String::new()
            } else {
                format!(", {}", how.join(", "))
            }
        );
        cx.push(
            Node::new(label)
                .span(span)
                .summary(summary)
                .lazy(mpq_file, (state.clone(), *block, name)),
        )
        .await;
    }
    Ok(())
}

async fn mpq_file(
    cx: Cx,
    (state, block, name): (MpqState, MpqBlock, Option<String>),
) -> Result<()> {
    let span = state.archive.sub(block.offset.into(), block.packed.into());
    let plain = block.flags & (MPQ_COMPRESS | MPQ_IMPLODE | MPQ_ENCRYPTED) == 0;
    let content = if plain {
        span
    } else {
        let data = state.read_file(&cx, &block, name.as_deref()).await?;
        cx.add_derived(
            crate::span::Origin {
                parent: span,
                transform: "mpq-file",
            },
            data,
            span.len,
            None,
        )?
        .span
    };
    crate::formats::dissect_or_data(cx, state.input.nested(content)).await
}

declare_format!(pub RGSSAD = "rgssad", "RPG Maker archive", ["rgssad", "rgss2a", "rgss3a"], "application/x-rgssad",
    Probe::Magic(&[(0, b"RGSSAD\0")]), rgssad);

async fn rgssad(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = head.get(7).copied().unwrap_or(0);
    cx.emit(Node::new("Header").span(file.sub(0, 8)).value(Value::UInt {
        value: version.into(),
        bits: 8,
        radix: crate::value::Radix::Dec,
    }));
    cx.emit(
        Node::new("Encrypted entries")
            .span(file.tail(8))
            .diag(Diagnostic::note("entries are XOR-obfuscated")),
    );
    let engine = match version {
        1 => "RPG Maker XP/VX",
        3 => "RPG Maker VX Ace",
        _ => "RPG Maker",
    };
    cx.annotate(format!("{engine} archive (v{version})"));
    Ok(())
}
