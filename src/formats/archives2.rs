//! Game and console archive formats, plus a few audio-production files.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, emit_record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

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

async fn psarc(cx: Cx, input: Input) -> Result<()> {
    let h: PsarcHeader = emit_record(&cx, input.span.sub(0, PsarcHeader::SIZE), BE).await?;
    cx.emit(Node::new("Table of contents").span(input.span.sub(
        PsarcHeader::SIZE,
        u64::from(h.toc_length).saturating_sub(PsarcHeader::SIZE),
    )));
    cx.emit(
        Node::new("Data blocks")
            .span(input.span.tail(h.toc_length.into()))
            .diag(Diagnostic::unsupported(format!(
                "{} compression",
                h.compression
            ))),
    );
    cx.annotate(format!(
        "PSARC {}.{}, {} entries, {}",
        h.major, h.minor, h.entries, h.compression
    ));
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
    let mut node = Node::new("Content").span(file.tail(10));
    if flags & 0xc0 != 0 {
        node = node.diag(Diagnostic::unsupported("LZX/LZ4-compressed content"));
    }
    cx.emit(node);
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
    cx.emit(
        Node::new("Hash table")
            .span(file.sub(
                base.saturating_add(h.hash_table.into()),
                u64::from(h.hash_entries).saturating_mul(16),
            ))
            .diag(Diagnostic::note("encrypted with the MPQ hash key")),
    );
    cx.emit(
        Node::new("Block table")
            .span(file.sub(
                base.saturating_add(h.block_table.into()),
                u64::from(h.block_entries).saturating_mul(16),
            ))
            .diag(Diagnostic::note("encrypted with the MPQ block key")),
    );
    cx.annotate(format!(
        "MPQ v{}, {} blocks, {}-byte sectors",
        u32::from(h.version).saturating_add(1),
        h.block_entries,
        512u32.checked_shl(h.block_size.into()).unwrap_or(0)
    ));
    Ok(())
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

// ---------------------------------------------------------------------------
// VST presets (FXP/FXB), FL Studio projects, Guitar Pro

declare_format!(pub FXP = "fxp", "VST preset / bank", ["fxp", "fxb"], "application/x-vst-preset",
    Probe::Magic(&[(0, b"CcnK")]), fxp);

const FXP_KINDS: EnumTable = &[
    (0x4678_4363, "FxCk (regular preset)"),
    (0x4650_6368, "FPCh (opaque preset chunk)"),
    (0x4678_426b, "FxBk (regular bank)"),
    (0x4642_4368, "FBCh (opaque bank chunk)"),
];

async fn fxp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 56)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Chunk magic", 4).emit()?;
    f.u32("Byte size").emit()?;
    let kind = f.u32("FX magic").enumeration(FXP_KINDS).emit()?;
    f.u32("Format version").emit()?;
    let plugin = f.ascii("Plugin ID", 4).emit()?;
    f.u32("Plugin version").emit()?;
    let count = f.u32("Parameters / programs").emit()?;
    let name = if kind == 0x4678_4363 || kind == 0x4650_6368 {
        f.ascii("Program name", 28).emit()?
    } else {
        String::new()
    };
    cx.emit(Node::new("Data").span(file.tail(f.pos())));
    cx.annotate(format!(
        "{} for plugin '{plugin}', {count} entries{}",
        lookup(FXP_KINDS, kind.into()).unwrap_or("VST data"),
        if name.is_empty() {
            String::new()
        } else {
            format!(", {name:?}")
        }
    ));
    Ok(())
}

declare_format!(pub FLP = "flp", "FL Studio project", ["flp"], "application/x-flp",
    Probe::Magic(&[(0, b"FLhd")]), flp);

async fn flp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 4).emit()?;
    f.u32("Header length").emit()?;
    f.u16("Format").emit()?;
    let channels = f.u16("Channels").emit()?;
    let ppq = f.u16("Pulses per quarter note").emit()?;
    let data = cx.read(file.sub(14, 8)).await?;
    let len = u32_le(&data, 4).unwrap_or(0);
    let events = file.sub(22, len.into());
    cx.emit(
        Node::new("Events (FLdt)")
            .span(events)
            .lazy(flp_events, events),
    );
    cx.annotate(format!("FL Studio project, {channels} channels, {ppq} PPQ"));
    Ok(())
}

async fn flp_events(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        let size: u64 = match id {
            0..=63 => 1,
            64..=127 => 2,
            128..=191 => 4,
            _ => {
                // Variable length: 7-bit varint size.
                let mut len = 0u64;
                for i in 0..4u32 {
                    let b = cur.u8().await?;
                    len |= u64::from(b & 0x7f)
                        .checked_shl(i.saturating_mul(7))
                        .unwrap_or(0);
                    if b & 0x80 == 0 {
                        break;
                    }
                }
                len
            }
        };
        let body = cur.span(size);
        cur.skip(size);
        let mut node = Node::new(format!("Event {id}")).span(cur.since(start));
        if id >= 192 && size < 256 {
            let text = cx.read_avail(body).await?;
            if text.len() >= 2 && text.get(1) == Some(&0) {
                node = node.summary(crate::text::utf16z(&text, LE).0);
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

fn guitar_pro_probe(h: &Head<'_>) -> bool {
    h.at(1, b"FICHIER GUITAR PRO") || h.at(1, b"FICHIER GUITARE PRO")
}

declare_format!(pub GUITAR_PRO = "guitar-pro", "Guitar Pro tablature", ["gp3", "gp4", "gp5", "gtp"], "application/x-guitar-pro",
    Probe::Custom(guitar_pro_probe), guitar_pro);

async fn guitar_pro(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 31)).await?;
    let len = usize::from(head.first().copied().unwrap_or(0)).min(30);
    let version =
        String::from_utf8_lossy(head.get(1..1usize.saturating_add(len)).unwrap_or_default())
            .into_owned();
    cx.emit(
        Node::new("Version")
            .span(file.sub(0, 31))
            .value(Value::Text(version.clone())),
    );
    // Then: title as an int-length-prefixed byte string.
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(31);
    let mut fields = Vec::new();
    for name in ["Title", "Subtitle", "Artist", "Album"] {
        let start = cur.pos();
        let _total = cur.u32().await?;
        let len = cur.u8().await?;
        let text = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
        cx.emit(
            Node::new(name)
                .span(cur.since(start))
                .value(Value::Text(text.clone())),
        );
        fields.push(text);
    }
    cx.emit(Node::new("Song data").span(file.tail(cur.pos())));
    cx.annotate(format!(
        "{version}: {:?} by {}",
        fields.first().cloned().unwrap_or_default(),
        fields.get(2).cloned().unwrap_or_default()
    ));
    Ok(())
}
