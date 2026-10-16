//! Bethesda archives: BSA (v103 Oblivion, v104 Fallout 3/New Vegas/Skyrim,
//! v105 Skyrim SE) and BA2 (`BTDX`: Fallout 4/76 and Starfield, GNRL and
//! DX10).
//!
//! Layouts as the `ba2` crate (Ryan McKenzie's bsa-rs) reads and writes
//! them (`tes4/archive.rs`, `fo4/archive.rs`), which the fixtures were
//! written with.

use std::sync::Arc;

use crate::bytes::{u16_le, u32_le, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::dsl::{Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::fmt;
use crate::formats::{Input, content, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// BSA

const BSA_FLAGS: FlagTable = &[
    flag(0x1, "DirectoryStrings"),
    flag(0x2, "FileStrings"),
    flag(0x4, "Compressed"),
    flag(0x8, "RetainDirectoryNames"),
    flag(0x10, "RetainFileNames"),
    flag(0x20, "RetainFileNameOffsets"),
    flag(0x40, "XboxArchive"),
    flag(0x80, "RetainStringsDuringStartup"),
    flag(0x100, "EmbeddedFileNames"),
    flag(0x200, "XboxCompressed"),
];

const BSA_TYPES: FlagTable = &[
    flag(0x1, "Meshes"),
    flag(0x2, "Textures"),
    flag(0x4, "Menus"),
    flag(0x8, "Sounds"),
    flag(0x10, "Voices"),
    flag(0x20, "Shaders"),
    flag(0x40, "Trees"),
    flag(0x80, "Fonts"),
    flag(0x100, "Misc"),
];

record! {
    pub struct BsaHeader {
        magic: ascii[4] "Magic",
        version: u32 "Version" .enumeration(&[(103, "Oblivion"), (104, "Fallout 3 / Skyrim"), (105, "Skyrim SE")]),
        offset: u32 "Folder records offset",
        flags: u32 "Archive flags" .flags(BSA_FLAGS),
        folders: u32 "Folders",
        files: u32 "Files",
        folder_names: u32 "Total folder name length",
        file_names: u32 "Total file name length",
        content: u16 "Content flags" .flags(BSA_TYPES),
        _padding: u16 "Padding",
    }
}

const DIRECTORY_STRINGS: u32 = 0x1;
const FILE_STRINGS: u32 = 0x2;
const COMPRESSED: u32 = 0x4;
const XBOX: u32 = 0x40;
const EMBEDDED_NAMES: u32 = 0x100;
/// In a file record's size: compression is the opposite of the archive's
/// default.
const SIZE_TOGGLE: u32 = 0x4000_0000;
const SIZE_CHECKED: u32 = 0x8000_0000;
const OFFSET_SECONDARY: u32 = 0x8000_0000;
const FILE_RECORD: u64 = 16;

/// What the folder and file walkers need from the header.
#[derive(Clone)]
struct Bsa {
    input: Input,
    version: u32,
    flags: u32,
    folders: u32,
    files: u32,
    /// Folder records, the file record blocks and the file name block.
    records: Span,
    blocks: Span,
    names: Span,
}

impl Bsa {
    fn folder_record(&self) -> u64 {
        if self.version >= 105 { 24 } else { 16 }
    }

    fn compressed(&self, size: u32) -> bool {
        (self.flags & COMPRESSED != 0) != (size & SIZE_TOGGLE != 0)
    }

    fn hash_endian(&self) -> Endian {
        if self.flags & XBOX != 0 {
            Endian::Big
        } else {
            LE
        }
    }
}

/// The BSA hash: last char, second-to-last, length, first char, and a
/// 32-bit hash of the rest (big-endian in Xbox archives).
fn bsa_hash(f: &mut Fields<'_>) -> Result<u64> {
    f.u64("Hash").hex().emit()
}

fn folder_record(f: &mut Fields<'_>, version: &u32) -> Result<(u32, u64)> {
    bsa_hash(f)?;
    let count = f.u32("File count").emit()?;
    if *version >= 105 {
        f.u32("Padding").emit()?;
        let offset = f
            .u64("File block offset")
            .hex()
            .desc("Plus the total file name length")
            .emit()?;
        Ok((count, offset))
    } else {
        let offset = f
            .u32("File block offset")
            .hex()
            .desc("Plus the total file name length")
            .emit()?;
        Ok((count, offset.into()))
    }
}

fn file_record(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    bsa_hash(f)?;
    let size = f
        .u32("Size")
        .desc("Bit 30 inverts the archive's compression default for this file")
        .with(|&v, n| {
            if v & (SIZE_TOGGLE | SIZE_CHECKED) == 0 {
                return n.as_size();
            }
            let toggled = if v & SIZE_TOGGLE != 0 {
                ", compression toggled"
            } else {
                ""
            };
            n.summary(format!(
                "{} bytes{toggled}",
                v & !(SIZE_TOGGLE | SIZE_CHECKED)
            ))
        })
        .emit()?;
    let offset = f.u32("Data offset").hex().emit()?;
    Ok((size, offset))
}

pub async fn bsa(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: BsaHeader = emit_record(&cx, file.sub(0, BsaHeader::SIZE), LE).await?;
    let game = match h.version {
        103 => "Oblivion",
        104 => "Fallout 3 / Skyrim",
        105 => "Skyrim SE",
        _ => "unknown game",
    };
    cx.annotate(format!(
        "BSA v{} ({game}), {}, {}{}",
        h.version,
        fmt::plural(h.folders, "folder"),
        fmt::plural(h.files, "file"),
        if h.flags & COMPRESSED != 0 {
            ", compressed"
        } else {
            ""
        }
    ));
    if !(103..=105).contains(&h.version) {
        return Err(Diagnostic::unsupported(format!(
            "BSA version {}",
            h.version
        )));
    }
    let record = if h.version >= 105 { 24 } else { 16 };
    let records = file.sub_exact(h.offset.into(), u64::from(h.folders).saturating_mul(record))?;
    // Each folder's block: its name as a length-prefixed, NUL-terminated
    // string (when folder names are stored), then its file records.
    let names_len = if h.flags & DIRECTORY_STRINGS != 0 {
        u64::from(h.folder_names).saturating_add(h.folders.into())
    } else {
        0
    };
    let blocks_at = records
        .offset
        .saturating_sub(file.offset)
        .saturating_add(records.len);
    let blocks_len = names_len.saturating_add(u64::from(h.files).saturating_mul(FILE_RECORD));
    let blocks = file.sub(blocks_at, blocks_len);
    if blocks.len < blocks_len {
        cx.diag(Diagnostic::truncated(
            Span::new(blocks.source, blocks.offset, blocks_len),
            blocks.len,
        ));
    }
    let names_at = blocks_at.saturating_add(blocks.len);
    let names = if h.flags & FILE_STRINGS != 0 {
        file.sub(names_at, h.file_names.into())
    } else {
        file.sub(names_at, 0)
    };
    let bsa = Bsa {
        input,
        version: h.version,
        flags: h.flags,
        folders: h.folders,
        files: h.files,
        records,
        blocks,
        names,
    };
    cx.emit(
        Node::new("Folder records")
            .span(records)
            .summary(fmt::plural(h.folders, "folder"))
            .lazy(bsa_folder_records, bsa.clone()),
    );
    cx.emit(
        Node::new("File record blocks")
            .span(blocks)
            .lazy(bsa_file_records, bsa.clone()),
    );
    if names.len > 0 {
        cx.emit(Node::new("File names").span(names));
    }
    cx.emit(
        Node::new("Folders")
            .summary(fmt::plural(h.files, "file"))
            .lazy(bsa_folders, bsa),
    );
    Ok(())
}

async fn bsa_folder_records(cx: Cx, bsa: Bsa) -> Result<()> {
    let size = bsa.folder_record();
    cx.set_count(Count::Exact(bsa.folders.into()));
    for i in 0..u64::from(bsa.folders) {
        let span = bsa.records.sub(i.saturating_mul(size), size);
        cx.push(struct_node(
            format!("Folder {i}"),
            span,
            bsa.hash_endian(),
            bsa.version,
            folder_record,
        ))
        .await;
    }
    Ok(())
}

/// One folder's place in the file record blocks.
#[derive(Clone)]
struct Folder {
    name: String,
    block: Span,
    records: Span,
    /// Index of the folder's first file in the file name block.
    first: u64,
}

/// Splits the file record blocks into folders, once.
async fn bsa_layout(cx: &Cx, bsa: &Bsa) -> Result<Arc<Vec<Folder>>> {
    if let Some(folders) = cx.cached::<Vec<Folder>>(bsa.blocks, "bsa-folders") {
        return Ok(folders);
    }
    let records = cx.read(bsa.records).await?;
    let blocks = cx.read(bsa.blocks).await?;
    let size = crate::bytes::to_usize(bsa.folder_record());
    let mut out = Vec::new();
    let mut at = 0usize;
    let mut first = 0u64;
    for (i, record) in records.chunks_exact(size).enumerate() {
        if i % 256 == 255 {
            cx.checkpoint().await;
        }
        let count = u32_le(record, 8).unwrap_or(0);
        let start = at;
        let name = if bsa.flags & DIRECTORY_STRINGS != 0 {
            let len = usize::from(blocks.get(at).copied().unwrap_or(0));
            let text = blocks
                .get(at.saturating_add(1)..at.saturating_add(1).saturating_add(len))
                .map(crate::text::until_nul)
                .unwrap_or_default();
            at = at.saturating_add(1).saturating_add(len);
            text
        } else {
            format!("Folder {i}")
        };
        let len = u64::from(count).saturating_mul(FILE_RECORD);
        let records_at = crate::bytes::to_u64(at);
        at = at.saturating_add(crate::bytes::to_usize(len));
        out.push(Folder {
            name,
            block: bsa.blocks.sub(
                crate::bytes::to_u64(start),
                crate::bytes::to_u64(at.saturating_sub(start)),
            ),
            records: bsa.blocks.sub(records_at, len),
            first,
        });
        first = first.saturating_add(count.into());
    }
    let out = Arc::new(out);
    cx.cache(bsa.blocks, "bsa-folders", out.clone());
    Ok(out)
}

/// The file name block's names, once.
async fn bsa_names(cx: &Cx, bsa: &Bsa) -> Result<Arc<Vec<String>>> {
    if let Some(names) = cx.cached::<Vec<String>>(bsa.names, "bsa-names") {
        return Ok(names);
    }
    let data = cx.read(bsa.names).await?;
    let mut names = Vec::new();
    for (i, name) in data.split(|&b| b == 0).enumerate() {
        if i % 1024 == 1023 {
            cx.checkpoint().await;
        }
        if crate::bytes::to_u64(names.len()) >= u64::from(bsa.files) {
            break;
        }
        names.push(crate::text::latin1(name));
    }
    let names = Arc::new(names);
    cx.cache(bsa.names, "bsa-names", names.clone());
    Ok(names)
}

async fn bsa_file_records(cx: Cx, bsa: Bsa) -> Result<()> {
    let folders = bsa_layout(&cx, &bsa).await?;
    let names = bsa_names(&cx, &bsa).await?;
    cx.set_count(Count::Exact(bsa.files.into()));
    for folder in folders.iter() {
        let count = folder.records.len.checked_div(FILE_RECORD).unwrap_or(0);
        for i in 0..count {
            let index = folder.first.saturating_add(i);
            let name = usize::try_from(index)
                .ok()
                .and_then(|n| names.get(n))
                .map_or_else(
                    || format!("File {index}"),
                    |n| format!("{}\\{n}", folder.name),
                );
            let span = folder
                .records
                .sub(i.saturating_mul(FILE_RECORD), FILE_RECORD);
            cx.push(struct_node(name, span, bsa.hash_endian(), (), file_record))
                .await;
        }
    }
    Ok(())
}

async fn bsa_folders(cx: Cx, bsa: Bsa) -> Result<()> {
    let folders = bsa_layout(&cx, &bsa).await?;
    cx.set_count(Count::Exact(crate::bytes::to_u64(folders.len())));
    for (i, folder) in folders.iter().enumerate() {
        let files = folder.records.len / FILE_RECORD;
        cx.push(
            Node::new(folder.name.clone())
                .span(folder.block)
                .summary(fmt::plural(files, "file"))
                .lazy(bsa_folder, (bsa.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn bsa_folder(cx: Cx, (bsa, index): (Bsa, usize)) -> Result<()> {
    let folders = bsa_layout(&cx, &bsa).await?;
    let Some(folder) = folders.get(index) else {
        return Ok(());
    };
    let names = bsa_names(&cx, &bsa).await?;
    let records = cx.read(folder.records).await?;
    let count = folder.records.len / FILE_RECORD;
    cx.set_count(Count::Exact(count));
    let file = bsa.input.span;
    for (i, record) in records.as_chunks::<16>().0.iter().enumerate() {
        let span = folder.records.sub(
            crate::bytes::to_u64(i).saturating_mul(FILE_RECORD),
            FILE_RECORD,
        );
        let size_raw = u32_le(record, 8).unwrap_or(0);
        let offset = u32_le(record, 12).unwrap_or(0) & !OFFSET_SECONDARY;
        let size = u64::from(size_raw & !(SIZE_TOGGLE | SIZE_CHECKED));
        let index = folder.first.saturating_add(crate::bytes::to_u64(i));
        let mut name = usize::try_from(index)
            .ok()
            .and_then(|n| names.get(n))
            .cloned()
            .unwrap_or_else(|| format!("File {index}"));
        let mut data = file.sub(offset.into(), size);
        let mut prefix = 0u64;
        // v104/v105 with embedded names: the data starts with the full path
        // as a length-prefixed string.
        if bsa.version >= 104 && bsa.flags & EMBEDDED_NAMES != 0 {
            let head = cx.read(data.sub(0, 1)).await?;
            let len = u64::from(head.first().copied().unwrap_or(0));
            let path = cx.read(data.sub(1, len)).await?;
            let path = crate::text::latin1(&path);
            if let Some(last) = path.rsplit(['\\', '/']).next()
                && names.is_empty()
            {
                name = last.to_owned();
            }
            prefix = len.saturating_add(1);
        }
        let compressed = bsa.compressed(size_raw);
        let node = if compressed {
            let head = cx.read(data.sub(prefix, 4)).await?;
            let original = u32_le(&head, 0).unwrap_or(0);
            let body = data.sub(
                prefix.saturating_add(4),
                size.saturating_sub(prefix.saturating_add(4)),
            );
            let codec = if bsa.version >= 105 {
                Codec::Lz4Frame
            } else {
                Codec::Zlib
            };
            let method = if bsa.version >= 105 { "LZ4" } else { "zlib" };
            content(name, bsa.input, body, codec, Some(original.into()))
                .summary(format!("{}, {method}", fmt::size(original.into())))
        } else {
            data = data.sub(prefix, size.saturating_sub(prefix));
            embedded(name, bsa.input.nested(data)).summary(fmt::size(data.len))
        };
        cx.push(node.target(span)).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// BA2

const BA2_CHUNK_SENTINEL: u32 = 0xbaad_f00d;

#[derive(Clone)]
struct Ba2 {
    input: Input,
    kind: [u8; 4],
    files: u32,
    lz4: bool,
    records: u64,
    names: Option<Span>,
}

/// The BA2 header: magic, version, type, file count and name table offset;
/// v2 and v3 (Starfield) add 8 bytes, v3 a compression method.
fn ba2_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32, u64, bool)> {
    f.ascii("Magic", 4).emit()?;
    let version = f.u32("Version").emit()?;
    f.ascii("Type", 4)
        .desc("GNRL (general), DX10 (textures) or GNMF (PS4 textures)")
        .emit()?;
    let files = f.u32("Files").emit()?;
    let names = f.u64("Name table offset").hex().emit()?;
    if version == 2 || version == 3 {
        f.u64("Unknown").hex().emit()?;
    }
    let lz4 = version == 3
        && f.u32("Compression")
            .enumeration(&[(0, "zlib"), (3, "LZ4")])
            .emit()?
            == 3;
    Ok((version, files, names, lz4))
}

pub async fn ba2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let version = u32_le(&head, 4).unwrap_or(0);
    let header_len: u64 = match version {
        2 => 0x20,
        3 => 0x24,
        _ => 0x18,
    };
    let header = file.sub(0, header_len);
    let (version, files, names, lz4) =
        crate::fields::parse(&cx, header, LE, &(), ba2_header).await?;
    cx.emit(struct_node("Header", header, LE, (), ba2_header));
    let raw = cx.read(file.sub(8, 4)).await?;
    let mut kind = [0u8; 4];
    for (k, b) in kind.iter_mut().zip(raw.iter()) {
        *k = *b;
    }
    let kind_text = String::from_utf8_lossy(&kind).into_owned();
    let names = (names > 0).then(|| file.tail(names));
    let ba2 = Ba2 {
        input,
        kind,
        files,
        lz4,
        records: header_len,
        names,
    };
    cx.emit(
        Node::new("Files")
            .summary(fmt::plural(files, "file"))
            .lazy(ba2_files, ba2),
    );
    if let Some(names) = names {
        cx.emit(Node::new("Name table").span(names));
    }
    cx.annotate(format!(
        "BA2 v{version} {kind_text}, {}{}",
        fmt::plural(files, "file"),
        if lz4 { ", LZ4" } else { "" }
    ));
    Ok(())
}

/// The name table's names (u16 length, then the bytes), once.
async fn ba2_names(cx: &Cx, ba2: &Ba2) -> Result<Arc<Vec<String>>> {
    let Some(span) = ba2.names else {
        return Ok(Arc::new(Vec::new()));
    };
    if let Some(names) = cx.cached::<Vec<String>>(span, "ba2-names") {
        return Ok(names);
    }
    let data = cx.read(span).await?;
    let mut names = Vec::new();
    let mut at = 0usize;
    while crate::bytes::to_u64(names.len()) < u64::from(ba2.files) {
        let Some(len) = u16_le(&data, at) else { break };
        let start = at.saturating_add(2);
        let end = start.saturating_add(usize::from(len));
        let Some(name) = data.get(start..end) else {
            break;
        };
        names.push(crate::text::latin1(name));
        at = end;
        if names.len() % 1024 == 1023 {
            cx.checkpoint().await;
        }
    }
    let names = Arc::new(names);
    cx.cache(span, "ba2-names", names.clone());
    Ok(names)
}

/// A file record: name hash, extension, directory hash, flags, chunk count
/// and chunk header size, then (DX10) the texture header.
fn ba2_record(f: &mut Fields<'_>, kind: &[u8; 4]) -> Result<u8> {
    f.u32("Name hash").hex().emit()?;
    f.ascii("Extension", 4).emit()?;
    f.u32("Directory hash").hex().emit()?;
    f.u8("Flags").hex().emit()?;
    let chunks = f.u8("Chunks").emit()?;
    f.u16("Chunk header size").emit()?;
    match kind {
        b"DX10" => {
            f.u16("Height").emit()?;
            f.u16("Width").emit()?;
            f.u8("Mip count").emit()?;
            f.u8("DXGI format").emit()?;
            f.u8("Flags").hex().emit()?;
            f.u8("Tile mode").emit()?;
        }
        b"GNMF" => {
            f.bytes("GNM metadata", 32).emit()?;
        }
        _ => {}
    }
    Ok(chunks)
}

fn ba2_chunk(f: &mut Fields<'_>, kind: &[u8; 4]) -> Result<()> {
    f.u64("Data offset").hex().emit()?;
    f.u32("Stored size")
        .desc("0 if stored uncompressed")
        .emit()?;
    f.u32("Size").emit()?;
    if kind != b"GNRL" {
        f.u16("First mip").emit()?;
        f.u16("Last mip").emit()?;
    }
    f.u32("Sentinel")
        .hex()
        .check(|&v| {
            (v != BA2_CHUNK_SENTINEL)
                .then(|| Diagnostic::malformed(format!("chunk sentinel {v:#x}")))
        })
        .emit()?;
    Ok(())
}

/// The content of a chunk: stored, zlib or (Starfield) a raw LZ4 block.
fn ba2_chunk_node(ba2: &Ba2, name: String, chunk: &[u8]) -> Node {
    let file = ba2.input.span;
    let offset = u64_le(chunk, 0).unwrap_or(0);
    let stored = u32_le(chunk, 8).unwrap_or(0);
    let size = u32_le(chunk, 12).unwrap_or(0);
    if stored == 0 {
        let span = file.sub(offset, size.into());
        return embedded(name, ba2.input.nested(span)).summary(fmt::size(size.into()));
    }
    let span = file.sub(offset, stored.into());
    let (codec, method) = if ba2.lz4 {
        (Codec::Lz4Block, "LZ4")
    } else {
        (Codec::Zlib, "zlib")
    };
    content(name, ba2.input, span, codec, Some(size.into()))
        .summary(format!("{}, {method}", fmt::size(size.into())))
}

async fn ba2_files(cx: Cx, ba2: Ba2) -> Result<()> {
    let file = ba2.input.span;
    let names = ba2_names(&cx, &ba2).await?;
    let (header, chunk_size): (u64, u64) = match &ba2.kind {
        b"GNRL" => (16, 20),
        b"DX10" => (24, 24),
        b"GNMF" => (48, 24),
        _ => return Err(Diagnostic::unsupported("BA2 type")),
    };
    cx.set_count(Count::Exact(ba2.files.into()));
    let (mut at, start) = cx.resume::<(u64, u32)>().unwrap_or((ba2.records, 0));
    for i in start..ba2.files {
        let mark = (at, i);
        cx.mark(move || mark);
        let head = cx.read(file.sub_exact(at, header)?).await?;
        let chunks = u64::from(head.get(13).copied().unwrap_or(0));
        let record =
            file.sub_exact(at, header.saturating_add(chunks.saturating_mul(chunk_size)))?;
        let data = cx.read(record).await?;
        let name = usize::try_from(i)
            .ok()
            .and_then(|n| names.get(n))
            .cloned()
            .unwrap_or_else(|| format!("File {i}"));
        let node = if &ba2.kind == b"GNRL" && chunks == 1 {
            let chunk = data.get(16..).unwrap_or_default();
            ba2_chunk_node(&ba2, name, chunk)
        } else {
            let summary = match &ba2.kind {
                b"DX10" => format!(
                    "{}x{}, {} mips, DXGI format {}, {}",
                    u16_le(&data, 18).unwrap_or(0),
                    u16_le(&data, 16).unwrap_or(0),
                    data.get(20).copied().unwrap_or(0),
                    data.get(21).copied().unwrap_or(0),
                    fmt::plural(chunks, "chunk")
                ),
                _ => fmt::plural(chunks, "chunk"),
            };
            Node::new(name)
                .summary(summary)
                .lazy(ba2_file_chunks, (ba2.clone(), record, header, chunk_size))
        };
        cx.push(node.target(record)).await;
        at = at.saturating_add(record.len);
    }
    Ok(())
}

/// A file's record fields, then each chunk's fields and content.
async fn ba2_file_chunks(
    cx: Cx,
    (ba2, record, header, chunk_size): (Ba2, Span, u64, u64),
) -> Result<()> {
    cx.emit(struct_node(
        "Record",
        record.sub(0, header),
        LE,
        ba2.kind,
        ba2_record,
    ));
    let data = cx.read(record).await?;
    let chunks = record
        .len
        .saturating_sub(header)
        .checked_div(chunk_size)
        .unwrap_or(0);
    for c in 0..chunks {
        let at = header.saturating_add(c.saturating_mul(chunk_size));
        let raw = data
            .get(crate::bytes::to_usize(at)..crate::bytes::to_usize(at.saturating_add(chunk_size)))
            .unwrap_or_default();
        let title = if &ba2.kind == b"GNRL" {
            format!("Chunk {c}")
        } else {
            format!(
                "Mips {}-{}",
                u16_le(raw, 16).unwrap_or(0),
                u16_le(raw, 18).unwrap_or(0)
            )
        };
        cx.emit(struct_node(
            format!("{title} record"),
            record.sub(at, chunk_size),
            LE,
            ba2.kind,
            ba2_chunk,
        ));
        cx.emit(ba2_chunk_node(&ba2, title, raw));
    }
    if &ba2.kind == b"DX10" && chunks > 0 {
        cx.emit(ba2_texture(&cx, &ba2, record, &data, header, chunk_size)?);
    }
    Ok(())
}

/// A DX10 texture as a DDS file, as Archive2 extracts it: a synthesized
/// header (with the DX10 extension, which names any DXGI format) followed
/// by the chunks' mips in order, as pieces of the archive (stored chunks)
/// and of their lazily decoded contents.
fn ba2_texture(
    cx: &Cx,
    ba2: &Ba2,
    record: Span,
    data: &[u8],
    header: u64,
    chunk_size: u64,
) -> Result<Node> {
    let file = ba2.input.span;
    let height = u16_le(data, 16).unwrap_or(0);
    let width = u16_le(data, 18).unwrap_or(0);
    let mips = data.get(20).copied().unwrap_or(0);
    let format = data.get(21).copied().unwrap_or(0);
    let cubemap = data.get(22).is_some_and(|f| f & 1 != 0);
    let dds = dds_header(width, height, mips, format, cubemap);
    let dds_len = crate::bytes::to_u64(dds.len());
    let head = cx.add_derived(
        crate::span::Origin {
            parent: record,
            transform: "ba2 DDS header",
        },
        dds,
        0,
        None,
    )?;
    let mut pieces = vec![head.span.sub(0, dds_len)];
    let chunks = record
        .len
        .saturating_sub(header)
        .checked_div(chunk_size)
        .unwrap_or(0);
    let mut total = dds_len;
    for c in 0..chunks {
        let at = crate::bytes::to_usize(header.saturating_add(c.saturating_mul(chunk_size)));
        let raw = data.get(at..).unwrap_or_default();
        let offset = u64_le(raw, 0).unwrap_or(0);
        let stored = u32_le(raw, 8).unwrap_or(0);
        let size = u64::from(u32_le(raw, 12).unwrap_or(0));
        let piece = if stored == 0 {
            file.sub_exact(offset, size)?
        } else {
            let codec = if ba2.lz4 {
                Codec::Lz4Block
            } else {
                Codec::Zlib
            };
            cx.decode_lazy(file.sub_exact(offset, stored.into())?, &codec, size)?
        };
        total = total.saturating_add(piece.len);
        pieces.push(piece);
    }
    let span = cx.add_pieces(
        crate::span::Origin {
            parent: record,
            transform: "ba2 DDS",
        },
        pieces,
    )?;
    Ok(
        crate::formats::embedded_named("Texture", ba2.input.nested(span), "dds")
            .summary(format!("rebuilt DDS file, {}", fmt::size(total))),
    )
}

/// A DDS header for a BA2 texture: magic, `DDS_HEADER` with a "DX10" pixel
/// format and `DDS_HEADER_DXT10`.
fn dds_header(width: u16, height: u16, mips: u8, format: u8, cubemap: bool) -> Vec<u8> {
    const CAPS: u32 = 0x1;
    const HEIGHT: u32 = 0x2;
    const WIDTH: u32 = 0x4;
    const PIXELFORMAT: u32 = 0x1000;
    const MIPMAPCOUNT: u32 = 0x2_0000;
    const DDPF_FOURCC: u32 = 0x4;
    const CAPS_COMPLEX: u32 = 0x8;
    const CAPS_TEXTURE: u32 = 0x1000;
    const CAPS_MIPMAP: u32 = 0x40_0000;
    const CAPS2_CUBEMAP_ALL: u32 = 0xfe00;
    let mut caps = CAPS_TEXTURE;
    if mips > 1 {
        caps |= CAPS_MIPMAP | CAPS_COMPLEX;
    }
    if cubemap {
        caps |= CAPS_COMPLEX;
    }
    let mut out = Vec::with_capacity(148);
    out.extend_from_slice(b"DDS ");
    let words_before_pf = [
        124,
        CAPS | HEIGHT | WIDTH | PIXELFORMAT | MIPMAPCOUNT,
        u32::from(height),
        u32::from(width),
        0,
        0,
        u32::from(mips),
    ];
    for w in words_before_pf {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(&[0; 44]);
    for w in [32, DDPF_FOURCC] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out.extend_from_slice(b"DX10");
    out.extend_from_slice(&[0; 20]);
    let caps2 = if cubemap { CAPS2_CUBEMAP_ALL } else { 0 };
    for w in [caps, caps2, 0, 0, 0] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    // DDS_HEADER_DXT10: format, TEXTURE2D, TEXTURECUBE flag, array size 1.
    let misc = if cubemap { 0x4 } else { 0 };
    for w in [u32::from(format), 3, misc, 1, 0] {
        out.extend_from_slice(&w.to_le_bytes());
    }
    out
}
