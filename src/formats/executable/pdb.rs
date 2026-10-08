//! Microsoft program databases (PDB) in the MSF 7.00 container.
//!
//! MSF is a small block-based file system: a superblock points at the block
//! list of the stream directory, which lists every stream's size and blocks.
//! Each stream (and the directory itself) becomes a piecewise source, so
//! streams read as contiguous bytes while spans still resolve to file
//! offsets.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};

const LE: Endian = Endian::Little;

declare_format!(pub PDB = "pdb", "Microsoft program database (PDB)", ["pdb"], "application/x-ms-pdb",
    Probe::Magic(&[(0, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")]), pdb);

declare_format!(pub PDB2 = "pdb2", "Microsoft program database (MSF 2.00)", ["pdb"], "application/x-ms-pdb",
    Probe::Magic(&[(0, b"Microsoft C/C++ program database 2.00\r\n\x1aJG\0\0")]), pdb2);

record! {
    pub struct SuperBlock {
        magic: ascii[32] "Magic",
        block_size: u32 "Block size",
        free_map: u32 "Free block map block",
        blocks: u32 "Number of blocks",
        directory_bytes: u32 "Stream directory size",
        _unknown: u32 "Unknown",
        block_map: u32 "Stream directory block map address",
    }
}

const PDB_VERSIONS: EnumTable = &[
    (19_941_610, "VC2"),
    (19_950_623, "VC4"),
    (19_950_814, "VC41"),
    (19_960_307, "VC50"),
    (19_970_604, "VC98"),
    (19_990_604, "VC70 (dep)"),
    (20_000_404, "VC70"),
    (20_030_901, "VC80"),
    (20_091_201, "VC110"),
    (20_140_508, "VC140"),
];

const MACHINES: EnumTable = &[
    (0x14c, "x86"),
    (0x8664, "x64"),
    (0xaa64, "ARM64"),
    (0x1c4, "ARMNT"),
    (0x200, "IA64"),
];

/// Fixed stream numbers.
const STREAM_NAMES: [&str; 5] = [
    "Old directory",
    "PDB info",
    "Type info (TPI)",
    "Debug info (DBI)",
    "ID info (IPI)",
];

/// The blocks of a stream as file spans.
fn stream_pieces(file: Span, block_size: u64, blocks: &[u32], len: u64) -> Vec<Span> {
    let mut remaining = len;
    blocks
        .iter()
        .map(|&b| {
            let take = remaining.min(block_size);
            remaining = remaining.saturating_sub(take);
            file.sub(u64::from(b).saturating_mul(block_size), take)
        })
        .collect()
}

async fn pdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sb: SuperBlock = read_record(&cx, file.sub(0, SuperBlock::SIZE), LE).await?;
    cx.emit(SuperBlock::node(
        "Superblock",
        file.sub(0, SuperBlock::SIZE),
        LE,
    ));
    let block_size = u64::from(sb.block_size);
    if !matches!(block_size, 512 | 1024 | 2048 | 4096 | 8192 | 16384 | 32768) {
        return Err(Diagnostic::malformed(format!(
            "unexpected block size {block_size}"
        )));
    }
    // The block map lists the blocks holding the stream directory.
    let directory_blocks = u64::from(sb.directory_bytes).div_ceil(block_size);
    let map = cx
        .read(file.sub_exact(
            u64::from(sb.block_map).saturating_mul(block_size),
            directory_blocks.saturating_mul(4),
        )?)
        .await?;
    let map: Vec<u32> = (0..to_usize(directory_blocks))
        .filter_map(|i| u32_le(&map, i.saturating_mul(4)))
        .collect();
    let directory = cx.add_pieces(
        Origin {
            parent: file,
            transform: "msf-directory",
        },
        stream_pieces(file, block_size, &map, sb.directory_bytes.into()),
    )?;
    let dir = cx.read(directory).await?;
    let count = u32_le(&dir, 0).unwrap_or(0);
    let count_usize = to_usize(count.into());
    if to_u64(count_usize).saturating_mul(4) > directory.len {
        return Err(Diagnostic::malformed("stream count exceeds the directory"));
    }
    let sizes: Vec<u32> = (0..count_usize)
        .filter_map(|i| u32_le(&dir, 4usize.saturating_add(i.saturating_mul(4))))
        .collect();
    let mut at = 4usize.saturating_add(count_usize.saturating_mul(4));
    let mut streams = Vec::new();
    for (i, &size) in sizes.iter().enumerate() {
        cx.checkpoint().await;
        // Deleted streams have size 0xffffffff and no blocks.
        let len = if size == u32::MAX { 0 } else { u64::from(size) };
        let n = to_usize(len.div_ceil(block_size));
        // Only the block numbers the directory holds: a bogus size must not
        // cost a pass over millions of missing ones.
        let have = n.min(dir.len().saturating_sub(at) / 4);
        let blocks: Vec<u32> = (0..have)
            .filter_map(|j| u32_le(&dir, at.saturating_add(j.saturating_mul(4))))
            .collect();
        at = at.saturating_add(n.saturating_mul(4));
        // Each stream needs its own memo key: use the directory source with
        // the stream number as the (empty) parent offset.
        let key = Span::new(directory.source, u64::try_from(i).unwrap_or(0), 0);
        let span = cx.add_pieces(
            Origin {
                parent: key,
                transform: "msf-stream",
            },
            stream_pieces(file, block_size, &blocks, len),
        )?;
        streams.push((size, span));
    }
    cx.emit(
        Node::new("Stream directory")
            .span(directory)
            .summary(format!("{count} streams")),
    );

    let mut summary = format!("PDB, {count} streams");
    if let Some((_, info)) = streams.get(1) {
        let block = cx.block(info.sub(0, 28)).await?;
        let mut f = Fields::new(&block, LE);
        let version = f.u32("Version").get()?;
        let _signature = f.u32("Signature").get()?;
        let age = f.u32("Age").get()?;
        let guid = f.guid("GUID").get()?;
        summary = format!(
            "PDB {}, GUID {guid}, age {age}",
            lookup(PDB_VERSIONS, version.into()).unwrap_or("unknown version")
        );
    }
    if let Some((_, dbi)) = streams.get(3)
        && dbi.len >= 64
    {
        let header = cx.read(dbi.sub(0, 64)).await?;
        let machine = crate::bytes::u16_le(&header, 58).unwrap_or(0);
        if let Some(m) = lookup(MACHINES, machine.into()) {
            summary = format!("{summary}, {m}");
        }
    }
    cx.emit(
        Node::new("Streams")
            .summary(format!("{count} streams"))
            .lazy(pdb_streams, (input, streams)),
    );
    cx.annotate(summary);
    Ok(())
}

async fn pdb_streams(cx: Cx, (input, streams): (Input, Vec<(u32, Span)>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(streams.len())));
    for (i, (size, span)) in streams.into_iter().enumerate() {
        let name = STREAM_NAMES
            .get(i)
            .map_or_else(|| format!("Stream {i}"), |n| format!("Stream {i}: {n}"));
        let node = if size == u32::MAX {
            Node::new(name).summary("deleted")
        } else if i == 1 {
            Node::new(name)
                .span(span)
                .summary(format!("{size} bytes"))
                .lazy(pdb_info, span)
        } else if i == 3 {
            Node::new(name)
                .span(span)
                .summary(format!("{size} bytes"))
                .lazy(dbi_header, span)
        } else {
            embedded(name, input.nested(span)).summary(format!("{size} bytes"))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn pdb_info(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Version").enumeration(PDB_VERSIONS).emit()?;
    f.u32("Signature").timestamp().emit()?;
    f.u32("Age").emit()?;
    f.guid("GUID")
        .desc("Matches the CodeView record of the image")
        .emit()?;
    let names_len = f.u32("Named stream map: string buffer size").emit()?;
    let strings = span.sub(32, names_len.into());
    let text = cx.read_avail(strings).await?;
    let names: Vec<String> = text
        .split(|&b| b == 0)
        .filter(|s| !s.is_empty())
        .map(|s| String::from_utf8_lossy(s).into_owned())
        .collect();
    cx.emit(
        Node::new("Named streams")
            .span(strings)
            .value(Value::Text(names.join(", "))),
    );
    Ok(())
}

record! {
    pub struct DbiHeader {
        signature: i32 "Version signature",
        version: u32 "Version header",
        age: u32 "Age",
        globals: u16 "Global symbol stream index",
        build: u16 "Build number" .hex(),
        publics: u16 "Public symbol stream index",
        dll_version: u16 "PDB DLL version",
        symbols: u16 "Symbol record stream index",
        dll_rbld: u16 "PDB DLL rebuild",
        module_info_size: i32 "Module info size",
        section_contribution_size: i32 "Section contribution size",
        section_map_size: i32 "Section map size",
        source_info_size: i32 "Source info size",
        type_server_map_size: i32 "Type server map size",
        mfc_index: u32 "MFC type server index",
        debug_header_size: i32 "Optional debug header size",
        ec_size: i32 "EC substream size",
        flags: u16 "Flags" .hex(),
        machine: u16 "Machine" .enumeration(MACHINES),
        _padding: u32 "Padding",
    }
}

async fn dbi_header(cx: Cx, span: Span) -> Result<()> {
    cx.emit(DbiHeader::node(
        "DBI header",
        span.sub(0, DbiHeader::SIZE),
        LE,
    ));
    cx.emit(Node::new("Substreams").span(span.tail(DbiHeader::SIZE)));
    Ok(())
}

async fn pdb2(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x3c)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Magic", 44).emit()?;
    let block_size = f.u32("Block size").emit()?;
    f.u16("Free block map block").emit()?;
    let blocks = f.u16("Number of blocks").emit()?;
    let dir = f.u32("Stream directory size").emit()?;
    cx.emit(Node::new("Blocks").span(file.tail(u64::from(block_size))));
    cx.annotate(format!(
        "PDB 2.00, {blocks} blocks of {block_size} bytes, directory {dir} bytes"
    ));
    Ok(())
}
