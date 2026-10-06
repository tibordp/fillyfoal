//! Microsoft program databases (PDB) in the MSF 7.0 container.
//!
//! An MSF file is a set of streams stored in fixed-size blocks; a stream
//! directory lists each stream's size and blocks. Expanding a stream
//! reassembles its blocks into a derived source (so spans inside it are
//! exact) and decodes the well-known ones: the PDB information stream (GUID,
//! age, named streams), the DBI stream (modules) and the TPI/IPI type
//! streams (type records).

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::binutil::{data_node, ellipsize, name_or, text};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::EnumTable;

const LE: Endian = Endian::Little;
const MAGIC: &[u8] = b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0";
/// Largest stream directory we read.
const MAX_DIRECTORY: u32 = 16 << 20;
const NIL: u32 = 0xffff_ffff;

pub static FORMAT: Format = Format {
    name: "pdb",
    title: "Microsoft program database (PDB)",
    extensions: &["pdb"],
    mime: "application/x-ms-pdb",
    probe: Probe::Magic(&[(0, b"Microsoft C/C++ MSF 7.00\r\n\x1aDS\0\0\0")]),
    dissect: crate::expander!(dissect: Input),
};

const PDB_VERSION: EnumTable = &[
    (19_941_610, "VC2"),
    (19_950_623, "VC4"),
    (19_950_814, "VC41"),
    (19_960_307, "VC50"),
    (19_970_604, "VC98"),
    (19_990_604, "VC70Dep"),
    (20_000_404, "VC70"),
    (20_030_901, "VC80"),
    (20_091_201, "VC110"),
    (20_140_508, "VC140"),
];

const TPI_VERSION: EnumTable = &[
    (19_950_410, "V40"),
    (19_951_122, "V41"),
    (19_961_031, "V50"),
    (19_990_903, "V70"),
    (20_040_203, "V80"),
];

const DBI_VERSION: EnumTable = &[
    (930_803, "VC41"),
    (19_960_307, "V50"),
    (19_970_606, "V60"),
    (19_990_903, "V70"),
    (20_091_201, "V110"),
];

const FEATURE: EnumTable = &[
    (20_140_508, "VC140"),
    (0x4d54_4f4e, "NoTypeMerge"),
    (0x494e_494d, "MinimalDebugInfo"),
];

const LEAF_KIND: EnumTable = &[
    (0x1001, "LF_MODIFIER"),
    (0x1002, "LF_POINTER"),
    (0x1008, "LF_PROCEDURE"),
    (0x1009, "LF_MFUNCTION"),
    (0x1201, "LF_ARGLIST"),
    (0x1203, "LF_FIELDLIST"),
    (0x1205, "LF_BITFIELD"),
    (0x1206, "LF_METHODLIST"),
    (0x1503, "LF_ARRAY"),
    (0x1504, "LF_CLASS"),
    (0x1505, "LF_STRUCTURE"),
    (0x1506, "LF_UNION"),
    (0x1507, "LF_ENUM"),
    (0x1519, "LF_INTERFACE"),
    (0x1601, "LF_FUNC_ID"),
    (0x1602, "LF_MFUNC_ID"),
    (0x1603, "LF_BUILDINFO"),
    (0x1604, "LF_SUBSTR_LIST"),
    (0x1605, "LF_STRING_ID"),
    (0x1606, "LF_UDT_SRC_LINE"),
    (0x1607, "LF_UDT_MOD_SRC_LINE"),
    (0x1608, "LF_CLASS2"),
    (0x1609, "LF_STRUCTURE2"),
];

const MACHINE: EnumTable = crate::formats::pe::tables::MACHINE;

record! {
    struct SuperBlock {
        magic: bytes[32] "FileMagic",
        block_size: u32 "BlockSize" .hex(),
        free_map: u32 "FreeBlockMapBlock",
        blocks: u32 "NumBlocks",
        directory_bytes: u32 "NumDirectoryBytes" .hex(),
        unknown: u32 "Unknown",
        block_map: u32 "BlockMapAddr" .desc("Block holding the directory's block list"),
    }
}

#[derive(Clone, Debug)]
struct Stream {
    size: u32,
    blocks: Vec<u32>,
    /// Where the block list is in the directory (derived source).
    list: Span,
}

type Msf = Arc<MsfInfo>;

struct MsfInfo {
    file: Span,
    block_size: u64,
    streams: Vec<Stream>,
    names: Vec<(u32, String)>,
}

impl MsfInfo {
    fn name(&self, index: usize) -> Option<&str> {
        let i = u32::try_from(index).ok()?;
        match index {
            0 => Some("Old Directory"),
            1 => Some("PDB Info"),
            2 => Some("TPI (types)"),
            3 => Some("DBI (debug info)"),
            4 => Some("IPI (ids)"),
            _ => self.names.iter().find(|(s, _)| *s == i).map(|(_, n)| n.as_str()),
        }
    }
}

/// Concatenates `blocks` (truncated to `size`) into a derived source.
async fn assemble(
    cx: &Cx,
    file: Span,
    block_size: u64,
    blocks: &[u32],
    size: u64,
    origin: Span,
) -> Result<Span> {
    let key = Origin {
        parent: origin,
        transform: "msf-stream",
    };
    if let Some(found) = cx.derived(key) {
        return Ok(found.span);
    }
    if size > cx.limits().max_read {
        return Err(Diagnostic::limit("stream too large to reassemble").at(origin));
    }
    let mut out = Vec::new();
    for &b in blocks {
        let remaining = size.saturating_sub(to_u64(out.len()));
        if remaining == 0 {
            break;
        }
        let at = u64::from(b).saturating_mul(block_size);
        let data = cx.read(file.sub_exact(at, remaining.min(block_size))?).await?;
        out.extend_from_slice(&data);
    }
    Ok(cx.add_derived(key, out, size, None)?.span)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sspan = file.sub(0, SuperBlock::SIZE);
    cx.emit(SuperBlock::node("Superblock", sspan, LE));
    let sb = parse(&cx, sspan, LE, &(), SuperBlock::layout).await?;
    if sb.magic.as_slice() != MAGIC {
        return Err(Diagnostic::malformed("bad MSF magic").at(sspan));
    }
    if !matches!(sb.block_size, 512 | 1024 | 2048 | 4096) {
        return Err(Diagnostic::malformed(format!("block size {}", sb.block_size)).at(sspan));
    }
    if sb.directory_bytes > MAX_DIRECTORY {
        return Err(Diagnostic::limit("stream directory too large").at(sspan));
    }
    let bs = u64::from(sb.block_size);
    let dir_blocks = u64::from(sb.directory_bytes).div_ceil(bs);
    let map = file.sub_exact(u64::from(sb.block_map).saturating_mul(bs), dir_blocks.saturating_mul(4))?;
    let map_bytes = cx.read(map).await?;
    let blocks: Vec<u32> = (0..to_usize(dir_blocks))
        .filter_map(|i| u32_le(&map_bytes, i.saturating_mul(4)))
        .collect();
    let directory = assemble(&cx, file, bs, &blocks, sb.directory_bytes.into(), map).await?;
    let dir = cx.read(directory).await?;

    // Directory: count, sizes, then block lists.
    let count = to_usize(u32_le(&dir, 0).unwrap_or(0).into()).min(dir.len() / 4);
    let mut at = 4usize.saturating_add(count.saturating_mul(4));
    let mut streams = Vec::new();
    for i in 0..count {
        let size = u32_le(&dir, 4usize.saturating_add(i.saturating_mul(4))).unwrap_or(0);
        let n = if size == NIL { 0 } else { u64::from(size).div_ceil(bs) };
        let n = to_usize(n).min(dir.len().saturating_sub(at) / 4);
        let list = directory.sub(to_u64(at), to_u64(n.saturating_mul(4)));
        let blocks: Vec<u32> = (0..n)
            .filter_map(|k| u32_le(&dir, at.saturating_add(k.saturating_mul(4))))
            .collect();
        at = at.saturating_add(n.saturating_mul(4));
        streams.push(Stream { size, blocks, list });
    }

    // The PDB information stream: GUID, age and named streams.
    let mut names = Vec::new();
    let mut summary = format!("PDB (MSF 7.0, {bs}-byte blocks), {count} streams");
    if let Some(info) = streams.get(1).filter(|s| s.size != NIL) {
        let span = assemble(&cx, file, bs, &info.blocks, info.size.into(), info.list).await?;
        let data = cx.read_avail(span).await?;
        if let Some(guid) = data.get(12..28) {
            summary.push_str(&format!(
                ", GUID {}, age {}",
                format_guid(guid),
                u32_le(&data, 8).unwrap_or(0)
            ));
        }
        names = named_streams(&data).0;
    }
    if let Some(dbi) = streams.get(3).filter(|s| s.size != NIL && s.size >= 64) {
        let span = assemble(&cx, file, bs, &dbi.blocks, dbi.size.into(), dbi.list).await?;
        let data = cx.read_avail(span.sub(0, 64)).await?;
        let machine = u16_le(&data, 58).unwrap_or(0);
        summary.push_str(&format!(", {}", name_or(MACHINE, machine.into(), "machine")));
    }
    cx.annotate(summary);

    let msf: Msf = Arc::new(MsfInfo {
        file,
        block_size: bs,
        streams,
        names,
    });
    cx.emit(
        Node::new("Stream Directory")
            .span(directory)
            .summary(format!("{count} streams"))
            .desc("Reassembled from the blocks listed at BlockMapAddr")
            .target(map),
    );
    cx.emit(
        Node::new("Streams")
            .summary(format!("{count} streams"))
            .lazy(stream_list, msf),
    );
    Ok(())
}

fn format_guid(b: &[u8]) -> String {
    let d1 = u32_le(b, 0).unwrap_or(0);
    let d2 = u16_le(b, 4).unwrap_or(0);
    let d3 = u16_le(b, 6).unwrap_or(0);
    let rest = crate::formats::binutil::hex_string(b.get(8..16).unwrap_or_default()).to_ascii_uppercase();
    format!(
        "{{{d1:08X}-{d2:04X}-{d3:04X}-{}-{}}}",
        rest.get(..4).unwrap_or_default(),
        rest.get(4..).unwrap_or_default()
    )
}

/// The named stream map of the PDB stream: `(stream, name)` pairs, and the
/// offset just past the map.
fn named_streams(data: &[u8]) -> (Vec<(u32, String)>, usize) {
    let mut out = Vec::new();
    let at = 28usize;
    let Some(len) = u32_le(data, at) else {
        return (out, at);
    };
    let strings_at = at.saturating_add(4);
    let strings = data
        .get(strings_at..strings_at.saturating_add(to_usize(len.into())))
        .unwrap_or_default();
    let mut p = strings_at.saturating_add(to_usize(len.into()));
    let size = u32_le(data, p).unwrap_or(0);
    let _capacity = u32_le(data, p.saturating_add(4)).unwrap_or(0);
    p = p.saturating_add(8);
    let present_words = to_usize(u32_le(data, p).unwrap_or(0).into()).min(data.len() / 4);
    p = p.saturating_add(4).saturating_add(present_words.saturating_mul(4));
    let deleted_words = to_usize(u32_le(data, p).unwrap_or(0).into()).min(data.len() / 4);
    p = p.saturating_add(4).saturating_add(deleted_words.saturating_mul(4));
    for _ in 0..size.min(4096) {
        let (Some(key), Some(value)) = (u32_le(data, p), u32_le(data, p.saturating_add(4))) else {
            break;
        };
        p = p.saturating_add(8);
        let name = crate::text::until_nul(strings.get(to_usize(key.into())..).unwrap_or_default());
        out.push((value, name));
    }
    (out, p)
}

async fn stream_list(cx: Cx, msf: Msf) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(msf.streams.len())));
    for (i, s) in msf.streams.iter().enumerate() {
        let label = match msf.name(i) {
            Some(n) => format!("Stream {i}: {n}"),
            None => format!("Stream {i}"),
        };
        let node = Node::new(label).span(s.list);
        let node = if s.size == NIL {
            node.summary("nil")
        } else {
            node.summary(format!("{:#x} bytes in {} blocks", s.size, s.blocks.len()))
                .lazy(stream_node, (msf.clone(), i))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn stream_node(cx: Cx, (msf, index): (Msf, usize)) -> Result<()> {
    let s = msf
        .streams
        .get(index)
        .ok_or_else(|| Diagnostic::internal("stream index out of range"))?;
    let blocks: Vec<String> = s.blocks.iter().take(32).map(u32::to_string).collect();
    cx.emit(
        Node::new("Blocks")
            .span(s.list)
            .value(text(ellipsize(&blocks.join(" "), 200))),
    );
    let span = assemble(&cx, msf.file, msf.block_size, &s.blocks, s.size.into(), s.list).await?;
    let name = msf.name(index).unwrap_or("");
    match index {
        1 => cx.emit(struct_node("PDB Info", span, LE, (), pdb_info)),
        2 | 4 => {
            cx.emit(struct_node("Header", span.sub(0, 56), LE, (), tpi_header));
            let data = cx.read_avail(span.sub(0, 8)).await?;
            let header = u64::from(u32_le(&data, 4).unwrap_or(56));
            cx.emit(
                Node::new("Type Records")
                    .span(span.tail(header))
                    .lazy(type_records, (span.tail(header), u32_le(&data, 8).unwrap_or(0x1000))),
            );
        }
        3 => {
            cx.emit(struct_node("Header", span.sub(0, 64), LE, (), dbi_header));
            let data = cx.read_avail(span.sub(0, 64)).await?;
            let size = u64::from(u32_le(&data, 24).unwrap_or(0));
            cx.emit(
                Node::new("Modules")
                    .span(span.sub(64, size))
                    .lazy(modules, span.sub(64, size)),
            );
        }
        _ if name == "/names" => cx.emit(struct_node("String Table", span, LE, (), string_table)),
        _ => cx.emit(data_node("Data", span, s.size.into())),
    }
    Ok(())
}

fn pdb_info(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Version").enumeration(PDB_VERSION).emit()?;
    f.u32("Signature").timestamp().emit()?;
    f.u32("Age").emit()?;
    f.bytes("Guid", 16)
        .with(|b, n| n.summary(format_guid(b)))
        .emit()?;
    let data = f.block().data.clone();
    let (names, end) = named_streams(&data);
    let map = f.peek_span(to_u64(end).saturating_sub(f.pos()));
    let list: Vec<String> = names.iter().map(|(s, n)| format!("{n} → {s}")).collect();
    f.node(
        Node::new("Named Streams")
            .span(map)
            .value(text(list.join(", "))),
    );
    f.seek(to_u64(end));
    while f.remaining() >= 4 {
        f.u32("Feature").enumeration(FEATURE).emit()?;
    }
    Ok(())
}

fn tpi_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Version").enumeration(TPI_VERSION).emit()?;
    f.u32("HeaderSize").emit()?;
    f.u32("TypeIndexBegin").hex().emit()?;
    f.u32("TypeIndexEnd").hex().emit()?;
    f.u32("TypeRecordBytes").hex().emit()?;
    f.u16("HashStreamIndex").emit()?;
    f.u16("HashAuxStreamIndex").emit()?;
    f.u32("HashKeySize").emit()?;
    f.u32("NumHashBuckets").emit()?;
    for name in [
        "HashValueBufferOffset",
        "HashValueBufferLength",
        "IndexOffsetBufferOffset",
        "IndexOffsetBufferLength",
        "HashAdjBufferOffset",
        "HashAdjBufferLength",
    ] {
        f.u32(name).hex().emit()?;
    }
    Ok(())
}

async fn type_records(cx: Cx, (span, first): (Span, u32)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    let mut index = first;
    while let Some(len) = u16_le(&data, at) {
        let kind = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        let total = usize::from(len).saturating_add(2);
        if len < 2 {
            break;
        }
        cx.push(
            Node::new(format!("{index:#x}"))
                .span(span.sub(to_u64(at), to_u64(total)))
                .value(crate::value::Value::Enum {
                    raw: kind.into(),
                    bits: 16,
                    name: crate::value::lookup(LEAF_KIND, kind.into()),
                })
                .summary(format!("{len} bytes")),
        )
        .await;
        at = at.saturating_add(total);
        index = index.saturating_add(1);
    }
    Ok(())
}

fn dbi_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.i32("VersionSignature").emit()?;
    f.u32("VersionHeader").enumeration(DBI_VERSION).emit()?;
    f.u32("Age").emit()?;
    f.u16("GlobalStreamIndex").emit()?;
    f.u16("BuildNumber")
        .hex()
        .with(|&v, n| n.summary(format!("{}.{}", (v >> 8) & 0x7f, v & 0xff)))
        .emit()?;
    f.u16("PublicStreamIndex").emit()?;
    f.u16("PdbDllVersion").emit()?;
    f.u16("SymRecordStream").emit()?;
    f.u16("PdbDllRbld").emit()?;
    for name in [
        "ModInfoSize",
        "SectionContributionSize",
        "SectionMapSize",
        "SourceInfoSize",
        "TypeServerMapSize",
        "MFCTypeServerIndex",
        "OptionalDbgHeaderSize",
        "ECSubstreamSize",
    ] {
        f.u32(name).emit()?;
    }
    f.u16("Flags").hex().emit()?;
    f.u16("Machine").enumeration(MACHINE).emit()?;
    f.u32("Padding").emit()?;
    Ok(())
}

async fn modules(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut at = 0usize;
    while at.saturating_add(64) <= data.len() {
        let start = at;
        let stream = u16_le(&data, at.saturating_add(34)).unwrap_or(0);
        let files = u16_le(&data, at.saturating_add(48)).unwrap_or(0);
        let name_at = at.saturating_add(64);
        let rest = data.get(name_at..).unwrap_or_default();
        let n1 = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let name = String::from_utf8_lossy(rest.get(..n1).unwrap_or_default()).into_owned();
        let rest2 = rest.get(n1.saturating_add(1)..).unwrap_or_default();
        let n2 = rest2.iter().position(|&b| b == 0).unwrap_or(rest2.len());
        let obj = String::from_utf8_lossy(rest2.get(..n2).unwrap_or_default()).into_owned();
        at = name_at
            .saturating_add(n1)
            .saturating_add(n2)
            .saturating_add(2)
            .checked_next_multiple_of(4)
            .unwrap_or(usize::MAX);
        let mut summary = format!("{files} source files");
        if stream != 0xffff {
            summary.push_str(&format!(", symbols in stream {stream}"));
        }
        if !obj.is_empty() && obj != name {
            summary.push_str(&format!(", object {obj}"));
        }
        cx.push(
            Node::new(name)
                .span(span.sub(to_u64(start), to_u64(at.saturating_sub(start))))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

fn string_table(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("Signature").hex().desc("0xEFFEEFFE").emit()?;
    f.u32("HashVersion").emit()?;
    let size = f.u32("ByteSize").emit()?;
    let start = f.pos();
    let data = f.block().data.clone();
    let mut p = to_usize(start);
    let end = p.saturating_add(to_usize(size.into())).min(data.len());
    while p < end {
        let rest = data.get(p..end).unwrap_or_default();
        let n = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        if n > 0 {
            f.seek(to_u64(p));
            f.cstr("string").emit()?;
        }
        p = p.saturating_add(n).saturating_add(1);
    }
    Ok(())
}
