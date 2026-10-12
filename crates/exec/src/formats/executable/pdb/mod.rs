//! Microsoft program databases (PDB) in the MSF 7.00 container.
//!
//! MSF is a small block-based file system: a superblock points at the block
//! list of the stream directory, which lists every stream's size and blocks.
//! Each stream (and the directory itself) becomes a piecewise source, so
//! streams read as contiguous bytes while spans still resolve to file
//! offsets.
//!
//! Streams 1-4 have fixed roles (PDB info, TPI, DBI, IPI); the others are
//! named by those: the info stream's named stream map (`/names`,
//! `/LinkInfo`, ...), the DBI header (global and public symbol hashes,
//! symbol records), its module info (one stream per module) and optional
//! debug header (section headers, FPO, ...), and the TPI/IPI headers (their
//! hash streams). Expanding "Streams" reads those small tables once; each
//! stream is then decoded by its role (`dbi`, `codeview` for type and
//! symbol records and module streams, `tables` for hash and string tables),
//! following LLVM's PDB documentation and checked against `llvm-pdbutil`.
//! Streams nobody names stay raw data.

use std::sync::Arc;

pub(in crate::formats::executable) mod codeview;
mod dbi;
mod tables;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::executable::pe::tables::MACHINE_SHORT;
use crate::formats::util::arcutil::push_nodes;
use crate::formats::util::fmt::plural;
use crate::formats::{Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value, lookup};
use codeview::{ModuleLayout, NameTables, Records, TypeHeader};
use dbi::DbiHeader;

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

/// The blocks of a stream as file spans (input-sized: checkpointed).
async fn stream_pieces(
    cx: &Cx,
    file: Span,
    block_size: u64,
    blocks: &[u32],
    len: u64,
) -> Vec<Span> {
    let mut remaining = len;
    let mut pieces = Vec::with_capacity(blocks.len());
    for (i, &b) in blocks.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let take = remaining.min(block_size);
        remaining = remaining.saturating_sub(take);
        pieces.push(file.sub(u64::from(b).saturating_mul(block_size), take));
    }
    pieces
}

/// Up to `n` little-endian `u32`s of `data` from `at` (input-sized: checkpointed).
async fn u32s(cx: &Cx, data: &[u8], at: usize, n: usize) -> Vec<u32> {
    let mut out = Vec::new();
    for j in 0..n {
        if j.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        match u32_le(data, at.saturating_add(j.saturating_mul(4))) {
            Some(v) => out.push(v),
            None => break,
        }
    }
    out
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
    let map = u32s(&cx, &map, 0, to_usize(directory_blocks)).await;
    let pieces = stream_pieces(&cx, file, block_size, &map, sb.directory_bytes.into()).await;
    let directory = cx
        .add_pieces_stepped(
            Origin {
                parent: file,
                transform: "msf-directory",
            },
            &pieces,
        )
        .await?;
    let dir = cx.read(directory).await?;
    let count = u32_le(&dir, 0).unwrap_or(0);
    let count_usize = to_usize(count.into());
    if to_u64(count_usize).saturating_mul(4) > directory.len {
        return Err(Diagnostic::malformed("stream count exceeds the directory"));
    }
    let sizes = u32s(&cx, &dir, 4, count_usize).await;
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
        let blocks = u32s(&cx, &dir, at, have).await;
        at = at.saturating_add(n.saturating_mul(4));
        // Each stream needs its own memo key: use the directory source with
        // the stream number as the (empty) parent offset.
        let key = Span::new(directory.source, u64::try_from(i).unwrap_or(0), 0);
        let pieces = stream_pieces(&cx, file, block_size, &blocks, len).await;
        let span = cx
            .add_pieces_stepped(
                Origin {
                    parent: key,
                    transform: "msf-stream",
                },
                &pieces,
            )
            .await?;
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
        if let Some(m) = lookup(MACHINE_SHORT, machine.into()) {
            summary = format!("{summary}, {m}");
        }
    } else if streams.get(3).is_some_and(|(_, dbi)| dbi.len == 0)
        && streams.get(2).is_some_and(|(_, tpi)| tpi.len > 56)
    {
        // cl /Zi's own PDB (mspdbsrv), the type server objects refer to
        // with LF_TYPESERVER2: types and IDs, no modules.
        summary = format!("{summary}, types only (compiler PDB)");
    }
    if let Some((_, info)) = streams.get(1)
        && let Ok(map) = named_streams(&cx, *info).await
    {
        let features = info.tail(map.features);
        let data = cx.read_avail(features.sub(0, 64)).await?;
        if data.chunks(4).any(|c| c == 0x494e_494du32.to_le_bytes()) {
            summary = format!("{summary}, /DEBUG:FASTLINK");
        }
    }
    cx.emit(
        Node::new("Streams")
            .summary(format!("{count} streams"))
            .lazy(pdb_streams, (input, Arc::new(streams))),
    );
    cx.annotate(summary);
    Ok(())
}

/// What a stream holds, as the other streams say.
#[derive(Clone, Debug)]
enum Role {
    OldDirectory,
    Info,
    Tpi,
    Dbi,
    Ipi,
    Globals,
    Publics,
    Symbols,
    /// The hash stream of the TPI (`false`) or IPI (`true`) stream.
    TypeHash(bool),
    Names,
    /// Another named stream (`/LinkInfo`, `/src/headerblock`, ...).
    Named(String),
    /// A stream of the DBI optional debug header (index into
    /// [`dbi::DEBUG_STREAMS`]).
    Debug(usize),
    /// A module's symbols and line information (index into the modules).
    Module(usize),
}

/// The stream roles and what decoding the streams needs, gathered from the
/// PDB info, DBI, TPI and IPI streams.
struct Layout {
    roles: Vec<Option<Role>>,
    modules: Vec<dbi::Module>,
    tpi: Option<TypeHeader>,
    ipi: Option<TypeHeader>,
    tables: NameTables,
}

impl Layout {
    async fn load(cx: &Cx, streams: &[(u32, Span)]) -> Layout {
        let span_of = |i: u16| {
            streams
                .get(usize::from(i))
                .filter(|(size, _)| *size != u32::MAX)
                .map(|&(_, span)| span)
        };
        let mut roles: Vec<Option<Role>> = vec![None; streams.len()];
        let mut set = |i: u16, role: Role| {
            if let Some(slot) = roles.get_mut(usize::from(i))
                && slot.is_none()
            {
                *slot = Some(role);
            }
        };
        set(0, Role::OldDirectory);
        set(1, Role::Info);
        set(2, Role::Tpi);
        set(3, Role::Dbi);
        set(4, Role::Ipi);
        let mut names = None;
        if let Some(info) = span_of(1)
            && let Ok(map) = named_streams(cx, info).await
        {
            for (name, index, _) in map.entries {
                let Ok(index) = u16::try_from(index) else {
                    continue;
                };
                if name == "/names" {
                    names = span_of(index);
                    set(index, Role::Names);
                } else {
                    set(index, Role::Named(name));
                }
            }
        }
        let mut modules = Vec::new();
        let mut symbols = None;
        if let Some(stream) = span_of(3)
            && stream.len >= DbiHeader::SIZE
            && let Ok(h) = read_record::<DbiHeader>(cx, stream.sub(0, DbiHeader::SIZE), LE).await
        {
            set(h.globals, Role::Globals);
            set(h.publics, Role::Publics);
            set(h.symbols, Role::Symbols);
            symbols = span_of(h.symbols);
            let subs = dbi::Substreams::new(stream, &h);
            modules = dbi::modules(cx, subs.modules).await.unwrap_or_default();
            for (i, m) in modules.iter().enumerate() {
                set(m.stream, Role::Module(i));
            }
            if let Ok(debug) = cx.read_avail(subs.debug).await {
                for k in 0..debug.len() / 2 {
                    if let Some(v) = u16_le(&debug, k.saturating_mul(2)) {
                        set(v, Role::Debug(k));
                    }
                }
            }
        }
        let mut headers = [None, None];
        for (slot, index, ipi) in [(0usize, 2u16, false), (1, 4, true)] {
            if let Some(stream) = span_of(index)
                && stream.len >= 56
                && let Ok(h) = parse(cx, stream.sub(0, 56), LE, &(), codeview::type_header).await
            {
                set(h.hash_stream, Role::TypeHash(ipi));
                if let Some(s) = headers.get_mut(slot) {
                    *s = Some(h);
                }
            }
        }
        // The string buffer of /names.
        let mut name_buffer = None;
        if let Some(n) = names
            && let Ok(head) = cx.read_avail(n.sub(0, 12)).await
            && let Some(size) = u32_le(&head, 8)
        {
            name_buffer = Some(n.sub(12, size.into()));
        }
        let [tpi, ipi] = headers;
        Layout {
            roles,
            modules,
            tpi,
            ipi,
            tables: NameTables {
                names: name_buffer,
                symbols,
            },
        }
    }

    fn label(&self, role: &Role) -> String {
        match role {
            Role::OldDirectory => "Old directory".to_owned(),
            Role::Info => "PDB info".to_owned(),
            Role::Tpi => "Type info (TPI)".to_owned(),
            Role::Dbi => "Debug info (DBI)".to_owned(),
            Role::Ipi => "ID info (IPI)".to_owned(),
            Role::Globals => "Global symbol hash".to_owned(),
            Role::Publics => "Public symbol hash".to_owned(),
            Role::Symbols => "Symbol records".to_owned(),
            Role::TypeHash(false) => "TPI hash".to_owned(),
            Role::TypeHash(true) => "IPI hash".to_owned(),
            Role::Names => "/names".to_owned(),
            Role::Named(name) => name.clone(),
            Role::Debug(k) => dbi::DEBUG_STREAMS
                .get(*k)
                .copied()
                .unwrap_or("Debug data")
                .to_owned(),
            Role::Module(i) => match self.modules.get(*i) {
                Some(m) => format!("Module {:?}", m.name),
                None => "Module".to_owned(),
            },
        }
    }
}

/// The named stream map of the PDB info stream, and the features after it.
struct NamedStreams {
    /// Name, stream number, and the span of the entry.
    entries: Vec<(String, u32, Span)>,
    /// The hash table (after the string buffer).
    table: Span,
    /// Where the feature signatures start.
    features: u64,
}

/// Reads the named stream map: a string buffer, then a hash table of
/// (string offset, stream) pairs with present and deleted bit vectors.
async fn named_streams(cx: &Cx, info: Span) -> Result<NamedStreams> {
    let data = cx.read_avail(info.sub(0, 1 << 20)).await?;
    let word = |at: usize| u32_le(&data, at);
    let strings_len = to_usize(word(28).unwrap_or(0).into());
    let strings_at = 32usize;
    let table_at = strings_at.saturating_add(strings_len);
    let size = word(table_at).unwrap_or(0);
    let mut at = table_at.saturating_add(8);
    // Present and deleted bit vectors: a word count, then the words.
    for _ in 0..2 {
        let words = to_usize(word(at).unwrap_or(0).into());
        at = at.saturating_add(4).saturating_add(words.saturating_mul(4));
    }
    let mut entries = Vec::new();
    for i in 0..size {
        if i.is_multiple_of(1024) {
            cx.checkpoint().await;
        }
        let (Some(key), Some(stream)) = (word(at), word(at.saturating_add(4))) else {
            break;
        };
        let name_at = strings_at.saturating_add(to_usize(key.into()));
        let s = data.get(name_at..).unwrap_or_default();
        let end = s.iter().position(|&b| b == 0).unwrap_or(s.len());
        let name = String::from_utf8_lossy(s.get(..end).unwrap_or_default()).into_owned();
        entries.push((name, stream, info.sub(to_u64(at), 8)));
        at = at.saturating_add(8);
    }
    // A trailing "niMac" word, then the feature signatures.
    let features = to_u64(at.saturating_add(4));
    Ok(NamedStreams {
        entries,
        table: info.sub(to_u64(table_at), to_u64(at.saturating_sub(table_at))),
        features,
    })
}

async fn pdb_streams(cx: Cx, (input, streams): (Input, Arc<Vec<(u32, Span)>>)) -> Result<()> {
    let layout = Arc::new(Layout::load(&cx, &streams).await);
    cx.set_count(Count::Exact(to_u64(streams.len())));
    for (i, &(size, span)) in streams.iter().enumerate() {
        let role = layout.roles.get(i).cloned().flatten();
        let name = match &role {
            Some(r) => format!("Stream {i}: {}", layout.label(r)),
            None => format!("Stream {i}"),
        };
        let node = if size == u32::MAX {
            Node::new(name).summary("deleted")
        } else {
            stream_node(Node::new(name).span(span), &input, span, role, &layout)
                .summary(format!("{size} bytes"))
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A stream's node, decoded according to its role. Streams nobody names
/// are raw data: they are binary records whose few bytes match weak magic
/// numbers of unrelated formats.
fn stream_node(node: Node, input: &Input, span: Span, role: Option<Role>, layout: &Layout) -> Node {
    let tables = layout.tables;
    match role {
        Some(Role::Info) => node.lazy(pdb_info, span),
        Some(Role::Tpi | Role::Ipi) if span.len >= 56 => node.lazy(codeview::type_stream, span),
        Some(Role::Dbi) if span.len >= DbiHeader::SIZE => node.lazy(dbi::dbi, span),
        Some(Role::Globals) => node.lazy(tables::globals, (span, tables.symbols)),
        Some(Role::Publics) => node.lazy(tables::publics, (span, tables.symbols)),
        Some(Role::Symbols) => node.lazy(codeview::records, (span, Records::Symbols(0))),
        Some(Role::TypeHash(ipi)) => match if ipi { layout.ipi } else { layout.tpi } {
            Some(h) => node.lazy(tables::type_hash, (span, h)),
            None => node,
        },
        Some(Role::Names) => node.lazy(tables::names, span),
        Some(Role::Debug(5 | 10)) => node.lazy(dbi::section_headers, span),
        Some(Role::Debug(0)) => node.lazy(crate::formats::executable::pe::debug::fpo, span),
        Some(Role::Debug(3 | 4)) => node.lazy(dbi::omap, span),
        Some(Role::Debug(9)) => node.lazy(dbi::new_fpo, (span, tables.names)),
        Some(Role::Module(i)) => match layout.modules.get(i) {
            Some(m) => node.lazy(
                codeview::module_stream,
                (
                    span,
                    ModuleLayout {
                        symbols: m.symbols,
                        c11: m.c11,
                        c13: m.c13,
                    },
                    tables,
                ),
            ),
            None => node,
        },
        // Embedded source files (clang /Zi /embed-source-ish named streams).
        Some(Role::Named(n)) if n.starts_with("/src/files/") => {
            embedded(node.name.clone(), input.nested(span))
        }
        _ => node.desc("Not decoded"),
    }
}

const FEATURES: EnumTable = &[
    (20_091_201, "VC110"),
    (20_140_508, "VC140"),
    (0x4d54_4f4e, "no type merge"),
    (0x494e_494d, "minimal debug info"),
];

async fn pdb_info(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 32)).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("Version").enumeration(PDB_VERSIONS).emit()?;
    f.u32("Signature")
        .hex()
        .desc("The time the PDB was written (MSVC), or a content hash (lld-link /Brepro)")
        .emit()?;
    f.u32("Age").emit()?;
    f.guid("GUID")
        .desc("Matches the CodeView record of the image")
        .emit()?;
    let names_len = f.u32("Named stream map: string buffer size").emit()?;
    let strings = span.sub(32, names_len.into());
    cx.emit(
        Node::new("Names")
            .span(strings)
            .lazy(crate::formats::util::binutil::cstrings, strings),
    );
    let map = named_streams(&cx, span).await?;
    let nodes: Vec<Node> = map
        .entries
        .iter()
        .map(|(name, stream, at)| {
            Node::new(name.clone())
                .span(*at)
                .value(crate::formats::util::val::uint(*stream, 32))
                .summary(format!("stream {stream}"))
        })
        .collect();
    cx.emit(
        Node::new("Named stream map")
            .span(map.table)
            .summary(format!("{} streams", nodes.len()))
            .lazy(push_nodes, Arc::new(nodes)),
    );
    let features = span.tail(map.features);
    let data = cx.read_avail(features.sub(0, 4096)).await?;
    for i in 0..data.len() / 4 {
        let v = u32_le(&data, i.saturating_mul(4)).unwrap_or(0);
        cx.emit(
            Node::new("Feature")
                .span(features.sub(to_u64(i.saturating_mul(4)), 4))
                .value(Value::Enum {
                    raw: v.into(),
                    bits: 32,
                    name: lookup(FEATURES, v.into()),
                }),
        );
    }
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
        "PDB 2.00, {blocks_block} of {block_size} bytes, directory {dir} bytes",
        blocks_block = plural(blocks, "block")
    ));
    Ok(())
}
