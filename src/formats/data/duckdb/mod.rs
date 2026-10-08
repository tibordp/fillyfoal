//! DuckDB database files (storage format 64 and later: DuckDB 0.9 to 1.5).
//!
//! The file starts with three 4 KiB headers: the main header (checksum,
//! `DUCK`, storage version, flags, the writing library's version and
//! source id) and two database headers written alternately at checkpoints
//! (the one with the higher iteration is current). Each database header
//! points at the metadata, records the free list, the number of blocks
//! and (since 1.2) the block size, vector size and the serialization
//! compatibility level. Blocks follow at 12 KiB, each starting with a
//! 64-bit checksum.
//!
//! Metadata blocks are split into 64 sub-blocks, each starting with a
//! pointer to the next one (block id in the low 56 bits, sub-block index
//! in the top 8): a metadata stream is such a chain, assembled here into
//! a piecewise source so spans keep their file offsets. The catalog stream
//! holds the entries serialized with DuckDB's `BinarySerializer` (see
//! `serial`); tables point at their own stream of statistics and row
//! groups, and row groups at per-column streams of segments (data
//! pointers with compression and min/max statistics). The free list stream
//! lists free blocks, shared data blocks and the metadata blocks with
//! their used sub-blocks. Column values are not decoded (they use
//! DuckDB's compression schemes: bitpacking, dictionary, FSST, ALP, ...).
//!
//! Layouts are from memory of DuckDB's storage code and were checked
//! against files written by DuckDB 1.5.6 at each storage version it can
//! write (64 to 68), including the release mapping below; checksums are
//! verified. Older files (storage versions below 64, DuckDB 0.8 and
//! earlier) used another metadata layout and only get their headers
//! shown. Encrypted databases (1.4+) are recognised from the main header
//! flag; their blocks are not decrypted.

mod catalog;
mod serial;

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use catalog::{Links, MetaPtr};
use serial::{Stream, Ty};

use crate::bytes::{to_u64, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::formats::text::plural;
use crate::formats::util::binutil::{Tree, dec, text};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Value};

const HEADER: u64 = 4096;
const BLOCKS_AT: u64 = 3 * HEADER;
const DEFAULT_BLOCK: u64 = 262_144;
const SUB_BLOCKS: u64 = 64;
const INVALID: u64 = u64::MAX;
/// The block id part of a metadata pointer word.
pub const BLOCK_MASK: u64 = 0x00ff_ffff_ffff_ffff;
/// The most metadata sub-blocks followed in one stream.
const MAX_CHAIN: usize = 1 << 18;
/// First read when parsing a stream; grown while the parse runs short.
const FIRST_READ: u64 = 64 << 10;

/// Storage version → the DuckDB releases that write it (checked against
/// DuckDB 1.5.6's `STORAGE_VERSION` option for 64 and later).
const STORAGE_VERSIONS: EnumTable = &[
    (64, "DuckDB 0.9 – 1.1"),
    (65, "DuckDB 1.2"),
    (66, "DuckDB 1.3"),
    (67, "DuckDB 1.4"),
    (68, "DuckDB 1.5"),
];

/// Serialization compatibility level → the oldest release that reads it.
const COMPATIBILITY: EnumTable = &[
    (1, "DuckDB 0.10"),
    (2, "DuckDB 1.0"),
    (3, "DuckDB 1.1"),
    (4, "DuckDB 1.2"),
    (5, "DuckDB 1.3"),
    (6, "DuckDB 1.4"),
    (7, "DuckDB 1.5"),
];

/// Where blocks and sub-blocks are.
#[derive(Clone, Copy, Debug)]
struct Geo {
    file: Span,
    alloc: u64,
    blocks: u64,
}

impl Geo {
    fn block(&self, id: u64) -> Option<Span> {
        if id >= self.blocks {
            return None;
        }
        let at = id.checked_mul(self.alloc)?.checked_add(BLOCKS_AT)?;
        let span = self.file.sub(at, self.alloc);
        (span.len > 8).then_some(span)
    }

    fn sub_size(&self) -> u64 {
        (self.alloc.saturating_sub(8) / SUB_BLOCKS) & !7
    }

    /// The sub-block an encoded metadata pointer word names.
    fn sub_block(&self, word: u64) -> Option<Span> {
        let index = word >> 56;
        if index >= SUB_BLOCKS {
            return None;
        }
        let size = self.sub_size();
        let span = self
            .block(word & BLOCK_MASK)?
            .sub(index.checked_mul(size)?.checked_add(8)?, size);
        (span.len == size && size > 8).then_some(span)
    }
}

fn describe_word(word: u64) -> String {
    if word == INVALID {
        "none".to_owned()
    } else {
        format!("block {}, sub-block {}", word & BLOCK_MASK, word >> 56)
    }
}

/// DuckDB's block checksum: 5381, XORed with each 64-bit word times a
/// constant (the payload sizes are multiples of 8, so the byte-wise tail
/// hash never applies).
fn checksum(data: &[u8]) -> u64 {
    data.as_chunks::<8>()
        .0
        .iter()
        .map(|c| u64::from_le_bytes(*c))
        .fold(5381u64, |acc, w| {
            acc ^ w.wrapping_mul(0xbf58_476d_1ce4_e5b9)
        })
}

fn checksum_node(stored: u64, payload: &[u8], at: Span) -> Node {
    let computed = checksum(payload);
    let node = Node::new("Checksum").span(at).value(Value::UInt {
        value: stored,
        bits: 64,
        radix: crate::value::Radix::Hex,
    });
    if stored == computed {
        node.summary("valid")
    } else {
        node.diag(Diagnostic::warning(format!(
            "checksum mismatch (computed {computed:#018x})"
        )))
    }
}

#[derive(Clone, Copy, Debug, Default)]
struct DbHeader {
    iteration: u64,
    meta: u64,
    free: u64,
    blocks: u64,
    alloc: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // Main header.
    let head = cx.block(file.sub(0, HEADER)).await?;
    let stored = u64_le(&head.data, 0).unwrap_or(0);
    let payload = head.data.get(8..).unwrap_or_default();
    let mut main = vec![checksum_node(stored, payload, file.sub(0, 8))];
    let version = u64_le(&head.data, 12).unwrap_or(0);
    let flags0 = u64_le(&head.data, 20).unwrap_or(0);
    let library = crate::text::until_nul(head.data.get(52..84).unwrap_or_default());
    let source_id = crate::text::until_nul(head.data.get(84..116).unwrap_or_default());
    main.push(Node::new("Magic").span(file.sub(8, 4)).value(text("DUCK")));
    main.push(
        Node::new("Storage version")
            .span(file.sub(12, 8))
            .value(dec(version, 64))
            .summary(
                crate::value::lookup(STORAGE_VERSIONS, version).unwrap_or(if version < 64 {
                    "DuckDB 0.8 or earlier"
                } else {
                    "unknown"
                }),
            ),
    );
    for i in 0..4u64 {
        let at = 20u64.saturating_add(i.saturating_mul(8));
        let v = u64_le(&head.data, crate::bytes::to_usize(at)).unwrap_or(0);
        let mut n = Node::new(format!("Flags {i}"))
            .span(file.sub(at, 8))
            .value(Value::UInt {
                value: v,
                bits: 64,
                radix: crate::value::Radix::Hex,
            });
        if i == 0 && v & 1 != 0 {
            n = n.summary("encrypted");
        }
        main.push(n);
    }
    if version >= 64 || !library.is_empty() {
        main.push(
            Node::new("Library version")
                .span(file.sub(52, 32))
                .value(text(library.clone())),
        );
        main.push(
            Node::new("Source id")
                .span(file.sub(84, 32))
                .value(text(source_id)),
        );
    }
    if flags0 & 1 != 0 {
        main.push(
            Node::new("Encryption fields")
                .span(file.sub(116, 32))
                .desc("Encryption metadata, database identifier (salt) and encrypted canary; layout from memory"),
        );
    }
    let main_summary = format!(
        "storage version {version}{}",
        if library.is_empty() {
            String::new()
        } else {
            format!(", written by DuckDB {library}")
        }
    );
    cx.emit(
        Node::new("Main header")
            .span(file.sub(0, HEADER))
            .summary(main_summary)
            .lazy(emit_all, Arc::new(main)),
    );

    // Database headers.
    let mut headers = [DbHeader::default(); 2];
    let mut nodes = Vec::new();
    for (i, h) in headers.iter_mut().enumerate() {
        let at = HEADER.saturating_mul(to_u64(i).saturating_add(1));
        let span = file.sub(at, HEADER);
        let block = cx.read_avail(span).await?;
        let get = |o: usize| u64_le(&block, o).unwrap_or(0);
        *h = DbHeader {
            iteration: get(8),
            meta: get(16),
            free: get(24),
            blocks: get(32),
            alloc: get(40),
        };
        let mut kids = vec![checksum_node(
            get(0),
            block.get(8..).unwrap_or_default(),
            span.sub(0, 8),
        )];
        let word = |name: &'static str, o: u64, v: u64| {
            Node::new(name)
                .span(span.sub(o, 8))
                .value(Value::UInt {
                    value: v,
                    bits: 64,
                    radix: crate::value::Radix::Hex,
                })
                .summary(describe_word(v))
        };
        kids.push(
            Node::new("Iteration")
                .span(span.sub(8, 8))
                .value(dec(h.iteration, 64)),
        );
        kids.push(word("Metadata", 16, h.meta).desc("Where the catalog stream starts"));
        kids.push(word("Free list", 24, h.free));
        kids.push(
            Node::new("Block count")
                .span(span.sub(32, 8))
                .value(dec(h.blocks, 64)),
        );
        if block.len() >= 64 {
            kids.push(
                Node::new("Block size")
                    .span(span.sub(40, 8))
                    .value(dec(h.alloc, 64)),
            );
            kids.push(
                Node::new("Vector size")
                    .span(span.sub(48, 8))
                    .value(dec(get(48), 64)),
            );
            let compat = get(56);
            kids.push(
                Node::new("Serialization compatibility")
                    .span(span.sub(56, 8))
                    .value(dec(compat, 64))
                    .summary(crate::value::lookup(COMPATIBILITY, compat).unwrap_or("unknown")),
            );
        }
        nodes.push((span, kids));
    }
    let [first, second] = headers;
    let active = usize::from(second.iteration > first.iteration);
    for (i, (span, kids)) in nodes.into_iter().enumerate() {
        let h = headers.get(i).copied().unwrap_or_default();
        let state = if i == active { "current" } else { "previous" };
        cx.emit(
            Node::new(format!("Database header {}", i.saturating_add(1)))
                .span(span)
                .summary(format!("{state}, iteration {}", h.iteration))
                .lazy(emit_all, Arc::new(kids)),
        );
    }
    let h = headers.get(active).copied().unwrap_or_default();
    let alloc = if h.alloc == 0 { DEFAULT_BLOCK } else { h.alloc };
    if !(16_384..=1 << 30).contains(&alloc) || !alloc.is_power_of_two() {
        return Err(Diagnostic::malformed(format!(
            "implausible block size {alloc}"
        )));
    }
    let geo = Geo {
        file,
        alloc,
        blocks: h.blocks,
    };
    let mut summary = format!(
        "DuckDB database, storage version {version}, {} of {}",
        plural(h.blocks, "block", "blocks"),
        size(alloc)
    );
    if version < 64 {
        cx.annotate(summary);
        cx.emit(
            Node::new("Blocks")
                .span(file.tail(BLOCKS_AT))
                .diag(Diagnostic::unsupported(
                    "storage versions before 64 (DuckDB 0.8 and earlier) are not decoded",
                )),
        );
        return Ok(());
    }
    if flags0 & 1 != 0 {
        summary.push_str(", encrypted");
        cx.annotate(summary);
        cx.emit(
            Node::new("Blocks")
                .span(file.tail(BLOCKS_AT))
                .diag(Diagnostic::unsupported(
                    "encrypted blocks are not decrypted",
                )),
        );
        return Ok(());
    }

    // Catalog: parsed now for the summary (it is small), shown lazily.
    if h.meta != INVALID {
        let ptr = MetaPtr {
            word: h.meta,
            offset: 8,
        };
        match catalog_tree(&cx, geo, ptr).await {
            Ok(cat) => {
                summary.push_str(&format!(
                    ", {}, {}",
                    plural(cat.counts.0, "table", "tables"),
                    plural(cat.counts.1, "view", "views")
                ));
                let mut n = Node::new("Catalog")
                    .span(cat.stream)
                    .summary(plural(to_u64(cat.roots.len()), "entry", "entries"))
                    .lazy(emit_tree, (cat.tree.clone(), cat.roots.clone()));
                if let Some(e) = cat.error.clone() {
                    n = n.diag(e);
                }
                cx.emit(n);
            }
            Err(e) => cx.emit(Node::new("Catalog").diag(e)),
        }
    } else {
        summary.push_str(", empty");
    }
    // Free list (also tells which blocks hold metadata).
    let usage = if h.free == INVALID {
        Arc::new(Usage::default())
    } else {
        match free_list(&cx, geo, h.free).await {
            Ok((stream, usage, kids)) => {
                cx.emit(
                    Node::new("Free list")
                        .span(stream)
                        .summary(format!(
                            "{} free, {} metadata",
                            plural(to_u64(usage.free.len()), "block", "blocks"),
                            to_u64(usage.metadata.len())
                        ))
                        .lazy(emit_all, Arc::new(kids)),
                );
                Arc::new(usage)
            }
            Err(e) => {
                cx.emit(Node::new("Free list").diag(e));
                Arc::new(Usage::default())
            }
        }
    };
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(BLOCKS_AT))
            .summary(format!(
                "{} of {}",
                plural(h.blocks, "block", "blocks"),
                size(alloc)
            ))
            .lazy(blocks, (geo, usage)),
    );
    cx.annotate(summary);
    Ok(())
}

fn size(n: u64) -> String {
    if n >= 1 << 20 && n.is_multiple_of(1 << 20) {
        format!("{} MiB", n >> 20)
    } else if n >= 1 << 10 && n.is_multiple_of(1 << 10) {
        format!("{} KiB", n >> 10)
    } else {
        format!("{n} bytes")
    }
}

async fn emit_all(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.emit(n.clone());
    }
    Ok(())
}

async fn emit_tree(cx: Cx, (tree, roots): (Arc<Tree>, Arc<Vec<usize>>)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(roots.len())));
    for &r in roots.iter() {
        cx.push(Tree::node(&tree, r)).await;
    }
    Ok(())
}

/// Assembles the metadata stream starting at `ptr` as a piecewise source.
async fn meta_stream(cx: &Cx, geo: Geo, ptr: MetaPtr) -> Result<Span> {
    let first = geo.sub_block(ptr.word).ok_or_else(|| {
        Diagnostic::malformed(format!(
            "metadata pointer ({}) is outside the file",
            describe_word(ptr.word)
        ))
    })?;
    if ptr.offset < 8 || ptr.offset >= first.len {
        return Err(Diagnostic::malformed(format!(
            "metadata offset {} is outside its sub-block",
            ptr.offset
        ))
        .at(first));
    }
    let head = first.tail(ptr.offset);
    let mut pieces = vec![head];
    let mut seen = BTreeSet::from([ptr.word]);
    let mut at = first;
    while pieces.len() < MAX_CHAIN {
        let next = u64_le(&cx.read(at.sub(0, 8)).await?, 0).unwrap_or(INVALID);
        if next == INVALID || !seen.insert(next) {
            break;
        }
        let Some(sb) = geo.sub_block(next) else { break };
        pieces.push(sb.tail(8));
        at = sb;
    }
    cx.add_pieces(
        Origin {
            parent: head,
            transform: "duckdb-metadata",
        },
        pieces,
    )
}

/// The result of parsing a stream into a tree: the top nodes, and the
/// error that stopped the parse (shown on the parent).
struct Parsed {
    tree: Arc<Tree>,
    error: Option<Diagnostic>,
}

impl Parsed {
    fn new(tree: Tree, r: Result<()>) -> Parsed {
        Parsed {
            tree: Arc::new(tree),
            error: r.err(),
        }
    }
}

struct LinksImpl {
    geo: Geo,
}

impl Links for LinksImpl {
    fn table_data(&self, ptr: MetaPtr, columns: Arc<Vec<(String, Ty)>>) -> Node {
        Node::new("Table data")
            .summary("statistics and row groups")
            .lazy(table_data, (self.geo, ptr, columns))
    }

    fn column_data(&self, ptr: MetaPtr, name: String, ty: Ty) -> Node {
        Node::new(name).lazy(column_data, (self.geo, ptr, Arc::new(ty)))
    }

    fn block_target(&self, block: i64, offset: u64) -> Option<Span> {
        let b = self.geo.block(u64::try_from(block).ok()?)?;
        Some(b.tail(offset.checked_add(8)?))
    }
}

struct CatalogTree {
    stream: Span,
    tree: Arc<Tree>,
    roots: Arc<Vec<usize>>,
    counts: (u64, u64),
    error: Option<Diagnostic>,
}

async fn catalog_tree(cx: &Cx, geo: Geo, ptr: MetaPtr) -> Result<CatalogTree> {
    let stream = meta_stream(cx, geo, ptr).await?;
    let links = LinksImpl { geo };
    let mut roots = Vec::new();
    let mut counts = catalog::Counts::default();
    let mut s = Stream::open(cx, stream, FIRST_READ).await?;
    let mut tree = Tree::default();
    let r = catalog::catalog(cx, &mut s, &mut tree, &links, &mut roots, &mut counts).await;
    let parsed = Parsed::new(tree, r);
    let counts = (counts.tables, counts.views);
    Ok(CatalogTree {
        stream,
        tree: parsed.tree,
        roots: Arc::new(roots),
        counts,
        error: parsed.error,
    })
}

async fn table_data(
    cx: Cx,
    (geo, ptr, columns): (Geo, MetaPtr, Arc<Vec<(String, Ty)>>),
) -> Result<()> {
    let stream = meta_stream(&cx, geo, ptr).await?;
    let links = LinksImpl { geo };
    let mut roots = Vec::new();
    let mut s = Stream::open(&cx, stream, FIRST_READ).await?;
    let mut tree = Tree::default();
    let r = catalog::table_data(&cx, &mut s, &mut tree, &columns, &links, &mut roots).await;
    let parsed = Parsed::new(tree, r);
    emit_parsed(&cx, &parsed.tree, &roots, parsed.error).await
}

async fn column_data(cx: Cx, (geo, ptr, ty): (Geo, MetaPtr, Arc<Ty>)) -> Result<()> {
    let stream = meta_stream(&cx, geo, ptr).await?;
    let links = LinksImpl { geo };
    let mut roots = Vec::new();
    let mut s = Stream::open(&cx, stream, FIRST_READ).await?;
    let mut tree = Tree::default();
    let r = catalog::column_data(&cx, &mut s, &mut tree, None, &ty, &links, 0, &mut roots).await;
    let parsed = Parsed::new(tree, r);
    emit_parsed(&cx, &parsed.tree, &roots, parsed.error).await
}

async fn emit_parsed(
    cx: &Cx,
    tree: &Arc<Tree>,
    roots: &[usize],
    error: Option<Diagnostic>,
) -> Result<()> {
    if let Some(e) = error {
        cx.diag(e);
    }
    for &r in roots {
        cx.push(Tree::node(tree, r)).await;
    }
    Ok(())
}

/// What the free list says about each block.
#[derive(Default)]
struct Usage {
    free: BTreeSet<u64>,
    /// Data blocks shared by several segments, with their use counts.
    shared: BTreeMap<u64, u32>,
    /// Metadata blocks with their free sub-block masks.
    metadata: BTreeMap<u64, u64>,
}

/// The free list stream: free blocks, shared blocks, metadata blocks.
async fn free_list(cx: &Cx, geo: Geo, word: u64) -> Result<(Span, Usage, Vec<Node>)> {
    let stream = meta_stream(cx, geo, MetaPtr { word, offset: 8 }).await?;
    let mut usage = Usage::default();
    let mut kids = Vec::new();
    let mut pos = 0u64;
    let rd = |pos: u64, n: u64| stream.sub_exact(pos, n);
    // Free blocks.
    let count = u64_le(&cx.read(rd(pos, 8)?).await?, 0).unwrap_or(0);
    let list = rd(pos.saturating_add(8), count.saturating_mul(8))?;
    let data = cx.read(list).await?;
    for (i, c) in data.as_chunks::<8>().0.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        usage.free.insert(u64_le(c, 0).unwrap_or(0));
    }
    kids.push(
        Node::new("Free blocks")
            .span(stream.sub(pos, list.len.saturating_add(8)))
            .value(dec(count, 64))
            .summary(id_list(usage.free.iter().copied())),
    );
    pos = list.end().saturating_sub(stream.offset);
    // Shared (multi-use) blocks.
    let count = u64_le(&cx.read(rd(pos, 8)?).await?, 0).unwrap_or(0);
    let list = rd(pos.saturating_add(8), count.saturating_mul(12))?;
    let data = cx.read(list).await?;
    for (i, c) in data.as_chunks::<12>().0.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        let id = u64_le(c, 0).unwrap_or(0);
        let uses = crate::bytes::u32_le(c, 8).unwrap_or(0);
        usage.shared.insert(id, uses);
    }
    kids.push(
        Node::new("Shared blocks")
            .span(stream.sub(pos, list.len.saturating_add(8)))
            .value(dec(count, 64))
            .summary(
                usage
                    .shared
                    .iter()
                    .take(16)
                    .map(|(b, n)| format!("{b} ({n} uses)"))
                    .collect::<Vec<_>>()
                    .join(", "),
            )
            .desc("Data blocks holding several segments, with their use counts"),
    );
    pos = list.end().saturating_sub(stream.offset);
    // Metadata blocks.
    let count = u64_le(&cx.read(rd(pos, 8)?).await?, 0).unwrap_or(0);
    let list = rd(pos.saturating_add(8), count.saturating_mul(16))?;
    let data = cx.read(list).await?;
    for (i, c) in data.as_chunks::<16>().0.iter().enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        usage
            .metadata
            .insert(u64_le(c, 0).unwrap_or(0), u64_le(c, 8).unwrap_or(0));
    }
    kids.push(
        Node::new("Metadata blocks")
            .span(stream.sub(pos, list.len.saturating_add(8)))
            .value(dec(count, 64))
            .summary(
                usage
                    .metadata
                    .iter()
                    .take(16)
                    .map(|(b, free)| format!("{b} ({}/64 used)", free.count_zeros()))
                    .collect::<Vec<_>>()
                    .join(", "),
            ),
    );
    Ok((stream, usage, kids))
}

fn id_list(ids: impl Iterator<Item = u64>) -> String {
    let all: Vec<String> = ids.take(17).map(|i| i.to_string()).collect();
    if all.len() > 16 {
        format!("{}, …", all.get(..16).unwrap_or_default().join(", "))
    } else {
        all.join(", ")
    }
}

async fn blocks(cx: Cx, (geo, usage): (Geo, Arc<Usage>)) -> Result<()> {
    let total = geo.blocks;
    cx.set_count(Count::Exact(total));
    let mut id = cx.resume::<u64>().unwrap_or(0);
    while id < total {
        let Some(span) = geo.block(id) else {
            cx.diag(Diagnostic::truncated(
                geo.file.sub(
                    BLOCKS_AT.saturating_add(id.saturating_mul(geo.alloc)),
                    geo.alloc,
                ),
                0,
            ));
            break;
        };
        let at = id;
        cx.mark(move || at);
        let role = if usage.free.contains(&id) {
            "free".to_owned()
        } else if let Some(mask) = usage.metadata.get(&id) {
            format!("metadata, {} of 64 sub-blocks used", mask.count_zeros())
        } else if let Some(n) = usage.shared.get(&id) {
            format!("data, shared by {n} segments")
        } else {
            "data".to_owned()
        };
        let metadata = usage.metadata.get(&id).copied();
        cx.push(
            Node::new(format!("Block {id}"))
                .span(span)
                .summary(role)
                .lazy(block, (geo, id, metadata)),
        )
        .await;
        id = id.saturating_add(1);
    }
    Ok(())
}

async fn block(cx: Cx, (geo, id, metadata): (Geo, u64, Option<u64>)) -> Result<()> {
    let span = geo
        .block(id)
        .ok_or_else(|| Diagnostic::malformed("block outside the file"))?;
    let data = cx.read(span).await?;
    cx.emit(checksum_node(
        u64_le(&data, 0).unwrap_or(0),
        data.get(8..).unwrap_or_default(),
        span.sub(0, 8),
    ));
    let Some(free) = metadata else {
        cx.emit(Node::new("Data").span(span.tail(8)));
        return Ok(());
    };
    let size = geo.sub_size();
    for i in 0..SUB_BLOCKS {
        let at = i.saturating_mul(size).saturating_add(8);
        let sub = span.sub(at, size);
        let next = u64_le(&data, crate::bytes::to_usize(at)).unwrap_or(INVALID);
        let used = free.checked_shr(u32::try_from(i).unwrap_or(0)).unwrap_or(0) & 1 == 0;
        let node = Node::new(format!("Sub-block {i}")).span(sub);
        let node = if used {
            node.value(Value::UInt {
                value: next,
                bits: 64,
                radix: crate::value::Radix::Hex,
            })
            .summary(format!("next: {}", describe_word(next)))
        } else {
            node.summary("free")
        };
        cx.push(node).await;
    }
    Ok(())
}
