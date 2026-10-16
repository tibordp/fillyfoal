//! Git commit-graph files (`.git/objects/info/commit-graph`, and the
//! layers of a split chain, `objects/info/commit-graphs/graph-*.graph`),
//! laid out as git's `gitformat-commit-graph` documents them: a 8-byte
//! header (`CGPH`, version 1, hash version, chunk count, base graph
//! count), a table of chunk IDs and offsets ending with a zero ID whose
//! offset is the end of the last chunk, the chunks, and a trailing
//! checksum of everything before it.
//!
//! Chunks shown: the OID fan-out (`OIDF`) and lookup (`OIDL`) tables, the
//! commit data (`CDAT`: root tree, parents, topological level and commit
//! time), corrected commit dates (`GDA2`, overflowing into `GDO2`), the
//! extra parents of octopus merges (`EDGE`), changed-path Bloom filters
//! (`BIDX` index and `BDAT` data) and the base graphs a layer of a split
//! chain builds on (`BASE`). Parents are positions in the whole chain:
//! the commits of the base graphs come first, so in a layer with base
//! graphs a position names a commit of this file only once the bases'
//! commit counts are known, which this file alone does not say.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, struct_node};
use crate::formats::util::datakit::{hex_string, uint};
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value};

use super::git::{checksum_node, trailer};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "git-commit-graph",
    title: "Git commit-graph",
    extensions: &["graph"],
    mime: "application/x-git-commit-graph",
    probe: Probe::Magic(&[(0, b"CGPH\x01\x01"), (0, b"CGPH\x01\x02")]),
    dissect: crate::expander!(dissect: Input),
};

const HASH_VERSIONS: EnumTable = &[(1, "SHA-1"), (2, "SHA-256")];

/// Known chunks: ID and name.
const CHUNKS: &[(&[u8; 4], &str)] = &[
    (b"OIDF", "OID fan-out"),
    (b"OIDL", "OID lookup"),
    (b"CDAT", "Commit data"),
    (b"GDA2", "Generation data"),
    (b"GDO2", "Generation data overflow"),
    (b"GDAT", "Generation data (v1, withdrawn)"),
    (b"GDOV", "Generation data overflow (v1, withdrawn)"),
    (b"EDGE", "Extra edge list"),
    (b"BIDX", "Bloom filter index"),
    (b"BDAT", "Bloom filter data"),
    (b"BASE", "Base graphs list"),
];

/// A parent position meaning "no parent".
const PARENT_NONE: u32 = 0x7000_0000;
/// Set in the second parent: the rest indexes the extra edge list.
const OCTOPUS: u32 = 0x8000_0000;
/// Set in an extra edge: the last parent of the commit.
const LAST_EDGE: u32 = 0x8000_0000;
/// Set in a corrected date offset: the rest indexes `GDO2`.
const OFFSET_OVERFLOW: u32 = 0x8000_0000;
/// Chunk table entries read at most (git writes about ten).
const MAX_CHUNKS: u64 = 64;
/// Parents listed at most for one octopus merge.
const MAX_EDGES: u64 = 4096;

/// The file's layout, shared by every expander.
#[derive(Clone, Debug)]
struct Graph {
    file: Span,
    /// Object name size: 20 (SHA-1) or 32 (SHA-256).
    hash: u64,
    /// Commits in this file (the fan-out table's last entry).
    count: u64,
    /// Base graphs (layers this one builds on).
    bases: u8,
    /// Chunks: ID and span.
    chunks: Arc<Vec<([u8; 4], Span)>>,
}

impl Graph {
    fn chunk(&self, id: &[u8; 4]) -> Option<Span> {
        self.chunks.iter().find(|(c, _)| c == id).map(|(_, s)| *s)
    }

    /// The span of the object name at `index` in `OIDL`.
    fn oid_span(&self, index: u64) -> Option<Span> {
        let oidl = self.chunk(b"OIDL")?;
        oidl.sub_exact(index.checked_mul(self.hash)?, self.hash)
            .ok()
    }

    async fn oid(&self, cx: &Cx, index: u64) -> Option<String> {
        let span = self.oid_span(index)?;
        cx.read(span).await.ok().map(|b| hex_string(&b))
    }

    /// The width of one `CDAT` record.
    fn record(&self) -> u64 {
        self.hash.saturating_add(16)
    }
}

fn chunk_name(id: &[u8; 4]) -> Option<&'static str> {
    CHUNKS.iter().find(|(c, _)| *c == id).map(|(_, n)| *n)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 8)?).await?;
    let hash_version = head.get(5).copied().unwrap_or(0);
    let chunk_count = head.get(6).copied().unwrap_or(0);
    let bases = head.get(7).copied().unwrap_or(0);
    let hash = if hash_version == 2 { 32 } else { 20 };
    cx.emit(struct_node("Header", file.sub(0, 8), BE, (), |f, _| {
        f.ascii("Signature", 4).emit()?;
        f.u8("Version").emit()?;
        f.u8("Hash version").enumeration(HASH_VERSIONS).emit()?;
        f.u8("Number of chunks").emit()?;
        f.u8("Number of base graphs")
            .desc("Layers of a split chain this one builds on (listed in BASE)")
            .emit()?;
        Ok(())
    }));
    // The chunk table: chunk_count entries and the terminating one.
    let entries = u64::from(chunk_count).saturating_add(1).min(MAX_CHUNKS);
    let table_span = file.sub(8, entries.saturating_mul(12));
    let table = cx.read(table_span).await?;
    let mut raw: Vec<([u8; 4], u64)> = Vec::new();
    for i in 0..entries {
        let at = crate::bytes::to_usize(i.saturating_mul(12));
        let (Some(id), Some(offset)) = (
            crate::bytes::array::<4>(&table, at),
            u64_be(&table, at.saturating_add(4)),
        ) else {
            break;
        };
        raw.push((id, offset));
    }
    let trailer_at = file.len.saturating_sub(hash);
    let mut chunks = Vec::new();
    let mut table_diags = Vec::new();
    for pair in raw.windows(2) {
        let (Some(&(id, start)), Some(&(_, end))) = (pair.first(), pair.get(1)) else {
            continue;
        };
        if id == [0; 4] {
            break;
        }
        if end < start || end > trailer_at {
            table_diags.push(Diagnostic::malformed(format!(
                "chunk {} runs from {start:#x} to {end:#x}",
                crate::formats::util::datakit::fourcc(&id)
            )));
            continue;
        }
        chunks.push((id, file.sub(start, end.saturating_sub(start))));
    }
    if raw.len() < crate::bytes::to_usize(u64::from(chunk_count).saturating_add(1)) {
        table_diags.push(Diagnostic::truncated(table_span, to_u64(table.len())));
    } else if raw.last().is_some_and(|(id, _)| *id != [0; 4]) {
        table_diags.push(Diagnostic::malformed(
            "the chunk table does not end with a zero ID",
        ));
    }
    let mut table_node = Node::new("Chunk table")
        .span(table_span)
        .summary(plural(chunks.len(), "chunk"))
        .lazy(chunk_table, (table_span, raw.len()));
    for d in table_diags {
        table_node = table_node.diag(d);
    }
    cx.emit(table_node);
    let mut g = Graph {
        file,
        hash,
        count: 0,
        bases,
        chunks: Arc::new(chunks),
    };
    if let Some(oidf) = g.chunk(b"OIDF") {
        let last = cx.read(oidf.sub(1020, 4)).await?;
        g.count = u64::from(u32_be(&last, 0).unwrap_or(0));
    }
    cx.annotate(format!(
        "Git commit-graph, {}{}{}",
        plural(g.count, "commit"),
        if hash == 32 { ", SHA-256" } else { "" },
        match bases {
            0 => String::new(),
            n => format!(", {} below", plural(n, "base graph")),
        }
    ));
    for (id, span) in g.chunks.iter() {
        cx.emit(chunk_node(&g, *id, *span));
    }
    let t = trailer(&cx, file, hash).await?;
    let mut sum = checksum_node(&cx, file, "Checksum", t).await?;
    if t.len != hash {
        sum = sum.diag(Diagnostic::warning(format!(
            "the checksum is a {}-byte hash, the header says {hash}",
            t.len
        )));
    }
    cx.emit(sum);
    Ok(())
}

async fn chunk_table(cx: Cx, (span, n): (Span, usize)) -> Result<()> {
    let data = cx.read(span).await?;
    for i in 0..n {
        let at = i.saturating_mul(12);
        let id = crate::bytes::array::<4>(&data, at).unwrap_or_default();
        let offset = u64_be(&data, at.saturating_add(4)).unwrap_or(0);
        let label = if id == [0; 4] {
            "end".to_owned()
        } else {
            crate::formats::util::datakit::fourcc(&id)
        };
        cx.push(
            Node::new(label)
                .span(span.sub(to_u64(at), 12))
                .value(crate::formats::util::datakit::hex(offset, 64))
                .summary(chunk_name(&id).unwrap_or(if id == [0; 4] {
                    "end of the last chunk"
                } else {
                    "unknown chunk"
                })),
        )
        .await;
    }
    Ok(())
}

fn chunk_node(g: &Graph, id: [u8; 4], span: Span) -> Node {
    let name = format!(
        "{} ({})",
        crate::formats::util::datakit::fourcc(&id),
        chunk_name(&id).unwrap_or("unknown")
    );
    let node = Node::new(name).span(span);
    let hash = g.hash;
    let count = g.count;
    let sized = |node: Node, want: Option<u64>, what: &str| match want {
        Some(w) if w != span.len => node.diag(Diagnostic::malformed(format!(
            "{} bytes, {} {what} need {w}",
            span.len, count
        ))),
        _ => node,
    };
    match &id {
        b"OIDF" => {
            let node = node.summary("cumulative commit counts by first byte");
            let node = if span.len == 1024 {
                node
            } else {
                node.diag(Diagnostic::malformed(format!(
                    "{} bytes, the fan-out table has 1024",
                    span.len
                )))
            };
            node.lazy(fanout, g.clone())
        }
        b"OIDL" => sized(
            node.summary(plural(count, "object name")),
            count.checked_mul(hash),
            "names",
        )
        .lazy(oid_list, g.clone()),
        b"CDAT" => sized(
            node.summary(plural(count, "commit")),
            count.checked_mul(g.record()),
            "commits",
        )
        .lazy(commits, g.clone()),
        b"GDA2" | b"GDAT" => sized(
            node.summary("corrected commit date offsets"),
            count.checked_mul(4),
            "commits",
        )
        .lazy(generation_data, (g.clone(), span)),
        b"GDO2" | b"GDOV" => node
            .summary(plural(span.len / 8, "overflowing offset"))
            .lazy(u64_list, span),
        b"EDGE" => node
            .summary(plural(span.len / 4, "edge"))
            .lazy(edges, (g.clone(), span)),
        b"BIDX" => sized(
            node.summary("end offsets of each commit's filter in BDAT"),
            count.checked_mul(4),
            "commits",
        )
        .lazy(bloom_index, span),
        b"BDAT" => node
            .summary("changed-path Bloom filters")
            .lazy(bloom_data, (g.clone(), span)),
        b"BASE" => {
            let want = u64::from(g.bases).checked_mul(hash);
            let node = node.summary(plural(g.bases, "base graph"));
            let node = match want {
                Some(w) if w != span.len => node.diag(Diagnostic::malformed(format!(
                    "{} bytes, {} base graphs need {w}",
                    span.len, g.bases
                ))),
                _ => node,
            };
            node.lazy(base_list, (span, hash))
        }
        _ => node,
    }
}

async fn fanout(cx: Cx, g: Graph) -> Result<()> {
    let Some(span) = g.chunk(b"OIDF") else {
        return Ok(());
    };
    let data = cx.read(span.sub(0, 1024)).await?;
    let mut prev = 0u32;
    for i in 0..256usize {
        let at = i.saturating_mul(4);
        let Some(v) = u32_be(&data, at) else {
            break;
        };
        let mut node = Node::new(format!("{i:02x}"))
            .span(span.sub(to_u64(at), 4))
            .value(uint(v, 32));
        if v < prev {
            node = node.diag(Diagnostic::malformed("fan-out counts decrease"));
        }
        prev = v;
        cx.push(node).await;
    }
    Ok(())
}

async fn oid_list(cx: Cx, g: Graph) -> Result<()> {
    cx.set_count(Count::Exact(g.count));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..g.count {
        cx.mark(move || i);
        let Some(span) = g.oid_span(i) else {
            cx.diag(Diagnostic::truncated(
                g.chunk(b"OIDL").unwrap_or(g.file).sub(0, 0),
                0,
            ));
            break;
        };
        let name = cx.read(span).await?;
        let mut node = Node::new(format!("[{i}]"))
            .span(span)
            .value(Value::Text(hex_string(&name)));
        // The names are sorted: check against the previous one.
        if let Some(prev) = i.checked_sub(1).and_then(|p| g.oid_span(p)) {
            let before = cx.read(prev).await?;
            if before >= name {
                node = node.diag(Diagnostic::malformed("object names are not sorted"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

/// One `CDAT` record.
struct Commit {
    tree: Vec<u8>,
    parent1: u32,
    parent2: u32,
    level: u32,
    date: u64,
}

fn decode_commit(b: &[u8], hash: usize) -> Option<Commit> {
    let tree = b.get(..hash)?.to_vec();
    let parent1 = u32_be(b, hash)?;
    let parent2 = u32_be(b, hash.checked_add(4)?)?;
    let tail = u64_be(b, hash.checked_add(8)?)?;
    Some(Commit {
        tree,
        parent1,
        parent2,
        level: u32::try_from(tail >> 34).unwrap_or(0),
        date: tail & ((1u64 << 34).saturating_sub(1)),
    })
}

fn timestamp(seconds: u64) -> Value {
    Value::Timestamp {
        unix_seconds: i64::try_from(seconds).unwrap_or(i64::MAX),
    }
}

/// The corrected commit date offset of commit `index` (from `GDA2`, and
/// `GDO2` when it overflows), if the file has them.
async fn date_offset(cx: &Cx, g: &Graph, index: u64) -> Option<u64> {
    let gda = g.chunk(b"GDA2")?;
    let raw = u32_be(
        &cx.read(gda.sub_exact(index.checked_mul(4)?, 4).ok()?)
            .await
            .ok()?,
        0,
    )?;
    if raw & OFFSET_OVERFLOW == 0 {
        return Some(raw.into());
    }
    let gdo = g.chunk(b"GDO2")?;
    let at = u64::from(raw & !OFFSET_OVERFLOW).checked_mul(8)?;
    u64_be(&cx.read(gdo.sub_exact(at, 8).ok()?).await.ok()?, 0)
}

/// A parent position as text: the commit's name when it is in this file
/// and the file has no base graphs.
async fn parent_text(cx: &Cx, g: &Graph, pos: u32) -> String {
    if g.bases == 0
        && let Some(oid) = g.oid(cx, pos.into()).await
    {
        return oid;
    }
    format!("position {pos}")
}

/// The extra parents of an octopus merge, starting at `EDGE` index
/// `first`: their positions (the last one with its flag cleared) and the
/// span they take.
async fn octopus(cx: &Cx, g: &Graph, first: u64) -> Result<(Vec<u32>, Span)> {
    let edge = g
        .chunk(b"EDGE")
        .ok_or_else(|| Diagnostic::malformed("octopus merge without an EDGE chunk"))?;
    let start = first.saturating_mul(4);
    let mut out = Vec::new();
    let mut at = start;
    loop {
        let b = cx.read(edge.sub_exact(at, 4)?).await?;
        let v = u32_be(&b, 0).unwrap_or(0);
        out.push(v & !LAST_EDGE);
        at = at.saturating_add(4);
        if v & LAST_EDGE != 0 {
            break;
        }
        if to_u64(out.len()) >= MAX_EDGES {
            return Err(
                Diagnostic::limit(format!("more than {MAX_EDGES} extra parents"))
                    .at(edge.sub(start, 4)),
            );
        }
        cx.checkpoint().await;
    }
    Ok((out, edge.sub(start, at.saturating_sub(start))))
}

async fn commits(cx: Cx, g: Graph) -> Result<()> {
    let Some(cdat) = g.chunk(b"CDAT") else {
        return Ok(());
    };
    cx.set_count(Count::Exact(g.count));
    let width = g.record();
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..g.count {
        cx.mark(move || i);
        let span = cdat.sub_exact(i.saturating_mul(width), width)?;
        let data = cx.read(span).await?;
        let Some(c) = decode_commit(&data, crate::bytes::to_usize(g.hash)) else {
            break;
        };
        let name = g.oid(&cx, i).await.unwrap_or_else(|| format!("[{i}]"));
        let parents = match (c.parent1, c.parent2) {
            (PARENT_NONE, _) => "root".to_owned(),
            (_, PARENT_NONE) => "1 parent".to_owned(),
            (_, p) if p & OCTOPUS != 0 => "octopus merge".to_owned(),
            _ => "2 parents".to_owned(),
        };
        let date = crate::render::value(&timestamp(c.date));
        cx.push(
            Node::new(name)
                .span(span)
                .summary(format!("#{i}, level {}, {date}, {parents}", c.level))
                .lazy(commit, (g.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn commit(cx: Cx, (g, i): (Graph, u64)) -> Result<()> {
    let Some(cdat) = g.chunk(b"CDAT") else {
        return Ok(());
    };
    let width = g.record();
    let span = cdat.sub_exact(i.saturating_mul(width), width)?;
    let data = cx.read(span).await?;
    let hash = crate::bytes::to_usize(g.hash);
    let c = decode_commit(&data, hash).ok_or_else(|| Diagnostic::truncated(span, 0))?;
    if let Some(oid) = g.oid_span(i) {
        cx.emit(
            Node::new("Commit")
                .span(oid)
                .value(Value::Text(g.oid(&cx, i).await.unwrap_or_default()))
                .desc("From the OID lookup table, at the same index"),
        );
    }
    cx.emit(
        Node::new("Root tree")
            .span(span.sub(0, g.hash))
            .value(Value::Text(hex_string(&c.tree))),
    );
    let parent_node = |name: &'static str, at: u64, pos: u32| {
        Node::new(name)
            .span(span.sub(g.hash.saturating_add(at), 4))
            .value(crate::formats::util::datakit::hex(pos, 32))
    };
    let p1 = parent_node("Parent 1", 0, c.parent1);
    cx.emit(if c.parent1 == PARENT_NONE {
        p1.summary("none")
    } else {
        p1.summary(parent_text(&cx, &g, c.parent1).await)
    });
    let p2 = parent_node("Parent 2", 4, c.parent2);
    if c.parent2 == PARENT_NONE {
        cx.emit(p2.summary("none"));
    } else if c.parent2 & OCTOPUS != 0 {
        let first = u64::from(c.parent2 & !OCTOPUS);
        match octopus(&cx, &g, first).await {
            Ok((positions, edge)) => {
                cx.emit(
                    p2.renamed("Extra edges")
                        .summary(format!(
                            "octopus merge: {} more parents from EDGE entry {first}",
                            positions.len()
                        ))
                        .target(edge),
                );
                for (k, pos) in positions.iter().enumerate() {
                    let at = edge.sub(to_u64(k).saturating_mul(4), 4);
                    cx.emit(
                        Node::new(format!("Parent {}", k.saturating_add(2)))
                            .span(at)
                            .value(crate::formats::util::datakit::hex(*pos, 32))
                            .summary(parent_text(&cx, &g, *pos).await)
                            .desc("From the extra edge list"),
                    );
                }
            }
            Err(d) => cx.emit(p2.diag(d)),
        }
    } else {
        cx.emit(p2.summary(parent_text(&cx, &g, c.parent2).await));
    }
    let tail = span.sub(g.hash.saturating_add(8), 8);
    cx.emit(
        Node::new("Topological level")
            .span(tail.sub(0, 4))
            .value(uint(c.level, 30))
            .desc("Generation number v1: the upper 30 bits"),
    );
    cx.emit(
        Node::new("Commit time")
            .span(tail)
            .value(timestamp(c.date))
            .desc("34 bits: the low 2 bits of the first word and the second word"),
    );
    if let Some(offset) = date_offset(&cx, &g, i).await {
        let corrected = c.date.saturating_add(offset);
        cx.emit(
            Node::new("Corrected commit date")
                .value(timestamp(corrected))
                .summary(format!("commit time + {offset} s (GDA2)"))
                .desc("Generation number v2"),
        );
    }
    Ok(())
}

async fn generation_data(cx: Cx, (g, span): (Graph, Span)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..n {
        cx.mark(move || i);
        let at = span.sub(i.saturating_mul(4), 4);
        let raw = u32_be(&cx.read(at).await?, 0).unwrap_or(0);
        let node = Node::new(format!("[{i}]")).span(at);
        cx.push(if raw & OFFSET_OVERFLOW != 0 {
            node.value(crate::formats::util::datakit::hex(raw, 32))
                .summary(format!("overflow: GDO2 entry {}", raw & !OFFSET_OVERFLOW))
        } else {
            let mut node = node.value(uint(raw, 31));
            if g.bases == 0
                && let Some(oid) = g.oid(&cx, i).await
            {
                node = node.summary(oid);
            }
            node
        })
        .await;
    }
    Ok(())
}

async fn u64_list(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 8;
    cx.set_count(Count::Exact(n));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..n {
        cx.mark(move || i);
        let at = span.sub(i.saturating_mul(8), 8);
        let v = u64_be(&cx.read(at).await?, 0).unwrap_or(0);
        cx.push(Node::new(format!("[{i}]")).span(at).value(uint(v, 64)))
            .await;
    }
    Ok(())
}

async fn edges(cx: Cx, (g, span): (Graph, Span)) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..n {
        cx.mark(move || i);
        let at = span.sub(i.saturating_mul(4), 4);
        let raw = u32_be(&cx.read(at).await?, 0).unwrap_or(0);
        let pos = raw & !LAST_EDGE;
        let mut text = parent_text(&cx, &g, pos).await;
        if raw & LAST_EDGE != 0 {
            text.push_str(", last parent");
        }
        cx.push(
            Node::new(format!("[{i}]"))
                .span(at)
                .value(crate::formats::util::datakit::hex(raw, 32))
                .summary(text),
        )
        .await;
    }
    Ok(())
}

async fn bloom_index(cx: Cx, span: Span) -> Result<()> {
    let n = span.len / 4;
    cx.set_count(Count::Exact(n));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..n {
        cx.mark(move || i);
        let at = span.sub(i.saturating_mul(4), 4);
        let v = u32_be(&cx.read(at).await?, 0).unwrap_or(0);
        cx.push(Node::new(format!("[{i}]")).span(at).value(uint(v, 32)))
            .await;
    }
    Ok(())
}

/// Filter bytes shown at most.
const MAX_FILTER_BYTES: u64 = 64;

async fn bloom_data(cx: Cx, (g, span): (Graph, Span)) -> Result<()> {
    let header = span.sub(0, 12);
    cx.emit(struct_node("Header", header, BE, (), |f, _| {
        f.u32("Hash version")
            .desc("1: murmur3 over signed chars (the original, buggy for bytes above 0x7f); 2: unsigned")
            .emit()?;
        f.u32("Number of hashes").emit()?;
        f.u32("Bits per entry").emit()?;
        Ok(())
    }));
    let filters = span.tail(12);
    let Some(bidx) = g.chunk(b"BIDX") else {
        cx.emit(
            Node::new("Filters")
                .span(filters)
                .diag(Diagnostic::malformed(
                    "no BIDX chunk to find the filters by",
                )),
        );
        return Ok(());
    };
    cx.emit(
        Node::new("Filters")
            .span(filters)
            .summary(plural(g.count, "filter"))
            .lazy(bloom_filters, (g, bidx, filters)),
    );
    Ok(())
}

async fn bloom_filters(cx: Cx, (g, bidx, filters): (Graph, Span, Span)) -> Result<()> {
    let n = (bidx.len / 4).min(g.count);
    cx.set_count(Count::Exact(n));
    let first = cx.resume::<u64>().unwrap_or(0);
    for i in first..n {
        cx.mark(move || i);
        let end = u32_be(&cx.read(bidx.sub(i.saturating_mul(4), 4)).await?, 0).unwrap_or(0);
        let start = match i.checked_sub(1) {
            Some(p) => u32_be(&cx.read(bidx.sub(p.saturating_mul(4), 4)).await?, 0).unwrap_or(0),
            None => 0,
        };
        let name = if g.bases == 0 {
            g.oid(&cx, i).await.unwrap_or_else(|| format!("[{i}]"))
        } else {
            format!("[{i}]")
        };
        let mut node = Node::new(name);
        if end < start || u64::from(end) > filters.len {
            node = node.diag(Diagnostic::malformed(format!(
                "filter from {start} to {end} does not fit"
            )));
            cx.push(node).await;
            continue;
        }
        let len = u64::from(end.saturating_sub(start));
        let span = filters.sub(start.into(), len);
        let bytes = cx.read(span.sub(0, MAX_FILTER_BYTES)).await?;
        let summary = match (len, bytes.first()) {
            (0, _) => "not computed".to_owned(),
            (1, Some(0)) => "no changed paths".to_owned(),
            (1, Some(0xff)) => "too many changed paths (all bits set)".to_owned(),
            _ => {
                let set: u32 = bytes.iter().map(|b| b.count_ones()).sum();
                let more = if len > MAX_FILTER_BYTES { "+" } else { "" };
                format!(
                    "{len} bytes, {set}{more} of {} bits set",
                    len.saturating_mul(8)
                )
            }
        };
        node = node.span(span).summary(summary);
        if len > 0 {
            node = node.value(Value::Bytes(bytes));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn base_list(cx: Cx, (span, hash): (Span, u64)) -> Result<()> {
    let n = span.len.checked_div(hash).unwrap_or(0);
    for i in 0..n {
        let at = span.sub(i.saturating_mul(hash), hash);
        let name = cx.read(at).await?;
        cx.push(
            Node::new(format!("[{i}]"))
                .span(at)
                .value(Value::Text(hex_string(&name)))
                .summary(format!("graph-{}.graph", hex_string(&name))),
        )
        .await;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::decode_commit;

    #[test]
    fn commit_record() {
        // level 3, date 0x1_0000_0002 (34 bits)
        let mut b = vec![0xaa; 20];
        b.extend_from_slice(&[0, 0, 0, 1, 0x70, 0, 0, 0]);
        b.extend_from_slice(&((3u64 << 34) | 0x1_0000_0002).to_be_bytes());
        let c = decode_commit(&b, 20).unwrap();
        assert_eq!(c.level, 3);
        assert_eq!(c.date, 0x1_0000_0002);
        assert_eq!(c.parent1, 1);
        assert_eq!(c.parent2, 0x7000_0000);
    }
}
