//! `mongodump --archive` files (MongoDB database tools): one stream that
//! multiplexes every dumped collection.
//!
//! Layout, as mongo-tools writes it (`common/archive`; written from memory
//! and checked against mongodump 100.17.0's output):
//! the magic number `0x8199e26d` (little-endian), the prelude (a header
//! document with the archive format version, server and tool versions,
//! then one document per collection: database, name, the collection's
//! metadata as extended JSON, size and type, ended by a terminator
//! `0xffffffff`), then blocks. A block is a namespace header document
//! (`db`, `collection`, `EOF`, `CRC`), the namespace's BSON documents and
//! a terminator; collections dumped in parallel interleave their blocks.
//! A namespace ends with a block whose header has `EOF` set and no
//! documents, carrying the CRC-64 (ECMA polynomial, reflected, as Go's
//! `hash/crc64` computes it: CRC-64/XZ) of all the namespace's documents,
//! checked here as the blocks are walked.
//!
//! `mongodump --archive --gzip` compresses the whole stream with gzip; the
//! gzip dissector finds the archive inside. Documents are dissected by the
//! BSON dissector.

use std::collections::BTreeMap;

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::codec::crc::CRC64_XZ;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, hex};
use crate::formats::util::fmt::plural;
use crate::formats::{Format, Head, Input, Probe, dissect_named};
use crate::node::{Count, Node};
use crate::span::Span;

use super::bson;

pub static FORMAT: Format = Format {
    name: "mongo-archive",
    title: "MongoDB dump archive",
    extensions: &["archive"],
    mime: "application/x-mongodb-archive",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const MAGIC: [u8; 4] = [0x6d, 0xe2, 0x99, 0x81];
const TERMINATOR: u32 = 0xffff_ffff;
/// Header documents (prelude and namespace headers) read at most.
const MAX_HEADER: u64 = 0x10_0000;
/// Bytes hashed per read when checking a namespace's CRC.
const HASH_CHUNK: u64 = 1 << 20;

/// The magic and a plausible first document (the prelude header).
fn probe(h: &Head<'_>) -> bool {
    if h.data.get(..4) != Some(&MAGIC[..]) {
        return false;
    }
    let Some(len) = u32_le(h.data, 4) else {
        return false;
    };
    let len = u64::from(len);
    if !(5..=MAX_HEADER).contains(&len) || (h.len_known && len.saturating_add(4) > h.len) {
        return false;
    }
    // The first element's type (the header holds strings and an int32),
    // and the document's terminating zero when the head holds it.
    let first_type_ok = matches!(h.data.get(8), Some(0x02 | 0x10 | 0x12 | 0x08 | 0x03 | 0x00));
    let end = to_usize(len.saturating_add(3));
    first_type_ok && h.data.get(end).is_none_or(|&b| b == 0)
}

/// A few scalar fields of a small, flat BSON document.
#[derive(Clone, Debug, Default)]
struct Fields {
    strings: BTreeMap<String, String>,
    ints: BTreeMap<String, i64>,
    bools: BTreeMap<String, bool>,
}

impl Fields {
    fn text(&self, key: &str) -> &str {
        self.strings.get(key).map_or("", String::as_str)
    }
}

/// Reads the scalar fields of the document `doc` (other elements are
/// skipped; nested documents are not entered).
fn flat_fields(doc: &[u8]) -> Fields {
    let mut f = Fields::default();
    let last = doc.len().saturating_sub(1);
    let mut p = 4usize;
    while p < last {
        let Some(&t) = doc.get(p) else {
            break;
        };
        let name_start = p.saturating_add(1);
        let Some(nul) = doc
            .get(name_start..last)
            .and_then(|b| b.iter().position(|&c| c == 0))
        else {
            break;
        };
        let name = String::from_utf8_lossy(
            doc.get(name_start..name_start.saturating_add(nul))
                .unwrap_or_default(),
        )
        .into_owned();
        let v = name_start.saturating_add(nul).saturating_add(1);
        let body = doc.get(v..).unwrap_or_default();
        let Some(n) = bson::value_len(t, body) else {
            break;
        };
        match t {
            0x02 => {
                let len = to_usize(n.saturating_sub(5));
                let s = body.get(4..4usize.saturating_add(len)).unwrap_or_default();
                f.strings
                    .insert(name, String::from_utf8_lossy(s).into_owned());
            }
            0x08 => {
                f.bools.insert(name, body.first().is_some_and(|&b| b != 0));
            }
            0x10 => {
                let b: [u8; 4] = body
                    .get(..4)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or_default();
                f.ints.insert(name, i32::from_le_bytes(b).into());
            }
            0x12 => {
                let b: [u8; 8] = body
                    .get(..8)
                    .and_then(|b| b.try_into().ok())
                    .unwrap_or_default();
                f.ints.insert(name, i64::from_le_bytes(b));
            }
            _ => {}
        }
        p = v.saturating_add(to_usize(n));
    }
    f
}

/// What is at `at`: a terminator, or a document of `len` bytes.
enum Item {
    Terminator,
    Document(u64),
}

async fn item(r: &mut ByteReader<'_>, at: u64) -> Result<Item> {
    let v = u32::try_from(r.le(at, 4).await?).unwrap_or(0);
    if v == TERMINATOR {
        return Ok(Item::Terminator);
    }
    let len = u64::from(v);
    let left = r.region().len.saturating_sub(at);
    if len < 5 || len > left {
        return Err(Diagnostic::malformed(format!(
            "document length {len} does not fit in the {left} bytes left"
        ))
        .at(r.span(at, 4)));
    }
    Ok(Item::Document(len))
}

/// Reads a small header document's scalar fields.
async fn header_fields(cx: &Cx, span: Span) -> Result<Fields> {
    let data = cx.read(span.sub(0, MAX_HEADER)).await?;
    Ok(flat_fields(&data))
}

/// A BSON document dissected by the BSON dissector, keeping `summary`
/// (what the document is in the archive) over the BSON dissector's own
/// "BSON document, N bytes" once it is expanded.
fn bson_node(input: &Input, name: impl Into<String>, span: Span, summary: String) -> Node {
    Node::new(name.into())
        .span(span)
        .summary(summary.clone())
        .lazy(bson_document, (input.nested(span), summary))
}

async fn bson_document(cx: Cx, (input, summary): (Input, String)) -> Result<()> {
    let result = dissect_named(cx.clone(), (input, bson::FORMAT.name)).await;
    cx.annotate(summary);
    result
}

/// Walk state: position, block index and the running CRCs of namespaces
/// not yet ended (namespace → CRC state, `None` once a document was too
/// large to hash).
type Walk = (u64, u64, BTreeMap<String, Option<u64>>);

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut r = ByteReader::new(&cx, file);
    let resumed = cx.resume::<Walk>();
    let (mut pos, mut index, mut crcs) = match resumed {
        Some(state) => state,
        None => {
            cx.emit(
                Node::new("Magic")
                    .span(file.sub(0, 4))
                    .value(hex(0x8199_e26du32, 32)),
            );
            let Item::Document(len) = item(&mut r, 4).await? else {
                return Err(Diagnostic::malformed("no prelude header").at(file.sub(4, 4)));
            };
            let header_span = file.sub(4, len);
            let header = header_fields(&cx, header_span).await?;
            cx.emit(bson_node(
                &input,
                "Prelude header",
                header_span,
                format!(
                    "archive format {}, server {}, tool {}",
                    header.text("version"),
                    header.text("server_version"),
                    header.text("tool_version")
                ),
            ));
            // The collection metadata documents, up to the terminator.
            let start = 4u64.saturating_add(len);
            let mut at = start;
            let mut count = 0u64;
            loop {
                match item(&mut r, at).await? {
                    Item::Terminator => break,
                    Item::Document(n) => {
                        at = at.saturating_add(n);
                        count = count.saturating_add(1);
                    }
                }
            }
            let list = file.sub(start, at.saturating_sub(start));
            cx.emit(
                Node::new("Collections")
                    .span(list)
                    .summary(plural(count, "collection"))
                    .lazy(collections, (input, list, count)),
            );
            cx.emit(
                Node::new("Prelude terminator")
                    .span(file.sub(at, 4))
                    .value(hex(TERMINATOR, 32)),
            );
            cx.annotate(format!(
                "mongodump archive, {}, server {}",
                plural(count, "collection"),
                header.text("server_version")
            ));
            (at.saturating_add(4), 0, BTreeMap::new())
        }
    };
    while pos < file.len {
        let mark: Walk = (pos, index, crcs.clone());
        cx.mark(move || mark);
        let block = match walk_block(&cx, &mut r, pos, &mut crcs).await {
            Ok(b) => b,
            Err(d) => {
                cx.push(
                    Node::new(format!("Block {index}"))
                        .span(file.tail(pos))
                        .diag(d),
                )
                .await;
                return Ok(());
            }
        };
        let span = file.sub(pos, block.end.saturating_sub(pos));
        let mut node = Node::new(block.namespace.clone()).span(span);
        node = match (block.eof, block.check) {
            (true, Some(true)) => node.summary(format!(
                "end of namespace, CRC-64 {:#018x} (valid)",
                block.crc
            )),
            (true, Some(false)) => node
                .summary(format!("end of namespace, CRC-64 {:#018x}", block.crc))
                .diag(Diagnostic::warning("CRC-64 mismatch")),
            (true, None) => node.summary(format!("end of namespace, CRC-64 {:#018x}", block.crc)),
            (false, _) => node.summary(plural(block.documents, "document")),
        };
        if block.eof && block.documents > 0 {
            node = node.diag(Diagnostic::malformed(
                "an end-of-namespace block holds documents",
            ));
        }
        cx.progress_in(file, block.end);
        cx.push(node.lazy(
            block_contents,
            (input, span, block.header_len, block.documents),
        ))
        .await;
        pos = block.end;
        index = index.saturating_add(1);
    }
    if !crcs.is_empty() {
        cx.diag(Diagnostic::warning(format!(
            "{} not ended (no EOF block)",
            plural(crcs.len(), "namespace")
        )));
    }
    Ok(())
}

/// A walked block.
struct Block {
    namespace: String,
    header_len: u64,
    documents: u64,
    eof: bool,
    /// The CRC the header records.
    crc: u64,
    /// Whether it matched (`None`: not checked).
    check: Option<bool>,
    /// Where the block ends (after its terminator).
    end: u64,
}

async fn walk_block(
    cx: &Cx,
    r: &mut ByteReader<'_>,
    pos: u64,
    crcs: &mut BTreeMap<String, Option<u64>>,
) -> Result<Block> {
    let Item::Document(header_len) = item(r, pos).await? else {
        return Err(
            Diagnostic::malformed("a terminator where a namespace header belongs")
                .at(r.span(pos, 4)),
        );
    };
    let header = header_fields(cx, r.span(pos, header_len)).await?;
    let namespace = format!("{}.{}", header.text("db"), header.text("collection"));
    let eof = header.bools.get("EOF").copied().unwrap_or(false);
    let crc = header
        .ints
        .get("CRC")
        .map_or(0, |&v| u64::from_le_bytes(v.to_le_bytes()));
    let mut at = pos.saturating_add(header_len);
    let mut documents = 0u64;
    let state = crcs
        .entry(namespace.clone())
        .or_insert(Some(CRC64_XZ.init()));
    loop {
        match item(r, at).await? {
            Item::Terminator => break,
            Item::Document(n) => {
                let span = r.span(at, n);
                if let Some(c) = state.as_mut() {
                    if n > cx.limits().max_read {
                        *state = None;
                    } else {
                        let mut done = 0u64;
                        while done < n {
                            let chunk = cx.read(span.sub(done, HASH_CHUNK)).await?;
                            if chunk.is_empty() {
                                break;
                            }
                            *c = CRC64_XZ.update(*c, &chunk);
                            cx.charge(to_u64(chunk.len()) / 256).await;
                            done = done.saturating_add(to_u64(chunk.len()));
                        }
                    }
                }
                at = at.saturating_add(n);
                documents = documents.saturating_add(1);
                cx.progress_in(r.region(), at);
            }
        }
    }
    let check = if eof {
        crcs.remove(&namespace)
            .flatten()
            .map(|c| CRC64_XZ.finish(c) == crc)
    } else {
        None
    };
    Ok(Block {
        namespace,
        header_len,
        documents,
        eof,
        crc,
        check,
        end: at.saturating_add(4),
    })
}

async fn collections(cx: Cx, (input, list, count): (Input, Span, u64)) -> Result<()> {
    cx.set_count(Count::Exact(count));
    let mut r = ByteReader::new(&cx, list);
    let (mut at, first) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    for i in first..count {
        let mark = (at, i);
        cx.mark(move || mark);
        let Item::Document(n) = item(&mut r, at).await? else {
            break;
        };
        let span = list.sub(at, n);
        let f = header_fields(&cx, span).await?;
        let size = f.ints.get("size").copied().unwrap_or(0);
        let mut summary = f.text("type").to_owned();
        if size > 0 {
            summary = format!("{summary}, {size} bytes");
        }
        cx.push(bson_node(
            &input,
            format!("{}.{}", f.text("db"), f.text("collection")),
            span,
            summary,
        ))
        .await;
        at = at.saturating_add(n);
    }
    Ok(())
}

async fn block_contents(
    cx: Cx,
    (input, span, header_len, documents): (Input, Span, u64, u64),
) -> Result<()> {
    cx.set_count(Count::Exact(documents.saturating_add(2)));
    let mut r = ByteReader::new(&cx, span);
    let (mut at, first) = match cx.resume::<(u64, u64)>() {
        Some(state) => state,
        None => {
            let header = span.sub(0, header_len);
            let f = header_fields(&cx, header).await?;
            let eof = f.bools.get("EOF").copied().unwrap_or(false);
            cx.push(bson_node(
                &input,
                "Namespace header",
                header,
                if eof {
                    "end of namespace"
                } else {
                    "documents follow"
                }
                .to_owned(),
            ))
            .await;
            (header_len, 0)
        }
    };
    for i in first..documents {
        let mark = (at, i);
        cx.mark(move || mark);
        let Item::Document(n) = item(&mut r, at).await? else {
            break;
        };
        let summary = bson::document_summary(&mut r, at, n).await;
        cx.push(bson_node(
            &input,
            format!("Document {i}"),
            span.sub(at, n),
            summary,
        ))
        .await;
        at = at.saturating_add(n);
    }
    cx.push(
        Node::new("Terminator")
            .span(span.sub(at, 4))
            .value(hex(TERMINATOR, 32)),
    )
    .await;
    Ok(())
}
