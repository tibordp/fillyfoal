//! Apache Arrow IPC files (Feather v2): `ARROW1`, a stream of messages
//! (schema, dictionary and record batches), then a footer (FlatBuffers)
//! indexing the batches, its length and `ARROW1` again.
//!
//! FlatBuffers are read with a small table reader; schema fields nest (via
//! children) and are expanded lazily with a depth cap.

use std::sync::Arc;

use crate::bytes::{to_u64, u32_le, u64_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::formats::util::wire::flatbuffers::mem::{Table, deref, table};
use crate::value::{EnumTable, Radix, Value, lookup};

const MAGIC: &[u8] = b"ARROW1";
const MAX_DEPTH: u32 = 32;
const MAX_FOOTER: u64 = 64 << 20;

pub static FORMAT: Format = Format {
    name: "arrow",
    title: "Apache Arrow IPC file (Feather v2)",
    extensions: &["arrow", "feather", "ipc"],
    mime: "application/vnd.apache.arrow.file",
    probe: Probe::Custom(|h: &Head<'_>| h.starts_with(b"ARROW1\0\0") && h.tail.ends_with(MAGIC)),
    dissect: crate::expander!(dissect: Input),
};

const TYPES: EnumTable = &[
    (0, "NONE"),
    (1, "Null"),
    (2, "Int"),
    (3, "FloatingPoint"),
    (4, "Binary"),
    (5, "Utf8"),
    (6, "Bool"),
    (7, "Decimal"),
    (8, "Date"),
    (9, "Time"),
    (10, "Timestamp"),
    (11, "Interval"),
    (12, "List"),
    (13, "Struct"),
    (14, "Union"),
    (15, "FixedSizeBinary"),
    (16, "FixedSizeList"),
    (17, "Map"),
    (18, "Duration"),
    (19, "LargeBinary"),
    (20, "LargeUtf8"),
    (21, "LargeList"),
    (22, "RunEndEncoded"),
    (23, "BinaryView"),
    (24, "Utf8View"),
    (25, "ListView"),
    (26, "LargeListView"),
];

const HEADERS: EnumTable = &[
    (1, "Schema"),
    (2, "DictionaryBatch"),
    (3, "RecordBatch"),
    (4, "Tensor"),
    (5, "SparseTensor"),
];
const VERSIONS: EnumTable = &[(0, "V1"), (1, "V2"), (2, "V3"), (3, "V4"), (4, "V5")];

// ---------------------------------------------------------------------------
// FlatBuffers (read with `util::wire::flatbuffers::mem`)

#[derive(Clone)]
struct Buf {
    data: Arc<Vec<u8>>,
    span: Span,
}

impl Buf {
    fn at(&self, pos: usize, len: usize) -> Span {
        self.span.sub(to_u64(pos), to_u64(len))
    }
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 8))
            .value(Value::Text("ARROW1".to_owned())),
    );
    let tail_span = file.sub(file.len.saturating_sub(10), 10);
    let tail = cx.read(tail_span).await?;
    let len = u64::from(u32_le(&tail, 0).unwrap_or(0));
    let start = file
        .len
        .saturating_sub(10)
        .checked_sub(len)
        .filter(|&s| s >= 8)
        .ok_or_else(|| {
            Diagnostic::malformed("footer length does not fit").at(tail_span.sub(0, 4))
        })?;
    if len > MAX_FOOTER {
        return Err(Diagnostic::limit("footer too large").at(tail_span));
    }
    let span = file.sub(start, len);
    let buf = Buf {
        data: Arc::new(cx.read(span).await?),
        span,
    };
    let data = &buf.data;
    let footer = deref(data, 0)
        .and_then(|p| table(data, p))
        .ok_or_else(|| Diagnostic::malformed("invalid footer table").at(span))?;
    let schema = footer.table(data, 1);
    let fields = schema.and_then(|s| s.vector(data, 1, 4)).map_or(0, |(n, _)| n);
    let batches = footer.vector(data, 3, 24).map_or(0, |(n, _)| n);
    let version = footer.i16(data, 0).unwrap_or(0);
    cx.annotate(format!(
        "Arrow IPC file, metadata {}, {fields} fields, {batches} record batches",
        lookup(VERSIONS, u64::from(version.cast_unsigned())).unwrap_or("unknown version")
    ));
    cx.emit(
        Node::new("Messages")
            .span(file.sub(8, start.saturating_sub(8)))
            .lazy(messages, (input, 8u64, start)),
    );
    cx.emit(
        Node::new("Footer")
            .span(span)
            .lazy(footer_node, (input, buf.clone())),
    );
    cx.emit(
        Node::new("Footer length")
            .span(tail_span.sub(0, 4))
            .value(Value::UInt {
                value: len,
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Magic")
            .span(tail_span.sub(4, 6))
            .value(Value::Text("ARROW1".to_owned())),
    );
    Ok(())
}

async fn footer_node(cx: Cx, (input, buf): (Input, Buf)) -> Result<()> {
    let data = &buf.data;
    let footer = deref(data, 0)
        .and_then(|p| table(data, p))
        .ok_or_else(|| Diagnostic::malformed("invalid footer table"))?;
    if let Some(v) = footer.i16(data, 0) {
        cx.emit(Node::new("Version").value(Value::Enum {
            raw: u64::from(v.cast_unsigned()),
            bits: 16,
            name: lookup(VERSIONS, u64::from(v.cast_unsigned())),
        }));
    }
    if let Some(schema) = footer.table(data, 1) {
        cx.emit(schema_node(&buf, schema));
    }
    for (i, name) in [(2usize, "Dictionaries"), (3, "Record batches")] {
        if let Some((n, start)) = footer.vector(data, i, 24) {
            cx.emit(
                Node::new(name)
                    .summary(format!("{n}"))
                    .lazy(blocks, (input, buf.clone(), n, start)),
            );
        }
    }
    Ok(())
}

fn schema_node(buf: &Buf, schema: Table) -> Node {
    let data = &buf.data;
    let (n, start) = schema.vector(data, 1, 4).unwrap_or((0, 0));
    Node::new("Schema")
        .span(buf.at(schema.pos, 4))
        .summary(format!("{n} fields"))
        .lazy(fields, (buf.clone(), n, start, 0u32))
}

fn type_summary(data: &[u8], field: &Table) -> String {
    let kind = field.u8(data, 2).unwrap_or(0);
    let name = lookup(TYPES, kind.into()).unwrap_or("unknown").to_owned();
    let Some(t) = field.table(data, 3) else {
        return name;
    };
    match kind {
        2 => format!(
            "{}{}",
            if t.u8(data, 1).unwrap_or(0) != 0 {
                "int"
            } else {
                "uint"
            },
            t.i32(data, 0).unwrap_or(0)
        ),
        3 => match t.i16(data, 0).unwrap_or(0) {
            0 => "float16".to_owned(),
            1 => "float32".to_owned(),
            _ => "float64".to_owned(),
        },
        7 => format!(
            "Decimal({}, {})",
            t.i32(data, 0).unwrap_or(0),
            t.i32(data, 1).unwrap_or(0)
        ),
        15 => format!("FixedSizeBinary({})", t.i32(data, 0).unwrap_or(0)),
        _ => name,
    }
}

async fn fields(cx: Cx, (buf, n, start, depth): (Buf, usize, usize, u32)) -> Result<()> {
    let data = buf.data.clone();
    cx.set_count(Count::Exact(to_u64(n)));
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(4));
        let Some(field) = deref(&data, at).and_then(|p| table(&data, p)) else {
            return Err(Diagnostic::malformed("invalid field table").at(buf.at(at, 4)));
        };
        let name = field.string(&data, 0).map(|s| s.0).unwrap_or_default();
        let nullable = field.u8(&data, 1).unwrap_or(0) != 0;
        let mut summary = type_summary(&data, &field);
        if nullable {
            summary.push_str(", nullable");
        }
        let mut node = Node::new(if name.is_empty() {
            format!("Field {i}")
        } else {
            name
        })
        .span(buf.at(field.pos, 4))
        .summary(summary);
        if let Some((count, children)) = field.vector(&data, 5, 4).filter(|(c, _)| *c > 0) {
            node = if depth >= MAX_DEPTH {
                node.diag(Diagnostic::limit("fields nested too deeply"))
            } else {
                node.lazy(
                    crate::expander!(self::fields: (Buf, usize, usize, u32)),
                    (buf.clone(), count, children, depth.saturating_add(1)),
                )
            };
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Footer blocks: (offset, metadata length, body length) structs.
async fn blocks(cx: Cx, (input, buf, n, start): (Input, Buf, usize, usize)) -> Result<()> {
    let data = buf.data.clone();
    cx.set_count(Count::Exact(to_u64(n)));
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(24));
        let (Some(offset), Some(meta), Some(body)) = (
            u64_le(&data, at),
            u32_le(&data, at.saturating_add(8)),
            u64_le(&data, at.saturating_add(16)),
        ) else {
            break;
        };
        let whole = input.span.sub(offset, u64::from(meta).saturating_add(body));
        cx.push(
            Node::new(format!("Block {i}"))
                .span(buf.at(at, 24))
                .value(Value::UInt {
                    value: offset,
                    bits: 64,
                    radix: Radix::Hex,
                })
                .summary(format!("metadata {meta} bytes, body {body} bytes"))
                .target(whole)
                .lazy(message, (input, offset)),
        )
        .await;
    }
    Ok(())
}

/// Messages in sequence: continuation marker, metadata length, metadata,
/// body.
async fn messages(cx: Cx, (input, start, end): (Input, u64, u64)) -> Result<()> {
    let mut pos = start;
    let mut i = 0u64;
    while pos < end {
        let head = cx.read_avail(input.span.sub(pos, 8)).await?;
        let (prefix, meta) = if u32_le(&head, 0) == Some(u32::MAX) {
            (8u64, u32_le(&head, 4).unwrap_or(0))
        } else {
            (4, u32_le(&head, 0).unwrap_or(0))
        };
        if meta == 0 {
            cx.push(Node::new("End of stream").span(input.span.sub(pos, prefix)))
                .await;
            break;
        }
        let body = message_body_len(&cx, input, pos.saturating_add(prefix), meta)
            .await
            .unwrap_or(0);
        let total = prefix.saturating_add(meta.into()).saturating_add(body);
        cx.push(
            Node::new(format!("Message {i}"))
                .span(input.span.sub(pos, total))
                .lazy(message, (input, pos)),
        )
        .await;
        pos = pos.saturating_add(total.max(1));
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn message_body_len(cx: &Cx, input: Input, at: u64, meta: u32) -> Result<u64> {
    let data = cx.read(input.span.sub_exact(at, meta.into())?).await?;
    let msg = deref(&data, 0)
        .and_then(|p| table(&data, p))
        .ok_or_else(|| Diagnostic::malformed("invalid message"))?;
    Ok(msg
        .i64(&data, 3)
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0))
}

async fn message(cx: Cx, (input, pos): (Input, u64)) -> Result<()> {
    let head = cx.read(input.span.sub(pos, 8)).await?;
    let (prefix, meta) = if u32_le(&head, 0) == Some(u32::MAX) {
        (8u64, u32_le(&head, 4).unwrap_or(0))
    } else {
        (4, u32_le(&head, 0).unwrap_or(0))
    };
    cx.emit(
        Node::new("Metadata length")
            .span(input.span.sub(pos, prefix))
            .value(Value::UInt {
                value: meta.into(),
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    let span = input
        .span
        .sub_exact(pos.saturating_add(prefix), meta.into())?;
    let buf = Buf {
        data: Arc::new(cx.read(span).await?),
        span,
    };
    let data = &buf.data;
    let msg = deref(data, 0)
        .and_then(|p| table(data, p))
        .ok_or_else(|| Diagnostic::malformed("invalid message").at(span))?;
    let kind = msg.u8(data, 1).unwrap_or(0);
    let body_len = msg
        .i64(data, 3)
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);
    cx.annotate(lookup(HEADERS, kind.into()).unwrap_or("message").to_owned());
    cx.emit(Node::new("Header type").value(Value::Enum {
        raw: kind.into(),
        bits: 8,
        name: lookup(HEADERS, kind.into()),
    }));
    let body = input.span.sub(
        pos.saturating_add(prefix).saturating_add(meta.into()),
        body_len,
    );
    match (kind, msg.table(data, 2)) {
        (1, Some(schema)) => cx.emit(schema_node(&buf, schema)),
        (3 | 2, Some(mut batch)) => {
            if kind == 2 {
                // DictionaryBatch: id, data (a RecordBatch), isDelta.
                cx.emit(Node::new("Dictionary id").value(Value::Int {
                    value: batch.i64(data, 0).unwrap_or(0),
                    bits: 64,
                }));
                match batch.table(data, 1) {
                    Some(b) => batch = b,
                    None => return Ok(()),
                }
            }
            cx.emit(
                Node::new("Length")
                    .value(Value::Int {
                        value: batch.i64(data, 0).unwrap_or(0),
                        bits: 64,
                    })
                    .summary("rows"),
            );
            if let Some((n, start)) = batch.vector(data, 1, 16) {
                let nodes: Vec<Node> = (0..n.min(4096))
                    .map(|i| {
                        let at = start.saturating_add(i.saturating_mul(16));
                        Node::new(format!("Field node {i}"))
                            .span(buf.at(at, 16))
                            .summary(format!(
                                "{} values, {} nulls",
                                u64_le(data, at).unwrap_or(0),
                                u64_le(data, at.saturating_add(8)).unwrap_or(0)
                            ))
                    })
                    .collect();
                cx.emit(
                    Node::new("Nodes")
                        .summary(format!("{n}"))
                        .lazy(emit_nodes, Arc::new(nodes)),
                );
            }
            if let Some((n, start)) = batch.vector(data, 2, 16) {
                let nodes: Vec<Node> = (0..n.min(4096))
                    .map(|i| {
                        let at = start.saturating_add(i.saturating_mul(16));
                        let off = u64_le(data, at).unwrap_or(0);
                        let len = u64_le(data, at.saturating_add(8)).unwrap_or(0);
                        Node::new(format!("Buffer {i}"))
                            .span(buf.at(at, 16))
                            .value(Value::UInt {
                                value: off,
                                bits: 64,
                                radix: Radix::Hex,
                            })
                            .summary(format!("{len} bytes"))
                            .target(body.sub(off, len))
                    })
                    .collect();
                cx.emit(
                    Node::new("Buffers")
                        .summary(format!("{n}"))
                        .lazy(emit_nodes, Arc::new(nodes)),
                );
            }
        }
        _ => {}
    }
    cx.emit(
        Node::new("Body")
            .span(body)
            .summary(format!("{body_len} bytes")),
    );
    Ok(())
}

async fn emit_nodes(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.push(n.clone()).await;
    }
    Ok(())
}
