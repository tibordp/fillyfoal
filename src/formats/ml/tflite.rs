//! FlatBuffers-based model formats: TensorFlow Lite (`TFL3`), the ONNX
//! Runtime format (`ORTM`) and ExecuTorch programs (`ET..`).

use std::sync::Arc;

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

use crate::formats::util::wire::flatbuffers::{Fb, Table, Vector, dims, raw_table};

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64) -> Value {
    Value::UInt {
        value,
        bits: 64,
        radix: Radix::Dec,
    }
}

/// The root offset must point inside the file, past the identifier.
fn root_ok(h: &Head<'_>) -> bool {
    u32_le(h.data, 0).is_some_and(|r| r >= 8 && u64::from(r) < h.len)
}

/// A node with the header fields of a FlatBuffer file.
fn header(file: Span, ident: &str) -> Node {
    Node::new("Header")
        .span(file.sub(0, 8))
        .summary(format!("root table offset, identifier {ident}"))
}

// ---------------------------------------------------------------------------
// TensorFlow Lite

const TENSOR_TYPE: EnumTable = &[
    (0, "FLOAT32"),
    (1, "FLOAT16"),
    (2, "INT32"),
    (3, "UINT8"),
    (4, "INT64"),
    (5, "STRING"),
    (6, "BOOL"),
    (7, "INT16"),
    (8, "COMPLEX64"),
    (9, "INT8"),
    (10, "FLOAT64"),
    (11, "COMPLEX128"),
    (12, "UINT64"),
    (13, "RESOURCE"),
    (14, "VARIANT"),
    (15, "UINT32"),
    (16, "UINT16"),
    (17, "INT4"),
];

const BUILTIN: &[&str] = &[
    "ADD",
    "AVERAGE_POOL_2D",
    "CONCATENATION",
    "CONV_2D",
    "DEPTHWISE_CONV_2D",
    "DEPTH_TO_SPACE",
    "DEQUANTIZE",
    "EMBEDDING_LOOKUP",
    "FLOOR",
    "FULLY_CONNECTED",
    "HASHTABLE_LOOKUP",
    "L2_NORMALIZATION",
    "L2_POOL_2D",
    "LOCAL_RESPONSE_NORMALIZATION",
    "LOGISTIC",
    "LSH_PROJECTION",
    "LSTM",
    "MAX_POOL_2D",
    "MUL",
    "RELU",
    "RELU_N1_TO_1",
    "RELU6",
    "RESHAPE",
    "RESIZE_BILINEAR",
    "RNN",
    "SOFTMAX",
    "SPACE_TO_DEPTH",
    "SVDF",
    "TANH",
    "CONCAT_EMBEDDINGS",
    "SKIP_GRAM",
    "CALL",
    "CUSTOM",
    "EMBEDDING_LOOKUP_SPARSE",
    "PAD",
    "UNIDIRECTIONAL_SEQUENCE_RNN",
    "GATHER",
    "BATCH_TO_SPACE_ND",
    "SPACE_TO_BATCH_ND",
    "TRANSPOSE",
    "MEAN",
    "SUB",
    "DIV",
    "SQUEEZE",
    "UNIDIRECTIONAL_SEQUENCE_LSTM",
    "STRIDED_SLICE",
    "BIDIRECTIONAL_SEQUENCE_RNN",
    "EXP",
    "TOPK_V2",
    "SPLIT",
    "LOG_SOFTMAX",
    "DELEGATE",
    "BIDIRECTIONAL_SEQUENCE_LSTM",
    "CAST",
    "PRELU",
    "MAXIMUM",
    "ARG_MAX",
    "MINIMUM",
    "LESS",
    "NEG",
    "PADV2",
    "GREATER",
    "GREATER_EQUAL",
    "LESS_EQUAL",
    "SELECT",
    "SLICE",
    "SIN",
    "TRANSPOSE_CONV",
    "SPARSE_TO_DENSE",
    "TILE",
    "EXPAND_DIMS",
    "EQUAL",
    "NOT_EQUAL",
    "LOG",
    "SUM",
    "SQRT",
    "RSQRT",
    "SHAPE",
    "POW",
    "ARG_MIN",
    "FAKE_QUANT",
    "REDUCE_PROD",
    "REDUCE_MAX",
    "PACK",
    "LOGICAL_OR",
    "ONE_HOT",
    "LOGICAL_AND",
    "LOGICAL_NOT",
    "UNPACK",
    "REDUCE_MIN",
    "FLOOR_DIV",
    "REDUCE_ANY",
    "SQUARE",
    "ZEROS_LIKE",
    "FILL",
    "FLOOR_MOD",
    "RANGE",
    "RESIZE_NEAREST_NEIGHBOR",
    "LEAKY_RELU",
    "SQUARED_DIFFERENCE",
    "MIRROR_PAD",
    "ABS",
    "SPLIT_V",
    "UNIQUE",
    "CEIL",
    "REVERSE_V2",
    "ADD_N",
    "GATHER_ND",
    "COS",
    "WHERE",
    "RANK",
    "ELU",
    "REVERSE_SEQUENCE",
    "MATRIX_DIAG",
    "QUANTIZE",
    "MATRIX_SET_DIAG",
    "ROUND",
    "HARD_SWISH",
    "IF",
    "WHILE",
    "NON_MAX_SUPPRESSION_V4",
    "NON_MAX_SUPPRESSION_V5",
    "SCATTER_ND",
    "SELECT_V2",
    "DENSIFY",
    "SEGMENT_SUM",
    "BATCH_MATMUL",
];

fn builtin_name(code: i32) -> String {
    usize::try_from(code)
        .ok()
        .and_then(|i| BUILTIN.get(i))
        .map_or_else(|| format!("builtin {code}"), |s| (*s).to_owned())
}

fn tflite_probe(h: &Head<'_>) -> bool {
    h.at(4, b"TFL3") && root_ok(h)
}

declare_format!(pub TFLITE = "tflite", "TensorFlow Lite model", ["tflite", "lite"], "application/x-tflite",
    Probe::Custom(tflite_probe), tflite);

async fn tflite(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fb = Fb::new(&cx, file);
    cx.emit(header(file, "TFL3"));
    let model = fb.root().await?;
    let version = fb.u32_field(&model, 0).await?.unwrap_or(0);
    let mut node = Node::new("Version").value(uint(version.into()));
    if let Some(p) = fb.field(&model, 0).await? {
        node = node.span(file.sub(p, 4));
    }
    cx.emit(node);
    let description = fb.string(&model, 3).await?;
    if let Some(d) = &description {
        cx.emit(Node::new("Description").value(text(d.clone())));
    }
    let codes = fb.vector(&model, 1, 4).await?;
    let subgraphs = fb.vector(&model, 2, 4).await?;
    let buffers = fb.vector(&model, 4, 4).await?;
    let metadata = fb.vector(&model, 6, 4).await?;
    let state = (file, model);
    if let Some(v) = codes {
        cx.emit(
            Node::new("Operator codes")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} codes", v.len))
                .lazy(operator_codes, state),
        );
    }
    let mut stats = String::new();
    if let Some(v) = subgraphs {
        let mut ops = 0u64;
        let mut tensors = 0u64;
        for i in 0..v.len.min(64) {
            let g = fb.table_in(v, i).await?;
            ops = ops.saturating_add(fb.vector(&g, 3, 4).await?.map_or(0, |o| o.len.into()));
            tensors =
                tensors.saturating_add(fb.vector(&g, 0, 4).await?.map_or(0, |t| t.len.into()));
        }
        stats = format!(
            ", {} subgraph(s), {ops} operators, {tensors} tensors",
            v.len
        );
        cx.emit(
            Node::new("Subgraphs")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} subgraphs", v.len))
                .lazy(subgraph_list, state),
        );
    }
    if let Some(v) = buffers {
        cx.emit(
            Node::new("Buffers")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} buffers", v.len))
                .lazy(buffer_list, (input, model)),
        );
    }
    if let Some(v) = metadata {
        cx.emit(
            Node::new("Metadata")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} entries", v.len))
                .lazy(metadata_list, state),
        );
    }
    let desc = description.map(|d| format!(" \"{d}\"")).unwrap_or_default();
    cx.annotate(format!("TensorFlow Lite model v{version}{desc}{stats}"));
    Ok(())
}

/// The operator names of the model, by opcode index.
async fn opcode_names(fb: &Fb<'_>, model: &Table) -> Result<Vec<String>> {
    let mut names = Vec::new();
    if let Some(v) = fb.vector(model, 1, 4).await? {
        for i in 0..v.len.min(4096) {
            let code = fb.table_in(v, i).await?;
            let deprecated = i32::from(fb.u8_field(&code, 0).await?.unwrap_or(0));
            let builtin = fb.i32_field(&code, 3).await?.unwrap_or(0).max(deprecated);
            let name = match fb.string(&code, 1).await? {
                Some(custom) if builtin == 32 => format!("CUSTOM {custom}"),
                _ => builtin_name(builtin),
            };
            names.push(name);
        }
    }
    Ok(names)
}

async fn operator_codes(cx: Cx, (file, model): (Span, Table)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    let Some(v) = fb.vector(&model, 1, 4).await? else {
        return Ok(());
    };
    cx.set_count(Count::Exact(v.len.into()));
    for i in 0..v.len {
        let code = fb.table_in(v, i).await?;
        let deprecated = i32::from(fb.u8_field(&code, 0).await?.unwrap_or(0));
        let builtin = fb.i32_field(&code, 3).await?.unwrap_or(0).max(deprecated);
        let version = fb.i32_field(&code, 2).await?.unwrap_or(1);
        let name = match fb.string(&code, 1).await? {
            Some(custom) => format!("CUSTOM {custom}"),
            None => builtin_name(builtin),
        };
        cx.push(
            Node::new(format!("[{i}]"))
                .span(fb.table_span(&code))
                .value(text(name))
                .summary(format!("version {version}")),
        )
        .await;
    }
    Ok(())
}

async fn subgraph_list(cx: Cx, (file, model): (Span, Table)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    let Some(v) = fb.vector(&model, 2, 4).await? else {
        return Ok(());
    };
    let names = Arc::new(opcode_names(&fb, &model).await?);
    cx.set_count(Count::Exact(v.len.into()));
    for i in 0..v.len {
        let g = fb.table_in(v, i).await?;
        let name = fb.string(&g, 4).await?.unwrap_or_default();
        let tensors = fb.vector(&g, 0, 4).await?.map_or(0, |t| t.len);
        let ops = fb.vector(&g, 3, 4).await?.map_or(0, |o| o.len);
        cx.push(
            Node::new(format!("Subgraph {i}"))
                .span(fb.table_span(&g))
                .value(text(name))
                .summary(format!("{tensors} tensors, {ops} operators"))
                .lazy(subgraph, (file, g, names.clone())),
        )
        .await;
    }
    Ok(())
}

async fn subgraph(cx: Cx, (file, g, names): (Span, Table, Arc<Vec<String>>)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    for (slot, label) in [(1u16, "Inputs"), (2, "Outputs")] {
        if let Some(v) = fb.vector(&g, slot, 4).await? {
            let values = fb.i32s(v, 64).await?;
            cx.emit(
                Node::new(label)
                    .span(fb.vector_span(v, 4))
                    .value(text(dims(&values, v.len)))
                    .desc("Tensor indices"),
            );
        }
    }
    if let Some(v) = fb.vector(&g, 0, 4).await? {
        cx.emit(
            Node::new("Tensors")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} tensors", v.len))
                .lazy(tensors, (file, v)),
        );
    }
    if let Some(v) = fb.vector(&g, 3, 4).await? {
        cx.emit(
            Node::new("Operators")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} operators", v.len))
                .lazy(operators, (file, v, names)),
        );
    }
    Ok(())
}

async fn tensors(cx: Cx, (file, v): (Span, Vector)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    cx.set_count(Count::Exact(v.len.into()));
    for i in 0..v.len {
        let t = fb.table_in(v, i).await?;
        let name = fb.string(&t, 3).await?.unwrap_or_default();
        let kind = fb.u8_field(&t, 1).await?.unwrap_or(0);
        let shape = match fb.vector(&t, 0, 4).await? {
            Some(s) => dims(&fb.i32s(s, 16).await?, s.len),
            None => "scalar".to_owned(),
        };
        let buffer = fb.u32_field(&t, 2).await?.unwrap_or(0);
        let type_name = lookup(TENSOR_TYPE, kind.into()).unwrap_or("?");
        let mut summary = format!("{type_name} {shape}");
        if buffer != 0 {
            summary.push_str(&format!(", buffer {buffer}"));
        }
        cx.push(
            Node::new(format!("[{i}]"))
                .span(fb.table_span(&t))
                .value(text(name))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

async fn operators(cx: Cx, (file, v, names): (Span, Vector, Arc<Vec<String>>)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    cx.set_count(Count::Exact(v.len.into()));
    for i in 0..v.len {
        let op = fb.table_in(v, i).await?;
        let index = fb.u32_field(&op, 0).await?.unwrap_or(0);
        let name = usize::try_from(index)
            .ok()
            .and_then(|i| names.get(i))
            .cloned()
            .unwrap_or_else(|| format!("opcode {index}"));
        let ins = match fb.vector(&op, 1, 4).await? {
            Some(s) => dims(&fb.i32s(s, 16).await?, s.len),
            None => "[]".to_owned(),
        };
        let outs = match fb.vector(&op, 2, 4).await? {
            Some(s) => dims(&fb.i32s(s, 16).await?, s.len),
            None => "[]".to_owned(),
        };
        cx.push(
            Node::new(format!("[{i}]"))
                .span(fb.table_span(&op))
                .value(text(name))
                .summary(format!("{ins} → {outs}")),
        )
        .await;
    }
    Ok(())
}

async fn buffer_list(cx: Cx, (input, model): (Input, Table)) -> Result<()> {
    let file = input.span;
    let fb = Fb::new(&cx, file);
    let Some(v) = fb.vector(&model, 4, 4).await? else {
        return Ok(());
    };
    cx.set_count(Count::Exact(v.len.into()));
    for i in 0..v.len {
        let b = fb.table_in(v, i).await?;
        let node = match fb.vector(&b, 0, 1).await? {
            Some(d) if d.len > 0 => {
                let span = fb.vector_span(d, 1);
                // Metadata buffers hold files (e.g. a zipped label map).
                let head = cx.read_avail(span.sub(0, 4)).await?;
                if head.starts_with(b"PK\x03\x04") {
                    embedded(format!("[{i}]"), input.nested(span))
                        .summary(format!("{} bytes", d.len))
                } else {
                    Node::new(format!("[{i}]"))
                        .span(span)
                        .summary(format!("{} bytes", d.len))
                }
            }
            _ => match (fb.u64_field(&b, 1).await?, fb.u64_field(&b, 2).await?) {
                (Some(offset), Some(size)) if size > 0 => Node::new(format!("[{i}]"))
                    .span(file.sub(offset, size))
                    .summary(format!(
                        "{size} bytes at {offset:#x} (outside the FlatBuffer)"
                    )),
                _ => Node::new(format!("[{i}]"))
                    .span(fb.table_span(&b))
                    .summary("empty"),
            },
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn metadata_list(cx: Cx, (file, model): (Span, Table)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    let Some(v) = fb.vector(&model, 6, 4).await? else {
        return Ok(());
    };
    for i in 0..v.len {
        let m = fb.table_in(v, i).await?;
        let name = fb.string(&m, 0).await?.unwrap_or_default();
        let buffer = fb.u32_field(&m, 1).await?.unwrap_or(0);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(fb.table_span(&m))
                .value(text(name))
                .summary(format!("buffer {buffer}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ONNX Runtime format (.ort)

fn ort_probe(h: &Head<'_>) -> bool {
    h.at(4, b"ORTM") && root_ok(h)
}

declare_format!(pub ORT = "ort", "ONNX Runtime model", ["ort"], "application/x-ort",
    Probe::Custom(ort_probe), ort);

async fn ort(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fb = Fb::new(&cx, file);
    cx.emit(header(file, "ORTM"));
    let session = fb.root().await?;
    let version = fb.string(&session, 0).await?.unwrap_or_default();
    cx.emit(Node::new("ORT format version").value(text(version.clone())));
    let mut parts = vec![format!("ONNX Runtime model, format v{version}")];
    if let Some(at) = fb.field(&session, 1).await? {
        let model = fb.table(fb.deref(at).await?).await?;
        let ir = fb.u64_field(&model, 0).await?.unwrap_or(0);
        let producer = fb.string(&model, 2).await?.unwrap_or_default();
        let producer_version = fb.string(&model, 3).await?.unwrap_or_default();
        cx.emit(Node::new("IR version").value(uint(ir)));
        if !producer.is_empty() {
            cx.emit(
                Node::new("Producer").value(text(
                    format!("{producer} {producer_version}")
                        .trim_end()
                        .to_owned(),
                )),
            );
            parts.push(format!("from {producer}"));
        }
        if let Some(v) = fb.vector(&model, 1, 4).await? {
            let mut sets = Vec::new();
            for i in 0..v.len.min(32) {
                let s = fb.table_in(v, i).await?;
                let domain = fb
                    .string(&s, 0)
                    .await?
                    .filter(|d| !d.is_empty())
                    .unwrap_or_else(|| "ai.onnx".to_owned());
                sets.push(format!(
                    "{domain} {}",
                    fb.u64_field(&s, 1).await?.unwrap_or(0)
                ));
            }
            cx.emit(
                Node::new("Opset imports")
                    .span(fb.vector_span(v, 4))
                    .value(text(sets.join(", "))),
            );
        }
        if let Some(gat) = fb.field(&model, 7).await? {
            let graph = fb.table(fb.deref(gat).await?).await?;
            if let Some(v) = fb.vector(&graph, 2, 4).await? {
                parts.push(format!("{} nodes", v.len));
                cx.emit(
                    Node::new("Nodes")
                        .span(fb.vector_span(v, 4))
                        .summary(format!("{} nodes", v.len))
                        .lazy(ort_nodes, (file, v)),
                );
            }
            cx.emit(
                Node::new("Graph table")
                    .span(fb.table_span(&graph))
                    .lazy(raw_table, (file, graph)),
            );
        }
    }
    cx.emit(
        Node::new("Session table")
            .span(fb.table_span(&session))
            .lazy(raw_table, (file, session)),
    );
    cx.annotate(parts.join(", "));
    Ok(())
}

async fn ort_nodes(cx: Cx, (file, v): (Span, Vector)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    cx.set_count(Count::Exact(v.len.into()));
    for i in 0..v.len {
        let n = fb.table_in(v, i).await?;
        let name = fb.string(&n, 0).await?.unwrap_or_default();
        let domain = fb.string(&n, 2).await?.filter(|d| !d.is_empty());
        let op = fb.string(&n, 5).await?.unwrap_or_default();
        let op = match domain {
            Some(d) => format!("{d}::{op}"),
            None => op,
        };
        cx.push(
            Node::new(format!("[{i}]"))
                .span(fb.table_span(&n))
                .value(text(op))
                .summary(name),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// ExecuTorch program (.pte)

fn pte_probe(h: &Head<'_>) -> bool {
    h.at(4, b"ET")
        && h.data
            .get(6..8)
            .is_some_and(|v| v.iter().all(u8::is_ascii_digit))
        && root_ok(h)
}

declare_format!(pub EXECUTORCH = "executorch", "ExecuTorch program", ["pte"], "application/x-executorch",
    Probe::Custom(pte_probe), executorch);

async fn executorch(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let fb = Fb::new(&cx, file);
    let ident = String::from_utf8_lossy(&fb.bytes(4, 4).await?).into_owned();
    cx.emit(header(file, &ident));
    // An optional extended header follows the identifier.
    let ext = cx.read_avail(file.sub(8, 32)).await?;
    if ext.starts_with(b"eh00") {
        let len = u32_le(&ext, 4).unwrap_or(0);
        cx.emit(crate::fields::struct_node(
            "Extended header",
            file.sub(8, len.into()),
            crate::fields::Endian::Little,
            (),
            |f, _| {
                f.ascii("Magic", 4).emit()?;
                f.u32("Length").emit()?;
                f.u64("Program size").emit()?;
                f.u64("Segment base offset").hex().emit()?;
                Ok(())
            },
        ));
    }
    let program = fb.root().await?;
    let version = fb.u32_field(&program, 0).await?.unwrap_or(0);
    cx.emit(Node::new("Version").value(uint(version.into())));
    let mut plans = Vec::new();
    if let Some(v) = fb.vector(&program, 1, 4).await? {
        for i in 0..v.len.min(64) {
            let p = fb.table_in(v, i).await?;
            plans.push(fb.string(&p, 0).await?.unwrap_or_default());
        }
        cx.emit(
            Node::new("Execution plans")
                .span(fb.vector_span(v, 4))
                .summary(plans.join(", "))
                .lazy(plans_list, (file, v)),
        );
    }
    if let Some(v) = fb.vector(&program, 4, 4).await? {
        cx.emit(
            Node::new("Segments")
                .span(fb.vector_span(v, 4))
                .summary(format!("{} segments", v.len)),
        );
    }
    cx.emit(
        Node::new("Program table")
            .span(fb.table_span(&program))
            .lazy(raw_table, (file, program)),
    );
    cx.annotate(format!(
        "ExecuTorch program ({ident}), version {version}, methods: {}",
        plans.join(", ")
    ));
    Ok(())
}

async fn plans_list(cx: Cx, (file, v): (Span, Vector)) -> Result<()> {
    let fb = Fb::new(&cx, file);
    for i in 0..v.len {
        let p = fb.table_in(v, i).await?;
        let name = fb.string(&p, 0).await?.unwrap_or_default();
        let mut ops = Vec::new();
        if let Some(o) = fb.vector(&p, 6, 4).await? {
            for j in 0..o.len.min(256) {
                let op = fb.table_in(o, j).await?;
                let n = fb.string(&op, 0).await?.unwrap_or_default();
                let overload = fb.string(&op, 1).await?.filter(|s| !s.is_empty());
                ops.push(match overload {
                    Some(ov) => format!("{n}.{ov}"),
                    None => n,
                });
            }
        }
        let values = fb.vector(&p, 2, 4).await?.map_or(0, |x| x.len);
        cx.push(
            Node::new(format!("[{i}]"))
                .span(fb.table_span(&p))
                .value(text(name))
                .summary(format!("{values} values, operators: {}", ops.join(", "))),
        )
        .await;
    }
    Ok(())
}
