//! Binary model and weight files with their own layouts: llama.cpp's
//! pre-GGUF GGML family (`ggml`, `ggmf`, `ggjt`, LoRA `ggla`), ncnn binary
//! parameters, MXNet NDArray lists, NNEF tensors, fastText models and MLIR
//! bytecode.

use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

fn uint(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

fn int(value: i64, bits: u8) -> Value {
    Value::Int { value, bits }
}

// ---------------------------------------------------------------------------
// GGML (llama.cpp before GGUF)

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Ggml {
    /// `lmgg`: no version, no token scores, no alignment.
    Unversioned,
    /// `fmgg`: version, token scores.
    Ggmf,
    /// `tjgg`: version, token scores, tensor data aligned to 32 bytes.
    Ggjt,
    /// `algg`: a LoRA adapter (no vocabulary).
    Ggla,
}

const GGML_TYPE: EnumTable = &[
    (0, "F32"),
    (1, "F16"),
    (2, "Q4_0"),
    (3, "Q4_1"),
    (6, "Q5_0"),
    (7, "Q5_1"),
    (8, "Q8_0"),
    (9, "Q8_1"),
    (10, "Q2_K"),
    (11, "Q3_K"),
    (12, "Q4_K"),
    (13, "Q5_K"),
    (14, "Q6_K"),
    (15, "Q8_K"),
];

/// Elements per block and bytes per block of a tensor type. Before ggjt v3,
/// Q4_0, Q4_1 and Q8_0 stored their scales as `f32`.
fn block(kind: u32, old_scales: bool) -> Option<(u64, u64)> {
    Some(match (kind, old_scales) {
        (0, _) => (1, 4),
        (1, _) => (1, 2),
        (2, true) => (32, 20),
        (2, false) => (32, 18),
        (3, true) => (32, 24),
        (3, false) => (32, 20),
        (6, _) => (32, 22),
        (7, _) => (32, 24),
        (8, true) => (32, 36),
        (8, false) => (32, 34),
        (9, _) => (32, 36),
        (10, _) => (256, 84),
        (11, _) => (256, 110),
        (12, _) => (256, 144),
        (13, _) => (256, 176),
        (14, _) => (256, 210),
        (15, _) => (256, 292),
        _ => return None,
    })
}

fn ggml_kind(h: &Head<'_>) -> Option<Ggml> {
    let version = u32_le(h.data, 4)?;
    let kind = match h.data.get(..4)? {
        b"lmgg" => Ggml::Unversioned,
        b"fmgg" if version == 1 => Ggml::Ggmf,
        b"tjgg" if (1..=3).contains(&version) => Ggml::Ggjt,
        b"algg" if version == 1 => Ggml::Ggla,
        _ => return None,
    };
    // The vocabulary size (first hyperparameter) must be plausible.
    let n_vocab = match kind {
        Ggml::Unversioned => version,
        Ggml::Ggla => return Some(kind),
        _ => u32_le(h.data, 8)?,
    };
    (1..=4_000_000).contains(&n_vocab).then_some(kind)
}

declare_format!(pub GGML = "ggml", "GGML model (legacy, unversioned)", ["bin", "ggml"], "application/x-ggml",
    Probe::Custom(|h| ggml_kind(h) == Some(Ggml::Unversioned)), ggml);
declare_format!(pub GGMF = "ggmf", "GGMF model (llama.cpp legacy)", ["bin"], "application/x-ggml",
    Probe::Custom(|h| ggml_kind(h) == Some(Ggml::Ggmf)), ggml);
declare_format!(pub GGJT = "ggjt", "GGJT model (llama.cpp legacy, mmap-able)", ["bin"], "application/x-ggml",
    Probe::Custom(|h| ggml_kind(h) == Some(Ggml::Ggjt)), ggml);
declare_format!(pub GGLA = "ggla", "GGML LoRA adapter (llama.cpp legacy)", ["bin"], "application/x-ggml",
    Probe::Custom(|h| ggml_kind(h) == Some(Ggml::Ggla)), ggml);

const LLAMA_FTYPE: EnumTable = &[
    (0, "ALL_F32"),
    (1, "MOSTLY_F16"),
    (2, "MOSTLY_Q4_0"),
    (3, "MOSTLY_Q4_1"),
    (4, "MOSTLY_Q4_1_SOME_F16"),
    (7, "MOSTLY_Q8_0"),
    (8, "MOSTLY_Q5_0"),
    (9, "MOSTLY_Q5_1"),
    (10, "MOSTLY_Q2_K"),
    (11, "MOSTLY_Q3_K_S"),
    (12, "MOSTLY_Q3_K_M"),
    (13, "MOSTLY_Q3_K_L"),
    (14, "MOSTLY_Q4_K_S"),
    (15, "MOSTLY_Q4_K_M"),
    (16, "MOSTLY_Q5_K_S"),
    (17, "MOSTLY_Q5_K_M"),
    (18, "MOSTLY_Q6_K"),
];

fn llama_hparams(f: &mut Fields<'_>, _: &()) -> Result<u32> {
    let n_vocab = f.u32("n_vocab").emit()?;
    f.u32("n_embd").emit()?;
    f.u32("n_mult").emit()?;
    f.u32("n_head").emit()?;
    f.u32("n_layer").emit()?;
    f.u32("n_rot").emit()?;
    f.u32("ftype").enumeration(LLAMA_FTYPE).emit()?;
    Ok(n_vocab)
}

fn lora_hparams(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("r").desc("LoRA rank").emit()?;
    f.u32("alpha").emit()?;
    Ok(())
}

/// Where the parts of a GGML file are.
#[derive(Clone, Copy)]
struct GgmlLayout {
    kind: Ggml,
    version: u32,
    vocab: Span,
    n_vocab: u32,
    tensors: Span,
}

async fn ggml(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let kind = match head.get(..4) {
        Some(b"fmgg") => Ggml::Ggmf,
        Some(b"tjgg") => Ggml::Ggjt,
        Some(b"algg") => Ggml::Ggla,
        _ => Ggml::Unversioned,
    };
    let versioned = kind != Ggml::Unversioned;
    let version = if versioned {
        u32_le(&head, 4).unwrap_or(0)
    } else {
        0
    };
    let header_len = if versioned { 8 } else { 4 };
    cx.emit(struct_node(
        "Header",
        file.sub(0, header_len),
        LE,
        versioned,
        |f, &versioned| {
            f.ascii("Magic", 4)
                .desc("Stored as a little-endian u32, so it reads backwards")
                .emit()?;
            if versioned {
                f.u32("Version").emit()?;
            }
            Ok(())
        },
    ));
    let (vocab_start, n_vocab) = if kind == Ggml::Ggla {
        cx.emit(struct_node(
            "Hyperparameters",
            file.sub(header_len, 8),
            LE,
            (),
            lora_hparams,
        ));
        (header_len.saturating_add(8), 0)
    } else {
        let span = file.sub(header_len, 28);
        let n_vocab = crate::fields::parse(&cx, span, LE, &(), llama_hparams).await?;
        cx.emit(
            struct_node("Hyperparameters", span, LE, (), llama_hparams)
                .desc("Assuming the LLaMA layout"),
        );
        (header_len.saturating_add(28), n_vocab)
    };
    // Walk the vocabulary to find the tensors.
    let scored = matches!(kind, Ggml::Ggmf | Ggml::Ggjt);
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(vocab_start);
    for _ in 0..n_vocab {
        let len = cur.u32().await?;
        cur.skip(len.into());
        if scored {
            cur.skip(4);
        }
        cx.checkpoint().await;
    }
    if cur.pos() > file.len {
        return Err(Diagnostic::truncated(
            file.sub(vocab_start, u64::MAX),
            file.len.saturating_sub(vocab_start),
        ));
    }
    let vocab = file.sub(vocab_start, cur.pos().saturating_sub(vocab_start));
    let tensors = file.tail(cur.pos());
    let layout = GgmlLayout {
        kind,
        version,
        vocab,
        n_vocab,
        tensors,
    };
    if kind != Ggml::Ggla {
        cx.emit(
            Node::new("Vocabulary")
                .span(vocab)
                .summary(format!("{n_vocab} tokens"))
                .lazy(ggml_vocab, layout),
        );
    }
    let (count, bytes) = ggml_walk(&cx, file, layout, false).await?;
    cx.emit(
        Node::new("Tensors")
            .span(tensors)
            .summary(format!("{count} tensors"))
            .lazy(ggml_tensors, (file, layout)),
    );
    let what = match kind {
        Ggml::Unversioned => "GGML model".to_owned(),
        Ggml::Ggmf => format!("GGMF v{version} model"),
        Ggml::Ggjt => format!("GGJT v{version} model"),
        Ggml::Ggla => format!("GGML LoRA adapter v{version}"),
    };
    let vocab_part = if kind == Ggml::Ggla {
        String::new()
    } else {
        format!("{n_vocab} tokens, ")
    };
    cx.annotate(format!(
        "{what}, {vocab_part}{count} tensors ({} of weights)",
        crate::formats::util::datakit::size(bytes)
    ));
    Ok(())
}

async fn ggml_vocab(cx: Cx, layout: GgmlLayout) -> Result<()> {
    let scored = matches!(layout.kind, Ggml::Ggmf | Ggml::Ggjt);
    let mut cur = Cursor::new(&cx, layout.vocab, LE);
    cx.set_count(crate::node::Count::Exact(layout.n_vocab.into()));
    for i in 0..layout.n_vocab {
        let start = cur.pos();
        let len = cur.u32().await?;
        let token = cur.bytes(len.into()).await?;
        let mut node =
            Node::new(format!("[{i}]")).value(text(String::from_utf8_lossy(&token).into_owned()));
        if scored {
            let score = f32::from_bits(cur.u32().await?);
            node = node.summary(format!("score {score}"));
        }
        cx.push(node.span(cur.since(start))).await;
    }
    Ok(())
}

/// One tensor header.
struct TensorInfo {
    name: String,
    kind: u32,
    dims: Vec<u32>,
    header: Span,
    data: Span,
}

/// Walks the tensors; returns their count and the size of their data, and
/// pushes a node for each if `emit`.
async fn ggml_walk(cx: &Cx, file: Span, layout: GgmlLayout, emit: bool) -> Result<(u64, u64)> {
    let old_scales = match layout.kind {
        Ggml::Ggjt | Ggml::Ggla => layout.version < 3 && layout.kind == Ggml::Ggjt,
        _ => true,
    };
    let aligned = matches!(layout.kind, Ggml::Ggjt | Ggml::Ggla);
    let mut cur = Cursor::new(cx, layout.tensors, LE);
    let base = layout.tensors.offset.saturating_sub(file.offset);
    let (mut count, mut bytes) = (0u64, 0u64);
    while !cur.at_end() {
        let start = cur.pos();
        let n_dims = cur.u32().await?;
        let name_len = cur.u32().await?;
        let kind = cur.u32().await?;
        if n_dims > 4 || name_len > 4096 {
            return Err(Diagnostic::malformed(format!(
                "tensor with {n_dims} dimensions, {name_len}-byte name"
            ))
            .at(cur.since(start)));
        }
        let mut dims = Vec::new();
        for _ in 0..n_dims {
            dims.push(cur.u32().await?);
        }
        let name = String::from_utf8_lossy(&cur.bytes(name_len.into()).await?).into_owned();
        if aligned {
            let abs = base.saturating_add(cur.pos());
            let pad = abs.wrapping_neg() & 31;
            cur.skip(pad);
        }
        let header = cur.since(start);
        let elements = dims.iter().fold(1u64, |a, &d| a.saturating_mul(d.into()));
        let Some((per, size)) = block(kind, old_scales) else {
            if emit {
                cx.push(
                    Node::new(name)
                        .span(header)
                        .diag(Diagnostic::unsupported(format!("tensor type {kind}")).at(header)),
                )
                .await;
            }
            return Err(Diagnostic::unsupported(format!(
                "tensor type {kind}: cannot size the data"
            ))
            .at(header));
        };
        let len = elements.div_ceil(per).saturating_mul(size);
        let data = cur.span(len);
        if data.len < len {
            return Err(Diagnostic::truncated(
                Span::new(data.source, data.offset, len),
                data.len,
            ));
        }
        cur.skip(len);
        count = count.saturating_add(1);
        bytes = bytes.saturating_add(len);
        if emit {
            let info = TensorInfo {
                name,
                kind,
                dims,
                header,
                data,
            };
            cx.push(tensor_node(info)).await;
        } else {
            cx.checkpoint().await;
        }
    }
    Ok((count, bytes))
}

fn tensor_node(t: TensorInfo) -> Node {
    let shape: Vec<String> = t.dims.iter().map(u32::to_string).collect();
    let kind = lookup(GGML_TYPE, t.kind.into()).unwrap_or("?");
    Node::new(t.name)
        .span(Span::new(
            t.header.source,
            t.header.offset,
            t.data.end().saturating_sub(t.header.offset),
        ))
        .summary(format!(
            "{kind} [{}], {} bytes",
            shape.join(" × "),
            t.data.len
        ))
        .lazy(
            tensor_fields,
            (
                t.header,
                t.data,
                t.kind,
                u32::try_from(t.dims.len()).unwrap_or(0),
            ),
        )
}

async fn tensor_fields(
    cx: Cx,
    (header, data, _kind, n_dims): (Span, Span, u32, u32),
) -> Result<()> {
    let block = cx.block(header).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u32("n_dims").emit()?;
    let name_len = f.u32("Name length").emit()?;
    f.u32("Type").enumeration(GGML_TYPE).emit()?;
    for _ in 0..n_dims {
        f.u32("ne").emit()?;
    }
    f.ascii("Name", name_len.into()).emit()?;
    if f.remaining() > 0 {
        let pad = f.remaining();
        f.bytes("Alignment padding", pad).emit()?;
    }
    cx.emit(
        Node::new("Data")
            .span(data)
            .summary(format!("{} bytes", data.len)),
    );
    Ok(())
}

async fn ggml_tensors(cx: Cx, (file, layout): (Span, GgmlLayout)) -> Result<()> {
    ggml_walk(&cx, file, layout, true).await.map(|_| ())
}

// ---------------------------------------------------------------------------
// ncnn binary parameters (.param.bin)

/// ncnn's built-in layer types, by index.
const NCNN_LAYERS: &[&str] = &[
    "AbsVal",
    "ArgMax",
    "BatchNorm",
    "Bias",
    "BNLL",
    "Concat",
    "Convolution",
    "Crop",
    "Deconvolution",
    "Dropout",
    "Eltwise",
    "ELU",
    "Embed",
    "Exp",
    "Flatten",
    "InnerProduct",
    "Input",
    "Log",
    "LRN",
    "MemoryData",
    "MVN",
    "Pooling",
    "Power",
    "PReLU",
    "Proposal",
    "Reduction",
    "ReLU",
    "Reshape",
    "ROIPooling",
    "Scale",
    "Sigmoid",
    "Slice",
    "Softmax",
    "Split",
    "SPP",
    "TanH",
    "Threshold",
    "Tile",
    "RNN",
    "LSTM",
    "BinaryOp",
    "UnaryOp",
    "ConvolutionDepthWise",
    "Padding",
    "Squeeze",
    "ExpandDims",
    "Normalize",
    "Permute",
    "PriorBox",
    "DetectionOutput",
    "Interp",
    "DeconvolutionDepthWise",
    "ShuffleChannel",
    "InstanceNorm",
    "Clip",
    "Reorg",
    "YoloDetectionOutput",
    "Quantize",
    "Dequantize",
    "Yolov3DetectionOutput",
];

const NCNN_MAGIC: u32 = 7_767_517;

fn ncnn_bin_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(NCNN_MAGIC)
        && u32_le(h.data, 4).is_some_and(|n| (1..=100_000).contains(&n))
        && u32_le(h.data, 8).is_some_and(|n| (1..=1_000_000).contains(&n))
}

declare_format!(pub NCNN_BIN = "ncnn-param-bin", "ncnn binary network parameters", ["bin"], "application/x-ncnn-param",
    Probe::Custom(ncnn_bin_probe), ncnn_bin);

/// The end-of-parameters marker.
const NCNN_END: i32 = -233;

async fn ncnn_bin(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(struct_node("Header", file.sub(0, 12), LE, (), |f, _| {
        f.u32("Magic").desc("7767517").emit()?;
        f.u32("Layer count").emit()?;
        f.u32("Blob count").emit()?;
        Ok(())
    }));
    let head = cx.read(file.sub(0, 12)).await?;
    let layers = u32_le(&head, 4).unwrap_or(0);
    let blobs = u32_le(&head, 8).unwrap_or(0);
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(12);
    for i in 0..layers {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let kind = cur.int::<i32>().await?;
        let bottoms = cur.u32().await?;
        let tops = cur.u32().await?;
        if bottoms > 4096 || tops > 4096 {
            return Err(Diagnostic::malformed("implausible blob count").at(cur.since(start)));
        }
        cur.skip(u64::from(bottoms.saturating_add(tops)).saturating_mul(4));
        let mut params = 0u32;
        loop {
            let id = cur.int::<i32>().await?;
            if id == NCNN_END {
                break;
            }
            if id <= -23300 {
                let n = cur.u32().await?;
                cur.skip(u64::from(n).saturating_mul(4));
            } else {
                cur.skip(4);
            }
            params = params.saturating_add(1);
            if cur.at_end() {
                return Err(Diagnostic::truncated(
                    cur.since(start),
                    cur.since(start).len,
                ));
            }
        }
        let name = usize::try_from(kind)
            .ok()
            .and_then(|k| NCNN_LAYERS.get(k))
            .map_or_else(|| format!("type {kind}"), |s| (*s).to_owned());
        cx.push(
            Node::new(format!("Layer {i}"))
                .span(cur.since(start))
                .value(text(name))
                .summary(format!("{bottoms} in, {tops} out, {params} params"))
                .lazy(ncnn_layer, cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!("ncnn binary param, {layers} layers, {blobs} blobs"));
    Ok(())
}

async fn ncnn_layer(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    let at = cur.pos();
    let kind = cur.int::<i32>().await?;
    cx.emit(
        Node::new("Type index")
            .span(cur.since(at))
            .value(int(kind.into(), 32)),
    );
    let at = cur.pos();
    let bottoms = cur.u32().await?;
    let tops = cur.u32().await?;
    cx.emit(
        Node::new("Blob counts")
            .span(cur.since(at))
            .summary(format!("{bottoms} bottom, {tops} top")),
    );
    for (label, n) in [("Bottom blobs", bottoms), ("Top blobs", tops)] {
        let at = cur.pos();
        let mut ids = Vec::new();
        for _ in 0..n.min(4096) {
            ids.push(cur.int::<i32>().await?.to_string());
        }
        cx.emit(
            Node::new(label)
                .span(cur.since(at))
                .value(text(ids.join(", "))),
        );
    }
    while !cur.at_end() {
        let at = cur.pos();
        let id = cur.int::<i32>().await?;
        if id == NCNN_END {
            cx.emit(Node::new("End of parameters").span(cur.since(at)));
            break;
        }
        if id <= -23300 {
            let real = (-23300i32).saturating_sub(id);
            let n = cur.u32().await?;
            let data = cur.bytes(u64::from(n.min(64)).saturating_mul(4)).await?;
            cur.skip(u64::from(n.saturating_sub(64)).saturating_mul(4));
            let shown: Vec<String> = data
                .as_chunks::<4>()
                .0
                .iter()
                .map(|c| show_word(u32::from_le_bytes(*c)))
                .collect();
            cx.emit(
                Node::new(format!("Param {real}"))
                    .span(cur.since(at))
                    .value(text(format!("[{}]", shown.join(", ")))),
            );
        } else {
            let v = cur.u32().await?;
            cx.emit(
                Node::new(format!("Param {id}"))
                    .span(cur.since(at))
                    .value(text(show_word(v))),
            );
        }
    }
    Ok(())
}

/// A parameter word: integer, or float if it looks like one.
fn show_word(v: u32) -> String {
    let i = i32::from_ne_bytes(v.to_ne_bytes());
    if (-65536..=65536).contains(&i) {
        i.to_string()
    } else {
        format!("{}", f32::from_bits(v))
    }
}

// ---------------------------------------------------------------------------
// MXNet NDArray list (.params, .nd)

const MXNET_LIST_MAGIC: u64 = 0x112;
const MXNET_V1: u32 = 0xF993_FAC8;
const MXNET_V2: u32 = 0xF993_FAC9;
const MXNET_V3: u32 = 0xF993_FACA;

const MXNET_TYPE: EnumTable = &[
    (0, "float32"),
    (1, "float64"),
    (2, "float16"),
    (3, "uint8"),
    (4, "int32"),
    (5, "int8"),
    (6, "int64"),
    (7, "bool"),
    (12, "bfloat16"),
];

fn mxnet_size(t: i32) -> Option<u64> {
    Some(match t {
        0 | 4 => 4,
        1 | 6 => 8,
        2 | 12 => 2,
        3 | 5 | 7 => 1,
        _ => return None,
    })
}

fn mxnet_probe(h: &Head<'_>) -> bool {
    u64_le(h.data, 0) == Some(MXNET_LIST_MAGIC)
        && u64_le(h.data, 8) == Some(0)
        && u64_le(h.data, 16).is_some_and(|n| n <= 1_000_000)
        && (u64_le(h.data, 16) == Some(0)
            || u32_le(h.data, 24).is_some_and(|m| matches!(m, MXNET_V1 | MXNET_V2 | MXNET_V3)))
}

declare_format!(pub MXNET = "mxnet-params", "MXNet NDArray parameters", ["params", "nd"], "application/x-mxnet-params",
    Probe::Custom(mxnet_probe), mxnet);

async fn mxnet(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(struct_node("Header", file.sub(0, 24), LE, (), |f, _| {
        f.u64("Magic").hex().emit()?;
        f.u64("Reserved").emit()?;
        f.u64("Array count").emit()?;
        Ok(())
    }));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(16);
    let count = cur.u64().await?;
    let mut arrays = Vec::new();
    let mut total = 0u64;
    for _ in 0..count {
        let start = cur.pos();
        let magic = cur.u32().await?;
        let mut summary = String::new();
        if magic == MXNET_V2 || magic == MXNET_V3 {
            let stype = cur.int::<i32>().await?;
            if stype != 0 {
                return Err(Diagnostic::unsupported("sparse NDArray").at(cur.since(start)));
            }
        } else if magic != MXNET_V1 {
            return Err(
                Diagnostic::unsupported(format!("NDArray magic {magic:#x}")).at(cur.since(start))
            );
        }
        let ndim = cur.u32().await?;
        if ndim > 32 {
            return Err(Diagnostic::malformed(format!("{ndim} dimensions")).at(cur.since(start)));
        }
        let mut dims = Vec::new();
        for _ in 0..ndim {
            dims.push(if magic == MXNET_V1 {
                u64::from(cur.u32().await?)
            } else {
                cur.u64().await?
            });
        }
        if ndim > 0 {
            let _dev_type = cur.int::<i32>().await?;
            let _dev_id = cur.int::<i32>().await?;
            let kind = cur.int::<i32>().await?;
            let size = mxnet_size(kind).ok_or_else(|| {
                Diagnostic::unsupported(format!("type flag {kind}")).at(cur.since(start))
            })?;
            let elements = dims.iter().fold(1u64, |a, &d| a.saturating_mul(d));
            let len = elements.saturating_mul(size);
            let data = cur.span(len);
            if data.len < len {
                return Err(Diagnostic::truncated(
                    Span::new(data.source, data.offset, len),
                    data.len,
                ));
            }
            cur.skip(len);
            total = total.saturating_add(len);
            let shape: Vec<String> = dims.iter().map(u64::to_string).collect();
            summary = format!(
                "{} [{}]",
                lookup(MXNET_TYPE, kind.unsigned_abs().into()).unwrap_or("?"),
                shape.join(" × ")
            );
        }
        arrays.push((cur.since(start), summary));
        cx.checkpoint().await;
    }
    // Names follow the arrays.
    let mut names = Vec::new();
    if !cur.at_end() {
        let n = cur.u64().await?;
        for _ in 0..n.min(count) {
            let len = cur.u64().await?;
            if len > 4096 {
                break;
            }
            names.push(String::from_utf8_lossy(&cur.bytes(len).await?).into_owned());
        }
    }
    for (i, (span, summary)) in arrays.into_iter().enumerate() {
        let name = names.get(i).cloned().unwrap_or_else(|| format!("[{i}]"));
        cx.push(Node::new(name).span(span).summary(summary)).await;
    }
    cx.annotate(format!(
        "MXNet parameters, {count} arrays, {}",
        crate::formats::util::datakit::size(total)
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// NNEF tensor binary (.dat)

fn nnef_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"\x4e\xef\x01")
        && h.data.get(3).is_some_and(|&m| m <= 1)
        && u32_le(h.data, 8).is_some_and(|r| r <= 8)
        && u32_le(h.data, 4).is_some_and(|len| u64::from(len).saturating_add(128) <= h.len)
}

declare_format!(pub NNEF_TENSOR = "nnef-tensor", "NNEF tensor data", ["dat"], "application/x-nnef-tensor",
    Probe::Custom(nnef_probe), nnef_tensor);

fn nnef_header(f: &mut Fields<'_>, _: &()) -> Result<(u32, Vec<u32>, u32)> {
    f.bytes("Magic", 2).emit()?;
    f.u8("Version major").emit()?;
    f.u8("Version minor").emit()?;
    let len = f.u32("Data length").emit()?;
    let rank = f.u32("Rank").emit()?;
    let mut dims = Vec::new();
    for i in 0..8 {
        let d = f.u32("Extent").emit()?;
        if i < rank {
            dims.push(d);
        }
    }
    let bits = f.u32("Bits per item").emit()?;
    f.u32("Item type").emit()?;
    let rest = f.remaining();
    f.bytes("Quantization and reserved", rest).emit()?;
    Ok((len, dims, bits))
}

async fn nnef_tensor(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header = file.sub(0, 128);
    let (len, dims, bits) = crate::fields::parse(&cx, header, LE, &(), nnef_header).await?;
    cx.emit(struct_node("Header", header, LE, (), nnef_header));
    cx.emit(
        Node::new("Data")
            .span(file.sub(128, len.into()))
            .summary(format!("{len} bytes")),
    );
    let shape: Vec<String> = dims.iter().map(u32::to_string).collect();
    cx.annotate(format!(
        "NNEF tensor [{}], {bits}-bit items",
        shape.join(" × ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// fastText model (.bin, .ftz)

const FASTTEXT_MAGIC: u32 = 793_712_314;

fn fasttext_probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 0) == Some(FASTTEXT_MAGIC)
        && u32_le(h.data, 4).is_some_and(|v| (11..=12).contains(&v))
}

declare_format!(pub FASTTEXT = "fasttext", "fastText model", ["bin", "ftz"], "application/x-fasttext",
    Probe::Custom(fasttext_probe), fasttext);

fn fasttext_args(f: &mut Fields<'_>, _: &()) -> Result<(u32, u32)> {
    f.u32("Magic").emit()?;
    f.u32("Version").emit()?;
    let dim = f.u32("dim").desc("Size of word vectors").emit()?;
    f.u32("ws").desc("Context window").emit()?;
    f.u32("epoch").emit()?;
    f.u32("minCount").emit()?;
    f.u32("neg").emit()?;
    f.u32("wordNgrams").emit()?;
    f.u32("loss")
        .enumeration(&[(1, "hs"), (2, "ns"), (3, "softmax"), (4, "ova")])
        .emit()?;
    let model = f
        .u32("model")
        .enumeration(&[(1, "cbow"), (2, "skipgram"), (3, "supervised")])
        .emit()?;
    f.u32("bucket").emit()?;
    f.u32("minn").emit()?;
    f.u32("maxn").emit()?;
    f.u32("lrUpdateRate").emit()?;
    f.f64("t").desc("Sampling threshold").emit()?;
    Ok((dim, model))
}

async fn fasttext(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let args = file.sub(0, 64);
    let (dim, model) = crate::fields::parse(&cx, args, LE, &(), fasttext_args).await?;
    cx.emit(struct_node("Arguments", args, LE, (), fasttext_args));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(64);
    let dict_start = cur.pos();
    let size = cur.u32().await?;
    let nwords = cur.u32().await?;
    let nlabels = cur.u32().await?;
    let ntokens = cur.u64().await?;
    let prune = cur.int::<i64>().await?;
    let entries_start = cur.pos();
    for _ in 0..size {
        let (_, s) = cur.cstr(4096).await?;
        if s.len == 0 {
            return Err(Diagnostic::truncated(cur.span(1), 0));
        }
        cur.skip(9);
        cx.checkpoint().await;
    }
    let words = file.sub(entries_start, cur.pos().saturating_sub(entries_start));
    if prune > 0 {
        cur.skip(prune.unsigned_abs().saturating_mul(8));
    }
    if cur.pos() > file.len {
        return Err(Diagnostic::truncated(
            file.tail(dict_start),
            file.len.saturating_sub(dict_start),
        ));
    }
    let dict = cur.since(dict_start);
    cx.emit(
        Node::new("Dictionary")
            .span(dict)
            .summary(format!(
                "{nwords} words, {nlabels} labels, {ntokens} tokens"
            ))
            .lazy(
                fasttext_dict,
                (
                    file.sub(dict_start, entries_start.saturating_sub(dict_start)),
                    words,
                    size,
                ),
            ),
    );
    let rest = file.tail(cur.pos());
    let quant = cx
        .read_avail(rest.sub(0, 1))
        .await?
        .first()
        .copied()
        .unwrap_or(0)
        != 0;
    cx.emit(
        Node::new("Quantized input")
            .span(rest.sub(0, 1))
            .value(Value::Bool(quant)),
    );
    if !quant && rest.len >= 17 {
        let m = rest.sub(1, 16);
        let dims = cx.read(m).await?;
        let (rows, cols) = (u64_le(&dims, 0).unwrap_or(0), u64_le(&dims, 8).unwrap_or(0));
        let len = rows.saturating_mul(cols).saturating_mul(4);
        let matrix = rest.sub(1, len.saturating_add(16));
        cx.emit(
            Node::new("Input matrix")
                .span(matrix)
                .summary(format!("{rows} × {cols} f32")),
        );
        let after = rest.tail(matrix.len.saturating_add(1));
        if !after.is_empty() {
            cx.emit(Node::new("Output matrix").span(after));
        }
    } else {
        cx.emit(Node::new("Matrices").span(rest.tail(1)));
    }
    let kind = lookup(
        &[(1, "cbow"), (2, "skipgram"), (3, "supervised")],
        model.into(),
    )
    .unwrap_or("?");
    cx.annotate(format!(
        "fastText {kind} model, dim {dim}, {nwords} words, {nlabels} labels"
    ));
    Ok(())
}

async fn fasttext_dict(cx: Cx, (head, entries, size): (Span, Span, u32)) -> Result<()> {
    cx.emit(struct_node("Header", head, LE, (), |f, _| {
        f.u32("size").emit()?;
        f.u32("nwords").emit()?;
        f.u32("nlabels").emit()?;
        f.u64("ntokens").emit()?;
        f.int::<i64>("pruneidx_size").emit()?;
        Ok(())
    }));
    let mut cur = Cursor::new(&cx, entries, LE);
    for _ in 0..size {
        if cur.at_end() {
            break;
        }
        let start = cur.pos();
        let (word, _) = cur.cstr(4096).await?;
        let count = cur.u64().await?;
        let kind = cur.u8().await?;
        let label = if kind == 1 { "label" } else { "word" };
        cx.push(
            Node::new(word)
                .span(cur.since(start))
                .value(uint(count, 64))
                .summary(label),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// MLIR bytecode (.mlirbc)

/// MLIR's prefix varint: the number of trailing zero bits in the first byte
/// gives the length.
async fn mlir_varint(cur: &mut Cursor<'_>) -> Result<u64> {
    let first = cur.u8().await?;
    if first & 1 == 1 {
        return Ok(u64::from(first >> 1));
    }
    if first == 0 {
        return cur.u64().await;
    }
    let extra = first.trailing_zeros();
    let rest = cur.bytes(extra.into()).await?;
    let mut value = u64::from(first);
    for (i, b) in rest.iter().enumerate() {
        value |= u64::from(*b)
            .checked_shl(
                u32::try_from(i.saturating_add(1))
                    .unwrap_or(0)
                    .saturating_mul(8),
            )
            .unwrap_or(0);
    }
    Ok(value.checked_shr(extra.saturating_add(1)).unwrap_or(0))
}

const MLIR_SECTIONS: EnumTable = &[
    (0, "String"),
    (1, "Dialect"),
    (2, "AttrType"),
    (3, "AttrTypeOffset"),
    (4, "IR"),
    (5, "Resource"),
    (6, "ResourceOffset"),
    (7, "DialectVersions"),
    (8, "Properties"),
];

declare_format!(pub MLIR = "mlir-bytecode", "MLIR bytecode", ["mlirbc"], "application/x-mlir-bytecode",
    Probe::Magic(&[(0, b"ML\xefR")]), mlir);

async fn mlir(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, LE);
    cur.skip(4);
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(Value::Bytes(b"ML\xefR".to_vec())),
    );
    let at = cur.pos();
    let version = mlir_varint(&mut cur).await?;
    cx.emit(
        Node::new("Version")
            .span(cur.since(at))
            .value(uint(version, 64)),
    );
    let (producer, span) = cur.cstr(1024).await?;
    cx.emit(
        Node::new("Producer")
            .span(span)
            .value(text(producer.clone())),
    );
    let mut sections = Vec::new();
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        let len = mlir_varint(&mut cur).await?;
        if id & 0x80 != 0 {
            let align = mlir_varint(&mut cur).await?;
            if align == 0 || !align.is_power_of_two() || align > 4096 {
                return Err(Diagnostic::malformed(format!("section alignment {align}"))
                    .at(cur.since(start)));
            }
            // Padding bytes (0xCB) up to the alignment, relative to the file.
            while cur.pos().checked_rem(align).unwrap_or(0) != 0 {
                cur.skip(1);
            }
        }
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len);
        let kind = id & 0x7f;
        let name = lookup(MLIR_SECTIONS, kind.into()).unwrap_or("unknown");
        sections.push(name);
        cx.push(
            Node::new(format!("{name} section"))
                .span(cur.since(start))
                .summary(format!("id {kind}, {len} bytes")),
        )
        .await;
    }
    cx.annotate(format!(
        "MLIR bytecode v{version} from \"{producer}\", {} sections",
        sections.len()
    ));
    Ok(())
}
