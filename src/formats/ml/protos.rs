//! Machine-learning formats built on protocol buffers: ONNX, Core ML,
//! TensorFlow SavedModel and frozen GraphDef, SentencePiece models, and
//! TFRecord files (with `tf.Example` and event records).
//!
//! Protobuf has no magic number, so each probe checks the first fields
//! against the schema: field numbers, wire types, plausible versions and
//! the shape of the first nested message.

use crate::bytes::{to_u64, u32_le, u64_le, uleb128};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::crc32c;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

use crate::formats::util::wire::protobuf::{self as proto, Elem, Msg, Ty, f, fields_in, string_in, varint_in};

// ---------------------------------------------------------------------------
// Probe helpers

/// A length-delimited field with tag byte `tag` at `at`: its body range.
fn delimited_at(d: &[u8], at: usize, tag: u8) -> Option<(usize, usize)> {
    if d.get(at) != Some(&tag) {
        return None;
    }
    let start = at.checked_add(1)?;
    let (len, n) = uleb128(d.get(start..)?)?;
    let body = start.checked_add(n)?;
    Some((body, usize::try_from(len).ok()?))
}

fn is_identifier(s: &[u8]) -> bool {
    !s.is_empty()
        && s.iter()
            .all(|&b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-' | b'/' | b':'))
}

fn is_label(s: &[u8]) -> bool {
    !s.is_empty() && s.iter().all(|&b| b.is_ascii_graphic() || b == b' ')
}

/// `08 <version>`: the leading version varint and where the next field is.
fn leading_version(d: &[u8]) -> Option<(u64, usize)> {
    if d.first() != Some(&0x08) {
        return None;
    }
    let (v, n) = uleb128(d.get(1..)?)?;
    Some((v, n.checked_add(1)?))
}

// ---------------------------------------------------------------------------
// ONNX

const ONNX_TYPE: EnumTable = &[
    (0, "UNDEFINED"),
    (1, "FLOAT"),
    (2, "UINT8"),
    (3, "INT8"),
    (4, "UINT16"),
    (5, "INT16"),
    (6, "INT32"),
    (7, "INT64"),
    (8, "STRING"),
    (9, "BOOL"),
    (10, "FLOAT16"),
    (11, "DOUBLE"),
    (12, "UINT32"),
    (13, "UINT64"),
    (14, "COMPLEX64"),
    (15, "COMPLEX128"),
    (16, "BFLOAT16"),
];

const ONNX_ATTR: EnumTable = &[
    (0, "UNDEFINED"),
    (1, "FLOAT"),
    (2, "INT"),
    (3, "STRING"),
    (4, "TENSOR"),
    (5, "GRAPH"),
    (6, "FLOATS"),
    (7, "INTS"),
    (8, "STRINGS"),
    (9, "TENSORS"),
    (10, "GRAPHS"),
    (11, "SPARSE_TENSOR"),
    (12, "SPARSE_TENSORS"),
    (13, "TYPE_PROTO"),
    (14, "TYPE_PROTOS"),
];

static ONNX_ENTRY: Msg = Msg {
    name: "StringStringEntryProto",
    fields: &[f(1, "key", Ty::Str), f(2, "value", Ty::Str)],
    title: &[1, 2],
};

static ONNX_OPSET: Msg = Msg {
    name: "OperatorSetIdProto",
    fields: &[f(1, "domain", Ty::Str), f(2, "version", Ty::Int)],
    title: &[1, 2],
};

static ONNX_DIM: Msg = Msg {
    name: "Dimension",
    fields: &[
        f(1, "dim_value", Ty::Int),
        f(2, "dim_param", Ty::Str),
        f(3, "denotation", Ty::Str),
    ],
    title: &[1, 2],
};

static ONNX_SHAPE: Msg = Msg {
    name: "TensorShapeProto",
    fields: &[f(1, "dim", Ty::Msg(&ONNX_DIM))],
    title: &[],
};

static ONNX_TENSOR_TYPE: Msg = Msg {
    name: "TypeProto.Tensor",
    fields: &[
        f(1, "elem_type", Ty::Enum(ONNX_TYPE)),
        f(2, "shape", Ty::Msg(&ONNX_SHAPE)),
    ],
    title: &[1],
};

static ONNX_TYPE_PROTO: Msg = Msg {
    name: "TypeProto",
    fields: &[
        f(1, "tensor_type", Ty::Msg(&ONNX_TENSOR_TYPE)),
        f(4, "sequence_type", Ty::Msg(&proto::UNKNOWN)),
        f(5, "map_type", Ty::Msg(&proto::UNKNOWN)),
        f(6, "denotation", Ty::Str),
        f(8, "sparse_tensor_type", Ty::Msg(&ONNX_TENSOR_TYPE)),
        f(9, "optional_type", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[],
};

static ONNX_VALUE_INFO: Msg = Msg {
    name: "ValueInfoProto",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "type", Ty::Msg(&ONNX_TYPE_PROTO)),
        f(3, "doc_string", Ty::Str),
    ],
    title: &[1],
};

static ONNX_TENSOR: Msg = Msg {
    name: "TensorProto",
    fields: &[
        f(1, "dims", Ty::Packed(Elem::Varint)),
        f(2, "data_type", Ty::Enum(ONNX_TYPE)),
        f(3, "segment", Ty::Msg(&proto::UNKNOWN)),
        f(4, "float_data", Ty::Packed(Elem::Float)),
        f(5, "int32_data", Ty::Packed(Elem::Varint)),
        f(6, "string_data", Ty::Bytes),
        f(7, "int64_data", Ty::Packed(Elem::Varint)),
        f(8, "name", Ty::Str),
        f(9, "raw_data", Ty::Bytes),
        f(10, "double_data", Ty::Packed(Elem::Double)),
        f(11, "uint64_data", Ty::Packed(Elem::Varint)),
        f(12, "doc_string", Ty::Str),
        f(13, "external_data", Ty::Msg(&ONNX_ENTRY)),
        f(
            14,
            "data_location",
            Ty::Enum(&[(0, "DEFAULT"), (1, "EXTERNAL")]),
        ),
    ],
    title: &[8, 2],
};

static ONNX_ATTRIBUTE: Msg = Msg {
    name: "AttributeProto",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "f", Ty::Float),
        f(3, "i", Ty::Int),
        f(4, "s", Ty::Str),
        f(5, "t", Ty::Msg(&ONNX_TENSOR)),
        f(6, "g", Ty::Msg(&ONNX_GRAPH)),
        f(7, "floats", Ty::Packed(Elem::Float)),
        f(8, "ints", Ty::Packed(Elem::Varint)),
        f(9, "strings", Ty::Str),
        f(10, "tensors", Ty::Msg(&ONNX_TENSOR)),
        f(11, "graphs", Ty::Msg(&ONNX_GRAPH)),
        f(13, "doc_string", Ty::Str),
        f(20, "type", Ty::Enum(ONNX_ATTR)),
        f(21, "ref_attr_name", Ty::Str),
    ],
    title: &[1, 20],
};

static ONNX_NODE: Msg = Msg {
    name: "NodeProto",
    fields: &[
        f(1, "input", Ty::Str),
        f(2, "output", Ty::Str),
        f(3, "name", Ty::Str),
        f(4, "op_type", Ty::Str),
        f(5, "attribute", Ty::Msg(&ONNX_ATTRIBUTE)),
        f(6, "doc_string", Ty::Str),
        f(7, "domain", Ty::Str),
    ],
    title: &[4, 3],
};

static ONNX_GRAPH: Msg = Msg {
    name: "GraphProto",
    fields: &[
        f(1, "node", Ty::Msg(&ONNX_NODE)),
        f(2, "name", Ty::Str),
        f(5, "initializer", Ty::Msg(&ONNX_TENSOR)),
        f(10, "doc_string", Ty::Str),
        f(11, "input", Ty::Msg(&ONNX_VALUE_INFO)),
        f(12, "output", Ty::Msg(&ONNX_VALUE_INFO)),
        f(13, "value_info", Ty::Msg(&ONNX_VALUE_INFO)),
        f(14, "quantization_annotation", Ty::Msg(&proto::UNKNOWN)),
        f(15, "sparse_initializer", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[2],
};

static ONNX_MODEL: Msg = Msg {
    name: "ModelProto",
    fields: &[
        f(1, "ir_version", Ty::Int),
        f(2, "producer_name", Ty::Str),
        f(3, "producer_version", Ty::Str),
        f(4, "domain", Ty::Str),
        f(5, "model_version", Ty::Int),
        f(6, "doc_string", Ty::Str),
        f(7, "graph", Ty::Msg(&ONNX_GRAPH)),
        f(8, "opset_import", Ty::Msg(&ONNX_OPSET)),
        f(14, "metadata_props", Ty::Msg(&ONNX_ENTRY)),
        f(20, "training_info", Ty::Msg(&proto::UNKNOWN)),
        f(25, "functions", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[],
};

fn onnx_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let Some((version, at)) = leading_version(d) else {
        return false;
    };
    if !(1..=15).contains(&version) {
        return false;
    }
    if let Some((body, len)) = delimited_at(d, at, 0x12) {
        // producer_name, then producer_version, domain, model_version,
        // doc_string, graph or opset_import.
        let Some(name) = body.checked_add(len).and_then(|end| d.get(body..end)) else {
            return false;
        };
        let next = body.saturating_add(len);
        return (1..=64).contains(&len)
            && is_label(name)
            && matches!(
                d.get(next),
                Some(0x1a | 0x22 | 0x28 | 0x32 | 0x3a | 0x42 | 0x72) | None
            );
    }
    // No producer: the graph follows, starting with a node or its name.
    delimited_at(d, at, 0x3a).is_some_and(|(body, len)| {
        to_u64(body.saturating_add(len)) <= h.len
            && d.get(body).is_some_and(|&b| b == 0x0a || b == 0x12)
            && delimited_at(d, body, 0x0a)
                .or_else(|| delimited_at(d, body, 0x12))
                .is_some()
    })
}

declare_format!(pub ONNX = "onnx", "ONNX model", ["onnx"], "application/x-onnx",
    Probe::Custom(onnx_probe), onnx);

async fn onnx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let top = proto::scan(&cx, file, 4096).await?;
    let mut parts = Vec::new();
    if let Some(v) = top.iter().find(|r| r.num == 1 && r.wire == 0) {
        parts.push(format!("IR v{}", v.value));
    }
    let producer = small_string(&cx, file, &top, 2).await?;
    let producer_version = small_string(&cx, file, &top, 3).await?;
    if let Some(p) = producer {
        parts.push(
            format!("from {p} {}", producer_version.unwrap_or_default())
                .trim_end()
                .to_owned(),
        );
    }
    for r in top
        .iter()
        .filter(|r| r.num == 8 && r.wire == 2 && r.len <= 256)
    {
        let data = cx.read(file.sub(r.at, r.len)).await?;
        let domain = string_in(&data, 1)
            .filter(|d| !d.is_empty())
            .unwrap_or_else(|| "ai.onnx".to_owned());
        if let Some(v) = varint_in(&data, 2) {
            parts.push(format!("opset {domain} {v}"));
        }
    }
    if let Some(g) = top.iter().find(|r| r.num == 7 && r.wire == 2) {
        let graph = file.sub(g.at, g.len);
        let fields = proto::scan(&cx, graph, 200_000).await?;
        let nodes = fields.iter().filter(|r| r.num == 1).count();
        let inits = fields.iter().filter(|r| r.num == 5).count();
        parts.push(format!("{nodes} nodes, {inits} initializers"));
    }
    proto::message(cx.clone(), (file, &ONNX_MODEL, 0)).await?;
    cx.annotate(format!("ONNX model, {}", parts.join(", ")));
    Ok(())
}

/// The value of a short string field `num` among top-level fields.
async fn small_string(cx: &Cx, file: Span, top: &[proto::Raw], num: u64) -> Result<Option<String>> {
    match top
        .iter()
        .find(|r| r.num == num && r.wire == 2 && r.len <= 1024)
    {
        Some(r) => {
            let data = cx.read(file.sub(r.at, r.len)).await?;
            Ok(Some(String::from_utf8_lossy(&data).into_owned()))
        }
        None => Ok(None),
    }
}

// ---------------------------------------------------------------------------
// Core ML model specification (.mlmodel)

const COREML_COLOR: EnumTable = &[
    (0, "INVALID_COLOR_SPACE"),
    (10, "GRAYSCALE"),
    (20, "RGB"),
    (30, "BGR"),
    (40, "GRAYSCALE_FLOAT16"),
];

const COREML_ARRAY: EnumTable = &[
    (0, "INVALID_ARRAY_DATA_TYPE"),
    (0x10010, "FLOAT16"),
    (0x10020, "FLOAT32"),
    (0x10040, "DOUBLE"),
    (0x20020, "INT32"),
];

static COREML_IMAGE: Msg = Msg {
    name: "ImageFeatureType",
    fields: &[
        f(1, "width", Ty::Int),
        f(2, "height", Ty::Int),
        f(3, "colorSpace", Ty::Enum(COREML_COLOR)),
    ],
    title: &[1, 2, 3],
};

static COREML_MULTIARRAY: Msg = Msg {
    name: "ArrayFeatureType",
    fields: &[
        f(1, "shape", Ty::Packed(Elem::Varint)),
        f(2, "dataType", Ty::Enum(COREML_ARRAY)),
    ],
    title: &[2],
};

static COREML_FEATURE_TYPE: Msg = Msg {
    name: "FeatureType",
    fields: &[
        f(1, "int64Type", Ty::Msg(&proto::UNKNOWN)),
        f(2, "doubleType", Ty::Msg(&proto::UNKNOWN)),
        f(3, "stringType", Ty::Msg(&proto::UNKNOWN)),
        f(4, "imageType", Ty::Msg(&COREML_IMAGE)),
        f(5, "multiArrayType", Ty::Msg(&COREML_MULTIARRAY)),
        f(6, "dictionaryType", Ty::Msg(&proto::UNKNOWN)),
        f(8, "sequenceType", Ty::Msg(&proto::UNKNOWN)),
        f(1000, "isOptional", Ty::Bool),
    ],
    title: &[],
};

static COREML_FEATURE: Msg = Msg {
    name: "FeatureDescription",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "shortDescription", Ty::Str),
        f(3, "type", Ty::Msg(&COREML_FEATURE_TYPE)),
    ],
    title: &[1],
};

static COREML_ENTRY: Msg = Msg {
    name: "map entry",
    fields: &[f(1, "key", Ty::Str), f(2, "value", Ty::Str)],
    title: &[1, 2],
};

static COREML_METADATA: Msg = Msg {
    name: "Metadata",
    fields: &[
        f(1, "shortDescription", Ty::Str),
        f(2, "versionString", Ty::Str),
        f(3, "author", Ty::Str),
        f(4, "license", Ty::Str),
        f(100, "userDefined", Ty::Msg(&COREML_ENTRY)),
    ],
    title: &[3],
};

static COREML_DESCRIPTION: Msg = Msg {
    name: "ModelDescription",
    fields: &[
        f(1, "input", Ty::Msg(&COREML_FEATURE)),
        f(10, "output", Ty::Msg(&COREML_FEATURE)),
        f(11, "predictedFeatureName", Ty::Str),
        f(12, "predictedProbabilitiesName", Ty::Str),
        f(13, "trainingInput", Ty::Msg(&COREML_FEATURE)),
        f(100, "metadata", Ty::Msg(&COREML_METADATA)),
    ],
    title: &[],
};

static COREML_LAYER: Msg = Msg {
    name: "NeuralNetworkLayer",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "input", Ty::Str),
        f(3, "output", Ty::Str),
        f(10, "isUpdatable", Ty::Bool),
    ],
    title: &[1],
};

static COREML_NN: Msg = Msg {
    name: "NeuralNetwork",
    fields: &[
        f(1, "layers", Ty::Msg(&COREML_LAYER)),
        f(2, "preprocessing", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[],
};

/// The model kinds of the `Model.Type` oneof.
const COREML_KINDS: &[(u64, &str)] = &[
    (200, "pipelineClassifier"),
    (201, "pipelineRegressor"),
    (202, "pipeline"),
    (300, "glmRegressor"),
    (301, "supportVectorRegressor"),
    (302, "treeEnsembleRegressor"),
    (303, "neuralNetworkRegressor"),
    (304, "bayesianProbitRegressor"),
    (400, "glmClassifier"),
    (401, "supportVectorClassifier"),
    (402, "treeEnsembleClassifier"),
    (403, "neuralNetworkClassifier"),
    (404, "kNearestNeighborsClassifier"),
    (500, "neuralNetwork"),
    (501, "itemSimilarityRecommender"),
    (502, "mlProgram"),
    (555, "customModel"),
    (556, "linkedModel"),
    (600, "oneHotEncoder"),
    (601, "imputer"),
    (602, "featureVectorizer"),
    (603, "dictVectorizer"),
    (604, "scaler"),
    (606, "categoricalMapping"),
    (607, "normalizer"),
    (609, "arrayFeatureExtractor"),
    (610, "nonMaximumSuppression"),
    (900, "identity"),
    (2000, "textClassifier"),
    (2001, "wordTagger"),
    (2002, "visionFeaturePrint"),
    (2003, "soundAnalysisPreprocessing"),
    (2004, "gazetteer"),
    (2005, "wordEmbedding"),
    (2006, "audioFeaturePrint"),
    (3000, "serializedModel"),
];

static COREML_MODEL: Msg = Msg {
    name: "Model",
    fields: &[
        f(1, "specificationVersion", Ty::Int),
        f(2, "description", Ty::Msg(&COREML_DESCRIPTION)),
        f(10, "isUpdatable", Ty::Bool),
        f(200, "pipelineClassifier", Ty::Msg(&proto::UNKNOWN)),
        f(201, "pipelineRegressor", Ty::Msg(&proto::UNKNOWN)),
        f(202, "pipeline", Ty::Msg(&proto::UNKNOWN)),
        f(303, "neuralNetworkRegressor", Ty::Msg(&COREML_NN)),
        f(403, "neuralNetworkClassifier", Ty::Msg(&COREML_NN)),
        f(500, "neuralNetwork", Ty::Msg(&COREML_NN)),
        f(502, "mlProgram", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[],
};

fn coreml_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let Some((version, at)) = leading_version(d) else {
        return false;
    };
    // The description starts with an input feature, which starts with its
    // name.
    (1..=12).contains(&version)
        && delimited_at(d, at, 0x12).is_some_and(|(body, len)| {
            to_u64(body.saturating_add(len)) <= h.len
                && delimited_at(d, body, 0x0a).is_some_and(|(feature, _)| {
                    delimited_at(d, feature, 0x0a).is_some_and(|(name, n)| {
                        name.checked_add(n)
                            .and_then(|e| d.get(name..e))
                            .is_some_and(is_label)
                    })
                })
        })
}

declare_format!(pub COREML = "coreml", "Core ML model specification", ["mlmodel"], "application/x-coreml",
    Probe::Custom(coreml_probe), coreml);

async fn coreml(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let top = proto::scan(&cx, file, 4096).await?;
    let version = top
        .iter()
        .find(|r| r.num == 1 && r.wire == 0)
        .map_or(0, |r| r.value);
    let kind = top
        .iter()
        .find_map(|r| {
            COREML_KINDS
                .iter()
                .find(|(n, _)| *n == r.num)
                .map(|(_, k)| *k)
        })
        .unwrap_or("unknown model type");
    let mut io = String::new();
    if let Some(d) = top
        .iter()
        .find(|r| r.num == 2 && r.wire == 2 && r.len <= 64 * 1024)
    {
        let data = cx.read(file.sub(d.at, d.len)).await?;
        let names = |num: u64| -> Vec<String> {
            fields_in(&data)
                .filter(|r| r.number == num && r.wire == 2)
                .filter_map(|r| string_in(r.payload(&data), 1))
                .collect()
        };
        io = format!(
            ", inputs {}, outputs {}",
            names(1).join(", "),
            names(10).join(", ")
        );
    }
    proto::message(cx.clone(), (file, &COREML_MODEL, 0)).await?;
    cx.annotate(format!(
        "Core ML model, specification v{version}, {kind}{io}"
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// TensorFlow: SavedModel and GraphDef

const TF_TYPE: EnumTable = &[
    (0, "DT_INVALID"),
    (1, "DT_FLOAT"),
    (2, "DT_DOUBLE"),
    (3, "DT_INT32"),
    (4, "DT_UINT8"),
    (5, "DT_INT16"),
    (6, "DT_INT8"),
    (7, "DT_STRING"),
    (8, "DT_COMPLEX64"),
    (9, "DT_INT64"),
    (10, "DT_BOOL"),
    (11, "DT_QINT8"),
    (12, "DT_QUINT8"),
    (13, "DT_QINT32"),
    (14, "DT_BFLOAT16"),
    (15, "DT_QINT16"),
    (16, "DT_QUINT16"),
    (17, "DT_UINT16"),
    (18, "DT_COMPLEX128"),
    (19, "DT_HALF"),
    (20, "DT_RESOURCE"),
    (21, "DT_VARIANT"),
    (22, "DT_UINT32"),
    (23, "DT_UINT64"),
];

static TF_DIM: Msg = Msg {
    name: "TensorShapeProto.Dim",
    fields: &[f(1, "size", Ty::Int), f(2, "name", Ty::Str)],
    title: &[1, 2],
};

static TF_SHAPE: Msg = Msg {
    name: "TensorShapeProto",
    fields: &[
        f(2, "dim", Ty::Msg(&TF_DIM)),
        f(3, "unknown_rank", Ty::Bool),
    ],
    title: &[],
};

static TF_TENSOR: Msg = Msg {
    name: "TensorProto",
    fields: &[
        f(1, "dtype", Ty::Enum(TF_TYPE)),
        f(2, "tensor_shape", Ty::Msg(&TF_SHAPE)),
        f(3, "version_number", Ty::Int),
        f(4, "tensor_content", Ty::Bytes),
        f(5, "float_val", Ty::Packed(Elem::Float)),
        f(6, "double_val", Ty::Packed(Elem::Double)),
        f(7, "int_val", Ty::Packed(Elem::Varint)),
        f(8, "string_val", Ty::Bytes),
        f(10, "int64_val", Ty::Packed(Elem::Varint)),
        f(11, "bool_val", Ty::Packed(Elem::Varint)),
    ],
    title: &[1],
};

static TF_ATTR_VALUE: Msg = Msg {
    name: "AttrValue",
    fields: &[
        f(1, "list", Ty::Msg(&proto::UNKNOWN)),
        f(2, "s", Ty::Str),
        f(3, "i", Ty::Int),
        f(4, "f", Ty::Float),
        f(5, "b", Ty::Bool),
        f(6, "type", Ty::Enum(TF_TYPE)),
        f(7, "shape", Ty::Msg(&TF_SHAPE)),
        f(8, "tensor", Ty::Msg(&TF_TENSOR)),
        f(9, "placeholder", Ty::Str),
        f(10, "func", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[2, 6],
};

static TF_ATTR: Msg = Msg {
    name: "attr entry",
    fields: &[f(1, "key", Ty::Str), f(2, "value", Ty::Msg(&TF_ATTR_VALUE))],
    title: &[1],
};

static TF_NODE: Msg = Msg {
    name: "NodeDef",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "op", Ty::Str),
        f(3, "input", Ty::Str),
        f(4, "device", Ty::Str),
        f(5, "attr", Ty::Msg(&TF_ATTR)),
        f(6, "experimental_debug_info", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[2, 1],
};

static TF_VERSIONS: Msg = Msg {
    name: "VersionDef",
    fields: &[
        f(1, "producer", Ty::Int),
        f(2, "min_consumer", Ty::Int),
        f(3, "bad_consumers", Ty::Packed(Elem::Varint)),
    ],
    title: &[1],
};

static TF_GRAPH: Msg = Msg {
    name: "GraphDef",
    fields: &[
        f(1, "node", Ty::Msg(&TF_NODE)),
        f(2, "library", Ty::Msg(&proto::UNKNOWN)),
        f(3, "version", Ty::Int),
        f(4, "versions", Ty::Msg(&TF_VERSIONS)),
    ],
    title: &[],
};

static TF_META_INFO: Msg = Msg {
    name: "MetaInfoDef",
    fields: &[
        f(1, "meta_graph_version", Ty::Str),
        f(2, "stripped_op_list", Ty::Msg(&proto::UNKNOWN)),
        f(3, "any_info", Ty::Msg(&proto::UNKNOWN)),
        f(4, "tags", Ty::Str),
        f(5, "tensorflow_version", Ty::Str),
        f(6, "tensorflow_git_version", Ty::Str),
        f(7, "stripped_default_attrs", Ty::Bool),
    ],
    title: &[5],
};

static TF_SIGNATURE_ENTRY: Msg = Msg {
    name: "signature_def entry",
    fields: &[
        f(1, "key", Ty::Str),
        f(2, "value", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[1],
};

static TF_META_GRAPH: Msg = Msg {
    name: "MetaGraphDef",
    fields: &[
        f(1, "meta_info_def", Ty::Msg(&TF_META_INFO)),
        f(2, "graph_def", Ty::Msg(&TF_GRAPH)),
        f(3, "saver_def", Ty::Msg(&proto::UNKNOWN)),
        f(4, "collection_def", Ty::Msg(&proto::UNKNOWN)),
        f(5, "signature_def", Ty::Msg(&TF_SIGNATURE_ENTRY)),
        f(6, "asset_file_def", Ty::Msg(&proto::UNKNOWN)),
        f(7, "object_graph_def", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[],
};

static TF_SAVED_MODEL: Msg = Msg {
    name: "SavedModel",
    fields: &[
        f(1, "saved_model_schema_version", Ty::Int),
        f(2, "meta_graphs", Ty::Msg(&TF_META_GRAPH)),
    ],
    title: &[],
};

fn saved_model_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    if !d.starts_with(b"\x08\x01\x12") {
        return false;
    }
    // Nothing but meta graphs follow, each starting with its meta-info.
    let mut at = 2usize;
    let mut graphs = 0u32;
    while at < d.len() {
        let Some((body, len)) = delimited_at(d, at, 0x12) else {
            return false;
        };
        if d.get(body).is_some_and(|&b| b != 0x0a) {
            return false;
        }
        graphs = graphs.saturating_add(1);
        let end = body.saturating_add(len);
        if to_u64(end) > h.len {
            return false;
        }
        if end >= d.len() {
            break;
        }
        at = end;
    }
    graphs > 0
}

declare_format!(pub SAVED_MODEL = "tf-savedmodel", "TensorFlow SavedModel", ["pb"], "application/x-tensorflow-savedmodel",
    Probe::Custom(saved_model_probe), saved_model);

async fn saved_model(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let top = proto::scan(&cx, file, 1024).await?;
    let graphs = top.iter().filter(|r| r.num == 2).count();
    let mut tags = Vec::new();
    for g in top.iter().filter(|r| r.num == 2 && r.wire == 2) {
        let meta = proto::scan(&cx, file.sub(g.at, g.len), 16).await?;
        if let Some(info) = meta
            .iter()
            .find(|r| r.num == 1 && r.wire == 2 && r.len <= 64 * 1024)
        {
            let data = cx
                .read(file.sub(g.at.saturating_add(info.at), info.len))
                .await?;
            tags.extend(
                fields_in(&data)
                    .filter(|r| r.number == 4 && r.wire == 2)
                    .map(|r| String::from_utf8_lossy(r.payload(&data)).into_owned()),
            );
            if let Some(v) = string_in(&data, 5) {
                tags.push(format!("TF {v}"));
            }
        }
    }
    proto::message(cx.clone(), (file, &TF_SAVED_MODEL, 0)).await?;
    cx.annotate(format!(
        "TensorFlow SavedModel, {graphs} meta graph(s) [{}]",
        tags.join(", ")
    ));
    Ok(())
}

fn graphdef_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    // node { name: "..." op: "Placeholder" ... }
    delimited_at(d, 0, 0x0a).is_some_and(|(node, _)| {
        delimited_at(d, node, 0x0a).is_some_and(|(name, n)| {
            let after = name.saturating_add(n);
            (1..=512).contains(&n)
                && name
                    .checked_add(n)
                    .and_then(|e| d.get(name..e))
                    .is_some_and(is_label)
                && delimited_at(d, after, 0x12).is_some_and(|(op, m)| {
                    (1..=64).contains(&m)
                        && op
                            .checked_add(m)
                            .and_then(|e| d.get(op..e))
                            .is_some_and(|s| {
                                is_identifier(s) && s.first().is_some_and(u8::is_ascii_uppercase)
                            })
                })
        })
    })
}

declare_format!(pub GRAPHDEF = "tf-graphdef", "TensorFlow GraphDef (frozen graph)", ["pb"], "application/x-tensorflow-graphdef",
    Probe::Custom(graphdef_probe), graphdef);

async fn graphdef(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let top = proto::scan(&cx, file, 200_000).await?;
    let nodes = top.iter().filter(|r| r.num == 1).count();
    let mut ops = std::collections::BTreeMap::<String, usize>::new();
    for r in top
        .iter()
        .filter(|r| r.num == 1 && r.wire == 2 && r.len <= 4096)
        .take(2000)
    {
        let data = cx.read(file.sub(r.at, r.len)).await?;
        if let Some(op) = string_in(&data, 2) {
            let n = ops.entry(op).or_default();
            *n = n.saturating_add(1);
        }
    }
    let mut common: Vec<(String, usize)> = ops.into_iter().collect();
    common.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let common: Vec<String> = common
        .iter()
        .take(5)
        .map(|(op, n)| format!("{op}×{n}"))
        .collect();
    proto::message(cx.clone(), (file, &TF_GRAPH, 0)).await?;
    cx.annotate(format!(
        "TensorFlow GraphDef, {nodes} nodes ({})",
        common.join(", ")
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// SentencePiece model

const PIECE_TYPE: EnumTable = &[
    (1, "NORMAL"),
    (2, "UNKNOWN"),
    (3, "CONTROL"),
    (4, "USER_DEFINED"),
    (5, "UNUSED"),
    (6, "BYTE"),
];

static SP_PIECE: Msg = Msg {
    name: "SentencePiece",
    fields: &[
        f(1, "piece", Ty::Str),
        f(2, "score", Ty::Float),
        f(3, "type", Ty::Enum(PIECE_TYPE)),
    ],
    title: &[1, 3],
};

static SP_TRAINER: Msg = Msg {
    name: "TrainerSpec",
    fields: &[
        f(1, "input", Ty::Str),
        f(2, "model_prefix", Ty::Str),
        f(
            3,
            "model_type",
            Ty::Enum(&[(1, "UNIGRAM"), (2, "BPE"), (3, "WORD"), (4, "CHAR")]),
        ),
        f(4, "vocab_size", Ty::Int),
        f(5, "accept_language", Ty::Str),
        f(7, "input_format", Ty::Str),
        f(10, "character_coverage", Ty::Float),
    ],
    title: &[3, 4],
};

static SP_NORMALIZER: Msg = Msg {
    name: "NormalizerSpec",
    fields: &[
        f(1, "name", Ty::Str),
        f(2, "precompiled_charsmap", Ty::Bytes),
        f(3, "add_dummy_prefix", Ty::Bool),
        f(4, "remove_extra_whitespaces", Ty::Bool),
        f(5, "escape_whitespaces", Ty::Bool),
        f(6, "normalization_rule_tsv", Ty::Str),
    ],
    title: &[1],
};

static SP_MODEL: Msg = Msg {
    name: "ModelProto",
    fields: &[
        f(1, "pieces", Ty::Msg(&SP_PIECE)),
        f(2, "trainer_spec", Ty::Msg(&SP_TRAINER)),
        f(3, "normalizer_spec", Ty::Msg(&SP_NORMALIZER)),
        f(4, "self_test_data", Ty::Msg(&proto::UNKNOWN)),
        f(5, "denormalizer_spec", Ty::Msg(&SP_NORMALIZER)),
    ],
    title: &[],
};

/// A piece entry at `at`: `0a L { 0a l "piece" (15 score | 18 type) }`.
fn piece_at(d: &[u8], at: usize) -> Option<usize> {
    let (body, len) = delimited_at(d, at, 0x0a)?;
    let (s, n) = delimited_at(d, body, 0x0a)?;
    let text = d.get(s..s.checked_add(n)?)?;
    let next = s.checked_add(n)?;
    (n <= 64 && std::str::from_utf8(text).is_ok() && matches!(d.get(next), Some(0x15 | 0x18)))
        .then(|| body.saturating_add(len))
}

fn sentencepiece_probe(h: &Head<'_>) -> bool {
    piece_at(h.data, 0)
        .and_then(|next| piece_at(h.data, next))
        .is_some()
}

declare_format!(pub SENTENCEPIECE = "sentencepiece", "SentencePiece tokenizer model", ["model"], "application/x-sentencepiece",
    Probe::Custom(sentencepiece_probe), sentencepiece);

async fn sentencepiece(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let top = proto::scan(&cx, file, 1_000_000).await?;
    let pieces = top.iter().filter(|r| r.num == 1).count();
    let mut kind = String::new();
    if let Some(t) = top
        .iter()
        .find(|r| r.num == 2 && r.wire == 2 && r.len <= 64 * 1024)
    {
        let data = cx.read(file.sub(t.at, t.len)).await?;
        if let Some(k) = varint_in(&data, 3) {
            kind = format!(
                ", {}",
                crate::value::lookup(&[(1, "unigram"), (2, "BPE"), (3, "word"), (4, "char")], k)
                    .unwrap_or("?")
            );
        }
    }
    proto::message(cx.clone(), (file, &SP_MODEL, 0)).await?;
    cx.annotate(format!("SentencePiece model, {pieces} pieces{kind}"));
    Ok(())
}

// ---------------------------------------------------------------------------
// TFRecord

static TF_BYTES_LIST: Msg = Msg {
    name: "BytesList",
    fields: &[f(1, "value", Ty::Bytes)],
    title: &[],
};
static TF_FLOAT_LIST: Msg = Msg {
    name: "FloatList",
    fields: &[f(1, "value", Ty::Packed(Elem::Float))],
    title: &[],
};
static TF_INT64_LIST: Msg = Msg {
    name: "Int64List",
    fields: &[f(1, "value", Ty::Packed(Elem::Varint))],
    title: &[],
};

static TF_FEATURE: Msg = Msg {
    name: "Feature",
    fields: &[
        f(1, "bytes_list", Ty::Msg(&TF_BYTES_LIST)),
        f(2, "float_list", Ty::Msg(&TF_FLOAT_LIST)),
        f(3, "int64_list", Ty::Msg(&TF_INT64_LIST)),
    ],
    title: &[],
};

static TF_FEATURE_ENTRY: Msg = Msg {
    name: "feature entry",
    fields: &[f(1, "key", Ty::Str), f(2, "value", Ty::Msg(&TF_FEATURE))],
    title: &[1],
};

static TF_FEATURES: Msg = Msg {
    name: "Features",
    fields: &[f(1, "feature", Ty::Msg(&TF_FEATURE_ENTRY))],
    title: &[],
};

static TF_EXAMPLE: Msg = Msg {
    name: "Example",
    fields: &[f(1, "features", Ty::Msg(&TF_FEATURES))],
    title: &[],
};

static TF_SUMMARY_VALUE: Msg = Msg {
    name: "Summary.Value",
    fields: &[
        f(1, "tag", Ty::Str),
        f(2, "simple_value", Ty::Float),
        f(4, "image", Ty::Msg(&proto::UNKNOWN)),
        f(5, "histo", Ty::Msg(&proto::UNKNOWN)),
        f(6, "audio", Ty::Msg(&proto::UNKNOWN)),
        f(7, "node_name", Ty::Str),
        f(8, "tensor", Ty::Msg(&TF_TENSOR)),
        f(9, "metadata", Ty::Msg(&proto::UNKNOWN)),
    ],
    title: &[1],
};

static TF_SUMMARY: Msg = Msg {
    name: "Summary",
    fields: &[f(1, "value", Ty::Msg(&TF_SUMMARY_VALUE))],
    title: &[],
};

static TF_EVENT: Msg = Msg {
    name: "Event",
    fields: &[
        f(1, "wall_time", Ty::Double),
        f(2, "step", Ty::Int),
        f(3, "file_version", Ty::Str),
        f(4, "graph_def", Ty::Bytes),
        f(5, "summary", Ty::Msg(&TF_SUMMARY)),
        f(6, "log_message", Ty::Msg(&proto::UNKNOWN)),
        f(7, "session_log", Ty::Msg(&proto::UNKNOWN)),
        f(8, "tagged_run_metadata", Ty::Msg(&proto::UNKNOWN)),
        f(9, "meta_graph_def", Ty::Bytes),
    ],
    title: &[],
};

fn masked_crc(data: &[u8]) -> u32 {
    crc32c(data).rotate_right(15).wrapping_add(0xa282_ead8)
}

fn tfrecord_probe(h: &Head<'_>) -> bool {
    let (Some(len), Some(crc), Some(bytes)) =
        (u64_le(h.data, 0), u32_le(h.data, 8), h.data.get(..8))
    else {
        return false;
    };
    len.checked_add(16).is_some_and(|total| total <= h.len) && masked_crc(bytes) == crc
}

declare_format!(pub TFRECORD = "tfrecord", "TFRecord file (TensorFlow records, event logs)", ["tfrecord", "tfrecords"], "application/x-tfrecord",
    Probe::Custom(tfrecord_probe), tfrecord);

/// Payload CRCs are verified for records up to this size.
const CRC_MAX: u64 = 1 << 20;

async fn tfrecord(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, Endian::Little);
    let mut n = 0u64;
    let mut kinds = (0u64, 0u64);
    while !cur.at_end() {
        let start = cur.pos();
        let head = cur.bytes(12).await?;
        let len = u64_le(&head, 0).unwrap_or(0);
        let len_crc = u32_le(&head, 8).unwrap_or(0);
        let body = cur.span(len);
        if body.len < len {
            return Err(Diagnostic::truncated(
                Span::new(body.source, body.offset, len),
                body.len,
            ));
        }
        cur.skip(len);
        let crc_at = cur.pos();
        let data_crc = cur.u32().await?;
        let mut node = Node::new(format!("Record {n}")).span(cur.since(start));
        if head.get(..8).map(masked_crc) != Some(len_crc) {
            node = node.diag(
                Diagnostic::malformed("length CRC mismatch")
                    .at(file.sub(start.saturating_add(8), 4)),
            );
        }
        if len <= CRC_MAX {
            let data = cx.read(body).await?;
            if masked_crc(&data) != data_crc {
                node =
                    node.diag(Diagnostic::malformed("data CRC mismatch").at(file.sub(crc_at, 4)));
            }
        }
        let first = cx.read_avail(body.sub(0, 1)).await?;
        let (schema, kind): (&'static Msg, &str) = if first.first() == Some(&0x09) {
            kinds.1 = kinds.1.saturating_add(1);
            (&TF_EVENT, "Event")
        } else {
            kinds.0 = kinds.0.saturating_add(1);
            (&TF_EXAMPLE, "Example")
        };
        cx.push(
            node.summary(format!("{len} bytes, {kind}?"))
                .lazy(record, (start, body, len_crc, data_crc, schema)),
        )
        .await;
        n = n.saturating_add(1);
    }
    let what = match kinds {
        (0, e) if e > 0 => "event log",
        (_, 0) => "examples",
        _ => "mixed records",
    };
    cx.annotate(format!("TFRecord, {n} records ({what})"));
    Ok(())
}

async fn record(
    cx: Cx,
    (_start, body, len_crc, data_crc, schema): (u64, Span, u32, u32, &'static Msg),
) -> Result<()> {
    let header = Span::new(body.source, body.offset.saturating_sub(12), 12);
    cx.emit(
        Node::new("Length")
            .span(header.sub(0, 8))
            .value(Value::UInt {
                value: body.len,
                bits: 64,
                radix: Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Length CRC (masked CRC-32C)")
            .span(header.sub(8, 4))
            .value(Value::UInt {
                value: len_crc.into(),
                bits: 32,
                radix: Radix::Hex,
            }),
    );
    cx.emit(proto::node(schema.name, body, schema));
    cx.emit(
        Node::new("Data CRC (masked CRC-32C)")
            .span(Span::new(body.source, body.end(), 4))
            .value(Value::UInt {
                value: data_crc.into(),
                bits: 32,
                radix: Radix::Hex,
            }),
    );
    Ok(())
}
