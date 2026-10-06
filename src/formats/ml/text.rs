//! Text model descriptions: ncnn `.param`, Caffe `.prototxt`, Darknet
//! `.cfg`, NNEF graphs, LIBSVM/LIBLINEAR/LightGBM models, and the
//! XML/JSON/YAML vocabularies of OpenVINO IR, PMML, OpenCV FileStorage,
//! MXNet symbols, TensorFlow.js models, Hugging Face tokenizers and
//! sharded safetensors indexes.
//!
//! The XML/JSON/YAML ones are dissected by the generic dissectors; this
//! module recognises them and summarises what they are.

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::formats::text::probe::{self, contains, find, significant, trim_start};
use crate::formats::text::scan::Lines;
use crate::formats::text::{json, xml, yaml};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// The first line of the head that is not blank or a comment.
fn first_line<'a>(data: &'a [u8], comments: &'a [&'a [u8]]) -> &'a [u8] {
    significant(data, comments).next().map(trim_start).unwrap_or_default()
}

/// The value of `key = value` / `key: value` / `key value` in a line.
fn after<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    let rest = line.trim_start().strip_prefix(key)?;
    let rest = rest.trim_start();
    let rest = rest.strip_prefix('=').or_else(|| rest.strip_prefix(':')).unwrap_or(rest);
    Some(rest.trim().trim_matches('"'))
}

/// A quoted JSON string value for `key` in `data` (the first occurrence).
fn json_str(data: &[u8], key: &str) -> Option<String> {
    let needle = format!("\"{key}\"");
    let at = find(data, needle.as_bytes())?.saturating_add(needle.len());
    let rest = trim_start(data.get(at..)?);
    let rest = trim_start(rest.strip_prefix(b":")?);
    let rest = rest.strip_prefix(b"\"")?;
    let end = rest.iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}

/// The value of attribute `name` in an XML start tag.
fn attr(tag: &[u8], name: &str) -> Option<String> {
    let needle = format!(" {name}=\"");
    let at = find(tag, needle.as_bytes())?.saturating_add(needle.len());
    let rest = tag.get(at..)?;
    let end = rest.iter().position(|&b| b == b'"')?;
    Some(String::from_utf8_lossy(rest.get(..end)?).into_owned())
}

/// How often `needle` occurs in `hay`.
fn count(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len().max(1)).filter(|w| *w == needle).count()
}

/// The probe head of `input`, for dissectors that summarise from it.
async fn head_bytes(cx: &Cx, input: &Input) -> Result<Vec<u8>> {
    cx.read_avail(input.span.sub(0, 64 * 1024)).await
}

// ---------------------------------------------------------------------------
// ncnn text parameters (.param)

fn ncnn_probe(h: &Head<'_>) -> bool {
    let mut lines = probe::lines(h.data);
    lines.next() == Some(b"7767517")
        && lines.next().is_some_and(|l| {
            let mut parts = l.split(|&b| b == b' ').filter(|p| !p.is_empty());
            parts.next().is_some_and(|p| p.iter().all(u8::is_ascii_digit))
                && parts.next().is_some_and(|p| p.iter().all(u8::is_ascii_digit))
                && parts.next().is_none()
        })
}

declare_format!(pub NCNN = "ncnn-param", "ncnn network parameters", ["param"], "text/x-ncnn-param",
    Probe::Custom(ncnn_probe), ncnn);

async fn ncnn(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let mut layers = 0u64;
    let mut kinds = std::collections::BTreeMap::<String, u64>::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let node = match line.number {
            1 => Node::new("Magic").value(text(t.trim())),
            2 => {
                let mut p = t.split_whitespace();
                Node::new("Counts").summary(format!(
                    "{} layers, {} blobs",
                    p.next().unwrap_or("?"),
                    p.next().unwrap_or("?")
                ))
            }
            _ if line.is_blank() => continue,
            _ => {
                let parts: Vec<&str> = t.split_whitespace().collect();
                let kind = parts.first().copied().unwrap_or_default();
                let name = parts.get(1).copied().unwrap_or_default();
                let nin: usize = parts.get(2).and_then(|n| n.parse().ok()).unwrap_or(0);
                let nout: usize = parts.get(3).and_then(|n| n.parse().ok()).unwrap_or(0);
                let ins = parts.get(4..4usize.saturating_add(nin)).unwrap_or_default().join(", ");
                let outs = parts
                    .get(4usize.saturating_add(nin)..4usize.saturating_add(nin).saturating_add(nout))
                    .unwrap_or_default()
                    .join(", ");
                let params = parts.get(4usize.saturating_add(nin).saturating_add(nout)..).unwrap_or_default().join(" ");
                layers = layers.saturating_add(1);
                let n = kinds.entry(kind.to_owned()).or_default();
                *n = n.saturating_add(1);
                let mut summary = format!("{kind}: [{ins}] → [{outs}]");
                if !params.is_empty() {
                    summary.push_str(&format!(" {params}"));
                }
                Node::new(name.to_owned()).value(text(kind)).summary(summary)
            }
        };
        cx.push(node.span(line.span)).await;
    }
    let mut common: Vec<(String, u64)> = kinds.into_iter().collect();
    common.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    let common: Vec<String> = common.iter().take(4).map(|(k, n)| format!("{k}×{n}")).collect();
    cx.annotate(format!("ncnn param, {layers} layers ({})", common.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// Caffe network definition (.prototxt)

fn caffe_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let first = first_line(&data, &[b"#"]);
    probe::is_text(h)
        && (first.starts_with(b"name:") || first.starts_with(b"layer") || first.starts_with(b"input"))
        && (contains(&data, b"layer {") || contains(&data, b"layers {"))
        && contains(&data, b"type:")
        && (contains(&data, b"bottom:") || contains(&data, b"top:"))
}

declare_format!(pub CAFFE = "caffe-prototxt", "Caffe network definition (prototxt)", ["prototxt", "pbtxt"], "text/x-caffe-prototxt",
    Probe::Custom(caffe_probe), caffe);

async fn caffe(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let mut depth = 0i64;
    let mut net = String::new();
    let mut layer: Option<(u64, String, String)> = None;
    let mut count = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let code = t.split('#').next().unwrap_or_default();
        let trimmed = code.trim();
        if depth == 0 {
            if let Some(n) = after(trimmed, "name") {
                net = n.to_owned();
                cx.push(Node::new("Network name").span(line.span).value(text(n))).await;
            } else if trimmed.starts_with("layer") && trimmed.contains('{') {
                layer = Some((line.start, String::new(), String::new()));
            } else if !trimmed.is_empty() {
                cx.push(Node::new("Setting").span(line.span).value(text(trimmed))).await;
            }
        } else if depth == 1
            && let Some((_, name, kind)) = layer.as_mut()
        {
            if let Some(n) = after(trimmed, "name") {
                *name = n.to_owned();
            } else if let Some(k) = after(trimmed, "type") {
                *kind = k.to_owned();
            }
        }
        let opens = i64::try_from(code.matches('{').count()).unwrap_or(0);
        let closes = i64::try_from(code.matches('}').count()).unwrap_or(0);
        depth = depth.saturating_add(opens).saturating_sub(closes).max(0);
        if depth == 0
            && let Some((start, name, kind)) = layer.take()
        {
            let span = input.span.sub(start, line.next.saturating_sub(start));
            cx.push(Node::new(name).span(span).value(text(kind)).lazy(block_lines, span)).await;
            count = count.saturating_add(1);
        }
    }
    cx.annotate(format!("Caffe network \"{net}\", {count} layers"));
    Ok(())
}

/// The lines of a block, one node each.
pub async fn block_lines(cx: Cx, span: Span) -> Result<()> {
    let mut lines = Lines::new(&cx, span);
    while let Some(line) = lines.next().await? {
        if line.is_blank() {
            continue;
        }
        let t = line.text();
        cx.push(Node::new(format!("Line {}", line.number)).span(line.span).value(text(t.trim()))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Darknet network configuration (.cfg)

fn darknet_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    let first = first_line(&data, &[b"#", b";"]);
    (first.starts_with(b"[net]") || first.starts_with(b"[network]"))
        && (contains(&data, b"[convolutional]") || contains(&data, b"[connected]") || contains(&data, b"[yolo]"))
}

declare_format!(pub DARKNET = "darknet-cfg", "Darknet network configuration", ["cfg"], "text/x-darknet-cfg",
    Probe::Custom(darknet_probe), darknet);

async fn darknet(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let mut section: Option<(u64, String, Vec<String>)> = None;
    let mut count = 0u64;
    let mut kinds = std::collections::BTreeMap::<String, u64>::new();
    let mut end = 0u64;
    loop {
        let line = lines.next().await?;
        let header = line.as_ref().and_then(|l| {
            let t = l.text();
            let t = t.trim();
            (t.starts_with('[') && t.ends_with(']')).then(|| t.trim_matches(['[', ']']).to_owned())
        });
        if (header.is_some() || line.is_none())
            && let Some((start, name, keys)) = section.take()
        {
            let span = input.span.sub(start, end.saturating_sub(start));
            let idx = count;
            let label = if name == "net" || name == "network" { name.clone() } else { format!("{idx}: {name}") };
            cx.push(Node::new(label).span(span).summary(keys.join(", ")).lazy(block_lines, span)).await;
            if name != "net" && name != "network" {
                count = count.saturating_add(1);
                let n = kinds.entry(name).or_default();
                *n = n.saturating_add(1);
            }
        }
        let Some(line) = line else { break };
        if let Some(name) = header {
            section = Some((line.start, name, Vec::new()));
        } else if let Some((_, _, keys)) = section.as_mut() {
            let t = line.text();
            let t = t.trim();
            if keys.len() < 4
                && ["filters", "size", "stride", "activation", "classes", "width", "height", "batch", "output"]
                    .iter()
                    .any(|k| t.split('=').next().is_some_and(|key| key.trim() == *k))
            {
                keys.push(t.replace(' ', ""));
            }
        }
        if !line.is_blank() {
            end = line.next;
        }
    }
    let kinds: Vec<String> = kinds.iter().map(|(k, n)| format!("{k}×{n}")).collect();
    cx.annotate(format!("Darknet configuration, {count} layers ({})", kinds.join(", ")));
    Ok(())
}

// ---------------------------------------------------------------------------
// NNEF graph description (graph.nnef)

fn nnef_probe(h: &Head<'_>) -> bool {
    let data = probe::head(h);
    first_line(&data, &[b"#"]).starts_with(b"version 1.") && contains(&data, b"graph ")
}

declare_format!(pub NNEF_GRAPH = "nnef-graph", "NNEF graph description", ["nnef"], "text/x-nnef",
    Probe::Custom(nnef_probe), nnef_graph);

async fn nnef_graph(cx: Cx, input: Input) -> Result<()> {
    let mut lines = Lines::new(&cx, input.span);
    let mut version = String::new();
    let mut graph = String::new();
    let mut ops = 0u64;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let code = t.split('#').next().unwrap_or_default().trim().to_owned();
        if code.is_empty() || code == "{" || code == "}" {
            continue;
        }
        let node = if let Some(v) = code.strip_prefix("version ") {
            version = v.trim_end_matches(';').to_owned();
            Node::new("Version").value(text(version.clone()))
        } else if let Some(e) = code.strip_prefix("extension ") {
            Node::new("Extension").value(text(e.trim_end_matches(';')))
        } else if let Some(g) = code.strip_prefix("graph ") {
            graph = g.split('(').next().unwrap_or_default().trim().to_owned();
            Node::new("Graph").value(text(g.trim_end_matches('{').trim()))
        } else if let Some((lhs, rhs)) = code.split_once('=') {
            ops = ops.saturating_add(1);
            let op = rhs.trim().split(['(', '<']).next().unwrap_or_default().trim().to_owned();
            Node::new(lhs.trim().to_owned()).value(text(op)).summary(rhs.trim().trim_end_matches(';').to_owned())
        } else {
            Node::new(format!("Line {}", line.number)).value(text(code))
        };
        cx.push(node.span(line.span)).await;
    }
    cx.annotate(format!("NNEF {version} graph \"{graph}\", {ops} operations"));
    Ok(())
}

// ---------------------------------------------------------------------------
// LIBSVM, LIBLINEAR and LightGBM models

fn libsvm_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"svm_type ") && contains(h.data, b"\nkernel_type ")
}

fn liblinear_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"solver_type ") && contains(h.data, b"\nnr_class ")
}

fn lightgbm_probe(h: &Head<'_>) -> bool {
    let mut lines = probe::lines(h.data);
    lines.next() == Some(b"tree") && lines.next().is_some_and(|l| l.starts_with(b"version=v"))
}

declare_format!(pub LIBSVM = "libsvm-model", "LIBSVM model", ["model", "svm"], "text/x-libsvm-model",
    Probe::Custom(libsvm_probe), libsvm);
declare_format!(pub LIBLINEAR = "liblinear-model", "LIBLINEAR model", ["model"], "text/x-liblinear-model",
    Probe::Custom(liblinear_probe), liblinear);
declare_format!(pub LIGHTGBM = "lightgbm-model", "LightGBM model", ["txt", "model"], "text/x-lightgbm-model",
    Probe::Custom(lightgbm_probe), lightgbm);

/// Header lines of `key value` until a line equal to `stop`; then the rest
/// as one node.
async fn header_then_rest(cx: &Cx, file: Span, stop: &str, rest_name: &'static str) -> Result<Vec<(String, String)>> {
    let mut lines = Lines::new(cx, file);
    let mut header = Vec::new();
    while let Some(line) = lines.next().await? {
        let t = line.text();
        if t.trim() == stop {
            cx.push(Node::new("Marker").span(line.span).value(text(t.trim()))).await;
            let rest = file.tail(line.next);
            let mut count = 0u64;
            let mut more = Lines::new(cx, rest);
            while let Some(l) = more.next_bounds().await? {
                if l.end > l.start {
                    count = count.saturating_add(1);
                }
            }
            cx.push(Node::new(rest_name).span(rest).summary(format!("{count} lines")).lazy(block_lines, rest)).await;
            break;
        }
        let (key, value) = t.split_once(' ').unwrap_or((t.as_str(), ""));
        header.push((key.to_owned(), value.to_owned()));
        cx.push(Node::new(key.to_owned()).span(line.span).value(text(value))).await;
    }
    Ok(header)
}

fn get<'a>(header: &'a [(String, String)], key: &str) -> &'a str {
    header.iter().find(|(k, _)| k == key).map_or("?", |(_, v)| v.as_str())
}

async fn libsvm(cx: Cx, input: Input) -> Result<()> {
    let h = header_then_rest(&cx, input.span, "SV", "Support vectors").await?;
    cx.annotate(format!(
        "LIBSVM model, {} with {} kernel, {} classes, {} support vectors",
        get(&h, "svm_type"),
        get(&h, "kernel_type"),
        get(&h, "nr_class"),
        get(&h, "total_sv")
    ));
    Ok(())
}

async fn liblinear(cx: Cx, input: Input) -> Result<()> {
    let h = header_then_rest(&cx, input.span, "w", "Weights").await?;
    cx.annotate(format!(
        "LIBLINEAR model, {}, {} classes, {} features",
        get(&h, "solver_type"),
        get(&h, "nr_class"),
        get(&h, "nr_feature")
    ));
    Ok(())
}

async fn lightgbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut lines = Lines::new(&cx, file);
    let mut header = Vec::new();
    let mut tree: Option<(u64, String, String)> = None;
    let mut trees = 0u64;
    let mut section: Option<(u64, String)> = None;
    while let Some(line) = lines.next().await? {
        let t = line.text();
        let t = t.trim().to_owned();
        let starts_tree = t.starts_with("Tree=");
        let ends_trees = t == "end of trees";
        if (starts_tree || ends_trees)
            && let Some((start, name, leaves)) = tree.take()
        {
            let span = file.sub(start, line.start.saturating_sub(start));
            cx.push(Node::new(name).span(span).summary(format!("{leaves} leaves")).lazy(block_lines, span)).await;
            trees = trees.saturating_add(1);
        }
        if starts_tree {
            tree = Some((line.start, t.clone(), String::new()));
            continue;
        }
        if let Some((_, _, leaves)) = tree.as_mut() {
            if let Some(n) = t.strip_prefix("num_leaves=") {
                *leaves = n.to_owned();
            }
            continue;
        }
        if ends_trees {
            cx.push(Node::new("End of trees").span(line.span)).await;
            continue;
        }
        if let Some((start, name)) = section.as_ref() {
            if t.starts_with("end of ") {
                let span = file.sub(*start, line.next.saturating_sub(*start));
                cx.push(Node::new(name.clone()).span(span).lazy(block_lines, span)).await;
                section = None;
            }
            continue;
        }
        if t == "parameters:" || t == "feature_importances:" {
            section = Some((line.start, t.trim_end_matches(':').to_owned()));
            if t == "feature_importances:" {
                // Feature importances run to the next blank line.
                section = None;
                cx.push(Node::new("feature_importances").span(line.span)).await;
            }
            continue;
        }
        if t.is_empty() {
            continue;
        }
        if line.number == 1 {
            cx.push(Node::new("Magic").span(line.span).value(text(t))).await;
            continue;
        }
        let (key, value) = t.split_once('=').unwrap_or((t.as_str(), ""));
        header.push((key.to_owned(), value.to_owned()));
        cx.push(Node::new(key.to_owned()).span(line.span).value(text(value))).await;
    }
    cx.annotate(format!(
        "LightGBM model {}, objective {}, {trees} trees, {} features",
        get(&header, "version"),
        get(&header, "objective"),
        get(&header, "max_feature_idx").parse::<u64>().map_or_else(|_| "?".to_owned(), |n| n.saturating_add(1).to_string())
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// XML vocabularies: OpenVINO IR, PMML, OpenCV FileStorage

fn openvino_probe(h: &Head<'_>) -> bool {
    xml::root(h).is_some_and(|r| r.is(b"net") && r.mentions(b"version=")) && contains(&probe::head(h), b"<layers>")
}

fn pmml_probe(h: &Head<'_>) -> bool {
    xml::root(h).is_some_and(|r| r.local() == b"PMML")
}

fn opencv_probe(h: &Head<'_>) -> bool {
    h.starts_with(b"%YAML:1.0") || xml::root(h).is_some_and(|r| r.is(b"opencv_storage"))
}

declare_format!(pub OPENVINO = "openvino-ir", "OpenVINO IR model (XML)", ["xml"], "application/x-openvino-ir",
    Probe::Custom(openvino_probe), openvino);
declare_format!(pub PMML = "pmml", "Predictive Model Markup Language", ["pmml", "xml"], "application/x-pmml",
    Probe::Custom(pmml_probe), pmml);
declare_format!(pub OPENCV = "opencv-storage", "OpenCV FileStorage (XML/YAML)", ["xml", "yml", "yaml"], "application/x-opencv-storage",
    Probe::Custom(opencv_probe), opencv);

fn root_tag(data: &[u8], len: u64) -> Option<Vec<u8>> {
    xml::root(&Head { data, tail: &[], len }).map(|r| r.tag)
}

async fn openvino(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let tag = root_tag(&head, input.span.len).unwrap_or_default();
    let layers = count(&head, b"<layer ");
    let more = if crate::bytes::to_u64(head.len()) < input.span.len { "+" } else { "" };
    xml::dissect(cx.clone(), input).await?;
    cx.annotate(format!(
        "OpenVINO IR v{}, model \"{}\", {layers}{more} layers",
        attr(&tag, "version").unwrap_or_default(),
        attr(&tag, "name").unwrap_or_default()
    ));
    Ok(())
}

const PMML_MODELS: &[&str] = &[
    "AssociationModel", "BayesianNetworkModel", "BaselineModel", "ClusteringModel", "GaussianProcessModel",
    "GeneralRegressionModel", "MiningModel", "NaiveBayesModel", "NearestNeighborModel", "NeuralNetwork",
    "RegressionModel", "RuleSetModel", "SequenceModel", "Scorecard", "SupportVectorMachineModel",
    "TextModel", "TimeSeriesModel", "TreeModel", "AnomalyDetectionModel",
];

async fn pmml(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let tag = root_tag(&head, input.span.len).unwrap_or_default();
    let models: Vec<&str> = PMML_MODELS
        .iter()
        .filter(|m| contains(&head, format!("<{m}").as_bytes()))
        .copied()
        .collect();
    let app = find(&head, b"<Application").and_then(|at| {
        let rest = head.get(at..)?;
        let end = rest.iter().position(|&b| b == b'>')?;
        attr(rest.get(..end)?, "name")
    });
    xml::dissect(cx.clone(), input).await?;
    let app = app.map(|a| format!(", from {a}")).unwrap_or_default();
    cx.annotate(format!("PMML {} ({}){app}", attr(&tag, "version").unwrap_or_default(), models.join(", ")));
    Ok(())
}

async fn opencv(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let yaml = head.starts_with(b"%YAML");
    let what = if contains(&head, b"<cascade") || contains(&head, b"cascade:") {
        "cascade classifier"
    } else if contains(&head, b"opencv-matrix") {
        "matrices"
    } else {
        "data"
    };
    if yaml {
        yaml::dissect(cx.clone(), input).await?;
    } else {
        xml::dissect(cx.clone(), input).await?;
    }
    cx.annotate(format!("OpenCV FileStorage ({}), {what}", if yaml { "YAML" } else { "XML" }));
    Ok(())
}

// ---------------------------------------------------------------------------
// JSON vocabularies

fn json_object(h: &Head<'_>) -> bool {
    trim_start(&probe::head(h)).starts_with(b"{")
}

fn mxnet_symbol_probe(h: &Head<'_>) -> bool {
    json_object(h) && contains(h.data, b"\"nodes\"") && contains(h.data, b"\"arg_nodes\"") && contains(h.data, b"\"heads\"")
}

fn tfjs_probe(h: &Head<'_>) -> bool {
    json_object(h)
        && contains(h.data, b"\"weightsManifest\"")
        && (contains(h.data, b"\"modelTopology\"") || contains(h.data, b"\"graph-model\""))
}

fn tokenizer_probe(h: &Head<'_>) -> bool {
    json_object(h)
        && contains(h.data, b"\"added_tokens\"")
        && contains(h.data, b"\"pre_tokenizer\"")
        && contains(h.data, b"\"normalizer\"")
}

fn safetensors_index_probe(h: &Head<'_>) -> bool {
    json_object(h) && contains(h.data, b"\"weight_map\"") && contains(h.data, b".safetensors\"")
}

declare_format!(pub MXNET_SYMBOL = "mxnet-symbol", "MXNet symbol graph (JSON)", ["json"], "application/json",
    Probe::Custom(mxnet_symbol_probe), mxnet_symbol);
declare_format!(pub TFJS = "tfjs-model", "TensorFlow.js model (JSON)", ["json"], "application/json",
    Probe::Custom(tfjs_probe), tfjs);
declare_format!(pub HF_TOKENIZER = "hf-tokenizer", "Hugging Face tokenizer (tokenizer.json)", ["json"], "application/json",
    Probe::Custom(tokenizer_probe), hf_tokenizer);
declare_format!(pub SAFETENSORS_INDEX = "safetensors-index", "Sharded safetensors index (JSON)", ["json"], "application/json",
    Probe::Custom(safetensors_index_probe), safetensors_index);

async fn mxnet_symbol(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let ops = count(&head, b"\"op\":");
    let nulls = count(&head, b"\"op\": \"null\"");
    let more = if crate::bytes::to_u64(head.len()) < input.span.len { "+" } else { "" };
    json::dissect(cx.clone(), input).await?;
    cx.annotate(format!(
        "MXNet symbol graph, {ops}{more} nodes ({} operators)",
        ops.saturating_sub(nulls)
    ));
    Ok(())
}

async fn tfjs(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let format = json_str(&head, "format").unwrap_or_else(|| "layers-model".to_owned());
    let by = json_str(&head, "generatedBy").unwrap_or_default();
    let converted = json_str(&head, "convertedBy").unwrap_or_default();
    let shards = count(&head, b"\"paths\":");
    json::dissect(cx.clone(), input).await?;
    cx.annotate(format!("TensorFlow.js {format}, {by} {converted}, {shards} weight group(s)").replace("  ", " "));
    Ok(())
}

async fn hf_tokenizer(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let model = find(&head, b"\"model\"")
        .and_then(|at| head.get(at..))
        .and_then(|rest| json_str(rest, "type"))
        .unwrap_or_else(|| "?".to_owned());
    let added = find(&head, b"\"added_tokens\"")
        .and_then(|at| head.get(at..))
        .map_or(0, |rest| {
            let end = find(rest, b"]").unwrap_or(rest.len());
            rest.get(..end).map_or(0, |r| count(r, b"\"id\":"))
        });
    json::dissect(cx.clone(), input).await?;
    cx.annotate(format!("Hugging Face tokenizer, {model} model, {added} added tokens"));
    Ok(())
}

async fn safetensors_index(cx: Cx, input: Input) -> Result<()> {
    let head = head_bytes(&cx, &input).await?;
    let total = find(&head, b"\"total_size\"")
        .and_then(|at| head.get(at.saturating_add(12)..))
        .map(|rest| {
            let rest = trim_start(trim_start(rest).strip_prefix(b":").unwrap_or_default());
            let n: String = rest.iter().take_while(|b| b.is_ascii_digit()).map(|&b| char::from(b)).collect();
            n.parse::<u64>().unwrap_or(0)
        });
    let mut shards: Vec<String> = Vec::new();
    let mut rest: &[u8] = &head;
    while let Some(at) = find(rest, b".safetensors\"") {
        let before = rest.get(..at).unwrap_or_default();
        let start = before.iter().rposition(|&b| b == b'"').map_or(0, |i| i.saturating_add(1));
        let name = String::from_utf8_lossy(before.get(start..).unwrap_or_default()).into_owned() + ".safetensors";
        if !shards.contains(&name) {
            shards.push(name);
        }
        rest = rest.get(at.saturating_add(13)..).unwrap_or_default();
    }
    json::dissect(cx.clone(), input).await?;
    let size = total.map(|t| format!(", {}", crate::formats::datakit::size(t))).unwrap_or_default();
    cx.annotate(format!("safetensors index, {} shard(s){size}", shards.len()));
    Ok(())
}
