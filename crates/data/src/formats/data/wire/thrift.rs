//! Thrift-serialised data without its IDL, in the binary
//! (`TBinaryProtocol`) and compact (`TCompactProtocol`) protocols: field
//! ids and types, scalars, strings (text when printable), nested structs,
//! lists, sets and maps. A file holding exactly one struct (what
//! `TSerializer` writes) shows its fields at the top; otherwise the file is
//! a sequence of structs or messages (`TMessage` header and arguments).
//!
//! Neither protocol has a signature, so both formats are reached by "inspect
//! as" only. Up to [`MAX_READ`] bytes are read into memory. Checked against
//! the Python `thrift` package (`tests/data/thrift`).

use std::sync::{Arc, Mutex};
use std::task::Poll;

use crate::bytes::to_u64;
use crate::cx::{Cx, lock};
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::fmt::uuid;
use crate::formats::util::wire::thrift::{
    Container, Header, MAX_DEPTH, MESSAGE_TYPES, Memo, Protocol, Scalar, Skip, Type,
};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Value, lookup};

use super::{plural, prefix, printable, short_text};

declare_format!(pub BINARY = "thrift-binary", "Thrift binary protocol data",
    ["bin"], "application/x-thrift", Probe::Never, dissect_binary);
declare_format!(pub COMPACT = "thrift-compact", "Thrift compact protocol data",
    ["bin"], "application/x-thrift", Probe::Never, dissect_compact);

/// Most bytes read (and kept in memory while the tree is shown).
pub const MAX_READ: u64 = 16 << 20;
/// Characters of a string shown.
const TEXT_MAX: usize = 256;
/// Values skipped per unit of work.
const SKIP_STEP: u32 = 256;

/// Bytes held in memory, with the span they came from.
#[derive(Clone)]
struct Buf {
    data: Arc<Vec<u8>>,
    span: Span,
    proto: Protocol,
    /// Ends of large values already skipped, shared by all nodes.
    memo: Arc<Mutex<Memo>>,
}

impl Buf {
    fn sub(&self, start: usize, end: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(end.saturating_sub(start)))
    }

    /// Skips the value of type `t` at `at`, in bounded steps: where it
    /// ends and how many fields (or elements) it has.
    async fn skip_counted(&self, cx: &Cx, at: usize, t: Type, depth: u32) -> Option<(usize, u64)> {
        let mut skip = Skip::new(self.proto, at, t, depth);
        loop {
            let step = skip.step(&self.data, Some(&mut lock(&self.memo)), SKIP_STEP);
            match step {
                Poll::Ready(r) => return r,
                Poll::Pending => cx.checkpoint().await,
            }
        }
    }

    async fn skip(&self, cx: &Cx, at: usize, t: Type, depth: u32) -> Option<usize> {
        self.skip_counted(cx, at, t, depth)
            .await
            .map(|(end, _)| end)
    }
}

async fn dissect_binary(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Protocol::Binary).await
}

async fn dissect_compact(cx: Cx, input: Input) -> Result<()> {
    dissect(cx, input, Protocol::Compact).await
}

fn protocol_name(proto: Protocol) -> &'static str {
    match proto {
        Protocol::Binary => "Thrift binary protocol",
        Protocol::Compact => "Thrift compact protocol",
    }
}

async fn dissect(cx: Cx, input: Input, proto: Protocol) -> Result<()> {
    let file = input.span;
    let data = cx.read(file.sub(0, MAX_READ)).await?;
    if file.len > MAX_READ {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_READ:#x} bytes are shown"
        )));
    }
    let buf = Buf {
        data: Arc::new(data),
        span: file,
        proto,
        memo: Arc::default(),
    };
    let len = buf.data.len();
    let one =
        proto.message(&buf.data).is_none() && buf.skip(&cx, 0, Type::Struct, 0).await == Some(len);
    if one {
        let fields = fields(&cx, &buf, 0, 0).await?;
        cx.annotate(format!(
            "{}, struct with {}",
            protocol_name(proto),
            plural(fields, "field")
        ));
    } else {
        let records = records(&cx, &buf).await?;
        cx.annotate(format!(
            "{}, {}",
            protocol_name(proto),
            plural(records, "record")
        ));
    }
    Ok(())
}

/// A sequence of messages and bare structs.
async fn records(cx: &Cx, buf: &Buf) -> Result<u64> {
    let (mut pos, mut i) = cx.resume::<(usize, u64)>().unwrap_or((0, 0));
    let len = buf.data.len();
    while pos < len {
        let at = (pos, i);
        cx.mark(move || at);
        let (node, end) = match buf.proto.message(buf.data.get(pos..).unwrap_or_default()) {
            Some(m) => {
                let args = pos.saturating_add(m.start);
                let end = buf.skip(cx, args, Type::Struct, 0).await;
                let kind = lookup(MESSAGE_TYPES, m.kind.into()).unwrap_or("message");
                let name = String::from_utf8_lossy(m.name).into_owned();
                let header = (pos, args, name.clone(), m.kind, m.seqid);
                let node = Node::new(format!("Message {i}"))
                    .summary(format!("{kind} {name}, seqid {}", m.seqid))
                    .lazy(message, (buf.clone(), header));
                (node, end)
            }
            None => {
                let end = buf.skip(cx, pos, Type::Struct, 0).await;
                let node = struct_node(cx, format!("Struct {i}"), buf, pos, 0).await;
                (node, end)
            }
        };
        let Some(end) = end else {
            cx.push(node.span(buf.sub(pos, len))).await;
            return Err(Diagnostic::malformed("invalid or truncated value").at(buf.sub(pos, len)));
        };
        cx.progress(to_u64(end), to_u64(len));
        cx.push(node.span(buf.sub(pos, end))).await;
        i = i.saturating_add(1);
        pos = end;
    }
    Ok(i)
}

type MessageHeader = (usize, usize, String, u8, i32);

async fn message(
    cx: Cx,
    (buf, (_start, args, name, kind, seqid)): (Buf, MessageHeader),
) -> Result<()> {
    cx.emit(Node::new("Name").value(Value::Text(name)));
    cx.emit(Node::new("Type").value(Value::Enum {
        raw: kind.into(),
        bits: 8,
        name: lookup(MESSAGE_TYPES, kind.into()),
    }));
    cx.emit(Node::new("Sequence id").value(Value::Int {
        value: seqid.into(),
        bits: 32,
    }));
    let end = buf
        .skip(&cx, args, Type::Struct, 0)
        .await
        .unwrap_or(buf.data.len());
    cx.emit(
        struct_node(&cx, "Arguments", &buf, args, 0)
            .await
            .span(buf.sub(args, end)),
    );
    Ok(())
}

/// The number of fields of the struct at `at`, if it parses (`depth` is at
/// most [`MAX_DEPTH`], so the struct itself is never too deep).
async fn count_fields(cx: &Cx, buf: &Buf, at: usize, depth: u32) -> Option<u64> {
    buf.skip_counted(cx, at, Type::Struct, depth)
        .await
        .map(|(_, n)| n)
}

type StructState = (Buf, usize, u32);

async fn struct_node(
    cx: &Cx,
    name: impl Into<std::borrow::Cow<'static, str>>,
    buf: &Buf,
    at: usize,
    depth: u32,
) -> Node {
    let node = Node::new(name);
    let summary = match count_fields(cx, buf, at, depth).await {
        Some(n) => format!("struct, {}", plural(n, "field")),
        None => "struct".to_owned(),
    };
    if depth >= MAX_DEPTH {
        return node
            .summary(summary)
            .diag(Diagnostic::limit("structures nested too deeply"));
    }
    node.summary(summary).lazy(
        crate::expander!(self::struct_fields: StructState),
        (buf.clone(), at, depth.saturating_add(1)),
    )
}

async fn struct_fields(cx: Cx, (buf, at, depth): StructState) -> Result<()> {
    fields(&cx, &buf, at, depth).await.map(|_| ())
}

/// Pushes a node per field of the struct at `at`; returns the count.
async fn fields(cx: &Cx, buf: &Buf, at: usize, depth: u32) -> Result<u64> {
    let (mut pos, mut last, mut n) = cx.resume::<(usize, i16, u64)>().unwrap_or((at, 0, 0));
    loop {
        let state = (pos, last, n);
        cx.mark(move || state);
        let Some((header, next)) = buf.proto.field_header(&buf.data, pos, last) else {
            return Err(Diagnostic::malformed("invalid or truncated field header")
                .at(buf.sub(pos, pos.saturating_add(3))));
        };
        let (id, t) = match header {
            Header::Stop => return Ok(n),
            Header::Field(id, t) => (id, t),
        };
        last = id;
        let (node, end) = value_node(cx, format!("field {id}"), buf, next, t, depth).await;
        n = n.saturating_add(1);
        match end {
            Some(end) => {
                cx.push(node.span(buf.sub(pos, end))).await;
                pos = end;
            }
            None => {
                cx.push(node.span(buf.sub(pos, buf.data.len()))).await;
                return Err(Diagnostic::malformed("invalid or truncated value")
                    .at(buf.sub(next, buf.data.len())));
            }
        }
    }
}

/// The node for a value of type `t` at `at` (without its span), and where
/// the value ends (`None` if it does not parse).
async fn value_node(
    cx: &Cx,
    name: String,
    buf: &Buf,
    at: usize,
    t: Type,
    depth: u32,
) -> (Node, Option<usize>) {
    let end = buf.skip(cx, at, t, depth).await;
    if t == Type::Struct {
        return (struct_node(cx, name, buf, at, depth).await, end);
    }
    let node = Node::new(name);
    let node = match t {
        Type::List | Type::Set | Type::Map => match buf.proto.container(&buf.data, at, t) {
            Some(c) => container_node(node, buf, c, t, depth),
            None => node.summary(t.name()),
        },
        _ => match buf.proto.scalar(&buf.data, at, t) {
            Some((scalar, _)) => scalar_node(node, scalar, t),
            None => node.summary(t.name()),
        },
    };
    (node, end)
}

fn scalar_node(node: Node, scalar: Scalar<'_>, t: Type) -> Node {
    match scalar {
        Scalar::Bool(b) => node.value(Value::Bool(b)).summary(t.name()),
        Scalar::Int(v, bits) => node.value(Value::Int { value: v, bits }).summary(t.name()),
        Scalar::Double(x) => node.value(Value::Float(x)).summary(t.name()),
        Scalar::Uuid(b) => node.value(Value::Text(uuid(b))).summary(t.name()),
        Scalar::Bytes([]) => node.summary("binary, empty"),
        Scalar::Bytes(b) if printable(b, false) => {
            let node = node.value(Value::Text(short_text(b, TEXT_MAX)));
            if b.len() > TEXT_MAX {
                node.summary(format!("string, {} bytes", b.len()))
            } else {
                node.summary("string")
            }
        }
        Scalar::Bytes(b) => node
            .value(prefix(b))
            .summary(format!("binary, {} bytes", b.len())),
    }
}

type ContainerState = (Buf, usize, u64, Option<Type>, Type, u32);

fn container_node(node: Node, buf: &Buf, c: Container, t: Type, depth: u32) -> Node {
    let summary = match (t, c.key, c.elem) {
        (Type::Map, Some(k), Some(v)) => {
            format!(
                "map<{}, {}>, {}",
                k.name(),
                v.name(),
                plural(c.count, "entry")
            )
        }
        (Type::Map, _, _) => format!("map, {}", plural(c.count, "entry")),
        (_, _, Some(e)) => format!("{}<{}>, {}", t.name(), e.name(), plural(c.count, "element")),
        _ => t.name().to_owned(),
    };
    let node = node.summary(summary);
    let Some(elem) = c.elem.filter(|_| c.count > 0) else {
        return node;
    };
    if depth >= MAX_DEPTH {
        return node.diag(Diagnostic::limit("containers nested too deeply"));
    }
    node.lazy(
        elements,
        (
            buf.clone(),
            c.start,
            c.count,
            c.key,
            elem,
            depth.saturating_add(1),
        ),
    )
}

/// Elements of a list or set, or entries of a map.
async fn elements(cx: Cx, (buf, start, count, key, elem, depth): ContainerState) -> Result<()> {
    let (mut pos, mut i) = cx.resume::<(usize, u64)>().unwrap_or((start, 0));
    while i < count {
        let at = (pos, i);
        cx.mark(move || at);
        let (node, end) = match key {
            None => value_node(&cx, format!("[{i}]"), &buf, pos, elem, depth).await,
            Some(k) => {
                let key_end = buf.skip(&cx, pos, k, depth).await;
                let value_end = match key_end {
                    Some(e) => buf.skip(&cx, e, elem, depth).await,
                    None => None,
                };
                let entry = (buf.clone(), pos, k, elem, depth);
                let node = Node::new(format!("[{i}]"))
                    .summary(entry_summary(&buf, pos, k, key_end, elem))
                    .lazy(map_entry, entry);
                (node, value_end)
            }
        };
        let Some(end) = end else {
            cx.push(node.span(buf.sub(pos, buf.data.len()))).await;
            return Err(Diagnostic::malformed("invalid or truncated element")
                .at(buf.sub(pos, buf.data.len())));
        };
        cx.push(node.span(buf.sub(pos, end))).await;
        pos = end;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// A short rendition of a scalar for a map entry's summary.
fn brief(buf: &Buf, at: usize, t: Type) -> String {
    match buf.proto.scalar(&buf.data, at, t) {
        Some((Scalar::Bool(b), _)) => b.to_string(),
        Some((Scalar::Int(v, _), _)) => v.to_string(),
        Some((Scalar::Double(x), _)) => x.to_string(),
        Some((Scalar::Bytes(b), _)) if printable(b, false) => format!("{:?}", short_text(b, 40)),
        Some((Scalar::Bytes(b), _)) => format!("{} bytes", b.len()),
        Some((Scalar::Uuid(b), _)) => uuid(b),
        None => t.name().to_owned(),
    }
}

fn entry_summary(buf: &Buf, at: usize, k: Type, key_end: Option<usize>, v: Type) -> String {
    let value = key_end.map_or_else(|| v.name().to_owned(), |e| brief(buf, e, v));
    format!("{} → {value}", brief(buf, at, k))
}

async fn map_entry(cx: Cx, (buf, at, k, v, depth): (Buf, usize, Type, Type, u32)) -> Result<()> {
    let (key, key_end) = value_node(&cx, "key".to_owned(), &buf, at, k, depth).await;
    let Some(key_end) = key_end else {
        cx.emit(key);
        return Err(Diagnostic::malformed("invalid map key"));
    };
    cx.emit(key.span(buf.sub(at, key_end)));
    let (value, end) = value_node(&cx, "value".to_owned(), &buf, key_end, v, depth).await;
    let end = end.unwrap_or(buf.data.len());
    cx.emit(value.span(buf.sub(key_end, end)));
    Ok(())
}
