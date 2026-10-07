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

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::wire::thrift::{
    Container, Header, MAX_DEPTH, MESSAGE_TYPES, Protocol, Scalar, Type,
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

/// Bytes held in memory, with the span they came from.
#[derive(Clone)]
struct Buf {
    data: Arc<Vec<u8>>,
    span: Span,
    proto: Protocol,
}

impl Buf {
    fn sub(&self, start: usize, end: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(end.saturating_sub(start)))
    }

    fn skip(&self, at: usize, t: Type, depth: u32) -> Option<usize> {
        self.proto.skip(&self.data, at, t, depth)
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
    };
    let len = buf.data.len();
    let one = proto.message(&buf.data).is_none() && buf.skip(0, Type::Struct, 0) == Some(len);
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
                let end = buf.skip(args, Type::Struct, 0);
                let kind = lookup(MESSAGE_TYPES, m.kind.into()).unwrap_or("message");
                let name = String::from_utf8_lossy(m.name).into_owned();
                let header = (pos, args, name.clone(), m.kind, m.seqid);
                let node = Node::new(format!("Message {i}"))
                    .summary(format!("{kind} {name}, seqid {}", m.seqid))
                    .lazy(message, (buf.clone(), header));
                (node, end)
            }
            None => {
                let end = buf.skip(pos, Type::Struct, 0);
                let node = struct_node(format!("Struct {i}"), buf, pos, 0);
                (node, end)
            }
        };
        let Some(end) = end else {
            cx.push(node.span(buf.sub(pos, len))).await;
            return Err(Diagnostic::malformed("invalid or truncated value").at(buf.sub(pos, len)));
        };
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
    let end = buf.skip(args, Type::Struct, 0).unwrap_or(buf.data.len());
    cx.emit(struct_node("Arguments", &buf, args, 0).span(buf.sub(args, end)));
    Ok(())
}

/// The number of fields of the struct at `at`, if it parses.
fn count_fields(buf: &Buf, at: usize, depth: u32) -> Option<u64> {
    let mut pos = at;
    let mut last = 0i16;
    let mut n = 0u64;
    loop {
        match buf.proto.field_header(&buf.data, pos, last)? {
            (Header::Stop, _) => return Some(n),
            (Header::Field(id, t), next) => {
                last = id;
                n = n.saturating_add(1);
                pos = buf.skip(next, t, depth.saturating_add(1))?;
            }
        }
    }
}

type StructState = (Buf, usize, u32);

fn struct_node(
    name: impl Into<std::borrow::Cow<'static, str>>,
    buf: &Buf,
    at: usize,
    depth: u32,
) -> Node {
    let node = Node::new(name);
    let summary = match count_fields(buf, at, depth) {
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
        let (node, end) = value_node(format!("field {id}"), buf, next, t, depth);
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

fn uuid(bytes: &[u8]) -> String {
    let hex: String = bytes.iter().map(|b| format!("{b:02x}")).collect();
    let part = |a: usize, b: usize| hex.get(a..b).unwrap_or_default();
    format!(
        "{}-{}-{}-{}-{}",
        part(0, 8),
        part(8, 12),
        part(12, 16),
        part(16, 20),
        part(20, 32)
    )
}

/// The node for a value of type `t` at `at` (without its span), and where
/// the value ends (`None` if it does not parse).
fn value_node(name: String, buf: &Buf, at: usize, t: Type, depth: u32) -> (Node, Option<usize>) {
    let end = buf.skip(at, t, depth);
    if t == Type::Struct {
        return (struct_node(name, buf, at, depth), end);
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
            None => value_node(format!("[{i}]"), &buf, pos, elem, depth),
            Some(k) => {
                let key_end = buf.skip(pos, k, depth);
                let value_end = key_end.and_then(|e| buf.skip(e, elem, depth));
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
    let (key, key_end) = value_node("key".to_owned(), &buf, at, k, depth);
    let Some(key_end) = key_end else {
        cx.emit(key);
        return Err(Diagnostic::malformed("invalid map key"));
    };
    cx.emit(key.span(buf.sub(at, key_end)));
    let (value, end) = value_node("value".to_owned(), &buf, key_end, v, depth);
    let end = end.unwrap_or(buf.data.len());
    cx.emit(value.span(buf.sub(key_end, end)));
    Ok(())
}
