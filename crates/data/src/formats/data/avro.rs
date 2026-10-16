//! Apache Avro object container files: a header with a metadata map (the
//! schema and codec) and a sync marker, then blocks of serialized objects,
//! each followed by the sync marker.
//!
//! Objects are decoded with the schema (the Avro binary encoding: zigzag
//! varints, length-prefixed bytes and strings, unions as a branch index,
//! arrays and maps in counted blocks). Checked against fastavro.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::text::json;
use crate::formats::util::json::Json;
use crate::formats::{Codec, Format, Input, Probe, content, embedded_as};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

pub static FORMAT: Format = Format {
    name: "avro",
    title: "Apache Avro object container",
    extensions: &["avro"],
    mime: "application/avro",
    probe: Probe::Magic(&[(0, b"Obj\x01")]),
    dissect: crate::expander!(dissect: Input),
};

/// Metadata entries read.
const MAX_ENTRIES: usize = 4096;

/// A metadata map entry: its key, (the first MiB of) its value, and
/// where the entry and its value are.
struct Entry {
    key: String,
    value: Vec<u8>,
    span: Span,
    value_span: Span,
}

/// A zigzag-encoded variable-length long at `at`: value and length.
fn long(data: &[u8], at: usize) -> Option<(i64, usize)> {
    let (raw, n) = crate::bytes::uleb128(data.get(at..)?)?;
    Some((crate::formats::util::wire::protobuf::zigzag(raw), n))
}

/// Reads a long through the cursor position `pos` of `span`.
async fn read_long(cx: &Cx, span: Span, pos: u64) -> Result<(i64, u64)> {
    let data = cx.read_avail(span.sub(pos, 10)).await?;
    long(&data, 0).map(|(v, n)| (v, to_u64(n))).ok_or_else(|| {
        Diagnostic::malformed("invalid variable-length integer").at(span.sub(pos, 10))
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(Value::Bytes(b"Obj\x01".to_vec())),
    );
    // Metadata map: blocks of (count, [size,] entries), ending with count 0.
    let mut pos = 4u64;
    let mut entries: Vec<Entry> = Vec::new();
    let map_start = pos;
    loop {
        let (count, n) = read_long(&cx, file, pos).await?;
        pos = pos.saturating_add(n);
        if count == 0 {
            break;
        }
        if count < 0 {
            let (_, n) = read_long(&cx, file, pos).await?;
            pos = pos.saturating_add(n);
        }
        for _ in 0..count.unsigned_abs() {
            if entries.len() >= MAX_ENTRIES {
                return Err(
                    Diagnostic::limit("too many metadata entries").at(file.sub(map_start, 0))
                );
            }
            let start = pos;
            let (klen, n) = read_long(&cx, file, pos).await?;
            pos = pos.saturating_add(n);
            let key = cx.read(file.sub_exact(pos, klen.unsigned_abs())?).await?;
            pos = pos.saturating_add(klen.unsigned_abs());
            let (vlen, n) = read_long(&cx, file, pos).await?;
            pos = pos.saturating_add(n);
            let value_span = file.sub_exact(pos, vlen.unsigned_abs())?;
            let value = cx.read(value_span.sub(0, 1 << 20)).await?;
            pos = pos.saturating_add(vlen.unsigned_abs());
            entries.push(Entry {
                key: String::from_utf8_lossy(&key).into_owned(),
                value,
                span: file.sub(start, pos.saturating_sub(start)),
                value_span,
            });
        }
    }
    let mut meta = Node::new("Metadata")
        .span(file.sub(map_start, pos.saturating_sub(map_start)))
        .summary(crate::formats::util::fmt::plural(entries.len(), "entry"));
    let codec = entries.iter().find(|e| e.key == "avro.codec").map_or_else(
        || "null".to_owned(),
        |e| String::from_utf8_lossy(&e.value).into_owned(),
    );
    let parsed = match entries.iter().find(|e| e.key == "avro.schema") {
        Some(e) => crate::formats::util::json::parse(&cx, &e.value).await.ok(),
        None => None,
    };
    let schema = parsed
        .as_ref()
        .and_then(|j| j.get("name"))
        .and_then(Json::as_str)
        .map(str::to_owned);
    let types = parsed.as_ref().and_then(Schema::parse).map(Arc::new);
    meta = meta.lazy(metadata, (input, std::sync::Arc::new(entries)));
    cx.emit(meta);
    let sync_span = file.sub(pos, 16);
    let sync = cx.read(sync_span).await?;
    cx.emit(
        Node::new("Sync marker")
            .span(sync_span)
            .value(Value::Bytes(sync.clone())),
    );
    pos = pos.saturating_add(16);

    let mut summary = format!("Avro object container, codec {codec}");
    if let Some(name) = schema {
        summary = format!("{summary}, schema {name}");
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(pos))
            .lazy(blocks, (input, pos, sync, codec, types)),
    );
    Ok(())
}

async fn metadata(cx: Cx, (input, entries): (Input, std::sync::Arc<Vec<Entry>>)) -> Result<()> {
    for Entry {
        key,
        value,
        span,
        value_span,
    } in entries.iter()
    {
        if key == "avro.schema" {
            cx.push(embedded_as(
                key.clone(),
                input.nested(*value_span),
                &json::FORMAT,
            ))
            .await;
            continue;
        }
        let node = match std::str::from_utf8(value) {
            Ok(text) => Node::new(key.clone()).value(Value::Text(text.to_owned())),
            Err(_) => {
                Node::new(key.clone()).value(Value::Bytes(value.iter().take(32).copied().collect()))
            }
        };
        cx.push(node.span(*span)).await;
    }
    Ok(())
}

type Blocks = (Input, u64, Vec<u8>, String, Option<Arc<Schema>>);

async fn blocks(cx: Cx, (input, start, sync, codec, schema): Blocks) -> Result<()> {
    let file = input.span;
    let mut pos = start;
    let mut index = 0u64;
    while pos < file.len {
        let block_start = pos;
        let (count, n) = read_long(&cx, file, pos).await?;
        pos = pos.saturating_add(n);
        let (size, n) = read_long(&cx, file, pos).await?;
        pos = pos.saturating_add(n);
        let size = size.unsigned_abs();
        let data = file.sub(pos, size);
        pos = pos.saturating_add(size);
        let marker = cx.read_avail(file.sub(pos, 16)).await?;
        pos = pos.saturating_add(16);
        let whole = file.sub(block_start, pos.saturating_sub(block_start));
        let mut node = Node::new(format!("Block {index}"))
            .span(whole)
            .summary(format!(
                "{count_object}, {size} bytes",
                count_object = crate::formats::util::fmt::plural(count, "object")
            ))
            .lazy(
                block,
                (input, whole, data, count, codec.clone(), schema.clone()),
            );
        if marker != sync {
            node = node.diag(Diagnostic::malformed(
                "sync marker does not match the header",
            ));
        }
        if data.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, size),
                data.len,
            ));
        }
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        index = index.saturating_add(1);
        if marker != sync {
            break;
        }
    }
    Ok(())
}

type Block = (Input, Span, Span, i64, String, Option<Arc<Schema>>);

async fn block(cx: Cx, (input, whole, data, count, codec, schema): Block) -> Result<()> {
    let header_len = data.offset.saturating_sub(whole.offset);
    let (_, count_len) = read_long(&cx, whole, 0).await?;
    cx.emit(
        Node::new("Object count")
            .span(whole.sub(0, count_len))
            .value(Value::Int {
                value: count,
                bits: 64,
            }),
    );
    cx.emit(
        Node::new("Size")
            .span(whole.sub(count_len, header_len.saturating_sub(count_len)))
            .value(Value::UInt {
                value: data.len,
                bits: 64,
                radix: Radix::Dec,
            }),
    );
    let codec = match codec.as_str() {
        "null" => Ok(Codec::Stored),
        "deflate" => Ok(Codec::Deflate),
        "bzip2" => Ok(Codec::Bzip2),
        "xz" => Ok(Codec::Xz),
        "zstandard" => Ok(Codec::Zstd),
        "snappy" => Ok(Codec::Snappy),
        other => Err(other),
    };
    // Snappy blocks end with a big-endian CRC-32 of the decoded data.
    let body = if matches!(codec, Ok(Codec::Snappy)) {
        data.sub(0, data.len.saturating_sub(4))
    } else {
        data
    };
    let node = match (codec, schema) {
        (Ok(Codec::Stored), Some(schema)) => Node::new("Objects")
            .span(data)
            .lazy(objects, (schema, data, count)),
        (Ok(c), Some(schema)) => Node::new("Objects")
            .span(body)
            .lazy(decoded_objects, (schema, body, c, count)),
        (Ok(c), None) => content("Objects", input, body, c, None),
        (Err(other), _) => Node::new("Objects")
            .span(data)
            .diag(Diagnostic::unsupported(format!("{other} codec"))),
    };
    cx.emit(node.summary(format!("{} bytes", data.len)));
    cx.emit(Node::new("Sync marker").span(whole.tail(whole.len.saturating_sub(16))));
    Ok(())
}

// ---------------------------------------------------------------------------
// Objects, decoded with the schema

/// Largest decoded block whose objects are listed.
const MAX_BLOCK: u64 = 16 << 20;
/// Bytes of a string or bytes value shown.
const MAX_SHOWN: usize = 4096;
/// Schema types parsed, and pending values while skipping one.
const MAX_TYPES: usize = 1 << 14;
const MAX_STACK: usize = 1 << 16;

/// One type of a parsed schema; named types are referred to by index.
#[derive(Clone, Debug)]
enum Ty {
    Null,
    Boolean,
    Int(Option<&'static str>),
    Long(Option<&'static str>),
    Float,
    Double,
    Bytes,
    String,
    Record(String, Vec<(String, usize)>),
    Enum(String, Vec<String>),
    Array(usize),
    Map(usize),
    Union(Vec<usize>),
    Fixed(String, u64),
}

/// A parsed schema: its types, the first being the top level.
#[derive(Debug, Default)]
struct Schema {
    types: Vec<Ty>,
}

impl Schema {
    fn parse(json: &Json) -> Option<Schema> {
        let mut s = Schema::default();
        let mut names = BTreeMap::new();
        s.add(json, &mut names, "", 0)?;
        Some(s)
    }

    fn ty(&self, i: usize) -> &Ty {
        self.types.get(i).unwrap_or(&Ty::Null)
    }

    /// Adds the type `json` describes and returns its index.
    fn add(
        &mut self,
        json: &Json,
        names: &mut BTreeMap<String, usize>,
        namespace: &str,
        depth: u32,
    ) -> Option<usize> {
        if depth > 64 || self.types.len() >= MAX_TYPES {
            return None;
        }
        let full = |name: &str, ns: &str| {
            if name.contains('.') || ns.is_empty() {
                name.to_owned()
            } else {
                format!("{ns}.{name}")
            }
        };
        let primitive = |name: &str, logical: Option<&str>| -> Option<Ty> {
            let logical = logical.and_then(|l| {
                [
                    "date",
                    "time-millis",
                    "time-micros",
                    "timestamp-millis",
                    "timestamp-micros",
                    "timestamp-nanos",
                    "local-timestamp-millis",
                    "local-timestamp-micros",
                ]
                .into_iter()
                .find(|k| *k == l)
            });
            Some(match name {
                "null" => Ty::Null,
                "boolean" => Ty::Boolean,
                "int" => Ty::Int(logical),
                "long" => Ty::Long(logical),
                "float" => Ty::Float,
                "double" => Ty::Double,
                "bytes" => Ty::Bytes,
                "string" => Ty::String,
                _ => return None,
            })
        };
        let push = |s: &mut Schema, t: Ty| {
            s.types.push(t);
            s.types.len().checked_sub(1)
        };
        match json {
            Json::Str(name) => match primitive(name, None) {
                Some(t) => push(self, t),
                None => names
                    .get(&full(name, namespace))
                    .or_else(|| names.get(name.as_str()))
                    .copied(),
            },
            Json::Arr(branches) => {
                let mut out = Vec::new();
                for b in branches {
                    out.push(self.add(b, names, namespace, depth.saturating_add(1))?);
                }
                push(self, Ty::Union(out))
            }
            Json::Obj(_) => {
                let kind = json.get("type")?;
                let Json::Str(kind) = kind else {
                    // {"type": {...}}: a nested type.
                    return self.add(kind, names, namespace, depth.saturating_add(1));
                };
                if let Some(t) = primitive(kind, json.get("logicalType").and_then(Json::as_str)) {
                    return push(self, t);
                }
                let name = json.get("name").and_then(Json::as_str).unwrap_or("");
                let ns = json
                    .get("namespace")
                    .and_then(Json::as_str)
                    .unwrap_or(namespace);
                let qualified = full(name, ns);
                let inner_ns = qualified.rsplit_once('.').map_or("", |(n, _)| n).to_owned();
                match kind.as_str() {
                    "record" | "error" => {
                        // Registered first, so the fields can refer to it.
                        let at = push(self, Ty::Record(name.to_owned(), Vec::new()))?;
                        names.insert(qualified, at);
                        let mut fields = Vec::new();
                        for f in json
                            .get("fields")
                            .and_then(Json::as_array)
                            .unwrap_or_default()
                        {
                            let fname = f.get("name").and_then(Json::as_str).unwrap_or("?");
                            let t = self.add(
                                f.get("type")?,
                                names,
                                &inner_ns,
                                depth.saturating_add(1),
                            )?;
                            fields.push((fname.to_owned(), t));
                        }
                        if let Some(slot) = self.types.get_mut(at) {
                            *slot = Ty::Record(name.to_owned(), fields);
                        }
                        Some(at)
                    }
                    "enum" => {
                        let symbols = json
                            .get("symbols")
                            .and_then(Json::as_array)
                            .unwrap_or_default()
                            .iter()
                            .filter_map(|s| s.as_str().map(str::to_owned))
                            .collect();
                        let at = push(self, Ty::Enum(name.to_owned(), symbols))?;
                        names.insert(qualified, at);
                        Some(at)
                    }
                    "fixed" => {
                        let size = json.get("size").and_then(Json::as_u64)?;
                        let at = push(self, Ty::Fixed(name.to_owned(), size))?;
                        names.insert(qualified, at);
                        Some(at)
                    }
                    "array" => {
                        let items = self.add(
                            json.get("items")?,
                            names,
                            namespace,
                            depth.saturating_add(1),
                        )?;
                        push(self, Ty::Array(items))
                    }
                    "map" => {
                        let values = self.add(
                            json.get("values")?,
                            names,
                            namespace,
                            depth.saturating_add(1),
                        )?;
                        push(self, Ty::Map(values))
                    }
                    other => names
                        .get(&full(other, namespace))
                        .or_else(|| names.get(other))
                        .copied(),
                }
            }
            _ => None,
        }
    }

    fn type_name(&self, i: usize) -> String {
        match self.ty(i) {
            Ty::Null => "null".into(),
            Ty::Boolean => "boolean".into(),
            Ty::Int(l) => l.unwrap_or("int").into(),
            Ty::Long(l) => l.unwrap_or("long").into(),
            Ty::Float => "float".into(),
            Ty::Double => "double".into(),
            Ty::Bytes => "bytes".into(),
            Ty::String => "string".into(),
            Ty::Record(n, _) => format!("record {n}"),
            Ty::Enum(n, _) => format!("enum {n}"),
            Ty::Array(_) => "array".into(),
            Ty::Map(_) => "map".into(),
            Ty::Union(_) => "union".into(),
            Ty::Fixed(n, size) => format!("fixed {n} ({size} bytes)"),
        }
    }
}

/// A decoded block: its bytes, where they are, and the schema.
struct Objects {
    schema: Arc<Schema>,
    data: Vec<u8>,
    span: Span,
}

impl Objects {
    fn long(&self, pos: usize) -> Result<(i64, usize)> {
        long(&self.data, pos)
            .map(|(v, n)| (v, pos.saturating_add(n)))
            .ok_or_else(|| self.bad(pos, "invalid variable-length integer"))
    }

    fn bytes(&self, pos: usize) -> Result<(&[u8], usize)> {
        let (len, at) = self.long(pos)?;
        let len = usize::try_from(len).map_err(|_| self.bad(pos, "negative length"))?;
        let end = at
            .checked_add(len)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| {
                Diagnostic::truncated(
                    self.span.sub(to_u64(at), to_u64(len)),
                    to_u64(self.data.len().saturating_sub(at)),
                )
            })?;
        Ok((self.data.get(at..end).unwrap_or_default(), end))
    }

    fn fixed(&self, pos: usize, n: u64) -> Result<usize> {
        pos.checked_add(to_usize(n))
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| {
                Diagnostic::truncated(
                    self.span.sub(to_u64(pos), n),
                    to_u64(self.data.len().saturating_sub(pos)),
                )
            })
    }

    fn bad(&self, pos: usize, what: &str) -> Diagnostic {
        Diagnostic::malformed(what.to_owned()).at(self.span.sub(to_u64(pos), 1))
    }

    fn span(&self, a: usize, b: usize) -> Span {
        self.span.sub(to_u64(a), to_u64(b.saturating_sub(a)))
    }
}

/// What remains to skip.
enum Pending {
    Value(usize),
    Key,
    /// Items of an array or map block, then its next block.
    Items {
        item: usize,
        map: bool,
        left: u64,
    },
    Blocks {
        item: usize,
        map: bool,
    },
}

/// Skips the value of type `ty` at `pos`: where it ends, and for an array
/// or map, how many items it has.
async fn skip_value(cx: &Cx, o: &Objects, pos: usize, ty: usize) -> Result<(usize, u64)> {
    let mut stack = vec![Pending::Value(ty)];
    let mut pos = pos;
    let mut steps = 0u32;
    let mut items = 0u64;
    let top = matches!(o.schema.ty(ty), Ty::Array(_) | Ty::Map(_));
    while let Some(p) = stack.pop() {
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        if stack.len() > MAX_STACK {
            return Err(Diagnostic::limit("values nested too deeply").at(o.span(pos, pos)));
        }
        match p {
            Pending::Key => pos = o.bytes(pos)?.1,
            Pending::Items { item, map, left } => {
                if left > 0 {
                    stack.push(Pending::Items {
                        item,
                        map,
                        left: left.saturating_sub(1),
                    });
                    stack.push(Pending::Value(item));
                    if map {
                        stack.push(Pending::Key);
                    }
                } else {
                    stack.push(Pending::Blocks { item, map });
                }
            }
            Pending::Blocks { item, map } => {
                let (count, at) = o.long(pos)?;
                pos = at;
                if count < 0 {
                    pos = o.long(pos)?.1;
                }
                if count != 0 {
                    if top && stack.is_empty() {
                        items = items.saturating_add(count.unsigned_abs());
                    }
                    stack.push(Pending::Items {
                        item,
                        map,
                        left: count.unsigned_abs(),
                    });
                }
            }
            Pending::Value(t) => match o.schema.ty(t) {
                Ty::Null => {}
                Ty::Boolean => pos = o.fixed(pos, 1)?,
                Ty::Int(_) | Ty::Long(_) | Ty::Enum(..) => pos = o.long(pos)?.1,
                Ty::Float => pos = o.fixed(pos, 4)?,
                Ty::Double => pos = o.fixed(pos, 8)?,
                Ty::Bytes | Ty::String => pos = o.bytes(pos)?.1,
                Ty::Fixed(_, n) => pos = o.fixed(pos, *n)?,
                Ty::Record(_, fields) => {
                    for (_, f) in fields.iter().rev() {
                        stack.push(Pending::Value(*f));
                    }
                }
                Ty::Array(item) => stack.push(Pending::Blocks {
                    item: *item,
                    map: false,
                }),
                Ty::Map(item) => stack.push(Pending::Blocks {
                    item: *item,
                    map: true,
                }),
                Ty::Union(branches) => {
                    let (i, at) = o.long(pos)?;
                    let Some(&b) = usize::try_from(i).ok().and_then(|i| branches.get(i)) else {
                        return Err(o.bad(pos, &format!("union branch {i} out of range")));
                    };
                    pos = at;
                    stack.push(Pending::Value(b));
                }
            },
        }
    }
    Ok((pos, items))
}

/// A scalar value of type `ty` at `pos`, or `None` for compound types.
fn scalar(o: &Objects, pos: usize, ty: usize) -> Result<Option<(Value, Option<String>)>> {
    let le = |n: u64| -> Result<&[u8]> {
        let end = o.fixed(pos, n)?;
        Ok(o.data.get(pos..end).unwrap_or_default())
    };
    Ok(Some(match o.schema.ty(ty) {
        Ty::Null => (Value::Text("null".to_owned()), None),
        Ty::Boolean => (Value::Bool(le(1)?.first().is_some_and(|&b| b != 0)), None),
        Ty::Int(logical) | Ty::Long(logical) => {
            let (v, _) = o.long(pos)?;
            let int = Value::Int {
                value: v,
                bits: if matches!(o.schema.ty(ty), Ty::Int(_)) {
                    32
                } else {
                    64
                },
            };
            use crate::value::{Time, Zone};
            // `local-timestamp-*` is a wall clock in no particular zone.
            let local = |t: Time| {
                if logical.is_some_and(|l| l.starts_with("local-")) {
                    Time {
                        zone: Zone::Local,
                        ..t
                    }
                } else {
                    t
                }
            };
            let per_sec = match *logical {
                Some("timestamp-millis" | "local-timestamp-millis") => Some(1_000),
                Some("timestamp-micros" | "local-timestamp-micros") => Some(1_000_000),
                Some("timestamp-nanos" | "local-timestamp-nanos") => Some(1_000_000_000),
                _ => None,
            };
            match (*logical, per_sec) {
                (Some("date"), _) => (
                    Value::Timestamp(Time::utc(v.saturating_mul(86_400)).day()),
                    Some(format!("{v} days")),
                ),
                (_, Some(per)) => (Value::Timestamp(local(Time::unix_scaled(v, per))), None),
                _ => (int, logical.map(str::to_owned)),
            }
        }
        Ty::Float => {
            let b = le(4)?;
            let v = f32::from_le_bytes(b.try_into().unwrap_or([0; 4]));
            (Value::f32(v), None)
        }
        Ty::Double => {
            let b = le(8)?;
            (
                Value::f64(f64::from_le_bytes(b.try_into().unwrap_or([0; 8]))),
                None,
            )
        }
        Ty::String => {
            let (b, _) = o.bytes(pos)?;
            let shown = b.get(..MAX_SHOWN).unwrap_or(b);
            (
                Value::Text(String::from_utf8_lossy(shown).into_owned()),
                (b.len() > MAX_SHOWN).then(|| format!("{} bytes", b.len())),
            )
        }
        Ty::Bytes => {
            let (b, _) = o.bytes(pos)?;
            (
                Value::Bytes(b.iter().take(64).copied().collect()),
                Some(format!("{} bytes", b.len())),
            )
        }
        Ty::Fixed(_, n) => (
            Value::Bytes(le(*n)?.iter().take(64).copied().collect()),
            None,
        ),
        Ty::Enum(_, symbols) => {
            let (i, _) = o.long(pos)?;
            match usize::try_from(i).ok().and_then(|i| symbols.get(i)) {
                Some(s) => (Value::Text(s.clone()), Some(format!("symbol {i}"))),
                None => (
                    Value::Int { value: i, bits: 32 },
                    Some("symbol out of range".to_owned()),
                ),
            }
        }
        _ => return Ok(None),
    }))
}

/// A node for the value of type `ty` at `pos`, and where the value ends.
async fn value_node(
    cx: &Cx,
    o: &Arc<Objects>,
    name: String,
    pos: usize,
    ty: usize,
) -> Result<(Node, usize)> {
    let (end, items) = skip_value(cx, o, pos, ty).await?;
    let mut node = Node::new(name).span(o.span(pos, end));
    // A union shows its branch's value.
    let (mut at, mut t, mut branch) = (pos, ty, None);
    if let Ty::Union(branches) = o.schema.ty(ty) {
        let (i, next) = o.long(pos)?;
        t = usize::try_from(i)
            .ok()
            .and_then(|i| branches.get(i))
            .copied()
            .unwrap_or(0);
        at = next;
        branch = Some(i);
    }
    let kind = o.schema.type_name(t);
    let note = |s: String| match branch {
        Some(b) => format!(
            "branch {b} ({kind}){}",
            if s.is_empty() {
                String::new()
            } else {
                format!(", {s}")
            }
        ),
        None => s,
    };
    if matches!(o.schema.ty(t), Ty::Null) {
        return Ok((
            node.summary(if branch.is_some() {
                note(String::new())
            } else {
                "null".to_owned()
            }),
            end,
        ));
    }
    if let Some((value, extra)) = scalar(o, at, t)? {
        node = node.value(value);
        let s = note(extra.unwrap_or_default());
        if !s.is_empty() {
            node = node.summary(s);
        }
        return Ok((node, end));
    }
    let summary = match o.schema.ty(t) {
        Ty::Record(name, fields) => {
            // A preview of the scalar fields.
            let mut parts = Vec::new();
            let mut p = at;
            for (fname, f) in fields.iter().take(8) {
                let (fend, _) = skip_value(cx, o, p, *f).await?;
                let mut ft = *f;
                let mut fp = p;
                if let Ty::Union(b) = o.schema.ty(*f) {
                    let (i, next) = o.long(p)?;
                    ft = usize::try_from(i)
                        .ok()
                        .and_then(|i| b.get(i))
                        .copied()
                        .unwrap_or(0);
                    fp = next;
                }
                let shown = match scalar(o, fp, ft)? {
                    _ if matches!(o.schema.ty(ft), Ty::Null) => "null".to_owned(),
                    Some((v, _)) => crate::formats::util::fmt::clip(&crate::render::value(&v), 24),
                    None => "…".to_owned(),
                };
                parts.push(format!("{fname}={shown}"));
                p = fend;
            }
            format!(
                "{name}: {}",
                crate::formats::util::fmt::clip(&parts.join(", "), 160)
            )
        }
        Ty::Array(_) => crate::formats::util::fmt::plural(items, "item"),
        Ty::Map(_) => crate::formats::util::fmt::count(items, "entry", "entries"),
        _ => kind.clone(),
    };
    node = node.summary(note(summary));
    if items == 0 && matches!(o.schema.ty(t), Ty::Array(_) | Ty::Map(_)) {
        return Ok((node, end));
    }
    node = node.lazy(
        crate::expander!(self::children: (Arc<Objects>, usize, usize)),
        (o.clone(), at, t),
    );
    Ok((node, end))
}

/// The fields of a record, or the items of an array or map.
async fn children(cx: Cx, (o, pos, ty): (Arc<Objects>, usize, usize)) -> Result<()> {
    match o.schema.ty(ty).clone() {
        Ty::Record(_, fields) => {
            let mut p = pos;
            for (name, f) in fields {
                let (node, end) = value_node(&cx, &o, name, p, f).await?;
                cx.push(node).await;
                p = end;
            }
        }
        Ty::Array(item) | Ty::Map(item) => {
            let map = matches!(o.schema.ty(ty), Ty::Map(_));
            let mut p = pos;
            let mut index = 0u64;
            loop {
                let (count, at) = o.long(p)?;
                p = at;
                if count == 0 {
                    break;
                }
                if count < 0 {
                    p = o.long(p)?.1;
                }
                for _ in 0..count.unsigned_abs() {
                    let start = p;
                    let name = if map {
                        let (key, at) = o.bytes(p)?;
                        p = at;
                        crate::formats::util::fmt::clip(&String::from_utf8_lossy(key), 120)
                    } else {
                        format!("[{index}]")
                    };
                    let (node, end) = value_node(&cx, &o, name, p, item).await?;
                    cx.push(node.span(o.span(start, end))).await;
                    p = end;
                    index = index.saturating_add(1);
                }
            }
        }
        _ => {}
    }
    Ok(())
}

/// The objects of a block, decoded with the schema.
async fn objects(cx: Cx, (schema, span, count): (Arc<Schema>, Span, i64)) -> Result<()> {
    if span.len > MAX_BLOCK {
        return Err(Diagnostic::limit("block too large to decode").at(span));
    }
    let data = cx.read(span).await?;
    let o = Arc::new(Objects { schema, data, span });
    let mut pos = 0usize;
    for i in 0..count.unsigned_abs() {
        let (node, end) = value_node(&cx, &o, format!("[{i}]"), pos, 0).await?;
        cx.push(node).await;
        pos = end;
    }
    if pos < o.data.len() {
        cx.push(Node::new("Unused").span(o.span(pos, o.data.len())))
            .await;
    }
    Ok(())
}

/// The objects of a compressed block: decoded first.
async fn decoded_objects(
    cx: Cx,
    (schema, span, codec, count): (Arc<Schema>, Span, Codec, i64),
) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, span, &codec, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    objects(cx, (schema, decoded.span, count)).await
}
