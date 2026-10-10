//! Apache Arrow IPC: the file format (Feather v2: `ARROW1`, a stream of
//! messages, a footer indexing them, its length and `ARROW1` again) and
//! the stream format (the messages alone, ending with an end-of-stream
//! marker).
//!
//! Each message is a continuation marker, a metadata length, a FlatBuffers
//! `Message` (schema, dictionary batch or record batch) and a body. Record
//! batch buffers are mapped to the schema's fields (validity, offsets,
//! data, ...); compressed buffers (LZ4 frame, Zstandard) are decoded and
//! their values shown. Layouts follow the Arrow columnar format and
//! `Schema.fbs`/`Message.fbs`/`File.fbs`; checked against pyarrow.

use std::sync::Arc;

use crate::bytes::{i32_le, to_u64, to_usize, u32_le, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::int;
use crate::formats::util::wire::flatbuffers::mem::{Table, deref, root, table};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const MAGIC: &[u8] = b"ARROW1";
/// Nested fields followed.
const MAX_DEPTH: u32 = 32;
/// Largest footer or message metadata read.
const MAX_META: u64 = 64 << 20;
/// Values read at once.
const WINDOW: u64 = 64 * 1024;
/// Largest buffer whose offsets are read whole to cut strings.
const MAX_OFFSETS: u64 = 16 << 20;

pub static FORMAT: Format = Format {
    name: "arrow",
    title: "Apache Arrow IPC file (Feather v2)",
    extensions: &["arrow", "feather", "ipc"],
    mime: "application/vnd.apache.arrow.file",
    probe: Probe::Custom(|h: &Head<'_>| h.starts_with(b"ARROW1\0\0") && h.tail.ends_with(MAGIC)),
    dissect: crate::expander!(dissect: Input),
};

pub static STREAM: Format = Format {
    name: "arrow-stream",
    title: "Apache Arrow IPC stream",
    extensions: &["arrows", "arrowstream"],
    mime: "application/vnd.apache.arrow.stream",
    probe: Probe::Custom(probe_stream),
    dissect: crate::expander!(dissect_stream: Input),
};

/// A stream starts with a continuation marker and a schema message.
fn probe_stream(h: &Head<'_>) -> bool {
    if !h.starts_with(b"\xff\xff\xff\xff") {
        return false;
    }
    let Some(len) = u32_le(h.data, 4).map(|l| to_usize(l.into())) else {
        return false;
    };
    if len < 16 || len % 8 != 0 || to_u64(len).saturating_add(8) > h.len {
        return false;
    }
    let Some(meta) = h.data.get(8..len.saturating_add(8)) else {
        return false;
    };
    root(meta).is_some_and(|m| {
        m.i16(meta, 0).is_some_and(|v| (0..=4).contains(&v))
            && m.u8(meta, 1) == Some(1)
            && m.table(meta, 2).is_some()
    })
}

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
const TIME_UNITS: EnumTable = &[
    (0, "second"),
    (1, "millisecond"),
    (2, "microsecond"),
    (3, "nanosecond"),
];
const DATE_UNITS: EnumTable = &[(0, "day"), (1, "millisecond")];
const INTERVAL_UNITS: EnumTable = &[(0, "year-month"), (1, "day-time"), (2, "month-day-nano")];
const PRECISIONS: EnumTable = &[(0, "half"), (1, "single"), (2, "double")];
const UNION_MODES: EnumTable = &[(0, "sparse"), (1, "dense")];
const CODECS: EnumTable = &[(0, "LZ4 frame"), (1, "Zstandard")];
const ENDIANNESS: EnumTable = &[(0, "little"), (1, "big")];

// ---------------------------------------------------------------------------
// FlatBuffers held in memory

#[derive(Clone)]
struct Buf {
    data: Arc<Vec<u8>>,
    span: Span,
}

impl Buf {
    fn at(&self, pos: usize, len: usize) -> Span {
        self.span.sub(to_u64(pos), to_u64(len))
    }

    /// A scalar field of `size` bytes: its node, if present.
    fn scalar(
        &self,
        t: &Table,
        slot: usize,
        name: &'static str,
        size: usize,
        value: Value,
    ) -> Option<Node> {
        let at = t.field(&self.data, slot)?;
        Some(Node::new(name).span(self.at(at, size)).value(value))
    }

    fn string(&self, t: &Table, slot: usize, name: &'static str) -> Option<Node> {
        let (s, start, end) = t.string(&self.data, slot)?;
        Some(
            Node::new(name)
                .span(self.at(
                    start.saturating_sub(4),
                    end.saturating_sub(start).saturating_add(4),
                ))
                .value(Value::Text(s)),
        )
    }
}

/// A table's link to its vtable and the vtable itself (FlatBuffers
/// bookkeeping: the offset of each field slot within the table).
fn vtable(buf: &Buf, t: &Table) -> Vec<Node> {
    let data = &buf.data;
    let Some(soffset) = i32_le(data, t.pos) else {
        return Vec::new();
    };
    let mut out = vec![
        Node::new("vtable offset")
            .span(buf.at(t.pos, 4))
            .value(Value::Int {
                value: soffset.into(),
                bits: 32,
            }),
    ];
    let at = i64::try_from(t.pos)
        .ok()
        .and_then(|p| p.checked_sub(soffset.into()))
        .and_then(|v| usize::try_from(v).ok());
    if let Some(at) = at
        && let (Some(len), Some(size)) = (
            crate::bytes::u16_le(data, at),
            crate::bytes::u16_le(data, at.saturating_add(2)),
        )
    {
        out.push(
            Node::new("vtable")
                .span(buf.at(at, len.into()))
                .value(Value::UInt {
                    value: u64::from(len.saturating_sub(4) / 2),
                    bits: 16,
                    radix: Radix::Dec,
                })
                .summary(format!("field slots; table of {size} bytes")),
        );
    }
    out
}

/// The inline part of a table (its size is in its vtable).
fn tspan(buf: &Buf, t: &Table) -> Span {
    let data = &buf.data;
    let size = i32_le(data, t.pos)
        .and_then(|soffset| i64::try_from(t.pos).ok()?.checked_sub(soffset.into()))
        .and_then(|v| usize::try_from(v).ok())
        .and_then(|at| crate::bytes::u16_le(data, at.saturating_add(2)))
        .map_or(4, usize::from);
    buf.at(t.pos, size.max(4))
}

/// The root offset at the start of a FlatBuffer.
fn root_offset(buf: &Buf) -> Node {
    Node::new("Root offset")
        .span(buf.at(0, 4))
        .value(Value::UInt {
            value: u32_le(&buf.data, 0).unwrap_or(0).into(),
            bits: 32,
            radix: Radix::Hex,
        })
}

fn enumv(raw: i64, bits: u8, table: EnumTable) -> Value {
    Value::Enum {
        raw: raw.cast_unsigned(),
        bits,
        name: lookup(table, raw.cast_unsigned()),
    }
}

// ---------------------------------------------------------------------------
// The schema

#[derive(Clone, Debug, Default)]
struct Field {
    name: String,
    nullable: bool,
    kind: u8,
    bits: i32,
    signed: bool,
    precision: i32,
    scale: i32,
    unit: i16,
    width: i32,
    mode: i16,
    tz: Option<String>,
    dict: Option<Dict>,
    children: Vec<Field>,
}

#[derive(Clone, Debug)]
struct Dict {
    id: i64,
    index_bits: i32,
    index_signed: bool,
    ordered: bool,
}

#[derive(Debug, Default)]
struct Schema {
    fields: Vec<Field>,
}

fn parse_field(data: &[u8], t: &Table, depth: u32) -> Field {
    let mut f = Field {
        name: t.string(data, 0).map(|s| s.0).unwrap_or_default(),
        nullable: t.u8(data, 1).unwrap_or(0) != 0,
        kind: t.u8(data, 2).unwrap_or(0),
        ..Field::default()
    };
    if let Some(ty) = t.table(data, 3) {
        match f.kind {
            2 => {
                f.bits = ty.i32(data, 0).unwrap_or(0);
                f.signed = ty.u8(data, 1).unwrap_or(0) != 0;
            }
            3 => f.precision = ty.i16(data, 0).unwrap_or(0).into(),
            7 => {
                f.precision = ty.i32(data, 0).unwrap_or(0);
                f.scale = ty.i32(data, 1).unwrap_or(0);
                f.bits = ty.i32(data, 2).unwrap_or(128);
            }
            8 => f.unit = ty.i16(data, 0).unwrap_or(1),
            9 => {
                f.unit = ty.i16(data, 0).unwrap_or(1);
                f.bits = ty.i32(data, 1).unwrap_or(32);
            }
            10 => {
                f.unit = ty.i16(data, 0).unwrap_or(0);
                f.tz = ty.string(data, 1).map(|s| s.0);
            }
            11 | 18 => f.unit = ty.i16(data, 0).unwrap_or(if f.kind == 18 { 1 } else { 0 }),
            14 => f.mode = ty.i16(data, 0).unwrap_or(0),
            15 | 16 => f.width = ty.i32(data, 0).unwrap_or(0),
            _ => {}
        }
    } else if f.kind == 8 || f.kind == 9 || f.kind == 18 {
        f.unit = 1;
        f.bits = 32;
    }
    if let Some(d) = t.table(data, 4) {
        let index = d.table(data, 1);
        f.dict = Some(Dict {
            id: d.i64(data, 0).unwrap_or(0),
            index_bits: index.and_then(|i| i.i32(data, 0)).unwrap_or(32),
            index_signed: index.and_then(|i| i.u8(data, 1)).unwrap_or(1) != 0,
            ordered: d.u8(data, 2).unwrap_or(0) != 0,
        });
    }
    if depth < MAX_DEPTH
        && let Some((n, start)) = t.vector(data, 5, 4)
    {
        for j in 0..n {
            if let Some(c) = Table::vector_table(data, start, j) {
                f.children
                    .push(parse_field(data, &c, depth.saturating_add(1)));
            }
        }
    }
    f
}

fn parse_schema(data: &[u8], t: &Table) -> Schema {
    let mut fields = Vec::new();
    if let Some((n, start)) = t.vector(data, 1, 4) {
        for j in 0..n {
            if let Some(c) = Table::vector_table(data, start, j) {
                fields.push(parse_field(data, &c, 0));
            }
        }
    }
    Schema { fields }
}

fn unit(table: EnumTable, u: i16) -> &'static str {
    lookup(table, u64::from(u.cast_unsigned())).unwrap_or("?")
}

/// `int32`, `timestamp[s, UTC]`, `list<utf8>`, `dictionary<int32 → utf8>`.
fn describe(f: &Field) -> String {
    let child = |i: usize| f.children.get(i).map_or_else(|| "?".to_owned(), describe);
    let base = match f.kind {
        1 => "null".to_owned(),
        2 => format!("{}int{}", if f.signed { "" } else { "u" }, f.bits),
        3 => match f.precision {
            0 => "float16".to_owned(),
            1 => "float32".to_owned(),
            _ => "float64".to_owned(),
        },
        4 => "binary".to_owned(),
        5 => "utf8".to_owned(),
        6 => "bool".to_owned(),
        7 => format!("decimal{}({}, {})", f.bits, f.precision, f.scale),
        8 => format!("date[{}]", unit(DATE_UNITS, f.unit)),
        9 => format!("time{}[{}]", f.bits, unit(TIME_UNITS, f.unit)),
        10 => format!(
            "timestamp[{}{}]",
            unit(TIME_UNITS, f.unit),
            f.tz.as_ref().map_or_else(String::new, |z| format!(", {z}"))
        ),
        11 => format!("interval[{}]", unit(INTERVAL_UNITS, f.unit)),
        12 => format!("list<{}>", child(0)),
        13 => {
            let parts: Vec<String> = f
                .children
                .iter()
                .map(|c| format!("{}: {}", c.name, describe(c)))
                .collect();
            format!("struct<{}>", parts.join(", "))
        }
        14 => format!("{} union", unit(UNION_MODES, f.mode)),
        15 => format!("fixed_size_binary[{}]", f.width),
        16 => format!("fixed_size_list<{}>[{}]", child(0), f.width),
        17 => format!("map<{}>", child(0)),
        18 => format!("duration[{}]", unit(TIME_UNITS, f.unit)),
        19 => "large_binary".to_owned(),
        20 => "large_utf8".to_owned(),
        21 => format!("large_list<{}>", child(0)),
        22 => format!("run_end_encoded<{}, {}>", child(0), child(1)),
        23 => "binary_view".to_owned(),
        24 => "utf8_view".to_owned(),
        25 => format!("list_view<{}>", child(0)),
        26 => format!("large_list_view<{}>", child(0)),
        _ => "unknown".to_owned(),
    };
    match &f.dict {
        Some(d) => format!(
            "dictionary<{}int{} → {base}>{}",
            if d.index_signed { "" } else { "u" },
            d.index_bits,
            if d.ordered { ", ordered" } else { "" }
        ),
        None => base,
    }
}

/// The nodes of a KeyValue vector (custom metadata).
fn metadata_node(buf: &Buf, t: &Table, slot: usize) -> Option<Node> {
    let data = &buf.data;
    let (n, start) = t.vector(data, slot, 4)?;
    let mut out = Vec::new();
    for j in 0..n {
        let Some(kv) = Table::vector_table(data, start, j) else {
            continue;
        };
        let key = kv.string(data, 0).map(|s| s.0).unwrap_or_default();
        let mut node = Node::new(key).span(buf.at(kv.pos, 4));
        if let Some((v, s, e)) = kv.string(data, 1) {
            node = node
                .value(Value::Text(v))
                .span(buf.at(s.saturating_sub(4), e.saturating_sub(s).saturating_add(4)));
        }
        out.push(node);
    }
    Some(
        group("Custom metadata", out)
            .span(buf.at(
                start.saturating_sub(4),
                n.saturating_mul(4).saturating_add(4),
            ))
            .summary(format!("{n} entries")),
    )
}

fn group(name: impl Into<std::borrow::Cow<'static, str>>, children: Vec<Node>) -> Node {
    Node::new(name).lazy(
        crate::formats::util::arcutil::push_nodes,
        Arc::new(children),
    )
}

/// The fields of a `Field` table.
fn field_nodes(buf: &Buf, t: &Table, depth: u32) -> Vec<Node> {
    let data = &buf.data;
    let mut out = vtable(buf, t);
    out.extend(buf.string(t, 0, "Name"));
    out.extend(buf.scalar(
        t,
        1,
        "Nullable",
        1,
        Value::Bool(t.u8(data, 1).unwrap_or(0) != 0),
    ));
    let kind = t.u8(data, 2).unwrap_or(0);
    out.extend(buf.scalar(t, 2, "Type", 1, enumv(kind.into(), 8, TYPES)));
    if let Some(ty) = t.table(data, 3) {
        let mut params = vtable(buf, &ty);
        let i16f = |slot: usize, name: &'static str, table: EnumTable| {
            buf.scalar(
                &ty,
                slot,
                name,
                2,
                enumv(ty.i16(data, slot).unwrap_or(0).into(), 16, table),
            )
        };
        let i32f = |slot: usize, name: &'static str| {
            buf.scalar(&ty, slot, name, 4, int(ty.i32(data, slot).unwrap_or(0), 32))
        };
        match kind {
            2 => {
                params.extend(i32f(0, "Bit width"));
                params.extend(buf.scalar(
                    &ty,
                    1,
                    "Signed",
                    1,
                    Value::Bool(ty.u8(data, 1).unwrap_or(0) != 0),
                ));
            }
            3 => params.extend(i16f(0, "Precision", PRECISIONS)),
            7 => {
                params.extend(i32f(0, "Precision"));
                params.extend(i32f(1, "Scale"));
                params.extend(i32f(2, "Bit width"));
            }
            8 => params.extend(i16f(0, "Unit", DATE_UNITS)),
            9 => {
                params.extend(i16f(0, "Unit", TIME_UNITS));
                params.extend(i32f(1, "Bit width"));
            }
            10 => {
                params.extend(i16f(0, "Unit", TIME_UNITS));
                params.extend(buf.string(&ty, 1, "Time zone"));
            }
            11 => params.extend(i16f(0, "Unit", INTERVAL_UNITS)),
            14 => {
                params.extend(i16f(0, "Mode", UNION_MODES));
                if let Some((n, start)) = ty.vector(data, 1, 4) {
                    let ids: Vec<String> = (0..n)
                        .filter_map(|j| i32_le(data, start.saturating_add(j.saturating_mul(4))))
                        .map(|v| v.to_string())
                        .collect();
                    params.push(
                        Node::new("Type IDs")
                            .span(buf.at(start, n.saturating_mul(4)))
                            .value(Value::Text(ids.join(", "))),
                    );
                }
            }
            15 => params.extend(i32f(0, "Byte width")),
            16 => params.extend(i32f(0, "List size")),
            17 => params.extend(buf.scalar(
                &ty,
                0,
                "Keys sorted",
                1,
                Value::Bool(ty.u8(data, 0).unwrap_or(0) != 0),
            )),
            18 => params.extend(i16f(0, "Unit", TIME_UNITS)),
            _ => {}
        }
        out.push(
            group("Type parameters", params)
                .span(tspan(buf, &ty))
                .summary(lookup(TYPES, kind.into()).unwrap_or("unknown").to_owned()),
        );
    }
    if let Some(d) = t.table(data, 4) {
        let mut dict = vtable(buf, &d);
        dict.extend(buf.scalar(&d, 0, "ID", 8, int(d.i64(data, 0).unwrap_or(0), 64)));
        if let Some(index) = d.table(data, 1) {
            let mut fields = vtable(buf, &index);
            fields.extend(buf.scalar(
                &index,
                0,
                "Bit width",
                4,
                int(index.i32(data, 0).unwrap_or(0), 32),
            ));
            fields.extend(buf.scalar(
                &index,
                1,
                "Signed",
                1,
                Value::Bool(index.u8(data, 1).unwrap_or(0) != 0),
            ));
            dict.push(group("Index type", fields).span(tspan(buf, &index)));
        }
        dict.extend(buf.scalar(
            &d,
            2,
            "Ordered",
            1,
            Value::Bool(d.u8(data, 2).unwrap_or(0) != 0),
        ));
        dict.extend(buf.scalar(
            &d,
            3,
            "Kind",
            2,
            enumv(
                d.i16(data, 3).unwrap_or(0).into(),
                16,
                &[(0, "dense array")],
            ),
        ));
        out.push(group("Dictionary encoding", dict).span(tspan(buf, &d)));
    }
    if let Some((n, start)) = t.vector(data, 5, 4).filter(|(n, _)| *n > 0) {
        let node = Node::new("Children")
            .span(buf.at(
                start.saturating_sub(4),
                n.saturating_mul(4).saturating_add(4),
            ))
            .summary(format!("{n}"));
        out.push(if depth >= MAX_DEPTH {
            node.diag(Diagnostic::limit("fields nested too deeply"))
        } else {
            node.lazy(
                crate::expander!(self::fields: (Buf, usize, usize, u32)),
                (buf.clone(), n, start, depth.saturating_add(1)),
            )
        });
    }
    out.extend(metadata_node(buf, t, 6));
    out
}

async fn fields(cx: Cx, (buf, n, start, depth): (Buf, usize, usize, u32)) -> Result<()> {
    let data = buf.data.clone();
    cx.set_count(Count::Exact(to_u64(n)));
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(4));
        let Some(t) = deref(&data, at).and_then(|p| table(&data, p)) else {
            return Err(Diagnostic::malformed("invalid field table").at(buf.at(at, 4)));
        };
        let f = parse_field(&data, &t, depth);
        let mut summary = describe(&f);
        if f.nullable {
            summary.push_str(", nullable");
        }
        let name = if f.name.is_empty() {
            format!("Field {i}")
        } else {
            f.name.clone()
        };
        cx.push(
            group(name, field_nodes(&buf, &t, depth))
                .span(tspan(&buf, &t))
                .summary(summary),
        )
        .await;
    }
    Ok(())
}

fn schema_node(buf: &Buf, schema: Table) -> Node {
    let data = &buf.data;
    let (n, start) = schema.vector(data, 1, 4).unwrap_or((0, 0));
    let mut children = vtable(buf, &schema);
    children.extend(buf.scalar(
        &schema,
        0,
        "Endianness",
        2,
        enumv(schema.i16(data, 0).unwrap_or(0).into(), 16, ENDIANNESS),
    ));
    children.push(
        Node::new("Fields")
            .span(buf.at(
                start.saturating_sub(4),
                n.saturating_mul(4).saturating_add(4),
            ))
            .summary(format!("{n}"))
            .lazy(fields, (buf.clone(), n, start, 0u32)),
    );
    children.extend(metadata_node(buf, &schema, 2));
    if let Some((k, at)) = schema.vector(data, 3, 8) {
        let features: Vec<String> = (0..k)
            .filter_map(|j| u64_le(data, at.saturating_add(j.saturating_mul(8))))
            .map(|v| match v {
                1 => "dictionary replacement".to_owned(),
                2 => "compressed body".to_owned(),
                v => format!("{v}"),
            })
            .collect();
        children.push(
            Node::new("Features")
                .span(buf.at(at, k.saturating_mul(8)))
                .value(Value::Text(features.join(", "))),
        );
    }
    group("Schema", children)
        .span(tspan(buf, &schema))
        .summary(format!("{n} fields"))
}

// ---------------------------------------------------------------------------
// Buffer layout

/// One buffer of a record batch: which field it belongs to and what it
/// holds.
#[derive(Clone, Debug)]
struct Slot {
    path: String,
    label: &'static str,
    field: Field,
    /// The field node (for its length and null count).
    node: usize,
    /// For string and binary data: the index of the offsets buffer.
    offsets: Option<usize>,
}

/// The buffers of `fields`, in the order a record batch lists them.
fn layout(fields: &[Field], variadic: &[i64]) -> (Vec<String>, Vec<Slot>) {
    fn add(
        slots: &mut Vec<Slot>,
        path: &str,
        label: &'static str,
        field: &Field,
        node: usize,
    ) -> usize {
        slots.push(Slot {
            path: path.to_owned(),
            label,
            field: field.clone(),
            node,
            offsets: None,
        });
        slots.len().saturating_sub(1)
    }
    let mut nodes = Vec::new();
    let mut slots: Vec<Slot> = Vec::new();
    let mut views = 0usize;
    let mut stack: Vec<(String, &Field, u32)> = fields
        .iter()
        .rev()
        .map(|f| (f.name.clone(), f, 0u32))
        .collect();
    while let Some((path, f, depth)) = stack.pop() {
        let node = nodes.len();
        nodes.push(path.clone());
        if let Some(d) = &f.dict {
            // The indices: an integer column.
            let mut index = f.clone();
            index.kind = 2;
            index.bits = d.index_bits;
            index.signed = d.index_signed;
            index.dict = None;
            add(&mut slots, &path, "validity", f, node);
            add(&mut slots, &path, "indices", &index, node);
            continue;
        }
        let mut recurse = false;
        match f.kind {
            22 => recurse = true,
            2 | 3 | 6 | 7 | 8 | 9 | 10 | 11 | 15 | 18 => {
                add(&mut slots, &path, "validity", f, node);
                add(&mut slots, &path, "data", f, node);
            }
            4 | 5 | 19 | 20 => {
                add(&mut slots, &path, "validity", f, node);
                let at = add(&mut slots, &path, "offsets", f, node);
                let data = add(&mut slots, &path, "data", f, node);
                if let Some(s) = slots.get_mut(data) {
                    s.offsets = Some(at);
                }
            }
            23 | 24 => {
                add(&mut slots, &path, "validity", f, node);
                add(&mut slots, &path, "views", f, node);
                let n = variadic.get(views).copied().unwrap_or(0);
                views = views.saturating_add(1);
                for _ in 0..n.clamp(0, 1 << 16) {
                    add(&mut slots, &path, "variadic data", f, node);
                }
            }
            12 | 17 | 21 => {
                add(&mut slots, &path, "validity", f, node);
                add(&mut slots, &path, "offsets", f, node);
                recurse = true;
            }
            25 | 26 => {
                add(&mut slots, &path, "validity", f, node);
                add(&mut slots, &path, "offsets", f, node);
                add(&mut slots, &path, "sizes", f, node);
                recurse = true;
            }
            13 | 16 => {
                add(&mut slots, &path, "validity", f, node);
                recurse = true;
            }
            14 => {
                add(&mut slots, &path, "type ids", f, node);
                if f.mode == 1 {
                    add(&mut slots, &path, "offsets", f, node);
                }
                recurse = true;
            }
            _ => {}
        }
        if recurse && depth < MAX_DEPTH {
            for c in f.children.iter().rev() {
                stack.push((format!("{path}.{}", c.name), c, depth.saturating_add(1)));
            }
        }
    }
    (nodes, slots)
}

/// The value field of dictionary `id`: the dictionary-encoded field with
/// its encoding removed.
fn dictionary_field(fields: &[Field], id: i64) -> Option<Field> {
    let mut stack: Vec<&Field> = fields.iter().collect();
    while let Some(f) = stack.pop() {
        if f.dict.as_ref().is_some_and(|d| d.id == id) {
            let mut v = f.clone();
            v.dict = None;
            v.name = format!("dictionary {id}");
            return Some(v);
        }
        stack.extend(f.children.iter());
    }
    None
}

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 6))
            .value(Value::Text("ARROW1".to_owned())),
    );
    cx.emit(
        Node::new("Padding")
            .span(file.sub(6, 2))
            .value(Value::Bytes(vec![0, 0])),
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
    if len > MAX_META {
        return Err(Diagnostic::limit("footer too large").at(tail_span));
    }
    let span = file.sub(start, len);
    let buf = Buf {
        data: Arc::new(cx.read(span).await?),
        span,
    };
    let data = &buf.data;
    let footer =
        root(data).ok_or_else(|| Diagnostic::malformed("invalid footer table").at(span))?;
    let schema = Arc::new(
        footer
            .table(data, 1)
            .map(|s| parse_schema(data, &s))
            .unwrap_or_default(),
    );
    let batches = footer.vector(data, 3, 24).map_or(0, |(n, _)| n);
    let rows = footer_rows(&cx, input, &buf, &footer).await;
    let version = footer.i16(data, 0).unwrap_or(0);
    cx.annotate(format!(
        "Arrow IPC file, metadata {}, {} fields, {batches} record batches{}",
        lookup(VERSIONS, u64::from(version.cast_unsigned())).unwrap_or("unknown version"),
        schema.fields.len(),
        rows.map_or_else(String::new, |r| format!(", {r} rows"))
    ));
    cx.emit(
        Node::new("Messages")
            .span(file.sub(8, start.saturating_sub(8)))
            .lazy(messages, (input, 8u64, start, Some(schema.clone()))),
    );
    cx.emit(
        Node::new("Footer")
            .span(span)
            .lazy(footer_node, (input, buf.clone(), schema)),
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

/// Total rows of the record batches a footer lists (reading each batch's
/// metadata; skipped for files with many batches).
async fn footer_rows(cx: &Cx, input: Input, buf: &Buf, footer: &Table) -> Option<i64> {
    let (n, start) = footer.vector(&buf.data, 3, 24)?;
    if n > 64 {
        return None;
    }
    let mut total = 0i64;
    for i in 0..n {
        let at = start.saturating_add(i.saturating_mul(24));
        let offset = u64_le(&buf.data, at)?;
        let meta = read_meta(cx, input, offset).await.ok()?;
        let msg = root(&meta.data)?;
        let batch = msg.table(&meta.data, 2)?;
        total = total.saturating_add(batch.i64(&meta.data, 0).unwrap_or(0));
    }
    Some(total)
}

pub async fn dissect_stream(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let first = read_meta(&cx, input, 0).await?;
    let msg =
        root(&first.data).ok_or_else(|| Diagnostic::malformed("invalid message").at(first.span))?;
    let schema = Arc::new(
        msg.table(&first.data, 2)
            .map(|s| parse_schema(&first.data, &s))
            .unwrap_or_default(),
    );
    let version = msg.i16(&first.data, 0).unwrap_or(0);
    cx.annotate(format!(
        "Arrow IPC stream, metadata {}, {} fields",
        lookup(VERSIONS, u64::from(version.cast_unsigned())).unwrap_or("unknown version"),
        schema.fields.len()
    ));
    messages(cx, (input, 0, file.len, Some(schema))).await
}

/// A message's prefix: (bytes before the metadata, metadata length).
async fn prefix(cx: &Cx, input: Input, pos: u64) -> Result<(u64, u32)> {
    let head = cx.read_avail(input.span.sub(pos, 8)).await?;
    Ok(if u32_le(&head, 0) == Some(u32::MAX) {
        (8, u32_le(&head, 4).unwrap_or(0))
    } else {
        (4, u32_le(&head, 0).unwrap_or(0))
    })
}

/// The metadata FlatBuffer of the message at `pos`.
async fn read_meta(cx: &Cx, input: Input, pos: u64) -> Result<Buf> {
    let (pre, len) = prefix(cx, input, pos).await?;
    if u64::from(len) > MAX_META {
        return Err(Diagnostic::limit("message metadata too large").at(input.span.sub(pos, pre)));
    }
    let span = input.span.sub_exact(pos.saturating_add(pre), len.into())?;
    Ok(Buf {
        data: Arc::new(cx.read(span).await?),
        span,
    })
}

async fn footer_node(cx: Cx, (input, buf, schema): (Input, Buf, Arc<Schema>)) -> Result<()> {
    let data = &buf.data;
    let footer = root(data).ok_or_else(|| Diagnostic::malformed("invalid footer table"))?;
    cx.emit(root_offset(&buf));
    for n in vtable(&buf, &footer) {
        cx.emit(n);
    }
    if let Some(v) = footer.i16(data, 0) {
        cx.emit(
            buf.scalar(&footer, 0, "Version", 2, enumv(v.into(), 16, VERSIONS))
                .unwrap_or_else(|| Node::new("Version")),
        );
    }
    if let Some(s) = footer.table(data, 1) {
        cx.emit(schema_node(&buf, s));
    }
    for (i, name) in [(2usize, "Dictionaries"), (3, "Record batches")] {
        if let Some((n, start)) = footer.vector(data, i, 24) {
            cx.emit(
                Node::new(name)
                    .span(buf.at(
                        start.saturating_sub(4),
                        n.saturating_mul(24).saturating_add(4),
                    ))
                    .summary(format!("{n}"))
                    .lazy(blocks, (input, buf.clone(), n, start, schema.clone())),
            );
        }
    }
    if let Some(m) = metadata_node(&buf, &footer, 4) {
        cx.emit(m);
    }
    Ok(())
}

/// Footer blocks: (offset, metadata length, body length) structs.
async fn blocks(
    cx: Cx,
    (input, buf, n, start, schema): (Input, Buf, usize, usize, Arc<Schema>),
) -> Result<()> {
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
        let fields = vec![
            Node::new("Offset").span(buf.at(at, 8)).value(Value::UInt {
                value: offset,
                bits: 64,
                radix: Radix::Hex,
            }),
            Node::new("Metadata length")
                .span(buf.at(at.saturating_add(8), 4))
                .value(Value::UInt {
                    value: meta.into(),
                    bits: 32,
                    radix: Radix::Dec,
                }),
            Node::new("Padding")
                .span(buf.at(at.saturating_add(12), 4))
                .value(Value::Bytes(
                    data.get(at.saturating_add(12)..at.saturating_add(16))
                        .unwrap_or_default()
                        .to_vec(),
                )),
            Node::new("Body length")
                .span(buf.at(at.saturating_add(16), 8))
                .value(Value::UInt {
                    value: body,
                    bits: 64,
                    radix: Radix::Dec,
                }),
        ];
        let mut fields = fields;
        fields.push(
            Node::new("Message")
                .span(whole)
                .lazy(message, (input, offset, Some(schema.clone()))),
        );
        cx.push(
            group(format!("Block {i}"), fields)
                .span(buf.at(at, 24))
                .value(Value::UInt {
                    value: offset,
                    bits: 64,
                    radix: Radix::Hex,
                })
                .summary(format!("metadata {meta} bytes, body {body} bytes"))
                .target(whole),
        )
        .await;
    }
    Ok(())
}

/// Messages in sequence: continuation marker, metadata length, metadata,
/// body.
async fn messages(
    cx: Cx,
    (input, start, end, schema): (Input, u64, u64, Option<Arc<Schema>>),
) -> Result<()> {
    let mut pos = start;
    let mut batch = 0u64;
    while pos < end {
        let (pre, meta) = prefix(&cx, input, pos).await?;
        if meta == 0 {
            cx.push(
                Node::new("End of stream")
                    .span(input.span.sub(pos, pre))
                    .value(Value::Bytes(cx.read_avail(input.span.sub(pos, pre)).await?)),
            )
            .await;
            pos = pos.saturating_add(pre);
            continue;
        }
        let m = read_meta(&cx, input, pos).await?;
        let msg =
            root(&m.data).ok_or_else(|| Diagnostic::malformed("invalid message").at(m.span))?;
        let kind = msg.u8(&m.data, 1).unwrap_or(0);
        let body = msg
            .i64(&m.data, 3)
            .and_then(|v| u64::try_from(v).ok())
            .unwrap_or(0);
        let total = pre.saturating_add(meta.into()).saturating_add(body);
        let mut summary = format!("{} bytes", total);
        let name = match kind {
            3 => {
                let rows = msg
                    .table(&m.data, 2)
                    .and_then(|b| b.i64(&m.data, 0))
                    .unwrap_or(0);
                summary = format!(
                    "{rows} rows, body {}",
                    crate::formats::util::fmt::size(body)
                );
                batch = batch.saturating_add(1);
                format!("Record batch {}", batch.saturating_sub(1))
            }
            2 => {
                let d = msg.table(&m.data, 2);
                let id = d.and_then(|d| d.i64(&m.data, 0)).unwrap_or(0);
                let rows = d
                    .and_then(|d| d.table(&m.data, 1))
                    .and_then(|b| b.i64(&m.data, 0))
                    .unwrap_or(0);
                summary = format!("dictionary {id}, {rows} values");
                "Dictionary batch".to_owned()
            }
            1 => {
                let n = msg
                    .table(&m.data, 2)
                    .and_then(|s| s.vector(&m.data, 1, 4))
                    .map_or(0, |(n, _)| n);
                summary = format!("{n} fields");
                "Schema".to_owned()
            }
            k => lookup(HEADERS, k.into()).unwrap_or("Message").to_owned(),
        };
        cx.progress(pos.saturating_sub(start), end.saturating_sub(start));
        cx.push(
            Node::new(name)
                .span(input.span.sub(pos, total))
                .summary(summary)
                .lazy(message, (input, pos, schema.clone())),
        )
        .await;
        pos = pos.saturating_add(total.max(1));
    }
    Ok(())
}

async fn message(cx: Cx, (input, pos, schema): (Input, u64, Option<Arc<Schema>>)) -> Result<()> {
    let (pre, meta) = prefix(&cx, input, pos).await?;
    if pre == 8 {
        cx.emit(
            Node::new("Continuation")
                .span(input.span.sub(pos, 4))
                .value(Value::UInt {
                    value: u32::MAX.into(),
                    bits: 32,
                    radix: Radix::Hex,
                }),
        );
    }
    cx.emit(
        Node::new("Metadata length")
            .span(input.span.sub(pos.saturating_add(pre).saturating_sub(4), 4))
            .value(Value::UInt {
                value: meta.into(),
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    let buf = read_meta(&cx, input, pos).await?;
    let data = &buf.data;
    let msg = root(data).ok_or_else(|| Diagnostic::malformed("invalid message").at(buf.span))?;
    let kind = msg.u8(data, 1).unwrap_or(0);
    let body_len = msg
        .i64(data, 3)
        .and_then(|v| u64::try_from(v).ok())
        .unwrap_or(0);
    let mut fields = vec![root_offset(&buf)];
    fields.extend(vtable(&buf, &msg));
    fields.extend(buf.scalar(
        &msg,
        0,
        "Version",
        2,
        enumv(msg.i16(data, 0).unwrap_or(0).into(), 16, VERSIONS),
    ));
    fields.extend(buf.scalar(&msg, 1, "Header type", 1, enumv(kind.into(), 8, HEADERS)));
    fields.extend(buf.scalar(
        &msg,
        3,
        "Body length",
        8,
        int(msg.i64(data, 3).unwrap_or(0), 64),
    ));
    fields.extend(metadata_node(&buf, &msg, 4));
    let body = input.span.sub(
        pos.saturating_add(pre).saturating_add(meta.into()),
        body_len,
    );
    let schema = match (kind, msg.table(data, 2), schema) {
        (1, Some(s), _) => Some(Arc::new(parse_schema(data, &s))),
        (_, _, s) => s,
    };
    let mut layout_info = None;
    match (kind, msg.table(data, 2)) {
        (1, Some(s)) => fields.push(schema_node(&buf, s)),
        (2 | 3, Some(mut batch)) => {
            let mut value_fields = schema.as_ref().map_or_else(Vec::new, |s| s.fields.clone());
            if kind == 2 {
                // DictionaryBatch: id, data (a RecordBatch), isDelta.
                let id = batch.i64(data, 0).unwrap_or(0);
                fields.extend(vtable(&buf, &batch));
                fields.extend(buf.scalar(&batch, 0, "Dictionary ID", 8, int(id, 64)));
                fields.extend(buf.scalar(
                    &batch,
                    2,
                    "Delta",
                    1,
                    Value::Bool(batch.u8(data, 2).unwrap_or(0) != 0),
                ));
                value_fields = dictionary_field(&value_fields, id).into_iter().collect();
                match batch.table(data, 1) {
                    Some(b) => batch = b,
                    None => {
                        emit_all(&cx, fields);
                        return Ok(());
                    }
                }
            }
            let (batch_nodes, info) = record_batch(&buf, &batch, &value_fields, body);
            fields.extend(batch_nodes);
            layout_info = Some(info);
        }
        _ => {}
    }
    emit_all(&cx, fields);
    let mut body_node = Node::new("Body")
        .span(body)
        .summary(crate::formats::util::fmt::size(body_len));
    if let Some(info) = layout_info {
        body_node = body_node.lazy(body_expand, (input, body, Arc::new(info)));
    }
    cx.emit(body_node);
    Ok(())
}

fn emit_all(cx: &Cx, nodes: Vec<Node>) {
    for n in nodes {
        cx.emit(n);
    }
}

/// What the body of a record batch holds.
#[derive(Debug)]
struct BatchInfo {
    slots: Vec<Slot>,
    /// (offset, length) of each buffer within the body.
    buffers: Vec<(u64, u64)>,
    /// (length, null count) of each field node.
    nodes: Vec<(i64, i64)>,
    codec: Option<u8>,
}

/// The fields of a RecordBatch table, and the buffer map of its body.
fn record_batch(buf: &Buf, batch: &Table, fields: &[Field], body: Span) -> (Vec<Node>, BatchInfo) {
    let data = &buf.data;
    let mut out = vtable(buf, batch);
    out.extend(
        buf.scalar(
            batch,
            0,
            "Length",
            8,
            int(batch.i64(data, 0).unwrap_or(0), 64),
        )
        .map(|n| n.summary("rows")),
    );
    let variadic: Vec<i64> = batch
        .vector(data, 4, 8)
        .map(|(n, start)| {
            (0..n.min(1 << 16))
                .filter_map(|j| u64_le(data, start.saturating_add(j.saturating_mul(8))))
                .map(u64::cast_signed)
                .collect()
        })
        .unwrap_or_default();
    let (names, slots) = layout(fields, &variadic);
    let mut node_values = Vec::new();
    if let Some((n, start)) = batch.vector(data, 1, 16) {
        let nodes: Vec<Node> = (0..n.min(1 << 16))
            .map(|i| {
                let at = start.saturating_add(i.saturating_mul(16));
                let len = u64_le(data, at).unwrap_or(0).cast_signed();
                let nulls = u64_le(data, at.saturating_add(8))
                    .unwrap_or(0)
                    .cast_signed();
                node_values.push((len, nulls));
                Node::new(
                    names
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| format!("Field node {i}")),
                )
                .span(buf.at(at, 16))
                .summary(format!("{len} values, {nulls} nulls"))
                .lazy(
                    crate::formats::util::arcutil::push_nodes,
                    Arc::new(vec![
                        Node::new("Length").span(buf.at(at, 8)).value(int(len, 64)),
                        Node::new("Null count")
                            .span(buf.at(at.saturating_add(8), 8))
                            .value(int(nulls, 64)),
                    ]),
                )
            })
            .collect();
        let mut node = group("Field nodes", nodes)
            .span(buf.at(
                start.saturating_sub(4),
                n.saturating_mul(16).saturating_add(4),
            ))
            .summary(format!("{n}"));
        if !fields.is_empty() && n != names.len() {
            node = node.diag(Diagnostic::warning(format!(
                "the schema has {} field nodes",
                names.len()
            )));
        }
        out.push(node);
    }
    let mut buffers = Vec::new();
    if let Some((n, start)) = batch.vector(data, 2, 16) {
        let nodes: Vec<Node> = (0..n.min(1 << 16))
            .map(|i| {
                let at = start.saturating_add(i.saturating_mul(16));
                let off = u64_le(data, at).unwrap_or(0);
                let len = u64_le(data, at.saturating_add(8)).unwrap_or(0);
                buffers.push((off, len));
                let name = slots.get(i).map_or_else(
                    || format!("Buffer {i}"),
                    |s| format!("{}: {}", s.path, s.label),
                );
                Node::new(name)
                    .span(buf.at(at, 16))
                    .value(Value::UInt {
                        value: off,
                        bits: 64,
                        radix: Radix::Hex,
                    })
                    .summary(format!("{len} bytes"))
                    .target(body.sub(off, len))
                    .lazy(
                        crate::formats::util::arcutil::push_nodes,
                        Arc::new(vec![
                            Node::new("Offset")
                                .span(buf.at(at, 8))
                                .value(int(off.cast_signed(), 64)),
                            Node::new("Length")
                                .span(buf.at(at.saturating_add(8), 8))
                                .value(int(len.cast_signed(), 64)),
                        ]),
                    )
            })
            .collect();
        let mut node = group("Buffers", nodes)
            .span(buf.at(
                start.saturating_sub(4),
                n.saturating_mul(16).saturating_add(4),
            ))
            .summary(format!("{n}"));
        if !fields.is_empty() && n != slots.len() {
            node = node.diag(Diagnostic::warning(format!(
                "the schema has {} buffers",
                slots.len()
            )));
        }
        out.push(node);
    }
    let mut codec = None;
    if let Some(c) = batch.table(data, 3) {
        let raw = c.u8(data, 0).unwrap_or(0);
        codec = Some(raw);
        let mut nodes = vtable(buf, &c);
        nodes.extend(buf.scalar(&c, 0, "Codec", 1, enumv(raw.into(), 8, CODECS)));
        nodes.extend(buf.scalar(
            &c,
            1,
            "Method",
            1,
            enumv(c.u8(data, 1).unwrap_or(0).into(), 8, &[(0, "per buffer")]),
        ));
        out.push(
            group("Compression", nodes).span(tspan(buf, &c)).summary(
                lookup(CODECS, raw.into())
                    .unwrap_or("unknown codec")
                    .to_owned(),
            ),
        );
    }
    if let Some((n, start)) = batch.vector(data, 4, 8) {
        out.push(
            Node::new("Variadic buffer counts")
                .span(buf.at(start, n.saturating_mul(8)))
                .value(Value::Text(
                    variadic
                        .iter()
                        .map(i64::to_string)
                        .collect::<Vec<_>>()
                        .join(", "),
                )),
        );
    }
    (
        out,
        BatchInfo {
            slots,
            buffers,
            nodes: node_values,
            codec,
        },
    )
}

// ---------------------------------------------------------------------------
// Bodies: the buffers themselves

async fn body_expand(cx: Cx, (input, body, info): (Input, Span, Arc<BatchInfo>)) -> Result<()> {
    let mut order: Vec<usize> = (0..info.buffers.len()).collect();
    order.sort_by_key(|&i| info.buffers.get(i).map_or(0, |b| b.0));
    let mut cursor = 0u64;
    for i in order {
        let Some(&(off, len)) = info.buffers.get(i) else {
            continue;
        };
        if off > cursor {
            let pad = body.sub(cursor, off.saturating_sub(cursor));
            let bytes = cx.read_avail(pad.sub(0, 64)).await?;
            cx.push(Node::new("Padding").span(pad).value(Value::Bytes(bytes)))
                .await;
        }
        cursor = cursor.max(off.saturating_add(len));
        let span = body.sub(off, len);
        let name = info.slots.get(i).map_or_else(
            || format!("Buffer {i}"),
            |s| format!("{}: {}", s.path, s.label),
        );
        let mut node = Node::new(name)
            .span(span)
            .summary(crate::formats::util::fmt::size(len));
        if len > 0 {
            node = node.lazy(buffer_expand, (input, body, info.clone(), i));
        }
        cx.push(node).await;
    }
    if body.len > cursor {
        let pad = body.sub(cursor, body.len.saturating_sub(cursor));
        let bytes = cx.read_avail(pad.sub(0, 64)).await?;
        cx.push(Node::new("Padding").span(pad).value(Value::Bytes(bytes)))
            .await;
    }
    Ok(())
}

/// The bytes of buffer `i`, decompressed if the batch is compressed.
async fn content(cx: &Cx, body: Span, info: &BatchInfo, i: usize) -> Result<Span> {
    let &(off, len) = info
        .buffers
        .get(i)
        .ok_or_else(|| Diagnostic::malformed("no such buffer"))?;
    let span = body.sub(off, len);
    let Some(codec) = info.codec else {
        return Ok(span);
    };
    if span.len < 8 {
        return Ok(span);
    }
    let head = cx.read(span.sub(0, 8)).await?;
    let raw = u64_le(&head, 0).unwrap_or(0).cast_signed();
    if raw < 0 {
        return Ok(span.tail(8));
    }
    let codec = match codec {
        0 => Codec::Lz4Frame,
        1 => Codec::Zstd,
        c => return Err(Diagnostic::unsupported(format!("compression codec {c}")).at(span)),
    };
    let decoded =
        crate::codec::decode_span(cx, span.tail(8), &codec, Some(raw.cast_unsigned())).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    Ok(decoded.span)
}

async fn buffer_expand(
    cx: Cx,
    (input, body, info, i): (Input, Span, Arc<BatchInfo>, usize),
) -> Result<()> {
    let &(off, len) = info.buffers.get(i).unwrap_or(&(0, 0));
    let span = body.sub(off, len);
    if let Some(codec) = info.codec {
        let head = cx.read(span.sub(0, 8)).await?;
        let raw = u64_le(&head, 0).unwrap_or(0).cast_signed();
        let mut node = Node::new("Uncompressed length")
            .span(span.sub(0, 8))
            .value(int(raw, 64));
        if raw < 0 {
            node = node.summary("stored uncompressed");
        }
        cx.emit(node);
        if raw >= 0 {
            cx.emit(
                Node::new(if codec == 0 {
                    "LZ4 frame"
                } else {
                    "Zstandard frame"
                })
                .span(span.tail(8))
                .summary(format!(
                    "{} → {}",
                    crate::formats::util::fmt::size(span.len.saturating_sub(8)),
                    crate::formats::util::fmt::size(raw.cast_unsigned())
                ))
                .lazy(values, (input, body, info.clone(), i)),
            );
            return Ok(());
        }
    }
    values(cx, (input, body, info, i)).await
}

/// Bits of a validity or boolean buffer, as text.
fn bits(data: &[u8], n: u64) -> String {
    (0..n.min(256))
        .map(|i| {
            let byte = data.get(to_usize(i / 8)).copied().unwrap_or(0);
            if byte >> (i % 8) & 1 != 0 { '1' } else { '0' }
        })
        .collect::<String>()
        + if n > 256 { "…" } else { "" }
}

/// The width in bytes of one value of a fixed-width field.
fn width(f: &Field) -> Option<u64> {
    Some(match f.kind {
        2 | 9 => u64::try_from(f.bits.max(8) / 8).ok()?,
        3 => match f.precision {
            0 => 2,
            1 => 4,
            _ => 8,
        },
        7 => u64::try_from(f.bits.max(8) / 8).ok()?,
        8 => {
            if f.unit == 0 {
                4
            } else {
                8
            }
        }
        10 | 18 => 8,
        11 => match f.unit {
            0 => 4,
            1 => 8,
            _ => 16,
        },
        15 => u64::try_from(f.width).ok()?,
        _ => return None,
    })
}

/// One value of a fixed-width field.
fn value(f: &Field, c: &[u8]) -> Value {
    let le = |n: usize| crate::formats::util::datakit::le_uint(c.get(..n).unwrap_or_default());
    match (f.kind, c.len()) {
        (2 | 9, n @ (1 | 2 | 4 | 8)) => {
            let raw = le(n);
            let bits = u32::try_from(n.saturating_mul(8)).unwrap_or(64);
            if f.signed || f.kind == 9 {
                let shift = 64u32.saturating_sub(bits);
                int(
                    raw.wrapping_shl(shift).cast_signed().wrapping_shr(shift),
                    u8::try_from(bits).unwrap_or(64),
                )
            } else {
                Value::UInt {
                    value: raw,
                    bits: u8::try_from(bits).unwrap_or(64),
                    radix: Radix::Dec,
                }
            }
        }
        (3, 4) => Value::Float(f32::from_le_bytes(c.try_into().unwrap_or([0; 4])).into()),
        (3, 8) => Value::Float(f64::from_le_bytes(c.try_into().unwrap_or([0; 8]))),
        (8, 4) => int(le(4).cast_signed().wrapping_shl(32).wrapping_shr(32), 32),
        (10, 8) if f.unit == 0 => Value::Timestamp {
            unix_seconds: le(8).cast_signed(),
        },
        (10 | 18 | 8, 8) => int(le(8).cast_signed(), 64),
        _ => Value::Bytes(c.to_vec()),
    }
}

async fn values(
    cx: Cx,
    (_input, body, info, i): (Input, Span, Arc<BatchInfo>, usize),
) -> Result<()> {
    let Some(slot) = info.slots.get(i) else {
        return Ok(());
    };
    let span = content(&cx, body, &info, i).await?;
    let (rows, nulls) = info.nodes.get(slot.node).copied().unwrap_or((0, 0));
    let rows = u64::try_from(rows).unwrap_or(0);
    let large = matches!(slot.field.kind, 19 | 20 | 21 | 26);
    match slot.label {
        "validity" | "data" if slot.label == "validity" || slot.field.kind == 6 => {
            let data = cx.read_avail(span.sub(0, rows.div_ceil(8).min(64))).await?;
            cx.emit(
                Node::new(if slot.label == "validity" {
                    "Validity"
                } else {
                    "Values"
                })
                .span(span)
                .value(Value::Text(bits(&data, rows)))
                .summary(if slot.label == "validity" {
                    format!("{nulls} nulls")
                } else {
                    "one bit per value".to_owned()
                }),
            );
        }
        "offsets" | "sizes" => {
            let w = if large { 8 } else { 4 };
            let n = if slot.label == "offsets" {
                rows.saturating_add(1)
            } else {
                rows
            };
            elements(&cx, span, w, n, |c| {
                int(signed(c), if c.len() == 4 { 32 } else { 64 })
            })
            .await?;
        }
        "type ids" => {
            elements(&cx, span, 1, rows, |c| {
                int(i64::from(c.first().copied().unwrap_or(0).cast_signed()), 8)
            })
            .await?;
        }
        "data" if matches!(slot.field.kind, 4 | 5 | 19 | 20) => {
            let Some(oi) = slot.offsets else {
                return Ok(());
            };
            let offsets = content(&cx, body, &info, oi).await?;
            strings(
                &cx,
                span,
                offsets,
                rows,
                large,
                slot.field.kind == 5 || slot.field.kind == 20,
            )
            .await?;
        }
        "data" | "indices" => match width(&slot.field) {
            Some(w) => {
                let field = slot.field.clone();
                elements(&cx, span, w, rows, move |c| value(&field, c)).await?;
            }
            None => cx.emit(Node::new("Values").span(span)),
        },
        _ => cx.emit(Node::new("Values").span(span)),
    }
    Ok(())
}

/// A little-endian signed integer of 4 or 8 bytes.
fn signed(c: &[u8]) -> i64 {
    let raw = crate::formats::util::datakit::le_uint(c).cast_signed();
    if c.len() == 4 {
        raw.wrapping_shl(32).wrapping_shr(32)
    } else {
        raw
    }
}

/// Fixed-width values, one node each.
async fn elements(cx: &Cx, span: Span, w: u64, n: u64, f: impl Fn(&[u8]) -> Value) -> Result<()> {
    let n = n.min(span.len.checked_div(w).unwrap_or(0));
    let per = WINDOW.checked_div(w).unwrap_or(1).max(1);
    let mut i = 0u64;
    while i < n {
        let k = per.min(n.saturating_sub(i));
        let window = span.sub(i.saturating_mul(w), k.saturating_mul(w));
        let data = cx.read(window).await?;
        for (j, c) in data.chunks_exact(to_usize(w)).enumerate() {
            let index = i.saturating_add(to_u64(j));
            cx.push(
                Node::new(format!("[{index}]"))
                    .span(window.sub(to_u64(j).saturating_mul(w), w))
                    .value(f(c)),
            )
            .await;
        }
        i = i.saturating_add(k);
    }
    let used = n.saturating_mul(w);
    if span.len > used {
        cx.push(Node::new("Unused").span(span.tail(used))).await;
    }
    Ok(())
}

/// Strings (or binary values) cut from a data buffer by its offsets.
async fn strings(
    cx: &Cx,
    data: Span,
    offsets: Span,
    n: u64,
    large: bool,
    utf8: bool,
) -> Result<()> {
    let w = if large { 8u64 } else { 4 };
    let len = n.saturating_add(1).saturating_mul(w).min(offsets.len);
    if len > MAX_OFFSETS {
        cx.emit(Node::new("Values").span(data).summary("too many to cut"));
        return Ok(());
    }
    let raw = cx.read(offsets.sub(0, len)).await?;
    let offs: Vec<u64> = raw
        .chunks_exact(to_usize(w))
        .map(crate::formats::util::datakit::le_uint)
        .collect();
    let mut end_max = 0u64;
    for (i, pair) in offs.windows(2).enumerate() {
        let (Some(&a), Some(&b)) = (pair.first(), pair.get(1)) else {
            continue;
        };
        let span = data.sub(a, b.saturating_sub(a));
        end_max = end_max.max(b);
        let bytes = cx.read_avail(span.sub(0, 4096)).await?;
        let value = if utf8 {
            Value::Text(String::from_utf8_lossy(&bytes).into_owned())
        } else {
            Value::Bytes(bytes)
        };
        cx.push(Node::new(format!("[{i}]")).span(span).value(value))
            .await;
    }
    if data.len > end_max {
        cx.push(Node::new("Unused").span(data.tail(end_max))).await;
    }
    Ok(())
}
