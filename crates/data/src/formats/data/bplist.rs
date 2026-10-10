//! Apple binary property lists (`bplist00`), including NSKeyedArchiver
//! archives, which are ordinary binary plists with a conventional layout.
//!
//! A 32-byte trailer at the end gives the offset table, which maps object
//! numbers to file offsets. Containers (arrays, sets, dictionaries) refer to
//! their members by object number, so the object graph is walked lazily from
//! the top object; references back to an ancestor are reported as cycles.

use std::sync::Arc;

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::datakit::be_uint;
use crate::formats::util::datakit::{cf_time, uint};
use crate::formats::util::fmt::clip;
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::Value;

const BE: Endian = Endian::Big;
/// Deepest container nesting that is walked.
const MAX_DEPTH: usize = 64;
/// Longest string decoded into a value.
const MAX_TEXT: u64 = 0x4000;

pub static FORMAT: Format = Format {
    name: "bplist",
    title: "Apple binary property list",
    extensions: &["plist", "bplist", "nib", "strings"],
    mime: "application/x-bplist",
    probe: Probe::Magic(&[(0, b"bplist00")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Trailer {
        _unused: bytes[5] "Unused",
        sort_version: u8 "Sort version",
        offset_size: u8 "Offset size" .desc("Bytes per offset table entry"),
        ref_size: u8 "Object reference size" .desc("Bytes per object reference in containers"),
        objects: u64 "Number of objects",
        top: u64 "Top object" .desc("Object number of the root"),
        table: u64 "Offset table offset" .hex(),
    }
}

record! {
    pub struct Header {
        magic: ascii[6] "Magic",
        version: ascii[2] "Version",
    }
}

struct Plist {
    input: Input,
    offset_size: u8,
    ref_size: u8,
    objects: u64,
    table: u64,
    /// NSKeyedArchiver: the `$objects` array (reference list start, count),
    /// which UIDs index.
    archive: Option<(u64, u64)>,
}

type Pl = Arc<Plist>;

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Scalar,
    Array,
    Set,
    Dict,
}

/// One decoded object header (and, for scalars, its value).
struct Obj {
    kind: Kind,
    span: Span,
    value: Option<Value>,
    summary: String,
    /// Members of a container.
    count: u64,
    /// Start of the reference list of a container (relative to the file).
    refs: u64,
    /// Data that is itself a binary plist.
    nested: bool,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Header::node("Header", file.sub(0, Header::SIZE), BE));
    let trailer_span = file.tail(file.len.saturating_sub(Trailer::SIZE));
    if file.len < Header::SIZE.saturating_add(Trailer::SIZE) {
        return Err(Diagnostic::truncated(trailer_span, trailer_span.len));
    }
    let trailer = parse(&cx, trailer_span, BE, &(), Trailer::layout).await?;
    let mut trailer_node = Trailer::node("Trailer", trailer_span, BE);
    let sizes_ok = (1..=8).contains(&trailer.offset_size) && (1..=8).contains(&trailer.ref_size);
    if !sizes_ok {
        trailer_node = trailer_node.diag(Diagnostic::malformed(
            "offset and reference sizes must be between 1 and 8",
        ));
    }
    let table_len = trailer.objects.saturating_mul(trailer.offset_size.into());
    let table_span = file.sub(trailer.table, table_len);
    // Only objects whose offsets exist can be listed.
    let listed = table_span
        .len
        .checked_div(trailer.offset_size.into())
        .unwrap_or(0);
    let mut plist = Plist {
        input,
        offset_size: trailer.offset_size,
        ref_size: trailer.ref_size,
        objects: listed,
        table: trailer.table,
        archive: None,
    };
    let root = if sizes_ok {
        Some(object(&cx, &plist, trailer.top).await)
    } else {
        None
    };
    if let Some(Ok(obj)) = &root
        && obj.kind == Kind::Dict
        && let Some(index) = key_value(&cx, &plist, obj, "$objects").await
        && let Ok(array) = object(&cx, &plist, index).await
        && array.kind == Kind::Array
    {
        plist.archive = Some((array.refs, array.count));
    }
    let pl: Pl = Arc::new(plist);
    match &root {
        Some(Ok(obj)) => {
            let mut summary = format!("binary plist, {} objects", trailer.objects);
            if obj.kind == Kind::Dict && has_key(&cx, &pl, obj, "$archiver").await {
                summary = format!("NSKeyedArchiver archive, {} objects", trailer.objects);
            }
            cx.annotate(format!("{summary}, root {}", obj.summary));
            cx.emit(object_node(&pl, "Root".into(), trailer.top, obj, &[]));
        }
        Some(Err(e)) => cx.emit(Node::new("Root").diag(e.clone())),
        None => {}
    }
    if sizes_ok {
        cx.emit(
            Node::new("Objects")
                .span(file.sub(Header::SIZE, trailer.table.saturating_sub(Header::SIZE)))
                .summary(format!("{} objects", trailer.objects))
                .lazy(objects, pl.clone()),
        );
        let mut table = Node::new("Offset table")
            .span(table_span)
            .summary(format!("{} entries", trailer.objects))
            .lazy(offset_table, pl);
        if table_span.len < table_len {
            table = table.diag(Diagnostic::truncated(
                Span::new(file.source, table_span.offset, table_len),
                table_span.len,
            ));
        }
        cx.emit(table);
    }
    cx.emit(trailer_node);
    Ok(())
}

/// The file offset of object `index`.
async fn offset_of(cx: &Cx, pl: &Plist, index: u64) -> Result<u64> {
    if index >= pl.objects {
        return Err(Diagnostic::malformed(format!(
            "object {index} is beyond the {} objects",
            pl.objects
        )));
    }
    let size = u64::from(pl.offset_size);
    let at = pl.table.saturating_add(index.saturating_mul(size));
    let bytes = cx.read(pl.input.span.sub_exact(at, size)?).await?;
    Ok(be_uint(&bytes))
}

/// The object number stored in the reference at `at`.
async fn reference(cx: &Cx, pl: &Plist, at: u64) -> Result<u64> {
    let span = pl.input.span.sub_exact(at, pl.ref_size.into())?;
    Ok(be_uint(&cx.read(span).await?))
}

async fn object(cx: &Cx, pl: &Plist, index: u64) -> Result<Obj> {
    let file = pl.input.span;
    let offset = offset_of(cx, pl, index).await?;
    let head = cx.read(file.sub_exact(offset, 1)?).await?;
    let marker = head.first().copied().unwrap_or(0);
    let (hi, lo) = (marker >> 4, marker & 0x0f);

    // Variable-length objects store a count in the low nibble, or 0xf and an
    // integer object with the real count.
    let (count, header) = if lo == 0x0f && matches!(hi, 0x4 | 0x5 | 0x6 | 0xa | 0xb | 0xc | 0xd) {
        let int = cx
            .read(file.sub_exact(offset.saturating_add(1), 1)?)
            .await?;
        let int = int.first().copied().unwrap_or(0);
        if int >> 4 != 1 || int & 0x0f > 3 {
            return Err(
                Diagnostic::malformed("bad count after object marker").at(file.sub(offset, 2))
            );
        }
        let size = 1u64 << (int & 0x0f);
        let bytes = cx
            .read(file.sub_exact(offset.saturating_add(2), size)?)
            .await?;
        (be_uint(&bytes), size.saturating_add(2))
    } else {
        (u64::from(lo), 1)
    };
    let body = offset.saturating_add(header);
    let span_of = |len: u64| file.sub(offset, header.saturating_add(len));
    let scalar = |span: Span, value: Value, summary: String| Obj {
        kind: Kind::Scalar,
        span,
        value: Some(value),
        summary,
        count: 0,
        refs: 0,
        nested: false,
    };
    let refs = u64::from(pl.ref_size);
    // Reject reference lists that cannot fit before walking them.
    let fits = |n: u64| file.sub_exact(body, n.saturating_mul(refs)).map(|_| ());
    let container = |kind: Kind, n: u64, summary: String| Obj {
        kind,
        span: span_of(n.saturating_mul(refs)),
        value: None,
        summary,
        count: count.min(u64::MAX / 2),
        refs: body,
        nested: false,
    };

    Ok(match (hi, lo) {
        (0x0, 0x0) => scalar(span_of(0), Value::Text("null".into()), "null".into()),
        (0x0, 0x8) => scalar(span_of(0), Value::Bool(false), "boolean".into()),
        (0x0, 0x9) => scalar(span_of(0), Value::Bool(true), "boolean".into()),
        (0x0, 0xf) => scalar(span_of(0), Value::Text("fill".into()), "fill".into()),
        (0x1, n) if n <= 4 => {
            let size = 1u64 << n;
            let bytes = cx.read(file.sub_exact(body, size)?).await?;
            let value = match size {
                8 => Value::Int {
                    value: be_uint(&bytes) as i64,
                    bits: 64,
                },
                16 => Value::Int {
                    value: be_uint(bytes.get(8..).unwrap_or_default()) as i64,
                    bits: 64,
                },
                _ => uint(
                    be_uint(&bytes),
                    u8::try_from(size.saturating_mul(8)).unwrap_or(64),
                ),
            };
            scalar(span_of(size), value, "integer".into())
        }
        (0x2, n @ (2 | 3)) => {
            let size = 1u64 << n;
            let bytes = cx.read(file.sub_exact(body, size)?).await?;
            scalar(span_of(size), Value::Float(real(&bytes)), "real".into())
        }
        (0x3, 0x3) => {
            let bytes = cx.read(file.sub_exact(body, 8)?).await?;
            let seconds = real(&bytes);
            scalar(
                span_of(8),
                cf_time(seconds),
                format!("date ({seconds} s since 2001)"),
            )
        }
        (0x4, _) => {
            let data = file.sub_exact(body, count)?;
            let head = cx.read_avail(data.sub(0, 32)).await?;
            Obj {
                nested: head.starts_with(b"bplist00"),
                count,
                refs: body,
                ..scalar(
                    span_of(count),
                    Value::Bytes(head),
                    format!("data, {count} bytes"),
                )
            }
        }
        (0x5, _) => {
            let data = file.sub_exact(body, count)?;
            let bytes = cx.read(data.sub(0, MAX_TEXT)).await?;
            let text: String = bytes.iter().map(|&b| char::from(b)).collect();
            scalar(span_of(count), Value::Text(text), "ASCII string".into())
        }
        (0x6, _) => {
            let len = count.saturating_mul(2);
            let data = file.sub_exact(body, len)?;
            let bytes = cx.read(data.sub(0, MAX_TEXT)).await?;
            let text = crate::text::utf16(&bytes, BE);
            scalar(span_of(len), Value::Text(text), "UTF-16 string".into())
        }
        (0x8, n) => {
            let size = u64::from(n).saturating_add(1);
            let bytes = cx.read(file.sub_exact(body, size)?).await?;
            scalar(span_of(size), uint(be_uint(&bytes), 64), "UID".into())
        }
        (0xa, _) => {
            fits(count)?;
            container(Kind::Array, count, format!("array ({count})"))
        }
        (0xc, _) => {
            fits(count)?;
            container(Kind::Set, count, format!("set ({count})"))
        }
        (0xd, _) => {
            fits(count.saturating_mul(2))?;
            container(
                Kind::Dict,
                count.saturating_mul(2),
                format!("dict ({count})"),
            )
        }
        _ => {
            return Err(
                Diagnostic::unsupported(format!("object marker {marker:#04x}"))
                    .at(file.sub(offset, 1)),
            );
        }
    })
}

fn real(bytes: &[u8]) -> f64 {
    match bytes.len() {
        4 => f64::from(f32::from_bits(be_uint(bytes) as u32)),
        _ => f64::from_bits(be_uint(bytes)),
    }
}

/// Whether a dictionary has a string key `wanted` (among its first keys).
async fn has_key(cx: &Cx, pl: &Plist, dict: &Obj, wanted: &str) -> bool {
    for i in 0..dict.count.min(16) {
        let at = dict
            .refs
            .saturating_add(i.saturating_mul(pl.ref_size.into()));
        let Ok(key) = reference(cx, pl, at).await else {
            return false;
        };
        if let Ok(obj) = object(cx, pl, key).await
            && obj.value == Some(Value::Text(wanted.to_owned()))
        {
            return true;
        }
    }
    false
}

/// The object number of the value under string key `wanted` (among the
/// first keys).
async fn key_value(cx: &Cx, pl: &Plist, dict: &Obj, wanted: &str) -> Option<u64> {
    let refs = u64::from(pl.ref_size);
    for i in 0..dict.count.min(64) {
        let at = dict.refs.saturating_add(i.saturating_mul(refs));
        let key = reference(cx, pl, at).await.ok()?;
        if let Ok(obj) = object(cx, pl, key).await
            && obj.value == Some(Value::Text(wanted.to_owned()))
        {
            let value_at = at.saturating_add(dict.count.saturating_mul(refs));
            return reference(cx, pl, value_at).await.ok();
        }
    }
    None
}

/// What an NSKeyedArchiver UID refers to: the `$objects` entry's string,
/// or the class name of an archived object.
async fn uid_summary(cx: &Cx, pl: &Plist, uid: u64) -> Option<String> {
    let (refs, count) = pl.archive?;
    if uid >= count {
        return Some(format!("$objects[{uid}] (out of range)"));
    }
    let size = u64::from(pl.ref_size);
    let index = reference(cx, pl, refs.saturating_add(uid.saturating_mul(size)))
        .await
        .ok()?;
    let obj = object(cx, pl, index).await.ok()?;
    let what = match (&obj.value, obj.kind) {
        (Some(Value::Text(t)), _) if t == "$null" => "$null".to_owned(),
        (Some(Value::Text(t)), _) => format!("\"{}\"", clip(t, 60)),
        (Some(Value::UInt { value, .. }), _) => format!("{} {value}", obj.summary),
        (Some(Value::Int { value, .. }), _) => format!("{} {value}", obj.summary),
        (Some(Value::Float(f)), _) => format!("{} {f}", obj.summary),
        (Some(Value::Bool(b)), _) => b.to_string(),
        (None, Kind::Dict) => match class_name(cx, pl, &obj).await {
            Some(c) => format!("<{c}>"),
            None => match own_class_name(cx, pl, &obj).await {
                Some(c) => format!("class {c}"),
                None => obj.summary.clone(),
            },
        },
        _ => obj.summary.clone(),
    };
    Some(format!("$objects[{uid}]: {what}"))
}

/// The `$classname` of a class description dictionary.
async fn own_class_name(cx: &Cx, pl: &Plist, dict: &Obj) -> Option<String> {
    let name = key_value(cx, pl, dict, "$classname").await?;
    match object(cx, pl, name).await.ok()?.value? {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

/// The `$classname` of an archived object's `$class`.
async fn class_name(cx: &Cx, pl: &Plist, dict: &Obj) -> Option<String> {
    let class_ref = key_value(cx, pl, dict, "$class").await?;
    let uid = match object(cx, pl, class_ref).await.ok()?.value? {
        Value::UInt { value, .. } => value,
        _ => return None,
    };
    let (refs, count) = pl.archive?;
    if uid >= count {
        return None;
    }
    let size = u64::from(pl.ref_size);
    let index = reference(cx, pl, refs.saturating_add(uid.saturating_mul(size)))
        .await
        .ok()?;
    let class = object(cx, pl, index).await.ok()?;
    if class.kind != Kind::Dict {
        return None;
    }
    let name = key_value(cx, pl, &class, "$classname").await?;
    match object(cx, pl, name).await.ok()?.value? {
        Value::Text(t) => Some(t),
        _ => None,
    }
}

#[derive(Clone)]
struct Walk {
    pl: Pl,
    index: u64,
    /// Object numbers of this container and its ancestors.
    path: Vec<u64>,
}

fn object_node(pl: &Pl, name: String, index: u64, obj: &Obj, path: &[u64]) -> Node {
    let mut node = Node::new(name).span(obj.span).summary(obj.summary.clone());
    if let Some(v) = &obj.value {
        node = node.value(v.clone());
    }
    if obj.nested {
        let body = pl.input.span.sub(obj.refs, obj.count);
        return embedded(node.name.clone(), pl.input.nested(body))
            .summary(obj.summary.clone())
            .value(node.value.unwrap_or(Value::Bool(true)));
    }
    if obj.kind == Kind::Scalar {
        return node;
    }
    if path.contains(&index) {
        return node.diag(Diagnostic::malformed(format!(
            "object {index} contains itself"
        )));
    }
    if path.len() >= MAX_DEPTH {
        return node.diag(Diagnostic::limit(format!(
            "containers nested deeper than {MAX_DEPTH}"
        )));
    }
    let mut path = path.to_vec();
    path.push(index);
    node.lazy(
        crate::expander!(self::members: Walk),
        Walk {
            pl: pl.clone(),
            index,
            path,
        },
    )
}

async fn members(cx: Cx, walk: Walk) -> Result<()> {
    let pl = &walk.pl;
    let obj = object(&cx, pl, walk.index).await?;
    cx.set_count(Count::Exact(obj.count));
    let refs = u64::from(pl.ref_size);
    for i in 0..obj.count {
        let at = obj.refs.saturating_add(i.saturating_mul(refs));
        let value_at = match obj.kind {
            Kind::Dict => at.saturating_add(obj.count.saturating_mul(refs)),
            _ => at,
        };
        let child = reference(&cx, pl, value_at).await?;
        let name = match obj.kind {
            Kind::Dict => {
                let key = reference(&cx, pl, at).await?;
                match object(&cx, pl, key).await {
                    Ok(Obj {
                        value: Some(Value::Text(t)),
                        ..
                    }) => clip(&t, 80),
                    _ => format!("key #{key}"),
                }
            }
            _ => format!("[{i}]"),
        };
        let node = match object(&cx, pl, child).await {
            Ok(o) => {
                let uid = uid_of(&o);
                let mut node =
                    object_node(pl, name, child, &o, &walk.path).desc(format!("object #{child}"));
                if let Some(uid) = uid
                    && let Some(s) = uid_summary(&cx, pl, uid).await
                {
                    node = node.summary(s);
                } else if o.kind == Kind::Dict && pl.archive.is_some() {
                    if let Some(c) = class_name(&cx, pl, &o).await {
                        node = node.summary(format!("<{c}>, {}", o.summary));
                    } else if let Some(c) = own_class_name(&cx, pl, &o).await {
                        node = node.summary(format!("class {c}, {}", o.summary));
                    }
                }
                node
            }
            Err(e) => Node::new(name).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// The value of a UID object.
fn uid_of(o: &Obj) -> Option<u64> {
    match (&o.value, o.summary.as_str()) {
        (Some(Value::UInt { value, .. }), "UID") => Some(*value),
        _ => None,
    }
}

async fn objects(cx: Cx, pl: Pl) -> Result<()> {
    cx.set_count(Count::Exact(pl.objects));
    for index in 0..pl.objects {
        let node = match object(&cx, &pl, index).await {
            // A flat listing: containers are walked from the root instead.
            Ok(o) => {
                let mut summary = o.summary.clone();
                if let Some(uid) = uid_of(&o)
                    && let Some(s) = uid_summary(&cx, &pl, uid).await
                {
                    summary = format!("UID, {s}");
                }
                let node = Node::new(format!("#{index}"))
                    .span(o.span)
                    .summary(summary)
                    .lazy(object_parts, (pl.clone(), index));
                match o.value {
                    Some(v) => node.value(v),
                    None => node,
                }
            }
            Err(e) => Node::new(format!("#{index}")).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

const MARKER_KIND: &[(u64, &str)] = &[
    (0x0, "singleton (null, false, true, fill)"),
    (0x1, "integer"),
    (0x2, "real"),
    (0x3, "date"),
    (0x4, "data"),
    (0x5, "ASCII string"),
    (0x6, "UTF-16 string"),
    (0x7, "UTF-8 string"),
    (0x8, "UID"),
    (0xa, "array"),
    (0xb, "ordered set"),
    (0xc, "set"),
    (0xd, "dictionary"),
];

/// One object's encoding: the marker byte (type nibble and size nibble),
/// the count integer when the size nibble is 0xf, then the payload or the
/// object references.
async fn object_parts(cx: Cx, (pl, index): (Pl, u64)) -> Result<()> {
    let o = object(&cx, &pl, index).await?;
    let file = pl.input.span;
    let start = o.span.offset.saturating_sub(file.offset);
    let marker = cx.read(file.sub(start, 1)).await?;
    let m = marker.first().copied().unwrap_or(0);
    cx.emit(
        Node::new("Marker")
            .span(file.sub(start, 1))
            .value(crate::formats::util::datakit::hex(u64::from(m), 8))
            .summary(format!(
                "{}, size nibble {}",
                crate::value::lookup(MARKER_KIND, (m >> 4).into()).unwrap_or("reserved"),
                m & 0xf
            )),
    );
    // A size nibble of 0xf is followed by an integer object with the count.
    let (count, body) = if m & 0xf == 0xf && matches!(m >> 4, 0x4..=0x7 | 0xa..=0xd) {
        let int = cx.read(file.sub(start.saturating_add(1), 1)).await?;
        let width = 1u64 << (int.first().copied().unwrap_or(0) & 3);
        let bytes = cx.read(file.sub(start.saturating_add(2), width)).await?;
        (
            be_uint(&bytes),
            start.saturating_add(2).saturating_add(width),
        )
    } else {
        (u64::from(m & 0xf), start.saturating_add(1))
    };
    if body > start.saturating_add(1) {
        let count_span = file.sub(
            start.saturating_add(1),
            body.saturating_sub(start).saturating_sub(1),
        );
        cx.emit(
            Node::new("Count")
                .span(count_span)
                .value(uint(count, 64))
                .desc("An integer object holding the length"),
        );
    }
    let end = o
        .span
        .offset
        .saturating_sub(file.offset)
        .saturating_add(o.span.len);
    match o.kind {
        Kind::Scalar => {
            if end > body {
                let s = file.sub(body, end.saturating_sub(body));
                let node = Node::new("Value").span(s);
                cx.emit(match o.value {
                    Some(v) if !matches!(m >> 4, 0x4) => node.value(v),
                    _ => node,
                });
            }
        }
        _ => {
            let size = u64::from(pl.ref_size);
            let n = o.count;
            let half = if o.kind == Kind::Dict { n / 2 } else { n };
            for i in 0..n.min(1 << 20) {
                let at = o.refs.saturating_add(i.saturating_mul(size));
                let target = reference(&cx, &pl, at).await?;
                let label = if o.kind == Kind::Dict {
                    if i < half {
                        format!("Key {i}")
                    } else {
                        format!("Value {}", i.saturating_sub(half))
                    }
                } else {
                    format!("Member {i}")
                };
                let mut node = Node::new(label)
                    .span(file.sub(at, size))
                    .value(uint(target, 64));
                if let Ok(t) = object(&cx, &pl, target).await {
                    let what = match &t.value {
                        Some(Value::Text(s)) => format!("#{target}: \"{}\"", clip(s, 60)),
                        _ => format!("#{target}: {}", t.summary),
                    };
                    node = node.summary(what).target(t.span);
                }
                cx.push(node).await;
            }
        }
    }
    Ok(())
}

async fn offset_table(cx: Cx, pl: Pl) -> Result<()> {
    cx.set_count(Count::Exact(pl.objects));
    let size = u64::from(pl.offset_size);
    for index in 0..pl.objects {
        let at = pl.table.saturating_add(index.saturating_mul(size));
        let span = pl.input.span.sub_exact(at, size)?;
        let offset = be_uint(&cx.read(span).await?);
        let mut node = Node::new(format!("#{index}"))
            .span(span)
            .value(crate::formats::util::datakit::hex(offset, 64));
        if offset < pl.input.span.len {
            node = node.target(pl.input.span.sub(offset, 1));
        } else {
            node = node.diag(Diagnostic::malformed("offset beyond the end of the file"));
        }
        cx.push(node).await;
    }
    Ok(())
}
