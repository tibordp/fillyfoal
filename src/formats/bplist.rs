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
use crate::formats::datakit::{cf_time, clip, uint};
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

fn be_uint(bytes: &[u8]) -> u64 {
    bytes.iter().fold(0u64, |acc, &b| {
        acc.checked_shl(8).unwrap_or(0) | u64::from(b)
    })
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
    let pl: Pl = Arc::new(Plist {
        input,
        offset_size: trailer.offset_size,
        ref_size: trailer.ref_size,
        objects: listed,
        table: trailer.table,
    });

    let root = if sizes_ok {
        Some(object(&cx, &pl, trailer.top).await)
    } else {
        None
    };
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
            Ok(o) => object_node(pl, name, child, &o, &walk.path).desc(format!("object #{child}")),
            Err(e) => Node::new(name).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn objects(cx: Cx, pl: Pl) -> Result<()> {
    cx.set_count(Count::Exact(pl.objects));
    for index in 0..pl.objects {
        let node = match object(&cx, &pl, index).await {
            // A flat listing: containers are walked from the root instead.
            Ok(o) => {
                let node = Node::new(format!("#{index}"))
                    .span(o.span)
                    .summary(o.summary);
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

async fn offset_table(cx: Cx, pl: Pl) -> Result<()> {
    cx.set_count(Count::Exact(pl.objects));
    let size = u64::from(pl.offset_size);
    for index in 0..pl.objects {
        let at = pl.table.saturating_add(index.saturating_mul(size));
        let span = pl.input.span.sub_exact(at, size)?;
        let offset = be_uint(&cx.read(span).await?);
        let mut node = Node::new(format!("#{index}"))
            .span(span)
            .value(crate::formats::datakit::hex(offset, 64));
        if offset < pl.input.span.len {
            node = node.target(pl.input.span.sub(offset, 1));
        } else {
            node = node.diag(Diagnostic::malformed("offset beyond the end of the file"));
        }
        cx.push(node).await;
    }
    Ok(())
}
