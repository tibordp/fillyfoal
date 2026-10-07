//! Cap'n Proto messages without their schema: the stream framing's segment
//! table, the segments, and the object graph from the root pointer.
//! Structs show their data words (with 32-bit and floating-point readings)
//! and pointer slots; lists show their elements by element size, composite
//! lists as structs, byte lists ending in NUL as text (`Text`) and other
//! byte lists as bytes (`Data`). Far pointers (single and double landing
//! pads) are followed across segments; capabilities show their index.
//!
//! The packed encoding (`capnp-packed`) is unpacked with
//! `Codec::CapnpPacked` and dissected the same way.
//!
//! Identification: a segment table whose segments account for exactly the
//! whole file, and a root pointer that is a struct pointer inside the first
//! segment or a far pointer to an existing segment. Packed messages have no
//! such structure and are only reached by extension or "inspect as".
//! Layouts from the encoding specification; checked against pycapnp (the
//! C++ reference implementation; `tests/data/capnp`).

use std::sync::Arc;

use crate::bytes::{to_u64, u64_le};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::wire::capnp::{
    ELEMENT_SIZES, MAX_SEGMENTS, Pointer, WORD, element_bits, pointer, segment_table, target,
};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Value, lookup};

use super::{hex, plausible_f32, plausible_f64, plural, prefix, printable, short_text, uint, widen};

declare_format!(pub FORMAT = "capnp", "Cap'n Proto message",
    ["bin", "capnp-bin"], "application/x-capnp", Probe::Custom(probe), dissect);
declare_format!(pub PACKED = "capnp-packed", "Cap'n Proto message (packed)",
    ["packed", "bin"], "application/x-capnp-packed", Probe::Never, dissect_packed);

/// Struct and list nesting followed.
const MAX_DEPTH: usize = 64;
/// Segments accepted by the probe.
const PROBE_SEGMENTS: u32 = 64;
/// Characters of a text shown.
const TEXT_MAX: usize = 256;

fn probe(h: &Head<'_>) -> bool {
    let Some(table) = segment_table(h.data) else {
        return false;
    };
    let count = table.segments.len();
    if h.len < 16
        || count > usize::try_from(PROBE_SEGMENTS).unwrap_or(0)
        || table.message_len() != h.len
        || table.segments.iter().any(|&(_, words)| words == 0)
    {
        return false;
    }
    let Some(&(start, words)) = table.segments.first() else {
        return false;
    };
    let Some(word) = usize::try_from(start).ok().and_then(|at| u64_le(h.data, at)) else {
        return false;
    };
    match pointer(word) {
        Pointer::Struct { offset, data, ptrs } => {
            let size = u64::from(data).saturating_add(ptrs.into());
            offset >= 0
                && size > 0
                && target(0, offset).is_some_and(|at| at.saturating_add(size) <= words)
        }
        Pointer::Far {
            offset, segment, ..
        } => table
            .segments
            .get(usize::try_from(segment).unwrap_or(usize::MAX))
            .is_some_and(|&(_, w)| u64::from(offset) < w),
        _ => false,
    }
}

/// The segments of a message: where each starts (in the message's span)
/// and its size in words.
struct Msg {
    span: Span,
    segments: Vec<(u64, u64)>,
}

/// A position in a message: segment and word.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
struct Loc {
    seg: u32,
    word: u64,
}

impl Msg {
    /// The span of `words` words at `loc`, if inside its segment.
    fn words(&self, loc: Loc, words: u64) -> Option<Span> {
        let &(start, size) = self.segments.get(usize::try_from(loc.seg).ok()?)?;
        if loc.word.checked_add(words)? > size {
            return None;
        }
        Some(
            self.span
                .sub(start.checked_add(loc.word.checked_mul(WORD)?)?, words.checked_mul(WORD)?),
        )
    }

    /// The span of `bytes` bytes at `loc`, if inside its segment.
    fn bytes(&self, loc: Loc, bytes: u64) -> Option<Span> {
        let words = bytes.div_ceil(WORD);
        self.words(loc, words).map(|s| Span::new(s.source, s.offset, bytes))
    }

    fn id(loc: Loc) -> u64 {
        (u64::from(loc.seg) << 40) | (loc.word & ((1 << 40) - 1))
    }
}

type M = Arc<Msg>;

async fn read_word(cx: &Cx, msg: &Msg, loc: Loc) -> Result<u64> {
    let span = msg
        .words(loc, 1)
        .ok_or_else(|| Diagnostic::malformed("pointer outside its segment"))?;
    let data = cx.read(span).await?;
    Ok(u64_le(&data, 0).unwrap_or(0))
}

/// What a pointer refers to, after following far pointers.
#[derive(Clone, Copy, Debug)]
enum Object {
    Null,
    Struct { at: Loc, data: u16, ptrs: u16 },
    List { at: Loc, elem: u8, count: u32 },
    Capability(u32),
}

/// Resolves the pointer at `loc`. Returns the object and, for far
/// pointers, a description of the hop.
async fn resolve(cx: &Cx, msg: &Msg, loc: Loc) -> Result<(Object, Option<String>)> {
    let word = read_word(cx, msg, loc).await?;
    match pointer(word) {
        Pointer::Far {
            double,
            offset,
            segment,
        } => {
            let pad = Loc {
                seg: segment,
                word: offset.into(),
            };
            let hop = format!("far pointer to segment {segment} word {offset}");
            if !double {
                let w = read_word(cx, msg, pad).await?;
                return Ok((object(pointer(w), pad)?, Some(hop)));
            }
            // A double landing pad: a far pointer to the content, then a
            // tag describing it.
            let far = read_word(cx, msg, pad).await?;
            let tag_at = Loc {
                seg: segment,
                word: u64::from(offset).saturating_add(1),
            };
            let tag = read_word(cx, msg, tag_at).await?;
            let Pointer::Far {
                double: false,
                offset: content,
                segment: content_seg,
            } = pointer(far)
            else {
                return Err(Diagnostic::malformed("double landing pad without a far pointer"));
            };
            let start = Loc {
                seg: content_seg,
                word: content.into(),
            };
            // The tag's offset is ignored: the content starts at `start`.
            let obj = match pointer(tag) {
                Pointer::Struct { data, ptrs, .. } => Object::Struct {
                    at: start,
                    data,
                    ptrs,
                },
                Pointer::List { elem, count, .. } => Object::List {
                    at: start,
                    elem,
                    count,
                },
                _ => return Err(Diagnostic::malformed("invalid landing pad tag")),
            };
            Ok((obj, Some(format!("{hop} (double)"))))
        }
        p => Ok((object(p, loc)?, None)),
    }
}

/// The object a (non-far) pointer at `loc` refers to.
fn object(p: Pointer, loc: Loc) -> Result<Object> {
    let at = |offset: i32| {
        target(loc.word, offset)
            .map(|word| Loc { seg: loc.seg, word })
            .ok_or_else(|| Diagnostic::malformed("pointer offset out of range"))
    };
    Ok(match p {
        Pointer::Null => Object::Null,
        Pointer::Struct { offset, data, ptrs } => Object::Struct {
            at: at(offset)?,
            data,
            ptrs,
        },
        Pointer::List {
            offset,
            elem,
            count,
        } => Object::List {
            at: at(offset)?,
            elem,
            count,
        },
        Pointer::Capability { index } => Object::Capability(index),
        Pointer::Far { .. } => return Err(Diagnostic::malformed("far pointer in a landing pad")),
        Pointer::Reserved(w) => {
            return Err(Diagnostic::malformed(format!("reserved pointer {w:#018x}")));
        }
    })
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let max = 4u64.saturating_add(u64::from(MAX_SEGMENTS).saturating_mul(4));
    let head = cx.read_avail(file.sub(0, max)).await?;
    let table = segment_table(&head).ok_or_else(|| {
        Diagnostic::malformed("invalid segment table").at(file.sub(0, 8))
    })?;
    let count = to_u64(table.segments.len());
    cx.emit(
        Node::new("Segment table")
            .span(file.sub(0, table.len))
            .summary(plural(count, "segment"))
            .lazy(segment_table_node, (file, table.segments.clone())),
    );
    let total = table.message_len();
    if total > file.len {
        cx.diag(Diagnostic::truncated(file.sub(0, total), file.len));
    } else if total < file.len {
        cx.diag(Diagnostic::note(format!(
            "{:#x} bytes follow the message",
            file.len.saturating_sub(total)
        )));
    }
    let msg = Arc::new(Msg {
        span: file,
        segments: table.segments,
    });
    let root = Loc { seg: 0, word: 0 };
    let node = pointer_node(&cx, &msg, "Root", root, &Path::new()).await?;
    let summary = node.summary.clone().unwrap_or_default();
    cx.emit(node);
    cx.annotate(format!(
        "Cap'n Proto message, {}, root {summary}",
        plural(count, "segment")
    ));
    Ok(())
}

async fn segment_table_node(cx: Cx, (file, segments): (Span, Vec<(u64, u64)>)) -> Result<()> {
    cx.emit(
        Node::new("Segment count - 1")
            .span(file.sub(0, 4))
            .value(uint(to_u64(segments.len()).saturating_sub(1), 32)),
    );
    for (i, &(start, words)) in segments.iter().enumerate() {
        let at = to_u64(i).saturating_mul(4).saturating_add(4);
        cx.push(
            Node::new(format!("Segment {i} size"))
                .span(file.sub(at, 4))
                .value(uint(words, 32))
                .summary(format!("words, at {:#x}", file.sub(start, 0).offset))
                .target(file.sub(start, words.saturating_mul(WORD))),
        )
        .await;
    }
    Ok(())
}

/// A node for the pointer at `loc`, expanding into what it refers to.
async fn pointer_node(cx: &Cx, msg: &M, name: impl Into<std::borrow::Cow<'static, str>>, loc: Loc, path: &Path) -> Result<Node> {
    let span = msg.words(loc, 1).unwrap_or(msg.span.sub(0, 0));
    let node = Node::new(name).span(span);
    let (obj, hop) = match resolve(cx, msg, loc).await {
        Ok(r) => r,
        Err(d) => return Ok(node.diag(d)),
    };
    let mut node = object_node(cx, msg, node, obj, path).await?;
    if let Some(hop) = hop {
        let what = node.summary.take().unwrap_or_default();
        node = node.summary(format!("{what} (through a {hop})"));
    }
    Ok(node)
}

async fn object_node(cx: &Cx, msg: &M, node: Node, obj: Object, path: &Path) -> Result<Node> {
    Ok(match obj {
        Object::Null => node.summary("null"),
        Object::Capability(i) => node.summary(format!("capability {i}")),
        Object::Struct { at, data, ptrs } => {
            let size = u64::from(data).saturating_add(ptrs.into());
            let summary = format!(
                "struct, {}, {}",
                plural(data.into(), "data word"),
                plural(ptrs.into(), "pointer")
            );
            let Some(target) = msg.words(at, size) else {
                return Ok(node
                    .summary(summary)
                    .diag(Diagnostic::malformed("struct outside its segment")));
            };
            let node = node.summary(summary).target(target);
            if size == 0 {
                return Ok(node);
            }
            match path.enter(Msg::id(at), MAX_DEPTH) {
                Ok(child) => node.lazy(
                    crate::expander!(self::struct_fields: StructState),
                    (msg.clone(), at, data, ptrs, child),
                ),
                Err(d) => node.diag(d),
            }
        }
        Object::List { at, elem, count } => list_node(cx, msg, node, at, elem, count, path).await?,
    })
}

type StructState = (M, Loc, u16, u16, Path);

async fn struct_fields(cx: Cx, (msg, at, data, ptrs, path): StructState) -> Result<()> {
    if data > 0 {
        let span = msg.words(at, data.into()).unwrap_or(msg.span.sub(0, 0));
        cx.emit(
            Node::new("Data section")
                .span(span)
                .summary(plural(data.into(), "word"))
                .lazy(data_words, (span, u64::from(data))),
        );
    }
    // At most 65535 pointers: pushed without resume marks (the data
    // section is emitted before them).
    let mut i = 0u16;
    while i < ptrs {
        let loc = Loc {
            seg: at.seg,
            word: at.word.saturating_add(data.into()).saturating_add(i.into()),
        };
        let node = pointer_node(&cx, &msg, format!("pointer {i}"), loc, &path).await?;
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// A data word with its 32-bit halves and, if plausible, as a double.
fn word_node(name: String, span: Span, w: u64) -> Node {
    let lo = u32::try_from(w & 0xffff_ffff).unwrap_or(0).cast_signed();
    let hi = u32::try_from(w >> 32).unwrap_or(0).cast_signed();
    let mut summary = format!("i32 [{lo}, {hi}]");
    if plausible_f64(w) {
        summary.push_str(&format!(" · double {}", f64::from_bits(w)));
    }
    Node::new(name).span(span).value(hex(w, 64)).summary(summary)
}

async fn data_words(cx: Cx, (span, words): (Span, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    for (i, chunk) in data.as_chunks::<8>().0.iter().enumerate().take(crate::bytes::to_usize(words)) {
        let w = u64::from_le_bytes(*chunk);
        let at = to_u64(i).saturating_mul(WORD);
        cx.push(word_node(format!("word {i}"), span.sub(at, WORD), w)).await;
    }
    Ok(())
}

/// The size in bytes of a non-composite list's elements.
fn list_bytes(elem: u8, count: u32) -> u64 {
    element_bits(elem)
        .saturating_mul(count.into())
        .div_ceil(8)
}

async fn list_node(cx: &Cx, msg: &M, node: Node, at: Loc, elem: u8, count: u32, path: &Path) -> Result<Node> {
    let elem_name = lookup(ELEMENT_SIZES, elem.into()).unwrap_or("?");
    if elem == 7 {
        // Composite: a tag word (struct pointer layout, offset = element
        // count), then the elements; `count` is the word count.
        let total = u64::from(count).saturating_add(1);
        let Some(span) = msg.words(at, total) else {
            return Ok(node
                .summary(format!("list of {elem_name}"))
                .diag(Diagnostic::malformed("list outside its segment")));
        };
        let tag = read_word(cx, msg, at).await?;
        let Pointer::Struct {
            offset: n,
            data,
            ptrs,
        } = pointer(tag)
        else {
            return Ok(node.diag(Diagnostic::malformed("composite list without a struct tag")));
        };
        let n = u32::try_from(n).unwrap_or(0);
        let per = u64::from(data).saturating_add(ptrs.into());
        let node = node
            .summary(format!(
                "list of {} ({}, {} each)",
                plural(n.into(), "struct"),
                plural(data.into(), "data word"),
                plural(ptrs.into(), "pointer")
            ))
            .target(span);
        if per.saturating_mul(n.into()) > count.into() {
            return Ok(node.diag(Diagnostic::malformed("composite list elements exceed its size")));
        }
        return Ok(match path.enter(Msg::id(at), MAX_DEPTH) {
            Ok(child) => node.lazy(
                crate::expander!(self::elements: ListState),
                (msg.clone(), at, elem, n, (data, ptrs), child),
            ),
            Err(d) => node.diag(d),
        });
    }
    let bytes = if elem == 6 {
        u64::from(count).saturating_mul(WORD)
    } else {
        list_bytes(elem, count)
    };
    let Some(span) = msg.bytes(at, bytes) else {
        return Ok(node
            .summary(format!("list of {} {elem_name}", count))
            .diag(Diagnostic::malformed("list outside its segment")));
    };
    let node = node.target(span);
    if elem == 2 {
        // Bytes: Text (NUL-terminated) or Data.
        let data = cx.read(span.sub(0, 4096)).await?;
        let whole = to_u64(data.len()) == bytes;
        if whole
            && let Some((&0, text)) = data.split_last()
            && (text.is_empty() || printable(text, false))
        {
            return Ok(node
                .value(Value::Text(short_text(text, TEXT_MAX)))
                .summary(format!("text, {}", plural(to_u64(text.len()), "byte"))));
        }
        return Ok(node
            .value(prefix(&data))
            .summary(format!("data, {}", plural(count.into(), "byte"))));
    }
    let node = node.summary(format!("list of {count} {elem_name}"));
    if elem == 0 || count == 0 {
        return Ok(node);
    }
    Ok(match path.enter(Msg::id(at), MAX_DEPTH) {
        Ok(child) => node.lazy(
            crate::expander!(self::elements: ListState),
            (msg.clone(), at, elem, count, (0, 0), child),
        ),
        Err(d) => node.diag(d),
    })
}

/// A list: its start, element size, element count, the struct sizes of a
/// composite list's elements, and the path.
type ListState = (M, Loc, u8, u32, (u16, u16), Path);

async fn elements(cx: Cx, (msg, at, elem, count, (data, ptrs), path): ListState) -> Result<()> {
    let mut i = cx.resume::<u32>().unwrap_or(0);
    while i < count {
        let here = i;
        cx.mark(move || here);
        let name = format!("[{i}]");
        let node = match elem {
            7 => {
                let per = u64::from(data).saturating_add(ptrs.into());
                let start = Loc {
                    seg: at.seg,
                    word: at
                        .word
                        .saturating_add(1)
                        .saturating_add(per.saturating_mul(i.into())),
                };
                let obj = Object::Struct {
                    at: start,
                    data,
                    ptrs,
                };
                let span = msg.words(start, per).unwrap_or(msg.span.sub(0, 0));
                object_node(&cx, &msg, Node::new(name).span(span), obj, &path).await?
            }
            6 => {
                let loc = Loc {
                    seg: at.seg,
                    word: at.word.saturating_add(i.into()),
                };
                pointer_node(&cx, &msg, name, loc, &path).await?
            }
            1 => {
                let byte_at = u64::from(i / 8);
                let span = msg.bytes(at, byte_at.saturating_add(1)).unwrap_or(msg.span.sub(0, 0));
                let b = cx.read(span.sub(byte_at, 1)).await?;
                let bit = b.first().is_some_and(|&b| b & (1 << (i % 8)) != 0);
                Node::new(name).span(span.sub(byte_at, 1)).value(Value::Bool(bit))
            }
            _ => {
                let size = element_bits(elem) / 8;
                let start = u64::from(i).saturating_mul(size);
                let list = msg.bytes(at, list_bytes(elem, count)).unwrap_or(msg.span.sub(0, 0));
                let span = list.sub(start, size);
                let raw = cx.read(span).await?;
                scalar_node(Node::new(name).span(span), &raw)
            }
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

/// A list element of 2, 4 or 8 bytes: signed if small and negative, a
/// float if plausible, unsigned otherwise.
fn scalar_node(node: Node, raw: &[u8]) -> Node {
    match raw.len() {
        2 => {
            let v = crate::bytes::u16_le(raw, 0).unwrap_or(0);
            let s = v.cast_signed();
            if s < 0 {
                node.value(Value::Int {
                    value: s.into(),
                    bits: 16,
                })
            } else {
                node.value(uint(v.into(), 16))
            }
        }
        4 => {
            let v = crate::bytes::u32_le(raw, 0).unwrap_or(0);
            let s = v.cast_signed();
            if s < 0 && s > -(1 << 24) {
                node.value(Value::Int {
                    value: s.into(),
                    bits: 32,
                })
            } else if plausible_f32(v) {
                node.value(Value::Float(widen(f32::from_bits(v))))
                    .summary(format!("float?; 32-bit {v:#x}"))
            } else {
                node.value(uint(v.into(), 32))
            }
        }
        _ => {
            let v = u64_le(raw, 0).unwrap_or(0);
            let s = v.cast_signed();
            if s < 0 && s > -(1 << 48) {
                node.value(Value::Int { value: s, bits: 64 })
            } else if plausible_f64(v) {
                node.value(Value::Float(f64::from_bits(v)))
                    .summary(format!("double?; 64-bit {v:#x}"))
            } else {
                node.value(uint(v, 64))
            }
        }
    }
}

async fn dissect_packed(cx: Cx, input: Input) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, input.span, &Codec::CapnpPacked, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    let unpacked = decoded.span.len;
    dissect(cx.clone(), input.nested(decoded.span)).await?;
    cx.annotate(format!(
        "Cap'n Proto message (packed, {unpacked:#x} bytes unpacked)"
    ));
    Ok(())
}
