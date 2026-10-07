//! FlatBuffers without their schema: the root table offset, the file
//! identifier (when bytes 4..8 are printable), and tables through their
//! vtables. A table lists its present field slots; each slot's width is
//! guessed from the gap to the next field and its alignment, and 4-byte
//! slots that point at something plausible are followed: a NUL-terminated
//! UTF-8 string, a table (vtable inside the buffer, field offsets inside
//! the table), or a vector (elements recognised when they are strings or
//! tables). Everything else is shown as an integer or float (whichever is
//! plausible), or as bytes for inline structs. These are guesses and the
//! summaries say so with a `?`. Size-prefixed buffers are recognised.
//!
//! No signature: the format is reached by extension or "inspect as".
//! Buffers with a known identifier (TFLite `TFL3`, ...) have their own
//! dissectors. Checked against the Python `flatbuffers` Builder
//! (`tests/data/flatbuffers`).

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Path;
use crate::error::Result;
use crate::formats::util::wire::flatbuffers::{Fb, Table};
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::{
    hex, plausible_f32, plausible_f64, plural, prefix, printable, short_text, uint, widen,
};

declare_format!(pub FORMAT = "flatbuffers", "FlatBuffers data (no schema)",
    ["fb", "bin"], "application/x-flatbuffers", Probe::Never, dissect);

/// Tables nested at most this deep.
const MAX_DEPTH: usize = 64;
/// Vector elements inspected to tell strings and tables apart.
const SAMPLE: u32 = 16;
/// Characters of a string shown.
const TEXT_MAX: u64 = 256;

/// Whether `bytes` looks like a file identifier.
fn identifier(bytes: &[u8]) -> bool {
    bytes.len() == 4 && bytes.iter().all(|b| b.is_ascii_graphic())
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 8)).await?;
    // A size-prefixed buffer: its length, then the buffer.
    let prefixed = u32_le(&head, 0).is_some_and(|n| u64::from(n) == file.len.saturating_sub(4))
        && file.len >= 12
        && Fb::new(&cx, file).root().await.is_err();
    let buf = if prefixed {
        cx.emit(
            Node::new("Size prefix")
                .span(file.sub(0, 4))
                .value(uint(file.len.saturating_sub(4), 32)),
        );
        file.tail(4)
    } else {
        file
    };
    let fb = Fb::new(&cx, buf);
    let root_off = fb.u32_at(0).await?;
    cx.emit(
        Node::new("Root table offset")
            .span(buf.sub(0, 4))
            .value(hex(root_off.into(), 32))
            .target(buf.sub(root_off.into(), 4)),
    );
    let id = cx.read_avail(buf.sub(4, 4)).await?;
    let mut summary = String::from("FlatBuffers data");
    if root_off >= 8 && identifier(&id) {
        let id = String::from_utf8_lossy(&id).into_owned();
        summary.push_str(&format!(", identifier {id}"));
        cx.emit(
            Node::new("File identifier")
                .span(buf.sub(4, 4))
                .value(Value::Text(id)),
        );
    }
    if prefixed {
        summary.push_str(", size-prefixed");
    }
    let root = fb.root().await?;
    let path = Path::new().enter(root.pos, MAX_DEPTH)?;
    let slots = present_slots(&fb, &root).await?;
    cx.emit(
        Node::new("Root table")
            .span(fb.table_span(&root))
            .summary(format!("table, {}", plural(slots, "field")))
            .lazy(crate::expander!(self::table: TableState), (buf, root, path)),
    );
    cx.annotate(summary);
    Ok(())
}

/// The number of present field slots of `t`.
async fn present_slots(fb: &Fb<'_>, t: &Table) -> Result<u64> {
    let vt = fb.bytes(t.vtable, t.vtable_len.into()).await?;
    Ok(to_u64(
        vt.get(4..)
            .unwrap_or_default()
            .as_chunks::<2>()
            .0
            .iter()
            .filter(|c| u16::from_le_bytes(**c) != 0)
            .count(),
    ))
}

/// What a 4-byte slot (or vector element) points to.
enum Target {
    Str {
        len: u64,
        text: String,
    },
    Table(Table),
    Vector {
        pos: u64,
        len: u32,
        kind: Elems,
        preview: Vec<u8>,
    },
    Empty,
}

/// What the elements of a vector were recognised as.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Elems {
    Strings,
    Tables,
    Unknown,
}

/// A string at `pos` (its length), if it is one: NUL-terminated UTF-8.
async fn string_at(fb: &Fb<'_>, pos: u64) -> Result<Option<(u64, String)>> {
    let Ok(len) = fb.u32_at(pos).await else {
        return Ok(None);
    };
    let len = u64::from(len);
    let end = pos.saturating_add(4).saturating_add(len);
    if len == 0 || end >= fb.buf.len {
        return Ok(None);
    }
    if fb.u8_at(end).await.ok() != Some(0) {
        return Ok(None);
    }
    let text = fb.bytes(pos.saturating_add(4), len.min(1024)).await?;
    let valid = printable(&text, len > 1024);
    Ok(valid.then(|| {
        (
            len,
            short_text(&text, usize::try_from(TEXT_MAX).unwrap_or(256)),
        )
    }))
}

/// A table at `pos`, if the structure is plausible: its vtable and inline
/// data inside the buffer and every field offset inside the table.
async fn table_at(fb: &Fb<'_>, pos: u64) -> Result<Option<Table>> {
    let Ok(t) = fb.table(pos).await else {
        return Ok(None);
    };
    if t.size < 4 || pos.saturating_add(t.size.into()) > fb.buf.len || t.vtable % 2 != 0 {
        return Ok(None);
    }
    let vt = fb.bytes(t.vtable, t.vtable_len.into()).await?;
    let ok = vt
        .get(4..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .all(|off| off == 0 || (4..t.size).contains(&off));
    Ok(ok.then_some(t))
}

/// What the uoffset stored at `at` points to, if anything plausible.
async fn target(fb: &Fb<'_>, at: u64, path: &Path) -> Result<Option<Target>> {
    let Ok(off) = fb.u32_at(at).await else {
        return Ok(None);
    };
    let pos = at.saturating_add(off.into());
    if off == 0 || pos % 4 != 0 || pos.saturating_add(4) > fb.buf.len {
        return Ok(None);
    }
    if let Some((len, text)) = string_at(fb, pos).await? {
        return Ok(Some(Target::Str { len, text }));
    }
    if !path.contains(pos)
        && let Some(t) = table_at(fb, pos).await?
    {
        return Ok(Some(Target::Table(t)));
    }
    let len = fb.u32_at(pos).await?;
    if len == 0 {
        // An empty vector, or an empty string.
        return Ok((fb.u8_at(pos.saturating_add(4)).await.ok() == Some(0)).then_some(Target::Empty));
    }
    let start = pos.saturating_add(4);
    if start.saturating_add(len.into()) > fb.buf.len {
        return Ok(None);
    }
    let kind = elements_kind(fb, start, len).await?;
    let preview = match kind {
        Elems::Unknown => fb.cx.read_avail(fb.buf.sub(start, 32)).await?,
        _ => Vec::new(),
    };
    Ok(Some(Target::Vector {
        pos,
        len,
        kind,
        preview,
    }))
}

/// Whether the first elements of a vector at `start` are all strings or
/// all tables.
async fn elements_kind(fb: &Fb<'_>, start: u64, len: u32) -> Result<Elems> {
    if start.saturating_add(u64::from(len).saturating_mul(4)) > fb.buf.len {
        return Ok(Elems::Unknown);
    }
    let (mut strings, mut tables) = (true, true);
    for i in 0..len.min(SAMPLE) {
        let at = start.saturating_add(u64::from(i).saturating_mul(4));
        let Ok(off) = fb.u32_at(at).await else {
            return Ok(Elems::Unknown);
        };
        let pos = at.saturating_add(off.into());
        if off == 0 || pos % 4 != 0 {
            return Ok(Elems::Unknown);
        }
        let is_string = string_at(fb, pos).await?.is_some();
        let is_table = !is_string && tables && table_at(fb, pos).await?.is_some();
        strings = strings && is_string;
        tables = tables && is_table;
        if !strings && !tables {
            return Ok(Elems::Unknown);
        }
    }
    Ok(if strings {
        Elems::Strings
    } else {
        Elems::Tables
    })
}

type TableState = (Span, Table, Path);

async fn table(cx: Cx, (buf, t, path): TableState) -> Result<()> {
    let fb = Fb::new(&cx, buf);
    let soff = fb.u32_at(t.pos).await?.cast_signed();
    cx.emit(
        Node::new("vtable offset")
            .span(buf.sub(t.pos, 4))
            .value(Value::Int {
                value: soff.into(),
                bits: 32,
            })
            .summary(format!("vtable at {:#x}", buf.sub(t.vtable, 0).offset))
            .target(buf.sub(t.vtable, t.vtable_len.into())),
    );
    let vt = fb.bytes(t.vtable, t.vtable_len.into()).await?;
    let offsets: Vec<u16> = vt
        .get(4..)
        .unwrap_or_default()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u16::from_le_bytes(*c))
        .collect();
    cx.emit(
        Node::new("vtable")
            .span(buf.sub(t.vtable, t.vtable_len.into()))
            .summary(format!(
                "{}, table size {}",
                plural(offsets.len().try_into().unwrap_or(0), "slot"),
                t.size
            ))
            .lazy(vtable, (buf, t)),
    );
    let mut sorted: Vec<u16> = offsets.iter().copied().filter(|&o| o != 0).collect();
    sorted.sort_unstable();
    for (slot, &off) in offsets.iter().enumerate() {
        if off == 0 {
            continue;
        }
        let next = sorted.iter().copied().find(|&o| o > off).unwrap_or(t.size);
        let gap = u64::from(next.saturating_sub(off));
        let at = t.pos.saturating_add(off.into());
        let node = slot_node(&cx, &fb, slot, at, gap, &path).await?;
        cx.push(node).await;
    }
    Ok(())
}

async fn vtable(cx: Cx, (buf, t): (Span, Table)) -> Result<()> {
    let fb = Fb::new(&cx, buf);
    cx.emit(
        Node::new("vtable size")
            .span(buf.sub(t.vtable, 2))
            .value(uint(t.vtable_len.into(), 16)),
    );
    cx.emit(
        Node::new("table size")
            .span(buf.sub(t.vtable.saturating_add(2), 2))
            .value(uint(t.size.into(), 16)),
    );
    for slot in 0..t.slots() {
        let at = t
            .vtable
            .saturating_add(4)
            .saturating_add(u64::from(slot).saturating_mul(2));
        let off = fb.u16_at(at).await?;
        let node = Node::new(format!("slot {slot}"))
            .span(buf.sub(at, 2))
            .value(uint(off.into(), 16));
        cx.push(if off == 0 {
            node.summary("absent")
        } else {
            node
        })
        .await;
    }
    Ok(())
}

/// The width of an inline scalar: the largest of 8, 4, 2, 1 that fits in
/// the gap to the next field and is aligned (the builder aligns scalars).
fn width(at: u64, gap: u64) -> u64 {
    [8u64, 4, 2, 1]
        .into_iter()
        .find(|&w| w <= gap && at.is_multiple_of(w))
        .unwrap_or(1)
}

async fn slot_node(
    cx: &Cx,
    fb: &Fb<'_>,
    slot: usize,
    at: u64,
    gap: u64,
    path: &Path,
) -> Result<Node> {
    let name = format!("field {slot}");
    if gap > 8 {
        let bytes = cx.read_avail(fb.buf.sub(at, gap)).await?;
        return Ok(Node::new(name)
            .span(fb.buf.sub(at, gap))
            .value(prefix(&bytes))
            .summary(format!("inline struct?, {gap} bytes")));
    }
    let w = width(at, gap);
    let span = fb.buf.sub(at, w);
    let raw = cx.read_avail(span).await?;
    let node = Node::new(name).span(span);
    Ok(match w {
        8 => {
            let v = u64_le(&raw, 0).unwrap_or(0);
            if plausible_f64(v) {
                node.value(Value::Float(f64::from_bits(v)))
                    .summary(format!("double?; 64-bit {v:#x}"))
            } else {
                scalar(node, v, v.cast_signed(), 64)
            }
        }
        4 => match target(fb, at, path).await? {
            Some(t) => target_node(node, fb, at, t, path)?,
            None => {
                let v = u32_le(&raw, 0).unwrap_or(0);
                if plausible_f32(v) {
                    node.value(Value::Float(widen(f32::from_bits(v))))
                        .summary(format!("float?; 32-bit {v:#x}"))
                } else {
                    scalar(node, v.into(), v.cast_signed().into(), 32)
                }
            }
        },
        2 => {
            let v = u16_le(&raw, 0).unwrap_or(0);
            scalar(node, v.into(), v.cast_signed().into(), 16)
        }
        _ => {
            let v = raw.first().copied().unwrap_or(0);
            node.value(uint(v.into(), 8)).summary("8-bit")
        }
    })
}

/// An integer of `bits` bits: signed if it reads as a small negative
/// number, unsigned otherwise.
fn scalar(node: Node, unsigned: u64, signed: i64, bits: u8) -> Node {
    let small = 1i64
        .checked_shl(u32::from(bits / 2).min(24))
        .map_or(i64::MIN, i64::saturating_neg);
    if signed < 0 && signed > small {
        node.value(Value::Int {
            value: signed,
            bits,
        })
        .summary(format!("{bits}-bit; unsigned {unsigned}"))
    } else {
        node.value(uint(unsigned, bits))
            .summary(format!("{bits}-bit"))
    }
}

/// A node for a 4-byte slot (or vector element) at `at` pointing to `t`.
fn target_node(node: Node, fb: &Fb<'_>, at: u64, t: Target, path: &Path) -> Result<Node> {
    Ok(match t {
        Target::Str { len, text } => {
            let node = node.value(Value::Text(text));
            if len > TEXT_MAX {
                node.summary(format!("string, {len} bytes"))
            } else {
                node.summary("string")
            }
        }
        Target::Empty => node.summary("empty string or vector"),
        Target::Table(t) => {
            let node = node.summary("table?").target(fb.table_span(&t));
            match path.enter(t.pos, MAX_DEPTH) {
                Ok(child) => node.lazy(
                    crate::expander!(self::table: TableState),
                    (fb.buf, t, child),
                ),
                Err(d) => node.diag(d),
            }
        }
        Target::Vector {
            pos,
            len,
            kind,
            preview,
        } => {
            let what = match kind {
                Elems::Strings => "vector of strings",
                Elems::Tables => "vector of tables?",
                Elems::Unknown => "vector?",
            };
            let node = node
                .summary(format!("{what}, {}", plural(len.into(), "element")))
                .target(fb.buf.sub(pos, 4));
            match kind {
                Elems::Unknown => node.value(prefix(&preview)),
                _ => node.lazy(
                    crate::expander!(self::vector: VectorState),
                    (fb.buf, at, kind, path.clone()),
                ),
            }
        }
    })
}

type VectorState = (Span, u64, Elems, Path);

/// The elements of a vector of strings or tables whose uoffset is at `at`.
async fn vector(cx: Cx, (buf, at, kind, path): VectorState) -> Result<()> {
    let fb = Fb::new(&cx, buf);
    let pos = fb.deref(at).await?;
    let len = fb.u32_at(pos).await?;
    let start = pos.saturating_add(4);
    buf.sub_exact(start, u64::from(len).saturating_mul(4))?;
    let mut i = cx.resume::<u32>().unwrap_or(0);
    while i < len {
        let here = i;
        cx.mark(move || here);
        let elem = start.saturating_add(u64::from(i).saturating_mul(4));
        let node = Node::new(format!("[{i}]")).span(buf.sub(elem, 4));
        let node = match target(&fb, elem, &path).await? {
            Some(t @ (Target::Str { .. } | Target::Table(_))) => {
                target_node(node, &fb, elem, t, &path)?
            }
            _ => node
                .value(hex(fb.u32_at(elem).await?.into(), 32))
                .summary(match kind {
                    Elems::Strings => "not a string",
                    _ => "not a table",
                }),
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}
