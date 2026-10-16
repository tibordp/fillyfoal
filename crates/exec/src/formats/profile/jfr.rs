//! JDK Flight Recorder recordings (`.jfr`, format 2.x as written by JDK 11
//! and later): a sequence of self-contained chunks.
//!
//! A chunk is a 68-byte big-endian header and a stream of events, each a
//! size and a type ID (LEB128-style integers when the chunk's
//! compressed-integers flag is set, as the JVM writes them) followed by
//! the event's fields. Two event types are special: the metadata event
//! (type 0) describes every type in the chunk as an element tree of
//! classes, fields and annotations over a string table, and checkpoint
//! events (type 1) carry constant pools (threads, stack traces, methods,
//! classes, symbols) that other events refer to by key. Checkpoint events
//! form a chain backwards from the header's constant pool offset.
//!
//! Events are decoded against the metadata: each field becomes a node,
//! constant pool references are resolved to a summary of the constant
//! (expandable into its fields), and tick timestamps and durations are
//! converted with the chunk's clock.

use std::collections::{BTreeMap, BTreeSet};
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::binutil::{NodeExt, Reader, data_node};
use crate::formats::util::civil::civil;
use crate::formats::util::fmt::{clip, plural};
use crate::formats::util::lines::flags;
use crate::formats::util::val::{hex, int, text, uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{FlagTable, Value, flag};

const BE: Endian = Endian::Big;
const HEADER_LEN: u64 = 68;

pub static FORMAT: Format = Format {
    name: "jfr",
    title: "JDK Flight Recorder recording",
    extensions: &["jfr"],
    mime: "application/x-jfr",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head) -> bool {
    let u16_at = |at: usize| crate::formats::util::binutil::get::<u16>(h.data, at, BE);
    let size = crate::formats::util::binutil::get::<u64>(h.data, 8, BE);
    h.starts_with(b"FLR\0")
        && matches!(u16_at(4), Some(1 | 2))
        && u16_at(6).is_some_and(|m| m < 16)
        && size.is_some_and(|s| s >= HEADER_LEN)
}

const CHUNK_FLAGS: FlagTable = &[flag(1, "COMPRESSED_INTS"), flag(2, "FINAL_CHUNK")];

record! {
    /// The chunk header.
    struct ChunkHeader {
        magic: ascii[4] "Magic",
        major: u16 "Major version",
        minor: u16 "Minor version",
        size: u64 "Chunk size" .hex(),
        cp_offset: u64 "Constant pool offset" .hex()
            .desc("Offset of the last checkpoint event, from the chunk start"),
        meta_offset: u64 "Metadata offset" .hex()
            .desc("Offset of the metadata event, from the chunk start"),
        start_nanos: u64 "Start time" .desc("Nanoseconds since 1970-01-01 UTC"),
        duration: u64 "Duration" .desc("Nanoseconds"),
        start_ticks: u64 "Start ticks",
        ticks_per_second: u64 "Ticks per second",
        generation: u8 "Generation"
            .desc("0 once the chunk is complete, 255 while it is being written"),
        _pad: u8 "Padding",
        flags: u16 "Flags" .flags(CHUNK_FLAGS),
    }
}

// ---------------------------------------------------------------------------
// Integers and strings

/// The chunk's integer encoding.
#[derive(Clone, Copy, Debug)]
struct Ints {
    compressed: bool,
}

impl Ints {
    /// An integer of `bytes` bytes: a varint (7 bits per byte, little end
    /// first, the ninth byte whole) when compressed, else big-endian.
    fn read(&self, r: &mut Reader, bytes: usize) -> Option<u64> {
        if !self.compressed {
            return match bytes {
                1 => r.u8().map(u64::from),
                2 => r.int::<u16>(BE).map(u64::from),
                4 => r.int::<u32>(BE).map(u64::from),
                _ => r.int::<u64>(BE),
            };
        }
        let mut v = 0u64;
        for i in 0..8u32 {
            let b = r.u8()?;
            v |= u64::from(b & 0x7f) << i.saturating_mul(7);
            if b & 0x80 == 0 {
                return Some(v);
            }
        }
        Some(v | (u64::from(r.u8()?) << 56))
    }
    fn long(&self, r: &mut Reader) -> Option<u64> {
        self.read(r, 8)
    }
    fn int(&self, r: &mut Reader) -> Option<u64> {
        self.read(r, 4)
    }
}

/// A string's encoding byte and content; constant pool references come
/// back as `Err(key)`.
fn read_string(ints: &Ints, r: &mut Reader) -> Option<std::result::Result<Option<String>, u64>> {
    match r.u8()? {
        0 => Some(Ok(None)),
        1 => Some(Ok(Some(String::new()))),
        2 => Some(Err(ints.long(r)?)),
        3 => {
            let n = to_usize(ints.int(r)?);
            Some(Ok(Some(String::from_utf8_lossy(r.bytes(n)?).into_owned())))
        }
        4 => {
            let n = ints.int(r)?;
            if n > to_u64(r.rest().len()) {
                return None;
            }
            let mut units = Vec::new();
            for _ in 0..n {
                units.push(u16::try_from(ints.read(r, 2)? & 0xffff).ok()?);
            }
            Some(Ok(Some(String::from_utf16_lossy(&units))))
        }
        5 => {
            let n = to_usize(ints.int(r)?);
            Some(Ok(Some(
                r.bytes(n)?.iter().map(|&b| char::from(b)).collect(),
            )))
        }
        _ => None,
    }
}

// ---------------------------------------------------------------------------
// Metadata

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Unit {
    Ticks,
    Nanos,
    Micros,
    Millis,
    Seconds,
    EpochMillis,
    EpochNanos,
}

#[derive(Clone, Debug, Default)]
struct FieldDef {
    name: String,
    type_id: u64,
    cp: bool,
    array: bool,
    label: Option<String>,
    timestamp: Option<Unit>,
    timespan: Option<Unit>,
    unsigned: bool,
}

#[derive(Clone, Debug, Default)]
struct Class {
    name: String,
    label: Option<String>,
    fields: Vec<FieldDef>,
}

/// One element of the metadata tree.
#[derive(Clone, Debug)]
struct Elem {
    name: usize,
    attrs: Vec<(usize, usize)>,
    children: Vec<usize>,
    start: u64,
    end: u64,
}

/// A parsed metadata event.
struct Meta {
    strings: Vec<(Option<String>, u64, u64)>,
    elems: Vec<Elem>,
    /// Offset of the string table and of the root element in the event.
    strings_at: u64,
    root_at: u64,
    classes: BTreeMap<u64, Class>,
    string_type: Option<u64>,
    error: Option<Diagnostic>,
}

impl Meta {
    fn string(&self, i: usize) -> &str {
        self.strings
            .get(i)
            .and_then(|(s, _, _)| s.as_deref())
            .unwrap_or("")
    }
    fn attr(&self, e: &Elem, key: &str) -> Option<&str> {
        e.attrs
            .iter()
            .find(|(k, _)| self.string(*k) == key)
            .map(|(_, v)| self.string(*v))
    }
    fn class_name(&self, id: u64) -> String {
        self.classes
            .get(&id)
            .map_or_else(|| format!("type {id}"), |c| c.name.clone())
    }
}

/// Limits on what one metadata event may describe.
const MAX_ELEMS: usize = 1 << 18;
const MAX_DEPTH: usize = 64;

/// Reads the metadata event at `span` (cached per span).
async fn metadata(cx: &Cx, span: Span, ints: Ints) -> Arc<Meta> {
    if let Some(m) = cx.cached::<Meta>(span, "jfr-metadata") {
        return m;
    }
    let mut meta = Meta {
        strings: Vec::new(),
        elems: Vec::new(),
        strings_at: 0,
        root_at: 0,
        classes: BTreeMap::new(),
        string_type: None,
        error: None,
    };
    if let Err(e) = parse_metadata(cx, span, ints, &mut meta).await {
        meta.error = Some(e);
    }
    let meta = Arc::new(meta);
    cx.cache(span, "jfr-metadata", meta.clone());
    meta
}

async fn parse_metadata(cx: &Cx, span: Span, ints: Ints, meta: &mut Meta) -> Result<()> {
    let data = cx.read(span).await?;
    let bad = || Diagnostic::malformed("metadata event ends early").at(span);
    let mut r = Reader::new(&data);
    for _ in 0..5 {
        // size, type, start time, duration, metadata ID
        ints.long(&mut r).ok_or_else(bad)?;
    }
    meta.strings_at = to_u64(r.pos());
    let count = ints.int(&mut r).ok_or_else(bad)?;
    if count > to_u64(r.rest().len()) {
        return Err(Diagnostic::malformed("string count exceeds the event").at(span));
    }
    for i in 0..count {
        if i % 512 == 511 {
            cx.checkpoint().await;
        }
        let start = to_u64(r.pos());
        let s = read_string(&ints, &mut r).ok_or_else(bad)?;
        meta.strings
            .push((s.ok().flatten(), start, to_u64(r.pos())));
    }
    meta.root_at = to_u64(r.pos());
    // The element tree, in pre-order, with an explicit stack of
    // (element, children left).
    let mut stack: Vec<(usize, u64)> = Vec::new();
    loop {
        if meta.elems.len() % 512 == 511 {
            cx.checkpoint().await;
        }
        if meta.elems.len() >= MAX_ELEMS || stack.len() > MAX_DEPTH {
            return Err(Diagnostic::limit("metadata tree too large or deep").at(span));
        }
        let start = to_u64(r.pos());
        let name = to_usize(ints.int(&mut r).ok_or_else(bad)?);
        let n_attrs = ints.int(&mut r).ok_or_else(bad)?;
        if n_attrs > to_u64(r.rest().len()) {
            return Err(bad());
        }
        let mut attrs = Vec::new();
        for _ in 0..n_attrs {
            let k = to_usize(ints.int(&mut r).ok_or_else(bad)?);
            let v = to_usize(ints.int(&mut r).ok_or_else(bad)?);
            attrs.push((k, v));
        }
        let n_children = ints.int(&mut r).ok_or_else(bad)?;
        if n_children > to_u64(r.rest().len()) {
            return Err(bad());
        }
        let index = meta.elems.len();
        meta.elems.push(Elem {
            name,
            attrs,
            children: Vec::new(),
            start,
            end: to_u64(r.pos()),
        });
        if let Some(&(parent, _)) = stack.last()
            && let Some(p) = meta.elems.get_mut(parent)
        {
            p.children.push(index);
        }
        if n_children > 0 {
            stack.push((index, n_children));
            continue;
        }
        // Close finished elements.
        let mut closed = index;
        loop {
            let end = to_u64(r.pos());
            if let Some(e) = meta.elems.get_mut(closed) {
                e.end = end;
            }
            let Some(top) = stack.last_mut() else {
                break;
            };
            top.1 = top.1.saturating_sub(1);
            if top.1 > 0 {
                break;
            }
            closed = top.0;
            stack.pop();
        }
        if stack.is_empty() {
            break;
        }
    }
    build_classes(meta);
    cx.charge(to_u64(meta.elems.len()) / 16).await;
    Ok(())
}

fn unit(s: &str) -> Option<Unit> {
    Some(match s {
        "TICKS" => Unit::Ticks,
        "NANOSECONDS" => Unit::Nanos,
        "MICROSECONDS" => Unit::Micros,
        "MILLISECONDS" => Unit::Millis,
        "SECONDS" => Unit::Seconds,
        "MILLISECONDS_SINCE_EPOCH" => Unit::EpochMillis,
        "NANOSECONDS_SINCE_EPOCH" => Unit::EpochNanos,
        _ => return None,
    })
}

fn build_classes(meta: &mut Meta) {
    let class_elems: Vec<usize> = meta
        .elems
        .iter()
        .enumerate()
        .filter(|(_, e)| meta.string(e.name) == "class")
        .map(|(i, _)| i)
        .collect();
    // Names first: annotations refer to their type by ID.
    let mut names = BTreeMap::new();
    for &i in &class_elems {
        let Some(e) = meta.elems.get(i) else { continue };
        if let Some(id) = meta.attr(e, "id").and_then(|s| s.parse::<u64>().ok()) {
            names.insert(id, meta.attr(e, "name").unwrap_or("").to_owned());
        }
    }
    let annotation = |meta: &Meta, e: &Elem| -> Option<(String, Option<String>)> {
        let id = meta.attr(e, "class")?.parse::<u64>().ok()?;
        Some((
            names.get(&id)?.clone(),
            meta.attr(e, "value").map(str::to_owned),
        ))
    };
    let mut classes = BTreeMap::new();
    for &i in &class_elems {
        let Some(e) = meta.elems.get(i) else { continue };
        let Some(id) = meta.attr(e, "id").and_then(|s| s.parse::<u64>().ok()) else {
            continue;
        };
        let mut class = Class {
            name: meta.attr(e, "name").unwrap_or("").to_owned(),
            ..Class::default()
        };
        for &c in &e.children {
            let Some(child) = meta.elems.get(c) else {
                continue;
            };
            match meta.string(child.name) {
                "annotation" => {
                    if let Some((name, Some(value))) = annotation(meta, child)
                        && name == "jdk.jfr.Label"
                    {
                        class.label = Some(value);
                    }
                }
                "field" => {
                    let mut f = FieldDef {
                        name: meta.attr(child, "name").unwrap_or("").to_owned(),
                        type_id: meta
                            .attr(child, "class")
                            .and_then(|s| s.parse().ok())
                            .unwrap_or(u64::MAX),
                        cp: meta.attr(child, "constantPool") == Some("true"),
                        array: meta.attr(child, "dimension") == Some("1"),
                        ..FieldDef::default()
                    };
                    for &a in &child.children {
                        let Some(ae) = meta.elems.get(a) else {
                            continue;
                        };
                        let Some((name, value)) = annotation(meta, ae) else {
                            continue;
                        };
                        match name.as_str() {
                            "jdk.jfr.Label" => f.label = value,
                            "jdk.jfr.Timestamp" => f.timestamp = value.as_deref().and_then(unit),
                            "jdk.jfr.Timespan" => f.timespan = value.as_deref().and_then(unit),
                            "jdk.jfr.Unsigned" => f.unsigned = true,
                            _ => {}
                        }
                    }
                    class.fields.push(f);
                }
                _ => {}
            }
        }
        if class.name == "java.lang.String" {
            meta.string_type = Some(id);
        }
        classes.insert(id, class);
    }
    meta.classes = classes;
}

// ---------------------------------------------------------------------------
// Values

/// A decoded value with its byte range in its buffer.
#[derive(Clone, Debug)]
enum Val {
    Null,
    Bool(bool),
    Int(i64),
    Float { value: f64, bits: u8 },
    Str(String),
    Ref { type_id: u64, key: u64 },
    Struct(u64, Vec<(usize, Val, usize, usize)>),
    Array(Vec<(Val, usize, usize)>),
}

/// The most values one decode may produce (bounds the work of a hostile
/// array or a deep structure).
const VALUE_BUDGET: u32 = 50_000;

struct Decoder<'a> {
    meta: &'a Meta,
    ints: Ints,
    budget: u32,
}

impl Decoder<'_> {
    fn new(meta: &Meta, ints: Ints) -> Decoder<'_> {
        Decoder {
            meta,
            ints,
            budget: VALUE_BUDGET,
        }
    }

    /// A value of type `type_id`; `cp` fields are constant pool keys.
    fn value(&mut self, r: &mut Reader, type_id: u64, cp: bool, depth: usize) -> Option<Val> {
        self.budget = self.budget.checked_sub(1)?;
        if depth > 16 {
            return None;
        }
        if cp {
            return Some(Val::Ref {
                type_id,
                key: self.ints.long(r)?,
            });
        }
        let class = self.meta.classes.get(&type_id)?;
        let i = &self.ints;
        Some(match class.name.as_str() {
            "boolean" => Val::Bool(r.u8()? != 0),
            "byte" => Val::Int(i64::from(i8::from_ne_bytes([r.u8()?]))),
            "short" => Val::Int(i64::from(i16::from_ne_bytes(
                u16::try_from(i.read(r, 2)? & 0xffff).ok()?.to_ne_bytes(),
            ))),
            "char" => Val::Str(
                char::from_u32(u32::try_from(i.read(r, 2)? & 0xffff).ok()?)
                    .unwrap_or('\u{fffd}')
                    .to_string(),
            ),
            "int" => Val::Int(i64::from(i32::from_ne_bytes(
                u32::try_from(i.int(r)? & 0xffff_ffff).ok()?.to_ne_bytes(),
            ))),
            "long" => Val::Int(i64::from_ne_bytes(i.long(r)?.to_ne_bytes())),
            "float" => Val::Float {
                value: f64::from(f32::from_bits(r.int::<u32>(BE)?)),
                bits: 32,
            },
            "double" => Val::Float {
                value: f64::from_bits(r.int::<u64>(BE)?),
                bits: 64,
            },
            "java.lang.String" => match read_string(i, r)? {
                Ok(Some(s)) => Val::Str(s),
                Ok(None) => Val::Null,
                Err(key) => Val::Ref { type_id, key },
            },
            _ => {
                let mut fields = Vec::new();
                for (n, f) in class.fields.iter().enumerate() {
                    let start = r.pos();
                    let v = if f.array {
                        let count = self.ints.int(r)?;
                        if count > to_u64(r.rest().len()) {
                            return None;
                        }
                        let mut items = Vec::new();
                        for _ in 0..count {
                            let s = r.pos();
                            let v = self.value(r, f.type_id, f.cp, depth.saturating_add(1))?;
                            items.push((v, s, r.pos()));
                        }
                        Val::Array(items)
                    } else {
                        self.value(r, f.type_id, f.cp, depth.saturating_add(1))?
                    };
                    fields.push((n, v, start, r.pos()));
                }
                Val::Struct(type_id, fields)
            }
        })
    }
}

// ---------------------------------------------------------------------------
// Chunks and constant pools

#[derive(Clone, Copy, Debug)]
struct Clock {
    start_nanos: u64,
    start_ticks: u64,
    ticks_per_second: u64,
}

impl Clock {
    fn ticks_to_nanos(&self, ticks: u64) -> Option<u64> {
        let tps = u128::from(self.ticks_per_second);
        if tps == 0 {
            return None;
        }
        u64::try_from(
            u128::from(ticks)
                .checked_mul(1_000_000_000)?
                .checked_div(tps)?,
        )
        .ok()
    }
    /// Nanoseconds since the epoch of a tick timestamp.
    fn epoch_nanos(&self, ticks: u64) -> Option<u64> {
        let delta = i128::from(ticks).checked_sub(i128::from(self.start_ticks))?;
        let tps = i128::from(self.ticks_per_second);
        let ns = delta.checked_mul(1_000_000_000)?.checked_div(tps)?;
        u64::try_from(i128::from(self.start_nanos).checked_add(ns)?).ok()
    }
}

#[derive(Clone, Debug)]
struct Chunk {
    span: Span,
    ints: Ints,
    clock: Clock,
    meta: Span,
    cp_offset: u64,
}

/// The constant pools of a chunk: every checkpoint event's bytes and an
/// index from `(type, key)` to the value's place.
struct Pools {
    events: Vec<(u64, Vec<u8>)>,
    index: BTreeMap<(u64, u64), (usize, usize)>,
    error: Option<Diagnostic>,
}

/// The most checkpoint events followed along a chunk's chain.
const MAX_CHECKPOINTS: usize = 1 << 16;

async fn pools(cx: &Cx, chunk: &Chunk, meta: &Meta) -> Arc<Pools> {
    if let Some(p) = cx.cached::<Pools>(chunk.span, "jfr-pools") {
        return p;
    }
    let mut pools = Pools {
        events: Vec::new(),
        index: BTreeMap::new(),
        error: None,
    };
    if let Err(e) = parse_pools(cx, chunk, meta, &mut pools).await {
        pools.error = Some(e);
    }
    let pools = Arc::new(pools);
    cx.cache(chunk.span, "jfr-pools", pools.clone());
    pools
}

async fn parse_pools(cx: &Cx, chunk: &Chunk, meta: &Meta, pools: &mut Pools) -> Result<()> {
    let ints = chunk.ints;
    let mut at = chunk.cp_offset;
    let mut seen = BTreeSet::new();
    while at >= HEADER_LEN && at < chunk.span.len && seen.insert(at) {
        if seen.len() > MAX_CHECKPOINTS {
            return Err(Diagnostic::limit("too many checkpoint events").at(chunk.span));
        }
        let head = cx.read_avail(chunk.span.sub(at, 10)).await?;
        let size = ints.int(&mut Reader::new(&head)).ok_or_else(|| {
            Diagnostic::malformed("bad checkpoint event").at(chunk.span.sub(at, 10))
        })?;
        let span = chunk.span.sub(at, size);
        let data = cx.read(span).await?;
        let mut r = Reader::new(&data);
        let bad = || Diagnostic::malformed("checkpoint event ends early").at(span);
        ints.int(&mut r).ok_or_else(bad)?;
        if ints.long(&mut r).ok_or_else(bad)? != 1 {
            return Err(
                Diagnostic::malformed("constant pool offset is not a checkpoint event").at(span),
            );
        }
        ints.long(&mut r).ok_or_else(bad)?;
        ints.long(&mut r).ok_or_else(bad)?;
        let delta = i64::from_ne_bytes(ints.long(&mut r).ok_or_else(bad)?.to_ne_bytes());
        r.u8().ok_or_else(bad)?;
        let index = pools.events.len();
        let count = ints.int(&mut r).ok_or_else(bad)?;
        let mut decoder = Decoder::new(meta, ints);
        'pools: for _ in 0..count.min(to_u64(data.len())) {
            let Some(type_id) = ints.long(&mut r) else {
                break;
            };
            let Some(n) = ints.int(&mut r) else { break };
            for j in 0..n.min(to_u64(data.len())) {
                if j % 256 == 255 {
                    cx.checkpoint().await;
                }
                let Some(key) = ints.long(&mut r) else {
                    break 'pools;
                };
                let start = r.pos();
                decoder.budget = VALUE_BUDGET;
                if decoder.value(&mut r, type_id, false, 0).is_none() {
                    pools.error = Some(
                        Diagnostic::malformed(format!(
                            "undecodable {} constant",
                            meta.class_name(type_id)
                        ))
                        .at(span),
                    );
                    break 'pools;
                }
                pools.index.entry((type_id, key)).or_insert((index, start));
            }
        }
        cx.charge(to_u64(data.len()) / 64).await;
        pools.events.push((at, data));
        if delta == 0 {
            break;
        }
        at = u64::try_from(i128::from(at).saturating_add(i128::from(delta))).unwrap_or(0);
    }
    Ok(())
}

/// Context for rendering values.
struct View<'a> {
    meta: &'a Meta,
    pools: &'a Pools,
    chunk: &'a Chunk,
}

impl View<'_> {
    /// The constant `(type, key)`: its decoded value and its span.
    fn constant(&self, type_id: u64, key: u64) -> Option<(Val, Span)> {
        let &(event, start) = self.pools.index.get(&(type_id, key))?;
        let (at, data) = self.pools.events.get(event)?;
        let mut r = Reader::at(data, start);
        let v = Decoder::new(self.meta, self.chunk.ints).value(&mut r, type_id, false, 0)?;
        let span = self.chunk.span.sub(
            at.saturating_add(to_u64(start)),
            to_u64(r.pos().saturating_sub(start)),
        );
        Some((v, span))
    }

    fn field<'b>(
        &self,
        type_id: u64,
        fields: &'b [(usize, Val, usize, usize)],
        name: &str,
    ) -> Option<&'b Val> {
        let class = self.meta.classes.get(&type_id)?;
        fields
            .iter()
            .find(|(n, ..)| class.fields.get(*n).is_some_and(|f| f.name == name))
            .map(|(_, v, ..)| v)
    }

    /// A short rendering of a value, resolving references `depth` deep.
    fn render(&self, v: &Val, depth: usize) -> String {
        match v {
            Val::Null => "null".to_owned(),
            Val::Bool(b) => b.to_string(),
            Val::Int(i) => i.to_string(),
            Val::Float { value, bits } => crate::render::float(*value, *bits),
            Val::Str(s) => s.clone(),
            Val::Ref { type_id, key } => {
                if *key == 0 {
                    return "null".to_owned();
                }
                match (depth, self.constant(*type_id, *key)) {
                    (1.., Some((c, _))) => self.render(&c, depth.saturating_sub(1)),
                    _ => format!("{}#{key}", short_type(&self.meta.class_name(*type_id))),
                }
            }
            Val::Array(items) => {
                let shown: Vec<String> = items
                    .iter()
                    .take(3)
                    .map(|(v, ..)| self.render(v, depth))
                    .collect();
                let more = if items.len() > 3 { ", …" } else { "" };
                format!("[{}{more}]", shown.join(", "))
            }
            Val::Struct(type_id, fields) => self.render_struct(*type_id, fields, depth),
        }
    }

    fn render_struct(
        &self,
        type_id: u64,
        fields: &[(usize, Val, usize, usize)],
        depth: usize,
    ) -> String {
        let get = |name: &str| {
            self.field(type_id, fields, name)
                .map(|v| self.render(v, depth))
        };
        let name = self.meta.class_name(type_id);
        let s = match name.as_str() {
            "jdk.types.Symbol"
            | "jdk.types.ThreadGroup"
            | "jdk.types.Package"
            | "jdk.types.Module" => get("string").or_else(|| get("name")),
            "java.lang.Thread" | "jdk.types.Thread" => get("javaName")
                .filter(|s| s != "null")
                .or_else(|| get("osName")),
            "java.lang.Class" | "jdk.types.Class" => get("name").map(|s| s.replace('/', ".")),
            "jdk.types.Method" => match (get("type"), get("name")) {
                (Some(t), Some(n)) => Some(format!("{t}.{n}")),
                _ => None,
            },
            "jdk.types.StackFrame" => get("method").map(|m| match get("lineNumber") {
                Some(l) if l != "-1" && l != "0" => format!("{m} line {l}"),
                _ => m,
            }),
            "jdk.types.StackTrace" => match self.field(type_id, fields, "frames") {
                Some(Val::Array(frames)) => Some(match frames.first() {
                    Some((top, ..)) => format!(
                        "{}, top {}",
                        plural(to_u64(frames.len()), "frame"),
                        self.render(top, depth)
                    ),
                    None => "no frames".to_owned(),
                }),
                _ => None,
            },
            _ => None,
        };
        s.unwrap_or_else(|| {
            if let [(_, only, ..)] = fields {
                return self.render(only, depth);
            }
            let class = self.meta.classes.get(&type_id);
            let parts: Vec<String> = fields
                .iter()
                .take(4)
                .map(|(n, v, ..)| {
                    let fname = class
                        .and_then(|c| c.fields.get(*n))
                        .map_or("?", |f| f.name.as_str());
                    format!("{fname}: {}", self.render(v, depth.min(1)))
                })
                .collect();
            clip(&format!("{{{}}}", parts.join(", ")), 120)
        })
    }
}

fn short_type(name: &str) -> &str {
    name.rsplit('.').next().unwrap_or(name)
}

fn time_of_day(nanos: u64) -> String {
    let secs = i64::try_from(nanos / 1_000_000_000).unwrap_or(0);
    let (y, m, d) = civil(secs.div_euclid(86_400));
    let t = secs.rem_euclid(86_400);
    format!(
        "{y:04}-{m:02}-{d:02} {:02}:{:02}:{:02}.{:09} UTC",
        t / 3600,
        t % 3600 / 60,
        t % 60,
        nanos % 1_000_000_000
    )
}

fn timestamp(nanos: u64) -> Value {
    Value::Timestamp {
        unix_seconds: i64::try_from(nanos / 1_000_000_000).unwrap_or(0),
    }
}

fn duration(nanos: u64) -> String {
    match nanos {
        0..1_000 => format!("{nanos} ns"),
        1_000..1_000_000 => format!("{:.3} µs", nanos as f64 / 1e3),
        1_000_000..1_000_000_000 => format!("{:.3} ms", nanos as f64 / 1e6),
        _ => format!("{:.3} s", nanos as f64 / 1e9),
    }
}

// ---------------------------------------------------------------------------
// Dissection

async fn chunk_at(cx: &Cx, file: Span, at: u64) -> Result<(Chunk, ChunkHeader)> {
    let span = file.sub(at, HEADER_LEN);
    let (h, _) = crate::dsl::Cursor::new(cx, span, BE)
        .record::<ChunkHeader>()
        .await?;
    let len = h.size.max(HEADER_LEN);
    let chunk = Chunk {
        span: file.sub(at, len),
        ints: Ints {
            compressed: h.flags & 1 != 0,
        },
        clock: Clock {
            start_nanos: h.start_nanos,
            start_ticks: h.start_ticks,
            ticks_per_second: h.ticks_per_second,
        },
        meta: Span::zeros(0),
        cp_offset: h.cp_offset,
    };
    Ok((chunk, h))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (mut at, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    let (_, h) = chunk_at(&cx, file, 0).await?;
    cx.annotate(format!(
        "JDK Flight Recorder recording, format {}.{}, started {}",
        h.major,
        h.minor,
        time_of_day(h.start_nanos)
    ));
    while at < file.len {
        let mark = (at, index);
        cx.mark(move || mark);
        let head = cx.read_avail(file.sub(at, 4)).await?;
        if head.as_slice() != b"FLR\0" {
            cx.push(
                data_node("Trailing data", file.tail(at), file.len.saturating_sub(at))
                    .diag(Diagnostic::malformed("no chunk magic")),
            )
            .await;
            break;
        }
        let (chunk, h) = chunk_at(&cx, file, at).await?;
        let mut node = Node::new(format!("Chunk {index}"))
            .span(chunk.span)
            .summary(format!(
                "{}, {}{}",
                time_of_day(h.start_nanos),
                crate::formats::util::fmt::size(chunk.span.len),
                if h.flags & 2 != 0 { ", final" } else { "" }
            ));
        if chunk.span.len < h.size {
            node = node.diag(Diagnostic::truncated(
                Span::new(chunk.span.source, chunk.span.offset, h.size),
                chunk.span.len,
            ));
        }
        if h.major != 2 {
            node = node.diag(Diagnostic::unsupported(format!(
                "format {}.{} (2.x is supported)",
                h.major, h.minor
            )));
        }
        let mut chunk = chunk;
        chunk.meta = chunk.span.sub(h.meta_offset, 0);
        cx.push(node.lazy(chunk_node, (chunk.clone(), h.meta_offset, h.major)))
            .await;
        at = at.saturating_add(chunk.span.len.max(HEADER_LEN));
        index = index.saturating_add(1);
    }
    Ok(())
}

/// The metadata event's span (its size is its first integer).
async fn meta_span(cx: &Cx, chunk: &Chunk, offset: u64) -> Option<Span> {
    if offset < HEADER_LEN || offset >= chunk.span.len {
        return None;
    }
    let head = cx.read_avail(chunk.span.sub(offset, 10)).await.ok()?;
    let size = chunk.ints.int(&mut Reader::new(&head))?;
    Some(chunk.span.sub(offset, size))
}

async fn chunk_node(cx: Cx, (mut chunk, meta_offset, major): (Chunk, u64, u16)) -> Result<()> {
    let (pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    if pos == 0 {
        cx.mark(|| (0u64, 0u64));
        cx.push(
            crate::formats::util::binutil::data_node(
                "Header",
                chunk.span.sub(0, HEADER_LEN),
                HEADER_LEN,
            )
            .lazy(chunk_header, chunk.span.sub(0, HEADER_LEN)),
        )
        .await;
    }
    if major != 2 {
        return Ok(());
    }
    let Some(meta_span) = meta_span(&cx, &chunk, meta_offset).await else {
        cx.diag(Diagnostic::malformed("metadata offset outside the chunk"));
        return Ok(());
    };
    chunk.meta = meta_span;
    let meta = metadata(&cx, meta_span, chunk.ints).await;
    if let Some(e) = &meta.error {
        cx.diag(e.clone());
    }
    let pools = pools(&cx, &chunk, &meta).await;
    if let Some(e) = &pools.error {
        cx.diag(e.clone());
    }
    let view = View {
        meta: &meta,
        pools: &pools,
        chunk: &chunk,
    };
    let mut pos = pos.max(HEADER_LEN);
    let chunk_arc = Arc::new(chunk.clone());
    while pos < chunk.span.len {
        let mark = (pos, index);
        cx.mark(move || mark);
        let head = cx.read_avail(chunk.span.sub(pos, 20)).await?;
        let mut r = Reader::new(&head);
        let (Some(size), Some(type_id)) = (chunk.ints.int(&mut r), chunk.ints.long(&mut r)) else {
            cx.push(data_node(
                "Trailing bytes",
                chunk.span.tail(pos),
                chunk.span.len.saturating_sub(pos),
            ))
            .await;
            break;
        };
        if size == 0 {
            cx.push(
                data_node("Event", chunk.span.tail(pos), 0)
                    .diag(Diagnostic::malformed("event of size 0")),
            )
            .await;
            break;
        }
        let span = chunk.span.sub(pos, size);
        let mut node = match type_id {
            0 => Node::new("Metadata").summary(plural(to_u64(meta.classes.len()), "type")),
            1 => {
                let mut n = Node::new("Checkpoint");
                if let Ok(data) = cx.read(span.sub(0, 64)).await {
                    n = n.summary(checkpoint_summary(chunk.ints, &data));
                }
                n
            }
            _ => {
                let name = meta.class_name(type_id);
                let mut n = Node::new(name);
                if let Ok(data) = cx.read(span).await {
                    n = n.summary(event_summary(&view, type_id, &data));
                }
                n
            }
        }
        .span(span);
        if span.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, size),
                span.len,
            ));
        }
        let node = match type_id {
            0 => node.lazy(metadata_event, (chunk_arc.clone(), span)),
            1 => node.lazy(checkpoint_event, (chunk_arc.clone(), span)),
            _ => node.lazy(event, (chunk_arc.clone(), span, type_id)),
        };
        cx.push(node).await;
        cx.progress_in(chunk.span, pos);
        pos = pos.saturating_add(size);
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn chunk_header(cx: Cx, span: Span) -> Result<()> {
    let (h, _) = crate::dsl::Cursor::new(&cx, span, BE)
        .record::<ChunkHeader>()
        .await?;
    cx.emit(Node::new("Magic").span(span.sub(0, 4)).value(text("FLR")));
    cx.emit(
        Node::new("Major version")
            .span(span.sub(4, 2))
            .value(uint(h.major, 16)),
    );
    cx.emit(
        Node::new("Minor version")
            .span(span.sub(6, 2))
            .value(uint(h.minor, 16)),
    );
    cx.emit(
        Node::new("Chunk size")
            .span(span.sub(8, 8))
            .value(uint(h.size, 64)),
    );
    cx.emit(
        Node::new("Constant pool offset")
            .span(span.sub(16, 8))
            .value(hex(h.cp_offset, 64))
            .desc("Offset of the last checkpoint event, from the chunk start")
            .target(Span::new(
                span.source,
                span.offset.saturating_add(h.cp_offset),
                0,
            )),
    );
    cx.emit(
        Node::new("Metadata offset")
            .span(span.sub(24, 8))
            .value(hex(h.meta_offset, 64))
            .target(Span::new(
                span.source,
                span.offset.saturating_add(h.meta_offset),
                0,
            )),
    );
    cx.emit(
        Node::new("Start time")
            .span(span.sub(32, 8))
            .value(timestamp(h.start_nanos))
            .summary(time_of_day(h.start_nanos)),
    );
    cx.emit(
        Node::new("Duration")
            .span(span.sub(40, 8))
            .value(uint(h.duration, 64))
            .summary(duration(h.duration)),
    );
    cx.emit(
        Node::new("Start ticks")
            .span(span.sub(48, 8))
            .value(uint(h.start_ticks, 64)),
    );
    cx.emit(
        Node::new("Ticks per second")
            .span(span.sub(56, 8))
            .value(uint(h.ticks_per_second, 64)),
    );
    cx.emit(
        Node::new("Generation")
            .span(span.sub(64, 1))
            .value(uint(h.generation, 8))
            .summary(match h.generation {
                0 => "complete",
                255 => "being written",
                _ => "flushed",
            }),
    );
    cx.emit(
        Node::new("Padding")
            .span(span.sub(65, 1))
            .value(uint(h._pad, 8)),
    );
    cx.emit(
        Node::new("Flags")
            .span(span.sub(66, 2))
            .value(flags(CHUNK_FLAGS, h.flags.into(), 16)),
    );
    Ok(())
}

/// The kind and pool count of a checkpoint event, from its first bytes.
fn checkpoint_summary(ints: Ints, data: &[u8]) -> String {
    let mut r = Reader::new(data);
    for _ in 0..5 {
        if ints.long(&mut r).is_none() {
            return String::new();
        }
    }
    let (Some(kind), Some(pools)) = (r.u8(), ints.int(&mut r)) else {
        return String::new();
    };
    let what = match kind {
        0 => "",
        1 => ", flush",
        2 => ", chunk header",
        4 => ", statics",
        8 => ", thread",
        _ => ", mixed",
    };
    format!("{}{what}", plural(pools, "pool"))
}

/// The first fields of an event after its timestamps, rendered.
fn event_summary(view: &View, type_id: u64, data: &[u8]) -> String {
    let mut r = Reader::new(data);
    let ints = view.chunk.ints;
    if ints.int(&mut r).is_none() || ints.long(&mut r).is_none() {
        return String::new();
    }
    let Some(Val::Struct(_, fields)) =
        Decoder::new(view.meta, ints).value(&mut r, type_id, false, 0)
    else {
        return "undecodable".to_owned();
    };
    let Some(class) = view.meta.classes.get(&type_id) else {
        return String::new();
    };
    let mut parts = Vec::new();
    let mut time = None;
    for (n, v, ..) in &fields {
        let Some(f) = class.fields.get(*n) else {
            continue;
        };
        if f.name == "startTime" {
            if let Val::Int(t) = v {
                time = view
                    .chunk
                    .clock
                    .epoch_nanos(u64::from_ne_bytes(t.to_ne_bytes()));
            }
            continue;
        }
        if f.name == "eventThread" || f.name == "stackTrace" || parts.len() >= 2 {
            continue;
        }
        parts.push(format!("{}: {}", f.name, render_field(view, f, v, 3)));
    }
    let mut s = time.map(time_of_day).unwrap_or_default();
    if !parts.is_empty() {
        if !s.is_empty() {
            s.push_str(", ");
        }
        s.push_str(&parts.join(", "));
    }
    clip(&s, 160)
}

/// A field's value rendered with its unit.
fn render_field(view: &View, f: &FieldDef, v: &Val, depth: usize) -> String {
    if let Val::Int(i) = v {
        let raw = u64::from_ne_bytes(i.to_ne_bytes());
        let clock = view.chunk.clock;
        if let Some(u) = f.timestamp {
            let ns = match u {
                Unit::Ticks => clock.epoch_nanos(raw),
                Unit::EpochMillis | Unit::Millis => raw.checked_mul(1_000_000),
                _ => Some(raw),
            };
            if let Some(ns) = ns {
                return time_of_day(ns);
            }
        }
        if let Some(u) = f.timespan {
            let ns = match u {
                Unit::Ticks => clock.ticks_to_nanos(raw),
                Unit::Micros => raw.checked_mul(1_000),
                Unit::Millis | Unit::EpochMillis => raw.checked_mul(1_000_000),
                Unit::Seconds => raw.checked_mul(1_000_000_000),
                _ => Some(raw),
            };
            if *i == i64::MIN || *i == i64::MAX {
                return "infinite".to_owned();
            }
            if let Some(ns) = ns {
                return duration(ns);
            }
        }
    }
    view.render(v, depth)
}

/// A node for a decoded value. `data` and `base` locate the value's buffer
/// in the chunk.
fn value_node(
    view: &View,
    name: String,
    f: Option<&FieldDef>,
    v: &Val,
    span: Span,
    chunk: &Arc<Chunk>,
    path: &Path,
) -> Node {
    let mut node = Node::new(name).span(span);
    if let Some(label) = f.and_then(|f| f.label.as_deref()) {
        node = node.desc(label.to_owned());
    }
    let rendered = match f {
        Some(f) => render_field(view, f, v, 4),
        None => view.render(v, 4),
    };
    match v {
        Val::Null => node.summary("null"),
        Val::Bool(b) => node.value(Value::Bool(*b)),
        Val::Int(i) => {
            let unsigned = f.is_some_and(|f| f.unsigned);
            let node = if unsigned {
                node.value(uint(u64::from_ne_bytes(i.to_ne_bytes()), 64))
            } else {
                node.value(int(*i, 64))
            };
            let node = if f.is_some_and(|f| f.timestamp.is_some()) {
                node.value(timestamp(match f.and_then(|f| f.timestamp) {
                    Some(Unit::Ticks) => view
                        .chunk
                        .clock
                        .epoch_nanos(u64::from_ne_bytes(i.to_ne_bytes()))
                        .unwrap_or(0),
                    _ => 0,
                }))
            } else {
                node
            };
            if rendered != i.to_string() {
                node.summary(rendered)
            } else {
                node
            }
        }
        Val::Float { value, bits } => node.value(Value::Float {
            value: *value,
            bits: *bits,
        }),
        Val::Str(s) => node.value(text(s.clone())),
        Val::Ref { type_id, key } => {
            let mut node = node.value(uint(*key, 64)).summary(if *key == 0 {
                "null".to_owned()
            } else {
                format!("{} {rendered}", short_type(&view.meta.class_name(*type_id)))
            });
            if *key != 0
                && let Some((_, target)) = view.constant(*type_id, *key)
            {
                node = node.target(target);
                // Constants refer to constants: follow them only along acyclic,
                // bounded paths.
                match path.enter(type_id.wrapping_shl(40) ^ *key, 32) {
                    Ok(p) => node = node.lazy(constant_node, (chunk.clone(), *type_id, *key, p)),
                    Err(d) => node = node.diag(d),
                }
            }
            node
        }
        Val::Array(items) => node
            .summary(format!(
                "{}: {rendered}",
                plural(to_u64(items.len()), "item")
            ))
            .lazy(
                value_children,
                (
                    chunk.clone(),
                    span,
                    f.map(|f| f.type_id).unwrap_or(0),
                    f.is_some_and(|f| f.cp),
                    true,
                    path.clone(),
                ),
            ),
        Val::Struct(type_id, _) => node.summary(rendered).lazy(
            value_children,
            (chunk.clone(), span, *type_id, false, false, path.clone()),
        ),
    }
}

/// Context loaded for an expansion inside a chunk.
async fn load(cx: &Cx, chunk: &Chunk) -> (Arc<Meta>, Arc<Pools>) {
    let meta = metadata(cx, chunk.meta, chunk.ints).await;
    let pools = pools(cx, chunk, &meta).await;
    (meta, pools)
}

/// Emits the fields of a struct value (or the items of an array) read at
/// `span`.
async fn value_children(
    cx: Cx,
    (chunk, span, type_id, cp, array, path): (Arc<Chunk>, Span, u64, bool, bool, Path),
) -> Result<()> {
    let (meta, pools) = load(&cx, &chunk).await;
    let view = View {
        meta: &meta,
        pools: &pools,
        chunk: &chunk,
    };
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let mut d = Decoder::new(&meta, chunk.ints);
    if array {
        let count = chunk.ints.int(&mut r).unwrap_or(0);
        for i in 0..count.min(to_u64(data.len())) {
            let start = r.pos();
            d.budget = VALUE_BUDGET;
            let Some(v) = d.value(&mut r, type_id, cp, 0) else {
                cx.diag(Diagnostic::malformed("undecodable array item"));
                break;
            };
            let s = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
            cx.push(value_node(
                &view,
                format!("[{i}]"),
                None,
                &v,
                s,
                &chunk,
                &path,
            ))
            .await;
        }
        return Ok(());
    }
    emit_struct(&cx, &view, &chunk, &mut d, &mut r, span, type_id, &path).await;
    Ok(())
}

/// Decodes and emits the fields of a struct of `type_id` from `r`, whose
/// buffer starts at `span`.
#[allow(clippy::too_many_arguments)]
async fn emit_struct(
    cx: &Cx,
    view: &View<'_>,
    chunk: &Arc<Chunk>,
    d: &mut Decoder<'_>,
    r: &mut Reader<'_>,
    span: Span,
    type_id: u64,
    path: &Path,
) {
    let Some(class) = view.meta.classes.get(&type_id) else {
        cx.diag(Diagnostic::malformed(format!("unknown type {type_id}")));
        return;
    };
    for f in &class.fields {
        let start = r.pos();
        d.budget = VALUE_BUDGET;
        let v = if f.array {
            let Some(count) = d.ints.int(r) else { break };
            let mut items = Vec::new();
            let mut ok = true;
            for _ in 0..count.min(to_u64(r.rest().len())) {
                let s = r.pos();
                match d.value(r, f.type_id, f.cp, 1) {
                    Some(v) => items.push((v, s, r.pos())),
                    None => {
                        ok = false;
                        break;
                    }
                }
            }
            if !ok {
                cx.emit(Node::new(f.name.clone()).diag(Diagnostic::malformed("undecodable array")));
                break;
            }
            Val::Array(items)
        } else {
            match d.value(r, f.type_id, f.cp, 0) {
                Some(v) => v,
                None => {
                    cx.emit(
                        Node::new(f.name.clone())
                            .span(span.tail(to_u64(start)))
                            .diag(Diagnostic::malformed(format!(
                                "undecodable {}",
                                view.meta.class_name(f.type_id)
                            ))),
                    );
                    break;
                }
            }
        };
        let s = span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        cx.push(value_node(
            view,
            f.name.clone(),
            Some(f),
            &v,
            s,
            chunk,
            path,
        ))
        .await;
    }
}

async fn constant_node(
    cx: Cx,
    (chunk, type_id, key, path): (Arc<Chunk>, u64, u64, Path),
) -> Result<()> {
    let (meta, pools) = load(&cx, &chunk).await;
    let view = View {
        meta: &meta,
        pools: &pools,
        chunk: &chunk,
    };
    let Some((v, span)) = view.constant(type_id, key) else {
        return Err(Diagnostic::malformed(format!(
            "no constant {key} of {}",
            meta.class_name(type_id)
        )));
    };
    match v {
        Val::Struct(..) => {
            let data = cx.read(span).await?;
            let mut r = Reader::new(&data);
            let mut d = Decoder::new(&meta, chunk.ints);
            emit_struct(&cx, &view, &chunk, &mut d, &mut r, span, type_id, &path).await;
        }
        other => cx.emit(value_node(
            &view,
            "Value".to_owned(),
            None,
            &other,
            span,
            &chunk,
            &path,
        )),
    }
    Ok(())
}

async fn event(cx: Cx, (chunk, span, type_id): (Arc<Chunk>, Span, u64)) -> Result<()> {
    let (meta, pools) = load(&cx, &chunk).await;
    let view = View {
        meta: &meta,
        pools: &pools,
        chunk: &chunk,
    };
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let ints = chunk.ints;
    let start = r.pos();
    if let Some(size) = ints.int(&mut r) {
        cx.emit(
            Node::new("Size")
                .span(span.sub(to_u64(start), to_u64(r.pos())))
                .value(uint(size, 64)),
        );
    }
    let start = r.pos();
    if ints.long(&mut r).is_some() {
        let mut node = Node::new("Type")
            .span(span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start))))
            .value(uint(type_id, 64))
            .summary(meta.class_name(type_id));
        if let Some(label) = meta.classes.get(&type_id).and_then(|c| c.label.clone()) {
            node = node.desc(label);
        }
        cx.emit(node);
    }
    let mut d = Decoder::new(&meta, ints);
    emit_struct(
        &cx,
        &view,
        &chunk,
        &mut d,
        &mut r,
        span,
        type_id,
        &Path::new(),
    )
    .await;
    if r.pos() < data.len() {
        let rest = to_u64(r.pos());
        cx.emit(data_node(
            "Unparsed",
            span.tail(rest),
            span.len.saturating_sub(rest),
        ));
    }
    Ok(())
}

async fn checkpoint_event(cx: Cx, (chunk, span): (Arc<Chunk>, Span)) -> Result<()> {
    let meta = metadata(&cx, chunk.meta, chunk.ints).await;
    let data = cx.read(span).await?;
    let ints = chunk.ints;
    let mut r = Reader::new(&data);
    let field =
        |r: &Reader, start: usize| span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
    let start = r.pos();
    let Some(size) = ints.int(&mut r) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Size")
            .span(field(&r, start))
            .value(uint(size, 64)),
    );
    let start = r.pos();
    let Some(t) = ints.long(&mut r) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Type")
            .span(field(&r, start))
            .value(uint(t, 64))
            .summary("checkpoint"),
    );
    let start = r.pos();
    let Some(time) = ints.long(&mut r) else {
        return Ok(());
    };
    let mut node = Node::new("Start time")
        .span(field(&r, start))
        .value(uint(time, 64));
    if let Some(ns) = chunk.clock.epoch_nanos(time) {
        node = node.summary(time_of_day(ns));
    }
    cx.emit(node);
    let start = r.pos();
    let Some(dur) = ints.long(&mut r) else {
        return Ok(());
    };
    let mut node = Node::new("Duration")
        .span(field(&r, start))
        .value(uint(dur, 64));
    if let Some(ns) = chunk.clock.ticks_to_nanos(dur) {
        node = node.summary(duration(ns));
    }
    cx.emit(node);
    let start = r.pos();
    let Some(delta) = ints.long(&mut r) else {
        return Ok(());
    };
    let delta = i64::from_ne_bytes(delta.to_ne_bytes());
    let mut node = Node::new("Delta to previous")
        .span(field(&r, start))
        .value(int(delta, 64))
        .desc("Offset of the previous checkpoint event from this one; 0 ends the chain");
    if delta != 0 {
        let target = i128::from(span.offset).saturating_add(i128::from(delta));
        if let Ok(t) = u64::try_from(target) {
            node = node.target(Span::new(span.source, t, 0));
        }
    }
    cx.emit(node);
    let start = r.pos();
    let Some(kind) = r.u8() else { return Ok(()) };
    const KINDS: FlagTable = &[
        flag(1, "FLUSH"),
        flag(2, "CHUNK_HEADER"),
        flag(4, "STATICS"),
        flag(8, "THREAD"),
    ];
    cx.emit(
        Node::new("Kind")
            .span(field(&r, start))
            .value(flags(KINDS, kind.into(), 8)),
    );
    let start = r.pos();
    let Some(count) = ints.int(&mut r) else {
        return Ok(());
    };
    cx.emit(
        Node::new("Pools")
            .span(field(&r, start))
            .value(uint(count, 64)),
    );
    let mut d = Decoder::new(&meta, ints);
    for _ in 0..count.min(to_u64(data.len())) {
        let pool_start = r.pos();
        let Some(type_id) = ints.long(&mut r) else {
            break;
        };
        let Some(n) = ints.int(&mut r) else { break };
        let entries_at = r.pos();
        let mut ok = true;
        for _ in 0..n.min(to_u64(data.len())) {
            d.budget = VALUE_BUDGET;
            if ints.long(&mut r).is_none() || d.value(&mut r, type_id, false, 0).is_none() {
                ok = false;
                break;
            }
        }
        let pool_span = field(&r, pool_start);
        let mut node = Node::new(meta.class_name(type_id))
            .span(pool_span)
            .summary(plural(n, "constant"))
            .lazy(
                pool_node,
                (chunk.clone(), span, to_u64(entries_at), type_id, n),
            );
        if !ok {
            node = node.diag(Diagnostic::malformed("undecodable constant"));
            cx.push(node).await;
            break;
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn pool_node(
    cx: Cx,
    (chunk, event, at, type_id, n): (Arc<Chunk>, Span, u64, u64, u64),
) -> Result<()> {
    let (meta, pools) = load(&cx, &chunk).await;
    let view = View {
        meta: &meta,
        pools: &pools,
        chunk: &chunk,
    };
    let data = cx.read(event).await?;
    let ints = chunk.ints;
    let mut r = Reader::at(&data, to_usize(at));
    let mut d = Decoder::new(&meta, ints);
    for _ in 0..n.min(to_u64(data.len())) {
        let start = r.pos();
        let Some(key) = ints.long(&mut r) else { break };
        let vstart = r.pos();
        d.budget = VALUE_BUDGET;
        let Some(v) = d.value(&mut r, type_id, false, 0) else {
            cx.diag(Diagnostic::malformed("undecodable constant"));
            break;
        };
        let entry = event.sub(to_u64(start), to_u64(r.pos().saturating_sub(start)));
        let vspan = event.sub(to_u64(vstart), to_u64(r.pos().saturating_sub(vstart)));
        let rendered = view.render(&v, 4);
        let mut node = Node::new(format!("#{key}"))
            .span(entry)
            .summary(clip(&rendered, 160));
        node = match v {
            Val::Struct(..) => node.lazy(
                value_children,
                (chunk.clone(), vspan, type_id, false, false, Path::new()),
            ),
            Val::Str(s) => node.value(text(s)),
            _ => node,
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn metadata_event(cx: Cx, (chunk, span): (Arc<Chunk>, Span)) -> Result<()> {
    let meta = metadata(&cx, span, chunk.ints).await;
    if let Some(e) = &meta.error {
        cx.diag(e.clone());
    }
    let data = cx.read(span.sub(0, meta.strings_at.max(1))).await?;
    let ints = chunk.ints;
    let mut r = Reader::new(&data);
    for name in ["Size", "Type", "Start time", "Duration", "Metadata ID"] {
        let start = r.pos();
        let Some(v) = ints.long(&mut r) else { break };
        let mut node = Node::new(name)
            .span(span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start))))
            .value(uint(v, 64));
        if name == "Start time"
            && let Some(ns) = chunk.clock.epoch_nanos(v)
        {
            node = node.summary(time_of_day(ns));
        } else if name == "Duration"
            && let Some(ns) = chunk.clock.ticks_to_nanos(v)
        {
            node = node.summary(duration(ns));
        }
        cx.emit(node);
    }
    let strings = span.sub(
        meta.strings_at,
        meta.root_at.saturating_sub(meta.strings_at),
    );
    cx.emit(
        Node::new("Strings")
            .span(strings)
            .summary(plural(to_u64(meta.strings.len()), "string"))
            .lazy(meta_strings, (chunk.clone(), span)),
    );
    if !meta.elems.is_empty() {
        cx.emit(element_node(&meta, &chunk, span, 0));
    }
    Ok(())
}

async fn meta_strings(cx: Cx, (chunk, span): (Arc<Chunk>, Span)) -> Result<()> {
    let meta = metadata(&cx, span, chunk.ints).await;
    let count_end = meta.strings.first().map_or(meta.root_at, |(_, s, _)| *s);
    cx.emit(
        Node::new("Count")
            .span(span.sub(meta.strings_at, count_end.saturating_sub(meta.strings_at)))
            .value(uint(to_u64(meta.strings.len()), 64)),
    );
    let mut i = cx.resume::<usize>().unwrap_or(0);
    while let Some((s, start, end)) = meta.strings.get(i) {
        let at = i;
        cx.mark(move || at);
        let mut node =
            Node::new(format!("[{i}]")).span(span.sub(*start, end.saturating_sub(*start)));
        node = match s {
            Some(s) => node.value(text(s.clone())),
            None => node.summary("null"),
        };
        cx.push(node).await;
        i = i.saturating_add(1);
    }
    Ok(())
}

fn element_node(meta: &Meta, chunk: &Arc<Chunk>, span: Span, index: usize) -> Node {
    let Some(e) = meta.elems.get(index) else {
        return Node::new("?");
    };
    let name = meta.string(e.name);
    let label = match name {
        "class" => format!("class {}", meta.attr(e, "name").unwrap_or("?")),
        "field" => format!("field {}", meta.attr(e, "name").unwrap_or("?")),
        "annotation" => format!(
            "annotation {}",
            meta.attr(e, "class")
                .and_then(|s| s.parse::<u64>().ok())
                .map_or_else(|| "?".to_owned(), |id| meta.class_name(id))
        ),
        other => other.to_owned(),
    };
    let attrs: Vec<String> = e
        .attrs
        .iter()
        .map(|(k, v)| format!("{}={}", meta.string(*k), meta.string(*v)))
        .collect();
    let mut node = Node::new(label)
        .span(span.sub(e.start, e.end.saturating_sub(e.start)))
        .maybe_summary(clip(&attrs.join(" "), 160));
    if !e.attrs.is_empty() || !e.children.is_empty() {
        node = node.lazy(element_children, (chunk.clone(), span, index));
    }
    node
}

async fn element_children(cx: Cx, (chunk, span, index): (Arc<Chunk>, Span, usize)) -> Result<()> {
    let meta = metadata(&cx, span, chunk.ints).await;
    let Some(e) = meta.elems.get(index) else {
        return Ok(());
    };
    for (k, v) in &e.attrs {
        cx.push(Node::new(meta.string(*k).to_owned()).value(text(meta.string(*v).to_owned())))
            .await;
    }
    for &c in &e.children {
        cx.push(element_node(&meta, &chunk, span, c)).await;
    }
    Ok(())
}
