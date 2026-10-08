//! Delphi / C++Builder / Lazarus binary form streams (`TPF0`): the component
//! trees VCL, CLX, FireMonkey and LCL forms are stored as, in `.dfm`/`.lfm`
//! files and in the `RT_RCDATA` resources of the programs built from them.
//!
//! Layout (from `TWriter`/`TReader` in `Classes.pas`): the signature `TPF0`,
//! then one component. A component is an optional filer-flags byte
//! (`0xF0 | flags`: 1 inherited, 2 child position follows as an integer
//! value, 4 inline), the class name and the component name (short strings:
//! length byte + bytes), its properties (a short-string name and a typed
//! value each, ending in an empty name) and its child components (ending in
//! a 0 byte). Values start with a `TValueType` byte; lists, sets and
//! collections nest, ending in a 0 byte.

use std::collections::BTreeMap;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::lines::{float, int};
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

/// Deepest nesting of components and values we follow.
const MAX_DEPTH: u32 = 64;

fn probe(h: &Head<'_>) -> bool {
    let Some(rest) = h.data.strip_prefix(b"TPF0") else {
        return false;
    };
    let rest = match rest.first() {
        Some(&b) if b & 0xf8 == 0xf0 => rest.get(1..).unwrap_or_default(),
        _ => rest,
    };
    // A class name: a short identifier.
    match rest.split_first() {
        Some((&len, name)) if (1..=64).contains(&len) => name
            .get(..usize::from(len))
            .is_some_and(|n| n.iter().all(|&c| c.is_ascii_alphanumeric() || c == b'_')),
        _ => false,
    }
}

declare_format!(pub DFM = "delphi-dfm", "Delphi / Lazarus binary form (TPF0)", ["dfm", "lfm", "xfm", "fmx"], "application/x-delphi-form",
    Probe::Custom(probe), dfm);

const VALUE_TYPES: EnumTable = &[
    (0, "vaNull"),
    (1, "vaList"),
    (2, "vaInt8"),
    (3, "vaInt16"),
    (4, "vaInt32"),
    (5, "vaExtended"),
    (6, "vaString"),
    (7, "vaIdent"),
    (8, "vaFalse"),
    (9, "vaTrue"),
    (10, "vaBinary"),
    (11, "vaSet"),
    (12, "vaLString"),
    (13, "vaNil"),
    (14, "vaCollection"),
    (15, "vaSingle"),
    (16, "vaCurrency"),
    (17, "vaDate"),
    (18, "vaWString"),
    (19, "vaInt64"),
    (20, "vaUTF8String"),
    (21, "vaDouble"),
];

fn malformed(what: &str, at: usize) -> Diagnostic {
    Diagnostic::malformed(format!("{what} at offset {at:#x}"))
}

/// Values, properties and set items parsed between two checkpoints.
const TICK: u32 = 256;
/// Bytes of a string decoded between two checkpoints.
const TEXT_CHUNK: usize = 4096;

/// A byte cursor over an in-memory stream; positions are byte offsets.
struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Reader<'_> {
    fn u8(&mut self) -> Result<u8> {
        let b = self
            .data
            .get(self.pos)
            .copied()
            .ok_or_else(|| malformed("unexpected end of stream", self.pos))?;
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    fn take(&mut self, n: usize) -> Result<&[u8]> {
        let end = self
            .pos
            .checked_add(n)
            .filter(|&e| e <= self.data.len())
            .ok_or_else(|| malformed("unexpected end of stream", self.pos))?;
        let bytes = self.data.get(self.pos..end).unwrap_or_default();
        self.pos = end;
        Ok(bytes)
    }

    fn u32(&mut self) -> Result<u32> {
        let b = self.take(4)?;
        Ok(u32::from_le_bytes(b.try_into().unwrap_or_default()))
    }

    fn short_bytes(&mut self) -> Result<&[u8]> {
        let len = self.u8()?;
        self.take(len.into())
    }

    fn short_string(&mut self) -> Result<String> {
        Ok(crate::text::latin1(self.short_bytes()?))
    }

    /// An integer value's data (`kind` 2, 3, 4 or 19).
    fn int(&mut self, kind: u8) -> Result<i64> {
        Ok(match kind {
            2 => i8::from_le_bytes([self.u8()?]).into(),
            3 => i16::from_le_bytes(self.take(2)?.try_into().unwrap_or_default()).into(),
            4 => i32::from_le_bytes(self.take(4)?.try_into().unwrap_or_default()).into(),
            _ => i64::from_le_bytes(self.take(8)?.try_into().unwrap_or_default()),
        })
    }
}

/// A decoded value; compound values are located by the parse.
enum Parsed {
    Null,
    List,
    Int(i64),
    Float(f64),
    Text(String),
    Ident(String),
    Bool(bool),
    Binary {
        at: usize,
        len: usize,
    },
    Set(String),
    Nil,
    Collection,
    Currency(i64),
    /// `TDateTime`: days since 1899-12-30.
    Date(f64),
}

/// A component, as offsets into the stream.
struct Comp {
    flags: Option<(usize, u8)>,
    position: Option<(usize, i64)>,
    class: (usize, String),
    name: (usize, String),
    properties: Vec<(usize, usize)>,
    /// Indices of the child components.
    children: Vec<usize>,
    /// This component and all its descendants.
    components: usize,
    start: usize,
    end: usize,
}

/// A collection item: its order value and properties.
struct Item {
    order: Option<(usize, usize)>,
    properties: Vec<(usize, usize)>,
}

/// A form stream parsed once: every component, list, collection and item
/// located, so expansions look their parts up instead of parsing again.
struct Form {
    /// The stream after the signature.
    data: Vec<u8>,
    comps: Vec<Comp>,
    root: usize,
    /// List value offset → element extents.
    lists: BTreeMap<usize, Vec<(usize, usize)>>,
    /// Collection value offset → item extents and order values.
    collections: BTreeMap<usize, Vec<(usize, usize, Option<i64>)>>,
    /// Item offset → item.
    items: BTreeMap<usize, Item>,
}

/// The parse of a form stream: async, charging as it goes.
struct Walker<'a> {
    cx: &'a Cx,
    r: Reader<'a>,
    ticks: u32,
    comps: Vec<Comp>,
    lists: BTreeMap<usize, Vec<(usize, usize)>>,
    collections: BTreeMap<usize, Vec<(usize, usize, Option<i64>)>>,
    items: BTreeMap<usize, Item>,
}

type Step<'s, T> = Pin<Box<dyn Future<Output = Result<T>> + Send + 's>>;

impl Walker<'_> {
    async fn tick(&mut self) {
        self.ticks = self.ticks.saturating_add(1);
        if self.ticks >= TICK {
            self.ticks = 0;
            self.cx.checkpoint().await;
        }
    }
}

/// Skips one value (type byte and data), recording lists and collections.
/// Returns the type and, for integers, the value.
fn value<'s, 'a: 's>(w: &'s mut Walker<'a>, depth: u32) -> Step<'s, (u8, Option<i64>)> {
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("values nested too deeply"));
        }
        w.tick().await;
        let start = w.r.pos;
        let kind = w.r.u8()?;
        let mut int = None;
        match kind {
            0 | 8 | 9 | 13 => {}
            1 => {
                let mut elements = Vec::new();
                while w.r.peek() != Some(0) {
                    if w.r.peek().is_none() {
                        return Err(malformed("unterminated list", start));
                    }
                    let at = w.r.pos;
                    value(w, depth.saturating_add(1)).await?;
                    elements.push((at, w.r.pos));
                }
                w.r.pos = w.r.pos.saturating_add(1);
                w.lists.insert(start, elements);
            }
            2 | 3 | 4 | 19 => int = Some(w.r.int(kind)?),
            5 => {
                w.r.take(10)?;
            }
            15 => {
                w.r.take(4)?;
            }
            16 | 17 | 21 => {
                w.r.take(8)?;
            }
            6 | 7 => {
                w.r.short_bytes()?;
            }
            10 | 12 | 20 => {
                let len = to_usize(w.r.u32()?.into());
                w.r.take(len)?;
            }
            18 => {
                let units = to_usize(w.r.u32()?.into());
                w.r.take(units.saturating_mul(2))?;
            }
            11 => loop {
                w.tick().await;
                if w.r.short_bytes()?.is_empty() {
                    break;
                }
            },
            14 => {
                let mut items = Vec::new();
                while w.r.peek() != Some(0) {
                    let at = w.r.pos;
                    let order = collection_item(w, depth.saturating_add(1)).await?;
                    items.push((at, w.r.pos, order));
                }
                w.r.pos = w.r.pos.saturating_add(1);
                w.collections.insert(start, items);
            }
            _ => return Err(malformed(&format!("unknown value type {kind}"), start)),
        }
        Ok((kind, int))
    })
}

/// One collection item: an optional order value, `vaList`, properties, 0.
/// Returns the order value if present.
fn collection_item<'s, 'a: 's>(w: &'s mut Walker<'a>, depth: u32) -> Step<'s, Option<i64>> {
    Box::pin(async move {
        let start = w.r.pos;
        let (order, order_at) = match w.r.peek() {
            Some(2..=4) => {
                let v = value(w, depth).await?.1;
                (v, Some((start, w.r.pos)))
            }
            None => return Err(malformed("unterminated collection", start)),
            _ => (None, None),
        };
        if w.r.u8()? != 1 {
            return Err(malformed("collection item without vaList", start));
        }
        let properties = properties(w, depth).await?;
        w.items.insert(
            start,
            Item {
                order: order_at,
                properties,
            },
        );
        Ok(order)
    })
}

/// Skips a property list (ending in an empty name); returns the extents of
/// the properties.
fn properties<'s, 'a: 's>(w: &'s mut Walker<'a>, depth: u32) -> Step<'s, Vec<(usize, usize)>> {
    Box::pin(async move {
        let mut out = Vec::new();
        loop {
            let start = w.r.pos;
            if w.r.short_bytes()?.is_empty() {
                return Ok(out);
            }
            value(w, depth.saturating_add(1)).await?;
            out.push((start, w.r.pos));
        }
    })
}

/// Parses a component and its descendants; returns its index.
fn component<'s, 'a: 's>(w: &'s mut Walker<'a>, depth: u32) -> Step<'s, usize> {
    Box::pin(async move {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("components nested too deeply"));
        }
        w.tick().await;
        let start = w.r.pos;
        let mut flags = None;
        let mut position = None;
        if let Some(b) = w.r.peek().filter(|b| b & 0xf0 == 0xf0) {
            flags = Some((w.r.pos, b & 0x0f));
            w.r.pos = w.r.pos.saturating_add(1);
            if b & 0x02 != 0 {
                let at = w.r.pos;
                match value(w, depth).await? {
                    (_, Some(v)) => position = Some((at, v)),
                    _ => return Err(malformed("child position is not an integer", at)),
                }
            }
        }
        let class_at = w.r.pos;
        let class = w.r.short_string()?;
        let name_at = w.r.pos;
        let name = w.r.short_string()?;
        let properties = properties(w, depth).await?;
        let mut children = Vec::new();
        let mut components = 1usize;
        loop {
            match w.r.peek() {
                Some(0) => {
                    w.r.pos = w.r.pos.saturating_add(1);
                    break;
                }
                None => return Err(malformed("unterminated child list", w.r.pos)),
                _ => {
                    let child = component(w, depth.saturating_add(1)).await?;
                    let n = w.comps.get(child).map_or(0, |c| c.components);
                    components = components.saturating_add(n);
                    children.push(child);
                }
            }
        }
        w.comps.push(Comp {
            flags,
            position,
            class: (class_at, class),
            name: (name_at, name),
            properties,
            children,
            components,
            start,
            end: w.r.pos,
        });
        Ok(w.comps.len().saturating_sub(1))
    })
}

/// Parses the stream after the signature.
async fn parse(cx: &Cx, data: Vec<u8>) -> Result<Form> {
    let mut w = Walker {
        cx,
        r: Reader {
            data: &data,
            pos: 0,
        },
        ticks: 0,
        comps: Vec::new(),
        lists: BTreeMap::new(),
        collections: BTreeMap::new(),
        items: BTreeMap::new(),
    };
    let root = component(&mut w, 0).await?;
    let Walker {
        comps,
        lists,
        collections,
        items,
        ..
    } = w;
    Ok(Form {
        data,
        comps,
        root,
        lists,
        collections,
        items,
    })
}

/// The parsed form of `file` (cached).
async fn load(cx: &Cx, file: Span) -> Result<Arc<Form>> {
    if let Some(form) = cx.cached::<Form>(file, "delphi-form") {
        return Ok(form);
    }
    let data = cx.read_avail(file).await?;
    let form = Arc::new(parse(cx, data.get(4..).unwrap_or_default().to_vec()).await?);
    cx.cache(file, "delphi-form", form.clone());
    Ok(form)
}

/// The span of `len` bytes at `pos` of the stream after the signature.
fn at(file: Span, pos: usize, len: usize) -> Span {
    file.sub(to_u64(pos).saturating_add(4), to_u64(len))
}

#[derive(Clone, Copy)]
enum Encoding {
    Latin1,
    Utf8,
    Utf16,
}

impl Encoding {
    fn decode(self, b: &[u8]) -> String {
        match self {
            Encoding::Latin1 => crate::text::latin1(b),
            Encoding::Utf8 => String::from_utf8_lossy(b).into_owned(),
            Encoding::Utf16 => crate::text::utf16(b, crate::fields::Endian::Little),
        }
    }

    /// A point at or just before `end` where decoding can be split without
    /// changing the result: not inside a UTF-8 sequence or a surrogate pair.
    fn split(self, b: &[u8], end: usize) -> usize {
        match self {
            Encoding::Latin1 => end,
            // Before a byte that is not a continuation byte, if one of the
            // last three is; otherwise no sequence crosses `end`.
            Encoding::Utf8 => (end.saturating_sub(3)..end)
                .rev()
                .find(|&i| b.get(i).is_some_and(|&c| c & 0xc0 != 0x80))
                .unwrap_or(end),
            Encoding::Utf16 => {
                let end = end & !1;
                let high = b
                    .get(end.saturating_sub(1))
                    .is_some_and(|&c| c & 0xfc == 0xd8);
                if high { end.saturating_sub(2) } else { end }
            }
        }
    }
}

/// Decodes `b` a chunk at a time, charging as it goes.
async fn decode(cx: &Cx, encoding: Encoding, b: &[u8]) -> String {
    let mut out = String::new();
    let mut pos = 0usize;
    while pos < b.len() {
        let mut end = b.len();
        if end.saturating_sub(pos) > TEXT_CHUNK {
            end = encoding.split(b, pos.saturating_add(TEXT_CHUNK));
        }
        if end <= pos {
            end = b.len();
        }
        out.push_str(&encoding.decode(b.get(pos..end).unwrap_or_default()));
        pos = end;
        if pos < b.len() {
            cx.checkpoint().await;
        }
    }
    out
}

/// Reads one value (type byte and data) for display. Lists and collections
/// are located by the parse and not descended into.
async fn show(cx: &Cx, r: &mut Reader<'_>) -> Result<(u8, Parsed)> {
    let start = r.pos;
    let kind = r.u8()?;
    let parsed = match kind {
        0 => Parsed::Null,
        1 => Parsed::List,
        2 | 3 | 4 | 19 => Parsed::Int(r.int(kind)?),
        5 => Parsed::Float(extended(r.take(10)?)),
        15 => Parsed::Float(f32::from_le_bytes(r.take(4)?.try_into().unwrap_or_default()).into()),
        17 => Parsed::Date(f64::from_le_bytes(
            r.take(8)?.try_into().unwrap_or_default(),
        )),
        21 => Parsed::Float(f64::from_le_bytes(
            r.take(8)?.try_into().unwrap_or_default(),
        )),
        16 => Parsed::Currency(i64::from_le_bytes(
            r.take(8)?.try_into().unwrap_or_default(),
        )),
        6 => Parsed::Text(r.short_string()?),
        7 => Parsed::Ident(r.short_string()?),
        8 => Parsed::Bool(false),
        9 => Parsed::Bool(true),
        13 => Parsed::Nil,
        10 => {
            let len = to_usize(r.u32()?.into());
            let at = r.pos;
            r.take(len)?;
            Parsed::Binary { at, len }
        }
        12 | 20 => {
            let len = to_usize(r.u32()?.into());
            let bytes = r.take(len)?;
            let encoding = if kind == 12 {
                Encoding::Latin1
            } else {
                Encoding::Utf8
            };
            Parsed::Text(decode(cx, encoding, bytes).await)
        }
        18 => {
            let units = to_usize(r.u32()?.into());
            let bytes = r.take(units.saturating_mul(2))?;
            Parsed::Text(decode(cx, Encoding::Utf16, bytes).await)
        }
        11 => {
            let mut items = String::from("[");
            let mut n = 0u32;
            loop {
                n = n.wrapping_add(1);
                if n.is_multiple_of(TICK) {
                    cx.checkpoint().await;
                }
                let item = r.short_string()?;
                if item.is_empty() {
                    break;
                }
                if n > 1 {
                    items.push_str(", ");
                }
                items.push_str(&item);
            }
            items.push(']');
            Parsed::Set(items)
        }
        14 => Parsed::Collection,
        _ => return Err(malformed(&format!("unknown value type {kind}"), start)),
    };
    Ok((kind, parsed))
}
/// An 80-bit x87 extended float.
fn extended(b: &[u8]) -> f64 {
    let mut mant = [0u8; 8];
    mant.copy_from_slice(b.get(..8).unwrap_or(&[0; 8]));
    let mant = u64::from_le_bytes(mant);
    let se = u16::from_le_bytes([
        b.get(8).copied().unwrap_or(0),
        b.get(9).copied().unwrap_or(0),
    ]);
    let exp = i32::from(se & 0x7fff);
    if exp == 0 && mant == 0 {
        return 0.0;
    }
    let m = mant as f64;
    let v = m * 2f64.powi(exp.saturating_sub(16383 + 63));
    if se & 0x8000 != 0 { -v } else { v }
}
/// A component node.
fn component_node(input: Input, form: &Form, index: usize) -> Node {
    let Some(c) = form.comps.get(index) else {
        return Node::new("Component");
    };
    let span = at(input.span, c.start, c.end.saturating_sub(c.start));
    let mut summary = format!(
        "{} properties, {} children",
        c.properties.len(),
        c.children.len()
    );
    if let Some((_, f)) = c.flags {
        summary.push_str(&format!(", {}", flag_names(f)));
    }
    Node::new(format!("{}: {}", display_name(&c.name.1), c.class.1))
        .span(span)
        .summary(summary)
        .lazy(
            crate::expander!(self::expand_component: (Input, usize)),
            (input, index),
        )
}

fn display_name(name: &str) -> &str {
    if name.is_empty() { "(unnamed)" } else { name }
}

fn flag_names(flags: u8) -> String {
    let mut out = Vec::new();
    if flags & 1 != 0 {
        out.push("inherited");
    }
    if flags & 2 != 0 {
        out.push("child position");
    }
    if flags & 4 != 0 {
        out.push("inline");
    }
    if out.is_empty() {
        "no flags".to_owned()
    } else {
        out.join(", ")
    }
}

async fn dfm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = cx.read_avail(file).await?;
    cx.emit(
        Node::new("Signature")
            .span(file.sub(0, 4))
            .value(Value::Text("TPF0".into())),
    );
    let form = match parse(&cx, data.get(4..).unwrap_or_default().to_vec()).await {
        Ok(form) => Arc::new(form),
        Err(e) => {
            cx.annotate("Delphi form");
            return Err(e);
        }
    };
    cx.cache(file, "delphi-form", form.clone());
    let Some(c) = form.comps.get(form.root) else {
        return Ok(());
    };
    cx.emit(component_node(input, &form, form.root));
    cx.annotate(format!(
        "Delphi form {}: {}, {} components",
        display_name(&c.name.1),
        c.class.1,
        c.components
    ));
    let rest = file.tail(to_u64(c.end).saturating_add(4));
    if rest.len > 0 {
        cx.emit(Node::new("Trailing data").span(rest));
    }
    Ok(())
}

async fn expand_component(cx: Cx, (input, index): (Input, usize)) -> Result<()> {
    let form = load(&cx, input.span).await?;
    let Some(c) = form.comps.get(index) else {
        return Ok(());
    };
    let file = input.span;
    if let Some((pos, flags)) = c.flags {
        cx.emit(
            Node::new("Filer flags")
                .span(at(file, pos, 1))
                .value(crate::formats::util::lines::hex(flags.into(), 8))
                .summary(flag_names(flags)),
        );
    }
    if let Some((pos, v)) = c.position {
        cx.emit(
            Node::new("Child position")
                .span(at(file, pos, c.class.0.saturating_sub(pos)))
                .value(int(v)),
        );
    }
    cx.emit(
        Node::new("Class")
            .span(at(
                file,
                c.class.0,
                c.class.1.chars().count().saturating_add(1),
            ))
            .value(Value::Text(c.class.1.clone())),
    );
    cx.emit(
        Node::new("Name")
            .span(at(
                file,
                c.name.0,
                c.name.1.chars().count().saturating_add(1),
            ))
            .value(Value::Text(c.name.1.clone())),
    );
    for &(start, end) in &c.properties {
        cx.push(property_node(&cx, input, &form, start, end).await)
            .await;
    }
    for &child in &c.children {
        cx.push(component_node(input, &form, child)).await;
    }
    Ok(())
}

/// A property (`name` + value) at `start..end` of the stream.
async fn property_node(cx: &Cx, input: Input, form: &Form, start: usize, end: usize) -> Node {
    let mut r = Reader {
        data: &form.data,
        pos: start,
    };
    let name = r.short_string().unwrap_or_default();
    let value_at = r.pos;
    let mut node = value_node(cx, input, form, name, value_at, end).await;
    node.span = Some(at(input.span, start, end.saturating_sub(start)));
    node
}

/// A node for the value at `start..end` of the stream.
async fn value_node(
    cx: &Cx,
    input: Input,
    form: &Form,
    name: String,
    start: usize,
    end: usize,
) -> Node {
    let whole = at(input.span, start, end.saturating_sub(start));
    let mut r = Reader {
        data: form.data.get(..end).unwrap_or_default(),
        pos: start,
    };
    let node = Node::new(name).span(whole);
    let (kind, parsed) = match show(cx, &mut r).await {
        Ok(v) => v,
        Err(e) => return node.diag(e),
    };
    let type_name = lookup(VALUE_TYPES, kind.into()).unwrap_or("?");
    match parsed {
        Parsed::Null => node.summary(type_name),
        Parsed::Nil => node.summary("nil"),
        Parsed::Int(v) => node.value(int(v)),
        Parsed::Float(v) => node.value(float(v)).summary(type_name),
        Parsed::Currency(v) => node.value(float(v as f64 / 10_000.0)).summary("vaCurrency"),
        Parsed::Date(days) => {
            let seconds = (days - 25_569.0) * 86_400.0;
            if seconds.is_finite() && seconds.abs() < 1e13 {
                #[allow(clippy::cast_possible_truncation)]
                let unix_seconds = seconds.round() as i64;
                node.value(Value::Timestamp { unix_seconds })
                    .summary(format!("vaDate {days}"))
            } else {
                node.value(float(days)).summary("vaDate")
            }
        }
        Parsed::Text(t) => node.value(Value::Text(t)),
        Parsed::Ident(t) => node.value(Value::Text(t)).summary("identifier"),
        Parsed::Bool(b) => node.value(Value::Bool(b)),
        Parsed::Set(items) => node.value(Value::Text(items)).summary("set"),
        Parsed::List => node.summary("list").lazy(
            crate::expander!(self::expand_list: (Input, usize)),
            (input, start),
        ),
        Parsed::Collection => node.summary("collection").lazy(
            crate::expander!(self::expand_collection: (Input, usize)),
            (input, start),
        ),
        Parsed::Binary { at: pos, len } => {
            let blob = at(input.span, pos, len);
            node.summary(format!("{len} bytes of binary data"))
                .lazy(expand_binary, (input, blob))
        }
    }
}

async fn expand_list(cx: Cx, (input, start): (Input, usize)) -> Result<()> {
    let form = load(&cx, input.span).await?;
    let Some(elements) = form.lists.get(&start) else {
        return Ok(());
    };
    for (index, &(from, to)) in elements.iter().enumerate() {
        let node = value_node(&cx, input, &form, format!("[{index}]"), from, to).await;
        cx.push(node).await;
    }
    Ok(())
}

async fn expand_collection(cx: Cx, (input, start): (Input, usize)) -> Result<()> {
    let form = load(&cx, input.span).await?;
    let Some(items) = form.collections.get(&start) else {
        return Ok(());
    };
    for (index, &(from, to, order)) in items.iter().enumerate() {
        let item = at(input.span, from, to.saturating_sub(from));
        let mut node = Node::new(format!("Item {index}")).span(item).lazy(
            crate::expander!(self::expand_item: (Input, usize)),
            (input, from),
        );
        if let Some(order) = order {
            node = node.summary(format!("order {order}"));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn expand_item(cx: Cx, (input, start): (Input, usize)) -> Result<()> {
    let form = load(&cx, input.span).await?;
    let Some(item) = form.items.get(&start) else {
        return Ok(());
    };
    if let Some((from, to)) = item.order {
        let node = value_node(&cx, input, &form, "Order".to_owned(), from, to).await;
        cx.emit(node);
    }
    for &(from, to) in &item.properties {
        cx.push(property_node(&cx, input, &form, from, to).await)
            .await;
    }
    Ok(())
}

/// Binary property data. `TPicture.Data` starts with the graphic's class
/// name as a short string; `TBitmap` (and `TJPEGImage`) data then starts
/// with its own byte count. Whatever remains is the graphic's file.
async fn expand_binary(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 69)).await?;
    let class = head.split_first().and_then(|(&len, rest)| {
        let name = rest.get(..usize::from(len))?;
        (len >= 2
            && name.first() == Some(&b'T')
            && name.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'_'))
        .then(|| crate::text::latin1(name))
    });
    let mut at = 0u64;
    if let Some(class) = class {
        let len = to_u64(class.len()).saturating_add(1);
        cx.emit(
            Node::new("Graphic class")
                .span(span.sub(0, len))
                .value(Value::Text(class)),
        );
        at = len;
    }
    let size = crate::bytes::u32_le(&head, to_usize(at)).map(u64::from);
    if size.is_some_and(|s| s.saturating_add(4) == span.len.saturating_sub(at)) {
        cx.emit(
            Node::new("Size")
                .span(span.sub(at, 4))
                .value(crate::formats::util::lines::uint(size.unwrap_or(0))),
        );
        at = at.saturating_add(4);
    }
    cx.emit(embedded("Data", input.nested(span.tail(at))));
    Ok(())
}
