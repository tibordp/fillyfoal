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

    fn short_string(&mut self) -> Result<String> {
        let len = self.u8()?;
        let bytes = self.take(len.into())?;
        Ok(crate::text::latin1(bytes))
    }
}

/// A decoded value; compound values keep their extent for lazy expansion.
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
    Set(Vec<String>),
    Nil,
    Collection,
    Currency(i64),
    /// `TDateTime`: days since 1899-12-30.
    Date(f64),
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

/// Reads one value (type byte and data). Lists and collections are skipped
/// over (checked) but not decoded.
fn value(r: &mut Reader<'_>, depth: u32) -> Result<(u8, Parsed)> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit("values nested too deeply"));
    }
    let start = r.pos;
    let kind = r.u8()?;
    let parsed = match kind {
        0 => Parsed::Null,
        1 => {
            while r.peek() != Some(0) {
                if r.peek().is_none() {
                    return Err(malformed("unterminated list", start));
                }
                value(r, depth.saturating_add(1))?;
            }
            r.pos = r.pos.saturating_add(1);
            Parsed::List
        }
        2 => Parsed::Int(i8::from_le_bytes([r.u8()?]).into()),
        3 => Parsed::Int(i16::from_le_bytes(r.take(2)?.try_into().unwrap_or_default()).into()),
        4 => Parsed::Int(i32::from_le_bytes(r.take(4)?.try_into().unwrap_or_default()).into()),
        19 => Parsed::Int(i64::from_le_bytes(
            r.take(8)?.try_into().unwrap_or_default(),
        )),
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
            Parsed::Text(if kind == 12 {
                crate::text::latin1(bytes)
            } else {
                String::from_utf8_lossy(bytes).into_owned()
            })
        }
        18 => {
            let units = to_usize(r.u32()?.into());
            let bytes = r.take(units.saturating_mul(2))?;
            Parsed::Text(crate::text::utf16(bytes, crate::fields::Endian::Little))
        }
        11 => {
            let mut items = Vec::new();
            loop {
                let item = r.short_string()?;
                if item.is_empty() {
                    break;
                }
                items.push(item);
            }
            Parsed::Set(items)
        }
        14 => {
            while r.peek() != Some(0) {
                collection_item(r, depth.saturating_add(1))?;
            }
            r.pos = r.pos.saturating_add(1);
            Parsed::Collection
        }
        _ => return Err(malformed(&format!("unknown value type {kind}"), start)),
    };
    Ok((kind, parsed))
}

/// One collection item: an optional order value, `vaList`, properties, 0.
/// Returns the order value if present.
fn collection_item(r: &mut Reader<'_>, depth: u32) -> Result<Option<i64>> {
    let start = r.pos;
    let order = match r.peek() {
        Some(2..=4) => match value(r, depth)?.1 {
            Parsed::Int(v) => Some(v),
            _ => None,
        },
        None => return Err(malformed("unterminated collection", start)),
        _ => None,
    };
    if r.u8()? != 1 {
        return Err(malformed("collection item without vaList", start));
    }
    properties(r, depth)?;
    Ok(order)
}

/// Skips a property list (ending in an empty name); returns the extents of
/// the properties.
fn properties(r: &mut Reader<'_>, depth: u32) -> Result<Vec<(usize, usize)>> {
    let mut out = Vec::new();
    loop {
        let start = r.pos;
        let name = r.short_string()?;
        if name.is_empty() {
            return Ok(out);
        }
        value(r, depth.saturating_add(1))?;
        out.push((start, r.pos));
    }
}

/// The parts of a component, as offsets.
struct Component {
    flags: Option<(usize, u8)>,
    position: Option<(usize, i64)>,
    class: (usize, String),
    name: (usize, String),
    properties: Vec<(usize, usize)>,
    children: Vec<(usize, usize)>,
    end: usize,
}

fn component(r: &mut Reader<'_>, depth: u32) -> Result<Component> {
    if depth > MAX_DEPTH {
        return Err(Diagnostic::limit("components nested too deeply"));
    }
    let mut flags = None;
    let mut position = None;
    if let Some(b) = r.peek().filter(|b| b & 0xf0 == 0xf0) {
        flags = Some((r.pos, b & 0x0f));
        r.pos = r.pos.saturating_add(1);
        if b & 0x02 != 0 {
            let at = r.pos;
            match value(r, depth)?.1 {
                Parsed::Int(v) => position = Some((at, v)),
                _ => return Err(malformed("child position is not an integer", at)),
            }
        }
    }
    let class_at = r.pos;
    let class = r.short_string()?;
    let name_at = r.pos;
    let name = r.short_string()?;
    let properties = properties(r, depth)?;
    let mut children = Vec::new();
    loop {
        match r.peek() {
            Some(0) => {
                r.pos = r.pos.saturating_add(1);
                break;
            }
            None => return Err(malformed("unterminated child list", r.pos)),
            _ => {
                let start = r.pos;
                component(r, depth.saturating_add(1))?;
                children.push((start, r.pos));
            }
        }
    }
    Ok(Component {
        flags,
        position,
        class: (class_at, class),
        name: (name_at, name),
        properties,
        children,
        end: r.pos,
    })
}

/// A component node (its extent must already be known).
fn component_node(input: Input, span: Span, data: &[u8], depth: u32) -> Node {
    let mut r = Reader { data, pos: 0 };
    let mut node = Node::new("Component").span(span);
    match component(&mut r, depth) {
        Ok(c) => {
            node.name = format!("{}: {}", display_name(&c.name.1), c.class.1).into();
            let mut summary = format!(
                "{} properties, {} children",
                c.properties.len(),
                c.children.len()
            );
            if let Some((_, f)) = c.flags {
                summary.push_str(&format!(", {}", flag_names(f)));
            }
            node = node.summary(summary).lazy(
                crate::expander!(self::expand_component: (Input, Span, u32)),
                (input, span, depth),
            );
        }
        Err(e) => node = node.diag(e),
    }
    node
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
    let body = data.get(4..).unwrap_or_default();
    let mut r = Reader { data: body, pos: 0 };
    match component(&mut r, 0) {
        Ok(c) => {
            let span = file.sub(4, to_u64(c.end));
            cx.emit(component_node(
                input,
                span,
                body.get(..c.end).unwrap_or_default(),
                0,
            ));
            cx.annotate(format!(
                "Delphi form {}: {}, {} components",
                display_name(&c.name.1),
                c.class.1,
                count_components(body.get(..c.end).unwrap_or_default())
            ));
            let rest = file.tail(to_u64(c.end).saturating_add(4));
            if rest.len > 0 {
                cx.emit(Node::new("Trailing data").span(rest));
            }
        }
        Err(e) => {
            cx.annotate("Delphi form");
            return Err(e);
        }
    }
    Ok(())
}

/// Components in a well-formed tree (the root included).
fn count_components(data: &[u8]) -> usize {
    fn walk(data: &[u8], at: usize, depth: u32) -> usize {
        let mut r = Reader { data, pos: at };
        match component(&mut r, depth) {
            Ok(c) => c.children.iter().fold(1usize, |n, &(s, _)| {
                n.saturating_add(walk(data, s, depth.saturating_add(1)))
            }),
            Err(_) => 0,
        }
    }
    walk(data, 0, 0)
}

async fn expand_component(cx: Cx, (input, span, depth): (Input, Span, u32)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader {
        data: &data,
        pos: 0,
    };
    let c = component(&mut r, depth)?;
    let at = |pos: usize, len: usize| span.sub(to_u64(pos), to_u64(len));
    if let Some((pos, flags)) = c.flags {
        cx.emit(
            Node::new("Filer flags")
                .span(at(pos, 1))
                .value(crate::formats::util::lines::hex(flags.into(), 8))
                .summary(flag_names(flags)),
        );
    }
    if let Some((pos, v)) = c.position {
        cx.emit(
            Node::new("Child position")
                .span(at(pos, c.class.0.saturating_sub(pos)))
                .value(int(v)),
        );
    }
    cx.emit(
        Node::new("Class")
            .span(at(c.class.0, c.class.1.chars().count().saturating_add(1)))
            .value(Value::Text(c.class.1.clone())),
    );
    cx.emit(
        Node::new("Name")
            .span(at(c.name.0, c.name.1.chars().count().saturating_add(1)))
            .value(Value::Text(c.name.1.clone())),
    );
    for &(start, end) in &c.properties {
        cx.push(property_node(input, &data, span, start, end, depth))
            .await;
    }
    for &(start, end) in &c.children {
        let child = at(start, end.saturating_sub(start));
        let bytes = data.get(start..end).unwrap_or_default();
        cx.push(component_node(input, child, bytes, depth.saturating_add(1)))
            .await;
    }
    Ok(())
}

/// A property (`name` + value) at `start..end` of `data` (which `span`
/// covers).
fn property_node(
    input: Input,
    data: &[u8],
    span: Span,
    start: usize,
    end: usize,
    depth: u32,
) -> Node {
    let mut r = Reader { data, pos: start };
    let name = r.short_string().unwrap_or_default();
    let value_at = r.pos;
    let mut node = value_node(input, data, span, name, value_at, end, depth);
    node.span = Some(span.sub(to_u64(start), to_u64(end.saturating_sub(start))));
    node
}

/// A node for the value at `start..end` of `data`.
fn value_node(
    input: Input,
    data: &[u8],
    span: Span,
    name: String,
    start: usize,
    end: usize,
    depth: u32,
) -> Node {
    let whole = span.sub(to_u64(start), to_u64(end.saturating_sub(start)));
    let mut r = Reader { data, pos: start };
    let node = Node::new(name).span(whole);
    let (kind, parsed) = match value(&mut r, depth) {
        Ok(v) => v,
        Err(e) => return node.diag(e),
    };
    let type_name = lookup(VALUE_TYPES, kind.into()).unwrap_or("?");
    let value_span = (whole, depth);
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
        Parsed::Set(items) => node
            .value(Value::Text(format!("[{}]", items.join(", "))))
            .summary("set"),
        Parsed::List => node.summary("list").lazy(
            crate::expander!(self::expand_list: (Input, (Span, u32))),
            (input, value_span),
        ),
        Parsed::Collection => node.summary("collection").lazy(
            crate::expander!(self::expand_collection: (Input, (Span, u32))),
            (input, value_span),
        ),
        Parsed::Binary { at, len } => {
            let blob = span.sub(to_u64(at), to_u64(len));
            node.summary(format!("{len} bytes of binary data"))
                .lazy(expand_binary, (input, blob))
        }
    }
}

async fn expand_list(cx: Cx, (input, (span, depth)): (Input, (Span, u32))) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader {
        data: &data,
        pos: 1,
    };
    let mut index = 0u64;
    while r.peek().is_some_and(|b| b != 0) {
        let start = r.pos;
        value(&mut r, depth.saturating_add(1))?;
        cx.push(value_node(
            input,
            &data,
            span,
            format!("[{index}]"),
            start,
            r.pos,
            depth.saturating_add(1),
        ))
        .await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn expand_collection(cx: Cx, (input, (span, depth)): (Input, (Span, u32))) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader {
        data: &data,
        pos: 1,
    };
    let mut index = 0u64;
    while r.peek().is_some_and(|b| b != 0) {
        let start = r.pos;
        let order = collection_item(&mut r, depth.saturating_add(1))?;
        let item = span.sub(to_u64(start), to_u64(r.pos.saturating_sub(start)));
        let mut node = Node::new(format!("Item {index}")).span(item).lazy(
            crate::expander!(self::expand_item: (Input, (Span, u32))),
            (input, (item, depth.saturating_add(1))),
        );
        if let Some(order) = order {
            node = node.summary(format!("order {order}"));
        }
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn expand_item(cx: Cx, (input, (span, depth)): (Input, (Span, u32))) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader {
        data: &data,
        pos: 0,
    };
    if let Some(2..=4) = r.peek() {
        let start = r.pos;
        value(&mut r, depth)?;
        cx.emit(value_node(
            input,
            &data,
            span,
            "Order".to_owned(),
            start,
            r.pos,
            depth,
        ));
    }
    r.pos = r.pos.saturating_add(1);
    for (start, end) in properties(&mut r, depth)? {
        cx.push(property_node(input, &data, span, start, end, depth))
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
