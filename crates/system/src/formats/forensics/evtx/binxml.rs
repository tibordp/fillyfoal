//! Binary XML (BinXML) as stored in EVTX chunks: a token stream
//! (fragment headers, elements, attributes, values, substitutions,
//! template instances) whose names and template definitions live at
//! chunk-relative offsets, stored inline the first time they are used.
//!
//! [`Parser`] decodes a record's token stream into a token [`Tree`] (for
//! display) and an item list (for rendering); [`Parser::render`] applies
//! template instances to their substitution values and writes XML text.
//! Work is counted in steps and bounded by [`MAX_STEPS`]; the caller
//! charges it.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::{to_u64, u16_le, u32_le, u64_le};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::forensics::winsec::{parse_sid, sid_name};
use crate::formats::text::xml::decode_entities;
use crate::formats::util::binutil::Tree;
use crate::formats::util::civil::systemtime;
use crate::formats::util::datakit::guid_le;
use crate::node::Node;
use crate::span::Span;
use crate::text::hex_upper;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Tokens and bytes a record may cost to parse and render.
pub const MAX_STEPS: u64 = 1 << 20;
/// Nesting of elements, template instances and embedded fragments.
const MAX_DEPTH: usize = 48;
/// Longest rendered XML kept.
const MAX_XML: usize = 1 << 16;
const NO_DEPENDENCY: u16 = 0xffff;

pub const VALUE_TYPES: EnumTable = &[
    (0x00, "Null"),
    (0x01, "String"),
    (0x02, "AnsiString"),
    (0x03, "Int8"),
    (0x04, "UInt8"),
    (0x05, "Int16"),
    (0x06, "UInt16"),
    (0x07, "Int32"),
    (0x08, "UInt32"),
    (0x09, "Int64"),
    (0x0a, "UInt64"),
    (0x0b, "Real32"),
    (0x0c, "Real64"),
    (0x0d, "Bool"),
    (0x0e, "Binary"),
    (0x0f, "GUID"),
    (0x10, "SizeT"),
    (0x11, "FILETIME"),
    (0x12, "SYSTEMTIME"),
    (0x13, "SID"),
    (0x14, "HexInt32"),
    (0x15, "HexInt64"),
    (0x20, "EvtHandle"),
    (0x21, "BinXml"),
    (0x23, "EvtXml"),
];

const TOKENS: EnumTable = &[
    (0x00, "EndOfFragment"),
    (0x01, "OpenStartElement"),
    (0x02, "CloseStartElement"),
    (0x03, "CloseEmptyElement"),
    (0x04, "EndElement"),
    (0x05, "Value"),
    (0x06, "Attribute"),
    (0x07, "CDATASection"),
    (0x08, "CharRef"),
    (0x09, "EntityRef"),
    (0x0a, "PITarget"),
    (0x0b, "PIData"),
    (0x0c, "TemplateInstance"),
    (0x0d, "NormalSubstitution"),
    (0x0e, "OptionalSubstitution"),
    (0x0f, "FragmentHeader"),
];

/// The name of a value type, with `[]` for arrays.
pub fn type_name(kind: u8) -> String {
    let base = lookup(VALUE_TYPES, (kind & 0x7f).into())
        .map_or_else(|| format!("type {:#04x}", kind & 0x7f), str::to_owned);
    if kind & 0x80 != 0 {
        format!("{base}[]")
    } else {
        base
    }
}

fn token_value(token: u8) -> Value {
    Value::Enum {
        raw: token.into(),
        bits: 8,
        name: lookup(TOKENS, (token & 0x0f).into()),
    }
}

#[derive(Clone)]
pub enum Item {
    Element(Element),
    Text(String),
    Sub { index: u16, optional: bool },
    CharRef(u16),
    Entity(String),
    CData(String),
    Pi(String, String),
    Instance(Instance),
}

#[derive(Clone)]
pub struct Element {
    name: String,
    dependency: u16,
    attributes: Vec<(String, Vec<Item>)>,
    content: Vec<Item>,
}

#[derive(Clone)]
pub struct Instance {
    definition: u32,
    values: Vec<SubValue>,
}

#[derive(Clone)]
pub struct SubValue {
    kind: u8,
    at: usize,
    len: usize,
    /// An embedded fragment (`BinXml` values).
    nested: Option<Arc<Vec<Item>>>,
}

struct Template {
    items: Vec<Item>,
    /// Where each substitution is used, e.g. `Provider@Name`.
    usage: BTreeMap<u16, String>,
}

/// Facts picked up while rendering, for summaries.
#[derive(Default, Clone)]
pub struct Facts {
    pub provider: Option<String>,
    pub event_id: Option<String>,
    pub level: Option<String>,
    pub channel: Option<String>,
}

/// Decodes the BinXML of one chunk (`data`, at `base`).
pub struct Parser<'a> {
    data: &'a [u8],
    base: Span,
    /// Work done so far (tokens and bytes).
    pub steps: u64,
    templates: BTreeMap<u32, Arc<Template>>,
    pub tree: Tree,
}

/// Where parsed tokens go: under a tree node, or nowhere.
type Emit = Option<usize>;

impl<'a> Parser<'a> {
    pub fn new(data: &'a [u8], base: Span) -> Self {
        Parser {
            data,
            base,
            steps: 0,
            templates: BTreeMap::new(),
            tree: Tree::default(),
        }
    }

    fn span(&self, at: usize, len: usize) -> Span {
        self.base.sub(to_u64(at), to_u64(len))
    }

    fn err(&self, at: usize, message: impl Into<String>) -> Diagnostic {
        Diagnostic::malformed(message.into()).at(self.span(at, 1))
    }

    fn step(&mut self, n: usize) -> Result<()> {
        self.steps = self.steps.saturating_add(to_u64(n).saturating_add(1));
        if self.steps > MAX_STEPS {
            return Err(Diagnostic::limit("Binary XML too complex to decode"));
        }
        Ok(())
    }

    fn bytes(&self, at: usize, len: usize, end: usize) -> Result<&'a [u8]> {
        let stop = at.checked_add(len).filter(|&e| e <= end);
        match stop.and_then(|e| self.data.get(at..e)) {
            Some(b) => Ok(b),
            None => Err(Diagnostic::truncated(
                self.span(at, len),
                to_u64(end.min(self.data.len()).saturating_sub(at)),
            )),
        }
    }

    fn u8(&self, at: usize, end: usize) -> Result<u8> {
        Ok(self.bytes(at, 1, end)?.first().copied().unwrap_or(0))
    }

    fn u16(&self, at: usize, end: usize) -> Result<u16> {
        Ok(u16_le(self.bytes(at, 2, end)?, 0).unwrap_or(0))
    }

    fn u32(&self, at: usize, end: usize) -> Result<u32> {
        Ok(u32_le(self.bytes(at, 4, end)?, 0).unwrap_or(0))
    }

    fn add(&mut self, parent: Emit, node: Node) -> Emit {
        parent.map(|p| self.tree.add(Some(p), node))
    }

    fn update(&mut self, index: Emit, f: impl FnOnce(Node) -> Node) {
        if let Some(i) = index {
            self.tree.update(i, f);
        }
    }

    fn leaf(&mut self, parent: Emit, name: &'static str, at: usize, len: usize, value: Value) {
        let span = self.span(at, len);
        self.add(parent, Node::new(name).span(span).value(value));
    }

    /// A name: stored inline when `offset` is the current position (and
    /// then skipped), otherwise elsewhere in the chunk.
    fn name(&mut self, offset: u32, pos: &mut usize, end: usize, emit: Emit) -> Result<String> {
        let at = usize::try_from(offset).unwrap_or(usize::MAX);
        let inline = at == *pos;
        let limit = if inline { end } else { self.data.len() };
        let hash = self.u16(at.saturating_add(4), limit)?;
        let count = usize::from(self.u16(at.saturating_add(6), limit)?);
        let chars = self.bytes(at.saturating_add(8), count.saturating_mul(2), limit)?;
        self.step(count)?;
        let name = crate::text::utf16(chars, Endian::Little);
        if inline {
            let size = count.saturating_mul(2).saturating_add(10);
            self.bytes(at, size, limit)?;
            let span = self.span(at, size);
            self.add(
                emit,
                Node::new("Name")
                    .span(span)
                    .value(Value::Text(name.clone()))
                    .summary(format!("hash {hash:#06x}")),
            );
            *pos = at.saturating_add(size);
        }
        Ok(name)
    }

    /// A fragment: header, an element or template instance, end of stream.
    /// Stops at `end` or after the end-of-fragment token.
    pub fn fragment(
        &mut self,
        pos: &mut usize,
        end: usize,
        emit: Emit,
        depth: usize,
        usage: &mut BTreeMap<u16, String>,
    ) -> Result<Vec<Item>> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("Binary XML nested too deeply").at(self.span(*pos, 1)));
        }
        let mut items = Vec::new();
        while *pos < end {
            self.step(0)?;
            let at = *pos;
            let token = self.u8(at, end)?;
            match token & 0x0f {
                0x00 => {
                    self.leaf(emit, "End of fragment", at, 1, token_value(token));
                    *pos = at.saturating_add(1);
                    break;
                }
                0x0f => {
                    let b = self.bytes(at, 4, end)?;
                    let (major, minor, flags) = (
                        b.get(1).copied().unwrap_or(0),
                        b.get(2).copied().unwrap_or(0),
                        b.get(3).copied().unwrap_or(0),
                    );
                    let span = self.span(at, 4);
                    self.add(
                        emit,
                        Node::new("Fragment header")
                            .span(span)
                            .value(Value::Text(format!("{major}.{minor}")))
                            .summary(format!("BinXML {major}.{minor}, flags {flags:#04x}")),
                    );
                    *pos = at.saturating_add(4);
                }
                0x0c => {
                    let instance = self.instance(pos, end, emit, depth)?;
                    items.push(Item::Instance(instance));
                }
                _ => {
                    let item = self.content_item(pos, end, emit, depth, usage, "")?;
                    items.extend(item);
                }
            }
        }
        Ok(items)
    }

    /// One content token (element, value, substitution, reference, ...).
    /// `None` for tokens that end a list (handled by the caller).
    fn content_item(
        &mut self,
        pos: &mut usize,
        end: usize,
        emit: Emit,
        depth: usize,
        usage: &mut BTreeMap<u16, String>,
        context: &str,
    ) -> Result<Option<Item>> {
        let at = *pos;
        let token = self.u8(at, end)?;
        match token & 0x0f {
            0x01 => Ok(Some(Item::Element(
                self.element(pos, end, emit, depth, usage)?,
            ))),
            0x05 => {
                let kind = self.u8(at.saturating_add(1), end)?;
                let (text, len) = match kind {
                    0x01 => {
                        let n = usize::from(self.u16(at.saturating_add(2), end)?);
                        let b = self.bytes(at.saturating_add(4), n.saturating_mul(2), end)?;
                        (
                            crate::text::utf16(b, Endian::Little),
                            n.saturating_mul(2).saturating_add(4),
                        )
                    }
                    0x02 => {
                        let n = usize::from(self.u16(at.saturating_add(2), end)?);
                        let b = self.bytes(at.saturating_add(4), n, end)?;
                        (crate::text::latin1(b), n.saturating_add(4))
                    }
                    _ => {
                        return Err(self.err(at, format!("value token of type {kind:#04x}")));
                    }
                };
                self.step(len)?;
                let span = self.span(at, len);
                self.add(
                    emit,
                    Node::new("Value")
                        .span(span)
                        .value(Value::Text(text.clone()))
                        .summary(type_name(kind)),
                );
                *pos = at.saturating_add(len);
                Ok(Some(Item::Text(text)))
            }
            0x0d | 0x0e => {
                let index = self.u16(at.saturating_add(1), end)?;
                let kind = self.u8(at.saturating_add(3), end)?;
                let optional = token & 0x0f == 0x0e;
                let span = self.span(at, 4);
                self.add(
                    emit,
                    Node::new(format!("Substitution #{index}"))
                        .span(span)
                        .value(Value::Enum {
                            raw: kind.into(),
                            bits: 8,
                            name: lookup(VALUE_TYPES, (kind & 0x7f).into()),
                        })
                        .summary(if optional {
                            "optional (omitted when null)"
                        } else {
                            "normal"
                        }),
                );
                if !context.is_empty() {
                    usage.entry(index).or_insert_with(|| context.to_owned());
                }
                *pos = at.saturating_add(4);
                Ok(Some(Item::Sub { index, optional }))
            }
            0x08 => {
                let c = self.u16(at.saturating_add(1), end)?;
                self.leaf(
                    emit,
                    "Character reference",
                    at,
                    3,
                    Value::UInt {
                        value: c.into(),
                        bits: 16,
                        radix: Radix::Dec,
                    },
                );
                *pos = at.saturating_add(3);
                Ok(Some(Item::CharRef(c)))
            }
            0x09 => {
                let offset = self.u32(at.saturating_add(1), end)?;
                let node = self.add(emit, Node::new("Entity reference"));
                *pos = at.saturating_add(5);
                let header = self.add(node, Node::new("Token"));
                let name = self.name(offset, pos, end, node)?;
                let tspan = self.span(at, 5);
                self.update(header, |n| n.span(tspan).value(token_value(token)));
                let span = self.span(at, pos.saturating_sub(at));
                let shown = name.clone();
                self.update(node, |n| n.span(span).value(Value::Text(shown)));
                Ok(Some(Item::Entity(name)))
            }
            0x07 | 0x0b => {
                let n = usize::from(self.u16(at.saturating_add(1), end)?);
                let b = self.bytes(at.saturating_add(3), n.saturating_mul(2), end)?;
                let text = crate::text::utf16(b, Endian::Little);
                let len = n.saturating_mul(2).saturating_add(3);
                self.step(len)?;
                let name = if token & 0x0f == 0x07 {
                    "CDATA section"
                } else {
                    "PI data"
                };
                self.leaf(emit, name, at, len, Value::Text(text.clone()));
                *pos = at.saturating_add(len);
                Ok(Some(if token & 0x0f == 0x07 {
                    Item::CData(text)
                } else {
                    Item::Pi(String::new(), text)
                }))
            }
            0x0a => {
                let offset = self.u32(at.saturating_add(1), end)?;
                let node = self.add(emit, Node::new("Processing instruction"));
                let header = self.add(node, Node::new("PI target"));
                *pos = at.saturating_add(5);
                let target = self.name(offset, pos, end, node)?;
                let tspan = self.span(at, 5);
                let shown = target.clone();
                self.update(header, |n| n.span(tspan).value(Value::Text(shown)));
                let mut data = String::new();
                if *pos < end
                    && self.u8(*pos, end)? & 0x0f == 0x0b
                    && let Some(Item::Pi(_, d)) =
                        self.content_item(pos, end, node, depth, usage, context)?
                {
                    data = d;
                }
                let span = self.span(at, pos.saturating_sub(at));
                let shown = target.clone();
                self.update(node, |n| n.span(span).value(Value::Text(shown)));
                Ok(Some(Item::Pi(target, data)))
            }
            0x0c => Ok(Some(Item::Instance(self.instance(pos, end, emit, depth)?))),
            _ => Err(self.err(at, format!("unexpected token {token:#04x}"))),
        }
    }

    fn element(
        &mut self,
        pos: &mut usize,
        end: usize,
        emit: Emit,
        depth: usize,
        usage: &mut BTreeMap<u16, String>,
    ) -> Result<Element> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("elements nested too deeply").at(self.span(*pos, 1)));
        }
        let start = *pos;
        let token = self.u8(start, end)?;
        let dependency = self.u16(start.saturating_add(1), end)?;
        let size = self.u32(start.saturating_add(3), end)?;
        let name_offset = self.u32(start.saturating_add(7), end)?;
        // The size counts what follows the size field.
        let declared_end = start
            .saturating_add(7)
            .saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
        let end = end.min(declared_end);
        let node = self.add(emit, Node::new("Element"));
        let header = self.add(node, Node::new("Start tag"));
        *pos = start.saturating_add(11);
        let name = self.name(name_offset, pos, end, node)?;
        let hspan = self.span(start, 11);
        let shown = name.clone();
        self.update(header, |n| {
            let n = n.span(hspan).value(Value::Text(shown));
            let n = n.summary(format!("{:#x} bytes", size));
            if dependency == NO_DEPENDENCY {
                n
            } else {
                n.summary(format!(
                    "{size:#x} bytes, omitted when substitution #{dependency} is null"
                ))
            }
        });
        if token & 0x40 != 0 {
            let list = self.u32(*pos, end)?;
            self.leaf(
                node,
                "Attribute list size",
                *pos,
                4,
                Value::UInt {
                    value: list.into(),
                    bits: 32,
                    radix: Radix::Hex,
                },
            );
            *pos = pos.saturating_add(4);
        }
        let mut attributes = Vec::new();
        while *pos < end && self.u8(*pos, end)? & 0x0f == 0x06 {
            self.step(0)?;
            let at = *pos;
            let offset = self.u32(at.saturating_add(1), end)?;
            let anode = self.add(node, Node::new("Attribute"));
            let aheader = self.add(anode, Node::new("Attribute token"));
            *pos = at.saturating_add(5);
            let aname = self.name(offset, pos, end, anode)?;
            let tspan = self.span(at, 5);
            let shown = aname.clone();
            self.update(aheader, |n| n.span(tspan).value(Value::Text(shown)));
            let context = format!("{name}@{aname}");
            let mut values = Vec::new();
            while *pos < end
                && matches!(self.u8(*pos, end)? & 0x0f, 0x05 | 0x08 | 0x09 | 0x0d | 0x0e)
            {
                self.step(0)?;
                values.extend(self.content_item(pos, end, anode, depth, usage, &context)?);
            }
            let span = self.span(at, pos.saturating_sub(at));
            let label = format!("@{aname}");
            self.update(anode, |n| {
                let mut n = n.span(span);
                n.name = label.into();
                n
            });
            attributes.push((aname, values));
        }
        let close_at = *pos;
        let close = self.u8(close_at, end)?;
        let mut content = Vec::new();
        match close & 0x0f {
            0x03 => {
                self.leaf(node, "Close empty element", close_at, 1, token_value(close));
                *pos = close_at.saturating_add(1);
            }
            0x02 => {
                self.leaf(node, "Close start tag", close_at, 1, token_value(close));
                *pos = close_at.saturating_add(1);
                loop {
                    self.step(0)?;
                    let at = *pos;
                    let t = self.u8(at, end)?;
                    if t & 0x0f == 0x04 {
                        self.leaf(node, "End element", at, 1, token_value(t));
                        *pos = at.saturating_add(1);
                        break;
                    }
                    if t & 0x0f == 0x00 {
                        return Err(self.err(at, format!("end of fragment inside <{name}>")));
                    }
                    content.extend(self.content_item(
                        pos,
                        end,
                        node,
                        depth.saturating_add(1),
                        usage,
                        &name,
                    )?);
                }
            }
            _ => {
                return Err(self.err(
                    close_at,
                    format!("unexpected token {close:#04x} in <{name}>"),
                ));
            }
        }
        let span = self.span(start, pos.saturating_sub(start));
        let label = format!("<{name}>");
        let summary = match (attributes.len(), content.len()) {
            (0, 0) => "empty".to_owned(),
            (a, c) => format!("{a} attributes, {c} items"),
        };
        self.update(node, |n| {
            let mut n = n.span(span).summary(summary);
            n.name = label.into();
            n
        });
        if *pos != declared_end {
            self.update(node, |n| {
                n.diag(Diagnostic::warning(format!(
                    "element ends at {:#x}, its size says {declared_end:#x}",
                    *pos
                )))
            });
        }
        Ok(Element {
            name,
            dependency,
            attributes,
            content,
        })
    }

    /// A template instance: header, the definition (if stored inline),
    /// then the substitution values.
    fn instance(
        &mut self,
        pos: &mut usize,
        end: usize,
        emit: Emit,
        depth: usize,
    ) -> Result<Instance> {
        let start = *pos;
        let id = self.u32(start.saturating_add(2), end)?;
        let definition = self.u32(start.saturating_add(6), end)?;
        let node = self.add(emit, Node::new("Template instance"));
        let header = self.add(node, Node::new("Instance header"));
        *pos = start.saturating_add(10);
        let def_at = usize::try_from(definition).unwrap_or(usize::MAX);
        let inline = def_at == *pos;
        let template = if inline {
            let size = self.u32(def_at.saturating_add(20), end)?;
            let data_at = def_at.saturating_add(24);
            let data_end = data_at.saturating_add(usize::try_from(size).unwrap_or(usize::MAX));
            if data_end > end {
                return Err(Diagnostic::truncated(
                    self.span(def_at, data_end.saturating_sub(def_at)),
                    to_u64(end.saturating_sub(def_at)),
                ));
            }
            let dnode = self.add(node, Node::new("Template definition"));
            let guid = guid_le(self.bytes(def_at.saturating_add(4), 16, end)?);
            let next = self.u32(def_at, end)?;
            let hspan = self.span(def_at, 24);
            self.add(
                dnode,
                Node::new("Definition header")
                    .span(hspan)
                    .value(Value::Guid(guid))
                    .summary(format!("{size} bytes, next in bucket {next:#x}")),
            );
            let mut p = data_at;
            let mut usage = BTreeMap::new();
            let items =
                self.fragment(&mut p, data_end, dnode, depth.saturating_add(1), &mut usage)?;
            let dspan = self.span(def_at, data_end.saturating_sub(def_at));
            self.update(dnode, |n| {
                n.span(dspan).summary(format!("{guid}, {size} bytes"))
            });
            *pos = data_end;
            let t = Arc::new(Template { items, usage });
            self.templates.insert(definition, t.clone());
            Some(t)
        } else {
            self.template_at(definition, depth).ok()
        };
        let hspan = self.span(start, 10);
        let def_span = self.span(def_at, 24);
        self.update(header, |n| {
            n.span(hspan)
                .value(Value::UInt {
                    value: id.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .summary(format!(
                    "template {id:#010x}, definition at {definition:#x}{}",
                    if inline { " (inline)" } else { "" }
                ))
                .target(def_span)
        });
        let count = self.u32(*pos, end)?;
        self.leaf(
            node,
            "Substitution count",
            *pos,
            4,
            Value::UInt {
                value: count.into(),
                bits: 32,
                radix: Radix::Dec,
            },
        );
        *pos = pos.saturating_add(4);
        let n = usize::try_from(count).unwrap_or(usize::MAX);
        let table = self.bytes(*pos, n.saturating_mul(4), end)?;
        self.step(n)?;
        let mut descriptors = Vec::new();
        for d in table.as_chunks::<4>().0 {
            let size = u16_le(d, 0).unwrap_or(0);
            let kind = d.get(2).copied().unwrap_or(0);
            descriptors.push((usize::from(size), kind));
        }
        let listed: Vec<String> = descriptors
            .iter()
            .map(|&(size, kind)| format!("{}:{size}", type_name(kind)))
            .collect();
        self.leaf(
            node,
            "Value descriptors",
            *pos,
            n.saturating_mul(4),
            Value::Text(listed.join(" ")),
        );
        *pos = pos.saturating_add(n.saturating_mul(4));
        let mut values = Vec::new();
        for (i, &(len, kind)) in descriptors.iter().enumerate() {
            let at = *pos;
            let bytes = self.bytes(at, len, end)?;
            self.step(len)?;
            let index = u16::try_from(i).unwrap_or(u16::MAX);
            let used = template
                .as_ref()
                .and_then(|t| t.usage.get(&index))
                .map_or_else(String::new, |u| format!(" {u}"));
            let span = self.span(at, len);
            let mut vnode = Node::new(format!("#{i}{used}")).span(span);
            let mut nested = None;
            if kind == 0x21 && len > 0 {
                let vindex = self.add(node, vnode.summary("BinXml"));
                let mut p = at;
                let mut throwaway = BTreeMap::new();
                let items = self.fragment(
                    &mut p,
                    at.saturating_add(len),
                    vindex,
                    depth.saturating_add(1),
                    &mut throwaway,
                )?;
                nested = Some(Arc::new(items));
            } else {
                vnode = if len == 0 || kind == 0 {
                    vnode
                        .value(Value::Text("null".into()))
                        .summary(type_name(kind))
                } else {
                    vnode
                        .value(typed_value(kind, bytes))
                        .summary(format!("{}, {len} bytes", type_name(kind)))
                };
                self.add(node, vnode);
            }
            values.push(SubValue {
                kind,
                at,
                len,
                nested,
            });
            *pos = at.saturating_add(len);
        }
        let span = self.span(start, pos.saturating_sub(start));
        let summary = format!("template {id:#010x}, {count} values");
        self.update(node, |n| n.span(span).summary(summary));
        Ok(Instance { definition, values })
    }

    /// A template defined elsewhere in the chunk, parsed silently (once).
    fn template_at(&mut self, offset: u32, depth: usize) -> Result<Arc<Template>> {
        if let Some(t) = self.templates.get(&offset) {
            return Ok(t.clone());
        }
        let at = usize::try_from(offset).unwrap_or(usize::MAX);
        let all = self.data.len();
        let size = self.u32(at.saturating_add(20), all)?;
        let data_at = at.saturating_add(24);
        let data_end = data_at
            .saturating_add(usize::try_from(size).unwrap_or(usize::MAX))
            .min(all);
        let mut p = data_at;
        let mut usage = BTreeMap::new();
        let items = self.fragment(&mut p, data_end, None, depth.saturating_add(1), &mut usage)?;
        let t = Arc::new(Template { items, usage });
        self.templates.insert(offset, t.clone());
        Ok(t)
    }

    /// The XML text of `items` (a record's fragment).
    pub fn render(&self, items: &[Item], facts: &mut Facts) -> String {
        let mut out = Xml::default();
        let mut steps = 0u64;
        self.render_items(items, &[], &mut out, facts, &mut steps, 0);
        if out.full {
            out.text.push('…');
        }
        out.text
    }

    fn render_items(
        &self,
        items: &[Item],
        subs: &[SubValue],
        out: &mut Xml,
        facts: &mut Facts,
        steps: &mut u64,
        depth: usize,
    ) {
        if depth > MAX_DEPTH {
            return;
        }
        for item in items {
            *steps = steps.saturating_add(1);
            if *steps > MAX_STEPS || out.full {
                out.full = true;
                return;
            }
            match item {
                Item::Element(e) => self.render_element(e, subs, out, facts, steps, depth),
                Item::Text(t) => out.push(&escape(t, false)),
                Item::Sub { index, .. } => {
                    self.render_sub(subs, *index, out, facts, steps, depth);
                }
                Item::CharRef(c) => out.push(&format!("&#{c};")),
                Item::Entity(n) => out.push(&format!("&{n};")),
                Item::CData(t) => out.push(&format!("<![CDATA[{t}]]>")),
                Item::Pi(t, d) => out.push(&format!("<?{t} {d}?>")),
                Item::Instance(inst) => {
                    if let Some(t) = self.templates.get(&inst.definition) {
                        self.render_items(
                            &t.items,
                            &inst.values,
                            out,
                            facts,
                            steps,
                            depth.saturating_add(1),
                        );
                    }
                }
            }
        }
    }

    fn render_sub(
        &self,
        subs: &[SubValue],
        index: u16,
        out: &mut Xml,
        facts: &mut Facts,
        steps: &mut u64,
        depth: usize,
    ) {
        let Some(v) = subs.get(usize::from(index)) else {
            return;
        };
        if let Some(items) = &v.nested {
            self.render_items(items, &[], out, facts, steps, depth.saturating_add(1));
            return;
        }
        let bytes = self
            .data
            .get(v.at..v.at.saturating_add(v.len))
            .unwrap_or_default();
        *steps = steps.saturating_add(to_u64(v.len));
        out.push(&escape(&value_text(v.kind, bytes), false));
    }

    fn is_null(subs: &[SubValue], index: u16) -> bool {
        subs.get(usize::from(index))
            .is_none_or(|v| v.len == 0 || v.kind == 0)
    }

    fn render_element(
        &self,
        e: &Element,
        subs: &[SubValue],
        out: &mut Xml,
        facts: &mut Facts,
        steps: &mut u64,
        depth: usize,
    ) {
        if e.dependency != NO_DEPENDENCY && Self::is_null(subs, e.dependency) {
            return;
        }
        out.push(&format!("<{}", e.name));
        for (name, values) in &e.attributes {
            // An attribute made only of null optional substitutions is left out.
            let omitted = !values.is_empty()
                && values.iter().all(|v| {
                    matches!(v, Item::Sub { index, optional: true } if Self::is_null(subs, *index))
                });
            if omitted {
                continue;
            }
            let mut inner = Xml::default();
            self.render_items(
                values,
                subs,
                &mut inner,
                facts,
                steps,
                depth.saturating_add(1),
            );
            if e.name == "Provider" && name == "Name" && facts.provider.is_none() {
                facts.provider = Some(decode_entities(&inner.text, false));
            }
            out.push(&format!(
                " {name}=\"{}\"",
                inner.text.replace('"', "&quot;")
            ));
        }
        let mut inner = Xml::default();
        self.render_items(
            &e.content,
            subs,
            &mut inner,
            facts,
            steps,
            depth.saturating_add(1),
        );
        let slot = match e.name.as_str() {
            "EventID" => Some(&mut facts.event_id),
            "Level" => Some(&mut facts.level),
            "Channel" => Some(&mut facts.channel),
            _ => None,
        };
        if let Some(slot) = slot
            && slot.is_none()
            && !inner.text.contains('<')
        {
            *slot = Some(decode_entities(&inner.text, false));
        }
        if inner.text.is_empty() {
            out.push("/>");
        } else {
            out.push(">");
            out.push(&inner.text);
            out.full |= inner.full;
            out.push(&format!("</{}>", e.name));
        }
    }
}

#[derive(Default)]
struct Xml {
    text: String,
    full: bool,
}

impl Xml {
    fn push(&mut self, s: &str) {
        if self.full {
            return;
        }
        if self.text.len().saturating_add(s.len()) > MAX_XML {
            self.full = true;
            return;
        }
        self.text.push_str(s);
    }
}

fn escape(s: &str, quotes: bool) -> String {
    let mut out = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' if quotes => out.push_str("&quot;"),
            _ => out.push(c),
        }
    }
    out
}

/// `2026-10-09T23:05:53.4961830Z` for a FILETIME.
pub fn filetime_text(ticks: u64) -> String {
    let unix = crate::text::filetime_to_unix(ticks);
    let frac = ticks.checked_rem(10_000_000).unwrap_or(0);
    let base = crate::render::value(&Value::Timestamp { unix_seconds: unix });
    let stem = base.strip_suffix(" UTC").unwrap_or(&base).replace(' ', "T");
    format!("{stem}.{frac:07}Z")
}

/// `2026-10-09T23:05:53.496Z` for a SYSTEMTIME; out-of-range fields are
/// shown as stored.
fn systemtime_text(b: &[u8]) -> String {
    let w: [u16; 8] = std::array::from_fn(|i| u16_le(b, i.saturating_mul(2)).unwrap_or(0));
    let [year, month, _, day, hour, minute, second, millis] = w;
    let Some(unix) = systemtime(w) else {
        return format!(
            "{year:04}-{month:02}-{day:02}T{hour:02}:{minute:02}:{second:02}.{millis:03}Z"
        );
    };
    let base = crate::render::value(&Value::Timestamp { unix_seconds: unix });
    let stem = base.strip_suffix(" UTC").unwrap_or(&base).replace(' ', "T");
    format!("{stem}.{millis:03}Z")
}

/// Size of one element of a fixed-size type (for arrays).
fn element_size(kind: u8, len: usize) -> Option<usize> {
    Some(match kind & 0x7f {
        0x03 | 0x04 => 1,
        0x05 | 0x06 => 2,
        0x07 | 0x08 | 0x0b | 0x0d | 0x14 => 4,
        0x09 | 0x0a | 0x0c | 0x11 | 0x15 => 8,
        0x0f | 0x12 => 16,
        0x10 => {
            if len.is_multiple_of(8) {
                8
            } else {
                4
            }
        }
        _ => return None,
    })
}

/// A value as Windows renders it in event XML.
pub fn value_text(kind: u8, b: &[u8]) -> String {
    if kind & 0x80 != 0 {
        let base = kind & 0x7f;
        let parts: Vec<String> = match base {
            0x01 => crate::text::utf16(b, Endian::Little)
                .trim_end_matches('\0')
                .split('\0')
                .map(str::to_owned)
                .collect(),
            0x02 => crate::text::latin1(b)
                .trim_end_matches('\0')
                .split('\0')
                .map(str::to_owned)
                .collect(),
            _ => match element_size(base, b.len()) {
                Some(size) => b.chunks(size).map(|c| value_text(base, c)).collect(),
                None => vec![hex_upper(b)],
            },
        };
        return parts.join(", ");
    }
    let le = |n: usize| -> Option<u64> {
        if b.len() != n {
            return None;
        }
        Some(
            b.iter()
                .rev()
                .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x)),
        )
    };
    let shown = match kind {
        0x00 => Some(String::new()),
        0x01 => Some(
            crate::text::utf16(b, Endian::Little)
                .trim_end_matches('\0')
                .to_owned(),
        ),
        0x02 => Some(crate::text::latin1(b).trim_end_matches('\0').to_owned()),
        0x03 => le(1).map(|v| (v as u8 as i8).to_string()),
        0x05 => le(2).map(|v| (v as u16 as i16).to_string()),
        0x07 => le(4).map(|v| (v as u32 as i32).to_string()),
        0x09 => le(8).map(|v| (v as i64).to_string()),
        0x04 => le(1).map(|v| v.to_string()),
        0x06 => le(2).map(|v| v.to_string()),
        0x08 => le(4).map(|v| v.to_string()),
        0x0a => le(8).map(|v| v.to_string()),
        0x0b => le(4).map(|v| f32::from_bits(v as u32).to_string()),
        0x0c => le(8).map(|v| f64::from_bits(v).to_string()),
        0x0d => le(4).map(|v| if v != 0 { "true" } else { "false" }.to_owned()),
        0x0f if b.len() == 16 => Some(guid_le(b).to_string().to_uppercase()),
        0x10 => match b.len() {
            8 => le(8).map(|v| format!("0x{v:016x}")),
            4 => le(4).map(|v| format!("0x{v:08x}")),
            _ => None,
        },
        0x11 => le(8).map(filetime_text),
        0x12 if b.len() == 16 => Some(systemtime_text(b)),
        0x13 => parse_sid(b).map(|(s, _)| s),
        0x14 => le(4).map(|v| format!("0x{v:x}")),
        0x15 => le(8).map(|v| format!("0x{v:x}")),
        _ => None,
    };
    shown.unwrap_or_else(|| hex_upper(b))
}

/// A substitution value as a typed node value.
fn typed_value(kind: u8, b: &[u8]) -> Value {
    let uint = |bits: u8, radix: Radix| -> Value {
        let v = b
            .iter()
            .rev()
            .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x));
        Value::UInt {
            value: v,
            bits,
            radix,
        }
    };
    let sized = |n: usize| b.len() == n;
    match kind {
        0x04 if sized(1) => uint(8, Radix::Dec),
        0x06 if sized(2) => uint(16, Radix::Dec),
        0x08 if sized(4) => uint(32, Radix::Dec),
        0x0a if sized(8) => uint(64, Radix::Dec),
        0x14 if sized(4) => uint(32, Radix::Hex),
        0x15 if sized(8) => uint(64, Radix::Hex),
        0x10 if sized(4) => uint(32, Radix::Hex),
        0x10 if sized(8) => uint(64, Radix::Hex),
        0x03 | 0x05 | 0x07 | 0x09 if matches!(b.len(), 1 | 2 | 4 | 8) => {
            let bits = u32::try_from(b.len().saturating_mul(8)).unwrap_or(64);
            let raw = b
                .iter()
                .rev()
                .fold(0u64, |acc, &x| acc.wrapping_shl(8) | u64::from(x));
            let shift = 64u32.saturating_sub(bits);
            let value = (raw.wrapping_shl(shift) as i64).wrapping_shr(shift);
            Value::Int {
                value,
                bits: u8::try_from(bits).unwrap_or(64),
            }
        }
        0x0b if sized(4) => Value::Float(f64::from(f32::from_bits(u32_le(b, 0).unwrap_or(0)))),
        0x0c if sized(8) => Value::Float(f64::from_bits(u64_le(b, 0).unwrap_or(0))),
        0x0d if sized(4) => Value::Bool(u32_le(b, 0).unwrap_or(0) != 0),
        0x0e => Value::Bytes(b.to_vec()),
        0x0f if sized(16) => Value::Guid(guid_le(b)),
        0x11 if sized(8) => Value::Timestamp {
            unix_seconds: crate::text::filetime_to_unix(u64_le(b, 0).unwrap_or(0)),
        },
        0x13 => match parse_sid(b) {
            Some((s, _)) => Value::Text(match sid_name(&s) {
                Some(n) => format!("{s} ({n})"),
                None => s,
            }),
            None => Value::Bytes(b.to_vec()),
        },
        _ => Value::Text(value_text(kind, b)),
    }
}

/// Renders a record body (a fragment at `pos..end` of the chunk) into the
/// token tree under a new root and returns (root, items).
pub fn parse_record(
    p: &mut Parser<'_>,
    pos: usize,
    end: usize,
    emit: bool,
) -> (Option<usize>, Result<Vec<Item>>) {
    let root = emit.then(|| p.tree.add(None, Node::new("Binary XML")));
    let mut at = pos;
    let mut usage = BTreeMap::new();
    let items = p.fragment(&mut at, end, root, 0, &mut usage);
    if items.is_ok() && at < end {
        let span = p.span(at, end.saturating_sub(at));
        let tail = p.data.get(at..end).unwrap_or_default();
        let node = if tail.len() < 8 && tail.iter().all(|&b| b == 0) {
            Node::new("Padding")
                .span(span)
                .value(Value::Bytes(tail.to_vec()))
                .desc("Zeros aligning the record to 8 bytes")
        } else {
            Node::new("Trailing data")
                .span(span)
                .diag(Diagnostic::warning("bytes after the end of the fragment"))
        };
        p.add(root, node);
    }
    (root, items)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn values() {
        assert_eq!(value_text(0x04, &[7]), "7");
        assert_eq!(value_text(0x05, &[0xfe, 0xff]), "-2");
        assert_eq!(
            value_text(0x15, &0x0080_0000_0000_0000u64.to_le_bytes()),
            "0x80000000000000"
        );
        assert_eq!(value_text(0x0e, &[0, 0xab]), "00AB");
        assert_eq!(value_text(0x0d, &[1, 0, 0, 0]), "true");
        assert_eq!(value_text(0x81, b"a\0b\0\0\0c\0\0\0"), "ab, c");
        assert_eq!(
            value_text(0x13, &[1, 2, 0, 0, 0, 0, 0, 5, 32, 0, 0, 0, 0x20, 2, 0, 0]),
            "S-1-5-32-544"
        );
        assert_eq!(
            filetime_text(116_444_736_000_000_001),
            "1970-01-01T00:00:00.0000001Z"
        );
    }
}
