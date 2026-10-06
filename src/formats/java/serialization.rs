//! Java object serialization streams (`ObjectOutputStream`, magic `AC ED`).
//!
//! The grammar is sequential: an item's size is known only after parsing
//! it, including any nested objects. So the stream is decoded once into a
//! tree (bounded by the input size and a nesting limit) that is then
//! displayed lazily.

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::binutil::{Reader, Tree, ellipsize, hex, mutf8, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, Value, decode_flags, flag};

const BE: crate::fields::Endian = crate::fields::Endian::Big;
/// Largest stream decoded (the decode is not incremental).
const MAX_STREAM: u64 = 4 << 20;
const MAX_DEPTH: u32 = 64;
const BASE_HANDLE: u32 = 0x7e_0000;

pub static FORMAT: Format = Format {
    name: "java-serialized",
    title: "Java serialization stream",
    extensions: &["ser"],
    mime: "application/x-java-serialized-object",
    probe: Probe::Magic(&[(0, b"\xac\xed\x00\x05")]),
    dissect: crate::expander!(dissect: Input),
};

const TC_NULL: u8 = 0x70;
const TC_REFERENCE: u8 = 0x71;
const TC_CLASSDESC: u8 = 0x72;
const TC_OBJECT: u8 = 0x73;
const TC_STRING: u8 = 0x74;
const TC_ARRAY: u8 = 0x75;
const TC_CLASS: u8 = 0x76;
const TC_BLOCKDATA: u8 = 0x77;
const TC_ENDBLOCKDATA: u8 = 0x78;
const TC_RESET: u8 = 0x79;
const TC_BLOCKDATALONG: u8 = 0x7a;
const TC_EXCEPTION: u8 = 0x7b;
const TC_LONGSTRING: u8 = 0x7c;
const TC_PROXYCLASSDESC: u8 = 0x7d;
const TC_ENUM: u8 = 0x7e;

const SC_WRITE_METHOD: u8 = 0x01;
const SC_SERIALIZABLE: u8 = 0x02;
const SC_EXTERNALIZABLE: u8 = 0x04;
const SC_BLOCK_DATA: u8 = 0x08;

const CLASS_FLAGS: FlagTable = &[
    flag(0x01, "SC_WRITE_METHOD"),
    flag(0x02, "SC_SERIALIZABLE"),
    flag(0x04, "SC_EXTERNALIZABLE"),
    flag(0x08, "SC_BLOCK_DATA"),
    flag(0x10, "SC_ENUM"),
];

#[derive(Clone, Debug)]
struct Field {
    code: u8,
    name: String,
}

#[derive(Clone, Debug, Default)]
struct ClassDesc {
    name: String,
    flags: u8,
    fields: Vec<Field>,
    parent: Option<u32>,
}

#[derive(Clone, Debug)]
enum Handle {
    Class(ClassDesc),
    Object(String),
    Text(String),
}

type Step<T> = std::result::Result<T, Diagnostic>;

struct Parser<'a> {
    r: Reader<'a>,
    file: Span,
    tree: Tree,
    handles: Vec<Handle>,
    /// Class names of the top-level objects, for the summary.
    top: Vec<String>,
}

fn type_name(code: u8) -> &'static str {
    match code {
        b'B' => "byte",
        b'C' => "char",
        b'D' => "double",
        b'F' => "float",
        b'I' => "int",
        b'J' => "long",
        b'S' => "short",
        b'Z' => "boolean",
        b'[' => "array",
        _ => "object",
    }
}

fn element_size(code: u8) -> Option<usize> {
    match code {
        b'B' | b'Z' => Some(1),
        b'C' | b'S' => Some(2),
        b'I' | b'F' => Some(4),
        b'J' | b'D' => Some(8),
        _ => None,
    }
}

impl Parser<'_> {
    fn span(&self, start: usize) -> Span {
        self.file
            .sub(to_u64(start), to_u64(self.r.pos().saturating_sub(start)))
    }

    fn fail(&self, what: &str) -> Diagnostic {
        Diagnostic::malformed(format!("truncated or malformed {what}"))
            .at(self.file.sub(to_u64(self.r.pos()), 1))
    }

    fn u8(&mut self) -> Step<u8> {
        self.r.u8().ok_or_else(|| self.fail("stream"))
    }

    fn peek(&self) -> Step<u8> {
        self.r.peek().ok_or_else(|| self.fail("stream"))
    }

    fn int<T: crate::fields::Prim>(&mut self) -> Step<T> {
        self.r.int::<T>(BE).ok_or_else(|| self.fail("value"))
    }

    fn bytes(&mut self, len: u64, what: &str) -> Step<&[u8]> {
        let n = usize::try_from(len).unwrap_or(usize::MAX);
        match self.r.bytes(n) {
            Some(b) => Ok(b),
            None => Err(self.fail(what)),
        }
    }

    fn utf(&mut self, long: bool) -> Step<String> {
        let len = if long {
            self.int::<u64>()?
        } else {
            self.int::<u16>()?.into()
        };
        Ok(mutf8(self.bytes(len, "string")?))
    }

    fn new_handle(&mut self, h: Handle) -> u32 {
        let n = u32::try_from(self.handles.len()).unwrap_or(u32::MAX);
        self.handles.push(h);
        BASE_HANDLE.saturating_add(n)
    }

    fn set_handle(&mut self, handle: u32, h: Handle) {
        if let Some(slot) = handle
            .checked_sub(BASE_HANDLE)
            .and_then(|i| self.handles.get_mut(usize::try_from(i).ok()?))
        {
            *slot = h;
        }
    }

    fn handle(&self, handle: u32) -> Option<&Handle> {
        let i = usize::try_from(handle.checked_sub(BASE_HANDLE)?).ok()?;
        self.handles.get(i)
    }

    fn class(&self, handle: Option<u32>) -> Option<&ClassDesc> {
        match self.handle(handle?)? {
            Handle::Class(c) => Some(c),
            _ => None,
        }
    }

    fn describe(&self, handle: u32) -> String {
        match self.handle(handle) {
            Some(Handle::Class(c)) => format!("class {}", c.name),
            Some(Handle::Object(name)) => format!("{name} object"),
            Some(Handle::Text(s)) => format!("{:?}", ellipsize(s, 60)),
            None => "unknown handle".to_owned(),
        }
    }

    /// One `content` item: an object or block data.
    fn content(&mut self, parent: usize, label: &str, depth: u32) -> Step<Option<u32>> {
        let start = self.r.pos();
        let tc = self.peek()?;
        if tc != TC_BLOCKDATA && tc != TC_BLOCKDATALONG {
            return self.object(parent, label, depth);
        }
        self.u8()?;
        let len = if tc == TC_BLOCKDATA {
            u64::from(self.u8()?)
        } else {
            self.int::<u32>()?.into()
        };
        let preview = self.bytes(len, "block data")?.to_vec();
        self.tree.add(
            Some(parent),
            Node::new("Block data")
                .span(self.span(start))
                .value(Value::Bytes(preview))
                .summary(format!("{len} bytes")),
        );
        Ok(None)
    }

    /// Contents up to and including `TC_ENDBLOCKDATA`.
    fn annotation(&mut self, parent: usize, depth: u32) -> Step<()> {
        loop {
            if self.peek()? == TC_ENDBLOCKDATA {
                self.u8()?;
                return Ok(());
            }
            self.content(parent, "annotation", depth.saturating_add(1))?;
        }
    }

    fn leaf(&mut self, parent: usize, label: &str, start: usize, value: Value) {
        let node = Node::new(label.to_owned())
            .span(self.span(start))
            .value(value);
        self.tree.add(Some(parent), node);
    }

    /// A class descriptor (or null or a reference to one).
    fn class_desc(&mut self, parent: usize, label: &str, depth: u32) -> Step<Option<u32>> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("class descriptors nested too deeply"));
        }
        let start = self.r.pos();
        match self.u8()? {
            TC_NULL => {
                self.leaf(parent, label, start, text("null"));
                Ok(None)
            }
            TC_REFERENCE => {
                let h = self.int::<u32>()?;
                let desc = self.describe(h);
                self.leaf(parent, label, start, text(format!("→ {desc}")));
                Ok(Some(h))
            }
            TC_CLASSDESC => {
                let name = self.utf(false)?;
                let uid = self.int::<i64>()?;
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let handle = self.new_handle(Handle::Class(ClassDesc {
                    name: name.clone(),
                    ..ClassDesc::default()
                }));
                let flags = self.u8()?;
                let count = self.int::<u16>()?;
                let mut fields = Vec::new();
                for _ in 0..count {
                    let at = self.r.pos();
                    let code = self.u8()?;
                    let field = self.utf(false)?;
                    let mut kind = type_name(code).to_owned();
                    if code == b'L' || code == b'[' {
                        // The field's type is a string object (or a reference).
                        let tc = self.peek()?;
                        let h = if tc == TC_STRING || tc == TC_LONGSTRING || tc == TC_REFERENCE {
                            self.object_quiet(depth)?
                        } else {
                            return Err(self.fail("field type"));
                        };
                        if let Some(Handle::Text(s)) = h.and_then(|h| self.handle(h)) {
                            kind = s.clone();
                        }
                    }
                    self.leaf(node, &field, at, text(kind));
                    fields.push(Field { code, name: field });
                }
                self.annotation(node, depth)?;
                let parent_desc =
                    self.class_desc(node, "superClassDesc", depth.saturating_add(1))?;
                let (set, _) = decode_flags(CLASS_FLAGS, flags.into());
                self.set_handle(
                    handle,
                    Handle::Class(ClassDesc {
                        name: name.clone(),
                        flags,
                        fields,
                        parent: parent_desc,
                    }),
                );
                let span = self.span(start);
                self.tree.update(node, |n| {
                    n.span(span).value(text(name)).summary(format!(
                        "serialVersionUID {uid:#x}, {count} fields, {}",
                        set.join(" ")
                    ))
                });
                Ok(Some(handle))
            }
            TC_PROXYCLASSDESC => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let handle = self.new_handle(Handle::Class(ClassDesc {
                    name: "proxy".to_owned(),
                    flags: SC_SERIALIZABLE,
                    ..ClassDesc::default()
                }));
                let count = self.int::<u32>()?;
                let mut names = Vec::new();
                for _ in 0..count {
                    let at = self.r.pos();
                    let name = self.utf(false)?;
                    self.leaf(node, "interface", at, text(name.clone()));
                    names.push(name);
                }
                self.annotation(node, depth)?;
                let parent_desc =
                    self.class_desc(node, "superClassDesc", depth.saturating_add(1))?;
                self.set_handle(
                    handle,
                    Handle::Class(ClassDesc {
                        name: "proxy".to_owned(),
                        flags: SC_SERIALIZABLE,
                        fields: Vec::new(),
                        parent: parent_desc,
                    }),
                );
                let span = self.span(start);
                self.tree.update(node, |n| {
                    n.span(span)
                        .value(text("proxy"))
                        .summary(ellipsize(&names.join(", "), 120))
                });
                Ok(Some(handle))
            }
            tc => Err(Diagnostic::malformed(format!(
                "expected a class descriptor, found {tc:#04x}"
            ))
            .at(self.file.sub(to_u64(start), 1))),
        }
    }

    /// Reads a string or reference without adding a node.
    fn object_quiet(&mut self, _depth: u32) -> Step<Option<u32>> {
        match self.u8()? {
            TC_STRING => {
                let s = self.utf(false)?;
                Ok(Some(self.new_handle(Handle::Text(s))))
            }
            TC_LONGSTRING => {
                let s = self.utf(true)?;
                Ok(Some(self.new_handle(Handle::Text(s))))
            }
            TC_REFERENCE => Ok(Some(self.int::<u32>()?)),
            _ => Err(self.fail("string")),
        }
    }

    /// The class hierarchy of a descriptor, superclass first.
    fn hierarchy(&self, handle: Option<u32>) -> Vec<ClassDesc> {
        let mut out = Vec::new();
        let mut next = handle;
        while let Some(desc) = self.class(next) {
            if out.len() >= 64 {
                break;
            }
            out.push(desc.clone());
            next = desc.parent;
        }
        out.reverse();
        out
    }

    fn primitive(&mut self, parent: usize, label: &str, code: u8) -> Step<()> {
        let start = self.r.pos();
        let value = match code {
            b'B' => Value::Int {
                value: self.int::<i8>()?.into(),
                bits: 8,
            },
            b'C' => {
                let c = self.int::<u16>()?;
                text(char::from_u32(c.into()).map_or_else(|| format!("\\u{c:04x}"), String::from))
            }
            b'D' => Value::Float(self.int::<f64>()?),
            b'F' => Value::Float(self.int::<f32>()?.into()),
            b'I' => Value::Int {
                value: self.int::<i32>()?.into(),
                bits: 32,
            },
            b'J' => Value::Int {
                value: self.int::<i64>()?,
                bits: 64,
            },
            b'S' => Value::Int {
                value: self.int::<i16>()?.into(),
                bits: 16,
            },
            b'Z' => Value::Bool(self.u8()? != 0),
            _ => return Err(self.fail("field type code")),
        };
        self.leaf(parent, label, start, value);
        Ok(())
    }

    fn object(&mut self, parent: usize, label: &str, depth: u32) -> Step<Option<u32>> {
        if depth > MAX_DEPTH {
            return Err(Diagnostic::limit("objects nested too deeply")
                .at(self.file.sub(to_u64(self.r.pos()), 1)));
        }
        let start = self.r.pos();
        let tc = self.peek()?;
        match tc {
            TC_CLASSDESC | TC_PROXYCLASSDESC => return self.class_desc(parent, label, depth),
            _ => {
                self.u8()?;
            }
        }
        let deeper = depth.saturating_add(1);
        match tc {
            TC_NULL => {
                self.leaf(parent, label, start, text("null"));
                Ok(None)
            }
            TC_REFERENCE => {
                let h = self.int::<u32>()?;
                let desc = self.describe(h);
                self.leaf(parent, label, start, text(format!("→ {desc}")));
                Ok(Some(h))
            }
            TC_STRING | TC_LONGSTRING => {
                let s = self.utf(tc == TC_LONGSTRING)?;
                let h = self.new_handle(Handle::Text(s.clone()));
                self.leaf(parent, label, start, text(s));
                Ok(Some(h))
            }
            TC_RESET => {
                self.handles.clear();
                self.leaf(parent, label, start, text("reset"));
                Ok(None)
            }
            TC_EXCEPTION => {
                self.handles.clear();
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let h = self.object(node, "exception", deeper)?;
                self.handles.clear();
                let span = self.span(start);
                self.tree
                    .update(node, |n| n.span(span).value(text("exception")));
                Ok(h)
            }
            TC_CLASS => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let desc = self.class_desc(node, "classDesc", deeper)?;
                let name = self.class(desc).map(|c| c.name.clone()).unwrap_or_default();
                let h = self.new_handle(Handle::Object("java.lang.Class".to_owned()));
                let span = self.span(start);
                self.tree
                    .update(node, |n| n.span(span).value(text(format!("class {name}"))));
                Ok(Some(h))
            }
            TC_ENUM => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let desc = self.class_desc(node, "classDesc", deeper)?;
                let name = self.class(desc).map(|c| c.name.clone()).unwrap_or_default();
                let h = self.new_handle(Handle::Object(name.clone()));
                let constant = self.object(node, "constant", deeper)?;
                let constant = match constant.and_then(|c| self.handle(c)) {
                    Some(Handle::Text(s)) => s.clone(),
                    _ => "?".to_owned(),
                };
                let span = self.span(start);
                self.tree.update(node, |n| {
                    n.span(span).value(text(format!("{name}.{constant}")))
                });
                Ok(Some(h))
            }
            TC_ARRAY => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let desc = self.class_desc(node, "classDesc", deeper)?;
                let name = self.class(desc).map(|c| c.name.clone()).unwrap_or_default();
                let h = self.new_handle(Handle::Object(name.clone()));
                let size = self.int::<i32>()?;
                let size = u64::try_from(size).map_err(|_| self.fail("array size"))?;
                let code = name.as_bytes().get(1).copied().unwrap_or(b'L');
                if let Some(width) = element_size(code) {
                    let at = self.r.pos();
                    let bytes = self.bytes(size.saturating_mul(to_u64(width)), "array")?;
                    let preview = bytes.get(..64).unwrap_or(bytes).to_vec();
                    let node_span = self.span(at);
                    self.tree.add(
                        Some(node),
                        Node::new("elements")
                            .span(node_span)
                            .value(Value::Bytes(preview))
                            .summary(format!("{size} × {}", type_name(code))),
                    );
                } else {
                    for i in 0..size {
                        self.object(node, &format!("[{i}]"), deeper)?;
                    }
                }
                let span = self.span(start);
                self.tree.update(node, |n| {
                    n.span(span)
                        .value(text(name))
                        .summary(format!("{size} elements"))
                });
                Ok(Some(h))
            }
            TC_OBJECT => {
                let node = self.tree.add(Some(parent), Node::new(label.to_owned()));
                let desc = self.class_desc(node, "classDesc", deeper)?;
                let name = self.class(desc).map(|c| c.name.clone()).unwrap_or_default();
                let h = self.new_handle(Handle::Object(name.clone()));
                for class in self.hierarchy(desc) {
                    let data = self
                        .tree
                        .add(Some(node), Node::new(format!("{} data", class.name)));
                    let at = self.r.pos();
                    if class.flags & SC_SERIALIZABLE != 0 {
                        for field in &class.fields {
                            if field.code == b'L' || field.code == b'[' {
                                self.object(data, &field.name, deeper)?;
                            } else {
                                self.primitive(data, &field.name, field.code)?;
                            }
                        }
                        if class.flags & SC_WRITE_METHOD != 0 {
                            self.annotation(data, deeper)?;
                        }
                    } else if class.flags & SC_EXTERNALIZABLE != 0 {
                        if class.flags & SC_BLOCK_DATA == 0 {
                            return Err(Diagnostic::unsupported(
                                "externalizable data in protocol version 1",
                            )
                            .at(self.file.sub(to_u64(at), 1)));
                        }
                        self.annotation(data, deeper)?;
                    }
                    let span = self.span(at);
                    self.tree.update(data, |n| n.span(span));
                }
                let span = self.span(start);
                self.tree
                    .update(node, |n| n.span(span).value(text(name.clone())));
                if depth == 0 {
                    self.top.push(name);
                }
                Ok(Some(h))
            }
            other => Err(
                Diagnostic::malformed(format!("unexpected type code {other:#04x}"))
                    .at(self.file.sub(to_u64(start), 1)),
            ),
        }
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    if file.len > MAX_STREAM {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_STREAM:#x} bytes are decoded"
        )));
    }
    let data = cx.read_avail(file.sub(0, MAX_STREAM)).await?;
    let mut p = Parser {
        r: Reader::new(&data),
        file,
        tree: Tree::default(),
        handles: Vec::new(),
        top: Vec::new(),
    };
    let root = p.tree.add(None, Node::new("stream"));
    p.r.int::<u16>(BE);
    p.leaf(root, "magic", 0, hex(0xaced, 16));
    let version = p.r.int::<u16>(BE).unwrap_or(0);
    p.leaf(
        root,
        "version",
        2,
        crate::formats::binutil::dec(version.into(), 16),
    );
    let mut items = 0u32;
    while !p.r.at_end() {
        let at = p.r.pos();
        if let Err(e) = p.content(root, "content", 0) {
            p.tree.add(
                Some(root),
                Node::new("Undecoded").span(file.tail(to_u64(at))).diag(e),
            );
            break;
        }
        items = items.saturating_add(1);
    }
    let mut summary = format!("Java serialization stream, {items} items");
    if !p.top.is_empty() {
        summary.push_str(&format!(": {}", ellipsize(&p.top.join(", "), 120)));
    }
    cx.annotate(summary);
    let tree = Arc::new(p.tree);
    Tree::emit_children(&cx, &tree, root).await;
    Ok(())
}

/// The length of a serialization stream holding one object at the start
/// of `data` (header included), if it decodes.
pub fn stream_len(data: &[u8]) -> Option<usize> {
    if !data.starts_with(b"\xac\xed\x00\x05") {
        return None;
    }
    let mut p = Parser {
        r: Reader::at(data, 4),
        file: Span::new(crate::span::SourceId(0), 0, to_u64(data.len())),
        tree: Tree::default(),
        handles: Vec::new(),
        top: Vec::new(),
    };
    let root = p.tree.add(None, Node::new("stream"));
    p.content(root, "content", 0).ok()?;
    Some(p.r.pos())
}
