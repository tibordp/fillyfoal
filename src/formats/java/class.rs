//! Java class files (JVMS chapter 4).
//!
//! Almost everything after the header depends on the constant pool, which
//! has variable-length entries and must be walked first; so expanding the
//! file reads the whole class (class files are small) and indexes it once:
//! constant pool entries, fields, methods and attributes. Each node then
//! resolves names through the index, and bytecode is disassembled only when
//! a `Code` attribute is expanded.

use std::sync::Arc;

use super::opcodes::{ARRAY_TYPE, OPCODES, Operands};
use crate::bytes::{to_u64, to_usize};
use crate::cx::{Block, Cx};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::binutil::{
    NodeExt, Reader, ellipsize, mutf8, name_or, text,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag};

const BE: Endian = Endian::Big;
/// Attributes nest (Code contains attributes); real classes use two levels.
const MAX_DEPTH: u32 = 4;
/// Longest constant chain we follow when resolving a name.
const MAX_RESOLVE: u32 = 4;

pub static FORMAT: Format = Format {
    name: "java-class",
    title: "Java class file",
    extensions: &["class"],
    mime: "application/java-vm",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let major = crate::bytes::u16_be(h.data, 6).unwrap_or(0);
    h.starts_with(b"\xca\xfe\xba\xbe") && (45..=100).contains(&major)
}

const TAG: EnumTable = &[
    (1, "Utf8"),
    (3, "Integer"),
    (4, "Float"),
    (5, "Long"),
    (6, "Double"),
    (7, "Class"),
    (8, "String"),
    (9, "Fieldref"),
    (10, "Methodref"),
    (11, "InterfaceMethodref"),
    (12, "NameAndType"),
    (15, "MethodHandle"),
    (16, "MethodType"),
    (17, "Dynamic"),
    (18, "InvokeDynamic"),
    (19, "Module"),
    (20, "Package"),
];

const REFERENCE_KIND: EnumTable = &[
    (1, "REF_getField"),
    (2, "REF_getStatic"),
    (3, "REF_putField"),
    (4, "REF_putStatic"),
    (5, "REF_invokeVirtual"),
    (6, "REF_invokeStatic"),
    (7, "REF_invokeSpecial"),
    (8, "REF_newInvokeSpecial"),
    (9, "REF_invokeInterface"),
];

const CLASS_FLAGS: FlagTable = &[
    flag(0x0001, "PUBLIC"),
    flag(0x0002, "PRIVATE"),
    flag(0x0004, "PROTECTED"),
    flag(0x0008, "STATIC"),
    flag(0x0010, "FINAL"),
    flag(0x0020, "SUPER"),
    flag(0x0200, "INTERFACE"),
    flag(0x0400, "ABSTRACT"),
    flag(0x1000, "SYNTHETIC"),
    flag(0x2000, "ANNOTATION"),
    flag(0x4000, "ENUM"),
    flag(0x8000, "MODULE"),
];

const FIELD_FLAGS: FlagTable = &[
    flag(0x0001, "PUBLIC"),
    flag(0x0002, "PRIVATE"),
    flag(0x0004, "PROTECTED"),
    flag(0x0008, "STATIC"),
    flag(0x0010, "FINAL"),
    flag(0x0040, "VOLATILE"),
    flag(0x0080, "TRANSIENT"),
    flag(0x1000, "SYNTHETIC"),
    flag(0x4000, "ENUM"),
];

const METHOD_FLAGS: FlagTable = &[
    flag(0x0001, "PUBLIC"),
    flag(0x0002, "PRIVATE"),
    flag(0x0004, "PROTECTED"),
    flag(0x0008, "STATIC"),
    flag(0x0010, "FINAL"),
    flag(0x0020, "SYNCHRONIZED"),
    flag(0x0040, "BRIDGE"),
    flag(0x0080, "VARARGS"),
    flag(0x0100, "NATIVE"),
    flag(0x0400, "ABSTRACT"),
    flag(0x0800, "STRICT"),
    flag(0x1000, "SYNTHETIC"),
];

const PARAMETER_FLAGS: FlagTable = &[
    flag(0x0010, "FINAL"),
    flag(0x1000, "SYNTHETIC"),
    flag(0x8000, "MANDATED"),
];

/// The Java release that introduced a class file major version.
pub fn release(major: u16) -> String {
    match major {
        45 => "Java 1.1".to_owned(),
        46 => "Java 1.2".to_owned(),
        47 => "Java 1.3".to_owned(),
        48 => "Java 1.4".to_owned(),
        49..=100 => format!("Java {}", major.saturating_sub(44)),
        _ => format!("class version {major}"),
    }
}

// ---------------------------------------------------------------------------
// Model

#[derive(Clone, Debug)]
enum Constant {
    Unusable,
    Utf8(String),
    Integer(i32),
    Float(f32),
    Long(i64),
    Double(f64),
    Class(u16),
    String(u16),
    Ref(u16, u16),
    NameAndType(u16, u16),
    MethodHandle(u8, u16),
    MethodType(u16),
    Dynamic(u16, u16),
    Module(u16),
    Package(u16),
}

#[derive(Clone, Debug)]
struct Entry {
    offset: usize,
    len: usize,
    tag: u8,
    value: Constant,
}

#[derive(Clone, Copy, Debug)]
struct Attribute {
    offset: usize,
    /// Including the six-byte header.
    len: usize,
    name: u16,
}

#[derive(Clone, Debug)]
struct Member {
    offset: usize,
    len: usize,
    access: u16,
    name: u16,
    descriptor: u16,
    attributes: Vec<Attribute>,
}

type Class = Arc<ClassInfo>;

struct ClassInfo {
    file: Span,
    data: Vec<u8>,
    minor: u16,
    major: u16,
    pool: Vec<Entry>,
    pool_span: (usize, usize),
    access_offset: usize,
    access: u16,
    this_class: u16,
    super_class: u16,
    interfaces: (usize, Vec<u16>),
    fields: (usize, usize, Vec<Member>),
    methods: (usize, usize, Vec<Member>),
    attributes: (usize, usize, Vec<Attribute>),
}

impl ClassInfo {
    fn span(&self, offset: usize, len: usize) -> Span {
        self.file.sub(to_u64(offset), to_u64(len))
    }

    fn block(&self, offset: usize, len: usize) -> Block {
        let end = offset.saturating_add(len).min(self.data.len());
        Block {
            span: self.span(offset, len),
            data: self
                .data
                .get(offset.min(end)..end)
                .unwrap_or_default()
                .to_vec(),
        }
    }

    fn constant(&self, index: u16) -> Option<&Entry> {
        self.pool.get(usize::from(index))
    }

    fn utf8(&self, index: u16) -> Option<&str> {
        match &self.constant(index)?.value {
            Constant::Utf8(s) => Some(s),
            _ => None,
        }
    }

    /// A human-readable rendering of a constant, following references.
    fn resolve(&self, index: u16) -> String {
        self.resolve_depth(index, MAX_RESOLVE)
    }

    fn resolve_depth(&self, index: u16, depth: u32) -> String {
        let Some(entry) = self.constant(index) else {
            return format!("#{index}?");
        };
        let Some(next) = depth.checked_sub(1) else {
            return format!("#{index}");
        };
        let r = |i: u16| self.resolve_depth(i, next);
        match &entry.value {
            Constant::Unusable => "(unusable)".to_owned(),
            Constant::Utf8(s) => s.clone(),
            Constant::Integer(v) => v.to_string(),
            Constant::Float(v) => format!("{v}f"),
            Constant::Long(v) => format!("{v}L"),
            Constant::Double(v) => format!("{v}d"),
            Constant::Class(i) | Constant::Module(i) | Constant::Package(i) => r(*i),
            Constant::String(i) => format!("{:?}", r(*i)),
            Constant::MethodType(i) => r(*i),
            Constant::Ref(class, nat) => format!("{}.{}", r(*class), r(*nat)),
            Constant::NameAndType(name, desc) => format!("{}:{}", r(*name), r(*desc)),
            Constant::MethodHandle(kind, i) => format!(
                "{} {}",
                name_or(REFERENCE_KIND, (*kind).into(), "kind"),
                r(*i)
            ),
            Constant::Dynamic(bsm, nat) => format!("bootstrap #{bsm} {}", r(*nat)),
        }
    }

    /// A class name in source form (`java.lang.Object`).
    fn class_name(&self, index: u16) -> String {
        if index == 0 {
            return "(none)".to_owned();
        }
        self.resolve(index).replace('/', ".")
    }
}

// ---------------------------------------------------------------------------
// Loading

fn malformed(what: &str, at: usize, file: Span) -> Diagnostic {
    Diagnostic::malformed(format!("truncated or malformed {what}")).at(file.sub(to_u64(at), 1))
}

fn read_attributes(r: &mut Reader<'_>, file: Span) -> Result<Vec<Attribute>> {
    let count = r
        .int::<u16>(BE)
        .ok_or_else(|| malformed("attribute count", r.pos(), file))?;
    let mut out = Vec::new();
    for _ in 0..count {
        let offset = r.pos();
        let name = r
            .int::<u16>(BE)
            .ok_or_else(|| malformed("attribute", offset, file))?;
        let len = r
            .int::<u32>(BE)
            .ok_or_else(|| malformed("attribute", offset, file))?;
        r.bytes(to_usize(len.into()))
            .ok_or_else(|| malformed("attribute", offset, file))?;
        out.push(Attribute {
            offset,
            len: to_usize(u64::from(len).saturating_add(6)),
            name,
        });
    }
    Ok(out)
}

fn read_members(r: &mut Reader<'_>, file: Span) -> Result<(usize, usize, Vec<Member>)> {
    let start = r.pos();
    let count = r
        .int::<u16>(BE)
        .ok_or_else(|| malformed("member count", start, file))?;
    let mut out = Vec::new();
    for _ in 0..count {
        let offset = r.pos();
        let bad = || malformed("field or method", offset, file);
        let access = r.int::<u16>(BE).ok_or_else(bad)?;
        let name = r.int::<u16>(BE).ok_or_else(bad)?;
        let descriptor = r.int::<u16>(BE).ok_or_else(bad)?;
        let attributes = read_attributes(r, file)?;
        out.push(Member {
            offset,
            len: r.pos().saturating_sub(offset),
            access,
            name,
            descriptor,
            attributes,
        });
    }
    Ok((start, r.pos().saturating_sub(start), out))
}

fn read_constant(r: &mut Reader<'_>, tag: u8) -> Option<Constant> {
    Some(match tag {
        1 => {
            let len = r.int::<u16>(BE)?;
            Constant::Utf8(mutf8(r.bytes(usize::from(len))?))
        }
        3 => Constant::Integer(r.int::<i32>(BE)?),
        4 => Constant::Float(r.int::<f32>(BE)?),
        5 => Constant::Long(r.int::<i64>(BE)?),
        6 => Constant::Double(r.int::<f64>(BE)?),
        7 => Constant::Class(r.int::<u16>(BE)?),
        8 => Constant::String(r.int::<u16>(BE)?),
        9..=11 => Constant::Ref(r.int::<u16>(BE)?, r.int::<u16>(BE)?),
        12 => Constant::NameAndType(r.int::<u16>(BE)?, r.int::<u16>(BE)?),
        15 => Constant::MethodHandle(r.u8()?, r.int::<u16>(BE)?),
        16 => Constant::MethodType(r.int::<u16>(BE)?),
        17 | 18 => Constant::Dynamic(r.int::<u16>(BE)?, r.int::<u16>(BE)?),
        19 => Constant::Module(r.int::<u16>(BE)?),
        20 => Constant::Package(r.int::<u16>(BE)?),
        _ => return None,
    })
}

async fn load(cx: &Cx, file: Span) -> Result<ClassInfo> {
    if file.len > cx.limits().max_read {
        return Err(Diagnostic::limit("class file is larger than the read limit").at(file));
    }
    let data = cx.read_avail(file).await?;
    let mut r = Reader::new(&data);
    let bad = |what: &str, at: usize| malformed(what, at, file);
    r.int::<u32>(BE).ok_or_else(|| bad("header", 0))?;
    let minor = r.int::<u16>(BE).ok_or_else(|| bad("header", 4))?;
    let major = r.int::<u16>(BE).ok_or_else(|| bad("header", 6))?;
    let count = r.int::<u16>(BE).ok_or_else(|| bad("header", 8))?;
    let pool_start = r.pos();
    let mut pool = vec![Entry {
        offset: pool_start,
        len: 0,
        tag: 0,
        value: Constant::Unusable,
    }];
    while pool.len() < usize::from(count) {
        if pool.len() % 256 == 0 {
            cx.checkpoint().await;
        }
        let offset = r.pos();
        let tag = r.u8().ok_or_else(|| bad("constant pool", offset))?;
        let value = read_constant(&mut r, tag).ok_or_else(|| {
            Diagnostic::malformed(format!("constant pool tag {tag}"))
                .at(file.sub(to_u64(offset), 1))
        })?;
        let wide = matches!(value, Constant::Long(_) | Constant::Double(_));
        pool.push(Entry {
            offset,
            len: r.pos().saturating_sub(offset),
            tag,
            value,
        });
        if wide {
            pool.push(Entry {
                offset: r.pos(),
                len: 0,
                tag: 0,
                value: Constant::Unusable,
            });
        }
    }
    let pool_span = (pool_start, r.pos().saturating_sub(pool_start));
    let access_offset = r.pos();
    let access = r.int::<u16>(BE).ok_or_else(|| bad("class header", access_offset))?;
    let this_class = r.int::<u16>(BE).ok_or_else(|| bad("class header", access_offset))?;
    let super_class = r.int::<u16>(BE).ok_or_else(|| bad("class header", access_offset))?;
    let interfaces_at = r.pos();
    let n = r.int::<u16>(BE).ok_or_else(|| bad("interfaces", interfaces_at))?;
    let mut interfaces = Vec::new();
    for _ in 0..n {
        interfaces.push(r.int::<u16>(BE).ok_or_else(|| bad("interfaces", interfaces_at))?);
    }
    cx.checkpoint().await;
    let fields = read_members(&mut r, file)?;
    cx.checkpoint().await;
    let methods = read_members(&mut r, file)?;
    let attributes_at = r.pos();
    let attributes = read_attributes(&mut r, file)?;
    let attributes = (attributes_at, r.pos().saturating_sub(attributes_at), attributes);
    Ok(ClassInfo {
        file,
        data,
        minor,
        major,
        pool,
        pool_span,
        access_offset,
        access,
        this_class,
        super_class,
        interfaces: (interfaces_at, interfaces),
        fields,
        methods,
        attributes,
    })
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(crate::fields::struct_node(
        "Header",
        file.sub(0, 10),
        BE,
        (),
        header,
    ));
    let c: Class = Arc::new(load(&cx, file).await?);

    let kind = if c.access & 0x8000 != 0 {
        "module"
    } else if c.access & 0x2000 != 0 {
        "annotation"
    } else if c.access & 0x0200 != 0 {
        "interface"
    } else if c.access & 0x4000 != 0 {
        "enum"
    } else {
        "class"
    };
    let mut summary = format!(
        "Java {kind} {} ({}{})",
        c.class_name(c.this_class),
        release(c.major),
        if c.minor == 0xffff { ", preview" } else { "" }
    );
    if c.super_class != 0 && c.class_name(c.super_class) != "java.lang.Object" {
        summary.push_str(&format!(", extends {}", c.class_name(c.super_class)));
    }
    summary.push_str(&format!(
        ", {} fields, {} methods",
        c.fields.2.len(),
        c.methods.2.len()
    ));
    cx.annotate(summary);

    let (pool_offset, pool_len) = c.pool_span;
    cx.emit(
        Node::new("Constant Pool")
            .span(c.span(pool_offset, pool_len))
            .summary(format!("{} entries", c.pool.len().saturating_sub(1)))
            .lazy(constant_pool, c.clone()),
    );
    let flags = |raw: u16, table: FlagTable| {
        let (set, unknown) = decode_flags(table, raw.into());
        Value::Flags {
            raw: raw.into(),
            bits: 16,
            set,
            unknown,
        }
    };
    cx.emit(
        Node::new("Access Flags")
            .span(c.span(c.access_offset, 2))
            .value(flags(c.access, CLASS_FLAGS)),
    );
    cx.emit(
        Node::new("This Class")
            .span(c.span(c.access_offset.saturating_add(2), 2))
            .value(text(c.class_name(c.this_class)))
            .summary(format!("#{}", c.this_class)),
    );
    cx.emit(
        Node::new("Super Class")
            .span(c.span(c.access_offset.saturating_add(4), 2))
            .value(text(c.class_name(c.super_class)))
            .summary(format!("#{}", c.super_class)),
    );
    let (at, list) = &c.interfaces;
    if !list.is_empty() {
        let names: Vec<String> = list.iter().map(|&i| c.class_name(i)).collect();
        cx.emit(
            Node::new("Interfaces")
                .span(c.span(*at, list.len().saturating_mul(2).saturating_add(2)))
                .summary(ellipsize(&names.join(", "), 120))
                .lazy(interfaces, c.clone()),
        );
    }
    for (name, which) in [("Fields", false), ("Methods", true)] {
        let (offset, len, members) = if which { &c.methods } else { &c.fields };
        cx.emit(
            Node::new(name)
                .span(c.span(*offset, *len))
                .summary(format!("{} entries", members.len()))
                .lazy(member_list, (c.clone(), which)),
        );
    }
    let (offset, len, attributes) = &c.attributes;
    cx.emit(
        Node::new("Attributes")
            .span(c.span(*offset, *len))
            .summary(attribute_names(&c, attributes))
            .lazy(attribute_list, (c.clone(), Owner::Class, 0u32)),
    );
    let end = offset.saturating_add(*len);
    if to_u64(end) < file.len {
        cx.emit(
            Node::new("Trailing data")
                .span(file.tail(to_u64(end)))
                .diag(Diagnostic::warning("data after the end of the class")),
        );
    }
    Ok(())
}

fn header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("magic").hex().desc("0xcafebabe").emit()?;
    f.u16("minor_version")
        .with(|&v, n| if v == 0xffff { n.summary("preview features") } else { n })
        .emit()?;
    f.u16("major_version")
        .with(|&v, n| n.summary(release(v)))
        .emit()?;
    f.u16("constant_pool_count").emit()?;
    Ok(())
}

fn attribute_names(c: &ClassInfo, list: &[Attribute]) -> String {
    let names: Vec<&str> = list.iter().map(|a| c.utf8(a.name).unwrap_or("?")).collect();
    ellipsize(&names.join(", "), 120)
}

// ---------------------------------------------------------------------------
// Constant pool

async fn constant_pool(cx: Cx, c: Class) -> Result<()> {
    let count = c.pool.len().saturating_sub(1);
    cx.set_count(Count::Exact(to_u64(count)));
    for (index, entry) in c.pool.iter().enumerate().skip(1) {
        let label = format!("#{index}");
        let node = if entry.tag == 0 {
            Node::new(label).summary("(second half of a Long or Double)")
        } else {
            let index = u16::try_from(index).unwrap_or(u16::MAX);
            let value = match &entry.value {
                Constant::Utf8(s) => text(s.clone()),
                Constant::Integer(v) => Value::Int {
                    value: (*v).into(),
                    bits: 32,
                },
                Constant::Long(v) => Value::Int {
                    value: *v,
                    bits: 64,
                },
                Constant::Float(v) => Value::Float((*v).into()),
                Constant::Double(v) => Value::Float(*v),
                _ => text(c.resolve(index)),
            };
            Node::new(label)
                .span(c.span(entry.offset, entry.len))
                .value(value)
                .summary(name_or(TAG, entry.tag.into(), "tag"))
                .lazy(constant_node, (c.clone(), index))
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn constant_node(cx: Cx, (c, index): (Class, u16)) -> Result<()> {
    let entry = c
        .constant(index)
        .ok_or_else(|| Diagnostic::internal("constant index out of range"))?;
    let block = c.block(entry.offset, entry.len);
    let mut f = Fields::emitting(&cx, &block, BE);
    let tag = f.u8("tag").enumeration(TAG).emit()?;
    let reference = |f: &mut Fields<'_>, name: &'static str| -> Result<u16> {
        f.u16(name)
            .with(|&v, n| n.summary(c.resolve(v)))
            .emit()
    };
    match tag {
        1 => {
            f.u16("length").emit()?;
            let len = block.data.len().saturating_sub(3);
            let bytes = block.data.get(3..).unwrap_or_default();
            f.bytes("bytes", to_u64(len))
                .with(|_, n| n.value(text(mutf8(bytes))))
                .emit()?;
        }
        3 => {
            f.i32("bytes").emit()?;
        }
        4 => {
            f.f32("bytes").emit()?;
        }
        5 => {
            f.int::<i64>("bytes").emit()?;
        }
        6 => {
            f.f64("bytes").emit()?;
        }
        7 | 19 | 20 => {
            reference(&mut f, "name_index")?;
        }
        8 => {
            reference(&mut f, "string_index")?;
        }
        9..=11 => {
            reference(&mut f, "class_index")?;
            reference(&mut f, "name_and_type_index")?;
        }
        12 => {
            reference(&mut f, "name_index")?;
            reference(&mut f, "descriptor_index")?;
        }
        15 => {
            f.u8("reference_kind").enumeration(REFERENCE_KIND).emit()?;
            reference(&mut f, "reference_index")?;
        }
        16 => {
            reference(&mut f, "descriptor_index")?;
        }
        _ => {
            f.u16("bootstrap_method_attr_index").emit()?;
            reference(&mut f, "name_and_type_index")?;
        }
    }
    Ok(())
}

async fn interfaces(cx: Cx, c: Class) -> Result<()> {
    let (at, list) = &c.interfaces;
    cx.set_count(Count::Exact(to_u64(list.len())));
    for (i, &index) in list.iter().enumerate() {
        let offset = at.saturating_add(2).saturating_add(i.saturating_mul(2));
        cx.push(
            Node::new(format!("[{i}]"))
                .span(c.span(offset, 2))
                .value(text(c.class_name(index)))
                .summary(format!("#{index}")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Descriptors

/// One field type from a descriptor, in source form; advances `s`.
fn field_type(s: &mut std::str::Chars<'_>) -> Option<String> {
    let mut dims = 0usize;
    let base = loop {
        match s.next()? {
            '[' => dims = dims.saturating_add(1),
            'B' => break "byte".to_owned(),
            'C' => break "char".to_owned(),
            'D' => break "double".to_owned(),
            'F' => break "float".to_owned(),
            'I' => break "int".to_owned(),
            'J' => break "long".to_owned(),
            'S' => break "short".to_owned(),
            'Z' => break "boolean".to_owned(),
            'V' => break "void".to_owned(),
            'L' => {
                let name: String = s.by_ref().take_while(|&ch| ch != ';').collect();
                break name.replace('/', ".");
            }
            _ => return None,
        }
    };
    Some(format!("{base}{}", "[]".repeat(dims.min(255))))
}

/// `int[] name` for fields, `void name(String, int)` for methods.
fn declaration(name: &str, descriptor: &str) -> String {
    let mut s = descriptor.chars();
    if descriptor.starts_with('(') {
        s.next();
        let mut params = Vec::new();
        let mut rest = s.clone();
        while rest.clone().next().is_some_and(|ch| ch != ')') {
            match field_type(&mut rest) {
                Some(t) => params.push(t),
                None => return format!("{name}{descriptor}"),
            }
        }
        rest.next();
        let ret = field_type(&mut rest).unwrap_or_else(|| "?".to_owned());
        format!("{ret} {name}({})", params.join(", "))
    } else {
        match field_type(&mut s) {
            Some(t) => format!("{t} {name}"),
            None => format!("{name}: {descriptor}"),
        }
    }
}

fn modifiers(access: u16, method: bool) -> String {
    let table: &[(u16, &str)] = if method {
        &[
            (0x1, "public"),
            (0x2, "private"),
            (0x4, "protected"),
            (0x8, "static"),
            (0x10, "final"),
            (0x20, "synchronized"),
            (0x100, "native"),
            (0x400, "abstract"),
        ]
    } else {
        &[
            (0x1, "public"),
            (0x2, "private"),
            (0x4, "protected"),
            (0x8, "static"),
            (0x10, "final"),
            (0x40, "volatile"),
            (0x80, "transient"),
        ]
    };
    table
        .iter()
        .filter(|(bit, _)| access & bit != 0)
        .map(|(_, word)| *word)
        .collect::<Vec<_>>()
        .join(" ")
}

// ---------------------------------------------------------------------------
// Fields and methods

async fn member_list(cx: Cx, (c, methods): (Class, bool)) -> Result<()> {
    let members = if methods { &c.methods.2 } else { &c.fields.2 };
    cx.set_count(Count::Exact(to_u64(members.len())));
    for (i, m) in members.iter().enumerate() {
        let name = c.utf8(m.name).unwrap_or("?").to_owned();
        let descriptor = c.utf8(m.descriptor).unwrap_or("?");
        let mut summary = modifiers(m.access, methods);
        if !summary.is_empty() {
            summary.push(' ');
        }
        summary.push_str(&declaration(&name, descriptor));
        cx.push(
            Node::new(name)
                .span(c.span(m.offset, m.len))
                .summary(summary)
                .lazy(member_node, (c.clone(), methods, i)),
        )
        .await;
    }
    Ok(())
}

async fn member_node(cx: Cx, (c, methods, index): (Class, bool, usize)) -> Result<()> {
    let members = if methods { &c.methods.2 } else { &c.fields.2 };
    let m = members
        .get(index)
        .ok_or_else(|| Diagnostic::internal("member index out of range"))?;
    let block = c.block(m.offset, 8);
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("access_flags")
        .flags(if methods { METHOD_FLAGS } else { FIELD_FLAGS })
        .emit()?;
    for name in ["name_index", "descriptor_index"] {
        f.u16(name).with(|&v, n| n.summary(c.resolve(v))).emit()?;
    }
    f.u16("attributes_count").emit()?;
    let owner = if methods {
        Owner::Method(index)
    } else {
        Owner::Field(index)
    };
    for (i, a) in m.attributes.iter().enumerate() {
        cx.emit(attribute_node(&c, a, owner, 0, i));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Attributes

/// Where an attribute list lives, so expansions can find it again.
#[derive(Clone, Copy, Debug)]
enum Owner {
    Class,
    Field(usize),
    Method(usize),
    /// The attributes of a `Code` attribute (offset of the Code attribute).
    Code(usize),
}

fn attributes_of(c: &ClassInfo, owner: Owner) -> Vec<Attribute> {
    match owner {
        Owner::Class => c.attributes.2.clone(),
        Owner::Field(i) => c.fields.2.get(i).map(|m| m.attributes.clone()).unwrap_or_default(),
        Owner::Method(i) => c.methods.2.get(i).map(|m| m.attributes.clone()).unwrap_or_default(),
        Owner::Code(offset) => code_parts(c, offset).map(|p| p.attributes).unwrap_or_default(),
    }
}

async fn attribute_list(cx: Cx, (c, owner, depth): (Class, Owner, u32)) -> Result<()> {
    let list = attributes_of(&c, owner);
    cx.set_count(Count::Exact(to_u64(list.len())));
    for (i, a) in list.iter().enumerate() {
        cx.push(attribute_node(&c, a, owner, depth, i)).await;
    }
    Ok(())
}

fn attribute_node(c: &Class, a: &Attribute, owner: Owner, depth: u32, index: usize) -> Node {
    let name = c.utf8(a.name).unwrap_or("?").to_owned();
    let summary = attribute_summary(c, &name, a);
    Node::new(name)
        .span(c.span(a.offset, a.len))
        .maybe_summary(summary)
        .lazy(
            crate::expander!(self::attribute: (Class, Owner, u32, usize)),
            (c.clone(), owner, depth, index),
        )
}

fn body<'a>(c: &'a ClassInfo, a: &Attribute) -> &'a [u8] {
    let start = a.offset.saturating_add(6);
    let end = a.offset.saturating_add(a.len).min(c.data.len());
    c.data.get(start.min(end)..end).unwrap_or_default()
}

fn attribute_summary(c: &ClassInfo, name: &str, a: &Attribute) -> String {
    let b = body(c, a);
    let u16_at = |at: usize| crate::bytes::u16_be(b, at).unwrap_or(0);
    match name {
        "SourceFile" | "Signature" | "NestHost" | "ModuleMainClass" => c.resolve(u16_at(0)),
        "ConstantValue" => c.resolve(u16_at(0)),
        "Code" => code_parts(c, a.offset).map_or_else(String::new, |p| {
            format!(
                "{} bytes of bytecode, max stack {}, max locals {}",
                p.code.1, p.max_stack, p.max_locals
            )
        }),
        "Exceptions" => {
            let n = usize::from(u16_at(0));
            let names: Vec<String> = (0..n.min(16))
                .map(|i| c.class_name(u16_at(i.saturating_mul(2).saturating_add(2))))
                .collect();
            names.join(", ")
        }
        "LineNumberTable" | "LocalVariableTable" | "LocalVariableTypeTable" | "InnerClasses"
        | "BootstrapMethods" | "NestMembers" | "PermittedSubclasses"
        | "StackMapTable" | "ModulePackages" => format!("{} entries", u16_at(0)),
        "RuntimeVisibleAnnotations" | "RuntimeInvisibleAnnotations" => {
            annotation_types(c, b).join(", ")
        }
        "MethodParameters" => format!("{} entries", b.first().copied().unwrap_or(0)),
        "SourceDebugExtension" => ellipsize(&String::from_utf8_lossy(b), 80),
        _ => format!("{} bytes", b.len()),
    }
}

/// The type names of the annotations in a `Runtime*Annotations` body. Only
/// the first annotation's type can be found without decoding element values,
/// so this decodes them, skipping values.
fn annotation_types(c: &ClassInfo, b: &[u8]) -> Vec<String> {
    let mut r = Reader::new(b);
    let mut out = Vec::new();
    let Some(n) = r.int::<u16>(BE) else {
        return out;
    };
    for _ in 0..n.min(64) {
        let Some(kind) = r.int::<u16>(BE) else { break };
        out.push(c.utf8(kind).map_or_else(|| format!("#{kind}"), |s| {
            s.trim_start_matches('L').trim_end_matches(';').replace('/', ".")
        }));
        let Some(pairs) = r.int::<u16>(BE) else { break };
        for _ in 0..pairs {
            if r.int::<u16>(BE).is_none() || !skip_element(&mut r, 0) {
                return out;
            }
        }
    }
    out
}

fn skip_element(r: &mut Reader<'_>, depth: u32) -> bool {
    if depth > 16 {
        return false;
    }
    let Some(tag) = r.u8() else { return false };
    match tag {
        b'B' | b'C' | b'D' | b'F' | b'I' | b'J' | b'S' | b'Z' | b's' | b'c' => {
            r.int::<u16>(BE).is_some()
        }
        b'e' => r.int::<u32>(BE).is_some(),
        b'@' => {
            if r.int::<u16>(BE).is_none() {
                return false;
            }
            let Some(pairs) = r.int::<u16>(BE) else { return false };
            (0..pairs).all(|_| r.int::<u16>(BE).is_some() && skip_element(r, depth.saturating_add(1)))
        }
        b'[' => {
            let Some(n) = r.int::<u16>(BE) else { return false };
            (0..n).all(|_| skip_element(r, depth.saturating_add(1)))
        }
        _ => false,
    }
}

/// The parts of a `Code` attribute at `offset`.
struct CodeParts {
    max_stack: u16,
    max_locals: u16,
    /// Offset and length of the bytecode.
    code: (usize, usize),
    attributes: Vec<Attribute>,
}

fn code_parts(c: &ClassInfo, offset: usize) -> Option<CodeParts> {
    let mut r = Reader::at(&c.data, offset.checked_add(6)?);
    let max_stack = r.int::<u16>(BE)?;
    let max_locals = r.int::<u16>(BE)?;
    let len = to_usize(r.int::<u32>(BE)?.into());
    let code = (r.pos(), len);
    r.bytes(len)?;
    let n = r.int::<u16>(BE)?;
    r.bytes(usize::from(n).saturating_mul(8))?;
    let attributes = read_attributes(&mut r, c.file).ok()?;
    Some(CodeParts {
        max_stack,
        max_locals,
        code,
        attributes,
    })
}

async fn attribute(cx: Cx, (c, owner, depth, index): (Class, Owner, u32, usize)) -> Result<()> {
    let list = attributes_of(&c, owner);
    let a = *list
        .get(index)
        .ok_or_else(|| Diagnostic::internal("attribute index out of range"))?;
    let name = c.utf8(a.name).unwrap_or("?").to_owned();
    let block = c.block(a.offset, a.len);
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("attribute_name_index")
        .with(|&v, n| n.summary(c.resolve(v)))
        .emit()?;
    f.u32("attribute_length").emit()?;
    let reference = |f: &mut Fields<'_>, label: &'static str| -> Result<u16> {
        f.u16(label).with(|&v, n| n.summary(c.resolve(v))).emit()
    };
    let class_ref = |f: &mut Fields<'_>, label: &'static str| -> Result<u16> {
        f.u16(label).with(|&v, n| n.summary(c.class_name(v))).emit()
    };
    match name.as_str() {
        "SourceFile" => {
            reference(&mut f, "sourcefile_index")?;
        }
        "Signature" => {
            reference(&mut f, "signature_index")?;
        }
        "ConstantValue" => {
            reference(&mut f, "constantvalue_index")?;
        }
        "NestHost" => {
            class_ref(&mut f, "host_class_index")?;
        }
        "ModuleMainClass" => {
            class_ref(&mut f, "main_class_index")?;
        }
        "EnclosingMethod" => {
            class_ref(&mut f, "class_index")?;
            reference(&mut f, "method_index")?;
        }
        "Exceptions" | "NestMembers" | "PermittedSubclasses" | "ModulePackages" => {
            let n = f.u16("number").emit()?;
            for _ in 0..n {
                class_ref(&mut f, "index")?;
            }
        }
        "LineNumberTable" => {
            let n = f.u16("line_number_table_length").emit()?;
            for _ in 0..n {
                let start = f.pos();
                let pc = f.u16("start_pc").get()?;
                let line = f.u16("line_number").get()?;
                f.node(
                    Node::new(format!("line {line}"))
                        .span(block.span.sub(start, 4))
                        .summary(format!("pc {pc}")),
                );
            }
        }
        "LocalVariableTable" | "LocalVariableTypeTable" => {
            let n = f.u16("local_variable_table_length").emit()?;
            for _ in 0..n {
                let start = f.pos();
                let pc = f.u16("start_pc").get()?;
                let len = f.u16("length").get()?;
                let var = f.u16("name_index").get()?;
                let desc = f.u16("descriptor_index").get()?;
                let slot = f.u16("index").get()?;
                let name = c.utf8(var).unwrap_or("?");
                f.node(
                    Node::new(format!("slot {slot}"))
                        .span(block.span.sub(start, 10))
                        .value(text(declaration(name, c.utf8(desc).unwrap_or("?"))))
                        .summary(format!("pc {pc}..{}", u32::from(pc).saturating_add(len.into()))),
                );
            }
        }
        "InnerClasses" => {
            let n = f.u16("number_of_classes").emit()?;
            for _ in 0..n {
                let start = f.pos();
                let inner = f.u16("inner_class_info_index").get()?;
                let outer = f.u16("outer_class_info_index").get()?;
                let inner_name = f.u16("inner_name_index").get()?;
                let flags = f.u16("inner_class_access_flags").get()?;
                let (set, _) = decode_flags(CLASS_FLAGS, flags.into());
                f.node(
                    Node::new(c.class_name(inner))
                        .span(block.span.sub(start, 8))
                        .summary(format!(
                            "{}, outer {}, flags {}",
                            if inner_name == 0 {
                                "anonymous".to_owned()
                            } else {
                                c.resolve(inner_name)
                            },
                            c.class_name(outer),
                            set.join(" ")
                        )),
                );
            }
        }
        "BootstrapMethods" => {
            let n = f.u16("num_bootstrap_methods").emit()?;
            for i in 0..n {
                let start = f.pos();
                let method = f.u16("bootstrap_method_ref").get()?;
                let args = f.u16("num_bootstrap_arguments").get()?;
                let mut values = Vec::new();
                for _ in 0..args {
                    values.push(c.resolve(f.u16("argument").get()?));
                }
                f.node(
                    Node::new(format!("[{i}]"))
                        .span(block.span.sub(start, f.pos().saturating_sub(start)))
                        .value(text(c.resolve(method)))
                        .summary(ellipsize(&values.join(", "), 120)),
                );
            }
        }
        "MethodParameters" => {
            let n = f.u8("parameters_count").emit()?;
            for _ in 0..n {
                reference(&mut f, "name_index")?;
                f.u16("access_flags").flags(PARAMETER_FLAGS).emit()?;
            }
        }
        "Code" => {
            code(&cx, &c, &mut f, a, depth)?;
        }
        "SourceDebugExtension" => {
            let rest = f.remaining();
            f.bytes("debug_extension", rest)
                .with(|v, n| n.value(text(String::from_utf8_lossy(v).into_owned())))
                .emit()?;
        }
        "Deprecated" | "Synthetic" => {}
        _ => {
            let rest = f.remaining();
            if rest > 0 {
                f.node(Node::new("info").span(f.peek_span(rest)));
            }
        }
    }
    Ok(())
}

fn code(cx: &Cx, c: &Class, f: &mut Fields<'_>, a: Attribute, depth: u32) -> Result<()> {
    f.u16("max_stack").emit()?;
    f.u16("max_locals").emit()?;
    let len = f.u32("code_length").emit()?;
    let code = f.peek_span(len.into());
    f.node(
        Node::new("code")
            .span(code)
            .summary(format!("{len} bytes"))
            .lazy(disassemble, (c.clone(), a.offset)),
    );
    f.skip(len.into());
    let n = f.u16("exception_table_length").emit()?;
    for _ in 0..n {
        let start = f.pos();
        let from = f.u16("start_pc").get()?;
        let to = f.u16("end_pc").get()?;
        let handler = f.u16("handler_pc").get()?;
        let catch = f.u16("catch_type").get()?;
        f.node(
            Node::new(if catch == 0 {
                "any".to_owned()
            } else {
                c.class_name(catch)
            })
            .span(f.block().span.sub(start, 8))
            .summary(format!("pc {from}..{to} → {handler}")),
        );
    }
    let count = f.u16("attributes_count").emit()?;
    if depth >= MAX_DEPTH {
        cx.diag(Diagnostic::limit("attributes nested too deeply"));
        return Ok(());
    }
    let owner = Owner::Code(a.offset);
    for (i, attr) in attributes_of(c, owner).iter().take(count.into()).enumerate() {
        f.node(attribute_node(c, attr, owner, depth.saturating_add(1), i));
    }
    Ok(())
}

/// Lists the instructions of the `Code` attribute at `offset`.
async fn disassemble(cx: Cx, (c, offset): (Class, usize)) -> Result<()> {
    let parts = code_parts(&c, offset).ok_or_else(|| Diagnostic::malformed("bad Code attribute"))?;
    let (start, len) = parts.code;
    let end = start.saturating_add(len).min(c.data.len());
    let code = c.data.get(start..end).unwrap_or_default();
    let mut r = Reader::new(code);
    while !r.at_end() {
        let pc = r.pos();
        let Some(op) = r.u8() else { break };
        let (mnemonic, operands) = OPCODES
            .get(usize::from(op))
            .copied()
            .unwrap_or(("<reserved>", Operands::None));
        let decoded = operand(&c, &mut r, pc, operands);
        let (args, node_diag) = match decoded {
            Some(args) => (args, None),
            None => (
                String::new(),
                Some(Diagnostic::truncated(
                    c.span(start.saturating_add(pc), r.pos().saturating_sub(pc).max(1)),
                    0,
                )),
            ),
        };
        let mut node = Node::new(format!("{pc}"))
            .span(c.span(start.saturating_add(pc), r.pos().saturating_sub(pc)))
            .value(text(mnemonic))
            .maybe_summary(args);
        if let Some(d) = node_diag {
            node = node.diag(d);
            cx.push(node).await;
            break;
        }
        cx.push(node).await;
    }
    Ok(())
}

fn operand(c: &ClassInfo, r: &mut Reader<'_>, pc: usize, kind: Operands) -> Option<String> {
    let target = |delta: i64| {
        i64::try_from(pc)
            .ok()
            .and_then(|p| p.checked_add(delta))
            .map_or_else(|| "?".to_owned(), |t| t.to_string())
    };
    Some(match kind {
        Operands::None => String::new(),
        Operands::I8 => r.int::<i8>(BE)?.to_string(),
        Operands::I16 => r.int::<i16>(BE)?.to_string(),
        Operands::Local => r.u8()?.to_string(),
        Operands::Iinc => format!("{} by {}", r.u8()?, r.int::<i8>(BE)?),
        Operands::Cp8 => {
            let i = r.u8()?;
            format!("#{i} {}", c.resolve(i.into()))
        }
        Operands::Cp16 => {
            let i = r.int::<u16>(BE)?;
            format!("#{i} {}", c.resolve(i))
        }
        Operands::Interface => {
            let i = r.int::<u16>(BE)?;
            let count = r.u8()?;
            r.u8()?;
            format!("#{i} {}, {count}", c.resolve(i))
        }
        Operands::Dynamic => {
            let i = r.int::<u16>(BE)?;
            r.int::<u16>(BE)?;
            format!("#{i} {}", c.resolve(i))
        }
        Operands::Multi => {
            let i = r.int::<u16>(BE)?;
            let dims = r.u8()?;
            format!("#{i} {}, {dims} dimensions", c.resolve(i))
        }
        Operands::ArrayType => {
            let t = r.u8()?;
            name_or(ARRAY_TYPE, t.into(), "type")
        }
        Operands::Branch16 => target(r.int::<i16>(BE)?.into()),
        Operands::Branch32 => target(r.int::<i32>(BE)?.into()),
        Operands::TableSwitch | Operands::LookupSwitch => {
            // Operands are aligned to four bytes from the start of the code.
            let pad = (4usize.saturating_sub(r.pos() % 4)) % 4;
            r.bytes(pad)?;
            let default = r.int::<i32>(BE)?;
            let mut cases = Vec::new();
            if kind == Operands::TableSwitch {
                let low = r.int::<i32>(BE)?;
                let high = r.int::<i32>(BE)?;
                let n = i64::from(high).checked_sub(low.into())?.checked_add(1)?;
                for i in 0..n.clamp(0, 0x10000) {
                    let off = r.int::<i32>(BE)?;
                    cases.push(format!("{}: {}", i64::from(low).saturating_add(i), target(off.into())));
                }
            } else {
                let n = r.int::<i32>(BE)?;
                for _ in 0..n.clamp(0, 0x10000) {
                    let key = r.int::<i32>(BE)?;
                    let off = r.int::<i32>(BE)?;
                    cases.push(format!("{key}: {}", target(off.into())));
                }
            }
            cases.push(format!("default: {}", target(default.into())));
            ellipsize(&cases.join(", "), 200)
        }
        Operands::Wide => {
            let inner = r.u8()?;
            let (name, _) = OPCODES.get(usize::from(inner)).copied()?;
            let index = r.int::<u16>(BE)?;
            if inner == 0x84 {
                format!("{name} {index} by {}", r.int::<i16>(BE)?)
            } else {
                format!("{name} {index}")
            }
        }
    })
}
