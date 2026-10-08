//! Android compiled resources: binary XML (`AndroidManifest.xml` and layouts
//! inside APKs) and the resource table (`resources.arsc`).
//!
//! Both are trees of `ResChunk` records (type, header size, total size).
//! Binary XML is a string pool, a resource ID map and a flat sequence of
//! start/end element events, which are rebuilt into an element tree. The
//! resource table holds a global string pool and packages of typed entries
//! per configuration.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::util::binutil::{NodeExt, Reader, Tree, ellipsize, text};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;
/// Largest file decoded in memory.
const MAX_FILE: u64 = 32 << 20;
const MAX_DEPTH: usize = 256;

pub static AXML: Format = Format {
    name: "android-xml",
    title: "Android binary XML",
    extensions: &["xml"],
    mime: "application/vnd.android.axml",
    probe: Probe::Custom(|h| probe(h, 0x0003, 8)),
    dissect: crate::expander!(dissect_xml: Input),
};

pub static ARSC: Format = Format {
    name: "android-resources",
    title: "Android resource table",
    extensions: &["arsc"],
    mime: "application/vnd.android.arsc",
    probe: Probe::Custom(|h| probe(h, 0x0002, 12)),
    dissect: crate::expander!(dissect_table: Input),
};

fn probe(h: &Head<'_>, kind: u16, header: u16) -> bool {
    u16_le(h.data, 0) == Some(kind)
        && u16_le(h.data, 2) == Some(header)
        && u32_le(h.data, 4).is_some_and(|s| u64::from(s) <= h.len && s >= u32::from(header))
        && u16_le(h.data, usize::from(header)) == Some(0x0001)
}

const CHUNK_TYPE: EnumTable = &[
    (0x0000, "RES_NULL_TYPE"),
    (0x0001, "RES_STRING_POOL_TYPE"),
    (0x0002, "RES_TABLE_TYPE"),
    (0x0003, "RES_XML_TYPE"),
    (0x0100, "RES_XML_START_NAMESPACE_TYPE"),
    (0x0101, "RES_XML_END_NAMESPACE_TYPE"),
    (0x0102, "RES_XML_START_ELEMENT_TYPE"),
    (0x0103, "RES_XML_END_ELEMENT_TYPE"),
    (0x0104, "RES_XML_CDATA_TYPE"),
    (0x0180, "RES_XML_RESOURCE_MAP_TYPE"),
    (0x0200, "RES_TABLE_PACKAGE_TYPE"),
    (0x0201, "RES_TABLE_TYPE_TYPE"),
    (0x0202, "RES_TABLE_TYPE_SPEC_TYPE"),
    (0x0203, "RES_TABLE_LIBRARY_TYPE"),
    (0x0204, "RES_TABLE_OVERLAYABLE_TYPE"),
    (0x0205, "RES_TABLE_OVERLAYABLE_POLICY_TYPE"),
    (0x0206, "RES_TABLE_STAGED_ALIAS_TYPE"),
];

const POOL_FLAGS: FlagTable = &[flag(0x1, "SORTED"), flag(0x100, "UTF8")];

const VALUE_TYPE: EnumTable = &[
    (0x00, "NULL"),
    (0x01, "REFERENCE"),
    (0x02, "ATTRIBUTE"),
    (0x03, "STRING"),
    (0x04, "FLOAT"),
    (0x05, "DIMENSION"),
    (0x06, "FRACTION"),
    (0x07, "DYNAMIC_REFERENCE"),
    (0x08, "DYNAMIC_ATTRIBUTE"),
    (0x10, "INT_DEC"),
    (0x11, "INT_HEX"),
    (0x12, "INT_BOOLEAN"),
    (0x1c, "INT_COLOR_ARGB8"),
    (0x1d, "INT_COLOR_RGB8"),
    (0x1e, "INT_COLOR_ARGB4"),
    (0x1f, "INT_COLOR_RGB4"),
];

const ENTRY_FLAGS: FlagTable = &[
    flag(0x1, "COMPLEX"),
    flag(0x2, "PUBLIC"),
    flag(0x4, "WEAK"),
    flag(0x8, "COMPACT"),
];

// ---------------------------------------------------------------------------
// Chunks and string pools

#[derive(Clone, Copy, Debug)]
struct Chunk {
    kind: u16,
    header: usize,
    offset: usize,
    size: usize,
}

fn chunk_at(data: &[u8], offset: usize, limit: usize) -> Option<Chunk> {
    let kind = u16_le(data, offset)?;
    let header = usize::from(u16_le(data, offset.checked_add(2)?)?);
    let size = to_usize(u32_le(data, offset.checked_add(4)?)?.into());
    (header >= 8 && size >= header && offset.checked_add(size)? <= limit).then_some(Chunk {
        kind,
        header,
        offset,
        size,
    })
}

/// The chunks laid out consecutively in `start..end`.
async fn children(cx: &Cx, data: &[u8], start: usize, end: usize) -> Vec<Chunk> {
    let mut out = Vec::new();
    let mut at = start;
    while at.saturating_add(8) <= end {
        if out.len().is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let Some(c) = chunk_at(data, at, end) else {
            break;
        };
        out.push(c);
        at = at.saturating_add(c.size);
    }
    out
}

/// Decodes all strings of a string pool chunk.
async fn pool_strings(cx: &Cx, data: &[u8], c: &Chunk) -> Vec<String> {
    let base = c.offset;
    let count = u32_le(data, base.saturating_add(8)).unwrap_or(0);
    let flags = u32_le(data, base.saturating_add(16)).unwrap_or(0);
    let start = to_usize(u32_le(data, base.saturating_add(20)).unwrap_or(0).into());
    let utf8 = flags & 0x100 != 0;
    let offsets = base.saturating_add(c.header);
    let end = base.saturating_add(c.size).min(data.len());
    let chunk = data.get(..end).unwrap_or_default();
    let mut out = Vec::new();
    for i in 0..to_usize(count.into()) {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let Some(off) = u32_le(chunk, offsets.saturating_add(i.saturating_mul(4))) else {
            break;
        };
        let at = base
            .saturating_add(start)
            .saturating_add(to_usize(off.into()));
        out.push(pool_string(chunk, at, utf8).unwrap_or_default());
    }
    out
}

fn pool_string(data: &[u8], at: usize, utf8: bool) -> Option<String> {
    let mut r = Reader::at(data, at);
    if utf8 {
        let len8 = |r: &mut Reader<'_>| -> Option<usize> {
            let a = r.u8()?;
            Some(if a & 0x80 != 0 {
                (usize::from(a & 0x7f) << 8) | usize::from(r.u8()?)
            } else {
                usize::from(a)
            })
        };
        len8(&mut r)?; // UTF-16 length
        let n = len8(&mut r)?;
        Some(String::from_utf8_lossy(r.bytes(n)?).into_owned())
    } else {
        let a = r.int::<u16>(LE)?;
        let n = if a & 0x8000 != 0 {
            (usize::from(a & 0x7fff) << 16) | usize::from(r.int::<u16>(LE)?)
        } else {
            usize::from(a)
        };
        Some(crate::text::utf16(r.bytes(n.checked_mul(2)?)?, LE))
    }
}

fn string(pool: &[String], index: u32) -> Option<&str> {
    if index == u32::MAX {
        return None;
    }
    pool.get(to_usize(index.into())).map(String::as_str)
}

/// A `Res_value` rendered as text.
fn render_value(kind: u8, data: u32, pool: &[String]) -> String {
    match kind {
        0x00 => {
            if data == 1 {
                "@empty".to_owned()
            } else {
                "@null".to_owned()
            }
        }
        0x01 | 0x07 => format!("@0x{data:08x}"),
        0x02 | 0x08 => format!("?0x{data:08x}"),
        0x03 => string(pool, data).unwrap_or("?").to_owned(),
        0x04 => f32::from_bits(data).to_string(),
        0x05 | 0x06 => {
            let mantissa = f64::from(i32::from_le_bytes((data & 0xffff_ff00).to_le_bytes()));
            let radix = match (data >> 4) & 3 {
                0 => 1.0 / 256.0,
                1 => 1.0 / 32768.0,
                2 => 1.0 / 8_388_608.0,
                _ => 1.0 / 2_147_483_648.0,
            };
            let v = mantissa * radix;
            let unit = if kind == 0x05 {
                ["px", "dp", "sp", "pt", "in", "mm"]
                    .get(to_usize((data & 0xf).into()))
                    .copied()
                    .unwrap_or("?")
            } else if data & 0xf == 0 {
                "%"
            } else {
                "%p"
            };
            format!("{v}{unit}")
        }
        0x10 => i32::from_le_bytes(data.to_le_bytes()).to_string(),
        0x12 => (data != 0).to_string(),
        0x1c..=0x1f => format!("#{data:08x}"),
        _ => format!("0x{data:x}"),
    }
}

/// Field nodes for a chunk header.
fn chunk_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u16("type").enumeration(CHUNK_TYPE).emit()?;
    f.u16("headerSize").emit()?;
    f.u32("size").hex().emit()?;
    Ok(())
}

#[derive(Clone)]
struct Doc {
    data: Arc<Vec<u8>>,
    span: Span,
}

impl Doc {
    fn at(&self, offset: usize, len: usize) -> Span {
        self.span.sub(to_u64(offset), to_u64(len))
    }
}

fn pool_node(doc: &Doc, c: &Chunk, label: &str) -> Node {
    let count = u32_le(&doc.data, c.offset.saturating_add(8)).unwrap_or(0);
    let flags = u32_le(&doc.data, c.offset.saturating_add(16)).unwrap_or(0);
    Node::new(label.to_owned())
        .span(doc.at(c.offset, c.size))
        .summary(format!(
            "{count} strings, {}",
            if flags & 0x100 != 0 {
                "UTF-8"
            } else {
                "UTF-16"
            }
        ))
        .lazy(string_pool, (doc.clone(), *c))
}

async fn string_pool(cx: Cx, (doc, c): (Doc, Chunk)) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        doc.at(c.offset, c.header),
        LE,
        (),
        pool_header,
    ));
    let strings = pool_strings(&cx, &doc.data, &c).await;
    for (i, s) in strings.into_iter().enumerate() {
        cx.push(Node::new(format!("{i}")).value(text(s))).await;
    }
    Ok(())
}

fn pool_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    chunk_header(f, &())?;
    f.u32("stringCount").emit()?;
    f.u32("styleCount").emit()?;
    f.u32("flags").flags(POOL_FLAGS).emit()?;
    f.u32("stringsStart").hex().emit()?;
    f.u32("stylesStart").hex().emit()?;
    Ok(())
}

async fn load(cx: &Cx, file: Span) -> Result<Doc> {
    if file.len > MAX_FILE {
        return Err(Diagnostic::limit("file too large to decode").at(file));
    }
    Ok(Doc {
        data: Arc::new(cx.read(file).await?),
        span: file,
    })
}

// ---------------------------------------------------------------------------
// Binary XML

struct XmlBuilder<'a> {
    doc: &'a Doc,
    pool: &'a [String],
    ids: Vec<u32>,
    tree: Tree,
    stack: Vec<usize>,
    root_summary: Option<String>,
}

impl XmlBuilder<'_> {
    fn name(&self, index: u32) -> String {
        match string(self.pool, index) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => match self.ids.get(to_usize(index.into())) {
                Some(id) => format!("attr 0x{id:08x}"),
                None => format!("#{index}"),
            },
        }
    }

    fn element(&mut self, c: &Chunk) {
        let data = &self.doc.data;
        let body = c.offset.saturating_add(c.header);
        let w = |o: usize| u32_le(data, body.saturating_add(o)).unwrap_or(0);
        let name = self.name(w(4));
        let attr_start = usize::from(u16_le(data, body.saturating_add(8)).unwrap_or(20));
        let attr_size = usize::from(u16_le(data, body.saturating_add(10)).unwrap_or(20)).max(20);
        let count = usize::from(u16_le(data, body.saturating_add(12)).unwrap_or(0));
        let parent = self.stack.last().copied();
        let node = self.tree.add(
            parent,
            Node::new(format!("<{name}>")).span(self.doc.at(c.offset, c.size)),
        );
        let mut parts = Vec::new();
        for i in 0..count {
            let at = body
                .saturating_add(attr_start)
                .saturating_add(i.saturating_mul(attr_size));
            let aw = |o: usize| u32_le(data, at.saturating_add(o)).unwrap_or(0);
            let ns = aw(0);
            let attr = self.name(aw(4));
            let raw = aw(8);
            let kind = data.get(at.saturating_add(15)).copied().unwrap_or(0);
            let value = if raw != u32::MAX && kind == 0x03 {
                string(self.pool, raw).unwrap_or("?").to_owned()
            } else {
                render_value(kind, aw(16), self.pool)
            };
            let prefix = match string(self.pool, ns) {
                Some(uri) if uri.contains("android") => "android:",
                Some(_) => "ns:",
                None => "",
            };
            let label = format!("{prefix}{attr}");
            if parts.len() < 4 {
                parts.push(format!("{label}={value}"));
            }
            let kind_name = crate::value::lookup(VALUE_TYPE, kind.into()).unwrap_or("?");
            self.tree.add(
                Some(node),
                Node::new(label)
                    .span(self.doc.at(at, 20))
                    .value(text(value))
                    .summary(kind_name),
            );
        }
        let summary = ellipsize(&parts.join(" "), 160);
        if self.root_summary.is_none() {
            self.root_summary = Some(format!("<{name} {summary}>"));
        }
        self.tree.update(node, |n| n.maybe_summary(summary.clone()));
        if self.stack.len() < MAX_DEPTH {
            self.stack.push(node);
        }
    }
}

pub async fn dissect_xml(cx: Cx, input: Input) -> Result<()> {
    let doc = load(&cx, input.span).await?;
    let data = doc.data.clone();
    let root = chunk_at(&data, 0, data.len())
        .ok_or_else(|| Diagnostic::malformed("bad XML chunk").at(doc.at(0, 8)))?;
    cx.emit(struct_node(
        "Header",
        doc.at(0, root.header),
        LE,
        (),
        chunk_header,
    ));
    let chunks = children(&cx, &data, root.header, root.size).await;
    let pool = match chunks.iter().find(|c| c.kind == 0x0001) {
        Some(c) => pool_strings(&cx, &data, c).await,
        None => Vec::new(),
    };
    let ids: Vec<u32> = chunks
        .iter()
        .find(|c| c.kind == 0x0180)
        .map(|c| {
            (c.header..c.size)
                .step_by(4)
                .filter_map(|o| u32_le(&data, c.offset.saturating_add(o)))
                .collect()
        })
        .unwrap_or_default();
    let mut b = XmlBuilder {
        doc: &doc,
        pool: &pool,
        ids,
        tree: Tree::default(),
        stack: Vec::new(),
        root_summary: None,
    };
    let top = b.tree.add(None, Node::new("Elements"));
    b.stack.push(top);
    for (i, c) in chunks.iter().enumerate() {
        if i % 256 == 0 {
            cx.checkpoint().await;
        }
        match c.kind {
            0x0001 => cx.emit(pool_node(&doc, c, "String Pool")),
            0x0180 => cx.emit(
                Node::new("Resource Map")
                    .span(doc.at(c.offset, c.size))
                    .summary(format!(
                        "{} attribute IDs",
                        c.size.saturating_sub(c.header) / 4
                    )),
            ),
            0x0102 => b.element(c),
            0x0103 => {
                if b.stack.len() > 1 {
                    b.stack.pop();
                }
            }
            0x0100 => {
                let body = c.offset.saturating_add(c.header);
                let prefix = string(&pool, u32_le(&data, body).unwrap_or(0))
                    .unwrap_or("")
                    .to_owned();
                let uri = string(&pool, u32_le(&data, body.saturating_add(4)).unwrap_or(0))
                    .unwrap_or("")
                    .to_owned();
                let parent = b.stack.last().copied();
                b.tree.add(
                    parent,
                    Node::new(format!("xmlns:{prefix}"))
                        .span(doc.at(c.offset, c.size))
                        .value(text(uri)),
                );
            }
            0x0104 => {
                let body = c.offset.saturating_add(c.header);
                let t = string(&pool, u32_le(&data, body).unwrap_or(0))
                    .unwrap_or("")
                    .to_owned();
                let parent = b.stack.last().copied();
                b.tree.add(
                    parent,
                    Node::new("text")
                        .span(doc.at(c.offset, c.size))
                        .value(text(t)),
                );
            }
            _ => {}
        }
    }
    let summary = b.root_summary.take();
    cx.annotate(match summary {
        Some(s) => format!("Android binary XML: {}", ellipsize(&s, 160)),
        None => "Android binary XML".to_owned(),
    });
    let tree = Arc::new(b.tree);
    cx.emit(
        Tree::node(&tree, top).span(doc.at(root.header, root.size.saturating_sub(root.header))),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Resource table

pub async fn dissect_table(cx: Cx, input: Input) -> Result<()> {
    let doc = load(&cx, input.span).await?;
    let data = doc.data.clone();
    let root = chunk_at(&data, 0, data.len())
        .ok_or_else(|| Diagnostic::malformed("bad table chunk").at(doc.at(0, 8)))?;
    cx.emit(struct_node(
        "Header",
        doc.at(0, root.header),
        LE,
        (),
        table_header,
    ));
    let chunks = children(&cx, &data, root.header, root.size).await;
    let pool: Arc<Vec<String>> = Arc::new(match chunks.iter().find(|c| c.kind == 0x0001) {
        Some(c) => pool_strings(&cx, &data, c).await,
        None => Vec::new(),
    });
    let mut packages = Vec::new();
    for c in &chunks {
        cx.checkpoint().await;
        match c.kind {
            0x0001 => cx.emit(pool_node(&doc, c, "Global String Pool")),
            0x0200 => {
                let name_bytes = data
                    .get(c.offset.saturating_add(12)..c.offset.saturating_add(268))
                    .unwrap_or_default();
                let name = crate::text::utf16z(name_bytes, LE).0;
                let id = u32_le(&data, c.offset.saturating_add(8)).unwrap_or(0);
                packages.push(name.clone());
                cx.emit(
                    Node::new(format!("Package {name}"))
                        .span(doc.at(c.offset, c.size))
                        .summary(format!("id 0x{id:02x}"))
                        .lazy(package, (doc.clone(), *c, pool.clone())),
                );
            }
            _ => cx.emit(
                Node::new(crate::value::lookup(CHUNK_TYPE, c.kind.into()).unwrap_or("chunk"))
                    .span(doc.at(c.offset, c.size)),
            ),
        }
    }
    cx.annotate(format!(
        "Android resource table, {} strings, packages {}",
        pool.len(),
        packages.join(", ")
    ));
    Ok(())
}

fn table_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    chunk_header(f, &())?;
    f.u32("packageCount").emit()?;
    Ok(())
}

fn package_header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    chunk_header(f, &())?;
    f.u32("id").hex().emit()?;
    f.utf16("name", 128).emit()?;
    f.u32("typeStrings").hex().emit()?;
    f.u32("lastPublicType").emit()?;
    f.u32("keyStrings").hex().emit()?;
    f.u32("lastPublicKey").emit()?;
    if f.remaining() >= 4 {
        f.u32("typeIdOffset").emit()?;
    }
    Ok(())
}

#[derive(Clone)]
struct Package {
    doc: Doc,
    pool: Arc<Vec<String>>,
    types: Arc<Vec<String>>,
    keys: Arc<Vec<String>>,
}

async fn package(cx: Cx, (doc, c, pool): (Doc, Chunk, Arc<Vec<String>>)) -> Result<()> {
    let data = doc.data.clone();
    cx.emit(struct_node(
        "Header",
        doc.at(c.offset, c.header),
        LE,
        (),
        package_header,
    ));
    let type_strings = to_usize(
        u32_le(&data, c.offset.saturating_add(268))
            .unwrap_or(0)
            .into(),
    );
    let key_strings = to_usize(
        u32_le(&data, c.offset.saturating_add(276))
            .unwrap_or(0)
            .into(),
    );
    let end = c.offset.saturating_add(c.size);
    let pool_at =
        |rel: usize| chunk_at(&data, c.offset.saturating_add(rel), end).filter(|p| p.kind == 1);
    let types = match pool_at(type_strings) {
        Some(p) => pool_strings(&cx, &data, &p).await,
        None => Vec::new(),
    };
    let keys = match pool_at(key_strings) {
        Some(p) => pool_strings(&cx, &data, &p).await,
        None => Vec::new(),
    };
    let pkg = Package {
        doc: doc.clone(),
        pool,
        types: Arc::new(types),
        keys: Arc::new(keys),
    };
    for child in children(&cx, &data, c.offset.saturating_add(c.header), end).await {
        cx.checkpoint().await;
        let span = doc.at(child.offset, child.size);
        let type_name = |id: u8| {
            pkg.types
                .get(usize::from(id).saturating_sub(1))
                .cloned()
                .unwrap_or_else(|| format!("type {id}"))
        };
        let node = match child.kind {
            0x0001 => {
                let label = if child.offset == c.offset.saturating_add(type_strings) {
                    "Type Strings"
                } else {
                    "Key Strings"
                };
                pool_node(&doc, &child, label)
            }
            0x0202 => {
                let id = data
                    .get(child.offset.saturating_add(8))
                    .copied()
                    .unwrap_or(0);
                let n = u32_le(&data, child.offset.saturating_add(12)).unwrap_or(0);
                Node::new(format!("Type Spec {}", type_name(id)))
                    .span(span)
                    .summary(format!("{n} entries"))
            }
            0x0201 => {
                let id = data
                    .get(child.offset.saturating_add(8))
                    .copied()
                    .unwrap_or(0);
                let n = u32_le(&data, child.offset.saturating_add(12)).unwrap_or(0);
                let config = config_summary(&data, child.offset.saturating_add(20));
                Node::new(format!("{} ({config})", type_name(id)))
                    .span(span)
                    .summary(format!("{n} entries"))
                    .lazy(type_chunk, (pkg.clone(), child))
            }
            other => Node::new(crate::value::lookup(CHUNK_TYPE, other.into()).unwrap_or("chunk"))
                .span(span),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A short rendering of a `ResTable_config` (`default`, `fr-rCA-v21`, ...).
fn config_summary(data: &[u8], at: usize) -> String {
    let byte = |o: usize| data.get(at.saturating_add(o)).copied().unwrap_or(0);
    let half = |o: usize| u16_le(data, at.saturating_add(o)).unwrap_or(0);
    let mut parts = Vec::new();
    let language = [byte(8), byte(9)];
    if language[0] != 0 && language[0] & 0x80 == 0 {
        parts.push(String::from_utf8_lossy(&language).into_owned());
    }
    let country = [byte(10), byte(11)];
    if country[0] != 0 && country[0] & 0x80 == 0 {
        parts.push(format!("r{}", String::from_utf8_lossy(&country)));
    }
    match byte(12) {
        1 => parts.push("port".to_owned()),
        2 => parts.push("land".to_owned()),
        _ => {}
    }
    match half(14) {
        0 => {}
        120 => parts.push("ldpi".to_owned()),
        160 => parts.push("mdpi".to_owned()),
        240 => parts.push("hdpi".to_owned()),
        320 => parts.push("xhdpi".to_owned()),
        480 => parts.push("xxhdpi".to_owned()),
        640 => parts.push("xxxhdpi".to_owned()),
        0xfffe => parts.push("anydpi".to_owned()),
        0xffff => parts.push("nodpi".to_owned()),
        d => parts.push(format!("{d}dpi")),
    }
    let sdk = half(24);
    if sdk != 0 {
        parts.push(format!("v{sdk}"));
    }
    if parts.is_empty() {
        "default".to_owned()
    } else {
        parts.join("-")
    }
}

async fn type_chunk(cx: Cx, (pkg, c): (Package, Chunk)) -> Result<()> {
    let data = pkg.doc.data.clone();
    let block = crate::cx::Block {
        span: pkg.doc.at(c.offset, c.header),
        data: data
            .get(c.offset..c.offset.saturating_add(c.header))
            .unwrap_or_default()
            .to_vec(),
    };
    let mut f = Fields::emitting(&cx, &block, LE);
    chunk_header(&mut f, &())?;
    f.u8("id").emit()?;
    let flags = f.u8("flags").hex().desc("1: sparse, 2: offset16").emit()?;
    f.u16("reserved").emit()?;
    let count = f.u32("entryCount").emit()?;
    let entries_start = f.u32("entriesStart").hex().emit()?;
    let config = config_summary(&data, c.offset.saturating_add(20));
    f.node(
        Node::new("config")
            .span(
                f.peek_span(
                    u32_le(&data, c.offset.saturating_add(20))
                        .unwrap_or(0)
                        .into(),
                ),
            )
            .value(text(config)),
    );
    let offsets = c.offset.saturating_add(c.header);
    let entries = c.offset.saturating_add(to_usize(entries_start.into()));
    let sparse = flags & 1 != 0;
    let offset16 = flags & 2 != 0;
    cx.set_count(Count::AtLeast(5));
    for i in 0..to_usize(count.into()).min(c.size) {
        if i.is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let (index, offset) = if sparse {
            let at = offsets.saturating_add(i.saturating_mul(4));
            (
                usize::from(u16_le(&data, at).unwrap_or(0)),
                u32::from(u16_le(&data, at.saturating_add(2)).unwrap_or(0)).saturating_mul(4),
            )
        } else if offset16 {
            let o = u16_le(&data, offsets.saturating_add(i.saturating_mul(2))).unwrap_or(0xffff);
            if o == 0xffff {
                continue;
            }
            (i, u32::from(o).saturating_mul(4))
        } else {
            let o = u32_le(&data, offsets.saturating_add(i.saturating_mul(4))).unwrap_or(u32::MAX);
            if o == u32::MAX {
                continue;
            }
            (i, o)
        };
        let at = entries.saturating_add(to_usize(offset.into()));
        let size = usize::from(u16_le(&data, at).unwrap_or(8));
        let eflags = u16_le(&data, at.saturating_add(2)).unwrap_or(0);
        let compact = eflags & 0x8 != 0;
        let key = if compact {
            u32::from(u16_le(&data, at).unwrap_or(0))
        } else {
            u32_le(&data, at.saturating_add(4)).unwrap_or(0)
        };
        let name = pkg
            .keys
            .get(to_usize(key.into()))
            .cloned()
            .unwrap_or_else(|| format!("entry {index}"));
        let node = if compact {
            let kind = u8::try_from(eflags >> 8).unwrap_or(0);
            let value = u32_le(&data, at.saturating_add(4)).unwrap_or(0);
            Node::new(name)
                .span(pkg.doc.at(at, 8))
                .value(text(render_value(kind, value, &pkg.pool)))
        } else if eflags & 0x1 != 0 {
            let parent = u32_le(&data, at.saturating_add(8)).unwrap_or(0);
            let n = u32_le(&data, at.saturating_add(12)).unwrap_or(0);
            Node::new(name)
                .span(pkg.doc.at(
                    at,
                    size.saturating_add(to_usize(n.into()).saturating_mul(12)),
                ))
                .value(text(format!("bag of {n}")))
                .maybe_summary(if parent == 0 {
                    String::new()
                } else {
                    format!("parent @0x{parent:08x}")
                })
        } else {
            let value_at = at.saturating_add(size);
            let kind = data.get(value_at.saturating_add(3)).copied().unwrap_or(0);
            let value = u32_le(&data, value_at.saturating_add(4)).unwrap_or(0);
            Node::new(name)
                .span(pkg.doc.at(at, size.saturating_add(8)))
                .value(text(render_value(kind, value, &pkg.pool)))
                .summary(crate::value::lookup(VALUE_TYPE, kind.into()).unwrap_or("?"))
        };
        let (set, _) = crate::value::decode_flags(ENTRY_FLAGS, eflags.into());
        let node = if set.is_empty() {
            node
        } else {
            node.desc(set.join(" "))
        };
        cx.push(node).await;
    }
    Ok(())
}
