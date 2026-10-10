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
use crate::formats::util::binutil::{NodeExt, Reader, Tree};
use crate::formats::util::fmt::clip;
use crate::formats::util::val::text;
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
    pool_entries(cx, data, c)
        .await
        .into_iter()
        .map(|e| e.text)
        .collect()
}

/// A decoded pool string and where its bytes (length prefix to
/// terminator) lie in the file.
struct PoolString {
    text: String,
    at: usize,
    len: usize,
}

/// Decodes all strings of a string pool chunk, with their positions.
async fn pool_entries(cx: &Cx, data: &[u8], c: &Chunk) -> Vec<PoolString> {
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
        let (text, len) = pool_string(chunk, at, utf8).unwrap_or_default();
        out.push(PoolString { text, at, len });
    }
    out
}

/// The string at `at` and the bytes it takes, terminator included.
fn pool_string(data: &[u8], at: usize, utf8: bool) -> Option<(String, usize)> {
    let mut r = Reader::at(data, at);
    let text = if utf8 {
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
        let s = String::from_utf8_lossy(r.bytes(n)?).into_owned();
        r.u8();
        s
    } else {
        let a = r.int::<u16>(LE)?;
        let n = if a & 0x8000 != 0 {
            (usize::from(a & 0x7fff) << 16) | usize::from(r.int::<u16>(LE)?)
        } else {
            usize::from(a)
        };
        let s = crate::text::utf16(r.bytes(n.checked_mul(2)?)?, LE);
        r.int::<u16>(LE);
        s
    };
    Some((text, r.pos().saturating_sub(at)))
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
            let v = mantissa * radix * if kind == 0x06 { 100.0 } else { 1.0 };
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
    let data = &doc.data;
    cx.emit(struct_node(
        "Header",
        doc.at(c.offset, c.header),
        LE,
        (),
        pool_header,
    ));
    let word = |o: usize| to_usize(u32_le(data, c.offset.saturating_add(o)).unwrap_or(0).into());
    let (count, styles) = (word(8), word(12));
    let (strings_start, styles_start) = (word(20), word(24));
    let offsets = c.offset.saturating_add(c.header);
    if count > 0 {
        cx.emit(
            Node::new("String offsets")
                .span(doc.at(offsets, count.saturating_mul(4)))
                .summary(format!("{count} × u32, from stringsStart")),
        );
    }
    if styles > 0 {
        cx.emit(
            Node::new("Style offsets")
                .span(doc.at(
                    offsets.saturating_add(count.saturating_mul(4)),
                    styles.saturating_mul(4),
                ))
                .summary(format!("{styles} × u32, from stylesStart")),
        );
    }
    let entries = pool_entries(&cx, data, &c).await;
    let mut end = c.offset.saturating_add(strings_start);
    for (i, e) in entries.into_iter().enumerate() {
        end = end.max(e.at.saturating_add(e.len));
        cx.push(
            Node::new(format!("{i}"))
                .span(doc.at(e.at, e.len))
                .value(text(e.text)),
        )
        .await;
    }
    let chunk_end = c.offset.saturating_add(c.size);
    if styles > 0 && styles_start > 0 {
        let at = c.offset.saturating_add(styles_start);
        let span = doc.at(at, chunk_end.saturating_sub(at));
        cx.push(
            Node::new("Styles")
                .span(span)
                .summary(format!("{styles} styled strings"))
                .lazy(pool_styles, (doc.clone(), c)),
        )
        .await;
        end = end.max(chunk_end);
    }
    if end < chunk_end {
        cx.push(
            Node::new("Padding")
                .span(doc.at(end, chunk_end.saturating_sub(end)))
                .desc("Zeros that align the chunk to 4 bytes"),
        )
        .await;
    }
    Ok(())
}

/// Style runs: per styled string, `ResStringPool_span` records (tag name,
/// first and last character) ended by `0xFFFFFFFF`.
async fn pool_styles(cx: Cx, (doc, c): (Doc, Chunk)) -> Result<()> {
    let data = &doc.data;
    let base = c.offset;
    let word = |o: usize| u32_le(data, o).unwrap_or(u32::MAX);
    let count = to_usize(word(base.saturating_add(8)).into());
    let styles = to_usize(word(base.saturating_add(12)).into());
    let styles_start = base.saturating_add(to_usize(word(base.saturating_add(24)).into()));
    let offsets = base
        .saturating_add(c.header)
        .saturating_add(count.saturating_mul(4));
    let end = base.saturating_add(c.size).min(data.len());
    let pool = pool_strings(&cx, data, &c).await;
    let mut last = styles_start;
    for i in 0..styles.min(c.size) {
        let Some(off) = u32_le(data, offsets.saturating_add(i.saturating_mul(4))) else {
            break;
        };
        let start = styles_start.saturating_add(to_usize(off.into()));
        let mut at = start;
        let mut runs = Vec::new();
        while at.saturating_add(4) <= end {
            let name = word(at);
            if name == u32::MAX {
                at = at.saturating_add(4);
                break;
            }
            if at.saturating_add(12) > end {
                break;
            }
            let (first, last_char) = (word(at.saturating_add(4)), word(at.saturating_add(8)));
            runs.push(
                Node::new(format!("<{}>", string(&pool, name).unwrap_or("?")))
                    .span(doc.at(at, 12))
                    .summary(format!("characters {first}–{last_char}")),
            );
            at = at.saturating_add(12);
            if runs.len().is_multiple_of(256) {
                cx.checkpoint().await;
            }
        }
        last = last.max(at);
        let mut node = Node::new(format!("Style {i}"))
            .span(doc.at(start, at.saturating_sub(start)))
            .summary(crate::formats::util::fmt::plural(
                to_u64(runs.len()),
                "span",
            ));
        if !runs.is_empty() {
            node = node.lazy(emit_nodes, Arc::new(runs));
        }
        cx.push(node).await;
    }
    if last < end {
        cx.push(
            Node::new("End of styles")
                .span(doc.at(last, end.saturating_sub(last)))
                .desc("0xFFFFFFFF terminators after the last style"),
        )
        .await;
    }
    Ok(())
}

async fn emit_nodes(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.push(n.clone()).await;
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

type Pool = Arc<Vec<String>>;

/// A `u32` string pool reference, summarised with the string.
fn str_ref(f: &mut Fields<'_>, name: &'static str, pool: &Pool) -> Result<u32> {
    f.u32(name)
        .with(|&v, n| match string(pool, v) {
            Some(s) => n.summary(format!("\"{}\"", clip(s, 80))),
            None if v == u32::MAX => n.summary("none"),
            None => n,
        })
        .emit()
}

/// A `Res_value`: size, reserved byte, data type and data.
fn res_value(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    f.u16("size").emit()?;
    f.u8("res0").emit()?;
    let kind = f.u8("dataType").enumeration(VALUE_TYPE).emit()?;
    f.u32("data")
        .hex()
        .with(|&v, n| n.summary(render_value(kind, v, pool)))
        .emit()?;
    Ok(())
}

/// `ResXMLTree_node`: chunk header, line number and comment.
fn xml_node_header(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    chunk_header(f, &())?;
    f.u32("lineNumber").emit()?;
    str_ref(f, "comment", pool)?;
    Ok(())
}

fn xml_start(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    xml_node_header(f, pool)?;
    str_ref(f, "ns", pool)?;
    str_ref(f, "name", pool)?;
    f.u16("attributeStart").emit()?;
    f.u16("attributeSize").emit()?;
    f.u16("attributeCount").emit()?;
    f.u16("idIndex")
        .desc("1-based index of the id attribute (0: none)")
        .emit()?;
    f.u16("classIndex")
        .desc("1-based index of the class attribute (0: none)")
        .emit()?;
    f.u16("styleIndex")
        .desc("1-based index of the style attribute (0: none)")
        .emit()?;
    Ok(())
}

fn xml_attr(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    str_ref(f, "ns", pool)?;
    str_ref(f, "name", pool)?;
    str_ref(f, "rawValue", pool)?;
    res_value(f, pool)
}

fn xml_end(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    xml_node_header(f, pool)?;
    str_ref(f, "ns", pool)?;
    str_ref(f, "name", pool)?;
    Ok(())
}

fn xml_namespace(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    xml_node_header(f, pool)?;
    str_ref(f, "prefix", pool)?;
    str_ref(f, "uri", pool)?;
    Ok(())
}

fn xml_cdata(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    xml_node_header(f, pool)?;
    str_ref(f, "data", pool)?;
    res_value(f, pool)
}

struct XmlBuilder<'a> {
    doc: &'a Doc,
    pool: Pool,
    ids: Vec<u32>,
    tree: Tree,
    /// Open elements: tree index and start offset.
    stack: Vec<(usize, usize)>,
    /// Elements past `MAX_DEPTH` that were not pushed.
    overflow: usize,
    root_summary: Option<String>,
}

impl XmlBuilder<'_> {
    fn name(&self, index: u32) -> String {
        match string(&self.pool, index) {
            Some(s) if !s.is_empty() => s.to_owned(),
            _ => match self.ids.get(to_usize(index.into())) {
                Some(&id) => {
                    android_attr(id).map_or_else(|| format!("attr 0x{id:08x}"), str::to_owned)
                }
                None => format!("#{index}"),
            },
        }
    }

    fn parent(&self) -> Option<usize> {
        self.stack.last().map(|&(i, _)| i)
    }

    fn element(&mut self, c: &Chunk) {
        let data = &self.doc.data;
        let body = c.offset.saturating_add(c.header);
        let w = |o: usize| u32_le(data, body.saturating_add(o)).unwrap_or(0);
        let name = self.name(w(4));
        let attr_start = usize::from(u16_le(data, body.saturating_add(8)).unwrap_or(20));
        let attr_size = usize::from(u16_le(data, body.saturating_add(10)).unwrap_or(20)).max(20);
        let count = usize::from(u16_le(data, body.saturating_add(12)).unwrap_or(0));
        let parent = self.parent();
        let node = self.tree.add(
            parent,
            Node::new(format!("<{name}>")).span(self.doc.at(c.offset, c.size)),
        );
        self.tree.add(
            Some(node),
            struct_node(
                "Start tag",
                self.doc
                    .at(c.offset, c.header.saturating_add(attr_start).min(c.size)),
                LE,
                self.pool.clone(),
                xml_start,
            ),
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
                string(&self.pool, raw).unwrap_or("?").to_owned()
            } else {
                render_value(kind, aw(16), &self.pool)
            };
            let prefix = match string(&self.pool, ns) {
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
                struct_node(
                    label,
                    self.doc.at(at, attr_size),
                    LE,
                    self.pool.clone(),
                    xml_attr,
                )
                .value(text(value))
                .summary(kind_name),
            );
        }
        let summary = clip(&parts.join(" "), 160);
        if self.root_summary.is_none() {
            self.root_summary = Some(format!("<{name} {summary}>"));
        }
        self.tree.update(node, |n| n.maybe_summary(summary.clone()));
        if self.stack.len() < MAX_DEPTH {
            self.stack.push((node, c.offset));
        } else {
            self.overflow = self.overflow.saturating_add(1);
        }
    }

    fn end_element(&mut self, c: &Chunk) {
        if self.overflow > 0 {
            self.overflow = self.overflow.saturating_sub(1);
            return;
        }
        if self.stack.len() <= 1 {
            return;
        }
        let Some((node, start)) = self.stack.pop() else {
            return;
        };
        self.tree.add(
            Some(node),
            struct_node(
                "End tag",
                self.doc.at(c.offset, c.size),
                LE,
                self.pool.clone(),
                xml_end,
            ),
        );
        let span = self
            .doc
            .at(start, c.offset.saturating_add(c.size).saturating_sub(start));
        self.tree.update(node, |n| n.span(span));
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
    let pool: Pool = Arc::new(match chunks.iter().find(|c| c.kind == 0x0001) {
        Some(c) => pool_strings(&cx, &data, c).await,
        None => Vec::new(),
    });
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
        pool: pool.clone(),
        ids,
        tree: Tree::default(),
        stack: Vec::new(),
        overflow: 0,
        root_summary: None,
    };
    let top = b.tree.add(None, Node::new("Elements"));
    b.stack.push((top, 0));
    let mut events = None::<(usize, usize)>;
    for (i, c) in chunks.iter().enumerate() {
        if i % 256 == 0 {
            cx.checkpoint().await;
        }
        if (0x0100..=0x0104).contains(&c.kind) {
            let end = c.offset.saturating_add(c.size);
            events = Some(events.map_or((c.offset, end), |(s, _)| (s, end)));
        }
        match c.kind {
            0x0001 => cx.emit(pool_node(&doc, c, "String Pool")),
            0x0180 => cx.emit(
                Node::new("Resource Map")
                    .span(doc.at(c.offset, c.size))
                    .summary(format!(
                        "{} attribute IDs",
                        c.size.saturating_sub(c.header) / 4
                    ))
                    .lazy(resource_map, (doc.clone(), *c)),
            ),
            0x0102 => b.element(c),
            0x0103 => b.end_element(c),
            0x0100 | 0x0101 => {
                let body = c.offset.saturating_add(c.header);
                let prefix = string(&pool, u32_le(&data, body).unwrap_or(0))
                    .unwrap_or("")
                    .to_owned();
                let uri = string(&pool, u32_le(&data, body.saturating_add(4)).unwrap_or(0))
                    .unwrap_or("")
                    .to_owned();
                let label = if c.kind == 0x0100 {
                    format!("xmlns:{prefix}")
                } else {
                    format!("End of xmlns:{prefix}")
                };
                let parent = b.parent();
                b.tree.add(
                    parent,
                    struct_node(
                        label,
                        doc.at(c.offset, c.size),
                        LE,
                        pool.clone(),
                        xml_namespace,
                    )
                    .value(text(uri)),
                );
            }
            0x0104 => {
                let body = c.offset.saturating_add(c.header);
                let t = string(&pool, u32_le(&data, body).unwrap_or(0))
                    .unwrap_or("")
                    .to_owned();
                let parent = b.parent();
                b.tree.add(
                    parent,
                    struct_node(
                        "text",
                        doc.at(c.offset, c.size),
                        LE,
                        pool.clone(),
                        xml_cdata,
                    )
                    .value(text(t)),
                );
            }
            _ => {}
        }
    }
    let summary = b.root_summary.take();
    cx.annotate(match summary {
        Some(s) => format!("Android binary XML: {}", clip(&s, 160)),
        None => "Android binary XML".to_owned(),
    });
    let tree = Arc::new(b.tree);
    let (start, end) = events.unwrap_or((root.header, root.header));
    cx.emit(Tree::node(&tree, top).span(doc.at(start, end.saturating_sub(start))));
    Ok(())
}

/// The resource IDs of the attribute names, by string pool index.
async fn resource_map(cx: Cx, (doc, c): (Doc, Chunk)) -> Result<()> {
    cx.emit(struct_node(
        "Header",
        doc.at(c.offset, c.header),
        LE,
        (),
        chunk_header,
    ));
    let n = c.size.saturating_sub(c.header) / 4;
    for i in 0..n {
        let at = c
            .offset
            .saturating_add(c.header)
            .saturating_add(i.saturating_mul(4));
        let id = u32_le(&doc.data, at).unwrap_or(0);
        cx.push(
            Node::new(format!("{i}"))
                .span(doc.at(at, 4))
                .value(crate::formats::util::val::hex(id, 32))
                .maybe_summary(android_attr(id).unwrap_or_default()),
        )
        .await;
    }
    Ok(())
}

/// The name of a common framework attribute ID (`android.R.attr`).
fn android_attr(id: u32) -> Option<&'static str> {
    crate::value::lookup(ANDROID_ATTRS, id.into())
}

/// Common `android.R.attr` IDs (from the SDK's `android.jar`).
const ANDROID_ATTRS: EnumTable = &[
    (0x0101_0000, "theme"),
    (0x0101_0001, "label"),
    (0x0101_0002, "icon"),
    (0x0101_0003, "name"),
    (0x0101_0006, "permission"),
    (0x0101_0007, "readPermission"),
    (0x0101_0008, "writePermission"),
    (0x0101_0009, "protectionLevel"),
    (0x0101_000b, "sharedUserId"),
    (0x0101_000c, "hasCode"),
    (0x0101_000d, "persistent"),
    (0x0101_000e, "enabled"),
    (0x0101_000f, "debuggable"),
    (0x0101_0010, "exported"),
    (0x0101_0011, "process"),
    (0x0101_0012, "taskAffinity"),
    (0x0101_0013, "multiprocess"),
    (0x0101_0018, "authorities"),
    (0x0101_0019, "syncable"),
    (0x0101_001c, "priority"),
    (0x0101_001d, "launchMode"),
    (0x0101_001e, "screenOrientation"),
    (0x0101_001f, "configChanges"),
    (0x0101_0020, "description"),
    (0x0101_0021, "targetPackage"),
    (0x0101_0022, "handleProfiling"),
    (0x0101_0023, "functionalTest"),
    (0x0101_0024, "value"),
    (0x0101_0025, "resource"),
    (0x0101_0026, "mimeType"),
    (0x0101_0027, "scheme"),
    (0x0101_0028, "host"),
    (0x0101_0029, "port"),
    (0x0101_002a, "path"),
    (0x0101_002b, "pathPrefix"),
    (0x0101_002c, "pathPattern"),
    (0x0101_002d, "action"),
    (0x0101_002e, "data"),
    (0x0101_0054, "windowBackground"),
    (0x0101_0056, "windowNoTitle"),
    (0x0101_0095, "textSize"),
    (0x0101_0097, "textStyle"),
    (0x0101_0098, "textColor"),
    (0x0101_00af, "gravity"),
    (0x0101_00b3, "layout_gravity"),
    (0x0101_00c4, "orientation"),
    (0x0101_00d0, "id"),
    (0x0101_00d1, "tag"),
    (0x0101_00d2, "scrollX"),
    (0x0101_00d3, "scrollY"),
    (0x0101_00d4, "background"),
    (0x0101_00d5, "padding"),
    (0x0101_00d6, "paddingLeft"),
    (0x0101_00d7, "paddingTop"),
    (0x0101_00d8, "paddingRight"),
    (0x0101_00d9, "paddingBottom"),
    (0x0101_00da, "focusable"),
    (0x0101_00dc, "visibility"),
    (0x0101_00e5, "clickable"),
    (0x0101_00f4, "layout_width"),
    (0x0101_00f5, "layout_height"),
    (0x0101_00f6, "layout_margin"),
    (0x0101_00f7, "layout_marginLeft"),
    (0x0101_00f8, "layout_marginTop"),
    (0x0101_00f9, "layout_marginRight"),
    (0x0101_00fa, "layout_marginBottom"),
    (0x0101_0119, "src"),
    (0x0101_011d, "scaleType"),
    (0x0101_014f, "text"),
    (0x0101_0150, "hint"),
    (0x0101_0155, "height"),
    (0x0101_0159, "width"),
    (0x0101_0181, "layout_weight"),
    (0x0101_0199, "drawable"),
    (0x0101_019a, "shape"),
    (0x0101_01a5, "color"),
    (0x0101_0202, "targetActivity"),
    (0x0101_0204, "allowTaskReparenting"),
    (0x0101_020c, "minSdkVersion"),
    (0x0101_020d, "windowFullscreen"),
    (0x0101_021b, "versionCode"),
    (0x0101_021c, "versionName"),
    (0x0101_0270, "targetSdkVersion"),
    (0x0101_0271, "maxSdkVersion"),
    (0x0101_0273, "contentDescription"),
    (0x0101_0280, "allowBackup"),
    (0x0101_0281, "glEsVersion"),
    (0x0101_028e, "required"),
    (0x0101_02b7, "installLocation"),
    (0x0101_02be, "logo"),
    (0x0101_02cd, "windowActionBar"),
    (0x0101_02d3, "hardwareAccelerated"),
    (0x0101_031f, "alpha"),
    (0x0101_035a, "largeHeap"),
    (0x0101_03a9, "isolatedProcess"),
    (0x0101_03af, "supportsRtl"),
    (0x0101_03b3, "paddingStart"),
    (0x0101_03b4, "paddingEnd"),
    (0x0101_03b5, "layout_marginStart"),
    (0x0101_03b6, "layout_marginEnd"),
    (0x0101_03f2, "banner"),
    (0x0101_0433, "colorPrimary"),
    (0x0101_0434, "colorPrimaryDark"),
    (0x0101_0435, "colorAccent"),
    (0x0101_0451, "statusBarColor"),
    (0x0101_0452, "navigationBarColor"),
    (0x0101_04ea, "extractNativeLibs"),
    (0x0101_04eb, "fullBackupContent"),
    (0x0101_04ec, "usesCleartextTraffic"),
    (0x0101_0505, "directBootAware"),
    (0x0101_0527, "networkSecurityConfig"),
    (0x0101_052c, "roundIcon"),
    (0x0101_057a, "appComponentFactory"),
    (0x0101_0603, "requestLegacyExternalStorage"),
    (0x0101_063e, "dataExtractionRules"),
    (0x0101_065b, "localeConfig"),
];

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
                    .lazy(type_spec, (doc.clone(), child))
            }
            0x0203 => Node::new("Library")
                .span(span)
                .summary(format!(
                    "{} shared libraries",
                    u32_le(&data, child.offset.saturating_add(8)).unwrap_or(0)
                ))
                .lazy(library, (doc.clone(), child)),
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

const SPEC_FLAGS: FlagTable = &[
    flag(0x0001, "MCC"),
    flag(0x0002, "MNC"),
    flag(0x0004, "LOCALE"),
    flag(0x0008, "TOUCHSCREEN"),
    flag(0x0010, "KEYBOARD"),
    flag(0x0020, "KEYBOARD_HIDDEN"),
    flag(0x0040, "NAVIGATION"),
    flag(0x0080, "ORIENTATION"),
    flag(0x0100, "DENSITY"),
    flag(0x0200, "SCREEN_SIZE"),
    flag(0x0400, "VERSION"),
    flag(0x0800, "SCREEN_LAYOUT"),
    flag(0x1000, "UI_MODE"),
    flag(0x2000, "SMALLEST_SCREEN_SIZE"),
    flag(0x4000, "LAYOUTDIR"),
    flag(0x8000, "SCREEN_ROUND"),
    flag(0x1_0000, "COLOR_MODE"),
    flag(0x2_0000, "GRAMMATICAL_GENDER"),
    flag(0x2000_0000, "SPEC_STAGED_API"),
    flag(0x4000_0000, "SPEC_PUBLIC"),
];

/// `ResTable_typeSpec`: per entry, the configuration axes its values vary
/// over.
async fn type_spec(cx: Cx, (doc, c): (Doc, Chunk)) -> Result<()> {
    let block = chunk_block(&doc, c.offset, c.header);
    let mut f = Fields::emitting(&cx, &block, LE);
    chunk_header(&mut f, &())?;
    f.u8("id").emit()?;
    f.u8("res0").emit()?;
    f.u16("typesCount")
        .desc("Number of type chunks for this type (res1 before Android 13)")
        .emit()?;
    let count = to_usize(f.u32("entryCount").emit()?.into());
    let at = c.offset.saturating_add(c.header);
    let n = count.min(c.size.saturating_sub(c.header) / 4);
    for i in 0..n {
        let o = at.saturating_add(i.saturating_mul(4));
        let v = u32_le(&doc.data, o).unwrap_or(0);
        let (set, unknown) = crate::value::decode_flags(SPEC_FLAGS, v.into());
        cx.push(
            Node::new(format!("{i}"))
                .span(doc.at(o, 4))
                .value(crate::value::Value::Flags {
                    raw: v.into(),
                    bits: 32,
                    set,
                    unknown,
                }),
        )
        .await;
    }
    Ok(())
}

/// `ResTable_lib_header`: the shared libraries the package refers to.
async fn library(cx: Cx, (doc, c): (Doc, Chunk)) -> Result<()> {
    let block = chunk_block(&doc, c.offset, c.header);
    let mut f = Fields::emitting(&cx, &block, LE);
    chunk_header(&mut f, &())?;
    let count = to_usize(f.u32("count").emit()?.into());
    let at = c.offset.saturating_add(c.header);
    for i in 0..count.min(c.size / 260) {
        let o = at.saturating_add(i.saturating_mul(260));
        let id = u32_le(&doc.data, o).unwrap_or(0);
        let name = crate::text::utf16z(
            doc.data
                .get(o.saturating_add(4)..o.saturating_add(260))
                .unwrap_or_default(),
            LE,
        )
        .0;
        cx.push(
            struct_node(
                format!("Library {name}"),
                doc.at(o, 260),
                LE,
                (),
                library_entry,
            )
            .summary(format!("package id 0x{id:02x}")),
        )
        .await;
    }
    Ok(())
}

fn library_entry(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u32("packageId").hex().emit()?;
    f.utf16("packageName", 128).emit()?;
    Ok(())
}

/// A block over `len` bytes of the loaded document at `offset`.
fn chunk_block(doc: &Doc, offset: usize, len: usize) -> crate::cx::Block {
    crate::cx::Block {
        span: doc.at(offset, len),
        data: doc
            .data
            .get(offset..offset.saturating_add(len).min(doc.data.len()))
            .unwrap_or_default()
            .to_vec(),
    }
}

/// `ResTable_config`, as far as its `size` reaches.
fn config_fields(f: &mut Fields<'_>, _: &()) -> Result<()> {
    let size = u64::from(f.u32("size").emit()?);
    let left = |f: &Fields<'_>| size.saturating_sub(f.pos());
    macro_rules! field {
        ($n:literal, u8) => {
            if left(f) >= 1 {
                f.u8($n).emit()?;
            }
        };
        ($n:literal, u16) => {
            if left(f) >= 2 {
                f.u16($n).emit()?;
            }
        };
        ($n:literal, ascii $len:literal) => {
            if left(f) >= $len {
                f.ascii($n, $len).emit()?;
            }
        };
    }
    field!("mcc", u16);
    field!("mnc", u16);
    field!("language", ascii 2);
    field!("country", ascii 2);
    field!("orientation", u8);
    field!("touchscreen", u8);
    field!("density", u16);
    field!("keyboard", u8);
    field!("navigation", u8);
    field!("inputFlags", u8);
    field!("inputPad0", u8);
    field!("screenWidth", u16);
    field!("screenHeight", u16);
    field!("sdkVersion", u16);
    field!("minorVersion", u16);
    field!("screenLayout", u8);
    field!("uiMode", u8);
    field!("smallestScreenWidthDp", u16);
    field!("screenWidthDp", u16);
    field!("screenHeightDp", u16);
    field!("localeScript", ascii 4);
    field!("localeVariant", ascii 8);
    field!("screenLayout2", u8);
    field!("colorMode", u8);
    field!("grammaticalInflection", u8);
    field!("screenConfigPad2", u8);
    field!("localeScriptWasComputed", u8);
    field!("localeNumberingSystem", ascii 8);
    let rest = left(f);
    if rest > 0 {
        f.bytes("padding", rest).emit()?;
    }
    Ok(())
}

/// Special `ResTable_map` names (attribute metadata and plural quantities).
const MAP_NAMES: EnumTable = &[
    (0x0100_0000, "^type"),
    (0x0100_0001, "^min"),
    (0x0100_0002, "^max"),
    (0x0100_0003, "^l10n"),
    (0x0100_0004, "^other"),
    (0x0100_0005, "^zero"),
    (0x0100_0006, "^one"),
    (0x0100_0007, "^two"),
    (0x0100_0008, "^few"),
    (0x0100_0009, "^many"),
];

fn map_name(id: u32) -> String {
    if let Some(n) = crate::value::lookup(MAP_NAMES, id.into()) {
        return n.to_owned();
    }
    if let Some(n) = android_attr(id) {
        return format!("android:{n}");
    }
    if id >> 24 == 0x02 {
        // Res_MAKEARRAY: an array item's index.
        return format!("[{}]", id & 0xffff);
    }
    format!("@0x{id:08x}")
}

#[derive(Clone)]
struct EntryCtx {
    pool: Pool,
    keys: Pool,
    /// Items of an `array` bag are shown by position.
    array: bool,
}

fn key_ref(f: &mut Fields<'_>, name: &'static str, keys: &Pool, wide: bool) -> Result<()> {
    let field = if wide {
        f.u32(name)
    } else {
        f.u16(name).map(u32::from)
    };
    field
        .with(|&v, n| match string(keys, v) {
            Some(s) => n.summary(format!("\"{}\"", clip(s, 80))),
            None => n,
        })
        .emit()?;
    Ok(())
}

/// One `ResTable_entry` and its value (or, for a bag, its map).
fn entry_fields(f: &mut Fields<'_>, ctx: &EntryCtx) -> Result<()> {
    let first = u16_le(&f.block().data, 2).unwrap_or(0);
    if first & 0x8 != 0 {
        key_ref(f, "key", &ctx.keys, false)?;
        f.u16("flags")
            .hex()
            .with(|&v, n| {
                n.summary(format!(
                    "COMPACT, dataType {}",
                    crate::value::lookup(VALUE_TYPE, (v >> 8).into()).unwrap_or("?")
                ))
            })
            .emit()?;
        let kind = u8::try_from(first >> 8).unwrap_or(0);
        f.u32("data")
            .hex()
            .with(|&v, n| n.summary(render_value(kind, v, &ctx.pool)))
            .emit()?;
        return Ok(());
    }
    let size = u64::from(f.u16("size").emit()?);
    let flags = f.u16("flags").flags(ENTRY_FLAGS).emit()?;
    key_ref(f, "key", &ctx.keys, true)?;
    if flags & 0x1 == 0 {
        f.seek(size);
        return res_value(f, &ctx.pool);
    }
    f.u32("parent")
        .hex()
        .with(|&v, n| {
            if v == 0 {
                n.summary("none")
            } else {
                n.summary(format!("@0x{v:08x}"))
            }
        })
        .emit()?;
    let count = f.u32("count").emit()?;
    f.seek(size);
    let mut index = 0u32;
    for _ in 0..count {
        if f.remaining() < 12 {
            break;
        }
        let data = &f.block().data;
        let at = to_usize(f.pos());
        let name = u32_le(data, at).unwrap_or(0);
        let kind = data.get(at.saturating_add(7)).copied().unwrap_or(0);
        let value = u32_le(data, at.saturating_add(8)).unwrap_or(0);
        let span = f.peek_span(12);
        f.skip(12);
        let label = if ctx.array {
            format!("[{index}]")
        } else {
            map_name(name)
        };
        index = index.saturating_add(1);
        f.node(
            struct_node(label, span, LE, ctx.pool.clone(), map_item)
                .value(text(if name == 0x0100_0000 {
                    attr_types(value)
                } else {
                    render_value(kind, value, &ctx.pool)
                }))
                .summary(crate::value::lookup(VALUE_TYPE, kind.into()).unwrap_or("?")),
        );
    }
    Ok(())
}

/// The formats an attribute accepts (`ResTable_map::ATTR_TYPE` value).
const ATTR_TYPES: FlagTable = &[
    flag(0x01, "reference"),
    flag(0x02, "string"),
    flag(0x04, "integer"),
    flag(0x08, "boolean"),
    flag(0x10, "color"),
    flag(0x20, "float"),
    flag(0x40, "dimension"),
    flag(0x80, "fraction"),
    flag(0x1_0000, "enum"),
    flag(0x2_0000, "flags"),
];

fn attr_types(v: u32) -> String {
    if v & 0xffff == 0xffff {
        return "any".to_owned();
    }
    let (set, unknown) = crate::value::decode_flags(ATTR_TYPES, v.into());
    let mut s = set.join("|");
    if unknown != 0 {
        s = format!("{s}|{unknown:#x}");
    }
    s
}

fn map_item(f: &mut Fields<'_>, pool: &Pool) -> Result<()> {
    f.u32("name")
        .hex()
        .with(|&v, n| n.summary(map_name(v)))
        .emit()?;
    res_value(f, pool)
}

async fn type_chunk(cx: Cx, (pkg, c): (Package, Chunk)) -> Result<()> {
    let data = pkg.doc.data.clone();
    let block = chunk_block(&pkg.doc, c.offset, c.header);
    let mut f = Fields::emitting(&cx, &block, LE);
    chunk_header(&mut f, &())?;
    f.u8("id").emit()?;
    let flags = f.u8("flags").flags(TYPE_FLAGS).emit()?;
    f.u16("reserved").emit()?;
    let count = f.u32("entryCount").emit()?;
    let entries_start = f.u32("entriesStart").hex().emit()?;
    let config = config_summary(&data, c.offset.saturating_add(20));
    let config_len = u32_le(&data, c.offset.saturating_add(20))
        .unwrap_or(0)
        .into();
    f.node(
        struct_node("config", f.peek_span(config_len), LE, (), config_fields).value(text(config)),
    );
    let offsets = c.offset.saturating_add(c.header);
    let entries = c.offset.saturating_add(to_usize(entries_start.into()));
    let sparse = flags & 1 != 0;
    let offset16 = flags & 2 != 0;
    if entries > offsets {
        let kind = if sparse {
            "sparse (u16 index, u16 offset / 4)"
        } else if offset16 {
            "u16 offset / 4"
        } else {
            "u32"
        };
        cx.emit(
            Node::new("Entry offsets")
                .span(pkg.doc.at(offsets, entries.saturating_sub(offsets)))
                .summary(format!("{count} × {kind}")),
        );
    }
    let ctx = EntryCtx {
        pool: pkg.pool.clone(),
        keys: pkg.keys.clone(),
        array: c
            .offset
            .checked_add(8)
            .and_then(|o| data.get(o))
            .and_then(|&id| pkg.types.get(usize::from(id).checked_sub(1)?))
            .is_some_and(|t| t == "array"),
    };
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
            struct_node(name, pkg.doc.at(at, 8), LE, ctx.clone(), entry_fields)
                .value(text(render_value(kind, value, &pkg.pool)))
        } else if eflags & 0x1 != 0 {
            let parent = u32_le(&data, at.saturating_add(8)).unwrap_or(0);
            let n = u32_le(&data, at.saturating_add(12)).unwrap_or(0);
            let len = size.saturating_add(to_usize(n.into()).saturating_mul(12));
            struct_node(name, pkg.doc.at(at, len), LE, ctx.clone(), entry_fields)
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
            struct_node(
                name,
                pkg.doc.at(at, size.saturating_add(8)),
                LE,
                ctx.clone(),
                entry_fields,
            )
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

const TYPE_FLAGS: FlagTable = &[flag(0x1, "SPARSE"), flag(0x2, "OFFSET16")];
