//! WebAssembly binary modules (`\0asm`).
//!
//! The file is a header and a sequence of sections (id, LEB128 size,
//! contents). The top level lists sections; expanding one decodes its
//! vector of entries (types, imports, exports, function bodies, data
//! segments, ...). Function names come from the custom `name` section,
//! which is read when the code section is expanded.

mod ops;

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::binutil::{NodeExt, Reader, dec, ellipsize, hex, name_or, text};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
/// Largest section decoded in memory.
const MAX_SECTION: u64 = 16 << 20;

pub static FORMAT: Format = Format {
    name: "wasm",
    title: "WebAssembly binary module",
    extensions: &["wasm"],
    mime: "application/wasm",
    probe: Probe::Magic(&[(0, b"\0asm\x01\0\0\0"), (0, b"\0asm\x0d\0\x01\0")]),
    dissect: crate::expander!(dissect: Input),
};

const SECTION: EnumTable = &[
    (0, "Custom"),
    (1, "Type"),
    (2, "Import"),
    (3, "Function"),
    (4, "Table"),
    (5, "Memory"),
    (6, "Global"),
    (7, "Export"),
    (8, "Start"),
    (9, "Element"),
    (10, "Code"),
    (11, "Data"),
    (12, "DataCount"),
    (13, "Tag"),
];

const EXTERNAL_KIND: EnumTable = &[
    (0, "func"),
    (1, "table"),
    (2, "memory"),
    (3, "global"),
    (4, "tag"),
];

const NAME_SUBSECTION: EnumTable = &[
    (0, "Module name"),
    (1, "Function names"),
    (2, "Local names"),
    (3, "Label names"),
    (4, "Type names"),
    (5, "Table names"),
    (6, "Memory names"),
    (7, "Global names"),
    (8, "Element segment names"),
    (9, "Data segment names"),
    (10, "Field names"),
    (11, "Tag names"),
];

#[derive(Clone, Copy, Debug)]
struct Section {
    id: u8,
    /// The whole section including its header.
    span: Span,
    /// The contents.
    body: Span,
}

type Module = Arc<ModuleInfo>;

struct ModuleInfo {
    sections: Vec<Section>,
    /// Name of each custom section, by section index.
    custom_names: Vec<(usize, String)>,
}

impl ModuleInfo {
    fn find(&self, id: u8) -> Option<&Section> {
        self.sections.iter().find(|s| s.id == id)
    }

    fn custom(&self, name: &str) -> Option<&Section> {
        self.custom_names
            .iter()
            .find(|(_, n)| n == name)
            .and_then(|(i, _)| self.sections.get(*i))
    }
}

// ---------------------------------------------------------------------------
// Value types and small decoders

fn heap_type(r: &mut Reader<'_>) -> Option<String> {
    let v = r.sleb()?;
    Some(match v {
        -0x10 => "func".to_owned(),
        -0x11 => "extern".to_owned(),
        -0x12 => "any".to_owned(),
        -0x13 => "eq".to_owned(),
        -0x14 => "i31".to_owned(),
        -0x15 => "struct".to_owned(),
        -0x16 => "array".to_owned(),
        -0x0d => "nofunc".to_owned(),
        -0x0e => "noextern".to_owned(),
        -0x0f => "none".to_owned(),
        -0x17 => "exn".to_owned(),
        n if n >= 0 => format!("type {n}"),
        n => format!("heap type {n}"),
    })
}

fn val_type(r: &mut Reader<'_>) -> Option<String> {
    Some(match r.u8()? {
        0x7f => "i32".to_owned(),
        0x7e => "i64".to_owned(),
        0x7d => "f32".to_owned(),
        0x7c => "f64".to_owned(),
        0x7b => "v128".to_owned(),
        0x70 => "funcref".to_owned(),
        0x6f => "externref".to_owned(),
        0x6e => "anyref".to_owned(),
        0x6d => "eqref".to_owned(),
        0x6c => "i31ref".to_owned(),
        0x6b => "structref".to_owned(),
        0x6a => "arrayref".to_owned(),
        0x69 => "exnref".to_owned(),
        0x64 => format!("(ref {})", heap_type(r)?),
        0x63 => format!("(ref null {})", heap_type(r)?),
        other => format!("type {other:#04x}"),
    })
}

fn name(r: &mut Reader<'_>) -> Option<String> {
    let len = r.uleb()?;
    let bytes = r.bytes(usize::try_from(len).ok()?)?;
    Some(String::from_utf8_lossy(bytes).into_owned())
}

fn limits(r: &mut Reader<'_>) -> Option<String> {
    let flags = r.u8()?;
    let min = r.uleb()?;
    let max = if flags & 1 != 0 {
        Some(r.uleb()?)
    } else {
        None
    };
    let mut s = match max {
        Some(max) => format!("{min}..{max}"),
        None => format!("{min}.."),
    };
    if flags & 2 != 0 {
        s.push_str(" shared");
    }
    if flags & 4 != 0 {
        s.push_str(" i64");
    }
    Some(s)
}

fn table_type(r: &mut Reader<'_>) -> Option<String> {
    let t = val_type(r)?;
    Some(format!("{t} {}", limits(r)?))
}

fn global_type(r: &mut Reader<'_>) -> Option<String> {
    let t = val_type(r)?;
    let mutable = r.u8()?;
    Some(if mutable & 1 != 0 {
        format!("mut {t}")
    } else {
        t
    })
}

/// A constant expression (up to and including `end`), rendered.
fn const_expr(r: &mut Reader<'_>) -> Option<String> {
    let mut parts = Vec::new();
    for _ in 0..64 {
        let op = r.u8()?;
        let s = match op {
            0x0b => break,
            0x41 => format!("i32.const {}", r.sleb()?),
            0x42 => format!("i64.const {}", r.sleb()?),
            0x43 => format!(
                "f32.const {}",
                f32::from_le_bytes(r.bytes(4)?.try_into().ok()?)
            ),
            0x44 => format!(
                "f64.const {}",
                f64::from_le_bytes(r.bytes(8)?.try_into().ok()?)
            ),
            0x23 => format!("global.get {}", r.uleb()?),
            0xd0 => format!("ref.null {}", heap_type(r)?),
            0xd2 => format!("ref.func {}", r.uleb()?),
            0x6a => "i32.add".to_owned(),
            0x6b => "i32.sub".to_owned(),
            0x6c => "i32.mul".to_owned(),
            0x7c => "i64.add".to_owned(),
            0x7d => "i64.sub".to_owned(),
            0x7e => "i64.mul".to_owned(),
            _ => return None,
        };
        parts.push(s);
    }
    Some(parts.join(" "))
}

// ---------------------------------------------------------------------------
// Entry point

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::new(&head, LE);
    f.bytes("magic", 4).get()?;
    let version = f.u16("version").get()?;
    let layer = f.u16("layer").get()?;
    cx.emit(crate::fields::struct_node(
        "Header",
        file.sub(0, 8),
        LE,
        (),
        header,
    ));

    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let mut sections = Vec::new();
    let mut custom_names = Vec::new();
    while !cur.at_end() {
        let start = cur.pos();
        let id = cur.u8().await?;
        let size = cur.uleb128().await?;
        let body = file.sub(cur.pos(), size);
        if body.len < size {
            cx.diag(Diagnostic::truncated(
                Span::new(body.source, body.offset, size),
                body.len,
            ));
        }
        cur.skip(size);
        let span = cur.since(start);
        if id == 0 {
            let data = cx.read_avail(body.sub(0, 0x110)).await?;
            let mut r = Reader::new(&data);
            if let Some(n) = name(&mut r) {
                custom_names.push((sections.len(), n));
            }
        }
        sections.push(Section { id, span, body });
    }
    let m: Module = Arc::new(ModuleInfo {
        sections,
        custom_names,
    });

    let summary = if layer == 1 {
        format!("WebAssembly component (version {version:#x})")
    } else {
        module_summary(&cx, &m).await
    };
    cx.annotate(summary);
    cx.set_count(Count::Exact(to_u64(m.sections.len()).saturating_add(1)));
    for (index, s) in m.sections.iter().enumerate() {
        let label = match m.custom_names.iter().find(|(i, _)| *i == index) {
            Some((_, n)) => format!("Custom \"{n}\""),
            None => name_or(SECTION, s.id.into(), "Section"),
        };
        let count = if matches!(s.id, 0 | 8 | 12) {
            None
        } else {
            let data = cx.read_avail(s.body.sub(0, 10)).await?;
            Reader::new(&data).uleb()
        };
        let mut summary = format!("{:#x} bytes", s.body.len);
        if let Some(n) = count {
            summary = format!("{n} entries, {summary}");
        }
        cx.push(
            Node::new(label)
                .span(s.span)
                .summary(summary)
                .lazy(section, (m.clone(), index)),
        )
        .await;
    }
    Ok(())
}

fn header(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.bytes("magic", 4).desc("\"\\0asm\"").emit()?;
    f.u16("version").emit()?;
    f.u16("layer").desc("0: core module, 1: component").emit()?;
    Ok(())
}

async fn module_summary(cx: &Cx, m: &ModuleInfo) -> String {
    let mut parts = vec!["WebAssembly module".to_owned()];
    let count = |id: u8| async move {
        let s = m.find(id)?;
        let data = cx.read_avail(s.body.sub(0, 10)).await.ok()?;
        Reader::new(&data).uleb()
    };
    let imported = match m.find(2) {
        Some(s) => imports_by_kind(cx, s.body).await.unwrap_or_default(),
        None => [0; 5],
    };
    if let Some(n) = count(3).await {
        let mut s = format!("{n} functions");
        if imported[0] > 0 {
            s.push_str(&format!(" + {} imported", imported[0]));
        }
        parts.push(s);
    }
    if let Some(s) = m.find(7)
        && let Ok(data) = cx.read_avail(s.body.sub(0, 0x1000)).await
    {
        let mut r = Reader::new(&data);
        let n = r.uleb().unwrap_or(0);
        let mut names = Vec::new();
        for _ in 0..n.min(16) {
            let Some(export) = name(&mut r) else { break };
            if r.u8().is_none() || r.uleb().is_none() {
                break;
            }
            names.push(export);
        }
        parts.push(format!(
            "{n} exports ({})",
            ellipsize(&names.join(", "), 80)
        ));
    }
    parts.join(", ")
}

/// How many functions, tables, memories, globals and tags are imported.
async fn imports_by_kind(cx: &Cx, body: Span) -> Result<[u64; 5]> {
    let data = cx.read(body.sub(0, MAX_SECTION)).await?;
    let mut r = Reader::new(&data);
    let mut out = [0u64; 5];
    let n = r.uleb().unwrap_or(0);
    for _ in 0..n {
        cx.checkpoint().await;
        if name(&mut r).is_none() || name(&mut r).is_none() {
            break;
        }
        let Some(kind) = r.u8() else { break };
        let ok = match kind {
            0 => r.uleb().is_some(),
            1 => table_type(&mut r).is_some(),
            2 => limits(&mut r).is_some(),
            3 => global_type(&mut r).is_some(),
            4 => r.u8().is_some() && r.uleb().is_some(),
            _ => false,
        };
        if !ok {
            break;
        }
        if let Some(slot) = out.get_mut(usize::from(kind)) {
            *slot = slot.saturating_add(1);
        }
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// Sections

/// Decoding context for one section: its bytes and where they are.
struct Body<'a> {
    r: Reader<'a>,
    span: Span,
}

impl Body<'_> {
    fn at(&self, start: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(self.r.pos().saturating_sub(start)))
    }

    fn malformed(&self, what: &str) -> Diagnostic {
        Diagnostic::malformed(format!("truncated or malformed {what}"))
            .at(self.span.sub(to_u64(self.r.pos()), 1))
    }
}

async fn section(cx: Cx, (m, index): (Module, usize)) -> Result<()> {
    let s = *m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let header = cx
        .block(s.span.sub(0, s.span.len.saturating_sub(s.body.len)))
        .await?;
    let mut f = Fields::emitting(&cx, &header, LE);
    f.u8("id").enumeration(SECTION).emit()?;
    let size_len = header.span.len.saturating_sub(1);
    f.bytes("size", size_len)
        .with(|_, n| n.value(dec(s.body.len, 32)).desc("LEB128"))
        .emit()?;
    if s.body.len > MAX_SECTION {
        return Err(Diagnostic::limit("section too large to decode").at(s.body));
    }
    let data = cx.read(s.body).await?;
    let mut b = Body {
        r: Reader::new(&data),
        span: s.body,
    };
    match s.id {
        0 => custom(&cx, &mut b).await,
        1 => types(&cx, &mut b).await,
        2 => imports(&cx, &mut b).await,
        3 => {
            let imported = match m.find(2) {
                Some(s) => imports_by_kind(&cx, s.body).await.unwrap_or_default()[0],
                None => 0,
            };
            vector(&cx, &mut b, "function", |b, i| {
                let t = b.r.uleb()?;
                Some((
                    format!("func {}", imported.saturating_add(i)),
                    text(format!("type {t}")),
                    String::new(),
                ))
            })
            .await
        }
        4 => {
            vector(&cx, &mut b, "table", |b, i| {
                Some((
                    format!("table {i}"),
                    text(table_type(&mut b.r)?),
                    String::new(),
                ))
            })
            .await
        }
        5 => {
            vector(&cx, &mut b, "memory", |b, i| {
                let l = limits(&mut b.r)?;
                Some((format!("memory {i}"), text(l), "pages of 64 KiB".to_owned()))
            })
            .await
        }
        6 => {
            vector(&cx, &mut b, "global", |b, i| {
                let t = global_type(&mut b.r)?;
                let init = const_expr(&mut b.r)?;
                Some((format!("global {i}"), text(t), init))
            })
            .await
        }
        7 => {
            vector(&cx, &mut b, "export", |b, _| {
                let n = name(&mut b.r)?;
                let kind = b.r.u8()?;
                let index = b.r.uleb()?;
                Some((
                    n,
                    text(format!(
                        "{} {index}",
                        name_or(EXTERNAL_KIND, kind.into(), "kind")
                    )),
                    String::new(),
                ))
            })
            .await
        }
        8 => {
            let start = b.r.pos();
            let f = b.r.uleb().ok_or_else(|| b.malformed("start"))?;
            cx.emit(
                Node::new("start function")
                    .span(b.at(start))
                    .value(dec(f, 32)),
            );
            Ok(())
        }
        9 => vector(&cx, &mut b, "element segment", element).await,
        10 => code(&cx, &m, &mut b).await,
        11 => {
            vector(&cx, &mut b, "data segment", |b, i| {
                let flags = b.r.uleb()?;
                let mode = match flags {
                    0 => format!("active, offset {}", const_expr(&mut b.r)?),
                    1 => "passive".to_owned(),
                    2 => {
                        let mem = b.r.uleb()?;
                        format!("active in memory {mem}, offset {}", const_expr(&mut b.r)?)
                    }
                    _ => return None,
                };
                let len = b.r.uleb()?;
                let bytes = b.r.bytes(usize::try_from(len).ok()?)?;
                let preview = bytes.get(..32).unwrap_or(bytes).to_vec();
                Some((
                    format!("segment {i}"),
                    Value::Bytes(preview),
                    format!("{mode}, {len} bytes"),
                ))
            })
            .await
        }
        12 => {
            let start = b.r.pos();
            let n = b.r.uleb().ok_or_else(|| b.malformed("data count"))?;
            cx.emit(
                Node::new("data segments")
                    .span(b.at(start))
                    .value(dec(n, 32)),
            );
            Ok(())
        }
        13 => {
            vector(&cx, &mut b, "tag", |b, i| {
                b.r.u8()?;
                let t = b.r.uleb()?;
                Some((format!("tag {i}"), text(format!("type {t}")), String::new()))
            })
            .await
        }
        _ => {
            cx.emit(
                Node::new("Contents")
                    .span(s.body)
                    .diag(Diagnostic::unsupported(format!("section id {}", s.id))),
            );
            Ok(())
        }
    }
}

/// Decodes a vector: a LEB128 count, then `count` entries. Each entry
/// becomes a node `(name, value, summary)` spanning its bytes.
async fn vector(
    cx: &Cx,
    b: &mut Body<'_>,
    what: &str,
    mut entry: impl FnMut(&mut Body<'_>, u64) -> Option<(String, Value, String)>,
) -> Result<()> {
    let n =
        b.r.uleb()
            .ok_or_else(|| b.malformed(&format!("{what} count")))?;
    for i in 0..n {
        let start = b.r.pos();
        let Some((label, value, summary)) = entry(b, i) else {
            return Err(b.malformed(what));
        };
        cx.push(
            Node::new(label)
                .span(b.at(start))
                .value(value)
                .maybe_summary(summary),
        )
        .await;
    }
    if !b.r.at_end() {
        cx.diag(Diagnostic::warning("data after the last entry"));
    }
    Ok(())
}

fn function_type(r: &mut Reader<'_>) -> Option<String> {
    let list = |r: &mut Reader<'_>| -> Option<Vec<String>> {
        let n = r.uleb()?;
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(val_type(r)?);
        }
        Some(out)
    };
    let params = list(r)?;
    let results = list(r)?;
    Some(format!(
        "({}) -> ({})",
        params.join(", "),
        results.join(", ")
    ))
}

fn composite_type(r: &mut Reader<'_>) -> Option<String> {
    match r.u8()? {
        0x60 => function_type(r),
        0x5f => {
            let n = r.uleb()?;
            let mut fields = Vec::new();
            for _ in 0..n {
                let t = storage_type(r)?;
                let m = r.u8()?;
                fields.push(if m & 1 != 0 { format!("mut {t}") } else { t });
            }
            Some(format!("struct {{{}}}", fields.join(", ")))
        }
        0x5e => {
            let t = storage_type(r)?;
            let m = r.u8()?;
            Some(format!("array {}{t}", if m & 1 != 0 { "mut " } else { "" }))
        }
        _ => None,
    }
}

fn storage_type(r: &mut Reader<'_>) -> Option<String> {
    match r.peek()? {
        0x78 => {
            r.u8();
            Some("i8".to_owned())
        }
        0x77 => {
            r.u8();
            Some("i16".to_owned())
        }
        _ => val_type(r),
    }
}

/// One entry of the type section: a function type, or (GC proposal) a
/// subtype or recursion group.
fn sub_type(r: &mut Reader<'_>) -> Option<String> {
    match r.peek()? {
        0x50 | 0x4f => {
            let final_ = r.u8()? == 0x4f;
            let n = r.uleb()?;
            let mut supers = Vec::new();
            for _ in 0..n {
                supers.push(r.uleb()?.to_string());
            }
            let body = composite_type(r)?;
            Some(format!(
                "sub{} [{}] {body}",
                if final_ { " final" } else { "" },
                supers.join(", ")
            ))
        }
        _ => composite_type(r),
    }
}

async fn types(cx: &Cx, b: &mut Body<'_>) -> Result<()> {
    let mut index = 0u64;
    vector(cx, b, "type", |b, _| {
        let start_index = index;
        let s = if b.r.peek()? == 0x4e {
            b.r.u8()?;
            let n = b.r.uleb()?;
            let mut members = Vec::new();
            for _ in 0..n {
                members.push(sub_type(&mut b.r)?);
            }
            index = index.saturating_add(n);
            format!("rec {{{}}}", members.join("; "))
        } else {
            index = index.saturating_add(1);
            sub_type(&mut b.r)?
        };
        Some((format!("type {start_index}"), text(s), String::new()))
    })
    .await
}

async fn imports(cx: &Cx, b: &mut Body<'_>) -> Result<()> {
    let mut counters = [0u64; 5];
    vector(cx, b, "import", |b, _| {
        let module = name(&mut b.r)?;
        let field = name(&mut b.r)?;
        let kind = b.r.u8()?;
        let desc = match kind {
            0 => format!("type {}", b.r.uleb()?),
            1 => table_type(&mut b.r)?,
            2 => limits(&mut b.r)?,
            3 => global_type(&mut b.r)?,
            4 => {
                b.r.u8()?;
                format!("type {}", b.r.uleb()?)
            }
            _ => return None,
        };
        let slot = counters.get_mut(usize::from(kind))?;
        let index = *slot;
        *slot = slot.saturating_add(1);
        Some((
            format!("{module}.{field}"),
            text(format!(
                "{} {index}",
                name_or(EXTERNAL_KIND, kind.into(), "kind")
            )),
            desc,
        ))
    })
    .await
}

fn element(b: &mut Body<'_>, i: u64) -> Option<(String, Value, String)> {
    let flags = b.r.uleb()?;
    let passive_or_declarative = flags & 1 != 0;
    let explicit_table = flags & 2 != 0;
    let expressions = flags & 4 != 0;
    let mut mode = if !passive_or_declarative {
        let table = if explicit_table { b.r.uleb()? } else { 0 };
        format!("active in table {table}, offset {}", const_expr(&mut b.r)?)
    } else if explicit_table {
        "declarative".to_owned()
    } else {
        "passive".to_owned()
    };
    if passive_or_declarative || explicit_table {
        if expressions {
            mode.push_str(&format!(", {}", val_type(&mut b.r)?));
        } else {
            b.r.u8()?; // elemkind: funcref
        }
    }
    let n = b.r.uleb()?;
    let mut items = Vec::new();
    for _ in 0..n {
        items.push(if expressions {
            const_expr(&mut b.r)?
        } else {
            format!("func {}", b.r.uleb()?)
        });
    }
    Some((
        format!("segment {i}"),
        text(ellipsize(&items.join(", "), 120)),
        format!("{mode}, {n} items"),
    ))
}

// ---------------------------------------------------------------------------
// Code

async fn function_names(cx: &Cx, m: &ModuleInfo) -> Vec<(u64, String)> {
    let Some(s) = m.custom("name") else {
        return Vec::new();
    };
    let Ok(data) = cx.read(s.body.sub(0, MAX_SECTION)).await else {
        return Vec::new();
    };
    let mut r = Reader::new(&data);
    let _ = name(&mut r);
    while !r.at_end() {
        let Some(id) = r.u8() else { break };
        let Some(size) = r.uleb() else { break };
        let Some(sub) = r.bytes(usize::try_from(size).unwrap_or(usize::MAX)) else {
            break;
        };
        if id == 1 {
            let mut s = Reader::new(sub);
            let n = s.uleb().unwrap_or(0);
            let mut out = Vec::new();
            for _ in 0..n {
                let (Some(index), Some(n)) = (s.uleb(), name(&mut s)) else {
                    break;
                };
                out.push((index, n));
            }
            return out;
        }
    }
    Vec::new()
}

async fn code(cx: &Cx, m: &ModuleInfo, b: &mut Body<'_>) -> Result<()> {
    let imported = match m.find(2) {
        Some(s) => imports_by_kind(cx, s.body).await.unwrap_or_default()[0],
        None => 0,
    };
    let names = Arc::new(function_names(cx, m).await);
    let n = b.r.uleb().ok_or_else(|| b.malformed("function count"))?;
    cx.set_count(Count::Exact(n));
    for i in 0..n {
        let start = b.r.pos();
        let size =
            b.r.uleb()
                .ok_or_else(|| b.malformed("function body size"))?;
        let body_start = b.r.pos();
        let Some(body) = b.r.bytes(usize::try_from(size).unwrap_or(usize::MAX)) else {
            return Err(b.malformed("function body"));
        };
        let index = imported.saturating_add(i);
        let label = names
            .iter()
            .find(|(n, _)| *n == index)
            .map_or_else(|| format!("func {index}"), |(_, s)| s.clone());
        // Locals: groups of (count, type).
        let mut r = Reader::new(body);
        let mut locals = Vec::new();
        let groups = r.uleb().unwrap_or(0);
        for _ in 0..groups.min(4096) {
            let (Some(count), Some(t)) = (r.uleb(), val_type(&mut r)) else {
                break;
            };
            locals.push(format!("{count} × {t}"));
        }
        let code_len = to_u64(body.len().saturating_sub(r.pos()));
        let mut summary = format!("{code_len} bytes of code");
        if !locals.is_empty() {
            summary.push_str(&format!(", locals {}", locals.join(", ")));
        }
        let span = b.at(start);
        let body_span = b.span.sub(to_u64(body_start), size);
        let locals_span = body_span.sub(0, to_u64(r.pos()));
        let code_span = body_span.tail(to_u64(r.pos()));
        cx.push(
            Node::new(label)
                .span(span)
                .value(hex(index, 32))
                .summary(summary)
                .lazy(
                    function_body,
                    (locals_span, code_span, locals, names.clone()),
                ),
        )
        .await;
    }
    Ok(())
}

type Names = Arc<Vec<(u64, String)>>;

async fn function_body(
    cx: Cx,
    (locals_span, code_span, locals, names): (Span, Span, Vec<String>, Names),
) -> Result<()> {
    cx.emit(
        Node::new("Locals")
            .span(locals_span)
            .maybe_summary(locals.join(", ")),
    );
    cx.emit(
        Node::new("Instructions")
            .span(code_span)
            .summary(format!("{} bytes", code_span.len))
            .lazy(instructions, (code_span, names)),
    );
    Ok(())
}

async fn instructions(cx: Cx, (span, names): (Span, Names)) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader::new(&data);
    let name = |f: u64| names.iter().find(|(i, _)| *i == f).map(|(_, n)| n.clone());
    let mut depth = 0usize;
    while !r.at_end() {
        let start = r.pos();
        let Some((mnemonic, operands)) = ops::instruction(&mut r, &name) else {
            cx.push(
                Node::new(format!("{start:#x}"))
                    .span(span.tail(to_u64(start)))
                    .diag(Diagnostic::unsupported("undecodable instruction")),
            )
            .await;
            break;
        };
        if matches!(
            mnemonic.as_str(),
            "end" | "else" | "catch" | "catch_all" | "delegate"
        ) {
            depth = depth.saturating_sub(1);
        }
        let indent = "  ".repeat(depth.min(32));
        if matches!(
            mnemonic.as_str(),
            "block" | "loop" | "if" | "else" | "try" | "try_table" | "catch" | "catch_all"
        ) {
            depth = depth.saturating_add(1);
        }
        cx.push(
            Node::new(format!("{start:#x}"))
                .span(span.sub(to_u64(start), to_u64(r.pos().saturating_sub(start))))
                .value(text(format!("{indent}{mnemonic}")))
                .maybe_summary(operands),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom sections

async fn custom(cx: &Cx, b: &mut Body<'_>) -> Result<()> {
    let start = b.r.pos();
    let section = name(&mut b.r).ok_or_else(|| b.malformed("custom section name"))?;
    cx.emit(
        Node::new("name")
            .span(b.at(start))
            .value(text(section.clone())),
    );
    let rest = b.span.tail(to_u64(b.r.pos()));
    match section.as_str() {
        "name" => {
            while !b.r.at_end() {
                let start = b.r.pos();
                let id = b.r.u8().ok_or_else(|| b.malformed("name subsection"))?;
                let size = b.r.uleb().ok_or_else(|| b.malformed("name subsection"))?;
                let body_start = b.r.pos();
                let sub =
                    b.r.bytes(usize::try_from(size).unwrap_or(usize::MAX))
                        .ok_or_else(|| b.malformed("name subsection"))?
                        .to_vec();
                let span = b.at(start);
                let body = b.span.sub(to_u64(body_start), size);
                let label = name_or(NAME_SUBSECTION, id.into(), "Subsection");
                cx.emit(
                    Node::new(label)
                        .span(span)
                        .lazy(name_subsection, (id, body, sub)),
                );
            }
        }
        "producers" => {
            let n = b.r.uleb().ok_or_else(|| b.malformed("producers"))?;
            for _ in 0..n {
                let start = b.r.pos();
                let field = name(&mut b.r).ok_or_else(|| b.malformed("producers"))?;
                let count = b.r.uleb().ok_or_else(|| b.malformed("producers"))?;
                let mut values = Vec::new();
                for _ in 0..count {
                    let (Some(n), Some(v)) = (name(&mut b.r), name(&mut b.r)) else {
                        return Err(b.malformed("producers"));
                    };
                    values.push(if v.is_empty() { n } else { format!("{n} {v}") });
                }
                cx.emit(
                    Node::new(field)
                        .span(b.at(start))
                        .value(text(values.join(", "))),
                );
            }
        }
        "target_features" => {
            let n = b.r.uleb().ok_or_else(|| b.malformed("target features"))?;
            for _ in 0..n {
                let start = b.r.pos();
                let prefix = b.r.u8().ok_or_else(|| b.malformed("target features"))?;
                let feature = name(&mut b.r).ok_or_else(|| b.malformed("target features"))?;
                cx.emit(
                    Node::new(feature)
                        .span(b.at(start))
                        .value(text(match prefix {
                            b'+' => "used",
                            b'-' => "disallowed",
                            b'=' => "required",
                            _ => "?",
                        })),
                );
            }
        }
        "sourceMappingURL" | "external_debug_info" => {
            let start = b.r.pos();
            let url = name(&mut b.r).ok_or_else(|| b.malformed("URL"))?;
            cx.emit(Node::new("URL").span(b.at(start)).value(text(url)));
        }
        _ => cx.emit(
            Node::new("Contents")
                .span(rest)
                .summary(format!("{:#x} bytes", rest.len)),
        ),
    }
    Ok(())
}

async fn name_subsection(cx: Cx, (id, span, data): (u8, Span, Vec<u8>)) -> Result<()> {
    let mut b = Body {
        r: Reader::new(&data),
        span,
    };
    match id {
        0 => {
            let start = b.r.pos();
            let n = name(&mut b.r).ok_or_else(|| b.malformed("module name"))?;
            cx.emit(Node::new("module").span(b.at(start)).value(text(n)));
            Ok(())
        }
        2 | 3 | 10 => {
            // Indirect name maps: (index, name map).
            vector(&cx, &mut b, "indirect name map", |b, _| {
                let outer = b.r.uleb()?;
                let n = b.r.uleb()?;
                let mut names = Vec::new();
                for _ in 0..n {
                    let i = b.r.uleb()?;
                    names.push(format!("{i}: {}", name(&mut b.r)?));
                }
                Some((
                    format!("[{outer}]"),
                    text(ellipsize(&names.join(", "), 120)),
                    String::new(),
                ))
            })
            .await
        }
        _ => {
            vector(&cx, &mut b, "name map", |b, _| {
                let index = b.r.uleb()?;
                let n = name(&mut b.r)?;
                Some((format!("[{index}]"), text(n), String::new()))
            })
            .await
        }
    }
}
