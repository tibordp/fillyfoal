//! WebAssembly binary modules (`\0asm`).
//!
//! The file is a header and a sequence of sections (id, LEB128 size,
//! contents). The top level walks the section headers only; expanding a
//! section walks its vector of entries (types, imports, exports, function
//! bodies, data segments, ...) through a read-ahead window, one bounded
//! piece at a time, with resume marks so a page deep into a large vector
//! does not re-walk it. A function body is read only when its entry is
//! expanded. Function names come from the custom `name` section: the code
//! section walks its function-name map alongside the bodies, and the
//! instruction listing looks names up in a sparse index of that map.

mod ops;

use std::cell::Cell;
use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::binutil::{NodeExt, Reader};
use crate::formats::util::fmt::{clip, count, plural};
use crate::formats::util::pace::{Pace, STEPS_PER_UNIT};
use crate::formats::util::val::{hex, name_or, text, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
/// Bytes read ahead when walking a vector.
const WINDOW: u64 = 64 << 10;
/// Bytes read ahead when looking up one name.
const LOOKUP_WINDOW: u64 = 4 << 10;
/// Largest single entry decoded in memory. Code bodies and data segment
/// payloads are not part of their entries' decoding.
const MAX_ENTRY: u64 = 4 << 20;
/// Largest import section the top level walks to count imported functions.
const ROOT_IMPORTS: u64 = 1 << 20;
/// Bytes of a function body looked at for its locals in the code listing.
const LOCALS_PEEK: u64 = 4 << 10;
/// Entries of the function-name map between two points of its index.
const NAME_STRIDE: u64 = 64;
/// Work charged per decoded item on top of its bytes (allocating and
/// rendering it), in [`STEPS_PER_UNIT`]ths of a unit.
const ITEM_COST: u64 = 256;
/// Most sections listed: real modules have a few dozen.
const MAX_SECTIONS: usize = 10_000;

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

fn malformed(at: Span, what: &str) -> Diagnostic {
    Diagnostic::malformed(format!("truncated or malformed {what}")).at(at)
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

/// The import descriptor after the kind byte, rendered.
fn import_desc(r: &mut Reader<'_>, kind: u8) -> Option<String> {
    Some(match kind {
        0 => format!("type {}", r.uleb()?),
        1 => table_type(r)?,
        2 => limits(r)?,
        3 => global_type(r)?,
        4 => {
            r.u8()?;
            format!("type {}", r.uleb()?)
        }
        _ => return None,
    })
}

// ---------------------------------------------------------------------------
// Windowed reading

/// A read-ahead buffer over a region, for decoding variable-length items
/// that are each small but together may be far larger than one read.
struct Window {
    region: Span,
    /// Offset of `data` in the region.
    base: u64,
    data: Vec<u8>,
    /// No more bytes follow `data` (the region's end, or the source's).
    exhausted: bool,
    step: u64,
}

impl Window {
    fn new(region: Span, step: u64) -> Self {
        Window {
            region,
            base: 0,
            data: Vec::new(),
            exhausted: false,
            step,
        }
    }

    /// The buffered bytes from `pos` on, if `pos` is buffered.
    fn from(&self, pos: u64) -> Option<&[u8]> {
        let off = usize::try_from(pos.checked_sub(self.base)?).ok()?;
        self.data.get(off..)
    }

    /// Decodes the item at `pos` (relative to the region) with `f`, which
    /// sees the bytes from `pos` on and returns `None` when it needs more.
    /// The window is refilled from `pos`, growing up to [`MAX_ENTRY`];
    /// `Ok(None)` means the item is malformed or runs past the end.
    async fn decode<T>(
        &mut self,
        cx: &Cx,
        pos: u64,
        mut f: impl FnMut(&[u8]) -> Option<T>,
    ) -> Result<Option<T>> {
        let max = MAX_ENTRY.min(cx.limits().max_read).max(self.step);
        loop {
            let mut want = self.step;
            if let Some(buf) = self.from(pos) {
                if let Some(t) = f(buf) {
                    return Ok(Some(t));
                }
                if self.exhausted {
                    return Ok(None);
                }
                if self.base == pos {
                    let have = to_u64(buf.len());
                    if have >= max {
                        return Err(
                            Diagnostic::limit(format!("entry larger than {max:#x} bytes"))
                                .at(self.region.sub(pos, have)),
                        );
                    }
                    want = have.saturating_mul(2).clamp(self.step, max);
                }
            }
            let span = self.region.sub(pos, want);
            self.data = cx.read_avail(span).await?;
            self.base = pos;
            self.exhausted = to_u64(self.data.len()) < want;
        }
    }
}

/// State of a vector walk, recorded in resume marks: the position of the
/// next entry (relative to the vector's region), its index, the number of
/// entries, and per-vector counters.
#[derive(Clone, Copy, Debug, Default)]
struct Walk {
    pos: u64,
    index: u64,
    count: u64,
    aux: [u64; 5],
}

/// One decoded vector entry: its node (without a span) and its length,
/// which for sized entries may extend past the bytes decoded.
struct Entry {
    node: Node,
    len: Option<u64>,
}

impl Entry {
    fn new(node: Node) -> Self {
        Entry { node, len: None }
    }
}

/// Reads a vector's leading count.
async fn vector_count(cx: &Cx, region: Span, what: &str) -> Result<(u64, u64)> {
    let mut cur = Cursor::new(cx, region, LE);
    let count = cur
        .uleb128()
        .await
        .map_err(|_| malformed(region.sub(0, 1), &format!("{what} count")))?;
    Ok((count, cur.pos()))
}

/// Walks a vector in `region`: a LEB128 count, then `count` entries, each
/// decoded by `entry` (given the entry's index and the walk's counters) and
/// pushed as a node spanning its bytes. `pre` children were emitted before
/// the walk (on a fresh run only).
async fn vector<F>(
    cx: &Cx,
    region: Span,
    resumed: Option<Walk>,
    pre: u64,
    what: &str,
    mut entry: F,
) -> Result<()>
where
    F: FnMut(&mut Reader<'_>, u64, &mut [u64; 5]) -> Option<Entry>,
{
    let mut walk = match resumed {
        Some(w) => w,
        None => {
            let (count, pos) = vector_count(cx, region, what).await?;
            Walk {
                pos,
                count,
                ..Walk::default()
            }
        }
    };
    if walk.count <= region.len {
        cx.set_count(Count::Exact(walk.count.saturating_add(pre)));
    }
    let mut win = Window::new(region, WINDOW);
    let mut pace = Pace::new(cx, STEPS_PER_UNIT);
    while walk.index < walk.count {
        let at = walk;
        cx.mark(move || at);
        let got = win
            .decode(cx, walk.pos, |buf| {
                let mut r = Reader::new(buf);
                let mut aux = walk.aux;
                let e = entry(&mut r, walk.index, &mut aux)?;
                Some((e, aux, to_u64(r.pos())))
            })
            .await?;
        let start = region.tail(walk.pos);
        let Some((e, aux, decoded)) = got else {
            return Err(malformed(start.sub(0, 1), what));
        };
        let len = e.len.unwrap_or(decoded);
        if len == 0 || len > start.len {
            return Err(malformed(start.sub(0, 1), what));
        }
        pace.add(decoded.saturating_add(ITEM_COST)).await;
        cx.push(e.node.span(start.sub(0, len))).await;
        walk.pos = walk.pos.saturating_add(len);
        walk.index = walk.index.saturating_add(1);
        walk.aux = aux;
    }
    if walk.pos < region.len {
        cx.diag(Diagnostic::warning("data after the last entry"));
    }
    Ok(())
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

    // Section headers only: an id, a size and, for custom sections, the
    // name at the start of the contents.
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(8);
    let mut sections = Vec::new();
    let mut custom_names = Vec::new();
    let mut rest = None;
    while !cur.at_end() {
        let start = cur.pos();
        if sections.len() >= MAX_SECTIONS {
            cx.diag(Diagnostic::limit(format!(
                "more than {MAX_SECTIONS} sections"
            )));
            rest = Some(file.tail(start));
            break;
        }
        let id = cur.u8().await?;
        let size = cur.uleb128().await?;
        if id == 0 && size == 0 {
            // A custom section starts with its name: this is not a section
            // header (zeros, or data past the module).
            cx.diag(Diagnostic::malformed("custom section without a name").at(file.sub(start, 2)));
            rest = Some(file.tail(start));
            break;
        }
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
    cx.set_count(Count::Exact(
        to_u64(m.sections.len())
            .saturating_add(1)
            .saturating_add(rest.map_or(0, |_| 1)),
    ));
    for (index, s) in m.sections.iter().enumerate() {
        // `custom_names` is in section order.
        let custom = m
            .custom_names
            .binary_search_by_key(&index, |(i, _)| *i)
            .ok()
            .and_then(|k| m.custom_names.get(k));
        let label = match custom {
            Some((_, n)) => format!("Custom \"{n}\""),
            None => name_or(SECTION, s.id.into(), "Section"),
        };
        let count = if matches!(s.id, 0 | 8 | 12) {
            None
        } else {
            leading_count(&cx, s.body).await
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
    if let Some(rest) = rest {
        cx.push(
            Node::new("Unparsed")
                .span(rest)
                .summary(format!("{:#x} bytes", rest.len)),
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

/// The LEB128 count a vector section starts with (a small read).
async fn leading_count(cx: &Cx, body: Span) -> Option<u64> {
    let data = cx.read_avail(body.sub(0, 10)).await.ok()?;
    Reader::new(&data).uleb()
}

async fn module_summary(cx: &Cx, m: &ModuleInfo) -> String {
    let mut parts = vec!["WebAssembly module".to_owned()];
    // Counting imported functions walks the import section; a large one is
    // summarised by its count instead.
    let imports = m.find(2);
    let imported = match imports {
        Some(s) if s.body.len <= ROOT_IMPORTS => Some(import_kinds(cx, s.body).await[0]),
        Some(_) => None,
        None => Some(0),
    };
    if let Some(s) = m.find(3)
        && let Some(n) = leading_count(cx, s.body).await
    {
        let mut s = format!("{n} functions");
        match imported {
            Some(0) => {}
            Some(k) => s.push_str(&format!(" + {k} imported")),
            None => {
                if let Some(i) = imports
                    && let Some(k) = leading_count(cx, i.body).await
                {
                    s.push_str(&format!(", {}", plural(k, "import")));
                }
            }
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
        parts.push(format!("{n} exports ({})", clip(&names.join(", "), 80)));
    }
    parts.join(", ")
}

/// How many functions, tables, memories, globals and tags are imported
/// (walked once per import section and cached; a malformed entry ends the
/// count).
async fn import_kinds(cx: &Cx, body: Span) -> [u64; 5] {
    if let Some(k) = cx.cached::<[u64; 5]>(body, "wasm-import-kinds") {
        return *k;
    }
    let mut out = [0u64; 5];
    if let Ok((count, mut pos)) = vector_count(cx, body, "import").await {
        let mut win = Window::new(body, WINDOW);
        let mut pace = Pace::new(cx, STEPS_PER_UNIT);
        for _ in 0..count {
            let got = win
                .decode(cx, pos, |buf| {
                    let mut r = Reader::new(buf);
                    name(&mut r)?;
                    name(&mut r)?;
                    let kind = r.u8()?;
                    import_desc(&mut r, kind)?;
                    Some((kind, to_u64(r.pos())))
                })
                .await;
            let Ok(Some((kind, len))) = got else { break };
            if let Some(slot) = out.get_mut(usize::from(kind)) {
                *slot = slot.saturating_add(1);
            }
            pos = pos.saturating_add(len);
            pace.add(len.saturating_add(ITEM_COST)).await;
        }
    }
    cx.cache(body, "wasm-import-kinds", Arc::new(out));
    out
}

async fn imported_functions(cx: &Cx, m: &ModuleInfo) -> u64 {
    match m.find(2) {
        Some(s) => import_kinds(cx, s.body).await[0],
        None => 0,
    }
}

// ---------------------------------------------------------------------------
// Sections

async fn section(cx: Cx, (m, index): (Module, usize)) -> Result<()> {
    let s = *m
        .sections
        .get(index)
        .ok_or_else(|| Diagnostic::internal("section index out of range"))?;
    let resumed = cx.resume::<Walk>();
    if resumed.is_none() {
        let header = cx
            .block(s.span.sub(0, s.span.len.saturating_sub(s.body.len)))
            .await?;
        let mut f = Fields::emitting(&cx, &header, LE);
        f.u8("id").enumeration(SECTION).emit()?;
        let size_len = header.span.len.saturating_sub(1);
        f.bytes("size", size_len)
            .with(|_, n| n.value(uint(s.body.len, 32)).desc("LEB128"))
            .emit()?;
    }
    let body = s.body;
    match s.id {
        0 => custom(&cx, body, resumed).await,
        1 => {
            vector(&cx, body, resumed, 2, "type", |r, _, aux| {
                // aux[0]: the index of the next type (a recursion group
                // defines several).
                let start_index = aux[0];
                let s = if r.peek()? == 0x4e {
                    r.u8()?;
                    let n = r.uleb()?;
                    let mut members = Vec::new();
                    for _ in 0..n {
                        members.push(sub_type(r)?);
                    }
                    aux[0] = aux[0].saturating_add(n);
                    format!("rec {{{}}}", members.join("; "))
                } else {
                    aux[0] = aux[0].saturating_add(1);
                    sub_type(r)?
                };
                Some(Entry::new(
                    Node::new(format!("type {start_index}")).value(text(s)),
                ))
            })
            .await
        }
        2 => {
            vector(&cx, body, resumed, 2, "import", |r, _, aux| {
                // aux[kind]: imports of each kind so far.
                let module = name(r)?;
                let field = name(r)?;
                let kind = r.u8()?;
                let desc = import_desc(r, kind)?;
                let slot = aux.get_mut(usize::from(kind))?;
                let index = *slot;
                *slot = slot.saturating_add(1);
                Some(Entry::new(
                    Node::new(format!("{module}.{field}"))
                        .value(text(format!(
                            "{} {index}",
                            name_or(EXTERNAL_KIND, kind.into(), "kind")
                        )))
                        .maybe_summary(desc),
                ))
            })
            .await
        }
        3 => {
            let imported = imported_functions(&cx, &m).await;
            vector(&cx, body, resumed, 2, "function", |r, i, _| {
                let t = r.uleb()?;
                Some(Entry::new(
                    Node::new(format!("func {}", imported.saturating_add(i)))
                        .value(text(format!("type {t}"))),
                ))
            })
            .await
        }
        4 => {
            vector(&cx, body, resumed, 2, "table", |r, i, _| {
                Some(Entry::new(
                    Node::new(format!("table {i}")).value(text(table_type(r)?)),
                ))
            })
            .await
        }
        5 => {
            vector(&cx, body, resumed, 2, "memory", |r, i, _| {
                let l = limits(r)?;
                Some(Entry::new(
                    Node::new(format!("memory {i}"))
                        .value(text(l))
                        .summary("pages of 64 KiB"),
                ))
            })
            .await
        }
        6 => {
            vector(&cx, body, resumed, 2, "global", |r, i, _| {
                let t = global_type(r)?;
                let init = const_expr(r)?;
                Some(Entry::new(
                    Node::new(format!("global {i}"))
                        .value(text(t))
                        .maybe_summary(init),
                ))
            })
            .await
        }
        7 => {
            vector(&cx, body, resumed, 2, "export", |r, _, _| {
                let n = name(r)?;
                let kind = r.u8()?;
                let index = r.uleb()?;
                Some(Entry::new(Node::new(n).value(text(format!(
                    "{} {index}",
                    name_or(EXTERNAL_KIND, kind.into(), "kind")
                )))))
            })
            .await
        }
        8 => single(&cx, body, "start function", "start").await,
        9 => vector(&cx, body, resumed, 2, "element segment", element).await,
        10 => code(&cx, &m, body, resumed).await,
        11 => vector(&cx, body, resumed, 2, "data segment", data_segment).await,
        12 => single(&cx, body, "data segments", "data count").await,
        13 => {
            vector(&cx, body, resumed, 2, "tag", |r, i, _| {
                r.u8()?;
                let t = r.uleb()?;
                Some(Entry::new(
                    Node::new(format!("tag {i}")).value(text(format!("type {t}"))),
                ))
            })
            .await
        }
        _ => {
            cx.emit(
                Node::new("Contents")
                    .span(body)
                    .diag(Diagnostic::unsupported(format!("section id {}", s.id))),
            );
            Ok(())
        }
    }
}

/// A section holding one LEB128 number (start, data count).
async fn single(cx: &Cx, body: Span, label: &'static str, what: &str) -> Result<()> {
    let mut cur = Cursor::new(cx, body, LE);
    let n = cur
        .uleb128()
        .await
        .map_err(|_| malformed(body.sub(0, 1), what))?;
    cx.emit(Node::new(label).span(cur.since(0)).value(uint(n, 32)));
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

fn element(r: &mut Reader<'_>, i: u64, _: &mut [u64; 5]) -> Option<Entry> {
    let flags = r.uleb()?;
    let passive_or_declarative = flags & 1 != 0;
    let explicit_table = flags & 2 != 0;
    let expressions = flags & 4 != 0;
    let mut mode = if !passive_or_declarative {
        let table = if explicit_table { r.uleb()? } else { 0 };
        format!("active in table {table}, offset {}", const_expr(r)?)
    } else if explicit_table {
        "declarative".to_owned()
    } else {
        "passive".to_owned()
    };
    if passive_or_declarative || explicit_table {
        if expressions {
            mode.push_str(&format!(", {}", val_type(r)?));
        } else {
            r.u8()?; // elemkind: funcref
        }
    }
    let n = r.uleb()?;
    let mut items = Vec::new();
    for _ in 0..n {
        let item = if expressions {
            const_expr(r)?
        } else {
            format!("func {}", r.uleb()?)
        };
        // 128 items join to more than the 120 characters shown.
        if items.len() < 128 {
            items.push(item);
        }
    }
    Some(Entry::new(
        Node::new(format!("segment {i}"))
            .value(text(clip(&items.join(", "), 120)))
            .summary(format!("{mode}, {n} items")),
    ))
}

/// A data segment: its mode and a preview of its bytes. The payload itself
/// is not read.
fn data_segment(r: &mut Reader<'_>, i: u64, _: &mut [u64; 5]) -> Option<Entry> {
    let flags = r.uleb()?;
    let mode = match flags {
        0 => format!("active, offset {}", const_expr(r)?),
        1 => "passive".to_owned(),
        2 => {
            let mem = r.uleb()?;
            format!("active in memory {mem}, offset {}", const_expr(r)?)
        }
        _ => return None,
    };
    let len = r.uleb()?;
    let head = to_u64(r.pos());
    let preview = r.bytes(usize::try_from(len.min(32)).ok()?)?.to_vec();
    Some(Entry {
        node: Node::new(format!("segment {i}"))
            .value(Value::Bytes(preview))
            .summary(format!("{mode}, {len} bytes")),
        len: Some(head.saturating_add(len)),
    })
}

// ---------------------------------------------------------------------------
// Function names

/// The function-name map of the `name` section (its subsection 1), found by
/// walking the subsection headers.
async fn function_names(cx: &Cx, m: &ModuleInfo) -> Option<Span> {
    let s = m.custom("name")?;
    let mut cur = Cursor::new(cx, s.body, LE);
    let len = cur.uleb128().await.ok()?;
    cur.skip(len);
    while !cur.at_end() {
        let id = cur.u8().await.ok()?;
        let size = cur.uleb128().await.ok()?;
        if id == 1 {
            return Some(s.body.sub(cur.pos(), size));
        }
        cur.skip(size);
    }
    None
}

/// Decodes one `(index, name)` pair of a name map: the index, the name and
/// the pair's length.
fn name_pair(buf: &[u8]) -> Option<(u64, String, u64)> {
    let mut r = Reader::new(buf);
    let index = r.uleb()?;
    let n = name(&mut r)?;
    Some((index, n, to_u64(r.pos())))
}

/// A sparse index of a function-name map: every [`NAME_STRIDE`]th entry's
/// function index, position and ordinal. Names are sorted by index, so a
/// lookup reads at most a stride or two of entries.
struct NameIndex {
    first: u64,
    count: u64,
    points: Vec<(u64, u64, u64)>,
}

async fn name_index(cx: &Cx, map: Span) -> Arc<NameIndex> {
    if let Some(index) = cx.cached::<NameIndex>(map, "wasm-name-index") {
        return index;
    }
    let mut index = NameIndex {
        first: 0,
        count: 0,
        points: Vec::new(),
    };
    if let Ok((count, first)) = vector_count(cx, map, "function names").await {
        index.first = first;
        let mut win = Window::new(map, WINDOW);
        let mut pace = Pace::new(cx, STEPS_PER_UNIT);
        let mut pos = first;
        for k in 0..count {
            let Ok(Some((f, _, len))) = win.decode(cx, pos, name_pair).await else {
                break;
            };
            if k.is_multiple_of(NAME_STRIDE) {
                index.points.push((f, pos, k));
            }
            index.count = k.saturating_add(1);
            pos = pos.saturating_add(len);
            pace.add(len.saturating_add(ITEM_COST)).await;
        }
    }
    let index = Arc::new(index);
    cx.cache(map, "wasm-name-index", index.clone());
    index
}

/// The name of function `f` (the first one given for it).
async fn lookup_name(cx: &Cx, map: Span, index: &NameIndex, f: u64) -> Option<String> {
    // The last point before `f`: the first name for `f` follows it.
    let k = index.points.partition_point(|&(i, _, _)| i < f);
    let (mut pos, mut ordinal) = match k.checked_sub(1).and_then(|k| index.points.get(k)) {
        Some(&(_, pos, ordinal)) => (pos, ordinal),
        None => (index.first, 0),
    };
    let mut win = Window::new(map, LOOKUP_WINDOW);
    for _ in 0..NAME_STRIDE.saturating_mul(2) {
        if ordinal >= index.count {
            break;
        }
        let (i, n, len) = win.decode(cx, pos, name_pair).await.ok().flatten()?;
        if i == f {
            return Some(n);
        }
        if i > f {
            break;
        }
        pos = pos.saturating_add(len);
        ordinal = ordinal.saturating_add(1);
    }
    None
}

// ---------------------------------------------------------------------------
// Code

/// The code section: one entry per body (its size and span), labelled with
/// the function's name. The function-name map is walked alongside, its
/// position kept in the walk's counters (`aux[0]`: position, `aux[1]`:
/// entries left).
async fn code(cx: &Cx, m: &ModuleInfo, region: Span, resumed: Option<Walk>) -> Result<()> {
    let imported = imported_functions(cx, m).await;
    let names = function_names(cx, m).await;
    let mut walk = match resumed {
        Some(w) => w,
        None => {
            let (count, pos) = vector_count(cx, region, "function count").await?;
            let mut aux = [0u64; 5];
            if let Some(map) = names
                && let Ok((n, first)) = vector_count(cx, map, "function names").await
            {
                aux[0] = first;
                aux[1] = n;
            }
            Walk {
                pos,
                index: 0,
                count,
                aux,
            }
        }
    };
    if walk.count <= region.len {
        cx.set_count(Count::Exact(walk.count.saturating_add(2)));
    }
    let mut win = Window::new(region, WINDOW);
    let mut name_win = names.map(|map| Window::new(map, WINDOW));
    let mut pace = Pace::new(cx, STEPS_PER_UNIT);
    while walk.index < walk.count {
        let at = walk;
        cx.mark(move || at);
        let index = imported.saturating_add(walk.index);

        let mut label = None;
        if let Some(nw) = name_win.as_mut() {
            while walk.aux[1] > 0 {
                let Ok(Some((f, n, len))) = nw.decode(cx, walk.aux[0], name_pair).await else {
                    walk.aux[1] = 0;
                    break;
                };
                if f > index {
                    break;
                }
                walk.aux[0] = walk.aux[0].saturating_add(len);
                walk.aux[1] = walk.aux[1].saturating_sub(1);
                pace.add(len.saturating_add(ITEM_COST)).await;
                if f == index {
                    label = Some(n);
                    break;
                }
            }
        }

        let start = region.tail(walk.pos);
        let got = win
            .decode(cx, walk.pos, |buf| {
                let mut r = Reader::new(buf);
                let size = r.uleb()?;
                let head = r.pos();
                let avail = r.rest();
                let want = usize::try_from(size.min(LOCALS_PEEK)).ok()?;
                let body = avail.get(..want.min(avail.len()))?;
                let (locals, parsed, complete) = locals(body);
                if !complete && body.len() < want {
                    return None;
                }
                Some((size, to_u64(head), parsed, locals))
            })
            .await?;
        let Some((size, head, locals_len, locals)) = got else {
            return Err(malformed(start.sub(0, 1), "function body size"));
        };
        let len = head.saturating_add(size);
        if len > start.len {
            return Err(malformed(start.sub(head, 1), "function body"));
        }
        pace.add(head.saturating_add(locals_len).saturating_add(ITEM_COST))
            .await;

        let code_len = size.saturating_sub(locals_len);
        let mut summary = format!("{code_len} bytes of code");
        if !locals.is_empty() {
            summary.push_str(&format!(", locals {}", locals.join(", ")));
        }
        let label = label.unwrap_or_else(|| format!("func {index}"));
        cx.push(
            Node::new(label)
                .span(start.sub(0, len))
                .value(hex(index, 32))
                .summary(summary)
                .lazy(function_body, (start.sub(head, size), names)),
        )
        .await;
        walk.pos = walk.pos.saturating_add(len);
        walk.index = walk.index.saturating_add(1);
    }
    if walk.pos < region.len {
        cx.diag(Diagnostic::warning("data after the last entry"));
    }
    Ok(())
}

/// The local declarations at the start of a function body (groups of
/// count and type, at most 4096 shown): the rendered groups, their length,
/// and whether they were decoded to the end.
fn locals(body: &[u8]) -> (Vec<String>, u64, bool) {
    let mut r = Reader::new(body);
    let mut out = Vec::new();
    let Some(groups) = r.uleb() else {
        return (out, 0, false);
    };
    for _ in 0..groups.min(4096) {
        let (Some(count), Some(t)) = (r.uleb(), val_type(&mut r)) else {
            return (out, to_u64(r.pos()), false);
        };
        out.push(format!("{count} × {t}"));
    }
    (out, to_u64(r.pos()), true)
}

async fn function_body(cx: Cx, (body, names): (Span, Option<Span>)) -> Result<()> {
    let data = cx.read(body).await?;
    let (locals, len, _) = locals(&data);
    cx.emit(
        Node::new("Locals")
            .span(body.sub(0, len))
            .maybe_summary(locals.join(", ")),
    );
    let code = body.tail(len);
    cx.emit(
        Node::new("Instructions")
            .span(code)
            .summary(format!("{} bytes", code.len))
            .lazy(instructions, (code, names)),
    );
    Ok(())
}

async fn instructions(cx: Cx, (span, names): (Span, Option<Span>)) -> Result<()> {
    let data = cx.read(span).await?;
    let (mut pos, mut depth) = cx.resume::<(usize, usize)>().unwrap_or((0, 0));
    let mut index: Option<Arc<NameIndex>> = None;
    let mut resolved: BTreeMap<u64, Option<String>> = BTreeMap::new();
    while pos < data.len() {
        let at = (pos, depth);
        cx.mark(move || at);
        let start = pos;
        // Decode once noting the function a call refers to; if it has a
        // name, decode again with it.
        let wanted = Cell::new(None);
        let mut r = Reader::at(&data, start);
        let mut decoded = ops::instruction(&mut r, &|f| {
            wanted.set(Some(f));
            None
        });
        let mut end = r.pos();
        if let (Some(f), Some(map), false) = (wanted.get(), names, cx.skipping()) {
            let n = match resolved.get(&f) {
                Some(n) => n.clone(),
                None => {
                    let ix = match &index {
                        Some(ix) => ix.clone(),
                        None => {
                            let ix = name_index(&cx, map).await;
                            index = Some(ix.clone());
                            ix
                        }
                    };
                    let n = lookup_name(&cx, map, &ix, f).await;
                    resolved.insert(f, n.clone());
                    n
                }
            };
            if n.is_some() {
                let mut r = Reader::at(&data, start);
                decoded = ops::instruction(&mut r, &|_| n.clone());
                end = r.pos();
            }
        }
        let Some((mnemonic, operands)) = decoded else {
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
                .span(span.sub(to_u64(start), to_u64(end.saturating_sub(start))))
                .value(text(format!("{indent}{mnemonic}")))
                .maybe_summary(operands),
        )
        .await;
        pos = end.max(start.saturating_add(1));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Custom sections

async fn custom(cx: &Cx, body: Span, resumed: Option<Walk>) -> Result<()> {
    let mut cur = Cursor::new(cx, body, LE);
    let len = cur
        .uleb128()
        .await
        .map_err(|_| malformed(body.sub(0, 1), "custom section name"))?;
    if len > 0x1_0000 {
        return Err(malformed(body.sub(0, 1), "custom section name"));
    }
    let bytes = cur
        .bytes(len)
        .await
        .map_err(|_| malformed(body.sub(0, 1), "custom section name"))?;
    let section = String::from_utf8_lossy(&bytes).into_owned();
    let rest = body.tail(cur.pos());
    if resumed.is_none() {
        cx.emit(
            Node::new("name")
                .span(cur.since(0))
                .value(text(section.clone())),
        );
    }
    match section.as_str() {
        "name" => name_section(cx, rest, resumed).await,
        "producers" => {
            vector(cx, rest, resumed, 3, "producers", |r, _, _| {
                let field = name(r)?;
                let count = r.uleb()?;
                let mut values = Vec::new();
                for _ in 0..count {
                    let n = name(r)?;
                    let v = name(r)?;
                    values.push(if v.is_empty() { n } else { format!("{n} {v}") });
                }
                Some(Entry::new(Node::new(field).value(text(values.join(", ")))))
            })
            .await
        }
        "target_features" => {
            vector(cx, rest, resumed, 3, "target features", |r, _, _| {
                let prefix = r.u8()?;
                let feature = name(r)?;
                Some(Entry::new(Node::new(feature).value(text(match prefix {
                    b'+' => "used",
                    b'-' => "disallowed",
                    b'=' => "required",
                    _ => "?",
                }))))
            })
            .await
        }
        "sourceMappingURL" | "external_debug_info" => {
            let mut win = Window::new(rest, LOOKUP_WINDOW);
            let got = win
                .decode(cx, 0, |buf| {
                    let mut r = Reader::new(buf);
                    let url = name(&mut r)?;
                    Some((url, to_u64(r.pos())))
                })
                .await?;
            let (url, len) = got.ok_or_else(|| malformed(rest.sub(0, 1), "URL"))?;
            cx.emit(Node::new("URL").span(rest.sub(0, len)).value(text(url)));
            Ok(())
        }
        _ => {
            cx.emit(
                Node::new("Contents")
                    .span(rest)
                    .summary(format!("{:#x} bytes", rest.len)),
            );
            Ok(())
        }
    }
}

/// The subsections of the `name` section (id, size, contents), each
/// decoded when expanded.
async fn name_section(cx: &Cx, region: Span, resumed: Option<Walk>) -> Result<()> {
    let mut walk = resumed.unwrap_or_default();
    let mut cur = Cursor::new(cx, region, LE);
    while walk.pos < region.len {
        let at = walk;
        cx.mark(move || at);
        cur.seek(walk.pos);
        let bad = || malformed(region.sub(walk.pos, 1), "name subsection");
        let id = cur.u8().await.map_err(|_| bad())?;
        let size = cur.uleb128().await.map_err(|_| bad())?;
        let body = region.sub(cur.pos(), size);
        if body.len < size {
            return Err(bad());
        }
        let label = name_or(NAME_SUBSECTION, id.into(), "Subsection");
        let mut node = Node::new(label).span(region.sub(
            walk.pos,
            cur.pos().saturating_add(size).saturating_sub(walk.pos),
        ));
        if id != 0
            && let Some(n) = leading_count(cx, body).await
        {
            node = node.summary(count(n, "entry", "entries"));
        }
        cx.push(node.lazy(name_subsection, (id, body))).await;
        walk.pos = cur.pos().saturating_add(size);
    }
    Ok(())
}

async fn name_subsection(cx: Cx, (id, body): (u8, Span)) -> Result<()> {
    let resumed = cx.resume::<Walk>();
    match id {
        0 => {
            let mut win = Window::new(body, LOOKUP_WINDOW);
            let got = win
                .decode(&cx, 0, |buf| {
                    let mut r = Reader::new(buf);
                    let n = name(&mut r)?;
                    Some((n, to_u64(r.pos())))
                })
                .await?;
            let (n, len) = got.ok_or_else(|| malformed(body.sub(0, 1), "module name"))?;
            cx.emit(Node::new("module").span(body.sub(0, len)).value(text(n)));
            Ok(())
        }
        2 | 3 | 10 => {
            // Indirect name maps: (index, name map).
            vector(&cx, body, resumed, 0, "indirect name map", |r, _, _| {
                let outer = r.uleb()?;
                let n = r.uleb()?;
                let mut names = Vec::new();
                for _ in 0..n {
                    let i = r.uleb()?;
                    let entry = format!("{i}: {}", name(r)?);
                    // 128 entries join to more than the 120 characters shown.
                    if names.len() < 128 {
                        names.push(entry);
                    }
                }
                Some(Entry::new(
                    Node::new(format!("[{outer}]")).value(text(clip(&names.join(", "), 120))),
                ))
            })
            .await
        }
        _ => {
            vector(&cx, body, resumed, 0, "name map", |r, _, _| {
                let index = r.uleb()?;
                let n = name(r)?;
                Some(Entry::new(Node::new(format!("[{index}]")).value(text(n))))
            })
            .await
        }
    }
}
