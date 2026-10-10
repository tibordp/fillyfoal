//! Realm database files (Realm Core 10 and later: file formats 20–24).
//!
//! A Realm file is a 24-byte header (two top refs, the `T-DB` mnemonic,
//! two file format versions and a flag byte choosing the current slot)
//! followed by *arrays*: 8-byte headers (a 4-byte checksum, normally
//! `AAAA`; a flag byte with the inner-B+tree, has-refs and context bits,
//! the width encoding and width; a 24-bit big-endian element count) and
//! packed elements of 0–64 bits, or fixed-size slots, or raw bytes.
//! Elements of arrays with refs are either refs (even) or tagged integers
//! (`value << 1 | 1`). A file written in streaming form (by compaction or
//! `writeCopy`) has an invalid top ref in the header and a 16-byte footer
//! with the top ref and a cookie.
//!
//! The top array (the *group*) holds the table names, the table refs, the
//! logical file size, the free lists, the version and history. Each table
//! has a top array with its spec (column types, names, attributes and
//! keys), a cluster tree of objects (leaf clusters hold the object keys
//! and one array per column; inner nodes hold child clusters), search
//! indexes, the table key and the link targets. Objects are listed with
//! their values decoded for the common column types (integers, booleans,
//! strings, binary, float, double, timestamps, links and lists of those).
//!
//! Layouts are from memory of Realm Core and were checked against a file
//! written by Realm JS 20.2 (Realm Core 14, file format 24). Older files
//! (formats before 20) store tables as column arrays and only get their
//! header and group shown. ObjectId, Decimal128, UUID, Mixed, dictionary
//! and set columns are shown raw.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u64_le};
use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::formats::text::plural;
use crate::formats::util::binutil::{dec, hex, text};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags, flag, lookup};

const COOKIE: u64 = 0x3034_1252_37e5_26c8;
const MAX_DEPTH: usize = 16;
/// Values shown per list.
const LIST_SHOWN: u64 = 32;
/// Characters of a string shown.
const MAX_TEXT: usize = 256;
/// Columns read per table.
const MAX_COLUMNS: u64 = 1024;
/// Slots of a group or table top array shown.
const MAX_SLOTS: u64 = 32;
/// Children of an inner cluster node, objects of a leaf (Realm uses 256).
const MAX_CLUSTER: u64 = 4096;
/// Column values decoded per object.
const MAX_VALUES: usize = 128;

const GROUP_SLOTS: &[&str] = &[
    "Table names",
    "Tables",
    "Logical file size",
    "Free positions",
    "Free sizes",
    "Free versions",
    "Version",
    "History type",
    "History",
    "History schema version",
    "Sync file id",
    "Evacuation point",
];

const TABLE_SLOTS: &[&str] = &[
    "Spec",
    "Columns (unused)",
    "Cluster tree",
    "Table key",
    "Search indexes",
    "Next column key tag",
    "Version",
    "Link target tables",
    "Link target columns",
    "Sequence number",
    "Collision map",
    "Primary key column",
    "Flags",
    "Tombstones",
];

const COLUMN_TYPES: EnumTable = &[
    (0, "int"),
    (1, "bool"),
    (2, "string"),
    (4, "binary"),
    (6, "mixed"),
    (8, "timestamp"),
    (9, "float"),
    (10, "double"),
    (11, "decimal128"),
    (12, "link"),
    (13, "link list"),
    (14, "backlink"),
    (15, "objectId"),
    (16, "typed link"),
    (17, "uuid"),
];

const ATTRS: FlagTable = &[
    flag(1, "indexed"),
    flag(2, "unique"),
    flag(8, "strong links"),
    flag(16, "nullable"),
    flag(32, "list"),
    flag(64, "dictionary"),
    flag(128, "set"),
    flag(256, "full text"),
];

const NULLABLE: u64 = 16;
const LIST: u64 = 32;
const COLLECTION: u64 = 32 | 64 | 128;

/// One array node.
#[derive(Clone, Debug)]
struct Arr {
    span: Span,
    inner: bool,
    refs: bool,
    context: bool,
    /// 0: bits per element, 1: bytes per element, 2: raw bytes.
    wtype: u8,
    width: u64,
    size: u64,
    data: Vec<u8>,
}

impl Arr {
    fn body(&self) -> Span {
        self.span.tail(8)
    }

    /// Element `i` (integer arrays), sign-extended for widths of 8 and up.
    fn get(&self, i: u64) -> Option<i64> {
        if i >= self.size || self.wtype != 0 {
            return None;
        }
        let w = self.width;
        if w == 0 {
            return Some(0);
        }
        let bit = i.checked_mul(w)?;
        let byte = to_usize(bit / 8);
        if w < 8 {
            let b = *self.data.get(byte)?;
            let shift = u32::try_from(bit % 8).ok()?;
            let mask: u8 = match w {
                1 => 1,
                2 => 3,
                _ => 15,
            };
            return Some(i64::from(b.checked_shr(shift)? & mask));
        }
        let n = to_usize(w / 8);
        let s = self.data.get(byte..byte.checked_add(n)?)?;
        Some(match n {
            1 => i64::from(i8::from_le_bytes([*s.first()?])),
            2 => i64::from(i16::from_le_bytes(s.try_into().ok()?)),
            4 => i64::from(i32::from_le_bytes(s.try_into().ok()?)),
            _ => i64::from_le_bytes(s.try_into().ok()?),
        })
    }

    fn ref_at(&self, i: u64) -> Option<u64> {
        let v = self.get(i)?;
        u64::try_from(v).ok().filter(|v| v % 2 == 0)
    }

    /// The bytes element `i` lives in.
    fn elem_span(&self, i: u64) -> Span {
        let w = self.width;
        match self.wtype {
            0 if w < 8 => self.body().sub(i.saturating_mul(w) / 8, 1),
            0 => self.body().sub(i.saturating_mul(w / 8), w / 8),
            1 => self.body().sub(i.saturating_mul(w), w),
            _ => self.body().sub(i, 1),
        }
    }

    fn describe(&self) -> String {
        let mut kind = Vec::new();
        if self.inner {
            kind.push("inner B+tree node");
        }
        if self.refs {
            kind.push("refs");
        }
        if self.context {
            kind.push("context");
        }
        let width = match self.wtype {
            0 => format!("{}-bit", self.width),
            1 => format!("{}-byte slots", self.width),
            _ => "bytes".to_owned(),
        };
        let mut s = format!("{}, {width}", plural(self.size, "element", "elements"));
        if !kind.is_empty() {
            s.push_str(&format!(" ({})", kind.join(", ")));
        }
        s
    }
}

/// Reads the array at `r`.
async fn array(cx: &Cx, file: Span, r: u64) -> Result<Arr> {
    if r == 0 || !r.is_multiple_of(8) {
        return Err(Diagnostic::malformed(format!("bad ref {r:#x}")));
    }
    let head = cx.read(file.sub_exact(r, 8)?).await?;
    let flags = head.get(4).copied().unwrap_or(0);
    let size = u64::from(u32::from_be_bytes([
        0,
        head.get(5).copied().unwrap_or(0),
        head.get(6).copied().unwrap_or(0),
        head.get(7).copied().unwrap_or(0),
    ]));
    let code = flags & 7;
    let width = if code == 0 {
        0
    } else {
        1u64.checked_shl(u32::from(code).saturating_sub(1))
            .unwrap_or(0)
    };
    let wtype = (flags >> 3) & 3;
    let len = match wtype {
        0 => size.saturating_mul(width).div_ceil(8),
        1 => size.saturating_mul(width),
        2 => size,
        _ => {
            return Err(
                Diagnostic::unsupported("array with an unknown width encoding").at(file.sub(r, 8)),
            );
        }
    };
    let body = file
        .sub_exact(r.saturating_add(8), len)
        .map_err(|e| e.at(file.sub(r, 8)))?;
    let data = cx.read(body).await?;
    Ok(Arr {
        span: file.sub(r, len.saturating_add(8)),
        inner: flags & 0x80 != 0,
        refs: flags & 0x40 != 0,
        context: flags & 0x20 != 0,
        wtype,
        width,
        size,
        data,
    })
}

/// A ref or tagged integer element, as a node value and summary.
fn slot(v: i64) -> (Value, String) {
    if v & 1 == 1 {
        let n = v >> 1;
        (Value::Int { value: n, bits: 64 }, "integer".to_owned())
    } else if v == 0 {
        (hex(0, 64), "none".to_owned())
    } else {
        (hex(u64::try_from(v).unwrap_or(0), 64), "ref".to_owned())
    }
}

fn untag(v: Option<i64>) -> Option<i64> {
    v.filter(|v| v & 1 == 1).map(|v| v >> 1)
}

/// A string or binary array: short strings (fixed slots), small blobs
/// (offsets, bytes, nulls) or big blobs (one ref per element).
struct Blobs {
    items: Vec<(Option<Vec<u8>>, Span)>,
}

/// Elements `from..limit` of a string or binary array.
async fn blobs(
    cx: &Cx,
    file: Span,
    a: &Arr,
    strings: bool,
    nullable: bool,
    from: u64,
    limit: u64,
) -> Result<Blobs> {
    let n = a.size.min(limit);
    let mut items = Vec::new();
    if !a.refs {
        // Short strings: each slot ends with its padding length.
        let w = a.width;
        for i in from..n {
            let span = a.elem_span(i);
            if w == 0 {
                items.push(((!nullable).then(Vec::new), span));
                continue;
            }
            let start = to_usize(i.saturating_mul(w));
            let slotb = a
                .data
                .get(start..start.saturating_add(to_usize(w)))
                .unwrap_or_default();
            let pad = u64::from(slotb.last().copied().unwrap_or(0));
            let len = w.checked_sub(1).and_then(|x| x.checked_sub(pad));
            items.push((
                len.map(|l| slotb.get(..to_usize(l)).unwrap_or_default().to_vec()),
                span,
            ));
        }
        return Ok(Blobs { items });
    }
    if a.context {
        // Big blobs: a ref per element (strings keep their NUL).
        for i in from..n {
            cx.checkpoint().await;
            let Some(r) = a.ref_at(i) else {
                items.push((None, a.elem_span(i)));
                continue;
            };
            if r == 0 {
                items.push((None, a.elem_span(i)));
                continue;
            }
            let b = array(cx, file, r).await?;
            let mut data = b
                .data
                .get(..to_usize(b.size.min(4096)))
                .unwrap_or_default()
                .to_vec();
            if strings && data.last() == Some(&0) {
                data.pop();
            }
            items.push((Some(data), b.span));
        }
        return Ok(Blobs { items });
    }
    // Small blobs: end offsets, the bytes, and null flags.
    let offsets = array(cx, file, a.ref_at(0).unwrap_or(0)).await?;
    let bytes = array(cx, file, a.ref_at(1).unwrap_or(0)).await?;
    let nulls = match a.ref_at(2) {
        Some(r) if r != 0 && a.size > 2 => Some(array(cx, file, r).await?),
        _ => None,
    };
    let mut begin = match from.checked_sub(1) {
        Some(p) => u64::try_from(offsets.get(p).unwrap_or(0)).unwrap_or(0),
        None => 0,
    };
    for i in from..offsets.size.min(limit) {
        let end = u64::try_from(offsets.get(i).unwrap_or(0)).unwrap_or(0);
        let null = nulls.as_ref().and_then(|z| z.get(i)).unwrap_or(0) != 0;
        let span = bytes.body().sub(begin, end.saturating_sub(begin));
        let mut data = bytes
            .data
            .get(to_usize(begin)..to_usize(end))
            .unwrap_or_default()
            .to_vec();
        if strings && data.last() == Some(&0) {
            data.pop();
        }
        items.push((if null { None } else { Some(data) }, span));
        begin = end.max(begin);
    }
    Ok(Blobs { items })
}

fn text_of(b: &[u8]) -> String {
    let s = String::from_utf8_lossy(b);
    if s.chars().count() > MAX_TEXT {
        let cut: String = s.chars().take(MAX_TEXT).collect();
        format!("{cut}…")
    } else {
        s.into_owned()
    }
}

#[derive(Clone, Debug)]
struct Column {
    name: String,
    kind: u64,
    attrs: u64,
    key: u64,
    /// Position in a leaf cluster (after the keys).
    index: u64,
    /// Target table name for links.
    target: Option<String>,
}

#[derive(Clone, Debug)]
struct Table {
    key: Option<i64>,
    columns: Vec<Column>,
    cluster: u64,
    pk: Option<u64>,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub_exact(0, 24)?).await?;
    let refs = [u64_le(&head, 0).unwrap_or(0), u64_le(&head, 8).unwrap_or(0)];
    let formats = [
        head.get(20).copied().unwrap_or(0),
        head.get(21).copied().unwrap_or(0),
    ];
    let flags = head.get(23).copied().unwrap_or(0);
    let sel = usize::from(flags & 1);
    let mut top = refs.get(sel).copied().unwrap_or(0);
    let format = formats.get(sel).copied().unwrap_or(0);
    let mut kids = Vec::new();
    for i in 0..2usize {
        let r = refs.get(i).copied().unwrap_or(0);
        let mut n = Node::new(format!("Top ref {i}"))
            .span(file.sub(to_u64(i).saturating_mul(8), 8))
            .value(hex(r, 64));
        if i == sel {
            n = n.summary(if r == u64::MAX {
                "current (in the footer)"
            } else {
                "current"
            });
        }
        kids.push(n);
    }
    kids.push(
        Node::new("Mnemonic")
            .span(file.sub(16, 4))
            .value(text("T-DB")),
    );
    for i in 0..2u64 {
        kids.push(
            Node::new(format!("File format {i}"))
                .span(file.sub(20u64.saturating_add(i), 1))
                .value(dec(
                    formats.get(to_usize(i)).copied().unwrap_or(0).into(),
                    8,
                )),
        );
    }
    kids.push(Node::new("Reserved").span(file.sub(22, 1)));
    kids.push(
        Node::new("Flags")
            .span(file.sub(23, 1))
            .value(hex(flags.into(), 8))
            .summary(format!("slot {sel} selected")),
    );
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 24))
            .lazy(emit_all, Arc::new(kids)),
    );
    // Streaming form: the top ref is in the footer.
    if top == u64::MAX && file.len >= 40 {
        let foot = file.sub(file.len.saturating_sub(16), 16);
        let d = cx.read(foot).await?;
        let cookie = u64_le(&d, 8).unwrap_or(0);
        top = u64_le(&d, 0).unwrap_or(0);
        let mut n = Node::new("Footer")
            .span(foot)
            .value(hex(top, 64))
            .summary("top ref");
        if cookie != COOKIE {
            n = n.diag(Diagnostic::malformed(format!("footer cookie {cookie:#x}")));
        }
        cx.emit(n);
    }
    let mut summary = format!("Realm database, file format {format}");
    if top == 0 {
        cx.annotate(format!("{summary}, empty"));
        return Ok(());
    }
    let group = array(&cx, file, top).await?;
    cx.emit(
        Node::new("Group")
            .span(group.span)
            .summary(group.describe())
            .lazy(slots, (file, top, GROUP_SLOTS)),
    );
    if format < 20 {
        cx.annotate(summary);
        cx.emit(Node::new("Tables").diag(Diagnostic::unsupported(
            "file formats before 20 (Realm Core 5 and earlier) store tables differently",
        )));
        return Ok(());
    }
    let names_ref = group.ref_at(0).unwrap_or(0);
    let tables_ref = group.ref_at(1).unwrap_or(0);
    if names_ref == 0 || tables_ref == 0 {
        cx.annotate(format!("{summary}, no tables"));
        return Ok(());
    }
    let names = array(&cx, file, names_ref).await?;
    let names = blobs(&cx, file, &names, true, false, 0, 4096).await?;
    let tables = array(&cx, file, tables_ref).await?;
    let user = names
        .items
        .iter()
        .filter(|(n, _)| n.as_deref().is_some_and(|n| n.starts_with(b"class_")))
        .count();
    summary.push_str(&format!(", {}", plural(to_u64(user), "class", "classes")));
    cx.annotate(summary);
    let list: Vec<(String, u64)> = names
        .items
        .iter()
        .enumerate()
        .map(|(i, (n, _))| {
            (
                text_of(n.as_deref().unwrap_or_default()),
                tables.ref_at(to_u64(i)).unwrap_or(0),
            )
        })
        .collect();
    cx.emit(
        Node::new("Tables")
            .span(tables.span)
            .summary(plural(to_u64(list.len()), "table", "tables"))
            .lazy(tables_x, (file, Arc::new(list))),
    );
    Ok(())
}

async fn emit_all(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.emit(n.clone());
    }
    Ok(())
}

async fn slots(cx: Cx, (file, top, names): (Span, u64, &'static [&'static str])) -> Result<()> {
    let a = array(&cx, file, top).await?;
    // Top arrays have a dozen slots; a bogus size is not walked.
    for i in 0..a.size.min(MAX_SLOTS) {
        let v = a.get(i).unwrap_or(0);
        let (value, kind) = slot(v);
        let name = names
            .get(to_usize(i))
            .map_or_else(|| format!("Slot {i}"), |s| (*s).to_owned());
        cx.push(
            Node::new(name)
                .span(a.elem_span(i))
                .value(value)
                .summary(kind),
        )
        .await;
    }
    Ok(())
}

async fn tables_x(cx: Cx, (file, list): (Span, Arc<Vec<(String, u64)>>)) -> Result<()> {
    // Table keys, for naming link targets.
    let mut keys = Vec::new();
    for (name, r) in list.iter() {
        let key = match array(&cx, file, *r).await {
            Ok(t) => untag(t.get(3)),
            Err(_) => None,
        };
        keys.push((key, name.clone()));
    }
    let keys = Arc::new(keys);
    cx.set_count(Count::Exact(to_u64(list.len())));
    for (name, r) in list.iter() {
        let shown = name.strip_prefix("class_").unwrap_or(name).to_owned();
        let node = match brief(&cx, file, *r).await {
            Ok((span, cols, objects)) => Node::new(shown)
                .span(span)
                .summary(format!(
                    "{}, {}",
                    plural(cols, "column", "columns"),
                    plural(objects, "object", "objects")
                ))
                .lazy(table_x, (file, *r, Arc::new(name.clone()), keys.clone())),
            Err(e) => Node::new(shown).diag(e),
        };
        cx.push(node).await;
    }
    Ok(())
}

/// A table's span, column count (without backlinks) and object count.
async fn brief(cx: &Cx, file: Span, r: u64) -> Result<(Span, u64, u64)> {
    let top = array(cx, file, r).await?;
    let spec = array(cx, file, top.ref_at(0).unwrap_or(0)).await?;
    let types = array(cx, file, spec.ref_at(0).unwrap_or(0)).await?;
    let cols = (0..types.size.min(MAX_COLUMNS))
        .filter(|&i| types.get(i) != Some(14))
        .count();
    let objects = cluster_count(cx, file, top.ref_at(2).unwrap_or(0))
        .await
        .unwrap_or(0);
    Ok((top.span, to_u64(cols), objects))
}

async fn table(cx: &Cx, file: Span, r: u64, keys: &[(Option<i64>, String)]) -> Result<Table> {
    let top = array(cx, file, r).await?;
    let spec = array(cx, file, top.ref_at(0).unwrap_or(0)).await?;
    let types = array(cx, file, spec.ref_at(0).unwrap_or(0)).await?;
    let names = array(cx, file, spec.ref_at(1).unwrap_or(0)).await?;
    let names = blobs(cx, file, &names, true, false, 0, 4096).await?;
    let attrs = array(cx, file, spec.ref_at(2).unwrap_or(0)).await?;
    let colkeys = match spec.ref_at(5) {
        Some(k) if k != 0 => Some(array(cx, file, k).await?),
        _ => None,
    };
    let targets = match top.ref_at(7) {
        Some(k) if k != 0 => Some(array(cx, file, k).await?),
        _ => None,
    };
    let mut columns = Vec::new();
    for i in 0..types.size.min(MAX_COLUMNS) {
        let kind = u64::try_from(types.get(i).unwrap_or(0)).unwrap_or(0);
        let name = names
            .items
            .get(to_usize(i))
            .and_then(|(n, _)| n.as_deref())
            .map(text_of)
            .unwrap_or_default();
        let target = targets
            .as_ref()
            .and_then(|t| t.get(i))
            .and_then(|k| keys.iter().find(|(key, _)| *key == Some(k)))
            .map(|(_, n)| n.strip_prefix("class_").unwrap_or(n).to_owned());
        columns.push(Column {
            name,
            kind,
            attrs: u64::try_from(attrs.get(i).unwrap_or(0)).unwrap_or(0),
            key: colkeys
                .as_ref()
                .and_then(|k| k.get(i))
                .and_then(|v| u64::try_from(v).ok())
                .unwrap_or(0),
            index: i,
            target,
        });
    }
    let pk = untag(top.get(11)).and_then(|v| u64::try_from(v).ok());
    Ok(Table {
        key: untag(top.get(3)),
        columns,
        cluster: top.ref_at(2).unwrap_or(0),
        pk,
    })
}

/// Objects in a cluster tree: a leaf's key count, or an inner node's
/// recorded tree size.
async fn cluster_count(cx: &Cx, file: Span, r: u64) -> Result<u64> {
    if r == 0 {
        return Ok(0);
    }
    let a = array(cx, file, r).await?;
    let n = if a.inner {
        untag(a.get(2)).unwrap_or(0)
    } else {
        match a.get(0) {
            Some(v) if v & 1 == 1 => v >> 1,
            Some(v) if v > 0 => {
                let keys = array(cx, file, u64::try_from(v).unwrap_or(0)).await?;
                i64::try_from(keys.size).unwrap_or(0)
            }
            _ => 0,
        }
    };
    Ok(u64::try_from(n).unwrap_or(0))
}

type TableState = (Span, u64, Arc<String>, Arc<Vec<(Option<i64>, String)>>);

async fn table_x(cx: Cx, (file, r, _name, keys): TableState) -> Result<()> {
    let t = Arc::new(table(&cx, file, r, &keys).await?);
    let top = array(&cx, file, r).await?;
    cx.emit(
        Node::new("Top array")
            .span(top.span)
            .summary(top.describe())
            .lazy(slots, (file, r, TABLE_SLOTS)),
    );
    cx.emit(
        Node::new("Table key")
            .span(top.elem_span(3))
            .value(t.key.map_or(Value::Text("none".into()), |k| Value::Int {
                value: k,
                bits: 64,
            })),
    );
    let mut cols = Vec::new();
    for c in t.columns.iter() {
        let (set, unknown) = decode_flags(ATTRS, c.attrs);
        let mut ty = lookup(COLUMN_TYPES, c.kind).unwrap_or("?").to_owned();
        if c.attrs & LIST != 0 {
            ty = format!("list of {ty}");
        } else if c.attrs & 64 != 0 {
            ty = format!("dictionary of {ty}");
        } else if c.attrs & 128 != 0 {
            ty = format!("set of {ty}");
        }
        if let Some(target) = &c.target
            && c.kind == 12
        {
            ty = format!("{ty} → {target}");
        }
        if c.attrs & NULLABLE != 0 {
            ty.push('?');
        }
        let name = if c.kind == 14 {
            format!("(backlink from {})", c.target.clone().unwrap_or_default())
        } else {
            c.name.clone()
        };
        let mut n = Node::new(name).value(text(ty));
        let mut kids = vec![
            Node::new("Type").value(Value::Enum {
                raw: c.kind,
                bits: 8,
                name: lookup(COLUMN_TYPES, c.kind),
            }),
            Node::new("Attributes").value(Value::Flags {
                raw: c.attrs,
                bits: 16,
                set,
                unknown,
            }),
            Node::new("Column key")
                .value(hex(c.key, 64))
                .summary(format!("index {}, tag {}", c.key & 0xffff, c.key >> 30)),
        ];
        if t.pk == Some(c.key) && c.kind != 14 {
            n = n.summary("primary key");
            kids.push(Node::new("Primary key").value(Value::Bool(true)));
        }
        cols.push(n.lazy(emit_all, Arc::new(kids)));
    }
    let shown = cols.len();
    cx.emit(
        Node::new("Columns")
            .summary(plural(to_u64(shown), "column", "columns"))
            .lazy(emit_all, Arc::new(cols)),
    );
    if t.cluster != 0 {
        let a = array(&cx, file, t.cluster).await?;
        cx.emit(
            Node::new("Objects")
                .span(a.span)
                .summary(a.describe())
                .lazy(objects, (file, t.cluster, 0i64, t.clone(), Path::new())),
        );
    }
    Ok(())
}

type ClusterState = (Span, u64, i64, Arc<Table>, Path);

/// The objects of a cluster (leaf) or the child clusters of an inner node.
async fn objects(cx: Cx, (file, r, offset, t, path): ClusterState) -> Result<()> {
    let a = array(&cx, file, r).await?;
    let path = path.enter(r, MAX_DEPTH)?;
    if a.inner {
        // Keys (offsets of the children, or none when they are dense),
        // the sub-tree depth, the tree size, then the children.
        let keys = match a.ref_at(0) {
            Some(k) if k != 0 => Some(array(&cx, file, k).await?),
            _ => None,
        };
        let mut next = offset;
        let children = if a.width == 0 {
            0
        } else {
            a.size.min(MAX_CLUSTER.saturating_add(3))
        };
        for i in 3..children {
            let Some(child) = a.ref_at(i) else { continue };
            let start = match keys.as_ref().and_then(|k| k.get(i.saturating_sub(3))) {
                Some(k) => offset.saturating_add(k),
                None => next,
            };
            let count = cluster_count(&cx, file, child).await.unwrap_or(0);
            next = start.saturating_add(i64::try_from(count).unwrap_or(0));
            cx.push(
                Node::new(format!("Cluster {}", i.saturating_sub(3)))
                    .span(a.elem_span(i))
                    .summary(format!(
                        "keys {start}–{}, {}",
                        next.saturating_sub(1),
                        plural(count, "object", "objects")
                    ))
                    .lazy(
                        crate::expander!(self::objects: ClusterState),
                        (file, child, start, t.clone(), path.clone()),
                    ),
            )
            .await;
        }
        return Ok(());
    }
    // Leaf: keys, then one array per column.
    let (count, keys) = match a.get(0) {
        Some(v) if v & 1 == 1 => (u64::try_from(v >> 1).unwrap_or(0), None),
        Some(v) if v > 0 => {
            let k = array(&cx, file, u64::try_from(v).unwrap_or(0)).await?;
            (k.size, Some(k))
        }
        _ => (0, None),
    };
    if count > MAX_CLUSTER {
        cx.diag(Diagnostic::malformed(format!(
            "implausible cluster of {count} objects"
        )));
    }
    let count = count.min(MAX_CLUSTER);
    cx.set_count(Count::Exact(count));
    let mut cols = Vec::new();
    for c in t.columns.iter().take(MAX_VALUES) {
        let r = a.ref_at(c.index.saturating_add(1)).unwrap_or(0);
        let arr = if r == 0 || c.kind == 14 {
            None
        } else {
            array(&cx, file, r).await.ok()
        };
        cols.push(arr);
    }
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < count {
        let at = i;
        cx.mark(move || at);
        let key = match keys.as_ref() {
            Some(k) => k.get(i).unwrap_or(0),
            None => i64::try_from(i).unwrap_or(0),
        };
        let key = offset.saturating_add(key);
        if cx.skipping() {
            cx.push(Node::new("")).await;
            i = i.saturating_add(1);
            continue;
        }
        let mut values = Vec::new();
        let mut shown = Vec::new();
        for (c, arr) in t.columns.iter().zip(cols.iter()) {
            if c.kind == 14 {
                continue;
            }
            let Some(arr) = arr else {
                values.push(Node::new(c.name.clone()).value(text("(empty)")));
                continue;
            };
            let n = value(&cx, file, c, arr, i).await;
            if shown.len() < 4
                && let Some(v) = &n.value
            {
                shown.push(format!("{}={}", c.name, short(v)));
            }
            values.push(n);
        }
        cx.push(
            Node::new(format!("#{key}"))
                .summary(shown.join(", "))
                .lazy(emit_all, Arc::new(values)),
        )
        .await;
        i = i.saturating_add(1);
    }
    Ok(())
}

fn short(v: &Value) -> String {
    let s = crate::render::value(v);
    if s.chars().count() > 24 {
        let cut: String = s.chars().take(24).collect();
        format!("{cut}…")
    } else {
        s
    }
}

/// The value of column `c` for the object at `i` in its leaf's array.
async fn value(cx: &Cx, file: Span, c: &Column, a: &Arr, i: u64) -> Node {
    let node = Node::new(c.name.clone());
    match scalar_or_list(cx, file, c, a, i).await {
        Ok(n) => n,
        Err(e) => node.diag(e),
    }
}

async fn scalar_or_list(cx: &Cx, file: Span, c: &Column, a: &Arr, i: u64) -> Result<Node> {
    let node = Node::new(c.name.clone()).span(a.elem_span(i));
    if c.attrs & COLLECTION != 0 {
        if c.attrs & LIST == 0 {
            return Ok(node.diag(Diagnostic::unsupported(
                "sets and dictionaries are not decoded",
            )));
        }
        let r = a.ref_at(i).unwrap_or(0);
        if r == 0 {
            return Ok(node.value(text("[]")).summary("empty list"));
        }
        let list = array(cx, file, r).await?;
        if list.inner {
            return Ok(node.span(list.span).summary("list (B+tree)").diag(
                Diagnostic::unsupported("lists spanning several leaves are not decoded"),
            ));
        }
        let mut items = Vec::new();
        let mut shown = Vec::new();
        let elem = Column {
            attrs: c.attrs & NULLABLE,
            ..c.clone()
        };
        for k in 0..list.size.min(LIST_SHOWN) {
            let n = element(cx, file, &elem, &list, k, true).await?;
            if let Some(v) = &n.value {
                shown.push(short(v));
            }
            items.push(n.renamed(format!("[{k}]")));
        }
        let mut summary = plural(list.size, "element", "elements");
        if list.size > LIST_SHOWN {
            summary.push_str(&format!(" ({LIST_SHOWN} shown)"));
        }
        return Ok(node
            .value(text(format!("[{}]", shown.join(", "))))
            .summary(summary)
            .lazy(emit_all, Arc::new(items)));
    }
    element(cx, file, c, a, i, false).await
}

/// Element `i` of a leaf array holding values of `c`'s type. List leaves
/// of nullable values use the same encodings as columns.
async fn element(cx: &Cx, file: Span, c: &Column, a: &Arr, i: u64, in_list: bool) -> Result<Node> {
    let node = Node::new(c.name.clone()).span(a.elem_span(i));
    let nullable = c.attrs & NULLABLE != 0;
    Ok(match c.kind {
        0 | 1 => {
            // Nullable integers keep the null sentinel in element 0.
            let v = if nullable {
                let sentinel = a.get(0);
                let v = a.get(i.saturating_add(1));
                let span = a.elem_span(i.saturating_add(1));
                return Ok(if v == sentinel || v.is_none() {
                    Node::new(c.name.clone()).span(span).summary("null")
                } else {
                    let v = v.unwrap_or(0);
                    Node::new(c.name.clone()).span(span).value(if c.kind == 1 {
                        Value::Bool(v != 0)
                    } else {
                        Value::Int { value: v, bits: 64 }
                    })
                });
            } else {
                a.get(i)
            };
            let v = v.ok_or_else(|| Diagnostic::malformed("value outside its array"))?;
            node.value(if c.kind == 1 {
                Value::Bool(v != 0)
            } else {
                Value::Int { value: v, bits: 64 }
            })
        }
        2 | 4 => {
            let b = blobs(cx, file, a, c.kind == 2, nullable, i, i.saturating_add(1)).await?;
            match b.items.first() {
                Some((Some(d), span)) => {
                    let n = Node::new(c.name.clone()).span(*span);
                    if c.kind == 2 {
                        n.value(text(text_of(d)))
                    } else {
                        n.value(Value::Bytes(d.get(..64).unwrap_or(d).to_vec()))
                            .summary(plural(to_u64(d.len()), "byte", "bytes"))
                    }
                }
                Some((None, span)) => Node::new(c.name.clone()).span(*span).summary("null"),
                None => node.diag(Diagnostic::malformed("value outside its array")),
            }
        }
        9 | 10 => {
            let w = if c.kind == 9 { 4 } else { 8 };
            let start = to_usize(i.saturating_mul(w));
            let b = a
                .data
                .get(start..start.saturating_add(to_usize(w)))
                .unwrap_or_default();
            let v = if c.kind == 9 {
                f64::from(f32::from_le_bytes(b.try_into().unwrap_or_default()))
            } else {
                f64::from_le_bytes(b.try_into().unwrap_or_default())
            };
            node.span(a.body().sub(i.saturating_mul(w), w))
                .value(Value::Float(v))
        }
        8 => {
            // A timestamp column is an array of two: seconds (nullable
            // integers) and nanoseconds.
            let secs = array(cx, file, a.ref_at(0).unwrap_or(0)).await?;
            let s = secs.get(i.saturating_add(1));
            if s == secs.get(0) || s.is_none() {
                Node::new(c.name.clone())
                    .span(secs.elem_span(i.saturating_add(1)))
                    .summary("null")
            } else {
                Node::new(c.name.clone())
                    .span(secs.elem_span(i.saturating_add(1)))
                    .value(Value::Timestamp {
                        unix_seconds: s.unwrap_or(0),
                    })
            }
        }
        12 => {
            // Links store the target key plus one (0 is null); in lists,
            // the key itself.
            let v = a
                .get(i)
                .ok_or_else(|| Diagnostic::malformed("value outside its array"))?;
            let key = if in_list {
                Some(v)
            } else {
                v.checked_sub(1).filter(|_| v != 0)
            };
            let target = c.target.clone().unwrap_or_else(|| "object".to_owned());
            match key {
                Some(k) => node.value(text(format!("{target} #{k}"))),
                None => node.summary("null"),
            }
        }
        _ => node.diag(Diagnostic::unsupported(format!(
            "{} values are not decoded",
            lookup(COLUMN_TYPES, c.kind).unwrap_or("these")
        ))),
    })
}
