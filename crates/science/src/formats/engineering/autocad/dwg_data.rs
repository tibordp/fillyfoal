//! The contents of DWG sections: header variables (raw), classes, the
//! object map and the objects it locates (type and handle), preview
//! images, summary info and application info.
//!
//! Layouts are from memory of the ODA specification and libredwg (see the
//! notes in `dwg`): the classes of R2010 and later keep their strings in a
//! separate string stream at the end of the data, located backwards from a
//! bit size; the object map is a series of big-endian sized blocks of
//! (handle delta, location delta) modular-char pairs, each block starting
//! from zero; each object starts with its size (`MS`), then its type and
//! its own handle.

use std::collections::BTreeMap;
use std::sync::Arc;

use super::bits::{Bits, modular_char, modular_short};
use super::dwg::{Drawing, Kind, Ver};
use crate::bytes::{to_u64, to_usize, u16_be, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::val::{hex, uint};
use crate::formats::{Input, embedded, embedded_as};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::Value;

const LE: Endian = Endian::Little;

pub const SENTINEL_HEADER: [u8; 16] = [
    0xcf, 0x7b, 0x1f, 0x23, 0xfd, 0xde, 0x38, 0xa9, 0x5f, 0x7c, 0x68, 0xb8, 0x4e, 0x6d, 0x33, 0x5f,
];
pub const SENTINEL_HEADER_END: [u8; 16] = [
    0x30, 0x84, 0xe0, 0xdc, 0x02, 0x21, 0xc7, 0x56, 0xa0, 0x83, 0x97, 0x47, 0xb1, 0x92, 0xcc, 0xa0,
];
pub const SENTINEL_CLASSES: [u8; 16] = [
    0x8d, 0xa1, 0xc4, 0xb8, 0xc4, 0xa9, 0xf8, 0xc5, 0xc0, 0xdc, 0xf4, 0x5f, 0xe7, 0xcf, 0xb6, 0x8a,
];
pub const SENTINEL_CLASSES_END: [u8; 16] = [
    0x72, 0x5e, 0x3b, 0x47, 0x3b, 0x56, 0x07, 0x3a, 0x3f, 0x23, 0x0b, 0xa0, 0x18, 0x30, 0x49, 0x75,
];
pub const SENTINEL_PREVIEW: [u8; 16] = [
    0x1f, 0x25, 0x6d, 0x07, 0xd4, 0x36, 0x28, 0x28, 0x9d, 0x57, 0xca, 0x3f, 0x9d, 0x44, 0x10, 0x2b,
];
pub const SENTINEL_PREVIEW_END: [u8; 16] = [
    0xe0, 0xda, 0x92, 0xf8, 0x2b, 0xc9, 0xd7, 0xd7, 0x62, 0xa8, 0x35, 0xc0, 0x62, 0xbb, 0xef, 0xd4,
];

/// The span of bits `from..to` of `base` (whole bytes).
fn bit_span(base: Span, from: u64, to: u64) -> Span {
    let start = from >> 3;
    base.sub(start, to.div_ceil(8).saturating_sub(start).max(1))
}

fn sentinel_check(want: [u8; 16]) -> impl FnOnce(&Vec<u8>) -> Option<Diagnostic> {
    move |got| (got.as_slice() != want).then(|| Diagnostic::warning("unexpected sentinel"))
}

/// Whether a size field is followed by a high size (R2010+ with a
/// maintenance release above 3, and R2018).
fn has_high_size(d: &Drawing) -> bool {
    d.ver >= Ver::R2018 || (d.ver >= Ver::R2010 && d.maint > 3)
}

// ---------------------------------------------------------------------------
// Header variables

pub async fn header_vars(cx: &Cx, d: &Drawing, data: Span) -> Result<()> {
    let high = has_high_size(d);
    let start = if high { 24 } else { 20 };
    let head = cx.block(data.sub(0, start)).await?;
    let mut f = Fields::emitting(cx, &head, LE);
    f.bytes("Sentinel", 16)
        .check(sentinel_check(SENTINEL_HEADER))
        .emit()?;
    let size = u64::from(f.u32("Size").hex().emit()?);
    if high {
        f.u32("High size").hex().emit()?;
    }
    let vars = data.sub(start, size);
    cx.emit(
        Node::new("Variables")
            .span(vars)
            .summary(format!("{size:#x} bytes, bit-coded"))
            .desc("The header variables ($ACADVER, $EXTMIN, ...) are not decoded"),
    );
    let tail = cx.block(data.sub(start.saturating_add(size), 18)).await?;
    let mut f = Fields::emitting(cx, &tail, LE);
    f.u16("CRC").hex().emit()?;
    f.bytes("End sentinel", 16)
        .check(sentinel_check(SENTINEL_HEADER_END))
        .emit()?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Classes

/// A decoded field of a bit-coded record: name, value, bit range.
type BitField = (&'static str, Value, u64, u64);

#[derive(Clone, Debug)]
pub struct Class {
    pub number: u16,
    pub dxf: String,
    pub cpp: String,
    pub app: String,
    pub item: u16,
    pub start: u64,
    pub end: u64,
    pub fields: Vec<BitField>,
    /// Bit ranges are of the main stream; strings of the string stream.
    pub string_fields: Vec<BitField>,
}

#[derive(Debug, Default)]
pub struct Classes {
    pub list: Vec<Class>,
    /// Class number to its first index in `list`.
    pub index: BTreeMap<u16, usize>,
    pub header: Vec<BitField>,
    /// Byte offset of the CRC.
    pub end: u64,
    pub error: Option<Diagnostic>,
}

impl Classes {
    pub fn name(&self, number: u16) -> Option<&str> {
        self.list
            .get(*self.index.get(&number)?)
            .map(|c| c.dxf.as_str())
    }
}

async fn parse_classes(cx: &Cx, data: &[u8], ver: Ver, high: bool) -> Classes {
    let mut out = Classes::default();
    let size = u64::from(u32_le(data, 16).unwrap_or(0));
    let area = if high { 24u64 } else { 20 };
    out.end = area.saturating_add(size);
    let end_bit = out.end.saturating_mul(8);
    let bytes = data.get(..to_usize(out.end)).unwrap_or(data);
    let mut r = Bits::new(bytes, area.saturating_mul(8));
    // R2010+: strings come from a string stream at the end of the data.
    let mut strings: Option<Bits<'_>> = None;
    if ver >= Ver::R2007 {
        let at = r.pos;
        let Some(bitsize) = r.rl() else {
            out.error = Some(Diagnostic::truncated(Span::zeros(0), 0));
            return out;
        };
        out.header.push(("Bit size", uint(bitsize, 64), at, r.pos));
        strings = string_stream(bytes, area.saturating_mul(8), u64::from(bitsize));
        if strings.is_none() {
            out.error = Some(Diagnostic::malformed("no string stream"));
        }
    }
    let mut count = None;
    if ver >= Ver::R2004 {
        let at = r.pos;
        let max = r.bs();
        let zero1 = r.rc();
        let zero2 = r.rc();
        let flag = r.b();
        let (Some(max), Some(_), Some(_), Some(_)) = (max, zero1, zero2, flag) else {
            out.error = Some(Diagnostic::malformed("classes header truncated"));
            return out;
        };
        out.header
            .push(("Maximum class number", uint(max, 64), at, r.pos));
        count = Some(usize::from(max.saturating_sub(499)));
    }
    loop {
        cx.checkpoint().await;
        match count {
            Some(n) if out.list.len() >= n => break,
            // Without a count: until fewer bits than the smallest class
            // remain.
            None if r.pos.saturating_add(32) > end_bit => break,
            _ => {}
        }
        let start = r.pos;
        let mut fields = Vec::new();
        let mut string_fields = Vec::new();
        let parsed = read_class(&mut r, &mut strings, ver, &mut fields, &mut string_fields);
        let Some((number, app, cpp, dxf, item)) = parsed else {
            out.error = Some(Diagnostic::malformed(format!(
                "class {} is truncated or malformed",
                out.list.len()
            )));
            break;
        };
        if r.pos > end_bit {
            out.error = Some(Diagnostic::malformed("classes overrun their section"));
            break;
        }
        out.index.entry(number).or_insert(out.list.len());
        out.list.push(Class {
            number,
            dxf,
            cpp,
            app,
            item,
            start,
            end: r.pos,
            fields,
            string_fields,
        });
    }
    out
}

/// A text field: from the string stream if there is one (R2007+), else
/// inline.
fn text_field(
    r: &mut Bits<'_>,
    strings: &mut Option<Bits<'_>>,
    name: &'static str,
    fields: &mut Vec<BitField>,
    string_fields: &mut Vec<BitField>,
) -> Option<String> {
    match strings {
        Some(s) => {
            let at = s.pos;
            let v = s.tu()?;
            string_fields.push((name, Value::Text(v.clone()), at, s.pos));
            Some(v)
        }
        None => {
            let at = r.pos;
            let v = r.tv()?;
            fields.push((name, Value::Text(v.clone()), at, r.pos));
            Some(v)
        }
    }
}

/// One class: (number, application, C++ class, DXF name, item class ID).
fn read_class(
    r: &mut Bits<'_>,
    strings: &mut Option<Bits<'_>>,
    ver: Ver,
    fields: &mut Vec<BitField>,
    string_fields: &mut Vec<BitField>,
) -> Option<(u16, String, String, String, u16)> {
    let at = r.pos;
    let number = r.bs()?;
    fields.push(("Class number", uint(number, 64), at, r.pos));
    let at = r.pos;
    let proxy = r.bs()?;
    fields.push(("Proxy flags", hex(proxy, 64), at, r.pos));
    let app = text_field(r, strings, "Application", fields, string_fields)?;
    let cpp = text_field(r, strings, "C++ class", fields, string_fields)?;
    let dxf = text_field(r, strings, "DXF name", fields, string_fields)?;
    let at = r.pos;
    let zombie = r.b()?;
    fields.push(("Was a zombie", Value::Bool(zombie), at, r.pos));
    let at = r.pos;
    let item = r.bs()?;
    fields.push((
        "Item class ID",
        Value::Enum {
            raw: item.into(),
            bits: 16,
            name: match item {
                0x1f2 => Some("entity"),
                0x1f3 => Some("object"),
                _ => None,
            },
        },
        at,
        r.pos,
    ));
    if ver >= Ver::R2004 {
        for name in [
            "Instances",
            "DWG version",
            "Maintenance version",
            "Unknown",
            "Unknown",
        ] {
            let at = r.pos;
            let v = r.bl()?;
            fields.push((name, uint(v, 64), at, r.pos));
        }
    }
    Some((number, app, cpp, dxf, item))
}

/// The string stream of an R2007+ bit-coded record whose data starts at
/// bit `area` and whose `bitsize` ends with the stream's presence flag.
fn string_stream(data: &[u8], area: u64, bitsize: u64) -> Option<Bits<'_>> {
    let flag_at = area.checked_add(bitsize)?.checked_sub(1)?;
    let mut r = Bits::new(data, flag_at);
    if !r.b()? {
        return None;
    }
    let mut at = flag_at.checked_sub(16)?;
    r.pos = at;
    let mut size = u64::from(r.rs()?);
    if size & 0x8000 != 0 {
        at = at.checked_sub(16)?;
        r.pos = at;
        let hi = u64::from(r.rs()?);
        size = (size & 0x7fff) | hi << 15;
    }
    Some(Bits::new(data, at.checked_sub(size)?))
}

async fn load_classes(cx: &Cx, d: &Drawing) -> Option<Arc<Classes>> {
    let s = d.find(Kind::Classes)?;
    if let Some(found) = cx.cached::<Classes>(s.data, "dwg-classes") {
        return Some(found);
    }
    let max = cx.limits().max_read;
    let data = cx.read_avail(s.data.sub(0, max)).await.ok()?;
    let classes = Arc::new(parse_classes(cx, &data, d.ver, has_high_size(d)).await);
    cx.cache(s.data, "dwg-classes", classes.clone());
    Some(classes)
}

fn bit_nodes(base: Span, fields: &[BitField]) -> Vec<Node> {
    fields
        .iter()
        .map(|(name, value, from, to)| {
            Node::new(*name)
                .span(bit_span(base, *from, *to))
                .value(value.clone())
        })
        .collect()
}

pub async fn classes_node(cx: &Cx, d: &Drawing, data: Span) -> Result<()> {
    let high = has_high_size(d);
    let head = cx.block(data.sub(0, if high { 24 } else { 20 })).await?;
    let mut f = Fields::emitting(cx, &head, LE);
    f.bytes("Sentinel", 16)
        .check(sentinel_check(SENTINEL_CLASSES))
        .emit()?;
    f.u32("Size").hex().emit()?;
    if high {
        f.u32("High size").hex().emit()?;
    }
    let classes = load_classes(cx, d)
        .await
        .ok_or_else(|| Diagnostic::malformed("classes unreadable"))?;
    for node in bit_nodes(data, &classes.header) {
        cx.emit(node);
    }
    for (i, class) in classes.list.iter().enumerate() {
        cx.checkpoint().await;
        let kind = match class.item {
            0x1f2 => "entity",
            0x1f3 => "object",
            _ => "class",
        };
        cx.emit(
            Node::new(class.dxf.clone())
                .span(bit_span(data, class.start, class.end))
                .value(Value::Text(class.cpp.clone()))
                .summary(format!("{kind} {}, {}", class.number, class.app))
                .lazy(class_fields, (data, classes.clone(), i)),
        );
    }
    if let Some(e) = &classes.error {
        cx.diag(e.clone());
    }
    let tail = cx.block(data.sub(classes.end, 18)).await?;
    let mut f = Fields::emitting(cx, &tail, LE);
    f.u16("CRC").hex().emit()?;
    f.bytes("End sentinel", 16)
        .check(sentinel_check(SENTINEL_CLASSES_END))
        .emit()?;
    cx.annotate(format!("{} classes", classes.list.len()));
    Ok(())
}

async fn class_fields(cx: Cx, (data, classes, i): (Span, Arc<Classes>, usize)) -> Result<()> {
    let class = classes
        .list
        .get(i)
        .ok_or_else(|| Diagnostic::internal("no such class"))?;
    for node in bit_nodes(data, &class.fields) {
        cx.emit(node);
    }
    for node in bit_nodes(data, &class.string_fields) {
        cx.emit(node.desc("From the string stream"));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Object map

#[derive(Debug, Default)]
pub struct ObjectMap {
    /// (handle, location).
    pub entries: Vec<(u64, i64)>,
    /// (span, first entry, entry count, CRC).
    pub blocks: Vec<(Span, usize, usize)>,
    pub error: Option<Diagnostic>,
}

async fn parse_map(cx: &Cx, data: &[u8], span: Span) -> ObjectMap {
    let mut out = ObjectMap::default();
    let mut pos = 0usize;
    loop {
        cx.checkpoint().await;
        let Some(size) = u16_be(data, pos) else {
            out.error = Some(Diagnostic::malformed(
                "object map ends without its final block",
            ));
            break;
        };
        let size = usize::from(size);
        let first = out.entries.len();
        if size <= 2 {
            out.blocks.push((span.sub(to_u64(pos), 4), first, 0));
            break;
        }
        let end = pos.saturating_add(size);
        let mut p = pos.saturating_add(2);
        let (mut handle, mut loc) = (0u64, 0i64);
        while p < end {
            let rest = data.get(p..end).unwrap_or_default();
            let Some((dh, n1)) = modular_char(rest, false) else {
                break;
            };
            let Some((dl, n2)) = modular_char(rest.get(n1..).unwrap_or_default(), true) else {
                break;
            };
            handle = handle.saturating_add(u64::try_from(dh).unwrap_or(0));
            loc = loc.saturating_add(dl);
            out.entries.push((handle, loc));
            p = p.saturating_add(n1).saturating_add(n2);
        }
        out.blocks.push((
            span.sub(to_u64(pos), to_u64(size.saturating_add(2))),
            first,
            out.entries.len().saturating_sub(first),
        ));
        if p != end {
            out.error = Some(Diagnostic::malformed(
                "object map block ends inside an entry",
            ));
            break;
        }
        pos = end.saturating_add(2);
    }
    out
}

async fn load_map(cx: &Cx, data: Span) -> Result<Arc<ObjectMap>> {
    if let Some(found) = cx.cached::<ObjectMap>(data, "dwg-object-map") {
        return Ok(found);
    }
    let max = cx.limits().max_read;
    let bytes = cx.read_avail(data.sub(0, max)).await?;
    let mut map = parse_map(cx, &bytes, data).await;
    if to_u64(bytes.len()) < data.len && map.error.is_some() {
        map.error = Some(Diagnostic::limit(
            "only the beginning of the object map was read",
        ));
    }
    let map = Arc::new(map);
    cx.cache(data, "dwg-object-map", map.clone());
    Ok(map)
}

pub async fn object_map(cx: &Cx, data: Span) -> Result<()> {
    let map = load_map(cx, data).await?;
    cx.annotate(format!("{} objects", map.entries.len()));
    if let Some(e) = &map.error {
        cx.diag(e.clone());
    }
    cx.set_count(Count::Exact(to_u64(map.blocks.len())));
    for (i, &(span, first, count)) in map.blocks.iter().enumerate() {
        let summary = if count == 0 {
            "end".to_owned()
        } else {
            format!("{count} entries")
        };
        cx.push(
            Node::new(format!("Block {i}"))
                .span(span)
                .summary(summary)
                .lazy(map_block, (span, map.clone(), first, count)),
        )
        .await;
    }
    Ok(())
}

async fn map_block(
    cx: Cx,
    (span, map, first, count): (Span, Arc<ObjectMap>, usize, usize),
) -> Result<()> {
    let bytes = cx.read(span).await?;
    cx.emit(
        Node::new("Size")
            .span(span.sub(0, 2))
            .value(uint(u16_be(&bytes, 0).unwrap_or(0), 64))
            .desc("Big-endian, counting itself"),
    );
    let mut pos = 2usize;
    for &(handle, loc) in map.entries.iter().skip(first).take(count) {
        let rest = bytes.get(pos..).unwrap_or_default();
        let n1 = modular_char(rest, false).map_or(1, |(_, n)| n);
        let n2 = modular_char(rest.get(n1..).unwrap_or_default(), true).map_or(1, |(_, n)| n);
        let len = n1.saturating_add(n2);
        cx.push(
            Node::new(format!("Handle {handle:#X}"))
                .span(span.sub(to_u64(pos), to_u64(len)))
                .value(match u64::try_from(loc) {
                    Ok(v) => hex(v, 64),
                    Err(_) => Value::Int {
                        value: loc,
                        bits: 64,
                    },
                })
                .summary("location"),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    cx.push(
        Node::new("CRC")
            .span(span.sub(to_u64(pos), 2))
            .value(hex(u16_be(&bytes, pos).unwrap_or(0), 64)),
    )
    .await;
    Ok(())
}

// ---------------------------------------------------------------------------
// Objects

/// Fixed object types (the ODA spec's table).
const OBJECT_TYPES: &[(u16, &str)] = &[
    (0x00, "UNUSED"),
    (0x01, "TEXT"),
    (0x02, "ATTRIB"),
    (0x03, "ATTDEF"),
    (0x04, "BLOCK"),
    (0x05, "ENDBLK"),
    (0x06, "SEQEND"),
    (0x07, "INSERT"),
    (0x08, "MINSERT"),
    (0x0a, "VERTEX_2D"),
    (0x0b, "VERTEX_3D"),
    (0x0c, "VERTEX_MESH"),
    (0x0d, "VERTEX_PFACE"),
    (0x0e, "VERTEX_PFACE_FACE"),
    (0x0f, "POLYLINE_2D"),
    (0x10, "POLYLINE_3D"),
    (0x11, "ARC"),
    (0x12, "CIRCLE"),
    (0x13, "LINE"),
    (0x14, "DIMENSION_ORDINATE"),
    (0x15, "DIMENSION_LINEAR"),
    (0x16, "DIMENSION_ALIGNED"),
    (0x17, "DIMENSION_ANG3PT"),
    (0x18, "DIMENSION_ANG2LN"),
    (0x19, "DIMENSION_RADIUS"),
    (0x1a, "DIMENSION_DIAMETER"),
    (0x1b, "POINT"),
    (0x1c, "3DFACE"),
    (0x1d, "POLYLINE_PFACE"),
    (0x1e, "POLYLINE_MESH"),
    (0x1f, "SOLID"),
    (0x20, "TRACE"),
    (0x21, "SHAPE"),
    (0x22, "VIEWPORT"),
    (0x23, "ELLIPSE"),
    (0x24, "SPLINE"),
    (0x25, "REGION"),
    (0x26, "3DSOLID"),
    (0x27, "BODY"),
    (0x28, "RAY"),
    (0x29, "XLINE"),
    (0x2a, "DICTIONARY"),
    (0x2b, "OLEFRAME"),
    (0x2c, "MTEXT"),
    (0x2d, "LEADER"),
    (0x2e, "TOLERANCE"),
    (0x2f, "MLINE"),
    (0x30, "BLOCK_CONTROL"),
    (0x31, "BLOCK_HEADER"),
    (0x32, "LAYER_CONTROL"),
    (0x33, "LAYER"),
    (0x34, "STYLE_CONTROL"),
    (0x35, "STYLE"),
    (0x38, "LTYPE_CONTROL"),
    (0x39, "LTYPE"),
    (0x3c, "VIEW_CONTROL"),
    (0x3d, "VIEW"),
    (0x3e, "UCS_CONTROL"),
    (0x3f, "UCS"),
    (0x40, "VPORT_CONTROL"),
    (0x41, "VPORT"),
    (0x42, "APPID_CONTROL"),
    (0x43, "APPID"),
    (0x44, "DIMSTYLE_CONTROL"),
    (0x45, "DIMSTYLE"),
    (0x46, "VX_CONTROL"),
    (0x47, "VX_TABLE_RECORD"),
    (0x48, "GROUP"),
    (0x49, "MLINESTYLE"),
    (0x4a, "OLE2FRAME"),
    (0x4b, "DUMMY"),
    (0x4c, "LONG_TRANSACTION"),
    (0x4d, "LWPOLYLINE"),
    (0x4e, "HATCH"),
    (0x4f, "XRECORD"),
    (0x50, "ACDBPLACEHOLDER"),
    (0x51, "VBA_PROJECT"),
    (0x52, "LAYOUT"),
    (0x1f2, "ACAD_PROXY_ENTITY"),
    (0x1f3, "ACAD_PROXY_OBJECT"),
];

fn type_name(t: u16, classes: Option<&Classes>) -> String {
    if let Some((_, name)) = OBJECT_TYPES.iter().find(|(n, _)| *n == t) {
        return (*name).to_owned();
    }
    if t >= 500
        && let Some(name) = classes.and_then(|c| c.name(t))
    {
        return name.to_owned();
    }
    format!("type {t}")
}

/// The start of an object.
#[derive(Clone, Debug)]
struct ObjectHead {
    /// Bytes of the `MS` size, and the size (without the CRC).
    ms_len: usize,
    size: u64,
    /// R2010+: the handle stream size in bits, and the bytes of its `UMC`.
    hsize: Option<(u64, usize)>,
    fields: Vec<BitField>,
    kind: Option<u16>,
    handle: Option<u64>,
}

fn parse_object(bytes: &[u8], ver: Ver) -> Option<ObjectHead> {
    let (size, ms_len) = modular_short(bytes)?;
    let mut at = ms_len;
    let mut hsize = None;
    if ver >= Ver::R2010 {
        let (h, n) = modular_char(bytes.get(at..)?, false)?;
        hsize = Some((u64::try_from(h).unwrap_or(0), n));
        at = at.saturating_add(n);
    }
    let mut head = ObjectHead {
        ms_len,
        size,
        hsize,
        fields: Vec::new(),
        kind: None,
        handle: None,
    };
    let mut r = Bits::new(bytes, to_u64(at).saturating_mul(8));
    let from = r.pos;
    let kind = if ver >= Ver::R2010 { r.ot() } else { r.bs() };
    let Some(kind) = kind else {
        return Some(head);
    };
    head.kind = Some(kind);
    head.fields.push(("Type", uint(kind, 64), from, r.pos));
    if (Ver::R2000..Ver::R2010).contains(&ver) {
        let from = r.pos;
        let Some(bits) = r.rl() else {
            return Some(head);
        };
        head.fields
            .push(("Data size in bits", uint(bits, 64), from, r.pos));
    }
    let from = r.pos;
    if let Some((_, handle)) = r.h() {
        head.handle = Some(handle);
        head.fields.push(("Handle", hex(handle, 64), from, r.pos));
    }
    Some(head)
}

pub async fn objects(cx: Cx, d: Arc<Drawing>) -> Result<()> {
    let handles = d
        .find(Kind::Handles)
        .ok_or_else(|| Diagnostic::malformed("no object map"))?;
    let base = d
        .objects()
        .ok_or_else(|| Diagnostic::malformed("no objects section"))?;
    let map = load_map(&cx, handles.data).await?;
    let classes = load_classes(&cx, &d).await;
    cx.annotate(format!("{} objects", map.entries.len()));
    let extra = if d.ver >= Ver::R2004 { 2 } else { 1 };
    cx.set_count(Count::Exact(
        to_u64(map.entries.len()).saturating_add(extra),
    ));
    cx.push(
        Node::new("Types")
            .desc("Objects counted by type")
            .lazy(object_types, d.clone()),
    )
    .await;
    if d.ver >= Ver::R2004 {
        // Not in the object map: the section's 4-byte signature.
        let sig = if cx.skipping() {
            Vec::new()
        } else {
            cx.read_avail(base.sub(0, 4)).await?
        };
        cx.push(
            Node::new("Signature")
                .span(base.sub(0, 4))
                .value(hex(u32_le(&sig, 0).unwrap_or(0), 64)),
        )
        .await;
    }
    for &(handle, loc) in &map.entries {
        if cx.skipping() {
            cx.push(Node::new("")).await;
            continue;
        }
        let node = object_node(&cx, &d, base, classes.as_deref(), handle, loc).await?;
        cx.push(node).await;
    }
    Ok(())
}

async fn object_node(
    cx: &Cx,
    d: &Arc<Drawing>,
    base: Span,
    classes: Option<&Classes>,
    handle: u64,
    loc: i64,
) -> Result<Node> {
    let Ok(at) = u64::try_from(loc) else {
        return Ok(Node::new(format!("Handle {handle:#X}"))
            .diag(Diagnostic::malformed(format!("negative location {loc}"))));
    };
    if at >= base.len {
        return Ok(
            Node::new(format!("Handle {handle:#X}")).diag(Diagnostic::malformed(format!(
                "location {at:#x} is outside the objects"
            ))),
        );
    }
    let bytes = cx.read_avail(base.sub(at, 32)).await?;
    let Some(head) = parse_object(&bytes, d.ver) else {
        return Ok(Node::new(format!("Handle {handle:#X}"))
            .span(base.sub(at, 2))
            .diag(Diagnostic::malformed("unreadable object size")));
    };
    let hlen = head.hsize.map_or(0, |(_, n)| n);
    let len = to_u64(head.ms_len)
        .saturating_add(to_u64(hlen))
        .saturating_add(head.size)
        .saturating_add(2);
    let span = base.sub(at, len);
    let name = head
        .kind
        .map_or_else(|| "object".to_owned(), |k| type_name(k, classes));
    let mut node = Node::new(name)
        .span(span)
        .summary(format!("handle {handle:#X}, {:#x} bytes", head.size))
        .lazy(object_fields, (span, d.ver, handle));
    if let Some(own) = head.handle
        && own != handle
    {
        node = node.diag(Diagnostic::warning(format!(
            "the object's own handle is {own:#X}"
        )));
    }
    if span.len < len {
        node = node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, len),
            span.len,
        ));
    }
    Ok(node)
}

async fn object_fields(cx: Cx, (span, ver, _handle): (Span, Ver, u64)) -> Result<()> {
    let bytes = cx.read_avail(span.sub(0, 32)).await?;
    let head = parse_object(&bytes, ver).ok_or_else(|| Diagnostic::malformed("bad object"))?;
    cx.emit(
        Node::new("Size")
            .span(span.sub(0, to_u64(head.ms_len)))
            .value(uint(head.size, 64))
            .desc("MS: bytes of object data, without the CRC"),
    );
    let mut data_start = to_u64(head.ms_len);
    if let Some((h, n)) = head.hsize {
        cx.emit(
            Node::new("Handle stream size")
                .span(span.sub(data_start, to_u64(n)))
                .value(uint(h, 64))
                .desc("UMC, in bits"),
        );
        data_start = data_start.saturating_add(to_u64(n));
    }
    for node in bit_nodes(span, &head.fields) {
        cx.emit(node);
    }
    cx.emit(
        Node::new("Data")
            .span(span.sub(data_start, head.size))
            .desc("Bit-coded object data (not decoded beyond type and handle)"),
    );
    let crc_at = data_start.saturating_add(head.size);
    let crc = cx.read_avail(span.sub(crc_at, 2)).await?;
    if let Some(v) = u16_le(&crc, 0) {
        cx.emit(Node::new("CRC").span(span.sub(crc_at, 2)).value(hex(v, 64)));
    }
    Ok(())
}

async fn object_types(cx: Cx, d: Arc<Drawing>) -> Result<()> {
    let handles = d
        .find(Kind::Handles)
        .ok_or_else(|| Diagnostic::malformed("no object map"))?;
    let base = d
        .objects()
        .ok_or_else(|| Diagnostic::malformed("no objects section"))?;
    let map = load_map(&cx, handles.data).await?;
    let classes = load_classes(&cx, &d).await;
    let mut counts: BTreeMap<String, u64> = BTreeMap::new();
    for &(_, loc) in &map.entries {
        let Ok(at) = u64::try_from(loc) else {
            continue;
        };
        let bytes = cx.read_avail(base.sub(at, 16)).await?;
        let name = parse_object(&bytes, d.ver)
            .and_then(|h| h.kind)
            .map_or_else(
                || "(unreadable)".to_owned(),
                |k| type_name(k, classes.as_deref()),
            );
        let n = counts.entry(name).or_insert(0);
        *n = n.saturating_add(1);
    }
    let mut sorted: Vec<(String, u64)> = counts.into_iter().collect();
    sorted.sort_by(|a, b| b.1.cmp(&a.1).then_with(|| a.0.cmp(&b.0)));
    cx.annotate(format!("{} types", sorted.len()));
    for (name, n) in sorted {
        cx.push(Node::new(name).value(uint(n, 64))).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Preview

const PREVIEW_CODES: &[(u64, &str)] = &[(1, "header"), (2, "BMP"), (3, "WMF"), (6, "PNG")];

pub async fn preview(cx: &Cx, d: &Drawing, span: Span, base: u64) -> Result<()> {
    let head = cx.block(span.sub(0, 21)).await?;
    let mut f = Fields::emitting(cx, &head, LE);
    f.bytes("Sentinel", 16)
        .check(sentinel_check(SENTINEL_PREVIEW))
        .emit()?;
    let size = u64::from(f.u32("Size").hex().emit()?);
    let count = u64::from(f.u8("Image count").emit()?);
    let dir = cx
        .read(span.sub_exact(21, count.saturating_mul(9))?)
        .await?;
    let mut entries = Vec::new();
    for (i, e) in dir.as_chunks::<9>().0.iter().enumerate() {
        let code = e.first().copied().unwrap_or(0);
        let start = u64::from(u32_le(e, 1).unwrap_or(0));
        let len = u64::from(u32_le(e, 5).unwrap_or(0));
        entries.push((code, start, len));
        let entry = span.sub(21u64.saturating_add(to_u64(i).saturating_mul(9)), 9);
        let kind = crate::value::lookup(PREVIEW_CODES, code.into()).unwrap_or("unknown");
        cx.emit(
            Node::new(format!("Entry {i}"))
                .span(entry)
                .summary(format!("{kind}, {len:#x} bytes at {start:#x}"))
                .lazy(preview_entry, entry),
        );
    }
    // Addresses are file offsets; inside the section they are relative to
    // the sentinel at `base`. If they do not fit, the images are taken to
    // follow the directory in order.
    let data_start = 21u64.saturating_add(count.saturating_mul(9));
    let fits = entries.iter().all(|&(_, start, len)| {
        start
            .checked_sub(base)
            .is_some_and(|rel| rel >= data_start && rel.saturating_add(len) <= span.len)
    });
    let mut next = data_start;
    for &(code, start, len) in &entries {
        let rel = if fits {
            start.saturating_sub(base)
        } else {
            next
        };
        next = rel.saturating_add(len);
        let image = span.sub(rel, len);
        let node = match code {
            1 => Node::new("Header data").span(image),
            2 => bmp_node(cx, &d.input, image).await?,
            3 => embedded("WMF image", d.input.nested(image)),
            6 => embedded("PNG image", d.input.nested(image)),
            _ => Node::new(format!("Image (code {code})")).span(image),
        };
        cx.emit(node);
    }
    let end = 20u64.saturating_add(size);
    let tail = cx.block(span.sub(end, 16)).await?;
    let mut f = Fields::emitting(cx, &tail, LE);
    f.bytes("End sentinel", 16)
        .check(sentinel_check(SENTINEL_PREVIEW_END))
        .emit()?;
    Ok(())
}

async fn preview_entry(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    f.u8("Code").enumeration(PREVIEW_CODES).emit()?;
    f.u32("Address").hex().emit()?;
    f.u32("Size").hex().emit()?;
    Ok(())
}

/// A headerless DIB, given a `BITMAPFILEHEADER` so the BMP dissector (and
/// any viewer) takes it as a file.
pub(crate) async fn bmp_node(cx: &Cx, input: &Input, dib: Span) -> Result<Node> {
    let info = cx.read_avail(dib.sub(0, 40)).await?;
    let header_size = u64::from(u32_le(&info, 0).unwrap_or(40));
    let bit_count = u16_le(&info, 14).unwrap_or(0);
    let compression = u32_le(&info, 16).unwrap_or(0);
    let used = u64::from(u32_le(&info, 32).unwrap_or(0));
    let colors = if used != 0 {
        used
    } else if bit_count <= 8 {
        1u64 << bit_count
    } else {
        0
    };
    let masks = if compression == 3 && header_size == 40 {
        12
    } else {
        0
    };
    let offset = 14u64
        .saturating_add(header_size)
        .saturating_add(colors.saturating_mul(4))
        .saturating_add(masks);
    let total = dib.len.saturating_add(14);
    let mut fh = b"BM".to_vec();
    fh.extend_from_slice(&u32::try_from(total).unwrap_or(u32::MAX).to_le_bytes());
    fh.extend_from_slice(&[0; 4]);
    fh.extend_from_slice(&u32::try_from(offset).unwrap_or(u32::MAX).to_le_bytes());
    let header = cx.add_derived(
        Origin {
            parent: dib,
            transform: "bmp-file-header",
        },
        fh,
        0,
        None,
    )?;
    let file = cx.add_pieces(
        Origin {
            parent: dib,
            transform: "bmp-file",
        },
        vec![header.span, dib],
    )?;
    Ok(embedded_as(
        "BMP image",
        input.nested(file),
        &crate::formats::image::bmp::FORMAT,
    )
    .desc("A DIB; the 14-byte file header is supplied"))
}

// ---------------------------------------------------------------------------
// Summary info and application info (R2004+)

/// Reads a length-prefixed string: an `RS` count of bytes (R2004) or of
/// UTF-16 code units (R2007+), the terminating NUL included.
fn string_at(data: &[u8], pos: usize, wide: bool) -> Option<(String, usize)> {
    let n = usize::from(u16_le(data, pos)?);
    let bytes = n.checked_mul(if wide { 2 } else { 1 })?;
    let body = data.get(pos.checked_add(2)?..pos.checked_add(2)?.checked_add(bytes)?)?;
    let text = if wide {
        let mut units: Vec<u16> = body
            .as_chunks::<2>()
            .0
            .iter()
            .map(|&c| u16::from_le_bytes(c))
            .collect();
        while units.last() == Some(&0) {
            units.pop();
        }
        String::from_utf16_lossy(&units)
    } else {
        crate::text::until_nul(body)
    };
    Some((text, bytes.saturating_add(2)))
}

/// Julian day number and milliseconds of the day, as Unix seconds.
fn julian(day: u32, ms: u32) -> i64 {
    i64::from(day)
        .saturating_sub(crate::formats::util::civil::UNIX_JULIAN_DAY)
        .saturating_mul(86_400)
        .saturating_add(i64::from(ms / 1000))
}

struct Reader<'a> {
    data: &'a [u8],
    span: Span,
    pos: usize,
    wide: bool,
}

impl Reader<'_> {
    fn string(&mut self, name: &'static str) -> Option<Node> {
        let (text, len) = string_at(self.data, self.pos, self.wide)?;
        let node = Node::new(name)
            .span(self.span.sub(to_u64(self.pos), to_u64(len)))
            .value(Value::Text(text));
        self.pos = self.pos.saturating_add(len);
        Some(node)
    }

    fn string_value(&mut self) -> Option<(String, Span)> {
        let (text, len) = string_at(self.data, self.pos, self.wide)?;
        let span = self.span.sub(to_u64(self.pos), to_u64(len));
        self.pos = self.pos.saturating_add(len);
        Some((text, span))
    }

    fn u32(&mut self) -> Option<(u32, Span)> {
        let v = u32_le(self.data, self.pos)?;
        let span = self.span.sub(to_u64(self.pos), 4);
        self.pos = self.pos.saturating_add(4);
        Some((v, span))
    }

    fn u16(&mut self) -> Option<(u16, Span)> {
        let v = u16_le(self.data, self.pos)?;
        let span = self.span.sub(to_u64(self.pos), 2);
        self.pos = self.pos.saturating_add(2);
        Some((v, span))
    }

    fn date(&mut self, name: &'static str) -> Option<Node> {
        let (day, a) = self.u32()?;
        let (ms, _) = self.u32()?;
        Some(
            Node::new(name)
                .span(Span::new(a.source, a.offset, 8))
                .value(Value::Timestamp {
                    unix_seconds: julian(day, ms),
                })
                .desc("Julian day and milliseconds"),
        )
    }

    fn bytes(&mut self, name: &'static str, n: usize) -> Option<Node> {
        let b = self.data.get(self.pos..self.pos.checked_add(n)?)?;
        let node = Node::new(name)
            .span(self.span.sub(to_u64(self.pos), to_u64(n)))
            .value(Value::Bytes(b.to_vec()));
        self.pos = self.pos.saturating_add(n);
        Some(node)
    }
}

async fn small_section(cx: &Cx, data: Span) -> Result<Vec<u8>> {
    let max = cx.limits().max_read.min(1 << 20);
    cx.read_avail(data.sub(0, max)).await
}

pub async fn summary_info(cx: &Cx, d: &Drawing, data: Span) -> Result<()> {
    let bytes = small_section(cx, data).await?;
    let mut r = Reader {
        data: &bytes,
        span: data,
        pos: 0,
        wide: d.ver >= Ver::R2007,
    };
    let truncated = || Diagnostic::malformed("summary info truncated");
    let mut title = None;
    for name in [
        "Title",
        "Subject",
        "Author",
        "Keywords",
        "Comments",
        "Last saved by",
        "Revision number",
        "Hyperlink base",
    ] {
        let node = r.string(name).ok_or_else(truncated)?;
        if name == "Title"
            && let Some(Value::Text(t)) = &node.value
            && !t.is_empty()
        {
            title = Some(t.clone());
        }
        cx.emit(node);
    }
    let (days, a) = r.u32().ok_or_else(truncated)?;
    let (ms, _) = r.u32().ok_or_else(truncated)?;
    let secs = ms / 1000;
    cx.emit(
        Node::new("Total editing time")
            .span(Span::new(a.source, a.offset, 8))
            .value(uint(days, 64))
            .summary(format!(
                "{days} days, {:02}:{:02}:{:02}",
                secs / 3600,
                secs / 60 % 60,
                secs % 60
            )),
    );
    cx.emit(r.date("Created").ok_or_else(truncated)?);
    cx.emit(r.date("Modified").ok_or_else(truncated)?);
    let (count, span) = r.u16().ok_or_else(truncated)?;
    cx.emit(
        Node::new("Custom properties")
            .span(span)
            .value(uint(count, 64)),
    );
    for _ in 0..count {
        let (name, a) = r.string_value().ok_or_else(truncated)?;
        let (value, b) = r.string_value().ok_or_else(truncated)?;
        cx.emit(
            Node::new(name)
                .span(Span::new(
                    a.source,
                    a.offset,
                    b.end().saturating_sub(a.offset),
                ))
                .value(Value::Text(value)),
        );
    }
    for _ in 0..2 {
        if let Some((v, span)) = r.u32() {
            cx.emit(Node::new("Unknown").span(span).value(hex(v, 64)));
        }
    }
    if let Some(t) = title {
        cx.annotate(format!("\"{t}\""));
    }
    Ok(())
}

pub async fn app_info(cx: &Cx, d: &Drawing, data: Span) -> Result<()> {
    let bytes = small_section(cx, data).await?;
    let wide = d.ver >= Ver::R2007;
    let mut r = Reader {
        data: &bytes,
        span: data,
        pos: 0,
        wide,
    };
    let truncated = || Diagnostic::malformed("application info truncated");
    let (v, span) = r.u32().ok_or_else(truncated)?;
    cx.emit(Node::new("Unknown").span(span).value(uint(v, 64)));
    cx.emit(r.string("Name").ok_or_else(truncated)?);
    let (v, span) = r.u32().ok_or_else(truncated)?;
    cx.emit(Node::new("Unknown").span(span).value(uint(v, 64)));
    let mut product = None;
    for name in ["Version", "Comment", "Product"] {
        if wide {
            cx.emit(r.bytes("Checksum", 16).ok_or_else(truncated)?);
        }
        let node = r.string(name).ok_or_else(truncated)?;
        if name == "Product"
            && let Some(Value::Text(t)) = &node.value
        {
            product = Some(t.clone());
        }
        cx.emit(node);
    }
    if let Some(p) = product.as_deref().and_then(product_name) {
        cx.annotate(p);
    }
    Ok(())
}

/// The `name` and `build_version` attributes of the product XML
/// (`<ProductInformation name ="AutoCAD" build_version="..." ...>`).
fn product_name(xml: &str) -> Option<String> {
    let attr = |key: &str| -> Option<String> {
        let mut from = 0usize;
        while let Some(found) = xml.get(from..)?.find(key) {
            let at = from.saturating_add(found);
            from = at.saturating_add(key.len());
            let before = xml.get(..at)?.chars().next_back();
            if before.is_some_and(|c| !c.is_whitespace()) {
                continue;
            }
            let rest = xml.get(from..)?.trim_start();
            let Some(rest) = rest.strip_prefix('=') else {
                continue;
            };
            let rest = rest.trim_start().strip_prefix('"')?;
            return Some(rest.get(..rest.find('"')?)?.to_owned());
        }
        None
    };
    let name = attr("name")?;
    Some(match attr("build_version") {
        Some(b) => format!("{name} {b}"),
        None => name,
    })
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::*;

    #[test]
    fn julian_dates() {
        // JD 2440588 is 1970-01-01; noon is 43_200_000 ms.
        assert_eq!(julian(2_440_588, 43_200_000), 43_200);
        assert_eq!(julian(2_451_545, 0), 946_684_800);
    }

    #[test]
    fn product() {
        assert_eq!(
            product_name(r#"<ProductInformation name ="AutoCAD" build_version="R24.1" />"#)
                .as_deref(),
            Some("AutoCAD R24.1")
        );
        assert_eq!(
            product_name(r#"<ProductInformation name="AutoCAD" build_version="R24.1"/>"#)
                .as_deref(),
            Some("AutoCAD R24.1")
        );
    }
}
