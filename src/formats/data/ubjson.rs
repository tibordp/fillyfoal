//! Universal Binary JSON (UBJSON, Draft 12; `.ubj`): JSON's data model
//! with one-byte type markers (`Z` null, `N` no-op, `T`/`F`, `i U I l L`
//! integers, `d D` floats, `H` high-precision number, `C` char, `S`
//! string, `[ ]` arrays, `{ }` objects), big-endian numbers, and lengths
//! written as integers with their own marker. Containers are either closed
//! by an end marker or "optimized": `#` and a count (no end marker),
//! optionally preceded by `$` and a type that every element shares (the
//! elements then carry no marker; `[$U#` is how byte arrays are written).
//!
//! UBJSON has no magic number. The probe accepts only a file the probe
//! window holds entirely that parses, to its last byte, as one object with
//! at least one entry, all keys and strings valid UTF-8 and the top-level
//! keys free of control characters. JSON text cannot pass (`{"` or `{` and
//! whitespace is not a valid key length), nor RTF (`{\`). Other files are
//! reached through the extension ("inspect as").

use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, be_uint};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::valuetree as vt;

pub static FORMAT: Format = Format {
    name: "ubjson",
    title: "Universal Binary JSON",
    extensions: &["ubj", "ubjson"],
    mime: "application/ubjson",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Most typed elements of a payload-less type (`$Z`, `$T`, ...) listed.
const MAX_EMPTY_ELEMENTS: u64 = 1000;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Null,
    NoOp,
    Bool(bool),
    /// Integer of this many bytes, signed or not.
    Int(u8, bool),
    Float32,
    Float64,
    Char,
    Str,
    HighPrecision,
    Array,
    Object,
}

#[derive(Clone, Copy, Debug)]
struct Item {
    kind: Kind,
    /// Bytes before the payload (marker, length, container parameters).
    head: u64,
    /// Integer bits, float bits, string length, or container count.
    arg: u64,
    /// Optimized containers: the element type and count.
    elem: Option<u8>,
    count: Option<u64>,
}

impl Item {
    fn payload(&self) -> u64 {
        match self.kind {
            Kind::Str | Kind::HighPrecision => self.arg,
            _ => 0,
        }
    }
}

enum Bad {
    Short,
    Malformed(String),
}

/// Width in bytes of a fixed-size value of type `m`, if it has one.
fn fixed_width(m: u8) -> Option<u64> {
    Some(match m {
        b'Z' | b'N' | b'T' | b'F' => 0,
        b'i' | b'U' | b'C' => 1,
        b'I' => 2,
        b'l' | b'd' => 4,
        b'L' | b'D' => 8,
        _ => return None,
    })
}

/// An integer `(value, bytes)` with its marker at the start of `b`, for
/// lengths and counts (which must not be negative).
fn length(b: &[u8]) -> std::result::Result<(u64, u64), Bad> {
    let m = *b.first().ok_or(Bad::Short)?;
    let (n, signed) = match m {
        b'i' => (1usize, true),
        b'U' => (1, false),
        b'I' => (2, true),
        b'l' => (4, true),
        b'L' => (8, true),
        _ => {
            return Err(Bad::Malformed(format!(
                "length marker {} is not an integer type",
                show(m)
            )));
        }
    };
    let raw = b.get(1..n.saturating_add(1)).ok_or(Bad::Short)?;
    let v = be_uint(raw);
    if signed && raw.first().is_some_and(|&x| x & 0x80 != 0) {
        return Err(Bad::Malformed("negative length".to_owned()));
    }
    Ok((v, u64::try_from(n).unwrap_or(0).saturating_add(1)))
}

fn show(m: u8) -> String {
    if m.is_ascii_graphic() {
        format!("'{}'", char::from(m))
    } else {
        format!("{m:#04x}")
    }
}

/// Decodes the value header at the start of `b`; `typed` is the element
/// type of an optimized container (the value then has no marker).
fn decode(b: &[u8], typed: Option<u8>) -> std::result::Result<Item, Bad> {
    let (m, rest, mut head) = match typed {
        Some(t) => (t, b, 0u64),
        None => (
            *b.first().ok_or(Bad::Short)?,
            b.get(1..).unwrap_or_default(),
            1,
        ),
    };
    let item = |kind, head, arg| Item {
        kind,
        head,
        arg,
        elem: None,
        count: None,
    };
    let int = |n: usize, signed: bool| -> std::result::Result<Item, Bad> {
        let raw = rest.get(..n).ok_or(Bad::Short)?;
        Ok(item(
            Kind::Int(u8::try_from(n).unwrap_or(8), signed),
            head.saturating_add(u64::try_from(n).unwrap_or(0)),
            be_uint(raw),
        ))
    };
    Ok(match m {
        b'Z' => item(Kind::Null, head, 0),
        b'N' => item(Kind::NoOp, head, 0),
        b'T' | b'F' => item(Kind::Bool(m == b'T'), head, 0),
        b'i' => int(1, true)?,
        b'U' => int(1, false)?,
        b'I' => int(2, true)?,
        b'l' => int(4, true)?,
        b'L' => int(8, true)?,
        b'd' => item(
            Kind::Float32,
            head.saturating_add(4),
            be_uint(rest.get(..4).ok_or(Bad::Short)?),
        ),
        b'D' => item(
            Kind::Float64,
            head.saturating_add(8),
            be_uint(rest.get(..8).ok_or(Bad::Short)?),
        ),
        b'C' => item(
            Kind::Char,
            head.saturating_add(1),
            u64::from(*rest.first().ok_or(Bad::Short)?),
        ),
        b'S' | b'H' => {
            let (len, n) = length(rest)?;
            let kind = if m == b'S' {
                Kind::Str
            } else {
                Kind::HighPrecision
            };
            item(kind, head.saturating_add(n), len)
        }
        b'[' | b'{' => {
            let kind = if m == b'[' { Kind::Array } else { Kind::Object };
            let mut it = item(kind, head, 0);
            let mut p = rest;
            if p.first() == Some(&b'$') {
                let t = *p.get(1).ok_or(Bad::Short)?;
                if fixed_width(t).is_none() && !matches!(t, b'S' | b'H' | b'[' | b'{') {
                    return Err(Bad::Malformed(format!("unknown element type {}", show(t))));
                }
                it.elem = Some(t);
                p = p.get(2..).unwrap_or_default();
                head = head.saturating_add(2);
                if p.is_empty() {
                    return Err(Bad::Short);
                }
                if p.first() != Some(&b'#') {
                    return Err(Bad::Malformed(
                        "element type ('$') without a count ('#')".to_owned(),
                    ));
                }
            }
            if p.first() == Some(&b'#') {
                let (count, n) = length(p.get(1..).unwrap_or_default())?;
                it.count = Some(count);
                it.arg = count;
                head = head.saturating_add(n).saturating_add(1);
            }
            it.head = head;
            it
        }
        _ => return Err(Bad::Malformed(format!("unknown type marker {}", show(m)))),
    })
}

/// The header of the value at `at` (12 bytes cover the longest one).
async fn head(r: &mut ByteReader<'_>, at: u64, typed: Option<u8>) -> Result<Item> {
    let avail = r.region().len.saturating_sub(at).min(12);
    let b = r.bytes(at, avail).await?;
    match decode(&b, typed) {
        Ok(item) => Ok(item),
        Err(Bad::Short) => Err(Diagnostic::truncated(r.span(at, 12), avail)),
        Err(Bad::Malformed(m)) => Err(Diagnostic::malformed(m).at(r.span(at, 1))),
    }
}

/// An object key at `at`: `(text length, bytes before the text)`.
async fn key_head(r: &mut ByteReader<'_>, at: u64) -> Result<(u64, u64)> {
    let avail = r.region().len.saturating_sub(at).min(9);
    let b = r.bytes(at, avail).await?;
    match length(&b) {
        Ok(v) => Ok(v),
        Err(Bad::Short) => Err(Diagnostic::truncated(r.span(at, 9), avail)),
        Err(Bad::Malformed(m)) => {
            Err(Diagnostic::malformed(format!("object key: {m}")).at(r.span(at, 1)))
        }
    }
}

/// A container being scanned.
struct Frame {
    /// Entries left, or `None` until the end marker.
    left: Option<u64>,
    elem: Option<u8>,
    object: bool,
}

/// The end of the value at `at` (scanning nested values).
async fn end_of(r: &mut ByteReader<'_>, at: u64, typed: Option<u8>) -> Result<u64> {
    let len = r.region().len;
    let mut stack: Vec<Frame> = Vec::new();
    let mut pos = at;
    let mut first = true;
    loop {
        r.cx().checkpoint().await;
        let elem = if first {
            first = false;
            typed
        } else {
            let Some(top) = stack.last_mut() else {
                return Ok(pos);
            };
            match top.left {
                Some(0) => {
                    stack.pop();
                    continue;
                }
                Some(ref mut n) => *n = n.saturating_sub(1),
                None => {
                    let b = r.byte(pos).await?;
                    if b == if top.object { b'}' } else { b']' } {
                        pos = pos.saturating_add(1);
                        stack.pop();
                        continue;
                    }
                    if b == b'N' {
                        pos = pos.saturating_add(1);
                        continue;
                    }
                }
            }
            if top.object {
                let (klen, n) = key_head(r, pos).await?;
                pos = pos.saturating_add(n).saturating_add(klen);
            }
            top.elem
        };
        let h = head(r, pos, elem).await?;
        let body = pos.saturating_add(h.head);
        pos = body.saturating_add(h.payload());
        if pos > len {
            return Err(Diagnostic::truncated(
                r.span(body, h.payload()),
                len.saturating_sub(body),
            ));
        }
        if let Some(n) = h.count
            && let Some(w) = h.elem.and_then(fixed_width)
            && h.kind == Kind::Array
        {
            // Fixed-size elements: skip them all at once.
            let size = n.saturating_mul(w);
            if size > len.saturating_sub(pos) {
                return Err(Diagnostic::truncated(
                    r.span(pos, size),
                    len.saturating_sub(pos),
                ));
            }
            pos = pos.saturating_add(size);
        } else if matches!(h.kind, Kind::Array | Kind::Object) {
            if h.count.is_some_and(|n| n > len.saturating_sub(pos)) {
                return Err(Diagnostic::malformed(format!(
                    "{} entries do not fit in the remaining {} bytes",
                    h.arg,
                    len.saturating_sub(pos)
                ))
                .at(r.span(pos, 1)));
            }
            if stack.len() >= vt::MAX_DEPTH {
                return Err(Diagnostic::limit(format!(
                    "values nested deeper than {}",
                    vt::MAX_DEPTH
                ))
                .at(r.span(pos, 1)));
            }
            stack.push(Frame {
                left: h.count,
                elem: h.elem,
                object: h.kind == Kind::Object,
            });
        }
        if stack.is_empty() {
            return Ok(pos);
        }
    }
}

/// Synchronous validation for the probe: the end of the value at `pos`.
fn skip(b: &[u8], pos: usize, typed: Option<u8>, depth: usize, keys_text: bool) -> Option<usize> {
    if depth > 32 {
        return None;
    }
    let h = decode(b.get(pos..)?, typed).ok()?;
    let body = pos.checked_add(usize::try_from(h.head).ok()?)?;
    let end = body.checked_add(usize::try_from(h.payload()).ok()?)?;
    match h.kind {
        Kind::NoOp => None,
        Kind::Str | Kind::HighPrecision => {
            std::str::from_utf8(b.get(body..end)?).ok()?;
            Some(end)
        }
        Kind::Array | Kind::Object => {
            let object = h.kind == Kind::Object;
            let mut p = end;
            let mut i = 0u64;
            loop {
                match h.count {
                    Some(n) if i >= n => break,
                    Some(_) => {}
                    None => {
                        while b.get(p) == Some(&b'N') {
                            p = p.checked_add(1)?;
                        }
                        let c = *b.get(p)?;
                        if c == if object { b'}' } else { b']' } {
                            p = p.checked_add(1)?;
                            break;
                        }
                    }
                }
                if object {
                    let (klen, n) = length(b.get(p..)?).ok()?;
                    let kb = p.checked_add(usize::try_from(n).ok()?)?;
                    let ke = kb.checked_add(usize::try_from(klen).ok()?)?;
                    let key = std::str::from_utf8(b.get(kb..ke)?).ok()?;
                    if keys_text && (key.is_empty() || key.chars().any(char::is_control)) {
                        return None;
                    }
                    p = ke;
                }
                p = skip(b, p, h.elem, depth.checked_add(1)?, false)?;
                i = i.checked_add(1)?;
            }
            (!object || i > 0 || !keys_text).then_some(p)
        }
        _ => (end <= b.len()).then_some(end),
    }
}

fn probe(h: &Head<'_>) -> bool {
    u64::try_from(h.data.len()).is_ok_and(|n| n == h.len)
        && h.data.first() == Some(&b'{')
        && h.len >= 4
        && skip(h.data, 0, None, 0, true) == Some(h.data.len())
}

fn describe(h: &Item) -> String {
    let typed = match h.elem {
        Some(t) => format!(" of {}", type_name(t)),
        None => String::new(),
    };
    match h.kind {
        Kind::Array => format!("{}{typed}", vt::array_summary("array", h.count)),
        Kind::Object => format!(
            "{}{typed}",
            vt::map_summary("object", h.count, "member", "members")
        ),
        _ => type_name_of(h.kind).to_owned(),
    }
}

fn type_name_of(kind: Kind) -> &'static str {
    match kind {
        Kind::Null => "null",
        Kind::NoOp => "no-op",
        Kind::Bool(_) => "boolean",
        Kind::Int(..) => "integer",
        Kind::Float32 | Kind::Float64 => "float",
        Kind::Char => "char",
        Kind::Str => "string",
        Kind::HighPrecision => "high-precision number",
        Kind::Array => "array",
        Kind::Object => "object",
    }
}

fn type_name(m: u8) -> &'static str {
    match m {
        b'Z' => "null",
        b'N' => "no-op",
        b'T' => "true",
        b'F' => "false",
        b'i' => "int8",
        b'U' => "uint8",
        b'I' => "int16",
        b'l' => "int32",
        b'L' => "int64",
        b'd' => "float32",
        b'D' => "float64",
        b'C' => "char",
        b'S' => "string",
        b'H' => "high-precision",
        b'[' => "array",
        b'{' => "object",
        _ => "?",
    }
}

/// Skips no-op markers between values.
async fn skip_noops(r: &mut ByteReader<'_>, mut pos: u64) -> Result<u64> {
    while pos < r.region().len && r.byte(pos).await? == b'N' {
        pos = pos.saturating_add(1);
    }
    Ok(pos)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let start = skip_noops(&mut r, 0).await?;
    let first = head(&mut r, start, None).await?;
    let whole = if matches!(first.kind, Kind::Array | Kind::Object) {
        match end_of(&mut r, start, None).await {
            Ok(end) => skip_noops(&mut r, end).await? == input.span.len,
            Err(_) => false,
        }
    } else {
        false
    };
    if whole {
        cx.annotate(format!("UBJSON {}", describe(&first)));
        return members(cx, (input.span, start, None, Path::new())).await;
    }
    cx.annotate(format!("UBJSON, first value: {}", describe(&first)));
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((start, 0));
    while pos < input.span.len {
        let at = (pos, index);
        cx.mark(move || at);
        let end = match end_of(&mut r, pos, None).await {
            Ok(end) => end,
            Err(d) => {
                cx.push(
                    Node::new(format!("[{index}]"))
                        .span(r.span(pos, input.span.len.saturating_sub(pos)))
                        .diag(d),
                )
                .await;
                break;
            }
        };
        let node = item_node(&mut r, pos, end, None, format!("[{index}]"), &Path::new()).await?;
        cx.push(node).await;
        pos = skip_noops(&mut r, end).await?;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// A node for the value at `start..end` (of type `typed` if it has no
/// marker of its own).
async fn item_node(
    r: &mut ByteReader<'_>,
    start: u64,
    end: u64,
    typed: Option<u8>,
    name: String,
    path: &Path,
) -> Result<Node> {
    let h = head(r, start, typed).await?;
    let node = Node::new(name).span(r.span(start, end.saturating_sub(start)));
    let body = start.saturating_add(h.head);
    Ok(match h.kind {
        Kind::Null => node.summary("null"),
        Kind::NoOp => node.summary("no-op"),
        Kind::Bool(b) => node.value(Value::Bool(b)),
        Kind::Int(n, signed) => {
            let bits = n.saturating_mul(8);
            if signed {
                let shift = 64u32.saturating_sub(u32::from(bits));
                let v = (h.arg.checked_shl(shift).unwrap_or(0) as i64)
                    .checked_shr(shift)
                    .unwrap_or(0);
                node.value(vt::int(v, bits))
            } else {
                node.value(vt::uint(h.arg, bits))
            }
        }
        Kind::Float32 => node.value(Value::Float(f64::from(f32::from_bits(
            u32::try_from(h.arg).unwrap_or(0),
        )))),
        Kind::Float64 => node.value(Value::Float(f64::from_bits(h.arg))),
        Kind::Char => {
            let c = u8::try_from(h.arg).unwrap_or(0);
            let node = node
                .value(Value::Text(char::from(c).to_string()))
                .summary("char");
            if c.is_ascii() {
                node
            } else {
                node.diag(Diagnostic::warning("char outside ASCII"))
            }
        }
        Kind::Str => {
            let data = r.bytes(body, h.arg.min(vt::MAX_TEXT)).await?;
            vt::text(node, &data, h.arg)
        }
        Kind::HighPrecision => {
            let data = r.bytes(body, h.arg.min(vt::MAX_TEXT)).await?;
            let node = vt::text(node, &data, h.arg);
            let number = std::str::from_utf8(&data).is_ok_and(|s| {
                !s.is_empty()
                    && s.bytes()
                        .all(|c| c.is_ascii_digit() || b"+-.eE".contains(&c))
            });
            let node = node.summary("high-precision number");
            if number {
                node
            } else {
                node.diag(Diagnostic::warning("not a JSON number"))
            }
        }
        Kind::Array | Kind::Object => {
            if h.elem == Some(b'U') && h.kind == Kind::Array {
                // `[$U#n`: how byte strings are written.
                let n = h.count.unwrap_or(0);
                let data = r.bytes(body, n.min(vt::MAX_BYTES)).await?;
                let node = vt::bytes(node, "uint8 array", data, n);
                return Ok(lazy_members(node, r.region(), start, typed, path));
            }
            let node = node.summary(describe(&h));
            if h.count == Some(0)
                || end.saturating_sub(start) <= h.head.saturating_add(1) && h.count.is_none()
            {
                node
            } else {
                lazy_members(node, r.region(), start, typed, path)
            }
        }
    })
}

fn lazy_members(node: Node, region: Span, start: u64, typed: Option<u8>, path: &Path) -> Node {
    match vt::enter(path, start) {
        Ok(p) => node.lazy(
            crate::expander!(self::members: (Span, u64, Option<u8>, Path)),
            (region, start, typed, p),
        ),
        Err(d) => node.diag(d),
    }
}

async fn members(
    cx: Cx,
    (region, start, typed, path): (Span, u64, Option<u8>, Path),
) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let h = head(&mut r, start, typed).await?;
    let object = h.kind == Kind::Object;
    if let Some(n) = h.count {
        cx.set_count(Count::Exact(n));
    }
    let empty_elements = h.elem.and_then(fixed_width) == Some(0);
    let (mut pos, mut index) = cx
        .resume::<(u64, u64)>()
        .unwrap_or((start.saturating_add(h.head), 0));
    loop {
        match h.count {
            Some(n) if index >= n => break,
            Some(n) if empty_elements && index >= MAX_EMPTY_ELEMENTS => {
                cx.push(Node::new("…").summary(format!("{} more", n.saturating_sub(index))))
                    .await;
                break;
            }
            Some(_) => {}
            None => {
                pos = skip_noops(&mut r, pos).await?;
                if r.byte(pos).await? == if object { b'}' } else { b']' } {
                    break;
                }
            }
        }
        let at = (pos, index);
        cx.mark(move || at);
        let name = if object {
            let (klen, n) = key_head(&mut r, pos).await?;
            let text = r.bytes(pos.saturating_add(n), klen.min(0x200)).await?;
            pos = pos.saturating_add(n).saturating_add(klen);
            vt::key_name(&String::from_utf8_lossy(&text), index)
        } else {
            format!("[{index}]")
        };
        let end = end_of(&mut r, pos, h.elem).await?;
        let node = item_node(&mut r, pos, end, h.elem, name, &path).await?;
        cx.push(node).await;
        pos = end;
        index = index.saturating_add(1);
    }
    Ok(())
}
