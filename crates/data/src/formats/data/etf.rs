//! Erlang external term format (`.etf`, `.term`; `term_to_binary/1`): the
//! version byte 131, then one term, each starting with a tag byte. Lists,
//! tuples and maps record their element count, not their size, so the end
//! of a term is found by scanning it; pids, ports and references hold
//! their node name (an atom term) followed by fixed fields. A compressed
//! term (`[compressed]`) is the tag 80, the uncompressed size and a zlib
//! stream.
//!
//! Terms shown: small and 32-bit integers, big integers (in decimal up to
//! 256 bytes), new and old (text) floats, atoms (Latin-1 and UTF-8, and
//! atom cache references), nil, strings (lists of bytes), lists (with an
//! improper tail), small and large tuples, maps, binaries, bit binaries,
//! pids, ports and references (old and new forms), export funs, local
//! funs (old and new forms, with their free variables). `LOCAL_EXT` (an
//! encoding private to one node) is not decodable.
//!
//! Layout written from memory of the OTP documentation ("External Term
//! Format", erts User's Guide), checked against files written by OTP 27.
//!
//! Probe (one weak byte): the version byte, then either a compressed term
//! whose size field is plausible and whose data starts with a valid zlib
//! header, or a term that parses with known tags and consistent lengths
//! exactly to the end of the file (when the probe window holds it all) or
//! through the whole window (at least 1 KiB of it) when the file is
//! larger. Anything else reaches the dissector by extension.

use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::{ByteReader, be_uint, hex};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

use super::valuetree as vt;

pub static FORMAT: Format = Format {
    name: "erlang-etf",
    title: "Erlang external term format",
    extensions: &["etf", "term"],
    mime: "application/x-erlang-binary",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

const VERSION: u8 = 131;

const TAGS: EnumTable = &[
    (70, "NEW_FLOAT_EXT"),
    (77, "BIT_BINARY_EXT"),
    (80, "COMPRESSED"),
    (82, "ATOM_CACHE_REF"),
    (88, "NEW_PID_EXT"),
    (89, "NEW_PORT_EXT"),
    (90, "NEWER_REFERENCE_EXT"),
    (97, "SMALL_INTEGER_EXT"),
    (98, "INTEGER_EXT"),
    (99, "FLOAT_EXT"),
    (100, "ATOM_EXT"),
    (101, "REFERENCE_EXT"),
    (102, "PORT_EXT"),
    (103, "PID_EXT"),
    (104, "SMALL_TUPLE_EXT"),
    (105, "LARGE_TUPLE_EXT"),
    (106, "NIL_EXT"),
    (107, "STRING_EXT"),
    (108, "LIST_EXT"),
    (109, "BINARY_EXT"),
    (110, "SMALL_BIG_EXT"),
    (111, "LARGE_BIG_EXT"),
    (112, "NEW_FUN_EXT"),
    (113, "EXPORT_EXT"),
    (114, "NEW_REFERENCE_EXT"),
    (115, "SMALL_ATOM_EXT"),
    (116, "MAP_EXT"),
    (117, "FUN_EXT"),
    (118, "ATOM_UTF8_EXT"),
    (119, "SMALL_ATOM_UTF8_EXT"),
    (120, "V4_PORT_EXT"),
    (121, "LOCAL_EXT"),
];

/// A term's framing: header bytes, payload bytes after them, nested terms
/// after the payload, and fixed bytes after the nested terms.
#[derive(Clone, Copy, Debug)]
struct Item {
    tag: u8,
    head: u64,
    payload: u64,
    nested: u64,
    trailer: u64,
}

/// Decodes the framing of the term at the start of `b` (`None`: an
/// unknown tag or `b` too short).
fn decode(b: &[u8]) -> Option<Item> {
    let tag = *b.first()?;
    let n = |at: usize, len: usize| -> Option<u64> { b.get(at..at.checked_add(len)?).map(be_uint) };
    let item = |head: u64, payload: u64, nested: u64, trailer: u64| {
        Some(Item {
            tag,
            head,
            payload,
            nested,
            trailer,
        })
    };
    match tag {
        70 => item(9, 0, 0, 0),
        77 => item(6, n(1, 4)?, 0, 0),
        82 | 97 => item(2, 0, 0, 0),
        98 => item(5, 0, 0, 0),
        99 => item(32, 0, 0, 0),
        88 => item(1, 0, 1, 12),
        89 => item(1, 0, 1, 8),
        120 => item(1, 0, 1, 12),
        101 | 102 => item(1, 0, 1, 5),
        103 => item(1, 0, 1, 9),
        90 => {
            let len = n(1, 2)?;
            item(3, 0, 1, len.checked_mul(4)?.checked_add(4)?)
        }
        114 => {
            let len = n(1, 2)?;
            item(3, 0, 1, len.checked_mul(4)?.checked_add(1)?)
        }
        100 | 107 | 118 => item(3, n(1, 2)?, 0, 0),
        115 | 119 => item(2, n(1, 1)?, 0, 0),
        104 => item(2, 0, n(1, 1)?, 0),
        105 => item(5, 0, n(1, 4)?, 0),
        106 => item(1, 0, 0, 0),
        108 => item(5, 0, n(1, 4)?.checked_add(1)?, 0),
        109 => item(5, n(1, 4)?, 0, 0),
        110 => item(3, n(1, 1)?, 0, 0),
        111 => item(6, n(1, 4)?, 0, 0),
        // The size counts itself and everything after the tag.
        112 => item(1, n(1, 4)?, 0, 0),
        113 => item(1, 0, 3, 0),
        116 => item(5, 0, n(1, 4)?.checked_mul(2)?, 0),
        117 => item(5, 0, n(1, 4)?.checked_add(4)?, 0),
        _ => None,
    }
}

/// Synchronous validation for the probe: the end of the term at `pos`
/// (`Err(true)`: the term runs past the end of `b`; `Err(false)`: invalid).
fn skip(b: &[u8], pos: usize, depth: usize) -> std::result::Result<usize, bool> {
    if depth > 64 {
        return Err(false);
    }
    let rest = b.get(pos..).ok_or(true)?;
    if rest.is_empty() {
        return Err(true);
    }
    let Some(it) = decode(rest) else {
        // Unknown tag, or a header cut by the end of `b`.
        return Err(
            rest.len() < 8 && lookup(TAGS, rest.first().copied().unwrap_or(0).into()).is_some()
        );
    };
    if matches!(it.tag, 80 | 82 | 121) {
        return Err(false);
    }
    let head_end = pos
        .checked_add(usize::try_from(it.head).map_err(|_| false)?)
        .ok_or(false)?;
    let payload = usize::try_from(it.payload).map_err(|_| false)?;
    let mut p = head_end.checked_add(payload).ok_or(false)?;
    let body = b.get(head_end..p.min(b.len())).unwrap_or_default();
    let cut = p > b.len();
    match it.tag {
        // Atoms: at most 255 characters; UTF-8 ones must be valid.
        118 | 119 if !cut => {
            if std::str::from_utf8(body).is_err() || payload > 1020 {
                return Err(false);
            }
        }
        100 | 115 if payload > 255 => return Err(false),
        77 => {
            let bits = rest.get(5).copied().unwrap_or(1);
            if !(1..=8).contains(&bits) || payload == 0 {
                return Err(false);
            }
        }
        110 | 111 => {
            if rest
                .get(usize::try_from(it.head).unwrap_or(0).saturating_sub(1))
                .is_some_and(|&s| s > 1)
            {
                return Err(false);
            }
        }
        _ => {}
    }
    if cut {
        return Err(true);
    }
    for _ in 0..it.nested {
        p = skip(b, p, depth.saturating_add(1))?;
    }
    let end = p
        .checked_add(usize::try_from(it.trailer).map_err(|_| false)?)
        .ok_or(false)?;
    if end > b.len() {
        return Err(true);
    }
    Ok(end)
}

fn probe(h: &Head<'_>) -> bool {
    if h.data.first() != Some(&VERSION) || h.len < 3 {
        return false;
    }
    if h.data.get(1) == Some(&80) {
        // COMPRESSED: a plausible size, then a zlib header.
        let size = h.data.get(2..6).map_or(0, be_uint);
        let (Some(&cmf), Some(&flg)) = (h.data.get(6), h.data.get(7)) else {
            return false;
        };
        return size >= 2
            && size <= h.len.saturating_mul(1032)
            && cmf & 0x0f == 8
            && (u16::from(cmf) << 8 | u16::from(flg)).is_multiple_of(31);
    }
    let whole = h.len_known && u64::try_from(h.data.len()).is_ok_and(|n| n == h.len);
    match skip(h.data, 1, 0) {
        Ok(end) => whole && end == h.data.len(),
        // Cut by the window of a larger file: valid as far as it goes.
        Err(true) => !whole && h.data.len() >= 1024,
        Err(false) => false,
    }
}

async fn head(r: &mut ByteReader<'_>, at: u64) -> Result<Item> {
    let avail = r.region().len.saturating_sub(at).min(16);
    let b = r.bytes(at, avail).await?;
    match decode(&b) {
        Some(it) if matches!(it.tag, 80 | 121) => Err(Diagnostic::unsupported(format!(
            "{} inside a term",
            lookup(TAGS, it.tag.into()).unwrap_or("?")
        ))
        .at(r.span(at, 1))),
        Some(it) => Ok(it),
        None => match b.first() {
            Some(&t) if lookup(TAGS, t.into()).is_none() => {
                Err(Diagnostic::malformed(format!("unknown tag {t}")).at(r.span(at, 1)))
            }
            _ => Err(Diagnostic::truncated(r.span(at, 16), avail)),
        },
    }
}

/// The end of the term at `at`, scanning nested terms.
async fn end_of(r: &mut ByteReader<'_>, at: u64) -> Result<u64> {
    // Frames: terms left, and the bytes that follow them.
    let mut stack: Vec<(u64, u64)> = vec![(1, 0)];
    let mut pos = at;
    let len = r.region().len;
    loop {
        while let Some(&(0, trailer)) = stack.last() {
            stack.pop();
            pos = pos.saturating_add(trailer);
        }
        let Some(top) = stack.last_mut() else {
            if pos > len {
                return Err(Diagnostic::truncated(
                    r.span(at, pos.saturating_sub(at)),
                    len.saturating_sub(at),
                ));
            }
            return Ok(pos);
        };
        top.0 = top.0.saturating_sub(1);
        r.cx().checkpoint().await;
        let it = head(r, pos).await?;
        let body = pos.saturating_add(it.head);
        pos = body.saturating_add(it.payload);
        if pos > len {
            return Err(Diagnostic::truncated(
                r.span(body, it.payload),
                len.saturating_sub(body),
            ));
        }
        if it.nested == 0 {
            pos = pos.saturating_add(it.trailer);
            continue;
        }
        // Every term takes at least one byte.
        if it.nested > len.saturating_sub(pos) {
            return Err(Diagnostic::malformed(format!(
                "{} terms do not fit in the remaining {} bytes",
                it.nested,
                len.saturating_sub(pos)
            ))
            .at(r.span(pos, 1)));
        }
        if stack.len() >= vt::MAX_DEPTH {
            return Err(
                Diagnostic::limit(format!("terms nested deeper than {}", vt::MAX_DEPTH))
                    .at(r.span(pos, 1)),
            );
        }
        stack.push((it.nested, it.trailer));
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let version = r.byte(0).await?;
    let mut v = Node::new("Version").span(r.span(0, 1)).value(Value::UInt {
        value: version.into(),
        bits: 8,
        radix: crate::value::Radix::Dec,
    });
    if version != VERSION {
        v = v.diag(Diagnostic::malformed(format!("version {version}, not 131")));
    }
    cx.emit(v);
    if r.byte(1).await? == 80 {
        let size = r.be(2, 4).await?;
        cx.emit(
            Node::new("Uncompressed size")
                .span(r.span(2, 4))
                .value(vt::uint(size, 32)),
        );
        let data = input.span.tail(6);
        let decoded =
            crate::codec::decode_span(&cx, data, &crate::codec::Codec::Zlib, Some(size)).await?;
        cx.annotate("Erlang term (compressed)");
        let mut node = Node::new("Term")
            .span(data)
            .summary(format!("zlib, {} → {size} bytes", data.len));
        if let Some(e) = decoded.error {
            node = node.diag(e);
        }
        if decoded.span.len != size {
            node = node.diag(Diagnostic::malformed(format!(
                "decoded {} bytes, the header says {size}",
                decoded.span.len
            )));
        }
        cx.emit(node.lazy(crate::expander!(self::root: (Span, u64)), (decoded.span, 0)));
        return Ok(());
    }
    let first = head(&mut r, 1).await?;
    cx.annotate(format!("Erlang term, {}", describe(&first)));
    let end = end_of(&mut r, 1).await?;
    if end < input.span.len {
        cx.emit(
            Node::new("Trailing data")
                .span(input.span.tail(end))
                .diag(Diagnostic::warning("bytes after the term")),
        );
    }
    root(cx, (input.span, 1)).await
}

/// The term at `start` of `region`: a container's members at this level,
/// anything else as one node.
async fn root(cx: Cx, (region, start): (Span, u64)) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let it = head(&mut r, start).await?;
    if matches!(it.tag, 104 | 105 | 108 | 116) {
        return members(cx, (region, start, Path::new())).await;
    }
    let end = end_of(&mut r, start).await?;
    let node = item_node(&mut r, start, end, "Term".to_owned(), &Path::new()).await?;
    cx.emit(node);
    Ok(())
}

fn describe(it: &Item) -> String {
    match it.tag {
        104 | 105 => vt::array_summary("tuple", Some(it.nested)),
        108 => vt::array_summary("list", Some(it.nested.saturating_sub(1))),
        116 => vt::map_summary("map", Some(it.nested / 2), "entry", "entries"),
        106 => "nil".to_owned(),
        107 => "string".to_owned(),
        109 => "binary".to_owned(),
        77 => "bit binary".to_owned(),
        97 | 98 | 110 | 111 => "integer".to_owned(),
        70 | 99 => "float".to_owned(),
        100 | 115 | 118 | 119 | 82 => "atom".to_owned(),
        88 | 103 => "pid".to_owned(),
        89 | 102 | 120 => "port".to_owned(),
        90 | 101 | 114 => "reference".to_owned(),
        112 | 117 => "fun".to_owned(),
        113 => "export fun".to_owned(),
        t => lookup(TAGS, t.into()).unwrap_or("?").to_owned(),
    }
}

/// An atom's text (Latin-1 or UTF-8).
fn atom_text(tag: u8, b: &[u8]) -> String {
    match tag {
        100 | 115 => b.iter().map(|&c| char::from(c)).collect(),
        _ => String::from_utf8_lossy(b).into_owned(),
    }
}

/// The text of the atom at `at` (for names), if it is one.
async fn atom_at(r: &mut ByteReader<'_>, at: u64) -> Result<Option<String>> {
    let it = head(r, at).await?;
    if !matches!(it.tag, 100 | 115 | 118 | 119) {
        return Ok(None);
    }
    let b = r
        .bytes(at.saturating_add(it.head), it.payload.min(1024))
        .await?;
    Ok(Some(atom_text(it.tag, &b)))
}

/// A big integer's digits (little-endian magnitude) in decimal.
fn big_text(negative: bool, le: &[u8]) -> String {
    let be: Vec<u8> = le.iter().rev().copied().collect();
    let digits = vt::magnitude_digits(&be);
    if digits.starts_with('<') {
        return if negative {
            format!("negative {digits}")
        } else {
            digits
        };
    }
    if negative && digits != "0" {
        format!("-{digits}")
    } else {
        digits
    }
}

/// `<node.id.serial>`-style text for a pid, port or reference whose node
/// atom is at `at` and fixed fields follow it.
async fn identity(r: &mut ByteReader<'_>, it: &Item, start: u64) -> Result<String> {
    let node_at = start.saturating_add(it.head);
    let node = atom_at(r, node_at).await?.unwrap_or_else(|| "?".to_owned());
    let node_end = end_of(r, node_at).await?;
    let f = r.bytes(node_end, it.trailer.min(64)).await?;
    let u32_at = |o: usize| f.get(o..o.saturating_add(4)).map_or(0, be_uint);
    Ok(match it.tag {
        88 | 103 => format!("<{node}.{}.{}>", u32_at(0), u32_at(4)),
        89 | 102 => format!("#Port<{node}.{}>", u32_at(0)),
        120 => format!("#Port<{node}.{}>", f.get(..8).map_or(0, be_uint)),
        101 => format!("#Ref<{node}.{}>", u32_at(0)),
        _ => {
            // NEWER/NEW_REFERENCE: creation, then the ID words (shown
            // most significant first, as the shell does).
            let skip = if it.tag == 90 { 4 } else { 1 };
            let ids: Vec<String> = f
                .get(skip..)
                .unwrap_or_default()
                .chunks_exact(4)
                .rev()
                .map(|w| be_uint(w).to_string())
                .collect();
            format!("#Ref<{node}.{}>", ids.join("."))
        }
    })
}

/// A node for the term at `start..end`.
async fn item_node(
    r: &mut ByteReader<'_>,
    start: u64,
    end: u64,
    name: String,
    path: &Path,
) -> Result<Node> {
    let it = head(r, start).await?;
    let span = r.span(start, end.saturating_sub(start));
    let node = Node::new(name).span(span);
    let body = start.saturating_add(it.head);
    let region = r.region();
    let container = |node: Node, kind: String| -> Node {
        let node = node.summary(kind);
        if it.nested == 0 {
            return node;
        }
        match vt::enter(path, span.offset) {
            Ok(p) => node.lazy(
                crate::expander!(self::members: (Span, u64, Path)),
                (region, start, p),
            ),
            Err(d) => node.diag(d),
        }
    };
    Ok(match it.tag {
        97 => node.value(vt::int(
            i64::from(r.byte(start.saturating_add(1)).await?),
            8,
        )),
        98 => {
            let v = r.be(start.saturating_add(1), 4).await?;
            let v = i32::from_be_bytes(u32::try_from(v).unwrap_or(0).to_be_bytes());
            node.value(vt::int(i64::from(v), 32))
        }
        110 | 111 => {
            let sign = r.byte(body.saturating_sub(1)).await?;
            let digits = r.bytes(body, it.payload.min(1024)).await?;
            let text = if it.payload > 1024 {
                format!("<{}-byte integer>", it.payload)
            } else {
                big_text(sign != 0, &digits)
            };
            node.value(Value::Text(text))
                .summary(format!("big integer, {} bytes", it.payload))
        }
        70 => node.value(Value::Float(f64::from_bits(
            r.be(start.saturating_add(1), 8).await?,
        ))),
        99 => {
            let b = r.bytes(start.saturating_add(1), 31).await?;
            let text = String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or_default())
                .into_owned();
            match text.trim().parse::<f64>() {
                Ok(f) => node
                    .value(Value::Float(f))
                    .summary(format!("float as text {text:?}")),
                Err(_) => node
                    .value(Value::Text(text))
                    .diag(Diagnostic::malformed("float text does not parse")),
            }
        }
        100 | 115 | 118 | 119 => {
            let b = r.bytes(body, it.payload.min(1024)).await?;
            node.value(Value::Text(atom_text(it.tag, &b)))
                .summary("atom")
        }
        82 => node
            .value(vt::uint(r.byte(body.saturating_sub(1)).await?, 8))
            .summary("atom cache reference (distribution only)"),
        106 => node.summary("[] (nil)"),
        107 => {
            let b = r.bytes(body, it.payload.min(vt::MAX_TEXT)).await?;
            if std::str::from_utf8(&b)
                .is_ok_and(|s| s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'))
            {
                vt::text(node, &b, it.payload).summary(format!(
                    "string, {}",
                    crate::formats::util::fmt::grouped_count(it.payload, "byte", "bytes")
                ))
            } else {
                vt::bytes(node, "string (list of small integers)", b, it.payload)
            }
        }
        109 => {
            let b = r.bytes(body, it.payload.min(vt::MAX_TEXT)).await?;
            let printable = !b.is_empty()
                && std::str::from_utf8(&b)
                    .is_ok_and(|s| s.chars().all(|c| !c.is_control() || c == '\n' || c == '\t'));
            if printable {
                vt::text(node, &b, it.payload).summary(format!(
                    "binary, {}",
                    crate::formats::util::fmt::grouped_count(it.payload, "byte", "bytes")
                ))
            } else {
                let shown = b.into_iter().take(vt::MAX_BYTES as usize).collect();
                vt::bytes(node, "binary", shown, it.payload)
            }
        }
        77 => {
            let bits = r.byte(start.saturating_add(5)).await?;
            let b = r.bytes(body, it.payload.min(vt::MAX_BYTES)).await?;
            let total = it
                .payload
                .saturating_sub(1)
                .saturating_mul(8)
                .saturating_add(bits.into());
            node.value(Value::Bytes(b))
                .summary(format!("bit binary, {total} bits"))
        }
        104 | 105 => container(node, vt::array_summary("tuple", Some(it.nested))),
        108 => {
            let mut kind = vt::array_summary("list", Some(it.nested.saturating_sub(1)));
            // An improper list's tail is not nil.
            let mut tail = body;
            let mut known = true;
            for _ in 0..it.nested.saturating_sub(1).min(4096) {
                match end_of(r, tail).await {
                    Ok(e) => tail = e,
                    Err(_) => {
                        known = false;
                        break;
                    }
                }
            }
            if known && it.nested <= 4097 && r.byte(tail).await.ok() != Some(106) {
                kind.push_str(", improper");
            }
            container(node, kind)
        }
        116 => container(
            node,
            vt::map_summary("map", Some(it.nested / 2), "entry", "entries"),
        ),
        88 | 103 | 89 | 102 | 120 | 90 | 101 | 114 => {
            let text = identity(r, &it, start).await?;
            node.value(Value::Text(text)).summary(describe(&it)).lazy(
                crate::expander!(self::identity_fields: (Span, Path)),
                (span, path.clone()),
            )
        }
        113 => {
            let m_at = body;
            let module = atom_at(r, m_at).await?.unwrap_or_default();
            let f_at = end_of(r, m_at).await?;
            let function = atom_at(r, f_at).await?.unwrap_or_default();
            let a_at = end_of(r, f_at).await?;
            let arity = r.byte(a_at.saturating_add(1)).await?;
            node.value(Value::Text(format!("fun {module}:{function}/{arity}")))
                .summary("export fun")
                .lazy(
                    crate::expander!(self::members: (Span, u64, Path)),
                    (r.region(), start, path.clone()),
                )
        }
        112 | 117 => node.summary("fun").lazy(
            crate::expander!(self::fun_fields: (Span, Path)),
            (span, path.clone()),
        ),
        t => node.value(hex(t, 8)).diag(Diagnostic::unsupported(format!(
            "{}",
            lookup(TAGS, t.into()).unwrap_or("unknown tag")
        ))),
    })
}

/// Short text for a map key: atoms, strings, binaries and integers.
async fn key_name(r: &mut ByteReader<'_>, at: u64, index: u64) -> Result<String> {
    let it = head(r, at).await?;
    let body = at.saturating_add(it.head);
    Ok(match it.tag {
        100 | 115 | 118 | 119 => {
            let b = r.bytes(body, it.payload.min(0x200)).await?;
            vt::key_name(&atom_text(it.tag, &b), index)
        }
        107 | 109 => {
            let b = r.bytes(body, it.payload.min(0x200)).await?;
            match std::str::from_utf8(&b) {
                Ok(s) => vt::key_name(&format!("{s:?}"), index),
                Err(_) => format!("key #{index}"),
            }
        }
        97 => r.byte(body.saturating_sub(1)).await?.to_string(),
        98 => {
            let v = r.be(at.saturating_add(1), 4).await?;
            i32::from_be_bytes(u32::try_from(v).unwrap_or(0).to_be_bytes()).to_string()
        }
        106 => "[]".to_owned(),
        _ => format!("key #{index}"),
    })
}

async fn members(cx: Cx, (region, start, path): (Span, u64, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let it = head(&mut r, start).await?;
    let pairs = it.tag == 116;
    let count = if pairs { it.nested / 2 } else { it.nested };
    if it.tag != 108 {
        cx.set_count(Count::Exact(count));
    }
    let (mut pos, mut index) = cx
        .resume::<(u64, u64)>()
        .unwrap_or((start.saturating_add(it.head).saturating_add(it.payload), 0));
    let labels: &[&str] = match it.tag {
        113 => &["module", "function", "arity"],
        _ => &[],
    };
    while index < count {
        let at = (pos, index);
        cx.mark(move || at);
        let node = if pairs {
            let key_end = end_of(&mut r, pos).await?;
            let value_end = end_of(&mut r, key_end).await?;
            let name = key_name(&mut r, pos, index).await?;
            let node = item_node(&mut r, key_end, value_end, name, &path)
                .await?
                .span(r.span(pos, value_end.saturating_sub(pos)));
            pos = value_end;
            node
        } else {
            let end = end_of(&mut r, pos).await?;
            let is_tail = it.tag == 108 && index.saturating_add(1) == count;
            let name = match labels.get(usize::try_from(index).unwrap_or(usize::MAX)) {
                Some(l) => (*l).to_owned(),
                None if is_tail => "tail".to_owned(),
                None => format!("[{index}]"),
            };
            // A proper list's nil tail is not shown.
            if is_tail && r.byte(pos).await? == 106 {
                break;
            }
            let node = item_node(&mut r, pos, end, name, &path).await?;
            pos = end;
            node
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    Ok(())
}

fn uint_node(r: &ByteReader<'_>, name: &'static str, at: u64, len: u64, v: u64) -> Node {
    Node::new(name).span(r.span(at, len)).value(vt::uint(
        v,
        u8::try_from(len.saturating_mul(8)).unwrap_or(64),
    ))
}

async fn identity_fields(cx: Cx, (span, path): (Span, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let it = head(&mut r, 0).await?;
    let mut at = 1u64;
    if matches!(it.tag, 90 | 114) {
        let n = r.be(1, 2).await?;
        cx.emit(uint_node(&r, "Length", 1, 2, n));
        at = 3;
    }
    let node_end = end_of(&mut r, at).await?;
    cx.emit(item_node(&mut r, at, node_end, "Node".to_owned(), &path).await?);
    let mut p = node_end;
    let fields: &[(&'static str, u64)] = match it.tag {
        88 => &[("ID", 4), ("Serial", 4), ("Creation", 4)],
        103 => &[("ID", 4), ("Serial", 4), ("Creation", 1)],
        89 => &[("ID", 4), ("Creation", 4)],
        102 => &[("ID", 4), ("Creation", 1)],
        120 => &[("ID", 8), ("Creation", 4)],
        101 => &[("ID", 4), ("Creation", 1)],
        90 => &[("Creation", 4)],
        _ => &[("Creation", 1)],
    };
    for &(name, len) in fields {
        let v = r.be(p, len).await?;
        cx.emit(uint_node(&r, name, p, len, v));
        p = p.saturating_add(len);
    }
    if matches!(it.tag, 90 | 114) {
        let n = r.be(1, 2).await?;
        for i in 0..n.min(64) {
            let v = r.be(p, 4).await?;
            cx.emit(
                Node::new(format!("ID word {i}"))
                    .span(r.span(p, 4))
                    .value(vt::uint(v, 32)),
            );
            p = p.saturating_add(4);
        }
    }
    Ok(())
}

async fn fun_fields(cx: Cx, (span, path): (Span, Path)) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let tag = r.byte(0).await?;
    let mut p;
    let numfree;
    if tag == 112 {
        let v = r.be(1, 4).await?;
        cx.emit(uint_node(&r, "Size", 1, 4, v));
        let v = r.be(5, 1).await?;
        cx.emit(uint_node(&r, "Arity", 5, 1, v));
        let uniq = r.bytes(6, 16).await?;
        cx.emit(Node::new("Uniq").span(r.span(6, 16)).value(Value::Text(
            crate::formats::util::datakit::hex_string(&uniq),
        )));
        let v = r.be(22, 4).await?;
        cx.emit(uint_node(&r, "Index", 22, 4, v));
        numfree = r.be(26, 4).await?;
        cx.emit(uint_node(&r, "Free variables", 26, 4, numfree));
        p = 30;
        for name in ["Module", "Old index", "Old uniq", "Pid"] {
            let end = end_of(&mut r, p).await?;
            cx.emit(item_node(&mut r, p, end, name.to_owned(), &path).await?);
            p = end;
        }
    } else {
        numfree = r.be(1, 4).await?;
        cx.emit(uint_node(&r, "Free variables", 1, 4, numfree));
        p = 5;
        for name in ["Pid", "Module", "Index", "Uniq"] {
            let end = end_of(&mut r, p).await?;
            cx.emit(item_node(&mut r, p, end, name.to_owned(), &path).await?);
            p = end;
        }
    }
    for i in 0..numfree {
        if p >= span.len {
            cx.diag(Diagnostic::truncated(span.tail(p), 0));
            break;
        }
        let end = end_of(&mut r, p).await?;
        cx.push(item_node(&mut r, p, end, format!("Free [{i}]"), &path).await?)
            .await;
        p = end;
    }
    if tag == 112 && p != span.len {
        cx.diag(Diagnostic::malformed(format!(
            "the fields end at {p}, the size says {}",
            span.len
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::probe;
    use crate::formats::Head;

    fn head(data: &[u8]) -> Head<'_> {
        Head {
            data,
            tail: data,
            len: data.len() as u64,
            len_known: true,
        }
    }

    #[test]
    fn probe_needs_a_whole_term() {
        // [1, two]
        let term = b"\x83l\x00\x00\x00\x02a\x01w\x03twoj";
        assert!(probe(&head(term)));
        // Cut short, or with bytes after it.
        assert!(!probe(&head(&term[..term.len() - 1])));
        let mut longer = term.to_vec();
        longer.push(0);
        assert!(!probe(&head(&longer)));
        // Windows-1252 text that starts with "ƒ".
        assert!(!probe(&head(b"\x83hello, this is text\r\n")));
        assert!(!probe(&head(b"\x83")));
    }
}
