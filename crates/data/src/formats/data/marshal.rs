//! Ruby `Marshal.dump` data (format 4.8; `.marshal`, `.dump`): the version
//! bytes 4 and 8, then one value, each starting with a type byte. Integers
//! and lengths are packed (one byte for small values, else a byte count
//! and little-endian bytes). Containers record their element count, so
//! the end of a value is found by scanning it. Symbols are written once
//! and then referenced by index (`;`), and every object (string, array,
//! hash, float, bignum, object, struct, ...) gets an index that later
//! object links (`@`) refer to; both tables are built by scanning from
//! the start as far as a reference needs, once per file.
//!
//! Values shown: nil, true, false, fixnums, bignums, floats, symbols and
//! symbol links, strings (with their encoding from the instance variables
//! `E` or `encoding`), regular expressions, arrays, hashes (with a
//! default), objects with instance variables, structs, `_dump` (`u`) and
//! `marshal_dump` (`U`) data, `_dump_data` (`d`), String/Array/Hash
//! subclasses (`C`), extended objects (`e`), classes and modules, and
//! object links (with the object they point to). `_dump` data that is
//! itself a Marshal stream (`Gem::Specification`, as in RubyGems' specs
//! indexes) is dissected as one, and a `Time`'s 8 packed bytes are
//! decoded, with its UTC offset, zone and nanoseconds from its instance
//! variables (`marshal_time` in Ruby's `time.c`, from memory; checked
//! against Times dumped by Ruby 3.4: UTC, local, with nanoseconds).
//!
//! Layout written from memory of Ruby's `doc/marshal.rdoc` and
//! `marshal.c` (including which values take an object index), checked
//! against files written by Ruby 3.4 (object links resolve to the objects
//! they were written for).
//!
//! Probe (two weak bytes): `04 08`, then a value that parses with known
//! types and consistent lengths exactly to the end of the file (when the
//! probe window holds it all) or through the whole window (at least 1 KiB
//! of it) when the file is larger. Anything else reaches the dissector by
//! extension.

use std::sync::{Arc, Mutex};

use crate::cx::{Cx, lock};
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::util::datakit::ByteReader;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

use super::valuetree as vt;

pub static FORMAT: Format = Format {
    name: "ruby-marshal",
    title: "Ruby Marshal data",
    extensions: &["marshal"],
    mime: "application/x-ruby-marshal",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// What follows a value's first nested values.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Then {
    Nothing,
    /// A packed count `k`, then `2k` more values (instance variables,
    /// struct members).
    Pairs,
    /// A packed length and that many raw bytes (`_dump` data).
    Bytes,
}

/// A value's framing: header bytes (type, packed numbers, raw bytes),
/// nested values, and what follows them.
#[derive(Clone, Copy, Debug)]
struct Item {
    tag: u8,
    head: u64,
    nested: u64,
    then: Then,
}

/// A packed integer (`w_long`) at the start of `b`: its value and size.
fn packed(b: &[u8]) -> Option<(i64, u64)> {
    let c = i8::from_le_bytes([*b.first()?]);
    match c {
        0 => Some((0, 1)),
        5..=127 => Some((i64::from(c).saturating_sub(5), 1)),
        -128..=-5 => Some((i64::from(c).saturating_add(5), 1)),
        1..=4 => {
            let n = usize::try_from(c).ok()?;
            let bytes = b.get(1..n.checked_add(1)?)?;
            let v = bytes
                .iter()
                .rev()
                .fold(0i64, |a, &x| a.wrapping_shl(8) | i64::from(x));
            Some((v, u64::try_from(n).ok()?.checked_add(1)?))
        }
        _ => {
            let n = usize::try_from(i64::from(c).saturating_neg()).ok()?;
            let bytes = b.get(1..n.checked_add(1)?)?;
            let mut v: i64 = -1;
            for (i, &x) in bytes.iter().enumerate() {
                let shift = u32::try_from(i.checked_mul(8)?).ok()?;
                v &= !(0xffi64.wrapping_shl(shift));
                v |= i64::from(x).wrapping_shl(shift);
            }
            Some((v, u64::try_from(n).ok()?.checked_add(1)?))
        }
    }
}

/// A packed count or length (non-negative).
fn count(b: &[u8]) -> Option<(u64, u64)> {
    let (v, n) = packed(b)?;
    Some((u64::try_from(v).ok()?, n))
}

/// Decodes the framing of the value at the start of `b`.
fn decode(b: &[u8]) -> Option<Item> {
    let tag = *b.first()?;
    let rest = b.get(1..)?;
    let item = |head: u64, nested: u64, then: Then| {
        Some(Item {
            tag,
            head,
            nested,
            then,
        })
    };
    // A packed length and that many bytes.
    let bytes = || -> Option<u64> {
        let (len, n) = count(rest)?;
        1u64.checked_add(n)?.checked_add(len)
    };
    match tag {
        b'0' | b'T' | b'F' => item(1, 0, Then::Nothing),
        b'i' | b';' | b'@' => item(1u64.checked_add(packed(rest)?.1)?, 0, Then::Nothing),
        b'l' => {
            let (words, n) = count(rest.get(1..)?)?;
            item(
                2u64.checked_add(n)?.checked_add(words.checked_mul(2)?)?,
                0,
                Then::Nothing,
            )
        }
        b'f' | b'"' | b':' | b'c' | b'm' | b'M' => item(bytes()?, 0, Then::Nothing),
        b'/' => item(bytes()?.checked_add(1)?, 0, Then::Nothing),
        b'[' => {
            let (k, n) = count(rest)?;
            item(1u64.checked_add(n)?, k, Then::Nothing)
        }
        b'{' | b'}' => {
            let (k, n) = count(rest)?;
            let extra = u64::from(tag == b'}');
            item(
                1u64.checked_add(n)?,
                k.checked_mul(2)?.checked_add(extra)?,
                Then::Nothing,
            )
        }
        b'I' | b'o' | b'S' => item(1, 1, Then::Pairs),
        b'u' => item(1, 1, Then::Bytes),
        b'U' | b'C' | b'e' | b'd' => item(1, 2, Then::Nothing),
        _ => None,
    }
}

/// Whether a value of this type takes an object index.
fn counted(tag: u8) -> bool {
    matches!(
        tag,
        b'"' | b'/'
            | b'['
            | b'{'
            | b'}'
            | b'o'
            | b'S'
            | b'l'
            | b'f'
            | b'c'
            | b'm'
            | b'M'
            | b'u'
            | b'U'
            | b'd'
    )
}

/// Synchronous validation for the probe (`Err(true)`: runs past the end of
/// `b`; `Err(false)`: invalid).
fn skip(b: &[u8], pos: usize, depth: usize) -> std::result::Result<usize, bool> {
    if depth > 64 {
        return Err(false);
    }
    let rest = b.get(pos..).ok_or(true)?;
    if rest.is_empty() {
        return Err(true);
    }
    let Some(it) = decode(rest) else {
        let known = decode(&[rest.first().copied().unwrap_or(0), 0, 0, 0, 0, 0]).is_some();
        return Err(known && rest.len() < 8);
    };
    let to = |n: u64| usize::try_from(n).map_err(|_| false);
    let mut p = pos.checked_add(to(it.head)?).ok_or(false)?;
    if p > b.len() {
        return Err(true);
    }
    // Symbols and class names are short identifiers in practice.
    if matches!(it.tag, b':' | b'c' | b'm') {
        let name = b.get(pos.saturating_add(1)..p).unwrap_or_default();
        let name = name
            .get(count(name).map_or(0, |(_, n)| to_usize(n))..)
            .unwrap_or_default();
        if name.is_empty() || std::str::from_utf8(name).is_err() || name.len() > 1024 {
            return Err(false);
        }
    }
    let mut nested = it.nested;
    let mut then = it.then;
    loop {
        for _ in 0..nested {
            p = skip(b, p, depth.saturating_add(1))?;
        }
        match then {
            Then::Nothing => return Ok(p),
            Then::Pairs => {
                let (k, n) =
                    count(b.get(p..).ok_or(true)?).ok_or(p >= b.len().saturating_sub(4))?;
                if k > 1 << 20 {
                    return Err(false);
                }
                p = p.checked_add(to(n)?).ok_or(false)?;
                nested = k.saturating_mul(2);
                then = Then::Nothing;
            }
            Then::Bytes => {
                let (len, n) =
                    count(b.get(p..).ok_or(true)?).ok_or(p >= b.len().saturating_sub(4))?;
                let end = p
                    .checked_add(to(n)?)
                    .and_then(|e| e.checked_add(to(len).ok()?))
                    .ok_or(false)?;
                if end > b.len() {
                    return Err(true);
                }
                return Ok(end);
            }
        }
    }
}

fn to_usize(n: u64) -> usize {
    crate::bytes::to_usize(n)
}

fn probe(h: &Head<'_>) -> bool {
    if h.data.get(..2) != Some(&[4, 8][..]) || h.len < 3 {
        return false;
    }
    let whole = h.len_known && u64::try_from(h.data.len()).is_ok_and(|n| n == h.len);
    // A leaf value (a string, a bignum) cut by the window says where it
    // ends: that must be the end of the file, or three bytes and a large
    // length would do.
    if let Some(it) = h.data.get(2..).and_then(decode)
        && it.nested == 0
        && it.then == Then::Nothing
        && h.len_known
        && !whole
    {
        return 2u64.checked_add(it.head) == Some(h.len) && skip(h.data, 2, 0) == Err(true);
    }
    match skip(h.data, 2, 0) {
        Ok(end) => whole && end == h.data.len(),
        Err(true) => !whole && h.data.len() >= 1024,
        Err(false) => false,
    }
}

async fn head(r: &mut ByteReader<'_>, at: u64) -> Result<Item> {
    let avail = r.region().len.saturating_sub(at).min(16);
    let b = r.bytes(at, avail).await?;
    match decode(&b) {
        Some(it) => Ok(it),
        None => match b.first() {
            Some(&t) if decode(&[t, 0, 0, 0, 0, 0, 0, 0, 0, 0]).is_none() => {
                Err(Diagnostic::malformed(format!("unknown type byte {t:#04x}")).at(r.span(at, 1)))
            }
            _ => Err(Diagnostic::truncated(r.span(at, 16), avail)),
        },
    }
}

/// A packed count at `at`: its value and size.
async fn count_at(r: &mut ByteReader<'_>, at: u64) -> Result<(u64, u64)> {
    let avail = r.region().len.saturating_sub(at).min(5);
    let b = r.bytes(at, avail).await?;
    count(&b).ok_or_else(|| Diagnostic::malformed("bad packed count").at(r.span(at, 1)))
}

/// A scan frame: values left, and what follows them.
#[derive(Clone, Copy, Debug)]
struct Frame {
    left: u64,
    then: Then,
}

/// A scanner over values: `visit` sees the type and offset of every value
/// as it starts. Returns where the value at `at` ends.
async fn end_of(r: &mut ByteReader<'_>, at: u64) -> Result<u64> {
    let mut scan = Scan::new(at);
    while !scan.done {
        scan.step(r, &mut |_, _, _| {}).await?;
    }
    Ok(scan.pos)
}

/// A resumable scan of one value (the whole stream, for the tables).
#[derive(Clone, Debug)]
struct Scan {
    pos: u64,
    stack: Vec<Frame>,
    done: bool,
    /// Steps taken (to tell scans of the same position apart).
    steps: u64,
}

impl Scan {
    fn new(at: u64) -> Self {
        Scan {
            pos: at,
            stack: vec![Frame {
                left: 1,
                then: Then::Nothing,
            }],
            done: false,
            steps: 0,
        }
    }

    /// Advances over one value header (or one deferred count); `visit`
    /// gets each value's type, offset and header length.
    async fn step(
        &mut self,
        r: &mut ByteReader<'_>,
        visit: &mut (dyn FnMut(u8, u64, u64) + Send),
    ) -> Result<()> {
        let len = r.region().len;
        self.steps = self.steps.saturating_add(1);
        let Some(top) = self.stack.last_mut() else {
            self.done = true;
            return Ok(());
        };
        if top.left == 0 {
            match top.then {
                Then::Nothing => {
                    self.stack.pop();
                    if self.stack.is_empty() {
                        self.done = true;
                    }
                }
                Then::Pairs => {
                    let (k, n) = count_at(r, self.pos).await?;
                    self.pos = self.pos.saturating_add(n);
                    if k > len.saturating_sub(self.pos) {
                        return Err(Diagnostic::malformed(format!(
                            "{k} instance variables do not fit"
                        ))
                        .at(r.span(self.pos, 1)));
                    }
                    top.left = k.saturating_mul(2);
                    top.then = Then::Nothing;
                }
                Then::Bytes => {
                    let (k, n) = count_at(r, self.pos).await?;
                    self.pos = self.pos.saturating_add(n).saturating_add(k);
                    if self.pos > len {
                        return Err(Diagnostic::truncated(r.span(self.pos, 0), 0));
                    }
                    self.stack.pop();
                    if self.stack.is_empty() {
                        self.done = true;
                    }
                }
            }
            return Ok(());
        }
        top.left = top.left.saturating_sub(1);
        r.cx().checkpoint().await;
        let it = head(r, self.pos).await?;
        visit(it.tag, self.pos, it.head);
        self.pos = self.pos.saturating_add(it.head);
        if self.pos > len {
            return Err(Diagnostic::truncated(
                r.span(self.pos.saturating_sub(it.head), it.head),
                len.saturating_sub(self.pos.saturating_sub(it.head)),
            ));
        }
        if it.nested > 0 || it.then != Then::Nothing {
            if it.nested > len.saturating_sub(self.pos) {
                return Err(Diagnostic::malformed(format!(
                    "{} values do not fit in the remaining {} bytes",
                    it.nested,
                    len.saturating_sub(self.pos)
                ))
                .at(r.span(self.pos, 1)));
            }
            if self.stack.len() >= vt::MAX_DEPTH {
                return Err(Diagnostic::limit(format!(
                    "values nested deeper than {}",
                    vt::MAX_DEPTH
                ))
                .at(r.span(self.pos, 1)));
            }
            self.stack.push(Frame {
                left: it.nested,
                then: it.then,
            });
        }
        Ok(())
    }
}

/// The object and symbol tables of a stream, built by one scan from its
/// first value as far as references need (shared through `cx.cache`).
#[derive(Debug)]
struct Tables {
    /// Offsets of the values that take object indexes, in index order
    /// (of the `I` wrapping one with its instance variables, so a link
    /// shows the string with its encoding).
    objects: Vec<u64>,
    /// Offsets of symbols (`:`), in index order.
    symbols: Vec<u64>,
    scan: Scan,
    /// The scan stopped on an error.
    failed: bool,
    /// The last value the scan visited: its type, offset and header length.
    last: Option<(u8, u64, u64)>,
}

const TABLES: &str = "ruby-marshal-tables";

/// What a lookup needs from the tables.
#[derive(Clone, Copy)]
enum Need {
    Object(u64),
    Symbol(u64),
}

/// The offset of object or symbol `need` in `region`, scanning as far as
/// needed (`None`: the stream has no such entry).
async fn lookup_entry(cx: &Cx, region: Span, need: Need) -> Option<u64> {
    let tables = match cx.cached::<Mutex<Tables>>(region, TABLES) {
        Some(t) => t,
        None => {
            let t = Arc::new(Mutex::new(Tables {
                objects: Vec::new(),
                symbols: Vec::new(),
                scan: Scan::new(2),
                failed: false,
                last: None,
            }));
            cx.cache(region, TABLES, t.clone());
            t
        }
    };
    let mut r = ByteReader::new(cx, region);
    loop {
        let (mut scan, mut last) = {
            let t = lock(&tables);
            let found = match need {
                Need::Object(i) => t.objects.get(to_usize(i)).copied(),
                Need::Symbol(i) => t.symbols.get(to_usize(i)).copied(),
            };
            if found.is_some() || t.scan.done || t.failed {
                return found;
            }
            (t.scan.clone(), t.last)
        };
        let start = scan.steps;
        let mut objects = Vec::new();
        let mut symbols = Vec::new();
        let mut failed = false;
        for _ in 0..256 {
            if scan.done {
                break;
            }
            let mut visit = |tag: u8, at: u64, head: u64| {
                if counted(tag) {
                    objects.push(match last {
                        Some((b'I', i, n)) if i.saturating_add(n) == at => i,
                        _ => at,
                    });
                }
                last = Some((tag, at, head));
                if tag == b':' {
                    symbols.push(at);
                }
            };
            if scan.step(&mut r, &mut visit).await.is_err() {
                failed = true;
                break;
            }
        }
        let mut t = lock(&tables);
        // Another lookup may have advanced the shared scan meanwhile.
        if t.scan.steps == start {
            t.objects.extend(objects);
            t.symbols.extend(symbols);
            t.scan = scan;
            t.failed = failed;
            t.last = last;
        }
    }
}

/// The name of symbol index `i`.
async fn symbol_name(cx: &Cx, region: Span, i: u64) -> Option<String> {
    let at = lookup_entry(cx, region, Need::Symbol(i)).await?;
    let mut r = ByteReader::new(cx, region);
    let (len, n) = count_at(&mut r, at.saturating_add(1)).await.ok()?;
    let b = r
        .bytes(at.saturating_add(1).saturating_add(n), len.min(1024))
        .await
        .ok()?;
    Some(String::from_utf8_lossy(&b).into_owned())
}

/// The text of a symbol or symbol link at `at`, if it is one.
async fn symbol_at(r: &mut ByteReader<'_>, at: u64) -> Result<Option<String>> {
    let it = head(r, at).await?;
    match it.tag {
        b':' => {
            let (len, n) = count_at(r, at.saturating_add(1)).await?;
            let b = r
                .bytes(at.saturating_add(1).saturating_add(n), len.min(1024))
                .await?;
            Ok(Some(String::from_utf8_lossy(&b).into_owned()))
        }
        b';' => {
            let (i, _) = count_at(r, at.saturating_add(1)).await?;
            Ok(Some(
                symbol_name(r.cx(), r.region(), i)
                    .await
                    .unwrap_or_else(|| format!("symbol #{i}")),
            ))
        }
        b'I' => {
            // A symbol with an encoding.
            let inner = at.saturating_add(1);
            if head(r, inner).await?.tag != b':' {
                return Ok(None);
            }
            let (len, n) = count_at(r, inner.saturating_add(1)).await?;
            let b = r
                .bytes(inner.saturating_add(1).saturating_add(n), len.min(1024))
                .await?;
            Ok(Some(String::from_utf8_lossy(&b).into_owned()))
        }
        _ => Ok(None),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let v = r.bytes(0, 2).await?;
    let (major, minor) = (
        v.first().copied().unwrap_or(0),
        v.get(1).copied().unwrap_or(0),
    );
    let mut node = Node::new("Version")
        .span(r.span(0, 2))
        .value(Value::Text(format!("{major}.{minor}")));
    if (major, minor) != (4, 8) {
        node = node.diag(Diagnostic::warning(format!(
            "version {major}.{minor} (Ruby writes 4.8)"
        )));
    }
    cx.emit(node);
    let first = head(&mut r, 2).await?;
    cx.annotate(format!("Ruby Marshal data, {}", describe(first.tag)));
    if matches!(first.tag, b'[' | b'{' | b'}' | b'o' | b'S') {
        // Listed as they are scanned; the trailing data check comes last.
        return walk_members(cx, input, 2, Path::new(), true).await;
    }
    let end = end_of(&mut r, 2).await?;
    let node = value_node(&mut r, input, 2, end, "Value".to_owned(), &Path::new()).await?;
    cx.emit(node);
    if let Some(node) = trailing(input.span, end) {
        cx.emit(node);
    }
    Ok(())
}

/// What follows the value ending at `end` of `region`, if anything.
fn trailing(region: Span, end: u64) -> Option<Node> {
    (end < region.len).then(|| {
        Node::new("Trailing data")
            .span(region.tail(end))
            .diag(Diagnostic::warning("bytes after the value"))
    })
}

fn describe(tag: u8) -> &'static str {
    match tag {
        b'0' => "nil",
        b'T' | b'F' => "boolean",
        b'i' => "fixnum",
        b'l' => "bignum",
        b'f' => "float",
        b':' => "symbol",
        b';' => "symbol link",
        b'"' => "string",
        b'/' => "regexp",
        b'[' => "array",
        b'{' => "hash",
        b'}' => "hash with default",
        b'o' => "object",
        b'S' => "struct",
        b'u' => "_dump data",
        b'U' => "marshal_dump data",
        b'd' => "_dump_data data",
        b'C' => "subclass instance",
        b'e' => "extended object",
        b'c' => "class",
        b'm' => "module",
        b'M' => "class or module (old)",
        b'@' => "object link",
        b'I' => "value with instance variables",
        _ => "?",
    }
}

/// A packed-length byte string at `at` (after the type byte): its first
/// bytes and full length.
async fn byte_string(r: &mut ByteReader<'_>, at: u64, max: u64) -> Result<(Vec<u8>, u64, u64)> {
    let (len, n) = count_at(r, at).await?;
    let b = r.bytes(at.saturating_add(n), len.min(max)).await?;
    Ok((b, len, n))
}

/// The encoding instance variables of an `I` value whose inner value ends
/// at `inner_end`: the encoding name, if they give one.
async fn encoding(r: &mut ByteReader<'_>, inner_end: u64) -> Result<Option<String>> {
    let (k, n) = count_at(r, inner_end).await?;
    let mut p = inner_end.saturating_add(n);
    for _ in 0..k.min(64) {
        let name = symbol_at(r, p).await?;
        let value_at = end_of(r, p).await?;
        let value_end = end_of(r, value_at).await?;
        match name.as_deref() {
            Some("E") => {
                let t = head(r, value_at).await?.tag;
                return Ok(Some(
                    if t == b'T' { "UTF-8" } else { "US-ASCII" }.to_owned(),
                ));
            }
            Some("encoding") if head(r, value_at).await?.tag == b'"' => {
                let (b, _, _) = byte_string(r, value_at.saturating_add(1), 64).await?;
                return Ok(Some(String::from_utf8_lossy(&b).into_owned()));
            }
            _ => {}
        }
        p = value_end;
    }
    Ok(None)
}

/// A string's text in its encoding (UTF-8 and ASCII as they are,
/// ISO-8859-1 by code point, anything else as bytes).
fn string_node(node: Node, b: Vec<u8>, total: u64, enc: Option<&str>) -> Node {
    let enc_name = enc.unwrap_or("ASCII-8BIT");
    match enc {
        Some("UTF-8") | Some("US-ASCII") => {
            vt::text(node, &b, total).summary(format!("string, {enc_name}"))
        }
        Some("ISO-8859-1") => {
            let s: String = b.iter().map(|&c| char::from(c)).collect();
            node.value(Value::Text(s))
                .summary(format!("string, {enc_name}"))
        }
        _ => {
            if std::str::from_utf8(&b).is_ok_and(|s| !s.chars().any(char::is_control))
                && !b.is_empty()
            {
                node.value(Value::Text(String::from_utf8_lossy(&b).into_owned()))
                    .summary(format!("string, {enc_name}"))
            } else {
                let shown = b.into_iter().take(vt::MAX_BYTES as usize).collect();
                vt::bytes(node, &format!("string, {enc_name}"), shown, total)
            }
        }
    }
}

/// [`value_node`], boxed for an object link to show the object it links
/// to (never another link).
fn value_node_boxed<'a, 'b: 'a>(
    r: &'a mut ByteReader<'b>,
    input: Input,
    start: u64,
    end: u64,
    path: &'a Path,
) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<Node>> + Send + 'a>> {
    Box::pin(value_node(r, input, start, end, String::new(), path))
}

/// A node for the value at `start..end`.
async fn value_node(
    r: &mut ByteReader<'_>,
    input: Input,
    start: u64,
    end: u64,
    name: String,
    path: &Path,
) -> Result<Node> {
    let it = head(r, start).await?;
    let span = r.span(start, end.saturating_sub(start));
    let node = Node::new(name).span(span);
    let region = r.region();
    let lazy_members = |node: Node, summary: String| -> Node {
        let node = node.summary(summary);
        match vt::enter(path, span.offset) {
            Ok(p) => node.lazy(
                crate::expander!(self::members: (Input, u64, Path)),
                (input, start, p),
            ),
            Err(d) => node.diag(d),
        }
    };
    Ok(match it.tag {
        b'0' => node.summary("nil"),
        b'T' => node.value(Value::Bool(true)),
        b'F' => node.value(Value::Bool(false)),
        b'i' => {
            let b = r
                .bytes(start.saturating_add(1), it.head.saturating_sub(1))
                .await?;
            let (v, _) = packed(&b).unwrap_or((0, 0));
            node.value(vt::int(v, 32))
        }
        b'l' => {
            let sign = r.byte(start.saturating_add(1)).await?;
            let (words, n) = count_at(r, start.saturating_add(2)).await?;
            let bytes = words.saturating_mul(2);
            let digits = r
                .bytes(start.saturating_add(2).saturating_add(n), bytes.min(256))
                .await?;
            let be: Vec<u8> = digits.iter().rev().copied().collect();
            let text = if bytes > 256 {
                format!("<{bytes}-byte integer>")
            } else {
                let d = vt::magnitude_digits(&be);
                if sign == b'-' { format!("-{d}") } else { d }
            };
            node.value(Value::Text(text))
                .summary(format!("bignum, {bytes} bytes"))
        }
        b'f' => {
            let (b, _, _) = byte_string(r, start.saturating_add(1), 64).await?;
            let text = String::from_utf8_lossy(b.split(|&c| c == 0).next().unwrap_or_default())
                .into_owned();
            let v = match text.as_str() {
                "nan" => Some(f64::NAN),
                "inf" => Some(f64::INFINITY),
                "-inf" => Some(f64::NEG_INFINITY),
                t => t.parse::<f64>().ok(),
            };
            match v {
                Some(f) => node.value(Value::f64(f)).summary("float"),
                None => node
                    .value(Value::Text(text))
                    .diag(Diagnostic::malformed("float text does not parse")),
            }
        }
        b':' => {
            let (b, len, _) = byte_string(r, start.saturating_add(1), 1024).await?;
            let _ = len;
            node.value(Value::Text(format!(":{}", String::from_utf8_lossy(&b))))
                .summary("symbol")
        }
        b';' => {
            let (i, _) = count_at(r, start.saturating_add(1)).await?;
            let mut node = node.summary(format!("symbol link #{i}"));
            match lookup_entry(r.cx(), region, Need::Symbol(i)).await {
                Some(at) => {
                    let name = symbol_name(r.cx(), region, i).await.unwrap_or_default();
                    let target_end = end_of(r, at).await.unwrap_or(at);
                    node = node
                        .value(Value::Text(format!(":{name}")))
                        .target(r.span(at, target_end.saturating_sub(at)));
                }
                None => {
                    node = node.diag(Diagnostic::malformed(format!("no symbol #{i} before it")));
                }
            }
            node
        }
        b'"' => {
            let (b, len, _) = byte_string(r, start.saturating_add(1), vt::MAX_TEXT).await?;
            string_node(node, b, len, None)
        }
        b'/' => {
            let (b, len, n) = byte_string(r, start.saturating_add(1), vt::MAX_TEXT).await?;
            let opts = r
                .byte(
                    start
                        .saturating_add(1)
                        .saturating_add(n)
                        .saturating_add(len),
                )
                .await?;
            node.value(Value::Text(format!(
                "/{}/{}",
                String::from_utf8_lossy(&b),
                regexp_options(opts)
            )))
            .summary("regexp")
        }
        b'c' | b'm' | b'M' => {
            let (b, _, _) = byte_string(r, start.saturating_add(1), 1024).await?;
            node.value(Value::Text(String::from_utf8_lossy(&b).into_owned()))
                .summary(describe(it.tag))
        }
        b'@' => {
            let (i, _) = count_at(r, start.saturating_add(1)).await?;
            match lookup_entry(r.cx(), region, Need::Object(i)).await {
                Some(at) if head(r, at).await?.tag != b'@' => {
                    // The object linked to, as it was shown where it was
                    // written (its members too: a link back to an
                    // enclosing object is caught by the path).
                    let t = head(r, at).await?.tag;
                    let target_end = end_of(r, at).await.unwrap_or(at);
                    let target = r.span(at, target_end.saturating_sub(at));
                    let shown = value_node_boxed(r, input, at, target_end, path).await?;
                    let what = shown
                        .summary
                        .clone()
                        .unwrap_or_else(|| describe(t).to_owned());
                    shown
                        .renamed(node.name)
                        .span(span)
                        .summary(format!("link to object #{i}, {what}"))
                        .target(target)
                }
                _ => node
                    .value(Value::Text(format!("object #{i}")))
                    .summary("object link")
                    .diag(Diagnostic::malformed(format!("no object #{i} before it"))),
            }
        }
        b'I' => {
            // The inner value, with the instance variables after it.
            let inner_at = start.saturating_add(1);
            let inner_end = end_of(r, inner_at).await?;
            let inner = head(r, inner_at).await?;
            match inner.tag {
                b'"' | b'/' => {
                    let enc = encoding(r, inner_end).await?;
                    let (b, len, n) =
                        byte_string(r, inner_at.saturating_add(1), vt::MAX_TEXT).await?;
                    let node = if inner.tag == b'"' {
                        string_node(node, b, len, enc.as_deref())
                    } else {
                        let opts = r
                            .byte(
                                inner_at
                                    .saturating_add(1)
                                    .saturating_add(n)
                                    .saturating_add(len),
                            )
                            .await?;
                        node.value(Value::Text(format!(
                            "/{}/{}",
                            String::from_utf8_lossy(&b),
                            regexp_options(opts)
                        )))
                        .summary(format!("regexp, {}", enc.unwrap_or_default()))
                    };
                    node.lazy(
                        crate::expander!(self::ivars: (Input, u64, u64, Path)),
                        (input, start, inner_end, path.clone()),
                    )
                }
                b'u' => {
                    // `_dump` data with instance variables: a Time's
                    // offset, zone and nanoseconds are among them.
                    let class = symbol_at(r, inner_at.saturating_add(1))
                        .await?
                        .unwrap_or_default();
                    let time = match class.as_str() {
                        "Time" => time_of(r, inner_at, inner_end).await?,
                        _ => None,
                    };
                    match time {
                        Some((t, extra)) => {
                            lazy_members(node, format!("Time, {}", t.text(Some(&extra)))).value(
                                Value::Timestamp {
                                    unix_seconds: t.unix_seconds(),
                                },
                            )
                        }
                        None => lazy_members(
                            node,
                            format!("{class}, _dump data, with instance variables"),
                        ),
                    }
                }
                _ => lazy_members(
                    node,
                    format!("{}, with instance variables", describe(inner.tag)),
                ),
            }
        }
        b'[' => {
            let (k, _) = count_at(r, start.saturating_add(1)).await?;
            if k == 0 {
                node.summary("array, empty")
            } else {
                lazy_members(node, vt::array_summary("array", Some(k)))
            }
        }
        b'{' | b'}' => {
            let (k, _) = count_at(r, start.saturating_add(1)).await?;
            let kind = if it.tag == b'}' {
                "hash with default"
            } else {
                "hash"
            };
            lazy_members(node, vt::map_summary(kind, Some(k), "entry", "entries"))
        }
        b'o' | b'S' | b'u' | b'U' | b'd' | b'C' | b'e' => {
            let class = symbol_at(r, start.saturating_add(1))
                .await?
                .unwrap_or_default();
            let kind = describe(it.tag);
            match it.tag {
                b'u' => {
                    let sym_end = end_of(r, start.saturating_add(1)).await?;
                    let (b, len, n) = byte_string(r, sym_end, vt::MAX_TEXT).await?;
                    let data_at = sym_end.saturating_add(n);
                    let state = (input, start, sym_end, data_at, len);
                    if class == "Time"
                        && let Some(t) = PackedTime::decode(&b)
                    {
                        // Time#_dump: the time in UTC, packed into 8 bytes.
                        return Ok(node
                            .value(Value::Timestamp {
                                unix_seconds: t.unix_seconds(),
                            })
                            .summary(if t.utc || t.old {
                                format!("Time, {}", t.text(None))
                            } else {
                                format!("Time, {} (a local time, stored in UTC)", t.text(None))
                            })
                            .lazy(crate::expander!(self::user_dump: Dump), state));
                    }
                    if len > 2 && b.starts_with(&[4, 8]) {
                        // _dump data that is itself a Marshal stream
                        // (Gem::Specification, Gem::Version, ...).
                        return Ok(node
                            .summary(format!("{class}, {kind}, a Marshal stream of {len} bytes"))
                            .lazy(crate::expander!(self::user_dump: Dump), state));
                    }
                    let node = node.summary(format!("{class}, {kind}"));
                    if std::str::from_utf8(&b).is_ok_and(|s| !s.chars().any(char::is_control)) {
                        vt::text(node, &b, len).summary(format!("{class}, {kind}"))
                    } else {
                        let shown = b.into_iter().take(vt::MAX_BYTES as usize).collect();
                        vt::bytes(node, &format!("{class}, {kind}"), shown, len)
                    }
                }
                b'e' => lazy_members(node, format!("extended with {class}")),
                _ => lazy_members(node, format!("{class}, {kind}")),
            }
        }
        _ => node.diag(Diagnostic::malformed(format!("type byte {:#04x}", it.tag))),
    })
}

/// `_dump` data (`u`): the value at `start`, its class symbol ending at
/// the second offset, and its data (offset and length).
type Dump = (Input, u64, u64, u64, u64);

/// The class and the data of `_dump` data: a Time's packed fields, or a
/// nested Marshal stream.
async fn user_dump(cx: Cx, (input, start, sym_end, data_at, len): Dump) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let class_at = start.saturating_add(1);
    let class = symbol_at(&mut r, class_at).await?.unwrap_or_default();
    cx.emit(
        Node::new("Class")
            .span(r.span(class_at, sym_end.saturating_sub(class_at)))
            .value(Value::Text(class.clone())),
    );
    cx.emit(
        Node::new("Length")
            .span(r.span(sym_end, data_at.saturating_sub(sym_end)))
            .value(vt::uint(len, 32)),
    );
    let data = r.span(data_at, len);
    let b = r.bytes(data_at, len.min(8)).await?;
    match PackedTime::decode(&b).filter(|_| class == "Time" && len == 8) {
        Some(t) => {
            let p = r.span(data_at, 4);
            let s = r.span(data_at.saturating_add(4), 4);
            let field = |name: &str, span: Span, v: u64, bits: u8| {
                Node::new(name.to_owned())
                    .span(span)
                    .value(vt::uint(v, bits))
            };
            if t.old {
                cx.emit(
                    Node::new("Seconds")
                        .span(p)
                        .value(Value::Timestamp {
                            unix_seconds: t.unix_seconds(),
                        })
                        .desc("Old format: seconds since 1970, then microseconds"),
                );
            } else {
                cx.emit(
                    Node::new("UTC")
                        .span(p)
                        .value(Value::Bool(t.utc))
                        .desc("Bit 30: a UTC time; otherwise local, offset in :offset"),
                );
                cx.emit(field("Year", p, t.year, 16).desc("Bits 14-29: year - 1900"));
                cx.emit(field("Month", p, t.mon.saturating_add(1), 4));
                cx.emit(field("Day", p, t.mday, 5));
                cx.emit(field("Hour", p, t.hour, 5));
                cx.emit(field("Minute", s, t.min, 6));
                cx.emit(field("Second", s, t.sec, 6));
            }
            cx.emit(field("Microseconds", s, t.usec, 20));
        }
        None if b.starts_with(&[4, 8]) => cx.emit(crate::formats::embedded_as(
            "Data",
            input.nested(data),
            &FORMAT,
        )),
        None => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

/// `Time#_dump`'s 8 bytes (`marshal_time` in Ruby's `time.c`, from
/// memory): two little-endian words. The first holds bit 31 (set: this
/// layout), bit 30 (UTC), the year - 1900 (16 bits), month - 1 (4), day
/// (5) and hour (5); the second minute (6), second (6) and microseconds
/// (20), all in UTC. With bit 31 clear (Ruby before 1.9) the words are
/// seconds since 1970 and microseconds.
#[derive(Clone, Copy, Debug)]
struct PackedTime {
    old: bool,
    utc: bool,
    year: u64,
    mon: u64,
    mday: u64,
    hour: u64,
    min: u64,
    sec: u64,
    usec: u64,
    seconds: u64,
}

/// What a Time's instance variables add: the UTC offset of a local
/// time, nanoseconds beyond the microseconds, the zone name and a year
/// too large for 16 bits.
#[derive(Clone, Debug, Default)]
struct TimeExtra {
    offset: Option<i64>,
    nano: Option<(i64, i64)>,
    submicro: Option<Vec<u8>>,
    zone: Option<String>,
    year: Option<i64>,
}

impl PackedTime {
    fn decode(b: &[u8]) -> Option<Self> {
        let p = u64::from(u32::from_le_bytes(b.get(..4)?.try_into().ok()?));
        let s = u64::from(u32::from_le_bytes(b.get(4..8)?.try_into().ok()?));
        let t = PackedTime {
            old: p & 1 << 31 == 0,
            utc: p & 1 << 30 != 0,
            year: (p >> 14 & 0xffff).saturating_add(1900),
            mon: p >> 10 & 0xf,
            mday: p >> 5 & 0x1f,
            hour: p & 0x1f,
            min: s >> 26 & 0x3f,
            sec: s >> 20 & 0x3f,
            usec: s & 0xf_ffff,
            seconds: p,
        };
        if t.old {
            return (s < 1_000_000).then_some(PackedTime { usec: s, ..t });
        }
        (t.mon < 12 && (1..=31).contains(&t.mday) && t.hour < 24 && t.min < 60 && t.sec < 61)
            .then_some(t)
    }

    fn unix_seconds(&self) -> i64 {
        if self.old {
            return i64::try_from(self.seconds).unwrap_or(0);
        }
        self.unix_with_year(i64::try_from(self.year).unwrap_or(0))
    }

    fn unix_with_year(&self, year: i64) -> i64 {
        let n = |v: u64| u32::try_from(v).unwrap_or(0);
        crate::formats::util::civil::civil_to_unix(
            year,
            n(self.mon.saturating_add(1)),
            n(self.mday),
            n(self.hour),
            n(self.min),
            n(self.sec),
        )
    }

    /// The time as Ruby shows it: local with its offset, or UTC.
    fn text(&self, extra: Option<&TimeExtra>) -> String {
        let mut nanos = self.usec.saturating_mul(1000);
        let mut unix = self.unix_seconds();
        if let Some(x) = extra {
            if let Some(year) = x.year.filter(|_| !self.old) {
                unix = self.unix_with_year(year);
            }
            match (x.nano, &x.submicro) {
                (Some((num, den)), _) if den > 0 && num >= 0 => {
                    nanos = nanos.saturating_add(
                        u64::try_from(num.checked_div(den).unwrap_or(0)).unwrap_or(0),
                    );
                }
                (_, Some(bcd)) => {
                    let digits = bcd.iter().flat_map(|&b| [b >> 4, b & 0xf]).take(3);
                    let mut scale = 100u64;
                    for d in digits {
                        nanos = nanos.saturating_add(u64::from(d.min(9)).saturating_mul(scale));
                        scale /= 10;
                    }
                }
                _ => {}
            }
        }
        let nanos = u32::try_from(nanos.min(999_999_999)).unwrap_or(0);
        let offset = extra
            .and_then(|x| x.offset)
            .filter(|_| !self.utc && !self.old);
        let mut text = match offset {
            Some(off) => {
                let local = vt::datetime(unix.saturating_add(off), nanos);
                let stem = local.strip_suffix(" UTC").unwrap_or(&local).to_owned();
                let sign = if off < 0 { '-' } else { '+' };
                let a = off.unsigned_abs();
                let (h, m, s) = (a / 3600, a / 60 % 60, a % 60);
                if s == 0 {
                    format!("{stem} {sign}{h:02}:{m:02}")
                } else {
                    format!("{stem} {sign}{h:02}:{m:02}:{s:02}")
                }
            }
            None => vt::datetime(unix, nanos),
        };
        if let Some(zone) = extra
            .and_then(|x| x.zone.as_deref())
            .filter(|z| !z.is_empty() && *z != "UTC")
        {
            text.push_str(&format!(" ({zone})"));
        }
        text
    }
}

/// The fixnum at `at`, if it is one.
async fn fixnum_at(r: &mut ByteReader<'_>, at: u64) -> Result<Option<i64>> {
    let it = head(r, at).await?;
    if it.tag != b'i' {
        return Ok(None);
    }
    let b = r
        .bytes(at.saturating_add(1), it.head.saturating_sub(1))
        .await?;
    Ok(packed(&b).map(|(v, _)| v))
}

/// The bytes of the string at `at` (bare or with an encoding), if it is one.
async fn string_at(r: &mut ByteReader<'_>, at: u64) -> Result<Option<Vec<u8>>> {
    let it = head(r, at).await?;
    let p = if it.tag == b'I' {
        at.saturating_add(1)
    } else {
        at
    };
    if head(r, p).await?.tag != b'"' {
        return Ok(None);
    }
    Ok(Some(byte_string(r, p.saturating_add(1), 64).await?.0))
}

/// The Time of the `I` value whose inner `_dump` data is at `inner_at`
/// (ending at `inner_end`): its packed fields and its instance variables.
async fn time_of(
    r: &mut ByteReader<'_>,
    inner_at: u64,
    inner_end: u64,
) -> Result<Option<(PackedTime, TimeExtra)>> {
    let sym_end = end_of(r, inner_at.saturating_add(1)).await?;
    let (b, len, _) = byte_string(r, sym_end, 8).await?;
    let Some(t) = PackedTime::decode(&b).filter(|_| len == 8) else {
        return Ok(None);
    };
    let mut x = TimeExtra::default();
    let (k, n) = count_at(r, inner_end).await?;
    let mut p = inner_end.saturating_add(n);
    let mut num = None;
    let mut den = None;
    for _ in 0..k.min(16) {
        let name = symbol_at(r, p).await?;
        let value_at = end_of(r, p).await?;
        let value_end = end_of(r, value_at).await?;
        match name.as_deref() {
            Some("offset") => x.offset = fixnum_at(r, value_at).await?,
            Some("nano_num") => num = fixnum_at(r, value_at).await?,
            Some("nano_den") => den = fixnum_at(r, value_at).await?,
            Some("year") => x.year = fixnum_at(r, value_at).await?,
            Some("submicro") => x.submicro = string_at(r, value_at).await?,
            Some("zone") => {
                x.zone = string_at(r, value_at)
                    .await?
                    .map(|z| String::from_utf8_lossy(&z).into_owned());
            }
            _ => {}
        }
        p = value_end;
    }
    x.nano = num.zip(den);
    Ok(Some((t, x)))
}

fn regexp_options(o: u8) -> String {
    let mut s = String::new();
    if o & 1 != 0 {
        s.push('i');
    }
    if o & 2 != 0 {
        s.push('x');
    }
    if o & 4 != 0 {
        s.push('m');
    }
    // Regexp::NOENCODING (/n); FIXEDENCODING (16) has no literal flag.
    if o & 0x20 != 0 {
        s.push('n');
    }
    s
}

/// A key's short text: symbols, strings and integers. `ivar` for the
/// names of instance variables and struct members, shown as Ruby shows
/// them (`@name`, `x`) rather than as symbols.
async fn key_name(r: &mut ByteReader<'_>, at: u64, index: u64, ivar: bool) -> Result<String> {
    if let Some(s) = symbol_at(r, at).await? {
        let s = if ivar { s } else { format!(":{s}") };
        return Ok(vt::key_name(&s, index));
    }
    let it = head(r, at).await?;
    let p = if it.tag == b'I' {
        at.saturating_add(1)
    } else {
        at
    };
    let inner = head(r, p).await?;
    Ok(match inner.tag {
        b'"' => {
            let (b, _, _) = byte_string(r, p.saturating_add(1), 0x200).await?;
            vt::key_name(&format!("{:?}", String::from_utf8_lossy(&b)), index)
        }
        b'i' => {
            let b = r
                .bytes(p.saturating_add(1), inner.head.saturating_sub(1))
                .await?;
            packed(&b).map_or_else(|| format!("key #{index}"), |(v, _)| v.to_string())
        }
        b'0' => "nil".to_owned(),
        _ => format!("key #{index}"),
    })
}

/// The members of the container at `start`: array elements, hash entries
/// (and the default), object and struct instance variables, the wrapped
/// value of `U`/`d`/`C`/`e` and the instance variables of an `I` value.
async fn members(cx: Cx, (input, start, path): (Input, u64, Path)) -> Result<()> {
    walk_members(cx, input, start, path, false).await
}

/// [`members`]; `top` for the file's own value, which is followed by a
/// check for trailing data once its end is reached.
async fn walk_members(cx: Cx, input: Input, start: u64, path: Path, top: bool) -> Result<()> {
    let region = input.span;
    let mut r = ByteReader::new(&cx, region);
    let it = head(&mut r, start).await?;
    let (mut pos, mut index) = match cx.resume::<(u64, u64)>() {
        Some(state) => state,
        None => {
            let mut pos = start.saturating_add(it.head);
            match it.tag {
                b'I' => {
                    // The wrapped value's own members first.
                    let inner_end = end_of(&mut r, pos).await?;
                    let node = value_node(&mut r, input, pos, inner_end, "Value".to_owned(), &path)
                        .await?;
                    cx.emit(node);
                    return ivars(cx, (input, start, inner_end, path)).await;
                }
                b'o' | b'S' | b'U' | b'd' | b'C' | b'e' => {
                    let sym_end = end_of(&mut r, pos).await?;
                    let label = if it.tag == b'e' { "Module" } else { "Class" };
                    let class = symbol_at(&mut r, pos).await?.unwrap_or_default();
                    cx.emit(
                        Node::new(label)
                            .span(r.span(pos, sym_end.saturating_sub(pos)))
                            .value(Value::Text(class)),
                    );
                    pos = sym_end;
                    if matches!(it.tag, b'U' | b'd' | b'C' | b'e') {
                        let end = end_of(&mut r, pos).await?;
                        let name = match it.tag {
                            b'U' => "Data",
                            b'd' => "Data",
                            _ => "Value",
                        };
                        let node =
                            value_node(&mut r, input, pos, end, name.to_owned(), &path).await?;
                        cx.emit(node);
                        return Ok(());
                    }
                    let (k, n) = count_at(&mut r, pos).await?;
                    cx.emit(
                        Node::new(if it.tag == b'S' {
                            "Members"
                        } else {
                            "Instance variables"
                        })
                        .span(r.span(pos, n))
                        .value(vt::uint(k, 32)),
                    );
                    pos = pos.saturating_add(n);
                }
                _ => {}
            }
            (pos, 0)
        }
    };
    let total = match it.tag {
        b'[' | b'{' | b'}' => count_at(&mut r, start.saturating_add(1)).await?.0,
        _ => {
            // Objects and structs: the count follows the class symbol.
            let sym_end = end_of(&mut r, start.saturating_add(1)).await?;
            count_at(&mut r, sym_end).await?.0
        }
    };
    if it.tag != b'}' {
        // The file's own value may be followed by trailing data.
        cx.set_count(if top {
            Count::AtLeast(total)
        } else {
            Count::Exact(total)
        });
    }
    let pairs = it.tag != b'[';
    while index < total {
        let at = (pos, index);
        cx.mark(move || at);
        let node = if pairs {
            let key_end = end_of(&mut r, pos).await?;
            let value_end = end_of(&mut r, key_end).await?;
            let name = key_name(&mut r, pos, index, matches!(it.tag, b'o' | b'S')).await?;
            let node = value_node(&mut r, input, key_end, value_end, name, &path)
                .await?
                .span(r.span(pos, value_end.saturating_sub(pos)));
            pos = value_end;
            node
        } else {
            let end = end_of(&mut r, pos).await?;
            let node = value_node(&mut r, input, pos, end, format!("[{index}]"), &path).await?;
            pos = end;
            node
        };
        cx.push(node).await;
        index = index.saturating_add(1);
    }
    if it.tag == b'}' && index == total {
        let end = end_of(&mut r, pos).await?;
        let node = value_node(&mut r, input, pos, end, "(default)".to_owned(), &path).await?;
        cx.push(node).await;
        pos = end;
    }
    if top && let Some(node) = trailing(region, pos) {
        cx.push(node).await;
    }
    Ok(())
}

/// The instance variables of the `I` value at `start` (its inner value
/// ends at `inner_end`).
async fn ivars(cx: Cx, (input, start, inner_end, path): (Input, u64, u64, Path)) -> Result<()> {
    let _ = start;
    let mut r = ByteReader::new(&cx, input.span);
    let (k, n) = count_at(&mut r, inner_end).await?;
    cx.emit(
        Node::new("Instance variables")
            .span(r.span(inner_end, n))
            .value(vt::uint(k, 32)),
    );
    let mut pos = inner_end.saturating_add(n);
    for i in 0..k {
        let key_end = end_of(&mut r, pos).await?;
        let value_end = end_of(&mut r, key_end).await?;
        let name = key_name(&mut r, pos, i, true).await?;
        let mut node = value_node(&mut r, input, key_end, value_end, name.clone(), &path)
            .await?
            .span(r.span(pos, value_end.saturating_sub(pos)));
        if name == "E" {
            node = node.desc("true: UTF-8, false: US-ASCII");
        }
        cx.push(node).await;
        pos = value_end;
    }
    Ok(())
}

#[cfg(test)]
#[allow(clippy::unwrap_used)]
mod tests {
    use super::{packed, probe};
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
    fn a_cut_leaf_must_end_at_the_end_of_the_file() {
        // A binary or string of 65,536 bytes, cut by a 2 KiB window.
        let mut data = b"\x04\x08\"\x03\x00\x00\x01".to_vec();
        data.resize(2048, b'x');
        let at = |len: u64| Head {
            data: &data,
            tail: &data,
            len,
            len_known: true,
        };
        assert!(probe(&at(2 + 5 + 65_536)));
        assert!(!probe(&at(200_000)));
    }

    #[test]
    fn probe_needs_a_whole_value() {
        // [1, :a]
        let value = b"\x04\x08[\x07i\x06:\x06a";
        assert!(probe(&head(value)));
        assert!(!probe(&head(
            value
                .get(..value.len().saturating_sub(1))
                .unwrap_or_default()
        )));
        let mut longer = value.to_vec();
        longer.push(0);
        assert!(!probe(&head(&longer)));
        assert!(!probe(&head(b"\x04\x08hello, this is not marshal")));
        assert!(!probe(&head(b"\x04\x08")));
    }

    #[test]
    fn packed_ints() {
        assert_eq!(packed(&[0]), Some((0, 1)));
        assert_eq!(packed(&[0x06]), Some((1, 1)));
        assert_eq!(packed(&[0xfa]), Some((-1, 1)));
        assert_eq!(packed(&[0x01, 0xc8]), Some((200, 2)));
        assert_eq!(packed(&[0x03, 0x70, 0x11, 0x01]), Some((70000, 4)));
        assert_eq!(packed(&[0xff, 0x00]), Some((-256, 2)));
        assert_eq!(packed(&[0x80]), Some((-123, 1)));
    }
}
