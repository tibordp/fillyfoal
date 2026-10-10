//! Amazon Ion, binary (`.10n`) and text (`.ion`).
//!
//! Binary Ion starts with the version marker `E0 01 00 EA`. Every value
//! starts with a type descriptor (type in the high nibble, length in the
//! low one; 14 means a VarUInt length follows, 15 means a typed null), so
//! every value's size is known without scanning. Field names, symbol
//! values and annotations are symbol IDs: 1-9 are the system symbols,
//! later ones are defined by local symbol tables, top-level structs
//! annotated `$ion_symbol_table` that list new `symbols` and either
//! `imports` shared tables (whose symbols we cannot know, shown as `$N`)
//! or append to the current table. The top level is walked in order to
//! track the table in effect; containers are expanded lazily with it.
//! Timestamps (UTC with a local offset and a precision), decimals
//! (exponent and signed-magnitude coefficient) and big integers are
//! decoded.
//!
//! Text Ion is recognised only when it starts with the `$ion_1_0` version
//! marker (the marker is optional in Ion text, so other Ion text is left
//! to the plain text view or the extension). It is shown lightly: one node
//! per top-level value (annotations, kind, typed scalars, a preview of
//! containers), found by a scanner that understands strings, symbols,
//! comments, lobs and nesting.

use std::sync::Arc;

use crate::cx::Cx;
use crate::dsl::Path;
use crate::error::{Diagnostic, Result};
use crate::formats::text::scan::Scanner;
use crate::formats::util::datakit::{ByteReader, be_uint, clip};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

use super::valuetree as vt;

const BVM: &[u8] = b"\xe0\x01\x00\xea";

pub static FORMAT: Format = Format {
    name: "ion",
    title: "Amazon Ion (binary)",
    extensions: &["10n", "ion"],
    mime: "application/x-amzn-ion",
    probe: Probe::Magic(&[(0, BVM)]),
    dissect: crate::expander!(dissect: Input),
};

pub static TEXT: Format = Format {
    name: "ion-text",
    title: "Amazon Ion (text)",
    extensions: &["ion"],
    mime: "text/x-amzn-ion",
    probe: Probe::Custom(probe_text),
    dissect: crate::expander!(dissect_text: Input),
};

/// Ion 1.0 system symbols, IDs 1 to 9.
const SYSTEM: [&str; 9] = [
    "$ion",
    "$ion_1_0",
    "$ion_symbol_table",
    "name",
    "version",
    "imports",
    "symbols",
    "max_id",
    "$ion_shared_symbol_table",
];

const TYPES: [&str; 16] = [
    "null",
    "bool",
    "int",
    "int",
    "float",
    "decimal",
    "timestamp",
    "symbol",
    "string",
    "clob",
    "blob",
    "list",
    "sexp",
    "struct",
    "annotation",
    "reserved",
];

/// Symbols after the system table: runs of known texts and of symbols
/// imported from shared tables we do not have. A persistent list (newest
/// run first) with skip links, so a table that imports the current one
/// shares it, and a lookup takes logarithmic time in the number of runs.
#[derive(Clone, Debug, Default)]
struct Symbols {
    top: Option<Arc<Run>>,
}

#[derive(Clone, Debug)]
enum Segment {
    Known(Arc<Vec<Option<String>>>),
    Unknown(u64),
}

/// One run: symbols `start..end` (counted from SID 10).
#[derive(Debug)]
struct Run {
    segment: Segment,
    start: u64,
    end: u64,
    depth: u64,
    parent: Option<Arc<Run>>,
    /// An ancestor further back (skew-binary jump pointers).
    jump: Option<Arc<Run>>,
}

impl Drop for Run {
    /// Unlinks a long chain iteratively rather than recursively.
    fn drop(&mut self) {
        let mut next = self.parent.take();
        while let Some(run) = next {
            match Arc::try_unwrap(run) {
                Ok(mut run) => next = run.parent.take(),
                Err(_) => break,
            }
        }
    }
}

impl Symbols {
    /// These symbols followed by `segment`.
    fn with(&self, segment: Segment) -> Symbols {
        let parent = self.top.clone();
        let start = parent.as_ref().map_or(0, |p| p.end);
        let n = match &segment {
            Segment::Known(v) => vt_len(v.len()),
            Segment::Unknown(n) => *n,
        };
        let jump = parent.as_ref().map(|p| match &p.jump {
            Some(j)
                if j.jump.as_ref().is_some_and(|jj| {
                    p.depth.saturating_sub(j.depth) == j.depth.saturating_sub(jj.depth)
                }) =>
            {
                j.jump.clone().unwrap_or_else(|| p.clone())
            }
            _ => p.clone(),
        });
        Symbols {
            top: Some(Arc::new(Run {
                segment,
                start,
                end: start.saturating_add(n),
                depth: parent.as_ref().map_or(0, |p| p.depth.saturating_add(1)),
                parent,
                jump,
            })),
        }
    }

    /// The text of symbol `sid`, if known.
    fn text(&self, sid: u64) -> Option<&str> {
        if sid == 0 {
            return None;
        }
        if let Some(s) = usize::try_from(sid)
            .ok()
            .and_then(|i| SYSTEM.get(i.wrapping_sub(1)))
        {
            return Some(s);
        }
        let i = sid.saturating_sub(10);
        let mut run = self.top.as_deref()?;
        if i >= run.end {
            return None;
        }
        // Starts decrease towards the oldest run: find the newest run
        // starting at or before `i`.
        while run.start > i {
            run = match &run.jump {
                Some(j) if j.start > i => j,
                _ => run.parent.as_deref()?,
            };
        }
        match &run.segment {
            Segment::Known(v) => v
                .get(usize::try_from(i.saturating_sub(run.start)).ok()?)?
                .as_deref(),
            Segment::Unknown(_) => None,
        }
    }

    fn name(&self, sid: u64) -> String {
        self.text(sid)
            .map_or_else(|| format!("${sid}"), str::to_owned)
    }

    fn count(&self) -> u64 {
        9u64.saturating_add(self.top.as_ref().map_or(0, |t| t.end))
    }
}

fn vt_len(n: usize) -> u64 {
    crate::formats::util::datakit::len64(n)
}

/// A value header: type, length nibble, header bytes, payload bytes.
#[derive(Clone, Copy, Debug)]
struct Hdr {
    t: u8,
    l: u8,
    head: u64,
    len: u64,
    null: bool,
}

impl Hdr {
    fn end(&self, at: u64) -> u64 {
        at.saturating_add(self.head).saturating_add(self.len)
    }
}

fn bad(r: &ByteReader<'_>, at: u64, msg: impl Into<String>) -> Diagnostic {
    Diagnostic::malformed(msg).at(r.span(at, 1))
}

/// A VarUInt at `at`: `(value, bytes)`.
async fn varuint(r: &mut ByteReader<'_>, at: u64) -> Result<(u64, u64)> {
    let mut acc = 0u64;
    for i in 0..10u64 {
        let b = r.byte(at.saturating_add(i)).await?;
        if acc > u64::MAX >> 7 {
            break;
        }
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 != 0 {
            return Ok((acc, i.saturating_add(1)));
        }
    }
    Err(bad(r, at, "VarUInt too long"))
}

/// A VarInt at `at`: `(negative, magnitude, bytes)`.
async fn varint(r: &mut ByteReader<'_>, at: u64) -> Result<(bool, u64, u64)> {
    let first = r.byte(at).await?;
    let negative = first & 0x40 != 0;
    let mut acc = u64::from(first & 0x3f);
    if first & 0x80 != 0 {
        return Ok((negative, acc, 1));
    }
    for i in 1..10u64 {
        let b = r.byte(at.saturating_add(i)).await?;
        if acc > u64::MAX >> 7 {
            break;
        }
        acc = (acc << 7) | u64::from(b & 0x7f);
        if b & 0x80 != 0 {
            return Ok((negative, acc, i.saturating_add(1)));
        }
    }
    Err(bad(r, at, "VarInt too long"))
}

fn signed(negative: bool, magnitude: u64) -> i64 {
    let v = i64::try_from(magnitude).unwrap_or(i64::MAX);
    if negative { v.saturating_neg() } else { v }
}

/// The header of the value at `at`, which must end by `limit`.
async fn header(r: &mut ByteReader<'_>, at: u64, limit: u64) -> Result<Hdr> {
    let td = r.byte(at).await?;
    let (t, l) = (td >> 4, td & 0x0f);
    let mut h = Hdr {
        t,
        l,
        head: 1,
        len: 0,
        null: false,
    };
    match (t, l) {
        (15, _) => return Err(bad(r, at, "reserved type 15")),
        (14, 0..=2 | 15) => {
            return Err(bad(r, at, format!("invalid annotation wrapper {td:#04x}")));
        }
        (1, 2..=14) => return Err(bad(r, at, format!("invalid boolean {td:#04x}"))),
        (4, 1..=3 | 5..=7 | 9..=14) => return Err(bad(r, at, format!("invalid float length {l}"))),
        (_, 15) => h.null = true,
        (1, _) => {}
        (13, 1) | (_, 14) => {
            let (len, n) = varuint(r, at.saturating_add(1)).await?;
            h.head = n.saturating_add(1);
            h.len = len;
        }
        _ => h.len = u64::from(l),
    }
    if h.end(at) > limit {
        return Err(Diagnostic::truncated(
            r.span(at, h.head.saturating_add(h.len)),
            limit.saturating_sub(at),
        ));
    }
    Ok(h)
}

/// A signed-magnitude `Int` of `len` bytes: `(negative, magnitude bytes)`.
async fn int_field(r: &mut ByteReader<'_>, at: u64, len: u64) -> Result<(bool, Vec<u8>)> {
    let mut b = r.bytes(at, len.min(256)).await?;
    let negative = b.first().is_some_and(|&x| x & 0x80 != 0);
    if let Some(x) = b.first_mut() {
        *x &= 0x7f;
    }
    Ok((negative, b))
}

/// The local symbol table defined by the struct at `at` (body
/// `body..end`), given the table in effect.
async fn symbol_table(
    r: &mut ByteReader<'_>,
    body: u64,
    end: u64,
    current: &Symbols,
) -> Result<Symbols> {
    let mut imports: Option<Symbols> = None;
    let mut symbols: Vec<Option<String>> = Vec::new();
    let mut pos = body;
    while pos < end {
        r.cx().checkpoint().await;
        let (field, n) = varuint(r, pos).await?;
        let at = pos.saturating_add(n);
        let h = header(r, at, end).await?;
        let vbody = at.saturating_add(h.head);
        let vend = h.end(at);
        match (field, h.t, h.null) {
            // `imports: $ion_symbol_table`: append to the current table.
            (6, 7, false) if be_uint(&r.bytes(vbody, h.len.min(8)).await?) == 3 => {
                imports = Some(current.clone());
            }
            (6, 11, false) => {
                let mut segs = Symbols::default();
                let mut p = vbody;
                while p < vend {
                    r.cx().checkpoint().await;
                    let ih = header(r, p, vend).await?;
                    if ih.t == 13 && !ih.null {
                        let (name, max_id) =
                            import_entry(r, p.saturating_add(ih.head), ih.end(p)).await?;
                        if name.as_deref() != Some("$ion") {
                            segs = segs.with(Segment::Unknown(max_id));
                        }
                    }
                    p = ih.end(p);
                }
                imports = Some(segs);
            }
            (7, 11, false) => {
                let mut p = vbody;
                while p < vend {
                    r.cx().checkpoint().await;
                    let sh = header(r, p, vend).await?;
                    if sh.t == 8 && !sh.null {
                        let data = r
                            .bytes(p.saturating_add(sh.head), sh.len.min(vt::MAX_TEXT))
                            .await?;
                        symbols.push(Some(String::from_utf8_lossy(&data).into_owned()));
                    } else if sh.t != 0 || sh.null {
                        symbols.push(None);
                    }
                    p = sh.end(p);
                }
            }
            _ => {}
        }
        pos = vend;
    }
    Ok(imports
        .unwrap_or_default()
        .with(Segment::Known(Arc::new(symbols))))
}

/// `name` and `max_id` of an import struct.
async fn import_entry(
    r: &mut ByteReader<'_>,
    body: u64,
    end: u64,
) -> Result<(Option<String>, u64)> {
    let (mut name, mut max_id) = (None, 0u64);
    let mut pos = body;
    while pos < end {
        r.cx().checkpoint().await;
        let (field, n) = varuint(r, pos).await?;
        let at = pos.saturating_add(n);
        let h = header(r, at, end).await?;
        let vbody = at.saturating_add(h.head);
        match (field, h.t) {
            (4, 8) => {
                name = Some(
                    String::from_utf8_lossy(&r.bytes(vbody, h.len.min(0x200)).await?).into_owned(),
                )
            }
            (8, 2) => max_id = be_uint(&r.bytes(vbody, h.len.min(8)).await?),
            _ => {}
        }
        pos = h.end(at);
    }
    Ok((name, max_id))
}

/// Annotations of the wrapper at `at` and where its value starts.
async fn annotations(r: &mut ByteReader<'_>, at: u64, h: &Hdr) -> Result<(Vec<u64>, u64)> {
    let body = at.saturating_add(h.head);
    let (alen, n) = varuint(r, body).await?;
    let mut pos = body.saturating_add(n);
    let end = pos.saturating_add(alen);
    if alen == 0 || end >= h.end(at) {
        return Err(bad(r, at, "invalid annotation length"));
    }
    let mut sids = Vec::new();
    while pos < end {
        if sids.len().is_multiple_of(256) {
            r.cx().checkpoint().await;
        }
        let (sid, n) = varuint(r, pos).await?;
        sids.push(sid);
        pos = pos.saturating_add(n);
    }
    Ok((sids, end))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut r = ByteReader::new(&cx, input.span);
    let len = input.span.len;
    let (mut pos, mut index, mut symbols) =
        cx.resume::<(u64, u64, Arc<Symbols>)>()
            .unwrap_or((0, 0, Arc::new(Symbols::default())));
    if pos == 0 {
        cx.annotate("Amazon Ion 1.0 (binary)");
    }
    while pos < len {
        let at = (pos, index, symbols.clone());
        cx.mark(move || at);
        if r.bytes(pos, 4.min(len.saturating_sub(pos))).await? == BVM {
            symbols = Arc::new(Symbols::default());
            cx.push(
                Node::new("Ion version marker")
                    .span(r.span(pos, 4))
                    .value(Value::Text("1.0".into()))
                    .summary("resets the symbol table"),
            )
            .await;
            pos = pos.saturating_add(4);
            continue;
        }
        let h = header(&mut r, pos, len).await?;
        let end = h.end(pos);
        if h.t == 0 && !h.null {
            cx.push(
                Node::new("Padding")
                    .span(r.span(pos, end.saturating_sub(pos)))
                    .summary("NOP padding"),
            )
            .await;
            pos = end;
            continue;
        }
        let name = format!("Value {index}");
        let mut node = value_node(&mut r, pos, h, name, &symbols, &Path::new()).await?;
        // A local symbol table changes the symbols of what follows.
        if h.t == 14 {
            let (sids, inner) = annotations(&mut r, pos, &h).await?;
            let ih = header(&mut r, inner, end).await?;
            if sids.first() == Some(&3) && ih.t == 13 && !ih.null {
                symbols = Arc::new(
                    symbol_table(
                        &mut r,
                        inner.saturating_add(ih.head),
                        ih.end(inner),
                        &symbols,
                    )
                    .await?,
                );
                node = node.summary(format!(
                    "local symbol table, symbols up to ${}",
                    symbols.count()
                ));
            }
        }
        cx.progress(end, len);
        cx.push(node).await;
        pos = end;
        index = index.saturating_add(1);
    }
    Ok(())
}

/// Text of an Ion timestamp: `(display, UTC seconds)`.
async fn timestamp(r: &mut ByteReader<'_>, body: u64, end: u64) -> Result<(String, Option<i64>)> {
    let (off_neg, off_mag, n) = varint(r, body).await?;
    let mut pos = body.saturating_add(n);
    let unknown_offset = off_neg && off_mag == 0;
    let offset = signed(off_neg, off_mag);
    let mut fields = [0u64; 6];
    let mut count = 0usize;
    for slot in fields.iter_mut() {
        if pos >= end {
            break;
        }
        let (v, n) = varuint(r, pos).await?;
        *slot = v;
        pos = pos.saturating_add(n);
        count = count.saturating_add(1);
    }
    let [year, month, day, hour, minute, second] = fields;
    let mut frac = String::new();
    if pos < end {
        let (eneg, emag, n) = varint(r, pos).await?;
        pos = pos.saturating_add(n);
        let (cneg, coef) = int_field(r, pos, end.saturating_sub(pos)).await?;
        let digits = vt::magnitude_digits(&coef);
        let exp = signed(eneg, emag);
        if !cneg && exp < 0 {
            let width = usize::try_from(exp.saturating_neg()).unwrap_or(0);
            if digits.len() <= width {
                frac = format!(".{digits:0>width$}");
            }
        }
        if frac.is_empty() && !(digits == "0" && exp >= 0) {
            frac = format!(" (fraction {})", vt::decimal_string(cneg, &digits, exp));
        }
    }
    let days = crate::formats::util::civil::days_from_civil(
        i64::try_from(year).unwrap_or(0),
        i64::try_from(month.max(1)).unwrap_or(1),
        i64::try_from(day.max(1)).unwrap_or(1),
    );
    let Some(days) = days.filter(|_| hour < 24 && minute < 60 && second < 60) else {
        return Ok((format!("invalid timestamp {year}-{month}-{day}"), None));
    };
    let utc = days.saturating_mul(86_400).saturating_add(
        i64::try_from(
            hour.saturating_mul(3600)
                .saturating_add(minute.saturating_mul(60))
                .saturating_add(second),
        )
        .unwrap_or(0),
    );
    // Fields are UTC; the text form shows local time and the offset.
    let local = crate::render::value(&Value::Timestamp {
        unix_seconds: utc.saturating_add(offset.saturating_mul(60)),
    });
    let date = local.get(..10).unwrap_or_default();
    let time = local.get(11..19).unwrap_or_default();
    let off = if unknown_offset {
        "-00:00".to_owned()
    } else if offset == 0 {
        "Z".to_owned()
    } else {
        let a = offset.unsigned_abs();
        format!(
            "{}{:02}:{:02}",
            if offset < 0 { '-' } else { '+' },
            a / 60,
            a % 60
        )
    };
    let text = match count {
        0 | 1 => format!("{year:04}T"),
        2 => format!("{}T", date.get(..7).unwrap_or_default()),
        3 => format!("{date}T"),
        4 | 5 => format!("{date}T{}{off}", time.get(..5).unwrap_or_default()),
        _ => format!("{date}T{time}{frac}{off}"),
    };
    Ok((text, Some(utc)))
}

/// A node for the value at `at` with header `h`.
async fn value_node(
    r: &mut ByteReader<'_>,
    at: u64,
    h: Hdr,
    name: String,
    symbols: &Arc<Symbols>,
    path: &Path,
) -> Result<Node> {
    let end = h.end(at);
    let span = r.span(at, end.saturating_sub(at));
    if h.t == 14 {
        let (sids, inner) = annotations(r, at, &h).await?;
        let ih = header(r, inner, end).await?;
        if ih.end(inner) != end {
            return Err(bad(r, inner, "annotated value does not fill its wrapper"));
        }
        if ih.t == 14 {
            return Err(bad(r, inner, "nested annotation wrapper"));
        }
        let names: Vec<String> = sids.iter().map(|&s| symbols.name(s)).collect();
        let (node, summary) = plain_value(r, inner, ih, name, symbols, path).await?;
        let prefix = format!("{}::", names.join("::"));
        return Ok(node.span(span).summary(match summary {
            Some(s) => format!("{prefix} {s}"),
            None => prefix,
        }));
    }
    let (node, summary) = plain_value(r, at, h, name, symbols, path).await?;
    Ok(match summary {
        Some(s) => node.summary(s),
        None => node,
    })
}

/// A node for a value that is not an annotation wrapper, and its summary.
async fn plain_value(
    r: &mut ByteReader<'_>,
    at: u64,
    h: Hdr,
    name: String,
    symbols: &Arc<Symbols>,
    path: &Path,
) -> Result<(Node, Option<String>)> {
    let end = h.end(at);
    let node = Node::new(name).span(r.span(at, end.saturating_sub(at)));
    let body = at.saturating_add(h.head);
    let kind = TYPES.get(usize::from(h.t)).copied().unwrap_or("?");
    if h.null {
        return Ok((
            node,
            Some(if h.t == 0 {
                "null".to_owned()
            } else {
                format!("null.{kind}")
            }),
        ));
    }
    Ok(match h.t {
        0 => (node, Some("NOP padding".to_owned())),
        1 => (node.value(Value::Bool(h.l == 1)), None),
        2 | 3 => {
            let b = r.bytes(body, h.len.min(256)).await?;
            let negative = h.t == 3;
            let node = if b.len() <= 8 && h.len <= 8 {
                let mag = be_uint(&b);
                if negative {
                    match i64::try_from(mag) {
                        Ok(v) => node.value(vt::int(v.saturating_neg(), 64)),
                        Err(_) if mag == 1u64 << 63 => node.value(vt::int(i64::MIN, 64)),
                        Err(_) => node.value(Value::Text(format!("-{mag}"))),
                    }
                } else {
                    node.value(vt::uint(mag, 64))
                }
            } else {
                let digits = vt::magnitude_digits(&b);
                node.value(Value::Text(if negative {
                    format!("-{digits}")
                } else {
                    digits
                }))
            };
            if negative && b.iter().all(|&x| x == 0) {
                (
                    node.diag(Diagnostic::malformed("negative zero integer")),
                    None,
                )
            } else {
                (node, None)
            }
        }
        4 => {
            let b = r.bytes(body, h.len).await?;
            let v = match h.len {
                0 => 0.0,
                4 => f64::from(f32::from_bits(u32::try_from(be_uint(&b)).unwrap_or(0))),
                _ => f64::from_bits(be_uint(&b)),
            };
            (node.value(Value::Float(v)), None)
        }
        5 => {
            if h.len == 0 {
                return Ok((
                    node.value(Value::Text("0".into())),
                    Some("decimal".to_owned()),
                ));
            }
            let (eneg, emag, n) = varint(r, body).await?;
            let cpos = body.saturating_add(n);
            let (cneg, coef) = int_field(r, cpos, end.saturating_sub(cpos)).await?;
            let text = vt::decimal_string(cneg, &vt::magnitude_digits(&coef), signed(eneg, emag));
            (node.value(Value::Text(text)), Some("decimal".to_owned()))
        }
        6 => {
            let (text, utc) = timestamp(r, body, end).await?;
            match utc {
                Some(s) => (
                    node.value(Value::Timestamp { unix_seconds: s }),
                    Some(format!("timestamp {text}")),
                ),
                None => (
                    node.diag(Diagnostic::malformed(text)),
                    Some("timestamp".to_owned()),
                ),
            }
        }
        7 => {
            let sid = be_uint(&r.bytes(body, h.len.min(8)).await?);
            let node = node.value(Value::Text(symbols.name(sid)));
            (node, Some(format!("symbol ${sid}")))
        }
        8 => {
            let data = r.bytes(body, h.len.min(vt::MAX_TEXT)).await?;
            (vt::text(node, &data, h.len), None)
        }
        9 => {
            let data = r.bytes(body, h.len.min(vt::MAX_TEXT)).await?;
            let node = node.value(Value::Text(String::from_utf8_lossy(&data).into_owned()));
            (
                node,
                Some(format!(
                    "clob, {}",
                    crate::formats::text::plural(h.len, "byte", "bytes")
                )),
            )
        }
        10 => {
            let data = r.bytes(body, h.len.min(vt::MAX_BYTES)).await?;
            (vt::bytes(node, "blob", data, h.len), None)
        }
        11..=13 => {
            let node = if h.len == 0 {
                node
            } else {
                match vt::enter(path, at) {
                    Ok(p) => node.lazy(
                        crate::expander!(self::members: (Span, u64, Arc<Symbols>, Path)),
                        (r.region(), at, symbols.clone(), p),
                    ),
                    Err(d) => node.diag(d),
                }
            };
            let summary = if h.len == 0 {
                format!("{kind}, empty")
            } else {
                kind.to_owned()
            };
            (node, Some(summary))
        }
        _ => (node.diag(bad(r, at, "unexpected type")), None),
    })
}

async fn members(
    cx: Cx,
    (region, at, symbols, path): (Span, u64, Arc<Symbols>, Path),
) -> Result<()> {
    let mut r = ByteReader::new(&cx, region);
    let h = header(&mut r, at, region.len).await?;
    let end = h.end(at);
    let is_struct = h.t == 13;
    let (mut pos, mut index) = cx
        .resume::<(u64, u64)>()
        .unwrap_or((at.saturating_add(h.head), 0));
    while pos < end {
        let mark = (pos, index);
        cx.mark(move || mark);
        let (name, vat) = if is_struct {
            let (sid, n) = varuint(&mut r, pos).await?;
            (
                vt::key_name(&symbols.name(sid), index),
                pos.saturating_add(n),
            )
        } else {
            (format!("[{index}]"), pos)
        };
        let vh = header(&mut r, vat, end).await?;
        if vh.t == 0 && !vh.null {
            // NOP padding (with a field name in structs).
            pos = vh.end(vat);
            cx.checkpoint().await;
            continue;
        }
        let node = value_node(&mut r, vat, vh, name, &symbols, &path).await?;
        cx.push(node).await;
        pos = vh.end(vat);
        index = index.saturating_add(1);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Text Ion

const MARKER: &[u8] = b"$ion_1_0";

fn is_ident(b: u8) -> bool {
    b.is_ascii_alphanumeric() || b == b'_' || b == b'$'
}

fn probe_text(h: &Head<'_>) -> bool {
    let data = h.data.strip_prefix(b"\xef\xbb\xbf").unwrap_or(h.data);
    let start = data
        .iter()
        .position(|b| !b.is_ascii_whitespace())
        .unwrap_or(data.len());
    let rest = data.get(start..).unwrap_or_default();
    rest.starts_with(MARKER) && rest.get(MARKER.len()).is_none_or(|&b| !is_ident(b))
}

/// What a top-level text value is.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum TextKind {
    String,
    LongString,
    QuotedSymbol,
    Struct,
    List,
    Sexp,
    Lob,
    Token,
}

/// Skips whitespace and comments from `pos`.
async fn skip_space(sc: &mut Scanner<'_>, mut pos: u64) -> Result<u64> {
    loop {
        sc.tick().await;
        match sc.byte(pos).await? {
            Some(b) if b.is_ascii_whitespace() => pos = pos.saturating_add(1),
            Some(b'/') => match sc.byte(pos.saturating_add(1)).await? {
                Some(b'/') => {
                    pos = sc
                        .find(pos, |b| b == b'\n')
                        .await?
                        .map_or(sc.len(), |p| p.saturating_add(1));
                }
                Some(b'*') => {
                    pos = match sc.find_seq(pos.saturating_add(2), b"*/").await? {
                        Some(p) => p.saturating_add(2),
                        None => sc.len(),
                    };
                }
                _ => return Ok(pos),
            },
            _ => return Ok(pos),
        }
    }
}

/// The end of a quoted run starting at `pos` (the opening quote), honouring
/// backslash escapes; the end of the region if it is not closed.
async fn quoted(sc: &mut Scanner<'_>, pos: u64, quote: u8) -> Result<u64> {
    let mut p = pos.saturating_add(1);
    loop {
        sc.tick().await;
        match sc.byte(p).await? {
            None => return Ok(p),
            Some(b'\\') => p = p.saturating_add(2),
            Some(b) if b == quote => return Ok(p.saturating_add(1)),
            Some(_) => p = p.saturating_add(1),
        }
    }
}

/// The end of a `'''` string starting at `pos`.
async fn long_string(sc: &mut Scanner<'_>, pos: u64) -> Result<u64> {
    let mut p = pos.saturating_add(3);
    loop {
        sc.tick().await;
        match sc.byte(p).await? {
            None => return Ok(p),
            Some(b'\\') => p = p.saturating_add(2),
            Some(b'\'') if sc.matches(p, b"'''").await? => return Ok(p.saturating_add(3)),
            Some(_) => p = p.saturating_add(1),
        }
    }
}

/// The end of the container opened at `pos`.
async fn container_end(sc: &mut Scanner<'_>, pos: u64) -> Result<u64> {
    let mut depth = 0u64;
    let mut p = pos;
    loop {
        sc.tick().await;
        let Some(b) = sc.byte(p).await? else {
            return Ok(p);
        };
        match b {
            b'"' => p = quoted(sc, p, b'"').await?,
            b'\'' if sc.matches(p, b"'''").await? => p = long_string(sc, p).await?,
            b'\'' => p = quoted(sc, p, b'\'').await?,
            b'/' if matches!(sc.byte(p.saturating_add(1)).await?, Some(b'/' | b'*')) => {
                p = skip_space(sc, p).await?
            }
            b'{' if sc.byte(p.saturating_add(1)).await? == Some(b'{') => {
                p = lob_end(sc, p).await?;
            }
            b'{' | b'[' | b'(' => {
                depth = depth.saturating_add(1);
                p = p.saturating_add(1);
            }
            b'}' | b']' | b')' => {
                depth = depth.saturating_sub(1);
                p = p.saturating_add(1);
                if depth == 0 {
                    return Ok(p);
                }
            }
            _ => p = p.saturating_add(1),
        }
    }
}

/// The end of a `{{ ... }}` lob starting at `pos`.
async fn lob_end(sc: &mut Scanner<'_>, pos: u64) -> Result<u64> {
    let mut p = pos.saturating_add(2);
    loop {
        sc.tick().await;
        match sc.byte(p).await? {
            None => return Ok(p),
            Some(b'"') => p = quoted(sc, p, b'"').await?,
            Some(b'\'') if sc.matches(p, b"'''").await? => p = long_string(sc, p).await?,
            Some(b'}') if sc.byte(p.saturating_add(1)).await? == Some(b'}') => {
                return Ok(p.saturating_add(2));
            }
            Some(_) => p = p.saturating_add(1),
        }
    }
}

/// The end of a bare token (number, identifier, timestamp, `null.int`).
async fn token_end(sc: &mut Scanner<'_>, pos: u64) -> Result<u64> {
    let mut p = pos;
    loop {
        sc.tick().await;
        match sc.byte(p).await? {
            Some(b) if b.is_ascii_whitespace() || b",{}[]()\"'".contains(&b) => return Ok(p),
            Some(b'/') if matches!(sc.byte(p.saturating_add(1)).await?, Some(b'/' | b'*')) => {
                return Ok(p);
            }
            Some(b':') if sc.byte(p.saturating_add(1)).await? == Some(b':') => return Ok(p),
            None => return Ok(p),
            Some(_) => p = p.saturating_add(1),
        }
    }
}

/// One datum at `pos`: its kind and end.
async fn datum(sc: &mut Scanner<'_>, pos: u64) -> Result<(TextKind, u64)> {
    let b = sc.byte(pos).await?.unwrap_or(0);
    Ok(match b {
        b'"' => (TextKind::String, quoted(sc, pos, b'"').await?),
        b'\'' if sc.matches(pos, b"'''").await? => {
            // Adjacent long strings form one value.
            let mut end = long_string(sc, pos).await?;
            loop {
                let next = skip_space(sc, end).await?;
                if sc.matches(next, b"'''").await? {
                    end = long_string(sc, next).await?;
                } else {
                    break;
                }
            }
            (TextKind::LongString, end)
        }
        b'\'' => (TextKind::QuotedSymbol, quoted(sc, pos, b'\'').await?),
        b'{' if sc.byte(pos.saturating_add(1)).await? == Some(b'{') => {
            (TextKind::Lob, lob_end(sc, pos).await?)
        }
        b'{' => (TextKind::Struct, container_end(sc, pos).await?),
        b'[' => (TextKind::List, container_end(sc, pos).await?),
        b'(' => (TextKind::Sexp, container_end(sc, pos).await?),
        _ => {
            let end = token_end(sc, pos).await?;
            // A stray delimiter: consume it so the walk progresses.
            (
                TextKind::Token,
                if end == pos {
                    pos.saturating_add(1)
                } else {
                    end
                },
            )
        }
    })
}

pub async fn dissect_text(cx: Cx, input: Input) -> Result<()> {
    let mut sc = Scanner::new(&cx, input.span);
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    if pos == 0 {
        cx.annotate("Amazon Ion 1.0 (text)");
        if sc.matches(0, b"\xef\xbb\xbf").await? {
            pos = 3;
        }
    }
    loop {
        pos = skip_space(&mut sc, pos).await?;
        if pos >= sc.len() {
            break;
        }
        let at = (pos, index);
        cx.mark(move || at);
        let start = pos;
        // Annotations: symbols followed by `::`.
        let mut annotations = Vec::new();
        let (mut kind, mut end) = datum(&mut sc, pos).await?;
        loop {
            let after = skip_space(&mut sc, end).await?;
            if matches!(kind, TextKind::Token | TextKind::QuotedSymbol)
                && sc.matches(after, b"::").await?
            {
                let text = sc.bytes(pos, end, 0x200).await?;
                annotations.push(String::from_utf8_lossy(&text).into_owned());
                pos = skip_space(&mut sc, after.saturating_add(2)).await?;
                (kind, end) = datum(&mut sc, pos).await?;
            } else {
                break;
            }
        }
        let node = text_value(&mut sc, start, pos, end, kind, &annotations, index).await?;
        let marker = node.name == "Ion version marker";
        cx.progress(end, sc.len());
        cx.push(node).await;
        pos = end;
        if !marker {
            index = index.saturating_add(1);
        }
    }
    Ok(())
}

/// A node for a top-level text value whose datum is `pos..end`.
async fn text_value(
    sc: &mut Scanner<'_>,
    start: u64,
    pos: u64,
    end: u64,
    kind: TextKind,
    annotations: &[String],
    index: u64,
) -> Result<Node> {
    let raw = sc.bytes(pos, end, vt::MAX_TEXT as usize).await?;
    let text = String::from_utf8_lossy(&raw).into_owned();
    let span = sc.span(start, end);
    let complete = vt_len(raw.len()) == end.saturating_sub(pos);
    let mut node = Node::new(format!("Value {index}")).span(span);
    let what: String = match kind {
        TextKind::String => {
            node = node.value(Value::Text(
                text.get(1..text.len().saturating_sub(1))
                    .unwrap_or_default()
                    .to_owned(),
            ));
            "string".into()
        }
        TextKind::LongString => {
            node = node.value(Value::Text(clip(&text, 200)));
            "long string".into()
        }
        TextKind::QuotedSymbol => {
            node = node.value(Value::Text(
                text.get(1..text.len().saturating_sub(1))
                    .unwrap_or_default()
                    .to_owned(),
            ));
            "symbol".into()
        }
        TextKind::Lob => {
            let inner = text
                .get(2..text.len().saturating_sub(2))
                .unwrap_or_default()
                .trim();
            node = node.value(Value::Text(clip(inner, 200)));
            if inner.starts_with('"') || inner.starts_with('\'') {
                "clob".into()
            } else {
                "blob (base64)".into()
            }
        }
        TextKind::Struct | TextKind::List | TextKind::Sexp => {
            let preview: String = text.split_whitespace().collect::<Vec<_>>().join(" ");
            node = node.value(Value::Text(clip(&preview, 80)));
            match kind {
                TextKind::Struct => "struct".into(),
                TextKind::List => "list".into(),
                _ => "sexp".into(),
            }
        }
        TextKind::Token => {
            if text == "$ion_1_0" && annotations.is_empty() {
                return Ok(Node::new("Ion version marker")
                    .span(span)
                    .value(Value::Text("1.0".into())));
            }
            match text.as_str() {
                "true" | "false" => {
                    node = node.value(Value::Bool(text == "true"));
                    "bool".into()
                }
                t if t == "null" || t.starts_with("null.") => t.to_owned(),
                t if t.starts_with(|c: char| c.is_ascii_digit() || c == '-' || c == '+') => {
                    if let Some(v) = crate::formats::text::number(t) {
                        node = node.value(v);
                        "number".into()
                    } else {
                        node = node.value(Value::Text(t.to_owned()));
                        if t.contains('T') && t.get(4..5) == Some("-") || t.ends_with('T') {
                            "timestamp".into()
                        } else if t.contains('d') || t.contains('D') || t.contains('.') {
                            "decimal".into()
                        } else {
                            "number".into()
                        }
                    }
                }
                t => {
                    node = node.value(Value::Text(t.to_owned()));
                    "symbol".into()
                }
            }
        }
    };
    let prefix = if annotations.is_empty() {
        String::new()
    } else {
        format!("{}:: ", annotations.join("::"))
    };
    let mut node = node.summary(format!("{prefix}{what}"));
    if !complete && !matches!(kind, TextKind::Struct | TextKind::List | TextKind::Sexp) {
        node = node.diag(Diagnostic::note(format!("first {} bytes shown", raw.len())));
    }
    let closer: &[u8] = match kind {
        TextKind::String => b"\"",
        TextKind::LongString | TextKind::QuotedSymbol => b"'",
        TextKind::Struct => b"}",
        TextKind::List => b"]",
        TextKind::Sexp => b")",
        TextKind::Lob => b"}}",
        TextKind::Token => b"",
    };
    let closed = end.saturating_sub(pos) > vt_len(closer.len())
        && sc
            .matches(end.saturating_sub(vt_len(closer.len())), closer)
            .await?;
    if !closer.is_empty() && !closed {
        node = node.diag(Diagnostic::malformed(
            "not closed before the end of the file",
        ));
    }
    Ok(node)
}
