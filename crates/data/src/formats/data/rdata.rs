//! R serialization (RDS/RData) and ASDF files.

use std::collections::BTreeMap;
use std::sync::{Arc, Mutex};

use crate::bytes::{to_u64, to_usize, u16_be, u64_be};
use crate::cx::{Cx, lock};
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::text;
use crate::formats::{Head, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

// ---------------------------------------------------------------------------
// Data: R serialization (RDS/RData)
//
// A stream (R's `serialize.c`) is a format marker (`X\n` XDR big-endian,
// `B\n` native little-endian, `A\n` ASCII), the serialization version, the
// writing and minimum reading R versions, in version 3 the native
// encoding, then one item. An item is a flags word (type in the low byte,
// then object, attribute and tag bits, and "levels"), then a payload that
// depends on the type: vectors are a length and their elements (strings
// and lists hold items), pairlists and language objects are cells of
// [attributes] [tag] CAR CDR, and attributes follow other payloads.
// Symbols, environments and a few other items enter a reference table
// that later `REFSXP` items point into.

/// A serialization's format marker and the RData signature it goes with.
const R_FORMATS: [(u8, &[u8]); 3] = [(b'X', b"RDX"), (b'A', b"RDA"), (b'B', b"RDB")];

fn r_probe(h: &Head<'_>) -> bool {
    let data = h.data;
    let body = match data.get(..5) {
        Some([b'R', b'D', f, v, b'\n'])
            if matches!(v, b'2' | b'3') && R_FORMATS.iter().any(|(c, _)| c == f) =>
        {
            if data.get(5) != Some(f) {
                return false;
            }
            data.get(5..).unwrap_or_default()
        }
        _ => data,
    };
    match body {
        [b'X', b'\n', 0, 0, 0, 2 | 3, ..] | [b'B', b'\n', 2 | 3, 0, 0, 0, ..] => true,
        [b'A', b'\n', b'2' | b'3', b'\n', rest @ ..] => {
            // Two more version numbers, one per line.
            let mut lines = rest.split(|&b| b == b'\n');
            (0..2).all(|_| {
                lines.next().is_some_and(|l| {
                    !l.is_empty() && l.len() <= 10 && l.iter().all(u8::is_ascii_digit)
                })
            })
        }
        _ => false,
    }
}

declare_format!(pub R_DATA = "r-serialized", "R serialized data (RDS/RData)", ["rds", "rdata", "rda"], "application/x-r-data",
    Probe::Custom(r_probe), r_data);

const SEXP_TYPES: EnumTable = &[
    (0, "NULL"),
    (1, "symbol"),
    (2, "pairlist"),
    (3, "closure"),
    (4, "environment"),
    (5, "promise"),
    (6, "language"),
    (7, "special function"),
    (8, "builtin function"),
    (9, "string (CHARSXP)"),
    (10, "logical vector"),
    (13, "integer vector"),
    (14, "double vector"),
    (15, "complex vector"),
    (16, "character vector"),
    (17, "dot-dot-dot"),
    (18, "any"),
    (19, "list"),
    (20, "expression vector"),
    (21, "byte code"),
    (22, "external pointer"),
    (23, "weak reference"),
    (24, "raw vector"),
    (25, "S4 object"),
    (238, "ALTREP"),
    (239, "pairlist with attributes (byte code)"),
    (240, "language with attributes (byte code)"),
    (241, "base environment"),
    (242, "empty environment"),
    (243, "byte code reference"),
    (244, "byte code definition"),
    (245, "generic reference"),
    (246, "class reference"),
    (247, "persistent name"),
    (248, "package environment"),
    (249, "namespace"),
    (250, "base namespace"),
    (251, "missing argument"),
    (252, "unbound value"),
    (253, "global environment"),
    (254, "NULL"),
    (255, "reference"),
];

const REFSXP: u32 = 255;
const NILVALUE: u32 = 254;
/// R's NA_real_: a NaN whose low word is 1954.
const NA_REAL: u64 = 0x7ff0_0000_0000_07a2;
/// Bytes read at once.
const R_WINDOW: usize = 64 * 1024;
/// Bytes of a string kept for display.
const R_MAX_STR: u64 = 4096;
/// Pending tasks of the item skipper (nesting of byte code).
const R_MAX_STACK: usize = 1 << 16;
/// Names kept to label vector elements.
const R_MAX_NAMES: u64 = 1 << 16;
/// Reference table entries remembered.
const R_MAX_REFS: usize = 1 << 20;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum RFmt {
    Xdr,
    Native,
    Ascii,
}

/// What a stream's items share: where it is, its format and the labels of
/// its reference table, filled in as items are passed.
struct RCtx {
    span: Span,
    fmt: RFmt,
    refs: Mutex<BTreeMap<u64, String>>,
}

impl RCtx {
    fn register(&self, refs: &mut u64, label: impl FnOnce() -> String) {
        *refs = refs.saturating_add(1);
        let mut t = lock(&self.refs);
        if t.len() < R_MAX_REFS && !t.contains_key(refs) {
            t.insert(*refs, label());
        }
    }

    fn lookup(&self, index: u64) -> Option<String> {
        lock(&self.refs).get(&index).cloned()
    }
}

/// A buffered reader of a stream's ints, doubles and strings.
struct Rd<'a> {
    cx: &'a Cx,
    span: Span,
    fmt: RFmt,
    pos: u64,
    /// Where the last value read started (after any whitespace).
    start: u64,
    buf: Vec<u8>,
    at: u64,
}

impl<'a> Rd<'a> {
    fn new(cx: &'a Cx, ctx: &RCtx, pos: u64) -> Rd<'a> {
        Rd {
            cx,
            span: ctx.span,
            fmt: ctx.fmt,
            pos,
            start: pos,
            buf: Vec::new(),
            at: 0,
        }
    }

    fn seek(&mut self, pos: u64) {
        self.pos = pos;
    }

    /// Up to `n` bytes from the current position, refilling the buffer.
    async fn avail(&mut self, n: usize) -> Result<&[u8]> {
        let off = self.pos.checked_sub(self.at).map(to_usize);
        let have = off.map_or(0, |o| self.buf.len().saturating_sub(o));
        if have < n {
            let want = to_u64(n.max(R_WINDOW));
            self.buf = self.cx.read_avail(self.span.sub(self.pos, want)).await?;
            self.at = self.pos;
        }
        let off = to_usize(self.pos.saturating_sub(self.at));
        let end = off.saturating_add(n).min(self.buf.len());
        Ok(self.buf.get(off..end).unwrap_or_default())
    }

    /// Exactly `n` (at most a window) bytes.
    async fn take(&mut self, n: usize) -> Result<Vec<u8>> {
        let pos = self.pos;
        let span = self.span;
        let data = self.avail(n).await?.to_vec();
        if data.len() < n {
            return Err(Diagnostic::truncated(
                span.sub(pos, to_u64(n)),
                to_u64(data.len()),
            ));
        }
        self.start = pos;
        self.pos = pos.saturating_add(to_u64(n));
        Ok(data)
    }

    /// The next whitespace-separated word (ASCII format).
    async fn word(&mut self) -> Result<String> {
        loop {
            let chunk = self.avail(1).await?;
            match chunk.first() {
                None => return Err(Diagnostic::truncated(self.span.sub(self.pos, 1), 0)),
                Some(b) if b.is_ascii_whitespace() => self.pos = self.pos.saturating_add(1),
                Some(_) => break,
            }
        }
        self.start = self.pos;
        let mut out = String::new();
        while out.len() < 64 {
            let Some(&b) = self.avail(1).await?.first() else {
                break;
            };
            if b.is_ascii_whitespace() {
                break;
            }
            out.push(char::from(b));
            self.pos = self.pos.saturating_add(1);
        }
        Ok(out)
    }

    async fn int(&mut self) -> Result<i32> {
        match self.fmt {
            RFmt::Xdr => Ok(i32::from_be_bytes(self.array().await?)),
            RFmt::Native => Ok(i32::from_le_bytes(self.array().await?)),
            RFmt::Ascii => {
                let w = self.word().await?;
                if w == "NA" {
                    return Ok(i32::MIN);
                }
                w.parse().map_err(|_| {
                    Diagnostic::malformed(format!("invalid integer {w:?}"))
                        .at(self.span.sub(self.start, to_u64(w.len())))
                })
            }
        }
    }

    async fn array<const N: usize>(&mut self) -> Result<[u8; N]> {
        let data = self.take(N).await?;
        let mut out = [0u8; N];
        out.copy_from_slice(data.get(..N).unwrap_or(&[0u8; N]));
        Ok(out)
    }

    async fn double(&mut self) -> Result<f64> {
        match self.fmt {
            RFmt::Xdr => Ok(f64::from_be_bytes(self.array().await?)),
            RFmt::Native => Ok(f64::from_le_bytes(self.array().await?)),
            RFmt::Ascii => {
                let w = self.word().await?;
                let v = match w.as_str() {
                    "NA" => Some(f64::from_bits(NA_REAL)),
                    "NaN" => Some(f64::NAN),
                    "Inf" => Some(f64::INFINITY),
                    "-Inf" => Some(f64::NEG_INFINITY),
                    _ => w.parse().ok().or_else(|| hex_float(&w)),
                };
                v.ok_or_else(|| {
                    Diagnostic::malformed(format!("invalid number {w:?}"))
                        .at(self.span.sub(self.start, to_u64(w.len())))
                })
            }
        }
    }

    /// A length: an int, or -1 and two ints for a long vector.
    async fn length(&mut self) -> Result<u64> {
        let start = self.pos;
        let n = self.int().await?;
        if n >= 0 {
            return Ok(u64::from(n.unsigned_abs()));
        }
        if n != -1 {
            return Err(
                Diagnostic::malformed(format!("negative length {n}")).at(self.span.sub(start, 4))
            );
        }
        let hi = self.int().await?.cast_unsigned();
        let lo = self.int().await?.cast_unsigned();
        Ok(u64::from(hi) << 32 | u64::from(lo))
    }

    /// A string of `len` bytes, keeping the first `R_MAX_STR`.
    async fn string(&mut self, len: u64) -> Result<Vec<u8>> {
        let mut out = Vec::new();
        if self.fmt != RFmt::Ascii {
            let keep = to_usize(len.min(R_MAX_STR));
            let start = self.pos;
            out = self.take(keep).await?;
            self.skip(len.saturating_sub(to_u64(keep))).await?;
            self.start = start;
            return Ok(out);
        }
        if len == 0 {
            return Ok(out);
        }
        // Escaped as in C, with octal escapes for other bytes.
        loop {
            let Some(&b) = self.avail(1).await?.first() else {
                return Err(Diagnostic::truncated(self.span.sub(self.pos, 1), 0));
            };
            if !b.is_ascii_whitespace() {
                break;
            }
            self.pos = self.pos.saturating_add(1);
        }
        let start = self.pos;
        for i in 0..len {
            if i % 256 == 255 {
                self.cx.checkpoint().await;
            }
            let c = self.next_byte().await?;
            let byte = if c == b'\\' {
                match self.next_byte().await? {
                    b'n' => b'\n',
                    b't' => b'\t',
                    b'v' => 0x0b,
                    b'b' => 0x08,
                    b'r' => b'\r',
                    b'f' => 0x0c,
                    b'a' => 0x07,
                    d @ b'0'..=b'7' => {
                        let mut v = u32::from(d.saturating_sub(b'0'));
                        for _ in 0..2 {
                            match self.avail(1).await?.first() {
                                Some(&o @ b'0'..=b'7') => {
                                    v = v
                                        .saturating_mul(8)
                                        .saturating_add(u32::from(o.saturating_sub(b'0')));
                                    self.pos = self.pos.saturating_add(1);
                                }
                                _ => break,
                            }
                        }
                        u8::try_from(v & 0xff).unwrap_or(0)
                    }
                    other => other,
                }
            } else {
                c
            };
            if to_u64(out.len()) < R_MAX_STR {
                out.push(byte);
            }
        }
        self.start = start;
        Ok(out)
    }

    async fn next_byte(&mut self) -> Result<u8> {
        let Some(&b) = self.avail(1).await?.first() else {
            return Err(Diagnostic::truncated(self.span.sub(self.pos, 1), 0));
        };
        self.pos = self.pos.saturating_add(1);
        Ok(b)
    }

    /// Skips `n` bytes (binary formats).
    async fn skip(&mut self, n: u64) -> Result<()> {
        let end = self.pos.saturating_add(n);
        if end > self.span.len {
            return Err(Diagnostic::truncated(
                self.span.sub(self.pos, n),
                self.span.len.saturating_sub(self.pos),
            ));
        }
        self.pos = end;
        Ok(())
    }

    /// Skips `n` values of `size` bytes, or `words` words each in ASCII.
    async fn skip_values(&mut self, n: u64, size: u64, words: u64) -> Result<()> {
        if self.fmt != RFmt::Ascii {
            return self.skip(n.saturating_mul(size)).await;
        }
        let total = n.saturating_mul(words);
        for i in 0..total {
            if i % 64 == 63 {
                self.cx.checkpoint().await;
            }
            self.word().await?;
        }
        Ok(())
    }
}

/// A C99 hexadecimal float (`0x1.8p+1`), as R's `asciihex` format writes.
fn hex_float(w: &str) -> Option<f64> {
    let (neg, rest) = match w.strip_prefix('-') {
        Some(r) => (true, r),
        None => (false, w.strip_prefix('+').unwrap_or(w)),
    };
    let rest = rest
        .strip_prefix("0x")
        .or_else(|| rest.strip_prefix("0X"))?;
    let (mant, exp) = rest.split_once(['p', 'P'])?;
    let exp: i32 = exp.parse().ok()?;
    let (int, frac) = mant.split_once('.').unwrap_or((mant, ""));
    let mut v = 0f64;
    for c in int.chars() {
        v = v * 16.0 + f64::from(c.to_digit(16)?);
    }
    let mut scale = 1.0 / 16.0;
    for c in frac.chars() {
        v += f64::from(c.to_digit(16)?) * scale;
        scale /= 16.0;
    }
    let v = v * 2f64.powi(exp);
    Some(if neg { -v } else { v })
}

/// The parts of a flags word.
#[derive(Clone, Copy, Debug)]
struct Flags(u32);

impl Flags {
    fn ty(self) -> u32 {
        self.0 & 0xff
    }
    fn object(self) -> bool {
        self.0 & 0x100 != 0
    }
    fn attr(self) -> bool {
        self.0 & 0x200 != 0
    }
    fn tag(self) -> bool {
        self.0 & 0x400 != 0
    }
    fn levels(self) -> u32 {
        self.0 >> 12
    }
}

fn type_name(ty: u32) -> &'static str {
    lookup(SEXP_TYPES, u64::from(ty)).unwrap_or("unknown type")
}

/// Work left while skipping items: items, or the parts of byte code.
#[derive(Clone, Copy, Debug)]
enum Task {
    Items(u64),
    /// Byte code: its code vector, then its constants.
    Code,
    ConstCount,
    Consts(u64),
    /// A language cell of byte code: its type, then the cell.
    Lang,
    LangOf(i32),
}

async fn read_flags(rd: &mut Rd<'_>) -> Result<Flags> {
    Ok(Flags(rd.int().await?.cast_unsigned()))
}

/// Skips one item at the reader's position, counting (and labelling) the
/// references it adds.
async fn skip_item(rd: &mut Rd<'_>, ctx: &RCtx, refs: &mut u64) -> Result<()> {
    skip_tasks(rd, ctx, refs, Task::Items(1)).await
}

async fn skip_tasks(rd: &mut Rd<'_>, ctx: &RCtx, refs: &mut u64, first: Task) -> Result<()> {
    let mut stack = vec![first];
    // The first step checkpoints too, so many small skips are charged.
    let mut steps = 15u32;
    while let Some(task) = stack.pop() {
        steps = steps.wrapping_add(1);
        if steps.is_multiple_of(16) {
            rd.cx.checkpoint().await;
        }
        if stack.len() > R_MAX_STACK {
            return Err(Diagnostic::limit("items nested too deeply").at(rd.span.sub(rd.pos, 1)));
        }
        match task {
            Task::Items(0) => {}
            Task::Items(n) => {
                if n > 1 {
                    stack.push(Task::Items(n.saturating_sub(1)));
                }
                item_payload(rd, ctx, refs, &mut stack).await?;
            }
            Task::Code => {
                stack.push(Task::ConstCount);
                stack.push(Task::Items(1));
            }
            Task::ConstCount => {
                let n = rd.int().await?;
                stack.push(Task::Consts(u64::try_from(n).unwrap_or(0)));
            }
            Task::Consts(0) => {}
            Task::Consts(n) => {
                if n > 1 {
                    stack.push(Task::Consts(n.saturating_sub(1)));
                }
                match rd.int().await? {
                    21 => stack.push(Task::Code),
                    t @ (2 | 6 | 239 | 240 | 243 | 244) => stack.push(Task::LangOf(t)),
                    _ => stack.push(Task::Items(1)),
                }
            }
            Task::Lang => {
                let t = rd.int().await?;
                stack.push(Task::LangOf(t));
            }
            Task::LangOf(243) => {
                rd.int().await?;
            }
            Task::LangOf(mut t @ (2 | 6 | 239 | 240 | 244)) => {
                if t == 244 {
                    rd.int().await?;
                    t = rd.int().await?;
                }
                // CDR, CAR, tag, attributes (pushed in reverse).
                stack.push(Task::Lang);
                stack.push(Task::Lang);
                stack.push(Task::Items(if matches!(t, 239 | 240) { 2 } else { 1 }));
            }
            Task::LangOf(_) => stack.push(Task::Items(1)),
        }
    }
    Ok(())
}

/// Reads one item's flags and fixed payload; its nested items become tasks.
async fn item_payload(
    rd: &mut Rd<'_>,
    ctx: &RCtx,
    refs: &mut u64,
    stack: &mut Vec<Task>,
) -> Result<()> {
    let start = rd.pos;
    let f = read_flags(rd).await?;
    let attr = u64::from(f.attr());
    let items = |n: u64| Task::Items(n);
    match f.ty() {
        241 | 242 | 250..=254 => {}
        REFSXP => {
            if f.0 >> 8 == 0 {
                rd.int().await?;
            }
        }
        247..=249 => {
            rd.int().await?;
            let n = rd.length().await?;
            let label = type_name(f.ty());
            ctx.register(refs, || label.to_owned());
            stack.push(items(n));
        }
        1 => {
            let name = charsxp_text(rd).await?;
            ctx.register(refs, || format!("symbol {name}"));
        }
        4 => {
            rd.int().await?;
            ctx.register(refs, || "environment".to_owned());
            stack.push(items(4));
        }
        2 | 3 | 5 | 6 | 17 => stack.push(items(
            attr.saturating_add(u64::from(f.tag())).saturating_add(2),
        )),
        238 => stack.push(items(3)),
        22 => {
            ctx.register(refs, || "external pointer".to_owned());
            stack.push(items(attr.saturating_add(2)));
        }
        23 => {
            ctx.register(refs, || "weak reference".to_owned());
            stack.push(items(attr));
        }
        7..=9 => {
            let n = rd.int().await?;
            if n >= 0 {
                rd.string(u64::from(n.unsigned_abs())).await?;
            }
            stack.push(items(attr));
        }
        10 | 13 => {
            let n = rd.length().await?;
            rd.skip_values(n, 4, 1).await?;
            stack.push(items(attr));
        }
        14 => {
            let n = rd.length().await?;
            rd.skip_values(n, 8, 1).await?;
            stack.push(items(attr));
        }
        15 => {
            let n = rd.length().await?;
            rd.skip_values(n, 16, 2).await?;
            stack.push(items(attr));
        }
        24 => {
            let n = rd.length().await?;
            rd.skip_values(n, 1, 1).await?;
            stack.push(items(attr));
        }
        16 | 19 | 20 => {
            let n = rd.length().await?;
            stack.push(items(n.saturating_add(attr)));
        }
        21 => {
            rd.int().await?;
            stack.push(items(attr));
            stack.push(Task::Code);
        }
        25 => stack.push(items(attr)),
        t => {
            return Err(
                Diagnostic::unsupported(format!("item of type {} ({t})", type_name(t)))
                    .at(rd.span.sub(start, 4)),
            );
        }
    }
    Ok(())
}

/// The text of the CHARSXP item at the reader (a symbol's print name),
/// or of whatever item is there.
async fn charsxp_text(rd: &mut Rd<'_>) -> Result<String> {
    let f = read_flags(rd).await?;
    if f.ty() != 9 {
        return Err(Diagnostic::malformed(format!(
            "expected a string, found {}",
            type_name(f.ty())
        ))
        .at(rd.span.sub(rd.start, 4)));
    }
    let n = rd.int().await?;
    if n < 0 {
        return Ok("NA".to_owned());
    }
    let s = rd.string(u64::from(n.unsigned_abs())).await?;
    Ok(String::from_utf8_lossy(&s).into_owned())
}

/// A string element: its text, or `None` for `NA`.
async fn string_item(rd: &mut Rd<'_>, ctx: &RCtx, refs: &mut u64) -> Result<Option<String>> {
    let pos = rd.pos;
    let f = read_flags(rd).await?;
    if f.ty() != 9 {
        rd.seek(pos);
        skip_item(rd, ctx, refs).await?;
        return Ok(Some(format!("<{}>", type_name(f.ty()))));
    }
    let n = rd.int().await?;
    let text = if n < 0 {
        None
    } else {
        let s = rd.string(u64::from(n.unsigned_abs())).await?;
        Some(String::from_utf8_lossy(&s).into_owned())
    };
    if f.attr() {
        skip_item(rd, ctx, refs).await?;
    }
    Ok(text)
}

/// The name an item stands for when it is a tag: a symbol, a reference
/// to one, or a string. Anything else is skipped.
async fn tag_name(rd: &mut Rd<'_>, ctx: &RCtx, refs: &mut u64) -> Result<Option<String>> {
    let pos = rd.pos;
    let f = read_flags(rd).await?;
    match f.ty() {
        1 => {
            let name = charsxp_text(rd).await?;
            let label = name.clone();
            ctx.register(refs, || format!("symbol {label}"));
            Ok(Some(name))
        }
        REFSXP => {
            let index = match f.0 >> 8 {
                0 => u64::from(rd.int().await?.cast_unsigned()),
                i => u64::from(i),
            };
            Ok(ctx
                .lookup(index)
                .map(|l| l.strip_prefix("symbol ").map_or(l.clone(), str::to_owned)))
        }
        _ => {
            rd.seek(pos);
            let mut r = *refs;
            let s = string_item(rd, ctx, &mut r).await?;
            *refs = r;
            Ok(s)
        }
    }
}

/// An element value of an atomic vector of type `ty`.
async fn atomic(rd: &mut Rd<'_>, ty: u32) -> Result<Value> {
    let na = || Value::Text("NA".to_owned());
    Ok(match ty {
        10 => match rd.int().await? {
            i32::MIN => na(),
            v => Value::Bool(v != 0),
        },
        13 => match rd.int().await? {
            i32::MIN => na(),
            v => Value::Int {
                value: v.into(),
                bits: 32,
            },
        },
        14 => {
            let v = rd.double().await?;
            if v.to_bits() == NA_REAL {
                na()
            } else {
                Value::f64(v)
            }
        }
        15 => {
            let start = rd.pos;
            let re = rd.double().await?;
            let im = rd.double().await?;
            rd.start = start;
            if re.to_bits() == NA_REAL || im.to_bits() == NA_REAL {
                na()
            } else if im.is_sign_negative() {
                Value::Text(format!("{re}-{}i", -im))
            } else {
                Value::Text(format!("{re}+{im}i"))
            }
        }
        _ => {
            let b = match rd.fmt {
                RFmt::Ascii => {
                    let w = rd.word().await?;
                    u8::from_str_radix(&w, 16).unwrap_or(0)
                }
                _ => rd.array::<1>().await?.first().copied().unwrap_or(0),
            };
            crate::formats::util::val::hex(b, 8)
        }
    })
}

/// A short rendering of a value for summaries.
fn short(v: &Value) -> String {
    match v {
        Value::Text(s) => s.clone(),
        Value::Bool(true) => "TRUE".to_owned(),
        Value::Bool(false) => "FALSE".to_owned(),
        other => crate::render::value(other),
    }
}

/// A node for the item at `pos`; with `measure`, the item is skipped to
/// find its end (and the references it adds).
async fn item_node(
    cx: &Cx,
    ctx: &Arc<RCtx>,
    name: String,
    pos: u64,
    refs: u64,
    measure: bool,
) -> Result<(Node, u64, u64)> {
    let mut rd = Rd::new(cx, ctx, pos);
    let mut after = refs;
    let end = if measure {
        skip_item(&mut rd, ctx, &mut after).await?;
        rd.pos
    } else {
        ctx.span.len
    };
    rd.seek(pos);
    let f = read_flags(&mut rd).await?;
    let ty = f.ty();
    let mut node = Node::new(name).span(ctx.span.sub(pos, end.saturating_sub(pos)));
    let mut summary = type_name(ty).to_owned();
    // A reference packs its index into the flags: no other bits.
    let reference = ty == REFSXP;
    let mut expandable = f.attr() && !reference;
    match ty {
        REFSXP => {
            let index = match f.0 >> 8 {
                0 => u64::from(rd.int().await?.cast_unsigned()),
                i => u64::from(i),
            };
            summary = format!("reference #{index}");
            if let Some(l) = ctx.lookup(index) {
                match l.strip_prefix("symbol ") {
                    Some(name) => {
                        node = node.value(Value::Text(name.to_owned()));
                        summary = format!("{summary} (symbol)");
                    }
                    None => summary = format!("{summary}: {l}"),
                }
            }
        }
        1 => {
            let name = charsxp_text(&mut rd).await?;
            node = node.value(Value::Text(name));
        }
        9 => {
            let n = rd.int().await?;
            node = node.value(Value::Text(if n < 0 {
                "NA".to_owned()
            } else {
                String::from_utf8_lossy(&rd.string(u64::from(n.unsigned_abs())).await?).into_owned()
            }));
        }
        7 | 8 => {
            let n = rd.int().await?;
            let s = rd.string(u64::try_from(n).unwrap_or(0)).await?;
            node = node.value(Value::Text(String::from_utf8_lossy(&s).into_owned()));
        }
        10 | 13 | 14 | 15 | 16 => {
            let n = rd.length().await?;
            let mut shown = Vec::new();
            let mut r = refs;
            // A preview only: a vector cut short still gets its node (its
            // elements show where it ends).
            for _ in 0..n.min(6) {
                let one = if ty == 16 {
                    string_item(&mut rd, ctx, &mut r).await.map(|s| {
                        s.map_or_else(
                            || "NA".to_owned(),
                            |s| format!("{:?}", crate::formats::util::fmt::clip(&s, 40)),
                        )
                    })
                } else {
                    atomic(&mut rd, ty).await.map(|v| short(&v))
                };
                match one {
                    Ok(s) => shown.push(s),
                    Err(_) => break,
                }
            }
            summary = format!(
                "{summary}, {}{}{}{}",
                crate::formats::util::fmt::plural(n, "value"),
                if n > 0 { ": " } else { "" },
                shown.join(" "),
                if n > 6 { " …" } else { "" }
            );
            expandable |= n > 0;
        }
        24 => {
            let n = rd.length().await?;
            summary = format!("{summary}, {}", crate::formats::util::fmt::size(n));
            expandable |= n > 0;
        }
        19 | 20 => {
            let n = rd.length().await?;
            summary = format!(
                "{summary}, {}",
                crate::formats::util::fmt::plural(n, "element")
            );
            expandable |= n > 0;
        }
        238 => {
            // The class is the first symbol of the info pairlist.
            let mut r = refs;
            let info = read_flags(&mut rd).await?;
            if info.ty() == 2
                && !info.attr()
                && !info.tag()
                && let Some(class) = tag_name(&mut rd, ctx, &mut r).await?
            {
                summary = format!("ALTREP {class}");
            }
            expandable = true;
        }
        4 => {
            let locked = rd.int().await? != 0;
            if locked {
                summary = format!("{summary}, locked");
            }
            expandable = true;
        }
        2 | 3 | 5 | 6 | 17 | 22 | 247..=249 => expandable = true,
        _ => {}
    }
    if f.object() && !reference {
        summary = format!("{summary}, object");
    }
    if ty == 9 && f.levels() & 0x48 != 0 {
        summary = format!(
            "{summary}, {}",
            if f.levels() & 0x08 != 0 {
                "UTF-8"
            } else {
                "ASCII"
            }
        );
    }
    node = node.summary(summary);
    if expandable {
        node = node.lazy(
            crate::expander!(self::item_children: (Arc<RCtx>, u64, u64)),
            (ctx.clone(), pos, refs),
        );
    }
    Ok((node, end, after))
}

/// Pushes the items at `pos` under the given names; returns where they end
/// and the reference count after them.
async fn fixed_children(
    cx: &Cx,
    ctx: &Arc<RCtx>,
    names: &[&str],
    mut pos: u64,
    mut refs: u64,
) -> Result<(u64, u64)> {
    for name in names {
        let (node, end, after) = item_node(cx, ctx, (*name).to_owned(), pos, refs, true).await?;
        cx.push(node).await;
        pos = end;
        refs = after;
    }
    Ok((pos, refs))
}

/// What a vector's elements need: where its attributes are and the names
/// that label its elements.
struct VecInfo {
    attr: Option<(u64, u64)>,
    names: Vec<String>,
}

/// The vector at `pos`'s attributes and element names, as far as they can
/// be read: a vector cut short (or claiming more elements than the stream
/// holds) has none, and its elements show where it ends.
async fn vec_info(cx: &Cx, ctx: &Arc<RCtx>, pos: u64, refs: u64) -> Arc<VecInfo> {
    let key = ctx.span.sub(pos, 1);
    if let Some(info) = cx.cached::<VecInfo>(key, "r-vector") {
        return info;
    }
    let mut info = VecInfo {
        attr: None,
        names: Vec::new(),
    };
    // Errors are reported where the elements or attributes are read.
    let _ = vec_walk(cx, ctx, pos, refs, &mut info).await;
    let info = Arc::new(info);
    cx.cache(key, "r-vector", info.clone());
    info
}

async fn vec_walk(cx: &Cx, ctx: &Arc<RCtx>, pos: u64, refs: u64, info: &mut VecInfo) -> Result<()> {
    let mut rd = Rd::new(cx, ctx, pos);
    let f = read_flags(&mut rd).await?;
    let n = rd.length().await?;
    let mut r = refs;
    match f.ty() {
        10 | 13 => rd.skip_values(n, 4, 1).await?,
        14 => rd.skip_values(n, 8, 1).await?,
        15 => rd.skip_values(n, 16, 2).await?,
        24 => rd.skip_values(n, 1, 1).await?,
        _ => skip_tasks(&mut rd, ctx, &mut r, Task::Items(n)).await?,
    }
    if f.attr() {
        info.attr = Some((rd.pos, r));
        // Walk the attribute pairlist for `names`.
        loop {
            cx.checkpoint().await;
            let cell = rd.pos;
            let c = read_flags(&mut rd).await?;
            if c.ty() != 2 {
                rd.seek(cell);
                break;
            }
            if c.attr() {
                skip_item(&mut rd, ctx, &mut r).await?;
            }
            let tag = if c.tag() {
                tag_name(&mut rd, ctx, &mut r).await?
            } else {
                None
            };
            let value = rd.pos;
            let vf = read_flags(&mut rd).await?;
            if tag.as_deref() == Some("names") && vf.ty() == 16 {
                let k = rd.length().await?;
                for i in 0..k.min(R_MAX_NAMES) {
                    if i % 16 == 15 {
                        cx.checkpoint().await;
                    }
                    let s = string_item(&mut rd, ctx, &mut r).await?;
                    info.names.push(s.unwrap_or_else(|| "NA".to_owned()));
                }
                break;
            }
            rd.seek(value);
            skip_item(&mut rd, ctx, &mut r).await?;
        }
    }
    Ok(())
}

fn element_label(names: &[String], i: u64) -> String {
    match names.get(to_usize(i)) {
        Some(n) if !n.is_empty() => crate::formats::util::fmt::clip(n, 120),
        _ => format!("[{}]", i.saturating_add(1)),
    }
}

/// The children of an item: elements, cells, or its parts.
async fn item_children(cx: Cx, (ctx, pos, refs): (Arc<RCtx>, u64, u64)) -> Result<()> {
    let mut rd = Rd::new(&cx, &ctx, pos);
    let f = read_flags(&mut rd).await?;
    let attr = f.attr();
    let at = rd.pos;
    match f.ty() {
        2 | 6 | 17 => return cells(cx, ctx, pos, refs).await,
        3 | 5 => {
            let (env, a, b) = if f.ty() == 3 {
                ("Environment", "Formals", "Body")
            } else {
                ("Environment", "Value", "Expression")
            };
            let mut names = Vec::new();
            if attr {
                names.push("Attributes");
            }
            if f.tag() {
                names.push(env);
            }
            names.extend([a, b]);
            fixed_children(&cx, &ctx, &names, at, refs).await?;
        }
        4 => {
            let locked = rd.int().await?;
            cx.push(
                Node::new("Locked")
                    .span(ctx.span.sub(rd.start, rd.pos.saturating_sub(rd.start)))
                    .value(Value::Bool(locked != 0)),
            )
            .await;
            let mut r = refs;
            ctx.register(&mut r, || "environment".to_owned());
            fixed_children(
                &cx,
                &ctx,
                &["Enclosure", "Frame", "Hash table", "Attributes"],
                rd.pos,
                r,
            )
            .await?;
        }
        238 => {
            fixed_children(&cx, &ctx, &["Class", "State", "Attributes"], at, refs).await?;
        }
        22 => {
            let mut r = refs;
            ctx.register(&mut r, || "external pointer".to_owned());
            let names: &[&str] = if attr {
                &["Protected", "Tag", "Attributes"]
            } else {
                &["Protected", "Tag"]
            };
            fixed_children(&cx, &ctx, names, at, r).await?;
        }
        247..=249 => {
            rd.int().await?;
            let n = rd.length().await?;
            let names: Vec<String> = (0..n.min(64))
                .map(|i| format!("[{}]", i.saturating_add(1)))
                .collect();
            let names: Vec<&str> = names.iter().map(String::as_str).collect();
            fixed_children(&cx, &ctx, &names, rd.pos, refs).await?;
        }
        10 | 13 | 14 | 15 | 16 | 19 | 20 | 24 => return elements(cx, ctx, pos, refs, f).await,
        _ => {
            if attr {
                // Attributes follow the payload: skip to them.
                let mut r = refs;
                let mut head = Rd::new(&cx, &ctx, pos);
                skip_without_attr(&mut head, &ctx, &mut r).await?;
                fixed_children(&cx, &ctx, &["Attributes"], head.pos, r).await?;
            }
        }
    }
    Ok(())
}

/// Skips an item's flags and payload, but not its attributes (for items
/// whose attributes are their only nested items, or byte code).
async fn skip_without_attr(rd: &mut Rd<'_>, ctx: &RCtx, refs: &mut u64) -> Result<()> {
    let mut stack = Vec::new();
    item_payload(rd, ctx, refs, &mut stack).await?;
    // The attributes are the first task pushed.
    if !stack.is_empty() {
        stack.remove(0);
    }
    while let Some(t) = stack.pop() {
        skip_tasks(rd, ctx, refs, t).await?;
    }
    Ok(())
}

/// A pairlist or language object: its cells flattened, each CAR named by
/// its tag.
async fn cells(cx: Cx, ctx: Arc<RCtx>, first: u64, refs: u64) -> Result<()> {
    let (mut pos, mut refs, mut index) = cx.resume::<(u64, u64, u64)>().unwrap_or((first, refs, 0));
    let mut language = false;
    loop {
        let at = (pos, refs, index);
        cx.mark(move || at);
        let mut rd = Rd::new(&cx, &ctx, pos);
        let f = read_flags(&mut rd).await?;
        if index == 0 && pos == first {
            language = f.ty() == 6;
        }
        let mut r = refs;
        let mut next = rd.pos;
        if f.attr() {
            let (node, end, after) =
                item_node(&cx, &ctx, "Attributes".to_owned(), next, r, true).await?;
            cx.push(node).await;
            next = end;
            r = after;
        }
        let mut name = None;
        if f.tag() {
            let mut tr = Rd::new(&cx, &ctx, next);
            name = tag_name(&mut tr, &ctx, &mut r).await?;
            next = tr.pos;
        }
        let label = name.unwrap_or_else(|| {
            if language && index == 0 {
                "Function".to_owned()
            } else {
                format!("[{}]", index.saturating_add(1))
            }
        });
        let (node, end, after) = item_node(&cx, &ctx, label, next, r, true).await?;
        cx.push(node).await;
        index = index.saturating_add(1);
        // The CDR: another cell, the end, or a dotted tail.
        let mut cdr = Rd::new(&cx, &ctx, end);
        let c = read_flags(&mut cdr).await?;
        match c.ty() {
            NILVALUE => break,
            2 | 6 | 17 => {
                pos = end;
                refs = after;
            }
            _ => {
                let (node, _, _) = item_node(&cx, &ctx, "CDR".to_owned(), end, after, true).await?;
                cx.push(node).await;
                break;
            }
        }
    }
    Ok(())
}

/// The elements of a vector, then its attributes.
async fn elements(cx: Cx, ctx: Arc<RCtx>, pos: u64, refs: u64, f: Flags) -> Result<()> {
    let info = vec_info(&cx, &ctx, pos, refs).await;
    let ty = f.ty();
    let mut rd = Rd::new(&cx, &ctx, pos);
    read_flags(&mut rd).await?;
    let n = rd.length().await?;
    if ty == 24 {
        let start = rd.pos;
        let mut shown = Vec::new();
        for _ in 0..n.min(64) {
            if let Value::UInt { value, .. } = atomic(&mut rd, 24).await? {
                shown.push(u8::try_from(value).unwrap_or(0));
            }
        }
        rd.skip_values(n.saturating_sub(64), 1, 1).await?;
        let end = rd.pos;
        cx.push(
            Node::new("Data")
                .span(ctx.span.sub(start, end.saturating_sub(start)))
                .value(Value::Bytes(shown))
                .summary(crate::formats::util::fmt::size(n)),
        )
        .await;
    } else {
        let (start, refs0, i0) = cx.resume::<(u64, u64, u64)>().unwrap_or((rd.pos, refs, 0));
        rd.seek(start);
        let mut r = refs0;
        if !matches!(ty, 16 | 19 | 20) {
            cx.set_count(Count::Exact(
                n.saturating_add(u64::from(info.attr.is_some())),
            ));
        }
        for i in i0..n {
            let at = (rd.pos, r, i);
            cx.mark(move || at);
            let label = element_label(&info.names, i);
            let node = match ty {
                19 | 20 => {
                    let (node, end, after) = item_node(&cx, &ctx, label, rd.pos, r, true).await?;
                    rd.seek(end);
                    r = after;
                    node
                }
                16 => {
                    let start = rd.pos;
                    let s = string_item(&mut rd, &ctx, &mut r).await?;
                    Node::new(label)
                        .span(ctx.span.sub(start, rd.pos.saturating_sub(start)))
                        .value(Value::Text(s.unwrap_or_else(|| "NA".to_owned())))
                }
                _ => {
                    let v = atomic(&mut rd, ty).await?;
                    Node::new(label)
                        .span(ctx.span.sub(rd.start, rd.pos.saturating_sub(rd.start)))
                        .value(v)
                }
            };
            cx.push(node).await;
        }
    }
    if let Some((a, r)) = info.attr {
        let (node, _, _) = item_node(&cx, &ctx, "Attributes".to_owned(), a, r, true).await?;
        cx.push(node).await;
    }
    Ok(())
}

/// A header int and its node.
async fn int_node(rd: &mut Rd<'_>, name: &'static str) -> Result<(u32, Node)> {
    let v = rd.int().await?.cast_unsigned();
    let node = Node::new(name)
        .span(rd.span.sub(rd.start, rd.pos.saturating_sub(rd.start)))
        .value(crate::formats::util::val::uint(v, 32));
    Ok((v, node))
}

async fn r_data(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let sig = cx.read_avail(file.sub(0, 5)).await?;
    let rdata = matches!(sig.as_slice(), [b'R', b'D', _, b'2' | b'3', b'\n']);
    let mut at = 0u64;
    if rdata {
        cx.emit(
            Node::new("RData signature")
                .span(file.sub(0, 5))
                .value(text(crate::text::latin1(sig.get(..4).unwrap_or_default()))),
        );
        at = 5;
    }
    let body = file.tail(at);
    let marker = cx.read(body.sub(0, 2)).await?;
    let (fmt, fmt_name) = match marker.first() {
        Some(b'X') => (RFmt::Xdr, "XDR"),
        Some(b'B') => (RFmt::Native, "native binary"),
        Some(b'A') => (RFmt::Ascii, "ASCII"),
        _ => return Err(Diagnostic::malformed("unknown serialization format").at(body.sub(0, 2))),
    };
    cx.emit(
        Node::new("Format")
            .span(body.sub(0, 2))
            .value(text(crate::text::latin1(&marker)))
            .summary(fmt_name),
    );
    let ctx = Arc::new(RCtx {
        span: body,
        fmt,
        refs: Mutex::new(BTreeMap::new()),
    });
    let mut rd = Rd::new(&cx, &ctx, 2);
    let (version, node) = int_node(&mut rd, "Serialization version").await?;
    cx.emit(node);
    let r_version = |v: u32| format!("R {}.{}.{}", v >> 16, (v >> 8) & 0xff, v & 0xff);
    let (writer, node) = int_node(&mut rd, "Written by R").await?;
    cx.emit(node.summary(r_version(writer)));
    let (reader, node) = int_node(&mut rd, "Minimum reader R").await?;
    cx.emit(node.summary(r_version(reader)));
    if version == 3 {
        let start = rd.pos;
        let l = rd.int().await?;
        let enc = rd.string(u64::try_from(l).unwrap_or(0)).await?;
        cx.emit(
            Node::new("Native encoding")
                .span(body.sub(start, rd.pos.saturating_sub(start)))
                .value(text(String::from_utf8_lossy(&enc).into_owned())),
        );
    }
    let pos = rd.pos;
    let mut peek = Rd::new(&cx, &ctx, pos);
    let flags = read_flags(&mut peek).await?;
    let (node, _, _) = item_node(&cx, &ctx, "Top-level object".to_owned(), pos, 0, false).await?;
    cx.emit(node);
    cx.annotate(format!(
        "R {} (serialization v{version}{}, {}), top level {}",
        if rdata {
            "workspace (RData)"
        } else {
            "object (RDS)"
        },
        if fmt == RFmt::Xdr {
            String::new()
        } else {
            format!(", {fmt_name}")
        },
        r_version(writer),
        type_name(flags.ty())
    ));
    Ok(())
}

declare_format!(pub ASDF = "asdf", "Advanced Scientific Data Format", ["asdf"], "application/x-asdf",
    Probe::Magic(&[(0, b"#ASDF ")]), asdf);

async fn asdf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1 << 20)).await?;
    let first = head.iter().position(|&b| b == b'\n').unwrap_or(0);
    let version = String::from_utf8_lossy(head.get(6..first).unwrap_or_default()).into_owned();
    // The YAML tree ends with "...\n"; binary blocks follow (magic \xd3BLK).
    let tree_end = head
        .windows(5)
        .position(|w| w == b"\n...\n")
        .map_or(to_u64(head.len()), |p| to_u64(p).saturating_add(5));
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, to_u64(first)))
            .value(text(version.clone())),
    );
    let yaml_at = head
        .windows(5)
        .position(|w| w == b"%YAML")
        .map_or(0, to_u64);
    cx.emit(embedded(
        "Tree (YAML)",
        input.nested(file.sub(yaml_at, tree_end.saturating_sub(yaml_at))),
    ));
    let mut pos = tree_end;
    let mut blocks = 0u32;
    while pos.saturating_add(6) <= file.len {
        cx.progress(pos, file.len);
        let h = cx.read(file.sub(pos, 6)).await?;
        if !h.starts_with(b"\xd3BLK") {
            break;
        }
        let header_len = u64::from(u16_be(&h, 4).unwrap_or(0));
        let b = cx
            .read(file.sub_exact(pos.saturating_add(6), header_len.min(48))?)
            .await?;
        let compression = String::from_utf8_lossy(b.get(4..8).unwrap_or_default())
            .trim_end_matches('\0')
            .to_owned();
        let allocated = u64_be(&b, 8).unwrap_or(0);
        let used = u64_be(&b, 16).unwrap_or(0);
        let data = file.sub(pos.saturating_add(6).saturating_add(header_len), used);
        let node = Node::new(format!("Block {blocks}"))
            .span(file.sub(
                pos,
                6u64.saturating_add(header_len).saturating_add(allocated),
            ))
            .summary(format!(
                "{used} bytes{}",
                if compression.is_empty() {
                    String::new()
                } else {
                    format!(", {compression}")
                }
            ));
        cx.push(if compression.is_empty() {
            node
        } else {
            node.diag(Diagnostic::note(format!(
                "{compression}-compressed: {data:?}"
            )))
        })
        .await;
        blocks = blocks.saturating_add(1);
        pos = pos
            .saturating_add(6)
            .saturating_add(header_len)
            .saturating_add(allocated);
    }
    cx.annotate(format!("ASDF {version}, {blocks} binary blocks"));
    Ok(())
}
