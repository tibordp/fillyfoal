//! SPSS portable files (`.por`).
//!
//! A text format of 80-column lines (line ends are not part of the data;
//! short lines are padded with spaces): five 40-byte "splash" strings, a
//! 256-byte table mapping SPSS's portable character set to the file's
//! bytes, the tag `SPSSPORT`, a version letter, creation date and time, and
//! tagged records: `1` product, `2` author, `3` subproduct, `4` variable
//! count, `5` precision, `6` weight variable, `7` variable (width, name,
//! print and write formats), `8`/`9`/`A`/`B` missing values, `C` variable
//! label, `D` value labels, `E` documents, and `F` data, which runs to a
//! `Z` filler. Numbers are base 30 (`0`-`9`, `A`-`T`) with an optional
//! fraction and exponent, ended by `/`; `*.` is system-missing. Strings are
//! a number (the length) and that many characters. Layout per GNU PSPP's
//! "Portable File Format", as remembered; checked against a file written
//! by ReadStat (pyreadstat).

use std::sync::Arc;

use super::spss::{EPOCH, date_type, format_parts};
use super::{Cell, Item, date_cell, number, row_node};
use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// The portable character set from position 64 (digits, letters, then
/// punctuation), as ReadStat and PSPP write its identity table.
const PORTABLE: &[u8] = b"0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz .<(+|&[]!$*);^-/|,%_>?`:#@'=\"";

/// Physical bytes of the header: splash strings, translation table and tag.
const SPLASH: u64 = 200;
const TABLE: u64 = 256;

/// The tag, in ASCII, at logical position 456 (after line ends are
/// removed); most files are ASCII and 80 columns wide.
fn probe(h: &Head<'_>) -> bool {
    let mut logical = Vec::with_capacity(470);
    for &b in h.data.iter().take(600) {
        if b != b'\r' && b != b'\n' {
            logical.push(b);
        }
        if logical.len() >= 464 {
            break;
        }
    }
    logical.get(456..464) == Some(b"SPSSPORT")
        || logical
            .get(..40)
            .is_some_and(|s| s.windows(15).any(|w| w == b"SPSS PORT FILE"))
}

declare_format!(pub POR = "spss-por", "SPSS portable file", ["por"], "application/x-spss-por",
    Probe::Custom(probe), dissect);

/// A reader over the logical character stream: line ends removed, short
/// lines padded to 80 columns, bytes translated to ASCII through the
/// file's table.
#[derive(Clone)]
struct Reader<'a> {
    cx: &'a Cx,
    file: Span,
    /// Physical position.
    pos: u64,
    col: u64,
    pad: u64,
    xlat: Arc<[u8; 256]>,
    buf: Vec<u8>,
    buf_at: u64,
}

/// Where a reader stands, for resuming.
#[derive(Clone, Copy, Debug)]
struct Mark {
    pos: u64,
    col: u64,
    pad: u64,
}

impl<'a> Reader<'a> {
    fn new(cx: &'a Cx, file: Span, xlat: Arc<[u8; 256]>) -> Self {
        Reader {
            cx,
            file,
            pos: 0,
            col: 0,
            pad: 0,
            xlat,
            buf: Vec::new(),
            buf_at: 0,
        }
    }

    fn mark(&self) -> Mark {
        Mark {
            pos: self.pos,
            col: self.col,
            pad: self.pad,
        }
    }

    fn restore(&mut self, m: Mark) {
        self.pos = m.pos;
        self.col = m.col;
        self.pad = m.pad;
    }

    async fn raw(&mut self) -> Result<Option<u8>> {
        let rel = self.pos.saturating_sub(self.buf_at);
        if self.pos < self.buf_at || rel >= to_u64(self.buf.len()) {
            self.buf = self.cx.read_avail(self.file.sub(self.pos, 4096)).await?;
            self.buf_at = self.pos;
        }
        let rel = crate::bytes::to_usize(self.pos.saturating_sub(self.buf_at));
        Ok(self.buf.get(rel).copied())
    }

    /// The next logical character, translated; `None` at the end.
    async fn next(&mut self) -> Result<Option<u8>> {
        loop {
            if self.pad > 0 {
                self.pad = self.pad.saturating_sub(1);
                return Ok(Some(b' '));
            }
            let Some(b) = self.raw().await? else {
                return Ok(None);
            };
            self.pos = self.pos.saturating_add(1);
            match b {
                b'\r' => {}
                b'\n' => {
                    if self.col < 80 && self.col > 0 {
                        self.pad = 80u64.saturating_sub(self.col);
                    }
                    self.col = 0;
                }
                _ => {
                    self.col = self.col.saturating_add(1);
                    return Ok(Some(self.xlat.get(usize::from(b)).copied().unwrap_or(b'?')));
                }
            }
        }
    }

    async fn peek(&mut self) -> Result<Option<u8>> {
        let m = self.mark();
        let c = self.next().await?;
        self.restore(m);
        Ok(c)
    }

    fn malformed(&self, what: &str) -> Diagnostic {
        Diagnostic::malformed(what.to_owned()).at(self.file.sub(self.pos, 1))
    }

    /// A base-30 number; `None` for system-missing (`*.`).
    async fn number(&mut self) -> Result<Option<f64>> {
        let mut c = self.next().await?;
        let mut spaces = 0u32;
        while c == Some(b' ') && spaces < 200 {
            c = self.next().await?;
            spaces = spaces.saturating_add(1);
        }
        if c == Some(b'*') {
            self.next().await?;
            return Ok(None);
        }
        let mut negative = false;
        if c == Some(b'-') {
            negative = true;
            c = self.next().await?;
        }
        let mut mantissa = 0f64;
        let mut scale = 0i32;
        let mut fraction = false;
        let mut exponent = 0i32;
        let mut exp_sign = 0i32;
        let mut digits = 0u32;
        loop {
            let Some(ch) = c else {
                return Err(self.malformed("number truncated"));
            };
            match ch {
                b'/' => break,
                b'.' if exp_sign == 0 => fraction = true,
                b'+' | b'-' => exp_sign = if ch == b'-' { -1 } else { 1 },
                _ => {
                    let d = match ch {
                        b'0'..=b'9' => ch.saturating_sub(b'0'),
                        b'A'..=b'T' => ch.saturating_sub(b'A').saturating_add(10),
                        _ => return Err(self.malformed("not a base-30 digit")),
                    };
                    if exp_sign != 0 {
                        exponent = exponent.saturating_mul(30).saturating_add(i32::from(d));
                    } else {
                        mantissa = mantissa * 30.0 + f64::from(d);
                        if fraction {
                            scale = scale.saturating_sub(1);
                        }
                    }
                }
            }
            digits = digits.saturating_add(1);
            if digits > 400 {
                return Err(self.malformed("number too long"));
            }
            c = self.next().await?;
        }
        let power = scale.saturating_add(exponent.saturating_mul(exp_sign.max(-1)));
        let v = mantissa * 30f64.powi(power);
        Ok(Some(if negative { -v } else { v }))
    }

    async fn integer(&mut self) -> Result<u64> {
        let v = self.number().await?.unwrap_or(0.0);
        if !(0.0..=1e9).contains(&v) {
            return Err(self.malformed("implausible count"));
        }
        Ok(v as u64)
    }

    async fn string(&mut self) -> Result<String> {
        let n = self.integer().await?.min(1 << 16);
        let mut out = Vec::new();
        for _ in 0..n {
            match self.next().await? {
                Some(c) => out.push(c),
                None => return Err(self.malformed("string truncated")),
            }
        }
        Ok(String::from_utf8_lossy(&out).into_owned())
    }
}

#[derive(Clone, Debug)]
struct Var {
    name: String,
    width: u64,
    print: (u32, u32, u32),
    write: (u32, u32, u32),
    label: String,
    missing: Vec<String>,
    span: Span,
}

#[derive(Clone, Debug)]
struct Labels {
    vars: Vec<String>,
    entries: Vec<(Option<f64>, String, String)>,
    span: Span,
}

#[derive(Clone, Debug)]
struct Por {
    file: Span,
    xlat: Arc<[u8; 256]>,
    vars: Vec<Var>,
    labels: Vec<Labels>,
    data: Option<Mark>,
}

/// One value: a number for numeric variables, else a string.
async fn value(r: &mut Reader<'_>, numeric: bool) -> Result<(Option<f64>, String)> {
    if numeric {
        let v = r.number().await?;
        Ok((v, v.map_or_else(|| ".".to_owned(), number)))
    } else {
        let s = r.string().await?;
        Ok((None, s))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    // The header is read through an identity table first.
    let mut identity = [0u8; 256];
    for (i, slot) in identity.iter_mut().enumerate() {
        *slot = u8::try_from(i).unwrap_or(0);
    }
    let mut r = Reader::new(&cx, file, Arc::new(identity));
    let mut splash = Vec::new();
    for _ in 0..SPLASH {
        splash.push(r.next().await?.unwrap_or(b' '));
    }
    let table_at = r.pos;
    let mut table = Vec::new();
    for _ in 0..TABLE {
        table.push(r.next().await?.unwrap_or(b'0'));
    }
    // Invert the table: the file's byte at portable position i is
    // PORTABLE[i - 64]. Lower positions win (unused slots repeat `0`).
    let mut xlat = [b'?'; 256];
    for (i, &b) in table.iter().enumerate().skip(64).rev() {
        if let Some(&c) = PORTABLE.get(i.saturating_sub(64))
            && let Some(slot) = xlat.get_mut(usize::from(b))
        {
            *slot = c;
        }
    }
    let identity_table = table.iter().skip(64).zip(PORTABLE).all(|(a, b)| a == b);
    let xlat = Arc::new(xlat);
    r.xlat = xlat.clone();
    let tag_at = r.pos;
    let mut tag = Vec::new();
    for _ in 0..8 {
        tag.push(r.next().await?.unwrap_or(0));
    }
    let splash_text = String::from_utf8_lossy(&splash).into_owned();
    let mut header = vec![
        Node::new("Splash strings")
            .span(file.sub(0, table_at))
            .value(Value::Text(splash_text.trim_end().to_owned())),
        Node::new("Character table")
            .span(file.sub(table_at, tag_at.saturating_sub(table_at)))
            .summary(if identity_table {
                "identity (ASCII)"
            } else {
                "translated"
            }),
        Node::new("Tag")
            .span(file.sub(tag_at, r.pos.saturating_sub(tag_at)))
            .value(Value::Text(String::from_utf8_lossy(&tag).into_owned())),
    ];
    if tag != b"SPSSPORT" {
        return Err(Diagnostic::malformed("missing SPSSPORT tag").at(file.sub(tag_at, 8)));
    }
    let version = r.next().await?.unwrap_or(0);
    let date = r.string().await?;
    let time = r.string().await?;
    header.push(Node::new("Version").value(Value::Text(char::from(version).to_string())));
    // `yyyyMMdd` and `HHmmss`, shown as an ISO date and time when they are.
    let (date, time) = match (
        date.get(..4),
        date.get(4..6),
        date.get(6..8),
        time.get(..2),
        time.get(2..4),
        time.get(4..6),
    ) {
        (Some(y), Some(mo), Some(d), Some(h), Some(mi), Some(se))
            if date.len() == 8 && time.len() == 6 =>
        {
            (format!("{y}-{mo}-{d}"), format!("{h}:{mi}:{se}"))
        }
        _ => (date, time),
    };
    header.push(Node::new("Created").value(Value::Text(format!("{date} {time}"))));
    let mut por = Por {
        file,
        xlat,
        vars: Vec::new(),
        labels: Vec::new(),
        data: None,
    };
    let mut product = String::new();
    let mut problem = None;
    let result: Result<()> = async {
        loop {
            cx.checkpoint().await;
            let start = r.pos;
            let Some(tag) = r.next().await? else {
                break;
            };
            match tag {
                b'1' | b'2' | b'3' | b'6' => {
                    let s = r.string().await?;
                    let name = match tag {
                        b'1' => "Product",
                        b'2' => "Author",
                        b'3' => "Subproduct",
                        _ => "Weight variable",
                    };
                    if tag == b'1' {
                        product.clone_from(&s);
                    }
                    header.push(
                        Node::new(name)
                            .span(file.sub(start, r.pos.saturating_sub(start)))
                            .value(Value::Text(s)),
                    );
                }
                b'4' | b'5' => {
                    let n = r.integer().await?;
                    header.push(
                        Node::new(if tag == b'4' {
                            "Variable count"
                        } else {
                            "Precision"
                        })
                        .span(file.sub(start, r.pos.saturating_sub(start)))
                        .value(Value::UInt {
                            value: n,
                            bits: 64,
                            radix: crate::value::Radix::Dec,
                        }),
                    );
                }
                b'7' => {
                    let width = r.integer().await?;
                    let name = r.string().await?;
                    let mut f = [0u32; 6];
                    for slot in &mut f {
                        *slot = u32::try_from(r.integer().await?).unwrap_or(0);
                    }
                    por.vars.push(Var {
                        name,
                        width,
                        print: (f[0], f[1], f[2]),
                        write: (f[3], f[4], f[5]),
                        label: String::new(),
                        missing: Vec::new(),
                        span: file.sub(start, r.pos.saturating_sub(start)),
                    });
                }
                b'8' | b'9' | b'A' | b'B' => {
                    let numeric = por.vars.last().is_none_or(|v| v.width == 0);
                    let (_, a) = value(&mut r, numeric).await?;
                    let text = match tag {
                        b'8' => a,
                        b'9' => format!("LO thru {a}"),
                        b'A' => format!("{a} thru HI"),
                        _ => {
                            let (_, b) = value(&mut r, numeric).await?;
                            format!("{a} thru {b}")
                        }
                    };
                    if let Some(v) = por.vars.last_mut() {
                        v.missing.push(text);
                        v.span = file.sub(
                            v.span.offset.saturating_sub(file.offset),
                            r.pos
                                .saturating_sub(v.span.offset.saturating_sub(file.offset)),
                        );
                    }
                }
                b'C' => {
                    let label = r.string().await?;
                    if let Some(v) = por.vars.last_mut() {
                        v.label = label;
                        v.span = file.sub(
                            v.span.offset.saturating_sub(file.offset),
                            r.pos
                                .saturating_sub(v.span.offset.saturating_sub(file.offset)),
                        );
                    }
                }
                b'D' => {
                    let n = r.integer().await?;
                    let mut vars = Vec::new();
                    for _ in 0..n {
                        cx.checkpoint().await;
                        vars.push(r.string().await?);
                    }
                    let numeric = vars
                        .first()
                        .and_then(|name| por.vars.iter().find(|v| &v.name == name))
                        .is_none_or(|v| v.width == 0);
                    let count = r.integer().await?;
                    let mut entries = Vec::new();
                    for _ in 0..count {
                        cx.checkpoint().await;
                        let (v, text) = value(&mut r, numeric).await?;
                        let label = r.string().await?;
                        entries.push((v, text, label));
                    }
                    por.labels.push(Labels {
                        vars,
                        entries,
                        span: file.sub(start, r.pos.saturating_sub(start)),
                    });
                }
                b'E' => {
                    let n = r.integer().await?;
                    for _ in 0..n {
                        cx.checkpoint().await;
                        let line = r.string().await?;
                        header.push(Node::new("Document line").value(Value::Text(line)));
                    }
                }
                b'F' => {
                    por.data = Some(r.mark());
                    break;
                }
                other => {
                    return Err(Diagnostic::malformed(format!(
                        "unknown record tag {:?}",
                        char::from(other)
                    ))
                    .at(file.sub(start, 1)));
                }
            }
        }
        Ok(())
    }
    .await;
    if let Err(e) = result {
        problem = Some(e);
    }
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, r.pos.min(file.len)))
            .summary(format!("{date} {time}, {product}"))
            .lazy(emit_nodes, Arc::new(header)),
    );
    let por = Arc::new(por);
    let mut vars = Node::new("Variables")
        .summary(format!("{} variables", por.vars.len()))
        .lazy(variables, por.clone());
    if let Some(p) = problem {
        vars = vars.diag(p);
    }
    cx.emit(vars);
    if !por.labels.is_empty() {
        cx.emit(
            Node::new("Value labels")
                .summary(format!("{} sets", por.labels.len()))
                .lazy(label_sets, por.clone()),
        );
    }
    if let Some(m) = por.data {
        cx.emit(
            Node::new("Cases")
                .span(file.tail(m.pos))
                .lazy(cases, por.clone()),
        );
    }
    cx.annotate(format!(
        "SPSS portable file, {} variables, {date} {time}{}",
        por.vars.len(),
        if product.is_empty() {
            String::new()
        } else {
            format!(", {product}")
        }
    ));
    Ok(())
}

async fn variables(cx: Cx, por: Arc<Por>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(por.vars.len())));
    for v in &por.vars {
        let kind = if v.width == 0 {
            "numeric".to_owned()
        } else {
            format!("string({})", v.width)
        };
        let print = format_parts(v.print.0, v.print.1, v.print.2);
        let mut parts = vec![kind.clone(), print.clone()];
        if !v.label.is_empty() {
            parts.push(format!("{:?}", v.label));
        }
        let mut fields = vec![
            Node::new("Name").value(Value::Text(v.name.clone())),
            Node::new("Label").value(Value::Text(v.label.clone())),
            Node::new("Type").value(Value::Text(kind)),
            Node::new("Print format").value(Value::Text(print)),
            Node::new("Write format")
                .value(Value::Text(format_parts(v.write.0, v.write.1, v.write.2))),
        ];
        if !v.missing.is_empty() {
            fields.push(Node::new("Missing values").value(Value::Text(v.missing.join(", "))));
        }
        cx.push(
            Node::new(v.name.clone())
                .span(v.span)
                .summary(parts.join(", "))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

async fn label_sets(cx: Cx, por: Arc<Por>) -> Result<()> {
    for set in &por.labels {
        let entries: Vec<Node> = set
            .entries
            .iter()
            .map(|(_, v, l)| Node::new(v.clone()).value(Value::Text(l.clone())))
            .collect();
        cx.push(
            Node::new(set.vars.join(", "))
                .span(set.span)
                .summary(
                    set.entries
                        .iter()
                        .take(8)
                        .map(|(_, v, l)| format!("{v} = {l:?}"))
                        .collect::<Vec<_>>()
                        .join(", "),
                )
                .lazy(emit_nodes, Arc::new(entries)),
        )
        .await;
    }
    Ok(())
}

async fn cases(cx: Cx, por: Arc<Por>) -> Result<()> {
    let Some(start) = por.data else {
        return Ok(());
    };
    if por.vars.is_empty() {
        return Ok(());
    }
    cx.set_count(Count::Unknown);
    let mut r = Reader::new(&cx, por.file, por.xlat.clone());
    let (m, mut index) = cx.resume::<(Mark, u64)>().unwrap_or((start, 0));
    r.restore(m);
    loop {
        let here = (r.mark(), index);
        match r.peek().await? {
            None | Some(b'Z') => break,
            _ => {}
        }
        cx.mark(move || here);
        let case_start = r.pos;
        let mut items = Vec::new();
        for var in &por.vars {
            let at = r.pos;
            let (v, text) = value(&mut r, var.width == 0).await?;
            let span = por.file.sub(at, r.pos.saturating_sub(at));
            let cell = if var.width != 0 {
                Cell::Text(text.trim_end().to_owned())
            } else {
                match v {
                    None => Cell::Missing {
                        name: "sysmis".to_owned(),
                        raw: None,
                    },
                    Some(x) => match date_type(i32::try_from(var.print.0).unwrap_or(0)) {
                        Some(time) => date_cell(x, 1.0, EPOCH, time),
                        None => Cell::Number(x),
                    },
                }
            };
            let label = por
                .labels
                .iter()
                .filter(|s| s.vars.contains(&var.name))
                .flat_map(|s| s.entries.iter())
                .find(|(n, t, _)| {
                    if var.width == 0 {
                        v.is_some() && *n == v
                    } else {
                        *t == text
                    }
                })
                .map(|(_, _, l)| l.clone());
            items.push(Item {
                name: var.name.clone(),
                cell,
                label,
                span,
            });
        }
        index = index.saturating_add(1);
        let span = por.file.sub(case_start, r.pos.saturating_sub(case_start));
        cx.push(row_node(format!("Case {index}"), span, items))
            .await;
    }
    Ok(())
}
