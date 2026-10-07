//! Stata `.dta` files: the binary layout of releases 113–115 (Stata 8–12)
//! and the tagged layout of releases 117–119 (Stata 13 and later).
//!
//! Both hold a header (byte order, variable and observation counts, data
//! label, time stamp), per-variable descriptors (types, names, sort order,
//! display formats, value label names, variable labels), the observations
//! as fixed-width rows, and value label tables; 117+ adds a section map,
//! characteristics and a table of long strings (strLs, `GSO` blocks).
//! Layout per Stata's `dta` documentation, as remembered; checked against
//! files written by ReadStat (pyreadstat) and by pandas' own writer.

use std::sync::Arc;

use super::{Cell, Item, date_cell, row_node, trim_end, until_nul};
use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::arcutil::emit_nodes;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::Value;

/// Stata dates count days (`%td`) or milliseconds (`%tc`) from 1960.
const EPOCH_1960: i64 = -315_619_200;

/// Binary releases we read (113–115), with a plausible header and the
/// first variable types valid.
fn probe(h: &Head<'_>) -> bool {
    if h.starts_with(b"<stata_dta>") {
        return true;
    }
    let d = h.data;
    let (Some(&release), Some(&order), Some(&kind), Some(&zero)) =
        (d.first(), d.get(1), d.get(2), d.get(3))
    else {
        return false;
    };
    if !(113..=115).contains(&release) || !matches!(order, 1 | 2) || kind != 1 || zero != 0 {
        return false;
    }
    let nvar = if order == 1 {
        crate::bytes::u16_be(d, 4)
    } else {
        crate::bytes::u16_le(d, 4)
    }
    .unwrap_or(0);
    let types = d.get(109..109usize.saturating_add(usize::from(nvar).min(64)));
    nvar > 0
        && types
            .is_some_and(|t| !t.is_empty() && t.iter().all(|&b| (1..=244).contains(&b) || b >= 251))
        && h.len >= 109u64.saturating_add(u64::from(nvar).saturating_mul(2))
}

declare_format!(pub STATA = "stata-dta", "Stata data file", ["dta"], "application/x-stata-dta",
    Probe::Custom(probe), dissect);

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Kind {
    Byte,
    Int,
    Long,
    Float,
    Double,
    Str(u64),
    StrL,
}

impl Kind {
    fn width(self) -> u64 {
        match self {
            Kind::Byte => 1,
            Kind::Int => 2,
            Kind::Long | Kind::Float => 4,
            Kind::Double | Kind::StrL => 8,
            Kind::Str(n) => n,
        }
    }

    fn name(self) -> String {
        match self {
            Kind::Byte => "byte".to_owned(),
            Kind::Int => "int".to_owned(),
            Kind::Long => "long".to_owned(),
            Kind::Float => "float".to_owned(),
            Kind::Double => "double".to_owned(),
            Kind::Str(n) => format!("str{n}"),
            Kind::StrL => "strL".to_owned(),
        }
    }
}

#[derive(Clone, Debug)]
struct Var {
    name: String,
    label: String,
    format: String,
    labels: String,
    kind: Kind,
    /// Offset within a row.
    offset: u64,
}

#[derive(Clone, Debug)]
struct LabelSet {
    name: String,
    span: Span,
    entries: Vec<(i32, String)>,
}

#[derive(Clone, Debug)]
struct Strl {
    v: u64,
    o: u64,
    binary: bool,
    data: Span,
}

#[derive(Clone, Debug)]
struct Dta {
    release: u32,
    endian: Endian,
    vars: Vec<Var>,
    rows: u64,
    row: u64,
    data: Span,
    sets: Vec<LabelSet>,
    strls: Vec<Strl>,
}

impl Dta {
    fn utf8(&self) -> bool {
        self.release >= 118
    }

    fn text(&self, bytes: &[u8]) -> String {
        let bytes = until_nul(bytes);
        if self.utf8() {
            String::from_utf8_lossy(bytes).into_owned()
        } else {
            super::decode_text(Some("windows-1252"), bytes)
        }
    }

    fn uint(&self, b: &[u8], at: usize, n: usize) -> u64 {
        let bytes = b.get(at..at.saturating_add(n)).unwrap_or_default();
        match self.endian {
            Endian::Big => crate::formats::util::datakit::be_uint(bytes),
            Endian::Little => crate::formats::util::datakit::le_uint(bytes),
        }
    }

    fn i32(&self, b: &[u8], at: usize) -> i32 {
        self.uint(b, at, 4) as u32 as i32
    }

    fn set(&self, name: &str) -> Option<&LabelSet> {
        if name.is_empty() {
            return None;
        }
        self.sets.iter().find(|s| s.name == name)
    }
}

fn kind_117(code: u64) -> Option<Kind> {
    Some(match code {
        1..=2045 => Kind::Str(code),
        32768 => Kind::StrL,
        65526 => Kind::Double,
        65527 => Kind::Float,
        65528 => Kind::Long,
        65529 => Kind::Int,
        65530 => Kind::Byte,
        _ => return None,
    })
}

fn kind_old(code: u8) -> Option<Kind> {
    Some(match code {
        1..=244 => Kind::Str(code.into()),
        251 => Kind::Byte,
        252 => Kind::Int,
        253 => Kind::Long,
        254 => Kind::Float,
        255 => Kind::Double,
        _ => return None,
    })
}

/// Finds `tag` in `hay` at or after `from`.
fn find(hay: &[u8], tag: &[u8], from: usize) -> Option<usize> {
    hay.get(from..)?
        .windows(tag.len())
        .position(|w| w == tag)
        .map(|p| p.saturating_add(from))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    if cx.read_avail(input.span.sub(0, 11)).await? == b"<stata_dta>" {
        tagged(cx, input.span).await
    } else {
        binary(cx, input.span).await
    }
}

fn text_node(name: &'static str, span: Span, s: &str) -> Node {
    Node::new(name).span(span).value(Value::Text(s.to_owned()))
}

fn int_node(name: &'static str, span: Span, v: u64) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value: v,
        bits: u8::try_from(span.len.saturating_mul(8).min(64)).unwrap_or(64),
        radix: crate::value::Radix::Dec,
    })
}

/// Reads `count` fixed-size names (or labels, formats) of `size` bytes.
async fn strings(cx: &Cx, dta: &Dta, span: Span, count: usize, size: u64) -> Result<Vec<String>> {
    let raw = cx
        .read(span.sub_exact(0, to_u64(count).saturating_mul(size))?)
        .await?;
    Ok(raw
        .chunks(to_usize(size.max(1)))
        .take(count)
        .map(|c| dta.text(c))
        .collect())
}

/// Releases 113–115.
async fn binary(cx: Cx, file: Span) -> Result<()> {
    let head = cx.read(file.sub(0, 109)).await?;
    let release = u32::from(head.first().copied().unwrap_or(0));
    let endian = if head.get(1) == Some(&1) {
        Endian::Big
    } else {
        Endian::Little
    };
    let mut dta = Dta {
        release,
        endian,
        vars: Vec::new(),
        rows: 0,
        row: 0,
        data: file.sub(0, 0),
        sets: Vec::new(),
        strls: Vec::new(),
    };
    let nvar = dta.uint(&head, 4, 2);
    let nobs = dta.uint(&head, 6, 4);
    let label = dta.text(head.get(10..91).unwrap_or_default());
    let stamp = dta.text(head.get(91..109).unwrap_or_default());
    let header = vec![
        int_node("Release", file.sub(0, 1), release.into()),
        Node::new("Byte order")
            .span(file.sub(1, 1))
            .value(Value::Text(
                if endian == Endian::Big {
                    "HILO (big-endian)"
                } else {
                    "LOHI (little-endian)"
                }
                .to_owned(),
            )),
        int_node(
            "File type",
            file.sub(2, 1),
            head.get(2).copied().unwrap_or(0).into(),
        ),
        int_node("Variables", file.sub(4, 2), nvar),
        int_node("Observations", file.sub(6, 4), nobs),
        text_node("Data label", file.sub(10, 81), &label),
        text_node("Time stamp", file.sub(91, 18), &stamp),
    ];
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, 109))
            .lazy(emit_nodes, Arc::new(header)),
    );
    let n = to_usize(nvar);
    let fmt_len = if release >= 114 { 49 } else { 12 };
    let mut at = 109u64;
    let mut section = |name: &'static str, len: u64| {
        let span = file.sub(at, len);
        at = at.saturating_add(len);
        (name, span)
    };
    let types = section("Variable types", nvar);
    let names = section("Variable names", nvar.saturating_mul(33));
    let sort = section("Sort order", nvar.saturating_add(1).saturating_mul(2));
    let formats = section("Display formats", nvar.saturating_mul(fmt_len));
    let lbl = section("Value label names", nvar.saturating_mul(33));
    let labels = section("Variable labels", nvar.saturating_mul(81));
    let raw_types = cx
        .read(file.sub_exact(types.1.offset.saturating_sub(file.offset), nvar)?)
        .await?;
    let names_v = strings(&cx, &dta, names.1, n, 33).await?;
    let formats_v = strings(&cx, &dta, formats.1, n, fmt_len).await?;
    let lbl_v = strings(&cx, &dta, lbl.1, n, 33).await?;
    let labels_v = strings(&cx, &dta, labels.1, n, 81).await?;
    let mut offset = 0u64;
    for i in 0..n {
        let code = raw_types.get(i).copied().unwrap_or(0);
        let kind = kind_old(code).ok_or_else(|| {
            Diagnostic::malformed(format!("unknown variable type {code}"))
                .at(types.1.sub(to_u64(i), 1))
        })?;
        dta.vars.push(Var {
            name: names_v.get(i).cloned().unwrap_or_default(),
            label: labels_v.get(i).cloned().unwrap_or_default(),
            format: formats_v.get(i).cloned().unwrap_or_default(),
            labels: lbl_v.get(i).cloned().unwrap_or_default(),
            kind,
            offset,
        });
        offset = offset.saturating_add(kind.width());
    }
    for (name, span) in [types, names, sort, formats, lbl, labels] {
        cx.emit(Node::new(name).span(span));
    }
    // Expansion fields: a type byte and a 4-byte length, until 0 and 0.
    let start = at;
    let mut fields = 0u32;
    loop {
        cx.checkpoint().await;
        let raw = cx.read(file.sub(at, 5)).await?;
        let kind = raw.first().copied().unwrap_or(0);
        let len = dta.uint(&raw, 1, 4);
        at = at.saturating_add(5);
        if kind == 0 && len == 0 {
            break;
        }
        file.sub_exact(at, len)?;
        at = at.saturating_add(len);
        fields = fields.saturating_add(1);
    }
    cx.emit(
        Node::new("Expansion fields")
            .span(file.sub(start, at.saturating_sub(start)))
            .summary(format!("{fields} fields")),
    );
    dta.row = offset;
    dta.rows = nobs;
    dta.data = file.sub(at, nobs.saturating_mul(offset));
    // Value labels follow the data, to the end of the file.
    let mut pos = dta.data.end().saturating_sub(file.offset);
    let mut problem = None;
    while pos < file.len {
        cx.checkpoint().await;
        match label_table(&cx, &dta, file, pos, 33).await {
            Ok((set, next)) => {
                dta.sets.push(set);
                pos = next;
            }
            Err(e) => {
                problem = Some(e);
                break;
            }
        }
    }
    finish(&cx, dta, problem, &label, &stamp, None)
}

/// One value label table at `pos`: its length, name, padding, and table.
async fn label_table(
    cx: &Cx,
    dta: &Dta,
    file: Span,
    pos: u64,
    name_len: u64,
) -> Result<(LabelSet, u64)> {
    let head = cx
        .read(file.sub_exact(pos, 4u64.saturating_add(name_len).saturating_add(3))?)
        .await?;
    let len = dta.uint(&head, 0, 4);
    let name = dta.text(head.get(4..).unwrap_or_default());
    let table_at = pos
        .saturating_add(4)
        .saturating_add(name_len)
        .saturating_add(3);
    let table = file.sub_exact(table_at, len)?;
    let raw = cx.read(table).await?;
    let n = u64::from(dta.i32(&raw, 0).max(0) as u32);
    let txt_len = u64::from(dta.i32(&raw, 4).max(0) as u32);
    let offsets = 8u64;
    let values = offsets.saturating_add(n.saturating_mul(4));
    let text = values.saturating_add(n.saturating_mul(4));
    if text.saturating_add(txt_len) > len {
        return Err(Diagnostic::malformed("value label table overruns its length").at(table));
    }
    let mut entries = Vec::new();
    for i in 0..n {
        let off = dta.uint(
            &raw,
            to_usize(offsets.saturating_add(i.saturating_mul(4))),
            4,
        );
        let value = dta.i32(&raw, to_usize(values.saturating_add(i.saturating_mul(4))));
        let start = to_usize(text.saturating_add(off));
        let end = to_usize(text.saturating_add(txt_len));
        let label = dta.text(raw.get(start..end).unwrap_or_default());
        entries.push((value, label));
    }
    Ok((
        LabelSet {
            name,
            span: file.sub(pos, table_at.saturating_add(len).saturating_sub(pos)),
            entries,
        },
        table_at.saturating_add(len),
    ))
}

/// Releases 117–119.
async fn tagged(cx: Cx, file: Span) -> Result<()> {
    let head = cx.read_avail(file.sub(0, 512)).await?;
    let tag_value = |name: &[u8]| -> Option<(usize, usize)> {
        let open = [b"<", name, b">"].concat();
        let close = [b"</", name, b">"].concat();
        let start = find(&head, &open, 0)?.saturating_add(open.len());
        let end = find(&head, &close, start)?;
        Some((start, end))
    };
    let text_of = |r: Option<(usize, usize)>| {
        r.and_then(|(s, e)| head.get(s..e))
            .map(|b| String::from_utf8_lossy(b).into_owned())
            .unwrap_or_default()
    };
    let release_at = tag_value(b"release");
    let release: u32 = text_of(release_at).trim().parse().unwrap_or(0);
    let order = text_of(tag_value(b"byteorder"));
    let endian = if order == "MSF" {
        Endian::Big
    } else {
        Endian::Little
    };
    let mut dta = Dta {
        release,
        endian,
        vars: Vec::new(),
        rows: 0,
        row: 0,
        data: file.sub(0, 0),
        sets: Vec::new(),
        strls: Vec::new(),
    };
    let span_of = |r: (usize, usize)| file.sub(to_u64(r.0), to_u64(r.1.saturating_sub(r.0)));
    let k_at =
        tag_value(b"K").ok_or_else(|| Diagnostic::malformed("no <K> tag").at(file.sub(0, 512)))?;
    let n_at =
        tag_value(b"N").ok_or_else(|| Diagnostic::malformed("no <N> tag").at(file.sub(0, 512)))?;
    let k = dta.uint(&head, k_at.0, k_at.1.saturating_sub(k_at.0).min(8));
    let n = dta.uint(&head, n_at.0, n_at.1.saturating_sub(n_at.0).min(8));
    let mut header = vec![
        Node::new("Release")
            .span(release_at.map_or(file.sub(0, 0), span_of))
            .value(Value::UInt {
                value: release.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            }),
        Node::new("Byte order")
            .span(tag_value(b"byteorder").map_or(file.sub(0, 0), span_of))
            .value(Value::Text(order.clone())),
        int_node("Variables (K)", span_of(k_at), k),
        int_node("Observations (N)", span_of(n_at), n),
    ];
    let mut label = String::new();
    if let Some((s, e)) = tag_value(b"label") {
        let wide = usize::from(release >= 118);
        let len = to_usize(dta.uint(&head, s, wide.saturating_add(1)));
        let at = s.saturating_add(wide).saturating_add(1);
        label = dta.text(
            head.get(at..at.saturating_add(len).min(e))
                .unwrap_or_default(),
        );
        header.push(text_node("Data label", span_of((s, e)), &label));
    }
    let mut stamp = String::new();
    if let Some((s, e)) = tag_value(b"timestamp") {
        stamp = dta.text(head.get(s.saturating_add(1)..e).unwrap_or_default());
        header.push(text_node("Time stamp", span_of((s, e)), &stamp));
    }
    let header_end = find(&head, b"</header>", 0).map_or(0, |p| p.saturating_add(9));
    cx.emit(
        Node::new("Header")
            .span(file.sub(0, to_u64(header_end)))
            .lazy(emit_nodes, Arc::new(header)),
    );
    // The map: 14 offsets of the sections.
    let map_at = to_u64(
        find(&head, b"<map>", 0)
            .ok_or_else(|| Diagnostic::malformed("no <map>").at(file.sub(0, 512)))?,
    )
    .saturating_add(5);
    let map_raw = cx.read(file.sub_exact(map_at, 14 * 8)?).await?;
    let map: Vec<u64> = (0..14usize)
        .map(|i| dta.uint(&map_raw, i.saturating_mul(8), 8))
        .collect();
    const SECTIONS: [&str; 14] = [
        "<stata_dta>",
        "Map",
        "Variable types",
        "Variable names",
        "Sort order",
        "Display formats",
        "Value label names",
        "Variable labels",
        "Characteristics",
        "Data",
        "Long strings (strLs)",
        "Value labels",
        "</stata_dta>",
        "End of file",
    ];
    let map_nodes: Vec<Node> = map
        .iter()
        .enumerate()
        .map(|(i, &v)| {
            Node::new(SECTIONS.get(i).copied().unwrap_or("?"))
                .span(file.sub(map_at.saturating_add(to_u64(i).saturating_mul(8)), 8))
                .value(Value::UInt {
                    value: v,
                    bits: 64,
                    radix: crate::value::Radix::Hex,
                })
        })
        .collect();
    let at = |i: usize| map.get(i).copied().unwrap_or(0);
    let section = |i: usize| file.sub(at(i), at(i.saturating_add(1)).saturating_sub(at(i)));
    cx.emit(
        Node::new("Map")
            .span(section(1))
            .lazy(emit_nodes, Arc::new(map_nodes)),
    );
    // Section bodies start after their opening tag.
    let body = |i: usize, tag: &str| {
        let s = section(i);
        s.sub(
            to_u64(tag.len()),
            s.len
                .saturating_sub(to_u64(tag.len()).saturating_mul(2).saturating_add(1)),
        )
    };
    let kn = to_usize(k);
    let name_len: u64 = if release >= 118 { 129 } else { 33 };
    let fmt_len: u64 = if release >= 118 { 57 } else { 49 };
    let vlabel_len: u64 = if release >= 118 { 321 } else { 81 };
    let types_raw = cx
        .read(body(2, "<variable_types>").sub_exact(0, k.saturating_mul(2))?)
        .await?;
    let names = strings(&cx, &dta, body(3, "<varnames>"), kn, name_len).await?;
    let formats = strings(&cx, &dta, body(5, "<formats>"), kn, fmt_len).await?;
    let lbl = strings(&cx, &dta, body(6, "<value_label_names>"), kn, name_len).await?;
    let labels = strings(&cx, &dta, body(7, "<variable_labels>"), kn, vlabel_len).await?;
    let mut offset = 0u64;
    for i in 0..kn {
        let code = dta.uint(&types_raw, i.saturating_mul(2), 2);
        let kind = kind_117(code).ok_or_else(|| {
            Diagnostic::malformed(format!("unknown variable type {code}")).at(body(
                2,
                "<variable_types>",
            )
            .sub(to_u64(i).saturating_mul(2), 2))
        })?;
        dta.vars.push(Var {
            name: names.get(i).cloned().unwrap_or_default(),
            label: labels.get(i).cloned().unwrap_or_default(),
            format: formats.get(i).cloned().unwrap_or_default(),
            labels: lbl.get(i).cloned().unwrap_or_default(),
            kind,
            offset,
        });
        offset = offset.saturating_add(kind.width());
    }
    for i in 2..=8 {
        cx.emit(Node::new(SECTIONS.get(i).copied().unwrap_or("?")).span(section(i)));
    }
    dta.row = offset;
    dta.rows = n;
    dta.data = body(9, "<data>");
    // Long strings: "GSO", v, o, type, length, data.
    let strls = body(10, "<strls>");
    let mut pos = 0u64;
    let o_len: u64 = if release >= 118 { 8 } else { 4 };
    let mut problem = None;
    while pos.saturating_add(3) <= strls.len {
        cx.checkpoint().await;
        let head_len = 3u64
            .saturating_add(4)
            .saturating_add(o_len)
            .saturating_add(5);
        let raw = cx.read(strls.sub(pos, head_len)).await?;
        if raw.get(..3) != Some(b"GSO") {
            problem = Some(Diagnostic::malformed("expected a GSO block").at(strls.sub(pos, 3)));
            break;
        }
        let v = dta.uint(&raw, 3, 4);
        let o = dta.uint(&raw, 7, to_usize(o_len));
        let t = raw
            .get(to_usize(7u64.saturating_add(o_len)))
            .copied()
            .unwrap_or(0);
        let len = dta.uint(&raw, to_usize(8u64.saturating_add(o_len)), 4);
        let data_at = pos.saturating_add(head_len);
        let data = match strls.sub_exact(data_at, len) {
            Ok(d) => d,
            Err(e) => {
                problem = Some(e);
                break;
            }
        };
        dta.strls.push(Strl {
            v,
            o,
            binary: t == 129,
            data,
        });
        pos = data_at.saturating_add(len);
    }
    // Value labels: "<lbl>", the table, "</lbl>".
    let tables = body(11, "<value_labels>");
    let mut pos = 0u64;
    while pos.saturating_add(5) <= tables.len && problem.is_none() {
        cx.checkpoint().await;
        if cx.read(tables.sub(pos, 5)).await? != b"<lbl>" {
            break;
        }
        let rel = tables
            .offset
            .saturating_sub(file.offset)
            .saturating_add(pos)
            .saturating_add(5);
        match label_table(&cx, &dta, file, rel, name_len).await {
            Ok((set, next)) => {
                dta.sets.push(set);
                pos = next
                    .saturating_add(6)
                    .saturating_sub(tables.offset.saturating_sub(file.offset));
            }
            Err(e) => problem = Some(e),
        }
    }
    let strl_count = dta.strls.len();
    finish(&cx, dta, problem, &label, &stamp, Some((strls, strl_count)))
}

fn finish(
    cx: &Cx,
    dta: Dta,
    problem: Option<Diagnostic>,
    label: &str,
    stamp: &str,
    strls: Option<(Span, usize)>,
) -> Result<()> {
    let dta = Arc::new(dta);
    cx.emit(
        Node::new("Variables")
            .summary(format!("{} variables", dta.vars.len()))
            .lazy(variables, dta.clone()),
    );
    let mut sets = Node::new("Value labels")
        .summary(format!("{} tables", dta.sets.len()))
        .lazy(label_sets, dta.clone());
    if let Some(p) = problem {
        sets = sets.diag(p);
    }
    if let Some((span, count)) = strls {
        cx.emit(
            Node::new("Long strings (strLs)")
                .span(span)
                .summary(format!("{count} GSO blocks"))
                .lazy(strl_nodes, dta.clone()),
        );
    }
    cx.emit(
        Node::new("Observations")
            .span(dta.data)
            .summary(format!("{} rows × {} bytes", dta.rows, dta.row))
            .lazy(observations, dta.clone()),
    );
    cx.emit(sets);
    let mut parts = vec![format!(
        "Stata release {}, {} variables × {} observations",
        dta.release,
        dta.vars.len(),
        dta.rows
    )];
    if !label.is_empty() {
        parts.push(format!("{label:?}"));
    }
    if !stamp.trim().is_empty() {
        parts.push(stamp.trim().to_owned());
    }
    parts.push(
        if dta.endian == Endian::Big {
            "big-endian"
        } else {
            "little-endian"
        }
        .to_owned(),
    );
    cx.annotate(parts.join(", "));
    Ok(())
}

async fn variables(cx: Cx, dta: Arc<Dta>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(dta.vars.len())));
    for var in &dta.vars {
        let mut parts = vec![var.kind.name(), var.format.clone()];
        if !var.label.is_empty() {
            parts.push(format!("{:?}", var.label));
        }
        if !var.labels.is_empty() {
            parts.push(format!("labels {}", var.labels));
        }
        let fields = vec![
            Node::new("Name").value(Value::Text(var.name.clone())),
            Node::new("Label").value(Value::Text(var.label.clone())),
            Node::new("Type").value(Value::Text(var.kind.name())),
            Node::new("Display format").value(Value::Text(var.format.clone())),
            Node::new("Value labels").value(Value::Text(var.labels.clone())),
            Node::new("Offset in row").value(Value::UInt {
                value: var.offset,
                bits: 64,
                radix: crate::value::Radix::Dec,
            }),
        ];
        cx.push(
            Node::new(var.name.clone())
                .summary(parts.join(", "))
                .lazy(emit_nodes, Arc::new(fields)),
        )
        .await;
    }
    Ok(())
}

async fn label_sets(cx: Cx, dta: Arc<Dta>) -> Result<()> {
    for set in &dta.sets {
        let entries: Vec<Node> = set
            .entries
            .iter()
            .map(|(v, l)| Node::new(v.to_string()).value(Value::Text(l.clone())))
            .collect();
        let summary = set
            .entries
            .iter()
            .take(8)
            .map(|(v, l)| format!("{v} = {l:?}"))
            .chain((set.entries.len() > 8).then(|| "…".to_owned()))
            .collect::<Vec<_>>()
            .join(", ");
        cx.push(
            Node::new(set.name.clone())
                .span(set.span)
                .summary(summary)
                .lazy(emit_nodes, Arc::new(entries)),
        )
        .await;
    }
    Ok(())
}

async fn strl_nodes(cx: Cx, dta: Arc<Dta>) -> Result<()> {
    for s in &dta.strls {
        let mut node = Node::new(format!("GSO ({}, {})", s.v, s.o)).span(s.data);
        if s.binary {
            node = node.summary(format!("{} bytes, binary", s.data.len));
        } else {
            let raw = cx.read_avail(s.data.sub(0, 256)).await?;
            node = node.value(Value::Text(dta.text(&raw)));
        }
        cx.push(node).await;
    }
    Ok(())
}

/// A numeric missing value's name (`.`, `.a` … `.z`) given its distance
/// from the first missing code.
fn missing(n: u64) -> Cell {
    let name = match n {
        0 => ".".to_owned(),
        1..=26 => format!(
            ".{}",
            char::from(b'a'.saturating_add(n as u8).saturating_sub(1))
        ),
        _ => format!(".? ({n})"),
    };
    Cell::Missing { name, raw: None }
}

fn number_cell(var: &Var, v: f64) -> Cell {
    let f = var.format.trim_start_matches('%').trim_start_matches('-');
    if f.starts_with("td") || f.starts_with('d') {
        date_cell(v, 86_400.0, EPOCH_1960, false)
    } else if f.starts_with("tc") || f.starts_with("tC") {
        date_cell(v, 0.001, EPOCH_1960, true)
    } else {
        Cell::Number(v)
    }
}

async fn decode_row(cx: &Cx, dta: &Dta, span: Span, raw: &[u8]) -> Result<Vec<Item>> {
    let mut items = Vec::new();
    for var in &dta.vars {
        let at = to_usize(var.offset);
        let width = var.kind.width();
        let cell_span = span.sub(var.offset, width);
        let int = |n: usize| dta.uint(raw, at, n);
        let cell = match var.kind {
            Kind::Byte => {
                let v = int(1) as u8 as i8;
                if v > 100 {
                    missing(u64::from((v as u8).saturating_sub(101)))
                } else {
                    number_cell(var, v.into())
                }
            }
            Kind::Int => {
                let v = int(2) as u16 as i16;
                if v > 32740 {
                    missing(u64::from((v as u16).saturating_sub(32741)))
                } else {
                    number_cell(var, v.into())
                }
            }
            Kind::Long => {
                let v = int(4) as u32 as i32;
                if v > 2_147_483_620 {
                    missing(u64::from((v as u32).saturating_sub(2_147_483_621)))
                } else {
                    number_cell(var, v.into())
                }
            }
            Kind::Float => {
                let bits = int(4) as u32;
                let v = f32::from_bits(bits);
                if (0x7f00_0000..0x8000_0000).contains(&bits) {
                    missing(u64::from(bits.saturating_sub(0x7f00_0000) >> 11))
                } else {
                    number_cell(var, v.into())
                }
            }
            Kind::Double => {
                let bits = int(8);
                if (0x7fe0_0000_0000_0000..0x8000_0000_0000_0000).contains(&bits) {
                    missing(bits.saturating_sub(0x7fe0_0000_0000_0000) >> 40)
                } else {
                    number_cell(var, f64::from_bits(bits))
                }
            }
            Kind::Str(n) => Cell::Text(
                dta.text(trim_end(
                    raw.get(at..at.saturating_add(to_usize(n)))
                        .unwrap_or_default(),
                )),
            ),
            Kind::StrL => {
                // (v, o): 4+4 bytes (117), 2+6 (118), 3+5 (119).
                let v_len = match dta.release {
                    117 => 4,
                    118 => 2,
                    _ => 3,
                };
                let (v, o) = match dta.endian {
                    Endian::Little => (
                        int(v_len),
                        dta.uint(raw, at.saturating_add(v_len), 8usize.saturating_sub(v_len)),
                    ),
                    Endian::Big => (
                        dta.uint(raw, at.saturating_add(8usize.saturating_sub(v_len)), v_len),
                        dta.uint(raw, at, 8usize.saturating_sub(v_len)),
                    ),
                };
                if v == 0 && o == 0 {
                    Cell::Text(String::new())
                } else {
                    match dta.strls.iter().find(|s| s.v == v && s.o == o) {
                        Some(s) if !s.binary => {
                            let bytes = cx.read_avail(s.data.sub(0, 4096)).await?;
                            Cell::Text(dta.text(&bytes))
                        }
                        Some(s) => Cell::Text(format!("<{} bytes of binary>", s.data.len)),
                        None => Cell::Text(format!("<strL ({v}, {o}) not found>")),
                    }
                }
            }
        };
        let label = match (&cell, dta.set(&var.labels)) {
            (Cell::Number(v), Some(set)) => set
                .entries
                .iter()
                .find(|(k, _)| f64::from(*k) == *v)
                .map(|(_, l)| l.clone()),
            _ => None,
        };
        items.push(Item {
            name: var.name.clone(),
            cell,
            label,
            span: cell_span,
        });
    }
    Ok(items)
}

async fn observations(cx: Cx, dta: Arc<Dta>) -> Result<()> {
    if dta.row == 0 {
        return Ok(());
    }
    cx.set_count(Count::Exact(dta.rows));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    while i < dta.rows {
        let at = i;
        cx.mark(move || at);
        let span = dta.data.sub(i.saturating_mul(dta.row), dta.row);
        let name = format!("Observation {}", i.saturating_add(1));
        if cx.skipping() {
            cx.push(Node::new(name)).await;
            i = i.saturating_add(1);
            continue;
        }
        let raw = cx.read(span).await?;
        if to_u64(raw.len()) < dta.row {
            return Err(Diagnostic::truncated(span, to_u64(raw.len())));
        }
        let items = decode_row(&cx, &dta, span, &raw).await?;
        cx.push(row_node(name, span, items)).await;
        i = i.saturating_add(1);
    }
    Ok(())
}
