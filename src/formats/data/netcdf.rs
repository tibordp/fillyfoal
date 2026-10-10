//! NetCDF classic files (CDF-1, the 64-bit offset CDF-2 and the 64-bit
//! data CDF-5): a header of dimensions, global attributes and variables,
//! then the data of the fixed-size variables, then the records (one slab
//! of every record variable per step along the unlimited dimension).
//!
//! Layouts follow the NetCDF Classic and 64-bit Offset Format
//! specification and the CDF-5 extension (8-byte counts and sizes, five
//! more types). Checked against files written by netCDF-C 4.9 and SciPy.
//! NetCDF-4 files are HDF5 and dissected there.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const BE: Endian = Endian::Big;
/// Elements per header list accepted.
const MAX_ELEMENTS: u64 = 1 << 16;
/// Values read at once.
const WINDOW: u64 = 64 * 1024;

pub static FORMAT: Format = Format {
    name: "netcdf",
    title: "NetCDF classic data",
    extensions: &["nc", "cdf", "nc3"],
    mime: "application/x-netcdf",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    // The dimension list follows the record count (8 bytes in CDF-5).
    let tag_at = match h.data.get(3) {
        Some(1 | 2) => 8usize,
        Some(5) => 12,
        _ => return false,
    };
    h.starts_with(b"CDF")
        && h.data
            .get(tag_at..tag_at.saturating_add(4))
            .is_some_and(|t| matches!(t, [0, 0, 0, 0 | 0x0a]))
}

const TYPES: EnumTable = &[
    (1, "byte"),
    (2, "char"),
    (3, "short"),
    (4, "int"),
    (5, "float"),
    (6, "double"),
    (7, "ubyte"),
    (8, "ushort"),
    (9, "uint"),
    (10, "int64"),
    (11, "uint64"),
];

const VERSIONS: EnumTable = &[
    (1, "classic (CDF-1)"),
    (2, "64-bit offset (CDF-2)"),
    (5, "64-bit data (CDF-5)"),
];

fn type_size(t: u32) -> u64 {
    match t {
        1 | 2 | 7 => 1,
        3 | 8 => 2,
        4 | 5 | 9 => 4,
        _ => 8,
    }
}

fn type_name(t: u32) -> &'static str {
    lookup(TYPES, t.into()).unwrap_or("unknown")
}

fn pad4(n: u64) -> u64 {
    n.wrapping_neg() & 3
}

#[derive(Clone, Debug)]
struct Dim {
    name: String,
    len: u64,
    span: Span,
}

#[derive(Clone, Debug)]
struct Attr {
    name: String,
    kind: u32,
    count: u64,
    values: Span,
    span: Span,
}

#[derive(Clone, Debug)]
struct Var {
    name: String,
    dims: Vec<u64>,
    attrs: Vec<Attr>,
    attr_span: Span,
    kind: u32,
    vsize: u64,
    begin: u64,
    span: Span,
}

struct Header {
    input: Input,
    version: u8,
    numrecs: u64,
    streaming: bool,
    dims: Vec<Dim>,
    dim_span: Span,
    attrs: Vec<Attr>,
    attr_span: Span,
    vars: Vec<Var>,
    var_span: Span,
    /// Bytes per record (all record variables, padded).
    recsize: u64,
    /// Where the records start.
    recstart: u64,
}

impl Header {
    fn wide(&self) -> bool {
        self.version == 5
    }

    fn dim(&self, id: u64) -> Option<&Dim> {
        self.dims.get(to_usize(id))
    }

    fn is_record(&self, v: &Var) -> bool {
        v.dims
            .first()
            .and_then(|&id| self.dim(id))
            .is_some_and(|d| d.len == 0)
    }

    /// The sizes of a variable's dimensions (the record dimension excluded).
    fn shape(&self, v: &Var) -> Vec<u64> {
        let skip = usize::from(self.is_record(v));
        v.dims
            .iter()
            .skip(skip)
            .map(|&id| self.dim(id).map_or(0, |d| d.len))
            .collect()
    }

    /// Bytes of one slab (the whole variable, or one record of it).
    fn slab(&self, v: &Var) -> u64 {
        self.shape(v)
            .iter()
            .fold(type_size(v.kind), |a, &d| a.saturating_mul(d))
    }
}

/// Reads the header as it is laid out (counts are 8 bytes in CDF-5).
struct Reader<'a> {
    cur: Cursor<'a>,
    wide: bool,
}

impl Reader<'_> {
    async fn count(&mut self) -> Result<u64> {
        if self.wide {
            self.cur.u64().await
        } else {
            Ok(self.cur.u32().await?.into())
        }
    }

    async fn name(&mut self) -> Result<String> {
        let at = self.cur.span(4);
        let len = self.count().await?;
        if len > 1 << 16 || self.cur.span(len).len < len {
            return Err(Diagnostic::malformed("invalid name length").at(at));
        }
        let bytes = self.cur.bytes(len).await?;
        self.cur.skip(pad4(len));
        Ok(String::from_utf8_lossy(&bytes).into_owned())
    }

    /// A list header: tag and element count (`ABSENT` is two zeros).
    async fn list(&mut self, tag: u32) -> Result<u64> {
        let at = self.cur.span(4);
        let t = self.cur.u32().await?;
        let n = self.count().await?;
        if t == 0 && n == 0 {
            return Ok(0);
        }
        if t != tag {
            return Err(
                Diagnostic::malformed(format!("expected list tag {tag:#x}, found {t:#x}")).at(at),
            );
        }
        if n > MAX_ELEMENTS {
            return Err(Diagnostic::limit(format!("{n} list elements")).at(at));
        }
        Ok(n)
    }

    async fn attrs(&mut self) -> Result<(Vec<Attr>, Span)> {
        let start = self.cur.pos();
        let n = self.list(0x0c).await?;
        let mut out = Vec::new();
        for _ in 0..n {
            let at = self.cur.pos();
            let name = self.name().await?;
            let kind = self.cur.u32().await?;
            let count = self.count().await?;
            let len = count.saturating_mul(type_size(kind));
            let values = self.cur.span(len);
            if values.len < len {
                return Err(Diagnostic::truncated(
                    Span::new(values.source, values.offset, len),
                    values.len,
                ));
            }
            self.cur.skip(len.saturating_add(pad4(len)));
            out.push(Attr {
                name,
                kind,
                count,
                values,
                span: self.cur.since(at),
            });
        }
        Ok((out, self.cur.since(start)))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let version = head.get(3).copied().unwrap_or(1);
    let wide = version == 5;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(Value::Enum {
        raw: version.into(),
        bits: 8,
        name: lookup(VERSIONS, version.into()),
    }));
    let mut r = Reader {
        cur: Cursor::new(&cx, file, BE),
        wide,
    };
    r.cur.seek(4);
    let numrecs_span = r.cur.span(if wide { 8 } else { 4 });
    let numrecs = r.count().await?;
    let streaming = numrecs == if wide { u64::MAX } else { u64::from(u32::MAX) };
    // Dimensions.
    let start = r.cur.pos();
    let n = r.list(0x0a).await?;
    let mut dims = Vec::new();
    for _ in 0..n {
        let at = r.cur.pos();
        let name = r.name().await?;
        let len = r.count().await?;
        dims.push(Dim {
            name,
            len,
            span: r.cur.since(at),
        });
    }
    let dim_span = r.cur.since(start);
    let (attrs, attr_span) = r.attrs().await?;
    // Variables.
    let start = r.cur.pos();
    let n = r.list(0x0b).await?;
    let mut vars = Vec::new();
    for _ in 0..n {
        cx.checkpoint().await;
        let at = r.cur.pos();
        let name = r.name().await?;
        let ndims = r.count().await?;
        if ndims > 1024 {
            return Err(Diagnostic::malformed("too many dimensions").at(r.cur.span(4)));
        }
        let mut ids = Vec::new();
        for _ in 0..ndims {
            ids.push(r.count().await?);
        }
        let (vattrs, vattr_span) = r.attrs().await?;
        let kind = r.cur.u32().await?;
        let vsize = r.count().await?;
        let begin = if version == 1 {
            u64::from(r.cur.u32().await?)
        } else {
            r.cur.u64().await?
        };
        vars.push(Var {
            name,
            dims: ids,
            attrs: vattrs,
            attr_span: vattr_span,
            kind,
            vsize,
            begin,
            span: r.cur.since(at),
        });
    }
    let var_span = r.cur.since(start);
    let header_end = r.cur.pos();
    let mut header = Header {
        input,
        version,
        numrecs,
        streaming,
        dims,
        dim_span,
        attrs,
        attr_span,
        vars,
        var_span,
        recsize: 0,
        recstart: 0,
    };
    // Records: every record variable's slab, each padded to 4 bytes unless
    // it is the only record variable.
    let (recstart, recsize) = {
        let records: Vec<&Var> = header.vars.iter().filter(|v| header.is_record(v)).collect();
        let single = records.len() == 1;
        let size = records.iter().fold(0u64, |a, v| {
            let slab = header.slab(v);
            a.saturating_add(if single {
                slab
            } else {
                slab.saturating_add(pad4(slab))
            })
        });
        (records.iter().map(|v| v.begin).min().unwrap_or(0), size)
    };
    header.recstart = recstart;
    header.recsize = recsize;
    if header.streaming && header.recsize > 0 {
        header.numrecs = file
            .len
            .saturating_sub(header.recstart)
            .checked_div(header.recsize)
            .unwrap_or(0);
    }
    let header = Arc::new(header);
    let unlimited = header
        .dims
        .iter()
        .find(|d| d.len == 0)
        .map(|d| d.name.clone());
    cx.annotate(format!(
        "NetCDF {}, {} dimensions{}, {} variables, {} global attributes",
        lookup(VERSIONS, version.into()).unwrap_or("classic"),
        header.dims.len(),
        unlimited.as_ref().map_or_else(String::new, |u| format!(
            " ({u} unlimited, {} records)",
            header.numrecs
        )),
        header.vars.len(),
        header.attrs.len()
    ));
    let mut node = Node::new("Number of records")
        .span(numrecs_span)
        .value(Value::UInt {
            value: numrecs,
            bits: if wide { 64 } else { 32 },
            radix: Radix::Dec,
        });
    if streaming {
        node = node.summary(format!(
            "streaming (not yet known); {} complete records in the file",
            header.numrecs
        ));
    }
    cx.emit(node);
    cx.emit(
        Node::new("Dimensions")
            .span(header.dim_span)
            .summary(format!("{}", header.dims.len()))
            .lazy(dimensions, header.clone()),
    );
    cx.emit(
        Node::new("Global attributes")
            .span(header.attr_span)
            .summary(format!("{}", header.attrs.len()))
            .lazy(global_attributes, header.clone()),
    );
    cx.emit(
        Node::new("Variables")
            .span(header.var_span)
            .summary(format!("{}", header.vars.len()))
            .lazy(variables, header.clone()),
    );
    // Header padding: space reserved before the first variable's data.
    let first = header
        .vars
        .iter()
        .map(|v| v.begin)
        .filter(|&b| b >= header_end)
        .min()
        .unwrap_or(file.len)
        .min(file.len);
    if first > header_end {
        cx.emit(
            Node::new("Header padding")
                .span(file.sub(header_end, first.saturating_sub(header_end)))
                .summary("reserved for the header to grow"),
        );
    }
    cx.emit(
        Node::new("Data")
            .span(file.sub(first, file.len.saturating_sub(first)))
            .summary(crate::formats::util::datakit::size(
                file.len.saturating_sub(first),
            ))
            .lazy(data, header.clone()),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// Header fields

/// Renders big-endian header fields from bytes in memory.
struct Fr<'a> {
    data: &'a [u8],
    span: Span,
    pos: usize,
    wide: bool,
    out: Vec<Node>,
}

impl<'a> Fr<'a> {
    fn new(data: &'a [u8], span: Span, wide: bool) -> Self {
        Fr {
            data,
            span,
            pos: 0,
            wide,
            out: Vec::new(),
        }
    }

    fn take(&mut self, n: usize) -> Option<(&'a [u8], Span)> {
        let data: &'a [u8] = self.data;
        let bytes = data.get(self.pos..self.pos.checked_add(n)?)?;
        let span = self.span.sub(to_u64(self.pos), to_u64(n));
        self.pos = self.pos.saturating_add(n);
        Some((bytes, span))
    }

    fn uint(&mut self, name: &'static str, n: usize) -> Option<u64> {
        let (bytes, span) = self.take(n)?;
        let v = crate::formats::util::datakit::be_uint(bytes);
        self.out.push(Node::new(name).span(span).value(Value::UInt {
            value: v,
            bits: u8::try_from(n.saturating_mul(8)).unwrap_or(64),
            radix: Radix::Dec,
        }));
        Some(v)
    }

    fn count(&mut self, name: &'static str) -> Option<u64> {
        let n = if self.wide { 8 } else { 4 };
        self.uint(name, n)
    }

    fn note(&mut self, s: impl Into<String>) {
        if let Some(n) = self.out.last_mut() {
            n.summary = Some(s.into());
        }
    }

    fn name(&mut self) -> Option<String> {
        let len = self.count("Name length")?;
        let (bytes, span) = self.take(to_usize(len))?;
        let text = String::from_utf8_lossy(bytes).into_owned();
        self.out.push(
            Node::new("Name")
                .span(span)
                .value(Value::Text(text.clone())),
        );
        self.padding(len)?;
        Some(text)
    }

    fn padding(&mut self, len: u64) -> Option<()> {
        let n = to_usize(pad4(len));
        if n > 0 {
            let (bytes, span) = self.take(n)?;
            self.out.push(
                Node::new("Padding")
                    .span(span)
                    .value(Value::Bytes(bytes.to_vec())),
            );
        }
        Some(())
    }

    fn kind(&mut self) -> Option<u32> {
        let (bytes, span) = self.take(4)?;
        let v = crate::formats::util::datakit::be_uint(bytes);
        self.out
            .push(Node::new("Type").span(span).value(Value::Enum {
                raw: v,
                bits: 32,
                name: lookup(TYPES, v),
            }));
        u32::try_from(v).ok()
    }

    fn list_head(&mut self, tag: &'static str) -> Option<u64> {
        let (bytes, span) = self.take(4)?;
        let v = crate::formats::util::datakit::be_uint(bytes);
        self.out.push(
            Node::new("Tag")
                .span(span)
                .value(Value::UInt {
                    value: v,
                    bits: 32,
                    radix: Radix::Hex,
                })
                .summary(if v == 0 { "absent" } else { tag }),
        );
        self.count("Number of elements")
    }
}

fn emit(cx: &Cx, out: Vec<Node>) {
    for n in out {
        cx.emit(n);
    }
}

async fn list_header(cx: &Cx, header: &Header, span: Span, tag: &'static str) -> Result<()> {
    let n = if header.wide() { 12 } else { 8 };
    let head = span.sub(0, n);
    let data = cx.read(head).await?;
    let mut fr = Fr::new(&data, head, header.wide());
    fr.list_head(tag);
    emit(cx, fr.out);
    Ok(())
}

async fn dimensions(cx: Cx, header: Arc<Header>) -> Result<()> {
    list_header(&cx, &header, header.dim_span, "NC_DIMENSION").await?;
    for (i, d) in header.dims.iter().enumerate() {
        let value = if d.len == 0 {
            Value::Text("unlimited".to_owned())
        } else {
            Value::UInt {
                value: d.len,
                bits: 64,
                radix: Radix::Dec,
            }
        };
        let mut node = Node::new(d.name.clone())
            .span(d.span)
            .value(value)
            .lazy(dimension_fields, (header.clone(), i));
        if d.len == 0 {
            node = node.summary(format!("{} records", header.numrecs));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn dimension_fields(cx: Cx, (header, i): (Arc<Header>, usize)) -> Result<()> {
    let Some(d) = header.dims.get(i) else {
        return Ok(());
    };
    let data = cx.read(d.span).await?;
    let mut fr = Fr::new(&data, d.span, header.wide());
    if fr.name().is_some() {
        fr.count("Length");
        if d.len == 0 {
            fr.note("unlimited (the record dimension)");
        }
    }
    emit(&cx, fr.out);
    Ok(())
}

/// A big-endian number of NetCDF type `kind`.
fn number(kind: u32, c: &[u8]) -> Value {
    let arr = |n: usize| c.get(..n).unwrap_or_default();
    let v = match kind {
        1 => c.first().map(|&b| Value::Int {
            value: i64::from(b.cast_signed()),
            bits: 8,
        }),
        7 => c.first().map(|&b| Value::UInt {
            value: b.into(),
            bits: 8,
            radix: Radix::Dec,
        }),
        3 => arr(2).try_into().ok().map(|b| Value::Int {
            value: i16::from_be_bytes(b).into(),
            bits: 16,
        }),
        8 => arr(2).try_into().ok().map(|b| Value::UInt {
            value: u16::from_be_bytes(b).into(),
            bits: 16,
            radix: Radix::Dec,
        }),
        4 => arr(4).try_into().ok().map(|b| Value::Int {
            value: i32::from_be_bytes(b).into(),
            bits: 32,
        }),
        9 => arr(4).try_into().ok().map(|b| Value::UInt {
            value: u32::from_be_bytes(b).into(),
            bits: 32,
            radix: Radix::Dec,
        }),
        5 => arr(4)
            .try_into()
            .ok()
            .map(|b| Value::Float(f32::from_be_bytes(b).into())),
        6 => arr(8)
            .try_into()
            .ok()
            .map(|b| Value::Float(f64::from_be_bytes(b))),
        10 => arr(8).try_into().ok().map(|b| Value::Int {
            value: i64::from_be_bytes(b),
            bits: 64,
        }),
        11 => arr(8).try_into().ok().map(|b| Value::UInt {
            value: u64::from_be_bytes(b),
            bits: 64,
            radix: Radix::Dec,
        }),
        _ => None,
    };
    v.unwrap_or_else(|| Value::Bytes(c.to_vec()))
}

/// The values of an attribute: text for chars, otherwise a list.
fn attr_value(a: &Attr, data: &[u8]) -> Value {
    if a.kind == 2 {
        return Value::Text(
            String::from_utf8_lossy(data)
                .trim_end_matches('\0')
                .to_owned(),
        );
    }
    let size = to_usize(type_size(a.kind));
    let values: Vec<Value> = data
        .chunks_exact(size.max(1))
        .take(16)
        .map(|c| number(a.kind, c))
        .collect();
    if a.count == 1
        && let Some(v) = values.into_iter().next()
    {
        return v;
    }
    let shown: Vec<String> = data
        .chunks_exact(size.max(1))
        .take(16)
        .map(|c| crate::render::value(&number(a.kind, c)))
        .collect();
    let more = if a.count > 16 { ", …" } else { "" };
    Value::Text(format!("[{}{more}]", shown.join(", ")))
}

async fn attribute_nodes(
    cx: &Cx,
    header: &Arc<Header>,
    attrs: &[Attr],
    var: Option<usize>,
) -> Result<()> {
    for (i, a) in attrs.iter().enumerate() {
        let data = cx.read_avail(a.values.sub(0, 4096)).await?;
        let node = Node::new(a.name.clone())
            .span(a.span)
            .value(attr_value(a, &data))
            .summary(format!("{}[{}]", type_name(a.kind), a.count))
            .lazy(attribute_fields, (header.clone(), var, i));
        cx.push(node).await;
    }
    Ok(())
}

async fn attribute_fields(
    cx: Cx,
    (header, var, i): (Arc<Header>, Option<usize>, usize),
) -> Result<()> {
    let attrs = match var {
        Some(v) => header.vars.get(v).map(|v| v.attrs.as_slice()),
        None => Some(header.attrs.as_slice()),
    };
    let Some(a) = attrs.and_then(|a| a.get(i)) else {
        return Ok(());
    };
    let head_len = a.values.offset.saturating_sub(a.span.offset);
    let head = a.span.sub(0, head_len);
    let data = cx.read(head).await?;
    let mut fr = Fr::new(&data, head, header.wide());
    if fr.name().is_some() && fr.kind().is_some() {
        fr.count("Number of values");
    }
    emit(&cx, fr.out);
    let len = a.count.saturating_mul(type_size(a.kind));
    if a.kind == 2 || a.count <= 1 {
        let data = cx.read_avail(a.values.sub(0, 4096)).await?;
        cx.emit(
            Node::new("Values")
                .span(a.values)
                .value(attr_value(a, &data)),
        );
    } else {
        cx.emit(
            Node::new("Values")
                .span(a.values)
                .summary(format!("{} {}", a.count, type_name(a.kind)))
                .lazy(
                    values,
                    Slab {
                        span: a.values,
                        kind: a.kind,
                        shape: Arc::new(vec![a.count]),
                        record: None,
                    },
                ),
        );
    }
    let pad = a.values.sub(len, pad4(len));
    if pad.len > 0 {
        let bytes = cx.read(pad).await?;
        cx.emit(Node::new("Padding").span(pad).value(Value::Bytes(bytes)));
    }
    Ok(())
}

async fn global_attributes(cx: Cx, header: Arc<Header>) -> Result<()> {
    list_header(&cx, &header, header.attr_span, "NC_ATTRIBUTE").await?;
    attribute_nodes(&cx, &header, &header.attrs, None).await
}

/// `short temp(time, lat, lon)`.
fn signature(header: &Header, var: &Var) -> String {
    let names: Vec<String> = var
        .dims
        .iter()
        .map(|&id| {
            header
                .dim(id)
                .map_or_else(|| format!("#{id}"), |d| d.name.clone())
        })
        .collect();
    format!("{} {}({})", type_name(var.kind), var.name, names.join(", "))
}

/// The value of a text attribute of a variable, if any.
async fn text_attr(cx: &Cx, var: &Var, name: &str) -> Option<String> {
    let a = var.attrs.iter().find(|a| a.name == name && a.kind == 2)?;
    let data = cx.read_avail(a.values.sub(0, 256)).await.ok()?;
    Some(
        String::from_utf8_lossy(&data)
            .trim_end_matches('\0')
            .to_owned(),
    )
}

async fn variables(cx: Cx, header: Arc<Header>) -> Result<()> {
    list_header(&cx, &header, header.var_span, "NC_VARIABLE").await?;
    for (i, v) in header.vars.iter().enumerate() {
        let mut summary = signature(&header, v);
        if let Some(units) = text_attr(&cx, v, "units").await {
            summary = format!("{summary}, {units}");
        }
        if let Some(long) = text_attr(&cx, v, "long_name").await {
            summary = format!("{summary}, \"{long}\"");
        }
        cx.push(
            Node::new(v.name.clone())
                .span(v.span)
                .summary(summary)
                .lazy(variable, (header.clone(), i)),
        )
        .await;
    }
    Ok(())
}

async fn variable(cx: Cx, (header, index): (Arc<Header>, usize)) -> Result<()> {
    let Some(v) = header.vars.get(index) else {
        return Ok(());
    };
    let wide = header.wide();
    let width = if wide { 8u64 } else { 4 };
    // Name and dimension IDs.
    let head = v
        .span
        .sub(0, v.attr_span.offset.saturating_sub(v.span.offset));
    let data = cx.read(head).await?;
    let mut fr = Fr::new(&data, head, wide);
    if fr.name().is_some() && fr.count("Number of dimensions").is_some() {
        for &id in &v.dims {
            let Some((_, span)) = fr.take(to_usize(width)) else {
                break;
            };
            let mut node = Node::new("Dimension ID").span(span).value(Value::UInt {
                value: id,
                bits: 32,
                radix: Radix::Dec,
            });
            node = match header.dim(id) {
                Some(d) if d.len == 0 => node.summary(format!("{} (unlimited)", d.name)),
                Some(d) => node.summary(format!("{} = {}", d.name, d.len)),
                None => node.diag(Diagnostic::malformed(format!(
                    "dimension {id} does not exist"
                ))),
            };
            fr.out.push(node);
        }
    }
    emit(&cx, fr.out);
    cx.emit(
        Node::new("Attributes")
            .span(v.attr_span)
            .summary(format!("{}", v.attrs.len()))
            .lazy(var_attributes, (header.clone(), index)),
    );
    // Type, size and offset.
    let tail = v.span.tail(v.attr_span.end().saturating_sub(v.span.offset));
    let data = cx.read(tail).await?;
    let mut fr = Fr::new(&data, tail, wide);
    let record = header.is_record(v);
    if fr.kind().is_some() && fr.count("Size").is_some() {
        fr.note(if record {
            "bytes per record, padded to 4"
        } else {
            "bytes, padded to 4"
        });
        // Writers store 2^32 - 1 for variables too large to say (CDF-2).
        let slab = header.slab(v);
        let expected = slab.saturating_add(pad4(slab));
        if v.vsize != expected
            && v.vsize != u64::from(u32::MAX)
            && let Some(last) = fr.out.last_mut()
        {
            last.diagnostics.push(Diagnostic::warning(format!(
                "the dimensions say {expected} bytes"
            )));
        }
        let n = if header.version == 1 { 4 } else { 8 };
        if fr.uint("Begin", n).is_some()
            && let Some(last) = fr.out.last_mut()
        {
            last.value = Some(Value::UInt {
                value: v.begin,
                bits: u8::try_from(n.saturating_mul(8)).unwrap_or(64),
                radix: Radix::Hex,
            });
            last.target = Some(header.input.span.sub(v.begin, header.slab(v)));
        }
    }
    emit(&cx, fr.out);
    cx.emit(data_node(&header, v));
    Ok(())
}

async fn var_attributes(cx: Cx, (header, index): (Arc<Header>, usize)) -> Result<()> {
    let Some(v) = header.vars.get(index) else {
        return Ok(());
    };
    list_header(&cx, &header, v.attr_span, "NC_ATTRIBUTE").await?;
    attribute_nodes(&cx, &header, &v.attrs, Some(index)).await
}

// ---------------------------------------------------------------------------
// Data

/// Elements of one type laid out row-major (one slab of a variable).
#[derive(Clone)]
struct Slab {
    span: Span,
    kind: u32,
    shape: Arc<Vec<u64>>,
    /// The record index, for record variables.
    record: Option<u64>,
}

/// A variable's data: its slab, or its slab in each record.
fn data_node(header: &Arc<Header>, v: &Var) -> Node {
    let file = header.input.span;
    let slab = header.slab(v);
    let shape = Arc::new(header.shape(v));
    if !header.is_record(v) {
        let span = file.sub(v.begin, slab);
        let mut node = Node::new(v.name.clone())
            .span(span)
            .summary(format!(
                "{}, {}",
                signature(header, v),
                crate::formats::util::datakit::size(slab)
            ))
            .lazy(
                values,
                Slab {
                    span,
                    kind: v.kind,
                    shape,
                    record: None,
                },
            );
        if span.len < slab {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, slab),
                span.len,
            ));
        }
        return node;
    }
    Node::new(v.name.clone())
        .summary(format!(
            "{}, {} records of {}",
            signature(header, v),
            header.numrecs,
            crate::formats::util::datakit::size(slab)
        ))
        .target(file.sub(v.begin, slab))
        .lazy(record_slabs, (header.clone(), v.begin, v.kind, shape, slab))
}

async fn record_slabs(
    cx: Cx,
    (header, begin, kind, shape, slab): (Arc<Header>, u64, u32, Arc<Vec<u64>>, u64),
) -> Result<()> {
    let file = header.input.span;
    cx.set_count(Count::Exact(header.numrecs));
    let start = cx.resume::<u64>().unwrap_or(0);
    for r in start..header.numrecs {
        let at = begin.saturating_add(r.saturating_mul(header.recsize));
        if at >= file.len {
            break;
        }
        cx.mark(move || r);
        cx.push(
            Node::new(format!("Record {r}"))
                .span(file.sub(at, slab))
                .lazy(
                    values,
                    Slab {
                        span: file.sub(at, slab),
                        kind,
                        shape: shape.clone(),
                        record: Some(r),
                    },
                ),
        )
        .await;
    }
    Ok(())
}

/// Row-major coordinates of element `i` in `shape`.
fn coords(mut i: u64, shape: &[u64]) -> Vec<u64> {
    let mut out = vec![0u64; shape.len()];
    for (slot, &d) in out.iter_mut().zip(shape).rev() {
        let d = d.max(1);
        *slot = i.checked_rem(d).unwrap_or(0);
        i = i.checked_div(d).unwrap_or(0);
    }
    out
}

fn element_name(slab: &Slab, i: u64) -> String {
    let mut c = coords(i, &slab.shape);
    if let Some(r) = slab.record {
        c.insert(0, r);
    }
    let parts: Vec<String> = c.iter().map(u64::to_string).collect();
    format!("[{}]", parts.join(", "))
}

/// The elements of a slab: one node per value; char data as one string
/// per row of the last dimension.
async fn values(cx: Cx, slab: Slab) -> Result<()> {
    let size = type_size(slab.kind);
    let total = slab.shape.iter().fold(1u64, |a, &d| a.saturating_mul(d));
    if slab.kind == 2 {
        let row = slab.shape.last().copied().unwrap_or(1).max(1);
        let rows = total.checked_div(row).unwrap_or(0);
        let mut slab = slab;
        let shape: Vec<u64> = slab
            .shape
            .iter()
            .take(slab.shape.len().saturating_sub(1))
            .copied()
            .collect();
        slab.shape = Arc::new(shape);
        for i in cx.resume::<u64>().unwrap_or(0)..rows {
            let span = slab.span.sub(i.saturating_mul(row), row);
            let data = cx.read_avail(span).await?;
            cx.mark(move || i);
            cx.push(
                Node::new(element_name(&slab, i))
                    .span(span)
                    .value(Value::Text(
                        String::from_utf8_lossy(&data)
                            .trim_end_matches('\0')
                            .to_owned(),
                    )),
            )
            .await;
        }
        return Ok(());
    }
    let n = total.min(slab.span.len.checked_div(size).unwrap_or(0));
    cx.set_count(Count::Exact(n));
    let mut i = cx.resume::<u64>().unwrap_or(0);
    let per = WINDOW.checked_div(size).unwrap_or(1).max(1);
    while i < n {
        let w = per.min(n.saturating_sub(i));
        let span = slab
            .span
            .sub(i.saturating_mul(size), w.saturating_mul(size));
        let data = cx.read(span).await?;
        for (j, c) in data.chunks_exact(to_usize(size)).enumerate() {
            let index = i.saturating_add(to_u64(j));
            cx.mark(move || index);
            cx.push(
                Node::new(element_name(&slab, index))
                    .span(span.sub(to_u64(j).saturating_mul(size), size))
                    .value(number(slab.kind, c)),
            )
            .await;
        }
        i = i.saturating_add(w);
    }
    Ok(())
}

/// The data section: fixed-size variables in file order, then the records.
async fn data(cx: Cx, header: Arc<Header>) -> Result<()> {
    let file = header.input.span;
    let mut fixed: Vec<&Var> = header
        .vars
        .iter()
        .filter(|v| !header.is_record(v))
        .collect();
    fixed.sort_by_key(|v| v.begin);
    for v in fixed {
        cx.push(data_node(&header, v)).await;
        let slab = header.slab(v);
        let pad = file.sub(v.begin.saturating_add(slab), pad4(slab));
        if pad.len > 0 {
            cx.push(Node::new("Padding").span(pad)).await;
        }
    }
    if header.recsize > 0 && header.numrecs > 0 {
        let span = file.sub(
            header.recstart,
            header.recsize.saturating_mul(header.numrecs),
        );
        cx.push(
            Node::new("Records")
                .span(span)
                .summary(format!(
                    "{} records of {}",
                    header.numrecs,
                    crate::formats::util::datakit::size(header.recsize)
                ))
                .lazy(records, header.clone()),
        )
        .await;
    }
    Ok(())
}

async fn records(cx: Cx, header: Arc<Header>) -> Result<()> {
    let file = header.input.span;
    let mut vars: Vec<&Var> = header.vars.iter().filter(|v| header.is_record(v)).collect();
    vars.sort_by_key(|v| v.begin);
    let vars: Arc<Vec<Var>> = Arc::new(vars.into_iter().cloned().collect());
    cx.set_count(Count::Exact(header.numrecs));
    for r in cx.resume::<u64>().unwrap_or(0)..header.numrecs {
        let at = header
            .recstart
            .saturating_add(r.saturating_mul(header.recsize));
        if at >= file.len {
            break;
        }
        cx.mark(move || r);
        cx.push(
            Node::new(format!("Record {r}"))
                .span(file.sub(at, header.recsize))
                .lazy(record, (header.clone(), vars.clone(), r)),
        )
        .await;
    }
    Ok(())
}

async fn record(cx: Cx, (header, vars, r): (Arc<Header>, Arc<Vec<Var>>, u64)) -> Result<()> {
    let file = header.input.span;
    let single = vars.len() == 1;
    for v in vars.iter() {
        let slab = header.slab(v);
        let at = v.begin.saturating_add(r.saturating_mul(header.recsize));
        let span = file.sub(at, slab);
        cx.emit(
            Node::new(v.name.clone())
                .span(span)
                .summary(signature(&header, v))
                .lazy(
                    values,
                    Slab {
                        span,
                        kind: v.kind,
                        shape: Arc::new(header.shape(v)),
                        record: Some(r),
                    },
                ),
        );
        if !single && pad4(slab) > 0 {
            let pad = file.sub(at.saturating_add(slab), pad4(slab));
            let bytes = cx.read_avail(pad).await?;
            cx.emit(
                Node::new("Padding")
                    .span(pad)
                    .value(Value::Bytes(bytes))
                    .summary("fill bytes"),
            );
        }
    }
    Ok(())
}
