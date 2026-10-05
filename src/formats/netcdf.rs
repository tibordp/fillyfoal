//! NetCDF classic files (CDF-1, the 64-bit offset CDF-2 and CDF-5): a
//! header of dimensions, global attributes and variables, then the data.

use std::sync::Arc;

use crate::bytes::to_u64;
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

pub static FORMAT: Format = Format {
    name: "netcdf",
    title: "NetCDF classic data",
    extensions: &["nc", "cdf", "nc3"],
    mime: "application/x-netcdf",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"CDF")
        && matches!(h.data.get(3), Some(1 | 2 | 5))
        && h.data
            .get(8..12)
            .is_some_and(|t| matches!(t, [0, 0, 0, 0 | 0x0a | 0x0c | 0x0b]))
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

fn type_size(t: u32) -> u64 {
    match t {
        1 | 2 | 7 => 1,
        3 | 8 => 2,
        4 | 5 | 9 => 4,
        _ => 8,
    }
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
    kind: u32,
    vsize: u64,
    begin: u64,
    span: Span,
}

struct Header {
    input: Input,
    dims: Vec<Dim>,
    attrs: Vec<Attr>,
    vars: Vec<Var>,
}

/// Reads the header as it is laid out (lengths are 8 bytes in CDF-5).
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
        let len = self.count().await?;
        let span = self.cur.span(len);
        if span.len < len || len > 1 << 16 {
            return Err(Diagnostic::malformed("invalid name length").at(self.cur.span(4)));
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

    async fn attrs(&mut self) -> Result<Vec<Attr>> {
        let n = self.list(0x0c).await?;
        let mut out = Vec::new();
        for _ in 0..n {
            let start = self.cur.pos();
            let name = self.name().await?;
            let kind = self.cur.u32().await?;
            let count = self.count().await?;
            let len = count.saturating_mul(type_size(kind));
            let values = self.cur.span(len);
            if values.len < len {
                return Err(Diagnostic::truncated(values, values.len));
            }
            self.cur.skip(len.saturating_add(pad4(len)));
            out.push(Attr {
                name,
                kind,
                count,
                values,
                span: self.cur.since(start),
            });
        }
        Ok(out)
    }
}

fn pad4(n: u64) -> u64 {
    n.wrapping_neg() & 3
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 4)).await?;
    let version = head.get(3).copied().unwrap_or(1);
    let wide = version == 5;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(Value::Enum {
        raw: version.into(),
        bits: 8,
        name: lookup(
            &[
                (1, "classic"),
                (2, "64-bit offset"),
                (5, "64-bit data (CDF-5)"),
            ],
            version.into(),
        ),
    }));
    let mut r = Reader {
        cur: Cursor::new(&cx, file, BE),
        wide,
    };
    r.cur.seek(4);
    let numrecs_span = r.cur.span(if wide { 8 } else { 4 });
    let numrecs = r.count().await?;
    cx.emit(Node::new("Number of records").span(numrecs_span).value(
        if numrecs == u64::from(u32::MAX) {
            Value::Text("streaming".to_owned())
        } else {
            Value::UInt {
                value: numrecs,
                bits: 64,
                radix: Radix::Dec,
            }
        },
    ));
    let n = r.list(0x0a).await?;
    let mut dims = Vec::new();
    for _ in 0..n {
        let start = r.cur.pos();
        let name = r.name().await?;
        let len = r.count().await?;
        dims.push(Dim {
            name,
            len,
            span: r.cur.since(start),
        });
    }
    let attrs = r.attrs().await?;
    let n = r.list(0x0b).await?;
    let mut vars = Vec::new();
    for _ in 0..n {
        cx.checkpoint().await;
        let start = r.cur.pos();
        let name = r.name().await?;
        let ndims = r.count().await?;
        if ndims > 1024 {
            return Err(Diagnostic::malformed("too many dimensions").at(r.cur.span(4)));
        }
        let mut ids = Vec::new();
        for _ in 0..ndims {
            ids.push(r.count().await?);
        }
        let vattrs = r.attrs().await?;
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
            kind,
            vsize,
            begin,
            span: r.cur.since(start),
        });
    }
    let header_end = r.cur.pos();
    let header = Arc::new(Header {
        input,
        dims,
        attrs,
        vars,
    });
    cx.annotate(format!(
        "NetCDF {}, {} dimensions, {} variables, {} global attributes",
        match version {
            1 => "classic",
            2 => "64-bit offset",
            _ => "CDF-5",
        },
        header.dims.len(),
        header.vars.len(),
        header.attrs.len()
    ));
    cx.emit(
        Node::new("Dimensions")
            .summary(format!("{}", header.dims.len()))
            .lazy(dimensions, header.clone()),
    );
    cx.emit(
        Node::new("Global attributes")
            .summary(format!("{}", header.attrs.len()))
            .lazy(global_attributes, header.clone()),
    );
    cx.emit(
        Node::new("Variables")
            .span(file.sub(0, header_end))
            .summary(format!("{}", header.vars.len()))
            .lazy(variables, header.clone()),
    );
    Ok(())
}

async fn dimensions(cx: Cx, header: Arc<Header>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(header.dims.len())));
    for d in &header.dims {
        let value = if d.len == 0 {
            Value::Text("unlimited".to_owned())
        } else {
            Value::UInt {
                value: d.len,
                bits: 64,
                radix: Radix::Dec,
            }
        };
        cx.push(Node::new(d.name.clone()).span(d.span).value(value))
            .await;
    }
    Ok(())
}

async fn attribute_nodes(cx: &Cx, attrs: &[Attr]) -> Result<()> {
    for a in attrs {
        let data = cx.read_avail(a.values.sub(0, 4096)).await?;
        let mut node = Node::new(a.name.clone()).span(a.span);
        let kind = lookup(TYPES, a.kind.into()).unwrap_or("unknown");
        node = match a.kind {
            2 => node.value(Value::Text(
                String::from_utf8_lossy(&data)
                    .trim_end_matches('\0')
                    .to_owned(),
            )),
            _ => {
                let size = crate::bytes::to_usize(type_size(a.kind));
                let shown: Vec<String> = data
                    .chunks_exact(size.max(1))
                    .take(16)
                    .map(|c| number(a.kind, c))
                    .collect();
                let more = if a.count > 16 { " …" } else { "" };
                node.value(Value::Text(format!("{}{more}", shown.join(", "))))
            }
        };
        cx.push(node.summary(format!("{kind}[{}]", a.count))).await;
    }
    Ok(())
}

fn number(kind: u32, c: &[u8]) -> String {
    let arr = |n: usize| c.get(..n).unwrap_or_default();
    match kind {
        1 => c
            .first()
            .map(|&b| (b as i8).to_string())
            .unwrap_or_default(),
        7 => c.first().map(u8::to_string).unwrap_or_default(),
        3 => arr(2)
            .try_into()
            .map(|b| i16::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        8 => arr(2)
            .try_into()
            .map(|b| u16::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        4 => arr(4)
            .try_into()
            .map(|b| i32::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        9 => arr(4)
            .try_into()
            .map(|b| u32::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        5 => arr(4)
            .try_into()
            .map(|b| f32::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        6 => arr(8)
            .try_into()
            .map(|b| f64::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        10 => arr(8)
            .try_into()
            .map(|b| i64::from_be_bytes(b).to_string())
            .unwrap_or_default(),
        _ => arr(8)
            .try_into()
            .map(|b| u64::from_be_bytes(b).to_string())
            .unwrap_or_default(),
    }
}

async fn global_attributes(cx: Cx, header: Arc<Header>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(header.attrs.len())));
    attribute_nodes(&cx, &header.attrs).await
}

fn shape(header: &Header, var: &Var) -> String {
    let names: Vec<String> = var
        .dims
        .iter()
        .map(|&id| {
            header
                .dims
                .get(crate::bytes::to_usize(id))
                .map_or_else(|| format!("#{id}"), |d| d.name.clone())
        })
        .collect();
    format!(
        "{} {}({})",
        lookup(TYPES, var.kind.into()).unwrap_or("unknown"),
        var.name,
        names.join(", ")
    )
}

async fn variables(cx: Cx, header: Arc<Header>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(header.vars.len())));
    for (i, v) in header.vars.iter().enumerate() {
        cx.push(
            Node::new(v.name.clone())
                .span(v.span)
                .summary(shape(&header, v))
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
    let record = v
        .dims
        .first()
        .and_then(|&id| header.dims.get(crate::bytes::to_usize(id)))
        .is_some_and(|d| d.len == 0);
    for (i, &id) in v.dims.iter().enumerate() {
        let d = header.dims.get(crate::bytes::to_usize(id));
        let mut node = Node::new(format!("Dimension {i}")).value(Value::Text(
            d.map_or_else(|| format!("#{id}"), |d| d.name.clone()),
        ));
        if d.is_none() {
            node = node.diag(Diagnostic::malformed(format!(
                "dimension {id} does not exist"
            )));
        }
        cx.emit(node);
    }
    if !v.attrs.is_empty() {
        cx.emit(
            Node::new("Attributes")
                .summary(format!("{}", v.attrs.len()))
                .lazy(var_attributes, (header.clone(), index)),
        );
    }
    cx.emit(Node::new("Type").value(Value::Enum {
        raw: v.kind.into(),
        bits: 32,
        name: lookup(TYPES, v.kind.into()),
    }));
    cx.emit(
        Node::new("Size")
            .value(Value::UInt {
                value: v.vsize,
                bits: 64,
                radix: Radix::Dec,
            })
            .summary(if record { "per record" } else { "bytes" }),
    );
    let data = header.input.span.sub(v.begin, v.vsize);
    let mut node = Node::new("Data").span(data).value(Value::UInt {
        value: v.begin,
        bits: 64,
        radix: Radix::Hex,
    });
    if record {
        node = node.summary("first record; records are interleaved");
    }
    if data.len < v.vsize {
        node = node.diag(Diagnostic::truncated(
            Span::new(data.source, data.offset, v.vsize),
            data.len,
        ));
    }
    cx.emit(node);
    Ok(())
}

async fn var_attributes(cx: Cx, (header, index): (Arc<Header>, usize)) -> Result<()> {
    if let Some(v) = header.vars.get(index) {
        attribute_nodes(&cx, &v.attrs).await?;
    }
    Ok(())
}
