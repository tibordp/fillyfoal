//! Apache ORC: `ORC`, stripes, then the footer and postscript (Protocol
//! Buffers), with the postscript's length in the last byte.
//!
//! The footer and stripe footers may be compressed in chunks; ZLIB, Snappy,
//! LZ4 and ZSTD chunks are decompressed one by one and joined as a piecewise
//! source (LZO is unsupported).

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::{EnumTable, Radix, Value, lookup};

/// Nested messages followed.
const MAX_DEPTH: u32 = 32;
/// Largest footer or stripe footer read.
const MAX_SECTION: u64 = 64 << 20;
/// Compression chunks per section.
const MAX_CHUNKS: usize = 1 << 16;

pub static FORMAT: Format = Format {
    name: "orc",
    title: "Apache ORC",
    extensions: &["orc"],
    mime: "application/vnd.apache.orc",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"ORC") && h.len > 4 && h.tail.len() >= 4 && {
        let ps_len = usize::from(h.tail.last().copied().unwrap_or(0));
        // The postscript ends with field 8000 = "ORC".
        h.tail.len() > ps_len
            && h.tail
                .get(h.tail.len().saturating_sub(4)..h.tail.len().saturating_sub(1))
                == Some(b"ORC")
    }
}

// ---------------------------------------------------------------------------
// Protocol Buffers

#[derive(Clone, Copy)]
pub enum Kind {
    Plain,
    Enum(EnumTable),
    Message(&'static MessageDef),
    /// A packed repeated varint field.
    Packed,
    /// A zigzag-encoded signed varint (`sint64`).
    Signed,
    Text,
}

pub struct FieldDef {
    id: u64,
    name: &'static str,
    kind: Kind,
}

pub struct MessageDef {
    name: &'static str,
    fields: &'static [FieldDef],
}

const fn f(id: u64, name: &'static str, kind: Kind) -> FieldDef {
    FieldDef { id, name, kind }
}

const P: Kind = Kind::Plain;
const T: Kind = Kind::Text;

fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let (v, n) = crate::bytes::uleb128(data.get(at..)?)?;
    Some((v, at.checked_add(n)?))
}

/// One field: id, wire type, where its value starts and ends.
fn field(data: &[u8], at: usize) -> Option<(u64, u8, usize, usize)> {
    let (key, start) = varint(data, at)?;
    let wire = (key & 7) as u8;
    let end = match wire {
        0 => varint(data, start)?.1,
        1 => start.checked_add(8)?,
        2 => {
            let (len, s) = varint(data, start)?;
            s.checked_add(to_usize(len))?
        }
        5 => start.checked_add(4)?,
        _ => return None,
    };
    (end <= data.len()).then_some((key >> 3, wire, start, end))
}

#[derive(Clone)]
struct Buf {
    data: Arc<Vec<u8>>,
    span: Span,
}

impl Buf {
    fn sub(&self, start: usize, end: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(end.saturating_sub(start)))
    }
}

#[derive(Clone)]
struct MsgState {
    buf: Buf,
    start: usize,
    end: usize,
    def: &'static MessageDef,
    depth: u32,
}

async fn message(cx: Cx, state: MsgState) -> Result<()> {
    let data = state.buf.data.clone();
    let body = data.get(..state.end).unwrap_or_default();
    let mut pos = state.start;
    while pos < state.end {
        cx.checkpoint().await;
        let Some((id, wire, start, end)) = field(body, pos) else {
            return Err(Diagnostic::malformed("invalid field").at(state.buf.sub(pos, state.end)));
        };
        let def = state.def.fields.iter().find(|d| d.id == id);
        let name = def.map_or_else(|| format!("Field {id}"), |d| d.name.to_owned());
        let kind = def.map_or(Kind::Plain, |d| d.kind);
        let mut node = Node::new(name).span(state.buf.sub(pos, end));
        node = match (wire, kind) {
            (0, Kind::Enum(table)) => {
                let v = varint(body, start).map_or(0, |(v, _)| v);
                node.value(Value::Enum {
                    raw: v,
                    bits: 32,
                    name: lookup(table, v),
                })
            }
            (0, Kind::Signed) => {
                let v = varint(body, start).map_or(0, |(v, _)| v);
                node.value(Value::Int {
                    value: ((v >> 1) as i64) ^ 0i64.wrapping_sub((v & 1) as i64),
                    bits: 64,
                })
            }
            (0, _) => node.value(Value::UInt {
                value: varint(body, start).map_or(0, |(v, _)| v),
                bits: 64,
                radix: Radix::Dec,
            }),
            (1, _) => node.value(Value::UInt {
                value: crate::bytes::u64_le(body, start).unwrap_or(0),
                bits: 64,
                radix: Radix::Hex,
            }),
            (5, _) => node.value(Value::UInt {
                value: crate::bytes::u32_le(body, start).unwrap_or(0).into(),
                bits: 32,
                radix: Radix::Hex,
            }),
            (_, Kind::Message(def)) => {
                let (_, s) = varint(body, start).unwrap_or((0, start));
                if state.depth >= MAX_DEPTH {
                    node.diag(Diagnostic::limit("messages nested too deeply"))
                } else {
                    let node = if node.name == def.name {
                        node
                    } else {
                        node.summary(def.name)
                    };
                    node.lazy(
                        crate::expander!(self::message: MsgState),
                        MsgState {
                            buf: state.buf.clone(),
                            start: s,
                            end,
                            def,
                            depth: state.depth.saturating_add(1),
                        },
                    )
                }
            }
            (_, Kind::Packed) => {
                let (_, mut s) = varint(body, start).unwrap_or((0, start));
                let mut values = Vec::new();
                while s < end && values.len() < 64 {
                    let Some((v, n)) = varint(body, s) else {
                        break;
                    };
                    values.push(v.to_string());
                    s = n;
                }
                node.value(Value::Text(values.join(", ")))
            }
            _ => {
                let (_, s) = varint(body, start).unwrap_or((0, start));
                let bytes = body.get(s..end).unwrap_or_default();
                match (kind, std::str::from_utf8(bytes)) {
                    (Kind::Text, Ok(text)) => node.value(Value::Text(text.to_owned())),
                    _ => node
                        .value(Value::Bytes(bytes.iter().take(32).copied().collect()))
                        .summary(format!("{} bytes", bytes.len())),
                }
            }
        };
        cx.push(node).await;
        pos = end;
    }
    Ok(())
}

/// Varint fields of a message, for the dissector's own use.
fn ints(data: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some((id, wire, start, end)) = field(data, pos) {
        if wire == 0
            && let Some((v, _)) = varint(data, start)
        {
            out.push((id, v));
        }
        pos = end;
    }
    out
}

/// Embedded messages with field number `id`: their (start, end).
fn messages(data: &[u8], id: u64) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    while let Some((fid, wire, start, end)) = field(data, pos) {
        if fid == id
            && wire == 2
            && let Some((_, s)) = varint(data, start)
        {
            out.push((s, end));
        }
        pos = end;
    }
    out
}

// ---------------------------------------------------------------------------
// ORC messages

const COMPRESSION: EnumTable = &[
    (0, "NONE"),
    (1, "ZLIB"),
    (2, "SNAPPY"),
    (3, "LZO"),
    (4, "LZ4"),
    (5, "ZSTD"),
];
const TYPE_KINDS: EnumTable = &[
    (0, "BOOLEAN"),
    (1, "BYTE"),
    (2, "SHORT"),
    (3, "INT"),
    (4, "LONG"),
    (5, "FLOAT"),
    (6, "DOUBLE"),
    (7, "STRING"),
    (8, "BINARY"),
    (9, "TIMESTAMP"),
    (10, "LIST"),
    (11, "MAP"),
    (12, "STRUCT"),
    (13, "UNION"),
    (14, "DECIMAL"),
    (15, "DATE"),
    (16, "VARCHAR"),
    (17, "CHAR"),
    (18, "TIMESTAMP_INSTANT"),
];
const STREAM_KINDS: EnumTable = &[
    (0, "PRESENT"),
    (1, "DATA"),
    (2, "LENGTH"),
    (3, "DICTIONARY_DATA"),
    (4, "DICTIONARY_COUNT"),
    (5, "SECONDARY"),
    (6, "ROW_INDEX"),
    (7, "BLOOM_FILTER"),
    (8, "BLOOM_FILTER_UTF8"),
    (10, "ENCRYPTED_INDEX"),
    (11, "ENCRYPTED_DATA"),
];
const ENCODINGS: EnumTable = &[
    (0, "DIRECT"),
    (1, "DICTIONARY"),
    (2, "DIRECT_V2"),
    (3, "DICTIONARY_V2"),
];

static POSTSCRIPT: MessageDef = MessageDef {
    name: "PostScript",
    fields: &[
        f(1, "footerLength", P),
        f(2, "compression", Kind::Enum(COMPRESSION)),
        f(3, "compressionBlockSize", P),
        f(4, "version", Kind::Packed),
        f(5, "metadataLength", P),
        f(6, "writerVersion", P),
        f(7, "stripeStatisticsLength", P),
        f(8000, "magic", T),
    ],
};

static STRIPE_INFORMATION: MessageDef = MessageDef {
    name: "StripeInformation",
    fields: &[
        f(1, "offset", P),
        f(2, "indexLength", P),
        f(3, "dataLength", P),
        f(4, "footerLength", P),
        f(5, "numberOfRows", P),
    ],
};

static TYPE: MessageDef = MessageDef {
    name: "Type",
    fields: &[
        f(1, "kind", Kind::Enum(TYPE_KINDS)),
        f(2, "subtypes", Kind::Packed),
        f(3, "fieldNames", T),
        f(4, "maximumLength", P),
        f(5, "precision", P),
        f(6, "scale", P),
    ],
};

static USER_METADATA: MessageDef = MessageDef {
    name: "UserMetadataItem",
    fields: &[f(1, "name", T), f(2, "value", P)],
};

static INTEGER_STATISTICS: MessageDef = MessageDef {
    name: "IntegerStatistics",
    fields: &[
        f(1, "minimum", Kind::Signed),
        f(2, "maximum", Kind::Signed),
        f(3, "sum", Kind::Signed),
    ],
};

static STRING_STATISTICS: MessageDef = MessageDef {
    name: "StringStatistics",
    fields: &[f(1, "minimum", T), f(2, "maximum", T), f(3, "sum", P)],
};

static COLUMN_STATISTICS: MessageDef = MessageDef {
    name: "ColumnStatistics",
    fields: &[
        f(1, "numberOfValues", P),
        f(2, "intStatistics", Kind::Message(&INTEGER_STATISTICS)),
        f(3, "doubleStatistics", P),
        f(4, "stringStatistics", Kind::Message(&STRING_STATISTICS)),
        f(5, "bucketStatistics", P),
        f(6, "decimalStatistics", P),
        f(7, "dateStatistics", P),
        f(8, "binaryStatistics", P),
        f(9, "timestampStatistics", P),
        f(10, "hasNull", P),
        f(11, "bytesOnDisk", P),
    ],
};

static FOOTER: MessageDef = MessageDef {
    name: "Footer",
    fields: &[
        f(1, "headerLength", P),
        f(2, "contentLength", P),
        f(3, "stripes", Kind::Message(&STRIPE_INFORMATION)),
        f(4, "types", Kind::Message(&TYPE)),
        f(5, "metadata", Kind::Message(&USER_METADATA)),
        f(6, "numberOfRows", P),
        f(7, "statistics", Kind::Message(&COLUMN_STATISTICS)),
        f(8, "rowIndexStride", P),
        f(9, "writer", P),
        f(10, "encryption", P),
        f(11, "calendar", P),
        f(12, "softwareVersion", T),
    ],
};

static STREAM: MessageDef = MessageDef {
    name: "Stream",
    fields: &[
        f(1, "kind", Kind::Enum(STREAM_KINDS)),
        f(2, "column", P),
        f(3, "length", P),
    ],
};

static COLUMN_ENCODING: MessageDef = MessageDef {
    name: "ColumnEncoding",
    fields: &[
        f(1, "kind", Kind::Enum(ENCODINGS)),
        f(2, "dictionarySize", P),
        f(3, "bloomEncoding", P),
    ],
};

static STRIPE_FOOTER: MessageDef = MessageDef {
    name: "StripeFooter",
    fields: &[
        f(1, "streams", Kind::Message(&STREAM)),
        f(2, "columns", Kind::Message(&COLUMN_ENCODING)),
        f(3, "writerTimezone", T),
        f(4, "encryption", P),
    ],
};

// ---------------------------------------------------------------------------
// Dissection

/// A section that may be compressed in chunks, as one span of plain bytes.
async fn section(cx: &Cx, span: Span, compression: u64) -> Result<Span> {
    if compression == 0 {
        return Ok(span);
    }
    // Each chunk is one raw stream: DEFLATE, Snappy, an LZ4 block or a
    // zstd frame.
    let codec = match compression {
        1 => crate::codec::Codec::Deflate,
        2 => crate::codec::Codec::Snappy,
        4 => crate::codec::Codec::Lz4Block,
        5 => crate::codec::Codec::Zstd,
        _ => {
            let name = lookup(COMPRESSION, compression).unwrap_or("unknown");
            return Err(Diagnostic::unsupported(format!("{name} compression")).at(span));
        }
    };
    let mut pieces = Vec::new();
    let mut pos = 0u64;
    while pos < span.len {
        cx.checkpoint().await;
        if pieces.len() >= MAX_CHUNKS {
            return Err(Diagnostic::limit("too many compression chunks").at(span));
        }
        let head = cx.read(span.sub(pos, 3)).await?;
        let header = u32::from_le_bytes([
            head.first().copied().unwrap_or(0),
            head.get(1).copied().unwrap_or(0),
            head.get(2).copied().unwrap_or(0),
            0,
        ]);
        let len = u64::from(header >> 1);
        let chunk = span.sub(pos.saturating_add(3), len);
        if header & 1 != 0 {
            pieces.push(chunk);
        } else {
            let decoded = crate::codec::decode_span(cx, chunk, &codec, None).await?;
            pieces.push(decoded.span);
        }
        pos = pos.saturating_add(3).saturating_add(len);
    }
    cx.add_pieces(
        Origin {
            parent: span,
            transform: "orc-chunks",
        },
        pieces,
    )
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 3))
            .value(Value::Text("ORC".to_owned())),
    );
    let last = cx.read(file.sub(file.len.saturating_sub(1), 1)).await?;
    let ps_len = u64::from(last.first().copied().unwrap_or(0));
    let ps_start = file
        .len
        .saturating_sub(1)
        .checked_sub(ps_len)
        .ok_or_else(|| {
            Diagnostic::malformed("postscript length does not fit")
                .at(file.sub(file.len.saturating_sub(1), 1))
        })?;
    let ps_span = file.sub(ps_start, ps_len);
    let ps = Arc::new(cx.read(ps_span).await?);
    let ps_ints = ints(&ps);
    let get =
        |fields: &[(u64, u64)], id: u64| fields.iter().find(|(f, _)| *f == id).map(|(_, v)| *v);
    let footer_len = get(&ps_ints, 1).unwrap_or(0);
    let compression = get(&ps_ints, 2).unwrap_or(0);
    let metadata_len = get(&ps_ints, 5).unwrap_or(0);
    let footer_start = ps_start
        .checked_sub(footer_len)
        .ok_or_else(|| Diagnostic::malformed("footer length does not fit").at(ps_span))?;
    let footer_raw = file.sub(footer_start, footer_len);
    if metadata_len > 0 {
        let start = footer_start.saturating_sub(metadata_len);
        cx.emit(
            Node::new("Metadata")
                .span(file.sub(start, metadata_len))
                .summary("stripe statistics"),
        );
    }
    let mut summary = format!(
        "ORC, {} compression",
        lookup(COMPRESSION, compression).unwrap_or("unknown")
    );
    let footer = match section(&cx, footer_raw, compression).await {
        Ok(span) if span.len <= MAX_SECTION => Some((span, Arc::new(cx.read(span).await?))),
        Ok(span) => {
            cx.diag(Diagnostic::limit("footer too large").at(span));
            None
        }
        Err(e) => {
            cx.diag(e);
            None
        }
    };
    if let Some((span, data)) = &footer {
        let fi = ints(data);
        if let Some(rows) = get(&fi, 6) {
            summary = format!("{summary}, {rows} rows");
        }
        summary = format!(
            "{summary}, {} stripes, {} types",
            messages(data, 3).len(),
            messages(data, 4).len()
        );
        cx.emit(
            Node::new("Stripes")
                .summary(format!("{}", messages(data, 3).len()))
                .lazy(
                    stripes,
                    (
                        input,
                        Buf {
                            data: data.clone(),
                            span: *span,
                        },
                        compression,
                    ),
                ),
        );
        let state = MsgState {
            buf: Buf {
                data: data.clone(),
                span: *span,
            },
            start: 0,
            end: data.len(),
            def: &FOOTER,
            depth: 0,
        };
        cx.emit(Node::new("Footer").span(footer_raw).lazy(message, state));
    }
    cx.annotate(summary);
    cx.emit(Node::new("PostScript").span(ps_span).lazy(
        message,
        MsgState {
            buf: Buf {
                data: ps.clone(),
                span: ps_span,
            },
            start: 0,
            end: ps.len(),
            def: &POSTSCRIPT,
            depth: 0,
        },
    ));
    cx.emit(
        Node::new("PostScript length")
            .span(file.sub(file.len.saturating_sub(1), 1))
            .value(Value::UInt {
                value: ps_len,
                bits: 8,
                radix: Radix::Dec,
            }),
    );
    Ok(())
}

async fn stripes(cx: Cx, (input, footer, compression): (Input, Buf, u64)) -> Result<()> {
    let list = messages(&footer.data, 3);
    cx.set_count(Count::Exact(to_u64(list.len())));
    for (i, (s, e)) in list.into_iter().enumerate() {
        let info = ints(footer.data.get(s..e).unwrap_or_default());
        let get = |id: u64| info.iter().find(|(f, _)| *f == id).map_or(0, |(_, v)| *v);
        let (offset, index, data, foot, rows) = (get(1), get(2), get(3), get(4), get(5));
        let whole = input
            .span
            .sub(offset, index.saturating_add(data).saturating_add(foot));
        cx.push(
            Node::new(format!("Stripe {i}"))
                .span(whole)
                .summary(format!("{rows} rows"))
                .lazy(stripe, (whole, index, data, foot, compression)),
        )
        .await;
    }
    Ok(())
}

async fn stripe(
    cx: Cx,
    (whole, index, data, foot, compression): (Span, u64, u64, u64, u64),
) -> Result<()> {
    if index > 0 {
        cx.emit(Node::new("Index streams").span(whole.sub(0, index)));
    }
    cx.emit(Node::new("Data streams").span(whole.sub(index, data)));
    let footer_raw = whole.sub(index.saturating_add(data), foot);
    let span = section(&cx, footer_raw, compression).await?;
    if span.len > MAX_SECTION {
        return Err(Diagnostic::limit("stripe footer too large").at(span));
    }
    let bytes = Arc::new(cx.read(span).await?);
    // Streams are laid out in order after the stripe's start.
    let mut pos = 0u64;
    let mut stream_nodes = Vec::new();
    for (s, e) in messages(&bytes, 1) {
        let fields = ints(bytes.get(s..e).unwrap_or_default());
        let get = |id: u64| fields.iter().find(|(f, _)| *f == id).map_or(0, |(_, v)| *v);
        let (kind, column, len) = (get(1), get(2), get(3));
        stream_nodes.push(
            Node::new(format!(
                "{} (column {column})",
                lookup(STREAM_KINDS, kind).unwrap_or("stream")
            ))
            .span(whole.sub(pos, len))
            .summary(format!("{len} bytes")),
        );
        pos = pos.saturating_add(len);
    }
    let state = MsgState {
        buf: Buf {
            data: bytes.clone(),
            span,
        },
        start: 0,
        end: bytes.len(),
        def: &STRIPE_FOOTER,
        depth: 0,
    };
    cx.emit(
        Node::new("Stripe footer")
            .span(footer_raw)
            .lazy(message, state),
    );
    for node in stream_nodes {
        cx.push(node).await;
    }
    Ok(())
}
