//! Apache ORC: `ORC`, stripes, then the footer and postscript (Protocol
//! Buffers), with the postscript's length in the last byte.
//!
//! The footer and stripe footers may be compressed in chunks; ZLIB, Snappy,
//! LZ4 and ZSTD chunks are decompressed one by one and joined as a piecewise
//! source (LZO is unsupported).

use std::sync::Arc;

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::wire::protobuf as pb;
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
// Protocol Buffers (schema-driven, over `util::wire::protobuf`)

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
    /// A `double` (fixed 64-bit).
    Double,
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
        let mut next = pos;
        let Some(fd) = pb::field(body, &mut next) else {
            return Err(Diagnostic::malformed("invalid field").at(state.buf.sub(pos, state.end)));
        };
        let (id, wire, end) = (fd.number, fd.wire, fd.end);
        let def = state.def.fields.iter().find(|d| d.id == id);
        let name = def.map_or_else(|| format!("Field {id}"), |d| d.name.to_owned());
        let kind = def.map_or(Kind::Plain, |d| d.kind);
        let mut node = Node::new(name).span(state.buf.sub(pos, end));
        node = match (wire, kind) {
            (0, Kind::Enum(table)) => node.value(Value::Enum {
                raw: fd.value,
                bits: 32,
                name: lookup(table, fd.value),
            }),
            (0, Kind::Signed) => node.value(Value::Int {
                value: pb::zigzag(fd.value),
                bits: 64,
            }),
            (0, _) => node.value(Value::UInt {
                value: fd.value,
                bits: 64,
                radix: Radix::Dec,
            }),
            (1, Kind::Double) => node.value(Value::Float(f64::from_bits(fd.value))),
            (1, _) => node.value(Value::UInt {
                value: fd.value,
                bits: 64,
                radix: Radix::Hex,
            }),
            (5, _) => node.value(Value::UInt {
                value: fd.value,
                bits: 32,
                radix: Radix::Hex,
            }),
            (_, Kind::Message(def)) => {
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
                            start: fd.body,
                            end,
                            def,
                            depth: state.depth.saturating_add(1),
                        },
                    )
                }
            }
            (_, Kind::Packed) => {
                let packed = fd.payload(body);
                let mut s = 0usize;
                let mut values = Vec::new();
                while s < packed.len() && values.len() < 64 {
                    let Some(v) = pb::varint(packed, &mut s) else {
                        break;
                    };
                    values.push(v.to_string());
                }
                node.value(Value::Text(values.join(", ")))
            }
            _ => {
                let bytes = fd.payload(body);
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
    pb::fields_in(data)
        .filter(|f| f.wire == pb::VARINT)
        .map(|f| (f.number, f.value))
        .collect()
}

/// [`ints`] for a footer, which may be large: a checkpoint every few
/// thousand fields.
async fn ints_stepped(cx: &Cx, data: &[u8]) -> Vec<(u64, u64)> {
    let mut out = Vec::new();
    for (i, f) in pb::fields_in(data).enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if f.wire == pb::VARINT {
            out.push((f.number, f.value));
        }
    }
    out
}

/// Embedded messages with field number `id`: their (start, end), with a
/// checkpoint every few thousand fields.
async fn messages_stepped(cx: &Cx, data: &[u8], id: u64) -> Vec<(usize, usize)> {
    let mut out = Vec::new();
    for (i, f) in pb::fields_in(data).enumerate() {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        if f.number == id && f.wire == pb::LEN {
            out.push((f.body, f.end));
        }
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
        f(7, "attributes", Kind::Message(&STRING_PAIR)),
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

static DOUBLE_STATISTICS: MessageDef = MessageDef {
    name: "DoubleStatistics",
    fields: &[
        f(1, "minimum", Kind::Double),
        f(2, "maximum", Kind::Double),
        f(3, "sum", Kind::Double),
    ],
};

static BUCKET_STATISTICS: MessageDef = MessageDef {
    name: "BucketStatistics",
    fields: &[f(1, "count", Kind::Packed)],
};

static DECIMAL_STATISTICS: MessageDef = MessageDef {
    name: "DecimalStatistics",
    fields: &[f(1, "minimum", T), f(2, "maximum", T), f(3, "sum", T)],
};

static DATE_STATISTICS: MessageDef = MessageDef {
    name: "DateStatistics",
    fields: &[f(1, "minimum", Kind::Signed), f(2, "maximum", Kind::Signed)],
};

static BINARY_STATISTICS: MessageDef = MessageDef {
    name: "BinaryStatistics",
    fields: &[f(1, "sum", Kind::Signed)],
};

static TIMESTAMP_STATISTICS: MessageDef = MessageDef {
    name: "TimestampStatistics",
    fields: &[
        f(1, "minimum", Kind::Signed),
        f(2, "maximum", Kind::Signed),
        f(3, "minimumUtc", Kind::Signed),
        f(4, "maximumUtc", Kind::Signed),
        f(5, "minimumNanos", P),
        f(6, "maximumNanos", P),
    ],
};

static COLLECTION_STATISTICS: MessageDef = MessageDef {
    name: "CollectionStatistics",
    fields: &[
        f(1, "minChildren", P),
        f(2, "maxChildren", P),
        f(3, "totalChildren", P),
    ],
};

static COLUMN_STATISTICS: MessageDef = MessageDef {
    name: "ColumnStatistics",
    fields: &[
        f(1, "numberOfValues", P),
        f(2, "intStatistics", Kind::Message(&INTEGER_STATISTICS)),
        f(3, "doubleStatistics", Kind::Message(&DOUBLE_STATISTICS)),
        f(4, "stringStatistics", Kind::Message(&STRING_STATISTICS)),
        f(5, "bucketStatistics", Kind::Message(&BUCKET_STATISTICS)),
        f(6, "decimalStatistics", Kind::Message(&DECIMAL_STATISTICS)),
        f(7, "dateStatistics", Kind::Message(&DATE_STATISTICS)),
        f(8, "binaryStatistics", Kind::Message(&BINARY_STATISTICS)),
        f(
            9,
            "timestampStatistics",
            Kind::Message(&TIMESTAMP_STATISTICS),
        ),
        f(10, "hasNull", P),
        f(11, "bytesOnDisk", P),
        f(
            12,
            "collectionStatistics",
            Kind::Message(&COLLECTION_STATISTICS),
        ),
    ],
};

static STRIPE_STATISTICS: MessageDef = MessageDef {
    name: "StripeStatistics",
    fields: &[f(1, "colStats", Kind::Message(&COLUMN_STATISTICS))],
};

static METADATA: MessageDef = MessageDef {
    name: "Metadata",
    fields: &[f(1, "stripeStats", Kind::Message(&STRIPE_STATISTICS))],
};

static ROW_INDEX_ENTRY: MessageDef = MessageDef {
    name: "RowIndexEntry",
    fields: &[
        f(1, "positions", Kind::Packed),
        f(2, "statistics", Kind::Message(&COLUMN_STATISTICS)),
    ],
};

static ROW_INDEX: MessageDef = MessageDef {
    name: "RowIndex",
    fields: &[f(1, "entry", Kind::Message(&ROW_INDEX_ENTRY))],
};

static BLOOM_FILTER: MessageDef = MessageDef {
    name: "BloomFilter",
    fields: &[
        f(1, "numHashFunctions", P),
        f(2, "bitset", P),
        f(3, "utf8bitset", P),
    ],
};

static BLOOM_FILTER_INDEX: MessageDef = MessageDef {
    name: "BloomFilterIndex",
    fields: &[f(1, "bloomFilter", Kind::Message(&BLOOM_FILTER))],
};

static STRING_PAIR: MessageDef = MessageDef {
    name: "StringPair",
    fields: &[f(1, "key", T), f(2, "value", T)],
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
    cx.add_pieces_stepped(
        Origin {
            parent: span,
            transform: "orc-chunks",
        },
        &pieces,
    )
    .await
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
                .summary("stripe statistics")
                .lazy(
                    section_message,
                    (file.sub(start, metadata_len), compression, &METADATA),
                ),
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
        let fi = ints_stepped(&cx, data).await;
        if let Some(rows) = get(&fi, 6) {
            summary = format!("{summary}, {rows} rows");
        }
        let stripe_count = messages_stepped(&cx, data, 3).await.len();
        summary = format!(
            "{summary}, {stripe_count} stripes, {} types",
            messages_stepped(&cx, data, 4).await.len()
        );
        cx.emit(
            Node::new("Stripes")
                .summary(format!("{stripe_count}"))
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
    let list = messages_stepped(&cx, &footer.data, 3).await;
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
    let footer_raw = whole.sub(index.saturating_add(data), foot);
    let span = section(&cx, footer_raw, compression).await?;
    if span.len > MAX_SECTION {
        return Err(Diagnostic::limit("stripe footer too large").at(span));
    }
    let bytes = Arc::new(cx.read(span).await?);
    // Streams are laid out in order after the stripe's start.
    let mut pos = 0u64;
    let mut stream_nodes = Vec::new();
    for (s, e) in messages_stepped(&cx, &bytes, 1).await {
        if stream_nodes.len().is_multiple_of(256) {
            cx.checkpoint().await;
        }
        let fields = ints(bytes.get(s..e).unwrap_or_default());
        let get = |id: u64| fields.iter().find(|(f, _)| *f == id).map_or(0, |(_, v)| *v);
        let (kind, column, len) = (get(1), get(2), get(3));
        let mut node = Node::new(format!(
            "{} (column {column})",
            lookup(STREAM_KINDS, kind).unwrap_or("stream")
        ))
        .span(whole.sub(pos, len))
        .summary(format!("{len} bytes"));
        if len > 0 {
            node = node.lazy(stream, (whole.sub(pos, len), compression, kind));
        }
        stream_nodes.push(node);
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

/// A protobuf message stored as a (possibly compressed) section.
async fn section_message(
    cx: Cx,
    (raw, compression, def): (Span, u64, &'static MessageDef),
) -> Result<()> {
    if compression != 0 {
        cx.emit(
            Node::new("Compression chunks")
                .span(raw)
                .lazy(chunks, (raw, compression)),
        );
    }
    let span = section(&cx, raw, compression).await?;
    if span.len > MAX_SECTION {
        return Err(Diagnostic::limit("section too large").at(span));
    }
    let data = Arc::new(cx.read(span).await?);
    let end = data.len();
    message(
        cx,
        MsgState {
            buf: Buf { data, span },
            start: 0,
            end,
            def,
            depth: 0,
        },
    )
    .await
}

/// The compression chunks of a section: 3-byte headers (length and an
/// "original" flag), then compressed or stored bytes.
async fn chunks(cx: Cx, (span, compression): (Span, u64)) -> Result<()> {
    let codec = match compression {
        1 => Some(crate::codec::Codec::Deflate),
        2 => Some(crate::codec::Codec::Snappy),
        4 => Some(crate::codec::Codec::Lz4Block),
        5 => Some(crate::codec::Codec::Zstd),
        _ => None,
    };
    let mut pos = 0u64;
    let mut i = 0usize;
    while pos < span.len && i < MAX_CHUNKS {
        let head = cx.read(span.sub(pos, 3)).await?;
        let header = u32::from_le_bytes([
            head.first().copied().unwrap_or(0),
            head.get(1).copied().unwrap_or(0),
            head.get(2).copied().unwrap_or(0),
            0,
        ]);
        let len = u64::from(header >> 1);
        let original = header & 1 != 0;
        cx.push(
            Node::new("Chunk header")
                .span(span.sub(pos, 3))
                .value(Value::UInt {
                    value: len,
                    bits: 23,
                    radix: Radix::Dec,
                })
                .summary(if original { "stored" } else { "compressed" }),
        )
        .await;
        let body = span.sub(pos.saturating_add(3), len);
        let mut node = Node::new(if original {
            "Stored chunk"
        } else {
            "Compressed chunk"
        })
        .span(body)
        .summary(format!("{len} bytes"));
        if body.len < len {
            cx.push(node.diag(Diagnostic::malformed(format!(
                "chunk of {len} bytes runs past the end of its section"
            ))))
            .await;
            break;
        }
        if original {
            let preview = cx.read_avail(body.sub(0, 32)).await?;
            node = node.value(Value::Bytes(preview));
        }
        if !original && let Some(codec) = codec.clone() {
            node = node.lazy(decoded_chunk, (body, codec));
        }
        cx.push(node).await;
        pos = pos.saturating_add(3).saturating_add(len);
        i = i.saturating_add(1);
    }
    Ok(())
}

async fn decoded_chunk(cx: Cx, (span, codec): (Span, crate::codec::Codec)) -> Result<()> {
    let decoded = crate::codec::decode_span(&cx, span, &codec, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    cx.emit(
        Node::new("Decompressed")
            .span(decoded.span)
            .summary(format!("{} bytes", decoded.span.len)),
    );
    Ok(())
}

/// A stream of a stripe: its compression chunks, then its contents
/// (index streams are protobuf messages; data streams run-length encoded
/// values).
async fn stream(cx: Cx, (raw, compression, kind): (Span, u64, u64)) -> Result<()> {
    let def = match kind {
        6 => Some(&ROW_INDEX),
        7 | 8 => Some(&BLOOM_FILTER_INDEX),
        _ => None,
    };
    if let Some(def) = def {
        return section_message(cx, (raw, compression, def)).await;
    }
    if compression != 0 {
        cx.emit(
            Node::new("Compression chunks")
                .span(raw)
                .lazy(chunks, (raw, compression)),
        );
    }
    let span = section(&cx, raw, compression).await?;
    let data = cx.read_avail(span.sub(0, 32)).await?;
    cx.emit(
        Node::new("Encoded values")
            .span(span)
            .value(Value::Bytes(data))
            .summary(format!(
                "{} bytes, {}",
                span.len,
                match kind {
                    0 => "present bits (boolean run-length)",
                    1 | 5 => "values (run-length encoded)",
                    2 => "lengths (integer run-length)",
                    3 => "dictionary bytes",
                    4 => "dictionary counts",
                    _ => "encoded",
                }
            )),
    );
    Ok(())
}
