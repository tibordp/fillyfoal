//! Apache Parquet: `PAR1`, column chunks, then the file metadata (Thrift
//! compact protocol), its length and `PAR1` again.
//!
//! The metadata is decoded lazily with a small schema of the Thrift
//! structures; column chunks list their pages (page headers are Thrift
//! too) on demand.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::wire::thrift::compact::{
    field_header, list_header, skip, varint, zigzag,
};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Nesting of Thrift structures followed.
const MAX_DEPTH: u32 = 32;
/// Largest footer read.
const MAX_FOOTER: u64 = 64 << 20;
/// Pages listed per column chunk before giving up on a broken chain.
const MAX_PAGES: u64 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "parquet",
    title: "Apache Parquet",
    extensions: &["parquet", "parq"],
    mime: "application/vnd.apache.parquet",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    h.starts_with(b"PAR1")
        && h.len >= 12
        && (h.tail.ends_with(b"PAR1") || h.tail.ends_with(b"PARE"))
}

// ---------------------------------------------------------------------------
// Thrift compact protocol (schema-driven, over `util::wire::thrift`)

#[derive(Clone, Copy)]
pub enum Kind {
    Plain,
    Enum(EnumTable),
    Struct(&'static StructDef),
    List(&'static Kind),
}

pub struct FieldDef {
    pub id: i16,
    pub name: &'static str,
    pub kind: Kind,
}

pub struct StructDef {
    pub name: &'static str,
    pub fields: &'static [FieldDef],
}

const fn f(id: i16, name: &'static str, kind: Kind) -> FieldDef {
    FieldDef { id, name, kind }
}

const P: Kind = Kind::Plain;

/// Bytes held in memory, with the span they came from.
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
struct ThriftState {
    buf: Buf,
    at: usize,
    def: &'static StructDef,
    depth: u32,
    file: Input,
}

/// A decoded scalar for display.
fn scalar(data: &[u8], at: usize, t: u8, kind: Kind) -> Option<Value> {
    Some(match t {
        1 | 2 => Value::Bool(t == 1),
        3 => Value::Int {
            value: i64::from(*data.get(at)? as i8),
            bits: 8,
        },
        4..=6 => {
            let (v, _) = varint(data, at)?;
            let v = zigzag(v);
            match kind {
                Kind::Enum(table) => Value::Enum {
                    raw: v.cast_unsigned(),
                    bits: 32,
                    name: lookup(table, v.cast_unsigned()),
                },
                _ => Value::Int { value: v, bits: 64 },
            }
        }
        7 => Value::Float(f64::from_le_bytes(crate::bytes::array(data, at)?)),
        8 => {
            let (len, e) = varint(data, at)?;
            let bytes = data.get(e..e.checked_add(to_usize(len))?)?;
            match std::str::from_utf8(bytes) {
                Ok(s) if !s.chars().any(char::is_control) => Value::Text(s.to_owned()),
                _ => Value::Bytes(bytes.iter().take(32).copied().collect()),
            }
        }
        _ => return None,
    })
}

/// The node for one value: scalars decoded, structs and lists expandable.
fn value_node(name: String, state: &ThriftState, at: usize, t: u8, kind: Kind) -> Node {
    let data = &state.buf.data;
    let end = skip(data, at, t, 0).unwrap_or(data.len());
    let mut node = Node::new(name).span(state.buf.sub(at, end));
    match (t, kind) {
        (12, _) => {
            let def = match kind {
                Kind::Struct(def) => def,
                _ => &UNKNOWN,
            };
            if node.name != def.name {
                node = node.summary(def.name.to_owned());
            }
            if state.depth >= MAX_DEPTH {
                return node.diag(Diagnostic::limit("structures nested too deeply"));
            }
            node.lazy(
                crate::expander!(self::thrift_struct: ThriftState),
                ThriftState {
                    at,
                    def,
                    depth: state.depth.saturating_add(1),
                    ..state.clone()
                },
            )
        }
        (9 | 10, _) => {
            let elem = match kind {
                Kind::List(k) => *k,
                _ => Kind::Plain,
            };
            let count = list_header(data, at).map_or(0, |(n, _, _)| n);
            node = node.summary(format!("{count} elements"));
            if state.depth >= MAX_DEPTH {
                return node.diag(Diagnostic::limit("structures nested too deeply"));
            }
            node.lazy(
                crate::expander!(self::thrift_list: (ThriftState, Kind)),
                (
                    ThriftState {
                        at,
                        depth: state.depth.saturating_add(1),
                        ..state.clone()
                    },
                    elem,
                ),
            )
        }
        (11, _) => node.summary("map"),
        _ => match scalar(data, at, t, kind) {
            Some(v) => node.value(v),
            None => node.diag(Diagnostic::malformed("invalid value")),
        },
    }
}

static UNKNOWN: StructDef = StructDef {
    name: "struct",
    fields: &[],
};

async fn thrift_struct(cx: Cx, state: ThriftState) -> Result<()> {
    let data = state.buf.data.clone();
    let mut pos = state.at;
    let mut id = 0i16;
    let mut ints: Vec<(i16, i64)> = Vec::new();
    loop {
        cx.checkpoint().await;
        let Some((field, t, next)) = field_header(&data, pos, id) else {
            return Err(Diagnostic::malformed("invalid field header")
                .at(state.buf.sub(pos, pos.saturating_add(1))));
        };
        if t == 0 {
            break;
        }
        id = field;
        let def = state.def.fields.iter().find(|d| d.id == field);
        let name = def.map_or_else(|| format!("Field {field}"), |d| d.name.to_owned());
        let kind = def.map_or(Kind::Plain, |d| d.kind);
        let mut node = value_node(name, &state, next, t, kind);
        // Spans include the field header.
        if let Some(span) = node.span {
            let start = state.buf.sub(pos, next).offset;
            node = node.span(Span::new(
                span.source,
                start,
                span.end().saturating_sub(start),
            ));
        }
        if matches!(t, 5 | 6)
            && let Some((v, _)) = varint(&data, next)
        {
            ints.push((field, zigzag(v)));
        }
        cx.emit(node);
        let Some(end) = skip(&data, next, t, 0) else {
            return Err(Diagnostic::malformed("invalid value")
                .at(state.buf.sub(next, next.saturating_add(1))));
        };
        pos = end;
    }
    if std::ptr::eq(state.def, &COLUMN_META_DATA) {
        column_pages(&cx, &state, &ints);
    }
    Ok(())
}

async fn thrift_list(cx: Cx, (state, elem): (ThriftState, Kind)) -> Result<()> {
    let data = state.buf.data.clone();
    let Some((n, t, mut pos)) = list_header(&data, state.at) else {
        return Err(Diagnostic::malformed("invalid list header"));
    };
    for i in 0..n {
        if pos >= data.len() {
            return Err(Diagnostic::truncated(
                state.buf.sub(state.at, pos),
                to_u64(data.len()),
            ));
        }
        let node = if t == 1 || t == 2 {
            let v = data.get(pos).copied().unwrap_or(0);
            let node = Node::new(format!("[{i}]"))
                .span(state.buf.sub(pos, pos.saturating_add(1)))
                .value(Value::Bool(v == 1));
            pos = pos.saturating_add(1);
            node
        } else {
            let node = value_node(format!("[{i}]"), &state, pos, t, elem);
            pos = skip(&data, pos, t, 0)
                .ok_or_else(|| Diagnostic::malformed("invalid list element"))?;
            node
        };
        cx.push(node).await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// The Parquet metadata structures

const TYPES: EnumTable = &[
    (0, "BOOLEAN"),
    (1, "INT32"),
    (2, "INT64"),
    (3, "INT96"),
    (4, "FLOAT"),
    (5, "DOUBLE"),
    (6, "BYTE_ARRAY"),
    (7, "FIXED_LEN_BYTE_ARRAY"),
];
const REPETITION: EnumTable = &[(0, "REQUIRED"), (1, "OPTIONAL"), (2, "REPEATED")];
const CONVERTED: EnumTable = &[
    (0, "UTF8"),
    (1, "MAP"),
    (2, "MAP_KEY_VALUE"),
    (3, "LIST"),
    (4, "ENUM"),
    (5, "DECIMAL"),
    (6, "DATE"),
    (7, "TIME_MILLIS"),
    (8, "TIME_MICROS"),
    (9, "TIMESTAMP_MILLIS"),
    (10, "TIMESTAMP_MICROS"),
    (11, "UINT_8"),
    (12, "UINT_16"),
    (13, "UINT_32"),
    (14, "UINT_64"),
    (15, "INT_8"),
    (16, "INT_16"),
    (17, "INT_32"),
    (18, "INT_64"),
    (19, "JSON"),
    (20, "BSON"),
    (21, "INTERVAL"),
];
const ENCODINGS: EnumTable = &[
    (0, "PLAIN"),
    (2, "PLAIN_DICTIONARY"),
    (3, "RLE"),
    (4, "BIT_PACKED"),
    (5, "DELTA_BINARY_PACKED"),
    (6, "DELTA_LENGTH_BYTE_ARRAY"),
    (7, "DELTA_BYTE_ARRAY"),
    (8, "RLE_DICTIONARY"),
    (9, "BYTE_STREAM_SPLIT"),
];
const CODECS: EnumTable = &[
    (0, "UNCOMPRESSED"),
    (1, "SNAPPY"),
    (2, "GZIP"),
    (3, "LZO"),
    (4, "BROTLI"),
    (5, "LZ4"),
    (6, "ZSTD"),
    (7, "LZ4_RAW"),
];
const PAGE_TYPES: EnumTable = &[
    (0, "DATA_PAGE"),
    (1, "INDEX_PAGE"),
    (2, "DICTIONARY_PAGE"),
    (3, "DATA_PAGE_V2"),
];

static STATISTICS: StructDef = StructDef {
    name: "Statistics",
    fields: &[
        f(1, "max", P),
        f(2, "min", P),
        f(3, "null_count", P),
        f(4, "distinct_count", P),
        f(5, "max_value", P),
        f(6, "min_value", P),
        f(7, "is_max_value_exact", P),
        f(8, "is_min_value_exact", P),
    ],
};

static LOGICAL_TYPE: StructDef = StructDef {
    name: "LogicalType",
    fields: &[
        f(1, "STRING", P),
        f(2, "MAP", P),
        f(3, "LIST", P),
        f(4, "ENUM", P),
        f(5, "DECIMAL", P),
        f(6, "DATE", P),
        f(7, "TIME", P),
        f(8, "TIMESTAMP", P),
        f(10, "INTEGER", P),
        f(11, "UNKNOWN", P),
        f(12, "JSON", P),
        f(13, "BSON", P),
        f(14, "UUID", P),
        f(15, "FLOAT16", P),
    ],
};

static SCHEMA_ELEMENT: StructDef = StructDef {
    name: "SchemaElement",
    fields: &[
        f(1, "type", Kind::Enum(TYPES)),
        f(2, "type_length", P),
        f(3, "repetition_type", Kind::Enum(REPETITION)),
        f(4, "name", P),
        f(5, "num_children", P),
        f(6, "converted_type", Kind::Enum(CONVERTED)),
        f(7, "scale", P),
        f(8, "precision", P),
        f(9, "field_id", P),
        f(10, "logicalType", Kind::Struct(&LOGICAL_TYPE)),
    ],
};

static KEY_VALUE: StructDef = StructDef {
    name: "KeyValue",
    fields: &[f(1, "key", P), f(2, "value", P)],
};

static COLUMN_META_DATA: StructDef = StructDef {
    name: "ColumnMetaData",
    fields: &[
        f(1, "type", Kind::Enum(TYPES)),
        f(2, "encodings", Kind::List(&Kind::Enum(ENCODINGS))),
        f(3, "path_in_schema", Kind::List(&P)),
        f(4, "codec", Kind::Enum(CODECS)),
        f(5, "num_values", P),
        f(6, "total_uncompressed_size", P),
        f(7, "total_compressed_size", P),
        f(
            8,
            "key_value_metadata",
            Kind::List(&Kind::Struct(&KEY_VALUE)),
        ),
        f(9, "data_page_offset", P),
        f(10, "index_page_offset", P),
        f(11, "dictionary_page_offset", P),
        f(12, "statistics", Kind::Struct(&STATISTICS)),
        f(13, "encoding_stats", P),
        f(14, "bloom_filter_offset", P),
        f(15, "bloom_filter_length", P),
    ],
};

static COLUMN_CHUNK: StructDef = StructDef {
    name: "ColumnChunk",
    fields: &[
        f(1, "file_path", P),
        f(2, "file_offset", P),
        f(3, "meta_data", Kind::Struct(&COLUMN_META_DATA)),
        f(4, "offset_index_offset", P),
        f(5, "offset_index_length", P),
        f(6, "column_index_offset", P),
        f(7, "column_index_length", P),
        f(8, "crypto_metadata", P),
        f(9, "encrypted_column_metadata", P),
    ],
};

static ROW_GROUP: StructDef = StructDef {
    name: "RowGroup",
    fields: &[
        f(1, "columns", Kind::List(&Kind::Struct(&COLUMN_CHUNK))),
        f(2, "total_byte_size", P),
        f(3, "num_rows", P),
        f(4, "sorting_columns", P),
        f(5, "file_offset", P),
        f(6, "total_compressed_size", P),
        f(7, "ordinal", P),
    ],
};

static FILE_META_DATA: StructDef = StructDef {
    name: "FileMetaData",
    fields: &[
        f(1, "version", P),
        f(2, "schema", Kind::List(&Kind::Struct(&SCHEMA_ELEMENT))),
        f(3, "num_rows", P),
        f(4, "row_groups", Kind::List(&Kind::Struct(&ROW_GROUP))),
        f(
            5,
            "key_value_metadata",
            Kind::List(&Kind::Struct(&KEY_VALUE)),
        ),
        f(6, "created_by", P),
        f(7, "column_orders", P),
        f(8, "encryption_algorithm", P),
        f(9, "footer_signing_key_metadata", P),
    ],
};

static DATA_PAGE_HEADER: StructDef = StructDef {
    name: "DataPageHeader",
    fields: &[
        f(1, "num_values", P),
        f(2, "encoding", Kind::Enum(ENCODINGS)),
        f(3, "definition_level_encoding", Kind::Enum(ENCODINGS)),
        f(4, "repetition_level_encoding", Kind::Enum(ENCODINGS)),
        f(5, "statistics", Kind::Struct(&STATISTICS)),
    ],
};

static DICTIONARY_PAGE_HEADER: StructDef = StructDef {
    name: "DictionaryPageHeader",
    fields: &[
        f(1, "num_values", P),
        f(2, "encoding", Kind::Enum(ENCODINGS)),
        f(3, "is_sorted", P),
    ],
};

static DATA_PAGE_HEADER_V2: StructDef = StructDef {
    name: "DataPageHeaderV2",
    fields: &[
        f(1, "num_values", P),
        f(2, "num_nulls", P),
        f(3, "num_rows", P),
        f(4, "encoding", Kind::Enum(ENCODINGS)),
        f(5, "definition_levels_byte_length", P),
        f(6, "repetition_levels_byte_length", P),
        f(7, "is_compressed", P),
        f(8, "statistics", Kind::Struct(&STATISTICS)),
    ],
};

static PAGE_HEADER: StructDef = StructDef {
    name: "PageHeader",
    fields: &[
        f(1, "type", Kind::Enum(PAGE_TYPES)),
        f(2, "uncompressed_page_size", P),
        f(3, "compressed_page_size", P),
        f(4, "crc", P),
        f(5, "data_page_header", Kind::Struct(&DATA_PAGE_HEADER)),
        f(6, "index_page_header", P),
        f(
            7,
            "dictionary_page_header",
            Kind::Struct(&DICTIONARY_PAGE_HEADER),
        ),
        f(8, "data_page_header_v2", Kind::Struct(&DATA_PAGE_HEADER_V2)),
    ],
};

// ---------------------------------------------------------------------------
// Dissection

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(Value::Text("PAR1".to_owned())),
    );
    let tail_span = file.sub(file.len.saturating_sub(8), 8);
    let tail = cx.read(tail_span).await?;
    let len = u64::from(u32_le(&tail, 0).unwrap_or(0));
    if tail.get(4..) == Some(b"PARE") {
        cx.annotate("Parquet (encrypted footer)");
        cx.emit(
            Node::new("Encrypted footer")
                .span(file.sub(file.len.saturating_sub(8).saturating_sub(len), len))
                .diag(Diagnostic::unsupported("encrypted footer")),
        );
        return Ok(());
    }
    let meta_start = file
        .len
        .saturating_sub(8)
        .checked_sub(len)
        .filter(|&s| s >= 4)
        .ok_or_else(|| {
            Diagnostic::malformed(format!("footer length {len} does not fit"))
                .at(tail_span.sub(0, 4))
        })?;
    if len > MAX_FOOTER {
        return Err(Diagnostic::limit("footer larger than 64 MiB").at(tail_span.sub(0, 4)));
    }
    let meta_span = file.sub(meta_start, len);
    let data = Arc::new(cx.read(meta_span).await?);
    let buf = Buf {
        data: data.clone(),
        span: meta_span,
    };
    cx.annotate(summary(&data));
    cx.emit(
        Node::new("Column chunks")
            .span(file.sub(4, meta_start.saturating_sub(4)))
            .summary(format!("{:#x} bytes", meta_start.saturating_sub(4))),
    );
    let state = ThriftState {
        buf,
        at: 0,
        def: &FILE_META_DATA,
        depth: 0,
        file: input,
    };
    cx.emit(value_node(
        "FileMetaData".to_owned(),
        &state,
        0,
        12,
        Kind::Struct(&FILE_META_DATA),
    ));
    cx.emit(
        Node::new("Metadata length")
            .span(tail_span.sub(0, 4))
            .value(Value::UInt {
                value: len,
                bits: 32,
                radix: Radix::Dec,
            }),
    );
    cx.emit(
        Node::new("Magic")
            .span(tail_span.sub(4, 4))
            .value(Value::Text("PAR1".to_owned())),
    );
    Ok(())
}

/// Rows, row groups, columns and writer from the top-level metadata fields.
fn summary(data: &[u8]) -> String {
    let mut pos = 0usize;
    let mut id = 0i16;
    let (mut rows, mut groups, mut columns, mut writer) = (None, None, None, None);
    while let Some((field, t, next)) = field_header(data, pos, id) {
        if t == 0 {
            break;
        }
        id = field;
        match (field, t) {
            (3, 6) => rows = varint(data, next).map(|(v, _)| zigzag(v)),
            (4, 9) => groups = list_header(data, next).map(|(n, _, _)| n),
            (2, 9) => columns = list_header(data, next).map(|(n, _, _)| n.saturating_sub(1)),
            (6, 8) => {
                if let Some(Value::Text(s)) = scalar(data, next, t, Kind::Plain) {
                    writer = Some(s);
                }
            }
            _ => {}
        }
        let Some(end) = skip(data, next, t, 0) else {
            break;
        };
        pos = end;
    }
    let mut out = "Parquet".to_owned();
    if let Some(r) = rows {
        out = format!("{out}, {r} rows");
    }
    if let Some(g) = groups {
        out = format!("{out}, {g} row groups");
    }
    if let Some(c) = columns {
        out = format!("{out}, {c} schema fields");
    }
    if let Some(w) = writer {
        out = format!("{out}, written by {w}");
    }
    out
}

/// Adds a "Pages" node to a ColumnMetaData expansion.
fn column_pages(cx: &Cx, state: &ThriftState, ints: &[(i16, i64)]) {
    let get = |id: i16| ints.iter().find(|(f, _)| *f == id).map(|(_, v)| *v);
    let (Some(data_page), Some(size)) = (get(9), get(7)) else {
        return;
    };
    let start = get(11)
        .filter(|&d| d > 0 && d < data_page)
        .unwrap_or(data_page);
    let (Ok(start), Ok(size)) = (u64::try_from(start), u64::try_from(size)) else {
        return;
    };
    let span = state.file.span.sub(start, size);
    cx.emit(
        Node::new("Pages")
            .span(span)
            .summary(format!("{size} bytes from {start:#x}"))
            .lazy(pages, (state.file, span)),
    );
}

async fn pages(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos < span.len && index < MAX_PAGES {
        let window = span.sub(pos, 64 * 1024);
        let data = Arc::new(cx.read_avail(window).await?);
        let end = skip(&data, 0, 12, 0)
            .ok_or_else(|| Diagnostic::malformed("invalid page header").at(window.sub(0, 1)))?;
        let mut compressed = 0u64;
        let mut kind = None;
        let mut id = 0i16;
        let mut p = 0usize;
        while let Some((field, t, next)) = field_header(&data, p, id) {
            if t == 0 {
                break;
            }
            id = field;
            if let Some((v, _)) = varint(&data, next).filter(|_| matches!(t, 5 | 6)) {
                match field {
                    1 => kind = Some(zigzag(v)),
                    3 => compressed = u64::try_from(zigzag(v)).unwrap_or(0),
                    _ => {}
                }
            }
            let Some(e) = skip(&data, next, t, 0) else {
                break;
            };
            p = e;
        }
        let header = window.sub(0, to_u64(end));
        let body = span.sub(pos.saturating_add(to_u64(end)), compressed);
        let name = kind
            .and_then(|k| lookup(PAGE_TYPES, k.cast_unsigned()))
            .unwrap_or("Page");
        let state = ThriftState {
            buf: Buf {
                data: data.clone(),
                span: window,
            },
            at: 0,
            def: &PAGE_HEADER,
            depth: 0,
            file: input,
        };
        cx.push(
            Node::new(format!("{name} {index}"))
                .span(span.sub(pos, to_u64(end).saturating_add(compressed)))
                .summary(format!("{compressed} bytes"))
                .lazy(page, (state, header, body)),
        )
        .await;
        pos = pos
            .saturating_add(to_u64(end))
            .saturating_add(compressed)
            .max(pos.saturating_add(1));
        index = index.saturating_add(1);
    }
    Ok(())
}

async fn page(cx: Cx, (state, header, body): (ThriftState, Span, Span)) -> Result<()> {
    cx.emit(
        value_node(
            "PageHeader".to_owned(),
            &state,
            0,
            12,
            Kind::Struct(&PAGE_HEADER),
        )
        .span(header),
    );
    cx.emit(
        Node::new("Page data")
            .span(body)
            .summary(format!("{} bytes", body.len)),
    );
    Ok(())
}
