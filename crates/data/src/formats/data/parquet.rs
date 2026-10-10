//! Apache Parquet: `PAR1`, the column chunks of each row group (pages:
//! a Thrift page header, then the page data), bloom filters and the page
//! index, then the file metadata (Thrift compact protocol), its length and
//! `PAR1` again.
//!
//! The metadata is decoded lazily with a small schema of the Thrift
//! structures (`parquet.thrift`); statistics and page index bounds are
//! shown in the column's physical type. Pages are decompressed (Snappy,
//! gzip, Brotli, Zstandard, LZ4 raw) and their contents shown: levels
//! (RLE/bit-packed hybrid runs), PLAIN values and dictionary indices.
//! Checked against pyarrow's `ParquetFile.metadata` and page readers.

use std::sync::{Arc, Mutex};
use std::task::Poll;

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::codec::Codec;
use crate::cx::{Cx, lock};
use crate::error::{Diagnostic, Result};
use crate::formats::util::wire::thrift::compact::{
    field_header, list_header, skip, varint, zigzag,
};
use crate::formats::util::wire::thrift::{Memo, Skip};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Nesting of Thrift structures followed.
const MAX_DEPTH: u32 = 32;
/// Largest footer read.
const MAX_FOOTER: u64 = 64 << 20;
/// Pages listed per column chunk before giving up on a broken chain.
const MAX_PAGES: u64 = 1 << 20;
/// Thrift values skipped per unit of work.
const SKIP_STEP: u32 = 256;
/// Largest page whose contents are decoded.
const MAX_PAGE: u64 = 16 << 20;
/// Values read at once.
const WINDOW: u64 = 64 * 1024;

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
    /// Binary holding a value of the column's physical type (statistics,
    /// page index bounds).
    Typed,
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
    /// Ends of large values already skipped, shared by all nodes.
    memo: Arc<Mutex<Memo>>,
}

impl Buf {
    fn new(data: Arc<Vec<u8>>, span: Span) -> Buf {
        Buf {
            data,
            span,
            memo: Arc::default(),
        }
    }

    fn sub(&self, start: usize, end: usize) -> Span {
        self.span
            .sub(to_u64(start), to_u64(end.saturating_sub(start)))
    }

    /// [`skip`] in bounded steps, remembering large values.
    async fn skip(&self, cx: &Cx, at: usize, t: u8) -> Option<usize> {
        skip_async(cx, &self.data, &self.memo, at, t).await
    }
}

/// [`skip`] of the value of compact type `t` at `at`, in bounded steps.
async fn skip_async(cx: &Cx, data: &[u8], memo: &Mutex<Memo>, at: usize, t: u8) -> Option<usize> {
    let mut skip = Skip::compact(at, t, 0);
    loop {
        let step = skip.step(data, Some(&mut lock(memo)), SKIP_STEP);
        match step {
            Poll::Ready(r) => return r.map(|(end, _)| end),
            Poll::Pending => cx.checkpoint().await,
        }
    }
}

#[derive(Clone)]
struct ThriftState {
    buf: Buf,
    at: usize,
    def: &'static StructDef,
    depth: u32,
    file: Input,
    /// The column's physical type, for typed binary values.
    phys: Option<i64>,
}

/// A value of physical type `phys` stored in `bytes` (PLAIN encoding).
fn typed(phys: i64, bytes: &[u8]) -> Value {
    let le = |n: usize| -> Option<[u8; 8]> {
        let mut out = [0u8; 8];
        out.get_mut(..n)?.copy_from_slice(bytes.get(..n)?);
        Some(out)
    };
    let v = match (phys, bytes.len()) {
        (0, 1..) => Some(Value::Bool(bytes.first().copied().unwrap_or(0) != 0)),
        (1, 4) => le(4).map(|b| Value::Int {
            value: i64::from(i32::from_le_bytes([b[0], b[1], b[2], b[3]])),
            bits: 32,
        }),
        (2, 8) => le(8).map(|b| Value::Int {
            value: i64::from_le_bytes(b),
            bits: 64,
        }),
        (3, 12) => {
            // INT96 timestamps: nanoseconds of the day, then the Julian day.
            let nanos = le(8).map(i64::from_le_bytes).unwrap_or(0);
            let day = bytes
                .get(8..12)
                .and_then(|d| d.try_into().ok())
                .map_or(0, i32::from_le_bytes);
            Some(Value::Timestamp {
                unix_seconds: i64::from(day)
                    .saturating_sub(crate::formats::util::civil::UNIX_JULIAN_DAY)
                    .saturating_mul(86_400)
                    .saturating_add(nanos / 1_000_000_000),
            })
        }
        (4, 4) => le(4).map(|b| Value::Float(f32::from_le_bytes([b[0], b[1], b[2], b[3]]).into())),
        (5, 8) => le(8).map(|b| Value::Float(f64::from_le_bytes(b))),
        (6, _) => std::str::from_utf8(bytes)
            .ok()
            .filter(|s| !s.chars().any(char::is_control))
            .map(|s| Value::Text(s.to_owned())),
        _ => None,
    };
    v.unwrap_or_else(|| Value::Bytes(bytes.iter().take(64).copied().collect()))
}

/// A decoded scalar for display.
fn scalar(data: &[u8], at: usize, t: u8, kind: Kind, phys: Option<i64>) -> Option<Value> {
    Some(match t {
        1 | 2 => Value::Bool(t == 1),
        3 => Value::Int {
            value: i64::from(data.get(at)?.cast_signed()),
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
            match (kind, phys) {
                (Kind::Typed, Some(p)) => typed(p, bytes),
                _ => match std::str::from_utf8(bytes) {
                    Ok(s) if !s.chars().any(char::is_control) => Value::Text(s.to_owned()),
                    _ => Value::Bytes(bytes.iter().take(32).copied().collect()),
                },
            }
        }
        _ => return None,
    })
}

/// The node for one value: scalars decoded, structs and lists expandable.
async fn value_node(
    cx: &Cx,
    name: String,
    state: &ThriftState,
    at: usize,
    t: u8,
    kind: Kind,
) -> Node {
    let data = &state.buf.data;
    let end = state.buf.skip(cx, at, t).await.unwrap_or(data.len());
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
        _ => match scalar(data, at, t, kind, state.phys) {
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
    let mut state = state;
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
        let mut node = value_node(&cx, name, &state, next, t, kind).await;
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
            let v = zigzag(v);
            ints.push((field, v));
            // The physical type comes first in ColumnMetaData.
            if std::ptr::eq(state.def, &COLUMN_META_DATA) && field == 1 {
                state.phys = Some(v);
            }
        }
        cx.emit(node);
        let Some(end) = state.buf.skip(&cx, next, t).await else {
            return Err(Diagnostic::malformed("invalid value")
                .at(state.buf.sub(next, next.saturating_add(1))));
        };
        pos = end;
    }
    cx.emit(
        Node::new("Stop")
            .span(state.buf.sub(pos, pos.saturating_add(1)))
            .value(Value::UInt {
                value: 0,
                bits: 8,
                radix: Radix::Hex,
            }),
    );
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
    cx.emit(
        Node::new("List header")
            .span(state.buf.sub(state.at, pos))
            .value(Value::UInt {
                value: n,
                bits: 32,
                radix: Radix::Dec,
            })
            .summary("element count and type"),
    );
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
            let node = value_node(&cx, format!("[{i}]"), &state, pos, t, elem).await;
            pos = state
                .buf
                .skip(&cx, pos, t)
                .await
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
const BOUNDARY_ORDERS: EnumTable = &[(0, "UNORDERED"), (1, "ASCENDING"), (2, "DESCENDING")];

static STATISTICS: StructDef = StructDef {
    name: "Statistics",
    fields: &[
        f(1, "max", Kind::Typed),
        f(2, "min", Kind::Typed),
        f(3, "null_count", P),
        f(4, "distinct_count", P),
        f(5, "max_value", Kind::Typed),
        f(6, "min_value", Kind::Typed),
        f(7, "is_max_value_exact", P),
        f(8, "is_min_value_exact", P),
    ],
};

static EMPTY: StructDef = StructDef {
    name: "(empty)",
    fields: &[],
};

static TIME_UNIT: StructDef = StructDef {
    name: "TimeUnit",
    fields: &[
        f(1, "MILLIS", Kind::Struct(&EMPTY)),
        f(2, "MICROS", Kind::Struct(&EMPTY)),
        f(3, "NANOS", Kind::Struct(&EMPTY)),
    ],
};

static DECIMAL_TYPE: StructDef = StructDef {
    name: "DecimalType",
    fields: &[f(1, "scale", P), f(2, "precision", P)],
};

static TIME_TYPE: StructDef = StructDef {
    name: "TimeType",
    fields: &[
        f(1, "isAdjustedToUTC", P),
        f(2, "unit", Kind::Struct(&TIME_UNIT)),
    ],
};

static INT_TYPE: StructDef = StructDef {
    name: "IntType",
    fields: &[f(1, "bitWidth", P), f(2, "isSigned", P)],
};

static LOGICAL_TYPE: StructDef = StructDef {
    name: "LogicalType",
    fields: &[
        f(1, "STRING", Kind::Struct(&EMPTY)),
        f(2, "MAP", Kind::Struct(&EMPTY)),
        f(3, "LIST", Kind::Struct(&EMPTY)),
        f(4, "ENUM", Kind::Struct(&EMPTY)),
        f(5, "DECIMAL", Kind::Struct(&DECIMAL_TYPE)),
        f(6, "DATE", Kind::Struct(&EMPTY)),
        f(7, "TIME", Kind::Struct(&TIME_TYPE)),
        f(8, "TIMESTAMP", Kind::Struct(&TIME_TYPE)),
        f(10, "INTEGER", Kind::Struct(&INT_TYPE)),
        f(11, "UNKNOWN", Kind::Struct(&EMPTY)),
        f(12, "JSON", Kind::Struct(&EMPTY)),
        f(13, "BSON", Kind::Struct(&EMPTY)),
        f(14, "UUID", Kind::Struct(&EMPTY)),
        f(15, "FLOAT16", Kind::Struct(&EMPTY)),
        f(16, "VARIANT", P),
        f(17, "GEOMETRY", P),
        f(18, "GEOGRAPHY", P),
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

static PAGE_ENCODING_STATS: StructDef = StructDef {
    name: "PageEncodingStats",
    fields: &[
        f(1, "page_type", Kind::Enum(PAGE_TYPES)),
        f(2, "encoding", Kind::Enum(ENCODINGS)),
        f(3, "count", P),
    ],
};

static SIZE_STATISTICS: StructDef = StructDef {
    name: "SizeStatistics",
    fields: &[
        f(1, "unencoded_byte_array_data_bytes", P),
        f(2, "repetition_level_histogram", Kind::List(&P)),
        f(3, "definition_level_histogram", Kind::List(&P)),
    ],
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
        f(
            13,
            "encoding_stats",
            Kind::List(&Kind::Struct(&PAGE_ENCODING_STATS)),
        ),
        f(14, "bloom_filter_offset", P),
        f(15, "bloom_filter_length", P),
        f(16, "size_statistics", Kind::Struct(&SIZE_STATISTICS)),
        f(17, "geospatial_statistics", P),
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

static SORTING_COLUMN: StructDef = StructDef {
    name: "SortingColumn",
    fields: &[
        f(1, "column_idx", P),
        f(2, "descending", P),
        f(3, "nulls_first", P),
    ],
};

static ROW_GROUP: StructDef = StructDef {
    name: "RowGroup",
    fields: &[
        f(1, "columns", Kind::List(&Kind::Struct(&COLUMN_CHUNK))),
        f(2, "total_byte_size", P),
        f(3, "num_rows", P),
        f(
            4,
            "sorting_columns",
            Kind::List(&Kind::Struct(&SORTING_COLUMN)),
        ),
        f(5, "file_offset", P),
        f(6, "total_compressed_size", P),
        f(7, "ordinal", P),
    ],
};

static COLUMN_ORDER: StructDef = StructDef {
    name: "ColumnOrder",
    fields: &[f(1, "TYPE_ORDER", Kind::Struct(&EMPTY))],
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
        f(7, "column_orders", Kind::List(&Kind::Struct(&COLUMN_ORDER))),
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

static PAGE_LOCATION: StructDef = StructDef {
    name: "PageLocation",
    fields: &[
        f(1, "offset", P),
        f(2, "compressed_page_size", P),
        f(3, "first_row_index", P),
    ],
};

static OFFSET_INDEX: StructDef = StructDef {
    name: "OffsetIndex",
    fields: &[
        f(
            1,
            "page_locations",
            Kind::List(&Kind::Struct(&PAGE_LOCATION)),
        ),
        f(2, "unencoded_byte_array_data_bytes", Kind::List(&P)),
    ],
};

static COLUMN_INDEX: StructDef = StructDef {
    name: "ColumnIndex",
    fields: &[
        f(1, "null_pages", Kind::List(&P)),
        f(2, "min_values", Kind::List(&Kind::Typed)),
        f(3, "max_values", Kind::List(&Kind::Typed)),
        f(4, "boundary_order", Kind::Enum(BOUNDARY_ORDERS)),
        f(5, "null_counts", Kind::List(&P)),
        f(6, "repetition_level_histograms", Kind::List(&P)),
        f(7, "definition_level_histograms", Kind::List(&P)),
    ],
};

static SPLIT_BLOCK: StructDef = StructDef {
    name: "BloomFilterAlgorithm",
    fields: &[f(1, "BLOCK", Kind::Struct(&EMPTY))],
};

static XXHASH: StructDef = StructDef {
    name: "BloomFilterHash",
    fields: &[f(1, "XXHASH", Kind::Struct(&EMPTY))],
};

static UNCOMPRESSED: StructDef = StructDef {
    name: "BloomFilterCompression",
    fields: &[f(1, "UNCOMPRESSED", Kind::Struct(&EMPTY))],
};

static BLOOM_FILTER_HEADER: StructDef = StructDef {
    name: "BloomFilterHeader",
    fields: &[
        f(1, "numBytes", P),
        f(2, "algorithm", Kind::Struct(&SPLIT_BLOCK)),
        f(3, "hash", Kind::Struct(&XXHASH)),
        f(4, "compression", Kind::Struct(&UNCOMPRESSED)),
    ],
};

// ---------------------------------------------------------------------------
// What the metadata says about each column chunk

#[derive(Clone, Debug, Default)]
struct Leaf {
    path: String,
    phys: i64,
    type_length: i64,
    max_def: u32,
    max_rep: u32,
}

#[derive(Clone, Debug, Default)]
struct Col {
    group: usize,
    leaf: Leaf,
    codec: i64,
    num_values: i64,
    data_page: i64,
    dict_page: Option<i64>,
    size: i64,
    bloom: Option<(i64, Option<i64>)>,
    column_index: Option<(i64, i64)>,
    offset_index: Option<(i64, i64)>,
}

#[derive(Debug, Default)]
struct Meta {
    cols: Vec<Col>,
    /// (rows, columns) of each row group.
    groups: Vec<(i64, Vec<usize>)>,
}

/// The fields of the struct at `at`: (id, type, value position), and
/// where the struct ends.
async fn fields_of(cx: &Cx, buf: &Buf, at: usize) -> Option<(Vec<(i16, u8, usize)>, usize)> {
    let data = &buf.data;
    let mut out = Vec::new();
    let mut pos = at;
    let mut id = 0i16;
    loop {
        let (field, t, next) = field_header(data, pos, id)?;
        if t == 0 {
            return Some((out, next));
        }
        id = field;
        out.push((field, t, next));
        pos = buf.skip(cx, next, t).await?;
        if out.len() > 1024 {
            return None;
        }
    }
}

fn int_at(data: &[u8], pos: usize, t: u8) -> Option<i64> {
    match t {
        3 => Some(i64::from(data.get(pos)?.cast_signed())),
        4..=6 => Some(zigzag(varint(data, pos)?.0)),
        _ => None,
    }
}

fn get(fields: &[(i16, u8, usize)], id: i16) -> Option<(u8, usize)> {
    fields
        .iter()
        .find(|(f, _, _)| *f == id)
        .map(|&(_, t, p)| (t, p))
}

fn int_field(data: &[u8], fields: &[(i16, u8, usize)], id: i16) -> Option<i64> {
    let (t, p) = get(fields, id)?;
    int_at(data, p, t)
}

fn string_at(data: &[u8], pos: usize) -> Option<String> {
    let (len, e) = varint(data, pos)?;
    Some(String::from_utf8_lossy(data.get(e..e.checked_add(to_usize(len))?)?).into_owned())
}

/// Walks the schema (leaf columns, their levels) and the row groups.
async fn collect(cx: &Cx, buf: &Buf) -> Option<Meta> {
    let data = buf.data.clone();
    let (top, _) = fields_of(cx, buf, 0).await?;
    // Schema leaves, depth-first: a stack of (children left, def, rep, path).
    let mut leaves = Vec::new();
    if let Some((9, at)) = get(&top, 2) {
        let (n, _, mut pos) = list_header(&data, at)?;
        let mut stack: Vec<(i64, u32, u32, String)> = Vec::new();
        for i in 0..n {
            cx.checkpoint().await;
            let (fields, end) = fields_of(cx, buf, pos).await?;
            pos = end;
            let name = get(&fields, 4)
                .and_then(|(_, p)| string_at(&data, p))
                .unwrap_or_default();
            let children = int_field(&data, &fields, 5).unwrap_or(0);
            let rep = int_field(&data, &fields, 3).unwrap_or(0);
            let (mut def, mut reps, mut path) = stack
                .last()
                .map(|(_, d, r, p)| (*d, *r, p.clone()))
                .unwrap_or_default();
            if i > 0 {
                if rep == 1 {
                    def = def.saturating_add(1);
                }
                if rep == 2 {
                    def = def.saturating_add(1);
                    reps = reps.saturating_add(1);
                }
                path = if path.is_empty() {
                    name
                } else {
                    format!("{path}.{name}")
                };
            }
            if let Some(top) = stack.last_mut() {
                top.0 = top.0.saturating_sub(1);
            }
            if children > 0 {
                stack.push((children, def, reps, path));
            } else if i > 0 {
                leaves.push(Leaf {
                    path,
                    phys: int_field(&data, &fields, 1).unwrap_or(-1),
                    type_length: int_field(&data, &fields, 2).unwrap_or(0),
                    max_def: def,
                    max_rep: reps,
                });
            }
            while stack.last().is_some_and(|t| t.0 <= 0) {
                stack.pop();
            }
        }
    }
    let mut meta = Meta::default();
    if let Some((9, at)) = get(&top, 4) {
        let (n, _, mut pos) = list_header(&data, at)?;
        for g in 0..to_usize(n) {
            let (rg, end) = fields_of(cx, buf, pos).await?;
            pos = end;
            let rows = int_field(&data, &rg, 3).unwrap_or(0);
            let mut cols = Vec::new();
            if let Some((9, at)) = get(&rg, 1) {
                let (k, _, mut cpos) = list_header(&data, at)?;
                for c in 0..to_usize(k) {
                    cx.checkpoint().await;
                    let (cc, end) = fields_of(cx, buf, cpos).await?;
                    cpos = end;
                    let mut col = Col {
                        group: g,
                        leaf: leaves.get(c).cloned().unwrap_or_default(),
                        ..Col::default()
                    };
                    let pair = |a: i16, b: i16| {
                        Some((int_field(&data, &cc, a)?, int_field(&data, &cc, b)?))
                    };
                    col.offset_index = pair(4, 5);
                    col.column_index = pair(6, 7);
                    if let Some((12, at)) = get(&cc, 3) {
                        let (md, _) = fields_of(cx, buf, at).await?;
                        let i = |id| int_field(&data, &md, id);
                        if let Some(p) = i(1) {
                            col.leaf.phys = p;
                        }
                        col.codec = i(4).unwrap_or(0);
                        col.num_values = i(5).unwrap_or(0);
                        col.size = i(7).unwrap_or(0);
                        col.data_page = i(9).unwrap_or(0);
                        col.dict_page = i(11).filter(|&d| d > 0);
                        col.bloom = i(14).map(|o| (o, i(15)));
                    }
                    cols.push(meta.cols.len());
                    meta.cols.push(col);
                }
            }
            meta.groups.push((rows, cols));
        }
    }
    Some(meta)
}

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
    let buf = Buf::new(data.clone(), meta_span);
    cx.annotate(summary(&cx, &buf).await);
    let meta = Arc::new(collect(&cx, &buf).await.unwrap_or_default());
    // Where the column chunks end: at the first bloom filter or index.
    let mut data_end = meta_start;
    for c in &meta.cols {
        for at in [
            c.bloom.map(|b| b.0),
            c.column_index.map(|i| i.0),
            c.offset_index.map(|i| i.0),
        ]
        .into_iter()
        .flatten()
        {
            if let Ok(at) = u64::try_from(at)
                && at >= 4
            {
                data_end = data_end.min(at);
            }
        }
    }
    let state = Ctx {
        input,
        meta: meta.clone(),
    };
    cx.emit(
        Node::new("Row groups")
            .span(file.sub(4, data_end.saturating_sub(4)))
            .summary(format!(
                "{}, {}",
                meta.groups.len(),
                crate::formats::util::fmt::size(data_end.saturating_sub(4))
            ))
            .lazy(row_groups, state.clone()),
    );
    let blooms = meta.cols.iter().filter(|c| c.bloom.is_some()).count();
    if blooms > 0 {
        cx.emit(
            Node::new("Bloom filters")
                .summary(format!("{blooms}"))
                .lazy(bloom_filters, state.clone()),
        );
    }
    let indexed = meta
        .cols
        .iter()
        .filter(|c| c.column_index.is_some() || c.offset_index.is_some())
        .count();
    if indexed > 0 {
        cx.emit(
            Node::new("Page index")
                .summary(format!("{indexed} column chunks"))
                .lazy(page_index, state.clone()),
        );
    }
    let tstate = ThriftState {
        buf,
        at: 0,
        def: &FILE_META_DATA,
        depth: 0,
        file: input,
        phys: None,
    };
    cx.emit(
        value_node(
            &cx,
            "FileMetaData".to_owned(),
            &tstate,
            0,
            12,
            Kind::Struct(&FILE_META_DATA),
        )
        .await,
    );
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

#[derive(Clone)]
struct Ctx {
    input: Input,
    meta: Arc<Meta>,
}

/// Rows, row groups, columns and writer from the top-level metadata fields.
async fn summary(cx: &Cx, buf: &Buf) -> String {
    let data = &buf.data;
    let mut pos = 0usize;
    let mut id = 0i16;
    let (mut rows, mut groups, mut columns, mut writer) = (None, None, None, None);
    while let Some((field, t, next)) = field_header(data, pos, id) {
        cx.checkpoint().await;
        if t == 0 {
            break;
        }
        id = field;
        match (field, t) {
            (3, 6) => rows = varint(data, next).map(|(v, _)| zigzag(v)),
            (4, 9) => groups = list_header(data, next).map(|(n, _, _)| n),
            (2, 9) => columns = list_header(data, next).map(|(n, _, _)| n.saturating_sub(1)),
            (6, 8) => {
                if let Some(Value::Text(s)) = scalar(data, next, t, Kind::Plain, None) {
                    writer = Some(s);
                }
            }
            _ => {}
        }
        let Some(end) = buf.skip(cx, next, t).await else {
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

fn col_span(input: Input, c: &Col) -> Option<Span> {
    let start = c
        .dict_page
        .filter(|&d| d < c.data_page)
        .unwrap_or(c.data_page);
    let (Ok(start), Ok(size)) = (u64::try_from(start), u64::try_from(c.size)) else {
        return None;
    };
    Some(input.span.sub(start, size))
}

async fn row_groups(cx: Cx, ctx: Ctx) -> Result<()> {
    for (g, (rows, cols)) in ctx.meta.groups.iter().enumerate() {
        let bytes: i64 = cols
            .iter()
            .filter_map(|&c| ctx.meta.cols.get(c))
            .map(|c| c.size)
            .sum();
        let start = cols
            .iter()
            .filter_map(|&c| ctx.meta.cols.get(c))
            .filter_map(|c| col_span(ctx.input, c))
            .map(|s| s.offset)
            .min();
        let mut node = Node::new(format!("Row group {g}"))
            .summary(format!(
                "{rows} rows, {} columns, {}",
                cols.len(),
                crate::formats::util::fmt::size(u64::try_from(bytes).unwrap_or(0))
            ))
            .lazy(columns, (ctx.clone(), g));
        if let Some(start) = start {
            node = node.span(Span::new(
                ctx.input.span.source,
                start,
                u64::try_from(bytes).unwrap_or(0),
            ));
        }
        cx.push(node).await;
    }
    Ok(())
}

async fn columns(cx: Cx, (ctx, g): (Ctx, usize)) -> Result<()> {
    let Some((_, cols)) = ctx.meta.groups.get(g) else {
        return Ok(());
    };
    for &i in cols {
        let Some(c) = ctx.meta.cols.get(i) else {
            continue;
        };
        let Some(span) = col_span(ctx.input, c) else {
            continue;
        };
        cx.push(
            Node::new(c.leaf.path.clone())
                .span(span)
                .summary(format!(
                    "{}, {}, {} values",
                    lookup(TYPES, c.leaf.phys.cast_unsigned()).unwrap_or("?"),
                    lookup(CODECS, c.codec.cast_unsigned()).unwrap_or("?"),
                    c.num_values
                ))
                .lazy(pages, (ctx.clone(), i, span)),
        )
        .await;
    }
    Ok(())
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
            .target(span),
    );
}

async fn pages(cx: Cx, (ctx, col, span): (Ctx, usize, Span)) -> Result<()> {
    let input = ctx.input;
    let phys = ctx.meta.cols.get(col).map(|c| c.leaf.phys);
    let mut pos = 0u64;
    let mut index = 0u64;
    let mut data_pages = 0u64;
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
        let name = match kind {
            Some(2) => "Dictionary page".to_owned(),
            Some(0 | 3) => {
                data_pages = data_pages.saturating_add(1);
                format!("Data page {}", data_pages.saturating_sub(1))
            }
            Some(k) => lookup(PAGE_TYPES, k.cast_unsigned())
                .unwrap_or("Page")
                .to_owned(),
            None => "Page".to_owned(),
        };
        let state = ThriftState {
            buf: Buf::new(data.clone(), window),
            at: 0,
            def: &PAGE_HEADER,
            depth: 0,
            file: input,
            phys,
        };
        cx.progress(pos, span.len);
        cx.push(
            Node::new(name)
                .span(span.sub(pos, to_u64(end).saturating_add(compressed)))
                .summary({
                    let info = page_info(&data);
                    format!(
                        "{}, {} values, {}",
                        crate::formats::util::fmt::size(compressed),
                        info.num_values,
                        lookup(ENCODINGS, info.encoding.cast_unsigned()).unwrap_or("?")
                    )
                })
                .lazy(page, (ctx.clone(), col, state, header, body)),
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

/// What a page header says (the fields that matter for its contents).
#[derive(Clone, Copy, Debug, Default)]
struct PageInfo {
    kind: i64,
    uncompressed: u64,
    crc: Option<u32>,
    num_values: u64,
    encoding: i64,
    /// Data page v2: level lengths, null count, whether values are
    /// compressed.
    def_len: u64,
    rep_len: u64,
    nulls: Option<u64>,
    compressed: bool,
}

fn page_info(data: &[u8]) -> PageInfo {
    let mut info = PageInfo {
        compressed: true,
        ..PageInfo::default()
    };
    let mut id = 0i16;
    let mut p = 0usize;
    while let Some((field, t, next)) = field_header(data, p, id) {
        if t == 0 {
            break;
        }
        id = field;
        let v = int_at(data, next, t).unwrap_or(0);
        match field {
            1 => info.kind = v,
            2 => info.uncompressed = u64::try_from(v).unwrap_or(0),
            4 => info.crc = u32::try_from(v & 0xffff_ffff).ok(),
            5 | 7 | 8 if t == 12 => {
                let mut sid = 0i16;
                let mut sp = next;
                while let Some((sf, st, snext)) = field_header(data, sp, sid) {
                    if st == 0 {
                        break;
                    }
                    sid = sf;
                    let sv = int_at(data, snext, st).unwrap_or(0);
                    match (field, sf) {
                        (_, 1) => info.num_values = u64::try_from(sv).unwrap_or(0),
                        (5 | 7, 2) | (8, 4) => info.encoding = sv,
                        (8, 2) => info.nulls = u64::try_from(sv).ok(),
                        (8, 5) => info.def_len = u64::try_from(sv).unwrap_or(0),
                        (8, 6) => info.rep_len = u64::try_from(sv).unwrap_or(0),
                        (8, 7) => info.compressed = st == 1,
                        _ => {}
                    }
                    let Some(e) = skip(data, snext, st, 0) else {
                        break;
                    };
                    sp = e;
                }
            }
            _ => {}
        }
        let Some(e) = skip(data, next, t, 0) else {
            break;
        };
        p = e;
    }
    info
}

fn codec(c: i64) -> Option<Codec> {
    Some(match c {
        1 => Codec::Snappy,
        2 => Codec::Gzip,
        4 => Codec::Brotli,
        6 => Codec::Zstd,
        7 => Codec::Lz4Block,
        _ => return None,
    })
}

async fn page(
    cx: Cx,
    (ctx, col, state, header, body): (Ctx, usize, ThriftState, Span, Span),
) -> Result<()> {
    cx.emit(
        value_node(
            &cx,
            "PageHeader".to_owned(),
            &state,
            0,
            12,
            Kind::Struct(&PAGE_HEADER),
        )
        .await
        .span(header),
    );
    let info = page_info(&state.buf.data);
    let Some(c) = ctx.meta.cols.get(col).cloned() else {
        cx.emit(Node::new("Page data").span(body));
        return Ok(());
    };
    if let Some(crc) = info.crc
        && body.len <= MAX_PAGE
    {
        let data = cx.read(body).await?;
        let computed = crate::formats::util::datakit::crc32_paced(&cx, &data).await;
        let node = Node::new("CRC check").value(Value::UInt {
            value: computed.into(),
            bits: 32,
            radix: Radix::Hex,
        });
        cx.emit(if computed == crc {
            node.summary("CRC-32 of the page data matches the header")
        } else {
            node.diag(Diagnostic::warning(format!(
                "page CRC mismatch: the header says {crc:#010x}"
            )))
        });
    }
    let v2 = info.kind == 3;
    let levels = info.rep_len.saturating_add(info.def_len);
    if v2 && levels > 0 {
        cx.emit(
            Node::new("Levels")
                .span(body.sub(0, levels))
                .summary("uncompressed")
                .lazy(levels_v2, (c.clone(), info, body.sub(0, levels))),
        );
    }
    let values = if v2 { body.tail(levels) } else { body };
    let compressed = c.codec != 0 && (!v2 || info.compressed);
    if !compressed {
        cx.emit(
            Node::new("Page data")
                .span(values)
                .lazy(page_contents, (c, info, values)),
        );
        return Ok(());
    }
    let expected = info
        .uncompressed
        .saturating_sub(if v2 { levels } else { 0 });
    let name = format!(
        "{} data",
        lookup(CODECS, c.codec.cast_unsigned()).unwrap_or("Compressed")
    );
    let mut node = Node::new(name).span(values).summary(format!(
        "{} → {}",
        crate::formats::util::fmt::size(values.len),
        crate::formats::util::fmt::size(expected)
    ));
    node = match codec(c.codec) {
        Some(codec) if expected <= MAX_PAGE => {
            node.lazy(decoded_page, (c, info, values, codec, expected))
        }
        Some(_) => node.diag(Diagnostic::limit("page too large to decode")),
        None => node.diag(Diagnostic::unsupported(format!(
            "{} compression",
            lookup(CODECS, c.codec.cast_unsigned()).unwrap_or("unknown")
        ))),
    };
    cx.emit(node);
    Ok(())
}

async fn decoded_page(
    cx: Cx,
    (c, info, span, codec, expected): (Col, PageInfo, Span, Codec, u64),
) -> Result<()> {
    // A GZIP page is a whole RFC 1952 stream; `Codec::Gzip` decodes from
    // the end of the first member's header.
    let span = if matches!(codec, Codec::Gzip) {
        let head = cx.read_avail(span.sub(0, 1 << 18)).await?;
        span.tail(to_u64(
            crate::codec::gzip::header_len(&head).map_err(|e| e.at(span))?,
        ))
    } else {
        span
    };
    let decoded = crate::codec::decode_span(&cx, span, &codec, Some(expected)).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    page_contents(cx, (c, info, decoded.span)).await
}

// ---------------------------------------------------------------------------
// Page contents

/// Bits needed for levels up to `max`.
fn bit_width(max: u32) -> u32 {
    32u32.saturating_sub(max.leading_zeros())
}

/// One run of the RLE/bit-packed hybrid encoding.
struct Run {
    span: (usize, usize),
    rle: bool,
    count: u64,
    values: Vec<u64>,
}

/// Values unpacked from bit-packed runs per page.
const MAX_UNPACK: u64 = 1 << 20;

/// Decodes RLE/bit-packed hybrid runs from `data` (at most `want`
/// values). Returns the runs and the bytes used.
async fn hybrid(cx: &Cx, data: &[u8], width: u32, want: u64) -> (Vec<Run>, usize) {
    let mut runs = Vec::new();
    let mut pos = 0usize;
    let mut got = 0u64;
    let mut unpacked = 0u64;
    let bytes = to_usize(u64::from(width).div_ceil(8));
    while got < want && pos < data.len() && runs.len() < 1 << 16 {
        if runs.len() % 256 == 255 {
            cx.checkpoint().await;
        }
        let Some((header, n)) = crate::bytes::uleb128(data.get(pos..).unwrap_or_default()) else {
            break;
        };
        let start = pos;
        pos = pos.saturating_add(n);
        if header & 1 == 0 {
            let count = header >> 1;
            let value = crate::formats::util::datakit::le_uint(
                data.get(pos..pos.saturating_add(bytes)).unwrap_or_default(),
            );
            pos = pos.saturating_add(bytes);
            got = got.saturating_add(count);
            runs.push(Run {
                span: (start, pos),
                rle: true,
                count,
                values: vec![value],
            });
        } else {
            let groups = header >> 1;
            let count = groups.saturating_mul(8);
            let len = to_usize(groups.saturating_mul(u64::from(width)));
            let packed = data.get(pos..pos.saturating_add(len)).unwrap_or_default();
            let mut values = Vec::new();
            let keep = count
                .min(want.saturating_sub(got))
                .min(MAX_UNPACK.saturating_sub(unpacked));
            unpacked = unpacked.saturating_add(keep);
            for i in 0..keep {
                if i % 4096 == 4095 {
                    cx.checkpoint().await;
                }
                let bit = i.saturating_mul(u64::from(width));
                let mut v = 0u64;
                for b in 0..u64::from(width) {
                    let at = bit.saturating_add(b);
                    let byte = packed.get(to_usize(at / 8)).copied().unwrap_or(0);
                    if byte >> (at % 8) & 1 != 0 {
                        v |= 1u64 << b.min(63);
                    }
                }
                values.push(v);
            }
            pos = pos.saturating_add(len);
            got = got.saturating_add(count);
            runs.push(Run {
                span: (start, pos.min(data.len())),
                rle: false,
                count,
                values,
            });
        }
    }
    (runs, pos.min(data.len()))
}

fn run_nodes(runs: &[Run], span: Span, base: usize) -> Vec<Node> {
    runs.iter()
        .map(|r| {
            let s = span.sub(
                to_u64(r.span.0.saturating_sub(base)),
                to_u64(r.span.1.saturating_sub(r.span.0)),
            );
            if r.rle {
                Node::new("RLE run")
                    .span(s)
                    .value(Value::UInt {
                        value: r.values.first().copied().unwrap_or(0),
                        bits: 64,
                        radix: Radix::Dec,
                    })
                    .summary(format!("repeated {} times", r.count))
            } else {
                let shown: Vec<String> = r.values.iter().take(32).map(u64::to_string).collect();
                Node::new("Bit-packed run")
                    .span(s)
                    .value(Value::Text(format!(
                        "{}{}",
                        shown.join(" "),
                        if r.count > 32 { " …" } else { "" }
                    )))
                    .summary(format!("{} values", r.count))
            }
        })
        .collect()
}

/// Levels of `max` stored as hybrid runs: nodes, how many equal `max`,
/// and the bytes used.
async fn levels(cx: &Cx, data: &[u8], span: Span, max: u32, want: u64) -> (Vec<Node>, u64, usize) {
    let (runs, used) = hybrid(cx, data, bit_width(max), want).await;
    let mut full = 0u64;
    let mut seen = 0u64;
    for r in &runs {
        if r.rle {
            let n = r.count.min(want.saturating_sub(seen));
            if r.values.first().copied() == Some(u64::from(max)) {
                full = full.saturating_add(n);
            }
            seen = seen.saturating_add(n);
        } else {
            for &v in &r.values {
                if seen >= want {
                    break;
                }
                if v == u64::from(max) {
                    full = full.saturating_add(1);
                }
                seen = seen.saturating_add(1);
            }
        }
    }
    (run_nodes(&runs, span, 0), full, used)
}

async fn levels_v2(cx: Cx, (c, info, span): (Col, PageInfo, Span)) -> Result<()> {
    let data = cx.read(span).await?;
    let rep = span.sub(0, info.rep_len);
    let def = span.sub(info.rep_len, info.def_len);
    if info.rep_len > 0 {
        let bytes = data.get(..to_usize(info.rep_len)).unwrap_or_default();
        let (nodes, _, _) = levels(&cx, bytes, rep, c.leaf.max_rep, info.num_values).await;
        cx.emit(group("Repetition levels", nodes).span(rep));
    }
    if info.def_len > 0 {
        let bytes = data.get(to_usize(info.rep_len)..).unwrap_or_default();
        let (nodes, _, _) = levels(&cx, bytes, def, c.leaf.max_def, info.num_values).await;
        cx.emit(group("Definition levels", nodes).span(def));
    }
    Ok(())
}

fn group(name: impl Into<std::borrow::Cow<'static, str>>, children: Vec<Node>) -> Node {
    Node::new(name).lazy(
        crate::formats::util::arcutil::push_nodes,
        Arc::new(children),
    )
}

/// The contents of a (decompressed) page: levels, then values.
async fn page_contents(cx: Cx, (c, info, span): (Col, PageInfo, Span)) -> Result<()> {
    if span.len > MAX_PAGE {
        cx.emit(Node::new("Values").span(span).summary("too large to show"));
        return Ok(());
    }
    let data = cx.read(span).await?;
    let mut pos = 0usize;
    let mut count = info.num_values;
    if info.kind == 2 {
        // Dictionary pages are PLAIN (old writers say PLAIN_DICTIONARY).
        return values(&cx, &c, 0, &data, span, 0, count).await;
    }
    if info.kind == 0 {
        // Data page v1: levels, each prefixed with its length.
        for (name, max) in [
            ("Repetition levels", c.leaf.max_rep),
            ("Definition levels", c.leaf.max_def),
        ] {
            if max == 0 {
                continue;
            }
            let len = to_usize(u32_le(&data, pos).unwrap_or(0).into());
            let body = data
                .get(pos.saturating_add(4)..pos.saturating_add(4).saturating_add(len))
                .unwrap_or_default();
            let lspan = span.sub(to_u64(pos), to_u64(len.saturating_add(4)));
            let (mut nodes, full, _) =
                levels(&cx, body, lspan.sub(4, to_u64(len)), max, info.num_values).await;
            nodes.insert(
                0,
                Node::new("Length")
                    .span(lspan.sub(0, 4))
                    .value(Value::UInt {
                        value: to_u64(len),
                        bits: 32,
                        radix: Radix::Dec,
                    }),
            );
            if name == "Definition levels" {
                count = full;
            }
            cx.emit(
                group(name, nodes)
                    .span(lspan)
                    .summary(format!("bit width {}", bit_width(max))),
            );
            pos = pos.saturating_add(4).saturating_add(len);
        }
    } else if let Some(nulls) = info.nulls {
        count = info.num_values.saturating_sub(nulls);
    }
    values(&cx, &c, info.encoding, &data, span, pos, count).await
}

/// Encoded values from `pos` to the end of the page.
async fn values(
    cx: &Cx,
    c: &Col,
    encoding: i64,
    data: &[u8],
    span: Span,
    pos: usize,
    count: u64,
) -> Result<()> {
    let rest = span.tail(to_u64(pos));
    let body = data.get(pos..).unwrap_or_default();
    match encoding {
        0 => {
            cx.emit(
                Node::new("Values")
                    .span(rest)
                    .summary(format!("{count} PLAIN values"))
                    .lazy(plain, (c.leaf.clone(), rest, count)),
            );
        }
        2 | 8 => {
            let width = u32::from(body.first().copied().unwrap_or(0)).min(32);
            let (runs, used) = hybrid(cx, body.get(1..).unwrap_or_default(), width, count).await;
            let mut nodes = vec![
                Node::new("Bit width")
                    .span(rest.sub(0, 1))
                    .value(Value::UInt {
                        value: width.into(),
                        bits: 8,
                        radix: Radix::Dec,
                    }),
            ];
            nodes.extend(run_nodes(&runs, rest.tail(1), 0));
            let end = to_u64(used).saturating_add(1);
            if rest.len > end {
                nodes.push(Node::new("Unused").span(rest.tail(end)));
            }
            cx.emit(
                group("Dictionary indices", nodes)
                    .span(rest)
                    .summary(format!("{count} values, {} runs", runs.len())),
            );
        }
        3 if c.leaf.phys == 0 => {
            let len = to_usize(u32_le(body, 0).unwrap_or(0).into());
            let (runs, _) = hybrid(
                cx,
                body.get(4..4usize.saturating_add(len)).unwrap_or_default(),
                1,
                count,
            )
            .await;
            let mut nodes = vec![Node::new("Length").span(rest.sub(0, 4)).value(Value::UInt {
                value: to_u64(len),
                bits: 32,
                radix: Radix::Dec,
            })];
            nodes.extend(run_nodes(&runs, rest.tail(4), 0));
            cx.emit(group("Values", nodes).span(rest).summary("RLE booleans"));
        }
        9 if byte_stream_split_width(&c.leaf).is_some() => {
            // BYTE_STREAM_SPLIT: the k-th bytes of all values, then the
            // next plane; un-split, the values are PLAIN.
            let width = byte_stream_split_width(&c.leaf).unwrap_or(1);
            let planes = rest.sub(0, count.saturating_mul(width));
            let codec = Codec::Unshuffle {
                width: to_usize(width),
            };
            let decoded = cx.decode_lazy(planes, &codec, planes.len)?;
            cx.emit(
                Node::new("Values")
                    .span(planes)
                    .summary(format!("{count} BYTE_STREAM_SPLIT values"))
                    .lazy(plain, (c.leaf.clone(), decoded, count)),
            );
        }
        e => {
            cx.emit(
                Node::new("Values")
                    .span(rest)
                    .summary(format!(
                        "{count} values, {}",
                        lookup(ENCODINGS, e.cast_unsigned()).unwrap_or("unknown encoding")
                    ))
                    .diag(Diagnostic::unsupported("this encoding is not decoded")),
            );
        }
    }
    Ok(())
}

/// The value width BYTE_STREAM_SPLIT splits into planes: INT32, INT64,
/// FLOAT, DOUBLE and FIXED_LEN_BYTE_ARRAY.
fn byte_stream_split_width(leaf: &Leaf) -> Option<u64> {
    match leaf.phys {
        1 | 4 => Some(4),
        2 | 5 => Some(8),
        7 => u64::try_from(leaf.type_length).ok().filter(|&w| w > 0),
        _ => None,
    }
}

/// PLAIN values of a column's physical type.
async fn plain(cx: Cx, (leaf, span, count): (Leaf, Span, u64)) -> Result<()> {
    let width: Option<u64> = match leaf.phys {
        1 | 4 => Some(4),
        2 | 5 => Some(8),
        3 => Some(12),
        7 => u64::try_from(leaf.type_length).ok().filter(|&w| w > 0),
        _ => None,
    };
    cx.set_count(Count::Exact(count));
    if leaf.phys == 0 {
        // Booleans: one bit each.
        let data = cx.read_avail(span.sub(0, count.div_ceil(8))).await?;
        for i in 0..count {
            let byte = data.get(to_usize(i / 8)).copied().unwrap_or(0);
            cx.push(
                Node::new(format!("[{i}]"))
                    .span(span.sub(i / 8, 1))
                    .value(Value::Bool(byte >> (i % 8) & 1 != 0)),
            )
            .await;
        }
        return Ok(());
    }
    if let Some(w) = width {
        let per = WINDOW.checked_div(w).unwrap_or(1).max(1);
        let n = count.min(span.len.checked_div(w).unwrap_or(0));
        let mut i = 0u64;
        while i < n {
            let k = per.min(n.saturating_sub(i));
            let window = span.sub(i.saturating_mul(w), k.saturating_mul(w));
            let data = cx.read(window).await?;
            for (j, chunk) in data.chunks_exact(to_usize(w)).enumerate() {
                let index = i.saturating_add(to_u64(j));
                cx.push(
                    Node::new(format!("[{index}]"))
                        .span(window.sub(to_u64(j).saturating_mul(w), w))
                        .value(typed(leaf.phys, chunk)),
                )
                .await;
            }
            i = i.saturating_add(k);
        }
        return Ok(());
    }
    // BYTE_ARRAY: a 4-byte length, then the bytes.
    let mut pos = 0u64;
    for i in 0..count {
        let head = cx.read_avail(span.sub(pos, 4)).await?;
        let Some(len) = u32_le(&head, 0) else {
            break;
        };
        let item = span.sub(pos, 4u64.saturating_add(len.into()));
        let bytes = cx.read_avail(item.sub(4, u64::from(len).min(4096))).await?;
        cx.push(
            Node::new(format!("[{i}]"))
                .span(item)
                .value(typed(6, &bytes))
                .summary(format!("{len} bytes")),
        )
        .await;
        pos = pos.saturating_add(item.len.max(1));
        if pos >= span.len {
            break;
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Bloom filters and the page index

async fn bloom_filters(cx: Cx, ctx: Ctx) -> Result<()> {
    for c in &ctx.meta.cols {
        let Some((off, len)) = c.bloom else {
            continue;
        };
        let Ok(off) = u64::try_from(off) else {
            continue;
        };
        // The header is Thrift; the bitset follows (its size is numBytes).
        let window = ctx.input.span.sub(off, 256);
        let head = Arc::new(cx.read_avail(window).await?);
        let end = skip(&head, 0, 12, 0).unwrap_or(0);
        let mut num_bytes = 0u64;
        if let Some((1, t, next)) = field_header(&head, 0, 0) {
            num_bytes = u64::try_from(int_at(&head, next, t).unwrap_or(0)).unwrap_or(0);
        }
        let total = len
            .and_then(|l| u64::try_from(l).ok())
            .unwrap_or_else(|| to_u64(end).saturating_add(num_bytes));
        let state = ThriftState {
            buf: Buf::new(head.clone(), window),
            at: 0,
            def: &BLOOM_FILTER_HEADER,
            depth: 0,
            file: ctx.input,
            phys: None,
        };
        let header = value_node(
            &cx,
            "BloomFilterHeader".to_owned(),
            &state,
            0,
            12,
            Kind::Struct(&BLOOM_FILTER_HEADER),
        )
        .await;
        let bitset = ctx
            .input
            .span
            .sub(off.saturating_add(to_u64(end)), num_bytes);
        let children = vec![
            header,
            Node::new("Bitset").span(bitset).summary(format!(
                "{} blocks of 256 bits (split block, xxHash64)",
                num_bytes / 32
            )),
        ];
        cx.push(
            group(format!("{} (row group {})", c.leaf.path, c.group), children)
                .span(ctx.input.span.sub(off, total))
                .summary(crate::formats::util::fmt::size(total)),
        )
        .await;
    }
    Ok(())
}

async fn page_index(cx: Cx, ctx: Ctx) -> Result<()> {
    for c in &ctx.meta.cols {
        for (index, def, label) in [
            (c.column_index, &COLUMN_INDEX, "column index"),
            (c.offset_index, &OFFSET_INDEX, "offset index"),
        ] {
            let Some((off, len)) = index else {
                continue;
            };
            let (Ok(off), Ok(len)) = (u64::try_from(off), u64::try_from(len)) else {
                continue;
            };
            let span = ctx.input.span.sub(off, len.min(MAX_FOOTER));
            let data = Arc::new(cx.read(span).await?);
            let state = ThriftState {
                buf: Buf::new(data, span),
                at: 0,
                def,
                depth: 0,
                file: ctx.input,
                phys: Some(c.leaf.phys),
            };
            let node = value_node(
                &cx,
                format!("{} {label} (row group {})", c.leaf.path, c.group),
                &state,
                0,
                12,
                Kind::Struct(def),
            )
            .await;
            cx.push(node).await;
        }
    }
    Ok(())
}
