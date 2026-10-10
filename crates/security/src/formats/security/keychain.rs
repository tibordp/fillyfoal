//! macOS keychains (`.keychain`, `.keychain-db`): Apple's CSSM data store
//! (`AppleDatabase` in Security.framework), a self-describing set of tables.
//! Layout reverse-engineered by others (chainbreaker and Apple's open-source
//! `AppleDatabase.cpp`, from memory) and checked against a keychain written
//! by `security create-keychain`; all integers big-endian.
//!
//! ```text
//! header: "kych", version, header size, schema offset, auth offset
//! schema: size, table count, table offsets (from the schema)
//! table: size, relation ID, record count, records offset, indexes
//!        offset, free list head, record slot count, slots (offsets from the
//!        table; 0 or odd = free)
//! record: size, number, create version, record version, data size,
//!         semantic info, one attribute offset per schema attribute (offset
//!         + 1 from the record, 0 = absent), the data, the attribute values
//! ```
//!
//! The schema is itself stored as tables: `CSSM_DL_DB_SCHEMA_ATTRIBUTES`
//! (relation 2) lists every relation's attributes in record order with their
//! formats, which is how records are decoded here. Item secrets stay
//! encrypted: password items hold an `ssgp` blob (3DES-CBC under a per-item
//! key, itself wrapped by the database key, which the keychain password
//! unlocks through the metadata `DbBlob`); certificates are stored in clear
//! and are dissected as X.509.

use std::collections::BTreeMap;
use std::sync::Arc;

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::fmt::plural;
use crate::formats::util::fmt::{fourcc, uuid};
use crate::formats::{Input, Probe, embedded_as};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

declare_format!(pub KEYCHAIN = "keychain", "macOS keychain", ["keychain", "keychain-db"], "application/x-apple-keychain",
    Probe::Magic(&[(0, b"kych")]), dissect);

const BE: Endian = Endian::Big;

record! {
    pub struct Header {
        magic: ascii[4] "Magic",
        version: u32 "Version" .hex(),
        header_size: u32 "Header size",
        schema_offset: u32 "Schema offset" .hex(),
        auth_offset: u32 "Auth offset" .hex(),
    }
}

record! {
    pub struct TableHeader {
        size: u32 "Table size" .hex(),
        relation: u32 "Relation ID" .hex() .enumeration(RELATIONS),
        records: u32 "Record count",
        records_offset: u32 "Records offset" .hex(),
        indexes_offset: u32 "Indexes offset" .hex(),
        free_list: u32 "Free list head" .hex(),
        slots: u32 "Record slots",
    }
}

record! {
    pub struct RecordHeader {
        size: u32 "Record size" .hex(),
        number: u32 "Record number",
        create_version: u32 "Create version",
        record_version: u32 "Record version",
        data_size: u32 "Data size",
        semantic: u32 "Semantic information" .hex(),
    }
}

/// CSSM record types (`CSSM_DL_DB_RECORD_*`, `CSSM_DL_DB_SCHEMA_*`).
const RELATIONS: EnumTable = &[
    (0x0, "CSSM_DL_DB_SCHEMA_INFO"),
    (0x1, "CSSM_DL_DB_SCHEMA_INDEXES"),
    (0x2, "CSSM_DL_DB_SCHEMA_ATTRIBUTES"),
    (0x3, "CSSM_DL_DB_SCHEMA_PARSING_MODULE"),
    (0xa, "CSSM_DL_DB_RECORD_ANY"),
    (0xb, "CSSM_DL_DB_RECORD_CERT"),
    (0xc, "CSSM_DL_DB_RECORD_CRL"),
    (0xd, "CSSM_DL_DB_RECORD_POLICY"),
    (0xe, "CSSM_DL_DB_RECORD_GENERIC"),
    (0xf, "CSSM_DL_DB_RECORD_PUBLIC_KEY"),
    (0x10, "CSSM_DL_DB_RECORD_PRIVATE_KEY"),
    (0x11, "CSSM_DL_DB_RECORD_SYMMETRIC_KEY"),
    (0x12, "CSSM_DL_DB_RECORD_ALL_KEYS"),
    (0x8000_0000, "CSSM_DL_DB_RECORD_GENERIC_PASSWORD"),
    (0x8000_0001, "CSSM_DL_DB_RECORD_INTERNET_PASSWORD"),
    (0x8000_0002, "CSSM_DL_DB_RECORD_APPLESHARE_PASSWORD"),
    (0x8000_0003, "CSSM_DL_DB_RECORD_USER_TRUST"),
    (0x8000_0004, "CSSM_DL_DB_RECORD_X509_CRL"),
    (0x8000_0005, "CSSM_DL_DB_RECORD_UNLOCK_REFERRAL"),
    (0x8000_0006, "CSSM_DL_DB_RECORD_EXTENDED_ATTRIBUTE"),
    (0x8000_1000, "CSSM_DL_DB_RECORD_X509_CERTIFICATE"),
    (0x8000_8000, "CSSM_DL_DB_RECORD_METADATA"),
];

/// Human names of the tables.
fn table_title(relation: u32) -> String {
    let title = match relation {
        0x0 => "Schema: relations",
        0x1 => "Schema: indexes",
        0x2 => "Schema: attributes",
        0x3 => "Schema: parsing modules",
        0xb => "Certificates (CSSM)",
        0xc => "CRLs (CSSM)",
        0xf => "Public keys",
        0x10 => "Private keys",
        0x11 => "Symmetric keys",
        0x8000_0000 => "Generic passwords",
        0x8000_0001 => "Internet passwords",
        0x8000_0002 => "AppleShare passwords",
        0x8000_0003 => "User trust",
        0x8000_0004 => "X.509 CRLs",
        0x8000_0005 => "Unlock referrals",
        0x8000_0006 => "Extended attributes",
        0x8000_1000 => "X.509 certificates",
        0x8000_8000 => "Metadata",
        _ => return format!("Relation {relation:#x}"),
    };
    title.to_owned()
}

/// `CSSM_DB_ATTRIBUTE_FORMAT_*`.
const FORMATS: EnumTable = &[
    (0, "string"),
    (1, "sint32"),
    (2, "uint32"),
    (3, "big number"),
    (4, "real"),
    (5, "time/date"),
    (6, "blob"),
    (7, "multi uint32"),
    (8, "complex"),
];

/// Display names of the four-character attribute IDs.
fn attribute_title(id: u32) -> Option<&'static str> {
    Some(match &id.to_be_bytes() {
        b"cdat" => "Creation date",
        b"mdat" => "Modification date",
        b"desc" => "Description",
        b"icmt" => "Comment",
        b"crtr" => "Creator",
        b"type" => "Type",
        b"scrp" => "Script code",
        b"invi" => "Invisible",
        b"nega" => "Negative",
        b"cusi" => "Custom icon",
        b"prot" => "Protected",
        b"acct" => "Account",
        b"svce" => "Service",
        b"gena" => "Generic",
        b"sdmn" => "Security domain",
        b"srvr" => "Server",
        b"ptcl" => "Protocol",
        b"atyp" => "Authentication type",
        b"port" => "Port",
        b"path" => "Path",
        b"vlme" => "Volume",
        b"addr" => "Address",
        b"ssig" => "Signature",
        _ => return None,
    })
}

/// One attribute of a relation.
#[derive(Clone, Debug)]
struct Attribute {
    /// The attribute's name (its string name or four-character ID).
    name: String,
    /// The attribute ID.
    id: u32,
    format: u32,
}

/// The decoded schema: relation names and their attributes, in order.
#[derive(Default, Debug)]
struct Schema {
    tables: Vec<(u32, Span)>,
    attributes: BTreeMap<u32, Vec<Attribute>>,
    names: BTreeMap<u32, String>,
}

/// The attributes of the attributes relation itself (the bootstrap).
fn bootstrap() -> Vec<Attribute> {
    let a = |name: &str, format: u32| Attribute {
        name: name.to_owned(),
        id: 0,
        format,
    };
    vec![
        a("RelationID", 2),
        a("AttributeID", 2),
        a("AttributeNameFormat", 2),
        a("AttributeName", 0),
        a("AttributeNameID", 6),
        a("AttributeFormat", 2),
    ]
}

/// The most records or tables decoded.
const MAX_RECORDS: u32 = 1 << 20;
const MAX_TABLES: u32 = 4096;

/// Reads a table header and its slot array; returns the record spans.
async fn table_records(cx: &Cx, table: Span) -> Result<(TableHeader, Vec<u32>)> {
    let h: TableHeader = read_record(cx, table.sub(0, TableHeader::SIZE), BE).await?;
    let slots = h.slots.min(MAX_RECORDS);
    let raw = cx
        .read(table.sub_exact(TableHeader::SIZE, u64::from(slots).saturating_mul(4))?)
        .await?;
    let offsets = raw
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .collect();
    Ok((h, offsets))
}

/// Whether a slot holds a record.
fn live(offset: u32) -> bool {
    offset != 0 && offset.trailing_zeros() >= 2
}

/// A record within its table, if its size is sane.
async fn record_span(cx: &Cx, table: Span, offset: u32) -> Result<Span> {
    let head = cx.read(table.sub_exact(offset.into(), 4)?).await?;
    let size = u32_be(&head, 0).unwrap_or(0);
    if u64::from(size) < RecordHeader::SIZE {
        return Err(
            Diagnostic::malformed("record smaller than its header").at(table.sub(offset.into(), 4))
        );
    }
    Ok(table.sub(offset.into(), size.into()))
}

/// A decoded attribute value with the span it came from.
struct AttrValue {
    span: Span,
    raw: Vec<u8>,
    uint: Option<u32>,
}

/// Decodes attribute `i` (format `format`) of a record held in `bytes`.
fn attribute(
    bytes: &[u8],
    record: Span,
    attributes: usize,
    i: usize,
    format: u32,
) -> Option<AttrValue> {
    let slot = 24usize.checked_add(i.checked_mul(4)?)?;
    let offset = u32_be(bytes, slot)?;
    if offset == 0 {
        return None;
    }
    let at = crate::bytes::to_usize(offset.saturating_sub(1).into());
    // Values follow the offsets array.
    if at < 24usize.saturating_add(attributes.saturating_mul(4)) {
        return None;
    }
    let (len, raw_at) = match format {
        1 | 2 => (4usize, at),
        5 => (16, at),
        4 => (8, at),
        7 => {
            let n = crate::bytes::to_usize(u32_be(bytes, at)?.into());
            (n.checked_mul(4)?.checked_add(4)?, at)
        }
        _ => (
            crate::bytes::to_usize(u32_be(bytes, at)?.into()),
            at.saturating_add(4),
        ),
    };
    let raw = bytes.get(raw_at..raw_at.checked_add(len)?)?.to_vec();
    let total = raw_at.saturating_sub(at).saturating_add(len);
    Some(AttrValue {
        span: record.sub(crate::bytes::to_u64(at), crate::bytes::to_u64(total)),
        uint: if matches!(format, 1 | 2) {
            u32_be(&raw, 0)
        } else {
            None
        },
        raw,
    })
}

/// Text without its terminating NUL, if it is all printable.
fn printable(b: &[u8]) -> Option<String> {
    let b = b.strip_suffix(b"\0").unwrap_or(b);
    let s = std::str::from_utf8(b).ok()?;
    (!s.is_empty() && s.chars().all(|c| !c.is_control())).then(|| s.to_owned())
}

/// `v` as a four-character code, if all four bytes are printable.
fn four_cc(v: u32) -> Option<String> {
    let b = v.to_be_bytes();
    b.iter()
        .all(|c| c.is_ascii_graphic() || *c == b' ')
        .then(|| fourcc(&b))
}

async fn schema(cx: &Cx, file: Span, h: &Header) -> Result<Arc<Schema>> {
    if let Some(s) = cx.cached::<Schema>(file, "keychain-schema") {
        return Ok(s);
    }
    let base = file.tail(h.schema_offset.into());
    let head = cx.read(base.sub_exact(0, 8)?).await?;
    let count = u32_be(&head, 4).unwrap_or(0).min(MAX_TABLES);
    let raw = cx
        .read(base.sub_exact(8, u64::from(count).saturating_mul(4))?)
        .await?;
    let mut schema = Schema::default();
    for off in raw
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
    {
        let table = base.tail(off.into());
        let Ok(sub) = table.sub_exact(0, 8) else {
            continue;
        };
        let Ok(head) = cx.read(sub).await else {
            continue;
        };
        let size = u32_be(&head, 0).unwrap_or(0);
        let relation = u32_be(&head, 4).unwrap_or(0);
        schema.tables.push((relation, table.sub(0, size.into())));
    }
    // Relation names (SCHEMA_INFO) and attributes (SCHEMA_ATTRIBUTES).
    let info_layout = [
        Attribute {
            name: "RelationID".to_owned(),
            id: 0,
            format: 2,
        },
        Attribute {
            name: "RelationName".to_owned(),
            id: 1,
            format: 0,
        },
    ];
    let boot = bootstrap();
    let tables = schema.tables.clone();
    for (relation, table) in tables {
        let layout: &[Attribute] = match relation {
            0 => &info_layout,
            2 => &boot,
            _ => continue,
        };
        let (_, slots) = table_records(cx, table).await?;
        for (n, off) in slots.into_iter().enumerate() {
            if n.is_multiple_of(256) {
                cx.checkpoint().await;
            }
            if !live(off) {
                continue;
            }
            let Ok(rec) = record_span(cx, table, off).await else {
                continue;
            };
            let bytes = cx.read_avail(rec).await?;
            let get = |i: usize| {
                attribute(
                    &bytes,
                    rec,
                    layout.len(),
                    i,
                    layout.get(i).map_or(6, |a| a.format),
                )
            };
            let rel = get(0).and_then(|v| v.uint).unwrap_or(u32::MAX);
            if relation == 0 {
                if let Some(name) = get(1).and_then(|v| printable(&v.raw)) {
                    schema.names.insert(rel, name);
                }
                continue;
            }
            let id = get(1).and_then(|v| v.uint).unwrap_or(0);
            let format = get(5).and_then(|v| v.uint).unwrap_or(6);
            let name = get(3)
                .and_then(|v| printable(&v.raw))
                .or_else(|| four_cc(id))
                .unwrap_or_else(|| format!("{id:#x}"));
            let list = schema.attributes.entry(rel).or_default();
            if list.len() < 256 {
                list.push(Attribute { name, id, format });
            }
        }
    }
    let schema = Arc::new(schema);
    cx.cache(file, "keychain-schema", schema.clone());
    Ok(schema)
}

#[derive(Clone, Copy)]
struct TableState {
    input: Input,
    header: Span,
    table: Span,
    relation: u32,
}

#[derive(Clone, Copy)]
struct RecordState {
    input: Input,
    header: Span,
    record: Span,
    relation: u32,
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h: Header = read_record(&cx, header_span, BE).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let base = file.tail(h.schema_offset.into());
    let head = cx.read(base.sub_exact(0, 8)?).await?;
    let count = u32_be(&head, 4).unwrap_or(0);
    cx.emit(
        Node::new("Schema")
            .span(
                base.sub(
                    0,
                    u64::from(count.min(MAX_TABLES))
                        .saturating_mul(4)
                        .saturating_add(8),
                ),
            )
            .summary(format!("{count} tables"))
            .lazy(schema_header, base),
    );
    let s = schema(&cx, file, &h).await?;
    let mut counts: BTreeMap<u32, u32> = BTreeMap::new();
    for &(relation, table) in &s.tables {
        let records = match table_records(&cx, table).await {
            Ok((th, _)) => th.records,
            Err(e) => {
                cx.push(Node::new(table_title(relation)).span(table).diag(e))
                    .await;
                continue;
            }
        };
        counts.insert(relation, records);
        let rel_name = s
            .names
            .get(&relation)
            .filter(|n| !n.is_empty())
            .cloned()
            .or_else(|| lookup(RELATIONS, relation.into()).map(str::to_owned));
        let mut node = Node::new(table_title(relation))
            .span(table)
            .summary(plural(records, "record"))
            .lazy(
                self::table,
                TableState {
                    input,
                    header: header_span,
                    table,
                    relation,
                },
            );
        if let Some(n) = rel_name {
            node = node.desc(n);
        }
        cx.push(node).await;
    }
    let n = |r: u32| counts.get(&r).copied().unwrap_or(0);
    let passwords = n(0x8000_0000)
        .saturating_add(n(0x8000_0001))
        .saturating_add(n(0x8000_0002));
    let keys = n(0xf).saturating_add(n(0x10)).saturating_add(n(0x11));
    cx.annotate(format!(
        "macOS keychain, {passwords} password{} ({} generic, {} internet), {} certificate{}, {keys} key{}",
        if passwords == 1 { "" } else { "s" },
        n(0x8000_0000),
        n(0x8000_0001),
        n(0x8000_1000),
        if n(0x8000_1000) == 1 { "" } else { "s" },
        if keys == 1 { "" } else { "s" },
    ));
    Ok(())
}

async fn schema_header(cx: Cx, base: Span) -> Result<()> {
    let head = cx.block(base.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Schema size").hex().emit()?;
    let count = f.u32("Table count").emit()?;
    let n = count.min(MAX_TABLES);
    let raw = cx
        .read(base.sub_exact(8, u64::from(n).saturating_mul(4))?)
        .await?;
    for (i, off) in raw
        .as_chunks::<4>()
        .0
        .iter()
        .map(|c| u32::from_be_bytes(*c))
        .enumerate()
    {
        cx.push(
            Node::new(format!("Table {i}"))
                .span(base.sub(
                    crate::bytes::to_u64(i).saturating_mul(4).saturating_add(8),
                    4,
                ))
                .value(Value::UInt {
                    value: off.into(),
                    bits: 32,
                    radix: Radix::Hex,
                })
                .target(base.tail(off.into()).sub(0, TableHeader::SIZE)),
        )
        .await;
    }
    Ok(())
}

/// A record's display name and summary, from its attributes.
fn describe(relation: u32, attrs: &[(String, Option<AttrValue>)], number: u32) -> (String, String) {
    let text = |key: &str| {
        attrs
            .iter()
            .find(|(n, _)| n == key)
            .and_then(|(_, v)| v.as_ref())
            .and_then(|v| printable(&v.raw))
    };
    let name = text("PrintName")
        .or_else(|| text("svce"))
        .or_else(|| text("srvr"))
        .or_else(|| text("RelationName").filter(|_| relation == 0))
        .or_else(|| text("AttributeName"))
        .unwrap_or_else(|| format!("Record {number}"));
    let mut parts = Vec::new();
    for (key, label) in [
        ("acct", "account"),
        ("svce", "service"),
        ("srvr", "server"),
        ("path", "path"),
    ] {
        if let Some(v) = text(key) {
            parts.push(format!("{label} {v}"));
        }
    }
    (name, parts.join(", "))
}

fn attr_list(schema: &Schema, relation: u32) -> Vec<Attribute> {
    match relation {
        2 => bootstrap(),
        _ => schema
            .attributes
            .get(&relation)
            .cloned()
            .unwrap_or_default(),
    }
}

async fn table(cx: Cx, t: TableState) -> Result<()> {
    let h: Header = read_record(&cx, t.header, BE).await?;
    let s = schema(&cx, t.input.span, &h).await?;
    let attrs = attr_list(&s, t.relation);
    let (th, slots) = table_records(&cx, t.table).await?;
    let mut index = cx.resume::<usize>().unwrap_or(0);
    if index == 0 {
        cx.push(TableHeader::node(
            "Table header",
            t.table.sub(0, TableHeader::SIZE),
            BE,
        ))
        .await;
        index = 1;
    }
    // Index 0 is the header; slots follow.
    while let Some(&off) = slots.get(index.saturating_sub(1)) {
        let at = index;
        cx.mark(move || at);
        index = index.saturating_add(1);
        if !live(off) {
            cx.checkpoint().await;
            continue;
        }
        let rec = match record_span(&cx, t.table, off).await {
            Ok(r) => r,
            Err(e) => {
                cx.push(Node::new("Record").span(t.table.sub(off.into(), 4)).diag(e))
                    .await;
                continue;
            }
        };
        if cx.skipping() {
            cx.push(Node::new("Record")).await;
            continue;
        }
        let bytes = cx.read_avail(rec).await?;
        let number = u32_be(&bytes, 4).unwrap_or(0);
        let values: Vec<(String, Option<AttrValue>)> = attrs
            .iter()
            .enumerate()
            .map(|(i, a)| {
                (
                    a.name.clone(),
                    attribute(&bytes, rec, attrs.len(), i, a.format),
                )
            })
            .collect();
        let (name, summary) = describe(t.relation, &values, number);
        let mut node = Node::new(name).span(rec).lazy(
            record,
            RecordState {
                input: t.input,
                header: t.header,
                record: rec,
                relation: t.relation,
            },
        );
        if !summary.is_empty() {
            node = node.summary(summary);
        }
        cx.push(node).await;
    }
    if th.indexes_offset != 0 && th.indexes_offset < th.size {
        cx.push(
            Node::new("Indexes")
                .span(t.table.sub(
                    th.indexes_offset.into(),
                    u64::from(th.size.saturating_sub(th.indexes_offset)),
                ))
                .summary("index data (not decoded)"),
        )
        .await;
    }
    Ok(())
}

fn value_node(a: &Attribute, v: AttrValue) -> Node {
    let title = attribute_title(a.id)
        .filter(|_| a.name.len() == 4)
        .map_or_else(|| a.name.clone(), |t| format!("{t} ({})", a.name));
    let node = Node::new(title).span(v.span);
    match a.format {
        1 => node.value(Value::Int {
            value: i64::from(v.uint.unwrap_or(0).cast_signed()),
            bits: 32,
        }),
        2 if matches!(a.name.as_str(), "RelationID" | "KeyClass" | "KeyType") => {
            let raw = v.uint.unwrap_or(0);
            let table = if a.name == "KeyType" {
                ALGORITHMS
            } else {
                RELATIONS
            };
            node.value(Value::Enum {
                raw: raw.into(),
                bits: 32,
                name: lookup(table, raw.into()),
            })
        }
        2 => {
            let raw = v.uint.unwrap_or(0);
            match four_cc(raw).filter(|_| raw > 0x2000_0000) {
                Some(cc) => node.value(Value::Text(cc)).summary(format!("{raw:#010x}")),
                None => node.value(Value::UInt {
                    value: raw.into(),
                    bits: 32,
                    radix: Radix::Dec,
                }),
            }
        }
        4 => node.value(Value::Float(f64::from_bits(
            crate::bytes::u64_be(&v.raw, 0).unwrap_or(0),
        ))),
        5 => {
            let text = crate::text::until_nul(&v.raw);
            match crate::formats::asn1::der::time(24, text.as_bytes()) {
                Some(t) => node.value(Value::Timestamp { unix_seconds: t }),
                None => node.value(Value::Bytes(v.raw)),
            }
        }
        7 => {
            let list: Vec<String> = v
                .raw
                .as_chunks::<4>()
                .0
                .iter()
                .skip(1)
                .map(|c| u32::from_be_bytes(*c).to_string())
                .collect();
            node.value(Value::Text(list.join(", ")))
        }
        _ => match printable(&v.raw) {
            Some(s) => node.value(Value::Text(s)),
            None if v.raw.is_empty() => node.summary("empty"),
            None => {
                let len = v.raw.len();
                node.value(Value::Bytes(v.raw.into_iter().take(64).collect()))
                    .summary(format!("{len} bytes"))
            }
        },
    }
}

async fn record(cx: Cx, r: RecordState) -> Result<()> {
    let h: Header = read_record(&cx, r.header, BE).await?;
    let s = schema(&cx, r.input.span, &h).await?;
    let attrs = attr_list(&s, r.relation);
    let rh: RecordHeader = read_record(&cx, r.record.sub(0, RecordHeader::SIZE), BE).await?;
    cx.emit(RecordHeader::node(
        "Record header",
        r.record.sub(0, RecordHeader::SIZE),
        BE,
    ));
    let bytes = cx.read_avail(r.record).await?;
    let offsets_len = crate::bytes::to_u64(attrs.len()).saturating_mul(4);
    if !attrs.is_empty() {
        cx.emit(
            Node::new("Attribute offsets")
                .span(r.record.sub(RecordHeader::SIZE, offsets_len))
                .summary(format!("{} attributes", attrs.len())),
        );
    }
    for (i, a) in attrs.iter().enumerate() {
        if let Some(v) = attribute(&bytes, r.record, attrs.len(), i, a.format) {
            let mut node = value_node(a, v);
            if a.format > 6 || lookup(FORMATS, a.format.into()).is_none() {
                node = node.desc(format!("format {}", a.format));
            }
            cx.emit(node);
        }
    }
    if rh.data_size > 0 {
        let data = r.record.sub(
            RecordHeader::SIZE.saturating_add(offsets_len),
            rh.data_size.into(),
        );
        cx.emit(data_node(r, data));
    }
    Ok(())
}

/// The record's data, by relation.
fn data_node(r: RecordState, data: Span) -> Node {
    match r.relation {
        0x8000_0000..=0x8000_0002 => Node::new("Password data (ssgp)")
            .span(data)
            .summary("encrypted")
            .lazy(ssgp, data),
        0x8000_1000 => embedded_as(
            "Certificate",
            r.input.nested(data),
            &crate::formats::asn1::X509,
        ),
        0xf..=0x11 => Node::new("Key blob").span(data).lazy(key_blob, data),
        0x8000_8000 => Node::new("Database blob").span(data).lazy(db_blob, data),
        _ => Node::new("Data").span(data),
    }
}

async fn ssgp(cx: Cx, data: Span) -> Result<()> {
    let bytes = cx.read_avail(data.sub(0, 28)).await?;
    if bytes.get(..4) != Some(b"ssgp") {
        cx.emit(
            Node::new("Data")
                .span(data)
                .diag(Diagnostic::unsupported("not an ssgp blob")),
        );
        return Ok(());
    }
    cx.emit(
        Node::new("Magic")
            .span(data.sub(0, 4))
            .value(Value::Text("ssgp".to_owned())),
    );
    cx.emit(
        Node::new("Key label")
            .span(data.sub(0, 20))
            .value(Value::Bytes(bytes.get(..20).unwrap_or_default().to_vec()))
            .desc("the Label of the symmetric key record that encrypts this item"),
    );
    cx.emit(
        Node::new("IV")
            .span(data.sub(20, 8))
            .value(Value::Bytes(bytes.get(20..28).unwrap_or_default().to_vec())),
    );
    cx.emit(
        Node::new("Encrypted secret")
            .span(data.tail(28))
            .summary(format!("{} bytes, 3DES-CBC", data.len.saturating_sub(28)))
            .diag(Diagnostic::note(
                "encrypted with the item key (needs the keychain password)",
            )),
    );
    Ok(())
}

/// `CSSM_ALGORITHMS` values seen in keychains.
const ALGORITHMS: EnumTable = &[
    (0, "none"),
    (14, "DES"),
    (17, "3DES (3-key EDE)"),
    (42, "RSA"),
    (43, "DSA"),
    (73, "ECDSA"),
    (0x8000_0001, "AES"),
];

const KEY_CLASSES: EnumTable = &[(0, "public"), (1, "private"), (2, "session (symmetric)")];

async fn key_blob(cx: Cx, data: Span) -> Result<()> {
    let head = cx.block(data.sub(0, 24 + 76)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Magic").hex().emit()?;
    f.u32("Blob version").hex().emit()?;
    let start = f.u32("Start of encrypted data").hex().emit()?;
    let total = f.u32("Total length").emit()?;
    f.bytes("IV", 8).emit()?;
    f.u32("Header version").emit()?;
    f.bytes("CSP ID", 16)
        .with(|v, node| node.value(Value::Text(uuid(v))))
        .emit()?;
    f.u32("Blob type").emit()?;
    f.u32("Format").emit()?;
    let alg = f.u32("Algorithm").enumeration(ALGORITHMS).emit()?;
    f.u32("Key class").enumeration(KEY_CLASSES).emit()?;
    let bits = f.u32("Logical key size").emit()?;
    f.u32("Key attributes").hex().emit()?;
    f.u32("Key usage").hex().emit()?;
    f.bytes("Start date", 8).emit()?;
    f.bytes("End date", 8).emit()?;
    f.u32("Wrap algorithm").enumeration(ALGORITHMS).emit()?;
    f.u32("Wrap mode").emit()?;
    f.u32("Reserved").emit()?;
    if start > 24 + 76 && start < total {
        cx.emit(
            Node::new("Access control")
                .span(data.sub(24 + 76, u64::from(start).saturating_sub(24 + 76)))
                .summary("ACL (not decoded)"),
        );
    }
    if start < total {
        cx.emit(
            Node::new("Wrapped key")
                .span(data.sub(start.into(), u64::from(total.saturating_sub(start))))
                .summary(format!(
                    "{} bytes, {}-bit {}",
                    total.saturating_sub(start),
                    bits,
                    lookup(ALGORITHMS, alg.into()).unwrap_or("key")
                ))
                .diag(Diagnostic::note(
                    "wrapped with the database key (needs the keychain password)",
                )),
        );
    }
    Ok(())
}

async fn db_blob(cx: Cx, data: Span) -> Result<()> {
    let head = cx.block(data.sub(0, 92)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u32("Magic").hex().emit()?;
    f.u32("Blob version").hex().emit()?;
    let start = f.u32("Start of encrypted data").hex().emit()?;
    let total = f.u32("Total length").emit()?;
    f.bytes("Random signature", 16).emit()?;
    f.u32("Sequence").emit()?;
    f.u32("Idle timeout")
        .desc("seconds before the keychain locks")
        .emit()?;
    f.u8("Lock on sleep").emit()?;
    f.bytes("Padding", 3).emit()?;
    f.bytes("Salt", 20)
        .desc("PBKDF2-SHA1 salt for the keychain password")
        .emit()?;
    f.bytes("IV", 8).emit()?;
    f.bytes("Blob signature", 20).emit()?;
    if start > 92 && start < total {
        cx.emit(
            Node::new("Access control")
                .span(data.sub(92, u64::from(start).saturating_sub(92)))
                .summary("ACL (not decoded)"),
        );
    }
    if start < total {
        cx.emit(
            Node::new("Encrypted database keys")
                .span(data.sub(start.into(), u64::from(total.saturating_sub(start))))
                .summary("3DES-CBC under the password-derived master key")
                .diag(Diagnostic::note("needs the keychain password")),
        );
    }
    Ok(())
}
