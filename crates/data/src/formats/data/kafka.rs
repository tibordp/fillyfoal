//! Apache Kafka partition log segments (`<base offset>.log`) and their
//! offset and time indexes (`.index`, `.timeindex`).
//!
//! A segment is a sequence of entries, each an 8-byte offset and a 4-byte
//! length, told apart by the magic byte at offset 16:
//!
//! - **record batches** (magic 2, Kafka 0.11+): a 61-byte header (base
//!   offset, length, partition leader epoch, magic, CRC-32C of everything
//!   after the CRC, attributes with the codec and the transactional and
//!   control bits, last offset delta, first and max timestamps, producer
//!   id, epoch and base sequence, record count), then the records,
//!   compressed together when the codec says so. Each record is a run of
//!   zigzag varints: its length, attributes, timestamp and offset deltas,
//!   key and value (length -1 for null) and headers. Control batches hold
//!   transaction markers (COMMIT or ABORT) or, in KRaft's
//!   `__cluster_metadata` log and snapshots, LEADER_CHANGE, snapshot
//!   header and footer, KRaft version and voters records (only the
//!   leader of a LEADER_CHANGE is decoded; type numbers from Kafka's
//!   `ControlRecordType`, written from memory, LEADER_CHANGE checked).
//!   The data records of `__cluster_metadata` are metadata records: a
//!   frame version (1), the record type's API key and its version as
//!   unsigned varints, then the message. A record with a null key whose
//!   value starts so, with a type and version Kafka 3.9.1 knows, is shown
//!   with its type's name (`TopicRecord`, `PartitionRecord`, ...;
//!   checked against `kafka-dump-log.sh --cluster-metadata-decoder`); the
//!   message itself is shown raw. The segment's file name, which would
//!   settle it, is not known here, so a user topic's null-key value that
//!   happens to start the same way is named too.
//! - **legacy messages** (magic 0 and 1): offset, size, CRC-32, magic,
//!   attributes, (v1) a timestamp, key and value. A compressed message's
//!   value is a whole inner message set, whose offsets are absolute in v0
//!   and relative in v1 (the wrapper holding the last inner message's
//!   absolute offset).
//!
//! Codecs: gzip, Snappy (snappy-java's "xerial" framing, as the Java
//! client writes it, or raw), LZ4 frames and Zstandard. Legacy v0 LZ4
//! messages carry a wrong frame header checksum (KAFKA-1493) and may not
//! decode.
//!
//! The offset index holds 8-byte entries (offset relative to the segment's
//! base offset, byte position in the `.log`), the time index 12-byte ones
//! (timestamp in milliseconds, relative offset); both are preallocated
//! with zeros while their segment is active. The transaction index
//! (`.txnindex`, beside them in a partition that saw an aborted
//! transaction) holds a 34-byte `AbortedTxn` per aborted transaction:
//! version, producer ID, first and last offset and the last stable
//! offset (checked against `kafka-dump-log.sh`). None has a signature,
//! so they are offered by extension only.
//!
//! The probe wants a non-negative offset, a known magic and sane fields;
//! for a v2 batch inside the head its CRC-32C must match (a larger one
//! needs real timestamps instead), for a legacy message the key and value
//! lengths must add up to its size and its CRC-32 must match.
//!
//! Layout from the Kafka protocol documentation ("Record Batch",
//! "Message Sets") and checked against segments a 3.9.1 broker wrote and
//! its `kafka-dump-log.sh` listing, legacy ones included (the same broker
//! in ZooKeeper mode with an old message format).

use crate::bytes::{i16_be, i32_be, i64_be, to_u64, u16_be, u32_be};
use crate::codec::Codec;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::datakit::{ByteReader, feed_paced};
use crate::formats::util::fmt::{plural, preview};
use crate::formats::util::val;
use crate::formats::{Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::{Origin, Span};
use crate::value::{Check, EnumTable, FlagTable, Value, field, flag};

const BE: Endian = Endian::Big;

declare_format!(pub LOG = "kafka-log", "Apache Kafka log segment", ["log"],
    "application/x-kafka-log", Probe::Custom(probe), dissect);
declare_format!(pub INDEX = "kafka-index", "Apache Kafka offset index", ["index"],
    "application/x-kafka-index", Probe::Never, dissect_index);
declare_format!(pub TIMEINDEX = "kafka-timeindex", "Apache Kafka time index", ["timeindex"],
    "application/x-kafka-timeindex", Probe::Never, dissect_timeindex);
declare_format!(pub TXNINDEX = "kafka-txnindex", "Apache Kafka transaction index", ["txnindex"],
    "application/x-kafka-txnindex", Probe::Never, dissect_txnindex);

/// Bytes of a v2 batch header, and the least its length field can say.
const BATCH_HEADER: u64 = 61;
const MIN_BATCH_LENGTH: i32 = 49;
/// The offset and length fields before every entry's counted bytes.
const LOG_OVERHEAD: u64 = 12;
/// Where the CRC-32C of a v2 batch starts counting (the attributes).
const CRC_START: u64 = 21;
/// Records listed per batch, headers per record.
const MAX_RECORDS: u64 = 1 << 20;
const MAX_HEADERS: u64 = 4096;
/// Bytes of a key or value shown in a summary.
const PREVIEW: u64 = 48;
/// Bytes of a header key or value shown as its value.
const MAX_SHOWN: u64 = 4096;
/// Snappy blocks in one xerial stream.
const MAX_SNAPPY_BLOCKS: usize = 1 << 16;
/// Nesting of legacy compressed messages (the protocol allows one level).
const MAX_DEPTH: u8 = 2;

const CODECS: EnumTable = &[
    (0, "none"),
    (1, "gzip"),
    (2, "snappy"),
    (3, "lz4"),
    (4, "zstd"),
];

const BATCH_ATTRIBUTES: FlagTable = &[
    field(0x7, 1, "GZIP"),
    field(0x7, 2, "SNAPPY"),
    field(0x7, 3, "LZ4"),
    field(0x7, 4, "ZSTD"),
    flag(0x8, "LOG_APPEND_TIME"),
    flag(0x10, "TRANSACTIONAL"),
    flag(0x20, "CONTROL"),
    flag(0x40, "DELETE_HORIZON"),
];

const MESSAGE_ATTRIBUTES: FlagTable = &[
    field(0x7, 1, "GZIP"),
    field(0x7, 2, "SNAPPY"),
    field(0x7, 3, "LZ4"),
    flag(0x8, "LOG_APPEND_TIME"),
];

/// `ControlRecordType`: transaction markers, and the KRaft ones that
/// `__cluster_metadata` and its snapshots hold.
const CONTROL_TYPES: EnumTable = &[
    (0, "ABORT"),
    (1, "COMMIT"),
    (2, "LEADER_CHANGE"),
    (3, "SNAPSHOT_HEADER"),
    (4, "SNAPSHOT_FOOTER"),
    (5, "KRAFT_VERSION"),
    (6, "KRAFT_VOTERS"),
];

/// KRaft metadata record types (`MetadataRecordType`): the `apiKey` and
/// `name` of each `type: metadata` message in Kafka 3.9.1's
/// `common/metadata/*.json` (see [`metadata_max_version`]).
const METADATA_NAMES: EnumTable = &[
    (0, "RegisterBrokerRecord"),
    (1, "UnregisterBrokerRecord"),
    (2, "TopicRecord"),
    (3, "PartitionRecord"),
    (4, "ConfigRecord"),
    (5, "PartitionChangeRecord"),
    (7, "FenceBrokerRecord"),
    (8, "UnfenceBrokerRecord"),
    (9, "RemoveTopicRecord"),
    (10, "DelegationTokenRecord"),
    (11, "UserScramCredentialRecord"),
    (12, "FeatureLevelRecord"),
    (14, "ClientQuotaRecord"),
    (15, "ProducerIdsRecord"),
    (17, "BrokerRegistrationChangeRecord"),
    (18, "AccessControlEntryRecord"),
    (19, "RemoveAccessControlEntryRecord"),
    (20, "NoOpRecord"),
    (21, "ZkMigrationStateRecord"),
    (22, "RemoveUserScramCredentialRecord"),
    (23, "BeginTransactionRecord"),
    (24, "EndTransactionRecord"),
    (25, "AbortTransactionRecord"),
    (26, "RemoveDelegationTokenRecord"),
    (27, "RegisterControllerRecord"),
];

/// The highest version of a metadata record type (their `validVersions`
/// in Kafka 3.9.1).
fn metadata_max_version(key: u64) -> u64 {
    match key {
        0 => 3,
        3 | 5 | 17 => 2,
        _ => 0,
    }
}

/// An unsigned varint (Kafka's `readUnsignedVarint`) at the start of `b`:
/// value and length.
fn uvarint(b: &[u8]) -> Option<(u64, u64)> {
    let mut v = 0u64;
    for i in 0..5u32 {
        let x = *b.get(usize::try_from(i).ok()?)?;
        v |= u64::from(x & 0x7f).checked_shl(i.checked_mul(7)?)?;
        if x & 0x80 == 0 {
            return Some((v, u64::from(i).checked_add(1)?));
        }
    }
    None
}

/// The framing of a KRaft metadata record's value
/// (`MetadataRecordSerde`): frame version 1, the record type's API key
/// and its version, each an unsigned varint, then the message. Only a
/// known type in a version Kafka writes counts.
#[derive(Clone, Copy, Debug)]
struct MetadataFrame {
    key: u64,
    version: u64,
    /// Bytes of the three varints, and of each.
    len: u64,
    lens: [u64; 3],
}

fn metadata_frame(b: &[u8]) -> Option<MetadataFrame> {
    let (frame, a) = uvarint(b)?;
    let (key, k) = uvarint(b.get(usize::try_from(a).ok()?..)?)?;
    let at = a.checked_add(k)?;
    let (version, v) = uvarint(b.get(usize::try_from(at).ok()?..)?)?;
    crate::value::lookup(METADATA_NAMES, key)?;
    (frame == 1 && version <= metadata_max_version(key)).then_some(MetadataFrame {
        key,
        version,
        len: at.checked_add(v)?,
        lens: [a, k, v],
    })
}

/// A compact string (unsigned varint length + 1, then the bytes) at the
/// start of `b`.
fn compact_string(b: &[u8]) -> Option<String> {
    let (n, k) = uvarint(b)?;
    let len = usize::try_from(n.checked_sub(1)?).ok()?;
    let start = usize::try_from(k).ok()?;
    let s = b.get(start..start.checked_add(len)?)?;
    Some(String::from_utf8_lossy(s).into_owned())
}

/// What a metadata record's summary says: its type, version and, for the
/// types that start with one (topics, feature levels), its name.
fn metadata_summary(f: &MetadataFrame, b: &[u8]) -> String {
    let name = val::name_or(METADATA_NAMES, f.key, "metadata record");
    let body = b.get(usize::try_from(f.len).unwrap_or(usize::MAX)..);
    let detail = match f.key {
        2 | 12 => body.and_then(compact_string).map(|s| format!(" \"{s}\"")),
        _ => None,
    };
    format!("{name} v{}{}", f.version, detail.unwrap_or_default())
}

// ---------------------------------------------------------------------------
// Probe

/// 2000-01-01 and 2100-01-01 in milliseconds: the timestamps a batch too
/// large for the head to check its CRC must carry.
const PLAUSIBLE_MS: std::ops::Range<i64> = 946_684_800_000..4_102_444_800_000;

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(offset), Some(length), Some(&magic)) = (i64_be(d, 0), i32_be(d, 8), d.get(16)) else {
        return false;
    };
    if offset < 0 || length < 0 {
        return false;
    }
    let whole =
        crate::bytes::to_usize(LOG_OVERHEAD.saturating_add(u64::from(length.unsigned_abs())));
    match magic {
        2 => probe_batch(d, length, whole),
        0 | 1 => probe_message(d, magic, length, whole),
        _ => false,
    }
}

fn probe_batch(d: &[u8], length: i32, whole: usize) -> bool {
    let (Some(epoch), Some(attributes), Some(delta), Some(count), Some(producer_epoch)) = (
        i32_be(d, 12),
        u16_be(d, 21),
        i32_be(d, 23),
        i32_be(d, 57),
        i16_be(d, 51),
    ) else {
        return false;
    };
    if length < MIN_BATCH_LENGTH
        || epoch < -1
        || attributes & !0x7f != 0
        || attributes & 7 > 4
        || delta < 0
        || count < 0
        || i64::from(count) > i64::from(delta).saturating_add(1)
        || producer_epoch < -1
    {
        return false;
    }
    match d.get(crate::bytes::to_usize(CRC_START)..whole) {
        Some(covered) => u32_be(d, 17) == Some(crate::codec::crc::crc32c(covered)),
        None => {
            // Larger than the head: the timestamps must be real.
            let first = i64_be(d, 27).unwrap_or(0);
            let max = i64_be(d, 35).unwrap_or(0);
            whole > d.len()
                && PLAUSIBLE_MS.contains(&first)
                && PLAUSIBLE_MS.contains(&max)
                && max >= first
                && i64_be(d, 43).is_some_and(|p| p >= -1)
        }
    }
}

fn probe_message(d: &[u8], magic: u8, length: i32, whole: usize) -> bool {
    let Some(&attributes) = d.get(17) else {
        return false;
    };
    let (fixed, allowed) = if magic == 0 { (14, 0x07) } else { (22, 0x0f) };
    if length < fixed || attributes & !allowed != 0 || attributes & 7 > 3 {
        return false;
    }
    // Key and value lengths must add up to the message size.
    let key_at = if magic == 0 { 18 } else { 26 };
    let Some(key) = i32_be(d, key_at) else {
        return false;
    };
    let value_at = key_at
        .saturating_add(4)
        .saturating_add(crate::bytes::to_usize(u64::from(key.max(0).unsigned_abs())));
    let Some(value) = i32_be(d, value_at) else {
        return false;
    };
    if key < -1 || value < -1 {
        return false;
    }
    let end = value_at
        .saturating_add(4)
        .saturating_add(crate::bytes::to_usize(u64::from(
            value.max(0).unsigned_abs(),
        )));
    if end != whole {
        return false;
    }
    d.get(16..whole)
        .is_none_or(|covered| u32_be(d, 12) == Some(crate::codec::crc::crc32(covered)))
}

// ---------------------------------------------------------------------------
// Helpers

/// A Kafka timestamp in milliseconds, as text.
fn ms_text(ms: i64) -> String {
    if ms < 0 {
        return "no timestamp".to_owned();
    }
    crate::value::Time::unix_millis(ms).to_string()
}

/// A Kafka timestamp in milliseconds as a value (-1 is "no timestamp").
fn ms_value(ms: i64, node: Node) -> Node {
    if ms < 0 {
        return node.value(val::int(ms, 64)).summary("no timestamp");
    }
    node.value(Value::Timestamp(crate::value::Time::unix_millis(ms)))
}

fn ms_node(name: &'static str, span: Span, ms: i64) -> Node {
    ms_value(ms, Node::new(name).span(span))
}

/// A zigzag varint (Kafka's `varint`/`varlong`) at `at`: value and length.
async fn varint(r: &mut ByteReader<'_>, at: u64) -> Result<(i64, u64)> {
    let mut raw = 0u64;
    for i in 0..10u32 {
        let b = r.byte(at.saturating_add(u64::from(i))).await?;
        raw |= u64::from(b & 0x7f)
            .checked_shl(i.saturating_mul(7))
            .unwrap_or(0);
        if b & 0x80 == 0 {
            let n = u64::from(i).saturating_add(1);
            return Ok((crate::formats::util::wire::protobuf::zigzag(raw), n));
        }
    }
    Err(Diagnostic::malformed("varint longer than 10 bytes").at(r.span(at, 10)))
}

/// A length that may be -1 (null), as a byte count (0 for null).
fn len_of(len: i64) -> u64 {
    u64::try_from(len).unwrap_or(0)
}

/// The codec of a batch or message, if it is one we decode.
fn codec(id: u8) -> Option<Codec> {
    match id {
        1 => Some(Codec::Gzip),
        2 => Some(Codec::Snappy),
        3 => Some(Codec::Lz4Frame),
        4 => Some(Codec::Zstd),
        _ => None,
    }
}

fn codec_name(id: impl Into<u64>) -> String {
    val::name_or(CODECS, id.into(), "codec")
}

const XERIAL_MAGIC: &[u8] = b"\x82SNAPPY\0";

/// The decoded bytes of a compressed batch or message value, as a lazily
/// decoded source. Snappy in snappy-java's framing (a 16-byte header, then
/// blocks of a big-endian length and raw Snappy data) becomes a piecewise
/// source of lazily decoded blocks.
async fn decoded(cx: &Cx, span: Span, codec_id: u8) -> Result<Span> {
    let Some(codec) = codec(codec_id) else {
        return Err(Diagnostic::unsupported(format!("compression type {codec_id}")).at(span));
    };
    if codec_id == 1 {
        // `Codec::Gzip` starts after the first member's header.
        let head = cx.read_avail(span.sub(0, 1 << 16)).await?;
        if !head.starts_with(b"\x1f\x8b") {
            return Err(Diagnostic::malformed("gzip data without the gzip magic").at(span));
        }
        let len = crate::codec::gzip::header_len(&head).map_err(|e| e.at(span))?;
        return whole(cx, span.tail(to_u64(len)), &codec).await;
    }
    let head = cx.read_avail(span.sub(0, 16)).await?;
    if codec_id != 2 || !head.starts_with(XERIAL_MAGIC) {
        return whole(cx, span, &codec).await;
    }
    let mut pieces = Vec::new();
    let mut pos = 16u64;
    while pos < span.len {
        if pieces.len() >= MAX_SNAPPY_BLOCKS {
            return Err(Diagnostic::limit("too many Snappy blocks").at(span));
        }
        let len = cx.read(span.sub_exact(pos, 4)?).await?;
        let len = u64::from(u32_be(&len, 0).unwrap_or(0));
        let block = span.sub_exact(pos.saturating_add(4), len)?;
        let preamble = cx.read_avail(block.sub(0, 5)).await?;
        let (size, _) = crate::bytes::uleb128(&preamble)
            .ok_or_else(|| Diagnostic::malformed("bad Snappy block preamble").at(block))?;
        pieces.push(cx.decode_lazy(block, &codec, size)?);
        pos = pos.saturating_add(4).saturating_add(len);
        cx.checkpoint().await;
    }
    cx.add_pieces(
        Origin {
            parent: span,
            transform: "xerial-snappy",
        },
        pieces,
    )
}

/// Keys and values up to this size are shown as their value; larger ones
/// are dissected as content when expanded.
const INLINE: u64 = 64;

/// `bytes` as text, if they are printable UTF-8 (possibly cut off within
/// a character at the end).
fn printable(bytes: &[u8]) -> Option<&str> {
    let s = match std::str::from_utf8(bytes) {
        Ok(s) => s,
        Err(e) if e.error_len().is_none() => {
            std::str::from_utf8(bytes.get(..e.valid_up_to()).unwrap_or_default()).ok()?
        }
        Err(_) => return None,
    };
    (!s.chars().any(|c| c.is_control() && c != '\n' && c != '\t')).then_some(s)
}

/// One compressed stream whose decoded size nothing records: small ones
/// are decoded at once (reporting a damaged stream on the node), larger
/// ones on demand.
async fn whole(cx: &Cx, span: Span, codec: &Codec) -> Result<Span> {
    if span.len > crate::formats::UNSIZED_LAZY_THRESHOLD {
        return cx.decode_lazy_unsized(span, codec);
    }
    let decoded = crate::codec::decode_span(cx, span, codec, None).await?;
    if let Some(e) = decoded.error {
        cx.diag(e);
    }
    Ok(decoded.span)
}

/// A key or value of `len` bytes (-1 for null) at `at`, as a node.
async fn blob(
    cx: &Cx,
    input: Input,
    name: &'static str,
    region: Span,
    at: u64,
    len: i64,
) -> Result<Node> {
    let Ok(n) = u64::try_from(len) else {
        return Ok(Node::new(name).summary("null"));
    };
    let span = region.sub(at, n);
    if n > INLINE {
        return Ok(Node::new(name)
            .span(span)
            .summary(plural(n, "byte"))
            .lazy(crate::formats::dissect_or_data, input.nested(span)));
    }
    let bytes = cx.read(span).await?;
    let node = Node::new(name).span(span);
    Ok(match printable(&bytes) {
        Some(text) if text.len() == bytes.len() => node.value(Value::Text(text.to_owned())),
        _ => node.value(Value::Bytes(bytes)),
    })
}

/// A short text (or size) rendering of a key or value, for summaries.
async fn peek(r: &mut ByteReader<'_>, at: u64, len: i64) -> Result<String> {
    let Ok(n) = u64::try_from(len) else {
        return Ok("null".to_owned());
    };
    let bytes = r.bytes(at, n.min(PREVIEW)).await?;
    Ok(match printable(&bytes) {
        Some(s) => {
            let mut text = preview(s, 40);
            if n > PREVIEW && !text.ends_with('…') {
                text.push('…');
            }
            format!("\"{text}\"")
        }
        None => plural(n, "byte"),
    })
}

/// The node of a stored CRC, with the verdict of checking it over
/// `covered` (read a piece at a time).
async fn crc_node(cx: &Cx, at: Span, stored: u32, covered: Span, castagnoli: bool) -> Result<Node> {
    const PIECE: u64 = 1 << 20;
    let mut reg = u32::MAX;
    let mut pos = 0u64;
    while pos < covered.len {
        let piece = cx.read(covered.sub(pos, PIECE)).await?;
        if piece.is_empty() {
            break;
        }
        feed_paced(cx, &piece, |p| {
            reg = if castagnoli {
                crate::codec::crc::crc32c_update(reg, p)
            } else {
                crate::codec::crc::crc32_update(reg, p)
            }
        })
        .await;
        pos = pos.saturating_add(to_u64(piece.len()));
    }
    let computed = !reg;
    Ok(Node::new("CRC")
        .span(at)
        .checksum(
            Check::new(if castagnoli { "CRC-32C" } else { "CRC-32" }, stored).verify(computed),
        )
        .desc(if castagnoli {
            "CRC-32C from the attributes to the end of the batch"
        } else {
            "CRC-32 from the magic byte to the end of the message"
        }))
}

// ---------------------------------------------------------------------------
// Segment

/// Totals for the segment's summary, carried by the walker.
#[derive(Clone, Default)]
struct Stats {
    batches: u64,
    /// Uncompressed legacy messages at the top level.
    messages: u64,
    /// Compressed legacy messages (wrappers of an inner message set).
    wrappers: u64,
    records: u64,
    /// Bit `n` set: codec `n` seen.
    codecs: u8,
    first: Option<i64>,
    last: Option<i64>,
}

impl Stats {
    fn codec(&mut self, id: u8) {
        if id != 0 {
            self.codecs |= 1u8.checked_shl(id.into()).unwrap_or(0);
        }
    }

    fn summary(&self) -> String {
        let mut parts = Vec::new();
        if self.batches > 0 {
            parts.push(format!(
                "{}, {}",
                plural(self.batches, "batch"),
                plural(self.records, "record")
            ));
        }
        if self.messages > 0 {
            parts.push(plural(self.messages, "legacy message"));
        }
        if self.wrappers > 0 {
            parts.push(plural(self.wrappers, "compressed wrapper"));
        }
        if parts.is_empty() {
            parts.push("empty".to_owned());
        }
        let codecs: Vec<&str> = CODECS
            .iter()
            .filter(|(id, _)| {
                *id > 0
                    && self.codecs
                        & 1u8
                            .checked_shl(u32::try_from(*id).unwrap_or(8))
                            .unwrap_or(0)
                        != 0
            })
            .map(|(_, n)| *n)
            .collect();
        if !codecs.is_empty() {
            parts.push(codecs.join("/"));
        }
        if let (Some(first), Some(last)) = (self.first, self.last) {
            parts.push(format!("offsets {first}–{last}"));
        }
        parts.join(", ")
    }
}

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    cx.annotate("Kafka log segment");
    walk(cx, (input, input.span, 0, 0)).await
}

/// Lists the entries of a segment, or of a legacy inner message set
/// (whose offsets count from `base`: see [`inner_base`]).
async fn walk(cx: Cx, (input, region, depth, base): (Input, Span, u8, i64)) -> Result<()> {
    let top = depth == 0;
    let (mut pos, mut stats) = cx.resume::<(u64, Stats)>().unwrap_or_default();
    loop {
        let head = cx.read_avail(region.sub(pos, BATCH_HEADER)).await?;
        if head.is_empty() {
            break;
        }
        let (Some(offset), Some(length), Some(&magic)) =
            (i64_be(&head, 0), i32_be(&head, 8), head.get(16))
        else {
            cx.push(
                Node::new("Trailing data")
                    .span(region.sub(pos, to_u64(head.len())))
                    .diag(Diagnostic::truncated(
                        region.sub(pos, 17),
                        to_u64(head.len()),
                    )),
            )
            .await;
            break;
        };
        if offset == 0 && length == 0 && pos > 0 {
            // A preallocated segment's zero tail.
            cx.push(Node::new("Unused (zeros)").span(region.tail(pos)))
                .await;
            break;
        }
        let total = LOG_OVERHEAD.saturating_add(u64::from(length.unsigned_abs()));
        let span = region.sub(pos, total);
        let at = (pos, stats.clone());
        cx.mark(move || at);
        let node = if magic == 2 && length >= MIN_BATCH_LENGTH && top {
            let attributes = u16_be(&head, 21).unwrap_or(0);
            let delta = i32_be(&head, 23).unwrap_or(0);
            let first_ts = i64_be(&head, 27).unwrap_or(-1);
            let count = i32_be(&head, 57).unwrap_or(0);
            let codec_id = u8::try_from(attributes & 7).unwrap_or(0);
            let last = offset.saturating_add(delta.into());
            stats.batches = stats.batches.saturating_add(1);
            stats.records = stats
                .records
                .saturating_add(u64::from(count.unsigned_abs()));
            stats.codec(codec_id);
            stats.first = Some(stats.first.map_or(offset, |f| f.min(offset)));
            stats.last = Some(stats.last.map_or(last, |l| l.max(last)));
            let range = if last == offset {
                format!("offset {offset}")
            } else {
                format!("offsets {offset}–{last}")
            };
            let mut summary = format!("{range}, {}", plural(count, "record"));
            if codec_id != 0 {
                summary.push_str(&format!(", {}", codec_name(codec_id)));
            }
            if attributes & 0x20 != 0 {
                summary.push_str(", control");
            } else if attributes & 0x10 != 0 {
                summary.push_str(", transactional");
            }
            summary.push_str(&format!(", {}", ms_text(first_ts)));
            Node::new(format!("Batch {offset}"))
                .span(span)
                .summary(summary)
                .lazy(batch, (input, span))
        } else if magic <= 1 && length >= 14 {
            let codec_id = head.get(17).copied().unwrap_or(0) & 7;
            stats.codec(codec_id);
            // A wrapper's offset is its last inner message's.
            let first = if codec_id == 0 {
                stats.messages = stats.messages.saturating_add(1);
                offset
            } else {
                stats.wrappers = stats.wrappers.saturating_add(1);
                if top && stats.first.is_none() {
                    first_inner(&cx, span, offset, magic, codec_id)
                        .await
                        .unwrap_or(offset)
                } else {
                    offset
                }
            };
            stats.first = Some(stats.first.map_or(first, |f| f.min(first)));
            stats.last = Some(stats.last.map_or(offset, |l| l.max(offset)));
            let absolute = offset.saturating_add(base);
            let mut summary = format!("v{magic}, {}", plural(length, "byte"));
            if codec_id != 0 {
                summary.push_str(&format!(", {} wrapper", codec_name(codec_id)));
            }
            if base != 0 {
                summary.push_str(&format!(", relative offset {offset}"));
            }
            Node::new(format!("Message {absolute}"))
                .span(span)
                .summary(summary)
                .lazy(
                    crate::expander!(self::message: (Input, Span, u8, i64)),
                    (input, span, depth, base),
                )
        } else {
            cx.push(Node::new("Unrecognised data").span(region.tail(pos)).diag(
                Diagnostic::malformed(format!("entry with magic {magic} and length {length}")),
            ))
            .await;
            break;
        };
        let node = if span.len < total {
            node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ))
        } else {
            node
        };
        cx.progress_in(region, region.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(total);
    }
    if top {
        cx.annotate(format!("Kafka log segment, {}", stats.summary()));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Record batches (magic 2)

record! {
    /// The header of a record batch.
    struct BatchHeader {
        base_offset: i64 "Base offset",
        length: i32 "Batch length" .desc("Bytes after this field"),
        leader_epoch: i32 "Partition leader epoch",
        magic: u8 "Magic",
        crc: u32 "CRC" .checksum("CRC-32"),
        attributes: u16 "Attributes" .flags(BATCH_ATTRIBUTES),
        last_offset_delta: i32 "Last offset delta",
        base_timestamp: i64 "Base timestamp",
        max_timestamp: i64 "Max timestamp",
        producer_id: i64 "Producer ID",
        producer_epoch: i16 "Producer epoch",
        base_sequence: i32 "Base sequence",
        count: i32 "Records count",
    }
}

async fn batch(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let n = |at: u64, len: u64| span.sub(at, len);
    if span.len < BATCH_HEADER {
        return Err(Diagnostic::truncated(n(0, BATCH_HEADER), span.len));
    }
    let h: BatchHeader = read_record(&cx, n(0, BATCH_HEADER), BE).await?;
    cx.emit(
        Node::new("Base offset")
            .span(n(0, 8))
            .value(val::int(h.base_offset, 64)),
    );
    cx.emit(
        Node::new("Batch length")
            .span(n(8, 4))
            .value(val::int(h.length, 32))
            .desc("Bytes after this field"),
    );
    cx.emit(
        Node::new("Partition leader epoch")
            .span(n(12, 4))
            .value(val::int(h.leader_epoch, 32)),
    );
    cx.emit(
        Node::new("Magic")
            .span(n(16, 1))
            .value(val::uint(h.magic, 8)),
    );
    let covered = span.tail(CRC_START);
    cx.emit(crc_node(&cx, n(17, 4), h.crc, covered, true).await?);
    let codec_id = u8::try_from(h.attributes & 7).unwrap_or(0);
    cx.emit(
        Node::new("Attributes")
            .span(n(21, 2))
            .value(val::flagsv(h.attributes, 16, BATCH_ATTRIBUTES))
            .summary(format!("compression {}", codec_name(codec_id))),
    );
    cx.emit(
        Node::new("Last offset delta")
            .span(n(23, 4))
            .value(val::int(h.last_offset_delta, 32))
            .summary(format!(
                "last offset {}",
                h.base_offset.saturating_add(h.last_offset_delta.into())
            )),
    );
    let kind = if h.attributes & 8 != 0 {
        "LogAppendTime: set by the broker"
    } else {
        "CreateTime: set by the producer"
    };
    cx.emit(ms_node("Base timestamp", n(27, 8), h.base_timestamp).desc(kind));
    cx.emit(ms_node("Max timestamp", n(35, 8), h.max_timestamp));
    cx.emit(
        Node::new("Producer ID")
            .span(n(43, 8))
            .value(val::int(h.producer_id, 64)),
    );
    cx.emit(
        Node::new("Producer epoch")
            .span(n(51, 2))
            .value(val::int(h.producer_epoch, 16)),
    );
    cx.emit(
        Node::new("Base sequence")
            .span(n(53, 4))
            .value(val::int(h.base_sequence, 32)),
    );
    cx.emit(
        Node::new("Records count")
            .span(n(57, 4))
            .value(val::int(h.count, 32)),
    );
    let body = span.tail(BATCH_HEADER);
    let records_text = plural(h.count, "record");
    let summary = if codec_id == 0 {
        records_text
    } else {
        format!("{records_text}, {}-compressed", codec_name(codec_id))
    };
    let state = Batch {
        input,
        body,
        codec: codec_id,
        base: h.base_offset,
        first_ts: h.base_timestamp,
        count: u64::from(h.count.unsigned_abs()).min(MAX_RECORDS),
        control: h.attributes & 0x20 != 0,
    };
    cx.emit(
        Node::new("Records")
            .span(body)
            .summary(summary)
            .lazy(records, state),
    );
    Ok(())
}

#[derive(Clone)]
struct Batch {
    input: Input,
    body: Span,
    codec: u8,
    base: i64,
    first_ts: i64,
    count: u64,
    control: bool,
}

/// Lists a batch's records (decoding them first if compressed).
async fn records(cx: Cx, b: Batch) -> Result<()> {
    let region = if b.codec == 0 {
        b.body
    } else {
        decoded(&cx, b.body, b.codec).await?
    };
    let mut r = ByteReader::new(&cx, region);
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while index < b.count {
        let at = (pos, index);
        cx.mark(move || at);
        let (len, n) = varint(&mut r, pos).await?;
        let len = u64::try_from(len).map_err(|_| {
            Diagnostic::malformed(format!("record length {len}")).at(r.span(pos, n))
        })?;
        let span = region.sub(pos, n.saturating_add(len));
        // Attributes, deltas, then the key and value.
        let mut p = pos.saturating_add(n).saturating_add(1);
        let (ts_delta, k) = varint(&mut r, p).await?;
        p = p.saturating_add(k);
        let (off_delta, k) = varint(&mut r, p).await?;
        p = p.saturating_add(k);
        let (key_len, k) = varint(&mut r, p).await?;
        p = p.saturating_add(k);
        let key = peek(&mut r, p, key_len).await?;
        let control_type = if b.control && key_len >= 4 {
            Some(r.be(p.saturating_add(2), 2).await?)
        } else {
            None
        };
        p = p.saturating_add(len_of(key_len));
        let (value_len, k) = varint(&mut r, p).await?;
        p = p.saturating_add(k);
        let summary = if let Some(kind) = control_type {
            format!(
                "control record, {}",
                val::name_or(CONTROL_TYPES, kind, "type")
            )
        } else if b.control {
            "control record".to_owned()
        } else {
            let head = if key_len < 0 && value_len >= 3 {
                r.bytes(p, len_of(value_len).min(PREVIEW)).await?
            } else {
                Vec::new()
            };
            match metadata_frame(&head) {
                Some(f) => metadata_summary(&f, &head),
                None => {
                    let value = peek(&mut r, p, value_len).await?;
                    format!("key {key}, value {value}")
                }
            }
        };
        let offset = b.base.saturating_add(off_delta);
        let ts = b.first_ts.saturating_add(ts_delta);
        cx.push(
            Node::new(format!("Record {offset}"))
                .span(span)
                .summary(format!("{summary}, {}", ms_text(ts)))
                .lazy(record, (b.clone(), span)),
        )
        .await;
        pos = pos.saturating_add(n).saturating_add(len);
        index = index.saturating_add(1);
    }
    let rest = cx.known(region.tail(pos)).await;
    if rest.len > 0 {
        cx.push(
            Node::new("Trailing data")
                .span(rest)
                .diag(Diagnostic::malformed("bytes after the last record")),
        )
        .await;
    }
    Ok(())
}

async fn record(cx: Cx, (b, span): (Batch, Span)) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let (len, mut p) = varint(&mut r, 0).await?;
    cx.emit(
        Node::new("Length")
            .span(span.sub(0, p))
            .value(val::int(len, 32)),
    );
    let attributes = r.byte(p).await?;
    cx.emit(
        Node::new("Attributes")
            .span(span.sub(p, 1))
            .value(val::hex(attributes, 8))
            .desc("Unused"),
    );
    p = p.saturating_add(1);
    let (ts_delta, k) = varint(&mut r, p).await?;
    cx.emit(
        Node::new("Timestamp delta")
            .span(span.sub(p, k))
            .value(val::int(ts_delta, 64))
            .summary(ms_text(b.first_ts.saturating_add(ts_delta))),
    );
    p = p.saturating_add(k);
    let (off_delta, k) = varint(&mut r, p).await?;
    cx.emit(
        Node::new("Offset delta")
            .span(span.sub(p, k))
            .value(val::int(off_delta, 32))
            .summary(format!("offset {}", b.base.saturating_add(off_delta))),
    );
    p = p.saturating_add(k);
    let (key_len, k) = varint(&mut r, p).await?;
    cx.emit(
        Node::new("Key length")
            .span(span.sub(p, k))
            .value(val::int(key_len, 32)),
    );
    p = p.saturating_add(k);
    let key_at = p;
    p = p.saturating_add(len_of(key_len));
    let (value_len, k) = varint(&mut r, p).await?;
    let value_len_node = Node::new("Value length")
        .span(span.sub(p, k))
        .value(val::int(value_len, 32));
    p = p.saturating_add(k);
    let value_at = p;
    p = p.saturating_add(len_of(value_len));
    if b.control {
        let key = span.sub(key_at, len_of(key_len));
        let (node, kind) = control_key(&cx, key).await?;
        cx.emit(node);
        cx.emit(value_len_node);
        let value = span.sub(value_at, len_of(value_len));
        cx.emit(control_value(&cx, value, kind).await?);
    } else {
        cx.emit(blob(&cx, b.input, "Key", span, key_at, key_len).await?);
        cx.emit(value_len_node);
        let head = if key_len < 0 && value_len >= 3 {
            r.bytes(value_at, len_of(value_len).min(PREVIEW)).await?
        } else {
            Vec::new()
        };
        match metadata_frame(&head) {
            Some(f) => {
                let value = span.sub(value_at, len_of(value_len));
                cx.emit(
                    Node::new("Value")
                        .span(value)
                        .summary(metadata_summary(&f, &head))
                        .lazy(crate::expander!(self::metadata_value: Span), value),
                );
            }
            None => cx.emit(blob(&cx, b.input, "Value", span, value_at, value_len).await?),
        }
    }
    let (count, k) = varint(&mut r, p).await?;
    let headers_span = span.tail(p);
    let mut node = Node::new("Headers")
        .span(headers_span)
        .value(val::int(count, 32))
        .summary(plural(count, "header"));
    if count > 0 {
        let count = len_of(count).min(MAX_HEADERS);
        node = node.lazy(headers, (headers_span, k, count));
    }
    cx.emit(node);
    Ok(())
}

record! {
    /// The key of a control record.
    struct ControlKey {
        version: i16 "Version",
        kind: u16 "Type" .enumeration(CONTROL_TYPES),
    }
}

record! {
    /// The value of a transaction marker (a COMMIT or ABORT control record).
    struct EndTxnMarker {
        version: i16 "Version",
        coordinator_epoch: i32 "Coordinator epoch",
    }
}

record! {
    /// The start of a LEADER_CHANGE control record's value
    /// (`LeaderChangeMessage`; the voter lists follow).
    struct LeaderChange {
        version: i16 "Version",
        leader: i32 "Leader ID",
    }
}

fn too_short(name: &'static str, span: Span, need: u64) -> Node {
    Node::new(name)
        .span(span)
        .diag(Diagnostic::malformed(format!(
            "control record field shorter than {need} bytes"
        )))
}

/// A control record's key (version and type), and the type.
async fn control_key(cx: &Cx, span: Span) -> Result<(Node, Option<u16>)> {
    if span.len < ControlKey::SIZE {
        return Ok((too_short("Key", span, ControlKey::SIZE), None));
    }
    let k: ControlKey = read_record(cx, span.sub(0, ControlKey::SIZE), BE).await?;
    let node = ControlKey::node("Key", span, BE).summary(val::name_or(
        CONTROL_TYPES,
        k.kind.into(),
        "type",
    ));
    Ok((node, Some(k.kind)))
}

/// A control record's value, by its key's type: a transaction marker for
/// ABORT and COMMIT, the leader for LEADER_CHANGE; the other KRaft types
/// (a version, then the message) are shown raw.
async fn control_value(cx: &Cx, span: Span, kind: Option<u16>) -> Result<Node> {
    const NAME: &str = "Value";
    match kind {
        Some(0 | 1) => {
            if span.len < EndTxnMarker::SIZE {
                return Ok(too_short(NAME, span, EndTxnMarker::SIZE));
            }
            let v: EndTxnMarker = read_record(cx, span.sub(0, EndTxnMarker::SIZE), BE).await?;
            Ok(EndTxnMarker::node(NAME, span, BE).summary(format!(
                "transaction marker, coordinator epoch {}",
                v.coordinator_epoch
            )))
        }
        Some(2) if span.len >= LeaderChange::SIZE => {
            let v: LeaderChange = read_record(cx, span.sub(0, LeaderChange::SIZE), BE).await?;
            Ok(LeaderChange::node(NAME, span, BE).summary(format!("leader {}", v.leader)))
        }
        _ => {
            let bytes = cx.read(span.sub(0, MAX_SHOWN)).await?;
            let mut node = Node::new(NAME).span(span).value(Value::Bytes(bytes));
            if let Some(kind) = kind {
                node = node.summary(val::name_or(CONTROL_TYPES, kind.into(), "type"));
            }
            Ok(node)
        }
    }
}

/// A KRaft metadata record's value: its framing, then the message (a
/// flexible-version Kafka message, shown raw).
async fn metadata_value(cx: Cx, span: Span) -> Result<()> {
    let head = cx.read(span.sub(0, 16)).await?;
    let Some(f) = metadata_frame(&head) else {
        return Err(Diagnostic::malformed("metadata record framing").at(span));
    };
    let [a, k, v] = f.lens;
    cx.emit(
        Node::new("Frame version")
            .span(span.sub(0, a))
            .value(val::uint(1u8, 8)),
    );
    cx.emit(
        Node::new("Record type")
            .span(span.sub(a, k))
            .value(val::enumv(f.key, 16, METADATA_NAMES))
            .desc("The API key of the metadata record type"),
    );
    cx.emit(
        Node::new("Version")
            .span(span.sub(a.saturating_add(k), v))
            .value(val::uint(f.version, 16)),
    );
    let body = span.tail(f.len);
    let bytes = cx.read(body.sub(0, MAX_SHOWN)).await?;
    cx.emit(Node::new("Message").span(body).value(Value::Bytes(bytes)));
    Ok(())
}

/// Lists a record's headers.
async fn headers(cx: Cx, (span, start, count): (Span, u64, u64)) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let mut p = start;
    for _ in 0..count {
        let begin = p;
        let (key_len, k) = varint(&mut r, p).await?;
        p = p.saturating_add(k);
        let key_len = len_of(key_len);
        let key = r.bytes(p, key_len.min(256)).await?;
        p = p.saturating_add(key_len);
        let (value_len, k) = varint(&mut r, p).await?;
        p = p.saturating_add(k);
        let value = peek(&mut r, p, value_len).await?;
        p = p.saturating_add(len_of(value_len));
        let hspan = span.sub(begin, p.saturating_sub(begin));
        cx.push(
            Node::new(format!("Header {}", String::from_utf8_lossy(&key)))
                .span(hspan)
                .summary(value)
                .lazy(header, hspan),
        )
        .await;
    }
    Ok(())
}

async fn header(cx: Cx, span: Span) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let (key_len, k) = varint(&mut r, 0).await?;
    cx.emit(
        Node::new("Key length")
            .span(span.sub(0, k))
            .value(val::int(key_len, 32)),
    );
    let key_len = len_of(key_len);
    let key = r.bytes(k, key_len.min(MAX_SHOWN)).await?;
    cx.emit(
        Node::new("Key")
            .span(span.sub(k, key_len))
            .value(Value::Text(String::from_utf8_lossy(&key).into_owned())),
    );
    let p = k.saturating_add(key_len);
    let (value_len, k) = varint(&mut r, p).await?;
    cx.emit(
        Node::new("Value length")
            .span(span.sub(p, k))
            .value(val::int(value_len, 32)),
    );
    let at = p.saturating_add(k);
    let node = match u64::try_from(value_len) {
        Err(_) => Node::new("Value").summary("null"),
        Ok(n) => {
            let bytes = r.bytes(at, n.min(MAX_SHOWN)).await?;
            let node = Node::new("Value").span(span.sub(at, n));
            match String::from_utf8(bytes) {
                Ok(text) => node.value(Value::Text(text)),
                Err(e) => node.value(Value::Bytes(e.into_bytes())),
            }
        }
    };
    cx.emit(node);
    Ok(())
}

// ---------------------------------------------------------------------------
// Legacy messages (magic 0 and 1)

async fn message(cx: Cx, (input, span, depth, base): (Input, Span, u8, i64)) -> Result<()> {
    let mut r = ByteReader::new(&cx, span);
    let head = cx.read_avail(span.sub(0, 26)).await?;
    let n = |at: u64, len: u64| span.sub(at, len);
    let offset = i64_be(&head, 0).unwrap_or(0);
    let mut offset_node = Node::new("Offset")
        .span(n(0, 8))
        .value(val::int(offset, 64));
    if base != 0 {
        offset_node = offset_node
            .summary(format!("offset {}", offset.saturating_add(base)))
            .desc("Relative to the wrapper's last inner message");
    }
    cx.emit(offset_node);
    cx.emit(
        Node::new("Message size")
            .span(n(8, 4))
            .value(val::int(i32_be(&head, 8).unwrap_or(0), 32))
            .desc("Bytes after this field"),
    );
    let stored = u32_be(&head, 12).unwrap_or(0);
    cx.emit(crc_node(&cx, n(12, 4), stored, span.tail(16), false).await?);
    let magic = head.get(16).copied().unwrap_or(0);
    cx.emit(Node::new("Magic").span(n(16, 1)).value(val::uint(magic, 8)));
    let attributes = head.get(17).copied().unwrap_or(0);
    let codec_id = attributes & 7;
    cx.emit(
        Node::new("Attributes")
            .span(n(17, 1))
            .value(val::flagsv(attributes, 8, MESSAGE_ATTRIBUTES))
            .summary(format!("compression {}", codec_name(codec_id))),
    );
    let mut p = 18u64;
    if magic == 1 {
        let ts = i64_be(&head, 18).unwrap_or(-1);
        let kind = if attributes & 8 != 0 {
            "LogAppendTime: set by the broker"
        } else {
            "CreateTime: set by the producer"
        };
        cx.emit(ms_node("Timestamp", n(18, 8), ts).desc(kind));
        p = 26;
    }
    let key_len = i64::from(i32::from_be_bytes(
        r.bytes(p, 4).await?.try_into().unwrap_or([0xff; 4]),
    ));
    cx.emit(
        Node::new("Key length")
            .span(n(p, 4))
            .value(val::int(key_len, 32)),
    );
    p = p.saturating_add(4);
    cx.emit(blob(&cx, input, "Key", span, p, key_len).await?);
    p = p.saturating_add(len_of(key_len));
    let value_len = i64::from(i32::from_be_bytes(
        r.bytes(p, 4).await?.try_into().unwrap_or([0xff; 4]),
    ));
    cx.emit(
        Node::new("Value length")
            .span(n(p, 4))
            .value(val::int(value_len, 32)),
    );
    p = p.saturating_add(4);
    let Ok(len) = u64::try_from(value_len) else {
        cx.emit(Node::new("Value").summary("null"));
        return Ok(());
    };
    let value = span.sub(p, len);
    if codec_id == 0 {
        cx.emit(blob(&cx, input, "Value", span, p, value_len).await?);
    } else if depth.saturating_add(1) >= MAX_DEPTH {
        cx.emit(Node::new("Value").span(value).diag(Diagnostic::malformed(
            "compressed message inside a compressed message",
        )));
    } else {
        cx.emit(
            Node::new("Messages")
                .span(value)
                .summary(format!("{}-compressed message set", codec_name(codec_id)))
                .lazy(inner, (input, value, codec_id, depth, (offset, magic))),
        );
    }
    Ok(())
}

/// The wrapper's offset and magic, for the inner offsets.
type Wrapper = (i64, u8);

async fn inner(
    cx: Cx,
    (input, value, codec_id, depth, (offset, magic)): (Input, Span, u8, u8, Wrapper),
) -> Result<()> {
    let region = decoded(&cx, value, codec_id).await?;
    let (base, _) = inner_base(&cx, region, offset, magic).await?;
    walk(cx, (input, region, depth.saturating_add(1), base)).await
}

/// What a legacy inner message set's offsets count from, and its first
/// message's offset as stored. Inner v0 messages carry absolute offsets;
/// inner v1 messages (KIP-31) relative ones from 0, the wrapper carrying
/// the last inner message's absolute offset, so an inner offset `r` is
/// `wrapper - last + r` (as Kafka's `AbstractLegacyRecordBatch` reads it).
/// Walks the inner entries' headers.
async fn inner_base(cx: &Cx, region: Span, wrapper: i64, magic: u8) -> Result<(i64, i64)> {
    let mut pos = 0u64;
    let (mut first, mut last) = (None, 0i64);
    loop {
        let head = cx.read_avail(region.sub(pos, LOG_OVERHEAD)).await?;
        let (Some(offset), Some(length)) = (i64_be(&head, 0), i32_be(&head, 8)) else {
            break;
        };
        if length <= 0 {
            break;
        }
        first.get_or_insert(offset);
        last = offset;
        pos = pos
            .saturating_add(LOG_OVERHEAD)
            .saturating_add(u64::from(length.unsigned_abs()));
    }
    let base = if magic == 0 {
        0
    } else {
        wrapper.saturating_sub(last)
    };
    Ok((base, first.unwrap_or(0)))
}

/// The absolute offset of the first message inside the legacy wrapper
/// `span` (for the segment's offset range when it starts with one).
async fn first_inner(cx: &Cx, span: Span, wrapper: i64, magic: u8, codec_id: u8) -> Option<i64> {
    let key_at: u64 = if magic == 1 { 26 } else { 18 };
    let key = cx.read(span.sub_exact(key_at, 4).ok()?).await.ok()?;
    let key_len = len_of(i32_be(&key, 0)?.into());
    let value_at = key_at.saturating_add(4).saturating_add(key_len);
    let len = cx.read(span.sub_exact(value_at, 4).ok()?).await.ok()?;
    let len = u64::try_from(i32_be(&len, 0)?).ok()?;
    let value = span.sub_exact(value_at.saturating_add(4), len).ok()?;
    let region = decoded(cx, value, codec_id).await.ok()?;
    let (base, first) = inner_base(cx, region, wrapper, magic).await.ok()?;
    Some(first.saturating_add(base))
}

// ---------------------------------------------------------------------------
// Indexes

record! {
    /// An offset index entry.
    struct IndexEntry {
        relative: u32 "Relative offset" .desc("Offset minus the segment's base offset"),
        position: u32 "Position" .desc("Byte position of the batch in the .log file"),
    }
}

record! {
    /// A time index entry.
    struct TimeIndexEntry {
        timestamp: i64 "Timestamp" .with(|&v, node| ms_value(v, node)),
        relative: u32 "Relative offset" .desc("Offset minus the segment's base offset"),
    }
}

async fn dissect_index(cx: Cx, input: Input) -> Result<()> {
    index_entries(cx, input, IndexEntry::SIZE).await
}

async fn dissect_timeindex(cx: Cx, input: Input) -> Result<()> {
    index_entries(cx, input, TimeIndexEntry::SIZE).await
}

record! {
    /// A transaction index entry (`AbortedTxn`): an aborted transaction.
    struct TxnIndexEntry {
        version: i16 "Version",
        producer: i64 "Producer ID",
        first: i64 "First offset" .desc("The transaction's first offset"),
        last: i64 "Last offset" .desc("The offset of its ABORT marker"),
        stable: i64 "Last stable offset"
            .desc("The log's last stable offset when the transaction was aborted"),
    }
}

async fn dissect_txnindex(cx: Cx, input: Input) -> Result<()> {
    index_entries(cx, input, TxnIndexEntry::SIZE).await
}

/// Lists an index's entries, up to the zeros of its preallocated tail.
async fn index_entries(cx: Cx, input: Input, size: u64) -> Result<()> {
    let file = input.span;
    let offsets = size == IndexEntry::SIZE;
    let (mut pos, mut index) = cx.resume::<(u64, u64)>().unwrap_or((0, 0));
    while pos.saturating_add(size) <= file.len {
        let at = (pos, index);
        cx.mark(move || at);
        let span = file.sub(pos, size);
        let e = cx.read(span).await?;
        if index > 0 && e.iter().all(|&b| b == 0) {
            cx.push(
                Node::new("Unused (zeros)")
                    .span(file.tail(pos))
                    .desc("Space preallocated for the active segment"),
            )
            .await;
            pos = file.len;
            break;
        }
        let name = format!("Entry {index}");
        let node = if offsets {
            let rel = u32_be(&e, 0).unwrap_or(0);
            let position = u32_be(&e, 4).unwrap_or(0);
            IndexEntry::node(name, span, BE)
                .summary(format!("relative offset {rel} at byte {position}"))
        } else if size == TxnIndexEntry::SIZE {
            let producer = i64_be(&e, 2).unwrap_or(-1);
            let first = i64_be(&e, 10).unwrap_or(-1);
            let last = i64_be(&e, 18).unwrap_or(-1);
            TxnIndexEntry::node(name, span, BE).summary(format!(
                "producer {producer}, aborted offsets {first}–{last}"
            ))
        } else {
            let ts = i64_be(&e, 0).unwrap_or(-1);
            let rel = u32_be(&e, 8).unwrap_or(0);
            TimeIndexEntry::node(name, span, BE)
                .summary(format!("{} at relative offset {rel}", ms_text(ts)))
        };
        cx.progress_in(file, file.offset.saturating_add(pos));
        cx.push(node).await;
        pos = pos.saturating_add(size);
        index = index.saturating_add(1);
    }
    if pos < file.len {
        cx.push(
            Node::new("Trailing data")
                .span(file.tail(pos))
                .diag(Diagnostic::malformed(format!(
                    "not a whole {size}-byte entry"
                ))),
        )
        .await;
    }
    let (kind, what) = if offsets {
        ("offset index", "entry")
    } else if size == TxnIndexEntry::SIZE {
        ("transaction index", "aborted transaction")
    } else {
        ("time index", "entry")
    };
    cx.annotate(format!("Kafka {kind}, {}", plural(index, what)));
    Ok(())
}
