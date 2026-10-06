//! xz (`.xz`) container.
//!
//! A file is one or more streams (separated by zero padding). Each stream is
//! a 12-byte header, blocks, an index and a 12-byte footer. The footer gives
//! the index size, and the index lists every block's sizes, so the whole
//! layout is found from the end without touching compressed data. Block
//! headers (filter chains) are decoded on expansion; the decompressed
//! content is decoded on demand.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::codec::crc32;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::arcutil::{count, emit_nodes, hex, human_size, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
/// Streams in one file before giving up.
const MAX_STREAMS: usize = 4096;

pub static FORMAT: Format = Format {
    name: "xz",
    title: "xz compressed data",
    extensions: &["xz", "txz"],
    mime: "application/x-xz",
    probe: Probe::Magic(&[(0, b"\xfd7zXZ\0")]),
    dissect: crate::expander!(dissect: Input),
};

const CHECK: EnumTable = &[(0, "none"), (1, "CRC32"), (4, "CRC64"), (10, "SHA-256")];

pub const FILTERS: EnumTable = &[
    (0x03, "Delta"),
    (0x04, "BCJ x86"),
    (0x05, "BCJ PowerPC"),
    (0x06, "BCJ IA-64"),
    (0x07, "BCJ ARM"),
    (0x08, "BCJ ARM-Thumb"),
    (0x09, "BCJ SPARC"),
    (0x0a, "BCJ ARM64"),
    (0x0b, "BCJ RISC-V"),
    (0x21, "LZMA2"),
];

fn check_size(check: u8) -> u64 {
    match check {
        0 => 0,
        1..=3 => 4,
        4..=6 => 8,
        7..=9 => 16,
        10..=12 => 32,
        _ => 64,
    }
}

fn check_name(check: u8) -> String {
    crate::value::lookup(CHECK, check.into())
        .map_or_else(|| format!("check {check}"), str::to_owned)
}

record! {
    pub struct StreamHeader {
        magic: bytes[6] "Magic",
        reserved: u8 "Reserved flags",
        check: u8 "Check type" .enumeration(CHECK),
        crc: u32 "CRC32" .hex() .desc("CRC32 of the stream flags"),
    }
}

record! {
    pub struct StreamFooter {
        crc: u32 "CRC32" .hex() .desc("CRC32 of the backward size and stream flags"),
        backward: u32 "Backward size"
            .with(|&v, n| n.summary(format!("index is {} bytes", u64::from(v).saturating_add(1).saturating_mul(4)))),
        reserved: u8 "Reserved flags",
        check: u8 "Check type" .enumeration(CHECK),
        magic: ascii[2] "Magic",
    }
}

/// The LZMA2 dictionary size encoded in its one-byte property.
pub fn lzma2_dict(props: u8) -> Option<u64> {
    match props {
        0..=39 => Some((2 | u64::from(props & 1)) << (props / 2).saturating_add(11)),
        40 => Some(u64::from(u32::MAX)),
        _ => None,
    }
}

/// One stream, located from its footer.
#[derive(Clone, Debug)]
struct Stream {
    span: Span,
    check: u8,
    index: Span,
    /// (unpadded size, uncompressed size) of each block.
    records: Arc<Vec<(u64, u64)>>,
}

impl Stream {
    fn uncompressed(&self) -> u64 {
        self.records
            .iter()
            .fold(0u64, |a, &(_, u)| a.saturating_add(u))
    }
}

/// A multibyte integer (7 bits per byte, little-endian, at most 9 bytes).
fn varint(data: &[u8], at: usize) -> Option<(u64, usize)> {
    let rest = data.get(at..)?;
    let (value, len) = crate::bytes::uleb128(rest.get(..rest.len().min(9))?)?;
    Some((value, len))
}

fn padded4(n: u64) -> u64 {
    n.div_ceil(4).saturating_mul(4)
}

/// Parses an index: indicator, record count, records, padding, CRC32.
fn parse_index(data: &[u8]) -> std::result::Result<Vec<(u64, u64)>, &'static str> {
    if data.first() != Some(&0) {
        return Err("index indicator is not zero");
    }
    let (n, mut at) = varint(data, 1).ok_or("bad record count")?;
    at = at.saturating_add(1);
    // Each record takes at least two bytes: bound the count by the data.
    if n > to_u64(data.len()) / 2 {
        return Err("record count exceeds the index size");
    }
    let mut records = Vec::new();
    for _ in 0..n {
        let (unpadded, l1) = varint(data, at).ok_or("bad record")?;
        at = at.saturating_add(l1);
        let (uncompressed, l2) = varint(data, at).ok_or("bad record")?;
        at = at.saturating_add(l2);
        records.push((unpadded, uncompressed));
    }
    Ok(records)
}

/// Walks streams backwards from the end of the file.
async fn find_streams(cx: &Cx, file: Span) -> Result<Vec<Stream>> {
    let mut streams = Vec::new();
    let mut end = file.len;
    while end > 0 && streams.len() < MAX_STREAMS {
        // Stream padding: zero bytes in multiples of four.
        while end >= 4 {
            let word = cx.read(file.sub(end.saturating_sub(4), 4)).await?;
            if word != [0, 0, 0, 0] {
                break;
            }
            end = end.saturating_sub(4);
        }
        if end == 0 {
            break;
        }
        let footer_at = end
            .checked_sub(12)
            .ok_or_else(|| Diagnostic::malformed("no stream footer").at(file.sub(0, end)))?;
        let footer_span = file.sub(footer_at, 12);
        let footer = crate::fields::parse(cx, footer_span, LE, &(), StreamFooter::layout).await?;
        if footer.magic != "YZ" {
            return Err(Diagnostic::malformed("no stream footer magic").at(footer_span));
        }
        let index_len = (u64::from(footer.backward))
            .saturating_add(1)
            .saturating_mul(4);
        let index_at = footer_at
            .checked_sub(index_len)
            .ok_or_else(|| Diagnostic::malformed("index larger than the file").at(footer_span))?;
        let index = file.sub(index_at, index_len);
        let data = cx.read(index).await?;
        let records = parse_index(&data).map_err(|e| Diagnostic::malformed(e).at(index))?;
        let blocks = records
            .iter()
            .fold(0u64, |a, &(u, _)| a.saturating_add(padded4(u)));
        let start = index_at
            .checked_sub(blocks)
            .and_then(|s| s.checked_sub(12))
            .ok_or_else(|| Diagnostic::malformed("blocks larger than the file").at(index))?;
        streams.push(Stream {
            span: file.sub(start, end.saturating_sub(start)),
            check: footer.check,
            index,
            records: Arc::new(records),
        });
        end = start;
        cx.checkpoint().await;
    }
    streams.reverse();
    Ok(streams)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, StreamHeader::SIZE);
    let streams = match find_streams(&cx, file).await {
        Ok(s) if !s.is_empty() => s,
        Ok(_) => return Err(Diagnostic::malformed("no streams").at(file)),
        Err(e) => {
            // Truncated or damaged: show what the start says.
            cx.emit(stream_header_node(&cx, header_span).await?);
            let body = file.tail(StreamHeader::SIZE);
            cx.emit(Node::new("Compressed data").span(body));
            cx.diag(e);
            cx.annotate("xz (footer missing or damaged)");
            return Ok(());
        }
    };
    let blocks = streams
        .iter()
        .fold(0u64, |a, s| a.saturating_add(to_u64(s.records.len())));
    let size = streams
        .iter()
        .fold(0u64, |a, s| a.saturating_add(s.uncompressed()));
    // The index records the decoded size, so large streams decode lazily.
    cx.emit(crate::formats::content("Decompressed", input, file, crate::codec::Codec::Xz, Some(size)));
    let check = streams.first().map_or(0, |s| s.check);
    let mut summary = format!(
        "xz, {}, {} uncompressed, {}",
        count(blocks, "block", "blocks"),
        human_size(size),
        check_name(check)
    );
    if streams.len() > 1 {
        summary = format!("{summary}, {} streams", streams.len());
    }
    cx.annotate(summary);

    if let [stream] = streams.as_slice() {
        if stream.span.offset > file.offset {
            cx.diag(Diagnostic::warning("data before the first stream"));
        }
        return emit_stream(&cx, input, stream).await;
    }
    let mut pos = 0u64;
    for (i, stream) in streams.iter().enumerate() {
        let rel = stream.span.offset.saturating_sub(file.offset);
        if rel > pos {
            cx.push(Node::new("Stream padding").span(file.sub(pos, rel.saturating_sub(pos))))
                .await;
        }
        cx.push(
            Node::new(format!("Stream {i}"))
                .span(stream.span)
                .summary(format!(
                    "{}, {} uncompressed",
                    count(to_u64(stream.records.len()), "block", "blocks"),
                    human_size(stream.uncompressed())
                ))
                .lazy(stream_node, (input, stream.clone())),
        )
        .await;
        pos = rel.saturating_add(stream.span.len);
    }
    if pos < file.len {
        cx.push(Node::new("Stream padding").span(file.tail(pos)))
            .await;
    }
    Ok(())
}

async fn stream_node(cx: Cx, (input, stream): (Input, Stream)) -> Result<()> {
    emit_stream(&cx, input, &stream).await
}

async fn stream_header_node(cx: &Cx, span: Span) -> Result<Node> {
    let data = cx.read_avail(span).await?;
    let mut node = StreamHeader::node("Stream header", span, LE);
    if let (Some(flags), Some(stored)) = (data.get(6..8), u32_le(&data, 8)) {
        node = verify(node, crc32(flags), stored);
    }
    Ok(node)
}

fn verify(node: Node, computed: u32, stored: u32) -> Node {
    if computed == stored {
        node.summary("CRC valid")
    } else {
        node.diag(Diagnostic::warning(format!(
            "CRC32 mismatch: computed {computed:#010x}"
        )))
    }
}

async fn emit_stream(cx: &Cx, input: Input, stream: &Stream) -> Result<()> {
    let span = stream.span;
    cx.emit(stream_header_node(cx, span.sub(0, StreamHeader::SIZE)).await?);
    let blocks_len = stream
        .index
        .offset
        .saturating_sub(span.offset.saturating_add(12));
    let n = to_u64(stream.records.len());
    cx.emit(
        Node::new("Blocks")
            .span(span.sub(12, blocks_len))
            .summary(count(n, "block", "blocks"))
            .lazy(blocks, (input, stream.clone())),
    );
    cx.emit(
        Node::new("Index")
            .span(stream.index)
            .summary(count(n, "record", "records"))
            .lazy(index, stream.index),
    );
    let footer_span = Span::new(span.source, stream.index.end(), 12);
    let footer = cx.read_avail(footer_span).await?;
    let mut node = StreamFooter::node("Stream footer", footer_span, LE);
    if let (Some(covered), Some(stored)) = (footer.get(4..10), u32_le(&footer, 0)) {
        node = verify(node, crc32(covered), stored);
    }
    cx.emit(node);
    Ok(())
}

async fn blocks(cx: Cx, (input, stream): (Input, Stream)) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(stream.records.len())));
    let mut at = stream.span.offset.saturating_add(12);
    for (i, &(unpadded, uncompressed)) in stream.records.iter().enumerate() {
        let len = padded4(unpadded);
        let span = Span::new(stream.span.source, at, len);
        cx.push(
            Node::new(format!("Block {i}"))
                .span(span)
                .summary(format!(
                    "{} → {}",
                    human_size(unpadded),
                    human_size(uncompressed)
                ))
                .lazy(block, (input, span, unpadded, stream.check)),
        )
        .await;
        at = at.saturating_add(len);
    }
    Ok(())
}

/// Helper for building nodes over varint-encoded structures in memory.
struct Reader<'a> {
    data: &'a [u8],
    base: Span,
    at: usize,
}

impl Reader<'_> {
    fn span(&self, from: usize) -> Span {
        self.base
            .sub(to_u64(from), to_u64(self.at.saturating_sub(from)))
    }

    fn u8(&mut self, name: &'static str) -> Option<(u8, Node)> {
        let from = self.at;
        let v = *self.data.get(self.at)?;
        self.at = self.at.saturating_add(1);
        Some((
            v,
            Node::new(name).span(self.span(from)).value(uint(v.into())),
        ))
    }

    fn varint(&mut self, name: &'static str) -> Option<(u64, Node)> {
        let from = self.at;
        let (v, len) = varint(self.data, self.at)?;
        self.at = self.at.saturating_add(len);
        Some((v, Node::new(name).span(self.span(from)).value(uint(v))))
    }

    fn bytes(&mut self, name: &'static str, n: u64) -> Option<(Vec<u8>, Node)> {
        let from = self.at;
        let end = from.checked_add(to_usize(n))?;
        let v = self.data.get(from..end)?.to_vec();
        self.at = end;
        Some((
            v.clone(),
            Node::new(name).span(self.span(from)).value(Value::Bytes(v)),
        ))
    }
}

fn filter_summary(id: u64, props: &[u8]) -> Option<String> {
    let p = props.first().copied();
    match id {
        0x21 => p
            .and_then(lzma2_dict)
            .map(|d| format!("dictionary {}", human_size(d))),
        0x03 => p.map(|d| format!("distance {}", u16::from(d).saturating_add(1))),
        0x04..=0x0b => u32_le(props, 0).map(|o| format!("start offset {o:#x}")),
        _ => None,
    }
}

async fn block(cx: Cx, (_input, span, unpadded, check): (Input, Span, u64, u8)) -> Result<()> {
    let first = cx.read(span.sub(0, 1)).await?;
    let header_len = u64::from(first.first().copied().unwrap_or(0))
        .saturating_add(1)
        .saturating_mul(4);
    let header_span = span.sub(0, header_len);
    let data = cx.read(header_span).await?;
    cx.emit(
        Node::new("Block header")
            .span(header_span)
            .lazy(block_header, header_span),
    );
    let filters = block_filters(&data);
    let codec = filters
        .last()
        .and_then(|&id| crate::value::lookup(FILTERS, id))
        .unwrap_or("unknown filter");
    let check_len = check_size(check);
    let compressed = unpadded
        .saturating_sub(header_len)
        .saturating_sub(check_len);
    let payload = span.sub(header_len, compressed);
    let mut node = Node::new("Compressed data").span(payload);
    let _ = codec;
    let chain: Vec<&str> = filters
        .iter()
        .map(|&id| crate::value::lookup(FILTERS, id).unwrap_or("?"))
        .collect();
    node = node.summary(format!("{}, {}", chain.join(" + "), human_size(compressed)));
    cx.emit(node);
    let pad_at = header_len.saturating_add(compressed);
    let pad = padded4(pad_at).saturating_sub(pad_at);
    if pad > 0 {
        cx.emit(Node::new("Block padding").span(span.sub(pad_at, pad)));
    }
    if check_len > 0 {
        let at = pad_at.saturating_add(pad);
        let bytes = cx.read_avail(span.sub(at, check_len)).await?;
        cx.emit(
            Node::new("Check")
                .span(span.sub(at, check_len))
                .value(Value::Bytes(bytes))
                .summary(check_name(check)),
        );
    }
    Ok(())
}

/// Filter IDs in a block header.
fn block_filters(data: &[u8]) -> Vec<u64> {
    let mut out = Vec::new();
    let Some(&flags) = data.get(1) else {
        return out;
    };
    let mut at = 2usize;
    for bit in [0x40u8, 0x80] {
        if flags & bit != 0 {
            let Some((_, len)) = varint(data, at) else {
                return out;
            };
            at = at.saturating_add(len);
        }
    }
    for _ in 0..=(flags & 3) {
        let Some((id, l1)) = varint(data, at) else {
            break;
        };
        at = at.saturating_add(l1);
        let Some((size, l2)) = varint(data, at) else {
            break;
        };
        at = at.saturating_add(l2).saturating_add(to_usize(size));
        out.push(id);
    }
    out
}

async fn block_header(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader {
        data: &data,
        base: span,
        at: 0,
    };
    let bad = || Diagnostic::malformed("bad block header").at(span);
    let (_, node) = r.u8("Header size").ok_or_else(bad)?;
    cx.emit(node.summary(format!("{} bytes", span.len)));
    let (flags, node) = r.u8("Flags").ok_or_else(bad)?;
    let filters = u64::from(flags & 3).saturating_add(1);
    let mut parts = vec![count(filters, "filter", "filters")];
    if flags & 0x40 != 0 {
        parts.push("compressed size present".to_owned());
    }
    if flags & 0x80 != 0 {
        parts.push("uncompressed size present".to_owned());
    }
    cx.emit(node.value(hex(flags.into())).summary(parts.join(", ")));
    if flags & 0x40 != 0 {
        let (v, node) = r.varint("Compressed size").ok_or_else(bad)?;
        cx.emit(node.summary(human_size(v)));
    }
    if flags & 0x80 != 0 {
        let (v, node) = r.varint("Uncompressed size").ok_or_else(bad)?;
        cx.emit(node.summary(human_size(v)));
    }
    for _ in 0..filters {
        let from = r.at;
        let (id, id_node) = r.varint("Filter ID").ok_or_else(bad)?;
        let (size, size_node) = r.varint("Properties size").ok_or_else(bad)?;
        let (props, props_node) = r.bytes("Properties", size).ok_or_else(bad)?;
        let name = crate::value::lookup(FILTERS, id)
            .map_or_else(|| format!("filter {id:#x}"), str::to_owned);
        let mut node = Node::new(name).span(r.span(from));
        if let Some(s) = filter_summary(id, &props) {
            node = node.summary(s);
        }
        let id_node = id_node.value(Value::Enum {
            raw: id,
            bits: 64,
            name: crate::value::lookup(FILTERS, id),
        });
        cx.emit(node.lazy(emit_nodes, Arc::new(vec![id_node, size_node, props_node])));
    }
    let crc_at = span.len.saturating_sub(4);
    let pad = to_u64(r.at);
    if crc_at > pad {
        cx.emit(Node::new("Header padding").span(span.sub(pad, crc_at.saturating_sub(pad))));
    }
    let stored = u32_le(&data, to_usize(crc_at)).unwrap_or(0);
    let node = Node::new("CRC32")
        .span(span.sub(crc_at, 4))
        .value(hex(stored.into()));
    let covered = data.get(..to_usize(crc_at)).unwrap_or_default();
    cx.emit(verify(node, crc32(covered), stored));
    Ok(())
}

async fn index(cx: Cx, span: Span) -> Result<()> {
    let data = cx.read(span).await?;
    let mut r = Reader {
        data: &data,
        base: span,
        at: 0,
    };
    let bad = || Diagnostic::malformed("bad index").at(span);
    let (_, node) = r.u8("Index indicator").ok_or_else(bad)?;
    cx.emit(node);
    let (n, node) = r.varint("Number of records").ok_or_else(bad)?;
    cx.emit(node);
    let crc_at = span.len.saturating_sub(4);
    for i in 0..n {
        let from = r.at;
        let (unpadded, a) = r.varint("Unpadded size").ok_or_else(bad)?;
        let (uncompressed, b) = r.varint("Uncompressed size").ok_or_else(bad)?;
        cx.push(
            Node::new(format!("Record {i}"))
                .span(r.span(from))
                .summary(format!(
                    "{} → {}",
                    human_size(unpadded),
                    human_size(uncompressed)
                ))
                .lazy(emit_nodes, Arc::new(vec![a, b])),
        )
        .await;
    }
    let pad = to_u64(r.at);
    if crc_at > pad {
        cx.emit(Node::new("Index padding").span(span.sub(pad, crc_at.saturating_sub(pad))));
    }
    let stored = u32_le(&data, to_usize(crc_at)).unwrap_or(0);
    let node = Node::new("CRC32")
        .span(span.sub(crc_at, 4))
        .value(hex(stored.into()));
    let covered = data.get(..to_usize(crc_at)).unwrap_or_default();
    cx.emit(verify(node, crc32(covered), stored));
    Ok(())
}
