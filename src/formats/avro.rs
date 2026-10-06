//! Apache Avro object container files: a header with a metadata map (the
//! schema and codec) and a sync marker, then blocks of serialized objects,
//! each followed by the sync marker.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Codec, Format, Input, Probe, content};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

pub static FORMAT: Format = Format {
    name: "avro",
    title: "Apache Avro object container",
    extensions: &["avro"],
    mime: "application/avro",
    probe: Probe::Magic(&[(0, b"Obj\x01")]),
    dissect: crate::expander!(dissect: Input),
};

/// Metadata entries read.
const MAX_ENTRIES: usize = 4096;

/// A zigzag-encoded variable-length long at `at`: value and length.
fn long(data: &[u8], at: usize) -> Option<(i64, usize)> {
    let (raw, n) = crate::bytes::uleb128(data.get(at..)?)?;
    Some((((raw >> 1) as i64) ^ 0i64.wrapping_sub((raw & 1) as i64), n))
}

/// Reads a long through the cursor position `pos` of `span`.
async fn read_long(cx: &Cx, span: Span, pos: u64) -> Result<(i64, u64)> {
    let data = cx.read_avail(span.sub(pos, 10)).await?;
    long(&data, 0).map(|(v, n)| (v, to_u64(n))).ok_or_else(|| {
        Diagnostic::malformed("invalid variable-length integer").at(span.sub(pos, 10))
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 4))
            .value(Value::Bytes(b"Obj\x01".to_vec())),
    );
    // Metadata map: blocks of (count, [size,] entries), ending with count 0.
    let mut pos = 4u64;
    let mut entries: Vec<(String, Vec<u8>, Span)> = Vec::new();
    let map_start = pos;
    loop {
        let (count, n) = read_long(&cx, file, pos).await?;
        pos = pos.saturating_add(n);
        if count == 0 {
            break;
        }
        if count < 0 {
            let (_, n) = read_long(&cx, file, pos).await?;
            pos = pos.saturating_add(n);
        }
        for _ in 0..count.unsigned_abs() {
            if entries.len() >= MAX_ENTRIES {
                return Err(
                    Diagnostic::limit("too many metadata entries").at(file.sub(map_start, 0))
                );
            }
            let start = pos;
            let (klen, n) = read_long(&cx, file, pos).await?;
            pos = pos.saturating_add(n);
            let key = cx.read(file.sub_exact(pos, klen.unsigned_abs())?).await?;
            pos = pos.saturating_add(klen.unsigned_abs());
            let (vlen, n) = read_long(&cx, file, pos).await?;
            pos = pos.saturating_add(n);
            let value_span = file.sub_exact(pos, vlen.unsigned_abs())?;
            let value = cx.read(value_span.sub(0, 1 << 20)).await?;
            pos = pos.saturating_add(vlen.unsigned_abs());
            entries.push((
                String::from_utf8_lossy(&key).into_owned(),
                value,
                file.sub(start, pos.saturating_sub(start)),
            ));
        }
    }
    let mut meta = Node::new("Metadata")
        .span(file.sub(map_start, pos.saturating_sub(map_start)))
        .summary(format!("{} entries", entries.len()));
    let codec = entries
        .iter()
        .find(|(k, _, _)| k == "avro.codec")
        .map_or_else(
            || "null".to_owned(),
            |(_, v, _)| String::from_utf8_lossy(v).into_owned(),
        );
    let schema = entries
        .iter()
        .find(|(k, _, _)| k == "avro.schema")
        .map(|(_, v, _)| String::from_utf8_lossy(v).into_owned());
    meta = meta.lazy(metadata, std::sync::Arc::new(entries));
    cx.emit(meta);
    let sync_span = file.sub(pos, 16);
    let sync = cx.read(sync_span).await?;
    cx.emit(
        Node::new("Sync marker")
            .span(sync_span)
            .value(Value::Bytes(sync.clone())),
    );
    pos = pos.saturating_add(16);

    let mut summary = format!("Avro object container, codec {codec}");
    if let Some(name) = schema.as_deref().and_then(schema_name) {
        summary = format!("{summary}, schema {name}");
    }
    cx.annotate(summary);
    cx.emit(
        Node::new("Blocks")
            .span(file.tail(pos))
            .lazy(blocks, (input, pos, sync, codec)),
    );
    Ok(())
}

/// The top-level "name" of a JSON schema (a light scan, not a JSON parser).
fn schema_name(schema: &str) -> Option<String> {
    let at = schema.find("\"name\"")?;
    let rest = schema.get(at.saturating_add(6)..)?;
    let start = rest.find('"')?.saturating_add(1);
    let len = rest.get(start..)?.find('"')?;
    rest.get(start..start.saturating_add(len))
        .map(str::to_owned)
}

async fn metadata(cx: Cx, entries: std::sync::Arc<Vec<(String, Vec<u8>, Span)>>) -> Result<()> {
    for (key, value, span) in entries.iter() {
        let node = match std::str::from_utf8(value) {
            Ok(text) => Node::new(key.clone()).value(Value::Text(text.to_owned())),
            Err(_) => {
                Node::new(key.clone()).value(Value::Bytes(value.iter().take(32).copied().collect()))
            }
        };
        cx.push(node.span(*span)).await;
    }
    Ok(())
}

async fn blocks(cx: Cx, (input, start, sync, codec): (Input, u64, Vec<u8>, String)) -> Result<()> {
    let file = input.span;
    let mut pos = start;
    let mut index = 0u64;
    while pos < file.len {
        let block_start = pos;
        let (count, n) = read_long(&cx, file, pos).await?;
        pos = pos.saturating_add(n);
        let (size, n) = read_long(&cx, file, pos).await?;
        pos = pos.saturating_add(n);
        let size = size.unsigned_abs();
        let data = file.sub(pos, size);
        pos = pos.saturating_add(size);
        let marker = cx.read_avail(file.sub(pos, 16)).await?;
        pos = pos.saturating_add(16);
        let whole = file.sub(block_start, pos.saturating_sub(block_start));
        let mut node = Node::new(format!("Block {index}"))
            .span(whole)
            .summary(format!("{count} objects, {size} bytes"))
            .lazy(block, (input, whole, data, count, codec.clone()));
        if marker != sync {
            node = node.diag(Diagnostic::malformed(
                "sync marker does not match the header",
            ));
        }
        if data.len < size {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, size),
                data.len,
            ));
        }
        cx.push(node).await;
        index = index.saturating_add(1);
        if marker != sync {
            break;
        }
    }
    Ok(())
}

async fn block(
    cx: Cx,
    (input, whole, data, count, codec): (Input, Span, Span, i64, String),
) -> Result<()> {
    let header_len = data.offset.saturating_sub(whole.offset);
    let (_, count_len) = read_long(&cx, whole, 0).await?;
    cx.emit(
        Node::new("Object count")
            .span(whole.sub(0, count_len))
            .value(Value::Int {
                value: count,
                bits: 64,
            }),
    );
    cx.emit(
        Node::new("Size")
            .span(whole.sub(count_len, header_len.saturating_sub(count_len)))
            .value(Value::UInt {
                value: data.len,
                bits: 64,
                radix: Radix::Dec,
            }),
    );
    let node = match codec.as_str() {
        "null" => content("Objects", input, data, Codec::Stored, None),
        "deflate" => content("Objects", input, data, Codec::Deflate, None),
        "bzip2" => content("Objects", input, data, Codec::Bzip2, None),
        "xz" => content("Objects", input, data, Codec::Xz, None),
        "zstandard" => content("Objects", input, data, Codec::Zstd, None),
        // Raw Snappy followed by a big-endian CRC-32 of the decoded data.
        "snappy" => content(
            "Objects",
            input,
            data.sub(0, data.len.saturating_sub(4)),
            Codec::Snappy,
            None,
        ),
        other => Node::new("Objects")
            .span(data)
            .diag(Diagnostic::unsupported(format!("{other} codec"))),
    };
    cx.emit(node.summary(format!("{} bytes", data.len)));
    cx.emit(Node::new("Sync marker").span(whole.tail(whole.len.saturating_sub(16))));
    Ok(())
}
