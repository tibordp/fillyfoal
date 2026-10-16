//! BorgBackup (1.x) hash indexes: a repository's `index.<n>` (where each
//! object is: segment and offset) and a client cache's `chunks` (each
//! chunk's reference count and sizes).
//!
//! The file is the magic `BORG_IDX`, the number of entries and of buckets
//! (little-endian 32-bit), the key size and the value size (one byte
//! each), then the open-addressing hash table itself: one bucket per slot,
//! the key (a 32-byte object ID) followed by the value. A bucket whose
//! value starts with `0xffffffff` is empty, with `0xfffffffe` a deleted
//! entry. Values are little-endian 32-bit words: segment and offset (value
//! size 8) or reference count, size and compressed size (value size 12).
//!
//! The layout is from Borg 1.2's `_hashindex.c` and `hashindex.pyx`
//! (BSD-3-Clause), read for facts only; checked against an `index.5` and a
//! `chunks` cache written by Borg 1.2.4.

use crate::bytes::{to_u64, to_usize, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::fmt::{grouped_count, hex_lower, size};
use crate::formats::util::val::{hex, uint};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::Value;

const LE: Endian = Endian::Little;
const EMPTY: u32 = 0xffff_ffff;
const DELETED: u32 = 0xffff_fffe;
/// Buckets read at a time while listing.
const BATCH: u64 = 256;

pub static FORMAT: Format = Format {
    name: "borg-index",
    title: "BorgBackup hash index",
    extensions: &[],
    mime: "application/x-borg-index",
    probe: Probe::Magic(&[(0, b"BORG_IDX")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    /// `HashHeader` (packed).
    pub struct Header {
        _magic: ascii[8] "Magic",
        entries: i32 "Entries",
        buckets: i32 "Buckets",
        key_size: u8 "Key size",
        value_size: u8 "Value size",
    }
}

/// What the bucket walk needs.
#[derive(Clone, Copy)]
struct Table {
    buckets: Span,
    count: u64,
    key: u64,
    value: u64,
    entries: u64,
}

impl Table {
    fn bucket(&self) -> u64 {
        self.key.saturating_add(self.value)
    }
}

fn kind(value: u64) -> &'static str {
    match value {
        8 => "repository index",
        12 => "chunks cache",
        _ => "hash index",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Header::SIZE);
    let h = parse(&cx, span, LE, &(), Header::layout).await?;
    let mut header = Header::node("Header", span, LE);
    let key = u64::from(h.key_size);
    let value = u64::from(h.value_size);
    let count = u64::try_from(h.buckets).unwrap_or(0);
    let entries = u64::try_from(h.entries).unwrap_or(0);
    let buckets = file.tail(Header::SIZE);
    let bucket = key.saturating_add(value);
    if value < 4 || key == 0 {
        header = header.diag(Diagnostic::malformed(format!(
            "{key}-byte keys and {value}-byte values"
        )));
        cx.emit(header);
        return Ok(());
    }
    let expected = count.saturating_mul(bucket);
    if expected != buckets.len {
        header = header.diag(Diagnostic::malformed(format!(
            "{} of {bucket} bytes need {}, the file has {}",
            grouped_count(count, "bucket", "buckets"),
            size(expected),
            size(buckets.len),
        )));
    }
    if entries > count {
        header = header.diag(Diagnostic::malformed("more entries than buckets"));
    }
    cx.emit(header);
    cx.annotate(format!(
        "Borg {}, {} in {}",
        kind(value),
        grouped_count(entries, "entry", "entries"),
        grouped_count(count, "bucket", "buckets"),
    ));
    let table = Table {
        buckets,
        count: count.min(buckets.len.checked_div(bucket).unwrap_or(0)),
        key,
        value,
        entries,
    };
    cx.emit(
        Node::new("Entries")
            .span(buckets)
            .summary(grouped_count(entries, "entry", "entries"))
            .desc("The buckets in use, in table order")
            .lazy(list, table),
    );
    Ok(())
}

/// The value's words, by value size.
fn describe(value: &[u8]) -> String {
    let w = |i: usize| u32_le(value, i.saturating_mul(4)).unwrap_or(0);
    match value.len() {
        8 => format!("segment {}, offset {:#x}", w(0), w(1)),
        12 => format!(
            "{} {}, {}, {} compressed",
            w(0),
            if w(0) == 1 { "reference" } else { "references" },
            size(u64::from(w(1))),
            size(u64::from(w(2))),
        ),
        _ => format!("value {}", hex_lower(value)),
    }
}

async fn list(cx: Cx, t: Table) -> Result<()> {
    let bucket = t.bucket();
    let (mut i, mut used, mut deleted) = cx.resume::<(u64, u64, u64)>().unwrap_or((0, 0, 0));
    while i < t.count {
        let n = BATCH.min(t.count.saturating_sub(i));
        let batch = cx
            .read(
                t.buckets
                    .sub_exact(i.saturating_mul(bucket), n.saturating_mul(bucket))?,
            )
            .await?;
        for raw in batch.chunks_exact(to_usize(bucket)) {
            let at = i;
            i = i.saturating_add(1);
            let (k, v) = raw.split_at(to_usize(t.key).min(raw.len()));
            match u32_le(v, 0) {
                Some(EMPTY) => continue,
                Some(DELETED) => {
                    deleted = deleted.saturating_add(1);
                    continue;
                }
                _ => {}
            }
            let mark = (at, used, deleted);
            cx.mark(move || mark);
            used = used.saturating_add(1);
            let span = t.buckets.sub(at.saturating_mul(bucket), bucket);
            let id = hex_lower(k);
            cx.push(
                Node::new(format!("{}…", id.get(..16).unwrap_or(&id)))
                    .span(span)
                    .value(Value::Text(id))
                    .summary(describe(v))
                    .lazy(fields, (span, t.key, to_u64(v.len()))),
            )
            .await;
        }
    }
    if deleted > 0 {
        cx.diag(Diagnostic::note(format!(
            "{} not listed",
            grouped_count(deleted, "deleted entry", "deleted entries")
        )));
    }
    if used != t.entries {
        cx.diag(Diagnostic::malformed(format!(
            "the header counts {} but {} in use",
            grouped_count(t.entries, "entry", "entries"),
            grouped_count(used, "bucket is", "buckets are"),
        )));
    }
    Ok(())
}

async fn fields(cx: Cx, (span, key, value): (Span, u64, u64)) -> Result<()> {
    let raw = cx.read(span).await?;
    cx.emit(
        Node::new("Key")
            .span(span.sub(0, key))
            .value(Value::Text(hex_lower(
                raw.get(..to_usize(key)).unwrap_or_default(),
            ))),
    );
    let names: &[&'static str] = match value {
        8 => &["Segment", "Offset"],
        12 => &["Reference count", "Size", "Compressed size"],
        _ => &[],
    };
    if names.is_empty() {
        cx.emit(Node::new("Value").span(span.sub(key, value)));
        return Ok(());
    }
    for (i, name) in (0u64..).zip(names) {
        let off = key.saturating_add(i.saturating_mul(4));
        let w = u32_le(&raw, to_usize(off)).unwrap_or(0);
        let node = Node::new(*name).span(span.sub(off, 4));
        cx.emit(match *name {
            "Offset" => node.value(hex(w, 32)),
            "Size" | "Compressed size" => node.value(uint(w, 32)).summary(size(u64::from(w))),
            _ => node.value(uint(w, 32)),
        });
    }
    Ok(())
}
