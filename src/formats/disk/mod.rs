//! Disk images, partition tables, volume headers and filesystems.
//!
//! Containers and partition tables present their payloads as embedded inputs
//! (`embedded(name, input.nested(span))`), so whatever lives inside a
//! partition or a virtual disk is detected and dissected in turn.
//! Filesystems present directories as lazily expanded, paged trees; a file's
//! content is its extent if contiguous, or a piecewise source assembled from
//! its fragments ([`Cx::add_pieces`]) otherwise.

pub mod fat;
pub mod gpt;
pub mod mbr;
pub mod ptypes;

use std::borrow::Cow;
use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Codec, Input, content, embedded};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::Value;

/// Human-readable size: `512 bytes`, `64 KiB`, `1.5 GiB`.
pub fn size(n: u64) -> String {
    const UNITS: [&str; 6] = ["KiB", "MiB", "GiB", "TiB", "PiB", "EiB"];
    if n < 1024 {
        return format!("{n} bytes");
    }
    let mut div = 1024u64;
    let mut unit = 0usize;
    while unit < 5 && n.checked_div(div).is_some_and(|q| q >= 1024) {
        div = div.saturating_mul(1024);
        unit = unit.saturating_add(1);
    }
    let whole = n.checked_div(div).unwrap_or(0);
    let tenths = n
        .checked_rem(div)
        .unwrap_or(0)
        .saturating_mul(10)
        .checked_div(div)
        .unwrap_or(0);
    let name = UNITS.get(unit).copied().unwrap_or("?");
    if tenths == 0 {
        format!("{whole} {name}")
    } else {
        format!("{whole}.{tenths} {name}")
    }
}

/// A UUID stored in RFC 4122 (big-endian) byte order.
pub fn uuid(b: &[u8]) -> String {
    let hex = |r: std::ops::Range<usize>| -> String {
        b.get(r)
            .unwrap_or_default()
            .iter()
            .map(|x| format!("{x:02x}"))
            .collect()
    };
    format!(
        "{}-{}-{}-{}-{}",
        hex(0..4),
        hex(4..6),
        hex(6..8),
        hex(8..10),
        hex(10..16)
    )
}

/// Decorator for `bytes[16]` record fields holding an RFC 4122 UUID.
#[allow(clippy::ptr_arg)] // used as a `Field::with` decorator
pub fn uuid_value(b: &Vec<u8>, node: Node) -> Node {
    node.value(Value::Text(uuid(b)))
}

/// Decorator showing a byte count in a human-readable way.
pub fn size_summary<T: Copy + Into<u64>>(v: &T, node: Node) -> Node {
    node.summary(size((*v).into()))
}

/// Text value of a NUL-padded byte string, decoded lossily.
pub fn text(b: &[u8]) -> Value {
    Value::Text(crate::text::until_nul(b))
}

/// A partition or volume payload, detected and dissected on expansion. A
/// region that starts where its container starts is not embedded: it would
/// be detected as the container again (a self-similar, exponential tree).
pub fn volume(name: impl Into<Cow<'static, str>>, input: &Input, span: Span) -> Node {
    if span.is_empty() {
        return Node::new(name).span(span).diag(Diagnostic::note("empty"));
    }
    if span.source == input.span.source && span.offset == input.span.offset {
        return Node::new(name).span(span).diag(Diagnostic::malformed(
            "starts at the beginning of its container; not dissected",
        ));
    }
    embedded(name, input.nested(span))
}

/// Merges physically adjacent pieces and clips the total to `size`.
pub fn coalesce(pieces: impl IntoIterator<Item = Span>, size: u64) -> Vec<Span> {
    let mut left = size;
    let mut out: Vec<Span> = Vec::new();
    for piece in pieces {
        if left == 0 {
            break;
        }
        let take = piece.len.min(left);
        left = left.saturating_sub(take);
        match out.last_mut() {
            Some(prev) if prev.source == piece.source && prev.end() == piece.offset => {
                prev.len = prev.len.saturating_add(take);
            }
            _ => out.push(Span::new(piece.source, piece.offset, take)),
        }
    }
    out
}

/// The bytes of a file stored in `pieces` (already in file order and clipped
/// to the file size). Contiguous content is a plain sub-span; fragmented
/// content becomes a piecewise source keyed by `anchor` (a span identifying
/// the file, e.g. its directory entry or inode) and `transform`.
pub fn assemble(cx: &Cx, anchor: Span, transform: &'static str, pieces: Vec<Span>) -> Result<Span> {
    match pieces.as_slice() {
        [] => Ok(Span::new(anchor.source, anchor.offset, 0)),
        [one] => Ok(*one),
        _ => cx.add_pieces(
            Origin {
                parent: anchor,
                transform,
            },
            pieces,
        ),
    }
}

/// Largest sparse hole materialized as zeros.
const MAX_HOLE: u64 = 64 * 1024 * 1024;

/// A run of zero bytes for sparse files: pieces of one shared zero-filled
/// derived source.
pub fn zeros(cx: &Cx, anchor: Span, len: u64) -> Result<Vec<Span>> {
    const BLOCK: u64 = 64 * 1024;
    if len > MAX_HOLE {
        return Err(Diagnostic::limit(format!(
            "sparse region of {} is not materialized",
            size(len)
        ))
        .at(anchor));
    }
    let zero = cx.add_derived(
        Origin {
            parent: Span::new(anchor.source, 0, 0),
            transform: "zeros",
        },
        vec![0; crate::bytes::to_usize(BLOCK)],
        0,
        None,
    )?;
    let mut out = Vec::new();
    let mut left = len;
    while left > 0 {
        let take = left.min(BLOCK);
        out.push(zero.span.sub(0, take));
        left = left.saturating_sub(take);
    }
    Ok(out)
}

/// Assembled file content: dissected if recognised, otherwise a data leaf.
pub fn content_node(input: &Input, span: Span) -> Node {
    content("Content", *input, span, Codec::Stored, None).summary(size(span.len))
}

/// Lists the fragments of a file, each spanning its bytes.
pub fn fragments_node(name: &'static str, pieces: Vec<Span>) -> Node {
    let total = pieces.iter().map(|p| p.len).fold(0, u64::saturating_add);
    let count = pieces.len();
    Node::new(name)
        .summary(if count == 1 {
            format!("contiguous, {}", size(total))
        } else {
            format!("{count} fragments, {}", size(total))
        })
        .lazy(list_fragments, Arc::new(pieces))
}

async fn list_fragments(cx: Cx, pieces: Arc<Vec<Span>>) -> Result<()> {
    cx.set_count(Count::Exact(crate::bytes::to_u64(pieces.len())));
    let mut logical = 0u64;
    for (i, piece) in pieces.iter().enumerate() {
        cx.push(
            Node::new(format!("Fragment {i}"))
                .span(*piece)
                .summary(format!("file offset {logical:#x}, {}", size(piece.len))),
        )
        .await;
        logical = logical.saturating_add(piece.len);
    }
    Ok(())
}

/// Seconds since the Unix epoch for a proleptic Gregorian date and time.
#[allow(clippy::arithmetic_side_effects)] // i128 cannot overflow for these inputs
pub fn civil_to_unix(year: i64, month: u32, day: u32, hour: u32, min: u32, sec: u32) -> i64 {
    // Howard Hinnant's days_from_civil.
    let y = i128::from(year) - i128::from(month <= 2);
    let era = y.div_euclid(400);
    let yoe = y - era * 400;
    let m = i128::from(month.clamp(1, 12));
    let mp = if m > 2 { m - 3 } else { m + 9 };
    let doy = (153 * mp + 2) / 5 + i128::from(day.clamp(1, 31)) - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    let days = era * 146_097 + doe - 719_468;
    let secs = days * 86_400 + i128::from(hour) * 3600 + i128::from(min) * 60 + i128::from(sec);
    i64::try_from(secs).unwrap_or(i64::MAX)
}

/// MS-DOS date (high 16 bits) and time (low 16 bits), as used by FAT and
/// exFAT, to Unix seconds.
pub fn dos_to_unix(stamp: u32) -> i64 {
    let date = stamp >> 16;
    let time = stamp & 0xffff;
    civil_to_unix(
        1980i64.saturating_add((date >> 9).into()),
        (date >> 5) & 0x0f,
        date & 0x1f,
        time >> 11,
        (time >> 5) & 0x3f,
        (time & 0x1f).saturating_mul(2),
    )
}

/// Decorator for a combined DOS time/date `u32` field.
pub fn dos_stamp(v: &u32, node: Node) -> Node {
    if *v == 0 {
        return node.summary("not set");
    }
    node.value(Value::Timestamp {
        unix_seconds: dos_to_unix(*v),
    })
}

/// Decorator for a DOS date-only `u16` field.
pub fn dos_date(v: &u16, node: Node) -> Node {
    if *v == 0 {
        return node.summary("not set");
    }
    node.value(Value::Timestamp {
        unix_seconds: dos_to_unix(u32::from(*v) << 16),
    })
}

/// Decorator for a Unix-seconds field, keeping 0 as "not set".
pub fn unix_time<T: Copy + Into<u64>>(v: &T, node: Node) -> Node {
    let v: u64 = (*v).into();
    if v == 0 {
        return node.summary("not set");
    }
    node.value(Value::Timestamp {
        unix_seconds: i64::try_from(v).unwrap_or(i64::MAX),
    })
}
