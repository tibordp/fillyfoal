//! Disk images, partition tables, volume headers and filesystems.
//!
//! Containers and partition tables present their payloads as embedded inputs
//! (`embedded(name, input.nested(span))`), so whatever lives inside a
//! partition or a virtual disk is detected and dissected in turn.
//! Filesystems present directories as lazily expanded, paged trees; a file's
//! content is its extent if contiguous, or a piecewise source assembled from
//! its fragments ([`Cx::add_pieces`]) otherwise.

pub mod apfs;
pub mod apm;
pub mod bfs;
pub mod bitlocker;
pub mod bsdlabel;
pub mod btrfs;
pub mod erofs;
pub mod exfat;
pub mod ext;
pub mod f2fs;
pub mod fat;
pub mod gpt;
pub mod hfs;
pub mod jfs;
pub mod luks;
pub mod lvm;
pub mod mbr;
pub mod mdraid;
pub mod minix;
pub mod nilfs;
pub mod ntfs;
pub mod parallels;
pub mod ptypes;
pub mod qcow;
pub mod swap;
pub mod uefi;
pub mod ufs;
pub mod vdi;
pub mod vhd;
pub mod vhdx;
pub mod vmdk;
pub mod xfs;
pub mod zfs;

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

/// Collects the pieces of a sparse or fragmented byte stream (a file with
/// holes, a virtual disk with unallocated blocks), merging adjacent pieces.
/// Holes are [`Span::zeros`] pieces.
pub struct PieceList {
    anchor: Span,
    pieces: Vec<Span>,
    len: u64,
}

impl PieceList {
    /// `anchor` identifies the stream (its metadata) for memoization and
    /// diagnostics.
    pub fn new(anchor: Span) -> Self {
        PieceList {
            anchor,
            pieces: Vec::new(),
            len: 0,
        }
    }

    pub fn len(&self) -> u64 {
        self.len
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    pub fn data(&mut self, piece: Span) {
        if piece.is_empty() {
            return;
        }
        self.len = self.len.saturating_add(piece.len);
        match self.pieces.last_mut() {
            Some(prev)
                if prev.source == crate::span::SourceId::ZEROS
                    && piece.source == crate::span::SourceId::ZEROS =>
            {
                prev.len = prev.len.saturating_add(piece.len);
            }
            Some(prev) if prev.source == piece.source && prev.end() == piece.offset => {
                prev.len = prev.len.saturating_add(piece.len);
            }
            _ => self.pieces.push(piece),
        }
    }

    /// Appends `len` zero bytes.
    pub fn hole(&mut self, _cx: &Cx, len: u64) -> Result<()> {
        self.data(Span::zeros(len));
        Ok(())
    }

    /// The pieces collected so far.
    pub fn pieces(&self) -> &[Span] {
        &self.pieces
    }

    /// Registers the stream as a source (or returns its single piece).
    pub fn finish(self, cx: &Cx, transform: &'static str) -> Result<Span> {
        assemble(cx, self.anchor, transform, self.pieces)
    }
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

/// CRC-32C (Castagnoli), as used by ext4, XFS, Btrfs and VHDX.
pub fn crc32c(data: &[u8]) -> u32 {
    crc32c_update(!0, data) ^ !0
}

/// Raw CRC-32C register update (no initial or final inversion).
pub fn crc32c_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0x82f6_3b78
            } else {
                crc >> 1
            };
        }
    }
    crc
}

/// APFS's Fletcher-64 checksum of a block whose first 8 bytes hold the
/// checksum (they are skipped). Returns the value to store there.
pub fn fletcher64(block: &[u8]) -> u64 {
    const MOD: u64 = 0xffff_ffff;
    let (mut lo, mut hi) = (0u64, 0u64);
    for word in block.get(8..).unwrap_or_default().as_chunks::<4>().0 {
        lo = lo.saturating_add(u32::from_le_bytes(*word).into()) % MOD;
        hi = hi.saturating_add(lo) % MOD;
    }
    let c1 = MOD.saturating_sub(lo.saturating_add(hi) % MOD);
    let c2 = MOD.saturating_sub(lo.saturating_add(c1) % MOD);
    c2 << 32 | c1
}

/// A Unix mode as `ls -l` shows it, e.g. `drwxr-xr-x`.
pub fn unix_mode(mode: u32) -> String {
    let kind = match mode & 0o170_000 {
        0o040_000 => 'd',
        0o100_000 => '-',
        0o120_000 => 'l',
        0o020_000 => 'c',
        0o060_000 => 'b',
        0o010_000 => 'p',
        0o140_000 => 's',
        _ => '?',
    };
    let mut out = String::from(kind);
    for shift in [6u32, 3, 0] {
        let bits = (mode >> shift) & 7;
        out.push(if bits & 4 != 0 { 'r' } else { '-' });
        out.push(if bits & 2 != 0 { 'w' } else { '-' });
        let special = match shift {
            6 => mode & 0o4000 != 0,
            3 => mode & 0o2000 != 0,
            _ => mode & 0o1000 != 0,
        };
        out.push(match (bits & 1 != 0, special, shift) {
            (true, true, 0) => 't',
            (false, true, 0) => 'T',
            (true, true, _) => 's',
            (false, true, _) => 'S',
            (true, false, _) => 'x',
            (false, false, _) => '-',
        });
    }
    out
}

/// A GUID in Microsoft mixed-endian layout from raw bytes (zero-padded).
pub fn guid_le(b: &[u8]) -> crate::value::Guid {
    let get = |i: usize| b.get(i).copied().unwrap_or(0);
    let mut data4 = [0u8; 8];
    for (i, d) in data4.iter_mut().enumerate() {
        *d = get(i.saturating_add(8));
    }
    crate::value::Guid {
        data1: u32::from_le_bytes([get(0), get(1), get(2), get(3)]),
        data2: u16::from_le_bytes([get(4), get(5)]),
        data3: u16::from_le_bytes([get(6), get(7)]),
        data4,
    }
}

/// Rounds `v` up to a multiple of `a`, saturating instead of overflowing.
pub fn align(v: u64, a: u64) -> u64 {
    v.checked_next_multiple_of(a).unwrap_or(u64::MAX)
}

/// Raw CRC-32 (IEEE polynomial, reflected) register update, without
/// initial or final inversion (LVM and F2FS seed it themselves).
pub fn crc32_update(mut crc: u32, data: &[u8]) -> u32 {
    for &byte in data {
        crc ^= u32::from(byte);
        for _ in 0..8 {
            crc = if crc & 1 != 0 {
                crc >> 1 ^ 0xedb8_8320
            } else {
                crc >> 1
            };
        }
    }
    crc
}
