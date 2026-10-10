//! Disk images, partition tables, volume headers and filesystems.
//!
//! Containers and partition tables present their payloads as embedded inputs
//! (`embedded(name, input.nested(span))`), so whatever lives inside a
//! partition or a virtual disk is detected and dissected in turn.
//! Filesystems present directories as lazily expanded, paged trees; a file's
//! content is its extent if contiguous, or a piecewise source assembled from
//! its fragments ([`Cx::add_pieces`]) otherwise.
//!
//! Also here: Apple disk images (`dmg`), ISO 9660 and SquashFS/CramFS.

pub mod apfs;
pub mod apm;
pub mod bfs;
pub mod bitlocker;
pub mod bsdlabel;
pub mod btrfs;
pub mod dmg;
pub mod erofs;
pub mod exfat;
pub mod ext;
pub mod f2fs;
pub mod fat;
pub mod gpt;
pub mod hfs;
pub mod iso9660;
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
pub mod squashfs;
pub mod swap;
pub mod udf;
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

pub use crate::codec::crc::{crc32_update, crc32c, crc32c_update};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Codec, Input, content, embedded};
use crate::node::{Count, Node};
use crate::span::{Origin, Span};
use crate::value::Value;

pub use crate::formats::util::fmt::{size, uuid};

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

/// Pieces handled per checkpoint by the passes over piece lists here.
const PIECES_PER_STEP: usize = 4096;

/// Merges physically adjacent pieces and clips the total to `size`. One
/// synchronous pass: for short lists only (a fork's eight extents, one
/// extent's spared packets); input-sized lists go through
/// [`coalesce_stepped`].
pub fn coalesce(pieces: impl IntoIterator<Item = Span>, size: u64) -> Vec<Span> {
    let mut c = Coalesce::new(size);
    for piece in pieces {
        if !c.push(piece) {
            break;
        }
    }
    c.out
}

/// [`coalesce`] for input-sized lists (cluster chains, run lists), yielding
/// every few thousand pieces.
pub async fn coalesce_stepped(
    cx: &Cx,
    pieces: impl IntoIterator<Item = Span>,
    size: u64,
) -> Vec<Span> {
    let mut c = Coalesce::new(size);
    for (i, piece) in pieces.into_iter().enumerate() {
        if i.is_multiple_of(PIECES_PER_STEP) {
            cx.checkpoint().await;
        }
        if !c.push(piece) {
            break;
        }
    }
    c.out
}

struct Coalesce {
    left: u64,
    out: Vec<Span>,
}

impl Coalesce {
    fn new(size: u64) -> Self {
        Coalesce {
            left: size,
            out: Vec::new(),
        }
    }

    /// Adds a piece; false once `size` bytes are collected.
    fn push(&mut self, piece: Span) -> bool {
        if self.left == 0 {
            return false;
        }
        let take = piece.len.min(self.left);
        self.left = self.left.saturating_sub(take);
        match self.out.last_mut() {
            Some(prev) if prev.source == piece.source && prev.end() == piece.offset => {
                prev.len = prev.len.saturating_add(take);
            }
            _ => self.out.push(Span::new(piece.source, piece.offset, take)),
        }
        true
    }
}

/// The bytes of a file stored in `pieces` (already in file order and clipped
/// to the file size). Contiguous content is a plain sub-span; fragmented
/// content becomes a piecewise source keyed by `anchor` (a span identifying
/// the file, e.g. its directory entry or inode) and `transform`.
pub async fn assemble(
    cx: &Cx,
    anchor: Span,
    transform: &'static str,
    pieces: &[Span],
) -> Result<Span> {
    match pieces {
        [] => Ok(Span::new(anchor.source, anchor.offset, 0)),
        [one] => Ok(*one),
        _ => {
            cx.add_pieces_stepped(
                Origin {
                    parent: anchor,
                    transform,
                },
                pieces,
            )
            .await
        }
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

    /// The pieces collected, without copying them.
    pub fn into_pieces(self) -> Vec<Span> {
        self.pieces
    }

    /// Registers the stream as a source (or returns its single piece).
    pub async fn finish(&self, cx: &Cx, transform: &'static str) -> Result<Span> {
        assemble(cx, self.anchor, transform, &self.pieces).await
    }
}

/// Assembled file content: dissected if recognised, otherwise a data leaf.
pub fn content_node(input: &Input, span: Span) -> Node {
    content("Content", *input, span, Codec::Stored, None).summary(size(span.len))
}

/// Lists the fragments of a file, each spanning its bytes.
pub async fn fragments_node(
    cx: &Cx,
    name: &'static str,
    pieces: impl Into<Arc<Vec<Span>>>,
) -> Node {
    let pieces = pieces.into();
    let mut total = 0u64;
    for chunk in pieces.chunks(PIECES_PER_STEP) {
        cx.checkpoint().await;
        total = chunk.iter().map(|p| p.len).fold(total, u64::saturating_add);
    }
    let count = pieces.len();
    Node::new(name)
        .summary(if count == 1 {
            format!("contiguous, {}", size(total))
        } else {
            format!("{count} fragments, {}", size(total))
        })
        .lazy(list_fragments, pieces)
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

pub use crate::formats::util::civil::civil_to_unix;

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

pub use crate::formats::util::arcutil::unix_mode;

pub use crate::formats::util::datakit::guid_le;

/// Directory-entry file types: Linux's `FT_*` codes (`fs_types.h`) shared
/// by ext, XFS, Btrfs, F2FS and EROFS, followed by a filesystem's own
/// extra entries.
macro_rules! dirent_types {
    ($($extra:expr),* $(,)?) => {
        &[
            (0, "unknown"),
            (1, "regular file"),
            (2, "directory"),
            (3, "character device"),
            (4, "block device"),
            (5, "FIFO"),
            (6, "socket"),
            (7, "symbolic link"),
            $($extra),*
        ]
    };
}
pub(crate) use dirent_types;

/// The Linux directory-entry file types, without filesystem extras.
pub const DIRENT_TYPES: crate::value::EnumTable = dirent_types!();

/// A `len`-byte name field (directory entry, xattr), shown as lossy UTF-8.
pub fn name_field(f: &mut crate::fields::Fields<'_>, len: u64) -> Result<Vec<u8>> {
    f.bytes("Name", len)
        .with(|b, n| n.value(Value::Text(String::from_utf8_lossy(b).into_owned())))
        .emit()
}

/// A value node holding a decimal integer.
pub fn uint_node(name: impl Into<Cow<'static, str>>, span: Span, value: u64, bits: u8) -> Node {
    Node::new(name)
        .span(span)
        .value(crate::formats::util::val::uint(value, bits))
}
