//! Byte provenance: sources and spans within them.

use std::fmt;

use crate::error::{Diagnostic, Result};

/// Identifies a byte space: a host-provided file today, derived streams
/// (decompressed members, reassembled fragments) later.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct SourceId(pub(crate) u32);

impl SourceId {
    pub fn index(self) -> u32 {
        self.0
    }

    /// The first source registered in a session (by convention, the file).
    pub const fn default_host() -> Self {
        SourceId(0)
    }

    /// A virtual, endless source of zero bytes. Spans of it serve as holes in
    /// [`Cx::add_pieces`](crate::Cx::add_pieces) (sparse files, unallocated
    /// virtual-disk blocks); they read as zeros and resolve to nothing.
    pub const ZEROS: SourceId = SourceId(u32::MAX);
}

/// How a derived source was produced: by applying `transform` (e.g.
/// `"deflate"`) to the bytes of `parent`. Decoded bytes generally have no
/// one-to-one position in the parent; the parent span is the provenance.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Origin {
    pub parent: Span,
    pub transform: &'static str,
}

/// A byte range within a source.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Span {
    pub source: SourceId,
    pub offset: u64,
    pub len: u64,
}

impl Span {
    /// A hole of `len` zero bytes (see [`SourceId::ZEROS`]).
    pub const fn zeros(len: u64) -> Span {
        Span {
            source: SourceId::ZEROS,
            offset: 0,
            len,
        }
    }

    pub const fn new(source: SourceId, offset: u64, len: u64) -> Self {
        Span {
            source,
            offset,
            len,
        }
    }

    /// One past the last byte (saturating).
    pub fn end(&self) -> u64 {
        self.offset.saturating_add(self.len)
    }

    pub fn is_empty(&self) -> bool {
        self.len == 0
    }

    /// The part of `offset..offset + len` (relative to this span) that lies
    /// within this span. Never fails: a range starting past the end yields an
    /// empty span at the end. Reading a clamped span returns fewer bytes than
    /// asked for, which field decoding reports as truncation.
    pub fn sub(&self, offset: u64, len: u64) -> Span {
        let start = offset.min(self.len);
        let len = len.min(self.len.saturating_sub(start));
        Span::new(self.source, self.offset.saturating_add(start), len)
    }

    /// Like [`Span::sub`], but the whole range must lie within this span.
    pub fn sub_exact(&self, offset: u64, len: u64) -> Result<Span> {
        let claimed = self
            .offset
            .checked_add(offset)
            .map(|start| Span::new(self.source, start, len))
            .filter(|s| s.offset.checked_add(s.len).is_some())
            .ok_or_else(|| Diagnostic::malformed(format!("offset {offset:#x} overflows")))?;
        let inner = self.sub(offset, len);
        if inner.len == len && inner.offset == claimed.offset {
            Ok(inner)
        } else {
            Err(Diagnostic::truncated(claimed, inner.len))
        }
    }

    /// Everything from `offset` (relative) to the end of this span.
    pub fn tail(&self, offset: u64) -> Span {
        self.sub(offset, u64::MAX)
    }

    pub fn contains(&self, other: &Span) -> bool {
        self.source == other.source && self.offset <= other.offset && other.end() <= self.end()
    }
}

impl fmt::Display for Span {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.source.0 != 0 {
            write!(f, "#{}:", self.source.0)?;
        }
        write!(f, "{:#x}+{:#x}", self.offset, self.len)
    }
}
