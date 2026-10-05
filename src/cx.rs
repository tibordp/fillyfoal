//! The dissector's view of a session: reading bytes and emitting nodes.
//!
//! Every way a dissector can suspend goes through [`Cx`]:
//!
//! - a read whose bytes are not cached yet (waiting for bytes),
//! - an exhausted work budget (yielded),
//! - a full page of children.
//!
//! The session inspects which of these happened after each poll; a future
//! that suspends any other way is reported as an internal error.

use std::collections::HashMap;
use std::future::poll_fn;
use std::sync::{Arc, Mutex, MutexGuard};
use std::task::Poll;

use crate::bytes::to_u64;
use crate::cache::ByteCache;
use crate::error::{Diagnostic, Result};
use crate::node::{Count, Node};
use crate::session::Limits;
use crate::span::{Origin, SourceId, Span};

/// Why the most recently polled expansion suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Bytes,
    Budget,
    Page,
}

pub(crate) struct SourceEntry {
    pub len: u64,
    /// Bytes of a derived (in-memory) source.
    pub data: Option<Arc<[u8]>>,
    pub origin: Option<Origin>,
    /// For derived sources: how many parent bytes the decoder consumed, and
    /// why it stopped early, if it did.
    pub consumed: u64,
    pub error: Option<Diagnostic>,
}

pub(crate) struct Shared {
    pub sources: Vec<SourceEntry>,
    pub derived: HashMap<Origin, SourceId>,
    pub derived_bytes: u64,
    pub cache: ByteCache,
    pub budget: u64,
    pub stop: Option<Stop>,
    pub wanted: Vec<(SourceId, u64)>,
    pub limits: Limits,
}

impl Shared {
    pub fn source(&self, source: SourceId) -> Option<&SourceEntry> {
        self.sources.get(crate::bytes::to_usize(source.0.into()))
    }

    pub fn source_len(&self, source: SourceId) -> u64 {
        self.source(source).map_or(0, |s| s.len)
    }

    fn charge(&mut self, units: u64) {
        self.budget = self.budget.saturating_sub(units);
    }
}

/// Output of one expansion, drained by the session after every poll.
#[derive(Default)]
pub(crate) struct Output {
    pub nodes: Vec<Node>,
    pub emitted: u64,
    pub target: u64,
    pub count: Option<Count>,
    pub summary: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
}

pub(crate) fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(|poisoned| poisoned.into_inner())
}

/// Bytes read from a span. `data` may be shorter than `span.len` when the
/// source ends early.
#[derive(Clone, Debug)]
pub struct Block {
    pub span: Span,
    pub data: Vec<u8>,
}

impl Block {
    pub fn is_complete(&self) -> bool {
        to_u64(self.data.len()) == self.span.len
    }
}

/// Context handed to every expansion.
#[derive(Clone)]
pub struct Cx {
    pub(crate) shared: Arc<Mutex<Shared>>,
    pub(crate) out: Arc<Mutex<Output>>,
}

impl Cx {
    pub fn limits(&self) -> Limits {
        lock(&self.shared).limits
    }

    pub fn source_len(&self, source: SourceId) -> u64 {
        lock(&self.shared).source_len(source)
    }

    /// Reads the bytes of `span` that exist in the source (possibly fewer than
    /// `span.len`, possibly none).
    pub async fn read_avail(&self, span: Span) -> Result<Vec<u8>> {
        let max = self.limits().max_read;
        if span.len > max {
            return Err(Diagnostic::limit(format!(
                "read of {:#x} bytes exceeds the {max:#x}-byte limit",
                span.len
            ))
            .at(span));
        }
        poll_fn(|_| {
            let mut sh = lock(&self.shared);
            if sh.budget == 0 {
                sh.stop = Some(Stop::Budget);
                return Poll::Pending;
            }
            let end = span.end().min(sh.source_len(span.source));
            let start = span.offset.min(end);
            if let Some(data) = sh.source(span.source).and_then(|s| s.data.clone()) {
                let bytes = data
                    .get(crate::bytes::to_usize(start)..crate::bytes::to_usize(end))
                    .unwrap_or_default()
                    .to_vec();
                sh.charge(1u64.saturating_add(to_u64(bytes.len()) >> 12));
                return Poll::Ready(Ok(bytes));
            }
            match sh.cache.read(span.source, start, end) {
                Ok(data) => {
                    sh.charge(1u64.saturating_add(to_u64(data.len()) >> 12));
                    Poll::Ready(Ok(data))
                }
                Err(missing) => {
                    sh.wanted
                        .extend(missing.into_iter().map(|i| (span.source, i)));
                    sh.stop = Some(Stop::Bytes);
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Reads exactly `span`, failing with a truncation diagnostic otherwise.
    pub async fn read(&self, span: Span) -> Result<Vec<u8>> {
        let data = self.read_avail(span).await?;
        if to_u64(data.len()) < span.len {
            return Err(Diagnostic::truncated(span, to_u64(data.len())));
        }
        Ok(data)
    }

    /// Reads what exists of `span`, for decoding with [`crate::Fields`].
    pub async fn block(&self, span: Span) -> Result<Block> {
        let data = self.read_avail(span).await?;
        Ok(Block { span, data })
    }

    /// Reads a NUL-terminated string starting at `span.offset`, looking at
    /// most `span.len` bytes ahead (in small steps, so a short string costs a
    /// short read). Returns the text (decoded lossily as UTF-8) and the span it
    /// occupies, including the terminator.
    pub async fn cstr(&self, span: Span) -> Result<(String, Span)> {
        const STEP: u64 = 256;
        let mut text = Vec::new();
        let mut pos = 0u64;
        while pos < span.len {
            let window = span.sub(pos, STEP);
            let data = self.read_avail(window).await?;
            if let Some(n) = data.iter().position(|&b| b == 0) {
                text.extend_from_slice(data.get(..n).unwrap_or_default());
                let len = to_u64(text.len()).saturating_add(1);
                return Ok((
                    String::from_utf8_lossy(&text).into_owned(),
                    span.sub(0, len),
                ));
            }
            text.extend_from_slice(&data);
            if to_u64(data.len()) < window.len {
                return Err(Diagnostic::truncated(span, to_u64(text.len())));
            }
            pos = pos.saturating_add(window.len);
        }
        Err(Diagnostic::malformed(format!(
            "string not terminated within {:#x} bytes",
            span.len
        ))
        .at(span))
    }

    /// A previously derived source with this origin, if any. Dissectors use
    /// this to avoid decoding the same bytes twice (e.g. after a collapse).
    pub fn derived(&self, origin: Origin) -> Option<crate::codec::Decoded> {
        let sh = lock(&self.shared);
        let id = *sh.derived.get(&origin)?;
        let entry = sh.source(id)?;
        Some(crate::codec::Decoded {
            source: id,
            span: Span::new(id, 0, entry.len),
            consumed: entry.consumed,
            error: entry.error.clone(),
        })
    }

    /// Registers decoded bytes as a new source. Fails if the session's total
    /// budget for derived bytes would be exceeded.
    pub fn add_derived(
        &self,
        origin: Origin,
        data: Vec<u8>,
        consumed: u64,
        error: Option<Diagnostic>,
    ) -> Result<crate::codec::Decoded> {
        if let Some(found) = self.derived(origin) {
            return Ok(found);
        }
        let mut sh = lock(&self.shared);
        let len = to_u64(data.len());
        let total = sh.derived_bytes.saturating_add(len);
        if total > sh.limits.max_derived {
            return Err(Diagnostic::limit(format!(
                "decoded data would exceed the {:#x}-byte limit for derived sources",
                sh.limits.max_derived
            ))
            .at(origin.parent));
        }
        sh.derived_bytes = total;
        let id = SourceId(u32::try_from(sh.sources.len()).unwrap_or(u32::MAX));
        sh.sources.push(SourceEntry {
            len,
            data: Some(data.into()),
            origin: Some(origin),
            consumed,
            error: error.clone(),
        });
        sh.derived.insert(origin, id);
        Ok(crate::codec::Decoded {
            source: id,
            span: Span::new(id, 0, len),
            consumed,
            error,
        })
    }

    /// Charges one unit of work, suspending first if the budget is exhausted.
    /// Call this in loops whose length depends on the input.
    pub async fn checkpoint(&self) {
        poll_fn(|_| {
            let mut sh = lock(&self.shared);
            if sh.budget == 0 {
                sh.stop = Some(Stop::Budget);
                Poll::Pending
            } else {
                sh.charge(1);
                Poll::Ready(())
            }
        })
        .await
    }

    /// Emits a child immediately, regardless of paging. Use for a small, fixed
    /// set of children; use [`Cx::push`] for collections.
    pub fn emit(&self, node: Node) {
        let mut out = lock(&self.out);
        out.nodes.push(node);
        out.emitted = out.emitted.saturating_add(1);
    }

    /// Emits the next element of a collection. Suspends first if the host has
    /// not asked for this many children yet, so work beyond the requested
    /// page happens only on demand.
    pub async fn push(&self, node: Node) {
        self.checkpoint().await;
        poll_fn(|_| {
            let page_full = {
                let out = lock(&self.out);
                out.emitted >= out.target
            };
            if page_full {
                lock(&self.shared).stop = Some(Stop::Page);
                Poll::Pending
            } else {
                Poll::Ready(())
            }
        })
        .await;
        self.emit(node);
    }

    /// Announces how many children this expansion will produce.
    pub fn set_count(&self, count: Count) {
        lock(&self.out).count = Some(count);
    }

    /// Replaces the summary of the node being expanded, e.g. once a format has
    /// been identified.
    pub fn annotate(&self, summary: impl Into<String>) {
        lock(&self.out).summary = Some(summary.into());
    }

    /// Attaches a non-fatal diagnostic to the node being expanded.
    pub fn diag(&self, diagnostic: Diagnostic) {
        lock(&self.out).diagnostics.push(diagnostic);
    }
}
