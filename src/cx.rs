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
use crate::secret::{MAX_ATTEMPTS, Secret, SecretRequest};
use crate::span::{Origin, SourceId, Span};

/// Why the most recently polled expansion suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Bytes,
    Budget,
    Page,
    Secret,
}

/// A source assembled from pieces of other sources, in order.
pub(crate) struct Pieces {
    pub spans: Vec<Span>,
    /// Offset of each piece within the assembled source.
    pub starts: Vec<u64>,
}

pub(crate) struct SourceEntry {
    pub len: u64,
    /// Bytes of a derived (in-memory) source.
    pub data: Option<Arc<[u8]>>,
    /// The layout of a piecewise source.
    pub pieces: Option<Arc<Pieces>>,
    /// A stream decoded on demand, as far as reads reach.
    pub lazy: Option<Box<LazyInflate>>,
    pub origin: Option<Origin>,
    /// For derived sources: how many parent bytes the decoder consumed, and
    /// why it stopped early, if it did.
    pub consumed: u64,
    pub error: Option<Diagnostic>,
}

/// State of a lazily inflated source: compressed input read so far, the
/// resumable decoder, and the output produced so far.
pub(crate) struct LazyInflate {
    parent: Span,
    /// Bytes to skip at the start of the input (the zlib header).
    skip: usize,
    input: Vec<u8>,
    input_eof: bool,
    out: Vec<u8>,
    inflater: crate::codec::inflate::Inflate,
    done: bool,
}

/// Compressed bytes kept ahead of the decoder, so it never runs out of input
/// in the middle of a symbol (an output step consumes far less than this).
const LOOKAHEAD: usize = 64 * 1024;
/// Output produced per decoder step.
const LAZY_STEP: usize = 16 * 1024;

pub(crate) struct Shared {
    pub sources: Vec<SourceEntry>,
    pub derived: HashMap<Origin, SourceId>,
    pub derived_bytes: u64,
    /// Parsed results shared between expansions (see [`Cx::cached`]).
    pub memo: HashMap<(Span, &'static str), Arc<dyn std::any::Any + Send + Sync>>,
    pub cache: ByteCache,
    pub budget: u64,
    pub stop: Option<Stop>,
    pub wanted: Vec<(SourceId, u64)>,
    /// Secrets answered by the host, by realm and attempt (`None`: declined).
    pub secrets: HashMap<(Span, u32), Option<Secret>>,
    /// The secret the current expansion is waiting for.
    pub secret_wanted: Option<SecretRequest>,
    pub limits: Limits,
}

impl Shared {
    pub fn source(&self, source: SourceId) -> Option<&SourceEntry> {
        self.sources.get(crate::bytes::to_usize(source.0.into()))
    }

    pub fn source_len(&self, source: SourceId) -> u64 {
        if source == SourceId::ZEROS {
            return u64::MAX;
        }
        self.source(source).map_or(0, |s| s.len)
    }

    fn charge(&mut self, units: u64) {
        self.budget = self.budget.saturating_sub(units);
    }

    /// Bytes `start..end` of `source` (clamped to its length), or the host
    /// chunks that must be supplied first. Piecewise sources are resolved
    /// through their parents.
    pub fn read_range(
        &mut self,
        source: SourceId,
        start: u64,
        end: u64,
        depth: u32,
    ) -> std::result::Result<Vec<u8>, Vec<(SourceId, u64)>> {
        let end = end.min(self.source_len(source));
        let start = start.min(end);
        if source == SourceId::ZEROS {
            return Ok(vec![0; crate::bytes::to_usize(end.saturating_sub(start))]);
        }
        let Some(entry) = self.source(source) else {
            return Ok(Vec::new());
        };
        if let Some(data) = &entry.data {
            return Ok(data
                .get(crate::bytes::to_usize(start)..crate::bytes::to_usize(end))
                .unwrap_or_default()
                .to_vec());
        }
        if entry.lazy.is_some() {
            return self.read_lazy(source, start, end, depth);
        }
        let Some(pieces) = entry.pieces.clone() else {
            return self
                .cache
                .read(source, start, end)
                .map_err(|missing| missing.into_iter().map(|i| (source, i)).collect());
        };
        if depth > 32 {
            return Ok(Vec::new());
        }
        let mut out = Vec::new();
        let mut missing = Vec::new();
        let mut index = pieces
            .starts
            .partition_point(|&s| s <= start)
            .saturating_sub(1);
        let mut pos = start;
        while pos < end {
            let (Some(piece), Some(&piece_start)) =
                (pieces.spans.get(index), pieces.starts.get(index))
            else {
                break;
            };
            let within = pos.saturating_sub(piece_start);
            let take = piece
                .len
                .saturating_sub(within)
                .min(end.saturating_sub(pos));
            if take == 0 {
                index = index.saturating_add(1);
                continue;
            }
            let from = piece.offset.saturating_add(within);
            match self.read_range(
                piece.source,
                from,
                from.saturating_add(take),
                depth.saturating_add(1),
            ) {
                Ok(bytes) => {
                    let short = to_u64(bytes.len()) < take;
                    out.extend_from_slice(&bytes);
                    if short && missing.is_empty() {
                        // The parent is shorter than the piece claims.
                        break;
                    }
                }
                Err(m) => missing.extend(m),
            }
            pos = pos.saturating_add(take);
            index = index.saturating_add(1);
        }
        if missing.is_empty() {
            Ok(out)
        } else {
            Err(missing)
        }
    }

    /// Reads from a lazily inflated source, decoding as far as `end`.
    fn read_lazy(
        &mut self,
        source: SourceId,
        start: u64,
        end: u64,
        depth: u32,
    ) -> std::result::Result<Vec<u8>, Vec<(SourceId, u64)>> {
        let index = crate::bytes::to_usize(source.0.into());
        let Some(mut st) = self.sources.get_mut(index).and_then(|e| e.lazy.take()) else {
            return Ok(Vec::new());
        };
        let before = st.out.len().saturating_add(st.input.len());
        let limit =
            crate::bytes::to_usize(self.limits.max_derived.saturating_sub(self.derived_bytes));
        let result = loop {
            if to_u64(st.out.len()) >= end || st.done {
                let from = crate::bytes::to_usize(start).min(st.out.len());
                let to = crate::bytes::to_usize(end).min(st.out.len());
                break Ok(st.out.get(from..to).unwrap_or_default().to_vec());
            }
            let pending = st
                .input
                .len()
                .saturating_sub(st.skip.saturating_add(st.inflater.consumed()));
            if !st.input_eof && pending < LOOKAHEAD {
                let fed = to_u64(st.input.len());
                let want = (LOOKAHEAD as u64).min(st.parent.len.saturating_sub(fed));
                if want == 0 {
                    st.input_eof = true;
                    continue;
                }
                let from = st.parent.offset.saturating_add(fed);
                match self.read_range(
                    st.parent.source,
                    from,
                    from.saturating_add(want),
                    depth.saturating_add(1),
                ) {
                    Ok(bytes) => {
                        if to_u64(bytes.len()) < want {
                            st.input_eof = true;
                        }
                        st.input.extend_from_slice(&bytes);
                    }
                    Err(missing) => break Err(missing),
                }
                continue;
            }
            let LazyInflate {
                input,
                out,
                inflater,
                skip,
                done,
                ..
            } = &mut *st;
            let body = input.get(*skip..).unwrap_or_default();
            match inflater.step(body, out, LAZY_STEP, out.len().saturating_add(limit)) {
                Ok(crate::codec::inflate::Step::More) => {}
                Ok(crate::codec::inflate::Step::Done) | Err(_) => *done = true,
            }
        };
        // Once the stream has ended, its real length is known.
        let finished_len = st.done.then(|| to_u64(st.out.len()));
        let after = st.out.len().saturating_add(st.input.len());
        self.derived_bytes = self
            .derived_bytes
            .saturating_add(to_u64(after.saturating_sub(before)));
        self.charge(to_u64(after.saturating_sub(before)) >> 12);
        if let Some(entry) = self.sources.get_mut(index) {
            entry.lazy = Some(st);
            if let Some(len) = finished_len {
                entry.len = entry.len.min(len);
            }
        }
        result
    }

    /// Resolves a span of any source to spans of non-piecewise sources.
    pub fn resolve(&self, span: Span, depth: u32, out: &mut Vec<Span>) {
        if span.source == SourceId::ZEROS {
            return;
        }
        let pieces = self.source(span.source).and_then(|e| e.pieces.clone());
        let Some(pieces) = pieces.filter(|_| depth <= 32) else {
            out.push(span);
            return;
        };
        let end = span.end();
        let mut index = pieces
            .starts
            .partition_point(|&s| s <= span.offset)
            .saturating_sub(1);
        let mut pos = span.offset;
        while pos < end {
            let (Some(piece), Some(&piece_start)) =
                (pieces.spans.get(index), pieces.starts.get(index))
            else {
                break;
            };
            let within = pos.saturating_sub(piece_start);
            let take = piece
                .len
                .saturating_sub(within)
                .min(end.saturating_sub(pos));
            if take > 0 {
                let parent = Span::new(piece.source, piece.offset.saturating_add(within), take);
                self.resolve(parent, depth.saturating_add(1), out);
            }
            pos = pos.saturating_add(take.max(1));
            index = index.saturating_add(1);
        }
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
            match sh.read_range(span.source, span.offset, span.end(), 0) {
                Ok(data) => {
                    sh.charge(1u64.saturating_add(to_u64(data.len()) >> 12));
                    Poll::Ready(Ok(data))
                }
                Err(missing) => {
                    // Scattered pieces could need more chunks than the cache
                    // holds at once; refuse rather than thrash forever.
                    let needed = to_u64(missing.len()).saturating_mul(sh.cache.chunk_size());
                    if needed > to_u64(sh.limits.cache_bytes) / 2 {
                        return Poll::Ready(Err(Diagnostic::limit(
                            "read spans too many scattered chunks",
                        )
                        .at(span)));
                    }
                    sh.wanted.extend(missing);
                    sh.stop = Some(Stop::Bytes);
                    Poll::Pending
                }
            }
        })
        .await
    }

    /// Asks the host for a secret (see [`crate::secret`]). Suspends until the
    /// host answers; `None` means the host declined. Answers are cached per
    /// realm and attempt for the whole session.
    pub async fn secret(&self, request: SecretRequest) -> Option<Secret> {
        let key = request.key();
        poll_fn(|_| {
            let mut sh = lock(&self.shared);
            if let Some(answer) = sh.secrets.get(&key) {
                return Poll::Ready(answer.clone());
            }
            sh.secret_wanted = Some(request.clone());
            sh.stop = Some(Stop::Secret);
            Poll::Pending
        })
        .await
    }

    /// Asks for a password for `realm` until `verify` accepts one, up to
    /// [`MAX_ATTEMPTS`] times. `None` if the host declined or every attempt
    /// failed. Formats with a free default (an empty password) should check
    /// it before calling this, so the user is never asked needlessly.
    ///
    /// `verify` must be cheap; with an expensive key derivation, loop over
    /// [`Cx::secret`] yourself and derive in budgeted steps.
    pub async fn unlock(
        &self,
        realm: Span,
        prompt: &str,
        verify: impl Fn(&Secret) -> bool,
    ) -> Option<Secret> {
        for attempt in 0..MAX_ATTEMPTS {
            let secret = self
                .secret(SecretRequest::password(realm, prompt, attempt))
                .await?;
            if verify(&secret) {
                return Some(secret);
            }
        }
        None
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

    /// Whether `source` is decoded on demand (reading its end decodes it all).
    pub fn is_lazy(&self, source: SourceId) -> bool {
        lock(&self.shared)
            .source(source)
            .is_some_and(|s| s.lazy.is_some())
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
            pieces: None,
            lazy: None,
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

    /// Registers a source assembled from `pieces` of other sources (a
    /// fragmented file, a sector chain). Nothing is copied: reads are mapped
    /// to the pieces, and provenance stays exact. Pieces are clamped to their
    /// sources; [`Span::zeros`] pieces are holes that read as zeros. Memoized
    /// by `origin`.
    pub fn add_pieces(&self, origin: Origin, pieces: Vec<Span>) -> Result<Span> {
        if let Some(found) = self.derived(origin) {
            return Ok(found.span);
        }
        let mut sh = lock(&self.shared);
        let mut spans = Vec::with_capacity(pieces.len());
        let mut starts = Vec::with_capacity(pieces.len());
        let mut len = 0u64;
        for piece in pieces {
            let source_len = sh.source_len(piece.source);
            let end = piece.end().min(source_len);
            let start = piece.offset.min(end);
            let clamped = Span::new(piece.source, start, end.saturating_sub(start));
            if clamped.len == 0 {
                continue;
            }
            starts.push(len);
            len = len.saturating_add(clamped.len);
            spans.push(clamped);
        }
        let id = SourceId(u32::try_from(sh.sources.len()).unwrap_or(u32::MAX));
        sh.sources.push(SourceEntry {
            len,
            data: None,
            pieces: Some(Arc::new(Pieces { spans, starts })),
            lazy: None,
            origin: Some(origin),
            consumed: 0,
            error: None,
        });
        sh.derived.insert(origin, id);
        Ok(Span::new(id, 0, len))
    }

    /// A value previously stored with [`Cx::cache`] for `(span, kind)`.
    ///
    /// Expansions are independent futures, so a dissector that parses the
    /// same structure for many nodes (a PDF object stream, a string table)
    /// can parse it once and share the result. Values must be deterministic
    /// functions of the bytes, like everything else a dissector produces.
    pub fn cached<T: std::any::Any + Send + Sync>(
        &self,
        span: Span,
        kind: &'static str,
    ) -> Option<Arc<T>> {
        let value = lock(&self.shared).memo.get(&(span, kind)).cloned()?;
        value.downcast::<T>().ok()
    }

    /// Stores a parsed value for later [`Cx::cached`] lookups. The cache is
    /// bounded; old entries are dropped arbitrarily when it is full.
    pub fn cache<T: std::any::Any + Send + Sync>(
        &self,
        span: Span,
        kind: &'static str,
        value: Arc<T>,
    ) {
        const MAX_ENTRIES: usize = 4096;
        let mut sh = lock(&self.shared);
        if sh.memo.len() >= MAX_ENTRIES
            && let Some(key) = sh.memo.keys().next().copied()
        {
            sh.memo.remove(&key);
        }
        sh.memo.insert((span, kind), value);
    }

    /// Registers `span` (raw DEFLATE, or zlib-wrapped) as a source that is
    /// decoded on demand: reading its first bytes decodes only those. `len` is
    /// the decoded size recorded by the container; reads beyond what the
    /// stream actually produces come back short. Memoized like other derived
    /// sources; decoded bytes count against `Limits::max_derived`.
    pub fn inflate_lazy(&self, span: Span, zlib: bool, len: u64) -> Result<Span> {
        let origin = Origin {
            parent: span,
            transform: if zlib {
                "zlib (lazy)"
            } else {
                "deflate (lazy)"
            },
        };
        if let Some(found) = self.derived(origin) {
            return Ok(found.span);
        }
        let mut sh = lock(&self.shared);
        let id = SourceId(u32::try_from(sh.sources.len()).unwrap_or(u32::MAX));
        sh.sources.push(SourceEntry {
            len,
            data: None,
            pieces: None,
            lazy: Some(Box::new(LazyInflate {
                parent: span,
                skip: if zlib { 2 } else { 0 },
                input: Vec::new(),
                input_eof: false,
                out: Vec::new(),
                inflater: crate::codec::inflate::Inflate::new(),
                done: false,
            })),
            origin: Some(origin),
            consumed: 0,
            error: None,
        });
        sh.derived.insert(origin, id);
        Ok(Span::new(id, 0, len))
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
