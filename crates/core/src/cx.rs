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
use crate::codec::Codec;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Registry};
use crate::node::{Count, Node};
use crate::secret::{MAX_ATTEMPTS, Secret, SecretRequest};
use crate::session::{Interpretation, Limits};
use crate::span::{Origin, SourceId, Span};

/// Why the most recently polled expansion suspended.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum Stop {
    Bytes,
    Budget,
    Page,
    Secret,
}

/// Why a read of a source could not complete yet.
#[derive(Debug)]
pub(crate) enum Pending {
    /// These host chunks must be supplied first.
    Bytes(Vec<(SourceId, u64)>),
    /// Decoding a lazy source used up the work budget; reading again
    /// continues where it stopped.
    Budget,
}

/// A source assembled from pieces of other sources, in order.
pub(crate) struct Pieces {
    pub spans: Vec<Span>,
    /// Offset of each piece within the assembled source.
    pub starts: Vec<u64>,
}

/// [`Pieces`] being built: pieces clamped to their sources, empty ones
/// dropped.
#[derive(Default)]
struct PieceIndex {
    spans: Vec<Span>,
    starts: Vec<u64>,
    len: u64,
}

impl PieceIndex {
    fn extend(&mut self, sh: &Shared, pieces: &[Span]) {
        self.spans.reserve(pieces.len());
        self.starts.reserve(pieces.len());
        for piece in pieces {
            let source_len = sh.source_len(piece.source);
            let end = piece.end().min(source_len);
            let start = piece.offset.min(end);
            let clamped = Span::new(piece.source, start, end.saturating_sub(start));
            if clamped.len == 0 {
                continue;
            }
            self.starts.push(self.len);
            self.len = self.len.saturating_add(clamped.len);
            self.spans.push(clamped);
        }
    }
}

pub(crate) struct SourceEntry {
    pub len: u64,
    /// Bytes of a derived (in-memory) source.
    pub data: Option<Arc<[u8]>>,
    /// The layout of a piecewise source.
    pub pieces: Option<Arc<Pieces>>,
    /// A stream decoded on demand, as far as reads reach.
    pub lazy: Option<Box<LazyDecode>>,
    pub origin: Option<Origin>,
    /// For derived sources: how many parent bytes the decoder consumed, and
    /// why it stopped early, if it did.
    pub consumed: u64,
    pub error: Option<Diagnostic>,
    /// How to decode the source again from its parent: set for sources
    /// decoded with a codec, which makes them evictable (see
    /// [`Shared::make_room`]).
    pub recipe: Option<Codec>,
    /// When the source was last read (for eviction).
    pub used: u64,
    /// Registered with [`Cx::decode_lazy`] (an evicted eager source decodes
    /// lazily too, but is not "on demand" to dissectors: what they see must
    /// not depend on eviction).
    pub on_demand: bool,
    /// Whether `len` is the real length. A lazily decoded stream whose size
    /// nothing records gets an upper bound (see [`Cx::decode_lazy_unsized`])
    /// that shrinks to the real length once the stream has been decoded.
    pub len_known: bool,
}

impl SourceEntry {
    pub(crate) fn host(len: u64) -> Self {
        SourceEntry {
            len,
            data: None,
            pieces: None,
            lazy: None,
            origin: None,
            consumed: 0,
            error: None,
            recipe: None,
            used: 0,
            on_demand: false,
            len_known: true,
        }
    }

    /// Bytes this source holds in memory (counted in `derived_bytes`).
    fn held(&self) -> u64 {
        match (&self.data, &self.lazy) {
            (Some(d), _) => to_u64(d.len()),
            (None, Some(l)) => to_u64(l.out.len().saturating_add(l.input.len())),
            _ => 0,
        }
    }
}

/// State of a lazily decoded source: encoded input read so far, the
/// resumable decoder, and the output produced so far.
pub(crate) struct LazyDecode {
    parent: Span,
    /// Encoded bytes read and not yet released; they start at `in_base`
    /// of the parent span.
    input: Vec<u8>,
    in_base: u64,
    input_eof: bool,
    /// Decoded bytes held; they start at `out_base` of the source. Output
    /// before the decoder's window is released once a stream grows large
    /// (see [`LAZY_KEEP`]); reading before `out_base` decodes again from
    /// the start.
    out: Vec<u8>,
    out_base: u64,
    decoder: Box<dyn crate::codec::pipeline::Decoder>,
    recipe: Codec,
    /// The decoder asked for more input than is buffered.
    starved: bool,
    done: bool,
}

impl LazyDecode {
    /// A decoder at the start of `parent`, or `None` for a codec without
    /// one.
    fn new(parent: Span, recipe: &Codec) -> Option<Self> {
        Some(LazyDecode {
            parent,
            input: Vec::new(),
            in_base: 0,
            input_eof: false,
            out: Vec::new(),
            out_base: 0,
            decoder: recipe.decoder()?,
            recipe: recipe.clone(),
            starved: false,
            done: false,
        })
    }

    /// Drops what the decoder no longer needs: consumed input, and output
    /// before both its window and `keep_from` (the start of the read being
    /// served), keeping at least `keep` bytes of output.
    fn release(&mut self, keep_from: u64, keep: usize) {
        let n = self.decoder.releasable_input().min(self.input.len());
        if n >= RELEASE_INPUT {
            self.decoder.release_input(n);
            self.input.drain(..n);
            self.in_base = self.in_base.saturating_add(to_u64(n));
        }
        let len = self.out.len();
        if len > keep.saturating_mul(2) {
            let n = self
                .decoder
                .releasable_output(len)
                .min(len.saturating_sub(keep))
                .min(crate::bytes::to_usize(
                    keep_from.saturating_sub(self.out_base),
                ));
            if n > 0 {
                self.decoder.release_output(n);
                self.out.drain(..n);
                self.out_base = self.out_base.saturating_add(to_u64(n));
            }
        }
    }
}

/// Decoded bytes a lazily decoded source keeps behind its decoding front
/// once it releases output (reads near the front need no re-decoding): at
/// most this, and at most a quarter of `Limits::max_derived`.
const LAZY_KEEP: usize = 16 * 1024 * 1024;
/// Consumed input is released in pieces at least this large.
const RELEASE_INPUT: usize = 1024 * 1024;

/// Encoded bytes kept ahead of the decoder, so it rarely runs out of input
/// in the middle of a step (it asks for more when it does).
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
    /// Logical clock for least-recently-used eviction of derived sources.
    pub tick: u64,
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

    /// Frees memory for `need` more derived bytes by evicting the least
    /// recently read sources that can be decoded again (those with a
    /// recipe). An evicted source becomes a fresh lazily decoded one: reading
    /// it later decodes it again from its parent, as far as the read
    /// reaches. `protect` and the sources it derives from are kept (they
    /// are being read). Returns whether `need` now fits.
    pub(crate) fn make_room(&mut self, need: u64, protect: SourceId) -> bool {
        let max = self.limits.max_derived;
        let mut chain = vec![protect];
        let mut cursor = protect;
        while let Some(parent) = self
            .source(cursor)
            .and_then(|e| e.origin)
            .map(|o| o.parent.source)
        {
            if chain.contains(&parent) || chain.len() > 64 {
                break;
            }
            chain.push(parent);
            cursor = parent;
        }
        while self.derived_bytes.saturating_add(need) > max {
            let victim = self
                .sources
                .iter()
                .enumerate()
                .filter(|(i, e)| {
                    e.recipe.is_some()
                        && e.held() > 0
                        && !chain
                            .iter()
                            .any(|c| crate::bytes::to_usize(c.0.into()) == *i)
                })
                .min_by_key(|(_, e)| e.used)
                .map(|(i, _)| i);
            let Some(entry) = victim.and_then(|i| self.sources.get_mut(i)) else {
                return false;
            };
            let Some(origin) = entry.origin else {
                entry.recipe = None;
                continue;
            };
            let held = entry.held();
            entry.data = None;
            let Some(fresh) = LazyDecode::new(
                origin.parent,
                entry.recipe.as_ref().unwrap_or(&Codec::Stored),
            ) else {
                entry.recipe = None;
                continue;
            };
            entry.lazy = Some(Box::new(fresh));
            self.derived_bytes = self.derived_bytes.saturating_sub(held);
        }
        true
    }

    fn charge(&mut self, units: u64) {
        self.budget = self.budget.saturating_sub(units);
    }

    /// Bytes `start..end` of `source` (clamped to its length), or why they
    /// are not available yet: host chunks to supply first, or a work budget
    /// used up decoding a lazy source (see [`Pending`]). Piecewise sources
    /// are resolved through their parents.
    pub fn read_range(
        &mut self,
        source: SourceId,
        start: u64,
        end: u64,
        depth: u32,
    ) -> std::result::Result<Vec<u8>, Pending> {
        let end = end.min(self.source_len(source));
        let start = start.min(end);
        self.tick = self.tick.wrapping_add(1);
        let tick = self.tick;
        if let Some(entry) = self
            .sources
            .get_mut(crate::bytes::to_usize(source.0.into()))
        {
            entry.used = tick;
        }
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
            return self.cache.read(source, start, end).map_err(|missing| {
                Pending::Bytes(missing.into_iter().map(|i| (source, i)).collect())
            });
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
                Err(Pending::Bytes(m)) => missing.extend(m),
                Err(Pending::Budget) => return Err(Pending::Budget),
            }
            pos = pos.saturating_add(take);
            index = index.saturating_add(1);
        }
        if missing.is_empty() {
            Ok(out)
        } else {
            Err(Pending::Bytes(missing))
        }
    }

    /// Reads from a lazily inflated source, decoding as far as `end`. Work
    /// is charged as the decoder goes; once the budget is used up the read
    /// stops with [`Pending::Budget`], keeping what was decoded, so that no
    /// single read decodes without bound. A read entered with budget left
    /// always makes progress.
    fn read_lazy(
        &mut self,
        source: SourceId,
        start: u64,
        end: u64,
        depth: u32,
    ) -> std::result::Result<Vec<u8>, Pending> {
        let index = crate::bytes::to_usize(source.0.into());
        let Some(mut st) = self.sources.get_mut(index).and_then(|e| e.lazy.take()) else {
            return Ok(Vec::new());
        };
        let before = st.out.len().saturating_add(st.input.len());
        // Released output is decoded again, from the start.
        if start < st.out_base
            && let Some(fresh) = LazyDecode::new(st.parent, &st.recipe)
        {
            *st = fresh;
        }
        // Room for the output still to come, and for the encoded input it
        // takes (kept alongside; rarely more than the output it produces).
        let keep = LAZY_KEEP.min(crate::bytes::to_usize(self.limits.max_derived / 4));
        let front = st.out_base.saturating_add(to_u64(st.out.len()));
        let more_out = end
            .saturating_sub(front)
            .min(to_u64(keep.saturating_mul(2)));
        let more_in = more_out
            .min(
                st.parent
                    .len
                    .saturating_sub(st.in_base.saturating_add(to_u64(st.input.len()))),
            )
            .saturating_add(to_u64(LOOKAHEAD));
        let need = more_out.saturating_add(more_in);
        self.make_room(need, source);
        let limit =
            crate::bytes::to_usize(self.limits.max_derived.saturating_sub(self.derived_bytes));
        let mut failure = None;
        let result = loop {
            if st.out_base.saturating_add(to_u64(st.out.len())) >= end || st.done {
                let from =
                    crate::bytes::to_usize(start.saturating_sub(st.out_base)).min(st.out.len());
                let to = crate::bytes::to_usize(end.saturating_sub(st.out_base)).min(st.out.len());
                break Ok(st.out.get(from..to).unwrap_or_default().to_vec());
            }
            if self.budget == 0 {
                break Err(Pending::Budget);
            }
            let pending = st.input.len().saturating_sub(st.decoder.consumed());
            if !st.input_eof && (st.starved || pending < LOOKAHEAD) {
                let fed = st.in_base.saturating_add(to_u64(st.input.len()));
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
                        self.charge(to_u64(bytes.len()) >> 12);
                        st.input.extend_from_slice(&bytes);
                        st.starved = false;
                    }
                    Err(pending) => break Err(pending),
                }
                continue;
            }
            let LazyDecode {
                input,
                input_eof,
                out,
                decoder,
                starved,
                done,
                ..
            } = &mut *st;
            let cap = out.len().saturating_add(limit);
            let produced_before = out.len();
            let status = decoder.decode(input, *input_eof, out, LAZY_STEP, cap);
            let produced = out.len().saturating_sub(produced_before);
            match status {
                Ok(crate::codec::pipeline::Status::More) => {}
                Ok(crate::codec::pipeline::Status::NeedInput) if !*input_eof => *starved = true,
                Ok(crate::codec::pipeline::Status::NeedInput) => {
                    *done = true;
                    failure = Some(Diagnostic::malformed("encoded stream ends early"));
                }
                Ok(crate::codec::pipeline::Status::Done) => *done = true,
                Err(e) => {
                    *done = true;
                    failure = Some(e);
                }
            }
            st.release(start, keep);
            self.charge((to_u64(produced) >> 12).max(1));
        };
        // Once the stream has ended, its real length is known, and so is any
        // problem that did not stop it (a checksum mismatch).
        let finished_len = st
            .done
            .then(|| st.out_base.saturating_add(to_u64(st.out.len())));
        if st.done && failure.is_none() {
            failure = st.decoder.warning(&st.out);
        }
        let after = st.out.len().saturating_add(st.input.len());
        self.derived_bytes = self
            .derived_bytes
            .saturating_add(to_u64(after))
            .saturating_sub(to_u64(before));
        if let Some(entry) = self.sources.get_mut(index) {
            let declared = entry.len;
            entry.consumed = st.in_base.saturating_add(to_u64(st.decoder.consumed()));
            entry.lazy = Some(st);
            if let Some(len) = finished_len {
                entry.len = entry.len.min(len);
            }
            let declared_known = entry.len_known;
            if finished_len.is_some() {
                entry.len_known = true;
            }
            // A stream that ended short of the size its container
            // declared is reported like a decoding error.
            if failure.is_none()
                && declared_known
                && let Some(len) = finished_len.filter(|&l| l < declared)
            {
                failure = Some(Diagnostic::warning(format!(
                    "decoded {len:#x} bytes, expected {declared:#x}"
                )));
            }
            if entry.error.is_none() {
                entry.error = failure;
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

/// A resume key: dissector state from which an expansion can restart.
pub(crate) type Key = Arc<dyn std::any::Any + Send + Sync>;

/// Children between resume marks an expansion keeps (see [`Cx::mark`]).
pub(crate) const MARK_SPACING: u64 = 256;

/// Output of one expansion, drained by the session after every poll.
#[derive(Default)]
pub(crate) struct Output {
    pub nodes: Vec<Node>,
    /// Index of the next child (emitted or skipped).
    pub emitted: u64,
    pub target: u64,
    /// Children below this index are dropped instead of emitted (the host
    /// asked for a window further on).
    pub skip: u64,
    /// The resume key this run started from, until the dissector takes it.
    pub resume: Option<Key>,
    /// Resume marks recorded since the last drain: (child index, key).
    pub marks: Vec<(u64, Key)>,
    pub last_mark: u64,
    pub count: Option<Count>,
    pub summary: Option<String>,
    pub diagnostics: Vec<Diagnostic>,
    /// The format the host forced for this node (see
    /// [`crate::Session::reinterpret`]).
    pub forced: Option<&'static Format>,
    /// Whether a detection step has run (see [`Cx::claim_detection`]).
    pub claimed: bool,
    /// What the node's own detection step settled on.
    pub interpretation: Option<Interpretation>,
    /// Progress the dissector reported: (done, total).
    pub progress: Option<(u64, u64)>,
}

pub fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
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
    pub(crate) registry: &'static Registry,
}

impl Cx {
    /// Claims the node's own detection step: the first one its expansion
    /// reaches, which decides what the node's content is (an expander may
    /// first decode it, as a "Decompressed" node does). Returns `None` to
    /// every later step, which belong to content nested inside; otherwise
    /// `Some` of the format the host forced, if any.
    pub(crate) fn claim_detection(&self) -> Option<Option<&'static Format>> {
        let mut out = lock(&self.out);
        if out.claimed {
            return None;
        }
        out.claimed = true;
        Some(out.forced)
    }

    /// The format the host forced for this node, if its detection step has
    /// not run yet (without claiming it; see [`Cx::claim_detection`]).
    pub(crate) fn forced_format(&self) -> Option<&'static Format> {
        let out = lock(&self.out);
        if out.claimed { None } else { out.forced }
    }

    /// Records what the node's own detection step settled on.
    pub(crate) fn interpreted(&self, interpretation: Interpretation) {
        lock(&self.out).interpretation = Some(interpretation);
    }

    /// The formats this session identifies.
    pub fn registry(&self) -> &'static Registry {
        self.registry
    }

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
                    // A short read of a lazily decoded source that stopped
                    // on an error is that error, not the end of the data.
                    let failed = (to_u64(data.len()) < span.len)
                        .then(|| sh.source(span.source))
                        .flatten()
                        .filter(|e| e.on_demand)
                        .and_then(|e| e.error.clone());
                    Poll::Ready(match failed {
                        Some(e) => Err(Diagnostic::new(
                            e.kind,
                            format!("decoding stopped: {}", e.message),
                        )
                        .at(span)),
                        None => Ok(data),
                    })
                }
                Err(Pending::Budget) => {
                    // Decoding continues on the next poll, where it stopped.
                    sh.stop = Some(Stop::Budget);
                    Poll::Pending
                }
                Err(Pending::Bytes(missing)) => {
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

    /// Whether `source`'s length is known; `false` for a lazily decoded
    /// stream of unrecorded size that has not been decoded to its end yet,
    /// whose length is an upper bound (see [`Cx::decode_lazy_unsized`]).
    pub fn len_known(&self, source: SourceId) -> bool {
        lock(&self.shared)
            .source(source)
            .is_none_or(|s| s.len_known)
    }

    /// Whether `source` is decoded on demand (reading its end decodes it all).
    pub fn is_lazy(&self, source: SourceId) -> bool {
        lock(&self.shared)
            .source(source)
            .is_some_and(|s| s.on_demand)
    }

    /// Whether reading the end of `source` is cheap: it is not decoded on
    /// demand, or its decoder has already reached the end of the stream (the
    /// decoder keeps a window behind its position, so the tail is still
    /// held, or re-decodable from a recent point).
    pub fn tail_is_cheap(&self, source: SourceId) -> bool {
        lock(&self.shared)
            .source(source)
            .is_none_or(|s| !s.on_demand || s.lazy.as_ref().is_some_and(|st| st.done))
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
    /// budget for derived bytes would be exceeded. Such sources stay in
    /// memory for the session (nothing records how to make them again); data
    /// decoded with a [`Codec`] should go through [`crate::codec::decode_span`]
    /// or [`Cx::decode_lazy`], whose sources can be evicted and re-decoded.
    pub fn add_derived(
        &self,
        origin: Origin,
        data: Vec<u8>,
        consumed: u64,
        error: Option<Diagnostic>,
    ) -> Result<crate::codec::Decoded> {
        self.add_bytes(origin, data, consumed, error, None)
    }

    /// [`Cx::add_derived`] for bytes decoded from `origin.parent` with
    /// `codec`: evictable, decoded again on demand.
    pub(crate) fn add_decoded(
        &self,
        origin: Origin,
        data: Vec<u8>,
        consumed: u64,
        error: Option<Diagnostic>,
        codec: &Codec,
    ) -> Result<crate::codec::Decoded> {
        self.add_bytes(origin, data, consumed, error, Some(codec.clone()))
    }

    fn add_bytes(
        &self,
        origin: Origin,
        data: Vec<u8>,
        consumed: u64,
        error: Option<Diagnostic>,
        recipe: Option<Codec>,
    ) -> Result<crate::codec::Decoded> {
        if let Some(found) = self.derived(origin) {
            return Ok(found);
        }
        let mut sh = lock(&self.shared);
        let len = to_u64(data.len());
        sh.make_room(len, origin.parent.source);
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
        let tick = sh.tick;
        sh.sources.push(SourceEntry {
            len,
            data: Some(data.into()),
            pieces: None,
            lazy: None,
            origin: Some(origin),
            consumed,
            error: error.clone(),
            recipe,
            used: tick,
            on_demand: false,
            len_known: true,
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
    ///
    /// This is one synchronous pass over `pieces` (a few nanoseconds each),
    /// fine for lists a caller built in a charged loop up to a few thousand
    /// pieces. For input-sized lists (a fragmented file, a sparse disk) use
    /// [`Cx::add_pieces_stepped`], which yields while it indexes them.
    pub fn add_pieces(&self, origin: Origin, pieces: Vec<Span>) -> Result<Span> {
        if let Some(found) = self.derived(origin) {
            return Ok(found.span);
        }
        let mut index = PieceIndex::default();
        index.extend(&lock(&self.shared), &pieces);
        Ok(self.register_pieces(origin, index))
    }

    /// [`Cx::add_pieces`] for input-sized lists: indexes `pieces` a bounded
    /// batch at a time, charging one unit per batch.
    pub async fn add_pieces_stepped(&self, origin: Origin, pieces: &[Span]) -> Result<Span> {
        const BATCH: usize = 1024;
        if let Some(found) = self.derived(origin) {
            return Ok(found.span);
        }
        let mut index = PieceIndex::default();
        for batch in pieces.chunks(BATCH) {
            self.checkpoint().await;
            index.extend(&lock(&self.shared), batch);
        }
        Ok(self.register_pieces(origin, index))
    }

    fn register_pieces(&self, origin: Origin, index: PieceIndex) -> Span {
        let mut sh = lock(&self.shared);
        // Another expansion may have registered it while this one yielded.
        if let Some(&id) = sh.derived.get(&origin)
            && let Some(entry) = sh.source(id)
        {
            return Span::new(id, 0, entry.len);
        }
        let PieceIndex { spans, starts, len } = index;
        let id = SourceId(u32::try_from(sh.sources.len()).unwrap_or(u32::MAX));
        let tick = sh.tick;
        sh.sources.push(SourceEntry {
            len,
            data: None,
            pieces: Some(Arc::new(Pieces { spans, starts })),
            lazy: None,
            origin: Some(origin),
            consumed: 0,
            error: None,
            recipe: None,
            used: tick,
            on_demand: false,
            len_known: true,
        });
        sh.derived.insert(origin, id);
        Span::new(id, 0, len)
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

    /// [`Cx::decode_lazy`] for raw DEFLATE or zlib-wrapped data.
    pub fn inflate_lazy(&self, span: Span, zlib: bool, len: u64) -> Result<Span> {
        let codec = if zlib { Codec::Zlib } else { Codec::Deflate };
        self.decode_lazy(span, &codec, len)
    }

    /// Registers `span`, encoded with `codec`, as a source that is decoded
    /// on demand: reading its first bytes decodes only those. `len` is the
    /// decoded size recorded by the container; reads beyond what the stream
    /// actually produces come back short. Memoized like other derived
    /// sources; decoded bytes count against `Limits::max_derived`.
    pub fn decode_lazy(&self, span: Span, codec: &Codec, len: u64) -> Result<Span> {
        self.register_lazy(span, codec, len, true)
    }

    /// [`Cx::decode_lazy`] for a stream whose decoded size nothing records
    /// (bzip2, zstd or LZ4 written to a pipe, ...). The source's length is an
    /// upper bound, the encoded size times the codec's maximum ratio, until
    /// the stream has been decoded to its end; then it shrinks to the real
    /// length. Reads past the real end come back short, and reading the end
    /// of the span decodes the whole stream, so dissectors over such a
    /// source should walk it from the start (as tar does) rather than look
    /// at its tail.
    pub fn decode_lazy_unsized(&self, span: Span, codec: &Codec) -> Result<Span> {
        let bound = span.len.saturating_mul(codec.max_ratio()).max(span.len);
        self.register_lazy(span, codec, bound, false)
    }

    fn register_lazy(&self, span: Span, codec: &Codec, len: u64, len_known: bool) -> Result<Span> {
        let Some(fresh) = LazyDecode::new(span, codec) else {
            return Ok(span);
        };
        let origin = Origin {
            parent: span,
            transform: codec.lazy_name(),
        };
        if let Some(found) = self.derived(origin) {
            return Ok(found.span);
        }
        let mut sh = lock(&self.shared);
        let id = SourceId(u32::try_from(sh.sources.len()).unwrap_or(u32::MAX));
        let tick = sh.tick;
        sh.sources.push(SourceEntry {
            len,
            data: None,
            pieces: None,
            lazy: Some(Box::new(fresh)),
            origin: Some(origin),
            consumed: 0,
            error: None,
            recipe: Some(codec.clone()),
            used: tick,
            on_demand: true,
            len_known,
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
        if out.emitted >= out.skip {
            out.nodes.push(node);
        }
        out.emitted = out.emitted.saturating_add(1);
    }

    /// Whether the next child will be dropped because the host asked for a
    /// window further on. A walker may then skip building the node (but
    /// must still call [`Cx::push`], which keeps the count).
    pub fn skipping(&self) -> bool {
        let out = lock(&self.out);
        out.emitted < out.skip
    }

    /// The resume key this expansion was restarted from, if any (see
    /// [`Cx::mark`]). A dissector that gets one restores its walk from it
    /// and continues exactly as it did after recording that mark: the next
    /// child it emits or pushes has the mark's index. Returns `None` on a
    /// fresh start (or if the key has another type).
    pub fn resume<K: std::any::Any + Send + Sync + Clone>(&self) -> Option<K> {
        let key = lock(&self.out).resume.take()?;
        key.downcast_ref::<K>().cloned()
    }

    /// Records a resume point: `key()` is walker state from which the walk
    /// can restart, producing the next child (the one about to be pushed)
    /// and everything after it. The session keeps marks sparsely and uses
    /// them to jump into a collection (a window far from the start) without
    /// re-walking from the beginning. Optional: without marks, a jump
    /// re-runs the expansion and drops the children before the window.
    pub fn mark<K: std::any::Any + Send + Sync>(&self, key: impl FnOnce() -> K) {
        let mut out = lock(&self.out);
        let index = out.emitted;
        if index >= out.last_mark.saturating_add(MARK_SPACING) {
            out.last_mark = index;
            out.marks.push((index, Arc::new(key())));
        }
    }

    /// Emits the next element of a collection. Suspends first if the host has
    /// not asked for this many children yet, so work beyond the requested
    /// page happens only on demand.
    pub async fn push(&self, node: Node) {
        self.checkpoint().await;
        {
            let mut out = lock(&self.out);
            if out.emitted < out.skip {
                out.emitted = out.emitted.saturating_add(1);
                return;
            }
        }
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

    /// Reports how far this expansion has got, as `done` out of `total`
    /// (in any unit), for the host's progress display (see
    /// [`crate::Session::progress`]). Walkers whose count is not known
    /// up front call this as they go; with an exact count announced
    /// ([`Cx::set_count`]) the session reports children produced instead.
    pub fn progress(&self, done: u64, total: u64) {
        lock(&self.out).progress = Some((done.min(total), total));
    }

    /// Reports progress as a position `pos` within `span` (a walker over
    /// the records of its input). For a lazily decoded source, whose length
    /// may not be known until it has been decoded, this reports the encoded
    /// bytes consumed out of the encoded stream instead.
    pub fn progress_in(&self, span: Span, pos: u64) {
        let lazy = {
            let sh = lock(&self.shared);
            sh.source(span.source)
                .filter(|e| e.on_demand)
                .and_then(|e| Some((e.consumed, e.lazy.as_ref()?.parent.len)))
        };
        match lazy {
            Some((consumed, total)) => self.progress(consumed, total),
            None => self.progress(pos.saturating_sub(span.offset), span.len),
        }
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
