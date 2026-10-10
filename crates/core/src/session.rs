//! The host-facing side: the node arena, expansion state, and the poll loop.

use std::borrow::Cow;
use std::mem::take;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::bytes::{to_u64, to_usize};
use crate::cache::ByteCache;
use crate::cx::{Cx, Key, Output, Pending, Shared, Stop, lock};
use crate::error::Diagnostic;
use crate::formats::{self, Catalog, Registry};
use crate::node::{Count, Expansion, Node};
use crate::secret::{Secret, SecretRequest};
use crate::span::{Origin, SourceId, Span};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Limits {
    /// Granularity of host reads and of the byte cache.
    pub chunk_size: u64,
    /// Upper bound on cached source bytes.
    pub cache_bytes: usize,
    /// Largest single read a dissector may issue.
    pub max_read: u64,
    /// How deeply embedded objects may nest (a resource in a PE in a ZIP ...).
    pub max_nesting: u32,
    /// Total bytes of decoded (derived) sources kept in memory.
    pub max_derived: u64,
    /// Work units one expansion may consume before it is stopped with a
    /// `Limit` diagnostic, counted from its start or from the last page of
    /// children it filled. A safety net against dissectors that loop without
    /// making progress on malformed input.
    pub max_work: u64,
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            chunk_size: 64 * 1024,
            cache_bytes: 64 * 1024 * 1024,
            max_read: 16 * 1024 * 1024,
            max_nesting: 16,
            max_derived: 256 * 1024 * 1024,
            max_work: 100_000_000,
        }
    }
}

/// Resume marks kept per node before they are thinned.
const MAX_MARKS: usize = 4096;

/// Handle to a node. Stale handles (to collapsed subtrees) are detected.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct NodeId {
    index: u32,
    generation: u32,
}

/// Where a node's children stand.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ChildState {
    /// The node has no children.
    Leaf,
    /// Never requested: no work has been done.
    NotRequested,
    /// An expansion is in progress.
    Running(Wait),
    /// The requested page is complete; more children may follow.
    More,
    /// All children have been produced.
    Complete,
    /// The expansion failed; children produced before the failure remain.
    Failed,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Wait {
    /// Ready to run on the next poll.
    Ready,
    /// Waiting for the host to supply bytes.
    Bytes,
    /// Suspended because the work budget ran out.
    Budget,
    /// Waiting for the host to answer a secret request.
    Secret,
}

pub struct Children<'a> {
    /// The children currently materialised: indices `first..first + ids.len()`
    /// of the collection (see [`Session::seek`]).
    pub ids: &'a [NodeId],
    /// Index of `ids[0]` within the collection; 0 unless the host moved the
    /// window with [`Session::seek`].
    pub first: u64,
    pub state: ChildState,
    pub count: Count,
    pub error: Option<&'a Diagnostic>,
}

/// How a node's content is being dissected (see [`Session::interpretation`]).
#[derive(Clone, Copy, Debug)]
pub struct Interpretation {
    /// The format dissecting the content; `None` if it was not recognised.
    pub format: Option<&'static formats::Format>,
    /// Whether the host chose the format with [`Session::reinterpret`].
    pub forced: bool,
}

/// Where a node sits: its root, then its index among its parent's children
/// at each level down. Expansion is deterministic, so this names the same
/// node after the subtree holding it is collapsed and expanded again (and,
/// with another root over the same bytes, in another session).
pub type Address = (NodeId, Vec<u64>);

/// A range of source bytes the host should read and [`Session::supply`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRequest {
    pub source: SourceId,
    pub offset: u64,
    pub len: u64,
}

/// Outcome of [`Session::read_step`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ReadProgress {
    /// The bytes of the span that exist (fewer than asked if the source
    /// ends first).
    Done(Vec<u8>),
    /// Supply these bytes and call again.
    NeedBytes(Vec<ByteRequest>),
    /// The budget ran out while decoding; call again to continue.
    Yielded,
}

/// Outcome of [`Session::poll`] and [`Session::poll_node`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Nothing to do until the host requests more.
    Idle,
    /// The budget ran out with work remaining; poll again.
    Yielded,
    /// Expansions are blocked on these bytes. Supply them and poll again.
    /// (Other expansions may also be runnable.)
    NeedBytes(Vec<ByteRequest>),
    /// Expansions are blocked on secrets (passwords). Answer each with
    /// [`Session::answer_secret`] (or decline) and poll again. Reported only
    /// when no bytes are wanted and nothing else can run.
    NeedSecret(Vec<SecretRequest>),
}

/// A dissection session over the formats of catalog `C` (the `fillyfoal`
/// crate's `Session` alias uses all of them).
pub struct Session<C> {
    registry: &'static Registry,
    catalog: std::marker::PhantomData<fn() -> C>,
    shared: Arc<Mutex<Shared>>,
    slots: Vec<Slot>,
    free: Vec<u32>,
    active: Vec<NodeId>,
    live: usize,
    clock: u64,
    /// Formats forced with [`Session::reinterpret`], by address so they
    /// outlive the nodes (see [`Session::trim`]).
    overrides: std::collections::HashMap<Address, &'static formats::Format>,
}

struct Slot {
    generation: u32,
    entry: Option<Entry>,
}

struct Entry {
    node: Node,
    parent: Option<NodeId>,
    /// Index among the parent's children (0 for a root).
    index: u64,
    /// The materialised window of children, starting at index `first`.
    children: Vec<NodeId>,
    first: u64,
    /// Resume marks recorded by expansions: child index → walker state.
    marks: std::collections::BTreeMap<u64, Key>,
    /// The node's own diagnostics (from its creator); expansions add more,
    /// which are dropped when the expansion restarts.
    own_diagnostics: usize,
    state: ChildState,
    count: Count,
    error: Option<Diagnostic>,
    run: Option<Run>,
    /// When the host last asked for this node's children.
    touched: u64,
    /// Work units consumed by the current expansion.
    work: u64,
    /// How far the current (or last) expansion has got: the index of the
    /// next child it would produce. Children before it that are not in the
    /// window were dropped and can only be produced again by a restart.
    produced: u64,
    /// What the node's own detection step settled on, once it has run.
    interpretation: Option<Interpretation>,
}

struct Run {
    future: Expansion,
    out: Arc<Mutex<Output>>,
    waiting: Vec<(SourceId, u64)>,
    secret: Option<SecretRequest>,
}

impl Entry {
    fn new(node: Node, parent: Option<NodeId>, index: u64) -> Self {
        let state = if node.has_children() {
            ChildState::NotRequested
        } else {
            ChildState::Leaf
        };
        Entry {
            own_diagnostics: node.diagnostics.len(),
            node,
            parent,
            index,
            children: Vec::new(),
            first: 0,
            marks: std::collections::BTreeMap::new(),
            state,
            count: Count::Unknown,
            error: None,
            run: None,
            touched: 0,
            work: 0,
            produced: 0,
            interpretation: None,
        }
    }
}

impl<C: Catalog> Session<C> {
    pub fn new(limits: Limits) -> Self {
        let mut limits = limits;
        limits.chunk_size = limits.chunk_size.max(1);
        // A single read must fit in the cache alongside a little slack, or it
        // could evict its own chunks forever.
        let floor = to_usize(
            limits
                .max_read
                .saturating_add(limits.chunk_size.saturating_mul(2)),
        );
        limits.cache_bytes = limits.cache_bytes.max(floor);
        let shared = Shared {
            sources: Vec::new(),
            derived: std::collections::HashMap::new(),
            derived_bytes: 0,
            memo: std::collections::HashMap::new(),
            cache: ByteCache::new(limits.chunk_size, limits.cache_bytes),
            budget: 0,
            stop: None,
            wanted: Vec::new(),
            secrets: std::collections::HashMap::new(),
            secret_wanted: None,
            limits,
            tick: 0,
        };
        Session {
            registry: C::REGISTRY,
            catalog: std::marker::PhantomData,
            shared: Arc::new(Mutex::new(shared)),
            slots: Vec::new(),
            free: Vec::new(),
            active: Vec::new(),
            live: 0,
            clock: 0,
            overrides: std::collections::HashMap::new(),
        }
    }

    /// Number of nodes currently materialised.
    pub fn live_nodes(&self) -> usize {
        self.live
    }

    /// Bounds memory by collapsing the least recently expanded subtrees until
    /// at most `max_nodes` nodes remain (or nothing more can be collapsed).
    /// Nodes in `keep`, and their ancestors, are not collapsed, nor are nodes
    /// whose expansion is still running. Collapsed
    /// nodes can be expanded again and produce the same children; handles to
    /// their former descendants become stale.
    pub fn trim(&mut self, max_nodes: usize, keep: &[NodeId]) {
        if self.live <= max_nodes {
            return;
        }
        let mut protected = std::collections::HashSet::new();
        for &id in keep {
            let mut cursor = Some(id);
            while let Some(c) = cursor {
                if !protected.insert(c) {
                    break;
                }
                cursor = self.parent(c);
            }
        }
        let mut candidates: Vec<(u64, NodeId)> = self
            .slots
            .iter()
            .enumerate()
            .filter_map(|(index, slot)| {
                let entry = slot.entry.as_ref()?;
                let id = NodeId {
                    index: u32::try_from(index).ok()?,
                    generation: slot.generation,
                };
                let expanded = !entry.children.is_empty() || entry.run.is_some();
                // A parked expansion (see [`Session::poll_node`]) is kept:
                // collapsing it would throw away its work.
                let running = matches!(entry.state, ChildState::Running(_));
                (expanded && !running && entry.parent.is_some() && !protected.contains(&id))
                    .then_some((entry.touched, id))
            })
            .collect();
        candidates.sort_unstable_by_key(|&(touched, _)| touched);
        for (_, id) in candidates {
            if self.live <= max_nodes {
                break;
            }
            self.collapse(id);
        }
    }

    pub fn limits(&self) -> Limits {
        lock(&self.shared).limits
    }

    /// Registers a host-provided byte source of the given length.
    pub fn add_source(&mut self, len: u64) -> SourceId {
        let mut sh = lock(&self.shared);
        let id = SourceId(u32::try_from(sh.sources.len()).unwrap_or(u32::MAX));
        sh.sources.push(crate::cx::SourceEntry::host(len));
        id
    }

    pub fn source_len(&self, source: SourceId) -> u64 {
        lock(&self.shared).source_len(source)
    }

    /// Whether [`Session::source_len`] is the real length. It is not for a
    /// lazily decoded stream whose size nothing records (a `.tar.bz2`, or a
    /// zstd stream written to a pipe) until it has been decoded to its end:
    /// until then the length is an upper bound, and reads past the real end
    /// come back short.
    pub fn source_len_known(&self, source: SourceId) -> bool {
        lock(&self.shared)
            .source(source)
            .is_none_or(|s| s.len_known)
    }

    /// Shrinks a source, e.g. when the host finds the file shorter than
    /// announced. Pending reads beyond the new end become truncations.
    pub fn set_source_len(&mut self, source: SourceId, len: u64) {
        let mut sh = lock(&self.shared);
        if let Some(slot) = sh.sources.get_mut(to_usize(source.0.into()))
            && slot.data.is_none()
        {
            slot.len = len;
        }
        sh.cache.truncate(source, len);
    }

    /// Bytes currently held by derived sources (decoded or reassembled data).
    pub fn derived_bytes(&self) -> u64 {
        lock(&self.shared).derived_bytes
    }

    /// Where a derived source came from (`None` for host sources).
    pub fn origin(&self, source: SourceId) -> Option<Origin> {
        lock(&self.shared).source(source).and_then(|s| s.origin)
    }

    /// Maps a span of any source to the host-file (or in-memory) spans that
    /// hold its bytes, following piecewise sources. For a hex view, this
    /// turns "bytes 100..200 of a fragmented file" into file offsets.
    pub fn resolve(&self, span: Span) -> Vec<Span> {
        let mut out = Vec::new();
        lock(&self.shared).resolve(span, 0, &mut out);
        out
    }

    /// Reads the bytes of any span (host, decoded, lazily decoded, evicted or
    /// piecewise), e.g. for a hex view. Decoded sources are decoded as far
    /// as needed, in one call however long that takes; see
    /// [`Session::read_step`] for a read in bounded steps. If host bytes are
    /// missing, returns the requests to [`Session::supply`] first.
    pub fn read(&mut self, span: Span) -> Result<Vec<u8>, Vec<ByteRequest>> {
        loop {
            match self.read_step(span, u64::MAX) {
                ReadProgress::Done(data) => return Ok(data),
                ReadProgress::NeedBytes(requests) => return Err(requests),
                ReadProgress::Yielded => {}
            }
        }
    }

    /// Like [`Session::read`], but decodes for at most `budget` units of work
    /// (the units of [`Session::poll`]) before returning
    /// [`ReadProgress::Yielded`]. Decoding progress is kept: calling again
    /// continues where it stopped, so a far read into a large compressed
    /// stream can be spread over several calls, or abandoned. Expansions
    /// share the decoders, so their reads profit from the work too.
    pub fn read_step(&mut self, span: Span, budget: u64) -> ReadProgress {
        let result = {
            let mut sh = lock(&self.shared);
            let saved = std::mem::replace(&mut sh.budget, budget.max(1));
            let result = sh.read_range(span.source, span.offset, span.end(), 0);
            sh.budget = saved;
            result
        };
        match result {
            Ok(data) => ReadProgress::Done(data),
            Err(Pending::Budget) => ReadProgress::Yielded,
            Err(Pending::Bytes(missing)) => ReadProgress::NeedBytes(self.requests(missing)),
        }
    }

    /// The bytes of a derived source held in memory, if they are (see
    /// [`Session::read`] for any source).
    pub fn derived_data(&self, source: SourceId) -> Option<Arc<[u8]>> {
        lock(&self.shared)
            .source(source)
            .and_then(|s| s.data.clone())
    }

    /// Adds a top-level node.
    pub fn add_root(&mut self, node: Node) -> NodeId {
        self.alloc(Entry::new(node, None, 0))
    }

    /// Registers a source and adds a root node that identifies and dissects it.
    pub fn open(&mut self, name: impl Into<Cow<'static, str>>, len: u64) -> NodeId {
        let source = self.add_source(len);
        self.add_root(formats::root(name, Span::new(source, 0, len)))
    }

    /// Registers a source and adds a root node that dissects it as `format`,
    /// skipping identification ("inspect as"). Use `formats::by_name` or
    /// `formats::by_extension` to pick the format. On data that does not
    /// match, the dissector shows what it could parse and reports where it
    /// stopped.
    pub fn open_as(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        len: u64,
        format: &'static formats::Format,
    ) -> NodeId {
        let source = self.add_source(len);
        let span = Span::new(source, 0, len);
        self.add_root(formats::embedded_as(
            name,
            formats::Input::root(span),
            format,
        ))
    }

    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.entry(id).map(|e| &e.node)
    }

    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.entry(id).and_then(|e| e.parent)
    }

    /// How `id`'s content is dissected: the format its own detection step
    /// identified, or the one forced with [`Session::reinterpret`]. `None`
    /// until an expansion of the node reaches that step, and for nodes whose
    /// children are fields rather than a file within the file.
    pub fn interpretation(&self, id: NodeId) -> Option<Interpretation> {
        self.entry(id).and_then(|e| e.interpretation)
    }

    /// Dissects `id`'s content as `format` ("inspect as"), or, with `None`,
    /// returns it to identification. Applies to nodes holding a file within
    /// the file: an archive member, decompressed data, an embedded resource,
    /// a root (see [`Session::interpretation`]); on others it has no effect.
    /// The format holds where identification would run, so a "Decompressed"
    /// node still decompresses first.
    ///
    /// The node is collapsed (expand it again to see the result), and
    /// formats forced below it are dropped. The choice survives
    /// [`Session::trim`] and collapsing an ancestor. Returns `false` if the
    /// node is stale or has no children to produce.
    pub fn reinterpret(&mut self, id: NodeId, format: Option<&'static formats::Format>) -> bool {
        let Some(entry) = self.entry(id) else {
            return false;
        };
        if !entry.node.has_children() {
            return false;
        }
        let Some((root, path)) = self.address(id) else {
            return false;
        };
        self.reinterpret_at(root, &path, format);
        true
    }

    /// [`Session::reinterpret`] by address: forces `format` (or, with
    /// `None`, identification) for the node at `path` below `root`, whether
    /// or not it is materialised now. It takes effect when that node is
    /// expanded. Hosts use this to restore choices made earlier, e.g. in
    /// another session over the same file (see [`Session::address`]).
    pub fn reinterpret_at(
        &mut self,
        root: NodeId,
        path: &[u64],
        format: Option<&'static formats::Format>,
    ) {
        self.overrides
            .retain(|(r, p), _| !(*r == root && p.len() > path.len() && p.starts_with(path)));
        let address = (root, path.to_vec());
        match format {
            Some(format) => self.overrides.insert(address, format),
            None => self.overrides.remove(&address),
        };
        if let Some(id) = self.node_at(root, path)
            && let Some(entry) = self.entry_mut(id)
        {
            entry.interpretation = None;
            self.collapse(id);
        }
    }

    /// The formats forced with [`Session::reinterpret`] below `root`: each
    /// node's path and format.
    pub fn reinterpretations(&self, root: NodeId) -> Vec<(Vec<u64>, &'static formats::Format)> {
        let mut out: Vec<_> = self
            .overrides
            .iter()
            .filter(|((r, _), _)| *r == root)
            .map(|((_, path), &format)| (path.clone(), format))
            .collect();
        out.sort_unstable_by(|a, b| a.0.cmp(&b.0));
        out
    }

    /// Where `id` sits: its root and its index among its parent's children
    /// at each level down (see [`Address`]). `None` for a stale handle.
    pub fn address(&self, id: NodeId) -> Option<Address> {
        let mut path = Vec::new();
        let mut cursor = id;
        loop {
            let entry = self.entry(cursor)?;
            match entry.parent {
                Some(parent) => {
                    path.push(entry.index);
                    cursor = parent;
                }
                None => {
                    path.reverse();
                    return Some((cursor, path));
                }
            }
        }
    }

    /// The node at `path` below `root`, if it is materialised. To reach one
    /// that is not, expand (or [`Session::seek`]) each level and poll.
    pub fn node_at(&self, root: NodeId, path: &[u64]) -> Option<NodeId> {
        let mut id = root;
        for &index in path {
            let entry = self.entry(id)?;
            let at = to_usize(index.checked_sub(entry.first)?);
            id = *entry.children.get(at)?;
        }
        self.entry(id).map(|_| id)
    }

    pub fn children(&self, id: NodeId) -> Option<Children<'_>> {
        self.entry(id).map(|e| Children {
            ids: &e.children,
            first: e.first,
            state: e.state,
            count: e.count,
            error: e.error.as_ref(),
        })
    }

    /// Requests the children of `id` up to index `at_least` (exclusive).
    /// No work happens until [`Session::poll`].
    pub fn expand(&mut self, id: NodeId, at_least: u64) {
        self.clock = self.clock.wrapping_add(1);
        let clock = self.clock;
        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        entry.touched = clock;
        let have = entry.first.saturating_add(to_u64(entry.children.len()));
        let first = entry.first;
        // Children past the window were produced and dropped (see
        // [`Session::seek`]): the run has moved on, so only a restart
        // produces them again.
        if at_least > have
            && entry.produced > have
            && !matches!(entry.state, ChildState::NotRequested | ChildState::Leaf)
        {
            let children = take(&mut entry.children);
            for child in children {
                self.release(child);
            }
            self.start(id, first, at_least);
            return;
        }
        match entry.state {
            ChildState::NotRequested => self.start(id, first, at_least),
            ChildState::More | ChildState::Running(_) => {
                if let Some(run) = &entry.run {
                    let mut out = lock(&run.out);
                    out.target = out.target.max(at_least);
                }
                if entry.state == ChildState::More && at_least > have {
                    entry.state = ChildState::Running(Wait::Ready);
                    self.active.push(id);
                }
            }
            ChildState::Leaf | ChildState::Complete | ChildState::Failed => {}
        }
    }

    /// Moves the window of `id`'s children to indices `start..start + len`:
    /// children outside it are released (their handles go stale) and the
    /// missing ones are produced on the next polls. Seeking forward continues
    /// the running expansion, dropping what lies before the window; seeking
    /// backward restarts it, from the nearest resume mark (see
    /// [`crate::Cx::mark`]) if the dissector records them. This keeps memory
    /// bounded for huge collections while allowing random access.
    pub fn seek(&mut self, id: NodeId, start: u64, len: u64) {
        self.clock = self.clock.wrapping_add(1);
        let clock = self.clock;
        let end = start.saturating_add(len);
        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        entry.touched = clock;
        if entry.state == ChildState::Leaf {
            return;
        }
        let first = entry.first;
        let have = first.saturating_add(to_u64(entry.children.len()));
        // Release children outside the window.
        let keep_from = to_usize(start.saturating_sub(first)).min(entry.children.len());
        let keep_to = to_usize(end.saturating_sub(first)).min(entry.children.len());
        let mut dropped: Vec<NodeId> = entry.children.drain(keep_to..).collect();
        dropped.extend(entry.children.drain(..keep_from));
        // The window needs children from here on; ones before `produced`
        // were dropped earlier, so the run (which continues from
        // `produced`) cannot supply them.
        let need_from = start.max(have);
        let restart = start < first
            || (entry.state == ChildState::NotRequested)
            || (end > need_from && entry.produced > need_from)
            || (end > have
                && matches!(entry.state, ChildState::More | ChildState::Running(_))
                && {
                    // Jump ahead from a mark if one lies beyond where the
                    // running expansion has got to.
                    let emitted = entry.run.as_ref().map_or(0, |r| lock(&r.out).emitted);
                    entry
                        .marks
                        .range(..=start)
                        .next_back()
                        .is_some_and(|(&i, _)| i > emitted)
                });
        if restart {
            dropped.append(&mut entry.children);
        }
        for child in dropped {
            self.release(child);
        }
        if restart {
            self.start(id, start, end);
            return;
        }
        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        // What is left starts at `start` (or nothing is left).
        entry.first = start;
        if end > have
            && let Some(run) = &entry.run
        {
            let mut out = lock(&run.out);
            out.target = out.target.max(end);
            out.skip = out.skip.max(start);
            drop(out);
            if entry.state == ChildState::More {
                entry.state = ChildState::Running(Wait::Ready);
                self.active.push(id);
            }
        }
    }

    /// Starts (or restarts) the expansion of `id`, producing children from
    /// index `start` up to `target`, resuming from the nearest mark.
    fn start(&mut self, id: NodeId, start: u64, target: u64) {
        let shared = self.shared.clone();
        let registry = self.registry;
        let forced = if self.overrides.is_empty() {
            None
        } else {
            self.address(id)
                .and_then(|address| self.overrides.get(&address).copied())
        };
        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        let Some(expander) = entry.node.expander.clone() else {
            return;
        };
        let (from, resume) = match entry.marks.range(..=start).next_back() {
            Some((&index, key)) => (index, Some(key.clone())),
            None => (0, None),
        };
        let out = Arc::new(Mutex::new(Output {
            target,
            skip: start,
            emitted: from,
            last_mark: from,
            resume,
            forced,
            ..Output::default()
        }));
        let cx = Cx {
            shared,
            out: out.clone(),
            registry,
        };
        entry.run = Some(Run {
            future: expander.start(cx),
            out,
            waiting: Vec::new(),
            secret: None,
        });
        // A restarted expansion reproduces its own diagnostics.
        entry.node.diagnostics.truncate(entry.own_diagnostics);
        entry.error = None;
        entry.work = 0;
        entry.produced = from;
        entry.first = start;
        entry.state = ChildState::Running(Wait::Ready);
        self.active.retain(|&a| a != id);
        self.active.push(id);
    }

    /// Requests `page` more children than are currently present.
    pub fn expand_more(&mut self, id: NodeId, page: u64) {
        let have = self
            .entry(id)
            .map_or(0, |e| e.first.saturating_add(to_u64(e.children.len())));
        self.expand(id, have.saturating_add(page));
    }

    /// Discards the children of `id` and any expansion in progress. Expanding
    /// again re-runs the dissector and produces the same children.
    pub fn collapse(&mut self, id: NodeId) {
        let children = match self.entry_mut(id) {
            Some(entry) => {
                entry.run = None;
                entry.work = 0;
                entry.produced = 0;
                entry.error = None;
                entry.first = 0;
                entry.node.diagnostics.truncate(entry.own_diagnostics);
                entry.count = Count::Unknown;
                entry.state = if entry.node.has_children() {
                    ChildState::NotRequested
                } else {
                    ChildState::Leaf
                };
                take(&mut entry.children)
            }
            None => return,
        };
        for child in children {
            self.release(child);
        }
        self.active.retain(|&a| a != id);
    }

    /// Runs expansions until they finish, block on bytes, fill their page, or
    /// the budget (in abstract work units) runs out.
    pub fn poll(&mut self, budget: u64) -> Progress {
        lock(&self.shared).budget = budget.max(1);
        let mut i = 0;
        while let Some(&id) = self.active.get(i) {
            if lock(&self.shared).budget == 0 {
                break;
            }
            i = i.saturating_add(1);
            if self.is_runnable(id) {
                self.step(id);
            }
        }
        // Round robin: the next poll starts with the first expansion this one
        // did not reach, so one that always uses up the budget cannot starve
        // the others.
        if i < self.active.len() {
            self.active.rotate_left(i);
        }
        self.active.retain(|&id| {
            self.slots
                .get(to_usize(id.index.into()))
                .filter(|s| s.generation == id.generation)
                .and_then(|s| s.entry.as_ref())
                .is_some_and(|e| matches!(e.state, ChildState::Running(_)))
        });

        let active = self.active.clone();
        self.report(&active)
    }

    /// What the expansions of `ids` are waiting for.
    fn report(&self, ids: &[NodeId]) -> Progress {
        let mut wanted: Vec<(SourceId, u64)> = Vec::new();
        let mut secrets: Vec<SecretRequest> = Vec::new();
        let mut runnable = false;
        for &id in ids {
            if self.is_runnable(id) {
                runnable = true;
            } else if let Some(run) = self.entry(id).and_then(|e| e.run.as_ref()) {
                wanted.extend(run.waiting.iter().copied());
                if let Some(request) = &run.secret
                    && !secrets.iter().any(|r| r.key() == request.key())
                {
                    secrets.push(request.clone());
                }
            }
        }
        let requests = self.requests(wanted);
        if !requests.is_empty() {
            Progress::NeedBytes(requests)
        } else if runnable {
            Progress::Yielded
        } else if !secrets.is_empty() {
            Progress::NeedSecret(secrets)
        } else {
            Progress::Idle
        }
    }

    /// Runs only the expansion of `id` until it finishes, blocks, fills its
    /// page, or the budget runs out. Nothing else runs: other expansions,
    /// and an expansion nobody polls, stay parked where they stopped, with
    /// their children and resume state, and continue when polled again. So
    /// a host cancels work by not polling it (rather than with
    /// [`Session::collapse`], which discards it).
    ///
    /// Expansions never wait on each other: lazily decoded sources are
    /// decoded by whichever read reaches them first, and the progress is
    /// shared. The result describes `id` alone; [`Progress::Idle`] means it
    /// has nothing to do (complete, failed, page full, or not expanded).
    pub fn poll_node(&mut self, id: NodeId, budget: u64) -> Progress {
        lock(&self.shared).budget = budget.max(1);
        if self.is_runnable(id) {
            self.step(id);
        }
        if self
            .entry(id)
            .is_some_and(|e| !matches!(e.state, ChildState::Running(_)))
        {
            self.active.retain(|&a| a != id);
        }
        self.report(&[id])
    }

    /// How far the running expansion of `id` has got, as `(done, total)`:
    /// what the dissector reported (see [`crate::Cx::progress`]), or else
    /// children produced out of an exact announced count. `None` if the
    /// node is not being expanded or there is nothing to go by.
    pub fn progress(&self, id: NodeId) -> Option<(u64, u64)> {
        let entry = self.entry(id)?;
        let run = entry.run.as_ref()?;
        let out = lock(&run.out);
        out.progress.or(match entry.count {
            Count::Exact(n) if n > 0 => Some((out.emitted.min(n), n)),
            _ => None,
        })
    }

    /// Answers a secret request (`None` declines it). The answer is kept for
    /// the session and serves every request with the same realm and attempt.
    pub fn answer_secret(&mut self, request: &SecretRequest, secret: Option<Secret>) {
        lock(&self.shared).secrets.insert(request.key(), secret);
    }

    /// Supplies source bytes starting at `offset`. Any whole cache chunks
    /// covered by `data` are stored; the rest is ignored.
    pub fn supply(&mut self, source: SourceId, offset: u64, data: &[u8]) {
        let mut sh = lock(&self.shared);
        let source_len = sh.source_len(source);
        let chunk_size = sh.cache.chunk_size();
        let end = offset.saturating_add(to_u64(data.len()));
        let mut index = sh
            .cache
            .chunk_index(offset.saturating_add(chunk_size.saturating_sub(1)));
        loop {
            let start = sh.cache.chunk_start(index);
            if start >= end || start >= source_len {
                break;
            }
            let chunk_end = start.saturating_add(chunk_size).min(source_len);
            if chunk_end > end {
                break;
            }
            let from = to_usize(start.saturating_sub(offset));
            let to = to_usize(chunk_end.saturating_sub(offset));
            if let Some(bytes) = data.get(from..to) {
                sh.cache.insert(source, index, bytes.to_vec());
            }
            index = index.saturating_add(1);
        }
    }

    fn is_runnable(&self, id: NodeId) -> bool {
        let Some(entry) = self.entry(id) else {
            return false;
        };
        let Some(run) = &entry.run else {
            return false;
        };
        match entry.state {
            ChildState::Running(Wait::Ready | Wait::Budget) => true,
            ChildState::Running(Wait::Bytes) => {
                let sh = lock(&self.shared);
                // A chunk past the end of a source that shrank meanwhile
                // (see [`Session::set_source_len`]) will never be supplied;
                // the read now ends before it.
                run.waiting.iter().all(|&(s, i)| {
                    sh.cache.contains(s, i) || sh.cache.chunk_start(i) >= sh.source_len(s)
                })
            }
            ChildState::Running(Wait::Secret) => run
                .secret
                .as_ref()
                .is_some_and(|r| lock(&self.shared).secrets.contains_key(&r.key())),
            _ => false,
        }
    }

    fn step(&mut self, id: NodeId) {
        let Some(mut run) = self.entry_mut(id).and_then(|e| e.run.take()) else {
            return;
        };
        let budget_before = {
            let mut sh = lock(&self.shared);
            sh.stop = None;
            sh.wanted.clear();
            sh.secret_wanted = None;
            sh.budget
        };
        let result = run
            .future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let (stop, wanted, secret, used, max_work) = {
            let mut sh = lock(&self.shared);
            (
                sh.stop.take(),
                take(&mut sh.wanted),
                sh.secret_wanted.take(),
                budget_before.saturating_sub(sh.budget),
                sh.limits.max_work,
            )
        };
        let (nodes, count, summary, diagnostics, marks, emitted, interpretation) = {
            let mut out = lock(&run.out);
            (
                take(&mut out.nodes),
                out.count,
                out.summary.take(),
                take(&mut out.diagnostics),
                take(&mut out.marks),
                out.emitted,
                out.interpretation.take(),
            )
        };
        // The window is contiguous: new children follow the present ones.
        let base = self
            .entry(id)
            .map_or(0, |e| e.first.saturating_add(to_u64(e.children.len())));
        let ids: Vec<NodeId> = nodes
            .into_iter()
            .zip(0u64..)
            .map(|(node, i)| self.alloc(Entry::new(node, Some(id), base.saturating_add(i))))
            .collect();

        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        entry.children.extend(ids);
        entry.produced = emitted;
        entry.marks.extend(marks);
        if interpretation.is_some() {
            entry.interpretation = interpretation;
        }
        // Keep marks sparse: past the cap, drop every other one.
        if entry.marks.len() > MAX_MARKS {
            let mut keep = false;
            entry.marks.retain(|_, _| {
                keep = !keep;
                keep
            });
        }
        if let Some(count) = count {
            entry.count = count;
        }
        if let Some(summary) = summary {
            entry.node.summary = Some(summary);
        }
        entry.node.diagnostics.extend(diagnostics);
        entry.work = entry.work.saturating_add(used);
        if result.is_pending() && entry.work > max_work {
            entry.state = ChildState::Failed;
            entry.error = Some(Diagnostic::limit(format!(
                "expansion stopped after {max_work} units of work"
            )));
            return;
        }
        match result {
            Poll::Ready(Ok(())) => {
                entry.state = ChildState::Complete;
                entry.count = Count::Exact(emitted);
            }
            Poll::Ready(Err(error)) => {
                entry.state = ChildState::Failed;
                entry.error = Some(error);
            }
            Poll::Pending => {
                entry.state = match stop {
                    Some(Stop::Bytes) => {
                        run.waiting = wanted;
                        ChildState::Running(Wait::Bytes)
                    }
                    Some(Stop::Budget) => ChildState::Running(Wait::Budget),
                    Some(Stop::Secret) => {
                        run.secret = secret;
                        ChildState::Running(Wait::Secret)
                    }
                    Some(Stop::Page) => {
                        // The host paces the expansion from here on: the
                        // work limit bounds work between pages (where a
                        // dissector that makes no progress shows), not the
                        // whole of a long listing.
                        entry.work = 0;
                        ChildState::More
                    }
                    None => {
                        entry.state = ChildState::Failed;
                        entry.error = Some(Diagnostic::internal(
                            "dissector suspended on a future that is not driven by Cx",
                        ));
                        return;
                    }
                };
                entry.run = Some(run);
            }
        }
    }

    /// Merges missing chunks into contiguous byte requests.
    fn requests(&self, mut wanted: Vec<(SourceId, u64)>) -> Vec<ByteRequest> {
        let sh = lock(&self.shared);
        wanted.retain(|&(s, i)| !sh.cache.contains(s, i));
        wanted.sort_unstable();
        wanted.dedup();
        let mut out: Vec<ByteRequest> = Vec::new();
        let chunk_size = sh.cache.chunk_size();
        for (source, index) in wanted {
            let offset = sh.cache.chunk_start(index);
            let len = chunk_size.min(sh.source_len(source).saturating_sub(offset));
            if len == 0 {
                continue;
            }
            if let Some(last) = out.last_mut()
                && last.source == source
                && last.offset.saturating_add(last.len) == offset
            {
                last.len = last.len.saturating_add(len);
                continue;
            }
            out.push(ByteRequest {
                source,
                offset,
                len,
            });
        }
        out
    }

    fn entry(&self, id: NodeId) -> Option<&Entry> {
        self.slots
            .get(to_usize(id.index.into()))
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.entry.as_ref())
    }

    fn entry_mut(&mut self, id: NodeId) -> Option<&mut Entry> {
        self.slots
            .get_mut(to_usize(id.index.into()))
            .filter(|s| s.generation == id.generation)
            .and_then(|s| s.entry.as_mut())
    }

    fn alloc(&mut self, entry: Entry) -> NodeId {
        self.live = self.live.saturating_add(1);
        if let Some(index) = self.free.pop()
            && let Some(slot) = self.slots.get_mut(to_usize(index.into()))
        {
            slot.entry = Some(entry);
            return NodeId {
                index,
                generation: slot.generation,
            };
        }
        let index = u32::try_from(self.slots.len()).unwrap_or(u32::MAX);
        self.slots.push(Slot {
            generation: 0,
            entry: Some(entry),
        });
        NodeId {
            index,
            generation: 0,
        }
    }

    fn release(&mut self, id: NodeId) {
        let mut stack = vec![id];
        while let Some(id) = stack.pop() {
            let Some(slot) = self
                .slots
                .get_mut(to_usize(id.index.into()))
                .filter(|s| s.generation == id.generation)
            else {
                continue;
            };
            if let Some(entry) = slot.entry.take() {
                stack.extend(entry.children);
                self.live = self.live.saturating_sub(1);
            }
            slot.generation = slot.generation.wrapping_add(1);
            self.free.push(id.index);
        }
        let slots = &self.slots;
        self.active.retain(|a| {
            slots
                .get(to_usize(a.index.into()))
                .is_some_and(|s| s.generation == a.generation && s.entry.is_some())
        });
    }
}
