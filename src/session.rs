//! The host-facing side: the node arena, expansion state, and the poll loop.

use std::borrow::Cow;
use std::mem::take;
use std::sync::{Arc, Mutex};
use std::task::{Context, Poll, Waker};

use crate::bytes::{to_u64, to_usize};
use crate::cache::ByteCache;
use crate::cx::{Cx, Output, Shared, Stop, lock};
use crate::error::Diagnostic;
use crate::formats;
use crate::node::{Count, Expansion, Node};
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
}

impl Default for Limits {
    fn default() -> Self {
        Limits {
            chunk_size: 64 * 1024,
            cache_bytes: 64 * 1024 * 1024,
            max_read: 16 * 1024 * 1024,
            max_nesting: 16,
            max_derived: 256 * 1024 * 1024,
        }
    }
}

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
}

pub struct Children<'a> {
    pub ids: &'a [NodeId],
    pub state: ChildState,
    pub count: Count,
    pub error: Option<&'a Diagnostic>,
}

/// A range of source bytes the host should read and [`Session::supply`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct ByteRequest {
    pub source: SourceId,
    pub offset: u64,
    pub len: u64,
}

/// Outcome of [`Session::poll`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Progress {
    /// Nothing to do until the host requests more.
    Idle,
    /// The budget ran out with work remaining; poll again.
    Yielded,
    /// Expansions are blocked on these bytes. Supply them and poll again.
    /// (Other expansions may also be runnable.)
    NeedBytes(Vec<ByteRequest>),
}

pub struct Session {
    shared: Arc<Mutex<Shared>>,
    slots: Vec<Slot>,
    free: Vec<u32>,
    active: Vec<NodeId>,
    live: usize,
    clock: u64,
}

struct Slot {
    generation: u32,
    entry: Option<Entry>,
}

struct Entry {
    node: Node,
    parent: Option<NodeId>,
    children: Vec<NodeId>,
    state: ChildState,
    count: Count,
    error: Option<Diagnostic>,
    run: Option<Run>,
    /// When the host last asked for this node's children.
    touched: u64,
}

struct Run {
    future: Expansion,
    out: Arc<Mutex<Output>>,
    waiting: Vec<(SourceId, u64)>,
}

impl Entry {
    fn new(node: Node, parent: Option<NodeId>) -> Self {
        let state = if node.has_children() {
            ChildState::NotRequested
        } else {
            ChildState::Leaf
        };
        Entry {
            node,
            parent,
            children: Vec::new(),
            state,
            count: Count::Unknown,
            error: None,
            run: None,
            touched: 0,
        }
    }
}

impl Session {
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
            cache: ByteCache::new(limits.chunk_size, limits.cache_bytes),
            budget: 0,
            stop: None,
            wanted: Vec::new(),
            limits,
        };
        Session {
            shared: Arc::new(Mutex::new(shared)),
            slots: Vec::new(),
            free: Vec::new(),
            active: Vec::new(),
            live: 0,
            clock: 0,
        }
    }

    /// Number of nodes currently materialised.
    pub fn live_nodes(&self) -> usize {
        self.live
    }

    /// Bounds memory by collapsing the least recently expanded subtrees until
    /// at most `max_nodes` nodes remain (or nothing more can be collapsed).
    /// Nodes in `keep`, and their ancestors, are not collapsed. Collapsed
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
                (expanded && entry.parent.is_some() && !protected.contains(&id))
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
        sh.sources.push(crate::cx::SourceEntry {
            len,
            data: None,
            origin: None,
            consumed: 0,
            error: None,
        });
        id
    }

    pub fn source_len(&self, source: SourceId) -> u64 {
        lock(&self.shared).source_len(source)
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

    /// Where a derived source came from (`None` for host sources).
    pub fn origin(&self, source: SourceId) -> Option<Origin> {
        lock(&self.shared).source(source).and_then(|s| s.origin)
    }

    /// The bytes of a derived source, e.g. for a hex view.
    pub fn derived_data(&self, source: SourceId) -> Option<Arc<[u8]>> {
        lock(&self.shared)
            .source(source)
            .and_then(|s| s.data.clone())
    }

    /// Adds a top-level node.
    pub fn add_root(&mut self, node: Node) -> NodeId {
        self.alloc(Entry::new(node, None))
    }

    /// Registers a source and adds a root node that identifies and dissects it.
    pub fn open(&mut self, name: impl Into<Cow<'static, str>>, len: u64) -> NodeId {
        let source = self.add_source(len);
        self.add_root(formats::root(name, Span::new(source, 0, len)))
    }

    pub fn node(&self, id: NodeId) -> Option<&Node> {
        self.entry(id).map(|e| &e.node)
    }

    pub fn parent(&self, id: NodeId) -> Option<NodeId> {
        self.entry(id).and_then(|e| e.parent)
    }

    pub fn children(&self, id: NodeId) -> Option<Children<'_>> {
        self.entry(id).map(|e| Children {
            ids: &e.children,
            state: e.state,
            count: e.count,
            error: e.error.as_ref(),
        })
    }

    /// Requests at least `at_least` children of `id`. No work happens until
    /// [`Session::poll`].
    pub fn expand(&mut self, id: NodeId, at_least: u64) {
        let shared = self.shared.clone();
        self.clock = self.clock.wrapping_add(1);
        let clock = self.clock;
        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        entry.touched = clock;
        let have = to_u64(entry.children.len());
        match entry.state {
            ChildState::NotRequested => {
                let Some(expander) = entry.node.expander.clone() else {
                    return;
                };
                let out = Arc::new(Mutex::new(Output {
                    target: at_least,
                    ..Output::default()
                }));
                let cx = Cx {
                    shared,
                    out: out.clone(),
                };
                entry.run = Some(Run {
                    future: expander.start(cx),
                    out,
                    waiting: Vec::new(),
                });
                entry.state = ChildState::Running(Wait::Ready);
                self.active.push(id);
            }
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

    /// Requests `page` more children than are currently present.
    pub fn expand_more(&mut self, id: NodeId, page: u64) {
        let have = self.entry(id).map_or(0, |e| to_u64(e.children.len()));
        self.expand(id, have.saturating_add(page));
    }

    /// Discards the children of `id` and any expansion in progress. Expanding
    /// again re-runs the dissector and produces the same children.
    pub fn collapse(&mut self, id: NodeId) {
        let children = match self.entry_mut(id) {
            Some(entry) => {
                entry.run = None;
                entry.error = None;
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
            i = i.saturating_add(1);
            if lock(&self.shared).budget == 0 {
                break;
            }
            if self.is_runnable(id) {
                self.step(id);
            }
        }
        self.active.retain(|&id| {
            self.slots
                .get(to_usize(id.index.into()))
                .filter(|s| s.generation == id.generation)
                .and_then(|s| s.entry.as_ref())
                .is_some_and(|e| matches!(e.state, ChildState::Running(_)))
        });

        let mut wanted: Vec<(SourceId, u64)> = Vec::new();
        let mut runnable = false;
        for &id in &self.active {
            if self.is_runnable(id) {
                runnable = true;
            } else if let Some(run) = self.entry(id).and_then(|e| e.run.as_ref()) {
                wanted.extend(run.waiting.iter().copied());
            }
        }
        let requests = self.requests(wanted);
        if !requests.is_empty() {
            Progress::NeedBytes(requests)
        } else if runnable {
            Progress::Yielded
        } else {
            Progress::Idle
        }
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
                run.waiting.iter().all(|&(s, i)| sh.cache.contains(s, i))
            }
            _ => false,
        }
    }

    fn step(&mut self, id: NodeId) {
        let Some(mut run) = self.entry_mut(id).and_then(|e| e.run.take()) else {
            return;
        };
        {
            let mut sh = lock(&self.shared);
            sh.stop = None;
            sh.wanted.clear();
        }
        let result = run
            .future
            .as_mut()
            .poll(&mut Context::from_waker(Waker::noop()));
        let (stop, wanted) = {
            let mut sh = lock(&self.shared);
            (sh.stop.take(), take(&mut sh.wanted))
        };
        let (nodes, count, summary, diagnostics) = {
            let mut out = lock(&run.out);
            (
                take(&mut out.nodes),
                out.count,
                out.summary.take(),
                take(&mut out.diagnostics),
            )
        };
        let ids: Vec<NodeId> = nodes
            .into_iter()
            .map(|node| self.alloc(Entry::new(node, Some(id))))
            .collect();

        let Some(entry) = self.entry_mut(id) else {
            return;
        };
        entry.children.extend(ids);
        if let Some(count) = count {
            entry.count = count;
        }
        if let Some(summary) = summary {
            entry.node.summary = Some(summary);
        }
        entry.node.diagnostics.extend(diagnostics);
        match result {
            Poll::Ready(Ok(())) => {
                entry.state = ChildState::Complete;
                entry.count = Count::Exact(to_u64(entry.children.len()));
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
                    Some(Stop::Page) => ChildState::More,
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
