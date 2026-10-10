//! fillyfoal for the browser: a [`Session`] over one file, driven a step at a
//! time by the explorer's worker, which reads the bytes the session asks for
//! with `Blob.slice()`.
//!
//! Nodes cross to JavaScript under small integer keys, as JSON: fillyfoal's
//! own handles aren't serializable, and children, once produced, are kept for
//! the life of the dissection, so a key stays valid. Sources cross by index;
//! the session has no lookup from an index back to a source, so every source
//! a span sent out names is remembered.

use std::collections::HashMap;

use fillyfoal::{
    ByteRequest, ChildState, Count, DiagKind, Diagnostic, Limits, NodeId, Progress, Radix,
    ReadProgress, Secret, SecretRequest, Session, SourceId, Span, Value, Wait, formats,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[wasm_bindgen]
pub struct Dissection {
    session: Session,
    root: NodeId,
    file: SourceId,
    ids: Vec<NodeId>,
    keys: HashMap<NodeId, u32>,
    sources: HashMap<u32, SourceId>,
    /// Passwords the expansions are waiting for, answered by index.
    secrets: Vec<SecretRequest>,
    /// What the last finished [`Dissection::read_step`] read.
    read: Vec<u8>,
}

fn error(message: impl Into<String>) -> JsError {
    JsError::new(&message.into())
}

fn json<T: Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap_or_else(|_| "null".into())
}

/// A JavaScript number as a byte offset or count; fractions and negatives
/// don't occur, and saturate if they do.
fn int(n: f64) -> u64 {
    n as u64
}

#[wasm_bindgen]
impl Dissection {
    /// A dissection of a file of `len` bytes called `name`, with the formats
    /// chosen for it or for files within it (`[{path, format}]` as JSON).
    /// Nothing is read until something is expanded.
    #[wasm_bindgen(constructor)]
    pub fn new(name: String, len: f64, choices: &str) -> Result<Dissection, JsError> {
        let choices: Vec<Choice> =
            serde_json::from_str(choices).map_err(|e| error(e.to_string()))?;
        let mut session = Session::new(Limits::default());
        let root = session.open(name, int(len));
        for choice in &choices {
            session.reinterpret_at(root, &choice.path, Some(format_named(&choice.format)?));
        }
        let file = session
            .node(root)
            .and_then(|n| n.span)
            .map_or(SourceId::default_host(), |s| s.source);
        let mut dissection = Dissection {
            session,
            root,
            file,
            ids: Vec::new(),
            keys: HashMap::new(),
            sources: HashMap::from([(file.index(), file)]),
            secrets: Vec::new(),
            read: Vec::new(),
        };
        dissection.key(root);
        Ok(dissection)
    }

    pub fn root(&mut self) -> u32 {
        self.key(self.root)
    }

    /// The index of the file's own byte space.
    #[wasm_bindgen(js_name = fileSource)]
    pub fn file_source(&self) -> u32 {
        self.file.index()
    }

    /// The node under `key` as JSON.
    pub fn node(&mut self, key: u32) -> Result<String, JsError> {
        let id = self.id(key)?;
        let node = self.wire_node(id);
        Ok(json(&node))
    }

    /// The node and every child it has loaded, as JSON.
    pub fn page(&mut self, key: u32) -> Result<String, JsError> {
        let id = self.id(key)?;
        let page = self.wire_page(id);
        Ok(json(&page))
    }

    /// Ask for at least `at_least` children of `key`; [`Dissection::poll`]
    /// produces them.
    pub fn expand(&mut self, key: u32, at_least: f64) -> Result<(), JsError> {
        let id = self.id(key)?;
        self.session.expand(id, int(at_least));
        Ok(())
    }

    #[wasm_bindgen(js_name = expandMore)]
    pub fn expand_more(&mut self, key: u32, page: f64) -> Result<(), JsError> {
        let id = self.id(key)?;
        self.session.expand_more(id, int(page));
        Ok(())
    }

    /// Run `key`'s expansion for about `budget` units of work. JSON:
    /// `{step: "idle" | "yielded" | "bytes" | "secret", requests?, progress?}`.
    pub fn poll(&mut self, key: u32, budget: f64) -> Result<String, JsError> {
        let id = self.id(key)?;
        let progress = self.session.poll_node(id, int(budget));
        let done = self.session.progress(id);
        let step = match progress {
            Progress::Idle => Step::Idle,
            Progress::Yielded => Step::Yielded,
            Progress::NeedBytes(requests) => Step::Bytes {
                requests: requests.iter().map(|r| self.request(r)).collect(),
            },
            Progress::NeedSecret(requests) => {
                self.secrets = requests;
                Step::Secret
            }
        };
        Ok(json(&Polled {
            step,
            progress: done,
        }))
    }

    /// Bytes read from the file at `offset`, for a request.
    pub fn supply(&mut self, source: u32, offset: f64, data: &[u8]) -> Result<(), JsError> {
        let source = self.source(source)?;
        self.session.supply(source, int(offset), data);
        Ok(())
    }

    /// The source ends at `len`: a read came back short.
    #[wasm_bindgen(js_name = setSourceLen)]
    pub fn set_source_len(&mut self, source: u32, len: f64) -> Result<(), JsError> {
        let source = self.source(source)?;
        self.session.set_source_len(source, int(len));
        Ok(())
    }

    /// Read bytes of any source a step at a time, decoding as needed. JSON
    /// like [`Dissection::poll`]'s, with `step: "done"` once the bytes are
    /// ready for [`Dissection::take_read`].
    #[wasm_bindgen(js_name = readStep)]
    pub fn read_step(
        &mut self,
        source: u32,
        offset: f64,
        len: f64,
        budget: f64,
    ) -> Result<String, JsError> {
        let source = self.source(source)?;
        let offset = int(offset);
        let len = int(len).min(self.session.source_len(source).saturating_sub(offset));
        let step = match self
            .session
            .read_step(Span::new(source, offset, len), int(budget))
        {
            ReadProgress::Done(bytes) => {
                self.read = bytes;
                Step::Done
            }
            ReadProgress::Yielded => Step::Yielded,
            ReadProgress::NeedBytes(requests) => Step::Bytes {
                requests: requests.iter().map(|r| self.request(r)).collect(),
            },
        };
        Ok(json(&Polled {
            step,
            progress: None,
        }))
    }

    #[wasm_bindgen(js_name = takeRead)]
    pub fn take_read(&mut self) -> Vec<u8> {
        std::mem::take(&mut self.read)
    }

    /// Where `key`'s children stand (see [`ChildrenState`]).
    #[wasm_bindgen(js_name = childState)]
    pub fn child_state(&self, key: u32) -> Result<String, JsError> {
        let id = self.id(key)?;
        let state = self
            .session
            .children(id)
            .map_or(ChildrenState::Leaf, |c| c.state.into());
        Ok(json(&state).trim_matches('"').to_string())
    }

    #[wasm_bindgen(js_name = childKeys)]
    pub fn child_keys(&mut self, key: u32) -> Result<Vec<u32>, JsError> {
        let id = self.id(key)?;
        let ids: Vec<NodeId> = self
            .session
            .children(id)
            .map(|c| c.ids.to_vec())
            .unwrap_or_default();
        Ok(ids.into_iter().map(|id| self.key(id)).collect())
    }

    /// Of `key`'s loaded children from index `from`, the one that comes
    /// closest to byte `offset` of `source` (see [`Dissection::reach`]), a
    /// container before a plain field at the same distance. JSON:
    /// `{found: key | null, scanned}` where `scanned` is where to go on from.
    #[wasm_bindgen(js_name = closestChild)]
    pub fn closest_child(
        &mut self,
        key: u32,
        from: u32,
        source: u32,
        offset: f64,
    ) -> Result<String, JsError> {
        let id = self.id(key)?;
        let lineage = self.lineage(self.source(source)?, int(offset));
        let ids = self.children_from(id, from);
        let best = ids
            .iter()
            .filter_map(|&child| {
                let (rank, has_children, _) = self.reach(child, &lineage);
                rank.map(|rank| ((rank, !has_children), child))
            })
            .min_by_key(|(order, _)| *order)
            .map(|(_, child)| child);
        let found = best.map(|id| self.key(id));
        Ok(json(&Found {
            found,
            scanned: self.scanned(from, ids.len()),
            deeper: Vec::new(),
        }))
    }

    /// One step of the search below a node none of whose children come
    /// close to the byte: of `key`'s loaded children from index `from`, the
    /// first that does (`found`), else those worth looking below
    /// (`deeper`): the ones with children whose bytes lie in a byte space
    /// on the byte's lineage.
    #[wasm_bindgen(js_name = searchChildren)]
    pub fn search_children(
        &mut self,
        key: u32,
        from: u32,
        source: u32,
        offset: f64,
    ) -> Result<String, JsError> {
        let id = self.id(key)?;
        let lineage = self.lineage(self.source(source)?, int(offset));
        let ids = self.children_from(id, from);
        let mut deeper = Vec::new();
        let mut found = None;
        for &child in &ids {
            let (rank, has_children, leads) = self.reach(child, &lineage);
            if rank.is_some() {
                found = Some(child);
                break;
            }
            if has_children && leads {
                deeper.push(child);
            }
        }
        let found = found.map(|id| self.key(id));
        let deeper = deeper.into_iter().map(|id| self.key(id)).collect();
        Ok(json(&Found {
            found,
            scanned: self.scanned(from, ids.len()),
            deeper,
        }))
    }

    /// Whether `key` holds a file within the file whose format is known
    /// (once it has been expanded).
    #[wasm_bindgen(js_name = holdsContent)]
    pub fn holds_content(&self, key: u32) -> Result<bool, JsError> {
        let id = self.id(key)?;
        Ok(self.session.interpretation(id).is_some())
    }

    /// Dissect `key`'s content as `format` (none identifies it again). What
    /// was below it is gone; expand it again.
    pub fn reinterpret(&mut self, key: u32, format: Option<String>) -> Result<bool, JsError> {
        let id = self.id(key)?;
        let format = format.map(|name| format_named(&name)).transpose()?;
        Ok(self.session.reinterpret(id, format))
    }

    /// Every format choice in effect, as JSON `[{path, format}]`.
    pub fn choices(&self) -> String {
        let choices: Vec<Choice> = self
            .session
            .reinterpretations(self.root)
            .into_iter()
            .map(|(path, format)| Choice {
                path,
                format: format.name.to_string(),
            })
            .collect();
        json(&choices)
    }

    /// Keys from the root down to `key`.
    #[wasm_bindgen(js_name = pathTo)]
    pub fn path_to(&mut self, key: u32) -> Result<Vec<u32>, JsError> {
        let mut id = self.id(key)?;
        let mut path = vec![id];
        while let Some(parent) = self.session.parent(id) {
            path.push(parent);
            id = parent;
        }
        path.reverse();
        Ok(path.into_iter().map(|id| self.key(id)).collect())
    }

    /// A byte space's length and where it came from, as JSON.
    #[wasm_bindgen(js_name = sourceInfo)]
    pub fn source_info(&mut self, source: u32) -> Result<String, JsError> {
        let source = self.source(source)?;
        let origin = self.session.origin(source).map(|o| WireOrigin {
            parent: self.span(o.parent),
            transform: o.transform.to_string(),
        });
        Ok(json(&WireSource {
            len: self.session.source_len(source),
            len_known: self.session.source_len_known(source),
            origin,
        }))
    }

    /// The first password an expansion waits for, as JSON, or `null`.
    pub fn secret(&self) -> String {
        json(&self.wire_secret())
    }

    /// Answer a password request (`None` declines it). The expansion waiting
    /// for it resumes when it is polled again.
    #[wasm_bindgen(js_name = answerSecret)]
    pub fn answer_secret(&mut self, index: u32, password: Option<String>) {
        let index = index as usize;
        let Some(request) = self.secrets.get(index).cloned() else {
            return;
        };
        self.session
            .answer_secret(&request, password.as_deref().map(Secret::password));
        self.secrets.remove(index);
    }

    /// The name of the file `key` holds, whose extension suggests formats:
    /// the nearest name with one, from `key` up (a member's data is called
    /// "Content", the member by its file name).
    #[wasm_bindgen(js_name = contentName)]
    pub fn content_name(&self, key: u32) -> Result<String, JsError> {
        let id = self.id(key)?;
        let mut cursor = Some(id);
        while let Some(id) = cursor {
            let name = self.session.node(id).map(|n| n.name.as_ref());
            if let Some(name) = name.filter(|n| n.contains('.')) {
                return Ok(name.to_string());
            }
            cursor = self.session.parent(id);
        }
        Ok(self
            .session
            .node(id)
            .map(|n| n.name.to_string())
            .unwrap_or_default())
    }
}

impl Dissection {
    fn key(&mut self, id: NodeId) -> u32 {
        if let Some(key) = self.keys.get(&id) {
            return *key;
        }
        let key = u32::try_from(self.ids.len()).unwrap_or(u32::MAX);
        self.ids.push(id);
        self.keys.insert(id, key);
        key
    }

    fn id(&self, key: u32) -> Result<NodeId, JsError> {
        self.ids
            .get(key as usize)
            .copied()
            .ok_or_else(|| error(format!("no node {key}")))
    }

    /// `offset` of `source`, then the bytes each stream it lies in was
    /// decoded from, down to the file.
    fn lineage(&self, source: SourceId, offset: u64) -> Vec<Span> {
        let mut lineage = vec![Span::new(source, offset, 1)];
        while let Some(origin) = lineage.last().and_then(|at| self.session.origin(at.source)) {
            // A decoded stream is never its own origin, but a loop must end.
            if lineage.len() > 64 {
                break;
            }
            lineage.push(origin.parent);
        }
        lineage
    }

    /// How close `id` comes to the byte at the head of `lineage`: 0 if it
    /// holds the byte, n if it holds the bytes the n-th stream down was
    /// decoded from (a "Content" node spans the compressed data, its fields
    /// the stream); `None` if neither. Also whether it has children, and
    /// whether they can lead to the byte at all: only through the byte
    /// spaces on its lineage.
    fn reach(&self, id: NodeId, lineage: &[Span]) -> (Option<usize>, bool, bool) {
        let Some(node) = self.session.node(id) else {
            return (None, false, false);
        };
        let span = node.span.filter(|s| !s.is_empty());
        let rank = span.and_then(|s| lineage.iter().position(|l| s.contains(l)));
        let leads = span.is_none_or(|s| lineage.iter().any(|l| l.source == s.source));
        (rank, node.has_children(), leads)
    }

    fn children_from(&self, id: NodeId, from: u32) -> Vec<NodeId> {
        self.session
            .children(id)
            .and_then(|c| c.ids.get((from as usize).min(c.ids.len())..))
            .map(<[NodeId]>::to_vec)
            .unwrap_or_default()
    }

    fn scanned(&self, from: u32, more: usize) -> u32 {
        u32::try_from(more).map_or(u32::MAX, |n| from.saturating_add(n))
    }

    fn source(&self, index: u32) -> Result<SourceId, JsError> {
        self.sources
            .get(&index)
            .copied()
            .ok_or_else(|| error(format!("no source {index}")))
    }

    fn span(&mut self, span: Span) -> WireSpan {
        self.sources.insert(span.source.index(), span.source);
        span.into()
    }

    fn request(&mut self, request: &ByteRequest) -> WireSpan {
        self.span(Span::new(request.source, request.offset, request.len))
    }

    fn wire_secret(&self) -> Option<WireSecret> {
        self.secrets.first().map(|request| WireSecret {
            index: 0,
            prompt: request.prompt.clone(),
            attempt: request.attempt,
        })
    }

    fn wire_page(&mut self, id: NodeId) -> WirePage {
        let ids: Vec<NodeId> = self
            .session
            .children(id)
            .map(|c| c.ids.to_vec())
            .unwrap_or_default();
        WirePage {
            parent: self.wire_node(id),
            nodes: ids.into_iter().map(|child| self.wire_node(child)).collect(),
            secret: self.wire_secret(),
        }
    }

    fn wire_node(&mut self, id: NodeId) -> WireNode {
        let key = self.key(id);
        let Some(node) = self.session.node(id) else {
            return WireNode::gone(key);
        };
        let mut spans: Vec<Span> = [node.span, node.target]
            .into_iter()
            .flatten()
            .chain(node.diagnostics.iter().filter_map(|d| d.span))
            .collect();
        let children = self.session.children(id);
        if let Some(span) = children.as_ref().and_then(|c| c.error.and_then(|e| e.span)) {
            spans.push(span);
        }
        let wire = WireNode {
            key,
            name: node.name.to_string(),
            value: node.value.as_ref().map(WireValue::from),
            summary: node.summary.clone(),
            description: node.description.as_ref().map(|d| d.to_string()),
            span: node.span.map(WireSpan::from),
            target: node.target.map(WireSpan::from),
            diagnostics: node.diagnostics.iter().map(WireDiagnostic::from).collect(),
            interpretation: self.session.interpretation(id).map(|i| WireInterpretation {
                format: i.format.map(|f| WireFormatName {
                    name: f.name,
                    title: f.title,
                }),
                forced: i.forced,
            }),
            children: match children {
                Some(c) => WireChildren {
                    state: c.state.into(),
                    loaded: u32::try_from(c.ids.len()).unwrap_or(u32::MAX),
                    count: match c.count {
                        Count::Exact(n) => Some(WireCount { n, at_least: false }),
                        Count::AtLeast(n) => Some(WireCount { n, at_least: true }),
                        Count::Unknown => None,
                    },
                    error: c.error.map(WireDiagnostic::from),
                },
                None => WireChildren::leaf(),
            },
        };
        for span in spans {
            self.span(span);
        }
        wire
    }
}

/// Every format, as JSON, those listing the extension of the file `name`
/// first.
#[wasm_bindgen]
pub fn formats(name: &str) -> String {
    let suggested = name
        .rsplit_once('.')
        .map(|(_, extension)| formats::by_extension(extension))
        .unwrap_or_default();
    let mut rest: Vec<_> = formats::FORMATS
        .iter()
        .filter(|f| !suggested.iter().any(|s| s.name == f.name))
        .collect();
    rest.sort_by_cached_key(|f| f.title.to_lowercase());
    let entry = |f: &formats::Format, suggested| WireFormat {
        name: f.name,
        title: f.title,
        extensions: f.extensions.to_vec(),
        suggested,
    };
    let list: Vec<WireFormat> = suggested
        .iter()
        .map(|f| entry(f, true))
        .chain(rest.into_iter().map(|f| entry(f, false)))
        .collect();
    json(&list)
}

fn format_named(name: &str) -> Result<&'static formats::Format, JsError> {
    formats::by_name(name).ok_or_else(|| error(format!("unknown format {name}")))
}

// --- Wire types ---

#[derive(Serialize, Deserialize)]
struct Choice {
    path: Vec<u64>,
    format: String,
}

#[derive(Serialize)]
#[serde(tag = "step", rename_all = "snake_case")]
enum Step {
    Idle,
    Yielded,
    Bytes { requests: Vec<WireSpan> },
    Secret,
    Done,
}

#[derive(Serialize)]
struct Polled {
    #[serde(flatten)]
    step: Step,
    progress: Option<(u64, u64)>,
}

#[derive(Serialize)]
struct Found {
    found: Option<u32>,
    scanned: u32,
    deeper: Vec<u32>,
}

#[derive(Serialize)]
struct WireNode {
    key: u32,
    name: String,
    value: Option<WireValue>,
    summary: Option<String>,
    description: Option<String>,
    span: Option<WireSpan>,
    target: Option<WireSpan>,
    diagnostics: Vec<WireDiagnostic>,
    interpretation: Option<WireInterpretation>,
    children: WireChildren,
}

impl WireNode {
    fn gone(key: u32) -> Self {
        WireNode {
            key,
            name: String::new(),
            value: None,
            summary: None,
            description: None,
            span: None,
            target: None,
            diagnostics: Vec::new(),
            interpretation: None,
            children: WireChildren::leaf(),
        }
    }
}

#[derive(Serialize)]
struct WireInterpretation {
    format: Option<WireFormatName>,
    forced: bool,
}

#[derive(Serialize)]
struct WireFormatName {
    name: &'static str,
    title: &'static str,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum ChildrenState {
    Leaf,
    Unloaded,
    Locked,
    More,
    /// Its expansion was stopped part-way; asking again continues it.
    Stopped,
    Complete,
    Failed,
}

impl From<ChildState> for ChildrenState {
    fn from(state: ChildState) -> Self {
        match state {
            ChildState::Leaf => Self::Leaf,
            ChildState::NotRequested => Self::Unloaded,
            ChildState::Running(Wait::Secret) => Self::Locked,
            ChildState::More => Self::More,
            // A finished request leaves no expansion running, so one still
            // running was stopped (or is being run by another request).
            ChildState::Running(_) => Self::Stopped,
            ChildState::Complete => Self::Complete,
            ChildState::Failed => Self::Failed,
        }
    }
}

#[derive(Serialize)]
struct WireChildren {
    state: ChildrenState,
    loaded: u32,
    count: Option<WireCount>,
    error: Option<WireDiagnostic>,
}

impl WireChildren {
    fn leaf() -> Self {
        WireChildren {
            state: ChildrenState::Leaf,
            loaded: 0,
            count: None,
            error: None,
        }
    }
}

#[derive(Serialize)]
struct WireCount {
    n: u64,
    at_least: bool,
}

#[derive(Serialize, Clone, Copy)]
#[serde(rename_all = "snake_case")]
enum ValueKind {
    Bool,
    Number,
    Enum,
    Flags,
    Float,
    Time,
    Text,
    Bytes,
    Guid,
}

#[derive(Serialize)]
struct WireValue {
    kind: ValueKind,
    /// The value as read: a name for an enum, the set flags, the number in
    /// the radix the format gives it.
    text: String,
    /// The number underneath, in the other radix (or the raw integer of an
    /// enum, flags or timestamp).
    raw: Option<String>,
}

/// Bits of a signed value as an unsigned number of that width.
fn twos_complement(value: i64, bits: u8) -> u64 {
    let mask = if bits >= 64 {
        u64::MAX
    } else {
        (1u64 << bits) - 1
    };
    value as u64 & mask
}

impl From<&Value> for WireValue {
    fn from(value: &Value) -> Self {
        use ValueKind as K;
        let (kind, text, raw) = match value {
            Value::Bool(b) => (K::Bool, b.to_string(), None),
            Value::UInt {
                value,
                radix: Radix::Hex,
                ..
            } => (K::Number, format!("{value:#x}"), Some(value.to_string())),
            Value::UInt { value, .. } => {
                (K::Number, value.to_string(), Some(format!("{value:#x}")))
            }
            Value::Int { value, bits } => (
                K::Number,
                value.to_string(),
                Some(format!("{:#x}", twos_complement(*value, *bits))),
            ),
            Value::Enum { raw, name, .. } => (
                K::Enum,
                name.map_or_else(|| "unknown".to_string(), str::to_string),
                Some(format!("{raw:#x}")),
            ),
            Value::Flags {
                raw, set, unknown, ..
            } => {
                let mut parts: Vec<String> = set.iter().map(|s| s.to_string()).collect();
                if *unknown != 0 {
                    parts.push(format!("{unknown:#x}"));
                }
                let text = if parts.is_empty() {
                    "none".to_string()
                } else {
                    parts.join(" | ")
                };
                (K::Flags, text, Some(format!("{raw:#x}")))
            }
            Value::Float(f) => (K::Float, f.to_string(), None),
            Value::Timestamp { unix_seconds } => (
                K::Time,
                fillyfoal::render::value(value),
                Some(unix_seconds.to_string()),
            ),
            Value::Text(s) => (K::Text, s.escape_debug().to_string(), None),
            Value::Bytes(b) => (
                K::Bytes,
                fillyfoal::render::value(value),
                Some(format!("{} bytes", b.len())),
            ),
            Value::Guid(g) => (K::Guid, g.to_string(), None),
        };
        WireValue { kind, text, raw }
    }
}

#[derive(Serialize, Clone, Copy)]
struct WireSpan {
    source: u32,
    offset: u64,
    len: u64,
}

impl From<Span> for WireSpan {
    fn from(span: Span) -> Self {
        WireSpan {
            source: span.source.index(),
            offset: span.offset,
            len: span.len,
        }
    }
}

#[derive(Serialize)]
#[serde(rename_all = "snake_case")]
enum DiagnosticKind {
    Truncated,
    Malformed,
    Unsupported,
    Limit,
    Warning,
    Note,
}

#[derive(Serialize)]
struct WireDiagnostic {
    kind: DiagnosticKind,
    message: String,
    span: Option<WireSpan>,
}

impl From<&Diagnostic> for WireDiagnostic {
    fn from(d: &Diagnostic) -> Self {
        use DiagnosticKind as K;
        WireDiagnostic {
            kind: match d.kind {
                DiagKind::Truncated => K::Truncated,
                DiagKind::Malformed => K::Malformed,
                DiagKind::Unsupported => K::Unsupported,
                DiagKind::Limit => K::Limit,
                DiagKind::Warning => K::Warning,
                // `Internal` and anything added later read as a note.
                _ => K::Note,
            },
            message: d.message.clone(),
            span: d.span.map(WireSpan::from),
        }
    }
}

#[derive(Serialize)]
struct WirePage {
    parent: WireNode,
    nodes: Vec<WireNode>,
    secret: Option<WireSecret>,
}

#[derive(Serialize)]
struct WireSecret {
    index: u32,
    prompt: String,
    attempt: u32,
}

#[derive(Serialize)]
struct WireFormat {
    name: &'static str,
    title: &'static str,
    extensions: Vec<&'static str>,
    suggested: bool,
}

#[derive(Serialize)]
struct WireSource {
    len: u64,
    len_known: bool,
    origin: Option<WireOrigin>,
}

#[derive(Serialize)]
struct WireOrigin {
    parent: WireSpan,
    transform: String,
}
