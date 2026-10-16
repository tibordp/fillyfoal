//! Nodes of the inspection tree.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::Span;
use crate::value::{Check, Value};

/// How many children a node has, as far as its dissector knows.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Count {
    Exact(u64),
    AtLeast(u64),
    Unknown,
}

/// One entry in the tree: a field, a group, or an embedded object.
///
/// A node with an expander has children that are produced only when the host
/// asks for them. The expander is plain data plus an `async fn`; running it
/// again yields the same children (determinism).
#[derive(Clone)]
pub struct Node {
    pub name: Cow<'static, str>,
    pub value: Option<Value>,
    /// One-line description of the content, for collapsed display.
    pub summary: Option<String>,
    /// What the field means, for tooltips or help panes.
    pub description: Option<Cow<'static, str>>,
    /// The bytes this node was decoded from.
    pub span: Option<Span>,
    /// The bytes this node refers to (e.g. what a pointer field points at).
    pub target: Option<Span>,
    pub diagnostics: Vec<Diagnostic>,
    pub(crate) expander: Option<Arc<dyn Expand>>,
}

impl Node {
    /// The node, named `name` instead.
    pub fn renamed(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        self.name = name.into();
        self
    }

    pub fn new(name: impl Into<Cow<'static, str>>) -> Self {
        Node {
            name: name.into(),
            value: None,
            summary: None,
            description: None,
            span: None,
            target: None,
            diagnostics: Vec::new(),
            expander: None,
        }
    }

    pub fn value(mut self, value: Value) -> Self {
        self.value = Some(value);
        self
    }

    /// A field whose stored value is the format's "no value" sentinel (a
    /// zero timestamp, an all-zero date): no value, summary "not set". The
    /// raw bytes stay in the span.
    pub fn not_set(mut self) -> Self {
        self.value = None;
        self.summary = Some("not set".to_owned());
        self
    }

    /// The node's value is the check value `check`; a mismatch is also
    /// reported as a warning, so it surfaces as a problem.
    pub fn checksum(mut self, check: Check) -> Self {
        if let Some(message) = check.mismatch_text() {
            self.diagnostics.push(Diagnostic::warning(message));
        }
        self.value = Some(Value::Checksum(Box::new(check)));
        self
    }

    /// Reports `check` as a warning if it is a mismatch, on a node that
    /// contains the check value rather than being it (a header whose
    /// checksum field is among its children), so the problem shows while
    /// the node is collapsed.
    pub fn check_diag(mut self, check: &Check) -> Self {
        if let Some(message) = check.mismatch_text() {
            self.diagnostics.push(Diagnostic::warning(message));
        }
        self
    }

    /// Gives the node's check value ([`Node::checksum`]) its verdict, `f`
    /// of the unchecked one; a node without one is left as it is.
    pub fn with_check(mut self, f: impl FnOnce(Check) -> Check) -> Self {
        match self.value.take() {
            Some(Value::Checksum(c)) => self.checksum(f(*c)),
            other => {
                self.value = other;
                self
            }
        }
    }

    /// The node's number is a size in bytes ([`Value::to_size`]).
    pub fn as_size(self) -> Self {
        self.as_blocks(1u64)
    }

    /// The node's number counts blocks of `block` bytes.
    pub fn as_blocks(mut self, block: impl Into<u64>) -> Self {
        self.value = self.value.map(|v| v.to_size(block));
        self
    }

    /// The node's number is a span of ticks of `1/per_sec` second
    /// ([`Value::to_duration`]).
    pub fn as_duration(mut self, per_sec: u64) -> Self {
        self.value = self.value.map(|v| v.to_duration(per_sec));
        self
    }

    pub fn summary(mut self, summary: impl Into<String>) -> Self {
        self.summary = Some(summary.into());
        self
    }

    pub fn desc(mut self, description: impl Into<Cow<'static, str>>) -> Self {
        self.description = Some(description.into());
        self
    }

    pub fn span(mut self, span: Span) -> Self {
        self.span = Some(span);
        self
    }

    pub fn target(mut self, target: Span) -> Self {
        self.target = Some(target);
        self
    }

    pub fn diag(mut self, diagnostic: Diagnostic) -> Self {
        self.diagnostics.push(diagnostic);
        self
    }

    /// Makes the node expandable: on expansion, `f(cx, state)` runs and
    /// emits the children through `cx`.
    pub fn lazy<S, F, Fut>(mut self, f: F, state: S) -> Self
    where
        S: Clone + Send + Sync + 'static,
        F: Fn(Cx, S) -> Fut + Send + Sync + 'static,
        Fut: Future<Output = Result<()>> + Send + 'static,
    {
        self.expander = Some(Arc::new(LazyFn { f, state }));
        self
    }

    /// The name the content is known by where it came from (a file's name
    /// in a file system) when the node itself is named otherwise
    /// ("Content"): what [`Cx::node_name`] returns while the node expands,
    /// so its dissector and identification (`formats::Deep::name`) can take
    /// it as a hint. Call it after [`Node::lazy`]; a node without an
    /// expander is left as it is.
    pub fn known_as(mut self, name: impl Into<Cow<'static, str>>) -> Self {
        if let Some(inner) = self.expander.take() {
            self.expander = Some(Arc::new(KnownAs {
                name: name.into(),
                inner,
            }));
        }
        self
    }

    pub fn has_children(&self) -> bool {
        self.expander.is_some()
    }
}

impl fmt::Debug for Node {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.name)
            .field("value", &self.value)
            .field("summary", &self.summary)
            .field("span", &self.span)
            .field("target", &self.target)
            .field("diagnostics", &self.diagnostics)
            .field("lazy", &self.expander.is_some())
            .finish()
    }
}

/// A boxed expansion future, as produced by [`expander!`](crate::expander).
pub type Expansion = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

/// Refers to an expander `async fn` from inside its own body (or from a
/// mutually recursive one): `node.lazy(expander!(walk: State), state)`.
///
/// Plain `node.lazy(walk, state)` would make the compiler check that `walk`'s
/// future is `Send` while it is still inferring that very future, which fails.
/// This macro moves the check into a separate item.
#[macro_export]
macro_rules! expander {
    ($f:path : $state:ty) => {{
        fn boxed(cx: $crate::Cx, state: $state) -> $crate::node::Expansion {
            ::std::boxed::Box::pin($f(cx, state))
        }
        boxed
    }};
}

pub(crate) trait Expand: Send + Sync {
    fn start(&self, cx: Cx) -> Expansion;

    /// See [`Node::known_as`].
    fn known_as(&self) -> Option<Cow<'static, str>> {
        None
    }
}

/// An expander whose node is known by another name ([`Node::known_as`]).
struct KnownAs {
    name: Cow<'static, str>,
    inner: Arc<dyn Expand>,
}

impl Expand for KnownAs {
    fn start(&self, cx: Cx) -> Expansion {
        self.inner.start(cx)
    }

    fn known_as(&self) -> Option<Cow<'static, str>> {
        Some(self.name.clone())
    }
}

struct LazyFn<F, S> {
    f: F,
    state: S,
}

impl<F, S, Fut> Expand for LazyFn<F, S>
where
    S: Clone + Send + Sync + 'static,
    F: Fn(Cx, S) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    fn start(&self, cx: Cx) -> Expansion {
        Box::pin((self.f)(cx, self.state.clone()))
    }
}
