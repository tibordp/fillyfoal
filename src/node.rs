//! Nodes of the inspection tree.

use std::borrow::Cow;
use std::fmt;
use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::span::Span;
use crate::value::Value;

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

pub(crate) type Expansion = Pin<Box<dyn Future<Output = Result<()>> + Send>>;

pub(crate) trait Expand: Send + Sync {
    fn start(&self, cx: Cx) -> Expansion;
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
