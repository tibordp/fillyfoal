//! Format identification and the dissectors themselves.

use std::borrow::Cow;

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::node::Node;
use crate::span::Span;

pub mod pe;

/// The region a format dissector works on, plus how deeply it is embedded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Input {
    pub span: Span,
    pub nesting: u32,
}

impl Input {
    pub fn root(span: Span) -> Self {
        Input { span, nesting: 0 }
    }

    /// An input embedded in this one.
    pub fn nested(&self, span: Span) -> Self {
        Input {
            span,
            nesting: self.nesting.saturating_add(1),
        }
    }
}

/// A top-level node that identifies and dissects `span` when expanded.
pub fn root(name: impl Into<Cow<'static, str>>, span: Span) -> Node {
    Node::new(name).span(span).lazy(dissect, Input::root(span))
}

/// A node for embedded content, identified and dissected on expansion.
pub fn embedded(name: impl Into<Cow<'static, str>>, input: Input) -> Node {
    Node::new(name).span(input.span).lazy(dissect, input)
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum Format {
    Pe,
}

fn identify(head: &[u8]) -> Option<Format> {
    if head.starts_with(b"MZ") {
        return Some(Format::Pe);
    }
    None
}

/// Identifies the format of `input` and dissects it.
pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let max = cx.limits().max_nesting;
    if input.nesting > max {
        return Err(
            Diagnostic::limit(format!("embedded objects nested deeper than {max}"))
                .at(input.span),
        );
    }
    let head = cx.read_avail(input.span.sub(0, 16)).await?;
    match identify(&head) {
        Some(Format::Pe) => pe::dissect(cx, input).await,
        None if head.is_empty() => Err(Diagnostic::note("empty").at(input.span)),
        None => Err(Diagnostic::unsupported("unrecognized format").at(input.span)),
    }
}
