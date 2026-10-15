//! Optional reads far into content decoded on demand.
//!
//! A volume dissector often checks something at the far end of its input
//! that it does not need: a backup header in the last sector of a disk,
//! a backup boot sector, a second anchor. On a file that is cheap. On a
//! disk image decompressed on demand it means decoding the whole image
//! before the expansion can finish, so the user waits minutes for the
//! primary structures that sit in the first kilobytes.
//!
//! The pattern: ask [`Cx::read_is_cheap`] for the far span; if it is cheap,
//! read and check it as before; if not, emit [`deferred`] in its place, a
//! node whose expansion reads it and runs the same checks (reporting what
//! they find with `cx.diag` on that node). The decision depends only on
//! how the content is decoded, not on what was decoded so far, so the tree
//! is the same each time the expander runs.
//!
//! Structures a format cannot do without (a ZIP central directory, a VHD
//! footer, a DMG trailer) are read wherever they are: there is no tree
//! without them.

use std::future::Future;

use crate::cx::Cx;
use crate::error::Result;
use crate::node::Node;
use crate::span::Span;

/// Whether reading `span` would decode far into content decoded on demand
/// (the opposite of [`Cx::read_is_cheap`]).
pub fn is_far(cx: &Cx, span: Span) -> bool {
    !cx.read_is_cheap(span)
}

/// A node for something optional at `span` that is not read during the
/// expansion that found it, because reading it decodes far into content
/// decoded on demand. `place` says where it lies ("at the end of the
/// disk"); expanding the node runs `f`, which reads it and emits what it
/// holds.
pub fn deferred<S, F, Fut>(name: &'static str, span: Span, place: &str, f: F, state: S) -> Node
where
    S: Clone + Send + Sync + 'static,
    F: Fn(Cx, S) -> Fut + Send + Sync + 'static,
    Fut: Future<Output = Result<()>> + Send + 'static,
{
    Node::new(name)
        .span(span)
        .summary(format!(
            "{place}, not read yet: expand to read it (decodes the content up to it)"
        ))
        .lazy(f, state)
}
