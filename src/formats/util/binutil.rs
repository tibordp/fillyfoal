//! Small helpers shared by the executable and bytecode dissectors.

use std::borrow::Cow;

use crate::bytes::to_usize;
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Prim};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

/// Decodes a `T` at `offset` in `data` with the given byte order.
pub fn get<T: Prim>(data: &[u8], offset: usize, endian: Endian) -> Option<T> {
    let end = offset.checked_add(T::SIZE)?;
    T::decode(data.get(offset..end)?, endian)
}

/// Like [`get`], with a `u64` offset.
pub fn get_at<T: Prim>(data: &[u8], offset: u64, endian: Endian) -> Option<T> {
    get(data, to_usize(offset), endian)
}

/// A hexadecimal unsigned value.
pub fn hex(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Hex,
    }
}

/// A decimal unsigned value.
pub fn dec(value: u64, bits: u8) -> Value {
    Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    }
}

pub fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

/// The table's name for `raw`, or `"<prefix> <raw:#x>"`.
pub fn name_or(table: EnumTable, raw: u64, prefix: &str) -> String {
    lookup(table, raw).map_or_else(|| format!("{prefix} {raw:#x}"), str::to_owned)
}

/// A leaf for raw bytes that were expected to be `wanted` long, with a
/// truncation diagnostic if the region was clamped.
pub fn data_node(name: impl Into<Cow<'static, str>>, span: Span, wanted: u64) -> Node {
    let node = Node::new(name).span(span);
    if span.len < wanted {
        node.diag(Diagnostic::truncated(
            Span::new(span.source, span.offset, wanted),
            span.len,
        ))
    } else {
        node
    }
}

/// Node conveniences.
pub trait NodeExt {
    /// Sets the summary unless it is empty.
    fn maybe_summary(self, summary: impl Into<String>) -> Self;
}

impl NodeExt for Node {
    fn maybe_summary(self, summary: impl Into<String>) -> Self {
        let summary = summary.into();
        if summary.is_empty() {
            self
        } else {
            self.summary(summary)
        }
    }
}

/// Lower-case hex digits of `bytes`, without separators.
pub fn hex_string(bytes: &[u8]) -> String {
    use std::fmt::Write;
    let mut out = String::with_capacity(bytes.len().saturating_mul(2));
    for b in bytes {
        let _ = write!(out, "{b:02x}");
    }
    out
}

/// `"rwx"`-style permission letters.
pub fn perms(read: bool, write: bool, exec: bool) -> String {
    [(read, 'r'), (write, 'w'), (exec, 'x')]
        .iter()
        .map(|&(on, c)| if on { c } else { '-' })
        .collect()
}

/// A short, printable rendering of a string for summaries.
pub fn ellipsize(s: &str, max: usize) -> String {
    if s.chars().count() <= max {
        s.to_owned()
    } else {
        let mut out: String = s.chars().take(max).collect();
        out.push('…');
        out
    }
}

/// Modified UTF-8 (Java class files, DEX): like UTF-8, but NUL is encoded
/// as `C0 80` and supplementary characters as surrogate pairs. Decoded
/// leniently.
pub fn mutf8(bytes: &[u8]) -> String {
    let mut units: Vec<u16> = Vec::with_capacity(bytes.len());
    let mut it = bytes.iter().copied();
    while let Some(a) = it.next() {
        let unit = if a & 0x80 == 0 {
            u16::from(a)
        } else if a & 0xe0 == 0xc0 {
            let b = it.next().unwrap_or(0);
            (u16::from(a & 0x1f) << 6) | u16::from(b & 0x3f)
        } else if a & 0xf0 == 0xe0 {
            let b = it.next().unwrap_or(0);
            let c = it.next().unwrap_or(0);
            (u16::from(a & 0x0f) << 12) | (u16::from(b & 0x3f) << 6) | u16::from(c & 0x3f)
        } else {
            0xfffd
        };
        units.push(unit);
    }
    String::from_utf16_lossy(&units)
}

/// A tree decoded up front (for formats that must be parsed sequentially to
/// find their structure, such as serialization streams), displayed lazily:
/// each node's children are emitted only when it is expanded.
#[derive(Default)]
pub struct Tree {
    nodes: Vec<TreeNode>,
}

#[derive(Clone)]
struct TreeNode {
    node: Node,
    children: Vec<usize>,
}

impl Tree {
    /// Adds a node under `parent` (or as a root) and returns its index.
    pub fn add(&mut self, parent: Option<usize>, node: Node) -> usize {
        let index = self.nodes.len();
        self.nodes.push(TreeNode {
            node,
            children: Vec::new(),
        });
        if let Some(p) = parent.and_then(|p| self.nodes.get_mut(p)) {
            p.children.push(index);
        }
        index
    }

    /// The index the next [`Tree::add`] returns.
    pub fn next_index(&self) -> usize {
        self.nodes.len()
    }

    /// Changes a node already added (e.g. to fill in its span or summary once
    /// its end is known).
    pub fn update(&mut self, index: usize, f: impl FnOnce(Node) -> Node) {
        if let Some(t) = self.nodes.get_mut(index) {
            let node = std::mem::replace(&mut t.node, Node::new(""));
            t.node = f(node);
        }
    }

    /// The display node for `index`: expandable if it has children.
    pub fn node(tree: &std::sync::Arc<Tree>, index: usize) -> Node {
        let Some(t) = tree.nodes.get(index) else {
            return Node::new("?");
        };
        if t.children.is_empty() {
            t.node.clone()
        } else {
            t.node.clone().lazy(tree_children, (tree.clone(), index))
        }
    }

    /// Emits (pages) the children of `index` into the current expansion.
    pub async fn emit_children(cx: &Cx, tree: &std::sync::Arc<Tree>, index: usize) {
        let children = tree
            .nodes
            .get(index)
            .map(|t| t.children.clone())
            .unwrap_or_default();
        cx.set_count(crate::node::Count::Exact(crate::bytes::to_u64(
            children.len(),
        )));
        for child in children {
            cx.push(Tree::node(tree, child)).await;
        }
    }
}

async fn tree_children(cx: Cx, (tree, index): (std::sync::Arc<Tree>, usize)) -> Result<()> {
    Tree::emit_children(&cx, &tree, index).await;
    Ok(())
}

/// Sequential decoding of an in-memory byte buffer (opcode streams, tries).
/// Every method returns `None` once the data runs out.
pub struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Reader { data, pos: 0 }
    }

    pub fn at(data: &'a [u8], pos: usize) -> Self {
        Reader { data, pos }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn at_end(&self) -> bool {
        self.pos >= self.data.len()
    }

    /// The unread bytes.
    pub fn rest(&self) -> &'a [u8] {
        self.data.get(self.pos..).unwrap_or_default()
    }

    /// The next byte, without consuming it.
    pub fn peek(&self) -> Option<u8> {
        self.data.get(self.pos).copied()
    }

    pub fn u8(&mut self) -> Option<u8> {
        let b = *self.data.get(self.pos)?;
        self.pos = self.pos.checked_add(1)?;
        Some(b)
    }

    pub fn int<T: Prim>(&mut self, endian: Endian) -> Option<T> {
        let v = get::<T>(self.data, self.pos, endian)?;
        self.pos = self.pos.checked_add(T::SIZE)?;
        Some(v)
    }

    pub fn bytes(&mut self, n: usize) -> Option<&'a [u8]> {
        let end = self.pos.checked_add(n)?;
        let b = self.data.get(self.pos..end)?;
        self.pos = end;
        Some(b)
    }

    pub fn uleb(&mut self) -> Option<u64> {
        let (v, n) = crate::bytes::uleb128(self.data.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(n)?;
        Some(v)
    }

    pub fn sleb(&mut self) -> Option<i64> {
        let (v, n) = crate::bytes::sleb128(self.data.get(self.pos..)?)?;
        self.pos = self.pos.checked_add(n)?;
        Some(v)
    }

    /// A NUL-terminated string (the NUL is consumed).
    pub fn cstr(&mut self) -> Option<&'a [u8]> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        let s = rest.get(..n)?;
        self.pos = self.pos.checked_add(n)?.checked_add(1)?;
        Some(s)
    }
}

/// Expander: the NUL-terminated strings in `span`, listed by offset (empty
/// strings are skipped).
pub async fn cstrings(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, Endian::Little);
    while !cur.at_end() {
        let start = cur.pos();
        let (s, at) = cur.cstr(4096).await?;
        if s.is_empty() {
            continue;
        }
        cx.push(Node::new(format!("{start:#x}")).span(at).value(text(s)))
            .await;
    }
    Ok(())
}

/// Reads a NUL-terminated string at `offset` within a string table.
pub async fn string_at(cx: &Cx, table: Span, offset: u64) -> Result<(String, Span)> {
    if offset >= table.len {
        return Err(Diagnostic::malformed(format!(
            "string offset {offset:#x} is outside the string table"
        )));
    }
    cx.cstr(table.tail(offset).sub(0, 4096)).await
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mutf8_decodes_nul_and_surrogates() {
        assert_eq!(mutf8(b"a\xc0\x80b"), "a\0b");
        assert_eq!(mutf8(b"\xed\xa0\xbd\xed\xb8\x80"), "\u{1f600}");
        assert_eq!(hex_string(&[0xde, 0xad]), "dead");
        assert_eq!(ellipsize("abcdef", 3), "abc…");
    }
}
