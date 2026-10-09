//! A bit reader that records a node for every syntax element it reads,
//! with spans mapped back through emulation-prevention bytes: the common
//! machinery of the parameter-set, slice-header, SEI, AV1 and VP9 parsers.
//!
//! Parsers are written once against [`Walker`]; with `emit` off the same
//! code only decodes (for summaries), with it on it also builds the tree.
//! Inputs are bounded by the callers (a parameter set, a header prefix), so
//! a walk is a bounded amount of work.

use std::borrow::Cow;
use std::sync::Arc;

use crate::error::Diagnostic;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

/// Removes emulation-prevention bytes (`00 00 03` → `00 00`) and returns,
/// for each byte kept, its offset in `data`.
pub fn unescape_mapped(data: &[u8]) -> (Vec<u8>, Vec<usize>) {
    let mut out = Vec::with_capacity(data.len());
    let mut map = Vec::with_capacity(data.len());
    let mut zeros = 0usize;
    for (i, &b) in data.iter().enumerate() {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
        out.push(b);
        map.push(i);
    }
    (out, map)
}

struct Group {
    name: Cow<'static, str>,
    start: usize,
    nodes: Vec<Node>,
}

/// MSB-first bit reader over an RBSP that records what it reads.
pub struct Walker {
    data: Vec<u8>,
    /// For each byte of `data`, its offset relative to `base`.
    map: Vec<usize>,
    base: Span,
    pos: usize,
    emit: bool,
    incomplete: bool,
    stack: Vec<Group>,
    nodes: Vec<Node>,
}

impl Walker {
    /// A walker over `raw` (whose bytes are at `base`), removing emulation
    /// prevention first when `escaped`.
    pub fn new(raw: &[u8], base: Span, escaped: bool, emit: bool) -> Self {
        let (data, map) = if escaped {
            unescape_mapped(raw)
        } else {
            (raw.to_vec(), (0..raw.len()).collect())
        };
        Walker {
            data,
            map,
            base,
            pos: 0,
            emit,
            incomplete: false,
            stack: Vec::new(),
            nodes: Vec::new(),
        }
    }

    /// A walker over bytes `start..start + len` of this one's data (already
    /// unescaped), with spans still mapped to the original bytes.
    pub fn sub(&self, start: usize, len: usize) -> Walker {
        let end = start.saturating_add(len).min(self.data.len());
        let start = start.min(end);
        Walker {
            data: self.data.get(start..end).unwrap_or_default().to_vec(),
            map: self.map.get(start..end).unwrap_or_default().to_vec(),
            base: self.base,
            pos: 0,
            emit: self.emit,
            incomplete: false,
            stack: Vec::new(),
            nodes: Vec::new(),
        }
    }

    /// Moves to bit `pos` (clamped to the data).
    pub fn seek(&mut self, pos: usize) {
        self.pos = pos.min(self.len_bits());
    }

    /// The number of open groups, for [`Walker::fail_to`].
    pub fn depth(&self) -> usize {
        self.stack.len()
    }

    /// Records that a part could not be parsed (its syntax ended early or
    /// held a value out of range) and closes the groups it opened, down to
    /// `depth`, so the caller can carry on with what it has.
    pub fn fail_to(&mut self, depth: usize) {
        if !self.incomplete {
            self.incomplete = true;
            self.unparsed();
        }
        while self.stack.len() > depth {
            self.end();
        }
    }

    fn unparsed(&mut self) {
        if self.emit {
            let rest = self.rest_span(self.pos);
            self.push(Node::new("Unparsed").span(rest).diag(Diagnostic::malformed(
                "the syntax ends early or holds a value out of range",
            )));
        }
    }

    pub fn emitting(&self) -> bool {
        self.emit
    }

    /// The current position in bits.
    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn len_bits(&self) -> usize {
        self.data.len().saturating_mul(8)
    }

    pub fn bits_left(&self) -> usize {
        self.len_bits().saturating_sub(self.pos)
    }

    pub fn byte_aligned(&self) -> bool {
        self.pos & 7 == 0
    }

    /// The unescaped bytes.
    pub fn data(&self) -> &[u8] {
        &self.data
    }

    /// Whether syntax elements remain before the RBSP trailing bits (the
    /// last 1 bit of the data and the zeros after it).
    pub fn more_rbsp_data(&self) -> bool {
        let Some(last) = self.data.iter().rposition(|&b| b != 0) else {
            return false;
        };
        let byte = self.data.get(last).copied().unwrap_or(0);
        let stop = last
            .saturating_mul(8)
            .saturating_add(7usize.saturating_sub(byte.trailing_zeros() as usize));
        self.pos < stop
    }

    /// The span of the bytes holding bits `start..end`.
    pub fn span_bits(&self, start: usize, end: usize) -> Span {
        let first = self.map.get(start >> 3).copied();
        let Some(first) = first else {
            let end_off = self.map.last().map_or(0, |&o| o.saturating_add(1));
            return self.base.sub(crate::bytes::to_u64(end_off), 0);
        };
        if end <= start {
            return self.base.sub(crate::bytes::to_u64(first), 0);
        }
        let last = self
            .map
            .get((end.saturating_sub(1)) >> 3)
            .or_else(|| self.map.last())
            .copied()
            .unwrap_or(first);
        self.base.sub(
            crate::bytes::to_u64(first),
            crate::bytes::to_u64(last.saturating_sub(first).saturating_add(1)),
        )
    }

    /// The span from bit `pos` to the end of `base` (which may extend
    /// beyond the bytes the walker was given).
    pub fn rest_span(&self, pos: usize) -> Span {
        let off = self
            .map
            .get(pos >> 3)
            .copied()
            .or_else(|| self.map.last().map(|&o| o.saturating_add(1)))
            .unwrap_or(0);
        self.base.tail(crate::bytes::to_u64(off))
    }

    /// The span from bit `start` to the current position.
    pub fn since(&self, start: usize) -> Span {
        self.span_bits(start, self.pos)
    }

    // -----------------------------------------------------------------
    // Silent reads

    pub fn bit(&mut self) -> Option<u64> {
        let byte = self.data.get(self.pos >> 3)?;
        let shift = 7 ^ (self.pos & 7);
        let v = u64::from((byte >> shift) & 1);
        self.pos = self.pos.checked_add(1)?;
        Some(v)
    }

    /// Reads `n` (at most 64) bits.
    pub fn read(&mut self, n: u32) -> Option<u64> {
        if n > 64 || self.bits_left() < n as usize {
            return None;
        }
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Some(v)
    }

    /// Reads `n` bytes silently.
    pub fn read_bytes(&mut self, n: usize) -> Option<Vec<u8>> {
        if self.bits_left() < n.saturating_mul(8) {
            return None;
        }
        let mut out = Vec::with_capacity(n);
        if self.byte_aligned() {
            let at = self.pos >> 3;
            out.extend_from_slice(self.data.get(at..at.checked_add(n)?)?);
            self.pos = self.pos.checked_add(n.checked_mul(8)?)?;
        } else {
            for _ in 0..n {
                out.push(u8::try_from(self.read(8)?).ok()?);
            }
        }
        Some(out)
    }

    pub fn read_flag(&mut self) -> Option<bool> {
        self.bit().map(|b| b != 0)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        let to = self.pos.checked_add(n)?;
        if to > self.len_bits() {
            return None;
        }
        self.pos = to;
        Some(())
    }

    /// Unsigned Exp-Golomb code (`ue(v)`).
    pub fn read_ue(&mut self) -> Option<u64> {
        let mut zeros = 0u32;
        while self.bit()? == 0 {
            zeros = zeros.checked_add(1)?;
            if zeros > 32 {
                return None;
            }
        }
        let rest = self.read(zeros)?;
        1u64.checked_shl(zeros)?.checked_sub(1)?.checked_add(rest)
    }

    /// Signed Exp-Golomb code (`se(v)`).
    pub fn read_se(&mut self) -> Option<i64> {
        let k = i64::try_from(self.read_ue()?).ok()?;
        let magnitude = k.checked_add(1)? >> 1;
        Some(if k & 1 == 1 {
            magnitude
        } else {
            magnitude.checked_neg()?
        })
    }

    /// AV1 `uvlc()`.
    pub fn read_uvlc(&mut self) -> Option<u64> {
        let mut zeros = 0u32;
        while self.bit()? == 0 {
            zeros = zeros.checked_add(1)?;
            if zeros >= 32 {
                return Some(u64::from(u32::MAX));
            }
        }
        let rest = self.read(zeros)?;
        1u64.checked_shl(zeros)?.checked_sub(1)?.checked_add(rest)
    }

    /// AV1 `leb128()` (byte aligned).
    pub fn read_leb128(&mut self) -> Option<u64> {
        let mut value = 0u64;
        for i in 0..8u32 {
            let byte = self.read(8)?;
            value |= (byte & 0x7f).checked_shl(i.checked_mul(7)?)?;
            if byte & 0x80 == 0 {
                return Some(value);
            }
        }
        None
    }

    /// AV1 `su(n)`: an `n`-bit two's complement value.
    pub fn read_su(&mut self, n: u32) -> Option<i64> {
        let v = self.read(n)?;
        let sign = 1u64.checked_shl(n.checked_sub(1)?)?;
        let v = i64::try_from(v).ok()?;
        let sign = i64::try_from(sign).ok()?;
        Some(if v & sign != 0 {
            v.checked_sub(sign.checked_mul(2)?)?
        } else {
            v
        })
    }

    // -----------------------------------------------------------------
    // Recording reads

    /// Records a node for bits `start..pos` with `value`.
    pub fn record(&mut self, name: impl Into<Cow<'static, str>>, start: usize, value: Value) {
        if !self.emit {
            return;
        }
        let node = Node::new(name).span(self.since(start)).value(value);
        self.push(node);
    }

    /// Adds a prepared node to the current group.
    pub fn push(&mut self, node: Node) {
        if !self.emit {
            return;
        }
        match self.stack.last_mut() {
            Some(g) => g.nodes.push(node),
            None => self.nodes.push(node),
        }
    }

    /// Applies `f` to the most recently recorded node (summary, desc, ...).
    pub fn with(&mut self, f: impl FnOnce(Node) -> Node) {
        if !self.emit {
            return;
        }
        let list = match self.stack.last_mut() {
            Some(g) => &mut g.nodes,
            None => &mut self.nodes,
        };
        if let Some(node) = list.pop() {
            list.push(f(node));
        }
    }

    /// Like [`Walker::with`] with a summary built only when emitting.
    pub fn summary(&mut self, f: impl FnOnce() -> String) {
        if self.emit {
            let s = f();
            self.with(|n| n.summary(s));
        }
    }

    pub fn desc(&mut self, d: &'static str) {
        self.with(|n| n.desc(d));
    }

    /// `u(n)`.
    pub fn u(&mut self, name: impl Into<Cow<'static, str>>, n: u32) -> Option<u64> {
        let start = self.pos;
        let v = self.read(n)?;
        self.record(
            name,
            start,
            Value::UInt {
                value: v,
                bits: u8::try_from(n).unwrap_or(64),
                radix: Radix::Dec,
            },
        );
        Some(v)
    }

    /// `u(n)` shown in hexadecimal.
    pub fn x(&mut self, name: impl Into<Cow<'static, str>>, n: u32) -> Option<u64> {
        let start = self.pos;
        let v = self.read(n)?;
        self.record(
            name,
            start,
            Value::UInt {
                value: v,
                bits: u8::try_from(n).unwrap_or(64),
                radix: Radix::Hex,
            },
        );
        Some(v)
    }

    /// A one-bit flag.
    pub fn flag(&mut self, name: impl Into<Cow<'static, str>>) -> Option<bool> {
        let start = self.pos;
        let v = self.read_flag()?;
        self.record(name, start, Value::Bool(v));
        Some(v)
    }

    /// `u(n)` with names from `table`.
    pub fn en(
        &mut self,
        name: impl Into<Cow<'static, str>>,
        n: u32,
        table: EnumTable,
    ) -> Option<u64> {
        let start = self.pos;
        let v = self.read(n)?;
        self.record(
            name,
            start,
            Value::Enum {
                raw: v,
                bits: u8::try_from(n).unwrap_or(64),
                name: crate::value::lookup(table, v),
            },
        );
        Some(v)
    }

    pub fn ue(&mut self, name: impl Into<Cow<'static, str>>) -> Option<u64> {
        let start = self.pos;
        let v = self.read_ue()?;
        self.record(
            name,
            start,
            Value::UInt {
                value: v,
                bits: 32,
                radix: Radix::Dec,
            },
        );
        Some(v)
    }

    /// `ue(v)` with names from `table`.
    pub fn ue_en(&mut self, name: impl Into<Cow<'static, str>>, table: EnumTable) -> Option<u64> {
        let start = self.pos;
        let v = self.read_ue()?;
        self.record(
            name,
            start,
            Value::Enum {
                raw: v,
                bits: 32,
                name: crate::value::lookup(table, v),
            },
        );
        Some(v)
    }

    pub fn se(&mut self, name: impl Into<Cow<'static, str>>) -> Option<i64> {
        let start = self.pos;
        let v = self.read_se()?;
        self.record(name, start, Value::Int { value: v, bits: 32 });
        Some(v)
    }

    pub fn su(&mut self, name: impl Into<Cow<'static, str>>, n: u32) -> Option<i64> {
        let start = self.pos;
        let v = self.read_su(n)?;
        self.record(
            name,
            start,
            Value::Int {
                value: v,
                bits: u8::try_from(n).unwrap_or(64),
            },
        );
        Some(v)
    }

    pub fn uvlc(&mut self, name: impl Into<Cow<'static, str>>) -> Option<u64> {
        let start = self.pos;
        let v = self.read_uvlc()?;
        self.record(
            name,
            start,
            Value::UInt {
                value: v,
                bits: 32,
                radix: Radix::Dec,
            },
        );
        Some(v)
    }

    pub fn leb128(&mut self, name: impl Into<Cow<'static, str>>) -> Option<u64> {
        let start = self.pos;
        let v = self.read_leb128()?;
        self.record(
            name,
            start,
            Value::UInt {
                value: v,
                bits: 64,
                radix: Radix::Dec,
            },
        );
        Some(v)
    }

    /// `n` bytes (byte aligned or not), recorded as a byte string.
    pub fn bytes(&mut self, name: impl Into<Cow<'static, str>>, n: usize) -> Option<Vec<u8>> {
        let start = self.pos;
        let out = self.read_bytes(n)?;
        if self.emit {
            self.record(name, start, Value::Bytes(out.clone()));
        }
        Some(out)
    }

    /// Records the bits `start..pos` (already consumed) as a node with a
    /// text value.
    pub fn text(&mut self, name: impl Into<Cow<'static, str>>, start: usize, text: String) {
        self.record(name, start, Value::Text(text));
    }

    /// Skips `n` bits, recording them under `name` (reserved bits, data
    /// not decoded further).
    pub fn skip_as(&mut self, name: impl Into<Cow<'static, str>>, n: usize) -> Option<()> {
        let start = self.pos;
        self.skip(n)?;
        if self.emit {
            let node = Node::new(name).span(self.since(start));
            self.push(node);
        }
        Some(())
    }

    // -----------------------------------------------------------------
    // Groups

    /// Starts a group: nodes recorded until [`Walker::end`] become its
    /// children.
    pub fn begin(&mut self, name: impl Into<Cow<'static, str>>) {
        if !self.emit {
            return;
        }
        self.stack.push(Group {
            name: name.into(),
            start: self.pos,
            nodes: Vec::new(),
        });
    }

    /// Renames the innermost open group.
    pub fn rename(&mut self, name: impl Into<Cow<'static, str>>) {
        if let Some(g) = self.stack.last_mut() {
            g.name = name.into();
        }
    }

    /// Ends the innermost group.
    pub fn end(&mut self) {
        self.end_with(None);
    }

    /// Ends the innermost group with a summary.
    pub fn end_summary(&mut self, f: impl FnOnce() -> String) {
        if self.emit {
            let s = f();
            self.end_with(Some(s));
        }
    }

    fn end_with(&mut self, summary: Option<String>) {
        let Some(g) = self.stack.pop() else {
            return;
        };
        let mut node = Node::new(g.name).span(self.since(g.start));
        if let Some(s) = summary {
            node = node.summary(s);
        }
        if !g.nodes.is_empty() {
            node = node.lazy(crate::formats::util::arcutil::emit_nodes, Arc::new(g.nodes));
        }
        self.push(node);
    }

    /// Closes any open groups and returns the recorded nodes. When the
    /// parse stopped early (`complete` false), a node says so.
    pub fn finish(mut self, complete: bool) -> Vec<Node> {
        if !complete && !self.incomplete {
            self.unparsed();
        }
        while !self.stack.is_empty() {
            self.end();
        }
        self.nodes
    }
}
