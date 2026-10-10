//! Small pieces shared by the HDF5 modules: the file's address geometry,
//! a reader that renders fields as it decodes them, and the checksums.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagDef, Radix, Value, lookup};

/// What every expansion needs: the file, where address 0 is, and the sizes
/// of offsets and lengths.
pub struct File {
    pub input: Input,
    /// Position of address 0 within the input (the base address).
    pub base: u64,
    pub o: usize,
    pub l: usize,
    /// B-tree K values: group leaf, group internal, indexed storage (nodes
    /// are allocated for 2K entries).
    pub k: [u64; 3],
}

pub type FileRef = Arc<File>;

impl File {
    /// The bytes at file address `addr`.
    pub fn at(&self, addr: u64, len: u64) -> Span {
        self.input.span.sub(self.base.saturating_add(addr), len)
    }

    /// The bytes at `addr`, failing if they do not all exist.
    pub fn exact(&self, addr: u64, len: u64) -> Result<Span> {
        self.input
            .span
            .sub_exact(self.base.saturating_add(addr), len)
    }

    /// Whether `addr` is the undefined address (all bits set).
    pub fn undef(&self, addr: u64) -> bool {
        undefined(addr, self.o)
    }
}

/// A little-endian unsigned integer of `n` (at most 8) bytes.
pub fn uint(data: &[u8], at: usize, n: usize) -> Option<u64> {
    if n > 8 {
        return None;
    }
    let bytes = data.get(at..at.checked_add(n)?)?;
    Some(
        bytes
            .iter()
            .rev()
            .fold(0u64, |acc, &b| acc.wrapping_shl(8) | u64::from(b)),
    )
}

/// Whether `addr` (stored in `n` bytes) has all bits set.
pub fn undefined(addr: u64, n: usize) -> bool {
    if n >= 8 {
        addr == u64::MAX
    } else {
        let bits = u32::try_from(n.saturating_mul(8)).unwrap_or(64);
        addr == 1u64
            .checked_shl(bits)
            .map_or(u64::MAX, |v| v.wrapping_sub(1))
    }
}

pub fn hex(v: u64) -> Value {
    Value::UInt {
        value: v,
        bits: 64,
        radix: Radix::Hex,
    }
}

pub fn dec(v: u64) -> Value {
    Value::UInt {
        value: v,
        bits: 64,
        radix: Radix::Dec,
    }
}

fn bits_of(n: usize) -> u8 {
    u8::try_from(n.saturating_mul(8).min(64)).unwrap_or(64)
}

/// floor(log2(n)), 0 for 0.
pub fn log2(n: u64) -> u32 {
    63u32.saturating_sub(n.leading_zeros())
}

/// Bytes needed to encode values up to `n` (HDF5's `H5VM_limit_enc_size`).
pub fn limit_enc_size(n: u64) -> usize {
    to_usize(u64::from(log2(n) / 8).saturating_add(1))
}

/// A node whose children are `children`, emitted on expansion.
pub fn group(name: impl Into<std::borrow::Cow<'static, str>>, children: Vec<Node>) -> Node {
    let node = Node::new(name);
    if children.is_empty() {
        node
    } else {
        node.lazy(emit_all, Arc::new(children))
    }
}

pub async fn emit_all(cx: Cx, nodes: Arc<Vec<Node>>) -> Result<()> {
    for n in nodes.iter() {
        cx.push(n.clone()).await;
    }
    Ok(())
}

/// Decodes fields from bytes held in memory, recording a node for each.
/// Methods return `None` when the bytes run out; callers then stop and
/// [`Rd::finish`] notes the truncation.
pub struct Rd<'a> {
    pub data: &'a [u8],
    /// The span `data` was read from.
    pub span: Span,
    pub pos: usize,
    pub out: Vec<Node>,
    pub o: usize,
    pub l: usize,
}

impl<'a> Rd<'a> {
    pub fn new(file: &File, data: &'a [u8], span: Span) -> Self {
        Rd {
            data,
            span,
            pos: 0,
            out: Vec::new(),
            o: file.o,
            l: file.l,
        }
    }

    /// A reader over the same bytes at the same position, collecting its
    /// own nodes (for a nested structure).
    pub fn fork(&self) -> Rd<'a> {
        Rd {
            data: self.data,
            span: self.span,
            pos: self.pos,
            out: Vec::new(),
            o: self.o,
            l: self.l,
        }
    }

    /// Adds the nodes of `sub` (forked at `start`) as one group named
    /// `name`, and continues after it.
    pub fn join(
        &mut self,
        name: impl Into<std::borrow::Cow<'static, str>>,
        start: usize,
        sub: Rd<'a>,
    ) {
        let span = self.sp(start, sub.pos.saturating_sub(start));
        self.pos = sub.pos;
        self.push(group(name, sub.out).span(span));
    }

    pub fn sp(&self, at: usize, len: usize) -> Span {
        self.span.sub(to_u64(at), to_u64(len))
    }

    /// The span from `start` to the current position.
    pub fn since(&self, start: usize) -> Span {
        self.sp(start, self.pos.saturating_sub(start))
    }

    pub fn left(&self) -> usize {
        self.data.len().saturating_sub(self.pos)
    }

    pub fn has(&self, n: usize) -> bool {
        self.left() >= n
    }

    /// The next `n`-byte integer, without consuming it.
    pub fn peek(&self, n: usize) -> Option<u64> {
        uint(self.data, self.pos, n)
    }

    /// Consumes `n` bytes, returning their value and span.
    pub fn take(&mut self, n: usize) -> Option<(u64, Span)> {
        let v = uint(self.data, self.pos, n)?;
        let span = self.sp(self.pos, n);
        self.pos = self.pos.saturating_add(n);
        Some((v, span))
    }

    pub fn slice(&mut self, n: usize) -> Option<(&'a [u8], Span)> {
        let data: &'a [u8] = self.data;
        let bytes = data.get(self.pos..self.pos.checked_add(n)?)?;
        let span = self.sp(self.pos, n);
        self.pos = self.pos.saturating_add(n);
        Some((bytes, span))
    }

    pub fn skip(&mut self, n: usize) {
        self.pos = self.pos.saturating_add(n);
    }

    pub fn push(&mut self, node: Node) {
        self.out.push(node);
    }

    /// The last node recorded (to decorate it).
    pub fn last(&mut self) -> Option<&mut Node> {
        self.out.last_mut()
    }

    pub fn desc(&mut self, d: &'static str) {
        if let Some(n) = self.last() {
            n.description = Some(d.into());
        }
    }

    pub fn note(&mut self, s: impl Into<String>) {
        if let Some(n) = self.last() {
            n.summary = Some(s.into());
        }
    }

    /// An unsigned decimal field.
    pub fn num(&mut self, name: &'static str, n: usize) -> Option<u64> {
        let (v, span) = self.take(n)?;
        self.push(Node::new(name).span(span).value(Value::UInt {
            value: v,
            bits: bits_of(n),
            radix: Radix::Dec,
        }));
        Some(v)
    }

    /// An unsigned hexadecimal field.
    pub fn hexn(&mut self, name: &'static str, n: usize) -> Option<u64> {
        let (v, span) = self.take(n)?;
        self.push(Node::new(name).span(span).value(Value::UInt {
            value: v,
            bits: bits_of(n),
            radix: Radix::Hex,
        }));
        Some(v)
    }

    pub fn en(&mut self, name: &'static str, n: usize, table: EnumTable) -> Option<u64> {
        let (v, span) = self.take(n)?;
        self.push(Node::new(name).span(span).value(Value::Enum {
            raw: v,
            bits: bits_of(n),
            name: lookup(table, v),
        }));
        Some(v)
    }

    pub fn flags(&mut self, name: &'static str, n: usize, table: &[FlagDef]) -> Option<u64> {
        let (v, span) = self.take(n)?;
        let mut covered = 0u64;
        let mut set = Vec::new();
        for def in table {
            if def.mask != 0 && def.value != 0 && v & def.mask == def.value {
                set.push(def.name);
                covered |= def.mask;
            }
        }
        let unknown = v & !covered;
        self.push(Node::new(name).span(span).value(Value::Flags {
            raw: v,
            bits: bits_of(n),
            set,
            unknown,
        }));
        Some(v)
    }

    /// A field with a value computed from the raw number.
    pub fn val(
        &mut self,
        name: &'static str,
        n: usize,
        f: impl FnOnce(u64) -> Value,
    ) -> Option<u64> {
        let (v, span) = self.take(n)?;
        self.push(Node::new(name).span(span).value(f(v)));
        Some(v)
    }

    /// The signature (magic) of a structure.
    pub fn sig(&mut self, n: usize) -> Option<()> {
        let (bytes, span) = self.slice(n)?;
        let text = String::from_utf8_lossy(bytes).into_owned();
        self.push(Node::new("Signature").span(span).value(Value::Text(text)));
        Some(())
    }

    /// A file address (size of offsets), shown in hex or as undefined.
    pub fn addr(&mut self, name: &'static str) -> Option<u64> {
        let o = self.o;
        let v = self.hexn(name, o)?;
        if undefined(v, o) {
            self.note("undefined");
        }
        Some(v)
    }

    /// A length (size of lengths).
    pub fn length(&mut self, name: &'static str) -> Option<u64> {
        let l = self.l;
        self.num(name, l)
    }

    pub fn bytes(&mut self, name: &'static str, n: usize) -> Option<&'a [u8]> {
        let (bytes, span) = self.slice(n)?;
        let shown = bytes
            .get(..bytes.len().min(256))
            .unwrap_or_default()
            .to_vec();
        self.push(Node::new(name).span(span).value(Value::Bytes(shown)));
        Some(bytes)
    }

    /// Text of `n` bytes, cut at the first NUL.
    pub fn text(&mut self, name: &'static str, n: usize) -> Option<String> {
        let (bytes, span) = self.slice(n)?;
        let text = crate::text::until_nul(bytes);
        self.push(Node::new(name).span(span).value(Value::Text(text.clone())));
        Some(text)
    }

    /// Bytes that are reserved or padding.
    pub fn reserved(&mut self, n: usize) -> Option<()> {
        if n == 0 {
            return Some(());
        }
        self.bytes("Reserved", n)?;
        Some(())
    }

    /// A NUL-terminated string, padded with NULs to a multiple of `align`
    /// bytes (1: no padding).
    pub fn cstr(&mut self, name: &'static str, align: usize) -> Option<String> {
        let rest = self.data.get(self.pos..)?;
        let n = rest.iter().position(|&b| b == 0)?;
        let total = n.saturating_add(1).checked_next_multiple_of(align.max(1))?;
        let text = String::from_utf8_lossy(rest.get(..n)?).into_owned();
        if total > rest.len() {
            return None;
        }
        let span = self.sp(self.pos, total);
        self.pos = self.pos.saturating_add(total);
        self.push(Node::new(name).span(span).value(Value::Text(text.clone())));
        Some(text)
    }

    /// Stops a structure that ran out of bytes: records a truncation note.
    pub fn finish(&mut self, ok: Option<()>) {
        if ok.is_none() {
            let span = self.sp(self.pos, 0);
            self.out.push(Node::new("Truncated").span(span).diag(
                crate::error::Diagnostic::truncated(Span::new(span.source, span.offset, 1), 0),
            ));
        }
    }

    /// Records the bytes from the current position to `end` (if any) as an
    /// unused remainder.
    pub fn rest(&mut self, name: &'static str, end: usize) {
        if end > self.pos && end <= self.data.len() {
            let span = self.sp(self.pos, end.saturating_sub(self.pos));
            self.push(Node::new(name).span(span));
            self.pos = end;
        }
    }
}

// ---------------------------------------------------------------------------
// Checksums

fn le32(b: &[u8], at: usize) -> u32 {
    crate::bytes::u32_le(b, at).unwrap_or(0)
}

/// Bob Jenkins' lookup3 `hashlittle` with an initial value of 0, which
/// HDF5 uses for metadata checksums (`H5_checksum_lookup3`).
pub async fn lookup3(cx: &Cx, data: &[u8]) -> u32 {
    let init =
        0xdead_beefu32.wrapping_add(u32::try_from(to_u64(data.len()) & 0xffff_ffff).unwrap_or(0));
    let (mut a, mut b, mut c) = (init, init, init);
    let mut rest = data;
    let mut rounds = 0usize;
    while rest.len() > 12 {
        let Some((block, tail)) = rest.split_at_checked(12) else {
            break;
        };
        a = a.wrapping_add(le32(block, 0));
        b = b.wrapping_add(le32(block, 4));
        c = c.wrapping_add(le32(block, 8));
        a = a.wrapping_sub(c);
        a ^= c.rotate_left(4);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(6);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(8);
        b = b.wrapping_add(a);
        a = a.wrapping_sub(c);
        a ^= c.rotate_left(16);
        c = c.wrapping_add(b);
        b = b.wrapping_sub(a);
        b ^= a.rotate_left(19);
        a = a.wrapping_add(c);
        c = c.wrapping_sub(b);
        c ^= b.rotate_left(4);
        b = b.wrapping_add(a);
        rest = tail;
        rounds = rounds.wrapping_add(1);
        if rounds.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
    }
    if rest.is_empty() {
        return c;
    }
    let mut last = [0u8; 12];
    if let Some(dst) = last.get_mut(..rest.len()) {
        dst.copy_from_slice(rest);
    }
    a = a.wrapping_add(le32(&last, 0));
    b = b.wrapping_add(le32(&last, 4));
    c = c.wrapping_add(le32(&last, 8));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(14));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(11));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(25));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(16));
    a ^= c;
    a = a.wrapping_sub(c.rotate_left(4));
    b ^= a;
    b = b.wrapping_sub(a.rotate_left(14));
    c ^= b;
    c = c.wrapping_sub(b.rotate_left(24));
    c
}

/// A checksum field over `data[..at]`, stored at `at` (the usual layout of
/// HDF5 metadata blocks: everything before the checksum is covered).
pub async fn checksum_node(cx: &Cx, data: &[u8], span: Span, at: usize) -> Option<Node> {
    let stored = crate::bytes::u32_le(data, at)?;
    let covered = data.get(..at)?;
    let computed = lookup3(cx, covered).await;
    let node = Node::new("Checksum")
        .span(span.sub(to_u64(at), 4))
        .value(Value::UInt {
            value: stored.into(),
            bits: 32,
            radix: Radix::Hex,
        });
    Some(if stored == computed {
        node.summary("lookup3, valid")
    } else {
        node.diag(crate::error::Diagnostic::warning(format!(
            "checksum mismatch: computed {computed:#010x}"
        )))
    })
}

/// HDF5's Fletcher-32 (`H5_checksum_fletcher32`): 16-bit big-endian words,
/// an odd last byte as the high half of a word.
pub async fn fletcher32(cx: &Cx, data: &[u8]) -> u32 {
    let (mut sum1, mut sum2) = (0u32, 0u32);
    let (words, odd) = data.as_chunks::<2>();
    for (i, block) in words.chunks(360).enumerate() {
        for w in block {
            sum1 = sum1.wrapping_add(u32::from(u16::from_be_bytes(*w)));
            sum2 = sum2.wrapping_add(sum1);
        }
        sum1 = (sum1 & 0xffff).wrapping_add(sum1 >> 16);
        sum2 = (sum2 & 0xffff).wrapping_add(sum2 >> 16);
        if i % 64 == 63 {
            cx.checkpoint().await;
        }
    }
    if let Some(&b) = odd.first() {
        sum1 = sum1.wrapping_add(u32::from(b) << 8);
        sum2 = sum2.wrapping_add(sum1);
        sum1 = (sum1 & 0xffff).wrapping_add(sum1 >> 16);
        sum2 = (sum2 & 0xffff).wrapping_add(sum2 >> 16);
    }
    sum1 = (sum1 & 0xffff).wrapping_add(sum1 >> 16);
    sum2 = (sum2 & 0xffff).wrapping_add(sum2 >> 16);
    (sum2 << 16) | sum1
}

/// Shows a list of numbers: `"1, 2, 3"`.
pub fn join<T: std::fmt::Display>(items: &[T], sep: &str) -> String {
    let parts: Vec<String> = items.iter().map(ToString::to_string).collect();
    parts.join(sep)
}

/// Dimensions as `20×20` (or `scalar`).
pub fn shape(dims: &[u64]) -> String {
    if dims.is_empty() {
        "scalar".to_owned()
    } else {
        join(dims, "×")
    }
}

/// A byte count for summaries.
pub fn size_text(n: u64) -> String {
    crate::formats::util::datakit::size(n)
}
