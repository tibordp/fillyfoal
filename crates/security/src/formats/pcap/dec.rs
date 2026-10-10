//! The packet decoder's builder: reads fields from the bytes of one packet
//! and, when building, records them as a tree of nodes with exact spans.
//!
//! The same decoders run in two modes. Listing a capture runs them without a
//! tree, over the first bytes of each packet, only to compute the one-line
//! summary (addresses, protocol, Info text); expanding a packet runs them
//! over the whole packet (up to [`MAX_DECODE`] bytes) and keeps the nodes.
//! Everything is synchronous and bounded by the packet length.

use std::borrow::Cow;
use std::sync::Arc;

use crate::bytes::to_u64;
use crate::error::Diagnostic;
use crate::fields::Endian;
use crate::formats::Input;
use crate::formats::util::binutil::{Tree, get};
use crate::formats::util::val::{enumv, hex, uint};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, decode_flags};

/// Bytes of a packet decoded on expansion; the rest is shown as data.
pub const MAX_DECODE: u64 = 0x1_0000;
/// Bytes of a packet looked at for its summary line.
pub const SUMMARY_WINDOW: u64 = 1536;
/// Nodes built per packet; decoding goes on silently past this.
pub const MAX_NODES: usize = 16_384;
/// Nested protocol layers (tunnels, VLAN tags, quoted datagrams) decoded.
const MAX_DEPTH: u32 = 24;

/// A node index in the tree being built (0, the packet, when not building).
pub type Ix = usize;

pub struct Dec<'a> {
    pub d: &'a [u8],
    span: Span,
    pub input: Input,
    tree: Option<Tree>,
    last: Ix,
    /// More than [`MAX_NODES`] nodes were wanted.
    pub overflow: bool,
    /// Byte order of the integer helpers (802.11 and radiotap are little-endian).
    pub endian: Endian,
    /// `d` holds the whole captured packet (not just a summary window).
    pub complete: bool,
    /// Inside a quoted datagram (ICMP error): the summary is not updated.
    pub quoted: u32,
    depth: u32,
    /// Info text: the most specific layer's one-line description.
    pub info: String,
    /// The most specific protocol decoded (for statistics).
    pub proto: &'static str,
    pub src: String,
    pub dst: String,
}

impl<'a> Dec<'a> {
    /// A decoder over `d`, the bytes at the start of `span` (a packet).
    pub fn new(d: &'a [u8], span: Span, input: Input, build: bool, complete: bool) -> Self {
        let tree = build.then(|| {
            let mut t = Tree::default();
            t.add(None, Node::new("packet"));
            t
        });
        Dec {
            d,
            span,
            input,
            tree,
            last: 0,
            overflow: false,
            endian: Endian::Big,
            complete,
            quoted: 0,
            depth: 0,
            info: String::new(),
            proto: "",
            src: String::new(),
            dst: String::new(),
        }
    }

    pub fn building(&self) -> bool {
        self.tree.is_some()
    }

    pub fn len(&self) -> usize {
        self.d.len()
    }

    pub fn is_empty(&self) -> bool {
        self.d.is_empty()
    }

    /// The finished tree (root 0 is the packet).
    pub fn finish(self) -> Option<Arc<Tree>> {
        self.tree.map(Arc::new)
    }

    /// The span of `len` bytes at `off` in the packet.
    pub fn sp(&self, off: usize, len: usize) -> Span {
        self.span.sub(to_u64(off), to_u64(len))
    }

    /// Enters a nested layer; false once too deep.
    pub fn enter(&mut self) -> bool {
        if self.depth >= MAX_DEPTH {
            return false;
        }
        self.depth = self.depth.saturating_add(1);
        true
    }

    pub fn leave(&mut self) {
        self.depth = self.depth.saturating_sub(1);
    }

    /// Whether summary fields may be set (not inside a quoted datagram).
    pub fn top(&self) -> bool {
        self.quoted == 0
    }

    pub fn set_info(&mut self, proto: &'static str, info: impl FnOnce() -> String) {
        if self.top() {
            self.proto = proto;
            self.info = info();
        }
    }

    pub fn set_addrs(&mut self, src: impl FnOnce() -> String, dst: impl FnOnce() -> String) {
        if self.top() {
            self.src = src();
            self.dst = dst();
        }
    }

    // -- reading --

    pub fn u8(&self, off: usize) -> Option<u8> {
        self.d.get(off).copied()
    }

    pub fn u16(&self, off: usize) -> Option<u16> {
        get::<u16>(self.d, off, self.endian)
    }

    pub fn u32(&self, off: usize) -> Option<u32> {
        get::<u32>(self.d, off, self.endian)
    }

    pub fn u64(&self, off: usize) -> Option<u64> {
        get::<u64>(self.d, off, self.endian)
    }

    pub fn be16(&self, off: usize) -> Option<u16> {
        get::<u16>(self.d, off, Endian::Big)
    }

    pub fn be32(&self, off: usize) -> Option<u32> {
        get::<u32>(self.d, off, Endian::Big)
    }

    /// An unsigned integer of `size` (1, 2, 3, 4 or 8) bytes.
    pub fn uint(&self, off: usize, size: usize) -> Option<u64> {
        match size {
            1 => self.u8(off).map(u64::from),
            2 => self.u16(off).map(u64::from),
            3 => {
                let b = self.bytes(off, 3)?;
                let (a, m, z) = (
                    u64::from(*b.first()?),
                    u64::from(*b.get(1)?),
                    u64::from(*b.get(2)?),
                );
                Some(match self.endian {
                    Endian::Big => a << 16 | m << 8 | z,
                    Endian::Little => z << 16 | m << 8 | a,
                })
            }
            4 => self.u32(off).map(u64::from),
            8 => self.u64(off),
            _ => None,
        }
    }

    pub fn bytes(&self, off: usize, len: usize) -> Option<&'a [u8]> {
        self.d.get(off..off.checked_add(len)?)
    }

    /// The bytes from `off` to `end` (clamped to what is present).
    pub fn range(&self, off: usize, end: usize) -> &'a [u8] {
        let end = end.min(self.d.len());
        self.d.get(off..end).unwrap_or_default()
    }

    // -- building --

    /// Adds a node under `parent`; `f` decorates it (only when building).
    pub fn add(
        &mut self,
        parent: Ix,
        name: impl Into<Cow<'static, str>>,
        off: usize,
        len: usize,
        f: impl FnOnce(Node) -> Node,
    ) -> Ix {
        let span = self.sp(off, len);
        match &mut self.tree {
            Some(t) if t.next_index() < MAX_NODES => {
                self.last = t.add(Some(parent), f(Node::new(name).span(span)));
                self.last
            }
            Some(_) => {
                self.overflow = true;
                self.last = usize::MAX;
                usize::MAX
            }
            None => 0,
        }
    }

    /// Adds a prebuilt node (e.g. an embedded format) under `parent`.
    pub fn push_node(&mut self, parent: Ix, node: Node) -> Ix {
        match &mut self.tree {
            Some(t) if t.next_index() < MAX_NODES => {
                self.last = t.add(Some(parent), node);
                self.last
            }
            Some(_) => {
                self.overflow = true;
                self.last = usize::MAX;
                usize::MAX
            }
            None => 0,
        }
    }

    /// A group (layer, structure) node.
    pub fn group(
        &mut self,
        parent: Ix,
        name: impl Into<Cow<'static, str>>,
        off: usize,
        len: usize,
    ) -> Ix {
        self.add(parent, name, off, len, |n| n)
    }

    /// Changes the node `ix` (only when building).
    pub fn update(&mut self, ix: Ix, f: impl FnOnce(Node) -> Node) {
        if let Some(t) = &mut self.tree {
            t.update(ix, f);
        }
    }

    /// Changes the node added last.
    pub fn tail(&mut self, f: impl FnOnce(Node) -> Node) {
        let last = self.last;
        self.update(last, f);
    }

    pub fn summary(&mut self, ix: Ix, s: impl FnOnce() -> String) {
        if self.building() {
            let s = s();
            self.update(ix, |n| n.summary(s));
        }
    }

    pub fn diag(&mut self, ix: Ix, d: Diagnostic) {
        self.update(ix, |n| n.diag(d));
    }

    /// An unsigned decimal field of `size` bytes.
    pub fn num(&mut self, p: Ix, name: &'static str, off: usize, size: usize) -> Option<u64> {
        let v = self.uint(off, size);
        self.field(p, name, off, size, v, |v| uint(v, bits(size)))
    }

    /// An unsigned hexadecimal field of `size` bytes.
    pub fn numx(&mut self, p: Ix, name: &'static str, off: usize, size: usize) -> Option<u64> {
        let v = self.uint(off, size);
        self.field(p, name, off, size, v, |v| hex(v, bits(size)))
    }

    /// An enumerated field of `size` bytes.
    pub fn enm(
        &mut self,
        p: Ix,
        name: &'static str,
        off: usize,
        size: usize,
        table: EnumTable,
    ) -> Option<u64> {
        let v = self.uint(off, size);
        self.field(p, name, off, size, v, |v| enumv(v, bits(size), table))
    }

    /// A flags field of `size` bytes.
    pub fn flg(
        &mut self,
        p: Ix,
        name: &'static str,
        off: usize,
        size: usize,
        table: FlagTable,
    ) -> Option<u64> {
        let v = self.uint(off, size);
        self.field(p, name, off, size, v, |v| flags(v, bits(size), table))
    }

    /// A field with a value computed from the integer at `off`.
    fn field(
        &mut self,
        p: Ix,
        name: &'static str,
        off: usize,
        size: usize,
        v: Option<u64>,
        value: impl FnOnce(u64) -> Value,
    ) -> Option<u64> {
        match v {
            Some(v) => {
                self.add(p, name, off, size, |n| n.value(value(v)));
                Some(v)
            }
            None => {
                self.truncated(p, name, off, size);
                None
            }
        }
    }

    /// A text field.
    pub fn text(
        &mut self,
        p: Ix,
        name: impl Into<Cow<'static, str>>,
        off: usize,
        len: usize,
        s: impl FnOnce() -> String,
    ) -> Ix {
        if self.bytes(off, len).is_none() {
            return self.truncated(p, name, off, len);
        }
        self.add(p, name, off, len, |n| n.value(Value::Text(s())))
    }

    /// An IPv4 address field.
    pub fn ip4(&mut self, p: Ix, name: &'static str, off: usize) -> Option<[u8; 4]> {
        let a: Option<[u8; 4]> = self.bytes(off, 4).and_then(|b| b.try_into().ok());
        self.text(p, name, off, 4, || a.map(|a| ipv4(&a)).unwrap_or_default());
        a
    }

    /// An IPv6 address field.
    pub fn ip6(&mut self, p: Ix, name: &'static str, off: usize) -> Option<[u8; 16]> {
        let a: Option<[u8; 16]> = self.bytes(off, 16).and_then(|b| b.try_into().ok());
        self.text(p, name, off, 16, || a.map(|a| ipv6(&a)).unwrap_or_default());
        a
    }

    /// A MAC address field.
    pub fn mac(&mut self, p: Ix, name: &'static str, off: usize) -> Option<[u8; 6]> {
        let a: Option<[u8; 6]> = self.bytes(off, 6).and_then(|b| b.try_into().ok());
        self.text(p, name, off, 6, || a.map(|a| mac(&a)).unwrap_or_default());
        a
    }

    /// Raw bytes shown as a hex value (short) or a sized leaf.
    pub fn raw(&mut self, p: Ix, name: impl Into<Cow<'static, str>>, off: usize, len: usize) -> Ix {
        match self.bytes(off, len) {
            Some(b) if len <= 256 => {
                let v = b.to_vec();
                self.add(p, name, off, len, |n| n.value(Value::Bytes(v)))
            }
            Some(_) => self.add(p, name, off, len, |n| {
                n.summary(crate::formats::util::fmt::size(to_u64(len)))
            }),
            None => self.truncated(p, name, off, len),
        }
    }

    /// Opaque data from `off` to `end` (nothing when empty); returns `end`.
    pub fn data(
        &mut self,
        p: Ix,
        name: impl Into<Cow<'static, str>>,
        off: usize,
        end: usize,
    ) -> usize {
        if off < end {
            let len = end.saturating_sub(off);
            self.add(p, name, off, len, |n| {
                n.summary(crate::formats::util::fmt::size(to_u64(len)))
            });
        }
        end.max(off)
    }

    /// A node for a field cut short by the end of the captured data.
    pub fn truncated(
        &mut self,
        p: Ix,
        name: impl Into<Cow<'static, str>>,
        off: usize,
        len: usize,
    ) -> Ix {
        let have = to_u64(self.d.len().saturating_sub(off));
        let want = self.sp(off, len);
        let want = Span::new(want.source, want.offset, to_u64(len));
        self.add(p, name, off, len, |n| {
            n.diag(Diagnostic::truncated(want, have))
        })
    }
}

fn bits(size: usize) -> u8 {
    u8::try_from(size.saturating_mul(8)).unwrap_or(64)
}

pub fn flags(v: u64, bits: u8, table: FlagTable) -> Value {
    let (set, unknown) = decode_flags(table, v);
    Value::Flags {
        raw: v,
        bits,
        set,
        unknown,
    }
}

/// The Internet checksum (RFC 1071) over `parts`, each summed as if
/// concatenated with even alignment per part.
pub fn inet_sum(parts: &[&[u8]]) -> u16 {
    let mut sum: u64 = 0;
    for part in parts {
        let (pairs, rest) = part.as_chunks::<2>();
        for &p in pairs {
            sum = sum.wrapping_add(u64::from(u16::from_be_bytes(p)));
        }
        if let Some(&b) = rest.first() {
            sum = sum.wrapping_add(u64::from(b) << 8);
        }
    }
    while sum > 0xffff {
        sum = (sum & 0xffff).wrapping_add(sum >> 16);
    }
    !u16::try_from(sum).unwrap_or(0)
}

pub fn mac(b: &[u8]) -> String {
    b.iter()
        .map(|x| format!("{x:02x}"))
        .collect::<Vec<_>>()
        .join(":")
}

pub fn ipv4(b: &[u8]) -> String {
    b.iter().map(u8::to_string).collect::<Vec<_>>().join(".")
}

pub fn ipv6(b: &[u8]) -> String {
    let groups: Vec<u16> = b
        .as_chunks::<2>()
        .0
        .iter()
        .map(|&p| u16::from_be_bytes(p))
        .collect();
    // An IPv4-mapped address.
    if groups.len() == 8
        && groups.get(..5).is_some_and(|g| g.iter().all(|&x| x == 0))
        && groups.get(5) == Some(&0xffff)
    {
        return format!("::ffff:{}", ipv4(b.get(12..16).unwrap_or_default()));
    }
    // Compress the longest run of zero groups.
    let (mut best, mut best_len, mut run, mut run_len) = (0usize, 0usize, 0usize, 0usize);
    for (i, &g) in groups.iter().enumerate() {
        if g == 0 {
            if run_len == 0 {
                run = i;
            }
            run_len = run_len.saturating_add(1);
            if run_len > best_len {
                best = run;
                best_len = run_len;
            }
        } else {
            run_len = 0;
        }
    }
    let hexes = |gs: &[u16]| {
        gs.iter()
            .map(|g| format!("{g:x}"))
            .collect::<Vec<_>>()
            .join(":")
    };
    if best_len < 2 {
        return hexes(&groups);
    }
    let head = groups.get(..best).unwrap_or_default();
    let tail = groups
        .get(best.saturating_add(best_len)..)
        .unwrap_or_default();
    format!("{}::{}", hexes(head), hexes(tail))
}
