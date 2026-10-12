//! ZFS pool members (vdevs): the vdev label's configuration, an XDR-encoded
//! name-value list, and its uberblock ring.
//!
//! Each label is 256 KiB: 16 KiB of padding and boot header, 112 KiB of
//! nvlist, 128 KiB of uberblocks. Labels 0 and 1 are at the start of the
//! device, 2 and 3 at its end.

use std::sync::Arc;

use crate::bytes::{to_u64, to_usize, u32_be, u64_be, u64_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

const LABEL: u64 = 256 * 1024;
const NVLIST: u64 = 16 * 1024;
const NVLIST_LEN: u64 = 112 * 1024;
const UBERBLOCKS: u64 = 128 * 1024;
const UB_MAGIC: u64 = 0x00ba_b10c;
/// Pairs decoded per nvlist, and nesting followed.
const MAX_PAIRS: usize = 4096;
const MAX_DEPTH: u32 = 16;

pub static FORMAT: Format = Format {
    name: "zfs",
    title: "ZFS pool member (vdev label)",
    extensions: &["img", "zfs"],
    mime: "application/x-zfs",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let at = to_usize(NVLIST);
    h.at(at, &[1])
        && h.data.get(at.saturating_add(1)).is_some_and(|&e| e <= 1)
        && h.at(at.saturating_add(2), &[0, 0, 0, 0, 0, 0, 0, 0, 0, 1])
}

/// A decoded nvlist value.
#[derive(Clone, Debug)]
enum Nv {
    Scalar(Value),
    List(Arc<NvList>),
    Lists(Vec<Arc<NvList>>),
    Other(&'static str),
}

#[derive(Clone, Debug, Default)]
struct NvList {
    pairs: Vec<(String, Nv, Span)>,
}

impl NvList {
    fn get(&self, key: &str) -> Option<&Nv> {
        self.pairs
            .iter()
            .find(|(k, _, _)| k == key)
            .map(|(_, v, _)| v)
    }

    fn text(&self, key: &str) -> Option<String> {
        match self.get(key)? {
            Nv::Scalar(Value::Text(s)) => Some(s.clone()),
            Nv::Scalar(Value::UInt { value, .. }) => Some(value.to_string()),
            _ => None,
        }
    }
}

const TYPES: EnumTable = &[
    (1, "boolean"),
    (2, "byte"),
    (3, "int16"),
    (4, "uint16"),
    (5, "int32"),
    (6, "uint32"),
    (7, "int64"),
    (8, "uint64"),
    (9, "string"),
    (10, "byte array"),
    (11, "int16 array"),
    (12, "uint16 array"),
    (13, "int32 array"),
    (14, "uint32 array"),
    (15, "int64 array"),
    (16, "uint64 array"),
    (17, "string array"),
    (18, "hrtime"),
    (19, "nvlist"),
    (20, "nvlist array"),
    (21, "boolean value"),
    (22, "int8"),
    (23, "uint8"),
    (24, "boolean array"),
    (25, "int8 array"),
    (26, "uint8 array"),
    (27, "double"),
];

/// An XDR decoder over an in-memory nvlist.
struct Xdr<'a> {
    data: &'a [u8],
    at: usize,
    base: Span,
    budget: usize,
}

impl Xdr<'_> {
    fn u32(&mut self) -> Option<u32> {
        let v = u32_be(self.data, self.at)?;
        self.at = self.at.saturating_add(4);
        Some(v)
    }

    fn u64(&mut self) -> Option<u64> {
        let v = u64_be(self.data, self.at)?;
        self.at = self.at.saturating_add(8);
        Some(v)
    }

    fn string(&mut self) -> Option<String> {
        let len = to_usize(self.u32()?.into());
        let bytes = self.data.get(self.at..self.at.checked_add(len)?)?;
        self.at = self.at.saturating_add(len.checked_next_multiple_of(4)?);
        Some(String::from_utf8_lossy(bytes).into_owned())
    }

    /// An nvlist: version, flags, pairs, then a zero terminator.
    fn list(&mut self, depth: u32) -> Option<NvList> {
        let _version = self.u32()?;
        let _flags = self.u32()?;
        let mut list = NvList::default();
        loop {
            let start = self.at;
            let encoded = to_usize(self.u32()?.into());
            let decoded = self.u32()?;
            if encoded == 0 && decoded == 0 {
                return Some(list);
            }
            self.budget = self.budget.checked_sub(1)?;
            let end = start.checked_add(encoded)?;
            if end > self.data.len() || encoded < 8 {
                return None;
            }
            let name = self.string()?;
            let kind = self.u32()?;
            let count = self.u32()?;
            let value = self
                .value(kind, count, depth)
                .unwrap_or(Nv::Other("undecoded"));
            let span = self.base.sub(to_u64(start), to_u64(encoded));
            list.pairs.push((name, value, span));
            self.at = end;
            if list.pairs.len() >= MAX_PAIRS {
                return Some(list);
            }
        }
    }

    fn value(&mut self, kind: u32, count: u32, depth: u32) -> Option<Nv> {
        let uint = |v: u64, bits: u8| {
            Nv::Scalar(Value::UInt {
                value: v,
                bits,
                radix: Radix::Dec,
            })
        };
        Some(match kind {
            1 => Nv::Scalar(Value::Bool(true)),
            21 => Nv::Scalar(Value::Bool(self.u32()? != 0)),
            2 | 4 | 6 | 23 => uint(self.u32()?.into(), 32),
            3 | 5 | 22 => Nv::Scalar(Value::Int {
                value: i64::from(i32::from_be_bytes(self.u32()?.to_be_bytes())),
                bits: 32,
            }),
            8 | 18 => uint(self.u64()?, 64),
            7 => Nv::Scalar(Value::Int {
                value: i64::from_be_bytes(self.u64()?.to_be_bytes()),
                bits: 64,
            }),
            9 => Nv::Scalar(Value::Text(self.string()?)),
            16 => {
                let n = self.u32()?.min(1024);
                let items: Option<Vec<String>> =
                    (0..n).map(|_| self.u64().map(|v| v.to_string())).collect();
                Nv::Scalar(Value::Text(format!("[{}]", items?.join(", "))))
            }
            19 if depth < MAX_DEPTH => Nv::List(Arc::new(self.list(depth.saturating_add(1))?)),
            20 if depth < MAX_DEPTH => {
                let mut lists = Vec::new();
                for _ in 0..count.min(1024) {
                    lists.push(Arc::new(self.list(depth.saturating_add(1))?));
                }
                Nv::Lists(lists)
            }
            other => Nv::Other(crate::value::lookup(TYPES, other.into()).unwrap_or("unknown type")),
        })
    }
}

/// Decodes the nvlist in a label's configuration area.
fn decode(data: &[u8], base: Span) -> Option<NvList> {
    // Header: encoding (1 = XDR), endianness, two reserved bytes.
    if data.first() != Some(&1) {
        return None;
    }
    let mut xdr = Xdr {
        data,
        at: 4,
        base,
        budget: 100_000,
    };
    xdr.list(0)
}

const STATES: EnumTable = &[
    (0, "active"),
    (1, "exported"),
    (2, "destroyed"),
    (3, "spare"),
    (4, "L2ARC"),
    (5, "uninitialized"),
    (6, "unavailable"),
    (7, "potentially active"),
];

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let dev = input.span;
    cx.emit(Node::new("Blank space").span(dev.sub(0, 8 * 1024)));
    cx.emit(Node::new("Boot block header").span(dev.sub(8 * 1024, 8 * 1024)));
    let nv_span = dev.sub(NVLIST, NVLIST_LEN);
    let data = cx.read_avail(nv_span).await?;
    let list = decode(&data, nv_span)
        .ok_or_else(|| Diagnostic::malformed("undecodable nvlist").at(nv_span))?;
    let name = list.text("name").unwrap_or_default();
    let state = list
        .get("state")
        .and_then(|v| match v {
            Nv::Scalar(Value::UInt { value, .. }) => crate::value::lookup(STATES, *value),
            _ => None,
        })
        .unwrap_or("unknown state");
    let (vdev, ashift) = match list.get("vdev_tree") {
        Some(Nv::List(v)) => (
            v.text("type").unwrap_or_default(),
            v.text("ashift").and_then(|a| a.parse().ok()),
        ),
        _ => (String::new(), None),
    };
    cx.annotate(format!(
        "ZFS pool \"{name}\" ({state}), {vdev} vdev, pool version {}, txg {}",
        list.text("version").unwrap_or_default(),
        list.text("txg").unwrap_or_default()
    ));
    let pairs = list.pairs.len();
    let config = Node::new("Configuration (label 0)")
        .span(nv_span)
        .lazy(crate::expander!(self::nvlist: Arc<NvList>), Arc::new(list));
    cx.emit(checked(&cx, config, &data, NVLIST, format!("{pairs} pairs")).await);
    let ring = dev.sub(UBERBLOCKS, UBERBLOCKS);
    // The slot size follows the top-level vdev's sector size (ashift).
    let slot = slot_size(ashift.unwrap_or(9));
    cx.emit(
        Node::new("Uberblocks (label 0)")
            .span(ring)
            .lazy(uberblocks, (ring, slot, UBERBLOCKS)),
    );
    // Labels 2 and 3 end the device, rounded down to whole labels
    // (`vdev_label_offset`).
    let size = dev.len & !(LABEL - 1);
    for (i, at) in [
        Some(LABEL),
        size.checked_sub(2 * LABEL),
        size.checked_sub(LABEL),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(at) = at.filter(|&a| a >= LABEL && dev.len >= a.saturating_add(LABEL)) {
            cx.emit(
                Node::new(format!("Label {}", i.saturating_add(1)))
                    .span(dev.sub(at, LABEL))
                    .lazy(label, (dev, at, slot)),
            );
        }
    }
    Ok(())
}

/// Labels 1 to 3: the same configuration and uberblock ring as label 0
/// (`zdb -l` compares them), checked at their own offsets.
async fn label(cx: Cx, (dev, at, slot): (Span, u64, u64)) -> Result<()> {
    let nv_at = at.saturating_add(NVLIST);
    let nv_span = dev.sub(nv_at, NVLIST_LEN);
    let data = cx.read_avail(nv_span).await?;
    let node = Node::new("Configuration").span(nv_span);
    let node = match decode(&data, nv_span) {
        Some(list) => {
            let pairs = list.pairs.len();
            let node = node.lazy(crate::expander!(self::nvlist: Arc<NvList>), Arc::new(list));
            checked(&cx, node, &data, nv_at, format!("{pairs} pairs")).await
        }
        None => node.diag(Diagnostic::malformed("undecodable nvlist").at(nv_span)),
    };
    cx.emit(node);
    let ring_at = at.saturating_add(UBERBLOCKS);
    let ring = dev.sub(ring_at, UBERBLOCKS);
    cx.emit(
        Node::new("Uberblocks")
            .span(ring)
            .lazy(uberblocks, (ring, slot, ring_at)),
    );
    Ok(())
}

async fn nvlist(cx: Cx, list: Arc<NvList>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(list.pairs.len())));
    for (name, value, span) in &list.pairs {
        let node = Node::new(name.clone()).span(*span);
        let node = match value {
            Nv::Scalar(Value::UInt { value, .. }) if name == "state" => {
                node.value(crate::formats::util::val::enumv(*value, 64, STATES))
            }
            Nv::Scalar(v) => node.value(v.clone()),
            Nv::List(inner) => node
                .summary(format!("{} pairs", inner.pairs.len()))
                .lazy(crate::expander!(self::nvlist: Arc<NvList>), inner.clone()),
            Nv::Lists(lists) => node.summary(format!("{} nvlists", lists.len())).lazy(
                crate::expander!(self::nvlists: Arc<Vec<Arc<NvList>>>),
                Arc::new(lists.clone()),
            ),
            Nv::Other(kind) => node.summary(format!("({kind})")),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn nvlists(cx: Cx, lists: Arc<Vec<Arc<NvList>>>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(lists.len())));
    for (i, list) in lists.iter().enumerate() {
        let label = list
            .text("type")
            .map_or_else(String::new, |t| format!("{t} "));
        let path = list.text("path").unwrap_or_default();
        cx.push(
            Node::new(format!("[{i}]"))
                .summary(format!("{label}{path}"))
                .lazy(crate::expander!(self::nvlist: Arc<NvList>), list.clone()),
        )
        .await;
    }
    Ok(())
}

record! {
    /// `uberblock_t`, up to its root block pointer.
    pub struct Uberblock {
        magic: u64 "Magic" .hex(),
        version: u64 "SPA version",
        txg: u64 "Transaction group",
        guid_sum: u64 "GUID sum" .hex(),
        timestamp: u64 "Written" .timestamp(),
    }
}

record! {
    /// `uberblock_t`, after its root block pointer.
    pub struct UberblockTail {
        software_version: u64 "Software version",
        mmp_magic: u64 "MMP magic" .hex(),
        mmp_delay: u64 "MMP delay (ns)",
        mmp_config: u64 "MMP configuration" .hex(),
        checkpoint_txg: u64 "Checkpoint txg",
        raidz_reflow: u64 "RAID-Z expansion state" .hex(),
    }
}

/// Size of a block pointer (`blkptr_t`).
const BP_SIZE: u64 = 128;

const COMPRESS: EnumTable = &[
    (0, "inherit"),
    (1, "on"),
    (2, "uncompressed"),
    (3, "lzjb"),
    (4, "empty"),
    (5, "gzip-1"),
    (6, "gzip-2"),
    (7, "gzip-3"),
    (8, "gzip-4"),
    (9, "gzip-5"),
    (10, "gzip-6"),
    (11, "gzip-7"),
    (12, "gzip-8"),
    (13, "gzip-9"),
    (14, "zle"),
    (15, "lz4"),
    (16, "zstd"),
];

const CHECKSUM: EnumTable = &[
    (0, "inherit"),
    (1, "on"),
    (2, "off"),
    (3, "label"),
    (4, "gang_header"),
    (5, "zilog"),
    (6, "fletcher2"),
    (7, "fletcher4"),
    (8, "sha256"),
    (9, "zilog2"),
    (10, "noparity"),
    (11, "sha512"),
    (12, "skein"),
    (13, "edonr"),
    (14, "blake3"),
];

/// `dmu_object_type_t`, as far as the types near the top of a pool.
const OBJECT_TYPES: EnumTable = &[
    (0, "none"),
    (1, "object directory"),
    (2, "object array"),
    (3, "packed nvlist"),
    (4, "packed nvlist size"),
    (5, "bpobj"),
    (6, "bpobj header"),
    (7, "SPA space map header"),
    (8, "SPA space map"),
    (9, "ZIL intent log"),
    (10, "DMU dnode"),
    (11, "DMU objset"),
    (12, "DSL directory"),
    (13, "DSL directory child map"),
    (14, "DSL dataset snap map"),
    (15, "DSL props"),
    (16, "DSL dataset"),
    (17, "ZFS znode"),
    (18, "ZFS V0 ACL"),
    (19, "ZFS plain file"),
    (20, "ZFS directory"),
    (21, "ZFS master node"),
    (22, "ZFS delete queue"),
    (23, "zvol object"),
    (24, "zvol prop"),
];

/// Bits `shift..shift + len` of `v`.
fn bits(v: u64, shift: u32, len: u32) -> u64 {
    v.checked_shr(shift).unwrap_or(0) & 1u64.checked_shl(len).unwrap_or(0).wrapping_sub(1)
}

fn name_of(table: EnumTable, v: u64) -> String {
    crate::value::lookup(table, v).map_or_else(|| v.to_string(), str::to_owned)
}

/// A DVA as zdb prints it, `<vdev:offset:allocated size>` (hex bytes).
fn dva(w0: u64, w1: u64) -> String {
    format!(
        "<{}:{:x}:{:x}>{}",
        bits(w0, 32, 24),
        bits(w1, 0, 63) << 9,
        bits(w0, 0, 24) << 9,
        if w1 >> 63 == 1 { " gang" } else { "" }
    )
}

/// The properties word as zdb prints it: `[L<level> <type>] <checksum>
/// <compression> <byte order> size=<logical>L/<physical>P`.
fn props_summary(prop: u64) -> String {
    let order = if prop >> 63 == 1 { "LE" } else { "BE" };
    let head = format!(
        "[L{} {}]",
        bits(prop, 56, 5),
        name_of(OBJECT_TYPES, bits(prop, 48, 8))
    );
    let comp = name_of(COMPRESS, bits(prop, 32, 7));
    if bits(prop, 39, 1) == 1 {
        // Embedded data: the payload replaces the DVAs and checksum.
        return format!(
            "{head} embedded type {} {comp} {order} size={:x}L/{:x}P",
            bits(prop, 40, 8),
            bits(prop, 0, 25).saturating_add(1),
            bits(prop, 25, 7).saturating_add(1)
        );
    }
    let mut extra = String::new();
    if bits(prop, 61, 1) == 1 {
        extra.push_str(" encrypted");
    }
    if bits(prop, 62, 1) == 1 {
        extra.push_str(" dedup");
    }
    format!(
        "{head} {} {comp}{extra} {order} size={:x}L/{:x}P",
        name_of(CHECKSUM, bits(prop, 40, 8)),
        bits(prop, 0, 16).saturating_add(1) << 9,
        bits(prop, 16, 16).saturating_add(1) << 9
    )
}

/// The 16 words of a block pointer.
fn bp_words(data: &[u8], endian: Endian) -> Option<[u64; 16]> {
    let mut w = [0u64; 16];
    for (i, slot) in w.iter_mut().enumerate() {
        let at = i.saturating_mul(8);
        *slot = match endian {
            Endian::Little => u64_le(data, at),
            Endian::Big => u64_be(data, at),
        }?;
    }
    Some(w)
}

/// zdb's one-line view of a block pointer (`snprintf_blkptr`).
fn bp_summary(w: &[u64; 16]) -> String {
    let [a0, a1, b0, b1, c0, c1, prop, _, _, phys, birth, fill, ..] = *w;
    if w.iter().all(|&x| x == 0) {
        return "hole".to_owned();
    }
    if bits(prop, 39, 1) == 1 {
        return format!("EMBEDDED {} birth={birth}L", props_summary(prop));
    }
    let dvas: Vec<String> = [(a0, a1), (b0, b1), (c0, c1)]
        .into_iter()
        .enumerate()
        .filter(|(_, (x, y))| *x != 0 || *y != 0)
        .map(|(i, (x, y))| format!("DVA[{i}]={}", dva(x, y)))
        .collect();
    let phys = if phys == 0 { birth } else { phys };
    format!(
        "{} {} birth={birth}L/{phys}P fill={fill}",
        dvas.join(" "),
        props_summary(prop)
    )
}

/// `blkptr_t`: three DVAs, the properties word, padding, birth txgs, fill
/// count and checksum.
fn bp_layout(f: &mut Fields<'_>, &endian: &Endian) -> Result<()> {
    let embedded = bp_words(&f.block().data, endian).is_some_and(|w| bits(w[6], 39, 1) == 1);
    if embedded {
        f.bytes("Embedded payload (part 1)", 48).emit()?;
        f.u64("Properties")
            .hex()
            .with(|&v, n| n.summary(props_summary(v)))
            .emit()?;
        f.bytes("Embedded payload (part 2)", 24).emit()?;
        f.u64("Logical birth txg").emit()?;
        f.bytes("Embedded payload (part 3)", 40).emit()?;
        return Ok(());
    }
    for name in ["DVA[0]", "DVA[1]", "DVA[2]"] {
        let span = f.peek_span(16);
        let w0 = f.u64("DVA word 0").get()?;
        let w1 = f.u64("DVA word 1").get()?;
        let node = Node::new(name).span(span);
        f.node(if w0 == 0 && w1 == 0 {
            node.summary("unused")
        } else {
            node.value(Value::Text(dva(w0, w1)))
                .desc("<vdev:offset:allocated size>, in bytes")
        });
    }
    f.u64("Properties")
        .hex()
        .with(|&v, n| n.summary(props_summary(v)))
        .emit()?;
    f.bytes("Padding", 16).emit()?;
    f.u64("Physical birth txg").emit()?;
    f.u64("Logical birth txg").emit()?;
    f.u64("Fill count").emit()?;
    let span = f.peek_span(32);
    let mut words = Vec::new();
    for _ in 0..4 {
        words.push(format!("{:016x}", f.u64("Checksum word").get()?));
    }
    f.node(
        Node::new("Checksum")
            .span(span)
            .value(Value::Text(words.join(":"))),
    );
    Ok(())
}

/// An uberblock: its fields, the root block pointer, and the rest.
fn ub_layout(f: &mut Fields<'_>, &endian: &Endian) -> Result<()> {
    Uberblock::read(f)?;
    let span = f.peek_span(BP_SIZE);
    let words = f
        .block()
        .data
        .get(to_usize(f.pos())..)
        .and_then(|d| bp_words(d, endian));
    let mut node = struct_node("Root block pointer", span, endian, endian, bp_layout);
    if let Some(w) = words {
        node = node.summary(bp_summary(&w));
    }
    f.node(node);
    f.skip(BP_SIZE);
    UberblockTail::read(f)?;
    Ok(())
}

/// The uberblock slot size: `1 << ashift`, at least 1 KiB and at most
/// 8 KiB (`VDEV_UBERBLOCK_SHIFT`).
fn slot_size(ashift: u64) -> u64 {
    1u64 << ashift.clamp(10, 13)
}

/// Magic of the embedded checksum trailer (`zio_eck_t`).
const ECK_MAGIC: u64 = 0x0210_da7a_b10c_7a11;

/// Verifies a label block's embedded checksum (`ZIO_CHECKSUM_LABEL`): the
/// block ends in a `zio_eck_t` (magic, four checksum words); the checksum
/// is SHA-256 of the block with the words replaced by the verifier (the
/// block's byte offset on the device, then zeros), each word the digest
/// read big-endian and stored in the block's byte order. `None` when the
/// block has no trailer.
async fn label_checksum(cx: &Cx, data: &[u8], offset: u64) -> Option<bool> {
    let tail = data.len().checked_sub(40)?;
    let le = if u64_le(data, tail) == Some(ECK_MAGIC) {
        true
    } else if u64_be(data, tail) == Some(ECK_MAGIC) {
        false
    } else {
        return None;
    };
    let mut buf = data.to_vec();
    let verifier = buf.get_mut(tail.saturating_add(8)..)?;
    verifier.fill(0);
    verifier.get_mut(..8)?.copy_from_slice(&if le {
        offset.to_le_bytes()
    } else {
        offset.to_be_bytes()
    });
    let digest =
        crate::formats::util::datakit::digest_paced::<crate::codec::crypto::Sha256>(cx, &buf).await;
    Some((0..4).all(|i: usize| {
        let at = i.saturating_mul(8);
        let want = digest
            .get(at..at.saturating_add(8))
            .and_then(|w| <[u8; 8]>::try_from(w).ok())
            .map(u64::from_be_bytes);
        let stored = tail.saturating_add(8).saturating_add(at);
        let got = if le {
            u64_le(data, stored)
        } else {
            u64_be(data, stored)
        };
        want.is_some() && want == got
    }))
}

/// Adds a label block's checksum status to its node's summary.
async fn checked(cx: &Cx, node: Node, data: &[u8], offset: u64, summary: String) -> Node {
    match label_checksum(cx, data, offset).await {
        Some(true) => node.summary(format!("{summary}, checksum valid")),
        Some(false) => node
            .summary(format!("{summary}, checksum INVALID"))
            .diag(Diagnostic::warning("label checksum (SHA-256) mismatch")),
        None => node.summary(summary),
    }
}

/// An uberblock ring; `base` is its offset on the device.
async fn uberblocks(cx: Cx, (ring, slot, base): (Span, u64, u64)) -> Result<()> {
    let slot = slot.max(1024);
    let size = Uberblock::SIZE
        .saturating_add(BP_SIZE)
        .saturating_add(UberblockTail::SIZE);
    let mut best: Option<u64> = None;
    for i in 0..ring.len.checked_div(slot).unwrap_or(0) {
        let span = ring.sub(i.saturating_mul(slot), size);
        let raw = cx.read_avail(span.sub(0, 24)).await?;
        let endian = if u64_le(&raw, 0) == Some(UB_MAGIC) {
            Endian::Little
        } else if u64_be(&raw, 0) == Some(UB_MAGIC) {
            Endian::Big
        } else {
            cx.checkpoint().await;
            continue;
        };
        let ub = parse(
            &cx,
            span.sub(0, Uberblock::SIZE),
            endian,
            &(),
            Uberblock::layout,
        )
        .await?;
        best = Some(best.map_or(ub.txg, |b| b.max(ub.txg)));
        let slot_span = ring.sub(i.saturating_mul(slot), slot);
        let node = struct_node(format!("Slot {i}"), slot_span, endian, endian, ub_layout);
        let data = cx.read_avail(slot_span).await?;
        let offset = base.saturating_add(i.saturating_mul(slot));
        let node = checked(&cx, node, &data, offset, format!("txg {}", ub.txg)).await;
        cx.push(node).await;
    }
    if let Some(txg) = best {
        cx.annotate(format!("newest txg {txg}"));
    }
    Ok(())
}
