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
use crate::fields::{Endian, parse};
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
    let vdev = match list.get("vdev_tree") {
        Some(Nv::List(v)) => v.text("type").unwrap_or_default(),
        _ => String::new(),
    };
    cx.annotate(format!(
        "ZFS pool \"{name}\" ({state}), {vdev} vdev, pool version {}, txg {}",
        list.text("version").unwrap_or_default(),
        list.text("txg").unwrap_or_default()
    ));
    cx.emit(
        Node::new("Configuration (label 0)")
            .span(nv_span)
            .summary(format!("{} pairs", list.pairs.len()))
            .lazy(crate::expander!(self::nvlist: Arc<NvList>), Arc::new(list)),
    );
    let ring = dev.sub(UBERBLOCKS, UBERBLOCKS);
    cx.emit(
        Node::new("Uberblocks (label 0)")
            .span(ring)
            .lazy(uberblocks, ring),
    );
    for (i, at) in [
        Some(LABEL),
        dev.len.checked_sub(2 * LABEL),
        dev.len.checked_sub(LABEL),
    ]
    .into_iter()
    .enumerate()
    {
        if let Some(at) = at.filter(|&a| a >= LABEL && dev.len >= a.saturating_add(LABEL)) {
            cx.emit(Node::new(format!("Label {}", i.saturating_add(1))).span(dev.sub(at, LABEL)));
        }
    }
    Ok(())
}

async fn nvlist(cx: Cx, list: Arc<NvList>) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(list.pairs.len())));
    for (name, value, span) in &list.pairs {
        let node = Node::new(name.clone()).span(*span);
        let node = match value {
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
    pub struct Uberblock {
        magic: u64 "Magic" .hex(),
        version: u64 "SPA version",
        txg: u64 "Transaction group",
        guid_sum: u64 "GUID sum" .hex(),
        timestamp: u64 "Written" .timestamp(),
        _rootbp: bytes[128] "Root block pointer",
        software_version: u64 "Software version",
    }
}

async fn uberblocks(cx: Cx, ring: Span) -> Result<()> {
    const SLOT: u64 = 1024;
    let mut best: Option<u64> = None;
    for i in 0..ring.len / SLOT {
        let span = ring.sub(i.saturating_mul(SLOT), Uberblock::SIZE);
        let raw = cx.read_avail(span.sub(0, 24)).await?;
        let endian = if u64_le(&raw, 0) == Some(UB_MAGIC) {
            Endian::Little
        } else if u64_be(&raw, 0) == Some(UB_MAGIC) {
            Endian::Big
        } else {
            cx.checkpoint().await;
            continue;
        };
        let ub = parse(&cx, span, endian, &(), Uberblock::layout).await?;
        best = Some(best.map_or(ub.txg, |b| b.max(ub.txg)));
        cx.push(
            Uberblock::node(
                format!("Slot {i}"),
                ring.sub(i.saturating_mul(SLOT), SLOT),
                endian,
            )
            .summary(format!("txg {}", ub.txg)),
        )
        .await;
    }
    if let Some(txg) = best {
        cx.annotate(format!("newest txg {txg}"));
    }
    Ok(())
}
