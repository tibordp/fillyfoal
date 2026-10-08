//! macOS Finder `.DS_Store` files (`Bud1`).
//!
//! The file is a buddy allocator: a header points at the allocator's root
//! block, which lists block addresses and a directory of named entries
//! (`DSDB`). The `DSDB` block describes a B-tree whose records are
//! `(file name, property code, typed value)`, e.g. icon positions (`Iloc`),
//! view settings (`bwsp`, `icvp`), comments (`cmmt`).

use std::sync::Arc;

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::util::datakit::{clip, fourcc};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;
const MAX_DEPTH: usize = 32;
const MAX_BLOCKS: u32 = 1 << 20;

pub static FORMAT: Format = Format {
    name: "ds_store",
    title: "macOS Finder .DS_Store",
    extensions: &["ds_store"],
    mime: "application/octet-stream",
    probe: Probe::Magic(&[(0, b"\x00\x00\x00\x01Bud1")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Header {
        alignment: u32 "Alignment" .hex(),
        magic: ascii[4] "Magic",
        root: u32 "Root block offset" .hex(),
        size: u32 "Root block size" .hex(),
        root_copy: u32 "Root block offset (copy)" .hex(),
        _unknown: bytes[16] "Unknown",
    }
}

const PROPERTIES: EnumTable = &[
    (0x426b_6764, "BKGD background"),
    (0x4943_5650, "ICVO icon view options"),
    (0x496c_6f63, "Iloc icon location"),
    (0x4c53_5650, "LSVO list view options"),
    (0x6277_7370, "bwsp browser window settings"),
    (0x636d_6d74, "cmmt comment"),
    (0x6463_6c73, "dscl disclosed in list view"),
    (0x6673_7774, "fwsw sidebar width"),
    (0x6677_6933, "fwi0 window info"),
    (0x6677_7669, "fwvh window height"),
    (0x6963_6770, "icgo"),
    (0x6963_7370, "icsp"),
    (0x6963_7670, "icvp icon view properties"),
    (0x6c67_3153, "lg1S logical size"),
    (0x6c73_7670, "lsvp list view properties"),
    (0x6c73_7650, "lsvP list view properties"),
    (0x6c73_7674, "lsvt list view text size"),
    (0x6d6f_6444, "modD modification date"),
    (0x6d6f_4444, "moDD modification date"),
    (0x7068_3153, "ph1S physical size"),
    (0x7074_6250, "ptbL trash put-back location"),
    (0x7074_624e, "ptbN trash put-back name"),
    (0x7653_726e, "vSrn"),
    (0x7673_7472, "vstl view style"),
    (0x6578_7465, "extn extension"),
];

struct Store {
    input: Input,
    /// Block addresses from the allocator.
    blocks: Vec<u32>,
}

type St = Arc<Store>;

impl Store {
    /// The data of block `id` (offsets are relative to byte 4).
    fn block(&self, id: u32) -> Result<Span> {
        let addr = *self
            .blocks
            .get(crate::bytes::to_usize(id.into()))
            .ok_or_else(|| Diagnostic::malformed(format!("block {id} does not exist")))?;
        let offset = u64::from(addr & !0x1f);
        let size = 1u64.checked_shl(addr & 0x1f).unwrap_or(0);
        Ok(self.input.span.sub(offset.saturating_add(4), size))
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let hspan = file.sub(0, Header::SIZE);
    let h = parse(&cx, hspan, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", hspan, BE));
    let root = file.sub(u64::from(h.root).saturating_add(4), h.size.into());
    let data = cx.read(root).await?;
    let count = u32_be(&data, 0).unwrap_or(0).min(MAX_BLOCKS);
    let mut blocks = Vec::new();
    for i in 0..crate::bytes::to_usize(count.into()) {
        if i.is_multiple_of(4096) {
            cx.checkpoint().await;
        }
        match u32_be(&data, 8usize.saturating_add(i.saturating_mul(4))) {
            Some(a) => blocks.push(a),
            None => break,
        }
    }
    // Addresses are padded to a multiple of 256 entries.
    let slots = to_u64(blocks.len())
        .checked_next_multiple_of(256)
        .unwrap_or(u64::MAX);
    let mut at = crate::bytes::to_usize(8u64.saturating_add(slots.saturating_mul(4)));
    let dir_count = u32_be(&data, at).unwrap_or(0);
    at = at.saturating_add(4);
    let mut directory = Vec::new();
    for _ in 0..dir_count.min(1024) {
        let Some(&len) = data.get(at) else { break };
        let name_end = at.saturating_add(1).saturating_add(usize::from(len));
        let name =
            String::from_utf8_lossy(data.get(at.saturating_add(1)..name_end).unwrap_or_default())
                .into_owned();
        let Some(id) = u32_be(&data, name_end) else {
            break;
        };
        directory.push((
            name,
            id,
            root.sub(to_u64(at), to_u64(usize::from(len).saturating_add(5))),
        ));
        at = name_end.saturating_add(4);
    }
    let store: St = Arc::new(Store { input, blocks });
    cx.emit(
        Node::new("Allocator")
            .span(root)
            .summary(format!(
                "{} blocks, {} directory entries",
                store.blocks.len(),
                directory.len()
            ))
            .lazy(allocator, store.clone()),
    );
    let mut summary = String::from(".DS_Store");
    for (name, id, span) in directory {
        let node = Node::new(format!("Directory entry {name:?}"))
            .span(span)
            .value(Value::UInt {
                value: id.into(),
                bits: 32,
                radix: crate::value::Radix::Dec,
            });
        if name != "DSDB" {
            cx.emit(node);
            continue;
        }
        cx.emit(node);
        let master = store.block(id)?;
        let m = cx.read(master.sub_exact(0, 20)?).await?;
        let root_node = u32_be(&m, 0).unwrap_or(0);
        let records = u32_be(&m, 8).unwrap_or(0);
        summary = format!("{summary}, {records} records");
        cx.emit(
            Node::new("DSDB")
                .span(master.sub(0, 20))
                .summary(format!(
                    "B-tree: {} levels, {records} records, {} nodes, page size {:#x}",
                    u32_be(&m, 4).unwrap_or(0),
                    u32_be(&m, 12).unwrap_or(0),
                    u32_be(&m, 16).unwrap_or(0)
                ))
                .lazy(
                    crate::expander!(self::tree_node: (St, u32, Vec<u32>)),
                    (store.clone(), root_node, Vec::new()),
                ),
        );
    }
    cx.annotate(summary);
    Ok(())
}

async fn allocator(cx: Cx, store: St) -> Result<()> {
    cx.set_count(Count::Exact(to_u64(store.blocks.len())));
    for (i, &addr) in store.blocks.iter().enumerate() {
        let id = u32::try_from(i).unwrap_or(u32::MAX);
        let mut node =
            Node::new(format!("Block {i}")).value(crate::formats::util::datakit::hex(addr, 32));
        if addr != 0
            && let Ok(span) = store.block(id)
        {
            node = node
                .summary(format!("{:#x} bytes at {:#x}", span.len, span.offset))
                .target(span);
        }
        cx.push(node).await;
    }
    Ok(())
}

/// One B-tree node: records (and, in internal nodes, child nodes).
async fn tree_node(cx: Cx, (store, id, path): (St, u32, Vec<u32>)) -> Result<()> {
    if path.contains(&id) {
        return Err(Diagnostic::malformed(format!(
            "node {id} is its own ancestor"
        )));
    }
    if path.len() >= MAX_DEPTH {
        return Err(Diagnostic::limit("B-tree deeper than 32 levels"));
    }
    let span = store.block(id)?;
    let head = cx.read(span.sub_exact(0, 8)?).await?;
    let rightmost = u32_be(&head, 0).unwrap_or(0);
    let count = u32_be(&head, 4).unwrap_or(0);
    let mut child_path = path.clone();
    child_path.push(id);
    let child = |cid: u32| {
        Node::new(format!("Node {cid}")).lazy(
            crate::expander!(self::tree_node: (St, u32, Vec<u32>)),
            (store.clone(), cid, child_path.clone()),
        )
    };
    let mut at = 8u64;
    for _ in 0..count {
        if rightmost != 0 {
            let c = cx.read(span.sub_exact(at, 4)?).await?;
            cx.push(child(u32_be(&c, 0).unwrap_or(0))).await;
            at = at.saturating_add(4);
        }
        let (node, len) = record(&cx, &store, span, at).await?;
        cx.push(node).await;
        at = at.saturating_add(len);
    }
    if rightmost != 0 {
        cx.push(child(rightmost)).await;
    }
    Ok(())
}

/// Decodes the record at `at` within `span`; returns its node and length.
async fn record(cx: &Cx, store: &Store, span: Span, at: u64) -> Result<(Node, u64)> {
    let n = cx.read(span.sub_exact(at, 4)?).await?;
    let chars = u64::from(u32_be(&n, 0).unwrap_or(0));
    let name_bytes = cx
        .read(span.sub_exact(at.saturating_add(4), chars.saturating_mul(2))?)
        .await?;
    let name = crate::text::utf16(&name_bytes, BE);
    let mut pos = at.saturating_add(4).saturating_add(chars.saturating_mul(2));
    let codes = cx.read(span.sub_exact(pos, 8)?).await?;
    let property = u32_be(&codes, 0).unwrap_or(0);
    let kind = codes.get(4..8).unwrap_or_default().to_vec();
    pos = pos.saturating_add(8);
    let (value, len): (Value, u64) = match kind.as_slice() {
        b"long" | b"shor" => {
            let v = cx.read(span.sub_exact(pos, 4)?).await?;
            (
                Value::Int {
                    value: i64::from(u32_be(&v, 0).unwrap_or(0) as i32),
                    bits: 32,
                },
                4,
            )
        }
        b"bool" => {
            let v = cx.read(span.sub_exact(pos, 1)?).await?;
            (Value::Bool(v.first() == Some(&1)), 1)
        }
        b"type" => {
            let v = cx.read(span.sub_exact(pos, 4)?).await?;
            (Value::Text(fourcc(&v)), 4)
        }
        b"comp" => {
            let v = cx.read(span.sub_exact(pos, 8)?).await?;
            (
                Value::UInt {
                    value: u64_be(&v, 0).unwrap_or(0),
                    bits: 64,
                    radix: crate::value::Radix::Dec,
                },
                8,
            )
        }
        b"dutc" => {
            let v = cx.read(span.sub_exact(pos, 8)?).await?;
            let ticks = u64_be(&v, 0).unwrap_or(0);
            (
                Value::Timestamp {
                    unix_seconds: crate::text::mac_to_unix(ticks >> 16),
                },
                8,
            )
        }
        b"ustr" => {
            let l = cx.read(span.sub_exact(pos, 4)?).await?;
            let chars = u64::from(u32_be(&l, 0).unwrap_or(0));
            let text = cx
                .read(span.sub_exact(pos.saturating_add(4), chars.saturating_mul(2))?)
                .await?;
            (
                Value::Text(crate::text::utf16(&text, BE)),
                chars.saturating_mul(2).saturating_add(4),
            )
        }
        b"blob" => {
            let l = cx.read(span.sub_exact(pos, 4)?).await?;
            let n = u64::from(u32_be(&l, 0).unwrap_or(0));
            let data = span.sub_exact(pos.saturating_add(4), n)?;
            let preview = cx.read(data.sub(0, 32)).await?;
            if preview.starts_with(b"bplist00") {
                let node = embedded(record_name(&name), store.input.nested(data))
                    .summary(format!("{}, blob", fourcc(&property.to_be_bytes())));
                return Ok((
                    node,
                    pos.saturating_add(4).saturating_add(n).saturating_sub(at),
                ));
            }
            (Value::Bytes(preview), n.saturating_add(4))
        }
        _ => {
            return Err(
                Diagnostic::unsupported(format!("value type {:?}", fourcc(&kind)))
                    .at(span.sub(pos.saturating_sub(4), 4)),
            );
        }
    };
    let total = pos.saturating_add(len).saturating_sub(at);
    let mut summary = crate::value::lookup(PROPERTIES, property.into())
        .map_or_else(|| fourcc(&property.to_be_bytes()), str::to_owned);
    if kind == b"blob" && property == 0x496c_6f63 {
        // Iloc: x, y as 32-bit integers.
        let d = cx.read(span.sub(pos.saturating_add(4), 8)).await?;
        summary = format!(
            "{summary} ({}, {})",
            u32_be(&d, 0).unwrap_or(0),
            u32_be(&d, 4).unwrap_or(0)
        );
    }
    let node = Node::new(record_name(&name))
        .span(span.sub(at, total))
        .value(value)
        .summary(format!("{summary}, {}", fourcc(&kind)));
    Ok((node, total))
}

fn record_name(name: &str) -> String {
    if name == "." {
        "(this folder)".to_owned()
    } else {
        clip(name, 200)
    }
}
