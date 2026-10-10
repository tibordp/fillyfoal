//! VirtualBox Disk Images (VDI).
//!
//! A text banner, a signature and a header (version 1.1) locate the block
//! map and the data area. Block map entries index allocated blocks; the
//! virtual disk is assembled from them, unallocated and zero blocks as
//! holes.

use std::sync::Arc;

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::disk::{PieceList, size};
use crate::formats::{Format, Head, Input, Probe, dissect_or_data};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const LE: Endian = Endian::Little;
const SIGNATURE: u32 = 0xbeda_107f;
const FREE: u32 = u32::MAX;
const ZERO: u32 = u32::MAX - 1;

pub static FORMAT: Format = Format {
    name: "vdi",
    title: "VirtualBox disk image",
    extensions: &["vdi"],
    mime: "application/x-virtualbox-vdi",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    u32_le(h.data, 64) == Some(SIGNATURE)
}

const TYPES: EnumTable = &[
    (1, "dynamic"),
    (2, "fixed"),
    (3, "undo"),
    (4, "differencing"),
];

record! {
    pub struct Header {
        banner: ascii[64] "Banner",
        signature: u32 "Signature" .hex(),
        version: u32 "Version" .hex() .with(|&v, n| n.summary(format!("{}.{}", v >> 16, v & 0xffff))),
        header_size: u32 "Header size",
        image_type: u32 "Image type" .enumeration(TYPES),
        flags: u32 "Flags" .hex(),
        description: ascii[256] "Description",
        blocks_offset: u32 "Block map offset" .hex(),
        data_offset: u32 "Data offset" .hex(),
        cylinders: u32 "Cylinders",
        heads: u32 "Heads",
        sectors: u32 "Sectors per track",
        sector_size: u32 "Sector size",
        _unused: u32 "Unused",
        disk_size: u64 "Disk size" .with(|&v, n| n.summary(size(v))),
        block_size: u32 "Block size" .with(|&v, n| n.summary(size(v.into()))),
        block_extra: u32 "Block extra data",
        blocks: u32 "Blocks",
        allocated: u32 "Allocated blocks",
        uuid: guid "Image UUID",
        modified_uuid: guid "Last modification UUID",
        parent_uuid: guid "Parent UUID",
        parent_modified_uuid: guid "Parent modification UUID",
    }
}

struct Image {
    input: Input,
    map: Span,
    data: u64,
    block: u64,
    extra: u64,
    size: u64,
}

impl Image {
    fn block_span(&self, index: u32) -> Span {
        let stride = self.block.saturating_add(self.extra);
        self.input.span.sub(
            self.data
                .saturating_add(u64::from(index).saturating_mul(stride))
                .saturating_add(self.extra),
            self.block,
        )
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let span = file.sub(0, Header::SIZE);
    let h = parse(&cx, span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", span, LE));
    let kind = crate::value::lookup(TYPES, h.image_type.into()).unwrap_or("unknown");
    cx.annotate(format!(
        "VirtualBox {kind} disk image, {}, {} of {} blocks allocated",
        size(h.disk_size),
        h.allocated,
        h.blocks
    ));
    let block = u64::from(h.block_size);
    if block == 0 {
        return Err(Diagnostic::malformed("zero block size").at(span));
    }
    let image = Arc::new(Image {
        input,
        map: file.sub_exact(
            h.blocks_offset.into(),
            u64::from(h.blocks).saturating_mul(4),
        )?,
        data: h.data_offset.into(),
        block,
        extra: h.block_extra.into(),
        size: h.disk_size,
    });
    cx.emit(
        Node::new("Block map")
            .span(image.map)
            .summary(format!("{} entries", h.blocks))
            .lazy(block_map, image.clone()),
    );
    cx.emit(if h.image_type == 4 {
        Node::new("Virtual disk").diag(Diagnostic::unsupported(
            "differencing image: unallocated blocks come from the parent",
        ))
    } else {
        Node::new("Virtual disk")
            .summary(size(h.disk_size))
            .lazy(virtual_disk, image)
    });
    Ok(())
}

async fn block_map(cx: Cx, image: Arc<Image>) -> Result<()> {
    let count = image.map.len / 4;
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let span = image.map.sub(i.saturating_mul(4), 4);
        let entry = u32_le(&cx.read(span).await?, 0).unwrap_or(FREE);
        let mut node = Node::new(format!("Block {i}")).span(span);
        node = match entry {
            FREE => node.value(Value::Text("not allocated".to_owned())),
            ZERO => node.value(Value::Text("zero".to_owned())),
            n => node
                .value(Value::UInt {
                    value: n.into(),
                    bits: 32,
                    radix: crate::value::Radix::Dec,
                })
                .target(image.block_span(n)),
        };
        cx.push(node).await;
    }
    Ok(())
}

async fn virtual_disk(cx: Cx, image: Arc<Image>) -> Result<()> {
    let map = cx.read(image.map).await?;
    let mut list = PieceList::new(image.map);
    for (i, raw) in map.as_chunks::<4>().0.iter().enumerate() {
        let want = image.block.min(image.size.saturating_sub(list.len()));
        if want == 0 {
            break;
        }
        if i.is_multiple_of(4096) {
            cx.progress(list.len(), image.size);
            cx.checkpoint().await;
        }
        let step = match u32::from_le_bytes(*raw) {
            FREE | ZERO => list.hole(&cx, want),
            n => {
                list.data(image.block_span(n).sub(0, want));
                Ok(())
            }
        };
        if let Err(e) = step {
            cx.diag(e);
            break;
        }
    }
    let span = list.finish(&cx, "vdi-blocks").await?;
    dissect_or_data(cx, image.input.nested(span)).await
}
