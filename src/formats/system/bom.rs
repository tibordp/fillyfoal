//! Apple BOM stores (bill-of-materials files, also `Assets.car`).

use crate::bytes::u32_be;
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::Result;
use crate::fields::Endian;
use crate::formats::{Input, Probe, embedded};
use crate::record;

const BE: Endian = Endian::Big;

// ---------------------------------------------------------------------------
// Apple BOM (Bill of Materials; also Assets.car)

declare_format!(pub BOMSTORE = "bom", "Apple bill of materials (BOMStore)", ["bom", "car"], "application/x-bom",
    Probe::Magic(&[(0, b"BOMStore")]), bomstore);

record! {
    pub struct BomHeader {
        magic: ascii[8] "Magic",
        version: u32 "Version",
        blocks: u32 "Non-null blocks",
        index_offset: u32 "Block index offset" .hex(),
        index_length: u32 "Block index length",
        vars_offset: u32 "Variables offset" .hex(),
        vars_length: u32 "Variables length",
    }
}

async fn bomstore(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: BomHeader = read_record(&cx, file.sub(0, BomHeader::SIZE), BE).await?;
    cx.emit(BomHeader::node("Header", file.sub(0, BomHeader::SIZE), BE));
    let index = cx
        .read(file.sub(h.index_offset.into(), h.index_length.into()))
        .await?;
    let block_count = u32_be(&index, 0).unwrap_or(0);
    let vars = file.sub(h.vars_offset.into(), h.vars_length.into());
    let mut cur = Cursor::new(&cx, vars, BE);
    let count = cur.u32().await?;
    let mut names = Vec::new();
    for _ in 0..count.min(1024) {
        let start = cur.pos();
        let block = cur.u32().await?;
        let len = cur.u8().await?;
        let name = String::from_utf8_lossy(&cur.bytes(len.into()).await?).into_owned();
        names.push(name.clone());
        let at = usize::try_from(block)
            .unwrap_or(0)
            .saturating_mul(8)
            .saturating_add(4);
        let (offset, length) = (
            u32_be(&index, at).unwrap_or(0),
            u32_be(&index, at.saturating_add(4)).unwrap_or(0),
        );
        cx.push(
            embedded(name, input.nested(file.sub(offset.into(), length.into())))
                .summary(format!("block {block}, {length} bytes"))
                .target(cur.since(start)),
        )
        .await;
    }
    cx.annotate(format!(
        "BOMStore, {block_count} blocks, variables: {}",
        names.join(", ")
    ));
    Ok(())
}
