//! Windows Address Book files (`.wab`).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Windows Address Book

declare_format!(pub WAB = "wab", "Windows Address Book", ["wab"], "application/x-wab",
    Probe::Magic(&[(0, b"\x9c\xcb\xcb\x8d\x13\x75\xd2\x11\x91\x58\x00\xc0\x4f\x79\x56\xa4")]), wab);

async fn wab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x34)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.guid("Signature").emit()?;
    f.u32("Next entry ID").emit()?;
    // Index descriptors: type, maximum, offset, count.
    let mut total = 0u32;
    for name in ["Text index", "Name index"] {
        f.u32(name).hex().emit()?;
        f.u32("Maximum entries").emit()?;
        f.u32("Offset").hex().emit()?;
        total = total.saturating_add(f.u32("Entries").emit()?);
    }
    cx.emit(Node::new("Indexes and records").span(file.tail(0x34)));
    cx.annotate(format!("Windows Address Book, {total} index entries"));
    Ok(())
}
