//! Sony BBeB e-books (LRF).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Sony BBeB e-books

declare_format!(pub LRF = "lrf", "Sony BBeB e-book (LRF)", ["lrf", "lrx"], "application/x-sony-bbeb",
    Probe::Magic(&[(0, b"L\0R\0F\0\0\0")]), lrf);

async fn lrf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 0x58)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 8).emit()?;
    let version = f.u16("Version").emit()?;
    f.u16("Pseudo-encryption key").hex().emit()?;
    f.u32("Root object ID").emit()?;
    let objects = f.u64("Number of objects").emit()?;
    f.u64("Object index offset").hex().emit()?;
    cx.emit(Node::new("Objects").span(file.tail(0x58)));
    cx.annotate(format!("Sony BBeB e-book v{version}, {objects} objects"));
    Ok(())
}
