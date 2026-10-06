//! Windows application compatibility databases (`.sdb`).

use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Windows application compatibility database (SDB)

fn sdb_probe(h: &Head<'_>) -> bool {
    h.at(8, b"sdbf")
}

declare_format!(pub SDB = "shim-sdb", "Windows shim database", ["sdb"], "application/x-ms-sdb",
    Probe::Custom(sdb_probe), shim_sdb);

async fn shim_sdb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    let major = f.u32("Major version").emit()?;
    let minor = f.u32("Minor version").emit()?;
    f.ascii("Magic", 4).emit()?;
    cx.emit(Node::new("Tags").span(file.tail(12)));
    cx.annotate(format!("shim database v{major}.{minor}"));
    Ok(())
}
