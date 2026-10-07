//! Less common archivers: ALZip, EGG and KGB. (InstallShield archives are
//! in `installer`.)

use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Archives: ALZip, EGG, KGB

declare_format!(pub ALZ = "alz", "ALZip archive", ["alz"], "application/x-alz",
    Probe::Magic(&[(0, b"ALZ\x01")]), alz);

async fn alz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Header").span(file.sub(0, 8)));
    let head = cx.read_avail(file.sub(0, 1 << 16)).await?;
    let entries = head.windows(4).filter(|w| *w == b"BLZ\x01").count();
    cx.emit(Node::new("Local file records").span(file.tail(8)));
    cx.annotate(format!("ALZip archive, {entries}+ entries"));
    Ok(())
}

declare_format!(pub EGG = "egg", "EGG archive", ["egg"], "application/x-egg",
    Probe::Magic(&[(0, b"EGGA")]), egg);

async fn egg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 14)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u16("Version").hex().emit()?;
    f.u32("Header ID").hex().emit()?;
    f.u32("Reserved").emit()?;
    cx.emit(Node::new("Blocks").span(file.tail(14)));
    cx.annotate(format!("EGG archive v{}.{}", version >> 8, version & 0xff));
    Ok(())
}

declare_format!(pub KGB = "kgb", "KGB archive", ["kgb", "kge"], "application/x-kgb",
    Probe::Magic(&[(0, b"KGB_arch")]), kgb);

async fn kgb(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Signature").span(file.sub(0, 8)));
    cx.emit(
        Node::new("Compressed data")
            .span(file.tail(8))
            .diag(Diagnostic::unsupported("PAQ6-based compression")),
    );
    cx.annotate("KGB archive");
    Ok(())
}
