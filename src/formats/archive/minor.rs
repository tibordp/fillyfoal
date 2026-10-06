//! Less common archivers and installers: ALZip, EGG, KGB and InstallShield
//! (cabinets and `.z` archives).

use crate::bytes::{u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Archives and installers: ALZip, EGG, KGB, InstallShield

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

declare_format!(pub ISCAB = "installshield-cab", "InstallShield cabinet", ["cab", "hdr"], "application/x-installshield-cab",
    Probe::Magic(&[(0, b"ISc(")]), iscab);

async fn iscab(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 20)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.u32("Volume info").hex().emit()?;
    let descriptor = f.u32("Cabinet descriptor offset").hex().emit()?;
    f.u32("Cabinet descriptor size").emit()?;
    cx.emit(Node::new("Cabinet descriptor").span(file.tail(descriptor.into())));
    let major = match version >> 24 {
        1 => (version >> 12) & 0xf,
        2 | 4 => version & 0xffff,
        _ => 0,
    };
    cx.annotate(format!("InstallShield cabinet, version {major}"));
    Ok(())
}

declare_format!(pub ISZ = "installshield-z", "InstallShield 3 archive (.Z)", ["z"], "application/x-installshield-z",
    Probe::Magic(&[(0, b"\x13\x5d\x65\x8c")]), isz);

async fn isz(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 0x29)).await?;
    let files = u16_le(&head, 0x0c).unwrap_or(0);
    let total = u32_le(&head, 0x12).unwrap_or(0);
    let dirs = u16_le(&head, 0x31).unwrap_or(0);
    cx.emit(Node::new("Header").span(file.sub(0, 0xff)));
    cx.emit(
        Node::new("Compressed data")
            .span(file.tail(0xff))
            .diag(Diagnostic::unsupported("PKWARE DCL implode")),
    );
    cx.annotate(format!(
        "InstallShield 3 archive, {files} files, {total} bytes, {dirs} directories"
    ));
    Ok(())
}
