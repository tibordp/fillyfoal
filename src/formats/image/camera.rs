//! Camera and scanning formats: Kodak Photo CD and Sigma X3F.

use crate::bytes::u32_le;
use crate::cx::Cx;
use crate::declare_format;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::{Head, Input, Probe};
use crate::node::Node;

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Cameras: Kodak Photo CD, Sigma X3F

fn photocd_probe(h: &Head<'_>) -> bool {
    h.at(0x800, b"PCD_IPI")
}

declare_format!(pub PHOTO_CD = "photo-cd", "Kodak Photo CD image pack", ["pcd"], "image/x-photo-cd",
    Probe::Custom(photocd_probe), photo_cd);

async fn photo_cd(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Image pack information").span(file.sub(0x800, 0x800)));
    cx.emit(Node::new("Base/16 image").span(file.sub(0x2000, 0x2400)));
    cx.emit(Node::new("Base/4 image").span(file.sub(0xb800, 0x9000)));
    cx.emit(Node::new("Base image").span(file.sub(0x30000, 0x24000)));
    cx.annotate("Kodak Photo CD image (Base/16 to Base resolutions)");
    Ok(())
}

declare_format!(pub X3F = "x3f", "Sigma/Foveon raw image", ["x3f"], "image/x-sigma-x3f",
    Probe::Magic(&[(0, b"FOVb")]), x3f);

async fn x3f(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 40)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.ascii("Signature", 4).emit()?;
    let version = f.u32("Version").hex().emit()?;
    f.bytes("Unique identifier", 16).emit()?;
    f.u32("Mark bits").hex().emit()?;
    let width = f.u32("Width").emit()?;
    let height = f.u32("Height").emit()?;
    let rotation = f.u32("Rotation").emit()?;
    let dir_at =
        u64::from(u32_le(&cx.read(file.sub(file.len.saturating_sub(4), 4)).await?, 0).unwrap_or(0));
    let dir = cx.read_avail(file.sub(dir_at, 12)).await?;
    if dir.starts_with(b"SECd") {
        let count = u32_le(&dir, 8).unwrap_or(0);
        for i in 0..count.min(256) {
            let at = dir_at
                .saturating_add(12)
                .saturating_add(u64::from(i).saturating_mul(12));
            let e = cx.read(file.sub(at, 12)).await?;
            let offset = u64::from(u32_le(&e, 0).unwrap_or(0));
            let len = u64::from(u32_le(&e, 4).unwrap_or(0));
            let kind = String::from_utf8_lossy(e.get(8..12).unwrap_or_default()).into_owned();
            cx.push(
                Node::new(kind)
                    .span(file.sub(offset, len))
                    .summary(format!("{len} bytes"))
                    .target(file.sub(at, 12)),
            )
            .await;
        }
    }
    cx.annotate(format!(
        "Sigma X3F v{}.{}, {width}×{height}, rotation {rotation}",
        version >> 16,
        version & 0xffff
    ));
    Ok(())
}
