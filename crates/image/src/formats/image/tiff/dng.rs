//! DNG opcode lists (OpcodeList1-3): always big-endian, a count and then
//! opcodes of `id, DNG version, flags, parameter length, parameters`.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::util::arcutil::human_size;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const BE: Endian = Endian::Big;

pub fn opcodes_node(span: Span) -> Node {
    Node::new("Opcodes").span(span).lazy(opcodes, span)
}

const OPCODES: EnumTable = &[
    (1, "WarpRectilinear"),
    (2, "WarpFisheye"),
    (3, "FixVignetteRadial"),
    (4, "FixBadPixelsConstant"),
    (5, "FixBadPixelsList"),
    (6, "TrimBounds"),
    (7, "MapTable"),
    (8, "MapPolynomial"),
    (9, "GainMap"),
    (10, "DeltaPerRow"),
    (11, "DeltaPerColumn"),
    (12, "ScalePerRow"),
    (13, "ScalePerColumn"),
    (14, "WarpRectilinear2"),
];

const FLAGS: FlagTable = &[flag(1, "OPTIONAL"), flag(2, "SKIP_FOR_PREVIEW")];

/// Opcodes per list before giving up.
const MAX_OPCODES: u32 = 4096;

async fn opcodes(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 4)).await?;
    let n = Fields::emitting(&cx, &block, BE)
        .u32("Opcode count")
        .emit()?;
    let mut pos = 4u64;
    for _ in 0..n.min(MAX_OPCODES) {
        if pos >= span.len {
            break;
        }
        let head = cx.read(span.sub(pos, 16)).await?;
        let get = |at: usize| crate::bytes::u32_be(&head, at).unwrap_or(0);
        let (id, version, flags, len) = (get(0), get(4), get(8), get(12));
        let whole = span.sub(pos, 16u64.saturating_add(len.into()));
        let name = lookup(OPCODES, id.into()).map_or_else(|| format!("Opcode {id}"), str::to_owned);
        let mut summary = format!(
            "DNG {}.{}.{}.{}, {}",
            version >> 24,
            (version >> 16) & 0xff,
            (version >> 8) & 0xff,
            version & 0xff,
            human_size(len.into())
        );
        if flags & 1 != 0 {
            summary.push_str(", optional");
        }
        cx.push(
            Node::new(name)
                .span(whole)
                .summary(summary)
                .lazy(opcode, (whole, id)),
        )
        .await;
        pos = pos.saturating_add(whole.len.max(16));
    }
    Ok(())
}

/// The fields of the area most opcodes apply to.
fn area(f: &mut Fields<'_>) -> Result<()> {
    for name in [
        "Top", "Left", "Bottom", "Right", "Plane", "Planes", "RowPitch", "ColPitch",
    ] {
        f.u32(name).emit()?;
    }
    Ok(())
}

async fn opcode(cx: Cx, (span, id): (Span, u32)) -> Result<()> {
    let block = cx.block(span.sub(0, 1040)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Opcode ID").enumeration(OPCODES).emit()?;
    f.u32("DNG version").hex().emit()?;
    f.u32("Flags").flags(FLAGS).emit()?;
    let len = f.u32("Parameter bytes").emit()?;
    let params_end = 16u64.saturating_add(len.into());
    match id {
        1 => {
            let planes = f.u32("Planes").emit()?;
            for _ in 0..planes.min(16) {
                for _ in 0..6 {
                    f.f64("Coefficient").emit()?;
                }
            }
            f.f64("Optical centre X").emit()?;
            f.f64("Optical centre Y").emit()?;
        }
        3 => {
            for name in ["k0", "k1", "k2", "k3", "k4"] {
                f.f64(name).emit()?;
            }
            f.f64("Optical centre X").emit()?;
            f.f64("Optical centre Y").emit()?;
        }
        4 => {
            f.u32("Constant").emit()?;
            f.u32("Bayer phase").emit()?;
        }
        5 => {
            f.u32("Bayer phase").emit()?;
            f.u32("Bad points").emit()?;
            f.u32("Bad rectangles").emit()?;
        }
        6 => {
            for name in ["Top", "Left", "Bottom", "Right"] {
                f.u32(name).emit()?;
            }
        }
        7 => {
            area(&mut f)?;
            f.u32("Table size").emit()?;
        }
        8 => {
            area(&mut f)?;
            let degree = f.u32("Degree").emit()?;
            for _ in 0..=degree.min(8) {
                f.f64("Coefficient").emit()?;
            }
        }
        9 => {
            area(&mut f)?;
            f.u32("Map points V").emit()?;
            f.u32("Map points H").emit()?;
            f.f64("Map spacing V").emit()?;
            f.f64("Map spacing H").emit()?;
            f.f64("Map origin V").emit()?;
            f.f64("Map origin H").emit()?;
            f.u32("Map planes").emit()?;
        }
        10..=13 => {
            area(&mut f)?;
            f.u32("Count").emit()?;
        }
        _ => {}
    }
    let at = f.pos();
    if at < params_end {
        let rest = span.sub(at, params_end.saturating_sub(at));
        cx.emit(Node::new("Data").span(rest).summary(human_size(rest.len)));
    }
    Ok(())
}
