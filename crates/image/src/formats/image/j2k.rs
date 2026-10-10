//! JPEG 2000 codestreams (J2K, J2C): the raw stream without the JP2 box
//! container.
//!
//! Marker segments: SOC, a main header (SIZ first, then COD, QCD, COM, ...),
//! tile-parts (SOT, tile-part header, SOD, data of the length given in SOT)
//! and EOC. The top level lists main-header segments and tile-parts.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, struct_node};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

use super::{dims, text};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "j2k",
    title: "JPEG 2000 codestream",
    extensions: &["j2k", "j2c", "jpc", "jhc"],
    mime: "image/x-jp2-codestream",
    probe: Probe::Magic(&[(0, b"\xff\x4f\xff\x51")]),
    dissect: crate::expander!(dissect: Input),
};

const MARKERS: EnumTable = &[
    (0xff4f, "SOC"),
    (0xff51, "SIZ"),
    (0xff52, "COD"),
    (0xff53, "COC"),
    (0xff55, "TLM"),
    (0xff57, "PLM"),
    (0xff58, "PLT"),
    (0xff59, "CPF"),
    (0xff5c, "QCD"),
    (0xff5d, "QCC"),
    (0xff5e, "RGN"),
    (0xff5f, "POC"),
    (0xff60, "PPM"),
    (0xff61, "PPT"),
    (0xff63, "CRG"),
    (0xff64, "COM"),
    (0xff74, "MCT"),
    (0xff75, "MCC"),
    (0xff77, "MCO"),
    (0xff78, "CBD"),
    (0xff90, "SOT"),
    (0xff91, "SOP"),
    (0xff92, "EPH"),
    (0xff93, "SOD"),
    (0xffd9, "EOC"),
];

const PROGRESSION: EnumTable = &[
    (0, "LRCP"),
    (1, "RLCP"),
    (2, "RPCL"),
    (3, "PCRL"),
    (4, "CPRL"),
];

const TRANSFORM: EnumTable = &[(0, "9-7 irreversible"), (1, "5-3 reversible")];

const CODING_STYLE: FlagTable = &[
    flag(0x01, "PRECINCTS"),
    flag(0x02, "SOP_MARKERS"),
    flag(0x04, "EPH_MARKERS"),
];

const QUANTIZATION: EnumTable = &[
    (0, "No quantization"),
    (1, "Scalar derived"),
    (2, "Scalar expounded"),
];

fn marker_name(m: u16) -> String {
    lookup(MARKERS, m.into()).map_or_else(|| format!("Marker {m:#06x}"), str::to_owned)
}

/// Markers without a length field.
fn standalone(m: u16) -> bool {
    matches!(m, 0xff4f | 0xff92 | 0xff93 | 0xffd9) || (0xff30..=0xff3f).contains(&m)
}

#[derive(Clone, Debug, Default)]
struct Siz {
    width: u32,
    height: u32,
    tile_width: u32,
    tile_height: u32,
    x_offset: u32,
    y_offset: u32,
    components: Vec<u8>,
}

fn siz(f: &mut Fields<'_>, _: &()) -> Result<Siz> {
    f.u16("Rsiz").hex().desc("Capabilities / profile").emit()?;
    let width = f.u32("Xsiz").desc("Reference grid width").emit()?;
    let height = f.u32("Ysiz").desc("Reference grid height").emit()?;
    let x_offset = f.u32("XOsiz").emit()?;
    let y_offset = f.u32("YOsiz").emit()?;
    let tile_width = f.u32("XTsiz").desc("Tile width").emit()?;
    let tile_height = f.u32("YTsiz").desc("Tile height").emit()?;
    f.u32("XTOsiz").emit()?;
    f.u32("YTOsiz").emit()?;
    let count = f.u16("Csiz").desc("Components").emit()?;
    let mut components = Vec::new();
    for _ in 0..count {
        if f.remaining() < 3 {
            break;
        }
        let s = f
            .u8("Ssiz")
            .hex()
            .with(|&s, n| {
                n.summary(format!(
                    "{}-bit {}",
                    (s & 0x7f).saturating_add(1),
                    if s & 0x80 != 0 { "signed" } else { "unsigned" }
                ))
            })
            .emit()?;
        f.u8("XRsiz").desc("Horizontal subsampling").emit()?;
        f.u8("YRsiz").desc("Vertical subsampling").emit()?;
        components.push((s & 0x7f).saturating_add(1));
    }
    Ok(Siz {
        width,
        height,
        tile_width,
        tile_height,
        x_offset,
        y_offset,
        components,
    })
}

fn cod(f: &mut Fields<'_>, _: &()) -> Result<u8> {
    f.u8("Scod").flags(CODING_STYLE).emit()?;
    f.u8("Progression order").enumeration(PROGRESSION).emit()?;
    f.u16("Layers").emit()?;
    f.u8("Multiple component transform").emit()?;
    f.u8("Decomposition levels").emit()?;
    f.u8("Code-block width")
        .with(|&v, n| {
            n.summary(format!(
                "{}",
                1u32.checked_shl(u32::from(v).saturating_add(2))
                    .unwrap_or(0)
            ))
        })
        .emit()?;
    f.u8("Code-block height")
        .with(|&v, n| {
            n.summary(format!(
                "{}",
                1u32.checked_shl(u32::from(v).saturating_add(2))
                    .unwrap_or(0)
            ))
        })
        .emit()?;
    f.u8("Code-block style").hex().emit()?;
    let transform = f.u8("Wavelet transform").enumeration(TRANSFORM).emit()?;
    if f.remaining() > 0 {
        let n = f.remaining();
        f.bytes("Precinct sizes", n).emit()?;
    }
    Ok(transform)
}

fn qcd(f: &mut Fields<'_>, _: &()) -> Result<()> {
    f.u8("Sqcd")
        .hex()
        .with(|&s, n| {
            let style = lookup(QUANTIZATION, (s & 0x1f).into()).unwrap_or("reserved");
            n.summary(format!("{style}, {} guard bits", s >> 5))
        })
        .emit()?;
    let n = f.remaining();
    f.bytes("Step sizes", n).emit()?;
    Ok(())
}

fn sot(f: &mut Fields<'_>, _: &()) -> Result<(u16, u32, u8)> {
    let tile = f.u16("Isot").desc("Tile index").emit()?;
    let len = f
        .u32("Psot")
        .desc("Tile-part length from SOT (0: to the end of the codestream)")
        .emit()?;
    let part = f.u8("TPsot").desc("Tile-part index").emit()?;
    f.u8("TNsot")
        .desc("Number of tile-parts (0: unknown)")
        .emit()?;
    Ok((tile, len, part))
}

/// One segment at the cursor: marker and the span of its payload.
async fn next(cur: &mut Cursor<'_>) -> Result<(u16, Span, Span)> {
    let start = cur.pos();
    let marker = cur.u16().await?;
    if marker >> 8 != 0xff {
        return Err(
            Diagnostic::malformed(format!("expected a marker, found {marker:#06x}"))
                .at(cur.since(start)),
        );
    }
    if standalone(marker) {
        return Ok((marker, cur.since(start), cur.span(0)));
    }
    let len = u64::from(cur.u16().await?);
    let payload = cur.span(len.saturating_sub(2));
    cur.skip(len.saturating_sub(2));
    Ok((marker, cur.since(start), payload))
}

fn segment_node(marker: u16, span: Span, payload: Span) -> Node {
    let node = Node::new(marker_name(marker)).span(span);
    match marker {
        0xff51 => struct_node("SIZ", span, BE, (), |f, _| {
            f.u16("Marker").hex().emit()?;
            f.u16("Lsiz").emit()?;
            siz(f, &()).map(drop)
        }),
        _ if standalone(marker) => node,
        _ => node.lazy(segment, (marker, span, payload)),
    }
}

async fn segment(cx: Cx, (marker, span, payload): (u16, Span, Span)) -> Result<()> {
    let head = cx.block(span.sub(0, 4)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.u16("Marker")
        .hex()
        .with(|&m, n| n.summary(marker_name(m)))
        .emit()?;
    f.u16("Length").emit()?;
    match marker {
        0xff52 => cx.emit(struct_node("Coding style", payload, BE, (), cod)),
        0xff5c => cx.emit(struct_node("Quantization", payload, BE, (), qcd)),
        0xff90 => cx.emit(struct_node("Tile-part header", payload, BE, (), sot)),
        0xff64 => {
            let data = cx.read(payload).await?;
            let kind = u16_be(&data, 0).unwrap_or(0);
            let body = data.get(2..).unwrap_or_default();
            cx.emit(
                Node::new("Comment")
                    .span(payload.tail(2))
                    .value(if kind == 1 {
                        text(crate::text::latin1(body))
                    } else {
                        crate::value::Value::Bytes(
                            body.get(..body.len().min(64)).unwrap_or_default().to_vec(),
                        )
                    })
                    .summary(if kind == 1 { "Latin-1" } else { "binary" }),
            );
        }
        _ => cx.emit(Node::new("Data").span(payload)),
    }
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut cur = Cursor::new(&cx, file, BE);
    let mut tile_parts = 0u64;
    let mut summary_done = false;
    while !cur.at_end() {
        let start = cur.pos();
        let (marker, span, payload) = next(&mut cur).await?;
        if marker == 0xff51 && !summary_done {
            summary_done = true;
            let block = cx.block(payload).await?;
            if let Ok(s) = siz(&mut Fields::new(&block, BE), &()) {
                let w = s.width.saturating_sub(s.x_offset);
                let h = s.height.saturating_sub(s.y_offset);
                let tiles_x = w.div_ceil(s.tile_width.max(1));
                let tiles_y = h.div_ceil(s.tile_height.max(1));
                let depth = s.components.first().copied().unwrap_or(0);
                let summary = format!(
                    "{}, {} components, {depth}-bit, {} tiles",
                    dims(w, h),
                    s.components.len(),
                    tiles_x.saturating_mul(tiles_y)
                );
                cx.annotate(summary.clone());
                cx.push(segment_node(marker, span, payload).summary(summary))
                    .await;
                continue;
            }
        }
        if marker == 0xff90 {
            let head = cx.read(payload.sub(0, 6)).await?;
            let tile = u16_be(&head, 0).unwrap_or(0);
            let len = u64::from(u32_be(&head, 2).unwrap_or(0));
            let part = head.get(6).copied().unwrap_or(0);
            let end = if len == 0 {
                file.len.saturating_sub(2).max(cur.pos())
            } else {
                start.saturating_add(len)
            };
            let span = file.sub(start, end.saturating_sub(start));
            cx.push(
                Node::new(format!("Tile-part {tile_parts}"))
                    .span(span)
                    .summary(format!("tile {tile}, part {part}, {:#x} bytes", span.len))
                    .lazy(tile_part, span),
            )
            .await;
            tile_parts = tile_parts.saturating_add(1);
            if end <= start {
                break;
            }
            cur.seek(end);
            continue;
        }
        cx.push(segment_node(marker, span, payload)).await;
        if marker == 0xffd9 {
            break;
        }
    }
    if !cur.at_end() {
        cx.push(Node::new("Trailing data").span(file.tail(cur.pos())))
            .await;
    }
    Ok(())
}

async fn tile_part(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while !cur.at_end() {
        let (marker, seg, payload) = next(&mut cur).await?;
        cx.push(segment_node(marker, seg, payload)).await;
        if marker == 0xff93 {
            let data = span.tail(cur.pos());
            cx.push(
                Node::new("Tile data")
                    .span(data)
                    .summary(format!("{:#x} bytes", data.len)),
            )
            .await;
            break;
        }
    }
    Ok(())
}
