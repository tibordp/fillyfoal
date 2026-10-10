//! JPEG 2000 file format boxes (JP2/JPX/MJ2, ISO 15444-1 annex I) and a
//! walk of the codestream's main header markers.

use crate::bytes::{u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::embedded;
use crate::node::Node;
use crate::span::Span;
use crate::value::EnumTable;

use super::{BE, BoxState, emit_fields, small};

const COLOUR_METHODS: EnumTable = &[
    (1, "enumerated"),
    (2, "restricted ICC"),
    (3, "any ICC"),
    (4, "vendor"),
    (5, "parameterized"),
];

const ENUM_CS: EnumTable = &[
    (0, "bi-level"),
    (1, "YCbCr(1)"),
    (3, "YCbCr(2)"),
    (4, "YCbCr(3)"),
    (9, "PhotoYCC"),
    (11, "CMY"),
    (12, "CMYK"),
    (13, "YCCK"),
    (14, "CIELab"),
    (15, "bi-level(2)"),
    (16, "sRGB"),
    (17, "greyscale"),
    (18, "sYCC"),
    (19, "CIEJab"),
    (20, "e-sRGB"),
    (21, "ROMM-RGB"),
    (22, "YPbPr(1125/60)"),
    (23, "YPbPr(1250/50)"),
    (24, "e-sYCC"),
];

const MARKERS: EnumTable = &[
    (0xff4f, "SOC"),
    (0xff51, "SIZ"),
    (0xff52, "COD"),
    (0xff53, "COC"),
    (0xff55, "TLM"),
    (0xff57, "PLM"),
    (0xff58, "PLT"),
    (0xff5c, "QCD"),
    (0xff5d, "QCC"),
    (0xff5e, "RGN"),
    (0xff5f, "POC"),
    (0xff60, "PPM"),
    (0xff61, "PPT"),
    (0xff63, "CRG"),
    (0xff64, "COM"),
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

/// Decodes JP2 boxes. Returns `false` for other types.
pub async fn decode(cx: &Cx, st: &BoxState) -> Result<bool> {
    let body = st.body();
    match &st.header.kind {
        b"jP  " => {
            emit_fields(cx, body, |f| {
                f.u32("Signature").hex().desc("0x0d0a870a").emit()?;
                Ok(())
            })
            .await?;
        }
        b"ihdr" => {
            emit_fields(cx, body, |f| {
                f.u32("Height").emit()?;
                f.u32("Width").emit()?;
                f.u16("Components").emit()?;
                f.u8("Bits per component")
                    .with(|&b, n| n.summary(bpc(b)))
                    .emit()?;
                f.u8("Compression type").desc("7 = JPEG 2000").emit()?;
                f.u8("Colourspace unknown").emit()?;
                f.u8("Intellectual property").emit()?;
                Ok(())
            })
            .await?;
        }
        b"colr" => {
            let head = cx.read_avail(body.sub(0, 3)).await?;
            let method = head.first().copied().unwrap_or(0);
            emit_fields(cx, body, |f| {
                f.u8("Method").enumeration(COLOUR_METHODS).emit()?;
                f.int::<i8>("Precedence").emit()?;
                f.u8("Approximation").emit()?;
                if method == 1 {
                    f.u32("Enumerated colourspace")
                        .enumeration(ENUM_CS)
                        .emit()?;
                }
                Ok(())
            })
            .await?;
            if method == 2 || method == 3 {
                cx.emit(embedded("ICC profile", st.input.nested(body.tail(3))));
            }
        }
        b"bpcc" => {
            emit_fields(cx, body, |f| {
                while f.remaining() > 0 {
                    f.u8("Bits per component")
                        .with(|&b, n| n.summary(bpc(b)))
                        .emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"pclr" => {
            emit_fields(cx, body, |f| {
                let entries = f.u16("Entries").emit()?;
                let columns = f.u8("Columns").emit()?;
                for _ in 0..columns {
                    f.u8("Bit depth").with(|&b, n| n.summary(bpc(b))).emit()?;
                }
                let rest = f.remaining();
                f.node(
                    Node::new("Palette")
                        .span(f.peek_span(rest))
                        .summary(format!("{entries} entries")),
                );
                Ok(())
            })
            .await?;
        }
        b"cmap" => {
            emit_fields(cx, body, |f| {
                while f.remaining() >= 4 {
                    f.u16("Component").emit()?;
                    f.u8("Mapping type").emit()?;
                    f.u8("Palette column").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"cdef" => {
            emit_fields(cx, body, |f| {
                let n = f.u16("Channel count").emit()?;
                for _ in 0..n {
                    f.u16("Channel").emit()?;
                    f.u16("Type")
                        .with(|&t, n| {
                            n.summary(match t {
                                0 => "colour",
                                1 => "opacity",
                                2 => "premultiplied opacity",
                                _ => "unspecified",
                            })
                        })
                        .emit()?;
                    f.u16("Association").emit()?;
                }
                Ok(())
            })
            .await?;
        }
        b"resc" | b"resd" => {
            emit_fields(cx, body, |f| {
                f.u16("Vertical numerator").emit()?;
                f.u16("Vertical denominator").emit()?;
                f.u16("Horizontal numerator").emit()?;
                f.u16("Horizontal denominator").emit()?;
                f.int::<i8>("Vertical exponent").emit()?;
                f.int::<i8>("Horizontal exponent").emit()?;
                Ok(())
            })
            .await?;
        }
        b"jp2c" => cx.emit(codestream_node(body)),
        b"xml " => cx.emit(embedded("XML", st.input.nested(body))),
        _ => return Ok(false),
    }
    Ok(true)
}

fn bpc(b: u8) -> String {
    if b == 0xff {
        "varies by component".to_owned()
    } else {
        format!(
            "{}-bit {}",
            (b & 0x7f).saturating_add(1),
            if b & 0x80 != 0 { "signed" } else { "unsigned" }
        )
    }
}

/// Summaries for the box list.
pub async fn describe(cx: &Cx, st: &BoxState) -> Option<String> {
    let kind = &st.header.kind;
    if !matches!(kind, b"ihdr" | b"colr" | b"jp2c") {
        return None;
    }
    let d = small(cx, st.body().sub(0, 64)).await.ok()?;
    match kind {
        b"ihdr" => Some(format!(
            "{}×{}, {} components, {}",
            u32_be(&d, 4)?,
            u32_be(&d, 0)?,
            u16_be(&d, 8)?,
            bpc(d.get(10).copied()?)
        )),
        b"colr" if d.first() == Some(&1) => {
            crate::value::lookup(ENUM_CS, u32_be(&d, 3)?.into()).map(str::to_owned)
        }
        b"colr" => Some("ICC profile".to_owned()),
        b"jp2c" => siz_summary(&d),
        _ => None,
    }
}

/// Image size and component count from the SIZ marker at the start of a
/// codestream.
pub fn siz_summary(d: &[u8]) -> Option<String> {
    if u16_be(d, 0)? != 0xff4f || u16_be(d, 2)? != 0xff51 {
        return None;
    }
    let width = u32_be(d, 8)?.saturating_sub(u32_be(d, 16)?);
    let height = u32_be(d, 12)?.saturating_sub(u32_be(d, 20)?);
    let components = u16_be(d, 40)?;
    Some(format!(
        "codestream {width}×{height}, {components} components"
    ))
}

/// A lazy node for a JPEG 2000 codestream (also used for raw `.j2k` data
/// inside other containers).
pub fn codestream_node(span: Span) -> Node {
    Node::new("Codestream").span(span).lazy(markers, span)
}

/// Lists codestream markers; tile-parts are skipped by their `Psot` length.
async fn markers(cx: Cx, span: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut guard = 0u32;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 12)).await?;
        let Some(marker) = u16_be(&head, 0) else {
            break;
        };
        if marker >> 8 != 0xff {
            cx.emit(Node::new("Data").span(span.tail(pos)));
            break;
        }
        let name = crate::value::lookup(MARKERS, marker.into())
            .map_or_else(|| format!("Marker {marker:#06x}"), str::to_owned);
        let len = match marker {
            0xff4f | 0xff93 | 0xffd9 | 0xff92 => 2u64,
            0xff90 => {
                // Psot covers the whole tile-part from the SOT marker.
                let psot = u32_be(&head, 6).unwrap_or(0);
                if psot == 0 {
                    span.len.saturating_sub(pos).saturating_sub(2).max(2)
                } else {
                    u64::from(psot)
                }
            }
            _ => u64::from(u16_be(&head, 2).unwrap_or(0)).saturating_add(2),
        };
        let seg = span.sub(pos, len.max(2));
        let mut node = Node::new(if marker == 0xff90 {
            "Tile-part".to_owned()
        } else {
            name
        })
        .span(seg)
        .value(crate::value::Value::Enum {
            raw: marker.into(),
            bits: 16,
            name: crate::value::lookup(MARKERS, marker.into()),
        });
        if marker == 0xff90 {
            node = node.summary(format!(
                "tile {}, part {}",
                u16_be(&head, 4).unwrap_or(0),
                head.get(10).copied().unwrap_or(0)
            ));
        }
        if matches!(marker, 0xff51 | 0xff52 | 0xff64 | 0xff90 | 0xff5c) {
            node = node.lazy(segment, (seg, marker));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len.max(2));
        if marker == 0xffd9 {
            if pos < span.len {
                cx.emit(Node::new("Trailing data").span(span.tail(pos)));
            }
            break;
        }
        guard = guard.saturating_add(1);
        if guard.is_multiple_of(64) {
            cx.checkpoint().await;
        }
    }
    Ok(())
}

async fn segment(cx: Cx, (span, marker): (Span, u16)) -> Result<()> {
    let block = cx.block(span.sub(0, 0x10000)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u16("Marker").hex().emit()?;
    match marker {
        0xff90 => {
            f.u16("Lsot").emit()?;
            f.u16("Tile index").emit()?;
            f.u32("Tile-part length").emit()?;
            f.u8("Tile-part index").emit()?;
            f.u8("Tile-parts").emit()?;
            let at = f.pos();
            cx.emit(Node::new("Tile data").span(span.tail(at)));
        }
        0xff51 => {
            f.u16("Lsiz").emit()?;
            f.u16("Capabilities").hex().emit()?;
            f.u32("Width").emit()?;
            f.u32("Height").emit()?;
            f.u32("Image X offset").emit()?;
            f.u32("Image Y offset").emit()?;
            f.u32("Tile width").emit()?;
            f.u32("Tile height").emit()?;
            f.u32("Tile X offset").emit()?;
            f.u32("Tile Y offset").emit()?;
            let n = f.u16("Components").emit()?;
            for _ in 0..n {
                if f.remaining() < 3 {
                    break;
                }
                f.u8("Component depth")
                    .with(|&b, n| n.summary(bpc(b)))
                    .emit()?;
                f.u8("Horizontal separation").emit()?;
                f.u8("Vertical separation").emit()?;
            }
        }
        0xff52 => {
            f.u16("Lcod").emit()?;
            f.u8("Coding style").hex().emit()?;
            f.u8("Progression order").enumeration(PROGRESSION).emit()?;
            f.u16("Layers").emit()?;
            f.u8("Multiple component transform").emit()?;
            f.u8("Decomposition levels").emit()?;
            f.u8("Code-block width")
                .with(|&v, n| {
                    n.summary(format!(
                        "{}",
                        1u32 << (u32::from(v & 15).saturating_add(2)).min(31)
                    ))
                })
                .emit()?;
            f.u8("Code-block height")
                .with(|&v, n| {
                    n.summary(format!(
                        "{}",
                        1u32 << (u32::from(v & 15).saturating_add(2)).min(31)
                    ))
                })
                .emit()?;
            f.u8("Code-block style").hex().emit()?;
            f.u8("Transformation")
                .with(|&v, n| {
                    n.summary(if v == 0 {
                        "9-7 irreversible"
                    } else {
                        "5-3 reversible"
                    })
                })
                .emit()?;
        }
        0xff64 => {
            f.u16("Lcom").emit()?;
            let kind = f.u16("Registration").emit()?;
            let rest = f.remaining();
            if kind == 1 {
                f.ascii("Comment", rest).emit()?;
            } else {
                f.bytes("Comment", rest).emit()?;
            }
        }
        _ => {
            f.u16("Length").emit()?;
            let rest = f.remaining();
            f.bytes("Parameters", rest).emit()?;
        }
    }
    Ok(())
}
