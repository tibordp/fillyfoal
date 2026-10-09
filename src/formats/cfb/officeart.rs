//! Office Art (Escher) records ([MS-ODRAW]): the drawing layer shared by
//! Word, Excel, PowerPoint and Publisher. Records have an 8-byte header
//! (version and instance, type, length); version 0xF marks a container.
//! PowerPoint records use the same header, so one walker serves both, and
//! PowerPoint records nested in drawings (client data, text boxes) are
//! decoded too.

use super::rec::{K, LE, enumv, hex, uint};
use crate::bytes::{i32_le, to_usize, u16_le, u32_le};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::Fields;
use crate::formats::Input;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Value, flag, lookup};

/// Container nesting followed.
const MAX_DEPTH: u32 = 32;

pub const NAMES: EnumTable = &[
    (0xf000, "OfficeArtDggContainer"),
    (0xf001, "OfficeArtBStoreContainer"),
    (0xf002, "OfficeArtDgContainer"),
    (0xf003, "OfficeArtSpgrContainer"),
    (0xf004, "OfficeArtSpContainer"),
    (0xf005, "OfficeArtSolverContainer"),
    (0xf006, "OfficeArtFDGGBlock"),
    (0xf007, "OfficeArtFBSE"),
    (0xf008, "OfficeArtFDG"),
    (0xf009, "OfficeArtFSPGR"),
    (0xf00a, "OfficeArtFSP"),
    (0xf00b, "OfficeArtFOPT"),
    (0xf00d, "OfficeArtClientTextbox"),
    (0xf00f, "OfficeArtChildAnchor"),
    (0xf010, "OfficeArtClientAnchor"),
    (0xf011, "OfficeArtClientData"),
    (0xf012, "OfficeArtFConnectorRule"),
    (0xf014, "OfficeArtFArcRule"),
    (0xf017, "OfficeArtFCalloutRule"),
    (0xf01a, "OfficeArtBlipEMF"),
    (0xf01b, "OfficeArtBlipWMF"),
    (0xf01c, "OfficeArtBlipPICT"),
    (0xf01d, "OfficeArtBlipJPEG"),
    (0xf01e, "OfficeArtBlipPNG"),
    (0xf01f, "OfficeArtBlipDIB"),
    (0xf029, "OfficeArtBlipTIFF"),
    (0xf02a, "OfficeArtBlipJPEG (CMYK)"),
    (0xf118, "OfficeArtFRITContainer"),
    (0xf119, "OfficeArtFDGSL"),
    (0xf11a, "OfficeArtColorMRUContainer"),
    (0xf11d, "OfficeArtFPSPL"),
    (0xf11e, "OfficeArtSplitMenuColorContainer"),
    (0xf121, "OfficeArtSecondaryFOPT"),
    (0xf122, "OfficeArtTertiaryFOPT"),
];

const SHAPE_TYPES: EnumTable = &[
    (0, "msosptNotPrimitive"),
    (1, "msosptRectangle"),
    (2, "msosptRoundRectangle"),
    (3, "msosptEllipse"),
    (4, "msosptDiamond"),
    (5, "msosptIsocelesTriangle"),
    (6, "msosptRightTriangle"),
    (7, "msosptParallelogram"),
    (8, "msosptTrapezoid"),
    (9, "msosptHexagon"),
    (10, "msosptOctagon"),
    (11, "msosptPlus"),
    (12, "msosptStar"),
    (13, "msosptArrow"),
    (15, "msosptHomePlate"),
    (16, "msosptCube"),
    (19, "msosptArc"),
    (20, "msosptLine"),
    (21, "msosptPlaque"),
    (22, "msosptCan"),
    (23, "msosptDonut"),
    (32, "msosptStraightConnector1"),
    (33, "msosptBentConnector2"),
    (34, "msosptBentConnector3"),
    (37, "msosptCurvedConnector3"),
    (61, "msosptWedgeRectCallout"),
    (75, "msosptPictureFrame"),
    (96, "msosptSmileyFace"),
    (136, "msosptTextPlainText"),
    (183, "msosptSun"),
    (184, "msosptMoon"),
    (185, "msosptBracketPair"),
    (186, "msosptBracePair"),
    (201, "msosptHostControl"),
    (202, "msosptTextBox"),
];

const FSP_FLAGS: FlagTable = &[
    flag(0x001, "fGroup"),
    flag(0x002, "fChild"),
    flag(0x004, "fPatriarch"),
    flag(0x008, "fDeleted"),
    flag(0x010, "fOleShape"),
    flag(0x020, "fHaveMaster"),
    flag(0x040, "fFlipH"),
    flag(0x080, "fFlipV"),
    flag(0x100, "fConnector"),
    flag(0x200, "fHaveAnchor"),
    flag(0x400, "fBackground"),
    flag(0x800, "fHaveSpt"),
];

const BLIP_TYPES: EnumTable = &[
    (0, "ERROR"),
    (1, "UNKNOWN"),
    (2, "EMF"),
    (3, "WMF"),
    (4, "PICT"),
    (5, "JPEG"),
    (6, "PNG"),
    (7, "DIB"),
    (17, "TIFF"),
    (18, "CMYK JPEG"),
];

const PROPERTIES: EnumTable = &[
    (0x0004, "rotation"),
    (0x007f, "protection booleans"),
    (0x0080, "lTxid"),
    (0x0081, "dxTextLeft"),
    (0x0082, "dyTextTop"),
    (0x0083, "dxTextRight"),
    (0x0084, "dyTextBottom"),
    (0x0085, "WrapText"),
    (0x0087, "anchorText"),
    (0x0088, "txflTextFlow"),
    (0x0089, "cdirFont"),
    (0x008a, "hspNext"),
    (0x008b, "txdir"),
    (0x00bf, "text booleans"),
    (0x00c0, "gtextUNICODE"),
    (0x00c2, "gtextAlign"),
    (0x00c3, "gtextSize"),
    (0x00c4, "gtextSpacing"),
    (0x00c5, "gtextFont"),
    (0x00ff, "geometry text booleans"),
    (0x0100, "cropFromTop"),
    (0x0101, "cropFromBottom"),
    (0x0102, "cropFromLeft"),
    (0x0103, "cropFromRight"),
    (0x0104, "pib"),
    (0x0105, "pibName"),
    (0x0106, "pibFlags"),
    (0x0107, "pictureTransparent"),
    (0x0108, "pictureContrast"),
    (0x0109, "pictureBrightness"),
    (0x010b, "pictureId"),
    (0x013f, "blip booleans"),
    (0x0140, "geoLeft"),
    (0x0141, "geoTop"),
    (0x0142, "geoRight"),
    (0x0143, "geoBottom"),
    (0x0144, "shapePath"),
    (0x0145, "pVertices"),
    (0x0146, "pSegmentInfo"),
    (0x0147, "adjustValue"),
    (0x0148, "adjust2Value"),
    (0x0149, "adjust3Value"),
    (0x0151, "pConnectionSites"),
    (0x0152, "pConnectionSitesDir"),
    (0x0155, "pAdjustHandles"),
    (0x0156, "pGuides"),
    (0x0157, "pInscribe"),
    (0x0158, "cxk"),
    (0x017f, "geometry booleans"),
    (0x0180, "fillType"),
    (0x0181, "fillColor"),
    (0x0182, "fillOpacity"),
    (0x0183, "fillBackColor"),
    (0x0184, "fillBackOpacity"),
    (0x0185, "fillCrMod"),
    (0x0186, "fillBlip"),
    (0x0187, "fillBlipName"),
    (0x0188, "fillBlipFlags"),
    (0x0189, "fillWidth"),
    (0x018a, "fillHeight"),
    (0x018b, "fillAngle"),
    (0x018c, "fillFocus"),
    (0x018d, "fillToLeft"),
    (0x018e, "fillToTop"),
    (0x018f, "fillToRight"),
    (0x0190, "fillToBottom"),
    (0x0191, "fillRectLeft"),
    (0x0192, "fillRectTop"),
    (0x0193, "fillRectRight"),
    (0x0194, "fillRectBottom"),
    (0x0195, "fillDztype"),
    (0x0196, "fillShadePreset"),
    (0x0197, "fillShadeColors"),
    (0x0198, "fillOriginX"),
    (0x0199, "fillOriginY"),
    (0x019a, "fillShapeOriginX"),
    (0x019b, "fillShapeOriginY"),
    (0x019c, "fillShadeType"),
    (0x01bf, "fill booleans"),
    (0x01c0, "lineColor"),
    (0x01c1, "lineOpacity"),
    (0x01c2, "lineBackColor"),
    (0x01c3, "lineCrMod"),
    (0x01c4, "lineType"),
    (0x01c5, "lineFillBlip"),
    (0x01cb, "lineWidth"),
    (0x01cc, "lineMiterLimit"),
    (0x01cd, "lineStyle"),
    (0x01ce, "lineDashing"),
    (0x01cf, "lineDashStyle"),
    (0x01d0, "lineStartArrowhead"),
    (0x01d1, "lineEndArrowhead"),
    (0x01d2, "lineStartArrowWidth"),
    (0x01d3, "lineStartArrowLength"),
    (0x01d4, "lineEndArrowWidth"),
    (0x01d5, "lineEndArrowLength"),
    (0x01d6, "lineJoinStyle"),
    (0x01d7, "lineEndCapStyle"),
    (0x01ff, "line booleans"),
    (0x0200, "shadowType"),
    (0x0201, "shadowColor"),
    (0x0202, "shadowHighlight"),
    (0x0203, "shadowCrMod"),
    (0x0204, "shadowOpacity"),
    (0x0205, "shadowOffsetX"),
    (0x0206, "shadowOffsetY"),
    (0x0207, "shadowSecondOffsetX"),
    (0x0208, "shadowSecondOffsetY"),
    (0x023f, "shadow booleans"),
    (0x027f, "perspective booleans"),
    (0x02bf, "3D object booleans"),
    (0x02ff, "3D style booleans"),
    (0x0301, "hspMaster"),
    (0x0303, "cxstyle"),
    (0x0304, "bWMode"),
    (0x0305, "bWModePureBW"),
    (0x0306, "bWModeBW"),
    (0x033f, "shape booleans"),
    (0x0380, "wzName"),
    (0x0381, "wzDescription"),
    (0x0382, "pihlShape"),
    (0x0383, "pWrapPolygonVertices"),
    (0x0384, "dxWrapDistLeft"),
    (0x0385, "dyWrapDistTop"),
    (0x0386, "dxWrapDistRight"),
    (0x0387, "dyWrapDistBottom"),
    (0x0388, "lidRegroup"),
    (0x038d, "wzTooltip"),
    (0x038e, "wzScript"),
    (0x038f, "posh"),
    (0x0390, "posrelh"),
    (0x0391, "posv"),
    (0x0392, "posrelv"),
    (0x0393, "pctHR"),
    (0x0394, "alignHR"),
    (0x0395, "dxHeightHR"),
    (0x0396, "dxWidthHR"),
    (0x0397, "wzScriptExtAttr"),
    (0x0398, "scriptLang"),
    (0x039a, "wzScriptLangAttr"),
    (0x039b, "borderTopColor"),
    (0x039c, "borderLeftColor"),
    (0x039d, "borderBottomColor"),
    (0x039e, "borderRightColor"),
    (0x039f, "tableProperties"),
    (0x03a0, "tableRowProperties"),
    (0x03a5, "wzWebBot"),
    (0x03a9, "metroBlob"),
    (0x03aa, "dhgt"),
    (0x03bf, "group shape booleans"),
    (0x0500, "unused (relative transform)"),
];

/// Properties whose value is a color.
fn is_color(pid: u16) -> bool {
    matches!(
        pid,
        0x0181 | 0x0183 | 0x01c0 | 0x01c2 | 0x0201 | 0x0202 | 0x039b..=0x039e
    )
}

/// A color (OfficeArtCOLORREF) as text.
pub fn color(v: u32) -> String {
    let flags = v >> 24;
    if flags & 0x08 != 0 {
        format!("scheme color {}", v & 0xff)
    } else if flags & 0x10 != 0 {
        format!("system color {:#x}", v & 0xffff)
    } else if flags & 0x01 != 0 {
        format!("palette index {}", v & 0xffff)
    } else {
        format!(
            "#{:02x}{:02x}{:02x}",
            v & 0xff,
            (v >> 8) & 0xff,
            (v >> 16) & 0xff
        )
    }
}

/// A record's name: Office Art types, then PowerPoint types.
pub fn name(kind: u16) -> String {
    lookup(NAMES, kind.into())
        .or_else(|| lookup(super::ppt::NAMES, kind.into()))
        .map_or_else(|| format!("Record {kind:#06x}"), str::to_owned)
}

/// The records at `span`, walked as a sequence (a drawing group, a
/// drawing, or an Escher stream).
pub async fn records_at(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    walk(cx, (input, span, 0)).await
}

/// A record sequence: each record's header, and containers as lazy levels.
pub async fn walk(cx: Cx, (input, span, depth): (Input, Span, u32)) -> Result<()> {
    let mut pos = 0u64;
    while pos.saturating_add(8) <= span.len {
        let head = cx.read(span.sub(pos, 8)).await?;
        let ver_inst = u16_le(&head, 0).unwrap_or(0);
        let kind = u16_le(&head, 2).unwrap_or(0);
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        let whole = span.sub(pos, len.saturating_add(8));
        let body = whole.tail(8);
        let container = ver_inst & 0xf == 0xf;
        let inst = ver_inst >> 4;
        let mut node = Node::new(name(kind)).span(whole).value(hex(kind, 16));
        if body.len < len {
            node = node.diag(Diagnostic::truncated(whole, body.len.saturating_add(8)));
        }
        if container {
            node = node.summary(container_summary(&cx, kind, body).await);
            node = if depth >= MAX_DEPTH {
                node.diag(Diagnostic::limit(format!(
                    "containers nested deeper than {MAX_DEPTH}"
                )))
            } else {
                node.lazy(
                    crate::expander!(self::container: (Input, Span, u32)),
                    (input, whole, depth.saturating_add(1)),
                )
            };
        } else {
            let peek = cx.read_avail(body.sub(0, 512)).await?;
            node = node
                .summary(atom_summary(kind, inst, &peek, body.len))
                .lazy(atom, (input, whole));
        }
        cx.progress_in(span, whole.offset);
        cx.push(node).await;
        if len == 0 && !container && whole.len < 8 {
            break;
        }
        pos = pos.saturating_add(len.saturating_add(8));
    }
    if pos < span.len {
        let rest = span.tail(pos);
        let data = cx.read_avail(rest.sub(0, 64)).await?;
        let node = Node::new("Trailing data").span(rest);
        cx.push(if data.iter().all(|&b| b == 0) {
            node.summary(format!("{} zero bytes", rest.len))
        } else {
            node.diag(Diagnostic::malformed("a record header does not fit"))
        })
        .await;
    }
    Ok(())
}

/// A container: its header, then its children.
async fn container(cx: Cx, (input, whole, depth): (Input, Span, u32)) -> Result<()> {
    header(&cx, whole).await?;
    walk(cx, (input, whole.tail(8), depth)).await
}

/// The record header as fields.
async fn header(cx: &Cx, whole: Span) -> Result<()> {
    let block = cx.block(whole.sub(0, 8)).await?;
    let mut f = Fields::emitting(cx, &block, LE);
    f.u16("recVer / recInstance")
        .hex()
        .with(|&v, n| n.summary(format!("version {:#x}, instance {:#x}", v & 0xf, v >> 4)))
        .emit()?;
    let kind = u16_le(&block.data, 2).unwrap_or(0);
    f.u16("recType")
        .hex()
        .with(|_, n| n.summary(name(kind)))
        .emit()?;
    f.u32("recLen").emit()?;
    Ok(())
}

async fn container_summary(cx: &Cx, kind: u16, body: Span) -> String {
    // Count the children without decoding them.
    let mut n = 0u32;
    let mut pos = 0u64;
    while pos.saturating_add(8) <= body.len && n < 10_000 {
        let Ok(h) = cx.read(body.sub(pos, 8)).await else {
            break;
        };
        pos = pos
            .saturating_add(8)
            .saturating_add(u32_le(&h, 4).unwrap_or(0).into());
        n = n.saturating_add(1);
    }
    let _ = kind;
    format!("container, {n} records, {} bytes", body.len)
}

fn atom_summary(kind: u16, inst: u16, data: &[u8], len: u64) -> String {
    let s = match kind {
        0xf006 => u32_le(data, 0)
            .zip(u32_le(data, 12))
            .map(|(max, dgs)| format!("next shape ID {max}, {dgs} drawings")),
        0xf008 => u32_le(data, 0).map(|n| format!("drawing {inst}, {n} shapes")),
        0xf00a => u32_le(data, 0).zip(u32_le(data, 4)).map(|(spid, flags)| {
            let (set, _) = crate::value::decode_flags(FSP_FLAGS, flags.into());
            format!(
                "shape {spid}, {}{}",
                lookup(SHAPE_TYPES, inst.into())
                    .map_or_else(|| format!("type {inst}"), str::to_owned),
                if set.is_empty() {
                    String::new()
                } else {
                    format!(" ({})", set.join(", "))
                }
            )
        }),
        0xf00b | 0xf121 | 0xf122 => Some(format!("{inst} properties")),
        0xf007 => data.first().map(|&t| {
            format!(
                "{} picture, {} references",
                lookup(BLIP_TYPES, t.into()).unwrap_or("unknown"),
                u32_le(data, 24).unwrap_or(0)
            )
        }),
        0xf009 | 0xf00f => {
            let r: Vec<i32> = (0..4usize)
                .filter_map(|i| i32_le(data, i.saturating_mul(4)))
                .collect();
            match r.as_slice() {
                [a, b, c, d] => Some(format!("({a}, {b})–({c}, {d})")),
                _ => None,
            }
        }
        0xf01a..=0xf117 => Some(format!("{} bytes", len)),
        k if k < 0xf000 => Some(super::ppt::atom_summary(k, inst, data, len)),
        _ => None,
    };
    s.unwrap_or_else(|| format!("atom, {len} bytes"))
}

/// An atom: its header and decoded fields.
async fn atom(cx: Cx, (input, whole): (Input, Span)) -> Result<()> {
    header(&cx, whole).await?;
    let head = cx.read(whole.sub(0, 8)).await?;
    let inst = u16_le(&head, 0).unwrap_or(0) >> 4;
    let kind = u16_le(&head, 2).unwrap_or(0);
    let body = whole.tail(8);
    if body.len == 0 {
        return Ok(());
    }
    let block = cx.block(body).await?;
    let mut f = Fields::emitting(&cx, &block, LE);
    match kind {
        0xf006 => {
            f.u32("spidMax").emit()?;
            let cidcl = f
                .u32("cidcl")
                .desc("Clusters of shape IDs, plus one")
                .emit()?;
            f.u32("cspSaved").emit()?;
            f.u32("cdgSaved").emit()?;
            for _ in 1..cidcl {
                if f.remaining() < 8 {
                    break;
                }
                let at = to_usize(f.pos());
                let (dg, cur) = (
                    u32_le(&block.data, at).unwrap_or(0),
                    u32_le(&block.data, at.saturating_add(4)).unwrap_or(0),
                );
                f.bytes("IDCL", 8)
                    .with(|_, n| n.summary(format!("drawing {dg}, next ID {cur}")))
                    .emit()?;
            }
        }
        0xf008 => {
            f.u32("csp").desc("Shapes in the drawing").emit()?;
            f.u32("spidCur").emit()?;
        }
        0xf00a => {
            f.u32("spid").emit()?;
            f.u32("Flags").flags(FSP_FLAGS).emit()?;
            cx.emit(
                Node::new("Shape type (instance)")
                    .span(whole.sub(0, 2))
                    .value(enumv(inst, 12, SHAPE_TYPES)),
            );
        }
        0xf009 | 0xf00f => {
            for name in ["xLeft", "yTop", "xRight", "yBottom"] {
                f.i32(name).emit()?;
            }
        }
        0xf010 => client_anchor(&mut f, body.len)?,
        0xf00b | 0xf121 | 0xf122 => fopt(&mut f, inst)?,
        0xf007 => {
            f.u8("btWin32").enumeration(BLIP_TYPES).emit()?;
            f.u8("btMacOS").enumeration(BLIP_TYPES).emit()?;
            f.bytes("rgbUid", 16)
                .desc("MD4 of the picture data")
                .emit()?;
            f.u16("tag").emit()?;
            f.u32("size").emit()?;
            f.u32("cRef").emit()?;
            f.u32("foDelay")
                .hex()
                .desc("Offset of the picture in the delay stream, if not embedded")
                .emit()?;
            f.u8("unused1").emit()?;
            let cb_name = f.u8("cbName").emit()?;
            f.u8("unused2").emit()?;
            f.u8("unused3").emit()?;
            if cb_name > 0 {
                f.utf16("nameData", u64::from(cb_name) / 2).emit()?;
            }
            if f.remaining() >= 8 {
                cx.emit(Node::new("Embedded blip").span(body.tail(f.pos())).lazy(
                    crate::expander!(self::walk: (Input, Span, u32)),
                    (input, body.tail(f.pos()), 1),
                ));
                f.seek(body.len);
            }
        }
        0xf01a..=0xf117 => blip(&cx, &mut f, input, body, kind, inst)?,
        k if k < 0xf000 => super::ppt::atom_fields(&cx, &mut f, k, inst, input, body).await?,
        _ => {}
    }
    let rest = body.len.saturating_sub(f.pos());
    if rest > 0 && f.pos() < body.len {
        cx.emit(
            Node::new(if f.pos() == 0 {
                "Data"
            } else {
                "Remaining data"
            })
            .span(body.tail(f.pos()))
            .summary(format!("{rest} bytes")),
        );
    }
    Ok(())
}

fn client_anchor(f: &mut Fields<'_>, len: u64) -> Result<()> {
    match len {
        18 => {
            // Excel: cell-relative anchor.
            f.u16("Flags").hex().emit()?;
            for (name, kind) in [
                ("colL", K::Col),
                ("dxL", K::U16),
                ("rwT", K::Row),
                ("dyT", K::U16),
                ("colR", K::Col),
                ("dxR", K::U16),
                ("rwB", K::Row),
                ("dyB", K::U16),
            ] {
                super::rec::field(f, name, kind)?;
            }
        }
        8 => {
            // PowerPoint: master units, 16-bit.
            for name in ["top", "left", "right", "bottom"] {
                f.int::<i16>(name).emit()?;
            }
        }
        16 => {
            for name in ["top", "left", "right", "bottom"] {
                f.i32(name).emit()?;
            }
        }
        4 => {
            f.i32("clientanchor")
                .desc("Index into the host's anchor table")
                .emit()?;
        }
        _ => {}
    }
    Ok(())
}

/// FOPT: a table of 6-byte properties, then the complex values in order.
fn fopt(f: &mut Fields<'_>, count: u16) -> Result<()> {
    let data = f.block().data.clone();
    let table = u64::from(count).saturating_mul(6);
    let mut complex_at = table;
    let mut complex = Vec::new();
    for i in 0..u64::from(count) {
        if f.remaining() < 6 {
            break;
        }
        let at = to_usize(i.saturating_mul(6));
        let opid = u16_le(&data, at).unwrap_or(0);
        let op = u32_le(&data, at.saturating_add(2)).unwrap_or(0);
        let pid = opid & 0x3fff;
        let name = lookup(PROPERTIES, pid.into())
            .map_or_else(|| format!("property {pid:#06x}"), str::to_owned);
        let mut node = Node::new(name).span(f.peek_span(6));
        if opid & 0x8000 != 0 {
            let len = u64::from(op);
            node = node
                .value(uint(op, 32))
                .summary(format!("{len} bytes of complex data"));
            complex.push((pid, complex_at, len));
            complex_at = complex_at.saturating_add(len);
        } else if opid & 0x4000 != 0 {
            node = node
                .value(uint(op, 32))
                .summary(format!("picture {op} in the blip store"));
        } else if is_color(pid) {
            node = node.value(hex(op, 32)).summary(color(op));
        } else if matches!(pid, 0x01cb | 0x0081..=0x0084 | 0x0205 | 0x0206 | 0x0384..=0x0387) {
            node = node
                .value(Value::Int {
                    value: i64::from(op.cast_signed()),
                    bits: 32,
                })
                .summary(format!("{:.2} pt", f64::from(op.cast_signed()) / 12700.0));
        } else if pid == 0x0004 {
            node = node
                .value(Value::Float(f64::from(op.cast_signed()) / 65536.0))
                .summary("degrees");
        } else {
            node = node.value(hex(op, 32));
        }
        node = node.desc(format!(
            "Property {pid:#06x}{}{}",
            if opid & 0x4000 != 0 { ", fBid" } else { "" },
            if opid & 0x8000 != 0 { ", fComplex" } else { "" }
        ));
        f.node(node);
        f.skip(6);
    }
    for (pid, at, len) in complex {
        let span = f.peek_span(0);
        let base = span.offset.saturating_sub(f.pos());
        let s = Span::new(span.source, base.saturating_add(at), len);
        let name = lookup(PROPERTIES, pid.into()).unwrap_or("complex property");
        let raw = data
            .get(to_usize(at)..to_usize(at.saturating_add(len)))
            .unwrap_or_default();
        let mut node = Node::new(format!("{name} data")).span(s);
        if matches!(
            pid,
            0x0380 | 0x0381 | 0x038d | 0x038e | 0x0105 | 0x0187 | 0x00c0 | 0x00c5
        ) {
            node = node.value(Value::Text(crate::text::utf16z(raw, LE).0));
        } else {
            node = node.value(Value::Bytes(raw.get(..64).unwrap_or(raw).to_vec()));
        }
        f.node(node);
    }
    f.seek(complex_at.min(f.block().span.len));
    Ok(())
}

/// A blip: UIDs, a metafile header or a tag byte, then the picture.
fn blip(cx: &Cx, f: &mut Fields<'_>, input: Input, body: Span, kind: u16, inst: u16) -> Result<()> {
    let _ = cx;
    f.bytes("rgbUid1", 16)
        .desc("MD4 of the uncompressed picture")
        .emit()?;
    let two = match kind {
        0xf01a => inst == 0x3d5,
        0xf01b => inst == 0x217,
        0xf01c => inst == 0x543,
        0xf01d | 0xf02a => inst == 0x46b || inst == 0x6e3,
        0xf01e => inst == 0x6e1,
        0xf01f => inst == 0x7a9,
        0xf029 => inst == 0x6e5,
        _ => false,
    };
    if two {
        f.bytes("rgbUid2", 16).emit()?;
    }
    let metafile = matches!(kind, 0xf01a..=0xf01c);
    if metafile {
        f.u32("cbSize").desc("Uncompressed size").emit()?;
        for name in ["left", "top", "right", "bottom"] {
            f.i32(name).emit()?;
        }
        f.i32("ptSize.x").emit()?;
        f.i32("ptSize.y").emit()?;
        f.u32("cbSave").desc("Stored size").emit()?;
        let comp = f
            .u8("fCompression")
            .enumeration(&[(0x00, "DEFLATE"), (0xfe, "none")])
            .emit()?;
        f.u8("fFilter").emit()?;
        let data = body.tail(f.pos());
        let node = if comp == 0 {
            crate::formats::content("Picture", input, data, crate::codec::Codec::Zlib, None)
        } else {
            crate::formats::embedded("Picture", input.nested(data))
        };
        f.node(node.summary(format!("{} bytes", data.len)));
    } else {
        f.u8("tag").emit()?;
        let data = body.tail(f.pos());
        f.node(
            crate::formats::embedded("Picture", input.nested(data))
                .summary(format!("{} bytes", data.len)),
        );
    }
    f.seek(body.len);
    Ok(())
}
