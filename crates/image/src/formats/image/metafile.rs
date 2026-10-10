//! Windows metafiles: WMF (16-bit, optionally with an Aldus placeable
//! header) and EMF (32-bit enhanced metafiles, including EMF+ comments).
//!
//! Both are a header followed by drawing records; records are listed in
//! pages with their function names and their key parameters (coordinates,
//! colors, fonts, text), and records that carry a device-independent bitmap
//! open it as one.
//!
//! Layouts are from [MS-WMF], [MS-EMF] and [MS-EMFPLUS].

use crate::bytes::{i16_le, i32_le, to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, lookup};

use super::{dims, text};

const LE: Endian = Endian::Little;

pub static WMF: Format = Format {
    name: "wmf",
    title: "Windows Metafile",
    extensions: &["wmf"],
    mime: "image/wmf",
    probe: Probe::Custom(probe_wmf),
    dissect: crate::expander!(dissect_wmf: Input),
};

pub static EMF: Format = Format {
    name: "emf",
    title: "Enhanced Metafile",
    extensions: &["emf", "emz"],
    mime: "image/emf",
    probe: Probe::Custom(|h| h.starts_with(b"\x01\0\0\0") && h.at(40, b" EMF")),
    dissect: crate::expander!(dissect_emf: Input),
};

const PLACEABLE: &[u8] = b"\xd7\xcd\xc6\x9a";

fn probe_wmf(h: &Head<'_>) -> bool {
    let header = if h.starts_with(PLACEABLE) { 22 } else { 0 };
    let (Some(kind), Some(size), Some(version)) = (
        u16_le(h.data, header),
        u16_le(h.data, header.saturating_add(2)),
        u16_le(h.data, header.saturating_add(4)),
    ) else {
        return false;
    };
    (kind == 1 || kind == 2) && size == 9 && (version == 0x0100 || version == 0x0300)
}

const WMF_RECORDS: EnumTable = &[
    (0x0000, "META_EOF"),
    (0x001e, "META_SAVEDC"),
    (0x0035, "META_REALIZEPALETTE"),
    (0x0037, "META_SETPALENTRIES"),
    (0x004f, "META_STARTPAGE"),
    (0x0050, "META_ENDPAGE"),
    (0x0052, "META_ABORTDOC"),
    (0x005e, "META_ENDDOC"),
    (0x00f7, "META_CREATEPALETTE"),
    (0x00f8, "META_CREATEBRUSH"),
    (0x0102, "META_SETBKMODE"),
    (0x0103, "META_SETMAPMODE"),
    (0x0104, "META_SETROP2"),
    (0x0105, "META_SETRELABS"),
    (0x0106, "META_SETPOLYFILLMODE"),
    (0x0107, "META_SETSTRETCHBLTMODE"),
    (0x0108, "META_SETTEXTCHAREXTRA"),
    (0x0127, "META_RESTOREDC"),
    (0x012a, "META_INVERTREGION"),
    (0x012b, "META_PAINTREGION"),
    (0x012c, "META_SELECTCLIPREGION"),
    (0x012d, "META_SELECTOBJECT"),
    (0x012e, "META_SETTEXTALIGN"),
    (0x0139, "META_RESIZEPALETTE"),
    (0x0142, "META_DIBCREATEPATTERNBRUSH"),
    (0x0149, "META_SETLAYOUT"),
    (0x01f0, "META_DELETEOBJECT"),
    (0x01f9, "META_CREATEPATTERNBRUSH"),
    (0x0201, "META_SETBKCOLOR"),
    (0x0209, "META_SETTEXTCOLOR"),
    (0x020a, "META_SETTEXTJUSTIFICATION"),
    (0x020b, "META_SETWINDOWORG"),
    (0x020c, "META_SETWINDOWEXT"),
    (0x020d, "META_SETVIEWPORTORG"),
    (0x020e, "META_SETVIEWPORTEXT"),
    (0x020f, "META_OFFSETWINDOWORG"),
    (0x0211, "META_OFFSETVIEWPORTORG"),
    (0x0213, "META_LINETO"),
    (0x0214, "META_MOVETO"),
    (0x0220, "META_OFFSETCLIPRGN"),
    (0x0228, "META_FILLREGION"),
    (0x0231, "META_SETMAPPERFLAGS"),
    (0x0234, "META_SELECTPALETTE"),
    (0x02fa, "META_CREATEPENINDIRECT"),
    (0x02fb, "META_CREATEFONTINDIRECT"),
    (0x02fc, "META_CREATEBRUSHINDIRECT"),
    (0x0324, "META_POLYGON"),
    (0x0325, "META_POLYLINE"),
    (0x0410, "META_SCALEWINDOWEXT"),
    (0x0412, "META_SCALEVIEWPORTEXT"),
    (0x0415, "META_EXCLUDECLIPRECT"),
    (0x0416, "META_INTERSECTCLIPRECT"),
    (0x0418, "META_ELLIPSE"),
    (0x0419, "META_FLOODFILL"),
    (0x041b, "META_RECTANGLE"),
    (0x041f, "META_SETPIXEL"),
    (0x0429, "META_FRAMEREGION"),
    (0x0436, "META_ANIMATEPALETTE"),
    (0x0521, "META_TEXTOUT"),
    (0x0538, "META_POLYPOLYGON"),
    (0x0548, "META_EXTFLOODFILL"),
    (0x061c, "META_ROUNDRECT"),
    (0x061d, "META_PATBLT"),
    (0x0626, "META_ESCAPE"),
    (0x06ff, "META_CREATEREGION"),
    (0x0817, "META_ARC"),
    (0x081a, "META_PIE"),
    (0x0830, "META_CHORD"),
    (0x0922, "META_BITBLT"),
    (0x0940, "META_DIBBITBLT"),
    (0x0a32, "META_EXTTEXTOUT"),
    (0x0b23, "META_STRETCHBLT"),
    (0x0b41, "META_DIBSTRETCHBLT"),
    (0x0d33, "META_SETDIBTODEV"),
    (0x0f43, "META_STRETCHDIB"),
];

const EMF_RECORDS: EnumTable = &[
    (1, "EMR_HEADER"),
    (2, "EMR_POLYBEZIER"),
    (3, "EMR_POLYGON"),
    (4, "EMR_POLYLINE"),
    (5, "EMR_POLYBEZIERTO"),
    (6, "EMR_POLYLINETO"),
    (7, "EMR_POLYPOLYLINE"),
    (8, "EMR_POLYPOLYGON"),
    (9, "EMR_SETWINDOWEXTEX"),
    (10, "EMR_SETWINDOWORGEX"),
    (11, "EMR_SETVIEWPORTEXTEX"),
    (12, "EMR_SETVIEWPORTORGEX"),
    (13, "EMR_SETBRUSHORGEX"),
    (14, "EMR_EOF"),
    (15, "EMR_SETPIXELV"),
    (16, "EMR_SETMAPPERFLAGS"),
    (17, "EMR_SETMAPMODE"),
    (18, "EMR_SETBKMODE"),
    (19, "EMR_SETPOLYFILLMODE"),
    (20, "EMR_SETROP2"),
    (21, "EMR_SETSTRETCHBLTMODE"),
    (22, "EMR_SETTEXTALIGN"),
    (23, "EMR_SETCOLORADJUSTMENT"),
    (24, "EMR_SETTEXTCOLOR"),
    (25, "EMR_SETBKCOLOR"),
    (26, "EMR_OFFSETCLIPRGN"),
    (27, "EMR_MOVETOEX"),
    (28, "EMR_SETMETARGN"),
    (29, "EMR_EXCLUDECLIPRECT"),
    (30, "EMR_INTERSECTCLIPRECT"),
    (31, "EMR_SCALEVIEWPORTEXTEX"),
    (32, "EMR_SCALEWINDOWEXTEX"),
    (33, "EMR_SAVEDC"),
    (34, "EMR_RESTOREDC"),
    (35, "EMR_SETWORLDTRANSFORM"),
    (36, "EMR_MODIFYWORLDTRANSFORM"),
    (37, "EMR_SELECTOBJECT"),
    (38, "EMR_CREATEPEN"),
    (39, "EMR_CREATEBRUSHINDIRECT"),
    (40, "EMR_DELETEOBJECT"),
    (41, "EMR_ANGLEARC"),
    (42, "EMR_ELLIPSE"),
    (43, "EMR_RECTANGLE"),
    (44, "EMR_ROUNDRECT"),
    (45, "EMR_ARC"),
    (46, "EMR_CHORD"),
    (47, "EMR_PIE"),
    (48, "EMR_SELECTPALETTE"),
    (49, "EMR_CREATEPALETTE"),
    (50, "EMR_SETPALETTEENTRIES"),
    (51, "EMR_RESIZEPALETTE"),
    (52, "EMR_REALIZEPALETTE"),
    (53, "EMR_EXTFLOODFILL"),
    (54, "EMR_LINETO"),
    (55, "EMR_ARCTO"),
    (56, "EMR_POLYDRAW"),
    (57, "EMR_SETARCDIRECTION"),
    (58, "EMR_SETMITERLIMIT"),
    (59, "EMR_BEGINPATH"),
    (60, "EMR_ENDPATH"),
    (61, "EMR_CLOSEFIGURE"),
    (62, "EMR_FILLPATH"),
    (63, "EMR_STROKEANDFILLPATH"),
    (64, "EMR_STROKEPATH"),
    (65, "EMR_FLATTENPATH"),
    (66, "EMR_WIDENPATH"),
    (67, "EMR_SELECTCLIPPATH"),
    (68, "EMR_ABORTPATH"),
    (70, "EMR_COMMENT"),
    (71, "EMR_FILLRGN"),
    (72, "EMR_FRAMERGN"),
    (73, "EMR_INVERTRGN"),
    (74, "EMR_PAINTRGN"),
    (75, "EMR_EXTSELECTCLIPRGN"),
    (76, "EMR_BITBLT"),
    (77, "EMR_STRETCHBLT"),
    (78, "EMR_MASKBLT"),
    (79, "EMR_PLGBLT"),
    (80, "EMR_SETDIBITSTODEVICE"),
    (81, "EMR_STRETCHDIBITS"),
    (82, "EMR_EXTCREATEFONTINDIRECTW"),
    (83, "EMR_EXTTEXTOUTA"),
    (84, "EMR_EXTTEXTOUTW"),
    (85, "EMR_POLYBEZIER16"),
    (86, "EMR_POLYGON16"),
    (87, "EMR_POLYLINE16"),
    (88, "EMR_POLYBEZIERTO16"),
    (89, "EMR_POLYLINETO16"),
    (90, "EMR_POLYPOLYLINE16"),
    (91, "EMR_POLYPOLYGON16"),
    (92, "EMR_POLYDRAW16"),
    (93, "EMR_CREATEMONOBRUSH"),
    (94, "EMR_CREATEDIBPATTERNBRUSHPT"),
    (95, "EMR_EXTCREATEPEN"),
    (96, "EMR_POLYTEXTOUTA"),
    (97, "EMR_POLYTEXTOUTW"),
    (98, "EMR_SETICMMODE"),
    (99, "EMR_CREATECOLORSPACE"),
    (100, "EMR_SETCOLORSPACE"),
    (101, "EMR_DELETECOLORSPACE"),
    (102, "EMR_GLSRECORD"),
    (103, "EMR_GLSBOUNDEDRECORD"),
    (104, "EMR_PIXELFORMAT"),
    (105, "EMR_DRAWESCAPE"),
    (106, "EMR_EXTESCAPE"),
    (108, "EMR_SMALLTEXTOUT"),
    (109, "EMR_FORCEUFIMAPPING"),
    (110, "EMR_NAMEDESCAPE"),
    (111, "EMR_COLORCORRECTPALETTE"),
    (112, "EMR_SETICMPROFILEA"),
    (113, "EMR_SETICMPROFILEW"),
    (114, "EMR_ALPHABLEND"),
    (115, "EMR_SETLAYOUT"),
    (116, "EMR_TRANSPARENTBLT"),
    (118, "EMR_GRADIENTFILL"),
    (119, "EMR_SETLINKEDUFIS"),
    (120, "EMR_SETTEXTJUSTIFICATION"),
    (121, "EMR_COLORMATCHTOTARGETW"),
    (122, "EMR_CREATECOLORSPACEW"),
];

/// [MS-EMFPLUS] 2.1.1.1 RecordType.
const EMFPLUS_RECORDS: EnumTable = &[
    (0x4001, "EmfPlusHeader"),
    (0x4002, "EmfPlusEndOfFile"),
    (0x4003, "EmfPlusComment"),
    (0x4004, "EmfPlusGetDC"),
    (0x4005, "EmfPlusMultiFormatStart"),
    (0x4006, "EmfPlusMultiFormatSection"),
    (0x4007, "EmfPlusMultiFormatEnd"),
    (0x4008, "EmfPlusObject"),
    (0x4009, "EmfPlusClear"),
    (0x400a, "EmfPlusFillRects"),
    (0x400b, "EmfPlusDrawRects"),
    (0x400c, "EmfPlusFillPolygon"),
    (0x400d, "EmfPlusDrawLines"),
    (0x400e, "EmfPlusFillEllipse"),
    (0x400f, "EmfPlusDrawEllipse"),
    (0x4010, "EmfPlusFillPie"),
    (0x4011, "EmfPlusDrawPie"),
    (0x4012, "EmfPlusDrawArc"),
    (0x4013, "EmfPlusFillRegion"),
    (0x4014, "EmfPlusFillPath"),
    (0x4015, "EmfPlusDrawPath"),
    (0x4016, "EmfPlusFillClosedCurve"),
    (0x4017, "EmfPlusDrawClosedCurve"),
    (0x4018, "EmfPlusDrawCurve"),
    (0x4019, "EmfPlusDrawBeziers"),
    (0x401a, "EmfPlusDrawImage"),
    (0x401b, "EmfPlusDrawImagePoints"),
    (0x401c, "EmfPlusDrawString"),
    (0x401d, "EmfPlusSetRenderingOrigin"),
    (0x401e, "EmfPlusSetAntiAliasMode"),
    (0x401f, "EmfPlusSetTextRenderingHint"),
    (0x4020, "EmfPlusSetTextContrast"),
    (0x4021, "EmfPlusSetInterpolationMode"),
    (0x4022, "EmfPlusSetPixelOffsetMode"),
    (0x4023, "EmfPlusSetCompositingMode"),
    (0x4024, "EmfPlusSetCompositingQuality"),
    (0x4025, "EmfPlusSave"),
    (0x4026, "EmfPlusRestore"),
    (0x4027, "EmfPlusBeginContainer"),
    (0x4028, "EmfPlusBeginContainerNoParams"),
    (0x4029, "EmfPlusEndContainer"),
    (0x402a, "EmfPlusSetWorldTransform"),
    (0x402b, "EmfPlusResetWorldTransform"),
    (0x402c, "EmfPlusMultiplyWorldTransform"),
    (0x402d, "EmfPlusTranslateWorldTransform"),
    (0x402e, "EmfPlusScaleWorldTransform"),
    (0x402f, "EmfPlusRotateWorldTransform"),
    (0x4030, "EmfPlusSetPageTransform"),
    (0x4031, "EmfPlusResetClip"),
    (0x4032, "EmfPlusSetClipRect"),
    (0x4033, "EmfPlusSetClipPath"),
    (0x4034, "EmfPlusSetClipRegion"),
    (0x4035, "EmfPlusOffsetClip"),
    (0x4036, "EmfPlusDrawDriverString"),
    (0x4037, "EmfPlusStrokeFillPath"),
    (0x4038, "EmfPlusSerializableObject"),
    (0x4039, "EmfPlusSetTSGraphics"),
    (0x403a, "EmfPlusSetTSClip"),
];

/// [MS-EMFPLUS] 2.1.1.22 ObjectType (bits 8–14 of an EmfPlusObject's flags).
const EMFPLUS_OBJECTS: EnumTable = &[
    (1, "brush"),
    (2, "pen"),
    (3, "path"),
    (4, "region"),
    (5, "image"),
    (6, "font"),
    (7, "string format"),
    (8, "image attributes"),
    (9, "custom line cap"),
];

const MAP_MODES: EnumTable = &[
    (1, "MM_TEXT"),
    (2, "MM_LOMETRIC"),
    (3, "MM_HIMETRIC"),
    (4, "MM_LOENGLISH"),
    (5, "MM_HIENGLISH"),
    (6, "MM_TWIPS"),
    (7, "MM_ISOTROPIC"),
    (8, "MM_ANISOTROPIC"),
];

const BK_MODES: EnumTable = &[(1, "TRANSPARENT"), (2, "OPAQUE")];

const BRUSH_STYLES: EnumTable = &[
    (0, "solid"),
    (1, "null"),
    (2, "hatched"),
    (3, "pattern"),
    (5, "DIB pattern"),
    (6, "DIB pattern (packed)"),
    (7, "pattern (8×8)"),
    (8, "DIB pattern (8×8)"),
    (9, "monochrome pattern"),
];

const PEN_STYLES: EnumTable = &[
    (0, "solid"),
    (1, "dash"),
    (2, "dot"),
    (3, "dash-dot"),
    (4, "dash-dot-dot"),
    (5, "null"),
    (6, "inside frame"),
    (7, "user style"),
    (8, "alternate"),
];

/// EMF stock objects: handles with the top bit set.
const STOCK_OBJECTS: EnumTable = &[
    (0x8000_0000, "WHITE_BRUSH"),
    (0x8000_0001, "LTGRAY_BRUSH"),
    (0x8000_0002, "GRAY_BRUSH"),
    (0x8000_0003, "DKGRAY_BRUSH"),
    (0x8000_0004, "BLACK_BRUSH"),
    (0x8000_0005, "NULL_BRUSH"),
    (0x8000_0006, "WHITE_PEN"),
    (0x8000_0007, "BLACK_PEN"),
    (0x8000_0008, "NULL_PEN"),
    (0x8000_000a, "OEM_FIXED_FONT"),
    (0x8000_000b, "ANSI_FIXED_FONT"),
    (0x8000_000c, "ANSI_VAR_FONT"),
    (0x8000_000d, "SYSTEM_FONT"),
    (0x8000_000e, "DEVICE_DEFAULT_FONT"),
    (0x8000_000f, "DEFAULT_PALETTE"),
    (0x8000_0010, "SYSTEM_FIXED_FONT"),
    (0x8000_0011, "DEFAULT_GUI_FONT"),
    (0x8000_0012, "DC_BRUSH"),
    (0x8000_0013, "DC_PEN"),
];

/// Public comment types in an EMR_COMMENT with the "GDIC" identifier.
const PUBLIC_COMMENTS: EnumTable = &[
    (0x8000_0001, "EMR_COMMENT_WINDOWS_METAFILE"),
    (0x0000_0002, "EMR_COMMENT_BEGINGROUP"),
    (0x0000_0003, "EMR_COMMENT_ENDGROUP"),
    (0x4000_0004, "EMR_COMMENT_MULTIFORMATS"),
    (0x0000_0040, "EMR_COMMENT_UNICODE_STRING"),
    (0x0000_0080, "EMR_COMMENT_UNICODE_END"),
];

record! {
    pub struct Placeable {
        key: u32 "Key" .hex(),
        hmf: u16 "Handle",
        left: i16 "Left",
        top: i16 "Top",
        right: i16 "Right",
        bottom: i16 "Bottom",
        inch: u16 "Units per inch" .desc("Logical units per inch (1440 = twips)"),
        reserved: u32 "Reserved",
        checksum: u16 "Checksum" .hex() .check(|&c| {
            let words = [
                (key & 0xffff) as u16,
                (key >> 16) as u16,
                hmf,
                left.cast_unsigned(),
                top.cast_unsigned(),
                right.cast_unsigned(),
                bottom.cast_unsigned(),
                inch,
                (reserved & 0xffff) as u16,
                (reserved >> 16) as u16,
            ];
            let sum = words.iter().fold(0u16, |a, &w| a ^ w);
            (sum != c).then(|| Diagnostic::warning(format!("checksum mismatch (computed {sum:#06x})")))
        }),
    }
}

record! {
    pub struct WmfHeader {
        kind: u16 "Type" .enumeration(&[(1, "memory"), (2, "disk")]),
        header_size: u16 "Header size (words)" .desc("In 16-bit words"),
        version: u16 "Version" .enumeration(&[(0x0100, "1.0 (no DIBs)"), (0x0300, "3.0")]),
        size: u32 "File size (words)" .desc("Of the whole metafile, without the placeable header, in 16-bit words"),
        objects: u16 "Number of objects",
        max_record: u32 "Largest record (words)" .desc("In 16-bit words"),
        members: u16 "Number of members" .desc("Not used; 0"),
    }
}

/// Records listed before giving up on a bogus file.
const MAX_RECORDS: u64 = 10_000_000;
/// Bytes of each record read for its parameters.
const PARAMS: u64 = 112;
/// Characters of text shown for a text record.
const MAX_TEXT: u64 = 1024;

pub async fn dissect_wmf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read_avail(file.sub(0, 4)).await?;
    let mut pos = 0u64;
    let mut size_summary = String::new();
    if magic == PLACEABLE {
        let span = file.sub(0, Placeable::SIZE);
        let p = parse(&cx, span, LE, &(), Placeable::layout).await?;
        let w = i32::from(p.right).saturating_sub(p.left.into());
        let h = i32::from(p.bottom).saturating_sub(p.top.into());
        let mut summary = format!("{} units", dims(w, h));
        if p.inch > 0 {
            let inch = f64::from(p.inch);
            summary = format!(
                "{summary} at {} per inch ({} in)",
                p.inch,
                dims(
                    format!("{:.2}", f64::from(w) / inch),
                    format!("{:.2}", f64::from(h) / inch)
                )
            );
        }
        size_summary = format!(", {summary}");
        cx.emit(Placeable::node("Placeable header", span, LE).summary(summary));
        pos = Placeable::SIZE;
    }
    let span = file.sub(pos, WmfHeader::SIZE);
    let h = parse(&cx, span, LE, &(), WmfHeader::layout).await?;
    let version = if h.version == 0x0100 { "1.0" } else { "3.0" };
    cx.emit(WmfHeader::node("Header", span, LE).summary(format!(
        "version {version}, {}, {} objects",
        crate::formats::util::arcutil::human_size(u64::from(h.size).saturating_mul(2)),
        h.objects
    )));
    cx.annotate(format!(
        "WMF {version}{size_summary}, {} objects",
        h.objects
    ));
    pos = pos.saturating_add(u64::from(h.header_size).saturating_mul(2));
    let records = file.tail(pos);
    cx.emit(
        Node::new("Records")
            .span(records)
            .lazy(wmf_records, (input, records)),
    );
    Ok(())
}

async fn wmf_records(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos.saturating_add(6) <= span.len && index < MAX_RECORDS {
        let params = cx.read(span.sub(pos, PARAMS)).await?;
        let words = u64::from(u32_le(&params, 0).unwrap_or(0));
        let function = u16_le(&params, 4).unwrap_or(0);
        let len = words.saturating_mul(2);
        if len < 6 {
            cx.diag(
                Diagnostic::malformed(format!("record size {len} is too small"))
                    .at(span.sub(pos, 6)),
            );
            break;
        }
        let record = span.sub(pos, len);
        cx.progress_in(span, record.end());
        let name = lookup(WMF_RECORDS, function.into())
            .map_or_else(|| format!("Record {function:#06x}"), str::to_owned);
        let params = params
            .get(..crate::bytes::to_usize(len))
            .unwrap_or(params.as_slice());
        let summary = match wmf_text(function, params) {
            Some((at, chars)) => {
                let bytes = cx.read_avail(record.sub(at, chars.min(MAX_TEXT))).await?;
                Some(format!("{:?}", crate::text::latin1(&bytes)))
            }
            None => wmf_summary(function, params),
        };
        let mut node = Node::new(name)
            .span(record)
            .summary(summary.unwrap_or_else(|| format!("{len} bytes")));
        if let Some(at) = wmf_dib(function, params) {
            let dib = record.tail(at);
            node = node.lazy(bitmap, (input, dib, None));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
        if function == 0 {
            break;
        }
    }
    Ok(())
}

/// A COLORREF (red, green, blue, reserved) as `#rrggbb`.
fn color(data: &[u8], at: usize) -> Option<String> {
    let [r, g, b] = crate::bytes::array::<3>(data, at)?;
    Some(format!("#{r:02x}{g:02x}{b:02x}"))
}

fn i16_at(data: &[u8], at: usize) -> Option<i16> {
    i16_le(data, at)
}

fn i32_at(data: &[u8], at: usize) -> Option<i32> {
    i32_le(data, at)
}

/// Where the text of a WMF text record starts and how many bytes it has.
fn wmf_text(function: u16, p: &[u8]) -> Option<(u64, u64)> {
    match function {
        // META_TEXTOUT: StringLength, String, YStart, XStart.
        0x0521 => Some((8, u16_le(p, 6)?.into())),
        // META_EXTTEXTOUT: Y, X, StringLength, fwOpts, [Rectangle], String.
        0x0a32 => {
            let opts = u16_le(p, 12)?;
            let at = if opts & 0x0006 != 0 { 22 } else { 14 };
            Some((at, u16_le(p, 10)?.into()))
        }
        _ => None,
    }
}

/// The parameters of a WMF record worth showing, from its first bytes.
fn wmf_summary(function: u16, p: &[u8]) -> Option<String> {
    // Parameters start at offset 6 and are mostly stored y before x.
    let point = || Some(format!("({}, {})", i16_at(p, 8)?, i16_at(p, 6)?));
    let extent = || Some(dims(i16_at(p, 8)?, i16_at(p, 6)?));
    let rect = || {
        Some(format!(
            "({}, {})–({}, {})",
            i16_at(p, 12)?,
            i16_at(p, 10)?,
            i16_at(p, 8)?,
            i16_at(p, 6)?
        ))
    };
    match function {
        0x020b | 0x020d | 0x0213 | 0x0214 | 0x020f | 0x0211 => point(),
        0x020c | 0x020e => extent(),
        0x0418 | 0x041b | 0x0415 | 0x0416 => rect(),
        0x0103 => Some(lookup(MAP_MODES, u16_le(p, 6)?.into())?.to_owned()),
        0x0102 => Some(lookup(BK_MODES, u16_le(p, 6)?.into())?.to_owned()),
        0x0201 | 0x0209 => color(p, 6),
        0x012d | 0x01f0 | 0x0234 => Some(format!("object {}", u16_le(p, 6)?)),
        0x0127 => Some(format!("saved state {}", i16_at(p, 6)?)),
        0x0324 | 0x0325 => Some(format!("{} points", u16_le(p, 6)?)),
        0x0538 => Some(format!("{} polygons", u16_le(p, 6)?)),
        0x0626 => Some(format!(
            "function {:#06x}, {} bytes",
            u16_le(p, 6)?,
            u16_le(p, 8)?
        )),
        0x02fa => {
            let style = u16_le(p, 6)?;
            Some(format!(
                "{} pen, width {}, {}",
                lookup(PEN_STYLES, u64::from(style & 0x0f)).unwrap_or("unknown"),
                i16_at(p, 8)?,
                color(p, 12)?
            ))
        }
        0x02fc => {
            let style = u16_le(p, 6)?;
            let name = lookup(BRUSH_STYLES, style.into()).unwrap_or("unknown");
            Some(if style == 0 || style == 2 {
                format!("{name} brush, {}", color(p, 8)?)
            } else {
                format!("{name} brush")
            })
        }
        0x02fb => {
            let face = crate::text::until_nul(p.get(24..56).unwrap_or_default());
            Some(format!("{face:?}, height {}", i16_at(p, 6)?))
        }
        _ => None,
    }
}

/// Where the DIB of a WMF bitmap record starts, if it has one.
fn wmf_dib(function: u16, p: &[u8]) -> Option<u64> {
    let at: usize = match function {
        // META_STRETCHDIB: ROP, ColorUsage, 8 coordinates.
        0x0f43 => 28,
        // META_DIBSTRETCHBLT: ROP, 8 coordinates.
        0x0b41 => 26,
        // META_DIBBITBLT: ROP, 6 coordinates.
        0x0940 => 22,
        // META_SETDIBTODEV: ColorUsage, 8 coordinates.
        0x0d33 => 24,
        // META_DIBCREATEPATTERNBRUSH: Style, ColorUsage.
        0x0142 => 10,
        _ => return None,
    };
    // The "without bitmap" variants of the blits have a shorter record; a
    // DIB starts with its header size.
    let size = u32_le(p, at)?;
    matches!(size, 12 | 40 | 52 | 56 | 64 | 108 | 124).then_some(to_u64(at))
}

/// Which EMR_HEADER extensions are present (0, 1 or 2).
fn emf_extensions(header_len: u64, desc_len: u64, desc_off: u64) -> u8 {
    let fits = |end: u64| header_len >= end && (desc_len == 0 || desc_off >= end);
    if fits(108) {
        2
    } else if fits(100) {
        1
    } else {
        0
    }
}

/// EMR_HEADER; returns the frame size (0.01 mm) and the record count.
fn emf_header(f: &mut Fields<'_>, extensions: &u8) -> Result<(i32, i32, u32)> {
    f.u32("Type").emit()?;
    f.u32("Size").emit()?;
    for name in ["Bounds left", "Bounds top", "Bounds right", "Bounds bottom"] {
        f.int::<i32>(name).desc("Device units").emit()?;
    }
    let mut frame = [0i32; 4];
    for (slot, name) in frame.iter_mut().zip([
        "Frame left (0.01 mm)",
        "Frame top (0.01 mm)",
        "Frame right (0.01 mm)",
        "Frame bottom (0.01 mm)",
    ]) {
        *slot = f.int::<i32>(name).emit()?;
    }
    f.ascii("Signature", 4).emit()?;
    f.u32("Version").hex().emit()?;
    f.u32("File size").desc("Of the whole metafile").emit()?;
    let records = f.u32("Records").emit()?;
    f.u16("Handles")
        .desc("Object table entries, plus one")
        .emit()?;
    f.u16("Reserved").emit()?;
    f.u32("Description length (chars)")
        .desc("In UTF-16 characters")
        .emit()?;
    f.u32("Description offset").hex().emit()?;
    f.u32("Palette entries").emit()?;
    f.int::<i32>("Reference device width (px)").emit()?;
    f.int::<i32>("Reference device height (px)").emit()?;
    f.int::<i32>("Reference device width (mm)").emit()?;
    f.int::<i32>("Reference device height (mm)").emit()?;
    if *extensions >= 1 {
        f.u32("Pixel format size").emit()?;
        f.u32("Pixel format offset").hex().emit()?;
        f.u32("OpenGL")
            .desc("1 if the metafile contains OpenGL records")
            .emit()?;
    }
    if *extensions >= 2 {
        f.u32("Reference device width (µm)").emit()?;
        f.u32("Reference device height (µm)").emit()?;
    }
    let [left, top, right, bottom] = frame;
    Ok((
        right.saturating_sub(left),
        bottom.saturating_sub(top),
        records,
    ))
}

pub async fn dissect_emf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let header_len = u64::from(u32_le(&head, 4).unwrap_or(0)).clamp(88, 0x1_0000);
    let span = file.sub(0, header_len);
    let block = cx.block(span).await?;
    let desc_len = u64::from(u32_le(&block.data, 60).unwrap_or(0)).saturating_mul(2);
    let desc_off = u64::from(u32_le(&block.data, 64).unwrap_or(0));
    let extensions = emf_extensions(header_len, desc_len, desc_off);
    let (w, h, records) = emf_header(&mut Fields::new(&block, LE), &extensions)?;
    let size = format!(
        "{} mm",
        dims(
            format!("{:.2}", f64::from(w) / 100.0),
            format!("{:.2}", f64::from(h) / 100.0)
        )
    );
    cx.emit(
        struct_node("EMR_HEADER", span, LE, extensions, emf_header)
            .summary(format!("{size}, {records} records")),
    );
    let mut summary = format!("EMF, {size}, {records} records");
    if desc_len > 0 && desc_off >= 88 {
        let desc_span = file.sub(desc_off, desc_len);
        let text_bytes = cx.read_avail(desc_span).await?;
        let description = crate::text::utf16(&text_bytes, LE).replace('\0', " / ");
        let description = description.trim_end_matches(" / ").to_owned();
        summary = format!("{summary}, {description:?}");
        cx.emit(
            Node::new("Description")
                .span(desc_span)
                .value(text(description))
                .desc("Application name and picture name"),
        );
    }
    cx.annotate(summary);
    let rest = file.tail(header_len);
    cx.emit(
        Node::new("Records")
            .span(rest)
            .summary(format!("{} records", records.saturating_sub(1)))
            .lazy(emf_records, (input, rest)),
    );
    Ok(())
}

async fn emf_records(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos.saturating_add(8) <= span.len && index < MAX_RECORDS {
        let params = cx.read(span.sub(pos, PARAMS)).await?;
        let kind = u32_le(&params, 0).unwrap_or(0);
        let len = u64::from(u32_le(&params, 4).unwrap_or(0));
        if len < 8 {
            cx.diag(
                Diagnostic::malformed(format!("record size {len} is too small"))
                    .at(span.sub(pos, 8)),
            );
            break;
        }
        let record = span.sub(pos, len);
        cx.progress_in(span, record.end());
        let name = lookup(EMF_RECORDS, kind.into())
            .map_or_else(|| format!("Record {kind}"), str::to_owned);
        let params = params
            .get(..crate::bytes::to_usize(len))
            .unwrap_or(params.as_slice());
        let mut node = Node::new(name).span(record);
        let summary = if kind == 83 || kind == 84 {
            // EMR_EXTTEXTOUTA/W: an EmrText at 36 (Reference, Chars,
            // offString, ...).
            match (u32_le(params, 44), u32_le(params, 48)) {
                (Some(chars), Some(at)) => {
                    let wide = kind == 84;
                    let bytes =
                        u64::from(chars)
                            .min(MAX_TEXT)
                            .saturating_mul(if wide { 2 } else { 1 });
                    let data = cx.read_avail(record.sub(at.into(), bytes)).await?;
                    let text = if wide {
                        crate::text::utf16(&data, LE)
                    } else {
                        crate::text::latin1(&data)
                    };
                    Some(format!("{text:?}"))
                }
                _ => None,
            }
        } else if kind == 70 {
            let (summary, plus) = emf_comment(params, len);
            if let Some(plus) = plus {
                let data = record.sub(16, plus);
                node = node.lazy(emfplus_records, data);
            }
            summary
        } else {
            emf_summary(kind, params)
        };
        node = node.summary(summary.unwrap_or_else(|| format!("{len} bytes")));
        if let Some(at) = emf_dib(kind) {
            node = node.lazy(bitmap_record, (input, record, at));
        }
        cx.push(node).await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
        if kind == 14 {
            break;
        }
    }
    Ok(())
}

/// The summary of an EMR_COMMENT, and the length of its EMF+ records.
fn emf_comment(p: &[u8], len: u64) -> (Option<String>, Option<u64>) {
    let data = u64::from(u32_le(p, 8).unwrap_or(0));
    match p.get(12..16) {
        Some(b"EMF+") => {
            let plus = data.saturating_sub(4).min(len.saturating_sub(16));
            (Some(format!("EMF+ records, {plus} bytes")), Some(plus))
        }
        Some(b"GDIC") => {
            let kind = u32_le(p, 16).unwrap_or(0);
            let name = lookup(PUBLIC_COMMENTS, kind.into())
                .map_or_else(|| format!("public comment {kind:#x}"), str::to_owned);
            (Some(name), None)
        }
        _ => (Some(format!("{data} bytes of private data")), None),
    }
}

/// The parameters of an EMF record worth showing, from its first bytes.
fn emf_summary(kind: u32, p: &[u8]) -> Option<String> {
    let point = |at: usize| {
        Some(format!(
            "({}, {})",
            i32_at(p, at)?,
            i32_at(p, at.checked_add(4)?)?
        ))
    };
    let rect = |at: usize| Some(format!("{}–{}", point(at)?, point(at.checked_add(8)?)?));
    let handle = |at: usize| {
        let h = u32_le(p, at)?;
        Some(lookup(STOCK_OBJECTS, h.into()).map_or_else(|| format!("object {h}"), str::to_owned))
    };
    match kind {
        9 | 11 => Some(dims(i32_at(p, 8)?, i32_at(p, 12)?)),
        10 | 12 | 13 | 27 | 54 => point(8),
        42 | 43 | 29 | 30 | 44 => rect(8),
        17 => Some(lookup(MAP_MODES, u32_le(p, 8)?.into())?.to_owned()),
        18 => Some(lookup(BK_MODES, u32_le(p, 8)?.into())?.to_owned()),
        24 | 25 => color(p, 8),
        37 | 40 | 48 => handle(8),
        34 => Some(format!("saved state {}", i32_at(p, 8)?)),
        2..=6 | 85..=89 => Some(format!("{} points", u32_le(p, 24)?)),
        7 | 8 | 90 | 91 => Some(format!(
            "{} polygons, {} points",
            u32_le(p, 24)?,
            u32_le(p, 28)?
        )),
        14 => Some(format!("{} palette entries", u32_le(p, 8)?)),
        38 => {
            let style = u32_le(p, 12)?;
            Some(format!(
                "{}: {} pen, width {}, {}",
                handle(8)?,
                lookup(PEN_STYLES, u64::from(style & 0x0f)).unwrap_or("unknown"),
                i32_at(p, 16)?,
                color(p, 24)?
            ))
        }
        39 => {
            let style = u32_le(p, 12)?;
            let name = lookup(BRUSH_STYLES, style.into()).unwrap_or("unknown");
            Some(if style == 0 || style == 2 {
                format!("{}: {name} brush, {}", handle(8)?, color(p, 16)?)
            } else {
                format!("{}: {name} brush", handle(8)?)
            })
        }
        82 => {
            let face = crate::text::utf16z(p.get(40..104).unwrap_or_default(), LE).0;
            Some(format!(
                "{}: {face:?}, height {}",
                handle(8)?,
                i32_at(p, 12)?
            ))
        }
        _ => None,
    }
}

/// Where the source bitmap's offset/size fields (offBmi, cbBmi, offBits,
/// cbBits) are in the EMF records that carry a DIB.
fn emf_dib(kind: u32) -> Option<u64> {
    match kind {
        // EMR_BITBLT, EMR_STRETCHBLT, EMR_MASKBLT, EMR_ALPHABLEND,
        // EMR_TRANSPARENTBLT: after the destination, ROP/blend, source
        // origin, XformSrc, BkColorSrc and UsageSrc.
        76 | 77 | 78 | 114 | 116 => Some(84),
        // EMR_PLGBLT: three destination points come first.
        79 => Some(96),
        // EMR_SETDIBITSTODEVICE, EMR_STRETCHDIBITS.
        80 | 81 => Some(48),
        // EMR_CREATEMONOBRUSH, EMR_CREATEDIBPATTERNBRUSHPT: ihBrush, Usage.
        93 | 94 => Some(16),
        _ => None,
    }
}

async fn bitmap_record(cx: Cx, (input, record, at): (Input, Span, u64)) -> Result<()> {
    let fields = cx.read_avail(record.sub(at, 16)).await?;
    let (Some(off_bmi), Some(cb_bmi), Some(off_bits), Some(cb_bits)) = (
        u32_le(&fields, 0),
        u32_le(&fields, 4),
        u32_le(&fields, 8),
        u32_le(&fields, 12),
    ) else {
        return Ok(());
    };
    if cb_bmi == 0 {
        cx.emit(
            Node::new("No source bitmap")
                .span(record.sub(at, 16))
                .desc("The operation uses only the destination and the brush"),
        );
        return Ok(());
    }
    // The bitmap header and the bits normally follow each other; show them
    // as one DIB.
    let end = u64::from(off_bits)
        .saturating_add(cb_bits.into())
        .max(u64::from(off_bmi).saturating_add(cb_bmi.into()));
    let dib = record.sub(off_bmi.into(), end.saturating_sub(off_bmi.into()));
    let pixels = u64::from(off_bits).saturating_sub(off_bmi.into());
    bitmap(cx, (input, dib, Some(pixels))).await
}

async fn bitmap(cx: Cx, (input, dib, pixels): (Input, Span, Option<u64>)) -> Result<()> {
    let info = super::bmp::dib(&cx, input, dib, pixels, false).await?;
    cx.annotate(super::bmp::describe(&info));
    Ok(())
}

/// The EMF+ records embedded in an EMR_COMMENT.
async fn emfplus_records(cx: Cx, span: Span) -> Result<()> {
    let mut pos = 0u64;
    while pos.saturating_add(12) <= span.len {
        let head = cx.read(span.sub(pos, 28)).await?;
        let kind = u16_le(&head, 0).unwrap_or(0);
        let flags = u16_le(&head, 2).unwrap_or(0);
        let size = u64::from(u32_le(&head, 4).unwrap_or(0));
        let data = u32_le(&head, 8).unwrap_or(0);
        if size < 12 {
            cx.diag(
                Diagnostic::malformed(format!("EMF+ record size {size} is too small"))
                    .at(span.sub(pos, 12)),
            );
            break;
        }
        let name = lookup(EMFPLUS_RECORDS, kind.into())
            .map_or_else(|| format!("EMF+ record {kind:#06x}"), str::to_owned);
        let summary = match kind {
            0x4001 => {
                let version = u32_le(&head, 12).unwrap_or(0);
                format!(
                    "version {version:#x}, {} dpi{}",
                    dims(
                        u32_le(&head, 20).unwrap_or(0),
                        u32_le(&head, 24).unwrap_or(0)
                    ),
                    if flags & 1 != 0 {
                        ", dual (EMF+ and EMF)"
                    } else {
                        ""
                    }
                )
            }
            0x4008 => {
                let object = u64::from((flags >> 8) & 0x7f);
                format!(
                    "{} {}{}, {data} bytes",
                    lookup(EMFPLUS_OBJECTS, object).unwrap_or("object"),
                    flags & 0xff,
                    if flags & 0x8000 != 0 {
                        " (continued)"
                    } else {
                        ""
                    }
                )
            }
            _ => format!("{data} bytes"),
        };
        cx.push(Node::new(name).span(span.sub(pos, size)).summary(summary))
            .await;
        pos = pos.saturating_add(size);
    }
    Ok(())
}
