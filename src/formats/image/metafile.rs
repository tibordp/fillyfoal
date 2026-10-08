//! Windows metafiles: WMF (16-bit, optionally with an Aldus placeable
//! header) and EMF (32-bit enhanced metafiles, including EMF+ comments).
//!
//! Both are a header followed by drawing records; records are listed in
//! pages with their function names.

use crate::bytes::{u16_le, u32_le};
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

record! {
    pub struct Placeable {
        key: u32 "Key" .hex(),
        hmf: u16 "Handle",
        left: i16 "Left",
        top: i16 "Top",
        right: i16 "Right",
        bottom: i16 "Bottom",
        inch: u16 "Units per inch",
        reserved: u32 "Reserved",
        checksum: u16 "Checksum" .hex(),
    }
}

record! {
    pub struct WmfHeader {
        kind: u16 "Type" .desc("1 = memory, 2 = disk"),
        header_size: u16 "Header size" .desc("In 16-bit words"),
        version: u16 "Version" .hex(),
        size: u32 "Size" .desc("In 16-bit words"),
        objects: u16 "Number of objects",
        max_record: u32 "Largest record" .desc("In 16-bit words"),
        params: u16 "Number of parameters",
    }
}

/// Records listed before giving up on a bogus file.
const MAX_RECORDS: u64 = 10_000_000;

pub async fn dissect_wmf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read_avail(file.sub(0, 4)).await?;
    let mut pos = 0u64;
    let mut size_summary = String::new();
    if magic == PLACEABLE {
        let span = file.sub(0, Placeable::SIZE);
        let p = parse(&cx, span, LE, &(), Placeable::layout).await?;
        cx.emit(Placeable::node("Placeable header", span, LE));
        let w = i32::from(p.right).saturating_sub(p.left.into());
        let h = i32::from(p.bottom).saturating_sub(p.top.into());
        size_summary = format!(", {} units at {} per inch", dims(w, h), p.inch);
        pos = Placeable::SIZE;
    }
    let span = file.sub(pos, WmfHeader::SIZE);
    let h = parse(&cx, span, LE, &(), WmfHeader::layout).await?;
    cx.emit(WmfHeader::node("Header", span, LE));
    cx.annotate(format!("WMF{size_summary}, {} objects", h.objects));
    pos = pos.saturating_add(u64::from(h.header_size).saturating_mul(2));
    let records = file.tail(pos);
    cx.emit(
        Node::new("Records")
            .span(records)
            .lazy(wmf_records, records),
    );
    Ok(())
}

async fn wmf_records(cx: Cx, span: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos.saturating_add(6) <= span.len && index < MAX_RECORDS {
        let head = cx.read(span.sub(pos, 6)).await?;
        let words = u64::from(u32_le(&head, 0).unwrap_or(0));
        let function = u16_le(&head, 4).unwrap_or(0);
        let len = words.saturating_mul(2);
        if len < 6 {
            return Err(
                Diagnostic::malformed(format!("record size {len} is too small"))
                    .at(span.sub(pos, 6)),
            );
        }
        let record = span.sub(pos, len);
        cx.progress_in(span, record.end());
        let name = lookup(WMF_RECORDS, function.into())
            .map_or_else(|| format!("Record {function:#06x}"), str::to_owned);
        cx.push(Node::new(name).span(record).summary(format!("{len} bytes")))
            .await;
        pos = pos.saturating_add(len);
        index = index.saturating_add(1);
        if function == 0 {
            break;
        }
    }
    Ok(())
}

/// EMR_HEADER; returns the frame size (0.01 mm) and the record count.
fn emf_header(f: &mut Fields<'_>, _: &()) -> Result<(i32, i32, u32)> {
    f.u32("Type").emit()?;
    f.u32("Size").emit()?;
    for name in ["Bounds left", "Bounds top", "Bounds right", "Bounds bottom"] {
        f.int::<i32>(name).desc("Device units").emit()?;
    }
    let mut frame = [0i32; 4];
    for (slot, name) in
        frame
            .iter_mut()
            .zip(["Frame left", "Frame top", "Frame right", "Frame bottom"])
    {
        *slot = f.int::<i32>(name).desc("0.01 mm").emit()?;
    }
    f.ascii("Signature", 4).emit()?;
    f.u32("Version").hex().emit()?;
    f.u32("Bytes").emit()?;
    let records = f.u32("Records").emit()?;
    f.u16("Handles").emit()?;
    f.u16("Reserved").emit()?;
    f.u32("Description length")
        .desc("In UTF-16 characters")
        .emit()?;
    f.u32("Description offset").hex().emit()?;
    f.u32("Palette entries").emit()?;
    f.int::<i32>("Reference device width")
        .desc("Pixels")
        .emit()?;
    f.int::<i32>("Reference device height")
        .desc("Pixels")
        .emit()?;
    f.int::<i32>("Reference device width (mm)").emit()?;
    f.int::<i32>("Reference device height (mm)").emit()?;
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
    let (w, h, records) = emf_header(&mut Fields::new(&block, LE), &())?;
    cx.emit(struct_node("EMR_HEADER", span, LE, (), emf_header));
    let desc_len = u64::from(u32_le(&block.data, 64).unwrap_or(0)).saturating_mul(2);
    let desc_off = u64::from(u32_le(&block.data, 68).unwrap_or(0));
    let mut summary = format!(
        "EMF, {} mm, {records} records",
        dims(f64::from(w) / 100.0, f64::from(h) / 100.0)
    );
    if desc_len > 0 && desc_off >= 88 {
        let desc_span = file.sub(desc_off, desc_len);
        let text_bytes = cx.read_avail(desc_span).await?;
        let description = crate::text::utf16(&text_bytes, LE).replace('\0', " / ");
        let description = description.trim_end_matches(" / ").to_owned();
        summary = format!("{summary}, {description:?}");
        cx.emit(
            Node::new("Description")
                .span(desc_span)
                .value(text(description)),
        );
    }
    cx.annotate(summary);
    let rest = file.tail(header_len);
    cx.emit(
        Node::new("Records")
            .span(rest)
            .lazy(emf_records, (input, rest)),
    );
    Ok(())
}

async fn emf_records(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
    let mut index = 0u64;
    while pos.saturating_add(8) <= span.len && index < MAX_RECORDS {
        let head = cx.read(span.sub(pos, 12)).await?;
        let kind = u32_le(&head, 0).unwrap_or(0);
        let len = u64::from(u32_le(&head, 4).unwrap_or(0));
        if len < 8 {
            return Err(
                Diagnostic::malformed(format!("record size {len} is too small"))
                    .at(span.sub(pos, 8)),
            );
        }
        let record = span.sub(pos, len);
        cx.progress_in(span, record.end());
        let name = lookup(EMF_RECORDS, kind.into())
            .map_or_else(|| format!("Record {kind}"), str::to_owned);
        let mut node = Node::new(name).span(record).summary(format!("{len} bytes"));
        if kind == 70 {
            // EMR_COMMENT: data size, then an identifier such as "EMF+".
            let id = cx.read_avail(record.sub(12, 4)).await?;
            if id == b"EMF+" {
                node = node.summary(format!("EMF+ records, {len} bytes"));
            }
        }
        if matches!(kind, 76 | 77 | 80 | 81) {
            node = node.lazy(bitmap_record, (input, record, kind));
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

/// Offsets of the bitmap header and bits in the records that carry a DIB.
fn dib_offsets(kind: u32) -> Option<u64> {
    match kind {
        76 => Some(84),
        77 => Some(88),
        80 => Some(48),
        81 => Some(48),
        _ => None,
    }
}

async fn bitmap_record(cx: Cx, (input, record, kind): (Input, Span, u32)) -> Result<()> {
    let Some(at) = dib_offsets(kind) else {
        return Ok(());
    };
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
        return Ok(());
    }
    // The bitmap header and the bits normally follow each other; show them
    // as one DIB.
    let end = u64::from(off_bits)
        .saturating_add(cb_bits.into())
        .max(u64::from(off_bmi).saturating_add(cb_bmi.into()));
    let dib = record.sub(off_bmi.into(), end.saturating_sub(off_bmi.into()));
    let pixels = u64::from(off_bits).saturating_sub(off_bmi.into());
    cx.emit(
        Node::new("Device-independent bitmap")
            .span(dib)
            .lazy(bitmap, (input, dib, pixels)),
    );
    Ok(())
}

async fn bitmap(cx: Cx, (input, dib, pixels): (Input, Span, u64)) -> Result<()> {
    let info = super::bmp::dib(&cx, input, dib, Some(pixels), false).await?;
    cx.annotate(super::bmp::describe(&info));
    Ok(())
}
