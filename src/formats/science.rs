//! Scientific, medical and geospatial formats.

use crate::bytes::{u16_be, u16_le, u32_be, u32_le, u64_be};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::{Cursor, Record, read_record};
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Head, Input, Probe};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

fn text(s: impl Into<String>) -> Value {
    Value::Text(s.into())
}

// ---------------------------------------------------------------------------
// FITS

declare_format!(pub FITS = "fits", "Flexible Image Transport System", ["fits", "fit", "fts"], "image/fits",
    Probe::Magic(&[(0, b"SIMPLE  =")]), fits);

const FITS_BLOCK: u64 = 2880;

/// The cards of one header, and where it ends.
struct FitsHeader {
    cards: Vec<(String, String, Span)>,
    end: u64,
}

async fn fits_header(cx: &Cx, file: Span, start: u64) -> Result<FitsHeader> {
    let mut cards = Vec::new();
    let mut pos = start;
    loop {
        let block = cx.read(file.sub_exact(pos, FITS_BLOCK)?).await?;
        for i in 0..36u64 {
            let card = block
                .get(
                    crate::bytes::to_usize(i.saturating_mul(80))
                        ..crate::bytes::to_usize(i.saturating_add(1).saturating_mul(80)),
                )
                .unwrap_or_default();
            let line = String::from_utf8_lossy(card).into_owned();
            let keyword = line.get(..8).unwrap_or_default().trim().to_owned();
            let span = file.sub(pos.saturating_add(i.saturating_mul(80)), 80);
            if keyword == "END" {
                return Ok(FitsHeader {
                    cards,
                    end: pos.saturating_add(FITS_BLOCK),
                });
            }
            if !keyword.is_empty() {
                let value = line
                    .get(8..)
                    .unwrap_or_default()
                    .trim_start_matches(['=', ' '])
                    .trim_end()
                    .to_owned();
                cards.push((keyword, value, span));
            }
        }
        pos = pos.saturating_add(FITS_BLOCK);
        cx.checkpoint().await;
        if cards.len() > 100_000 {
            return Err(Diagnostic::limit("FITS header has too many cards"));
        }
    }
}

fn fits_value(cards: &[(String, String, Span)], key: &str) -> Option<String> {
    cards.iter().find(|(k, _, _)| k == key).map(|(_, v, _)| {
        v.split('/')
            .next()
            .unwrap_or_default()
            .trim()
            .trim_matches('\'')
            .trim()
            .to_owned()
    })
}

fn fits_int(cards: &[(String, String, Span)], key: &str) -> Option<i64> {
    fits_value(cards, key)?.parse().ok()
}

async fn fits(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut index = 0u32;
    let mut first = None;
    while pos < file.len {
        let header = fits_header(&cx, file, pos).await?;
        let cards = &header.cards;
        let bitpix = fits_int(cards, "BITPIX").unwrap_or(8).unsigned_abs() / 8;
        let naxis = fits_int(cards, "NAXIS").unwrap_or(0);
        let mut size: u64 = if naxis > 0 { 1 } else { 0 };
        let mut dims = Vec::new();
        for n in 1..=naxis.min(999) {
            let d = fits_int(cards, &format!("NAXIS{n}"))
                .unwrap_or(0)
                .max(0)
                .unsigned_abs();
            dims.push(d.to_string());
            size = size.saturating_mul(d);
        }
        let pcount = fits_int(cards, "PCOUNT").unwrap_or(0).max(0).unsigned_abs();
        let gcount = fits_int(cards, "GCOUNT").unwrap_or(1).max(1).unsigned_abs();
        let data_len = bitpix.saturating_mul(gcount.saturating_mul(pcount.saturating_add(size)));
        let padded = data_len.div_ceil(FITS_BLOCK).saturating_mul(FITS_BLOCK);
        let kind = fits_value(cards, "XTENSION").unwrap_or_else(|| "PRIMARY".to_owned());
        let describe = format!(
            "{kind}, BITPIX {}, {}",
            fits_int(cards, "BITPIX").unwrap_or(0),
            if dims.is_empty() {
                "no data".to_owned()
            } else {
                dims.join("×")
            }
        );
        if first.is_none() {
            first = Some(describe.clone());
        }
        let hdu = file.sub(pos, header.end.saturating_sub(pos).saturating_add(padded));
        let data = file.sub(header.end, data_len);
        cx.push(
            Node::new(format!("HDU {index}"))
                .span(hdu)
                .summary(describe)
                .lazy(fits_hdu, (header.cards, data)),
        )
        .await;
        pos = header.end.saturating_add(padded);
        index = index.saturating_add(1);
    }
    cx.annotate(format!("{} HDU(s); {}", index, first.unwrap_or_default()));
    Ok(())
}

async fn fits_hdu(cx: Cx, (cards, data): (Vec<(String, String, Span)>, Span)) -> Result<()> {
    for (keyword, value, span) in cards {
        let (value, comment) = match value.split_once(" /") {
            Some((v, c)) => (v.trim().to_owned(), Some(c.trim().to_owned())),
            None => (value, None),
        };
        let mut node = Node::new(keyword)
            .span(span)
            .value(text(value.trim_matches('\'').trim()));
        if let Some(c) = comment {
            node = node.desc(c);
        }
        cx.push(node).await;
    }
    if data.len > 0 {
        cx.emit(Node::new("Data").span(data));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// DICOM

declare_format!(pub DICOM = "dicom", "DICOM medical image", ["dcm", "dicom"], "application/dicom",
    Probe::Magic(&[(128, b"DICM")]), dicom);

/// (group, element, VR, name) for common attributes.
const DICOM_TAGS: &[(u16, u16, &str, &str)] = &[
    (0x0002, 0x0000, "UL", "File Meta Information Group Length"),
    (0x0002, 0x0001, "OB", "File Meta Information Version"),
    (0x0002, 0x0002, "UI", "Media Storage SOP Class UID"),
    (0x0002, 0x0003, "UI", "Media Storage SOP Instance UID"),
    (0x0002, 0x0010, "UI", "Transfer Syntax UID"),
    (0x0002, 0x0012, "UI", "Implementation Class UID"),
    (0x0002, 0x0013, "SH", "Implementation Version Name"),
    (0x0008, 0x0005, "CS", "Specific Character Set"),
    (0x0008, 0x0008, "CS", "Image Type"),
    (0x0008, 0x0016, "UI", "SOP Class UID"),
    (0x0008, 0x0018, "UI", "SOP Instance UID"),
    (0x0008, 0x0020, "DA", "Study Date"),
    (0x0008, 0x0021, "DA", "Series Date"),
    (0x0008, 0x0030, "TM", "Study Time"),
    (0x0008, 0x0050, "SH", "Accession Number"),
    (0x0008, 0x0060, "CS", "Modality"),
    (0x0008, 0x0070, "LO", "Manufacturer"),
    (0x0008, 0x0080, "LO", "Institution Name"),
    (0x0008, 0x0090, "PN", "Referring Physician's Name"),
    (0x0008, 0x1030, "LO", "Study Description"),
    (0x0008, 0x103e, "LO", "Series Description"),
    (0x0008, 0x1090, "LO", "Manufacturer's Model Name"),
    (0x0008, 0x1140, "SQ", "Referenced Image Sequence"),
    (0x0008, 0x1150, "UI", "Referenced SOP Class UID"),
    (0x0008, 0x1155, "UI", "Referenced SOP Instance UID"),
    (0x0010, 0x0010, "PN", "Patient's Name"),
    (0x0010, 0x0020, "LO", "Patient ID"),
    (0x0010, 0x0030, "DA", "Patient's Birth Date"),
    (0x0010, 0x0040, "CS", "Patient's Sex"),
    (0x0010, 0x1010, "AS", "Patient's Age"),
    (0x0018, 0x0015, "CS", "Body Part Examined"),
    (0x0018, 0x0050, "DS", "Slice Thickness"),
    (0x0018, 0x0088, "DS", "Spacing Between Slices"),
    (0x0018, 0x1020, "LO", "Software Versions"),
    (0x0018, 0x5100, "CS", "Patient Position"),
    (0x0020, 0x000d, "UI", "Study Instance UID"),
    (0x0020, 0x000e, "UI", "Series Instance UID"),
    (0x0020, 0x0010, "SH", "Study ID"),
    (0x0020, 0x0011, "IS", "Series Number"),
    (0x0020, 0x0013, "IS", "Instance Number"),
    (0x0020, 0x0032, "DS", "Image Position (Patient)"),
    (0x0020, 0x0037, "DS", "Image Orientation (Patient)"),
    (0x0020, 0x0052, "UI", "Frame of Reference UID"),
    (0x0028, 0x0002, "US", "Samples per Pixel"),
    (0x0028, 0x0004, "CS", "Photometric Interpretation"),
    (0x0028, 0x0008, "IS", "Number of Frames"),
    (0x0028, 0x0010, "US", "Rows"),
    (0x0028, 0x0011, "US", "Columns"),
    (0x0028, 0x0030, "DS", "Pixel Spacing"),
    (0x0028, 0x0100, "US", "Bits Allocated"),
    (0x0028, 0x0101, "US", "Bits Stored"),
    (0x0028, 0x0102, "US", "High Bit"),
    (0x0028, 0x0103, "US", "Pixel Representation"),
    (0x0028, 0x1050, "DS", "Window Center"),
    (0x0028, 0x1051, "DS", "Window Width"),
    (0x0028, 0x1052, "DS", "Rescale Intercept"),
    (0x0028, 0x1053, "DS", "Rescale Slope"),
    (0x7fe0, 0x0010, "OW", "Pixel Data"),
    (0xfffe, 0xe000, "", "Item"),
    (0xfffe, 0xe00d, "", "Item Delimitation Item"),
    (0xfffe, 0xe0dd, "", "Sequence Delimitation Item"),
];

const DICOM_UIDS: &[(&str, &str)] = &[
    ("1.2.840.10008.1.2", "Implicit VR Little Endian"),
    ("1.2.840.10008.1.2.1", "Explicit VR Little Endian"),
    (
        "1.2.840.10008.1.2.1.99",
        "Deflated Explicit VR Little Endian",
    ),
    ("1.2.840.10008.1.2.2", "Explicit VR Big Endian"),
    ("1.2.840.10008.1.2.4.50", "JPEG Baseline"),
    ("1.2.840.10008.1.2.4.51", "JPEG Extended"),
    ("1.2.840.10008.1.2.4.57", "JPEG Lossless"),
    ("1.2.840.10008.1.2.4.70", "JPEG Lossless SV1"),
    ("1.2.840.10008.1.2.4.80", "JPEG-LS Lossless"),
    ("1.2.840.10008.1.2.4.81", "JPEG-LS Near-Lossless"),
    ("1.2.840.10008.1.2.4.90", "JPEG 2000 Lossless"),
    ("1.2.840.10008.1.2.4.91", "JPEG 2000"),
    ("1.2.840.10008.1.2.5", "RLE Lossless"),
    (
        "1.2.840.10008.5.1.4.1.1.1",
        "Computed Radiography Image Storage",
    ),
    ("1.2.840.10008.5.1.4.1.1.2", "CT Image Storage"),
    ("1.2.840.10008.5.1.4.1.1.4", "MR Image Storage"),
    ("1.2.840.10008.5.1.4.1.1.6.1", "Ultrasound Image Storage"),
    (
        "1.2.840.10008.5.1.4.1.1.7",
        "Secondary Capture Image Storage",
    ),
    ("1.2.840.10008.5.1.4.1.1.128", "PET Image Storage"),
];

fn dicom_tag(group: u16, element: u16) -> Option<(&'static str, &'static str)> {
    DICOM_TAGS
        .iter()
        .find(|(g, e, _, _)| *g == group && *e == element)
        .map(|(_, _, vr, name)| (*vr, *name))
}

/// VRs whose explicit encoding has a 2-byte reserved field and 4-byte length.
fn long_vr(vr: &[u8]) -> bool {
    matches!(
        vr,
        b"OB"
            | b"OW"
            | b"OF"
            | b"OD"
            | b"OL"
            | b"OV"
            | b"SQ"
            | b"UT"
            | b"UN"
            | b"UC"
            | b"UR"
            | b"SV"
            | b"UV"
    )
}

#[derive(Clone, Copy, Debug)]
struct Encoding {
    explicit: bool,
    endian: Endian,
}

async fn dicom(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(Node::new("Preamble").span(file.sub(0, 128)));
    cx.emit(
        Node::new("Prefix")
            .span(file.sub(128, 4))
            .value(text("DICM")),
    );
    // The meta group is always explicit little endian; its length is known.
    let meta_head = cx.read(file.sub(132, 12)).await?;
    let meta_len = if meta_head.get(0..4) == Some(&[2, 0, 0, 0]) {
        u64::from(u32_le(&meta_head, 8).unwrap_or(0)).saturating_add(12)
    } else {
        0
    };
    let meta = file.sub(132, meta_len);
    let meta_bytes = cx.read_avail(meta).await?;
    let syntax = find_uid(&meta_bytes, 0x0010).unwrap_or_default();
    let syntax_name = DICOM_UIDS
        .iter()
        .find(|(u, _)| *u == syntax)
        .map_or("unknown transfer syntax", |(_, n)| n);
    cx.emit(Node::new("File Meta Information").span(meta).lazy(
        dicom_elements,
        (
            meta,
            Encoding {
                explicit: true,
                endian: LE,
            },
            0u32,
        ),
    ));
    let encoding = match syntax.as_str() {
        "1.2.840.10008.1.2" => Encoding {
            explicit: false,
            endian: LE,
        },
        "1.2.840.10008.1.2.2" => Encoding {
            explicit: true,
            endian: BE,
        },
        _ => Encoding {
            explicit: true,
            endian: LE,
        },
    };
    let dataset = file.tail(132u64.saturating_add(meta_len));
    if syntax.ends_with(".99") {
        cx.emit(crate::formats::content(
            "Data Set (deflated)",
            input,
            dataset,
            crate::formats::Codec::Deflate,
            None,
        ));
    } else {
        cx.emit(
            Node::new("Data Set")
                .span(dataset)
                .lazy(dicom_elements, (dataset, encoding, 0u32)),
        );
    }
    let sop = find_uid(&meta_bytes, 0x0002).unwrap_or_default();
    let sop_name = DICOM_UIDS
        .iter()
        .find(|(u, _)| *u == sop)
        .map_or(sop.as_str(), |(_, n)| n);
    cx.annotate(format!("{sop_name}, {syntax_name}"));
    Ok(())
}

/// Finds a UI value in the (explicit LE) meta group by element number.
fn find_uid(meta: &[u8], element: u16) -> Option<String> {
    let mut at = 0usize;
    while at.saturating_add(8) <= meta.len() {
        let e = u16_le(meta, at.saturating_add(2))?;
        let vr = meta.get(at.saturating_add(4)..at.saturating_add(6))?;
        let (len, header) = if long_vr(vr) {
            (u32_le(meta, at.saturating_add(8))? as usize, 12usize)
        } else {
            (usize::from(u16_le(meta, at.saturating_add(6))?), 8)
        };
        let value =
            meta.get(at.saturating_add(header)..at.saturating_add(header).saturating_add(len))?;
        if e == element {
            return Some(
                String::from_utf8_lossy(value)
                    .trim_end_matches(['\0', ' '])
                    .to_owned(),
            );
        }
        at = at.saturating_add(header).saturating_add(len);
    }
    None
}

const UNDEFINED: u32 = 0xffff_ffff;

async fn dicom_elements(cx: Cx, (span, enc, depth): (Span, Encoding, u32)) -> Result<()> {
    if depth > 16 {
        return Err(Diagnostic::limit("DICOM sequences nested too deeply"));
    }
    let mut cur = Cursor::new(&cx, span, enc.endian);
    while cur.remaining() >= 8 {
        let start = cur.pos();
        let group = cur.u16().await?;
        let element = cur.u16().await?;
        let known = dicom_tag(group, element);
        // Items and delimiters have no VR, even in explicit encodings.
        let (vr, len) = if group == 0xfffe {
            (String::new(), cur.u32().await?)
        } else if enc.explicit {
            let vr = cur.bytes(2).await?;
            let len = if long_vr(&vr) {
                cur.skip(2);
                cur.u32().await?
            } else {
                u32::from(cur.u16().await?)
            };
            (String::from_utf8_lossy(&vr).into_owned(), len)
        } else {
            (
                known.map_or("UN", |(vr, _)| vr).to_owned(),
                cur.u32().await?,
            )
        };
        let name = known.map_or_else(
            || format!("({group:04x},{element:04x})"),
            |(_, n)| n.to_owned(),
        );
        let label = format!("{name} [{vr}]");
        let value_start = cur.pos();
        if group == 0xfffe && element != 0xe000 {
            cx.push(Node::new(label).span(cur.since(start))).await;
            if element == 0xe0dd {
                break;
            }
            continue;
        }
        let undefined = len == UNDEFINED;
        let body = if undefined {
            cur.region().tail(value_start)
        } else {
            cur.span(len.into())
        };
        let mut node = Node::new(label);
        if vr == "SQ" || (group == 0xfffe && element == 0xe000) || (undefined && group != 0x7fe0) {
            // Nested data sets: an item's body holds elements; a sequence's
            // body holds items. Undefined lengths end at a delimiter.
            node = node.lazy(
                crate::expander!(self::dicom_elements: (Span, Encoding, u32)),
                (body, enc, depth.saturating_add(1)),
            );
            if undefined {
                let end = find_delimiter(
                    &cx,
                    body,
                    enc.endian,
                    if vr == "SQ" { 0xe0dd } else { 0xe00d },
                )
                .await?;
                cur.seek(value_start.saturating_add(end));
                node = node.span(cur.since(start));
            } else {
                cur.skip(len.into());
                node = node.span(cur.since(start));
            }
        } else if undefined {
            // Encapsulated pixel data: fragments until a sequence delimiter.
            let end = find_delimiter(&cx, body, enc.endian, 0xe0dd).await?;
            node = node
                .span(span.sub(start, value_start.saturating_add(end).saturating_sub(start)))
                .summary("encapsulated")
                .lazy(
                    crate::expander!(self::dicom_elements: (Span, Encoding, u32)),
                    (
                        body.sub(0, end),
                        Encoding {
                            explicit: false,
                            endian: enc.endian,
                        },
                        depth.saturating_add(1),
                    ),
                );
            cur.seek(value_start.saturating_add(end));
        } else {
            cur.skip(len.into());
            node = node.span(cur.since(start));
            if let Some(value) = dicom_value(&cx, &vr, body, enc.endian).await? {
                node = node.value(value);
            } else if group == 0x7fe0 || len > 64 {
                node = node.summary(format!("{len} bytes"));
            }
        }
        cx.push(node).await;
    }
    Ok(())
}

/// Finds the end (just past) of a delimiter item with `element` in `span`,
/// skipping over nested items with defined lengths.
async fn find_delimiter(cx: &Cx, span: Span, endian: Endian, element: u16) -> Result<u64> {
    let mut cur = Cursor::new(cx, span, endian);
    let mut depth = 0u32;
    while cur.remaining() >= 8 {
        let group = cur.u16().await?;
        let e = cur.u16().await?;
        if group == 0xfffe {
            let len = cur.u32().await?;
            match e {
                0xe000 if len != UNDEFINED => cur.skip(len.into()),
                0xe000 => depth = depth.saturating_add(1),
                0xe00d if depth > 0 && element != 0xe00d => depth = depth.saturating_sub(1),
                _ if e == element && depth == 0 => return Ok(cur.pos()),
                0xe0dd if depth > 0 => {}
                _ => {}
            }
        } else {
            // Inside an item with undefined length: an element. Skip it
            // using explicit-VR heuristics (best effort).
            let vr = cur.peek(2).await?;
            if vr.iter().all(u8::is_ascii_uppercase) {
                cur.skip(2);
                let len = if long_vr(&vr) {
                    cur.skip(2);
                    cur.u32().await?
                } else {
                    u32::from(cur.u16().await?)
                };
                if len != UNDEFINED {
                    cur.skip(len.into());
                }
            } else {
                let len = cur.u32().await?;
                if len != UNDEFINED {
                    cur.skip(len.into());
                }
            }
        }
        cx.checkpoint().await;
    }
    Ok(span.len)
}

async fn dicom_value(cx: &Cx, vr: &str, span: Span, endian: Endian) -> Result<Option<Value>> {
    if span.len > 1024 {
        return Ok(None);
    }
    let bytes = cx.read_avail(span).await?;
    let num = |n: usize| -> Option<u64> {
        let b = bytes.get(..n)?;
        let mut v = 0u64;
        for (i, byte) in b.iter().enumerate() {
            let shift = if endian == LE {
                i
            } else {
                n.saturating_sub(i).saturating_sub(1)
            };
            v |= u64::from(*byte).checked_shl(u32::try_from(shift.saturating_mul(8)).ok()?)?;
        }
        Some(v)
    };
    Ok(match vr {
        "AE" | "AS" | "CS" | "DA" | "DS" | "DT" | "IS" | "LO" | "LT" | "PN" | "SH" | "ST"
        | "TM" | "UI" | "UC" | "UR" | "UT" => {
            let s = String::from_utf8_lossy(&bytes)
                .trim_end_matches(['\0', ' '])
                .to_owned();
            let named = if vr == "UI" {
                DICOM_UIDS
                    .iter()
                    .find(|(u, _)| *u == s)
                    .map(|(_, n)| format!("{s} ({n})"))
            } else {
                None
            };
            Some(text(named.unwrap_or(s)))
        }
        "US" => num(2).map(|v| Value::UInt {
            value: v,
            bits: 16,
            radix: Radix::Dec,
        }),
        "UL" => num(4).map(|v| Value::UInt {
            value: v,
            bits: 32,
            radix: Radix::Dec,
        }),
        "SS" => num(2).map(|v| Value::Int {
            value: i64::from(v as u16 as i16),
            bits: 16,
        }),
        "SL" => num(4).map(|v| Value::Int {
            value: i64::from(v as u32 as i32),
            bits: 32,
        }),
        "FL" => num(4).map(|v| Value::Float(f64::from(f32::from_bits(v as u32)))),
        "FD" => num(8).map(|v| Value::Float(f64::from_bits(v))),
        "AT" => match (num(2), bytes.get(2..4)) {
            (Some(g), Some(_)) => {
                let e = if endian == LE {
                    u16_le(&bytes, 2)
                } else {
                    u16_be(&bytes, 2)
                }
                .unwrap_or(0);
                Some(text(format!("({g:04x},{e:04x})")))
            }
            _ => None,
        },
        _ => None,
    })
}

// ---------------------------------------------------------------------------
// ESRI Shapefile (.shp / .shx) and dBase tables (.dbf)

const SHAPE_TYPES: EnumTable = &[
    (0, "Null"),
    (1, "Point"),
    (3, "PolyLine"),
    (5, "Polygon"),
    (8, "MultiPoint"),
    (11, "PointZ"),
    (13, "PolyLineZ"),
    (15, "PolygonZ"),
    (18, "MultiPointZ"),
    (21, "PointM"),
    (23, "PolyLineM"),
    (25, "PolygonM"),
    (28, "MultiPointM"),
    (31, "MultiPatch"),
];

fn shape_header(h: &Head<'_>) -> bool {
    h.at(0, b"\x00\x00\x27\x0a") && u32_le(h.data, 28) == Some(1000)
}

fn shx_probe(h: &Head<'_>) -> bool {
    shape_header(h)
        && h.len >= 100
        && h.len.saturating_sub(100).is_multiple_of(8)
        && (h.len == 100 || u32_be(h.data, 100) == Some(50))
}

declare_format!(pub SHX = "shx", "ESRI shapefile index", ["shx"], "application/x-esri-shape-index",
    Probe::Custom(shx_probe), shx);
declare_format!(pub SHP = "shp", "ESRI shapefile", ["shp"], "application/x-esri-shape",
    Probe::Custom(shape_header), shp);

record! {
    pub struct ShapeHeader {
        code: u32 "File code" .desc("9994"),
        _unused: bytes[20] "Unused",
        length: u32 "File length (16-bit words)",
    }
}

record! {
    pub struct ShapeBounds {
        version: u32 "Version",
        shape: u32 "Shape type" .enumeration(SHAPE_TYPES),
        x_min: f64 "X min",
        y_min: f64 "Y min",
        x_max: f64 "X max",
        y_max: f64 "Y max",
        z_min: f64 "Z min",
        z_max: f64 "Z max",
        m_min: f64 "M min",
        m_max: f64 "M max",
    }
}

async fn shape_common(cx: &Cx, file: Span) -> Result<ShapeBounds> {
    cx.emit(ShapeHeader::node(
        "File header",
        file.sub(0, ShapeHeader::SIZE),
        BE,
    ));
    let span = file.sub(ShapeHeader::SIZE, ShapeBounds::SIZE);
    let b: ShapeBounds = read_record(cx, span, LE).await?;
    cx.emit(ShapeBounds::node("Bounds", span, LE));
    Ok(b)
}

async fn shp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let b = shape_common(&cx, file).await?;
    let records = file.tail(100);
    cx.emit(
        Node::new("Records")
            .span(records)
            .lazy(shp_records, records),
    );
    let kind = lookup(SHAPE_TYPES, b.shape.into()).unwrap_or("unknown shapes");
    cx.annotate(format!(
        "{kind}, x {}..{}, y {}..{}",
        b.x_min, b.x_max, b.y_min, b.y_max
    ));
    Ok(())
}

async fn shp_records(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, BE);
    while cur.remaining() >= 12 {
        let start = cur.pos();
        let number = cur.u32().await?;
        let words = cur.u32().await?;
        let content = cur.span(u64::from(words).saturating_mul(2));
        let kind = u32_le(&cx.read_avail(content.sub(0, 4)).await?, 0).unwrap_or(0);
        cur.skip(u64::from(words).saturating_mul(2));
        let name = lookup(SHAPE_TYPES, kind.into()).unwrap_or("unknown");
        cx.push(
            Node::new(format!("Record {number}"))
                .span(cur.since(start))
                .summary(name),
        )
        .await;
    }
    Ok(())
}

async fn shx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let b = shape_common(&cx, file).await?;
    let count = file.len.saturating_sub(100) / 8;
    cx.emit(
        Node::new("Index")
            .span(file.tail(100))
            .summary(format!("{count} records"))
            .lazy(shx_index, file.tail(100)),
    );
    let kind = lookup(SHAPE_TYPES, b.shape.into()).unwrap_or("unknown shapes");
    cx.annotate(format!("index of {count} {kind} records"));
    Ok(())
}

async fn shx_index(cx: Cx, span: Span) -> Result<()> {
    let count = span.len / 8;
    cx.set_count(Count::Exact(count));
    let mut cur = Cursor::new(&cx, span, BE);
    for i in 0..count {
        let at = cur.span(8);
        let offset = cur.u32().await?;
        let words = cur.u32().await?;
        cx.push(
            Node::new(format!("Record {}", i.saturating_add(1)))
                .span(at)
                .summary(format!(
                    "offset {:#x}, {} bytes",
                    u64::from(offset).saturating_mul(2),
                    u64::from(words).saturating_mul(2)
                )),
        )
        .await;
    }
    Ok(())
}

const DBF_VERSIONS: EnumTable = &[
    (0x02, "FoxBASE"),
    (0x03, "dBase III"),
    (0x04, "dBase IV"),
    (0x05, "dBase V"),
    (0x30, "Visual FoxPro"),
    (0x31, "Visual FoxPro (autoincrement)"),
    (0x32, "Visual FoxPro (varchar)"),
    (0x43, "dBase IV SQL table"),
    (0x63, "dBase IV SQL system"),
    (0x83, "dBase III with memo"),
    (0x8b, "dBase IV with memo"),
    (0x8e, "dBase IV with SQL table"),
    (0xcb, "dBase IV SQL table with memo"),
    (0xf5, "FoxPro with memo"),
    (0xfb, "FoxBASE"),
];

fn dbf_probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let (Some(&v), Some(&mm), Some(&dd)) = (d.first(), d.get(2), d.get(3)) else {
        return false;
    };
    let header = u16_le(d, 8).unwrap_or(0);
    let record = u16_le(d, 10).unwrap_or(0);
    let records = u32_le(d, 4).unwrap_or(0);
    lookup(DBF_VERSIONS, v.into()).is_some()
        && (1..=12).contains(&mm)
        && (1..=31).contains(&dd)
        && header >= 65
        && record > 0
        && d.get(usize::from(header).saturating_sub(1)) == Some(&0x0d)
        && u64::from(records)
            .saturating_mul(record.into())
            .saturating_add(header.into())
            <= h.len.saturating_add(1)
}

declare_format!(pub DBF = "dbf", "dBase table", ["dbf"], "application/x-dbf",
    Probe::Custom(dbf_probe), dbf);

record! {
    pub struct DbfHeader {
        version: u8 "Version" .enumeration(DBF_VERSIONS),
        year: u8 "Last update: year (since 1900)",
        month: u8 "Last update: month",
        day: u8 "Last update: day",
        records: u32 "Records",
        header: u16 "Header size",
        record: u16 "Record size",
        _reserved: bytes[20] "Reserved",
    }
}

record! {
    pub struct DbfField {
        name: ascii[11] "Name",
        kind: ascii[1] "Type",
        displacement: u32 "Displacement",
        length: u8 "Length",
        decimals: u8 "Decimal places",
        flags: u8 "Flags" .hex(),
        _reserved: bytes[13] "Reserved",
    }
}

async fn dbf(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: DbfHeader = read_record(&cx, file.sub(0, DbfHeader::SIZE), LE).await?;
    cx.emit(DbfHeader::node("Header", file.sub(0, DbfHeader::SIZE), LE));
    let count = (u64::from(h.header).saturating_sub(33)) / DbfField::SIZE;
    let mut fields = Vec::new();
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(DbfHeader::SIZE);
    for _ in 0..count {
        let (f, span) = cur.record::<DbfField>().await?;
        fields.push((f.name.clone(), f.kind.clone(), u64::from(f.length), span));
    }
    let descriptors = file.sub(DbfHeader::SIZE, count.saturating_mul(DbfField::SIZE));
    cx.emit(
        Node::new("Fields")
            .span(descriptors)
            .summary(format!("{count} fields"))
            .lazy(dbf_fields, descriptors),
    );
    let records = file.sub(
        h.header.into(),
        u64::from(h.records).saturating_mul(h.record.into()),
    );
    cx.emit(
        Node::new("Records")
            .span(records)
            .summary(format!("{} records", h.records))
            .lazy(dbf_records, (records, u64::from(h.record), fields.clone())),
    );
    let version = lookup(DBF_VERSIONS, h.version.into()).unwrap_or("dBase");
    let names: Vec<String> = fields.iter().map(|f| f.0.clone()).collect();
    cx.annotate(format!(
        "{version}, {} records × [{}]",
        h.records,
        names.join(", ")
    ));
    Ok(())
}

async fn dbf_fields(cx: Cx, span: Span) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, LE);
    while cur.remaining() >= DbfField::SIZE {
        let (f, at) = cur.record::<DbfField>().await?;
        cx.push(
            DbfField::node(f.name.clone(), at, LE).summary(format!("{} ({})", f.kind, f.length)),
        )
        .await;
    }
    Ok(())
}

/// Field name, type, length and descriptor span.
type DbfFields = Vec<(String, String, u64, Span)>;

async fn dbf_records(cx: Cx, (span, size, fields): (Span, u64, DbfFields)) -> Result<()> {
    if size == 0 {
        return Ok(());
    }
    let count = span.len.checked_div(size).unwrap_or(0);
    cx.set_count(Count::Exact(count));
    for i in 0..count {
        let record = span.sub(i.saturating_mul(size), size);
        let bytes = cx.read(record).await?;
        let mut at = 1usize;
        let mut values = Vec::new();
        for (name, _, len, _) in &fields {
            let len = crate::bytes::to_usize(*len);
            let value =
                String::from_utf8_lossy(bytes.get(at..at.saturating_add(len)).unwrap_or_default())
                    .trim()
                    .to_owned();
            values.push(format!("{name}={value}"));
            at = at.saturating_add(len);
        }
        let deleted = bytes.first() == Some(&b'*');
        cx.push(
            Node::new(format!(
                "#{}{}",
                i.saturating_add(1),
                if deleted { " (deleted)" } else { "" }
            ))
            .span(record)
            .summary(values.join(", ")),
        )
        .await;
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// LAS point clouds

declare_format!(pub LAS = "las", "LAS point cloud", ["las"], "application/vnd.las",
    Probe::Magic(&[(0, b"LASF")]), las);

record! {
    pub struct LasHeader {
        magic: ascii[4] "File signature",
        source: u16 "File source ID",
        encoding: u16 "Global encoding" .hex(),
        guid: guid "Project ID",
        major: u8 "Version major",
        minor: u8 "Version minor",
        system: ascii[32] "System identifier",
        software: ascii[32] "Generating software",
        day: u16 "Creation day of year",
        year: u16 "Creation year",
        header_size: u16 "Header size",
        points_offset: u32 "Offset to point data" .hex(),
        vlrs: u32 "Variable length records",
        point_format: u8 "Point data record format",
        point_length: u16 "Point data record length",
        points: u32 "Number of point records (legacy)",
        by_return: bytes[20] "Points by return (legacy)",
        x_scale: f64 "X scale factor",
        y_scale: f64 "Y scale factor",
        z_scale: f64 "Z scale factor",
        x_offset: f64 "X offset",
        y_offset: f64 "Y offset",
        z_offset: f64 "Z offset",
        x_max: f64 "Max X",
        x_min: f64 "Min X",
        y_max: f64 "Max Y",
        y_min: f64 "Min Y",
        z_max: f64 "Max Z",
        z_min: f64 "Min Z",
    }
}

async fn las(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let h: LasHeader = read_record(&cx, file.sub(0, LasHeader::SIZE), LE).await?;
    cx.emit(LasHeader::node(
        "Public header block",
        file.sub(0, h.header_size.into()),
        LE,
    ));
    let mut cur = Cursor::new(&cx, file, LE);
    cur.seek(h.header_size.into());
    for _ in 0..h.vlrs.min(10_000) {
        let start = cur.pos();
        cur.skip(2);
        let user = crate::text::until_nul(&cur.bytes(16).await?);
        let record = cur.u16().await?;
        let len = cur.u16().await?;
        let description = crate::text::until_nul(&cur.bytes(32).await?);
        cur.skip(len.into());
        cx.push(
            Node::new(format!("VLR {user}/{record}"))
                .span(cur.since(start))
                .summary(description),
        )
        .await;
    }
    cx.emit(
        Node::new("Point records")
            .span(file.tail(h.points_offset.into()))
            .summary(format!(
                "{} points × {} bytes (format {})",
                h.points, h.point_length, h.point_format
            )),
    );
    cx.annotate(format!(
        "LAS {}.{}, {} points, by {}",
        h.major,
        h.minor,
        h.points,
        h.software.trim_end()
    ));
    Ok(())
}

// ---------------------------------------------------------------------------
// GRIB and BUFR (meteorological messages)

declare_format!(pub GRIB = "grib", "GRIB weather data", ["grib", "grb", "grib2", "grb2"], "application/x-grib",
    Probe::Magic(&[(0, b"GRIB")]), grib);

const GRIB2_SECTIONS: [&str; 9] = [
    "Indicator",
    "Identification",
    "Local use",
    "Grid definition",
    "Product definition",
    "Data representation",
    "Bit-map",
    "Data",
    "End",
];

async fn grib(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut messages = 0u32;
    let mut edition = 0u8;
    while pos.saturating_add(16) <= file.len {
        let head = cx.read(file.sub(pos, 16)).await?;
        if !head.starts_with(b"GRIB") {
            break;
        }
        edition = head.get(7).copied().unwrap_or(0);
        let len = if edition == 2 {
            u64_be(&head, 8).unwrap_or(0)
        } else {
            u64::from(crate::bytes::u24_be(&head, 4).unwrap_or(0))
        };
        if len < 16 {
            cx.diag(Diagnostic::malformed("message shorter than its indicator"));
            break;
        }
        let span = file.sub(pos, len);
        let discipline = head.get(6).copied().unwrap_or(0);
        cx.push(
            Node::new(format!("Message {}", messages.saturating_add(1)))
                .span(span)
                .summary(format!(
                    "edition {edition}, discipline {discipline}, {len} bytes"
                ))
                .lazy(grib_sections, (span, edition)),
        )
        .await;
        messages = messages.saturating_add(1);
        pos = pos.saturating_add(len);
    }
    cx.annotate(format!("{messages} GRIB{edition} message(s)"));
    Ok(())
}

async fn grib_sections(cx: Cx, (span, edition): (Span, u8)) -> Result<()> {
    if edition != 2 {
        cx.emit(Node::new("Indicator").span(span.sub(0, 8)));
        cx.emit(Node::new("Sections").span(span.sub(8, span.len.saturating_sub(12))));
        cx.emit(Node::new("End (7777)").span(span.tail(span.len.saturating_sub(4))));
        return Ok(());
    }
    cx.emit(Node::new("Indicator").span(span.sub(0, 16)));
    let mut cur = Cursor::new(&cx, span, BE);
    cur.seek(16);
    while cur.remaining() > 4 {
        let start = cur.pos();
        let len = cur.u32().await?;
        let number = cur.u8().await?;
        if len < 5 {
            break;
        }
        cur.seek(start.saturating_add(len.into()));
        let name = GRIB2_SECTIONS
            .get(usize::from(number))
            .unwrap_or(&"Unknown");
        cx.push(
            Node::new(format!("Section {number}: {name}"))
                .span(cur.since(start))
                .summary(format!("{len} bytes")),
        )
        .await;
    }
    cx.emit(Node::new("End (7777)").span(cur.span(4)));
    Ok(())
}

declare_format!(pub BUFR = "bufr", "BUFR observation data", ["bufr"], "application/x-bufr",
    Probe::Magic(&[(0, b"BUFR")]), bufr);

async fn bufr(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read(file.sub(0, 8)).await?;
    let len = u64::from(crate::bytes::u24_be(&head, 4).unwrap_or(0));
    let edition = head.get(7).copied().unwrap_or(0);
    cx.emit(
        Node::new("Section 0 (indicator)")
            .span(file.sub(0, 8))
            .value(Value::UInt {
                value: edition.into(),
                bits: 8,
                radix: Radix::Dec,
            }),
    );
    let mut cur = Cursor::new(&cx, file.sub(0, len), BE);
    cur.seek(8);
    for number in 1..=4u8 {
        if cur.remaining() < 3 {
            break;
        }
        let start = cur.pos();
        let section_len = u64::from(crate::bytes::u24_be(&cur.peek(3).await?, 0).unwrap_or(0));
        if section_len < 3 {
            break;
        }
        cur.skip(section_len);
        cx.emit(
            Node::new(format!("Section {number}"))
                .span(cur.since(start))
                .summary(format!("{section_len} bytes")),
        );
        // Section 2 is optional (flag in section 1); a 7777 here ends it.
        if cur.peek(4).await? == b"7777" {
            break;
        }
    }
    cx.emit(Node::new("Section 5 (7777)").span(cur.span(4)));
    cx.annotate(format!("BUFR edition {edition}, {len} bytes"));
    Ok(())
}
