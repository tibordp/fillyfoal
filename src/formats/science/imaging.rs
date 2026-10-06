//! Scientific and medical imaging: FITS (astronomy) and DICOM.

use crate::bytes::{u16_be, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

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
