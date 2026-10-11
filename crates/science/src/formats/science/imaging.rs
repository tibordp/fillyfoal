//! Medical imaging: DICOM. (FITS, the astronomy format, is in
//! `image::fits`.)

use crate::bytes::{u16_be, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::dsl::Cursor;
use crate::error::{Diagnostic, Result};
use crate::fields::Endian;
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{Radix, Value};

const LE: Endian = Endian::Little;
const BE: Endian = Endian::Big;

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
    (0x0008, 0x0100, "SH", "Code Value"),
    (0x0008, 0x0102, "SH", "Coding Scheme Designator"),
    (0x0008, 0x0104, "LO", "Code Meaning"),
    (0x0008, 0x1032, "SQ", "Procedure Code Sequence"),
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
    (0x0040, 0xa043, "SQ", "Concept Name Code Sequence"),
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
        cx.progress_in(span, span.offset.saturating_add(cur.pos()));
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
            // Delimiters (and stray items of other kinds) carry no value.
            // A delimiter is the last thing in its sequence or item body,
            // which ends right after it, so there is nothing to stop here.
            cx.push(Node::new(label).span(cur.since(start))).await;
            continue;
        }
        let undefined = len == UNDEFINED;
        let item = group == 0xfffe && element == 0xe000;
        let mut node = Node::new(label);
        if group == 0x7fe0 && undefined {
            // Encapsulated pixel data: fragments until a sequence delimiter.
            let end = find_end(&cx, cur.region().tail(value_start), enc, Nest::Sequence).await?;
            let body = cur.span(end);
            cur.skip(end);
            node = node.span(cur.since(start)).summary("encapsulated").lazy(
                crate::expander!(self::dicom_fragments: (Span, Endian)),
                (body, enc.endian),
            );
        } else if vr == "SQ" || item || undefined {
            // Nested data sets: an item's body holds elements; a sequence's
            // body holds items. An undefined length outside Pixel Data
            // means a sequence (whatever VR an implicit-VR reader guessed),
            // which ends at its Sequence Delimitation Item; an item of
            // undefined length ends at its Item Delimitation Item. An
            // explicit-VR UN of undefined length holds implicit VR little
            // endian (PS3.5 6.2.2).
            let inner = if undefined && enc.explicit && vr == "UN" {
                Encoding {
                    explicit: false,
                    endian: LE,
                }
            } else {
                enc
            };
            let body_len = if undefined {
                let nest = if item { Nest::Item } else { Nest::Sequence };
                find_end(&cx, cur.region().tail(value_start), inner, nest).await?
            } else {
                u64::from(len)
            };
            let body = cur.span(body_len);
            cur.skip(body_len);
            node = node.span(cur.since(start)).lazy(
                crate::expander!(self::dicom_elements: (Span, Encoding, u32)),
                (body, inner, depth.saturating_add(1)),
            );
        } else {
            let body = cur.span(len.into());
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

/// The items of encapsulated Pixel Data: the Basic Offset Table, then one
/// or more fragments of compressed frames (PS3.5 A.4), then the Sequence
/// Delimitation Item. Item bodies are opaque bytes, not data sets.
async fn dicom_fragments(cx: Cx, (span, endian): (Span, Endian)) -> Result<()> {
    let mut cur = Cursor::new(&cx, span, endian);
    let mut index = 0u64;
    while cur.remaining() >= 8 {
        cx.progress_in(span, span.offset.saturating_add(cur.pos()));
        let start = cur.pos();
        let group = cur.u16().await?;
        let element = cur.u16().await?;
        let len = cur.u32().await?;
        let (name, done) = match (group, element) {
            (0xfffe, 0xe000) if index == 0 => ("Basic Offset Table".to_owned(), false),
            (0xfffe, 0xe000) => (format!("Fragment {index}"), false),
            (0xfffe, 0xe0dd) => ("Sequence Delimitation Item".to_owned(), true),
            _ => (format!("({group:04x},{element:04x})"), false),
        };
        if len != UNDEFINED {
            cur.skip(len.into());
        }
        let mut node = Node::new(name).span(cur.since(start));
        if !done {
            node = node.summary(format!("{len} bytes"));
        }
        cx.push(node).await;
        if done || len == UNDEFINED {
            break;
        }
        index = index.saturating_add(1);
    }
    Ok(())
}

/// A container of undefined length, and the delimiter that closes it.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Nest {
    /// Closed by (FFFE,E0DD) Sequence Delimitation Item.
    Sequence,
    /// Closed by (FFFE,E00D) Item Delimitation Item.
    Item,
}

/// Undefined-length containers nested deeper than this are not followed.
const MAX_NEST: usize = 64;

/// Finds the end (just past the closing delimiter) of the body of a `nest`
/// of undefined length that starts at `span`, walking the elements in
/// `enc` and keeping a stack of the undefined-length sequences and items
/// opened on the way, so that each delimiter closes only its own
/// container. Defined lengths are skipped without reading. Without a
/// closing delimiter the body runs to the end of `span`.
async fn find_end(cx: &Cx, span: Span, enc: Encoding, nest: Nest) -> Result<u64> {
    let mut cur = Cursor::new(cx, span, enc.endian);
    let mut stack = vec![(nest, enc)];
    while cur.remaining() >= 8 {
        let Some(&(top, here)) = stack.last() else {
            break;
        };
        let tag_start = cur.pos();
        let group = cur.u16().await?;
        let element = cur.u16().await?;
        if group == 0xfffe {
            let len = cur.u32().await?;
            match element {
                0xe000 if len == UNDEFINED => stack.push((Nest::Item, here)),
                0xe00d if top == Nest::Item => {
                    stack.pop();
                }
                0xe0dd => {
                    // Closes the innermost open sequence; open items inside
                    // it lacked their delimiters and end here too.
                    let Some(at) = stack.iter().rposition(|(n, _)| *n == Nest::Sequence) else {
                        // A stray sequence delimiter in an item: the item
                        // (which lacked its own delimiter) ends before it.
                        if stack.len() == 1 {
                            return Ok(tag_start);
                        }
                        cx.checkpoint().await;
                        continue;
                    };
                    if at == 0 && nest == Nest::Item {
                        return Ok(tag_start);
                    }
                    stack.truncate(at);
                }
                // Stray item delimiters and items of defined length.
                _ if len != UNDEFINED => cur.skip(len.into()),
                _ => {}
            }
        } else {
            let (vr, len) = if here.explicit {
                let vr = cur.bytes(2).await?;
                let len = if long_vr(&vr) {
                    cur.skip(2);
                    cur.u32().await?
                } else {
                    u32::from(cur.u16().await?)
                };
                (vr, len)
            } else {
                (Vec::new(), cur.u32().await?)
            };
            if len == UNDEFINED {
                let inner = if here.explicit && vr == b"UN" {
                    Encoding {
                        explicit: false,
                        endian: LE,
                    }
                } else {
                    here
                };
                stack.push((Nest::Sequence, inner));
            } else {
                cur.skip(len.into());
            }
        }
        if stack.is_empty() {
            return Ok(cur.pos().min(span.len));
        }
        if stack.len() > MAX_NEST {
            return Err(Diagnostic::limit("DICOM sequences nested too deeply"));
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
