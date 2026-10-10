//! IPTC-NAA Information Interchange Model records (IIM 4.2), as stored in
//! Photoshop image resource 1028 (PSD files, JPEG APP13 segments) and TIFF
//! tag 33723.
//!
//! A sequence of datasets: the tag marker 0x1C, record and dataset numbers,
//! a big-endian 16-bit length (or, with its top bit set, the number of
//! bytes of a longer length that follows), then the data. Record 1 is the
//! envelope, record 2 the application record (caption, keywords, credits);
//! records 7 to 9 frame an object carried in the stream itself.

use crate::bytes::{to_u64, u16_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::val::uint;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

/// How much of a dataset's data is read for its value.
const PEEK: u64 = 1024;

/// IPTC-IIM datasets on their own, as in TIFF tag 33723 and ImageMagick's
/// raw `iptc` profiles.
pub static FORMAT: Format = Format {
    name: "iptc-iim",
    title: "IPTC Information Interchange Model",
    extensions: &["iptc"],
    mime: "application/x-iptc",
    probe: Probe::Never,
    dissect: crate::expander!(dissect: Input),
};

async fn dissect(cx: Cx, input: Input) -> Result<()> {
    datasets(cx.clone(), input.span).await?;
    cx.annotate("IPTC-IIM datasets");
    Ok(())
}

/// A lazy node listing the IPTC-IIM datasets in `span`.
pub fn node(name: &'static str, span: Span) -> Node {
    Node::new(name)
        .span(span)
        .summary("IPTC Information Interchange Model datasets")
        .lazy(datasets, span)
}

const fn id(record: u64, dataset: u64) -> u64 {
    (record << 8) | dataset
}

const DATASETS: EnumTable = &[
    (id(1, 0), "Envelope record version"),
    (id(1, 5), "Destination"),
    (id(1, 20), "File format"),
    (id(1, 22), "File format version"),
    (id(1, 30), "Service identifier"),
    (id(1, 40), "Envelope number"),
    (id(1, 50), "Product ID"),
    (id(1, 60), "Envelope priority"),
    (id(1, 70), "Date sent"),
    (id(1, 80), "Time sent"),
    (id(1, 90), "Coded character set"),
    (id(1, 100), "Unique name of object"),
    (id(1, 120), "ARM identifier"),
    (id(1, 122), "ARM version"),
    (id(2, 0), "Record version"),
    (id(2, 3), "Object type reference"),
    (id(2, 4), "Object attribute reference"),
    (id(2, 5), "Object name"),
    (id(2, 7), "Edit status"),
    (id(2, 8), "Editorial update"),
    (id(2, 10), "Urgency"),
    (id(2, 12), "Subject reference"),
    (id(2, 15), "Category"),
    (id(2, 20), "Supplemental category"),
    (id(2, 22), "Fixture identifier"),
    (id(2, 25), "Keywords"),
    (id(2, 26), "Content location code"),
    (id(2, 27), "Content location name"),
    (id(2, 30), "Release date"),
    (id(2, 35), "Release time"),
    (id(2, 37), "Expiration date"),
    (id(2, 38), "Expiration time"),
    (id(2, 40), "Special instructions"),
    (id(2, 42), "Action advised"),
    (id(2, 45), "Reference service"),
    (id(2, 47), "Reference date"),
    (id(2, 50), "Reference number"),
    (id(2, 55), "Date created"),
    (id(2, 60), "Time created"),
    (id(2, 62), "Digital creation date"),
    (id(2, 63), "Digital creation time"),
    (id(2, 65), "Originating program"),
    (id(2, 70), "Program version"),
    (id(2, 75), "Object cycle"),
    (id(2, 80), "By-line"),
    (id(2, 85), "By-line title"),
    (id(2, 90), "City"),
    (id(2, 92), "Sub-location"),
    (id(2, 95), "Province/state"),
    (id(2, 100), "Country code"),
    (id(2, 101), "Country name"),
    (id(2, 103), "Original transmission reference"),
    (id(2, 105), "Headline"),
    (id(2, 110), "Credit"),
    (id(2, 115), "Source"),
    (id(2, 116), "Copyright notice"),
    (id(2, 118), "Contact"),
    (id(2, 120), "Caption/abstract"),
    (id(2, 121), "Local caption"),
    (id(2, 122), "Writer/editor"),
    (id(2, 125), "Rasterized caption"),
    (id(2, 130), "Image type"),
    (id(2, 131), "Image orientation"),
    (id(2, 135), "Language identifier"),
    (id(2, 150), "Audio type"),
    (id(2, 151), "Audio sampling rate"),
    (id(2, 152), "Audio sampling resolution"),
    (id(2, 153), "Audio duration"),
    (id(2, 154), "Audio outcue"),
    (id(2, 184), "Job ID"),
    (id(2, 185), "Master document ID"),
    (id(2, 186), "Short document ID"),
    (id(2, 187), "Unique document ID"),
    (id(2, 188), "Owner ID"),
    (id(2, 200), "Object preview file format"),
    (id(2, 201), "Object preview file format version"),
    (id(2, 202), "Object preview data"),
    (id(2, 221), "Photo Mechanic preferences"),
    (id(2, 225), "Classify state"),
    (id(2, 228), "Similarity index"),
    (id(2, 230), "Document notes"),
    (id(2, 231), "Document history"),
    (id(2, 232), "Exif camera info"),
    (id(2, 255), "Catalog sets"),
    (id(7, 10), "Size mode"),
    (id(7, 20), "Max subfile size"),
    (id(7, 90), "Object size announced"),
    (id(7, 95), "Maximum object size"),
    (id(8, 10), "Subfile"),
    (id(9, 10), "Confirmed object size"),
];

/// Datasets holding binary numbers rather than text.
fn is_number(key: u64) -> bool {
    matches!(
        key,
        0x0100
            | 0x0114
            | 0x0116
            | 0x0178
            | 0x017a
            | 0x0200
            | 0x02c8
            | 0x02c9
            | 0x070a
            | 0x0714
            | 0x075a
            | 0x075f
            | 0x090a
    )
}

/// Datasets holding binary data: the character set's escape sequence, the
/// object preview and a subfile of the object.
fn is_binary(key: u64) -> bool {
    matches!(key, 0x015a | 0x02ca | 0x080a)
}

/// Dates ("CCYYMMDD") and times ("HHMMSS±HHMM").
fn is_date(key: u64) -> bool {
    matches!(key, 0x0146 | 0x021e | 0x0225 | 0x022f | 0x0237 | 0x023e)
}

fn is_time(key: u64) -> bool {
    matches!(key, 0x0150 | 0x0223 | 0x0226 | 0x023c | 0x023f)
}

/// "CCYYMMDD" → "CCYY-MM-DD".
fn date(text: &str) -> Option<String> {
    if text.len() != 8 || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(format!(
        "{}-{}-{}",
        text.get(..4)?,
        text.get(4..6)?,
        text.get(6..)?
    ))
}

/// "HHMMSS±HHMM" → "HH:MM:SS±HH:MM" (the offset is optional).
fn time(text: &str) -> Option<String> {
    let clock = text.get(..6)?;
    if !clock.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let hms = format!(
        "{}:{}:{}",
        clock.get(..2)?,
        clock.get(2..4)?,
        clock.get(4..)?
    );
    match text.get(6..)? {
        "" => Some(hms),
        zone if zone.len() == 5
            && matches!(zone.as_bytes().first(), Some(b'+' | b'-'))
            && zone.bytes().skip(1).all(|b| b.is_ascii_digit()) =>
        {
            Some(format!("{hms}{}:{}", zone.get(..3)?, zone.get(3..)?))
        }
        _ => None,
    }
}

/// Text in UTF-8 if it is (possibly cut short in a character) or the
/// character set says so, else ISO 8859-1.
fn decode(bytes: &[u8], utf8: bool) -> String {
    match std::str::from_utf8(bytes) {
        Ok(s) => s.to_owned(),
        Err(e) if utf8 || e.error_len().is_none() => {
            String::from_utf8_lossy(bytes.get(..e.valid_up_to()).unwrap_or_default()).into_owned()
        }
        Err(_) => crate::text::latin1(bytes),
    }
}

async fn datasets(cx: Cx, span: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut utf8 = false;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 5)).await?;
        match head.first() {
            Some(0x1c) => {}
            Some(_) => {
                let rest = span.tail(pos);
                let bytes = cx.read_avail(rest.sub(0, 4096)).await?;
                let node = Node::new("Padding").span(rest);
                cx.push(if bytes.iter().all(|&b| b == 0) {
                    node
                } else {
                    Node::new("Data")
                        .span(rest)
                        .diag(Diagnostic::malformed("expected the IPTC tag marker 0x1C").at(rest))
                })
                .await;
                break;
            }
            None => break,
        }
        let (Some(&record), Some(&dataset), Some(short)) =
            (head.get(1), head.get(2), u16_be(&head, 3))
        else {
            cx.push(
                Node::new("Truncated dataset")
                    .span(span.tail(pos))
                    .diag(Diagnostic::truncated(span.sub(pos, 5), to_u64(head.len()))),
            )
            .await;
            break;
        };
        let start = pos;
        let (len, header) = if short & 0x8000 != 0 {
            // Extended dataset: the low bits give the size of the length.
            let n = u64::from(short & 0x7fff);
            let ext = cx
                .read_avail(span.sub(pos.saturating_add(5), n.min(9)))
                .await?;
            if n > 8 || to_u64(ext.len()) < n {
                cx.push(
                    Node::new(format!("Dataset {record}:{dataset}"))
                        .span(span.sub(pos, 5u64.saturating_add(n)))
                        .diag(Diagnostic::malformed(format!(
                            "{n}-byte extended dataset length"
                        ))),
                )
                .await;
                break;
            }
            let len = ext.iter().fold(0u64, |acc, &b| {
                acc.checked_shl(8).unwrap_or(0) | u64::from(b)
            });
            (len, 5u64.saturating_add(n))
        } else {
            (u64::from(short), 5)
        };
        let data = span.sub(pos.saturating_add(header), len);
        pos = pos.saturating_add(header).saturating_add(len);
        let key = id(record.into(), dataset.into());
        let name = lookup(DATASETS, key)
            .map_or_else(|| format!("Dataset {record}:{dataset}"), str::to_owned);
        let mut node = Node::new(name)
            .span(span.sub(start, pos.saturating_sub(start)))
            .target(data);
        if data.len < len {
            node = node.diag(Diagnostic::truncated(
                Span::new(data.source, data.offset, len),
                data.len,
            ));
        }
        let bytes = cx.read_avail(data.sub(0, PEEK)).await?;
        if is_number(key) && !bytes.is_empty() && bytes.len() <= 8 {
            let v = bytes.iter().fold(0u64, |acc, &b| {
                acc.checked_shl(8).unwrap_or(0) | u64::from(b)
            });
            node = node.value(uint(v, 64));
        } else if key == id(1, 90) {
            utf8 = bytes == b"\x1b%G";
            node = node.value(Value::Bytes(bytes));
            if utf8 {
                node = node.summary("UTF-8");
            }
        } else if is_binary(key) || is_number(key) {
            node = node.value(Value::Bytes(
                bytes
                    .get(..bytes.len().min(32))
                    .unwrap_or_default()
                    .to_vec(),
            ));
            node = node.summary(human_size(len));
        } else {
            let text = decode(&bytes, utf8);
            let pretty = if is_date(key) {
                date(&text)
            } else if is_time(key) {
                time(&text)
            } else {
                None
            };
            if let Some(p) = pretty {
                node = node.summary(p);
            } else if len > PEEK {
                node = node.summary(human_size(len));
            }
            node = node.value(Value::Text(text));
        }
        cx.push(node.desc(format!("Record {record}, dataset {dataset}")))
            .await;
    }
    Ok(())
}
