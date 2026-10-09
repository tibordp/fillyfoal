//! IPTC-NAA Information Interchange Model records (IIM 4.2), as stored in
//! TIFF tag 33723 and Photoshop image resource 1028.
//!
//! A sequence of datasets: the tag marker 0x1C, record and dataset numbers,
//! a big-endian 16-bit length (or, with its top bit set, the number of
//! bytes of a longer length that follows), then the data.

use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::Input;
use crate::formats::util::arcutil::human_size;
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Value, lookup};

/// A lazy node listing the IPTC datasets in `span`.
pub fn node(name: &'static str, input: Input, span: Span) -> Node {
    Node::new(name).span(span).lazy(datasets, (input, span))
}

const fn id(record: u64, dataset: u64) -> u64 {
    (record << 8) | dataset
}

const DATASETS: EnumTable = &[
    (id(1, 0), "EnvelopeRecordVersion"),
    (id(1, 5), "Destination"),
    (id(1, 20), "FileFormat"),
    (id(1, 22), "FileVersion"),
    (id(1, 30), "ServiceIdentifier"),
    (id(1, 40), "EnvelopeNumber"),
    (id(1, 50), "ProductID"),
    (id(1, 60), "EnvelopePriority"),
    (id(1, 70), "DateSent"),
    (id(1, 80), "TimeSent"),
    (id(1, 90), "CodedCharacterSet"),
    (id(1, 100), "UniqueObjectName"),
    (id(1, 120), "ARMIdentifier"),
    (id(1, 122), "ARMVersion"),
    (id(2, 0), "ApplicationRecordVersion"),
    (id(2, 3), "ObjectTypeReference"),
    (id(2, 4), "ObjectAttributeReference"),
    (id(2, 5), "ObjectName"),
    (id(2, 7), "EditStatus"),
    (id(2, 8), "EditorialUpdate"),
    (id(2, 10), "Urgency"),
    (id(2, 12), "SubjectReference"),
    (id(2, 15), "Category"),
    (id(2, 20), "SupplementalCategories"),
    (id(2, 22), "FixtureIdentifier"),
    (id(2, 25), "Keywords"),
    (id(2, 26), "ContentLocationCode"),
    (id(2, 27), "ContentLocationName"),
    (id(2, 30), "ReleaseDate"),
    (id(2, 35), "ReleaseTime"),
    (id(2, 37), "ExpirationDate"),
    (id(2, 38), "ExpirationTime"),
    (id(2, 40), "SpecialInstructions"),
    (id(2, 42), "ActionAdvised"),
    (id(2, 45), "ReferenceService"),
    (id(2, 47), "ReferenceDate"),
    (id(2, 50), "ReferenceNumber"),
    (id(2, 55), "DateCreated"),
    (id(2, 60), "TimeCreated"),
    (id(2, 62), "DigitalCreationDate"),
    (id(2, 63), "DigitalCreationTime"),
    (id(2, 65), "OriginatingProgram"),
    (id(2, 70), "ProgramVersion"),
    (id(2, 75), "ObjectCycle"),
    (id(2, 80), "By-line"),
    (id(2, 85), "By-lineTitle"),
    (id(2, 90), "City"),
    (id(2, 92), "Sub-location"),
    (id(2, 95), "Province-State"),
    (id(2, 100), "Country-PrimaryLocationCode"),
    (id(2, 101), "Country-PrimaryLocationName"),
    (id(2, 103), "OriginalTransmissionReference"),
    (id(2, 105), "Headline"),
    (id(2, 110), "Credit"),
    (id(2, 115), "Source"),
    (id(2, 116), "CopyrightNotice"),
    (id(2, 118), "Contact"),
    (id(2, 120), "Caption-Abstract"),
    (id(2, 121), "LocalCaption"),
    (id(2, 122), "Writer-Editor"),
    (id(2, 125), "RasterizedCaption"),
    (id(2, 130), "ImageType"),
    (id(2, 131), "ImageOrientation"),
    (id(2, 135), "LanguageIdentifier"),
    (id(2, 150), "AudioType"),
    (id(2, 151), "AudioSamplingRate"),
    (id(2, 152), "AudioSamplingResolution"),
    (id(2, 153), "AudioDuration"),
    (id(2, 154), "AudioOutcue"),
    (id(2, 184), "JobID"),
    (id(2, 185), "MasterDocumentID"),
    (id(2, 186), "ShortDocumentID"),
    (id(2, 187), "UniqueDocumentID"),
    (id(2, 188), "OwnerID"),
    (id(2, 200), "ObjectPreviewFileFormat"),
    (id(2, 201), "ObjectPreviewFileVersion"),
    (id(2, 202), "ObjectPreviewData"),
    (id(2, 221), "Prefs"),
    (id(2, 225), "ClassifyState"),
    (id(2, 228), "SimilarityIndex"),
    (id(2, 230), "DocumentNotes"),
    (id(2, 231), "DocumentHistory"),
    (id(2, 232), "ExifCameraInfo"),
    (id(2, 255), "CatalogSets"),
    (id(7, 10), "SizeMode"),
    (id(7, 20), "MaxSubfileSize"),
    (id(7, 90), "ObjectSizeAnnounced"),
    (id(7, 95), "MaximumObjectSize"),
    (id(8, 10), "SubFile"),
    (id(9, 10), "ConfirmedObjectSize"),
];

/// Datasets holding binary numbers rather than text.
fn is_binary(key: u64) -> bool {
    matches!(
        key,
        0x0100
            | 0x0114
            | 0x0116
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

async fn datasets(cx: Cx, (_input, span): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
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
                    node.diag(Diagnostic::malformed("expected the IPTC tag marker 0x1C"))
                })
                .await;
                break;
            }
            None => break,
        }
        let (Some(&record), Some(&dataset)) = (head.get(1), head.get(2)) else {
            cx.push(
                Node::new("Truncated dataset")
                    .span(span.tail(pos))
                    .diag(Diagnostic::truncated(span.sub(pos, 5), to_u64(head.len()))),
            )
            .await;
            break;
        };
        let short = crate::bytes::u16_be(&head, 3).unwrap_or(0);
        let (len, header) = if short & 0x8000 != 0 {
            let n = u64::from(short & 0x7fff).min(8);
            let ext = cx.read(span.sub(pos.saturating_add(5), n)).await?;
            let len = ext.iter().fold(0u64, |acc, &b| {
                acc.checked_shl(8).unwrap_or(0) | u64::from(b)
            });
            (len, 5u64.saturating_add(n))
        } else {
            (u64::from(short), 5)
        };
        let start = pos;
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
        let bytes = cx.read_avail(data.sub(0, 1024)).await?;
        if is_binary(key) && bytes.len() <= 8 {
            let v = bytes.iter().fold(0u64, |acc, &b| {
                acc.checked_shl(8).unwrap_or(0) | u64::from(b)
            });
            node = node.value(super::super::uint(v));
        } else if key == id(1, 90) {
            let charset = match bytes.as_slice() {
                b"\x1b%G" => Some("UTF-8"),
                _ => None,
            };
            node = node.value(Value::Bytes(bytes.clone()));
            if let Some(c) = charset {
                node = node.summary(c);
            }
        } else if crate::text::looks_like_text(&bytes) || bytes.is_empty() {
            let text = match std::str::from_utf8(&bytes) {
                Ok(t) => t.to_owned(),
                Err(_) => crate::text::latin1(&bytes),
            };
            if let Some(d) = date(&text) {
                node = node.summary(d);
            }
            node = node.value(Value::Text(text));
        } else {
            node = node.summary(human_size(len));
        }
        cx.push(node.desc(format!("Record {record}, dataset {dataset}")))
            .await;
    }
    Ok(())
}

fn to_u64(n: usize) -> u64 {
    crate::bytes::to_u64(n)
}
