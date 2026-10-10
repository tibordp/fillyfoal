//! Scientific and lab data: bioinformatics ([`bio`]), instrument recordings
//! (`instruments`, `waveforms`), spectroscopy, microscopy and lab images
//! (`microscopy`, `lab_images`), DICOM (`imaging`; FITS is in
//! `image::fits`), molecular simulation, statistics package data files
//! (`stats`: SPSS, SAS, Stata) and other science datasets (`datasets`).
//!
//! Geoscience lives in [`super::geo`].

pub mod bio;
pub mod datasets;
pub mod hdf4;
pub mod imaging;
pub mod instruments;
pub mod lab_images;
pub mod microscopy;
pub mod molecular;
pub mod nifti;
pub mod numarray;
pub mod spectroscopy;
pub mod stats;
pub mod waveforms;

use crate::cx::Cx;
use crate::error::Result;
use crate::node::Node;
use crate::span::Span;

/// Trims ASCII padding (spaces and NULs) from a fixed-width text field.
pub(crate) fn field_text(b: &[u8]) -> String {
    String::from_utf8_lossy(b)
        .trim_matches(['\0', ' '])
        .to_owned()
}

/// A Windows `SYSTEMTIME` (eight little-endian words) as
/// `YYYY-MM-DD hh:mm:ss.mmm`, the fields shown as stored.
pub(crate) fn systemtime(b: &[u8]) -> String {
    let w = |i: usize| crate::bytes::u16_le(b, i.saturating_mul(2)).unwrap_or(0);
    format!(
        "{:04}-{:02}-{:02} {:02}:{:02}:{:02}.{:03}",
        w(0),
        w(1),
        w(3),
        w(4),
        w(5),
        w(6),
        w(7)
    )
}

/// Expands key/value pairs parsed with their parent: one node per pair,
/// its value a number when it reads as one.
pub(crate) async fn kv_spans(cx: Cx, items: Vec<(String, String, Span)>) -> Result<()> {
    for (k, v, span) in items {
        cx.push(
            Node::new(k)
                .span(span)
                .value(crate::formats::util::lines::number(&v)),
        )
        .await;
    }
    Ok(())
}
