//! Geospatial data, GNSS streams, telemetry, vehicle bus logs, drone and
//! robotics logs, and sports and fitness files.
//!
//! Shared here: value constructors, checksums used by several receivers'
//! protocols, and helpers for text formats
//! whose records are lines of delimited or fixed-column fields.
//!
//! Also here: geoscience (`geoscience`: seismic, well logs, grids, planetary
//! labels; `dlis`), survey data (`survey`: Shapefile, LAS, GRIB/BUFR),
//! OpenStreetMap PBF (`osm`) and elevation and imagery (`elevation`).

use std::borrow::Cow;

pub(crate) use crate::codec::crc::{crc16_xmodem, crc24q};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::Head;
use crate::formats::text::piece::Piece;
use crate::formats::text::probe;
use crate::formats::text::scan::LineBuf;
use crate::node::Node;
use crate::span::Span;
use crate::value::Value;

pub mod bufr;
pub mod dlis;
pub mod elevation;
pub mod fit;
pub mod geoscience;
pub mod gis;
pub mod gistext;
pub mod gnss;
pub mod grib;
pub mod markup;
pub mod mdf;
pub mod osm;
pub mod rinex;
pub mod robotics;
pub mod survey;
pub mod tiles;
pub mod vehicle;

// ---------------------------------------------------------------------------
// Values

pub(crate) use crate::formats::util::val::{enumv, hex, int, text, uint};

pub(crate) fn time(unix_seconds: i64) -> Value {
    Value::Timestamp { unix_seconds }
}

pub(crate) use crate::formats::util::arcutil::emit_nodes;

/// `x` rounded to six decimal places, for display.
pub(crate) fn round(x: f64) -> f64 {
    (x * 1e6).round() / 1e6
}

/// A plain leaf with a value.
pub(crate) fn leaf(name: impl Into<Cow<'static, str>>, span: Span, value: Value) -> Node {
    Node::new(name).span(span).value(value)
}

/// Text from fixed-width, NUL- or space-padded bytes.
pub(crate) fn fixed(b: &[u8]) -> String {
    crate::text::until_nul(b).trim_end().to_owned()
}

// ---------------------------------------------------------------------------
// Checksums

// ---------------------------------------------------------------------------
// Text helpers

/// The first `n` lines of the head (without terminators).
pub(crate) fn head_lines(h: &Head<'_>, n: usize) -> Vec<Vec<u8>> {
    let data = probe::head(h);
    probe::lines(&data).take(n).map(<[u8]>::to_vec).collect()
}

/// A field label table for delimited or fixed-column records.
pub(crate) type Labels = &'static [&'static str];

/// A node for one line of delimited fields; expanding it shows the fields
/// labelled from `labels` (extra fields are numbered).
pub(crate) fn delimited_node(
    name: impl Into<Cow<'static, str>>,
    line: &LineBuf,
    sep: u8,
    labels: Labels,
) -> Node {
    delimited_span(name, line.span, sep, labels)
}

/// Like [`delimited_node`], for part of a line.
pub(crate) fn delimited_span(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    sep: u8,
    labels: Labels,
) -> Node {
    Node::new(name)
        .span(span)
        .lazy(delimited, (span, sep, labels))
}

async fn delimited(cx: Cx, (span, sep, labels): (Span, u8, Labels)) -> Result<()> {
    let bytes = cx
        .read_avail(span.sub(0, crate::formats::text::scan::LINE_CAP as u64))
        .await?;
    let piece = Piece::new(&bytes, span);
    for (i, field) in piece.split(sep).enumerate() {
        let name: Cow<'static, str> = match labels.get(i) {
            Some(l) => Cow::Borrowed(*l),
            None => Cow::Owned(format!("Field {}", i.saturating_add(1))),
        };
        cx.emit(field_node(name, field));
    }
    Ok(())
}

/// Whitespace-separated words of a line, labelled.
pub(crate) fn words_node(
    name: impl Into<Cow<'static, str>>,
    line: &LineBuf,
    labels: Labels,
) -> Node {
    Node::new(name)
        .span(line.span)
        .lazy(words, (line.span, labels))
}

async fn words(cx: Cx, (span, labels): (Span, Labels)) -> Result<()> {
    let bytes = cx
        .read_avail(span.sub(0, crate::formats::text::scan::LINE_CAP as u64))
        .await?;
    let piece = Piece::new(&bytes, span);
    for (i, word) in piece.words().enumerate() {
        let name: Cow<'static, str> = match labels.get(i) {
            Some(l) => Cow::Borrowed(*l),
            None => Cow::Owned(format!("Field {}", i.saturating_add(1))),
        };
        cx.emit(field_node(name, word));
    }
    Ok(())
}

/// A fixed-column layout: `(start column, width, label)`, 0-based.
pub(crate) type Columns = &'static [(usize, usize, &'static str)];

/// A node for a fixed-column record; expanding it shows the columns.
pub(crate) fn columns_node(name: impl Into<Cow<'static, str>>, span: Span, cols: Columns) -> Node {
    Node::new(name).span(span).lazy(columns, (span, cols))
}

async fn columns(cx: Cx, (span, cols): (Span, Columns)) -> Result<()> {
    let bytes = cx
        .read_avail(span.sub(0, crate::formats::text::scan::LINE_CAP as u64))
        .await?;
    let piece = Piece::new(&bytes, span);
    for &(start, width, label) in cols {
        if start >= piece.len() {
            break;
        }
        let field = piece.slice(start, start.saturating_add(width).min(piece.len()));
        cx.emit(field_node(label, field));
    }
    Ok(())
}

/// A text field as a leaf: numbers become numeric values.
pub(crate) fn field_node(name: impl Into<Cow<'static, str>>, field: Piece<'_>) -> Node {
    let t = field.trim();
    let s = t.text();
    // Zero-padded codes (dates, IDs) stay text.
    let padded = s.len() > 1
        && !s.contains('.')
        && s.starts_with('0')
        && s.as_bytes().get(1).is_some_and(u8::is_ascii_digit);
    let value = if padded {
        None
    } else {
        crate::formats::text::number(&s)
    }
    .unwrap_or(Value::Text(s));
    Node::new(name).span(t.span()).value(value)
}

/// `key<sep>value` header lines as leaves (key trimmed, value trimmed).
pub(crate) fn key_value(line: &LineBuf, sep: u8) -> Option<Node> {
    let piece = line.piece();
    let (k, v) = piece.split_once(sep)?;
    let key = k.trim().text();
    if key.is_empty() {
        return None;
    }
    Some(field_node(key, v).span(line.span))
}
