//! Radiance RGBE (HDR): text header lines up to an empty line, a
//! resolution line such as `-Y 480 +X 640`, then (usually run-length
//! encoded) RGBE scanlines.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::text;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;

use super::{dims, region};

pub static FORMAT: Format = Format {
    name: "hdr",
    title: "Radiance HDR image",
    extensions: &["hdr", "pic", "rgbe", "xyze"],
    mime: "image/vnd.radiance",
    probe: Probe::Magic(&[(0, b"#?RADIANCE\n"), (0, b"#?RGBE\n"), (0, b"#?AUTOPANO\n")]),
    dissect: crate::expander!(dissect: Input),
};

const HEADER_MAX: u64 = 0x4000;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, HEADER_MAX)).await?;
    let mut pos = 0usize;
    let mut format = String::new();
    let mut lines = 0usize;
    loop {
        let rest = head.get(pos..).unwrap_or_default();
        let Some(len) = rest.iter().position(|&b| b == b'\n') else {
            return Err(
                Diagnostic::malformed("header does not end").at(file.sub(0, to_u64(head.len())))
            );
        };
        let line = crate::text::latin1(rest.get(..len).unwrap_or_default());
        let span = file.sub(to_u64(pos), to_u64(len));
        pos = pos.saturating_add(len).saturating_add(1);
        if line.is_empty() {
            break;
        }
        let node = if lines == 0 {
            Node::new("Signature").span(span).value(text(line))
        } else if let Some((key, value)) = line.split_once('=') {
            if key == "FORMAT" {
                format = value.to_owned();
            }
            Node::new(key.to_owned()).span(span).value(text(value))
        } else if line.starts_with('#') {
            Node::new("Comment").span(span).value(text(line))
        } else {
            Node::new("Line").span(span).value(text(line))
        };
        cx.emit(node);
        lines = lines.saturating_add(1);
    }
    let rest = head.get(pos..).unwrap_or_default();
    let len = rest.iter().position(|&b| b == b'\n').unwrap_or(rest.len());
    let resolution = crate::text::latin1(rest.get(..len).unwrap_or_default());
    let words: Vec<&str> = resolution.split_whitespace().collect();
    let (mut width, mut height) = (0u64, 0u64);
    if let [a, h, b, w] = words.as_slice() {
        let rows: u64 = h.parse().unwrap_or(0);
        let cols: u64 = w.parse().unwrap_or(0);
        if a.ends_with('Y') && b.ends_with('X') {
            (width, height) = (cols, rows);
        } else {
            (width, height) = (rows, cols);
        }
    }
    cx.emit(
        Node::new("Resolution")
            .span(file.sub(to_u64(pos), to_u64(len)))
            .value(text(resolution.clone()))
            .summary(dims(width, height)),
    );
    let start = to_u64(pos).saturating_add(to_u64(len)).saturating_add(1);
    let mut summary = dims(width, height);
    if !format.is_empty() {
        summary = format!("{summary}, {format}");
    }
    cx.annotate(summary);
    cx.emit(
        region("Scanlines", file, start, file.len.saturating_sub(start))
            .summary(format!("{height} scanlines")),
    );
    Ok(())
}
