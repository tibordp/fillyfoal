//! X BitMap (XBM) and X PixMap (XPM): images stored as C source.
//!
//! XBM: `#define name_width`, `#define name_height` (and optional hotspot)
//! followed by a `name_bits[]` byte array. XPM 3: a `/* XPM */` comment and
//! an array of strings: values (`width height colors chars-per-pixel`),
//! color definitions, then one string per pixel row.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;

use super::{dims, text, uint};

pub static XBM: Format = Format {
    name: "xbm",
    title: "X BitMap",
    extensions: &["xbm", "bm"],
    mime: "image/x-xbitmap",
    probe: Probe::Custom(probe_xbm),
    dissect: crate::expander!(dissect_xbm: Input),
};

pub static XPM: Format = Format {
    name: "xpm",
    title: "X PixMap",
    extensions: &["xpm", "pm"],
    mime: "image/x-xpixmap",
    probe: Probe::Magic(&[(0, b"/* XPM */")]),
    dissect: crate::expander!(dissect_xpm: Input),
};

fn probe_xbm(h: &Head<'_>) -> bool {
    let first = h.data.split(|&b| b == b'\n').next().unwrap_or_default();
    h.starts_with(b"#define ")
        && first.windows(7).any(|w| w == b"_width ")
        && h.data.windows(8).any(|w| w == b"_height ")
}

/// Text files are read whole, up to this size.
const MAX_TEXT: u64 = 0x10_0000;

async fn whole(cx: &Cx, file: Span) -> Result<Vec<u8>> {
    if file.len > MAX_TEXT {
        cx.diag(Diagnostic::limit(format!(
            "only the first {MAX_TEXT:#x} bytes are examined"
        )));
    }
    cx.read_avail(file.sub(0, MAX_TEXT)).await
}

/// Lines of `data` as `(start, text)`.
fn lines(data: &[u8]) -> impl Iterator<Item = (usize, &[u8])> {
    let mut pos = 0usize;
    data.split(|&b| b == b'\n').map(move |line| {
        let start = pos;
        pos = pos.saturating_add(line.len()).saturating_add(1);
        (start, line)
    })
}

fn find(data: &[u8], needle: &[u8], from: usize) -> Option<usize> {
    data.get(from..)?
        .windows(needle.len())
        .position(|w| w == needle)
        .map(|p| p.saturating_add(from))
}

pub async fn dissect_xbm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = whole(&cx, file).await?;
    let (mut width, mut height) = (0u64, 0u64);
    let mut name = String::new();
    for (start, line) in lines(&data) {
        let text_line = crate::text::latin1(line);
        let mut words = text_line.split_whitespace();
        if words.next() != Some("#define") {
            continue;
        }
        let (Some(symbol), Some(value)) = (words.next(), words.next()) else {
            continue;
        };
        let Ok(value) = value.parse::<u64>() else {
            continue;
        };
        let suffix = ["_width", "_height", "_x_hot", "_y_hot"]
            .into_iter()
            .find(|s| symbol.ends_with(s));
        match suffix {
            Some("_width") => {
                width = value;
                name = symbol.trim_end_matches("_width").to_owned();
            }
            Some("_height") => height = value,
            _ => {}
        }
        cx.emit(
            Node::new(symbol.to_owned())
                .span(file.sub(to_u64(start), to_u64(line.len())))
                .value(uint(value)),
        );
    }
    let open = find(&data, b"{", 0);
    let close = open.and_then(|o| find(&data, b"}", o));
    let expected = (width.saturating_add(7) / 8).saturating_mul(height);
    if let (Some(open), Some(close)) = (open, close) {
        let body = data.get(open..close).unwrap_or_default();
        let values = body.split(|&b| b == b',').filter(|v| v.iter().any(u8::is_ascii_hexdigit)).count();
        let mut node = Node::new("Bits")
            .span(file.sub(to_u64(open), to_u64(close.saturating_sub(open)).saturating_add(1)))
            .summary(format!("{values} bytes, LSB is the leftmost pixel"));
        if to_u64(values) != expected {
            node = node.diag(Diagnostic::warning(format!("expected {expected} bytes")));
        }
        cx.emit(node);
    }
    cx.annotate(format!("{}, {name:?}", dims(width, height)));
    Ok(())
}

/// The C string literals in `data`: `(start of the quote, contents)`.
fn strings(data: &[u8]) -> Vec<(usize, &[u8])> {
    let mut out = Vec::new();
    let mut pos = 0usize;
    let mut in_comment = false;
    while let Some(&b) = data.get(pos) {
        let next = data.get(pos.saturating_add(1)).copied();
        if in_comment {
            if b == b'*' && next == Some(b'/') {
                in_comment = false;
                pos = pos.saturating_add(1);
            }
        } else if b == b'/' && next == Some(b'*') {
            in_comment = true;
        } else if b == b'"' {
            let start = pos.saturating_add(1);
            let end = data
                .get(start..)
                .and_then(|r| r.iter().position(|&c| c == b'"' || c == b'\n'))
                .map_or(data.len(), |e| e.saturating_add(start));
            out.push((pos, data.get(start..end).unwrap_or_default()));
            pos = end;
        }
        pos = pos.saturating_add(1);
    }
    out
}

pub async fn dissect_xpm(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let data = whole(&cx, file).await?;
    let all = strings(&data);
    let span_of = |(start, s): (usize, &[u8])| file.sub(to_u64(start), to_u64(s.len()).saturating_add(2));
    let Some(&first) = all.first() else {
        return Err(Diagnostic::malformed("no strings").at(file));
    };
    let values: Vec<u64> = crate::text::latin1(first.1)
        .split_whitespace()
        .filter_map(|w| w.parse().ok())
        .collect();
    let [width, height, colors, cpp, ..] = values.as_slice() else {
        return Err(Diagnostic::malformed("bad values string").at(span_of(first)));
    };
    cx.emit(
        Node::new("Values")
            .span(span_of(first))
            .value(text(crate::text::latin1(first.1)))
            .summary(format!("{}, {colors} colors, {cpp} chars per pixel", dims(width, height))),
    );
    cx.annotate(format!("{}, {colors} colors", dims(width, height)));
    let color_lines: Vec<Span> = all
        .iter()
        .skip(1)
        .take(usize::try_from(*colors).unwrap_or(usize::MAX))
        .map(|&s| span_of(s))
        .collect();
    if let (Some(a), Some(b)) = (color_lines.first(), color_lines.last()) {
        let span = Span::new(a.source, a.offset, b.end().saturating_sub(a.offset));
        cx.emit(
            Node::new("Colors")
                .span(span)
                .summary(format!("{} entries", color_lines.len()))
                .lazy(xpm_colors, (span, *cpp)),
        );
    }
    let rows: Vec<Span> = all
        .iter()
        .skip(color_lines.len().saturating_add(1))
        .take(usize::try_from(*height).unwrap_or(usize::MAX))
        .map(|&s| span_of(s))
        .collect();
    if let (Some(a), Some(b)) = (rows.first(), rows.last()) {
        let mut node = Node::new("Pixels")
            .span(Span::new(a.source, a.offset, b.end().saturating_sub(a.offset)))
            .summary(format!("{} rows", rows.len()));
        if to_u64(rows.len()) != *height {
            node = node.diag(Diagnostic::warning(format!("expected {height} rows")));
        }
        cx.emit(node);
    }
    Ok(())
}

async fn xpm_colors(cx: Cx, (span, cpp): (Span, u64)) -> Result<()> {
    let data = cx.read(span).await?;
    let entries = strings(&data);
    cx.set_count(Count::Exact(to_u64(entries.len())));
    for (start, s) in entries {
        let chars = usize::try_from(cpp).unwrap_or(0).min(s.len());
        let (key, rest) = s.split_at(chars);
        cx.push(
            Node::new(format!("{:?}", crate::text::latin1(key)))
                .span(span.sub(to_u64(start), to_u64(s.len()).saturating_add(2)))
                .value(text(crate::text::latin1(rest).trim().to_owned())),
        )
        .await;
    }
    Ok(())
}
