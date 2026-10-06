//! YUV4MPEG2 (`.y4m`): a text header line with stream parameters, then
//! frames, each a `FRAME` line followed by raw planes.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::vidutil::{self, text};
use crate::formats::{Format, Input, Probe};
use crate::node::{Count, Node};
use crate::span::Span;

pub static FORMAT: Format = Format {
    name: "y4m",
    title: "YUV4MPEG2 video",
    extensions: &["y4m"],
    mime: "video/x-yuv4mpeg",
    probe: Probe::Magic(&[(0, b"YUV4MPEG2 ")]),
    dissect: crate::expander!(dissect: Input),
};

const MAX_LINE: u64 = 4096;

/// Stream parameters from the header.
#[derive(Clone, Copy, Debug, Default)]
struct Params {
    width: u64,
    height: u64,
    /// Plane sizes (Y, Cb, Cr, alpha) in bytes.
    planes: [u64; 4],
}

impl Params {
    fn frame_size(&self) -> u64 {
        self.planes.iter().fold(0u64, |a, &p| a.saturating_add(p))
    }
}

fn plane_sizes(width: u64, height: u64, colour: &str) -> [u64; 4] {
    let depth = if colour.contains("p10")
        || colour.contains("p12")
        || colour.contains("p14")
        || colour.contains("p16")
    {
        2
    } else {
        1
    };
    let luma = width.saturating_mul(height).saturating_mul(depth);
    let half = |n: u64| n.div_ceil(2);
    let chroma = if colour.starts_with("420") || colour.is_empty() {
        half(width).saturating_mul(half(height))
    } else if colour.starts_with("422") {
        half(width).saturating_mul(height)
    } else if colour.starts_with("411") {
        width.div_ceil(4).saturating_mul(height)
    } else if colour.starts_with("444") {
        width.saturating_mul(height)
    } else {
        0
    }
    .saturating_mul(depth);
    let alpha = if colour == "444alpha" { luma } else { 0 };
    [luma, chroma, chroma, alpha]
}

/// Reads one `\n`-terminated line starting at `pos`.
async fn line(cx: &Cx, file: Span, pos: u64) -> Result<Option<(String, u64)>> {
    let d = cx.read_avail(file.sub(pos, MAX_LINE)).await?;
    Ok(d.iter().position(|&b| b == b'\n').map(|n| {
        (
            String::from_utf8_lossy(d.get(..n).unwrap_or_default()).into_owned(),
            to_u64(n).saturating_add(1),
        )
    }))
}

#[derive(Clone, Copy, Debug)]
struct Frames {
    file: Span,
    start: u64,
    params: Params,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let Some((header, len)) = line(&cx, file, 0).await? else {
        return Err(Diagnostic::malformed("header line not terminated").at(file.sub(0, MAX_LINE)));
    };
    let header_span = file.sub(0, len);
    let mut params = Params::default();
    let mut colour = String::new();
    let mut rate = None;
    let mut interlace = None;
    for token in header.split(' ').skip(1) {
        let mut chars = token.chars();
        let Some(tag) = chars.next() else { continue };
        let value: String = chars.collect();
        match tag {
            'W' => params.width = value.parse().unwrap_or(0),
            'H' => params.height = value.parse().unwrap_or(0),
            'C' => colour = value,
            'F' => rate = Some(value),
            'I' => interlace = Some(value),
            _ => {}
        }
    }
    params.planes = plane_sizes(params.width, params.height, &colour);
    cx.emit(
        Node::new("Stream header")
            .span(header_span)
            .lazy(header_fields, header_span),
    );
    let frame_size = params.frame_size();
    // Frames without parameters are "FRAME\n" + planes.
    let per_frame = frame_size.saturating_add(6);
    let count = file
        .len
        .saturating_sub(len)
        .checked_div(per_frame)
        .unwrap_or(0);
    let mut summary = format!(
        "YUV4MPEG2, {}×{} {}",
        params.width,
        params.height,
        if colour.is_empty() {
            "420jpeg"
        } else {
            &colour
        }
    );
    if let Some(r) = rate {
        let fps = match r.split_once(':') {
            Some((n, d)) => match (n.parse::<f64>(), d.parse::<f64>()) {
                (Ok(n), Ok(d)) if d > 0.0 => vidutil::num(n / d),
                _ => r.clone(),
            },
            None => r.clone(),
        };
        summary = format!("{summary}, {fps} fps");
    }
    if interlace.as_deref().is_some_and(|i| i != "p") {
        summary.push_str(", interlaced");
    }
    summary = format!("{summary}, ~{}", vidutil::plural(count, "frame"));
    cx.annotate(summary);
    cx.emit(
        Node::new("Frames")
            .span(file.tail(len))
            .summary(format!("{frame_size} bytes per frame"))
            .lazy(
                frames,
                Frames {
                    file,
                    start: len,
                    params,
                },
            ),
    );
    Ok(())
}

async fn header_fields(cx: Cx, span: Span) -> Result<()> {
    let d = cx.read_avail(span).await?;
    let mut at = 0usize;
    for token in d.split(|&b| b == b' ' || b == b'\n') {
        let tspan = vidutil::at(span, at, token.len());
        at = at.saturating_add(token.len()).saturating_add(1);
        let Some((&tag, value)) = token.split_first() else {
            continue;
        };
        let value = String::from_utf8_lossy(value).into_owned();
        let name = match tag {
            b'Y' => {
                cx.emit(text(
                    "Signature",
                    tspan,
                    String::from_utf8_lossy(token).into_owned(),
                ));
                continue;
            }
            b'W' => "Width",
            b'H' => "Height",
            b'F' => "Frame rate",
            b'I' => "Interlacing",
            b'A' => "Pixel aspect ratio",
            b'C' => "Colour space",
            b'X' => "Extension",
            _ => "Parameter",
        };
        let mut node = match (tag, value.parse::<u64>()) {
            (b'W' | b'H', Ok(n)) => vidutil::uint(name, tspan, n, 32),
            _ => text(name, tspan, value.clone()),
        };
        if tag == b'I' {
            node = node.summary(match value.as_str() {
                "p" => "progressive",
                "t" => "top field first",
                "b" => "bottom field first",
                "m" => "mixed",
                _ => "unknown",
            });
        }
        cx.emit(node);
    }
    Ok(())
}

async fn frames(cx: Cx, f: Frames) -> Result<()> {
    let mut pos = f.start;
    let mut index = 0u64;
    let size = f.params.frame_size();
    while pos < f.file.len {
        let Some((head, len)) = line(&cx, f.file, pos).await? else {
            cx.emit(
                Node::new("Trailing data")
                    .span(f.file.tail(pos))
                    .diag(Diagnostic::malformed("frame header not terminated")),
            );
            break;
        };
        if !head.starts_with("FRAME") {
            cx.emit(
                Node::new("Trailing data")
                    .span(f.file.tail(pos))
                    .diag(Diagnostic::malformed("expected FRAME")),
            );
            break;
        }
        let total = len.saturating_add(size);
        let span = f.file.sub(pos, total);
        let mut node = Node::new(format!("Frame {index}"))
            .span(span)
            .lazy(frame, (span, len, f.params));
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        cx.push(node).await;
        pos = pos.saturating_add(total.max(1));
        index = index.saturating_add(1);
    }
    cx.set_count(Count::Exact(index));
    Ok(())
}

async fn frame(cx: Cx, (span, header, params): (Span, u64, Params)) -> Result<()> {
    let d = cx.read_avail(span.sub(0, header)).await?;
    let line = String::from_utf8_lossy(d.get(..d.len().saturating_sub(1)).unwrap_or_default())
        .into_owned();
    cx.emit(text("Frame header", span.sub(0, header), line));
    let mut at = header;
    for (name, size) in ["Y plane", "Cb plane", "Cr plane", "Alpha plane"]
        .iter()
        .zip(params.planes)
    {
        if size == 0 {
            continue;
        }
        cx.emit(
            Node::new(*name)
                .span(span.sub(at, size))
                .summary(format!("{size} bytes")),
        );
        at = at.saturating_add(size);
    }
    Ok(())
}
