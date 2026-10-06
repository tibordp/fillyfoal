//! Netpbm: PBM, PGM, PPM (plain P1–P3 and raw P4–P6), PAM (P7) and the
//! floating-point PFM.
//!
//! A text header (magic, whitespace-separated numbers, `#` comments) is
//! followed by the raster. P7 has a line-oriented header ending in `ENDHDR`.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;

use super::{dims, region, text, uint};

macro_rules! pnm_format {
    ($id:ident, $name:literal, $title:literal, [$($ext:literal),*], $mime:literal, $magics:expr) => {
        pub static $id: Format = Format {
            name: $name,
            title: $title,
            extensions: &[$($ext),*],
            mime: $mime,
            probe: Probe::Custom(|h| probe(h, $magics)),
            dissect: crate::expander!(dissect: Input),
        };
    };
}

pnm_format!(PBM, "pbm", "Portable bitmap", ["pbm"], "image/x-portable-bitmap", b"14");
pnm_format!(PGM, "pgm", "Portable graymap", ["pgm"], "image/x-portable-graymap", b"25");
pnm_format!(PPM, "ppm", "Portable pixmap", ["ppm", "pnm"], "image/x-portable-pixmap", b"36");
pnm_format!(PAM, "pam", "Portable arbitrary map", ["pam"], "image/x-portable-arbitrarymap", b"7");
pnm_format!(PFM, "pfm", "Portable float map", ["pfm"], "image/x-portable-floatmap", b"Ff");

/// `P` + one of `magics`, then whitespace and a digit or comment (P7: a
/// keyword line).
fn probe(h: &Head<'_>, magics: &[u8]) -> bool {
    let d = h.data;
    let (Some(b'P'), Some(m), Some(ws)) = (d.first(), d.get(1), d.get(2)) else {
        return false;
    };
    if !magics.contains(m) || !ws.is_ascii_whitespace() {
        return false;
    }
    let next = d.get(3..).and_then(|r| r.iter().find(|b| !b.is_ascii_whitespace()));
    match m {
        b'7' => next.is_some_and(|b| b.is_ascii_uppercase() || *b == b'#'),
        _ => next.is_some_and(|b| b.is_ascii_digit() || *b == b'#'),
    }
}

/// How much header text is examined.
const HEADER_MAX: u64 = 4096;

/// A whitespace-separated word or a comment within the header.
#[derive(Debug)]
struct Token<'a> {
    start: usize,
    text: &'a [u8],
    comment: bool,
}

/// Splits `data` into words and comments, starting at `pos`.
fn tokens(data: &[u8], mut pos: usize) -> impl Iterator<Item = Token<'_>> {
    std::iter::from_fn(move || {
        while data.get(pos).is_some_and(u8::is_ascii_whitespace) {
            pos = pos.saturating_add(1);
        }
        let start = pos;
        let comment = data.get(pos) == Some(&b'#');
        let stop = |b: &u8| {
            if comment {
                *b == b'\n' || *b == b'\r'
            } else {
                b.is_ascii_whitespace() || *b == b'#'
            }
        };
        while data.get(pos).is_some_and(|b| !stop(b)) {
            pos = pos.saturating_add(1);
        }
        (pos > start).then(|| Token {
            start,
            text: data.get(start..pos).unwrap_or_default(),
            comment,
        })
    })
}

fn number(t: &Token<'_>) -> Option<u64> {
    std::str::from_utf8(t.text).ok()?.parse().ok()
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, HEADER_MAX)).await?;
    let magic = head.get(1).copied().unwrap_or(0);
    let (kind, encoding) = match magic {
        b'1' => ("PBM", "plain"),
        b'2' => ("PGM", "plain"),
        b'3' => ("PPM", "plain"),
        b'4' => ("PBM", "raw"),
        b'5' => ("PGM", "raw"),
        b'6' => ("PPM", "raw"),
        b'7' => ("PAM", "raw"),
        b'F' => ("PFM", "RGB"),
        b'f' => ("PFM", "grayscale"),
        _ => return Err(Diagnostic::malformed("not a Netpbm magic").at(file.sub(0, 2))),
    };
    cx.emit(
        Node::new("Magic")
            .span(file.sub(0, 2))
            .value(text(crate::text::latin1(head.get(..2).unwrap_or_default())))
            .summary(format!("{kind}, {encoding}")),
    );
    let at = |t: &Token<'_>| file.sub(to_u64(t.start), to_u64(t.text.len()));
    let (raster_start, width, height, raster_len, detail) = if magic == b'7' {
        pam_header(&cx, file, &head).await?
    } else {
        let names: &[&'static str] = match magic {
            b'1' | b'4' => &["Width", "Height"],
            b'F' | b'f' => &["Width", "Height", "Scale"],
            _ => &["Width", "Height", "Maxval"],
        };
        let mut values = Vec::new();
        let mut end = 2usize;
        for t in tokens(&head, 2) {
            end = t.start.saturating_add(t.text.len());
            if t.comment {
                cx.emit(
                    Node::new("Comment")
                        .span(at(&t))
                        .value(text(crate::text::latin1(t.text))),
                );
                continue;
            }
            let Some(&name) = names.get(values.len()) else {
                break;
            };
            let word = crate::text::latin1(t.text);
            let node = Node::new(name).span(at(&t));
            if name == "Scale" {
                let scale: f64 = word.parse().unwrap_or(0.0);
                let order = if scale < 0.0 {
                    "little-endian"
                } else {
                    "big-endian"
                };
                cx.emit(node.value(crate::value::Value::Float(scale)).summary(order));
                values.push(0);
            } else {
                let Some(n) = number(&t) else {
                    return Err(Diagnostic::malformed(format!("bad {name}")).at(at(&t)));
                };
                cx.emit(node.value(uint(n)));
                values.push(n);
            }
            if values.len() == names.len() {
                break;
            }
        }
        if values.len() < names.len() {
            return Err(Diagnostic::truncated(file.sub(0, to_u64(head.len())), to_u64(head.len())));
        }
        let w = values.first().copied().unwrap_or(0);
        let h = values.get(1).copied().unwrap_or(0);
        let maxval = values.get(2).copied().unwrap_or(1);
        let bytes_per_sample: u64 = if maxval > 255 { 2 } else { 1 };
        let pixels = w.saturating_mul(h);
        let len = match magic {
            b'4' => (w.saturating_add(7) / 8).saturating_mul(h),
            b'5' => pixels.saturating_mul(bytes_per_sample),
            b'6' => pixels.saturating_mul(3).saturating_mul(bytes_per_sample),
            b'F' => pixels.saturating_mul(12),
            b'f' => pixels.saturating_mul(4),
            // Plain formats: the rest of the file.
            _ => file.len.saturating_sub(to_u64(end).saturating_add(1)),
        };
        let detail = match magic {
            b'1' | b'4' => "1-bit".to_owned(),
            b'F' | b'f' => "32-bit float".to_owned(),
            _ => format!("maxval {maxval}"),
        };
        (to_u64(end).saturating_add(1), w, h, len, detail)
    };
    cx.annotate(format!("{}, {kind} {encoding}, {detail}", dims(width, height)));
    let raster = region("Raster", file, raster_start, raster_len);
    cx.emit(if magic == b'F' || magic == b'f' {
        raster.desc("Rows bottom to top")
    } else {
        raster
    });
    let end = raster_start.saturating_add(raster_len);
    if end < file.len && matches!(magic, b'4' | b'5' | b'6' | b'7') {
        let rest = file.tail(end);
        cx.emit(embedded("Next image", input.nested(rest)).summary(format!("{:#x} bytes", rest.len)));
    }
    Ok(())
}

/// The P7 header: `KEY value` lines up to `ENDHDR`.
async fn pam_header(
    cx: &Cx,
    file: Span,
    head: &[u8],
) -> Result<(u64, u64, u64, u64, String)> {
    let (mut w, mut h, mut depth, mut maxval) = (0u64, 0u64, 0u64, 0u64);
    let mut tuple = String::new();
    let mut pos = 3usize;
    loop {
        let rest = head.get(pos..).unwrap_or_default();
        let Some(len) = rest.iter().position(|&b| b == b'\n') else {
            return Err(Diagnostic::malformed("PAM header without ENDHDR").at(file.sub(0, to_u64(head.len()))));
        };
        let line = rest.get(..len).unwrap_or_default();
        let span = file.sub(to_u64(pos), to_u64(len));
        pos = pos.saturating_add(len).saturating_add(1);
        let text_line = crate::text::latin1(line);
        let mut words = text_line.split_whitespace();
        let key = words.next().unwrap_or_default().to_owned();
        let value = words.collect::<Vec<_>>().join(" ");
        if key.starts_with('#') {
            cx.emit(Node::new("Comment").span(span).value(text(text_line.clone())));
            continue;
        }
        if key == "ENDHDR" {
            cx.emit(Node::new("ENDHDR").span(span));
            break;
        }
        if key.is_empty() {
            continue;
        }
        let n: Option<u64> = value.parse().ok();
        match key.as_str() {
            "WIDTH" => w = n.unwrap_or(0),
            "HEIGHT" => h = n.unwrap_or(0),
            "DEPTH" => depth = n.unwrap_or(0),
            "MAXVAL" => maxval = n.unwrap_or(0),
            "TUPLTYPE" => tuple = value.clone(),
            _ => {}
        }
        let node = Node::new(key).span(span);
        cx.emit(match n {
            Some(n) => node.value(uint(n)),
            None => node.value(text(value)),
        });
    }
    let bps: u64 = if maxval > 255 { 2 } else { 1 };
    let len = w.saturating_mul(h).saturating_mul(depth).saturating_mul(bps);
    let detail = if tuple.is_empty() {
        format!("depth {depth}, maxval {maxval}")
    } else {
        format!("{tuple}, maxval {maxval}")
    };
    Ok((to_u64(pos), w, h, len, detail))
}
