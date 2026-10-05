//! PNG, APNG and MNG/JNG-style chunk streams.
//!
//! The file is a signature followed by chunks `length, type, data, crc`. The
//! top level lists chunks (paged); expanding one decodes its fields and checks
//! its CRC.

use crate::bytes::u32_be;
use crate::codec::{crc32, inflate_span};
use crate::cx::Cx;
use crate::dsl::{Cursor, Record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "png",
    title: "Portable Network Graphics",
    extensions: &["png", "apng"],
    mime: "image/png",
    probe: Probe::Magic(&[(0, b"\x89PNG\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

pub static MNG: Format = Format {
    name: "mng",
    title: "Multiple-image Network Graphics",
    extensions: &["mng"],
    mime: "video/x-mng",
    probe: Probe::Magic(&[(0, b"\x8aMNG\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

pub static JNG: Format = Format {
    name: "jng",
    title: "JPEG Network Graphics",
    extensions: &["jng"],
    mime: "image/x-jng",
    probe: Probe::Magic(&[(0, b"\x8bJNG\r\n\x1a\n")]),
    dissect: crate::expander!(dissect: Input),
};

const COLOR_TYPE: EnumTable = &[
    (0, "Grayscale"),
    (2, "RGB"),
    (3, "Indexed"),
    (4, "Grayscale + alpha"),
    (6, "RGBA"),
];

const INTERLACE: EnumTable = &[(0, "None"), (1, "Adam7")];

const UNIT: EnumTable = &[(0, "unknown"), (1, "metre")];

const RENDERING_INTENT: EnumTable = &[
    (0, "Perceptual"),
    (1, "Relative colorimetric"),
    (2, "Saturation"),
    (3, "Absolute colorimetric"),
];

record! {
    pub struct Ihdr {
        width: u32 "Width",
        height: u32 "Height",
        bit_depth: u8 "Bit depth",
        color_type: u8 "Color type" .enumeration(COLOR_TYPE),
        compression: u8 "Compression method" .desc("0 = deflate"),
        filter: u8 "Filter method",
        interlace: u8 "Interlace method" .enumeration(INTERLACE),
    }
}

record! {
    pub struct Phys {
        x: u32 "Pixels per unit, X",
        y: u32 "Pixels per unit, Y",
        unit: u8 "Unit" .enumeration(UNIT),
    }
}

record! {
    pub struct Time {
        year: u16 "Year",
        month: u8 "Month",
        day: u8 "Day",
        hour: u8 "Hour",
        minute: u8 "Minute",
        second: u8 "Second",
    }
}

record! {
    pub struct Chrm {
        white_x: u32 "White point x",
        white_y: u32 "White point y",
        red_x: u32 "Red x",
        red_y: u32 "Red y",
        green_x: u32 "Green x",
        green_y: u32 "Green y",
        blue_x: u32 "Blue x",
        blue_y: u32 "Blue y",
    }
}

record! {
    /// APNG animation control.
    pub struct Actl {
        frames: u32 "Number of frames",
        plays: u32 "Number of plays" .desc("0 = loop forever"),
    }
}

record! {
    /// APNG frame control.
    pub struct Fctl {
        sequence: u32 "Sequence number",
        width: u32 "Width",
        height: u32 "Height",
        x: u32 "X offset",
        y: u32 "Y offset",
        delay_num: u16 "Delay numerator",
        delay_den: u16 "Delay denominator",
        dispose: u8 "Dispose op",
        blend: u8 "Blend op",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let mut cur = Cursor::new(&cx, input.span, BE);
    cx.emit(Node::new("Signature").span(cur.span(8)));
    cur.skip(8);
    let mut first = true;
    let mut animated = false;
    while !cur.at_end() {
        let start = cur.pos();
        let header = cur.bytes(8).await?;
        let len = u64::from(u32_be(&header, 0).unwrap_or(0));
        let kind = String::from_utf8_lossy(header.get(4..8).unwrap_or_default()).into_owned();
        let total = len.saturating_add(12);
        let span = input.span.sub(start, total);
        let mut node = Node::new(kind.clone())
            .span(span)
            .summary(format!("{len:#x} bytes"));
        if span.len < total {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, total),
                span.len,
            ));
        }
        if first && kind == "IHDR" {
            let data = cur.peek(Ihdr::SIZE).await?;
            if let (Some(w), Some(h)) = (u32_be(&data, 0), u32_be(&data, 4)) {
                let depth = data.get(8).copied().unwrap_or(0);
                let color = data.get(9).copied().unwrap_or(0);
                let color = crate::value::lookup(COLOR_TYPE, color.into()).unwrap_or("?");
                node = node.summary(format!("{w}×{h}, {depth}-bit {color}"));
                cx.annotate(format!("{w}×{h}, {depth}-bit {color}"));
            }
        }
        if kind == "acTL" && !animated {
            animated = true;
            cx.diag(Diagnostic::note("animated (APNG)"));
        }
        first = false;
        cx.push(node.lazy(chunk, (input, span, kind.clone()))).await;
        cur.seek(start.saturating_add(total));
        if kind == "IEND" || kind == "MEND" {
            break;
        }
    }
    if !cur.at_end() {
        let rest = input.span.tail(cur.pos());
        cx.emit(
            embedded("Trailing data", input.nested(rest))
                .summary(format!("{:#x} bytes after the end chunk", rest.len)),
        );
    }
    Ok(())
}

async fn chunk(cx: Cx, (input, span, kind): (Input, Span, String)) -> Result<()> {
    let header = cx.block(span.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &header, BE);
    f.u32("Length").emit()?;
    f.ascii("Type", 4).summary(chunk_kind(&kind)).emit()?;
    let data = span.sub(8, span.len.saturating_sub(12));
    let rec = |name: &'static str, size: u64| (name, data.sub(0, size));
    match kind.as_str() {
        "IHDR" => {
            let (name, s) = rec("Header", Ihdr::SIZE);
            cx.emit(Ihdr::node(name, s, BE));
        }
        "pHYs" => {
            let (name, s) = rec("Physical dimensions", Phys::SIZE);
            cx.emit(Phys::node(name, s, BE));
        }
        "tIME" => {
            let (name, s) = rec("Last modification", Time::SIZE);
            cx.emit(Time::node(name, s, BE));
        }
        "cHRM" => {
            let (name, s) = rec("Chromaticities", Chrm::SIZE);
            cx.emit(Chrm::node(name, s, BE));
        }
        "acTL" => {
            let (name, s) = rec("Animation control", Actl::SIZE);
            cx.emit(Actl::node(name, s, BE));
        }
        "fcTL" => {
            let (name, s) = rec("Frame control", Fctl::SIZE);
            cx.emit(Fctl::node(name, s, BE));
        }
        "gAMA" => {
            let v = cx.read(data.sub(0, 4)).await?;
            let gamma = u32_be(&v, 0).unwrap_or(0);
            cx.emit(
                Node::new("Gamma")
                    .span(data.sub(0, 4))
                    .value(Value::UInt {
                        value: gamma.into(),
                        bits: 32,
                        radix: crate::value::Radix::Dec,
                    })
                    .summary(format!("{:.5}", f64::from(gamma) / 100_000.0)),
            );
        }
        "sRGB" => {
            let v = cx.read(data.sub(0, 1)).await?;
            let intent = v.first().copied().unwrap_or(0);
            cx.emit(Node::new("Rendering intent").span(data.sub(0, 1)).value(
                Value::Enum {
                    raw: intent.into(),
                    bits: 8,
                    name: crate::value::lookup(RENDERING_INTENT, intent.into()),
                },
            ));
        }
        "PLTE" => {
            cx.emit(
                Node::new("Palette")
                    .span(data)
                    .summary(format!("{} entries", data.len / 3)),
            );
        }
        "tEXt" => text(&cx, data, false).await?,
        "zTXt" => text(&cx, data, true).await?,
        "iTXt" => international_text(&cx, data).await?,
        "iCCP" => {
            let (name, at) = cx.cstr(data.sub(0, 80)).await?;
            cx.emit(Node::new("Profile name").span(at).value(Value::Text(name)));
            let compressed = data.tail(at.len.saturating_add(1));
            let decoded = inflate_span(&cx, compressed, true, None).await?;
            let mut node = embedded("ICC profile", input.nested(decoded.span))
                .summary(format!("{:#x} bytes decompressed", decoded.span.len));
            if let Some(e) = decoded.error {
                node = node.diag(e);
            }
            cx.emit(node);
        }
        "eXIf" => cx.emit(embedded("Exif", input.nested(data))),
        _ => cx.emit(Node::new("Data").span(data)),
    }

    let crc_span = span.sub(span.len.saturating_sub(4), 4);
    let stored = cx.read(crc_span).await?;
    let stored = u32_be(&stored, 0).unwrap_or(0);
    let mut node = Node::new("CRC").span(crc_span).value(Value::UInt {
        value: stored.into(),
        bits: 32,
        radix: crate::value::Radix::Hex,
    });
    let covered = span.sub(4, span.len.saturating_sub(8));
    if covered.len <= cx.limits().max_read {
        let bytes = cx.read(covered).await?;
        let computed = crc32(&bytes);
        node = if computed == stored {
            node.summary("valid")
        } else {
            node.diag(Diagnostic::warning(format!(
                "CRC mismatch: computed {computed:#010x}"
            )))
        };
    }
    cx.emit(node);
    Ok(())
}

/// `tEXt` / `zTXt`: keyword, NUL, (compression method,) text.
async fn text(cx: &Cx, data: Span, compressed: bool) -> Result<()> {
    let (keyword, at) = cx.cstr(data.sub(0, 80)).await?;
    cx.annotate(keyword.clone());
    cx.emit(Node::new("Keyword").span(at).value(Value::Text(keyword)));
    let rest = data.tail(at.len);
    if compressed {
        let body = rest.tail(1);
        let decoded = inflate_span(cx, body, true, None).await?;
        let text = cx.read(decoded.span).await?;
        let mut node = Node::new("Text")
            .span(body)
            .value(Value::Text(latin1(&text)));
        if let Some(e) = decoded.error {
            node = node.diag(e);
        }
        cx.emit(node);
    } else {
        let text = cx.read(rest).await?;
        cx.emit(Node::new("Text").span(rest).value(Value::Text(latin1(&text))));
    }
    Ok(())
}

/// `iTXt`: keyword, flag, method, language, translated keyword, text (UTF-8).
async fn international_text(cx: &Cx, data: Span) -> Result<()> {
    let (keyword, at) = cx.cstr(data.sub(0, 80)).await?;
    cx.annotate(keyword.clone());
    cx.emit(Node::new("Keyword").span(at).value(Value::Text(keyword)));
    let mut pos = at.len;
    let flags = cx.read(data.sub(pos, 2)).await?;
    let compressed = flags.first().copied().unwrap_or(0) != 0;
    pos = pos.saturating_add(2);
    let (language, at) = cx.cstr(data.tail(pos)).await?;
    cx.emit(Node::new("Language").span(at).value(Value::Text(language)));
    pos = pos.saturating_add(at.len);
    let (translated, at) = cx.cstr(data.tail(pos)).await?;
    cx.emit(
        Node::new("Translated keyword")
            .span(at)
            .value(Value::Text(translated)),
    );
    pos = pos.saturating_add(at.len);
    let body = data.tail(pos);
    let (bytes, error) = if compressed {
        let decoded = inflate_span(cx, body, true, None).await?;
        (cx.read(decoded.span).await?, decoded.error)
    } else {
        (cx.read(body).await?, None)
    };
    let mut node = Node::new("Text")
        .span(body)
        .value(Value::Text(String::from_utf8_lossy(&bytes).into_owned()));
    if let Some(e) = error {
        node = node.diag(e);
    }
    cx.emit(node);
    Ok(())
}

fn latin1(bytes: &[u8]) -> String {
    bytes.iter().map(|&b| char::from(b)).collect()
}

fn chunk_kind(kind: &str) -> String {
    let bytes = kind.as_bytes();
    let bit = |i: usize| bytes.get(i).is_some_and(|b| b & 0x20 != 0);
    format!(
        "{}, {}, {}",
        if bit(0) { "ancillary" } else { "critical" },
        if bit(1) { "private" } else { "public" },
        if bit(3) { "safe to copy" } else { "unsafe to copy" }
    )
}
