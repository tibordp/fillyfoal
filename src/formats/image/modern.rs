//! Smaller modern codecs with simple headers: BPG (HEVC in a light
//! wrapper) and FLIF (Free Lossless Image Format). Only their headers are
//! decoded; the compressed data is shown as a region.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::Node;
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value, lookup};

use super::{dims, region, text, uint};

pub static BPG: Format = Format {
    name: "bpg",
    title: "Better Portable Graphics",
    extensions: &["bpg"],
    mime: "image/bpg",
    probe: Probe::Magic(&[(0, b"BPG\xfb")]),
    dissect: crate::expander!(dissect_bpg: Input),
};

pub static FLIF: Format = Format {
    name: "flif",
    title: "Free Lossless Image Format",
    extensions: &["flif"],
    mime: "image/flif",
    probe: Probe::Custom(|h| {
        h.starts_with(b"FLIF")
            && h.data.get(4).is_some_and(|&b| (0x31..=0x64).contains(&b))
            && h.data
                .get(5)
                .is_some_and(|&b| matches!(b, b'0' | b'1' | b'2'))
    }),
    dissect: crate::expander!(dissect_flif: Input),
};

/// Big-endian base-128 with a continuation bit (BPG `ue7`, FLIF varint):
/// `(value, length)`.
fn varint(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..9usize {
        let b = *data.get(pos.checked_add(i)?)?;
        value = value.checked_shl(7)? | u64::from(b & 0x7f);
        if b & 0x80 == 0 {
            return Some((value, i.checked_add(1)?));
        }
    }
    None
}

/// Emits a varint field at `*pos` within `span` and advances.
fn varint_node(
    name: &'static str,
    span: Span,
    data: &[u8],
    pos: &mut usize,
) -> Result<(Node, u64)> {
    let (value, len) = varint(data, *pos).ok_or_else(|| {
        Diagnostic::malformed(format!("bad {name}")).at(span.sub(to_u64(*pos), 1))
    })?;
    let node = Node::new(name)
        .span(span.sub(to_u64(*pos), to_u64(len)))
        .value(uint(value));
    *pos = pos.saturating_add(len);
    Ok((node, value))
}

fn byte_node(name: &'static str, span: Span, value: u8, pos: usize) -> Node {
    Node::new(name)
        .span(span.sub(to_u64(pos), 1))
        .value(Value::UInt {
            value: value.into(),
            bits: 8,
            radix: Radix::Hex,
        })
}

const BPG_FORMATS: EnumTable = &[
    (0, "Grayscale"),
    (1, "YCbCr 4:2:0 (JPEG chroma position)"),
    (2, "YCbCr 4:2:2 (JPEG chroma position)"),
    (3, "YCbCr 4:4:4"),
    (4, "YCbCr 4:2:0 (MPEG2 chroma position)"),
    (5, "YCbCr 4:2:2 (MPEG2 chroma position)"),
];

const BPG_SPACES: EnumTable = &[
    (0, "YCbCr (BT.601)"),
    (1, "RGB"),
    (2, "YCgCo"),
    (3, "YCbCr (BT.709)"),
    (4, "YCbCr (BT.2020 non-constant luminance)"),
    (5, "YCbCr (BT.2020 constant luminance)"),
];

const BPG_EXTENSIONS: EnumTable = &[
    (1, "Exif"),
    (2, "ICC profile"),
    (3, "XMP"),
    (4, "Thumbnail"),
    (5, "Animation control"),
];

/// What the alpha flags say about the fourth plane.
fn bpg_alpha(alpha1: bool, alpha2: bool) -> Option<&'static str> {
    match (alpha1, alpha2) {
        (false, false) => None,
        (true, false) => Some("alpha"),
        (true, true) => Some("premultiplied alpha"),
        (false, true) => Some("CMYK (the alpha plane holds black)"),
    }
}

/// Bytes of the BPG header read at once (the extension data is read
/// separately).
const BPG_HEAD: u64 = 64;

pub async fn dissect_bpg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, BPG_HEAD)).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let (Some(&b4), Some(&b5)) = (head.get(4), head.get(5)) else {
        return Err(Diagnostic::truncated(file.sub(0, 6), to_u64(head.len())));
    };
    let format = b4 >> 5;
    let alpha1 = b4 & 0x10 != 0;
    let depth = (b4 & 15).saturating_add(8);
    let space = b5 >> 4;
    let extension = b5 & 8 != 0;
    let alpha2 = b5 & 4 != 0;
    let limited = b5 & 2 != 0;
    let animated = b5 & 1 != 0;
    let alpha = bpg_alpha(alpha1, alpha2);
    let pixel_format = lookup(BPG_FORMATS, format.into()).unwrap_or("reserved");
    cx.emit(
        byte_node("Pixel format, alpha, bit depth", file, b4, 4).summary(format!(
            "{pixel_format}{}, {depth}-bit",
            if alpha1 { ", alpha" } else { "" }
        )),
    );
    let color_space = lookup(BPG_SPACES, space.into()).unwrap_or("reserved");
    cx.emit(
        byte_node("Color space and flags", file, b5, 5).summary(format!(
            "{color_space}{}{}{}{}",
            if extension { ", extensions" } else { "" },
            if alpha2 { ", alpha2" } else { "" },
            if limited { ", limited range" } else { "" },
            if animated { ", animated" } else { "" }
        )),
    );
    let mut pos = 6usize;
    let (node, width) = varint_node("Width", file, &head, &mut pos)?;
    cx.emit(node);
    let (node, height) = varint_node("Height", file, &head, &mut pos)?;
    cx.emit(node);
    let (node, data_len) = varint_node("Picture data length", file, &head, &mut pos)?;
    cx.emit(node.desc("0: up to the end of the file"));
    let mut at = to_u64(pos);
    if extension {
        let (node, ext_len) = varint_node("Extension data length", file, &head, &mut pos)?;
        cx.emit(node);
        at = to_u64(pos);
        let ext = file.sub(at, ext_len);
        cx.emit(region("Extension data", file, at, ext_len).lazy(bpg_extensions, (input, ext)));
        at = at.saturating_add(ext_len);
    }
    let mut summary = format!("{}, {pixel_format}, {depth}-bit", dims(width, height));
    if let Some(alpha) = alpha {
        summary = format!("{summary}, {alpha}");
    }
    if space != 0 {
        summary = format!("{summary}, {color_space}");
    }
    if animated {
        summary.push_str(", animated");
    }
    cx.annotate(summary);
    let len = if data_len == 0 {
        file.len.saturating_sub(at)
    } else {
        data_len
    };
    let picture = file.sub(at, len);
    cx.emit(
        region("Picture data", file, at, len)
            .desc("HEVC header(s) for the alpha and color planes, then the HEVC NAL units")
            .lazy(bpg_picture, (picture, alpha.is_some())),
    );
    Ok(())
}

async fn bpg_extensions(cx: Cx, (input, span): (Input, Span)) -> Result<()> {
    let mut pos = 0u64;
    while pos < span.len {
        let head = cx.read_avail(span.sub(pos, 20)).await?;
        let Some((tag, n)) = varint(&head, 0) else {
            cx.diag(Diagnostic::malformed("bad extension tag").at(span.sub(pos, 1)));
            break;
        };
        let Some((len, m)) = varint(&head, n) else {
            cx.diag(Diagnostic::malformed("bad extension length").at(span.sub(pos, 1)));
            break;
        };
        let at = to_u64(n.saturating_add(m));
        let body = span.sub(pos.saturating_add(at), len);
        let entry = span.sub(pos, at.saturating_add(len));
        let name =
            lookup(BPG_EXTENSIONS, tag).map_or_else(|| format!("Extension {tag}"), str::to_owned);
        let node = match tag {
            // Exif (a TIFF structure), ICC profile, XMP packet.
            1..=3 => embedded(name, input.nested(body)),
            5 => {
                let data = cx.read_avail(body.sub(0, 16)).await?;
                let (loops, a) = varint(&data, 0).unwrap_or_default();
                let (num, b) = varint(&data, a).unwrap_or_default();
                let (den, _) = varint(&data, a.saturating_add(b)).unwrap_or_default();
                let fps = if num > 0 {
                    format!("{:.3} fps", den as f64 / num as f64)
                } else {
                    "unknown rate".to_owned()
                };
                Node::new(name).span(entry).summary(format!(
                    "{}, frame period {num}/{den} s ({fps})",
                    if loops == 0 {
                        "loops forever".to_owned()
                    } else {
                        format!("{loops} loops")
                    }
                ))
            }
            _ => Node::new(name).span(entry).summary(format!("{len} bytes")),
        };
        cx.push(node).await;
        pos = pos.saturating_add(entry.len.max(1));
    }
    Ok(())
}

async fn bpg_picture(cx: Cx, (span, alpha): (Span, bool)) -> Result<()> {
    let mut pos = 0u64;
    let planes: &[&'static str] = if alpha {
        &["Alpha HEVC header", "HEVC header"]
    } else {
        &["HEVC header"]
    };
    for &name in planes {
        let head = cx.read_avail(span.sub(pos, 8)).await?;
        let Some((len, n)) = varint(&head, 0) else {
            return Err(Diagnostic::malformed("bad HEVC header length").at(span.sub(pos, 1)));
        };
        let entry = span.sub(pos, to_u64(n).saturating_add(len));
        cx.emit(
            Node::new(name)
                .span(entry)
                .summary(format!("{len} bytes"))
                .desc("Length, then the SPS fields BPG keeps (exp-Golomb coded)"),
        );
        pos = pos.saturating_add(entry.len);
    }
    cx.emit(region("HEVC data", span, pos, span.len.saturating_sub(pos)));
    Ok(())
}

/// Metadata chunks listed before giving up.
const MAX_FLIF_CHUNKS: usize = 64;

pub async fn dissect_flif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 32)).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(text("FLIF")));
    let (Some(&kind), Some(&bpc)) = (head.get(4), head.get(5)) else {
        return Err(Diagnostic::truncated(file.sub(0, 6), to_u64(head.len())));
    };
    let interlaced = matches!(kind >> 4, 4 | 6);
    let animated = matches!(kind >> 4, 5 | 6);
    let channels = kind & 15;
    let color = match channels {
        1 => "grayscale",
        3 => "RGB",
        4 => "RGBA",
        _ => "channels",
    };
    cx.emit(
        Node::new("Format")
            .span(file.sub(4, 1))
            .value(text(char::from(kind).to_string()))
            .summary(format!(
                "{}{}, {channels} channels ({color})",
                if interlaced {
                    "interlaced"
                } else {
                    "non-interlaced"
                },
                if animated { ", animated" } else { "" }
            )),
    );
    let depth = match bpc {
        b'1' => "8-bit",
        b'2' => "16-bit",
        _ => "custom depth",
    };
    cx.emit(
        Node::new("Bytes per channel")
            .span(file.sub(5, 1))
            .value(text(char::from(bpc).to_string()))
            .summary(depth),
    );
    let mut pos = 6usize;
    let (node, w) = varint_node("Width - 1", file, &head, &mut pos)?;
    cx.emit(node);
    let (node, h) = varint_node("Height - 1", file, &head, &mut pos)?;
    cx.emit(node);
    let mut frames = 1;
    if animated {
        let (node, n) = varint_node("Frames - 2", file, &head, &mut pos)?;
        cx.emit(node);
        frames = n.saturating_add(2);
    }
    let (width, height) = (w.saturating_add(1), h.saturating_add(1));
    let mut summary = format!("{}, {color}, {depth}", dims(width, height));
    if interlaced {
        summary.push_str(", interlaced");
    }
    if animated {
        summary = format!("{summary}, {frames} frames");
    }
    cx.annotate(summary);
    // Metadata chunks: four-letter name, varint length, deflated content.
    // The second header (the image data) starts with a byte below 32.
    let mut pos = to_u64(pos);
    for _ in 0..MAX_FLIF_CHUNKS {
        let chunk = cx.read_avail(file.sub(pos, 14)).await?;
        let Some(&first) = chunk.first() else {
            break;
        };
        if first < 32 {
            break;
        }
        let name = crate::text::latin1(chunk.get(..4).unwrap_or_default());
        let Some((len, n)) = varint(&chunk, 4) else {
            break;
        };
        let header = to_u64(n).saturating_add(4);
        let span = file.sub(pos, header.saturating_add(len));
        let what = match name.as_str() {
            "iCCP" => "ICC profile",
            "eXif" => "Exif",
            "eXmp" => "XMP",
            _ => "metadata",
        };
        cx.emit(
            Node::new(name)
                .span(span)
                .summary(format!("{what}, {len} bytes, deflate-compressed")),
        );
        pos = pos.saturating_add(header).saturating_add(len);
    }
    cx.emit(region(
        "Image data",
        file,
        pos,
        file.len.saturating_sub(pos),
    ));
    Ok(())
}
