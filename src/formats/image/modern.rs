//! Smaller modern codecs with simple headers: BPG (HEVC in a light
//! wrapper) and FLIF (Free Lossless Image Format). Only their headers are
//! decoded; the compressed data is shown as a region.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::{Format, Input, Probe};
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
    (4, "YCbCr (BT.2020)"),
    (5, "Reserved"),
];

pub async fn dissect_bpg(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 64)).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)));
    let (Some(&b4), Some(&b5)) = (head.get(4), head.get(5)) else {
        return Err(Diagnostic::truncated(file.sub(0, 6), to_u64(head.len())));
    };
    let format = b4 >> 5;
    let depth = (b4 & 15).saturating_add(8);
    let space = b5 >> 4;
    let animated = b5 & 1 != 0;
    let extension = b5 & 8 != 0;
    let pixel_format = lookup(BPG_FORMATS, format.into()).unwrap_or("reserved");
    cx.emit(
        byte_node("Pixel format, alpha, bit depth", file, b4, 4).summary(format!(
            "{pixel_format}{}, {depth}-bit",
            if b4 & 0x10 != 0 { ", alpha" } else { "" }
        )),
    );
    cx.emit(
        byte_node("Color space and flags", file, b5, 5).summary(format!(
            "{}{}{}{}",
            lookup(BPG_SPACES, space.into()).unwrap_or("reserved"),
            if extension { ", extensions" } else { "" },
            if b5 & 2 != 0 { ", limited range" } else { "" },
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
    if extension {
        let (node, ext_len) = varint_node("Extension data length", file, &head, &mut pos)?;
        cx.emit(node);
        cx.emit(region("Extension data", file, to_u64(pos), ext_len));
        pos = pos.saturating_add(usize::try_from(ext_len).unwrap_or(usize::MAX));
    }
    cx.annotate(format!(
        "{}, {pixel_format}, {depth}-bit{}",
        dims(width, height),
        if animated { ", animated" } else { "" }
    ));
    let start = to_u64(pos);
    let len = if data_len == 0 {
        file.len.saturating_sub(start)
    } else {
        data_len
    };
    cx.emit(region("HEVC picture data", file, start, len));
    Ok(())
}

pub async fn dissect_flif(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 0x1000)).await?;
    cx.emit(Node::new("Magic").span(file.sub(0, 4)).value(text("FLIF")));
    let (Some(&kind), Some(&bpc)) = (head.get(4), head.get(5)) else {
        return Err(Diagnostic::truncated(file.sub(0, 6), to_u64(head.len())));
    };
    let interlaced = matches!(kind >> 4, 4 | 6);
    let animated = matches!(kind >> 4, 5 | 6);
    let channels = kind & 15;
    cx.emit(
        Node::new("Format")
            .span(file.sub(4, 1))
            .value(text(char::from(kind).to_string()))
            .summary(format!(
                "{}{}, {channels} channels",
                if interlaced {
                    "interlaced"
                } else {
                    "non-interlaced"
                },
                if animated { ", animated" } else { "" }
            )),
    );
    cx.emit(
        Node::new("Bytes per channel")
            .span(file.sub(5, 1))
            .value(text(char::from(bpc).to_string())),
    );
    let mut pos = 6usize;
    let (node, w) = varint_node("Width - 1", file, &head, &mut pos)?;
    cx.emit(node);
    let (node, h) = varint_node("Height - 1", file, &head, &mut pos)?;
    cx.emit(node);
    if animated {
        let (node, _) = varint_node("Frames - 2", file, &head, &mut pos)?;
        cx.emit(node);
    }
    let (width, height) = (w.saturating_add(1), h.saturating_add(1));
    cx.annotate(format!(
        "{}, {channels} channels{}",
        dims(width, height),
        if animated { ", animated" } else { "" }
    ));
    // Metadata chunks: four-letter name, varint length, deflated content.
    // The image data starts with a byte below 32.
    for _ in 0..64 {
        let Some(&first) = head.get(pos) else {
            break;
        };
        if first < 32 {
            break;
        }
        let name = crate::text::latin1(head.get(pos..pos.saturating_add(4)).unwrap_or_default());
        let start = pos;
        pos = pos.saturating_add(4);
        let Some((len, n)) = varint(&head, pos) else {
            break;
        };
        pos = pos
            .saturating_add(n)
            .saturating_add(usize::try_from(len).unwrap_or(usize::MAX));
        cx.emit(
            Node::new(name)
                .span(file.sub(to_u64(start), to_u64(pos.saturating_sub(start))))
                .summary(format!("{len} bytes, deflate-compressed")),
        );
    }
    let start = to_u64(pos);
    cx.emit(region(
        "Image data",
        file,
        start,
        file.len.saturating_sub(start),
    ));
    Ok(())
}
