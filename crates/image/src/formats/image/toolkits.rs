//! Images from graphics toolkits and editors: ImageMagick MIFF, Utah RLE and
//! Paint Shop Pro.

use crate::bytes::{to_u64, u16_le, u32_le};
use crate::cx::Cx;
use crate::declare_format;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::util::val::text;
use crate::formats::{Input, Probe};
use crate::node::Node;
use crate::span::Span;
use crate::value::{FlagTable, flag};

const LE: Endian = Endian::Little;

// ---------------------------------------------------------------------------
// Imagery: ImageMagick MIFF, Utah RLE, Paint Shop Pro

/// `KEY=VALUE` pairs separated by whitespace (quoted values may contain
/// spaces), with spans relative to `base`.
fn label_pairs(data: &[u8], base: Span) -> Vec<(String, String, Span)> {
    let mut out = Vec::new();
    let mut i = 0usize;
    let n = data.len();
    while i < n {
        while i < n && data.get(i).is_some_and(|b| b.is_ascii_whitespace()) {
            i = i.saturating_add(1);
        }
        let start = i;
        while i < n
            && data
                .get(i)
                .is_some_and(|&b| b != b'=' && !b.is_ascii_whitespace())
        {
            i = i.saturating_add(1);
        }
        if data.get(i) != Some(&b'=') {
            break;
        }
        let key = String::from_utf8_lossy(data.get(start..i).unwrap_or_default()).into_owned();
        i = i.saturating_add(1);
        let vstart = i;
        if data.get(i) == Some(&b'\'') {
            i = i.saturating_add(1);
            while i < n && data.get(i) != Some(&b'\'') {
                i = i.saturating_add(1);
            }
            i = i.saturating_add(1).min(n);
        } else {
            while i < n && data.get(i).is_some_and(|b| !b.is_ascii_whitespace()) {
                i = i.saturating_add(1);
            }
        }
        let value = String::from_utf8_lossy(data.get(vstart..i).unwrap_or_default())
            .trim_matches('\'')
            .to_owned();
        out.push((
            key,
            value,
            base.sub(to_u64(start), to_u64(i.saturating_sub(start))),
        ));
    }
    out
}

declare_format!(pub MIFF = "miff", "ImageMagick image (MIFF)", ["miff", "mif"], "image/x-miff",
    Probe::Magic(&[(0, b"id=ImageMagick")]), miff);

async fn miff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 1 << 16)).await?;
    let end = head
        .windows(2)
        .position(|w| w == b":\x1a")
        .unwrap_or(head.len());
    let header = head.get(..end).unwrap_or_default();
    // Strip {comments}.
    let pairs = label_pairs(header, file);
    for (k, v, span) in pairs.iter().take(256) {
        cx.emit(Node::new(k.clone()).span(*span).value(text(v.clone())));
    }
    cx.emit(Node::new("Pixels").span(file.tail(to_u64(end).saturating_add(2))));
    let get = |k: &str| {
        pairs
            .iter()
            .find(|(a, _, _)| a == k)
            .map_or("?", |(_, v, _)| v.as_str())
    };
    cx.annotate(format!(
        "MIFF {} image, {}, {}",
        get("class"),
        get("columns").to_owned() + "×" + get("rows"),
        get("colorspace")
    ));
    Ok(())
}

const RLE_FLAGS: FlagTable = &[
    flag(1, "clear first"),
    flag(2, "no background"),
    flag(4, "alpha"),
    flag(8, "comments"),
];

declare_format!(pub UTAH_RLE = "utah-rle", "Utah Raster Toolkit RLE", ["rle"], "image/x-utah-rle",
    Probe::Magic(&[(0, b"\x52\xcc")]), utah_rle);

async fn utah_rle(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 15)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.u16("Magic").hex().emit()?;
    f.u16("X position").emit()?;
    f.u16("Y position").emit()?;
    let w = f.u16("Width").emit()?;
    let h = f.u16("Height").emit()?;
    f.u8("Flags").flags(RLE_FLAGS).emit()?;
    let channels = f.u8("Colour channels").emit()?;
    let bits = f.u8("Bits per pixel").emit()?;
    f.u8("Colour map channels").emit()?;
    f.u8("Colour map length (log2)").emit()?;
    cx.emit(Node::new("Scanline data").span(file.tail(15)));
    cx.annotate(format!(
        "Utah RLE, {w}×{h}, {channels} channel(s) × {bits} bits"
    ));
    Ok(())
}

declare_format!(pub PSP = "psp-image", "Paint Shop Pro image", ["pspimage", "psp", "tub", "pspframe"], "image/x-psp",
    Probe::Magic(&[(0, b"Paint Shop Pro Image File\n\x1a")]), psp);

const PSP_BLOCKS: &[(u64, &str)] = &[
    (0, "Image attributes"),
    (1, "Creator"),
    (2, "Colour palette"),
    (3, "Layer bank"),
    (4, "Channel"),
    (5, "Selection"),
    (6, "Alpha bank"),
    (7, "Alpha channel"),
    (8, "Composite image"),
    (9, "Extended data"),
    (10, "Picture tube"),
    (11, "Adjustment layer"),
    (12, "Vector layer"),
    (13, "Shape"),
    (14, "Paint style"),
    (15, "Composite image bank"),
    (16, "Composite attributes"),
    (17, "JPEG"),
    (18, "Line style"),
    (19, "Table bank"),
    (20, "Table"),
    (21, "Paper"),
    (22, "Pattern"),
    (23, "Gradient"),
    (26, "Group extension"),
    (27, "Mask extension"),
    (28, "Brush"),
    (29, "Art media"),
];

async fn psp(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 36)).await?;
    let mut f = Fields::emitting(&cx, &head, LE);
    f.bytes("Signature", 32).emit()?;
    let major = f.u16("Major version").emit()?;
    let minor = f.u16("Minor version").emit()?;
    // Blocks: "~BK\0", id, (initial length before v4), total length.
    let block_head: u64 = if major < 4 { 14 } else { 10 };
    let mut pos = 36u64;
    let mut n = 0u32;
    while pos.saturating_add(block_head) <= file.len {
        let h = cx.read(file.sub(pos, block_head)).await?;
        if h.get(..4) != Some(b"~BK\0") {
            return Err(Diagnostic::malformed("missing ~BK block marker").at(file.sub(pos, 4)));
        }
        let id = u64::from(u16_le(&h, 4).unwrap_or(0));
        let len = u64::from(u32_le(&h, if major < 4 { 10 } else { 6 }).unwrap_or(0));
        let name = PSP_BLOCKS
            .iter()
            .find(|(k, _)| *k == id)
            .map_or("Unknown block", |(_, v)| v);
        let mut node = Node::new(name)
            .span(file.sub(pos, len.saturating_add(block_head)))
            .summary(format!("{len} bytes"));
        if id == 0 {
            let a = cx
                .read_avail(file.sub(pos.saturating_add(block_head), 16))
                .await?;
            let (w, hgt) = if major < 4 {
                (u32_le(&a, 0), u32_le(&a, 4))
            } else {
                (u32_le(&a, 4), u32_le(&a, 8))
            };
            node = node.summary(format!("{}×{}", w.unwrap_or(0), hgt.unwrap_or(0)));
        }
        cx.push(node).await;
        n = n.saturating_add(1);
        pos = pos.saturating_add(block_head).saturating_add(len);
    }
    cx.annotate(format!("Paint Shop Pro image v{major}.{minor}, {n} blocks"));
    Ok(())
}
