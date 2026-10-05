//! JPEG XL: bare codestreams (`FF 0A`) and the ISO BMFF-style container
//! (`JXL ` signature box, then `ftyp`, `jxll`, `jxlc` or `jxlp`, `Exif`,
//! `xml `, `jbrd`, `brob` ... boxes).
//!
//! Of the codestream only the size header is decoded (it is bit-packed,
//! least significant bit first); the rest is shown as one region.

use crate::bytes::{to_u64, u32_be, u64_be};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::{Format, Input, Probe, embedded, embedded_as};
use crate::node::Node;
use crate::span::Span;

use super::{dims, region, text, uint};

const BE: Endian = Endian::Big;
const SIGNATURE: &[u8] = b"\0\0\0\x0cJXL \r\n\x87\n";

pub static FORMAT: Format = Format {
    name: "jxl",
    title: "JPEG XL image",
    extensions: &["jxl"],
    mime: "image/jxl",
    probe: Probe::Magic(&[(0, b"\xff\x0a"), (0, SIGNATURE)]),
    dissect: crate::expander!(dissect: Input),
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let head = cx.read_avail(input.span.sub(0, 12)).await?;
    if head.starts_with(b"\xff\x0a") {
        codestream(&cx, input.span).await
    } else {
        container(&cx, input).await
    }
}

/// Reads bits least significant first.
struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl Bits<'_> {
    fn read(&mut self, n: u32) -> Option<u64> {
        let mut value = 0u64;
        for i in 0..n {
            let byte = *self.data.get(self.pos / 8)?;
            let bit = (byte >> (self.pos % 8)) & 1;
            value |= u64::from(bit).checked_shl(i)?;
            self.pos = self.pos.checked_add(1)?;
        }
        Some(value)
    }

    /// `U32(1 + u(9), 1 + u(13), 1 + u(18), 1 + u(30))`, as used for sizes.
    fn size(&mut self) -> Option<u64> {
        let bits = [9, 13, 18, 30];
        let selector = usize::try_from(self.read(2)?).ok()?;
        self.read(*bits.get(selector)?)?.checked_add(1)
    }
}

/// Width and height from the codestream's SizeHeader, and its length in
/// bytes (rounded up).
fn size_header(data: &[u8]) -> Option<(u64, u64, u64)> {
    let mut b = Bits { data, pos: 16 };
    let small = b.read(1)? == 1;
    let height = if small {
        b.read(5)?.checked_add(1)?.checked_mul(8)?
    } else {
        b.size()?
    };
    let ratio = b.read(3)?;
    let width = match ratio {
        0 if small => b.read(5)?.checked_add(1)?.checked_mul(8)?,
        0 => b.size()?,
        1 => height,
        2 => height.checked_mul(12)? / 10,
        3 => height.checked_mul(4)? / 3,
        4 => height.checked_mul(3)? / 2,
        5 => height.checked_mul(16)? / 9,
        6 => height.checked_mul(5)? / 4,
        _ => height.checked_mul(2)?,
    };
    Some((width, height, to_u64(b.pos.div_ceil(8))))
}

async fn codestream(cx: &Cx, span: Span) -> Result<()> {
    let head = cx.read_avail(span.sub(0, 16)).await?;
    cx.emit(Node::new("Signature").span(span.sub(0, 2)).summary("FF 0A"));
    let Some((w, h, len)) = size_header(&head) else {
        return Err(Diagnostic::truncated(span.sub(0, 16), to_u64(head.len())));
    };
    cx.annotate(format!("{}, codestream", dims(w, h)));
    cx.emit(
        Node::new("Size header")
            .span(span.sub(2, len.saturating_sub(2)))
            .summary(dims(w, h))
            .lazy(size_fields, (span.sub(2, len.saturating_sub(2)), w, h)),
    );
    cx.emit(region("Image metadata, frames", span, len, span.len.saturating_sub(len)));
    Ok(())
}

/// The size header is bit-packed, so both fields share its span.
async fn size_fields(cx: Cx, (span, w, h): (Span, u64, u64)) -> Result<()> {
    cx.emit(Node::new("Width").span(span).value(uint(w)));
    cx.emit(Node::new("Height").span(span).value(uint(h)));
    Ok(())
}

/// Boxes per listing before giving up on a bogus file.
const MAX_BOXES: usize = 4096;

async fn container(cx: &Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut pos = 0u64;
    let mut dims_found = false;
    for _ in 0..MAX_BOXES {
        if pos >= file.len {
            break;
        }
        let head = cx.read(file.sub(pos, 8)).await?;
        let size = u64::from(u32_be(&head, 0).unwrap_or(0));
        let kind = head.get(4..8).unwrap_or_default().to_vec();
        let (header_len, len) = match size {
            0 => (8, file.len.saturating_sub(pos)),
            1 => {
                let large = cx.read(file.sub(pos.saturating_add(8), 8)).await?;
                (16, u64_be(&large, 0).unwrap_or(0))
            }
            n => (8, n),
        };
        if len < header_len {
            return Err(Diagnostic::malformed(format!("box size {len} too small")).at(file.sub(pos, 8)));
        }
        let span = file.sub(pos, len);
        let name = crate::text::latin1(&kind);
        let payload = span.tail(header_len);
        let mut node = Node::new(name.clone()).span(span);
        if !dims_found && (kind == b"jxlc" || kind == b"jxlp") {
            let offset = if kind == b"jxlp" { 4 } else { 0 };
            let head = cx.read_avail(payload.sub(offset, 16)).await?;
            if let Some((w, h, _)) = head.starts_with(b"\xff\x0a").then(|| size_header(&head)).flatten() {
                dims_found = true;
                cx.annotate(format!("{}, container", dims(w, h)));
                node = node.summary(dims(w, h));
            }
        }
        cx.push(node.lazy(jxl_box, (input, span, header_len, kind))).await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

async fn jxl_box(cx: Cx, (input, span, header_len, kind): (Input, Span, u64, Vec<u8>)) -> Result<()> {
    let block = cx.block(span.sub(0, header_len)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Size").desc("0: to the end of the file; 1: 64-bit size follows").emit()?;
    f.ascii("Type", 4).emit()?;
    if header_len == 16 {
        f.u64("Large size").emit()?;
    }
    let payload = span.tail(header_len);
    match kind.as_slice() {
        b"JXL " => cx.emit(Node::new("Signature").span(payload)),
        b"ftyp" => {
            let block = cx.block(payload).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.ascii("Major brand", 4).emit()?;
            f.u32("Minor version").emit()?;
            while f.remaining() >= 4 {
                f.ascii("Compatible brand", 4).emit()?;
            }
        }
        b"jxll" => {
            let block = cx.block(payload.sub(0, 1)).await?;
            Fields::emitting(&cx, &block, BE)
                .u8("Level")
                .desc("5 or 10")
                .emit()?;
        }
        b"jxlc" => cx.emit(embedded("Codestream", input.nested(payload))),
        b"jxlp" => {
            let block = cx.block(payload.sub(0, 4)).await?;
            let index = Fields::emitting(&cx, &block, BE)
                .u32("Index")
                .with(|&i, n| if i & 0x8000_0000 != 0 { n.summary("last part") } else { n })
                .emit()?;
            let part = payload.tail(4);
            if index & 0x7fff_ffff == 0 {
                cx.emit(embedded("Codestream (first part)", input.nested(part)));
            } else {
                cx.emit(Node::new("Partial codestream").span(part));
            }
        }
        b"Exif" => {
            let block = cx.block(payload.sub(0, 4)).await?;
            let offset = Fields::emitting(&cx, &block, BE)
                .u32("TIFF header offset")
                .emit()?;
            let tiff = payload.tail(4u64.saturating_add(offset.into()));
            cx.emit(embedded_as("Exif", input.nested(tiff), &super::tiff::FORMAT));
        }
        b"xml " => cx.emit(embedded("XMP", input.nested(payload))),
        b"brob" => {
            let inner = cx.read_avail(payload.sub(0, 4)).await?;
            cx.emit(
                Node::new("Brotli-compressed box")
                    .span(payload.tail(4))
                    .value(text(crate::text::latin1(&inner)))
                    .diag(Diagnostic::unsupported("Brotli compression")),
            );
        }
        b"jbrd" => cx.emit(Node::new("JPEG reconstruction data").span(payload)),
        _ => cx.emit(Node::new("Data").span(payload)),
    }
    Ok(())
}
