//! Wireless bitmap (WBMP, type 0): a type field, a fixed header byte, width
//! and height as multi-byte integers (7 bits per byte, high bit = more),
//! then 1-bit rows padded to bytes.
//!
//! There is no magic, so the probe requires the file size to match the
//! declared dimensions exactly.

use crate::bytes::to_u64;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::val::uint;
use crate::formats::{Format, Head, Input, Probe};
use crate::node::Node;

use super::{dims, region};

pub static FORMAT: Format = Format {
    name: "wbmp",
    title: "Wireless bitmap",
    extensions: &["wbmp", "wbm"],
    mime: "image/vnd.wap.wbmp",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Decodes a multi-byte integer at `pos`: `(value, length)`.
fn multibyte(data: &[u8], pos: usize) -> Option<(u64, usize)> {
    crate::bytes::vlq_be(data.get(pos..)?, 5)
}

/// `(width, height, header length)`.
fn header(data: &[u8]) -> Option<(u64, u64, usize)> {
    if data.first() != Some(&0) || data.get(1) != Some(&0) {
        return None;
    }
    let (w, a) = multibyte(data, 2)?;
    let (h, b) = multibyte(data, a.checked_add(2)?)?;
    Some((w, h, a.checked_add(b)?.checked_add(2)?))
}

fn raster_len(w: u64, h: u64) -> u64 {
    (w.saturating_add(7) / 8).saturating_mul(h)
}

fn probe(h: &Head<'_>) -> bool {
    header(h.data).is_some_and(|(w, height, len)| {
        w > 0 && height > 0 && to_u64(len).saturating_add(raster_len(w, height)) == h.len
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.read_avail(file.sub(0, 12)).await?;
    let Some((w, h, len)) = header(&head) else {
        return Err(Diagnostic::malformed("bad WBMP header").at(file.sub(0, 12)));
    };
    cx.emit(
        Node::new("Type")
            .span(file.sub(0, 1))
            .value(uint(0u8, 64))
            .desc("0 = monochrome, uncompressed"),
    );
    cx.emit(
        Node::new("Fixed header")
            .span(file.sub(1, 1))
            .value(uint(0u8, 64)),
    );
    let (_, wl) = multibyte(&head, 2).unwrap_or((0, 0));
    cx.emit(
        Node::new("Width")
            .span(file.sub(2, to_u64(wl)))
            .value(uint(w, 64)),
    );
    let hl = len.saturating_sub(2).saturating_sub(wl);
    cx.emit(
        Node::new("Height")
            .span(file.sub(to_u64(wl).saturating_add(2), to_u64(hl)))
            .value(uint(h, 64)),
    );
    cx.annotate(format!("{}, 1-bit", dims(w, h)));
    cx.emit(
        region("Raster", file, to_u64(len), raster_len(w, h)).summary(format!(
            "{h} rows of {} bytes, 1 = white",
            w.saturating_add(7) / 8
        )),
    );
    Ok(())
}
