//! Windows Recycle Bin metadata files (`$I......`, Vista and later).
//!
//! Each deleted file has a `$R` file (the content) and a small `$I` file with
//! its original size, deletion time and path. Version 1 (Vista to 8) stores
//! the path in a fixed 520-byte field; version 2 (10 and later) stores its
//! length first.

use crate::bytes::{u32_le, u64_le};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields};
use crate::formats::datakit::size;
use crate::formats::{Format, Head, Input, Probe};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "recycle-bin-info",
    title: "Windows Recycle Bin $I file",
    extensions: &[],
    mime: "application/octet-stream",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// The version, and a length that matches it exactly.
fn probe(h: &Head<'_>) -> bool {
    let plausible_time = u64_le(h.data, 16).is_some_and(|t| (0x01b0_0000_0000_0000..0x0300_0000_0000_0000).contains(&t));
    match u64_le(h.data, 0) {
        Some(1) => h.len == 544 && plausible_time,
        Some(2) => {
            let chars = u32_le(h.data, 24).map_or(0, u64::from);
            chars > 0 && h.len == 28u64.saturating_add(chars.saturating_mul(2)) && plausible_time
        }
        _ => false,
    }
}

fn layout(f: &mut Fields<'_>, _: &()) -> Result<(u64, String)> {
    let version = f.u64("Version").emit()?;
    let original = f
        .u64("Original size")
        .with(|&s, n| n.summary(size(s)))
        .emit()?;
    f.u64("Deletion time").filetime().emit()?;
    let path = if version >= 2 {
        let chars = f.u32("Path length").desc("Characters, including the terminator").emit()?;
        f.utf16("Original path", chars.into()).emit()?
    } else {
        f.utf16("Original path", 260).emit()?
    };
    Ok((original, path))
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let block = cx.block(input.span).await?;
    let (original, path) = layout(&mut Fields::emitting(&cx, &block, LE), &())?;
    cx.annotate(format!("deleted file {path:?}, {}", size(original)));
    Ok(())
}
