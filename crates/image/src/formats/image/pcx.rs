//! ZSoft PC Paintbrush (PCX): a 128-byte header with a 16-color palette,
//! RLE-encoded scanlines, and for 256-color images a palette at the end
//! (`0C` followed by 768 bytes).

use crate::bytes::{to_u64, u16_le};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::{Format, Head, Input, Probe, embedded};
use crate::record;
use crate::value::EnumTable;

use super::{ColorOrder, dims, palette, region};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "pcx",
    title: "PC Paintbrush image",
    extensions: &["pcx", "pcc", "dcx"],
    mime: "image/vnd.zbrush.pcx",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// One magic byte is not enough: check every header field that has a small
/// set of valid values.
fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    let byte = |i: usize| d.get(i).copied();
    let word = |i: usize| u16_le(d, i);
    let (Some(xmin), Some(ymin), Some(xmax), Some(ymax), Some(bpl)) =
        (word(4), word(6), word(8), word(10), word(66))
    else {
        return false;
    };
    let planes = byte(65).unwrap_or(0);
    h.len > 128
        && byte(0) == Some(0x0a)
        && matches!(byte(1), Some(0 | 2 | 3 | 4 | 5))
        && matches!(byte(2), Some(0 | 1))
        && matches!(byte(3), Some(1 | 2 | 4 | 8))
        && xmax >= xmin
        && ymax >= ymin
        && (1..=4).contains(&planes)
        && bpl > 0
        && byte(64) == Some(0)
}

const VERSIONS: EnumTable = &[
    (0, "PC Paintbrush 2.5"),
    (2, "2.8 with palette"),
    (3, "2.8 without palette"),
    (4, "PC Paintbrush for Windows"),
    (5, "3.0 and later"),
];

const PALETTE_INFO: EnumTable = &[(1, "Color or black and white"), (2, "Grayscale")];

record! {
    pub struct Header {
        manufacturer: u8 "Manufacturer" .hex() .desc("Always 0x0a"),
        version: u8 "Version" .enumeration(VERSIONS),
        encoding: u8 "Encoding" .desc("1 = run-length encoding"),
        bits: u8 "Bits per pixel per plane",
        xmin: u16 "X min",
        ymin: u16 "Y min",
        xmax: u16 "X max",
        ymax: u16 "Y max",
        hdpi: u16 "Horizontal DPI",
        vdpi: u16 "Vertical DPI",
        colormap: bytes[48] "EGA palette",
        reserved: u8 "Reserved",
        planes: u8 "Color planes",
        bytes_per_line: u16 "Bytes per line" .desc("Per plane; always even"),
        palette_info: u16 "Palette info" .enumeration(PALETTE_INFO),
        hscreen: u16 "Horizontal screen size",
        vscreen: u16 "Vertical screen size",
        filler: bytes[54] "Filler",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, LE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, LE));
    let width = u32::from(h.xmax.saturating_sub(h.xmin)).saturating_add(1);
    let height = u32::from(h.ymax.saturating_sub(h.ymin)).saturating_add(1);
    let depth = u16::from(h.bits).saturating_mul(h.planes.into());
    cx.annotate(format!(
        "{}, {depth}-bit, {} planes",
        dims(width, height),
        h.planes
    ));
    if depth <= 4 {
        cx.emit(palette(
            "Header palette",
            header_span.sub(16, 48),
            ColorOrder::Rgb,
        ));
    }
    // A 256-color palette sits at the end, introduced by 0x0c.
    let mut end = file.len;
    if h.bits == 8 && h.planes == 1 && file.len >= Header::SIZE.saturating_add(769) {
        let at = file.len.saturating_sub(769);
        if cx.read(file.sub(at, 1)).await? == [0x0c] {
            end = at;
        }
    }
    cx.emit(
        region(
            "Image data",
            file,
            Header::SIZE,
            end.saturating_sub(Header::SIZE),
        )
        .summary(format!(
            "{height} scanlines × {} planes × {} bytes{}",
            h.planes,
            h.bytes_per_line,
            if h.encoding == 1 { ", RLE" } else { "" }
        )),
    );
    if end < file.len {
        cx.emit(region("Palette marker", file, end, 1));
        cx.emit(palette(
            "Palette",
            file.tail(end.saturating_add(1)),
            ColorOrder::Rgb,
        ));
    }
    Ok(())
}

/// Multi-page PCX (DCX): a magic number and up to 1023 page offsets
/// (terminated by zero), each pointing at a complete PCX image.
pub static DCX: Format = Format {
    name: "dcx",
    title: "Multi-page PCX",
    extensions: &["dcx"],
    mime: "image/x-dcx",
    probe: Probe::Magic(&[(0, b"\xb1\x68\xde\x3a")]),
    dissect: crate::expander!(dissect_dcx: Input),
};

pub async fn dissect_dcx(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    cx.emit(region("Magic", file, 0, 4));
    let table = cx.read_avail(file.sub(4, 1023 * 4)).await?;
    let offsets: Vec<u64> = table
        .as_chunks::<4>()
        .0
        .iter()
        .map(|b| u64::from(u32::from_le_bytes(*b)))
        .take_while(|&o| o != 0)
        .collect();
    let table_len = to_u64(offsets.len()).saturating_add(1).saturating_mul(4);
    cx.emit(region("Page table", file, 4, table_len).summary(format!("{} pages", offsets.len())));
    cx.annotate(format!("{} pages", offsets.len()));
    for (i, &offset) in offsets.iter().enumerate() {
        let end = offsets
            .get(i.saturating_add(1))
            .copied()
            .unwrap_or(file.len);
        let page = file.sub(offset, end.saturating_sub(offset));
        cx.push(embedded(format!("Page {i}"), input.nested(page)))
            .await;
    }
    Ok(())
}
