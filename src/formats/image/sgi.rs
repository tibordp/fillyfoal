//! SGI image (RGB/BW/RGBA/INT): a 512-byte big-endian header, then either
//! verbatim planar scanlines or RLE scanlines located through offset and
//! length tables.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::{Format, Head, Input, Probe};
use crate::record;
use crate::value::EnumTable;

use super::{dims, region};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "sgi",
    title: "SGI image",
    extensions: &["sgi", "rgb", "rgba", "bw", "int", "inta"],
    mime: "image/x-sgi",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    let d = h.data;
    h.starts_with(b"\x01\xda")
        && d.get(2).is_some_and(|&s| s <= 1)
        && d.get(3).is_some_and(|&b| b == 1 || b == 2)
        && crate::bytes::u16_be(d, 4).is_some_and(|dim| (1..=3).contains(&dim))
}

const STORAGE: EnumTable = &[(0, "Verbatim"), (1, "RLE")];
const COLORMAP: EnumTable = &[
    (0, "Normal"),
    (1, "Dithered (obsolete)"),
    (2, "Screen (obsolete)"),
    (3, "Colormap (obsolete)"),
];

record! {
    pub struct Header {
        magic: u16 "Magic" .hex(),
        storage: u8 "Storage" .enumeration(STORAGE),
        bpc: u8 "Bytes per channel",
        dimension: u16 "Dimension" .desc("1: one scanline, 2: one channel, 3: several channels"),
        xsize: u16 "Width",
        ysize: u16 "Height",
        zsize: u16 "Channels",
        pixmin: i32 "Minimum pixel value",
        pixmax: i32 "Maximum pixel value",
        dummy: bytes[4] "Reserved",
        name: ascii[80] "Image name",
        colormap: u32 "Colormap" .enumeration(COLORMAP),
        dummy2: bytes[404] "Reserved",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let channels = match h.zsize {
        1 => "grayscale".to_owned(),
        3 => "RGB".to_owned(),
        4 => "RGBA".to_owned(),
        n => format!("{n} channels"),
    };
    let storage = if h.storage == 1 { "RLE" } else { "verbatim" };
    let mut summary = format!(
        "{}, {channels}, {}-bit, {storage}",
        dims(h.xsize, h.ysize),
        u16::from(h.bpc).saturating_mul(8)
    );
    if !h.name.is_empty() {
        summary = format!("{summary}, {:?}", h.name);
    }
    cx.annotate(summary);
    let rows = u64::from(h.ysize).saturating_mul(h.zsize.max(1).into());
    if h.storage == 1 {
        let table = rows.saturating_mul(4);
        cx.emit(region("Scanline offsets", file, Header::SIZE, table).summary(format!("{rows} entries")));
        cx.emit(
            region("Scanline lengths", file, Header::SIZE.saturating_add(table), table)
                .summary(format!("{rows} entries")),
        );
        let start = Header::SIZE.saturating_add(table.saturating_mul(2));
        cx.emit(region("RLE data", file, start, file.len.saturating_sub(start)));
    } else {
        let len = rows
            .saturating_mul(h.xsize.into())
            .saturating_mul(h.bpc.into());
        cx.emit(
            region("Pixel data", file, Header::SIZE, len)
                .summary(format!("{rows} planar scanlines, bottom row first")),
        );
    }
    Ok(())
}
