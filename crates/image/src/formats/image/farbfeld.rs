//! farbfeld: magic, 32-bit big-endian width and height, then 16-bit RGBA
//! pixels.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::{Format, Input, Probe};
use crate::record;

use super::{dims, region};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "farbfeld",
    title: "farbfeld image",
    extensions: &["ff"],
    mime: "image/x-farbfeld",
    probe: Probe::Magic(&[(0, b"farbfeld")]),
    dissect: crate::expander!(dissect: Input),
};

record! {
    pub struct Header {
        magic: ascii[8] "Magic",
        width: u32 "Width",
        height: u32 "Height",
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    cx.annotate(format!("{}, 16-bit RGBA", dims(h.width, h.height)));
    let len = u64::from(h.width)
        .saturating_mul(h.height.into())
        .saturating_mul(8);
    cx.emit(
        region("Pixels", file, Header::SIZE, len)
            .summary(format!("{} rows of {} pixels", h.height, h.width)),
    );
    Ok(())
}
