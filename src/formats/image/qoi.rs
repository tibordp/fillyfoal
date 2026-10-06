//! The Quite OK Image format (QOI).
//!
//! A 14-byte header, a stream of byte-aligned chunks, and an 8-byte end
//! marker (seven zeros and a one).

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, parse};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, lookup};

use super::dims;

const BE: Endian = Endian::Big;
const END: &[u8] = b"\0\0\0\0\0\0\0\x01";

pub static FORMAT: Format = Format {
    name: "qoi",
    title: "Quite OK Image",
    extensions: &["qoi"],
    mime: "image/qoi",
    probe: Probe::Magic(&[(0, b"qoif")]),
    dissect: crate::expander!(dissect: Input),
};

const CHANNELS: EnumTable = &[(3, "RGB"), (4, "RGBA")];
const COLORSPACE: EnumTable = &[(0, "sRGB with linear alpha"), (1, "all channels linear")];

record! {
    pub struct Header {
        magic: ascii[4] "Magic",
        width: u32 "Width",
        height: u32 "Height",
        channels: u8 "Channels" .enumeration(CHANNELS),
        colorspace: u8 "Colorspace" .enumeration(COLORSPACE),
    }
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let header_span = file.sub(0, Header::SIZE);
    let h = parse(&cx, header_span, BE, &(), Header::layout).await?;
    cx.emit(Header::node("Header", header_span, BE));
    let channels = lookup(CHANNELS, h.channels.into()).unwrap_or("?");
    let space = if h.colorspace == 0 { "sRGB" } else { "linear" };
    cx.annotate(format!("{}, {channels}, {space}", dims(h.width, h.height)));
    let body = file.tail(Header::SIZE);
    let end_span = body.tail(body.len.saturating_sub(8));
    let end = cx.read_avail(end_span).await?;
    cx.emit(
        Node::new("Chunks")
            .span(body.sub(0, body.len.saturating_sub(end_span.len)))
            .desc("QOI_OP_RGB, RGBA, INDEX, DIFF, LUMA and RUN operations"),
    );
    let mut node = Node::new("End marker").span(end_span);
    if end != END {
        node = node.diag(Diagnostic::warning("missing end marker (00 × 7, 01)"));
    }
    cx.emit(node);
    Ok(())
}
