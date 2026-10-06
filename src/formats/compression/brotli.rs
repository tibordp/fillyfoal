//! Brotli (`.br`, RFC 7932) streams.
//!
//! Brotli has no magic number or header beyond the window size in the
//! first bits, so a file is recognised only when the probe window holds all
//! of it and it decodes as exactly one complete stream; larger files are
//! left to their `.br` extension. The content is decoded on expansion.

use crate::cx::Cx;
use crate::error::Result;
use crate::formats::util::arcutil::human_size;
use crate::formats::{Codec, Format, Head, Input, Probe, content};
use crate::node::Node;

pub static FORMAT: Format = Format {
    name: "brotli",
    title: "Brotli compressed data",
    extensions: &["br"],
    mime: "application/x-brotli",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

/// Output a probe may decode before giving up.
const PROBE_LIMIT: usize = 1 << 22;

fn probe(h: &Head<'_>) -> bool {
    h.len >= 4
        && u64::try_from(h.data.len()).is_ok_and(|n| n == h.len)
        && crate::codec::brotli::is_complete_stream(h.data, PROBE_LIMIT)
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let first = cx.read(file.sub(0, 2)).await?;
    cx.emit(content("Decompressed", input, file, Codec::Brotli, None));
    cx.emit(Node::new("Compressed data").span(file));
    let window = crate::codec::brotli::window_bits_of(&first)
        .map(|w| format!(", {} window", human_size((1u64 << w).saturating_sub(16))))
        .unwrap_or_default();
    cx.annotate(format!("Brotli{window}, {} compressed", human_size(file.len)));
    Ok(())
}
