//! Sun/NeXT audio (`.snd`, `.au`): a big-endian header (data offset, size,
//! encoding, rate, channels), an annotation, then the samples. DEC's
//! little-endian variant (`.sd\0`, magic `dns.`) is handled too.

use crate::cx::Cx;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::sound::{channels, duration_of, leaf, peek_text, text};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "au",
    title: "Sun/NeXT audio",
    extensions: &["au", "snd"],
    mime: "audio/basic",
    probe: Probe::Magic(&[(0, b".snd"), (0, b"dns.")]),
    dissect: crate::expander!(dissect: Input),
};

const ENCODING: EnumTable = &[
    (1, "8-bit µ-law"),
    (2, "8-bit linear PCM"),
    (3, "16-bit linear PCM"),
    (4, "24-bit linear PCM"),
    (5, "32-bit linear PCM"),
    (6, "32-bit IEEE float"),
    (7, "64-bit IEEE float"),
    (8, "fragmented sample data"),
    (10, "DSP program"),
    (11, "8-bit fixed point"),
    (12, "16-bit fixed point"),
    (13, "24-bit fixed point"),
    (14, "32-bit fixed point"),
    (18, "16-bit linear with emphasis"),
    (19, "16-bit linear compressed"),
    (20, "16-bit linear with emphasis and compression"),
    (21, "Music Kit DSP commands"),
    (23, "G.721 4-bit ADPCM"),
    (24, "G.722 ADPCM"),
    (25, "G.723 3-bit ADPCM"),
    (26, "G.723 5-bit ADPCM"),
    (27, "8-bit A-law"),
];

fn bits(encoding: u32) -> u64 {
    match encoding {
        1 | 2 | 11 | 27 => 8,
        3 | 12 | 18..=20 => 16,
        4 | 13 => 24,
        5 | 6 | 14 => 32,
        7 => 64,
        23 => 4,
        25 => 3,
        26 => 5,
        _ => 0,
    }
}

#[derive(Clone, Copy, Debug)]
struct Header {
    offset: u32,
    size: u32,
    encoding: u32,
    rate: u32,
    channels: u32,
}

fn header(f: &mut Fields<'_>, _: &()) -> Result<Header> {
    f.ascii("Magic", 4).emit()?;
    Ok(Header {
        offset: f.u32("Data offset").hex().emit()?,
        size: f
            .u32("Data size")
            .desc("0xffffffff = unknown")
            .emit()?,
        encoding: f.u32("Encoding").enumeration(ENCODING).emit()?,
        rate: f.u32("Sample rate").emit()?,
        channels: f.u32("Channels").emit()?,
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let magic = cx.read(file.sub(0, 4)).await?;
    let endian = if magic == b"dns." {
        Endian::Little
    } else {
        Endian::Big
    };
    let span = file.sub(0, 24);
    let h = parse(&cx, span, endian, &(), header).await?;
    cx.emit(struct_node("Header", span, endian, (), header));
    let offset = u64::from(h.offset).max(24);
    let note = file.sub(24, offset.saturating_sub(24));
    if !note.is_empty() {
        let t = peek_text(&cx, note, note.len.min(4096)).await?;
        cx.emit(leaf("Annotation", note, text(t)));
    }
    let size = if h.size == u32::MAX {
        file.len.saturating_sub(offset)
    } else {
        u64::from(h.size)
    };
    let data = file.sub(offset, size);
    let encoding =
        crate::value::lookup(ENCODING, h.encoding.into()).map_or_else(|| format!("encoding {}", h.encoding), str::to_owned);
    let mut line = format!("{encoding}, {} Hz, {}", h.rate, channels(h.channels));
    let frame_bits = bits(h.encoding).saturating_mul(h.channels.into());
    let frames = data.len.saturating_mul(8).checked_div(frame_bits).unwrap_or(0);
    let mut node = Node::new("Samples").span(data);
    if let Some(d) = duration_of(frames, h.rate.into()) {
        line.push_str(&format!(", {d}"));
        node = node.summary(d);
    }
    cx.annotate(line);
    cx.emit(node);
    let end = offset.saturating_add(size);
    if end < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(end)));
    }
    Ok(())
}
