//! Direct Stream Digital files: Sony DSF (little-endian `DSD `, `fmt `,
//! `data` chunks with 64-bit sizes and an ID3v2 tag at the end) and
//! Philips DSDIFF (big-endian `FRM8` with nested property chunks).

use crate::bytes::{u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse};
use crate::formats::sound::{channels, duration_of, fourcc, leaf, text};
use crate::formats::{Format, Input, Probe, embedded, id3};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::EnumTable;

pub static DSF: Format = Format {
    name: "dsf",
    title: "DSD Stream File",
    extensions: &["dsf"],
    mime: "audio/x-dsf",
    probe: Probe::Custom(|h| h.starts_with(b"DSD \x1c\0\0\0\0\0\0\0")),
    dissect: crate::expander!(dsf: Input),
};

pub static DFF: Format = Format {
    name: "dff",
    title: "DSD Interchange File Format",
    extensions: &["dff"],
    mime: "audio/x-dff",
    probe: Probe::Custom(|h| h.starts_with(b"FRM8") && h.at(12, b"DSD ")),
    dissect: crate::expander!(dff: Input),
};

const CHANNEL_TYPE: EnumTable = &[
    (1, "mono"),
    (2, "stereo"),
    (3, "3 channels"),
    (4, "quad"),
    (5, "4 channels"),
    (6, "5 channels"),
    (7, "5.1"),
];

/// "DSD64 (2.8224 MHz)".
fn dsd_rate(rate: u64) -> String {
    let multiple = rate / 44100;
    format!("DSD{multiple} ({:.4} MHz)", rate as f64 / 1e6)
}

record! {
    pub struct DsfHeader {
        id: ascii[4] "Chunk ID",
        size: u64 "Chunk size",
        file_size: u64 "File size",
        metadata: u64 "Metadata offset" .hex() .desc("Offset of the ID3v2 tag; 0 if none"),
    }
}

record! {
    pub struct DsfFormat {
        id: ascii[4] "Chunk ID",
        size: u64 "Chunk size",
        version: u32 "Format version",
        format: u32 "Format ID" .enumeration(&[(0, "DSD raw")]),
        channel_type: u32 "Channel type" .enumeration(CHANNEL_TYPE),
        channels: u32 "Channels",
        rate: u32 "Sampling frequency" .with(|&r, n| n.summary(dsd_rate(r.into()))),
        bits: u32 "Bits per sample" .desc("1 = LSB first, 8 = MSB first"),
        samples: u64 "Sample count" .desc("Per channel"),
        block_size: u32 "Block size per channel",
        _reserved: u32 "Reserved",
    }
}

pub async fn dsf(cx: Cx, input: Input) -> Result<()> {
    const LE: Endian = Endian::Little;
    let file = input.span;
    let hspan = file.sub(0, DsfHeader::SIZE);
    let h = parse(&cx, hspan, LE, &(), DsfHeader::layout).await?;
    cx.emit(DsfHeader::node("DSD chunk", hspan, LE));
    let fspan = file.sub(h.size, DsfFormat::SIZE);
    let fmt = parse(&cx, fspan, LE, &(), DsfFormat::layout).await?;
    cx.emit(DsfFormat::node("fmt chunk", file.sub(h.size, fmt.size), LE));
    let data_at = h.size.saturating_add(fmt.size);
    let head = cx.read_avail(file.sub(data_at, 12)).await?;
    let data_size = crate::bytes::u64_le(&head, 4).unwrap_or(0);
    let data = file.sub(data_at, data_size);
    cx.emit(
        Node::new("data chunk")
            .span(data)
            .summary(format!("{} bytes", data_size.saturating_sub(12)))
            .lazy(dsf_data, data),
    );
    if h.metadata > 0 {
        let tag = file.tail(h.metadata);
        cx.emit(id3::tag_node(&cx, input, tag).await);
    }
    let mut line = format!(
        "DSF, {}, {}",
        dsd_rate(fmt.rate.into()),
        channels(fmt.channels)
    );
    if let Some(d) = duration_of(fmt.samples, fmt.rate.into()) {
        line.push_str(&format!(", {d}"));
    }
    cx.annotate(line);
    Ok(())
}

async fn dsf_data(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &block, Endian::Little);
    f.ascii("Chunk ID", 4).emit()?;
    f.u64("Chunk size").emit()?;
    cx.emit(
        Node::new("Samples")
            .span(span.tail(12))
            .desc("Interleaved per-channel blocks"),
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// DSDIFF

/// Chunks that hold further chunks after a 4-byte type, or directly.
fn dff_container(id: &[u8]) -> Option<u64> {
    match id {
        b"FRM8" | b"PROP" => Some(4),
        b"DIIN" | b"DST " => Some(0),
        _ => None,
    }
}

fn dff_describe(id: &[u8]) -> Option<&'static str> {
    Some(match id {
        b"FVER" => "Format version",
        b"PROP" => "Properties",
        b"FS  " => "Sample rate",
        b"CHNL" => "Channels",
        b"CMPR" => "Compression type",
        b"ABSS" => "Absolute start time",
        b"LSCO" => "Loudspeaker configuration",
        b"DSD " => "Uncompressed DSD sound data",
        b"DST " => "DST-compressed sound data",
        b"DSTI" => "DST frame index",
        b"COMT" => "Comments",
        b"DIIN" => "Edited master information",
        b"EMID" => "Edited master ID",
        b"MARK" => "Marker",
        b"DIAR" => "Artist",
        b"DITI" => "Title",
        b"MANF" => "Manufacturer-specific",
        b"ID3 " => "ID3 tag",
        _ => return None,
    })
}

pub async fn dff(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let mut info = DffInfo::default();
    collect(&cx, file.sub(16, file.len.saturating_sub(16)), &mut info, 0).await?;
    let mut line = format!(
        "DSDIFF, {}, {}, {}",
        info.compression.as_deref().unwrap_or("DSD"),
        dsd_rate(info.rate),
        channels(info.channels)
    );
    if let Some(d) = info
        .dsd_bytes
        .checked_mul(8)
        .and_then(|bits| bits.checked_div(info.channels))
        .and_then(|samples| duration_of(samples, info.rate))
    {
        line.push_str(&format!(", {d}"));
    }
    cx.annotate(line);
    dff_walk(&cx, input, file).await
}

#[derive(Default)]
struct DffInfo {
    rate: u64,
    channels: u64,
    compression: Option<String>,
    dsd_bytes: u64,
}

/// Gathers what the summary needs (two levels deep).
async fn collect(cx: &Cx, region: Span, info: &mut DffInfo, depth: u32) -> Result<()> {
    let mut pos = 0u64;
    let mut n = 0u32;
    while region.len.saturating_sub(pos) >= 12 && n < 64 {
        let h = cx.read(region.sub(pos, 16)).await?;
        let id = h.get(..4).unwrap_or_default();
        let size = u64_be(&h, 4).unwrap_or(0);
        let data = region.sub(pos.saturating_add(12), size);
        match id {
            b"FS  " => info.rate = u32_be(&h, 12).unwrap_or(0).into(),
            b"CHNL" => info.channels = crate::bytes::u16_be(&h, 12).unwrap_or(0).into(),
            b"CMPR" => info.compression = Some(fourcc(h.get(12..16).unwrap_or_default())),
            b"DSD " if depth > 0 => info.dsd_bytes = size,
            b"PROP" if depth == 0 => {
                Box::pin(collect(cx, data.tail(4), info, 1)).await?;
            }
            _ => {}
        }
        if id == b"DSD " && depth == 0 {
            info.dsd_bytes = size;
        }
        pos = pos
            .saturating_add(12)
            .saturating_add(size)
            .saturating_add(size & 1);
        n = n.saturating_add(1);
    }
    Ok(())
}

async fn dff_walk(cx: &Cx, input: Input, region: Span) -> Result<()> {
    let mut pos = 0u64;
    while region.len.saturating_sub(pos) >= 12 {
        let h = cx.read(region.sub(pos, 16)).await?;
        let id = h.get(..4).unwrap_or_default().to_vec();
        let size = u64_be(&h, 4).unwrap_or(0);
        let span = region.sub(pos, size.saturating_add(12));
        let mut name = fourcc(&id);
        if dff_container(&id) == Some(4) {
            name = format!("{name} {}", fourcc(h.get(12..16).unwrap_or_default()));
        }
        let mut node = Node::new(name).span(span).summary(format!("{size} bytes"));
        if let Some(d) = dff_describe(&id) {
            node = node.desc(d);
        }
        cx.push(node.lazy(
            crate::expander!(self::dff_chunk: (Input, Vec<u8>, Span)),
            (input, id, span),
        ))
        .await;
        pos = pos
            .saturating_add(12)
            .saturating_add(size)
            .saturating_add(size & 1);
    }
    Ok(())
}

async fn dff_chunk(cx: Cx, (input, id, span): (Input, Vec<u8>, Span)) -> Result<()> {
    const BE: Endian = Endian::Big;
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Chunk ID", 4).emit()?;
    f.u64("Chunk size").emit()?;
    let data = span.tail(12);
    if let Some(skip) = dff_container(&id) {
        if skip > 0 {
            let t = cx.read(data.sub(0, 4)).await?;
            cx.emit(leaf("Type", data.sub(0, 4), text(fourcc(&t))));
        }
        return dff_walk(&cx, input, data.tail(skip)).await;
    }
    let block = cx.block(data.sub(0, data.len.min(256))).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    match id.as_slice() {
        b"FVER" => {
            f.u32("Version")
                .hex()
                .with(|&v, n| {
                    n.summary(format!(
                        "{}.{}.{}.{}",
                        v >> 24,
                        (v >> 16) & 0xff,
                        (v >> 8) & 0xff,
                        v & 0xff
                    ))
                })
                .emit()?;
        }
        b"FS  " => {
            f.u32("Sample rate")
                .with(|&r, n| n.summary(dsd_rate(r.into())))
                .emit()?;
        }
        b"CHNL" => {
            let n = f.u16("Channels").emit()?;
            for _ in 0..n.min(64) {
                f.ascii("Channel ID", 4).emit()?;
            }
        }
        b"CMPR" => {
            f.ascii("Compression type", 4).emit()?;
            let len = f.u8("Name length").emit()?;
            f.ascii("Name", len.into()).emit()?;
        }
        b"ABSS" => {
            f.u16("Hours").emit()?;
            f.u8("Minutes").emit()?;
            f.u8("Seconds").emit()?;
            f.u32("Samples").emit()?;
        }
        b"LSCO" => {
            f.u16("Loudspeaker configuration")
                .enumeration(&[
                    (0, "2-channel stereo"),
                    (3, "5-channel"),
                    (4, "6-channel (5.1)"),
                    (65535, "undefined"),
                ])
                .emit()?;
        }
        b"DIAR" | b"DITI" => {
            let len = f.u32("Length").emit()?;
            crate::formats::sound::latin1_field(&mut f, "Text", len.into()).emit()?;
        }
        b"ID3 " => cx.emit(embedded("ID3 tag", input.nested(data))),
        b"DSD " => cx.emit(Node::new("Samples").span(data)),
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}
