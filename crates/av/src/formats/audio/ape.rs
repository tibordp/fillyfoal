//! Monkey's Audio (`MAC `): a descriptor and header (or, before version
//! 3.98, a single older header), a seek table, the original WAV header,
//! the compressed frames, and usually an APE tag at the end.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, parse};
use crate::formats::util::sound::{channels, duration_of};
use crate::formats::{Format, Input, Probe, audio::id3};
use crate::node::Node;
use crate::record;
use crate::value::{EnumTable, FlagTable, flag};

const LE: Endian = Endian::Little;

pub static FORMAT: Format = Format {
    name: "ape",
    title: "Monkey's Audio",
    extensions: &["ape", "apl"],
    mime: "audio/x-ape",
    probe: Probe::Custom(|h| {
        h.starts_with(b"MAC ")
            && crate::bytes::u16_le(h.data, 4).is_some_and(|v| (3800..=4100).contains(&v))
    }),
    dissect: crate::expander!(dissect: Input),
};

const LEVEL: EnumTable = &[
    (1000, "fast"),
    (2000, "normal"),
    (3000, "high"),
    (4000, "extra high"),
    (5000, "insane"),
];

const FLAGS: FlagTable = &[
    flag(0x1, "8_BIT"),
    flag(0x2, "CRC"),
    flag(0x4, "HAS_PEAK_LEVEL"),
    flag(0x8, "24_BIT"),
    flag(0x10, "HAS_SEEK_ELEMENTS"),
    flag(0x20, "CREATE_WAV_HEADER"),
    flag(0x40, "AIFF"),
    flag(0x80, "W64"),
    flag(0x100, "SND"),
    flag(0x200, "BIG_ENDIAN"),
    flag(0x400, "CAF"),
    flag(0x800, "FLOATING_POINT"),
];

record! {
    pub struct Descriptor {
        id: ascii[4] "ID",
        version: u16 "Version" .with(|&v, n| n.summary(format!("{}.{:02}", v / 1000, v % 1000 / 10))),
        padding: u16 "Padding",
        descriptor_bytes: u32 "Descriptor bytes",
        header_bytes: u32 "Header bytes",
        seek_table_bytes: u32 "Seek table bytes",
        wav_header_bytes: u32 "WAV header bytes",
        frame_bytes: u32 "Frame data bytes",
        frame_bytes_high: u32 "Frame data bytes (high)",
        terminating_bytes: u32 "Terminating data bytes",
        md5: bytes[16] "MD5",
    }
}

record! {
    pub struct Header {
        level: u16 "Compression level" .enumeration(LEVEL),
        flags: u16 "Format flags" .flags(FLAGS),
        blocks_per_frame: u32 "Blocks per frame",
        final_frame_blocks: u32 "Final frame blocks",
        frames: u32 "Total frames",
        bits: u16 "Bits per sample",
        channels: u16 "Channels",
        rate: u32 "Sample rate",
    }
}

record! {
    /// The header of files older than version 3.98.
    pub struct OldHeader {
        id: ascii[4] "ID",
        version: u16 "Version" .with(|&v, n| n.summary(format!("{}.{:02}", v / 1000, v % 1000 / 10))),
        level: u16 "Compression level" .enumeration(LEVEL),
        flags: u16 "Format flags" .flags(FLAGS),
        channels: u16 "Channels",
        rate: u32 "Sample rate",
        wav_header_bytes: u32 "WAV header bytes",
        terminating_bytes: u32 "Terminating data bytes",
        frames: u32 "Total frames",
        final_frame_blocks: u32 "Final frame blocks",
    }
}

struct Info {
    level: u16,
    bits: u16,
    channels: u16,
    rate: u32,
    samples: u64,
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, tags) = trailing_tags(&cx, input).await?;
    let head = cx.read(file.sub(0, 6)).await?;
    let version = crate::bytes::u16_le(&head, 4).unwrap_or(0);
    let (info, data_start, sections) = if version >= 3980 {
        let dspan = file.sub(0, Descriptor::SIZE);
        let d = parse(&cx, dspan, LE, &(), Descriptor::layout).await?;
        cx.emit(Descriptor::node("Descriptor", dspan, LE));
        let hspan = file.sub(d.descriptor_bytes.into(), d.header_bytes.into());
        let h = parse(&cx, hspan.sub(0, Header::SIZE), LE, &(), Header::layout).await?;
        cx.emit(Header::node("Header", hspan, LE));
        let samples = u64::from(h.frames.saturating_sub(1))
            .saturating_mul(h.blocks_per_frame.into())
            .saturating_add(h.final_frame_blocks.into());
        let mut at = hspan.end().saturating_sub(file.offset);
        let mut sections = Vec::new();
        for (name, len) in [
            ("Seek table", u64::from(d.seek_table_bytes)),
            ("WAV header", u64::from(d.wav_header_bytes)),
            (
                "Frame data",
                u64::from(d.frame_bytes) | (u64::from(d.frame_bytes_high) << 32),
            ),
            ("Terminating data", u64::from(d.terminating_bytes)),
        ] {
            sections.push((name, file.sub(at, len)));
            at = at.saturating_add(len);
        }
        let info = Info {
            level: h.level,
            bits: h.bits,
            channels: h.channels,
            rate: h.rate,
            samples,
        };
        (info, at, sections)
    } else {
        let span = file.sub(0, OldHeader::SIZE);
        let h = parse(&cx, span, LE, &(), OldHeader::layout).await?;
        cx.emit(OldHeader::node("Header", span, LE));
        // As FFmpeg's ape demuxer reads them.
        let blocks: u64 = if version >= 3950 {
            73728 * 4
        } else if version >= 3900 || (version >= 3800 && h.level >= 4000) {
            73728
        } else {
            9216
        };
        let samples = u64::from(h.frames.saturating_sub(1))
            .saturating_mul(blocks)
            .saturating_add(h.final_frame_blocks.into());
        let mut at = OldHeader::SIZE;
        let mut sections = Vec::new();
        if h.flags & 0x4 != 0 {
            sections.push(("Peak level", file.sub(at, 4)));
            at = at.saturating_add(4);
        }
        let mut seek_entries = u64::from(h.frames);
        if h.flags & 0x10 != 0 {
            let n = cx.read_avail(file.sub(at, 4)).await?;
            seek_entries = crate::bytes::u32_le(&n, 0).map_or(0, u64::from);
            sections.push(("Seek elements", file.sub(at, 4)));
            at = at.saturating_add(4);
        }
        if h.flags & 0x20 == 0 {
            sections.push(("WAV header", file.sub(at, h.wav_header_bytes.into())));
            at = at.saturating_add(h.wav_header_bytes.into());
        }
        let seek = seek_entries.saturating_mul(4);
        sections.push(("Seek table", file.sub(at, seek)));
        at = at.saturating_add(seek);
        if version < 3810 {
            sections.push(("Seek bit table", file.sub(at, h.frames.into())));
            at = at.saturating_add(h.frames.into());
        }
        sections.push(("Frame data", file.sub(at, end.saturating_sub(at))));
        let bits = if h.flags & 1 != 0 {
            8
        } else if h.flags & 8 != 0 {
            24
        } else {
            16
        };
        let info = Info {
            level: h.level,
            bits,
            channels: h.channels,
            rate: h.rate,
            samples,
        };
        (info, end, sections)
    };
    let layout = match info.channels {
        1 => "mono".to_owned(),
        2 => "stereo".to_owned(),
        n => channels(n),
    };
    let mut line = format!(
        "Monkey's Audio {}-bit, {}, {layout}",
        info.bits,
        crate::formats::iff::wav::khz(info.rate),
    );
    if let Some(d) = duration_of(info.samples, info.rate.into()) {
        line.push_str(&format!(", {d}"));
    }
    if let Some(level) = crate::value::lookup(LEVEL, info.level.into()) {
        line.push_str(&format!(", {level} compression"));
    }
    cx.annotate(line);
    for (name, span) in sections {
        if span.is_empty() {
            continue;
        }
        let node = match name {
            "Seek table" => crate::formats::util::sound::table::<SeekEntry>(
                name,
                span,
                LE,
                "Frame",
                Some(|e| format!("at {:#x}", e.offset)),
            ),
            "Peak level" | "Seek elements" => {
                let v = cx.read_avail(span).await?;
                crate::formats::util::sound::leaf(
                    name,
                    span,
                    crate::formats::util::sound::uint(crate::bytes::u32_le(&v, 0).unwrap_or(0), 32),
                )
            }
            "Seek bit table" => Node::new(name)
                .span(span)
                .desc("Bit offsets within the first byte of each frame (before 3.81)"),
            "WAV header" => crate::formats::embedded(name, input.nested(span)),
            _ => Node::new(name)
                .span(span)
                .summary(format!("{} bytes", span.len)),
        };
        cx.emit(node);
    }
    if data_start < end {
        cx.emit(
            Node::new("Unaccounted data")
                .span(file.sub(data_start, end.saturating_sub(data_start))),
        );
    }
    for node in tags {
        cx.emit(node);
    }
    Ok(())
}

record! {
    pub struct SeekEntry {
        offset: u32 "Offset" .hex(),
    }
}

/// The tags at the end of `input` (shared by the APE-tagged formats):
/// where the audio data ends, and the tag nodes in file order. APE, ID3v1
/// (with Enhanced TAG+), Lyrics3 and appended ID3v2 tags are found in any
/// order, as [`id3::trailing_tags`] finds them for MP3 and FLAC.
pub async fn trailing_tags(cx: &Cx, input: Input) -> Result<(u64, Vec<Node>)> {
    let t = id3::trailing_tags(cx, input, input.span, 0).await?;
    Ok((t.end, t.nodes))
}
