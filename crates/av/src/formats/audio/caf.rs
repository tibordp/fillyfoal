//! Apple Core Audio Format: `caff`, version and flags, then chunks with a
//! four-character type and a 64-bit big-endian size (-1 for a final `data`
//! chunk that runs to the end of the file).
//!
//! Decoded: `desc` (format IDs and their flags), `data`, `pakt` (the
//! packet table, each entry pointing at its packet in the audio data),
//! `kuki` (the magic cookie: an MPEG-4 ES descriptor for AAC, the
//! `ALACSpecificConfig` for Apple Lossless), `chan` (channel layout tag,
//! bitmap and descriptions; shared with AIFF's `CHAN`), `info`, `strg`,
//! `mark`, `regn`, `inst`, `peak`, `ovvw`, `umid`, `uuid`, `midi`, `free`.

use crate::bytes::{to_u64, to_usize, u32_be, u64_be};
use crate::cx::Cx;
use crate::dsl::{Record, emit_record};
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields, parse};
use crate::formats::iff::wav;
use crate::formats::util::sound::{channels, duration_of, fourcc, leaf, table, text, uint};
use crate::formats::util::vidutil::esds;
use crate::formats::{Format, Input, Probe, embedded};
use crate::node::{Count, Node};
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag, lookup};

const BE: Endian = Endian::Big;

pub static FORMAT: Format = Format {
    name: "caf",
    title: "Core Audio Format",
    extensions: &["caf"],
    mime: "audio/x-caf",
    probe: Probe::Magic(&[(0, b"caff\x00\x01")]),
    dissect: crate::expander!(dissect: Input),
};

/// `kAudioFormat*` identifiers (CoreAudioBaseTypes.h).
const FORMATS: &[(&[u8; 4], &str)] = &[
    (b"lpcm", "Linear PCM"),
    (b"ac-3", "AC-3"),
    (b"cac3", "AC-3 (IEC 60958)"),
    (b"ec-3", "E-AC-3"),
    (b"ima4", "IMA 4:1 ADPCM"),
    (b"aac ", "AAC"),
    (b"aach", "HE-AAC"),
    (b"aacp", "HE-AAC v2"),
    (b"aacl", "AAC LD"),
    (b"aace", "AAC ELD"),
    (b"aacf", "AAC ELD SBR"),
    (b"aacg", "AAC ELD v2"),
    (b"aacs", "AAC spatial"),
    (b"usac", "USAC (xHE-AAC)"),
    (b"celp", "MPEG-4 CELP"),
    (b"hvxc", "MPEG-4 HVXC"),
    (b"twvq", "MPEG-4 TwinVQ"),
    (b"MAC3", "MACE 3:1"),
    (b"MAC6", "MACE 6:1"),
    (b"ulaw", "µ-law"),
    (b"alaw", "A-law"),
    (b"QDMC", "QDesign Music"),
    (b"QDM2", "QDesign Music 2"),
    (b"Qclp", "QCELP"),
    (b"Qclq", "QCELP (low)"),
    (b".mp1", "MPEG Layer I"),
    (b".mp2", "MPEG Layer II"),
    (b".mp3", "MPEG Layer III"),
    (b"time", "Time code"),
    (b"midi", "MIDI stream"),
    (b"apvs", "Parameter value stream"),
    (b"alac", "Apple Lossless"),
    (b"samr", "AMR-NB"),
    (b"sawb", "AMR-WB"),
    (b"AUDB", "Audible"),
    (b"ilbc", "iLBC"),
    (b"dvi8", "DVI/Intel IMA ADPCM"),
    (b"ms\x00\x02", "Microsoft ADPCM"),
    (b"ms\x00\x11", "DVI/Intel IMA ADPCM"),
    (b"flac", "FLAC"),
    (b"opus", "Opus"),
    (b"apac", "APAC"),
];

fn format_name(id: &[u8]) -> String {
    FORMATS
        .iter()
        .find(|(k, _)| k.as_slice() == id)
        .map_or_else(|| fourcc(id), |(_, n)| (*n).to_owned())
}

const PCM_FLAGS: FlagTable = &[flag(0x1, "FLOAT"), flag(0x2, "LITTLE_ENDIAN")];
const ALAC_FLAGS: EnumTable = &[
    (0, "unspecified"),
    (1, "16-bit source"),
    (2, "20-bit source"),
    (3, "24-bit source"),
    (4, "32-bit source"),
];

#[derive(Clone, Debug, Default)]
struct Description {
    rate: f64,
    format: Vec<u8>,
    flags: u32,
    bytes_per_packet: u32,
    frames_per_packet: u32,
    channels: u32,
    bits: u32,
}

impl Description {
    fn bits(&self) -> u32 {
        if self.bits > 0 {
            return self.bits;
        }
        match (self.format.as_slice(), self.flags) {
            (b"alac", 1) => 16,
            (b"alac", 2) => 20,
            (b"alac", 3) => 24,
            (b"alac", 4) => 32,
            _ => 0,
        }
    }

    fn codec(&self) -> String {
        let mut s = match (self.format.as_slice(), self.flags & 1) {
            (b"lpcm", 1) => "Float PCM".to_owned(),
            _ => format_name(&self.format),
        };
        if self.bits() > 0 {
            s.push_str(&format!(" {}-bit", self.bits()));
        }
        if self.format == b"lpcm" && self.bits > 8 {
            s.push_str(if self.flags & 2 != 0 { " LE" } else { " BE" });
        }
        s
    }

    fn rate(&self) -> String {
        if self.rate.fract() == 0.0 && self.rate >= 0.0 && self.rate < 4e9 {
            wav::khz(self.rate as u32)
        } else {
            format!("{:.3} Hz", self.rate)
        }
    }
}

fn desc(f: &mut Fields<'_>, _: &()) -> Result<Description> {
    let rate = f.f64("Sample rate").emit()?;
    let format = f
        .bytes("Format ID", 4)
        .with(|b, n| n.value(text(fourcc(b))).summary(format_name(b)))
        .emit()?;
    let flags = match format.as_slice() {
        b"lpcm" => f.u32("Format flags").flags(PCM_FLAGS).emit()?,
        b"alac" => f.u32("Format flags").enumeration(ALAC_FLAGS).emit()?,
        b"aac " | b"aach" | b"aacp" | b"aacl" | b"aace" => f
            .u32("Format flags")
            .desc("MPEG-4 audio object type")
            .with(|&v, n| {
                match lookup(crate::formats::util::vidutil::AUDIO_OBJECT_TYPES, v.into()) {
                    Some(t) => n.summary(t),
                    None => n,
                }
            })
            .emit()?,
        _ => f.u32("Format flags").hex().emit()?,
    };
    Ok(Description {
        rate,
        format,
        flags,
        bytes_per_packet: f.u32("Bytes per packet").desc("0 = variable").emit()?,
        frames_per_packet: f.u32("Frames per packet").desc("0 = variable").emit()?,
        channels: f.u32("Channels per frame").emit()?,
        bits: f
            .u32("Bits per channel")
            .desc("0 for compressed formats")
            .emit()?,
    })
}

const CHUNKS: &[(&[u8; 4], &str)] = &[
    (b"desc", "Audio description"),
    (b"data", "Audio data"),
    (b"pakt", "Packet table"),
    (b"chan", "Channel layout"),
    (b"kuki", "Magic cookie (codec configuration)"),
    (b"info", "Information strings"),
    (b"strg", "Strings"),
    (b"mark", "Markers"),
    (b"regn", "Regions"),
    (b"inst", "Instrument"),
    (b"midi", "MIDI data"),
    (b"umid", "Unique material identifier"),
    (b"ovvw", "Overview"),
    (b"peak", "Peak values"),
    (b"edct", "Edit comments"),
    (b"uuid", "User-defined"),
    (b"free", "Free space"),
];

/// What a chunk's expansion needs to know about the file.
#[derive(Clone, Debug)]
struct ChunkState {
    input: Input,
    id: [u8; 4],
    span: Span,
    desc: Option<Description>,
    /// The audio data (after the edit count).
    audio: Option<Span>,
}

/// Chunks listed (a guard against hostile files of empty chunks).
const MAX_CHUNKS: usize = 4096;

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let head = cx.block(file.sub(0, 8)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("File type", 4).emit()?;
    f.u16("Version").emit()?;
    f.u16("Flags").emit()?;

    let mut pos = 8u64;
    let mut description = None;
    let mut audio = None;
    let mut valid_frames = None;
    let mut layout_tag = None;
    let mut chunks = Vec::new();
    while file.len.saturating_sub(pos) >= 12 && chunks.len() < MAX_CHUNKS {
        let h = cx.read(file.sub(pos, 12)).await?;
        let id: [u8; 4] = crate::bytes::array(&h, 0).unwrap_or_default();
        let raw = u64_be(&h, 4).unwrap_or(0);
        let size = if raw == u64::MAX {
            file.len.saturating_sub(pos).saturating_sub(12)
        } else {
            raw
        };
        let span = file.sub(pos, size.saturating_add(12));
        let data = span.tail(12);
        match &id {
            b"desc" => description = parse(&cx, data, BE, &(), desc).await.ok(),
            b"data" => audio = Some(data.tail(4)),
            b"pakt" => {
                let p = cx.read_avail(data.sub(8, 8)).await?;
                valid_frames = u64_be(&p, 0);
            }
            b"chan" => layout_tag = u32_be(&cx.read_avail(data.sub(0, 4)).await?, 0),
            _ => {}
        }
        chunks.push((id, span, raw));
        pos = pos.saturating_add(size).saturating_add(12);
    }
    if let Some(d) = &description {
        let layout = match layout_tag {
            Some(t) if t >> 16 >= 100 && t != 0xffff_0000 => layout_short(t),
            _ => match d.channels {
                1 => "mono".to_owned(),
                2 => "stereo".to_owned(),
                n => channels(n),
            },
        };
        let mut line = format!("CAF {}, {}, {layout}", d.codec(), d.rate());
        let frames = match (valid_frames, audio) {
            (Some(n), _) => Some(n),
            (None, Some(a)) if d.bytes_per_packet > 0 => Some(
                a.len
                    .checked_div(d.bytes_per_packet.into())
                    .unwrap_or(0)
                    .saturating_mul(d.frames_per_packet.max(1).into()),
            ),
            _ => None,
        };
        if let Some(t) = frames.and_then(|n| duration_of(n, d.rate as u64)) {
            line.push_str(&format!(", {t}"));
        }
        cx.annotate(line);
    }
    for (id, span, raw) in chunks {
        let mut node = Node::new(fourcc(&id)).span(span);
        if let Some((_, d)) = CHUNKS.iter().find(|(k, _)| *k == &id) {
            node = node.desc(*d);
        }
        let size = span.len.saturating_sub(12);
        node = node.summary(match &id {
            b"desc" => description.as_ref().map_or_else(
                || format!("{size} bytes"),
                |d| format!("{}, {}, {}", d.codec(), d.rate(), channels(d.channels)),
            ),
            b"data" => format!("{} bytes of audio", size.saturating_sub(4)),
            b"chan" => match layout_tag {
                Some(t) => layout_name(t),
                None => format!("{size} bytes"),
            },
            b"pakt" => {
                let p = cx.read_avail(span.tail(12).sub(0, 16)).await?;
                format!(
                    "{} packets, {} valid frames",
                    u64_be(&p, 0).unwrap_or(0),
                    u64_be(&p, 8).unwrap_or(0)
                )
            }
            b"kuki" => match description.as_ref().map(|d| d.format.as_slice()) {
                Some(b"aac " | b"aach" | b"aacp") => {
                    let b = cx.read_avail(span.tail(12).sub(0, 256)).await?;
                    esds::esds_summary(&b).unwrap_or_else(|| format!("{size} bytes"))
                }
                Some(b"alac") => "ALAC configuration".to_owned(),
                _ => format!("{size} bytes"),
            },
            _ => format!("{size} bytes"),
        });
        let declared = raw.saturating_add(12);
        if raw != u64::MAX && span.len < declared {
            node = node.diag(Diagnostic::truncated(
                Span::new(span.source, span.offset, declared),
                span.len,
            ));
        }
        let state = ChunkState {
            input,
            id,
            span,
            desc: description.clone(),
            audio,
        };
        cx.push(node.lazy(chunk, state)).await;
    }
    if pos < file.len {
        cx.emit(Node::new("Trailing data").span(file.tail(pos)));
    }
    Ok(())
}

async fn chunk(cx: Cx, st: ChunkState) -> Result<()> {
    let span = st.span;
    let head = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &head, BE);
    f.ascii("Chunk type", 4).emit()?;
    f.u64("Chunk size")
        .with(|&s, n| {
            if s == u64::MAX {
                n.summary("-1: to the end of the file")
            } else {
                n
            }
        })
        .emit()?;
    let data = span.tail(12);
    match &st.id {
        b"desc" => {
            let block = cx.block(data).await?;
            desc(&mut Fields::emitting(&cx, &block, BE), &())?;
        }
        b"data" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, BE)
                .u32("Edit count")
                .desc("Incremented whenever the audio data changes")
                .emit()?;
            cx.emit(Node::new("Audio data").span(data.tail(4)));
        }
        b"pakt" => {
            let block = cx.block(data.sub(0, 24)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            let packets = f.int::<i64>("Packets").emit()?;
            f.int::<i64>("Valid frames")
                .desc("Frames of audio, excluding priming and remainder")
                .emit()?;
            f.i32("Priming frames")
                .desc("Encoder delay at the start")
                .emit()?;
            f.i32("Remainder frames")
                .desc("Padding at the end of the last packet")
                .emit()?;
            let entries = data.tail(24);
            let (bpp, fpp) = st
                .desc
                .as_ref()
                .map_or((0, 0), |d| (d.bytes_per_packet, d.frames_per_packet));
            cx.emit(
                Node::new("Packet sizes")
                    .span(entries)
                    .summary(format!("{packets} packets"))
                    .desc("Variable-length integers: the size of each packet (and its frames, if variable)")
                    .lazy(
                        packet_table,
                        PacketTable {
                            entries,
                            audio: st.audio,
                            packets: u64::try_from(packets).unwrap_or(0),
                            variable_size: bpp == 0,
                            variable_frames: fpp == 0,
                        },
                    ),
            );
        }
        b"chan" => {
            channel_layout(&cx, data, BE).await?;
        }
        b"kuki" => {
            let format = st
                .desc
                .as_ref()
                .map(|d| d.format.clone())
                .unwrap_or_default();
            match format.as_slice() {
                b"aac " | b"aach" | b"aacp" | b"aacl" | b"aace" => {
                    let total = esds::header(&cx.read_avail(data.sub(0, 8)).await?)
                        .map_or(data.len, |(_, len, head)| len.saturating_add(head))
                        .min(data.len);
                    esds::descriptors(&cx, st.input, data.sub(0, total), 0).await?;
                    if data.len > total {
                        cx.push(Node::new("Padding").span(data.tail(total))).await;
                    }
                }
                b"alac" => alac_cookie(&cx, data).await?,
                _ => cx.emit(Node::new("Data").span(data)),
            }
        }
        b"info" => {
            let block = cx.block(data.sub(0, data.len.min(1 << 16))).await?;
            let count = u32_be(&block.data, 0).unwrap_or(0);
            cx.emit(leaf("Entries", data.sub(0, 4), uint(count, 32)));
            let mut at = 4usize;
            for _ in 0..count {
                let rest = block.data.get(at..).unwrap_or_default();
                let Some(k) = rest.iter().position(|&b| b == 0) else {
                    break;
                };
                let after = rest.get(k.saturating_add(1)..).unwrap_or_default();
                let Some(v) = after.iter().position(|&b| b == 0) else {
                    break;
                };
                let key = String::from_utf8_lossy(rest.get(..k).unwrap_or_default()).into_owned();
                let value =
                    String::from_utf8_lossy(after.get(..v).unwrap_or_default()).into_owned();
                let len = k.saturating_add(v).saturating_add(2);
                cx.emit(leaf(key, data.sub(to_u64(at), to_u64(len)), text(value)));
                at = at.saturating_add(len);
            }
        }
        b"strg" => strings(&cx, data).await?,
        b"mark" => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.u32("SMPTE time type").enumeration(SMPTE_TYPE).emit()?;
            let n = f.u32("Markers").emit()?;
            let markers = data.sub(8, u64::from(n).saturating_mul(Marker::SIZE));
            cx.emit(table::<Marker>(
                "Markers",
                markers,
                BE,
                "Marker",
                Some(|m| format!("{} at frame {}", marker_type(&m.kind), m.position)),
            ));
        }
        b"regn" => regions(&cx, data).await?,
        b"inst" => {
            emit_record::<Instrument>(&cx, data, BE).await?;
        }
        b"peak" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(&cx, &block, BE).u32("Edit count").emit()?;
            cx.emit(table::<Peak>(
                "Peaks",
                data.tail(4),
                BE,
                "Channel",
                Some(|p| format!("{} at frame {}", p.value, p.frame)),
            ));
        }
        b"ovvw" => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(&cx, &block, BE);
            f.u32("Edit count").emit()?;
            f.u32("Frames per overview sample").emit()?;
            cx.emit(
                Node::new("Overview samples")
                    .span(data.tail(8))
                    .desc("Minimum and maximum (16-bit) per sample and channel"),
            );
        }
        b"umid" => {
            let block = cx.block(data.sub(0, 64)).await?;
            wav::umid(&mut Fields::emitting(&cx, &block, BE), &())?;
        }
        b"midi" => cx.emit(embedded("MIDI file", st.input.nested(data))),
        b"free" => cx.emit(Node::new("Padding").span(data)),
        b"uuid" => {
            let block = cx.block(data.sub(0, 16)).await?;
            Fields::emitting(&cx, &block, BE)
                .bytes("UUID", 16)
                .with(|b, n| n.summary(crate::formats::util::vidutil::uuid(b)))
                .emit()?;
            cx.emit(Node::new("Data").span(data.tail(16)));
        }
        _ => cx.emit(Node::new("Data").span(data)),
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Packet table

#[derive(Clone, Debug)]
struct PacketTable {
    entries: Span,
    audio: Option<Span>,
    packets: u64,
    variable_size: bool,
    variable_frames: bool,
}

/// A CAF variable-length integer (7 bits per byte, most significant
/// first): (value, bytes).
fn varint(b: &[u8], at: usize) -> Option<(u64, usize)> {
    let mut value = 0u64;
    for i in 0..9usize {
        let byte = *b.get(at.saturating_add(i))?;
        value = (value << 7) | u64::from(byte & 0x7f);
        if byte & 0x80 == 0 {
            return Some((value, i.saturating_add(1)));
        }
    }
    None
}

async fn packet_table(cx: Cx, t: PacketTable) -> Result<()> {
    if !t.variable_size && !t.variable_frames {
        cx.emit(Node::new("Data").span(t.entries));
        return Ok(());
    }
    if t.packets <= t.entries.len {
        cx.set_count(Count::Exact(t.packets));
    }
    let (mut pos, mut index, mut offset) = cx.resume::<(u64, u64, u64)>().unwrap_or((0, 0, 0));
    while pos < t.entries.len && index < t.packets {
        let at = (pos, index, offset);
        cx.mark(move || at);
        let b = cx.read_avail(t.entries.sub(pos, 18)).await?;
        let mut used = 0usize;
        let mut size = None;
        let mut frames = None;
        if t.variable_size {
            let Some((v, n)) = varint(&b, used) else {
                break;
            };
            size = Some(v);
            used = used.saturating_add(n);
        }
        if t.variable_frames {
            let Some((v, n)) = varint(&b, used) else {
                break;
            };
            frames = Some(v);
            used = used.saturating_add(n);
        }
        let span = t.entries.sub(pos, to_u64(used));
        let mut node = Node::new(format!("Packet {index}")).span(span);
        let mut parts = Vec::new();
        if let Some(s) = size {
            node = node.value(uint(s, 64));
            parts.push(format!("{s} bytes at {offset:#x}"));
            if let Some(audio) = t.audio {
                node = node.target(audio.sub(offset, s));
            }
            offset = offset.saturating_add(s);
        }
        if let Some(fr) = frames {
            parts.push(format!("{fr} frames"));
            if size.is_none() {
                node = node.value(uint(fr, 64));
            }
        }
        cx.push(node.summary(parts.join(", "))).await;
        pos = pos.saturating_add(to_u64(used));
        index = index.saturating_add(1);
    }
    if pos < t.entries.len {
        cx.emit(Node::new("Unused").span(t.entries.tail(pos)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Channel layouts (also AIFF `CHAN`)

/// `kAudioChannelLayoutTag_*`, by the high 16 bits (the low 16 bits are
/// the channel count).
const LAYOUT_TAGS: EnumTable = &[
    (0, "Use channel descriptions"),
    (1, "Use channel bitmap"),
    (100, "Mono"),
    (101, "Stereo"),
    (102, "Stereo (headphones)"),
    (103, "Matrix stereo"),
    (104, "Mid/side"),
    (105, "XY"),
    (106, "Binaural"),
    (107, "Ambisonic B-format"),
    (108, "Quadraphonic"),
    (109, "Pentagonal"),
    (110, "Hexagonal"),
    (111, "Octagonal"),
    (112, "Cube"),
    (113, "MPEG 3.0 A"),
    (114, "MPEG 3.0 B"),
    (115, "MPEG 4.0 A"),
    (116, "MPEG 4.0 B"),
    (117, "MPEG 5.0 A"),
    (118, "MPEG 5.0 B"),
    (119, "MPEG 5.0 C"),
    (120, "MPEG 5.0 D"),
    (121, "MPEG 5.1 A"),
    (122, "MPEG 5.1 B"),
    (123, "MPEG 5.1 C"),
    (124, "MPEG 5.1 D"),
    (125, "MPEG 6.1 A"),
    (126, "MPEG 7.1 A"),
    (127, "MPEG 7.1 B"),
    (128, "MPEG 7.1 C"),
    (129, "Emagic default 7.1"),
    (130, "SMPTE DTV"),
    (131, "ITU 2.1"),
    (132, "ITU 2.2"),
    (133, "DVD 4"),
    (134, "DVD 5"),
    (135, "DVD 6"),
    (136, "DVD 10"),
    (137, "DVD 11"),
    (138, "DVD 18"),
    (139, "AudioUnit 6.0"),
    (140, "AudioUnit 7.0"),
    (141, "AAC 6.0"),
    (142, "AAC 6.1"),
    (143, "AAC 7.0"),
    (144, "AAC octagonal"),
    (145, "TMH 10.2 standard"),
    (146, "TMH 10.2 full"),
    (147, "Discrete in order"),
    (148, "AudioUnit 7.0 front"),
    (149, "AC-3 1/0.1"),
    (150, "AC-3 3/0"),
    (151, "AC-3 3/1"),
    (152, "AC-3 3/0.1"),
    (153, "AC-3 2/1.1"),
    (154, "AC-3 3/1.1"),
    (155, "E-AC-3 6.0 A"),
    (156, "E-AC-3 7.0 A"),
    (157, "E-AC-3 6.1 A"),
    (158, "E-AC-3 6.1 B"),
    (159, "E-AC-3 6.1 C"),
    (160, "E-AC-3 7.1 A"),
    (161, "E-AC-3 7.1 B"),
    (162, "E-AC-3 7.1 C"),
    (163, "E-AC-3 7.1 D"),
    (164, "E-AC-3 7.1 E"),
    (165, "E-AC-3 7.1 F"),
    (166, "E-AC-3 7.1 G"),
    (167, "E-AC-3 7.1 H"),
    (168, "DTS 3.1"),
    (169, "DTS 4.1"),
    (170, "DTS 6.0 A"),
    (171, "DTS 6.0 B"),
    (172, "DTS 6.0 C"),
    (173, "DTS 6.1 A"),
    (174, "DTS 6.1 B"),
    (175, "DTS 6.1 C"),
    (176, "DTS 7.0"),
    (177, "DTS 7.1"),
    (178, "DTS 8.0 A"),
    (179, "DTS 8.0 B"),
    (180, "DTS 8.1 A"),
    (181, "DTS 8.1 B"),
    (182, "DTS 6.1 D"),
    (183, "AAC 7.1 B"),
    (184, "AAC 7.1 C"),
    (185, "WAVE 4.0 B"),
    (186, "WAVE 5.0 B"),
    (187, "WAVE 5.1 B"),
    (188, "WAVE 6.1"),
    (189, "WAVE 7.1"),
    (190, "HOA ACN SN3D"),
    (191, "HOA ACN N3D"),
    (192, "Atmos 7.1.4"),
    (193, "Atmos 9.1.6"),
    (194, "Atmos 5.1.2"),
    (0xffff, "Unknown"),
];

/// "MPEG 5.1 A, 6 ch".
pub fn layout_name(tag: u32) -> String {
    let kind = tag >> 16;
    let count = tag & 0xffff;
    match lookup(LAYOUT_TAGS, kind.into()) {
        Some(name) if kind >= 100 && kind != 0xffff => format!("{name}, {}", channels(count)),
        Some(name) => name.to_owned(),
        None => format!("layout {kind}, {}", channels(count)),
    }
}

/// "mono", "stereo", "MPEG 5.1 A".
fn layout_short(tag: u32) -> String {
    match tag >> 16 {
        100 => "mono".to_owned(),
        101 => "stereo".to_owned(),
        kind => {
            lookup(LAYOUT_TAGS, kind.into()).map_or_else(|| channels(tag & 0xffff), str::to_owned)
        }
    }
}

/// `kAudioChannelBit_*`.
const CHANNEL_BITS: FlagTable = &[
    flag(0x1, "LEFT"),
    flag(0x2, "RIGHT"),
    flag(0x4, "CENTER"),
    flag(0x8, "LFE_SCREEN"),
    flag(0x10, "LEFT_SURROUND"),
    flag(0x20, "RIGHT_SURROUND"),
    flag(0x40, "LEFT_CENTER"),
    flag(0x80, "RIGHT_CENTER"),
    flag(0x100, "CENTER_SURROUND"),
    flag(0x200, "LEFT_SURROUND_DIRECT"),
    flag(0x400, "RIGHT_SURROUND_DIRECT"),
    flag(0x800, "TOP_CENTER_SURROUND"),
    flag(0x1000, "VERTICAL_HEIGHT_LEFT"),
    flag(0x2000, "VERTICAL_HEIGHT_CENTER"),
    flag(0x4000, "VERTICAL_HEIGHT_RIGHT"),
    flag(0x8000, "TOP_BACK_LEFT"),
    flag(0x10000, "TOP_BACK_CENTER"),
    flag(0x20000, "TOP_BACK_RIGHT"),
];

/// `kAudioChannelLabel_*`.
const CHANNEL_LABELS: EnumTable = &[
    (0, "Unused"),
    (1, "Left"),
    (2, "Right"),
    (3, "Center"),
    (4, "LFE"),
    (5, "Left surround"),
    (6, "Right surround"),
    (7, "Left center"),
    (8, "Right center"),
    (9, "Center surround"),
    (10, "Left surround direct"),
    (11, "Right surround direct"),
    (12, "Top center surround"),
    (13, "Vertical height left"),
    (14, "Vertical height center"),
    (15, "Vertical height right"),
    (16, "Top back left"),
    (17, "Top back center"),
    (18, "Top back right"),
    (33, "Rear surround left"),
    (34, "Rear surround right"),
    (35, "Left wide"),
    (36, "Right wide"),
    (37, "LFE 2"),
    (38, "Left total"),
    (39, "Right total"),
    (40, "Hearing impaired"),
    (41, "Narration"),
    (42, "Mono"),
    (43, "Dialog centric mix"),
    (44, "Center surround direct"),
    (45, "Haptic"),
    (100, "Use coordinates"),
    (200, "Ambisonic W"),
    (201, "Ambisonic X"),
    (202, "Ambisonic Y"),
    (203, "Ambisonic Z"),
    (204, "Mid"),
    (205, "Side"),
    (206, "XY X"),
    (207, "XY Y"),
    (301, "Headphones left"),
    (302, "Headphones right"),
    (304, "Click track"),
    (305, "Foreign language"),
    (400, "Discrete"),
    (0xffff_ffff, "Unknown"),
];

const DESCRIPTION_FLAGS: FlagTable = &[
    flag(0x1, "RECTANGULAR"),
    flag(0x2, "SPHERICAL"),
    flag(0x4, "METERS"),
];

record! {
    pub struct ChannelDescription {
        label: u32 "Label" .enumeration(CHANNEL_LABELS),
        flags: u32 "Flags" .flags(DESCRIPTION_FLAGS),
        x: f32 "Coordinate 1" .desc("Left/right, or azimuth"),
        y: f32 "Coordinate 2" .desc("Back/front, or elevation"),
        z: f32 "Coordinate 3" .desc("Down/up, or distance"),
    }
}

fn label_name(label: u32) -> String {
    if label >> 16 == 1 {
        return format!("Discrete {}", label & 0xffff);
    }
    lookup(CHANNEL_LABELS, label.into()).map_or_else(|| format!("label {label}"), str::to_owned)
}

/// An `AudioChannelLayout` at the start of `data` (CAF `chan`, AIFF
/// `CHAN`): tag, bitmap, and channel descriptions.
pub async fn channel_layout(cx: &Cx, data: Span, endian: Endian) -> Result<()> {
    let block = cx.block(data.sub(0, 12)).await?;
    let mut f = Fields::emitting(cx, &block, endian);
    f.u32("Layout tag")
        .hex()
        .with(|&t, n| n.summary(layout_name(t)))
        .desc("Layout in the high 16 bits, channel count in the low 16")
        .emit()?;
    f.u32("Channel bitmap").flags(CHANNEL_BITS).emit()?;
    let n = f.u32("Channel descriptions").emit()?;
    let rest = data.tail(12);
    let len = u64::from(n)
        .saturating_mul(ChannelDescription::SIZE)
        .min(rest.len);
    if len > 0 {
        cx.emit(table::<ChannelDescription>(
            "Descriptions",
            rest.sub(0, len),
            endian,
            "Channel",
            Some(|d| label_name(d.label)),
        ));
    }
    if rest.len > len {
        cx.emit(Node::new("Unused").span(rest.tail(len)));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// Magic cookies

record! {
    /// `ALACSpecificConfig` (ALACMagicCookieDescription.txt).
    pub struct AlacConfig {
        frame_length: u32 "Frame length" .desc("Samples per frame"),
        compatible_version: u8 "Compatible version",
        bit_depth: u8 "Bit depth",
        pb: u8 "Rice history multiplier (pb)",
        mb: u8 "Rice initial history (mb)",
        kb: u8 "Rice parameter limit (kb)",
        channels: u8 "Channels",
        max_run: u16 "Maximum run",
        max_frame_bytes: u32 "Maximum frame bytes" .desc("0 = unknown"),
        avg_bit_rate: u32 "Average bit rate",
        sample_rate: u32 "Sample rate",
    }
}

fn alac_summary(c: &AlacConfig) -> String {
    format!(
        "{}-bit, {}, {}, {} samples per frame",
        c.bit_depth,
        wav::khz(c.sample_rate),
        channels(c.channels),
        c.frame_length
    )
}

/// The ALAC cookie: either the bare `ALACSpecificConfig` (with an
/// optional channel layout), or QuickTime-style `frma` and `alac` atoms.
async fn alac_cookie(cx: &Cx, data: Span) -> Result<()> {
    let head = cx.read_avail(data.sub(0, 8)).await?;
    if head.get(4..8) != Some(b"frma".as_slice()) {
        let config = data.sub(0, AlacConfig::SIZE);
        let c = crate::dsl::read_record::<AlacConfig>(cx, config, BE).await?;
        cx.emit(AlacConfig::node("ALACSpecificConfig", config, BE).summary(alac_summary(&c)));
        let rest = data.tail(AlacConfig::SIZE);
        if !rest.is_empty() {
            atoms(cx, rest).await?;
        }
        return Ok(());
    }
    atoms(cx, data).await
}

/// QuickTime atoms in an ALAC cookie.
async fn atoms(cx: &Cx, region: Span) -> Result<()> {
    let mut pos = 0u64;
    let mut count = 0u32;
    while region.len.saturating_sub(pos) >= 8 && count < 64 {
        count = count.saturating_add(1);
        let h = cx.read_avail(region.sub(pos, 8)).await?;
        let size = u64::from(u32_be(&h, 0).unwrap_or(0)).max(8);
        let kind = h.get(4..8).unwrap_or_default().to_vec();
        let span = region.sub(pos, size);
        let body = span.tail(8);
        let mut node = Node::new(format!("{} atom", fourcc(&kind))).span(span);
        match kind.as_slice() {
            b"frma" => {
                let b = cx.read_avail(body.sub(0, 4)).await?;
                node = node.summary(format_name(&b)).desc("Original format");
            }
            b"alac" => {
                let config = body.sub(4, AlacConfig::SIZE);
                if let Ok(c) = crate::dsl::read_record::<AlacConfig>(cx, config, BE).await {
                    node = node.summary(alac_summary(&c));
                }
                node = node.lazy(alac_atom, body);
            }
            b"chan" => {
                node = node.lazy(chan_atom, body);
            }
            [0, 0, 0, 0] => node = node.desc("Terminator"),
            _ => {}
        }
        cx.emit(node);
        pos = pos.saturating_add(size);
    }
    if pos < region.len {
        cx.emit(Node::new("Unused").span(region.tail(pos)));
    }
    Ok(())
}

async fn alac_atom(cx: Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 4)).await?;
    Fields::emitting(&cx, &block, BE)
        .u32("Version and flags")
        .hex()
        .emit()?;
    emit_record::<AlacConfig>(&cx, body.sub(4, AlacConfig::SIZE), BE).await?;
    Ok(())
}

async fn chan_atom(cx: Cx, body: Span) -> Result<()> {
    let block = cx.block(body.sub(0, 4)).await?;
    Fields::emitting(&cx, &block, BE)
        .u32("Version and flags")
        .hex()
        .emit()?;
    channel_layout(&cx, body.tail(4), BE).await
}

// ---------------------------------------------------------------------------
// Strings, markers, regions, instrument, peaks

/// `strg`: string IDs and offsets, then the NUL-terminated strings.
async fn strings(cx: &Cx, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, data.len.min(1 << 16))).await?;
    let count = u32_be(&block.data, 0).unwrap_or(0);
    cx.emit(leaf("Strings", data.sub(0, 4), uint(count, 32)));
    let table_len = u64::from(count).saturating_mul(12);
    let base = table_len.saturating_add(4);
    for i in 0..u64::from(count) {
        let at = to_usize(i.saturating_mul(12).saturating_add(4));
        let Some(entry) = block.data.get(at..at.saturating_add(12)) else {
            break;
        };
        let id = u32_be(entry, 0).unwrap_or(0);
        let offset = u64_be(entry, 4).unwrap_or(0);
        let start = base.saturating_add(offset);
        let rest = block.data.get(to_usize(start)..).unwrap_or_default();
        let len = rest.iter().position(|&b| b == 0).unwrap_or(rest.len());
        let value = String::from_utf8_lossy(rest.get(..len).unwrap_or_default()).into_owned();
        cx.emit(
            Node::new(format!("String {id}"))
                .span(data.sub(start, to_u64(len).saturating_add(1)))
                .value(text(value))
                .desc("Referred to by markers and regions"),
        );
    }
    Ok(())
}

const SMPTE_TYPE: EnumTable = &[
    (0, "none"),
    (1, "24 fps"),
    (2, "25 fps"),
    (3, "30 fps drop-frame"),
    (4, "30 fps"),
    (5, "29.97 fps"),
    (6, "29.97 fps drop-frame"),
    (7, "60 fps"),
    (8, "59.94 fps"),
    (9, "60 fps drop-frame"),
    (10, "59.94 fps drop-frame"),
    (11, "50 fps"),
    (12, "23.976 fps"),
];

fn marker_type(kind: &[u8]) -> String {
    let name = match kind {
        [0, 0, 0, 0] => "generic",
        b"pbeg" => "program start",
        b"pend" => "program end",
        b"tbeg" => "track start",
        b"tend" => "track end",
        b"indx" => "index",
        b"rbeg" => "region start",
        b"rend" => "region end",
        b"rsyc" => "region sync point",
        b"sbeg" => "selection start",
        b"send" => "selection end",
        b"cbeg" => "edit source start",
        b"cend" => "edit source end",
        b"dbeg" => "edit destination start",
        b"dend" => "edit destination end",
        b"slbg" => "sustain loop start",
        b"slen" => "sustain loop end",
        b"rlbg" => "release loop start",
        b"rlen" => "release loop end",
        b"sply" => "saved play position",
        b"tmpo" => "tempo",
        b"tsig" => "time signature",
        b"ksig" => "key signature",
        _ => return fourcc(kind),
    };
    name.to_owned()
}

record! {
    pub struct Marker {
        kind: bytes[4] "Type" .with(|b, n| n.value(text(fourcc(b))).summary(marker_type(b))),
        position: f64 "Frame position",
        id: u32 "Marker ID" .desc("String ID of the marker's name in strg"),
        hours: i8 "SMPTE hours",
        minutes: i8 "SMPTE minutes",
        seconds: i8 "SMPTE seconds",
        frames: i8 "SMPTE frames",
        subframe: u32 "SMPTE sub-frame sample offset",
        channel: u32 "Channel" .desc("0 = all channels"),
    }
}

const REGION_FLAGS: FlagTable = &[
    flag(0x1, "LOOP_ENABLE"),
    flag(0x2, "PLAY_FORWARD"),
    flag(0x4, "PLAY_BACKWARD"),
];

/// Regions listed (each holds its own markers).
const MAX_REGIONS: u32 = 4096;

async fn regions(cx: &Cx, data: Span) -> Result<()> {
    let block = cx.block(data.sub(0, 8)).await?;
    let mut f = Fields::emitting(cx, &block, BE);
    f.u32("SMPTE time type").enumeration(SMPTE_TYPE).emit()?;
    let n = f.u32("Regions").emit()?;
    let mut pos = 8u64;
    for _ in 0..n.min(MAX_REGIONS) {
        let h = cx.read_avail(data.sub(pos, 12)).await?;
        if h.len() < 12 {
            break;
        }
        let id = u32_be(&h, 0).unwrap_or(0);
        let markers = u32_be(&h, 8).unwrap_or(0);
        let len = u64::from(markers)
            .saturating_mul(Marker::SIZE)
            .saturating_add(12);
        let span = data.sub(pos, len);
        cx.push(
            Node::new(format!("Region {id}"))
                .span(span)
                .summary(format!("{markers} markers"))
                .lazy(region, span),
        )
        .await;
        pos = pos.saturating_add(len);
    }
    Ok(())
}

async fn region(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span.sub(0, 12)).await?;
    let mut f = Fields::emitting(&cx, &block, BE);
    f.u32("Region ID").emit()?;
    f.u32("Flags").flags(REGION_FLAGS).emit()?;
    f.u32("Markers").emit()?;
    cx.emit(table::<Marker>(
        "Markers",
        span.tail(12),
        BE,
        "Marker",
        Some(|m| format!("{} at frame {}", marker_type(&m.kind), m.position)),
    ));
    Ok(())
}

record! {
    pub struct Instrument {
        base_note: f32 "Base note" .desc("MIDI note number, fractional for detuning"),
        high_note: u8 "MIDI high note",
        low_note: u8 "MIDI low note",
        high_velocity: u8 "MIDI high velocity",
        low_velocity: u8 "MIDI low velocity",
        gain: f32 "Gain (dB)",
        start_region: u32 "Start region ID",
        sustain_region: u32 "Sustain region ID",
        release_region: u32 "Release region ID",
        instrument: u32 "Instrument ID" .desc("String ID of the instrument's name"),
    }
}

record! {
    pub struct Peak {
        value: f32 "Value",
        frame: u64 "Frame position",
    }
}
