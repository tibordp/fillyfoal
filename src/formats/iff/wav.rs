//! WAVE chunks: `fmt ` (including WAVE_FORMAT_EXTENSIBLE), `fact`, `data`,
//! Broadcast Wave `bext`, `cue `, `smpl`, `inst`, `LIST adtl`, RF64 `ds64`.
//!
//! The `fmt ` layout ([`wave_format`]) is shared with AVI audio streams and
//! DLS wave pools.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Endian, Fields, parse, struct_node};
use crate::formats::iff::{Chunk, Ctx, FourCc, find, scan};
use crate::formats::sound::{channels, duration_of, peek_text, table, text};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, Guid, flag, lookup};

pub const FORMAT_TAG: EnumTable = &[
    (0x0000, "Unknown"),
    (0x0001, "PCM"),
    (0x0002, "Microsoft ADPCM"),
    (0x0003, "IEEE float"),
    (0x0005, "IBM CVSD"),
    (0x0006, "A-law"),
    (0x0007, "µ-law"),
    (0x0010, "OKI ADPCM"),
    (0x0011, "IMA ADPCM"),
    (0x0014, "G.723 ADPCM (Yamaha)"),
    (0x0016, "Antex G.723 ADPCM"),
    (0x0020, "Yamaha ADPCM"),
    (0x0022, "DSP Group TrueSpeech"),
    (0x0031, "GSM 6.10"),
    (0x0040, "G.721 ADPCM"),
    (0x0042, "MSG723"),
    (0x0045, "G.726 ADPCM"),
    (0x0050, "MPEG audio"),
    (0x0055, "MPEG Layer III"),
    (0x0061, "Duck DK4 ADPCM"),
    (0x0062, "Duck DK3 ADPCM"),
    (0x0064, "G.726 ADPCM"),
    (0x0069, "Voxware"),
    (0x0092, "Dolby AC-3 SPDIF"),
    (0x00ff, "AAC"),
    (0x0130, "ACELP.net"),
    (0x0160, "WMA v1"),
    (0x0161, "WMA v2"),
    (0x0162, "WMA Pro"),
    (0x0163, "WMA Lossless"),
    (0x0200, "Creative ADPCM"),
    (0x0270, "Sony ATRAC3"),
    (0x0401, "Intel Music Coder"),
    (0x1600, "MPEG-2 AAC (ADTS)"),
    (0x1602, "MPEG-4 AAC (LATM)"),
    (0x1610, "HE-AAC"),
    (0x2000, "AC-3"),
    (0x2001, "DTS"),
    (0x3313, "AVI AAC"),
    (0x4143, "Divio AAC"),
    (0x566f, "Vorbis"),
    (0x674f, "Ogg Vorbis (mode 1)"),
    (0x6750, "Ogg Vorbis (mode 2)"),
    (0x6751, "Ogg Vorbis (mode 3)"),
    (0x676f, "Ogg Vorbis (mode 1+)"),
    (0x6770, "Ogg Vorbis (mode 2+)"),
    (0x6771, "Ogg Vorbis (mode 3+)"),
    (0x704f, "Opus"),
    (0x706d, "AAC (FAAD)"),
    (0x7361, "AMR-NB"),
    (0x7362, "AMR-WB"),
    (0xa106, "AAC"),
    (0xa109, "Speex"),
    (0xf1ac, "FLAC"),
    (0xfffe, "Extensible"),
];

const SPEAKERS: FlagTable = &[
    flag(0x1, "FRONT_LEFT"),
    flag(0x2, "FRONT_RIGHT"),
    flag(0x4, "FRONT_CENTER"),
    flag(0x8, "LOW_FREQUENCY"),
    flag(0x10, "BACK_LEFT"),
    flag(0x20, "BACK_RIGHT"),
    flag(0x40, "FRONT_LEFT_OF_CENTER"),
    flag(0x80, "FRONT_RIGHT_OF_CENTER"),
    flag(0x100, "BACK_CENTER"),
    flag(0x200, "SIDE_LEFT"),
    flag(0x400, "SIDE_RIGHT"),
    flag(0x800, "TOP_CENTER"),
    flag(0x1000, "TOP_FRONT_LEFT"),
    flag(0x2000, "TOP_FRONT_CENTER"),
    flag(0x4000, "TOP_FRONT_RIGHT"),
    flag(0x8000, "TOP_BACK_LEFT"),
    flag(0x10000, "TOP_BACK_CENTER"),
    flag(0x20000, "TOP_BACK_RIGHT"),
    flag(0x8000_0000, "ALL"),
];

/// A decoded `WAVEFORMATEX`.
#[derive(Clone, Debug, Default)]
pub struct WaveFormat {
    pub tag: u16,
    pub channels: u16,
    pub rate: u32,
    pub avg_bytes: u32,
    pub align: u16,
    pub bits: u16,
    /// The format tag inside WAVE_FORMAT_EXTENSIBLE's subformat GUID.
    pub subformat: Option<u16>,
}

impl WaveFormat {
    /// The effective format tag (the subformat for EXTENSIBLE).
    pub fn codec(&self) -> u16 {
        self.subformat.unwrap_or(self.tag)
    }

    pub fn codec_name(&self) -> String {
        lookup(FORMAT_TAG, self.codec().into())
            .map_or_else(|| format!("format {:#06x}", self.codec()), str::to_owned)
    }

    /// "PCM, 44100 Hz, 2 ch, 16-bit".
    pub fn summary(&self) -> String {
        let mut s = format!(
            "{}, {} Hz, {}",
            self.codec_name(),
            self.rate,
            channels(self.channels)
        );
        if self.bits > 0 {
            s.push_str(&format!(", {}-bit", self.bits));
        }
        s
    }

    /// Playing time of `bytes` of sample data (`samples` from `fact`, if
    /// known, for compressed formats).
    pub fn duration(&self, bytes: u64, samples: Option<u64>) -> Option<String> {
        match (self.codec(), samples) {
            (1 | 3 | 6 | 7, _) | (_, None) => duration_of(bytes, self.avg_bytes.into()),
            (_, Some(n)) => duration_of(n, self.rate.into()),
        }
    }
}

/// The KSDATAFORMAT_SUBTYPE GUIDs are `XXXXXXXX-0000-0010-8000-00aa00389b71`
/// with a format tag in the first field.
fn subformat_tag(g: &Guid) -> Option<u16> {
    (g.data2 == 0 && g.data3 == 0x10 && g.data4 == [0x80, 0, 0, 0xaa, 0, 0x38, 0x9b, 0x71])
        .then(|| u16::try_from(g.data1).ok())
        .flatten()
}

/// `WAVEFORMATEX` / `WAVEFORMATEXTENSIBLE`.
pub fn wave_format(f: &mut Fields<'_>, _: &()) -> Result<WaveFormat> {
    let mut w = WaveFormat {
        tag: f.u16("Format tag").enumeration(FORMAT_TAG).emit()?,
        channels: f.u16("Channels").emit()?,
        rate: f.u32("Sample rate").desc("Samples per second").emit()?,
        avg_bytes: f.u32("Average bytes per second").emit()?,
        align: f.u16("Block align").desc("Bytes per sample frame").emit()?,
        ..WaveFormat::default()
    };
    if f.remaining() >= 2 {
        w.bits = f.u16("Bits per sample").emit()?;
    }
    if f.remaining() >= 2 {
        let extra = f.u16("Extension size").emit()?;
        if w.tag == 0xfffe && extra >= 22 {
            f.u16("Valid bits per sample").emit()?;
            f.u32("Channel mask").flags(SPEAKERS).emit()?;
            let guid = f
                .guid("Subformat")
                .with(|g, n| match subformat_tag(g) {
                    Some(tag) => n.summary(
                        lookup(FORMAT_TAG, tag.into())
                            .map_or_else(|| format!("format {tag:#06x}"), str::to_owned),
                    ),
                    None => n,
                })
                .emit()?;
            w.subformat = subformat_tag(&guid);
            let rest = u64::from(extra).saturating_sub(22).min(f.remaining());
            if rest > 0 {
                f.bytes("Extension data", rest).emit()?;
            }
        } else if extra > 0 {
            let rest = u64::from(extra).min(f.remaining());
            f.bytes("Extension data", rest).emit()?;
        }
    }
    Ok(w)
}

record! {
    /// Broadcast Wave Format extension (EBU Tech 3285).
    pub struct Bext {
        description: ascii[256] "Description",
        originator: ascii[32] "Originator",
        reference: ascii[32] "Originator reference",
        date: ascii[10] "Origination date",
        time: ascii[8] "Origination time",
        time_low: u32 "Time reference (low)" .desc("Sample count since midnight, low 32 bits"),
        time_high: u32 "Time reference (high)",
        version: u16 "Version",
        umid: bytes[64] "UMID" .desc("SMPTE 330M unique material identifier"),
        loudness: i16 "Loudness value" .with(|&v, n| n.summary(centi(v, "LUFS"))),
        range: i16 "Loudness range" .with(|&v, n| n.summary(centi(v, "LU"))),
        true_peak: i16 "Max true peak level" .with(|&v, n| n.summary(centi(v, "dBTP"))),
        momentary: i16 "Max momentary loudness" .with(|&v, n| n.summary(centi(v, "LUFS"))),
        short_term: i16 "Max short-term loudness" .with(|&v, n| n.summary(centi(v, "LUFS"))),
        _reserved: bytes[180] "Reserved",
    }
}

fn centi(v: i16, unit: &str) -> String {
    format!("{:.2} {unit}", f64::from(v) / 100.0)
}

record! {
    pub struct CuePoint {
        id: u32 "Identifier",
        position: u32 "Position" .desc("Sample position in play order"),
        chunk: ascii[4] "Data chunk ID",
        chunk_start: u32 "Chunk start",
        block_start: u32 "Block start",
        offset: u32 "Sample offset",
    }
}

record! {
    pub struct Sampler {
        manufacturer: u32 "Manufacturer" .hex(),
        product: u32 "Product" .hex(),
        period: u32 "Sample period" .desc("Nanoseconds per sample"),
        unity_note: u32 "MIDI unity note",
        pitch_fraction: u32 "MIDI pitch fraction" .hex(),
        smpte_format: u32 "SMPTE format",
        smpte_offset: u32 "SMPTE offset" .hex(),
        loops: u32 "Sample loops",
        sampler_data: u32 "Sampler data size",
    }
}

const LOOP_TYPE: EnumTable = &[(0, "forward"), (1, "alternating"), (2, "backward")];

record! {
    pub struct SampleLoop {
        id: u32 "Cue point ID",
        kind: u32 "Type" .enumeration(LOOP_TYPE),
        start: u32 "Start",
        end: u32 "End",
        fraction: u32 "Fraction" .hex(),
        count: u32 "Play count" .desc("0 = infinite"),
    }
}

record! {
    pub struct Instrument {
        note: u8 "Unshifted note",
        fine_tune: i8 "Fine tune (cents)",
        gain: i8 "Gain (dB)",
        low_note: u8 "Low note",
        high_note: u8 "High note",
        low_velocity: u8 "Low velocity",
        high_velocity: u8 "High velocity",
    }
}

record! {
    pub struct Ds64 {
        riff_size: u64 "RIFF size",
        data_size: u64 "data size",
        samples: u64 "Sample count",
        table: u32 "Table length",
    }
}

record! {
    pub struct Acid {
        flags: u32 "Flags" .hex(),
        root_note: u16 "Root note",
        _unknown1: u16 "Unknown",
        _unknown2: f32 "Unknown",
        beats: u32 "Beats",
        meter_denominator: u16 "Meter denominator",
        meter_numerator: u16 "Meter numerator",
        tempo: f32 "Tempo (BPM)",
    }
}

pub fn describe_id(id: &FourCc) -> Option<&'static str> {
    Some(match id {
        b"fmt " => "Sample format",
        b"data" => "Sample data",
        b"fact" => "Sample count (for compressed formats)",
        b"cue " => "Cue points",
        b"smpl" => "Sampler parameters and loops",
        b"inst" => "Instrument parameters",
        b"bext" => "Broadcast Wave extension",
        b"ds64" => "64-bit sizes (RF64)",
        b"PEAK" => "Peak levels",
        b"cart" => "Broadcast cart chunk",
        b"plst" => "Playlist",
        b"acid" => "ACID loop information",
        b"DISP" => "Clipboard display data",
        b"labl" => "Cue point label",
        b"note" => "Cue point note",
        b"ltxt" => "Labelled text",
        _ => return None,
    })
}

async fn fmt_of(cx: &Cx, chunk: &Chunk) -> Option<WaveFormat> {
    let fmt = find(cx, &chunk.ctx, chunk.parent, b"fmt ").await.ok()??;
    parse(cx, fmt.data, chunk.endian(), &(), wave_format)
        .await
        .ok()
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let e = chunk.endian();
    Ok(match &chunk.id {
        b"fmt " => Some(parse(cx, chunk.data, e, &(), wave_format).await?.summary()),
        b"data" => {
            let mut s = format!("{} bytes", chunk.size);
            if let Some(fmt) = fmt_of(cx, chunk).await
                && let Some(d) = fmt.duration(chunk.size, None)
            {
                s.push_str(&format!(", {d}"));
            }
            Some(s)
        }
        b"fact" => {
            let n = cx.read(chunk.data.sub(0, 4)).await?;
            Some(format!(
                "{} samples",
                crate::bytes::u32_le(&n, 0).unwrap_or(0)
            ))
        }
        b"cue " => Some(format!("{} cue points", chunk.size.saturating_sub(4) / 24)),
        b"bext" => {
            let text = peek_text(cx, chunk.data, 256).await?;
            (!text.is_empty()).then(|| crate::formats::sound::clip(&text, 60))
        }
        b"labl" | b"note" => {
            let text = peek_text(cx, chunk.data.tail(4), 120).await?;
            Some(crate::formats::sound::clip(&text, 60))
        }
        _ => None,
    })
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    match &chunk.id {
        b"fmt " => {
            let block = cx.block(data).await?;
            wave_format(&mut Fields::emitting(cx, &block, e), &())?;
        }
        b"data" => {
            let mut node = Node::new("Samples").span(data);
            if let Some(fmt) = fmt_of(cx, chunk).await {
                let samples = fact_samples(cx, chunk).await;
                if let Some(d) = fmt.duration(chunk.size, samples) {
                    node = node.summary(d);
                }
            }
            cx.emit(node);
        }
        b"fact" => {
            let block = cx.block(data).await?;
            Fields::emitting(cx, &block, e)
                .u32("Sample length")
                .desc("Samples per channel")
                .emit()?;
        }
        b"ds64" => {
            cx.emit(Ds64::node("ds64", data.sub(0, Ds64::SIZE), e));
            let rest = data.tail(Ds64::SIZE);
            if !rest.is_empty() {
                cx.emit(Node::new("Size table").span(rest));
            }
        }
        b"bext" => {
            cx.emit(Bext::node(
                "Broadcast extension",
                data.sub(0, Bext::SIZE),
                e,
            ));
            let history = data.tail(Bext::SIZE);
            if !history.is_empty() {
                let t = peek_text(cx, history, history.len.min(1 << 16)).await?;
                cx.emit(Node::new("Coding history").span(history).value(text(t)));
            }
        }
        b"cue " => {
            let block = cx.block(data.sub(0, 4)).await?;
            let count = Fields::emitting(cx, &block, e).u32("Cue points").emit()?;
            let points = data.sub(4, u64::from(count).saturating_mul(CuePoint::SIZE));
            cx.emit(table::<CuePoint>(
                "Points",
                points,
                e,
                "Cue",
                Some(|c| format!("#{} at sample {}", c.id, c.position)),
            ));
        }
        b"smpl" => {
            cx.emit(Sampler::node("Sampler", data.sub(0, Sampler::SIZE), e));
            let loops = data.tail(Sampler::SIZE);
            if !loops.is_empty() {
                cx.emit(table::<SampleLoop>(
                    "Loops",
                    loops,
                    e,
                    "Loop",
                    Some(|l| format!("{}..{}", l.start, l.end)),
                ));
            }
        }
        b"inst" => cx.emit(Instrument::node("Instrument", data, e)),
        b"acid" => cx.emit(Acid::node("ACID", data, e)),
        b"labl" | b"note" => {
            let block = cx.block(data).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Cue point ID").emit()?;
            let t = peek_text(cx, data.tail(4), data.len).await?;
            cx.emit(Node::new("Text").span(data.tail(4)).value(text(t)));
        }
        b"ltxt" => {
            let block = cx.block(data.sub(0, 20)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Cue point ID").emit()?;
            f.u32("Sample length").emit()?;
            f.ascii("Purpose", 4).emit()?;
            f.u16("Country").emit()?;
            f.u16("Language").emit()?;
            f.u16("Dialect").emit()?;
            f.u16("Code page").emit()?;
            let rest = data.tail(20);
            if !rest.is_empty() {
                let t = peek_text(cx, rest, rest.len).await?;
                cx.emit(Node::new("Text").span(rest).value(text(t)));
            }
        }
        b"PEAK" => {
            let block = cx.block(data).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.u32("Version").emit()?;
            f.u32("Timestamp").timestamp().emit()?;
            let mut i = 0u32;
            while f.remaining() >= 8 {
                cx.checkpoint().await;
                f.f32("Peak value").summary(format!("channel {i}")).emit()?;
                f.u32("Peak position").emit()?;
                i = i.saturating_add(1);
            }
        }
        _ => return Ok(false),
    }
    Ok(true)
}

async fn fact_samples(cx: &Cx, chunk: &Chunk) -> Option<u64> {
    let fact = find(cx, &chunk.ctx, chunk.parent, b"fact").await.ok()??;
    let n = cx.read(fact.data.sub(0, 4)).await.ok()?;
    let n = match chunk.endian() {
        Endian::Little => crate::bytes::u32_le(&n, 0),
        Endian::Big => crate::bytes::u32_be(&n, 0),
    };
    n.map(u64::from)
}

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let chunks = scan(cx, ctx, region, 64).await?;
    let Some(fmt) = chunks.iter().find(|c| &c.id == b"fmt ") else {
        return Ok(None);
    };
    let fmt = parse(cx, fmt.data, ctx.endian, &(), wave_format).await?;
    let mut line = fmt.summary();
    let samples = match chunks.iter().find(|c| &c.id == b"fact") {
        Some(fact) => {
            let n = cx.read_avail(fact.data.sub(0, 4)).await?;
            crate::bytes::u32_le(&n, 0).map(u64::from)
        }
        None => None,
    };
    if let Some(data) = chunks.iter().find(|c| &c.id == b"data")
        && let Some(d) = fmt.duration(data.size, samples)
    {
        line.push_str(&format!(", {d}"));
    }
    if !ctx.sizes.is_empty() {
        line = format!("RF64 {line}");
    }
    Ok(Some(line))
}

/// A lazy node for a `WAVEFORMATEX` at `span` (used by AVI and DLS).
pub fn format_node(name: &'static str, span: Span, endian: Endian) -> Node {
    struct_node(name, span, endian, (), wave_format)
}
