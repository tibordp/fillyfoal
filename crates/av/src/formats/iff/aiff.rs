//! AIFF and AIFF-C chunks: `COMM` (with its 80-bit extended sample rate
//! and AIFF-C compression type), `SSND`, `MARK`, `INST`, `COMT`, `FVER`,
//! `APPL`, `CHAN` (Core Audio channel layout), `AESD`, `MIDI`. The text
//! chunks (`NAME`, `AUTH`, `(c) `, `ANNO`), `ID3 ` and `FLLR` padding are
//! handled by the IFF walker.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Fields, parse};
use crate::formats::audio::midi::note_name;
use crate::formats::iff::{Chunk, Ctx, FourCc, find};
use crate::formats::util::sound::{channels, duration, f80_be, fourcc, hz};
use crate::formats::util::val::text;
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

/// AIFF-C compression types (Apple's and those other writers use).
const COMPRESSION: &[(&FourCc, &str)] = &[
    (b"NONE", "PCM"),
    (b"twos", "PCM (big-endian)"),
    (b"sowt", "PCM (little-endian)"),
    (b"raw ", "PCM (unsigned)"),
    (b"in24", "24-bit PCM"),
    (b"42ni", "24-bit PCM (little-endian)"),
    (b"in32", "32-bit PCM"),
    (b"23ni", "32-bit PCM (little-endian)"),
    (b"fl32", "32-bit float"),
    (b"FL32", "32-bit float"),
    (b"fl64", "64-bit float"),
    (b"FL64", "64-bit float"),
    (b"alaw", "A-law"),
    (b"ALAW", "A-law"),
    (b"ulaw", "µ-law"),
    (b"ULAW", "µ-law"),
    (b"ima4", "IMA 4:1 ADPCM"),
    (b"ADP4", "Intel/DVI ADPCM"),
    (b"MAC3", "MACE 3:1"),
    (b"MAC6", "MACE 6:1"),
    (b"ACE2", "ACE 2:1"),
    (b"ACE8", "ACE 8:3"),
    (b"GSM ", "GSM 6.10"),
    (b"G722", "G.722"),
    (b"G726", "G.726"),
    (b"G728", "G.728"),
    (b"DWVW", "Delta with variable word width"),
    (b"Qclp", "Qualcomm PureVoice"),
    (b"QDMC", "QDesign Music"),
    (b"QDM2", "QDesign Music 2"),
    (b"sdx2", "SDX2 (3DO)"),
    (b"SDX2", "SDX2 (3DO)"),
    (b"cdx2", "CDX2 (3DO)"),
    (b"cdx4", "CDX4 (3DO)"),
    (b"rt24", "VoxWare RT24"),
    (b"rt29", "VoxWare RT29"),
    (b"alac", "Apple Lossless"),
];

fn compression(kind: &[u8]) -> Option<&'static str> {
    COMPRESSION
        .iter()
        .find(|(k, _)| k.as_slice() == kind)
        .map(|(_, n)| *n)
}

/// Sample frames per packet of the block-based codecs: their `COMM` frame
/// count counts packets (as Apple and FFmpeg read them).
fn frames_per_packet(kind: &[u8]) -> u32 {
    match kind {
        b"ima4" => 64,
        b"MAC3" | b"MAC6" => 6,
        b"GSM " => 160,
        _ => 1,
    }
}

const PLAY_MODE: EnumTable = &[(0, "no looping"), (1, "forward"), (2, "forward/backward")];

/// The `COMM` chunk.
#[derive(Clone, Debug, Default)]
pub struct Common {
    pub channels: i16,
    pub frames: u32,
    pub bits: i16,
    pub rate: f64,
    pub compression: Option<(Vec<u8>, String)>,
}

impl Common {
    fn kind(&self) -> &[u8] {
        self.compression
            .as_ref()
            .map_or(b"NONE".as_slice(), |(k, _)| k.as_slice())
    }

    fn codec(&self) -> String {
        match &self.compression {
            None => "PCM".to_owned(),
            Some((kind, name)) => compression(kind).map_or_else(
                || {
                    if name.is_empty() {
                        fourcc(kind)
                    } else {
                        name.clone()
                    }
                },
                str::to_owned,
            ),
        }
    }

    /// "PCM 16-bit", "PCM 16-bit little-endian", "IMA 4:1 ADPCM".
    fn format(&self) -> String {
        let pcm = match self.kind() {
            b"NONE" | b"twos" | b"in24" | b"in32" => Some(""),
            b"sowt" | b"42ni" | b"23ni" => Some(" little-endian"),
            b"raw " => Some(" unsigned"),
            _ => None,
        };
        match pcm {
            Some(suffix) if self.bits > 0 => format!("PCM {}-bit{suffix}", self.bits),
            _ => self.codec(),
        }
    }

    fn rate_text(&self) -> String {
        if self.rate.fract() == 0.0 && self.rate > 0.0 && self.rate < 4e9 {
            crate::formats::util::vidutil::khz(self.rate as u64)
        } else {
            hz(self.rate)
        }
    }

    /// Sample frames (packets times frames per packet).
    fn sample_frames(&self) -> u64 {
        u64::from(self.frames).saturating_mul(frames_per_packet(self.kind()).into())
    }

    /// "PCM 16-bit, 44.1 kHz, stereo, 3:25".
    fn summary(&self) -> String {
        let layout = match self.channels.unsigned_abs() {
            1 => "mono".to_owned(),
            2 => "stereo".to_owned(),
            n => channels(u64::from(n)),
        };
        let mut s = format!("{}, {}, {layout}", self.format(), self.rate_text());
        if self.rate > 0.0 {
            s.push_str(&format!(
                ", {}",
                duration(self.sample_frames() as f64 / self.rate)
            ));
        }
        s
    }
}

/// A Pascal string (count byte, text, pad to an even total).
fn pstring(f: &mut Fields<'_>, name: &'static str) -> Result<String> {
    let at = f.peek_span(1);
    let len = f.u8(name).get()?;
    let total = u64::from(len).saturating_add(1);
    let value = crate::text::latin1(&f.bytes(name, len.into()).get()?);
    f.node(
        Node::new(name)
            .span(Span::new(at.source, at.offset, total))
            .value(text(value.clone())),
    );
    if total % 2 == 1 {
        f.skip(1);
    }
    Ok(value)
}

fn comm(f: &mut Fields<'_>, aifc: &bool) -> Result<Common> {
    let mut c = Common {
        channels: f.int::<i16>("Channels").emit()?,
        frames: f
            .u32("Sample frames")
            .desc("Samples per channel (packets, for block-based codecs)")
            .emit()?,
        bits: f
            .int::<i16>("Sample size")
            .desc("Bits per sample (of the decoded audio, for compressed types)")
            .emit()?,
        ..Common::default()
    };
    c.rate = f
        .bytes("Sample rate", 10)
        .map(|b| f80_be(&b).unwrap_or(0.0))
        .with(|&r, n| {
            n.value(Value::Float(r))
                .desc("80-bit IEEE 754 extended precision")
        })
        .emit()?;
    if *aifc && f.remaining() >= 4 {
        let kind = f
            .bytes("Compression type", 4)
            .with(|b, n| {
                let n = n.value(text(fourcc(b)));
                match compression(b) {
                    Some(name) => n.summary(name),
                    None => n,
                }
            })
            .emit()?;
        let name = if f.remaining() >= 1 {
            pstring(f, "Compression name")?
        } else {
            String::new()
        };
        c.compression = Some((kind, name));
    }
    Ok(c)
}

fn note(v: i8) -> String {
    u8::try_from(v).map_or_else(|_| "?".to_owned(), note_name)
}

record! {
    pub struct Instrument {
        base_note: i8 "Base note" .with(|&v, n| n.summary(note(v))),
        detune: i8 "Detune (cents)",
        low_note: i8 "Low note" .with(|&v, n| n.summary(note(v))),
        high_note: i8 "High note" .with(|&v, n| n.summary(note(v))),
        low_velocity: i8 "Low velocity",
        high_velocity: i8 "High velocity",
        gain: i16 "Gain (dB)",
        sustain_mode: i16 "Sustain loop play mode" .enumeration(PLAY_MODE),
        sustain_begin: i16 "Sustain loop begin marker" .desc("Marker ID"),
        sustain_end: i16 "Sustain loop end marker" .desc("Marker ID"),
        release_mode: i16 "Release loop play mode" .enumeration(PLAY_MODE),
        release_begin: i16 "Release loop begin marker" .desc("Marker ID"),
        release_end: i16 "Release loop end marker" .desc("Marker ID"),
    }
}

record! {
    /// AES3 channel status (the `AESD` chunk).
    pub struct Aesd {
        status: bytes[24] "Channel status" .desc("AES3 channel status bytes 0-23"),
    }
}

pub fn describe_id(id: &FourCc) -> Option<&'static str> {
    Some(match id {
        b"COMM" => "Common: channels, frames, sample size and rate",
        b"SSND" => "Sound data",
        b"MARK" => "Markers",
        b"INST" => "Instrument",
        b"COMT" => "Comments",
        b"FVER" => "Format version (AIFF-C)",
        b"APPL" => "Application-specific data",
        b"MIDI" => "MIDI data",
        b"AESD" => "AES channel status",
        b"CHAN" => "Channel layout (Core Audio)",
        b"FLLR" => "Filler, ignored",
        b"ID3 " | b"ID32" => "ID3 tag",
        _ => return None,
    })
}

fn is_aifc(chunk_ctx: &Ctx) -> bool {
    &chunk_ctx.form == b"AIFC"
}

async fn common_of(cx: &Cx, ctx: &Ctx, region: Span) -> Option<Common> {
    let comm_chunk = find(cx, ctx, region, b"COMM").await.ok()??;
    parse(cx, comm_chunk.data, ctx.endian, &is_aifc(ctx), comm)
        .await
        .ok()
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let data = chunk.data;
    Ok(match &chunk.id {
        b"COMM" => Some(
            parse(cx, data, chunk.endian(), &is_aifc(&chunk.ctx), comm)
                .await?
                .summary(),
        ),
        b"SSND" => Some(format!("{} bytes", chunk.size)),
        b"MARK" => {
            let n = cx.read(data.sub(0, 2)).await?;
            Some(format!(
                "{} markers",
                crate::bytes::u16_be(&n, 0).unwrap_or(0)
            ))
        }
        b"COMT" => {
            let n = cx.read(data.sub(0, 2)).await?;
            Some(format!(
                "{} comments",
                crate::bytes::u16_be(&n, 0).unwrap_or(0)
            ))
        }
        b"CHAN" => {
            let t = cx.read(data.sub(0, 4)).await?;
            Some(crate::formats::audio::caf::layout_name(
                crate::bytes::u32_be(&t, 0).unwrap_or(0),
            ))
        }
        b"APPL" => Some(fourcc(&cx.read_avail(data.sub(0, 4)).await?)),
        b"FVER" => {
            let b = cx.read(data.sub(0, 4)).await?;
            match crate::bytes::u32_be(&b, 0) {
                Some(0xa280_5140) => Some("AIFF-C version 1".to_owned()),
                _ => None,
            }
        }
        b"INST" => {
            let b = cx.read(data.sub(0, 4)).await?;
            let get = |i: usize| b.get(i).copied().unwrap_or(0) as i8;
            Some(format!(
                "base note {}, keys {}–{}",
                note(get(0)),
                note(get(2)),
                note(get(3))
            ))
        }
        _ => None,
    })
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    match &chunk.id {
        b"COMM" => {
            let block = cx.block(data).await?;
            comm(&mut Fields::emitting(cx, &block, e), &is_aifc(&chunk.ctx))?;
        }
        b"SSND" => {
            let block = cx.block(data.sub(0, 8)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            let offset = f
                .u32("Offset")
                .desc("Bytes to skip before the first sample frame")
                .emit()?;
            f.u32("Block size")
                .desc("Alignment block size; usually 0")
                .emit()?;
            let skip = data.sub(8, offset.into());
            if !skip.is_empty() {
                cx.emit(Node::new("Alignment").span(skip));
            }
            let samples = data.tail(u64::from(offset).saturating_add(8));
            let mut node = Node::new("Samples").span(samples);
            if let Some(c) = common_of(cx, &chunk.ctx, chunk.parent).await {
                node = node.summary(c.summary());
            }
            cx.emit(node);
        }
        b"MARK" => {
            let rate = common_of(cx, &chunk.ctx, chunk.parent)
                .await
                .map_or(0.0, |c| c.rate);
            let block = cx.block(data).await?;
            let mut f = Fields::emitting(cx, &block, e);
            let count = f.u16("Markers").emit()?;
            let mut quiet = Fields::new(&block, e);
            quiet.seek(2);
            for _ in 0..count {
                if quiet.remaining() < 7 {
                    break;
                }
                let start = quiet.pos();
                let id = quiet.int::<i16>("ID").get()?;
                let position = quiet.u32("Position").get()?;
                let name = pstring(&mut quiet, "Name")?;
                let span = data.sub(start, quiet.pos().saturating_sub(start));
                let mut summary = format!("frame {position}");
                if rate > 0.0 {
                    summary.push_str(&format!(" ({})", duration(f64::from(position) / rate)));
                }
                cx.push(
                    Node::new(format!("Marker {id}"))
                        .span(span)
                        .value(text(name))
                        .summary(summary)
                        .lazy(marker, span),
                )
                .await;
            }
        }
        b"INST" => {
            crate::dsl::emit_record::<Instrument>(cx, data.sub(0, Instrument::SIZE), e).await?;
        }
        b"COMT" => {
            let block = cx.block(data).await?;
            let mut f = Fields::new(&block, e);
            let count = f.u16("Comments").get()?;
            for i in 0..count {
                if f.remaining() < 8 {
                    break;
                }
                let start = f.pos();
                f.u32("Timestamp").get()?;
                let marker = f.int::<i16>("Marker").get()?;
                let len = f.u16("Count").get()?;
                let body = f.bytes("Text", len.into()).get()?;
                if len % 2 == 1 {
                    f.skip(1);
                }
                let span = data.sub(start, f.pos().saturating_sub(start));
                let node = Node::new(format!("Comment {i}"))
                    .span(span)
                    .value(text(crate::text::latin1(&body)));
                let node = if marker != 0 {
                    node.summary(format!("marker {marker}"))
                } else {
                    node
                };
                cx.push(node.lazy(comment, span)).await;
            }
        }
        b"FVER" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e)
                .u32("Timestamp")
                .mac_time()
                .desc("0xa2805140 = AIFF-C version 1")
                .emit()?;
        }
        b"APPL" => {
            let block = cx.block(data.sub(0, data.len.min(260))).await?;
            let mut f = Fields::emitting(cx, &block, e);
            let sig = f
                .bytes("Signature", 4)
                .with(|b, n| n.value(text(fourcc(b))))
                .desc("Application OSType")
                .emit()?;
            if sig == b"stoc" && f.remaining() >= 1 {
                pstring(&mut f, "Application name")?;
            }
            let at = f.pos();
            if at < data.len {
                cx.emit(Node::new("Data").span(data.tail(at)));
            }
        }
        b"CHAN" => crate::formats::audio::caf::channel_layout(cx, data, e).await?,
        b"AESD" => {
            crate::dsl::emit_record::<Aesd>(cx, data.sub(0, Aesd::SIZE), e).await?;
        }
        b"MIDI" => cx.emit(
            Node::new("MIDI data")
                .span(data)
                .desc("MIDI messages for the sampler, as sent on the wire"),
        ),
        _ => return Ok(false),
    }
    Ok(true)
}

async fn marker(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, crate::fields::Endian::Big);
    f.int::<i16>("ID").emit()?;
    f.u32("Position").desc("Sample frame").emit()?;
    pstring(&mut f, "Name")?;
    Ok(())
}

async fn comment(cx: Cx, span: Span) -> Result<()> {
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(&cx, &block, crate::fields::Endian::Big);
    f.u32("Timestamp").mac_time().emit()?;
    f.int::<i16>("Marker")
        .desc("0 = not attached to a marker")
        .emit()?;
    let len = f.u16("Count").emit()?;
    crate::formats::util::sound::latin1_field(&mut f, "Text", len.into()).emit()?;
    Ok(())
}

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    Ok(common_of(cx, ctx, region).await.map(|c| {
        let kind = if is_aifc(ctx) { "AIFF-C" } else { "AIFF" };
        format!("{kind} {}", c.summary())
    }))
}
