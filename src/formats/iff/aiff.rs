//! AIFF and AIFF-C chunks: `COMM` (with its 80-bit extended sample rate
//! and AIFF-C compression type), `SSND`, `MARK`, `INST`, `COMT`, `FVER`,
//! `APPL`.

use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Fields, parse};
use crate::formats::iff::{Chunk, Ctx, FourCc, find};
use crate::formats::sound::{channels, duration, f80_be, fourcc, hz, text};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, Value};

const COMPRESSION: &[(&FourCc, &str)] = &[
    (b"NONE", "PCM"),
    (b"twos", "PCM (big-endian)"),
    (b"sowt", "PCM (little-endian)"),
    (b"raw ", "PCM (unsigned)"),
    (b"in24", "24-bit PCM"),
    (b"in32", "32-bit PCM"),
    (b"fl32", "32-bit float"),
    (b"FL32", "32-bit float"),
    (b"fl64", "64-bit float"),
    (b"FL64", "64-bit float"),
    (b"alaw", "A-law"),
    (b"ALAW", "A-law"),
    (b"ulaw", "µ-law"),
    (b"ULAW", "µ-law"),
    (b"ima4", "IMA 4:1 ADPCM"),
    (b"MAC3", "MACE 3:1"),
    (b"MAC6", "MACE 6:1"),
    (b"GSM ", "GSM 6.10"),
    (b"Qclp", "Qualcomm PureVoice"),
    (b"QDMC", "QDesign Music"),
    (b"QDM2", "QDesign Music 2"),
    (b"sdx2", "SDX2 (3DO)"),
];

fn compression(kind: &[u8]) -> Option<&'static str> {
    COMPRESSION
        .iter()
        .find(|(k, _)| k.as_slice() == kind)
        .map(|(_, n)| *n)
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

    fn summary(&self) -> String {
        let mut s = format!(
            "{}, {}, {}",
            self.codec(),
            hz(self.rate),
            channels(u64::from(self.channels.unsigned_abs()))
        );
        if self.bits > 0 {
            s.push_str(&format!(", {}-bit", self.bits));
        }
        if self.rate > 0.0 {
            s.push_str(&format!(", {}", duration(f64::from(self.frames) / self.rate)));
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
            .desc("Samples per channel")
            .emit()?,
        bits: f.int::<i16>("Sample size").desc("Bits per sample").emit()?,
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

record! {
    pub struct Instrument {
        base_note: i8 "Base note",
        detune: i8 "Detune (cents)",
        low_note: i8 "Low note",
        high_note: i8 "High note",
        low_velocity: i8 "Low velocity",
        high_velocity: i8 "High velocity",
        gain: i16 "Gain (dB)",
        sustain_mode: i16 "Sustain loop play mode" .enumeration(PLAY_MODE),
        sustain_begin: i16 "Sustain loop begin marker",
        sustain_end: i16 "Sustain loop end marker",
        release_mode: i16 "Release loop play mode" .enumeration(PLAY_MODE),
        release_begin: i16 "Release loop begin marker",
        release_end: i16 "Release loop end marker",
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
        b"ID3 " => "ID3 tag",
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
    Ok(match &chunk.id {
        b"COMM" => Some(
            parse(cx, chunk.data, chunk.endian(), &is_aifc(&chunk.ctx), comm)
                .await?
                .summary(),
        ),
        b"SSND" => Some(format!("{} bytes", chunk.size)),
        b"MARK" => {
            let n = cx.read(chunk.data.sub(0, 2)).await?;
            Some(format!(
                "{} markers",
                crate::bytes::u16_be(&n, 0).unwrap_or(0)
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
            f.u32("Block size").emit()?;
            let samples = data.tail(u64::from(offset).saturating_add(8));
            let mut node = Node::new("Samples").span(samples);
            if let Some(c) = common_of(cx, &chunk.ctx, chunk.parent).await {
                node = node.summary(c.summary());
            }
            cx.emit(node);
        }
        b"MARK" => {
            let block = cx.block(data).await?;
            let mut f = Fields::emitting(cx, &block, e);
            let count = f.u16("Markers").emit()?;
            let mut quiet = Fields::new(&block, e);
            quiet.seek(2);
            for _ in 0..count {
                cx.checkpoint().await;
                let start = quiet.pos();
                let id = quiet.int::<i16>("ID").get()?;
                let position = quiet.u32("Position").get()?;
                let name = pstring(&mut quiet, "Name")?;
                let span = data.sub(start, quiet.pos().saturating_sub(start));
                cx.emit(
                    Node::new(format!("Marker {id}"))
                        .span(span)
                        .value(text(name))
                        .summary(format!("frame {position}"))
                        .lazy(marker, span),
                );
            }
        }
        b"INST" => cx.emit(Instrument::node("Instrument", data.sub(0, Instrument::SIZE), e)),
        b"COMT" => {
            let block = cx.block(data).await?;
            let mut f = Fields::new(&block, e);
            let count = f.u16("Comments").get()?;
            for i in 0..count {
                cx.checkpoint().await;
                let start = f.pos();
                f.u32("Timestamp").get()?;
                let marker = f.int::<i16>("Marker").get()?;
                let len = f.u16("Count").get()?;
                let body = f.bytes("Text", len.into()).get()?;
                if len % 2 == 1 {
                    f.skip(1);
                }
                let span = data.sub(start, f.pos().saturating_sub(start));
                cx.emit(
                    Node::new(format!("Comment {i}"))
                        .span(span)
                        .value(text(crate::text::latin1(&body)))
                        .summary(format!("marker {marker}"))
                        .lazy(comment, span),
                );
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
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e)
                .ascii("Signature", 4)
                .emit()?;
            cx.emit(Node::new("Data").span(data.tail(4)));
        }
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
    f.int::<i16>("Marker").emit()?;
    let len = f.u16("Count").emit()?;
    crate::formats::sound::latin1_field(&mut f, "Text", len.into()).emit()?;
    Ok(())
}

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    Ok(common_of(cx, ctx, region).await.map(|c| {
        let kind = if is_aifc(ctx) { "AIFF-C" } else { "AIFF" };
        format!("{kind} {}", c.summary())
    }))
}
