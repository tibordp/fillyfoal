//! Amiga IFF forms: 8SVX/16SV sampled voices, ILBM/PBM bitmaps, ANIM
//! animations, SMUS scores and MAUD audio.

use crate::bytes::u16_be;
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::Result;
use crate::fields::{Fields, parse};
use crate::formats::iff::{Chunk, Ctx, find, scan};
use crate::formats::sound::{duration_of, table};
use crate::node::Node;
use crate::record;
use crate::span::Span;
use crate::value::{EnumTable, FlagTable, flag};

const SVX_COMPRESSION: EnumTable = &[
    (0, "none"),
    (1, "Fibonacci delta"),
    (2, "exponential delta"),
];
const MASKING: EnumTable = &[
    (0, "none"),
    (1, "has mask plane"),
    (2, "transparent color"),
    (3, "lasso"),
];
const ILBM_COMPRESSION: EnumTable = &[(0, "none"), (1, "ByteRun1"), (2, "VDAT")];
const CAMG: FlagTable = &[
    flag(0x8000, "HIRES"),
    flag(0x0800, "HAM"),
    flag(0x0080, "EXTRA_HALFBRITE"),
    flag(0x0400, "DUALPF"),
    flag(0x0020, "SUPERHIRES"),
    flag(0x0004, "LACE"),
];
const ANIM_OPERATION: EnumTable = &[
    (0, "set (ILBM BODY)"),
    (1, "XOR"),
    (2, "long delta"),
    (3, "short delta"),
    (4, "generalized short/long delta"),
    (5, "byte vertical delta"),
    (6, "stereo byte delta"),
    (7, "short/long vertical delta"),
    (8, "short/long vertical delta (sets)"),
    (74, "Eric Graham's mode J"),
];
const CHANNEL: EnumTable = &[(2, "left"), (4, "right"), (6, "stereo")];

record! {
    /// Voice8Header
    pub struct VoiceHeader {
        one_shot: u32 "One-shot samples" .desc("Samples in the high octave's one-shot part"),
        repeat: u32 "Repeat samples",
        per_cycle: u32 "Samples per cycle" .desc("Of the high octave, 0 if unknown"),
        rate: u16 "Samples per second",
        octaves: u8 "Octaves",
        compression: u8 "Compression" .enumeration(SVX_COMPRESSION),
        volume: u32 "Volume" .hex() .with(|&v, n| n.summary(format!("{:.3}", f64::from(v) / 65536.0))),
    }
}

record! {
    /// BitMapHeader
    pub struct BitmapHeader {
        width: u16 "Width",
        height: u16 "Height",
        x: i16 "X",
        y: i16 "Y",
        planes: u8 "Planes",
        masking: u8 "Masking" .enumeration(MASKING),
        compression: u8 "Compression" .enumeration(ILBM_COMPRESSION),
        _pad: u8 "Pad",
        transparent: u16 "Transparent color",
        x_aspect: u8 "X aspect",
        y_aspect: u8 "Y aspect",
        page_width: i16 "Page width",
        page_height: i16 "Page height",
    }
}

record! {
    pub struct ColorRange {
        _pad: i16 "Pad",
        rate: i16 "Rate" .desc("16384 = 60 steps per second"),
        flags: i16 "Flags" .hex(),
        low: u8 "Low color",
        high: u8 "High color",
    }
}

record! {
    pub struct Color {
        red: u8 "Red",
        green: u8 "Green",
        blue: u8 "Blue",
    }
}

record! {
    pub struct AnimHeader {
        operation: u8 "Operation" .enumeration(ANIM_OPERATION),
        mask: u8 "Mask" .hex(),
        width: u16 "Width",
        height: u16 "Height",
        x: i16 "X",
        y: i16 "Y",
        abs_time: u32 "Absolute time" .desc("Jiffies from the start"),
        rel_time: u32 "Relative time" .desc("Jiffies since the previous frame"),
        interleave: u8 "Interleave",
        _pad0: u8 "Pad",
        bits: u32 "Bits" .hex(),
        _pad: bytes[16] "Reserved",
    }
}

record! {
    pub struct EnvelopePoint {
        duration: u16 "Duration (ms)",
        destination: u32 "Destination volume" .hex(),
    }
}

record! {
    pub struct ScoreHeader {
        tempo: u16 "Tempo" .desc("Quarter notes per minute × 128"),
        volume: u8 "Volume",
        tracks: u8 "Tracks",
    }
}

record! {
    pub struct MaudHeader {
        samples: u32 "Samples",
        bits: u16 "Bits per sample",
        bits_used: u16 "Bits used",
        clock: u32 "Clock frequency",
        divide: u16 "Clock divider",
        channel_info: u16 "Channel info",
        channels: u16 "Channels",
        compression: u16 "Compression",
        _reserved: bytes[12] "Reserved",
    }
}

pub async fn summary(cx: &Cx, chunk: &Chunk) -> Result<Option<String>> {
    let e = chunk.endian();
    Ok(match &chunk.id {
        b"VHDR" => {
            let h = parse(cx, chunk.data, e, &(), VoiceHeader::layout).await?;
            Some(format!(
                "{} Hz, {} octaves, {} + {} samples",
                h.rate, h.octaves, h.one_shot, h.repeat
            ))
        }
        b"BMHD" => {
            let h = parse(cx, chunk.data, e, &(), BitmapHeader::layout).await?;
            Some(format!("{}×{}, {} planes", h.width, h.height, h.planes))
        }
        b"CMAP" => Some(format!("{} colors", chunk.size / 3)),
        b"ANHD" => {
            let h = parse(cx, chunk.data, e, &(), AnimHeader::layout).await?;
            Some(format!("operation {}, {} jiffies", h.operation, h.rel_time))
        }
        _ => None,
    })
}

pub async fn chunk(cx: &Cx, chunk: &Chunk) -> Result<bool> {
    let e = chunk.endian();
    let data = chunk.data;
    match &chunk.id {
        b"VHDR" => cx.emit(VoiceHeader::node("Voice header", data, e)),
        b"BMHD" => cx.emit(BitmapHeader::node("Bitmap header", data, e)),
        b"CMAP" => cx.emit(table::<Color>(
            "Colors",
            data,
            e,
            "Color",
            Some(|c| format!("#{:02x}{:02x}{:02x}", c.red, c.green, c.blue)),
        )),
        b"CAMG" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e)
                .u32("Viewport mode")
                .flags(CAMG)
                .emit()?;
        }
        b"CRNG" => cx.emit(ColorRange::node("Color range", data, e)),
        b"GRAB" | b"DEST" | b"DPI " => {
            let block = cx.block(data.sub(0, 4)).await?;
            let mut f = Fields::emitting(cx, &block, e);
            f.int::<i16>("X").emit()?;
            f.int::<i16>("Y").emit()?;
        }
        b"ANHD" => cx.emit(AnimHeader::node("Animation header", data, e)),
        b"DLTA" => cx.emit(Node::new("Delta data").span(data)),
        b"ATAK" | b"RLSE" => cx.emit(table::<EnvelopePoint>(
            "Envelope",
            data,
            e,
            "Point",
            Some(|p| format!("{} ms", p.duration)),
        )),
        b"CHAN" => {
            let block = cx.block(data.sub(0, 4)).await?;
            Fields::emitting(cx, &block, e)
                .u32("Channel")
                .enumeration(CHANNEL)
                .emit()?;
        }
        b"SHDR" => cx.emit(ScoreHeader::node("Score header", data, e)),
        b"MHDR" => cx.emit(MaudHeader::node("MAUD header", data, e)),
        b"BODY" | b"MDAT" => {
            let what = match &chunk.ctx.form {
                b"8SVX" | b"16SV" | b"MAUD" => "Samples",
                _ => "Pixel data",
            };
            cx.emit(Node::new(what).span(data));
        }
        _ => return Ok(false),
    }
    Ok(true)
}

pub async fn describe(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let e = ctx.endian;
    Ok(match &ctx.form {
        b"8SVX" | b"16SV" => {
            let Some(vhdr) = find(cx, ctx, region, b"VHDR").await? else {
                return Ok(None);
            };
            let h = parse(cx, vhdr.data, e, &(), VoiceHeader::layout).await?;
            let samples = u64::from(h.one_shot).saturating_add(h.repeat.into());
            let mut line = format!(
                "{}, {} Hz, {} samples",
                if &ctx.form == b"8SVX" { "8SVX" } else { "16SV" },
                h.rate,
                samples
            );
            if let Some(d) = duration_of(samples, h.rate.into()) {
                line.push_str(&format!(", {d}"));
            }
            Some(line)
        }
        b"ILBM" | b"PBM " | b"ACBM" => bitmap(cx, ctx, region).await?,
        b"ANIM" => {
            let forms = scan(cx, ctx, region, 4096).await?;
            let frames = forms.iter().filter(|f| &f.id == b"FORM").count();
            let first = match forms.first() {
                Some(f) if &f.id == b"FORM" => {
                    let inner = Ctx {
                        form: *b"ILBM",
                        ..ctx.clone()
                    };
                    bitmap(cx, &inner, f.data.tail(4)).await?
                }
                _ => None,
            };
            Some(match first {
                Some(f) => format!("ANIM, {frames} frames, first: {f}"),
                None => format!("ANIM, {frames} frames"),
            })
        }
        b"SMUS" => match find(cx, ctx, region, b"SHDR").await? {
            Some(h) => {
                let h = parse(cx, h.data, e, &(), ScoreHeader::layout).await?;
                Some(format!(
                    "SMUS score, {} tracks, {} BPM",
                    h.tracks,
                    h.tempo / 128
                ))
            }
            None => None,
        },
        b"MAUD" => match find(cx, ctx, region, b"MHDR").await? {
            Some(h) => {
                let h = parse(cx, h.data, e, &(), MaudHeader::layout).await?;
                let rate = u64::from(h.clock).checked_div(h.divide.into()).unwrap_or(0);
                Some(format!(
                    "MAUD, {rate} Hz, {} ch, {}-bit",
                    h.channels, h.bits
                ))
            }
            None => None,
        },
        _ => None,
    })
}

async fn bitmap(cx: &Cx, ctx: &Ctx, region: Span) -> Result<Option<String>> {
    let Some(bmhd) = find(cx, ctx, region, b"BMHD").await? else {
        return Ok(None);
    };
    let h = parse(cx, bmhd.data, ctx.endian, &(), BitmapHeader::layout).await?;
    let mut line = format!(
        "{} {}×{}, {} planes",
        crate::formats::sound::fourcc(&ctx.form),
        h.width,
        h.height,
        h.planes
    );
    if let Some(name) = crate::value::lookup(ILBM_COMPRESSION, h.compression.into())
        && h.compression != 0
    {
        line.push_str(&format!(", {name}"));
    }
    if let Some(camg) = find(cx, ctx, region, b"CAMG").await? {
        let mode = cx.read_avail(camg.data.sub(0, 4)).await?;
        let mode = u16_be(&mode, 2).unwrap_or(0);
        if mode & 0x0800 != 0 {
            line.push_str(", HAM");
        }
        if mode & 0x0080 != 0 {
            line.push_str(", EHB");
        }
    }
    Ok(Some(line))
}
