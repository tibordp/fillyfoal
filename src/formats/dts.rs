//! DTS Coherent Acoustics core streams (big-endian 16-bit, sync word
//! `7FFE8001`): each frame header gives its size, block count, channel
//! arrangement, sample rate and bit rate.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::sound::{Bits, FrameSyntax, count_frames, duration, frames_node};
use crate::formats::{Format, Input, Probe};
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "dts",
    title: "DTS audio",
    extensions: &["dts", "cpt"],
    mime: "audio/vnd.dts",
    probe: Probe::Custom(|h| {
        parse(h.data).is_some_and(|(len, _)| match h.data.get(to_usize(len)..) {
            Some(next) if next.len() >= 4 => next.starts_with(&[0x7f, 0xfe, 0x80, 0x01]),
            _ => true,
        })
    }),
    dissect: crate::expander!(dissect: Input),
};

const RATES: [u32; 16] = [
    0, 8000, 16000, 32000, 0, 0, 11025, 22050, 44100, 0, 0, 12000, 24000, 48000, 0, 0,
];

const BITRATES: [u32; 29] = [
    32, 56, 64, 96, 112, 128, 192, 224, 256, 320, 384, 448, 512, 576, 640, 768, 960, 1024, 1152,
    1280, 1344, 1408, 1411, 1472, 1536, 1920, 2048, 3072, 3840,
];

const AMODE: EnumTable = &[
    (0, "mono"),
    (1, "dual mono"),
    (2, "stereo"),
    (3, "stereo (sum/difference)"),
    (4, "stereo (total)"),
    (5, "3/0"),
    (6, "2/1"),
    (7, "3/1"),
    (8, "2/2"),
    (9, "3/2"),
    (10, "2/2/2"),
    (11, "2/2/2/2"),
    (12, "3/2/2"),
    (13, "3/2/1/2"),
    (14, "3/2/2/2"),
    (15, "3/3/2/2"),
];

const LFE: EnumTable = &[
    (0, "none"),
    (1, "128 interpolation"),
    (2, "64 interpolation"),
    (3, "invalid"),
];

/// The header fields the summary needs.
fn fields(d: &[u8]) -> Option<(u64, u64, u64, u64, u64, u64)> {
    if d.get(..4)? != [0x7f, 0xfe, 0x80, 0x01] {
        return None;
    }
    let w = crate::bytes::u64_be(d, 4)?;
    let bits = |start: u32, n: u32| {
        (w >> (64u32.saturating_sub(start).saturating_sub(n))) & (1u64 << n).saturating_sub(1)
    };
    let nblks = bits(7, 7);
    let fsize = bits(14, 14);
    let amode = bits(28, 6);
    let sfreq = bits(34, 4);
    let rate = bits(38, 5);
    let lff = bits(53, 2);
    Some((nblks, fsize, amode, sfreq, rate, lff))
}

fn parse(d: &[u8]) -> Option<(u64, String)> {
    let (nblks, fsize, amode, sfreq, rate, lff) = fields(d)?;
    if fsize < 95 || nblks < 5 {
        return None;
    }
    let hz = *RATES.get(to_usize(sfreq))?;
    if hz == 0 {
        return None;
    }
    let kbps = BITRATES
        .get(to_usize(rate))
        .map_or_else(|| "open".to_owned(), |k| format!("{k} kbps"));
    let lfe = if lff == 1 || lff == 2 { " + LFE" } else { "" };
    Some((
        fsize.saturating_add(1),
        format!(
            "DTS, {kbps}, {hz} Hz, {}{lfe}",
            crate::value::lookup(AMODE, amode).unwrap_or("custom")
        ),
    ))
}

fn header(_: &[u8]) -> u64 {
    11
}

fn layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync word", 32).hex().emit()?;
    b.field("Frame type", 1)
        .with(|v, n| n.summary(if v == 1 { "normal" } else { "termination" }))
        .emit()?;
    b.field("Deficit sample count", 5).emit()?;
    b.field("CRC present", 1).flag().emit()?;
    b.field("PCM sample blocks − 1", 7)
        .with(|v, n| {
            n.summary(format!(
                "{} samples",
                v.saturating_add(1).saturating_mul(32)
            ))
        })
        .emit()?;
    b.field("Frame size − 1", 14).emit()?;
    b.field("Channel arrangement", 6)
        .enumeration(AMODE)
        .emit()?;
    b.field("Sample rate", 4)
        .with(|v, n| match RATES.get(to_usize(v)) {
            Some(&r) if r > 0 => n.summary(format!("{r} Hz")),
            _ => n,
        })
        .emit()?;
    b.field("Bit rate", 5)
        .with(|v, n| match BITRATES.get(to_usize(v)) {
            Some(k) => n.summary(format!("{k} kbps")),
            None => n.summary("open, variable or lossless"),
        })
        .emit()?;
    b.field("Reserved", 1).emit()?;
    b.field("Dynamic range", 1).flag().emit()?;
    b.field("Time stamp", 1).flag().emit()?;
    b.field("Auxiliary data", 1).flag().emit()?;
    b.field("HDCD", 1).flag().emit()?;
    b.field("Extension audio ID", 3).emit()?;
    b.field("Extension audio", 1).flag().emit()?;
    b.field("Audio sync word insertion", 1).flag().emit()?;
    b.field("LFE", 2).enumeration(LFE).emit()?;
    b.field("Predictor history", 1).flag().emit()?;
    Ok(())
}

static SYNTAX: FrameSyntax = FrameSyntax {
    peek: 16,
    parse,
    header,
    layout,
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let window = cx.read_avail(file.sub(0, 0x10000)).await?;
    if let (Some((_, describe)), Some((nblks, _, _, sfreq, _, _))) =
        (parse(&window), fields(&window))
    {
        let (count, covered) = count_frames(&window, &SYNTAX);
        let frames = if covered == to_u64(window.len()) || covered == 0 {
            count as f64
        } else {
            count as f64 * file.len as f64 / covered as f64
        };
        let rate = RATES.get(to_usize(sfreq)).copied().unwrap_or(0);
        let samples = nblks.saturating_add(1).saturating_mul(32) as f64;
        let seconds = if rate > 0 {
            frames * samples / f64::from(rate)
        } else {
            0.0
        };
        cx.annotate(format!("{describe}, {}", duration(seconds)));
    }
    cx.emit(frames_node(file, &SYNTAX));
    Ok(())
}
