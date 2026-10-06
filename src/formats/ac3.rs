//! Dolby AC-3 and E-AC-3 elementary streams: sync frames starting with
//! `0B 77`, each self-describing its size, sample rate and channel mode.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::Result;
use crate::formats::sound::{Bits, FrameSyntax, count_frames, duration, frames_node};
use crate::formats::{Format, Head, Input, Probe};
use crate::value::EnumTable;

pub static FORMAT: Format = Format {
    name: "ac3",
    title: "Dolby Digital (AC-3, E-AC-3)",
    extensions: &["ac3", "eac3", "ec3"],
    mime: "audio/ac3",
    probe: Probe::Custom(probe),
    dissect: crate::expander!(dissect: Input),
};

fn probe(h: &Head<'_>) -> bool {
    match parse(h.data) {
        Some((len, _)) => match h.data.get(to_usize(len)..) {
            Some(next) if next.len() >= 8 => parse(next).is_some(),
            _ => true,
        },
        None => false,
    }
}

/// AC-3 frame sizes in 16-bit words at 44.1 kHz, by frame size code.
const WORDS_44K: [u16; 38] = [
    69, 70, 87, 88, 104, 105, 121, 122, 139, 140, 174, 175, 208, 209, 243, 244, 278, 279, 348, 349,
    417, 418, 487, 488, 557, 558, 696, 697, 835, 836, 975, 976, 1114, 1115, 1253, 1254, 1393, 1394,
];
const BITRATES: [u16; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];

const ACMOD: EnumTable = &[
    (0, "1+1 (dual mono)"),
    (1, "1/0 (mono)"),
    (2, "2/0 (stereo)"),
    (3, "3/0"),
    (4, "2/1"),
    (5, "3/1"),
    (6, "2/2"),
    (7, "3/2"),
];
const CHANNELS: [u8; 8] = [2, 1, 2, 3, 3, 4, 4, 5];
const BSMOD: EnumTable = &[
    (0, "complete main"),
    (1, "music and effects"),
    (2, "visually impaired"),
    (3, "hearing impaired"),
    (4, "dialogue"),
    (5, "commentary"),
    (6, "emergency"),
    (7, "voice over / karaoke"),
];
const STRMTYP: EnumTable = &[(0, "independent"), (1, "dependent"), (2, "AC-3 converted")];

fn acmod_name(acmod: u8, lfe: bool) -> String {
    let n = CHANNELS.get(usize::from(acmod)).copied().unwrap_or(0);
    if lfe {
        format!("{n}.1 ch")
    } else {
        format!("{n} ch")
    }
}

/// The LFE flag sits after optional mix level fields.
fn lfe_bit(acmod: u8, bits_after_acmod: u16) -> bool {
    let mut skip = 0u32;
    if acmod & 1 != 0 && acmod != 1 {
        skip = skip.saturating_add(2);
    }
    if acmod & 4 != 0 {
        skip = skip.saturating_add(2);
    }
    if acmod == 2 {
        skip = skip.saturating_add(2);
    }
    (bits_after_acmod >> (15u32.saturating_sub(skip))) & 1 == 1
}

fn parse(d: &[u8]) -> Option<(u64, String)> {
    if d.get(..2)? != [0x0b, 0x77] {
        return None;
    }
    let bsid = d.get(5)? >> 3;
    if bsid <= 10 {
        let fscod = d.get(4)? >> 6;
        let code = usize::from(d.get(4)? & 0x3f);
        let kbps = u64::from(*BITRATES.get(code / 2)?);
        let (rate, words) = match fscod {
            0 => (48000, kbps.saturating_mul(2)),
            1 => (44100, u64::from(*WORDS_44K.get(code)?)),
            2 => (32000, kbps.saturating_mul(3)),
            _ => return None,
        };
        let acmod = d.get(6)? >> 5;
        let rest = crate::bytes::u16_be(d, 6)? << 3;
        let lfe = lfe_bit(acmod, rest);
        Some((
            words.saturating_mul(2),
            format!("AC-3, {kbps} kbps, {rate} Hz, {}", acmod_name(acmod, lfe)),
        ))
    } else if bsid <= 16 {
        let w = crate::bytes::u16_be(d, 2)?;
        let frmsiz = u64::from(w & 0x7ff);
        let b4 = *d.get(4)?;
        let fscod = b4 >> 6;
        let (rate, blocks) = if fscod == 3 {
            let rate = match (b4 >> 4) & 3 {
                0 => 24000,
                1 => 22050,
                2 => 16000,
                _ => return None,
            };
            (rate, 6)
        } else {
            let rate = [48000, 44100, 32000].get(usize::from(fscod)).copied()?;
            (
                rate,
                [1u64, 2, 3, 6].get(usize::from((b4 >> 4) & 3)).copied()?,
            )
        };
        let acmod = (b4 >> 1) & 7;
        let lfe = b4 & 1 == 1;
        let bytes = frmsiz.saturating_add(1).saturating_mul(2);
        let kbps = bytes
            .saturating_mul(8)
            .saturating_mul(rate)
            .checked_div(blocks.saturating_mul(256).saturating_mul(1000))
            .unwrap_or(0);
        Some((
            bytes,
            format!("E-AC-3, {kbps} kbps, {rate} Hz, {}", acmod_name(acmod, lfe)),
        ))
    } else {
        None
    }
}

fn header(d: &[u8]) -> u64 {
    if d.get(5).is_some_and(|b| b >> 3 > 10) {
        7
    } else {
        8
    }
}

fn layout(b: &mut Bits<'_>) -> Result<()> {
    // The bitstream ID (bits 40..45) tells AC-3 from E-AC-3.
    b.skip(40);
    let bsid = b.read(5).unwrap_or(0);
    b.seek(0);
    b.field("Sync word", 16).hex().emit()?;
    if bsid <= 10 {
        ac3_layout(b)
    } else {
        eac3_layout(b)
    }
}

fn ac3_layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("CRC1", 16).hex().emit()?;
    b.field("Sample rate code", 2)
        .with(|v, n| {
            n.summary(match v {
                0 => "48 kHz",
                1 => "44.1 kHz",
                2 => "32 kHz",
                _ => "reserved",
            })
        })
        .emit()?;
    b.field("Frame size code", 6)
        .with(|v, n| match BITRATES.get(to_usize(v / 2)) {
            Some(k) => n.summary(format!("{k} kbps")),
            None => n,
        })
        .emit()?;
    b.field("Bitstream ID", 5).emit()?;
    b.field("Bitstream mode", 3).enumeration(BSMOD).emit()?;
    let acmod = b.field("Audio coding mode", 3).enumeration(ACMOD).emit()?;
    if acmod & 1 != 0 && acmod != 1 {
        b.field("Center mix level", 2).emit()?;
    }
    if acmod & 4 != 0 {
        b.field("Surround mix level", 2).emit()?;
    }
    if acmod == 2 {
        b.field("Dolby Surround mode", 2).emit()?;
    }
    b.field("LFE on", 1).flag().emit()?;
    b.field("Dialogue normalisation", 5)
        .with(|v, n| n.summary(format!("-{v} dB")))
        .emit()?;
    Ok(())
}

fn eac3_layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("Stream type", 2).enumeration(STRMTYP).emit()?;
    b.field("Substream ID", 3).emit()?;
    b.field("Frame size − 1", 11)
        .desc("In 16-bit words")
        .emit()?;
    let fscod = b.field("Sample rate code", 2).emit()?;
    if fscod == 3 {
        b.field("Sample rate code 2", 2).emit()?;
    } else {
        b.field("Blocks per frame code", 2)
            .with(|v, n| {
                n.summary(format!(
                    "{} blocks",
                    [1, 2, 3, 6].get(to_usize(v)).copied().unwrap_or(0)
                ))
            })
            .emit()?;
    }
    b.field("Audio coding mode", 3).enumeration(ACMOD).emit()?;
    b.field("LFE on", 1).flag().emit()?;
    b.field("Bitstream ID", 5).emit()?;
    b.field("Dialogue normalisation", 5)
        .with(|v, n| n.summary(format!("-{v} dB")))
        .emit()?;
    Ok(())
}

static SYNTAX: FrameSyntax = FrameSyntax {
    peek: 8,
    parse,
    header,
    layout,
};

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let window = cx.read_avail(file.sub(0, 0x10000)).await?;
    if let Some((_, describe)) = parse(&window) {
        let (count, covered) = count_frames(&window, &SYNTAX);
        let frames = if covered == to_u64(window.len()) || covered == 0 {
            count as f64
        } else {
            count as f64 * file.len as f64 / covered as f64
        };
        // AC-3 frames hold 1536 samples; E-AC-3 frames 256 per block.
        let samples = if describe.starts_with("AC-3") {
            1536.0
        } else {
            let b4 = window.get(4).copied().unwrap_or(0);
            if b4 >> 6 == 3 {
                1536.0
            } else {
                [256.0, 512.0, 768.0, 1536.0]
                    .get(usize::from((b4 >> 4) & 3))
                    .copied()
                    .unwrap_or(1536.0)
            }
        };
        let rate = describe
            .split(", ")
            .find_map(|p| p.strip_suffix(" Hz"))
            .and_then(|r| r.parse::<f64>().ok())
            .unwrap_or(0.0);
        let seconds = if rate > 0.0 {
            frames * samples / rate
        } else {
            0.0
        };
        cx.annotate(format!("{describe}, {}", duration(seconds)));
    }
    cx.emit(frames_node(file, &SYNTAX));
    Ok(())
}
