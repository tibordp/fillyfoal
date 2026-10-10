//! DTS Coherent Acoustics streams (big-endian 16-bit words): core frames
//! (sync word `7FFE8001`), each giving its size, block count, channel
//! arrangement, sample rate and bit rate, and DTS-HD extension substreams
//! (sync word `64582025`), whose assets carry the HD components (lossless
//! XLL, XBR, X96, XXCH, LBR) named by their own sync words.

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::formats::util::arcutil::human_size;
use crate::formats::util::sound::{Bits, FrameRef, FrameSyntax, bits_node, duration, frames_node};
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::{SourceId, Span};
use crate::value::{EnumTable, lookup};

pub static FORMAT: Format = Format {
    name: "dts",
    title: "DTS audio",
    extensions: &["dts", "dtshd", "cpt"],
    mime: "audio/vnd.dts",
    probe: Probe::Custom(|h| {
        parse_core(h.data).is_some_and(|(len, _)| match h.data.get(to_usize(len)..) {
            Some(next) if next.len() >= 4 => {
                next.starts_with(&CORE) || next.starts_with(&SUBSTREAM)
            }
            _ => true,
        })
    }),
    dissect: crate::expander!(dissect: Input),
};

const CORE: [u8; 4] = [0x7f, 0xfe, 0x80, 0x01];
const SUBSTREAM: [u8; 4] = [0x64, 0x58, 0x20, 0x25];

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
    (5, "3/0 (C, L, R)"),
    (6, "2/1 (L, R, S)"),
    (7, "3/1 (C, L, R, S)"),
    (8, "2/2 (L, R, SL, SR)"),
    (9, "3/2 (C, L, R, SL, SR)"),
    (10, "2/2/2"),
    (11, "2/2/2/2"),
    (12, "3/2/2"),
    (13, "3/2/1/2"),
    (14, "3/2/2/2"),
    (15, "3/3/2/2"),
];

/// Channels per arrangement.
const AMODE_CHANNELS: [u8; 16] = [1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 8, 8];

const LFE: EnumTable = &[
    (0, "none"),
    (1, "128× interpolation"),
    (2, "64× interpolation"),
    (3, "invalid"),
];

const EXT_AUDIO: EnumTable = &[
    (0, "XCh (6.1 channel extension)"),
    (2, "X96 (96 kHz extension)"),
    (6, "XXCH (channel extension)"),
];

const PCMR: EnumTable = &[
    (0, "16-bit"),
    (1, "16-bit, ES"),
    (2, "20-bit"),
    (3, "20-bit, ES"),
    (5, "24-bit"),
    (6, "24-bit, ES"),
];

const CHIST: EnumTable = &[
    (0, "copy prohibited"),
    (1, "first generation"),
    (2, "second generation"),
    (3, "original"),
];

/// The core header fields the summary needs.
#[derive(Clone, Copy, Debug)]
struct Core {
    blocks: u64,
    size: u64,
    amode: u64,
    rate: u32,
    bitrate: u64,
    lfe: u64,
    ext: Option<u64>,
}

fn core(d: &[u8]) -> Option<Core> {
    if d.get(..4)? != CORE {
        return None;
    }
    let w = crate::bytes::u64_be(d, 4)?;
    let bits = |start: u32, n: u32| {
        (w >> (64u32.saturating_sub(start).saturating_sub(n))) & (1u64 << n).saturating_sub(1)
    };
    let c = Core {
        blocks: bits(7, 7).saturating_add(1),
        size: bits(14, 14).saturating_add(1),
        amode: bits(28, 6),
        rate: *RATES.get(to_usize(bits(34, 4)))?,
        bitrate: bits(38, 5),
        lfe: bits(53, 2),
        ext: (bits(51, 1) == 1).then(|| bits(48, 3)),
    };
    (c.size >= 96 && c.blocks >= 6 && c.rate > 0).then_some(c)
}

impl Core {
    fn channels(&self) -> String {
        let n = AMODE_CHANNELS
            .get(to_usize(self.amode))
            .copied()
            .unwrap_or(0);
        let lfe = if matches!(self.lfe, 1 | 2) { ".1" } else { "" };
        match lookup(AMODE, self.amode) {
            Some(name) => format!("{n}{lfe} ch, {name}"),
            None => format!("{n}{lfe} ch, user-defined arrangement"),
        }
    }

    fn kbps(&self) -> String {
        match BITRATES.get(to_usize(self.bitrate)) {
            Some(1411) => "1411.2 kbps".to_owned(),
            Some(k) => format!("{k} kbps"),
            None => match self.bitrate {
                30 => "variable bitrate".to_owned(),
                31 => "lossless".to_owned(),
                _ => "open bitrate".to_owned(),
            },
        }
    }

    fn describe(&self) -> String {
        let mut s = format!(
            "DTS core, {}, {} Hz, {}",
            self.kbps(),
            self.rate,
            self.channels()
        );
        if let Some(name) = self.ext.and_then(|e| lookup(EXT_AUDIO, e)) {
            s.push_str(&format!(" + {name}"));
        }
        s
    }
}

fn parse_core(d: &[u8]) -> Option<(u64, String)> {
    let c = core(d)?;
    Some((c.size, c.describe()))
}

/// Length and fields of the extension substream header at the start of
/// `d`: (frame size, header size, index).
fn substream(d: &[u8]) -> Option<(u64, u64, u64)> {
    if d.get(..4)? != SUBSTREAM {
        return None;
    }
    let mut b = Bits::new(d, Span::new(SourceId::ZEROS, 0, to_u64(d.len())));
    b.skip(40);
    let index = b.read(2)?;
    let wide = b.read(1)? != 0;
    let (header, size) = if wide {
        (b.read(12)?, b.read(20)?)
    } else {
        (b.read(8)?, b.read(16)?)
    };
    let (header, size) = (header.saturating_add(1), size.saturating_add(1));
    (size >= header && header >= 16).then_some((size, header, index))
}

/// HD components by sync word.
const COMPONENTS: &[([u8; 4], &str)] = &[
    ([0x41, 0xa2, 0x95, 0x47], "XLL (lossless, DTS-HD MA)"),
    ([0x65, 0x5e, 0x31, 0x5e], "XBR (DTS-HD High Resolution)"),
    ([0x1d, 0x95, 0xf2, 0x62], "X96"),
    ([0x47, 0x00, 0x4a, 0x03], "XXCH"),
    ([0x0a, 0x80, 0x19, 0x21], "LBR (DTS Express)"),
    ([0x5a, 0x5a, 0x5a, 0x5a], "XCh"),
    ([0x02, 0xb0, 0x92, 0x61], "DTS:X / object audio"),
];

/// The components whose sync words occur in `d` (a substream's payload).
fn components(d: &[u8]) -> Vec<&'static str> {
    let mut out = Vec::new();
    for (sync, name) in COMPONENTS {
        if d.windows(4).any(|w| w == sync) && !out.contains(name) {
            out.push(*name);
        }
    }
    out
}

fn parse(d: &[u8]) -> Option<(u64, String)> {
    if let Some(r) = parse_core(d) {
        return Some(r);
    }
    let (size, _, index) = substream(d)?;
    Some((size, format!("DTS-HD extension substream {index}")))
}

fn header(d: &[u8]) -> u64 {
    if let Some((_, header, _)) = substream(d) {
        return header;
    }
    // The core header: 11 bytes, 2 more with the header CRC, then 2 more.
    let crc = d.get(4).is_some_and(|b| b & 0x02 != 0);
    if crc { 15 } else { 13 }
}

fn layout(b: &mut Bits<'_>) -> Result<()> {
    b.seek(0);
    let sync = b.read(32).unwrap_or(0);
    b.seek(0);
    if sync == 0x6458_2025 {
        return substream_layout(b);
    }
    b.field("Sync word", 32).hex().emit()?;
    b.field("Frame type", 1)
        .with(|v, n| n.summary(if v == 1 { "normal" } else { "termination" }))
        .emit()?;
    b.field("Deficit sample count", 5)
        .with(|v, n| {
            if v == 31 {
                n.summary("normal frame")
            } else {
                n.summary(format!("{} samples short", v.saturating_add(1)))
            }
        })
        .emit()?;
    let crc = b.field("CRC present", 1).flag().emit()?;
    b.field("PCM sample blocks − 1", 7)
        .with(|v, n| {
            n.summary(format!(
                "{} samples",
                v.saturating_add(1).saturating_mul(32)
            ))
        })
        .emit()?;
    b.field("Frame size − 1", 14)
        .with(|v, n| n.summary(format!("{} bytes", v.saturating_add(1))))
        .emit()?;
    b.field("Channel arrangement", 6)
        .enumeration(AMODE)
        .emit()?;
    b.field("Sample rate", 4)
        .with(|v, n| match RATES.get(to_usize(v)) {
            Some(&r) if r > 0 => n.summary(format!("{r} Hz")),
            _ => n.diag(Diagnostic::malformed("invalid sample rate code")),
        })
        .emit()?;
    b.field("Bit rate", 5)
        .with(|v, n| match BITRATES.get(to_usize(v)) {
            Some(1411) => n.summary("1411.2 kbps"),
            Some(k) => n.summary(format!("{k} kbps")),
            None => n.summary(match v {
                30 => "variable",
                31 => "lossless",
                _ => "open",
            }),
        })
        .emit()?;
    b.field("Reserved", 1).emit()?;
    b.field("Dynamic range coefficients", 1).flag().emit()?;
    b.field("Time stamp", 1).flag().emit()?;
    b.field("Auxiliary data", 1).flag().emit()?;
    b.field("HDCD", 1).flag().emit()?;
    // The extension ID only means something when the flag after it is set.
    let mut ahead = b.silent();
    ahead.skip(3);
    let extended = ahead.read(1).unwrap_or(0) != 0;
    let ext = b.field("Extension audio ID", 3);
    if extended {
        ext.enumeration(EXT_AUDIO).emit()?;
    } else {
        ext.with(|_, n| n.summary("unused")).emit()?;
    }
    b.field("Extension audio", 1).flag().emit()?;
    b.field("Audio sync word insertion", 1).flag().emit()?;
    b.field("LFE", 2).enumeration(LFE).emit()?;
    b.field("Predictor history", 1).flag().emit()?;
    if crc != 0 {
        b.field("Header CRC", 16).hex().emit()?;
    }
    b.field("Multirate interpolator", 1)
        .with(|v, n| {
            n.summary(if v == 0 {
                "non-perfect reconstruction"
            } else {
                "perfect reconstruction"
            })
        })
        .emit()?;
    let version = b
        .field("Encoder software revision", 4)
        .with(|v, n| match v {
            7 => n.summary("current"),
            6 => n.summary("future, compatible"),
            _ => n,
        })
        .emit()?;
    b.field("Copy history", 2).enumeration(CHIST).emit()?;
    b.field("Source PCM resolution", 3)
        .enumeration(PCMR)
        .emit()?;
    b.field("Front sum/difference", 1).flag().emit()?;
    b.field("Surround sum/difference", 1).flag().emit()?;
    b.field("Dialogue normalisation", 4)
        .with(|v, n| match version {
            7 if v == 0 => n.summary("0 dB"),
            7 => n.summary(format!("−{v} dB")),
            6 => n.summary(format!("−{} dB", v.saturating_add(16))),
            _ => n.summary("unspecified"),
        })
        .emit()?;
    Ok(())
}

fn substream_layout(b: &mut Bits<'_>) -> Result<()> {
    b.field("Sync word", 32).hex().emit()?;
    b.field("User defined", 8).hex().emit()?;
    b.field("Substream index", 2).emit()?;
    let wide = b.field("Header size type", 1).emit()?;
    let (h, f) = if wide == 0 { (8, 16) } else { (12, 20) };
    b.field("Header size − 1", h)
        .with(|v, n| n.summary(format!("{} bytes", v.saturating_add(1))))
        .emit()?;
    b.field("Substream size − 1", f)
        .with(|v, n| n.summary(format!("{} bytes", v.saturating_add(1))))
        .emit()?;
    let fixed = b.field("Static fields present", 1).flag().emit()?;
    if fixed != 0 {
        b.field("Reference clock", 2)
            .with(|v, n| {
                n.summary(match v {
                    0 => "32 kHz",
                    1 => "44.1 kHz",
                    2 => "48 kHz",
                    _ => "invalid",
                })
            })
            .emit()?;
        b.field("Frame duration code", 3)
            .with(|v, n| {
                n.summary(format!(
                    "{} clock periods",
                    v.saturating_add(1).saturating_mul(512)
                ))
            })
            .emit()?;
        if b.field("Time stamp present", 1).flag().emit()? != 0 {
            b.field("Time stamp", 32).emit()?;
            b.field("Time stamp LSBs", 4).emit()?;
        }
        b.field("Audio presentations − 1", 3).emit()?;
        b.field("Assets − 1", 3).emit()?;
    }
    Ok(())
}

static SYNTAX: FrameSyntax = FrameSyntax {
    peek: 32,
    sync: &[0x7f, 0x64],
    parse,
    header,
    layout,
    expand: Some(crate::expander!(frame: FrameRef)),
};

async fn frame(cx: Cx, f: FrameRef) -> Result<()> {
    cx.emit(bits_node("Header", f.header, layout, false));
    let payload = f.span.tail(f.header.len);
    let head = cx.read_avail(f.span.sub(0, 4)).await?;
    let mut node = Node::new(if head == SUBSTREAM {
        "Asset data"
    } else {
        "Audio data"
    })
    .span(payload)
    .summary(human_size(payload.len));
    if head == SUBSTREAM {
        let data = cx.read_avail(payload.sub(0, 0x10000)).await?;
        let found = components(&data);
        if !found.is_empty() {
            node = node.summary(format!("{}, {}", found.join(", "), human_size(payload.len)));
        }
    }
    cx.emit(node);
    Ok(())
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let window = cx.read_avail(file.sub(0, 0x10000)).await?;
    if let Some(first) = core(&window) {
        let mut at = 0usize;
        let (mut frames, mut bytes) = (0u64, 0u64);
        let mut hd = Vec::new();
        while let Some((len, _)) = window.get(at..).and_then(parse) {
            let end = at.saturating_add(to_usize(len));
            if end > window.len() || len == 0 {
                break;
            }
            let rest = window.get(at..end).unwrap_or_default();
            if rest.starts_with(&CORE) {
                frames = frames.saturating_add(1);
            } else if hd.is_empty() {
                hd = components(rest);
            }
            bytes = bytes.saturating_add(len);
            at = end;
        }
        let total = if to_u64(window.len()) >= file.len || bytes == 0 {
            frames as f64
        } else {
            frames as f64 * file.len as f64 / bytes as f64
        };
        let seconds = total * first.blocks.saturating_mul(32) as f64 / f64::from(first.rate);
        let mut line = first.describe();
        if !hd.is_empty() {
            line = format!("{line}; DTS-HD: {}", hd.join(", "));
        }
        cx.annotate(format!("{line}, {}", duration(seconds)));
    } else if let Some((_, _, _)) = substream(&window) {
        let found = components(&window);
        cx.annotate(format!(
            "DTS-HD extension substreams (no core){}",
            if found.is_empty() {
                String::new()
            } else {
                format!(": {}", found.join(", "))
            }
        ));
    }
    cx.emit(frames_node(file, &SYNTAX));
    Ok(())
}
