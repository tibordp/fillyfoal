//! Musepack: stream version 8 (`MPCK`, a sequence of keyed packets with
//! variable-length sizes) and the older version 7 (`MP+` and a fixed
//! header).

use crate::bytes::vlq_be;
use crate::cx::Cx;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::formats::audio::ape::trailing_tags;
use crate::formats::util::sound::{Bits, channels, duration_of, leaf};
use crate::formats::util::val::uint;
use crate::formats::{Format, Input, Probe};
use crate::node::Node;
use crate::span::Span;

pub static FORMAT: Format = Format {
    name: "musepack",
    title: "Musepack",
    extensions: &["mpc", "mp+", "mpp"],
    mime: "audio/x-musepack",
    probe: Probe::Custom(|h| {
        h.starts_with(b"MPCK")
            || (h.starts_with(b"MP+") && h.data.get(3).is_some_and(|v| v & 0xf == 7))
    }),
    dissect: crate::expander!(dissect: Input),
};

const RATES: [u32; 4] = [44100, 48000, 37800, 32000];

const KEYS: &[(&[u8; 2], &str)] = &[
    (b"SH", "Stream header"),
    (b"RG", "Replay gain"),
    (b"EI", "Encoder info"),
    (b"SO", "Seek table offset"),
    (b"AP", "Audio packet"),
    (b"ST", "Seek table"),
    (b"SE", "Stream end"),
    (b"CT", "Chapter tag"),
];

/// Musepack SV8 sizes are big-endian base-128 integers of at most 9 bytes.
const MAX_VARINT: usize = 9;

#[derive(Clone, Copy, Debug, Default)]
struct StreamHeader {
    samples: u64,
    rate: u32,
    channels: u64,
}

fn stream_header(data: &[u8]) -> Option<StreamHeader> {
    let rest = data.get(5..)?;
    let (samples, a) = vlq_be(rest, MAX_VARINT)?;
    let (_, b) = vlq_be(rest.get(a..)?, MAX_VARINT)?;
    let bits = crate::bytes::u16_be(rest, a.saturating_add(b))?;
    Some(StreamHeader {
        samples,
        rate: RATES.get(usize::from(bits >> 13)).copied().unwrap_or(0),
        channels: u64::from((bits >> 4) & 0xf).saturating_add(1),
    })
}

pub async fn dissect(cx: Cx, input: Input) -> Result<()> {
    let file = input.span;
    let (end, tags) = trailing_tags(&cx, input).await?;
    let magic = cx.read(file.sub(0, 4)).await?;
    if magic.starts_with(b"MP+") {
        sv7(&cx, file).await?;
    } else {
        cx.emit(Node::new("Magic").span(file.sub(0, 4)));
        let mut pos = 4u64;
        let mut annotated = false;
        while pos < end {
            let head = cx.read_avail(file.sub(pos, 11)).await?;
            let key: [u8; 2] = crate::bytes::array(&head, 0).unwrap_or_default();
            let Some((size, size_len)) = head.get(2..).and_then(|d| vlq_be(d, MAX_VARINT)) else {
                cx.emit(
                    Node::new("Unparsed data")
                        .span(file.sub(pos, end.saturating_sub(pos)))
                        .diag(Diagnostic::malformed("invalid packet header")),
                );
                break;
            };
            let header_len = 2u64.saturating_add(crate::bytes::to_u64(size_len));
            let len = size.max(header_len);
            let span = file.sub(pos, len);
            let name = KEYS.iter().find(|(k, _)| **k == key).map_or_else(
                || crate::formats::util::sound::fourcc(&key),
                |(_, n)| (*n).to_owned(),
            );
            let mut node = Node::new(name).span(span).summary(format!("{len} bytes"));
            if &key == b"SH" {
                let data = cx.read_avail(span.tail(header_len).sub(0, 32)).await?;
                if let Some(h) = stream_header(&data) {
                    let mut s = format!("{} Hz, {}", h.rate, channels(h.channels));
                    if let Some(d) = duration_of(h.samples, h.rate.into()) {
                        s.push_str(&format!(", {d}"));
                    }
                    node = node.summary(s.clone());
                    if !annotated {
                        cx.annotate(format!("Musepack SV8, {s}"));
                        annotated = true;
                    }
                }
            }
            cx.push(node.lazy(packet, (span, header_len, key))).await;
            pos = pos.saturating_add(len);
            if &key == b"SE" {
                break;
            }
        }
        if pos < end {
            cx.emit(Node::new("Trailing data").span(file.sub(pos, end.saturating_sub(pos))));
        }
    }
    for node in tags {
        cx.emit(node);
    }
    Ok(())
}

async fn packet(cx: Cx, (span, header_len, key): (Span, u64, [u8; 2])) -> Result<()> {
    cx.emit(leaf(
        "Key",
        span.sub(0, 2),
        crate::formats::util::val::text(crate::formats::util::sound::fourcc(&key)),
    ));
    let head = cx.read(span.sub(2, header_len.saturating_sub(2))).await?;
    let size = vlq_be(&head, MAX_VARINT).map_or(0, |v| v.0);
    cx.emit(leaf(
        "Size",
        span.sub(2, header_len.saturating_sub(2)),
        uint(size, 64),
    ));
    let payload = span.tail(header_len);
    let data = cx.read_avail(payload.sub(0, 64)).await?;
    match &key {
        b"SH" => {
            let block = cx.block(payload.sub(0, 5)).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Big);
            f.u32("CRC").hex().emit()?;
            f.u8("Stream version").emit()?;
            let mut at = 5usize;
            for name in ["Sample count", "Beginning silence"] {
                let (v, n) = data
                    .get(at..)
                    .and_then(|d| vlq_be(d, MAX_VARINT))
                    .unwrap_or((0, 1));
                cx.emit(leaf(
                    name,
                    payload.sub(crate::bytes::to_u64(at), crate::bytes::to_u64(n)),
                    uint(v, 64),
                ));
                at = at.saturating_add(n);
            }
            let bits_span = payload.sub(crate::bytes::to_u64(at), 2);
            let raw = data.get(at..).unwrap_or_default();
            let mut b = Bits::emitting(&cx, raw, bits_span);
            b.field("Sample rate index", 3)
                .with(|v, n| match RATES.get(crate::bytes::to_usize(v)) {
                    Some(r) => n.summary(format!("{r} Hz")),
                    None => n,
                })
                .emit()?;
            b.field("Max used bands − 1", 5).emit()?;
            b.field("Channels − 1", 4).emit()?;
            b.field("Mid/side stereo", 1).flag().emit()?;
            b.field("Audio block frames", 3)
                .with(|v, n| {
                    n.summary(format!(
                        "{} frames per packet",
                        1u64.checked_shl(u32::try_from(v.saturating_mul(2)).unwrap_or(64))
                            .unwrap_or(0)
                    ))
                })
                .emit()?;
        }
        b"RG" => {
            let block = cx.block(payload.sub(0, 9)).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Big);
            f.u8("Version").emit()?;
            f.int::<i16>("Title gain").emit()?;
            f.u16("Title peak").emit()?;
            f.int::<i16>("Album gain").emit()?;
            f.u16("Album peak").emit()?;
        }
        b"EI" => {
            let raw = data.first().copied().unwrap_or(0);
            cx.emit(
                leaf("Profile", payload.sub(0, 1), uint(raw >> 1, 7))
                    .summary(format!("{:.1}", f64::from(raw >> 1) / 8.0)),
            );
            cx.emit(leaf(
                "PNS",
                payload.sub(0, 1),
                crate::value::Value::Bool(raw & 1 != 0),
            ));
            let block = cx.block(payload.sub(1, 3)).await?;
            let mut f = Fields::emitting(&cx, &block, Endian::Big);
            f.u8("Encoder major").emit()?;
            f.u8("Encoder minor").emit()?;
            f.u8("Encoder build").emit()?;
        }
        b"SO" => {
            let (v, n) = vlq_be(&data, MAX_VARINT).unwrap_or((0, 1));
            cx.emit(
                leaf(
                    "Offset",
                    payload.sub(0, crate::bytes::to_u64(n)),
                    uint(v, 64),
                )
                .desc("From the start of this packet to the seek table"),
            );
        }
        _ => cx.emit(Node::new("Data").span(payload)),
    }
    Ok(())
}

/// SV7 profiles (libmpcdec's names).
const SV7_PROFILES: [&str; 16] = [
    "n.a.",
    "experimental",
    "n.a.",
    "n.a.",
    "n.a.",
    "below telephone (q=0)",
    "below telephone (q=1)",
    "telephone (q=2)",
    "thumb (q=3)",
    "radio (q=4)",
    "standard (q=5)",
    "extreme (q=6)",
    "insane (q=7)",
    "braindead (q=8)",
    "above braindead (q=9)",
    "above braindead (q=10)",
];

/// Stream version 7: `MP+`, version byte, then 32-bit little-endian words
/// read most significant bit first (as libmpcdec does).
async fn sv7(cx: &Cx, file: Span) -> Result<()> {
    let span = file.sub(0, 28);
    let block = cx.block(span).await?;
    let mut f = Fields::emitting(cx, &block, Endian::Little);
    f.ascii("Magic", 3).emit()?;
    f.u8("Version").hex().emit()?;
    let frames = f.u32("Frames").emit()?;
    let info = f
        .u32("Stream info")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "{} Hz, profile {}, max band {}{}, link {}",
                RATES
                    .get(crate::bytes::to_usize(((v >> 16) & 3).into()))
                    .copied()
                    .unwrap_or(0),
                SV7_PROFILES
                    .get(crate::bytes::to_usize(((v >> 20) & 0xf).into()))
                    .copied()
                    .unwrap_or("?"),
                (v >> 24) & 0x3f,
                if v & 0x4000_0000 != 0 { ", mid/side" } else { "" },
                (v >> 18) & 3
            ))
        })
        .desc("Intensity stereo (bit 31), mid/side (30), max band (24-29), profile (20-23), link (18-19), sample rate (16-17), estimated peak (0-15)")
        .emit()?;
    f.u16("Title peak").emit()?;
    f.int::<i16>("Title gain")
        .with(|&g, n| n.summary(format!("{:.2} dB", f64::from(g) / 100.0)))
        .emit()?;
    f.u16("Album peak").emit()?;
    f.int::<i16>("Album gain")
        .with(|&g, n| n.summary(format!("{:.2} dB", f64::from(g) / 100.0)))
        .emit()?;
    let gapless = f
        .u32("Gapless info")
        .hex()
        .with(|&v, n| {
            n.summary(format!(
                "true gapless {}, last frame {} samples, fast seek {}",
                v >> 31 != 0,
                (v >> 20) & 0x7ff,
                (v >> 19) & 1 != 0
            ))
        })
        .emit()?;
    f.u32("Encoder")
        .hex()
        .with(|&v, n| {
            let e = v >> 24;
            n.summary(format!("encoder version {}.{:02}", e / 100, e % 100))
        })
        .desc("Encoder version in the top byte")
        .emit()?;
    let rate = RATES
        .get(crate::bytes::to_usize(((info >> 16) & 3).into()))
        .copied()
        .unwrap_or(44100);
    let samples = if gapless >> 31 != 0 {
        u64::from(frames.saturating_sub(1))
            .saturating_mul(1152)
            .saturating_add(((gapless >> 20) & 0x7ff).into())
    } else {
        u64::from(frames).saturating_mul(1152)
    };
    let mut line = format!(
        "Musepack SV7, {}, stereo",
        crate::formats::util::vidutil::khz(rate.into())
    );
    if let Some(d) = duration_of(samples, rate.into()) {
        line.push_str(&format!(", {d}"));
    }
    if let Some(p) = SV7_PROFILES.get(crate::bytes::to_usize(((info >> 20) & 0xf).into())) {
        line.push_str(&format!(", profile {p}"));
    }
    cx.annotate(line);
    cx.emit(Node::new("Audio data").span(file.tail(28)));
    Ok(())
}
