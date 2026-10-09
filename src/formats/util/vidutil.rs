//! Helpers shared by the video and container dissectors: durations and
//! FourCCs, a bit reader with Exp-Golomb codes, start-code scanning and
//! paged fixed-stride tables, and codec syntax in submodules:
//!
//! - `bitwalk`: a bit reader that records a node per syntax element, with
//!   spans mapped through emulation-prevention bytes;
//! - `h264`, `hevc`, `sei`: parameter sets (with VUI, HRD, scaling lists),
//!   slice headers and SEI messages;
//! - `av1`, `vp9`: AV1 OBUs and sequence headers, VP8/VP9 frame headers;
//! - `audio`: the MPEG-4 AudioSpecificConfig and audio elementary stream
//!   frame headers;
//! - `nal`: entry points over whole NAL units and the `avcC`, `hvcC`,
//!   `av1C` and `vpcC` configuration records;
//! - `params`, `tables`: what parameter sets say, and shared code points.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Radix, Value};

pub mod audio;
pub mod av1;
pub mod bitwalk;
pub mod h264;
pub mod hevc;
pub mod nal;
pub mod params;
pub mod sei;
pub mod tables;
pub mod vp9;

pub use audio::{AAC_SAMPLE_RATES, AUDIO_OBJECT_TYPES};
pub use nal::{NalCodec, NalInfo, parse_nal};
pub use params::{ParamSets, PpsInfo, SliceInfo, SpsInfo, h264_level, hevc_level};
pub use tables::{
    COLOUR_PRIMARIES, H264_NAL_TYPES, H264_PROFILES, HEVC_NAL_TYPES, HEVC_PROFILES,
    MATRIX_COEFFICIENTS, TRANSFER_CHARACTERISTICS, VVC_NAL_TYPES, lookup_or,
};

// ---------------------------------------------------------------------------
// Presentation helpers

/// `units` of `1/timescale` seconds as `hh:mm:ss.mmm`.
pub fn duration(units: u64, timescale: u64) -> String {
    if timescale == 0 {
        return format!("{units} units");
    }
    let millis = u128::from(units)
        .saturating_mul(1000)
        .checked_div(u128::from(timescale))
        .unwrap_or(0);
    seconds_ms(u64::try_from(millis).unwrap_or(u64::MAX))
}

/// Milliseconds as `hh:mm:ss.mmm`.
pub fn seconds_ms(millis: u64) -> String {
    let ms = millis % 1000;
    let s = millis / 1000;
    format!("{:02}:{:02}:{:02}.{ms:03}", s / 3600, s / 60 % 60, s % 60)
}

/// Seconds (floating point) as `hh:mm:ss.mmm`.
pub fn seconds_f64(seconds: f64) -> String {
    if !seconds.is_finite() || seconds < 0.0 {
        return format!("{seconds}");
    }
    // Saturating float-to-int conversion.
    #[allow(clippy::cast_possible_truncation, clippy::cast_sign_loss)]
    let millis = (seconds * 1000.0).round() as u64;
    seconds_ms(millis)
}

/// `n` followed by a noun, pluralised with an `s` unless `n` is 1.
pub fn plural(n: impl Into<u64>, noun: &str) -> String {
    let n = n.into();
    if n == 1 {
        format!("1 {noun}")
    } else {
        format!("{n} {noun}s")
    }
}

/// A four-character code, with non-printable bytes escaped.
pub fn fourcc(bytes: &[u8]) -> String {
    let mut out = String::new();
    for &b in bytes {
        if b.is_ascii_graphic() || b == b' ' {
            out.push(char::from(b));
        } else if b == 0xa9 {
            out.push('©');
        } else {
            out.push_str(&format!("\\x{b:02x}"));
        }
    }
    out
}

/// 16.16 fixed point.
pub fn fixed16(v: u32) -> f64 {
    f64::from(v) / 65536.0
}

/// Signed 16.16 fixed point.
pub fn sfixed16(v: i32) -> f64 {
    f64::from(v) / 65536.0
}

/// 8.8 fixed point.
pub fn fixed8(v: u16) -> f64 {
    f64::from(v) / 256.0
}

/// Formats a float without a pointless fractional part.
pub fn num(v: f64) -> String {
    if v.fract() == 0.0 && v.abs() < 1e15 {
        format!("{v:.0}")
    } else {
        format!("{v:.3}")
    }
}

/// An unsigned value node for a bit field (or any number not read through
/// [`Fields`]); `span` is the bytes containing it.
pub fn uint(name: impl Into<Cow<'static, str>>, span: Span, value: u64, bits: u8) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value,
        bits,
        radix: Radix::Dec,
    })
}

pub fn hex(name: impl Into<Cow<'static, str>>, span: Span, value: u64, bits: u8) -> Node {
    Node::new(name).span(span).value(Value::UInt {
        value,
        bits,
        radix: Radix::Hex,
    })
}

pub fn enumerated(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    value: u64,
    bits: u8,
    table: EnumTable,
) -> Node {
    Node::new(name).span(span).value(Value::Enum {
        raw: value,
        bits,
        name: crate::value::lookup(table, value),
    })
}

pub fn flag_node(name: impl Into<Cow<'static, str>>, span: Span, set: bool) -> Node {
    Node::new(name).span(span).value(Value::Bool(set))
}

pub fn text(name: impl Into<Cow<'static, str>>, span: Span, text: impl Into<String>) -> Node {
    Node::new(name).span(span).value(Value::Text(text.into()))
}

/// Formats a 16-byte UUID in the usual big-endian textual form.
pub fn uuid(b: &[u8]) -> String {
    let mut out = String::new();
    for (i, byte) in b.iter().enumerate() {
        if matches!(i, 4 | 6 | 8 | 10) {
            out.push('-');
        }
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

// ---------------------------------------------------------------------------
// Bit reader

/// MSB-first bit reader over a byte slice.
pub struct Bits<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Bits<'a> {
    pub fn new(data: &'a [u8]) -> Self {
        Bits { data, pos: 0 }
    }

    pub fn pos(&self) -> usize {
        self.pos
    }

    pub fn bit(&mut self) -> Option<u64> {
        let byte = self.data.get(self.pos >> 3)?;
        let shift = 7 ^ (self.pos & 7);
        self.pos = self.pos.checked_add(1)?;
        Some(u64::from((byte >> shift) & 1))
    }

    pub fn flag(&mut self) -> Option<bool> {
        self.bit().map(|b| b != 0)
    }

    /// Reads `n` (at most 64) bits.
    pub fn bits(&mut self, n: u32) -> Option<u64> {
        if n > 64 {
            return None;
        }
        let mut v = 0u64;
        for _ in 0..n {
            v = (v << 1) | self.bit()?;
        }
        Some(v)
    }

    pub fn skip(&mut self, n: usize) -> Option<()> {
        self.pos = self.pos.checked_add(n)?;
        (self.pos <= self.data.len().saturating_mul(8)).then_some(())
    }

    /// Unsigned Exp-Golomb code.
    pub fn ue(&mut self) -> Option<u64> {
        let mut zeros = 0u32;
        while self.bit()? == 0 {
            zeros = zeros.checked_add(1)?;
            if zeros > 32 {
                return None;
            }
        }
        let rest = self.bits(zeros)?;
        (1u64 << zeros).checked_sub(1)?.checked_add(rest)
    }

    /// Signed Exp-Golomb code.
    pub fn se(&mut self) -> Option<i64> {
        let k = i64::try_from(self.ue()?).ok()?;
        let magnitude = k.checked_add(1)? >> 1;
        Some(if k & 1 == 1 {
            magnitude
        } else {
            magnitude.checked_neg()?
        })
    }
}

/// Removes emulation-prevention bytes (`00 00 03` → `00 00`).
pub fn unescape_rbsp(data: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(data.len());
    let mut zeros = 0usize;
    for &b in data {
        if zeros >= 2 && b == 3 {
            zeros = 0;
            continue;
        }
        zeros = if b == 0 { zeros.saturating_add(1) } else { 0 };
        out.push(b);
    }
    out
}

// ---------------------------------------------------------------------------
// H.264 / HEVC parameter sets

/// A span for parsing bytes that are not shown (summaries only).
fn detached(len: usize) -> Span {
    Span::new(crate::span::SourceId::default_host(), 0, to_u64(len))
}

/// Parses an H.264 sequence parameter set (NAL unit including its header,
/// emulation prevention still present).
pub fn h264_sps(nal: &[u8]) -> Option<SpsInfo> {
    let (info, _) = parse_nal(
        NalCodec::Avc,
        nal,
        detached(nal.len()),
        &ParamSets::default(),
        false,
    );
    info.sps.filter(|_| info.nal_type == 7)
}

/// Parses an HEVC sequence parameter set (NAL unit including its two-byte
/// header).
pub fn hevc_sps(nal: &[u8]) -> Option<SpsInfo> {
    let (info, _) = parse_nal(
        NalCodec::Hevc,
        nal,
        detached(nal.len()),
        &ParamSets::default(),
        false,
    );
    info.sps.filter(|_| info.nal_type == 33)
}

/// Codec summary from an AVC decoder configuration record (`avcC`).
pub fn avcc_summary(d: &[u8]) -> Option<String> {
    let len = usize::from(crate::bytes::u16_be(d, 6)?);
    if let Some(sps) = d.get(8..).and_then(|r| r.get(..len)).and_then(h264_sps) {
        return Some(sps.h264_summary());
    }
    Some(format!(
        "{}@L{}",
        lookup_or(H264_PROFILES, d.get(1).copied()?.into()),
        h264_level(d.get(3).copied()?)
    ))
}

/// Codec summary from an HEVC decoder configuration record (`hvcC`).
pub fn hvcc_summary(d: &[u8]) -> Option<String> {
    hvcc_sps(d)
        .and_then(hevc_sps)
        .map(|s| s.hevc_summary())
        .or_else(|| Some(format!("level {}", hevc_level(d.get(12).copied()?))))
}

/// The first SPS NAL unit in an `hvcC` body.
pub fn hvcc_sps(d: &[u8]) -> Option<&[u8]> {
    let arrays = d.get(22).copied()?;
    let mut at = 23usize;
    for _ in 0..arrays {
        let kind = d.get(at).copied()? & 0x3f;
        let n = crate::bytes::u16_be(d, at.saturating_add(1))?;
        at = at.saturating_add(3);
        for _ in 0..n {
            let len = usize::from(crate::bytes::u16_be(d, at)?);
            let nal = d.get(at.saturating_add(2)..at.saturating_add(2).saturating_add(len))?;
            if kind == 33 {
                return Some(nal);
            }
            at = at.saturating_add(2).saturating_add(len);
        }
    }
    None
}

// ---------------------------------------------------------------------------
// Start codes

/// Finds the next `00 00 01` at or after `from` (relative to `span`),
/// reading in windows. Returns its offset.
pub async fn next_start_code(cx: &Cx, span: Span, from: u64) -> Result<Option<u64>> {
    const WINDOW: u64 = 0x4000;
    let mut pos = from;
    while pos < span.len {
        let data = cx.read_avail(span.sub(pos, WINDOW)).await?;
        if let Some(i) = data.windows(3).position(|w| w == [0, 0, 1]) {
            return Ok(Some(pos.saturating_add(to_u64(i))));
        }
        if to_u64(data.len()) < 3 {
            return Ok(None);
        }
        // Keep the last two bytes: a start code may straddle windows.
        pos = pos.saturating_add(to_u64(data.len()).saturating_sub(2));
        cx.checkpoint().await;
    }
    Ok(None)
}

// ---------------------------------------------------------------------------
// Paged fixed-stride tables

/// An entry of a fixed-stride table.
pub trait Entry: Record + Sync {
    /// The name of the entry at 0-based `index`.
    fn label(index: u64) -> String {
        format!("#{}", index.saturating_add(1))
    }
    /// A one-line description.
    fn summary(&self) -> Option<String> {
        None
    }
    /// For single-valued entries: show the entry as a leaf with this value.
    fn leaf(&self) -> Option<Value> {
        None
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Table {
    pub span: Span,
    pub count: u64,
    pub endian: Endian,
}

/// A lazy node listing `count` entries of type `E` stored at `span`.
pub fn table<E: Entry>(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    count: u64,
    endian: Endian,
) -> Node {
    Node::new(name)
        .span(span)
        .summary(if count == 1 {
            "1 entry".to_owned()
        } else {
            format!("{count} entries")
        })
        .lazy(
            expand_table::<E>,
            Table {
                span,
                count,
                endian,
            },
        )
}

const PAGE: u64 = 256;

pub async fn expand_table<E: Entry>(cx: Cx, t: Table) -> Result<()> {
    let stride = E::SIZE;
    let fits = t.span.len.checked_div(stride).unwrap_or(0);
    let count = t.count.min(fits);
    if t.count > fits {
        cx.diag(
            Diagnostic::truncated(
                Span::new(t.span.source, t.span.offset, t.count.saturating_mul(stride)),
                t.span.len,
            )
            .at(t.span),
        );
    }
    cx.set_count(Count::Exact(count));
    let mut index = 0u64;
    while index < count {
        let n = count.saturating_sub(index).min(PAGE);
        let page = t
            .span
            .sub(index.saturating_mul(stride), n.saturating_mul(stride));
        let block = cx.block(page).await?;
        let mut f = Fields::new(&block, t.endian);
        for j in 0..n {
            let at = j.saturating_mul(stride);
            f.seek(at);
            let entry = E::read(&mut f)?;
            let span = page.sub(at, stride);
            let label = E::label(index.saturating_add(j));
            let mut node = match entry.leaf() {
                Some(value) => Node::new(label).span(span).value(value),
                None => E::node(label, span, t.endian),
            };
            if let Some(s) = entry.summary() {
                node = node.summary(s);
            }
            cx.push(node).await;
        }
        index = index.saturating_add(n);
    }
    Ok(())
}

/// Reads `len` bytes at `span` start, bounded by the read limit (for
/// in-memory parsing of small structures).
pub async fn read_small(cx: &Cx, span: Span, max: u64) -> Result<Vec<u8>> {
    let len = span.len.min(max).min(cx.limits().max_read);
    cx.read_avail(span.sub(0, len)).await
}

/// Searches `data` for `needle`.
pub fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    data.windows(needle.len()).position(|w| w == needle)
}

/// Converts a slice index to a span offset helper.
pub fn at(span: Span, offset: usize, len: usize) -> Span {
    span.sub(to_u64(offset), to_u64(len))
}

/// Clamps a `u64` length to `usize` for slicing.
pub fn us(n: u64) -> usize {
    to_usize(n)
}

// ---------------------------------------------------------------------------
// MPEG-4 audio

/// An MPEG-4 AudioSpecificConfig: (object type, sample rate, channel
/// configuration).
pub fn audio_specific_config(data: &[u8]) -> Option<(u64, u64, u64)> {
    let mut b = Bits::new(data);
    let mut object = b.bits(5)?;
    if object == 31 {
        object = b.bits(6)?.checked_add(32)?;
    }
    let index = b.bits(4)?;
    let rate = if index == 15 {
        b.bits(24)?
    } else {
        u64::from(*AAC_SAMPLE_RATES.get(usize::try_from(index).ok()?)?)
    };
    let channels = b.bits(4)?;
    Some((object, rate, channels))
}

pub fn asc_summary(data: &[u8]) -> Option<String> {
    let (object, rate, channels) = audio_specific_config(data)?;
    Some(format!(
        "{}, {rate} Hz, channel configuration {channels}",
        lookup_or(AUDIO_OBJECT_TYPES, object)
    ))
}

/// Human-readable codec names for FourCCs used by MP4/MOV/AVI/IVF.
pub fn codec_name(fourcc: &[u8]) -> Option<&'static str> {
    Some(match fourcc {
        b"avc1" | b"avc2" | b"avc3" | b"avc4" | b"H264" | b"h264" | b"X264" | b"x264" => "H.264",
        b"hvc1" | b"hev1" | b"HEVC" | b"H265" | b"h265" => "HEVC",
        b"dvh1" | b"dvhe" => "Dolby Vision (HEVC)",
        b"dva1" | b"dvav" => "Dolby Vision (H.264)",
        b"av01" | b"AV01" => "AV1",
        b"vp08" | b"VP80" => "VP8",
        b"vp09" | b"VP90" => "VP9",
        b"vvc1" | b"vvi1" => "VVC",
        b"mp4v" | b"FMP4" | b"XVID" | b"DIVX" | b"DX50" => "MPEG-4 Visual",
        b"s263" | b"h263" | b"H263" => "H.263",
        b"jpeg" | b"mjpa" | b"mjpb" | b"MJPG" | b"AVDJ" => "Motion JPEG",
        b"mjp2" => "Motion JPEG 2000",
        b"apch" | b"apcn" | b"apcs" | b"apco" | b"ap4h" | b"ap4x" => "Apple ProRes",
        b"mp2v" | b"m2v1" | b"xdvc" | b"hdv1" | b"mx5p" => "MPEG-2 video",
        b"mp1v" | b"m1v " => "MPEG-1 video",
        b"dvc " | b"dvcp" | b"dv5n" | b"dvhq" => "DV",
        b"png " => "PNG",
        b"rle " => "Apple Animation",
        b"SVQ3" => "Sorenson Video 3",
        b"cvid" => "Cinepak",
        b"mp4a" => "AAC",
        b".mp3" | b"mp3 " => "MP3",
        b"ac-3" | b"sac3" => "AC-3",
        b"ec-3" => "E-AC-3",
        b"ac-4" => "AC-4",
        b"Opus" | b"opus" => "Opus",
        b"fLaC" => "FLAC",
        b"alac" => "ALAC",
        b"samr" => "AMR-NB",
        b"sawb" => "AMR-WB",
        b"sowt" | b"twos" | b"lpcm" | b"ipcm" | b"fpcm" | b"raw " | b"in24" | b"in32" | b"fl32"
        | b"fl64" | b"NONE" => "PCM",
        b"ulaw" => "µ-law",
        b"alaw" => "A-law",
        b"ima4" => "IMA ADPCM",
        b"dtsc" | b"dtsh" | b"dtsl" | b"dtse" => "DTS",
        b"mha1" | b"mhm1" => "MPEG-H 3D Audio",
        b"tx3g" => "3GPP timed text",
        b"wvtt" => "WebVTT",
        b"stpp" => "TTML",
        b"c608" => "CEA-608",
        b"tmcd" => "timecode",
        b"encv" => "encrypted video",
        b"enca" => "encrypted audio",
        _ => return None,
    })
}
