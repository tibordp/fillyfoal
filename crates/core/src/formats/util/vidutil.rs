//! Helpers shared by the video and container dissectors: durations and
//! FourCCs, a bit reader with Exp-Golomb codes, start-code scanning and
//! paged fixed-stride tables, and codec syntax in submodules:
//!
//! - `bitwalk`: a bit reader that records a node per syntax element, with
//!   spans mapped through emulation-prevention bytes;
//! - `h264`, `hevc`, `sei`: parameter sets (with VUI, HRD, scaling lists),
//!   slice headers and SEI messages;
//! - `av1`, `vp9`: AV1 OBUs and sequence headers, VP8/VP9 frame headers;
//! - `audio`: the MPEG-4 AudioSpecificConfig, the Opus identification
//!   header and audio elementary stream frame headers;
//! - `esds`: MPEG-4 Systems descriptors (`esds`, `iods`, CAF `kuki`);
//! - `nal`: entry points over whole NAL units and the `avcC`, `hvcC`,
//!   `av1C` and `vpcC` configuration records, AudioSpecificConfig and
//!   Opus headers;
//! - `params`, `tables`: what parameter sets say, and shared code points.

use std::borrow::Cow;

use crate::bytes::{to_u64, to_usize};
use crate::cx::Cx;
use crate::dsl::Record;
use crate::error::{Diagnostic, Result};
use crate::fields::{Endian, Fields};
use crate::node::{Count, Node};
use crate::span::Span;
use crate::value::{EnumTable, Value};

pub mod audio;
pub mod av1;
pub mod bitwalk;
pub mod esds;
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

pub use super::fmt::{plural, uuid};

/// A four-character code, with non-printable bytes escaped, except that
/// QuickTime's 0xA9 (the first byte of user-data atoms such as `©nam`) is
/// shown as `©`.
pub fn fourcc(bytes: &[u8]) -> String {
    bytes
        .split_inclusive(|&b| b == 0xa9)
        .map(|part| match part.split_last() {
            Some((0xa9, head)) => format!("{}©", super::fmt::fourcc(head)),
            _ => super::fmt::fourcc(part),
        })
        .collect()
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

/// "48 kHz", "44.1 kHz", "22.05 kHz".
pub fn khz(rate: u64) -> String {
    if rate == 0 {
        return "? Hz".to_owned();
    }
    if rate < 1000 {
        return format!("{rate} Hz");
    }
    let s = format!("{:.3}", rate as f64 / 1000.0);
    let s = s.trim_end_matches('0').trim_end_matches('.');
    format!("{s} kHz")
}

/// "128 kb/s", "12.5 Mb/s".
pub fn bitrate(bps: u64) -> String {
    let one_decimal = |v: f64| {
        let s = format!("{v:.1}");
        s.strip_suffix(".0")
            .map_or_else(|| s.clone(), str::to_owned)
    };
    if bps >= 10_000_000 {
        format!("{} Mb/s", one_decimal(bps as f64 / 1_000_000.0))
    } else if bps >= 1000 {
        format!("{} kb/s", one_decimal(bps as f64 / 1000.0))
    } else {
        format!("{bps} b/s")
    }
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
    Node::new(name)
        .span(span)
        .value(super::val::uint(value, bits))
}

pub fn hex(name: impl Into<Cow<'static, str>>, span: Span, value: u64, bits: u8) -> Node {
    Node::new(name)
        .span(span)
        .value(super::val::hex(value, bits))
}

pub fn enumerated(
    name: impl Into<Cow<'static, str>>,
    span: Span,
    value: u64,
    bits: u8,
    table: EnumTable,
) -> Node {
    Node::new(name)
        .span(span)
        .value(super::val::enumv(value, bits, table))
}

pub fn flag_node(name: impl Into<Cow<'static, str>>, span: Span, set: bool) -> Node {
    Node::new(name).span(span).value(Value::Bool(set))
}

pub fn text(name: impl Into<Cow<'static, str>>, span: Span, text: impl Into<String>) -> Node {
    Node::new(name).span(span).value(super::val::text(text))
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

// ---------------------------------------------------------------------------
// H.264 / HEVC parameter sets

/// A span for parsing bytes that are not shown (summaries only).
pub fn detached(len: usize) -> Span {
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

/// Codec summary from an AVC decoder configuration record (`avcC`): what
/// its first SPS says, else its profile, level and High-profile extension.
pub fn avcc_summary(d: &[u8]) -> Option<String> {
    let (header, sps, _) = nal::avcc_config(d, detached(d.len()), false);
    sps.map(|s| s.describe())
        .or_else(|| Some(header?.describe()))
}

/// Codec summary from an HEVC decoder configuration record (`hvcC`): what
/// its first SPS says, else its profile, level and format.
pub fn hvcc_summary(d: &[u8]) -> Option<String> {
    let (header, sps, _) = nal::hvcc_config(d, detached(d.len()), false);
    sps.map(|s| s.describe())
        .or_else(|| Some(header?.describe()))
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

/// Searches `data` for `needle` (an empty needle is not found).
pub fn find(data: &[u8], needle: &[u8]) -> Option<usize> {
    if needle.is_empty() {
        return None;
    }
    crate::bytes::find(data, needle, 0)
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

/// A one-line description of an MPEG-4 AudioSpecificConfig ("AAC-LC,
/// 48000 Hz, stereo").
pub fn asc_summary(data: &[u8]) -> Option<String> {
    let (asc, _) = nal::asc(data, detached(data.len()), false);
    asc.map(|a| a.describe())
}

/// Human-readable codec names for FourCCs: the sample entry types of
/// MP4/MOV/3GP (case-sensitive), then Video for Windows FourCCs of
/// AVI/ASF/Matroska/IVF (case-insensitive).
pub fn codec_name(fourcc: &[u8]) -> Option<&'static str> {
    qt_codec_name(fourcc).or_else(|| {
        let mut up = [0u8; 4];
        for (u, c) in up.iter_mut().zip(fourcc) {
            *u = c.to_ascii_uppercase();
        }
        (fourcc.len() == 4).then_some(())?;
        vfw_codec_name(&up)
    })
}

/// Video for Windows FourCCs, upper case.
fn vfw_codec_name(up: &[u8; 4]) -> Option<&'static str> {
    Some(match up {
        b"WMV1" => "Windows Media Video 7",
        b"WMV2" => "Windows Media Video 8",
        b"WMV3" => "Windows Media Video 9",
        b"WMVA" => "Windows Media Video 9 Advanced",
        b"WVC1" => "VC-1",
        b"WMVP" | b"WVP2" => "Windows Media Video 9 Image",
        b"MSS1" | b"MSS2" => "Windows Media Screen",
        b"MP41" | b"MPG4" => "MS MPEG-4 v1",
        b"MP42" => "MS MPEG-4 v2",
        b"MP43" | b"DIV3" | b"DIV4" => "MS MPEG-4 v3",
        b"XVID" | b"DIVX" | b"DX50" | b"FMP4" | b"MP4V" | b"MP4S" | b"M4S2" => "MPEG-4 Visual",
        b"H264" | b"X264" | b"AVC1" => "H.264",
        b"HEVC" | b"H265" | b"HVC1" => "HEVC",
        b"H263" | b"S263" => "H.263",
        b"MJPG" | b"AVRN" | b"DMB1" => "Motion JPEG",
        b"IV31" | b"IV32" => "Indeo 3",
        b"IV41" => "Indeo 4",
        b"IV50" => "Indeo 5",
        b"CVID" => "Cinepak",
        b"MSVC" | b"CRAM" | b"WHAM" => "Microsoft Video 1",
        b"MRLE" => "Microsoft RLE",
        b"VP30" | b"VP31" => "VP3",
        b"VP50" => "VP5",
        b"VP60" | b"VP61" | b"VP62" | b"VP6F" => "VP6",
        b"VP80" => "VP8",
        b"VP90" => "VP9",
        b"AV01" => "AV1",
        b"FFV1" => "FFV1",
        b"HFYU" | b"FFVH" => "HuffYUV",
        b"DVSD" | b"DV25" | b"DV50" | b"CDVC" => "DV",
        b"MPG1" => "MPEG-1 video",
        b"MPG2" | b"MPEG" => "MPEG-2 video",
        b"FLV1" => "Sorenson Spark",
        b"TSCC" => "TechSmith Screen Capture",
        b"YUY2" | b"UYVY" | b"YV12" | b"I420" | b"IYUV" | b"NV12" | b"Y800" | b"YVYU" => {
            "uncompressed YUV"
        }
        b"THEO" => "Theora",
        b"DRAC" => "Dirac",
        b"APCN" | b"APCH" | b"APCS" | b"APCO" | b"AP4H" | b"AP4X" => "Apple ProRes",
        _ => return None,
    })
}

/// MP4/QuickTime sample entry types (case-sensitive).
fn qt_codec_name(fourcc: &[u8]) -> Option<&'static str> {
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
        b"text" => "QuickTime text",
        b"mebx" => "QuickTime metadata",
        b"mett" | b"metx" => "timed metadata",
        b"mp4s" => "MPEG-4 Systems",
        b"iamf" => "IAMF",
        b"apv1" => "APV",
        b"wvtt" => "WebVTT",
        b"stpp" => "TTML",
        b"c608" => "CEA-608",
        b"tmcd" => "timecode",
        b"encv" => "encrypted video",
        b"enca" => "encrypted audio",
        _ => return None,
    })
}
