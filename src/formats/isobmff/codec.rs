//! Codec configuration records decoded bit by bit (MPEG-4
//! AudioSpecificConfig, AC-3/E-AC-3 specific boxes, AV1 configuration and
//! OBUs, HEVC/AVC parameter-set arrays) and what is derived from them:
//! profile names, channel layouts, RFC 6381 codec strings.

use crate::bytes::{to_u64, to_usize, u16_be, u32_be};
use crate::cx::Cx;
use crate::error::Result;
use crate::fields::Fields;
use crate::formats::util::sound::Bits as BitFields;
use crate::formats::util::vidutil::{self, AAC_SAMPLE_RATES, hevc_sps, lookup_or, unescape_rbsp};
use crate::node::Node;
use crate::span::{SourceId, Span};
use crate::value::EnumTable;

/// A bit reader over the next `n` bytes of `f`, emitting when `cx` is
/// given; `f` advances past them.
pub fn bits_at<'a>(cx: Option<&'a Cx>, f: &mut Fields<'a>, n: u64) -> BitFields<'a> {
    let span = f.peek_span(n);
    let start = to_usize(f.pos());
    let data: &'a [u8] = f.block().data.get(start..).unwrap_or_default();
    let data = data.get(..to_usize(n)).unwrap_or(data);
    f.skip(n);
    match cx {
        Some(cx) => BitFields::emitting(cx, data, span),
        None => BitFields::new(data, span),
    }
}

/// A placeholder span for silent bit parsing of in-memory bytes.
pub fn nowhere(len: usize) -> Span {
    Span::new(SourceId(0), 0, to_u64(len))
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

/// A channel count as a layout name where one is customary.
pub fn channel_count(n: u64) -> String {
    match n {
        1 => "mono".to_owned(),
        2 => "stereo".to_owned(),
        6 => "5.1".to_owned(),
        8 => "7.1".to_owned(),
        _ => format!("{n} ch"),
    }
}

// ---------------------------------------------------------------------------
// MPEG-4 audio (ISO/IEC 14496-3 1.6.2.1)

pub const AUDIO_OBJECT_TYPES: EnumTable = &[
    (0, "null"),
    (1, "AAC Main"),
    (2, "AAC LC"),
    (3, "AAC SSR"),
    (4, "AAC LTP"),
    (5, "SBR"),
    (6, "AAC Scalable"),
    (7, "TwinVQ"),
    (8, "CELP"),
    (9, "HVXC"),
    (12, "TTSI"),
    (13, "Main synthetic"),
    (14, "Wavetable synthesis"),
    (15, "General MIDI"),
    (16, "Algorithmic synthesis"),
    (17, "ER AAC LC"),
    (19, "ER AAC LTP"),
    (20, "ER AAC Scalable"),
    (21, "ER TwinVQ"),
    (22, "ER BSAC"),
    (23, "ER AAC LD"),
    (24, "ER CELP"),
    (25, "ER HVXC"),
    (26, "ER HILN"),
    (27, "ER Parametric"),
    (28, "SSC"),
    (29, "PS"),
    (30, "MPEG Surround"),
    (32, "MPEG-1/2 Layer 1"),
    (33, "MPEG-1/2 Layer 2"),
    (34, "MPEG-1/2 Layer 3"),
    (35, "DST"),
    (36, "ALS"),
    (37, "SLS"),
    (38, "SLS non-core"),
    (39, "ER AAC ELD"),
    (40, "SMR Simple"),
    (41, "SMR Main"),
    (42, "USAC"),
    (43, "SAOC"),
    (44, "LD MPEG Surround"),
    (45, "SAOC-DE"),
    (46, "Audio sync"),
];

pub const CHANNEL_CONFIGURATIONS: EnumTable = &[
    (0, "defined in AOT-specific config"),
    (1, "mono (C)"),
    (2, "stereo (L R)"),
    (3, "3.0 (C L R)"),
    (4, "4.0 (C L R Cs)"),
    (5, "5.0 (C L R Ls Rs)"),
    (6, "5.1 (C L R Ls Rs LFE)"),
    (7, "7.1 (C Lc Rc L R Ls Rs LFE)"),
    (11, "6.1"),
    (12, "7.1 (back)"),
    (13, "22.2"),
    (14, "7.1 (top front)"),
];

/// Channels implied by a channel configuration.
fn configured_channels(config: u64) -> u64 {
    match config {
        1..=6 => config,
        7 | 12 | 14 => 8,
        11 => 7,
        13 => 24,
        _ => 0,
    }
}

/// A decoded AudioSpecificConfig.
#[derive(Clone, Debug, Default)]
pub struct Asc {
    /// The audio object type as first signalled (5 or 29 for explicit
    /// hierarchical SBR/PS signalling).
    pub signalled: u64,
    /// The core object type.
    pub object: u64,
    pub rate: u64,
    pub config: u64,
    pub sbr: bool,
    pub ps: bool,
    pub ext_rate: Option<u64>,
}

impl Asc {
    /// "AAC LC", "HE-AAC", "HE-AACv2".
    pub fn profile(&self) -> String {
        if self.ps {
            return "HE-AACv2".to_owned();
        }
        if self.sbr {
            return "HE-AAC".to_owned();
        }
        match self.object {
            1 => "AAC Main".to_owned(),
            2 => "AAC-LC".to_owned(),
            4 => "AAC-LTP".to_owned(),
            17 => "ER AAC-LC".to_owned(),
            23 => "AAC-LD".to_owned(),
            39 => "AAC-ELD".to_owned(),
            42 => "xHE-AAC (USAC)".to_owned(),
            o => lookup_or(AUDIO_OBJECT_TYPES, o),
        }
    }

    pub fn output_rate(&self) -> u64 {
        match self.ext_rate {
            Some(r) if self.sbr => r,
            _ => self.rate,
        }
    }

    pub fn channels(&self) -> u64 {
        let n = configured_channels(self.config);
        if self.ps && n == 1 { 2 } else { n }
    }

    /// The layout: "mono", "stereo", "5.1".
    pub fn layout(&self) -> String {
        match self.config {
            0 => "custom layout".to_owned(),
            1 if self.ps => "stereo (parametric)".to_owned(),
            3 => "3.0".to_owned(),
            4 => "4.0".to_owned(),
            5 => "5.0".to_owned(),
            11 => "6.1".to_owned(),
            13 => "22.2".to_owned(),
            c => channel_count(configured_channels(c)),
        }
    }

    pub fn summary(&self) -> String {
        let mut s = format!("{}, {}", self.profile(), khz(self.output_rate()));
        if self.sbr && self.output_rate() != self.rate {
            s.push_str(&format!(" (core {})", khz(self.rate)));
        }
        format!("{s}, {}", self.layout())
    }
}

fn object_type(b: &mut BitFields<'_>, name: &'static str) -> Result<u64> {
    let v = b
        .field(name, 5)
        .enumeration(AUDIO_OBJECT_TYPES)
        .desc("31 escapes to a 6-bit extension (32 + value)")
        .emit()?;
    if v != 31 {
        return Ok(v);
    }
    let ext = b
        .field("Object type extension", 6)
        .with(|e, n| n.summary(lookup_or(AUDIO_OBJECT_TYPES, e.saturating_add(32))))
        .emit()?;
    Ok(ext.saturating_add(32))
}

fn sampling_frequency(b: &mut BitFields<'_>, name: &'static str) -> Result<u64> {
    let index = b
        .field(name, 4)
        .with(|i, n| match AAC_SAMPLE_RATES.get(to_usize(i)) {
            Some(r) => n.summary(format!("{r} Hz")),
            None if i == 15 => n.summary("explicit"),
            None => n.summary("reserved"),
        })
        .emit()?;
    if index == 15 {
        return b
            .field("Sampling frequency", 24)
            .with(|r, n| n.summary(format!("{r} Hz")))
            .emit();
    }
    Ok(AAC_SAMPLE_RATES
        .get(to_usize(index))
        .copied()
        .map_or(0, u64::from))
}

fn is_ga(object: u64) -> bool {
    matches!(object, 1..=4 | 6 | 7 | 17 | 19..=23)
}

fn is_er(object: u64) -> bool {
    matches!(object, 17 | 19..=27 | 39)
}

/// AudioSpecificConfig as a bit layout (emits when `b` is emitting).
pub fn asc_layout(b: &mut BitFields<'_>) -> Result<Asc> {
    let signalled = object_type(b, "Audio object type")?;
    let mut asc = Asc {
        signalled,
        object: signalled,
        ..Asc::default()
    };
    asc.rate = sampling_frequency(b, "Sampling frequency index")?;
    asc.config = b
        .field("Channel configuration", 4)
        .enumeration(CHANNEL_CONFIGURATIONS)
        .emit()?;
    let mut explicit = false;
    if asc.object == 5 || asc.object == 29 {
        explicit = true;
        asc.sbr = true;
        asc.ps = asc.object == 29;
        asc.ext_rate = Some(sampling_frequency(b, "Extension sampling frequency index")?);
        asc.object = object_type(b, "Core audio object type")?;
        if asc.object == 22 {
            b.field("Extension channel configuration", 4).emit()?;
        }
    }
    if !is_ga(asc.object) {
        return Ok(asc);
    }
    // GASpecificConfig
    b.field("Frame length flag", 1)
        .with(|v, n| {
            n.summary(if v == 0 {
                "1024 samples"
            } else {
                "960 samples"
            })
        })
        .emit()?;
    if b.field("Depends on core coder", 1).flag().emit()? == 1 {
        b.field("Core coder delay", 14).emit()?;
    }
    let extension = b.field("Extension flag", 1).flag().emit()?;
    if asc.config == 0 {
        // A program_config_element follows; it is not decoded here.
        return Ok(asc);
    }
    if asc.object == 6 || asc.object == 20 {
        b.field("Layer number", 3).emit()?;
    }
    if extension == 1 {
        if asc.object == 22 {
            b.field("Number of subframes", 5).emit()?;
            b.field("Layer length", 11).emit()?;
        }
        if matches!(asc.object, 17 | 19 | 20 | 23) {
            b.field("Section data resilience", 1).flag().emit()?;
            b.field("Scale factor data resilience", 1).flag().emit()?;
            b.field("Spectral data resilience", 1).flag().emit()?;
        }
        b.field("Extension flag 3", 1).flag().emit()?;
    }
    if is_er(asc.object) {
        b.field("Error protection config", 2).emit()?;
    }
    if explicit {
        return Ok(asc);
    }
    // Backward-compatible (implicit-explicit) SBR/PS signalling.
    let save = b.pos();
    let peek = b.read(16);
    b.seek(save);
    if peek.is_some_and(|v| v >> 5 == 0x2b7) {
        b.field("Sync extension type", 11).hex().emit()?;
        let ext = object_type(b, "Extension audio object type")?;
        if ext == 5 {
            let sbr = b.field("SBR present", 1).flag().emit()?;
            if sbr == 1 {
                asc.sbr = true;
                asc.ext_rate = Some(sampling_frequency(b, "Extension sampling frequency index")?);
                let save = b.pos();
                let peek = b.read(12);
                b.seek(save);
                if peek.is_some_and(|v| v >> 1 == 0x548) {
                    b.field("Sync extension type", 11).hex().emit()?;
                    asc.ps = b.field("PS present", 1).flag().emit()? == 1;
                }
            }
        }
    }
    Ok(asc)
}

/// Silently decodes an AudioSpecificConfig.
pub fn asc(data: &[u8]) -> Option<Asc> {
    asc_layout(&mut BitFields::new(data, nowhere(data.len()))).ok()
}

// ---------------------------------------------------------------------------
// AC-3 and E-AC-3 (ETSI TS 102 366 annex F)

pub const AC3_RATES: EnumTable = &[(0, "48000 Hz"), (1, "44100 Hz"), (2, "32000 Hz")];
const AC3_RATE_HZ: [u64; 3] = [48000, 44100, 32000];

pub const AC3_ACMOD: EnumTable = &[
    (0, "1+1 (dual mono)"),
    (1, "1/0 (mono)"),
    (2, "2/0 (stereo)"),
    (3, "3/0 (L C R)"),
    (4, "2/1 (L R S)"),
    (5, "3/1 (L C R S)"),
    (6, "2/2 (L R SL SR)"),
    (7, "3/2 (L C R SL SR)"),
];

pub const AC3_BSMOD: EnumTable = &[
    (0, "complete main"),
    (1, "music and effects"),
    (2, "visually impaired"),
    (3, "hearing impaired"),
    (4, "dialogue"),
    (5, "commentary"),
    (6, "emergency"),
    (7, "voice over / karaoke"),
];

const AC3_BITRATES: [u64; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];

/// What a `dac3` or the first `dec3` substream says.
#[derive(Clone, Debug, Default)]
pub struct Ac3 {
    pub rate: u64,
    pub acmod: u64,
    pub lfe: bool,
    pub kbps: u64,
    pub atmos: bool,
}

impl Ac3 {
    pub fn channels(&self) -> u64 {
        let base = [2u64, 1, 2, 3, 3, 4, 4, 5]
            .get(to_usize(self.acmod))
            .copied()
            .unwrap_or(0);
        base.saturating_add(u64::from(self.lfe))
    }

    pub fn layout(&self) -> String {
        match (self.acmod, self.lfe) {
            (0, _) => "dual mono".to_owned(),
            (1, false) => "mono".to_owned(),
            (2, false) => "stereo".to_owned(),
            (2, true) => "2.1".to_owned(),
            (7, false) => "5.0".to_owned(),
            (7, true) => "5.1".to_owned(),
            _ => {
                let base = lookup_or(AC3_ACMOD, self.acmod);
                let base = base.split(' ').next().unwrap_or_default().to_owned();
                if self.lfe {
                    format!("{base}+LFE")
                } else {
                    base
                }
            }
        }
    }

    pub fn summary(&self) -> String {
        let mut s = format!("{}, {}, {} kb/s", khz(self.rate), self.layout(), self.kbps);
        if self.atmos {
            s.push_str(", Dolby Atmos (JOC)");
        }
        s
    }
}

pub fn dac3_layout(b: &mut BitFields<'_>) -> Result<Ac3> {
    let fscod = b
        .field("Sample rate code (fscod)", 2)
        .enumeration(AC3_RATES)
        .emit()?;
    b.field("Bit stream identification (bsid)", 5).emit()?;
    b.field("Bit stream mode (bsmod)", 3)
        .enumeration(AC3_BSMOD)
        .emit()?;
    let acmod = b
        .field("Audio coding mode (acmod)", 3)
        .enumeration(AC3_ACMOD)
        .emit()?;
    let lfe = b.field("LFE on", 1).flag().emit()?;
    let rate = b
        .field("Bit rate code", 5)
        .with(|v, n| match AC3_BITRATES.get(to_usize(v)) {
            Some(k) => n.summary(format!("{k} kb/s")),
            None => n,
        })
        .emit()?;
    b.field("Reserved", 5).emit()?;
    Ok(Ac3 {
        rate: AC3_RATE_HZ.get(to_usize(fscod)).copied().unwrap_or(0),
        acmod,
        lfe: lfe == 1,
        kbps: AC3_BITRATES.get(to_usize(rate)).copied().unwrap_or(0),
        atmos: false,
    })
}

pub fn dec3_layout(b: &mut BitFields<'_>) -> Result<Ac3> {
    let kbps = b
        .field("Data rate", 13)
        .with(|v, n| n.summary(format!("{v} kb/s")))
        .emit()?;
    let subs = b
        .field("Independent substreams", 3)
        .with(|v, n| n.summary(format!("{}", v.saturating_add(1))))
        .desc("Number of independent substreams minus one")
        .emit()?;
    let mut first: Option<Ac3> = None;
    for _ in 0..=subs {
        let fscod = b
            .field("Sample rate code (fscod)", 2)
            .enumeration(AC3_RATES)
            .emit()?;
        b.field("Bit stream identification (bsid)", 5).emit()?;
        b.field("Reserved", 1).emit()?;
        b.field("Audio service (asvc)", 1).flag().emit()?;
        b.field("Bit stream mode (bsmod)", 3)
            .enumeration(AC3_BSMOD)
            .emit()?;
        let acmod = b
            .field("Audio coding mode (acmod)", 3)
            .enumeration(AC3_ACMOD)
            .emit()?;
        let lfe = b.field("LFE on", 1).flag().emit()?;
        b.field("Reserved", 3).emit()?;
        let deps = b.field("Dependent substreams", 4).emit()?;
        if deps > 0 {
            b.field("Channel locations", 9).hex().emit()?;
        } else {
            b.field("Reserved", 1).emit()?;
        }
        if first.is_none() {
            first = Some(Ac3 {
                rate: AC3_RATE_HZ.get(to_usize(fscod)).copied().unwrap_or(0),
                acmod,
                lfe: lfe == 1,
                kbps,
                atmos: false,
            });
        }
    }
    let mut info = first.unwrap_or_default();
    let save = b.pos();
    if b.read(16).is_some() {
        b.seek(save);
        b.field("Reserved", 7).emit()?;
        let joc = b
            .field("E-AC-3 extension type A", 1)
            .flag()
            .desc("Joint object coding (Dolby Atmos)")
            .emit()?;
        b.field("Complexity index type A", 8).emit()?;
        info.atmos = joc == 1;
    } else {
        b.seek(save);
    }
    Ok(info)
}

// ---------------------------------------------------------------------------
// AV1 (AV1 Codec ISO Media File Format Binding, AV1 bitstream spec 5.3, 5.5)

pub const AV1_CHROMA_POSITION: EnumTable = &[
    (0, "unknown"),
    (1, "vertical (left)"),
    (2, "colocated (top-left)"),
    (3, "reserved"),
];

pub const OBU_TYPES: EnumTable = &[
    (1, "OBU_SEQUENCE_HEADER"),
    (2, "OBU_TEMPORAL_DELIMITER"),
    (3, "OBU_FRAME_HEADER"),
    (4, "OBU_TILE_GROUP"),
    (5, "OBU_METADATA"),
    (6, "OBU_FRAME"),
    (7, "OBU_REDUNDANT_FRAME_HEADER"),
    (8, "OBU_TILE_LIST"),
    (15, "OBU_PADDING"),
];

pub const AV1_PROFILES: EnumTable = &[(0, "Main"), (1, "High"), (2, "Professional")];

/// "4.0" from a seq_level_idx.
pub fn av1_level(idx: u64) -> String {
    if idx == 31 {
        return "max".to_owned();
    }
    format!("{}.{}", 2u64.saturating_add(idx >> 2), idx & 3)
}

/// The `av1C` record's fixed fields.
#[derive(Clone, Debug, Default)]
pub struct Av1Config {
    pub profile: u64,
    pub level: u64,
    pub tier: u64,
    pub depth: u64,
    pub mono: bool,
    pub sub_x: u64,
    pub sub_y: u64,
}

impl Av1Config {
    pub fn chroma(&self) -> &'static str {
        match (self.mono, self.sub_x, self.sub_y) {
            (true, _, _) => "4:0:0",
            (_, 1, 1) => "4:2:0",
            (_, 1, 0) => "4:2:2",
            _ => "4:4:4",
        }
    }

    pub fn summary(&self) -> String {
        format!(
            "{} profile, level {}{}, {}-bit {}",
            lookup_or(AV1_PROFILES, self.profile),
            av1_level(self.level),
            if self.tier == 1 { " high tier" } else { "" },
            self.depth,
            self.chroma()
        )
    }

    /// `av01.P.LLT.DD`.
    pub fn codec_string(&self) -> String {
        format!(
            "av01.{}.{:02}{}.{:02}",
            self.profile,
            self.level,
            if self.tier == 1 { 'H' } else { 'M' },
            self.depth
        )
    }
}

pub fn av1c_layout(b: &mut BitFields<'_>) -> Result<Av1Config> {
    b.field("Marker", 1).emit()?;
    b.field("Version", 7).emit()?;
    let profile = b
        .field("Sequence profile", 3)
        .enumeration(AV1_PROFILES)
        .emit()?;
    let level = b
        .field("Sequence level index", 5)
        .with(|v, n| n.summary(format!("level {}", av1_level(v))))
        .emit()?;
    let tier = b
        .field("Tier", 1)
        .with(|v, n| n.summary(if v == 1 { "high" } else { "main" }))
        .emit()?;
    let high = b.field("High bit depth", 1).flag().emit()?;
    let twelve = b.field("Twelve bit", 1).flag().emit()?;
    let mono = b.field("Monochrome", 1).flag().emit()?;
    let sub_x = b.field("Chroma subsampling x", 1).emit()?;
    let sub_y = b.field("Chroma subsampling y", 1).emit()?;
    b.field("Chroma sample position", 2)
        .enumeration(AV1_CHROMA_POSITION)
        .emit()?;
    b.field("Reserved", 3).emit()?;
    let delay = b
        .field("Initial presentation delay present", 1)
        .flag()
        .emit()?;
    if delay == 1 {
        b.field("Initial presentation delay minus one", 4).emit()?;
    } else {
        b.field("Reserved", 4).emit()?;
    }
    let depth = match (high, twelve) {
        (1, 1) => 12,
        (1, _) => 10,
        _ => 8,
    };
    Ok(Av1Config {
        profile,
        level,
        tier,
        depth,
        mono: mono == 1,
        sub_x,
        sub_y,
    })
}

pub fn av1c(data: &[u8]) -> Option<Av1Config> {
    av1c_layout(&mut BitFields::new(data, nowhere(data.len()))).ok()
}

/// What a sequence header OBU says.
#[derive(Clone, Debug, Default)]
pub struct SequenceHeader {
    pub profile: u64,
    pub still: bool,
    pub level: u64,
    pub width: u64,
    pub height: u64,
}

impl SequenceHeader {
    pub fn summary(&self) -> String {
        format!(
            "{} profile, level {}, up to {}×{}{}",
            lookup_or(AV1_PROFILES, self.profile),
            av1_level(self.level),
            self.width,
            self.height,
            if self.still { ", still picture" } else { "" }
        )
    }
}

fn uvlc(b: &mut BitFields<'_>, name: &'static str) -> Result<u64> {
    let mut zeros = 0u32;
    loop {
        let save = b.pos();
        match b.read(1) {
            Some(0) => zeros = zeros.saturating_add(1),
            Some(_) => {
                b.seek(save);
                break;
            }
            None => {
                b.seek(save);
                break;
            }
        }
        if zeros >= 32 {
            break;
        }
    }
    b.skip(1);
    let v = b.field(name, zeros).emit()?;
    Ok(v.saturating_add(1u64.checked_shl(zeros).unwrap_or(0).saturating_sub(1)))
}

/// sequence_header_obu() up to the maximum frame size.
pub fn sequence_header_layout(b: &mut BitFields<'_>) -> Result<SequenceHeader> {
    let mut h = SequenceHeader {
        profile: b
            .field("Sequence profile", 3)
            .enumeration(AV1_PROFILES)
            .emit()?,
        ..SequenceHeader::default()
    };
    h.still = b.field("Still picture", 1).flag().emit()? == 1;
    let reduced = b.field("Reduced still picture header", 1).flag().emit()?;
    if reduced == 1 {
        h.level = b
            .field("Sequence level index", 5)
            .with(|v, n| n.summary(format!("level {}", av1_level(v))))
            .emit()?;
    } else {
        let mut buffer_delay_bits = 0u32;
        let timing = b.field("Timing info present", 1).flag().emit()?;
        let mut decoder_model = 0;
        if timing == 1 {
            b.field("Units in display tick", 32).emit()?;
            b.field("Time scale", 32).emit()?;
            if b.field("Equal picture interval", 1).flag().emit()? == 1 {
                uvlc(b, "Ticks per picture minus one")?;
            }
            decoder_model = b.field("Decoder model info present", 1).flag().emit()?;
            if decoder_model == 1 {
                let n = b.field("Buffer delay length minus one", 5).emit()?;
                buffer_delay_bits = u32::try_from(n).unwrap_or(0).saturating_add(1);
                b.field("Units in decoding tick", 32).emit()?;
                b.field("Buffer removal time length minus one", 5).emit()?;
                b.field("Frame presentation time length minus one", 5)
                    .emit()?;
            }
        }
        let display_delay = b.field("Initial display delay present", 1).flag().emit()?;
        let points = b.field("Operating points minus one", 5).emit()?;
        for i in 0..=points {
            b.field("Operating point IDC", 12).hex().emit()?;
            let level = b
                .field("Sequence level index", 5)
                .with(|v, n| n.summary(format!("level {}", av1_level(v))))
                .emit()?;
            if i == 0 {
                h.level = level;
            }
            if level > 7 {
                b.field("Sequence tier", 1).emit()?;
            }
            if decoder_model == 1 && b.field("Decoder model present", 1).flag().emit()? == 1 {
                b.field("Decoder buffer delay", buffer_delay_bits).emit()?;
                b.field("Encoder buffer delay", buffer_delay_bits).emit()?;
                b.field("Low delay mode", 1).flag().emit()?;
            }
            if display_delay == 1
                && b.field("Initial display delay present for point", 1)
                    .flag()
                    .emit()?
                    == 1
            {
                b.field("Initial display delay minus one", 4).emit()?;
            }
        }
    }
    let wbits = b.field("Frame width bits minus one", 4).emit()?;
    let hbits = b.field("Frame height bits minus one", 4).emit()?;
    let w = b
        .field(
            "Max frame width minus one",
            u32::try_from(wbits).unwrap_or(0).saturating_add(1),
        )
        .with(|v, n| n.summary(format!("{}", v.saturating_add(1))))
        .emit()?;
    let hh = b
        .field(
            "Max frame height minus one",
            u32::try_from(hbits).unwrap_or(0).saturating_add(1),
        )
        .with(|v, n| n.summary(format!("{}", v.saturating_add(1))))
        .emit()?;
    h.width = w.saturating_add(1);
    h.height = hh.saturating_add(1);
    Ok(h)
}

/// One OBU's header: (type, header length, payload length).
pub fn obu_header(d: &[u8]) -> Option<(u8, usize, usize)> {
    let first = *d.first()?;
    let kind = (first >> 3) & 15;
    let ext = first & 4 != 0;
    let has_size = first & 2 != 0;
    let mut at = if ext { 2usize } else { 1 };
    let size = if has_size {
        let (v, n) = crate::bytes::uleb128(d.get(at..)?)?;
        at = at.checked_add(n)?;
        usize::try_from(v).ok()?
    } else {
        d.len().checked_sub(at)?
    };
    Some((kind, at, size))
}

/// Emits the OBUs in `span` (AV1 configuration OBUs or item data).
pub async fn obus(cx: &Cx, span: Span) -> Result<()> {
    let data = vidutil::read_small(cx, span, 0x10000).await?;
    let mut at = 0usize;
    let mut count = 0u32;
    while at < data.len() {
        let Some(rest) = data.get(at..) else { break };
        let Some((kind, header, size)) = obu_header(rest) else {
            cx.emit(Node::new("Data").span(vidutil::at(span, at, rest.len())));
            break;
        };
        let total = header.saturating_add(size).min(rest.len());
        let obu = vidutil::at(span, at, total);
        let payload = rest.get(header..total).unwrap_or_default();
        let mut node = Node::new(lookup_or(OBU_TYPES, kind.into()))
            .span(obu)
            .summary(format!("{size} bytes"));
        if kind == 1
            && let Ok(seq) =
                sequence_header_layout(&mut BitFields::new(payload, nowhere(payload.len())))
        {
            node = node.summary(seq.summary());
        }
        cx.emit(node.lazy(obu_node, (obu, to_u64(header))));
        at = at.saturating_add(total.max(1));
        count = count.saturating_add(1);
        if count & 0xff == 0 {
            cx.checkpoint().await;
        }
    }
    Ok(())
}

async fn obu_node(cx: Cx, (span, header): (Span, u64)) -> Result<()> {
    let data = cx.read_avail(span.sub(0, 0x10000)).await?;
    let mut b = BitFields::emitting(&cx, &data, span);
    b.field("Forbidden bit", 1).emit()?;
    let kind = b.field("OBU type", 4).enumeration(OBU_TYPES).emit()?;
    let ext = b.field("Extension flag", 1).flag().emit()?;
    let has_size = b.field("Has size field", 1).flag().emit()?;
    b.field("Reserved", 1).emit()?;
    if ext == 1 {
        b.field("Temporal ID", 3).emit()?;
        b.field("Spatial ID", 2).emit()?;
        b.field("Reserved", 3).emit()?;
    }
    if has_size == 1 {
        let at = if ext == 1 { 2 } else { 1 };
        let len = header.saturating_sub(at);
        let size = data
            .get(to_usize(at)..)
            .and_then(crate::bytes::uleb128)
            .map_or(0, |(v, _)| v);
        cx.emit(
            vidutil::uint("OBU size", span.sub(at, len), size, 64)
                .desc("LEB128-coded payload size"),
        );
    }
    let payload = span.tail(header);
    if kind == 1 {
        let body = data.get(to_usize(header)..).unwrap_or_default();
        let mut b = BitFields::emitting(&cx, body, payload);
        let _ = sequence_header_layout(&mut b);
    } else if !payload.is_empty() {
        cx.emit(Node::new("Payload").span(payload));
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// HEVC and AVC parameter sets

/// A one-line description of an HEVC NAL unit (header included).
pub fn hevc_nal_summary(nal: &[u8]) -> Option<String> {
    let kind = (nal.first()? >> 1) & 0x3f;
    match kind {
        33 => hevc_sps(nal).map(|s| {
            format!(
                "{}, {}-bit {}",
                s.hevc_summary(),
                s.bit_depth,
                chroma_name(s.chroma_format)
            )
        }),
        39 | 40 => sei_summary(nal.get(2..)?),
        _ => None,
    }
}

/// A one-line description of an H.264 NAL unit (header included).
pub fn avc_nal_summary(nal: &[u8]) -> Option<String> {
    let kind = nal.first()? & 0x1f;
    match kind {
        7 => vidutil::h264_sps(nal).map(|s| {
            format!(
                "{}, {}-bit {}",
                s.h264_summary(),
                s.bit_depth,
                chroma_name(s.chroma_format)
            )
        }),
        6 => sei_summary(nal.get(1..)?),
        _ => None,
    }
}

pub fn chroma_name(c: u64) -> &'static str {
    match c {
        0 => "4:0:0",
        1 => "4:2:0",
        2 => "4:2:2",
        3 => "4:4:4",
        _ => "?",
    }
}

/// The first SEI message: its type, and the text of unregistered user
/// data (encoders put their settings there).
fn sei_summary(payload: &[u8]) -> Option<String> {
    let rbsp = unescape_rbsp(payload);
    let mut at = 0usize;
    let mut kind = 0u64;
    loop {
        let b = *rbsp.get(at)?;
        kind = kind.saturating_add(b.into());
        at = at.saturating_add(1);
        if b != 0xff {
            break;
        }
    }
    let mut size = 0usize;
    loop {
        let b = *rbsp.get(at)?;
        size = size.saturating_add(b.into());
        at = at.saturating_add(1);
        if b != 0xff {
            break;
        }
    }
    let body = rbsp.get(at..at.saturating_add(size).min(rbsp.len()))?;
    let name = match kind {
        0 => "buffering period",
        1 => "picture timing",
        4 => "registered user data",
        5 => "unregistered user data",
        6 => "recovery point",
        129 => "active parameter sets",
        137 => "mastering display colour volume",
        144 => "content light level",
        147 => "alternative transfer characteristics",
        _ => "",
    };
    let mut s = if name.is_empty() {
        format!("SEI type {kind}")
    } else {
        format!("SEI: {name}")
    };
    if kind == 5
        && let Some(text) = body.get(16..)
    {
        let text = crate::text::until_nul(text);
        if !text.is_empty() && crate::text::looks_like_text(text.as_bytes()) {
            s = format!("{s}: {}", crate::formats::util::sound::clip(&text, 60));
        }
    }
    Some(s)
}

pub const HEVC_PROFILE_SPACES: EnumTable = &[(0, "general"), (1, "A"), (2, "B"), (3, "C")];

/// What an `hvcC` header says, for summaries and codec strings.
#[derive(Clone, Debug, Default)]
pub struct HevcConfig {
    pub space: u8,
    pub tier: u8,
    pub profile: u8,
    pub compat: u32,
    pub constraints: [u8; 6],
    pub level: u8,
    pub chroma: u64,
    pub luma_depth: u64,
}

pub fn hevc_config(d: &[u8]) -> Option<HevcConfig> {
    let b1 = *d.get(1)?;
    Some(HevcConfig {
        space: b1 >> 6,
        tier: (b1 >> 5) & 1,
        profile: b1 & 0x1f,
        compat: u32_be(d, 2)?,
        constraints: crate::bytes::array(d, 6)?,
        level: *d.get(12)?,
        chroma: u64::from(d.get(16)? & 3),
        luma_depth: u64::from(d.get(17)? & 7).saturating_add(8),
    })
}

impl HevcConfig {
    /// `hvc1.1.6.L93.B0` (ISO/IEC 14496-15 E.3).
    pub fn codec_string(&self, fourcc: &str) -> String {
        let space = match self.space {
            1 => "A",
            2 => "B",
            3 => "C",
            _ => "",
        };
        let mut s = format!(
            "{fourcc}.{space}{}.{:X}.{}{}",
            self.profile,
            self.compat.reverse_bits(),
            if self.tier == 1 { 'H' } else { 'L' },
            self.level
        );
        let used = self
            .constraints
            .iter()
            .rposition(|&b| b != 0)
            .map_or(0, |i| i.saturating_add(1));
        for b in self.constraints.iter().take(used) {
            s.push_str(&format!(".{b:X}"));
        }
        s
    }
}

/// `avc1.640028` from the three bytes after the configuration version.
pub fn avc_codec_string(fourcc: &str, d: &[u8]) -> Option<String> {
    Some(format!(
        "{fourcc}.{:02x}{:02x}{:02x}",
        d.get(1)?,
        d.get(2)?,
        d.get(3)?
    ))
}

/// The first SPS NAL unit in an `avcC` body.
pub fn avcc_sps(d: &[u8]) -> Option<&[u8]> {
    if d.get(5)? & 0x1f == 0 {
        return None;
    }
    let len = usize::from(u16_be(d, 6)?);
    d.get(8..8usize.checked_add(len)?)
}
