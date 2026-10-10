//! Audio configuration that video containers carry: the MPEG-4
//! AudioSpecificConfig (ISO/IEC 14496-3 1.6.2.1) with its SBR/PS
//! signalling and program config element, the Opus identification header
//! (`OpusHead` and the ISOBMFF `dOps`), and one-line descriptions of the
//! first frame of an ADTS, MPEG audio, AC-3, E-AC-3 or DTS elementary
//! stream.

use super::bitwalk::Walker;
use super::tables::lookup_or;
use crate::error::Diagnostic;
use crate::value::{EnumTable, Radix, Value};

pub const AAC_SAMPLE_RATES: [u32; 13] = [
    96000, 88200, 64000, 48000, 44100, 32000, 24000, 22050, 16000, 12000, 11025, 8000, 7350,
];

pub const AUDIO_OBJECT_TYPES: EnumTable = &[
    (1, "AAC Main"),
    (2, "AAC LC"),
    (3, "AAC SSR"),
    (4, "AAC LTP"),
    (5, "HE-AAC (SBR)"),
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
    (29, "HE-AACv2 (PS)"),
    (30, "MPEG Surround"),
    (32, "MPEG-1 Layer 1"),
    (33, "MPEG-1 Layer 2"),
    (34, "MPEG-1 Layer 3"),
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

pub const CHANNEL_CONFIGS: EnumTable = &[
    (0, "defined in the program config element"),
    (1, "mono"),
    (2, "stereo"),
    (3, "3.0"),
    (4, "4.0"),
    (5, "5.0"),
    (6, "5.1"),
    (7, "7.1"),
    (11, "6.1"),
    (12, "7.1 (rear)"),
    (13, "22.2"),
    (14, "7.1 (top)"),
];

/// The profile of a program config element and of an ADTS header: the
/// audio object type minus one.
pub const AAC_PROFILES: EnumTable = &[(0, "Main"), (1, "LC"), (2, "SSR"), (3, "LTP")];

const SAMPLE_RATE_INDEX: EnumTable = &[
    (0, "96000 Hz"),
    (1, "88200 Hz"),
    (2, "64000 Hz"),
    (3, "48000 Hz"),
    (4, "44100 Hz"),
    (5, "32000 Hz"),
    (6, "24000 Hz"),
    (7, "22050 Hz"),
    (8, "16000 Hz"),
    (9, "12000 Hz"),
    (10, "11025 Hz"),
    (11, "8000 Hz"),
    (12, "7350 Hz"),
    (15, "explicit"),
];

/// The sample rate a `samplingFrequencyIndex` stands for.
pub fn aac_rate(index: u64) -> Option<u64> {
    AAC_SAMPLE_RATES
        .get(usize::try_from(index).ok()?)
        .map(|&r| u64::from(r))
}

/// What an AudioSpecificConfig says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AscInfo {
    /// The audio object type as first signalled: 5 or 29 with explicit
    /// SBR/PS signalling (what RFC 6381 codec strings use).
    pub signalled_type: u64,
    /// The core audio object type.
    pub object_type: u64,
    /// The core sample rate.
    pub sample_rate: u64,
    pub channel_config: u64,
    /// SBR (HE-AAC) and its output rate.
    pub sbr: Option<u64>,
    pub ps: bool,
    /// Samples per frame (core rate) for the GA object types; 0 otherwise.
    pub frame_length: u64,
    /// The program config element of channel configuration 0.
    pub pce: Option<PceInfo>,
}

impl AscInfo {
    /// "AAC-LC", "HE-AAC", "HE-AACv2", "AAC-LD".
    pub fn profile(&self) -> String {
        if self.ps {
            return "HE-AACv2".to_owned();
        }
        if self.sbr.is_some() {
            return "HE-AAC".to_owned();
        }
        match self.object_type {
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

    /// The decoded sample rate (the SBR rate for HE-AAC).
    pub fn output_rate(&self) -> u64 {
        self.sbr.unwrap_or(self.sample_rate)
    }

    /// Output channels (parametric stereo makes mono stereo); 0 when
    /// unknown.
    pub fn channels(&self) -> u64 {
        let n = match self.channel_config {
            0 => self.pce.map_or(0, |p| p.total()),
            c @ 1..=6 => c,
            7 | 12 | 14 => 8,
            11 => 7,
            13 => 24,
            _ => 0,
        };
        if self.ps && n == 1 { 2 } else { n }
    }

    /// "mono", "stereo", "5.1", "stereo (parametric)".
    pub fn layout(&self) -> String {
        match (self.channel_config, self.pce) {
            (0, Some(p)) => p.layout(),
            (0, None) => "custom layout".to_owned(),
            (1, _) if self.ps => "stereo (parametric)".to_owned(),
            (c, _) => lookup_or(CHANNEL_CONFIGS, c),
        }
    }

    /// "HE-AAC, 44100 Hz (core 22050 Hz), stereo".
    pub fn describe(&self) -> String {
        let mut s = format!("{}, {} Hz", self.profile(), self.output_rate());
        if self.sbr.is_some_and(|r| r != self.sample_rate) {
            s.push_str(&format!(" (core {} Hz)", self.sample_rate));
        }
        format!("{s}, {}", self.layout())
    }
}

/// What a program config element says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct PceInfo {
    /// The profile (audio object type minus one).
    pub profile: u64,
    pub sample_rate: Option<u64>,
    /// Full-bandwidth channels (front, side and back).
    pub channels: u64,
    pub lfe: u64,
}

impl PceInfo {
    pub fn total(&self) -> u64 {
        self.channels.saturating_add(self.lfe)
    }

    /// "5.1", "stereo", "3 channels".
    pub fn layout(&self) -> String {
        match (self.channels, self.lfe) {
            (n, l) if l > 0 => format!("{n}.{l}"),
            (1, _) => "mono".to_owned(),
            (2, _) => "stereo".to_owned(),
            (n, _) => format!("{n} channels"),
        }
    }
}

fn object_type(w: &mut Walker, name: &'static str) -> Option<u64> {
    let start = w.pos();
    let mut t = w.read(5)?;
    if t == 31 {
        t = w.read(6)?.checked_add(32)?;
    }
    w.record(
        name,
        start,
        Value::Enum {
            raw: t,
            bits: 11,
            name: crate::value::lookup(AUDIO_OBJECT_TYPES, t),
        },
    );
    Some(t)
}

fn sample_rate(w: &mut Walker, index: &'static str, explicit: &'static str) -> Option<u64> {
    let i = w.en(index, 4, SAMPLE_RATE_INDEX)?;
    if i == 15 {
        let r = w.u(explicit, 24)?;
        w.summary(|| format!("{r} Hz"));
        Some(r)
    } else {
        let r = aac_rate(i);
        if r.is_none() {
            w.with(|n| n.diag(Diagnostic::malformed("reserved sampling frequency index")));
        }
        r
    }
}

/// `AudioSpecificConfig()`.
pub fn audio_specific_config(w: &mut Walker) -> Option<AscInfo> {
    // A program config element aligns to bytes counted from here.
    let origin = w.pos();
    let first = object_type(w, "audioObjectType")?;
    let mut a = AscInfo {
        signalled_type: first,
        object_type: first,
        ..AscInfo::default()
    };
    a.sample_rate = sample_rate(w, "samplingFrequencyIndex", "samplingFrequency")?;
    a.channel_config = w.en("channelConfiguration", 4, CHANNEL_CONFIGS)?;
    let mut extension = 0;
    if a.object_type == 5 || a.object_type == 29 {
        extension = 5;
        a.ps = a.object_type == 29;
        a.sbr = Some(sample_rate(
            w,
            "extensionSamplingFrequencyIndex",
            "extensionSamplingFrequency",
        )?);
        a.object_type = object_type(w, "audioObjectType (core)")?;
        if a.object_type == 22 {
            w.en("extensionChannelConfiguration", 4, CHANNEL_CONFIGS)?;
        }
    }
    match a.object_type {
        1..=4 | 6 | 7 | 17 | 19..=23 => {
            w.begin("GASpecificConfig");
            let short = w.flag("frameLengthFlag")?;
            a.frame_length = match (a.object_type == 23, short) {
                (true, true) => 480,
                (true, false) => 512,
                (false, true) => 960,
                (false, false) => 1024,
            };
            let samples = a.frame_length;
            w.summary(|| format!("{samples} samples"));
            if w.flag("dependsOnCoreCoder")? {
                w.u("coreCoderDelay", 14)?;
            }
            let ext = w.flag("extensionFlag")?;
            if a.channel_config == 0 {
                a.pce = Some(program_config_element(w, origin)?);
            }
            if a.object_type == 6 || a.object_type == 20 {
                w.u("layerNr", 3)?;
            }
            if ext {
                if a.object_type == 22 {
                    w.u("numOfSubFrame", 5)?;
                    w.u("layer_length", 11)?;
                }
                if matches!(a.object_type, 17 | 19 | 20 | 23) {
                    w.flag("aacSectionDataResilienceFlag")?;
                    w.flag("aacScalefactorDataResilienceFlag")?;
                    w.flag("aacSpectralDataResilienceFlag")?;
                }
                w.flag("extensionFlag3")?;
            }
            w.end_summary(|| format!("{samples} samples per frame"));
        }
        _ => return Some(a),
    }
    if matches!(a.object_type, 17 | 19..=27 | 39) {
        w.u("epConfig", 2)?;
    }
    if extension != 5 && w.bits_left() >= 16 {
        let at = w.pos();
        if w.read(11)? == 0x2b7 {
            w.seek(at);
            w.begin("Backward-compatible extension");
            w.x("syncExtensionType", 11)?;
            let ext = object_type(w, "extensionAudioObjectType")?;
            if ext == 5 && w.flag("sbrPresentFlag")? {
                a.sbr = Some(sample_rate(
                    w,
                    "extensionSamplingFrequencyIndex",
                    "extensionSamplingFrequency",
                )?);
                if w.bits_left() >= 12 {
                    let at = w.pos();
                    if w.read(11)? == 0x548 {
                        w.seek(at);
                        w.x("syncExtensionType", 11)?;
                        a.ps = w.flag("psPresentFlag")?;
                    } else {
                        w.seek(at);
                    }
                }
            }
            let what = match (a.sbr.is_some(), a.ps) {
                (_, true) => "SBR and PS",
                (true, false) => "SBR",
                _ => "no SBR",
            };
            w.end_summary(|| what.to_owned());
        } else {
            w.seek(at);
        }
    }
    Some(a)
}

/// `program_config_element()` (after its element ID). Byte alignment is
/// counted from bit `origin` (the start of the enclosing
/// AudioSpecificConfig, or 0).
pub fn program_config_element(w: &mut Walker, origin: usize) -> Option<PceInfo> {
    w.begin("program_config_element");
    w.u("element_instance_tag", 4)?;
    let profile = w.en("object_type", 2, AAC_PROFILES)?;
    let rate = w.en("sampling_frequency_index", 4, SAMPLE_RATE_INDEX)?;
    let front = w.u("num_front_channel_elements", 4)?;
    let side = w.u("num_side_channel_elements", 4)?;
    let back = w.u("num_back_channel_elements", 4)?;
    let lfe = w.u("num_lfe_channel_elements", 2)?;
    let assoc = w.u("num_assoc_data_elements", 3)?;
    let cc = w.u("num_valid_cc_elements", 4)?;
    if w.flag("mono_mixdown_present")? {
        w.u("mono_mixdown_element_number", 4)?;
    }
    if w.flag("stereo_mixdown_present")? {
        w.u("stereo_mixdown_element_number", 4)?;
    }
    if w.flag("matrix_mixdown_idx_present")? {
        w.u("matrix_mixdown_idx", 2)?;
        w.flag("pseudo_surround_enable")?;
    }
    let mut pce = PceInfo {
        profile,
        sample_rate: aac_rate(rate),
        channels: 0,
        lfe,
    };
    for (n, kind) in [(front, "front"), (side, "side"), (back, "back")] {
        for i in 0..n {
            let cpe = w.flag(format!("{kind}_element_is_cpe[{i}]"))?;
            w.summary(|| {
                if cpe {
                    "channel pair".to_owned()
                } else {
                    "single channel".to_owned()
                }
            });
            w.u(format!("{kind}_element_tag_select[{i}]"), 4)?;
            pce.channels = pce.channels.saturating_add(if cpe { 2 } else { 1 });
        }
    }
    for i in 0..lfe {
        w.u(format!("lfe_element_tag_select[{i}]"), 4)?;
    }
    for i in 0..assoc {
        w.u(format!("assoc_data_element_tag_select[{i}]"), 4)?;
    }
    for i in 0..cc {
        w.flag(format!("cc_element_is_ind_sw[{i}]"))?;
        w.u(format!("valid_cc_element_tag_select[{i}]"), 4)?;
    }
    let used = w.pos().saturating_sub(origin);
    let pad = (8usize.saturating_sub(used & 7)) & 7;
    if pad > 0 {
        w.skip_as("byte_alignment", pad)?;
    }
    let n = w.u("comment_field_bytes", 8)?;
    if n > 0 {
        let start = w.pos();
        let text = w.read_bytes(usize::try_from(n).ok()?)?;
        w.text(
            "comment_field_data",
            start,
            String::from_utf8_lossy(&text).into_owned(),
        );
    }
    let mut summary = pce.layout();
    if let Some(r) = pce.sample_rate {
        summary = format!("{summary}, {r} Hz");
    }
    w.end_summary(|| summary);
    Some(pce)
}

// ---------------------------------------------------------------------------
// Opus

pub const OPUS_FAMILIES: EnumTable = &[
    (0, "mono/stereo"),
    (1, "Vorbis channel order"),
    (2, "ambisonics"),
    (3, "ambisonics with demixing"),
    (255, "discrete"),
];

/// What an Opus identification header says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct OpusInfo {
    pub channels: u64,
    /// Samples at 48 kHz to discard from the start.
    pub pre_skip: u64,
    pub input_rate: u64,
    /// Output gain in 1/256 dB.
    pub gain: i64,
    pub family: u64,
}

/// "stereo", "5.1", "ambisonics, 4 ch".
pub fn opus_layout(channels: u64, family: u64) -> String {
    match (family, channels) {
        (0 | 1, 1) => "mono".to_owned(),
        (0 | 1, 2) => "stereo".to_owned(),
        (1, 3) => "3.0".to_owned(),
        (1, 4) => "quad".to_owned(),
        (1, 5) => "5.0".to_owned(),
        (1, 6) => "5.1".to_owned(),
        (1, 7) => "6.1".to_owned(),
        (1, 8) => "7.1".to_owned(),
        (2 | 3, n) => format!("ambisonics, {n} ch"),
        (_, n) => format!("{n} ch"),
    }
}

impl OpusInfo {
    pub fn layout(&self) -> String {
        opus_layout(self.channels, self.family)
    }

    /// "stereo, input 44.1 kHz, pre-skip 312 (6.5 ms)".
    pub fn describe(&self) -> String {
        format!(
            "{}, input {}, pre-skip {} ({} ms)",
            self.layout(),
            super::khz(self.input_rate),
            self.pre_skip,
            super::num(self.pre_skip as f64 / 48.0)
        )
    }
}

/// An unsigned integer of `bytes` bytes in either byte order.
fn word(w: &mut Walker, name: &'static str, bytes: usize, big: bool) -> Option<u64> {
    let start = w.pos();
    let b = w.read_bytes(bytes)?;
    let fold = |v: u64, &x: &u8| (v << 8) | u64::from(x);
    let value = if big {
        b.iter().fold(0, fold)
    } else {
        b.iter().rev().fold(0, fold)
    };
    w.record(
        name,
        start,
        Value::UInt {
            value,
            bits: u8::try_from(bytes.saturating_mul(8)).unwrap_or(64),
            radix: Radix::Dec,
        },
    );
    Some(value)
}

/// The Opus identification header: `OpusHead` (RFC 7845 5.1:
/// little-endian, after its magic signature) when `dops` is false, the
/// ISOBMFF `dOps` box body (big-endian, no signature) when true.
pub fn opus_head(w: &mut Walker, dops: bool) -> Option<OpusInfo> {
    if !dops {
        let start = w.pos();
        let magic = w.read_bytes(8)?;
        w.text(
            "Magic signature",
            start,
            String::from_utf8_lossy(&magic).into_owned(),
        );
        if magic != b"OpusHead" {
            w.with(|n| n.diag(Diagnostic::malformed("expected \"OpusHead\"")));
        }
    }
    w.u("Version", 8)?;
    let channels = w.u("Output channel count", 8)?;
    let pre_skip = word(w, "Pre-skip", 2, dops)?;
    w.summary(|| format!("{} ms at 48 kHz", super::num(pre_skip as f64 / 48.0)));
    w.desc("Samples to discard from the start of the decoded output");
    let input_rate = word(w, "Input sample rate", 4, dops)?;
    w.summary(|| super::khz(input_rate));
    w.desc("The original rate; Opus always decodes at 48 kHz");
    let start = w.pos();
    let g = w.read_bytes(2)?;
    let pair = [
        g.first().copied().unwrap_or(0),
        g.get(1).copied().unwrap_or(0),
    ];
    let gain = i64::from(if dops {
        i16::from_be_bytes(pair)
    } else {
        i16::from_le_bytes(pair)
    });
    w.record(
        "Output gain",
        start,
        Value::Int {
            value: gain,
            bits: 16,
        },
    );
    w.summary(|| format!("{:.2} dB", gain as f64 / 256.0));
    let family = w.en("Channel mapping family", 8, OPUS_FAMILIES)?;
    if family != 0 {
        let streams = w.u("Stream count", 8)?;
        let coupled = w.u("Coupled count", 8)?;
        let ch = usize::try_from(channels).ok()?;
        if family == 3 {
            let n = usize::try_from(streams.saturating_add(coupled))
                .ok()?
                .saturating_mul(ch)
                .saturating_mul(2);
            w.bytes("Demixing matrix", n)?;
        } else {
            w.bytes("Channel mapping", ch)?;
        }
    }
    Some(OpusInfo {
        channels,
        pre_skip,
        input_rate,
        gain,
        family,
    })
}

// ---------------------------------------------------------------------------
// Elementary stream headers

const MPA_BITRATES: [[u16; 15]; 5] = [
    // MPEG-1 layer I, II, III; MPEG-2/2.5 layer I; layers II and III.
    [
        0, 32, 64, 96, 128, 160, 192, 224, 256, 288, 320, 352, 384, 416, 448,
    ],
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384,
    ],
    [
        0, 32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320,
    ],
    [
        0, 32, 48, 56, 64, 80, 96, 112, 128, 144, 160, 176, 192, 224, 256,
    ],
    [0, 8, 16, 24, 32, 40, 48, 56, 64, 80, 96, 112, 128, 144, 160],
];

const AC3_BITRATES: [u16; 19] = [
    32, 40, 48, 56, 64, 80, 96, 112, 128, 160, 192, 224, 256, 320, 384, 448, 512, 576, 640,
];

const AC3_MODES: [&str; 8] = ["1+1", "mono", "stereo", "3.0", "2.1", "3.1", "2.2", "5.0"];

const DTS_RATES: [u32; 16] = [
    0, 8000, 16000, 32000, 0, 0, 11025, 22050, 44100, 0, 0, 12000, 24000, 48000, 0, 0,
];
const DTS_CHANNELS: [u8; 16] = [1, 2, 2, 2, 2, 3, 3, 4, 4, 5, 6, 6, 6, 7, 8, 8];

fn ac3_layout(acmod: u64, lfe: bool) -> String {
    let base = AC3_MODES
        .get(usize::try_from(acmod).unwrap_or(0))
        .copied()
        .unwrap_or("?");
    match (acmod, lfe) {
        (7, true) => "5.1".to_owned(),
        (1, true) => "mono + LFE".to_owned(),
        (2, true) => "2.1".to_owned(),
        (_, true) => format!("{base} + LFE"),
        _ => base.to_owned(),
    }
}

/// A one-line description of the first frame of an audio elementary
/// stream, if `d` starts with a recognised frame header.
pub fn es_summary(d: &[u8]) -> Option<String> {
    let b0 = *d.first()?;
    let b1 = *d.get(1)?;
    if b0 == 0x0b && b1 == 0x77 {
        return ac3(d);
    }
    if d.starts_with(&[0x7f, 0xfe, 0x80, 0x01]) {
        return dts(d);
    }
    if b0 == 0xff && b1 & 0xf6 == 0xf0 {
        return adts(d);
    }
    if b0 == 0xff && b1 & 0xe0 == 0xe0 {
        return mpa(d);
    }
    None
}

fn adts(d: &[u8]) -> Option<String> {
    let mut b = super::Bits::new(d);
    b.bits(12)?;
    b.bits(4)?;
    let object = b.bits(2)?.checked_add(1)?;
    let index = b.bits(4)?;
    b.bit()?;
    let channels = b.bits(3)?;
    let rate = AAC_SAMPLE_RATES.get(usize::try_from(index).ok()?)?;
    Some(format!(
        "{}, {rate} Hz, {}",
        lookup_or(AUDIO_OBJECT_TYPES, object),
        lookup_or(CHANNEL_CONFIGS, channels)
    ))
}

fn mpa(d: &[u8]) -> Option<String> {
    let mut b = super::Bits::new(d);
    b.bits(11)?;
    let version = b.bits(2)?;
    let layer = b.bits(2)?;
    b.bit()?;
    let rate_index = usize::try_from(b.bits(4)?).ok()?;
    let freq = b.bits(2)?;
    b.bits(2)?;
    let mode = b.bits(2)?;
    if version == 1 || layer == 0 || freq == 3 || rate_index == 15 {
        return None;
    }
    let layer_n = 4u64.checked_sub(layer)?;
    let table = match (version, layer_n) {
        (3, 1) => 0,
        (3, 2) => 1,
        (3, _) => 2,
        (_, 1) => 3,
        _ => 4,
    };
    let kbps = MPA_BITRATES.get(table)?.get(rate_index)?;
    let base = [44100u32, 48000, 32000].get(usize::try_from(freq).ok()?)?;
    let rate = match version {
        3 => *base,
        2 => base / 2,
        _ => base / 4,
    };
    let name = match version {
        3 => "MPEG-1",
        2 => "MPEG-2",
        _ => "MPEG-2.5",
    };
    let layer_name = ["I", "II", "III"].get(usize::try_from(layer_n.checked_sub(1)?).ok()?)?;
    Some(format!(
        "{name} Layer {layer_name}, {kbps} kb/s, {rate} Hz, {}",
        if mode == 3 { "mono" } else { "stereo" }
    ))
}

fn ac3(d: &[u8]) -> Option<String> {
    let bsid = d.get(5)? >> 3;
    let mut b = super::Bits::new(d.get(2..)?);
    if bsid > 10 {
        // E-AC-3: strmtyp, substreamid, frmsiz, fscod, numblkscod/fscod2.
        b.bits(2)?;
        b.bits(3)?;
        let words = b.bits(11)?.checked_add(1)?;
        let fscod = b.bits(2)?;
        let (rate, blocks) = if fscod == 3 {
            let r = [24000u32, 22050, 16000]
                .get(usize::try_from(b.bits(2)?).ok()?)
                .copied()?;
            (r, 6u64)
        } else {
            let r = [48000u32, 44100, 32000]
                .get(usize::try_from(fscod).ok()?)
                .copied()?;
            let n = [1u64, 2, 3, 6]
                .get(usize::try_from(b.bits(2)?).ok()?)
                .copied()?;
            (r, n)
        };
        let acmod = b.bits(3)?;
        let lfe = b.bit()? == 1;
        // Frame bytes × 8 bits / (blocks × 256 samples) × rate.
        let bitrate = words
            .saturating_mul(16)
            .saturating_mul(u64::from(rate))
            .checked_div(blocks.saturating_mul(256))?
            / 1000;
        return Some(format!(
            "E-AC-3, {bitrate} kb/s, {rate} Hz, {}",
            ac3_layout(acmod, lfe)
        ));
    }
    b.bits(16)?;
    let fscod = b.bits(2)?;
    let frmsizecod = b.bits(6)?;
    b.bits(5)?;
    b.bits(3)?;
    let acmod = b.bits(3)?;
    if acmod & 1 != 0 && acmod != 1 {
        b.bits(2)?;
    }
    if acmod & 4 != 0 {
        b.bits(2)?;
    }
    if acmod == 2 {
        b.bits(2)?;
    }
    let lfe = b.bit()? == 1;
    let rate = [48000u32, 44100, 32000].get(usize::try_from(fscod).ok()?)?;
    let kbps = AC3_BITRATES.get(usize::try_from(frmsizecod >> 1).ok()?)?;
    Some(format!(
        "AC-3, {kbps} kb/s, {rate} Hz, {}",
        ac3_layout(acmod, lfe)
    ))
}

fn dts(d: &[u8]) -> Option<String> {
    let mut b = super::Bits::new(d.get(4..)?);
    // FTYPE, SHORT, CPF, NBLKS, FSIZE.
    b.bits(28)?;
    let amode = b.bits(6)?;
    let sfreq = b.bits(4)?;
    b.bits(5)?;
    b.bits(10)?;
    let lff = b.bits(2)?;
    let rate = DTS_RATES.get(usize::try_from(sfreq).ok()?).copied()?;
    let channels = u64::from(
        DTS_CHANNELS
            .get(usize::try_from(amode).ok()?)
            .copied()
            .unwrap_or(0),
    );
    let lfe = lff == 1 || lff == 2;
    let layout = match (channels, lfe) {
        (5, true) => "5.1".to_owned(),
        (n, true) => format!("{} channels", n.saturating_add(1)),
        (1, false) => "mono".to_owned(),
        (2, false) => "stereo".to_owned(),
        (n, false) => format!("{n} channels"),
    };
    Some(format!("DTS, {rate} Hz, {layout}"))
}
