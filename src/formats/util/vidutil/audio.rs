//! Audio configuration that video containers carry: the MPEG-4
//! AudioSpecificConfig (ISO/IEC 14496-3 1.6.2.1) with its SBR/PS
//! signalling and program config element, and one-line descriptions of
//! the first frame of an ADTS, MPEG audio, AC-3, E-AC-3 or DTS elementary
//! stream.

use super::bitwalk::Walker;
use super::tables::lookup_or;
use crate::value::EnumTable;

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

/// What an AudioSpecificConfig says.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct AscInfo {
    pub object_type: u64,
    pub sample_rate: u64,
    pub channel_config: u64,
    /// SBR (HE-AAC) and its output rate.
    pub sbr: Option<u64>,
    pub ps: bool,
    /// Channels counted in a program config element.
    pub pce_channels: Option<u64>,
}

impl AscInfo {
    pub fn describe(&self) -> String {
        let object = match (self.sbr, self.ps) {
            (Some(_), true) => "HE-AACv2".to_owned(),
            (Some(_), false) => "HE-AAC".to_owned(),
            _ => lookup_or(AUDIO_OBJECT_TYPES, self.object_type),
        };
        let rate = self.sbr.unwrap_or(self.sample_rate);
        let channels = match self.pce_channels {
            Some(n) if self.channel_config == 0 => format!("{n} channels"),
            _ => lookup_or(CHANNEL_CONFIGS, self.channel_config),
        };
        format!("{object}, {rate} Hz, {channels}")
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
        crate::value::Value::Enum {
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
        w.u(explicit, 24)
    } else {
        Some(u64::from(*AAC_SAMPLE_RATES.get(usize::try_from(i).ok()?)?))
    }
}

/// `AudioSpecificConfig()`.
pub fn audio_specific_config(w: &mut Walker) -> Option<AscInfo> {
    let mut a = AscInfo {
        object_type: object_type(w, "audioObjectType")?,
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
            w.u("extensionChannelConfiguration", 4)?;
        }
    }
    match a.object_type {
        1..=4 | 6 | 7 | 17 | 19..=23 => {
            w.begin("GASpecificConfig");
            let short = w.flag("frameLengthFlag")?;
            let ld = matches!(a.object_type, 23 | 39);
            w.summary(|| {
                match (ld, short) {
                    (true, true) => "480 samples",
                    (true, false) => "512 samples",
                    (false, true) => "960 samples",
                    (false, false) => "1024 samples",
                }
                .to_owned()
            });
            if w.flag("dependsOnCoreCoder")? {
                w.u("coreCoderDelay", 14)?;
            }
            let ext = w.flag("extensionFlag")?;
            if a.channel_config == 0 {
                a.pce_channels = Some(program_config_element(w)?);
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
            w.end();
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
            w.end();
        } else {
            w.seek(at);
        }
    }
    Some(a)
}

/// `program_config_element()`: returns the number of channels.
fn program_config_element(w: &mut Walker) -> Option<u64> {
    w.begin("program_config_element");
    w.u("element_instance_tag", 4)?;
    w.u("object_type", 2)?;
    w.en("sampling_frequency_index", 4, SAMPLE_RATE_INDEX)?;
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
    let mut channels = 0u64;
    for (n, kind) in [(front, "front"), (side, "side"), (back, "back")] {
        for i in 0..n {
            let cpe = w.flag(format!("{kind}_element_is_cpe[{i}]"))?;
            w.u(format!("{kind}_element_tag_select[{i}]"), 4)?;
            channels = channels.saturating_add(if cpe { 2 } else { 1 });
        }
    }
    for i in 0..lfe {
        w.u(format!("lfe_element_tag_select[{i}]"), 4)?;
        channels = channels.saturating_add(1);
    }
    for i in 0..assoc {
        w.u(format!("assoc_data_element_tag_select[{i}]"), 4)?;
    }
    for i in 0..cc {
        w.flag(format!("cc_element_is_ind_sw[{i}]"))?;
        w.u(format!("valid_cc_element_tag_select[{i}]"), 4)?;
    }
    let pad = (8usize.saturating_sub(w.pos() & 7)) & 7;
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
    w.end_summary(|| format!("{channels} channels"));
    Some(channels)
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
